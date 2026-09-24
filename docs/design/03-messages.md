# 03 — ABI 2.1 messages and control blobs

Status: normative for FSRING ABI 2.1. ABI 2.1 supersedes the ABI 2.0
pre-release draft, which is non-interoperable and is never negotiated. The
authoritative machine-readable declarations are `fsring-abi/src/msgs/*.rs`,
`fsring-abi/src/layout.rs`, `fsring-abi/src/features.rs`,
`fsring-abi/src/ids.rs`, `fsring-abi/src/digest.rs`,
`fsring-abi/src/durable/*.rs`, `fsring-abi/src/validate/*.rs`, and the
generated `fsring-abi/include/fsring_abi.h`. Where any prose and the Rust
crate disagree, the Rust crate wins.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are
normative. All integers are little-endian. A receiver validates every length,
offset, range, enum, flag, reserved field, identity, epoch, opcode, completion
kind, buffer direction, and status before use.

## 1. Encoding rules

- Ring requests travel kernel-to-daemon on the SQ. Ordinary replies and
  notifications travel daemon-to-kernel on the CQ.
- `SqeBody.payload` is 88 bytes. `payload_len` is the exact fixed payload
  size selected by the opcode. The canonical encoder zero-fills the unused
  payload tail. The SQE envelope additionally carries `opcode`, `flags`,
  `reserved` (zero), `req_id`, `kernel_open_id`, and `ccb_sequence`; each
  opcode decides which outer identities MUST be zero or nonzero.
- `CqeBody.out` is 24 bytes. The opcode and terminal status select whether a
  valid 24-byte output record is present; only then is `out_len = 24`. An
  empty or status-invalid result uses `out_len = 0`. The canonical encoder
  zero-fills unused output bytes.
- `SqeBody.reserved` and `CqeBody.reserved` MUST be zero on send and MUST be
  validated as zero on receive.
- Every message type below is gapless: the Rust tests prove that each field
  starts where the preceding field ends and that there is no implicit tail
  padding. A named `reserved` field is wire data and MUST be zero; it is
  never optional compiler padding.
- The canonical POD encoder copies exactly the known object representation
  and zero-fills the remainder of its destination. A decoder reads only the
  validated known size. For versioned blobs, bytes after `struct_size` are an
  optional future tail and are not part of the known structure. Digestable
  mutation bodies are the exception: they permit no unknown optional tail
  (§8.1).

## 2. Identity, feature, and value registries

### 2.1 Transport and durable identities

| Type | Wire representation | Meaning |
|---|---|---|
| `ReqId` | 8 bytes, alignment 8; generation in bits 24–63, slot index in bits 0–23 | Session-scoped inflight request identity. |
| `OpId` | 16/8; `lo:u64@0, hi:u64@8` | Durable exactly-once identity. Stable across retry, daemon restart, and replay. |
| `FileId` | 16/8; `lo:u64@0, hi:u64@8` | Stable provider stream identity. |
| `LinkId` | 16/8; `lo:u64@0, hi:u64@8` | Stable namespace-link identity. |
| `MountId` | 16/8; `lo:u64@0, hi:u64@8` | Mount identity used by authenticated attach; one boot-local mount incarnation. |
| `TransactionId` | 16/8; `lo:u64@0, hi:u64@8` | Prepared OPEN transaction identity; indexes the open-prepare record (§6.1). |
| `AckToken` | 16/8; `lo:u64@0, hi:u64@8` | Notification acknowledgement identity with the closed lane encoding in §9.3. |

`req_id` is never a durable mutation identity. A completion MUST match the
live slot, full generation, request opcode, and current `session_epoch`.
Notifications set `req_id == 0`. Their acknowledgement token is the
`AckToken` inside `NotifyEnvelopeV2`; no request-ID bit has notification
semantics.

READ requires `PRw.op_id == OpId::ZERO`. WRITE requires a nonzero `op_id`.
Every mutation that can have an ambiguous effect uses a stable nonzero
`op_id`, unpredictable and unique within the MountId.

`volume_commit_sequence` is one mount-wide `u64` committed-transaction order
shared by successful COMMIT_OPEN, WRITE, MUTATE, RESIZE, and external
DIR_CHANGE. Zero is invalid. Every distinct committed provider or external
transaction allocates a value strictly greater than every previously
allocated value; the counter never wraps. Ordinary completion, durable
result, QUERY_OP, replay, and any notification for the same transaction
repeat its exact original value rather than allocating another. Ring
delivery is explicitly not ordered by this counter.

### 2.2 Protocol features and OS capabilities

`FeatureSet` is 16 bytes, alignment 8, with `words:[u64;2]@0`. Bit `n` is
`words[n/64] & (1 << (n%64))`.

| Protocol feature bit | Value | Base 2.1 status |
|---|---:|---|
| `PT` | 0 | selectable (profile-gated) |
| `MMAP` | 1 | selectable |
| `HOT_RESTART` | 2 | selectable only paired with `EXACTLY_ONCE` and the dedicated service SID |
| `EXACTLY_ONCE` | 3 | selectable only paired with `HOT_RESTART` |
| `SECURITY` | 4 | REQUIRED base feature of every successful session |
| `REPARSE` | 5 | registry-stable, unselectable |
| `TOKEN_DONATION` | 6 | registry-stable, unselectable |
| `MAPPED_IO` | 7 | selectable (runtime-probed MDL protection) |
| `NOTIFY_NAMES` | 8 | registry-stable, unselectable |
| `CASE_SENSITIVE_NAMES` | 9 | registry-stable, unselectable |

`BASE_REQUIRED_PROTOCOL_MASK` is word0 `0x10` (SECURITY).
`UNSELECTABLE_PROTOCOL_MASK` is word0 `0x360` (bits 5, 6, 8, 9). A SETUP or
ATTACH that requires an unselectable bit fails NOT_SUPPORTED.

| OS-capability bit | Value |
|---|---:|
| `MDL_NO_WRITE` | 0 |
| `MDL_NO_EXECUTE` | 1 |
| `MODERN_COHERENCY` | 2 |
| `ARM64` | 3 |

The two bitsets are independent. The kernel alone supplies
`os_capabilities`. Required features/capabilities MUST be subsets of the
negotiated sets. Unassigned bits are not advertised or required.

Feature-to-wire legality is closed and checked before SQ publication:

- SECURITY is selected in every successful 2.1 session, so QUERY_SECURITY
  and SET_SECURITY have no feature-off form; per-object access checks always
  use the captured subject context and a validated provider descriptor.
- REPARSE is unselectable in base 2.1. Native get/set/delete-reparse
  requests complete locally with NOT_SUPPORTED and emit no SQE. Emitting
  SET_REPARSE or DELETE_REPARSE, returning a REPARSE_POINT attribute, or
  returning a nonzero reparse tag is a provider protocol fault. A create or
  SET_BASIC_INFO input containing FILE_ATTRIBUTE_REPARSE_POINT
  (`0x00000400`), or a create containing FILE_OPEN_REPARSE_POINT
  (`0x00200000`), is rejected locally with NOT_SUPPORTED and no SQE.
- Sparse mutation is likewise unselectable. Native `FSCTL_SET_SPARSE` (TRUE
  or FALSE) completes locally with NOT_SUPPORTED and emits no SQE. Mutation
  kind SET_SPARSE, `SetSparseV1`, or a provider result for it is a protocol
  fault; assignment 11 reserves registry compatibility only.
- Without PT, backing donation returns NOT_SUPPORTED, and PT notifications
  plus their acknowledgement opcodes are excluded from the wire.
- REPLAY_OPEN, QUERY_OP, ACK_RESULT, and ATTACH journal version 1 are legal
  only with the paired HOT_RESTART+EXACTLY_ONCE features.
- Without MMAP, the kernel rejects creation/use of mapped file sections
  locally and never emits an rw record with MAPPED; receiving that flag is a
  protocol fault.
- Without MAPPED_IO, every `BufferRef` kind MAPPING is rejected and the
  transport uses SLOT grants only.

Feature-off local rejection is not a provider completion and consumes no
ReqId, grant, credit, or ring entry. A provider completion or notification
for any feature-gated form that could not have been emitted is a session
protocol fault, not a pass-through NOT_SUPPORTED result.

### 2.3 Opcode registry

| Opcode | Value | Opcode | Value |
|---|---:|---|---:|
| `PREPARE_OPEN` | `0x0001` | `COMMIT_OPEN` | `0x0002` |
| `ABORT_OPEN` | `0x0003` | `CLEANUP` | `0x0004` |
| `CLOSE` | `0x0005` | `READ` | `0x0010` |
| `WRITE` | `0x0011` | `FLUSH` | `0x0012` |
| `QUERY_INFO` | `0x0020` | `MUTATE` | `0x0021` |
| `QUERY_DIR` | `0x0022` | `QUERY_VOLUME` | `0x0023` |
| `QUERY_SECURITY` | `0x0024` | `FSCTL` | `0x0025` |
| `CANCEL` | `0x0030` | `ATTACH` | `0x0040` |
| `REPLAY_OPEN` | `0x0041` | `QUERY_OP` | `0x0042` |
| `ACK_RESULT` | `0x0043` | `PT_ROUTE_ACK` | `0x0050` |
| `PT_EXTERNAL_SAFE_ACK` | `0x0051` | `DIR_CHANGE_ACK` | `0x0052` |

All existing 2.0 values are stable; ABI 2.1 adds only `DIR_CHANGE_ACK` =
`0x0052`. FSCTL keeps its opcode number for registry stability but registers
no code (§5.4).

### 2.4 CQ kinds and notification codes

| CQ kind | Value | Required interpretation |
|---|---:|---|
| `COMPLETION` | 0 | Terminal reply to the matching SQ request. |
| `NOTIFY` | 1 | Unsolicited notification; `req_id == 0` and `out` contains `OControl` (§9.1). |
| `PROTOCOL` | 2 | Protocol/session event; exactly one record is registered (§4.8). |

| Notification code | Value | Acknowledgement |
|---|---:|---|
| `INVALIDATE_FILE` | 1 | none; AckToken zero |
| `INVALIDATE_ENTRY` | 2 | none; AckToken zero |
| `PT_GRANT` | 3 | none; AckToken zero |
| `PT_REVOKE_ROUTE` | 4 | `PT_ROUTE_ACK` with `PNotifyAck` |
| `PT_EXTERNAL_MUTATION_SAFE` | 5 | `PT_EXTERNAL_SAFE_ACK` with `PNotifyAck` |
| `RESIZE` | 6 | none; AckToken zero |
| `DIR_CHANGE` | 7 | `DIR_CHANGE_ACK` with inline `PDirChangeAckV1` |
| `PT_LANE_READY` | 8 | none; AckToken zero |
| `EXTERNAL_CHANGE_READY` | 9 | none; AckToken zero |
| `EXTERNAL_CHANGE_CUT` | 10 | none; AckToken zero |

The notification code is in `NotifyEnvelopeV2.notify_code`, not in
`CqeBody.opcode` or `req_id`.

### 2.5 Buffer and flag registries

| `BufferRef.kind` | Value | Meaning |
|---|---:|---|
| `NONE` | 0 | No buffer. The opcode and grant table decide whether absence is permitted. |
| `SLOT` | 1 | Directional shared slot; `token` is the generation-stamped `SlotToken` (see `02-transport.md`). |
| `MAPPING` | 2 | Kernel-tracked mapped buffer; requires the MAPPED_IO feature. |

| `BufferRef.access` | Value | Direction |
|---|---:|---|
| `K2U_READ_ONLY` | 1 | Kernel-produced bytes; daemon receives a read-only view. |
| `U2K_WRITE` | 2 | Daemon-produced bytes in a kernel-granted writable region. |

| Flag registry | Bit/value |
|---|---:|
| `SqeBody.flags.NO_COMPLETION` | `1 << 0` |
| `rw_flags.PAGING` | `0x01` |
| `rw_flags.NOCACHE` | `0x02` |
| `rw_flags.WRITE_THROUGH` | `0x04` |
| `rw_flags.MAPPED` | `0x08` |
| `rw_flags.SYNC_PAGING` | `0x10` |
| `rw_flags.EXTENDING` | `0x20` |
| `rw_flags.ZERO_RANGE_VALID` | `0x40` |
| `query_dir_flags.RESTART` | `0x00000001` |
| `query_dir_flags.SINGLE` | `0x00000002` |
| `query_dir_flags.EXACT_PATTERN` | `0x00000004` |
| `query_dir_result_flags.EOF` | `0x00000001` |
| `rename_flags.REPLACE_IF_EXISTS` | `0x00000001` |
| `link_flags.REPLACE_IF_EXISTS` | `0x00000001` |
| `query_op_required_flags.ABORT_IF_PREPARED` | `0x0001` |

The rw-flag mask is closed at the seven bits above. Unknown rw bits fail
before submission. The numeric subregistries for mutation kinds, QUERY_OP
states, journal versions, create results, `basic_info_set_mask`, and
`security_information` are closed in §4.4, §4.6, and §8.

Every other named flags field is registered with mask zero in base 2.1:
`CqeBody.flags`, `PBarrier.flags`, `open_flags`, `object_flags`,
`commit_flags`, both open-result `result_flags`, outer `mutation_flags`,
`MutationResultV2.result_flags`, `WriteResultV2.flags`, the kind-result
`flags`, `ReplayOpenV2.state_flags`, `AttachV1.flags`,
`QueryOpResultV1.flags`, `NotifyEnvelopeV2.notify_flags`, every notification
body `flags`, all query/body `flags` fields, `SetSizeV1.flags`,
`SetSecurityV1.flags`, `SetReparseV1.flags`, `DeleteReparseV1.flags`, and
both authenticated-donation `flags` fields. An ABI 2.1 sender emits zero; a
receiver validates zero and MUST NOT guess a meaning for a nonzero
unregistered bit.

### 2.6 Name policy and wildcard registry

Base 2.1 has one fixed name policy, `WINDOWS_ORDINAL_CASE_INSENSITIVE = 1`:
names preserve their original validated UTF-16LE bytes, receive no Unicode
normalization, and collide/compare by the running OS Windows ordinal
case-insensitive upcase table. Kernel mode uses the corresponding Rtl/FsRtl
Unicode comparison and expression routines; the user SDK uses the same
running OS NTDLL semantics. Exact-pattern lookup, create collision,
rename/link collision, directory wildcards, and notification-cache lookup
all use this one policy. There is no mount-local or per-request case-policy
negotiation; a request that would require per-directory case policy
completes locally with NOT_SUPPORTED, zero information, and no
ReqId/grant/SQ record. Requiring feature bit 9 at SETUP also returns
NOT_SUPPORTED.

The wildcard registry, used only in directory search expressions, is exact:

```text
STAR     = U+002A (*)      QUESTION = U+003F (?)
DOS_STAR = U+003C (<)      DOS_QM   = U+003E (>)
DOS_DOT  = U+0022 (")
```

A stored or returned filesystem component is nonempty, at most
`MAX_COMPONENT_UTF16_CODE_UNITS = 255` UTF-16 code units, has valid
surrogate pairs, is not `.` or `..`, and contains none of NUL, slash,
backslash, colon, or the five wildcard code units. This one rule applies to
create, rename, link, canonical directory entries, and notification names;
the provider cannot treat a wildcard token as an ordinary stored character.

## 3. Control-header evolution

All versioned types below begin with this exact prefix:

| Type | Size/alignment | Ordered fields |
|---|---:|---|
| `ControlHeader` | 8/4 | `+0 struct_size:u32`; `+4 struct_version:u16`; `+6 required_flags:u16` |

`CONTROL_VERSION_V1 = 1` and `CONTROL_VERSION_V2 = 2`. These are
control-structure versions inside ABI major 2; neither is the removed
ABI-major-1 protocol. A type whose name ends in `V1` carries
`struct_version = CONTROL_VERSION_V1`; a type whose name ends in `V2`
carries `struct_version = CONTROL_VERSION_V2`.

ABI 2.1 requires the control-version-2 request forms and rejects their
version-1 request forms (the complete cutover map is §5.4):

| Version-2 request | Size/align | Replaces |
|---|---:|---|
| `PrepareOpenV2` | 192/8 | the 96-byte version-1 prepare form |
| `CommitOpenV2` | 104/8 | the 72-byte version-1 commit form |
| `WriteV2` | 112/8 | the inline `PRw` WRITE encoding |
| `MutationV2` | 128/8 | the 72-byte version-1 mutation form |
| `QueryDirV2` | 64/8 | the 56-byte version-1 directory query |
| `ReplayOpenV2` | 104/8 | the 80-byte version-1 replay form |
| `QueryOpV2` | 104/8 | the 56-byte version-1 query-op form |
| `AckResultV2` | 56/8 | the 24-byte version-1 acknowledgement |

Result upgrades `CommitOpenResultV2` (112/8), `WriteResultV2` (56/8),
`MutationResultV2` (112/8), `RenameResultV2` (112/8), and `LinkResultV2`
(104/8) carry version 2; `NotifyEnvelopeV2` (56/8) is the only notification
envelope. Every other versioned blob remains at version 1.

A receiver MUST:

1. verify that at least eight bytes are available before reading the prefix;
2. use checked arithmetic to require
   `8 <= struct_size <= available_blob_length`, where the available length
   comes from the validated `BufferRef` or the authenticated control-IOCTL
   input buffer, as applicable;
3. verify the version and the complete known prefix before reading later
   fields;
4. require at least the known structure size for a supported version;
5. skip an unknown optional tail using `struct_size`, except where a schema
   forbids tails (digestable mutation bodies, §8.1); and
6. reject an unknown bit in `required_flags` with a deterministic
   unsupported-version/request result.

The supported `required_flags` mask is zero for every ABI 2.1 structure
except `QueryOpV2`, whose only registered bit is
`ABORT_IF_PREPARED = 0x0001` (§8.3). An ABI 2.1 sender otherwise sets
`required_flags = 0`. A larger `struct_size` is not by itself an error when
the known prefix and required flags are supported.

## 4. Byte-exact payload catalogue

Notation is `+offset field:type`. In the versioned tables, `+0 header` is
exact shorthand for `+0 header:ControlHeader`. Every row is gapless and has
no implicit tail padding. Sizes and alignments are bytes. A "registry" row
is a byte-stable published layout retained for ABI-major registry stability;
§5.4 states which registry rows are excluded from the ABI 2.1 wire.

### 4.1 Common and fixed ring payloads

| Type | Size/align | Fields in wire order | Required-zero/access rule |
|---|---:|---|---|
| `BlobSlice` | 8/4 | `+0 offset:u32`; `+4 length:u32` | Relative to the start of its containing control blob unless a schema states otherwise. Checked, minimally encoded, non-overlapping where required. |
| `BufferRef` | 24/8 | `+0 token:u64`; `+8 offset:u32`; `+12 length:u32`; `+16 kind:u16`; `+18 access:u16`; `+20 reserved:u32` | `reserved=0`. Validate kind, access, token generation, checked `offset+length`, grant lifetime, and opcode direction. |
| `SizeState` | 32/8 | `+0 allocation_size:u64`; `+8 file_size:u64`; `+16 valid_data_length:u64`; `+24 size_epoch:u64` | Validate the invariants in §7. |
| `PControl` | 24/8 | `+0 body:BufferRef` | SQ input blob; K2U_READ_ONLY. |
| `OControl` | 24/8 | `+0 body:BufferRef` | CQ result/notification blob; the grant echo of §5.2. |
| `PBarrier` | 24/8 | `+0 op_id:OpId`; `+16 flags:u32`; `+20 reserved:u32` | `reserved=0`; flags mask is zero. |
| `PCancel` | 16/8 | `+0 target_req_id:u64`; `+8 target_session_epoch:u64` | One legal encoding only (§8.3). |
| `PNotifyAck` | 24/8 | `+0 token:AckToken`; `+16 epoch:u64` | PT acknowledgements only; `epoch` is the PT epoch of the acknowledged transition. |
| `PRw` | 80/8 | `+0 op_id:OpId`; `+16 offset:u64`; `+24 size_epoch:u64`; `+32 initialized_offset:u64`; `+40 data:BufferRef`; `+64 length:u32`; `+68 initialized_length:u32`; `+72 rw_flags:u32`; `+76 reserved:u32` | `reserved=0`. READ-only in ABI 2.1: zero `op_id` and a U2K data grant. |
| `ORw` | 24/8 | `+0 file_size:u64`; `+8 valid_data_length:u64`; `+16 size_epoch:u64` | READ-lane registry layout; no ABI 2.1 CQE carries it (§5.4). |
| `PDirChangeAckV1` | 64/8 | `+0 token:AckToken`; `+16 through_ordinal:u64`; `+24 volume_commit_sequence:u64`; `+32 semantic_digest:[u8;32]` | Inline `DIR_CHANGE_ACK` payload; all four fields MUST equal the retained canonical event tuple (§9.5). |

Exact SQ lengths and zero tails are:

| Payload | `payload_len` | Zero-filled tail in the 88-byte array |
|---|---:|---:|
| `PControl` | 24 | 64 |
| `PBarrier` | 24 | 64 |
| `PRw` | 80 | 8 |
| `PCancel` | 16 | 72 |
| `PNotifyAck` | 24 | 64 |
| `PDirChangeAckV1` | 64 | 24 |

`OControl` occupies all 24 CQ output bytes. An empty completion uses
`out_len = 0` and a zero-filled 24-byte `out` array.

### 4.2 Transactional OPEN blobs

| Type | Size/align | Fields in wire order | Rule |
|---|---:|---|---|
| `PrepareOpenV1` | 96/8 | `+0 header`; `+8 op_id:OpId`; `+24 parent_id:FileId`; `+40 name:BufferRef`; `+64 security_context_id:u64`; `+72 desired_access:u32`; `+76 share_access:u32`; `+80 disposition:u32`; `+84 create_options:u32`; `+88 file_attributes:u32`; `+92 open_flags:u32` | Registry prefix of the V2 form; rejected as a 2.1 request (§5.4). |
| `PrepareOpenV2` | 192/8 | the complete 96-byte V1 prefix; `+96 requested_security_descriptor:BufferRef`; `+120 extended_attributes:BufferRef`; `+144 reply:BufferRef`; `+168 result_security_descriptor:BufferRef` | `name` is kernel-produced K2U data; `security_context_id` is exactly zero (TOKEN_DONATION is unselectable); open-flags mask is zero. Grant capacities per §5.2. |
| `PrepareOpenResultV1` | 136/8 | `+0 header`; `+8 transaction_id:TransactionId`; `+24 file_id:FileId`; `+40 link_id:LinkId`; `+56 security_descriptor:BufferRef`; `+80 sizes:SizeState`; `+112 namespace_generation:u64`; `+120 security_generation:u64`; `+128 object_flags:u32`; `+132 reserved:u32` | `reserved=0`; the descriptor echoes the 65536-byte result-SD grant shrunk to the validated descriptor length; object-flags mask is zero. |
| `CommitOpenV1` | 72/8 | `+0 header`; `+8 op_id:OpId`; `+24 transaction_id:TransactionId`; `+40 expected_namespace_generation:u64`; `+48 expected_security_generation:u64`; `+56 kernel_open_id:u64`; `+64 commit_flags:u32`; `+68 reserved:u32` | Registry prefix of the V2 form; rejected as a 2.1 request (§5.4). |
| `CommitOpenV2` | 104/8 | the complete 72-byte V1 prefix; `+72 granted_access:u32`; `+76 reserved2:u32`; `+80 reply:BufferRef` | `reserved=0`, `reserved2=0`; `granted_access` is the access actually granted by the kernel; commit-flags mask is zero. |
| `CommitOpenResultV1` | 104/8 | `+0 header`; `+8 provider_open_cookie:u64`; `+16 file_id:FileId`; `+32 link_id:LinkId`; `+48 sizes:SizeState`; `+80 namespace_generation:u64`; `+88 security_generation:u64`; `+96 create_result:u32`; `+100 result_flags:u32` | Registry prefix of the V2 result; a 2.1 COMMIT_OPEN success returns the V2 form. |
| `CommitOpenResultV2` | 112/8 | the complete 104-byte `CommitOpenResultV1` prefix; `+104 volume_commit_sequence:u64` | `create_result` in 0–3 (§4.4 registry); result-flags mask is zero; nonzero `volume_commit_sequence`. |
| `AbortOpenV1` | 24/8 | `+0 header`; `+8 transaction_id:TransactionId` | The ABI 2.1 ABORT_OPEN request; resolves and deletes exactly the retained open-prepare/index pair (§6.1). |

### 4.3 WRITE blobs

| Type | Size/align | Fields in wire order | Rule |
|---|---:|---|---|
| `WriteV2` | 112/8 | `+0 header`; `+8 op_id:OpId`; `+24 offset:u64`; `+32 expected_size_epoch:u64`; `+40 initialized_offset:u64`; `+48 data:BufferRef`; `+72 length:u32`; `+76 initialized_length:u32`; `+80 rw_flags:u32`; `+84 reserved:u32`; `+88 reply:BufferRef` | `reserved=0`; nonzero `op_id`; K2U data grant of exactly `length` bytes; U2K reply grant of at least 56 bytes. |
| `WriteResultV2` | 56/8 | `+0 header`; `+8 sizes:SizeState`; `+40 volume_commit_sequence:u64`; `+48 flags:u32`; `+52 reserved:u32` | `flags=0`, `reserved=0`; nonzero `volume_commit_sequence`; `sizes` satisfies §7 and covers the committed byte prefix reported in CQ `information`. |

### 4.4 Mutation blobs, bodies, and kind results

| Type | Size/align | Fields in wire order | Rule |
|---|---:|---|---|
| `MutationV1` | 72/8 | `+0 header`; `+8 op_id:OpId`; `+24 mutation_kind:u16`; `+26 mutation_flags:u16`; `+28 reserved:u32`; `+32 expected_namespace_generation:u64`; `+40 expected_size_epoch:u64`; `+48 body:BufferRef` | Registry form; rejected as a 2.1 request (§5.4). |
| `MutationV2` | 128/8 | `+0 header`; `+8 op_id:OpId`; `+24 mutation_kind:u16`; `+26 mutation_flags:u16`; `+28 reserved:u32`; `+32 expected_namespace_generation:u64`; `+40 expected_size_epoch:u64`; `+48 expected_security_generation:u64`; `+56 body:BufferRef`; `+80 reply:BufferRef`; `+104 kind_result:BufferRef` | `reserved=0`; outer mutation-flags mask is zero; K2U body of exactly the body `struct_size`; U2K reply of at least 112 bytes; kind-result grant exactly as §5.2. |
| `MutationResultV1` | 80/8 | `+0 header`; `+8 op_id:OpId`; `+24 volume_commit_sequence:u64`; `+32 sizes:SizeState`; `+64 namespace_generation:u64`; `+72 result_flags:u32`; `+76 reserved:u32` | Registry form; a 2.1 MUTATE success returns the V2 result. |
| `MutationResultV2` | 112/8 | `+0 header`; `+8 op_id:OpId`; `+24 volume_commit_sequence:u64`; `+32 mutation_kind:u16`; `+34 result_flags:u16`; `+36 reserved:u32`; `+40 sizes:SizeState`; `+72 namespace_generation:u64`; `+80 security_generation:u64`; `+88 kind_result:BufferRef` | `result_flags=0`, `reserved=0`; nonzero `volume_commit_sequence`; generation semantics per the result table below. |

The mutation-kind registry is closed:

```text
INVALID=0            SET_BASIC_INFO=1     SET_ALLOCATION_SIZE=2
SET_END_OF_FILE=3    SET_VALID_DATA_LENGTH=4
RENAME=5             LINK=6               UNLINK=7
SET_SECURITY=8       SET_REPARSE=9        DELETE_REPARSE=10
SET_SPARSE=11        // assigned/reserved; never selectable in base 2.1
```

The nine fixed body layouts are:

| Type | Size/align | Fields after `ControlHeader` |
|---|---:|---|
| `SetBasicInfoV1` | 48/8 | `+8 creation_time:i64`; `+16 last_access_time:i64`; `+24 last_write_time:i64`; `+32 change_time:i64`; `+40 attributes:u32`; `+44 set_mask:u32` |
| `SetSizeV1` | 24/8 | `+8 new_size:u64`; `+16 flags:u32`; `+20 reserved:u32` |
| `RenameV1` | 72/8 | `+8 source_link_id:LinkId`; `+24 target_parent_id:FileId`; `+40 expected_source_parent_generation:u64`; `+48 expected_target_parent_generation:u64`; `+56 name:BlobSlice`; `+64 flags:u32`; `+68 reserved:u32` |
| `LinkV1` | 64/8 | `+8 source_file_id:FileId`; `+24 target_parent_id:FileId`; `+40 expected_target_parent_generation:u64`; `+48 name:BlobSlice`; `+56 flags:u32`; `+60 reserved:u32` |
| `UnlinkV1` | 56/8 | `+8 link_id:LinkId`; `+24 parent_id:FileId`; `+40 expected_parent_generation:u64`; `+48 flags:u32`; `+52 reserved:u32` |
| `SetSecurityV1` | 24/4 | `+8 security_information:u32`; `+12 flags:u32`; `+16 security_descriptor:BlobSlice` |
| `SetReparseV1` | 24/4 | `+8 tag:u32`; `+12 flags:u32`; `+16 reparse_data:BlobSlice` |
| `DeleteReparseV1` | 16/4 | `+8 tag:u32`; `+12 flags:u32` |
| `SetSparseV1` | 16/4 | `+8 sparse:u32`; `+12 flags:u32` — registry-only assigned layout; accepted by no 2.1 validator |

The body registries are closed:

```text
basic_info_set_mask:
  CREATION_TIME=0x00000001, LAST_ACCESS_TIME=0x00000002,
  LAST_WRITE_TIME=0x00000004, CHANGE_TIME=0x00000008,
  FILE_ATTRIBUTES=0x00000010          (ALL=0x0000001f)
rename_flags: REPLACE_IF_EXISTS=0x00000001
link_flags:   REPLACE_IF_EXISTS=0x00000001

security_information (SET_SECURITY wire registry; SET_MASK=0xf001007f):
  OWNER=0x00000001, GROUP=0x00000002, DACL=0x00000004,
  SACL=0x00000008, LABEL=0x00000010, ATTRIBUTE=0x00000020,
  SCOPE=0x00000040, BACKUP=0x00010000,
  UNPROTECTED_SACL=0x10000000, UNPROTECTED_DACL=0x20000000,
  PROTECTED_SACL=0x40000000, PROTECTED_DACL=0x80000000
```

Native QUERY_SECURITY accepts the smaller closed query mask
`QUERY_ACCEPTED_MASK = 0x0000000f` (exactly OWNER|GROUP|DACL|SACL, at least
one bit); every other bit is rejected locally with INVALID_PARAMETER and no
SQE. At least one basic set-mask or security-information bit is required.
Size, unlink, security-body, reparse, delete-reparse, all outer mutation,
and all result flag masks are zero in base 2.1; only rename/link accept
their single replacement bit. Unknown bits fail.

Each body's variable tail begins exactly at its fixed-prefix size. Each
slice is nonempty, consumes all non-padding tail bytes, and is followed only
by the zero bytes needed to round `struct_size` to eight. Rename/link names
are minimally encoded and satisfy the §2.6 stored-component rule. A security
tail is one validated self-relative descriptor of
`MIN_SECURITY_DESCRIPTOR_BYTES = 20` through
`MAX_SECURITY_DESCRIPTOR_BYTES = 65536` bytes; a reparse tail is one
complete validated buffer no larger than `MAX_REPARSE_DATA_BYTES = 16384`
whose embedded tag equals the fixed tag. Including the 24-byte
`SetSecurityV1` prefix and alignment, the largest canonical mutation body is
65560 bytes. No tail aliases its fixed prefix. There is exactly one accepted
byte representation for a semantic body: mask-excluded values, alternate
slice placement, extra tail bytes, and nonzero padding fail before digesting
or submission.

The known file-attribute registry mask is `REGISTRY_MASK = 0x7fb7`. Because
REPARSE is unselectable, the accepted mask is `ACCEPTED_MASK_V21 = 0x7bb7`
and every returned reparse tag is zero. The settable basic-info attribute
mask is `SETTABLE_BASIC_MASK = 0x31a7` (READONLY, HIDDEN, SYSTEM, ARCHIVE,
NORMAL, TEMPORARY, OFFLINE, NOT_CONTENT_INDEXED); NORMAL is legal only
alone; DIRECTORY, SPARSE_FILE, REPARSE_POINT, COMPRESSED, and ENCRYPTED are
query-only. A file is never converted to or from a directory.

The target FileId is not duplicated inside `MutationV2`: it is the retained
FCB identity bound to the enclosing SQE's nonzero `kernel_open_id`. The
outer prerequisite table is exact ("file generation" is the retained
generation for namespace-visible metadata and the link set; "parent
generation" is the retained directory-entry-set generation):

| Kind | Outer `expected_namespace_generation` | size epoch | security generation | Body parent prerequisite(s) |
|---|---|---|---|---|
| SET_BASIC_INFO | target file generation, nonzero | zero | zero | none |
| SET_ALLOCATION_SIZE / SET_END_OF_FILE / SET_VALID_DATA_LENGTH | zero | target size epoch, nonzero | zero | none |
| RENAME | source link-set generation, nonzero | zero | zero | source and target parent generations, both nonzero |
| LINK | source link-set generation, nonzero | zero | zero | target parent generation, nonzero |
| UNLINK | target link-set generation, nonzero | zero | zero | parent generation, nonzero |
| SET_SECURITY | zero | zero | target security generation, nonzero | none |
| SET_REPARSE / DELETE_REPARSE | target file generation, nonzero | zero | zero | none |

Every identity relation and every generation is checked as one
precondition; a stale or contradictory value yields RETRY and no partial
mutation. For rename, the source `LinkId` must belong to the target FileId
and match the explicit expected source-parent generation; same-directory
rename requires equal expected parent fields.

Result-generation meaning is also exact; each returned generation is the
post-commit value for the exact retained entity and is strictly greater
than its required input generation, including a semantically no-op
successful mutation. A result field specified as zero is exactly zero:

| Kind | `MutationResultV2.namespace_generation` | `security_generation` | Kind-result parent generation(s) |
|---|---|---|---|
| SET_BASIC_INFO / SET_REPARSE / DELETE_REPARSE | resulting file generation, nonzero | zero | none |
| size mutations | zero | zero | none |
| RENAME / LINK / UNLINK | resulting link-set generation, nonzero | zero | source+target / target / parent respectively, all nonzero |
| SET_SECURITY | zero | resulting security generation, nonzero | none |

For a size mutation, the returned `SizeState.size_epoch` is strictly
greater than the required input epoch. SET_VALID_DATA_LENGTH success
additionally requires unchanged allocation and file size with
`valid_data_length` equal to the requested new VDL; SET_ALLOCATION_SIZE and
SET_END_OF_FILE follow their exact shrink/extend postconditions in the
corrective design; any different successful state is a protocol fault. For
every other mutation, `sizes` is the validated current snapshot and must
not regress the retained size epoch/state.

Kind-result layouts:

| Type | Size/align | Fields in wire order |
|---|---:|---|
| `RenameResultV2` | 112/8 | `+0 header`; `+8 file_id:FileId`; `+24 link_id:LinkId`; `+40 replaced_file_id:FileId`; `+56 replaced_link_id:LinkId`; `+72 source_parent_generation:u64`; `+80 target_parent_generation:u64`; `+88 replaced_namespace_generation:u64`; `+96 link_count:u32`; `+100 replaced_link_count:u32`; `+104 flags:u32`; `+108 reserved:u32` |
| `LinkResultV2` | 104/8 | `+0 header`; `+8 file_id:FileId`; `+24 new_link_id:LinkId`; `+40 replaced_file_id:FileId`; `+56 replaced_link_id:LinkId`; `+72 target_parent_generation:u64`; `+80 replaced_namespace_generation:u64`; `+88 link_count:u32`; `+92 replaced_link_count:u32`; `+96 flags:u32`; `+100 reserved:u32` |
| `UnlinkResultV1` | 56/8 | `+0 header`; `+8 file_id:FileId`; `+24 removed_link_id:LinkId`; `+40 parent_generation:u64`; `+48 remaining_link_count:u32`; `+52 flags:u32` |

All flags and reserved fields are zero. With no replacement, both
replacement identities, the replaced generation, and the replaced link
count are zero. With a replacement, both identities and the post-commit
replaced-file link-set generation are nonzero; the replaced link count is
its exact remaining count and may be zero. A half-present replacement tuple
is invalid. Rename preserves its LinkId; link returns a new nonzero LinkId
distinct from every retained and replaced LinkId; unlink returns the
removed nonzero LinkId. Same-directory rename returns equal source and
target parent generations. If `replaced_file_id == file_id`, both
post-commit link-set generations and link counts must be exactly equal.

### 4.5 Query blobs

| Type | Size/align | Fields in wire order | Rule |
|---|---:|---|---|
| `QueryInfoV1` | 40/8 | `+0 header`; `+8 info_class:u16`; `+10 flags:u16`; `+12 reserved:u32`; `+16 output:BufferRef` | `reserved=0`; flags mask zero; `query_info_class`: INVALID=0, CANONICAL=1. Output grant at least 104 bytes. |
| `FileInfoV1` | 104/8 | `+0 header`; `+8 creation_time:i64`; `+16 last_access_time:i64`; `+24 last_write_time:i64`; `+32 change_time:i64`; `+40 sizes:SizeState`; `+72 namespace_generation:u64`; `+80 security_generation:u64`; `+88 attributes:u32`; `+92 link_count:u32`; `+96 reparse_tag:u32`; `+100 flags:u32` | Both generations nonzero; attributes within `0x7bb7`; reparse tag zero; flags zero. Link count may be zero only for an already-open unlinked file. |
| `QueryDirV1` | 56/8 | `+0 header`; `+8 enumeration_cookie:u64`; `+16 flags:u32`; `+20 reserved:u32`; `+24 pattern:BlobSlice`; `+32 output:BufferRef` | Registry prefix of `QueryDirV2`; rejected as a 2.1 request (§5.4). |
| `QueryDirV2` | 64/8 | the complete 56-byte V1 prefix; `+56 enumeration_generation:u64` | `reserved=0`; flags within RESTART/SINGLE/EXACT_PATTERN; `enumeration_generation` is nonzero. Output grant at least the 40-byte result prefix; capacity in `[40, MAX_CONTROL_BLOB]`. |
| `QueryDirResultV1` | 40/8 fixed prefix | `+0 header`; `+8 next_cookie:u64`; `+16 flags:u32`; `+20 entry_count:u32`; `+24 entries:BlobSlice`; `+32 required_length:u32`; `+36 reserved:u32` | Result flags accept only EOF. With entries, `entries` starts exactly at byte 40; without entries it is `{0,0}`. On success `required_length` and `reserved` are zero. |
| `DirEntryV1` | 136/8 fixed prefix | `+0 header`; `+8 file_id:FileId`; `+24 link_id:LinkId`; `+40 sizes:SizeState`; `+72 creation_time:i64`; `+80 last_access_time:i64`; `+88 last_write_time:i64`; `+96 change_time:i64`; `+104 namespace_generation:u64`; `+112 attributes:u32`; `+116 reparse_tag:u32`; `+120 flags:u32`; `+124 reserved:u32`; `+128 name:BlobSlice` | Name slice is entry-relative, starts at byte 136, has even length, and is followed only by zero padding to a multiple of eight. Identities and generation nonzero. |
| `QueryVolumeV1` | 40/8 | `+0 header`; `+8 info_class:u16`; `+10 flags:u16`; `+12 reserved:u32`; `+16 output:BufferRef` | `query_volume_class`: INVALID=0, SIZE=1. Output grant at least 40 bytes. |
| `VolumeSizeInfoV1` | 40/8 | `+0 header`; `+8 total_allocation_units:u64`; `+16 available_allocation_units:u64`; `+24 sectors_per_allocation_unit:u32`; `+28 bytes_per_sector:u32`; `+32 flags:u32`; `+36 reserved:u32` | `available <= total`; `bytes_per_sector` a power of two in `[512, 65536]`; nonzero power-of-two `sectors_per_allocation_unit`; checked cluster-size product at most 16 MiB; derived byte totals at most `MAX_FILE_SIZE`. |
| `QuerySecurityV1` | 40/8 | `+0 header`; `+8 security_information:u32`; `+12 flags:u32`; `+16 output:BufferRef` | Mask within `0x0000000f`, at least one bit; U2K output grant of exactly 65536 bytes. |
| `FsctlV1` | 64/8 | `+0 header`; `+8 code:u32`; `+12 flags:u32`; `+16 input:BufferRef`; `+40 output:BufferRef` | Registry-only layout. ABI 2.1 registers no FSCTL code (§5.4). |

Cookie ordinals are verified, not opaque: input cookie zero is the start
position; a successful non-final batch proves
`next_cookie = input_cookie + entry_count` with checked arithmetic; a
successful final batch carries EOF and `next_cookie = 0`; zero has no other
successor meaning. Same-cookie, skipped-cookie, wrapped, and cyclic
successors are protocol faults. `MAX_CANONICAL_DIR_ENTRY_BYTES = 648`
(136-byte prefix, at most 510 name bytes, and alignment);
`MAX_CONTROL_BLOB = 16777216` (16 MiB). Because every issued QueryDir grant
holds a maximum entry, provider BUFFER_TOO_SMALL and empty success are
protocol faults. A new or restarted snapshot with no match returns
NO_SUCH_FILE; after it has returned an entry, exhaustion returns
NO_MORE_FILES. The snapshot key is
`(MountId, kernel_open_id, enumeration_generation)`; a repeated nonzero
input cookie is nondestructive.

QueryInfo CANONICAL writes exactly one `FileInfoV1`; QueryVolume SIZE
writes exactly one `VolumeSizeInfoV1`; QuerySecurity writes only one
validated self-relative security descriptor of 20–65536 bytes into its
65536-byte grant, with no bytes beyond the validated descriptor.

### 4.6 Recovery and journal blobs

| Type | Size/align | Fields in wire order | Rule |
|---|---:|---|---|
| `ReplayOpenV1` | 80/8 | `+0 header`; `+8 kernel_open_id:u64`; `+16 file_id:FileId`; `+32 link_id:LinkId`; `+48 desired_access:u32`; `+52 share_access:u32`; `+56 create_options:u32`; `+60 disposition:u32`; `+64 ccb_sequence:u64`; `+72 state_flags:u64` | Registry prefix of the V2 form; rejected as a 2.1 request (§5.4). |
| `ReplayOpenV2` | 104/8 | the complete 80-byte V1 prefix; `+80 reply:BufferRef` | U2K reply grant of at least 16 bytes; state-flags mask zero except the replay modes defined in `02-transport.md`. |
| `ReplayOpenResultV1` | 16/8 | `+0 header`; `+8 provider_open_cookie:u64` | Cookie is scoped to the new session. |
| `AttachV1` | 56/8 | `+0 header`; `+8 prior_session_epoch:u64`; `+16 requested_features:FeatureSet`; `+32 mount_id:MountId`; `+48 journal_version:u32`; `+52 flags:u32` | Authenticated control IOCTL only; flags mask zero; journal versions NONE=0, V1=1 (V1 only with the restart pair). |
| `QueryOpV1` | 56/8 | `+0 header`; `+8 op_id:OpId`; `+24 operation_digest:[u8;32]` | Registry prefix of the V2 form; rejected as a 2.1 request (§5.4). |
| `QueryOpV2` | 104/8 | the complete 56-byte V1 prefix; `+56 reply:BufferRef`; `+80 committed_result:BufferRef` | U2K reply of at least 56 bytes; U2K committed-result grant of 40–224 bytes (§5.2); `required_flags` zero or exactly `ABORT_IF_PREPARED`. |
| `QueryOpResultV1` | 56/8 | `+0 header`; `+8 state:u16`; `+10 flags:u16`; `+12 reserved:u32`; `+16 op_id:OpId`; `+32 result:BufferRef` | `flags=0`, `reserved=0`; `op_id` equals the request. States: INVALID=0, NOT_FOUND=1, PREPARED=2, COMMITTED=3. NOT_FOUND/PREPARED require `result = BufferRef::NONE`; COMMITTED requires the committed-result grant echo shrunk to the exact derived `CommittedResultV1.struct_size`. |
| `AckResultV1` | 24/8 | `+0 header`; `+8 op_id:OpId` | Registry prefix of the V2 form; rejected as a 2.1 request (§5.4). |
| `AckResultV2` | 56/8 | the complete 24-byte V1 prefix; `+24 operation_digest:[u8;32]` | Both the OpId and the exact operation digest authenticate which durable bundle may be pruned. |

### 4.7 Notification envelopes and bodies

| Type | Size/align | Fields in wire order | Rule |
|---|---:|---|---|
| `NotifyEnvelopeV1` | 72/8 | `+0 header`; `+8 notify_code:u16`; `+10 notify_flags:u16`; `+12 reserved:u32`; `+16 token:AckToken`; `+32 file_id:FileId`; `+48 body:BufferRef` | Registry-stable ABI-major envelope; superseded by the V2 envelope (§5.4). |
| `NotifyEnvelopeV2` | 56/8 | `+0 header`; `+8 notify_code:u16`; `+10 notify_flags:u16`; `+12 reserved:u32`; `+16 token:AckToken`; `+32 file_id:FileId`; `+48 body:BlobSlice` | `reserved=0`; notify-flags mask zero. The inline body begins exactly at byte 56; `body.length` equals the selected body's `ControlHeader.struct_size`; the envelope ends at the same byte as the body. |
| `InvalidateFileV1` | 40/8 | `+0 header`; `+8 offset:u64`; `+16 length:u64`; `+24 content_epoch:u64`; `+32 flags:u32`; `+36 reserved:u32` | `length = 0` means the whole stream and requires `offset = 0`; a nonempty range satisfies the §7 `MAX_FILE_SIZE` rule. |
| `InvalidateEntryV1` | 32/8 | `+0 header`; `+8 namespace_generation:u64`; `+16 name:BlobSlice`; `+24 flags:u32`; `+28 reserved:u32` | Inline UTF-16 name begins at byte 32 and consumes the body tail; the envelope FileId is the parent directory. |
| `PtGrantV1` | 24/8 | `+0 header`; `+8 pt_epoch:u64`; `+16 sector_size:u32`; `+20 flags:u32` | Must match a prior authenticated current-session backing donation; backing handles stay on the control path. |
| `PtEpochV1` | 16/8 | `+0 header`; `+8 pt_epoch:u64` | Body of PT_REVOKE_ROUTE and PT_EXTERNAL_MUTATION_SAFE; must match the exact live transition epoch. |
| `ResizeV1` | 48/8 | `+0 header`; `+8 sizes:SizeState`; `+40 volume_commit_sequence:u64` | Nonzero `size_epoch` and `volume_commit_sequence`; merge rules in §9.2. |
| `ExternalDirChangeV1` | 176/8 fixed prefix | full field table below | Precise/OVERFLOW validity rules in §9.5. |
| `PtLaneReadyV1` | 24/8 | `+0 header`; `+8 kind_ordinal:u16`; `+10 reserved0:u16`; `+12 flags:u32`; `+16 high_watermark:u64` | `kind_ordinal` exactly 1 or 2; envelope FileId and AckToken zero; only during PT reconciliation. |
| `ExternalChangeReadyV1` | 32/8 | `+0 header`; `+8 reconcile_cut:u64`; `+16 processed_high_watermark:u64`; `+24 flags:u32`; `+28 reserved:u32` | Ring zero only; both watermarks equal the stored attach cut (§9.5). |
| `ExternalChangeCutV1` | 24/8 | `+0 header`; `+8 reconcile_cut:u64`; `+16 flags:u32`; `+20 reserved:u32` | Ring zero only; published once before any probe or row (§9.5). |

```text
ExternalDirChangeV1: 176/8 fixed prefix
  +0   header:ControlHeader
  +8   first_ordinal:u64
  +16  through_ordinal:u64
  +24  volume_commit_sequence:u64
  +32  change_kind:u16       // ADD=1, REMOVE=2, MODIFY=3,
                             // RENAME=4, OVERFLOW=0xffff
  +34  object_kind:u16       // FILE=1, DIRECTORY=2; zero for OVERFLOW
  +36  filter_match:u32
  +40  flags:u32
  +44  reserved0:u32
  +48  target_link_id:LinkId
  +64  replaced_file_id:FileId
  +80  replaced_link_id:LinkId
  +96  old_parent_id:FileId
  +112 new_parent_id:FileId
  +128 old_parent_generation:u64
  +136 new_parent_generation:u64
  +144 target_namespace_generation:u64
  +152 replaced_namespace_generation:u64
  +160 old_name:BlobSlice
  +168 new_name:BlobSlice
```

External old/new names are body-relative, begin at byte 176 in that order,
are each absent or 2–510 bytes, minimally packed without a gap, and are
followed only by zero padding to eight. Each name satisfies the §2.6
stored-component rule and contains no wildcard. With two maximum names the
body is 1200 bytes and the complete envelope is 1256 bytes, so the
unconditional 2048-byte minimum notification credit holds every atomic
rename.

### 4.8 PROTOCOL record

CQ kind PROTOCOL has one registered ABI 2.1 record:

```text
protocol_opcode::ABORT_SESSION      = 1
protocol_reason::PROVIDER_FATAL_STATE = 1

ProtocolAbortV1: 24/8
  +0  header:ControlHeader   // size 24, version 1, flags 0
  +8  reason:u32
  +12 reserved:u32
  +16 context:u64
```

Its CQE is exactly kind PROTOCOL, opcode `ABORT_SESSION`, flags 0, out
length 24, request ID 0, success status, reserved 0, information 0, and the
inline `ProtocolAbortV1` with `reason = PROVIDER_FATAL_STATE` and
`reserved = 0`. `context` is diagnostic only: it is logged only as a
rate-limited hexadecimal value and is never dereferenced or used as
authority. A valid record requests immediate quarantine and controlled
teardown. Any other PROTOCOL encoding is a structural protocol fault.

### 4.9 Authenticated-control-only payloads

| Type | Size/align | Fields in wire order | Rule |
|---|---:|---|---|
| `DonateBackingV1` | 48/8 | `+0 header`; `+8 file_id:FileId`; `+24 pt_epoch:u64`; `+32 daemon_handle:u64`; `+40 sector_size:u32`; `+44 flags:u32` | Registry-stable control-side layout; the active control form is `DonateBackingV2` (see `02-transport.md`). Never a ring payload. |
| `DonateSecurityContextV1` | 32/8 | `+0 header`; `+8 security_context_id:u64`; `+16 daemon_handle:u64`; `+24 flags:u32`; `+28 reserved:u32` | Registry-stable; a well-formed authorized call returns NOT_SUPPORTED and never references the supplied handle (TOKEN_DONATION is unselectable). |

`AttachV1` and both donation payloads travel only through the authenticated
control IOCTL after process/mount/session binding; none is ever accepted
from an unestablished ring. `daemon_handle` is a handle value in the
authorized daemon process, never a shared kernel pointer.

### 4.10 Durable committed results

These structures are durable journal payloads read back through QUERY_OP;
their semantics are §8.2.

| Type | Size/align | Fields in wire order |
|---|---:|---|
| `CommittedResultV1` | 40/8 fixed prefix | `+0 header`; `+8 opcode:u16`; `+10 result_kind:u16`; `+12 status:i32`; `+16 information:u64`; `+24 payload:BlobSlice`; `+32 volume_commit_sequence:u64` |
| `CommittedOpenResultV1` | 96/8 | `+0 header`; `+8 file_id:FileId`; `+24 link_id:LinkId`; `+40 sizes:SizeState`; `+72 namespace_generation:u64`; `+80 security_generation:u64`; `+88 create_result:u32`; `+92 flags:u32` |
| `CommittedWriteResultV1` | 40/8 | `+0 header`; `+8 sizes:SizeState` |
| `CommittedMutationResultV1` | 72/8 fixed prefix | `+0 header`; `+8 mutation_kind:u16`; `+10 flags:u16`; `+12 reserved:u32`; `+16 sizes:SizeState`; `+48 namespace_generation:u64`; `+56 security_generation:u64`; `+64 kind_payload:BlobSlice` |

The create-information reference constants are `SUPERSEDED=0`, `OPENED=1`,
`CREATED=2`, `OVERWRITTEN=3`, `EXISTS=4`, `DOES_NOT_EXIST=5`. The
`create_result` validator accepts only 0–3 in a successful COMMIT result;
`EXISTS` and `DOES_NOT_EXIST` are reference constants, never wire results.
Failed COMMIT has no output.

## 5. Opcode-to-payload and status-class map

"Ordinary terminal" below means only an operation-appropriate terminal
success, a status from the opcode's registered failure array (§5.3), or the
opcode's registered extra statuses. A stale expected namespace generation,
security generation, or size epoch is explicitly retryable with
`STATUS_RETRY`. A protocol fault is not an ordinary request result: it
quarantines the session and enters GRACE or teardown.

### 5.1 Ring payload map

This map transcribes the module documentation of `fsring-abi/src/msgs/mod.rs`,
which is the authoritative ring-payload map.

| Opcode | SQ payload (`payload_len`) | K2U body blob | CQ output | Result blob |
|---|---|---|---|---|
| `PREPARE_OPEN` | `PControl` (24) | `PrepareOpenV2` | `OControl` | `PrepareOpenResultV1` |
| `COMMIT_OPEN` | `PControl` (24) | `CommitOpenV2` | `OControl` | `CommitOpenResultV2` |
| `ABORT_OPEN` | `PControl` (24) | `AbortOpenV1` | empty | — |
| `CLEANUP` | `PBarrier` (24) | — | empty | — |
| `CLOSE` | `PBarrier` (24) | — | empty | — |
| `READ` | inline `PRw` (80) | — | `OControl` | data-grant echo shrunk to transferred bytes |
| `WRITE` | `PControl` (24) | `WriteV2` | `OControl` | `WriteResultV2` (reply-grant echo, 56 bytes) |
| `FLUSH` | `PBarrier` (24) | — | empty | — |
| `QUERY_INFO` | `PControl` (24) | `QueryInfoV1` | `OControl` | `FileInfoV1` |
| `MUTATE` | `PControl` (24) | `MutationV2` | `OControl` | `MutationResultV2` (+ kind result) |
| `QUERY_DIR` | `PControl` (24) | `QueryDirV2` | `OControl` | `QueryDirResultV1` + `DirEntryV1` records |
| `QUERY_VOLUME` | `PControl` (24) | `QueryVolumeV1` | `OControl` | `VolumeSizeInfoV1` |
| `QUERY_SECURITY` | `PControl` (24) | `QuerySecurityV1` | `OControl` | self-relative descriptor, 20–65536 bytes |
| `FSCTL` | none | — | none | no request or completion is accepted in ABI 2.1 |
| `CANCEL` | `PCancel` (16); `NO_COMPLETION` REQUIRED | — | none: the daemon MUST NOT emit a CQE | — |
| `ATTACH` | control IOCTL only (`AttachV1`) | — | control-path result | — |
| `REPLAY_OPEN` | `PControl` (24) | `ReplayOpenV2` | `OControl` | `ReplayOpenResultV1` |
| `QUERY_OP` | `PControl` (24) | `QueryOpV2` | `OControl` | `QueryOpResultV1` |
| `ACK_RESULT` | `PControl` (24) | `AckResultV2` | empty | — |
| `PT_ROUTE_ACK` | `PNotifyAck` (24) | — | empty | — |
| `PT_EXTERNAL_SAFE_ACK` | `PNotifyAck` (24) | — | empty | — |
| `DIR_CHANGE_ACK` | inline `PDirChangeAckV1` (64) | — | empty | — |

`DIR_CHANGE_ACK` carries its 64-byte payload inline with
`payload_len = 64`; a `PControl`/`BufferRef` form of this acknowledgement
is rejected. READ keeps the inline `PRw` with a zero `OpId` and a U2K data
grant. For every ordinary completion, `CqeBody.kind = COMPLETION`, `opcode`
echoes the request, and `req_id` exactly matches the request. `status` is
terminal; `STATUS_PENDING` is not a terminal CQ result. Result bytes are
consumed only when the opcode/status contract declares them valid.

### 5.2 Grant rules

Every output-producing request carries its kernel-issued U2K grants inside
its control-version-2 body. The grant rules are exact:

| Request field | Required direction/capacity | NONE legality | Result echo |
|---|---|---|---|
| Prepare requested SD, EA | K2U; exact validated input bytes | allowed independently | never echoed |
| Prepare reply | U2K, at least 136 bytes | forbidden | CQ `OControl` |
| Prepare result SD | U2K, exactly 65536 bytes | forbidden | `PrepareOpenResultV1.security_descriptor` |
| Commit reply | U2K, at least 112 bytes | forbidden | CQ `OControl` |
| Read data | U2K; requested capacity | forbidden | CQ `OControl` shrunk to transferred bytes |
| Write data | K2U; exact request length | forbidden | never echoed |
| Write reply | U2K, at least 56 bytes | forbidden | CQ `OControl` |
| Mutation body | K2U, exact body `struct_size` | forbidden | never echoed |
| Mutation reply | U2K, at least 112 bytes | forbidden | CQ `OControl` |
| Mutation kind result | U2K, exactly 112/104/56 bytes for RENAME/LINK/UNLINK | required for those three; NONE for all others | `MutationResultV2.kind_result` |
| Replay reply | U2K, at least 16 bytes | forbidden | CQ `OControl` |
| QueryOp reply | U2K, at least 56 bytes | forbidden | CQ `OControl` |
| QueryOp committed result | U2K, 40–224 bytes; ordinary confirmation reserves 224 | forbidden | `QueryOpResultV1.result`, COMMITTED only |
| QuerySecurity descriptor | U2K, exactly 65536 bytes | forbidden | CQ `OControl` shrunk to the complete descriptor length |

K2U means `K2U_READ_ONLY`; U2K means `U2K_WRITE`. A grant may be SLOT or
MAPPING if the negotiated transport supports that kind. Every ordinary
result echoes token, kind, access, and offset exactly and reduces length to
its exact validated result size. Successful COMMIT_OPEN and WRITE echo
their reply grants shrunk to exactly 112 and 56 bytes. The kernel always
grants the complete 65536 bytes for a Prepare result SD, so PREPARE_OPEN
BUFFER_TOO_SMALL is a protocol fault and can never drive an internal retry;
QUERY_SECURITY likewise always has the complete descriptor grant, so a
provider BUFFER_TOO_SMALL there is unregistered and never supplies a native
required length. QueryOp BUFFER_TOO_SMALL refers only to the
committed-result grant (§8.3).

Create SD and EA inputs are each at most 65536 bytes; the SD is valid
self-relative form, and the EA chain is walked with checked offsets,
canonical alignment, bounded names/values, and no trailing bytes before
either becomes a grant or digest input.

### 5.3 Completion status and output matrix

The status validator is keyed by `(kind, opcode, status)`; there is no
severity-based catch-all. The six sorted named failure arrays are exact:

```text
OPEN_FAILURES = [
  ACCESS_DENIED(0xc0000022), OBJECT_NAME_NOT_FOUND(0xc0000034),
  OBJECT_NAME_COLLISION(0xc0000035), OBJECT_PATH_NOT_FOUND(0xc000003a),
  DATA_ERROR(0xc000003e), SHARING_VIOLATION(0xc0000043),
  DELETE_PENDING(0xc0000056), DISK_FULL(0xc000007f),
  INSUFFICIENT_RESOURCES(0xc000009a), MEDIA_WRITE_PROTECTED(0xc00000a2),
  DEVICE_NOT_READY(0xc00000a3), IO_TIMEOUT(0xc00000b5),
  FILE_IS_A_DIRECTORY(0xc00000ba), NOT_SUPPORTED(0xc00000bb),
  FILE_CORRUPT_ERROR(0xc0000102), NOT_A_DIRECTORY(0xc0000103),
  CANCELLED(0xc0000120) ]                                   // 17 entries

READ_FAILURES = [
  ACCESS_DENIED(0xc0000022), DATA_ERROR(0xc000003e),
  FILE_LOCK_CONFLICT(0xc0000054), INSUFFICIENT_RESOURCES(0xc000009a),
  DEVICE_NOT_READY(0xc00000a3), IO_TIMEOUT(0xc00000b5),
  FILE_CORRUPT_ERROR(0xc0000102), CANCELLED(0xc0000120) ]   // 8 entries

WRITE_FAILURES = [
  ACCESS_DENIED(0xc0000022), DATA_ERROR(0xc000003e),
  FILE_LOCK_CONFLICT(0xc0000054), DISK_FULL(0xc000007f),
  INSUFFICIENT_RESOURCES(0xc000009a), MEDIA_WRITE_PROTECTED(0xc00000a2),
  DEVICE_NOT_READY(0xc00000a3), IO_TIMEOUT(0xc00000b5),
  FILE_CORRUPT_ERROR(0xc0000102), CANCELLED(0xc0000120),
  RETRY(0xc000022d) ]                                       // 11 entries

FLUSH_FAILURES = [
  DATA_ERROR(0xc000003e), INSUFFICIENT_RESOURCES(0xc000009a),
  MEDIA_WRITE_PROTECTED(0xc00000a2), DEVICE_NOT_READY(0xc00000a3),
  IO_TIMEOUT(0xc00000b5), FILE_CORRUPT_ERROR(0xc0000102),
  CANCELLED(0xc0000120) ]                                   // 7 entries

QUERY_FAILURES = [
  ACCESS_DENIED(0xc0000022), DATA_ERROR(0xc000003e),
  INSUFFICIENT_RESOURCES(0xc000009a), DEVICE_NOT_READY(0xc00000a3),
  IO_TIMEOUT(0xc00000b5), NOT_SUPPORTED(0xc00000bb),
  FILE_CORRUPT_ERROR(0xc0000102), CANCELLED(0xc0000120) ]   // 8 entries

MUTATE_FAILURES = [
  ACCESS_DENIED(0xc0000022), OBJECT_NAME_NOT_FOUND(0xc0000034),
  OBJECT_NAME_COLLISION(0xc0000035), OBJECT_PATH_NOT_FOUND(0xc000003a),
  DATA_ERROR(0xc000003e), SHARING_VIOLATION(0xc0000043),
  DELETE_PENDING(0xc0000056), PRIVILEGE_NOT_HELD(0xc0000061),
  INVALID_SECURITY_DESCR(0xc0000079), DISK_FULL(0xc000007f),
  INSUFFICIENT_RESOURCES(0xc000009a), MEDIA_WRITE_PROTECTED(0xc00000a2),
  DEVICE_NOT_READY(0xc00000a3), IO_TIMEOUT(0xc00000b5),
  NOT_SUPPORTED(0xc00000bb), DIRECTORY_NOT_EMPTY(0xc0000101),
  FILE_CORRUPT_ERROR(0xc0000102), NOT_A_DIRECTORY(0xc0000103),
  CANCELLED(0xc0000120), CANNOT_DELETE(0xc0000121),
  RETRY(0xc000022d), USER_MAPPED_FILE(0xc0000243) ]         // 22 entries
```

The exact per-opcode sets (union adds no other value):

| Opcode | Legal statuses |
|---|---|
| `PREPARE_OPEN` | SUCCESS, `OPEN_FAILURES` |
| `COMMIT_OPEN` | SUCCESS, RETRY, `OPEN_FAILURES` |
| `ABORT_OPEN` / `CLEANUP` / `CLOSE` | SUCCESS only |
| `READ` | SUCCESS, END_OF_FILE(`0xc0000011`), `READ_FAILURES` |
| `WRITE` | SUCCESS, `WRITE_FAILURES` |
| `FLUSH` | SUCCESS, `FLUSH_FAILURES` |
| `QUERY_INFO` / `QUERY_VOLUME` | SUCCESS, `QUERY_FAILURES` |
| `QUERY_DIR` | SUCCESS, NO_MORE_FILES(`0x80000006`), NO_SUCH_FILE(`0xc000000f`), `QUERY_FAILURES` |
| `QUERY_SECURITY` | SUCCESS, `QUERY_FAILURES` |
| `MUTATE` | SUCCESS, `MUTATE_FAILURES` |
| `REPLAY_OPEN` / `ACK_RESULT` / `PT_ROUTE_ACK` / `PT_EXTERNAL_SAFE_ACK` / `DIR_CHANGE_ACK` | SUCCESS only |
| `QUERY_OP` | SUCCESS, BUFFER_TOO_SMALL(`0xc0000023`) |
| `CANCEL` | no CQE |
| `ATTACH` | control IOCTL only; no ring completion |
| `FSCTL` | no registered request or completion |

PREPARE does not accept RETRY. PENDING(`0x00000103`),
BUFFER_OVERFLOW(`0x80000005`), reparse control statuses, all other
warning/informational values, and every unregistered error are never passed
through. `STATUS_INTEGER_OVERFLOW`(`0xc0000095`) from QueryDir generation
exhaustion is a local native IRP completion and is deliberately absent from
the provider QUERY_DIR registry; receiving it in a CQE is an unregistered
provider status.

Only a structurally empty unregistered result for the observational READ,
QUERY_INFO, QUERY_DIR, QUERY_VOLUME, or QUERY_SECURITY opcodes is
normalized to `STATUS_IO_DEVICE_ERROR`(`0xc0000185`), recorded as a
provider violation, and discarded. An unregistered result for any
state-changing, transactional, lifetime, acknowledgement, or protocol
opcode is a session protocol fault; the journaled-operation recovery rule
in §8.3 takes precedence. Any nonempty or contradictory shape is also a
session protocol fault. Adding a status requires a registry change,
exhaustive tests, and a compatible ABI-minor rule.

Only `out_len` 0 or 24 is legal:

| Case | `out_len` | `information` | Output |
|---|---:|---|---|
| PREPARE success | 24 | 136 | `OControl` echoing reply grant |
| COMMIT success | 24 | 112 | `OControl` echoing reply grant |
| MUTATE success | 24 | 112 | `OControl` echoing reply grant |
| REPLAY_OPEN success | 24 | 16 | `OControl` echoing reply grant |
| QUERY_OP success | 24 | 56 | `OControl` echoing reply grant |
| READ success | 24 | `1..=request length` | `OControl` echoing data grant, length = transferred bytes |
| WRITE success | 24 | `1..=request length` | `OControl` echoing the 56-byte `WriteResultV2` reply grant |
| QUERY_INFO / QUERY_VOLUME / QUERY_DIR success | 24 | exact valid canonical blob bytes | `OControl` echoing output grant |
| QUERY_SECURITY success | 24 | exact validated descriptor bytes, 20–65536 | `OControl` echoing descriptor grant shrunk to that length |
| BUFFER_TOO_SMALL for QUERY_OP | 0 | exact retained-op size in `{80, 112, 136, 168, 216, 224}`, greater than current capacity | zero |
| RETRY, END_OF_FILE, NO_MORE_FILES, NO_SUCH_FILE | 0 | 0 | zero |
| registered ordinary failure | 0 | 0 | zero |
| ABORT/CLEANUP/CLOSE/FLUSH/ACK_RESULT/PT ack/DIR_CHANGE_ACK success | 0 | 0 | zero |
| CANCEL | no CQE | — | — |

When `out_len` is zero, all 24 output bytes are zero. `OControl` output
uses all 24 bytes. Output on a status that forbids it, a mismatched grant,
an invalid result size, nonzero reserved/unused bytes, impossible
information, or an illegal opcode/kind combination is a protocol fault. For
QUERY_SECURITY, a provider BUFFER_TOO_SMALL with zero information and zero
output is a structurally empty unregistered observational result and
normalizes to IO_DEVICE_ERROR; any nonzero information or output on that
status is contradictory and faults the session. Neither form can supply a
native required length.

NOTIFY requires opcode 0, flags 0, request ID 0, success status, output
length 24, reserved 0, and `OControl` to a valid `NotifyEnvelopeV2`; CQ
`information`, the `OControl` length, and `NotifyEnvelopeV2.struct_size`
are the same exact total envelope-plus-body byte length (§9.1). PROTOCOL
follows the exact record in §4.8.

### 5.4 V1-to-V2 cutover legality map

The following registry-stable published layouts are excluded from the
ABI 2.1 wire. Each remains byte-stable in the crate and header for
ABI-major registry stability; none is a valid 2.1 request, result, or
notification.

NotifyEnvelopeV1 MUST NOT appear on the ABI 2.1 wire.
ABI 2.1 notifications use only the 56-byte V2 envelope with its inline
`BlobSlice` body.

AckResultV1 MUST NOT appear on the ABI 2.1 wire.
An OpId alone cannot authenticate which durable semantic operation may be
pruned; the V2 acknowledgement adds the 32-byte `operation_digest`.

QueryDirV1 MUST NOT appear on the ABI 2.1 wire.
Every directory query is `QueryDirV2` with a nonzero
`enumeration_generation`.

MutationV1 MUST NOT appear on the ABI 2.1 wire.
Every mutation is `MutationV2` with the expected security generation and
the reply/kind-result grants.

| Registry form | ABI 2.1 disposition |
|---|---|
| `PrepareOpenV1` | Superseded by `PrepareOpenV2`; rejected as a request. |
| `CommitOpenV1` | Superseded by `CommitOpenV2`; rejected as a request. |
| `ReplayOpenV1` | Superseded by `ReplayOpenV2`; rejected as a request. |
| `QueryOpV1` | Superseded by `QueryOpV2`; rejected as a request. |
| `MutationResultV1` | Superseded by `MutationResultV2`; rejected as a result. |
| `CommitOpenResultV1` | Prefix only; a 2.1 COMMIT_OPEN success returns `CommitOpenResultV2`. |
| `SetSparseV1` | Mutation kind 11 is reserved; accepted by no 2.1 validator. |
| `FsctlV1` | FSCTL registers no code; no request or completion is accepted in ABI 2.1. The kernel MUST NOT emit FSCTL. A later minor may add a code only together with its exact input/output schema, access rule, maximum sizes, and status array. |
| `SlotRef` | Byte-stable published helper; never a message token. `BufferRef.token` for kind SLOT is the generation-stamped `SlotToken` (see `02-transport.md`). |
| `DonateBackingV1` | Control-side registry layout; the wire rule is stated in `02-transport.md`. Never a ring payload. |
| `DonateSecurityContextV1` | Control-side registry layout; a well-formed authorized call returns NOT_SUPPORTED. |

`ORw` survives only as a registry-stable ABI-major layout on the READ lane;
no ABI 2.1 CQE carries that fixed 24-byte record. A READ success returns
the `OControl` data-grant echo.
WRITE returns the `WriteResultV2` reply grant.

The provider does not infer a missing grant or digest from retained
process-local state: a version-1 request form observed on a 2.1 session is
rejected before any provider execution, and a version-1 result or envelope
form produced by the provider is a session protocol fault.

## 6. Transactional OPEN and ordering

`PREPARE_OPEN` is non-mutating. It resolves the parent/name and returns
stable file/link identities, a nonzero `TransactionId`, size state,
namespace/security generations, and a self-relative security descriptor in
the exactly-65536-byte result-SD grant. The kernel validates that
descriptor and performs authorization, traversal, share-access, oplock,
delete-pending, and cache-policy decisions. `PrepareOpenV2` carries the
optional create security descriptor and EA by value; both are validated by
the kernel before submission and are included by value in the durable
digest where applicable.

`COMMIT_OPEN` carries the stable `op_id`, the prepared transaction, exact
expected generations, `kernel_open_id`, and the access actually granted by
the kernel. The daemon atomically applies create/overwrite/supersede
semantics. A stale prerequisite returns `STATUS_RETRY` without partial
namespace mutation. `ABORT_OPEN` releases the prepared transaction.

The provider-open cookie is session-local authority; it may appear in an
ordinary `CommitOpenResultV2` but MUST NOT be stored in a durable committed
result. `kernel_open_id`, `FileId`, `LinkId`, granted access/share state,
and the per-CCB sequence survive replay; recovery obtains a fresh cookie
through `REPLAY_OPEN` on the ring's reserved open-lifecycle lane. CLEANUP
is a barrier after all earlier requests for that CCB; CLOSE follows the
unique terminal CLEANUP completion.

### 6.1 Restart-stable two-phase CREATE

PREPARE_OPEN and COMMIT_OPEN are phases of one logical native CREATE, not
two independent application requests. The CREATE occupies one application
request-table slot from its first Prepare publication until Prepare failure
or a successful Commit/Abort and, when journaled, the final ACK. Each wire
phase — Prepare retry, Commit, `AbortOpenV1`, QueryOp, AckResult, and any
bounded QueryOp BUFFER_TOO_SMALL retry — reuses that slot index with a
fresh nonzero generation, so `max_inflight = 1` makes progress.
`PrepareOpenV2` and `CommitOpenV2` carry the same nonzero OpId for the
logical CREATE; it keys the open-prepare record before commit and the
physical journal bundle/digest at commit. No other logical operation may
use that OpId within the MountId.

Before returning PREPARE_OPEN success, the provider creates a
restart-stable open-prepare record keyed by `(MountId, Prepare OpId)`. The
record contains the exact semantic Prepare request by value — parent,
validated name, requested security descriptor and EA, desired/share access,
disposition, create options, file attributes, and open flags — plus the
exact successful Prepare result and its nonzero `TransactionId`. BufferRef
coordinates, ReqId, grants, and session epoch are excluded. The same OpId
with the same semantic bytes is idempotent and returns the same
TransactionId/result; reuse with different bytes is a protocol fault. The
TransactionId uniquely indexes that record within the MountId.
`MAX_RETAINED_PREPARE_BYTES_PER_MOUNT = 67108864` bounds the retained
Prepare state.

When HOT_RESTART+EXACTLY_ONCE is selected, the record and all variable
bytes survive process exit, session fencing, and ATTACH. The kernel retains
the bounded semantic inputs and one of the exact phases `PREPARE_UNSENT`,
`PREPARE_MAY_BE_VISIBLE`, `PREPARE_SUCCEEDED`, or `PREPARE_FAILED`.
PREPARE_SUCCEEDED is never forgotten or downgraded at ATTACH: it continues
with the exact Commit, or the exact Abort if cancellation won, without
allocating a second logical CREATE. Without the paired restart features,
session loss tears down the mount and ordinary provider cleanup retires the
boot-local open-prepare/index pair.

COMMIT_OPEN resolves the exact TransactionId index, requires its OpId to
equal the Commit OpId, exact-queries the open-prepare record, and verifies
its stored semantic fields against the retained request and operation
digest. With the restart pair, a successful commit atomically performs the
filesystem transaction, the complete PREPARED-to-COMMITTED journal-bundle
transition, the OPEN(LIVE) row creation, and the retirement of the
open-prepare/index pair. Without the pair it performs the filesystem
transaction and retires the pair but creates no journal bundle or digest.
A registered non-success Commit removes/refunds its complete PREPARED
bundle before CQ publication but keeps the open-prepare/index pair
reusable, because an unseen failure candidate may legally cause the exact
Commit to be attempted again.

After QueryOp NOT_FOUND confirms a visible failure or cancellation, the
kernel publishes the idempotent `AbortOpenV1 { transaction_id }` on the
same logical slot before completing the native IRP. ABORT deletes only the
exact retained open-prepare/index pair; joint absence succeeds, while a
one-sided or mismatched pair is corruption. Session loss at any point
retains the slot and retries that ABORT after ATTACH. Neither timeout nor
daemon exit discards a prepared open transaction.

The QueryOp `ABORT_IF_PREPARED` operation deletes/refunds only the complete
journal PREPARED bundle; for COMMIT_OPEN the separate open-prepare/index
pair remains until the kernel's ABORT_OPEN or a successful Commit. A
non-cancelled NOT_FOUND can therefore resubmit the exact Commit with the
original TransactionId and inputs — including after a crash between
Prepare success and the journal-bundle ABSENT-to-PREPARED transaction —
while a cancelled one follows the mandatory ABORT_OPEN subprotocol before
completing.

## 7. READ, WRITE, and `SizeState`

`MAX_FILE_SIZE = 0x7fff_ffff_ffff_ffff` (`i64::MAX`). Every wire field that
represents allocation size, EOF/file size, VDL, file offset, byte-range
end, or a native volume byte total is an unsigned encoding of a value in
`[0, MAX_FILE_SIZE]` and is rejected before conversion to `LARGE_INTEGER`
otherwise. Every accepted size state satisfies:

```text
MAX_FILE_SIZE >= allocation_size >= file_size >= valid_data_length
```

For a nonempty file byte range, checked arithmetic must prove
`offset < MAX_FILE_SIZE`, `1 <= length <= MAX_FILE_SIZE`, and
`offset + length <= MAX_FILE_SIZE`. A schema whose zero length means the
whole stream additionally requires offset zero. These rules apply uniformly
to READ/WRITE, `SizeState` in every request/result/notification, size
mutations, committed results, query metadata, RESIZE, INVALIDATE_FILE, and
native volume conversions; no opcode may fall back to unsigned wrap or an
implementation-defined volume maximum.

`size_epoch` serializes the kernel mirror and durable provider metadata. A
successful size-changing result must contain the exact expected next epoch.
A skipped, repeated, or stale epoch triggers retry/reconciliation, never
silent acceptance.

READ uses `OpId::ZERO`, an inline `PRw`, and a U2K-writable data grant of
the requested capacity. WRITE uses a nonzero durable `op_id`, a `PControl`
whose K2U body is exactly one validated `WriteV2`, a K2U data grant of
exactly the request length, and a U2K reply grant of at least 56 bytes. The
enclosing SQE `kernel_open_id`, the `WriteV2` expected size epoch,
offset/length, and the retained FCB identity must all describe the same
live request before either the data or the reply grant is exposed.

Every actual paging READ/WRITE is stream-owned: its outer `kernel_open_id`
is nonzero, its outer `ccb_sequence` is zero, and PAGING is set. Ordinary
nonpaging READ/WRITE and native user mutations require a nonzero current
CCB sequence. Zero sequence on another opcode/provenance, PAGING with a
nonzero sequence, or a stream request whose open row/replay mode is not
LIVE-ordinary or CLEANED-PAGING_ONLY is a protocol fault.

Zero-length READ/WRITE is completed in the kernel and never emitted. For an
emitted request, data length equals the nonzero request length, initialized
length does not exceed it, and every offset/length/end calculation
satisfies `MAX_FILE_SIZE`. Unknown rw-flag bits and a nonzero reserved
field fail before submission. A successful emitted READ or WRITE transfers
`1..=request_length` bytes. A read with no byte available at EOF uses
END_OF_FILE with zero information; SUCCESS with zero information is illegal
for both opcodes. Windows 7 application WRITE may use a kernel-owned K2U
copy slot instead of a protected MDL mapping; message semantics do not
change.

Extending and paging writes carry the initialized range and size epoch.
Logical VDL advances only after the corresponding cache bytes contain
written data or zeros. Recoverable VDL advances only after the provider can
reconstruct those initialized bytes. No result may expose uninitialized
bytes above VDL.

## 8. Mutation, replay, and durable results

When the paired HOT_RESTART+EXACTLY_ONCE features are selected, exactly
COMMIT_OPEN, WRITE, and MUTATE are journaled in base 2.1; all three use the
PREPARED/COMMITTED/QUERY_OP/ACK_RESULT protocol. When the pair is not
selected, none of them creates a durable journal bundle or digest, QUERY_OP
and ACK_RESULT are never emitted, daemon loss tears the mount down, and no
operation is replayed into another session. The three operations still
carry unpredictable nonzero OpIds unique within the MountId for transaction
correlation and duplicate-fault detection in the live session.

The provider durably records PREPARED (`op_id`, digest, prerequisites)
before an effect can become ambiguous and COMMITTED (`op_id`, complete
result) before returning success. Reusing an `op_id` with a different
digest is a protocol fault.

`ReplayOpenV2` reconstructs one CCB, not merely one FCB, and produces a
fresh session-local provider cookie. REPLAY_OPEN has no durable child row,
reservation, or accounting charge; per bound session the provider keeps
bounded volatile replay state keyed by `(session_epoch, kernel_open_id)`
(`UNSEEN -> PENDING -> DONE`). An exact duplicate in the same epoch
serializes with PENDING or returns the identical DONE cookie; a changed
duplicate is a protocol fault. Zero state flags require an OPEN row in
LIVE; PAGING_ONLY requires CLEANED; ABSENT always faults. `AttachV1` is
accepted only on the authenticated control channel bound to the authorized
daemon process, mount identity, and fresh session.

### 8.1 Operation digest

Journal v1 uses SHA-256 over this exact 64-byte little-endian prefix
followed by exactly `semantic_length` semantic bytes (domain
`FSRING-OP-DIGEST`):

```text
+0  domain:[u8;16]        = ASCII "FSRING-OP-DIGEST"
+16 digest_format:u16     = 1
+18 abi_major:u16         = 2
+20 journal_version:u32   = 1
+24 mount_id:MountId
+40 op_id:OpId
+56 opcode:u16            // COMMIT_OPEN, WRITE, or MUTATE only
+58 mutation_kind:u16     // zero unless opcode is MUTATE
+60 semantic_length:u32
    semantic_bytes[semantic_length]
```

Canonical transcript structures are serialized field-by-field in the order
below; identities are `lo` then `hi`, all integers are little-endian, and
there is no compiler padding. ReqId, session epoch, BufferRef
coordinates/tokens, reply grants, and provider-open cookies never occur in
a transcript. Transcript slices are relative to the start of
`semantic_bytes`.

```text
CommitOpenDigestV1: 112-byte fixed semantic prefix
  +0   parent_id:FileId
  +16  transaction_id:TransactionId
  +32  kernel_open_id:u64
  +40  expected_namespace_generation:u64
  +48  expected_security_generation:u64
  +56  desired_access:u32     +60 share_access:u32
  +64  disposition:u32        +68 create_options:u32
  +72  file_attributes:u32    +76 open_flags:u32
  +80  granted_access:u32     +84 commit_flags:u32
  +88  name:BlobSlice
  +96  requested_security_descriptor:BlobSlice
  +104 ea:BlobSlice

WriteDigestV1: 72-byte fixed semantic prefix
  +0   file_id:FileId
  +16  kernel_open_id:u64
  +24  offset:u64
  +32  size_epoch:u64
  +40  initialized_offset:u64
  +48  length:u32             +52 initialized_length:u32
  +56  rw_flags:u32           +60 reserved:u32 = 0
  +64  data:BlobSlice

MutationDigestV1: 64-byte fixed semantic prefix
  +0   file_id:FileId
  +16  kernel_open_id:u64
  +24  expected_namespace_generation:u64
  +32  expected_size_epoch:u64
  +40  expected_security_generation:u64
  +48  mutation_kind:u16      +50 mutation_flags:u16
  +52  body_length:u32
  +56  body:BlobSlice
```

Commit tails are the nonempty name, SD, and EA values concatenated in that
order starting at byte 112; an absent value is `{0,0}` and creates no gap.
Write data starts at byte 72 and its slice length equals the request
length. The mutation body starts at byte 64, its slice length equals
`body_length`, and its bytes are the canonical validated mutation control
blob from byte zero through its `struct_size`, including the fixed
`ControlHeader` and explicit zero reserved fields. Mutation bodies permit
no optional extension. There are no gaps, tail padding, aliases, overlaps,
or bytes after the final slice; `semantic_length` equals the complete
fixed-prefix-plus-tail length.

When EXACTLY_ONCE is selected, WRITE semantic bytes come only from a
kernel-owned immutable snapshot with no application-writable alias; the
digest is computed from that same snapshot and retained through PREPARED
recovery until a terminal result and ACK/rundown.
`MAX_JOURNALED_WRITE_BYTES_PER_REQUEST = 16777216` and
`MAX_IMMUTABLE_WRITE_BYTES_PER_MOUNT = 268435456`; larger application
writes are split in CCB order into independently identified chunks, each
with its own OpId/digest and CQ byte count, while the parent IRP reports
the ordered committed prefix. Without EXACTLY_ONCE, `WriteV2` remains the
wire form but an original-IRP MAPPING may use the negotiated zero-copy
path.

### 8.2 Durable committed results

Layouts are §4.10. Result kinds are `INVALID = 0`, `EMPTY = 1` (reserved,
never emitted in base 2.1), `COMMIT_OPEN = 2`, `WRITE = 3`, and
`MUTATION = 4`. `CommittedResultV1.status` is exactly SUCCESS and its
`volume_commit_sequence` is nonzero. COMMIT_OPEN and MUTATION information
is zero; WRITE information is the committed byte count bounded by the
original request. The outer payload begins at byte 40 and contains exactly
the matching inner result blob. A committed mutation `kind_payload` is
`{0,0}` except for RENAME/LINK/UNLINK, whose exact §4.4 result record
follows inline. Every committed flags/reserved field is zero. No durable
payload contains a session token or provider cookie.

The derived committed-result total size is fixed by the retained request:

```text
WRITE          = 80    COMMIT_OPEN = 136   base mutation = 112
UNLINK         = 168   LINK        = 216   RENAME        = 224
derived size set = {80, 112, 136, 168, 216, 224}
MAX_COMMITTED_RESULT_BYTES = 224
```

Candidate-to-durable equality is field-for-field after excluding only the
explicitly session-local open cookie: the COMMIT_OPEN outer sequence equals
`CommitOpenResultV2.volume_commit_sequence` and the inner identities,
sizes, generations, create result, and flags equal the ordinary result;
the WRITE outer sequence equals `WriteResultV2.volume_commit_sequence`,
outer information equals CQ information, and the inner `sizes` equal
`WriteResultV2.sizes`; the MUTATE outer sequence equals
`MutationResultV2.volume_commit_sequence` and the inner kind, flags,
sizes, generations, and exact inline kind payload equal the validated
ordinary result and its referenced kind-result blob.

### 8.3 QUERY_OP, acknowledgement, and cancellation

When EXACTLY_ONCE is selected, an ordinary successful COMMIT_OPEN, WRITE,
or MUTATE CQE is only a candidate result: the kernel privately snapshots
it, then issues `QueryOpV2` on the authenticated live session with the same
OpId and operation digest and validates the durable read-back before
applying anything. One logical journaled operation occupies one
`max_inflight` slot through confirmation and acknowledgement; QUERY_OP,
every legal BUFFER_TOO_SMALL retry, and ACK_RESULT reuse the same slot
index with the next nonzero generation.

`MAX_QUERY_OP_BTS_RETRIES = 1`. Recovery allocates the exact derived
capacity initially. If an already-issued smaller recovery grant receives
BUFFER_TOO_SMALL, one retry is legal only when CQ information equals the
exact derived size, is strictly greater than the current grant capacity,
and no prior BTS retry occurred. Repeated, equal/decreasing, wrong-size, or
out-of-range BTS is a protocol fault. BUFFER_TOO_SMALL against the ordinary
confirmation's 224-byte grant is always a protocol fault. A legal retry
changes no journal, candidate, cancellation, or retained-operation state.

`ABORT_IF_PREPARED` (`QueryOpV2.header.required_flags = 0x0001`) is legal
only for a retained NO_CANDIDATE operation whose application IRP was
cancelled after possible SQ publication; every other `QueryOpV2` carries
zero required flags. The provider handles the query and the physical
journal bundle in one atomic transaction: an exact PREPARED bundle is
deleted/refunded and reported NOT_FOUND; complete ABSENT reports NOT_FOUND;
an exact COMMITTED bundle is left untouched and reported COMMITTED with its
durable result. Abort mode can never report PREPARED. A digest mismatch is
a protocol fault, and every partial bundle is corruption.

The retained phases are `NO_CANDIDATE`, `FAILURE_CANDIDATE`,
`SUCCESS_CANDIDATE`, `INVALID_CANDIDATE`, `COMMITTED_VERIFIED`,
`APPLIED_NOTIFY_PENDING`, `APPLIED_ACK_UNSENT`, `APPLIED_ACK_SENT`,
`ACKNOWLEDGED`, and `INDETERMINATE`. The closed phase-by-answer table is:

| Retained phase | NOT_FOUND | PREPARED | COMMITTED |
|---|---|---|---|
| `NO_CANDIDATE` | cancelled: WRITE/MUTATE complete CANCELLED; COMMIT_OPEN first runs the retained ABORT_OPEN subprotocol. Otherwise resubmit the exact OpId/digest/request | cancelled: issue the atomic `ABORT_IF_PREPARED` query; otherwise resume that exact transaction | validate retained request/digest/result, then `COMMITTED_VERIFIED` |
| `FAILURE_CANDIDATE` | WRITE/MUTATE complete the exact saved registered failure; COMMIT_OPEN first runs the ABORT_OPEN subprotocol, then completes it | protocol contradiction: `INDETERMINATE` | durable success is authoritative; validate it, record the provider violation, then `COMMITTED_VERIFIED` |
| `SUCCESS_CANDIDATE` | `INDETERMINATE`; never resubmit | `INDETERMINATE`; never resume/resubmit | require exact candidate projection equality, then `COMMITTED_VERIFIED`; mismatch is `INDETERMINATE` |
| `INVALID_CANDIDATE` | `INDETERMINATE`; never resubmit | `INDETERMINATE`; never resume/resubmit | ignore the candidate; validate the durable result against the original request/digest, record the violation, then `COMMITTED_VERIFIED` |
| `COMMITTED_VERIFIED` | protocol fault: `INDETERMINATE` | protocol fault: `INDETERMINATE` | exact repeat; enter fence-excluded APPLYING, apply once, then `APPLIED_NOTIFY_PENDING` |
| `APPLIED_NOTIFY_PENDING` | illegal pre-ACK pruning: `INDETERMINATE`; never reapply | protocol fault: `INDETERMINATE` | exact repeat; deliver the staged local event or cover it by rescan, then `APPLIED_ACK_UNSENT` |
| `APPLIED_ACK_UNSENT` | illegal pre-ACK pruning: `INDETERMINATE`; never reapply | protocol fault: `INDETERMINATE` | prepare ACK_RESULT, enter `APPLIED_ACK_SENT` before its publication Release, then publish |
| `APPLIED_ACK_SENT` | prior ACK deletion succeeded and its CQE was lost: `ACKNOWLEDGED` | protocol fault: `INDETERMINATE` | retry the identical ACK_RESULT; never reapply |
| `ACKNOWLEDGED` | no QueryOp is emitted | no QueryOp is emitted | no QueryOp is emitted |
| `INDETERMINATE` | administrative teardown only | administrative teardown only | administrative teardown only |

Only NO_CANDIDATE may resubmit a semantic operation, and it always reuses
the same OpId/digest/bytes. INDETERMINATE is fail-closed: the kernel blocks
new mount I/O, conservatively invalidates caches, records a
journal-integrity violation, sends no ACK, and permits only bounded
administrative teardown; affected IRPs complete FILE_CORRUPT_ERROR with
zero information only after the mount is quarantined.

If a journaled operation returns any registered non-success terminal status
(including RETRY), the provider must prove that no side effect was
committed and atomically delete/refund its exact PREPARED bundle before
publishing that CQE; the kernel confirms with QueryOp and only NOT_FOUND
allows the IRP to complete with the saved failure. A PREPARED bundle is
never silently pruned because of timeout or live-mount session loss.

`AckResultV2 { op_id, operation_digest }` is published only after the local
notification descriptor is DELIVERED or COVERED_BY_RESCAN. The provider
atomically deletes/refunds only the exact COMMITTED bundle matching both
values before returning ACK_RESULT success. ACK_RESULT is idempotent only
when the complete bundle and all of its reservations are absent; a partial
bundle or any present row with the same OpId and a different digest is
corruption and cannot be inferred as a prior ACK. A clean DETACH is
DEVICE_BUSY while any retained request is PREPARED/COMMITTED or any ACK is
outstanding.

`PCancel` is an advisory, slot-free record with this one legal SQE
encoding: opcode CANCEL, flags `NO_COMPLETION`, `payload_len = 16`,
reserved zero, outer `req_id = 0`, `kernel_open_id = 0`,
`ccb_sequence = 0`, `PCancel.target_req_id` equal to the currently live
semantic ReqId, `target_session_epoch` equal to that generation's current
session epoch, and all unused payload bytes zero. CANCEL consumes no
request-table entry, advances no ReqId generation, and receives no CQE. It
is published on the same SQ ring after the target semantic cell and may
target only a still-live application semantic generation — never QUERY_OP,
ACK_RESULT, PREPARE/REPLAY_OPEN recovery control traffic, or PT/external
acknowledgements. A stale or duplicate target is ignored by the provider
without completion.

## 9. Notifications and acknowledgement lanes

### 9.1 NOTIFY completion shape

A notification CQE has `kind = NOTIFY`, opcode 0, flags 0, `req_id = 0`,
success status, reserved 0, `out_len = 24`, and `out = OControl` pointing
at one valid `NotifyEnvelopeV2` in a notification credit. CQ `information`,
the `OControl` length, and `NotifyEnvelopeV2.struct_size` are the same
exact total envelope-plus-body byte length. The envelope's `notify_code`
selects one of the ten registered codes (§2.4); the inline body begins at
byte 56 and its length equals the selected body's `struct_size`.

### 9.2 Notification validity and merge rules

Content, namespace, PT, size, and volume-commit epochs/sequences are
nonzero. For `InvalidateFileV1` and single-name `InvalidateEntryV1`, a
generation at or below retained state is structurally valid but never
suppresses the payload: every validated range/name invalidation is repeated
idempotently, and a greater generation also advances retained state
atomically. Precise namespace insertion/removal is only an optimization;
the fallback is conservative invalidation.

`ResizeV1` validates the §7 size invariants, a nonzero `size_epoch`, and a
nonzero `volume_commit_sequence`, then merges under the two-key rule: for a
lower volume sequence, a lower size epoch is stale and discarded, an equal
epoch is discarded only when the complete SizeState matches retained state,
and a higher epoch is a causal protocol fault; an equal volume sequence
requires the complete SizeState to match; for a greater volume sequence, a
lower epoch is a protocol fault, an equal epoch requires the complete
SizeState to match and advances only the retained sequence, and a greater
epoch applies the complete SizeState and both counters atomically.

`PtGrantV1` must match a prior authenticated current-session backing
donation for the same FileId, exact PT epoch, supported power-of-two sector
size, and a state with no active grant; an exact duplicate of an applied
grant is idempotent, a lower different grant is stale and ignored, and an
unknown greater epoch is a protocol fault. PT_REVOKE_ROUTE and
PT_EXTERNAL_MUTATION_SAFE must match the exact live transition epoch; for
an acknowledgement-required code, an older epoch with a new token is a
protocol fault.

### 9.3 AckToken encoding and PT acknowledgement lanes

AckToken has a closed, mount-scoped lane/ordinal encoding:

```text
ACK_TOKEN_HI_TAG  = 0x465352494e470000     // ASCII "FSRING" << 16
ACK_TOKEN_HI_MASK = 0xffffffffffff0000
token.lo          = nonzero per-lane ordinal
token.hi          = ACK_TOKEN_HI_TAG | (kind_ordinal << 8) | ring_index
kind_ordinal      = 1 for PT_REVOKE_ROUTE
                    2 for PT_EXTERNAL_MUTATION_SAFE
                    3 for external DIR_CHANGE
ring_index        = bits 0..5; bits 6..7 are zero;
                    exactly zero for kind 3
```

For each `(MountId, ring, kind)` lane, a new token ordinal is exactly the
retained high-watermark plus one; it is never skipped, reused, or wrapped.
INVALIDATE_FILE, INVALIDATE_ENTRY, PT_GRANT, RESIZE, PT_LANE_READY,
EXTERNAL_CHANGE_READY, and EXTERNAL_CHANGE_CUT require AckToken zero.
PT_REVOKE_ROUTE and PT_EXTERNAL_MUTATION_SAFE require a nonzero AckToken
and their distinct SQ acknowledgement opcodes carrying `PNotifyAck` with
the exact envelope token and the PT epoch; DIR_CHANGE requires the inline
`PDirChangeAckV1` (§9.5).

`MAX_OUTSTANDING_PT_ACKS_PER_KIND_PER_RING = 1`: exactly one pending
acknowledgement-required PT notification exists per lane, and provider lane
storage is exactly `{latest_processed?, pending?}`. On receiving
`PNotifyAck`, the provider accepts either its exact PENDING tuple (performs
the transition, replaces latest_processed, posts SUCCESS) or an exact
repeat of latest_processed (posts duplicate SUCCESS without repeating the
transition). Unknown, lower, skipped, cross-lane, or tuple-mismatched
values are protocol faults. After ATTACH the kernel prepublishes one
idempotent reconciliation `PNotifyAck` probe on every lane whose
high-watermark is nonzero; the provider drains a lane's probe before
publishing any notification on that lane.

`PtLaneReadyV1` (code PT_LANE_READY) is legal only while the session is in
PT reconciliation: `kind_ordinal` is exactly 1 or 2, the owning CQ ring
supplies the lane, envelope FileId and AckToken are zero, and
`high_watermark` is the provider's durable processed high-watermark for
that lane. The kernel verifies it equals its own retained value. An exact
duplicate before PT activation is idempotent; an early, cross-lane,
mismatched, backward/skipped-watermark, or post-activation READY is a
protocol fault. No PT fast path is enabled until READY has been consumed
for both kinds on every ring and open replay is complete.

### 9.4 Local causal notification map

Every provider-backed local state change stages one kernel event descriptor
from the retained request plus verified result; the provider MUST NOT
publish DIR_CHANGE for an OpId-backed transaction, and its change collector
suppresses those backing changes by OpId. Observing an external record
whose volume sequence is already owned by retained operation provenance, or
the converse, is a protocol fault.

| Committed operation | Native event and exact filter |
|---|---|
| COMMIT_OPEN CREATED | ADDED; FILE_NAME `0x1` or DIR_NAME `0x2` from the returned type |
| COMMIT_OPEN OPENED | none |
| COMMIT_OPEN OVERWRITTEN | MODIFIED; SIZE+LAST_WRITE `0x18` |
| COMMIT_OPEN SUPERSEDED | rescan; the base result lacks the complete replaced-link identity |
| WRITE | MODIFIED; LAST_WRITE `0x10`, plus SIZE `0x8` iff allocation/EOF changed |
| SET_BASIC_INFO | OR of CREATION `0x40`, LAST_ACCESS `0x20`, LAST_WRITE `0x10`, and ATTRIBUTES `0x4` for selected attributes or ChangeTime |
| SET_ALLOCATION_SIZE / SET_END_OF_FILE | MODIFIED; SIZE `0x8` iff SizeState changed |
| SET_VALID_DATA_LENGTH | MODIFIED; LAST_WRITE `0x10` |
| RENAME | atomic OLD+NEW pair; a replacement REMOVED precedes the pair |
| LINK | ADDED; a replacement REMOVED precedes ADDED |
| UNLINK | REMOVED |
| SET_SECURITY | MODIFIED; SECURITY `0x100` |
| READ / QUERY forms / FLUSH / CLEANUP / CLOSE | none |

The name filter uses the target object's exact file/directory kind. A
successful no-op with no mapped category stages nothing. Delete-on-close
commits through the same UNLINK result path; CLEANUP cannot hide namespace
deletion. For a multiply linked file the metadata/data rows expand to every
live link or to rescan under the
`MAX_PRECISE_NOTIFY_LINKS_PER_LOCAL_OPERATION = 64` bound. The source IRP
and ACK_RESULT publication wait until the staged event is DELIVERED or
COVERED_BY_RESCAN; post-commit cancellation does not suppress the event.

### 9.5 Durable external-change lane

Every provider/external mutation not initiated by an FSRING OpId MUST
atomically commit either one or more precise external-change outbox rows or
one covering OVERFLOW row together with the backing effect; a detected gap
becomes OVERFLOW, and silence is never a fallback. External RESIZE performs
its cache-coherence notification and the same transaction appends one
DIR_CHANGE per affected live link or an overflow.

```text
MAX_DURABLE_EXTERNAL_OUTBOX_RECORDS = 4096
MAX_DURABLE_EXTERNAL_OUTBOX_BYTES   = 8388608
MAX_OUTSTANDING_EXTERNAL_CHANGE     = 1
```

Only 4095 slots and all but 2048 bytes admit precise rows; one slot and
2048 bytes are permanently reserved for overflow. Outbox ordinals are
nonzero, contiguous, and nonwrapping; the published head is immutable. If a
precise tail cannot fit, one transaction replaces every nonpublished tail
row with an OVERFLOW spanning the earliest discarded through newest
ordinal.

For precise records, `first_ordinal == through_ordinal != 0`, and the
volume sequence, envelope target FileId, target LinkId, target generation,
relevant parent IDs/generations, and relevant names are nonzero. ADD/MODIFY
use only the new parent/name; REMOVE uses only the old; RENAME uses both.
Same-directory rename has equal parents/generations; a byte-identical
same-parent rename is invalid while a case-only byte change is valid.
Replacement FileId/LinkId/generation are all zero or all nonzero and only
for ADD/RENAME. A precise name change uses exactly FILE_NAME `0x1` for
FILE or DIR_NAME `0x2` for DIRECTORY; MODIFY uses a nonzero subset of
`0x000001fc` and has no replacement. Flags/reserved are zero. OVERFLOW has
nonzero `first_ordinal <= through_ordinal`, its highest covered volume
commit sequence, and zero envelope FileId, object identities, object kind,
filter, parents, generations, and slices. No external record is split into
OLD and NEW wire messages.

DIR_CHANGE is ring-zero and acknowledgement-required. Its AckToken lane is
kind 3 with ring index zero: `token.lo = first_ordinal` and
`token.hi = ACK_TOKEN_HI_TAG | (3 << 8)`. The acknowledgement is the
`DIR_CHANGE_ACK` SQE with `payload_len = 64` carrying `PDirChangeAckV1`
inline; all four fields MUST equal the retained canonical event tuple, and
the digest is never reconstructed from only an ordinal range:

```text
semantic_digest = SHA256(
  ASCII "FSRING-EXTERNAL-DIR-CHANGE-v1\0" ||
  MountId.lo_le || MountId.hi_le ||
  canonical NotifyEnvelopeV2 bytes through struct_size)
```

Session credit and BufferRef coordinates are excluded from the digest
image. A new record starts exactly at the kernel external high-watermark
plus one; precise records advance one ordinal, overflow advances through
its range. An exact latest duplicate is not applied twice and is re-ACKed;
a changed duplicate, old non-latest record, gap, overlap, wrong ring/token,
or second published record is a protocol fault. Credit return is only
transport ownership and never authorizes outbox deletion. No next external
record may be CQ-published until the previous acknowledgement's SUCCESS
Release; ring-zero FIFO is the ordering barrier.

At ATTACH the provider first publishes `EXTERNAL_CHANGE_CUT`
(`ExternalChangeCutV1`, ring zero, envelope FileId/AckToken/flags zero)
carrying the durable stored cut before any probe or row. The kernel accepts
it once and requires its high-watermark to be at most the cut. The kernel
then sends an idempotent `DIR_CHANGE_ACK` probe containing the complete
retained `PDirChangeAckV1` when its high-watermark is nonzero; no
zero-token probe is sent. The provider compares token, range, volume
sequence, and digest against the exact durable head or latest-processed
tuple, then drains every row in `(kernel_high_watermark, attach_cut]`.
Post-cut rows remain queued. After the final ACK SUCCESS Release it
publishes `ExternalChangeReadyV1` (code EXTERNAL_CHANGE_READY, ring zero)
with `reconcile_cut == processed_high_watermark ==` the stored attach cut.
The kernel requires the stored cut, the provider processed high-watermark,
and its own high-watermark all equal. An early, mismatched, cross-ring,
backward, or post-active READY is a protocol fault; an exact duplicate
before activation is idempotent. Both READY watermarks may be zero only
when the ordinal counter, stored cut, and kernel high-watermark are all
zero. On initial SETUP the lane starts at zero and needs no READY
handshake. Only after READY and all PT/open replay barriers does ATTACH
reopen Windows notify admission.

A fence preserves the external high-watermark/latest tuple and every
captured or ACK-visible state; a record beyond the old stable prefix
remains in the provider outbox and is republished with a fresh session
credit. For restart mounts the outbox and latest-processed tuple are
durable MountId children; for nonrestart mounts the same bounded state
machine lives in volatile provider memory and is destroyed on daemon
loss/direct teardown.

## 10. Failure and validation policy

- A malformed reserved field, impossible length/range, wrong buffer
  direction, contradictory identity/epoch/generation, or impossible
  completion kind is hostile input. Persistent contradiction is a
  session-level `PROTOCOL_FAULT`.
- Unknown optional control tails are skipped where the schema permits a
  tail. Unknown required flags produce a deterministic unsupported request
  or negotiation result. Digestable mutation bodies reject any tail.
- Provider statuses are accepted only from the closed per-opcode registry
  in §5.3. Structurally empty unregistered observational results are
  normalized to IO_DEVICE_ERROR; every other unregistered or contradictory
  result is a session protocol fault.
- Resource/transient failures are bounded; kernel code never spins or
  allocates without a bound based on daemon-controlled input.
- Daemon death/restart is not reported as an arbitrary provider status. It
  invalidates the session and follows GRACE/attach/replay or teardown
  policy; with the restart pair, the journaled-operation table in §8.3
  governs every ambiguous outcome.
- A failed result does not authorize reading output fields unless that
  opcode's registry explicitly defines a needed-length convention (QUERY_OP
  BUFFER_TOO_SMALL is the only one).
- No decoded handle, pointer, buffer token, object identity, or provider
  status is trusted merely because its bytes fit the declared layout.

## 11. Completeness ledger

This registry contains all machine-exported message values and layouts:

- 22 opcodes;
- 3 CQ kinds;
- 10 notification codes and 3 acknowledgement-lane kind ordinals;
- 10 protocol-feature bits and 4 OS-capability bits;
- 3 buffer kinds and 2 buffer-access values;
- 1 SQE flag, 7 READ/WRITE flags, 3 directory-query flags, 1
  directory-result flag, 1 rename flag, 1 link flag, and 1 QUERY_OP
  required flag;
- 12 mutation kinds (kind 11 reserved), 4 QUERY_OP states, 2 journal
  versions, 5 committed-result kinds (EMPTY reserved), and 6
  create-information constants (0–3 wire-legal);
- 6 named failure arrays totalling 73 status entries, 1 PROTOCOL record,
  and 1 normalization status; and
- 75 public message structures — the `ControlHeader` prefix in §3 plus the
  complete §4 catalogue (74 layouts across §4.1–§4.10), including every
  registry-stable form that §5.4 excludes from the 2.1 wire.

The catalogue also records both ring-envelope required-zero fields, every
fixed payload tail, and every named `reserved` field in its structure row.
Every numeric subregistry cited above is closed in this document and is
transcribed from the Rust registry; none is inferred from removed 2.0
material.
