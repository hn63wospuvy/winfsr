# 09 - ABI 2.1 security, trust boundary, and hostile-input validation

Status: normative for FSRING ABI 2.1. This document defines the complete
kernel/daemon trust boundary: control-device authorization for the
authenticated control IOCTL registry, the access-decision model for CREATE
and the SD round-trip opcodes, the memory-protection rule for the
daemon-facing MAPPED tier, the `SlotToken`/K2U/U2K grant-direction
discipline that makes a daemon-supplied buffer reference safe to resolve,
the exhaustive per-field CQE validation table for every wire struct a
hostile daemon can forge, and the protocol-fault/quarantine disposition
that a malformed or contradictory daemon answer drives the session toward.
It supersedes the 2.0 security draft in full; no 2.0 access-check sequence,
optional security mode, or token-donation roadmap item survives into 2.1.

The authoritative registries for this document are the unpacked crate
sources `fsring-abi/src/slots.rs` (`SlotToken`, `resolve_slot`,
`validate_buffer_ref`), `msgs/common.rs` (`buffer_access::K2U_READ_ONLY`,
`U2K_WRITE`, `buffer_kind`), `msgs/mutation.rs` (`SetSecurityV1`,
`security_information`), `msgs/query.rs` (`QuerySecurityV1`), `msgs/notify.rs`
(`DonateSecurityContextV1`), `validate/messages.rs` (the
`MUTATE_FAILURES`/`INVALID_SECURITY_DESCR` status registry, the
`CompletionDispositionV21`/`SessionProtocolFault` classification, the
`QueryOpTableActionV21::ExactlyOnceProtocolFault` and
`AttachBarrierV21`/`PtLaneAckActionV21::ProtocolFault` dispositions),
`validate/queries.rs` (the `QuerySecurityV1`/`QueryDirV2`/`DirEntryV1`
validators), `features.rs` (`protocol_feature::SECURITY`,
`BASE_REQUIRED_PROTOCOL_MASK`, `protocol_feature::TOKEN_DONATION`,
`UNSELECTABLE_PROTOCOL_MASK`), `ids.rs` (`ReqId` generation/index split), and
`limits.rs` (`MIN_SECURITY_DESCRIPTOR_BYTES`, `MAX_SECURITY_DESCRIPTOR_BYTES`),
together with the frozen generated header `fsring-abi/include/fsring_abi.h`.
If prose, generated archives, or an implementation disagree with those
unpacked sources, the unpacked sources win. Every wire value below is
transcribed from that registry: `SlotToken` packs a 2-bit class, a 20-bit
index, and a 42-bit nonzero generation (`SLOT_TOKEN_CLASS_MAX = 3`,
`SLOT_TOKEN_INDEX_MAX = 2^20-1`, `SLOT_TOKEN_GENERATION_MAX = 2^42-1`);
`K2U_READ_ONLY = 1`, `U2K_WRITE = 2`; `QuerySecurityV1` is 40/8 and
`SetSecurityV1` is 24/4; `DonateSecurityContextV1` is 32/8;
`security_information::QUERY_ACCEPTED_MASK = 0x0000_000f` and
`SET_MASK = 0xf001_007f`; `MIN_SECURITY_DESCRIPTOR_BYTES = 20`,
`MAX_SECURITY_DESCRIPTOR_BYTES = 65536`; `protocol_feature::SECURITY` is bit
4 and is the only bit set in `BASE_REQUIRED_PROTOCOL_MASK`;
`protocol_feature::TOKEN_DONATION` is bit 6, one of the four bits in
`UNSELECTABLE_PROTOCOL_MASK`.

A handful of driver-behavior identifiers this document states are WDK/kernel
concepts the `fsring-abi` crate does not and will never carry, because the
crate is the `no_std` wire-format and validation library, not the driver
itself: `RequestorMode`, `EPROCESS`, and `SeAccessCheck` are transcribed from
the corrective-design control-IOCTL registry and access-decision sections
(`docs/superpowers/specs/2026-07-15-fsring-abi-v2.1-corrective-design.md`
section 6) and from the original error-model design
(`docs/superpowers/specs/2026-07-15-fsring-abi-v2-design.md` section 11),
not from a crate item. `SeValidSecurityDescriptor` and
`RtlValidRelativeSecurityDescriptor` are standard WDK security-descriptor
validation routines with no corrective-design, original-design, or crate
citation of their own; their SEH-wrapped validation role in this document is
specified by this rewrite's own design record instead
(`docs/superpowers/specs/2026-07-20-fsring-abi-v2.1-wave-13-cache-passthrough-security-docs-07-09-design.md`,
Document Content Architecture, 09-security.md items 6-7). `MdlMappingNoExecute`
is likewise a WDK mapping flag, already bound as `05-irp-dispatch.md`'s
REQUIRED vocabulary; this document cites its security consequence rather than
re-deriving the profile table.

RFC 2119 keywords (MUST, MUST NOT, SHOULD, MAY) are used in this document
with their normative meaning.

## 1. Control device authorization

`\Device\FsRing` uses `FILE_DEVICE_UNKNOWN`, private IOCTL function codes
starting at `0x800`, `METHOD_BUFFERED`, and `FILE_READ_ACCESS|FILE_WRITE_ACCESS`.
`FILE_DEVICE_SECURE_OPEN` is a required device characteristic, not a
packaging option. The device is created securely with SDDL
`D:P(A;;GA;;;SY)(A;;GA;;;BA)` (LocalSystem and Builtin Administrators only),
and the I/O manager's own access check is not bypassed by a custom dispatch
path.

CREATE behavior is closed and uses this precedence:

1. A non-`UserMode` create returns `ACCESS_DENIED` (`0xc0000022`).
2. A create whose `FileObject->FileName` is nonempty or whose
   `RelatedFileObject` is non-null (any trailing-name, relative, or
   otherwise non-root open) returns `OBJECT_NAME_NOT_FOUND` (`0xc0000034`).
3. Failure to allocate/reference the per-file context returns
   `INSUFFICIENT_RESOURCES`.

Every one of these failures completes with `IoStatus.Information = 0` and
installs no file context. A successful `UserMode` root create atomically
captures and references the IRP requestor `EPROCESS` in that per-file
context before returning `SUCCESS` with `Information = 0`. No SETUP or
ATTACH has occurred yet at CREATE time.

Every subsequent SETUP/ATTACH/IOCTL on that handle — including
`IOCTL_FSRING_DONATE_SECURITY_CONTEXT` (function `0x804`,
`0x0022e010`) — requires both `RequestorMode == UserMode` **and** the
current IRP's requestor `EPROCESS` matching the one captured at CREATE. A
duplicated or inherited handle presented from a different process is
`ACCESS_DENIED`, with no mapping or side effect, even before the first
IOCTL executes. Cleanup/close releases the captured `EPROCESS` reference
only after IOCTL rundown completes. `RequestorMode` and `EPROCESS` are WDK
identifiers per the provenance note above, not crate-carried constants.

## 2. Access-decision model

The kernel is the sole access-decision authority in ABI 2.1. There is
exactly one access-decision mechanism, and it runs entirely on the kernel
side of the trust boundary:

- The kernel captures the requesting application thread's subject context
  on the app thread itself — the same thread that already owns that
  context, so there is no cross-process handle-donation problem to solve.
- The daemon supplies the object's security descriptor through
  `QuerySecurityV1` (40/8): a self-relative SD written into a `U2K_WRITE`
  slot or mapping grant, never a verdict.
- The kernel calls `SeAccessCheck` against that captured subject context
  and the daemon-supplied descriptor and makes the grant/deny decision
  itself. The daemon is never asked for, and never returns, an access
  decision; it returns descriptor bytes only.

Token donation is a **closed, permanently-`NOT_SUPPORTED` registry entry**,
not a deferred v1.1 feature. `DonateSecurityContextV1` (32/8: `header`,
`security_context_id:u64`, `daemon_handle:u64`, `flags:u32`, `reserved:u32`)
remains registry-stable for wire compatibility, and its authenticated
control IOCTL (`IOCTL_FSRING_DONATE_SECURITY_CONTEXT`, function `0x804`,
`0x0022e010`) is reachable under the authorization rule of section 1 above,
but a well-formed authorized call unconditionally returns `NOT_SUPPORTED`
and never references the supplied handle field. `protocol_feature::TOKEN_DONATION`
(bit 6) is one of the four bits in `UNSELECTABLE_PROTOCOL_MASK`: it can be
assigned in the registry but can never be selected by a SETUP or ATTACH.
`PrepareOpenV2`'s security-context field is exactly zero on every 2.1
CREATE — there is no wire path by which a daemon-side impersonation token
ever becomes relevant to an access decision. `TOKEN_DONATION is unselectable`
is the exact disposition this document and `03-messages.md` share for that
registry entry.

Share access is always kernel-enforced (the FCB-level share-access rule
cross-referenced to `04-object-model.md`), independently of the
SD-based access decision above: a `SeAccessCheck` grant never overrides a
share-mode conflict, and a share-mode grant never substitutes for
`SeAccessCheck`.

## 3. Security is unconditional in ABI 2.1

There is no feature-off relaxation mode for object-level access checks.
`protocol_feature::SECURITY` (bit 4) is the only bit set in
`BASE_REQUIRED_PROTOCOL_MASK`: it is required — not merely offered — for
every successful ABI 2.1 session, and a SETUP or ATTACH cannot omit it.
`03-messages.md` states the same fact from the transport side: SECURITY is
selected in every successful 2.1 session, so `QUERY_SECURITY` and
`SET_SECURITY` have no feature-off form.

Concretely, every successful 2.1 session performs `SeAccessCheck` on CREATE
against a descriptor obtained through `QuerySecurityV1`, and both
`QuerySecurityV1` and `SetSecurityV1` are always available for the full
query/set round trip described in sections 6 and 7. The 2.0 draft's
optional relaxed-trust mode — a synthesized default descriptor standing in
for `QUERY_SECURITY` and a local rejection standing in for `SET_SECURITY` —
does not exist in 2.1 and MUST NOT be reintroduced in any form; there is no
volume-level switch that turns object-level access checks off.

## 4. MAPPED-tier memory protection

For `MAPPED_IO`-negotiated requests, the kernel maps exactly the pages of
the originating IRP's own MDL into the daemon process — nothing more, and
never a whole section or an unrelated range. The direction of the request
sets the mapping's write permission:

- READ: the daemon writes the result into the app's buffer, so the daemon
  mapping is RW.
- WRITE: the daemon only reads the app-supplied data, so the daemon mapping
  is RO wherever the platform can enforce a read-only MDL mapping
  protection. This document does not restate `05-irp-dispatch.md`'s
  per-platform mapping-flag table (`MdlMappingNoExecute` is unconditional
  there; the profile-specific write-protection flag for input-only pages is
  05's territory) — it states only the security consequence: on a platform
  that cannot enforce the RO protection, the kernel maps RW and accepts,
  as a documented and low-severity risk, that the daemon could overwrite
  the app's own WRITE-source buffer; it never attempts a half-enforced RO
  mapping, since a half-enforced protection produces a fault that is harder
  to diagnose than a clearly-documented RW fallback.

`MdlMappingNoExecute` applies to every MAPPED-tier mapping without
exception — a daemon-facing mapping backed by application IRP pages is
never executable.

The daemon-facing mapping is unmapped at completion, in daemon context, and
is never held across an op round-trip. A PT backing-donation `FILE_OBJECT`
reference (08's territory) is a wholly different mechanism — a durable
kernel-handle reference to a backing stream, not a page mapping — and this
document's MAPPED-tier rule does not apply to it.

## 5. `SlotToken`/K2U/U2K grant-direction model

`SlotToken` is the generation-stamped capability that stands in for a
pointer everywhere a daemon-supplied buffer reference crosses the trust
boundary: 2-bit class, 20-bit index, 42-bit nonzero generation (already
`02-transport.md`'s canonical `generation:42` definition; not redefined
here). `resolve_slot` treats the index half purely as a bounds-checked
index into a kernel-owned class table (`index >= descriptor.slot_count`
is rejected as out of range) and every offset/length computation along that
path — arena packing, slot-range resolution, and buffer-range containment —
uses checked arithmetic (`checked_add`/`checked_mul`) rather than raw
wrapping arithmetic, so an adversarial index or length fails cleanly
instead of wrapping into an out-of-bounds range.

`K2U_READ_ONLY = 1` and `U2K_WRITE = 2` (`buffer_access`) are the two legal
grant directions and are also the security boundary between kernel-owned
and daemon-owned slot bytes: a K2U grant is kernel-written, daemon-read-only
data; a U2K grant is the one direction in which the kernel treats
daemon-written bytes as untrusted input, never trusted as anything but raw
bytes until validated. `validate_buffer_ref` additionally requires the
candidate `BufferRef`'s session epoch, owner (`ReqId` or notification-credit
ring index), capability kind, and capability token to match the live grant
exactly before any range math runs; a session-epoch or owner mismatch, or
an unknown `kind`/`access` value, is rejected before the reference is ever
resolved to a byte range.

A daemon-supplied `SlotRef`/index is never dereferenced as a pointer. It is
validated as an index into a kernel-owned table and nothing else; the crate
carries no code path that treats a daemon-controlled integer as an address.

## 6. Per-field CQE validation table

The governing sentence for this whole document, verbatim from the original
error-model design: a daemon-controlled value can fail a request, session,
or volume, but must not directly cause an unchecked dereference, integer
wrap, panic, or system bugcheck. Every untrusted length, offset, count,
alignment, enum, flag, reserved field, UTF-16 string, generation, session,
opcode, status, and object identity is validated before use.

`05-irp-dispatch.md` already states the general completion-disposition
framework a hostile CQE is classified under
(`CompletionDispositionV21::Registered`/`NormalizeObservational`/
`JournaledCandidateFault`/`SessionProtocolFault`, driven by
`classify_completion_v21` against the closed `(kind, opcode, status)`
registry); this document does not restate that framework. It states the
per-struct field bounds that are specifically this document's hostile-input
territory:

| Field/struct | Bound |
|---|---|
| `req_id` | Decoded as `{generation:40, slot_index:24}` (`ids.rs`); a generation that does not match the retained `ReqSlot` generation is stale and is dropped, never treated as an address or reused as identity. |
| `kind` | Only `COMPLETION`, `NOTIFY`, and `PROTOCOL` are legal `cq_kind` values; anything else is a `SessionProtocolFault` at `classify_completion_v21`'s catch-all arm. |
| `status` | Only an `(opcode, status)` pair present in the closed status registry (`fsring-abi/src/validate/messages.rs`'s `is_registered_completion_status_v21`, cross-referenced in `03-messages.md`) is accepted; `PENDING` and any REPARSE-shaped status are never registered for any 09-relevant opcode and are rejected exactly like every other unregistered status. |
| `information`/`out_len` | `out_len` MUST be exactly 0 or 24; `validate_completion_output_v21` then requires `information` to equal the request-derived bound exactly for the opcode (READ/WRITE: `information` in `(0, request_length]`; QUERY_INFO/QUERY_VOLUME/QUERY_DIR: `information` equal to the canonical blob length; `QUERY_SECURITY`: `information` equal to the descriptor length). An out-of-relationship value is rejected, not silently clamped. |
| `QuerySecurityV1` output | `security_information` restricted to `QUERY_ACCEPTED_MASK = 0x0000_000f` (owner/group/DACL/SACL bits only); `output.length` fixed at 65536; a successful completion's descriptor length is bounded `[20, 65536]` and `information` MUST equal it exactly. The returned bytes are then gated by `RtlValidRelativeSecurityDescriptor` (SEH-wrapped, WDK-only per the provenance note above) before the kernel treats them as a real security descriptor; a descriptor that fails that check is never copied to the app and the completion is treated as a protocol fault, never a partial/best-effort result. |
| `SetSecurityV1` body | `security_information` nonzero and a subset of `SET_MASK = 0xf001_007f`; `security_descriptor.length` bounded `[MIN_SECURITY_DESCRIPTOR_BYTES=20, MAX_SECURITY_DESCRIPTOR_BYTES=65536]`. |
| `MutationResultV2.security_generation` | For mutation kind `SET_SECURITY`, MUST be strictly greater than the request's `expected_security_generation`; for every other mutation kind it MUST be exactly zero. The same discipline applies uniformly to `namespace_generation` and `sizes.size_epoch` against their own kind predicates — a generation field is never accepted merely because it is nonzero. |
| `CommitOpenResultV2` | Carries `namespace_generation` and `security_generation` as CREATE-time identity fields; both are validated with the same progressing-generation discipline, tying the object identity returned by CREATE to the descriptor the access decision in section 2 was made against. |
| `WriteResultV2`/READ `information` | Bounded against the originating `PRw`/`WriteV2` request length; zero is not a legal success value and a value exceeding the requested length is rejected, not clamped. |
| `QueryDirV2`/`DirEntryV1` | Every entry has a fixed 136-byte prefix (`entry.name.offset` MUST equal 136); `struct_size` MUST be 8-aligned, at least 136, and at most `MAX_CANONICAL_DIR_ENTRY_BYTES = 648`; `file_id`/`link_id` MUST be nonzero and `namespace_generation` MUST be nonzero; `attributes` is masked to the accepted attribute set and `reparse_tag` MUST be zero (REPARSE is unselectable in base 2.1); every timestamp field MUST be nonnegative; any padding byte after the name MUST be zero; the size trio is validated by the same size-state rule 07 owns for the cache/MM domain. A single malformed entry fails validation of the entire batch — there is no partial-prefix salvage — and the completion is classified as a protocol fault rather than continuing on unverified bytes. |
| Volume-size query output | The successor of the old `FsringVolSize` record requires `output.length >= 40` bytes before any field is trusted. |
| Notify-driven identity (`file_id`, directory identity) | A lookup miss on a notification body is ignored; the kernel never creates a new object purely because a notification named one. |

Every validator above returns a typed error and never panics, never
indexes unchecked, and never trusts a length before it is range-checked —
the same `no_std`/no-`unwrap`/fallible-allocation discipline the crate's
`validate/*` modules implement throughout, not a security-specific
exception.

## 7. SD operations

QUERY: the kernel issues `QuerySecurityV1` with `security_information`
trimmed to `QUERY_ACCEPTED_MASK`; the daemon writes a self-relative
security descriptor into the `U2K_WRITE` output grant; the kernel validates
it (`RtlValidRelativeSecurityDescriptor`, SEH-wrapped) and only then trims
and copies the mask-selected components into the application's buffer. If
that application buffer is smaller than the trimmed descriptor's needed
length, the driver completes the native IRP `BUFFER_OVERFLOW` with the
needed length — an IRP-completion-level status, distinct from the ring CQE
status registry, where `QUERY_SECURITY` only ever registers `SUCCESS` or
the closed `QUERY_FAILURES` set and never `BUFFER_OVERFLOW`.

SET: the kernel validates the application-supplied security descriptor
(`SeValidSecurityDescriptor`/`RtlValidRelativeSecurityDescriptor`-equivalent
check under SEH) before it is ever placed into the outbound `SetSecurityV1`
body and reaches the daemon. `security_information` MUST be nonzero and a
subset of `SET_MASK`; `security_descriptor.length` MUST fall in
`[MIN_SECURITY_DESCRIPTOR_BYTES, MAX_SECURITY_DESCRIPTOR_BYTES]`. The
kernel never edits an ACL itself; it forwards exactly the validated bytes
and trusts only the resulting `security_generation` advance as proof the
daemon applied them. `INVALID_SECURITY_DESCR` (`0xc0000079`) is the closed
`MUTATE_FAILURES` status the daemon may return for a `SET_SECURITY` it
rejects; the full `MUTATE_FAILURES` registry itself is not restated here.

## 8. Protocol-fault and quarantine disposition

Protocol fault is its own error class, distinct from a request/provider
error: malformed or contradictory daemon state is a protocol fault, and a
protocol fault quarantines the session and drives it toward GRACE/teardown
rather than failing one request in isolation. This document is the
normative home for "quarantine" as FSRING vocabulary — the word appears
only in prose elsewhere in the document set — and ties it to the concrete
crate-level classification the kernel actually runs, not narrative alone:

- `CompletionDispositionV21::SessionProtocolFault`
  (`classify_completion_v21` in `validate/messages.rs`) is the disposition
  for a CQE whose `(kind, opcode, status)` triple, or whose shape once that
  triple is registered, cannot be trusted.
- `QueryOpTableActionV21::ExactlyOnceProtocolFault` is the disposition for
  a `QUERY_OP`/journaled-recovery answer that contradicts the retained
  operation phase.
- `AttachBarrierV21::ProtocolFault` and `PtLaneAckActionV21::ProtocolFault`
  are the analogous dispositions for a malformed ATTACH barrier or PT-lane
  acknowledgement (06's and 08's state machines are where the reaction to
  these dispositions is normative; this document defines what the
  disposition means and names the functions that compute it).

`02-transport.md` and `03-messages.md` already describe the behavioral
contract this section formally names: a valid protocol-fault record
requests immediate quarantine and controlled teardown, and once quarantined
a session stops accepting further writable-memory trust from that daemon.
Nothing in this document weakens that: every validator in sections 5-7
above resolves to either an ordinary request/provider error or one of
these protocol-fault dispositions, never to unchecked trust.

## 9. Stated (not executed) DoD

- 24-hour fuzz of every CQE field, including malformed SD and dirent
  payloads, with zero bugcheck and zero out-of-bounds access under Driver
  Verifier special pool. M1 gate and maintained thereafter.
- `SeAccessCheck` deny-path test: opening a file whose descriptor denies
  the requestor returns `ACCESS_DENIED` (M2).
- Control-device non-privileged-open test: a `UserMode` open of
  `\Device\FsRing` by a principal outside LocalSystem/Administrators
  returns `ACCESS_DENIED` (M1).
- MAPPED-tier RO write-attempt test: a daemon write attempt against a
  WRITE-tier page mapped RO leaves the application's data unmodified (M2,
  where RO enforcement is available on the platform); where the platform
  cannot enforce RO, the equivalent test is the documented RW-fallback
  accepted-risk case instead.

## C4 device security and mapping validation

Both named C4 roles are created with `IoCreateDeviceSecure`, the exact SDDL
`D:P(A;;GA;;;SY)(A;;GA;;;BA)`, and `FILE_DEVICE_SECURE_OPEN`. The
filesystem-control role uses class GUID
`{201DC259-6F66-4682-A3CD-04CCEBE3D8B2}`; every per-mount VDO shares the
distinct role class GUID `{92AC3ED3-4505-42D5-A81C-901212229852}`. These are
static security-class selectors, not per-volume identity and not wire fields.
The VDO's native name is derived from the returned MountId as
`\Device\FsRingVolume-<lo:016X>-<hi:016X>`; that name is routing, not
authentication.

A returned user address is never authority. The daemon client recomputes the
section placement from the request it sent, checks every descriptor against it,
proves each claimed range is fully `MEM_COMMIT`/`MEM_MAPPED` with the exact
protection its access demands and no executable or guard modifier, copies the
global header and ring directory into private buffers, and re-parses those
copies with `validate_header_directory_v21` before a single borrow exists. The
kernel likewise never accepts a returned user address as an unmap key: the
authoritative alias record is.
