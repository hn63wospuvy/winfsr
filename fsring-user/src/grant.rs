//! The host model of the kernel grant table, and the single-fetch read that
//! turns a peer `BufferRef` into private bytes.
//!
//! A `PControl.body: BufferRef` is entirely peer-controlled; turning it into
//! real bytes is the most safety-critical operation in the SDK. The frozen ABI
//! owns the validation (`validate_buffer_ref` → a section-relative
//! `CheckedRange64` proven `⊆ slot ⊆ arena ⊆ [0, section_size)`); this module
//! supplies the grant table those validators need (the harness, playing the
//! kernel, issues grants; the daemon looks them up) and the one guarded copy
//! that reads the validated range into an owned [`BodyView`]. No borrow into the
//! peer-mutable section is ever formed.
//!
//! The ABI grant contract requires the caller to hold the real kernel
//! rundown/state guard across the snapshot's use; host-side there is no such
//! guard — the harness owns the table single-threaded and `GrantState::Live` is
//! only the checked snapshot. That boundary is recorded, not simulated.

use core::ptr;

use fsring_abi::codec::{try_encode, Pod};
use fsring_abi::msgs::{buffer_access, buffer_kind, BufferRef};
use fsring_abi::slots::{
    resolve_slot, validate_buffer_ref, validate_grant_metadata, BufferRefPolicy, BufferRefRule,
    EmptyBufferRule, GrantCapability, GrantMetadata, GrantOwner, GrantState, SlotToken,
    ValidatedBuffer, ValidatedSlotArena,
};
use fsring_abi::validate::CheckedRange64;

use crate::error::GrantError;
use crate::section::SharedSection;

/// A private, owned copy of a granted body, single-fetched from the section
/// after `validate_buffer_ref` proved its range in bounds. Decoders read this,
/// never the peer-mutable section, so no field can change under validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyView {
    bytes: Box<[u8]>,
}

impl BodyView {
    /// The fetched body bytes (exactly the grant's validated length).
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// The host model of the kernel grant table for one session.
///
/// The harness (kernel role) issues grants; the daemon looks them up by token to
/// validate an incoming `BufferRef`. Both use the table's fixed `session_epoch`,
/// so issue and resolve agree.
pub struct GrantTable {
    session_epoch: u64,
    grants: Vec<(u64, GrantMetadata)>,
}

impl GrantTable {
    pub fn new(session_epoch: u64) -> Self {
        Self {
            session_epoch,
            grants: Vec::new(),
        }
    }

    /// Issue a `K2U_READ_ONLY` slot grant of `length` bytes to `owner`, resolving
    /// `token` in `arena`. Returns the `BufferRef` the request echoes; records
    /// the matching `GrantMetadata`.
    pub fn issue_k2u(
        &mut self,
        arena: &ValidatedSlotArena,
        owner: GrantOwner,
        token: SlotToken,
        length: u32,
    ) -> Result<BufferRef, GrantError> {
        let resolved = resolve_slot(arena, token)?;
        let issued = BufferRef {
            token: token.raw(),
            offset: 0,
            length,
            kind: buffer_kind::SLOT,
            access: buffer_access::K2U_READ_ONLY,
            reserved: 0,
        };
        let grant = GrantMetadata {
            capability: GrantCapability::Slot(resolved),
            session_epoch: self.session_epoch,
            owner,
            access: buffer_access::K2U_READ_ONLY,
            maximum: CheckedRange64 {
                start: 0,
                end: u64::from(resolved.slot_size()),
            },
            state: GrantState::Live,
            issued,
        };
        // The grant we just built must itself be well-formed.
        validate_grant_metadata(&grant)?;
        self.grants.push((token.raw(), grant));
        Ok(issued)
    }

    /// Issue a `U2K_WRITE` slot grant of `length` bytes to `owner` (an output
    /// buffer the daemon writes: a `reply`/`result_security_descriptor` echo).
    /// Mirrors [`issue_k2u`] with the opposite access direction.
    pub fn issue_u2k(
        &mut self,
        arena: &ValidatedSlotArena,
        owner: GrantOwner,
        token: SlotToken,
        length: u32,
    ) -> Result<BufferRef, GrantError> {
        let resolved = resolve_slot(arena, token)?;
        let issued = BufferRef {
            token: token.raw(),
            offset: 0,
            length,
            kind: buffer_kind::SLOT,
            access: buffer_access::U2K_WRITE,
            reserved: 0,
        };
        let grant = GrantMetadata {
            capability: GrantCapability::Slot(resolved),
            session_epoch: self.session_epoch,
            owner,
            access: buffer_access::U2K_WRITE,
            maximum: CheckedRange64 {
                start: 0,
                end: u64::from(resolved.slot_size()),
            },
            state: GrantState::Live,
            issued,
        };
        validate_grant_metadata(&grant)?;
        self.grants.push((token.raw(), grant));
        Ok(issued)
    }

    /// The session epoch this table issues and resolves against.
    pub fn session_epoch(&self) -> u64 {
        self.session_epoch
    }

    /// The live grant metadata bound to `token`, for building an ABI
    /// `GrantBindingV21` when validating a multi-grant body. Returns `None` if
    /// the table never issued `token`.
    pub fn grant_for(&self, token: u64) -> Option<&GrantMetadata> {
        self.grants
            .iter()
            .find(|(t, _)| *t == token)
            .map(|(_, grant)| grant)
    }

    /// Validate an incoming `BufferRef` against its live grant, returning the
    /// ABI `ValidatedBuffer` (whose `section_range()` feeds `resolve_body`).
    pub fn resolve(
        &self,
        reference: &BufferRef,
        expected_owner: GrantOwner,
        policy: BufferRefPolicy,
    ) -> Result<ValidatedBuffer, GrantError> {
        let grant = self
            .grants
            .iter()
            .find(|(token, _)| *token == reference.token)
            .map(|(_, grant)| grant)
            .ok_or(GrantError::UnknownToken)?;
        let rule = BufferRefRule::Grant {
            grant,
            expected_session_epoch: self.session_epoch,
            expected_owner,
            policy,
            empty: EmptyBufferRule::Forbidden,
        };
        Ok(validate_buffer_ref(reference, &rule)?)
    }
}

/// Single-fetch the bytes of an already-validated slot range into a private copy.
///
/// `validated` came from `validate_buffer_ref`, so its section range is proven
/// `⊆ slot ⊆ arena ⊆ [0, section_size)`. We *additionally* bounds-check it
/// against this daemon's own mapping length before the one `unsafe` copy, and
/// never form a borrow into the peer-mutable section.
pub fn resolve_body<S: SharedSection>(
    section: &S,
    validated: &ValidatedBuffer,
) -> Result<BodyView, GrantError> {
    let range = validated.section_range().ok_or(GrantError::NotASlot)?;
    let start = usize::try_from(range.start).map_err(|_| GrantError::Arithmetic)?;
    let end = usize::try_from(range.end).map_err(|_| GrantError::Arithmetic)?;
    if start > end || end > section.len() {
        return Err(GrantError::OutOfBounds);
    }
    let len = end - start;
    let mut bytes = vec![0u8; len];
    // SAFETY: `[start, end) ⊆ [0, section.len())` — the ABI-validated slot range,
    // plus the load-bearing `end <= section.len()` re-check above (this mapping
    // may be smaller than the section_size the buffer was validated against);
    // `section.base()` is a live mapping of `len` bytes; we copy exactly `len`
    // bytes into an owned buffer and never retain a pointer into the section.
    unsafe {
        ptr::copy_nonoverlapping(section.base().add(start), bytes.as_mut_ptr(), len);
    }
    Ok(BodyView {
        bytes: bytes.into_boxed_slice(),
    })
}

/// Single-write `bytes` into an already-validated slot range: the exact
/// bounds-guarded inverse of [`resolve_body`], for the U2K direction (a
/// `reply` / `result_security_descriptor` echo the daemon writes back).
///
/// `validated` came from `validate_buffer_ref`, so its section range is proven
/// `⊆ slot ⊆ arena ⊆ [0, section_size)`. We *additionally* bounds-check it
/// against this daemon's own mapping length before the one `unsafe` copy, and
/// require `bytes` to be exactly the validated length before writing.
pub fn write_body<S: SharedSection>(
    section: &S,
    validated: &ValidatedBuffer,
    bytes: &[u8],
) -> Result<(), GrantError> {
    let range = validated.section_range().ok_or(GrantError::NotASlot)?;
    let start = usize::try_from(range.start).map_err(|_| GrantError::Arithmetic)?;
    let end = usize::try_from(range.end).map_err(|_| GrantError::Arithmetic)?;
    if start > end || end > section.len() {
        return Err(GrantError::OutOfBounds);
    }
    let len = end - start;
    if bytes.len() != len {
        return Err(GrantError::LengthMismatch);
    }
    // SAFETY: `[start, end) ⊆ [0, section.len())` — the ABI-validated slot range,
    // plus the load-bearing `end <= section.len()` re-check above (this mapping
    // may be smaller than the section_size the buffer was validated against);
    // `section.base()` is a live mapping of `len` bytes; we copy exactly `len`
    // bytes from an owned buffer, never forming a `&mut` into the peer-mutable
    // section (mirrors `resolve_body`'s single-fetch discipline in the opposite
    // direction).
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), section.base().add(start), len);
    }
    Ok(())
}

/// Encode a POD wire struct into an owned byte buffer of exactly its size.
///
/// The single shared result-encoder helper: the `dataio` / `mutation` /
/// `openbody` / `queryinfo` / `queryvolume` result builders all frame a fixed
/// POD wire struct into `Vec<u8>` the daemon writes back, so the one-line
/// pattern lives here rather than being copied five times.
pub(crate) fn encode_pod<T: Pod>(value: &T) -> Vec<u8> {
    let mut bytes = vec![0u8; core::mem::size_of::<T>()];
    try_encode(value, &mut bytes).expect("owned buffer is exactly the struct size");
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::valid_setup;
    use crate::layout::PhysicalLayout;
    use crate::section::{HeapSection, SharedSection};
    use fsring_abi::ids::ReqId;
    use fsring_abi::slots::{resolve_slot, validate_slot_arena, SlotDirection};

    const PAGE: u32 = 4096;
    const SESSION_EPOCH: u64 = 1;

    fn k2u_arena(layout: &PhysicalLayout) -> ValidatedSlotArena {
        validate_slot_arena(
            SlotDirection::K2u,
            layout.section_size,
            layout.k2u_slots,
            layout.k2u_slot_classes,
        )
        .expect("k2u arena")
    }

    fn u2k_arena(layout: &PhysicalLayout) -> ValidatedSlotArena {
        validate_slot_arena(
            SlotDirection::U2k,
            layout.section_size,
            layout.u2k_arena,
            layout.u2k_slot_classes,
        )
        .expect("u2k arena")
    }

    #[test]
    fn granted_bytes_resolve_and_single_fetch() {
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).unwrap();
        let section = HeapSection::with_len(layout.section_size as usize, PAGE as usize);
        // SAFETY: zeroed mapping of section_size bytes.
        unsafe { layout.construct(section.base(), section.len()) };
        let arena = k2u_arena(&layout);

        let owner = GrantOwner::Request(ReqId::from_raw(0x0001_0000_0001));
        let token = SlotToken::try_new(0, 0, 1).unwrap();

        // Harness (kernel role) writes the body into the slot it will grant.
        let resolved = resolve_slot(&arena, token).unwrap();
        let start = resolved.section_range().start as usize;
        let body = [0xABu8; 24];
        // SAFETY: `start + 24` is inside the resolved slot, inside the section.
        unsafe { ptr::copy_nonoverlapping(body.as_ptr(), section.base().add(start), body.len()) };

        let mut table = GrantTable::new(SESSION_EPOCH);
        let reference = table
            .issue_k2u(&arena, owner, token, body.len() as u32)
            .unwrap();

        // Daemon role: look the grant up and single-fetch the body.
        let validated = table
            .resolve(&reference, owner, BufferRefPolicy::Exact)
            .expect("resolve");
        let view = resolve_body(&section, &validated).expect("resolve_body");
        assert_eq!(view.as_slice(), &body);
    }

    #[test]
    fn a_wrong_owner_is_rejected() {
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).unwrap();
        let section = HeapSection::with_len(layout.section_size as usize, PAGE as usize);
        // SAFETY: zeroed mapping.
        unsafe { layout.construct(section.base(), section.len()) };
        let arena = k2u_arena(&layout);

        let owner = GrantOwner::Request(ReqId::from_raw(0x0001_0000_0001));
        let other = GrantOwner::Request(ReqId::from_raw(0x0001_0000_0002));
        let token = SlotToken::try_new(0, 0, 1).unwrap();
        let mut table = GrantTable::new(SESSION_EPOCH);
        let reference = table.issue_k2u(&arena, owner, token, 24).unwrap();

        assert!(matches!(
            table.resolve(&reference, other, BufferRefPolicy::Exact),
            Err(GrantError::BufferRef(_))
        ));
    }

    /// Issue a single k2u grant and return the table + the issued reference.
    fn issued_grant() -> (GrantTable, BufferRef, GrantOwner) {
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).unwrap();
        let section = HeapSection::with_len(layout.section_size as usize, PAGE as usize);
        // SAFETY: zeroed mapping.
        unsafe { layout.construct(section.base(), section.len()) };
        let arena = k2u_arena(&layout);
        let owner = GrantOwner::Request(ReqId::from_raw(0x0001_0000_0001));
        let token = SlotToken::try_new(0, 0, 1).unwrap();
        let mut table = GrantTable::new(SESSION_EPOCH);
        let reference = table.issue_k2u(&arena, owner, token, 24).unwrap();
        (table, reference, owner)
    }

    #[test]
    fn an_unknown_token_is_rejected() {
        let (table, mut reference, owner) = issued_grant();
        reference.token ^= 0xff; // not a token the table issued
        assert_eq!(
            table.resolve(&reference, owner, BufferRefPolicy::Exact),
            Err(GrantError::UnknownToken)
        );
    }

    #[test]
    fn an_echo_length_mismatch_is_rejected() {
        let (table, mut reference, owner) = issued_grant();
        reference.length = 20; // Exact policy requires length == issued.length (24)
        assert!(matches!(
            table.resolve(&reference, owner, BufferRefPolicy::Exact),
            Err(GrantError::BufferRef(_))
        ));
    }

    #[test]
    fn a_non_zero_reserved_is_rejected() {
        let (table, mut reference, owner) = issued_grant();
        reference.reserved = 1;
        assert!(matches!(
            table.resolve(&reference, owner, BufferRefPolicy::Exact),
            Err(GrantError::BufferRef(_))
        ));
    }

    #[test]
    fn a_wrong_access_is_rejected() {
        use fsring_abi::msgs::buffer_access;
        let (table, mut reference, owner) = issued_grant();
        reference.access = buffer_access::U2K_WRITE; // grant is K2U_READ_ONLY
        assert!(matches!(
            table.resolve(&reference, owner, BufferRefPolicy::Exact),
            Err(GrantError::BufferRef(_))
        ));
    }

    #[test]
    fn a_none_kind_reference_is_rejected() {
        use fsring_abi::msgs::buffer_kind;
        let (table, mut reference, owner) = issued_grant();
        reference.kind = buffer_kind::NONE; // grant capability is SLOT
        assert!(matches!(
            table.resolve(&reference, owner, BufferRefPolicy::Exact),
            Err(GrantError::BufferRef(_))
        ));
    }

    #[test]
    fn a_range_past_the_slot_is_rejected() {
        let (table, mut reference, owner) = issued_grant();
        reference.length = u32::MAX; // far past the slot's capacity
        assert!(matches!(
            table.resolve(&reference, owner, BufferRefPolicy::Exact),
            Err(GrantError::BufferRef(_))
        ));
    }

    #[test]
    fn resolve_body_rejects_a_range_past_the_mapping() {
        // A validated range from a full section, fed to a shorter mapping, hits
        // the redundant `end <= section.len()` guard (defends a section_size vs
        // mapping-length divergence). Exercises GrantError::OutOfBounds.
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).unwrap();
        let section = HeapSection::with_len(layout.section_size as usize, PAGE as usize);
        // SAFETY: zeroed mapping.
        unsafe { layout.construct(section.base(), section.len()) };
        let arena = k2u_arena(&layout);
        let owner = GrantOwner::Request(ReqId::from_raw(0x0001_0000_0001));
        let token = SlotToken::try_new(0, 0, 1).unwrap();
        let mut table = GrantTable::new(SESSION_EPOCH);
        let reference = table.issue_k2u(&arena, owner, token, 24).unwrap();
        let validated = table
            .resolve(&reference, owner, BufferRefPolicy::Exact)
            .unwrap();

        let tiny = HeapSection::with_len(64, PAGE as usize);
        assert_eq!(
            resolve_body(&tiny, &validated),
            Err(GrantError::OutOfBounds)
        );
    }

    #[test]
    fn resolve_body_rejects_a_non_slot_buffer() {
        use fsring_abi::msgs::{buffer_kind, BufferRef};
        use fsring_abi::slots::{validate_buffer_ref, BufferRefRule};
        // A validated NONE buffer has no section range; resolve_body must not
        // fetch anything. Exercises GrantError::NotASlot.
        let none_ref = BufferRef {
            token: 0,
            offset: 0,
            length: 0,
            kind: buffer_kind::NONE,
            access: 0,
            reserved: 0,
        };
        let validated = validate_buffer_ref(&none_ref, &BufferRefRule::None).unwrap();
        let section = HeapSection::with_len(4096, PAGE as usize);
        assert_eq!(
            resolve_body(&section, &validated),
            Err(GrantError::NotASlot)
        );
    }

    #[test]
    fn write_body_round_trips_a_u2k_grant() {
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).unwrap();
        let section = HeapSection::with_len(layout.section_size as usize, PAGE as usize);
        // SAFETY: zeroed mapping of section_size bytes.
        unsafe { layout.construct(section.base(), section.len()) };
        let arena = u2k_arena(&layout);

        let owner = GrantOwner::Request(ReqId::from_raw(0x0001_0000_0001));
        let token = SlotToken::try_new(0, 0, 1).unwrap();
        let mut table = GrantTable::new(SESSION_EPOCH);
        let body = [0xCDu8; 24];
        let reference = table
            .issue_u2k(&arena, owner, token, body.len() as u32)
            .unwrap();

        // Daemon role: resolve the grant, then write the reply body back.
        let validated = table
            .resolve(&reference, owner, BufferRefPolicy::Exact)
            .expect("resolve");
        write_body(&section, &validated, &body).expect("write_body");

        // Read it back the same way a peer/kernel reader would: single-fetch.
        let view = resolve_body(&section, &validated).expect("resolve_body");
        assert_eq!(view.as_slice(), &body);
    }

    #[test]
    fn write_body_rejects_a_short_source() {
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).unwrap();
        let section = HeapSection::with_len(layout.section_size as usize, PAGE as usize);
        // SAFETY: zeroed mapping.
        unsafe { layout.construct(section.base(), section.len()) };
        let arena = u2k_arena(&layout);
        let owner = GrantOwner::Request(ReqId::from_raw(0x0001_0000_0001));
        let token = SlotToken::try_new(0, 0, 1).unwrap();
        let mut table = GrantTable::new(SESSION_EPOCH);
        let reference = table.issue_u2k(&arena, owner, token, 24).unwrap();
        let validated = table
            .resolve(&reference, owner, BufferRefPolicy::Exact)
            .unwrap();

        let short = [0xCDu8; 23];
        assert_eq!(
            write_body(&section, &validated, &short),
            Err(GrantError::LengthMismatch)
        );
    }

    #[test]
    fn write_body_rejects_a_long_source() {
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).unwrap();
        let section = HeapSection::with_len(layout.section_size as usize, PAGE as usize);
        // SAFETY: zeroed mapping.
        unsafe { layout.construct(section.base(), section.len()) };
        let arena = u2k_arena(&layout);
        let owner = GrantOwner::Request(ReqId::from_raw(0x0001_0000_0001));
        let token = SlotToken::try_new(0, 0, 1).unwrap();
        let mut table = GrantTable::new(SESSION_EPOCH);
        let reference = table.issue_u2k(&arena, owner, token, 24).unwrap();
        let validated = table
            .resolve(&reference, owner, BufferRefPolicy::Exact)
            .unwrap();

        let long = [0xCDu8; 25];
        assert_eq!(
            write_body(&section, &validated, &long),
            Err(GrantError::LengthMismatch)
        );
    }

    #[test]
    fn write_body_rejects_a_range_past_the_mapping() {
        // Mirrors `resolve_body_rejects_a_range_past_the_mapping`: a validated
        // range from a full section, fed to a shorter mapping, hits the
        // redundant `end <= section.len()` guard before the length check runs.
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).unwrap();
        let section = HeapSection::with_len(layout.section_size as usize, PAGE as usize);
        // SAFETY: zeroed mapping.
        unsafe { layout.construct(section.base(), section.len()) };
        let arena = u2k_arena(&layout);
        let owner = GrantOwner::Request(ReqId::from_raw(0x0001_0000_0001));
        let token = SlotToken::try_new(0, 0, 1).unwrap();
        let mut table = GrantTable::new(SESSION_EPOCH);
        let reference = table.issue_u2k(&arena, owner, token, 24).unwrap();
        let validated = table
            .resolve(&reference, owner, BufferRefPolicy::Exact)
            .unwrap();

        let tiny = HeapSection::with_len(64, PAGE as usize);
        let body = [0xCDu8; 24];
        assert_eq!(
            write_body(&tiny, &validated, &body),
            Err(GrantError::OutOfBounds)
        );
    }

    /// A well-formed live k2u grant plus the `BufferRef` it issued, for the ABI
    /// guards that `GrantTable`'s single-epoch / exact-token lookup cannot reach.
    fn live_k2u_grant() -> (GrantMetadata, BufferRef, GrantOwner) {
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).unwrap();
        let arena = k2u_arena(&layout);
        let owner = GrantOwner::Request(ReqId::from_raw(0x0001_0000_0001));
        let token = SlotToken::try_new(0, 0, 1).unwrap();
        let resolved = resolve_slot(&arena, token).unwrap();
        let issued = BufferRef {
            token: token.raw(),
            offset: 0,
            length: 24,
            kind: buffer_kind::SLOT,
            access: buffer_access::K2U_READ_ONLY,
            reserved: 0,
        };
        let grant = GrantMetadata {
            capability: GrantCapability::Slot(resolved),
            session_epoch: SESSION_EPOCH,
            owner,
            access: buffer_access::K2U_READ_ONLY,
            maximum: CheckedRange64 {
                start: 0,
                end: u64::from(resolved.slot_size()),
            },
            state: GrantState::Live,
            issued,
        };
        (grant, issued, owner)
    }

    #[test]
    fn validate_buffer_ref_rejects_a_wrong_session_epoch() {
        use fsring_abi::slots::BufferRefError;
        // GrantTable forwards one session epoch to both issue and resolve, so a
        // wrong-epoch reference cannot arise through it; prove the ABI epoch guard
        // directly with an expected epoch that differs from the grant's.
        let (grant, issued, owner) = live_k2u_grant();
        let rule = BufferRefRule::Grant {
            grant: &grant,
            expected_session_epoch: SESSION_EPOCH + 1,
            expected_owner: owner,
            policy: BufferRefPolicy::Exact,
            empty: EmptyBufferRule::Forbidden,
        };
        assert_eq!(
            validate_buffer_ref(&issued, &rule).err(),
            Some(BufferRefError::SessionEpochMismatch)
        );
    }

    #[test]
    fn validate_buffer_ref_rejects_a_stale_token_generation() {
        use fsring_abi::slots::BufferRefError;
        // A stale-generation reference 404s in GrantTable's exact-token lookup;
        // prove the ABI capability guard directly by echoing a token whose
        // generation (2) differs from the granted slot's (1).
        let (grant, mut reference, owner) = live_k2u_grant();
        reference.token = SlotToken::try_new(0, 0, 2).unwrap().raw();
        let rule = BufferRefRule::Grant {
            grant: &grant,
            expected_session_epoch: SESSION_EPOCH,
            expected_owner: owner,
            policy: BufferRefPolicy::Exact,
            empty: EmptyBufferRule::Forbidden,
        };
        assert_eq!(
            validate_buffer_ref(&reference, &rule).err(),
            Some(BufferRefError::CapabilityMismatch)
        );
    }
}
