//! Hostile-section rejection matrix and a stable decoder-robustness sweep.
//!
//! Proves that `PhysicalLayout::validate` classifies every corrupted section
//! with its precise error and never panics or reads out of bounds on arbitrary
//! or bit-flipped input. Runs on stable (no cargo-fuzz required); see
//! `fuzz/fuzz_targets/` for the libFuzzer harness used when a fuzzing toolchain
//! is available.

use fsring_abi::layout::{GlobalHeader, RingDesc};
use fsring_abi::limits::USER_VIEW_OFFSET_ALIGNMENT;
use fsring_user::handshake::{build_setup_request, encode_setup_request, serve_setup};
use fsring_user::{HeapSection, PhysicalLayout, SectionError, SharedSection};

const PAGE: u32 = 4096;

fn fresh() -> (HeapSection, PhysicalLayout) {
    let setup = serve_setup(&encode_setup_request(&build_setup_request(1))).expect("valid SETUP");
    let layout = PhysicalLayout::compute(&setup, PAGE).expect("compute");
    let section = HeapSection::with_len(layout.section_size as usize, PAGE as usize);
    // SAFETY: freshly allocated zeroed section of section_size bytes.
    unsafe { layout.construct(section.base(), section.len()) };
    (section, layout)
}

fn validate(section: &HeapSection) -> Option<SectionError> {
    // SAFETY: the section holds `len()` readable bytes.
    unsafe { PhysicalLayout::validate(section.base(), section.len()) }.err()
}

fn edit_header(section: &HeapSection, edit: impl FnOnce(&mut GlobalHeader)) {
    // SAFETY: the section is at least one GlobalHeader in size and page-aligned.
    unsafe {
        let ptr = section.base().cast::<GlobalHeader>();
        let mut header = core::ptr::read_unaligned(ptr);
        edit(&mut header);
        core::ptr::write_unaligned(ptr, header);
    }
}

fn edit_ring0(section: &HeapSection, dir_offset: u64, edit: impl FnOnce(&mut RingDesc)) {
    // SAFETY: `dir_offset` is the in-bounds ring directory offset from a valid
    // layout; ring 0's descriptor is the first RingDesc there.
    unsafe {
        let ptr = section.base().add(dir_offset as usize).cast::<RingDesc>();
        let mut desc = core::ptr::read_unaligned(ptr);
        edit(&mut desc);
        core::ptr::write_unaligned(ptr, desc);
    }
}

#[test]
fn a_well_formed_section_is_accepted() {
    let (section, _layout) = fresh();
    assert_eq!(validate(&section), None);
}

#[test]
fn legacy_parsed_layout_remains_constructible() {
    // Mutation caught: dropping the metadata construction authority when the
    // expectation-free legacy parser cannot retain a compact canonical plan.
    let (section, _) = fresh();
    // SAFETY: the source section holds `len()` readable bytes.
    let parsed = unsafe { PhysicalLayout::validate(section.base(), section.len()) }
        .expect("legacy parser accepts canonical section");
    let reconstructed =
        HeapSection::with_len(parsed.section_size as usize, parsed.page_size as usize);
    // SAFETY: the destination is a fresh zeroed mapping of section_size bytes.
    unsafe { parsed.construct(reconstructed.base(), reconstructed.len()) };
    // SAFETY: the reconstructed section holds `len()` readable bytes.
    let reparsed = unsafe { PhysicalLayout::validate(reconstructed.base(), reconstructed.len()) }
        .expect("legacy parsed layout reconstructs normalized valid metadata");
    assert_eq!(reparsed.section_size, parsed.section_size);
    assert_eq!(reparsed.ring_directory, parsed.ring_directory);
    assert_eq!(reparsed.rings.len(), parsed.rings.len());
}

#[test]
fn expected_setup_validation_accepts_only_the_canonical_image() {
    // Mutation caught: validate_for_setup falls back to the expectation-free
    // legacy parser or ignores the expected session epoch.
    let setup = serve_setup(&encode_setup_request(&build_setup_request(1))).expect("valid SETUP");
    let (section, _layout) = fresh();
    // SAFETY: the section holds `len()` readable bytes.
    let parsed =
        unsafe { PhysicalLayout::validate_for_setup(section.base(), section.len(), &setup, 1) }
            .expect("expected topology validates");
    assert_eq!(parsed.rings.len(), 1);
    // SAFETY: same valid mapping; only the expectation is intentionally wrong.
    assert!(unsafe {
        PhysicalLayout::validate_for_setup(section.base(), section.len(), &setup, 2)
    }
    .is_err());
}

#[test]
fn corrupt_magic_is_rejected() {
    let (section, _) = fresh();
    edit_header(&section, |h| h.magic = 0);
    assert_eq!(validate(&section), Some(SectionError::BadMagic));
}

#[test]
fn wrong_header_size_is_rejected() {
    let (section, _) = fresh();
    edit_header(&section, |h| h.header_size = 1);
    assert_eq!(
        validate(&section),
        Some(SectionError::UnsupportedHeaderSize)
    );
}

#[test]
fn abi_minor_zero_is_rejected() {
    let (section, _) = fresh();
    edit_header(&section, |h| h.abi_minor = 0);
    assert_eq!(validate(&section), Some(SectionError::RevisionMismatch));
}

#[test]
fn non_little_endian_is_rejected() {
    let (section, _) = fresh();
    edit_header(&section, |h| h.byte_order = 2);
    assert_eq!(validate(&section), Some(SectionError::BadByteOrder));
}

#[test]
fn non_power_of_two_page_size_is_rejected() {
    let (section, _) = fresh();
    edit_header(&section, |h| h.page_size = 3);
    assert_eq!(validate(&section), Some(SectionError::BadPageSize));
}

#[test]
fn section_size_beyond_mapping_is_rejected() {
    let (section, _) = fresh();
    edit_header(&section, |h| h.section_size += USER_VIEW_OFFSET_ALIGNMENT);
    assert_eq!(validate(&section), Some(SectionError::SectionTooSmall));
}

#[test]
fn out_of_bounds_ring_directory_is_rejected() {
    let (section, _) = fresh();
    let size = {
        let (_, l) = fresh();
        l.section_size
    };
    edit_header(&section, |h| h.ring_directory.offset = size);
    assert_eq!(validate(&section), Some(SectionError::RegionOutOfBounds));
}

#[test]
fn corrupt_ring_desc_magic_is_rejected() {
    let (section, layout) = fresh();
    let dir = layout.ring_directory.offset;
    edit_ring0(&section, dir, |r| r.magic = 0);
    assert_eq!(validate(&section), Some(SectionError::BadRingDesc));
}

#[test]
fn non_power_of_two_ring_capacity_is_rejected() {
    let (section, layout) = fresh();
    let dir = layout.ring_directory.offset;
    edit_ring0(&section, dir, |r| r.sq_capacity = 3);
    assert_eq!(validate(&section), Some(SectionError::BadCapacity));
}

#[test]
fn out_of_bounds_ring_region_is_rejected() {
    let (section, layout) = fresh();
    let dir = layout.ring_directory.offset;
    let size = layout.section_size;
    edit_ring0(&section, dir, |r| r.cq_entries.offset = size);
    assert_eq!(validate(&section), Some(SectionError::RegionOutOfBounds));
}

#[test]
fn misaligned_ring_region_is_rejected() {
    let (section, layout) = fresh();
    let dir = layout.ring_directory.offset;
    // 64 KiB-aligned + 64: still in-bounds, but no longer 4096-aligned for the
    // align(4096) ProducerPage it will be cast to.
    edit_ring0(&section, dir, |r| r.sq_producer.offset += 64);
    assert_eq!(validate(&section), Some(SectionError::RegionMisaligned));
}

#[test]
fn overlapping_ring_regions_are_rejected() {
    let (section, layout) = fresh();
    let dir = layout.ring_directory.offset;
    // Point cq_producer at sq_producer: both aligned and in-bounds, but they now
    // overlap (breaking the one-writer discipline).
    edit_ring0(&section, dir, |r| {
        r.cq_producer.offset = r.sq_producer.offset
    });
    assert_eq!(validate(&section), Some(SectionError::RegionOverlap));
}

#[test]
fn non_zero_reserved_field_is_rejected() {
    let (section, _) = fresh();
    edit_header(&section, |h| h.reserved[0] = 1);
    assert_eq!(validate(&section), Some(SectionError::ReservedNonZero));
}

#[test]
fn under_sized_entries_region_is_rejected() {
    let (section, layout) = fresh();
    let dir = layout.ring_directory.offset;
    // In-bounds and aligned, but too small to hold sq_capacity SQEs.
    edit_ring0(&section, dir, |r| r.sq_entries.length = 64);
    assert_eq!(validate(&section), Some(SectionError::BadRingDesc));
}

/// splitmix64: a tiny deterministic PRNG (no `rand` dependency).
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[test]
fn validate_never_panics_on_arbitrary_or_bitflipped_input() {
    let mut rng = SplitMix(0x243F_6A88_85A3_08D3);
    // Miri interprets ~100x slower; a smaller sweep still exercises the paths.
    let (random_iters, bitflip_iters) = if cfg!(miri) { (60, 20) } else { (5000, 2000) };

    // Arbitrary buffers of varying length.
    for _ in 0..random_iters {
        let len = (rng.next() % 8193) as usize;
        let mut buf = vec![0u8; len];
        for byte in buf.iter_mut() {
            *byte = (rng.next() & 0xff) as u8;
        }
        // SAFETY: the pointer covers `len` readable bytes.
        let _ = unsafe { PhysicalLayout::validate(buf.as_ptr(), buf.len()) };
        // The control decoder must also tolerate arbitrary bytes.
        let _ = serve_setup(&buf);
    }

    // Bit-flips in an otherwise valid section.
    for _ in 0..bitflip_iters {
        let (section, _layout) = fresh();
        let flips = (rng.next() % 8) + 1;
        for _ in 0..flips {
            let index = (rng.next() as usize) % section.len();
            // SAFETY: `index < len`; a single in-bounds byte is xor-flipped.
            unsafe {
                let cell = section.base().add(index);
                *cell ^= (rng.next() & 0xff) as u8;
            }
        }
        let _ = validate(&section);
    }
}
