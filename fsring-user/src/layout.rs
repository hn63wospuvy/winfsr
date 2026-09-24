//! Physical section layout: compute, construct, and validate.
//!
//! The ABI validates only the *daemon-writable view* subset of a section
//! ([`SessionViewLayout`]); the concrete placement of every region is a layout
//! decision the kernel makes and describes in the `GlobalHeader`/`RingDesc`
//! self-describing tables. This module makes that decision for `fsring-user`:
//! [`PhysicalLayout::compute`] chooses a page-aligned layout, `construct` writes
//! the self-describing tables into a zeroed section, and `validate` parses a
//! peer-constructed section as hostile input.

use core::mem::{align_of, size_of};
use core::ptr;

use fsring_abi::features::FeatureSet;
use fsring_abi::layout::{
    ConsumerPage, Cqe, GlobalHeader, ProducerPage, RegionDesc, RingDesc, SlotClassDesc, Sqe,
    FSRING_ABI_MAJOR, FSRING_ABI_MINOR, FSRING_ENDIAN_LITTLE, FSRING_MAGIC, SLOT_CLASS_COUNT,
};
use fsring_abi::section_layout::{
    validate_finished_section_v21, SectionLayoutError, SectionLayoutPlan,
};
use fsring_abi::slots::{validate_slot_arena, validate_zeroed_padding, SlotDirection};
use fsring_abi::validate::{validate_section_size_v21, RingViewLayout, ValidatedSetupRequest};

use crate::error::SectionError;

/// The six self-describing regions of one ring plus its capacities.
///
/// This remains a `Vec`-friendly host fixture over the compact ABI plan.
#[derive(Clone, Copy)]
pub struct RingRegions {
    pub sq_capacity: u32,
    pub cq_capacity: u32,
    pub sq_entries: RegionDesc,
    pub sq_producer: RegionDesc,
    pub sq_consumer: RegionDesc,
    pub cq_entries: RegionDesc,
    pub cq_producer: RegionDesc,
    pub cq_consumer: RegionDesc,
}

/// A concrete page-aligned placement of every region of a section.
#[derive(Clone)]
pub struct PhysicalLayout {
    pub section_size: u64,
    pub page_size: u32,
    pub ring_directory: RegionDesc,
    pub k2u_slots: RegionDesc,
    pub u2k_arena: RegionDesc,
    pub k2u_slot_classes: [SlotClassDesc; SLOT_CLASS_COUNT],
    pub u2k_slot_classes: [SlotClassDesc; SLOT_CLASS_COUNT],
    pub notify_names: RegionDesc,
    pub rings: Vec<RingRegions>,
    protocol_features: FeatureSet,
    os_capabilities: FeatureSet,
    max_inflight: u32,
    session_epoch: u64,
    plan: Option<SectionLayoutPlan>,
}

const RING_DESC_VERSION: u16 = FSRING_ABI_MINOR;

fn is_pow2_ge2(value: u32) -> bool {
    value >= 2 && value.is_power_of_two()
}

fn map_plan_error(error: SectionLayoutError) -> SectionError {
    match error {
        SectionLayoutError::InvalidPageSize => SectionError::BadPageSize,
        SectionLayoutError::InvalidCapacity => SectionError::BadCapacity,
        SectionLayoutError::InvalidIdentity => SectionError::RevisionMismatch,
        SectionLayoutError::InvalidRegion | SectionLayoutError::InvalidDescriptor => {
            SectionError::BadRingDesc
        }
        SectionLayoutError::InvalidPadding | SectionLayoutError::OutputNotZero => {
            SectionError::ReservedNonZero
        }
        SectionLayoutError::ArithmeticOverflow => SectionError::Arithmetic,
        SectionLayoutError::SectionTooLarge | SectionLayoutError::BufferTooSmall => {
            SectionError::SectionTooSmall
        }
    }
}

/// Validate one slot arena as hostile input: the ABI `validate_slot_arena` over
/// the header-supplied descriptors, then `validate_zeroed_padding` over a
/// **private single-fetched copy** of the arena's final padding.
///
/// # Safety
/// `base` must point to at least `len` readable bytes.
unsafe fn validate_arena(
    base: *const u8,
    len: usize,
    section_size: u64,
    direction: SlotDirection,
    arena: RegionDesc,
    classes: [SlotClassDesc; SLOT_CLASS_COUNT],
) -> Result<(), SectionError> {
    let validated = validate_slot_arena(direction, section_size, arena, classes)
        .map_err(|_| SectionError::BadSlotArena)?;
    let padding = validated.final_padding();
    let start = usize::try_from(padding.start).map_err(|_| SectionError::Arithmetic)?;
    let end = usize::try_from(padding.end).map_err(|_| SectionError::Arithmetic)?;
    if start > end || end > len {
        return Err(SectionError::RegionOutOfBounds);
    }
    let mut copy = vec![0u8; end - start];
    // SAFETY: `[start, end) ⊆ [0, len)` (checked above); `base` covers `len`
    // readable bytes; copy exactly the padding into a private owned buffer.
    unsafe { ptr::copy_nonoverlapping(base.add(start), copy.as_mut_ptr(), end - start) };
    validate_zeroed_padding(&copy, padding).map_err(|_| SectionError::BadSlotArena)?;
    Ok(())
}

fn region_end(region: RegionDesc, section_size: u64) -> Result<u64, SectionError> {
    let end = region
        .offset
        .checked_add(region.length)
        .ok_or(SectionError::Arithmetic)?;
    if end > section_size {
        return Err(SectionError::RegionOutOfBounds);
    }
    Ok(end)
}

fn check_region(region: RegionDesc, section_size: u64) -> Result<(), SectionError> {
    region_end(region, section_size).map(|_| ())
}

/// A region that will be cast to `T`: in-bounds, aligned for `T`, and at least
/// `size_of::<T>()` long.
fn check_typed_region<T>(region: RegionDesc, section_size: u64) -> Result<(), SectionError> {
    check_region(region, section_size)?;
    if region.offset % align_of::<T>() as u64 != 0 {
        return Err(SectionError::RegionMisaligned);
    }
    if region.length < size_of::<T>() as u64 {
        return Err(SectionError::BadRingDesc);
    }
    Ok(())
}

/// A region holding `count` values of `T`: in-bounds, aligned for `T`, and at
/// least `count * size_of::<T>()` long.
fn check_array_region<T>(
    region: RegionDesc,
    count: u32,
    section_size: u64,
) -> Result<(), SectionError> {
    check_region(region, section_size)?;
    if region.offset % align_of::<T>() as u64 != 0 {
        return Err(SectionError::RegionMisaligned);
    }
    let needed = u64::from(count)
        .checked_mul(size_of::<T>() as u64)
        .ok_or(SectionError::Arithmetic)?;
    if region.length < needed {
        return Err(SectionError::BadRingDesc);
    }
    Ok(())
}

/// Reject any pairwise overlap among a section's regions (sorted-sweep, so
/// hostile large ring counts stay `O(n log n)`, not `O(n^2)`).
fn check_no_overlap(mut intervals: Vec<(u64, u64)>) -> Result<(), SectionError> {
    intervals.sort_by_key(|&(start, _)| start);
    for pair in intervals.windows(2) {
        // pair[i] precedes pair[i+1] by start; a later start inside the earlier
        // region's [start, end) is an overlap.
        if pair[0].1 > pair[1].0 {
            return Err(SectionError::RegionOverlap);
        }
    }
    Ok(())
}

impl PhysicalLayout {
    /// Materialize the host-friendly `Vec` view of a compact ABI plan.
    pub fn from_plan(plan: &SectionLayoutPlan) -> Self {
        let rings = plan
            .rings()
            .map(|ring| RingRegions {
                sq_capacity: plan.sq_capacity(),
                cq_capacity: plan.cq_capacity(),
                sq_entries: ring.sq_entries,
                sq_producer: ring.sq_producer,
                sq_consumer: ring.sq_consumer,
                cq_entries: ring.cq_entries,
                cq_producer: ring.cq_producer,
                cq_consumer: ring.cq_consumer,
            })
            .collect();
        Self {
            section_size: plan.section_size(),
            page_size: plan.page_size(),
            ring_directory: plan.ring_directory(),
            k2u_slots: plan.k2u_slots(),
            u2k_arena: plan.u2k_slots(),
            k2u_slot_classes: plan.k2u_slot_classes(),
            u2k_slot_classes: plan.u2k_slot_classes(),
            notify_names: plan.notify_names(),
            rings,
            protocol_features: plan.protocol_features(),
            os_capabilities: plan.os_capabilities(),
            max_inflight: plan.max_inflight(),
            session_epoch: plan.session_epoch(),
            plan: Some(*plan),
        }
    }

    /// Compute a page-aligned layout for the validated topology.
    ///
    /// Every region offset is placed on a 64 KiB boundary so the daemon-writable
    /// views satisfy [`SessionViewLayout::for_setup`]; the `u2k` arena length is
    /// 64 KiB-aligned and every other length is page-aligned.
    ///
    /// [`SessionViewLayout::for_setup`]: fsring_abi::validate::SessionViewLayout::for_setup
    pub fn compute(setup: &ValidatedSetupRequest, page_size: u32) -> Result<Self, SectionError> {
        let plan = SectionLayoutPlan::compute(setup, page_size).map_err(map_plan_error)?;
        Ok(Self::from_plan(&plan))
    }

    /// The session epoch this layout was computed for (grants validate against
    /// it).
    pub fn session_epoch(&self) -> u64 {
        self.session_epoch
    }

    /// The daemon-writable views for [`SessionViewLayout::for_setup`]: the
    /// per-ring `(sq_consumer, cq_entries, cq_producer)` triples and the `u2k`
    /// arena.
    ///
    /// [`SessionViewLayout::for_setup`]: fsring_abi::validate::SessionViewLayout::for_setup
    pub fn writable_views(&self) -> (Vec<RingViewLayout>, RegionDesc) {
        let rings = self
            .rings
            .iter()
            .map(|ring| RingViewLayout {
                sq_consumer: ring.sq_consumer,
                cq_entries: ring.cq_entries,
                cq_producer: ring.cq_producer,
            })
            .collect();
        (rings, self.u2k_arena)
    }

    /// Write the self-describing `GlobalHeader` and `RingDesc` tables into a
    /// fresh zeroed section. Producer/consumer pages and entries are left zeroed
    /// (their correct initial state: `tail = head = 0`, `park_state = ACTIVE`).
    ///
    /// # Safety
    /// `base` must point to a live, zeroed, writable mapping of at least
    /// [`section_size`](PhysicalLayout::section_size) bytes for the duration of
    /// this call.
    pub unsafe fn construct(&self, base: *mut u8, len: usize) {
        if let Some(plan) = &self.plan {
            // SAFETY: the caller promises `base` covers `len` live writable bytes.
            let output = unsafe { core::slice::from_raw_parts_mut(base, len) };
            plan.construct(output)
                .expect("construct requires a zeroed mapping of sufficient length");
            return;
        }

        // The expectation-free legacy parser accepts structurally valid,
        // non-canonical placement, so it cannot manufacture a compact plan.
        // Preserve its public parse->construct behavior by serializing its
        // already-validated metadata without performing any placement math.
        debug_assert!(len as u64 >= self.section_size);
        let header = GlobalHeader {
            magic: FSRING_MAGIC,
            header_size: size_of::<GlobalHeader>() as u16,
            abi_major: FSRING_ABI_MAJOR,
            abi_minor: FSRING_ABI_MINOR,
            byte_order: FSRING_ENDIAN_LITTLE,
            header_flags: 0,
            page_size: self.page_size,
            session_epoch: self.session_epoch,
            section_size: self.section_size,
            ring_count: self.rings.len() as u32,
            ring_desc_size: size_of::<RingDesc>() as u32,
            ring_directory: self.ring_directory,
            k2u_slots: self.k2u_slots,
            u2k_slots: self.u2k_arena,
            notify_names: self.notify_names,
            protocol_features: self.protocol_features,
            os_capabilities: self.os_capabilities,
            max_inflight: self.max_inflight,
            flags: 0,
            k2u_slot_classes: self.k2u_slot_classes,
            u2k_slot_classes: self.u2k_slot_classes,
            reserved: [0; 3824],
        };
        // SAFETY: the caller guarantees `base` covers `section_size` writable
        // bytes; the header occupies offset zero and needs no alignment.
        unsafe { ptr::write_unaligned(base.cast::<GlobalHeader>(), header) };
        for (index, ring) in self.rings.iter().enumerate() {
            let descriptor = RingDesc {
                magic: FSRING_MAGIC,
                desc_size: size_of::<RingDesc>() as u16,
                desc_version: RING_DESC_VERSION,
                ring_index: index as u32,
                flags: 0,
                sq_capacity: ring.sq_capacity,
                cq_capacity: ring.cq_capacity,
                sq_entries: ring.sq_entries,
                sq_producer: ring.sq_producer,
                sq_consumer: ring.sq_consumer,
                cq_entries: ring.cq_entries,
                cq_producer: ring.cq_producer,
                cq_consumer: ring.cq_consumer,
                reserved: [0; 8],
            };
            let offset = self.ring_directory.offset + index as u64 * size_of::<RingDesc>() as u64;
            debug_assert!(offset + size_of::<RingDesc>() as u64 <= len as u64);
            // SAFETY: legacy validation proved every descriptor slot lies in
            // the in-bounds directory region.
            unsafe { ptr::write_unaligned(base.add(offset as usize).cast(), descriptor) };
        }
    }

    /// Validate a section against the negotiated SETUP request and epoch.
    ///
    /// The mapping is single-fetched into private storage before the compact ABI
    /// parser examines it, so hostile concurrent mutation cannot produce a
    /// mixed header/directory snapshot.
    ///
    /// # Safety
    /// `base` must point to at least `len` readable bytes.
    pub unsafe fn validate_for_setup(
        base: *const u8,
        len: usize,
        expected: &ValidatedSetupRequest,
        expected_session_epoch: u64,
    ) -> Result<Self, SectionError> {
        let mut snapshot = vec![0u8; len];
        // SAFETY: the caller promises `base` covers `len` readable bytes and
        // `snapshot` owns exactly `len` writable bytes.
        unsafe { ptr::copy_nonoverlapping(base, snapshot.as_mut_ptr(), len) };
        let validated = validate_finished_section_v21(&snapshot, expected, expected_session_epoch)
            .map_err(map_plan_error)?;
        Ok(Self::from_plan(validated.plan()))
    }

    /// Validate a peer-constructed section as hostile input, returning the
    /// parsed layout. Single-fetches the header into a local copy and
    /// bounds-checks every descriptor before use; never dereferences an
    /// unvalidated offset and never panics.
    ///
    /// # Safety
    /// `base` must point to at least `len` readable bytes.
    pub unsafe fn validate(base: *const u8, len: usize) -> Result<Self, SectionError> {
        if len < size_of::<GlobalHeader>() {
            return Err(SectionError::SectionTooSmall);
        }
        // SAFETY: the mapping holds at least `size_of::<GlobalHeader>()` bytes
        // (checked above); `read_unaligned` needs no alignment guarantee.
        let header = unsafe { ptr::read_unaligned(base.cast::<GlobalHeader>()) };

        if header.magic != FSRING_MAGIC {
            return Err(SectionError::BadMagic);
        }
        if header.header_size as usize != size_of::<GlobalHeader>() {
            return Err(SectionError::UnsupportedHeaderSize);
        }
        if header.abi_major != FSRING_ABI_MAJOR || header.abi_minor != FSRING_ABI_MINOR {
            return Err(SectionError::RevisionMismatch);
        }
        if header.byte_order != FSRING_ENDIAN_LITTLE {
            return Err(SectionError::BadByteOrder);
        }
        if header.page_size == 0 || !header.page_size.is_power_of_two() {
            return Err(SectionError::BadPageSize);
        }
        if header.reserved.iter().any(|&byte| byte != 0) {
            return Err(SectionError::ReservedNonZero);
        }

        let section_size = header.section_size;
        validate_section_size_v21(section_size).map_err(|_| SectionError::SectionTooSmall)?;
        if section_size > len as u64 {
            return Err(SectionError::SectionTooSmall);
        }

        // Collect every region as an interval for the final non-overlap sweep.
        // The header occupies `[0, size_of::<GlobalHeader>())` at offset 0.
        let mut intervals: Vec<(u64, u64)> = vec![(0, size_of::<GlobalHeader>() as u64)];

        check_region(header.ring_directory, section_size)?;
        intervals.push((
            header.ring_directory.offset,
            region_end(header.ring_directory, section_size)?,
        ));
        let ring_count = header.ring_count;
        let directory_bytes = u64::from(ring_count)
            .checked_mul(size_of::<RingDesc>() as u64)
            .ok_or(SectionError::Arithmetic)?;
        if directory_bytes > header.ring_directory.length {
            return Err(SectionError::BadRingDesc);
        }

        let mut rings = Vec::with_capacity(ring_count as usize);
        for index in 0..ring_count {
            let offset =
                header.ring_directory.offset + u64::from(index) * size_of::<RingDesc>() as u64;
            // SAFETY: `offset + size_of::<RingDesc>()` lies within the ring
            // directory region, which is within `section_size <= len`.
            let ring_desc =
                unsafe { ptr::read_unaligned(base.add(offset as usize).cast::<RingDesc>()) };
            if ring_desc.magic != FSRING_MAGIC
                || ring_desc.desc_size as usize != size_of::<RingDesc>()
            {
                return Err(SectionError::BadRingDesc);
            }
            if ring_desc.reserved.iter().any(|&byte| byte != 0) {
                return Err(SectionError::ReservedNonZero);
            }
            if !is_pow2_ge2(ring_desc.sq_capacity) || !is_pow2_ge2(ring_desc.cq_capacity) {
                return Err(SectionError::BadCapacity);
            }
            // Each region is bounds-, alignment-, and length-checked for the type
            // it will be cast to at `attach` time (pages are `align(4096)`,
            // entries `align(64)`), so a validated layout is safe to attach.
            check_typed_region::<ProducerPage>(ring_desc.sq_producer, section_size)?;
            check_typed_region::<ConsumerPage>(ring_desc.sq_consumer, section_size)?;
            check_array_region::<Sqe>(ring_desc.sq_entries, ring_desc.sq_capacity, section_size)?;
            check_typed_region::<ProducerPage>(ring_desc.cq_producer, section_size)?;
            check_typed_region::<ConsumerPage>(ring_desc.cq_consumer, section_size)?;
            check_array_region::<Cqe>(ring_desc.cq_entries, ring_desc.cq_capacity, section_size)?;
            for region in [
                ring_desc.sq_producer,
                ring_desc.sq_consumer,
                ring_desc.sq_entries,
                ring_desc.cq_producer,
                ring_desc.cq_consumer,
                ring_desc.cq_entries,
            ] {
                intervals.push((region.offset, region_end(region, section_size)?));
            }
            rings.push(RingRegions {
                sq_capacity: ring_desc.sq_capacity,
                cq_capacity: ring_desc.cq_capacity,
                sq_entries: ring_desc.sq_entries,
                sq_producer: ring_desc.sq_producer,
                sq_consumer: ring_desc.sq_consumer,
                cq_entries: ring_desc.cq_entries,
                cq_producer: ring_desc.cq_producer,
                cq_consumer: ring_desc.cq_consumer,
            });
        }

        for region in [header.u2k_slots, header.k2u_slots, header.notify_names] {
            intervals.push((region.offset, region_end(region, section_size)?));
        }

        check_no_overlap(intervals)?;

        // Validate both slot arenas as hostile input: the ABI arena rules plus a
        // zeroed final padding, over private copies (never in place).
        // SAFETY: `base` covers `len` readable bytes (guaranteed by the caller).
        unsafe {
            validate_arena(
                base,
                len,
                section_size,
                SlotDirection::K2u,
                header.k2u_slots,
                header.k2u_slot_classes,
            )?;
            validate_arena(
                base,
                len,
                section_size,
                SlotDirection::U2k,
                header.u2k_slots,
                header.u2k_slot_classes,
            )?;
        }

        Ok(Self {
            section_size,
            page_size: header.page_size,
            ring_directory: header.ring_directory,
            k2u_slots: header.k2u_slots,
            u2k_arena: header.u2k_slots,
            k2u_slot_classes: header.k2u_slot_classes,
            u2k_slot_classes: header.u2k_slot_classes,
            notify_names: header.notify_names,
            rings,
            protocol_features: header.protocol_features,
            os_capabilities: header.os_capabilities,
            max_inflight: header.max_inflight,
            session_epoch: header.session_epoch,
            plan: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::valid_setup;
    use crate::section::{HeapSection, SharedSection};
    use fsring_abi::validate::SessionViewLayout;

    const PAGE: u32 = 4096;

    #[test]
    fn physical_layout_is_exactly_the_compact_plan_fixture() {
        // Mutation caught: PhysicalLayout::compute regains an independent
        // placement path or from_plan drops/reorders a ring descriptor.
        let setup = valid_setup(16);
        let plan = fsring_abi::section_layout::SectionLayoutPlan::compute(&setup, PAGE)
            .expect("compact plan");
        let from_plan = PhysicalLayout::from_plan(&plan);
        let computed = PhysicalLayout::compute(&setup, PAGE).expect("host layout");
        assert_eq!(from_plan.section_size, computed.section_size);
        assert_eq!(from_plan.page_size, computed.page_size);
        assert_eq!(from_plan.ring_directory, computed.ring_directory);
        assert_eq!(from_plan.k2u_slots, computed.k2u_slots);
        assert_eq!(from_plan.u2k_arena, computed.u2k_arena);
        assert_eq!(from_plan.k2u_slot_classes, computed.k2u_slot_classes);
        assert_eq!(from_plan.u2k_slot_classes, computed.u2k_slot_classes);
        assert_eq!(from_plan.notify_names, computed.notify_names);
        assert_eq!(from_plan.session_epoch(), computed.session_epoch());
        assert_eq!(from_plan.rings.len(), computed.rings.len());
        for (host, compact) in computed.rings.iter().zip(plan.rings()) {
            assert_eq!(host.sq_capacity, plan.sq_capacity());
            assert_eq!(host.cq_capacity, plan.cq_capacity());
            assert_eq!(host.sq_entries, compact.sq_entries);
            assert_eq!(host.sq_producer, compact.sq_producer);
            assert_eq!(host.sq_consumer, compact.sq_consumer);
            assert_eq!(host.cq_entries, compact.cq_entries);
            assert_eq!(host.cq_producer, compact.cq_producer);
            assert_eq!(host.cq_consumer, compact.cq_consumer);
        }

        let mut compact_bytes = vec![0u8; plan.section_size() as usize];
        plan.construct(&mut compact_bytes).expect("compact bytes");
        let mut host_bytes = vec![0u8; plan.section_size() as usize];
        // SAFETY: `host_bytes` is a zeroed writable allocation of section_size.
        unsafe { computed.construct(host_bytes.as_mut_ptr(), host_bytes.len()) };
        assert_eq!(host_bytes, compact_bytes);
    }

    #[test]
    fn compute_writable_views_are_accepted_by_for_setup() {
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).expect("compute");
        let (rings, u2k) = layout.writable_views();
        SessionViewLayout::for_setup(&setup, layout.section_size, PAGE, u2k, &rings)
            .expect("for_setup accepts the computed writable views");
    }

    #[test]
    fn construct_then_validate_round_trips() {
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).expect("compute");
        let section = HeapSection::with_len(layout.section_size as usize, PAGE as usize);
        // SAFETY: the section is a zeroed mapping of exactly section_size bytes.
        unsafe { layout.construct(section.base(), section.len()) };
        // SAFETY: the section holds `len()` readable bytes.
        let parsed = unsafe { PhysicalLayout::validate(section.base(), section.len()) }
            .expect("validate accepts a well-formed section");
        assert_eq!(parsed.section_size, layout.section_size);
        assert_eq!(parsed.rings.len(), 1);
        assert_eq!(parsed.rings[0].sq_capacity, 8);
        assert_eq!(parsed.rings[0].cq_capacity, 2);
        assert_eq!(
            parsed.rings[0].sq_entries.offset,
            layout.rings[0].sq_entries.offset
        );
        assert_eq!(
            parsed.rings[0].cq_producer.offset,
            layout.rings[0].cq_producer.offset
        );
    }

    #[test]
    fn computed_arenas_are_accepted_by_validate_slot_arena() {
        use fsring_abi::slots::{validate_slot_arena, SlotDirection};
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).expect("compute");
        validate_slot_arena(
            SlotDirection::K2u,
            layout.section_size,
            layout.k2u_slots,
            layout.k2u_slot_classes,
        )
        .expect("k2u arena is ABI-valid");
        validate_slot_arena(
            SlotDirection::U2k,
            layout.section_size,
            layout.u2k_arena,
            layout.u2k_slot_classes,
        )
        .expect("u2k arena is ABI-valid");
    }

    #[test]
    fn first_active_slot_class_is_packed() {
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).expect("compute");
        let first = layout.k2u_slot_classes[0];
        assert!(
            first.slot_size >= 256,
            "an active class has a real slot size"
        );
        assert!(first.slot_count >= 1);
        assert_eq!(
            first.data_offset % 64,
            0,
            "data_offset is SLOT_ALIGNMENT-aligned"
        );
        assert!(
            first.data_offset >= layout.k2u_slots.offset,
            "the class lives inside its arena"
        );
    }

    /// Construct a valid section, then mutate the single-fetched `GlobalHeader`
    /// through `corrupt`, and return the section for `validate`.
    fn corrupt_header(corrupt: impl FnOnce(&mut GlobalHeader)) -> (HeapSection, u64) {
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).expect("compute");
        let section = HeapSection::with_len(layout.section_size as usize, PAGE as usize);
        // SAFETY: zeroed mapping of section_size bytes.
        unsafe { layout.construct(section.base(), section.len()) };
        // SAFETY: the header occupies offset 0; read/modify/write it unaligned.
        unsafe {
            let mut header = ptr::read_unaligned(section.base().cast::<GlobalHeader>());
            corrupt(&mut header);
            ptr::write_unaligned(section.base().cast::<GlobalHeader>(), header);
        }
        (section, layout.section_size)
    }

    #[test]
    fn validate_rejects_misaligned_slot_class() {
        let (section, _) = corrupt_header(|h| h.k2u_slot_classes[0].data_offset += 1);
        // SAFETY: the section holds `len()` readable bytes.
        let result = unsafe { PhysicalLayout::validate(section.base(), section.len()) };
        assert_eq!(result.err(), Some(SectionError::BadSlotArena));
    }

    #[test]
    fn validate_rejects_non_power_of_two_slot_size() {
        let (section, _) = corrupt_header(|h| h.k2u_slot_classes[0].slot_size += 1);
        // SAFETY: the section holds `len()` readable bytes.
        let result = unsafe { PhysicalLayout::validate(section.base(), section.len()) };
        assert_eq!(result.err(), Some(SectionError::BadSlotArena));
    }

    #[test]
    fn validate_rejects_non_increasing_slot_sizes() {
        // The canonical u2k arena is [credit(2048), control(131072)]; make the
        // second class's size equal the first so sizes stop strictly increasing.
        let (section, _) = corrupt_header(|h| {
            h.u2k_slot_classes[1].slot_size = h.u2k_slot_classes[0].slot_size;
        });
        // SAFETY: the section holds `len()` readable bytes.
        let result = unsafe { PhysicalLayout::validate(section.base(), section.len()) };
        assert_eq!(result.err(), Some(SectionError::BadSlotArena));
    }

    #[test]
    fn validate_rejects_non_zero_slot_padding() {
        use fsring_abi::slots::{validate_slot_arena, SlotDirection};
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).expect("compute");
        let section = HeapSection::with_len(layout.section_size as usize, PAGE as usize);
        // SAFETY: zeroed mapping.
        unsafe { layout.construct(section.base(), section.len()) };
        // The u2k arena rounds a non-64K-aligned packed end up to 64K, so it has
        // real final padding; write a non-zero byte into it.
        let arena = validate_slot_arena(
            SlotDirection::U2k,
            layout.section_size,
            layout.u2k_arena,
            layout.u2k_slot_classes,
        )
        .expect("u2k arena");
        let pad = arena.final_padding();
        assert!(pad.end > pad.start, "the u2k arena has final padding");
        // SAFETY: `pad.start` is inside the section (`< section_size <= len`).
        unsafe { *section.base().add(pad.start as usize) = 1 };
        // SAFETY: the section holds `len()` readable bytes.
        let result = unsafe { PhysicalLayout::validate(section.base(), section.len()) };
        assert_eq!(result.err(), Some(SectionError::BadSlotArena));
    }

    #[test]
    fn validate_rejects_active_after_inactive_slot_class() {
        // The canonical u2k arena has two active classes; blank the first cleanly
        // so the second becomes "active after inactive".
        let (section, _) = corrupt_header(|h| {
            h.u2k_slot_classes[0] = SlotClassDesc {
                slot_size: 0,
                slot_count: 0,
                data_offset: 0,
            };
        });
        // SAFETY: the section holds `len()` readable bytes.
        let result = unsafe { PhysicalLayout::validate(section.base(), section.len()) };
        assert_eq!(result.err(), Some(SectionError::BadSlotArena));
    }

    #[test]
    fn validate_rejects_short_buffer() {
        let bytes = [0u8; 64];
        // SAFETY: the pointer covers 64 readable bytes.
        let result = unsafe { PhysicalLayout::validate(bytes.as_ptr(), bytes.len()) };
        assert_eq!(result.err(), Some(SectionError::SectionTooSmall));
    }

    #[test]
    fn validate_rejects_bad_magic() {
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, PAGE).expect("compute");
        let section = HeapSection::with_len(layout.section_size as usize, PAGE as usize);
        // SAFETY: zeroed mapping of section_size bytes.
        unsafe { layout.construct(section.base(), section.len()) };
        // SAFETY: corrupt the first magic byte in-bounds.
        unsafe { ptr::write(section.base(), 0xFF) };
        // SAFETY: the section holds `len()` readable bytes.
        let result = unsafe { PhysicalLayout::validate(section.base(), section.len()) };
        assert_eq!(result.err(), Some(SectionError::BadMagic));
    }
}
