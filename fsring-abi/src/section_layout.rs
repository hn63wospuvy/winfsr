//! Allocation-free canonical placement and validation for ABI 2.1 sections.

use core::mem::size_of;

#[cfg(test)]
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::codec::{try_decode, try_encode};
use crate::control::SlotClassRequest;
use crate::features::FeatureSet;
use crate::layout::{
    ConsumerPage, Cqe, GlobalHeader, ProducerPage, RegionDesc, RingDesc, SlotClassDesc, Sqe,
    FSRING_ABI_MAJOR, FSRING_ABI_MINOR, FSRING_ENDIAN_LITTLE, FSRING_MAGIC, SLOT_CLASS_COUNT,
};
use crate::limits::{
    MAX_CQ_CAPACITY, MAX_SECTION_BYTES, MAX_SQ_CAPACITY, MIN_CQ_CAPACITY, MIN_SQ_CAPACITY,
    SLOT_ALIGNMENT, USER_VIEW_OFFSET_ALIGNMENT,
};
use crate::slots::{validate_slot_arena, SlotDirection};
use crate::validate::ValidatedSetupRequest;

const RING_DESC_VERSION: u16 = FSRING_ABI_MINOR;
const ZERO_CLASS: SlotClassDesc = SlotClassDesc {
    slot_size: 0,
    slot_count: 0,
    data_offset: 0,
};

#[cfg(test)]
static HEADER_DECODE_COUNT: AtomicUsize = AtomicUsize::new(0);

fn decode_header(input: &[u8]) -> Result<GlobalHeader, SectionLayoutError> {
    #[cfg(test)]
    HEADER_DECODE_COUNT.fetch_add(1, Ordering::Relaxed);
    try_decode::<GlobalHeader>(input).map_err(|_| SectionLayoutError::BufferTooSmall)
}

/// cbindgen:ignore
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionLayoutPlan {
    section_size: u64,
    page_size: u32,
    ring_count: u32,
    sq_capacity: u32,
    cq_capacity: u32,
    ring_directory: RegionDesc,
    ring_base: u64,
    ring_stride: u64,
    k2u_slots: RegionDesc,
    u2k_slots: RegionDesc,
    notify_names: RegionDesc,
    k2u_slot_classes: [SlotClassDesc; SLOT_CLASS_COUNT],
    u2k_slot_classes: [SlotClassDesc; SLOT_CLASS_COUNT],
    protocol_features: FeatureSet,
    os_capabilities: FeatureSet,
    max_inflight: u32,
    session_epoch: u64,
}

/// cbindgen:ignore
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingLayoutPlan {
    pub ring_index: u32,
    pub sq_entries: RegionDesc,
    pub sq_producer: RegionDesc,
    pub sq_consumer: RegionDesc,
    pub cq_entries: RegionDesc,
    pub cq_producer: RegionDesc,
    pub cq_consumer: RegionDesc,
}

/// cbindgen:ignore
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionLayoutError {
    InvalidPageSize,
    InvalidCapacity,
    InvalidIdentity,
    InvalidRegion,
    InvalidPadding,
    InvalidDescriptor,
    ArithmeticOverflow,
    SectionTooLarge,
    BufferTooSmall,
    OutputNotZero,
}

/// cbindgen:ignore
pub struct RingLayoutIter<'a> {
    plan: &'a SectionLayoutPlan,
    next_index: u32,
}

/// cbindgen:ignore
pub struct ValidatedSectionImage {
    plan: SectionLayoutPlan,
}

const fn checked_align_up(value: u64, alignment: u64) -> Option<u64> {
    let mask = match alignment.checked_sub(1) {
        Some(mask) => mask,
        None => return None,
    };
    let with_mask = match value.checked_add(mask) {
        Some(value) => value,
        None => return None,
    };
    Some(with_mask & !mask)
}

fn place(cursor: &mut u64, len: u64, len_align: u64) -> Result<RegionDesc, SectionLayoutError> {
    let length = checked_align_up(len, len_align).ok_or(SectionLayoutError::ArithmeticOverflow)?;
    let span = checked_align_up(length, USER_VIEW_OFFSET_ALIGNMENT)
        .ok_or(SectionLayoutError::ArithmeticOverflow)?;
    let offset = *cursor;
    *cursor = cursor
        .checked_add(span)
        .ok_or(SectionLayoutError::ArithmeticOverflow)?;
    Ok(RegionDesc { offset, length })
}

fn pack_arena(
    offset: u64,
    requests: &[SlotClassRequest; SLOT_CLASS_COUNT],
) -> Result<(RegionDesc, [SlotClassDesc; SLOT_CLASS_COUNT]), SectionLayoutError> {
    let mut classes = [ZERO_CLASS; SLOT_CLASS_COUNT];
    let mut cursor = offset;
    for (index, request) in requests.iter().enumerate() {
        if request.slot_size == 0 || request.slot_count == 0 {
            continue;
        }
        let data_offset = checked_align_up(cursor, SLOT_ALIGNMENT)
            .ok_or(SectionLayoutError::ArithmeticOverflow)?;
        let length = u64::from(request.slot_size)
            .checked_mul(u64::from(request.slot_count))
            .ok_or(SectionLayoutError::ArithmeticOverflow)?;
        cursor = data_offset
            .checked_add(length)
            .ok_or(SectionLayoutError::ArithmeticOverflow)?;
        classes[index] = SlotClassDesc {
            slot_size: request.slot_size,
            slot_count: request.slot_count,
            data_offset,
        };
    }
    let end = checked_align_up(cursor, USER_VIEW_OFFSET_ALIGNMENT)
        .ok_or(SectionLayoutError::ArithmeticOverflow)?;
    let length = end
        .checked_sub(offset)
        .ok_or(SectionLayoutError::ArithmeticOverflow)?;
    Ok((RegionDesc { offset, length }, classes))
}

const fn region_from_raw(offset: u64, raw_length: u64, page_size: u32) -> Option<RegionDesc> {
    let length = match checked_align_up(raw_length, page_size as u64) {
        Some(length) => length,
        None => return None,
    };
    Some(RegionDesc { offset, length })
}

const fn region_span(region: RegionDesc) -> Option<u64> {
    checked_align_up(region.length, USER_VIEW_OFFSET_ALIGNMENT)
}

const fn advance_region(offset: u64, region: RegionDesc) -> Option<u64> {
    let span = match region_span(region) {
        Some(span) => span,
        None => return None,
    };
    offset.checked_add(span)
}

impl SectionLayoutPlan {
    /// cbindgen:ignore
    pub fn compute(
        setup: &ValidatedSetupRequest,
        page_size: u32,
    ) -> Result<Self, SectionLayoutError> {
        if page_size == 0 || !page_size.is_power_of_two() {
            return Err(SectionLayoutError::InvalidPageSize);
        }
        let topology = setup.topology();
        let ring_count = topology.ring_count();
        let sq_capacity = topology.sq_capacity();
        let cq_capacity = topology.cq_capacity();
        if sq_capacity < MIN_SQ_CAPACITY
            || sq_capacity > MAX_SQ_CAPACITY
            || !sq_capacity.is_power_of_two()
            || cq_capacity < MIN_CQ_CAPACITY
            || cq_capacity > MAX_CQ_CAPACITY
            || !cq_capacity.is_power_of_two()
        {
            return Err(SectionLayoutError::InvalidCapacity);
        }

        let page = u64::from(page_size);
        let mut cursor = 0;
        place(&mut cursor, size_of::<GlobalHeader>() as u64, page)?;
        let directory_bytes = u64::from(ring_count)
            .checked_mul(size_of::<RingDesc>() as u64)
            .ok_or(SectionLayoutError::ArithmeticOverflow)?;
        let ring_directory = place(&mut cursor, directory_bytes, page)?;
        let ring_base = cursor;

        place(&mut cursor, size_of::<ProducerPage>() as u64, page)?;
        place(&mut cursor, size_of::<ConsumerPage>() as u64, page)?;
        place(
            &mut cursor,
            u64::from(sq_capacity)
                .checked_mul(size_of::<Sqe>() as u64)
                .ok_or(SectionLayoutError::ArithmeticOverflow)?,
            page,
        )?;
        place(&mut cursor, size_of::<ProducerPage>() as u64, page)?;
        place(&mut cursor, size_of::<ConsumerPage>() as u64, page)?;
        place(
            &mut cursor,
            u64::from(cq_capacity)
                .checked_mul(size_of::<Cqe>() as u64)
                .ok_or(SectionLayoutError::ArithmeticOverflow)?,
            page,
        )?;
        let ring_stride = cursor
            .checked_sub(ring_base)
            .ok_or(SectionLayoutError::ArithmeticOverflow)?;
        cursor = ring_base
            .checked_add(
                ring_stride
                    .checked_mul(u64::from(ring_count))
                    .ok_or(SectionLayoutError::ArithmeticOverflow)?,
            )
            .ok_or(SectionLayoutError::ArithmeticOverflow)?;

        let (k2u_slots, k2u_slot_classes) = pack_arena(cursor, &topology.k2u_slot_classes())?;
        cursor = cursor
            .checked_add(k2u_slots.length)
            .ok_or(SectionLayoutError::ArithmeticOverflow)?;
        let (u2k_slots, u2k_slot_classes) = pack_arena(cursor, &topology.u2k_slot_classes())?;
        cursor = cursor
            .checked_add(u2k_slots.length)
            .ok_or(SectionLayoutError::ArithmeticOverflow)?;
        let notify_names = place(&mut cursor, page, page)?;
        if cursor > MAX_SECTION_BYTES {
            return Err(SectionLayoutError::SectionTooLarge);
        }

        Ok(Self {
            section_size: cursor,
            page_size,
            ring_count,
            sq_capacity,
            cq_capacity,
            ring_directory,
            ring_base,
            ring_stride,
            k2u_slots,
            u2k_slots,
            notify_names,
            k2u_slot_classes,
            u2k_slot_classes,
            protocol_features: setup.selection().selected_features,
            os_capabilities: setup.selection().detected_os_capabilities,
            max_inflight: topology.max_inflight(),
            session_epoch: 1,
        })
    }

    /// cbindgen:ignore
    pub const fn section_size(&self) -> u64 {
        self.section_size
    }

    /// cbindgen:ignore
    pub const fn page_size(&self) -> u32 {
        self.page_size
    }

    /// cbindgen:ignore
    pub const fn ring_count(&self) -> u32 {
        self.ring_count
    }

    /// cbindgen:ignore
    pub const fn sq_capacity(&self) -> u32 {
        self.sq_capacity
    }

    /// cbindgen:ignore
    pub const fn cq_capacity(&self) -> u32 {
        self.cq_capacity
    }

    /// cbindgen:ignore
    pub const fn ring_directory(&self) -> RegionDesc {
        self.ring_directory
    }

    /// cbindgen:ignore
    pub const fn k2u_slots(&self) -> RegionDesc {
        self.k2u_slots
    }

    /// cbindgen:ignore
    pub const fn u2k_slots(&self) -> RegionDesc {
        self.u2k_slots
    }

    /// cbindgen:ignore
    pub const fn notify_names(&self) -> RegionDesc {
        self.notify_names
    }

    /// cbindgen:ignore
    pub const fn k2u_slot_classes(&self) -> [SlotClassDesc; SLOT_CLASS_COUNT] {
        self.k2u_slot_classes
    }

    /// cbindgen:ignore
    pub const fn u2k_slot_classes(&self) -> [SlotClassDesc; SLOT_CLASS_COUNT] {
        self.u2k_slot_classes
    }

    /// cbindgen:ignore
    pub const fn protocol_features(&self) -> FeatureSet {
        self.protocol_features
    }

    /// cbindgen:ignore
    pub const fn os_capabilities(&self) -> FeatureSet {
        self.os_capabilities
    }

    /// cbindgen:ignore
    pub const fn max_inflight(&self) -> u32 {
        self.max_inflight
    }

    /// cbindgen:ignore
    pub const fn session_epoch(&self) -> u64 {
        self.session_epoch
    }

    /// cbindgen:ignore
    pub const fn ring(&self, index: u32) -> Option<RingLayoutPlan> {
        if index >= self.ring_count {
            return None;
        }
        let ring_delta = match self.ring_stride.checked_mul(index as u64) {
            Some(value) => value,
            None => return None,
        };
        let mut cursor = match self.ring_base.checked_add(ring_delta) {
            Some(value) => value,
            None => return None,
        };

        let sq_producer =
            match region_from_raw(cursor, size_of::<ProducerPage>() as u64, self.page_size) {
                Some(region) => region,
                None => return None,
            };
        cursor = match advance_region(cursor, sq_producer) {
            Some(value) => value,
            None => return None,
        };
        let sq_consumer =
            match region_from_raw(cursor, size_of::<ConsumerPage>() as u64, self.page_size) {
                Some(region) => region,
                None => return None,
            };
        cursor = match advance_region(cursor, sq_consumer) {
            Some(value) => value,
            None => return None,
        };
        let sq_raw = match (self.sq_capacity as u64).checked_mul(size_of::<Sqe>() as u64) {
            Some(value) => value,
            None => return None,
        };
        let sq_entries = match region_from_raw(cursor, sq_raw, self.page_size) {
            Some(region) => region,
            None => return None,
        };
        cursor = match advance_region(cursor, sq_entries) {
            Some(value) => value,
            None => return None,
        };
        let cq_producer =
            match region_from_raw(cursor, size_of::<ProducerPage>() as u64, self.page_size) {
                Some(region) => region,
                None => return None,
            };
        cursor = match advance_region(cursor, cq_producer) {
            Some(value) => value,
            None => return None,
        };
        let cq_consumer =
            match region_from_raw(cursor, size_of::<ConsumerPage>() as u64, self.page_size) {
                Some(region) => region,
                None => return None,
            };
        cursor = match advance_region(cursor, cq_consumer) {
            Some(value) => value,
            None => return None,
        };
        let cq_raw = match (self.cq_capacity as u64).checked_mul(size_of::<Cqe>() as u64) {
            Some(value) => value,
            None => return None,
        };
        let cq_entries = match region_from_raw(cursor, cq_raw, self.page_size) {
            Some(region) => region,
            None => return None,
        };

        Some(RingLayoutPlan {
            ring_index: index,
            sq_entries,
            sq_producer,
            sq_consumer,
            cq_entries,
            cq_producer,
            cq_consumer,
        })
    }

    /// cbindgen:ignore
    pub const fn rings(&self) -> RingLayoutIter<'_> {
        RingLayoutIter {
            plan: self,
            next_index: 0,
        }
    }

    /// cbindgen:ignore
    pub fn construct(&self, output: &mut [u8]) -> Result<(), SectionLayoutError> {
        let needed =
            usize::try_from(self.section_size).map_err(|_| SectionLayoutError::SectionTooLarge)?;
        if output.len() < needed {
            return Err(SectionLayoutError::BufferTooSmall);
        }
        if output.iter().any(|byte| *byte != 0) {
            return Err(SectionLayoutError::OutputNotZero);
        }
        let header = self.header();
        try_encode(&header, &mut output[..size_of::<GlobalHeader>()])
            .map_err(|_| SectionLayoutError::BufferTooSmall)?;
        let directory_offset = usize::try_from(self.ring_directory.offset)
            .map_err(|_| SectionLayoutError::ArithmeticOverflow)?;
        for ring in self.rings() {
            let descriptor = self.ring_desc(ring);
            let relative = usize::try_from(
                u64::from(descriptor.ring_index)
                    .checked_mul(size_of::<RingDesc>() as u64)
                    .ok_or(SectionLayoutError::ArithmeticOverflow)?,
            )
            .map_err(|_| SectionLayoutError::ArithmeticOverflow)?;
            let start = directory_offset
                .checked_add(relative)
                .ok_or(SectionLayoutError::ArithmeticOverflow)?;
            let end = start
                .checked_add(size_of::<RingDesc>())
                .ok_or(SectionLayoutError::ArithmeticOverflow)?;
            try_encode(&descriptor, &mut output[start..end])
                .map_err(|_| SectionLayoutError::BufferTooSmall)?;
        }
        Ok(())
    }

    fn header(&self) -> GlobalHeader {
        GlobalHeader {
            magic: FSRING_MAGIC,
            header_size: size_of::<GlobalHeader>() as u16,
            abi_major: FSRING_ABI_MAJOR,
            abi_minor: FSRING_ABI_MINOR,
            byte_order: FSRING_ENDIAN_LITTLE,
            header_flags: 0,
            page_size: self.page_size,
            session_epoch: self.session_epoch,
            section_size: self.section_size,
            ring_count: self.ring_count,
            ring_desc_size: size_of::<RingDesc>() as u32,
            ring_directory: self.ring_directory,
            k2u_slots: self.k2u_slots,
            u2k_slots: self.u2k_slots,
            notify_names: self.notify_names,
            protocol_features: self.protocol_features,
            os_capabilities: self.os_capabilities,
            max_inflight: self.max_inflight,
            flags: 0,
            k2u_slot_classes: self.k2u_slot_classes,
            u2k_slot_classes: self.u2k_slot_classes,
            reserved: [0; 3824],
        }
    }

    fn ring_desc(&self, ring: RingLayoutPlan) -> RingDesc {
        RingDesc {
            magic: FSRING_MAGIC,
            desc_size: size_of::<RingDesc>() as u16,
            desc_version: RING_DESC_VERSION,
            ring_index: ring.ring_index,
            flags: 0,
            sq_capacity: self.sq_capacity,
            cq_capacity: self.cq_capacity,
            sq_entries: ring.sq_entries,
            sq_producer: ring.sq_producer,
            sq_consumer: ring.sq_consumer,
            cq_entries: ring.cq_entries,
            cq_producer: ring.cq_producer,
            cq_consumer: ring.cq_consumer,
            reserved: [0; 8],
        }
    }
}

impl<'a> Iterator for RingLayoutIter<'a> {
    type Item = RingLayoutPlan;

    fn next(&mut self) -> Option<Self::Item> {
        let ring = self.plan.ring(self.next_index)?;
        self.next_index += 1;
        Some(ring)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.plan.ring_count.saturating_sub(self.next_index) as usize;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for RingLayoutIter<'_> {}

fn header_identity_matches(actual: &GlobalHeader, expected: &GlobalHeader) -> bool {
    actual.magic == expected.magic
        && actual.header_size == expected.header_size
        && actual.abi_major == expected.abi_major
        && actual.abi_minor == expected.abi_minor
        && actual.byte_order == expected.byte_order
        && actual.page_size == expected.page_size
        && actual.session_epoch == expected.session_epoch
        && actual.section_size == expected.section_size
        && actual.ring_count == expected.ring_count
        && actual.ring_desc_size == expected.ring_desc_size
        && actual.protocol_features == expected.protocol_features
        && actual.os_capabilities == expected.os_capabilities
        && actual.max_inflight == expected.max_inflight
}

fn header_regions_match(actual: &GlobalHeader, expected: &GlobalHeader) -> bool {
    actual.ring_directory == expected.ring_directory
        && actual.k2u_slots == expected.k2u_slots
        && actual.u2k_slots == expected.u2k_slots
        && actual.notify_names == expected.notify_names
        && actual.k2u_slot_classes == expected.k2u_slot_classes
        && actual.u2k_slot_classes == expected.u2k_slot_classes
}

fn ring_desc_matches(actual: &RingDesc, expected: &RingDesc) -> bool {
    actual.magic == expected.magic
        && actual.desc_size == expected.desc_size
        && actual.desc_version == expected.desc_version
        && actual.ring_index == expected.ring_index
        && actual.flags == expected.flags
        && actual.sq_capacity == expected.sq_capacity
        && actual.cq_capacity == expected.cq_capacity
        && actual.sq_entries == expected.sq_entries
        && actual.sq_producer == expected.sq_producer
        && actual.sq_consumer == expected.sq_consumer
        && actual.cq_entries == expected.cq_entries
        && actual.cq_producer == expected.cq_producer
        && actual.cq_consumer == expected.cq_consumer
        && actual.reserved == expected.reserved
}

/// cbindgen:ignore
pub fn validate_header_directory_v21(
    header_bytes: &[u8],
    directory_bytes: &[u8],
    expected: &ValidatedSetupRequest,
    expected_session_epoch: u64,
) -> Result<ValidatedSectionImage, SectionLayoutError> {
    if header_bytes.len() < size_of::<GlobalHeader>() {
        return Err(SectionLayoutError::BufferTooSmall);
    }
    let header = decode_header(&header_bytes[..size_of::<GlobalHeader>()])?;
    validate_decoded_header_directory_v21(header, directory_bytes, expected, expected_session_epoch)
}

fn validate_decoded_header_directory_v21(
    header: GlobalHeader,
    directory_bytes: &[u8],
    expected: &ValidatedSetupRequest,
    expected_session_epoch: u64,
) -> Result<ValidatedSectionImage, SectionLayoutError> {
    if header.page_size == 0 || !header.page_size.is_power_of_two() {
        return Err(SectionLayoutError::InvalidPageSize);
    }
    if expected_session_epoch == 0 || header.session_epoch != expected_session_epoch {
        return Err(SectionLayoutError::InvalidIdentity);
    }
    let mut plan = SectionLayoutPlan::compute(expected, header.page_size)?;
    plan.session_epoch = expected_session_epoch;
    let canonical = plan.header();
    if !header_identity_matches(&header, &canonical) {
        return Err(SectionLayoutError::InvalidIdentity);
    }
    if !header_regions_match(&header, &canonical) {
        return Err(SectionLayoutError::InvalidRegion);
    }
    if header.header_flags != 0
        || header.flags != 0
        || header.reserved.iter().any(|byte| *byte != 0)
    {
        return Err(SectionLayoutError::InvalidPadding);
    }

    let directory_length = usize::try_from(plan.ring_directory.length)
        .map_err(|_| SectionLayoutError::ArithmeticOverflow)?;
    if directory_bytes.len() < directory_length {
        return Err(SectionLayoutError::BufferTooSmall);
    }
    for ring in plan.rings() {
        let start = usize::try_from(
            u64::from(ring.ring_index)
                .checked_mul(size_of::<RingDesc>() as u64)
                .ok_or(SectionLayoutError::ArithmeticOverflow)?,
        )
        .map_err(|_| SectionLayoutError::ArithmeticOverflow)?;
        let end = start
            .checked_add(size_of::<RingDesc>())
            .ok_or(SectionLayoutError::ArithmeticOverflow)?;
        let actual = try_decode::<RingDesc>(&directory_bytes[start..end])
            .map_err(|_| SectionLayoutError::BufferTooSmall)?;
        let expected_desc = plan.ring_desc(ring);
        if !ring_desc_matches(&actual, &expected_desc) {
            return Err(SectionLayoutError::InvalidDescriptor);
        }
    }
    let used = usize::try_from(
        u64::from(plan.ring_count)
            .checked_mul(size_of::<RingDesc>() as u64)
            .ok_or(SectionLayoutError::ArithmeticOverflow)?,
    )
    .map_err(|_| SectionLayoutError::ArithmeticOverflow)?;
    if directory_bytes[used..directory_length]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(SectionLayoutError::InvalidPadding);
    }
    validate_slot_arena(
        SlotDirection::K2u,
        plan.section_size,
        header.k2u_slots,
        header.k2u_slot_classes,
    )
    .map_err(|_| SectionLayoutError::InvalidRegion)?;
    validate_slot_arena(
        SlotDirection::U2k,
        plan.section_size,
        header.u2k_slots,
        header.u2k_slot_classes,
    )
    .map_err(|_| SectionLayoutError::InvalidRegion)?;
    Ok(ValidatedSectionImage { plan })
}

/// cbindgen:ignore
pub fn validate_finished_section_v21(
    bytes: &[u8],
    expected: &ValidatedSetupRequest,
    expected_session_epoch: u64,
) -> Result<ValidatedSectionImage, SectionLayoutError> {
    if bytes.len() < size_of::<GlobalHeader>() {
        return Err(SectionLayoutError::BufferTooSmall);
    }
    let header = decode_header(&bytes[..size_of::<GlobalHeader>()])?;
    let directory_start = usize::try_from(header.ring_directory.offset)
        .map_err(|_| SectionLayoutError::ArithmeticOverflow)?;
    let directory_length = usize::try_from(header.ring_directory.length)
        .map_err(|_| SectionLayoutError::ArithmeticOverflow)?;
    let directory_end = directory_start
        .checked_add(directory_length)
        .ok_or(SectionLayoutError::ArithmeticOverflow)?;
    if directory_end > bytes.len() {
        return Err(SectionLayoutError::BufferTooSmall);
    }
    let validated = validate_decoded_header_directory_v21(
        header,
        &bytes[directory_start..directory_end],
        expected,
        expected_session_epoch,
    )?;
    let section_size = usize::try_from(validated.plan.section_size)
        .map_err(|_| SectionLayoutError::SectionTooLarge)?;
    if bytes.len() < section_size {
        return Err(SectionLayoutError::BufferTooSmall);
    }

    let descriptor_bytes = usize::try_from(
        u64::from(validated.plan.ring_count)
            .checked_mul(size_of::<RingDesc>() as u64)
            .ok_or(SectionLayoutError::ArithmeticOverflow)?,
    )
    .map_err(|_| SectionLayoutError::ArithmeticOverflow)?;
    for (index, byte) in bytes[..section_size].iter().enumerate() {
        let in_header = index < size_of::<GlobalHeader>();
        let in_descriptors =
            index >= directory_start && index < directory_start.saturating_add(descriptor_bytes);
        if !in_header && !in_descriptors && *byte != 0 {
            return Err(SectionLayoutError::InvalidPadding);
        }
    }
    Ok(validated)
}

impl ValidatedSectionImage {
    /// cbindgen:ignore
    pub const fn plan(&self) -> &SectionLayoutPlan {
        &self.plan
    }
}

const _: () = assert!(core::mem::size_of::<SectionLayoutPlan>() <= 512);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::try_encode;
    use crate::control::{SetupRequestV1, SlotClassRequest, SETUP_REQUEST_V1_SIZE};
    use crate::features::PlatformProfile;
    use crate::limits::{
        MIN_CONTROL_SLOT_SIZE, MIN_K2U_PROGRESS_SLOTS_PER_RING, MIN_NOTIFICATION_CREDIT_SIZE,
        MIN_U2K_PROGRESS_SLOTS_PER_RING,
    };
    use crate::msgs::ControlHeader;
    use crate::validate::validate_setup_request_v1;

    const SECURITY: FeatureSet = FeatureSet { words: [0x10, 0] };
    const ZERO_CLASS: SlotClassRequest = SlotClassRequest {
        slot_size: 0,
        slot_count: 0,
    };

    fn setup() -> ValidatedSetupRequest {
        let request = SetupRequestV1 {
            header: ControlHeader {
                struct_size: SETUP_REQUEST_V1_SIZE,
                struct_version: 1,
                required_flags: 0,
            },
            abi_major: 2,
            min_abi_minor: 1,
            max_abi_minor: 1,
            reserved0: 0,
            offered_features: SECURITY,
            required_features: SECURITY,
            required_os_capabilities: FeatureSet { words: [0, 0] },
            ring_count: 1,
            sq_capacity: MIN_SQ_CAPACITY,
            cq_capacity: MIN_CQ_CAPACITY,
            max_inflight: 1,
            k2u_slot_classes: [
                SlotClassRequest {
                    slot_size: MIN_CONTROL_SLOT_SIZE,
                    slot_count: MIN_K2U_PROGRESS_SLOTS_PER_RING,
                },
                ZERO_CLASS,
                ZERO_CLASS,
                ZERO_CLASS,
            ],
            u2k_slot_classes: [
                SlotClassRequest {
                    slot_size: MIN_NOTIFICATION_CREDIT_SIZE,
                    slot_count: 1,
                },
                SlotClassRequest {
                    slot_size: MIN_CONTROL_SLOT_SIZE,
                    slot_count: MIN_U2K_PROGRESS_SLOTS_PER_RING,
                },
                ZERO_CLASS,
                ZERO_CLASS,
            ],
            notification_credit_count: 1,
            notification_credit_size: MIN_NOTIFICATION_CREDIT_SIZE,
            flags: 0,
            reserved1: 0,
        };
        let mut bytes = [0; SETUP_REQUEST_V1_SIZE as usize];
        try_encode(&request, &mut bytes).expect("SETUP encodes");
        validate_setup_request_v1(
            &bytes,
            PlatformProfile::Win10X64,
            SECURITY,
            FeatureSet { words: [0x3, 0] },
            true,
        )
        .expect("SETUP validates")
    }

    #[test]
    fn finished_section_decodes_header_exactly_once() {
        // Mutation caught: selecting the directory from one header snapshot and
        // validating a second header snapshot.
        let setup = setup();
        let plan = SectionLayoutPlan::compute(&setup, 4096).expect("plan");
        let mut bytes = vec![0; plan.section_size() as usize];
        plan.construct(&mut bytes).expect("construct");

        HEADER_DECODE_COUNT.store(0, Ordering::Relaxed);
        validate_finished_section_v21(&bytes, &setup, 1).expect("valid image");
        assert_eq!(HEADER_DECODE_COUNT.load(Ordering::Relaxed), 1);
    }
}
