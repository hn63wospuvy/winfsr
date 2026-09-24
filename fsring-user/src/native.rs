//! The Windows native control session.
//!
//! A daemon reaches the driver through exactly two seams: a
//! [`ControlTransport`] that issues one `DeviceIoControl` and a
//! [`MappingInspector`] that can describe and privately copy its own address
//! space. Both are traits so the whole validation pipeline runs on any host
//! against fakes, and the Windows implementations behind them contain no
//! decisions of their own.
//!
//! **Nothing the driver returns is authority.** A returned user address is a
//! *claim*: this module re-derives the section placement from the request it
//! sent, checks every descriptor against that placement, proves the claimed
//! range is fully committed, mapped, non-executable, unguarded, and of the
//! protection its access demands, copies the header and ring directory into
//! private buffers, and re-parses those copies with the frozen ABI validator.
//! Only then does a borrow into that memory exist.
//!
//! The order is fixed and observable, because a check performed after a borrow
//! has already been formed is not a check:
//!
//! ```text
//! device-io-control
//! validate-result-bytes
//! validate-descriptor-arithmetic
//! virtual-query-full-coverage
//! read-process-memory-header-directory
//! validate-private-copy
//! construct-native-borrows
//! ```

use std::marker::PhantomData;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Arc;

use fsring_abi::codec::try_decode;
use fsring_abi::control::{
    enter_request_flags, view_access, view_kind, EnterRequestV1, EnterResultV1,
    NotificationCreditV1, SessionResultV1, UserViewDesc, ENTER_REQUEST_V1_SIZE, GLOBAL_RING_INDEX,
    IOCTL_FSRING_ENTER, IOCTL_FSRING_SETUP, NOTIFICATION_CREDIT_V1_SIZE,
    SESSION_RESULT_V1_PREFIX_SIZE, SETUP_REQUEST_V1_SIZE, USER_VIEW_DESC_SIZE,
};
use fsring_abi::layout::{ConsumerPage, Cqe, ProducerPage, RegionDesc, Sqe};
use fsring_abi::section_layout::{
    validate_header_directory_v21, RingLayoutPlan, SectionLayoutError, SectionLayoutPlan,
};
use fsring_abi::validate::{
    enter_result_size_v1, validate_enter_result_v1, validate_session_result_v1, RingViewLayout,
    SessionValidationError, SessionViewLayout, ValidatedSetupRequest, ValidatedTopology,
};
use fsring_abi::{BootInstanceId, MountId};

use crate::handshake::{build_setup_request, encode_setup_request};
use crate::ring::DaemonRing;
use fsring_abi::control::SetupRequestV1;

/// The page size every C4 section is placed on.
const PAGE_SIZE: u32 = 4096;

/// The alignment every returned view base must prove.
///
/// Each view is a separate kernel mapping of a page-aligned section region, so
/// page alignment is what a correct driver returns — and it is also the
/// strictest alignment any consumer of these addresses needs: `ProducerPage`
/// and `ConsumerPage` are `align(4096)`, `Sqe`/`Cqe` are `align(64)`, and the
/// read-only base has page-aligned region offsets added to it. The assertion
/// below is what keeps that "strictest" claim true if a wire type ever grows a
/// larger alignment.
const VIEW_ALIGNMENT: usize = PAGE_SIZE as usize;

const _: () = {
    assert!(core::mem::align_of::<ProducerPage>() <= VIEW_ALIGNMENT);
    assert!(core::mem::align_of::<ConsumerPage>() <= VIEW_ALIGNMENT);
    assert!(core::mem::align_of::<Sqe>() <= VIEW_ALIGNMENT);
    assert!(core::mem::align_of::<Cqe>() <= VIEW_ALIGNMENT);
};

/// `ERROR_SUCCESS`.
pub const ERROR_SUCCESS: u32 = 0;

/// `MEM_COMMIT`.
pub const MEM_COMMIT: u32 = 0x0000_1000;
/// `MEM_MAPPED`.
pub const MEM_MAPPED: u32 = 0x0004_0000;
/// `PAGE_NOACCESS`.
pub const PAGE_NOACCESS: u32 = 0x01;
/// `PAGE_READONLY`.
pub const PAGE_READONLY: u32 = 0x02;
/// `PAGE_READWRITE`.
pub const PAGE_READWRITE: u32 = 0x04;
/// `PAGE_GUARD`, a protection *modifier*.
pub const PAGE_GUARD: u32 = 0x100;
/// `PAGE_NOCACHE`, a modifier this client tolerates on neither alias.
pub const PAGE_NOCACHE: u32 = 0x200;
/// `PAGE_WRITECOMBINE`, likewise.
pub const PAGE_WRITECOMBINE: u32 = 0x400;

/// Every executable base protection, ORed.
///
/// A single mask rather than five comparisons, so a new executable value is
/// added in one place and the rejection below cannot be partially updated.
pub const PAGE_EXECUTE_MASK: u32 = 0x10 | 0x20 | 0x40 | 0x80;

/// The modifiers a session alias may never carry.
const PAGE_FORBIDDEN_MODIFIERS: u32 = PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;

/// One completed `DeviceIoControl`, successful or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoctlOutcome {
    pub win32_code: u32,
    pub information: u64,
}

/// Issue one control request.
///
/// `Error` is reserved for the inability to *issue or observe* a terminal
/// operation. A control request that completed and was rejected is an
/// [`IoctlOutcome`], not an error: the difference matters because the duplicate
/// probe below needs the rejection itself.
pub trait ControlTransport {
    type Error;
    fn ioctl(
        &self,
        code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<IoctlOutcome, Self::Error>;
}

/// Describe and privately copy this process's own memory.
pub trait MappingInspector {
    type Error;
    /// Every region covering `[address, address + length)`, in address order.
    fn query_covering(
        &self,
        address: usize,
        length: usize,
    ) -> Result<Vec<MemoryRegion>, Self::Error>;
    /// Copy exactly `length` bytes into a private buffer.
    fn copy_read_only(&self, address: usize, length: usize) -> Result<Vec<u8>, Self::Error>;
}

/// One `MEMORY_BASIC_INFORMATION`, with the raw values preserved.
///
/// Raw, not normalized: a fail-closed comparison against the exact
/// `MEM_COMMIT`/`MEM_MAPPED`/`PAGE_*` values is only possible if nothing on the
/// way here has already interpreted them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub region_size: usize,
    pub state: u32,
    pub mapping_type: u32,
    pub protection: u32,
}

/// The durable identity of one native session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeIdentity {
    pub boot_instance_id: BootInstanceId,
    pub mount_id: MountId,
    pub session_epoch: u64,
}

/// One validated user view. Every field is private: a view is evidence, not a
/// value a caller may edit.
#[derive(Clone, Copy, Debug)]
pub struct OwnedView {
    address: NonZeroUsize,
    length: usize,
    kind: u16,
    access: u16,
    ring_index: Option<u32>,
}

impl OwnedView {
    const fn address(&self) -> usize {
        self.address.get()
    }

    const fn end(&self) -> usize {
        self.address.get().saturating_add(self.length)
    }
}

/// Layout facts re-derived from a published session's views and private copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionLayoutObservation {
    pub independent_parser: bool,
    pub exact_lengths: bool,
    pub zero_padding: bool,
    pub zero_cursors: bool,
    pub descriptor_counts_match: bool,
}

/// View-protection facts re-queried from the process address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewProtectionObservation {
    pub virtual_query_coverage: bool,
    pub exact_protections: bool,
    pub overlap_count: u64,
    pub executable_range_count: u64,
}

fn expected_view_count(topology: &ValidatedTopology) -> usize {
    // Whole-section read-only + U2K arena + three writable aliases per ring.
    2usize.saturating_add(3usize.saturating_mul(topology.ring_count() as usize))
}

fn canonical_span_length(setup: &ValidatedSetupRequest, view: &OwnedView) -> Option<usize> {
    let plan = SectionLayoutPlan::compute(setup, PAGE_SIZE).ok()?;
    let kind = view.kind;
    let length = match kind {
        view_kind::SECTION_READ_ONLY => plan.section_size(),
        view_kind::U2K_ARENA => plan.u2k_slots().length,
        view_kind::SQ_CONSUMER_PAGE => plan.ring(view.ring_index?)?.sq_consumer.length,
        view_kind::CQ_ENTRIES => plan.ring(view.ring_index?)?.cq_entries.length,
        view_kind::CQ_PRODUCER_PAGE => plan.ring(view.ring_index?)?.cq_producer.length,
        _ => return None,
    };
    usize::try_from(length).ok()
}

/// Everything one native session can refuse for.
#[derive(Debug)]
pub enum NativeSessionError<TE, IE> {
    Transport(TE),
    Inspection(IE),
    IoFailure { win32_code: u32, information: u64 },
    ResultValidation(SessionValidationError),
    LayoutValidation(SectionLayoutError),
    ArithmeticOverflow,
    InvalidDescriptor,
    MappingGap,
    WrongMappingState,
    WrongMappingType,
    WrongProtection,
    ExecutableOrGuarded,
    VirtualAddressOverlap,
    DescriptorMismatch,
    MisalignedView,
    TerminalAlreadyObserved,
}

impl<TE, IE> PartialEq for NativeSessionError<TE, IE> {
    /// Compares the refusal *reason*, which is what a test asserts on; the two
    /// seam errors are opaque by construction.
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}

/// The unopened control device.
pub struct ControlDevice<T, I> {
    transport: Arc<T>,
    inspector: Arc<I>,
}

/// One published session and everything it validated.
pub struct NativeSession<T, I> {
    transport: Arc<T>,
    inspector: Arc<I>,
    identity: NativeIdentity,
    validated_setup: ValidatedSetupRequest,
    #[allow(dead_code)] // Retained evidence: every borrow below came from these.
    views: Vec<OwnedView>,
    rings: Vec<NativeRing>,
}

/// One ring's validated view bases and canonical layout.
pub struct NativeRing {
    ring_index: u32,
    layout: RingLayoutPlan,
    sq_capacity: usize,
    cq_capacity: usize,
    section_read_only: usize,
    sq_consumer_read_write: usize,
    cq_entries_read_write: usize,
    cq_producer_read_write: usize,
    #[allow(dead_code)] // Task 15's grant writes use the shared arena alias.
    u2k_read_write: usize,
}

/// The six typed pointers one daemon ring role needs.
///
/// Its mandatory `&'a mut NativeRing` owner token is the whole point: the
/// returned [`DaemonRing`] keeps that exclusive borrow, so a second daemon role
/// on the same ring, or a session teardown while one is live, is not
/// representable.
pub struct DaemonRingRegionSet<'a> {
    pub(crate) sq_producer: *const ProducerPage,
    pub(crate) sq_consumer: *mut ConsumerPage,
    pub(crate) sq_entries: *const Sqe,
    pub(crate) sq_capacity: usize,
    pub(crate) cq_producer: *mut ProducerPage,
    pub(crate) cq_consumer: *const ConsumerPage,
    pub(crate) cq_entries: *mut Cqe,
    pub(crate) cq_capacity: usize,
    pub(crate) _owner: PhantomData<&'a mut NativeRing>,
}

impl<'a> DaemonRingRegionSet<'a> {
    /// # Safety
    /// Every pointer must have been derived from a view this module validated
    /// for the matching access, and `owner` must be the ring those views belong
    /// to.
    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn from_validated_native(
        owner: &'a mut NativeRing,
        sq_producer: *const ProducerPage,
        sq_consumer: *mut ConsumerPage,
        sq_entries: *const Sqe,
        sq_capacity: usize,
        cq_producer: *mut ProducerPage,
        cq_consumer: *const ConsumerPage,
        cq_entries: *mut Cqe,
        cq_capacity: usize,
    ) -> Self {
        let _ = owner;
        Self {
            sq_producer,
            sq_consumer,
            sq_entries,
            sq_capacity,
            cq_producer,
            cq_consumer,
            cq_entries,
            cq_capacity,
            _owner: PhantomData,
        }
    }
}

impl NativeRing {
    pub const fn ring_index(&self) -> u32 {
        self.ring_index
    }

    pub const fn layout(&self) -> RingLayoutPlan {
        self.layout
    }

    /// Attach the daemon role to this ring.
    ///
    /// Safe, because no raw pointer enters from the caller: every address comes
    /// from a view this module validated, and the exclusive borrow is what
    /// keeps the role unique.
    pub fn attach_daemon(&mut self) -> DaemonRing<'_> {
        let base = self.section_read_only;
        let sq_producer =
            base.wrapping_add(self.layout.sq_producer.offset as usize) as *const ProducerPage;
        let sq_entries = base.wrapping_add(self.layout.sq_entries.offset as usize) as *const Sqe;
        let cq_consumer =
            base.wrapping_add(self.layout.cq_consumer.offset as usize) as *const ConsumerPage;
        let sq_consumer = self.sq_consumer_read_write as *mut ConsumerPage;
        let cq_producer = self.cq_producer_read_write as *mut ProducerPage;
        let cq_entries = self.cq_entries_read_write as *mut Cqe;
        let (sq_capacity, cq_capacity) = (self.sq_capacity, self.cq_capacity);
        // SAFETY: the read-only pointers are offsets inside the validated
        // whole-section alias; the three writable pointers are the bases of
        // the separately validated read-write aliases for exactly this ring.
        // The owner token below is this ring, and it stays exclusively
        // borrowed for as long as the returned role lives.
        let regions = unsafe {
            DaemonRingRegionSet::from_validated_native(
                self,
                sq_producer,
                sq_consumer,
                sq_entries,
                sq_capacity,
                cq_producer,
                cq_consumer,
                cq_entries,
                cq_capacity,
            )
        };
        // SAFETY: forwarded verbatim from the region set's own contract.
        unsafe { DaemonRing::attach_regions(regions) }
    }
}

impl<T, I> ControlDevice<T, I>
where
    T: ControlTransport,
    I: MappingInspector,
{
    /// The host-integration and fake seam.
    pub fn from_parts(transport: T, inspector: I) -> Self {
        Self {
            transport: Arc::new(transport),
            inspector: Arc::new(inspector),
        }
    }

    /// Send one SETUP and validate everything it returns.
    ///
    /// Consumes the device, so ordinary safe code cannot issue a duplicate
    /// SETUP on the same wrapper.
    pub fn setup(
        self,
        ring_count: u32,
    ) -> Result<NativeSession<T, I>, NativeSessionError<T::Error, I::Error>> {
        self.setup_with_request(build_setup_request(ring_count))
    }

    /// Send one caller-built SETUP request straight to the driver and return
    /// only its raw outcome.
    ///
    /// Smoke-only. [`Self::setup_with_request`] validates the request locally
    /// before any IOCTL, which is right for a client and wrong for a probe of
    /// the DRIVER's refusal: a request the SDK refuses never reaches the
    /// driver, so the probe would observe the SDK. Round-17 evidence E4 found
    /// `setup-required-unavailable` in exactly that state.
    ///
    /// It adopts nothing the driver returns -- no view, no ring, no identity --
    /// so it cannot become a session however the driver answers. The output
    /// buffer is sized for the canonical one-ring topology, which is what a
    /// refused request never reaches.
    #[doc(hidden)]
    pub fn probe_raw_setup(
        &self,
        request: SetupRequestV1,
    ) -> Result<IoctlOutcome, NativeSessionError<T::Error, I::Error>> {
        let _ = &self.inspector;
        let input = encode_setup_request(&request);
        let canonical =
            crate::handshake::serve_setup(&encode_setup_request(&build_setup_request(1)))
                .map_err(NativeSessionError::ResultValidation)?;
        let required = fsring_abi::validate::session_result_size_v1(&canonical.topology())
            .map_err(|_| NativeSessionError::ArithmeticOverflow)?;
        let mut output = vec![
            0u8;
            usize::try_from(required)
                .map_err(|_| NativeSessionError::ArithmeticOverflow)?
        ];
        self.transport
            .ioctl(IOCTL_FSRING_SETUP, &input, &mut output)
            .map_err(NativeSessionError::Transport)
    }

    /// Send one caller-built SETUP request and validate everything it returns.
    pub fn setup_with_request(
        self,
        request: SetupRequestV1,
    ) -> Result<NativeSession<T, I>, NativeSessionError<T::Error, I::Error>> {
        let input = encode_setup_request(&request);
        let validated_setup =
            crate::handshake::serve_setup(&input).map_err(NativeSessionError::ResultValidation)?;
        let topology = validated_setup.topology();
        let required = fsring_abi::validate::session_result_size_v1(&topology)
            .map_err(|_| NativeSessionError::ArithmeticOverflow)?;
        let required =
            usize::try_from(required).map_err(|_| NativeSessionError::ArithmeticOverflow)?;
        let mut output = vec![0u8; required];

        // 1. device-io-control
        let outcome = self
            .transport
            .ioctl(IOCTL_FSRING_SETUP, &input, &mut output)
            .map_err(NativeSessionError::Transport)?;
        if outcome.win32_code != ERROR_SUCCESS {
            return Err(NativeSessionError::IoFailure {
                win32_code: outcome.win32_code,
                information: outcome.information,
            });
        }
        let written = usize::try_from(outcome.information)
            .map_err(|_| NativeSessionError::ArithmeticOverflow)?;
        if written != required {
            return Err(NativeSessionError::InvalidDescriptor);
        }

        // 2. validate-result-bytes
        let plan = SectionLayoutPlan::compute(&validated_setup, PAGE_SIZE)
            .map_err(NativeSessionError::LayoutValidation)?;
        let rings: Vec<RingViewLayout> = plan
            .rings()
            .map(|ring| RingViewLayout {
                sq_consumer: ring.sq_consumer,
                cq_entries: ring.cq_entries,
                cq_producer: ring.cq_producer,
            })
            .collect();
        let expected = SessionViewLayout::for_setup(
            &validated_setup,
            plan.section_size(),
            plan.page_size(),
            plan.u2k_slots(),
            &rings,
        )
        .map_err(|_| NativeSessionError::InvalidDescriptor)?;
        validate_session_result_v1(&output, &expected)
            .map_err(NativeSessionError::ResultValidation)?;
        let prefix: SessionResultV1 = try_decode(
            output
                .get(..SESSION_RESULT_V1_PREFIX_SIZE as usize)
                .ok_or(NativeSessionError::InvalidDescriptor)?,
        )
        .map_err(|_| NativeSessionError::InvalidDescriptor)?;

        // 3. validate-descriptor-arithmetic
        let views = decode_views(&output, &prefix, &plan)?;

        // 4. virtual-query-full-coverage
        for view in &views {
            self.prove_mapping(view)?;
        }
        reject_overlap(&views)?;

        // 5. read-process-memory-header-directory
        let section = views
            .iter()
            .find(|view| view.kind == view_kind::SECTION_READ_ONLY)
            .copied()
            .ok_or(NativeSessionError::InvalidDescriptor)?;
        let directory = plan.ring_directory();
        let header_bytes = self
            .inspector
            .copy_read_only(section.address(), plan.page_size() as usize)
            .map_err(NativeSessionError::Inspection)?;
        let directory_address = section
            .address()
            .checked_add(
                usize::try_from(directory.offset)
                    .map_err(|_| NativeSessionError::ArithmeticOverflow)?,
            )
            .ok_or(NativeSessionError::ArithmeticOverflow)?;
        let directory_len = usize::try_from(directory.length)
            .map_err(|_| NativeSessionError::ArithmeticOverflow)?;
        let directory_bytes = self
            .inspector
            .copy_read_only(directory_address, directory_len)
            .map_err(NativeSessionError::Inspection)?;

        // 6. validate-private-copy. Never the full-section validator: these are
        // two partial snapshots, and feeding a partial image to a whole-image
        // parser would either fail spuriously or accept a short read.
        validate_header_directory_v21(&header_bytes, &directory_bytes, &validated_setup, 1)
            .map_err(NativeSessionError::LayoutValidation)?;

        // 7. construct-native-borrows
        let identity = NativeIdentity {
            boot_instance_id: prefix.boot_instance_id,
            mount_id: prefix.mount_id,
            session_epoch: prefix.session_epoch,
        };
        let native_rings = build_rings(&plan, &views, section.address())?;
        Ok(NativeSession {
            transport: self.transport,
            inspector: self.inspector,
            identity,
            validated_setup,
            views,
            rings: native_rings,
        })
    }

    /// Prove one claimed range is fully committed, mapped, non-executable,
    /// unguarded, and of the protection its access demands.
    fn prove_mapping(
        &self,
        view: &OwnedView,
    ) -> Result<(), NativeSessionError<T::Error, I::Error>> {
        let regions = self
            .inspector
            .query_covering(view.address(), view.length)
            .map_err(NativeSessionError::Inspection)?;
        let mut cursor = view.address();
        let end = view.end();
        for region in regions {
            if region.base_address > cursor {
                // A hole between two regions: the claimed range is not one
                // continuously mapped span.
                return Err(NativeSessionError::MappingGap);
            }
            let region_end = region
                .base_address
                .checked_add(region.region_size)
                .ok_or(NativeSessionError::ArithmeticOverflow)?;
            if region_end <= cursor {
                continue;
            }
            if region.state != MEM_COMMIT {
                return Err(NativeSessionError::WrongMappingState);
            }
            if region.mapping_type != MEM_MAPPED {
                return Err(NativeSessionError::WrongMappingType);
            }
            let protection = region.protection;
            if protection & PAGE_EXECUTE_MASK != 0 {
                return Err(NativeSessionError::ExecutableOrGuarded);
            }
            if protection & PAGE_FORBIDDEN_MODIFIERS != 0 {
                return Err(NativeSessionError::ExecutableOrGuarded);
            }
            let expected = match view.access {
                view_access::READ_ONLY => PAGE_READONLY,
                view_access::READ_WRITE => PAGE_READWRITE,
                _ => return Err(NativeSessionError::InvalidDescriptor),
            };
            if protection == PAGE_NOACCESS || protection != expected {
                return Err(NativeSessionError::WrongProtection);
            }
            cursor = region_end;
            if cursor >= end {
                return Ok(());
            }
        }
        Err(NativeSessionError::MappingGap)
    }
}

/// Decode and range-check every returned view descriptor.
fn decode_views<TE, IE>(
    output: &[u8],
    prefix: &SessionResultV1,
    plan: &SectionLayoutPlan,
) -> Result<Vec<OwnedView>, NativeSessionError<TE, IE>> {
    let mut views = Vec::new();
    let mut offset = prefix.views_offset as usize;
    for _ in 0..prefix.view_count {
        let end = offset
            .checked_add(USER_VIEW_DESC_SIZE as usize)
            .ok_or(NativeSessionError::ArithmeticOverflow)?;
        let bytes = output
            .get(offset..end)
            .ok_or(NativeSessionError::InvalidDescriptor)?;
        let desc: UserViewDesc =
            try_decode(bytes).map_err(|_| NativeSessionError::InvalidDescriptor)?;
        offset = end;

        let address = NonZeroUsize::new(usize::try_from(desc.user_address).unwrap_or(0))
            .ok_or(NativeSessionError::InvalidDescriptor)?;
        // Alignment is authority the driver cannot assert for itself. Every
        // address below is cast to an `align(4096)` page or an `align(64)`
        // entry and then read through an ephemeral `&AtomicU64`/`&AtomicU32`;
        // forming that reference on a misaligned address is undefined behavior
        // before the load even happens. Coverage and protection say the bytes
        // are there and writable — they say nothing about where the address
        // starts inside its region, so this is checked here rather than left
        // to `prove_mapping`.
        if address.get() % VIEW_ALIGNMENT != 0 {
            return Err(NativeSessionError::MisalignedView);
        }
        let length =
            usize::try_from(desc.length).map_err(|_| NativeSessionError::ArithmeticOverflow)?;
        if length == 0 {
            return Err(NativeSessionError::InvalidDescriptor);
        }
        // The claimed range must not wrap the address space.
        address
            .get()
            .checked_add(length)
            .ok_or(NativeSessionError::ArithmeticOverflow)?;
        // Every descriptor must name a span the canonical placement actually
        // has: the driver's numbers are checked against the layout this client
        // recomputed from its own request.
        let expected = canonical_span(plan, &desc).ok_or(NativeSessionError::DescriptorMismatch)?;
        if expected.offset != desc.section_offset || expected.length != desc.length {
            return Err(NativeSessionError::DescriptorMismatch);
        }
        views.push(OwnedView {
            address,
            length,
            kind: desc.kind,
            access: desc.access,
            ring_index: (desc.ring_index != GLOBAL_RING_INDEX).then_some(desc.ring_index),
        });
    }
    Ok(views)
}

/// The canonical section span one descriptor claims to describe.
fn canonical_span(plan: &SectionLayoutPlan, desc: &UserViewDesc) -> Option<RegionDesc> {
    match desc.kind {
        view_kind::SECTION_READ_ONLY => (desc.ring_index == GLOBAL_RING_INDEX
            && desc.access == view_access::READ_ONLY)
            .then(|| RegionDesc {
                offset: 0,
                length: plan.section_size(),
            }),
        view_kind::U2K_ARENA => (desc.ring_index == GLOBAL_RING_INDEX
            && desc.access == view_access::READ_WRITE)
            .then(|| plan.u2k_slots()),
        view_kind::SQ_CONSUMER_PAGE | view_kind::CQ_ENTRIES | view_kind::CQ_PRODUCER_PAGE => {
            if desc.access != view_access::READ_WRITE {
                return None;
            }
            let ring = plan.ring(desc.ring_index)?;
            Some(match desc.kind {
                view_kind::SQ_CONSUMER_PAGE => ring.sq_consumer,
                view_kind::CQ_ENTRIES => ring.cq_entries,
                _ => ring.cq_producer,
            })
        }
        _ => None,
    }
}

/// Reject any two writable aliases that overlap in the address space.
///
/// The whole-section read-only alias deliberately covers every writable one at
/// *section* offsets; what must not overlap is the returned *virtual* ranges of
/// two distinct writable aliases, because that would make one region two
/// different things.
fn reject_overlap<TE, IE>(views: &[OwnedView]) -> Result<(), NativeSessionError<TE, IE>> {
    let writable: Vec<&OwnedView> = views
        .iter()
        .filter(|view| view.access == view_access::READ_WRITE)
        .collect();
    for (index, left) in writable.iter().enumerate() {
        for right in writable.iter().skip(index.saturating_add(1)) {
            if left.address() < right.end() && right.address() < left.end() {
                return Err(NativeSessionError::VirtualAddressOverlap);
            }
        }
    }
    Ok(())
}

/// Build one `NativeRing` per ring from the validated views.
fn build_rings<TE, IE>(
    plan: &SectionLayoutPlan,
    views: &[OwnedView],
    section_base: usize,
) -> Result<Vec<NativeRing>, NativeSessionError<TE, IE>> {
    let u2k = views
        .iter()
        .find(|view| view.kind == view_kind::U2K_ARENA)
        .ok_or(NativeSessionError::InvalidDescriptor)?;
    let mut rings = Vec::new();
    for ring in plan.rings() {
        let index = ring.ring_index;
        let base_of = |kind: u16| -> Option<usize> {
            views
                .iter()
                .find(|view| view.kind == kind && view.ring_index == Some(index))
                .map(OwnedView::address)
        };
        rings.push(NativeRing {
            ring_index: index,
            layout: ring,
            sq_capacity: plan.sq_capacity() as usize,
            cq_capacity: plan.cq_capacity() as usize,
            section_read_only: section_base,
            sq_consumer_read_write: base_of(view_kind::SQ_CONSUMER_PAGE)
                .ok_or(NativeSessionError::InvalidDescriptor)?,
            cq_entries_read_write: base_of(view_kind::CQ_ENTRIES)
                .ok_or(NativeSessionError::InvalidDescriptor)?,
            cq_producer_read_write: base_of(view_kind::CQ_PRODUCER_PAGE)
                .ok_or(NativeSessionError::InvalidDescriptor)?,
            u2k_read_write: u2k.address(),
        });
    }
    Ok(rings)
}

impl<T, I> NativeSession<T, I> {
    pub const fn identity(&self) -> NativeIdentity {
        self.identity
    }

    pub const fn topology(&self) -> ValidatedTopology {
        self.validated_setup.topology()
    }

    pub const fn validated_setup(&self) -> ValidatedSetupRequest {
        self.validated_setup
    }

    pub fn ring_count(&self) -> usize {
        self.rings.len()
    }

    pub fn ring(&self, index: u32) -> Option<&NativeRing> {
        self.rings.get(usize::try_from(index).ok()?)
    }

    pub fn ring_mut(&mut self, index: u32) -> Option<&mut NativeRing> {
        self.rings.get_mut(usize::try_from(index).ok()?)
    }

    /// Re-derive layout facts from the views this session already validated.
    ///
    /// These are observations, not the smoke oracle table: a hostile or empty
    /// session can report `false` for any flag.
    pub fn observe_session_layout(&self) -> SessionLayoutObservation
    where
        I: MappingInspector,
    {
        let expected_views = expected_view_count(&self.topology());
        let descriptor_counts_match = self.views.len() == expected_views;
        let exact_lengths = self.views.iter().all(|view| {
            view.length != 0
                && canonical_span_length(&self.validated_setup, view)
                    .is_some_and(|length| length == view.length)
        });
        let mut zero_cursors = true;
        let mut zero_padding = true;
        for ring in &self.rings {
            if let Ok(bytes) = self
                .inspector
                .copy_read_only(ring.sq_consumer_read_write, 8)
            {
                if u64::from_le_bytes(bytes.try_into().unwrap_or([1; 8])) != 0 {
                    zero_cursors = false;
                }
            } else {
                zero_cursors = false;
            }
            if let Ok(bytes) = self
                .inspector
                .copy_read_only(ring.cq_producer_read_write, 8)
            {
                if u64::from_le_bytes(bytes.try_into().unwrap_or([1; 8])) != 0 {
                    zero_cursors = false;
                }
            } else {
                zero_cursors = false;
            }
            if let Ok(bytes) = self
                .inspector
                .copy_read_only(ring.sq_consumer_read_write.saturating_add(16), 8)
            {
                if bytes.iter().any(|byte| *byte != 0) {
                    zero_padding = false;
                }
            }
        }
        SessionLayoutObservation {
            independent_parser: true,
            exact_lengths,
            zero_padding,
            zero_cursors,
            descriptor_counts_match,
        }
    }

    /// Re-query every retained view and count overlaps/executable ranges.
    pub fn observe_view_protections(&self) -> ViewProtectionObservation
    where
        I: MappingInspector,
    {
        let mut coverage = true;
        let mut exact = true;
        let mut executable_range_count = 0u64;
        for view in &self.views {
            match self.inspector.query_covering(view.address(), view.length) {
                Ok(regions) => {
                    if regions.is_empty() {
                        coverage = false;
                        continue;
                    }
                    let expected = match view.access {
                        view_access::READ_ONLY => PAGE_READONLY,
                        view_access::READ_WRITE => PAGE_READWRITE,
                        _ => {
                            exact = false;
                            continue;
                        }
                    };
                    for region in regions {
                        if region.state != MEM_COMMIT || region.mapping_type != MEM_MAPPED {
                            coverage = false;
                        }
                        if region.protection & PAGE_EXECUTE_MASK != 0 {
                            executable_range_count = executable_range_count.saturating_add(1);
                        }
                        if region.protection != expected {
                            exact = false;
                        }
                    }
                }
                Err(_) => coverage = false,
            }
        }
        let writable: Vec<&OwnedView> = self
            .views
            .iter()
            .filter(|view| view.access == view_access::READ_WRITE)
            .collect();
        let mut overlap_count = 0u64;
        for (index, left) in writable.iter().enumerate() {
            for right in writable.iter().skip(index.saturating_add(1)) {
                if left.address() < right.end() && right.address() < left.end() {
                    overlap_count = overlap_count.saturating_add(1);
                }
            }
        }
        ViewProtectionObservation {
            virtual_query_coverage: coverage,
            exact_protections: exact,
            overlap_count,
            executable_range_count,
        }
    }

    /// Addresses this session still owns, for cleanup-after-drop observations.
    pub fn view_spans(&self) -> Vec<(usize, usize)> {
        self.views
            .iter()
            .map(|view| (view.address(), view.length))
            .collect()
    }

    /// Send one canonical duplicate SETUP and return only its raw outcome.
    ///
    /// Smoke-only. It adopts nothing the driver returns — no view, no ring, no
    /// identity — so the probe cannot become a second session however the
    /// driver answers.
    #[doc(hidden)]
    pub fn probe_duplicate_setup(
        &self,
    ) -> Result<IoctlOutcome, NativeSessionError<T::Error, I::Error>>
    where
        T: ControlTransport,
        I: MappingInspector,
    {
        let _ = &self.inspector;
        let ring_count = self.validated_setup.topology().ring_count();
        let request = build_setup_request(ring_count);
        let input = encode_setup_request(&request);
        let required = fsring_abi::validate::session_result_size_v1(&self.topology())
            .map_err(|_| NativeSessionError::ArithmeticOverflow)?;
        let mut output = vec![
            0u8;
            usize::try_from(required)
                .map_err(|_| NativeSessionError::ArithmeticOverflow)?
        ];
        debug_assert_eq!(input.len(), SETUP_REQUEST_V1_SIZE as usize);
        self.transport
            .ioctl(IOCTL_FSRING_SETUP, &input, &mut output)
            .map_err(NativeSessionError::Transport)
    }
}

// ---------------------------------------------------------------------------
// Native ENTER
// ---------------------------------------------------------------------------

/// `ERROR_OPERATION_ABORTED`.
pub const ERROR_OPERATION_ABORTED: u32 = 995;

/// What one ENTER asks the driver to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnterMode {
    Poll,
    Wait { timeout_ms: u32 },
    Drain { cq_budget: u32 },
}

impl EnterMode {
    /// The exact wire triple this mode encodes to.
    const fn wire(self) -> (u32, u32, u32) {
        match self {
            Self::Poll => (0, 0, 0),
            Self::Wait { timeout_ms } => (enter_request_flags::WAIT_SQ, 0, timeout_ms),
            Self::Drain { cq_budget } => (enter_request_flags::DRAIN_CQ, cq_budget, 0),
        }
    }
}

/// How an overlapped operation started.
pub enum BeginIo<P> {
    Completed(IoTerminal),
    Pending(P),
}

/// A terminal observation of one overlapped operation.
pub enum IoTerminal {
    Success {
        output: Vec<u8>,
        bytes_returned: usize,
    },
    /// `NonZeroU32`, so "failed" cannot silently carry success.
    Failed {
        win32_code: NonZeroU32,
        bytes_returned: usize,
    },
}

/// What an exact cancellation request found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelRequest {
    Issued,
    NotFound,
}

/// A transport that can start, cancel, and terminally observe one operation.
///
/// # Safety
/// This trait's ownership promise is a memory-safety contract, not a
/// convention. An implementation's `Pending` value must independently own the
/// device handle reference, the input and output buffers, the pinned
/// `OVERLAPPED`, and the completion event, and must keep all of them alive
/// until a terminal observation *succeeds*. In particular `wait_terminal` must
/// leave every one of them intact when it returns `Err`, because the OS may
/// still be writing into them.
pub unsafe trait OverlappedControlTransport: ControlTransport {
    type Pending;

    fn begin_ioctl(
        &self,
        code: u32,
        input: &[u8],
        output_capacity: usize,
    ) -> Result<BeginIo<Self::Pending>, Self::Error>;

    /// Cancel exactly this operation, never a sibling.
    fn cancel_exact(&self, pending: &Self::Pending) -> Result<CancelRequest, Self::Error>;

    /// Observe this operation's terminal state, non-alertably.
    fn wait_terminal(&self, pending: &mut Self::Pending) -> Result<IoTerminal, Self::Error>;
}

/// One validated ENTER result and its returned credits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnterCompletion {
    pub result: EnterResultV1,
    pub returned_credits: Vec<NotificationCreditV1>,
}

/// The sole owner of one in-flight overlapped operation.
///
/// Every path that can pend — the public WAIT and a locally pended POLL or
/// DRAIN alike — routes through this type, so no branch ever keeps a bare
/// `T::Pending` in a local where a `?` could drop it while the OS still owns
/// its buffers.
struct PendingOperation<'a, T: OverlappedControlTransport> {
    transport: &'a T,
    pending: Option<T::Pending>,
    terminal: bool,
}

impl<'a, T: OverlappedControlTransport> PendingOperation<'a, T> {
    const fn new(transport: &'a T, pending: T::Pending) -> Self {
        Self {
            transport,
            pending: Some(pending),
            terminal: false,
        }
    }

    /// Observe the terminal state, keeping the operation retryable on error.
    fn observe(&mut self) -> Result<Option<IoTerminal>, T::Error> {
        if self.terminal {
            return Ok(None);
        }
        let Some(pending) = self.pending.as_mut() else {
            return Ok(None);
        };
        // On `Err` the operation object is left exactly as it was: still
        // owning its buffers, still retryable.
        let terminal = self.transport.wait_terminal(pending)?;
        // Only now is it safe to release: the OS is done with the storage.
        self.pending = None;
        self.terminal = true;
        Ok(Some(terminal))
    }

    /// Cancel exactly this operation, then observe its terminal state.
    ///
    /// `NotFound` is not by itself a terminal: the operation may have completed
    /// between the two calls, and only `wait_terminal` can say so.
    fn cancel_and_observe(&mut self) -> Result<Option<IoTerminal>, T::Error> {
        if self.terminal {
            return Ok(None);
        }
        if let Some(pending) = self.pending.as_ref() {
            let _ = self.transport.cancel_exact(pending)?;
        }
        self.observe()
    }
}

impl<T: OverlappedControlTransport> Drop for PendingOperation<'_, T> {
    fn drop(&mut self) {
        if self.terminal || self.pending.is_none() {
            return;
        }
        if self.cancel_and_observe().is_ok() {
            return;
        }
        // The transport cannot tell us the OS is finished with this
        // operation's buffers. Freeing them now would hand the kernel a
        // dangling write target, so the object is deliberately leaked. A rare
        // leak is the fail-safe terminal policy; a use-after-free is not.
        if let Some(pending) = self.pending.take() {
            core::mem::forget(pending);
        }
    }
}

/// A started WAIT that has not completed yet.
pub struct PendingEnter<'a, T: OverlappedControlTransport, I: MappingInspector> {
    session: &'a NativeSession<T, I>,
    request: EnterRequestV1,
    operation: PendingOperation<'a, T>,
}

/// How a started ENTER turned out.
pub enum EnterStart<'a, T: OverlappedControlTransport, I: MappingInspector> {
    Completed(EnterCompletion),
    Pending(PendingEnter<'a, T, I>),
}

/// The terminal of one pending ENTER.
pub enum EnterTerminalResult {
    Completed(EnterCompletion),
    Cancelled {
        win32_code: u32,
        bytes_returned: usize,
    },
}

impl<T, I> PendingEnter<'_, T, I>
where
    T: OverlappedControlTransport,
    I: MappingInspector,
{
    /// Wait for this ENTER to finish.
    ///
    /// An aborted terminal is *not* reinterpreted as cancellation here: only an
    /// explicit [`Self::cancel`] may report `Cancelled`, and only for an exact
    /// abort that returned no bytes.
    pub fn wait(&mut self) -> Result<EnterTerminalResult, NativeSessionError<T::Error, I::Error>> {
        let terminal = self
            .operation
            .observe()
            .map_err(NativeSessionError::Transport)?
            .ok_or(NativeSessionError::TerminalAlreadyObserved)?;
        self.session.finish_enter(&self.request, terminal, false)
    }

    /// Cancel exactly this ENTER and observe its terminal.
    pub fn cancel(
        &mut self,
    ) -> Result<EnterTerminalResult, NativeSessionError<T::Error, I::Error>> {
        let terminal = self
            .operation
            .cancel_and_observe()
            .map_err(NativeSessionError::Transport)?
            .ok_or(NativeSessionError::TerminalAlreadyObserved)?;
        self.session.finish_enter(&self.request, terminal, true)
    }
}

impl<T, I> NativeSession<T, I>
where
    T: OverlappedControlTransport,
    I: MappingInspector,
{
    /// One non-waiting, non-draining ENTER.
    pub fn enter_poll(
        &self,
        ring_index: u32,
    ) -> Result<EnterCompletion, NativeSessionError<T::Error, I::Error>> {
        self.enter_synchronous(ring_index, EnterMode::Poll)
    }

    /// One bounded CQ drain. The driver request carries no WAIT semantics.
    pub fn enter_drain(
        &self,
        ring_index: u32,
        cq_budget: u32,
    ) -> Result<EnterCompletion, NativeSessionError<T::Error, I::Error>> {
        self.enter_synchronous(ring_index, EnterMode::Drain { cq_budget })
    }

    /// One waiting ENTER, which truthfully reports whether it pended.
    pub fn enter_wait(
        &self,
        ring_index: u32,
        timeout_ms: u32,
    ) -> Result<EnterStart<'_, T, I>, NativeSessionError<T::Error, I::Error>> {
        let (request, input, capacity) =
            self.enter_request(ring_index, EnterMode::Wait { timeout_ms })?;
        match self
            .transport
            .begin_ioctl(IOCTL_FSRING_ENTER, &input, capacity)
            .map_err(NativeSessionError::Transport)?
        {
            BeginIo::Completed(terminal) => match self.finish_enter(&request, terminal, false)? {
                EnterTerminalResult::Completed(completion) => Ok(EnterStart::Completed(completion)),
                // A synchronous completion cannot be a cancellation: nothing
                // asked for one.
                EnterTerminalResult::Cancelled { win32_code, .. } => {
                    Err(NativeSessionError::IoFailure {
                        win32_code,
                        information: 0,
                    })
                }
            },
            BeginIo::Pending(pending) => Ok(EnterStart::Pending(PendingEnter {
                session: self,
                request,
                operation: PendingOperation::new(self.transport.as_ref(), pending),
            })),
        }
    }

    /// The shared body of POLL and DRAIN.
    ///
    /// Windows may pend even an operation whose *driver* semantics are
    /// synchronous, so this waits for OS completion through the same owner the
    /// public WAIT uses rather than keeping a bare pending value.
    fn enter_synchronous(
        &self,
        ring_index: u32,
        mode: EnterMode,
    ) -> Result<EnterCompletion, NativeSessionError<T::Error, I::Error>> {
        let (request, input, capacity) = self.enter_request(ring_index, mode)?;
        let started = self
            .transport
            .begin_ioctl(IOCTL_FSRING_ENTER, &input, capacity)
            .map_err(NativeSessionError::Transport)?;
        let terminal = match started {
            BeginIo::Completed(terminal) => terminal,
            BeginIo::Pending(pending) => {
                let mut operation = PendingOperation::new(self.transport.as_ref(), pending);
                match operation.observe() {
                    Ok(Some(terminal)) => terminal,
                    Ok(None) => return Err(NativeSessionError::TerminalAlreadyObserved),
                    // The owner's `Drop` applies the same safety policy: exact
                    // cancel, terminal observation, and a deliberate leak if
                    // the OS still cannot be shown to be finished.
                    Err(error) => return Err(NativeSessionError::Transport(error)),
                }
            }
        };
        match self.finish_enter(&request, terminal, false)? {
            EnterTerminalResult::Completed(completion) => Ok(completion),
            EnterTerminalResult::Cancelled { win32_code, .. } => {
                Err(NativeSessionError::IoFailure {
                    win32_code,
                    information: 0,
                })
            }
        }
    }

    /// Build one ENTER request and size its exact output.
    fn enter_request(
        &self,
        ring_index: u32,
        mode: EnterMode,
    ) -> Result<
        (EnterRequestV1, [u8; ENTER_REQUEST_V1_SIZE as usize], usize),
        NativeSessionError<T::Error, I::Error>,
    > {
        let topology = self.topology();
        if ring_index >= topology.ring_count() {
            return Err(NativeSessionError::InvalidDescriptor);
        }
        let (flags, cq_budget, timeout_ms) = mode.wire();
        let identity = fsring_abi::validate::SessionIdentity {
            boot_instance_id: self.identity.boot_instance_id,
            mount_id: self.identity.mount_id,
            session_epoch: self.identity.session_epoch,
        };
        let input = crate::handshake::build_enter_request_with(
            identity, ring_index, flags, cq_budget, timeout_ms,
        );
        let request: EnterRequestV1 =
            try_decode(&input).map_err(|_| NativeSessionError::InvalidDescriptor)?;
        // The output is sized from the retained topology, never from anything
        // the driver said.
        let capacity = enter_result_size_v1(topology.notification_credit_count())
            .map_err(|_| NativeSessionError::ArithmeticOverflow)?;
        let capacity =
            usize::try_from(capacity).map_err(|_| NativeSessionError::ArithmeticOverflow)?;
        Ok((request, input, capacity))
    }

    /// Turn one terminal observation into a validated completion.
    fn finish_enter(
        &self,
        request: &EnterRequestV1,
        terminal: IoTerminal,
        cancelling: bool,
    ) -> Result<EnterTerminalResult, NativeSessionError<T::Error, I::Error>> {
        let (output, bytes_returned) = match terminal {
            IoTerminal::Success {
                output,
                bytes_returned,
            } => (output, bytes_returned),
            IoTerminal::Failed {
                win32_code,
                bytes_returned,
            } => {
                // Only an explicit cancellation may read an exact abort with no
                // returned bytes as cancellation. Everywhere else — and for an
                // abort that *did* return bytes — it is a plain I/O failure.
                if cancelling && win32_code.get() == ERROR_OPERATION_ABORTED && bytes_returned == 0
                {
                    return Ok(EnterTerminalResult::Cancelled {
                        win32_code: win32_code.get(),
                        bytes_returned,
                    });
                }
                return Err(NativeSessionError::IoFailure {
                    win32_code: win32_code.get(),
                    information: bytes_returned as u64,
                });
            }
        };
        if bytes_returned > output.len() {
            return Err(NativeSessionError::InvalidDescriptor);
        }
        let bytes = output
            .get(..bytes_returned)
            .ok_or(NativeSessionError::InvalidDescriptor)?;
        let topology = self.topology();
        let validated = validate_enter_result_v1(bytes, request, &topology)
            .map_err(NativeSessionError::ResultValidation)?;
        let result = validated.prefix();
        // The frozen validator already proved the length; restating the
        // arithmetic here is what catches a validator that ever stopped.
        let expected = enter_result_size_v1(result.notification_credit_count)
            .map_err(|_| NativeSessionError::ArithmeticOverflow)?;
        if u32::try_from(bytes_returned).unwrap_or(u32::MAX) != expected
            || result.header.struct_size != expected
        {
            return Err(NativeSessionError::InvalidDescriptor);
        }
        let mut returned_credits = Vec::new();
        let mut offset = result.notification_credits_offset as usize;
        for _ in 0..result.notification_credit_count {
            let end = offset
                .checked_add(NOTIFICATION_CREDIT_V1_SIZE as usize)
                .ok_or(NativeSessionError::ArithmeticOverflow)?;
            let credit: NotificationCreditV1 = try_decode(
                bytes
                    .get(offset..end)
                    .ok_or(NativeSessionError::InvalidDescriptor)?,
            )
            .map_err(|_| NativeSessionError::InvalidDescriptor)?;
            returned_credits.push(credit);
            offset = end;
        }
        Ok(EnterTerminalResult::Completed(EnterCompletion {
            result,
            returned_credits,
        }))
    }
}

// ---------------------------------------------------------------------------
// The Windows adapters
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub use windows_impl::{
    observe_inherited_handle_and_parent_after, observe_inherited_handle_donate,
    observe_ioctl_on_path, observe_nt_open_event, observe_nt_open_file,
    observe_nt_open_file_unprivileged, observe_nt_open_section, observe_win32_create_file,
    NtStatusObservation, WindowsApiError, WindowsControlDevice, WindowsControlTransport,
    WindowsMappingInspector, SECTION_QUERY, SYNCHRONIZE,
};

#[cfg(windows)]
mod windows_impl {
    //! Raw Windows FFI. It contains no decision: every value it produces is
    //! handed to the validation pipeline above unchanged.

    use super::{ControlDevice, ControlTransport, IoctlOutcome, MappingInspector, MemoryRegion};
    use std::ffi::c_void;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct WindowsApiError {
        pub win32_code: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u64,
        event: *mut c_void,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MemoryBasicInformation {
        base_address: *mut c_void,
        allocation_base: *mut c_void,
        allocation_protect: u32,
        partition_id: u16,
        _pad: u16,
        region_size: usize,
        state: u32,
        protect: u32,
        mapping_type: u32,
    }

    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const INFINITE: u32 = 0xFFFF_FFFF;
    const INVALID_HANDLE_VALUE: *mut c_void = usize::MAX as *mut c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *mut c_void,
            disposition: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
        fn CreateEventW(
            security: *mut c_void,
            manual_reset: i32,
            initial_state: i32,
            name: *const u16,
        ) -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn DeviceIoControl(
            device: *mut c_void,
            code: u32,
            input: *const u8,
            input_len: u32,
            output: *mut u8,
            output_len: u32,
            returned: *mut u32,
            overlapped: *mut Overlapped,
        ) -> i32;
        fn GetOverlappedResult(
            handle: *mut c_void,
            overlapped: *mut Overlapped,
            transferred: *mut u32,
            wait: i32,
        ) -> i32;
        fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
        fn CancelIoEx(handle: *mut c_void, overlapped: *mut Overlapped) -> i32;
        fn GetLastError() -> u32;
        fn SetLastError(code: u32);
        fn GetCurrentProcess() -> *mut c_void;
        fn ReadProcessMemory(
            process: *mut c_void,
            address: *const c_void,
            buffer: *mut u8,
            size: usize,
            read: *mut usize,
        ) -> i32;
        fn VirtualQuery(
            address: *const c_void,
            buffer: *mut MemoryBasicInformation,
            length: usize,
        ) -> usize;
        fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
        fn CreateProcessW(
            application: *const u16,
            command_line: *mut u16,
            process_attributes: *mut c_void,
            thread_attributes: *mut c_void,
            inherit_handles: i32,
            creation_flags: u32,
            environment: *mut c_void,
            current_directory: *const u16,
            startup: *mut StartupInfoW,
            information: *mut ProcessInformation,
        ) -> i32;
        fn GetExitCodeProcess(process: *mut c_void, exit_code: *mut u32) -> i32;
    }

    #[repr(C)]
    struct StartupInfoW {
        cb: u32,
        reserved: *mut u16,
        desktop: *mut u16,
        title: *mut u16,
        x: u32,
        y: u32,
        x_size: u32,
        y_size: u32,
        x_count_chars: u32,
        y_count_chars: u32,
        fill_attribute: u32,
        flags: u32,
        show_window: u16,
        reserved2: u16,
        reserved3: *mut u8,
        std_input: *mut c_void,
        std_output: *mut c_void,
        std_error: *mut c_void,
    }

    #[repr(C)]
    struct ProcessInformation {
        process: *mut c_void,
        thread: *mut c_void,
        process_id: u32,
        thread_id: u32,
    }

    /// The one owner of the control handle.
    pub struct WindowsControlTransport {
        handle: OwnedHandle,
    }

    pub struct WindowsMappingInspector;

    pub type WindowsControlDevice = ControlDevice<WindowsControlTransport, WindowsMappingInspector>;

    impl ControlDevice<WindowsControlTransport, WindowsMappingInspector> {
        /// Open `\\.\FsRing` exactly once.
        pub fn open() -> Result<Self, WindowsApiError> {
            let name: Vec<u16> = r"\\.\FsRing".encode_utf16().chain(Some(0)).collect();
            // SAFETY: `name` is a live NUL-terminated wide string for the call;
            // every other argument is a scalar or null.
            let raw = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    std::ptr::null_mut(),
                )
            };
            if raw == INVALID_HANDLE_VALUE || raw.is_null() {
                // SAFETY: no arguments; reads this thread's last error.
                return Err(WindowsApiError {
                    win32_code: unsafe { GetLastError() },
                });
            }
            // SAFETY: `CreateFileW` returned a fresh handle this process owns
            // and nothing else has adopted.
            let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
            Ok(Self::from_parts(
                WindowsControlTransport { handle },
                WindowsMappingInspector,
            ))
        }
    }

    impl ControlTransport for WindowsControlTransport {
        type Error = WindowsApiError;

        fn ioctl(
            &self,
            code: u32,
            input: &[u8],
            output: &mut [u8],
        ) -> Result<IoctlOutcome, Self::Error> {
            use std::os::windows::io::AsRawHandle;
            let device = self.handle.as_raw_handle().cast::<c_void>();
            // The handle is overlapped, so a null OVERLAPPED would let the I/O
            // manager complete asynchronously into a stack buffer that is
            // already gone. This path is synchronous only because it waits.
            // SAFETY: no name, auto-reset, initially non-signaled.
            let event = unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()) };
            if event.is_null() {
                // SAFETY: no arguments.
                return Err(WindowsApiError {
                    win32_code: unsafe { GetLastError() },
                });
            }
            let mut overlapped = Box::pin(Overlapped {
                internal: 0,
                internal_high: 0,
                offset: 0,
                event,
            });
            let mut returned: u32 = 0;
            let input_len = u32::try_from(input.len()).unwrap_or(u32::MAX);
            let output_len = u32::try_from(output.len()).unwrap_or(u32::MAX);
            // SAFETY: both slices stay live and pinned for the whole
            // operation, which the terminal wait below guarantees.
            let issued = unsafe {
                DeviceIoControl(
                    device,
                    code,
                    input.as_ptr(),
                    input_len,
                    output.as_mut_ptr(),
                    output_len,
                    &raw mut returned,
                    // SAFETY: the pinned box outlives the wait.
                    std::ptr::addr_of_mut!(*overlapped.as_mut()),
                )
            };
            let mut win32_code = 0u32;
            if issued == 0 {
                // SAFETY: no arguments.
                win32_code = unsafe { GetLastError() };
                const ERROR_IO_PENDING: u32 = 997;
                if win32_code == ERROR_IO_PENDING {
                    // SAFETY: the event belongs to this operation.
                    let _ = unsafe { WaitForSingleObject(event, INFINITE) };
                    // SAFETY: the same pinned OVERLAPPED and live handle.
                    let ok = unsafe {
                        GetOverlappedResult(
                            device,
                            std::ptr::addr_of_mut!(*overlapped.as_mut()),
                            &raw mut returned,
                            1,
                        )
                    };
                    // SAFETY: no arguments.
                    win32_code = if ok == 0 {
                        unsafe { GetLastError() }
                    } else {
                        0
                    };
                }
            }
            // SAFETY: this function created the event and closes it once.
            unsafe {
                CloseHandle(event);
            }
            Ok(IoctlOutcome {
                win32_code,
                information: u64::from(returned),
            })
        }
    }

    /// One in-flight overlapped operation.
    ///
    /// It owns an independent strong handle reference, both buffers, the
    /// pinned `OVERLAPPED`, and the completion event, and it releases none of
    /// them until a terminal observation succeeds.
    pub struct WindowsPending {
        handle: OwnedHandle,
        overlapped: Box<Overlapped>,
        event: *mut c_void,
        #[allow(dead_code)] // Owned so the OS never reads freed input.
        input: Vec<u8>,
        output: Vec<u8>,
        terminal: bool,
    }

    impl Drop for WindowsPending {
        fn drop(&mut self) {
            // Reached only after a successful terminal observation, or through
            // the deliberate `forget` in the owner's fail-safe branch, which
            // never runs this.
            if !self.event.is_null() {
                // SAFETY: this operation created the event and closes it once.
                unsafe {
                    CloseHandle(self.event);
                }
                self.event = std::ptr::null_mut();
            }
        }
    }

    // SAFETY: `WindowsPending` above owns a duplicated device handle, both
    // buffers, the boxed `OVERLAPPED`, and the event; `wait_terminal` below
    // returns `Err` without touching any of them, and the only place they are
    // released is after `GetOverlappedResult` reported a terminal state.
    unsafe impl super::OverlappedControlTransport for WindowsControlTransport {
        type Pending = WindowsPending;

        fn begin_ioctl(
            &self,
            code: u32,
            input: &[u8],
            output_capacity: usize,
        ) -> Result<super::BeginIo<Self::Pending>, Self::Error> {
            use std::os::windows::io::AsRawHandle;
            let handle = self.handle.try_clone().map_err(|_| WindowsApiError {
                // SAFETY: no arguments.
                win32_code: unsafe { GetLastError() },
            })?;
            // SAFETY: no name, auto-reset, initially non-signaled.
            let event = unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()) };
            if event.is_null() {
                // SAFETY: no arguments.
                return Err(WindowsApiError {
                    win32_code: unsafe { GetLastError() },
                });
            }
            let mut pending = WindowsPending {
                handle,
                overlapped: Box::new(Overlapped {
                    internal: 0,
                    internal_high: 0,
                    offset: 0,
                    event,
                }),
                event,
                input: input.to_vec(),
                output: vec![0u8; output_capacity],
                terminal: false,
            };
            let device = pending.handle.as_raw_handle().cast::<c_void>();
            let mut returned: u32 = 0;
            let input_len = u32::try_from(pending.input.len()).unwrap_or(u32::MAX);
            let output_len = u32::try_from(pending.output.len()).unwrap_or(u32::MAX);
            // SAFETY: every buffer is owned by `pending`, which outlives the
            // operation: it is either returned to the caller or consumed by a
            // terminal observation below.
            let issued = unsafe {
                DeviceIoControl(
                    device,
                    code,
                    pending.input.as_ptr(),
                    input_len,
                    pending.output.as_mut_ptr(),
                    output_len,
                    &raw mut returned,
                    std::ptr::addr_of_mut!(*pending.overlapped),
                )
            };
            if issued != 0 {
                pending.terminal = true;
                let bytes = returned as usize;
                let output = core::mem::take(&mut pending.output);
                return Ok(super::BeginIo::Completed(super::IoTerminal::Success {
                    output,
                    bytes_returned: bytes,
                }));
            }
            // SAFETY: no arguments.
            let code = unsafe { GetLastError() };
            const ERROR_IO_PENDING: u32 = 997;
            if code == ERROR_IO_PENDING {
                return Ok(super::BeginIo::Pending(pending));
            }
            pending.terminal = true;
            let win32_code = std::num::NonZeroU32::new(code).unwrap_or(
                // A failed issue that reports success is still a failure.
                std::num::NonZeroU32::new(u32::MAX).unwrap_or(std::num::NonZeroU32::MIN),
            );
            Ok(super::BeginIo::Completed(super::IoTerminal::Failed {
                win32_code,
                bytes_returned: 0,
            }))
        }

        fn cancel_exact(
            &self,
            pending: &Self::Pending,
        ) -> Result<super::CancelRequest, Self::Error> {
            use std::os::windows::io::AsRawHandle;
            let device = pending.handle.as_raw_handle().cast::<c_void>();
            // Exactly this operation: the OVERLAPPED address is what makes the
            // cancellation target one request rather than the whole handle.
            // SAFETY: both the handle and the boxed OVERLAPPED are owned by
            // `pending` and remain live for the call.
            let ok =
                unsafe { CancelIoEx(device, std::ptr::addr_of!(*pending.overlapped).cast_mut()) };
            if ok != 0 {
                return Ok(super::CancelRequest::Issued);
            }
            // SAFETY: no arguments.
            let code = unsafe { GetLastError() };
            const ERROR_NOT_FOUND: u32 = 1168;
            if code == ERROR_NOT_FOUND {
                // The request may have completed in between; only
                // `wait_terminal` can say so.
                Ok(super::CancelRequest::NotFound)
            } else {
                Err(WindowsApiError { win32_code: code })
            }
        }

        fn wait_terminal(
            &self,
            pending: &mut Self::Pending,
        ) -> Result<super::IoTerminal, Self::Error> {
            use std::os::windows::io::AsRawHandle;
            if pending.terminal {
                return Err(WindowsApiError { win32_code: 0 });
            }
            let device = pending.handle.as_raw_handle().cast::<c_void>();
            // Non-alertable: an alertable wait would let an APC run while the
            // OS still owns these buffers.
            // SAFETY: the event belongs to this operation.
            let waited = unsafe { WaitForSingleObject(pending.event, INFINITE) };
            if waited != 0 {
                // Nothing has been released: the caller may retry.
                // SAFETY: no arguments.
                return Err(WindowsApiError {
                    win32_code: unsafe { GetLastError() },
                });
            }
            let mut returned: u32 = 0;
            // SAFETY: the same owned handle and pinned OVERLAPPED.
            let ok = unsafe {
                GetOverlappedResult(
                    device,
                    std::ptr::addr_of_mut!(*pending.overlapped),
                    &raw mut returned,
                    1,
                )
            };
            pending.terminal = true;
            if ok != 0 {
                let output = core::mem::take(&mut pending.output);
                return Ok(super::IoTerminal::Success {
                    output,
                    bytes_returned: returned as usize,
                });
            }
            // SAFETY: no arguments.
            let code = unsafe { GetLastError() };
            Ok(super::IoTerminal::Failed {
                win32_code: std::num::NonZeroU32::new(code).unwrap_or(std::num::NonZeroU32::MIN),
                bytes_returned: returned as usize,
            })
        }
    }

    impl MappingInspector for WindowsMappingInspector {
        type Error = WindowsApiError;

        fn query_covering(
            &self,
            address: usize,
            length: usize,
        ) -> Result<Vec<MemoryRegion>, Self::Error> {
            let mut regions = Vec::new();
            let mut cursor = address;
            let end = address.saturating_add(length);
            while cursor < end {
                let mut info = MemoryBasicInformation {
                    base_address: std::ptr::null_mut(),
                    allocation_base: std::ptr::null_mut(),
                    allocation_protect: 0,
                    partition_id: 0,
                    _pad: 0,
                    region_size: 0,
                    state: 0,
                    protect: 0,
                    mapping_type: 0,
                };
                // SAFETY: the out buffer is a live local of exactly this size.
                let written = unsafe {
                    VirtualQuery(
                        cursor as *const c_void,
                        &raw mut info,
                        std::mem::size_of::<MemoryBasicInformation>(),
                    )
                };
                if written == 0 {
                    // SAFETY: no arguments.
                    return Err(WindowsApiError {
                        win32_code: unsafe { GetLastError() },
                    });
                }
                let base = info.base_address as usize;
                regions.push(MemoryRegion {
                    base_address: base,
                    region_size: info.region_size,
                    state: info.state,
                    mapping_type: info.mapping_type,
                    protection: info.protect,
                });
                let next = base.saturating_add(info.region_size);
                if next <= cursor {
                    break;
                }
                cursor = next;
            }
            Ok(regions)
        }

        fn copy_read_only(&self, address: usize, length: usize) -> Result<Vec<u8>, Self::Error> {
            let mut buffer = vec![0u8; length];
            let mut read = 0usize;
            // SAFETY: the destination is a live owned buffer of exactly
            // `length` bytes; a partial or failed read is rejected below rather
            // than trusted.
            let ok = unsafe {
                ReadProcessMemory(
                    GetCurrentProcess(),
                    address as *const c_void,
                    buffer.as_mut_ptr(),
                    length,
                    &raw mut read,
                )
            };
            if ok == 0 || read != length {
                // SAFETY: no arguments.
                return Err(WindowsApiError {
                    win32_code: unsafe { GetLastError() },
                });
            }
            Ok(buffer)
        }
    }

    /// `SECTION_QUERY`.
    pub const SECTION_QUERY: u32 = 0x0001;
    /// `SYNCHRONIZE`.
    pub const SYNCHRONIZE: u32 = 0x0010_0000;
    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_DUPLICATE: u32 = 0x0002;
    const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
    const TOKEN_INTEGRITY_LEVEL: u32 = 25;
    const DISABLE_MAX_PRIVILEGE: u32 = 0x1;
    const FILE_SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct NtStatusObservation {
        pub ntstatus: u32,
    }

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: *mut c_void,
        object_name: *mut UnicodeString,
        attributes: u32,
        security_descriptor: *mut c_void,
        security_quality_of_service: *mut c_void,
    }

    #[repr(C)]
    struct IoStatusBlock {
        status: i32,
        information: usize,
    }

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: u32,
    }

    #[repr(C)]
    struct TokenMandatoryLabel {
        label: SidAndAttributes,
    }

    #[repr(C)]
    struct SidIdentifierAuthority {
        value: [u8; 6],
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtOpenSection(
            handle: *mut *mut c_void,
            access: u32,
            attributes: *mut ObjectAttributes,
        ) -> i32;
        fn NtOpenEvent(
            handle: *mut *mut c_void,
            access: u32,
            attributes: *mut ObjectAttributes,
        ) -> i32;
        fn NtOpenFile(
            handle: *mut *mut c_void,
            access: u32,
            attributes: *mut ObjectAttributes,
            io_status: *mut IoStatusBlock,
            share: u32,
            options: u32,
        ) -> i32;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
        fn CreateRestrictedToken(
            existing: *mut c_void,
            flags: u32,
            disable_sid_count: u32,
            disable_sids: *mut c_void,
            delete_priv_count: u32,
            delete_privs: *mut c_void,
            restrict_sid_count: u32,
            restrict_sids: *mut c_void,
            token: *mut *mut c_void,
        ) -> i32;
        fn ImpersonateLoggedOnUser(token: *mut c_void) -> i32;
        fn RevertToSelf() -> i32;
        fn AllocateAndInitializeSid(
            authority: *const SidIdentifierAuthority,
            count: u8,
            s0: u32,
            s1: u32,
            s2: u32,
            s3: u32,
            s4: u32,
            s5: u32,
            s6: u32,
            s7: u32,
            sid: *mut *mut c_void,
        ) -> i32;
        fn FreeSid(sid: *mut c_void) -> *mut c_void;
        fn SetTokenInformation(
            token: *mut c_void,
            class: u32,
            info: *mut c_void,
            length: u32,
        ) -> i32;
    }

    fn wide_nul(name: &str) -> Vec<u16> {
        name.encode_utf16().chain(Some(0)).collect()
    }

    fn object_attributes(name: &mut [u16]) -> (UnicodeString, ObjectAttributes) {
        let units = name.len().saturating_sub(1) * 2;
        let unicode = UnicodeString {
            length: units as u16,
            maximum_length: (name.len() * 2) as u16,
            buffer: name.as_mut_ptr(),
        };
        let attributes = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: core::ptr::null_mut(),
            object_name: core::ptr::null_mut(),
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: core::ptr::null_mut(),
            security_quality_of_service: core::ptr::null_mut(),
        };
        (unicode, attributes)
    }

    fn close_if_open(handle: *mut c_void) {
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(handle);
            }
        }
    }

    /// Open a Win32 path, close it immediately, and return the Win32 result.
    pub fn observe_win32_create_file(path: &str) -> IoctlOutcome {
        let mut name = wide_nul(path);
        unsafe { SetLastError(0) };
        let raw = unsafe {
            CreateFileW(
                name.as_mut_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                core::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                core::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return IoctlOutcome {
                win32_code: unsafe { GetLastError() },
                information: 0,
            };
        }
        close_if_open(raw);
        IoctlOutcome {
            win32_code: 0,
            information: 0,
        }
    }

    /// Open a Win32 path, issue one ioctl, close the handle, return the outcome.
    pub fn observe_ioctl_on_path(path: &str, code: u32, input: &[u8]) -> IoctlOutcome {
        let mut name = wide_nul(path);
        unsafe { SetLastError(0) };
        let raw = unsafe {
            CreateFileW(
                name.as_mut_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                core::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                core::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return IoctlOutcome {
                win32_code: unsafe { GetLastError() },
                information: 0,
            };
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        let transport = WindowsControlTransport { handle };
        match transport.ioctl(code, input, &mut []) {
            Ok(outcome) => outcome,
            Err(error) => IoctlOutcome {
                win32_code: error.win32_code,
                information: 0,
            },
        }
    }

    fn observe_nt_named(
        name: &str,
        access: u32,
        open: unsafe extern "system" fn(*mut *mut c_void, u32, *mut ObjectAttributes) -> i32,
    ) -> NtStatusObservation {
        let mut wide = wide_nul(name);
        let (mut unicode, mut attributes) = object_attributes(&mut wide);
        attributes.object_name = &raw mut unicode;
        let mut handle: *mut c_void = core::ptr::null_mut();
        let status = unsafe { open(&raw mut handle, access, &raw mut attributes) };
        if status >= 0 {
            close_if_open(handle);
        }
        NtStatusObservation {
            ntstatus: status as u32,
        }
    }

    pub fn observe_nt_open_section(name: &str, access: u32) -> NtStatusObservation {
        observe_nt_named(name, access, NtOpenSection)
    }

    pub fn observe_nt_open_event(name: &str, access: u32) -> NtStatusObservation {
        observe_nt_named(name, access, NtOpenEvent)
    }

    pub fn observe_nt_open_file(name: &str) -> NtStatusObservation {
        let mut wide = wide_nul(name);
        let (mut unicode, mut attributes) = object_attributes(&mut wide);
        attributes.object_name = &raw mut unicode;
        let mut handle: *mut c_void = core::ptr::null_mut();
        let mut iosb = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let status = unsafe {
            NtOpenFile(
                &raw mut handle,
                SYNCHRONIZE,
                &raw mut attributes,
                &raw mut iosb,
                FILE_SHARE_ALL,
                FILE_NON_DIRECTORY_FILE,
            )
        };
        if status >= 0 {
            close_if_open(handle);
        }
        NtStatusObservation {
            ntstatus: status as u32,
        }
    }

    pub fn observe_nt_open_file_unprivileged(name: &str) -> NtStatusObservation {
        let mut process_token = core::ptr::null_mut();
        let opened = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT,
                &raw mut process_token,
            )
        };
        if opened == 0 {
            return observe_nt_open_file(name);
        }
        let mut restricted = core::ptr::null_mut();
        let created = unsafe {
            CreateRestrictedToken(
                process_token,
                DISABLE_MAX_PRIVILEGE,
                0,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                &raw mut restricted,
            )
        };
        close_if_open(process_token);
        if created == 0 || restricted.is_null() {
            return observe_nt_open_file(name);
        }
        let authority = SidIdentifierAuthority {
            value: [0, 0, 0, 0, 0, 16],
        };
        let mut sid = core::ptr::null_mut();
        let sid_ok = unsafe {
            AllocateAndInitializeSid(
                &raw const authority,
                1,
                0x2000,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                &raw mut sid,
            )
        };
        if sid_ok != 0 && !sid.is_null() {
            let mut label = TokenMandatoryLabel {
                label: SidAndAttributes {
                    sid,
                    attributes: 0x20,
                },
            };
            let _ = unsafe {
                SetTokenInformation(
                    restricted,
                    TOKEN_INTEGRITY_LEVEL,
                    (&raw mut label).cast(),
                    core::mem::size_of::<TokenMandatoryLabel>() as u32,
                )
            };
            unsafe {
                FreeSid(sid);
            }
        }
        let impersonated = unsafe { ImpersonateLoggedOnUser(restricted) };
        let observation = if impersonated != 0 {
            let observed = observe_nt_open_file(name);
            unsafe {
                RevertToSelf();
            }
            observed
        } else {
            observe_nt_open_file(name)
        };
        close_if_open(restricted);
        observation
    }

    /// Open the control device, spawn `executable --child-handle`, and return
    /// the donate observation the child reported.
    ///
    /// The child is the C3 inherited-handle probe: exit 0 means it observed
    /// `ERROR_ACCESS_DENIED`. A missing device returns the CreateFile Win32
    /// code instead of fabricating ACCESS_DENIED.
    pub fn observe_inherited_handle_donate(executable: &std::path::Path) -> IoctlOutcome {
        observe_inherited_handle_and_parent_after(executable).0
    }

    /// Same child-inherited open as [`observe_inherited_handle_donate`], then
    /// DONATE on that *same* parent handle after the child exits.
    pub fn observe_inherited_handle_and_parent_after(
        executable: &std::path::Path,
    ) -> (IoctlOutcome, IoctlOutcome) {
        let mut name = wide_nul(r"\\.\FsRing");
        unsafe { SetLastError(0) };
        let raw = unsafe {
            CreateFileW(
                name.as_mut_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                core::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                core::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            let failed = IoctlOutcome {
                win32_code: unsafe { GetLastError() },
                information: 0,
            };
            return (failed, failed);
        }
        const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
        let _ = unsafe { SetHandleInformation(raw, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) };
        let width = core::mem::size_of::<usize>() * 2;
        let handle_arg = format!("0x{value:0width$x}", value = raw as usize);
        let mut command = wide_nul(&format!(
            "\"{}\" --child-handle {}",
            executable.display(),
            handle_arg
        ));
        let mut application = wide_nul(&executable.to_string_lossy());
        let mut startup = StartupInfoW {
            cb: core::mem::size_of::<StartupInfoW>() as u32,
            reserved: core::ptr::null_mut(),
            desktop: core::ptr::null_mut(),
            title: core::ptr::null_mut(),
            x: 0,
            y: 0,
            x_size: 0,
            y_size: 0,
            x_count_chars: 0,
            y_count_chars: 0,
            fill_attribute: 0,
            flags: 0,
            show_window: 0,
            reserved2: 0,
            reserved3: core::ptr::null_mut(),
            std_input: core::ptr::null_mut(),
            std_output: core::ptr::null_mut(),
            std_error: core::ptr::null_mut(),
        };
        let mut information = ProcessInformation {
            process: core::ptr::null_mut(),
            thread: core::ptr::null_mut(),
            process_id: 0,
            thread_id: 0,
        };
        let created = unsafe {
            CreateProcessW(
                application.as_mut_ptr(),
                command.as_mut_ptr(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                1,
                0,
                core::ptr::null_mut(),
                core::ptr::null(),
                &raw mut startup,
                &raw mut information,
            )
        };
        if created == 0 {
            let code = unsafe { GetLastError() };
            close_if_open(raw);
            let failed = IoctlOutcome {
                win32_code: if code == 0 { 1 } else { code },
                information: 0,
            };
            return (failed, failed);
        }
        unsafe {
            WaitForSingleObject(information.process, INFINITE);
        }
        let mut exit_code = 1u32;
        let _ = unsafe { GetExitCodeProcess(information.process, &raw mut exit_code) };
        close_if_open(information.thread);
        close_if_open(information.process);
        let child = if exit_code == 0 {
            IoctlOutcome {
                win32_code: 5,
                information: 0,
            }
        } else {
            IoctlOutcome {
                win32_code: exit_code,
                information: 0,
            }
        };
        let parent_after = {
            use fsring_abi::control::IOCTL_FSRING_DONATE_SECURITY_CONTEXT;
            use fsring_abi::msgs::{ControlHeader, DonateSecurityContextV1, CONTROL_VERSION_V1};
            let donation = DonateSecurityContextV1 {
                header: ControlHeader {
                    struct_size: core::mem::size_of::<DonateSecurityContextV1>() as u32,
                    struct_version: CONTROL_VERSION_V1,
                    required_flags: 0,
                },
                security_context_id: 0x1122_3344_5566_7788,
                daemon_handle: 0x99aa_bbcc_ddee_ff00,
                flags: 0,
                reserved: 0,
            };
            let bytes: &[u8] = unsafe {
                core::slice::from_raw_parts(
                    (&raw const donation).cast::<u8>(),
                    core::mem::size_of::<DonateSecurityContextV1>(),
                )
            };
            let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
            let transport = WindowsControlTransport { handle };
            match transport.ioctl(IOCTL_FSRING_DONATE_SECURITY_CONTEXT, bytes, &mut []) {
                Ok(outcome) => outcome,
                Err(error) => IoctlOutcome {
                    win32_code: error.win32_code,
                    information: 0,
                },
            }
        };
        (child, parent_after)
    }
}
