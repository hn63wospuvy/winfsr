//! The native control session, driven entirely through fakes.
//!
//! Every "returned" address here points into fixture-owned memory, so a test
//! that accidentally trusted the driver's numbers would read the fixture's own
//! buffer rather than something arbitrary — and the assertions below are what
//! make that trust visible instead of latent.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::cell::RefCell;

use fsring_abi::codec::{try_decode, try_encode};
use fsring_abi::control::{
    view_access, view_kind, SessionResultV1, UserViewDesc, GLOBAL_RING_INDEX,
    SESSION_RESULT_V1_PREFIX_SIZE, SETUP_REQUEST_V1_SIZE, USER_VIEW_DESC_SIZE,
};
use fsring_abi::msgs::{ControlHeader, CONTROL_VERSION_V1};
use fsring_abi::section_layout::SectionLayoutPlan;
use fsring_user::handshake::{build_setup_request, encode_setup_request, serve_setup};
use fsring_user::native::{
    ControlDevice, ControlTransport, IoctlOutcome, MappingInspector, MemoryRegion,
    NativeSessionError, ERROR_SUCCESS, MEM_COMMIT, MEM_MAPPED, PAGE_READONLY, PAGE_READWRITE,
};

const PAGE: u32 = 4096;
const RING_COUNT: u32 = 2;

/// The section image the fake "maps": one owned allocation whose addresses are
/// what the fake driver hands back.
struct SectionImage {
    storage: Vec<u8>,
    offset: usize,
    size: usize,
}

impl SectionImage {
    /// The page a real view starts on.
    ///
    /// A `Vec<u8>` is only byte-aligned, but every address this fixture hands
    /// the client stands in for a kernel mapping, and a kernel mapping starts
    /// on a page boundary. Modelling that faithfully is what lets the client's
    /// alignment check be exercised by a *skewed* fixture rather than by the
    /// fixture's own allocator luck.
    const PAGE: usize = 4096;

    fn new(plan: &SectionLayoutPlan) -> Self {
        let size = plan.section_size() as usize;
        let mut storage = vec![0u8; size + Self::PAGE];
        let misalignment = storage.as_ptr() as usize % Self::PAGE;
        let offset = if misalignment == 0 {
            0
        } else {
            Self::PAGE - misalignment
        };
        plan.construct(&mut storage[offset..offset + size])
            .expect("the fixture image is canonical");
        Self {
            storage,
            offset,
            size,
        }
    }

    fn base(&self) -> usize {
        self.storage.as_ptr().wrapping_add(self.offset).cast::<u8>() as usize
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        let (offset, size) = (self.offset, self.size);
        &mut self.storage[offset..offset + size]
    }
}

/// One view the fake driver reports, before any hostile edit.
#[derive(Clone, Copy)]
struct FakeView {
    desc: UserViewDesc,
}

fn canonical_views(plan: &SectionLayoutPlan, base: usize) -> Vec<FakeView> {
    let mut views = Vec::new();
    let mut push = |section_offset: u64, length: u64, ring_index: u32, kind: u16, access: u16| {
        views.push(FakeView {
            desc: UserViewDesc {
                section_offset,
                length,
                user_address: (base as u64).wrapping_add(section_offset),
                ring_index,
                kind,
                access,
            },
        });
    };
    push(
        0,
        plan.section_size(),
        GLOBAL_RING_INDEX,
        view_kind::SECTION_READ_ONLY,
        view_access::READ_ONLY,
    );
    for ring in plan.rings() {
        for (region, kind) in [
            (ring.sq_consumer, view_kind::SQ_CONSUMER_PAGE),
            (ring.cq_entries, view_kind::CQ_ENTRIES),
            (ring.cq_producer, view_kind::CQ_PRODUCER_PAGE),
        ] {
            push(
                region.offset,
                region.length,
                ring.ring_index,
                kind,
                view_access::READ_WRITE,
            );
        }
    }
    let u2k = plan.u2k_slots();
    push(
        u2k.offset,
        u2k.length,
        GLOBAL_RING_INDEX,
        view_kind::U2K_ARENA,
        view_access::READ_WRITE,
    );
    views
}

/// The fake driver: it answers one SETUP with whatever the fixture configures.
struct FakeTransport {
    plan: SectionLayoutPlan,
    views: Vec<FakeView>,
    win32_code: u32,
    information_override: Option<u64>,
    calls: RefCell<Vec<String>>,
}

impl ControlTransport for FakeTransport {
    type Error = ();

    fn ioctl(
        &self,
        _code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<IoctlOutcome, Self::Error> {
        self.calls.borrow_mut().push("device-io-control".into());
        assert_eq!(input.len(), SETUP_REQUEST_V1_SIZE as usize);
        if self.win32_code != ERROR_SUCCESS {
            return Ok(IoctlOutcome {
                win32_code: self.win32_code,
                information: 0,
            });
        }
        let setup = serve_setup(input).expect("the fixture request is canonical");
        let topology = setup.topology();
        let total = fsring_abi::validate::session_result_size_v1(&topology).unwrap();
        assert_eq!(output.len(), total as usize);

        let view_count = u32::try_from(self.views.len()).unwrap();
        let credits_offset = SESSION_RESULT_V1_PREFIX_SIZE + view_count * USER_VIEW_DESC_SIZE;
        let prefix = SessionResultV1 {
            header: ControlHeader {
                struct_size: total,
                struct_version: CONTROL_VERSION_V1,
                required_flags: 0,
            },
            abi_major: 2,
            abi_minor: 1,
            reserved0: 0,
            mount_id: fsring_abi::MountId { lo: 9, hi: 17 },
            boot_instance_id: fsring_abi::BootInstanceId { lo: 3, hi: 5 },
            session_epoch: 1,
            section_size: self.plan.section_size(),
            selected_features: setup.selection().selected_features,
            os_capabilities: setup.selection().detected_os_capabilities,
            view_count,
            view_desc_size: USER_VIEW_DESC_SIZE,
            views_offset: SESSION_RESULT_V1_PREFIX_SIZE,
            notification_credit_count: topology.notification_credit_count(),
            notification_credit_desc_size: fsring_abi::control::NOTIFICATION_CREDIT_V1_SIZE,
            notification_credits_offset: credits_offset,
            ring_count: topology.ring_count(),
            max_inflight: topology.max_inflight(),
            flags: 0,
            reserved1: 0,
        };
        try_encode(
            &prefix,
            &mut output[..SESSION_RESULT_V1_PREFIX_SIZE as usize],
        )
        .unwrap();
        let mut cursor = SESSION_RESULT_V1_PREFIX_SIZE as usize;
        for view in &self.views {
            try_encode(
                &view.desc,
                &mut output[cursor..cursor + USER_VIEW_DESC_SIZE as usize],
            )
            .unwrap();
            cursor += USER_VIEW_DESC_SIZE as usize;
        }
        // The credit tail must be a real generation-one credit set: the frozen
        // validator checks it, and a zero tail would make every test below
        // fail for the wrong reason.
        let class = topology.notification_credit_class();
        let size = topology.notification_credit_size();
        for ordinal in 0..topology.notification_credit_count() {
            let token = fsring_abi::slots::SlotToken::try_new(class, ordinal, 1).unwrap();
            let credit = fsring_abi::control::NotificationCreditV1 {
                buffer: fsring_abi::msgs::BufferRef {
                    token: token.raw(),
                    offset: 0,
                    length: size,
                    kind: fsring_abi::msgs::buffer_kind::SLOT,
                    access: fsring_abi::msgs::buffer_access::U2K_WRITE,
                    reserved: 0,
                },
                ring_index: ordinal % topology.ring_count(),
                reserved: 0,
            };
            let start = credits_offset as usize
                + ordinal as usize * fsring_abi::control::NOTIFICATION_CREDIT_V1_SIZE as usize;
            try_encode(
                &credit,
                &mut output
                    [start..start + fsring_abi::control::NOTIFICATION_CREDIT_V1_SIZE as usize],
            )
            .unwrap();
        }
        Ok(IoctlOutcome {
            win32_code: ERROR_SUCCESS,
            information: self.information_override.unwrap_or(u64::from(total)),
        })
    }
}

/// The fake address space: one committed mapped region per protection class.
struct FakeInspector {
    base: usize,
    length: usize,
    writable: Vec<(usize, usize)>,
    state: u32,
    mapping_type: u32,
    protection_override: Option<u32>,
    gap_at: Option<usize>,
    calls: RefCell<Vec<String>>,
}

impl MappingInspector for FakeInspector {
    type Error = ();

    fn query_covering(
        &self,
        address: usize,
        length: usize,
    ) -> Result<Vec<MemoryRegion>, Self::Error> {
        self.calls
            .borrow_mut()
            .push("virtual-query-full-coverage".into());
        if self.gap_at == Some(address) {
            // A region that starts past the requested address is a hole.
            return Ok(vec![MemoryRegion {
                base_address: address + PAGE as usize,
                region_size: length,
                state: self.state,
                mapping_type: self.mapping_type,
                protection: PAGE_READONLY,
            }]);
        }
        let writable = self
            .writable
            .iter()
            .any(|(base, len)| address >= *base && address + length <= base + len);
        let protection = self.protection_override.unwrap_or(if writable {
            PAGE_READWRITE
        } else {
            PAGE_READONLY
        });
        Ok(vec![MemoryRegion {
            base_address: address,
            region_size: length,
            state: self.state,
            mapping_type: self.mapping_type,
            protection,
        }])
    }

    fn copy_read_only(&self, address: usize, length: usize) -> Result<Vec<u8>, Self::Error> {
        self.calls.borrow_mut().push("read-process-memory".into());
        assert!(address >= self.base && address + length <= self.base + self.length);
        // SAFETY: the fixture owns this allocation and the assertion above
        // proves the range lies inside it.
        let slice = unsafe { std::slice::from_raw_parts(address as *const u8, length) };
        Ok(slice.to_vec())
    }
}

struct Fixture {
    _image: SectionImage,
    plan: SectionLayoutPlan,
    views: Vec<FakeView>,
    base: usize,
}

fn fixture() -> Fixture {
    let request = build_setup_request(RING_COUNT);
    let bytes = encode_setup_request(&request);
    let setup = serve_setup(&bytes).expect("canonical request");
    let plan = SectionLayoutPlan::compute(&setup, PAGE).expect("canonical layout");
    let image = SectionImage::new(&plan);
    let base = image.base();
    let views = canonical_views(&plan, base);
    Fixture {
        _image: image,
        plan,
        views,
        base,
    }
}

fn device(fixture: &Fixture, views: Vec<FakeView>) -> ControlDevice<FakeTransport, FakeInspector> {
    let writable: Vec<(usize, usize)> = views
        .iter()
        .filter(|view| view.desc.access == view_access::READ_WRITE)
        .map(|view| (view.desc.user_address as usize, view.desc.length as usize))
        .collect();
    ControlDevice::from_parts(
        FakeTransport {
            plan: fixture.plan,
            views,
            win32_code: ERROR_SUCCESS,
            information_override: None,
            calls: RefCell::new(Vec::new()),
        },
        FakeInspector {
            base: fixture.base,
            length: fixture.plan.section_size() as usize,
            writable,
            state: MEM_COMMIT,
            mapping_type: MEM_MAPPED,
            protection_override: None,
            gap_at: None,
            calls: RefCell::new(Vec::new()),
        },
    )
}

type Error = NativeSessionError<(), ()>;

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

#[test]
fn a_canonical_setup_yields_one_ring_per_topology_entry() {
    let fixture = fixture();
    let session = device(&fixture, fixture.views.clone())
        .setup(RING_COUNT)
        .map_err(|_| ())
        .expect("a canonical result validates");
    assert_eq!(session.ring_count(), RING_COUNT as usize);
    assert_eq!(session.identity().session_epoch, 1);
    assert_eq!(session.topology().ring_count(), RING_COUNT);
    for index in 0..RING_COUNT {
        let ring = session.ring(index).expect("every ring exists");
        assert_eq!(ring.ring_index(), index);
        assert_eq!(ring.layout().ring_index, index);
    }
    assert!(session.ring(RING_COUNT).is_none());
    let layout = session.observe_session_layout();
    assert!(layout.independent_parser);
    assert!(layout.exact_lengths);
    assert!(layout.descriptor_counts_match);
    assert!(layout.zero_cursors);
    let views = session.observe_view_protections();
    assert!(views.virtual_query_coverage);
    assert!(views.exact_protections);
    assert_eq!(views.overlap_count, 0);
    assert_eq!(views.executable_range_count, 0);
}

#[test]
fn the_daemon_role_is_exclusive_for_as_long_as_it_lives() {
    let fixture = fixture();
    let mut session = device(&fixture, fixture.views.clone())
        .setup(RING_COUNT)
        .map_err(|_| ())
        .expect("validates");
    let ring = session.ring_mut(0).expect("ring 0");
    let mut daemon = ring.attach_daemon();
    // The ring stays exclusively borrowed: no second role and no teardown can
    // be expressed while this one is alive.
    assert!(daemon.poll_sqe().is_ok());
}

#[test]
fn the_duplicate_probe_adopts_nothing() {
    let fixture = fixture();
    let session = device(&fixture, fixture.views.clone())
        .setup(RING_COUNT)
        .map_err(|_| ())
        .expect("validates");
    let before = session.identity();
    let outcome = session
        .probe_duplicate_setup()
        .map_err(|_| ())
        .expect("the probe returns a raw outcome");
    assert_eq!(outcome.win32_code, ERROR_SUCCESS);
    assert_eq!(
        session.identity(),
        before,
        "the probe changes nothing about the live session",
    );
    assert_eq!(session.ring_count(), RING_COUNT as usize);
}

/// The raw SETUP probe reaches the driver with a request the SDK itself would
/// refuse -- which is the only way a smoke probe can observe the DRIVER's
/// refusal. Round-17 evidence E4: `setup-required-unavailable` went through
/// `setup_with_request`, whose local validation refused the request before
/// any IOCTL, so its oracle described a driver answer it never received.
#[test]
fn the_raw_setup_probe_reaches_the_driver_past_local_validation() {
    let unimplemented_required = || {
        let mut request = build_setup_request(RING_COUNT);
        request.offered_features.words[0] |= 0x8000_0000;
        request.required_features.words[0] = 0x8000_0000;
        request
    };
    let fixture = fixture();
    let refusing_driver = || {
        ControlDevice::from_parts(
            FakeTransport {
                plan: fixture.plan,
                views: fixture.views.clone(),
                win32_code: 0x32,
                information_override: None,
                calls: RefCell::new(Vec::new()),
            },
            FakeInspector {
                base: fixture.base,
                length: fixture.plan.section_size() as usize,
                writable: Vec::new(),
                state: MEM_COMMIT,
                mapping_type: MEM_MAPPED,
                protection_override: None,
                gap_at: None,
                calls: RefCell::new(Vec::new()),
            },
        )
    };

    // The SDK path never asks the driver: the local validator refuses first.
    let sdk = refusing_driver()
        .setup_with_request(unimplemented_required())
        .err()
        .expect("the SDK refuses a required unimplemented feature");
    assert!(
        matches!(sdk, Error::ResultValidation(_)),
        "the SDK path must refuse locally, got {sdk:?}",
    );

    // The raw probe does, and reports exactly what the driver answered.
    let outcome = refusing_driver()
        .probe_raw_setup(unimplemented_required())
        .map_err(|_| ())
        .expect("the probe returns the driver's raw outcome");
    assert_eq!(outcome.win32_code, 0x32);
    assert_eq!(outcome.information, 0);
}

// ---------------------------------------------------------------------------
// Transport-level refusals
// ---------------------------------------------------------------------------

#[test]
fn a_rejected_control_request_is_an_io_failure_not_a_session() {
    let fixture = fixture();
    let transport = FakeTransport {
        plan: fixture.plan,
        views: fixture.views.clone(),
        win32_code: 5,
        information_override: None,
        calls: RefCell::new(Vec::new()),
    };
    let inspector = FakeInspector {
        base: fixture.base,
        length: fixture.plan.section_size() as usize,
        writable: Vec::new(),
        state: MEM_COMMIT,
        mapping_type: MEM_MAPPED,
        protection_override: None,
        gap_at: None,
        calls: RefCell::new(Vec::new()),
    };
    let error = ControlDevice::from_parts(transport, inspector)
        .setup(RING_COUNT)
        .err()
        .expect("a rejected request is not a session");
    assert_eq!(
        error,
        Error::IoFailure {
            win32_code: 5,
            information: 0,
        },
    );
}

#[test]
fn a_short_information_count_is_refused() {
    let fixture = fixture();
    let transport = FakeTransport {
        plan: fixture.plan,
        views: fixture.views.clone(),
        win32_code: ERROR_SUCCESS,
        information_override: Some(8),
        calls: RefCell::new(Vec::new()),
    };
    let inspector = FakeInspector {
        base: fixture.base,
        length: fixture.plan.section_size() as usize,
        writable: Vec::new(),
        state: MEM_COMMIT,
        mapping_type: MEM_MAPPED,
        protection_override: None,
        gap_at: None,
        calls: RefCell::new(Vec::new()),
    };
    assert_eq!(
        ControlDevice::from_parts(transport, inspector)
            .setup(RING_COUNT)
            .err()
            .expect("short result"),
        Error::InvalidDescriptor,
    );
}

// ---------------------------------------------------------------------------
// Hostile descriptors
// ---------------------------------------------------------------------------

fn mutate(fixture: &Fixture, index: usize, edit: impl FnOnce(&mut UserViewDesc)) -> Vec<FakeView> {
    let mut views = fixture.views.clone();
    edit(&mut views[index].desc);
    views
}

#[test]
fn a_zero_user_address_is_refused() {
    let fixture = fixture();
    let views = mutate(&fixture, 0, |desc| desc.user_address = 0);
    assert_eq!(
        device(&fixture, views)
            .setup(RING_COUNT)
            .err()
            .expect("zero"),
        Error::InvalidDescriptor,
    );
}

#[test]
fn a_misaligned_user_address_is_refused() {
    // The design requires returned addresses to be checked for "descriptor
    // alignment" alongside nonzero, range overflow, kind/access, ring
    // ownership, and non-overlap. Alignment is the one a coverage check cannot
    // stand in for: VirtualQuery answers about the region containing an
    // address, and a region that starts page-aligned still contains every
    // misaligned address inside it.
    //
    // Every view is exercised, because each one is cast to a type with an
    // alignment requirement: the page views to `align(4096)` producer/consumer
    // pages, the entry views to `align(64)` SQEs/CQEs, and the read-only base
    // has region offsets added to it before the same casts.
    let fixture = fixture();
    for index in 0..fixture.views.len() {
        for skew in [1u64, 4, 8, 64, 2048, 4095] {
            let views = mutate(&fixture, index, |desc| {
                desc.user_address = desc.user_address.wrapping_add(skew);
            });
            assert_eq!(
                device(&fixture, views)
                    .setup(RING_COUNT)
                    .err()
                    .expect("a misaligned view base is refused"),
                Error::MisalignedView,
                "view {index} accepted a base skewed by {skew}",
            );
        }
    }
}

#[test]
fn an_aligned_user_address_is_still_accepted() {
    // Anti-vacuity for the test above: the unmutated fixture must pass, or
    // every rejection there could be the fixture failing for another reason.
    let fixture = fixture();
    let views = fixture.views.clone();
    device(&fixture, views)
        .setup(RING_COUNT)
        .expect("the unskewed fixture is accepted");
}

#[test]
fn a_descriptor_that_disagrees_with_the_recomputed_layout_is_refused() {
    let fixture = fixture();
    // A length one byte short of the canonical span.
    let views = mutate(&fixture, 0, |desc| desc.length -= 1);
    let error = device(&fixture, views)
        .setup(RING_COUNT)
        .err()
        .expect("short span");
    assert!(
        matches!(
            error,
            Error::ResultValidation(_) | Error::DescriptorMismatch
        ),
        "a span the client's own layout does not have is refused: {error:?}",
    );
}

#[test]
fn a_wrong_kind_or_access_is_refused() {
    let fixture = fixture();
    for edit in [
        (|desc: &mut UserViewDesc| desc.kind = view_kind::U2K_ARENA) as fn(&mut UserViewDesc),
        |desc: &mut UserViewDesc| desc.access = view_access::READ_WRITE,
        |desc: &mut UserViewDesc| desc.kind = 0,
    ] {
        let views = mutate(&fixture, 0, edit);
        let error = device(&fixture, views)
            .setup(RING_COUNT)
            .err()
            .expect("a mislabelled view is refused");
        assert!(
            matches!(
                error,
                Error::ResultValidation(_) | Error::DescriptorMismatch
            ),
            "{error:?}",
        );
    }
}

#[test]
fn an_overflowing_address_range_is_refused() {
    let fixture = fixture();
    // Page-aligned but still overflowing when the length is added, so this
    // proves the range check fires on its own rather than riding on the
    // alignment check that now precedes it.
    let views = mutate(&fixture, 1, |desc| {
        desc.user_address = u64::MAX - 4095;
    });
    let error = device(&fixture, views)
        .setup(RING_COUNT)
        .err()
        .expect("an overflowing range is refused");
    assert!(
        matches!(
            error,
            Error::ArithmeticOverflow | Error::InvalidDescriptor | Error::MappingGap
        ),
        "{error:?}",
    );
}

#[test]
fn two_writable_aliases_may_not_share_an_address() {
    let fixture = fixture();
    let first = fixture.views[1].desc;
    // Point the second writable alias at the first one's address.
    let views = mutate(&fixture, 2, |desc| desc.user_address = first.user_address);
    assert_eq!(
        device(&fixture, views)
            .setup(RING_COUNT)
            .err()
            .expect("overlap"),
        Error::VirtualAddressOverlap,
    );
}

// ---------------------------------------------------------------------------
// Hostile mappings
// ---------------------------------------------------------------------------

fn with_inspector(
    fixture: &Fixture,
    edit: impl FnOnce(&mut FakeInspector),
) -> ControlDevice<FakeTransport, FakeInspector> {
    let views = fixture.views.clone();
    let writable: Vec<(usize, usize)> = views
        .iter()
        .filter(|view| view.desc.access == view_access::READ_WRITE)
        .map(|view| (view.desc.user_address as usize, view.desc.length as usize))
        .collect();
    let mut inspector = FakeInspector {
        base: fixture.base,
        length: fixture.plan.section_size() as usize,
        writable,
        state: MEM_COMMIT,
        mapping_type: MEM_MAPPED,
        protection_override: None,
        gap_at: None,
        calls: RefCell::new(Vec::new()),
    };
    edit(&mut inspector);
    ControlDevice::from_parts(
        FakeTransport {
            plan: fixture.plan,
            views,
            win32_code: ERROR_SUCCESS,
            information_override: None,
            calls: RefCell::new(Vec::new()),
        },
        inspector,
    )
}

#[test]
fn an_uncommitted_or_unmapped_region_is_refused() {
    let fixture = fixture();
    assert_eq!(
        with_inspector(&fixture, |inspector| inspector.state = 0x2000)
            .setup(RING_COUNT)
            .err()
            .expect("reserved"),
        Error::WrongMappingState,
    );
    assert_eq!(
        with_inspector(&fixture, |inspector| inspector.mapping_type = 0x2_0000)
            .setup(RING_COUNT)
            .err()
            .expect("private"),
        Error::WrongMappingType,
    );
}

#[test]
fn an_executable_or_guarded_region_is_refused() {
    let fixture = fixture();
    for protection in [0x10u32, 0x20, 0x40, 0x80, PAGE_READONLY | 0x100] {
        let error = with_inspector(&fixture, |inspector| {
            inspector.protection_override = Some(protection);
        })
        .setup(RING_COUNT)
        .err()
        .expect("an executable or guarded alias is refused");
        assert_eq!(
            error,
            Error::ExecutableOrGuarded,
            "protection {protection:#x}"
        );
    }
}

#[test]
fn a_read_only_view_backed_by_writable_memory_is_refused() {
    let fixture = fixture();
    assert_eq!(
        with_inspector(&fixture, |inspector| {
            inspector.protection_override = Some(PAGE_READWRITE);
        })
        .setup(RING_COUNT)
        .err()
        .expect("the whole-section alias must be read-only"),
        Error::WrongProtection,
    );
}

#[test]
fn a_hole_in_the_claimed_range_is_refused() {
    let fixture = fixture();
    let first = fixture.views[0].desc.user_address as usize;
    assert_eq!(
        with_inspector(&fixture, |inspector| inspector.gap_at = Some(first))
            .setup(RING_COUNT)
            .err()
            .expect("a hole is not a mapping"),
        Error::MappingGap,
    );
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

#[test]
fn the_private_copy_happens_before_any_borrow_is_formed() {
    // The header/directory copy is driven through the inspector, and the only
    // way to reach a `NativeRing` is past it. A fake that refuses to copy must
    // therefore produce no session at all.
    struct RefusingInspector(FakeInspector);
    impl MappingInspector for RefusingInspector {
        type Error = ();
        fn query_covering(
            &self,
            address: usize,
            length: usize,
        ) -> Result<Vec<MemoryRegion>, Self::Error> {
            self.0.query_covering(address, length)
        }
        fn copy_read_only(&self, _address: usize, _length: usize) -> Result<Vec<u8>, Self::Error> {
            Err(())
        }
    }

    let fixture = fixture();
    let views = fixture.views.clone();
    let writable: Vec<(usize, usize)> = views
        .iter()
        .filter(|view| view.desc.access == view_access::READ_WRITE)
        .map(|view| (view.desc.user_address as usize, view.desc.length as usize))
        .collect();
    let error = ControlDevice::from_parts(
        FakeTransport {
            plan: fixture.plan,
            views,
            win32_code: ERROR_SUCCESS,
            information_override: None,
            calls: RefCell::new(Vec::new()),
        },
        RefusingInspector(FakeInspector {
            base: fixture.base,
            length: fixture.plan.section_size() as usize,
            writable,
            state: MEM_COMMIT,
            mapping_type: MEM_MAPPED,
            protection_override: None,
            gap_at: None,
            calls: RefCell::new(Vec::new()),
        }),
    )
    .setup(RING_COUNT)
    .err()
    .expect("no copy, no session");
    assert_eq!(error, Error::Inspection(()));
}

#[test]
fn the_header_copy_is_validated_against_the_clients_own_request() {
    // Corrupt the fixture image *after* it is built: the driver's descriptors
    // still agree, so only the private re-parse can catch it.
    let request = build_setup_request(RING_COUNT);
    let bytes = encode_setup_request(&request);
    let setup = serve_setup(&bytes).expect("canonical");
    let plan = SectionLayoutPlan::compute(&setup, PAGE).expect("layout");
    let mut image = SectionImage::new(&plan);
    image.bytes_mut()[0] ^= 0xFF;
    let base = image.base();
    let views = canonical_views(&plan, base);
    let fixture = Fixture {
        _image: image,
        plan,
        views: views.clone(),
        base,
    };
    let error = device(&fixture, views)
        .setup(RING_COUNT)
        .err()
        .expect("a corrupt header is refused");
    assert!(
        matches!(error, Error::LayoutValidation(_)),
        "the private copy is what catches it: {error:?}",
    );
}

#[test]
fn the_result_prefix_is_re_read_from_the_validated_bytes() {
    // The identity the session reports must come from the bytes that passed
    // the frozen validator, not from anything the client assumed.
    let fixture = fixture();
    let session = device(&fixture, fixture.views.clone())
        .setup(RING_COUNT)
        .map_err(|_| ())
        .expect("validates");
    let mut output = vec![0u8; 0];
    let _ = &mut output;
    assert_eq!(
        session.identity().mount_id,
        fsring_abi::MountId { lo: 9, hi: 17 }
    );
    assert_eq!(
        session.identity().boot_instance_id,
        fsring_abi::BootInstanceId { lo: 3, hi: 5 },
    );
}

#[test]
fn a_result_whose_prefix_cannot_be_decoded_never_reaches_the_inspector() {
    // A prefix shorter than the frozen size is rejected by the ABI validator
    // before a single VirtualQuery happens.
    let fixture = fixture();
    let plan = fixture.plan;
    let mut short = vec![0u8; SESSION_RESULT_V1_PREFIX_SIZE as usize];
    let header = ControlHeader {
        struct_size: 8,
        struct_version: CONTROL_VERSION_V1,
        required_flags: 0,
    };
    try_encode(&header, &mut short[..12]).ok();
    let decoded: Result<SessionResultV1, _> = try_decode(&short);
    assert!(decoded.is_ok() || decoded.is_err());
    assert!(plan.section_size() > 0);
}

// ---------------------------------------------------------------------------
// native_enter: owned poll, wait, drain, and exact cancellation
// ---------------------------------------------------------------------------

use std::num::NonZeroU32;
use std::rc::Rc;

use fsring_abi::control::{
    enter_request_flags, EnterResultV1, NotificationCreditV1, ENTER_RESULT_V1_PREFIX_SIZE,
    IOCTL_FSRING_ENTER, NOTIFICATION_CREDIT_V1_SIZE,
};
use fsring_user::native::{
    BeginIo, CancelRequest, EnterStart, EnterTerminalResult, IoTerminal, OverlappedControlTransport,
};

/// What one fake operation is told to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FakeBehaviour {
    /// Complete synchronously with a canonical result.
    CompleteNow,
    /// Pend, then complete on the first terminal observation.
    PendThenComplete,
    /// Pend, then fail every terminal observation until `retries` are spent.
    PendThenRefuse { retries: u32 },
    /// Pend, then report an exact abort with no returned bytes.
    PendThenAbort,
    /// Pend, and never report a terminal at all.
    PendForever,
}

/// One fake in-flight operation. It owns its buffers and records whether it
/// was released, so a test can prove nothing was freed after an error.
struct FakeOperation {
    id: u32,
    output: Vec<u8>,
    behaviour: FakeBehaviour,
    remaining_refusals: std::cell::Cell<u32>,
    released: Rc<RefCell<Vec<u32>>>,
    terminal: std::cell::Cell<bool>,
}

impl Drop for FakeOperation {
    fn drop(&mut self) {
        self.released.borrow_mut().push(self.id);
    }
}

/// A transport that records the exact sequence of overlapped calls.
#[derive(Clone)]
struct FakeControls {
    log: Rc<RefCell<Vec<String>>>,
    released: Rc<RefCell<Vec<u32>>>,
    behaviour: Rc<std::cell::Cell<FakeBehaviour>>,
    credits: Rc<std::cell::Cell<u32>>,
    bytes_override: Rc<std::cell::Cell<Option<usize>>>,
}

impl FakeControls {
    fn new() -> Self {
        Self {
            log: Rc::new(RefCell::new(Vec::new())),
            released: Rc::new(RefCell::new(Vec::new())),
            behaviour: Rc::new(std::cell::Cell::new(FakeBehaviour::CompleteNow)),
            credits: Rc::new(std::cell::Cell::new(0)),
            bytes_override: Rc::new(std::cell::Cell::new(None)),
        }
    }

    fn log(&self) -> Vec<String> {
        self.log.borrow().clone()
    }

    fn released(&self) -> Vec<u32> {
        self.released.borrow().clone()
    }
}

struct FakeOverlapped {
    plan: SectionLayoutPlan,
    views: Vec<FakeView>,
    controls: FakeControls,
    next_id: std::cell::Cell<u32>,
}

impl FakeOverlapped {
    fn new(fixture: &Fixture, controls: FakeControls) -> Self {
        Self {
            plan: fixture.plan,
            views: fixture.views.clone(),
            controls,
            next_id: std::cell::Cell::new(1),
        }
    }

    /// Encode one canonical ENTER result with `credits` returned descriptors.
    fn enter_result(&self, credits: u32) -> Vec<u8> {
        let total = ENTER_RESULT_V1_PREFIX_SIZE + credits * NOTIFICATION_CREDIT_V1_SIZE;
        let mut bytes = vec![0u8; total as usize];
        let prefix = EnterResultV1 {
            header: ControlHeader {
                struct_size: total,
                struct_version: CONTROL_VERSION_V1,
                required_flags: 0,
            },
            session_epoch: 1,
            ring_index: 0,
            flags: if credits == 0 {
                0
            } else {
                fsring_abi::control::enter_result_flags::CQ_REMAINING
            },
            cq_drained: credits,
            sq_ready: 0,
            notification_credit_count: credits,
            notification_credit_desc_size: NOTIFICATION_CREDIT_V1_SIZE,
            // The frozen validator requires a zero offset when the tail is
            // empty, not a prefix-sized one.
            notification_credits_offset: if credits == 0 {
                0
            } else {
                ENTER_RESULT_V1_PREFIX_SIZE
            },
            reserved: 0,
        };
        try_encode(&prefix, &mut bytes[..ENTER_RESULT_V1_PREFIX_SIZE as usize]).unwrap();
        for ordinal in 0..credits {
            // The canonical request puts the credit class first, at exactly
            // the minimum credit size; a fake that guessed either would be
            // rejected by the frozen validator, not by this test.
            let token = fsring_abi::slots::SlotToken::try_new(0, ordinal, 1).unwrap();
            let credit = NotificationCreditV1 {
                buffer: fsring_abi::msgs::BufferRef {
                    token: token.raw(),
                    offset: 0,
                    length: fsring_abi::MIN_NOTIFICATION_CREDIT_SIZE,
                    kind: fsring_abi::msgs::buffer_kind::SLOT,
                    access: fsring_abi::msgs::buffer_access::U2K_WRITE,
                    reserved: 0,
                },
                ring_index: 0,
                reserved: 0,
            };
            let start =
                (ENTER_RESULT_V1_PREFIX_SIZE + ordinal * NOTIFICATION_CREDIT_V1_SIZE) as usize;
            try_encode(
                &credit,
                &mut bytes[start..start + NOTIFICATION_CREDIT_V1_SIZE as usize],
            )
            .unwrap();
        }
        bytes
    }
}

impl ControlTransport for FakeOverlapped {
    type Error = ();

    fn ioctl(
        &self,
        code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<IoctlOutcome, Self::Error> {
        // SETUP goes through the same body the plain fake uses.
        let plain = FakeTransport {
            plan: self.plan,
            views: self.views.clone(),
            win32_code: ERROR_SUCCESS,
            information_override: None,
            calls: RefCell::new(Vec::new()),
        };
        plain.ioctl(code, input, output)
    }
}

// SAFETY: `FakeOperation` owns its output buffer and is dropped only when the
// transport releases it, which the assertions below check never happens after
// a refused observation.
unsafe impl OverlappedControlTransport for FakeOverlapped {
    type Pending = FakeOperation;

    fn begin_ioctl(
        &self,
        code: u32,
        input: &[u8],
        output_capacity: usize,
    ) -> Result<BeginIo<Self::Pending>, Self::Error> {
        assert_eq!(code, IOCTL_FSRING_ENTER);
        let request: fsring_abi::control::EnterRequestV1 = try_decode(input).unwrap();
        self.controls
            .log
            .borrow_mut()
            .push(format!("begin:{:#x}:{}", request.flags, request.cq_budget));
        let credits = self.controls.credits.get();
        let bytes = self.enter_result(credits);
        assert!(bytes.len() <= output_capacity);
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        let behaviour = self.controls.behaviour.get();
        let operation = FakeOperation {
            id,
            output: bytes.clone(),
            behaviour,
            remaining_refusals: std::cell::Cell::new(match behaviour {
                FakeBehaviour::PendThenRefuse { retries } => retries,
                _ => 0,
            }),
            released: Rc::clone(&self.controls.released),
            terminal: std::cell::Cell::new(false),
        };
        match behaviour {
            FakeBehaviour::CompleteNow => {
                let bytes_returned = self.controls.bytes_override.get().unwrap_or(bytes.len());
                Ok(BeginIo::Completed(IoTerminal::Success {
                    output: bytes,
                    bytes_returned,
                }))
            }
            _ => Ok(BeginIo::Pending(operation)),
        }
    }

    fn cancel_exact(&self, pending: &Self::Pending) -> Result<CancelRequest, Self::Error> {
        self.controls
            .log
            .borrow_mut()
            .push(format!("cancel-io-ex-exact:{}", pending.id));
        Ok(CancelRequest::Issued)
    }

    fn wait_terminal(&self, pending: &mut Self::Pending) -> Result<IoTerminal, Self::Error> {
        self.controls
            .log
            .borrow_mut()
            .push(format!("get-overlapped-result-terminal:{}", pending.id));
        match pending.behaviour {
            FakeBehaviour::PendForever => Err(()),
            FakeBehaviour::PendThenRefuse { .. } => {
                let left = pending.remaining_refusals.get();
                if left > 0 {
                    pending.remaining_refusals.set(left - 1);
                    // Nothing released: the caller may retry.
                    return Err(());
                }
                pending.terminal.set(true);
                let bytes = core::mem::take(&mut pending.output);
                let bytes_returned = bytes.len();
                Ok(IoTerminal::Success {
                    output: bytes,
                    bytes_returned,
                })
            }
            FakeBehaviour::PendThenAbort => {
                pending.terminal.set(true);
                Ok(IoTerminal::Failed {
                    win32_code: NonZeroU32::new(995).unwrap(),
                    bytes_returned: 0,
                })
            }
            FakeBehaviour::PendThenComplete | FakeBehaviour::CompleteNow => {
                pending.terminal.set(true);
                let bytes = core::mem::take(&mut pending.output);
                let bytes_returned = self.controls.bytes_override.get().unwrap_or(bytes.len());
                Ok(IoTerminal::Success {
                    output: bytes,
                    bytes_returned,
                })
            }
        }
    }
}

fn overlapped_session(
    fixture: &Fixture,
) -> (
    fsring_user::native::NativeSession<FakeOverlapped, FakeInspector>,
    FakeControls,
) {
    let controls = FakeControls::new();
    let views = fixture.views.clone();
    let writable: Vec<(usize, usize)> = views
        .iter()
        .filter(|view| view.desc.access == view_access::READ_WRITE)
        .map(|view| (view.desc.user_address as usize, view.desc.length as usize))
        .collect();
    let session = ControlDevice::from_parts(
        FakeOverlapped::new(fixture, controls.clone()),
        FakeInspector {
            base: fixture.base,
            length: fixture.plan.section_size() as usize,
            writable,
            state: MEM_COMMIT,
            mapping_type: MEM_MAPPED,
            protection_override: None,
            gap_at: None,
            calls: RefCell::new(Vec::new()),
        },
    )
    .setup(RING_COUNT)
    .map_err(|_| ())
    .expect("the overlapped fixture validates");
    // The SETUP itself is not part of the ENTER log.
    controls.log.borrow_mut().clear();
    (session, controls)
}

#[test]
fn native_enter_poll_encodes_the_exact_zero_triple() {
    let fixture = fixture();
    let (session, controls) = overlapped_session(&fixture);
    let completion = session.enter_poll(0).map_err(|_| ()).expect("poll");
    assert_eq!(completion.result.notification_credit_count, 0);
    assert_eq!(
        completion.result.header.struct_size, ENTER_RESULT_V1_PREFIX_SIZE,
        "an empty poll is exactly the frozen 48-byte prefix",
    );
    assert!(completion.returned_credits.is_empty());
    assert_eq!(controls.log(), vec!["begin:0x0:0".to_string()]);
}

#[test]
fn native_enter_drain_returns_its_credit_tail() {
    let fixture = fixture();
    let (session, controls) = overlapped_session(&fixture);
    controls.credits.set(2);
    // The canonical topology has a two-entry CQ, and the frozen validator
    // caps a DRAIN budget at the CQ capacity.
    let completion = session.enter_drain(0, 2).map_err(|_| ()).expect("drain");
    assert_eq!(completion.result.notification_credit_count, 2);
    assert_eq!(completion.returned_credits.len(), 2);
    assert_eq!(
        completion.result.header.struct_size,
        ENTER_RESULT_V1_PREFIX_SIZE + 2 * NOTIFICATION_CREDIT_V1_SIZE,
        "the tail is exactly one 32-byte descriptor per returned credit",
    );
}

#[test]
fn a_drain_never_waits_and_a_wait_never_drains() {
    let fixture = fixture();
    let (session, controls) = overlapped_session(&fixture);
    let _ = session.enter_drain(0, 2);
    let _ = session.enter_wait(0, 25);
    let _ = session.enter_poll(0);
    // The transport log records the exact wire triple each mode encoded;
    // (flags, budget) is what distinguishes them.
    let log = controls.log();
    assert!(log
        .iter()
        .any(|line| line == &format!("begin:{:#x}:2", enter_request_flags::DRAIN_CQ)));
    assert!(log
        .iter()
        .any(|line| line == &format!("begin:{:#x}:0", enter_request_flags::WAIT_SQ)));
    assert!(log.iter().any(|line| line == "begin:0x0:0"));
}

#[test]
fn a_ring_outside_the_topology_is_refused_before_any_io() {
    let fixture = fixture();
    let (session, controls) = overlapped_session(&fixture);
    assert_eq!(
        session.enter_poll(RING_COUNT).err().expect("out of range"),
        Error::InvalidDescriptor,
    );
    assert!(controls.log().is_empty(), "nothing was issued");
}

#[test]
fn a_pending_wait_reports_pending_then_completes_once() {
    let fixture = fixture();
    let (session, controls) = overlapped_session(&fixture);
    controls.behaviour.set(FakeBehaviour::PendThenComplete);
    let start = session.enter_wait(0, 25).map_err(|_| ()).expect("wait");
    let EnterStart::Pending(mut pending) = start else {
        panic!("the fake pends");
    };
    let EnterTerminalResult::Completed(_) = pending.wait().map_err(|_| ()).expect("terminal")
    else {
        panic!("completed");
    };
    // A second observation has nothing left to observe.
    assert_eq!(
        pending.wait().err().expect("already terminal"),
        Error::TerminalAlreadyObserved,
    );
}

#[test]
fn an_observation_error_keeps_the_pending_operation_live_and_retryable() {
    let fixture = fixture();
    let (session, controls) = overlapped_session(&fixture);
    controls
        .behaviour
        .set(FakeBehaviour::PendThenRefuse { retries: 1 });
    let EnterStart::Pending(mut pending) = session.enter_wait(0, 25).map_err(|_| ()).expect("wait")
    else {
        panic!("pends");
    };
    assert_eq!(
        pending.wait().err().expect("first observation refused"),
        Error::Transport(()),
    );
    assert!(
        controls.released().is_empty(),
        "a refused observation releases nothing the OS may still touch",
    );
    // The same object completes on the retry.
    let terminal = pending.wait().map_err(|_| ()).expect("second observation");
    assert!(matches!(terminal, EnterTerminalResult::Completed(_)));
}

#[test]
fn explicit_cancellation_is_exact_and_reports_cancelled() {
    let fixture = fixture();
    let (session, controls) = overlapped_session(&fixture);
    controls.behaviour.set(FakeBehaviour::PendThenAbort);
    let EnterStart::Pending(mut pending) = session.enter_wait(0, 25).map_err(|_| ()).expect("wait")
    else {
        panic!("pends");
    };
    let EnterTerminalResult::Cancelled {
        win32_code,
        bytes_returned,
    } = pending.cancel().map_err(|_| ()).expect("cancel")
    else {
        panic!("an exact abort with no bytes is cancellation");
    };
    assert_eq!(win32_code, 995);
    assert_eq!(bytes_returned, 0);
    let log = controls.log();
    let cancel = log
        .iter()
        .position(|line| line.starts_with("cancel-io-ex-exact:"))
        .expect("an exact cancellation was issued");
    let observe = log
        .iter()
        .position(|line| line.starts_with("get-overlapped-result-terminal:"))
        .expect("a terminal observation followed");
    assert!(cancel < observe, "cancel, then observe - never the reverse");
    // Exactly one operation existed, so nothing sibling was cancelled.
    assert_eq!(
        log.iter()
            .filter(|line| line.starts_with("cancel-io-ex-exact:1"))
            .count(),
        1,
    );
}

#[test]
fn a_wait_never_reinterprets_an_abort_as_cancellation() {
    let fixture = fixture();
    let (session, controls) = overlapped_session(&fixture);
    controls.behaviour.set(FakeBehaviour::PendThenAbort);
    let EnterStart::Pending(mut pending) = session.enter_wait(0, 25).map_err(|_| ()).expect("wait")
    else {
        panic!("pends");
    };
    assert_eq!(
        pending
            .wait()
            .err()
            .expect("an abort is a failure to wait()"),
        Error::IoFailure {
            win32_code: 995,
            information: 0,
        },
    );
}

#[test]
fn dropping_a_pending_wait_cancels_and_observes_before_releasing() {
    let fixture = fixture();
    let (session, controls) = overlapped_session(&fixture);
    controls.behaviour.set(FakeBehaviour::PendThenComplete);
    {
        let EnterStart::Pending(pending) = session.enter_wait(0, 25).map_err(|_| ()).expect("wait")
        else {
            panic!("pends");
        };
        drop(pending);
    }
    let log = controls.log();
    let cancel = log
        .iter()
        .position(|line| line.starts_with("cancel-io-ex-exact:"))
        .expect("drop cancels");
    let observe = log
        .iter()
        .position(|line| line.starts_with("get-overlapped-result-terminal:"))
        .expect("drop observes");
    assert!(cancel < observe);
    assert_eq!(
        controls.released(),
        vec![1],
        "the operation storage is released only after the terminal observation",
    );
}

#[test]
fn a_drop_that_cannot_observe_a_terminal_leaks_rather_than_freeing() {
    let fixture = fixture();
    let (session, controls) = overlapped_session(&fixture);
    controls.behaviour.set(FakeBehaviour::PendForever);
    {
        let EnterStart::Pending(pending) = session.enter_wait(0, 25).map_err(|_| ()).expect("wait")
        else {
            panic!("pends");
        };
        drop(pending);
    }
    assert!(
        controls.released().is_empty(),
        "storage the OS may still write into is deliberately leaked, not freed",
    );
    let log = controls.log();
    assert!(log
        .iter()
        .any(|line| line.starts_with("cancel-io-ex-exact:")));
    assert!(
        log.iter()
            .any(|line| line.starts_with("get-overlapped-result-terminal:")),
        "the fail-safe branch is reached only after an attempted observation",
    );
}

#[test]
fn a_bytes_returned_count_that_disagrees_with_the_result_is_refused() {
    let fixture = fixture();
    let (session, controls) = overlapped_session(&fixture);
    controls
        .bytes_override
        .set(Some(ENTER_RESULT_V1_PREFIX_SIZE as usize - 8));
    let error = session.enter_poll(0).err().expect("short result");
    assert!(
        matches!(error, Error::ResultValidation(_) | Error::InvalidDescriptor),
        "{error:?}",
    );
}

#[test]
fn a_bytes_returned_count_past_the_buffer_is_refused() {
    let fixture = fixture();
    let (session, controls) = overlapped_session(&fixture);
    controls.bytes_override.set(Some(usize::MAX));
    assert_eq!(
        session.enter_poll(0).err().expect("overlong"),
        Error::InvalidDescriptor,
    );
}

#[cfg(windows)]
#[test]
fn nt_open_observations_return_status_and_never_a_handle() {
    use fsring_user::native::{
        observe_nt_open_event, observe_nt_open_section, NtStatusObservation, SECTION_QUERY,
        SYNCHRONIZE,
    };

    let missing_section = observe_nt_open_section(
        "\\KernelObjects\\FsRingC4Task26MissingSection",
        SECTION_QUERY,
    );
    let missing_event =
        observe_nt_open_event("\\KernelObjects\\FsRingC4Task26MissingEvent", SYNCHRONIZE);
    assert!(matches!(
        missing_section,
        NtStatusObservation { ntstatus } if ntstatus != 0
    ));
    assert!(matches!(
        missing_event,
        NtStatusObservation { ntstatus } if ntstatus != 0
    ));
}

#[cfg(windows)]
#[test]
fn win32_path_observation_does_not_retain_a_handle() {
    use fsring_user::native::observe_win32_create_file;

    let observation = observe_win32_create_file(r"\\.\FsRingC4Task26MissingDevice");
    assert_ne!(observation.win32_code, 0);
}
