use super::*;
use fsring_abi::control::BOOT_CONTEXT_SECTION_BYTES;

fn must_ok<T, E: core::fmt::Debug>(result: Result<T, E>, message: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{message}: {error:?}"),
    }
}

fn must_err<T, E>(result: Result<T, E>, message: &str) -> E {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

// ---------------------------------------------------------------------------
// Normative payloads: `02-transport.md` section 10.10 and `10-lifecycle.md`
// section 3. Each expectation below is written from the document, not from the
// module, so a changed constant fails here rather than silently redefining the
// contract.
// ---------------------------------------------------------------------------

#[test]
fn the_two_permanent_object_names_are_exact() {
    let lock: Vec<u16> = "\\KernelObjects\\FsRingBootContextLock-v1"
        .encode_utf16()
        .collect();
    let section: Vec<u16> = "\\KernelObjects\\FsRingBootContext-v1"
        .encode_utf16()
        .collect();

    assert_eq!(BOOT_CONTEXT_LOCK_OBJECT_NAME.as_slice(), lock.as_slice());
    assert_eq!(
        BOOT_CONTEXT_SECTION_OBJECT_NAME.as_slice(),
        section.as_slice()
    );
    // A UNICODE_STRING is counted, so an embedded or trailing NUL would make
    // the declared length disagree with the name the Object Manager sees.
    assert!(!BOOT_CONTEXT_LOCK_OBJECT_NAME.contains(&0));
    assert!(!BOOT_CONTEXT_SECTION_OBJECT_NAME.contains(&0));
}

#[test]
fn both_permanent_objects_use_kernel_permanent_case_insensitive_attributes() {
    assert_eq!(BOOT_OBJECT_ATTRIBUTES, 0x0000_0250);
    assert_eq!(
        BOOT_OBJECT_ATTRIBUTES,
        OBJ_KERNEL_HANDLE | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE
    );
    assert_eq!(
        BOOT_OBJECT_ATTRIBUTES & OBJ_OPENIF,
        0,
        "OBJ_OPENIF is forbidden: it would collapse the open/create/reopen \
         status protocol into a silent create"
    );
}

#[test]
fn the_lock_event_access_mask_is_exactly_the_documented_value() {
    assert_eq!(BOOT_LOCK_EVENT_ACCESS, 0x0013_0003);
}

#[test]
fn the_section_access_mask_is_exact_and_never_executable() {
    assert_eq!(BOOT_SECTION_ACCESS, 0x0003_0007);
    assert_eq!(BOOT_SECTION_ACCESS & SECTION_MAP_EXECUTE, 0);
    assert_eq!(BOOT_SECTION_ACCESS & SECTION_MAP_EXECUTE_EXPLICIT, 0);
}

#[test]
fn neither_boot_handle_mask_requests_access_system_security() {
    assert_eq!(BOOT_LOCK_EVENT_ACCESS & ACCESS_SYSTEM_SECURITY, 0);
    assert_eq!(BOOT_SECTION_ACCESS & ACCESS_SYSTEM_SECURITY, 0);
    assert_eq!(
        BOOT_LOCK_EVENT_CREATE.desired_access,
        BOOT_LOCK_EVENT_ACCESS
    );
    assert_eq!(BOOT_SECTION_CREATE.desired_access, BOOT_SECTION_ACCESS);
}

#[test]
fn the_lock_object_is_a_synchronization_event_created_signaled() {
    // The complete `ZwCreateEvent` payload as one literal from the document,
    // so an added, dropped, or silently retyped field fails here.
    assert_eq!(
        BOOT_LOCK_EVENT_CREATE,
        BootLockEventCreateParameters {
            desired_access: 0x0013_0003,
            object_attributes: 0x0000_0250,
            event_type: SYNCHRONIZATION_EVENT,
            initial_state: true,
        }
    );
    assert_eq!(SYNCHRONIZATION_EVENT, 1);
    assert_eq!(NOTIFICATION_EVENT, 0);
    assert_ne!(SYNCHRONIZATION_EVENT, NOTIFICATION_EVENT);
}

#[test]
fn the_bounded_wait_is_kernel_mode_non_alertable_with_a_fixed_30_second_timeout() {
    assert_eq!(
        BOOT_LOCK_WAIT,
        BootLockWaitParameters {
            wait_reason: WAIT_REASON_EXECUTIVE,
            processor_mode: KERNEL_MODE,
            alertable: false,
            // Negative 100-nanosecond units are a *relative* deadline:
            // 30 s = 3e8 units. A positive value would be an absolute time in
            // 1601 and would expire instantly.
            relative_timeout_100ns: -300_000_000,
        }
    );
    assert_eq!(KERNEL_MODE, 0);
    assert_eq!(WAIT_REASON_EXECUTIVE, 0);
}

#[test]
fn a_new_section_is_pagefile_backed_commit_readwrite_and_exactly_64_kib() {
    assert_eq!(BOOT_CONTEXT_SECTION_BYTES, 65_536);
    assert_eq!(
        BOOT_SECTION_CREATE,
        BootSectionCreateParameters {
            desired_access: 0x0003_0007,
            object_attributes: 0x0000_0250,
            maximum_size: u64::from(BOOT_CONTEXT_SECTION_BYTES),
            page_protection: PAGE_READWRITE,
            allocation_attributes: SEC_COMMIT,
            file_handle_is_null: true,
        }
    );
    assert_eq!(SEC_COMMIT, 0x0800_0000);
    assert_eq!(PAGE_READWRITE, 0x0000_0004);
}

#[test]
fn release_sets_the_event_once_with_io_no_increment_and_no_wait() {
    assert_eq!(
        BOOT_LOCK_RELEASE,
        BootLockReleaseParameters {
            priority_increment: IO_NO_INCREMENT,
            wait: false,
        }
    );
    assert_eq!(IO_NO_INCREMENT, 0);
}

// ---------------------------------------------------------------------------
// Open / create / reopen status protocol
// ---------------------------------------------------------------------------

const UNRELATED_STATUSES: [i32; 5] = [
    0x0000_0102,            // STATUS_TIMEOUT
    0xC000_0022_u32 as i32, // STATUS_ACCESS_DENIED
    0xC000_0033_u32 as i32, // STATUS_OBJECT_NAME_INVALID, a near neighbour
    0xC000_009A_u32 as i32, // STATUS_INSUFFICIENT_RESOURCES
    0xC000_0024_u32 as i32, // STATUS_OBJECT_TYPE_MISMATCH
];

#[test]
fn open_creates_only_after_object_name_not_found() {
    assert_eq!(decide_open(STATUS_SUCCESS), OpenDecision::Opened);
    assert_eq!(
        decide_open(STATUS_OBJECT_NAME_NOT_FOUND),
        OpenDecision::Create
    );
    assert_eq!(
        decide_open(STATUS_OBJECT_NAME_COLLISION),
        OpenDecision::Fail,
        "a collision from an open is not a create trigger"
    );
    for status in UNRELATED_STATUSES {
        assert_eq!(
            decide_open(status),
            OpenDecision::Fail,
            "status {status:#010x} must fail the load unchanged"
        );
    }
}

#[test]
fn create_reopens_only_after_object_name_collision() {
    assert_eq!(decide_create(STATUS_SUCCESS), CreateDecision::Created);
    assert_eq!(
        decide_create(STATUS_OBJECT_NAME_COLLISION),
        CreateDecision::Reopen
    );
    assert_eq!(
        decide_create(STATUS_OBJECT_NAME_NOT_FOUND),
        CreateDecision::Fail
    );
    for status in UNRELATED_STATUSES {
        assert_eq!(decide_create(status), CreateDecision::Fail);
    }
}

#[test]
fn a_reopen_accepts_only_success() {
    assert_eq!(decide_reopen(STATUS_SUCCESS), ReopenDecision::Opened);
    assert_eq!(
        decide_reopen(STATUS_OBJECT_NAME_NOT_FOUND),
        ReopenDecision::Fail,
        "the object vanished between the collision and the reopen"
    );
    assert_eq!(
        decide_reopen(STATUS_OBJECT_NAME_COLLISION),
        ReopenDecision::Fail
    );
    for status in UNRELATED_STATUSES {
        assert_eq!(decide_reopen(status), ReopenDecision::Fail);
    }
}

#[test]
fn an_informational_nonzero_success_is_not_an_exact_success() {
    // `NT_SUCCESS` accepts every status with a clear sign bit. The BootContext
    // protocol accepts only exact STATUS_SUCCESS, so STATUS_PENDING and
    // friends must not open, create, or acquire anything.
    for status in [0x0000_0103_i32, 0x0000_0102_i32, 0x4000_0000_i32] {
        assert_eq!(decide_open(status), OpenDecision::Fail);
        assert_eq!(decide_create(status), CreateDecision::Fail);
        assert_eq!(decide_reopen(status), ReopenDecision::Fail);
        assert!(!wait_is_acquired(status, 0));
    }
}

// ---------------------------------------------------------------------------
// Object security and section geometry
// ---------------------------------------------------------------------------

#[test]
fn the_canonical_boot_descriptor_is_accepted() {
    assert!(boot_object_security_is_canonical(
        CANONICAL_BOOT_OBJECT_SECURITY
    ));
    assert_eq!(CANONICAL_BOOT_OBJECT_SECURITY.dacl_size, ACL_HEADER_BYTES);
    assert_eq!(ACL_HEADER_BYTES, 8);
}

#[test]
fn every_single_deviation_from_the_canonical_descriptor_is_rejected() {
    let base = CANONICAL_BOOT_OBJECT_SECURITY;
    let mutants: [(&str, BootObjectSecurity); 8] = [
        (
            "owner is not LocalSystem",
            BootObjectSecurity {
                owner_is_local_system: false,
                ..base
            },
        ),
        (
            "group is not LocalSystem",
            BootObjectSecurity {
                group_is_local_system: false,
                ..base
            },
        ),
        (
            "no DACL is present",
            BootObjectSecurity {
                dacl_present: false,
                ..base
            },
        ),
        (
            "a null DACL grants everyone",
            BootObjectSecurity {
                dacl_null: true,
                ..base
            },
        ),
        (
            "an unprotected DACL can inherit an ACE",
            BootObjectSecurity {
                dacl_protected: false,
                ..base
            },
        ),
        (
            "an ACE grants some principal access",
            BootObjectSecurity {
                dacl_ace_count: 1,
                ..base
            },
        ),
        (
            "a longer ACL carries hidden ACE bytes",
            BootObjectSecurity {
                dacl_size: ACL_HEADER_BYTES + 1,
                ..base
            },
        ),
        (
            "a SACL is present",
            BootObjectSecurity {
                sacl_present: true,
                ..base
            },
        ),
    ];

    for (why, facts) in mutants {
        assert!(
            !boot_object_security_is_canonical(facts),
            "must reject a descriptor where {why}"
        );
    }
}

#[test]
fn the_canonical_descriptor_bytes_parse_back_to_the_canonical_facts() {
    // The bytes both permanent objects are *created* with must be exactly the
    // ones the post-create validation *accepts*. Building and checking from two
    // unrelated constants is how an object ends up rejecting itself.
    let parsed = match parse_boot_object_security(&CANONICAL_BOOT_SECURITY_DESCRIPTOR) {
        Some(parsed) => parsed,
        None => panic!("the canonical descriptor must parse"),
    };
    assert_eq!(parsed, CANONICAL_BOOT_OBJECT_SECURITY);
    assert!(boot_object_security_is_canonical(parsed));
}

#[test]
fn the_canonical_descriptor_is_self_relative_and_names_local_system() {
    // Offsets and SIDs read straight from the byte image, so a mis-sized field
    // or a wrong authority byte cannot hide behind the parser.
    assert_eq!(CANONICAL_BOOT_SECURITY_DESCRIPTOR.len(), 52);
    assert_eq!(CANONICAL_BOOT_SECURITY_DESCRIPTOR.first(), Some(&1u8));
    let control = u16::from_le_bytes([
        CANONICAL_BOOT_SECURITY_DESCRIPTOR[2],
        CANONICAL_BOOT_SECURITY_DESCRIPTOR[3],
    ]);
    // SE_SELF_RELATIVE | SE_DACL_PROTECTED | SE_DACL_PRESENT.
    assert_eq!(control, 0x8000 | 0x1000 | 0x0004);
    // S-1-5-18 twice: revision 1, one subauthority, NT authority, 18.
    let local_system = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    assert_eq!(&CANONICAL_BOOT_SECURITY_DESCRIPTOR[20..32], &local_system);
    assert_eq!(&CANONICAL_BOOT_SECURITY_DESCRIPTOR[32..44], &local_system);
    // A protected empty DACL is exactly its 8-byte header.
    assert_eq!(
        &CANONICAL_BOOT_SECURITY_DESCRIPTOR[44..52],
        &[2u8, 0, 8, 0, 0, 0, 0, 0]
    );
}

#[test]
fn a_hostile_descriptor_image_is_rejected_rather_than_misread() {
    // Truncation, an out-of-range offset, and a lying ACL size must all fail
    // closed: this parser runs on bytes the Object Manager owns.
    assert_eq!(parse_boot_object_security(&[]), None);
    for len in 0..CANONICAL_BOOT_SECURITY_DESCRIPTOR.len() {
        let truncated = match CANONICAL_BOOT_SECURITY_DESCRIPTOR.get(..len) {
            Some(truncated) => truncated,
            None => panic!("{len} is within the canonical descriptor"),
        };
        assert_eq!(
            parse_boot_object_security(truncated),
            None,
            "a {len}-byte descriptor must not parse"
        );
    }

    let mut far_owner = CANONICAL_BOOT_SECURITY_DESCRIPTOR;
    far_owner[4] = 200;
    assert_eq!(parse_boot_object_security(&far_owner), None);

    let mut far_dacl = CANONICAL_BOOT_SECURITY_DESCRIPTOR;
    far_dacl[16] = 200;
    assert_eq!(parse_boot_object_security(&far_dacl), None);

    // A wrong revision is not this format at all.
    let mut wrong_revision = CANONICAL_BOOT_SECURITY_DESCRIPTOR;
    wrong_revision[0] = 2;
    assert_eq!(parse_boot_object_security(&wrong_revision), None);

    // Not self-relative: the offsets would be pointers, not offsets.
    let mut absolute = CANONICAL_BOOT_SECURITY_DESCRIPTOR;
    absolute[3] = 0x10;
    assert_eq!(parse_boot_object_security(&absolute), None);
}

#[test]
fn a_descriptor_that_grants_access_parses_but_fails_the_contract() {
    // The parser reports facts; the closed predicate decides. A foreign
    // descriptor that is structurally valid must still be refused.
    // ACL header: [44] revision, [45] Sbz1, [46..48] AclSize, [48..50] AceCount.
    let mut with_ace = CANONICAL_BOOT_SECURITY_DESCRIPTOR;
    with_ace[48] = 1; // AceCount = 1 while AclSize still claims an empty ACL
    let parsed = match parse_boot_object_security(&with_ace) {
        Some(parsed) => parsed,
        None => panic!("a structurally valid descriptor must still parse"),
    };
    assert_eq!(parsed.dacl_ace_count, 1);
    assert!(!boot_object_security_is_canonical(parsed));

    let mut everyone = CANONICAL_BOOT_SECURITY_DESCRIPTOR;
    everyone[16] = 0; // a null DACL grants everyone while still "present"
    everyone[17] = 0;
    everyone[18] = 0;
    everyone[19] = 0;
    let parsed = match parse_boot_object_security(&everyone) {
        Some(parsed) => parsed,
        None => panic!("a null-DACL descriptor is well formed"),
    };
    assert!(parsed.dacl_null);
    assert!(!boot_object_security_is_canonical(parsed));

    let mut foreign_owner = CANONICAL_BOOT_SECURITY_DESCRIPTOR;
    foreign_owner[28] = 32; // S-1-5-32 (BUILTIN) instead of S-1-5-18
    let parsed = match parse_boot_object_security(&foreign_owner) {
        Some(parsed) => parsed,
        None => panic!("a foreign-owner descriptor is well formed"),
    };
    assert!(!parsed.owner_is_local_system);
    assert!(!boot_object_security_is_canonical(parsed));
}

#[test]
fn an_existing_section_must_be_exactly_64_kib_and_sec_commit() {
    let canonical = SectionBasicFacts {
        maximum_size: u64::from(BOOT_CONTEXT_SECTION_BYTES),
        allocation_attributes: SEC_COMMIT,
    };
    assert!(existing_section_is_canonical(canonical));

    for facts in [
        SectionBasicFacts {
            maximum_size: u64::from(BOOT_CONTEXT_SECTION_BYTES) - 1,
            ..canonical
        },
        SectionBasicFacts {
            maximum_size: u64::from(BOOT_CONTEXT_SECTION_BYTES) + 1,
            ..canonical
        },
        SectionBasicFacts {
            maximum_size: 0,
            ..canonical
        },
        SectionBasicFacts {
            allocation_attributes: 0,
            ..canonical
        },
        SectionBasicFacts {
            // SEC_IMAGE / SEC_RESERVE alongside SEC_COMMIT is still not exact.
            allocation_attributes: SEC_COMMIT | 0x0100_0000,
            ..canonical
        },
    ] {
        assert!(
            !existing_section_is_canonical(facts),
            "must reject {facts:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The affine boot lock-event protocol
// ---------------------------------------------------------------------------

const STATUS_TIMEOUT: i32 = 0x0000_0102;
const STATUS_ALERTED: i32 = 0x0000_0101;

fn acquired(cell: &mut BootLockCell) -> BootLockGuard {
    let region = must_ok(cell.enter(), "a free cell enters its critical region");
    match cell.finish_wait(region, STATUS_SUCCESS, 0) {
        BootLockAcquisition::Acquired(guard) => guard,
        BootLockAcquisition::Rejected(_) => panic!("an exact success with a zero state acquires"),
    }
}

#[test]
fn a_successful_wait_with_a_zero_state_yields_one_guard() {
    let mut cell = BootLockCell::new();
    assert!(!cell.is_held());
    let guard = acquired(&mut cell);
    assert!(cell.is_held());

    let release = cell.release(guard, 0);
    assert_eq!(release.violation(), None);
    release.leave();
    assert!(!cell.is_held());
}

#[test]
fn a_failed_or_timed_out_wait_leaves_the_region_without_the_event() {
    for status in [
        STATUS_TIMEOUT,
        STATUS_ALERTED,
        0xC000_0022_u32 as i32,
        0xC000_009A_u32 as i32,
    ] {
        let mut cell = BootLockCell::new();
        let region = must_ok(cell.enter(), "a free cell enters");
        match cell.finish_wait(region, status, 0) {
            BootLockAcquisition::Acquired(_) => {
                panic!("status {status:#010x} must not acquire the lock")
            }
            // Consuming the returned region is the only way to spend it: the
            // rejection path therefore cannot set the event, and cannot forget
            // to leave the critical region either.
            BootLockAcquisition::Rejected(region) => leave_critical_region(region),
        }
        assert!(
            !cell.is_held(),
            "status {status:#010x} must leave no ownership behind"
        );
    }
}

#[test]
fn a_same_name_notification_event_is_rejected_without_claiming_ownership() {
    // A NotificationEvent stays signaled after a satisfied wait. Exactly that
    // nonzero post-wait state is the rejection signal.
    for state_after_wait in [1u32, 2, u32::MAX] {
        let mut cell = BootLockCell::new();
        let region = must_ok(cell.enter(), "a free cell enters");
        match cell.finish_wait(region, STATUS_SUCCESS, state_after_wait) {
            BootLockAcquisition::Acquired(_) => {
                panic!("post-wait state {state_after_wait} must reject the subtype")
            }
            BootLockAcquisition::Rejected(region) => leave_critical_region(region),
        }
        assert!(!cell.is_held());
        assert!(!wait_is_acquired(STATUS_SUCCESS, state_after_wait));
    }
}

#[test]
fn releasing_requires_a_zero_prior_state_and_always_returns_the_region() {
    let mut cell = BootLockCell::new();
    let guard = acquired(&mut cell);

    // A nonzero prior state means somebody else already set the event while
    // this guard claimed exclusive ownership. That is a protocol violation,
    // but the critical region must still be left exactly once.
    let release = cell.release(guard, 1);
    assert_eq!(
        release.violation(),
        Some(AdapterPlanError::InvalidTransition)
    );
    release.leave();
    assert!(!cell.is_held());
}

#[test]
fn recursive_acquisition_is_rejected() {
    let mut cell = BootLockCell::new();
    let guard = acquired(&mut cell);

    assert_eq!(
        must_err(cell.enter(), "a held cell must refuse a second entry"),
        AdapterPlanError::InvalidTransition
    );

    cell.release(guard, 0).leave();
    // And the refusal is state, not a one-way latch: a clean release makes the
    // cell usable by the next BootContext writer.
    let second = acquired(&mut cell);
    cell.release(second, 0).leave();
}

// ---------------------------------------------------------------------------
// Load choreography
// ---------------------------------------------------------------------------

/// The successful trace, transcribed from the slice plan. Written as a literal
/// so a reordered `LOAD_EFFECTS` fails here.
const EXPECTED_LOAD_TRACE: [LoadEffect; 15] = [
    LoadEffect::OpenAndAcquireBootLockEvent,
    LoadEffect::OpenOrCreateBootSection,
    LoadEffect::MapSystemView,
    LoadEffect::ValidateOrInitialize,
    LoadEffect::PublishLoadGeneration,
    LoadEffect::ReleaseBootLockEvent,
    LoadEffect::RegisterEtw,
    LoadEffect::AllocateDriverState,
    LoadEffect::RegisterProcessNotify,
    LoadEffect::CreateProviderSecure,
    LoadEffect::CreateFscontrolSecure,
    LoadEffect::CreateProviderDosLink,
    LoadEffect::PublishProvider,
    LoadEffect::PublishFscontrol,
    LoadEffect::RegisterFilesystem,
];

#[derive(Clone, Copy, Debug)]
struct BootShape {
    lock: ObjectDisposition,
    section: ObjectDisposition,
    validation: BootValidation,
    origin: BootOrigin,
}

const EXISTING_CONTEXT: BootShape = BootShape {
    lock: ObjectDisposition::OpenedExisting,
    section: ObjectDisposition::OpenedExisting,
    validation: BootValidation::ExistingReady,
    origin: BootOrigin::ExistingReady,
};

const CREATED_CONTEXT: BootShape = BootShape {
    lock: ObjectDisposition::CreatedNew,
    section: ObjectDisposition::CreatedNew,
    validation: BootValidation::NewPrepared,
    origin: BootOrigin::NewlyInitializedReady,
};

const REOPENED_CONTEXT: BootShape = BootShape {
    lock: ObjectDisposition::ReopenedAfterCollision,
    section: ObjectDisposition::ReopenedAfterCollision,
    validation: BootValidation::NewPrepared,
    origin: BootOrigin::NewlyInitializedReady,
};

/// An existing but never-initialized section: opened, not created here, and
/// still driven through EMPTY -> INITIALIZING -> READY.
const EXISTING_EMPTY_CONTEXT: BootShape = BootShape {
    lock: ObjectDisposition::OpenedExisting,
    section: ObjectDisposition::OpenedExisting,
    validation: BootValidation::NewPrepared,
    origin: BootOrigin::NewlyInitializedReady,
};

const ALL_SHAPES: [BootShape; 4] = [
    EXISTING_CONTEXT,
    CREATED_CONTEXT,
    REOPENED_CONTEXT,
    EXISTING_EMPTY_CONTEXT,
];

fn outcome_for(effect: LoadEffect, shape: BootShape) -> LoadEffectOutcome {
    match effect {
        LoadEffect::OpenAndAcquireBootLockEvent => {
            LoadEffectOutcome::BootLockEventAcquired(shape.lock)
        }
        LoadEffect::OpenOrCreateBootSection => LoadEffectOutcome::BootSectionOpened(shape.section),
        LoadEffect::ValidateOrInitialize => {
            LoadEffectOutcome::BootContextValidated(shape.validation)
        }
        LoadEffect::PublishLoadGeneration => LoadEffectOutcome::BootContextPublished(shape.origin),
        LoadEffect::MapSystemView
        | LoadEffect::ReleaseBootLockEvent
        | LoadEffect::RegisterEtw
        | LoadEffect::AllocateDriverState
        | LoadEffect::RegisterProcessNotify
        | LoadEffect::CreateProviderSecure
        | LoadEffect::CreateFscontrolSecure
        | LoadEffect::CreateProviderDosLink
        | LoadEffect::PublishProvider
        | LoadEffect::PublishFscontrol
        | LoadEffect::RegisterFilesystem => LoadEffectOutcome::Done,
    }
}

/// Balances of everything a load can acquire. Every count is incremented by the
/// effect that acquires it and decremented by the rollback effect that releases
/// it, so a missing, duplicated, or misordered unwind entry is arithmetic, not
/// opinion.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Ledger {
    lock_event_handle: i32,
    lock_event_held: i32,
    section_handle: i32,
    system_view: i32,
    etw: i32,
    driver_state: i32,
    process_notify: i32,
    provider_device: i32,
    fscontrol_device: i32,
    provider_dos_link: i32,
    provider_published: i32,
    fscontrol_published: i32,
    filesystem_registered: i32,
    section_made_temporary: i32,
}

/// Checked counter movement: `+=` is a denied lint on every path in this
/// crate, and a wrapped balance would silently turn a leak into a pass.
fn bump(counter: &mut i32, delta: i32) {
    *counter = match counter.checked_add(delta) {
        Some(next) => next,
        None => panic!("ledger counter overflowed"),
    };
}

impl Ledger {
    fn acquire(&mut self, effect: LoadEffect) {
        match effect {
            LoadEffect::OpenAndAcquireBootLockEvent => {
                bump(&mut self.lock_event_handle, 1);
                bump(&mut self.lock_event_held, 1);
            }
            LoadEffect::OpenOrCreateBootSection => bump(&mut self.section_handle, 1),
            LoadEffect::MapSystemView => bump(&mut self.system_view, 1),
            LoadEffect::ValidateOrInitialize | LoadEffect::PublishLoadGeneration => {}
            LoadEffect::ReleaseBootLockEvent => {
                assert_eq!(self.lock_event_held, 1, "release requires a held guard");
                bump(&mut self.lock_event_held, -1);
            }
            LoadEffect::RegisterEtw => bump(&mut self.etw, 1),
            LoadEffect::AllocateDriverState => bump(&mut self.driver_state, 1),
            LoadEffect::RegisterProcessNotify => bump(&mut self.process_notify, 1),
            LoadEffect::CreateProviderSecure => bump(&mut self.provider_device, 1),
            LoadEffect::CreateFscontrolSecure => bump(&mut self.fscontrol_device, 1),
            LoadEffect::CreateProviderDosLink => bump(&mut self.provider_dos_link, 1),
            LoadEffect::PublishProvider => bump(&mut self.provider_published, 1),
            LoadEffect::PublishFscontrol => bump(&mut self.fscontrol_published, 1),
            LoadEffect::RegisterFilesystem => bump(&mut self.filesystem_registered, 1),
        }
    }

    fn release(&mut self, effect: LoadRollbackEffect) {
        let counter = match effect {
            LoadRollbackEffect::UnregisterFilesystem => &mut self.filesystem_registered,
            LoadRollbackEffect::UnpublishFscontrol => &mut self.fscontrol_published,
            LoadRollbackEffect::UnpublishProvider => &mut self.provider_published,
            LoadRollbackEffect::RemoveProviderDosLink => &mut self.provider_dos_link,
            LoadRollbackEffect::DeleteFscontrol => &mut self.fscontrol_device,
            LoadRollbackEffect::DeleteProvider => &mut self.provider_device,
            LoadRollbackEffect::UnregisterProcessNotify => &mut self.process_notify,
            LoadRollbackEffect::ReleaseDriverState => &mut self.driver_state,
            LoadRollbackEffect::UnregisterEtw => &mut self.etw,
            LoadRollbackEffect::UnmapSystemView => &mut self.system_view,
            LoadRollbackEffect::MakeNewBootSectionTemporary => {
                // Not a release: it converts a permanent object this load
                // created into a temporary one, so that closing the last
                // handle destroys it.
                bump(&mut self.section_made_temporary, 1);
                assert_eq!(
                    self.section_handle, 1,
                    "a section can only be made temporary while this load still holds it"
                );
                return;
            }
            LoadRollbackEffect::CloseBootSection => &mut self.section_handle,
            LoadRollbackEffect::ReleaseBootLockEvent => &mut self.lock_event_held,
            LoadRollbackEffect::CloseBootLockEvent => &mut self.lock_event_handle,
        };
        assert!(
            *counter > 0,
            "{effect:?} releases a resource this load does not own"
        );
        bump(counter, -1);
    }

    fn is_empty(self) -> bool {
        self == Ledger {
            section_made_temporary: self.section_made_temporary,
            ..Ledger::default()
        }
    }
}

/// The test's own statement of the unwind rule: undo the completed effects in
/// reverse acquisition order, and undo each one with its own inverse. The
/// module states the same rule as static slices; comparing the two catches a
/// reordered, missing, or duplicated slice entry.
fn undo(effect: LoadEffect, shape: BootShape, prefix: usize) -> Vec<LoadRollbackEffect> {
    let created_here = matches!(shape.section, ObjectDisposition::CreatedNew);
    // The section is READY once the load-generation publication (index 4) has
    // completed; an existing READY context is already READY at validation.
    let ready =
        prefix > 4 || matches!(shape.validation, BootValidation::ExistingReady) && prefix > 3;
    // The load releases lock ownership at index 5.
    let held = prefix <= 5;

    match effect {
        LoadEffect::OpenAndAcquireBootLockEvent => {
            let mut out = Vec::new();
            if held {
                out.push(LoadRollbackEffect::ReleaseBootLockEvent);
            }
            out.push(LoadRollbackEffect::CloseBootLockEvent);
            out
        }
        LoadEffect::OpenOrCreateBootSection => {
            let mut out = Vec::new();
            if created_here && !ready {
                out.push(LoadRollbackEffect::MakeNewBootSectionTemporary);
            }
            out.push(LoadRollbackEffect::CloseBootSection);
            out
        }
        LoadEffect::MapSystemView => vec![LoadRollbackEffect::UnmapSystemView],
        LoadEffect::ValidateOrInitialize
        | LoadEffect::PublishLoadGeneration
        | LoadEffect::ReleaseBootLockEvent => Vec::new(),
        LoadEffect::RegisterEtw => vec![LoadRollbackEffect::UnregisterEtw],
        LoadEffect::AllocateDriverState => vec![LoadRollbackEffect::ReleaseDriverState],
        LoadEffect::RegisterProcessNotify => vec![LoadRollbackEffect::UnregisterProcessNotify],
        LoadEffect::CreateProviderSecure => vec![LoadRollbackEffect::DeleteProvider],
        LoadEffect::CreateFscontrolSecure => vec![LoadRollbackEffect::DeleteFscontrol],
        LoadEffect::CreateProviderDosLink => vec![LoadRollbackEffect::RemoveProviderDosLink],
        LoadEffect::PublishProvider => vec![LoadRollbackEffect::UnpublishProvider],
        LoadEffect::PublishFscontrol => vec![LoadRollbackEffect::UnpublishFscontrol],
        LoadEffect::RegisterFilesystem => vec![LoadRollbackEffect::UnregisterFilesystem],
    }
}

fn expected_rollback(shape: BootShape, prefix: usize) -> Vec<LoadRollbackEffect> {
    EXPECTED_LOAD_TRACE
        .iter()
        .take(prefix)
        .rev()
        .flat_map(|effect| undo(*effect, shape, prefix))
        .collect()
}

struct Driven {
    trace: Vec<LoadEffect>,
    ledger: Ledger,
    rollback: Option<Vec<LoadRollbackEffect>>,
    driver: Option<LoadedDriver>,
}

fn drive(shape: BootShape, fail_at: Option<usize>) -> Driven {
    let mut ledger = Ledger::default();
    let mut trace: Vec<LoadEffect> = Vec::new();
    let mut progress = LoadPlan::begin();
    let mut index = 0usize;

    loop {
        match progress {
            LoadProgress::Ready(driver) => {
                return Driven {
                    trace,
                    ledger,
                    rollback: None,
                    driver: Some(driver),
                };
            }
            LoadProgress::Effect(pending) => {
                let effect = pending.effect();
                if fail_at == Some(index) {
                    let plan = pending.failed();
                    let effects: Vec<LoadRollbackEffect> = plan.effects().to_vec();
                    for one in effects.iter().copied() {
                        ledger.release(one);
                    }
                    return Driven {
                        trace,
                        ledger,
                        rollback: Some(effects),
                        driver: None,
                    };
                }
                trace.push(effect);
                ledger.acquire(effect);
                progress = must_ok(
                    pending.succeeded(outcome_for(effect, shape)),
                    "the matching outcome must advance the plan",
                );
                index = match index.checked_add(1) {
                    Some(next) => next,
                    None => panic!("the load cursor overflowed"),
                };
            }
        }
    }
}

#[test]
fn the_successful_load_trace_is_exactly_the_fifteen_ordered_effects() {
    for shape in ALL_SHAPES {
        let run = drive(shape, None);
        assert_eq!(
            run.trace.as_slice(),
            EXPECTED_LOAD_TRACE.as_slice(),
            "unexpected trace for {shape:?}"
        );
        assert!(run.driver.is_some(), "a complete load yields the proof");
        assert!(run.rollback.is_none());
        assert_eq!(
            run.ledger.lock_event_held, 0,
            "load must not retain the guard"
        );
        assert_eq!(run.ledger.lock_event_handle, 1, "the handle is retained");
        assert_eq!(run.ledger.section_handle, 1);
        assert_eq!(run.ledger.system_view, 1);
        assert_eq!(run.ledger.section_made_temporary, 0);
    }
}

#[test]
fn failure_at_every_step_unwinds_the_exact_owned_prefix_in_reverse() {
    for shape in ALL_SHAPES {
        for prefix in 0..EXPECTED_LOAD_TRACE.len() {
            let run = drive(shape, Some(prefix));
            let rollback = match run.rollback {
                Some(rollback) => rollback,
                None => panic!("a failure at {prefix} must produce a rollback plan"),
            };
            assert_eq!(
                rollback,
                expected_rollback(shape, prefix),
                "wrong unwind after a failure at effect {prefix} for {shape:?}"
            );
            assert!(
                run.ledger.is_empty(),
                "a failed load at effect {prefix} left {:?} behind for {shape:?}",
                run.ledger
            );
        }
    }
}

#[test]
fn only_a_new_section_that_never_reached_ready_is_made_temporary() {
    for shape in ALL_SHAPES {
        let created_here = matches!(shape.section, ObjectDisposition::CreatedNew);
        for prefix in 0..EXPECTED_LOAD_TRACE.len() {
            let run = drive(shape, Some(prefix));
            // A section exists from effect 1 onwards; it becomes READY when the
            // load-generation publication (effect index 4) completes.
            let owns_section = prefix > 1;
            let ready = prefix > 4;
            let expected = i32::from(created_here && owns_section && !ready);
            assert_eq!(
                run.ledger.section_made_temporary, expected,
                "wrong temporary decision at prefix {prefix} for {shape:?}"
            );
        }
        // And a completed load never makes its section temporary.
        assert_eq!(drive(shape, None).ledger.section_made_temporary, 0);
    }
}

#[test]
fn no_rollback_releases_the_lock_event_after_the_release_effect() {
    for shape in ALL_SHAPES {
        for prefix in 6..EXPECTED_LOAD_TRACE.len() {
            let run = drive(shape, Some(prefix));
            let rollback = run.rollback.unwrap_or_default();
            assert!(
                !rollback.contains(&LoadRollbackEffect::ReleaseBootLockEvent),
                "prefix {prefix} already released ownership; a second release \
                 would set an event this load does not own"
            );
            assert!(rollback.contains(&LoadRollbackEffect::CloseBootLockEvent));
        }
    }
}

#[test]
fn rollback_touches_each_boot_handle_exactly_once() {
    for shape in ALL_SHAPES {
        for prefix in 0..EXPECTED_LOAD_TRACE.len() {
            let rollback = drive(shape, Some(prefix)).rollback.unwrap_or_default();
            for once in [
                LoadRollbackEffect::CloseBootLockEvent,
                LoadRollbackEffect::CloseBootSection,
                LoadRollbackEffect::ReleaseBootLockEvent,
                LoadRollbackEffect::MakeNewBootSectionTemporary,
                LoadRollbackEffect::UnmapSystemView,
            ] {
                let count = rollback.iter().filter(|e| **e == once).count();
                assert!(
                    count <= 1,
                    "{once:?} appears {count} times at prefix {prefix} for {shape:?}"
                );
            }
        }
    }
}

#[test]
fn each_pending_effect_accepts_only_its_matching_outcome() {
    let all_outcomes = [
        LoadEffectOutcome::Done,
        LoadEffectOutcome::BootLockEventAcquired(ObjectDisposition::OpenedExisting),
        LoadEffectOutcome::BootSectionOpened(ObjectDisposition::OpenedExisting),
        LoadEffectOutcome::BootContextValidated(BootValidation::ExistingReady),
        LoadEffectOutcome::BootContextPublished(BootOrigin::ExistingReady),
    ];

    for prefix in 0..EXPECTED_LOAD_TRACE.len() {
        for wrong in all_outcomes {
            let pending = pending_at(EXISTING_CONTEXT, prefix);
            let effect = pending.effect();
            let matching = core::mem::discriminant(&outcome_for(effect, EXISTING_CONTEXT))
                == core::mem::discriminant(&wrong);
            if matching {
                continue;
            }
            assert_eq!(
                must_err(
                    pending.succeeded(wrong),
                    "a mismatched outcome must not advance the plan",
                ),
                AdapterPlanError::InvalidInput,
                "{effect:?} wrongly accepted {wrong:?}"
            );
        }
    }
}

fn pending_at(shape: BootShape, prefix: usize) -> PendingLoadEffect {
    let mut progress = LoadPlan::begin();
    for step in 0..prefix {
        let pending = match progress {
            LoadProgress::Effect(pending) => pending,
            LoadProgress::Ready(_) => panic!("the plan ended before step {step}"),
        };
        let effect = pending.effect();
        progress = must_ok(
            pending.succeeded(outcome_for(effect, shape)),
            "the fixture advances with matching outcomes",
        );
    }
    match progress {
        LoadProgress::Effect(pending) => pending,
        LoadProgress::Ready(_) => panic!("no pending effect at prefix {prefix}"),
    }
}

#[test]
fn a_created_section_cannot_report_an_existing_ready_validation() {
    // A freshly created pagefile-backed section is entirely zero, so claiming
    // it already carried a READY header is a contradiction, not a shortcut.
    let pending = pending_at(CREATED_CONTEXT, 3);
    assert_eq!(pending.effect(), LoadEffect::ValidateOrInitialize);
    assert_eq!(
        must_err(
            pending.succeeded(LoadEffectOutcome::BootContextValidated(
                BootValidation::ExistingReady
            )),
            "a created section cannot already be READY",
        ),
        AdapterPlanError::InvalidTransition
    );
}

#[test]
fn publication_origin_must_agree_with_validation() {
    let pending = pending_at(EXISTING_CONTEXT, 4);
    assert_eq!(pending.effect(), LoadEffect::PublishLoadGeneration);
    assert_eq!(
        must_err(
            pending.succeeded(LoadEffectOutcome::BootContextPublished(
                BootOrigin::NewlyInitializedReady
            )),
            "an adopted READY context was not initialized by this load",
        ),
        AdapterPlanError::InvalidTransition
    );

    let pending = pending_at(EXISTING_EMPTY_CONTEXT, 4);
    assert_eq!(
        must_err(
            pending.succeeded(LoadEffectOutcome::BootContextPublished(
                BootOrigin::ExistingReady
            )),
            "a context this load initialized cannot be reported as adopted",
        ),
        AdapterPlanError::InvalidTransition
    );
}

#[test]
fn an_outcome_cannot_carry_a_boot_context_image() {
    // Every outcome is a closed tag. A header, slot array, or byte buffer
    // could not fit, so the native executor cannot smuggle unvalidated
    // BootContext bytes back into the plan; `bootctx` stays the only decider.
    assert!(
        core::mem::size_of::<LoadEffectOutcome>() <= 2,
        "LoadEffectOutcome grew to {} bytes",
        core::mem::size_of::<LoadEffectOutcome>()
    );
}

// ---------------------------------------------------------------------------
// Unload
// ---------------------------------------------------------------------------

const EXPECTED_UNLOAD_TRACE: [UnloadEffect; 16] = [
    UnloadEffect::CloseGlobalAdmissions,
    UnloadEffect::UnregisterProcessNotify,
    UnloadEffect::WaitProcessCallbacks,
    UnloadEffect::WaitSetupAdmission,
    UnloadEffect::ClaimOrJoinOneSession,
    UnloadEffect::RestartSessionScan,
    UnloadEffect::DrainR3Finalizers,
    UnloadEffect::WaitControlContextAdmission,
    UnloadEffect::PreflightR3LedgersAndRoot,
    UnloadEffect::UnregisterFilesystem,
    UnloadEffect::DeleteFscontrol,
    UnloadEffect::RemoveProviderDosLink,
    UnloadEffect::DeleteProvider,
    UnloadEffect::ReleaseBootObjects,
    UnloadEffect::ReleaseDriverState,
    UnloadEffect::UnregisterEtw,
];

// Independent specification roster. Do not derive this from
// `R3UnloadPredicate::ALL`: deleting the same row from the enum and its
// implementation roster must still make this test fail.
const EXPECTED_R3_UNLOAD_PREDICATES: [R3UnloadPredicate; 31] = [
    R3UnloadPredicate::CoreAdmissionClosed,
    R3UnloadPredicate::ProcessCallbackAdmissionClosed,
    R3UnloadPredicate::ProcessCallbacksDrained,
    R3UnloadPredicate::SetupAdmissionClosed,
    R3UnloadPredicate::SetupAdmissionDrained,
    R3UnloadPredicate::SessionScanStableEmpty,
    R3UnloadPredicate::CoreSessionSlotsEmpty,
    R3UnloadPredicate::NativeSessionCellsEmpty,
    R3UnloadPredicate::TerminalRendezvousInactive,
    R3UnloadPredicate::TerminalJoinersDrained,
    R3UnloadPredicate::TerminalEventsQuiescent,
    R3UnloadPredicate::MountOwnerAbsent,
    R3UnloadPredicate::MountTicketsAndWaitersDrained,
    R3UnloadPredicate::MountSignalsAcknowledged,
    R3UnloadPredicate::FinalizerAdmissionClosed,
    R3UnloadPredicate::FinalizersDrained,
    R3UnloadPredicate::FinalizerDepositsAbsent,
    R3UnloadPredicate::FinalizerHandoffsAbsent,
    R3UnloadPredicate::FailStopSlotsEmpty,
    R3UnloadPredicate::SessionShellOwnersAbsent,
    R3UnloadPredicate::SessionRootOwnersAbsent,
    R3UnloadPredicate::RegistryLeasesAbsent,
    R3UnloadPredicate::ControlOwnersAbsent,
    R3UnloadPredicate::CheckpointReadinessAbsent,
    R3UnloadPredicate::ControlContextAdmissionClosed,
    R3UnloadPredicate::ControlContextAdmissionDrained,
    R3UnloadPredicate::ControlBindingsClosed,
    R3UnloadPredicate::CompletedControlRecordsAbsent,
    R3UnloadPredicate::CloseRightsAbsent,
    R3UnloadPredicate::ControlContextsAbsent,
    R3UnloadPredicate::SoleDriverRootReference,
];

fn unload_prefix() -> (Vec<UnloadEffect>, R3UnloadPreflightBoundary) {
    let driver = match drive(EXISTING_CONTEXT, None).driver {
        Some(driver) => driver,
        None => panic!("a complete load yields the proof consumed by unload"),
    };
    let mut progress = UnloadPlan::begin(driver);
    let mut trace = Vec::new();
    loop {
        progress = match progress {
            R3UnloadPlanProgress::Effect(effect) => {
                trace.push(effect.effect());
                effect.performed()
            }
            R3UnloadPlanProgress::Preflight(boundary) => return (trace, boundary),
        };
    }
}

// Proof of safety: the fixture under test is constructed in this function to
// satisfy the very precondition being unwrapped, so a `None`/`Err` here is a
// broken fixture that must fail the test loudly. Host test code only.
#[allow(clippy::expect_used)]
fn unload_trace() -> Vec<UnloadEffect> {
    let (mut trace, boundary) = unload_prefix();
    trace.push(UnloadEffect::PreflightR3LedgersAndRoot);
    let prepared =
        R3UnloadPreflight::prepare(boundary, R3UnloadPreflightObservation::all_clear_for_test())
            .expect("the canonical fixture discharges every independent preflight");
    let mut destruction = prepared.into_destruction();
    loop {
        destruction = match destruction {
            R3UnloadDestructionProgress::Effect(effect) => {
                trace.push(effect.effect());
                effect.performed()
            }
            R3UnloadDestructionProgress::Complete(_) => return trace,
        };
    }
}

fn position(trace: &[UnloadEffect], effect: UnloadEffect) -> usize {
    match trace.iter().position(|e| *e == effect) {
        Some(index) => index,
        None => panic!("unload never performs {effect:?}"),
    }
}

#[test]
fn the_unload_sequence_is_exactly_the_sixteen_ordered_effects() {
    assert_eq!(
        UnloadPlan::EFFECTS.as_slice(),
        EXPECTED_UNLOAD_TRACE.as_slice()
    );
    assert_eq!(unload_trace().as_slice(), EXPECTED_UNLOAD_TRACE.as_slice());
}

#[test]
fn unload_closes_admission_before_enumerating_sessions() {
    let trace = unload_trace();
    assert!(
        position(&trace, UnloadEffect::CloseGlobalAdmissions)
            < position(&trace, UnloadEffect::ClaimOrJoinOneSession),
        "an open registry could admit a session into an unloading driver"
    );
}

#[test]
fn unload_closes_permanent_admission_then_waits_setup_before_cell_scan() {
    const TASK12_UNLOAD_TRACE: [&str; 16] = [
        "CloseGlobalAdmissions",
        "UnregisterProcessNotify",
        "WaitProcessCallbacks",
        "WaitSetupAdmission",
        "ClaimOrJoinOneSession",
        "RestartSessionScan",
        "DrainR3Finalizers",
        "WaitControlContextAdmission",
        "PreflightR3LedgersAndRoot",
        "UnregisterFilesystem",
        "DeleteFscontrol",
        "RemoveProviderDosLink",
        "DeleteProvider",
        "ReleaseBootObjects",
        "ReleaseDriverState",
        "UnregisterEtw",
    ];

    let trace = unload_trace();
    let actual: Vec<String> = trace.iter().map(|effect| format!("{effect:?}")).collect();
    assert_eq!(
        actual.iter().map(String::as_str).collect::<Vec<_>>(),
        TASK12_UNLOAD_TRACE,
        "the R3 unload must execute the exact 16-effect admission, scan, ledger, and destruction trace"
    );
}

#[test]
fn process_notification_unregisters_after_fencing_and_before_state_release() {
    let trace = unload_trace();
    let unregister = position(&trace, UnloadEffect::UnregisterProcessNotify);
    assert!(
        position(&trace, UnloadEffect::CloseGlobalAdmissions) < unregister,
        "callback admission must close before native unregistration"
    );
    assert!(
        unregister < position(&trace, UnloadEffect::WaitProcessCallbacks),
        "waiting before unregistering can never drain"
    );
    assert!(
        position(&trace, UnloadEffect::WaitProcessCallbacks)
            < position(&trace, UnloadEffect::ReleaseDriverState),
        "an in-flight callback would touch released root storage"
    );
}

#[test]
fn failed_process_notify_unregister_runs_no_later_effect() {
    fn fake_ddi_trace(status: i32) -> Vec<UnloadEffect> {
        let mut trace = vec![
            UnloadEffect::CloseGlobalAdmissions,
            UnloadEffect::UnregisterProcessNotify,
        ];
        if classify_process_notify_unregister(status)
            == ProcessNotifyUnregisterDisposition::ContinueToCallbackDrain
        {
            trace.push(UnloadEffect::WaitProcessCallbacks);
        }
        trace
    }

    assert_eq!(
        fake_ddi_trace(-1),
        [
            UnloadEffect::CloseGlobalAdmissions,
            UnloadEffect::UnregisterProcessNotify,
        ],
        "a failed unregister may leave the callback registered, so no later effect is reachable"
    );
    assert_eq!(
        fake_ddi_trace(0),
        [
            UnloadEffect::CloseGlobalAdmissions,
            UnloadEffect::UnregisterProcessNotify,
            UnloadEffect::WaitProcessCallbacks,
        ]
    );
}

#[test]
fn unload_preflight_refuses_each_r3_ledger_predicate_independently() {
    assert_eq!(
        R3UnloadPredicate::ALL,
        EXPECTED_R3_UNLOAD_PREDICATES,
        "effect nine must retain the independent exact 31-row roster"
    );
    let all_clear = R3UnloadPreflightObservation::all_clear_for_test();
    let (_, boundary) = unload_prefix();
    assert!(R3UnloadPreflight::prepare(boundary, all_clear).is_ok());

    for predicate in EXPECTED_R3_UNLOAD_PREDICATES {
        let observed = all_clear.with_failed_for_test(predicate);
        let (_, boundary) = unload_prefix();
        match R3UnloadPreflight::prepare(boundary, observed) {
            Err(rejected) => assert_eq!(
                rejected, predicate,
                "effect nine rejected the wrong predicate"
            ),
            Ok(_) => panic!("effect nine accepted independently failed {predicate:?} predicate"),
        }
    }
}

#[test]
// Proof of safety: the fixture under test is constructed in this function to
// satisfy the very precondition being unwrapped, so a `None`/`Err` here is a
// broken fixture that must fail the test loudly. Host test code only.
#[allow(clippy::expect_used)]
fn prepared_unload_destruction_has_one_non_refusing_seven_effect_suffix() {
    let (_, boundary) = unload_prefix();
    let prepared =
        R3UnloadPreflight::prepare(boundary, R3UnloadPreflightObservation::all_clear_for_test())
            .expect("all independent ledgers are empty and the sole root remains");
    let mut progress = prepared.into_destruction();
    let mut actual = Vec::new();
    loop {
        progress = match progress {
            R3UnloadDestructionProgress::Effect(effect) => {
                actual.push(effect.effect());
                effect.performed()
            }
            R3UnloadDestructionProgress::Complete(_) => break,
        };
    }
    assert_eq!(
        actual,
        EXPECTED_UNLOAD_TRACE[9..],
        "only the effect-nine proof may enter the fixed effects 10-16 suffix"
    );
}

#[test]
fn etw_unregisters_last() {
    let trace = unload_trace();
    assert_eq!(
        position(&trace, UnloadEffect::UnregisterEtw),
        trace.len() - 1
    );
}

#[test]
fn neither_rollback_nor_unload_deletes_a_ready_permanent_object() {
    // The only object-destroying step in the whole vocabulary is
    // MakeNewBootSectionTemporary, and it exists solely for a section this
    // load created and never published as READY. Unload has no such step at
    // all: it unmaps and closes, which leaves both permanent objects intact.
    let unload_names = format!("{EXPECTED_UNLOAD_TRACE:?}");
    for forbidden in ["Temporary", "Delete Boot", "DeleteBoot"] {
        assert!(
            !unload_names.contains(forbidden),
            "unload must not contain {forbidden}"
        );
    }

    for shape in ALL_SHAPES {
        for prefix in 5..EXPECTED_LOAD_TRACE.len() {
            let rollback = drive(shape, Some(prefix)).rollback.unwrap_or_default();
            assert!(
                !rollback.contains(&LoadRollbackEffect::MakeNewBootSectionTemporary),
                "a READY section must survive a failed load at prefix {prefix}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Production-used R3 unload and process-callback runners
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum R3UnloadNativeCall {
    CloseGlobalAdmissions,
    UnregisterProcessNotify,
    WaitProcessCallbacks,
    WaitSetupAdmission,
    ClaimOrJoinOneSession,
    RestartSessionScan,
    DrainR3Finalizers,
    WaitControlContextAdmission,
    PreflightR3LedgersAndRoot,
    UnregisterFilesystem,
    DeleteFscontrol,
    RemoveProviderDosLink,
    DeleteProvider,
    ReleaseBootObjects,
    ReleaseDriverState,
    UnregisterEtw,
    WaitBlockedUnloadForever,
}

const EXPECTED_R3_UNLOAD_NATIVE_CALLS: [R3UnloadNativeCall; 16] = [
    R3UnloadNativeCall::CloseGlobalAdmissions,
    R3UnloadNativeCall::UnregisterProcessNotify,
    R3UnloadNativeCall::WaitProcessCallbacks,
    R3UnloadNativeCall::WaitSetupAdmission,
    R3UnloadNativeCall::ClaimOrJoinOneSession,
    R3UnloadNativeCall::RestartSessionScan,
    R3UnloadNativeCall::DrainR3Finalizers,
    R3UnloadNativeCall::WaitControlContextAdmission,
    R3UnloadNativeCall::PreflightR3LedgersAndRoot,
    R3UnloadNativeCall::UnregisterFilesystem,
    R3UnloadNativeCall::DeleteFscontrol,
    R3UnloadNativeCall::RemoveProviderDosLink,
    R3UnloadNativeCall::DeleteProvider,
    R3UnloadNativeCall::ReleaseBootObjects,
    R3UnloadNativeCall::ReleaseDriverState,
    R3UnloadNativeCall::UnregisterEtw,
];

struct NativeStage1;
struct NativeStage2;
struct NativeStage3;
struct NativeStage4;
struct NativeStage5;
struct NativeStage6;
struct NativeStage7;
struct NativeStage8;
struct NativeStage9;
struct NativeStage10;
struct NativeStage11;
struct NativeStage12;
struct NativeStage13;
struct NativeStage14;
struct NativeStage15;
struct NativeBlocked;

struct RecordingR3Unload {
    trace: std::rc::Rc<std::cell::RefCell<Vec<R3UnloadNativeCall>>>,
    block_scan: bool,
}

impl RecordingR3Unload {
    fn record(&self, call: R3UnloadNativeCall) {
        self.trace.borrow_mut().push(call);
    }
}

unsafe impl R3UnloadNativeOps for RecordingR3Unload {
    type ClosedAdmissions = NativeStage1;
    type ProcessNotifyUnregistered = NativeStage2;
    type ProcessCallbacksDrained = NativeStage3;
    type SetupAdmissionDrained = NativeStage4;
    type OneSessionObserved = NativeStage5;
    type StableSessionScan = NativeStage6;
    type BlockedSessionScan = NativeBlocked;
    type FinalizersDrained = NativeStage7;
    type ControlContextsDrained = NativeStage8;
    type PreparedDestruction = NativeStage9;
    type FilesystemUnregistered = NativeStage10;
    type FscontrolDeleted = NativeStage11;
    type ProviderDosLinkRemoved = NativeStage12;
    type ProviderDeleted = NativeStage13;
    type BootObjectsReleased = NativeStage14;
    type DriverStateReleased = NativeStage15;

    unsafe fn close_global_admissions(&mut self) -> Self::ClosedAdmissions {
        self.record(R3UnloadNativeCall::CloseGlobalAdmissions);
        NativeStage1
    }

    unsafe fn unregister_process_notify(
        &mut self,
        _closed: Self::ClosedAdmissions,
    ) -> Self::ProcessNotifyUnregistered {
        self.record(R3UnloadNativeCall::UnregisterProcessNotify);
        NativeStage2
    }

    unsafe fn wait_process_callbacks(
        &mut self,
        _unregistered: Self::ProcessNotifyUnregistered,
    ) -> Self::ProcessCallbacksDrained {
        self.record(R3UnloadNativeCall::WaitProcessCallbacks);
        NativeStage3
    }

    unsafe fn wait_setup_admission(
        &mut self,
        _process: Self::ProcessCallbacksDrained,
    ) -> Self::SetupAdmissionDrained {
        self.record(R3UnloadNativeCall::WaitSetupAdmission);
        NativeStage4
    }

    unsafe fn claim_or_join_one_session(
        &mut self,
        _setup: Self::SetupAdmissionDrained,
    ) -> Self::OneSessionObserved {
        self.record(R3UnloadNativeCall::ClaimOrJoinOneSession);
        NativeStage5
    }

    unsafe fn restart_session_scan(
        &mut self,
        _first: Self::OneSessionObserved,
    ) -> R3UnloadSessionScan<Self::StableSessionScan, Self::BlockedSessionScan> {
        self.record(R3UnloadNativeCall::RestartSessionScan);
        if self.block_scan {
            R3UnloadSessionScan::Blocked(NativeBlocked)
        } else {
            R3UnloadSessionScan::Stable(NativeStage6)
        }
    }

    unsafe fn wait_blocked_unload_forever(&mut self, _blocked: Self::BlockedSessionScan) -> ! {
        self.record(R3UnloadNativeCall::WaitBlockedUnloadForever);
        std::panic::panic_any(BlockedUnloadTestSentinel)
    }

    unsafe fn drain_r3_finalizers(
        &mut self,
        _stable: Self::StableSessionScan,
    ) -> Self::FinalizersDrained {
        self.record(R3UnloadNativeCall::DrainR3Finalizers);
        NativeStage7
    }

    unsafe fn wait_control_context_admission(
        &mut self,
        _finalizers: Self::FinalizersDrained,
    ) -> Self::ControlContextsDrained {
        self.record(R3UnloadNativeCall::WaitControlContextAdmission);
        NativeStage8
    }

    unsafe fn preflight_r3_ledgers_and_root(
        &mut self,
        _boundary: R3UnloadPreflightBoundary,
        _control: Self::ControlContextsDrained,
    ) -> Self::PreparedDestruction {
        self.record(R3UnloadNativeCall::PreflightR3LedgersAndRoot);
        NativeStage9
    }

    unsafe fn unregister_filesystem(
        &mut self,
        _prepared: Self::PreparedDestruction,
    ) -> Self::FilesystemUnregistered {
        self.record(R3UnloadNativeCall::UnregisterFilesystem);
        NativeStage10
    }

    unsafe fn delete_fscontrol(
        &mut self,
        _stage: Self::FilesystemUnregistered,
    ) -> Self::FscontrolDeleted {
        self.record(R3UnloadNativeCall::DeleteFscontrol);
        NativeStage11
    }

    unsafe fn remove_provider_dos_link(
        &mut self,
        _stage: Self::FscontrolDeleted,
    ) -> Self::ProviderDosLinkRemoved {
        self.record(R3UnloadNativeCall::RemoveProviderDosLink);
        NativeStage12
    }

    unsafe fn delete_provider(
        &mut self,
        _stage: Self::ProviderDosLinkRemoved,
    ) -> Self::ProviderDeleted {
        self.record(R3UnloadNativeCall::DeleteProvider);
        NativeStage13
    }

    unsafe fn release_boot_objects(
        &mut self,
        _stage: Self::ProviderDeleted,
    ) -> Self::BootObjectsReleased {
        self.record(R3UnloadNativeCall::ReleaseBootObjects);
        NativeStage14
    }

    unsafe fn release_driver_state(
        &mut self,
        _stage: Self::BootObjectsReleased,
    ) -> Self::DriverStateReleased {
        self.record(R3UnloadNativeCall::ReleaseDriverState);
        NativeStage15
    }

    unsafe fn unregister_etw(self, _stage: Self::DriverStateReleased) {
        self.record(R3UnloadNativeCall::UnregisterEtw);
    }
}

#[derive(Debug)]
struct BlockedUnloadTestSentinel;

// Proof of safety: the fixture under test is constructed in this function to
// satisfy the very precondition being unwrapped, so a `None`/`Err` here is a
// broken fixture that must fail the test loudly. Host test code only.
#[allow(clippy::expect_used)]
fn loaded_driver_for_native_trace() -> LoadedDriver {
    drive(EXISTING_CONTEXT, None)
        .driver
        .expect("the complete load owns the affine unload proof")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessCallbackNativeCall {
    AcquireGuard,
    ObserveCell { guard: u8, cursor: u32 },
    ReleaseGuard { guard: u8 },
}

struct RecordingProcessCallback {
    trace: std::rc::Rc<std::cell::RefCell<Vec<ProcessCallbackNativeCall>>>,
    admit: bool,
    observation: u8,
}

struct RecordingProcessCallbackGuard(u8);

impl R3ProcessCallbackNativeOps for RecordingProcessCallback {
    type Guard = RecordingProcessCallbackGuard;

    unsafe fn acquire_guard(&mut self) -> R3ProcessCallbackAdmission<Self::Guard> {
        self.trace
            .borrow_mut()
            .push(ProcessCallbackNativeCall::AcquireGuard);
        if self.admit {
            R3ProcessCallbackAdmission::Admitted(RecordingProcessCallbackGuard(37))
        } else {
            R3ProcessCallbackAdmission::Refused
        }
    }

    unsafe fn observe_one(&mut self, guard: &Self::Guard, cursor: u32) -> R3ProcessCallbackStep {
        self.trace
            .borrow_mut()
            .push(ProcessCallbackNativeCall::ObserveCell {
                guard: guard.0,
                cursor,
            });
        let step = match self.observation {
            0 => R3ProcessCallbackStep::Restart,
            1 => R3ProcessCallbackStep::ResumeAt(1),
            _ => R3ProcessCallbackStep::Complete,
        };
        self.observation = self.observation.saturating_add(1);
        step
    }

    unsafe fn release_guard(self, guard: Self::Guard) {
        self.trace
            .borrow_mut()
            .push(ProcessCallbackNativeCall::ReleaseGuard { guard: guard.0 });
    }

    unsafe fn wait_process_scan_invariant_forever(self, _guard: Self::Guard) -> ! {
        std::panic::panic_any(BlockedUnloadTestSentinel)
    }
}

#[test]
// Proof of safety: every index below is a fixed test fixture position or a
// cursor the same test just asserted, and this is host test code, not a
// driver input path. An out-of-range index here is the test failing, which
// is exactly the outcome wanted.
#[allow(clippy::indexing_slicing)]
fn native_process_callback_trace_closes_unregisters_waits_before_first_cell() {
    let unload_trace = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    unsafe {
        run_r3_unload(
            loaded_driver_for_native_trace(),
            RecordingR3Unload {
                trace: unload_trace.clone(),
                block_scan: false,
            },
        )
    };
    let unload_trace = unload_trace.borrow();
    assert_eq!(
        &unload_trace[..5],
        &EXPECTED_R3_UNLOAD_NATIVE_CALLS[..5],
        "global close, unregister, and process/setup waits must all precede the first cell"
    );

    let callback_trace = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    unsafe {
        run_r3_process_callback(RecordingProcessCallback {
            trace: callback_trace.clone(),
            admit: true,
            observation: 0,
        })
    };
    assert_eq!(
        callback_trace.borrow().as_slice(),
        [
            ProcessCallbackNativeCall::AcquireGuard,
            ProcessCallbackNativeCall::ObserveCell {
                guard: 37,
                cursor: 0,
            },
            ProcessCallbackNativeCall::ObserveCell {
                guard: 37,
                cursor: 0,
            },
            ProcessCallbackNativeCall::ObserveCell {
                guard: 37,
                cursor: 1,
            },
            ProcessCallbackNativeCall::ReleaseGuard { guard: 37 },
        ],
        "one authentic guard must span the complete restarted callback scan"
    );

    let refused_trace = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    unsafe {
        run_r3_process_callback(RecordingProcessCallback {
            trace: refused_trace.clone(),
            admit: false,
            observation: 0,
        })
    };
    assert_eq!(
        refused_trace.borrow().as_slice(),
        [ProcessCallbackNativeCall::AcquireGuard],
        "refused admission must touch neither registry nor cell"
    );
}

#[test]
fn native_borrow_refusal_is_mutation_free_and_cannot_reenter_or_unload() {
    let fsd = include_str!("../../../../fsring-fsd/src/fence.rs");
    assert!(
        fsd.contains("NativeFenceBorrowRefusal")
            && fsd.contains("FenceNativeBorrowFailStopDeposit"),
        "a native borrow refusal must be mutation-free and park rather than reenter or unload"
    );
}

#[test]
fn native_unload_trace_calls_all_sixteen_operations_once_in_order() {
    let trace = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    unsafe {
        run_r3_unload(
            loaded_driver_for_native_trace(),
            RecordingR3Unload {
                trace: trace.clone(),
                block_scan: false,
            },
        )
    };
    assert_eq!(
        trace.borrow().as_slice(),
        EXPECTED_R3_UNLOAD_NATIVE_CALLS,
        "the recording fake and production must traverse the same named runner"
    );
}

#[test]
// Proof of safety: the fixture under test is constructed in this function to
// satisfy the very precondition being unwrapped, so a `None`/`Err` here is a
// broken fixture that must fail the test loudly. Host test code only.
#[allow(clippy::expect_used)]
fn native_unload_blocked_trace_waits_on_the_dedicated_never_signalled_event() {
    let trace = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
        let trace = trace.clone();
        move || unsafe {
            run_r3_unload(
                loaded_driver_for_native_trace(),
                RecordingR3Unload {
                    trace,
                    block_scan: true,
                },
            )
        }
    }));
    let payload = caught.expect_err("the fake permanent wait uses a non-hanging sentinel");
    assert!(payload.is::<BlockedUnloadTestSentinel>());
    assert_eq!(
        trace.borrow().as_slice(),
        [
            R3UnloadNativeCall::CloseGlobalAdmissions,
            R3UnloadNativeCall::UnregisterProcessNotify,
            R3UnloadNativeCall::WaitProcessCallbacks,
            R3UnloadNativeCall::WaitSetupAdmission,
            R3UnloadNativeCall::ClaimOrJoinOneSession,
            R3UnloadNativeCall::RestartSessionScan,
            R3UnloadNativeCall::WaitBlockedUnloadForever,
        ],
        "a blocked generation must never reach finalizer drain, preflight, or destruction"
    );
}

#[test]
// Proof of safety: every index below is a fixed test fixture position or a
// cursor the same test just asserted, and this is host test code, not a
// driver input path. An out-of-range index here is the test failing, which
// is exactly the outcome wanted.
#[allow(clippy::indexing_slicing)]
fn native_unload_destructive_suffix_has_no_refusal_or_success_return() {
    let trace = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    unsafe {
        run_r3_unload(
            loaded_driver_for_native_trace(),
            RecordingR3Unload {
                trace: trace.clone(),
                block_scan: false,
            },
        )
    };
    let trace = trace.borrow();
    assert_eq!(
        &trace[9..],
        &EXPECTED_R3_UNLOAD_NATIVE_CALLS[9..],
        "after the sole preflight, seven consuming operations must run without a branch"
    );
}

// ---------------------------------------------------------------------------
// Anti-vacuity
// ---------------------------------------------------------------------------

#[test]
fn the_load_vocabulary_names_no_abandonment_or_ownership_steal() {
    // `02-transport.md` section 10.10 forbids mutant/semaphore locks,
    // abandonment recovery, ownership stealing, and force-setting a timed-out
    // event. Prose may discuss those words; code may not name them, so only
    // non-comment lines are scanned.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/adapter/load.rs");
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => panic!("cannot read {path}: {error}"),
    };
    let code: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .collect();
    assert!(
        code.len() > 100,
        "only {} code lines scanned; the check would be vacuous",
        code.len()
    );

    for forbidden in [
        "abandon",
        "Abandon",
        "steal",
        "Steal",
        "mutant",
        "Mutant",
        "semaphore",
        "Semaphore",
        "force_set",
        "ForceSet",
        "ZwCreateMutant",
        "ExMutantObjectType",
    ] {
        for line in &code {
            assert!(
                !line.contains(forbidden),
                "load.rs code names the forbidden concept {forbidden}: {line}"
            );
        }
    }
}
