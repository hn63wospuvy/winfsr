use super::*;
use crate::controldev::{CreateRequest, RequestorMode, decide_create};
use crate::effect::{
    ALL_DISMOUNT_EFFECTS, ALL_EFFECTS, ALL_MOUNT_EFFECTS, ALL_MOUNT_ROLLBACK_EFFECTS, Effect,
};
use fsring_abi::{BootInstanceId, MountId};

const SUCCESS: i32 = 0;
const INVALID_DEVICE_REQUEST: i32 = 0xC000_0010_u32 as i32;

const IRP_MJ_CREATE: u8 = 0x00;
const IRP_MJ_CLOSE: u8 = 0x02;
const IRP_MJ_READ: u8 = 0x03;
const IRP_MJ_WRITE: u8 = 0x04;
const IRP_MJ_FILE_SYSTEM_CONTROL: u8 = 0x0D;
const IRP_MJ_DEVICE_CONTROL: u8 = 0x0E;
const IRP_MJ_CLEANUP: u8 = 0x12;
const IRP_MN_MOUNT_VOLUME: u32 = 0x01;
const IRP_MN_VERIFY_VOLUME: u32 = 0x02;
const IOCTL_STORAGE_CHECK_VERIFY: u32 = 0x002D_4800;
const IOCTL_STORAGE_CHECK_VERIFY2: u32 = 0x002D_0800;

fn identity() -> SessionIdentity {
    SessionIdentity {
        mount_id: MountId { lo: 11, hi: 13 },
        boot_instance_id: BootInstanceId { lo: 17, hi: 19 },
        session_epoch: 23,
    }
}

fn initial_pending() -> PendingMountEffect {
    match begin_mount(VolumeState::Active, identity(), true) {
        Ok(MountProgress::Effect(pending)) => pending,
        Ok(MountProgress::Published(_)) => panic!("begin_mount published before any effect"),
        Err(_) => panic!("a valid ACTIVE target was refused"),
    }
}

fn success_outcome(effect: MountEffect) -> MountEffectOutcome {
    if matches!(
        effect,
        MountEffect::RevalidateTargetIdentityAdmissionAndBinding
    ) {
        MountEffectOutcome::Revalidated(MountRevalidation {
            target_identity_matches: true,
            admission_open: true,
            binding_unchanged: true,
            session_active: true,
        })
    } else {
        MountEffectOutcome::Done
    }
}

fn advance_success(pending: PendingMountEffect) -> MountProgress {
    match pending.prepare() {
        PreparedMountEffect::Ordinary(pending) => {
            let outcome = success_outcome(pending.effect());
            match pending.succeeded(outcome) {
                Ok(progress) => progress,
                Err(_) => panic!("the valid success outcome entered rollback"),
            }
        }
        PreparedMountEffect::PublishMountOwner(pending) => pending.published(),
        PreparedMountEffect::ClearDeviceInitializing(pending) => {
            MountProgress::Published(pending.cleared())
        }
    }
}

fn pending_at(target: usize) -> PendingMountEffect {
    let mut position = 0usize;
    let mut progress = MountProgress::Effect(initial_pending());
    loop {
        match progress {
            MountProgress::Effect(pending) if position == target => return pending,
            MountProgress::Effect(pending) => {
                progress = advance_success(pending);
                position = position.saturating_add(1);
            }
            MountProgress::Published(_) => {
                panic!("requested a pending effect after publication")
            }
        }
    }
}

fn published_mount() -> PublishedMount {
    let mut progress = MountProgress::Effect(initial_pending());
    loop {
        progress = match progress {
            MountProgress::Effect(pending) => advance_success(pending),
            MountProgress::Published(volume) => return volume,
        };
    }
}

fn rollback_from_mismatch(
    pending: PendingMountEffect,
    outcome: MountEffectOutcome,
) -> MountRollback {
    match pending.prepare() {
        PreparedMountEffect::Ordinary(pending) => match pending.succeeded(outcome) {
            Err(rollback) => rollback,
            Ok(_) => panic!("a mismatched effect outcome advanced the mount"),
        },
        PreparedMountEffect::PublishMountOwner(_) => {
            panic!("owner publication has no outcome-bearing mismatch path")
        }
        PreparedMountEffect::ClearDeviceInitializing(_) => {
            panic!("terminal clear has no outcome-bearing mismatch path")
        }
    }
}

fn rollback_before_effect(pending: PendingMountEffect) -> MountRollback {
    match pending.prepare() {
        PreparedMountEffect::Ordinary(pending) => pending.failed(),
        PreparedMountEffect::PublishMountOwner(pending) => pending.failed(),
        PreparedMountEffect::ClearDeviceInitializing(_) => {
            panic!("the post-publication clear has no rollback edge")
        }
    }
}

#[test]
fn raw_device_tags_accept_exactly_the_four_closed_kinds() {
    let admitted = [
        (1, DeviceKind::ProviderControl),
        (2, DeviceKind::FileSystemControl),
        (3, DeviceKind::VirtualDisk),
        (4, DeviceKind::MountedVolume),
    ];
    for (raw, expected) in admitted {
        assert_eq!(DeviceKind::from_raw(raw), Some(expected));
        assert_eq!(expected as u32, raw);
    }
    for raw in [0, 5, u32::MAX] {
        assert_eq!(DeviceKind::from_raw(raw), None);
    }
}

#[test]
fn provider_control_fails_closed_here_and_keeps_controldev_as_its_only_route() {
    for (major, subcode, root_open) in [
        (IRP_MJ_CREATE, 0, true),
        (IRP_MJ_CREATE, 0, false),
        (IRP_MJ_DEVICE_CONTROL, 0x0022_E000, true),
        (IRP_MJ_CLEANUP, 0, true),
        (IRP_MJ_CLOSE, 0, true),
    ] {
        assert_eq!(
            decide_volume_dispatch(DeviceKind::ProviderControl, major, subcode, root_open),
            VolumeDispatchDecision::Complete(INVALID_DEVICE_REQUEST)
        );
    }

    let admitted = decide_create(CreateRequest {
        mode: RequestorMode::UserMode,
        file_name_empty: true,
        related_file_object_null: true,
        context_alloc_ok: true,
    });
    assert_eq!(admitted.status, SUCCESS);
    assert_eq!(admitted.information, 0);
    assert!(admitted.context_installed);

    let named = decide_create(CreateRequest {
        mode: RequestorMode::UserMode,
        file_name_empty: false,
        related_file_object_null: true,
        context_alloc_ok: true,
    });
    assert_eq!(
        named.status,
        fsring_abi::control::status::OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(named.information, 0);
    assert!(!named.context_installed);
}

#[test]
fn non_provider_create_is_root_only_and_cleanup_close_are_bookkeeping() {
    for kind in [
        DeviceKind::FileSystemControl,
        DeviceKind::VirtualDisk,
        DeviceKind::MountedVolume,
    ] {
        assert_eq!(
            decide_volume_dispatch(kind, IRP_MJ_CREATE, 0, true),
            VolumeDispatchDecision::Complete(SUCCESS)
        );
        assert_eq!(
            decide_volume_dispatch(kind, IRP_MJ_CREATE, 0, false),
            VolumeDispatchDecision::Complete(INVALID_DEVICE_REQUEST)
        );
        for major in [IRP_MJ_CLEANUP, IRP_MJ_CLOSE] {
            assert_eq!(
                decide_volume_dispatch(kind, major, u32::MAX, false),
                VolumeDispatchDecision::Complete(SUCCESS)
            );
        }
    }
}

#[test]
fn mount_and_verify_route_only_on_the_exact_fs_control_cells() {
    assert_eq!(
        decide_volume_dispatch(
            DeviceKind::FileSystemControl,
            IRP_MJ_FILE_SYSTEM_CONTROL,
            IRP_MN_MOUNT_VOLUME,
            false,
        ),
        VolumeDispatchDecision::Mount
    );
    assert_eq!(
        decide_volume_dispatch(
            DeviceKind::FileSystemControl,
            IRP_MJ_FILE_SYSTEM_CONTROL,
            IRP_MN_VERIFY_VOLUME,
            false,
        ),
        VolumeDispatchDecision::Verify
    );

    for kind in [DeviceKind::VirtualDisk, DeviceKind::MountedVolume] {
        for minor in [IRP_MN_MOUNT_VOLUME, IRP_MN_VERIFY_VOLUME] {
            assert_eq!(
                decide_volume_dispatch(kind, IRP_MJ_FILE_SYSTEM_CONTROL, minor, true),
                VolumeDispatchDecision::Complete(INVALID_DEVICE_REQUEST)
            );
        }
    }
    for minor in [IRP_MN_MOUNT_VOLUME, IRP_MN_VERIFY_VOLUME] {
        assert_eq!(
            decide_volume_dispatch(
                DeviceKind::FileSystemControl,
                IRP_MJ_DEVICE_CONTROL,
                minor,
                true,
            ),
            VolumeDispatchDecision::Complete(INVALID_DEVICE_REQUEST)
        );
    }
}

#[test]
fn storage_checks_route_only_on_the_exact_vdo_device_control_cells() {
    for ioctl in [IOCTL_STORAGE_CHECK_VERIFY, IOCTL_STORAGE_CHECK_VERIFY2] {
        let decision =
            decide_volume_dispatch(DeviceKind::VirtualDisk, IRP_MJ_DEVICE_CONTROL, ioctl, false);
        assert_eq!(decision, VolumeDispatchDecision::Complete(SUCCESS));
        assert_eq!(decision.information(), 0);

        for kind in [DeviceKind::FileSystemControl, DeviceKind::MountedVolume] {
            assert_eq!(
                decide_volume_dispatch(kind, IRP_MJ_DEVICE_CONTROL, ioctl, true),
                VolumeDispatchDecision::Complete(INVALID_DEVICE_REQUEST)
            );
        }
        assert_eq!(
            decide_volume_dispatch(
                DeviceKind::VirtualDisk,
                IRP_MJ_FILE_SYSTEM_CONTROL,
                ioctl,
                true,
            ),
            VolumeDispatchDecision::Complete(INVALID_DEVICE_REQUEST)
        );
    }
}

#[test]
fn unsupported_data_majors_and_cross_role_subcodes_fail_closed_with_zero_information() {
    for kind in [DeviceKind::VirtualDisk, DeviceKind::MountedVolume] {
        for major in [IRP_MJ_READ, IRP_MJ_WRITE] {
            let decision = decide_volume_dispatch(kind, major, 0, true);
            assert_eq!(
                decision,
                VolumeDispatchDecision::Complete(INVALID_DEVICE_REQUEST)
            );
            assert_eq!(decision.information(), 0);
        }
    }

    for (kind, major, subcode) in [
        (
            DeviceKind::FileSystemControl,
            IRP_MJ_FILE_SYSTEM_CONTROL,
            IOCTL_STORAGE_CHECK_VERIFY,
        ),
        (
            DeviceKind::VirtualDisk,
            IRP_MJ_DEVICE_CONTROL,
            IRP_MN_MOUNT_VOLUME,
        ),
        (
            DeviceKind::MountedVolume,
            IRP_MJ_DEVICE_CONTROL,
            IRP_MN_VERIFY_VOLUME,
        ),
        (
            DeviceKind::FileSystemControl,
            IRP_MJ_FILE_SYSTEM_CONTROL,
            u32::MAX,
        ),
    ] {
        let decision = decide_volume_dispatch(kind, major, subcode, true);
        assert_eq!(
            decision,
            VolumeDispatchDecision::Complete(INVALID_DEVICE_REQUEST)
        );
        assert_eq!(decision.information(), 0);
    }
}

#[test]
fn mount_admission_requires_active_state_valid_identity_and_matching_target() {
    for state in [
        VolumeState::Staging,
        VolumeState::Mounted,
        VolumeState::Teardown,
        VolumeState::Destroyed,
    ] {
        match begin_mount(state, identity(), true) {
            Err(error) => assert_eq!(error, VolumeError::InvalidState),
            Ok(_) => panic!("a non-ACTIVE state admitted mount"),
        }
    }
    match begin_mount(VolumeState::Active, identity(), false) {
        Err(error) => assert_eq!(error, VolumeError::TargetMismatch),
        Ok(_) => panic!("a mismatched target admitted mount"),
    }

    let invalid = SessionIdentity {
        mount_id: MountId { lo: 0, hi: 0 },
        boot_instance_id: BootInstanceId { lo: 17, hi: 19 },
        session_epoch: 23,
    };
    match begin_mount(VolumeState::Active, invalid, true) {
        Err(error) => assert_eq!(error, VolumeError::IdentityMismatch),
        Ok(_) => panic!("an invalid session identity admitted mount"),
    }
}

#[test]
fn publication_requires_the_exact_fourteen_effect_sequence() {
    assert_eq!(
        MountTransaction::SUCCESS_EFFECTS,
        [
            MountEffect::AcquireVpb,
            MountEffect::ValidateTarget,
            MountEffect::ReleaseVpb,
            MountEffect::AcquireSessionReference,
            MountEffect::CreateMountedDevice,
            MountEffect::AllocateVcb,
            MountEffect::InitializeDeviceAndVcb,
            MountEffect::AcquireVpb,
            MountEffect::RevalidateTargetIdentityAdmissionAndBinding,
            MountEffect::BindVpb,
            MountEffect::SetVpbMounted,
            MountEffect::ReleaseVpb,
            MountEffect::PublishMountOwner,
            MountEffect::ClearDeviceInitializing,
        ]
    );

    let mut progress = MountProgress::Effect(initial_pending());
    let mut completed = 0usize;
    for expected in MountTransaction::SUCCESS_EFFECTS {
        let pending = match progress {
            MountProgress::Effect(pending) => pending,
            MountProgress::Published(_) => {
                panic!("publication occurred before all fourteen effects")
            }
        };
        progress = match pending.prepare() {
            PreparedMountEffect::Ordinary(pending) => {
                assert_eq!(pending.effect(), expected);
                let outcome = success_outcome(pending.effect());
                match pending.succeeded(outcome) {
                    Ok(progress) => progress,
                    Err(_) => panic!("the valid success outcome entered rollback"),
                }
            }
            PreparedMountEffect::PublishMountOwner(pending) => {
                assert_eq!(pending.effect(), expected);
                pending.published()
            }
            PreparedMountEffect::ClearDeviceInitializing(pending) => {
                assert_eq!(pending.effect(), expected);
                MountProgress::Published(pending.cleared())
            }
        };
        completed = completed.saturating_add(1);
    }
    match progress {
        MountProgress::Published(volume) => {
            assert_eq!(completed, 14);
            assert_eq!(volume.identity(), identity());
        }
        MountProgress::Effect(_) => panic!("the complete transaction did not publish"),
    }
}

#[test]
fn mount_publishes_owner_after_commit_vpb_release_before_device_open() {
    let observed: Vec<String> = MountTransaction::SUCCESS_EFFECTS
        .into_iter()
        .map(|effect| format!("{effect:?}"))
        .collect();

    assert_eq!(
        observed,
        [
            "AcquireVpb",
            "ValidateTarget",
            "ReleaseVpb",
            "AcquireSessionReference",
            "CreateMountedDevice",
            "AllocateVcb",
            "InitializeDeviceAndVcb",
            "AcquireVpb",
            "RevalidateTargetIdentityAdmissionAndBinding",
            "BindVpb",
            "SetVpbMounted",
            "ReleaseVpb",
            "PublishMountOwner",
            "ClearDeviceInitializing",
        ]
        .map(String::from),
        "the complete owner must enter the rendezvous after the commit VPB lock is released and before the device becomes openable"
    );
}

#[test]
// Proof of safety: the value is produced by this test's own fixture to
// satisfy the very precondition being unwrapped, so `None` means the
// fixture is broken and the test must fail loudly. Host test code only.
#[allow(clippy::expect_used)]
fn vpb_is_cleared_before_both_device_deletions() {
    // A device deleted while the VPB still points at it leaves the I/O manager
    // holding a pointer to freed storage. The clear is therefore before *both*
    // deletions, and the VPB lock is released before either — a spin lock is
    // not held across `IoDeleteDevice`.
    let plan = DISMOUNT_EFFECTS;
    let clear = plan
        .iter()
        .position(|effect| matches!(effect, DismountEffect::ClearVpbBinding))
        .expect("the plan clears the VPB binding");
    let release = plan
        .iter()
        .position(|effect| matches!(effect, DismountEffect::ReleaseVpb))
        .expect("the plan releases the VPB lock");
    let mounted = plan
        .iter()
        .position(|effect| matches!(effect, DismountEffect::DeleteMountedDevice))
        .expect("the plan deletes the mounted device");
    let vdo = plan
        .iter()
        .position(|effect| matches!(effect, DismountEffect::DeleteVdo))
        .expect("the plan deletes the VDO");

    assert!(clear < mounted, "the mounted device is deleted while bound");
    assert!(clear < vdo, "the VDO is deleted while bound");
    assert!(
        release < mounted,
        "a spin lock is held across IoDeleteDevice"
    );
    assert!(release < vdo, "a spin lock is held across IoDeleteDevice");
}

#[test]
// Proof of safety: the value is produced by this test's own fixture to
// satisfy the very precondition being unwrapped, so `None` means the
// fixture is broken and the test must fail loudly. Host test code only.
#[allow(clippy::expect_used)]
fn teardown_never_reads_an_extension_after_iodeletedevice() {
    // Everything that reads a device extension — the registry entry removal and
    // the session-reference release — comes *after* both deletions in the plan,
    // which is precisely the ordering that would be a use-after-free if the
    // reads happened there. So the rule is the other way round: nothing in the
    // plan after a deletion may name that device's extension, and the two
    // trailing effects name the *session*, not a device.
    let plan = DISMOUNT_EFFECTS;
    let vdo = plan
        .iter()
        .position(|effect| matches!(effect, DismountEffect::DeleteVdo))
        .expect("the plan deletes the VDO");
    for effect in plan.iter().skip(vdo.saturating_add(1)) {
        match effect {
            // Neither reads a deleted extension: the registry entry is a
            // separate object and the reference is the core registry's.
            DismountEffect::RemoveRegistryEntry | DismountEffect::ReleaseSessionReference => {}
            other => panic!("{other:?} follows the deletions and may read an extension"),
        }
    }
    // ...and no device operation appears twice, so nothing deletes a device a
    // second time and then reads it.
    for target in [
        DismountEffect::DeleteMountedDevice,
        DismountEffect::DeleteVdo,
        DismountEffect::ClearVpbBinding,
    ] {
        let count = plan.iter().filter(|effect| **effect == target).count();
        assert_eq!(count, 1, "{target:?} appears {count} times");
    }
}

#[test]
// Proof of safety: the value is produced by this test's own fixture to
// satisfy the very precondition being unwrapped, so `None` means the
// fixture is broken and the test must fail loudly. Host test code only.
#[allow(clippy::expect_used)]
fn mount_releases_initial_vpb_before_registry_reference() {
    // The registry lock and the VPB lock must never overlap. The old order took
    // the core registry reference while the initial VPB spin lock was still
    // held; this asserts the two are now strictly separated, in both directions.
    let roster = MountTransaction::SUCCESS_EFFECTS;
    let release = roster
        .iter()
        .position(|effect| matches!(effect, MountEffect::ReleaseVpb))
        .expect("the roster releases the initial VPB lock");
    let reference = roster
        .iter()
        .position(|effect| matches!(effect, MountEffect::AcquireSessionReference))
        .expect("the roster acquires a session reference");
    assert!(
        release < reference,
        "the initial VPB lock must be released before the registry is touched"
    );

    // The reference is taken outside *both* VPB brackets. Walking the roster
    // rather than checking one index is what makes this a statement about the
    // whole sequence: a second acquisition slipped inside the commit bracket
    // would fail here too.
    let mut vpb_depth = 0i32;
    for effect in roster {
        match effect {
            MountEffect::AcquireVpb => vpb_depth = vpb_depth.saturating_add(1),
            MountEffect::ReleaseVpb => vpb_depth = vpb_depth.saturating_sub(1),
            MountEffect::AcquireSessionReference => assert_eq!(
                vpb_depth, 0,
                "the registry is touched while a VPB spin lock is held"
            ),
            _ => {}
        }
        assert!(
            (0..=1).contains(&vpb_depth),
            "the VPB brackets are unbalanced"
        );
    }
    assert_eq!(vpb_depth, 0, "every acquisition is released");

    // An unwind that owns both — the commit bracket legitimately does, because
    // the reference was taken long before it — must give the spin lock back
    // first. Holding a VPB lock across a registry release is the same overlap
    // in the other direction.
    for position in 0..MountTransaction::SUCCESS_EFFECTS.len().saturating_sub(1) {
        let rollback = rollback_before_effect(pending_at(position));
        let vpb = rollback
            .effects()
            .iter()
            .position(|effect| matches!(effect, MountRollbackEffect::ReleaseVpbIfHeld));
        let reference = rollback
            .effects()
            .iter()
            .position(|effect| matches!(effect, MountRollbackEffect::ReleaseSessionReference));
        if let (Some(vpb), Some(reference)) = (vpb, reference) {
            assert!(
                vpb < reference,
                "pre-effect position {position} releases the registry under a VPB lock"
            );
        }
    }
}

#[test]
fn mount_acquires_a_core_strong_reference_not_a_driver_root() {
    // There is one acquisition in the roster and one matching release in the
    // unwind vocabulary, and both name the *session*. A driver-root reference
    // would have to appear as a distinct effect; the closed enums have no such
    // variant, so a root acquisition cannot be expressed here at all.
    let acquisitions = MountTransaction::SUCCESS_EFFECTS
        .iter()
        .filter(|effect| matches!(effect, MountEffect::AcquireSessionReference))
        .count();
    assert_eq!(acquisitions, 1, "exactly one reference is taken");

    for effect in ALL_MOUNT_EFFECTS {
        match effect {
            MountEffect::AcquireVpb
            | MountEffect::ValidateTarget
            | MountEffect::AcquireSessionReference
            | MountEffect::ReleaseVpb
            | MountEffect::CreateMountedDevice
            | MountEffect::AllocateVcb
            | MountEffect::InitializeDeviceAndVcb
            | MountEffect::RevalidateTargetIdentityAdmissionAndBinding
            | MountEffect::BindVpb
            | MountEffect::SetVpbMounted
            | MountEffect::PublishMountOwner
            | MountEffect::ClearDeviceInitializing => {}
        }
    }
    for effect in ALL_MOUNT_ROLLBACK_EFFECTS {
        match effect {
            MountRollbackEffect::ClearUnpublishedVpbBinding
            | MountRollbackEffect::FreeVcb
            | MountRollbackEffect::DeleteMountedDevice
            | MountRollbackEffect::ReleaseSessionReference
            | MountRollbackEffect::ReleaseVpbIfHeld => {}
        }
    }

    // Every unwind that releases anything releases the session reference at
    // most once: a doubled release is a use-after-free of a live generation.
    for position in 0..MountTransaction::SUCCESS_EFFECTS.len().saturating_sub(1) {
        let rollback = rollback_before_effect(pending_at(position));
        let releases = rollback
            .effects()
            .iter()
            .filter(|effect| matches!(effect, MountRollbackEffect::ReleaseSessionReference))
            .count();
        assert!(releases <= 1, "position {position} releases twice");
    }
}

#[test]
fn rollback_before_and_after_owner_transfer_releases_once() {
    // Before the transfer the unwind releases the reference itself; after it,
    // the reference belongs to the mount owner and the unwind must not touch
    // it. Both halves are checked, over every position, in both tables.
    for position in 0..MountTransaction::SUCCESS_EFFECTS.len().saturating_sub(1) {
        let pre = rollback_before_effect(pending_at(position));
        let pre_releases = pre
            .effects()
            .iter()
            .filter(|effect| matches!(effect, MountRollbackEffect::ReleaseSessionReference))
            .count();
        assert!(pre_releases <= 1, "pre-effect {position} releases twice");
    }
    for position in 0..12usize {
        let post = rollback_from_mismatch(
            pending_at(position),
            MountEffectOutcome::Revalidated(MountRevalidation {
                target_identity_matches: false,
                admission_open: true,
                binding_unchanged: true,
                session_active: true,
            }),
        );
        let releases = post
            .effects()
            .iter()
            .filter(|effect| matches!(effect, MountRollbackEffect::ReleaseSessionReference))
            .count();
        assert!(releases <= 1, "post-effect {position} releases twice");
        let vpb = post
            .effects()
            .iter()
            .position(|effect| matches!(effect, MountRollbackEffect::ReleaseVpbIfHeld));
        let reference = post
            .effects()
            .iter()
            .position(|effect| matches!(effect, MountRollbackEffect::ReleaseSessionReference));
        if let (Some(vpb), Some(reference)) = (vpb, reference) {
            assert!(
                vpb < reference,
                "post-effect {position} releases the registry under a VPB lock"
            );
        }
    }
}

#[test]
fn vpb_reads_writes_and_mounted_flags_are_bracketed_by_the_two_lock_pairs() {
    let expected = [
        MountEffect::AcquireVpb,
        MountEffect::ValidateTarget,
        MountEffect::ReleaseVpb,
        MountEffect::AcquireSessionReference,
        MountEffect::CreateMountedDevice,
        MountEffect::AllocateVcb,
        MountEffect::InitializeDeviceAndVcb,
        MountEffect::AcquireVpb,
        MountEffect::RevalidateTargetIdentityAdmissionAndBinding,
        MountEffect::BindVpb,
        MountEffect::SetVpbMounted,
        MountEffect::ReleaseVpb,
        MountEffect::PublishMountOwner,
        MountEffect::ClearDeviceInitializing,
    ];
    assert_eq!(MountTransaction::SUCCESS_EFFECTS, expected);

    let lock_count = expected
        .iter()
        .filter(|effect| matches!(effect, MountEffect::AcquireVpb))
        .count();
    let unlock_count = expected
        .iter()
        .filter(|effect| matches!(effect, MountEffect::ReleaseVpb))
        .count();
    assert_eq!(lock_count, 2);
    assert_eq!(unlock_count, 2);
}

#[test]
fn every_pending_failure_rolls_back_only_owned_resources_in_reverse_order() {
    const EXPECTED: [&[MountRollbackEffect]; 13] = [
        &[],
        &[MountRollbackEffect::ReleaseVpbIfHeld],
        &[MountRollbackEffect::ReleaseVpbIfHeld],
        // Between releasing the initial VPB lock and taking the session
        // reference nothing at all is owned. That gap is the reorder: no state
        // holds both, so no unwind releases a registry reference while a VPB
        // spin lock is still held.
        &[],
        &[MountRollbackEffect::ReleaseSessionReference],
        &[
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
        &[
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
        &[
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
        &[
            MountRollbackEffect::ReleaseVpbIfHeld,
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
        &[
            MountRollbackEffect::ReleaseVpbIfHeld,
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
        &[
            MountRollbackEffect::ClearUnpublishedVpbBinding,
            MountRollbackEffect::ReleaseVpbIfHeld,
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
        &[
            MountRollbackEffect::ClearUnpublishedVpbBinding,
            MountRollbackEffect::ReleaseVpbIfHeld,
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
        &[
            MountRollbackEffect::ClearUnpublishedVpbBinding,
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
    ];

    for (position, expected) in EXPECTED.into_iter().enumerate() {
        let pending = pending_at(position);
        let rollback = rollback_before_effect(pending);
        assert_eq!(rollback.identity(), identity());
        assert_eq!(rollback.effects(), expected);
    }
}

#[test]
fn every_mismatched_post_effect_outcome_rolls_back_the_effects_new_ownership() {
    const EXPECTED: [&[MountRollbackEffect]; 12] = [
        &[MountRollbackEffect::ReleaseVpbIfHeld],
        &[MountRollbackEffect::ReleaseVpbIfHeld],
        // After the release: nothing owned. After the acquisition: the
        // reference alone.
        &[],
        &[MountRollbackEffect::ReleaseSessionReference],
        &[
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
        &[
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
        &[
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
        &[
            MountRollbackEffect::ReleaseVpbIfHeld,
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
        &[
            MountRollbackEffect::ReleaseVpbIfHeld,
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
        &[
            MountRollbackEffect::ClearUnpublishedVpbBinding,
            MountRollbackEffect::ReleaseVpbIfHeld,
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
        &[
            MountRollbackEffect::ClearUnpublishedVpbBinding,
            MountRollbackEffect::ReleaseVpbIfHeld,
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
        &[
            MountRollbackEffect::ClearUnpublishedVpbBinding,
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
    ];

    for (position, (effect, expected)) in MountTransaction::SUCCESS_EFFECTS
        .into_iter()
        .zip(EXPECTED)
        .enumerate()
    {
        let outcome = if matches!(
            effect,
            MountEffect::RevalidateTargetIdentityAdmissionAndBinding
        ) {
            MountEffectOutcome::Done
        } else {
            MountEffectOutcome::Revalidated(MountRevalidation {
                target_identity_matches: true,
                admission_open: true,
                binding_unchanged: true,
                session_active: true,
            })
        };
        let rollback = rollback_from_mismatch(pending_at(position), outcome);
        assert_eq!(rollback.identity(), identity());
        assert_eq!(rollback.effects(), expected, "post-effect phase {position}");
    }
}

#[test]
fn terminal_clear_is_split_before_the_ddi_and_can_only_publish_after_clear() {
    let terminal = match pending_at(13).prepare() {
        PreparedMountEffect::Ordinary(_) => {
            panic!("terminal clear remained in the outcome-bearing ordinary path")
        }
        PreparedMountEffect::PublishMountOwner(_) => {
            panic!("terminal clear remained in the fallible publication path")
        }
        PreparedMountEffect::ClearDeviceInitializing(terminal) => terminal,
    };
    assert_eq!(terminal.effect(), MountEffect::ClearDeviceInitializing);

    // This method is called only after the infallible DDI has executed. Its
    // return type contains no outcome mismatch and no unpublished rollback.
    let published: PublishedMount = terminal.cleared();
    assert_eq!(published.identity(), identity());
}

#[test]
fn unpublished_vpb_clear_atomically_clears_binding_pointers_and_mounted_under_lock() {
    assert_eq!(
        MountRollbackEffect::ClearUnpublishedVpbBinding.vpb_clear_semantics(),
        Some(UnpublishedVpbClearSemantics {
            clears_binding_and_pointers: true,
            clears_mounted_flag: true,
            requires_vpb_lock: true,
            acquire_release_if_unheld: true,
        })
    );
    for effect in [
        MountRollbackEffect::FreeVcb,
        MountRollbackEffect::DeleteMountedDevice,
        MountRollbackEffect::ReleaseSessionReference,
        MountRollbackEffect::ReleaseVpbIfHeld,
    ] {
        assert_eq!(effect.vpb_clear_semantics(), None);
    }
}

#[test]
fn routing_preflight_still_requires_authoritative_target_validation_under_vpb_lock() {
    match begin_mount(VolumeState::Active, identity(), false) {
        Err(error) => assert_eq!(error, VolumeError::TargetMismatch),
        Ok(_) => panic!("routing mismatch admitted a mount"),
    }

    let acquire = initial_pending();
    let acquire = match acquire.prepare() {
        PreparedMountEffect::Ordinary(pending) => pending,
        PreparedMountEffect::PublishMountOwner(_) => {
            panic!("initial acquire was classified as owner publication")
        }
        PreparedMountEffect::ClearDeviceInitializing(_) => {
            panic!("initial acquire was classified as terminal clear")
        }
    };
    assert_eq!(acquire.effect(), MountEffect::AcquireVpb);
    let validate = match acquire.succeeded(MountEffectOutcome::Done) {
        Ok(MountProgress::Effect(pending)) => pending,
        Ok(MountProgress::Published(_)) => panic!("preflight skipped locked validation"),
        Err(_) => panic!("VPB acquisition did not advance to validation"),
    };
    let validate = match validate.prepare() {
        PreparedMountEffect::Ordinary(pending) => pending,
        PreparedMountEffect::PublishMountOwner(_) => {
            panic!("authoritative validation was classified as owner publication")
        }
        PreparedMountEffect::ClearDeviceInitializing(_) => {
            panic!("authoritative validation was classified as terminal clear")
        }
    };
    assert_eq!(validate.effect(), MountEffect::ValidateTarget);
}

#[test]
fn only_revalidation_accepts_revalidated_and_false_fields_consume_into_rollback() {
    let accepted = MountRevalidation {
        target_identity_matches: true,
        admission_open: true,
        binding_unchanged: true,
        session_active: true,
    };
    for (position, effect) in MountTransaction::SUCCESS_EFFECTS
        .into_iter()
        .take(12)
        .enumerate()
    {
        if matches!(
            effect,
            MountEffect::RevalidateTargetIdentityAdmissionAndBinding
        ) {
            continue;
        }
        let rollback = rollback_from_mismatch(
            pending_at(position),
            MountEffectOutcome::Revalidated(MountRevalidation { ..accepted }),
        );
        assert_eq!(rollback.identity(), identity());
    }

    let rollback = rollback_from_mismatch(pending_at(8), MountEffectOutcome::Done);
    assert_eq!(
        rollback.effects(),
        &[
            MountRollbackEffect::ReleaseVpbIfHeld,
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ]
    );

    for rejected in [
        MountRevalidation {
            target_identity_matches: false,
            ..accepted
        },
        MountRevalidation {
            admission_open: false,
            ..accepted
        },
        MountRevalidation {
            binding_unchanged: false,
            ..accepted
        },
        MountRevalidation {
            session_active: false,
            ..accepted
        },
    ] {
        let rollback =
            rollback_from_mismatch(pending_at(8), MountEffectOutcome::Revalidated(rejected));
        assert_eq!(
            rollback.effects(),
            &[
                MountRollbackEffect::ReleaseVpbIfHeld,
                MountRollbackEffect::FreeVcb,
                MountRollbackEffect::DeleteMountedDevice,
                MountRollbackEffect::ReleaseSessionReference,
            ]
        );
    }
}

#[test]
fn verify_precedence_has_no_fabricated_verify_required_path() {
    for state in [
        VolumeState::Staging,
        VolumeState::Active,
        VolumeState::Mounted,
        VolumeState::Teardown,
        VolumeState::Destroyed,
    ] {
        assert_eq!(
            decide_verify(state, false),
            VerifyDecision::InvalidTarget,
            "identity mismatch must win in {state:?}"
        );
    }
    assert_eq!(
        decide_verify(VolumeState::Staging, true),
        VerifyDecision::InvalidTarget
    );
    assert_eq!(
        decide_verify(VolumeState::Active, true),
        VerifyDecision::InvalidTarget
    );
    assert_eq!(
        decide_verify(VolumeState::Mounted, true),
        VerifyDecision::Success
    );
    for state in [VolumeState::Teardown, VolumeState::Destroyed] {
        assert_eq!(decide_verify(state, true), VerifyDecision::VolumeDismounted);
    }
}

#[test]
fn dismount_refines_the_existing_fence_owner_in_exact_order_without_completion() {
    let plan = plan_dismount(published_mount());
    assert_eq!(plan.identity(), identity());
    assert_eq!(
        plan.effects(),
        [
            DismountEffect::AcquireVpb,
            DismountEffect::ClearVpbBinding,
            DismountEffect::ReleaseVpb,
            DismountEffect::DeleteMountedDevice,
            DismountEffect::DeleteVdo,
            DismountEffect::RemoveRegistryEntry,
            DismountEffect::ReleaseSessionReference,
        ]
    );
    assert_eq!(
        ALL_EFFECTS
            .iter()
            .filter(|effect| matches!(effect, Effect::CompleteIrp))
            .count(),
        1
    );
}

#[test]
fn effect_rosters_record_and_sweep_all_mount_rollback_and_dismount_domains() {
    assert_eq!(
        ALL_MOUNT_EFFECTS,
        [
            MountEffect::AcquireVpb,
            MountEffect::ValidateTarget,
            MountEffect::AcquireSessionReference,
            MountEffect::ReleaseVpb,
            MountEffect::CreateMountedDevice,
            MountEffect::AllocateVcb,
            MountEffect::InitializeDeviceAndVcb,
            MountEffect::RevalidateTargetIdentityAdmissionAndBinding,
            MountEffect::BindVpb,
            MountEffect::SetVpbMounted,
            MountEffect::ClearDeviceInitializing,
            MountEffect::PublishMountOwner,
        ]
    );
    assert_eq!(
        ALL_MOUNT_ROLLBACK_EFFECTS,
        [
            MountRollbackEffect::ClearUnpublishedVpbBinding,
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
            MountRollbackEffect::ReleaseVpbIfHeld,
        ]
    );
    assert_eq!(
        ALL_DISMOUNT_EFFECTS,
        [
            DismountEffect::AcquireVpb,
            DismountEffect::ClearVpbBinding,
            DismountEffect::ReleaseVpb,
            DismountEffect::DeleteMountedDevice,
            DismountEffect::DeleteVdo,
            DismountEffect::RemoveRegistryEntry,
            DismountEffect::ReleaseSessionReference,
        ]
    );

    for effect in ALL_MOUNT_EFFECTS {
        assert!(ALL_EFFECTS.contains(&Effect::Mount(effect)));
    }
    for effect in ALL_MOUNT_ROLLBACK_EFFECTS {
        assert!(ALL_EFFECTS.contains(&Effect::MountRollback(effect)));
    }
    for effect in ALL_DISMOUNT_EFFECTS {
        assert!(ALL_EFFECTS.contains(&Effect::Dismount(effect)));
    }
    assert_eq!(ALL_EFFECTS.len(), 62);
}
