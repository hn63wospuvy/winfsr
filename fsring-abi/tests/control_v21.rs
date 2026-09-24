use core::{
    convert::TryFrom,
    mem::{align_of, offset_of, size_of},
};

use fsring_abi::{
    codec::{try_decode, try_encode, Pod},
    control::{
        self, enter_request_flags, enter_result_flags, ioctl_function, is_legal_create_status,
        is_legal_ioctl_status, retire_mount_action, retire_mount_state, status, view_access,
        view_kind, AttachV1, DetachRequestV1, DonateBackingV2, EnterRequestV1, EnterResultV1,
        NotificationCreditV1, RetireMountResultV1, RetireMountV1, SessionResultV1, SetupRequestV1,
        SlotClassRequest, UserViewDesc, CONTROL_DEVICE_SDDL, CONTROL_IOCTL_ACCESS,
        DETACH_REQUEST_V1_SIZE, DONATE_BACKING_V2_PREFIX_SIZE, DONATE_BACKING_VERSION_V2,
        ENTER_REQUEST_V1_SIZE, ENTER_RESULT_V1_PREFIX_SIZE, ENTER_TIMEOUT_INFINITE,
        FILE_DEVICE_UNKNOWN, FILE_READ_ACCESS, FILE_WRITE_ACCESS, FSRING_MOUNT_CONTROL,
        GLOBAL_RING_INDEX, IOCTL_FSRING_ATTACH, IOCTL_FSRING_DETACH, IOCTL_FSRING_DONATE_BACKING,
        IOCTL_FSRING_DONATE_SECURITY_CONTEXT, IOCTL_FSRING_ENTER, IOCTL_FSRING_RETIRE_MOUNT,
        IOCTL_FSRING_SETUP, METHOD_BUFFERED, NOTIFICATION_CREDIT_V1_SIZE,
        RETIRE_MOUNT_RESULT_V1_SIZE, RETIRE_MOUNT_V1_SIZE, SESSION_RESULT_V1_PREFIX_SIZE,
        SETUP_REQUEST_V1_SIZE, SLOT_CLASS_REQUEST_SIZE, USER_VIEW_DESC_SIZE,
    },
    features::{
        os_cap, protocol_feature, select_features_v21, validate_implementation_protocol_mask,
        FeatureSelection, FeatureSelectionError, FeatureSelectionInput, ImplementationMaskError,
        PlatformProfile,
    },
    ids::{FileId, MountId, ReqId},
    layout::{RegionDesc, SlotClassDesc, SLOT_CLASS_COUNT},
    limits::{
        MAX_BACKING_PATH_BYTES, MAX_BACKING_SECTOR_SIZE, MAX_ENTER_CQ_BUDGET,
        MAX_NOTIFICATION_CREDITS_PER_RING, MAX_NOTIFICATION_CREDITS_PER_SESSION,
        MAX_NOTIFICATION_CREDIT_BYTES, MAX_NOTIFICATION_CREDIT_SIZE, MAX_SECTION_BYTES,
        MAX_SLOT_COUNT, MAX_SLOT_SIZE, MIN_BACKING_PATH_BYTES, MIN_BACKING_SECTOR_SIZE,
        MIN_CONTROL_SLOT_SIZE, MIN_K2U_PROGRESS_SLOTS_PER_RING, MIN_NOTIFICATION_CREDIT_SIZE,
        MIN_U2K_PROGRESS_SLOTS_PER_RING, RESTART_GRACE_TIMEOUT_MS, USER_VIEW_OFFSET_ALIGNMENT,
    },
    msgs::{
        buffer_access, buffer_kind, BlobSlice, BufferRef, ControlHeader, DonateBackingV1,
        CONTROL_VERSION_V1,
    },
    slots::{
        resolve_slot, validate_buffer_ref, validate_grant_metadata, validate_slot_arena,
        validate_zeroed_padding, BufferRefError, BufferRefPolicy, BufferRefRule, EmptyBufferRule,
        GrantCapability, GrantMetadata, GrantOwner, GrantState, ResolvedSlot, SlotDirection,
        SlotLayoutError, SlotToken, ValidatedBuffer,
    },
    validate::{
        enter_result_size_v1, resolve_blob_slice, session_result_size_v1, validate_attach_v1,
        validate_control_prefix, validate_control_prefix_with_schemas, validate_detach_request_v1,
        validate_donate_backing_v2, validate_donate_security_context_v1, validate_enter_request_v1,
        validate_enter_result_v1, validate_retire_mount_result_v1, validate_retire_mount_v1,
        validate_section_size_v21, validate_session_result_v1, validate_setup_request_v1,
        validate_tail_coverage, AttachExpectation, BlobSliceRule, CheckedRange32, CheckedRange64,
        ControlError, ControlVersionSchema, EmptySliceRule, RingViewLayout, SessionContextError,
        SessionIdentity, SessionValidationError, SessionViewLayout, TailSegment, TailSegmentKind,
        ValidatedDonateBacking, ValidatedEnterResult, ValidatedSessionResult,
        ValidatedSetupRequest, ValidatedTopology,
    },
    BootInstanceId, FeatureSet, RetireToken,
};

fn blob(struct_size: u32, version: u16, flags: u16) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&struct_size.to_le_bytes());
    bytes[4..6].copy_from_slice(&version.to_le_bytes());
    bytes[6..8].copy_from_slice(&flags.to_le_bytes());
    bytes
}

const ZERO_CLASS: SlotClassDesc = SlotClassDesc {
    slot_size: 0,
    slot_count: 0,
    data_offset: 0,
};

fn one_class(
    slot_size: u32,
    slot_count: u32,
    data_offset: u64,
) -> [SlotClassDesc; SLOT_CLASS_COUNT] {
    [
        SlotClassDesc {
            slot_size,
            slot_count,
            data_offset,
        },
        ZERO_CLASS,
        ZERO_CLASS,
        ZERO_CLASS,
    ]
}

fn canonical_owner() -> GrantOwner {
    GrantOwner::Request(ReqId::try_new(1, 0).unwrap())
}

fn canonical_none() -> BufferRef {
    BufferRef {
        token: 0,
        offset: 0,
        length: 0,
        kind: buffer_kind::NONE,
        access: 0,
        reserved: 0,
    }
}

fn canonical_resolved_slot(direction: SlotDirection) -> ResolvedSlot {
    let arena = validate_slot_arena(
        direction,
        196_608,
        RegionDesc {
            offset: 65_536,
            length: 65_536,
        },
        [
            SlotClassDesc {
                slot_size: 256,
                slot_count: 2,
                data_offset: 65_536,
            },
            SlotClassDesc {
                slot_size: 512,
                slot_count: 1,
                data_offset: 66_048,
            },
            ZERO_CLASS,
            ZERO_CLASS,
        ],
    )
    .unwrap();
    resolve_slot(&arena, SlotToken::try_new(0, 1, 7).unwrap()).unwrap()
}

fn canonical_slot_grant(direction: SlotDirection, state: GrantState) -> GrantMetadata {
    let slot = canonical_resolved_slot(direction);
    let access = match direction {
        SlotDirection::K2u => buffer_access::K2U_READ_ONLY,
        SlotDirection::U2k => buffer_access::U2K_WRITE,
    };
    GrantMetadata {
        capability: GrantCapability::Slot(slot),
        session_epoch: 9,
        owner: canonical_owner(),
        access,
        maximum: CheckedRange64 {
            start: 16,
            end: 224,
        },
        state,
        issued: BufferRef {
            token: slot.token().raw(),
            offset: 32,
            length: 128,
            kind: buffer_kind::SLOT,
            access,
            reserved: 0,
        },
    }
}

fn canonical_mapping_grant(access: u16, state: GrantState) -> GrantMetadata {
    GrantMetadata {
        capability: GrantCapability::Mapping {
            token: 4,
            length: 256,
        },
        session_epoch: 9,
        owner: canonical_owner(),
        access,
        maximum: CheckedRange64 {
            start: 16,
            end: 224,
        },
        state,
        issued: BufferRef {
            token: 4,
            offset: 32,
            length: 128,
            kind: buffer_kind::MAPPING,
            access,
            reserved: 0,
        },
    }
}

fn grant_rule(
    grant: &GrantMetadata,
    policy: BufferRefPolicy,
    empty: EmptyBufferRule,
) -> BufferRefRule<'_> {
    BufferRefRule::Grant {
        grant,
        expected_session_epoch: grant.session_epoch,
        expected_owner: grant.owner,
        policy,
        empty,
    }
}

#[test]
fn control_primitives_keep_exact_layouts() {
    assert_eq!(
        (size_of::<ControlHeader>(), align_of::<ControlHeader>()),
        (8, 4)
    );
    assert_eq!((size_of::<BufferRef>(), align_of::<BufferRef>()), (24, 8));
    assert_eq!((size_of::<BlobSlice>(), align_of::<BlobSlice>()), (8, 4));
    assert_eq!(offset_of!(BlobSlice, offset), 0);
    assert_eq!(offset_of!(BlobSlice, length), 4);
}

#[test]
fn uniform_control_prefix_has_exact_precedence_and_snapshot_binding() {
    assert_eq!(
        validate_control_prefix(&[0; 7], &[], 0, 7),
        Err(ControlError::ShortPrefix),
    );

    let valid = blob(8, CONTROL_VERSION_V1, 0);
    assert_eq!(
        validate_control_prefix(&valid[..8], &[], 0, 8),
        Err(ControlError::UnsupportedSchema),
    );
    assert_eq!(
        validate_control_prefix(&valid[..8], &[0], 0, 8),
        Err(ControlError::UnsupportedSchema),
    );
    assert_eq!(
        validate_control_prefix(&valid[..8], &[1, 1], 0, 8),
        Err(ControlError::UnsupportedSchema),
    );
    assert_eq!(
        validate_control_prefix(&valid[..8], &[1], 0, 7),
        Err(ControlError::UnsupportedSchema),
    );

    let unknown_bad_everything = blob(0, 2, u16::MAX);
    assert_eq!(
        validate_control_prefix(&unknown_bad_everything[..8], &[1], 0, 24),
        Err(ControlError::RevisionMismatch),
    );
    let flags_before_size = blob(0, 1, 1);
    assert_eq!(
        validate_control_prefix(&flags_before_size[..8], &[1], 0, 24),
        Err(ControlError::UnsupportedRequiredFlags),
    );
    let too_small = blob(23, 1, 0);
    assert_eq!(
        validate_control_prefix(&too_small[..24], &[1], 0, 24),
        Err(ControlError::InvalidSize),
    );
    let exceeds = blob(25, 1, 0);
    assert_eq!(
        validate_control_prefix(&exceeds[..24], &[1], 0, 24),
        Err(ControlError::InvalidSize),
    );

    let accepted = blob(8, 1, 0x0002);
    let prefix = validate_control_prefix(&accepted[..16], &[1], 0x0002, 8).unwrap();
    assert_eq!(prefix.header().required_flags, 0x0002);
    assert_eq!(prefix.struct_size(), 8);
    assert_eq!(prefix.bytes(), &accepted[..8]);
}

#[test]
fn schema_table_uses_version_specific_masks_and_minima() {
    let valid = blob(8, 1, 0);
    assert_eq!(
        validate_control_prefix_with_schemas(&[0; 7], &[]),
        Err(ControlError::ShortPrefix),
    );
    assert_eq!(
        validate_control_prefix_with_schemas(&valid[..8], &[]),
        Err(ControlError::UnsupportedSchema),
    );
    for schemas in [
        [
            ControlVersionSchema {
                version: 0,
                accepted_required_flags: 0,
                minimum_size: 8,
            },
            ControlVersionSchema {
                version: 2,
                accepted_required_flags: 0,
                minimum_size: 8,
            },
        ],
        [
            ControlVersionSchema {
                version: 1,
                accepted_required_flags: 0,
                minimum_size: 7,
            },
            ControlVersionSchema {
                version: 2,
                accepted_required_flags: 0,
                minimum_size: 8,
            },
        ],
        [ControlVersionSchema {
            version: 1,
            accepted_required_flags: 0,
            minimum_size: 8,
        }; 2],
    ] {
        assert_eq!(
            validate_control_prefix_with_schemas(&valid[..8], &schemas),
            Err(ControlError::UnsupportedSchema),
        );
    }

    let schemas = [
        ControlVersionSchema {
            version: 1,
            accepted_required_flags: 0,
            minimum_size: 8,
        },
        ControlVersionSchema {
            version: 2,
            accepted_required_flags: 1,
            minimum_size: 16,
        },
    ];
    let v2_too_small = blob(8, 2, 0);
    assert_eq!(
        validate_control_prefix_with_schemas(&v2_too_small[..8], &schemas),
        Err(ControlError::InvalidSize),
    );
    let v2_bad_flags = blob(8, 2, 2);
    assert_eq!(
        validate_control_prefix_with_schemas(&v2_bad_flags[..8], &schemas),
        Err(ControlError::UnsupportedRequiredFlags),
    );
    let v2_unknown = blob(8, 3, u16::MAX);
    assert_eq!(
        validate_control_prefix_with_schemas(&v2_unknown[..8], &schemas),
        Err(ControlError::RevisionMismatch),
    );
    let v2 = blob(16, 2, 1);
    let parsed = validate_control_prefix_with_schemas(&v2[..16], &schemas).unwrap();
    assert_eq!(parsed.header().struct_version, 2);
    assert_eq!(parsed.struct_size(), 16);
    assert_eq!(parsed.bytes(), &v2[..16]);
}

#[test]
fn blob_slice_rules_are_schema_specific_and_checked() {
    let absent = BlobSlice {
        offset: 0,
        length: 0,
    };
    let optional = BlobSliceRule {
        minimum_offset: 8,
        alignment: 4,
        empty: EmptySliceRule::CanonicalAbsent,
    };
    let required = BlobSliceRule {
        empty: EmptySliceRule::Forbidden,
        ..optional
    };

    assert_eq!(resolve_blob_slice(absent, 16, optional), Ok(None));
    assert_eq!(
        resolve_blob_slice(absent, 16, required),
        Err(ControlError::InvalidRange),
    );
    assert_eq!(
        resolve_blob_slice(
            absent,
            16,
            BlobSliceRule {
                alignment: 0,
                ..optional
            }
        ),
        Err(ControlError::UnsupportedSchema),
    );
    assert_eq!(
        resolve_blob_slice(
            absent,
            16,
            BlobSliceRule {
                alignment: 3,
                ..optional
            }
        ),
        Err(ControlError::UnsupportedSchema),
    );
    assert_eq!(
        resolve_blob_slice(
            BlobSlice {
                offset: 4,
                length: 4
            },
            16,
            required
        ),
        Err(ControlError::InvalidRange),
    );
    assert_eq!(
        resolve_blob_slice(
            BlobSlice {
                offset: 10,
                length: 2
            },
            16,
            required
        ),
        Err(ControlError::InvalidAlignment),
    );
    assert_eq!(
        resolve_blob_slice(
            BlobSlice {
                offset: 12,
                length: 0
            },
            16,
            required
        ),
        Err(ControlError::InvalidRange),
    );
    assert_eq!(
        resolve_blob_slice(
            BlobSlice {
                offset: u32::MAX - 1,
                length: 4
            },
            u32::MAX,
            BlobSliceRule {
                minimum_offset: 8,
                alignment: 1,
                empty: EmptySliceRule::Forbidden
            },
        ),
        Err(ControlError::InvalidRange),
    );
    assert_eq!(
        resolve_blob_slice(
            BlobSlice {
                offset: 12,
                length: 8
            },
            16,
            required
        ),
        Err(ControlError::InvalidRange),
    );
    assert_eq!(
        resolve_blob_slice(
            BlobSlice {
                offset: 12,
                length: 4
            },
            16,
            required
        ),
        Ok(Some(CheckedRange32 { start: 12, end: 16 })),
    );
}

#[test]
fn tail_coverage_classifies_every_byte_of_the_bound_snapshot() {
    let mut snapshot = [0u8; 25];
    snapshot[..8].copy_from_slice(&blob(24, 1, 0)[..8]);
    snapshot[16..20].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    snapshot[24] = 0xff;
    let prefix = validate_control_prefix(&snapshot, &[1], 0, 16).unwrap();
    assert_eq!(prefix.bytes(), &snapshot[..24]);

    let segments = [
        TailSegment {
            range: CheckedRange32 { start: 16, end: 20 },
            kind: TailSegmentKind::Payload,
        },
        TailSegment {
            range: CheckedRange32 { start: 20, end: 24 },
            kind: TailSegmentKind::ZeroPadding,
        },
    ];
    assert_eq!(
        validate_tail_coverage(&prefix, 16, &segments, false),
        Ok(())
    );
    assert_eq!(
        validate_tail_coverage(&prefix, 7, &segments, false),
        Err(ControlError::UnsupportedSchema),
    );
    assert_eq!(
        validate_tail_coverage(&prefix, 25, &segments, false),
        Err(ControlError::InvalidRange),
    );

    let gap = [TailSegment {
        range: CheckedRange32 { start: 17, end: 24 },
        kind: TailSegmentKind::Payload,
    }];
    assert_eq!(
        validate_tail_coverage(&prefix, 16, &gap, false),
        Err(ControlError::UnclassifiedTail),
    );
    let empty = [TailSegment {
        range: CheckedRange32 { start: 16, end: 16 },
        kind: TailSegmentKind::Payload,
    }];
    assert_eq!(
        validate_tail_coverage(&prefix, 16, &empty, false),
        Err(ControlError::InvalidRange),
    );
    let overlap = [
        TailSegment {
            range: CheckedRange32 { start: 16, end: 21 },
            kind: TailSegmentKind::Payload,
        },
        TailSegment {
            range: CheckedRange32 { start: 20, end: 24 },
            kind: TailSegmentKind::Payload,
        },
    ];
    assert_eq!(
        validate_tail_coverage(&prefix, 16, &overlap, false),
        Err(ControlError::InvalidRange),
    );
    let out_of_bounds = [TailSegment {
        range: CheckedRange32 { start: 16, end: 25 },
        kind: TailSegmentKind::Payload,
    }];
    assert_eq!(
        validate_tail_coverage(&prefix, 16, &out_of_bounds, false),
        Err(ControlError::InvalidRange),
    );

    let payload_only = [segments[0]];
    let mut optional_suffix = snapshot;
    optional_suffix[22] = 0x5a;
    let optional_prefix = validate_control_prefix(&optional_suffix, &[1], 0, 16).unwrap();
    assert_eq!(
        validate_tail_coverage(&optional_prefix, 16, &payload_only, false),
        Err(ControlError::UnclassifiedTail),
    );
    assert_eq!(
        validate_tail_coverage(&optional_prefix, 16, &payload_only, true),
        Ok(()),
    );
    assert_eq!(
        validate_tail_coverage(&optional_prefix, 16, &segments, false),
        Err(ControlError::NonZeroReserved),
    );

    let mut nonzero_padding = snapshot;
    nonzero_padding[21] = 1;
    let nonzero_prefix = validate_control_prefix(&nonzero_padding, &[1], 0, 16).unwrap();
    assert_eq!(
        validate_tail_coverage(&nonzero_prefix, 16, &segments, false),
        Err(ControlError::NonZeroReserved),
    );
}

#[test]
fn checked_range64_handles_exclusive_empty_and_reversed_ranges() {
    let outer = CheckedRange64 {
        start: 64,
        end: 128,
    };
    assert_eq!(outer.checked_len(), Some(64));
    assert!(outer.contains(CheckedRange64 {
        start: 64,
        end: 128,
    }));
    assert!(outer.contains(CheckedRange64 {
        start: 128,
        end: 128,
    }));
    assert!(!outer.contains(CheckedRange64 { start: 63, end: 64 }));
    assert!(!outer.contains(CheckedRange64 {
        start: 96,
        end: 129,
    }));
    assert!(!outer.contains(CheckedRange64 {
        start: 100,
        end: 99,
    }));

    let empty = CheckedRange64 {
        start: 128,
        end: 128,
    };
    assert_eq!(empty.checked_len(), Some(0));
    assert!(empty.contains(empty));
    assert!(!empty.contains(CheckedRange64 {
        start: 127,
        end: 128,
    }));

    let reversed = CheckedRange64 {
        start: 128,
        end: 64,
    };
    assert_eq!(reversed.checked_len(), None);
    assert!(!reversed.contains(CheckedRange64 { start: 64, end: 64 }));
}

#[test]
fn canonical_arenas_pack_exactly_and_retain_direction() {
    let arena = RegionDesc {
        offset: 65_536,
        length: 65_536,
    };
    let classes = [
        SlotClassDesc {
            slot_size: 256,
            slot_count: 2,
            data_offset: 65_536,
        },
        SlotClassDesc {
            slot_size: 512,
            slot_count: 1,
            data_offset: 66_048,
        },
        ZERO_CLASS,
        ZERO_CLASS,
    ];
    let validated = validate_slot_arena(SlotDirection::U2k, 196_608, arena, classes).unwrap();
    assert_eq!(validated.direction(), SlotDirection::U2k);
    assert_eq!(validated.section_size(), 196_608);
    assert_eq!(validated.arena().offset, 65_536);
    assert_eq!(validated.arena().length, 65_536);
    assert_eq!(validated.active_class_count(), 2);
    assert_eq!(
        validated.final_padding(),
        CheckedRange64 {
            start: 66_560,
            end: 131_072,
        }
    );

    let token = SlotToken::try_new(0, 1, 7).unwrap();
    let slot = resolve_slot(&validated, token).unwrap();
    assert_eq!(slot.token(), token);
    assert_eq!(slot.direction(), SlotDirection::U2k);
    assert_eq!(slot.slot_size(), 256);
    assert_eq!(
        slot.section_range(),
        CheckedRange64 {
            start: 65_792,
            end: 66_048,
        }
    );
    assert_eq!(
        resolve_slot(
            &validated,
            SlotToken::try_new(2, MAX_SLOT_COUNT - 1, 7).unwrap()
        ),
        Err(SlotLayoutError::ClassOutOfRange),
    );
    assert_eq!(
        resolve_slot(&validated, SlotToken::try_new(0, 2, 7).unwrap()),
        Err(SlotLayoutError::IndexOutOfRange),
    );

    let zero_arena = validate_slot_arena(
        SlotDirection::K2u,
        USER_VIEW_OFFSET_ALIGNMENT,
        RegionDesc {
            offset: 0,
            length: USER_VIEW_OFFSET_ALIGNMENT,
        },
        one_class(256, 1, 0),
    )
    .unwrap();
    assert_eq!(zero_arena.direction(), SlotDirection::K2u);
    assert_eq!(
        zero_arena.final_padding(),
        CheckedRange64 {
            start: 256,
            end: USER_VIEW_OFFSET_ALIGNMENT,
        }
    );
    let zero_slot = resolve_slot(&zero_arena, SlotToken::try_new(0, 0, 1).unwrap()).unwrap();
    assert_eq!(zero_slot.direction(), SlotDirection::K2u);
    assert_eq!(
        zero_slot.section_range(),
        CheckedRange64 { start: 0, end: 256 }
    );
}

#[test]
fn arena_envelope_errors_have_exact_precedence() {
    let malformed = one_class(0, 1, 1);
    let rows = [
        (
            "zero section precedes arena and class",
            0,
            RegionDesc {
                offset: 1,
                length: 0,
            },
            malformed,
            SlotLayoutError::InvalidSectionSize,
        ),
        (
            "oversize section precedes arena and class",
            MAX_SECTION_BYTES + 1,
            RegionDesc {
                offset: 1,
                length: 0,
            },
            malformed,
            SlotLayoutError::InvalidSectionSize,
        ),
        (
            "misaligned offset precedes overflowing end and class",
            MAX_SECTION_BYTES,
            RegionDesc {
                offset: u64::MAX,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            malformed,
            SlotLayoutError::InvalidArenaAlignment,
        ),
        (
            "zero arena length",
            MAX_SECTION_BYTES,
            RegionDesc {
                offset: 0,
                length: 0,
            },
            malformed,
            SlotLayoutError::InvalidArenaAlignment,
        ),
        (
            "misaligned arena length",
            MAX_SECTION_BYTES,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT - 1,
            },
            malformed,
            SlotLayoutError::InvalidArenaAlignment,
        ),
        (
            "aligned arena end overflow precedes bounds and class",
            MAX_SECTION_BYTES,
            RegionDesc {
                offset: u64::MAX - (USER_VIEW_OFFSET_ALIGNMENT - 1),
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            malformed,
            SlotLayoutError::ArithmeticOverflow,
        ),
        (
            "arena out of section precedes class",
            USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: USER_VIEW_OFFSET_ALIGNMENT,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            malformed,
            SlotLayoutError::ArenaOutOfBounds,
        ),
    ];

    for (name, section_size, arena, classes, expected) in rows {
        assert_eq!(
            validate_slot_arena(SlotDirection::U2k, section_size, arena, classes).err(),
            Some(expected),
            "{name}",
        );
    }
}

#[test]
fn class_shape_field_and_packing_errors_have_exact_precedence() {
    let active = SlotClassDesc {
        slot_size: 256,
        slot_count: 1,
        data_offset: 0,
    };
    let rows = [
        (
            "all inactive",
            USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            [ZERO_CLASS; SLOT_CLASS_COUNT],
            SlotLayoutError::NoActiveClasses,
        ),
        (
            "zero size with nonzero count",
            USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            one_class(0, MAX_SLOT_COUNT + 1, 1),
            SlotLayoutError::InvalidInactiveClass,
        ),
        (
            "zero count with nonzero size",
            USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            one_class(256, 0, 0),
            SlotLayoutError::InvalidInactiveClass,
        ),
        (
            "inactive nonzero offset",
            USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            one_class(0, 0, 64),
            SlotLayoutError::InvalidInactiveClass,
        ),
        (
            "active after inactive precedes later active fields",
            USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            [
                active,
                ZERO_CLASS,
                SlotClassDesc {
                    slot_size: 255,
                    slot_count: MAX_SLOT_COUNT + 1,
                    data_offset: 1,
                },
                ZERO_CLASS,
            ],
            SlotLayoutError::ActiveAfterInactive,
        ),
        (
            "malformed inactive after inactive precedes sequence state",
            USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            [
                active,
                ZERO_CLASS,
                SlotClassDesc {
                    slot_size: 0,
                    slot_count: 1,
                    data_offset: 1,
                },
                ZERO_CLASS,
            ],
            SlotLayoutError::InvalidInactiveClass,
        ),
        (
            "slot size below minimum",
            USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            one_class(255, MAX_SLOT_COUNT + 1, 1),
            SlotLayoutError::InvalidSlotSize,
        ),
        (
            "slot size not power of two",
            USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            one_class(257, MAX_SLOT_COUNT + 1, 1),
            SlotLayoutError::InvalidSlotSize,
        ),
        (
            "slot size above maximum",
            USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            one_class(MAX_SLOT_SIZE + 1, MAX_SLOT_COUNT + 1, 1),
            SlotLayoutError::InvalidSlotSize,
        ),
        (
            "slot count precedes data alignment",
            USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            one_class(256, MAX_SLOT_COUNT + 1, 1),
            SlotLayoutError::InvalidSlotCount,
        ),
        (
            "data alignment",
            USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            one_class(256, 1, 1),
            SlotLayoutError::InvalidClassAlignment,
        ),
        (
            "data alignment precedes decreasing size",
            USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            [
                SlotClassDesc {
                    slot_size: 512,
                    slot_count: 1,
                    data_offset: 0,
                },
                SlotClassDesc {
                    slot_size: 256,
                    slot_count: 1,
                    data_offset: 513,
                },
                ZERO_CLASS,
                ZERO_CLASS,
            ],
            SlotLayoutError::InvalidClassAlignment,
        ),
        (
            "equal size precedes packing",
            USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            [
                SlotClassDesc {
                    slot_size: 512,
                    slot_count: 1,
                    data_offset: 0,
                },
                SlotClassDesc {
                    slot_size: 512,
                    slot_count: 1,
                    data_offset: 1_024,
                },
                ZERO_CLASS,
                ZERO_CLASS,
            ],
            SlotLayoutError::NonIncreasingSlotSize,
        ),
        (
            "descending size",
            USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            [
                SlotClassDesc {
                    slot_size: 512,
                    slot_count: 1,
                    data_offset: 0,
                },
                SlotClassDesc {
                    slot_size: 256,
                    slot_count: 1,
                    data_offset: 512,
                },
                ZERO_CLASS,
                ZERO_CLASS,
            ],
            SlotLayoutError::NonIncreasingSlotSize,
        ),
        (
            "packing overlap",
            2 * USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: USER_VIEW_OFFSET_ALIGNMENT,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            one_class(256, 1, USER_VIEW_OFFSET_ALIGNMENT - 64),
            SlotLayoutError::PackingMismatch,
        ),
        (
            "packing gap",
            2 * USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: USER_VIEW_OFFSET_ALIGNMENT,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            one_class(256, 1, USER_VIEW_OFFSET_ALIGNMENT + 64),
            SlotLayoutError::PackingMismatch,
        ),
    ];

    for (name, section_size, arena, classes, expected) in rows {
        assert_eq!(
            validate_slot_arena(SlotDirection::U2k, section_size, arena, classes).err(),
            Some(expected),
            "{name}",
        );
    }
}

#[test]
fn arena_length_and_maximum_math_are_checked_without_wrap() {
    assert_eq!(
        validate_slot_arena(
            SlotDirection::U2k,
            2 * USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            one_class(USER_VIEW_OFFSET_ALIGNMENT as u32, 2, 0),
        )
        .err(),
        Some(SlotLayoutError::ArenaLengthMismatch),
    );
    assert_eq!(
        validate_slot_arena(
            SlotDirection::U2k,
            2 * USER_VIEW_OFFSET_ALIGNMENT,
            RegionDesc {
                offset: 0,
                length: 2 * USER_VIEW_OFFSET_ALIGNMENT,
            },
            one_class(USER_VIEW_OFFSET_ALIGNMENT as u32, 1, 0),
        )
        .err(),
        Some(SlotLayoutError::ArenaLengthMismatch),
    );

    let greatest_arena_offset = MAX_SECTION_BYTES - USER_VIEW_OFFSET_ALIGNMENT;
    assert_eq!(
        validate_slot_arena(
            SlotDirection::U2k,
            MAX_SECTION_BYTES,
            RegionDesc {
                offset: greatest_arena_offset,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            one_class(MAX_SLOT_SIZE, MAX_SLOT_COUNT, greatest_arena_offset),
        )
        .err(),
        Some(SlotLayoutError::ArenaLengthMismatch),
        "maximum bounded product/end/final align-up must not wrap",
    );

    let maximum_section = validate_slot_arena(
        SlotDirection::U2k,
        MAX_SECTION_BYTES,
        RegionDesc {
            offset: 0,
            length: MAX_SECTION_BYTES,
        },
        one_class(MAX_SLOT_SIZE, 64, 0),
    )
    .unwrap();
    assert_eq!(
        maximum_section.final_padding(),
        CheckedRange64 {
            start: MAX_SECTION_BYTES,
            end: MAX_SECTION_BYTES,
        }
    );
    let maximum_size_slot =
        resolve_slot(&maximum_section, SlotToken::try_new(0, 63, 1).unwrap()).unwrap();
    assert_eq!(maximum_size_slot.slot_size(), MAX_SLOT_SIZE);
    assert_eq!(
        maximum_size_slot.section_range(),
        CheckedRange64 {
            start: MAX_SECTION_BYTES - u64::from(MAX_SLOT_SIZE),
            end: MAX_SECTION_BYTES,
        }
    );

    let maximum_count_bytes = u64::from(256u32)
        .checked_mul(u64::from(MAX_SLOT_COUNT))
        .unwrap();
    let maximum_count = validate_slot_arena(
        SlotDirection::U2k,
        maximum_count_bytes,
        RegionDesc {
            offset: 0,
            length: maximum_count_bytes,
        },
        one_class(256, MAX_SLOT_COUNT, 0),
    )
    .unwrap();
    let last = resolve_slot(
        &maximum_count,
        SlotToken::try_new(0, MAX_SLOT_COUNT - 1, 1).unwrap(),
    )
    .unwrap();
    assert_eq!(
        last.section_range(),
        CheckedRange64 {
            start: maximum_count_bytes - 256,
            end: maximum_count_bytes,
        }
    );

    let four = validate_slot_arena(
        SlotDirection::K2u,
        USER_VIEW_OFFSET_ALIGNMENT,
        RegionDesc {
            offset: 0,
            length: USER_VIEW_OFFSET_ALIGNMENT,
        },
        [
            SlotClassDesc {
                slot_size: 256,
                slot_count: 1,
                data_offset: 0,
            },
            SlotClassDesc {
                slot_size: 512,
                slot_count: 1,
                data_offset: 256,
            },
            SlotClassDesc {
                slot_size: 1_024,
                slot_count: 1,
                data_offset: 768,
            },
            SlotClassDesc {
                slot_size: 2_048,
                slot_count: 1,
                data_offset: 1_792,
            },
        ],
    )
    .unwrap();
    assert_eq!(four.active_class_count(), 4);
    let class_three = resolve_slot(&four, SlotToken::try_new(3, 0, 9).unwrap()).unwrap();
    assert_eq!(class_three.direction(), SlotDirection::K2u);
    assert_eq!(class_three.slot_size(), 2_048);
    assert_eq!(
        class_three.section_range(),
        CheckedRange64 {
            start: 1_792,
            end: 3_840,
        }
    );
}

#[test]
fn final_padding_requires_one_exact_private_zero_snapshot() {
    let validated = validate_slot_arena(
        SlotDirection::U2k,
        196_608,
        RegionDesc {
            offset: 65_536,
            length: 65_536,
        },
        [
            SlotClassDesc {
                slot_size: 256,
                slot_count: 2,
                data_offset: 65_536,
            },
            SlotClassDesc {
                slot_size: 512,
                slot_count: 1,
                data_offset: 66_048,
            },
            ZERO_CLASS,
            ZERO_CLASS,
        ],
    )
    .unwrap();
    let expected = validated.final_padding();
    let expected_len = usize::try_from(expected.checked_len().unwrap()).unwrap();
    assert_eq!(expected_len, 64_512);

    let zeros = [0u8; 64_512];
    assert_eq!(validate_zeroed_padding(&zeros, expected), Ok(()));

    let mut wrong_length_nonzero = [0u8; 64_511];
    wrong_length_nonzero[0] = 1;
    assert_eq!(
        validate_zeroed_padding(&wrong_length_nonzero, expected),
        Err(SlotLayoutError::PaddingLengthMismatch),
    );
    let too_long = [0u8; 64_513];
    assert_eq!(
        validate_zeroed_padding(&too_long, expected),
        Err(SlotLayoutError::PaddingLengthMismatch),
    );
    let mut nonzero = zeros;
    nonzero[64_511] = 1;
    assert_eq!(
        validate_zeroed_padding(&nonzero, expected),
        Err(SlotLayoutError::NonZeroPadding),
    );
    assert_eq!(
        validate_zeroed_padding(
            &[1],
            CheckedRange64 {
                start: expected.end,
                end: expected.start,
            },
        ),
        Err(SlotLayoutError::ArithmeticOverflow),
    );

    #[cfg(target_pointer_width = "32")]
    assert_eq!(
        validate_zeroed_padding(
            &[],
            CheckedRange64 {
                start: 0,
                end: u64::from(u32::MAX) + 1,
            },
        ),
        Err(SlotLayoutError::ArithmeticOverflow),
    );

    let no_padding = validate_slot_arena(
        SlotDirection::K2u,
        USER_VIEW_OFFSET_ALIGNMENT,
        RegionDesc {
            offset: 0,
            length: USER_VIEW_OFFSET_ALIGNMENT,
        },
        one_class(USER_VIEW_OFFSET_ALIGNMENT as u32, 1, 0),
    )
    .unwrap();
    assert_eq!(
        no_padding.final_padding(),
        CheckedRange64 {
            start: USER_VIEW_OFFSET_ALIGNMENT,
            end: USER_VIEW_OFFSET_ALIGNMENT,
        }
    );
    assert_eq!(
        validate_zeroed_padding(&[], no_padding.final_padding()),
        Ok(())
    );
}

#[test]
fn none_rule_accepts_only_the_all_zero_encoding() {
    let validated: ValidatedBuffer =
        validate_buffer_ref(&canonical_none(), &BufferRefRule::None).unwrap();
    assert_eq!(validated.kind(), buffer_kind::NONE);
    assert!(validated.is_none());
    assert_eq!(validated.slot_token(), None);
    assert_eq!(validated.mapping_token(), None);
    assert_eq!(validated.section_range(), None);
    assert_eq!(validated.mapping_range(), None);

    let mut token = canonical_none();
    token.token = 1;
    let mut offset = canonical_none();
    offset.offset = 1;
    let mut length = canonical_none();
    length.length = 1;
    let mut kind = canonical_none();
    kind.kind = buffer_kind::SLOT;
    let mut access = canonical_none();
    access.access = buffer_access::K2U_READ_ONLY;
    let mut reserved = canonical_none();
    reserved.reserved = 1;

    for reference in [token, offset, length, kind, access, reserved] {
        assert_eq!(
            validate_buffer_ref(&reference, &BufferRefRule::None),
            Err(BufferRefError::InvalidNone),
        );
    }
}

#[test]
fn slot_grant_metadata_closes_shape_direction_and_owner() {
    assert_eq!(
        validate_grant_metadata(&canonical_slot_grant(SlotDirection::U2k, GrantState::Live,)),
        Ok(()),
    );
    assert_eq!(
        validate_grant_metadata(&canonical_slot_grant(
            SlotDirection::U2k,
            GrantState::Rundown,
        )),
        Ok(()),
    );
    assert_eq!(
        validate_grant_metadata(&canonical_slot_grant(SlotDirection::K2u, GrantState::Live,)),
        Ok(()),
    );

    let mut generation_zero_nonzero_index =
        canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    generation_zero_nonzero_index.owner = GrantOwner::Request(ReqId::try_new(0, 1).unwrap());
    assert_eq!(
        validate_grant_metadata(&generation_zero_nonzero_index),
        Ok(()),
    );

    let mut notification = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    notification.owner = GrantOwner::NotificationCredit {
        ring_index: u32::MAX,
    };
    assert_eq!(validate_grant_metadata(&notification), Ok(()));

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.session_epoch = 0;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.owner = GrantOwner::Request(ReqId::from_raw(0));
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.access = u16::MAX;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.issued.access = u16::MAX;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.issued.access = buffer_access::K2U_READ_ONLY;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.access = buffer_access::K2U_READ_ONLY;
    invalid.issued.access = buffer_access::K2U_READ_ONLY;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::K2u, GrantState::Live);
    invalid.access = buffer_access::U2K_WRITE;
    invalid.issued.access = buffer_access::U2K_WRITE;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.maximum = CheckedRange64 { start: 16, end: 16 };
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.maximum = CheckedRange64 {
        start: 224,
        end: 16,
    };
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.maximum.end = 257;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.issued.length = 0;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.issued.reserved = 1;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.issued.kind = buffer_kind::MAPPING;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.issued.token = SlotToken::try_new(0, 1, 8).unwrap().raw();
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.issued.offset = 15;
    invalid.issued.length = 1;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.issued.offset = 224;
    invalid.issued.length = 1;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    invalid.issued.offset = 255;
    invalid.issued.length = 2;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );
}

#[test]
fn mapping_grant_metadata_keeps_tokens_opaque_and_access_closed() {
    assert!(SlotToken::from_raw(4).is_err());
    assert_eq!(
        validate_grant_metadata(&canonical_mapping_grant(
            buffer_access::K2U_READ_ONLY,
            GrantState::Live,
        )),
        Ok(()),
    );
    assert_eq!(
        validate_grant_metadata(&canonical_mapping_grant(
            buffer_access::U2K_WRITE,
            GrantState::Live,
        )),
        Ok(()),
    );
    assert_eq!(
        validate_grant_metadata(&canonical_mapping_grant(
            buffer_access::U2K_WRITE,
            GrantState::Rundown,
        )),
        Ok(()),
    );

    let maximum_end = u64::from(u32::MAX) + u64::from(u32::MAX);
    let mut maximum = canonical_mapping_grant(buffer_access::U2K_WRITE, GrantState::Live);
    maximum.capability = GrantCapability::Mapping {
        token: 4,
        length: maximum_end,
    };
    maximum.maximum = CheckedRange64 {
        start: 0,
        end: maximum_end,
    };
    maximum.issued.offset = u32::MAX;
    maximum.issued.length = u32::MAX;
    assert_eq!(maximum_end, 8_589_934_590);
    assert_eq!(validate_grant_metadata(&maximum), Ok(()));

    let mut invalid = canonical_mapping_grant(buffer_access::U2K_WRITE, GrantState::Live);
    invalid.capability = GrantCapability::Mapping {
        token: 0,
        length: 256,
    };
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_mapping_grant(buffer_access::U2K_WRITE, GrantState::Live);
    invalid.capability = GrantCapability::Mapping {
        token: 4,
        length: 0,
    };
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_mapping_grant(buffer_access::U2K_WRITE, GrantState::Live);
    invalid.access = u16::MAX;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_mapping_grant(buffer_access::U2K_WRITE, GrantState::Live);
    invalid.issued.access = u16::MAX;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_mapping_grant(buffer_access::U2K_WRITE, GrantState::Live);
    invalid.issued.access = buffer_access::K2U_READ_ONLY;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_mapping_grant(buffer_access::U2K_WRITE, GrantState::Live);
    invalid.maximum.end = 257;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_mapping_grant(buffer_access::U2K_WRITE, GrantState::Live);
    invalid.issued.kind = buffer_kind::SLOT;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let mut invalid = canonical_mapping_grant(buffer_access::U2K_WRITE, GrantState::Live);
    invalid.issued.token = 8;
    assert_eq!(
        validate_grant_metadata(&invalid),
        Err(BufferRefError::InvalidGrantMetadata),
    );
}

#[test]
fn candidate_precedence_matches_every_binding_row() {
    let mut malformed = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    malformed.session_epoch = 0;
    let all_bad = BufferRef {
        token: 0,
        offset: u32::MAX,
        length: u32::MAX,
        kind: u16::MAX,
        access: u16::MAX,
        reserved: u32::MAX,
    };
    assert_eq!(
        validate_buffer_ref(
            &all_bad,
            &grant_rule(
                &malformed,
                BufferRefPolicy::Exact,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::InvalidGrantMetadata),
    );

    let grant = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    let mut candidate = grant.issued;
    candidate.reserved = 1;
    candidate.kind = u16::MAX;
    candidate.access = u16::MAX;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::NonZeroReserved),
    );

    let mut candidate = grant.issued;
    candidate.kind = u16::MAX;
    candidate.access = u16::MAX;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::UnknownKind),
    );

    let rundown = canonical_slot_grant(SlotDirection::U2k, GrantState::Rundown);
    let mut candidate = rundown.issued;
    candidate.access = u16::MAX;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&rundown, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::UnknownAccess),
    );

    let wrong_owner = GrantOwner::NotificationCredit { ring_index: 0 };
    assert_eq!(
        validate_buffer_ref(
            &rundown.issued,
            &BufferRefRule::Grant {
                grant: &rundown,
                expected_session_epoch: rundown.session_epoch + 1,
                expected_owner: wrong_owner,
                policy: BufferRefPolicy::Exact,
                empty: EmptyBufferRule::Forbidden,
            },
        ),
        Err(BufferRefError::GrantNotLive),
    );

    assert_eq!(
        validate_buffer_ref(
            &grant.issued,
            &BufferRefRule::Grant {
                grant: &grant,
                expected_session_epoch: grant.session_epoch + 1,
                expected_owner: wrong_owner,
                policy: BufferRefPolicy::Exact,
                empty: EmptyBufferRule::Forbidden,
            },
        ),
        Err(BufferRefError::SessionEpochMismatch),
    );

    let mut candidate = grant.issued;
    candidate.kind = buffer_kind::MAPPING;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &BufferRefRule::Grant {
                grant: &grant,
                expected_session_epoch: grant.session_epoch,
                expected_owner: wrong_owner,
                policy: BufferRefPolicy::Exact,
                empty: EmptyBufferRule::Forbidden,
            },
        ),
        Err(BufferRefError::OwnerMismatch),
    );

    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::KindMismatch),
    );

    let mut candidate = grant.issued;
    candidate.token = 4;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::InvalidSlotToken),
    );

    let mut candidate = grant.issued;
    candidate.token = SlotToken::try_new(0, 1, 8).unwrap().raw();
    candidate.access = buffer_access::K2U_READ_ONLY;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::CapabilityMismatch),
    );

    let mut candidate = grant.issued;
    candidate.access = buffer_access::K2U_READ_ONLY;
    candidate.length = 0;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::AccessMismatch),
    );

    let mut candidate = grant.issued;
    candidate.offset = u32::MAX;
    candidate.length = 0;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::EmptyNotAllowed),
    );

    candidate.length = 1;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::RangeOutOfBounds),
    );

    let mut candidate = grant.issued;
    candidate.offset = 33;
    candidate.length = 127;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::EchoMismatch),
    );

    let mut candidate = grant.issued;
    candidate.offset = 33;
    candidate.length = 129;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &grant,
                BufferRefPolicy::ShrinkOnly,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::EchoMismatch),
    );

    let mut candidate = grant.issued;
    candidate.length = 193;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &grant,
                BufferRefPolicy::ShrinkOnly,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::RangeOutOfBounds),
    );

    candidate.length = 129;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &grant,
                BufferRefPolicy::ShrinkOnly,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::LengthGrowth),
    );

    let mut candidate = grant.issued;
    candidate.offset = 16;
    candidate.length = 16;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &grant,
                BufferRefPolicy::DerivedSubrange,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::RangeOutOfBounds),
    );

    assert!(validate_buffer_ref(
        &grant.issued,
        &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
    )
    .is_ok());

    assert_eq!(
        validate_buffer_ref(
            &canonical_none(),
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::UnknownAccess),
    );

    let mapping = canonical_mapping_grant(buffer_access::U2K_WRITE, GrantState::Live);
    let mut candidate = mapping.issued;
    candidate.kind = buffer_kind::SLOT;
    assert_eq!(candidate.token, 4);
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&mapping, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::KindMismatch),
    );
}

#[test]
fn slot_tokens_bind_exact_identity_and_accessors_are_absolute() {
    let slot = canonical_resolved_slot(SlotDirection::U2k);
    assert_eq!(slot.token().raw(), 0x01c0_0004);
    assert_eq!(slot.token().raw(), 29_360_132);
    assert_eq!(
        slot.section_range(),
        CheckedRange64 {
            start: 65_792,
            end: 66_048,
        },
    );

    let grant = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    assert_eq!(
        CheckedRange64 {
            start: slot.section_range().start + grant.maximum.start,
            end: slot.section_range().start + grant.maximum.end,
        },
        CheckedRange64 {
            start: 65_808,
            end: 66_016,
        },
    );
    let validated = validate_buffer_ref(
        &grant.issued,
        &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden),
    )
    .unwrap();
    assert_eq!(validated.kind(), buffer_kind::SLOT);
    assert!(!validated.is_none());
    assert_eq!(validated.slot_token(), Some(slot.token()));
    assert_eq!(validated.mapping_token(), None);
    assert_eq!(
        validated.section_range(),
        Some(CheckedRange64 {
            start: 65_824,
            end: 65_952,
        }),
    );
    assert_eq!(validated.mapping_range(), None);

    let mut candidate = grant.issued;
    candidate.token = 0;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::InvalidSlotToken),
    );
    candidate.token = 4;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::InvalidSlotToken),
    );
    candidate.token = SlotToken::try_new(0, 1, 8).unwrap().raw();
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::CapabilityMismatch),
    );
    candidate.token = SlotToken::try_new(1, 1, 7).unwrap().raw();
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::CapabilityMismatch),
    );
    candidate.token = SlotToken::try_new(0, 0, 7).unwrap().raw();
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::CapabilityMismatch),
    );
}

#[test]
fn exact_and_shrink_policies_keep_offset_fixed_and_apply_empty_rules() {
    let grant = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    assert!(validate_buffer_ref(
        &grant.issued,
        &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
    )
    .is_ok());

    let mut candidate = grant.issued;
    candidate.offset = 33;
    candidate.length = 127;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden,),
        ),
        Err(BufferRefError::EchoMismatch),
    );

    let mut candidate = grant.issued;
    candidate.length = 64;
    let shrunk = validate_buffer_ref(
        &candidate,
        &grant_rule(
            &grant,
            BufferRefPolicy::ShrinkOnly,
            EmptyBufferRule::Forbidden,
        ),
    )
    .unwrap();
    assert_eq!(
        shrunk.section_range(),
        Some(CheckedRange64 {
            start: 65_824,
            end: 65_888,
        }),
    );

    candidate.offset = 33;
    candidate.length = 129;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &grant,
                BufferRefPolicy::ShrinkOnly,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::EchoMismatch),
    );

    candidate.offset = grant.issued.offset;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &grant,
                BufferRefPolicy::ShrinkOnly,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::LengthGrowth),
    );

    candidate.length = 0;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &grant,
                BufferRefPolicy::ShrinkOnly,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::EmptyNotAllowed),
    );

    let empty = validate_buffer_ref(
        &candidate,
        &grant_rule(
            &grant,
            BufferRefPolicy::ShrinkOnly,
            EmptyBufferRule::Allowed,
        ),
    )
    .unwrap();
    assert_eq!(
        empty.section_range(),
        Some(CheckedRange64 {
            start: 65_824,
            end: 65_824,
        }),
    );

    candidate.offset = 33;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &grant,
                BufferRefPolicy::ShrinkOnly,
                EmptyBufferRule::Allowed,
            ),
        ),
        Err(BufferRefError::EchoMismatch),
    );

    candidate.offset = grant.issued.offset;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(&grant, BufferRefPolicy::Exact, EmptyBufferRule::Allowed,),
        ),
        Err(BufferRefError::EchoMismatch),
    );
}

#[test]
fn derived_subranges_include_empty_issued_boundaries_only_when_allowed() {
    let grant = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    let mut candidate = grant.issued;
    candidate.offset = 48;
    candidate.length = 64;
    let validated = validate_buffer_ref(
        &candidate,
        &grant_rule(
            &grant,
            BufferRefPolicy::DerivedSubrange,
            EmptyBufferRule::Forbidden,
        ),
    )
    .unwrap();
    assert_eq!(
        validated.section_range(),
        Some(CheckedRange64 {
            start: 65_840,
            end: 65_904,
        }),
    );

    candidate.offset = 31;
    candidate.length = 1;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &grant,
                BufferRefPolicy::DerivedSubrange,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::RangeOutOfBounds),
    );

    candidate.offset = 160;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &grant,
                BufferRefPolicy::DerivedSubrange,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::RangeOutOfBounds),
    );

    candidate.offset = 32;
    candidate.length = 0;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &grant,
                BufferRefPolicy::DerivedSubrange,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::EmptyNotAllowed),
    );

    let at_start = validate_buffer_ref(
        &candidate,
        &grant_rule(
            &grant,
            BufferRefPolicy::DerivedSubrange,
            EmptyBufferRule::Allowed,
        ),
    )
    .unwrap();
    assert_eq!(
        at_start.section_range(),
        Some(CheckedRange64 {
            start: 65_824,
            end: 65_824,
        }),
    );

    candidate.offset = 160;
    let at_end = validate_buffer_ref(
        &candidate,
        &grant_rule(
            &grant,
            BufferRefPolicy::DerivedSubrange,
            EmptyBufferRule::Allowed,
        ),
    )
    .unwrap();
    assert_eq!(
        at_end.section_range(),
        Some(CheckedRange64 {
            start: 65_952,
            end: 65_952,
        }),
    );

    candidate.offset = 16;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &grant,
                BufferRefPolicy::DerivedSubrange,
                EmptyBufferRule::Allowed,
            ),
        ),
        Err(BufferRefError::RangeOutOfBounds),
    );
}

#[test]
fn slot_maximum_and_full_capacity_use_exclusive_checked_ends() {
    let mut grant = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    grant.issued.offset = 16;
    grant.issued.length = 208;

    let mut candidate = grant.issued;
    candidate.length = 1;
    let first = validate_buffer_ref(
        &candidate,
        &grant_rule(
            &grant,
            BufferRefPolicy::DerivedSubrange,
            EmptyBufferRule::Forbidden,
        ),
    )
    .unwrap();
    assert_eq!(
        first.section_range(),
        Some(CheckedRange64 {
            start: 65_808,
            end: 65_809,
        }),
    );

    candidate.offset = 223;
    let last = validate_buffer_ref(
        &candidate,
        &grant_rule(
            &grant,
            BufferRefPolicy::DerivedSubrange,
            EmptyBufferRule::Forbidden,
        ),
    )
    .unwrap();
    assert_eq!(
        last.section_range(),
        Some(CheckedRange64 {
            start: 66_015,
            end: 66_016,
        }),
    );

    candidate.offset = 15;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &grant,
                BufferRefPolicy::DerivedSubrange,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::RangeOutOfBounds),
    );

    candidate.offset = 224;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &grant,
                BufferRefPolicy::DerivedSubrange,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::RangeOutOfBounds),
    );

    let mut full = canonical_slot_grant(SlotDirection::U2k, GrantState::Live);
    full.maximum = CheckedRange64 { start: 0, end: 256 };
    full.issued.offset = 0;
    full.issued.length = 256;
    let mut candidate = full.issued;
    candidate.offset = 255;
    candidate.length = 1;
    let last = validate_buffer_ref(
        &candidate,
        &grant_rule(
            &full,
            BufferRefPolicy::DerivedSubrange,
            EmptyBufferRule::Forbidden,
        ),
    )
    .unwrap();
    assert_eq!(
        last.section_range(),
        Some(CheckedRange64 {
            start: 66_047,
            end: 66_048,
        }),
    );

    candidate.length = 2;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &full,
                BufferRefPolicy::DerivedSubrange,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::RangeOutOfBounds),
    );

    candidate.offset = u32::MAX;
    candidate.length = 1;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &full,
                BufferRefPolicy::DerivedSubrange,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::RangeOutOfBounds),
    );
}

#[test]
fn mapping_tokens_and_u32_boundaries_stay_opaque_and_relative() {
    let u32_end = u64::from(u32::MAX);
    let four_gib = u32_end + 1;

    let mut below_four_gib = canonical_mapping_grant(buffer_access::U2K_WRITE, GrantState::Live);
    below_four_gib.capability = GrantCapability::Mapping {
        token: 4,
        length: u32_end,
    };
    below_four_gib.maximum = CheckedRange64 {
        start: 0,
        end: u32_end,
    };
    below_four_gib.issued.offset = 0;
    below_four_gib.issued.length = u32::MAX;
    let mut candidate = below_four_gib.issued;
    candidate.offset = u32::MAX;
    candidate.length = 1;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &below_four_gib,
                BufferRefPolicy::DerivedSubrange,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::RangeOutOfBounds),
    );

    let mut at_four_gib = canonical_mapping_grant(buffer_access::U2K_WRITE, GrantState::Live);
    at_four_gib.capability = GrantCapability::Mapping {
        token: 4,
        length: four_gib,
    };
    at_four_gib.maximum = CheckedRange64 {
        start: 0,
        end: four_gib,
    };
    at_four_gib.issued.offset = u32::MAX;
    at_four_gib.issued.length = 1;
    let validated = validate_buffer_ref(
        &at_four_gib.issued,
        &grant_rule(
            &at_four_gib,
            BufferRefPolicy::Exact,
            EmptyBufferRule::Forbidden,
        ),
    )
    .unwrap();
    assert_eq!(validated.kind(), buffer_kind::MAPPING);
    assert!(!validated.is_none());
    assert_eq!(validated.slot_token(), None);
    assert_eq!(validated.mapping_token(), Some(4));
    assert_eq!(validated.section_range(), None);
    assert_eq!(
        validated.mapping_range(),
        Some(CheckedRange64 {
            start: u32_end,
            end: four_gib,
        }),
    );

    let mut candidate = at_four_gib.issued;
    candidate.token = 0;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &at_four_gib,
                BufferRefPolicy::Exact,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::CapabilityMismatch),
    );
    candidate.token = 8;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &at_four_gib,
                BufferRefPolicy::Exact,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::CapabilityMismatch),
    );
    candidate.token = 4;
    candidate.kind = buffer_kind::SLOT;
    assert_eq!(
        validate_buffer_ref(
            &candidate,
            &grant_rule(
                &at_four_gib,
                BufferRefPolicy::Exact,
                EmptyBufferRule::Forbidden,
            ),
        ),
        Err(BufferRefError::KindMismatch),
    );

    let maximum_end = u32_end + u32_end;
    let mut maximum = canonical_mapping_grant(buffer_access::K2U_READ_ONLY, GrantState::Live);
    maximum.capability = GrantCapability::Mapping {
        token: 4,
        length: maximum_end,
    };
    maximum.maximum = CheckedRange64 {
        start: 0,
        end: maximum_end,
    };
    maximum.issued.offset = u32::MAX;
    maximum.issued.length = u32::MAX;
    let validated = validate_buffer_ref(
        &maximum.issued,
        &grant_rule(&maximum, BufferRefPolicy::Exact, EmptyBufferRule::Forbidden),
    )
    .unwrap();
    assert_eq!(maximum_end, 8_589_934_590);
    assert_eq!(validated.mapping_token(), Some(4));
    assert_eq!(
        validated.mapping_range(),
        Some(CheckedRange64 {
            start: u32_end,
            end: maximum_end,
        }),
    );
}

fn assert_control_pod<T: Pod>() {}

macro_rules! assert_control_wire_layout {
    ($ty:ty, $size:expr, $align:expr; $($field:ident : $field_ty:ty => $offset:expr),+ $(,)?) => {{
        assert_eq!(size_of::<$ty>(), $size, "{} size", stringify!($ty));
        assert_eq!(
            align_of::<$ty>(),
            $align,
            "{} alignment",
            stringify!($ty)
        );
        let mut next = 0usize;
        $(
            let _: fn(&$ty) -> $field_ty = |value| value.$field;
            let expected_offset: usize = $offset;
            assert_eq!(
                offset_of!($ty, $field),
                expected_offset,
                "{}.{} offset",
                stringify!($ty),
                stringify!($field)
            );
            assert_eq!(
                expected_offset,
                next,
                "implicit gap before {}.{}",
                stringify!($ty),
                stringify!($field)
            );
            next += size_of::<$field_ty>();
        )+
        assert_eq!(
            next,
            size_of::<$ty>(),
            "{} tail padding",
            stringify!($ty)
        );
        assert_control_pod::<$ty>();
    }};
}

#[test]
fn control_ioctl_and_status_registries_are_closed_and_exact() {
    assert_eq!(FILE_DEVICE_UNKNOWN, 0x22);
    assert_eq!(METHOD_BUFFERED, 0);
    assert_eq!(FILE_READ_ACCESS, 1);
    assert_eq!(FILE_WRITE_ACCESS, 2);
    assert_eq!(CONTROL_IOCTL_ACCESS, 3);
    assert_eq!(CONTROL_DEVICE_SDDL, "D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    let ioctls = [
        (ioctl_function::SETUP, IOCTL_FSRING_SETUP, 0x0022_e000),
        (ioctl_function::ENTER, IOCTL_FSRING_ENTER, 0x0022_e004),
        (ioctl_function::ATTACH, IOCTL_FSRING_ATTACH, 0x0022_e008),
        (
            ioctl_function::DONATE_BACKING,
            IOCTL_FSRING_DONATE_BACKING,
            0x0022_e00c,
        ),
        (
            ioctl_function::DONATE_SECURITY_CONTEXT,
            IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
            0x0022_e010,
        ),
        (ioctl_function::DETACH, IOCTL_FSRING_DETACH, 0x0022_e014),
        (
            ioctl_function::RETIRE_MOUNT,
            IOCTL_FSRING_RETIRE_MOUNT,
            0x0022_e018,
        ),
    ];
    for (function, ioctl, expected) in ioctls {
        assert_eq!(ioctl, expected);
        assert_eq!((ioctl >> 16) & 0xffff, FILE_DEVICE_UNKNOWN);
        assert_eq!((ioctl >> 14) & 0x3, CONTROL_IOCTL_ACCESS);
        assert_eq!((ioctl >> 2) & 0x0fff, function);
        assert_eq!(ioctl & 0x3, METHOD_BUFFERED);
    }

    assert_eq!(status::SUCCESS as u32, 0x0000_0000);
    assert_eq!(status::DEVICE_BUSY as u32, 0x8000_0011);
    assert_eq!(status::INVALID_PARAMETER as u32, 0xc000_000d);
    assert_eq!(status::ACCESS_DENIED as u32, 0xc000_0022);
    assert_eq!(status::BUFFER_TOO_SMALL as u32, 0xc000_0023);
    assert_eq!(status::OBJECT_NAME_NOT_FOUND as u32, 0xc000_0034);
    assert_eq!(status::REVISION_MISMATCH as u32, 0xc000_0059);
    assert_eq!(status::INTEGER_OVERFLOW as u32, 0xc000_0095);
    assert_eq!(status::INSUFFICIENT_RESOURCES as u32, 0xc000_009a);
    assert_eq!(status::NOT_SUPPORTED as u32, 0xc000_00bb);
    assert_eq!(status::CANCELLED as u32, 0xc000_0120);
    assert_eq!(status::INVALID_DEVICE_STATE as u32, 0xc000_0184);

    let all_statuses = [
        status::SUCCESS,
        status::DEVICE_BUSY,
        status::INVALID_PARAMETER,
        status::ACCESS_DENIED,
        status::BUFFER_TOO_SMALL,
        status::OBJECT_NAME_NOT_FOUND,
        status::REVISION_MISMATCH,
        status::INTEGER_OVERFLOW,
        status::INSUFFICIENT_RESOURCES,
        status::NOT_SUPPORTED,
        status::CANCELLED,
        status::INVALID_DEVICE_STATE,
    ];
    let create = [
        status::SUCCESS,
        status::ACCESS_DENIED,
        status::OBJECT_NAME_NOT_FOUND,
        status::INSUFFICIENT_RESOURCES,
    ];
    for candidate in all_statuses {
        assert_eq!(
            is_legal_create_status(candidate),
            create.contains(&candidate),
            "CREATE status {candidate:#010x}"
        );
    }

    let rows: [(u32, &[i32]); 7] = [
        (
            IOCTL_FSRING_SETUP,
            &[
                status::SUCCESS,
                status::DEVICE_BUSY,
                status::INVALID_PARAMETER,
                status::ACCESS_DENIED,
                status::BUFFER_TOO_SMALL,
                status::REVISION_MISMATCH,
                status::INTEGER_OVERFLOW,
                status::INSUFFICIENT_RESOURCES,
                status::NOT_SUPPORTED,
                status::CANCELLED,
            ],
        ),
        (
            IOCTL_FSRING_ATTACH,
            &[
                status::SUCCESS,
                status::DEVICE_BUSY,
                status::INVALID_PARAMETER,
                status::ACCESS_DENIED,
                status::BUFFER_TOO_SMALL,
                status::REVISION_MISMATCH,
                status::INSUFFICIENT_RESOURCES,
                status::NOT_SUPPORTED,
                status::CANCELLED,
                status::INVALID_DEVICE_STATE,
            ],
        ),
        (
            IOCTL_FSRING_ENTER,
            &[
                status::SUCCESS,
                status::DEVICE_BUSY,
                status::INVALID_PARAMETER,
                status::ACCESS_DENIED,
                status::BUFFER_TOO_SMALL,
                status::REVISION_MISMATCH,
                status::NOT_SUPPORTED,
                status::CANCELLED,
                status::INVALID_DEVICE_STATE,
            ],
        ),
        (
            IOCTL_FSRING_DONATE_BACKING,
            &[
                status::SUCCESS,
                status::DEVICE_BUSY,
                status::INVALID_PARAMETER,
                status::ACCESS_DENIED,
                status::REVISION_MISMATCH,
                status::INSUFFICIENT_RESOURCES,
                status::NOT_SUPPORTED,
                status::CANCELLED,
                status::INVALID_DEVICE_STATE,
            ],
        ),
        (
            IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
            &[
                status::INVALID_PARAMETER,
                status::ACCESS_DENIED,
                status::REVISION_MISMATCH,
                status::NOT_SUPPORTED,
                status::INVALID_DEVICE_STATE,
            ],
        ),
        (
            IOCTL_FSRING_DETACH,
            &[
                status::SUCCESS,
                status::DEVICE_BUSY,
                status::INVALID_PARAMETER,
                status::ACCESS_DENIED,
                status::REVISION_MISMATCH,
                status::NOT_SUPPORTED,
                status::CANCELLED,
                status::INVALID_DEVICE_STATE,
            ],
        ),
        (
            IOCTL_FSRING_RETIRE_MOUNT,
            &[
                status::SUCCESS,
                status::DEVICE_BUSY,
                status::INVALID_PARAMETER,
                status::ACCESS_DENIED,
                status::BUFFER_TOO_SMALL,
                status::REVISION_MISMATCH,
                status::NOT_SUPPORTED,
                status::INVALID_DEVICE_STATE,
            ],
        ),
    ];
    for (ioctl, expected) in rows {
        for candidate in all_statuses {
            assert_eq!(
                is_legal_ioctl_status(ioctl, candidate),
                expected.contains(&candidate),
                "IOCTL {ioctl:#010x} status {candidate:#010x}"
            );
        }
    }

    let unknown_status = 0xdead_beefu32 as i32;
    assert!(!is_legal_create_status(unknown_status));
    assert!(!is_legal_ioctl_status(IOCTL_FSRING_SETUP, unknown_status));
    assert!(!is_legal_ioctl_status(0, status::SUCCESS));
    assert!(!is_legal_ioctl_status(u32::MAX, status::SUCCESS));
}

#[test]
fn control_scalar_limits_and_identity_types_are_exact() {
    assert_eq!(GLOBAL_RING_INDEX, u32::MAX);
    assert_eq!(FSRING_MOUNT_CONTROL, 1);
    assert_eq!(DONATE_BACKING_VERSION_V2, 2);
    assert_eq!(ENTER_TIMEOUT_INFINITE, u32::MAX);

    assert_eq!(view_kind::INVALID, 0);
    assert_eq!(view_kind::SECTION_READ_ONLY, 1);
    assert_eq!(view_kind::SQ_CONSUMER_PAGE, 2);
    assert_eq!(view_kind::CQ_ENTRIES, 3);
    assert_eq!(view_kind::CQ_PRODUCER_PAGE, 4);
    assert_eq!(view_kind::U2K_ARENA, 5);
    assert_eq!(view_access::INVALID, 0);
    assert_eq!(view_access::READ_ONLY, 1);
    assert_eq!(view_access::READ_WRITE, 2);

    assert_eq!(enter_request_flags::DRAIN_CQ, 0x0000_0001);
    assert_eq!(enter_request_flags::WAIT_SQ, 0x0000_0002);
    assert_eq!(enter_request_flags::KNOWN_MASK, 0x0000_0003);
    assert_eq!(enter_result_flags::SQ_READY, 0x0000_0001);
    assert_eq!(enter_result_flags::CQ_REMAINING, 0x0000_0002);
    assert_eq!(enter_result_flags::TIMED_OUT, 0x0000_0004);
    assert_eq!(enter_result_flags::NOTIFY_BLOCKED, 0x0000_0008);
    assert_eq!(enter_result_flags::CQ_CONTENDED, 0x0000_0010);
    assert_eq!(enter_result_flags::KNOWN_MASK, 0x0000_001f);

    assert_eq!(retire_mount_action::QUERY, 1);
    assert_eq!(retire_mount_action::ACK, 2);
    assert_eq!(retire_mount_state::ABSENT, 1);
    assert_eq!(retire_mount_state::ACTIVE, 2);
    assert_eq!(retire_mount_state::GRACE, 3);
    assert_eq!(retire_mount_state::TERMINAL, 4);
    assert_eq!(retire_mount_state::BOUND_RECONCILING, 5);

    assert_eq!(MIN_NOTIFICATION_CREDIT_SIZE, 2_048);
    assert_eq!(MAX_NOTIFICATION_CREDIT_SIZE, 65_536);
    assert_eq!(MAX_NOTIFICATION_CREDITS_PER_RING, 64);
    assert_eq!(MAX_NOTIFICATION_CREDITS_PER_SESSION, 1_024);
    assert_eq!(MAX_NOTIFICATION_CREDIT_BYTES, 16 * 1024 * 1024);
    assert_eq!(MIN_CONTROL_SLOT_SIZE, 131_072);
    assert_eq!(MIN_K2U_PROGRESS_SLOTS_PER_RING, 4);
    assert_eq!(MIN_U2K_PROGRESS_SLOTS_PER_RING, 2);
    assert_eq!(MAX_ENTER_CQ_BUDGET, 4_096);
    assert_eq!(MIN_BACKING_PATH_BYTES, 2);
    assert_eq!(MAX_BACKING_PATH_BYTES, 32_760);
    assert_eq!(MIN_BACKING_SECTOR_SIZE, 512);
    assert_eq!(MAX_BACKING_SECTOR_SIZE, 65_536);
    assert_eq!(RESTART_GRACE_TIMEOUT_MS, 30_000);

    assert_eq!(
        (size_of::<BootInstanceId>(), align_of::<BootInstanceId>()),
        (16, 8)
    );
    assert_eq!(offset_of!(BootInstanceId, lo), 0);
    assert_eq!(offset_of!(BootInstanceId, hi), 8);
    assert_eq!(BootInstanceId::ZERO, BootInstanceId::default());
    assert_eq!(
        (size_of::<RetireToken>(), align_of::<RetireToken>()),
        (16, 8)
    );
    assert_eq!(offset_of!(RetireToken, lo), 0);
    assert_eq!(offset_of!(RetireToken, hi), 8);
    assert_eq!(RetireToken::ZERO, RetireToken::default());
    assert_control_pod::<BootInstanceId>();
    assert_control_pod::<RetireToken>();
}

#[test]
fn session_wire_prefixes_are_gapless_pod_layouts() {
    assert_eq!(SLOT_CLASS_REQUEST_SIZE, 8);
    assert_eq!(SETUP_REQUEST_V1_SIZE, 160);
    assert_eq!(USER_VIEW_DESC_SIZE, 32);
    assert_eq!(NOTIFICATION_CREDIT_V1_SIZE, 32);
    assert_eq!(SESSION_RESULT_V1_PREFIX_SIZE, 136);
    assert_eq!(ENTER_REQUEST_V1_SIZE, 48);
    assert_eq!(ENTER_RESULT_V1_PREFIX_SIZE, 48);
    assert_eq!(DETACH_REQUEST_V1_SIZE, 40);
    assert_eq!(DONATE_BACKING_V2_PREFIX_SIZE, 48);
    assert_eq!(RETIRE_MOUNT_V1_SIZE, 48);
    assert_eq!(RETIRE_MOUNT_RESULT_V1_SIZE, 96);

    assert_control_wire_layout!(SlotClassRequest, 8, 4;
        slot_size: u32 => 0,
        slot_count: u32 => 4,
    );
    assert_control_wire_layout!(SetupRequestV1, 160, 8;
        header: ControlHeader => 0,
        abi_major: u16 => 8,
        min_abi_minor: u16 => 10,
        max_abi_minor: u16 => 12,
        reserved0: u16 => 14,
        offered_features: FeatureSet => 16,
        required_features: FeatureSet => 32,
        required_os_capabilities: FeatureSet => 48,
        ring_count: u32 => 64,
        sq_capacity: u32 => 68,
        cq_capacity: u32 => 72,
        max_inflight: u32 => 76,
        k2u_slot_classes: [SlotClassRequest; SLOT_CLASS_COUNT] => 80,
        u2k_slot_classes: [SlotClassRequest; SLOT_CLASS_COUNT] => 112,
        notification_credit_count: u32 => 144,
        notification_credit_size: u32 => 148,
        flags: u32 => 152,
        reserved1: u32 => 156,
    );
    assert_control_wire_layout!(UserViewDesc, 32, 8;
        section_offset: u64 => 0,
        length: u64 => 8,
        user_address: u64 => 16,
        ring_index: u32 => 24,
        kind: u16 => 28,
        access: u16 => 30,
    );
    assert_control_wire_layout!(NotificationCreditV1, 32, 8;
        buffer: BufferRef => 0,
        ring_index: u32 => 24,
        reserved: u32 => 28,
    );
    assert_control_wire_layout!(SessionResultV1, 136, 8;
        header: ControlHeader => 0,
        abi_major: u16 => 8,
        abi_minor: u16 => 10,
        reserved0: u32 => 12,
        mount_id: fsring_abi::MountId => 16,
        boot_instance_id: BootInstanceId => 32,
        session_epoch: u64 => 48,
        section_size: u64 => 56,
        selected_features: FeatureSet => 64,
        os_capabilities: FeatureSet => 80,
        view_count: u32 => 96,
        view_desc_size: u32 => 100,
        views_offset: u32 => 104,
        notification_credit_count: u32 => 108,
        notification_credit_desc_size: u32 => 112,
        notification_credits_offset: u32 => 116,
        ring_count: u32 => 120,
        max_inflight: u32 => 124,
        flags: u32 => 128,
        reserved1: u32 => 132,
    );
    assert_control_wire_layout!(EnterRequestV1, 48, 8;
        header: ControlHeader => 0,
        mount_id: fsring_abi::MountId => 8,
        session_epoch: u64 => 24,
        ring_index: u32 => 32,
        flags: u32 => 36,
        cq_budget: u32 => 40,
        timeout_ms: u32 => 44,
    );
    assert_control_wire_layout!(EnterResultV1, 48, 8;
        header: ControlHeader => 0,
        session_epoch: u64 => 8,
        ring_index: u32 => 16,
        flags: u32 => 20,
        cq_drained: u32 => 24,
        sq_ready: u32 => 28,
        notification_credit_count: u32 => 32,
        notification_credit_desc_size: u32 => 36,
        notification_credits_offset: u32 => 40,
        reserved: u32 => 44,
    );
    assert_control_wire_layout!(DetachRequestV1, 40, 8;
        header: ControlHeader => 0,
        mount_id: fsring_abi::MountId => 8,
        session_epoch: u64 => 24,
        flags: u32 => 32,
        reserved: u32 => 36,
    );
    assert_control_wire_layout!(DonateBackingV2, 48, 8;
        header: ControlHeader => 0,
        file_id: fsring_abi::FileId => 8,
        pt_epoch: u64 => 24,
        sector_size: u32 => 32,
        flags: u32 => 36,
        backing_path: BlobSlice => 40,
    );
    assert_control_wire_layout!(RetireMountV1, 48, 8;
        header: ControlHeader => 0,
        mount_id: fsring_abi::MountId => 8,
        token: RetireToken => 24,
        action: u32 => 40,
        reserved: u32 => 44,
    );
    assert_control_wire_layout!(RetireMountResultV1, 96, 8;
        header: ControlHeader => 0,
        mount_id: fsring_abi::MountId => 8,
        boot_instance_id: BootInstanceId => 24,
        proof_token: RetireToken => 40,
        latest_session_epoch: u64 => 56,
        selected_features: FeatureSet => 64,
        journal_version: u32 => 80,
        mount_state: u16 => 84,
        flags: u16 => 86,
        reserved: u64 => 88,
    );
}

#[test]
fn control_namespace_reuses_existing_message_types() {
    let _: fn(fsring_abi::msgs::AttachV1) -> control::AttachV1 = |value| value;
    let _: fn(control::AttachV1) -> fsring_abi::msgs::AttachV1 = |value| value;
    let _: fn(fsring_abi::msgs::DonateSecurityContextV1) -> control::DonateSecurityContextV1 =
        |value| value;
    let _: fn(control::DonateSecurityContextV1) -> fsring_abi::msgs::DonateSecurityContextV1 =
        |value| value;

    assert_eq!(size_of::<control::AttachV1>(), 56);
    assert_eq!(align_of::<control::AttachV1>(), 8);
    assert_eq!(size_of::<control::DonateSecurityContextV1>(), 32);
    assert_eq!(align_of::<control::DonateSecurityContextV1>(), 8);
}

#[test]
fn setup_request_v1_has_literal_160_byte_little_endian_golden() {
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
        offered_features: FeatureSet { words: [0x9f, 0] },
        required_features: FeatureSet { words: [0x10, 0] },
        required_os_capabilities: FeatureSet { words: [0, 0] },
        ring_count: 1,
        sq_capacity: 8,
        cq_capacity: 2,
        max_inflight: 1,
        k2u_slot_classes: [
            SlotClassRequest {
                slot_size: 131_072,
                slot_count: 4,
            },
            SlotClassRequest {
                slot_size: 262_144,
                slot_count: 1,
            },
            SlotClassRequest::default(),
            SlotClassRequest::default(),
        ],
        u2k_slot_classes: [
            SlotClassRequest {
                slot_size: 2_048,
                slot_count: 1,
            },
            SlotClassRequest {
                slot_size: 131_072,
                slot_count: 2,
            },
            SlotClassRequest::default(),
            SlotClassRequest::default(),
        ],
        notification_credit_count: 1,
        notification_credit_size: 2_048,
        flags: 0,
        reserved1: 0,
    };
    let expected = [
        0xa0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x9f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut encoded = [0xa5; 160];
    assert_eq!(try_encode(&request, &mut encoded), Ok(160));
    assert_eq!(encoded, expected);
    assert_eq!(try_decode::<SetupRequestV1>(&expected), Ok(request));
}

const ZERO_CLASS_REQUEST: SlotClassRequest = SlotClassRequest {
    slot_size: 0,
    slot_count: 0,
};

fn feature_words(low: u64, high: u64) -> FeatureSet {
    FeatureSet { words: [low, high] }
}

fn slot_class_request(slot_size: u32, slot_count: u32) -> SlotClassRequest {
    SlotClassRequest {
        slot_size,
        slot_count,
    }
}

fn valid_setup_request_with_credit_size(
    ring_count: u32,
    notification_credit_count: u32,
    notification_credit_size: u32,
) -> SetupRequestV1 {
    let k2u_slot_classes = [
        slot_class_request(
            MIN_CONTROL_SLOT_SIZE,
            MIN_K2U_PROGRESS_SLOTS_PER_RING * ring_count,
        ),
        ZERO_CLASS_REQUEST,
        ZERO_CLASS_REQUEST,
        ZERO_CLASS_REQUEST,
    ];
    let u2k_slot_classes = if notification_credit_size < MIN_CONTROL_SLOT_SIZE {
        [
            slot_class_request(notification_credit_size, notification_credit_count),
            slot_class_request(
                MIN_CONTROL_SLOT_SIZE,
                MIN_U2K_PROGRESS_SLOTS_PER_RING * ring_count,
            ),
            ZERO_CLASS_REQUEST,
            ZERO_CLASS_REQUEST,
        ]
    } else {
        [
            slot_class_request(
                notification_credit_size,
                notification_credit_count + MIN_U2K_PROGRESS_SLOTS_PER_RING * ring_count,
            ),
            ZERO_CLASS_REQUEST,
            ZERO_CLASS_REQUEST,
            ZERO_CLASS_REQUEST,
        ]
    };
    SetupRequestV1 {
        header: ControlHeader {
            struct_size: SETUP_REQUEST_V1_SIZE,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        abi_major: 2,
        min_abi_minor: 1,
        max_abi_minor: 1,
        reserved0: 0,
        offered_features: feature_words(0x9f, 0),
        required_features: feature_words(0x10, 0),
        required_os_capabilities: feature_words(0, 0),
        ring_count,
        sq_capacity: 8,
        cq_capacity: 2,
        max_inflight: 1,
        k2u_slot_classes,
        u2k_slot_classes,
        notification_credit_count,
        notification_credit_size,
        flags: 0,
        reserved1: 0,
    }
}

fn valid_setup_request(ring_count: u32, notification_credit_count: u32) -> SetupRequestV1 {
    valid_setup_request_with_credit_size(
        ring_count,
        notification_credit_count,
        MIN_NOTIFICATION_CREDIT_SIZE,
    )
}

fn encode_setup_request(request: &SetupRequestV1) -> [u8; SETUP_REQUEST_V1_SIZE as usize] {
    let mut bytes = [0u8; SETUP_REQUEST_V1_SIZE as usize];
    assert_eq!(
        try_encode(request, &mut bytes),
        Ok(SETUP_REQUEST_V1_SIZE as usize)
    );
    bytes
}

fn validate_setup_bytes(bytes: &[u8]) -> Result<ValidatedSetupRequest, SessionValidationError> {
    validate_setup_request_v1(
        bytes,
        PlatformProfile::Win10X64,
        feature_words(0x9f, 0),
        feature_words(0x3, 0),
        true,
    )
}

fn validate_setup(
    request: &SetupRequestV1,
) -> Result<ValidatedSetupRequest, SessionValidationError> {
    validate_setup_bytes(&encode_setup_request(request))
}

fn validated_setup(ring_count: u32, credit_count: u32) -> ValidatedSetupRequest {
    match validate_setup(&valid_setup_request(ring_count, credit_count)) {
        Ok(setup) => setup,
        Err(error) => panic!("valid SETUP rejected: {error:?}"),
    }
}

fn assert_setup_error(request: &SetupRequestV1, expected: SessionValidationError) {
    assert_eq!(validate_setup(request).err(), Some(expected));
}

fn assert_setup_bytes_error(bytes: &[u8], expected: SessionValidationError) {
    assert_eq!(validate_setup_bytes(bytes).err(), Some(expected));
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn section_size_for_rings(ring_count: u32) -> u64 {
    u64::from(3 * ring_count + 3) * USER_VIEW_OFFSET_ALIGNMENT
}

fn u2k_arena_for_rings(ring_count: u32) -> RegionDesc {
    RegionDesc {
        offset: u64::from(3 * ring_count + 1) * USER_VIEW_OFFSET_ALIGNMENT,
        length: USER_VIEW_OFFSET_ALIGNMENT,
    }
}

fn ring_view_layouts(ring_count: u32) -> Vec<RingViewLayout> {
    (0..ring_count)
        .map(|ring_index| {
            let first = u64::from(3 * ring_index + 1) * USER_VIEW_OFFSET_ALIGNMENT;
            RingViewLayout {
                sq_consumer: RegionDesc {
                    offset: first,
                    length: 4_096,
                },
                cq_entries: RegionDesc {
                    offset: first + USER_VIEW_OFFSET_ALIGNMENT,
                    length: 4_096,
                },
                cq_producer: RegionDesc {
                    offset: first + 2 * USER_VIEW_OFFSET_ALIGNMENT,
                    length: 4_096,
                },
            }
        })
        .collect()
}

fn encode_at<T: Pod>(value: &T, bytes: &mut [u8], offset: usize) {
    let end = offset + size_of::<T>();
    assert_eq!(
        try_encode(value, &mut bytes[offset..end]),
        Ok(size_of::<T>())
    );
}

fn build_session_result(
    setup: &ValidatedSetupRequest,
    layout: &SessionViewLayout<'_>,
    reverse_credits: bool,
) -> Vec<u8> {
    let topology = setup.topology();
    let selection = setup.selection();
    let view_count = 2 + 3 * topology.ring_count();
    let credits_offset = SESSION_RESULT_V1_PREFIX_SIZE + view_count * USER_VIEW_DESC_SIZE;
    let struct_size =
        credits_offset + topology.notification_credit_count() * NOTIFICATION_CREDIT_V1_SIZE;
    let prefix = SessionResultV1 {
        header: ControlHeader {
            struct_size,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        abi_major: 2,
        abi_minor: setup.selected_abi_minor(),
        reserved0: 0,
        mount_id: fsring_abi::MountId { lo: 1, hi: 2 },
        boot_instance_id: BootInstanceId { lo: 3, hi: 4 },
        session_epoch: 1,
        section_size: layout.section_size(),
        selected_features: selection.selected_features,
        os_capabilities: selection.detected_os_capabilities,
        view_count,
        view_desc_size: USER_VIEW_DESC_SIZE,
        views_offset: SESSION_RESULT_V1_PREFIX_SIZE,
        notification_credit_count: topology.notification_credit_count(),
        notification_credit_desc_size: NOTIFICATION_CREDIT_V1_SIZE,
        notification_credits_offset: credits_offset,
        ring_count: topology.ring_count(),
        max_inflight: topology.max_inflight(),
        flags: 0,
        reserved1: 0,
    };
    let mut bytes = vec![0u8; struct_size as usize];
    encode_at(&prefix, &mut bytes, 0);

    let whole_section = UserViewDesc {
        section_offset: 0,
        length: layout.section_size(),
        user_address: 0,
        ring_index: GLOBAL_RING_INDEX,
        kind: view_kind::SECTION_READ_ONLY,
        access: view_access::READ_ONLY,
    };
    encode_at(
        &whole_section,
        &mut bytes,
        SESSION_RESULT_V1_PREFIX_SIZE as usize,
    );

    let mut view_ordinal = 1u32;
    for ring_index in 0..topology.ring_count() {
        let ring = layout.ring(ring_index).unwrap();
        let views = [
            UserViewDesc {
                section_offset: ring.sq_consumer.offset,
                length: ring.sq_consumer.length,
                user_address: if ring_index == 0 {
                    1
                } else {
                    u64::from(ring_index) * 3 + 1
                },
                ring_index,
                kind: view_kind::SQ_CONSUMER_PAGE,
                access: view_access::READ_WRITE,
            },
            UserViewDesc {
                section_offset: ring.cq_entries.offset,
                length: ring.cq_entries.length,
                user_address: if ring_index == 0 {
                    u64::MAX
                } else {
                    u64::from(ring_index) * 3 + 2
                },
                ring_index,
                kind: view_kind::CQ_ENTRIES,
                access: view_access::READ_WRITE,
            },
            UserViewDesc {
                section_offset: ring.cq_producer.offset,
                length: ring.cq_producer.length,
                user_address: if ring_index == 0 {
                    0x8000_0000_0000_0000
                } else {
                    u64::from(ring_index) * 3 + 3
                },
                ring_index,
                kind: view_kind::CQ_PRODUCER_PAGE,
                access: view_access::READ_WRITE,
            },
        ];
        for view in views {
            encode_at(
                &view,
                &mut bytes,
                (SESSION_RESULT_V1_PREFIX_SIZE + view_ordinal * USER_VIEW_DESC_SIZE) as usize,
            );
            view_ordinal += 1;
        }
    }

    let u2k_arena = layout.u2k_arena();
    let u2k_view = UserViewDesc {
        section_offset: u2k_arena.offset,
        length: u2k_arena.length,
        user_address: 0x1234,
        ring_index: GLOBAL_RING_INDEX,
        kind: view_kind::U2K_ARENA,
        access: view_access::READ_WRITE,
    };
    encode_at(
        &u2k_view,
        &mut bytes,
        (SESSION_RESULT_V1_PREFIX_SIZE + view_ordinal * USER_VIEW_DESC_SIZE) as usize,
    );

    for ordinal in 0..topology.notification_credit_count() {
        let source = if reverse_credits {
            topology.notification_credit_count() - 1 - ordinal
        } else {
            ordinal
        };
        let credit = NotificationCreditV1 {
            buffer: BufferRef {
                token: SlotToken::try_new(topology.notification_credit_class(), source, 1)
                    .unwrap()
                    .raw(),
                offset: 0,
                length: topology.notification_credit_size(),
                kind: buffer_kind::SLOT,
                access: buffer_access::U2K_WRITE,
                reserved: 0,
            },
            ring_index: source % topology.ring_count(),
            reserved: 0,
        };
        encode_at(
            &credit,
            &mut bytes,
            (credits_offset + ordinal * NOTIFICATION_CREDIT_V1_SIZE) as usize,
        );
    }
    bytes
}

fn assert_session_result_error(
    bytes: &[u8],
    layout: &SessionViewLayout<'_>,
    expected: SessionValidationError,
) {
    match validate_session_result_v1(bytes, layout) {
        Err(actual) => assert_eq!(actual, expected),
        Ok(_) => panic!("invalid SessionResult accepted"),
    }
}

fn assert_context_error(
    setup: &ValidatedSetupRequest,
    section_size: u64,
    page_size: u32,
    u2k_arena: RegionDesc,
    rings: &[RingViewLayout],
    expected: SessionContextError,
) {
    match SessionViewLayout::for_setup(setup, section_size, page_size, u2k_arena, rings) {
        Err(actual) => assert_eq!(actual, expected),
        Ok(_) => panic!("invalid trusted layout accepted"),
    }
}

#[test]
fn session_validation_status_mapping_is_closed() {
    assert_eq!(
        SessionValidationError::InvalidParameter.status(),
        status::INVALID_PARAMETER
    );
    assert_eq!(
        SessionValidationError::RevisionMismatch.status(),
        status::REVISION_MISMATCH
    );
    assert_eq!(
        SessionValidationError::NotSupported.status(),
        status::NOT_SUPPORTED
    );
    assert_eq!(
        SessionValidationError::AccessDenied.status(),
        status::ACCESS_DENIED
    );
    assert_eq!(
        SessionValidationError::IntegerOverflow.status(),
        status::INTEGER_OVERFLOW
    );
}

#[test]
fn implementation_mask_shape_is_closed() {
    let profiles = [
        (
            PlatformProfile::Win10X64,
            FeatureSet { words: [0x9f, 0] },
            FeatureSet { words: [0x10, 1] },
        ),
        (
            PlatformProfile::Win10Arm64,
            FeatureSet { words: [0x9f, 0] },
            FeatureSet { words: [0x410, 0] },
        ),
        (
            PlatformProfile::Win7X64,
            FeatureSet { words: [0x1f, 0] },
            FeatureSet { words: [0x410, 0] },
        ),
    ];

    for (profile, valid, outside_profile) in profiles {
        assert_eq!(
            validate_implementation_protocol_mask(profile, valid),
            Ok(())
        );
        assert_eq!(
            validate_implementation_protocol_mask(profile, FeatureSet { words: [0, 0] }),
            Err(ImplementationMaskError::MissingSecurity)
        );
        assert_eq!(
            validate_implementation_protocol_mask(profile, outside_profile),
            Err(ImplementationMaskError::OutsideProfile)
        );
        assert_eq!(
            validate_implementation_protocol_mask(profile, FeatureSet { words: [0x110, 0] }),
            Err(ImplementationMaskError::ContainsUnselectable)
        );
        assert_eq!(
            validate_implementation_protocol_mask(profile, FeatureSet { words: [0x14, 0] }),
            Err(ImplementationMaskError::RestartPairMismatch)
        );
    }

    assert_eq!(
        select_features_v21(
            PlatformProfile::Win10X64,
            FeatureSelectionInput {
                offered_features: feature_words(0x10, 0),
                required_features: feature_words(0x10, 0),
                required_os_capabilities: feature_words(0, 0),
                implementation_protocol_mask: feature_words(0, 0),
                runtime_probe_mask: feature_words(0x3, 0),
                has_dedicated_service_sid: true,
            },
        ),
        Err(FeatureSelectionError::InvalidImplementationMask)
    );
}

#[test]
fn required_unimplemented_precedes_service_sid() {
    const SECURITY_ONLY: FeatureSet = FeatureSet { words: [0x10, 0] };

    assert_eq!(
        select_features_v21(
            PlatformProfile::Win10X64,
            FeatureSelectionInput {
                offered_features: FeatureSet { words: [0x9f, 0] },
                required_features: FeatureSet { words: [0x11, 0] },
                required_os_capabilities: FeatureSet { words: [0, 0] },
                implementation_protocol_mask: SECURITY_ONLY,
                runtime_probe_mask: FeatureSet { words: [0x3, 0] },
                has_dedicated_service_sid: false,
            },
        ),
        Err(FeatureSelectionError::RequiredFeatureUnavailable),
    );
}

#[test]
fn optional_unimplemented_bits_are_omitted() {
    const SECURITY_ONLY: FeatureSet = FeatureSet { words: [0x10, 0] };

    let selection = select_features_v21(
        PlatformProfile::Win10X64,
        FeatureSelectionInput {
            offered_features: FeatureSet { words: [0x9f, 0] },
            required_features: FeatureSet { words: [0x10, 0] },
            required_os_capabilities: FeatureSet { words: [0, 0] },
            implementation_protocol_mask: SECURITY_ONLY,
            runtime_probe_mask: FeatureSet { words: [0x3, 0] },
            has_dedicated_service_sid: true,
        },
    )
    .unwrap();
    assert_eq!(selection.selected_features, FeatureSet { words: [0x10, 0] });
}

#[test]
fn feature_selection_profiles_and_unknown_bits_are_exact() {
    let profiles = [
        (PlatformProfile::Win10X64, 0x9f, 0x3),
        (PlatformProfile::Win10Arm64, 0x9f, 0xb),
        (PlatformProfile::Win7X64, 0x1f, 0),
    ];
    for (profile, protocol_low, os_low) in profiles {
        assert_eq!(profile.protocol_mask(), feature_words(protocol_low, 0));
        assert_eq!(profile.os_capability_mask(), feature_words(os_low, 0));
        let selection: FeatureSelection = select_features_v21(
            profile,
            FeatureSelectionInput {
                offered_features: feature_words(u64::MAX, u64::MAX),
                required_features: feature_words(1u64 << protocol_feature::SECURITY, 0),
                required_os_capabilities: feature_words(0, 0),
                implementation_protocol_mask: profile.protocol_mask(),
                runtime_probe_mask: feature_words(u64::MAX, u64::MAX),
                has_dedicated_service_sid: true,
            },
        )
        .unwrap();
        assert_eq!(selection.selected_features, feature_words(protocol_low, 0));
        assert_eq!(selection.detected_os_capabilities, feature_words(os_low, 0));
    }

    let optional_unknowns = select_features_v21(
        PlatformProfile::Win10X64,
        FeatureSelectionInput {
            offered_features: feature_words(0x3ff | (1u64 << 63), u64::MAX),
            required_features: feature_words(1u64 << protocol_feature::SECURITY, 0),
            required_os_capabilities: feature_words(0, 0),
            implementation_protocol_mask: feature_words(0x9f, 0),
            runtime_probe_mask: feature_words(
                (1u64 << os_cap::MDL_NO_WRITE) | (1u64 << os_cap::MDL_NO_EXECUTE),
                u64::MAX,
            ),
            has_dedicated_service_sid: true,
        },
    )
    .unwrap();
    assert_eq!(optional_unknowns.selected_features, feature_words(0x9f, 0));
    assert_eq!(
        optional_unknowns.detected_os_capabilities,
        feature_words(0x3, 0)
    );

    let one_mdl_bit = select_features_v21(
        PlatformProfile::Win10X64,
        FeatureSelectionInput {
            offered_features: feature_words(0x9f, 0),
            required_features: feature_words(1u64 << protocol_feature::SECURITY, 0),
            required_os_capabilities: feature_words(0, 0),
            implementation_protocol_mask: feature_words(0x9f, 0),
            runtime_probe_mask: feature_words(1u64 << os_cap::MDL_NO_WRITE, 0),
            has_dedicated_service_sid: true,
        },
    )
    .unwrap();
    assert_eq!(one_mdl_bit.selected_features, feature_words(0x1f, 0));
    assert_eq!(one_mdl_bit.detected_os_capabilities, feature_words(1, 0));

    let optional_restart_without_sid = select_features_v21(
        PlatformProfile::Win10X64,
        FeatureSelectionInput {
            offered_features: feature_words(0x1c, 0),
            required_features: feature_words(1u64 << protocol_feature::SECURITY, 0),
            required_os_capabilities: feature_words(0, 0),
            implementation_protocol_mask: feature_words(0x1c, 0),
            runtime_probe_mask: feature_words(0x3, 0),
            has_dedicated_service_sid: false,
        },
    )
    .unwrap();
    assert_eq!(
        optional_restart_without_sid.selected_features,
        feature_words(0x10, 0)
    );
}

#[test]
fn feature_selection_structural_errors_precede_policy() {
    let security = 1u64 << protocol_feature::SECURITY;
    let restart =
        (1u64 << protocol_feature::HOT_RESTART) | (1u64 << protocol_feature::EXACTLY_ONCE);
    let mapped_io = 1u64 << protocol_feature::MAPPED_IO;

    assert_eq!(
        select_features_v21(
            PlatformProfile::Win10X64,
            FeatureSelectionInput {
                offered_features: feature_words(security, 0),
                required_features: feature_words(security | restart, 0),
                required_os_capabilities: feature_words(0, 0),
                implementation_protocol_mask: feature_words(security | restart, 0),
                runtime_probe_mask: feature_words(0, 0),
                has_dedicated_service_sid: false,
            },
        ),
        Err(FeatureSelectionError::RequiredFeatureNotOffered)
    );

    assert_eq!(
        select_features_v21(
            PlatformProfile::Win10X64,
            FeatureSelectionInput {
                offered_features: feature_words(
                    security | (1u64 << protocol_feature::HOT_RESTART),
                    0,
                ),
                required_features: feature_words(security, 0),
                required_os_capabilities: feature_words(0, 0),
                implementation_protocol_mask: feature_words(security, 0),
                runtime_probe_mask: feature_words(0x3, 0),
                has_dedicated_service_sid: true,
            },
        ),
        Err(FeatureSelectionError::RestartPairMismatch)
    );

    assert_eq!(
        select_features_v21(
            PlatformProfile::Win10X64,
            FeatureSelectionInput {
                offered_features: feature_words(security | restart, 0),
                required_features: feature_words(
                    security | (1u64 << protocol_feature::HOT_RESTART),
                    0,
                ),
                required_os_capabilities: feature_words(0, 0),
                implementation_protocol_mask: feature_words(security | restart, 0),
                runtime_probe_mask: feature_words(0x3, 0),
                has_dedicated_service_sid: true,
            },
        ),
        Err(FeatureSelectionError::RestartPairMismatch)
    );

    assert_eq!(
        select_features_v21(
            PlatformProfile::Win10X64,
            FeatureSelectionInput {
                offered_features: feature_words(security | restart, 0),
                required_features: feature_words(security | restart, 0),
                required_os_capabilities: feature_words(0, 0),
                implementation_protocol_mask: feature_words(security | restart, 0),
                runtime_probe_mask: feature_words(0x3, 0),
                has_dedicated_service_sid: false,
            },
        ),
        Err(FeatureSelectionError::DedicatedServiceSidRequired)
    );

    assert_eq!(
        select_features_v21(
            PlatformProfile::Win10X64,
            FeatureSelectionInput {
                offered_features: feature_words(1u64 << protocol_feature::PT, 0),
                required_features: feature_words(0, 0),
                required_os_capabilities: feature_words(0, 0),
                implementation_protocol_mask: feature_words(security, 0),
                runtime_probe_mask: feature_words(0x3, 0),
                has_dedicated_service_sid: true,
            },
        ),
        Err(FeatureSelectionError::RequiredFeatureUnavailable)
    );

    assert_eq!(
        select_features_v21(
            PlatformProfile::Win10X64,
            FeatureSelectionInput {
                offered_features: feature_words(security | mapped_io, 0),
                required_features: feature_words(security | mapped_io, 0),
                required_os_capabilities: feature_words(0, 0),
                implementation_protocol_mask: feature_words(security | mapped_io, 0),
                runtime_probe_mask: feature_words(1u64 << os_cap::MDL_NO_WRITE, 0),
                has_dedicated_service_sid: true,
            },
        ),
        Err(FeatureSelectionError::RequiredFeatureUnavailable)
    );

    assert_eq!(
        select_features_v21(
            PlatformProfile::Win10X64,
            FeatureSelectionInput {
                offered_features: feature_words(security | (1u64 << 63), 0),
                required_features: feature_words(security | (1u64 << 63), 0),
                required_os_capabilities: feature_words(0, 0),
                implementation_protocol_mask: feature_words(security, 0),
                runtime_probe_mask: feature_words(0x3, 0),
                has_dedicated_service_sid: true,
            },
        ),
        Err(FeatureSelectionError::RequiredFeatureUnavailable)
    );

    assert_eq!(
        select_features_v21(
            PlatformProfile::Win10X64,
            FeatureSelectionInput {
                offered_features: feature_words(security, 0),
                required_features: feature_words(security, 0),
                required_os_capabilities: feature_words(0, 1),
                implementation_protocol_mask: feature_words(security, 0),
                runtime_probe_mask: feature_words(0x3, 1),
                has_dedicated_service_sid: true,
            },
        ),
        Err(FeatureSelectionError::RequiredOsCapabilityUnavailable)
    );
}

#[test]
fn setup_header_minor_and_feature_precedence_is_exact() {
    let request = valid_setup_request(1, 1);
    let valid = encode_setup_request(&request);
    assert_setup_bytes_error(&valid[..0], SessionValidationError::InvalidParameter);
    assert_setup_bytes_error(&valid[..7], SessionValidationError::InvalidParameter);

    let mut bytes = valid;
    put_u32(&mut bytes, 0, 0);
    put_u16(&mut bytes, 4, 2);
    assert_setup_bytes_error(&bytes, SessionValidationError::RevisionMismatch);

    let mut bytes = valid;
    put_u16(&mut bytes, 6, 1);
    put_u16(&mut bytes, 14, 1);
    assert_setup_bytes_error(&bytes, SessionValidationError::NotSupported);

    let mut bytes = valid;
    put_u32(&mut bytes, 0, SETUP_REQUEST_V1_SIZE - 1);
    assert_setup_bytes_error(&bytes, SessionValidationError::InvalidParameter);

    let mut trailing = valid.to_vec();
    trailing.push(0);
    assert_setup_bytes_error(&trailing, SessionValidationError::InvalidParameter);

    for (offset, width) in [(14usize, 2usize), (152, 4), (156, 4)] {
        let mut bytes = valid;
        match width {
            2 => put_u16(&mut bytes, offset, 1),
            4 => put_u32(&mut bytes, offset, 1),
            _ => unreachable!(),
        }
        assert_setup_bytes_error(&bytes, SessionValidationError::InvalidParameter);
    }

    let mut inverted_before_major = request;
    inverted_before_major.abi_major = 3;
    inverted_before_major.min_abi_minor = 2;
    inverted_before_major.max_abi_minor = 1;
    assert_setup_error(
        &inverted_before_major,
        SessionValidationError::InvalidParameter,
    );

    let mut wrong_major = request;
    wrong_major.abi_major = 3;
    assert_setup_error(&wrong_major, SessionValidationError::RevisionMismatch);

    let mut excludes_minor_one = request;
    excludes_minor_one.min_abi_minor = 2;
    excludes_minor_one.max_abi_minor = 2;
    assert_setup_error(
        &excludes_minor_one,
        SessionValidationError::RevisionMismatch,
    );

    let mut includes_minor_one = request;
    includes_minor_one.min_abi_minor = 0;
    let setup = validate_setup(&includes_minor_one).unwrap();
    assert_eq!(setup.selected_abi_minor(), 1);
    assert_eq!(setup.request(), includes_minor_one);

    let mut required_not_offered = request;
    required_not_offered.required_features = feature_words(0x30, 0);
    assert_setup_error(
        &required_not_offered,
        SessionValidationError::InvalidParameter,
    );

    let mut restart_without_sid = request;
    restart_without_sid.required_features = feature_words(0x1c, 0);
    let restart_bytes = encode_setup_request(&restart_without_sid);
    assert_eq!(
        validate_setup_request_v1(
            &restart_bytes,
            PlatformProfile::Win10X64,
            feature_words(0x9f, 0),
            feature_words(0x3, 0),
            false,
        )
        .err(),
        Some(SessionValidationError::AccessDenied)
    );

    let mut mapped_without_caps = request;
    mapped_without_caps.required_features = feature_words(0x90, 0);
    let mapped_bytes = encode_setup_request(&mapped_without_caps);
    assert_eq!(
        validate_setup_request_v1(
            &mapped_bytes,
            PlatformProfile::Win10X64,
            feature_words(0x9f, 0),
            feature_words(1u64 << os_cap::MDL_NO_WRITE, 0),
            true,
        )
        .err(),
        Some(SessionValidationError::NotSupported)
    );

    let mut unknown_required_os = request;
    unknown_required_os.required_os_capabilities = feature_words(0, 1);
    let os_bytes = encode_setup_request(&unknown_required_os);
    assert_eq!(
        validate_setup_request_v1(
            &os_bytes,
            PlatformProfile::Win10X64,
            feature_words(0x9f, 0),
            feature_words(0x3, 1),
            true,
        )
        .err(),
        Some(SessionValidationError::NotSupported)
    );

    let mut feature_before_topology = restart_without_sid;
    feature_before_topology.ring_count = 0;
    let feature_before_topology_bytes = encode_setup_request(&feature_before_topology);
    assert_eq!(
        validate_setup_request_v1(
            &feature_before_topology_bytes,
            PlatformProfile::Win10X64,
            feature_words(0x9f, 0),
            feature_words(0x3, 0),
            false,
        )
        .err(),
        Some(SessionValidationError::AccessDenied)
    );
}

#[test]
fn setup_topology_boundaries_are_exact() {
    for ring_count in [1, 16, 64] {
        let request = valid_setup_request(ring_count, ring_count);
        let setup = validate_setup(&request).unwrap();
        let topology: ValidatedTopology = setup.topology();
        assert_eq!(topology.ring_count(), ring_count);
        assert_eq!(setup.request(), request);
    }

    for ring_count in [0, 65] {
        let mut request = valid_setup_request(1, 1);
        request.ring_count = ring_count;
        assert_setup_error(&request, SessionValidationError::InvalidParameter);
    }

    for (sq_capacity, accepted) in [
        (7, false),
        (8, true),
        (65_536, true),
        (65_537, false),
        (12, false),
    ] {
        let mut request = valid_setup_request(1, 1);
        request.sq_capacity = sq_capacity;
        if accepted {
            let setup = validate_setup(&request).unwrap();
            assert_eq!(setup.topology().sq_capacity(), sq_capacity);
            assert_eq!(setup.request(), request);
        } else {
            assert_setup_error(&request, SessionValidationError::InvalidParameter);
        }
    }

    for (cq_capacity, accepted) in [
        (1, false),
        (2, true),
        (65_536, true),
        (65_537, false),
        (3, false),
    ] {
        let mut request = valid_setup_request(1, 1);
        request.cq_capacity = cq_capacity;
        if accepted {
            let setup = validate_setup(&request).unwrap();
            assert_eq!(setup.topology().cq_capacity(), cq_capacity);
            assert_eq!(setup.request(), request);
        } else {
            assert_setup_error(&request, SessionValidationError::InvalidParameter);
        }
    }

    for (max_inflight, accepted) in [
        (0, false),
        (1, true),
        (16_777_023, true),
        (16_777_024, false),
    ] {
        let mut request = valid_setup_request(1, 1);
        request.max_inflight = max_inflight;
        if accepted {
            let setup = validate_setup(&request).unwrap();
            assert_eq!(setup.topology().max_inflight(), max_inflight);
            assert_eq!(setup.request(), request);
        } else {
            assert_setup_error(&request, SessionValidationError::InvalidParameter);
        }
    }

    let mut active_after_inactive = valid_setup_request(1, 1);
    active_after_inactive.k2u_slot_classes = [
        slot_class_request(MIN_CONTROL_SLOT_SIZE, 4),
        ZERO_CLASS_REQUEST,
        slot_class_request(MIN_CONTROL_SLOT_SIZE * 2, 1),
        ZERO_CLASS_REQUEST,
    ];
    assert_setup_error(
        &active_after_inactive,
        SessionValidationError::InvalidParameter,
    );

    let mut u2k_active_after_inactive = valid_setup_request(1, 1);
    u2k_active_after_inactive.u2k_slot_classes = [
        slot_class_request(MIN_NOTIFICATION_CREDIT_SIZE, 1),
        ZERO_CLASS_REQUEST,
        slot_class_request(MIN_CONTROL_SLOT_SIZE, 2),
        ZERO_CLASS_REQUEST,
    ];
    assert_setup_error(
        &u2k_active_after_inactive,
        SessionValidationError::InvalidParameter,
    );

    let mut half_zero = valid_setup_request(1, 1);
    half_zero.k2u_slot_classes[0] = slot_class_request(MIN_CONTROL_SLOT_SIZE, 0);
    assert_setup_error(&half_zero, SessionValidationError::InvalidParameter);

    let mut u2k_half_zero = valid_setup_request(1, 1);
    u2k_half_zero.u2k_slot_classes[0] = slot_class_request(MIN_NOTIFICATION_CREDIT_SIZE, 0);
    assert_setup_error(&u2k_half_zero, SessionValidationError::InvalidParameter);

    let mut below_minimum_size = valid_setup_request(1, 1);
    below_minimum_size.k2u_slot_classes = [
        slot_class_request(128, 1),
        slot_class_request(MIN_CONTROL_SLOT_SIZE, 4),
        ZERO_CLASS_REQUEST,
        ZERO_CLASS_REQUEST,
    ];
    assert_setup_error(
        &below_minimum_size,
        SessionValidationError::InvalidParameter,
    );

    let mut minimum_size = valid_setup_request(1, 1);
    minimum_size.k2u_slot_classes = [
        slot_class_request(256, 1),
        slot_class_request(MIN_CONTROL_SLOT_SIZE, 4),
        ZERO_CLASS_REQUEST,
        ZERO_CLASS_REQUEST,
    ];
    let setup = validate_setup(&minimum_size).unwrap();
    assert_eq!(
        setup.topology().k2u_slot_classes(),
        minimum_size.k2u_slot_classes
    );

    let mut maximum_size = valid_setup_request(1, 1);
    maximum_size.k2u_slot_classes = [
        slot_class_request(MAX_SLOT_SIZE, 4),
        ZERO_CLASS_REQUEST,
        ZERO_CLASS_REQUEST,
        ZERO_CLASS_REQUEST,
    ];
    let setup = validate_setup(&maximum_size).unwrap();
    assert_eq!(
        setup.topology().k2u_slot_classes(),
        maximum_size.k2u_slot_classes
    );

    let mut above_maximum_size = maximum_size;
    above_maximum_size.k2u_slot_classes[0].slot_size = MAX_SLOT_SIZE * 2;
    assert_setup_error(
        &above_maximum_size,
        SessionValidationError::InvalidParameter,
    );

    let mut non_power_size = valid_setup_request(1, 1);
    non_power_size.k2u_slot_classes = [
        slot_class_request(384, 1),
        slot_class_request(MIN_CONTROL_SLOT_SIZE, 4),
        ZERO_CLASS_REQUEST,
        ZERO_CLASS_REQUEST,
    ];
    assert_setup_error(&non_power_size, SessionValidationError::InvalidParameter);

    let mut minimum_count = valid_setup_request(1, 1);
    minimum_count.k2u_slot_classes = [
        slot_class_request(MIN_CONTROL_SLOT_SIZE, 1),
        slot_class_request(MIN_CONTROL_SLOT_SIZE * 2, 3),
        ZERO_CLASS_REQUEST,
        ZERO_CLASS_REQUEST,
    ];
    let setup = validate_setup(&minimum_count).unwrap();
    assert_eq!(
        setup.topology().k2u_slot_classes(),
        minimum_count.k2u_slot_classes
    );

    let mut maximum_count = valid_setup_request(1, 1);
    maximum_count.k2u_slot_classes = [
        slot_class_request(MIN_CONTROL_SLOT_SIZE, MAX_SLOT_COUNT),
        ZERO_CLASS_REQUEST,
        ZERO_CLASS_REQUEST,
        ZERO_CLASS_REQUEST,
    ];
    let setup = validate_setup(&maximum_count).unwrap();
    assert_eq!(
        setup.topology().k2u_slot_classes(),
        maximum_count.k2u_slot_classes
    );

    let mut above_maximum_count = maximum_count;
    above_maximum_count.k2u_slot_classes[0].slot_count = MAX_SLOT_COUNT + 1;
    assert_setup_error(
        &above_maximum_count,
        SessionValidationError::InvalidParameter,
    );

    let mut non_increasing = valid_setup_request(1, 1);
    non_increasing.k2u_slot_classes = [
        slot_class_request(MIN_CONTROL_SLOT_SIZE, 4),
        slot_class_request(MIN_CONTROL_SLOT_SIZE, 1),
        ZERO_CLASS_REQUEST,
        ZERO_CLASS_REQUEST,
    ];
    assert_setup_error(&non_increasing, SessionValidationError::InvalidParameter);
}

#[test]
fn setup_credit_selection_caps_and_progress_are_exact() {
    assert_setup_error(
        &valid_setup_request(2, 1),
        SessionValidationError::InvalidParameter,
    );
    assert!(validate_setup(&valid_setup_request(2, 2)).is_ok());
    assert!(validate_setup(&valid_setup_request(1, 64)).is_ok());
    assert_setup_error(
        &valid_setup_request(1, 65),
        SessionValidationError::InvalidParameter,
    );
    assert!(validate_setup(&valid_setup_request(16, 1_024)).is_ok());
    assert_setup_error(
        &valid_setup_request(16, 1_025),
        SessionValidationError::InvalidParameter,
    );

    assert!(validate_setup(&valid_setup_request_with_credit_size(1, 1, 2_048)).is_ok());
    assert!(validate_setup(&valid_setup_request_with_credit_size(1, 1, 65_536)).is_ok());
    for invalid_size in [1_024, 3_072, 131_072] {
        assert_setup_error(
            &valid_setup_request_with_credit_size(1, 1, invalid_size),
            SessionValidationError::InvalidParameter,
        );
    }

    assert!(validate_setup(&valid_setup_request_with_credit_size(16, 1_024, 16_384)).is_ok());
    assert_setup_error(
        &valid_setup_request_with_credit_size(16, 1_024, 32_768),
        SessionValidationError::InvalidParameter,
    );

    let mut no_eligible_u2k = valid_setup_request_with_credit_size(2, 2, 65_536);
    no_eligible_u2k.u2k_slot_classes = [
        slot_class_request(2_048, 2),
        slot_class_request(32_768, 4),
        ZERO_CLASS_REQUEST,
        ZERO_CLASS_REQUEST,
    ];
    assert_setup_error(&no_eligible_u2k, SessionValidationError::InvalidParameter);

    let mut smallest_eligible = valid_setup_request(2, 2);
    smallest_eligible.u2k_slot_classes = [
        slot_class_request(2_048, 1),
        slot_class_request(4_096, 2),
        slot_class_request(MIN_CONTROL_SLOT_SIZE, 4),
        ZERO_CLASS_REQUEST,
    ];
    let selected = validate_setup(&smallest_eligible).unwrap();
    assert_eq!(selected.topology().notification_credit_class(), 1);

    let mut k2u_one_below = valid_setup_request(2, 2);
    k2u_one_below.k2u_slot_classes[0].slot_count = 7;
    assert_setup_error(&k2u_one_below, SessionValidationError::InvalidParameter);
    let mut k2u_exact = k2u_one_below;
    k2u_exact.k2u_slot_classes[0].slot_count = 8;
    assert!(validate_setup(&k2u_exact).is_ok());

    let small_credit = validate_setup(&valid_setup_request(2, 2)).unwrap();
    assert_eq!(small_credit.topology().notification_credit_class(), 0);

    let mut eligible_credit_one_below = valid_setup_request_with_credit_size(2, 2, 65_536);
    eligible_credit_one_below.u2k_slot_classes = [
        slot_class_request(MIN_CONTROL_SLOT_SIZE, 5),
        ZERO_CLASS_REQUEST,
        ZERO_CLASS_REQUEST,
        ZERO_CLASS_REQUEST,
    ];
    assert_setup_error(
        &eligible_credit_one_below,
        SessionValidationError::InvalidParameter,
    );
    let mut eligible_credit_exact = eligible_credit_one_below;
    eligible_credit_exact.u2k_slot_classes[0].slot_count = 6;
    let setup = validate_setup(&eligible_credit_exact).unwrap();
    assert_eq!(setup.topology().notification_credit_class(), 0);
}

#[test]
fn section_and_session_result_sizes_are_checked() {
    assert_eq!(
        validate_section_size_v21(0),
        Err(SessionValidationError::InvalidParameter)
    );
    assert_eq!(
        validate_section_size_v21(65_535),
        Err(SessionValidationError::InvalidParameter)
    );
    assert_eq!(validate_section_size_v21(65_536), Ok(()));
    assert_eq!(validate_section_size_v21(MAX_SECTION_BYTES), Ok(()));
    assert_eq!(
        validate_section_size_v21(MAX_SECTION_BYTES + 65_536),
        Err(SessionValidationError::InvalidParameter)
    );

    for (ring_count, credit_count, expected_size) in
        [(1, 1, 328), (16, 1_024, 34_504), (64, 1_024, 39_112)]
    {
        let topology: ValidatedTopology = validated_setup(ring_count, credit_count).topology();
        assert_eq!(session_result_size_v1(&topology), Ok(expected_size));
    }
}

#[test]
fn trusted_view_layout_rejects_bad_context_without_ntstatus() {
    let setup = validated_setup(1, 1);
    let rings = ring_view_layouts(1);
    let section_size = section_size_for_rings(1);
    let u2k_arena = u2k_arena_for_rings(1);
    let valid =
        SessionViewLayout::for_setup(&setup, section_size, 4_096, u2k_arena, &rings).unwrap();
    assert_eq!(valid.section_size(), section_size);
    assert_eq!(valid.page_size(), 4_096);
    assert_eq!(valid.ring_count(), 1);
    assert_eq!(valid.ring(0).unwrap().sq_consumer.offset, 65_536);
    assert!(valid.ring(1).is_none());

    assert_context_error(
        &setup,
        section_size,
        4_096,
        u2k_arena,
        &[],
        SessionContextError::InvalidRingCount,
    );

    for page_size in [0, 3_000, 131_072] {
        assert_context_error(
            &setup,
            section_size,
            page_size,
            u2k_arena,
            &rings,
            SessionContextError::InvalidPageSize,
        );
    }

    for invalid_section in [0, 65_535, MAX_SECTION_BYTES + 65_536] {
        assert_context_error(
            &setup,
            invalid_section,
            4_096,
            u2k_arena,
            &rings,
            SessionContextError::InvalidSectionSize,
        );
    }

    let mut bad_rings = rings.clone();
    bad_rings[0].sq_consumer.offset += 1;
    assert_context_error(
        &setup,
        section_size,
        4_096,
        u2k_arena,
        &bad_rings,
        SessionContextError::InvalidRegion,
    );

    let mut bad_rings = rings.clone();
    bad_rings[0].sq_consumer.length = 0;
    assert_context_error(
        &setup,
        section_size,
        4_096,
        u2k_arena,
        &bad_rings,
        SessionContextError::InvalidRegion,
    );

    let mut bad_rings = rings.clone();
    bad_rings[0].sq_consumer.length = 4_095;
    assert_context_error(
        &setup,
        section_size,
        4_096,
        u2k_arena,
        &bad_rings,
        SessionContextError::InvalidRegion,
    );

    let mut bad_rings = rings.clone();
    bad_rings[0].cq_producer.offset = section_size;
    assert_context_error(
        &setup,
        section_size,
        4_096,
        u2k_arena,
        &bad_rings,
        SessionContextError::InvalidRegion,
    );

    let mut bad_rings = rings.clone();
    bad_rings[0].sq_consumer = RegionDesc {
        offset: u64::MAX - (USER_VIEW_OFFSET_ALIGNMENT - 1),
        length: USER_VIEW_OFFSET_ALIGNMENT,
    };
    assert_context_error(
        &setup,
        section_size,
        4_096,
        u2k_arena,
        &bad_rings,
        SessionContextError::InvalidRegion,
    );

    assert_context_error(
        &setup,
        section_size,
        4_096,
        RegionDesc {
            offset: 0,
            length: USER_VIEW_OFFSET_ALIGNMENT,
        },
        &rings,
        SessionContextError::InvalidRegion,
    );
    assert_context_error(
        &setup,
        section_size,
        4_096,
        RegionDesc {
            offset: u2k_arena.offset + 1,
            length: u2k_arena.length,
        },
        &rings,
        SessionContextError::InvalidRegion,
    );
    assert_context_error(
        &setup,
        section_size,
        4_096,
        RegionDesc {
            offset: u2k_arena.offset,
            length: 4_096,
        },
        &rings,
        SessionContextError::InvalidRegion,
    );

    let mut overlap = rings.clone();
    overlap[0].sq_consumer.offset = overlap[0].cq_entries.offset;
    assert_context_error(
        &setup,
        section_size,
        4_096,
        u2k_arena,
        &overlap,
        SessionContextError::OverlappingWritableViews,
    );

    let mut overlap = rings.clone();
    overlap[0].sq_consumer.offset = overlap[0].cq_producer.offset;
    assert_context_error(
        &setup,
        section_size,
        4_096,
        u2k_arena,
        &overlap,
        SessionContextError::OverlappingWritableViews,
    );

    let mut overlap = rings.clone();
    overlap[0].cq_entries.offset = overlap[0].cq_producer.offset;
    assert_context_error(
        &setup,
        section_size,
        4_096,
        u2k_arena,
        &overlap,
        SessionContextError::OverlappingWritableViews,
    );

    for overlapping_u2k_offset in [
        rings[0].sq_consumer.offset,
        rings[0].cq_entries.offset,
        rings[0].cq_producer.offset,
    ] {
        assert_context_error(
            &setup,
            section_size,
            4_096,
            RegionDesc {
                offset: overlapping_u2k_offset,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            &rings,
            SessionContextError::OverlappingWritableViews,
        );
    }

    let setup_two = validated_setup(2, 2);
    let mut rings_two = ring_view_layouts(2);
    rings_two[1].sq_consumer.offset = rings_two[0].cq_producer.offset;
    assert_context_error(
        &setup_two,
        section_size_for_rings(2),
        4_096,
        u2k_arena_for_rings(2),
        &rings_two,
        SessionContextError::OverlappingWritableViews,
    );
}

#[test]
fn setup_session_result_has_literal_328_byte_golden() {
    let setup = validated_setup(1, 1);
    let rings = ring_view_layouts(1);
    let layout = SessionViewLayout::for_setup(
        &setup,
        section_size_for_rings(1),
        4_096,
        u2k_arena_for_rings(1),
        &rings,
    )
    .unwrap();
    let bytes = build_session_result(&setup, &layout, false);
    let expected: [u8; 328] = [
        0x48, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x9f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x88,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x28, 0x01, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
        0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(bytes.as_slice(), expected.as_slice());

    let validated: ValidatedSessionResult<'_> =
        validate_session_result_v1(&expected, &layout).unwrap();
    assert_eq!(
        validated.prefix(),
        try_decode::<SessionResultV1>(&expected[..SESSION_RESULT_V1_PREFIX_SIZE as usize]).unwrap()
    );
    assert_eq!(
        validated.identity(),
        SessionIdentity {
            mount_id: fsring_abi::MountId { lo: 1, hi: 2 },
            boot_instance_id: BootInstanceId { lo: 3, hi: 4 },
            session_epoch: 1,
        }
    );
    assert_eq!(validated.bytes(), expected.as_slice());
    assert_eq!(validated.view_count(), 5);

    let expected_views = [
        UserViewDesc {
            section_offset: 0,
            length: 393_216,
            user_address: 0,
            ring_index: GLOBAL_RING_INDEX,
            kind: view_kind::SECTION_READ_ONLY,
            access: view_access::READ_ONLY,
        },
        UserViewDesc {
            section_offset: 65_536,
            length: 4_096,
            user_address: 1,
            ring_index: 0,
            kind: view_kind::SQ_CONSUMER_PAGE,
            access: view_access::READ_WRITE,
        },
        UserViewDesc {
            section_offset: 131_072,
            length: 4_096,
            user_address: u64::MAX,
            ring_index: 0,
            kind: view_kind::CQ_ENTRIES,
            access: view_access::READ_WRITE,
        },
        UserViewDesc {
            section_offset: 196_608,
            length: 4_096,
            user_address: 0x8000_0000_0000_0000,
            ring_index: 0,
            kind: view_kind::CQ_PRODUCER_PAGE,
            access: view_access::READ_WRITE,
        },
        UserViewDesc {
            section_offset: 262_144,
            length: 65_536,
            user_address: 0x1234,
            ring_index: GLOBAL_RING_INDEX,
            kind: view_kind::U2K_ARENA,
            access: view_access::READ_WRITE,
        },
    ];
    for (index, expected_view) in expected_views.into_iter().enumerate() {
        assert_eq!(validated.view(index as u32), Some(expected_view));
    }
    assert_eq!(validated.view(5), None);
    assert_eq!(validated.view(u32::MAX), None);

    let expected_credit = NotificationCreditV1 {
        buffer: BufferRef {
            token: SlotToken::try_new(0, 0, 1).unwrap().raw(),
            offset: 0,
            length: 2_048,
            kind: buffer_kind::SLOT,
            access: buffer_access::U2K_WRITE,
            reserved: 0,
        },
        ring_index: 0,
        reserved: 0,
    };
    assert_eq!(validated.notification_credit_count(), 1);
    assert_eq!(validated.notification_credit(0), Some(expected_credit));
    assert_eq!(validated.notification_credit(1), None);
    assert_eq!(validated.notification_credit(u32::MAX), None);
}

#[test]
fn session_result_rejects_wrong_prefix_echo_views_and_credits() {
    let setup = validated_setup(1, 1);
    let rings = ring_view_layouts(1);
    let layout = SessionViewLayout::for_setup(
        &setup,
        section_size_for_rings(1),
        4_096,
        u2k_arena_for_rings(1),
        &rings,
    )
    .unwrap();
    let valid = build_session_result(&setup, &layout, false);

    let mut bytes = valid.clone();
    put_u16(&mut bytes, 4, 2);
    assert_session_result_error(&bytes, &layout, SessionValidationError::RevisionMismatch);

    let mut bytes = valid.clone();
    put_u16(&mut bytes, 6, 1);
    assert_session_result_error(&bytes, &layout, SessionValidationError::NotSupported);

    let mut bytes = valid.clone();
    put_u32(&mut bytes, 0, 327);
    assert_session_result_error(&bytes, &layout, SessionValidationError::InvalidParameter);
    assert_session_result_error(
        &valid[..valid.len() - 1],
        &layout,
        SessionValidationError::InvalidParameter,
    );
    let mut trailing = valid.clone();
    trailing.push(0);
    assert_session_result_error(&trailing, &layout, SessionValidationError::InvalidParameter);

    for offset in [12usize, 128, 132] {
        let mut bytes = valid.clone();
        put_u32(&mut bytes, offset, 1);
        assert_session_result_error(&bytes, &layout, SessionValidationError::InvalidParameter);
    }

    for offset in [8usize, 10] {
        let mut bytes = valid.clone();
        put_u16(&mut bytes, offset, 3);
        assert_session_result_error(&bytes, &layout, SessionValidationError::RevisionMismatch);
    }

    for identity_offset in [16usize, 24] {
        let mut bytes = valid.clone();
        put_u64(&mut bytes, identity_offset, 0);
        assert_session_result_error(&bytes, &layout, SessionValidationError::InvalidParameter);
    }
    let mut zero_boot = valid.clone();
    put_u64(&mut zero_boot, 32, 0);
    put_u64(&mut zero_boot, 40, 0);
    assert_session_result_error(
        &zero_boot,
        &layout,
        SessionValidationError::InvalidParameter,
    );

    let mut zero_boot_lo_only = valid.clone();
    put_u64(&mut zero_boot_lo_only, 32, 0);
    assert!(validate_session_result_v1(&zero_boot_lo_only, &layout).is_ok());
    let mut zero_boot_hi_only = valid.clone();
    put_u64(&mut zero_boot_hi_only, 40, 0);
    assert!(validate_session_result_v1(&zero_boot_hi_only, &layout).is_ok());

    for epoch in [0, 2] {
        let mut bytes = valid.clone();
        put_u64(&mut bytes, 48, epoch);
        assert_session_result_error(&bytes, &layout, SessionValidationError::InvalidParameter);
    }

    for (offset, value) in [(56usize, 65_536u64), (64, 0x1fu64), (80, 0x1u64)] {
        let mut bytes = valid.clone();
        put_u64(&mut bytes, offset, value);
        assert_session_result_error(&bytes, &layout, SessionValidationError::InvalidParameter);
    }

    for (offset, value) in [
        (96usize, 4u32),
        (100, 31),
        (104, 137),
        (108, 2),
        (112, 31),
        (116, 295),
        (120, 2),
        (124, 2),
    ] {
        let mut bytes = valid.clone();
        put_u32(&mut bytes, offset, value);
        assert_session_result_error(&bytes, &layout, SessionValidationError::InvalidParameter);
    }

    for view_index in 0..5usize {
        let base =
            SESSION_RESULT_V1_PREFIX_SIZE as usize + view_index * USER_VIEW_DESC_SIZE as usize;
        let mut bytes = valid.clone();
        put_u64(&mut bytes, base, u64::MAX);
        assert_session_result_error(&bytes, &layout, SessionValidationError::InvalidParameter);

        let mut bytes = valid.clone();
        put_u64(&mut bytes, base + 8, 0);
        assert_session_result_error(&bytes, &layout, SessionValidationError::InvalidParameter);

        let mut bytes = valid.clone();
        put_u32(&mut bytes, base + 24, 1);
        assert_session_result_error(&bytes, &layout, SessionValidationError::InvalidParameter);

        let mut bytes = valid.clone();
        put_u16(&mut bytes, base + 28, view_kind::INVALID);
        assert_session_result_error(&bytes, &layout, SessionValidationError::InvalidParameter);

        let mut bytes = valid.clone();
        put_u16(&mut bytes, base + 30, view_access::INVALID);
        assert_session_result_error(&bytes, &layout, SessionValidationError::InvalidParameter);
    }

    let credit_offset = 296usize;
    for (relative_offset, width, value) in [
        (0usize, 8usize, 0u64),
        (8, 4, 1),
        (12, 4, 2_049),
        (16, 2, buffer_kind::NONE as u64),
        (18, 2, buffer_access::K2U_READ_ONLY as u64),
        (20, 4, 1),
        (24, 4, 1),
        (28, 4, 1),
    ] {
        let mut bytes = valid.clone();
        match width {
            2 => put_u16(&mut bytes, credit_offset + relative_offset, value as u16),
            4 => put_u32(&mut bytes, credit_offset + relative_offset, value as u32),
            8 => put_u64(&mut bytes, credit_offset + relative_offset, value),
            _ => unreachable!(),
        }
        assert_session_result_error(&bytes, &layout, SessionValidationError::InvalidParameter);
    }

    let mut wrong_class = valid.clone();
    put_u64(
        &mut wrong_class,
        credit_offset,
        SlotToken::try_new(1, 0, 1).unwrap().raw(),
    );
    assert_session_result_error(
        &wrong_class,
        &layout,
        SessionValidationError::InvalidParameter,
    );

    let mut wrong_index = valid.clone();
    put_u64(
        &mut wrong_index,
        credit_offset,
        SlotToken::try_new(0, 1, 1).unwrap().raw(),
    );
    assert_session_result_error(
        &wrong_index,
        &layout,
        SessionValidationError::InvalidParameter,
    );

    let setup_two = validated_setup(2, 2);
    let rings_two = ring_view_layouts(2);
    let layout_two = SessionViewLayout::for_setup(
        &setup_two,
        section_size_for_rings(2),
        4_096,
        u2k_arena_for_rings(2),
        &rings_two,
    )
    .unwrap();
    let valid_two = build_session_result(&setup_two, &layout_two, false);
    let credits_two_offset =
        (SESSION_RESULT_V1_PREFIX_SIZE + (2 + 3 * 2) * USER_VIEW_DESC_SIZE) as usize;

    let mut duplicate = valid_two.clone();
    put_u64(
        &mut duplicate,
        credits_two_offset + NOTIFICATION_CREDIT_V1_SIZE as usize,
        SlotToken::try_new(0, 0, 1).unwrap().raw(),
    );
    assert_session_result_error(
        &duplicate,
        &layout_two,
        SessionValidationError::InvalidParameter,
    );

    let mut same_slot_new_generation = valid_two.clone();
    put_u64(
        &mut same_slot_new_generation,
        credits_two_offset + NOTIFICATION_CREDIT_V1_SIZE as usize,
        SlotToken::try_new(0, 0, 2).unwrap().raw(),
    );
    assert_session_result_error(
        &same_slot_new_generation,
        &layout_two,
        SessionValidationError::InvalidParameter,
    );

    let mut imbalanced = valid_two;
    put_u32(
        &mut imbalanced,
        credits_two_offset + NOTIFICATION_CREDIT_V1_SIZE as usize + 24,
        0,
    );
    assert_session_result_error(
        &imbalanced,
        &layout_two,
        SessionValidationError::InvalidParameter,
    );

    let setup_per_ring_cap = validated_setup(2, 128);
    let rings_per_ring_cap = ring_view_layouts(2);
    let layout_per_ring_cap = SessionViewLayout::for_setup(
        &setup_per_ring_cap,
        section_size_for_rings(2),
        4_096,
        u2k_arena_for_rings(2),
        &rings_per_ring_cap,
    )
    .unwrap();
    let mut over_per_ring_cap =
        build_session_result(&setup_per_ring_cap, &layout_per_ring_cap, false);
    for ordinal in 0..128usize {
        put_u32(
            &mut over_per_ring_cap,
            credits_two_offset + ordinal * NOTIFICATION_CREDIT_V1_SIZE as usize + 24,
            if ordinal < 65 { 0 } else { 1 },
        );
    }
    assert_session_result_error(
        &over_per_ring_cap,
        &layout_per_ring_cap,
        SessionValidationError::InvalidParameter,
    );
}

#[test]
fn session_result_accepts_ring_1_16_64_and_maximum_credit_multisets() {
    for (ring_count, credit_count) in [(1, 64), (3, 4), (16, 1_024), (64, 1_024)] {
        let setup = validated_setup(ring_count, credit_count);
        let rings = ring_view_layouts(ring_count);
        let layout = SessionViewLayout::for_setup(
            &setup,
            section_size_for_rings(ring_count),
            4_096,
            u2k_arena_for_rings(ring_count),
            &rings,
        )
        .unwrap();
        let bytes = build_session_result(&setup, &layout, true);
        let expected_size = SESSION_RESULT_V1_PREFIX_SIZE
            + (2 + 3 * ring_count) * USER_VIEW_DESC_SIZE
            + credit_count * NOTIFICATION_CREDIT_V1_SIZE;
        assert_eq!(bytes.len(), expected_size as usize);
        assert_eq!(session_result_size_v1(&setup.topology()), Ok(expected_size));

        let validated = validate_session_result_v1(&bytes, &layout).unwrap();
        assert!(validated.view(0).is_some());
        assert!(validated.view(validated.view_count() - 1).is_some());
        assert!(validated.notification_credit(0).is_some());
        assert!(validated
            .notification_credit(validated.notification_credit_count() - 1)
            .is_some());
        assert_eq!(
            SlotToken::from_raw(validated.notification_credit(0).unwrap().buffer.token)
                .unwrap()
                .index(),
            credit_count - 1
        );
        assert_eq!(
            SlotToken::from_raw(
                validated
                    .notification_credit(credit_count - 1)
                    .unwrap()
                    .buffer
                    .token
            )
            .unwrap()
            .index(),
            0
        );
    }
}

#[test]
fn session_result_claimed_tail_arithmetic_fails_closed() {
    let setup = validated_setup(1, 1);
    let rings = ring_view_layouts(1);
    let layout = SessionViewLayout::for_setup(
        &setup,
        section_size_for_rings(1),
        4_096,
        u2k_arena_for_rings(1),
        &rings,
    )
    .unwrap();
    let valid = build_session_result(&setup, &layout, false);

    let mut huge_view_count = valid.clone();
    put_u32(&mut huge_view_count, 96, u32::MAX);
    assert_session_result_error(
        &huge_view_count,
        &layout,
        SessionValidationError::InvalidParameter,
    );

    let mut huge_credit_count = valid;
    put_u32(&mut huge_credit_count, 108, u32::MAX);
    assert_session_result_error(
        &huge_credit_count,
        &layout,
        SessionValidationError::InvalidParameter,
    );
}

fn wave3c_encode_fixed<T: Pod, const N: usize>(value: &T) -> [u8; N] {
    let mut bytes = [0xa5; N];
    assert_eq!(try_encode(value, &mut bytes), Ok(N));
    bytes
}

fn wave3c_identity() -> SessionIdentity {
    SessionIdentity {
        mount_id: MountId { lo: 1, hi: 2 },
        boot_instance_id: BootInstanceId { lo: 3, hi: 4 },
        session_epoch: 1,
    }
}

fn wave3c_setup_without_restart() -> ValidatedSetupRequest {
    let mut request = valid_setup_request(1, 2);
    request.offered_features = feature_words(1u64 << protocol_feature::SECURITY, 0);
    request.required_features = feature_words(1u64 << protocol_feature::SECURITY, 0);
    validate_setup(&request).unwrap()
}

fn wave3c_setup_with_cq_capacity(
    ring_count: u32,
    credit_count: u32,
    cq_capacity: u32,
) -> ValidatedSetupRequest {
    let mut request = valid_setup_request(ring_count, credit_count);
    request.cq_capacity = cq_capacity;
    validate_setup(&request).unwrap()
}

fn wave3c_expectation(setup: &ValidatedSetupRequest) -> AttachExpectation {
    AttachExpectation::new(wave3c_identity(), setup.selection(), setup.topology()).unwrap()
}

fn wave3c_attach_layout<'a>(
    expected: &AttachExpectation,
    section_size: u64,
    page_size: u32,
    u2k_arena: RegionDesc,
    rings: &'a [RingViewLayout],
) -> Result<SessionViewLayout<'a>, SessionContextError> {
    SessionViewLayout::for_attach(expected, section_size, page_size, u2k_arena, rings)
}

fn wave3c_assert_attach_context_error(
    result: Result<SessionViewLayout<'_>, SessionContextError>,
    expected: SessionContextError,
) {
    match result {
        Err(actual) => assert_eq!(actual, expected),
        Ok(_) => panic!("invalid ATTACH layout accepted"),
    }
}

fn wave3c_attach_bytes(expected: &AttachExpectation, journal_version: u32) -> [u8; 56] {
    let identity = expected.prior_identity();
    wave3c_encode_fixed(&AttachV1 {
        header: ControlHeader {
            struct_size: 56,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        prior_session_epoch: identity.session_epoch,
        requested_features: expected.selected_features(),
        mount_id: identity.mount_id,
        journal_version,
        flags: 0,
    })
}

fn wave3c_assert_attach_error(
    bytes: &[u8],
    expected: &AttachExpectation,
    error: SessionValidationError,
) {
    match validate_attach_v1(bytes, expected) {
        Err(actual) => assert_eq!(actual, error),
        Ok(_) => panic!("invalid ATTACH accepted"),
    }
}

fn wave3c_enter_request(
    identity: SessionIdentity,
    ring_index: u32,
    flags: u32,
    cq_budget: u32,
    timeout_ms: u32,
) -> EnterRequestV1 {
    EnterRequestV1 {
        header: ControlHeader {
            struct_size: ENTER_REQUEST_V1_SIZE,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        mount_id: identity.mount_id,
        session_epoch: identity.session_epoch,
        ring_index,
        flags,
        cq_budget,
        timeout_ms,
    }
}

fn wave3c_enter_request_bytes(request: &EnterRequestV1) -> [u8; 48] {
    wave3c_encode_fixed(request)
}

fn wave3c_build_enter_result(
    request: &EnterRequestV1,
    topology: &ValidatedTopology,
    flags: u32,
    cq_drained: u32,
    sq_ready: u32,
    physical_indices: &[u32],
) -> Vec<u8> {
    let count = u32::try_from(physical_indices.len()).unwrap();
    let struct_size = ENTER_RESULT_V1_PREFIX_SIZE + count * NOTIFICATION_CREDIT_V1_SIZE;
    let prefix = EnterResultV1 {
        header: ControlHeader {
            struct_size,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        session_epoch: request.session_epoch,
        ring_index: request.ring_index,
        flags,
        cq_drained,
        sq_ready,
        notification_credit_count: count,
        notification_credit_desc_size: NOTIFICATION_CREDIT_V1_SIZE,
        notification_credits_offset: if count == 0 {
            0
        } else {
            ENTER_RESULT_V1_PREFIX_SIZE
        },
        reserved: 0,
    };
    let mut bytes = vec![0u8; struct_size as usize];
    encode_at(&prefix, &mut bytes, 0);
    for (ordinal, physical_index) in physical_indices.iter().copied().enumerate() {
        let credit = NotificationCreditV1 {
            buffer: BufferRef {
                token: SlotToken::try_new(topology.notification_credit_class(), physical_index, 1)
                    .unwrap()
                    .raw(),
                offset: 0,
                length: topology.notification_credit_size(),
                kind: buffer_kind::SLOT,
                access: buffer_access::U2K_WRITE,
                reserved: 0,
            },
            ring_index: request.ring_index,
            reserved: 0,
        };
        encode_at(
            &credit,
            &mut bytes,
            ENTER_RESULT_V1_PREFIX_SIZE as usize + ordinal * NOTIFICATION_CREDIT_V1_SIZE as usize,
        );
    }
    bytes
}

fn wave3c_assert_enter_result_error(
    bytes: &[u8],
    request: &EnterRequestV1,
    topology: &ValidatedTopology,
    error: SessionValidationError,
) {
    match validate_enter_result_v1(bytes, request, topology) {
        Err(actual) => assert_eq!(actual, error),
        Ok(_) => panic!("invalid ENTER result accepted"),
    }
}

fn wave3c_detach_bytes(identity: SessionIdentity) -> [u8; 40] {
    wave3c_encode_fixed(&DetachRequestV1 {
        header: ControlHeader {
            struct_size: DETACH_REQUEST_V1_SIZE,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        mount_id: identity.mount_id,
        session_epoch: identity.session_epoch,
        flags: 0,
        reserved: 0,
    })
}

fn wave3c_donate_backing_v1_bytes() -> [u8; 48] {
    wave3c_encode_fixed(&DonateBackingV1 {
        header: ControlHeader {
            struct_size: 48,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        file_id: FileId { lo: 5, hi: 6 },
        pt_epoch: 7,
        daemon_handle: 0,
        sector_size: MIN_BACKING_SECTOR_SIZE,
        flags: 0,
    })
}

fn wave3c_utf16_units(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

fn wave3c_donate_backing_v2_bytes(path: &[u16]) -> Vec<u8> {
    let path_length = path.len().checked_mul(2).unwrap();
    let end = DONATE_BACKING_V2_PREFIX_SIZE as usize + path_length;
    let struct_size = end.checked_add(7).unwrap() & !7;
    let prefix = DonateBackingV2 {
        header: ControlHeader {
            struct_size: u32::try_from(struct_size).unwrap(),
            struct_version: DONATE_BACKING_VERSION_V2,
            required_flags: 0,
        },
        file_id: FileId { lo: 5, hi: 6 },
        pt_epoch: 7,
        sector_size: MIN_BACKING_SECTOR_SIZE,
        flags: 0,
        backing_path: BlobSlice {
            offset: DONATE_BACKING_V2_PREFIX_SIZE,
            length: u32::try_from(path_length).unwrap(),
        },
    };
    let mut bytes = vec![0u8; struct_size];
    encode_at(&prefix, &mut bytes, 0);
    for (index, unit) in path.iter().copied().enumerate() {
        put_u16(
            &mut bytes,
            DONATE_BACKING_V2_PREFIX_SIZE as usize + 2 * index,
            unit,
        );
    }
    bytes
}

fn wave3c_assert_donate_backing_error(bytes: &[u8], error: SessionValidationError) {
    match validate_donate_backing_v2(bytes) {
        Err(actual) => assert_eq!(actual, error),
        Ok(_) => panic!("invalid backing donation accepted"),
    }
}

fn wave3c_security_donation_bytes() -> [u8; 32] {
    wave3c_encode_fixed(&control::DonateSecurityContextV1 {
        header: ControlHeader {
            struct_size: 32,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        security_context_id: 0,
        daemon_handle: 0,
        flags: 0,
        reserved: 0,
    })
}

fn wave3c_retire_request_bytes(request: &RetireMountV1) -> [u8; 48] {
    wave3c_encode_fixed(request)
}

fn wave3c_retire_query(mount_id: MountId) -> RetireMountV1 {
    RetireMountV1 {
        header: ControlHeader {
            struct_size: RETIRE_MOUNT_V1_SIZE,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        mount_id,
        token: RetireToken::ZERO,
        action: retire_mount_action::QUERY,
        reserved: 0,
    }
}

fn wave3c_retire_result_bytes(
    mount_id: MountId,
    proof_token: RetireToken,
    latest_session_epoch: u64,
    selected_features: FeatureSet,
    journal_version: u32,
    mount_state: u16,
) -> [u8; 96] {
    wave3c_encode_fixed(&RetireMountResultV1 {
        header: ControlHeader {
            struct_size: RETIRE_MOUNT_RESULT_V1_SIZE,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        mount_id,
        boot_instance_id: BootInstanceId { lo: 3, hi: 4 },
        proof_token,
        latest_session_epoch,
        selected_features,
        journal_version,
        mount_state,
        flags: 0,
        reserved: 0,
    })
}

#[test]
fn wave3c_public_surface_and_contexts_compile() {
    assert_eq!(enter_result_size_v1(0), Ok(ENTER_RESULT_V1_PREFIX_SIZE));
    assert_eq!(enter_result_size_v1(1), Ok(80));
    assert_eq!(
        enter_result_size_v1(u32::MAX),
        Err(SessionContextError::ArithmeticOverflow)
    );

    let setup = validated_setup(1, 2);
    let rings = ring_view_layouts(1);
    let setup_layout = SessionViewLayout::for_setup(
        &setup,
        section_size_for_rings(1),
        4_096,
        u2k_arena_for_rings(1),
        &rings,
    )
    .unwrap();
    let prior_bytes = build_session_result(&setup, &setup_layout, false);
    let prior = validate_session_result_v1(&prior_bytes, &setup_layout).unwrap();
    let prior_identity = prior.identity();
    let expectation =
        AttachExpectation::new(prior_identity, setup.selection(), setup.topology()).unwrap();
    assert_eq!(expectation.prior_identity(), prior_identity);
    assert_eq!(
        expectation.selected_features(),
        setup.selection().selected_features
    );
    assert_eq!(expectation.topology(), setup.topology());
    assert_eq!(expectation.next_session_epoch(), 2);

    wave3c_assert_attach_context_error(
        wave3c_attach_layout(
            &expectation,
            section_size_for_rings(1),
            4_096,
            u2k_arena_for_rings(1),
            &[],
        ),
        SessionContextError::InvalidRingCount,
    );
    wave3c_assert_attach_context_error(
        wave3c_attach_layout(
            &expectation,
            section_size_for_rings(1),
            0,
            u2k_arena_for_rings(1),
            &rings,
        ),
        SessionContextError::InvalidPageSize,
    );
    wave3c_assert_attach_context_error(
        wave3c_attach_layout(&expectation, 0, 4_096, u2k_arena_for_rings(1), &rings),
        SessionContextError::InvalidSectionSize,
    );
    wave3c_assert_attach_context_error(
        wave3c_attach_layout(
            &expectation,
            section_size_for_rings(1),
            4_096,
            RegionDesc {
                offset: 0,
                length: USER_VIEW_OFFSET_ALIGNMENT,
            },
            &rings,
        ),
        SessionContextError::InvalidRegion,
    );
    let mut overlap = rings.clone();
    overlap[0].sq_consumer.offset = overlap[0].cq_entries.offset;
    wave3c_assert_attach_context_error(
        wave3c_attach_layout(
            &expectation,
            section_size_for_rings(1),
            4_096,
            u2k_arena_for_rings(1),
            &overlap,
        ),
        SessionContextError::OverlappingWritableViews,
    );

    for boot_instance_id in [
        BootInstanceId { lo: 0, hi: 4 },
        BootInstanceId { lo: 3, hi: 0 },
    ] {
        let one_word_boot = AttachExpectation::new(
            SessionIdentity {
                boot_instance_id,
                ..prior_identity
            },
            setup.selection(),
            setup.topology(),
        )
        .unwrap();
        assert_eq!(
            one_word_boot.prior_identity().boot_instance_id,
            boot_instance_id
        );
    }

    for invalid_identity in [
        SessionIdentity {
            mount_id: MountId {
                lo: 0,
                ..prior_identity.mount_id
            },
            ..prior_identity
        },
        SessionIdentity {
            mount_id: MountId {
                hi: 0,
                ..prior_identity.mount_id
            },
            ..prior_identity
        },
        SessionIdentity {
            boot_instance_id: BootInstanceId::ZERO,
            ..prior_identity
        },
        SessionIdentity {
            session_epoch: 0,
            ..prior_identity
        },
    ] {
        assert_eq!(
            AttachExpectation::new(invalid_identity, setup.selection(), setup.topology()),
            Err(SessionContextError::InvalidIdentity)
        );
    }

    for selected_features in [
        feature_words(
            (1u64 << protocol_feature::SECURITY) | (1u64 << protocol_feature::HOT_RESTART),
            0,
        ),
        feature_words(
            (1u64 << protocol_feature::SECURITY) | (1u64 << protocol_feature::EXACTLY_ONCE),
            0,
        ),
    ] {
        let mut selection = setup.selection();
        selection.selected_features = selected_features;
        assert_eq!(
            AttachExpectation::new(prior_identity, selection, setup.topology()),
            Err(SessionContextError::InvalidFeatureSelection)
        );
    }

    assert_eq!(
        AttachExpectation::new(
            SessionIdentity {
                session_epoch: u64::MAX,
                ..prior_identity
            },
            setup.selection(),
            setup.topology(),
        ),
        Err(SessionContextError::ArithmeticOverflow)
    );
}

#[test]
fn attach_request_and_result_identity_are_exact() {
    let setup = validated_setup(1, 2);
    let rings = ring_view_layouts(1);
    let setup_layout = SessionViewLayout::for_setup(
        &setup,
        section_size_for_rings(1),
        4_096,
        u2k_arena_for_rings(1),
        &rings,
    )
    .unwrap();
    let prior_bytes = build_session_result(&setup, &setup_layout, false);
    let prior = validate_session_result_v1(&prior_bytes, &setup_layout).unwrap();
    let expectation =
        AttachExpectation::new(prior.identity(), setup.selection(), setup.topology()).unwrap();

    let valid = wave3c_attach_bytes(&expectation, 1);
    let accepted = validate_attach_v1(&valid, &expectation).unwrap();
    let accepted_bytes: [u8; 56] = wave3c_encode_fixed(&accepted);
    assert_eq!(accepted_bytes, valid);
    wave3c_assert_attach_error(
        &valid[..55],
        &expectation,
        SessionValidationError::InvalidParameter,
    );
    let mut trailing = valid.to_vec();
    trailing.push(0);
    wave3c_assert_attach_error(
        &trailing,
        &expectation,
        SessionValidationError::InvalidParameter,
    );

    for (offset, value) in [(8usize, 2u64), (32, 9), (40, 9)] {
        let mut bytes = valid;
        put_u64(&mut bytes, offset, value);
        wave3c_assert_attach_error(
            &bytes,
            &expectation,
            SessionValidationError::InvalidParameter,
        );
    }
    for (offset, value) in [(16usize, 0u64), (24, 1)] {
        let mut bytes = valid;
        put_u64(&mut bytes, offset, value);
        wave3c_assert_attach_error(
            &bytes,
            &expectation,
            SessionValidationError::InvalidParameter,
        );
    }
    let mut request_flags = valid;
    put_u32(&mut request_flags, 52, 1);
    wave3c_assert_attach_error(
        &request_flags,
        &expectation,
        SessionValidationError::InvalidParameter,
    );

    let attach_layout = wave3c_attach_layout(
        &expectation,
        section_size_for_rings(1),
        4_096,
        u2k_arena_for_rings(1),
        &rings,
    )
    .unwrap();
    let mut result_bytes = build_session_result(&setup, &attach_layout, false);
    put_u64(&mut result_bytes, 48, expectation.next_session_epoch());
    let attached = validate_session_result_v1(&result_bytes, &attach_layout).unwrap();
    assert_eq!(
        attached.identity(),
        SessionIdentity {
            session_epoch: expectation.next_session_epoch(),
            ..prior.identity()
        }
    );

    for (offset, value) in [
        (16usize, 9u64),
        (24, 9),
        (32, 9),
        (40, 9),
        (48, expectation.next_session_epoch() + 1),
    ] {
        let mut bytes = result_bytes.clone();
        put_u64(&mut bytes, offset, value);
        assert_session_result_error(
            &bytes,
            &attach_layout,
            SessionValidationError::InvalidParameter,
        );
    }
}

#[test]
fn attach_common_header_and_journal_precedence() {
    let setup = validated_setup(1, 2);
    let expectation = wave3c_expectation(&setup);
    let mut bytes = wave3c_attach_bytes(&expectation, 1);

    wave3c_assert_attach_error(
        &bytes[..7],
        &expectation,
        SessionValidationError::InvalidParameter,
    );
    put_u16(&mut bytes, 4, 2);
    wave3c_assert_attach_error(
        &bytes,
        &expectation,
        SessionValidationError::RevisionMismatch,
    );
    put_u16(&mut bytes, 4, CONTROL_VERSION_V1);
    put_u16(&mut bytes, 6, 1);
    wave3c_assert_attach_error(&bytes, &expectation, SessionValidationError::NotSupported);
    put_u16(&mut bytes, 6, 0);
    put_u32(&mut bytes, 0, 55);
    wave3c_assert_attach_error(
        &bytes,
        &expectation,
        SessionValidationError::InvalidParameter,
    );

    for journal_version in [0, 2] {
        let bytes = wave3c_attach_bytes(&expectation, journal_version);
        wave3c_assert_attach_error(
            &bytes,
            &expectation,
            SessionValidationError::InvalidParameter,
        );
    }
    let mut mismatched_pair = wave3c_attach_bytes(&expectation, 1);
    put_u64(
        &mut mismatched_pair,
        16,
        (1u64 << protocol_feature::SECURITY) | (1u64 << protocol_feature::HOT_RESTART),
    );
    put_u64(&mut mismatched_pair, 24, 0);
    wave3c_assert_attach_error(
        &mismatched_pair,
        &expectation,
        SessionValidationError::InvalidParameter,
    );

    let no_restart_setup = wave3c_setup_without_restart();
    let no_restart = wave3c_expectation(&no_restart_setup);
    assert!(validate_attach_v1(&wave3c_attach_bytes(&no_restart, 0), &no_restart).is_ok());
    wave3c_assert_attach_error(
        &wave3c_attach_bytes(&no_restart, 1),
        &no_restart,
        SessionValidationError::InvalidParameter,
    );
}

#[test]
fn enter_request_roles_budgets_timeouts_and_identity() {
    let setup = validated_setup(1, 2);
    let topology = setup.topology();
    let identity = wave3c_identity();
    let canonical = wave3c_enter_request(identity, 0, 0, 0, 0);
    let mut bytes = wave3c_enter_request_bytes(&canonical);

    assert_eq!(
        validate_enter_request_v1(&bytes[..7], identity, &topology).err(),
        Some(SessionValidationError::InvalidParameter)
    );
    put_u16(&mut bytes, 4, 2);
    assert_eq!(
        validate_enter_request_v1(&bytes, identity, &topology).err(),
        Some(SessionValidationError::RevisionMismatch)
    );
    put_u16(&mut bytes, 4, CONTROL_VERSION_V1);
    put_u16(&mut bytes, 6, 1);
    assert_eq!(
        validate_enter_request_v1(&bytes, identity, &topology).err(),
        Some(SessionValidationError::NotSupported)
    );
    put_u16(&mut bytes, 6, 0);
    put_u32(&mut bytes, 0, ENTER_REQUEST_V1_SIZE - 1);
    assert_eq!(
        validate_enter_request_v1(&bytes, identity, &topology).err(),
        Some(SessionValidationError::InvalidParameter)
    );

    for request in [
        canonical,
        wave3c_enter_request(identity, 0, enter_request_flags::DRAIN_CQ, 1, 0),
        wave3c_enter_request(identity, 0, enter_request_flags::DRAIN_CQ, 2, 0),
        wave3c_enter_request(identity, 0, enter_request_flags::WAIT_SQ, 0, 0),
        wave3c_enter_request(identity, 0, enter_request_flags::WAIT_SQ, 0, 37),
        wave3c_enter_request(
            identity,
            0,
            enter_request_flags::WAIT_SQ,
            0,
            ENTER_TIMEOUT_INFINITE,
        ),
    ] {
        let encoded = wave3c_enter_request_bytes(&request);
        assert_eq!(
            validate_enter_request_v1(&encoded, identity, &topology),
            Ok(request)
        );
    }

    for invalid_identity in [
        SessionIdentity {
            mount_id: MountId {
                lo: 0,
                ..identity.mount_id
            },
            ..identity
        },
        SessionIdentity {
            mount_id: MountId {
                hi: 0,
                ..identity.mount_id
            },
            ..identity
        },
        SessionIdentity {
            session_epoch: 0,
            ..identity
        },
    ] {
        let request = wave3c_enter_request(invalid_identity, 0, 0, 0, 0);
        assert_eq!(
            validate_enter_request_v1(
                &wave3c_enter_request_bytes(&request),
                invalid_identity,
                &topology,
            )
            .err(),
            Some(SessionValidationError::InvalidParameter)
        );
    }

    let large_setup = wave3c_setup_with_cq_capacity(1, 2, 8_192);
    let large_topology = large_setup.topology();
    let maximum = wave3c_enter_request(
        identity,
        0,
        enter_request_flags::DRAIN_CQ,
        MAX_ENTER_CQ_BUDGET,
        0,
    );
    assert!(validate_enter_request_v1(
        &wave3c_enter_request_bytes(&maximum),
        identity,
        &large_topology,
    )
    .is_ok());
    let over_maximum = EnterRequestV1 {
        cq_budget: MAX_ENTER_CQ_BUDGET + 1,
        ..maximum
    };
    assert_eq!(
        validate_enter_request_v1(
            &wave3c_enter_request_bytes(&over_maximum),
            identity,
            &large_topology,
        )
        .err(),
        Some(SessionValidationError::InvalidParameter)
    );

    let mut trailing = wave3c_enter_request_bytes(&canonical).to_vec();
    trailing.push(0);
    assert_eq!(
        validate_enter_request_v1(&trailing, identity, &topology).err(),
        Some(SessionValidationError::InvalidParameter)
    );
    assert_eq!(
        validate_enter_request_v1(
            &wave3c_enter_request_bytes(&canonical)[..47],
            identity,
            &topology,
        )
        .err(),
        Some(SessionValidationError::InvalidParameter)
    );

    for (offset, value) in [
        (8usize, 0u64),
        (16, 0),
        (8, identity.mount_id.lo + 1),
        (16, identity.mount_id.hi + 1),
        (24, 0),
        (24, identity.session_epoch + 1),
    ] {
        let mut encoded = wave3c_enter_request_bytes(&canonical);
        put_u64(&mut encoded, offset, value);
        assert_eq!(
            validate_enter_request_v1(&encoded, identity, &topology).err(),
            Some(SessionValidationError::InvalidParameter)
        );
    }

    for request in [
        wave3c_enter_request(identity, 1, 0, 0, 0),
        wave3c_enter_request(identity, 0, !enter_request_flags::KNOWN_MASK, 0, 0),
        wave3c_enter_request(
            identity,
            0,
            enter_request_flags::DRAIN_CQ | enter_request_flags::WAIT_SQ,
            1,
            0,
        ),
        wave3c_enter_request(identity, 0, enter_request_flags::DRAIN_CQ, 0, 0),
        wave3c_enter_request(identity, 0, enter_request_flags::DRAIN_CQ, 3, 0),
        wave3c_enter_request(identity, 0, 0, 1, 0),
        wave3c_enter_request(identity, 0, 0, 0, 1),
        wave3c_enter_request(identity, 0, enter_request_flags::DRAIN_CQ, 1, 1),
    ] {
        let encoded = wave3c_enter_request_bytes(&request);
        assert_eq!(
            validate_enter_request_v1(&encoded, identity, &topology).err(),
            Some(SessionValidationError::InvalidParameter),
            "accepted invalid ENTER request: {request:?}"
        );
    }
}

#[test]
fn enter_result_tail_and_accessors_are_exact() {
    let setup = validated_setup(1, 2);
    let topology = setup.topology();
    let identity = wave3c_identity();
    let request = wave3c_enter_request(identity, 0, enter_request_flags::DRAIN_CQ, 2, 0);
    let request =
        validate_enter_request_v1(&wave3c_enter_request_bytes(&request), identity, &topology)
            .unwrap();

    let mut zero = wave3c_build_enter_result(&request, &topology, 0, 0, 0, &[]);
    wave3c_assert_enter_result_error(
        &zero[..7],
        &request,
        &topology,
        SessionValidationError::InvalidParameter,
    );
    put_u16(&mut zero, 4, 2);
    wave3c_assert_enter_result_error(
        &zero,
        &request,
        &topology,
        SessionValidationError::RevisionMismatch,
    );
    put_u16(&mut zero, 4, CONTROL_VERSION_V1);
    put_u16(&mut zero, 6, 1);
    wave3c_assert_enter_result_error(
        &zero,
        &request,
        &topology,
        SessionValidationError::NotSupported,
    );
    put_u16(&mut zero, 6, 0);
    put_u32(&mut zero, 0, ENTER_RESULT_V1_PREFIX_SIZE - 1);
    wave3c_assert_enter_result_error(
        &zero,
        &request,
        &topology,
        SessionValidationError::InvalidParameter,
    );

    let zero = wave3c_build_enter_result(&request, &topology, 0, 0, 0, &[]);
    let validated_zero: ValidatedEnterResult<'_> =
        validate_enter_result_v1(&zero, &request, &topology).unwrap();
    assert_eq!(validated_zero.bytes(), zero.as_slice());
    assert_eq!(validated_zero.prefix().notification_credit_count, 0);
    assert_eq!(validated_zero.prefix().notification_credits_offset, 0);
    assert_eq!(validated_zero.notification_credit_count(), 0);
    assert_eq!(validated_zero.notification_credit(0), None);
    assert_eq!(validated_zero.notification_credit(u32::MAX), None);

    assert_eq!(enter_result_size_v1(2), Ok(112));
    let nonzero = wave3c_build_enter_result(
        &request,
        &topology,
        enter_result_flags::CQ_REMAINING,
        2,
        0,
        &[0, 1],
    );
    let validated: ValidatedEnterResult<'_> =
        validate_enter_result_v1(&nonzero, &request, &topology).unwrap();
    assert_eq!(validated.bytes(), nonzero.as_slice());
    assert_eq!(
        validated.prefix(),
        try_decode::<EnterResultV1>(&nonzero[..ENTER_RESULT_V1_PREFIX_SIZE as usize]).unwrap()
    );
    assert_eq!(validated.notification_credit_count(), 2);
    for index in 0..2 {
        let credit = validated.notification_credit(index).unwrap();
        assert_eq!(credit.ring_index, request.ring_index);
        assert_eq!(credit.buffer.length, topology.notification_credit_size());
        assert_eq!(
            SlotToken::from_raw(credit.buffer.token).unwrap().index(),
            index
        );
    }
    assert_eq!(validated.notification_credit(2), None);
    assert_eq!(validated.notification_credit(u32::MAX), None);

    let fewer_credits_than_drained = wave3c_build_enter_result(&request, &topology, 0, 2, 0, &[0]);
    assert!(validate_enter_result_v1(&fewer_credits_than_drained, &request, &topology).is_ok());

    wave3c_assert_enter_result_error(
        &nonzero[..nonzero.len() - 1],
        &request,
        &topology,
        SessionValidationError::InvalidParameter,
    );
    let mut trailing = nonzero.clone();
    trailing.push(0);
    wave3c_assert_enter_result_error(
        &trailing,
        &request,
        &topology,
        SessionValidationError::InvalidParameter,
    );

    let mut zero_with_offset = wave3c_build_enter_result(&request, &topology, 0, 0, 0, &[]);
    put_u32(&mut zero_with_offset, 40, ENTER_RESULT_V1_PREFIX_SIZE);
    wave3c_assert_enter_result_error(
        &zero_with_offset,
        &request,
        &topology,
        SessionValidationError::InvalidParameter,
    );

    for (offset, value) in [(36usize, 31u32), (36, 33), (40, 0), (40, 49)] {
        let mut bytes = nonzero.clone();
        put_u32(&mut bytes, offset, value);
        wave3c_assert_enter_result_error(
            &bytes,
            &request,
            &topology,
            SessionValidationError::InvalidParameter,
        );
    }

    let mut overflowing_count = wave3c_build_enter_result(&request, &topology, 0, 0, 0, &[]);
    put_u32(&mut overflowing_count, 32, u32::MAX);
    put_u32(&mut overflowing_count, 40, ENTER_RESULT_V1_PREFIX_SIZE);
    wave3c_assert_enter_result_error(
        &overflowing_count,
        &request,
        &topology,
        SessionValidationError::InvalidParameter,
    );
}

#[test]
fn enter_result_flags_and_credit_shape_fail_closed() {
    let setup = validated_setup(1, 2);
    let topology = setup.topology();
    let identity = wave3c_identity();
    let drain = wave3c_enter_request(identity, 0, enter_request_flags::DRAIN_CQ, 2, 0);
    let wait = wave3c_enter_request(identity, 0, enter_request_flags::WAIT_SQ, 0, 19);

    for bytes in [
        wave3c_build_enter_result(
            &drain,
            &topology,
            enter_result_flags::CQ_REMAINING,
            1,
            0,
            &[],
        ),
        wave3c_build_enter_result(
            &drain,
            &topology,
            enter_result_flags::CQ_REMAINING | enter_result_flags::NOTIFY_BLOCKED,
            1,
            0,
            &[],
        ),
        wave3c_build_enter_result(
            &drain,
            &topology,
            enter_result_flags::CQ_CONTENDED,
            1,
            0,
            &[],
        ),
    ] {
        assert!(validate_enter_result_v1(&bytes, &drain, &topology).is_ok());
    }
    for bytes in [
        wave3c_build_enter_result(&wait, &topology, enter_result_flags::SQ_READY, 0, 1, &[]),
        wave3c_build_enter_result(&wait, &topology, enter_result_flags::TIMED_OUT, 0, 0, &[]),
    ] {
        assert!(validate_enter_result_v1(&bytes, &wait, &topology).is_ok());
    }
    let no_wait = wave3c_enter_request(identity, 0, 0, 0, 0);
    let ready_without_wait =
        wave3c_build_enter_result(&no_wait, &topology, enter_result_flags::SQ_READY, 0, 1, &[]);
    assert!(validate_enter_result_v1(&ready_without_wait, &no_wait, &topology).is_ok());

    let valid_two = wave3c_build_enter_result(&drain, &topology, 0, 2, 0, &[0, 1]);
    let mut generation_two = wave3c_build_enter_result(&drain, &topology, 0, 1, 0, &[0]);
    put_u64(
        &mut generation_two,
        ENTER_RESULT_V1_PREFIX_SIZE as usize,
        SlotToken::try_new(topology.notification_credit_class(), 0, 2)
            .unwrap()
            .raw(),
    );
    assert!(validate_enter_result_v1(&generation_two, &drain, &topology).is_ok());
    for (offset, width, value) in [
        (8usize, 8usize, 2u64),
        (16, 4, 1),
        (20, 4, u64::from(!enter_result_flags::KNOWN_MASK)),
        (24, 4, 3),
        (28, 4, 2),
        (44, 4, 1),
    ] {
        let mut bytes = valid_two.clone();
        match width {
            4 => put_u32(&mut bytes, offset, value as u32),
            8 => put_u64(&mut bytes, offset, value),
            _ => unreachable!(),
        }
        wave3c_assert_enter_result_error(
            &bytes,
            &drain,
            &topology,
            SessionValidationError::InvalidParameter,
        );
    }

    let mut ready_without_flag = wave3c_build_enter_result(&wait, &topology, 0, 0, 0, &[]);
    put_u32(&mut ready_without_flag, 28, 1);
    wave3c_assert_enter_result_error(
        &ready_without_flag,
        &wait,
        &topology,
        SessionValidationError::InvalidParameter,
    );
    let ready_flag_without_value =
        wave3c_build_enter_result(&wait, &topology, enter_result_flags::SQ_READY, 0, 0, &[]);
    wave3c_assert_enter_result_error(
        &ready_flag_without_value,
        &wait,
        &topology,
        SessionValidationError::InvalidParameter,
    );

    let more_credits_than_drained = wave3c_build_enter_result(&drain, &topology, 0, 0, 0, &[0]);
    wave3c_assert_enter_result_error(
        &more_credits_than_drained,
        &drain,
        &topology,
        SessionValidationError::InvalidParameter,
    );

    let setup_one = validated_setup(1, 1);
    let topology_one = setup_one.topology();
    let drain_two = wave3c_enter_request(identity, 0, enter_request_flags::DRAIN_CQ, 2, 0);
    let more_than_topology = wave3c_build_enter_result(&drain_two, &topology_one, 0, 2, 0, &[0, 1]);
    wave3c_assert_enter_result_error(
        &more_than_topology,
        &drain_two,
        &topology_one,
        SessionValidationError::InvalidParameter,
    );

    let over_per_ring = MAX_NOTIFICATION_CREDITS_PER_RING + 1;
    let large_setup = wave3c_setup_with_cq_capacity(2, over_per_ring, 128);
    let large_topology = large_setup.topology();
    let large_drain =
        wave3c_enter_request(identity, 0, enter_request_flags::DRAIN_CQ, over_per_ring, 0);
    let physical_indices: Vec<u32> = (0..over_per_ring).collect();
    let too_many_for_ring = wave3c_build_enter_result(
        &large_drain,
        &large_topology,
        0,
        over_per_ring,
        0,
        &physical_indices,
    );
    wave3c_assert_enter_result_error(
        &too_many_for_ring,
        &large_drain,
        &large_topology,
        SessionValidationError::InvalidParameter,
    );

    let no_role = wave3c_enter_request(identity, 0, 0, 0, 0);
    for bytes in [
        wave3c_build_enter_result(&no_role, &topology, 0, 1, 0, &[]),
        wave3c_build_enter_result(&no_role, &topology, 0, 1, 0, &[0]),
        wave3c_build_enter_result(
            &no_role,
            &topology,
            enter_result_flags::CQ_REMAINING,
            0,
            0,
            &[],
        ),
        wave3c_build_enter_result(
            &no_role,
            &topology,
            enter_result_flags::NOTIFY_BLOCKED,
            0,
            0,
            &[],
        ),
        wave3c_build_enter_result(
            &no_role,
            &topology,
            enter_result_flags::CQ_CONTENDED,
            0,
            0,
            &[],
        ),
    ] {
        wave3c_assert_enter_result_error(
            &bytes,
            &no_role,
            &topology,
            SessionValidationError::InvalidParameter,
        );
    }

    for flags in [
        enter_result_flags::NOTIFY_BLOCKED,
        enter_result_flags::CQ_CONTENDED | enter_result_flags::CQ_REMAINING,
        enter_result_flags::CQ_CONTENDED
            | enter_result_flags::CQ_REMAINING
            | enter_result_flags::NOTIFY_BLOCKED,
    ] {
        let bytes = wave3c_build_enter_result(&drain, &topology, flags, 1, 0, &[]);
        wave3c_assert_enter_result_error(
            &bytes,
            &drain,
            &topology,
            SessionValidationError::InvalidParameter,
        );
    }

    let timed_out_without_wait =
        wave3c_build_enter_result(&drain, &topology, enter_result_flags::TIMED_OUT, 0, 0, &[]);
    wave3c_assert_enter_result_error(
        &timed_out_without_wait,
        &drain,
        &topology,
        SessionValidationError::InvalidParameter,
    );
    for (flags, sq_ready) in [
        (
            enter_result_flags::TIMED_OUT | enter_result_flags::SQ_READY,
            1,
        ),
        (
            enter_result_flags::TIMED_OUT | enter_result_flags::CQ_REMAINING,
            0,
        ),
        (
            enter_result_flags::TIMED_OUT
                | enter_result_flags::CQ_REMAINING
                | enter_result_flags::NOTIFY_BLOCKED,
            0,
        ),
        (
            enter_result_flags::TIMED_OUT | enter_result_flags::CQ_CONTENDED,
            0,
        ),
    ] {
        let bytes = wave3c_build_enter_result(&wait, &topology, flags, 0, sq_ready, &[]);
        wave3c_assert_enter_result_error(
            &bytes,
            &wait,
            &topology,
            SessionValidationError::InvalidParameter,
        );
    }

    for invalid_request in [
        wave3c_enter_request(
            SessionIdentity {
                mount_id: MountId {
                    lo: 0,
                    ..identity.mount_id
                },
                ..identity
            },
            0,
            0,
            0,
            0,
        ),
        wave3c_enter_request(
            SessionIdentity {
                mount_id: MountId {
                    hi: 0,
                    ..identity.mount_id
                },
                ..identity
            },
            0,
            0,
            0,
            0,
        ),
        wave3c_enter_request(
            SessionIdentity {
                session_epoch: 0,
                ..identity
            },
            0,
            0,
            0,
            0,
        ),
        wave3c_enter_request(identity, 1, 0, 0, 0),
        wave3c_enter_request(identity, 0, !enter_request_flags::KNOWN_MASK, 0, 0),
        wave3c_enter_request(
            identity,
            0,
            enter_request_flags::DRAIN_CQ | enter_request_flags::WAIT_SQ,
            1,
            0,
        ),
        wave3c_enter_request(identity, 0, enter_request_flags::DRAIN_CQ, 0, 0),
        wave3c_enter_request(identity, 0, enter_request_flags::DRAIN_CQ, 3, 0),
        wave3c_enter_request(identity, 0, 0, 1, 0),
        wave3c_enter_request(identity, 0, 0, 0, 1),
    ] {
        let bytes = wave3c_build_enter_result(&invalid_request, &topology, 0, 0, 0, &[]);
        wave3c_assert_enter_result_error(
            &bytes,
            &invalid_request,
            &topology,
            SessionValidationError::InvalidParameter,
        );
    }
    let maximum_setup = wave3c_setup_with_cq_capacity(1, 2, 8_192);
    let maximum_topology = maximum_setup.topology();
    let over_maximum_request = wave3c_enter_request(
        identity,
        0,
        enter_request_flags::DRAIN_CQ,
        MAX_ENTER_CQ_BUDGET + 1,
        0,
    );
    let over_maximum_result =
        wave3c_build_enter_result(&over_maximum_request, &maximum_topology, 0, 0, 0, &[]);
    wave3c_assert_enter_result_error(
        &over_maximum_result,
        &over_maximum_request,
        &maximum_topology,
        SessionValidationError::InvalidParameter,
    );

    let credit_offset = ENTER_RESULT_V1_PREFIX_SIZE as usize;
    for (relative_offset, width, value) in [
        (0usize, 8usize, 0u64),
        (8, 4, 1),
        (12, 4, u64::from(topology.notification_credit_size() + 1)),
        (16, 2, u64::from(buffer_kind::NONE)),
        (18, 2, u64::from(buffer_access::K2U_READ_ONLY)),
        (20, 4, 1),
        (24, 4, 1),
        (28, 4, 1),
    ] {
        let mut bytes = valid_two.clone();
        match width {
            2 => put_u16(&mut bytes, credit_offset + relative_offset, value as u16),
            4 => put_u32(&mut bytes, credit_offset + relative_offset, value as u32),
            8 => put_u64(&mut bytes, credit_offset + relative_offset, value),
            _ => unreachable!(),
        }
        wave3c_assert_enter_result_error(
            &bytes,
            &drain,
            &topology,
            SessionValidationError::InvalidParameter,
        );
    }

    let mut wrong_class = valid_two.clone();
    put_u64(
        &mut wrong_class,
        credit_offset,
        SlotToken::try_new(1, 0, 1).unwrap().raw(),
    );
    wave3c_assert_enter_result_error(
        &wrong_class,
        &drain,
        &topology,
        SessionValidationError::InvalidParameter,
    );

    let mut wrong_index = valid_two.clone();
    put_u64(
        &mut wrong_index,
        credit_offset,
        SlotToken::try_new(topology.notification_credit_class(), 2, 1)
            .unwrap()
            .raw(),
    );
    wave3c_assert_enter_result_error(
        &wrong_index,
        &drain,
        &topology,
        SessionValidationError::InvalidParameter,
    );

    let two_ring_setup = validated_setup(2, 2);
    let two_ring_topology = two_ring_setup.topology();
    let ring_zero_request = wave3c_enter_request(identity, 0, enter_request_flags::DRAIN_CQ, 1, 0);
    let two_ring_valid =
        wave3c_build_enter_result(&ring_zero_request, &two_ring_topology, 0, 1, 0, &[0]);
    assert!(
        validate_enter_result_v1(&two_ring_valid, &ring_zero_request, &two_ring_topology,).is_ok()
    );
    let mut in_range_wrong_result_ring = two_ring_valid.clone();
    put_u32(&mut in_range_wrong_result_ring, 16, 1);
    wave3c_assert_enter_result_error(
        &in_range_wrong_result_ring,
        &ring_zero_request,
        &two_ring_topology,
        SessionValidationError::InvalidParameter,
    );
    let mut in_range_wrong_credit_ring = two_ring_valid;
    put_u32(
        &mut in_range_wrong_credit_ring,
        ENTER_RESULT_V1_PREFIX_SIZE as usize + 24,
        1,
    );
    wave3c_assert_enter_result_error(
        &in_range_wrong_credit_ring,
        &ring_zero_request,
        &two_ring_topology,
        SessionValidationError::InvalidParameter,
    );

    let mut duplicate_physical_index = valid_two;
    put_u64(
        &mut duplicate_physical_index,
        credit_offset + NOTIFICATION_CREDIT_V1_SIZE as usize,
        SlotToken::try_new(topology.notification_credit_class(), 0, 2)
            .unwrap()
            .raw(),
    );
    wave3c_assert_enter_result_error(
        &duplicate_physical_index,
        &drain,
        &topology,
        SessionValidationError::InvalidParameter,
    );
}

#[test]
fn detach_request_is_fixed_and_session_bound() {
    let identity = wave3c_identity();
    let mut bytes = wave3c_detach_bytes(identity);

    assert_eq!(
        validate_detach_request_v1(&bytes[..7], identity).err(),
        Some(SessionValidationError::InvalidParameter)
    );
    put_u16(&mut bytes, 4, 2);
    assert_eq!(
        validate_detach_request_v1(&bytes, identity).err(),
        Some(SessionValidationError::RevisionMismatch)
    );
    put_u16(&mut bytes, 4, CONTROL_VERSION_V1);
    put_u16(&mut bytes, 6, 1);
    assert_eq!(
        validate_detach_request_v1(&bytes, identity).err(),
        Some(SessionValidationError::NotSupported)
    );
    put_u16(&mut bytes, 6, 0);
    put_u32(&mut bytes, 0, DETACH_REQUEST_V1_SIZE - 1);
    assert_eq!(
        validate_detach_request_v1(&bytes, identity).err(),
        Some(SessionValidationError::InvalidParameter)
    );

    let valid = wave3c_detach_bytes(identity);
    assert_eq!(
        validate_detach_request_v1(&valid, identity),
        try_decode::<DetachRequestV1>(&valid).map_err(|_| SessionValidationError::InvalidParameter)
    );
    assert_eq!(
        validate_detach_request_v1(&valid[..39], identity).err(),
        Some(SessionValidationError::InvalidParameter)
    );
    let mut trailing = valid.to_vec();
    trailing.push(0);
    assert_eq!(
        validate_detach_request_v1(&trailing, identity).err(),
        Some(SessionValidationError::InvalidParameter)
    );

    for (offset, value) in [
        (8usize, 0u64),
        (16, 0),
        (8, identity.mount_id.lo + 1),
        (16, identity.mount_id.hi + 1),
        (24, 0),
        (24, identity.session_epoch + 1),
    ] {
        let mut invalid = valid;
        put_u64(&mut invalid, offset, value);
        assert_eq!(
            validate_detach_request_v1(&invalid, identity).err(),
            Some(SessionValidationError::InvalidParameter)
        );
    }
    for offset in [32usize, 36] {
        let mut invalid = valid;
        put_u32(&mut invalid, offset, 1);
        assert_eq!(
            validate_detach_request_v1(&invalid, identity).err(),
            Some(SessionValidationError::InvalidParameter)
        );
    }

    assert_eq!(
        validate_detach_request_v1(
            &valid,
            SessionIdentity {
                session_epoch: 2,
                ..identity
            },
        )
        .err(),
        Some(SessionValidationError::InvalidParameter)
    );
}

#[test]
fn donate_backing_versions_have_exact_precedence() {
    let mut bytes = wave3c_donate_backing_v1_bytes();

    wave3c_assert_donate_backing_error(&bytes[..7], SessionValidationError::InvalidParameter);
    put_u16(&mut bytes, 4, 3);
    wave3c_assert_donate_backing_error(&bytes, SessionValidationError::RevisionMismatch);
    put_u16(&mut bytes, 4, CONTROL_VERSION_V1);
    put_u16(&mut bytes, 6, 1);
    wave3c_assert_donate_backing_error(&bytes, SessionValidationError::NotSupported);
    put_u16(&mut bytes, 6, 0);
    put_u32(&mut bytes, 0, 47);
    wave3c_assert_donate_backing_error(&bytes, SessionValidationError::InvalidParameter);

    let valid_v1 = wave3c_donate_backing_v1_bytes();
    wave3c_assert_donate_backing_error(&valid_v1, SessionValidationError::NotSupported);
    let mut maximum_sector = valid_v1;
    put_u32(&mut maximum_sector, 40, MAX_BACKING_SECTOR_SIZE);
    wave3c_assert_donate_backing_error(&maximum_sector, SessionValidationError::NotSupported);
    let mut opaque_handle = valid_v1;
    put_u64(&mut opaque_handle, 32, u64::MAX);
    wave3c_assert_donate_backing_error(&opaque_handle, SessionValidationError::NotSupported);
    for file_word_offset in [8usize, 16] {
        let mut one_word_file = valid_v1;
        put_u64(&mut one_word_file, file_word_offset, 0);
        wave3c_assert_donate_backing_error(&one_word_file, SessionValidationError::NotSupported);
    }

    let mut flags_before_invalid_body = valid_v1;
    put_u16(&mut flags_before_invalid_body, 6, 1);
    put_u64(&mut flags_before_invalid_body, 24, 0);
    wave3c_assert_donate_backing_error(
        &flags_before_invalid_body,
        SessionValidationError::NotSupported,
    );

    let mut trailing = valid_v1.to_vec();
    trailing.push(0);
    wave3c_assert_donate_backing_error(&trailing, SessionValidationError::InvalidParameter);

    let mut zero_file = valid_v1;
    put_u64(&mut zero_file, 8, 0);
    put_u64(&mut zero_file, 16, 0);
    wave3c_assert_donate_backing_error(&zero_file, SessionValidationError::InvalidParameter);
    let mut zero_epoch = valid_v1;
    put_u64(&mut zero_epoch, 24, 0);
    wave3c_assert_donate_backing_error(&zero_epoch, SessionValidationError::InvalidParameter);
    for sector_size in [
        0,
        MIN_BACKING_SECTOR_SIZE - 1,
        MIN_BACKING_SECTOR_SIZE + 1,
        MAX_BACKING_SECTOR_SIZE + 1,
    ] {
        let mut invalid = valid_v1;
        put_u32(&mut invalid, 40, sector_size);
        wave3c_assert_donate_backing_error(&invalid, SessionValidationError::InvalidParameter);
    }
    let mut fixed_flags = valid_v1;
    put_u32(&mut fixed_flags, 44, 1);
    wave3c_assert_donate_backing_error(&fixed_flags, SessionValidationError::InvalidParameter);

    let mut unknown_bad_everything = valid_v1;
    put_u32(&mut unknown_bad_everything, 0, 0);
    put_u16(&mut unknown_bad_everything, 4, 3);
    put_u16(&mut unknown_bad_everything, 6, u16::MAX);
    put_u64(&mut unknown_bad_everything, 8, 0);
    put_u64(&mut unknown_bad_everything, 16, 0);
    put_u64(&mut unknown_bad_everything, 24, 0);
    put_u32(&mut unknown_bad_everything, 40, 0);
    put_u32(&mut unknown_bad_everything, 44, u32::MAX);
    wave3c_assert_donate_backing_error(
        &unknown_bad_everything,
        SessionValidationError::RevisionMismatch,
    );

    let valid_v2 = wave3c_donate_backing_v2_bytes(&wave3c_utf16_units(r"\Device\A"));
    assert!(validate_donate_backing_v2(&valid_v2).is_ok());
    let mut maximum_sector_v2 = valid_v2.clone();
    put_u32(&mut maximum_sector_v2, 32, MAX_BACKING_SECTOR_SIZE);
    assert!(validate_donate_backing_v2(&maximum_sector_v2).is_ok());
    let mut required_flags_v2 = valid_v2.clone();
    put_u16(&mut required_flags_v2, 6, 1);
    wave3c_assert_donate_backing_error(&required_flags_v2, SessionValidationError::NotSupported);
    let mut zero_file_v2 = valid_v2.clone();
    put_u64(&mut zero_file_v2, 8, 0);
    put_u64(&mut zero_file_v2, 16, 0);
    wave3c_assert_donate_backing_error(&zero_file_v2, SessionValidationError::InvalidParameter);
    for file_word_offset in [8usize, 16] {
        let mut one_word_zero = valid_v2.clone();
        put_u64(&mut one_word_zero, file_word_offset, 0);
        assert!(validate_donate_backing_v2(&one_word_zero).is_ok());
    }
    for (offset, width, value) in [
        (24usize, 8usize, 0u64),
        (32, 4, 0),
        (32, 4, u64::from(MIN_BACKING_SECTOR_SIZE - 1)),
        (32, 4, u64::from(MIN_BACKING_SECTOR_SIZE + 1)),
        (32, 4, u64::from(MAX_BACKING_SECTOR_SIZE + 1)),
        (36, 4, 1),
    ] {
        let mut invalid = valid_v2.clone();
        match width {
            4 => put_u32(&mut invalid, offset, value as u32),
            8 => put_u64(&mut invalid, offset, value),
            _ => unreachable!(),
        }
        wave3c_assert_donate_backing_error(&invalid, SessionValidationError::InvalidParameter);
    }
}

#[test]
fn donate_backing_v2_accepts_canonical_utf16_device_paths() {
    for path in [
        r"\Device\Volume",
        r"\dEvIcE\Disk",
        r"\Device\Mup\server\share",
        r"\DEVICE\Disk😀\Ω",
        r"\Device\Disk*?",
    ] {
        let units = wave3c_utf16_units(path);
        let bytes = wave3c_donate_backing_v2_bytes(&units);
        let validated: ValidatedDonateBacking<'_> = validate_donate_backing_v2(&bytes).unwrap();
        let expected_end = DONATE_BACKING_V2_PREFIX_SIZE as usize + units.len() * size_of::<u16>();
        assert_eq!(validated.bytes(), bytes.as_slice());
        assert_eq!(
            validated.prefix(),
            try_decode::<DonateBackingV2>(&bytes[..DONATE_BACKING_V2_PREFIX_SIZE as usize])
                .unwrap()
        );
        assert_eq!(
            validated.backing_path_bytes(),
            &bytes[DONATE_BACKING_V2_PREFIX_SIZE as usize..expected_end]
        );
    }

    let mut maximum = wave3c_utf16_units(r"\Device\");
    maximum.resize((MAX_BACKING_PATH_BYTES / 2) as usize, u16::from(b'A'));
    let maximum_bytes = wave3c_donate_backing_v2_bytes(&maximum);
    let validated = validate_donate_backing_v2(&maximum_bytes).unwrap();
    assert_eq!(
        validated.backing_path_bytes().len(),
        MAX_BACKING_PATH_BYTES as usize
    );
    assert!(validated.backing_path_bytes().len() > 255 * size_of::<u16>());
}

#[test]
fn donate_backing_v2_rejects_malformed_tail_utf16_and_components() {
    let canonical_units = wave3c_utf16_units(r"\Device\A");
    let canonical = wave3c_donate_backing_v2_bytes(&canonical_units);
    let path_end =
        DONATE_BACKING_V2_PREFIX_SIZE as usize + canonical_units.len() * size_of::<u16>();
    assert!(path_end < canonical.len());

    for (offset, value) in [
        (40usize, DONATE_BACKING_V2_PREFIX_SIZE - 2),
        (40, DONATE_BACKING_V2_PREFIX_SIZE + 2),
        (44, 0),
        (44, 1),
        (44, MAX_BACKING_PATH_BYTES + 2),
        (44, u32::MAX - 1),
    ] {
        let mut invalid = canonical.clone();
        put_u32(&mut invalid, offset, value);
        wave3c_assert_donate_backing_error(&invalid, SessionValidationError::InvalidParameter);
    }

    for struct_size in [
        u32::try_from(path_end).unwrap(),
        u32::try_from(canonical.len() - 1).unwrap(),
        u32::try_from(canonical.len() + 8).unwrap(),
    ] {
        let mut invalid = canonical.clone();
        put_u32(&mut invalid, 0, struct_size);
        wave3c_assert_donate_backing_error(&invalid, SessionValidationError::InvalidParameter);
    }
    let mut unaligned_exact_input = canonical[..path_end].to_vec();
    put_u32(
        &mut unaligned_exact_input,
        0,
        u32::try_from(path_end).unwrap(),
    );
    wave3c_assert_donate_backing_error(
        &unaligned_exact_input,
        SessionValidationError::InvalidParameter,
    );
    let mut overpadded_exact_input = canonical.clone();
    overpadded_exact_input.resize(canonical.len() + 8, 0);
    let overpadded_size = u32::try_from(overpadded_exact_input.len()).unwrap();
    put_u32(&mut overpadded_exact_input, 0, overpadded_size);
    wave3c_assert_donate_backing_error(
        &overpadded_exact_input,
        SessionValidationError::InvalidParameter,
    );
    wave3c_assert_donate_backing_error(
        &canonical[..canonical.len() - 1],
        SessionValidationError::InvalidParameter,
    );
    let mut trailing = canonical.clone();
    trailing.push(0);
    wave3c_assert_donate_backing_error(&trailing, SessionValidationError::InvalidParameter);
    let mut nonzero_padding = canonical.clone();
    nonzero_padding[path_end] = 1;
    wave3c_assert_donate_backing_error(&nonzero_padding, SessionValidationError::InvalidParameter);

    let prefix = wave3c_utf16_units(r"\Device\");
    for suffix in [
        vec![0xd800],
        vec![0xdc00],
        vec![0xd800, u16::from(b'A')],
        vec![0xdc00, 0xd800],
        vec![0xd800, 0xd800, 0xdc00],
    ] {
        let mut malformed = prefix.clone();
        malformed.extend_from_slice(&suffix);
        wave3c_assert_donate_backing_error(
            &wave3c_donate_backing_v2_bytes(&malformed),
            SessionValidationError::InvalidParameter,
        );
    }

    for path in [
        r"Device\Disk",
        r"C:\Disk",
        r"\\server\share",
        r"/Device/Disk",
        r"\Devices\Disk",
        r"\Device",
        r"\Device\",
        r"\Device\\Disk",
        r"\Device\.\Disk",
        r"\Device\..\Disk",
        r"\Device\A/B",
        r"\Device\A:B",
        "\\Device\\A\0B",
    ] {
        wave3c_assert_donate_backing_error(
            &wave3c_donate_backing_v2_bytes(&wave3c_utf16_units(path)),
            SessionValidationError::InvalidParameter,
        );
    }
}

#[test]
fn donate_security_context_v1_is_structurally_validated_then_unsupported() {
    let mut bytes = wave3c_security_donation_bytes();

    assert_eq!(
        validate_donate_security_context_v1(&bytes[..7]),
        Err(SessionValidationError::InvalidParameter)
    );
    put_u16(&mut bytes, 4, 2);
    assert_eq!(
        validate_donate_security_context_v1(&bytes),
        Err(SessionValidationError::RevisionMismatch)
    );
    put_u16(&mut bytes, 4, CONTROL_VERSION_V1);
    put_u16(&mut bytes, 6, 1);
    assert_eq!(
        validate_donate_security_context_v1(&bytes),
        Err(SessionValidationError::NotSupported)
    );
    put_u16(&mut bytes, 6, 0);
    put_u32(&mut bytes, 0, 31);
    assert_eq!(
        validate_donate_security_context_v1(&bytes),
        Err(SessionValidationError::InvalidParameter)
    );

    let valid = wave3c_security_donation_bytes();
    assert_eq!(
        validate_donate_security_context_v1(&valid),
        Err(SessionValidationError::NotSupported)
    );
    let mut flags_before_invalid_body = valid;
    put_u16(&mut flags_before_invalid_body, 6, 1);
    put_u32(&mut flags_before_invalid_body, 24, 1);
    assert_eq!(
        validate_donate_security_context_v1(&flags_before_invalid_body),
        Err(SessionValidationError::NotSupported)
    );
    assert_eq!(
        validate_donate_security_context_v1(&valid[..31]),
        Err(SessionValidationError::InvalidParameter)
    );
    let mut trailing = valid.to_vec();
    trailing.push(0);
    assert_eq!(
        validate_donate_security_context_v1(&trailing),
        Err(SessionValidationError::InvalidParameter)
    );

    for offset in [24usize, 28] {
        let mut invalid = valid;
        put_u32(&mut invalid, offset, 1);
        assert_eq!(
            validate_donate_security_context_v1(&invalid),
            Err(SessionValidationError::InvalidParameter)
        );
    }
    let mut opaque = valid;
    put_u64(&mut opaque, 8, u64::MAX);
    put_u64(&mut opaque, 16, 0x1234_5678_9abc_def0);
    assert_eq!(
        validate_donate_security_context_v1(&opaque),
        Err(SessionValidationError::NotSupported)
    );
}

#[test]
fn retire_request_query_ack_shapes_are_closed() {
    let query = wave3c_retire_query(MountId::ZERO);
    let mut bytes = wave3c_retire_request_bytes(&query);

    assert_eq!(
        validate_retire_mount_v1(&bytes[..7]).err(),
        Some(SessionValidationError::InvalidParameter)
    );
    put_u16(&mut bytes, 4, 2);
    assert_eq!(
        validate_retire_mount_v1(&bytes).err(),
        Some(SessionValidationError::RevisionMismatch)
    );
    put_u16(&mut bytes, 4, CONTROL_VERSION_V1);
    put_u16(&mut bytes, 6, 1);
    assert_eq!(
        validate_retire_mount_v1(&bytes).err(),
        Some(SessionValidationError::NotSupported)
    );
    put_u16(&mut bytes, 6, 0);
    put_u32(&mut bytes, 0, RETIRE_MOUNT_V1_SIZE - 1);
    assert_eq!(
        validate_retire_mount_v1(&bytes).err(),
        Some(SessionValidationError::InvalidParameter)
    );

    for mount_id in [
        MountId::ZERO,
        MountId { lo: 7, hi: 0 },
        MountId { lo: 0, hi: 8 },
        MountId {
            lo: u64::MAX,
            hi: u64::MAX,
        },
    ] {
        let request = wave3c_retire_query(mount_id);
        assert_eq!(
            validate_retire_mount_v1(&wave3c_retire_request_bytes(&request)),
            Ok(request)
        );
    }

    let valid = wave3c_retire_request_bytes(&query);
    assert_eq!(
        validate_retire_mount_v1(&valid[..47]).err(),
        Some(SessionValidationError::InvalidParameter)
    );
    let mut trailing = valid.to_vec();
    trailing.push(0);
    assert_eq!(
        validate_retire_mount_v1(&trailing).err(),
        Some(SessionValidationError::InvalidParameter)
    );

    for token in [RetireToken { lo: 1, hi: 0 }, RetireToken { lo: 0, hi: 1 }] {
        let mut invalid_query = query;
        invalid_query.token = token;
        assert_eq!(
            validate_retire_mount_v1(&wave3c_retire_request_bytes(&invalid_query)).err(),
            Some(SessionValidationError::InvalidParameter)
        );
    }
    let mut reserved_query = query;
    reserved_query.reserved = 1;
    assert_eq!(
        validate_retire_mount_v1(&wave3c_retire_request_bytes(&reserved_query)).err(),
        Some(SessionValidationError::InvalidParameter)
    );

    for (mount_id, token) in [
        (MountId { lo: 1, hi: 0 }, RetireToken { lo: 0, hi: 2 }),
        (MountId { lo: 0, hi: 2 }, RetireToken { lo: 1, hi: 0 }),
        (MountId { lo: 1, hi: 2 }, RetireToken { lo: 3, hi: 4 }),
    ] {
        let request = RetireMountV1 {
            mount_id,
            token,
            action: retire_mount_action::ACK,
            ..query
        };
        assert_eq!(
            validate_retire_mount_v1(&wave3c_retire_request_bytes(&request)),
            Ok(request)
        );
    }

    let invalid_reserved_ack = RetireMountV1 {
        mount_id: MountId { lo: 1, hi: 0 },
        token: RetireToken { lo: 0, hi: 1 },
        action: retire_mount_action::ACK,
        reserved: 1,
        ..query
    };
    assert_eq!(
        validate_retire_mount_v1(&wave3c_retire_request_bytes(&invalid_reserved_ack)).err(),
        Some(SessionValidationError::InvalidParameter)
    );

    for (mount_id, token) in [
        (MountId::ZERO, RetireToken { lo: 1, hi: 0 }),
        (MountId { lo: 1, hi: 0 }, RetireToken::ZERO),
    ] {
        let invalid_ack = RetireMountV1 {
            mount_id,
            token,
            action: retire_mount_action::ACK,
            ..query
        };
        assert_eq!(
            validate_retire_mount_v1(&wave3c_retire_request_bytes(&invalid_ack)).err(),
            Some(SessionValidationError::InvalidParameter)
        );
    }

    for action in [0, 3, u32::MAX] {
        let invalid_action = RetireMountV1 { action, ..query };
        assert_eq!(
            validate_retire_mount_v1(&wave3c_retire_request_bytes(&invalid_action)).err(),
            Some(SessionValidationError::InvalidParameter)
        );
    }
}

#[test]
fn retire_result_states_and_absent_fields_are_closed() {
    let inventory = wave3c_retire_query(MountId::ZERO);
    let opaque_proof = RetireToken {
        lo: 0x0123_4567_89ab_cdef,
        hi: 0xfedc_ba98_7654_3210,
    };
    let mut absent = wave3c_retire_result_bytes(
        MountId::ZERO,
        opaque_proof,
        0,
        feature_words(0, 0),
        0,
        retire_mount_state::ABSENT,
    );

    assert_eq!(
        validate_retire_mount_result_v1(&absent[..7], &inventory).err(),
        Some(SessionValidationError::InvalidParameter)
    );
    put_u16(&mut absent, 4, 2);
    assert_eq!(
        validate_retire_mount_result_v1(&absent, &inventory).err(),
        Some(SessionValidationError::RevisionMismatch)
    );
    put_u16(&mut absent, 4, CONTROL_VERSION_V1);
    put_u16(&mut absent, 6, 1);
    assert_eq!(
        validate_retire_mount_result_v1(&absent, &inventory).err(),
        Some(SessionValidationError::NotSupported)
    );
    put_u16(&mut absent, 6, 0);
    put_u32(&mut absent, 0, RETIRE_MOUNT_RESULT_V1_SIZE - 1);
    assert_eq!(
        validate_retire_mount_result_v1(&absent, &inventory).err(),
        Some(SessionValidationError::InvalidParameter)
    );

    let absent = wave3c_retire_result_bytes(
        MountId::ZERO,
        opaque_proof,
        0,
        feature_words(0, 0),
        0,
        retire_mount_state::ABSENT,
    );
    assert_eq!(
        validate_retire_mount_result_v1(&absent, &inventory),
        Ok(try_decode::<RetireMountResultV1>(&absent).unwrap())
    );
    let absent_zero_proof = wave3c_retire_result_bytes(
        MountId::ZERO,
        RetireToken::ZERO,
        0,
        feature_words(0, 0),
        0,
        retire_mount_state::ABSENT,
    );
    assert!(validate_retire_mount_result_v1(&absent_zero_proof, &inventory).is_ok());
    assert_eq!(
        validate_retire_mount_result_v1(&absent[..95], &inventory).err(),
        Some(SessionValidationError::InvalidParameter)
    );
    let mut trailing = absent.to_vec();
    trailing.push(0);
    assert_eq!(
        validate_retire_mount_result_v1(&trailing, &inventory).err(),
        Some(SessionValidationError::InvalidParameter)
    );

    for mount_state in [
        retire_mount_state::ACTIVE,
        retire_mount_state::GRACE,
        retire_mount_state::TERMINAL,
        retire_mount_state::BOUND_RECONCILING,
    ] {
        let bytes = wave3c_retire_result_bytes(
            MountId { lo: 5, hi: 6 },
            opaque_proof,
            9,
            feature_words(0x9f, 0),
            1,
            mount_state,
        );
        assert!(validate_retire_mount_result_v1(&bytes, &inventory).is_ok());
    }
    let arbitrary_non_absent = wave3c_retire_result_bytes(
        MountId { lo: 5, hi: 6 },
        RetireToken::ZERO,
        1,
        feature_words(u64::MAX, u64::MAX),
        u32::MAX,
        retire_mount_state::ACTIVE,
    );
    assert!(validate_retire_mount_result_v1(&arbitrary_non_absent, &inventory).is_ok());

    let one_word_key = MountId { lo: 0, hi: 9 };
    let exact_one_word = wave3c_retire_query(one_word_key);
    let one_word_absent = wave3c_retire_result_bytes(
        one_word_key,
        opaque_proof,
        0,
        feature_words(0, 0),
        0,
        retire_mount_state::ABSENT,
    );
    assert!(validate_retire_mount_result_v1(&one_word_absent, &exact_one_word).is_ok());
    let mut wrong_echo = one_word_absent;
    put_u64(&mut wrong_echo, 16, 10);
    assert_eq!(
        validate_retire_mount_result_v1(&wrong_echo, &exact_one_word).err(),
        Some(SessionValidationError::InvalidParameter)
    );
    let one_word_active = wave3c_retire_result_bytes(
        one_word_key,
        opaque_proof,
        1,
        feature_words(0, 0),
        0,
        retire_mount_state::ACTIVE,
    );
    assert_eq!(
        validate_retire_mount_result_v1(&one_word_active, &exact_one_word).err(),
        Some(SessionValidationError::InvalidParameter)
    );

    let exact_key = MountId { lo: 7, hi: 8 };
    let exact = wave3c_retire_query(exact_key);
    let exact_active = wave3c_retire_result_bytes(
        exact_key,
        opaque_proof,
        1,
        feature_words(0x9f, 0),
        1,
        retire_mount_state::ACTIVE,
    );
    assert!(validate_retire_mount_result_v1(&exact_active, &exact).is_ok());
    for (mount_word_offset, wrong_value) in [(8usize, 9u64), (16, 10)] {
        let mut wrong_exact_echo = exact_active;
        put_u64(&mut wrong_exact_echo, mount_word_offset, wrong_value);
        assert_eq!(
            validate_retire_mount_result_v1(&wrong_exact_echo, &exact).err(),
            Some(SessionValidationError::InvalidParameter)
        );
    }

    for mount_word_offset in [8usize, 16] {
        let mut inventory_absent_with_mount = absent;
        put_u64(&mut inventory_absent_with_mount, mount_word_offset, 1);
        assert_eq!(
            validate_retire_mount_result_v1(&inventory_absent_with_mount, &inventory).err(),
            Some(SessionValidationError::InvalidParameter)
        );
    }
    for mount_word_offset in [8usize, 16] {
        let mut one_word_zero_active = exact_active;
        put_u64(&mut one_word_zero_active, mount_word_offset, 0);
        assert_eq!(
            validate_retire_mount_result_v1(&one_word_zero_active, &inventory).err(),
            Some(SessionValidationError::InvalidParameter)
        );
    }

    for (offset, width, value) in [(56usize, 8usize, 1u64), (64, 8, 1), (72, 8, 1), (80, 4, 1)] {
        let mut invalid_absent = absent;
        match width {
            4 => put_u32(&mut invalid_absent, offset, value as u32),
            8 => put_u64(&mut invalid_absent, offset, value),
            _ => unreachable!(),
        }
        assert_eq!(
            validate_retire_mount_result_v1(&invalid_absent, &inventory).err(),
            Some(SessionValidationError::InvalidParameter)
        );
    }
    let mut zero_epoch_active = exact_active;
    put_u64(&mut zero_epoch_active, 56, 0);
    assert_eq!(
        validate_retire_mount_result_v1(&zero_epoch_active, &exact).err(),
        Some(SessionValidationError::InvalidParameter)
    );

    let mut zero_boot = absent;
    put_u64(&mut zero_boot, 24, 0);
    put_u64(&mut zero_boot, 32, 0);
    assert_eq!(
        validate_retire_mount_result_v1(&zero_boot, &inventory).err(),
        Some(SessionValidationError::InvalidParameter)
    );
    for boot_word_offset in [24usize, 32] {
        let mut one_word_zero_boot = absent;
        put_u64(&mut one_word_zero_boot, boot_word_offset, 0);
        assert!(validate_retire_mount_result_v1(&one_word_zero_boot, &inventory).is_ok());
    }
    for state in [0, retire_mount_state::BOUND_RECONCILING + 1] {
        let mut invalid_state = absent;
        put_u16(&mut invalid_state, 84, state);
        assert_eq!(
            validate_retire_mount_result_v1(&invalid_state, &inventory).err(),
            Some(SessionValidationError::InvalidParameter)
        );
    }
    let mut result_flags = absent;
    put_u16(&mut result_flags, 86, 1);
    assert_eq!(
        validate_retire_mount_result_v1(&result_flags, &inventory).err(),
        Some(SessionValidationError::InvalidParameter)
    );
    let mut reserved = absent;
    put_u64(&mut reserved, 88, 1);
    assert_eq!(
        validate_retire_mount_result_v1(&reserved, &inventory).err(),
        Some(SessionValidationError::InvalidParameter)
    );

    let ack = RetireMountV1 {
        mount_id: exact_key,
        token: opaque_proof,
        action: retire_mount_action::ACK,
        ..inventory
    };
    assert_eq!(
        validate_retire_mount_result_v1(&absent, &ack).err(),
        Some(SessionValidationError::InvalidParameter)
    );
    for malformed_query in [
        RetireMountV1 {
            token: RetireToken { lo: 1, hi: 0 },
            ..inventory
        },
        RetireMountV1 {
            reserved: 1,
            ..inventory
        },
        RetireMountV1 {
            action: 0,
            ..inventory
        },
    ] {
        assert_eq!(
            validate_retire_mount_result_v1(&absent, &malformed_query).err(),
            Some(SessionValidationError::InvalidParameter)
        );
    }
}
