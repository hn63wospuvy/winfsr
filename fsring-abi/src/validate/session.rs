use core::{convert::TryFrom, mem::size_of};

use crate::{
    codec::{try_decode, Pod},
    control::{
        enter_request_flags, enter_result_flags, retire_mount_action, retire_mount_state, status,
        view_access, view_kind, AttachV1, DetachRequestV1, DonateBackingV2,
        DonateSecurityContextV1, EnterRequestV1, EnterResultV1, NotificationCreditV1,
        RetireMountResultV1, RetireMountV1, SessionResultV1, SetupRequestV1, SlotClassRequest,
        UserViewDesc, DETACH_REQUEST_V1_SIZE, DONATE_BACKING_V2_PREFIX_SIZE, ENTER_REQUEST_V1_SIZE,
        ENTER_RESULT_V1_PREFIX_SIZE, GLOBAL_RING_INDEX, NOTIFICATION_CREDIT_V1_SIZE,
        RETIRE_MOUNT_RESULT_V1_SIZE, RETIRE_MOUNT_V1_SIZE, SESSION_RESULT_V1_PREFIX_SIZE,
        SETUP_REQUEST_V1_SIZE, USER_VIEW_DESC_SIZE,
    },
    features::{
        protocol_feature, select_features_v21, FeatureSelection, FeatureSelectionError,
        FeatureSelectionInput, FeatureSet, PlatformProfile,
    },
    ids::{BootInstanceId, FileId, MountId, RetireToken},
    layout::{RegionDesc, SLOT_CLASS_COUNT},
    limits::{
        GLOBAL_EXTERNAL_CHANGE_ACK_REQID, MAX_BACKING_PATH_BYTES, MAX_BACKING_SECTOR_SIZE,
        MAX_CQ_CAPACITY, MAX_ENTER_CQ_BUDGET, MAX_INFLIGHT, MAX_NOTIFICATION_CREDITS_PER_RING,
        MAX_NOTIFICATION_CREDITS_PER_SESSION, MAX_NOTIFICATION_CREDIT_BYTES,
        MAX_NOTIFICATION_CREDIT_SIZE, MAX_RING_COUNT, MAX_SECTION_BYTES, MAX_SLOT_COUNT,
        MAX_SLOT_SIZE, MAX_SQ_CAPACITY, MIN_BACKING_PATH_BYTES, MIN_BACKING_SECTOR_SIZE,
        MIN_CONTROL_SLOT_SIZE, MIN_CQ_CAPACITY, MIN_K2U_PROGRESS_SLOTS_PER_RING,
        MIN_NOTIFICATION_CREDIT_SIZE, MIN_RING_COUNT, MIN_SLOT_COUNT, MIN_SLOT_SIZE,
        MIN_SQ_CAPACITY, MIN_U2K_PROGRESS_SLOTS_PER_RING, SLOT_ALIGNMENT, SYSTEM_REQID_BASE,
        SYSTEM_REQUEST_SLOTS_PER_RING, USER_VIEW_OFFSET_ALIGNMENT,
    },
    msgs::{buffer_access, buffer_kind, DonateBackingV1},
    slots::SlotToken,
};

use super::{
    is_canonical_backing_device_path, validate_control_prefix,
    validate_control_prefix_with_schemas, ControlError, ControlVersionSchema,
};

const ATTACH_V1_SIZE: u32 = 56;
const DONATE_BACKING_V1_SIZE: u32 = 48;
const DONATE_SECURITY_CONTEXT_V1_SIZE: u32 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionValidationError {
    InvalidParameter,
    RevisionMismatch,
    NotSupported,
    AccessDenied,
    IntegerOverflow,
}

impl SessionValidationError {
    pub const fn status(self) -> i32 {
        match self {
            Self::InvalidParameter => status::INVALID_PARAMETER,
            Self::RevisionMismatch => status::REVISION_MISMATCH,
            Self::NotSupported => status::NOT_SUPPORTED,
            Self::AccessDenied => status::ACCESS_DENIED,
            Self::IntegerOverflow => status::INTEGER_OVERFLOW,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionContextError {
    InvalidRingCount,
    InvalidPageSize,
    InvalidSectionSize,
    InvalidRegion,
    OverlappingWritableViews,
    ArithmeticOverflow,
    InvalidIdentity,
    InvalidFeatureSelection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionIdentity {
    pub mount_id: MountId,
    pub boot_instance_id: BootInstanceId,
    pub session_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedTopology {
    ring_count: u32,
    sq_capacity: u32,
    cq_capacity: u32,
    max_inflight: u32,
    k2u_slot_classes: [SlotClassRequest; SLOT_CLASS_COUNT],
    u2k_slot_classes: [SlotClassRequest; SLOT_CLASS_COUNT],
    notification_credit_count: u32,
    notification_credit_size: u32,
    notification_credit_class: u8,
}

impl ValidatedTopology {
    pub const fn ring_count(&self) -> u32 {
        self.ring_count
    }

    pub const fn sq_capacity(&self) -> u32 {
        self.sq_capacity
    }

    pub const fn cq_capacity(&self) -> u32 {
        self.cq_capacity
    }

    pub const fn max_inflight(&self) -> u32 {
        self.max_inflight
    }

    pub const fn k2u_slot_classes(&self) -> [SlotClassRequest; SLOT_CLASS_COUNT] {
        self.k2u_slot_classes
    }

    pub const fn u2k_slot_classes(&self) -> [SlotClassRequest; SLOT_CLASS_COUNT] {
        self.u2k_slot_classes
    }

    pub const fn notification_credit_count(&self) -> u32 {
        self.notification_credit_count
    }

    pub const fn notification_credit_size(&self) -> u32 {
        self.notification_credit_size
    }

    pub const fn notification_credit_class(&self) -> u8 {
        self.notification_credit_class
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachExpectation {
    prior_identity: SessionIdentity,
    abi_minor: u16,
    selection: FeatureSelection,
    topology: ValidatedTopology,
    next_session_epoch: u64,
}

impl AttachExpectation {
    pub fn new(
        prior_identity: SessionIdentity,
        selection: FeatureSelection,
        topology: ValidatedTopology,
    ) -> Result<Self, SessionContextError> {
        if prior_identity.mount_id.lo == 0
            || prior_identity.mount_id.hi == 0
            || prior_identity.boot_instance_id == BootInstanceId::ZERO
            || prior_identity.session_epoch == 0
        {
            return Err(SessionContextError::InvalidIdentity);
        }
        if !restart_pair_is_matched(selection.selected_features) {
            return Err(SessionContextError::InvalidFeatureSelection);
        }
        let next_session_epoch = prior_identity
            .session_epoch
            .checked_add(1)
            .ok_or(SessionContextError::ArithmeticOverflow)?;
        Ok(Self {
            prior_identity,
            abi_minor: 1,
            selection,
            topology,
            next_session_epoch,
        })
    }

    pub const fn prior_identity(&self) -> SessionIdentity {
        self.prior_identity
    }

    pub const fn selected_features(&self) -> FeatureSet {
        self.selection.selected_features
    }

    pub const fn topology(&self) -> ValidatedTopology {
        self.topology
    }

    pub const fn next_session_epoch(&self) -> u64 {
        self.next_session_epoch
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedSetupRequest {
    request: SetupRequestV1,
    selected_abi_minor: u16,
    selection: FeatureSelection,
    topology: ValidatedTopology,
}

impl ValidatedSetupRequest {
    pub const fn request(&self) -> SetupRequestV1 {
        self.request
    }

    pub const fn selected_abi_minor(&self) -> u16 {
        self.selected_abi_minor
    }

    pub const fn selection(&self) -> FeatureSelection {
        self.selection
    }

    pub const fn topology(&self) -> ValidatedTopology {
        self.topology
    }
}

#[derive(Clone, Copy)]
pub struct RingViewLayout {
    pub sq_consumer: RegionDesc,
    pub cq_entries: RegionDesc,
    pub cq_producer: RegionDesc,
}

#[derive(Clone, Copy)]
pub struct SessionViewLayout<'a> {
    section_size: u64,
    page_size: u32,
    u2k_arena: RegionDesc,
    rings: &'a [RingViewLayout],
    selected_abi_minor: u16,
    selection: FeatureSelection,
    topology: ValidatedTopology,
    expected_session_epoch: u64,
    expected_identity: Option<SessionIdentity>,
}

impl<'a> SessionViewLayout<'a> {
    pub fn for_setup(
        setup: &ValidatedSetupRequest,
        section_size: u64,
        page_size: u32,
        u2k_arena: RegionDesc,
        rings: &'a [RingViewLayout],
    ) -> Result<Self, SessionContextError> {
        Self::from_trusted(
            setup.selected_abi_minor,
            setup.selection,
            setup.topology,
            1,
            None,
            section_size,
            page_size,
            u2k_arena,
            rings,
        )
    }

    pub fn for_attach(
        expected: &AttachExpectation,
        section_size: u64,
        page_size: u32,
        u2k_arena: RegionDesc,
        rings: &'a [RingViewLayout],
    ) -> Result<Self, SessionContextError> {
        let expected_identity = SessionIdentity {
            mount_id: expected.prior_identity.mount_id,
            boot_instance_id: expected.prior_identity.boot_instance_id,
            session_epoch: expected.next_session_epoch,
        };
        Self::from_trusted(
            expected.abi_minor,
            expected.selection,
            expected.topology,
            expected.next_session_epoch,
            Some(expected_identity),
            section_size,
            page_size,
            u2k_arena,
            rings,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_trusted(
        selected_abi_minor: u16,
        selection: FeatureSelection,
        topology: ValidatedTopology,
        expected_session_epoch: u64,
        expected_identity: Option<SessionIdentity>,
        section_size: u64,
        page_size: u32,
        u2k_arena: RegionDesc,
        rings: &'a [RingViewLayout],
    ) -> Result<Self, SessionContextError> {
        let expected_ring_count = usize::try_from(topology.ring_count)
            .map_err(|_| SessionContextError::ArithmeticOverflow)?;
        if rings.len() != expected_ring_count {
            return Err(SessionContextError::InvalidRingCount);
        }
        if page_size == 0
            || !page_size.is_power_of_two()
            || u64::from(page_size) > USER_VIEW_OFFSET_ALIGNMENT
            || USER_VIEW_OFFSET_ALIGNMENT % u64::from(page_size) != 0
        {
            return Err(SessionContextError::InvalidPageSize);
        }
        validate_trusted_section_size(section_size)?;

        let ring_region_count = rings
            .len()
            .checked_mul(3)
            .ok_or(SessionContextError::ArithmeticOverflow)?;
        let writable_region_count = ring_region_count
            .checked_add(1)
            .ok_or(SessionContextError::ArithmeticOverflow)?;

        let mut ordinal = 0usize;
        while ordinal < writable_region_count {
            let region = writable_region(rings, u2k_arena, ring_region_count, ordinal)
                .ok_or(SessionContextError::ArithmeticOverflow)?;
            validate_writable_region(region, section_size, page_size)?;
            ordinal += 1;
        }
        if u2k_arena.offset == 0
            || u2k_arena.offset % USER_VIEW_OFFSET_ALIGNMENT != 0
            || u2k_arena.length % USER_VIEW_OFFSET_ALIGNMENT != 0
        {
            return Err(SessionContextError::InvalidRegion);
        }

        let mut left_ordinal = 0usize;
        while left_ordinal < writable_region_count {
            let left = writable_region(rings, u2k_arena, ring_region_count, left_ordinal)
                .ok_or(SessionContextError::ArithmeticOverflow)?;
            let left_end = left
                .offset
                .checked_add(left.length)
                .ok_or(SessionContextError::ArithmeticOverflow)?;
            let mut right_ordinal = left_ordinal + 1;
            while right_ordinal < writable_region_count {
                let right = writable_region(rings, u2k_arena, ring_region_count, right_ordinal)
                    .ok_or(SessionContextError::ArithmeticOverflow)?;
                let right_end = right
                    .offset
                    .checked_add(right.length)
                    .ok_or(SessionContextError::ArithmeticOverflow)?;
                if left.offset < right_end && right.offset < left_end {
                    return Err(SessionContextError::OverlappingWritableViews);
                }
                right_ordinal += 1;
            }
            left_ordinal += 1;
        }

        Ok(Self {
            section_size,
            page_size,
            u2k_arena,
            rings,
            selected_abi_minor,
            selection,
            topology,
            expected_session_epoch,
            expected_identity,
        })
    }

    pub const fn section_size(&self) -> u64 {
        self.section_size
    }

    pub const fn page_size(&self) -> u32 {
        self.page_size
    }

    pub const fn ring_count(&self) -> u32 {
        self.topology.ring_count
    }

    pub const fn u2k_arena(&self) -> RegionDesc {
        self.u2k_arena
    }

    pub fn ring(&self, index: u32) -> Option<RingViewLayout> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.rings.get(index))
            .copied()
    }
}

#[derive(Clone, Copy)]
pub struct ValidatedSessionResult<'a> {
    prefix: SessionResultV1,
    identity: SessionIdentity,
    bytes: &'a [u8],
}

impl<'a> ValidatedSessionResult<'a> {
    pub const fn prefix(&self) -> SessionResultV1 {
        self.prefix
    }

    pub const fn identity(&self) -> SessionIdentity {
        self.identity
    }

    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub const fn view_count(&self) -> u32 {
        self.prefix.view_count
    }

    pub fn view(&self, index: u32) -> Option<UserViewDesc> {
        if index >= self.prefix.view_count {
            return None;
        }
        let relative = index.checked_mul(USER_VIEW_DESC_SIZE)?;
        let offset = self.prefix.views_offset.checked_add(relative)?;
        decode_at(self.bytes, offset)
    }

    pub const fn notification_credit_count(&self) -> u32 {
        self.prefix.notification_credit_count
    }

    pub fn notification_credit(&self, index: u32) -> Option<NotificationCreditV1> {
        if index >= self.prefix.notification_credit_count {
            return None;
        }
        let relative = index.checked_mul(NOTIFICATION_CREDIT_V1_SIZE)?;
        let offset = self
            .prefix
            .notification_credits_offset
            .checked_add(relative)?;
        decode_at(self.bytes, offset)
    }
}

#[derive(Clone, Copy)]
pub struct ValidatedEnterResult<'a> {
    prefix: EnterResultV1,
    bytes: &'a [u8],
}

impl<'a> ValidatedEnterResult<'a> {
    pub const fn prefix(&self) -> EnterResultV1 {
        self.prefix
    }

    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub const fn notification_credit_count(&self) -> u32 {
        self.prefix.notification_credit_count
    }

    pub fn notification_credit(&self, index: u32) -> Option<NotificationCreditV1> {
        if index >= self.prefix.notification_credit_count {
            return None;
        }
        let relative = index.checked_mul(NOTIFICATION_CREDIT_V1_SIZE)?;
        let offset = self
            .prefix
            .notification_credits_offset
            .checked_add(relative)?;
        decode_at(self.bytes, offset)
    }
}

#[derive(Clone, Copy)]
pub struct ValidatedDonateBacking<'a> {
    prefix: DonateBackingV2,
    bytes: &'a [u8],
    backing_path: &'a [u8],
}

impl<'a> ValidatedDonateBacking<'a> {
    pub const fn prefix(&self) -> DonateBackingV2 {
        self.prefix
    }

    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn backing_path_bytes(&self) -> &'a [u8] {
        self.backing_path
    }
}

pub fn validate_attach_v1(
    input: &[u8],
    expected: &AttachExpectation,
) -> Result<AttachV1, SessionValidationError> {
    let request = validate_fixed_v1::<AttachV1>(input, ATTACH_V1_SIZE)?;
    let restart_pair = restart_pair_is_matched(request.requested_features);
    let journal_version = if request
        .requested_features
        .contains(protocol_feature::HOT_RESTART)
        && request
            .requested_features
            .contains(protocol_feature::EXACTLY_ONCE)
    {
        1
    } else {
        0
    };
    if request.flags != 0
        || request.mount_id != expected.prior_identity.mount_id
        || request.prior_session_epoch != expected.prior_identity.session_epoch
        || request.requested_features != expected.selection.selected_features
        || !restart_pair
        || request.journal_version != journal_version
    {
        return Err(SessionValidationError::InvalidParameter);
    }
    Ok(request)
}

pub fn validate_enter_request_v1(
    input: &[u8],
    identity: SessionIdentity,
    topology: &ValidatedTopology,
) -> Result<EnterRequestV1, SessionValidationError> {
    let request = validate_fixed_v1::<EnterRequestV1>(input, ENTER_REQUEST_V1_SIZE)?;
    validate_enter_request_shape(&request, topology)?;
    if request.mount_id != identity.mount_id || request.session_epoch != identity.session_epoch {
        return Err(SessionValidationError::InvalidParameter);
    }
    Ok(request)
}

pub fn enter_result_size_v1(notification_credit_count: u32) -> Result<u32, SessionContextError> {
    notification_credit_count
        .checked_mul(NOTIFICATION_CREDIT_V1_SIZE)
        .and_then(|tail| ENTER_RESULT_V1_PREFIX_SIZE.checked_add(tail))
        .ok_or(SessionContextError::ArithmeticOverflow)
}

pub fn validate_enter_result_v1<'a>(
    input: &'a [u8],
    request: &EnterRequestV1,
    topology: &ValidatedTopology,
) -> Result<ValidatedEnterResult<'a>, SessionValidationError> {
    let validated_prefix = validate_control_prefix(input, &[1], 0, ENTER_RESULT_V1_PREFIX_SIZE)
        .map_err(map_control_error)?;
    let prefix = try_decode::<EnterResultV1>(validated_prefix.bytes())
        .map_err(|_| SessionValidationError::InvalidParameter)?;
    validate_enter_request_shape(request, topology)?;

    let expected_size = enter_result_size_v1(prefix.notification_credit_count)
        .map_err(|_| SessionValidationError::InvalidParameter)?;
    let expected_offset = if prefix.notification_credit_count == 0 {
        0
    } else {
        ENTER_RESULT_V1_PREFIX_SIZE
    };
    if prefix.header.struct_size != expected_size
        || input.len()
            != usize::try_from(expected_size)
                .map_err(|_| SessionValidationError::InvalidParameter)?
        || prefix.notification_credit_desc_size != NOTIFICATION_CREDIT_V1_SIZE
        || prefix.notification_credits_offset != expected_offset
    {
        return Err(SessionValidationError::InvalidParameter);
    }

    let drains = request.flags & enter_request_flags::DRAIN_CQ != 0;
    let waits = request.flags & enter_request_flags::WAIT_SQ != 0;
    let sq_flag = prefix.flags & enter_result_flags::SQ_READY != 0;
    let remaining = prefix.flags & enter_result_flags::CQ_REMAINING != 0;
    let timed_out = prefix.flags & enter_result_flags::TIMED_OUT != 0;
    let blocked = prefix.flags & enter_result_flags::NOTIFY_BLOCKED != 0;
    let contended = prefix.flags & enter_result_flags::CQ_CONTENDED != 0;

    if prefix.session_epoch != request.session_epoch
        || prefix.ring_index != request.ring_index
        || prefix.flags & !enter_result_flags::KNOWN_MASK != 0
        || prefix.reserved != 0
        || prefix.sq_ready > 1
        || sq_flag != (prefix.sq_ready == 1)
        || prefix.cq_drained > request.cq_budget
        || prefix.notification_credit_count > prefix.cq_drained
        || prefix.notification_credit_count > topology.notification_credit_count
        || prefix.notification_credit_count > MAX_NOTIFICATION_CREDITS_PER_RING
        || (!drains
            && (prefix.cq_drained != 0
                || prefix.notification_credit_count != 0
                || remaining
                || blocked
                || contended))
        || (blocked && !remaining)
        || (contended && (remaining || blocked))
        || (timed_out
            && (!waits || prefix.sq_ready != 0 || sq_flag || remaining || blocked || contended))
    {
        return Err(SessionValidationError::InvalidParameter);
    }

    validate_enter_credits(input, &prefix, request, topology)?;
    Ok(ValidatedEnterResult {
        prefix,
        bytes: input,
    })
}

pub fn validate_detach_request_v1(
    input: &[u8],
    identity: SessionIdentity,
) -> Result<DetachRequestV1, SessionValidationError> {
    let request = validate_fixed_v1::<DetachRequestV1>(input, DETACH_REQUEST_V1_SIZE)?;
    if request.mount_id != identity.mount_id
        || request.session_epoch != identity.session_epoch
        || request.flags != 0
        || request.reserved != 0
    {
        return Err(SessionValidationError::InvalidParameter);
    }
    Ok(request)
}

pub fn validate_donate_backing_v2<'a>(
    input: &'a [u8],
) -> Result<ValidatedDonateBacking<'a>, SessionValidationError> {
    const SCHEMAS: [ControlVersionSchema; 2] = [
        ControlVersionSchema {
            version: 1,
            accepted_required_flags: 0,
            minimum_size: DONATE_BACKING_V1_SIZE,
        },
        ControlVersionSchema {
            version: 2,
            accepted_required_flags: 0,
            minimum_size: DONATE_BACKING_V2_PREFIX_SIZE,
        },
    ];
    let validated_prefix =
        validate_control_prefix_with_schemas(input, &SCHEMAS).map_err(map_control_error)?;
    match validated_prefix.header().struct_version {
        1 => {
            if validated_prefix.header().struct_size != DONATE_BACKING_V1_SIZE
                || input.len() != DONATE_BACKING_V1_SIZE as usize
            {
                return Err(SessionValidationError::InvalidParameter);
            }
            let prefix = try_decode::<DonateBackingV1>(validated_prefix.bytes())
                .map_err(|_| SessionValidationError::InvalidParameter)?;
            validate_backing_fixed(
                prefix.file_id,
                prefix.pt_epoch,
                prefix.sector_size,
                prefix.flags,
            )?;
            Err(SessionValidationError::NotSupported)
        }
        2 => {
            let prefix = try_decode::<DonateBackingV2>(validated_prefix.bytes())
                .map_err(|_| SessionValidationError::InvalidParameter)?;
            validate_backing_fixed(
                prefix.file_id,
                prefix.pt_epoch,
                prefix.sector_size,
                prefix.flags,
            )?;
            if prefix.backing_path.offset != DONATE_BACKING_V2_PREFIX_SIZE
                || prefix.backing_path.length < MIN_BACKING_PATH_BYTES
                || prefix.backing_path.length > MAX_BACKING_PATH_BYTES
                || prefix.backing_path.length % 2 != 0
            {
                return Err(SessionValidationError::InvalidParameter);
            }
            let path_end = prefix
                .backing_path
                .offset
                .checked_add(prefix.backing_path.length)
                .ok_or(SessionValidationError::InvalidParameter)?;
            let aligned_end = path_end
                .checked_add(7)
                .map(|end| end & !7)
                .ok_or(SessionValidationError::InvalidParameter)?;
            if prefix.header.struct_size != aligned_end
                || input.len()
                    != usize::try_from(aligned_end)
                        .map_err(|_| SessionValidationError::InvalidParameter)?
            {
                return Err(SessionValidationError::InvalidParameter);
            }
            let path_start = usize::try_from(prefix.backing_path.offset)
                .map_err(|_| SessionValidationError::InvalidParameter)?;
            let path_end =
                usize::try_from(path_end).map_err(|_| SessionValidationError::InvalidParameter)?;
            let backing_path = input
                .get(path_start..path_end)
                .ok_or(SessionValidationError::InvalidParameter)?;
            let padding = input
                .get(path_end..)
                .ok_or(SessionValidationError::InvalidParameter)?;
            if padding.iter().any(|byte| *byte != 0) {
                return Err(SessionValidationError::InvalidParameter);
            }
            if !is_canonical_backing_device_path(backing_path) {
                return Err(SessionValidationError::InvalidParameter);
            }
            Ok(ValidatedDonateBacking {
                prefix,
                bytes: input,
                backing_path,
            })
        }
        _ => Err(SessionValidationError::RevisionMismatch),
    }
}

pub fn validate_donate_security_context_v1(input: &[u8]) -> Result<(), SessionValidationError> {
    let request =
        validate_fixed_v1::<DonateSecurityContextV1>(input, DONATE_SECURITY_CONTEXT_V1_SIZE)?;
    if request.flags != 0 || request.reserved != 0 {
        return Err(SessionValidationError::InvalidParameter);
    }
    Err(SessionValidationError::NotSupported)
}

pub fn validate_retire_mount_v1(input: &[u8]) -> Result<RetireMountV1, SessionValidationError> {
    let request = validate_fixed_v1::<RetireMountV1>(input, RETIRE_MOUNT_V1_SIZE)?;
    if request.reserved != 0 {
        return Err(SessionValidationError::InvalidParameter);
    }
    match request.action {
        retire_mount_action::QUERY if request.token == RetireToken::ZERO => Ok(request),
        retire_mount_action::ACK
            if request.mount_id != MountId::ZERO && request.token != RetireToken::ZERO =>
        {
            Ok(request)
        }
        _ => Err(SessionValidationError::InvalidParameter),
    }
}

pub fn validate_retire_mount_result_v1(
    input: &[u8],
    request: &RetireMountV1,
) -> Result<RetireMountResultV1, SessionValidationError> {
    let result = validate_fixed_v1::<RetireMountResultV1>(input, RETIRE_MOUNT_RESULT_V1_SIZE)?;
    if request.action != retire_mount_action::QUERY
        || request.token != RetireToken::ZERO
        || request.reserved != 0
        || result.boot_instance_id == BootInstanceId::ZERO
        || result.flags != 0
        || result.reserved != 0
        || !is_retire_mount_state(result.mount_state)
    {
        return Err(SessionValidationError::InvalidParameter);
    }

    let absent = result.mount_state == retire_mount_state::ABSENT;
    if (request.mount_id != MountId::ZERO && result.mount_id != request.mount_id)
        || (request.mount_id == MountId::ZERO && absent && result.mount_id != MountId::ZERO)
        || (!absent && (result.mount_id.lo == 0 || result.mount_id.hi == 0))
        || (absent
            && (result.latest_session_epoch != 0
                || result.selected_features.words != [0, 0]
                || result.journal_version != 0))
        || (!absent && result.latest_session_epoch == 0)
    {
        return Err(SessionValidationError::InvalidParameter);
    }
    Ok(result)
}

pub fn validate_setup_request_v1(
    input: &[u8],
    profile: PlatformProfile,
    implementation_protocol_mask: FeatureSet,
    runtime_probe_mask: FeatureSet,
    has_dedicated_service_sid: bool,
) -> Result<ValidatedSetupRequest, SessionValidationError> {
    let prefix = validate_control_prefix(input, &[1], 0, SETUP_REQUEST_V1_SIZE)
        .map_err(map_control_error)?;
    if prefix.header().struct_size != SETUP_REQUEST_V1_SIZE
        || input.len() != SETUP_REQUEST_V1_SIZE as usize
    {
        return Err(SessionValidationError::InvalidParameter);
    }
    let request = try_decode::<SetupRequestV1>(prefix.bytes())
        .map_err(|_| SessionValidationError::InvalidParameter)?;
    if request.reserved0 != 0 || request.flags != 0 || request.reserved1 != 0 {
        return Err(SessionValidationError::InvalidParameter);
    }
    if request.min_abi_minor > request.max_abi_minor {
        return Err(SessionValidationError::InvalidParameter);
    }
    if request.abi_major != 2 || request.min_abi_minor > 1 || request.max_abi_minor < 1 {
        return Err(SessionValidationError::RevisionMismatch);
    }

    let selection = select_features_v21(
        profile,
        FeatureSelectionInput {
            offered_features: request.offered_features,
            required_features: request.required_features,
            required_os_capabilities: request.required_os_capabilities,
            implementation_protocol_mask,
            runtime_probe_mask,
            has_dedicated_service_sid,
        },
    )
    .map_err(map_feature_selection_error)?;
    let topology = validate_topology(&request)?;
    Ok(ValidatedSetupRequest {
        request,
        selected_abi_minor: 1,
        selection,
        topology,
    })
}

pub fn validate_section_size_v21(section_size: u64) -> Result<(), SessionValidationError> {
    if section_size == 0
        || section_size % USER_VIEW_OFFSET_ALIGNMENT != 0
        || section_size > MAX_SECTION_BYTES
        || usize::try_from(section_size).is_err()
    {
        return Err(SessionValidationError::InvalidParameter);
    }
    Ok(())
}

pub fn session_result_size_v1(topology: &ValidatedTopology) -> Result<u32, SessionContextError> {
    let (_, _, total_size) = result_layout_parts(topology)?;
    Ok(total_size)
}

pub fn validate_session_result_v1<'a>(
    input: &'a [u8],
    expected: &SessionViewLayout<'_>,
) -> Result<ValidatedSessionResult<'a>, SessionValidationError> {
    let validated_prefix = validate_control_prefix(input, &[1], 0, SESSION_RESULT_V1_PREFIX_SIZE)
        .map_err(map_control_error)?;
    let prefix = try_decode::<SessionResultV1>(validated_prefix.bytes())
        .map_err(|_| SessionValidationError::InvalidParameter)?;

    if prefix.reserved0 != 0 || prefix.flags != 0 || prefix.reserved1 != 0 {
        return Err(SessionValidationError::InvalidParameter);
    }
    if prefix.abi_major != 2 || prefix.abi_minor != expected.selected_abi_minor {
        return Err(SessionValidationError::RevisionMismatch);
    }
    if prefix.mount_id.lo == 0
        || prefix.mount_id.hi == 0
        || (prefix.boot_instance_id.lo == 0 && prefix.boot_instance_id.hi == 0)
        || prefix.session_epoch != expected.expected_session_epoch
    {
        return Err(SessionValidationError::InvalidParameter);
    }
    if let Some(identity) = expected.expected_identity {
        if prefix.mount_id != identity.mount_id
            || prefix.boot_instance_id != identity.boot_instance_id
            || prefix.session_epoch != identity.session_epoch
        {
            return Err(SessionValidationError::InvalidParameter);
        }
    }

    validate_section_size_v21(prefix.section_size)?;
    if prefix.section_size != expected.section_size {
        return Err(SessionValidationError::InvalidParameter);
    }
    if prefix.selected_features != expected.selection.selected_features
        || prefix.os_capabilities != expected.selection.detected_os_capabilities
        || prefix.ring_count != expected.topology.ring_count
        || prefix.max_inflight != expected.topology.max_inflight
        || prefix.notification_credit_count != expected.topology.notification_credit_count
    {
        return Err(SessionValidationError::InvalidParameter);
    }

    let claimed_credits_offset = prefix
        .view_count
        .checked_mul(USER_VIEW_DESC_SIZE)
        .and_then(|tail| SESSION_RESULT_V1_PREFIX_SIZE.checked_add(tail))
        .ok_or(SessionValidationError::InvalidParameter)?;
    let claimed_total_size = prefix
        .notification_credit_count
        .checked_mul(NOTIFICATION_CREDIT_V1_SIZE)
        .and_then(|tail| claimed_credits_offset.checked_add(tail))
        .ok_or(SessionValidationError::InvalidParameter)?;
    let (expected_view_count, expected_credits_offset, expected_total_size) =
        result_layout_parts(&expected.topology)
            .map_err(|_| SessionValidationError::InvalidParameter)?;
    if prefix.view_count != expected_view_count
        || prefix.view_desc_size != USER_VIEW_DESC_SIZE
        || prefix.views_offset != SESSION_RESULT_V1_PREFIX_SIZE
        || prefix.notification_credit_desc_size != NOTIFICATION_CREDIT_V1_SIZE
        || prefix.notification_credits_offset != claimed_credits_offset
        || prefix.notification_credits_offset != expected_credits_offset
        || prefix.header.struct_size != claimed_total_size
        || prefix.header.struct_size != expected_total_size
        || input.len()
            != usize::try_from(expected_total_size)
                .map_err(|_| SessionValidationError::InvalidParameter)?
    {
        return Err(SessionValidationError::InvalidParameter);
    }

    validate_result_views(input, expected)?;
    validate_result_credits(input, &prefix, &expected.topology)?;

    Ok(ValidatedSessionResult {
        prefix,
        identity: SessionIdentity {
            mount_id: prefix.mount_id,
            boot_instance_id: prefix.boot_instance_id,
            session_epoch: prefix.session_epoch,
        },
        bytes: input,
    })
}

fn validate_fixed_v1<T: Pod>(input: &[u8], size: u32) -> Result<T, SessionValidationError> {
    let prefix = validate_control_prefix(input, &[1], 0, size).map_err(map_control_error)?;
    if prefix.header().struct_size != size
        || input.len()
            != usize::try_from(size).map_err(|_| SessionValidationError::InvalidParameter)?
    {
        return Err(SessionValidationError::InvalidParameter);
    }
    try_decode::<T>(prefix.bytes()).map_err(|_| SessionValidationError::InvalidParameter)
}

fn restart_pair_is_matched(features: FeatureSet) -> bool {
    features.contains(protocol_feature::HOT_RESTART)
        == features.contains(protocol_feature::EXACTLY_ONCE)
}

fn validate_enter_request_shape(
    request: &EnterRequestV1,
    topology: &ValidatedTopology,
) -> Result<(), SessionValidationError> {
    let drains = request.flags & enter_request_flags::DRAIN_CQ != 0;
    let waits = request.flags & enter_request_flags::WAIT_SQ != 0;
    let maximum_budget = core::cmp::min(topology.cq_capacity, MAX_ENTER_CQ_BUDGET);
    if request.mount_id.lo == 0
        || request.mount_id.hi == 0
        || request.session_epoch == 0
        || request.ring_index >= topology.ring_count
        || request.flags & !enter_request_flags::KNOWN_MASK != 0
        || (drains && waits)
        || (drains && (request.cq_budget == 0 || request.cq_budget > maximum_budget))
        || (!drains && request.cq_budget != 0)
        || (!waits && request.timeout_ms != 0)
    {
        return Err(SessionValidationError::InvalidParameter);
    }
    Ok(())
}

fn validate_backing_fixed(
    file_id: FileId,
    pt_epoch: u64,
    sector_size: u32,
    flags: u32,
) -> Result<(), SessionValidationError> {
    if file_id == FileId::ZERO
        || pt_epoch == 0
        || !(MIN_BACKING_SECTOR_SIZE..=MAX_BACKING_SECTOR_SIZE).contains(&sector_size)
        || !sector_size.is_power_of_two()
        || flags != 0
    {
        return Err(SessionValidationError::InvalidParameter);
    }
    Ok(())
}

fn is_retire_mount_state(state: u16) -> bool {
    matches!(
        state,
        retire_mount_state::ABSENT
            | retire_mount_state::ACTIVE
            | retire_mount_state::GRACE
            | retire_mount_state::TERMINAL
            | retire_mount_state::BOUND_RECONCILING
    )
}

fn map_control_error(error: ControlError) -> SessionValidationError {
    match error {
        ControlError::RevisionMismatch => SessionValidationError::RevisionMismatch,
        ControlError::UnsupportedRequiredFlags => SessionValidationError::NotSupported,
        ControlError::ShortPrefix
        | ControlError::InvalidSize
        | ControlError::InvalidRange
        | ControlError::InvalidAlignment
        | ControlError::NonZeroReserved
        | ControlError::UnsupportedSchema
        | ControlError::UnclassifiedTail => SessionValidationError::InvalidParameter,
    }
}

fn map_feature_selection_error(error: FeatureSelectionError) -> SessionValidationError {
    match error {
        FeatureSelectionError::RequiredFeatureNotOffered
        | FeatureSelectionError::RestartPairMismatch
        | FeatureSelectionError::InvalidImplementationMask => {
            SessionValidationError::InvalidParameter
        }
        FeatureSelectionError::DedicatedServiceSidRequired => SessionValidationError::AccessDenied,
        FeatureSelectionError::RequiredFeatureUnavailable
        | FeatureSelectionError::RequiredOsCapabilityUnavailable => {
            SessionValidationError::NotSupported
        }
    }
}

fn validate_topology(
    request: &SetupRequestV1,
) -> Result<ValidatedTopology, SessionValidationError> {
    if request.ring_count < MIN_RING_COUNT || request.ring_count > MAX_RING_COUNT {
        return Err(SessionValidationError::InvalidParameter);
    }
    if request.sq_capacity < MIN_SQ_CAPACITY
        || request.sq_capacity > MAX_SQ_CAPACITY
        || !request.sq_capacity.is_power_of_two()
        || request.cq_capacity < MIN_CQ_CAPACITY
        || request.cq_capacity > MAX_CQ_CAPACITY
        || !request.cq_capacity.is_power_of_two()
        || request.max_inflight == 0
        || request.max_inflight > MAX_INFLIGHT
    {
        return Err(SessionValidationError::InvalidParameter);
    }

    let system_request_count = request
        .ring_count
        .checked_mul(SYSTEM_REQUEST_SLOTS_PER_RING)
        .ok_or(SessionValidationError::IntegerOverflow)?;
    let system_request_end = SYSTEM_REQID_BASE
        .checked_add(system_request_count)
        .ok_or(SessionValidationError::IntegerOverflow)?;
    if system_request_end > GLOBAL_EXTERNAL_CHANGE_ACK_REQID {
        return Err(SessionValidationError::IntegerOverflow);
    }

    validate_slot_class_requests(&request.k2u_slot_classes)?;
    validate_slot_class_requests(&request.u2k_slot_classes)?;

    if request.notification_credit_size < MIN_NOTIFICATION_CREDIT_SIZE
        || request.notification_credit_size > MAX_NOTIFICATION_CREDIT_SIZE
        || !request.notification_credit_size.is_power_of_two()
        || u64::from(request.notification_credit_size) % SLOT_ALIGNMENT != 0
    {
        return Err(SessionValidationError::InvalidParameter);
    }
    let per_ring_credit_limit = request
        .ring_count
        .checked_mul(MAX_NOTIFICATION_CREDITS_PER_RING)
        .ok_or(SessionValidationError::InvalidParameter)?;
    let credit_limit = if per_ring_credit_limit < MAX_NOTIFICATION_CREDITS_PER_SESSION {
        per_ring_credit_limit
    } else {
        MAX_NOTIFICATION_CREDITS_PER_SESSION
    };
    if request.notification_credit_count < request.ring_count
        || request.notification_credit_count > credit_limit
    {
        return Err(SessionValidationError::InvalidParameter);
    }
    let credit_bytes = u64::from(request.notification_credit_count)
        .checked_mul(u64::from(request.notification_credit_size))
        .ok_or(SessionValidationError::InvalidParameter)?;
    if credit_bytes > MAX_NOTIFICATION_CREDIT_BYTES {
        return Err(SessionValidationError::InvalidParameter);
    }

    let notification_credit_class = select_notification_credit_class(
        &request.u2k_slot_classes,
        request.notification_credit_size,
        request.notification_credit_count,
    )
    .ok_or(SessionValidationError::InvalidParameter)?;

    let required_k2u = request
        .ring_count
        .checked_mul(MIN_K2U_PROGRESS_SLOTS_PER_RING)
        .ok_or(SessionValidationError::InvalidParameter)?;
    let eligible_k2u = eligible_progress_slot_count(&request.k2u_slot_classes)?;
    if eligible_k2u < required_k2u {
        return Err(SessionValidationError::InvalidParameter);
    }

    let required_u2k = request
        .ring_count
        .checked_mul(MIN_U2K_PROGRESS_SLOTS_PER_RING)
        .ok_or(SessionValidationError::InvalidParameter)?;
    let mut eligible_u2k = eligible_progress_slot_count(&request.u2k_slot_classes)?;
    let selected_class = request.u2k_slot_classes[usize::from(notification_credit_class)];
    if selected_class.slot_size >= MIN_CONTROL_SLOT_SIZE {
        eligible_u2k = eligible_u2k
            .checked_sub(request.notification_credit_count)
            .ok_or(SessionValidationError::InvalidParameter)?;
    }
    if eligible_u2k < required_u2k {
        return Err(SessionValidationError::InvalidParameter);
    }

    Ok(ValidatedTopology {
        ring_count: request.ring_count,
        sq_capacity: request.sq_capacity,
        cq_capacity: request.cq_capacity,
        max_inflight: request.max_inflight,
        k2u_slot_classes: request.k2u_slot_classes,
        u2k_slot_classes: request.u2k_slot_classes,
        notification_credit_count: request.notification_credit_count,
        notification_credit_size: request.notification_credit_size,
        notification_credit_class,
    })
}

fn validate_slot_class_requests(
    classes: &[SlotClassRequest; SLOT_CLASS_COUNT],
) -> Result<(), SessionValidationError> {
    let mut active_count = 0usize;
    let mut previous_size = 0u32;
    let mut inactive_seen = false;
    for class in classes {
        if class.slot_size == 0 || class.slot_count == 0 {
            if class.slot_size != 0 || class.slot_count != 0 {
                return Err(SessionValidationError::InvalidParameter);
            }
            inactive_seen = true;
            continue;
        }
        if inactive_seen
            || class.slot_size < MIN_SLOT_SIZE
            || class.slot_size > MAX_SLOT_SIZE
            || !class.slot_size.is_power_of_two()
            || class.slot_count < MIN_SLOT_COUNT
            || class.slot_count > MAX_SLOT_COUNT
            || (active_count != 0 && class.slot_size <= previous_size)
        {
            return Err(SessionValidationError::InvalidParameter);
        }
        active_count += 1;
        previous_size = class.slot_size;
    }
    if active_count == 0 {
        return Err(SessionValidationError::InvalidParameter);
    }
    Ok(())
}

fn select_notification_credit_class(
    classes: &[SlotClassRequest; SLOT_CLASS_COUNT],
    credit_size: u32,
    credit_count: u32,
) -> Option<u8> {
    for (index, class) in classes.iter().enumerate() {
        if class.slot_size == 0 {
            break;
        }
        if class.slot_size >= credit_size && class.slot_count >= credit_count {
            return u8::try_from(index).ok();
        }
    }
    None
}

fn eligible_progress_slot_count(
    classes: &[SlotClassRequest; SLOT_CLASS_COUNT],
) -> Result<u32, SessionValidationError> {
    let mut total = 0u32;
    for class in classes {
        if class.slot_size == 0 {
            break;
        }
        if class.slot_size >= MIN_CONTROL_SLOT_SIZE {
            total = total
                .checked_add(class.slot_count)
                .ok_or(SessionValidationError::InvalidParameter)?;
        }
    }
    Ok(total)
}

fn validate_trusted_section_size(section_size: u64) -> Result<(), SessionContextError> {
    if section_size == 0
        || section_size % USER_VIEW_OFFSET_ALIGNMENT != 0
        || section_size > MAX_SECTION_BYTES
        || usize::try_from(section_size).is_err()
    {
        return Err(SessionContextError::InvalidSectionSize);
    }
    Ok(())
}

fn validate_writable_region(
    region: RegionDesc,
    section_size: u64,
    page_size: u32,
) -> Result<(), SessionContextError> {
    if region.offset % USER_VIEW_OFFSET_ALIGNMENT != 0
        || region.length == 0
        || region.length % u64::from(page_size) != 0
    {
        return Err(SessionContextError::InvalidRegion);
    }
    let end = region
        .offset
        .checked_add(region.length)
        .ok_or(SessionContextError::InvalidRegion)?;
    if end > section_size {
        return Err(SessionContextError::InvalidRegion);
    }
    Ok(())
}

fn writable_region(
    rings: &[RingViewLayout],
    u2k_arena: RegionDesc,
    ring_region_count: usize,
    ordinal: usize,
) -> Option<RegionDesc> {
    if ordinal == ring_region_count {
        return Some(u2k_arena);
    }
    let ring = rings.get(ordinal / 3)?;
    match ordinal % 3 {
        0 => Some(ring.sq_consumer),
        1 => Some(ring.cq_entries),
        2 => Some(ring.cq_producer),
        _ => None,
    }
}

fn result_layout_parts(
    topology: &ValidatedTopology,
) -> Result<(u32, u32, u32), SessionContextError> {
    let ring_views = topology
        .ring_count
        .checked_mul(3)
        .ok_or(SessionContextError::ArithmeticOverflow)?;
    let view_count = 2u32
        .checked_add(ring_views)
        .ok_or(SessionContextError::ArithmeticOverflow)?;
    let view_bytes = view_count
        .checked_mul(USER_VIEW_DESC_SIZE)
        .ok_or(SessionContextError::ArithmeticOverflow)?;
    let credits_offset = SESSION_RESULT_V1_PREFIX_SIZE
        .checked_add(view_bytes)
        .ok_or(SessionContextError::ArithmeticOverflow)?;
    let credit_bytes = topology
        .notification_credit_count
        .checked_mul(NOTIFICATION_CREDIT_V1_SIZE)
        .ok_or(SessionContextError::ArithmeticOverflow)?;
    let total_size = credits_offset
        .checked_add(credit_bytes)
        .ok_or(SessionContextError::ArithmeticOverflow)?;
    Ok((view_count, credits_offset, total_size))
}

fn validate_result_views(
    input: &[u8],
    expected: &SessionViewLayout<'_>,
) -> Result<(), SessionValidationError> {
    let mut offset = SESSION_RESULT_V1_PREFIX_SIZE;
    validate_expected_view(
        input,
        offset,
        UserViewDesc {
            section_offset: 0,
            length: expected.section_size,
            user_address: 0,
            ring_index: GLOBAL_RING_INDEX,
            kind: view_kind::SECTION_READ_ONLY,
            access: view_access::READ_ONLY,
        },
    )?;
    offset = offset
        .checked_add(USER_VIEW_DESC_SIZE)
        .ok_or(SessionValidationError::InvalidParameter)?;

    for (ring_index, ring) in expected.rings.iter().enumerate() {
        let ring_index =
            u32::try_from(ring_index).map_err(|_| SessionValidationError::InvalidParameter)?;
        for (region, kind) in [
            (ring.sq_consumer, view_kind::SQ_CONSUMER_PAGE),
            (ring.cq_entries, view_kind::CQ_ENTRIES),
            (ring.cq_producer, view_kind::CQ_PRODUCER_PAGE),
        ] {
            validate_expected_view(
                input,
                offset,
                UserViewDesc {
                    section_offset: region.offset,
                    length: region.length,
                    user_address: 0,
                    ring_index,
                    kind,
                    access: view_access::READ_WRITE,
                },
            )?;
            offset = offset
                .checked_add(USER_VIEW_DESC_SIZE)
                .ok_or(SessionValidationError::InvalidParameter)?;
        }
    }

    validate_expected_view(
        input,
        offset,
        UserViewDesc {
            section_offset: expected.u2k_arena.offset,
            length: expected.u2k_arena.length,
            user_address: 0,
            ring_index: GLOBAL_RING_INDEX,
            kind: view_kind::U2K_ARENA,
            access: view_access::READ_WRITE,
        },
    )
}

fn validate_expected_view(
    input: &[u8],
    offset: u32,
    expected: UserViewDesc,
) -> Result<(), SessionValidationError> {
    let actual =
        decode_at::<UserViewDesc>(input, offset).ok_or(SessionValidationError::InvalidParameter)?;
    if actual.section_offset != expected.section_offset
        || actual.length != expected.length
        || actual.ring_index != expected.ring_index
        || actual.kind != expected.kind
        || actual.access != expected.access
    {
        return Err(SessionValidationError::InvalidParameter);
    }
    Ok(())
}

fn validate_enter_credits(
    input: &[u8],
    prefix: &EnterResultV1,
    request: &EnterRequestV1,
    topology: &ValidatedTopology,
) -> Result<(), SessionValidationError> {
    let mut ordinal = 0u32;
    while ordinal < prefix.notification_credit_count {
        let credit = decode_credit_at(input, prefix.notification_credits_offset, ordinal)?;
        let token = validate_notification_credit_shape(&credit, topology)?;
        if credit.ring_index != request.ring_index {
            return Err(SessionValidationError::InvalidParameter);
        }

        let mut prior_ordinal = 0u32;
        while prior_ordinal < ordinal {
            let prior = decode_credit_at(input, prefix.notification_credits_offset, prior_ordinal)?;
            let prior_token = SlotToken::from_raw(prior.buffer.token)
                .map_err(|_| SessionValidationError::InvalidParameter)?;
            if prior_token.index() == token.index() {
                return Err(SessionValidationError::InvalidParameter);
            }
            prior_ordinal += 1;
        }
        ordinal += 1;
    }
    Ok(())
}

fn validate_notification_credit_shape(
    credit: &NotificationCreditV1,
    topology: &ValidatedTopology,
) -> Result<SlotToken, SessionValidationError> {
    if credit.reserved != 0
        || credit.ring_index >= topology.ring_count
        || credit.buffer.kind != buffer_kind::SLOT
        || credit.buffer.access != buffer_access::U2K_WRITE
        || credit.buffer.offset != 0
        || credit.buffer.length != topology.notification_credit_size
        || credit.buffer.reserved != 0
    {
        return Err(SessionValidationError::InvalidParameter);
    }
    let token = SlotToken::from_raw(credit.buffer.token)
        .map_err(|_| SessionValidationError::InvalidParameter)?;
    let selected_class = topology.u2k_slot_classes[usize::from(topology.notification_credit_class)];
    if token.class() != topology.notification_credit_class
        || token.index() >= selected_class.slot_count
    {
        return Err(SessionValidationError::InvalidParameter);
    }
    Ok(token)
}

fn validate_result_credits(
    input: &[u8],
    prefix: &SessionResultV1,
    topology: &ValidatedTopology,
) -> Result<(), SessionValidationError> {
    let mut ordinal = 0u32;
    while ordinal < prefix.notification_credit_count {
        let credit = decode_credit(input, prefix, ordinal)?;
        let token = validate_notification_credit_shape(&credit, topology)?;

        let mut prior_ordinal = 0u32;
        while prior_ordinal < ordinal {
            let prior = decode_credit(input, prefix, prior_ordinal)?;
            let prior_token = SlotToken::from_raw(prior.buffer.token)
                .map_err(|_| SessionValidationError::InvalidParameter)?;
            if prior_token.index() == token.index() {
                return Err(SessionValidationError::InvalidParameter);
            }
            prior_ordinal += 1;
        }

        ordinal += 1;
    }

    let mut minimum = u32::MAX;
    let mut maximum = 0u32;
    let mut ring_index = 0u32;
    while ring_index < topology.ring_count {
        let mut count = 0u32;
        let mut ordinal = 0u32;
        while ordinal < prefix.notification_credit_count {
            let credit = decode_credit(input, prefix, ordinal)?;
            if credit.ring_index == ring_index {
                count = count
                    .checked_add(1)
                    .ok_or(SessionValidationError::InvalidParameter)?;
            }
            ordinal += 1;
        }
        if count > MAX_NOTIFICATION_CREDITS_PER_RING {
            return Err(SessionValidationError::InvalidParameter);
        }
        if count < minimum {
            minimum = count;
        }
        if count > maximum {
            maximum = count;
        }
        ring_index = ring_index
            .checked_add(1)
            .ok_or(SessionValidationError::InvalidParameter)?;
    }
    if maximum
        .checked_sub(minimum)
        .ok_or(SessionValidationError::InvalidParameter)?
        > 1
    {
        return Err(SessionValidationError::InvalidParameter);
    }
    Ok(())
}

fn decode_credit(
    input: &[u8],
    prefix: &SessionResultV1,
    ordinal: u32,
) -> Result<NotificationCreditV1, SessionValidationError> {
    decode_credit_at(input, prefix.notification_credits_offset, ordinal)
}

fn decode_credit_at(
    input: &[u8],
    credits_offset: u32,
    ordinal: u32,
) -> Result<NotificationCreditV1, SessionValidationError> {
    let relative = ordinal
        .checked_mul(NOTIFICATION_CREDIT_V1_SIZE)
        .ok_or(SessionValidationError::InvalidParameter)?;
    let offset = credits_offset
        .checked_add(relative)
        .ok_or(SessionValidationError::InvalidParameter)?;
    decode_at(input, offset).ok_or(SessionValidationError::InvalidParameter)
}

fn decode_at<T: Pod>(input: &[u8], offset: u32) -> Option<T> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(size_of::<T>())?;
    try_decode(input.get(start..end)?).ok()
}
