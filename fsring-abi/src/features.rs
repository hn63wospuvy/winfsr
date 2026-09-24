#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeatureSet {
    pub words: [u64; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureError {
    BitOutOfRange,
}

impl FeatureSet {
    pub const fn contains(self, bit: u8) -> bool {
        bit < 128 && (self.words[(bit / 64) as usize] & (1u64 << (bit % 64))) != 0
    }
    pub fn insert(&mut self, bit: u8) -> Result<(), FeatureError> {
        if bit >= 128 {
            return Err(FeatureError::BitOutOfRange);
        }
        self.words[(bit / 64) as usize] |= 1u64 << (bit % 64);
        Ok(())
    }
    pub const fn is_subset_of(self, offered: Self) -> bool {
        (self.words[0] & !offered.words[0]) == 0 && (self.words[1] & !offered.words[1]) == 0
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self {
            words: [
                self.words[0] & other.words[0],
                self.words[1] & other.words[1],
            ],
        }
    }
}

pub mod protocol_feature {
    pub const PT: u8 = 0;
    pub const MMAP: u8 = 1;
    pub const HOT_RESTART: u8 = 2;
    pub const EXACTLY_ONCE: u8 = 3;
    pub const SECURITY: u8 = 4;
    pub const REPARSE: u8 = 5;
    pub const TOKEN_DONATION: u8 = 6;
    pub const MAPPED_IO: u8 = 7;
    pub const NOTIFY_NAMES: u8 = 8;
    pub const CASE_SENSITIVE_NAMES: u8 = 9;
}
pub mod os_cap {
    pub const MDL_NO_WRITE: u8 = 0;
    pub const MDL_NO_EXECUTE: u8 = 1;
    pub const MODERN_COHERENCY: u8 = 2;
    pub const ARM64: u8 = 3;
}

/// SECURITY is required for every successful ABI 2.1 session.
/// cbindgen:ignore
pub const BASE_REQUIRED_PROTOCOL_MASK: FeatureSet = FeatureSet { words: [0x10, 0] };

/// Registry-stable features that base ABI 2.1 assigns but cannot select.
/// cbindgen:ignore
pub const UNSELECTABLE_PROTOCOL_MASK: FeatureSet = FeatureSet { words: [0x360, 0] };

/// cbindgen:ignore
pub const WIN10_X64_PROTOCOL_MASK: FeatureSet = FeatureSet { words: [0x9f, 0] };
/// cbindgen:ignore
pub const WIN10_ARM64_PROTOCOL_MASK: FeatureSet = FeatureSet { words: [0x9f, 0] };
/// cbindgen:ignore
pub const WIN7_X64_PROTOCOL_MASK: FeatureSet = FeatureSet { words: [0x1f, 0] };

/// cbindgen:ignore
pub const WIN10_X64_OS_CAPABILITIES: FeatureSet = FeatureSet { words: [0x3, 0] };
/// cbindgen:ignore
pub const WIN10_ARM64_OS_CAPABILITIES: FeatureSet = FeatureSet { words: [0xb, 0] };
/// cbindgen:ignore
pub const WIN7_X64_OS_CAPABILITIES: FeatureSet = FeatureSet { words: [0, 0] };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformProfile {
    Win10X64,
    Win10Arm64,
    Win7X64,
}

impl PlatformProfile {
    pub const fn protocol_mask(self) -> FeatureSet {
        match self {
            Self::Win10X64 => WIN10_X64_PROTOCOL_MASK,
            Self::Win10Arm64 => WIN10_ARM64_PROTOCOL_MASK,
            Self::Win7X64 => WIN7_X64_PROTOCOL_MASK,
        }
    }

    pub const fn os_capability_mask(self) -> FeatureSet {
        match self {
            Self::Win10X64 => WIN10_X64_OS_CAPABILITIES,
            Self::Win10Arm64 => WIN10_ARM64_OS_CAPABILITIES,
            Self::Win7X64 => WIN7_X64_OS_CAPABILITIES,
        }
    }
}

/// cbindgen:ignore
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeatureSelectionInput {
    pub offered_features: FeatureSet,
    pub required_features: FeatureSet,
    pub required_os_capabilities: FeatureSet,
    pub implementation_protocol_mask: FeatureSet,
    pub runtime_probe_mask: FeatureSet,
    pub has_dedicated_service_sid: bool,
}

/// cbindgen:ignore
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeatureSelection {
    pub selected_features: FeatureSet,
    pub detected_os_capabilities: FeatureSet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureSelectionError {
    RequiredFeatureNotOffered,
    RestartPairMismatch,
    InvalidImplementationMask,
    RequiredFeatureUnavailable,
    RequiredOsCapabilityUnavailable,
    DedicatedServiceSidRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImplementationMaskError {
    MissingSecurity,
    OutsideProfile,
    ContainsUnselectable,
    RestartPairMismatch,
}

pub const fn validate_implementation_protocol_mask(
    profile: PlatformProfile,
    implementation_protocol_mask: FeatureSet,
) -> Result<(), ImplementationMaskError> {
    if !BASE_REQUIRED_PROTOCOL_MASK.is_subset_of(implementation_protocol_mask) {
        return Err(ImplementationMaskError::MissingSecurity);
    }
    if !implementation_protocol_mask
        .intersection(UNSELECTABLE_PROTOCOL_MASK)
        .is_subset_of(FeatureSet { words: [0, 0] })
    {
        return Err(ImplementationMaskError::ContainsUnselectable);
    }
    if !implementation_protocol_mask.is_subset_of(profile.protocol_mask()) {
        return Err(ImplementationMaskError::OutsideProfile);
    }
    if !restart_pair_is_matched(implementation_protocol_mask) {
        return Err(ImplementationMaskError::RestartPairMismatch);
    }
    Ok(())
}

pub const fn select_features_v21(
    profile: PlatformProfile,
    input: FeatureSelectionInput,
) -> Result<FeatureSelection, FeatureSelectionError> {
    if validate_implementation_protocol_mask(profile, input.implementation_protocol_mask).is_err() {
        return Err(FeatureSelectionError::InvalidImplementationMask);
    }
    if !input.required_features.is_subset_of(input.offered_features) {
        return Err(FeatureSelectionError::RequiredFeatureNotOffered);
    }
    if !restart_pair_is_matched(input.offered_features)
        || !restart_pair_is_matched(input.required_features)
    {
        return Err(FeatureSelectionError::RestartPairMismatch);
    }

    let offered = input.offered_features.intersection(profile.protocol_mask());
    let implemented = offered.intersection(input.implementation_protocol_mask);
    let required_with_base = union(input.required_features, BASE_REQUIRED_PROTOCOL_MASK);
    if !required_with_base.is_subset_of(implemented) {
        return Err(FeatureSelectionError::RequiredFeatureUnavailable);
    }

    let detected_os_capabilities = profile
        .os_capability_mask()
        .intersection(input.runtime_probe_mask);
    let mut runtime_protocol = implemented;
    if !(detected_os_capabilities.contains(os_cap::MDL_NO_WRITE)
        && detected_os_capabilities.contains(os_cap::MDL_NO_EXECUTE))
    {
        runtime_protocol = without_bit(runtime_protocol, protocol_feature::MAPPED_IO);
    }
    if !required_with_base.is_subset_of(runtime_protocol) {
        return Err(FeatureSelectionError::RequiredFeatureUnavailable);
    }
    if input
        .required_features
        .contains(protocol_feature::HOT_RESTART)
        && !input.has_dedicated_service_sid
    {
        return Err(FeatureSelectionError::DedicatedServiceSidRequired);
    }
    if !input.has_dedicated_service_sid {
        runtime_protocol = without_bit(runtime_protocol, protocol_feature::HOT_RESTART);
        runtime_protocol = without_bit(runtime_protocol, protocol_feature::EXACTLY_ONCE);
    }
    if !input
        .required_os_capabilities
        .is_subset_of(detected_os_capabilities)
    {
        return Err(FeatureSelectionError::RequiredOsCapabilityUnavailable);
    }

    Ok(FeatureSelection {
        selected_features: runtime_protocol,
        detected_os_capabilities,
    })
}

const fn union(left: FeatureSet, right: FeatureSet) -> FeatureSet {
    FeatureSet {
        words: [
            left.words[0] | right.words[0],
            left.words[1] | right.words[1],
        ],
    }
}

const fn without_bit(mut set: FeatureSet, bit: u8) -> FeatureSet {
    set.words[(bit / 64) as usize] &= !(1u64 << (bit % 64));
    set
}

const fn restart_pair_is_matched(set: FeatureSet) -> bool {
    set.contains(protocol_feature::HOT_RESTART) == set.contains(protocol_feature::EXACTLY_ONCE)
}
