//! The compiled platform profile (`11-rust-implementation.md` section 2).
//!
//! Platform selection is a compile-time decision, never a runtime branch:
//! exactly one of `platform-win10` (default) and `platform-win7` is selected,
//! and the target architecture completes the choice. This module is WDK-free —
//! it imports nothing from `wdk*` — so it is pure data over the frozen ABI
//! registry, and it re-derives no wire number: every mask is obtained by
//! calling `fsring-abi`.

use fsring_abi::features::{
    BASE_REQUIRED_PROTOCOL_MASK, FeatureSet, PlatformProfile, os_cap, protocol_feature,
};

#[cfg(all(feature = "platform-win10", feature = "platform-win7"))]
compile_error!(
    "platform-win10 and platform-win7 are mutually exclusive: selecting both is a build error \
     (11-rust-implementation.md section 2)"
);

#[cfg(not(any(feature = "platform-win10", feature = "platform-win7")))]
compile_error!(
    "exactly one of platform-win10 (default) or platform-win7 must be selected: selecting \
     neither is a build error (11-rust-implementation.md section 2)"
);

#[cfg(all(feature = "platform-win7", target_arch = "aarch64"))]
compile_error!(
    "platform-win7 is x64-only: ARM64 is modern-only and there is no ARM64 legacy image \
     (11-rust-implementation.md section 2)"
);

/// Equality over `FeatureSet` without indexing its `words` array, which
/// `clippy::indexing_slicing` denies crate-wide. Uses only the ABI's own
/// `const fn` surface.
///
/// Public because `rustc`'s `dead_code` analysis does not count uses that
/// occur only inside anonymous `const _: () = { ... }` items, which is where
/// every call below lives. The batteries are demonstrably live — perturbing a
/// single expected mask fails the build with `E0080` — so the alternative to
/// `pub` here is an `#[allow(dead_code)]` that suppresses a warning about code
/// that is, in fact, evaluated on every build.
pub const fn feature_set_eq(a: FeatureSet, b: FeatureSet) -> bool {
    a.is_subset_of(b) && b.is_subset_of(a)
}

#[cfg(all(
    feature = "platform-win10",
    not(feature = "platform-win7"),
    target_arch = "x86_64"
))]
mod selected {
    use super::PlatformProfile;
    pub const PROFILE: PlatformProfile = PlatformProfile::Win10X64;
    pub const PROFILE_NAME: &str = "Win10X64";
    pub const BANNER: &core::ffi::CStr = c"FSRING FSD loaded (profile Win10X64)\n";
}

#[cfg(all(
    feature = "platform-win10",
    not(feature = "platform-win7"),
    target_arch = "aarch64"
))]
mod selected {
    use super::PlatformProfile;
    pub const PROFILE: PlatformProfile = PlatformProfile::Win10Arm64;
    pub const PROFILE_NAME: &str = "Win10Arm64";
    pub const BANNER: &core::ffi::CStr = c"FSRING FSD loaded (profile Win10Arm64)\n";
}

#[cfg(all(
    feature = "platform-win7",
    not(feature = "platform-win10"),
    target_arch = "x86_64"
))]
mod selected {
    use super::PlatformProfile;
    pub const PROFILE: PlatformProfile = PlatformProfile::Win7X64;
    pub const PROFILE_NAME: &str = "Win7X64";
    pub const BANNER: &core::ffi::CStr = c"FSRING FSD loaded (profile Win7X64)\n";
}

pub use selected::{BANNER, PROFILE, PROFILE_NAME};

/// The protocol features this profile speaks, straight from the ABI registry.
pub const PROTOCOL_MASK: FeatureSet = PROFILE.protocol_mask();

/// The protocol features implemented by this driver image.
pub const IMPLEMENTED_PROTOCOL_MASK: FeatureSet = FeatureSet { words: [0x10, 0] };

/// The OS capabilities this profile advertises, straight from the ABI registry.
pub const OS_CAPABILITY_MASK: FeatureSet = PROFILE.os_capability_mask();

/// Capacity of the driver-global mount registry.
///
/// Bound to the permanent BootContext's slot count rather than chosen: a
/// registry that could outgrow the durable context would admit a mount the
/// permanent record cannot describe. Taken from the frozen ABI, so this file
/// still derives no layout number of its own.
pub const MOUNT_REGISTRY_CAPACITY: usize = fsring_abi::control::BOOT_CONTEXT_SLOT_COUNT as usize;

const _: () = assert!(
    MOUNT_REGISTRY_CAPACITY == 64,
    "the mount registry must match the 64 permanent BootContext slots"
);

// --- Selection battery -----------------------------------------------------
//
// cfg-gated on purpose. A variant-addressed battery (asserting things about
// PlatformProfile::Win10X64 by name) would check only that the crate agrees
// with the document, and would pass without ever consulting PROFILE — leaving
// the cfg selection above, this module's one piece of real logic, unverified.
// Here a wrong selection arm is a build failure, and the three gate builds
// exercise all three arms between them. The literals are the
// 11-rust-implementation.md section 2 table; the values under test come from
// the crate.

#[cfg(all(
    feature = "platform-win10",
    not(feature = "platform-win7"),
    target_arch = "x86_64"
))]
const _: () = {
    assert!(matches!(PROFILE, PlatformProfile::Win10X64));
    assert!(feature_set_eq(
        PROTOCOL_MASK,
        FeatureSet { words: [0x9f, 0] }
    ));
    assert!(feature_set_eq(
        OS_CAPABILITY_MASK,
        FeatureSet { words: [0x3, 0] }
    ));
};

#[cfg(all(
    feature = "platform-win10",
    not(feature = "platform-win7"),
    target_arch = "aarch64"
))]
const _: () = {
    assert!(matches!(PROFILE, PlatformProfile::Win10Arm64));
    assert!(feature_set_eq(
        PROTOCOL_MASK,
        FeatureSet { words: [0x9f, 0] }
    ));
    assert!(feature_set_eq(
        OS_CAPABILITY_MASK,
        FeatureSet { words: [0xb, 0] }
    ));
};

#[cfg(all(
    feature = "platform-win7",
    not(feature = "platform-win10"),
    target_arch = "x86_64"
))]
const _: () = {
    assert!(matches!(PROFILE, PlatformProfile::Win7X64));
    assert!(feature_set_eq(
        PROTOCOL_MASK,
        FeatureSet { words: [0x1f, 0] }
    ));
    assert!(feature_set_eq(
        OS_CAPABILITY_MASK,
        FeatureSet { words: [0, 0] }
    ));
};

// --- Registry battery ------------------------------------------------------
//
// cfg-free: these hold for every profile in every build, so they are asserted
// once over all three variants.

const _: () = {
    // SECURITY is a kernel-required base feature on every profile
    // (11-rust-implementation.md section 2).
    assert!(BASE_REQUIRED_PROTOCOL_MASK.is_subset_of(PlatformProfile::Win10X64.protocol_mask()));
    assert!(BASE_REQUIRED_PROTOCOL_MASK.is_subset_of(PlatformProfile::Win10Arm64.protocol_mask()));
    assert!(BASE_REQUIRED_PROTOCOL_MASK.is_subset_of(PlatformProfile::Win7X64.protocol_mask()));

    // The Win7 profile omits MAPPED_IO because it advertises neither MDL
    // no-write nor MDL no-execute; both Win10 profiles carry it. This is the
    // stated reason for the 0x1f versus 0x9f difference.
    assert!(
        PlatformProfile::Win10X64
            .protocol_mask()
            .contains(protocol_feature::MAPPED_IO)
    );
    assert!(
        PlatformProfile::Win10Arm64
            .protocol_mask()
            .contains(protocol_feature::MAPPED_IO)
    );
    assert!(
        !PlatformProfile::Win7X64
            .protocol_mask()
            .contains(protocol_feature::MAPPED_IO)
    );

    // ARM64 is the only profile that advertises the ARM64 OS capability, and
    // the MDL protections belong to the modern profiles only.
    assert!(
        PlatformProfile::Win10Arm64
            .os_capability_mask()
            .contains(os_cap::ARM64)
    );
    assert!(
        !PlatformProfile::Win10X64
            .os_capability_mask()
            .contains(os_cap::ARM64)
    );
    assert!(
        PlatformProfile::Win10X64
            .os_capability_mask()
            .contains(os_cap::MDL_NO_WRITE)
    );
    assert!(
        PlatformProfile::Win10X64
            .os_capability_mask()
            .contains(os_cap::MDL_NO_EXECUTE)
    );
    assert!(
        !PlatformProfile::Win7X64
            .os_capability_mask()
            .contains(os_cap::MDL_NO_WRITE)
    );
    assert!(
        !PlatformProfile::Win7X64
            .os_capability_mask()
            .contains(os_cap::MDL_NO_EXECUTE)
    );
};
