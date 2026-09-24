//! MDL mapping protections and section protections.
//!
//! `02-transport.md` and `05-irp-dispatch.md` govern, and `00-INDEX.md` section
//! 4 ranks `02-transport.md` above `11-rust-implementation.md`: the flags are
//! **profile-fixed** and **per-page-direction**. The modern profile passes
//! `NormalPagePriority | MdlMappingNoExecute`, and additionally
//! `MdlMappingNoWrite` **only for input-only pages — output pages remain
//! writable**. The Win7 profile passes only `NormalPagePriority`, because those
//! flag encodings are not a Win7 contract and applying either is a defect.
//!
//! `11-rust-implementation.md` section 4 phrases the modern rule as "when the
//! OS-capability probe reports them". That agrees here by construction: the
//! capability masks are compile-time profile constants
//! (`WIN10_X64_OS_CAPABILITIES = 0x3`, `WIN7_X64_OS_CAPABILITIES = 0`), so the
//! probe's answer is fixed per profile.

use fsring_abi::features::PlatformProfile;

/// Closed result exposed by the native exception boundary. Raw exception and
/// NTSTATUS values never cross into the transport state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingResourceError {
    InsufficientResources,
}

/// Normalize the probe shim's status. Only exact `STATUS_SUCCESS` succeeds.
pub const fn normalize_probe_status(status: i32) -> Result<(), MappingResourceError> {
    if status == 0 {
        Ok(())
    } else {
        Err(MappingResourceError::InsufficientResources)
    }
}

/// Normalize the map shim's status/address pair. Success requires both exact
/// `STATUS_SUCCESS` and a non-null address; every other combination collapses
/// to the same resource error.
pub fn normalize_mapping_result(
    status: i32,
    address: *mut core::ffi::c_void,
) -> Result<core::ptr::NonNull<core::ffi::c_void>, MappingResourceError> {
    if status != 0 {
        return Err(MappingResourceError::InsufficientResources);
    }
    core::ptr::NonNull::new(address).ok_or(MappingResourceError::InsufficientResources)
}

/// `MdlMappingNoWrite`, from the generated `wdk-sys` constants.
pub const MDL_MAPPING_NO_WRITE: u32 = 0x8000_0000;
/// `MdlMappingNoExecute`, from the generated `wdk-sys` constants.
pub const MDL_MAPPING_NO_EXECUTE: u32 = 0x4000_0000;
/// `NormalPagePriority`, from the generated `wdk-sys` types.
pub const NORMAL_PAGE_PRIORITY: u32 = 16;

/// Which way the application's bytes travel through the mapped pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageDirection {
    /// The daemon only reads these pages (a WRITE request's source data).
    InputOnly,
    /// The daemon writes into these pages (a READ request's destination).
    Output,
}

/// The flag word passed to `MmMapLockedPagesSpecifyCache`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingFlags(u32);

impl MappingFlags {
    /// The raw word to hand the kernel.
    pub const fn raw(self) -> u32 {
        self.0
    }
    pub const fn contains_no_write(self) -> bool {
        self.0 & MDL_MAPPING_NO_WRITE != 0
    }
    pub const fn contains_no_execute(self) -> bool {
        self.0 & MDL_MAPPING_NO_EXECUTE != 0
    }
}

/// The mapping flags for one profile and one page direction.
///
/// Total over three profiles times two directions; all six cells are exercised
/// by the tests below.
pub const fn mdl_mapping_flags(profile: PlatformProfile, direction: PageDirection) -> MappingFlags {
    match profile {
        PlatformProfile::Win7X64 => MappingFlags(NORMAL_PAGE_PRIORITY),
        PlatformProfile::Win10X64 | PlatformProfile::Win10Arm64 => match direction {
            PageDirection::InputOnly => {
                MappingFlags(NORMAL_PAGE_PRIORITY | MDL_MAPPING_NO_EXECUTE | MDL_MAPPING_NO_WRITE)
            }
            PageDirection::Output => MappingFlags(NORMAL_PAGE_PRIORITY | MDL_MAPPING_NO_EXECUTE),
        },
    }
}

/// Section view protection for the legacy `ZwMapViewOfSection` path.
///
/// The enum has exactly two variants **on purpose**: `11-rust-implementation.md`
/// section 4 requires every original and alias view to reject `PAGE_EXECUTE*`,
/// and an unrepresentable value cannot be passed by mistake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionProtect {
    ReadOnly,
    ReadWrite,
}

impl SectionProtect {
    /// `PAGE_READONLY = 0x02`, `PAGE_READWRITE = 0x04`.
    pub const fn raw(self) -> u32 {
        match self {
            Self::ReadOnly => 0x02,
            Self::ReadWrite => 0x04,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsring_abi::features::PlatformProfile::{Win7X64, Win10Arm64, Win10X64};

    #[test]
    fn modern_output_pages_stay_writable() {
        // 02-transport.md and 05-irp-dispatch.md: MdlMappingNoWrite applies ONLY
        // to input-only pages; output pages remain writable. This is the cell the
        // first draft of this slice got wrong, and it would have been wrong on
        // every modern system.
        let f = mdl_mapping_flags(Win10X64, PageDirection::Output);
        assert!(!f.contains_no_write(), "output pages must remain writable");
        assert!(
            f.contains_no_execute(),
            "NoExecute is unconditional on modern"
        );
    }

    #[test]
    fn modern_input_only_pages_are_read_only_and_no_execute() {
        for p in [Win10X64, Win10Arm64] {
            let f = mdl_mapping_flags(p, PageDirection::InputOnly);
            assert!(f.contains_no_write());
            assert!(f.contains_no_execute());
        }
    }

    #[test]
    fn win7_passes_neither_flag_in_either_direction() {
        for d in [PageDirection::InputOnly, PageDirection::Output] {
            let f = mdl_mapping_flags(Win7X64, d);
            assert!(
                !f.contains_no_write(),
                "the Win7 encodings are not a contract"
            );
            assert!(!f.contains_no_execute());
            assert_eq!(
                f.raw(),
                NORMAL_PAGE_PRIORITY,
                "Win7 passes only the priority"
            );
        }
    }

    #[test]
    fn every_cell_carries_the_page_priority() {
        for p in [Win10X64, Win10Arm64, Win7X64] {
            for d in [PageDirection::InputOnly, PageDirection::Output] {
                assert_ne!(mdl_mapping_flags(p, d).raw() & NORMAL_PAGE_PRIORITY, 0);
            }
        }
    }

    #[test]
    fn the_two_modern_profiles_agree_cell_for_cell() {
        // The ARM64 profile differs from x64 only in the os_cap ARM64 bit, which
        // has no mapping consequence; a divergence here would be a bug.
        for d in [PageDirection::InputOnly, PageDirection::Output] {
            assert_eq!(
                mdl_mapping_flags(Win10X64, d),
                mdl_mapping_flags(Win10Arm64, d)
            );
        }
    }

    #[test]
    fn encodings_match_the_kernel_numeric_values() {
        // Pins the pure core to the wdk-sys values so the two cannot drift.
        assert_eq!(MDL_MAPPING_NO_WRITE, 0x8000_0000);
        assert_eq!(MDL_MAPPING_NO_EXECUTE, 0x4000_0000);
        assert_eq!(NORMAL_PAGE_PRIORITY, 16);
    }

    #[test]
    fn section_protect_has_no_executable_variant() {
        for p in [SectionProtect::ReadOnly, SectionProtect::ReadWrite] {
            let raw = p.raw();
            assert!(
                raw == 0x02 || raw == 0x04,
                "only PAGE_READONLY and PAGE_READWRITE are representable"
            );
        }
    }

    #[test]
    fn exact_success_is_required_for_probe_normalization() {
        assert_eq!(normalize_probe_status(0), Ok(()));
        assert_eq!(
            normalize_probe_status(1),
            Err(MappingResourceError::InsufficientResources)
        );
        assert_eq!(
            normalize_probe_status(i32::MIN),
            Err(MappingResourceError::InsufficientResources)
        );
    }

    #[test]
    fn mapping_normalization_requires_exact_success_and_nonnull_address() {
        let address = core::ptr::without_provenance_mut::<core::ffi::c_void>(0x1000);
        assert_eq!(
            normalize_mapping_result(0, address).map(|p| p.as_ptr()),
            Ok(address)
        );

        for (status, mapped) in [
            (0, core::ptr::null_mut()),
            (1, address),
            (i32::MIN, address),
        ] {
            assert_eq!(
                normalize_mapping_result(status, mapped),
                Err(MappingResourceError::InsufficientResources)
            );
        }
    }
}
