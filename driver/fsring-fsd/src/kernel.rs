//! Kernel implementations of the seams `fsring-core` defines.
//!
//! `fsring-core` holds the decisions as total functions; this module holds the
//! call sites, and it is the only place in the driver that touches a kernel
//! routine. Every routine comes through `fsring-sys`, never from a local
//! `extern` block.

use fsring_core::alloc::{Allocator, PoolPolicy, RawPool, pool_policy, try_alloc};
use fsring_core::random::{RandomError, RandomSource};
use fsring_core::resolver::{ResolvedDdis, resolve_all};

/// Call the secure-device constructor quarantined in `fsring-sys`.
///
/// # Safety
/// All pointer and PASSIVE_LEVEL obligations are those of
/// `WdmlibIoCreateDeviceSecure`.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn create_secure_device(
    driver: fsring_sys::PDRIVER_OBJECT,
    extension_size: fsring_sys::ULONG,
    device_name: fsring_sys::PUNICODE_STRING,
    device_type: fsring_sys::ULONG,
    characteristics: fsring_sys::ULONG,
    exclusive: fsring_sys::BOOLEAN,
    default_sddl: fsring_sys::PCUNICODE_STRING,
    class_guid: fsring_sys::LPCGUID,
    device_out: *mut fsring_sys::PDEVICE_OBJECT,
) -> fsring_sys::NTSTATUS {
    // SAFETY: forwarded unchanged under the caller's contract.
    unsafe {
        fsring_sys::WdmlibIoCreateDeviceSecure(
            driver,
            extension_size,
            device_name,
            device_type,
            characteristics,
            exclusive,
            default_sddl,
            class_guid,
            device_out,
        )
    }
}

/// Create a DOS symbolic link to the control device.
///
/// # Safety
/// Both descriptors must remain valid for the synchronous PASSIVE_LEVEL call.
pub(crate) unsafe fn create_symbolic_link(
    link: fsring_sys::PUNICODE_STRING,
    target: fsring_sys::PUNICODE_STRING,
) -> fsring_sys::NTSTATUS {
    // SAFETY: forwarded unchanged under the caller's contract.
    unsafe { fsring_sys::IoCreateSymbolicLink(link, target) }
}

/// Delete a DOS symbolic link.
///
/// # Safety
/// `link` must name a valid counted string for the synchronous PASSIVE_LEVEL
/// call.
pub(crate) unsafe fn delete_symbolic_link(
    link: fsring_sys::PUNICODE_STRING,
) -> fsring_sys::NTSTATUS {
    // SAFETY: forwarded unchanged under the caller's contract.
    unsafe { fsring_sys::IoDeleteSymbolicLink(link) }
}

/// Delete a device object owned by this driver.
///
/// # Safety
/// `device` must be live, owned by this driver, and deleted exactly once at
/// APC_LEVEL or lower.
pub(crate) unsafe fn delete_device(device: fsring_sys::PDEVICE_OBJECT) {
    // SAFETY: forwarded unchanged under the caller's contract.
    unsafe { fsring_sys::IoDeleteDevice(device) };
}

/// Complete one IRP after its status block has been finalized.
///
/// # Safety
/// `irp` must be live and owned by the current dispatch path. The caller must
/// neither complete it twice nor access it after this call.
pub(crate) unsafe fn complete_request(irp: fsring_sys::PIRP, increment: fsring_sys::CCHAR) {
    // SAFETY: forwarded unchanged under the caller's contract.
    unsafe { fsring_sys::IofCompleteRequest(irp, increment) };
}

/// Build a counted `UNICODE_STRING` over a caller-owned buffer of code units.
///
/// Object Manager names are counted, not NUL terminated, and `Buffer` is a
/// `*mut`, so callers pass a local copy of the constant rather than a pointer
/// into read-only image data.
pub(crate) fn counted_unicode_units(buffer: &mut [u16]) -> Option<wdk_sys::UNICODE_STRING> {
    let bytes = buffer.len().checked_mul(core::mem::size_of::<u16>())?;
    let length = u16::try_from(bytes).ok()?;
    Some(wdk_sys::UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: buffer.as_mut_ptr(),
    })
}

/// Build a NUL-terminated `UNICODE_STRING` over a caller-owned buffer.
///
/// This is the OTHER convention, and the difference is not cosmetic:
/// `WdmlibIoCreateDeviceSecure`'s `DefaultSDDLString` is a terminated string
/// whose `MaximumLength` counts the terminator, while an Object Manager name
/// passed to the same call is counted and unterminated. Both used to be built
/// by `counted_unicode_units`, so the SDDL reached the WDK claiming
/// `MaximumLength == Length` over a buffer with no terminator -- two
/// conventions on one argument, and at most one of them can be right.
///
/// Refusing a buffer whose last unit is not NUL is what keeps the two apart:
/// a caller that reaches for this with an Object Manager name gets `None`
/// rather than a subtly wrong descriptor.
pub(crate) fn counted_unicode_sz(buffer: &mut [u16]) -> Option<wdk_sys::UNICODE_STRING> {
    if buffer.last().copied() != Some(0) {
        return None;
    }
    let units = buffer.len().checked_sub(1)?;
    let length = u16::try_from(units.checked_mul(core::mem::size_of::<u16>())?).ok()?;
    let maximum = u16::try_from(buffer.len().checked_mul(core::mem::size_of::<u16>())?).ok()?;
    Some(wdk_sys::UNICODE_STRING {
        Length: length,
        MaximumLength: maximum,
        Buffer: buffer.as_mut_ptr(),
    })
}

/// Free one tagged block allocated through [`KernelPool`].
///
/// # Safety
/// `block` must be a non-null block this driver allocated with [`POOL_TAG`] and
/// has not already freed.
pub(crate) unsafe fn free_pool(block: *mut u8) {
    // SAFETY: forwarded unchanged under the caller's contract. One free path
    // serves both allocators: they share this tag.
    unsafe { fsring_sys::ExFreePoolWithTag(block.cast(), POOL_TAG) };
}

/// Retained storage for the resolved optional allocator address.
///
/// A stable exported symbol rather than a private field, because the static
/// audit must be able to prove from the final image that the resolver edge
/// exists — a source-level `Option<fn>` leaves nothing to point at. Zero means
/// the capability was never latched.
// SAFETY-OF-NAME: the audit matches this exact spelling; renaming it silently
// removes the anchor rather than failing a check.
#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static mut fsring_resolved_ex_allocate_pool2: usize = 0;

/// Publish the resolved optional-allocator address.
///
/// # Safety
/// Must be called once on the DriverEntry thread, before either endpoint is
/// published, so no dispatch path can observe a half-written value.
pub(crate) unsafe fn publish_resolved_pool2(ddis: &ResolvedDdis) {
    let address = ddis.ex_allocate_pool2.unwrap_or(0);
    // SAFETY: the load thread is the only writer and no other path is
    // reachable yet, so this store races with nothing. `&raw mut` avoids
    // creating a reference to a `static mut`.
    unsafe { core::ptr::write(&raw mut fsring_resolved_ex_allocate_pool2, address) };
}

/// The single call edge to the resolved optional allocator.
///
/// Non-inlined and exported so the static audit can find exactly one call site
/// for a DDI that is deliberately never a static import.
///
/// # Safety
/// Callable at IRQL <= DISPATCH_LEVEL. Returns null when the capability was
/// never latched, which the caller must treat as an allocation failure.
// SAFETY-OF-NAME: as above, the audit matches this exact spelling.
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn fsring_call_ex_allocate_pool2(
    flags: u64,
    bytes: fsring_sys::SIZE_T,
    tag: fsring_sys::ULONG,
) -> fsring_sys::PVOID {
    // SAFETY: publication happened on the load thread before any caller
    // existed; this reads a plain machine word without forming a reference.
    let address = unsafe { core::ptr::read(&raw const fsring_resolved_ex_allocate_pool2) };
    if address == 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: `MmGetSystemRoutineAddress` returned this address for the exact
    // name "ExAllocatePool2", whose signature is `ExAllocatePool2Fn`.
    let allocate = unsafe { core::mem::transmute::<usize, fsring_sys::ExAllocatePool2Fn>(address) };
    // SAFETY: forwarded unchanged under this function's own contract.
    unsafe { allocate(flags, bytes, tag) }
}

/// Pool tag, rendered `FSRg` by poolmon and `!poolused`.
///
/// Those tools print the ULONG's four bytes in memory order, so the literal
/// must be in display order too. The C multi-character-literal spelling
/// `'gRSF'` is already reversed; feeding it to `from_le_bytes` reverses it a
/// second time and displays backwards.
pub const POOL_TAG: u32 = u32::from_le_bytes(*b"FSRg");

const _: () = assert!(
    POOL_TAG.to_le_bytes()[0] == b'F',
    "the tag must display as FSRg"
);

/// The kernel pool behind [`fsring_core::alloc::try_alloc`].
///
/// Carries the resolved `ExAllocatePool2` address, so the capability the
/// resolver latched actually selects a different allocator. Without that, both
/// branches of the resolution would behave identically and the whole
/// optional-DDI mechanism would be decoration.
///
/// The zeroing obligation is NOT discharged here: `try_alloc` owns it, so a
/// second `RawPool` implementation cannot forget it.
pub struct KernelPool {
    pub(crate) pool2: bool,
}

impl KernelPool {
    /// Build a pool from the latched resolution outcome.
    pub fn new(ddis: &ResolvedDdis) -> Self {
        Self {
            pool2: ddis.all_resolved(),
        }
    }
}

impl RawPool for KernelPool {
    fn allocate(&mut self, policy: PoolPolicy, bytes: usize) -> *mut u8 {
        let size = bytes as fsring_sys::SIZE_T;
        let raw = match (policy.allocator, self.pool2) {
            (Allocator::Pool2, true) => {
                // SAFETY: the retained edge reads the address the resolver
                // latched and returns null when it never latched one, which
                // `try_alloc` turns into an error. The legacy profile's
                // `pool_policy` never selects this allocator.
                unsafe { fsring_call_ex_allocate_pool2(policy.pool_flags, size, POOL_TAG) }
            }
            // Either the profile selects the baseline path, or the capability
            // was never latched. Both take the always-present allocator.
            _ => {
                // SAFETY: `ExAllocatePoolWithTag` is callable at
                // IRQL <= DISPATCH_LEVEL for non-paged pool, which is the only
                // pool type `pool_policy` selects. Null on failure, which
                // `try_alloc` turns into an error.
                unsafe { fsring_sys::ExAllocatePoolWithTag(policy.pool_type, size, POOL_TAG) }
            }
        };
        raw.cast::<u8>()
    }
}

/// The one allocation site for a per-ring DRAIN scratch buffer.
///
/// Retained, non-inlined, and exported so the static audit can prove there is
/// exactly one owner of this topology-sized buffer. A second allocation site
/// would make "one negotiated-size scratch per ring" unverifiable from the
/// image, and a shared buffer between two rings would corrupt a notification
/// refresh under a concurrent drain.
///
/// # Safety
/// `pool` must point to a live [`KernelPool`]. Callable at IRQL <=
/// DISPATCH_LEVEL. Returns null on allocation failure, which the caller must
/// treat as failure and never dereference; a non-null result is adopted into
/// the session immediately.
// SAFETY-OF-NAME: the pool-owner audit matches this exact spelling.
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn fsring_allocate_drain_scratch(
    pool: *const KernelPool,
    byte_count: usize,
) -> *mut u8 {
    // SAFETY: the caller's pool contract; the delegation below is the only
    // allocation this wrapper performs.
    unsafe { allocate_scratch(pool, byte_count) }
}

/// The one allocation site for the session's single fence scratch buffer.
///
/// Deliberately a separate retained symbol from the DRAIN wrapper: the fence
/// scratch is `MAX_NOTIFICATION_CREDIT_SIZE` and must never be a ring's buffer,
/// and two distinct audit keys is what makes that checkable in the final image.
///
/// # Safety
/// As [`fsring_allocate_drain_scratch`].
// SAFETY-OF-NAME: as above.
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn fsring_allocate_fence_scratch(
    pool: *const KernelPool,
    byte_count: usize,
) -> *mut u8 {
    // SAFETY: as above.
    unsafe { allocate_scratch(pool, byte_count) }
}

/// The shared body of both retained scratch wrappers.
///
/// # Safety
/// As [`fsring_allocate_drain_scratch`].
unsafe fn allocate_scratch(pool: *const KernelPool, byte_count: usize) -> *mut u8 {
    if pool.is_null() || byte_count == 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller's contract; the pool is read-only here and the
    // allocator takes its own short-lived mutable copy.
    let mut owned = KernelPool {
        pool2: unsafe { (*pool).pool2 },
    };
    let policy = pool_policy(crate::platform::PROFILE, owned.pool2);
    match try_alloc(&mut owned, policy, byte_count) {
        Ok(block) => block,
        Err(_) => core::ptr::null_mut(),
    }
}

/// Longest optional-DDI name the resolver can convert to a `UNICODE_STRING`.
/// `ExAllocatePool2` is 15 characters; the bound is generous and checked.
const MAX_ROUTINE_NAME: usize = 64;

/// Resolve one exported routine by name.
///
/// `11-rust-implementation.md` section 3: `MmGetSystemRoutineAddress` is used
/// **only** for documented kernel/HAL exports, and a resolved pointer is
/// validated non-null before first use. A name too long for the buffer resolves
/// to `None`, which clears the capability rather than guessing.
fn resolve_one(name: &str) -> Option<usize> {
    let mut utf16 = [0u16; MAX_ROUTINE_NAME];
    let mut len = 0usize;
    for ch in name.chars() {
        if len >= MAX_ROUTINE_NAME || !ch.is_ascii() {
            return None;
        }
        let slot = utf16.get_mut(len)?;
        *slot = ch as u16;
        len = len.saturating_add(1);
    }

    // UNICODE_STRING lengths are byte counts in a u16 field.
    let bytes = len.checked_mul(2)?;
    let byte_len = u16::try_from(bytes).ok()?;

    let mut name_string = wdk_sys::UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: utf16.as_mut_ptr(),
    };

    // SAFETY: `name_string` describes `len` valid UTF-16 code units that live
    // for the duration of the call. `MmGetSystemRoutineAddress` returns null
    // when the routine is absent, which is the answer we want.
    let address = unsafe { fsring_sys::MmGetSystemRoutineAddress(&raw mut name_string) };
    if address.is_null() {
        None
    } else {
        Some(address as usize)
    }
}

/// Resolve every optional DDI in `fsring_core::resolver::RESOLVER_TABLE`.
///
/// Called once during bring-up and latched — never lazily on a hot path. A null
/// result clears the capability and selects the static path.
pub fn resolve_optional_ddis() -> ResolvedDdis {
    resolve_all(resolve_one)
}

/// The kernel CNG randomness source.
///
/// `11-rust-implementation.md` section 4 makes this the only permitted source:
/// there is no weaker fallback, and `RtlRandom*` is forbidden.
pub struct CngRandom;

impl RandomSource for CngRandom {
    fn fill(&mut self, out: &mut [u8; 8]) -> Result<(), RandomError> {
        // SAFETY: `out` is valid for 8 bytes. A null algorithm handle together
        // with BCRYPT_USE_SYSTEM_PREFERRED_RNG selects the system RNG, which is
        // the documented contract. Must be called at PASSIVE_LEVEL.
        let status = unsafe {
            fsring_sys::BCryptGenRandom(
                core::ptr::null_mut(),
                out.as_mut_ptr(),
                8,
                fsring_sys::BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            return Err(RandomError::SourceFailed);
        }
        Ok(())
    }
}
