//! # FSRING pinned kernel bindings.
//!
//! **This is the only crate in the driver that writes an `extern` block.**
//! `fsring-core` is WDK-free and `fsring-fsd` calls through here, so the import
//! audit and its allowlists have exactly one place to look, and
//! `fsring-core`'s quarantine test can assert that.
//!
//! Most of the kernel surface comes from `wdk-sys`, re-exported below so call
//! sites have a single import path. Four items cannot come from there, each
//! for a different and separately verified reason; they are hand-written here
//! with the header, line and reason recorded, so the surface can be audited
//! against the kit rather than trusted.
#![no_std]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

pub mod c4;

pub use c4::{FsRingMapLockedPagesSeh, FsRingProbeAndLockPagesSeh};

pub use wdk_sys::_WORK_QUEUE_TYPE::DelayedWorkQueue;
pub use wdk_sys::ntddk::{
    ExAcquireRundownProtection, ExFreePoolWithTag, ExInitializeRundownProtection,
    ExReInitializeRundownProtection, ExReleaseRundownProtection, ExRundownCompleted,
    ExWaitForRundownProtectionRelease, IoAllocateWorkItem, IoCreateSymbolicLink, IoDeleteDevice,
    IoDeleteSymbolicLink, IoFreeWorkItem, IoGetRequestorProcess, IoQueueWorkItem,
    IofCompleteRequest, KeAcquireSpinLockRaiseToDpc, KeBugCheckEx, KeInitializeSpinLock,
    KeReleaseSpinLock, MmGetSystemRoutineAddress, MmMapLockedPagesSpecifyCache,
    ObfDereferenceObject, ObfReferenceObject,
};
pub use wdk_sys::{
    BOOLEAN, CCHAR, CSHORT, EX_RUNDOWN_REF, FILE_DEVICE_SECURE_OPEN, FILE_DEVICE_UNKNOWN, GUID,
    IO_NO_INCREMENT, IRP, IRP_MJ_MAXIMUM_FUNCTION, KPROCESSOR_MODE, KSPIN_LOCK, LOCK_OPERATION,
    LPCGUID, MDL, MEMORY_ALLOCATION_ALIGNMENT, MEMORY_CACHING_TYPE, NTSTATUS, PCUNICODE_STRING,
    PDEVICE_OBJECT, PDRIVER_OBJECT, PEPROCESS, PEX_RUNDOWN_REF, PIO_STACK_LOCATION, PIO_WORKITEM,
    PIO_WORKITEM_ROUTINE, PIRP, PKSPIN_LOCK, PMDL, POOL_TYPE, PUNICODE_STRING, PVOID, SIZE_T,
    ULONG, ULONG_PTR, WORK_QUEUE_TYPE,
};

/// `POOL_TYPE` values this driver uses, named so call sites do not repeat raw
/// discriminants. Verified against the generated `wdk-sys` `_POOL_TYPE`.
pub mod pool_type {
    use super::POOL_TYPE;

    /// `NonPagedPool = 0` — the Win7 legacy pool. No NX guarantee on that
    /// baseline, which is why the legacy profile owes an explicit zeroing.
    pub const NON_PAGED: POOL_TYPE = 0;
    /// `NonPagedPoolNx = 512` — non-paged, no-execute. Present since Windows 8,
    /// so it is available at the modern profile's Windows 10 1507 floor.
    pub const NON_PAGED_NX: POOL_TYPE = 512;
}

/// `NormalPagePriority = 16`, from the generated `_MM_PAGE_PRIORITY`.
/// `02-transport.md` mandates it on both profiles.
pub const NORMAL_PAGE_PRIORITY: ULONG = 16;

/// `MDL_MAPPED_TO_SYSTEM_VA`, `wdm.h:18616`. `MdlFlags` is a `CSHORT`.
pub const MDL_MAPPED_TO_SYSTEM_VA: CSHORT = 0x0001;
/// `MDL_SOURCE_IS_NONPAGED_POOL`, `wdm.h:18618`.
pub const MDL_SOURCE_IS_NONPAGED_POOL: CSHORT = 0x0004;

/// `BCryptGenRandom` flag selecting the system-preferred RNG, from `bcrypt.h`.
pub const BCRYPT_USE_SYSTEM_PREFERRED_RNG: ULONG = 0x0000_0002;

unsafe extern "C" {
    /// The pool allocator this driver static-imports on **both** profiles.
    ///
    /// Hand-declared because **`wdk-build` blocklists it**:
    /// `wdk-build-0.5.1/src/bindgen.rs:99`,
    /// `.blocklist_item("ExAllocatePoolWithTag") // Deprecated`. It is not a
    /// macro — `wdm.h:25297` declares it as a real `NTKERNELAPI` function,
    /// gated only by `NTDDI_WIN2K`, so it is exported at every baseline this
    /// project supports.
    ///
    /// The project overrides the upstream deprecation deliberately. The modern
    /// replacement `ExAllocatePool2` is `NTDDI_WIN10_VB` (Windows 10 2004),
    /// newer than the modern profile's Windows 10 1507 floor, so
    /// static-importing it would fail the kernel loader on 1507-1909 x64 and
    /// 1709-1903 ARM64 — `00-INDEX.md` section 5 forbids exactly that. It is
    /// reached through `fsring_core::resolver` instead.
    ///
    /// # Safety
    /// Callable at IRQL <= DISPATCH_LEVEL for non-paged pool. Returns null on
    /// failure; the caller must treat null as failure and never dereference it.
    pub fn ExAllocatePoolWithTag(pool_type: POOL_TYPE, bytes: SIZE_T, tag: ULONG) -> PVOID;
}

#[link(name = "wdmsec", kind = "static", modifiers = "-bundle")]
unsafe extern "C" {
    /// Create a named device with the supplied SDDL and class GUID.
    ///
    /// Hand-declared because `wdk-sys` generates only its WDM base header set
    /// (`ntifs.h`, `ntddk.h`, and `ntstrsafe.h`); `wdmsec.h` is outside it, so
    /// `wdk-sys 0.5.1` has no generated declaration. `wdmsec.h:381-404`
    /// aliases `IoCreateDeviceSecure` to this export, declares it at
    /// PASSIVE_LEVEL, and names `Wdmsec.lib` (this `#[link]`) as its library.
    /// `wdm.h:7088` defines the macro-only `DEVICE_TYPE` parameter as `ULONG`.
    ///
    /// # Safety
    /// Call only at PASSIVE_LEVEL. `driver` and `device_name` must remain valid
    /// for the call; `default_sddl` must point to a valid Unicode string;
    /// `class_guid` may be null or point to a valid GUID;
    /// and `device_out` must be writable for one device-object pointer. On
    /// success the caller owns the returned device object's lifetime and must
    /// ultimately call `IoDeleteDevice` at its documented APC-or-lower IRQL.
    pub fn WdmlibIoCreateDeviceSecure(
        driver: PDRIVER_OBJECT,
        extension_size: ULONG,
        device_name: PUNICODE_STRING,
        device_type: ULONG,
        characteristics: ULONG,
        exclusive: BOOLEAN,
        default_sddl: PCUNICODE_STRING,
        class_guid: LPCGUID,
        device_out: *mut PDEVICE_OBJECT,
    ) -> NTSTATUS;
}

#[link(name = "ksecdd")]
unsafe extern "C" {
    /// The **only** randomness source `11-rust-implementation.md` section 4
    /// permits. Time, counters, PIDs, `RtlRandom*` and daemon-supplied bytes are
    /// never entropy, and there is no weaker fallback.
    ///
    /// Hand-declared because it is not in the WDM base header set
    /// (`ntifs.h`/`ntddk.h`/`ntstrsafe.h`) that `wdk-sys` generates from; it
    /// lives in `bcrypt.h`. It links against `km/x64/ksecdd.lib`, present in
    /// WDK 10.0.26100 — hence the `ksecdd.sys` entry in
    /// `driver/audit/kernel-modules.allow`.
    ///
    /// # Safety
    /// Must be called at PASSIVE_LEVEL. `buffer` must be valid for `length`
    /// bytes. Pass a null `algorithm` together with
    /// [`BCRYPT_USE_SYSTEM_PREFERRED_RNG`].
    pub fn BCryptGenRandom(
        algorithm: PVOID,
        buffer: *mut u8,
        length: ULONG,
        flags: ULONG,
    ) -> NTSTATUS;
}

/// Signature of `ExAllocatePool2`, called through the pointer
/// `MmGetSystemRoutineAddress` returns.
///
/// It is never a static import: `wdm.h` declares it inside
/// `#if (NTDDI_VERSION >= NTDDI_WIN10_VB)` (Windows 10 2004), newer than the
/// modern profile's 1507 floor, so importing it would fail the kernel loader on
/// 1507-1909. `driver/scripts/audit_sys.sh --resolver-table` asserts its
/// absence from every image's import directory.
pub type ExAllocatePool2Fn = unsafe extern "C" fn(u64, SIZE_T, ULONG) -> PVOID;

/// Reimplementation of the `MmGetSystemAddressForMdlSafe` FORCEINLINE.
///
/// There is no `ntoskrnl` export of this name to declare: `wdm.h` defines it as
/// a `FORCEINLINE` function over [`MmMapLockedPagesSpecifyCache`], so the fast
/// path must be **ported**, not bound. The logic below is the header's: if the
/// MDL already has a system virtual address, or its source is non-paged pool,
/// reuse the existing mapping; otherwise map it.
///
/// # Safety
/// `mdl` must point to a valid, locked MDL. A null return means the mapping
/// failed and the caller must complete `INSUFFICIENT_RESOURCES`
/// (`02-transport.md`); it must never be dereferenced.
pub unsafe fn mm_get_system_address_for_mdl_safe(mdl: PMDL, priority: ULONG) -> PVOID {
    // SAFETY: the caller guarantees `mdl` points to a valid locked MDL.
    let flags = unsafe { (*mdl).MdlFlags };
    if flags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL) != 0 {
        // SAFETY: the flag just tested says the system VA is already valid.
        unsafe { (*mdl).MappedSystemVa }
    } else {
        // SAFETY: KernelMode, MmCached, a null requested address and
        // BugCheckOnFailure = FALSE are the header's own arguments; `mdl` is
        // valid per the caller's contract.
        unsafe {
            MmMapLockedPagesSpecifyCache(
                mdl,
                KERNEL_MODE,
                MM_CACHED,
                core::ptr::null_mut(),
                0,
                priority,
            )
        }
    }
}

/// Port of the `IoGetCurrentIrpStackLocation` `FORCEINLINE` field read.
///
/// This is intentionally not an extern: `wdm.h:34656-34682` defines it inline
/// and no corresponding kernel export exists. The header asserts
/// `CurrentLocation <= StackCount + 1` before reading
/// `Irp->Tail.Overlay.CurrentStackLocation`; this preserves that assertion and
/// then follows the measured bindgen union path. The helper itself has no IRQL
/// restriction beyond the IRP owner's valid lifetime.
///
/// # Safety
/// `irp` must be non-null and remain a valid IRP for the read. Its
/// `CurrentLocation <= StackCount + 1` invariant must hold, and the returned
/// stack-location pointer is borrowed from that IRP: it must not outlive the
/// IRP or be dereferenced after the stack location is no longer current.
pub unsafe fn io_get_current_irp_stack_location(irp: PIRP) -> PIO_STACK_LOCATION {
    assert!(
        !irp.is_null(),
        "IoGetCurrentIrpStackLocation requires a non-null IRP"
    );

    // SAFETY: the caller guarantees `irp` remains a valid IRP for these field
    // reads; the assertion below is the WDK inline's input invariant.
    let (current_location, stack_count) = unsafe { ((*irp).CurrentLocation, (*irp).StackCount) };
    assert!(
        i16::from(current_location) <= i16::from(stack_count).saturating_add(1),
        "IRP CurrentLocation exceeds StackCount + 1"
    );

    // SAFETY: `Tail` and the two anonymous union members are active according
    // to the same IRP layout contract as the WDK inline. The pointer is only
    // returned, not dereferenced here.
    unsafe {
        (*irp)
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation
    }
}

/// `KernelMode = 0` from `_MODE`, narrowed to `KPROCESSOR_MODE` (a `CCHAR`).
const KERNEL_MODE: KPROCESSOR_MODE = 0;
/// `MmCached = 1` from `_MEMORY_CACHING_TYPE`.
const MM_CACHED: MEMORY_CACHING_TYPE = 1;

// These values are mirrored by `fsring-core`, which is WDK-free and cannot
// import them. Asserted at compile time rather than in a test module: this crate
// is unconditionally `no_std`, so it has no test harness, and a `const` assert
// is checked on every build including both kernel targets — which is where a
// drifted value would actually matter.
// Compared against the KIT, not against literals. A literal-to-literal assert
// only fires when someone edits this file; it cannot fire when a WDK upgrade
// changes a value, which is the drift the design names as the real risk. These
// compare to `wdk-sys`, which regenerates from the installed kit on every build.
const _: () = {
    assert!(pool_type::NON_PAGED == wdk_sys::_POOL_TYPE::NonPagedPool);
    assert!(pool_type::NON_PAGED_NX == wdk_sys::_POOL_TYPE::NonPagedPoolNx);
    assert!(NORMAL_PAGE_PRIORITY == wdk_sys::_MM_PAGE_PRIORITY::NormalPagePriority as ULONG);
    assert!(KERNEL_MODE as i32 == wdk_sys::_MODE::KernelMode);
    assert!(MM_CACHED == wdk_sys::_MEMORY_CACHING_TYPE::MmCached);
    assert!(MDL_MAPPED_TO_SYSTEM_VA as u32 == wdk_sys::MDL_MAPPED_TO_SYSTEM_VA);
    assert!(MDL_SOURCE_IS_NONPAGED_POOL as u32 == wdk_sys::MDL_SOURCE_IS_NONPAGED_POOL);
    // Not in the kit's generated set: bcrypt.h is outside the WDM base headers,
    // which is why BCryptGenRandom is hand-declared at all. Pinned to the
    // header's literal, with bcrypt.h:1437 as its provenance.
    assert!(BCRYPT_USE_SYSTEM_PREFERRED_RNG == 0x0000_0002);
};
