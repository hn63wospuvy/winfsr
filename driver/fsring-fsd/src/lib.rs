//! # FSRING filesystem driver (`fsring.sys`).
//!
//! This crate proves the Rust -> `.sys` build/link path, carries the compiled
//! platform profile, and publishes the secure native control device with its
//! implemented per-file context and allowlisted IOCTL handling. The filesystem
//! object model and transport arrive in later slices. It declares the mutually exclusive
//! `platform-win10`/`platform-win7` feature pair of
//! `11-rust-implementation.md` section 2 and selects exactly one profile at
//! compile time; see [`platform`].
#![no_std]
// 11-rust-implementation.md section 5: the driver input paths forbid these.
// The lints are asserted on every driver input path.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

pub mod boot;
pub mod control;
pub mod driver;
pub mod fence;
pub mod fscontrol;
pub mod kernel;
pub mod lifecycle;
pub mod pending_enter;
pub mod platform;
pub mod seh;
pub mod session;
pub mod trace;
pub mod volume;

// Task 9's native compiler gate: these exact C ABI assignments fail to compile
// until fsring-sys exposes both exception-contained shims with their audited
// signatures. They remain as drift checks on every x64/ARM64/profile build.
const _: unsafe extern "C" fn(
    wdk_sys::PMDL,
    wdk_sys::KPROCESSOR_MODE,
    wdk_sys::LOCK_OPERATION,
) -> wdk_sys::NTSTATUS = fsring_sys::FsRingProbeAndLockPagesSeh;
const _: unsafe extern "C" fn(
    wdk_sys::PMDL,
    wdk_sys::KPROCESSOR_MODE,
    wdk_sys::MEMORY_CACHING_TYPE,
    wdk_sys::PVOID,
    wdk_sys::ULONG,
    wdk_sys::ULONG,
    *mut wdk_sys::NTSTATUS,
) -> wdk_sys::PVOID = fsring_sys::FsRingMapLockedPagesSeh;

// Task 6's native compiler gate. Every assignment names the generated WDK
// declaration and its exact generated parameter/return types, so drift cannot
// be hidden behind a hand-written declaration or a locally invented callback.
const _: unsafe extern "C" fn(wdk_sys::PKSPIN_LOCK) = fsring_sys::c4::KeInitializeSpinLock;
const _: unsafe extern "C" fn(wdk_sys::PKSPIN_LOCK) -> wdk_sys::KIRQL =
    fsring_sys::c4::KeAcquireSpinLockRaiseToDpc;
const _: unsafe extern "C" fn(wdk_sys::PKSPIN_LOCK, wdk_sys::KIRQL) =
    fsring_sys::c4::KeReleaseSpinLock;
const _: unsafe extern "C" fn(wdk_sys::PEX_RUNDOWN_REF) =
    fsring_sys::c4::ExInitializeRundownProtection;
const _: unsafe extern "C" fn(wdk_sys::PEX_RUNDOWN_REF) -> wdk_sys::BOOLEAN =
    fsring_sys::c4::ExAcquireRundownProtection;
const _: unsafe extern "C" fn(wdk_sys::PEX_RUNDOWN_REF) =
    fsring_sys::c4::ExReleaseRundownProtection;
const _: unsafe extern "C" fn(wdk_sys::PEX_RUNDOWN_REF) =
    fsring_sys::c4::ExWaitForRundownProtectionRelease;
const _: unsafe extern "C" fn(wdk_sys::PEX_RUNDOWN_REF) = fsring_sys::c4::ExRundownCompleted;
const _: unsafe extern "C" fn(wdk_sys::PEX_RUNDOWN_REF) =
    fsring_sys::c4::ExReInitializeRundownProtection;
const _: unsafe extern "C" fn(wdk_sys::PRKEVENT, wdk_sys::EVENT_TYPE, wdk_sys::BOOLEAN) =
    fsring_sys::c4::KeInitializeEvent;
const _: unsafe extern "C" fn(wdk_sys::PRKEVENT) = fsring_sys::c4::KeClearEvent;
const _: unsafe extern "C" fn(wdk_sys::PRKEVENT) -> wdk_sys::LONG =
    fsring_sys::c4::KeReadStateEvent;
const _: unsafe extern "C" fn(
    wdk_sys::PRKEVENT,
    wdk_sys::KPRIORITY,
    wdk_sys::BOOLEAN,
) -> wdk_sys::LONG = fsring_sys::c4::KeSetEvent;
const _: unsafe extern "C" fn(
    wdk_sys::PVOID,
    wdk_sys::KWAIT_REASON,
    wdk_sys::KPROCESSOR_MODE,
    wdk_sys::BOOLEAN,
    wdk_sys::PLARGE_INTEGER,
) -> wdk_sys::NTSTATUS = fsring_sys::c4::KeWaitForSingleObject;
const _: unsafe extern "C" fn(wdk_sys::PDEVICE_OBJECT) -> wdk_sys::PIO_WORKITEM =
    fsring_sys::c4::IoAllocateWorkItem;
const _: unsafe extern "C" fn(
    wdk_sys::PIO_WORKITEM,
    wdk_sys::PIO_WORKITEM_ROUTINE,
    wdk_sys::WORK_QUEUE_TYPE,
    wdk_sys::PVOID,
) = fsring_sys::c4::IoQueueWorkItem;
const _: unsafe extern "C" fn(wdk_sys::PIO_WORKITEM) = fsring_sys::c4::IoFreeWorkItem;
const _: unsafe extern "C" fn(wdk_sys::PKIRQL) = fsring_sys::c4::IoAcquireVpbSpinLock;
const _: unsafe extern "C" fn(wdk_sys::KIRQL) = fsring_sys::c4::IoReleaseVpbSpinLock;

// Task 7 binds each installed asynchronous entry point to the generated WDK
// callback alias. These are type checks, not hand-written ABI declarations.
const _: wdk_sys::PIO_WORKITEM_ROUTINE = Some(lifecycle::fsring_finalizer_callback);
const _: wdk_sys::PCREATE_PROCESS_NOTIFY_ROUTINE_EX = Some(driver::fsring_process_loss);
const _: wdk_sys::PETWENABLECALLBACK = Some(trace::fsring_trace_enable_callback);

use wdk_sys::{DRIVER_OBJECT, NTSTATUS, PCUNICODE_STRING, STATUS_UNSUCCESSFUL, ntddk::DbgPrint};

// There is deliberately NO `#[global_allocator]` here, and no `wdk-alloc`.
// A global allocator exists to make `alloc`'s infallible APIs work, which is
// exactly the path `11-rust-implementation.md` section 5 forbids: allocation on
// the driver's input paths MUST be fallible and MUST NOT depend on an allocator
// that aborts on out-of-memory. Every allocation goes through
// `fsring_core::alloc::try_alloc` and returns a `Result`.

/// Bugcheck code for a Rust panic in the FSRING driver.
///
/// `11-rust-implementation.md` section 5: a Rust panic in the kernel is a real,
/// proven bug, not a recoverable condition, and is expressed as a coded
/// bugcheck rather than silent unwinding. The value sits in the
/// vendor-definable `0xE000_0000` range, so it cannot collide with a
/// Microsoft-assigned bugcheck code.
pub const FSRING_PANIC_BUGCHECK: u32 = 0xE000_0F51;

/// Kernel panic handler.
///
/// Replaces `wdk-panic`, whose handler is a bare `loop {}` — an infinite spin
/// at whatever IRQL the panic occurred, which hangs the machine instead of
/// producing a diagnosable crash dump.
///
/// The four parameters carry the panic SITE, because the panic MESSAGE is not
/// in the image to carry. `panic = "abort"` plus the optimiser drop every
/// format string, so a handler that passed four zeroes made every assert,
/// `unreachable!` and slot-less callback in this driver produce one
/// indistinguishable bugcheck — the failure could be told apart only by
/// disassembling the return address. `PanicInfo::location` survives: the file
/// path is a `&'static str` in `.rdata` and the line and column are constants.
///
/// Parameter slots, documented so a future dump is readable:
///   1: address of the panic site's file-path bytes (not NUL-terminated)
///   2: length of those bytes
///   3: line number, 1-based
///   4: column number, 1-based
///
/// A `PanicInfo` with no location yields four zeroes, which is the old
/// behaviour and the only case that keeps it.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let (file_ptr, file_len, line, column) = match info.location() {
        Some(location) => {
            let file = location.file();
            (
                file.as_ptr() as usize as fsring_sys::ULONG_PTR,
                file.len() as fsring_sys::ULONG_PTR,
                location.line() as fsring_sys::ULONG_PTR,
                location.column() as fsring_sys::ULONG_PTR,
            )
        }
        None => (0, 0, 0, 0),
    };
    // SAFETY: `KeBugCheckEx` is callable at any IRQL and never returns; it is
    // the last thing this image does. The parameters are plain integers: the
    // DDI records them, it does not dereference them.
    unsafe { fsring_sys::KeBugCheckEx(FSRING_PANIC_BUGCHECK, file_ptr, file_len, line, column) }
}

/// WDM driver entry point.
///
/// # Safety
/// Invoked by the Windows kernel loader with a valid `driver` object and
/// `registry_path`. It dereferences nothing from `registry_path`.
// SAFETY: "DriverEntry" is the required export name for a WDM entry point; no
// other symbol in this crate exports that name.
#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    if fsring_abi::features::validate_implementation_protocol_mask(
        platform::PROFILE,
        platform::IMPLEMENTED_PROTOCOL_MASK,
    )
    .is_err()
    {
        return STATUS_UNSUCCESSFUL;
    }

    // Emit one debug line so the image links a real kernel import (`DbgPrint`
    // from ntoskrnl.exe) and so the compiled profile name is embedded in the
    // image, where the static audit can find it (`audit_sys.sh
    // --expect-profile`). This keeps the audit non-vacuous: it proves the
    // toolchain links kernel imports while excluding the C runtime, rather than
    // passing on an empty import table. The banner is a per-profile C-string
    // constant, so there is no variadic call or allocation. Its DbgPrint import
    // remains inside the static audit's explicit kernel-import allowlist
    // alongside the implemented allocator, resolver, RNG, and control paths.
    // SAFETY: `BANNER` is a valid NUL-terminated string constant; `DbgPrint`
    // only reads it as its format argument and takes no variadic arguments.
    unsafe {
        DbgPrint(platform::BANNER.as_ptr().cast());
    }
    // Reference fsring-core from the entry path so the dependency is
    // load-bearing rather than merely declared: a core that fails to compile
    // for a kernel target now fails the image build. DriverEntry runs at
    // PASSIVE_LEVEL, which is exactly what this token asserts. The token is
    // zero-sized, so this is a compile-time claim - it puts no bytes in the
    // image and makes no runtime IRQL check.
    // SAFETY: `DriverEntry` runs at PASSIVE_LEVEL by the kernel's own contract,
    // which is exactly what `passive_at_driver_entry` requires of its caller.
    let passive = unsafe { fsring_core::typestate::passive_at_driver_entry() };

    // Resolve the optional DDIs once, here, and latch the result. Section 3 of
    // 11-rust-implementation.md requires this to happen during bring-up rather
    // than lazily on a hot path, and a null result clears the capability and
    // selects the complete static path.
    let ddis = kernel::resolve_optional_ddis();
    // SAFETY: the load thread is the only writer and no endpoint is reachable
    // yet, so the retained resolver edge is published before its first caller.
    unsafe { kernel::publish_resolved_pool2(&ddis) };
    // SAFETY: the two banners are valid NUL-terminated string constants;
    // DbgPrint reads them as its format argument with no variadic arguments.
    unsafe {
        if ddis.all_resolved() {
            DbgPrint(
                c"FSRING FSD: optional DDIs resolved
"
                .as_ptr()
                .cast(),
            );
        } else {
            DbgPrint(
                c"FSRING FSD: optional DDIs absent, static path selected
"
                .as_ptr()
                .cast(),
            );
        }
    }
    // Bring-up self-check. This is not ceremony: `11-rust-implementation.md`
    // section 4 states that a BCryptGenRandom failure aborts DriverEntry, and
    // exercising the pool and the RNG here is also what keeps their imports
    // live rather than dead-stripped under lto - the vacuity trap the toolchain
    // slice already fell into once with an empty import table.
    if bring_up(&passive, &ddis).is_err() {
        return STATUS_UNSUCCESSFUL;
    }

    // The dispatch table is complete before any device object exists, so no
    // request can reach a device whose major functions are still absent.
    // SAFETY: `driver` is the loader-owned object and this runs once.
    let dispatch_status = unsafe { control::install_dispatch_table(driver) };
    if dispatch_status != wdk_sys::STATUS_SUCCESS {
        return dispatch_status;
    }

    // Everything after this point is the ordered load choreography that
    // `fsring_core::adapter::load` owns; DriverEntry states none of it.
    // SAFETY: PASSIVE_LEVEL, once, with the loader-owned driver object.
    unsafe { driver::load(driver, ddis) }
}

/// Bring-up self-check: prove the fallible pool and the mandated randomness
/// source both work before the driver claims to have loaded.
///
/// Returns `Err(())` on any failure, which `DriverEntry` turns into a failed
/// load. There is deliberately no weaker path: `11-rust-implementation.md`
/// section 4 requires a randomness failure to fail closed rather than fall back
/// to a lesser source.
fn bring_up(
    _passive: &fsring_core::typestate::Passive,
    ddis: &fsring_core::resolver::ResolvedDdis,
) -> Result<(), ()> {
    use fsring_core::alloc::{pool_policy, try_alloc};
    use fsring_core::random::draw_nonzero;

    // The latched capability selects the allocator: this is where the resolver
    // stops being decoration.
    let policy = pool_policy(platform::PROFILE, ddis.all_resolved());
    let mut pool = kernel::KernelPool::new(ddis);
    let block = try_alloc(&mut pool, policy, 64).map_err(|_| ())?;
    // SAFETY: `try_alloc` returned a non-null 64-byte block from the tagged
    // pool, so freeing it with the same tag is the matching operation.
    unsafe { fsring_sys::ExFreePoolWithTag(block.cast(), kernel::POOL_TAG) };
    // ExFreePoolWithTag frees blocks from either allocator; ExAllocatePool2
    // takes the same tag, so one free path serves both.

    // The caller's `&Passive` is the compile-time evidence that this runs at
    // PASSIVE_LEVEL, which CNG requires.
    let mut rng = kernel::CngRandom;
    let _seed = draw_nonzero(&mut rng).map_err(|_| ())?;
    Ok(())
}
