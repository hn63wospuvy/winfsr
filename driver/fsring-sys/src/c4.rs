//! C4 kernel binding surface and exception-contained mapping shim declarations.
//!
//! WDK 10.0.26100 generates every public DDI re-exported below. The section
//! query import and its information structure are the only kernel declarations
//! missing from `wdk-sys`; the two `FsRing*Seh` declarations bind the C shim
//! compiled into `fsring-fsd`.

pub use wdk_sys::_EVENT_TYPE::NotificationEvent;
pub use wdk_sys::_LOCK_OPERATION::{IoModifyAccess, IoReadAccess};
pub use wdk_sys::_WORK_QUEUE_TYPE::DelayedWorkQueue;
pub use wdk_sys::ExEventObjectType;
pub use wdk_sys::ntddk::{
    EtwRegister, EtwUnregister, EtwWrite, ExAcquireRundownProtection,
    ExInitializeRundownProtection, ExReInitializeRundownProtection, ExReleaseRundownProtection,
    ExRundownCompleted, ExWaitForRundownProtectionRelease, IoAcquireVpbSpinLock, IoAllocateMdl,
    IoAllocateWorkItem, IoBuildPartialMdl, IoCreateDevice, IoCsqInitialize, IoCsqInitializeEx,
    IoCsqInsertIrp, IoCsqInsertIrpEx, IoCsqRemoveIrp, IoCsqRemoveNextIrp, IoDeleteDevice,
    IoFreeMdl, IoFreeWorkItem, IoQueueWorkItem, IoRegisterFileSystem, IoReleaseVpbSpinLock,
    IoUnregisterFileSystem, KeAcquireSpinLockRaiseToDpc, KeCancelTimer, KeClearEvent,
    KeDelayExecutionThread, KeEnterCriticalRegion, KeExpandKernelStackAndCallout, KeInitializeDpc,
    KeInitializeEvent, KeInitializeSpinLock, KeInitializeTimer, KeLeaveCriticalRegion,
    KeReadStateEvent, KeReleaseSpinLock, KeSetEvent, KeSetTimer, KeStackAttachProcess,
    KeUnstackDetachProcess, KeWaitForSingleObject, MmMapViewInSystemSpace, MmUnlockPages,
    MmUnmapLockedPages, MmUnmapViewInSystemSpace, ObGetObjectSecurity, ObReferenceObjectByHandle,
    ObReleaseObjectSecurity, PsSetCreateProcessNotifyRoutineEx, ZwClose, ZwCreateEvent,
    ZwCreateSection, ZwMakeTemporaryObject, ZwMapViewOfSection, ZwOpenEvent, ZwOpenSection,
    ZwUnmapViewOfSection,
};

pub use wdk_sys::{
    ACCESS_MASK, BOOLEAN, DEVICE_OBJECT, EVENT_TYPE, EX_RUNDOWN_REF, HANDLE, IO_CSQ,
    IO_CSQ_IRP_CONTEXT, KDPC, KEVENT, KIRQL, KPRIORITY, KPROCESSOR_MODE, KSPIN_LOCK, KTIMER,
    KWAIT_REASON, LARGE_INTEGER, LOCK_OPERATION, LONG, LPCGUID, MDL, MEMORY_CACHING_TYPE, NTSTATUS,
    PBOOLEAN, PCEVENT_DESCRIPTOR, PCREATE_PROCESS_NOTIFY_ROUTINE_EX, PDEVICE_OBJECT,
    PDRIVER_OBJECT, PEPROCESS, PETWENABLECALLBACK, PEVENT_DATA_DESCRIPTOR, PEX_RUNDOWN_REF,
    PEXPAND_STACK_CALLOUT, PHANDLE, PIO_CSQ, PIO_CSQ_ACQUIRE_LOCK, PIO_CSQ_COMPLETE_CANCELED_IRP,
    PIO_CSQ_INSERT_IRP, PIO_CSQ_INSERT_IRP_EX, PIO_CSQ_IRP_CONTEXT, PIO_CSQ_PEEK_NEXT_IRP,
    PIO_CSQ_RELEASE_LOCK, PIO_CSQ_REMOVE_IRP, PIO_WORKITEM, PIO_WORKITEM_ROUTINE, PIRP,
    PKDEFERRED_ROUTINE, PKDPC, PKIRQL, PKSPIN_LOCK, PKTIMER, PLARGE_INTEGER, PMDL,
    POBJECT_ATTRIBUTES, POBJECT_HANDLE_INFORMATION, POBJECT_TYPE, PREGHANDLE, PRKAPC_STATE, PRKDPC,
    PRKEVENT, PRKPROCESS, PSECURITY_DESCRIPTOR, PSIZE_T, PUNICODE_STRING, PVOID, REGHANDLE,
    SECTION_INHERIT, SIZE_T, ULONG, ULONG_PTR, VPB, WORK_QUEUE_TYPE,
};

// ---------------------------------------------------------------------------
// R4 Task 17: the staged non-Ex CSQ binding shape
// ---------------------------------------------------------------------------
//
// The production ENTER route uses the linked non-Ex CSQ: `IoCsqInitialize`
// plus void `IoCsqInsertIrp`, which itself marks the IRP pending. There is no
// separate `IoMarkIrpPending` helper. The Ex pair remains generated for
// signature comparison only.
//
// These are signature assertions, not wrappers: each names a locally declared
// function with the shape the WDK documents and assigns it to the generated
// callback type. A generated shape that differs -- an extra parameter, a
// returned status where the DDI returns void -- fails to compile here rather
// than being discovered against a live queue.
const _: () = {
    unsafe extern "C" fn insert(_csq: PIO_CSQ, _irp: PIRP) {}
    unsafe extern "C" fn remove(_csq: PIO_CSQ, _irp: PIRP) {}
    unsafe extern "C" fn peek(_csq: PIO_CSQ, _irp: PIRP, _context: PVOID) -> PIRP {
        core::ptr::null_mut()
    }
    unsafe extern "C" fn acquire(_csq: PIO_CSQ, _irql: PKIRQL) {}
    unsafe extern "C" fn release(_csq: PIO_CSQ, _irql: KIRQL) {}
    unsafe extern "C" fn cancel(_csq: PIO_CSQ, _irp: PIRP) {}

    let _: PIO_CSQ_INSERT_IRP = Some(insert);
    let _: PIO_CSQ_REMOVE_IRP = Some(remove);
    let _: PIO_CSQ_PEEK_NEXT_IRP = Some(peek);
    let _: PIO_CSQ_ACQUIRE_LOCK = Some(acquire);
    let _: PIO_CSQ_RELEASE_LOCK = Some(release);
    let _: PIO_CSQ_COMPLETE_CANCELED_IRP = Some(cancel);
};

/// Native `SECTION_INFORMATION_CLASS`; the WDK declares this as an enum-sized
/// integer but does not expose it through the generated WDM header set.
#[allow(non_camel_case_types)]
pub type SECTION_INFORMATION_CLASS = core::ffi::c_int;

/// `SectionBasicInformation = 0`.
pub const SECTION_BASIC_INFORMATION_CLASS: SECTION_INFORMATION_CLASS = 0;

/// Section information returned for [`SECTION_BASIC_INFORMATION_CLASS`].
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub struct SECTION_BASIC_INFORMATION {
    pub BaseAddress: PVOID,
    pub AllocationAttributes: ULONG,
    pub MaximumSize: LARGE_INTEGER,
}

unsafe extern "C" {
    /// Query basic information for a section object.
    pub fn ZwQuerySection(
        section: HANDLE,
        class: SECTION_INFORMATION_CLASS,
        information: PVOID,
        length: SIZE_T,
        return_length: PSIZE_T,
    ) -> NTSTATUS;

    /// Object Manager type used to make a typed section reference.
    pub static mut MmSectionObjectType: *mut POBJECT_TYPE;

    /// Fault-contained wrapper around `MmProbeAndLockPages`.
    pub fn FsRingProbeAndLockPagesSeh(
        mdl: *mut MDL,
        access_mode: KPROCESSOR_MODE,
        operation: LOCK_OPERATION,
    ) -> NTSTATUS;

    /// Fault-contained wrapper around `MmMapLockedPagesSpecifyCache`.
    pub fn FsRingMapLockedPagesSeh(
        mdl: *mut MDL,
        access_mode: KPROCESSOR_MODE,
        cache_type: MEMORY_CACHING_TYPE,
        requested_address: PVOID,
        bugcheck_on_failure: ULONG,
        priority: ULONG,
        status: *mut NTSTATUS,
    ) -> PVOID;
}

const _: () = {
    assert!(core::mem::size_of::<SECTION_BASIC_INFORMATION>() == 24);
    assert!(core::mem::align_of::<SECTION_BASIC_INFORMATION>() == 8);
    assert!(core::mem::offset_of!(SECTION_BASIC_INFORMATION, BaseAddress) == 0);
    assert!(core::mem::offset_of!(SECTION_BASIC_INFORMATION, AllocationAttributes) == 8);
    assert!(core::mem::offset_of!(SECTION_BASIC_INFORMATION, MaximumSize) == 16);
};
