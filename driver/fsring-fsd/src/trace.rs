//! Fixed-GUID ETW registration and the closed C4 evidence events.
//!
//! Design section 6.6: events observe already-committed transitions. Nothing
//! here authorizes, rolls back, or blocks a filesystem transition, and a
//! missing or failed write fails native *evidence*, never the operation that
//! was already committed.

// The four C4 evidence events observe transitions that arrive with SETUP,
// mount, verify, and the session fence. This slice owns the registration, its
// fixed provider identity, and the closed payload shape those transitions
// emit.
//
// This comment used to end "Task 11 onward are their first callers". Task 11
// is closed, and `trace::emit` is called today from SETUP's
// `EmitSessionPublished` arm while `trace::register` is called from LOAD's
// `RegisterEtw` arm -- so the sentence named a closed task as a future
// caller, which is what the promise gate exists to stop.
//
// MEASURED, round 19: this allow hides 2 of the 63 dead-code diagnostics
// `fsring-fsd` reports without its three module-wide allows; the count and
// the method are recorded on the one in `lifecycle.rs` (native review
// N18-3).
#![allow(dead_code)]

use fsring_abi::{BootInstanceId, MountId};
use wdk_sys::{EVENT_DATA_DESCRIPTOR, EVENT_DESCRIPTOR, GUID, NTSTATUS, REGHANDLE, STATUS_SUCCESS};

/// `{76A354FE-986E-4968-B41E-BB1209D57157}`.
const PROVIDER_GUID: GUID = GUID {
    Data1: 0x76A3_54FE,
    Data2: 0x986E,
    Data3: 0x4968,
    Data4: [0xB4, 0x1E, 0xBB, 0x12, 0x09, 0xD5, 0x71, 0x57],
};

/// The only event version this driver emits.
const EVENT_VERSION: u8 = 1;
/// `TRACE_LEVEL_INFORMATION`.
const EVENT_LEVEL: u8 = 4;
/// The lifecycle keyword.
const EVENT_KEYWORD: u64 = 0x1;

/// The closed C4 event identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum EvidenceEvent {
    SessionPublished = 1,
    MountPublished = 2,
    VerifySucceeded = 3,
    SessionFenced = 4,
}

/// The closed fence reasons. Every other event carries reason zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum FenceReason {
    Cleanup = 1,
    ProcessLoss = 2,
    ProtocolAbort = 3,
    Unload = 4,
}

/// The complete payload of every C4 evidence event.
///
/// Identity and one closed reason: no SID, path, pointer, user address, name,
/// or provider payload can be added without changing this type.
#[repr(C)]
struct EvidencePayload {
    version: u32,
    reserved: u32,
    boot_instance_lo: u64,
    boot_instance_hi: u64,
    mount_lo: u64,
    mount_hi: u64,
    session_epoch: u64,
    reason: u32,
    reserved_tail: u32,
}

const _: () = assert!(core::mem::size_of::<EvidencePayload>() == 56);

/// The driver's one trace registration.
pub(crate) struct TraceRegistration {
    handle: REGHANDLE,
    registered: bool,
}

impl TraceRegistration {
    pub(crate) const fn new() -> Self {
        Self {
            handle: 0,
            registered: false,
        }
    }

    pub(crate) const fn is_registered(&self) -> bool {
        self.registered
    }
}

/// The retained enable callback.
///
/// It is deliberately inert: enabling a provider must not be able to change
/// driver behaviour, only whether a write is consumed.
///
/// The ABI is `extern "C"` because `PETWENABLECALLBACK` is: Rust keeps
/// `"system"` and `"C"` distinct in the type system even where the target ABI
/// is identical, so an `extern "system"` body could not be installed here at
/// all. What the audit anchors on is the retained exported *name*, which is
/// unaffected.
///
/// # Safety
/// Invoked by ETW with its own arguments; this body dereferences none of them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsring_trace_enable_callback(
    _source: wdk_sys::LPCGUID,
    _control: wdk_sys::ULONG,
    _level: wdk_sys::UCHAR,
    _match_any: u64,
    _match_all: u64,
    _filter: wdk_sys::PEVENT_FILTER_DESCRIPTOR,
    _context: wdk_sys::PVOID,
) {
}

/// Register the fixed provider before either endpoint is published.
///
/// # Safety
/// Must run once at PASSIVE_LEVEL during load.
// One load effect, one frame: see `driver`'s "Bounded load frames".
#[inline(never)]
pub(crate) unsafe fn register(trace: &mut TraceRegistration) -> Result<(), NTSTATUS> {
    let provider = PROVIDER_GUID;
    let mut handle: REGHANDLE = 0;
    // SAFETY: the GUID and out parameter live on this frame for the call; the
    // callback is a retained function with the required ABI.
    let status = unsafe {
        fsring_sys::c4::EtwRegister(
            &raw const provider,
            Some(fsring_trace_enable_callback),
            core::ptr::null_mut(),
            &raw mut handle,
        )
    };
    if status != STATUS_SUCCESS {
        return Err(status);
    }
    trace.handle = handle;
    trace.registered = true;
    Ok(())
}

/// Unregister the provider. Idempotent, and last on every teardown path.
///
/// # Safety
/// Must run at PASSIVE_LEVEL.
pub(crate) unsafe fn unregister(trace: &mut TraceRegistration) {
    if !trace.registered {
        return;
    }
    // SAFETY: exactly this driver's registration, released once.
    unsafe {
        let _ = fsring_sys::c4::EtwUnregister(trace.handle);
    }
    trace.handle = 0;
    trace.registered = false;
}

/// Emit one evidence event for an already-committed transition.
///
/// The result is deliberately discarded by callers on the committed path: a
/// failed write is an evidence fault, not a filesystem fault.
///
/// # Safety
/// Must run at IRQL <= APC_LEVEL with the registration live.
pub(crate) unsafe fn emit(
    trace: &TraceRegistration,
    event: EvidenceEvent,
    boot_instance_id: BootInstanceId,
    mount_id: MountId,
    session_epoch: u64,
    reason: Option<FenceReason>,
) -> NTSTATUS {
    if !trace.registered {
        return wdk_sys::STATUS_INVALID_DEVICE_STATE;
    }

    let payload = EvidencePayload {
        version: u32::from(EVENT_VERSION),
        reserved: 0,
        boot_instance_lo: boot_instance_id.lo,
        boot_instance_hi: boot_instance_id.hi,
        mount_lo: mount_id.lo,
        mount_hi: mount_id.hi,
        session_epoch,
        // Only the fence event carries a nonzero reason.
        reason: match (event, reason) {
            (EvidenceEvent::SessionFenced, Some(reason)) => reason as u32,
            _ => 0,
        },
        reserved_tail: 0,
    };

    let descriptor = EVENT_DESCRIPTOR {
        Id: event as u16,
        Version: EVENT_VERSION,
        Channel: 0,
        Level: EVENT_LEVEL,
        Opcode: 0,
        Task: 0,
        Keyword: EVENT_KEYWORD,
    };

    let mut data = EVENT_DATA_DESCRIPTOR {
        Ptr: (&raw const payload) as u64,
        Size: core::mem::size_of::<EvidencePayload>() as u32,
        __bindgen_anon_1: wdk_sys::_EVENT_DATA_DESCRIPTOR__bindgen_ty_1 { Reserved: 0 },
    };

    // SAFETY: the descriptor, payload, and data descriptor all live on this
    // frame for the duration of the synchronous write.
    unsafe {
        fsring_sys::c4::EtwWrite(
            trace.handle,
            &raw const descriptor,
            core::ptr::null(),
            1,
            &raw mut data,
        )
    }
}
