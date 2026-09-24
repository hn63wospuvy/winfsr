//! Real Windows shared-section [`SharedSection`] and an auto-reset-[`EventWaiter`].
//!
//! `MappedSection` backs the section with a pagefile-backed
//! `CreateFileMapping`/`MapViewOfFile` section and parks/wakes on a Windows
//! auto-reset event. Unlike the heap backend it can be mapped at two independent
//! base addresses (proving the transport's section-relative addressing) and its
//! event wait is the shape the kernel's `KEVENT`-based wait will take.
//!
//! It uses raw `kernel32` FFI (seven stable calls) rather than a binding crate,
//! keeping `fsring-user` dependency-free for the eventual PE import audit.

use std::io;
use std::ptr;

use super::{SharedSection, Waiter};

mod sys {
    use core::ffi::c_void;

    pub type Handle = *mut c_void;
    pub type Bool = i32;

    pub const INVALID_HANDLE_VALUE: Handle = usize::MAX as Handle; // (HANDLE)-1
    pub const FALSE: Bool = 0;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const FILE_MAP_ALL_ACCESS: u32 = 0x000F_001F;
    pub const INFINITE: u32 = 0xFFFF_FFFF;
    pub const WAIT_FAILED: u32 = 0xFFFF_FFFF;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn CreateFileMappingW(
            file: Handle,
            attributes: *const c_void,
            protect: u32,
            maximum_size_high: u32,
            maximum_size_low: u32,
            name: *const u16,
        ) -> Handle;
        pub fn MapViewOfFile(
            mapping: Handle,
            desired_access: u32,
            file_offset_high: u32,
            file_offset_low: u32,
            number_of_bytes: usize,
        ) -> *mut c_void;
        pub fn UnmapViewOfFile(base_address: *const c_void) -> Bool;
        pub fn CreateEventW(
            attributes: *const c_void,
            manual_reset: Bool,
            initial_state: Bool,
            name: *const u16,
        ) -> Handle;
        pub fn SetEvent(event: Handle) -> Bool;
        pub fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        pub fn CloseHandle(object: Handle) -> Bool;
    }
}

/// A [`Waiter`] backed by a Windows auto-reset event.
///
/// Auto-reset events already have the saturating single-pending-wake semantics
/// the [`Waiter`] trait requires: `SetEvent` on an already-signaled event is a
/// no-op, and `WaitForSingleObject` consumes the signal, so a wake before a wait
/// is never lost.
pub struct EventWaiter {
    handle: sys::Handle,
}

impl EventWaiter {
    fn create() -> io::Result<Self> {
        // manual_reset = FALSE (auto-reset), initial_state = FALSE (non-signaled).
        // SAFETY: null attributes/name are valid; the returned handle is checked.
        let handle = unsafe { sys::CreateEventW(ptr::null(), sys::FALSE, sys::FALSE, ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle })
    }
}

impl Waiter for EventWaiter {
    fn wait(&self) {
        // SAFETY: `handle` is a live event owned by `self` until `Drop`.
        let result = unsafe { sys::WaitForSingleObject(self.handle, sys::INFINITE) };
        debug_assert_ne!(result, sys::WAIT_FAILED, "WaitForSingleObject failed");
    }

    fn wake(&self) {
        // SAFETY: `handle` is a live event owned by `self` until `Drop`.
        let ok = unsafe { sys::SetEvent(self.handle) };
        debug_assert!(ok != 0, "SetEvent failed");
    }
}

impl Drop for EventWaiter {
    fn drop(&mut self) {
        // SAFETY: `handle` was created by `CreateEventW` and is closed once.
        unsafe { sys::CloseHandle(self.handle) };
    }
}

// SAFETY: an event handle is a kernel object safe to signal/wait from any thread.
unsafe impl Send for EventWaiter {}
unsafe impl Sync for EventWaiter {}

/// A second mapped view of a [`MappedSection`], at an independent base address.
///
/// Unmaps its view on drop; it borrows (does not own) the parent section's
/// mapping and event, so it must not outlive the parent.
pub struct PeerView<'a> {
    view: *mut u8,
    len: usize,
    _parent: core::marker::PhantomData<&'a MappedSection>,
}

impl PeerView<'_> {
    /// Base address of this view (differs from the parent's base).
    pub fn base(&self) -> *mut u8 {
        self.view
    }

    /// Byte length of the view.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len
    }
}

impl Drop for PeerView<'_> {
    fn drop(&mut self) {
        // SAFETY: `view` came from `MapViewOfFile` and is unmapped once.
        unsafe { sys::UnmapViewOfFile(self.view.cast()) };
    }
}

/// A [`SharedSection`] backed by a real pagefile-backed Windows section.
pub struct MappedSection {
    mapping: sys::Handle,
    view: *mut u8,
    len: usize,
    waiter: EventWaiter,
}

impl MappedSection {
    /// Create a zeroed section of `len` bytes and map one view of it.
    ///
    /// The section is pagefile-backed, so its bytes start zeroed. The view is
    /// aligned to the 64 KiB allocation granularity, satisfying every ABI
    /// structure alignment.
    pub fn create(len: usize) -> io::Result<Self> {
        assert!(len > 0, "section length must be non-zero");
        let size = len as u64;
        // SAFETY: INVALID_HANDLE_VALUE requests a pagefile-backed section; null
        // attributes/name are valid; the returned handle is checked.
        let mapping = unsafe {
            sys::CreateFileMappingW(
                sys::INVALID_HANDLE_VALUE,
                ptr::null(),
                sys::PAGE_READWRITE,
                (size >> 32) as u32,
                (size & 0xFFFF_FFFF) as u32,
                ptr::null(),
            )
        };
        if mapping.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `mapping` is a live section handle; mapping `len` bytes at
        // offset 0 with full access.
        let view = unsafe { sys::MapViewOfFile(mapping, sys::FILE_MAP_ALL_ACCESS, 0, 0, len) };
        if view.is_null() {
            let error = io::Error::last_os_error();
            // SAFETY: `mapping` is live and closed once on this error path.
            unsafe { sys::CloseHandle(mapping) };
            return Err(error);
        }
        let waiter = match EventWaiter::create() {
            Ok(waiter) => waiter,
            Err(error) => {
                // SAFETY: both handles are live and released once on this path.
                unsafe {
                    sys::UnmapViewOfFile(view);
                    sys::CloseHandle(mapping);
                }
                return Err(error);
            }
        };
        Ok(Self {
            mapping,
            view: view.cast::<u8>(),
            len,
            waiter,
        })
    }

    /// Map a second view of the same section at an independent base address.
    pub fn map_peer_view(&self) -> io::Result<PeerView<'_>> {
        // SAFETY: `self.mapping` is a live section handle for `self`'s lifetime.
        let view =
            unsafe { sys::MapViewOfFile(self.mapping, sys::FILE_MAP_ALL_ACCESS, 0, 0, self.len) };
        if view.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(PeerView {
            view: view.cast::<u8>(),
            len: self.len,
            _parent: core::marker::PhantomData,
        })
    }
}

// SAFETY: the section owns a unique view+mapping+event live until `Drop`. Both
// roles address it via section-relative offsets and access ring cells only
// through the ABI atomic/volatile operations; the event is thread-safe.
unsafe impl SharedSection for MappedSection {
    fn base(&self) -> *mut u8 {
        self.view
    }

    fn len(&self) -> usize {
        self.len
    }

    type Waiter = EventWaiter;

    fn waiter(&self) -> &EventWaiter {
        &self.waiter
    }
}

// SAFETY: a mapped section is shared memory intended for concurrent access from
// both roles; the view pointer is stable and cell access is atomic/volatile.
unsafe impl Send for MappedSection {}
unsafe impl Sync for MappedSection {}

impl Drop for MappedSection {
    fn drop(&mut self) {
        // SAFETY: `view`/`mapping` came from Map/CreateFileMapping and are each
        // released exactly once here; the waiter closes its own handle.
        unsafe {
            sys::UnmapViewOfFile(self.view.cast());
            sys::CloseHandle(self.mapping);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::pump_once;
    use crate::fixture::valid_setup;
    use crate::layout::PhysicalLayout;
    use crate::provider::EchoProvider;
    use crate::ring::{DaemonRing, KernelRing};
    use fsring_abi::layout::{cq_kind, SqeBody, SQE_PAYLOAD_LEN};
    use std::sync::atomic::{AtomicBool, Ordering};

    const CLEANUP: u16 = 0x0004;

    fn request(req_id: u64) -> SqeBody {
        SqeBody {
            opcode: CLEANUP,
            flags: 0,
            payload_len: 24,
            reserved: 0,
            req_id,
            kernel_open_id: 0,
            ccb_sequence: 0,
            payload: [0u8; SQE_PAYLOAD_LEN],
        }
    }

    #[test]
    fn event_waiter_wake_before_wait_is_not_lost() {
        use std::sync::mpsc;
        use std::sync::Arc;
        use std::time::Duration;
        let section = Arc::new(MappedSection::create(65536).expect("create section"));
        section.waiter().wake(); // wake BEFORE wait
        let peer = Arc::clone(&section);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            peer.waiter().wait();
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "auto-reset event lost a wake delivered before wait"
        );
    }

    #[test]
    fn two_views_alias_the_same_memory_at_different_bases() {
        let section = MappedSection::create(65536).expect("create section");
        let peer = section.map_peer_view().expect("map peer view");
        assert_ne!(
            section.base() as usize,
            peer.base() as usize,
            "the two views must map at different base addresses"
        );
        assert_eq!(section.len(), peer.len());
        // Write through the primary view, read through the peer view.
        // SAFETY: both views cover `len` writable/readable bytes of one section.
        unsafe {
            ptr::write(section.base().add(4096), 0xABu8);
            assert_eq!(ptr::read(peer.base().add(4096)), 0xAB, "views must alias");
        }
    }

    fn build_mapped_single_ring() -> (MappedSection, PhysicalLayout) {
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, 4096).expect("compute");
        let section = MappedSection::create(layout.section_size as usize).expect("create section");
        // SAFETY: freshly created zeroed section of section_size bytes.
        unsafe { layout.construct(section.base(), section.len()) };
        (section, layout)
    }

    #[test]
    fn single_round_trip_over_a_real_section() {
        let (section, layout) = build_mapped_single_ring();
        let regions = layout.rings[0];
        // SAFETY: section outlives both handles; one handle per role.
        let kernel = unsafe { KernelRing::attach(section.base(), &regions) };
        let mut daemon = unsafe { DaemonRing::attach(section.base(), &regions) };

        let mut provider = EchoProvider;
        let _receipt = kernel.submit(request(9)).expect("submit");
        assert_eq!(
            pump_once(&mut daemon, &mut provider).expect("pump").posted,
            1
        );
        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.req_id, 9);
        assert_eq!(cqe.kind, cq_kind::COMPLETION);
        assert_eq!(cqe.status, 0, "EchoProvider posts SUCCESS on both backends");
    }

    #[test]
    fn two_threads_ping_pong_with_blocking_park_and_wake() {
        let (section, layout) = build_mapped_single_ring();
        let regions = layout.rings[0];
        // SAFETY: section outlives both handles (scoped threads); one per role.
        let mut daemon = unsafe { DaemonRing::attach(section.base(), &regions) };
        let kernel = unsafe { KernelRing::attach(section.base(), &regions) };

        const N: u64 = 20;
        let stop = AtomicBool::new(false);

        let parks = std::thread::scope(|scope| {
            // Daemon: blocking ENTER loop. Returns how many times it parked.
            let daemon_handle = scope.spawn(|| {
                let mut provider = EchoProvider;
                let mut parks = 0u64;
                while !stop.load(Ordering::Acquire) {
                    if pump_once(&mut daemon, &mut provider).expect("pump").handled == 0
                        && daemon.declare_park().expect("declare_park")
                    {
                        parks += 1;
                        section.waiter().wait();
                    }
                }
                parks
            });

            // Kernel role: strict ping-pong — one request in flight at a time so
            // the small CQ never overflows and the daemon parks between rounds.
            scope.spawn(|| {
                let mut kernel = kernel;
                // Let the daemon reach declare_park + wait before the first
                // submit, so the parked path is exercised deterministically
                // (parks >= 1 rather than merely probable).
                std::thread::sleep(std::time::Duration::from_millis(20));
                for req_id in 1..=N {
                    loop {
                        match kernel.submit(request(req_id)) {
                            Ok(receipt) => {
                                if receipt.should_wake {
                                    section.waiter().wake();
                                }
                                break;
                            }
                            Err(_full) => std::thread::yield_now(),
                        }
                    }
                    // wait for exactly this completion
                    loop {
                        match kernel.reap().expect("reap") {
                            Some(cqe) => {
                                assert_eq!(cqe.req_id, req_id, "FIFO across threads");
                                break;
                            }
                            None => std::thread::yield_now(),
                        }
                    }
                }
                stop.store(true, Ordering::Release);
                section.waiter().wake(); // release a parked daemon so it can exit
            });

            daemon_handle.join().expect("daemon thread")
        });

        assert!(
            parks > 0,
            "the daemon must have actually blocked/parked, not busy-spun"
        );
    }
}
