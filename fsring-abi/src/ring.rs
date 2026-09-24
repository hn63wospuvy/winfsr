//! Ownership-separated FSRING ABI v2 transport.
//!
//! SQ storage is written by [`MpscProducer`] and read by one
//! [`SingleConsumer`]. CQ storage is written by [`SpscProducer`] and read by
//! one `SingleConsumer`. Wire fields remain plain integers in `layout`; this
//! module creates an atomic view of one aligned cursor or sequence field only
//! for the duration of each atomic operation.

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("fsring-abi v2 atomic shared-memory transport supports only x86_64 and aarch64");

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::ptr::{self, addr_of, addr_of_mut};
use core::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};

use crate::layout::{PARK_STATE_ACTIVE, PARK_STATE_PARKED, PARK_STATE_POLLING};
use crate::{ConsumerPage, Cqe, CqeBody, ProducerPage, Sqe, SqeBody};

/// Exact upper bound on MPSC reservation attempts in one `try_push` call.
pub const MAX_RESERVE_RETRIES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorFault {
    AheadOfProducer,
    Regressed,
    FutureSequence,
    Exhausted,
    OverCapacity,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PushError<T> {
    Full(T),
    Contended(T),
    Protocol(CursorFault, T),
}

/// Result of a successful producer publication.
///
/// The wake decision is sampled immediately after the entry's Release
/// publication and is therefore bound to the same ring as the reservation.
/// If `should_wake` is true, it must be routed only to that ring instance's
/// wake object; using another ring's event can lose the intended wakeup.
#[must_use = "a successful publication's wake decision must be handled"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PushReceipt {
    pub position: u64,
    pub should_wake: bool,
}

impl<T> fmt::Debug for PushError<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full(_) => formatter.write_str("Full(..)"),
            Self::Contended(_) => formatter.write_str("Contended(..)"),
            Self::Protocol(fault, _) => formatter.debug_tuple("Protocol").field(fault).finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PopError {
    Protocol(CursorFault),
}

mod private {
    pub trait Sealed {}
}

/// Sealed association between a wire entry and its `Copy` body.
pub trait WireEntry: private::Sealed {
    type Body: Copy;

    #[doc(hidden)]
    unsafe fn sequence_ptr(entry: *mut Self) -> *mut u64;

    #[doc(hidden)]
    unsafe fn body_ptr(entry: *mut Self) -> *mut Self::Body;
}

impl private::Sealed for Sqe {}

impl WireEntry for Sqe {
    type Body = SqeBody;

    unsafe fn sequence_ptr(entry: *mut Self) -> *mut u64 {
        // SAFETY: the caller supplies a live aligned `Sqe` pointer.
        unsafe { addr_of_mut!((*entry).sequence) }
    }

    unsafe fn body_ptr(entry: *mut Self) -> *mut Self::Body {
        // SAFETY: the caller supplies a live aligned `Sqe` pointer.
        unsafe { addr_of_mut!((*entry).body) }
    }
}

impl private::Sealed for Cqe {}

impl WireEntry for Cqe {
    type Body = CqeBody;

    unsafe fn sequence_ptr(entry: *mut Self) -> *mut u64 {
        // SAFETY: the caller supplies a live aligned `Cqe` pointer.
        unsafe { addr_of_mut!((*entry).sequence) }
    }

    unsafe fn body_ptr(entry: *mut Self) -> *mut Self::Body {
        // SAFETY: the caller supplies a live aligned `Cqe` pointer.
        unsafe { addr_of_mut!((*entry).body) }
    }
}

/// Statically dispatched reservation instrumentation.
///
/// Normal callers use the zero-sized [`NativeReservation`]. Test policies can
/// deterministically interleave observations or force CAS failure without a
/// function pointer, trait object, allocation, or branch in the monomorphized
/// production path.
/// # Safety
/// None of these callbacks may read or mutate ring entry/wire state, except
/// that `compare_exchange` operates on the supplied `tail`. That method must
/// have the exact observable contract of one
/// `tail.compare_exchange_weak(current, next, Release, Relaxed)` attempt:
///
/// - `Ok(current)` is permitted only after this call atomically changes that
///   tail exactly once from `current` to `next`;
/// - `Err(observed)` leaves the tail unchanged by this call and reports the
///   value witnessed by the failed attempt; a spurious `Err(current)` is
///   permitted; and
/// - no callback may roll back a reservation or make any additional ring/wire
///   mutation.
///
/// Callbacks may block or mutate instrumentation state outside the ring.
pub unsafe trait ReservationHooks {
    #[doc(hidden)]
    #[inline(always)]
    fn after_head_observed(&self, _observed: u64) {}

    #[doc(hidden)]
    #[inline(always)]
    fn after_validated_head_rmw(&self, _previous: u64, _observed: u64) {}

    #[doc(hidden)]
    #[inline(always)]
    fn after_capacity_snapshot(&self, _tail: u64, _validated_head: u64) {}

    #[doc(hidden)]
    fn compare_exchange(&self, tail: &AtomicU64, current: u64, next: u64) -> Result<u64, u64>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NativeReservation;

// SAFETY: delegates directly to the atomic compare-exchange operation.
unsafe impl ReservationHooks for NativeReservation {
    #[inline(always)]
    fn compare_exchange(&self, tail: &AtomicU64, current: u64, next: u64) -> Result<u64, u64> {
        tail.compare_exchange_weak(current, next, Ordering::Release, Ordering::Relaxed)
    }
}

#[inline(always)]
unsafe fn load_read_only_u64_relaxed(field: *const u64) -> u64 {
    // SAFETY: attach contracts require a live, readable, naturally aligned
    // u64 field accessed atomically for the duration of this operation. On the
    // supported x86_64/aarch64 targets, Rust guarantees <= 8-byte Relaxed
    // atomic loads from OS read-only memory. Forming an ephemeral shared
    // AtomicU64 reference requires no write permission; no writable atomic
    // view is requested, and the reference cannot escape or perform store/RMW.
    unsafe { (&*field.cast::<AtomicU64>()).load(Ordering::Relaxed) }
}

#[inline(always)]
unsafe fn load_read_only_u64_acquire(field: *const u64) -> u64 {
    // SAFETY: forwarded from this helper's identical pointer contract.
    let value = unsafe { load_read_only_u64_relaxed(field) };
    // Rust documents Acquire load equivalence as Relaxed load + Acquire fence.
    fence(Ordering::Acquire);
    value
}

#[inline(always)]
unsafe fn store_u64(field: *mut u64, value: u64, order: Ordering) {
    // SAFETY: attach contracts require a live, naturally aligned u64 field;
    // the returned atomic reference is confined to this single operation.
    unsafe { AtomicU64::from_ptr(field) }.store(value, order);
}

#[inline(always)]
unsafe fn compare_exchange_with<H: ReservationHooks>(
    field: *mut u64,
    current: u64,
    next: u64,
    hooks: &H,
) -> Result<u64, u64> {
    // SAFETY: attach contracts require a live, naturally aligned tail field;
    // the atomic view cannot escape this statically dispatched call.
    hooks.compare_exchange(unsafe { AtomicU64::from_ptr(field) }, current, next)
}

#[inline(always)]
unsafe fn load_read_only_u32_relaxed(field: *const u32) -> u32 {
    // SAFETY: attach contracts require a live, readable, naturally aligned
    // u32 field accessed atomically. The ephemeral shared atomic reference is
    // used only for a supported-target Relaxed load and never escapes.
    unsafe { (&*field.cast::<AtomicU32>()).load(Ordering::Relaxed) }
}

#[inline(always)]
unsafe fn store_u32(field: *const u32, value: u32, order: Ordering) {
    // SAFETY: only the consumer-role park view calls this on its owned field.
    unsafe { AtomicU32::from_ptr(field as *mut u32) }.store(value, order);
}

#[inline(always)]
unsafe fn write_body<E: WireEntry>(entry: *mut E, value: E::Body) {
    // SAFETY: reservation gives this producer exclusive access until the
    // following Release sequence store. Volatile is transport I/O, not the
    // synchronization edge.
    unsafe { ptr::write_volatile(E::body_ptr(entry), value) };
}

#[inline(always)]
unsafe fn read_body<E: WireEntry>(entry: *const E) -> E::Body {
    // SAFETY: the exact expected sequence was Acquire-loaded before this read,
    // and capacity/head ownership prevents producer reuse until head advances.
    unsafe { ptr::read_volatile(E::body_ptr(entry as *mut E)) }
}

pub struct MpscProducer<'a, E: WireEntry = Sqe, H: ReservationHooks = NativeReservation> {
    tail: *mut u64,
    remote_head: *const u64,
    entries: *mut E,
    capacity: u64,
    mask: u64,
    validated_head: AtomicU64,
    park: ParkProtocol<'a, ProducerPark>,
    hooks: H,
    _storage: PhantomData<&'a mut [E]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CapacitySnapshot {
    tail: u64,
    validated_head: u64,
}

// SAFETY: sequence publication gives exclusive cell access; the only shared
// local state is atomic and hooks must support the corresponding operation.
unsafe impl<E: WireEntry, H: ReservationHooks + Send> Send for MpscProducer<'_, E, H> where
    E::Body: Send
{
}
unsafe impl<E: WireEntry, H: ReservationHooks + Sync> Sync for MpscProducer<'_, E, H> where
    E::Body: Send
{
}

/// Single-writer producer. It is `Send` but deliberately not `Sync`.
///
/// ```compile_fail
/// use fsring_abi::ring::SpscProducer;
/// fn require_sync<T: Sync>() {}
/// require_sync::<SpscProducer<'static>>();
/// ```
pub struct SpscProducer<'a, E: WireEntry = Cqe> {
    tail_field: *mut u64,
    remote_head: *const u64,
    entries: *mut E,
    capacity: u64,
    mask: u64,
    tail: u64,
    validated_head: u64,
    park: ParkProtocol<'a, ProducerPark>,
    _storage: PhantomData<&'a mut [E]>,
    _single_owner: PhantomData<Cell<()>>,
}

// SAFETY: moving transfers the sole producer capability; `Cell` prevents Sync.
unsafe impl<E: WireEntry> Send for SpscProducer<'_, E> where E::Body: Send {}

/// Sole consumer. It owns `ConsumerPage.head` and `park_state`, never entry
/// storage.
/// It is `Send` but deliberately not `Sync`.
///
/// ```compile_fail
/// use fsring_abi::ring::SingleConsumer;
/// fn require_sync<T: Sync>() {}
/// require_sync::<SingleConsumer<'static>>();
/// ```
pub struct SingleConsumer<'a, E: WireEntry = Sqe> {
    _producer_tail: *const u64,
    head_field: *mut u64,
    entries: *const E,
    mask: u64,
    head: u64,
    park: ParkProtocol<'a, ConsumerPark>,
    _storage: PhantomData<&'a [E]>,
    _single_owner: PhantomData<Cell<()>>,
}

// SAFETY: moving transfers the sole consumer capability; `Cell` prevents Sync.
unsafe impl<E: WireEntry> Send for SingleConsumer<'_, E> where E::Body: Send {}

pub struct ConsumerPark(Cell<()>);
pub struct ProducerPark;

/// Ring-bound park-state capability embedded in producer and consumer handles.
///
/// Its raw constructors and role operations are intentionally private: queue
/// rechecks and wake decisions can be made only through the handle attached to
/// the same `ConsumerPage`.
///
/// ```compile_fail
/// use fsring_abi::{ConsumerPage, ParkProtocol, ProducerPark};
/// let page = core::ptr::null::<ConsumerPage>();
/// let _ = unsafe { ParkProtocol::<ProducerPark>::from_producer_page(page) };
/// ```
pub struct ParkProtocol<'a, Role = ProducerPark> {
    state: *const u32,
    _lifetime: PhantomData<&'a u32>,
    _role: PhantomData<Role>,
}

// SAFETY: moving either role preserves its capability. Only the producer role
// is shareable; `ConsumerPark` contains `Cell` and therefore prevents Sync.
unsafe impl<Role: Send> Send for ParkProtocol<'_, Role> {}
unsafe impl Sync for ParkProtocol<'_, ProducerPark> {}

#[inline]
fn capacity_parts(capacity: usize) -> (u64, u64) {
    debug_assert!(capacity >= 2 && capacity.is_power_of_two());
    debug_assert_eq!(capacity as u64 as usize, capacity);
    (capacity as u64, capacity.saturating_sub(1) as u64)
}

impl<'a> MpscProducer<'a, Sqe, NativeReservation> {
    /// Attach the kernel SQ producer capability to shared wire storage.
    ///
    /// # Safety
    /// - all pointers cover live, naturally aligned Task 3 wire objects for
    ///   `'a`, and `entries` contains `capacity` initialized `Sqe` objects;
    /// - `producer_page`, `consumer_page`, and `entries` are regions of the
    ///   same logical SQ and session epoch for all of `'a`; its returned wake
    ///   decision is routed only to that SQ instance's wake object;
    /// - capacity is a power of two and at least two;
    /// - only this capability family writes `producer_page.tail` and SQ
    ///   entries, while only the remote consumer writes `consumer_page.head`;
    /// - every concurrent access to cursor/sequence fields uses atomics.
    pub unsafe fn attach_sq(
        producer_page: *mut ProducerPage,
        consumer_page: *const ConsumerPage,
        entries: *mut Sqe,
        capacity: usize,
    ) -> Self {
        // SAFETY: forwarded unchanged from this constructor's contract.
        unsafe {
            Self::attach_sq_with_hooks(
                producer_page,
                consumer_page,
                entries,
                capacity,
                NativeReservation,
            )
        }
    }
}

impl<'a, H: ReservationHooks> MpscProducer<'a, Sqe, H> {
    /// Attach an SQ producer with statically dispatched reservation hooks.
    ///
    /// This exists for deterministic model/injection tests. Normal production
    /// calls use [`MpscProducer::attach_sq`] and its zero-sized native policy.
    ///
    /// # Safety
    /// The pointer, capacity, ownership, and atomic-access requirements of
    /// [`MpscProducer::attach_sq`] apply. The hook safety contract also holds.
    pub unsafe fn attach_sq_with_hooks(
        producer_page: *mut ProducerPage,
        consumer_page: *const ConsumerPage,
        entries: *mut Sqe,
        capacity: usize,
        hooks: H,
    ) -> Self {
        let (capacity, mask) = capacity_parts(capacity);
        Self {
            // SAFETY: both page pointers satisfy the attach contract.
            tail: unsafe { addr_of_mut!((*producer_page).tail) },
            // SAFETY: both page pointers satisfy the attach contract.
            remote_head: unsafe { addr_of!((*consumer_page).head) },
            entries,
            capacity,
            mask,
            // No hostile cursor is trusted merely because attachment occurred.
            validated_head: AtomicU64::new(0),
            // SAFETY: the same consumer page satisfies this attach contract.
            park: unsafe { ParkProtocol::from_producer_page(consumer_page) },
            hooks,
            _storage: PhantomData,
        }
    }
}

impl<E: WireEntry, H: ReservationHooks> MpscProducer<'_, E, H> {
    #[inline]
    fn refresh_validated_head(&self) -> Result<(), CursorFault> {
        // Load the local floor before the hostile cursor. A producer that
        // sampled an older head before a concurrent floor publication may
        // still finish safely; the fetch_max return is never called a
        // regression.
        let floor = self.validated_head.load(Ordering::Acquire);
        // SAFETY: attach guarantees an aligned live consumer head field.
        let observed_head = unsafe { load_read_only_u64_acquire(self.remote_head) };
        self.hooks.after_head_observed(observed_head);
        // Loading tail after head prevents a valid newly advanced head from
        // being compared with a producer's stale earlier tail snapshot.
        // SAFETY: attach guarantees an aligned live producer tail field.
        let tail = unsafe { load_read_only_u64_relaxed(self.tail) };

        if observed_head < floor {
            return Err(CursorFault::Regressed);
        }
        if observed_head > tail {
            return Err(CursorFault::AheadOfProducer);
        }
        if observed_head > floor {
            let previous = self
                .validated_head
                .fetch_max(observed_head, Ordering::AcqRel);
            self.hooks.after_validated_head_rmw(previous, observed_head);
        }
        Ok(())
    }

    #[inline]
    fn capacity_snapshot(&self) -> CapacitySnapshot {
        CapacitySnapshot {
            // SAFETY: attach guarantees an aligned live producer tail field.
            tail: unsafe { load_read_only_u64_acquire(self.tail) },
            validated_head: self.validated_head.load(Ordering::Acquire),
        }
    }

    /// Reserve, copy, and Release-publish one producer-owned entry body.
    pub fn try_push(&self, value: E::Body) -> Result<PushReceipt, PushError<E::Body>> {
        for _ in 0..MAX_RESERVE_RETRIES {
            if let Err(fault) = self.refresh_validated_head() {
                return Err(PushError::Protocol(fault, value));
            }

            let first = self.capacity_snapshot();
            if first.tail == u64::MAX {
                return Err(PushError::Protocol(CursorFault::Exhausted, value));
            }
            let Some(distance) = first.tail.checked_sub(first.validated_head) else {
                continue;
            };
            if distance >= self.capacity {
                self.hooks
                    .after_capacity_snapshot(first.tail, first.validated_head);
                if let Err(fault) = self.refresh_validated_head() {
                    return Err(PushError::Protocol(fault, value));
                }
                let second = self.capacity_snapshot();
                let Some(stable_distance) = second.tail.checked_sub(second.validated_head) else {
                    continue;
                };
                if first != second {
                    continue;
                }
                if stable_distance == self.capacity {
                    return Err(PushError::Full(value));
                }
                if stable_distance > self.capacity {
                    return Err(PushError::Protocol(CursorFault::OverCapacity, value));
                }
                continue;
            }
            let Some(next) = first.tail.checked_add(1) else {
                return Err(PushError::Protocol(CursorFault::Exhausted, value));
            };

            // SAFETY: hooks obey their unsafe atomic-reservation contract.
            if unsafe { compare_exchange_with(self.tail, first.tail, next, &self.hooks) }.is_err() {
                continue;
            }

            let index = (first.tail & self.mask) as usize;
            // SAFETY: mask bounds the index and the successful reservation gives
            // exclusive producer access until sequence publication.
            let entry = unsafe { self.entries.add(index) };
            // SAFETY: reservation/capacity protocol owns this entry body.
            unsafe { write_body(entry, value) };
            // SAFETY: sequence is the aligned first u64 in the live entry.
            unsafe { store_u64(E::sequence_ptr(entry), next, Ordering::Release) };
            let should_wake = self.park.should_wake();
            return Ok(PushReceipt {
                position: first.tail,
                should_wake,
            });
        }
        Err(PushError::Contended(value))
    }
}

impl<'a> SpscProducer<'a, Cqe> {
    /// Attach the sole daemon CQ producer capability.
    ///
    /// # Safety
    /// The pointers remain live/aligned for `'a`; entries contains `capacity`
    /// initialized CQEs; `producer_page`, `consumer_page`, and `entries` are
    /// regions of the same logical CQ and session epoch for all of `'a`, and
    /// its returned wake decision is routed only to that CQ instance's wake
    /// object; capacity is a power of two and at least two; this is the only
    /// producer/tail writer; the remote side alone writes head; all cursor and
    /// sequence access is atomic.
    pub unsafe fn attach_cq(
        producer_page: *mut ProducerPage,
        consumer_page: *const ConsumerPage,
        entries: *mut Cqe,
        capacity: usize,
    ) -> Self {
        let (capacity, mask) = capacity_parts(capacity);
        // SAFETY: both page pointers satisfy the attach contract.
        let tail_field = unsafe { addr_of_mut!((*producer_page).tail) };
        // SAFETY: guaranteed by this constructor's contract.
        let tail = unsafe { load_read_only_u64_acquire(tail_field) };
        Self {
            tail_field,
            // SAFETY: both page pointers satisfy the attach contract.
            remote_head: unsafe { addr_of!((*consumer_page).head) },
            entries,
            capacity,
            mask,
            tail,
            validated_head: 0,
            // SAFETY: the same consumer page satisfies this attach contract.
            park: unsafe { ParkProtocol::from_producer_page(consumer_page) },
            _storage: PhantomData,
            _single_owner: PhantomData,
        }
    }
}

impl<E: WireEntry> SpscProducer<'_, E> {
    /// Reserve, copy, and Release-publish from the sole producer.
    pub fn try_push(&mut self, value: E::Body) -> Result<PushReceipt, PushError<E::Body>> {
        let floor = self.validated_head;
        // SAFETY: attach guarantees an aligned live consumer head field.
        let observed_head = unsafe { load_read_only_u64_acquire(self.remote_head) };
        let tail = self.tail;
        if observed_head < floor {
            return Err(PushError::Protocol(CursorFault::Regressed, value));
        }
        if observed_head > tail {
            return Err(PushError::Protocol(CursorFault::AheadOfProducer, value));
        }
        self.validated_head = observed_head;

        if tail == u64::MAX {
            return Err(PushError::Protocol(CursorFault::Exhausted, value));
        }
        let Some(distance) = tail.checked_sub(observed_head) else {
            return Err(PushError::Protocol(CursorFault::AheadOfProducer, value));
        };
        if distance == self.capacity {
            return Err(PushError::Full(value));
        }
        if distance > self.capacity {
            return Err(PushError::Protocol(CursorFault::OverCapacity, value));
        }
        let Some(next) = tail.checked_add(1) else {
            return Err(PushError::Protocol(CursorFault::Exhausted, value));
        };

        // Reserve the producer-owned tail before touching the body. The entry
        // sequence, not tail, is the consumer's publication edge.
        // SAFETY: this is the sole producer and owns the tail field.
        unsafe { store_u64(self.tail_field, next, Ordering::Relaxed) };
        self.tail = next;
        let index = (tail & self.mask) as usize;
        // SAFETY: capacity bounds the entry and sole-producer ownership applies.
        let entry = unsafe { self.entries.add(index) };
        // SAFETY: producer owns body and sequence until Release publication.
        unsafe { write_body(entry, value) };
        // SAFETY: sequence is an aligned live entry field.
        unsafe { store_u64(E::sequence_ptr(entry), next, Ordering::Release) };
        let should_wake = self.park.should_wake();
        Ok(PushReceipt {
            position: tail,
            should_wake,
        })
    }
}

impl<'a, E: WireEntry> SingleConsumer<'a, E> {
    unsafe fn attach_raw(
        producer_page: *const ProducerPage,
        consumer_page: *mut ConsumerPage,
        entries: *const E,
        capacity: usize,
    ) -> Self {
        let (_, mask) = capacity_parts(capacity);
        // SAFETY: both page pointers satisfy the attach contract.
        let head_field = unsafe { addr_of_mut!((*consumer_page).head) };
        // SAFETY: forwarded from the specialized public constructor.
        let head = unsafe { load_read_only_u64_acquire(head_field) };
        Self {
            // SAFETY: both page pointers satisfy the attach contract.
            _producer_tail: unsafe { addr_of!((*producer_page).tail) },
            head_field,
            entries,
            mask,
            head,
            // SAFETY: the same consumer page satisfies this attach contract.
            park: unsafe { ParkProtocol::from_consumer_page(consumer_page) },
            _storage: PhantomData,
            _single_owner: PhantomData,
        }
    }

    /// Return whether the next exact sequence is ready without changing head.
    pub fn has_item(&self) -> Result<bool, PopError> {
        let Some(expected) = self.head.checked_add(1) else {
            return Err(PopError::Protocol(CursorFault::Exhausted));
        };
        let index = (self.head & self.mask) as usize;
        // SAFETY: mask bounds the live entry array from attach.
        let entry = unsafe { self.entries.add(index) };
        // SAFETY: sequence is an aligned live entry u64 field; no entry
        // reference is formed.
        let sequence = unsafe { load_read_only_u64_acquire(E::sequence_ptr(entry as *mut E)) };
        if sequence == expected {
            Ok(true)
        } else if sequence < expected {
            Ok(false)
        } else {
            Err(PopError::Protocol(CursorFault::FutureSequence))
        }
    }

    /// Mark this ring's consumer active.
    pub fn set_active(&mut self) {
        self.park.set_active();
    }

    /// Mark this ring's consumer as polling.
    pub fn set_polling(&mut self) {
        self.park.set_polling();
    }

    /// Declare this ring's consumer parked and recheck this ring's exact next
    /// sequence before reporting that sleep is safe. `true` means no work is
    /// ready; visible work or a protocol fault restores `ACTIVE` first.
    pub fn declare_park(&mut self) -> Result<bool, PopError> {
        self.park.declare();
        match self.has_item() {
            Ok(false) => Ok(true),
            Ok(true) => {
                self.park.set_active();
                Ok(false)
            }
            Err(error) => {
                self.park.set_active();
                Err(error)
            }
        }
    }

    /// Acquire the exact next sequence, volatile-copy its body, and advance
    /// only the consumer-owned head page.
    pub fn try_pop(&mut self) -> Result<Option<E::Body>, PopError> {
        let Some(next) = self.head.checked_add(1) else {
            return Err(PopError::Protocol(CursorFault::Exhausted));
        };
        let index = (self.head & self.mask) as usize;
        // SAFETY: mask bounds the live entry array from attach.
        let entry = unsafe { self.entries.add(index) };
        // SAFETY: sequence is an aligned live entry u64 field.
        let sequence = unsafe { load_read_only_u64_acquire(E::sequence_ptr(entry as *mut E)) };
        if sequence < next {
            return Ok(None);
        }
        if sequence > next {
            return Err(PopError::Protocol(CursorFault::FutureSequence));
        }

        // SAFETY: exact Acquire sequence publication makes the Copy body ready;
        // the producer cannot reuse this cell before the Release head store.
        let body = unsafe { read_body(entry) };
        // SAFETY: this sole consumer owns the aligned head field.
        unsafe { store_u64(self.head_field, next, Ordering::Release) };
        self.head = next;
        Ok(Some(body))
    }
}

impl<'a> SingleConsumer<'a, Sqe> {
    /// Attach the sole daemon SQ consumer. The returned handle has no mutable
    /// producer-page or entry pointer and therefore cannot write either.
    ///
    /// # Safety
    /// Pointers remain live/aligned for `'a`; entries contains `capacity`
    /// initialized SQEs; `producer_page`, `consumer_page`, and `entries` are
    /// regions of the same logical SQ and session epoch for all of `'a`;
    /// capacity is a power of two and at least two; this is the only head
    /// writer; producer-side fields are written only atomically.
    pub unsafe fn attach_sq(
        producer_page: *const ProducerPage,
        consumer_page: *mut ConsumerPage,
        entries: *const Sqe,
        capacity: usize,
    ) -> Self {
        // SAFETY: forwarded unchanged from this constructor's contract.
        unsafe { Self::attach_raw(producer_page, consumer_page, entries, capacity) }
    }
}

impl<'a> SingleConsumer<'a, Cqe> {
    /// Attach the sole kernel CQ drain consumer. It can write only CQ head.
    ///
    /// # Safety
    /// The same logical-ring/session, storage, capacity, sole-consumer,
    /// lifetime, alignment, and atomic-access conditions as
    /// [`SingleConsumer::attach_sq`] apply to CQEs.
    pub unsafe fn attach_cq(
        producer_page: *const ProducerPage,
        consumer_page: *mut ConsumerPage,
        entries: *const Cqe,
        capacity: usize,
    ) -> Self {
        // SAFETY: forwarded unchanged from this constructor's contract.
        unsafe { Self::attach_raw(producer_page, consumer_page, entries, capacity) }
    }
}

impl<'a> ParkProtocol<'a, ConsumerPark> {
    unsafe fn from_consumer_page(consumer_page: *mut ConsumerPage) -> Self {
        Self {
            // SAFETY: the page pointer satisfies the attach contract.
            state: unsafe { addr_of!((*consumer_page).park_state) },
            _lifetime: PhantomData,
            _role: PhantomData,
        }
    }

    fn set_active(&mut self) {
        // SAFETY: the consumer role owns this state field.
        unsafe { store_u32(self.state, PARK_STATE_ACTIVE, Ordering::Relaxed) };
    }

    fn set_polling(&mut self) {
        // SAFETY: the consumer role owns this state field.
        unsafe { store_u32(self.state, PARK_STATE_POLLING, Ordering::Relaxed) };
    }

    fn declare(&mut self) {
        // SAFETY: the consumer role alone writes park state.
        unsafe { store_u32(self.state, PARK_STATE_PARKED, Ordering::SeqCst) };
        fence(Ordering::SeqCst);
    }
}

impl<'a> ParkProtocol<'a, ProducerPark> {
    unsafe fn from_producer_page(consumer_page: *const ConsumerPage) -> Self {
        Self {
            // SAFETY: the page pointer satisfies the attach contract.
            state: unsafe { addr_of!((*consumer_page).park_state) },
            _lifetime: PhantomData,
            _role: PhantomData,
        }
    }

    /// Called immediately after publication. The SeqCst fence pairs with the
    /// consumer's declaration/recheck sequence; the producer only reads remote
    /// state.
    fn should_wake(&self) -> bool {
        fence(Ordering::SeqCst);
        // SAFETY: attach guarantees an aligned live atomic park field.
        (unsafe { load_read_only_u32_relaxed(self.state) }) == PARK_STATE_PARKED
    }
}

#[cfg(test)]
mod load_only_tests {
    use super::{load_read_only_u32_relaxed, load_read_only_u64_acquire};

    #[test]
    fn load_only_helpers_read_values_without_requesting_a_writable_atomic_view() {
        let value64 = 0x1122_3344_5566_7788u64;
        let value32 = 0x99aa_bbccu32;

        // SAFETY: both pointers are live and naturally aligned for this call.
        assert_eq!(unsafe { load_read_only_u64_acquire(&value64) }, value64);
        // SAFETY: both pointers are live and naturally aligned for this call.
        assert_eq!(unsafe { load_read_only_u32_relaxed(&value32) }, value32);
    }
}

// ---------------------------------------------------------------------------
// R5 Task 20 (abi half): the deferred CQ pop
// ---------------------------------------------------------------------------
//
// `try_pop` reads the body and stores the new head in one call. That is correct
// for a consumer that always keeps what it read — but a CQ drain has to decide
// *after* seeing the body whether it can account for the entry, and once the
// head has moved the producer may reuse the cell. A drain that read, failed to
// account, and then tried to un-advance would be reading a cell the producer
// already owns again.
//
// The deferred pop splits the two: `try_peek` reads the body and holds the
// consumer borrowed at the *unadvanced* head; `commit` performs the Release
// store and mints the receipt. Dropping the `PendingPop` without committing
// leaves the head exactly where it was, which is the whole point.

macro_rules! private_authority_seals {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Debug)]
            struct $name(());
        )+
    };
}

private_authority_seals!(PrivateHeadAdvanceReceipt);

/// One entry read but not yet accounted for.
///
/// It borrows the consumer mutably for its whole life, so nothing else can pop,
/// peek, or advance while a decision is outstanding.
#[must_use]
pub struct PendingPop<'consumer, 'storage, E: WireEntry> {
    consumer: &'consumer mut SingleConsumer<'storage, E>,
    body: E::Body,
    sequence: u64,
    next_head: u64,
}

/// Proof that exactly one head advance happened, for exactly one sequence.
#[must_use]
pub struct HeadAdvanceReceipt<E: WireEntry> {
    sequence: u64,
    next_head: u64,
    // Never read: the seal exists so no caller outside this module can build a
    // receipt claiming a head advance that did not happen.
    #[allow(dead_code)]
    private: PrivateHeadAdvanceReceipt,
    marker: PhantomData<E>,
}

/// A committed pop: the body, and the receipt that says the head moved.
#[must_use]
pub struct CommittedPop<E: WireEntry> {
    body: E::Body,
    receipt: HeadAdvanceReceipt<E>,
}

impl<E: WireEntry> HeadAdvanceReceipt<E> {
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn next_head(&self) -> u64 {
        self.next_head
    }
}

impl<E: WireEntry> CommittedPop<E> {
    pub const fn body(&self) -> E::Body
    where
        E::Body: Copy,
    {
        self.body
    }

    pub fn into_parts(self) -> (E::Body, HeadAdvanceReceipt<E>) {
        let Self { body, receipt } = self;
        (body, receipt)
    }
}

impl<'consumer, 'storage, E: WireEntry> PendingPop<'consumer, 'storage, E> {
    /// The body, readable before the decision to keep it.
    pub const fn body(&self) -> E::Body
    where
        E::Body: Copy,
    {
        self.body
    }

    /// The sequence this entry carries.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The head this pop would store, readable before the decision to store it.
    ///
    /// A caller that must record what it is about to commit -- a driver holding
    /// a lock it will drop before the store, say -- needs the value up front.
    /// Recomputing it as `head + 1` at the call site would be a second, and
    /// therefore forgeable, source of the same number.
    pub const fn next_head(&self) -> u64 {
        self.next_head
    }

    /// Accept the entry: advance the head and mint the receipt.
    pub fn commit(self) -> CommittedPop<E> {
        let Self {
            consumer,
            body,
            sequence,
            next_head,
        } = self;
        // SAFETY: this sole consumer owns the aligned head field, and
        // `next_head` is the exact successor `try_peek` validated.
        unsafe { store_u64(consumer.head_field, next_head, Ordering::Release) };
        consumer.head = next_head;
        CommittedPop {
            body,
            receipt: HeadAdvanceReceipt {
                sequence,
                next_head,
                private: PrivateHeadAdvanceReceipt(()),
                marker: PhantomData,
            },
        }
    }

    /// Decline the entry: the head does not move.
    ///
    /// Explicit rather than relying on the drop, so a drain that cannot account
    /// for an entry says so at the call site.
    pub fn release(self) {}
}

impl<'storage, E: WireEntry> SingleConsumer<'storage, E> {
    /// Read the next entry without advancing the head.
    ///
    /// The consumer stays borrowed until the returned pop is committed or
    /// released, so the head cannot move underneath a decision in flight.
    pub fn try_peek(&mut self) -> Result<Option<PendingPop<'_, 'storage, E>>, PopError> {
        let Some(next) = self.head.checked_add(1) else {
            return Err(PopError::Protocol(CursorFault::Exhausted));
        };
        let index = (self.head & self.mask) as usize;
        // SAFETY: mask bounds the live entry array from attach.
        let entry = unsafe { self.entries.add(index) };
        // SAFETY: sequence is an aligned live entry u64 field.
        let sequence = unsafe { load_read_only_u64_acquire(E::sequence_ptr(entry as *mut E)) };
        if sequence < next {
            return Ok(None);
        }
        if sequence > next {
            return Err(PopError::Protocol(CursorFault::FutureSequence));
        }
        // SAFETY: exact Acquire sequence publication makes the Copy body ready;
        // the producer cannot reuse this cell before the Release head store,
        // which `commit` is the only thing that performs.
        let body = unsafe { read_body(entry) };
        Ok(Some(PendingPop {
            consumer: self,
            body,
            sequence,
            next_head: next,
        }))
    }
}
