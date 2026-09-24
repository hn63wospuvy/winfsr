use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use fsring_abi::ring::{
    CursorFault, MpscProducer, NativeReservation, PopError, PushError, ReservationHooks,
    SingleConsumer, SpscProducer, MAX_RESERVE_RETRIES,
};
use fsring_abi::{
    ConsumerPage, Cqe, CqeBody, ProducerPage, Sqe, SqeBody, PARK_STATE_ACTIVE, PARK_STATE_PARKED,
    PARK_STATE_POLLING,
};
use std::sync::Barrier;

const CAPACITY: usize = 4;

#[test]
fn park_state_wire_values_are_pinned() {
    assert_eq!(PARK_STATE_ACTIVE, 0);
    assert_eq!(PARK_STATE_POLLING, 1);
    assert_eq!(PARK_STATE_PARKED, 2);
}

#[test]
fn read_only_load_helpers_never_use_atomic_from_ptr() {
    let source = include_str!("../src/ring.rs");
    let u64_load = source
        .split("unsafe fn load_read_only_u64_relaxed")
        .nth(1)
        .and_then(|tail| tail.split("unsafe fn load_read_only_u64_acquire").next())
        .expect("load-only u64 helper must exist");
    let u32_load = source
        .split("unsafe fn load_read_only_u32_relaxed")
        .nth(1)
        .and_then(|tail| tail.split("unsafe fn store_u32").next())
        .expect("load-only u32 helper must exist");

    assert!(!u64_load.contains("from_ptr"));
    assert!(!u32_load.contains("from_ptr"));
}

#[test]
fn msrv_covers_read_only_atomic_guarantee_and_windows_test_syntax() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        manifest.contains("rust-version = \"1.82\""),
        "MSRV must cover the read-only atomic guarantee and `unsafe extern`"
    );
}

#[test]
fn reserve_retry_limit_is_exactly_sixty_four() {
    assert_eq!(MAX_RESERVE_RETRIES, 64);
}

fn producer_page(tail: u64) -> Box<ProducerPage> {
    Box::new(ProducerPage {
        tail,
        wake_sequence: 0,
        flags: 0,
        reserved0: [0; 4],
        reserved: [0; 4072],
    })
}

fn consumer_page(head: u64) -> Box<ConsumerPage> {
    Box::new(ConsumerPage {
        head,
        park_state: 0,
        flags: 0,
        heartbeat: 0,
        reserved: [0; 4072],
    })
}

fn body(value: u64) -> SqeBody {
    SqeBody {
        opcode: 0,
        flags: 0,
        payload_len: 0,
        reserved: 0,
        req_id: value,
        kernel_open_id: 0,
        ccb_sequence: 0,
        payload: [0; 88],
    }
}

fn entries() -> Box<[Sqe; CAPACITY]> {
    Box::new(
        [Sqe {
            sequence: 0,
            body: body(0),
        }; CAPACITY],
    )
}

fn cqe_body(value: u64) -> CqeBody {
    CqeBody {
        kind: 0,
        opcode: 0,
        flags: 0,
        out_len: 0,
        req_id: value,
        status: 0,
        reserved: 0,
        information: 0,
        out: [0; 24],
    }
}

fn cqe_entries() -> Box<[Cqe; CAPACITY]> {
    Box::new(
        [Cqe {
            sequence: 0,
            body: cqe_body(0),
        }; CAPACITY],
    )
}

unsafe fn atomic_store_u64(field: *mut u64, value: u64) {
    // SAFETY: callers pass an aligned live u64 wire field and use atomic access
    // for the duration of concurrent attachment.
    unsafe { AtomicU64::from_ptr(field).store(value, Ordering::Release) };
}

#[test]
fn capacity_four_is_fifo_and_reports_full() {
    let mut producer_page = producer_page(0);
    let mut consumer_page = consumer_page(0);
    let mut entries = entries();

    let producer = unsafe {
        MpscProducer::attach_sq(
            addr_of_mut!(*producer_page),
            addr_of!(*consumer_page),
            entries.as_mut_ptr(),
            CAPACITY,
        )
    };
    let mut consumer = unsafe {
        SingleConsumer::attach_sq(
            addr_of!(*producer_page),
            addr_of_mut!(*consumer_page),
            entries.as_ptr(),
            CAPACITY,
        )
    };

    assert!(consumer.try_pop().unwrap().is_none());
    for value in 10..14 {
        assert_eq!(producer.try_push(body(value)).unwrap().position, value - 10);
    }
    match producer.try_push(body(99)) {
        Err(PushError::Full(returned)) => assert_eq!(returned.req_id, 99),
        _ => panic!("expected Full"),
    }
    for expected in 10..14 {
        assert_eq!(consumer.try_pop().unwrap().unwrap().req_id, expected);
    }
    assert!(consumer.try_pop().unwrap().is_none());
}

#[test]
fn hostile_remote_head_ahead_and_regression_are_distinct() {
    let mut producer_page = producer_page(0);
    let mut consumer_page = consumer_page(0);
    let mut entries = entries();
    let consumer_page_ptr = addr_of_mut!(*consumer_page);

    let producer = unsafe {
        MpscProducer::attach_sq(
            addr_of_mut!(*producer_page),
            consumer_page_ptr,
            entries.as_mut_ptr(),
            CAPACITY,
        )
    };
    let mut consumer = unsafe {
        SingleConsumer::attach_sq(
            addr_of!(*producer_page),
            consumer_page_ptr,
            entries.as_ptr(),
            CAPACITY,
        )
    };

    assert_eq!(producer.try_push(body(10)).unwrap().position, 0);
    assert_eq!(consumer.try_pop().unwrap().unwrap().req_id, 10);
    assert_eq!(producer.try_push(body(11)).unwrap().position, 1);
    assert_eq!(consumer.try_pop().unwrap().unwrap().req_id, 11);

    unsafe { atomic_store_u64(addr_of_mut!((*consumer_page_ptr).head), 3) };
    match producer.try_push(body(12)) {
        Err(PushError::Protocol(CursorFault::AheadOfProducer, returned)) => {
            assert_eq!(returned.req_id, 12)
        }
        _ => panic!("expected AheadOfProducer"),
    }

    // The rejected ahead value must not poison the validated-head shadow.
    unsafe { atomic_store_u64(addr_of_mut!((*consumer_page_ptr).head), 2) };
    assert_eq!(producer.try_push(body(12)).unwrap().position, 2);

    unsafe { atomic_store_u64(addr_of_mut!((*consumer_page_ptr).head), 0) };
    match producer.try_push(body(13)) {
        Err(PushError::Protocol(CursorFault::Regressed, returned)) => {
            assert_eq!(returned.req_id, 13)
        }
        _ => panic!("expected Regressed"),
    }
}

#[test]
fn u64_tail_exhaustion_is_reported_without_wrap() {
    let mut producer_page = producer_page(u64::MAX);
    let consumer_page = consumer_page(u64::MAX);
    let mut entries = entries();

    let producer = unsafe {
        MpscProducer::attach_sq(
            addr_of_mut!(*producer_page),
            addr_of!(*consumer_page),
            entries.as_mut_ptr(),
            CAPACITY,
        )
    };
    match producer.try_push(body(77)) {
        Err(PushError::Protocol(CursorFault::Exhausted, returned)) => {
            assert_eq!(returned.req_id, 77)
        }
        _ => panic!("expected Exhausted"),
    }
    assert_eq!(producer_page.tail, u64::MAX);
}

#[test]
fn future_cell_sequence_is_a_protocol_fault() {
    let producer_page = producer_page(0);
    let mut consumer_page = consumer_page(0);
    let mut entries = entries();
    entries[0].sequence = 2;

    let mut consumer = unsafe {
        SingleConsumer::attach_sq(
            addr_of!(*producer_page),
            addr_of_mut!(*consumer_page),
            entries.as_ptr(),
            CAPACITY,
        )
    };
    assert!(matches!(
        consumer.try_pop(),
        Err(PopError::Protocol(CursorFault::FutureSequence))
    ));
    assert_eq!(consumer_page.head, 0);
}

#[test]
fn cq_spsc_uses_the_same_publication_and_capacity_rules() {
    let mut producer_page = producer_page(0);
    let mut consumer_page = consumer_page(0);
    let mut entries = cqe_entries();

    let mut producer = unsafe {
        SpscProducer::attach_cq(
            addr_of_mut!(*producer_page),
            addr_of!(*consumer_page),
            entries.as_mut_ptr(),
            CAPACITY,
        )
    };
    let mut consumer = unsafe {
        SingleConsumer::attach_cq(
            addr_of!(*producer_page),
            addr_of_mut!(*consumer_page),
            entries.as_ptr(),
            CAPACITY,
        )
    };

    assert!(consumer.try_pop().unwrap().is_none());
    for value in 20..24 {
        assert_eq!(
            producer.try_push(cqe_body(value)).unwrap().position,
            value - 20
        );
    }
    match producer.try_push(cqe_body(99)) {
        Err(PushError::Full(returned)) => assert_eq!(returned.req_id, 99),
        _ => panic!("expected Full"),
    }
    for expected in 20..24 {
        assert_eq!(consumer.try_pop().unwrap().unwrap().req_id, expected);
    }
    assert!(consumer.try_pop().unwrap().is_none());
}

#[test]
fn bound_park_declaration_rechecks_its_queue_and_push_returns_wake_receipt() {
    let mut producer_page = producer_page(0);
    let mut consumer_page = consumer_page(0);
    let mut entries = entries();
    let consumer_page_ptr = addr_of_mut!(*consumer_page);
    let producer = unsafe {
        MpscProducer::attach_sq(
            addr_of_mut!(*producer_page),
            consumer_page_ptr,
            entries.as_mut_ptr(),
            CAPACITY,
        )
    };
    let mut consumer = unsafe {
        SingleConsumer::attach_sq(
            addr_of!(*producer_page),
            consumer_page_ptr,
            entries.as_ptr(),
            CAPACITY,
        )
    };
    consumer.set_polling();
    assert!(consumer.declare_park().unwrap());

    let receipt = producer.try_push(body(55)).unwrap();
    assert_eq!(receipt.position, 0);
    assert!(receipt.should_wake);

    consumer.set_polling();
    assert!(!consumer.declare_park().unwrap());
}

#[test]
fn two_rings_cannot_cross_pair_park_state_or_queue_recheck() {
    let mut producer_page_a = producer_page(0);
    let mut consumer_page_a = consumer_page(0);
    let mut entries_a = entries();
    let mut producer_page_b = producer_page(0);
    let mut consumer_page_b = consumer_page(0);
    let mut entries_b = entries();

    let producer_a = unsafe {
        MpscProducer::attach_sq(
            addr_of_mut!(*producer_page_a),
            addr_of!(*consumer_page_a),
            entries_a.as_mut_ptr(),
            CAPACITY,
        )
    };
    let producer_b = unsafe {
        MpscProducer::attach_sq(
            addr_of_mut!(*producer_page_b),
            addr_of!(*consumer_page_b),
            entries_b.as_mut_ptr(),
            CAPACITY,
        )
    };
    let mut consumer_a = unsafe {
        SingleConsumer::attach_sq(
            addr_of!(*producer_page_a),
            addr_of_mut!(*consumer_page_a),
            entries_a.as_ptr(),
            CAPACITY,
        )
    };
    let mut consumer_b = unsafe {
        SingleConsumer::attach_sq(
            addr_of!(*producer_page_b),
            addr_of_mut!(*consumer_page_b),
            entries_b.as_ptr(),
            CAPACITY,
        )
    };

    consumer_a.set_active();
    consumer_b.set_polling();
    assert!(consumer_b.declare_park().unwrap());

    let receipt_a = producer_a.try_push(body(70)).unwrap();
    assert!(
        !receipt_a.should_wake,
        "ring A must not observe ring B park"
    );
    let receipt_b = producer_b.try_push(body(80)).unwrap();
    assert!(receipt_b.should_wake, "ring B must observe its own park");

    consumer_a.set_polling();
    assert!(!consumer_a.declare_park().unwrap());
    assert!(!consumer_b.declare_park().unwrap());
    assert_eq!(consumer_a.try_pop().unwrap().unwrap().req_id, 70);
    assert_eq!(consumer_b.try_pop().unwrap().unwrap().req_id, 80);
}

struct AlwaysContended<'a> {
    attempts: &'a AtomicUsize,
}

// SAFETY: this hook touches only external instrumentation. It reports only a
// permitted spurious `Err(current)` and never mutates the supplied tail.
unsafe impl ReservationHooks for AlwaysContended<'_> {
    fn compare_exchange(&self, _tail: &AtomicU64, current: u64, _next: u64) -> Result<u64, u64> {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        Err(current)
    }
}

#[test]
fn reservation_contention_is_exactly_bounded() {
    let mut producer_page = producer_page(0);
    let consumer_page = consumer_page(0);
    let mut entries = entries();
    let attempts = AtomicUsize::new(0);

    let producer = unsafe {
        MpscProducer::attach_sq_with_hooks(
            addr_of_mut!(*producer_page),
            addr_of!(*consumer_page),
            entries.as_mut_ptr(),
            CAPACITY,
            AlwaysContended {
                attempts: &attempts,
            },
        )
    };
    match producer.try_push(body(31)) {
        Err(PushError::Contended(returned)) => assert_eq!(returned.req_id, 31),
        _ => panic!("expected Contended"),
    }
    assert_eq!(attempts.load(Ordering::Relaxed), MAX_RESERVE_RETRIES);
    assert_eq!(producer_page.tail, 0);
    assert_eq!(entries[0].sequence, 0);
    assert_eq!(core::mem::size_of::<NativeReservation>(), 0);
}

struct StaleObservationHooks<'a> {
    sampled_old_head: &'a Barrier,
    release_old_observer: &'a Barrier,
    blocked: &'a AtomicUsize,
}

// SAFETY: observation touches only external synchronization state. Reservation
// results come exactly from the supplied tail's one Release/Relaxed weak CAS
// attempt.
unsafe impl ReservationHooks for StaleObservationHooks<'_> {
    fn after_head_observed(&self, observed: u64) {
        if observed == 0 && self.blocked.fetch_add(1, Ordering::Relaxed) == 0 {
            self.sampled_old_head.wait();
            self.release_old_observer.wait();
        }
    }

    fn compare_exchange(&self, tail: &AtomicU64, current: u64, next: u64) -> Result<u64, u64> {
        tail.compare_exchange_weak(current, next, Ordering::Release, Ordering::Relaxed)
    }
}

struct ShadowAdvanceHooks<'a> {
    advances: &'a AtomicUsize,
}

// SAFETY: observation touches only external instrumentation. Reservation
// results come exactly from the supplied tail's one Release/Relaxed weak CAS
// attempt.
unsafe impl ReservationHooks for ShadowAdvanceHooks<'_> {
    fn after_validated_head_rmw(&self, _previous: u64, _observed: u64) {
        self.advances.fetch_add(1, Ordering::Relaxed);
    }

    fn compare_exchange(&self, tail: &AtomicU64, current: u64, next: u64) -> Result<u64, u64> {
        tail.compare_exchange_weak(current, next, Ordering::Release, Ordering::Relaxed)
    }
}

#[test]
fn equal_validated_head_avoids_shadow_rmw() {
    let mut producer_page = producer_page(0);
    let mut consumer_page = consumer_page(0);
    let mut entries = entries();
    let consumer_page_ptr = addr_of_mut!(*consumer_page);
    let advances = AtomicUsize::new(0);
    let producer = unsafe {
        MpscProducer::attach_sq_with_hooks(
            addr_of_mut!(*producer_page),
            consumer_page_ptr,
            entries.as_mut_ptr(),
            CAPACITY,
            ShadowAdvanceHooks {
                advances: &advances,
            },
        )
    };

    assert_eq!(producer.try_push(body(60)).unwrap().position, 0);
    assert_eq!(advances.load(Ordering::Relaxed), 0);

    unsafe { atomic_store_u64(addr_of_mut!((*consumer_page_ptr).head), 1) };
    assert_eq!(producer.try_push(body(61)).unwrap().position, 1);
    assert_eq!(advances.load(Ordering::Relaxed), 1);

    assert_eq!(producer.try_push(body(62)).unwrap().position, 2);
    assert_eq!(advances.load(Ordering::Relaxed), 1);
}

#[test]
fn concurrent_stale_valid_head_sample_is_not_a_false_regression() {
    let mut producer_page = producer_page(1);
    let mut consumer_page = consumer_page(0);
    let mut entries = entries();
    let consumer_page_ptr = addr_of_mut!(*consumer_page);
    let sampled_old_head = Barrier::new(2);
    let release_old_observer = Barrier::new(2);
    let blocked = AtomicUsize::new(0);

    let producer = unsafe {
        MpscProducer::attach_sq_with_hooks(
            addr_of_mut!(*producer_page),
            consumer_page_ptr,
            entries.as_mut_ptr(),
            CAPACITY,
            StaleObservationHooks {
                sampled_old_head: &sampled_old_head,
                release_old_observer: &release_old_observer,
                blocked: &blocked,
            },
        )
    };

    std::thread::scope(|scope| {
        let old_observer = scope.spawn(|| producer.try_push(body(41)).unwrap().position);
        sampled_old_head.wait();

        unsafe { atomic_store_u64(addr_of_mut!((*consumer_page_ptr).head), 1) };
        let new_observer = scope.spawn(|| producer.try_push(body(42)).unwrap().position);
        assert_eq!(new_observer.join().unwrap(), 1);

        release_old_observer.wait();
        assert_eq!(old_observer.join().unwrap(), 2);
    });

    assert_eq!(producer_page.tail, 3);
}

#[test]
fn stable_mpsc_over_capacity_is_a_protocol_fault_without_mutation() {
    let mut producer_page = producer_page(5);
    let consumer_page = consumer_page(0);
    let mut entries = entries();
    let producer = unsafe {
        MpscProducer::attach_sq(
            addr_of_mut!(*producer_page),
            addr_of!(*consumer_page),
            entries.as_mut_ptr(),
            CAPACITY,
        )
    };

    match producer.try_push(body(0x5152)) {
        Err(PushError::Protocol(CursorFault::OverCapacity, returned)) => {
            assert_eq!(returned.req_id, 0x5152)
        }
        other => panic!("expected stable OverCapacity, got {other:?}"),
    }
    assert_eq!(producer_page.tail, 5);
    assert!(entries
        .iter()
        .all(|entry| entry.sequence == 0 && entry.body.req_id == 0));
}

#[test]
fn stable_spsc_over_capacity_is_a_protocol_fault_without_mutation() {
    let mut producer_page = producer_page(5);
    let consumer_page = consumer_page(0);
    let mut entries = cqe_entries();
    let mut producer = unsafe {
        SpscProducer::attach_cq(
            addr_of_mut!(*producer_page),
            addr_of!(*consumer_page),
            entries.as_mut_ptr(),
            CAPACITY,
        )
    };

    match producer.try_push(cqe_body(0x6162)) {
        Err(PushError::Protocol(CursorFault::OverCapacity, returned)) => {
            assert_eq!(returned.req_id, 0x6162)
        }
        other => panic!("expected stable OverCapacity, got {other:?}"),
    }
    assert_eq!(producer_page.tail, 5);
    assert!(entries
        .iter()
        .all(|entry| entry.sequence == 0 && entry.body.req_id == 0));
}

#[test]
fn native_reservation_uses_release_success_and_relaxed_failure() {
    let source = include_str!("../src/ring.rs");
    let native = source
        .split("unsafe impl ReservationHooks for NativeReservation")
        .nth(1)
        .and_then(|tail| tail.split("unsafe fn load_read_only_u64_relaxed").next())
        .expect("native reservation implementation");
    assert!(native
        .contains("compare_exchange_weak(current, next, Ordering::Release, Ordering::Relaxed)"));
}

#[test]
fn capacity_snapshot_acquires_tail_before_validated_head() {
    let source = include_str!("../src/ring.rs");
    let helper = source
        .split("fn capacity_snapshot(&self) -> CapacitySnapshot")
        .nth(1)
        .and_then(|tail| tail.split("/// Reserve, copy").next())
        .expect("capacity snapshot helper");
    let tail_load = helper
        .find("tail: unsafe { load_read_only_u64_acquire(self.tail) }")
        .expect("Acquire tail load");
    let head_load = helper
        .find("validated_head: self.validated_head.load(Ordering::Acquire)")
        .expect("Acquire validated-head load");
    assert!(tail_load < head_load, "tail must be Acquire-loaded first");
}

struct CapacitySnapshotHooks<'a> {
    requested: &'a Barrier,
    completed: &'a Barrier,
    snapshots: &'a AtomicUsize,
}

// SAFETY: the callback touches only barriers/counters. A separate consumer
// owner writes remote head; the CAS has the exact Release/Relaxed contract.
unsafe impl ReservationHooks for CapacitySnapshotHooks<'_> {
    fn after_capacity_snapshot(&self, _tail: u64, _validated_head: u64) {
        self.snapshots.fetch_add(1, Ordering::Relaxed);
        self.requested.wait();
        self.completed.wait();
    }

    fn compare_exchange(&self, tail: &AtomicU64, current: u64, next: u64) -> Result<u64, u64> {
        tail.compare_exchange_weak(current, next, Ordering::Release, Ordering::Relaxed)
    }
}

fn push_after_one_capacity_snapshot_progress(
    initial_tail: u64,
    advanced_head: u64,
    request_id: u64,
) -> (u64, Box<ProducerPage>, Box<[Sqe; CAPACITY]>, usize) {
    let mut producer_page = producer_page(initial_tail);
    let mut consumer_page = consumer_page(0);
    let mut entries = entries();
    let consumer_page_ptr = addr_of_mut!(*consumer_page);
    let remote_head = addr_of_mut!(consumer_page.head) as usize;
    let requested = Barrier::new(2);
    let completed = Barrier::new(2);
    let snapshots = AtomicUsize::new(0);
    let producer = unsafe {
        MpscProducer::attach_sq_with_hooks(
            addr_of_mut!(*producer_page),
            consumer_page_ptr,
            entries.as_mut_ptr(),
            CAPACITY,
            CapacitySnapshotHooks {
                requested: &requested,
                completed: &completed,
                snapshots: &snapshots,
            },
        )
    };

    let position = std::thread::scope(|scope| {
        let requested = &requested;
        let completed = &completed;
        let consumer_owner = scope.spawn(move || {
            requested.wait();
            unsafe { atomic_store_u64(remote_head as *mut u64, advanced_head) };
            completed.wait();
        });
        let receipt = producer
            .try_push(body(request_id))
            .expect("capacity progress must force a retry");
        consumer_owner.join().unwrap();
        receipt.position
    });

    (
        position,
        producer_page,
        entries,
        snapshots.load(Ordering::Relaxed),
    )
}

#[test]
fn remote_head_progress_between_over_capacity_snapshots_prevents_false_fault() {
    let (position, producer_page, entries, snapshots) =
        push_after_one_capacity_snapshot_progress(5, 2, 0x7172);
    assert_eq!(position, 5);
    assert_eq!(snapshots, 1);
    assert_eq!(producer_page.tail, 6);
    assert_eq!(entries[1].sequence, 6);
    assert_eq!(entries[1].body.req_id, 0x7172);
}

#[test]
fn remote_head_progress_between_full_snapshots_prevents_stale_full() {
    let (position, producer_page, entries, snapshots) =
        push_after_one_capacity_snapshot_progress(4, 1, 0x7374);
    assert_eq!(position, 4);
    assert_eq!(snapshots, 1);
    assert_eq!(producer_page.tail, 5);
    assert_eq!(entries[0].sequence, 5);
    assert_eq!(entries[0].body.req_id, 0x7374);
}

#[test]
fn sixty_four_changing_snapshot_pairs_return_contended_without_mutation() {
    let mut producer_page = producer_page(69);
    let mut consumer_page = consumer_page(0);
    let mut entries = entries();
    let consumer_page_ptr = addr_of_mut!(*consumer_page);
    let remote_head = addr_of_mut!(consumer_page.head) as usize;
    let requested = Barrier::new(2);
    let completed = Barrier::new(2);
    let snapshots = AtomicUsize::new(0);
    let producer = unsafe {
        MpscProducer::attach_sq_with_hooks(
            addr_of_mut!(*producer_page),
            consumer_page_ptr,
            entries.as_mut_ptr(),
            CAPACITY,
            CapacitySnapshotHooks {
                requested: &requested,
                completed: &completed,
                snapshots: &snapshots,
            },
        )
    };

    std::thread::scope(|scope| {
        let requested = &requested;
        let completed = &completed;
        let consumer_owner = scope.spawn(move || {
            for head in 1..=64 {
                requested.wait();
                unsafe { atomic_store_u64(remote_head as *mut u64, head) };
                completed.wait();
            }
        });
        match producer.try_push(body(0x8182)) {
            Err(PushError::Contended(returned)) => assert_eq!(returned.req_id, 0x8182),
            other => panic!("expected Contended, got {other:?}"),
        }
        consumer_owner.join().unwrap();
    });

    assert_eq!(snapshots.load(Ordering::Relaxed), 64);
    assert_eq!(producer_page.tail, 69);
    assert!(entries
        .iter()
        .all(|entry| entry.sequence == 0 && entry.body.req_id == 0));
}

fn test_divisor() -> u64 {
    std::env::var("FSRING_TEST_DIV")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0)
        .unwrap_or(1)
}

#[test]
fn mpsc_stress_four_producers_one_consumer_preserves_every_item_and_source_order() {
    const PRODUCERS: usize = 4;
    const CAP: usize = 256;
    const PER_PRODUCER_FULL: u64 = 100_000;

    let per_producer = (PER_PRODUCER_FULL / test_divisor()).max(2_000);
    let total = per_producer * PRODUCERS as u64;
    let mut producer_page = producer_page(0);
    let mut consumer_page = consumer_page(0);
    let mut entries = vec![
        Sqe {
            sequence: 0,
            body: body(0),
        };
        CAP
    ]
    .into_boxed_slice();

    let producer = unsafe {
        MpscProducer::attach_sq(
            addr_of_mut!(*producer_page),
            addr_of!(*consumer_page),
            entries.as_mut_ptr(),
            CAP,
        )
    };
    let mut consumer = unsafe {
        SingleConsumer::attach_sq(
            addr_of!(*producer_page),
            addr_of_mut!(*consumer_page),
            entries.as_ptr(),
            CAP,
        )
    };

    let mut count = 0u64;
    let mut sum = 0u64;
    let mut next_by_producer = [0u64; PRODUCERS];
    let started = std::time::Instant::now();

    std::thread::scope(|scope| {
        for producer_index in 0..PRODUCERS as u64 {
            let producer = &producer;
            scope.spawn(move || {
                for sequence in 0..per_producer {
                    let mut item = body((producer_index << 32) | sequence);
                    loop {
                        match producer.try_push(item) {
                            Ok(_) => break,
                            Err(PushError::Full(returned) | PushError::Contended(returned)) => {
                                item = returned;
                                std::thread::yield_now();
                            }
                            Err(PushError::Protocol(fault, _)) => {
                                panic!("unexpected producer protocol fault: {fault:?}")
                            }
                        }
                    }
                }
            });
        }

        while count != total {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(60),
                "stress test stalled at {count}/{total}"
            );
            match consumer.try_pop() {
                Ok(Some(item)) => {
                    let producer_index = (item.req_id >> 32) as usize;
                    let sequence = item.req_id & u32::MAX as u64;
                    assert_eq!(sequence, next_by_producer[producer_index]);
                    next_by_producer[producer_index] += 1;
                    count += 1;
                    sum += item.req_id;
                }
                Ok(None) => std::thread::yield_now(),
                Err(PopError::Protocol(fault)) => {
                    panic!("unexpected consumer protocol fault: {fault:?}")
                }
            }
        }
    });

    assert_eq!(count, total);
    assert_eq!(next_by_producer, [per_producer; PRODUCERS]);
    let expected_sum = (0..PRODUCERS as u64)
        .map(|producer_index| {
            per_producer * (producer_index << 32) + per_producer * (per_producer - 1) / 2
        })
        .sum::<u64>();
    assert_eq!(sum, expected_sum);
}
