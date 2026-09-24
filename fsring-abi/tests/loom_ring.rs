#![cfg(loom)]

//! Reduced-state publication model for the v2 SQ algorithm.
//!
//! This deliberately models capacity two, exactly two producers, one
//! consumer, two pushes, and two pops. It checks the Release/Acquire publish
//! edge, unique reservation/consumption, and the capacity rule that forbids
//! cell reuse before observed head. A separate one-producer generation model
//! makes a third push at capacity two and therefore exercises actual reuse.
//! It does not model hostile cursors, larger capacities, park/wake, or `u64`
//! exhaustion; the native behavior, injection, and stress tests cover those
//! dimensions.

use loom::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;

use fsring_abi::MAX_RESERVE_RETRIES;

const CAPACITY: u64 = 2;

fn push(
    tail: &AtomicU64,
    head: &AtomicU64,
    sequence: &[AtomicU64; 2],
    body: &[AtomicU64; 2],
    in_use: &[AtomicBool; 2],
    value: u64,
) {
    for _ in 0..2 {
        let observed_head = head.load(Ordering::Acquire);
        let position = tail.load(Ordering::Relaxed);
        assert!(observed_head <= position);
        let distance = position.checked_sub(observed_head).unwrap();
        if distance >= CAPACITY {
            thread::yield_now();
            continue;
        }
        let next = position.checked_add(1).unwrap();
        if tail
            .compare_exchange(position, next, Ordering::Release, Ordering::Relaxed)
            .is_err()
        {
            continue;
        }

        // This is the reduced model's explicit "no reuse before head" check.
        assert!(position < observed_head.checked_add(CAPACITY).unwrap());
        let index = (position % CAPACITY) as usize;
        assert!(in_use[index]
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok());
        body[index].store(value, Ordering::Relaxed);
        sequence[index].store(next, Ordering::Release);
        return;
    }
    panic!("bounded two-producer reservation did not complete");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Snapshot {
    tail: u64,
    head: u64,
}

fn snapshot(tail: &AtomicU64, validated_head: &AtomicU64) -> Snapshot {
    Snapshot {
        tail: tail.load(Ordering::Acquire),
        head: validated_head.load(Ordering::Acquire),
    }
}

fn over_capacity(value: Snapshot) -> bool {
    value.tail.checked_sub(value.head).unwrap() > CAPACITY
}

#[test]
fn reserve_retry_limit_matches_the_native_contract() {
    assert_eq!(MAX_RESERVE_RETRIES, 64);
}

#[test]
fn stale_floor_and_release_reservation_cannot_false_fault() {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.max_branches = 20_000;
    builder.check(|| {
        let tail = Arc::new(AtomicU64::new(2));
        let remote_head = Arc::new(AtomicU64::new(0));
        let validated_head = Arc::new(AtomicU64::new(0));
        let cell_released = Arc::new(AtomicBool::new(false));

        let consumer = {
            let remote_head = remote_head.clone();
            let cell_released = cell_released.clone();
            thread::spawn(move || {
                cell_released.store(true, Ordering::Release);
                remote_head.store(1, Ordering::Release);
            })
        };
        let reserver = {
            let tail = tail.clone();
            let remote_head = remote_head.clone();
            let cell_released = cell_released.clone();
            thread::spawn(move || {
                while remote_head.load(Ordering::Acquire) == 0 {
                    thread::yield_now();
                }
                assert!(cell_released.load(Ordering::Acquire));
                assert!(tail
                    .compare_exchange(2, 3, Ordering::Release, Ordering::Relaxed)
                    .is_ok());
            })
        };
        let observer = {
            let tail = tail.clone();
            let remote_head = remote_head.clone();
            let validated_head = validated_head.clone();
            thread::spawn(move || {
                let initial = remote_head.load(Ordering::Acquire);
                validated_head.fetch_max(initial, Ordering::AcqRel);
                let first = snapshot(&tail, &validated_head);
                if !over_capacity(first) {
                    return;
                }

                let refreshed = remote_head.load(Ordering::Acquire);
                validated_head.fetch_max(refreshed, Ordering::AcqRel);
                let second = snapshot(&tail, &validated_head);
                assert!(first != second || !over_capacity(second));
            })
        };

        consumer.join().unwrap();
        reserver.join().unwrap();
        observer.join().unwrap();
        assert_eq!(remote_head.load(Ordering::Acquire), 1);
        assert_eq!(tail.load(Ordering::Acquire), 3);
    });
}

fn push_spsc(
    position: u64,
    head: &AtomicU64,
    sequence: &[AtomicU64; 2],
    body: &[AtomicU64; 2],
    in_use: &[AtomicBool; 2],
    value: u64,
) -> u64 {
    loop {
        let observed_head = head.load(Ordering::Acquire);
        assert!(observed_head <= position);
        if position.checked_sub(observed_head).unwrap() >= CAPACITY {
            thread::yield_now();
            continue;
        }

        let next = position.checked_add(1).unwrap();
        let index = (position % CAPACITY) as usize;
        // On position two this succeeds only after the consumer's Release head
        // publication makes its preceding cell-release visible to this Acquire.
        assert!(in_use[index]
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok());
        body[index].store(value, Ordering::Relaxed);
        sequence[index].store(next, Ordering::Release);
        return next;
    }
}

#[test]
fn two_producers_publish_exactly_once_before_single_consumer_reads() {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.max_branches = 10_000;
    builder.check(|| {
        let tail = Arc::new(AtomicU64::new(0));
        let head = Arc::new(AtomicU64::new(0));
        let sequence = Arc::new([AtomicU64::new(0), AtomicU64::new(0)]);
        let body = Arc::new([AtomicU64::new(0), AtomicU64::new(0)]);
        let in_use = Arc::new([AtomicBool::new(false), AtomicBool::new(false)]);

        let first = {
            let tail = tail.clone();
            let head = head.clone();
            let sequence = sequence.clone();
            let body = body.clone();
            let in_use = in_use.clone();
            thread::spawn(move || push(&tail, &head, &sequence, &body, &in_use, 1))
        };
        let second = {
            let tail = tail.clone();
            let head = head.clone();
            let sequence = sequence.clone();
            let body = body.clone();
            let in_use = in_use.clone();
            thread::spawn(move || push(&tail, &head, &sequence, &body, &in_use, 2))
        };
        let consumer = {
            let head = head.clone();
            let sequence = sequence.clone();
            let body = body.clone();
            let in_use = in_use.clone();
            thread::spawn(move || {
                let mut seen = [false; 3];
                for position in 0..2u64 {
                    let expected = position.checked_add(1).unwrap();
                    let index = (position % CAPACITY) as usize;
                    while sequence[index].load(Ordering::Acquire) != expected {
                        thread::yield_now();
                    }
                    let value = body[index].load(Ordering::Relaxed);
                    assert!(value == 1 || value == 2, "read before publication");
                    assert!(!seen[value as usize], "duplicate consumption");
                    seen[value as usize] = true;
                    in_use[index].store(false, Ordering::Release);
                    head.store(expected, Ordering::Release);
                }
                assert!(seen[1] && seen[2]);
            })
        };

        first.join().unwrap();
        second.join().unwrap();
        consumer.join().unwrap();
        assert_eq!(head.load(Ordering::Acquire), 2);
    });
}

#[test]
fn third_push_reuses_first_cell_only_after_head_release() {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.max_branches = 10_000;
    builder.check(|| {
        let head = Arc::new(AtomicU64::new(0));
        let sequence = Arc::new([AtomicU64::new(0), AtomicU64::new(0)]);
        let body = Arc::new([AtomicU64::new(0), AtomicU64::new(0)]);
        let in_use = Arc::new([AtomicBool::new(false), AtomicBool::new(false)]);

        let producer = {
            let head = head.clone();
            let sequence = sequence.clone();
            let body = body.clone();
            let in_use = in_use.clone();
            thread::spawn(move || {
                let mut tail = 0;
                for value in 1..=3 {
                    tail = push_spsc(tail, &head, &sequence, &body, &in_use, value);
                }
            })
        };
        let consumer = {
            let head = head.clone();
            let sequence = sequence.clone();
            let body = body.clone();
            let in_use = in_use.clone();
            thread::spawn(move || {
                for position in 0..3u64 {
                    let expected = position.checked_add(1).unwrap();
                    let index = (position % CAPACITY) as usize;
                    while sequence[index].load(Ordering::Acquire) != expected {
                        thread::yield_now();
                    }
                    assert_eq!(body[index].load(Ordering::Relaxed), expected);
                    in_use[index].store(false, Ordering::Release);
                    head.store(expected, Ordering::Release);
                }
            })
        };

        producer.join().unwrap();
        consumer.join().unwrap();
        assert_eq!(head.load(Ordering::Acquire), 3);
    });
}
