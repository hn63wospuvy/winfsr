//! Focused v2 park/wake race over the ownership-separated SQ transport.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use fsring_abi::ring::{MpscProducer, PushError, SingleConsumer};
use fsring_abi::{ConsumerPage, ProducerPage, Sqe, SqeBody};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

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

fn test_divisor() -> u64 {
    std::env::var("FSRING_TEST_DIV")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0)
        .unwrap_or(1)
}

struct AutoResetEvent {
    signaled: Mutex<bool>,
    changed: Condvar,
}

impl AutoResetEvent {
    fn new() -> Self {
        Self {
            signaled: Mutex::new(false),
            changed: Condvar::new(),
        }
    }

    fn set(&self) {
        let mut signaled = self.signaled.lock().unwrap();
        *signaled = true;
        self.changed.notify_one();
    }

    fn wait(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut signaled = self.signaled.lock().unwrap();
        while !*signaled {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (next, _) = self.changed.wait_timeout(signaled, deadline - now).unwrap();
            signaled = next;
        }
        *signaled = false;
        true
    }
}

#[test]
fn ownership_separated_park_wake_race_has_no_lost_wakeup() {
    const COUNT_FULL: u64 = 100_000;
    const ROUNDS: usize = 2;
    const CAPACITY: usize = 2;

    let count = (COUNT_FULL / test_divisor()).max(2_000);
    for round in 0..ROUNDS {
        let mut producer_page = Box::new(ProducerPage {
            tail: 0,
            wake_sequence: 0,
            flags: 0,
            reserved0: [0; 4],
            reserved: [0; 4072],
        });
        let mut consumer_page = Box::new(ConsumerPage {
            head: 0,
            park_state: 0,
            flags: 0,
            heartbeat: 0,
            reserved: [0; 4072],
        });
        let mut entries = Box::new(
            [Sqe {
                sequence: 0,
                body: body(0),
            }; CAPACITY],
        );
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
        let event = AutoResetEvent::new();
        let done = AtomicBool::new(false);
        let lost_wakeups = AtomicUsize::new(0);
        let started = Instant::now();

        std::thread::scope(|scope| {
            scope.spawn(|| {
                for value in 0..count {
                    let mut item = body(value);
                    loop {
                        match producer.try_push(item) {
                            Ok(receipt) => {
                                if receipt.should_wake {
                                    event.set();
                                }
                                break;
                            }
                            Err(PushError::Full(returned) | PushError::Contended(returned)) => {
                                item = returned;
                                std::thread::yield_now();
                            }
                            Err(PushError::Protocol(fault, _)) => {
                                panic!("unexpected producer protocol fault: {fault:?}")
                            }
                        }
                    }
                    if value % 5 == 0 {
                        std::thread::yield_now();
                    }
                }
                done.store(true, Ordering::SeqCst);
                event.set();
            });

            scope.spawn(|| {
                let mut received = 0u64;
                loop {
                    consumer.set_active();
                    while let Some(item) = consumer.try_pop().unwrap() {
                        assert_eq!(item.req_id, received);
                        received += 1;
                    }
                    if done.load(Ordering::SeqCst)
                        && !consumer.has_item().unwrap()
                        && received == count
                    {
                        break;
                    }
                    assert!(
                        started.elapsed() < Duration::from_secs(60),
                        "round {round} stalled at {received}/{count}"
                    );
                    consumer.set_polling();
                    if !consumer.declare_park().unwrap() {
                        continue;
                    }
                    let signaled = event.wait(Duration::from_millis(200));
                    if !signaled && consumer.has_item().unwrap() {
                        lost_wakeups.fetch_add(1, Ordering::Relaxed);
                    }
                }
                assert_eq!(received, count);
            });
        });

        assert_eq!(
            lost_wakeups.load(Ordering::Relaxed),
            0,
            "round {round}: lost wakeup"
        );
    }
}
