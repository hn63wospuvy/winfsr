//! R5 Task 20 (abi half): the deferred CQ pop.
//!
//! `try_pop` reads the body and stores the new head in one call. A CQ drain has
//! to decide *after* seeing the body whether it can account for the entry, and
//! once the head has moved the producer may reuse the cell — so a drain that
//! read, failed to account, and then tried to un-advance would be reading a cell
//! the producer already owns again. `try_peek` splits the read from the store.

use core::ptr::{addr_of, addr_of_mut};

use fsring_abi::ring::{MpscProducer, SingleConsumer};
use fsring_abi::{ConsumerPage, ProducerPage, Sqe, SqeBody};

const CAPACITY: usize = 8;

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

struct Ring {
    producer_page: Box<ProducerPage>,
    consumer_page: Box<ConsumerPage>,
    entries: Box<[Sqe; CAPACITY]>,
}

impl Ring {
    fn new() -> Self {
        Self {
            producer_page: Box::new(ProducerPage {
                tail: 0,
                wake_sequence: 0,
                flags: 0,
                reserved0: [0; 4],
                reserved: [0; 4072],
            }),
            consumer_page: Box::new(ConsumerPage {
                head: 0,
                park_state: 0,
                flags: 0,
                heartbeat: 0,
                reserved: [0; 4072],
            }),
            entries: Box::new(
                [Sqe {
                    sequence: 0,
                    body: body(0),
                }; CAPACITY],
            ),
        }
    }

    fn split(&mut self) -> (MpscProducer<'_>, SingleConsumer<'_>) {
        let consumer_page_ptr = addr_of_mut!(*self.consumer_page);
        let producer = unsafe {
            MpscProducer::attach_sq(
                addr_of_mut!(*self.producer_page),
                consumer_page_ptr,
                self.entries.as_mut_ptr(),
                CAPACITY,
            )
        };
        let consumer = unsafe {
            SingleConsumer::attach_sq(
                addr_of!(*self.producer_page),
                consumer_page_ptr,
                self.entries.as_ptr(),
                CAPACITY,
            )
        };
        (producer, consumer)
    }

    /// The head the consumer has published, read straight from the page.
    fn published_head(&self) -> u64 {
        self.consumer_page.head
    }
}

#[test]
fn released_peek_leaves_the_head_exactly_where_it_was() {
    let mut ring = Ring::new();
    let (producer, mut consumer) = ring.split();
    producer.try_push(body(7)).expect("a fresh ring accepts");

    // Peek reads the body without moving the head.
    {
        let pending = consumer
            .try_peek()
            .expect("no protocol fault")
            .expect("one entry is ready");
        assert_eq!(pending.body().req_id, 7);
        assert_eq!(pending.sequence(), 1);
        pending.release();
    }
    drop(consumer);
    assert_eq!(
        ring.published_head(),
        0,
        "a released peek publishes no head advance"
    );

    // And the same entry is still there for the next reader, which is the whole
    // point: declining an entry must not consume it.
    let (_producer, mut consumer) = ring.split();
    let pending = consumer
        .try_peek()
        .expect("no protocol fault")
        .expect("the entry survived the release");
    assert_eq!(pending.body().req_id, 7);
    pending.release();
}

#[test]
fn committed_peek_advances_the_head_once_and_mints_one_receipt() {
    let mut ring = Ring::new();
    let (producer, mut consumer) = ring.split();
    producer.try_push(body(11)).expect("a fresh ring accepts");
    producer.try_push(body(12)).expect("capacity remains");

    let (first_body, receipt) = {
        let pending = consumer
            .try_peek()
            .expect("no protocol fault")
            .expect("one entry is ready");
        pending.commit().into_parts()
    };
    assert_eq!(first_body.req_id, 11);
    assert_eq!(receipt.sequence(), 1);
    assert_eq!(receipt.next_head(), 1);

    // The head moved exactly once, and the next peek sees the *second* entry —
    // so the commit consumed one entry, not zero and not two.
    let second = consumer
        .try_peek()
        .expect("no protocol fault")
        .expect("the second entry is ready");
    assert_eq!(second.body().req_id, 12);
    assert_eq!(second.sequence(), 2);
    second.release();

    drop(consumer);
    assert_eq!(
        ring.published_head(),
        1,
        "exactly one advance was published"
    );
}

#[test]
fn deferred_pop_matches_try_pop_over_a_whole_drain() {
    // The deferred route must not change what a drain observes: same bodies,
    // same order, same final head. Otherwise the split would be a behaviour
    // change wearing an ownership change's clothes.
    let mut direct = Ring::new();
    let mut deferred = Ring::new();
    const COUNT: u64 = 6;

    let mut direct_seen = Vec::new();
    {
        let (producer, mut consumer) = direct.split();
        for value in 0..COUNT {
            producer.try_push(body(value)).expect("capacity");
        }
        while let Some(item) = consumer.try_pop().expect("no protocol fault") {
            direct_seen.push(item.req_id);
        }
    }

    let mut deferred_seen = Vec::new();
    {
        let (producer, mut consumer) = deferred.split();
        for value in 0..COUNT {
            producer.try_push(body(value)).expect("capacity");
        }
        loop {
            let Some(pending) = consumer.try_peek().expect("no protocol fault") else {
                break;
            };
            deferred_seen.push(pending.commit().body().req_id);
        }
    }

    assert_eq!(direct_seen, deferred_seen, "same bodies in the same order");
    assert_eq!(
        direct.published_head(),
        deferred.published_head(),
        "same final head"
    );
    assert_eq!(direct_seen.len(), COUNT as usize);
}
