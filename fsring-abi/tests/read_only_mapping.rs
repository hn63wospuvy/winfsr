#![cfg(windows)]

use core::ffi::c_void;
use core::ptr::{addr_of_mut, null_mut};

use fsring_abi::ring::{MpscProducer, SingleConsumer};
use fsring_abi::{ConsumerPage, ProducerPage, Sqe, SqeBody, PARK_STATE_PARKED, SQE_PAYLOAD_LEN};

const CAPACITY: usize = 4;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualAlloc(
        address: *mut c_void,
        size: usize,
        allocation_type: u32,
        protect: u32,
    ) -> *mut c_void;
    fn VirtualProtect(
        address: *mut c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32;
    fn VirtualFree(address: *mut c_void, size: usize, free_type: u32) -> i32;
}

struct Allocation(*mut c_void);

impl Allocation {
    fn new(bytes: usize) -> Self {
        // SAFETY: arguments request a new anonymous committed/reserved region.
        let pointer =
            unsafe { VirtualAlloc(null_mut(), bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        assert!(!pointer.is_null(), "VirtualAlloc failed");
        Self(pointer)
    }

    fn as_mut<T>(&self) -> *mut T {
        self.0.cast()
    }

    fn protect_read_only(&self, bytes: usize) {
        let mut old_protect = 0;
        // SAFETY: this allocation is live and covers `bytes`; old protection
        // is returned through a valid pointer.
        let succeeded =
            unsafe { VirtualProtect(self.0, bytes, PAGE_READONLY, addr_of_mut!(old_protect)) };
        assert_ne!(succeeded, 0, "VirtualProtect(PAGE_READONLY) failed");
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        // SAFETY: MEM_RELEASE with size zero releases this complete allocation.
        let succeeded = unsafe { VirtualFree(self.0, 0, MEM_RELEASE) };
        assert_ne!(succeeded, 0, "VirtualFree failed");
    }
}

fn producer_page() -> ProducerPage {
    ProducerPage {
        tail: 0,
        wake_sequence: 0,
        flags: 0,
        reserved0: [0; 4],
        reserved: [0; 4072],
    }
}

fn consumer_page(park_state: u32) -> ConsumerPage {
    ConsumerPage {
        head: 0,
        park_state,
        flags: 0,
        heartbeat: 0,
        reserved: [0; 4072],
    }
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
        payload: [0; SQE_PAYLOAD_LEN],
    }
}

unsafe fn initialize_entries(entries: *mut Sqe) {
    for index in 0..CAPACITY {
        // SAFETY: caller supplies storage for CAPACITY initialized entries.
        unsafe {
            entries.add(index).write(Sqe {
                sequence: 0,
                body: body(0),
            })
        };
    }
}

#[test]
fn peer_owned_head_park_and_entries_are_read_from_page_readonly_mappings() {
    let producer_memory = Allocation::new(core::mem::size_of::<ProducerPage>());
    let remote_consumer_memory = Allocation::new(core::mem::size_of::<ConsumerPage>());
    let entries_memory = Allocation::new(CAPACITY * core::mem::size_of::<Sqe>());
    let producer_page_ptr = producer_memory.as_mut::<ProducerPage>();
    let remote_consumer_ptr = remote_consumer_memory.as_mut::<ConsumerPage>();
    let entries_ptr = entries_memory.as_mut::<Sqe>();

    // SAFETY: fresh allocations are aligned, writable, and large enough.
    unsafe {
        producer_page_ptr.write(producer_page());
        remote_consumer_ptr.write(consumer_page(PARK_STATE_PARKED));
        initialize_entries(entries_ptr);
    }
    remote_consumer_memory.protect_read_only(core::mem::size_of::<ConsumerPage>());
    let receipt = {
        let producer = unsafe {
            MpscProducer::attach_sq(
                producer_page_ptr,
                remote_consumer_ptr,
                entries_ptr,
                CAPACITY,
            )
        };
        producer.try_push(body(41)).unwrap()
    };
    assert_eq!(receipt.position, 0);
    assert!(receipt.should_wake);

    let second_producer_memory = Allocation::new(core::mem::size_of::<ProducerPage>());
    let local_consumer_memory = Allocation::new(core::mem::size_of::<ConsumerPage>());
    let published_entries_memory = Allocation::new(CAPACITY * core::mem::size_of::<Sqe>());
    let second_producer_ptr = second_producer_memory.as_mut::<ProducerPage>();
    let local_consumer_ptr = local_consumer_memory.as_mut::<ConsumerPage>();
    let published_entries_ptr = published_entries_memory.as_mut::<Sqe>();

    // SAFETY: fresh allocations are aligned, writable, and large enough.
    unsafe {
        second_producer_ptr.write(producer_page());
        local_consumer_ptr.write(consumer_page(0));
        initialize_entries(published_entries_ptr);
    }
    let receipt = {
        let second_producer = unsafe {
            MpscProducer::attach_sq(
                second_producer_ptr,
                local_consumer_ptr,
                published_entries_ptr,
                CAPACITY,
            )
        };
        second_producer.try_push(body(99)).unwrap()
    };
    assert_eq!(receipt.position, 0);

    second_producer_memory.protect_read_only(core::mem::size_of::<ProducerPage>());
    published_entries_memory.protect_read_only(CAPACITY * core::mem::size_of::<Sqe>());
    let mut consumer = unsafe {
        SingleConsumer::attach_sq(
            second_producer_ptr,
            local_consumer_ptr,
            published_entries_ptr,
            CAPACITY,
        )
    };
    assert_eq!(consumer.try_pop().unwrap().unwrap().req_id, 99);
    assert_eq!(unsafe { (*local_consumer_ptr).head }, 1);
    assert_eq!(unsafe { (*second_producer_ptr).tail }, 1);
    assert_eq!(unsafe { (*published_entries_ptr).body.req_id }, 99);
}
