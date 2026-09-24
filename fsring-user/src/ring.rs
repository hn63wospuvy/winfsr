//! Typed ring handles binding the ABI ring core to a section's pages.
//!
//! Each ring has two sides. The **daemon** consumes SQEs and produces CQEs; the
//! **kernel role** (the harness, or eventually the real driver) produces SQEs
//! and consumes CQEs. The ring algorithm, cursors, and memory ordering all live
//! in [`fsring_abi::ring`]; these handles only attach it to the region pointers
//! `PhysicalLayout` placed and translate the ABI results into transport terms.

use fsring_abi::layout::{ConsumerPage, Cqe, CqeBody, ProducerPage, Sqe, SqeBody};
use fsring_abi::ring::{MpscProducer, PushError, PushReceipt, SingleConsumer, SpscProducer};

use crate::error::TransportError;
use crate::layout::RingRegions;

/// The daemon side of one ring: consumes SQEs, produces CQEs.
pub struct DaemonRing<'a> {
    sq: SingleConsumer<'a, Sqe>,
    cq: SpscProducer<'a, Cqe>,
}

impl<'a> DaemonRing<'a> {
    /// Attach the daemon-side handle for the ring described by `regions`.
    ///
    /// # Safety
    /// `base` must point to a validated section that stays live for `'a` and in
    /// which `regions` describes this ring's pages/entries; this must be the
    /// only daemon-side handle for that ring (it is the sole writer of the SQ
    /// consumer head and the CQ producer tail/entries). `base` must be at least
    /// 4096-aligned so the section's 64 KiB-aligned page offsets land the
    /// `align(4096)` `ProducerPage`/`ConsumerPage` at aligned addresses
    /// (`HeapSection` and `MappedSection` both guarantee this).
    pub unsafe fn attach(base: *mut u8, regions: &RingRegions) -> Self {
        // SAFETY: each pointer is `base` offset by a region the caller
        // guarantees validated and in-bounds; the ABI attach contracts (same
        // logical ring/epoch, power-of-two capacity, sole writer) are forwarded.
        unsafe {
            let sq = SingleConsumer::attach_sq(
                base.add(regions.sq_producer.offset as usize)
                    .cast::<ProducerPage>(),
                base.add(regions.sq_consumer.offset as usize)
                    .cast::<ConsumerPage>(),
                base.add(regions.sq_entries.offset as usize).cast::<Sqe>(),
                regions.sq_capacity as usize,
            );
            let cq = SpscProducer::attach_cq(
                base.add(regions.cq_producer.offset as usize)
                    .cast::<ProducerPage>(),
                base.add(regions.cq_consumer.offset as usize)
                    .cast::<ConsumerPage>(),
                base.add(regions.cq_entries.offset as usize).cast::<Cqe>(),
                regions.cq_capacity as usize,
            );
            Self { sq, cq }
        }
    }

    /// Attach the daemon-side handle from separately validated view bases.
    ///
    /// This is the native path: unlike [`Self::attach`], no single base is
    /// trusted to cover every region. The read-only pointers come from the
    /// whole-section alias and the three writable ones from their own
    /// per-ring aliases, each validated for exactly the access it is used at.
    ///
    /// # Safety
    /// `regions` must have been built by `fsring_user::native` from views it
    /// validated, and its owner token keeps the ring exclusively borrowed for
    /// `'a`.
    pub(crate) unsafe fn attach_regions(regions: crate::native::DaemonRingRegionSet<'a>) -> Self {
        // SAFETY: forwarded verbatim from this function's own contract. The
        // SQ producer/entries and the CQ consumer are handed over as const
        // pointers because the daemon never writes them.
        unsafe {
            let sq = SingleConsumer::attach_sq(
                regions.sq_producer.cast_mut(),
                regions.sq_consumer,
                regions.sq_entries.cast_mut(),
                regions.sq_capacity,
            );
            let cq = SpscProducer::attach_cq(
                regions.cq_producer,
                regions.cq_consumer.cast_mut(),
                regions.cq_entries,
                regions.cq_capacity,
            );
            Self { sq, cq }
        }
    }

    /// Pop the next request, if one is ready.
    pub fn poll_sqe(&mut self) -> Result<Option<SqeBody>, TransportError> {
        self.sq.try_pop().map_err(TransportError::from)
    }

    /// Publish one completion. On [`PushError::Full`] the body is returned so the
    /// caller can park on the CQ producer and retry the same completion.
    // The large `Err` is deliberate: it carries the message body back for
    // lossless retry, exactly as the ABI `SpscProducer::try_push` does.
    #[allow(clippy::result_large_err)]
    pub fn post_cqe(&mut self, cqe: CqeBody) -> Result<PushReceipt, PushError<CqeBody>> {
        self.cq.try_push(cqe)
    }

    /// Declare the SQ consumer parked and recheck for a request that raced in.
    /// `Ok(true)` means it is safe to block; `Ok(false)` means work appeared.
    pub fn declare_park(&mut self) -> Result<bool, TransportError> {
        self.sq.declare_park().map_err(TransportError::from)
    }

    /// Mark the SQ consumer polling (about to drain without blocking).
    pub fn set_polling(&mut self) {
        self.sq.set_polling();
    }

    /// Mark the SQ consumer active.
    pub fn set_active(&mut self) {
        self.sq.set_active();
    }
}

/// The kernel-role side of one ring: produces SQEs, consumes CQEs.
pub struct KernelRing<'a> {
    sq: MpscProducer<'a, Sqe>,
    cq: SingleConsumer<'a, Cqe>,
}

impl<'a> KernelRing<'a> {
    /// Attach the kernel-role handle for the ring described by `regions`.
    ///
    /// # Safety
    /// Same contract as [`DaemonRing::attach`] (including the ≥4096-aligned
    /// `base` requirement), for the opposite role: this must be the only
    /// kernel-role handle for the ring (sole writer of the SQ producer
    /// tail/entries and the CQ consumer head).
    pub unsafe fn attach(base: *mut u8, regions: &RingRegions) -> Self {
        // SAFETY: as in `DaemonRing::attach`, with the producer/consumer roles
        // swapped; the ABI attach contracts are forwarded.
        unsafe {
            let sq = MpscProducer::attach_sq(
                base.add(regions.sq_producer.offset as usize)
                    .cast::<ProducerPage>(),
                base.add(regions.sq_consumer.offset as usize)
                    .cast::<ConsumerPage>(),
                base.add(regions.sq_entries.offset as usize).cast::<Sqe>(),
                regions.sq_capacity as usize,
            );
            let cq = SingleConsumer::attach_cq(
                base.add(regions.cq_producer.offset as usize)
                    .cast::<ProducerPage>(),
                base.add(regions.cq_consumer.offset as usize)
                    .cast::<ConsumerPage>(),
                base.add(regions.cq_entries.offset as usize).cast::<Cqe>(),
                regions.cq_capacity as usize,
            );
            Self { sq, cq }
        }
    }

    /// Submit one request. On [`PushError::Full`] the body is returned so the
    /// caller can park on the SQ producer and retry.
    // The large `Err` is deliberate: it carries the message body back for
    // lossless retry, exactly as the ABI `MpscProducer::try_push` does.
    #[allow(clippy::result_large_err)]
    pub fn submit(&self, sqe: SqeBody) -> Result<PushReceipt, PushError<SqeBody>> {
        self.sq.try_push(sqe)
    }

    /// Reap the next completion, if one is ready.
    pub fn reap(&mut self) -> Result<Option<CqeBody>, TransportError> {
        self.cq.try_pop().map_err(TransportError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::valid_setup;
    use crate::layout::PhysicalLayout;
    use crate::section::{HeapSection, SharedSection};
    use fsring_abi::layout::SQE_PAYLOAD_LEN;

    fn sqe(opcode: u16, req_id: u64) -> SqeBody {
        SqeBody {
            opcode,
            flags: 0,
            payload_len: 0,
            reserved: 0,
            req_id,
            kernel_open_id: 0,
            ccb_sequence: 0,
            payload: [0u8; SQE_PAYLOAD_LEN],
        }
    }

    #[test]
    fn submitted_sqe_is_polled_by_the_daemon() {
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, 4096).unwrap();
        let section = HeapSection::with_len(layout.section_size as usize, 4096);
        // SAFETY: zeroed mapping of section_size bytes.
        unsafe { layout.construct(section.base(), section.len()) };
        let regions = layout.rings[0];

        // SAFETY: the section outlives both rings; one handle per role.
        let kernel = unsafe { KernelRing::attach(section.base(), &regions) };
        // SAFETY: same section; sole daemon-side handle.
        let mut daemon = unsafe { DaemonRing::attach(section.base(), &regions) };

        let _receipt = kernel.submit(sqe(0x0010, 42)).expect("submit succeeds");
        let popped = daemon
            .poll_sqe()
            .expect("poll succeeds")
            .expect("a request is ready");
        assert_eq!(popped.req_id, 42);
        assert_eq!(popped.opcode, 0x0010);
        // no second request
        assert!(daemon.poll_sqe().expect("poll succeeds").is_none());
    }
}
