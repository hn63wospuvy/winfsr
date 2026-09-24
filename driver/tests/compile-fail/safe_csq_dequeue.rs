// A dequeue receipt is proof that one exact IRP left the queue. Safe code
// cannot mint one, and cannot reach the arbiter's parked plan to invent one:
// the fields are private and there is no safe dequeue that skips the CSQ.
use fsring_core::enter::{DequeuedIrp, IrpObservation, PendingIrpArbiter, PendingReason};

pub fn prove(arbiter: PendingIrpArbiter, irp: IrpObservation) {
    // The receipt has private fields and a private seal.
    let _forged = DequeuedIrp {
        reason: PendingReason::Cancel,
        irp,
    };

    // And there is no dequeue that does not go through a CSQ return value.
    let _receipt = arbiter.dequeue_without_csq(PendingReason::Cancel);
}
