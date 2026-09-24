// A pending disposition says the pending context owns the IRP. The receipt that
// proves it is minted only by the post-handoff transition; a raw IRP, or a
// "we inserted it into the CSQ" belief, is not ownership proof.
use fsring_core::adapter::enter::PendingDispatchReceipt;
use fsring_core::enter::IrpObservation;

pub fn prove(irp: IrpObservation) {
    // No public constructor, and no conversion from a bare observation.
    let _forged = PendingDispatchReceipt { irp };
    let _converted = PendingDispatchReceipt::from_irp(irp);
}
