// One validated completion completes one IRP. `prepare_for_irp` consumes it and
// `commit_after_io_complete` consumes the prepared value, so a second
// completion would need a second validation -- and neither value is Clone.
use fsring_core::adapter::enter::ValidatedCompletion;

pub fn prove(completion: ValidatedCompletion) {
    let prepared = unsafe { completion.prepare_for_irp() };
    let _first = unsafe { prepared.commit_after_io_complete() };

    // The completion was moved into `prepare_for_irp`; using it again, or
    // reusing the prepared value, is a use after move.
    let _again = unsafe { completion.prepare_for_irp() };
    let _second = unsafe { prepared.commit_after_io_complete() };
}
