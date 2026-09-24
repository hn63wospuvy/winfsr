// A fence retry fail-stop holds every authority the generation still has, and
// it must not be able to turn any of them into deletion authority: a fail-stop
// that could delete is not a fail-stop.
use fsring_core::adapter::fence::FenceRetryFailStopRight;
use fsring_core::session::DeleteSessionRight;

pub fn prove(refused: FenceRetryFailStopRight) {
    let _forged = DeleteSessionRight::new(refused.retry_key());
    let _from_refusal = refused.into_delete_right();
}
