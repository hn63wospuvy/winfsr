// 06-locking.md section 3.3: "A wait or resource drop invalidates the captured
// size epoch and repeats the size decision if state changed." An invalidated
// capture must not yield its epoch.
use fsring_core::size::EpochCapture;

pub fn use_a_waited_capture() -> u64 {
    let capture = EpochCapture::new(42);
    let invalidated = capture.wait_occurred();
    invalidated.epoch()
}
