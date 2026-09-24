use fsring_core::reqtab::{
    ApplicationCapture, CapturedApplication, CapturedControl, CaptureToken, ControlCapture,
};

fn requires_clone<T: Clone>() {}

pub fn capture_token_clone() {
    requires_clone::<CaptureToken>();
    requires_clone::<ApplicationCapture>();
    requires_clone::<ControlCapture>();
    requires_clone::<CapturedApplication>();
    requires_clone::<CapturedControl>();
}
