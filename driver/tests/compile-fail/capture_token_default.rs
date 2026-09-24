use fsring_core::reqtab::{
    ApplicationCapture, CapturedApplication, CapturedControl, CaptureToken, ControlCapture,
};

fn requires_default<T: Default>() {}

pub fn capture_token_default() {
    requires_default::<CaptureToken>();
    requires_default::<ApplicationCapture>();
    requires_default::<ControlCapture>();
    requires_default::<CapturedApplication>();
    requires_default::<CapturedControl>();
}
