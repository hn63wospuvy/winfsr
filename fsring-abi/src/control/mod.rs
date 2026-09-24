//! Authenticated control-device registries and session wire definitions.

mod boot;
mod session;

pub use crate::msgs::{AttachV1, DonateSecurityContextV1};
pub use boot::*;
pub use session::*;

/// cbindgen:ignore
pub const FILE_DEVICE_UNKNOWN: u32 = 0x22;
/// cbindgen:ignore
pub const METHOD_BUFFERED: u32 = 0;
/// cbindgen:ignore
pub const FILE_READ_ACCESS: u32 = 1;
/// cbindgen:ignore
pub const FILE_WRITE_ACCESS: u32 = 2;
/// cbindgen:ignore
pub const CONTROL_IOCTL_ACCESS: u32 = FILE_READ_ACCESS | FILE_WRITE_ACCESS;

/// cbindgen:ignore
pub const CONTROL_DEVICE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
/// cbindgen:ignore
pub const FSRING_MOUNT_CONTROL: u32 = 0x0000_0001;
/// cbindgen:ignore
pub const GLOBAL_RING_INDEX: u32 = u32::MAX;
/// cbindgen:ignore
pub const ENTER_TIMEOUT_INFINITE: u32 = u32::MAX;
/// cbindgen:ignore
pub const DONATE_BACKING_VERSION_V2: u16 = 2;

/// cbindgen:ignore
pub mod ioctl_function {
    pub const SETUP: u32 = 0x800;
    pub const ENTER: u32 = 0x801;
    pub const ATTACH: u32 = 0x802;
    pub const DONATE_BACKING: u32 = 0x803;
    pub const DONATE_SECURITY_CONTEXT: u32 = 0x804;
    pub const DETACH: u32 = 0x805;
    pub const RETIRE_MOUNT: u32 = 0x806;
}

const fn control_ioctl(function: u32) -> u32 {
    (FILE_DEVICE_UNKNOWN << 16) | (CONTROL_IOCTL_ACCESS << 14) | (function << 2) | METHOD_BUFFERED
}

/// cbindgen:ignore
pub const IOCTL_FSRING_SETUP: u32 = control_ioctl(ioctl_function::SETUP);
/// cbindgen:ignore
pub const IOCTL_FSRING_ENTER: u32 = control_ioctl(ioctl_function::ENTER);
/// cbindgen:ignore
pub const IOCTL_FSRING_ATTACH: u32 = control_ioctl(ioctl_function::ATTACH);
/// cbindgen:ignore
pub const IOCTL_FSRING_DONATE_BACKING: u32 = control_ioctl(ioctl_function::DONATE_BACKING);
/// cbindgen:ignore
pub const IOCTL_FSRING_DONATE_SECURITY_CONTEXT: u32 =
    control_ioctl(ioctl_function::DONATE_SECURITY_CONTEXT);
/// cbindgen:ignore
pub const IOCTL_FSRING_DETACH: u32 = control_ioctl(ioctl_function::DETACH);
/// cbindgen:ignore
pub const IOCTL_FSRING_RETIRE_MOUNT: u32 = control_ioctl(ioctl_function::RETIRE_MOUNT);

/// cbindgen:ignore
pub mod status {
    pub const SUCCESS: i32 = 0x0000_0000;
    pub const DEVICE_BUSY: i32 = 0x8000_0011u32 as i32;
    pub const INVALID_PARAMETER: i32 = 0xc000_000du32 as i32;
    pub const ACCESS_DENIED: i32 = 0xc000_0022u32 as i32;
    pub const BUFFER_TOO_SMALL: i32 = 0xc000_0023u32 as i32;
    pub const OBJECT_NAME_NOT_FOUND: i32 = 0xc000_0034u32 as i32;
    pub const REVISION_MISMATCH: i32 = 0xc000_0059u32 as i32;
    pub const INTEGER_OVERFLOW: i32 = 0xc000_0095u32 as i32;
    pub const INSUFFICIENT_RESOURCES: i32 = 0xc000_009au32 as i32;
    pub const NOT_SUPPORTED: i32 = 0xc000_00bbu32 as i32;
    pub const CANCELLED: i32 = 0xc000_0120u32 as i32;
    pub const INVALID_DEVICE_STATE: i32 = 0xc000_0184u32 as i32;
}

pub const fn is_legal_create_status(candidate: i32) -> bool {
    matches!(
        candidate,
        status::SUCCESS
            | status::ACCESS_DENIED
            | status::OBJECT_NAME_NOT_FOUND
            | status::INSUFFICIENT_RESOURCES
    )
}

pub const fn is_legal_ioctl_status(ioctl: u32, candidate: i32) -> bool {
    match ioctl {
        IOCTL_FSRING_SETUP => matches!(
            candidate,
            status::SUCCESS
                | status::DEVICE_BUSY
                | status::INVALID_PARAMETER
                | status::ACCESS_DENIED
                | status::BUFFER_TOO_SMALL
                | status::REVISION_MISMATCH
                | status::INTEGER_OVERFLOW
                | status::INSUFFICIENT_RESOURCES
                | status::NOT_SUPPORTED
                | status::CANCELLED
        ),
        IOCTL_FSRING_ATTACH => matches!(
            candidate,
            status::SUCCESS
                | status::DEVICE_BUSY
                | status::INVALID_PARAMETER
                | status::ACCESS_DENIED
                | status::BUFFER_TOO_SMALL
                | status::REVISION_MISMATCH
                | status::INSUFFICIENT_RESOURCES
                | status::NOT_SUPPORTED
                | status::CANCELLED
                | status::INVALID_DEVICE_STATE
        ),
        IOCTL_FSRING_ENTER => matches!(
            candidate,
            status::SUCCESS
                | status::DEVICE_BUSY
                | status::INVALID_PARAMETER
                | status::ACCESS_DENIED
                | status::BUFFER_TOO_SMALL
                | status::REVISION_MISMATCH
                | status::NOT_SUPPORTED
                | status::CANCELLED
                | status::INVALID_DEVICE_STATE
        ),
        IOCTL_FSRING_DONATE_BACKING => matches!(
            candidate,
            status::SUCCESS
                | status::DEVICE_BUSY
                | status::INVALID_PARAMETER
                | status::ACCESS_DENIED
                | status::REVISION_MISMATCH
                | status::INSUFFICIENT_RESOURCES
                | status::NOT_SUPPORTED
                | status::CANCELLED
                | status::INVALID_DEVICE_STATE
        ),
        IOCTL_FSRING_DONATE_SECURITY_CONTEXT => matches!(
            candidate,
            status::INVALID_PARAMETER
                | status::ACCESS_DENIED
                | status::REVISION_MISMATCH
                | status::NOT_SUPPORTED
                | status::INVALID_DEVICE_STATE
        ),
        IOCTL_FSRING_DETACH => matches!(
            candidate,
            status::SUCCESS
                | status::DEVICE_BUSY
                | status::INVALID_PARAMETER
                | status::ACCESS_DENIED
                | status::REVISION_MISMATCH
                | status::NOT_SUPPORTED
                | status::CANCELLED
                | status::INVALID_DEVICE_STATE
        ),
        IOCTL_FSRING_RETIRE_MOUNT => matches!(
            candidate,
            status::SUCCESS
                | status::DEVICE_BUSY
                | status::INVALID_PARAMETER
                | status::ACCESS_DENIED
                | status::BUFFER_TOO_SMALL
                | status::REVISION_MISMATCH
                | status::NOT_SUPPORTED
                | status::INVALID_DEVICE_STATE
        ),
        _ => false,
    }
}

/// cbindgen:ignore
pub mod view_kind {
    pub const INVALID: u16 = 0;
    pub const SECTION_READ_ONLY: u16 = 1;
    pub const SQ_CONSUMER_PAGE: u16 = 2;
    pub const CQ_ENTRIES: u16 = 3;
    pub const CQ_PRODUCER_PAGE: u16 = 4;
    pub const U2K_ARENA: u16 = 5;
}

/// cbindgen:ignore
pub mod view_access {
    pub const INVALID: u16 = 0;
    pub const READ_ONLY: u16 = 1;
    pub const READ_WRITE: u16 = 2;
}

/// cbindgen:ignore
pub mod enter_request_flags {
    pub const DRAIN_CQ: u32 = 0x0000_0001;
    pub const WAIT_SQ: u32 = 0x0000_0002;
    pub const KNOWN_MASK: u32 = DRAIN_CQ | WAIT_SQ;
}

/// cbindgen:ignore
pub mod enter_result_flags {
    pub const SQ_READY: u32 = 0x0000_0001;
    pub const CQ_REMAINING: u32 = 0x0000_0002;
    pub const TIMED_OUT: u32 = 0x0000_0004;
    pub const NOTIFY_BLOCKED: u32 = 0x0000_0008;
    pub const CQ_CONTENDED: u32 = 0x0000_0010;
    pub const KNOWN_MASK: u32 = SQ_READY | CQ_REMAINING | TIMED_OUT | NOTIFY_BLOCKED | CQ_CONTENDED;
}

/// cbindgen:ignore
pub mod retire_mount_action {
    pub const QUERY: u32 = 1;
    pub const ACK: u32 = 2;
}

/// cbindgen:ignore
pub mod retire_mount_state {
    pub const ABSENT: u16 = 1;
    pub const ACTIVE: u16 = 2;
    pub const GRACE: u16 = 3;
    pub const TERMINAL: u16 = 4;
    pub const BOUND_RECONCILING: u16 = 5;
}
