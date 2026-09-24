#![no_main]
//! Fuzz the SETUP control decoder: arbitrary bytes presented as a daemon SETUP
//! request must be validated or rejected without panicking.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fsring_user::handshake::serve_setup(data);
});
