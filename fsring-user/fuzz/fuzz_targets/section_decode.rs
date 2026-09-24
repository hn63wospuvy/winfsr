#![no_main]
//! Fuzz the hostile-section validator: arbitrary bytes presented as a mapped
//! section must never panic or read out of bounds.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // SAFETY: `data` covers `data.len()` readable bytes; `validate` only reads
    // within that length (it checks `len` before every access).
    let _ = unsafe { fsring_user::PhysicalLayout::validate(data.as_ptr(), data.len()) };
});
