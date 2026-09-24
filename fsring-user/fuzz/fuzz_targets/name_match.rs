#![no_main]
//! Fuzz the name matcher: arbitrary bytes split into a (pattern, name) UTF-16
//! pair must compile-and-match without panicking or reading out of bounds. The
//! match result is the OS's contract; we only assert no crash.

use fsring_user::name_in_expression;
use libfuzzer_sys::fuzz_target;

fn to_u16(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

fuzz_target!(|data: &[u8]| {
    // First byte picks the split point (in u16 units) between pattern and name.
    if data.is_empty() {
        return;
    }
    let split = (data[0] as usize) * 2;
    let rest = &data[1..];
    let split = split.min(rest.len());
    let pattern = to_u16(&rest[..split]);
    let name = to_u16(&rest[split..]);
    let _ = name_in_expression(&pattern, &name);
});
