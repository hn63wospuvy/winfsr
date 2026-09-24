// The driver defines its own #[panic_handler]; a second one must not compile.
// This is what makes the replacement load-bearing: an import-table diff cannot
// distinguish it from wdk-panic's loop{} handler, which imports nothing.
#![no_std]

#[panic_handler]
fn first(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[panic_handler]
fn second(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
