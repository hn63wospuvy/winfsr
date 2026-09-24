const HEADER: &str = include_str!("../include/fsring_abi.h");

#[test]
fn generated_header_excludes_ring_implementation_internals() {
    for forbidden in [
        "#define MAX_RESERVE_RETRIES",
        "RingProducer",
        "RingConsumer",
        "SingleConsumer",
        "ParkProtocol",
        "PushReceipt",
        "ReservationHooks",
    ] {
        assert!(
            !HEADER.contains(forbidden),
            "generated wire header leaked internal symbol {forbidden}"
        );
    }
}

#[test]
fn generated_header_records_the_pinned_generator_and_guard() {
    assert!(HEADER.contains("Generated with cbindgen:0.29.4"));
    assert!(HEADER.contains("#ifndef FSRING_ABI_H"));
    assert!(HEADER.contains("#define FSRING_ABI_H"));
}

#[test]
fn generated_header_has_a_minimal_freestanding_include_surface() {
    assert!(HEADER.contains("#include <stdint.h>"));

    for forbidden in [
        "#include <stdarg.h>",
        "#include <stdbool.h>",
        "#include <stdlib.h>",
    ] {
        assert!(
            !HEADER.contains(forbidden),
            "generated wire header included unnecessary host header {forbidden}"
        );
    }
}
