//! Configures the WDK link environment for a library crate, so the hand-written
//! `#[link(name = "ksecdd")]` block in `src/lib.rs` resolves at final link.
fn main() -> Result<(), wdk_build::ConfigError> {
    wdk_build::configure_wdk_library_build()
}
