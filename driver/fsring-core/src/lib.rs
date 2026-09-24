//! # FSRING driver pure core.
//!
//! The WDK-free half of the driver: state machines, closed tables and total
//! functions that decide the kernel contract of documents 04-11 without
//! touching a kernel API. `fsring-fsd` compiles this into the `.sys` image;
//! `cargo test` compiles the same source for the host, which is how the driver
//! phase gets real test coverage on a machine that cannot load a driver.
//!
//! Two rules define the crate:
//!
//! 1. **No WDK, no OS.** Its only dependency is the frozen `fsring-abi`.
//!    `tests/dependency_closure.rs` enforces this.
//! 2. **Profiles are values, not `cfg`s.** A profile-dependent decision takes
//!    `PlatformProfile` as a parameter, so one host build exercises all three
//!    profiles. Compile-time selection belongs to `fsring-fsd`.
#![cfg_attr(not(test), no_std)]
// 11-rust-implementation.md section 5: the driver input paths forbid these.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

/// The `#[allow]` proof-comment scanner. Test-only: it is a review tool, and
/// nothing in the kernel image calls it.
#[cfg(test)]
pub mod allowscan;

pub mod adapter;
pub mod alloc;
pub mod bootctx;
pub mod controldev;
pub mod effect;
pub mod enter;
pub mod grant;
pub mod lockrank;
pub mod mapping;
pub mod pagingledger;
pub mod random;
pub mod reqtab;
pub mod resolver;
pub mod session;
pub mod size;
pub mod terminal;
pub mod typestate;
pub mod volume;
