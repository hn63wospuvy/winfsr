//! Canonical valid SETUP fixtures for tests and the kernel-role harness.
//!
//! Delegates to the production [`crate::handshake`] SETUP path so there is a
//! single source for a valid `SetupRequestV1`.

use fsring_abi::validate::ValidatedSetupRequest;

use crate::handshake::{build_setup_request, encode_setup_request, serve_setup};

/// Validate the canonical SETUP for `ring_count` rings on the Win10-x64 profile.
///
/// # Panics
/// Panics if the canonical request is rejected — that is a fixture bug, not a
/// hostile-input path.
pub(crate) fn valid_setup(ring_count: u32) -> ValidatedSetupRequest {
    let bytes = encode_setup_request(&build_setup_request(ring_count));
    serve_setup(&bytes).expect("canonical SETUP accepted")
}
