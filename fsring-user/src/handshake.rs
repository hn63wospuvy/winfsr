//! The SETUP + ENTER-request control-path exchange.
//!
//! Modeled as an in-process exchange of the real ABI control structures: the
//! daemon builds a `SetupRequestV1`/`EnterRequestV1`, the kernel role validates
//! it with the frozen ABI validators. A later slice can slot a real
//! `DeviceIoControl` transport behind this same API without changing the ring or
//! daemon code, and will add the ENTER *result* (with notification credits and
//! the flags matrix), which is out of this transport-foundation slice's scope.

use fsring_abi::codec::try_encode;
use fsring_abi::control::{
    EnterRequestV1, SetupRequestV1, SlotClassRequest, ENTER_REQUEST_V1_SIZE, SETUP_REQUEST_V1_SIZE,
};
use fsring_abi::features::{FeatureSet, PlatformProfile};
use fsring_abi::limits::{
    MIN_CONTROL_SLOT_SIZE, MIN_K2U_PROGRESS_SLOTS_PER_RING, MIN_NOTIFICATION_CREDIT_SIZE,
    MIN_U2K_PROGRESS_SLOTS_PER_RING,
};
use fsring_abi::msgs::common::{ControlHeader, CONTROL_VERSION_V1};
use fsring_abi::validate::{
    validate_enter_request_v1, validate_setup_request_v1, SessionIdentity, SessionValidationError,
    ValidatedSetupRequest, ValidatedTopology,
};

const ZERO_CLASS: SlotClassRequest = SlotClassRequest {
    slot_size: 0,
    slot_count: 0,
};

const SECURITY_ONLY: FeatureSet = FeatureSet { words: [0x10, 0] };

/// Build the canonical Win10-x64 `SetupRequestV1` for `ring_count` rings
/// (`sq_capacity = 8`, `cq_capacity = 2`). This is the single source for the
/// slice-1 SETUP request; test fixtures delegate here.
pub fn build_setup_request(ring_count: u32) -> SetupRequestV1 {
    let credit_count = ring_count.max(1);
    let credit_size = MIN_NOTIFICATION_CREDIT_SIZE;

    let k2u_slot_classes = [
        SlotClassRequest {
            slot_size: MIN_CONTROL_SLOT_SIZE,
            slot_count: MIN_K2U_PROGRESS_SLOTS_PER_RING * ring_count,
        },
        ZERO_CLASS,
        ZERO_CLASS,
        ZERO_CLASS,
    ];
    // credit_size (2048) < MIN_CONTROL_SLOT_SIZE (131072): a dedicated credit
    // class precedes the u2k progress class, sizes strictly increasing.
    let u2k_slot_classes = [
        SlotClassRequest {
            slot_size: credit_size,
            slot_count: credit_count,
        },
        SlotClassRequest {
            slot_size: MIN_CONTROL_SLOT_SIZE,
            slot_count: MIN_U2K_PROGRESS_SLOTS_PER_RING * ring_count,
        },
        ZERO_CLASS,
        ZERO_CLASS,
    ];

    SetupRequestV1 {
        header: ControlHeader {
            struct_size: SETUP_REQUEST_V1_SIZE,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        abi_major: 2,
        min_abi_minor: 1,
        max_abi_minor: 1,
        reserved0: 0,
        offered_features: SECURITY_ONLY,
        required_features: SECURITY_ONLY,
        required_os_capabilities: FeatureSet { words: [0, 0] },
        ring_count,
        sq_capacity: 8,
        cq_capacity: 2,
        max_inflight: 1,
        k2u_slot_classes,
        u2k_slot_classes,
        notification_credit_count: credit_count,
        notification_credit_size: credit_size,
        flags: 0,
        reserved1: 0,
    }
}

/// Encode a `SetupRequestV1` to its wire bytes (the daemon's SETUP request).
pub fn encode_setup_request(request: &SetupRequestV1) -> [u8; SETUP_REQUEST_V1_SIZE as usize] {
    let mut bytes = [0u8; SETUP_REQUEST_V1_SIZE as usize];
    try_encode(request, &mut bytes).expect("SetupRequestV1 fits its wire size");
    bytes
}

/// Kernel role: validate a daemon's SETUP request bytes on the Win10-x64 profile
/// and negotiate the session, returning the validated request (topology +
/// selected features).
pub fn serve_setup(request_bytes: &[u8]) -> Result<ValidatedSetupRequest, SessionValidationError> {
    validate_setup_request_v1(
        request_bytes,
        PlatformProfile::Win10X64,
        SECURITY_ONLY,
        FeatureSet { words: [0x3, 0] }, // Win10-x64 OS-capability probe
        true,                           // dedicated service SID present
    )
}

/// Build an ENTER request for `identity` on `ring_index`: a non-draining,
/// non-waiting poll (`flags = 0`, `cq_budget = 0`, `timeout_ms = 0`).
pub fn build_enter_request(
    identity: SessionIdentity,
    ring_index: u32,
) -> [u8; ENTER_REQUEST_V1_SIZE as usize] {
    build_enter_request_with(identity, ring_index, 0, 0, 0)
}

/// Build an ENTER request with an explicit mode triple.
///
/// The three wire fields are not independent: the frozen validator refuses
/// DRAIN together with WAIT, a budget without DRAIN, and a timeout without
/// WAIT. Taking them together here keeps the one place that encodes them
/// honest about that.
pub fn build_enter_request_with(
    identity: SessionIdentity,
    ring_index: u32,
    flags: u32,
    cq_budget: u32,
    timeout_ms: u32,
) -> [u8; ENTER_REQUEST_V1_SIZE as usize] {
    let request = EnterRequestV1 {
        header: ControlHeader {
            struct_size: ENTER_REQUEST_V1_SIZE,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        mount_id: identity.mount_id,
        session_epoch: identity.session_epoch,
        ring_index,
        flags,
        cq_budget,
        timeout_ms,
    };
    let mut bytes = [0u8; ENTER_REQUEST_V1_SIZE as usize];
    try_encode(&request, &mut bytes).expect("EnterRequestV1 fits its wire size");
    bytes
}

/// Kernel role: validate a daemon's ENTER request against the session identity
/// and topology established at SETUP.
pub fn serve_enter(
    request_bytes: &[u8],
    identity: SessionIdentity,
    topology: &ValidatedTopology,
) -> Result<EnterRequestV1, SessionValidationError> {
    validate_enter_request_v1(request_bytes, identity, topology)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsring_abi::ids::{BootInstanceId, MountId};

    fn identity() -> SessionIdentity {
        SessionIdentity {
            mount_id: MountId { lo: 1, hi: 1 },
            boot_instance_id: BootInstanceId { lo: 1, hi: 1 },
            session_epoch: 1,
        }
    }

    #[test]
    fn setup_round_trips_topology() {
        let bytes = encode_setup_request(&build_setup_request(1));
        let validated = serve_setup(&bytes).expect("valid SETUP accepted");
        let topology = validated.topology();
        assert_eq!(topology.ring_count(), 1);
        assert_eq!(topology.sq_capacity(), 8);
        assert_eq!(topology.cq_capacity(), 2);
    }

    #[test]
    fn canonical_c4_setup_offers_security_only() {
        let request = build_setup_request(1);
        assert_eq!(request.offered_features, FeatureSet { words: [0x10, 0] });
        assert_eq!(request.required_features, FeatureSet { words: [0x10, 0] });
    }

    #[test]
    fn setup_rejects_abi_minor_zero_only() {
        let mut request = build_setup_request(1);
        request.min_abi_minor = 0;
        request.max_abi_minor = 0; // offers only the non-interoperable pre-release
        let bytes = encode_setup_request(&request);
        assert_eq!(
            serve_setup(&bytes).err(),
            Some(SessionValidationError::RevisionMismatch)
        );
    }

    #[test]
    fn enter_request_round_trips_against_identity() {
        let setup = serve_setup(&encode_setup_request(&build_setup_request(1))).unwrap();
        let topology = setup.topology();
        let bytes = build_enter_request(identity(), 0);
        let request = serve_enter(&bytes, identity(), &topology).expect("valid ENTER accepted");
        assert_eq!(request.ring_index, 0);
        assert_eq!(request.session_epoch, 1);
    }

    #[test]
    fn enter_request_rejects_wrong_session_epoch() {
        let setup = serve_setup(&encode_setup_request(&build_setup_request(1))).unwrap();
        let topology = setup.topology();
        // Daemon builds ENTER for epoch 1; kernel expects a different epoch.
        let bytes = build_enter_request(identity(), 0);
        let mut wrong = identity();
        wrong.session_epoch = 2;
        assert_eq!(
            serve_enter(&bytes, wrong, &topology).err(),
            Some(SessionValidationError::InvalidParameter)
        );
    }
}
