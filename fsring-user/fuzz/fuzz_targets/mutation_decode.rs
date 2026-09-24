#![no_main]
//! Fuzz the namespace-mutation decoder: an attacker-chosen `MutationV2` envelope
//! or mutation body behind a valid grant must be decoded or rejected without
//! panicking or reading out of bounds. Paths per input — a corrupt envelope
//! (reaching `try_decode` + `validate_mutation_v2`) and a corrupt body behind a
//! valid envelope for each kind whose body decode/validate + offset arithmetic
//! is worth exercising directly: RENAME (`try_decode::<RenameV1>` +
//! `validate_mutation_body_v21` + `owned_name`'s offset arithmetic),
//! SET_BASIC_INFO, SET_ALLOCATION_SIZE (also covers SET_END_OF_FILE /
//! SET_VALID_DATA_LENGTH, which share `SetSizeV1`), and SET_SECURITY (whose
//! body carries the security-descriptor `BlobSlice` offset/length arithmetic).

use libfuzzer_sys::fuzz_target;

use fsring_user::decode_mutation;
use fsring_user::testkit::MutationFixture;

fuzz_target!(|data: &[u8]| {
    // The last byte drives the same_parent_rename hint.
    let same_parent = data.last().copied().unwrap_or(0) & 1 != 0;

    // Path A: an attacker-chosen envelope behind a valid outer grant.
    let fx = MutationFixture::rename();
    fx.overwrite_env(data);
    let _ = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, same_parent);

    // Path B: a valid RENAME envelope with an attacker-chosen body slot.
    let fx = MutationFixture::rename();
    fx.overwrite_body(data);
    let _ = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, same_parent);

    // Path C: a valid SET_BASIC_INFO envelope with an attacker-chosen body slot.
    let fx = MutationFixture::set_basic_info();
    fx.overwrite_body(data);
    let _ = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, same_parent);

    // Path D: a valid SET_ALLOCATION_SIZE envelope with an attacker-chosen body
    // slot (shares `SetSizeV1` with SET_END_OF_FILE / SET_VALID_DATA_LENGTH).
    let fx = MutationFixture::set_allocation_size();
    fx.overwrite_body(data);
    let _ = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, same_parent);

    // Path E: a valid SET_SECURITY envelope with an attacker-chosen body slot
    // (reaches the security-descriptor `BlobSlice` offset/length arithmetic).
    let fx = MutationFixture::set_security();
    fx.overwrite_body(data);
    let _ = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, same_parent);
});
