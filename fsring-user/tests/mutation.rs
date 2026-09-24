//! End-to-end namespace mutations: decode a granted RENAME/LINK/UNLINK/
//! SET_BASIC_INFO/SET_ALLOCATION_SIZE/SET_END_OF_FILE/SET_VALID_DATA_LENGTH/
//! SET_SECURITY through the A2 grant layer, build its result from a provider
//! effect, and confirm the produced bytes re-decode to the expected committed
//! identities.
//!
//! Gated on `testkit` (the kernel-role fixtures live there).
#![cfg(feature = "testkit")]

use fsring_abi::codec::try_decode;
use fsring_abi::ids::{FileId, LinkId};
use fsring_abi::msgs::{
    mutation_kind, LinkResultV2, MutationResultV2, RenameResultV2, SizeState, UnlinkResultV1,
};
use fsring_abi::validate::MessageValidationError;

use fsring_user::testkit::MutationFixture;
use fsring_user::{
    build_mutation_result, decode_mutation, revalidate_context, MutationContext, MutationEffect,
    MutationError, MutationResultError,
};

fn sizes() -> SizeState {
    SizeState {
        allocation_size: 0,
        file_size: 0,
        valid_data_length: 0,
        size_epoch: 1,
    }
}

fn effect() -> MutationEffect {
    MutationEffect {
        file_id: FileId { lo: 0x100, hi: 0 },
        new_link_id: LinkId { lo: 0x101, hi: 0 },
        replaced: None,
        link_count: 1,
        namespace_generation: 2,
        source_parent_generation: 2,
        target_parent_generation: 2,
        parent_generation: 2,
        sizes: sizes(),
        retained_sizes: sizes(),
        volume_commit_sequence: 5,
        security_generation: 0,
    }
}

#[test]
fn rename_end_to_end() {
    let fx = MutationFixture::rename();
    let req = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
    let bytes = build_mutation_result(&req, &effect(), &fx.table, fx.owner).expect("result");

    let result: MutationResultV2 = try_decode(&bytes.result).expect("result envelope");
    assert_eq!(result.mutation_kind, mutation_kind::RENAME);
    assert_eq!(result.op_id.lo, req.op_id().lo);
    assert_eq!(result.namespace_generation, 2);

    // RENAME preserves the body's source link id.
    let kr: RenameResultV2 = try_decode(&bytes.kind_result).expect("rename kind result");
    assert_eq!(kr.link_id, fx.source_link_id);
    assert_eq!(kr.file_id, FileId { lo: 0x100, hi: 0 });
}

#[test]
fn link_end_to_end() {
    let fx = MutationFixture::link();
    let req = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
    let bytes = build_mutation_result(&req, &effect(), &fx.table, fx.owner).expect("result");

    let result: MutationResultV2 = try_decode(&bytes.result).expect("result envelope");
    assert_eq!(result.mutation_kind, mutation_kind::LINK);
    // LINK returns the new (distinct) link id.
    let kr: LinkResultV2 = try_decode(&bytes.kind_result).expect("link kind result");
    assert_eq!(kr.new_link_id, LinkId { lo: 0x101, hi: 0 });
}

#[test]
fn unlink_end_to_end() {
    let fx = MutationFixture::unlink();
    let req = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
    let bytes = build_mutation_result(&req, &effect(), &fx.table, fx.owner).expect("result");

    let result: MutationResultV2 = try_decode(&bytes.result).expect("result envelope");
    assert_eq!(result.mutation_kind, mutation_kind::UNLINK);
    // UNLINK returns the body's link id as removed.
    let kr: UnlinkResultV1 = try_decode(&bytes.kind_result).expect("unlink kind result");
    assert_eq!(kr.removed_link_id, fx.source_link_id);
}

#[test]
fn set_basic_info_end_to_end() {
    let fx = MutationFixture::set_basic_info();
    let req = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
    let bytes = build_mutation_result(&req, &effect(), &fx.table, fx.owner).expect("result");

    let result: MutationResultV2 = try_decode(&bytes.result).expect("result envelope");
    assert_eq!(result.mutation_kind, mutation_kind::SET_BASIC_INFO);
    assert_eq!(result.namespace_generation, 2);
    assert_eq!(result.security_generation, 0);
    // SET_BASIC_INFO carries no kind result.
    assert!(bytes.kind_result.is_empty());
}

/// An `effect()` with `sizes`/`retained_sizes` overridden for a size-kind
/// result (the metadata/namespace lanes are irrelevant to these kinds).
fn size_effect(sizes: SizeState, retained_sizes: SizeState) -> MutationEffect {
    let mut e = effect();
    e.sizes = sizes;
    e.retained_sizes = retained_sizes;
    e
}

#[test]
fn set_allocation_size_end_to_end() {
    let fx = MutationFixture::set_allocation_size();
    let req = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
    let eff = size_effect(
        SizeState {
            allocation_size: 8192,
            file_size: 4096,
            valid_data_length: 4096,
            size_epoch: 2,
        },
        SizeState {
            allocation_size: 4096,
            file_size: 4096,
            valid_data_length: 4096,
            size_epoch: 1,
        },
    );
    let bytes = build_mutation_result(&req, &eff, &fx.table, fx.owner).expect("result");

    let result: MutationResultV2 = try_decode(&bytes.result).expect("result envelope");
    assert_eq!(result.mutation_kind, mutation_kind::SET_ALLOCATION_SIZE);
    assert_eq!(result.namespace_generation, 0);
    assert_eq!(result.sizes.size_epoch, 2);
    // Size kinds carry no kind result.
    assert!(bytes.kind_result.is_empty());
}

#[test]
fn set_end_of_file_end_to_end() {
    let fx = MutationFixture::set_end_of_file();
    let req = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
    let eff = size_effect(
        SizeState {
            allocation_size: 8192,
            file_size: 4096,
            valid_data_length: 2048,
            size_epoch: 2,
        },
        SizeState {
            allocation_size: 8192,
            file_size: 2048,
            valid_data_length: 2048,
            size_epoch: 1,
        },
    );
    let bytes = build_mutation_result(&req, &eff, &fx.table, fx.owner).expect("result");

    let result: MutationResultV2 = try_decode(&bytes.result).expect("result envelope");
    assert_eq!(result.mutation_kind, mutation_kind::SET_END_OF_FILE);
    assert_eq!(result.namespace_generation, 0);
    assert_eq!(result.sizes.size_epoch, 2);
    assert!(bytes.kind_result.is_empty());
}

#[test]
fn set_valid_data_length_end_to_end() {
    let fx = MutationFixture::set_valid_data_length();
    let req = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
    let eff = size_effect(
        SizeState {
            allocation_size: 8192,
            file_size: 4096,
            valid_data_length: 4096,
            size_epoch: 2,
        },
        SizeState {
            allocation_size: 8192,
            file_size: 4096,
            valid_data_length: 2048,
            size_epoch: 1,
        },
    );
    let bytes = build_mutation_result(&req, &eff, &fx.table, fx.owner).expect("result");

    let result: MutationResultV2 = try_decode(&bytes.result).expect("result envelope");
    assert_eq!(result.mutation_kind, mutation_kind::SET_VALID_DATA_LENGTH);
    assert_eq!(result.namespace_generation, 0);
    assert_eq!(result.sizes.size_epoch, 2);
    assert!(bytes.kind_result.is_empty());
}

#[test]
fn set_security_end_to_end() {
    let fx = MutationFixture::set_security();
    let req = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
    let mut eff = effect();
    eff.security_generation = 2;
    eff.namespace_generation = 0;
    let bytes = build_mutation_result(&req, &eff, &fx.table, fx.owner).expect("result");

    let result: MutationResultV2 = try_decode(&bytes.result).expect("result envelope");
    assert_eq!(result.mutation_kind, mutation_kind::SET_SECURITY);
    assert_eq!(result.security_generation, 2);
    assert_eq!(result.namespace_generation, 0);
    // SET_SECURITY carries no kind result.
    assert!(bytes.kind_result.is_empty());
}

#[test]
fn mutation_context_revalidation_rejects_unequal_parents_without_refetch() {
    let fixture = MutationFixture::rename_unequal_parents();
    let request = decode_mutation(
        &fixture.sqe,
        &fixture.table,
        fixture.section(),
        fixture.owner,
        false,
    )
    .expect("conservative decode accepts unequal parent generations");

    assert!(matches!(
        revalidate_context(
            request,
            &fixture.table,
            fixture.owner,
            MutationContext {
                same_parent_rename: true,
            },
        ),
        Err(MutationError::Message(MessageValidationError::Relationship))
    ));
}

#[test]
fn mutation_context_flag_and_generation_accessors_drive_result_validation() {
    let fixture = MutationFixture::rename();
    let request = decode_mutation(
        &fixture.sqe,
        &fixture.table,
        fixture.section(),
        fixture.owner,
        false,
    )
    .expect("decode rename");
    assert_eq!(request.expected_namespace_generation(), 1);
    assert_eq!(request.expected_size_epoch(), 0);
    assert_eq!(request.expected_security_generation(), 0);
    assert!(!request.same_parent_rename());

    let request = revalidate_context(
        request,
        &fixture.table,
        fixture.owner,
        MutationContext {
            same_parent_rename: true,
        },
    )
    .expect("equal generations revalidate");
    assert!(request.same_parent_rename());

    let mut inconsistent = effect();
    inconsistent.target_parent_generation = 3;
    assert_eq!(
        build_mutation_result(&request, &inconsistent, &fixture.table, fixture.owner),
        Err(MutationResultError::Message(
            MessageValidationError::Relationship
        ))
    );
}
