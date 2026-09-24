#![no_main]
//! Fuzz context revalidation over an owned copy of a validator-accepted
//! mutation. The backing section is dropped before revalidation, proving the
//! operation can use only retained body bytes and grant metadata. Stable valid
//! fixtures must succeed except for the exact unequal-parent relationship;
//! mutated bodies may return typed errors, while successes preserve the copied
//! request's kind, body variant, generations, and selected context.

use fsring_abi::msgs::mutation_kind;
use fsring_abi::validate::MessageValidationError;
use fsring_user::testkit::MutationFixture;
use fsring_user::{
    decode_mutation, revalidate_context, DecodedBody, MutationContext, MutationError,
    MutationRequest,
};
use libfuzzer_sys::fuzz_target;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MutationCase {
    Rename,
    RenameUnequalParents,
    Link,
    Unlink,
    SetBasicInfo,
    SetAllocationSize,
    SetEndOfFile,
    SetValidDataLength,
    SetSecurity,
}

fn case_for_selector(selector: u8) -> MutationCase {
    match selector % 9 {
        0 => MutationCase::Rename,
        1 => MutationCase::RenameUnequalParents,
        2 => MutationCase::Link,
        3 => MutationCase::Unlink,
        4 => MutationCase::SetBasicInfo,
        5 => MutationCase::SetAllocationSize,
        6 => MutationCase::SetEndOfFile,
        7 => MutationCase::SetSecurity,
        _ => MutationCase::SetValidDataLength,
    }
}

impl MutationCase {
    fn mutation_kind(self) -> u16 {
        match self {
            MutationCase::Rename | MutationCase::RenameUnequalParents => mutation_kind::RENAME,
            MutationCase::Link => mutation_kind::LINK,
            MutationCase::Unlink => mutation_kind::UNLINK,
            MutationCase::SetBasicInfo => mutation_kind::SET_BASIC_INFO,
            MutationCase::SetAllocationSize => mutation_kind::SET_ALLOCATION_SIZE,
            MutationCase::SetEndOfFile => mutation_kind::SET_END_OF_FILE,
            MutationCase::SetValidDataLength => mutation_kind::SET_VALID_DATA_LENGTH,
            MutationCase::SetSecurity => mutation_kind::SET_SECURITY,
        }
    }
}

fn fixture_for_case(case: MutationCase) -> MutationFixture {
    match case {
        MutationCase::Rename => MutationFixture::rename(),
        MutationCase::RenameUnequalParents => MutationFixture::rename_unequal_parents(),
        MutationCase::Link => MutationFixture::link(),
        MutationCase::Unlink => MutationFixture::unlink(),
        MutationCase::SetBasicInfo => MutationFixture::set_basic_info(),
        MutationCase::SetAllocationSize => MutationFixture::set_allocation_size(),
        MutationCase::SetEndOfFile => MutationFixture::set_end_of_file(),
        MutationCase::SetValidDataLength => MutationFixture::set_valid_data_length(),
        MutationCase::SetSecurity => MutationFixture::set_security(),
    }
}

fn accepts_stable_revalidation(
    result: &Result<MutationRequest, MutationError>,
    expect_relationship: bool,
) -> bool {
    match (result, expect_relationship) {
        (Ok(_), false) => true,
        (Err(MutationError::Message(MessageValidationError::Relationship)), true) => true,
        _ => false,
    }
}

fn assert_success_invariants(
    accepted: &MutationRequest,
    case: MutationCase,
    context: MutationContext,
    expected_generations: (u64, u64, u64),
) {
    assert_eq!(accepted.mutation_kind(), case.mutation_kind());
    assert_eq!(accepted.same_parent_rename(), context.same_parent_rename);
    assert_eq!(
        (
            accepted.expected_namespace_generation(),
            accepted.expected_size_epoch(),
            accepted.expected_security_generation(),
        ),
        expected_generations,
        "context validation must preserve the copied request generations",
    );
    let body_matches = matches!(
        (case, accepted.body()),
        (
            MutationCase::Rename | MutationCase::RenameUnequalParents,
            DecodedBody::Rename { .. },
        ) | (MutationCase::Link, DecodedBody::Link { .. })
            | (MutationCase::Unlink, DecodedBody::Unlink { .. })
            | (MutationCase::SetBasicInfo, DecodedBody::SetBasicInfo { .. },)
            | (
                MutationCase::SetAllocationSize,
                DecodedBody::SetAllocationSize { .. },
            )
            | (MutationCase::SetEndOfFile, DecodedBody::SetEndOfFile { .. },)
            | (
                MutationCase::SetValidDataLength,
                DecodedBody::SetValidDataLength { .. },
            )
            | (MutationCase::SetSecurity, DecodedBody::SetSecurity { .. },)
    );
    assert!(body_matches, "the copied body must still match its kind");
}

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        case_for_selector(8),
        MutationCase::SetValidDataLength,
        "selector 8 must keep SET_VALID_DATA_LENGTH reachable",
    );
    assert!(
        !accepts_stable_revalidation(&Err(MutationError::Truncated), false),
        "an arbitrary typed error must not satisfy a stable valid-fixture oracle",
    );
    let relationship = Err(MutationError::Message(MessageValidationError::Relationship));
    assert!(accepts_stable_revalidation(&relationship, true));
    assert!(!accepts_stable_revalidation(&relationship, false));

    let selector = data.first().copied().unwrap_or(0);
    let context_byte = data.get(1).copied().unwrap_or(0);
    let case = case_for_selector(selector);
    let fixture = fixture_for_case(case);
    let stable = selector & 0x80 != 0;

    // Keep one stable valid-body lane so both successful and rejecting context
    // paths remain continuously reachable. The other lane replaces the entire
    // body slot with attacker bytes before the conservative decode.
    if !stable {
        fixture.overwrite_body(data.get(2..).unwrap_or_default());
    }
    let request = match decode_mutation(
        &fixture.sqe,
        &fixture.table,
        fixture.section(),
        fixture.owner,
        false,
    ) {
        Ok(request) => request.clone(),
        Err(error) if stable => panic!("stable valid fixture failed to decode: {error:?}"),
        Err(_) => return,
    };
    assert_eq!(request.mutation_kind(), case.mutation_kind());
    let expected_generations = (
        request.expected_namespace_generation(),
        request.expected_size_epoch(),
        request.expected_security_generation(),
    );

    let (harness, table, _sqe, owner) = fixture.into_parts();
    drop(harness); // no section remains available to `revalidate_context`
    let context = MutationContext {
        same_parent_rename: context_byte & 1 != 0,
    };

    let result = revalidate_context(request, &table, owner, context);
    let expect_relationship =
        stable && case == MutationCase::RenameUnequalParents && context.same_parent_rename;

    if stable {
        assert!(
            accepts_stable_revalidation(&result, expect_relationship),
            "stable fixture produced an unexpected revalidation outcome",
        );
    }

    if let Ok(accepted) = result {
        assert_success_invariants(&accepted, case, context, expected_generations);
    }
});
