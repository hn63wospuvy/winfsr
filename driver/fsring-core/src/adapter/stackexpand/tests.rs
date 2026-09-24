use super::{
    CLEANUP_EXPANSION_ATTEMPTS, CleanupExpandFault, CleanupExpansionBudget,
    CleanupExpansionRecourse, ExpandFault, STATUS_NO_MEMORY, resolve, resolve_cleanup,
};

#[test]
fn a_refused_expansion_never_produces_a_result() {
    assert_eq!(resolve::<u32>(false, None), Err(ExpandFault::Refused));
}

#[test]
fn a_refused_expansion_does_not_trust_a_written_slot() {
    // The callout is only reached through a successful expansion, so a slot
    // written under a refusal was written by something this model does not
    // describe. Discarding it is the fail-closed reading.
    assert_eq!(resolve(false, Some(7u32)), Err(ExpandFault::Refused));
}

#[test]
fn a_successful_expansion_with_no_result_is_a_fault() {
    assert_eq!(resolve::<u32>(true, None), Err(ExpandFault::SlotUnwritten));
}

#[test]
fn a_successful_expansion_carries_the_callout_result() {
    assert_eq!(resolve(true, Some(7u32)), Ok(7u32));
}

// `ntstatus.h` values, written out here rather than imported so a wrong
// constant in the module under test cannot also be the expectation.
const SUCCESS: i32 = 0;
const NO_MEMORY: i32 = 0xC000_0017_u32 as i32;
const STACK_OVERFLOW: i32 = 0xC000_00FD_u32 as i32;
const INVALID_PARAMETER_3: i32 = 0xC000_00F1_u32 as i32;
const INVALID_PARAMETER_4: i32 = 0xC000_00F2_u32 as i32;
const INSUFFICIENT_RESOURCES: i32 = 0xC000_009A_u32 as i32;
const PENDING: i32 = 0x0000_0103;

#[test]
fn the_memory_status_is_the_one_ntstatus_h_defines() {
    assert_eq!(STATUS_NO_MEMORY, NO_MEMORY);
}

/// Every pair the reading distinguishes, and a few it must not be fooled by.
#[test]
fn a_cleanup_expansion_is_read_from_its_status_and_its_slot() {
    use CleanupExpandFault as F;
    /// `(status, slot)` and what it must read as.
    type Row = ((i32, Option<u32>), Result<u32, F>);
    let rows: [Row; 12] = [
        ((SUCCESS, Some(7)), Ok(7)),
        ((SUCCESS, None), Err(F::SlotUnwritten)),
        ((NO_MEMORY, None), Err(F::ShortOfMemory)),
        // The four failures Microsoft lists for the Ex routine.
        ((STACK_OVERFLOW, None), Err(F::Refused)),
        ((INVALID_PARAMETER_3, None), Err(F::Refused)),
        ((INVALID_PARAMETER_4, None), Err(F::Refused)),
        // A resource status the DDI is not documented to return is not assumed
        // to clear with time: giving up on it is the conservative reading.
        ((INSUFFICIENT_RESOURCES, None), Err(F::Refused)),
        // Success is STATUS_SUCCESS exactly, not any non-negative status.
        ((PENDING, None), Err(F::Refused)),
        // A failure beside a written slot: the callout may have claimed, so it
        // must never read as the memory refusal that is retried.
        ((NO_MEMORY, Some(7)), Err(F::Contradicted)),
        ((STACK_OVERFLOW, Some(7)), Err(F::Contradicted)),
        ((PENDING, Some(7)), Err(F::Contradicted)),
        ((0xC000_0001_u32 as i32, None), Err(F::Refused)),
    ];
    for ((status, slot), expected) in rows {
        assert_eq!(
            resolve_cleanup(status, slot),
            expected,
            "status {status:#010x} with slot {slot:?}",
        );
    }
}

/// `limit` attempts, `limit - 1` waits, and spent stays spent.
#[test]
fn a_memory_refusal_is_retried_until_the_budget_is_spent() {
    let mut budget = CleanupExpansionBudget::per_arrival();
    for attempt in 1..CLEANUP_EXPANSION_ATTEMPTS {
        assert_eq!(
            budget.answer_refusal(CleanupExpandFault::ShortOfMemory),
            CleanupExpansionRecourse::DelayAndRetry,
            "attempt {attempt}",
        );
    }
    assert_eq!(
        budget.answer_refusal(CleanupExpandFault::ShortOfMemory),
        CleanupExpansionRecourse::Exhausted,
    );
    assert_eq!(
        budget.answer_refusal(CleanupExpandFault::ShortOfMemory),
        CleanupExpansionRecourse::Exhausted,
    );
}

/// At least one retry, and a bound a closing thread can wait out: 1000
/// attempts would be about ten seconds of 10 ms waits.
#[test]
fn the_budget_retries_and_is_bounded() {
    assert!((2..=1000).contains(&CLEANUP_EXPANSION_ATTEMPTS));
}

/// No wait changes these answers, so none is waited for.
#[test]
fn a_refusal_no_wait_can_clear_is_given_up_at_once() {
    for fault in [
        CleanupExpandFault::Refused,
        CleanupExpandFault::Contradicted,
        CleanupExpandFault::SlotUnwritten,
    ] {
        let mut budget = CleanupExpansionBudget::per_arrival();
        assert_eq!(
            budget.answer_refusal(fault),
            CleanupExpansionRecourse::Surrender,
            "{fault:?}",
        );
    }
    // Nor after memory refusals: a permanent answer ends the retry.
    let mut budget = CleanupExpansionBudget::per_arrival();
    assert_eq!(
        budget.answer_refusal(CleanupExpandFault::ShortOfMemory),
        CleanupExpansionRecourse::DelayAndRetry,
    );
    assert_eq!(
        budget.answer_refusal(CleanupExpandFault::Refused),
        CleanupExpansionRecourse::Surrender,
    );
}
