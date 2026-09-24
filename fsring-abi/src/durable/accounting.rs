/// cbindgen:ignore
pub const MAX_DURABLE_RECOVERY_BYTES_GLOBAL: u64 = 4_294_967_296;
/// cbindgen:ignore
pub const DURABLE_RECORD_ACCOUNTING_OVERHEAD: u64 = 64;
/// cbindgen:ignore
pub const RETIRE_RECEIPT_CHARGE_BYTES: u64 = 128;
/// cbindgen:ignore
pub const RETIRE_RECEIPT_RESERVED_BYTES: u64 = 8_192;
/// cbindgen:ignore
pub const MAX_DURABLE_RETIRE_RECEIPTS: u64 = 64;
/// cbindgen:ignore
pub const MAX_DURABLE_ORDINARY_BYTES_GLOBAL: u64 = 4_294_959_104;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableAccountingV1 {
    pub ordinary_charged_bytes: u64,
    pub receipt_count: u64,
    pub receipt_actual_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableAccountingError {
    ArithmeticOverflow,
    OrdinaryLimitExceeded,
    ReceiptCountExceeded,
    ReceiptBytesMismatch,
    ReceiptReserveExceeded,
    GlobalLimitExceeded,
    Underflow,
}

pub const fn durable_record_charge_v1(
    key_bytes: u64,
    value_bytes: u64,
) -> Result<u64, DurableAccountingError> {
    let sum = match key_bytes.checked_add(value_bytes) {
        Some(value) => value,
        None => return Err(DurableAccountingError::ArithmeticOverflow),
    };
    let rounded = match sum.checked_add(7) {
        Some(value) => value,
        None => return Err(DurableAccountingError::ArithmeticOverflow),
    };
    let aligned = rounded & !7;
    match aligned.checked_add(DURABLE_RECORD_ACCOUNTING_OVERHEAD) {
        Some(value) => Ok(value),
        None => Err(DurableAccountingError::ArithmeticOverflow),
    }
}

pub const fn validate_durable_accounting_v1(
    state: DurableAccountingV1,
) -> Result<(), DurableAccountingError> {
    let expected_receipt_bytes = match state.receipt_count.checked_mul(RETIRE_RECEIPT_CHARGE_BYTES)
    {
        Some(value) => value,
        None => return Err(DurableAccountingError::ArithmeticOverflow),
    };
    if state.ordinary_charged_bytes > MAX_DURABLE_ORDINARY_BYTES_GLOBAL {
        return Err(DurableAccountingError::OrdinaryLimitExceeded);
    }
    if state.receipt_count > MAX_DURABLE_RETIRE_RECEIPTS {
        return Err(DurableAccountingError::ReceiptCountExceeded);
    }
    if state.receipt_actual_bytes != expected_receipt_bytes {
        return Err(DurableAccountingError::ReceiptBytesMismatch);
    }
    if state.receipt_actual_bytes > RETIRE_RECEIPT_RESERVED_BYTES {
        return Err(DurableAccountingError::ReceiptReserveExceeded);
    }
    let total = match state
        .ordinary_charged_bytes
        .checked_add(state.receipt_actual_bytes)
    {
        Some(value) => value,
        None => return Err(DurableAccountingError::ArithmeticOverflow),
    };
    if total > MAX_DURABLE_RECOVERY_BYTES_GLOBAL {
        return Err(DurableAccountingError::GlobalLimitExceeded);
    }
    Ok(())
}

pub const fn checked_add_ordinary_charge_v1(
    state: DurableAccountingV1,
    charge: u64,
) -> Result<DurableAccountingV1, DurableAccountingError> {
    match validate_durable_accounting_v1(state) {
        Ok(()) => {}
        Err(error) => return Err(error),
    }
    let ordinary_charged_bytes = match state.ordinary_charged_bytes.checked_add(charge) {
        Some(value) => value,
        None => return Err(DurableAccountingError::ArithmeticOverflow),
    };
    let next = DurableAccountingV1 {
        ordinary_charged_bytes,
        receipt_count: state.receipt_count,
        receipt_actual_bytes: state.receipt_actual_bytes,
    };
    match validate_durable_accounting_v1(next) {
        Ok(()) => Ok(next),
        Err(error) => Err(error),
    }
}

pub const fn checked_remove_ordinary_charge_v1(
    state: DurableAccountingV1,
    charge: u64,
) -> Result<DurableAccountingV1, DurableAccountingError> {
    match validate_durable_accounting_v1(state) {
        Ok(()) => {}
        Err(error) => return Err(error),
    }
    let ordinary_charged_bytes = match state.ordinary_charged_bytes.checked_sub(charge) {
        Some(value) => value,
        None => return Err(DurableAccountingError::Underflow),
    };
    let next = DurableAccountingV1 {
        ordinary_charged_bytes,
        receipt_count: state.receipt_count,
        receipt_actual_bytes: state.receipt_actual_bytes,
    };
    match validate_durable_accounting_v1(next) {
        Ok(()) => Ok(next),
        Err(error) => Err(error),
    }
}

pub const fn checked_add_retire_receipt_v1(
    state: DurableAccountingV1,
) -> Result<DurableAccountingV1, DurableAccountingError> {
    match validate_durable_accounting_v1(state) {
        Ok(()) => {}
        Err(error) => return Err(error),
    }
    let receipt_count = match state.receipt_count.checked_add(1) {
        Some(value) => value,
        None => return Err(DurableAccountingError::ArithmeticOverflow),
    };
    let receipt_actual_bytes = match state
        .receipt_actual_bytes
        .checked_add(RETIRE_RECEIPT_CHARGE_BYTES)
    {
        Some(value) => value,
        None => return Err(DurableAccountingError::ArithmeticOverflow),
    };
    let next = DurableAccountingV1 {
        ordinary_charged_bytes: state.ordinary_charged_bytes,
        receipt_count,
        receipt_actual_bytes,
    };
    match validate_durable_accounting_v1(next) {
        Ok(()) => Ok(next),
        Err(error) => Err(error),
    }
}

pub const fn checked_remove_retire_receipt_v1(
    state: DurableAccountingV1,
) -> Result<DurableAccountingV1, DurableAccountingError> {
    match validate_durable_accounting_v1(state) {
        Ok(()) => {}
        Err(error) => return Err(error),
    }
    let receipt_count = match state.receipt_count.checked_sub(1) {
        Some(value) => value,
        None => return Err(DurableAccountingError::Underflow),
    };
    let receipt_actual_bytes = match state
        .receipt_actual_bytes
        .checked_sub(RETIRE_RECEIPT_CHARGE_BYTES)
    {
        Some(value) => value,
        None => return Err(DurableAccountingError::Underflow),
    };
    let next = DurableAccountingV1 {
        ordinary_charged_bytes: state.ordinary_charged_bytes,
        receipt_count,
        receipt_actual_bytes,
    };
    match validate_durable_accounting_v1(next) {
        Ok(()) => Ok(next),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        checked_add_ordinary_charge_v1, checked_add_retire_receipt_v1,
        checked_remove_ordinary_charge_v1, checked_remove_retire_receipt_v1,
        durable_record_charge_v1, validate_durable_accounting_v1, DurableAccountingError,
        DurableAccountingV1, MAX_DURABLE_ORDINARY_BYTES_GLOBAL,
    };

    const ZERO: DurableAccountingV1 = DurableAccountingV1 {
        ordinary_charged_bytes: 0,
        receipt_count: 0,
        receipt_actual_bytes: 0,
    };

    #[test]
    fn charges_align_and_overflow_exactly() {
        assert_eq!(durable_record_charge_v1(34, 160), Ok(264));
        for remainder in 0u64..8 {
            assert_eq!(
                durable_record_charge_v1(remainder, 0),
                Ok(((remainder + 7) & !7) + 64)
            );
        }
        assert_eq!(
            durable_record_charge_v1(u64::MAX, 1),
            Err(DurableAccountingError::ArithmeticOverflow)
        );
        assert_eq!(
            durable_record_charge_v1(u64::MAX, 0),
            Err(DurableAccountingError::ArithmeticOverflow)
        );
    }

    #[test]
    fn snapshots_and_transitions_are_inverse() {
        assert_eq!(validate_durable_accounting_v1(ZERO), Ok(()));
        let ordinary = checked_add_ordinary_charge_v1(ZERO, 264).unwrap();
        assert_eq!(checked_remove_ordinary_charge_v1(ordinary, 264), Ok(ZERO));
        let receipt = checked_add_retire_receipt_v1(ZERO).unwrap();
        assert_eq!(checked_remove_retire_receipt_v1(receipt), Ok(ZERO));
        assert_eq!(
            checked_remove_ordinary_charge_v1(ZERO, 1),
            Err(DurableAccountingError::Underflow)
        );
        assert_eq!(
            checked_add_ordinary_charge_v1(ZERO, MAX_DURABLE_ORDINARY_BYTES_GLOBAL + 1),
            Err(DurableAccountingError::OrdinaryLimitExceeded)
        );
    }
}
