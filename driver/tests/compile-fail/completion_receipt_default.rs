use fsring_core::reqtab::CompletionReceipt;

fn requires_default<T: Default>() {}

pub fn completion_receipt_default() {
    requires_default::<CompletionReceipt>();
}
