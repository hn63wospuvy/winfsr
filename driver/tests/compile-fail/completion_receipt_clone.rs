use fsring_core::reqtab::CompletionReceipt;

fn requires_clone<T: Clone>() {}

pub fn completion_receipt_clone() {
    requires_clone::<CompletionReceipt>();
}
