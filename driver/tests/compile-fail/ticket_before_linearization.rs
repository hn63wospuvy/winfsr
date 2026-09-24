// The second of section 6's three named post-linearization steps: "reserve the
// common admission quota ticket". 06-locking.md section 5.1 owns the ticket;
// section 6 owns WHEN it may be reserved, which is after the issue exists.
use fsring_core::pagingledger::*;

pub fn reserve_before_linearizing(write: PagingWrite<Extracted>) -> Issue {
    write.reserve_ticket()
}
