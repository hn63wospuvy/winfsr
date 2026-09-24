// 07-cache-mm.md section 6: "only after that linearization may dispatch
// validate the MDL, reserve the common admission quota ticket, map pages, or
// take any further fallible step."
//
// Validating the MDL before linearization is a fallible step with no issue
// number, and 07:294-299 requires that "no paging WRITE with a valid extracted
// range ever returns an unnumbered failure".
use fsring_core::pagingledger::*;

pub fn validate_before_linearizing(write: PagingWrite<Extracted>) -> Issue {
    write.validate_mdl()
}
