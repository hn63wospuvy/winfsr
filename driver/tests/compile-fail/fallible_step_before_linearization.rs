// The third of section 6's three named post-linearization steps: "map pages".
//
// Section 6 closes with "or take any further fallible step", an OPEN class no
// fixture count can close. These three fixtures prove the ordering for the
// three steps the document names; the open class is carried in the gate's
// PENDING block rather than claimed as proven.
use fsring_core::pagingledger::*;

pub fn map_before_linearizing(write: PagingWrite<Extracted>) -> Issue {
    write.map_pages()
}
