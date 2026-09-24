// 07-cache-mm.md section 5 orders the purge (step 3) AFTER the publication
// (step 2), so that "Cc already knows the new EOF when it discards pages".
// Skipping straight from the cleared veto to the purge must not compile.
//
// Note what this does NOT prove, after a review pointed it out: it starts from
// Truncation<VetoCleared>, so the veto has already run. That the veto comes
// FIRST is proved by truncation_publish_before_veto -- VetoCleared has no
// constructor but mm_veto.
use fsring_core::size::*;

pub fn purge_first(t: Truncation<VetoCleared>) {
    // Step 3 from step 1: the publication (step 2) has not happened.
    let _ = t.purge_tail();
}
