use fsring_core::pagingledger::{Interval, IntervalStatus, Issue};
pub fn forge_interval_fields(issue: Issue, status: IntervalStatus) -> Interval {
    Interval {
        start: 0,
        end: 10,
        lowest_issue: issue,
        status,
    }
}
