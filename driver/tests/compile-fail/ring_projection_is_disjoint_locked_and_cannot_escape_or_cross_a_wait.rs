use fsring_core::adapter::lifecycle::LockedEnterState;
use fsring_core::enter::RingEnterState;

pub fn escape_raw_state(state: &mut RingEnterState) -> &mut RingEnterState {
    let locked = LockedEnterState::from_locked(state);
    locked.state
}
