use fsring_core::session::{SessionLocator, StrongSessionRef};

pub fn forge(seed: SessionLocator) -> SessionLocator {
    SessionLocator {
        slot_index: 0,
        ..seed
    }
}

pub fn project(reference: StrongSessionRef) -> StrongSessionRef {
    let StrongSessionRef { authority } = reference;
    StrongSessionRef { authority }
}
