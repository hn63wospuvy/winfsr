use fsring_core::reqtab::ControlSlot;

pub fn control_slot_private() -> ControlSlot<()> {
    ControlSlot {
        state: unsafe { core::mem::zeroed() },
    }
}
