use fsring_core::session::{
    DeleteSessionRight, PreparedDeleteCoreCommit, RegistryLease, StrongSessionRef,
    TerminalSessionRef,
};

fn needs_default<T: Default>() {}

pub fn prove() {
    needs_default::<RegistryLease>();
    needs_default::<StrongSessionRef>();
    needs_default::<TerminalSessionRef>();
    needs_default::<DeleteSessionRight>();
    needs_default::<PreparedDeleteCoreCommit>();
}
