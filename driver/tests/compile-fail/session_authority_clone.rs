use fsring_core::session::{
    DeleteSessionRight, PreparedDeleteCoreCommit, RegistryLease, StrongSessionRef,
    TerminalSessionRef,
};

fn needs_clone<T: Clone>() {}

pub fn prove() {
    needs_clone::<RegistryLease>();
    needs_clone::<StrongSessionRef>();
    needs_clone::<TerminalSessionRef>();
    needs_clone::<DeleteSessionRight>();
    needs_clone::<PreparedDeleteCoreCommit>();
}
