use fsring_core::session::{
    ControlBinding, InstalledSession, SessionRegistry, SetupFailure, SetupReservation,
    SetupTransaction, TerminalRendezvous, prepare_installed_setup_publication,
    prepare_installed_setup_rollback,
};

pub fn rollback_after_publish(
    transaction: SetupTransaction,
    registry: &mut SessionRegistry<1>,
    binding: &mut ControlBinding,
    reservation: SetupReservation,
    installed: InstalledSession,
) {
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let _published = prepare_installed_setup_publication(
        transaction,
        registry,
        binding,
        &mut rendezvous,
        reservation,
        installed,
    );
    let _rollback = prepare_installed_setup_rollback(
        transaction,
        SetupFailure::Cancelled,
        registry,
        binding,
        reservation,
        installed,
    );
}
