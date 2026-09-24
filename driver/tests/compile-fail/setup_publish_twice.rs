use fsring_core::session::{
    ControlBinding, InstalledSession, SessionRegistry, SetupReservation, SetupTransaction,
    TerminalRendezvous, prepare_installed_setup_publication,
};

pub fn publish_twice(
    transaction: SetupTransaction,
    registry: &mut SessionRegistry<1>,
    binding: &mut ControlBinding,
    reservation: SetupReservation,
    installed: InstalledSession,
) {
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let _first = prepare_installed_setup_publication(
        transaction,
        registry,
        binding,
        &mut rendezvous,
        reservation,
        installed,
    );
    let _second = prepare_installed_setup_publication(
        transaction,
        registry,
        binding,
        &mut rendezvous,
        reservation,
        installed,
    );
}
