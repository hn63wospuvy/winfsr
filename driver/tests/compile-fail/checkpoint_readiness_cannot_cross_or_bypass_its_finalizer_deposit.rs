// A completed R3 checkpoint may reach the finalizer only through the locked,
// consuming deposit transition.  Holding authentic inputs as function
// parameters must not let an external crate reconstruct that transition.
use fsring_core::adapter::fence::{
    FinalDeletePlan, PendingAccessRundown, PendingCompletedPublication, PendingCountedArrivalDrain,
    PendingJoinerDrain, PendingOutcomeSignal, PendingRundownDisposition, PreparedDeleteStorage,
    PreparedDeleteStorageOps, FenceDeletionReadiness, R3FinalizerCell, FinalizerDeposit,
    R3FinalizerKick, R3FinalizerRunningRight,
};
use fsring_core::session::{
    DeleteSessionRight, PreparedDeleteCoreCommit, SessionLocator, SessionRegistry,
    TerminalRendezvous,
};

pub fn cannot_combine_with_a_bare_delete_right<Owners>(
    readiness: FenceDeletionReadiness<Owners>,
    right: DeleteSessionRight,
) {
    let _forged = FinalizerDeposit { readiness, right };
}

pub fn cannot_construct_a_deposit_without_the_locked_boundary<Owners>(
    readiness: FenceDeletionReadiness<Owners>,
    right: DeleteSessionRight,
) {
    let _forged = FinalizerDeposit::new(readiness, right);
}

pub fn cannot_forge_readiness<Owners>(locator: SessionLocator, owners: Owners) {
    let _forged = FenceDeletionReadiness { locator, owners };
}

fn requires_clone<T: Clone>() {}
fn requires_default<T: Default>() {}

pub fn readiness_and_deposit_are_affine<Owners>() {
    requires_clone::<FenceDeletionReadiness<Owners>>();
    requires_default::<FenceDeletionReadiness<Owners>>();
    requires_clone::<FinalizerDeposit<Owners>>();
    requires_default::<FinalizerDeposit<Owners>>();
}

pub fn readiness_cannot_become_a_deposit<Owners>(readiness: FenceDeletionReadiness<Owners>) {
    let _deposit: FinalizerDeposit<Owners> = readiness.into();
}

pub fn readiness_and_right_cannot_become_a_deposit<Owners>(
    readiness: FenceDeletionReadiness<Owners>,
    right: DeleteSessionRight,
) {
    let _deposit: FinalizerDeposit<Owners> = (readiness, right).into();
}

pub fn cannot_forge_a_kick(locator: SessionLocator) {
    let _forged = R3FinalizerKick { locator };
}

pub fn locator_cannot_become_a_kick(locator: SessionLocator) {
    let _kick: R3FinalizerKick = locator.into();
}

pub fn cannot_clone_or_default_a_kick(kick: R3FinalizerKick) {
    let _second = kick.clone();
    let _invented = R3FinalizerKick::default();
}

pub fn readiness_cannot_become_a_kick<Owners>(readiness: FenceDeletionReadiness<Owners>) {
    let _kick: R3FinalizerKick = readiness.into();
}

pub fn deposit_cannot_become_a_kick<Owners>(deposit: FinalizerDeposit<Owners>) {
    let _kick: R3FinalizerKick = deposit.into();
}

pub unsafe fn destructive_storage_operation_requires_the_private_permit<Shell, RootRelease>(
    shell: Shell,
    root: RootRelease,
) where
    Shell: PreparedDeleteStorageOps<RootRelease>,
{
    unsafe { shell.destroy_shell_then_release_root(root) };
}

pub unsafe fn prepared_storage_cannot_bypass_the_core_runner<Shell, RootRelease, NativeReset>(
    storage: PreparedDeleteStorage<Shell, RootRelease, NativeReset>,
) where
    Shell: PreparedDeleteStorageOps<RootRelease>,
{
    let _cursor = unsafe { storage.execute() };
}

pub fn prepared_cursor_transitions_are_not_an_external_execution_api<NativeReset>(
    publication: PendingCompletedPublication<NativeReset>,
    outcome: PendingOutcomeSignal<NativeReset>,
    arrivals: PendingCountedArrivalDrain<NativeReset>,
    joiners: PendingJoinerDrain<NativeReset>,
    rundown: PendingAccessRundown<NativeReset>,
    disposition: PendingRundownDisposition<NativeReset>,
    retired: PendingRundownDisposition<NativeReset>,
) {
    let _ = publication.completed_publication_completed();
    let _ = outcome.outcome_signalled();
    let _ = arrivals.counted_arrivals_drained();
    let _ = joiners.joiners_drained();
    let _ = rundown.access_rundown_completed();
    let _ = disposition.reinitialized_for_reuse();
    let _ = retired.retired_without_reinitialize();
}

pub fn a_copyable_locator_cannot_begin_the_destructive_suffix(locator: SessionLocator) {
    let _cursor = FinalDeletePlan::begin(locator);
}

pub unsafe fn separate_reset_inputs_cannot_reset_a_finalizer<const N: usize, Owners>(
    finalizer: &mut R3FinalizerCell<Owners>,
    registry: &mut SessionRegistry<N>,
    commit: PreparedDeleteCoreCommit,
    running: R3FinalizerRunningRight,
) {
    let _ = unsafe { finalizer.finish_run_and_reset(registry, commit, running) };
}

pub unsafe fn a_rendezvous_cannot_deactivate_without_final_reset_authority(
    rendezvous: &mut TerminalRendezvous,
) {
    unsafe { rendezvous.deactivate_after_delete_prepared() };
}
