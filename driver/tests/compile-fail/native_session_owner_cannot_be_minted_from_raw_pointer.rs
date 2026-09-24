// Native owner envelopes are minted only by consuming authentic setup-state
// rights. These probes intentionally have no such bind right: neither an
// observed address nor the copyable locator identifying its cell is ownership
// authority by itself.
use fsring_core::adapter::lifecycle::{NativeSessionOwner, SessionRootReleaseRight};
use fsring_core::session::{
    ControlBinding, NativeOwnerBindRights, NativeSessionOwnerBindRight, SessionLocator,
    SessionRegistry, SessionRootReleaseBindRight, SetupStage, SetupTransaction,
};

// A default external consumer must not be able to turn even an authentic
// installation of its own into native payload authority. `transaction` is the
// public IdentityBurned cursor because this rustc fixture intentionally links
// only the real fsring-core rlib; a normal Cargo consumer can create it from
// fsring-abi's public SessionIdentity and then run this same chain.
pub fn authentic_external_install_cannot_bind_raw_payloads(
    transaction: SetupTransaction,
    mut binding: ControlBinding,
    shell: *mut u8,
    root: *mut u16,
) {
    let reservation = binding.begin_setup().unwrap();
    let transaction = transaction.stage(SetupStage::LayoutPlanned).unwrap();
    let transaction = transaction.stage(SetupStage::SectionReady).unwrap();
    let transaction = transaction.stage(SetupStage::GrantsReady).unwrap();
    let transaction = transaction.stage(SetupStage::VolumeReady).unwrap();
    let transaction = transaction.stage(SetupStage::ViewsReady).unwrap();
    let transaction = transaction.stage(SetupStage::OutputReady).unwrap();
    let mut registry = SessionRegistry::<1>::new();
    let mut installed = registry
        .install_staging(&transaction, &binding, &reservation)
        .unwrap();
    let rights = installed.take_native_owner_bind_rights().unwrap();
    let (shell_right, root_right, _finalizer_right) = rights.into_parts();
    let _shell_owner: NativeSessionOwner<*mut u8> = shell_right.bind(shell);
    let _root_right: SessionRootReleaseRight<*mut u16> = root_right.bind(root);
}

// Keep all three downstream gates explicit so restoring only the first gate
// cannot make the fixture pass while a later split/bind bridge remains public.
pub fn external_consumer_cannot_split_native_bind_rights(rights: NativeOwnerBindRights) {
    let _ = rights.into_parts();
}

pub fn external_consumer_cannot_bind_shell(right: NativeSessionOwnerBindRight, shell: *mut u8) {
    let _ = right.bind(shell);
}

pub fn external_consumer_cannot_bind_root(right: SessionRootReleaseBindRight, root: *mut u16) {
    let _ = right.bind(root);
}

pub fn raw_pointer_cannot_mint_shell_owner<Shell>(raw: *mut Shell) {
    let _owner: NativeSessionOwner<Shell> = raw.into();
}

pub fn raw_pointer_cannot_mint_root_release<RootRelease>(raw: *mut RootRelease) {
    let _right: SessionRootReleaseRight<RootRelease> = raw.into();
}

pub fn locator_cannot_mint_shell_owner<Shell>(locator: SessionLocator) {
    let _owner: NativeSessionOwner<Shell> = locator.into();
}

pub fn locator_cannot_mint_root_release<RootRelease>(locator: SessionLocator) {
    let _right: SessionRootReleaseRight<RootRelease> = locator.into();
}

fn requires_clone<T: Clone>() {}
fn requires_default<T: Default>() {}

pub fn owner_envelopes_are_affine<Shell, RootRelease>() {
    requires_clone::<NativeSessionOwner<Shell>>();
    requires_default::<NativeSessionOwner<Shell>>();
    requires_clone::<SessionRootReleaseRight<RootRelease>>();
    requires_default::<SessionRootReleaseRight<RootRelease>>();
}

pub fn shell_payload_cannot_be_projected<Shell>(owner: NativeSessionOwner<Shell>) {
    let _payload = owner.payload;
}

pub fn root_payload_cannot_be_projected<RootRelease>(right: SessionRootReleaseRight<RootRelease>) {
    let _payload = right.payload;
}

pub fn shell_owner_has_no_generic_extraction<Shell>(owner: NativeSessionOwner<Shell>) {
    let _inner = owner.into_inner();
    let _storage = owner.into_storage();
}

pub fn root_right_has_no_generic_extraction<RootRelease>(
    right: SessionRootReleaseRight<RootRelease>,
) {
    let _inner = right.into_inner();
    let _storage = right.into_storage();
}
