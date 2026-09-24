//! WDK-free driver-load and unload choreography.
//!
//! `02-transport.md` section 10.10 and `10-lifecycle.md` section 3 fix the two
//! permanent BootContext objects, their exact attributes, access masks, and
//! security descriptor, the bounded event-lock protocol, and the order in which
//! a load may publish its endpoints. This module owns all of that as pure data
//! and a closed ordered plan, so the host test binary can prove it on a machine
//! that cannot load a driver. `fsring-fsd` translates one typed effect into
//! exactly one native call and reports the matching outcome; it restates none
//! of the transition order and none of these payloads.
//!
//! A [`LoadPlan`] is an ordering and ownership *model*, never a resource owner.
//! It cannot claim that a handle, mapping, device, or registration exists: the
//! native executor holds the real handles in its own affine wrappers, and the
//! [`LoadRollbackPlan`] only says in which order the ones it still owns must be
//! unwound.

use super::AdapterPlanError;
use fsring_abi::control::{
    BOOT_CONTEXT_LOCK_NAME, BOOT_CONTEXT_SECTION_BYTES, BOOT_CONTEXT_SECTION_NAME,
};

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// Object Manager names
// ---------------------------------------------------------------------------

/// `\KernelObjects\FsRingBootContextLock-v1`, the permanent publication lock.
///
/// Widened from the frozen ABI constant rather than retyped here, so the
/// driver cannot drift away from the name the wire authority publishes.
pub const BOOT_CONTEXT_LOCK_OBJECT_NAME: [u16; 39] =
    super::ascii_utf16_name(BOOT_CONTEXT_LOCK_NAME);

/// `\KernelObjects\FsRingBootContext-v1`, the permanent 64-KiB section.
pub const BOOT_CONTEXT_SECTION_OBJECT_NAME: [u16; 35] =
    super::ascii_utf16_name(BOOT_CONTEXT_SECTION_NAME);

// ---------------------------------------------------------------------------
// Object attributes, access masks, and creation payloads
// ---------------------------------------------------------------------------

/// `OBJ_KERNEL_HANDLE`: the handle is invisible to user mode.
pub const OBJ_KERNEL_HANDLE: u32 = 0x0000_0200;
/// `OBJ_PERMANENT`: the object outlives its last handle.
pub const OBJ_PERMANENT: u32 = 0x0000_0010;
/// `OBJ_CASE_INSENSITIVE`: the documented lookup rule for both names.
pub const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
/// `OBJ_OPENIF`, declared only so its exclusion is checkable. It would turn a
/// create into a silent open and erase the collision branch entirely.
pub const OBJ_OPENIF: u32 = 0x0000_0080;

/// The exact attribute mask used by both permanent BootContext objects.
pub const BOOT_OBJECT_ATTRIBUTES: u32 = OBJ_KERNEL_HANDLE | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE;

/// `ACCESS_SYSTEM_SECURITY`, declared only so its absence is checkable.
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;

/// `EVENT_QUERY_STATE | EVENT_MODIFY_STATE | SYNCHRONIZE | READ_CONTROL |
/// DELETE`.
pub const BOOT_LOCK_EVENT_ACCESS: u32 = 0x0013_0003;

/// `SECTION_MAP_EXECUTE`, declared only so its absence is checkable.
pub const SECTION_MAP_EXECUTE: u32 = 0x0000_0008;
/// `SECTION_MAP_EXECUTE_EXPLICIT`, declared only so its absence is checkable.
pub const SECTION_MAP_EXECUTE_EXPLICIT: u32 = 0x0000_0020;

/// `SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ | READ_CONTROL |
/// DELETE`; never an executable mapping right.
pub const BOOT_SECTION_ACCESS: u32 = 0x0003_0007;

/// `SEC_COMMIT`.
pub const SEC_COMMIT: u32 = 0x0800_0000;
/// `PAGE_READWRITE`.
pub const PAGE_READWRITE: u32 = 0x0000_0004;

/// `EVENT_TYPE::SynchronizationEvent`.
pub const SYNCHRONIZATION_EVENT: u32 = 1;
/// `EVENT_TYPE::NotificationEvent`, declared so the rejected subtype is named.
pub const NOTIFICATION_EVENT: u32 = 0;

/// `KPROCESSOR_MODE::KernelMode`.
pub const KERNEL_MODE: u8 = 0;
/// `KWAIT_REASON::Executive`.
pub const WAIT_REASON_EXECUTIVE: u32 = 0;
/// `IO_NO_INCREMENT`.
pub const IO_NO_INCREMENT: u8 = 0;
/// `sizeof(ACL)`: an empty ACL is exactly its header.
pub const ACL_HEADER_BYTES: u32 = 8;

/// `ZwCreateEvent` payload for the permanent publication lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootLockEventCreateParameters {
    pub desired_access: u32,
    pub object_attributes: u32,
    pub event_type: u32,
    pub initial_state: bool,
}

/// The event is created already signaled, so the first acquirer wins its wait
/// immediately rather than deadlocking against a never-set object.
pub const BOOT_LOCK_EVENT_CREATE: BootLockEventCreateParameters = BootLockEventCreateParameters {
    desired_access: BOOT_LOCK_EVENT_ACCESS,
    object_attributes: BOOT_OBJECT_ATTRIBUTES,
    event_type: SYNCHRONIZATION_EVENT,
    initial_state: true,
};

/// `ZwCreateSection` payload for the permanent BootContext section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootSectionCreateParameters {
    pub desired_access: u32,
    pub object_attributes: u32,
    pub maximum_size: u64,
    pub page_protection: u32,
    pub allocation_attributes: u32,
    /// Pagefile-backed: `FileHandle = NULL`.
    pub file_handle_is_null: bool,
}

pub const BOOT_SECTION_CREATE: BootSectionCreateParameters = BootSectionCreateParameters {
    desired_access: BOOT_SECTION_ACCESS,
    object_attributes: BOOT_OBJECT_ATTRIBUTES,
    maximum_size: BOOT_CONTEXT_SECTION_BYTES as u64,
    page_protection: PAGE_READWRITE,
    allocation_attributes: SEC_COMMIT,
    file_handle_is_null: true,
};

/// `KeWaitForSingleObject` payload for one bounded lock acquisition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootLockWaitParameters {
    pub wait_reason: u32,
    pub processor_mode: u8,
    pub alertable: bool,
    /// Negative 100-nanosecond units: a relative, not absolute, deadline.
    pub relative_timeout_100ns: i64,
}

pub const BOOT_LOCK_WAIT: BootLockWaitParameters = BootLockWaitParameters {
    wait_reason: WAIT_REASON_EXECUTIVE,
    processor_mode: KERNEL_MODE,
    alertable: false,
    relative_timeout_100ns: -300_000_000,
};

/// `KeSetEvent` payload for the one release a guard performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootLockReleaseParameters {
    pub priority_increment: u8,
    pub wait: bool,
}

pub const BOOT_LOCK_RELEASE: BootLockReleaseParameters = BootLockReleaseParameters {
    priority_increment: IO_NO_INCREMENT,
    wait: false,
};

// ---------------------------------------------------------------------------
// Open / create / reopen status protocol
// ---------------------------------------------------------------------------

/// `STATUS_SUCCESS`.
pub const STATUS_SUCCESS: i32 = 0;
/// `STATUS_OBJECT_NAME_NOT_FOUND`: the only status that permits a create.
pub const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
/// `STATUS_OBJECT_NAME_COLLISION`: the only status that permits a reopen.
pub const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;

/// What an open of a permanent BootContext object permits next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenDecision {
    Opened,
    Create,
    Fail,
}

/// What a create of a permanent BootContext object permits next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateDecision {
    Created,
    Reopen,
    Fail,
}

/// What the single post-collision reopen permits next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReopenDecision {
    Opened,
    Fail,
}

/// Exact `STATUS_SUCCESS` opens; exact `STATUS_OBJECT_NAME_NOT_FOUND` creates;
/// every other status, informational ones included, fails the load unchanged.
pub const fn decide_open(status: i32) -> OpenDecision {
    if status == STATUS_SUCCESS {
        OpenDecision::Opened
    } else if status == STATUS_OBJECT_NAME_NOT_FOUND {
        OpenDecision::Create
    } else {
        OpenDecision::Fail
    }
}

/// Exact `STATUS_SUCCESS` creates; exact `STATUS_OBJECT_NAME_COLLISION` means
/// another loader won the race and permits exactly one reopen.
pub const fn decide_create(status: i32) -> CreateDecision {
    if status == STATUS_SUCCESS {
        CreateDecision::Created
    } else if status == STATUS_OBJECT_NAME_COLLISION {
        CreateDecision::Reopen
    } else {
        CreateDecision::Fail
    }
}

/// The reopen is the last attempt: only exact `STATUS_SUCCESS` continues.
pub const fn decide_reopen(status: i32) -> ReopenDecision {
    if status == STATUS_SUCCESS {
        ReopenDecision::Opened
    } else {
        ReopenDecision::Fail
    }
}

// ---------------------------------------------------------------------------
// Security descriptor and section geometry
// ---------------------------------------------------------------------------

/// The facts `ObGetObjectSecurity` yields about one BootContext object.
///
/// Booleans, not a descriptor pointer: the WDK-free half decides, the native
/// half projects. `ObReleaseObjectSecurity` always pairs with the query on the
/// native side, whatever this decision returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootObjectSecurity {
    pub owner_is_local_system: bool,
    pub group_is_local_system: bool,
    pub dacl_present: bool,
    pub dacl_null: bool,
    pub dacl_protected: bool,
    pub dacl_ace_count: u32,
    pub dacl_size: u32,
    pub sacl_present: bool,
}

/// LocalSystem owner and group, a present protected non-null empty DACL, and
/// no SACL: no user-mode principal can open or map either object.
pub const CANONICAL_BOOT_OBJECT_SECURITY: BootObjectSecurity = BootObjectSecurity {
    owner_is_local_system: true,
    group_is_local_system: true,
    dacl_present: true,
    dacl_null: false,
    dacl_protected: true,
    dacl_ace_count: 0,
    dacl_size: ACL_HEADER_BYTES,
    sacl_present: false,
};

/// Accept only the exact canonical descriptor. A null DACL grants everyone, an
/// unprotected one can inherit an ACE, and an ACL longer than its header can
/// carry ACE bytes an empty count does not describe.
pub const fn boot_object_security_is_canonical(facts: BootObjectSecurity) -> bool {
    facts.owner_is_local_system
        && facts.group_is_local_system
        && facts.dacl_present
        && !facts.dacl_null
        && facts.dacl_protected
        && facts.dacl_ace_count == 0
        && facts.dacl_size == ACL_HEADER_BYTES
        && !facts.sacl_present
}

/// `SE_DACL_PRESENT`.
const SE_DACL_PRESENT: u16 = 0x0004;
/// `SE_SACL_PRESENT`.
const SE_SACL_PRESENT: u16 = 0x0010;
/// `SE_DACL_PROTECTED`.
const SE_DACL_PROTECTED: u16 = 0x1000;
/// `SE_SELF_RELATIVE`.
const SE_SELF_RELATIVE: u16 = 0x8000;

/// `SECURITY_DESCRIPTOR_RELATIVE` header length.
const SD_HEADER_BYTES: usize = 20;
/// `SECURITY_DESCRIPTOR_REVISION`.
const SD_REVISION: u8 = 1;
/// `ACL_REVISION`.
const ACL_REVISION: u8 = 2;
/// The `S-1-5-18` (LocalSystem) SID, byte for byte: revision 1, one
/// subauthority, `SECURITY_NT_AUTHORITY`, and `SECURITY_LOCAL_SYSTEM_RID`.
const LOCAL_SYSTEM_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

/// The exact self-relative descriptor both permanent objects are created with.
///
/// Written as bytes rather than assembled through `Rtl*` helpers so that the
/// image the driver *creates* is literally the image its post-create
/// validation *accepts*; an object that rejects itself on the next load is the
/// failure this constant exists to make impossible.
pub const CANONICAL_BOOT_SECURITY_DESCRIPTOR: [u8; 52] = [
    // SECURITY_DESCRIPTOR_RELATIVE.
    SD_REVISION,
    0, // Sbz1
    0x04,
    0x90, // Control = SE_DACL_PRESENT | SE_DACL_PROTECTED | SE_SELF_RELATIVE
    20,
    0,
    0,
    0, // Owner offset
    32,
    0,
    0,
    0, // Group offset
    0,
    0,
    0,
    0, // Sacl offset: no SACL
    44,
    0,
    0,
    0, // Dacl offset
    // Owner: S-1-5-18.
    1,
    1,
    0,
    0,
    0,
    0,
    0,
    5,
    18,
    0,
    0,
    0,
    // Group: S-1-5-18.
    1,
    1,
    0,
    0,
    0,
    0,
    0,
    5,
    18,
    0,
    0,
    0,
    // Present, protected, non-null, empty DACL: exactly an ACL header.
    ACL_REVISION,
    0,
    8,
    0,
    0,
    0,
    0,
    0,
];

const _: () = assert!(
    CANONICAL_BOOT_SECURITY_DESCRIPTOR.len() == 52,
    "the canonical descriptor is a fixed 52-byte image"
);

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let field: [u8; 2] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(field))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let field: [u8; 4] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(field))
}

/// Is the SID at `offset` exactly `S-1-5-18`?
fn sid_is_local_system(bytes: &[u8], offset: usize) -> Option<bool> {
    let end = offset.checked_add(LOCAL_SYSTEM_SID.len())?;
    let sid = bytes.get(offset..end)?;
    Some(sid == LOCAL_SYSTEM_SID)
}

/// Project the facts of a self-relative security descriptor.
///
/// The input is bytes the Object Manager owns, so every offset is bounds
/// checked against the caller's own length and a malformed image is `None`
/// rather than a partially trusted [`BootObjectSecurity`]. The predicate
/// [`boot_object_security_is_canonical`] then decides; parsing successfully is
/// never by itself acceptance.
pub fn parse_boot_object_security(bytes: &[u8]) -> Option<BootObjectSecurity> {
    if bytes.len() < SD_HEADER_BYTES {
        return None;
    }
    if bytes.first().copied()? != SD_REVISION {
        return None;
    }
    let control = read_u16_le(bytes, 2)?;
    if control & SE_SELF_RELATIVE == 0 {
        // An absolute descriptor stores pointers in these fields. Reading them
        // as offsets would be a wild read, so it is rejected outright.
        return None;
    }

    let owner_offset = read_u32_le(bytes, 4)?;
    let group_offset = read_u32_le(bytes, 8)?;
    let dacl_offset = read_u32_le(bytes, 16)?;

    let owner_is_local_system =
        sid_is_local_system(bytes, usize::try_from(owner_offset).ok()?).unwrap_or(false);
    let group_is_local_system =
        sid_is_local_system(bytes, usize::try_from(group_offset).ok()?).unwrap_or(false);
    if owner_offset == 0 || group_offset == 0 {
        return None;
    }
    // An offset that leaves the image is malformed, not merely non-canonical.
    if sid_is_local_system(bytes, usize::try_from(owner_offset).ok()?).is_none()
        || sid_is_local_system(bytes, usize::try_from(group_offset).ok()?).is_none()
    {
        return None;
    }

    let dacl_present = control & SE_DACL_PRESENT != 0;
    let sacl_present = control & SE_SACL_PRESENT != 0;
    let dacl_null = dacl_present && dacl_offset == 0;

    let (dacl_size, dacl_ace_count) = if dacl_present && dacl_offset != 0 {
        let start = usize::try_from(dacl_offset).ok()?;
        let size = read_u16_le(bytes, start.checked_add(2)?)?;
        let aces = read_u16_le(bytes, start.checked_add(4)?)?;
        // The ACL must lie inside the image it claims to belong to.
        let end = start.checked_add(usize::from(size))?;
        if end > bytes.len() {
            return None;
        }
        (u32::from(size), u32::from(aces))
    } else {
        (0, 0)
    };

    Some(BootObjectSecurity {
        owner_is_local_system,
        group_is_local_system,
        dacl_present,
        dacl_null,
        dacl_protected: control & SE_DACL_PROTECTED != 0,
        dacl_ace_count,
        dacl_size,
        sacl_present,
    })
}

/// The `SectionBasicInformation` facts required before mapping an existing
/// section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionBasicFacts {
    pub maximum_size: u64,
    pub allocation_attributes: u32,
}

/// Exactly 64 KiB and exactly `SEC_COMMIT`; any extra attribute bit is a
/// different object than the one this driver publishes.
pub const fn existing_section_is_canonical(facts: SectionBasicFacts) -> bool {
    facts.maximum_size == BOOT_CONTEXT_SECTION_BYTES as u64
        && facts.allocation_attributes == SEC_COMMIT
}

// ---------------------------------------------------------------------------
// The affine boot lock-event protocol
// ---------------------------------------------------------------------------

/// Affine evidence that the calling thread entered a critical region.
///
/// It has no public constructor and no `Clone`, so the only ways to spend it
/// are [`leave_critical_region`] and a successful acquisition — which is what
/// makes "a failed wait still leaves the critical region" checkable.
#[derive(Debug)]
pub struct CriticalRegion(());

/// Consume the entry token: the thread leaves its critical region.
pub fn leave_critical_region(region: CriticalRegion) {
    let CriticalRegion(()) = region;
}

/// Affine ownership of the permanent named lock event.
#[derive(Debug)]
pub struct BootLockGuard {
    region: CriticalRegion,
}

/// The two outcomes of one bounded wait. A rejection hands the critical-region
/// token straight back, so no path can set an event it never acquired.
#[derive(Debug)]
pub enum BootLockAcquisition {
    Acquired(BootLockGuard),
    Rejected(CriticalRegion),
}

/// The result of releasing a guard.
///
/// The critical-region token is returned even when the prior state was wrong,
/// because leaving the region is not optional; the violation is reported
/// separately so the caller can fail the operation.
#[derive(Debug)]
pub struct BootLockRelease {
    region: CriticalRegion,
    violation: Option<AdapterPlanError>,
}

impl BootLockRelease {
    pub const fn violation(&self) -> Option<AdapterPlanError> {
        self.violation
    }

    /// Leave the critical region, consuming the last token.
    pub fn leave(self) {
        leave_critical_region(self.region);
    }
}

/// Exact `STATUS_SUCCESS` plus a post-wait state of zero.
///
/// A nonzero state means the satisfied object stayed signaled, which is a
/// same-name `NotificationEvent` rather than the documented
/// `SynchronizationEvent`; it is rejected without claiming ownership.
pub const fn wait_is_acquired(wait_status: i32, state_after_wait: u32) -> bool {
    wait_status == STATUS_SUCCESS && state_after_wait == 0
}

/// The driver-wide BootContext lock state.
///
/// One cell exists per loaded driver. Its only job is to make a second
/// acquisition on top of a live guard a refusal instead of a self-deadlock.
#[derive(Debug, Default)]
pub struct BootLockCell {
    held: bool,
}

impl BootLockCell {
    pub const fn new() -> Self {
        Self { held: false }
    }

    pub const fn is_held(&self) -> bool {
        self.held
    }

    /// Enter the critical region before the bounded wait.
    ///
    /// Recursive acquisition is refused here rather than being detected after
    /// the wait has already blocked forever.
    pub fn enter(&mut self) -> Result<CriticalRegion, AdapterPlanError> {
        if self.held {
            return Err(AdapterPlanError::InvalidTransition);
        }
        Ok(CriticalRegion(()))
    }

    /// Classify one completed wait.
    pub fn finish_wait(
        &mut self,
        region: CriticalRegion,
        wait_status: i32,
        state_after_wait: u32,
    ) -> BootLockAcquisition {
        if wait_is_acquired(wait_status, state_after_wait) {
            self.held = true;
            BootLockAcquisition::Acquired(BootLockGuard { region })
        } else {
            BootLockAcquisition::Rejected(region)
        }
    }

    /// Consume the guard after the single `KeSetEvent`.
    ///
    /// `previous_state` is that call's return value. A nonzero prior state
    /// means somebody set the event while this guard claimed it exclusively.
    pub fn release(&mut self, guard: BootLockGuard, previous_state: u32) -> BootLockRelease {
        let BootLockGuard { region } = guard;
        self.held = false;
        BootLockRelease {
            region,
            violation: if previous_state == 0 {
                None
            } else {
                Some(AdapterPlanError::InvalidTransition)
            },
        }
    }
}

// ---------------------------------------------------------------------------
// The ordered load choreography
// ---------------------------------------------------------------------------

/// One native operation in the non-skippable successful load sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadEffect {
    OpenAndAcquireBootLockEvent,
    OpenOrCreateBootSection,
    MapSystemView,
    ValidateOrInitialize,
    PublishLoadGeneration,
    ReleaseBootLockEvent,
    RegisterEtw,
    AllocateDriverState,
    RegisterProcessNotify,
    CreateProviderSecure,
    CreateFscontrolSecure,
    CreateProviderDosLink,
    PublishProvider,
    PublishFscontrol,
    RegisterFilesystem,
}

const LOAD_EFFECTS: [LoadEffect; 15] = [
    LoadEffect::OpenAndAcquireBootLockEvent,
    LoadEffect::OpenOrCreateBootSection,
    LoadEffect::MapSystemView,
    LoadEffect::ValidateOrInitialize,
    LoadEffect::PublishLoadGeneration,
    LoadEffect::ReleaseBootLockEvent,
    LoadEffect::RegisterEtw,
    LoadEffect::AllocateDriverState,
    LoadEffect::RegisterProcessNotify,
    LoadEffect::CreateProviderSecure,
    LoadEffect::CreateFscontrolSecure,
    LoadEffect::CreateProviderDosLink,
    LoadEffect::PublishProvider,
    LoadEffect::PublishFscontrol,
    LoadEffect::RegisterFilesystem,
];

const INDEX_REGISTER_ETW: u8 = 6;
const INDEX_ALLOCATE_DRIVER_STATE: u8 = 7;
const INDEX_REGISTER_PROCESS_NOTIFY: u8 = 8;
const INDEX_CREATE_PROVIDER_SECURE: u8 = 9;
const INDEX_CREATE_FSCONTROL_SECURE: u8 = 10;
const INDEX_CREATE_PROVIDER_DOS_LINK: u8 = 11;
const INDEX_PUBLISH_PROVIDER: u8 = 12;
const INDEX_PUBLISH_FSCONTROL: u8 = 13;

/// How a named permanent object came into this load's hands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectDisposition {
    OpenedExisting,
    CreatedNew,
    ReopenedAfterCollision,
}

/// What the private BootContext snapshot turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootValidation {
    /// A valid READY header and every non-FREE slot validated.
    ExistingReady,
    /// An entirely zeroed context was driven to INITIALIZING by this load.
    NewPrepared,
}

/// Which context the load-generation publication committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootOrigin {
    ExistingReady,
    NewlyInitializedReady,
}

/// The closed outcome vocabulary a native executor may report.
///
/// Every variant is a tag. No header, slot, or byte buffer fits, so unvalidated
/// BootContext bytes cannot re-enter the plan; `bootctx` stays the only
/// decider of context content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadEffectOutcome {
    Done,
    BootLockEventAcquired(ObjectDisposition),
    BootSectionOpened(ObjectDisposition),
    BootContextValidated(BootValidation),
    BootContextPublished(BootOrigin),
}

/// The ordering and ownership state of one driver load.
pub struct LoadPlan {
    next: u8,
    owned: u32,
    lock_event_open: bool,
    lock_event_held: bool,
    section_open: bool,
    section_created_here: bool,
    section_ready: bool,
    system_view_mapped: bool,
}

/// A one-shot capability requesting exactly one native load effect.
pub struct PendingLoadEffect {
    plan: LoadPlan,
    effect: LoadEffect,
}

/// The only two observable states of a load.
pub enum LoadProgress {
    Effect(PendingLoadEffect),
    Ready(LoadedDriver),
}

/// Proof that all fifteen load effects completed successfully. Consumed by
/// [`UnloadPlan::begin`], so an unload cannot be planned for a failed load.
pub struct LoadedDriver(());

/// One native action in a reverse-order unwind of a failed load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadRollbackEffect {
    UnregisterFilesystem,
    UnpublishFscontrol,
    UnpublishProvider,
    RemoveProviderDosLink,
    DeleteFscontrol,
    DeleteProvider,
    UnregisterProcessNotify,
    ReleaseDriverState,
    UnregisterEtw,
    UnmapSystemView,
    /// The one destroying step in the whole vocabulary, and only for a section
    /// this load created that never reached READY.
    MakeNewBootSectionTemporary,
    CloseBootSection,
    ReleaseBootLockEvent,
    CloseBootLockEvent,
}

/// Keeps the unwind tables below readable without a glob import.
type Undo = LoadRollbackEffect;

const ROLLBACK_NONE: &[Undo] = &[];

const ROLLBACK_HELD_LOCK: &[Undo] = &[Undo::ReleaseBootLockEvent, Undo::CloseBootLockEvent];

const ROLLBACK_LOCK_ONLY: &[Undo] = &[Undo::CloseBootLockEvent];

const ROLLBACK_NEW_SECTION_HELD: &[Undo] = &[
    Undo::MakeNewBootSectionTemporary,
    Undo::CloseBootSection,
    Undo::ReleaseBootLockEvent,
    Undo::CloseBootLockEvent,
];

const ROLLBACK_SECTION_HELD: &[Undo] = &[
    Undo::CloseBootSection,
    Undo::ReleaseBootLockEvent,
    Undo::CloseBootLockEvent,
];

const ROLLBACK_NEW_SECTION: &[Undo] = &[
    Undo::MakeNewBootSectionTemporary,
    Undo::CloseBootSection,
    Undo::CloseBootLockEvent,
];

const ROLLBACK_SECTION: &[Undo] = &[Undo::CloseBootSection, Undo::CloseBootLockEvent];

const ROLLBACK_NEW_VIEW_HELD: &[Undo] = &[
    Undo::UnmapSystemView,
    Undo::MakeNewBootSectionTemporary,
    Undo::CloseBootSection,
    Undo::ReleaseBootLockEvent,
    Undo::CloseBootLockEvent,
];

const ROLLBACK_VIEW_HELD: &[Undo] = &[
    Undo::UnmapSystemView,
    Undo::CloseBootSection,
    Undo::ReleaseBootLockEvent,
    Undo::CloseBootLockEvent,
];

const ROLLBACK_NEW_VIEW: &[Undo] = &[
    Undo::UnmapSystemView,
    Undo::MakeNewBootSectionTemporary,
    Undo::CloseBootSection,
    Undo::CloseBootLockEvent,
];

/// The boot tail every post-boot prefix shares: the guard is released, the
/// context is READY, and both permanent objects survive.
const ROLLBACK_BOOT_READY: &[Undo] = &[
    Undo::UnmapSystemView,
    Undo::CloseBootSection,
    Undo::CloseBootLockEvent,
];

const ROLLBACK_ETW: &[Undo] = &[
    Undo::UnregisterEtw,
    Undo::UnmapSystemView,
    Undo::CloseBootSection,
    Undo::CloseBootLockEvent,
];

const ROLLBACK_DRIVER_STATE: &[Undo] = &[
    Undo::ReleaseDriverState,
    Undo::UnregisterEtw,
    Undo::UnmapSystemView,
    Undo::CloseBootSection,
    Undo::CloseBootLockEvent,
];

const ROLLBACK_PROCESS_NOTIFY: &[Undo] = &[
    Undo::UnregisterProcessNotify,
    Undo::ReleaseDriverState,
    Undo::UnregisterEtw,
    Undo::UnmapSystemView,
    Undo::CloseBootSection,
    Undo::CloseBootLockEvent,
];

const ROLLBACK_PROVIDER: &[Undo] = &[
    Undo::DeleteProvider,
    Undo::UnregisterProcessNotify,
    Undo::ReleaseDriverState,
    Undo::UnregisterEtw,
    Undo::UnmapSystemView,
    Undo::CloseBootSection,
    Undo::CloseBootLockEvent,
];

const ROLLBACK_FSCONTROL: &[Undo] = &[
    Undo::DeleteFscontrol,
    Undo::DeleteProvider,
    Undo::UnregisterProcessNotify,
    Undo::ReleaseDriverState,
    Undo::UnregisterEtw,
    Undo::UnmapSystemView,
    Undo::CloseBootSection,
    Undo::CloseBootLockEvent,
];

const ROLLBACK_DOS_LINK: &[Undo] = &[
    Undo::RemoveProviderDosLink,
    Undo::DeleteFscontrol,
    Undo::DeleteProvider,
    Undo::UnregisterProcessNotify,
    Undo::ReleaseDriverState,
    Undo::UnregisterEtw,
    Undo::UnmapSystemView,
    Undo::CloseBootSection,
    Undo::CloseBootLockEvent,
];

const ROLLBACK_PROVIDER_PUBLISHED: &[Undo] = &[
    Undo::UnpublishProvider,
    Undo::RemoveProviderDosLink,
    Undo::DeleteFscontrol,
    Undo::DeleteProvider,
    Undo::UnregisterProcessNotify,
    Undo::ReleaseDriverState,
    Undo::UnregisterEtw,
    Undo::UnmapSystemView,
    Undo::CloseBootSection,
    Undo::CloseBootLockEvent,
];

const ROLLBACK_FSCONTROL_PUBLISHED: &[Undo] = &[
    Undo::UnpublishFscontrol,
    Undo::UnpublishProvider,
    Undo::RemoveProviderDosLink,
    Undo::DeleteFscontrol,
    Undo::DeleteProvider,
    Undo::UnregisterProcessNotify,
    Undo::ReleaseDriverState,
    Undo::UnregisterEtw,
    Undo::UnmapSystemView,
    Undo::CloseBootSection,
    Undo::CloseBootLockEvent,
];

/// The immutable unwind plan for one failed load.
pub struct LoadRollbackPlan {
    effects: &'static [LoadRollbackEffect],
}

impl LoadRollbackPlan {
    pub const fn effects(&self) -> &'static [LoadRollbackEffect] {
        self.effects
    }
}

const fn bit(index: u8) -> u32 {
    1u32.wrapping_shl(index as u32)
}

impl LoadPlan {
    /// Begin a load. The first effect is fixed by `10-lifecycle.md` section 3:
    /// nothing else may happen before the publication lock is owned.
    pub const fn begin() -> LoadProgress {
        LoadProgress::Effect(PendingLoadEffect {
            plan: Self {
                next: 0,
                owned: 0,
                lock_event_open: false,
                lock_event_held: false,
                section_open: false,
                section_created_here: false,
                section_ready: false,
                system_view_mapped: false,
            },
            effect: LoadEffect::OpenAndAcquireBootLockEvent,
        })
    }

    const fn owns(&self, index: u8) -> bool {
        self.owned & bit(index) != 0
    }

    /// Derive the unwind from what this load still owns.
    ///
    /// The boot arm is written as a total match over the five ownership facts
    /// rather than as a cursor lookup: an unwind that assumed a prefix number
    /// would silently release the wrong thing if the order ever changed.
    const fn rollback_effects(&self) -> &'static [LoadRollbackEffect] {
        if self.owns(INDEX_PUBLISH_FSCONTROL) {
            return ROLLBACK_FSCONTROL_PUBLISHED;
        }
        if self.owns(INDEX_PUBLISH_PROVIDER) {
            return ROLLBACK_PROVIDER_PUBLISHED;
        }
        if self.owns(INDEX_CREATE_PROVIDER_DOS_LINK) {
            return ROLLBACK_DOS_LINK;
        }
        if self.owns(INDEX_CREATE_FSCONTROL_SECURE) {
            return ROLLBACK_FSCONTROL;
        }
        if self.owns(INDEX_CREATE_PROVIDER_SECURE) {
            return ROLLBACK_PROVIDER;
        }
        if self.owns(INDEX_REGISTER_PROCESS_NOTIFY) {
            return ROLLBACK_PROCESS_NOTIFY;
        }
        if self.owns(INDEX_ALLOCATE_DRIVER_STATE) {
            return ROLLBACK_DRIVER_STATE;
        }
        if self.owns(INDEX_REGISTER_ETW) {
            return ROLLBACK_ETW;
        }

        let temporary = self.section_created_here && !self.section_ready;
        match (
            self.lock_event_open,
            self.section_open,
            self.system_view_mapped,
            temporary,
            self.lock_event_held,
        ) {
            (false, _, _, _, _) => ROLLBACK_NONE,
            (true, false, _, _, true) => ROLLBACK_HELD_LOCK,
            (true, false, _, _, false) => ROLLBACK_LOCK_ONLY,
            (true, true, false, true, true) => ROLLBACK_NEW_SECTION_HELD,
            (true, true, false, false, true) => ROLLBACK_SECTION_HELD,
            (true, true, false, true, false) => ROLLBACK_NEW_SECTION,
            (true, true, false, false, false) => ROLLBACK_SECTION,
            (true, true, true, true, true) => ROLLBACK_NEW_VIEW_HELD,
            (true, true, true, false, true) => ROLLBACK_VIEW_HELD,
            (true, true, true, true, false) => ROLLBACK_NEW_VIEW,
            (true, true, true, false, false) => ROLLBACK_BOOT_READY,
        }
    }
}

impl PendingLoadEffect {
    pub const fn effect(&self) -> LoadEffect {
        self.effect
    }

    /// Consume this capability after its native effect completed.
    ///
    /// Only the outcome variant that belongs to this effect is accepted. A
    /// mismatch is a contract violation by the in-crate executor, which builds
    /// the outcome in the same match arm that issues the call, so a released
    /// driver cannot reach it; the executor still owns every native handle in
    /// its own affine wrapper and unwinds those on any error.
    pub fn succeeded(self, outcome: LoadEffectOutcome) -> Result<LoadProgress, AdapterPlanError> {
        let Self { mut plan, effect } = self;

        match (effect, outcome) {
            (
                LoadEffect::OpenAndAcquireBootLockEvent,
                LoadEffectOutcome::BootLockEventAcquired(_),
            ) => {
                plan.lock_event_open = true;
                plan.lock_event_held = true;
            }
            (
                LoadEffect::OpenOrCreateBootSection,
                LoadEffectOutcome::BootSectionOpened(disposition),
            ) => {
                plan.section_open = true;
                plan.section_created_here = matches!(disposition, ObjectDisposition::CreatedNew);
            }
            (LoadEffect::MapSystemView, LoadEffectOutcome::Done) => {
                plan.system_view_mapped = true;
            }
            (LoadEffect::ValidateOrInitialize, LoadEffectOutcome::BootContextValidated(what)) => {
                match what {
                    BootValidation::ExistingReady => {
                        // A section this load created is pagefile-backed and
                        // entirely zero, so it cannot already carry a READY
                        // header. Accepting that claim would skip the
                        // initializer and leave the context EMPTY forever.
                        if plan.section_created_here {
                            return Err(AdapterPlanError::InvalidTransition);
                        }
                        plan.section_ready = true;
                    }
                    BootValidation::NewPrepared => {}
                }
            }
            (
                LoadEffect::PublishLoadGeneration,
                LoadEffectOutcome::BootContextPublished(origin),
            ) => {
                let adopted = plan.section_ready;
                match (origin, adopted) {
                    (BootOrigin::ExistingReady, true)
                    | (BootOrigin::NewlyInitializedReady, false) => {}
                    (BootOrigin::ExistingReady, false)
                    | (BootOrigin::NewlyInitializedReady, true) => {
                        return Err(AdapterPlanError::InvalidTransition);
                    }
                }
                plan.section_ready = true;
            }
            (LoadEffect::ReleaseBootLockEvent, LoadEffectOutcome::Done) => {
                if !plan.lock_event_held {
                    return Err(AdapterPlanError::InvalidTransition);
                }
                plan.lock_event_held = false;
            }
            (
                LoadEffect::RegisterEtw
                | LoadEffect::AllocateDriverState
                | LoadEffect::RegisterProcessNotify
                | LoadEffect::CreateProviderSecure
                | LoadEffect::CreateFscontrolSecure
                | LoadEffect::CreateProviderDosLink
                | LoadEffect::PublishProvider
                | LoadEffect::PublishFscontrol
                | LoadEffect::RegisterFilesystem,
                LoadEffectOutcome::Done,
            ) => {}
            (
                LoadEffect::OpenAndAcquireBootLockEvent
                | LoadEffect::OpenOrCreateBootSection
                | LoadEffect::MapSystemView
                | LoadEffect::ValidateOrInitialize
                | LoadEffect::PublishLoadGeneration
                | LoadEffect::ReleaseBootLockEvent
                | LoadEffect::RegisterEtw
                | LoadEffect::AllocateDriverState
                | LoadEffect::RegisterProcessNotify
                | LoadEffect::CreateProviderSecure
                | LoadEffect::CreateFscontrolSecure
                | LoadEffect::CreateProviderDosLink
                | LoadEffect::PublishProvider
                | LoadEffect::PublishFscontrol
                | LoadEffect::RegisterFilesystem,
                _,
            ) => return Err(AdapterPlanError::InvalidInput),
        }

        plan.owned |= bit(plan.next);
        plan.next = match plan.next.checked_add(1) {
            Some(next) => next,
            None => return Err(AdapterPlanError::ArithmeticOverflow),
        };

        match LOAD_EFFECTS.get(usize::from(plan.next)) {
            Some(effect) => Ok(LoadProgress::Effect(PendingLoadEffect {
                plan,
                effect: *effect,
            })),
            None => Ok(LoadProgress::Ready(LoadedDriver(()))),
        }
    }

    /// Consume a failed native effect into the exact resources already owned.
    pub fn failed(self) -> LoadRollbackPlan {
        LoadRollbackPlan {
            effects: self.plan.rollback_effects(),
        }
    }
}

// ---------------------------------------------------------------------------
// Unload
// ---------------------------------------------------------------------------

/// One native operation in the symmetric unload sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnloadEffect {
    CloseGlobalAdmissions,
    UnregisterProcessNotify,
    WaitProcessCallbacks,
    WaitSetupAdmission,
    ClaimOrJoinOneSession,
    RestartSessionScan,
    DrainR3Finalizers,
    WaitControlContextAdmission,
    PreflightR3LedgersAndRoot,
    UnregisterFilesystem,
    DeleteFscontrol,
    RemoveProviderDosLink,
    DeleteProvider,
    /// Unmap and close only. Both permanent objects survive an ordinary
    /// unload, which is what lets a reload adopt the same boot identity.
    ReleaseBootObjects,
    ReleaseDriverState,
    UnregisterEtw,
}

/// Pure fake-DDI seam for effect two. A failed unregister must park/fail-stop
/// the prefix; it can never authorize effect three or any destructive suffix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessNotifyUnregisterDisposition {
    ContinueToCallbackDrain,
    FailStop,
}

pub const fn classify_process_notify_unregister(status: i32) -> ProcessNotifyUnregisterDisposition {
    if status >= 0 {
        ProcessNotifyUnregisterDisposition::ContinueToCallbackDrain
    } else {
        ProcessNotifyUnregisterDisposition::FailStop
    }
}

/// Every independently observed condition effect nine must discharge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum R3UnloadPredicate {
    CoreAdmissionClosed,
    ProcessCallbackAdmissionClosed,
    ProcessCallbacksDrained,
    SetupAdmissionClosed,
    SetupAdmissionDrained,
    SessionScanStableEmpty,
    CoreSessionSlotsEmpty,
    NativeSessionCellsEmpty,
    TerminalRendezvousInactive,
    TerminalJoinersDrained,
    TerminalEventsQuiescent,
    MountOwnerAbsent,
    MountTicketsAndWaitersDrained,
    MountSignalsAcknowledged,
    FinalizerAdmissionClosed,
    FinalizersDrained,
    FinalizerDepositsAbsent,
    FinalizerHandoffsAbsent,
    FailStopSlotsEmpty,
    SessionShellOwnersAbsent,
    SessionRootOwnersAbsent,
    RegistryLeasesAbsent,
    ControlOwnersAbsent,
    CheckpointReadinessAbsent,
    ControlContextAdmissionClosed,
    ControlContextAdmissionDrained,
    ControlBindingsClosed,
    CompletedControlRecordsAbsent,
    CloseRightsAbsent,
    ControlContextsAbsent,
    SoleDriverRootReference,
}

impl R3UnloadPredicate {
    pub const ALL: [Self; 31] = [
        Self::CoreAdmissionClosed,
        Self::ProcessCallbackAdmissionClosed,
        Self::ProcessCallbacksDrained,
        Self::SetupAdmissionClosed,
        Self::SetupAdmissionDrained,
        Self::SessionScanStableEmpty,
        Self::CoreSessionSlotsEmpty,
        Self::NativeSessionCellsEmpty,
        Self::TerminalRendezvousInactive,
        Self::TerminalJoinersDrained,
        Self::TerminalEventsQuiescent,
        Self::MountOwnerAbsent,
        Self::MountTicketsAndWaitersDrained,
        Self::MountSignalsAcknowledged,
        Self::FinalizerAdmissionClosed,
        Self::FinalizersDrained,
        Self::FinalizerDepositsAbsent,
        Self::FinalizerHandoffsAbsent,
        Self::FailStopSlotsEmpty,
        Self::SessionShellOwnersAbsent,
        Self::SessionRootOwnersAbsent,
        Self::RegistryLeasesAbsent,
        Self::ControlOwnersAbsent,
        Self::CheckpointReadinessAbsent,
        Self::ControlContextAdmissionClosed,
        Self::ControlContextAdmissionDrained,
        Self::ControlBindingsClosed,
        Self::CompletedControlRecordsAbsent,
        Self::CloseRightsAbsent,
        Self::ControlContextsAbsent,
        Self::SoleDriverRootReference,
    ];

    #[cfg(test)]
    const fn bit(self) -> u64 {
        1u64 << (self as u64)
    }
}

/// Copy-only effect-nine observation. Native code populates each predicate
/// independently while every admission/drain proof is still live.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct R3UnloadPreflightObservation {
    satisfied: u64,
}

#[cfg(test)]
impl R3UnloadPreflightObservation {
    pub(crate) const fn all_clear_for_test() -> Self {
        Self {
            // `1 << n` is at least one, so the mask cannot underflow;
            // saturating agrees with checked and keeps the `const fn`.
            satisfied: (1u64 << R3UnloadPredicate::ALL.len()).saturating_sub(1),
        }
    }

    pub(crate) const fn with_failed_for_test(self, predicate: R3UnloadPredicate) -> Self {
        Self {
            satisfied: self.satisfied & !predicate.bit(),
        }
    }

    const fn satisfies(self, predicate: R3UnloadPredicate) -> bool {
        self.satisfied & predicate.bit() != 0
    }
}

#[cfg(test)]
pub(crate) struct R3UnloadPreflight;

/// Sole authority that may enter effects 10-16.
#[cfg(test)]
pub(crate) struct PreparedUnloadDestruction {
    boundary: R3UnloadPreflightBoundary,
    authority: PrivatePreparedUnloadDestructionAuthority,
}

#[cfg(test)]
struct PrivatePreparedUnloadDestructionAuthority(());

#[cfg(test)]
impl R3UnloadPreflight {
    pub(crate) fn prepare(
        boundary: R3UnloadPreflightBoundary,
        observed: R3UnloadPreflightObservation,
    ) -> Result<PreparedUnloadDestruction, R3UnloadPredicate> {
        for predicate in R3UnloadPredicate::ALL {
            if !observed.satisfies(predicate) {
                return Err(predicate);
            }
        }
        Ok(PreparedUnloadDestruction {
            boundary,
            authority: PrivatePreparedUnloadDestructionAuthority(()),
        })
    }
}

pub const R3_UNLOAD_DESTRUCTION_EFFECTS: [UnloadEffect; 7] = [
    UnloadEffect::UnregisterFilesystem,
    UnloadEffect::DeleteFscontrol,
    UnloadEffect::RemoveProviderDosLink,
    UnloadEffect::DeleteProvider,
    UnloadEffect::ReleaseBootObjects,
    UnloadEffect::ReleaseDriverState,
    UnloadEffect::UnregisterEtw,
];

#[cfg(test)]
pub(crate) struct R3UnloadDestructionEffect {
    next: u8,
    effect: UnloadEffect,
    boundary: R3UnloadPreflightBoundary,
    authority: PrivatePreparedUnloadDestructionAuthority,
}

#[cfg(test)]
pub(crate) struct R3UnloadDestructionComplete {
    _boundary: R3UnloadPreflightBoundary,
    _authority: PrivatePreparedUnloadDestructionAuthority,
}

#[cfg(test)]
pub(crate) enum R3UnloadDestructionProgress {
    Effect(R3UnloadDestructionEffect),
    Complete(R3UnloadDestructionComplete),
}

#[cfg(test)]
impl PreparedUnloadDestruction {
    pub(crate) fn into_destruction(self) -> R3UnloadDestructionProgress {
        let Self {
            boundary,
            authority,
        } = self;
        R3UnloadDestructionProgress::Effect(R3UnloadDestructionEffect {
            next: 1,
            effect: R3_UNLOAD_DESTRUCTION_EFFECTS[0],
            boundary,
            authority,
        })
    }
}

#[cfg(test)]
impl R3UnloadDestructionEffect {
    pub(crate) const fn effect(&self) -> UnloadEffect {
        self.effect
    }

    pub fn performed(self) -> R3UnloadDestructionProgress {
        let Self {
            next,
            effect: _,
            boundary,
            authority,
        } = self;
        match R3_UNLOAD_DESTRUCTION_EFFECTS.get(usize::from(next)) {
            // `get` proved `next` indexes the destruction roster, so the
            // successor stays in `u8` and saturating agrees with checked.
            Some(effect) => R3UnloadDestructionProgress::Effect(Self {
                next: next.saturating_add(1),
                effect: *effect,
                boundary,
                authority,
            }),
            None => R3UnloadDestructionProgress::Complete(R3UnloadDestructionComplete {
                _boundary: boundary,
                _authority: authority,
            }),
        }
    }
}

const R3_UNLOAD_PREFIX_EFFECTS: [UnloadEffect; 8] = [
    UnloadEffect::CloseGlobalAdmissions,
    UnloadEffect::UnregisterProcessNotify,
    UnloadEffect::WaitProcessCallbacks,
    UnloadEffect::WaitSetupAdmission,
    UnloadEffect::ClaimOrJoinOneSession,
    UnloadEffect::RestartSessionScan,
    UnloadEffect::DrainR3Finalizers,
    UnloadEffect::WaitControlContextAdmission,
];

struct PrivateR3UnloadBoundaryAuthority(());

/// The sole boundary between the eight nondestructive effects and effect nine.
/// It can be retained inside only a private native preflight result; core never
/// exposes a constructor for a prepared destructive suffix.
pub struct R3UnloadPreflightBoundary {
    _authority: PrivateR3UnloadBoundaryAuthority,
}

pub struct PendingR3UnloadEffect {
    next: u8,
    effect: UnloadEffect,
    authority: PrivateR3UnloadBoundaryAuthority,
}

pub enum R3UnloadPlanProgress {
    Effect(PendingR3UnloadEffect),
    Preflight(R3UnloadPreflightBoundary),
}

/// Entry to the exact R3 prefix. The destructive suffix is deliberately not
/// reachable through this cursor.
pub struct UnloadPlan;

impl UnloadPlan {
    /// Admission closes first; process notification is unregistered and both
    /// callback/setup rundowns drain before the first cell is observed. Every
    /// session then reaches a stable empty pass, and tracing stops last so a
    /// teardown fault is still observable.
    pub const EFFECTS: [UnloadEffect; 16] = [
        UnloadEffect::CloseGlobalAdmissions,
        UnloadEffect::UnregisterProcessNotify,
        UnloadEffect::WaitProcessCallbacks,
        UnloadEffect::WaitSetupAdmission,
        UnloadEffect::ClaimOrJoinOneSession,
        UnloadEffect::RestartSessionScan,
        UnloadEffect::DrainR3Finalizers,
        UnloadEffect::WaitControlContextAdmission,
        UnloadEffect::PreflightR3LedgersAndRoot,
        UnloadEffect::UnregisterFilesystem,
        UnloadEffect::DeleteFscontrol,
        UnloadEffect::RemoveProviderDosLink,
        UnloadEffect::DeleteProvider,
        UnloadEffect::ReleaseBootObjects,
        UnloadEffect::ReleaseDriverState,
        UnloadEffect::UnregisterEtw,
    ];

    /// Consume the load proof: only a fully published driver can unload.
    pub fn begin(driver: LoadedDriver) -> R3UnloadPlanProgress {
        let LoadedDriver(()) = driver;
        R3UnloadPlanProgress::Effect(PendingR3UnloadEffect {
            next: 1,
            effect: R3_UNLOAD_PREFIX_EFFECTS[0],
            authority: PrivateR3UnloadBoundaryAuthority(()),
        })
    }
}

impl PendingR3UnloadEffect {
    pub const fn effect(&self) -> UnloadEffect {
        self.effect
    }

    /// Consume one completed nondestructive effect into the sole continuation.
    pub fn performed(self) -> R3UnloadPlanProgress {
        let Self {
            next,
            effect: _,
            authority,
        } = self;
        match R3_UNLOAD_PREFIX_EFFECTS.get(usize::from(next)) {
            // `get` just proved `next` indexes the eight-entry prefix, so the
            // successor cannot leave `u8` and saturating agrees with checked
            // here. Section 5 forbids the bare `+` regardless of the proof.
            Some(effect) => R3UnloadPlanProgress::Effect(Self {
                next: next.saturating_add(1),
                effect: *effect,
                authority,
            }),
            None => R3UnloadPlanProgress::Preflight(R3UnloadPreflightBoundary {
                _authority: authority,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Production-used R3 unload and process-callback runners
// ---------------------------------------------------------------------------

/// The only two terminal outcomes of the fixed-domain session scan.
///
/// Core deliberately cannot construct either associated payload. The native
/// implementation alone owns the fixed 64-cell cursor and can mint a stable
/// pass or an authenticated permanent-wait authority after driving it.
pub enum R3UnloadSessionScan<Stable, Blocked> {
    Stable(Stable),
    Blocked(Blocked),
}

/// Closed native operation surface for the exact sixteen-effect R3 unload.
///
/// Effects 1-9 carry distinct affine associated types instead of copied
/// booleans. Effects 10-16 form an infallible consuming chain: none of those
/// methods returns `Result`, `Option`, a refusal, or a success discriminator.
/// The final operation consumes the executor so it cannot touch the released
/// driver allocation afterwards.
///
/// # Safety
/// Implementations must perform every named operation exactly once, preserve
/// the admission/drain and scan lineages represented by the associated types,
/// and honor the non-return contract of a blocked unload.
// The once-each, lineage-preserving, non-returning contract above governs
// every method below; restating it twenty times would not add a constraint.
#[allow(clippy::missing_safety_doc)]
pub unsafe trait R3UnloadNativeOps: Sized {
    type ClosedAdmissions;
    type ProcessNotifyUnregistered;
    type ProcessCallbacksDrained;
    type SetupAdmissionDrained;
    type OneSessionObserved;
    type StableSessionScan;
    type BlockedSessionScan;
    type FinalizersDrained;
    type ControlContextsDrained;
    type PreparedDestruction;
    type FilesystemUnregistered;
    type FscontrolDeleted;
    type ProviderDosLinkRemoved;
    type ProviderDeleted;
    type BootObjectsReleased;
    type DriverStateReleased;

    unsafe fn close_global_admissions(&mut self) -> Self::ClosedAdmissions;
    unsafe fn unregister_process_notify(
        &mut self,
        closed: Self::ClosedAdmissions,
    ) -> Self::ProcessNotifyUnregistered;
    unsafe fn wait_process_callbacks(
        &mut self,
        unregistered: Self::ProcessNotifyUnregistered,
    ) -> Self::ProcessCallbacksDrained;
    unsafe fn wait_setup_admission(
        &mut self,
        process: Self::ProcessCallbacksDrained,
    ) -> Self::SetupAdmissionDrained;
    unsafe fn claim_or_join_one_session(
        &mut self,
        setup: Self::SetupAdmissionDrained,
    ) -> Self::OneSessionObserved;
    unsafe fn restart_session_scan(
        &mut self,
        first: Self::OneSessionObserved,
    ) -> R3UnloadSessionScan<Self::StableSessionScan, Self::BlockedSessionScan>;
    unsafe fn wait_blocked_unload_forever(&mut self, blocked: Self::BlockedSessionScan) -> !;
    unsafe fn drain_r3_finalizers(
        &mut self,
        stable: Self::StableSessionScan,
    ) -> Self::FinalizersDrained;
    unsafe fn wait_control_context_admission(
        &mut self,
        finalizers: Self::FinalizersDrained,
    ) -> Self::ControlContextsDrained;
    unsafe fn preflight_r3_ledgers_and_root(
        &mut self,
        boundary: R3UnloadPreflightBoundary,
        control: Self::ControlContextsDrained,
    ) -> Self::PreparedDestruction;
    unsafe fn unregister_filesystem(
        &mut self,
        prepared: Self::PreparedDestruction,
    ) -> Self::FilesystemUnregistered;
    unsafe fn delete_fscontrol(
        &mut self,
        stage: Self::FilesystemUnregistered,
    ) -> Self::FscontrolDeleted;
    unsafe fn remove_provider_dos_link(
        &mut self,
        stage: Self::FscontrolDeleted,
    ) -> Self::ProviderDosLinkRemoved;
    unsafe fn delete_provider(
        &mut self,
        stage: Self::ProviderDosLinkRemoved,
    ) -> Self::ProviderDeleted;
    unsafe fn release_boot_objects(
        &mut self,
        stage: Self::ProviderDeleted,
    ) -> Self::BootObjectsReleased;
    unsafe fn release_driver_state(
        &mut self,
        stage: Self::BootObjectsReleased,
    ) -> Self::DriverStateReleased;
    unsafe fn unregister_etw(self, stage: Self::DriverStateReleased);
}

fn expect_r3_unload_effect(
    progress: R3UnloadPlanProgress,
    expected: UnloadEffect,
) -> PendingR3UnloadEffect {
    match progress {
        R3UnloadPlanProgress::Effect(effect) if effect.effect() == expected => effect,
        R3UnloadPlanProgress::Effect(_) | R3UnloadPlanProgress::Preflight(_) => {
            unreachable!("the closed R3 unload runner and prefix roster agree")
        }
    }
}

/// Consume the affine blocked-unload token at the outer runner boundary.
///
/// Keeping this WDK-free handoff named lets fail-stop traces compose their
/// phase-A authenticated continuation with the exact production sink used by
/// unload, without teaching core anything about the native wait object.
pub fn run_r3_blocked_unload_wait<Token, Output>(
    token: Token,
    wait: impl FnOnce(Token) -> Output,
) -> Output {
    wait(token)
}

/// Drive the exact production R3 unload through one closed typed executor.
///
/// # Safety
/// `native` owns the live driver resources named by `driver`, runs at the
/// required native IRQLs, and satisfies [`R3UnloadNativeOps`].
#[inline(never)]
pub unsafe fn run_r3_unload<Native: R3UnloadNativeOps>(driver: LoadedDriver, mut native: Native) {
    let effect = expect_r3_unload_effect(
        UnloadPlan::begin(driver),
        UnloadEffect::CloseGlobalAdmissions,
    );
    let closed = unsafe { native.close_global_admissions() };

    let effect = expect_r3_unload_effect(effect.performed(), UnloadEffect::UnregisterProcessNotify);
    let unregistered = unsafe { native.unregister_process_notify(closed) };

    let effect = expect_r3_unload_effect(effect.performed(), UnloadEffect::WaitProcessCallbacks);
    let process = unsafe { native.wait_process_callbacks(unregistered) };

    let effect = expect_r3_unload_effect(effect.performed(), UnloadEffect::WaitSetupAdmission);
    let setup = unsafe { native.wait_setup_admission(process) };

    let effect = expect_r3_unload_effect(effect.performed(), UnloadEffect::ClaimOrJoinOneSession);
    let first = unsafe { native.claim_or_join_one_session(setup) };

    let effect = expect_r3_unload_effect(effect.performed(), UnloadEffect::RestartSessionScan);
    let stable = match unsafe { native.restart_session_scan(first) } {
        R3UnloadSessionScan::Stable(stable) => stable,
        R3UnloadSessionScan::Blocked(blocked) => unsafe {
            run_r3_blocked_unload_wait(blocked, |blocked| {
                native.wait_blocked_unload_forever(blocked)
            })
        },
    };

    let effect = expect_r3_unload_effect(effect.performed(), UnloadEffect::DrainR3Finalizers);
    let finalizers = unsafe { native.drain_r3_finalizers(stable) };

    let effect = expect_r3_unload_effect(
        effect.performed(),
        UnloadEffect::WaitControlContextAdmission,
    );
    let control = unsafe { native.wait_control_context_admission(finalizers) };

    let boundary = match effect.performed() {
        R3UnloadPlanProgress::Preflight(boundary) => boundary,
        R3UnloadPlanProgress::Effect(_) => {
            unreachable!("the closed R3 unload prefix ends at effect nine")
        }
    };
    let prepared = unsafe { native.preflight_r3_ledgers_and_root(boundary, control) };
    let filesystem = unsafe { native.unregister_filesystem(prepared) };
    let fscontrol = unsafe { native.delete_fscontrol(filesystem) };
    let link = unsafe { native.remove_provider_dos_link(fscontrol) };
    let provider = unsafe { native.delete_provider(link) };
    let boot = unsafe { native.release_boot_objects(provider) };
    let state = unsafe { native.release_driver_state(boot) };
    unsafe { native.unregister_etw(state) };
}

/// Admission result for one process-callback invocation.
pub enum R3ProcessCallbackAdmission<Guard> {
    Admitted(Guard),
    Refused,
}

/// One observation made while the same callback guard remains held.
pub enum R3ProcessCallbackStep {
    /// One authentic action completed; restart the fixed-domain scan at zero.
    Restart,
    /// No match at the current cell; continue at this exact next cursor.
    ResumeAt(u32),
    /// A complete stable pass ended the callback.
    Complete,
    /// Native state was inconsistent and the callback must not return.
    Invariant,
}

/// WDK-free process-callback boundary shared by production and its recorder.
/// # Safety
/// The runner acquires the guard once, observes only cells inside the fixed
/// domain while holding it, and releases or permanently parks it exactly once.
/// An implementation may not name the registry or a cell without the guard,
/// nor return from the invariant park.
// One contract, four methods that share it.
#[allow(clippy::missing_safety_doc)]
pub trait R3ProcessCallbackNativeOps: Sized {
    type Guard;

    unsafe fn acquire_guard(&mut self) -> R3ProcessCallbackAdmission<Self::Guard>;
    unsafe fn observe_one(&mut self, guard: &Self::Guard, cursor: u32) -> R3ProcessCallbackStep;
    unsafe fn release_guard(self, guard: Self::Guard);
    unsafe fn wait_process_scan_invariant_forever(self, guard: Self::Guard) -> !;
}

/// Run one process callback with one guard spanning every scan restart.
///
/// # Safety
/// The native implementation binds `Guard` to its callback rundown and keeps
/// every registry/cell access within that guard's lifetime.
#[inline(never)]
pub unsafe fn run_r3_process_callback<Native: R3ProcessCallbackNativeOps>(mut native: Native) {
    let guard = match unsafe { native.acquire_guard() } {
        R3ProcessCallbackAdmission::Admitted(guard) => guard,
        R3ProcessCallbackAdmission::Refused => return,
    };
    let mut cursor = 0;
    loop {
        match unsafe { native.observe_one(&guard, cursor) } {
            R3ProcessCallbackStep::Restart => cursor = 0,
            R3ProcessCallbackStep::ResumeAt(next) => cursor = next,
            R3ProcessCallbackStep::Complete => {
                unsafe { native.release_guard(guard) };
                return;
            }
            R3ProcessCallbackStep::Invariant => unsafe {
                native.wait_process_scan_invariant_forever(guard)
            },
        }
    }
}
