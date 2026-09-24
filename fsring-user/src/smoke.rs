//! The public `fsring-control-smoke/v2` report and the closed private worker
//! protocol.
//!
//! Two schemas live here, and the separation is the point. The **public** v2
//! report is what PowerShell alone emits; the **private** worker frames are how
//! one contained Rust worker hands its observations back. A private frame is
//! never a public report, and a malformed private frame contributes *nothing* —
//! no identity, no event, no probe fact — rather than contributing its
//! well-formed prefix.
//!
//! Everything is hand-encoded. There is no serde and no derive: the exact key
//! order, the exact hex widths, and the refusal of a duplicate or
//! escaped-equivalent key are the contract, and a derive macro would decide
//! them for us.

use std::io::{Read, Write};

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// The smallest possible worker payload: `{}`.
pub const WORKER_FRAME_MIN: usize = 2;
/// The largest payload a runner will read.
pub const WORKER_FRAME_MAX: usize = 262_144;
/// At most eight lifecycle events per private record.
pub const PRIVATE_EVENT_MAX: usize = 8;
/// At most 35 reasons per report.
pub const REASON_MAX_ENTRIES: usize = 35;
/// Each reason is `[1, 512]` bytes.
pub const REASON_MAX_BYTES: usize = 512;
/// The reserved machine-readable runner prefix.
pub const INFRASTRUCTURE_PREFIX: &str = "INFRASTRUCTURE:";
/// The private worker schema name.
pub const WORKER_SCHEMA: &str = "fsring-c4-worker/v1";
/// The public report schema name.
pub const PUBLIC_SCHEMA_V2: &str = "fsring-control-smoke/v2";

// ---------------------------------------------------------------------------
// Closed vocabularies
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    Pass,
    Fail,
    NotRun,
}

impl ProbeOutcome {
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::NotRun => "NOT RUN",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overall {
    Pass,
    Fail,
    NotRun,
}

impl Overall {
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::NotRun => "NOT RUN",
        }
    }

    /// The exit code the runner returns for this verdict.
    pub const fn exit_code(self) -> u32 {
        match self {
            Self::Pass => 0,
            Self::Fail => 1,
            Self::NotRun => 2,
        }
    }
}

macro_rules! probe_roster {
    ($($variant:ident => $wire:literal),+ $(,)?) => {
        /// The one closed ordered v2 probe roster.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum ProbeName {
            $($variant),+
        }

        /// Every probe, in the exact order the report must list them.
        pub const PROBE_ROSTER_V2: [ProbeName; <[()]>::len(&[$(probe_roster!(@unit $variant)),+])] =
            [$(ProbeName::$variant),+];

        impl ProbeName {
            pub const fn wire(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire),+
                }
            }

            /// Parse one wire name. Total over `&str`.
            pub fn parse(text: &str) -> Option<Self> {
                $(if text == $wire { return Some(Self::$variant); })+
                None
            }

            /// Closed roster index. Structural validation only; oracles stay
            /// independent of this mapping.
            pub const fn index(self) -> usize {
                self as usize
            }

            pub const fn from_index(index: usize) -> Option<Self> {
                if index >= PROBE_ROSTER_V2.len() {
                    None
                } else {
                    Some(PROBE_ROSTER_V2[index])
                }
            }
        }
    };
    (@unit $variant:ident) => { () };
}

probe_roster! {
    RootOpen => "root-open",
    TrailingOpen => "trailing-open",
    UnknownIoctl => "unknown-ioctl",
    DonateShort => "donate-short",
    DonateWrongVersion => "donate-wrong-version",
    Donate => "donate",
    ChildInheritedHandle => "child-inherited-handle",
    ParentHandleAfterChild => "parent-handle-after-child",
    FscontrolAcl => "fscontrol-acl",
    SetupRequiredUnavailable => "setup-required-unavailable",
    SetupOptionalDowngrade => "setup-optional-downgrade",
    SetupSecurity => "setup-security",
    SetupDuplicate => "setup-duplicate",
    SessionLayout => "session-layout",
    ViewProtections => "view-protections",
    VdoAcl => "vdo-acl",
    VdoMount => "vdo-mount",
    EnterPoll => "enter-poll",
    EnterTimeout => "enter-timeout",
    EnterDualRole => "enter-dual-role",
    EnterNotifyCredit => "enter-notify-credit",
    EnterContention => "enter-contention",
    EnterCancel => "enter-cancel",
    ProtocolAbort => "protocol-abort",
    CleanupClose => "cleanup-close",
    UnloadTransients => "unload-transients",
    BootContextPersistent => "bootcontext-persistent",
}

/// The probe slice one STAGED record carries.
pub const STAGED_PROBE_RANGE: core::ops::Range<usize> = 0..15;
/// The probe slice one LIVE_CLEANED record carries.
pub const LIVE_PROBE_RANGE: core::ops::Range<usize> = 15..25;
/// The probe slice one POST_UNLOAD record carries.
pub const POST_PROBE_RANGE: core::ops::Range<usize> = 26..27;

const _: () = assert!(
    PROBE_ROSTER_V2.len() == 27,
    "the v2 roster is exactly the design's twenty-seven probes"
);
// Index 25 is `unload-transients`: it is observed by the runner across a
// service stop, so no worker slice may contain it.
const _: () = assert!(
    STAGED_PROBE_RANGE.end == LIVE_PROBE_RANGE.start
        && LIVE_PROBE_RANGE.end == 25
        && POST_PROBE_RANGE.start == 26,
    "the three private slices must skip exactly index 25"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventName {
    SessionPublished,
    MountPublished,
    VerifySucceeded,
    SessionFenced,
}

impl EventName {
    pub const fn wire(self) -> &'static str {
        match self {
            Self::SessionPublished => "SESSION_PUBLISHED",
            Self::MountPublished => "MOUNT_PUBLISHED",
            Self::VerifySucceeded => "VERIFY_SUCCEEDED",
            Self::SessionFenced => "SESSION_FENCED",
        }
    }

    /// The ETW event id this name is pinned to.
    pub const fn id(self) -> u32 {
        match self {
            Self::SessionPublished => 1,
            Self::MountPublished => 2,
            Self::VerifySucceeded => 3,
            Self::SessionFenced => 4,
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "SESSION_PUBLISHED" => Some(Self::SessionPublished),
            "MOUNT_PUBLISHED" => Some(Self::MountPublished),
            "VERIFY_SUCCEEDED" => Some(Self::VerifySucceeded),
            "SESSION_FENCED" => Some(Self::SessionFenced),
            _ => None,
        }
    }
}

/// Every way a schema value can be refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmokeSchemaError {
    Length,
    Utf8,
    Json,
    DuplicateOrEscapedKey,
    UnknownOrReorderedKey,
    WrongType,
    WrongLiteral,
    WrongSequence,
    InvalidNonce,
    InvalidIdentity,
    InvalidName,
    InvalidProbeRoster,
    InvalidEvent,
    InvalidCleanup,
    InvalidReason,
    TrailingBytes,
}

#[derive(Debug)]
pub enum WorkerIoError {
    Io(std::io::Error),
    UnexpectedEof,
    Schema(SmokeSchemaError),
}

// ---------------------------------------------------------------------------
// Identities, nonces, and reasons
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HexIdentity {
    pub lo: u64,
    pub hi: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmokeIdentity {
    pub boot_instance_id: HexIdentity,
    pub mount_id: HexIdentity,
    pub session_epoch: u64,
}

/// Exactly 32 uppercase hex digits, with no `0x`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerNonce([u8; 16]);

impl WorkerNonce {
    pub fn parse(text: &str) -> Result<Self, SmokeSchemaError> {
        let bytes = text.as_bytes();
        if bytes.len() != 32 {
            return Err(SmokeSchemaError::InvalidNonce);
        }
        let mut out = [0u8; 16];
        for (index, pair) in bytes.chunks_exact(2).enumerate() {
            let high = upper_hex_digit(pair[0]).ok_or(SmokeSchemaError::InvalidNonce)?;
            let low = upper_hex_digit(pair[1]).ok_or(SmokeSchemaError::InvalidNonce)?;
            let Some(slot) = out.get_mut(index) else {
                return Err(SmokeSchemaError::InvalidNonce);
            };
            *slot = (high << 4) | low;
        }
        Ok(Self(out))
    }

    pub fn encode_upper(&self) -> [u8; 32] {
        let mut out = [b'0'; 32];
        for (index, byte) in self.0.iter().enumerate() {
            let high = HEX_UPPER[usize::from(byte >> 4)];
            let low = HEX_UPPER[usize::from(byte & 0x0F)];
            if let Some(slot) = out.get_mut(index * 2) {
                *slot = high;
            }
            if let Some(slot) = out.get_mut(index * 2 + 1) {
                *slot = low;
            }
        }
        out
    }

    pub fn as_text(&self) -> String {
        String::from_utf8_lossy(&self.encode_upper()).into_owned()
    }
}

const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";

/// Only uppercase hex is accepted, so a lowercase nonce is a schema error
/// rather than a silently normalized value.
fn upper_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// One bounded report reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmokeReason(String);

impl SmokeReason {
    /// `allow_infrastructure` is false for every ordinary probe reason: the
    /// reserved prefix is the runner's alone, and a worker that could emit it
    /// could force the aggregate verdict.
    pub fn parse(text: &str, allow_infrastructure: bool) -> Result<Self, SmokeSchemaError> {
        if text.is_empty() || text.len() > REASON_MAX_BYTES {
            return Err(SmokeSchemaError::InvalidReason);
        }
        if text.bytes().any(|byte| byte == 0 || byte < 0x20) {
            return Err(SmokeSchemaError::InvalidReason);
        }
        if !allow_infrastructure && text.starts_with(INFRASTRUCTURE_PREFIX) {
            return Err(SmokeSchemaError::InvalidReason);
        }
        Ok(Self(text.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Is this the reserved runner form?
    pub fn is_infrastructure(&self) -> bool {
        self.0.starts_with(INFRASTRUCTURE_PREFIX)
    }
}

// ---------------------------------------------------------------------------
// Oracles
// ---------------------------------------------------------------------------

/// The status domain an oracle reports in.
///
/// A provider IOCTL row records the Win32 result the caller actually saw; it is
/// never reverse-converted into an NTSTATUS and reported as one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusDomain {
    Ntstatus,
    Win32,
}

impl StatusDomain {
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Ntstatus => "ntstatus",
            Self::Win32 => "win32",
        }
    }
}

/// One fact value. Booleans and fixed-width uppercase hex only — there is no
/// free-form detail field, because a free-form field is not an oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactValue {
    Bool(bool),
    /// A 32-bit value, encoded `0xXXXXXXXX`.
    Hex32(u32),
    /// A 64-bit value, encoded `0xXXXXXXXXXXXXXXXX`.
    Hex64(u64),
}

impl FactValue {
    fn encode(self) -> String {
        match self {
            Self::Bool(value) => value.to_string(),
            Self::Hex32(value) => format!("\"0x{value:08X}\""),
            Self::Hex64(value) => format!("\"0x{value:016X}\""),
        }
    }
}

/// The four closed tagged oracle shapes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Oracle {
    Status {
        domain: StatusDomain,
        code: u32,
        /// `None` encodes JSON null.
        information: Option<u64>,
    },
    Facts {
        values: Vec<(&'static str, FactValue)>,
    },
    Events {
        names: Vec<EventName>,
        identity: SmokeIdentity,
    },
    Compound {
        facts: Vec<(&'static str, FactValue)>,
        names: Vec<EventName>,
        identity: SmokeIdentity,
    },
}

impl Oracle {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Status { .. } => "status",
            Self::Facts { .. } => "facts",
            Self::Events { .. } => "events",
            Self::Compound { .. } => "compound",
        }
    }

    /// The exact fact key set, for the roster comparison.
    pub fn fact_keys(&self) -> Vec<&'static str> {
        match self {
            Self::Facts { values } => values.iter().map(|(key, _)| *key).collect(),
            Self::Compound { facts, .. } => facts.iter().map(|(key, _)| *key).collect(),
            Self::Status { .. } | Self::Events { .. } => Vec::new(),
        }
    }
}

/// The exact PASS expectation for one probe, from the design's table.
///
/// The identity-bearing oracles need the root identity, which is why this is a
/// function of it rather than a constant.
pub fn expected_oracle(probe: ProbeName, root: SmokeIdentity) -> Oracle {
    use FactValue::{Bool, Hex32, Hex64};
    use ProbeName as P;
    let win32 = |code: u32, information: Option<u64>| Oracle::Status {
        domain: StatusDomain::Win32,
        code,
        information,
    };
    match probe {
        P::RootOpen => Oracle::Facts {
            values: vec![("opened", Bool(true))],
        },
        P::TrailingOpen => win32(0x0000_0002, None),
        P::UnknownIoctl => win32(0x0000_0001, Some(0)),
        P::DonateShort => win32(0x0000_0057, Some(0)),
        P::DonateWrongVersion => win32(0x0000_051A, Some(0)),
        P::Donate | P::ParentHandleAfterChild => win32(0x0000_0032, Some(0)),
        P::ChildInheritedHandle => win32(0x0000_0005, Some(0)),
        P::FscontrolAcl => Oracle::Facts {
            values: vec![
                ("elevatedNtstatus", Hex32(0x0000_0000)),
                ("unprivilegedChildNtstatus", Hex32(0xC000_0022)),
            ],
        },
        P::SetupRequiredUnavailable => Oracle::Facts {
            values: vec![
                ("win32Code", Hex32(0x0000_0032)),
                ("information", Hex64(0)),
                // Externally derived from the two retained MountIds, never read
                // back out of the BootContext.
                ("mountSequenceDelta", Hex64(0)),
            ],
        },
        P::SetupOptionalDowngrade => Oracle::Facts {
            values: vec![
                ("win32Code", Hex32(0x0000_0000)),
                ("selectedMask", Hex64(0x0000_0000_0000_0010)),
                ("unavailableSelectedMask", Hex64(0)),
                ("cleanupFenceMatched", Bool(true)),
                ("transientsRemoved", Bool(true)),
                ("identityDistinctFromRoot", Bool(true)),
            ],
        },
        P::SetupSecurity => Oracle::Facts {
            values: vec![
                ("win32Code", Hex32(0x0000_0000)),
                ("resultSizeMatches", Bool(true)),
                ("selectedMask", Hex64(0x0000_0000_0000_0010)),
                ("identityNonzero", Bool(true)),
            ],
        },
        P::SetupDuplicate => win32(0x0000_00AA, Some(0)),
        P::SessionLayout => Oracle::Facts {
            values: vec![
                ("independentParser", Bool(true)),
                ("exactLengths", Bool(true)),
                ("zeroPadding", Bool(true)),
                ("zeroCursors", Bool(true)),
                ("descriptorCountsMatch", Bool(true)),
            ],
        },
        P::ViewProtections => Oracle::Facts {
            values: vec![
                ("virtualQueryCoverage", Bool(true)),
                ("exactProtections", Bool(true)),
                ("overlapCount", Hex64(0)),
                ("executableRangeCount", Hex64(0)),
            ],
        },
        P::VdoAcl => Oracle::Facts {
            values: vec![("unprivilegedChildCode", Hex32(0x0000_0005))],
        },
        P::VdoMount => Oracle::Compound {
            facts: vec![
                ("createFileCode", Hex32(0x0000_0000)),
                ("rootVolumeHandle", Bool(true)),
            ],
            names: vec![EventName::SessionPublished, EventName::MountPublished],
            identity: root,
        },
        P::EnterPoll => Oracle::Facts {
            values: vec![
                ("win32Code", Hex32(0x0000_0000)),
                ("information", Hex64(0x30)),
                ("flags", Hex32(0x0000_0000)),
                ("cqDrained", Hex32(0x0000_0000)),
                ("returnedCredits", Hex32(0x0000_0000)),
            ],
        },
        P::EnterTimeout => Oracle::Facts {
            values: vec![
                ("win32Code", Hex32(0x0000_0000)),
                ("information", Hex64(0x30)),
                ("flags", Hex32(0x0000_0004)),
                ("cqDrained", Hex32(0x0000_0000)),
                ("returnedCredits", Hex32(0x0000_0000)),
            ],
        },
        P::EnterDualRole => Oracle::Facts {
            values: vec![
                ("firstWaitPending", Bool(true)),
                ("concurrentDrainWin32Code", Hex32(0x0000_0000)),
                ("conflictingWaitWin32Code", Hex32(0x0000_00AA)),
                ("rolesReleased", Bool(true)),
            ],
        },
        P::EnterNotifyCredit => Oracle::Facts {
            values: vec![
                ("win32Code", Hex32(0x0000_0000)),
                ("cqDrained", Hex32(0x0000_0001)),
                ("returnedCredits", Hex32(0x0000_0001)),
                ("oldGeneration", Hex64(1)),
                ("newGeneration", Hex64(2)),
            ],
        },
        P::EnterContention => Oracle::Facts {
            values: vec![
                ("win32Code", Hex32(0x0000_0000)),
                ("flags", Hex32(0x0000_0010)),
                ("bounded", Bool(true)),
            ],
        },
        P::EnterCancel => Oracle::Facts {
            values: vec![
                ("win32Code", Hex32(0x0000_03E3)),
                ("information", Hex64(0)),
                ("exactOverlapped", Bool(true)),
                ("completedOnce", Bool(true)),
            ],
        },
        P::ProtocolAbort => Oracle::Compound {
            facts: vec![
                ("enterWin32Code", Hex32(0x0000_0000)),
                ("fenceReason", Hex32(0x0000_0003)),
                ("sessionAbsent", Bool(true)),
            ],
            names: vec![EventName::SessionFenced],
            identity: root,
        },
        P::CleanupClose => Oracle::Facts {
            values: vec![
                ("pendingEnterCount", Hex32(0x0000_0000)),
                ("aliasCount", Hex32(0x0000_0000)),
                ("ownedHandleCount", Hex32(0x0000_0000)),
                ("completedOnce", Bool(true)),
            ],
        },
        P::UnloadTransients => Oracle::Facts {
            values: vec![
                ("serviceStopped", Bool(true)),
                ("providerOpenNtstatus", Hex32(0xC000_0034)),
                ("fscontrolOpenNtstatus", Hex32(0xC000_0034)),
                ("vdoOpenNtstatus", Hex32(0xC000_0034)),
                ("dosLinkQueryWin32Code", Hex32(0x0000_0002)),
                ("formerAliasRangesFree", Bool(true)),
                ("ownedHandlesClosed", Bool(true)),
            ],
        },
        P::BootContextPersistent => Oracle::Facts {
            values: vec![
                // Denied, not absent: the permanent objects survive an unload
                // and stay unreachable from user mode. A success or a
                // name-not-found is not a valid public fact here, and neither
                // is any claim about the header or a slot byte.
                ("sectionOpenNtstatus", Hex32(0xC000_0022)),
                ("eventOpenNtstatus", Hex32(0xC000_0022)),
                ("objectsPersistAndRemainKernelOnly", Bool(true)),
            ],
        },
    }
}

// ---------------------------------------------------------------------------
// Probes and the public report
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeV2 {
    pub name: ProbeName,
    pub outcome: ProbeOutcome,
    /// Always present.
    pub expected: Oracle,
    /// `None` only for a NOT RUN probe.
    pub actual: Option<Oracle>,
}

impl ProbeV2 {
    /// Is this probe's shape internally consistent?
    ///
    /// An executed probe must carry an `actual` of the same kind; a NOT RUN
    /// probe must carry none. A PASS additionally requires the two to be equal,
    /// which is what makes a self-reported PASS worthless.
    pub fn validate(&self) -> Result<(), SmokeSchemaError> {
        match (self.outcome, &self.actual) {
            (ProbeOutcome::NotRun, None) => Ok(()),
            (ProbeOutcome::NotRun, Some(_)) => Err(SmokeSchemaError::WrongType),
            (_, None) => Err(SmokeSchemaError::WrongType),
            (outcome, Some(actual)) => {
                if actual.kind() != self.expected.kind() {
                    return Err(SmokeSchemaError::WrongType);
                }
                if actual.fact_keys() != self.expected.fact_keys() {
                    return Err(SmokeSchemaError::UnknownOrReorderedKey);
                }
                if matches!(outcome, ProbeOutcome::Pass) && actual != &self.expected {
                    return Err(SmokeSchemaError::WrongLiteral);
                }
                Ok(())
            }
        }
    }

    /// The outcome an independent comparison derives, ignoring the reported
    /// one entirely.
    pub fn derived_outcome(&self) -> ProbeOutcome {
        match &self.actual {
            None => ProbeOutcome::NotRun,
            Some(actual) if *actual == self.expected => ProbeOutcome::Pass,
            Some(_) => ProbeOutcome::Fail,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmokeReportV2 {
    pub overall: Overall,
    pub exit_code: u32,
    pub identity: Option<SmokeIdentity>,
    pub probes: Vec<ProbeV2>,
    pub reasons: Vec<SmokeReason>,
}

/// Derive the aggregate verdict.
///
/// The reported per-probe outcome strings are deliberately ignored: the
/// comparison is redone from `expected` against `actual`. A retained root
/// identity means external mutation began, so an unobserved probe is a failure
/// rather than a "not run".
pub fn derive_overall(
    probes: &[ProbeV2],
    reasons: &[SmokeReason],
    root_identity: Option<SmokeIdentity>,
) -> Overall {
    if probes.len() != PROBE_ROSTER_V2.len() {
        return Overall::Fail;
    }
    for (probe, expected_name) in probes.iter().zip(PROBE_ROSTER_V2.iter()) {
        if probe.name != *expected_name {
            return Overall::Fail;
        }
    }
    if reasons.iter().any(SmokeReason::is_infrastructure) {
        return Overall::Fail;
    }
    let mut any_not_run = false;
    for probe in probes {
        match probe.derived_outcome() {
            ProbeOutcome::Fail => return Overall::Fail,
            ProbeOutcome::NotRun => any_not_run = true,
            ProbeOutcome::Pass => {}
        }
    }
    if any_not_run {
        // Mutation began the moment a root identity was validated, so a gap
        // after that point is a failure, not an unstarted run.
        return if root_identity.is_some() {
            Overall::Fail
        } else {
            Overall::NotRun
        };
    }
    if reasons.is_empty() {
        Overall::Pass
    } else {
        Overall::Fail
    }
}

// ---------------------------------------------------------------------------
// Private records
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerEvent {
    pub name: EventName,
    pub id: u32,
    pub version: u32,
    pub keyword: u64,
    pub identity: SmokeIdentity,
    pub reason: u32,
}

impl WorkerEvent {
    /// Pin the id, version, keyword, and reason to the named event.
    ///
    /// Only a fence carries a nonzero reason, and only one of the four closed
    /// reasons.
    pub fn validate(&self) -> Result<(), SmokeSchemaError> {
        if self.id != self.name.id() || self.version != 1 || self.keyword != 0x1 {
            return Err(SmokeSchemaError::InvalidEvent);
        }
        let reason_ok = match self.name {
            EventName::SessionFenced => (1..=4).contains(&self.reason),
            _ => self.reason == 0,
        };
        if !reason_ok {
            return Err(SmokeSchemaError::InvalidEvent);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CleanupSummary {
    pub pending_enter_count: u64,
    pub alias_count: u64,
    pub owned_handle_count: u64,
    pub completed_once: bool,
}

impl CleanupSummary {
    /// The canonical fact values this summary is equivalent to.
    fn as_facts(&self) -> Vec<(&'static str, FactValue)> {
        vec![
            (
                "pendingEnterCount",
                FactValue::Hex32(self.pending_enter_count as u32),
            ),
            ("aliasCount", FactValue::Hex32(self.alias_count as u32)),
            (
                "ownedHandleCount",
                FactValue::Hex32(self.owned_handle_count as u32),
            ),
            ("completedOnce", FactValue::Bool(self.completed_once)),
        ]
    }

    /// The summary must be exactly the `cleanup-close` probe's own facts.
    ///
    /// Two statements of the same numbers, compared rather than trusted: a
    /// worker that reported a clean fence in one and a leak in the other is
    /// refused instead of being averaged.
    pub fn validate_against(&self, cleanup_probe: &ProbeV2) -> Result<(), SmokeSchemaError> {
        if cleanup_probe.name != ProbeName::CleanupClose {
            return Err(SmokeSchemaError::InvalidCleanup);
        }
        let Some(Oracle::Facts { values }) = cleanup_probe.actual.as_ref() else {
            return Err(SmokeSchemaError::InvalidCleanup);
        };
        if *values != self.as_facts() {
            return Err(SmokeSchemaError::InvalidCleanup);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnloadSeed {
    pub former_alias_ranges_free: bool,
    pub owned_handles_closed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnloadObservation {
    pub provider_open_ntstatus: u32,
    pub fscontrol_open_ntstatus: u32,
    pub vdo_open_ntstatus: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedRecord {
    pub sequence: u32,
    pub nonce: WorkerNonce,
    pub root_identity: SmokeIdentity,
    pub disposable_identity: SmokeIdentity,
    pub vdo_native_name: String,
    pub probes: Vec<ProbeV2>,
    pub events: Vec<WorkerEvent>,
    pub reasons: Vec<SmokeReason>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunMountCommand {
    pub sequence: u32,
    pub nonce: WorkerNonce,
    pub root_identity: SmokeIdentity,
    pub vdo_native_name: String,
    pub dos_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveCleanedRecord {
    pub sequence: u32,
    pub nonce: WorkerNonce,
    pub root_identity: SmokeIdentity,
    pub disposable_identity: SmokeIdentity,
    pub vdo_native_name: String,
    pub dos_name: String,
    pub probes: Vec<ProbeV2>,
    pub events: Vec<WorkerEvent>,
    pub cleanup: CleanupSummary,
    pub unload_seed: UnloadSeed,
    pub reasons: Vec<SmokeReason>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostUnloadRecord {
    pub sequence: u32,
    pub nonce: WorkerNonce,
    pub root_identity: SmokeIdentity,
    pub vdo_native_name: String,
    pub dos_name: String,
    pub unload_observation: UnloadObservation,
    pub probes: Vec<ProbeV2>,
    pub reasons: Vec<SmokeReason>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerFrame {
    Staged(StagedRecord),
    RunMount(RunMountCommand),
    LiveCleaned(LiveCleanedRecord),
    PostUnload(PostUnloadRecord),
}

impl WorkerFrame {
    pub const fn stage(&self) -> &'static str {
        match self {
            Self::Staged(_) => "STAGED",
            Self::RunMount(_) => "RUN_MOUNT",
            Self::LiveCleaned(_) => "LIVE_CLEANED",
            Self::PostUnload(_) => "POST_UNLOAD",
        }
    }

    pub const fn sequence(&self) -> u32 {
        match self {
            Self::Staged(_) => 1,
            Self::RunMount(_) => 2,
            Self::LiveCleaned(_) => 3,
            Self::PostUnload(_) => 4,
        }
    }

    /// The probe slice this stage is allowed to carry.
    pub const fn probe_range(&self) -> Option<core::ops::Range<usize>> {
        match self {
            Self::Staged(_) => Some(STAGED_PROBE_RANGE),
            Self::LiveCleaned(_) => Some(LIVE_PROBE_RANGE),
            Self::PostUnload(_) => Some(POST_PROBE_RANGE),
            Self::RunMount(_) => None,
        }
    }

    fn probes(&self) -> &[ProbeV2] {
        match self {
            Self::Staged(record) => &record.probes,
            Self::LiveCleaned(record) => &record.probes,
            Self::PostUnload(record) => &record.probes,
            Self::RunMount(_) => &[],
        }
    }

    fn events(&self) -> &[WorkerEvent] {
        match self {
            Self::Staged(record) => &record.events,
            Self::LiveCleaned(record) => &record.events,
            Self::PostUnload(_) | Self::RunMount(_) => &[],
        }
    }

    fn reasons(&self) -> &[SmokeReason] {
        match self {
            Self::Staged(record) => &record.reasons,
            Self::LiveCleaned(record) => &record.reasons,
            Self::PostUnload(record) => &record.reasons,
            Self::RunMount(_) => &[],
        }
    }

    /// Everything a frame must satisfy before any of its facts may be trusted.
    ///
    /// One refusal invalidates the *whole* frame: a record whose event roster
    /// is wrong contributes no identity and no probe either.
    pub fn validate(&self) -> Result<(), SmokeSchemaError> {
        let sequence = match self {
            Self::Staged(record) => record.sequence,
            Self::RunMount(record) => record.sequence,
            Self::LiveCleaned(record) => record.sequence,
            Self::PostUnload(record) => record.sequence,
        };
        if sequence != self.sequence() {
            return Err(SmokeSchemaError::WrongSequence);
        }
        if let Some(range) = self.probe_range() {
            let expected = PROBE_ROSTER_V2
                .get(range)
                .ok_or(SmokeSchemaError::InvalidProbeRoster)?;
            let probes = self.probes();
            if probes.len() != expected.len() {
                return Err(SmokeSchemaError::InvalidProbeRoster);
            }
            for (probe, name) in probes.iter().zip(expected.iter()) {
                if probe.name != *name {
                    return Err(SmokeSchemaError::InvalidProbeRoster);
                }
                probe.validate()?;
            }
            // Index 25 is the runner's alone.
            if probes
                .iter()
                .any(|probe| probe.name == ProbeName::UnloadTransients)
            {
                return Err(SmokeSchemaError::InvalidProbeRoster);
            }
        }
        let events = self.events();
        if events.len() > PRIVATE_EVENT_MAX {
            return Err(SmokeSchemaError::InvalidEvent);
        }
        for (index, event) in events.iter().enumerate() {
            event.validate()?;
            if events
                .iter()
                .skip(index.saturating_add(1))
                .any(|other| other == event)
            {
                return Err(SmokeSchemaError::InvalidEvent);
            }
        }
        let reasons = self.reasons();
        if reasons.len() > REASON_MAX_ENTRIES {
            return Err(SmokeSchemaError::InvalidReason);
        }
        if reasons.iter().any(SmokeReason::is_infrastructure) {
            // The reserved prefix belongs to the runner; a worker that could
            // emit it could force the aggregate verdict from inside.
            return Err(SmokeSchemaError::InvalidReason);
        }
        if let Self::LiveCleaned(record) = self {
            let cleanup_probe = record
                .probes
                .iter()
                .find(|probe| probe.name == ProbeName::CleanupClose)
                .ok_or(SmokeSchemaError::InvalidCleanup)?;
            record.cleanup.validate_against(cleanup_probe)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The frame codec
// ---------------------------------------------------------------------------

mod json;
pub mod live;

pub use json::{
    decode_public_report_v2, decode_worker_frame, encode_public_report_v2, encode_worker_frame,
};
pub use live::{
    c4_session_fenced_record, encode_c4_evidence_payload, identity_from_c4_evidence_payload,
    merge_unload_transients, mount_sequence_delta, observe_from_mapped_ops, observe_live_range,
    observe_post_unload, observe_staged_prefix, oracle_from_cleanup_close,
    oracle_from_enter_cancel, oracle_from_enter_contention, oracle_from_enter_dual_role,
    oracle_from_enter_notify_credit, oracle_from_enter_poll, oracle_from_enter_timeout,
    oracle_from_inherited_handle, oracle_from_protocol_abort, oracle_from_session_layout,
    oracle_from_setup_security, oracle_from_view_protections, parse_c4_evidence_payload,
    protocol_abort_cqe, protocol_abort_from_session_fenced, session_fenced_worker_event,
    worker_event_from_c4_etw_record, C4EtwProviderGuid, C4EtwRecord, C4EvidencePayload,
    C4MappedOps, C4ObserveError, C4ProbeAccumulator, C4ProbeBackend, C4ProbeState,
    C4RequiredUnavailableDelta, C4UnloadFacts, CleanupCloseObservation, EnterCancelObservation,
    EnterContentionObservation, EnterDualRoleObservation, EnterNotifyCreditObservation,
    EnterPollObservation, InheritedHandleObservation, PostUnloadObservation, ProbeError,
    ProtocolAbortObservation, SessionLayoutFacts, SetupSecurityObservation, ViewProtectionFacts,
    C4_ETW_PROVIDER_GUID, C4_EVIDENCE_EVENT_VERSION, C4_EVIDENCE_KEYWORD, C4_EVIDENCE_PAYLOAD_SIZE,
    C4_SESSION_FENCED_EVENT_ID, LIVE_OPERATION_ORDER, LIVE_SIDECAR_NAMES,
    PREFLIGHT_ORCHESTRATION_SCHEMA, SESSION_FENCE_REASON_PROTOCOL_ABORT, STAGED_OPERATION_ORDER,
};

/// Write one length-prefixed frame.
pub fn write_worker_frame<W: Write>(
    writer: &mut W,
    frame: &WorkerFrame,
) -> Result<(), WorkerIoError> {
    let payload = encode_worker_frame(frame).map_err(WorkerIoError::Schema)?;
    let length = u32::try_from(payload.len())
        .map_err(|_| WorkerIoError::Schema(SmokeSchemaError::Length))?;
    writer
        .write_all(&length.to_le_bytes())
        .map_err(WorkerIoError::Io)?;
    writer.write_all(&payload).map_err(WorkerIoError::Io)?;
    writer.flush().map_err(WorkerIoError::Io)
}

/// Read one length-prefixed frame with bounded exact reads.
///
/// An early EOF is distinguished from a malformed payload: the runner needs to
/// tell "the worker died" from "the worker lied".
pub fn read_worker_frame<R: Read>(reader: &mut R) -> Result<WorkerFrame, WorkerIoError> {
    let mut header = [0u8; 4];
    read_exact_or_eof(reader, &mut header)?;
    let length = u32::from_le_bytes(header) as usize;
    if !(WORKER_FRAME_MIN..=WORKER_FRAME_MAX).contains(&length) {
        return Err(WorkerIoError::Schema(SmokeSchemaError::Length));
    }
    let mut payload = vec![0u8; length];
    read_exact_or_eof(reader, &mut payload)?;
    decode_worker_frame(&payload).map_err(WorkerIoError::Schema)
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), WorkerIoError> {
    let mut filled = 0usize;
    while filled < buffer.len() {
        let Some(slot) = buffer.get_mut(filled..) else {
            return Err(WorkerIoError::UnexpectedEof);
        };
        match reader.read(slot) {
            Ok(0) => return Err(WorkerIoError::UnexpectedEof),
            Ok(read) => filled = filled.saturating_add(read),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(WorkerIoError::Io(error)),
        }
    }
    Ok(())
}
