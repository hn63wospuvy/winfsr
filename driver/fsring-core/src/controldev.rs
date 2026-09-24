//! The control device's decidable half (`09-security.md` §1).
//!
//! **No device object is created here, or anywhere in slice C2.** This module
//! decides what a CREATE returns. Calling `IoCreateDeviceSecure`, proving the
//! SDDL yields the intended ACL, proving `FILE_DEVICE_SECURE_OPEN` behaves, and
//! proving a captured `EPROCESS` is the requestor are all **load-gated**: no
//! evidence for any of them is obtainable on a machine that cannot load a
//! driver, and a static string audit proves bytes reached the image, not that a
//! DDI was called with them.
//!
//! What *is* decidable is the precedence those properties surround, and it is a
//! total function over a finite domain.

#[cfg(test)]
mod tests;

/// ABI status names used directly by this module.
///
/// The behavior tests compare every returned status with
/// `fsring_abi::control::status`. They prove value agreement, not the
/// repository-wide absence of an unused equivalent literal.
pub use fsring_abi::control::status::{INSUFFICIENT_RESOURCES, SUCCESS};

/// The IRP's requestor mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestorMode {
    /// `UserMode`. The only mode §1 rule 1 admits.
    UserMode,
    /// Anything else. §1 rule 1: *"A non-`UserMode` create returns
    /// `ACCESS_DENIED`"*.
    KernelMode,
}

/// Every requestor mode, for exhaustive iteration.
pub const ALL_REQUESTOR_MODES: [RequestorMode; 2] =
    [RequestorMode::UserMode, RequestorMode::KernelMode];

/// The four inputs `09-security.md` §1's precedence is stated over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateRequest {
    /// The IRP's requestor mode.
    pub mode: RequestorMode,
    /// `FileObject->FileName` is empty — a root open.
    pub file_name_empty: bool,
    /// `RelatedFileObject` is null.
    pub related_file_object_null: bool,
    /// The per-file context was allocated and referenced.
    pub context_alloc_ok: bool,
}

/// What the create completes with.
///
/// §1: *"Every one of these failures completes with `IoStatus.Information = 0`
/// and installs no file context."* The success returns `Information = 0` too, so
/// `information` is 0 on every cell and `context_installed` is what separates
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateOutcome {
    /// `IoStatus.Status`.
    pub status: i32,
    /// `IoStatus.Information`.
    pub information: usize,
    /// Whether the per-file context is installed.
    pub context_installed: bool,
}

/// Every cell of the decision's domain, for exhaustive iteration.
///
/// Four booleans-worth of input — mode, name, related object, allocation — so
/// sixteen cells, listed rather than generated because a `const` context cannot
/// build them and because listing them makes the domain visible.
pub const ALL_CREATE_REQUESTS: [CreateRequest; 16] = {
    const fn r(m: RequestorMode, n: bool, rel: bool, a: bool) -> CreateRequest {
        CreateRequest {
            mode: m,
            file_name_empty: n,
            related_file_object_null: rel,
            context_alloc_ok: a,
        }
    }
    use RequestorMode::{KernelMode, UserMode};
    [
        r(UserMode, true, true, true),
        r(UserMode, true, true, false),
        r(UserMode, true, false, true),
        r(UserMode, true, false, false),
        r(UserMode, false, true, true),
        r(UserMode, false, true, false),
        r(UserMode, false, false, true),
        r(UserMode, false, false, false),
        r(KernelMode, true, true, true),
        r(KernelMode, true, true, false),
        r(KernelMode, true, false, true),
        r(KernelMode, true, false, false),
        r(KernelMode, false, true, true),
        r(KernelMode, false, true, false),
        r(KernelMode, false, false, true),
        r(KernelMode, false, false, false),
    ]
};

/// Decide a create, per `09-security.md` §1's closed precedence.
///
/// **The ORDER is the claim, not the row mapping.** Rules 1 and 2 overlap on
/// every `KernelMode` cell that also has a name or a related object, and only
/// precedence decides that `ACCESS_DENIED` wins there. A test that checked each
/// rule's mapping in isolation would pass with the rules reversed.
///
/// Two tests hold it. `the_overlapping_cell_resolves_to_rule_one` names that
/// cell against this function, and
/// `reordering_the_rules_changes_the_derived_decision` reorders the document's
/// own rule texts and requires the decision to move with them. C2's first round
/// found this comment claiming instead that "the mutation gate carries a
/// row-reordering class"; **it did not, and no such operator existed** — the
/// reordering had been applied once by hand and reverted.
pub const fn decide_create(request: CreateRequest) -> CreateOutcome {
    // A closure would be cleaner and is not callable from a `const fn`, so the
    // refusal shape is written out. It is identical on all three failing rules,
    // which is §1's "Every one of these failures completes with
    // IoStatus.Information = 0 and installs no file context" made structural:
    // there is no way to write a failing arm that installs a context.
    const fn refused(status: i32) -> CreateOutcome {
        CreateOutcome {
            status,
            information: 0,
            context_installed: false,
        }
    }

    // Rule 1: "A non-`UserMode` create returns `ACCESS_DENIED`".
    if !matches!(request.mode, RequestorMode::UserMode) {
        return refused(fsring_abi::control::status::ACCESS_DENIED);
    }
    // Rule 2: "a create whose FileObject->FileName is nonempty or whose
    // RelatedFileObject is non-null ... returns OBJECT_NAME_NOT_FOUND".
    if !request.file_name_empty || !request.related_file_object_null {
        return refused(fsring_abi::control::status::OBJECT_NAME_NOT_FOUND);
    }
    // Rule 3: "Failure to allocate/reference the per-file context returns
    // INSUFFICIENT_RESOURCES".
    if !request.context_alloc_ok {
        return refused(INSUFFICIENT_RESOURCES);
    }
    // "A successful UserMode root create atomically captures and references the
    // IRP requestor EPROCESS in that per-file context before returning SUCCESS
    // with Information = 0."
    CreateOutcome {
        status: SUCCESS,
        information: 0,
        context_installed: true,
    }
}

macro_rules! control_ioctl_registry {
    (
        $(
            $(#[$variant_meta:meta])*
            $variant:ident => {
                code: $code:ident,
                name: $name:literal,
                function: $function:ident
            }
        ),+ $(,)?
    ) => {
        /// The seven control IOCTLs of `02-transport.md` §10.2.
        ///
        /// A closed set: the demux admits exactly these and nothing else.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum ControlIoctl {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
        }

        /// Every control IOCTL, for exhaustive iteration.
        pub const ALL_CONTROL_IOCTLS: [ControlIoctl; <[()]>::len(&[
            $(control_ioctl_registry!(@unit $variant)),+
        ])] = [$(ControlIoctl::$variant),+];

        impl ControlIoctl {
            /// This IOCTL's control code, taken from the frozen `fsring-abi`.
            pub const fn code(self) -> u32 {
                match self {
                    $(Self::$variant => fsring_abi::control::$code),+
                }
            }

            /// This IOCTL's `02-transport.md` §10.2 name, for the document check.
            pub const fn doc_name(self) -> &'static str {
                match self {
                    $(Self::$variant => $name),+
                }
            }

            /// This IOCTL's function number.
            pub const fn function(self) -> u32 {
                match self {
                    $(Self::$variant => fsring_abi::control::ioctl_function::$function),+
                }
            }
        }

        /// Map a control code to its IOCTL, or refuse it.
        ///
        /// Total over `u32`: exactly the registered codes are admitted.
        pub const fn demux(code: u32) -> Option<ControlIoctl> {
            $(if code == fsring_abi::control::$code {
                return Some(ControlIoctl::$variant);
            })+
            None
        }
    };
    (@unit $variant:ident) => { () };
}

control_ioctl_registry! {
    /// `IOCTL_FSRING_SETUP`, function `0x800`.
    Setup => {
        code: IOCTL_FSRING_SETUP,
        name: "IOCTL_FSRING_SETUP",
        function: SETUP
    },
    /// `IOCTL_FSRING_ENTER`, function `0x801`.
    Enter => {
        code: IOCTL_FSRING_ENTER,
        name: "IOCTL_FSRING_ENTER",
        function: ENTER
    },
    /// `IOCTL_FSRING_ATTACH`, function `0x802`.
    Attach => {
        code: IOCTL_FSRING_ATTACH,
        name: "IOCTL_FSRING_ATTACH",
        function: ATTACH
    },
    /// `IOCTL_FSRING_DONATE_BACKING`, function `0x803`.
    DonateBacking => {
        code: IOCTL_FSRING_DONATE_BACKING,
        name: "IOCTL_FSRING_DONATE_BACKING",
        function: DONATE_BACKING
    },
    /// `IOCTL_FSRING_DONATE_SECURITY_CONTEXT`, function `0x804`.
    DonateSecurityContext => {
        code: IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
        name: "IOCTL_FSRING_DONATE_SECURITY_CONTEXT",
        function: DONATE_SECURITY_CONTEXT
    },
    /// `IOCTL_FSRING_DETACH`, function `0x805`.
    Detach => {
        code: IOCTL_FSRING_DETACH,
        name: "IOCTL_FSRING_DETACH",
        function: DETACH
    },
    /// `IOCTL_FSRING_RETIRE_MOUNT`, function `0x806`.
    RetireMount => {
        code: IOCTL_FSRING_RETIRE_MOUNT,
        name: "IOCTL_FSRING_RETIRE_MOUNT",
        function: RETIRE_MOUNT
    },
}

/// An opaque requestor identity.
///
/// `09-security.md` §1's `EPROCESS`, modelled as a value the host can compare
/// and nothing more. §1's provenance note is explicit that `RequestorMode` and
/// `EPROCESS` are *"WDK identifiers … not crate-carried constants"*, so this
/// carries no wire meaning and is not derived from `fsring-abi`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestorId(pub u64);

/// A handle admitted for a subsequent operation.
///
/// Constructible only by [`authorize`], and only when both of §1's conditions
/// held. It is the *permission*, not the operation: C2 creates no device and
/// performs no IOCTL.
#[derive(Debug, PartialEq, Eq)]
pub struct AdmittedHandle {
    identity: RequestorId,
}

impl AdmittedHandle {
    /// The identity this admission was granted against.
    pub const fn identity(&self) -> RequestorId {
        self.identity
    }
}

/// The result of authorizing an operation on a control handle.
///
/// **`Refused` carries no payload, and that is the point.** §1 requires a
/// refusal to happen *"with no mapping or side effect, even before the first
/// IOCTL executes"*. Making the refusal a variant with no fields means a
/// refusal that carried a mapping is **not representable**, rather than being
/// forbidden by a test somebody has to remember to write. C1's review spent
/// three rounds establishing that a structural catch is worth more than an
/// asserted one.
#[derive(Debug, PartialEq, Eq)]
pub enum Authorization {
    /// Both of §1's conditions held.
    Admitted(AdmittedHandle),
    /// `ACCESS_DENIED`, with nothing attached.
    Refused,
}

impl Authorization {
    /// The status a refusal completes with. §1: `ACCESS_DENIED`.
    pub const fn status(&self) -> i32 {
        match self {
            Self::Admitted(_) => SUCCESS,
            Self::Refused => fsring_abi::control::status::ACCESS_DENIED,
        }
    }
}

/// Authorize a subsequent operation on a control handle.
///
/// `09-security.md` §1: every subsequent SETUP/ATTACH/IOCTL *"requires **both**
/// `RequestorMode == UserMode` **and** the current IRP's requestor `EPROCESS`
/// matching the one captured at CREATE. A duplicated or inherited handle
/// presented from a different process is `ACCESS_DENIED`."*
///
/// A conjunction, and both halves are load-bearing: `both_conditions_are_
/// required_and_each_is_load_bearing` fails if either is dropped.
pub const fn authorize(
    mode: RequestorMode,
    captured: RequestorId,
    current: RequestorId,
) -> Authorization {
    if !matches!(mode, RequestorMode::UserMode) {
        return Authorization::Refused;
    }
    if captured.0 != current.0 {
        return Authorization::Refused;
    }
    Authorization::Admitted(AdmittedHandle { identity: captured })
}

/// The inputs to one synchronous control-device IOCTL decision.
///
/// This is deliberately just the data the pure core can decide. An IRP adapter
/// supplies it after safely obtaining the buffered input; this module neither
/// observes IRP state nor performs a side effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlIoctlRequest<'a> {
    /// The current IRP requestor mode.
    pub mode: RequestorMode,
    /// The identity captured at CREATE for this handle.
    pub captured: RequestorId,
    /// The current IRP requestor identity.
    pub current: RequestorId,
    /// The raw IOCTL control code.
    pub code: u32,
    /// The buffered IOCTL input body.
    pub input: &'a [u8],
}

/// A synchronous control-device IOCTL decision with no side-effect payload.
///
/// `Unknown` is intentionally not a numeric status. The WDK adapter alone
/// translates it to `STATUS_INVALID_DEVICE_REQUEST`, keeping the pure core
/// WDK-number-free. Neither variant can contain a result value, and
/// [`Self::information`] is structurally zero for every decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlDispatchDecision {
    /// Complete the IOCTL with this frozen-ABI status.
    Complete(i32),
    /// The raw code is outside the closed control IOCTL registry.
    Unknown,
    /// An authorized SETUP. The native adapter owns the whole ordered
    /// choreography, including the completion status and `Information`.
    DispatchSetup,
    /// An authorized ENTER, likewise adapter-owned.
    DispatchEnter,
}

impl ControlDispatchDecision {
    /// `IoStatus.Information` for every synchronous decision.
    ///
    /// There is no field to accidentally set: the synchronous control decisions
    /// produce neither an output body nor a side-effect value. The two
    /// adapter-owned variants are not synchronous at all — see
    /// [`Self::is_synchronous`] — and the adapter writes their own status and
    /// information; this value says nothing about them.
    pub const fn information(self) -> usize {
        0
    }

    /// Does this decision complete the IRP by itself?
    ///
    /// The dispatch variants deliberately carry no status and no information,
    /// so a caller that forgets to route them cannot accidentally complete an
    /// admitted SETUP or ENTER with a fabricated success.
    pub const fn is_synchronous(self) -> bool {
        matches!(self, Self::Complete(_) | Self::Unknown)
    }
}

/// Decide one synchronous control-device IOCTL.
///
/// Authorization is deliberately first: an unadmitted caller cannot learn
/// whether the code is registered or whether a donation body is malformed.
/// Only an admitted caller reaches the closed IOCTL demux, and only the
/// donation code reaches its frozen-ABI validator.
pub fn decide_control_ioctl(request: ControlIoctlRequest<'_>) -> ControlDispatchDecision {
    if matches!(
        authorize(request.mode, request.captured, request.current),
        Authorization::Refused
    ) {
        return ControlDispatchDecision::Complete(fsring_abi::control::status::ACCESS_DENIED);
    }

    let Some(ioctl) = demux(request.code) else {
        return ControlDispatchDecision::Unknown;
    };

    match ioctl {
        // SETUP is implemented. Its request body is *not* validated here: the
        // adapter owns a private METHOD_BUFFERED snapshot, and validating a
        // buffer the daemon can still change would be a decision made on
        // different bytes than the ones the session is built from.
        ControlIoctl::Setup => ControlDispatchDecision::DispatchSetup,
        // ENTER is implemented too, and for the same reason its request body is
        // not validated here: the adapter owns the private snapshot.
        ControlIoctl::Enter => ControlDispatchDecision::DispatchEnter,
        ControlIoctl::DonateSecurityContext => {
            let status =
                match fsring_abi::validate::validate_donate_security_context_v1(request.input) {
                    Ok(()) => fsring_abi::control::status::NOT_SUPPORTED,
                    Err(error) => error.status(),
                };
            ControlDispatchDecision::Complete(status)
        }
        _ => ControlDispatchDecision::Complete(fsring_abi::control::status::NOT_SUPPORTED),
    }
}

/// How many bytes of a METHOD_BUFFERED control request to snapshot before the
/// frozen validator runs.
///
/// `02-transport.md`: "Once eight bytes are safely available, an unknown
/// version has precedence and maps to REVISION_MISMATCH, then unsupported
/// required flags map to NOT_SUPPORTED, then malformed size/range/reserved bytes
/// map to INVALID_PARAMETER. A length below eight cannot expose a version and is
/// INVALID_PARAMETER." The `fsring-abi` validators already apply that order to
/// the slice they are given -- but only if the slice is the caller's bytes. A
/// dispatch that refuses a wrong length BEFORE the header is read, or hands the
/// validator a fixed-size copy, answers INVALID_PARAMETER where the version or
/// the required flags should have decided (round-17 evidence E4).
///
/// `None` below the eight-byte header. Otherwise the caller's length, capped at
/// one byte past the known size: enough for the validator to see a wrong length
/// without ever copying an unbounded buffer.
pub const fn control_request_snapshot_len(input_length: usize, known_size: usize) -> Option<usize> {
    if input_length < 8 {
        return None;
    }
    let cap = known_size.saturating_add(1);
    Some(if input_length < cap {
        input_length
    } else {
        cap
    })
}
