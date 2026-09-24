use std::fmt::{self, Write as _};

const NORMAL_PROBE_NAMES: [&str; 9] = [
    "root-open",
    "trailing-open",
    "unknown-ioctl",
    "setup",
    "donate-short",
    "donate-wrong-version",
    "donate",
    "child-inherited-handle",
    "parent-handle-after-child",
];
const NORMAL_EXPECTED_ERRORS: [Option<u32>; 9] = [
    None,
    Some(ERROR_FILE_NOT_FOUND),
    Some(ERROR_INVALID_FUNCTION),
    Some(ERROR_NOT_SUPPORTED),
    Some(ERROR_INVALID_PARAMETER),
    Some(ERROR_REVISION_MISMATCH),
    Some(ERROR_NOT_SUPPORTED),
    Some(ERROR_ACCESS_DENIED),
    Some(ERROR_NOT_SUPPORTED),
];
const ABSENT_PROBE_NAMES: [&str; 1] = ["device-absent"];

const ERROR_INVALID_FUNCTION: u32 = 1;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_NOT_SUPPORTED: u32 = 50;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_REVISION_MISMATCH: u32 = 1306;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Pass,
    Fail,
    NotRun,
}

impl fmt::Display for Outcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::NotRun => "NOT RUN",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProbeResult {
    name: &'static str,
    outcome: Outcome,
    expected: Option<u32>,
    actual: Option<u32>,
    reason: Option<String>,
}

impl ProbeResult {
    fn passed(name: &'static str) -> Self {
        Self {
            name,
            outcome: Outcome::Pass,
            expected: None,
            actual: None,
            reason: None,
        }
    }

    fn not_run_expected(
        name: &'static str,
        expected: Option<u32>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            name,
            outcome: Outcome::NotRun,
            expected,
            actual: None,
            reason: Some(reason.into()),
        }
    }

    fn failed(
        name: &'static str,
        expected: Option<u32>,
        actual: Option<u32>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            name,
            outcome: Outcome::Fail,
            expected,
            actual,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Report {
    overall: Outcome,
    exit_code: i32,
    probes: Vec<ProbeResult>,
    reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeObservation {
    Success,
    Error(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RunMode {
    Normal,
    ExpectAbsent,
    ChildHandle(usize),
    /// The persistent live worker. It speaks only the private protocol.
    C4LiveWorker(String),
    /// The read-only post-unload worker.
    C4PostUnload(Box<PostUnloadArgs>),
}

fn parse_args(args: &[String]) -> Result<RunMode, String> {
    match args {
        [] => Ok(RunMode::Normal),
        [mode] if mode == "--expect-absent" => Ok(RunMode::ExpectAbsent),
        [mode, raw_handle] if mode == "--child-handle" => {
            let digits = raw_handle
                .strip_prefix("0x")
                .or_else(|| raw_handle.strip_prefix("0X"))
                .unwrap_or(raw_handle);
            let width = std::mem::size_of::<usize>() * 2;
            if digits.len() != width || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(format!(
                    "child handle must contain exactly {width} hexadecimal digits"
                ));
            }

            let handle = usize::from_str_radix(digits, 16)
                .map_err(|_| "child handle is outside the pointer-sized range".to_owned())?;
            if handle == 0 || handle == usize::MAX {
                return Err("child handle is a reserved value".to_owned());
            }
            Ok(RunMode::ChildHandle(handle))
        }
        [mode, ..] if mode == "--child-handle" => {
            Err("--child-handle requires exactly one value".to_owned())
        }
        [mode, flag, value] if mode == "--c4-live-worker" && flag == "--nonce" => {
            if fsring_user::smoke::WorkerNonce::parse(value).is_err() {
                return Err("--nonce must be 32 uppercase hex digits".to_owned());
            }
            Ok(RunMode::C4LiveWorker(value.clone()))
        }
        [mode, ..] if mode == "--c4-live-worker" => {
            Err("--c4-live-worker requires exactly --nonce HEX32".to_owned())
        }
        [mode, ..] if mode == "--c4-post-unload" => {
            parse_post_unload_args(args).map(|parsed| RunMode::C4PostUnload(Box::new(parsed)))
        }
        _ => Err(
            "expected no arguments, --expect-absent, --child-handle VALUE, --c4-live-worker, or --c4-post-unload"
                .to_owned(),
        ),
    }
}

fn expected_error_probe(
    name: &'static str,
    expected: u32,
    observation: NativeObservation,
) -> ProbeResult {
    match observation {
        NativeObservation::Error(actual) if actual == expected => ProbeResult {
            name,
            outcome: Outcome::Pass,
            expected: Some(expected),
            actual: Some(actual),
            reason: None,
        },
        NativeObservation::Error(actual) => ProbeResult {
            name,
            outcome: Outcome::Fail,
            expected: Some(expected),
            actual: Some(actual),
            reason: Some(format!(
                "expected Win32 error {expected}, observed Win32 error {actual}"
            )),
        },
        NativeObservation::Success => ProbeResult {
            name,
            outcome: Outcome::Fail,
            expected: Some(expected),
            actual: None,
            reason: Some(format!(
                "expected Win32 error {expected}, but the native call succeeded"
            )),
        },
    }
}

fn summarize(
    required_names: &[&str],
    probes: Vec<ProbeResult>,
    mut reasons: Vec<String>,
) -> Report {
    let has_infrastructure_error = !reasons.is_empty();
    let mut malformed_roster = false;

    if required_names.is_empty() {
        malformed_roster = true;
        reasons.push("required probe roster is empty".to_owned());
    }

    for (index, required) in required_names.iter().enumerate() {
        if required_names[..index].contains(required) {
            malformed_roster = true;
            reasons.push(format!("required probe roster duplicates {required}"));
            continue;
        }

        let count = probes
            .iter()
            .filter(|probe| probe.name == *required)
            .count();
        match count {
            0 => {
                malformed_roster = true;
                reasons.push(format!("missing required probe {required}"));
            }
            1 => {}
            _ => {
                malformed_roster = true;
                reasons.push(format!("duplicate required probe {required}"));
            }
        }
    }

    for probe in &probes {
        if !required_names.contains(&probe.name) {
            malformed_roster = true;
            reasons.push(format!("unexpected probe {}", probe.name));
        }
        if let Some(reason) = &probe.reason {
            reasons.push(format!("{}: {reason}", probe.name));
        }
    }

    if probes.len() != required_names.len() {
        malformed_roster = true;
    }

    let overall = if has_infrastructure_error
        || malformed_roster
        || probes.iter().any(|probe| probe.outcome == Outcome::Fail)
    {
        Outcome::Fail
    } else if probes.iter().any(|probe| probe.outcome == Outcome::NotRun) {
        Outcome::NotRun
    } else {
        Outcome::Pass
    };
    let exit_code = match overall {
        Outcome::Pass => 0,
        Outcome::Fail => 1,
        Outcome::NotRun => 2,
    };

    Report {
        overall,
        exit_code,
        probes,
        reasons,
    }
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\t' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\u{000c}' => output.push_str("\\f"),
            '\r' => output.push_str("\\r"),
            '\u{0000}'..='\u{001f}' => {
                write!(output, "\\u{:04X}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            _ => output.push(character),
        }
    }
    output.push('"');
}

fn push_optional_number(output: &mut String, value: Option<u32>) {
    match value {
        Some(value) => write!(output, "{value}").expect("writing to a String cannot fail"),
        None => output.push_str("null"),
    }
}

fn report_json(report: &Report) -> String {
    let mut output = String::from("{\"schema\":\"fsring-control-smoke/v1\",\"overall\":");
    push_json_string(&mut output, &report.overall.to_string());
    write!(output, ",\"exitCode\":{},\"probes\":[", report.exit_code)
        .expect("writing to a String cannot fail");

    for (index, probe) in report.probes.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("{\"name\":");
        push_json_string(&mut output, probe.name);
        output.push_str(",\"outcome\":");
        push_json_string(&mut output, &probe.outcome.to_string());
        output.push_str(",\"expected\":");
        push_optional_number(&mut output, probe.expected);
        output.push_str(",\"actual\":");
        push_optional_number(&mut output, probe.actual);
        output.push('}');
    }

    output.push_str("],\"reasons\":[");
    for (index, reason) in report.reasons.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        push_json_string(&mut output, reason);
    }
    output.push_str("]}");
    output
}

#[cfg(test)]
fn child_wait_needs_containment(wait_result: u32) -> bool {
    wait_result != 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleFailure {
    RestoreNotConfirmed,
    ResumeFailed,
    WrongResumeCount(u32),
    WaitTimeout,
    WaitFailed,
    UnexpectedWait(u32),
    ExitQueryFailed,
    NonzeroExit(u32),
    ActiveQueryFailed,
    ActiveProcesses(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleStep {
    RestoreConfirmed(bool),
    ResumeResult(u32),
    WaitResult(u32),
    ExitResult(Result<u32, ()>),
    ActiveResult(Result<u32, ()>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleDecision {
    Continue,
    Pass,
    ContainAndFail(LifecycleFailure),
}

fn lifecycle_decision(step: LifecycleStep) -> LifecycleDecision {
    match step {
        LifecycleStep::RestoreConfirmed(true) => LifecycleDecision::Continue,
        LifecycleStep::RestoreConfirmed(false) => {
            LifecycleDecision::ContainAndFail(LifecycleFailure::RestoreNotConfirmed)
        }
        LifecycleStep::ResumeResult(1) => LifecycleDecision::Continue,
        LifecycleStep::ResumeResult(u32::MAX) => {
            LifecycleDecision::ContainAndFail(LifecycleFailure::ResumeFailed)
        }
        LifecycleStep::ResumeResult(count) => {
            LifecycleDecision::ContainAndFail(LifecycleFailure::WrongResumeCount(count))
        }
        LifecycleStep::WaitResult(0) => LifecycleDecision::Continue,
        LifecycleStep::WaitResult(258) => {
            LifecycleDecision::ContainAndFail(LifecycleFailure::WaitTimeout)
        }
        LifecycleStep::WaitResult(u32::MAX) => {
            LifecycleDecision::ContainAndFail(LifecycleFailure::WaitFailed)
        }
        LifecycleStep::WaitResult(other) => {
            LifecycleDecision::ContainAndFail(LifecycleFailure::UnexpectedWait(other))
        }
        LifecycleStep::ExitResult(Ok(0)) => LifecycleDecision::Continue,
        LifecycleStep::ExitResult(Err(())) => {
            LifecycleDecision::ContainAndFail(LifecycleFailure::ExitQueryFailed)
        }
        LifecycleStep::ExitResult(Ok(code)) => {
            LifecycleDecision::ContainAndFail(LifecycleFailure::NonzeroExit(code))
        }
        LifecycleStep::ActiveResult(Ok(0)) => LifecycleDecision::Pass,
        LifecycleStep::ActiveResult(Err(())) => {
            LifecycleDecision::ContainAndFail(LifecycleFailure::ActiveQueryFailed)
        }
        LifecycleStep::ActiveResult(Ok(active)) => {
            LifecycleDecision::ContainAndFail(LifecycleFailure::ActiveProcesses(active))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContainmentObservation {
    terminate_succeeded: bool,
    zero_confirmed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FailureResolution {
    probe_passes: bool,
    release_job: bool,
}

fn resolve_failed_lifecycle(observation: ContainmentObservation) -> FailureResolution {
    let _termination_remains_part_of_the_failure = observation.terminate_succeeded;
    FailureResolution {
        probe_passes: false,
        release_job: observation.zero_confirmed,
    }
}

struct PreparedReport<L> {
    report: Report,
    lease: Option<L>,
}

impl<L> PreparedReport<L> {
    fn new(report: Report, lease: Option<L>) -> Self {
        Self { report, lease }
    }
}

fn write_prepared_report<W: std::io::Write, L>(
    writer: &mut W,
    prepared: PreparedReport<L>,
) -> std::io::Result<()> {
    let PreparedReport { report, lease } = prepared;
    let json = report_json(&report);
    let write_result = writer
        .write_all(json.as_bytes())
        .and_then(|()| writer.write_all(b"\n"));
    let flush_result = writer.flush();
    drop(json);
    drop(report);
    // The containment lease is deliberately the final owned report resource.
    drop(lease);

    match (write_result, flush_result) {
        (Err(error), _) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[cfg(windows)]
mod windows {
    use super::{
        expected_error_probe, summarize, NativeObservation, ProbeResult, Report,
        ABSENT_PROBE_NAMES, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_FUNCTION,
        ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, ERROR_REVISION_MISMATCH,
        NORMAL_EXPECTED_ERRORS, NORMAL_PROBE_NAMES,
    };
    use fsring_abi::{
        control::{IOCTL_FSRING_DONATE_SECURITY_CONTEXT, IOCTL_FSRING_SETUP},
        msgs::{ControlHeader, DonateSecurityContextV1, CONTROL_VERSION_V1},
    };
    use std::{
        mem::{align_of, size_of},
        os::windows::ffi::OsStrExt,
        ptr, slice,
        time::{Duration, Instant},
    };

    mod sys {
        use core::ffi::c_void;

        pub type Handle = *mut c_void;
        pub type Bool = i32;

        pub const FALSE: Bool = 0;
        pub const TRUE: Bool = 1;
        pub const INVALID_HANDLE_VALUE: Handle = usize::MAX as Handle;
        pub const GENERIC_READ: u32 = 0x8000_0000;
        pub const GENERIC_WRITE: u32 = 0x4000_0000;
        pub const FILE_SHARE_READ: u32 = 0x0000_0001;
        pub const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        pub const FILE_SHARE_DELETE: u32 = 0x0000_0004;
        pub const OPEN_EXISTING: u32 = 3;
        pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
        pub const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
        pub const WAIT_FAILED: u32 = 0xffff_ffff;
        pub const CREATE_SUSPENDED: u32 = 0x0000_0004;
        pub const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
        pub const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
        pub const PROC_THREAD_ATTRIBUTE_JOB_LIST: usize = 0x0002_000d;
        pub const JOB_OBJECT_LIMIT_BREAKAWAY_OK: u32 = 0x0000_0800;
        pub const JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK: u32 = 0x0000_1000;
        pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
        pub const JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS: i32 = 1;
        pub const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;

        #[repr(C)]
        pub struct StartupInfoW {
            pub cb: u32,
            pub lp_reserved: *mut u16,
            pub lp_desktop: *mut u16,
            pub lp_title: *mut u16,
            pub dw_x: u32,
            pub dw_y: u32,
            pub dw_x_size: u32,
            pub dw_y_size: u32,
            pub dw_x_count_chars: u32,
            pub dw_y_count_chars: u32,
            pub dw_fill_attribute: u32,
            pub dw_flags: u32,
            pub w_show_window: u16,
            pub cb_reserved2: u16,
            pub lp_reserved2: *mut u8,
            pub h_std_input: Handle,
            pub h_std_output: Handle,
            pub h_std_error: Handle,
        }

        #[repr(C)]
        pub struct StartupInfoExW {
            pub startup_info: StartupInfoW,
            pub attribute_list: *mut c_void,
        }

        #[repr(C)]
        pub struct ProcessInformation {
            pub h_process: Handle,
            pub h_thread: Handle,
            pub process_id: u32,
            pub thread_id: u32,
        }

        #[repr(C)]
        pub struct JobObjectBasicAccountingInformation {
            pub total_user_time: i64,
            pub total_kernel_time: i64,
            pub this_period_total_user_time: i64,
            pub this_period_total_kernel_time: i64,
            pub total_page_fault_count: u32,
            pub total_processes: u32,
            pub active_processes: u32,
            pub total_terminated_processes: u32,
        }

        #[repr(C)]
        pub struct JobObjectBasicLimitInformation {
            pub per_process_user_time_limit: i64,
            pub per_job_user_time_limit: i64,
            pub limit_flags: u32,
            pub minimum_working_set_size: usize,
            pub maximum_working_set_size: usize,
            pub active_process_limit: u32,
            pub affinity: usize,
            pub priority_class: u32,
            pub scheduling_class: u32,
        }

        #[repr(C)]
        pub struct IoCounters {
            pub read_operation_count: u64,
            pub write_operation_count: u64,
            pub other_operation_count: u64,
            pub read_transfer_count: u64,
            pub write_transfer_count: u64,
            pub other_transfer_count: u64,
        }

        #[repr(C)]
        pub struct JobObjectExtendedLimitInformation {
            pub basic_limit_information: JobObjectBasicLimitInformation,
            pub io_info: IoCounters,
            pub process_memory_limit: usize,
            pub job_memory_limit: usize,
            pub peak_process_memory_used: usize,
            pub peak_job_memory_used: usize,
        }

        #[link(name = "kernel32")]
        extern "system" {
            pub fn CreateFileW(
                file_name: *const u16,
                desired_access: u32,
                share_mode: u32,
                security_attributes: *mut c_void,
                creation_disposition: u32,
                flags_and_attributes: u32,
                template_file: Handle,
            ) -> Handle;
            pub fn DeviceIoControl(
                device: Handle,
                ioctl: u32,
                input: *mut c_void,
                input_len: u32,
                output: *mut c_void,
                output_len: u32,
                bytes_returned: *mut u32,
                overlapped: *mut c_void,
            ) -> Bool;
            pub fn GetHandleInformation(object: Handle, flags: *mut u32) -> Bool;
            pub fn SetHandleInformation(object: Handle, mask: u32, flags: u32) -> Bool;
            pub fn CreateProcessW(
                application_name: *const u16,
                command_line: *mut u16,
                process_attributes: *mut c_void,
                thread_attributes: *mut c_void,
                inherit_handles: Bool,
                creation_flags: u32,
                environment: *mut c_void,
                current_directory: *const u16,
                startup_info: *mut StartupInfoW,
                process_information: *mut ProcessInformation,
            ) -> Bool;
            pub fn CreateJobObjectW(job_attributes: *mut c_void, name: *const u16) -> Handle;
            pub fn SetInformationJobObject(
                job: Handle,
                information_class: i32,
                information: *mut c_void,
                information_length: u32,
            ) -> Bool;
            pub fn QueryInformationJobObject(
                job: Handle,
                information_class: i32,
                information: *mut c_void,
                information_length: u32,
                return_length: *mut u32,
            ) -> Bool;
            pub fn TerminateJobObject(job: Handle, exit_code: u32) -> Bool;
            pub fn InitializeProcThreadAttributeList(
                attribute_list: *mut c_void,
                attribute_count: u32,
                flags: u32,
                size: *mut usize,
            ) -> Bool;
            pub fn UpdateProcThreadAttribute(
                attribute_list: *mut c_void,
                flags: u32,
                attribute: usize,
                value: *mut c_void,
                size: usize,
                previous_value: *mut c_void,
                return_size: *mut usize,
            ) -> Bool;
            pub fn DeleteProcThreadAttributeList(attribute_list: *mut c_void);
            pub fn ResumeThread(thread: Handle) -> u32;
            pub fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
            pub fn GetExitCodeProcess(process: Handle, exit_code: *mut u32) -> Bool;
            pub fn CloseHandle(object: Handle) -> Bool;
            pub fn GetLastError() -> u32;
            pub fn SetLastError(error: u32);
        }
    }

    const DEVICE_PATH: &str = r"\\.\FsRing";
    const TRAILING_DEVICE_PATH: &str = r"\\.\FsRing\trailing";
    const ERROR_INVALID_HANDLE: u32 = 6;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const CHILD_TIMEOUT_MILLISECONDS: u32 = 30_000;
    const CHILD_TERMINATION_CONFIRM_MILLISECONDS: u32 = 5_000;
    const CHILD_TERMINATION_POLL_MILLISECONDS: u64 = 10;
    const CHILD_PARSE_OR_HANDLE_FAILURE: u8 = 20;
    const CHILD_UNEXPECTED_IOCTL_SUCCESS: u8 = 21;
    const CHILD_WRONG_WIN32_ERROR: u8 = 22;
    const CHILD_FORCED_TERMINATION: u32 = 23;

    // CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, Function=0x8ff,
    // METHOD_BUFFERED=0, FILE_READ_ACCESS|FILE_WRITE_ACCESS=3).
    const UNKNOWN_BUFFERED_READ_WRITE_IOCTL: u32 = 0x0022_e3fc;

    const _: () = assert!(size_of::<DonateSecurityContextV1>() == 32);
    const _: () = assert!(align_of::<DonateSecurityContextV1>() == 8);
    #[cfg(target_pointer_width = "64")]
    const _: () = {
        assert!(size_of::<sys::StartupInfoW>() == 104);
        assert!(align_of::<sys::StartupInfoW>() == 8);
        assert!(size_of::<sys::StartupInfoExW>() == 112);
        assert!(align_of::<sys::StartupInfoExW>() == 8);
        assert!(std::mem::offset_of!(sys::StartupInfoExW, attribute_list) == 104);
        assert!(size_of::<sys::ProcessInformation>() == 24);
        assert!(align_of::<sys::ProcessInformation>() == 8);
        assert!(size_of::<sys::JobObjectBasicAccountingInformation>() == 48);
        assert!(align_of::<sys::JobObjectBasicAccountingInformation>() == 8);
        assert!(
            std::mem::offset_of!(sys::JobObjectBasicAccountingInformation, active_processes) == 40
        );
        assert!(size_of::<sys::JobObjectBasicLimitInformation>() == 64);
        assert!(align_of::<sys::JobObjectBasicLimitInformation>() == 8);
        assert!(size_of::<sys::IoCounters>() == 48);
        assert!(align_of::<sys::IoCounters>() == 8);
        assert!(size_of::<sys::JobObjectExtendedLimitInformation>() == 144);
        assert!(align_of::<sys::JobObjectExtendedLimitInformation>() == 8);
    };

    pub(super) struct OwnedHandle {
        raw: sys::Handle,
    }

    impl OwnedHandle {
        /// The caller transfers one live, non-null, non-sentinel Win32 handle.
        unsafe fn from_raw(raw: sys::Handle) -> Self {
            Self { raw }
        }

        fn raw(&self) -> sys::Handle {
            self.raw
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: `raw` was transferred into this owner once and remains live
            // until this sole `CloseHandle` call.
            let succeeded = unsafe { sys::CloseHandle(self.raw) };
            if succeeded == sys::FALSE {
                // SAFETY: CloseHandle just returned FALSE; this is the
                // immediate last-error read. Drop cannot surface the error.
                let _error = unsafe { sys::GetLastError() };
            }
        }
    }

    pub(super) struct JobGuard {
        handle: OwnedHandle,
    }

    impl JobGuard {
        fn create_private_kill_on_close() -> Result<Self, String> {
            // SAFETY: deterministic last-error initialization has no pointer or
            // ownership requirements.
            unsafe {
                sys::SetLastError(0);
            }
            // SAFETY: null security attributes make the returned handle
            // non-inheritable; a null name creates a private unnamed job.
            let raw = unsafe { sys::CreateJobObjectW(ptr::null_mut(), ptr::null()) };
            if raw.is_null() {
                // SAFETY: CreateJobObjectW just returned its failure sentinel.
                let error = unsafe { sys::GetLastError() };
                return Err(format!("CreateJobObjectW failed with Win32 error {error}"));
            }
            // SAFETY: the successful call transferred one live job handle.
            let handle = unsafe { OwnedHandle::from_raw(raw) };

            let mut handle_flags = 0u32;
            // SAFETY: the job handle is live and `handle_flags` is writable.
            let got_flags = unsafe { sys::GetHandleInformation(handle.raw(), &mut handle_flags) };
            if got_flags == sys::FALSE {
                // SAFETY: immediate last-error read after the failed query.
                let error = unsafe { sys::GetLastError() };
                return Err(format!(
                    "GetHandleInformation(job) failed with Win32 error {error}"
                ));
            }
            if handle_flags & sys::HANDLE_FLAG_INHERIT != 0 {
                return Err("private job handle was unexpectedly inheritable".to_owned());
            }

            // SAFETY: all-zero is a valid inactive limit structure.
            let mut limits: sys::JobObjectExtendedLimitInformation = unsafe { std::mem::zeroed() };
            limits.basic_limit_information.limit_flags = sys::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: the job is live and `limits` is a correctly sized,
            // initialized JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
            let set = unsafe {
                sys::SetInformationJobObject(
                    handle.raw(),
                    sys::JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                    (&mut limits as *mut sys::JobObjectExtendedLimitInformation).cast(),
                    size_of::<sys::JobObjectExtendedLimitInformation>() as u32,
                )
            };
            if set == sys::FALSE {
                // SAFETY: immediate last-error read after SetInformationJobObject.
                let error = unsafe { sys::GetLastError() };
                return Err(format!(
                    "SetInformationJobObject failed with Win32 error {error}"
                ));
            }

            // SAFETY: all-zero is a valid output buffer for the queried limits.
            let mut observed: sys::JobObjectExtendedLimitInformation =
                unsafe { std::mem::zeroed() };
            let mut returned = 0u32;
            // SAFETY: the live job is queryable and both output pointers cover
            // their declared lengths.
            let queried = unsafe {
                sys::QueryInformationJobObject(
                    handle.raw(),
                    sys::JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                    (&mut observed as *mut sys::JobObjectExtendedLimitInformation).cast(),
                    size_of::<sys::JobObjectExtendedLimitInformation>() as u32,
                    &mut returned,
                )
            };
            if queried == sys::FALSE {
                // SAFETY: immediate last-error read after the failed query.
                let error = unsafe { sys::GetLastError() };
                return Err(format!(
                    "QueryInformationJobObject(limits) failed with Win32 error {error}"
                ));
            }
            if returned != size_of::<sys::JobObjectExtendedLimitInformation>() as u32 {
                return Err(format!(
                    "QueryInformationJobObject(limits) returned {returned} bytes, expected {}",
                    size_of::<sys::JobObjectExtendedLimitInformation>()
                ));
            }
            let flags = observed.basic_limit_information.limit_flags;
            if flags & sys::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 {
                return Err("job query did not confirm KILL_ON_JOB_CLOSE".to_owned());
            }
            if flags
                & (sys::JOB_OBJECT_LIMIT_BREAKAWAY_OK | sys::JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
                != 0
            {
                return Err("job query observed a forbidden breakaway flag".to_owned());
            }

            Ok(Self { handle })
        }

        fn raw(&self) -> sys::Handle {
            self.handle.raw()
        }

        fn active_processes(&self) -> Result<u32, String> {
            // SAFETY: all-zero is a valid output buffer for basic accounting.
            let mut accounting: sys::JobObjectBasicAccountingInformation =
                unsafe { std::mem::zeroed() };
            let mut returned = 0u32;
            // SAFETY: the live job is queryable and the output pointers cover
            // their declared lengths.
            let queried = unsafe {
                sys::QueryInformationJobObject(
                    self.raw(),
                    sys::JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS,
                    (&mut accounting as *mut sys::JobObjectBasicAccountingInformation).cast(),
                    size_of::<sys::JobObjectBasicAccountingInformation>() as u32,
                    &mut returned,
                )
            };
            if queried == sys::FALSE {
                // SAFETY: immediate last-error read after the failed query.
                let error = unsafe { sys::GetLastError() };
                return Err(format!(
                    "QueryInformationJobObject(accounting) failed with Win32 error {error}"
                ));
            }
            if returned != size_of::<sys::JobObjectBasicAccountingInformation>() as u32 {
                return Err(format!(
                    "QueryInformationJobObject(accounting) returned {returned} bytes, expected {}",
                    size_of::<sys::JobObjectBasicAccountingInformation>()
                ));
            }
            Ok(accounting.active_processes)
        }

        fn terminate(&self) -> Result<(), u32> {
            // SAFETY: deterministic last-error initialization has no pointer or
            // ownership requirements.
            unsafe {
                sys::SetLastError(0);
            }
            // SAFETY: this is the live private job and the diagnostic exit code
            // is private to the containment protocol.
            let terminated =
                unsafe { sys::TerminateJobObject(self.raw(), CHILD_FORCED_TERMINATION) };
            if terminated == sys::FALSE {
                // SAFETY: immediate last-error read after failed termination.
                Err(unsafe { sys::GetLastError() })
            } else {
                Ok(())
            }
        }
    }

    struct ProcThreadAttributes {
        attribute_list: *mut core::ffi::c_void,
        _storage: Vec<usize>,
        _job_values: Box<[sys::Handle; 1]>,
        _handle_values: Box<[sys::Handle; 1]>,
    }

    impl ProcThreadAttributes {
        fn new(job: &JobGuard, intended: sys::Handle) -> Result<Self, String> {
            let mut required_size = 0usize;
            // SAFETY: deterministic last-error initialization has no pointer or
            // ownership requirements.
            unsafe {
                sys::SetLastError(0);
            }
            // SAFETY: the documented sizing call takes a null list and writes
            // only the required byte count.
            let sized = unsafe {
                sys::InitializeProcThreadAttributeList(ptr::null_mut(), 2, 0, &mut required_size)
            };
            let sizing_error = if sized == sys::FALSE {
                // SAFETY: immediate last-error read after the sizing call.
                unsafe { sys::GetLastError() }
            } else {
                0
            };
            if sized != sys::FALSE || sizing_error != ERROR_INSUFFICIENT_BUFFER {
                return Err(format!(
                    "attribute-list sizing returned {sized} with Win32 error {sizing_error}, expected FALSE/122"
                ));
            }
            if required_size == 0 {
                return Err("attribute-list sizing returned zero bytes".to_owned());
            }

            let words = required_size
                .checked_add(size_of::<usize>() - 1)
                .ok_or_else(|| "attribute-list size overflow".to_owned())?
                / size_of::<usize>();
            let mut storage = vec![0usize; words];
            let attribute_list = storage.as_mut_ptr().cast();
            let job_values = Box::new([job.raw()]);
            let handle_values = Box::new([intended]);

            // SAFETY: pointer-aligned `storage` covers at least the required
            // byte count and remains owned by the returned guard.
            let initialized = unsafe {
                sys::InitializeProcThreadAttributeList(attribute_list, 2, 0, &mut required_size)
            };
            if initialized == sys::FALSE {
                // SAFETY: immediate last-error read after initialization.
                let error = unsafe { sys::GetLastError() };
                return Err(format!(
                    "InitializeProcThreadAttributeList failed with Win32 error {error}"
                ));
            }

            let attributes = Self {
                attribute_list,
                _storage: storage,
                _job_values: job_values,
                _handle_values: handle_values,
            };
            attributes.update(
                sys::PROC_THREAD_ATTRIBUTE_JOB_LIST,
                attributes._job_values.as_ptr().cast_mut().cast(),
                size_of::<sys::Handle>(),
                "JOB_LIST",
            )?;
            attributes.update(
                sys::PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                attributes._handle_values.as_ptr().cast_mut().cast(),
                size_of::<sys::Handle>(),
                "HANDLE_LIST",
            )?;
            Ok(attributes)
        }

        fn update(
            &self,
            attribute: usize,
            value: *mut core::ffi::c_void,
            value_size: usize,
            name: &str,
        ) -> Result<(), String> {
            // SAFETY: this initialized list is live; `value` points into a
            // stable boxed array retained until this list is deleted.
            let updated = unsafe {
                sys::UpdateProcThreadAttribute(
                    self.attribute_list,
                    0,
                    attribute,
                    value,
                    value_size,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if updated == sys::FALSE {
                // SAFETY: immediate last-error read after the failed update.
                let error = unsafe { sys::GetLastError() };
                Err(format!(
                    "UpdateProcThreadAttribute({name}) failed with Win32 error {error}"
                ))
            } else {
                Ok(())
            }
        }
    }

    impl Drop for ProcThreadAttributes {
        fn drop(&mut self) {
            // SAFETY: initialization succeeded exactly once; deletion runs
            // before the backing storage and both lpValue arrays are freed.
            unsafe {
                sys::DeleteProcThreadAttributeList(self.attribute_list);
            }
        }
    }

    struct RestorationProof {
        _private: (),
    }

    struct InheritRestoreGuard {
        handle: sys::Handle,
        original_flags: u32,
        armed: bool,
    }

    impl InheritRestoreGuard {
        fn enable(handle: sys::Handle) -> Result<Self, u32> {
            let mut original_flags = 0u32;
            // SAFETY: this only initializes the current thread's last-error slot.
            unsafe {
                sys::SetLastError(0);
            }
            // SAFETY: `handle` is borrowed from a live `OwnedHandle`, and
            // `original_flags` is a valid writable `u32`.
            let succeeded = unsafe { sys::GetHandleInformation(handle, &mut original_flags) };
            if succeeded == sys::FALSE {
                // SAFETY: `GetHandleInformation` just returned FALSE; this is
                // the immediate last-error read.
                return Err(unsafe { sys::GetLastError() });
            }

            // Arm restoration before attempting the mutation, so even the
            // failed-enable path restores the saved original bit.
            let guard = Self {
                handle,
                original_flags,
                armed: true,
            };

            // SAFETY: this only initializes the current thread's last-error slot.
            unsafe {
                sys::SetLastError(0);
            }
            // SAFETY: `handle` remains live; the mask changes only its
            // HANDLE_FLAG_INHERIT bit and preserves every other flag.
            let succeeded = unsafe {
                sys::SetHandleInformation(
                    handle,
                    sys::HANDLE_FLAG_INHERIT,
                    sys::HANDLE_FLAG_INHERIT,
                )
            };
            if succeeded == sys::FALSE {
                // SAFETY: `SetHandleInformation` just returned FALSE; this is
                // the immediate last-error read. Dropping the armed guard then
                // attempts restoration before this function returns.
                let error = unsafe { sys::GetLastError() };
                drop(guard);
                return Err(error);
            }

            Ok(guard)
        }

        fn restore_and_verify(&mut self) -> Result<RestorationProof, String> {
            // SAFETY: this only initializes the current thread's last-error slot.
            unsafe {
                sys::SetLastError(0);
            }
            // SAFETY: the parent still owns `handle`; the saved bit is exactly
            // the original HANDLE_FLAG_INHERIT state.
            let succeeded = unsafe {
                sys::SetHandleInformation(
                    self.handle,
                    sys::HANDLE_FLAG_INHERIT,
                    self.original_flags & sys::HANDLE_FLAG_INHERIT,
                )
            };
            if succeeded == sys::FALSE {
                // SAFETY: `SetHandleInformation` just returned FALSE; this is
                // the immediate last-error read.
                let error = unsafe { sys::GetLastError() };
                return Err(format!(
                    "restoring the inherit bit failed with Win32 error {error}"
                ));
            }

            let mut observed_flags = 0u32;
            // SAFETY: `handle` remains live and `observed_flags` is writable.
            let queried = unsafe { sys::GetHandleInformation(self.handle, &mut observed_flags) };
            if queried == sys::FALSE {
                // SAFETY: immediate last-error read after the failed query.
                let error = unsafe { sys::GetLastError() };
                return Err(format!(
                    "verifying restored handle flags failed with Win32 error {error}"
                ));
            }
            if observed_flags != self.original_flags {
                return Err(format!(
                    "restored handle flags were 0x{observed_flags:08x}, expected exact original 0x{:08x}",
                    self.original_flags
                ));
            }
            self.armed = false;
            Ok(RestorationProof { _private: () })
        }
    }

    impl Drop for InheritRestoreGuard {
        fn drop(&mut self) {
            if self.armed {
                // SAFETY: this guard borrows a still-live parent handle. This
                // final best-effort call retries restoration on every unwinding
                // or early-return path and changes only the inherit bit.
                let succeeded = unsafe {
                    sys::SetHandleInformation(
                        self.handle,
                        sys::HANDLE_FLAG_INHERIT,
                        self.original_flags & sys::HANDLE_FLAG_INHERIT,
                    )
                };
                if succeeded == sys::FALSE {
                    // SAFETY: SetHandleInformation just returned FALSE; this
                    // is the immediate last-error read. Drop cannot report it.
                    let _error = unsafe { sys::GetLastError() };
                }
            }
        }
    }

    fn wide_nul(value: &std::ffi::OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn open_device(path: &str) -> Result<OwnedHandle, u32> {
        let path = wide_nul(std::ffi::OsStr::new(path));
        // SAFETY: setting this thread's last-error slot to a deterministic value
        // has no pointer or ownership requirements.
        unsafe {
            sys::SetLastError(0);
        }
        // SAFETY: `path` is a live NUL-terminated UTF-16 string; optional
        // pointers/handle are null; access/share/disposition flags are valid.
        let raw = unsafe {
            sys::CreateFileW(
                path.as_ptr(),
                sys::GENERIC_READ | sys::GENERIC_WRITE,
                sys::FILE_SHARE_READ | sys::FILE_SHARE_WRITE | sys::FILE_SHARE_DELETE,
                ptr::null_mut(),
                sys::OPEN_EXISTING,
                sys::FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if raw == sys::INVALID_HANDLE_VALUE {
            // SAFETY: `CreateFileW` just returned its documented failure
            // sentinel; this is the immediate last-error read.
            let error = unsafe { sys::GetLastError() };
            return Err(error);
        }
        if raw.is_null() {
            // `CreateFileW` documents INVALID_HANDLE_VALUE, not null, for
            // failure. Refuse to create an invalid RAII owner defensively.
            return Err(ERROR_INVALID_HANDLE);
        }

        // SAFETY: successful `CreateFileW` returned one live device handle and
        // ownership is transferred to this RAII value exactly once.
        Ok(unsafe { OwnedHandle::from_raw(raw) })
    }

    fn observe_open(path: &str) -> NativeObservation {
        match open_device(path) {
            Ok(handle) => {
                drop(handle);
                NativeObservation::Success
            }
            Err(error) => NativeObservation::Error(error),
        }
    }

    fn device_io_control(device: &OwnedHandle, ioctl: u32, input: &[u8]) -> NativeObservation {
        let input_len =
            u32::try_from(input.len()).expect("fixed control input length must fit in u32");
        let input_pointer = if input.is_empty() {
            ptr::null_mut()
        } else {
            input.as_ptr().cast_mut().cast()
        };
        let mut bytes_returned = 0u32;

        // SAFETY: setting this thread's last-error slot makes unexpected native
        // behavior deterministic without affecting handle ownership.
        unsafe {
            sys::SetLastError(0);
        }
        // SAFETY: `device` owns a live handle; `input_pointer` covers exactly
        // `input_len` initialized bytes (or is null for zero); output and
        // OVERLAPPED are intentionally null; `bytes_returned` is live.
        let succeeded = unsafe {
            sys::DeviceIoControl(
                device.raw(),
                ioctl,
                input_pointer,
                input_len,
                ptr::null_mut(),
                0,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };
        if succeeded == sys::FALSE {
            // SAFETY: `DeviceIoControl` just returned FALSE; this is the
            // immediate last-error read before formatting/allocation/other FFI.
            NativeObservation::Error(unsafe { sys::GetLastError() })
        } else {
            NativeObservation::Success
        }
    }

    fn donation(version: u16) -> DonateSecurityContextV1 {
        DonateSecurityContextV1 {
            header: ControlHeader {
                struct_size: size_of::<DonateSecurityContextV1>() as u32,
                struct_version: version,
                required_flags: 0,
            },
            security_context_id: 0x1122_3344_5566_7788,
            daemon_handle: 0x99aa_bbcc_ddee_ff00,
            flags: 0,
            reserved: 0,
        }
    }

    fn donation_bytes(value: &DonateSecurityContextV1) -> &[u8] {
        // SAFETY: `DonateSecurityContextV1` is the ABI crate's initialized,
        // fixed-size POD wire type; its asserted 32-byte layout has no
        // uninitialized padding, and the returned slice borrows `value`.
        unsafe {
            slice::from_raw_parts(
                (value as *const DonateSecurityContextV1).cast::<u8>(),
                size_of::<DonateSecurityContextV1>(),
            )
        }
    }

    fn child_command_line(executable: &std::ffi::OsStr, handle: sys::Handle) -> Vec<u16> {
        let mut command_line = Vec::new();
        command_line.push(u16::from(b'"'));
        command_line.extend(executable.encode_wide());
        command_line.extend("\" --child-handle ".encode_utf16());
        let width = size_of::<usize>() * 2;
        command_line.extend(format!("0x{value:0width$x}", value = handle as usize).encode_utf16());
        command_line.push(0);
        command_line
    }

    struct ChildRun {
        result: Result<u32, String>,
        job_lease: Option<JobGuard>,
        #[cfg(test)]
        containment: Option<super::ContainmentObservation>,
    }

    fn child_run_without_job(reason: String) -> ChildRun {
        ChildRun {
            result: Err(reason),
            job_lease: None,
            #[cfg(test)]
            containment: None,
        }
    }

    fn confirm_job_empty(job: &JobGuard) -> (bool, String) {
        let deadline = Instant::now()
            + Duration::from_millis(u64::from(CHILD_TERMINATION_CONFIRM_MILLISECONDS));

        loop {
            let last_observation = match job.active_processes() {
                Ok(0) => {
                    return (
                        true,
                        "job accounting confirmed ActiveProcesses == 0".to_owned(),
                    );
                }
                Ok(active) => {
                    format!("job accounting still reported {active} active process(es)")
                }
                Err(error) => error,
            };

            if Instant::now() >= deadline {
                return (
                    false,
                    format!(
                        "job did not confirm empty within {CHILD_TERMINATION_CONFIRM_MILLISECONDS} ms; {last_observation}"
                    ),
                );
            }
            std::thread::sleep(Duration::from_millis(CHILD_TERMINATION_POLL_MILLISECONDS));
        }
    }

    fn fail_and_contain(
        job: JobGuard,
        process: Option<OwnedHandle>,
        thread: Option<OwnedHandle>,
        failure: String,
    ) -> ChildRun {
        let termination = job.terminate();
        // Windows can retain ActiveProcesses while either initial
        // PROCESS_INFORMATION handle is open. Close both before polling.
        drop(thread);
        drop(process);
        let (zero_confirmed, confirmation) = confirm_job_empty(&job);
        let terminate_succeeded = termination.is_ok();
        let resolution = super::resolve_failed_lifecycle(super::ContainmentObservation {
            terminate_succeeded,
            zero_confirmed,
        });
        debug_assert!(!resolution.probe_passes);

        let termination_text = match termination {
            Ok(()) => "TerminateJobObject succeeded".to_owned(),
            Err(error) => format!("TerminateJobObject failed with Win32 error {error}"),
        };
        let job_lease = if resolution.release_job {
            None
        } else {
            Some(job)
        };
        ChildRun {
            result: Err(format!(
                "{failure}; job containment: {termination_text}; {confirmation}"
            )),
            job_lease,
            #[cfg(test)]
            containment: Some(super::ContainmentObservation {
                terminate_succeeded,
                zero_confirmed,
            }),
        }
    }

    fn resume_suspended_thread(
        thread: &OwnedHandle,
        _restoration: RestorationProof,
    ) -> Result<(), String> {
        // SAFETY: deterministic last-error initialization has no pointer or
        // ownership requirements.
        unsafe {
            sys::SetLastError(0);
        }
        // SAFETY: this is the live initial thread handle returned for a process
        // created with CREATE_SUSPENDED. This is the sole ResumeThread call.
        let previous_count = unsafe { sys::ResumeThread(thread.raw()) };
        let resume_error = if previous_count == u32::MAX {
            // SAFETY: immediate last-error read after ResumeThread failure.
            Some(unsafe { sys::GetLastError() })
        } else {
            None
        };

        match super::lifecycle_decision(super::LifecycleStep::ResumeResult(previous_count)) {
            super::LifecycleDecision::Continue => Ok(()),
            super::LifecycleDecision::ContainAndFail(super::LifecycleFailure::ResumeFailed) => {
                Err(format!(
                    "ResumeThread failed with Win32 error {}",
                    resume_error.unwrap_or(0)
                ))
            }
            super::LifecycleDecision::ContainAndFail(
                super::LifecycleFailure::WrongResumeCount(count),
            ) => Err(format!(
                "ResumeThread reported prior suspend count {count}, expected exactly 1"
            )),
            _ => unreachable!("resume lifecycle step has one decision family"),
        }
    }

    fn create_and_wait_for_command(
        device: &OwnedHandle,
        application_name: &[u16],
        command_line: &mut [u16],
        primary_timeout_milliseconds: u32,
    ) -> ChildRun {
        let job = match JobGuard::create_private_kill_on_close() {
            Ok(job) => job,
            Err(error) => return child_run_without_job(error),
        };
        let attributes = match ProcThreadAttributes::new(&job, device.raw()) {
            Ok(attributes) => attributes,
            Err(error) => return fail_and_contain(job, None, None, error),
        };

        // SAFETY: all-zero bit patterns are valid initial values for these
        // Win32 integer/pointer-only structures.
        let mut startup_info: sys::StartupInfoExW = unsafe { std::mem::zeroed() };
        startup_info.startup_info.cb = size_of::<sys::StartupInfoExW>() as u32;
        startup_info.attribute_list = attributes.attribute_list;
        // SAFETY: all-zero is the required initial output state; successful
        // CreateProcessW replaces both owned handle fields.
        let mut process_information: sys::ProcessInformation = unsafe { std::mem::zeroed() };

        // Only the intended handle's inherit bit is temporarily changed.
        let mut restore_guard = match InheritRestoreGuard::enable(device.raw()) {
            Ok(guard) => guard,
            Err(error) => {
                return fail_and_contain(
                    job,
                    None,
                    None,
                    format!("Get/SetHandleInformation failed with Win32 error {error}"),
                );
            }
        };

        // SAFETY: deterministic last-error initialization has no pointer or
        // ownership requirements.
        unsafe {
            sys::SetLastError(0);
        }
        // SAFETY: application_name is an exact NUL-terminated executable path;
        // command_line is writable and NUL-terminated; the STARTUPINFOEXW and
        // output layouts are asserted; the attribute list contains exactly the
        // private JOB_LIST and intended HANDLE_LIST entries.
        let created = unsafe {
            sys::CreateProcessW(
                application_name.as_ptr(),
                command_line.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                sys::TRUE,
                sys::EXTENDED_STARTUPINFO_PRESENT | sys::CREATE_SUSPENDED,
                ptr::null_mut(),
                ptr::null(),
                (&mut startup_info as *mut sys::StartupInfoExW).cast(),
                &mut process_information,
            )
        };
        let create_error = if created == sys::FALSE {
            // SAFETY: immediate last-error read after failed CreateProcessW.
            Some(unsafe { sys::GetLastError() })
        } else {
            None
        };
        // Microsoft requires the lpValue arrays to live until list deletion.
        // `attributes` owns both arrays and deletes the list before freeing them.
        drop(attributes);

        let (process, thread) = if created == sys::FALSE {
            (None, None)
        } else {
            // SAFETY: successful CreateProcessW transferred these two distinct
            // live handles exactly once.
            (
                Some(unsafe { OwnedHandle::from_raw(process_information.h_process) }),
                Some(unsafe { OwnedHandle::from_raw(process_information.h_thread) }),
            )
        };

        let restoration = restore_guard.restore_and_verify();
        // On a failed explicit restore/verification, Drop retries restoration;
        // no proof is produced and the suspended child is never resumed.
        drop(restore_guard);

        if let Some(error) = create_error {
            let failure = match restoration {
                Ok(_) => format!("CreateProcessW failed with Win32 error {error}"),
                Err(restore_error) => {
                    format!("CreateProcessW failed with Win32 error {error}; {restore_error}")
                }
            };
            return fail_and_contain(job, process, thread, failure);
        }

        let restoration = match restoration {
            Ok(proof) => proof,
            Err(error) => {
                let decision =
                    super::lifecycle_decision(super::LifecycleStep::RestoreConfirmed(false));
                debug_assert_eq!(
                    decision,
                    super::LifecycleDecision::ContainAndFail(
                        super::LifecycleFailure::RestoreNotConfirmed
                    )
                );
                return fail_and_contain(job, process, thread, error);
            }
        };
        debug_assert_eq!(
            super::lifecycle_decision(super::LifecycleStep::RestoreConfirmed(true)),
            super::LifecycleDecision::Continue
        );

        let process = process.expect("successful CreateProcessW supplied a process handle");
        let thread = thread.expect("successful CreateProcessW supplied a thread handle");
        if let Err(error) = resume_suspended_thread(&thread, restoration) {
            return fail_and_contain(job, Some(process), Some(thread), error);
        }
        // The successful resume returned exactly one; close hThread
        // immediately, before the primary wait.
        drop(thread);

        // SAFETY: `process` is live and the finite timeout is in milliseconds.
        let wait_result =
            unsafe { sys::WaitForSingleObject(process.raw(), primary_timeout_milliseconds) };
        let wait_error = if wait_result == sys::WAIT_FAILED {
            // SAFETY: immediate last-error read after failed wait.
            Some(unsafe { sys::GetLastError() })
        } else {
            None
        };
        match super::lifecycle_decision(super::LifecycleStep::WaitResult(wait_result)) {
            super::LifecycleDecision::Continue => {}
            super::LifecycleDecision::ContainAndFail(super::LifecycleFailure::WaitTimeout) => {
                return fail_and_contain(
                    job,
                    Some(process),
                    None,
                    format!("child did not exit within {primary_timeout_milliseconds} ms"),
                );
            }
            super::LifecycleDecision::ContainAndFail(super::LifecycleFailure::WaitFailed) => {
                return fail_and_contain(
                    job,
                    Some(process),
                    None,
                    format!(
                        "WaitForSingleObject failed with Win32 error {}",
                        wait_error.unwrap_or(0)
                    ),
                );
            }
            super::LifecycleDecision::ContainAndFail(super::LifecycleFailure::UnexpectedWait(
                other,
            )) => {
                return fail_and_contain(
                    job,
                    Some(process),
                    None,
                    format!("WaitForSingleObject returned unexpected status {other}"),
                );
            }
            _ => unreachable!("wait lifecycle step has one decision family"),
        }

        let mut exit_code = 0u32;
        // SAFETY: the root process is signaled and `exit_code` is writable.
        let exit_queried = unsafe { sys::GetExitCodeProcess(process.raw(), &mut exit_code) };
        let exit_error = if exit_queried == sys::FALSE {
            // SAFETY: immediate last-error read after failed exit query.
            Some(unsafe { sys::GetLastError() })
        } else {
            None
        };
        let exit_observation = if exit_queried == sys::FALSE {
            Err(())
        } else {
            Ok(exit_code)
        };
        match super::lifecycle_decision(super::LifecycleStep::ExitResult(exit_observation)) {
            super::LifecycleDecision::Continue => {}
            super::LifecycleDecision::ContainAndFail(super::LifecycleFailure::ExitQueryFailed) => {
                return fail_and_contain(
                    job,
                    Some(process),
                    None,
                    format!(
                        "GetExitCodeProcess failed with Win32 error {}",
                        exit_error.unwrap_or(0)
                    ),
                );
            }
            super::LifecycleDecision::ContainAndFail(super::LifecycleFailure::NonzeroExit(
                code,
            )) => {
                return fail_and_contain(
                    job,
                    Some(process),
                    None,
                    format!("child returned private diagnostic exit code {code}"),
                );
            }
            _ => unreachable!("exit lifecycle step has one decision family"),
        }

        // ActiveProcesses cannot reliably reach zero while either initial
        // process/thread handle remains open.
        drop(process);
        let active_observation = job.active_processes();
        let active_step = match &active_observation {
            Ok(active) => super::LifecycleStep::ActiveResult(Ok(*active)),
            Err(_) => super::LifecycleStep::ActiveResult(Err(())),
        };
        match super::lifecycle_decision(active_step) {
            super::LifecycleDecision::Pass => ChildRun {
                result: Ok(0),
                job_lease: None,
                #[cfg(test)]
                containment: None,
            },
            super::LifecycleDecision::ContainAndFail(
                super::LifecycleFailure::ActiveQueryFailed,
            ) => fail_and_contain(
                job,
                None,
                None,
                active_observation
                    .err()
                    .unwrap_or_else(|| "job accounting query failed".to_owned()),
            ),
            super::LifecycleDecision::ContainAndFail(super::LifecycleFailure::ActiveProcesses(
                active,
            )) => fail_and_contain(
                job,
                None,
                None,
                format!("root exited zero but job accounting reported {active} active process(es)"),
            ),
            _ => unreachable!("active lifecycle step has one decision family"),
        }
    }

    fn create_and_wait_for_child(device: &OwnedHandle) -> ChildRun {
        let executable = match std::env::current_exe() {
            Ok(executable) => executable,
            Err(error) => {
                return child_run_without_job(format!(
                    "current_exe failed before inheritance: {error}"
                ));
            }
        };
        let application_name = wide_nul(executable.as_os_str());
        let mut command_line = child_command_line(executable.as_os_str(), device.raw());
        create_and_wait_for_command(
            device,
            &application_name,
            &mut command_line,
            CHILD_TIMEOUT_MILLISECONDS,
        )
    }

    struct InheritedProbeResult {
        probe: ProbeResult,
        job_lease: Option<JobGuard>,
    }

    fn inherited_handle_probe(device: &OwnedHandle) -> InheritedProbeResult {
        let child = create_and_wait_for_child(device);
        let probe = match child.result {
            Ok(0) => expected_error_probe(
                NORMAL_PROBE_NAMES[7],
                ERROR_ACCESS_DENIED,
                NativeObservation::Error(ERROR_ACCESS_DENIED),
            ),
            Ok(exit_code) => ProbeResult::failed(
                NORMAL_PROBE_NAMES[7],
                Some(ERROR_ACCESS_DENIED),
                None,
                format!("child returned private diagnostic exit code {exit_code}"),
            ),
            Err(reason) => ProbeResult::failed(
                NORMAL_PROBE_NAMES[7],
                Some(ERROR_ACCESS_DENIED),
                None,
                reason,
            ),
        };
        InheritedProbeResult {
            probe,
            job_lease: child.job_lease,
        }
    }

    fn blocked_after_root_failure(error: u32) -> Report {
        let mut probes = Vec::with_capacity(NORMAL_PROBE_NAMES.len());
        probes.push(ProbeResult::failed(
            NORMAL_PROBE_NAMES[0],
            None,
            Some(error),
            format!("root CreateFileW failed with Win32 error {error}"),
        ));
        for index in 1..NORMAL_PROBE_NAMES.len() {
            probes.push(ProbeResult::not_run_expected(
                NORMAL_PROBE_NAMES[index],
                NORMAL_EXPECTED_ERRORS[index],
                "root device handle was unavailable",
            ));
        }
        summarize(&NORMAL_PROBE_NAMES, probes, Vec::new())
    }

    pub(super) fn normal_report() -> super::PreparedReport<JobGuard> {
        let root = match open_device(DEVICE_PATH) {
            Ok(root) => root,
            Err(error) => {
                return super::PreparedReport::new(blocked_after_root_failure(error), None);
            }
        };

        let mut probes = Vec::with_capacity(NORMAL_PROBE_NAMES.len());
        probes.push(ProbeResult::passed(NORMAL_PROBE_NAMES[0]));
        probes.push(expected_error_probe(
            NORMAL_PROBE_NAMES[1],
            ERROR_FILE_NOT_FOUND,
            observe_open(TRAILING_DEVICE_PATH),
        ));
        probes.push(expected_error_probe(
            NORMAL_PROBE_NAMES[2],
            ERROR_INVALID_FUNCTION,
            device_io_control(&root, UNKNOWN_BUFFERED_READ_WRITE_IOCTL, &[]),
        ));
        probes.push(expected_error_probe(
            NORMAL_PROBE_NAMES[3],
            ERROR_NOT_SUPPORTED,
            device_io_control(&root, IOCTL_FSRING_SETUP, &[]),
        ));

        let valid_donation = donation(CONTROL_VERSION_V1);
        let valid_bytes = donation_bytes(&valid_donation);
        probes.push(expected_error_probe(
            NORMAL_PROBE_NAMES[4],
            ERROR_INVALID_PARAMETER,
            device_io_control(
                &root,
                IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
                &valid_bytes[..valid_bytes.len() - 1],
            ),
        ));

        let wrong_version_donation = donation(CONTROL_VERSION_V1 + 1);
        probes.push(expected_error_probe(
            NORMAL_PROBE_NAMES[5],
            ERROR_REVISION_MISMATCH,
            device_io_control(
                &root,
                IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
                donation_bytes(&wrong_version_donation),
            ),
        ));
        probes.push(expected_error_probe(
            NORMAL_PROBE_NAMES[6],
            ERROR_NOT_SUPPORTED,
            device_io_control(&root, IOCTL_FSRING_DONATE_SECURITY_CONTEXT, valid_bytes),
        ));

        let inherited_probe = inherited_handle_probe(&root);
        probes.push(inherited_probe.probe);
        probes.push(expected_error_probe(
            NORMAL_PROBE_NAMES[8],
            ERROR_NOT_SUPPORTED,
            device_io_control(&root, IOCTL_FSRING_DONATE_SECURITY_CONTEXT, valid_bytes),
        ));

        drop(root);
        super::PreparedReport::new(
            summarize(&NORMAL_PROBE_NAMES, probes, Vec::new()),
            inherited_probe.job_lease,
        )
    }

    pub(super) fn absent_report() -> super::PreparedReport<JobGuard> {
        let probe = expected_error_probe(
            ABSENT_PROBE_NAMES[0],
            ERROR_FILE_NOT_FOUND,
            observe_open(DEVICE_PATH),
        );
        super::PreparedReport::new(
            summarize(&ABSENT_PROBE_NAMES, vec![probe], Vec::new()),
            None,
        )
    }

    #[cfg(test)]
    fn test_helper_command_line(executable: &std::ffi::OsStr, test_name: &str) -> Vec<u16> {
        let mut command_line = Vec::new();
        command_line.push(u16::from(b'"'));
        command_line.extend(executable.encode_wide());
        command_line.extend("\" --exact ".encode_utf16());
        command_line.extend(test_name.encode_utf16());
        command_line.extend(" --ignored --nocapture".encode_utf16());
        command_line.push(0);
        command_line
    }

    #[cfg(test)]
    pub(super) struct TestChildResult {
        pub(super) result: Result<u32, String>,
        pub(super) containment_zero_confirmed: bool,
        pub(super) retained_job_lease: bool,
    }

    #[cfg(test)]
    pub(super) fn run_contained_test_helper(
        intended: &OwnedHandle,
        test_name: &str,
        primary_timeout_milliseconds: u32,
    ) -> TestChildResult {
        let executable = match std::env::current_exe() {
            Ok(executable) => executable,
            Err(error) => {
                return TestChildResult {
                    result: Err(format!("test current_exe failed: {error}")),
                    containment_zero_confirmed: false,
                    retained_job_lease: false,
                };
            }
        };
        let application_name = wide_nul(executable.as_os_str());
        let mut command_line = test_helper_command_line(executable.as_os_str(), test_name);
        let child = create_and_wait_for_command(
            intended,
            &application_name,
            &mut command_line,
            primary_timeout_milliseconds,
        );
        TestChildResult {
            containment_zero_confirmed: child
                .containment
                .is_some_and(|observation| observation.zero_confirmed),
            retained_job_lease: child.job_lease.is_some(),
            result: child.result,
        }
    }

    #[cfg(test)]
    pub(super) fn test_open_nul() -> Result<OwnedHandle, u32> {
        open_device("NUL")
    }

    #[cfg(test)]
    pub(super) fn test_handle_flags(handle: &OwnedHandle) -> Result<u32, u32> {
        let mut flags = 0u32;
        // SAFETY: the test owns `handle` and `flags` is writable.
        let succeeded = unsafe { sys::GetHandleInformation(handle.raw(), &mut flags) };
        if succeeded == sys::FALSE {
            // SAFETY: immediate last-error read after the failed query.
            Err(unsafe { sys::GetLastError() })
        } else {
            Ok(flags)
        }
    }

    #[cfg(test)]
    pub(super) fn test_set_inherit(handle: &OwnedHandle, inheritable: bool) -> Result<(), u32> {
        let value = if inheritable {
            sys::HANDLE_FLAG_INHERIT
        } else {
            0
        };
        // SAFETY: the test owns `handle`; only HANDLE_FLAG_INHERIT changes.
        let succeeded =
            unsafe { sys::SetHandleInformation(handle.raw(), sys::HANDLE_FLAG_INHERIT, value) };
        if succeeded == sys::FALSE {
            // SAFETY: immediate last-error read after the failed mutation.
            Err(unsafe { sys::GetLastError() })
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(super) fn test_handle_value(handle: &OwnedHandle) -> usize {
        handle.raw() as usize
    }

    #[cfg(test)]
    pub(super) fn test_handle_is_valid(value: usize) -> bool {
        let mut flags = 0u32;
        // SAFETY: the opaque candidate is intentionally validated by this
        // query and never dereferenced or closed.
        unsafe { sys::GetHandleInformation(value as sys::Handle, &mut flags) != sys::FALSE }
    }

    pub fn child_exit(handle_value: usize) -> u8 {
        let raw = handle_value as sys::Handle;
        let mut flags = 0u32;
        // SAFETY: this only initializes the current thread's last-error slot.
        unsafe {
            sys::SetLastError(0);
        }
        // SAFETY: `raw` is an opaque parsed candidate; the call validates that
        // it names a handle in this child before ownership or use.
        let succeeded = unsafe { sys::GetHandleInformation(raw, &mut flags) };
        if succeeded == sys::FALSE {
            // SAFETY: GetHandleInformation just returned FALSE; consume the
            // error immediately even though the private code does not expose it.
            let _error = unsafe { sys::GetLastError() };
            return CHILD_PARSE_OR_HANDLE_FAILURE;
        }

        // SAFETY: successful GetHandleInformation proved this is a live handle;
        // child mode receives ownership of the inherited reference and closes
        // it exactly once before returning.
        let inherited = unsafe { OwnedHandle::from_raw(raw) };
        let valid_donation = donation(CONTROL_VERSION_V1);
        let observation = device_io_control(
            &inherited,
            IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
            donation_bytes(&valid_donation),
        );
        drop(inherited);

        match observation {
            NativeObservation::Error(ERROR_ACCESS_DENIED) => 0,
            NativeObservation::Success => CHILD_UNEXPECTED_IOCTL_SUCCESS,
            NativeObservation::Error(_) => CHILD_WRONG_WIN32_ERROR,
        }
    }
}

#[cfg(not(windows))]
fn unsupported_report(required_names: &[&'static str], expected: &[Option<u32>]) -> Report {
    let probes = required_names
        .iter()
        .zip(expected)
        .map(|(name, expected)| {
            ProbeResult::not_run_expected(name, *expected, "Windows is required")
        })
        .collect();
    summarize(required_names, probes, Vec::new())
}

fn emit_report<L>(prepared: PreparedReport<L>) -> std::process::ExitCode {
    let report_exit = prepared.report.exit_code as u8;
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    if write_prepared_report(&mut locked, prepared).is_err() {
        return std::process::ExitCode::from(1);
    }
    std::process::ExitCode::from(report_exit)
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = match parse_args(&args) {
        Ok(mode) => mode,
        Err(reason) if args.first().is_some_and(|arg| arg == "--child-handle") => {
            let _ = reason;
            return std::process::ExitCode::from(20);
        }
        Err(reason) => {
            let probe = ProbeResult::failed("invocation", None, None, reason);
            return emit_report(PreparedReport::<()>::new(
                summarize(&["invocation"], vec![probe], Vec::new()),
                None,
            ));
        }
    };

    match mode {
        RunMode::Normal => {
            #[cfg(windows)]
            {
                emit_report(windows::normal_report())
            }
            #[cfg(not(windows))]
            {
                emit_report(PreparedReport::<()>::new(
                    unsupported_report(&NORMAL_PROBE_NAMES, &NORMAL_EXPECTED_ERRORS),
                    None,
                ))
            }
        }
        RunMode::C4LiveWorker(nonce) => run_c4_live_worker(&nonce),
        RunMode::C4PostUnload(args) => run_c4_post_unload(&args),
        RunMode::ExpectAbsent => {
            #[cfg(windows)]
            {
                emit_report(windows::absent_report())
            }
            #[cfg(not(windows))]
            {
                emit_report(PreparedReport::<()>::new(
                    unsupported_report(&ABSENT_PROBE_NAMES, &[Some(ERROR_FILE_NOT_FOUND)]),
                    None,
                ))
            }
        }
        RunMode::ChildHandle(handle) => {
            #[cfg(windows)]
            {
                std::process::ExitCode::from(windows::child_exit(handle))
            }
            #[cfg(not(windows))]
            {
                let _ = handle;
                std::process::ExitCode::from(20)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::{
        ffi::{OsStr, OsString},
        path::{Path, PathBuf},
        process::Command,
        sync::{
            atomic::{AtomicU64, Ordering},
            Mutex,
        },
        thread,
        time::{Duration, Instant},
    };

    #[cfg(windows)]
    static R3_INTEGRATION_LOCK: Mutex<()> = Mutex::new(());
    #[cfg(windows)]
    static R3_NONCE: AtomicU64 = AtomicU64::new(0);

    #[cfg(windows)]
    struct R3EnvironmentGuard {
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    #[cfg(windows)]
    impl R3EnvironmentGuard {
        fn set(values: &[(&'static str, &OsStr)]) -> Self {
            let mut saved = Vec::with_capacity(values.len());
            for (name, value) in values {
                saved.push((*name, std::env::var_os(name)));
                std::env::set_var(name, value);
            }
            Self { saved }
        }
    }

    #[cfg(windows)]
    impl Drop for R3EnvironmentGuard {
        fn drop(&mut self) {
            for (name, value) in self.saved.iter().rev() {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn one_failed_probe_makes_the_report_fail() {
        let probe = ProbeResult {
            name: "only",
            outcome: Outcome::Fail,
            expected: Some(50),
            actual: Some(87),
            reason: Some("wrong Win32 error".to_owned()),
        };

        let report = summarize(&["only"], vec![probe], Vec::new());

        assert_eq!(report.overall, Outcome::Fail);
        assert_eq!(report.exit_code, 1);
    }

    #[test]
    fn skipped_prerequisite_is_distinct_from_pass() {
        let report = summarize(
            &["only"],
            vec![ProbeResult::not_run_expected(
                "only",
                None,
                "prerequisite failed",
            )],
            Vec::new(),
        );

        assert_eq!(report.overall, Outcome::NotRun);
        assert_eq!(report.exit_code, 2);
    }

    #[test]
    fn incomplete_or_duplicate_rosters_cannot_pass() {
        let empty = summarize(&NORMAL_PROBE_NAMES, Vec::new(), Vec::new());
        assert_eq!(empty.overall, Outcome::Fail);

        let missing = summarize(
            &NORMAL_PROBE_NAMES,
            NORMAL_PROBE_NAMES[..8]
                .iter()
                .map(|name| ProbeResult::passed(name))
                .collect(),
            Vec::new(),
        );
        assert_eq!(missing.overall, Outcome::Fail);

        let mut duplicate: Vec<_> = NORMAL_PROBE_NAMES
            .iter()
            .map(|name| ProbeResult::passed(name))
            .collect();
        duplicate.push(ProbeResult::passed(NORMAL_PROBE_NAMES[0]));
        let duplicate = summarize(&NORMAL_PROBE_NAMES, duplicate, Vec::new());
        assert_eq!(duplicate.overall, Outcome::Fail);
    }

    #[test]
    fn complete_passing_roster_passes() {
        let report = summarize(
            &NORMAL_PROBE_NAMES,
            NORMAL_PROBE_NAMES
                .iter()
                .map(|name| ProbeResult::passed(name))
                .collect(),
            Vec::new(),
        );

        assert_eq!(report.overall, Outcome::Pass);
        assert_eq!(report.exit_code, 0);
    }

    #[test]
    fn child_mode_requires_exactly_one_fixed_width_valid_handle() {
        let width = std::mem::size_of::<usize>() * 2;
        let valid = format!("0x{value:0width$x}", value = 1usize);
        let valid_without_prefix = format!("{value:0width$x}", value = 2usize);
        assert_eq!(
            parse_args(&strings(&["--child-handle", &valid])),
            Ok(RunMode::ChildHandle(1))
        );
        assert_eq!(
            parse_args(&strings(&["--child-handle", &valid_without_prefix])),
            Ok(RunMode::ChildHandle(2))
        );

        let maximum = format!("0x{value:0width$x}", value = usize::MAX);
        let zero = format!("0x{value:0width$x}", value = 0usize);
        for invalid in [
            strings(&["--child-handle"]),
            strings(&["--child-handle", &valid, "extra"]),
            strings(&["--child-handle", "1"]),
            strings(&["--child-handle", &zero]),
            strings(&["--child-handle", &maximum]),
            strings(&["--child-handle", "0xgggggggggggggggg"]),
        ] {
            assert!(parse_args(&invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn wrong_expected_win32_error_is_detected() {
        let probe = expected_error_probe("probe", 50, NativeObservation::Error(87));

        assert_eq!(probe.outcome, Outcome::Fail);
        assert_eq!(probe.expected, Some(50));
        assert_eq!(probe.actual, Some(87));
        let report = summarize(&["probe"], vec![probe], Vec::new());
        assert_eq!(report.overall, Outcome::Fail);
        assert_eq!(report.exit_code, 1);
    }

    #[test]
    fn unexpected_native_success_is_detected() {
        let probe = expected_error_probe("probe", 50, NativeObservation::Success);

        assert_eq!(probe.outcome, Outcome::Fail);
        assert_eq!(probe.expected, Some(50));
        assert_eq!(probe.actual, None);
    }

    #[test]
    fn only_a_signaled_child_wait_avoids_containment() {
        assert!(!child_wait_needs_containment(0));
        assert!(child_wait_needs_containment(258));
        assert!(child_wait_needs_containment(0xffff_ffff));
        assert!(child_wait_needs_containment(7));
    }

    #[test]
    fn lifecycle_gate_exhausts_restore_resume_wait_exit_and_active_failures() {
        let cases = [
            (
                LifecycleStep::RestoreConfirmed(true),
                LifecycleDecision::Continue,
            ),
            (
                LifecycleStep::RestoreConfirmed(false),
                LifecycleDecision::ContainAndFail(LifecycleFailure::RestoreNotConfirmed),
            ),
            (LifecycleStep::ResumeResult(1), LifecycleDecision::Continue),
            (
                LifecycleStep::ResumeResult(u32::MAX),
                LifecycleDecision::ContainAndFail(LifecycleFailure::ResumeFailed),
            ),
            (
                LifecycleStep::ResumeResult(0),
                LifecycleDecision::ContainAndFail(LifecycleFailure::WrongResumeCount(0)),
            ),
            (
                LifecycleStep::ResumeResult(2),
                LifecycleDecision::ContainAndFail(LifecycleFailure::WrongResumeCount(2)),
            ),
            (LifecycleStep::WaitResult(0), LifecycleDecision::Continue),
            (
                LifecycleStep::WaitResult(258),
                LifecycleDecision::ContainAndFail(LifecycleFailure::WaitTimeout),
            ),
            (
                LifecycleStep::WaitResult(u32::MAX),
                LifecycleDecision::ContainAndFail(LifecycleFailure::WaitFailed),
            ),
            (
                LifecycleStep::WaitResult(7),
                LifecycleDecision::ContainAndFail(LifecycleFailure::UnexpectedWait(7)),
            ),
            (
                LifecycleStep::ExitResult(Ok(0)),
                LifecycleDecision::Continue,
            ),
            (
                LifecycleStep::ExitResult(Err(())),
                LifecycleDecision::ContainAndFail(LifecycleFailure::ExitQueryFailed),
            ),
            (
                LifecycleStep::ExitResult(Ok(9)),
                LifecycleDecision::ContainAndFail(LifecycleFailure::NonzeroExit(9)),
            ),
            (LifecycleStep::ActiveResult(Ok(0)), LifecycleDecision::Pass),
            (
                LifecycleStep::ActiveResult(Err(())),
                LifecycleDecision::ContainAndFail(LifecycleFailure::ActiveQueryFailed),
            ),
            (
                LifecycleStep::ActiveResult(Ok(1)),
                LifecycleDecision::ContainAndFail(LifecycleFailure::ActiveProcesses(1)),
            ),
        ];

        for (step, expected) in cases {
            assert_eq!(lifecycle_decision(step), expected, "{step:?}");
        }
    }

    #[test]
    fn confirmed_containment_never_turns_protocol_failure_into_pass() {
        for terminate_succeeded in [false, true] {
            for zero_confirmed in [false, true] {
                let resolution = resolve_failed_lifecycle(ContainmentObservation {
                    terminate_succeeded,
                    zero_confirmed,
                });
                assert!(!resolution.probe_passes);
                assert_eq!(resolution.release_job, zero_confirmed);
            }
        }
    }

    #[test]
    fn unconfirmed_job_lease_drops_only_after_report_write_and_flush() {
        use std::{cell::RefCell, io, rc::Rc};

        struct RecordingWriter(Rc<RefCell<Vec<&'static str>>>);
        impl io::Write for RecordingWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.borrow_mut().push("write");
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                self.0.borrow_mut().push("flush");
                Ok(())
            }
        }

        struct RecordingLease(Rc<RefCell<Vec<&'static str>>>);
        impl Drop for RecordingLease {
            fn drop(&mut self) {
                self.0.borrow_mut().push("drop");
            }
        }

        let events = Rc::new(RefCell::new(Vec::new()));
        let prepared = PreparedReport::new(
            summarize(&["only"], vec![ProbeResult::passed("only")], Vec::new()),
            Some(RecordingLease(Rc::clone(&events))),
        );
        assert!(events.borrow().is_empty());

        write_prepared_report(&mut RecordingWriter(Rc::clone(&events)), prepared)
            .expect("write report");

        assert_eq!(&*events.borrow(), &["write", "write", "flush", "drop"]);
    }

    #[test]
    fn json_escapes_quotes_backslashes_newlines_controls_and_keeps_unicode() {
        let report = Report {
            overall: Outcome::Fail,
            exit_code: 1,
            probes: vec![ProbeResult {
                name: "probe",
                outcome: Outcome::Fail,
                expected: Some(50),
                actual: Some(87),
                reason: None,
            }],
            reasons: vec![
                "localized ไทย \"quote\" \\ slash\nline\u{0001}".to_owned(),
                "top\rreason".to_owned(),
            ],
        };

        assert_eq!(
            report_json(&report),
            "{\"schema\":\"fsring-control-smoke/v1\",\"overall\":\"FAIL\",\"exitCode\":1,\
\"probes\":[{\"name\":\"probe\",\"outcome\":\"FAIL\",\"expected\":50,\"actual\":87}],\
\"reasons\":[\"localized ไทย \\\"quote\\\" \\\\ slash\\nline\\u0001\",\
\"top\\rreason\"]}"
        );
    }

    #[cfg(windows)]
    fn r3_unique_path(label: &str) -> PathBuf {
        let nonce = R3_NONCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("fsring-r3-{}-{nonce}-{label}", std::process::id()))
    }

    #[cfg(windows)]
    fn r3_wait_for_path(path: &Path, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if path.exists() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(windows)]
    fn r3_helper_command(test_name: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("test executable path"));
        command
            .arg("--exact")
            .arg(test_name)
            .arg("--ignored")
            .arg("--nocapture");
        command
    }

    #[cfg(windows)]
    #[test]
    #[ignore]
    fn r3_helper_delayed_grandchild() {
        if std::env::var_os("FSRING_R3_HELPER_ROLE").as_deref()
            != Some(std::ffi::OsStr::new("grandchild"))
        {
            return;
        }

        let ready = PathBuf::from(std::env::var_os("FSRING_R3_READY").expect("ready path"));
        let sentinel =
            PathBuf::from(std::env::var_os("FSRING_R3_SENTINEL").expect("sentinel path"));
        std::fs::write(&ready, b"ready").expect("write ready marker");
        thread::sleep(Duration::from_millis(800));
        std::fs::write(&sentinel, b"escaped").expect("write delayed sentinel");
    }

    #[cfg(windows)]
    #[test]
    #[ignore]
    fn r3_helper_root_exits_with_live_grandchild() {
        if std::env::var_os("FSRING_R3_HELPER_ROLE").as_deref()
            != Some(std::ffi::OsStr::new("root"))
        {
            return;
        }

        let ready = PathBuf::from(std::env::var_os("FSRING_R3_READY").expect("ready path"));
        let sentinel =
            PathBuf::from(std::env::var_os("FSRING_R3_SENTINEL").expect("sentinel path"));
        let mut grandchild = r3_helper_command("tests::r3_helper_delayed_grandchild");
        grandchild
            .env("FSRING_R3_HELPER_ROLE", "grandchild")
            .env("FSRING_R3_READY", &ready)
            .env("FSRING_R3_SENTINEL", &sentinel);
        let grandchild_process = grandchild.spawn().expect("spawn grandchild");
        assert!(
            r3_wait_for_path(&ready, Duration::from_secs(5)),
            "grandchild never published ready marker"
        );
        // The adversarial root must exit while its job-contained grandchild is live.
        // Release only this root's observer handles; waiting would invalidate the fixture.
        drop(grandchild_process);
    }

    #[cfg(windows)]
    #[test]
    #[ignore]
    fn r3_helper_stalled_root() {
        if std::env::var_os("FSRING_R3_HELPER_ROLE").as_deref()
            != Some(std::ffi::OsStr::new("stalled-root"))
        {
            return;
        }
        thread::sleep(Duration::from_secs(30));
    }

    #[cfg(windows)]
    #[test]
    #[ignore]
    fn r3_helper_validates_handle_allowlist() {
        if std::env::var_os("FSRING_R3_HELPER_ROLE").as_deref()
            != Some(std::ffi::OsStr::new("handle-list"))
        {
            return;
        }

        let intended = std::env::var("FSRING_R3_INTENDED_HANDLE")
            .expect("intended handle")
            .parse::<usize>()
            .expect("intended handle value");
        let ambient = std::env::var("FSRING_R3_AMBIENT_HANDLE")
            .expect("ambient handle")
            .parse::<usize>()
            .expect("ambient handle value");
        assert!(windows::test_handle_is_valid(intended));
        assert!(!windows::test_handle_is_valid(ambient));
    }

    #[cfg(windows)]
    #[test]
    fn private_job_contains_stalled_root_and_confirms_zero() {
        let _lock = R3_INTEGRATION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let intended = windows::test_open_nul().expect("open intended NUL");
        windows::test_set_inherit(&intended, true).expect("make intended originally inheritable");
        let original_flags = windows::test_handle_flags(&intended).expect("intended flags");
        let role = OsStr::new("stalled-root");
        let _environment = R3EnvironmentGuard::set(&[("FSRING_R3_HELPER_ROLE", role)]);

        let result =
            windows::run_contained_test_helper(&intended, "tests::r3_helper_stalled_root", 100);

        assert!(
            result
                .result
                .as_ref()
                .is_err_and(|reason| reason.contains("child did not exit within 100 ms")),
            "{:?}",
            result.result
        );
        assert!(result.containment_zero_confirmed);
        assert!(!result.retained_job_lease);
        assert_eq!(
            windows::test_handle_flags(&intended).expect("restored intended flags"),
            original_flags
        );
    }

    #[cfg(windows)]
    #[test]
    fn private_job_rejects_zero_root_with_live_grandchild_and_blocks_sentinel() {
        let _lock = R3_INTEGRATION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let ready = r3_unique_path("ready");
        let sentinel = r3_unique_path("sentinel");
        let _ = std::fs::remove_file(&ready);
        let _ = std::fs::remove_file(&sentinel);
        let intended = windows::test_open_nul().expect("open intended NUL");
        let original_flags = windows::test_handle_flags(&intended).expect("intended flags");
        let _environment = R3EnvironmentGuard::set(&[
            ("FSRING_R3_HELPER_ROLE", OsStr::new("root")),
            ("FSRING_R3_READY", ready.as_os_str()),
            ("FSRING_R3_SENTINEL", sentinel.as_os_str()),
        ]);

        let result = windows::run_contained_test_helper(
            &intended,
            "tests::r3_helper_root_exits_with_live_grandchild",
            5_000,
        );

        assert!(
            result.result.as_ref().is_err_and(|reason| reason
                .contains("root exited zero but job accounting reported 1 active process(es)")),
            "{:?}",
            result.result
        );
        assert!(result.containment_zero_confirmed);
        assert!(!result.retained_job_lease);
        assert_eq!(
            windows::test_handle_flags(&intended).expect("restored intended flags"),
            original_flags
        );
        assert!(
            r3_wait_for_path(&ready, Duration::from_secs(1)),
            "grandchild never published ready marker"
        );
        thread::sleep(Duration::from_millis(1_000));
        assert!(
            !sentinel.exists(),
            "contained grandchild wrote its forbidden delayed sentinel"
        );

        let _ = std::fs::remove_file(&ready);
        let _ = std::fs::remove_file(&sentinel);
    }

    #[cfg(windows)]
    #[test]
    fn handle_list_excludes_ambient_inheritable_handle() {
        let _lock = R3_INTEGRATION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let intended = windows::test_open_nul().expect("open intended NUL");
        // Keep enough non-inheritable handles open that the ambient candidate's
        // numeric slot cannot be accidentally reused by ordinary child startup.
        // The assertion still checks the real child handle table, not a mock.
        let ambient_reservations: Vec<_> = (0..256)
            .map(|_| windows::test_open_nul().expect("open ambient NUL reservation"))
            .collect();
        let ambient = ambient_reservations
            .last()
            .expect("ambient reservation roster is nonempty");
        windows::test_set_inherit(ambient, true).expect("make ambient inheritable");
        let original_flags = windows::test_handle_flags(&intended).expect("intended flags");
        let intended_value = windows::test_handle_value(&intended).to_string();
        let ambient_value = windows::test_handle_value(ambient).to_string();
        let _environment = R3EnvironmentGuard::set(&[
            ("FSRING_R3_HELPER_ROLE", OsStr::new("handle-list")),
            (
                "FSRING_R3_INTENDED_HANDLE",
                OsStr::new(intended_value.as_str()),
            ),
            (
                "FSRING_R3_AMBIENT_HANDLE",
                OsStr::new(ambient_value.as_str()),
            ),
        ]);

        let result = windows::run_contained_test_helper(
            &intended,
            "tests::r3_helper_validates_handle_allowlist",
            5_000,
        );

        assert_eq!(result.result, Ok(0));
        assert!(!result.containment_zero_confirmed);
        assert!(!result.retained_job_lease);
        assert_eq!(
            windows::test_handle_flags(&intended).expect("restored intended flags"),
            original_flags
        );
    }
}

// ---------------------------------------------------------------------------
// The C4 private worker modes
// ---------------------------------------------------------------------------

/// The arguments `--c4-post-unload` requires, each as one native argv element.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PostUnloadArgs {
    nonce: String,
    boot_lo: u64,
    boot_hi: u64,
    mount_lo: u64,
    mount_hi: u64,
    session_epoch: u64,
    vdo_native_name: String,
    dos_name: String,
}

/// Parse exactly `digits` uppercase hex characters with no `0x`.
///
/// Uppercase only, and exact width: a lenient parser here would let the runner
/// and the worker disagree about an identity while both looked well formed.
fn parse_exact_hex(value: &str, digits: usize) -> Result<u64, String> {
    if value.len() != digits
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'F'))
    {
        return Err(format!("expected exactly {digits} uppercase hex digits"));
    }
    u64::from_str_radix(value, 16).map_err(|_| "value is outside the 64-bit range".to_owned())
}

/// Pull one `--flag VALUE` pair out of the remaining arguments.
///
/// The flag must be present exactly once and its value must be the very next
/// element, so a quoted argument that split into two never silently becomes a
/// different name.
fn take_flag<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    let mut found: Option<&str> = None;
    let mut index = 0usize;
    while index < args.len() {
        let Some(current) = args.get(index) else {
            break;
        };
        if current == flag {
            if found.is_some() {
                return Err(format!("{flag} was supplied more than once"));
            }
            let Some(value) = args.get(index.saturating_add(1)) else {
                return Err(format!("{flag} requires exactly one value"));
            };
            found = Some(value.as_str());
            index = index.saturating_add(2);
            continue;
        }
        index = index.saturating_add(1);
    }
    found.ok_or_else(|| format!("{flag} is required"))
}

fn parse_post_unload_args(args: &[String]) -> Result<PostUnloadArgs, String> {
    // Eight flag/value pairs plus the mode itself.
    if args.len() != 17 {
        return Err("--c4-post-unload requires all eight arguments".to_owned());
    }
    let rest = args.get(1..).unwrap_or_default();
    let nonce = take_flag(rest, "--nonce")?.to_owned();
    if fsring_user::smoke::WorkerNonce::parse(&nonce).is_err() {
        return Err("--nonce must be 32 uppercase hex digits".to_owned());
    }
    let vdo_native_name = take_flag(rest, "--vdo-native-name")?.to_owned();
    let dos_name = take_flag(rest, "--dos-name")?.to_owned();
    if vdo_native_name.is_empty() || dos_name.is_empty() {
        return Err("names must be non-empty".to_owned());
    }
    Ok(PostUnloadArgs {
        nonce,
        boot_lo: parse_exact_hex(take_flag(rest, "--boot-lo")?, 16)?,
        boot_hi: parse_exact_hex(take_flag(rest, "--boot-hi")?, 16)?,
        mount_lo: parse_exact_hex(take_flag(rest, "--mount-lo")?, 16)?,
        mount_hi: parse_exact_hex(take_flag(rest, "--mount-hi")?, 16)?,
        session_epoch: parse_exact_hex(take_flag(rest, "--session-epoch")?, 16)?,
        vdo_native_name,
        dos_name,
    })
}

impl PostUnloadArgs {
    fn identity(&self) -> fsring_user::smoke::SmokeIdentity {
        fsring_user::smoke::SmokeIdentity {
            boot_instance_id: fsring_user::smoke::HexIdentity {
                lo: self.boot_lo,
                hi: self.boot_hi,
            },
            mount_id: fsring_user::smoke::HexIdentity {
                lo: self.mount_lo,
                hi: self.mount_hi,
            },
            session_epoch: self.session_epoch,
        }
    }
}

/// Emit one private frame on stdout and return the process exit code.
///
/// A worker mode never emits a public report: the runner alone owns `v2`.
fn emit_worker_frame(frame: &fsring_user::smoke::WorkerFrame) -> bool {
    let mut stdout = std::io::stdout().lock();
    // The runner detects a missing frame by its own deadline; a partial frame
    // must never reach it, so a write failure ends the worker immediately.
    fsring_user::smoke::write_worker_frame(&mut stdout, frame).is_ok()
}

/// The persistent live worker.
///
/// It performs the parent-required STAGED operation trace, sends `STAGED`,
/// waits for exactly one `RUN_MOUNT`, performs the live probes, and sends
/// `LIVE_CLEANED`. The happy path never calls a NOT RUN placeholder constructor.
fn run_c4_live_worker(nonce: &str) -> std::process::ExitCode {
    use fsring_user::smoke::{
        live::{
            live_cleaned_frame, observe_live_range, observe_staged_prefix, staged_frame,
            zero_identity,
        },
        CleanupSummary, SmokeReason, UnloadSeed, WorkerFrame, WorkerNonce,
    };
    let Ok(nonce) = WorkerNonce::parse(nonce) else {
        return std::process::ExitCode::from(21);
    };

    let mut reasons: Vec<SmokeReason> = Vec::new();

    #[cfg(not(windows))]
    {
        let _ = (nonce, &mut reasons);
        if let Ok(reason) = SmokeReason::parse("the live worker requires a Windows host", false) {
            reasons.push(reason);
        }
        return std::process::ExitCode::from(21);
    }

    #[cfg(windows)]
    {
        use fsring_user::smoke::live::WindowsC4Backend;
        let mut acc = fsring_user::smoke::C4ProbeAccumulator::new();
        let mut backend = WindowsC4Backend::new();
        let staged_probes = match observe_staged_prefix(&mut acc, &mut backend, zero_identity()) {
            Ok(probes) => probes,
            Err(_) => {
                if let Ok(reason) = SmokeReason::parse("staged observation failed", false) {
                    reasons.push(reason);
                }
                return std::process::ExitCode::from(21);
            }
        };
        let root = backend.root_identity();
        let disposable = backend.disposable_identity();
        let vdo_native_name = format!(
            "\\Device\\FsRingVolume-{:016X}-{:016X}",
            root.mount_id.lo, root.mount_id.hi,
        );
        let staged_events = backend.take_events();
        let staged = staged_frame(
            nonce,
            root,
            disposable,
            vdo_native_name.clone(),
            staged_probes,
            staged_events,
            reasons.clone(),
        );
        if !emit_worker_frame(&staged) {
            return std::process::ExitCode::from(21);
        }

        let mut stdin = std::io::stdin().lock();
        let command = match fsring_user::smoke::read_worker_frame(&mut stdin) {
            Ok(WorkerFrame::RunMount(command)) => command,
            Ok(_) | Err(_) => return std::process::ExitCode::from(22),
        };
        if command.nonce != nonce || command.root_identity != root {
            return std::process::ExitCode::from(23);
        }

        let live_probes = match observe_live_range(&mut acc, &mut backend, root) {
            Ok(probes) => probes,
            Err(_) => {
                if let Ok(reason) = SmokeReason::parse("live observation failed", false) {
                    reasons.push(reason);
                }
                return std::process::ExitCode::from(21);
            }
        };
        let cleanup = live_probes
            .iter()
            .find(|probe| probe.name == fsring_user::smoke::ProbeName::CleanupClose)
            .and_then(|probe| probe.actual.as_ref())
            .and_then(|actual| match actual {
                fsring_user::smoke::Oracle::Facts { values } => Some(CleanupSummary {
                    pending_enter_count: values
                        .iter()
                        .find(|(key, _)| *key == "pendingEnterCount")
                        .and_then(|(_, value)| match value {
                            fsring_user::smoke::FactValue::Hex32(raw) => Some(u64::from(*raw)),
                            _ => None,
                        })
                        .unwrap_or(0),
                    alias_count: values
                        .iter()
                        .find(|(key, _)| *key == "aliasCount")
                        .and_then(|(_, value)| match value {
                            fsring_user::smoke::FactValue::Hex32(raw) => Some(u64::from(*raw)),
                            _ => None,
                        })
                        .unwrap_or(0),
                    owned_handle_count: values
                        .iter()
                        .find(|(key, _)| *key == "ownedHandleCount")
                        .and_then(|(_, value)| match value {
                            fsring_user::smoke::FactValue::Hex32(raw) => Some(u64::from(*raw)),
                            _ => None,
                        })
                        .unwrap_or(0),
                    completed_once: values
                        .iter()
                        .find(|(key, _)| *key == "completedOnce")
                        .and_then(|(_, value)| match value {
                            fsring_user::smoke::FactValue::Bool(flag) => Some(*flag),
                            _ => None,
                        })
                        .unwrap_or(false),
                }),
                _ => None,
            })
            .unwrap_or(CleanupSummary {
                pending_enter_count: 0,
                alias_count: 0,
                owned_handle_count: 0,
                completed_once: true,
            });
        let live = live_cleaned_frame(
            command.nonce,
            root,
            disposable,
            vdo_native_name,
            command.dos_name,
            live_probes,
            backend.take_events(),
            cleanup,
            UnloadSeed {
                former_alias_ranges_free: cleanup.alias_count == 0,
                owned_handles_closed: cleanup.owned_handle_count == 0 && cleanup.completed_once,
            },
            reasons,
        );
        if emit_worker_frame(&live) {
            std::process::ExitCode::SUCCESS
        } else {
            std::process::ExitCode::from(21)
        }
    }
}

/// The read-only post-unload worker.
///
/// It opens nothing it can write through and maps nothing at all: the two
/// BootContext opens are expected to be *denied*, which is the whole claim, and
/// a worker that could read the context could not make it.
fn run_c4_post_unload(args: &PostUnloadArgs) -> std::process::ExitCode {
    use fsring_user::smoke::{
        live::{observe_post_unload, post_unload_frame},
        WorkerNonce,
    };
    let Ok(nonce) = WorkerNonce::parse(&args.nonce) else {
        return std::process::ExitCode::from(21);
    };
    let root = args.identity();

    #[cfg(not(windows))]
    {
        let _ = (nonce, root, args);
        return std::process::ExitCode::from(21);
    }

    #[cfg(windows)]
    {
        use fsring_user::smoke::live::WindowsC4Backend;
        let mut acc = fsring_user::smoke::C4ProbeAccumulator::new();
        let mut backend = WindowsC4Backend::with_root(root);
        let observation = match observe_post_unload(&mut acc, &mut backend, root) {
            Ok(observation) => observation,
            Err(_) => return std::process::ExitCode::from(21),
        };
        let frame = post_unload_frame(
            nonce,
            root,
            args.vdo_native_name.clone(),
            args.dos_name.clone(),
            observation,
            Vec::new(),
        );
        if emit_worker_frame(&frame) {
            std::process::ExitCode::SUCCESS
        } else {
            std::process::ExitCode::from(21)
        }
    }
}
