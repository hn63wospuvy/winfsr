//! The strict canonical codec for private worker frames.
//!
//! This is deliberately **not** a JSON parser. It is a walk over the exact
//! expected shape: each key is matched as a raw byte literal in its fixed
//! position, so a reordered key, a duplicate key, and an escaped-equivalent
//! key (`name` for `name`) are all rejected by construction rather than by
//! a rule somebody has to remember to write. A general parser followed by
//! order checks would have to *decide* those cases; this one cannot express
//! them.
//!
//! The encoder emits exactly what the decoder accepts, so a round trip is
//! byte-identical.

use super::{
    CleanupSummary, EventName, FactValue, HexIdentity, LiveCleanedRecord, Oracle, Overall,
    PostUnloadRecord, ProbeName, ProbeOutcome, ProbeV2, RunMountCommand, SmokeIdentity,
    SmokeReason, SmokeReportV2, SmokeSchemaError, StagedRecord, StatusDomain, UnloadObservation,
    UnloadSeed, WorkerEvent, WorkerFrame, WorkerNonce, PRIVATE_EVENT_MAX, PROBE_ROSTER_V2,
    PUBLIC_SCHEMA_V2, REASON_MAX_ENTRIES, WORKER_SCHEMA,
};

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

fn hex64(value: u64) -> String {
    format!("\"0x{value:016X}\"")
}

fn hex32(value: u32) -> String {
    format!("\"0x{value:08X}\"")
}

fn identity(value: &SmokeIdentity) -> String {
    format!(
        "{{\"bootInstanceId\":{{\"lo\":{},\"hi\":{}}},\"mountId\":{{\"lo\":{},\"hi\":{}}},\"sessionEpoch\":{}}}",
        hex64(value.boot_instance_id.lo),
        hex64(value.boot_instance_id.hi),
        hex64(value.mount_id.lo),
        hex64(value.mount_id.hi),
        hex64(value.session_epoch),
    )
}

/// Only the characters a bounded reason or a canonical name may contain are
/// emitted; everything else was already refused by the validating constructor.
fn json_string(text: &str) -> Result<String, SmokeSchemaError> {
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => return Err(SmokeSchemaError::InvalidReason),
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

fn facts(values: &[(&'static str, FactValue)]) -> Result<String, SmokeSchemaError> {
    let mut out = String::from("{");
    for (index, (key, value)) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&json_string(key)?);
        out.push(':');
        out.push_str(&encode_fact(*value));
    }
    out.push('}');
    Ok(out)
}

fn encode_fact(value: FactValue) -> String {
    match value {
        FactValue::Bool(flag) => flag.to_string(),
        FactValue::Hex32(raw) => hex32(raw),
        FactValue::Hex64(raw) => hex64(raw),
    }
}

fn event_names(names: &[EventName]) -> Result<String, SmokeSchemaError> {
    let mut out = String::from("[");
    for (index, name) in names.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&json_string(name.wire())?);
    }
    out.push(']');
    Ok(out)
}

fn oracle(value: &Oracle) -> Result<String, SmokeSchemaError> {
    Ok(match value {
        Oracle::Status {
            domain,
            code,
            information,
        } => format!(
            "{{\"kind\":\"status\",\"domain\":{},\"code\":{},\"information\":{}}}",
            json_string(domain.wire())?,
            hex32(*code),
            information.map_or_else(|| "null".to_string(), hex64),
        ),
        Oracle::Facts { values } => {
            format!("{{\"kind\":\"facts\",\"values\":{}}}", facts(values)?)
        }
        Oracle::Events {
            names,
            identity: who,
        } => format!(
            "{{\"kind\":\"events\",\"names\":{},\"identity\":{}}}",
            event_names(names)?,
            identity(who),
        ),
        Oracle::Compound {
            facts: values,
            names,
            identity: who,
        } => format!(
            "{{\"kind\":\"compound\",\"facts\":{{\"kind\":\"facts\",\"values\":{}}},\"events\":{{\"kind\":\"events\",\"names\":{},\"identity\":{}}}}}",
            facts(values)?,
            event_names(names)?,
            identity(who),
        ),
    })
}

fn probe(value: &ProbeV2) -> Result<String, SmokeSchemaError> {
    Ok(format!(
        "{{\"name\":{},\"outcome\":{},\"expected\":{},\"actual\":{}}}",
        json_string(value.name.wire())?,
        json_string(value.outcome.wire())?,
        oracle(&value.expected)?,
        match &value.actual {
            Some(actual) => oracle(actual)?,
            None => "null".to_string(),
        },
    ))
}

fn probes(values: &[ProbeV2]) -> Result<String, SmokeSchemaError> {
    let mut out = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&probe(value)?);
    }
    out.push(']');
    Ok(out)
}

fn events(values: &[WorkerEvent]) -> Result<String, SmokeSchemaError> {
    let mut out = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"name\":{},\"id\":{},\"version\":{},\"keyword\":{},\"identity\":{},\"reason\":{}}}",
            json_string(value.name.wire())?,
            value.id,
            value.version,
            hex64(value.keyword),
            identity(&value.identity),
            value.reason,
        ));
    }
    out.push(']');
    Ok(out)
}

fn reasons(values: &[SmokeReason]) -> Result<String, SmokeSchemaError> {
    if values.len() > REASON_MAX_ENTRIES {
        return Err(SmokeSchemaError::InvalidReason);
    }
    let mut out = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&json_string(value.as_str())?);
    }
    out.push(']');
    Ok(out)
}

fn cleanup(value: &CleanupSummary) -> String {
    format!(
        "{{\"pendingEnterCount\":{},\"aliasCount\":{},\"ownedHandleCount\":{},\"completedOnce\":{}}}",
        hex32(value.pending_enter_count as u32),
        hex32(value.alias_count as u32),
        hex32(value.owned_handle_count as u32),
        value.completed_once,
    )
}

fn unload_seed(value: &UnloadSeed) -> String {
    format!(
        "{{\"formerAliasRangesFree\":{},\"ownedHandlesClosed\":{}}}",
        value.former_alias_ranges_free, value.owned_handles_closed,
    )
}

fn unload_observation(value: &UnloadObservation) -> String {
    format!(
        "{{\"providerOpenNtstatus\":{},\"fscontrolOpenNtstatus\":{},\"vdoOpenNtstatus\":{}}}",
        hex32(value.provider_open_ntstatus),
        hex32(value.fscontrol_open_ntstatus),
        hex32(value.vdo_open_ntstatus),
    )
}

fn nonce(value: &WorkerNonce) -> Result<String, SmokeSchemaError> {
    json_string(&value.as_text())
}

/// Encode one frame into its canonical bytes.
pub fn encode_worker_frame(frame: &WorkerFrame) -> Result<Vec<u8>, SmokeSchemaError> {
    frame.validate()?;
    let head = format!(
        "{{\"schema\":{},\"sequence\":{},\"stage\":{}",
        json_string(WORKER_SCHEMA)?,
        frame.sequence(),
        json_string(frame.stage())?,
    );
    let body = match frame {
        WorkerFrame::Staged(record) => format!(
            ",\"nonce\":{},\"rootIdentity\":{},\"disposableIdentity\":{},\"vdoNativeName\":{},\"probes\":{},\"events\":{},\"reasons\":{}}}",
            nonce(&record.nonce)?,
            identity(&record.root_identity),
            identity(&record.disposable_identity),
            json_string(&record.vdo_native_name)?,
            probes(&record.probes)?,
            events(&record.events)?,
            reasons(&record.reasons)?,
        ),
        WorkerFrame::RunMount(record) => format!(
            ",\"nonce\":{},\"rootIdentity\":{},\"vdoNativeName\":{},\"dosName\":{}}}",
            nonce(&record.nonce)?,
            identity(&record.root_identity),
            json_string(&record.vdo_native_name)?,
            json_string(&record.dos_name)?,
        ),
        WorkerFrame::LiveCleaned(record) => format!(
            ",\"nonce\":{},\"rootIdentity\":{},\"disposableIdentity\":{},\"vdoNativeName\":{},\"dosName\":{},\"probes\":{},\"events\":{},\"cleanup\":{},\"unloadSeed\":{},\"reasons\":{}}}",
            nonce(&record.nonce)?,
            identity(&record.root_identity),
            identity(&record.disposable_identity),
            json_string(&record.vdo_native_name)?,
            json_string(&record.dos_name)?,
            probes(&record.probes)?,
            events(&record.events)?,
            cleanup(&record.cleanup),
            unload_seed(&record.unload_seed),
            reasons(&record.reasons)?,
        ),
        WorkerFrame::PostUnload(record) => format!(
            ",\"nonce\":{},\"rootIdentity\":{},\"vdoNativeName\":{},\"dosName\":{},\"unloadObservation\":{},\"probes\":{},\"reasons\":{}}}",
            nonce(&record.nonce)?,
            identity(&record.root_identity),
            json_string(&record.vdo_native_name)?,
            json_string(&record.dos_name)?,
            unload_observation(&record.unload_observation),
            probes(&record.probes)?,
            reasons(&record.reasons)?,
        ),
    };
    Ok(format!("{head}{body}").into_bytes())
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// A cursor that only ever moves forward over the exact expected shape.
struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, SmokeSchemaError> {
        // No BOM, no NUL, valid UTF-8: three refusals a lenient reader would
        // have to be told about separately.
        if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            return Err(SmokeSchemaError::Json);
        }
        if bytes.contains(&0) {
            return Err(SmokeSchemaError::Utf8);
        }
        core::str::from_utf8(bytes).map_err(|_| SmokeSchemaError::Utf8)?;
        Ok(Self { bytes, cursor: 0 })
    }

    /// Consume an exact byte literal. Every structural token and every key
    /// goes through here, which is what makes reordering unrepresentable.
    fn expect(&mut self, literal: &str) -> Result<(), SmokeSchemaError> {
        let end = self
            .cursor
            .checked_add(literal.len())
            .ok_or(SmokeSchemaError::Json)?;
        let seen = self
            .bytes
            .get(self.cursor..end)
            .ok_or(SmokeSchemaError::Json)?;
        if seen != literal.as_bytes() {
            return Err(SmokeSchemaError::UnknownOrReorderedKey);
        }
        self.cursor = end;
        Ok(())
    }

    fn peek(&self, literal: &str) -> bool {
        let Some(end) = self.cursor.checked_add(literal.len()) else {
            return false;
        };
        self.bytes.get(self.cursor..end) == Some(literal.as_bytes())
    }

    fn done(&self) -> bool {
        self.cursor == self.bytes.len()
    }

    /// Read one quoted string with the encoder's exact escape vocabulary.
    fn string(&mut self) -> Result<String, SmokeSchemaError> {
        self.expect("\"")?;
        let mut out = String::new();
        loop {
            let byte = *self.bytes.get(self.cursor).ok_or(SmokeSchemaError::Json)?;
            self.cursor = self.cursor.saturating_add(1);
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let escape = *self.bytes.get(self.cursor).ok_or(SmokeSchemaError::Json)?;
                    self.cursor = self.cursor.saturating_add(1);
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        // `\u` is the escaped-equivalent form; accepting it
                        // here would reopen the key-aliasing hole the literal
                        // matching above closes.
                        _ => return Err(SmokeSchemaError::DuplicateOrEscapedKey),
                    }
                }
                byte if byte < 0x20 => return Err(SmokeSchemaError::Json),
                byte => out.push(char::from(byte)),
            }
        }
    }

    fn hex_string(&mut self, digits: usize) -> Result<u64, SmokeSchemaError> {
        let text = self.string()?;
        parse_hex(&text, digits)
    }

    fn bool(&mut self) -> Result<bool, SmokeSchemaError> {
        if self.peek("true") {
            self.expect("true")?;
            Ok(true)
        } else if self.peek("false") {
            self.expect("false")?;
            Ok(false)
        } else {
            Err(SmokeSchemaError::WrongType)
        }
    }

    /// A bare unsigned decimal integer with no sign, no leading zero, and no
    /// fraction.
    fn integer(&mut self) -> Result<u64, SmokeSchemaError> {
        let start = self.cursor;
        while matches!(self.bytes.get(self.cursor), Some(byte) if byte.is_ascii_digit()) {
            self.cursor = self.cursor.saturating_add(1);
        }
        let digits = self
            .bytes
            .get(start..self.cursor)
            .ok_or(SmokeSchemaError::Json)?;
        if digits.is_empty() || (digits.len() > 1 && digits.first() == Some(&b'0')) {
            return Err(SmokeSchemaError::WrongType);
        }
        core::str::from_utf8(digits)
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or(SmokeSchemaError::WrongType)
    }
}

fn parse_hex(text: &str, digits: usize) -> Result<u64, SmokeSchemaError> {
    let Some(body) = text.strip_prefix("0x") else {
        return Err(SmokeSchemaError::WrongType);
    };
    if body.len() != digits
        || !body
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'F'))
    {
        return Err(SmokeSchemaError::WrongType);
    }
    u64::from_str_radix(body, 16).map_err(|_| SmokeSchemaError::WrongType)
}

fn read_identity(reader: &mut Reader<'_>) -> Result<SmokeIdentity, SmokeSchemaError> {
    reader.expect("{\"bootInstanceId\":{\"lo\":")?;
    let boot_lo = reader.hex_string(16)?;
    reader.expect(",\"hi\":")?;
    let boot_hi = reader.hex_string(16)?;
    reader.expect("},\"mountId\":{\"lo\":")?;
    let mount_lo = reader.hex_string(16)?;
    reader.expect(",\"hi\":")?;
    let mount_hi = reader.hex_string(16)?;
    reader.expect("},\"sessionEpoch\":")?;
    let session_epoch = reader.hex_string(16)?;
    reader.expect("}")?;
    Ok(SmokeIdentity {
        boot_instance_id: HexIdentity {
            lo: boot_lo,
            hi: boot_hi,
        },
        mount_id: HexIdentity {
            lo: mount_lo,
            hi: mount_hi,
        },
        session_epoch,
    })
}

/// Read one facts object. The keys are whatever the frame carries; the roster
/// comparison against the expected table happens in `ProbeV2::validate`.
fn read_facts(
    reader: &mut Reader<'_>,
    expected_keys: &[&'static str],
) -> Result<Vec<(&'static str, FactValue)>, SmokeSchemaError> {
    reader.expect("{")?;
    let mut values = Vec::new();
    for (index, key) in expected_keys.iter().enumerate() {
        if index > 0 {
            reader.expect(",")?;
        }
        reader.expect("\"")?;
        reader.expect(key)?;
        reader.expect("\":")?;
        let value = if reader.peek("true") || reader.peek("false") {
            FactValue::Bool(reader.bool()?)
        } else {
            let text = reader.string()?;
            let body = text.strip_prefix("0x").ok_or(SmokeSchemaError::WrongType)?;
            match body.len() {
                8 => FactValue::Hex32(
                    u32::try_from(parse_hex(&text, 8)?).map_err(|_| SmokeSchemaError::WrongType)?,
                ),
                16 => FactValue::Hex64(parse_hex(&text, 16)?),
                _ => return Err(SmokeSchemaError::WrongType),
            }
        };
        values.push((*key, value));
    }
    reader.expect("}")?;
    Ok(values)
}

fn read_event_names(reader: &mut Reader<'_>) -> Result<Vec<EventName>, SmokeSchemaError> {
    reader.expect("[")?;
    let mut names = Vec::new();
    if !reader.peek("]") {
        loop {
            let text = reader.string()?;
            names.push(EventName::parse(&text).ok_or(SmokeSchemaError::InvalidName)?);
            if reader.peek(",") {
                reader.expect(",")?;
            } else {
                break;
            }
        }
    }
    reader.expect("]")?;
    Ok(names)
}

/// Read one oracle whose expected shape is already known from the roster.
fn read_oracle(reader: &mut Reader<'_>, expected: &Oracle) -> Result<Oracle, SmokeSchemaError> {
    match expected {
        Oracle::Status { .. } => {
            reader.expect("{\"kind\":\"status\",\"domain\":")?;
            let domain = match reader.string()?.as_str() {
                "ntstatus" => StatusDomain::Ntstatus,
                "win32" => StatusDomain::Win32,
                _ => return Err(SmokeSchemaError::WrongLiteral),
            };
            reader.expect(",\"code\":")?;
            let code =
                u32::try_from(reader.hex_string(8)?).map_err(|_| SmokeSchemaError::WrongType)?;
            reader.expect(",\"information\":")?;
            let information = if reader.peek("null") {
                reader.expect("null")?;
                None
            } else {
                Some(reader.hex_string(16)?)
            };
            reader.expect("}")?;
            Ok(Oracle::Status {
                domain,
                code,
                information,
            })
        }
        Oracle::Facts { values } => {
            reader.expect("{\"kind\":\"facts\",\"values\":")?;
            let keys: Vec<&'static str> = values.iter().map(|(key, _)| *key).collect();
            let read = read_facts(reader, &keys)?;
            reader.expect("}")?;
            Ok(Oracle::Facts { values: read })
        }
        Oracle::Events { .. } => {
            reader.expect("{\"kind\":\"events\",\"names\":")?;
            let names = read_event_names(reader)?;
            reader.expect(",\"identity\":")?;
            let who = read_identity(reader)?;
            reader.expect("}")?;
            Ok(Oracle::Events {
                names,
                identity: who,
            })
        }
        Oracle::Compound { facts: values, .. } => {
            reader.expect("{\"kind\":\"compound\",\"facts\":{\"kind\":\"facts\",\"values\":")?;
            let keys: Vec<&'static str> = values.iter().map(|(key, _)| *key).collect();
            let read = read_facts(reader, &keys)?;
            reader.expect("},\"events\":{\"kind\":\"events\",\"names\":")?;
            let names = read_event_names(reader)?;
            reader.expect(",\"identity\":")?;
            let who = read_identity(reader)?;
            reader.expect("}}")?;
            Ok(Oracle::Compound {
                facts: read,
                names,
                identity: who,
            })
        }
    }
}

fn read_probes(
    reader: &mut Reader<'_>,
    range: core::ops::Range<usize>,
    root: SmokeIdentity,
) -> Result<Vec<ProbeV2>, SmokeSchemaError> {
    let expected_names = PROBE_ROSTER_V2
        .get(range)
        .ok_or(SmokeSchemaError::InvalidProbeRoster)?;
    reader.expect("[")?;
    let mut out = Vec::new();
    for (index, expected_name) in expected_names.iter().enumerate() {
        if index > 0 {
            reader.expect(",")?;
        }
        reader.expect("{\"name\":")?;
        let name_text = reader.string()?;
        let name = ProbeName::parse(&name_text).ok_or(SmokeSchemaError::InvalidName)?;
        if name != *expected_name {
            return Err(SmokeSchemaError::InvalidProbeRoster);
        }
        reader.expect(",\"outcome\":")?;
        let outcome = match reader.string()?.as_str() {
            "PASS" => ProbeOutcome::Pass,
            "FAIL" => ProbeOutcome::Fail,
            "NOT RUN" => ProbeOutcome::NotRun,
            _ => return Err(SmokeSchemaError::WrongLiteral),
        };
        let table = super::expected_oracle(name, root);
        reader.expect(",\"expected\":")?;
        let expected = read_oracle(reader, &table)?;
        reader.expect(",\"actual\":")?;
        let actual = if reader.peek("null") {
            reader.expect("null")?;
            None
        } else {
            Some(read_oracle(reader, &table)?)
        };
        reader.expect("}")?;
        out.push(ProbeV2 {
            name,
            outcome,
            expected,
            actual,
        });
    }
    reader.expect("]")?;
    Ok(out)
}

fn read_events(reader: &mut Reader<'_>) -> Result<Vec<WorkerEvent>, SmokeSchemaError> {
    reader.expect("[")?;
    let mut out = Vec::new();
    if !reader.peek("]") {
        loop {
            if out.len() >= PRIVATE_EVENT_MAX {
                return Err(SmokeSchemaError::InvalidEvent);
            }
            reader.expect("{\"name\":")?;
            let name = EventName::parse(&reader.string()?).ok_or(SmokeSchemaError::InvalidName)?;
            reader.expect(",\"id\":")?;
            let id = u32::try_from(reader.integer()?).map_err(|_| SmokeSchemaError::WrongType)?;
            reader.expect(",\"version\":")?;
            let version =
                u32::try_from(reader.integer()?).map_err(|_| SmokeSchemaError::WrongType)?;
            reader.expect(",\"keyword\":")?;
            let keyword = reader.hex_string(16)?;
            reader.expect(",\"identity\":")?;
            let who = read_identity(reader)?;
            reader.expect(",\"reason\":")?;
            let reason =
                u32::try_from(reader.integer()?).map_err(|_| SmokeSchemaError::WrongType)?;
            reader.expect("}")?;
            out.push(WorkerEvent {
                name,
                id,
                version,
                keyword,
                identity: who,
                reason,
            });
            if reader.peek(",") {
                reader.expect(",")?;
            } else {
                break;
            }
        }
    }
    reader.expect("]")?;
    Ok(out)
}

fn read_reasons(reader: &mut Reader<'_>) -> Result<Vec<SmokeReason>, SmokeSchemaError> {
    reader.expect("[")?;
    let mut out = Vec::new();
    if !reader.peek("]") {
        loop {
            if out.len() >= REASON_MAX_ENTRIES {
                return Err(SmokeSchemaError::InvalidReason);
            }
            let text = reader.string()?;
            out.push(SmokeReason::parse(&text, false)?);
            if reader.peek(",") {
                reader.expect(",")?;
            } else {
                break;
            }
        }
    }
    reader.expect("]")?;
    Ok(out)
}

fn read_nonce(reader: &mut Reader<'_>) -> Result<WorkerNonce, SmokeSchemaError> {
    WorkerNonce::parse(&reader.string()?)
}

/// Decode one complete frame. Trailing bytes are a refusal, not a stop.
pub fn decode_worker_frame(bytes: &[u8]) -> Result<WorkerFrame, SmokeSchemaError> {
    if bytes.len() < super::WORKER_FRAME_MIN || bytes.len() > super::WORKER_FRAME_MAX {
        return Err(SmokeSchemaError::Length);
    }
    let mut reader = Reader::new(bytes)?;
    reader.expect("{\"schema\":\"")?;
    reader.expect(WORKER_SCHEMA)?;
    reader.expect("\",\"sequence\":")?;
    let sequence = u32::try_from(reader.integer()?).map_err(|_| SmokeSchemaError::WrongType)?;
    reader.expect(",\"stage\":")?;
    let stage = reader.string()?;
    let frame = match (sequence, stage.as_str()) {
        (1, "STAGED") => {
            reader.expect(",\"nonce\":")?;
            let nonce = read_nonce(&mut reader)?;
            reader.expect(",\"rootIdentity\":")?;
            let root_identity = read_identity(&mut reader)?;
            reader.expect(",\"disposableIdentity\":")?;
            let disposable_identity = read_identity(&mut reader)?;
            reader.expect(",\"vdoNativeName\":")?;
            let vdo_native_name = reader.string()?;
            reader.expect(",\"probes\":")?;
            let probes = read_probes(&mut reader, super::STAGED_PROBE_RANGE, root_identity)?;
            reader.expect(",\"events\":")?;
            let events = read_events(&mut reader)?;
            reader.expect(",\"reasons\":")?;
            let reasons = read_reasons(&mut reader)?;
            reader.expect("}")?;
            WorkerFrame::Staged(StagedRecord {
                sequence,
                nonce,
                root_identity,
                disposable_identity,
                vdo_native_name,
                probes,
                events,
                reasons,
            })
        }
        (2, "RUN_MOUNT") => {
            reader.expect(",\"nonce\":")?;
            let nonce = read_nonce(&mut reader)?;
            reader.expect(",\"rootIdentity\":")?;
            let root_identity = read_identity(&mut reader)?;
            reader.expect(",\"vdoNativeName\":")?;
            let vdo_native_name = reader.string()?;
            reader.expect(",\"dosName\":")?;
            let dos_name = reader.string()?;
            reader.expect("}")?;
            WorkerFrame::RunMount(RunMountCommand {
                sequence,
                nonce,
                root_identity,
                vdo_native_name,
                dos_name,
            })
        }
        (3, "LIVE_CLEANED") => {
            reader.expect(",\"nonce\":")?;
            let nonce = read_nonce(&mut reader)?;
            reader.expect(",\"rootIdentity\":")?;
            let root_identity = read_identity(&mut reader)?;
            reader.expect(",\"disposableIdentity\":")?;
            let disposable_identity = read_identity(&mut reader)?;
            reader.expect(",\"vdoNativeName\":")?;
            let vdo_native_name = reader.string()?;
            reader.expect(",\"dosName\":")?;
            let dos_name = reader.string()?;
            reader.expect(",\"probes\":")?;
            let probes = read_probes(&mut reader, super::LIVE_PROBE_RANGE, root_identity)?;
            reader.expect(",\"events\":")?;
            let events = read_events(&mut reader)?;
            reader.expect(",\"cleanup\":{\"pendingEnterCount\":")?;
            let pending_enter_count = reader.hex_string(8)?;
            reader.expect(",\"aliasCount\":")?;
            let alias_count = reader.hex_string(8)?;
            reader.expect(",\"ownedHandleCount\":")?;
            let owned_handle_count = reader.hex_string(8)?;
            reader.expect(",\"completedOnce\":")?;
            let completed_once = reader.bool()?;
            reader.expect("},\"unloadSeed\":{\"formerAliasRangesFree\":")?;
            let former_alias_ranges_free = reader.bool()?;
            reader.expect(",\"ownedHandlesClosed\":")?;
            let owned_handles_closed = reader.bool()?;
            reader.expect("},\"reasons\":")?;
            let reasons = read_reasons(&mut reader)?;
            reader.expect("}")?;
            WorkerFrame::LiveCleaned(LiveCleanedRecord {
                sequence,
                nonce,
                root_identity,
                disposable_identity,
                vdo_native_name,
                dos_name,
                probes,
                events,
                cleanup: CleanupSummary {
                    pending_enter_count,
                    alias_count,
                    owned_handle_count,
                    completed_once,
                },
                unload_seed: UnloadSeed {
                    former_alias_ranges_free,
                    owned_handles_closed,
                },
                reasons,
            })
        }
        (4, "POST_UNLOAD") => {
            reader.expect(",\"nonce\":")?;
            let nonce = read_nonce(&mut reader)?;
            reader.expect(",\"rootIdentity\":")?;
            let root_identity = read_identity(&mut reader)?;
            reader.expect(",\"vdoNativeName\":")?;
            let vdo_native_name = reader.string()?;
            reader.expect(",\"dosName\":")?;
            let dos_name = reader.string()?;
            reader.expect(",\"unloadObservation\":{\"providerOpenNtstatus\":")?;
            let provider_open_ntstatus =
                u32::try_from(reader.hex_string(8)?).map_err(|_| SmokeSchemaError::WrongType)?;
            reader.expect(",\"fscontrolOpenNtstatus\":")?;
            let fscontrol_open_ntstatus =
                u32::try_from(reader.hex_string(8)?).map_err(|_| SmokeSchemaError::WrongType)?;
            reader.expect(",\"vdoOpenNtstatus\":")?;
            let vdo_open_ntstatus =
                u32::try_from(reader.hex_string(8)?).map_err(|_| SmokeSchemaError::WrongType)?;
            reader.expect("},\"probes\":")?;
            let probes = read_probes(&mut reader, super::POST_PROBE_RANGE, root_identity)?;
            reader.expect(",\"reasons\":")?;
            let reasons = read_reasons(&mut reader)?;
            reader.expect("}")?;
            WorkerFrame::PostUnload(PostUnloadRecord {
                sequence,
                nonce,
                root_identity,
                vdo_native_name,
                dos_name,
                unload_observation: UnloadObservation {
                    provider_open_ntstatus,
                    fscontrol_open_ntstatus,
                    vdo_open_ntstatus,
                },
                probes,
                reasons,
            })
        }
        // A sequence that does not match its stage is a forged frame, not a
        // recoverable one.
        _ => return Err(SmokeSchemaError::WrongSequence),
    };
    if !reader.done() {
        return Err(SmokeSchemaError::TrailingBytes);
    }
    // One refusal invalidates the whole frame: nothing it carried is trusted.
    frame.validate()?;
    Ok(frame)
}

fn strip_one_trailing_lf(bytes: &[u8]) -> &[u8] {
    match bytes.split_last() {
        Some((b'\n', rest)) => rest,
        _ => bytes,
    }
}

/// Canonical public `fsring-control-smoke/v2` bytes, including the trailing LF.
pub fn encode_public_report_v2(report: &SmokeReportV2) -> Result<Vec<u8>, SmokeSchemaError> {
    let identity_json = match &report.identity {
        Some(value) => identity(value),
        None => "null".to_string(),
    };
    let mut bytes = format!(
        "{{\"schema\":{},\"overall\":{},\"exitCode\":{},\"identity\":{},\"probes\":{},\"reasons\":{}}}",
        json_string(PUBLIC_SCHEMA_V2)?,
        json_string(report.overall.wire())?,
        report.exit_code,
        identity_json,
        probes(&report.probes)?,
        reasons(&report.reasons)?,
    )
    .into_bytes();
    bytes.push(b'\n');
    Ok(bytes)
}

/// Decode one canonical public v2 object. A v1 harness or wrapper is
/// `WrongLiteral`, never a successful v2 report.
pub fn decode_public_report_v2(bytes: &[u8]) -> Result<SmokeReportV2, SmokeSchemaError> {
    let bytes = strip_one_trailing_lf(bytes);
    let mut reader = Reader::new(bytes)?;
    reader.expect("{\"schema\":")?;
    let schema = reader.string()?;
    if schema != PUBLIC_SCHEMA_V2 {
        return Err(SmokeSchemaError::WrongLiteral);
    }
    reader.expect(",\"overall\":")?;
    let overall = match reader.string()?.as_str() {
        "PASS" => Overall::Pass,
        "FAIL" => Overall::Fail,
        "NOT RUN" => Overall::NotRun,
        _ => return Err(SmokeSchemaError::WrongLiteral),
    };
    reader.expect(",\"exitCode\":")?;
    let exit_code = u32::try_from(reader.integer()?).map_err(|_| SmokeSchemaError::WrongType)?;
    reader.expect(",\"identity\":")?;
    let identity = if reader.peek("null") {
        reader.expect("null")?;
        None
    } else {
        Some(read_identity(&mut reader)?)
    };
    let root = identity.unwrap_or(SmokeIdentity {
        boot_instance_id: HexIdentity { lo: 0, hi: 0 },
        mount_id: HexIdentity { lo: 0, hi: 0 },
        session_epoch: 0,
    });
    reader.expect(",\"probes\":")?;
    let probes = read_probes(&mut reader, 0..PROBE_ROSTER_V2.len(), root)?;
    reader.expect(",\"reasons\":")?;
    let reasons = read_reasons(&mut reader)?;
    reader.expect("}")?;
    if !reader.done() {
        return Err(SmokeSchemaError::TrailingBytes);
    }
    Ok(SmokeReportV2 {
        overall,
        exit_code,
        identity,
        probes,
        reasons,
    })
}
