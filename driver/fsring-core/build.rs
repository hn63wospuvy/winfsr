//! Fail-closed production-attestation verification and witness generation.
//!
//! A `cargo check` proves the driver compiles. It says nothing about whether
//! the staged R3/R4/R5 machinery in the same tree is reachable from a dispatch
//! entry point — that is what `driver/scripts/audit_c4_production_graph.py`
//! decides. The problem with running that auditor by hand is that its PASS is
//! about *a* source tree, and nothing stops the PASS from outliving the tree it
//! was computed for.
//!
//! So the PASS becomes a build input. When `fsring-fsd` depends on this crate
//! it turns on the private `production-attested` feature, and this script then
//! refuses to build unless the tracked attestation still names this exact
//! source identity. Only after that does it generate the sealed witness the
//! crate embeds. Standalone `cargo test -p fsring-core` leaves the feature off,
//! runs no auditor, and uses an injected `#[cfg(test)]` witness instead — which
//! is what keeps the property rows inside the attestation from recursing into
//! the build script that verifies them.
//!
//! Every failure here is a hard build failure. There is no warn-and-continue
//! path: a driver image that embedded an unverified witness would be exactly
//! the artifact this whole protocol exists to make impossible.

use std::path::{Path, PathBuf};

/// The literal closed identity domain, mirroring the auditor's own constant.
const PACKAGE_ROOTS: [&str; 4] = [
    "fsring-abi",
    "driver/fsring-core",
    "driver/fsring-fsd",
    "driver/fsring-sys",
];

const CARGO_INPUTS: [&str; 6] = [
    "fsring-abi/Cargo.toml",
    "driver/fsring-core/Cargo.toml",
    "driver/fsring-fsd/Cargo.toml",
    "driver/fsring-sys/Cargo.toml",
    "driver/Cargo.toml",
    "driver/Cargo.lock",
];

const AUDITOR: &str = "driver/scripts/audit_c4_production_graph.py";
const MANIFEST: &str = "driver/audit/c4-production-graph.json";
const ATTESTATION: &str = "driver/audit/c4-production-attestation.json";
const TASK12_GATE: &str = "task12_r3_cutover_has_exactly_one_terminal_delete_path";
const TASK12_DELETE: &str = "task12_delete_requires_r3_discharge_and_later_authority_absence";
const R4_GATE: &str = "task13_18_r4_staging_is_production_unreachable";
const R4_CUTOVER_GATE: &str = "task19_r4_cutover_has_exactly_one_pending_terminal_delete_path";
const R5_GATE: &str = "task20_24_r5_staging_is_production_unreachable";
const R5_CUTOVER_GATE: &str = "task25_r5_cutover_has_exactly_one_all16_terminal_delete_path";
const KNOWN_CAPABILITY_ROWS: [&str; 6] = [
    TASK12_GATE,
    TASK12_DELETE,
    R4_GATE,
    R4_CUTOVER_GATE,
    R5_GATE,
    R5_CUTOVER_GATE,
];
const MAX_ATTESTED_REQUIRED_ROWS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AttestedRowCapabilities(u8);

impl AttestedRowCapabilities {
    const NONE: Self = Self(0);
    #[allow(dead_code)]
    const TASK12_CUTOVER: Self = Self(1 << 0);
    #[allow(dead_code)]
    const TASK12_EXACT_DELETE: Self = Self(1 << 1);
    /// Retired by Task 19's cutover: only the historical parser still emits it.
    #[cfg(test)]
    const R4_STAGING: Self = Self(1 << 2);
    #[allow(dead_code)]
    const R5_STAGING: Self = Self(1 << 3);
    const R4_CUTOVER: Self = Self(1 << 4);
    const R5_CUTOVER: Self = Self(1 << 5);

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    const fn bits(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CapabilityParseError {
    UnknownProfile,
    MissingKnownRow(&'static str),
    DuplicateKnownRow(&'static str),
    DuplicateUnrelatedRow,
    ProfileInappropriateRow(&'static str),
}

fn parse_required_row_capabilities(
    profile: &str,
    required_gates: &[&str],
    required_properties: &[&str],
) -> Result<AttestedRowCapabilities, CapabilityParseError> {
    if profile != "r5-cutover" {
        return Err(CapabilityParseError::UnknownProfile);
    }

    for name in KNOWN_CAPABILITY_ROWS {
        if count_row(required_gates, name) + count_row(required_properties, name) > 1 {
            return Err(CapabilityParseError::DuplicateKnownRow(name));
        }
    }
    reject_duplicate_unrelated_rows(required_gates, required_properties)?;

    require_row(required_gates, R4_CUTOVER_GATE)?;
    require_row(required_gates, R5_CUTOVER_GATE)?;
    reject_profile_row(required_gates, required_properties, R5_GATE)?;
    reject_profile_row(required_gates, required_properties, R4_GATE)?;
    Ok(AttestedRowCapabilities::NONE
        .union(AttestedRowCapabilities::R4_CUTOVER)
        .union(AttestedRowCapabilities::R5_CUTOVER))
}

#[cfg(test)]
fn parse_historical_required_row_capabilities(
    profile: &str,
    required_gates: &[&str],
    required_properties: &[&str],
) -> Result<AttestedRowCapabilities, CapabilityParseError> {
    if !matches!(profile, "r3-cutover" | "r4-stage" | "r5-stage") {
        return Err(CapabilityParseError::UnknownProfile);
    }

    for name in KNOWN_CAPABILITY_ROWS {
        if count_row(required_gates, name) + count_row(required_properties, name) > 1 {
            return Err(CapabilityParseError::DuplicateKnownRow(name));
        }
    }
    reject_duplicate_unrelated_rows(required_gates, required_properties)?;

    require_row(required_gates, TASK12_GATE)?;
    require_row(required_properties, TASK12_DELETE)?;
    let mut capabilities = AttestedRowCapabilities::NONE
        .union(AttestedRowCapabilities::TASK12_CUTOVER)
        .union(AttestedRowCapabilities::TASK12_EXACT_DELETE);
    match profile {
        "r3-cutover" => {
            reject_profile_row(required_gates, required_properties, R4_GATE)?;
            reject_profile_row(required_gates, required_properties, R5_GATE)?;
        }
        "r4-stage" => {
            require_row(required_gates, R4_GATE)?;
            capabilities = capabilities.union(AttestedRowCapabilities::R4_STAGING);
            reject_profile_row(required_gates, required_properties, R5_GATE)?;
        }
        "r5-stage" => {
            require_row(required_gates, R4_GATE)?;
            require_row(required_gates, R5_GATE)?;
            capabilities = capabilities
                .union(AttestedRowCapabilities::R4_STAGING)
                .union(AttestedRowCapabilities::R5_STAGING);
        }
        _ => return Err(CapabilityParseError::UnknownProfile),
    }
    reject_profile_row(required_gates, required_properties, R4_CUTOVER_GATE)?;
    Ok(capabilities)
}

fn count_row(rows: &[&str], required: &str) -> usize {
    rows.iter().filter(|row| **row == required).count()
}

fn require_row(rows: &[&str], required: &'static str) -> Result<(), CapabilityParseError> {
    if count_row(rows, required) == 1 {
        Ok(())
    } else {
        Err(CapabilityParseError::MissingKnownRow(required))
    }
}

fn reject_profile_row(
    gates: &[&str],
    properties: &[&str],
    row: &'static str,
) -> Result<(), CapabilityParseError> {
    if count_row(gates, row) + count_row(properties, row) == 0 {
        Ok(())
    } else {
        Err(CapabilityParseError::ProfileInappropriateRow(row))
    }
}

fn reject_duplicate_unrelated_rows(
    gates: &[&str],
    properties: &[&str],
) -> Result<(), CapabilityParseError> {
    for (index, row) in gates.iter().enumerate() {
        if KNOWN_CAPABILITY_ROWS.contains(row) {
            continue;
        }
        if gates[..index].contains(row) || properties.contains(row) {
            return Err(CapabilityParseError::DuplicateUnrelatedRow);
        }
    }
    for (index, row) in properties.iter().enumerate() {
        if KNOWN_CAPABILITY_ROWS.contains(row) {
            continue;
        }
        if properties[..index].contains(row) {
            return Err(CapabilityParseError::DuplicateUnrelatedRow);
        }
    }
    Ok(())
}

fn fail(message: &str) -> ! {
    // `panic!` in a build script is the documented hard failure; the message
    // reaches the user as the build error.
    panic!("{message}");
}

fn repo_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|_| fail("CARGO_MANIFEST_DIR is not set"));
    let path = PathBuf::from(manifest_dir);
    let Some(driver) = path.parent() else {
        fail("the package directory has no parent")
    };
    let Some(root) = driver.parent() else {
        fail("the driver directory has no parent")
    };
    root.to_path_buf()
}

/// Emit one `rerun-if-changed` per current canonical-domain member.
///
/// The directories are emitted too: a file *added* to or *removed* from the
/// domain changes the identity, and only a directory dependency invalidates a
/// warm cache for that.
fn emit_rerun_lines(root: &Path) {
    for name in [AUDITOR, MANIFEST, ATTESTATION] {
        println!("cargo:rerun-if-changed={}", root.join(name).display());
    }
    for name in CARGO_INPUTS {
        println!("cargo:rerun-if-changed={}", root.join(name).display());
    }
    for package in PACKAGE_ROOTS {
        let directory = root.join(package);
        println!("cargo:rerun-if-changed={}", directory.display());
        emit_rust_inputs(&directory);
    }
    println!("cargo:rerun-if-env-changed=FSRING_PYTHON");
}

fn emit_rust_inputs(directory: &Path) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            // `target` is generated output, never identity.
            if name == "target" || name == ".git" {
                continue;
            }
            println!("cargo:rerun-if-changed={}", path.display());
            emit_rust_inputs(&path);
        } else if name.ends_with(".rs") {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn python() -> String {
    std::env::var("FSRING_PYTHON").unwrap_or_else(|_| "python".to_string())
}

/// Run the auditor's identity-only verification. Any nonzero exit is fatal.
fn verify_attestation(root: &Path) {
    let output = std::process::Command::new(python())
        .current_dir(root)
        .args([AUDITOR, "--manifest", MANIFEST, "--verify-attestation"])
        .output();
    let output = match output {
        Ok(output) => output,
        Err(error) => fail(&format!(
            "the production attestation could not be verified: {AUDITOR} failed to start ({error}). \
             A production build may not proceed without it."
        )),
    };
    if !output.status.success() {
        fail(&format!(
            "the production attestation is stale or missing.\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
}

/// The exact fields the witness carries, read out of the verified document.
struct Attested {
    profile: String,
    source_identity: String,
    manifest_sha256: String,
    auditor_sha256: String,
    row_count: usize,
    capabilities: AttestedRowCapabilities,
}

/// A deliberately tiny reader for the values this script embeds.
///
/// The auditor already refused the document unless its root keys are the exact
/// ordered set, so the shape is fixed by the time these values are read; a full
/// JSON parser would only add a dependency this crate does not have.
fn read_attested(root: &Path) -> Attested {
    let path = root.join(ATTESTATION);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => fail(&format!(
            "the verified attestation at {} could not be read: {error}",
            path.display()
        )),
    };
    let profile = string_field(&text, "profile");
    let required_gates = string_array_field(&text, "requiredGates");
    let required_properties = string_array_field(&text, "requiredProperties");
    let capabilities = parse_required_row_capabilities(
        &profile,
        required_gates.as_slice(),
        required_properties.as_slice(),
    )
    .unwrap_or_else(|error| {
        fail(&format!(
            "the verified attestation has an invalid capability bundle: {error:?}"
        ))
    });
    Attested {
        profile,
        source_identity: string_field(&text, "sourceIdentity"),
        manifest_sha256: string_field(&text, "manifestSha256"),
        auditor_sha256: string_field(&text, "auditorSha256"),
        row_count: text.matches("\"stdoutSha256\"").count(),
        capabilities,
    }
}

fn string_field(text: &str, key: &str) -> String {
    let needle = format!("\"{key}\": \"");
    let Some(start) = text.find(&needle) else {
        fail(&format!("the attestation has no {key} field"))
    };
    let rest = &text[start.saturating_add(needle.len())..];
    let Some(end) = rest.find('"') else {
        fail(&format!("the attestation's {key} field is unterminated"))
    };
    let value = &rest[..end];
    if value.is_empty() {
        fail(&format!("the attestation's {key} field is empty"));
    }
    // These are hex digests and a profile name; nothing else may reach a
    // generated Rust literal.
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        fail(&format!(
            "the attestation's {key} field is not a plain token"
        ));
    }
    value.to_string()
}

fn string_array_field<'text>(text: &'text str, key: &str) -> Vec<&'text str> {
    let needle = format!("\"{key}\"");
    let mut fields = text.match_indices(&needle);
    let Some((start, _)) = fields.next() else {
        fail(&format!("the attestation has no {key} field"))
    };
    if fields.next().is_some() {
        fail(&format!("the attestation repeats its {key} field"));
    }

    let bytes = text.as_bytes();
    let mut cursor = start.saturating_add(needle.len());
    skip_ascii_whitespace(bytes, &mut cursor);
    require_byte(bytes, &mut cursor, b':', key);
    skip_ascii_whitespace(bytes, &mut cursor);
    require_byte(bytes, &mut cursor, b'[', key);
    skip_ascii_whitespace(bytes, &mut cursor);

    let mut values = Vec::new();
    if bytes.get(cursor) == Some(&b']') {
        return values;
    }
    loop {
        require_byte(bytes, &mut cursor, b'"', key);
        let value_start = cursor;
        while let Some(&byte) = bytes.get(cursor) {
            if byte == b'"' {
                break;
            }
            if !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')) {
                fail(&format!(
                    "the attestation's {key} array contains a non-token value"
                ));
            }
            cursor = cursor.saturating_add(1);
        }
        if bytes.get(cursor) != Some(&b'"') || cursor == value_start {
            fail(&format!(
                "the attestation's {key} array contains an empty or unterminated value"
            ));
        }
        values.push(&text[value_start..cursor]);
        if values.len() > MAX_ATTESTED_REQUIRED_ROWS {
            fail(&format!(
                "the attestation's {key} array exceeds the bounded row limit"
            ));
        }
        cursor = cursor.saturating_add(1);
        skip_ascii_whitespace(bytes, &mut cursor);
        match bytes.get(cursor) {
            Some(b']') => break,
            Some(b',') => {
                cursor = cursor.saturating_add(1);
                skip_ascii_whitespace(bytes, &mut cursor);
                if bytes.get(cursor) == Some(&b']') {
                    fail(&format!(
                        "the attestation's {key} array has a trailing comma"
                    ));
                }
            }
            _ => fail(&format!(
                "the attestation's {key} array is not comma-delimited"
            )),
        }
    }
    values
}

fn skip_ascii_whitespace(bytes: &[u8], cursor: &mut usize) {
    while bytes.get(*cursor).is_some_and(u8::is_ascii_whitespace) {
        *cursor = cursor.saturating_add(1);
    }
}

fn require_byte(bytes: &[u8], cursor: &mut usize, expected: u8, key: &str) {
    if bytes.get(*cursor) != Some(&expected) {
        fail(&format!(
            "the attestation's {key} field has an invalid shape"
        ));
    }
    *cursor = cursor.saturating_add(1);
}

/// Hand the verified values to the compiler through the build environment.
///
/// Deliberately not a generated file included with `include!`: this crate
/// forbids `include!` and `#[path]` source inclusion and
/// `tests/extern_quarantine.rs` enforces that. It is also the stronger option —
/// `fsring-core` parses each value back with an in-crate `const fn`, so a
/// malformed digest, an unknown profile, or a zero row count is a
/// const-evaluation failure rather than generated text nobody re-checked.
fn emit_witness_env(attested: &Attested) {
    let Attested {
        profile,
        source_identity,
        manifest_sha256,
        auditor_sha256,
        row_count,
        capabilities,
    } = attested;
    println!("cargo:rustc-env=FSRING_C4_PROFILE={profile}");
    println!("cargo:rustc-env=FSRING_C4_SOURCE_SHA256={source_identity}");
    println!("cargo:rustc-env=FSRING_C4_MANIFEST_SHA256={manifest_sha256}");
    println!("cargo:rustc-env=FSRING_C4_AUDITOR_SHA256={auditor_sha256}");
    println!("cargo:rustc-env=FSRING_C4_ROWS={row_count}");
    println!(
        "cargo:rustc-env=FSRING_C4_CAPABILITIES={}",
        capabilities.bits()
    );
}

fn main() {
    let root = repo_root();
    emit_rerun_lines(&root);

    if std::env::var_os("CARGO_FEATURE_PRODUCTION_ATTESTED").is_none() {
        // Standalone core builds and the attestation's own property rows land
        // here. No auditor, no witness, no recursion.
        return;
    }

    verify_attestation(&root);
    let attested = read_attested(&root);
    if attested.row_count == 0 {
        fail("the verified attestation carries no rows");
    }
    emit_witness_env(&attested);
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED_R4_CUTOVER: AttestedRowCapabilities = AttestedRowCapabilities::TASK12_CUTOVER
        .union(AttestedRowCapabilities::TASK12_EXACT_DELETE)
        .union(AttestedRowCapabilities::R4_CUTOVER)
        .union(AttestedRowCapabilities::R5_STAGING);

    const CUTOVER_GATES: [&str; 3] = [TASK12_GATE, R4_CUTOVER_GATE, R5_GATE];

    #[test]
    fn canonical_r4_cutover_arrays_produce_the_four_required_capabilities() {
        assert_eq!(
            parse_required_row_capabilities("r4-cutover", &CUTOVER_GATES, &[TASK12_DELETE]),
            Ok(REQUIRED_R4_CUTOVER)
        );
    }

    #[test]
    fn a_missing_known_cutover_row_is_rejected() {
        assert_eq!(
            parse_required_row_capabilities(
                "r4-cutover",
                &[TASK12_GATE, R4_CUTOVER_GATE],
                &[TASK12_DELETE],
            ),
            Err(CapabilityParseError::MissingKnownRow(R5_GATE))
        );
    }

    #[test]
    fn a_duplicate_known_row_is_rejected() {
        assert_eq!(
            parse_required_row_capabilities(
                "r4-cutover",
                &[TASK12_GATE, R4_CUTOVER_GATE, R5_GATE, R5_GATE],
                &[TASK12_DELETE],
            ),
            Err(CapabilityParseError::DuplicateKnownRow(R5_GATE))
        );
    }

    /// The row the cutover *retires*. Carrying it would claim R4 is both live
    /// and unreachable in one artifact, so it is refused rather than ignored.
    #[test]
    fn the_retired_r4_staging_row_is_refused_by_the_cutover_profile() {
        assert_eq!(
            parse_required_row_capabilities(
                "r4-cutover",
                &[TASK12_GATE, R4_GATE, R4_CUTOVER_GATE, R5_GATE],
                &[TASK12_DELETE],
            ),
            Err(CapabilityParseError::ProfileInappropriateRow(R4_GATE))
        );
    }

    /// The mirror image: a predecessor profile may not borrow the cutover row.
    #[test]
    fn historical_profiles_refuse_the_cutover_row() {
        for profile in ["r3-cutover", "r4-stage", "r5-stage"] {
            let gates: Vec<&str> = match profile {
                "r3-cutover" => vec![TASK12_GATE, R4_CUTOVER_GATE],
                "r4-stage" => vec![TASK12_GATE, R4_GATE, R4_CUTOVER_GATE],
                _ => vec![TASK12_GATE, R4_GATE, R5_GATE, R4_CUTOVER_GATE],
            };
            assert_eq!(
                parse_historical_required_row_capabilities(profile, &gates, &[TASK12_DELETE]),
                Err(CapabilityParseError::ProfileInappropriateRow(
                    R4_CUTOVER_GATE
                )),
                "{profile} must not borrow the cutover row"
            );
        }
    }

    #[test]
    fn same_cardinality_substitution_cannot_satisfy_any_required_name() {
        for (missing, gates) in [
            (
                TASK12_GATE,
                ["substituted_task12_gate", R4_CUTOVER_GATE, R5_GATE],
            ),
            (
                R4_CUTOVER_GATE,
                [TASK12_GATE, "substituted_r4_cutover_gate", R5_GATE],
            ),
            (
                R5_GATE,
                [TASK12_GATE, R4_CUTOVER_GATE, "substituted_r5_gate"],
            ),
        ] {
            assert_eq!(
                parse_required_row_capabilities("r4-cutover", &gates, &[TASK12_DELETE]),
                Err(CapabilityParseError::MissingKnownRow(missing)),
                "a same-cardinality substitution must not stand in for {missing}"
            );
        }
        assert_eq!(
            parse_required_row_capabilities(
                "r4-cutover",
                &CUTOVER_GATES,
                &["substituted_task12_delete_property"],
            ),
            Err(CapabilityParseError::MissingKnownRow(TASK12_DELETE))
        );
    }

    #[test]
    fn a_required_name_in_the_wrong_gate_or_property_kind_is_missing() {
        assert_eq!(
            parse_required_row_capabilities(
                "r4-cutover",
                &["replacement_gate", R4_CUTOVER_GATE, R5_GATE],
                &[TASK12_DELETE, TASK12_GATE],
            ),
            Err(CapabilityParseError::MissingKnownRow(TASK12_GATE))
        );
        assert_eq!(
            parse_required_row_capabilities(
                "r4-cutover",
                &[TASK12_GATE, R4_CUTOVER_GATE, R5_GATE, TASK12_DELETE],
                &["replacement_property"],
            ),
            Err(CapabilityParseError::MissingKnownRow(TASK12_DELETE))
        );
    }

    #[test]
    fn an_unknown_profile_is_rejected_before_capabilities_are_emitted() {
        assert_eq!(
            parse_required_row_capabilities("r6-stage", &CUTOVER_GATES, &[TASK12_DELETE]),
            Err(CapabilityParseError::UnknownProfile)
        );
    }

    #[test]
    fn historical_test_profiles_parse_only_their_historical_bundles() {
        let r3 = AttestedRowCapabilities::TASK12_CUTOVER
            .union(AttestedRowCapabilities::TASK12_EXACT_DELETE);
        let r4 = r3.union(AttestedRowCapabilities::R4_STAGING);
        let r5 = r4.union(AttestedRowCapabilities::R5_STAGING);
        for (profile, gates) in [
            ("r3-cutover", vec![TASK12_GATE]),
            ("r4-stage", vec![TASK12_GATE, R4_GATE]),
            ("r5-stage", vec![TASK12_GATE, R4_GATE, R5_GATE]),
        ] {
            assert_eq!(
                parse_required_row_capabilities(profile, &gates, &[TASK12_DELETE]),
                Err(CapabilityParseError::UnknownProfile),
                "{profile} is retired and may not parse as the active bundle"
            );
        }
        assert_eq!(
            parse_historical_required_row_capabilities(
                "r3-cutover",
                &[TASK12_GATE],
                &[TASK12_DELETE],
            ),
            Ok(r3)
        );
        assert_eq!(
            parse_historical_required_row_capabilities(
                "r4-stage",
                &[TASK12_GATE, R4_GATE],
                &[TASK12_DELETE],
            ),
            Ok(r4)
        );
        assert_eq!(
            parse_historical_required_row_capabilities(
                "r5-stage",
                &[TASK12_GATE, R4_GATE, R5_GATE],
                &[TASK12_DELETE],
            ),
            Ok(r5)
        );
    }

    #[test]
    fn unrelated_verified_properties_are_tolerated() {
        assert_eq!(
            parse_required_row_capabilities(
                "r4-cutover",
                &[
                    TASK12_GATE,
                    R4_CUTOVER_GATE,
                    R5_GATE,
                    "an_unrelated_verified_gate"
                ],
                &[TASK12_DELETE, "an_unrelated_verified_property"],
            ),
            Ok(REQUIRED_R4_CUTOVER)
        );
    }
}
