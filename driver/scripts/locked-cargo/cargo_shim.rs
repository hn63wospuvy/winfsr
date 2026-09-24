// Copyright (c) FSRING contributors.
//
// This dependency-free executable is generated as `cargo.exe` by
// build_matrix.cmd. cargo-wdk 0.1.1 hard-codes `Command::new("cargo")` for its
// package build, so a native executable (not a .cmd file) must be first on
// PATH. The matrix validates the create-new attestation written below before it
// accepts either package build.

#![cfg(windows)]

use std::{
    env,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    process::Command,
};

const TOOLCHAIN: &str = "1.85.0";
const RUSTUP_PROXY_SOURCE_ENV: &str = "FSRING_RUSTUP_PROXY_SOURCE";
const RUSTUP_PROXY_SOURCE_HASH_ENV: &str = "FSRING_RUSTUP_PROXY_SOURCE_SHA256";
const RUSTUP_SELECTOR_DIR_ENV: &str = "FSRING_RUSTUP_SELECTOR_DIR";
const RUSTUP_SELECTOR_RUSTC_ENV: &str = "FSRING_RUSTUP_SELECTOR_RUSTC";
const RUSTUP_SELECTOR_RUSTC_HASH_ENV: &str = "FSRING_RUSTUP_SELECTOR_RUSTC_SHA256";
const REAL_CARGO_ENV: &str = "FSRING_REAL_CARGO";
const REAL_CARGO_HASH_ENV: &str = "FSRING_REAL_CARGO_SHA256";
const TOOLCHAIN_CARGO_ENV: &str = "FSRING_TOOLCHAIN_CARGO";
const TOOLCHAIN_CARGO_HASH_ENV: &str = "FSRING_TOOLCHAIN_CARGO_SHA256";
const RUSTC_ENV: &str = "FSRING_RUSTC";
const RUSTC_HASH_ENV: &str = "FSRING_RUSTC_SHA256";
const RUSTUP_HOME_ENV: &str = "FSRING_RUSTUP_HOME";
const TARGET_DIR_ENV: &str = "FSRING_LOCKED_CARGO_TARGET_DIR";
const TOOLCHAIN_ENV: &str = "FSRING_LOCKED_CARGO_TOOLCHAIN";
const ATTESTATION_ENV: &str = "FSRING_LOCKED_CARGO_ATTESTATION";
const NONCE_ENV: &str = "FSRING_LOCKED_CARGO_NONCE";
const MAX_ATTESTATION_BYTES: usize = 64 * 1024;
const MAX_ARGUMENTS: usize = 64;
const MAX_FIELD_UTF16_UNITS: usize = 2_048;
const MAX_TOTAL_UTF16_UNITS: usize = 8_192;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];
const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428A_2F98,
    0x7137_4491,
    0xB5C0_FBCF,
    0xE9B5_DBA5,
    0x3956_C25B,
    0x59F1_11F1,
    0x923F_82A4,
    0xAB1C_5ED5,
    0xD807_AA98,
    0x1283_5B01,
    0x2431_85BE,
    0x550C_7DC3,
    0x72BE_5D74,
    0x80DE_B1FE,
    0x9BDC_06A7,
    0xC19B_F174,
    0xE49B_69C1,
    0xEFBE_4786,
    0x0FC1_9DC6,
    0x240C_A1CC,
    0x2DE9_2C6F,
    0x4A74_84AA,
    0x5CB0_A9DC,
    0x76F9_88DA,
    0x983E_5152,
    0xA831_C66D,
    0xB003_27C8,
    0xBF59_7FC7,
    0xC6E0_0BF3,
    0xD5A7_9147,
    0x06CA_6351,
    0x1429_2967,
    0x27B7_0A85,
    0x2E1B_2138,
    0x4D2C_6DFC,
    0x5338_0D13,
    0x650A_7354,
    0x766A_0ABB,
    0x81C2_C92E,
    0x9272_2C85,
    0xA2BF_E8A1,
    0xA81A_664B,
    0xC24B_8B70,
    0xC76C_51A3,
    0xD192_E819,
    0xD699_0624,
    0xF40E_3585,
    0x106A_A070,
    0x19A4_C116,
    0x1E37_6C08,
    0x2748_774C,
    0x34B0_BCB5,
    0x391C_0CB3,
    0x4ED8_AA4A,
    0x5B9C_CA4F,
    0x682E_6FF3,
    0x748F_82EE,
    0x78A5_636F,
    0x84C8_7814,
    0x8CC7_0208,
    0x90BE_FFFA,
    0xA450_6CEB,
    0xBEF9_A3F7,
    0xC671_78F2,
];

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    byte_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: SHA256_INITIAL_STATE,
            buffer: [0; 64],
            buffer_len: 0,
            byte_len: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) -> Result<(), String> {
        self.byte_len = self
            .byte_len
            .checked_add(input.len() as u64)
            .ok_or_else(|| "LOCKED-CARGO: FAIL: SHA-256 byte length overflow.".to_string())?;
        if self.byte_len > u64::MAX / 8 {
            return Err("LOCKED-CARGO: FAIL: SHA-256 bit length overflow.".into());
        }

        if self.buffer_len != 0 {
            let copy_len = (64 - self.buffer_len).min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + copy_len]
                .copy_from_slice(&input[..copy_len]);
            self.buffer_len += copy_len;
            input = &input[copy_len..];
            if self.buffer_len < 64 {
                return Ok(());
            }
            let block = self.buffer;
            self.process_block(&block);
            self.buffer_len = 0;
        }

        while input.len() >= 64 {
            let block: &[u8; 64] = input[..64]
                .try_into()
                .expect("a 64-byte slice converts to a 64-byte array");
            self.process_block(block);
            input = &input[64..];
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_len = input.len();
        Ok(())
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        let mut words = [0u32; 64];
        for (index, bytes) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(
                bytes
                    .try_into()
                    .expect("a four-byte chunk converts to a four-byte array"),
            );
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(SHA256_ROUND_CONSTANTS[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    fn finish(mut self) -> [u8; 32] {
        let bit_len = self.byte_len * 8;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.process_block(&block);
            self.buffer = [0; 64];
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.process_block(&block);

        let mut digest = [0u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

fn encode_sha256(digest: [u8; 32]) -> String {
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02X}").expect("writing to String cannot fail");
    }
    encoded
}

fn required_env(name: &str) -> Result<OsString, String> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("LOCKED-CARGO: FAIL: {name} is required and must be nonempty."))
}

fn normalized_windows_path_units(path: &Path) -> Vec<u16> {
    const EXTENDED_PREFIX: &[u16] = &[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    const UNC_PREFIX: &[u16] = &[b'U' as u16, b'N' as u16, b'C' as u16, b'\\' as u16];

    let units: Vec<u16> = path.as_os_str().encode_wide().collect();
    let body = if units.starts_with(EXTENDED_PREFIX) {
        &units[EXTENDED_PREFIX.len()..]
    } else {
        &units
    };
    let mut normalized = if body.len() >= UNC_PREFIX.len()
        && body[..UNC_PREFIX.len()]
            .iter()
            .zip(UNC_PREFIX)
            .all(|(left, right)| {
                let folded = if (b'a' as u16..=b'z' as u16).contains(left) {
                    *left - (b'a' - b'A') as u16
                } else {
                    *left
                };
                folded == *right
            })
        && units.starts_with(EXTENDED_PREFIX)
    {
        let mut unc = vec![b'\\' as u16, b'\\' as u16];
        unc.extend_from_slice(&body[UNC_PREFIX.len()..]);
        unc
    } else {
        body.to_vec()
    };
    for unit in &mut normalized {
        if (b'A' as u16..=b'Z' as u16).contains(unit) {
            *unit += (b'a' - b'A') as u16;
        }
    }
    normalized
}

fn same_windows_path(left: &Path, right: &Path) -> bool {
    normalized_windows_path_units(left) == normalized_windows_path_units(right)
}

fn canonical_paths_match(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => same_windows_path(&left, &right),
        _ => false,
    }
}

fn validate_absolute_file(path: &Path, variable: &str) -> Result<(), String> {
    if !path.is_absolute()
        || !fs::metadata(path)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
    {
        return Err(format!(
            "LOCKED-CARGO: FAIL: {variable} must name an absolute existing file."
        ));
    }
    Ok(())
}

fn validate_absolute_directory(path: &Path, variable: &str) -> Result<(), String> {
    if !path.is_absolute()
        || !fs::metadata(path)
            .map(|metadata| metadata.is_dir())
            .unwrap_or(false)
    {
        return Err(format!(
            "LOCKED-CARGO: FAIL: {variable} must name an absolute existing directory."
        ));
    }
    Ok(())
}

fn validate_absolute_native_identity(
    path: &Path,
    variable: &str,
    require_directory: bool,
) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "LOCKED-CARGO: FAIL: {variable} must be an absolute normalized path."
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("LOCKED-CARGO: FAIL: cannot inspect {variable}: {error}"))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!(
            "LOCKED-CARGO: FAIL: {variable} must not be a reparse point."
        ));
    }
    if require_directory {
        if !metadata.is_dir() {
            return Err(format!(
                "LOCKED-CARGO: FAIL: {variable} must be a directory."
            ));
        }
    } else if !metadata.is_file() {
        return Err(format!(
            "LOCKED-CARGO: FAIL: {variable} must be a regular file."
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        format!("LOCKED-CARGO: FAIL: cannot resolve {variable} final path: {error}")
    })?;
    if !same_windows_path(path, &canonical) {
        return Err(format!(
            "LOCKED-CARGO: FAIL: {variable} final path escaped or was not normalized."
        ));
    }
    Ok(())
}

fn validate_selector_entry_names(names: &[OsString]) -> Result<(), String> {
    if names.len() != 2 {
        return Err(
            "LOCKED-CARGO: FAIL: selector directory must contain exactly two entries.".into(),
        );
    }
    let cargo_count = names
        .iter()
        .filter(|name| name.to_string_lossy().eq_ignore_ascii_case("cargo.exe"))
        .count();
    let rustc_count = names
        .iter()
        .filter(|name| name.to_string_lossy().eq_ignore_ascii_case("rustc.exe"))
        .count();
    if cargo_count != 1 || rustc_count != 1 {
        return Err(
            "LOCKED-CARGO: FAIL: selector entries must be distinct cargo.exe and rustc.exe.".into(),
        );
    }
    Ok(())
}

fn validate_selector_directory(directory: &Path) -> Result<(), String> {
    validate_absolute_native_identity(directory, "selector directory", true)?;
    let mut names = Vec::new();
    for entry in fs::read_dir(directory).map_err(|error| {
        format!("LOCKED-CARGO: FAIL: cannot enumerate selector directory: {error}")
    })? {
        let entry = entry.map_err(|error| {
            format!("LOCKED-CARGO: FAIL: cannot enumerate selector entry: {error}")
        })?;
        validate_absolute_native_identity(&entry.path(), "selector entry", false)?;
        names.push(entry.file_name());
    }
    validate_selector_entry_names(&names)?;
    validate_absolute_native_identity(directory, "selector directory", true)
}

fn validate_attestation_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err("LOCKED-CARGO: FAIL: attestation path must be an absolute file path.".into());
    }

    let parent = path.parent().ok_or_else(|| {
        "LOCKED-CARGO: FAIL: attestation path does not have a parent directory.".to_string()
    })?;
    let canonical_parent = fs::canonicalize(parent).map_err(|error| {
        format!("LOCKED-CARGO: FAIL: attestation parent is unavailable: {error}")
    })?;
    let executable = env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| format!("LOCKED-CARGO: FAIL: cannot identify the native shim: {error}"))?;
    let executable_parent = executable.parent().ok_or_else(|| {
        "LOCKED-CARGO: FAIL: native shim does not have a parent directory.".to_string()
    })?;

    if !same_windows_path(&canonical_parent, executable_parent) {
        return Err(
            "LOCKED-CARGO: FAIL: attestation must be beside the generated native shim.".into(),
        );
    }
    Ok(())
}

fn encode_utf16_hex(value: &OsStr, field: &str, total_units: &mut usize) -> Result<String, String> {
    let units: Vec<u16> = value
        .encode_wide()
        .take(MAX_FIELD_UTF16_UNITS + 1)
        .collect();
    if units.len() > MAX_FIELD_UTF16_UNITS {
        return Err(format!(
            "LOCKED-CARGO: FAIL: {field} exceeds {MAX_FIELD_UTF16_UNITS} UTF-16 units."
        ));
    }
    *total_units = total_units
        .checked_add(units.len())
        .ok_or_else(|| "LOCKED-CARGO: FAIL: attestation decoded-size overflow.".to_string())?;
    if *total_units > MAX_TOTAL_UTF16_UNITS {
        return Err(format!(
            "LOCKED-CARGO: FAIL: attestation exceeds {MAX_TOTAL_UTF16_UNITS} decoded UTF-16 units."
        ));
    }

    let mut encoded = String::with_capacity(units.len() * 4);
    for unit in units {
        use std::fmt::Write as _;
        write!(&mut encoded, "{unit:04X}").expect("writing to String cannot fail");
    }
    Ok(encoded)
}

fn validate_sha256(variable: &str, value: &OsStr) -> Result<String, String> {
    let value = value
        .to_str()
        .ok_or_else(|| format!("LOCKED-CARGO: FAIL: {variable} must be Unicode."))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        return Err(format!(
            "LOCKED-CARGO: FAIL: {variable} must be 64 uppercase hexadecimal digits."
        ));
    }
    Ok(value.to_owned())
}

fn file_sha256(path: &Path, variable: &str) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|error| {
        format!("LOCKED-CARGO: FAIL: cannot open {variable} for SHA-256: {error}")
    })?;
    let mut sha256 = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            format!("LOCKED-CARGO: FAIL: cannot read {variable} for SHA-256: {error}")
        })?;
        if count == 0 {
            break;
        }
        sha256.update(&buffer[..count])?;
    }
    Ok(encode_sha256(sha256.finish()))
}

fn verify_file_sha256(path: &Path, expected: &str, variable: &str) -> Result<(), String> {
    let actual = file_sha256(path, variable)?;
    if actual != expected {
        return Err(format!(
            "LOCKED-CARGO: FAIL: {variable} does not match its exact SHA-256."
        ));
    }
    Ok(())
}

struct SelectorClosure {
    rustup_source: PathBuf,
    rustup_source_hash: String,
    directory: PathBuf,
    cargo: PathBuf,
    cargo_hash: String,
    rustc: PathBuf,
    rustc_hash: String,
}

impl SelectorClosure {
    fn validate(&self) -> Result<(), String> {
        validate_absolute_native_identity(&self.rustup_source, RUSTUP_PROXY_SOURCE_ENV, false)?;
        validate_selector_directory(&self.directory)?;
        validate_absolute_native_identity(&self.cargo, REAL_CARGO_ENV, false)?;
        validate_absolute_native_identity(&self.rustc, RUSTUP_SELECTOR_RUSTC_ENV, false)?;

        if self
            .rustup_source
            .file_name()
            .map(|name| name.to_string_lossy().eq_ignore_ascii_case("rustup.exe"))
            != Some(true)
        {
            return Err(format!(
                "LOCKED-CARGO: FAIL: {RUSTUP_PROXY_SOURCE_ENV} must name rustup.exe."
            ));
        }
        if self
            .cargo
            .file_name()
            .map(|name| name.to_string_lossy().eq_ignore_ascii_case("cargo.exe"))
            != Some(true)
            || self.cargo.parent().is_none()
            || !same_windows_path(
                self.cargo.parent().expect("checked"),
                self.directory.as_path(),
            )
        {
            return Err(format!(
                "LOCKED-CARGO: FAIL: {REAL_CARGO_ENV} must be direct selector child cargo.exe."
            ));
        }
        if self
            .rustc
            .file_name()
            .map(|name| name.to_string_lossy().eq_ignore_ascii_case("rustc.exe"))
            != Some(true)
            || self.rustc.parent().is_none()
            || !same_windows_path(
                self.rustc.parent().expect("checked"),
                self.directory.as_path(),
            )
        {
            return Err(format!(
                "LOCKED-CARGO: FAIL: {RUSTUP_SELECTOR_RUSTC_ENV} must be direct selector child rustc.exe."
            ));
        }
        if self.rustup_source_hash != self.cargo_hash || self.rustup_source_hash != self.rustc_hash
        {
            return Err(
                "LOCKED-CARGO: FAIL: selector Cargo/rustc copies must retain the exact rustup.exe SHA-256."
                    .into(),
            );
        }

        verify_file_sha256(
            &self.rustup_source,
            &self.rustup_source_hash,
            RUSTUP_PROXY_SOURCE_ENV,
        )?;
        verify_file_sha256(&self.cargo, &self.cargo_hash, REAL_CARGO_ENV)?;
        verify_file_sha256(&self.rustc, &self.rustc_hash, RUSTUP_SELECTOR_RUSTC_ENV)?;

        validate_absolute_native_identity(&self.rustup_source, RUSTUP_PROXY_SOURCE_ENV, false)?;
        validate_selector_directory(&self.directory)?;
        validate_absolute_native_identity(&self.cargo, REAL_CARGO_ENV, false)?;
        validate_absolute_native_identity(&self.rustc, RUSTUP_SELECTOR_RUSTC_ENV, false)
    }
}

fn build_attestation(
    nonce: &OsStr,
    real_cargo: &Path,
    real_cargo_hash: &str,
    toolchain_cargo: &Path,
    toolchain_cargo_hash: &str,
    rustc: &Path,
    rustc_hash: &str,
    rustup_home: &Path,
    target_dir: &Path,
    final_arguments: &[OsString],
) -> Result<Vec<u8>, String> {
    use std::fmt::Write as _;

    if final_arguments.len() > MAX_ARGUMENTS {
        return Err(format!(
            "LOCKED-CARGO: FAIL: argument count exceeds {MAX_ARGUMENTS}."
        ));
    }
    let mut total_units = 0usize;
    let nonce = encode_utf16_hex(nonce, "nonce", &mut total_units)?;
    let real_cargo_path =
        encode_utf16_hex(real_cargo.as_os_str(), "real Cargo path", &mut total_units)?;
    let toolchain_cargo_path = encode_utf16_hex(
        toolchain_cargo.as_os_str(),
        "actual toolchain Cargo path",
        &mut total_units,
    )?;
    let rustc_path = encode_utf16_hex(rustc.as_os_str(), "rustc path", &mut total_units)?;
    let rustup_home = encode_utf16_hex(rustup_home.as_os_str(), "rustup home", &mut total_units)?;
    let target_dir =
        encode_utf16_hex(target_dir.as_os_str(), "target directory", &mut total_units)?;
    let toolchain = encode_utf16_hex(OsStr::new(TOOLCHAIN), "toolchain", &mut total_units)?;

    let mut encoded_arguments = Vec::with_capacity(final_arguments.len());
    for (index, argument) in final_arguments.iter().enumerate() {
        encoded_arguments.push((
            index,
            encode_utf16_hex(argument, &format!("argument {index}"), &mut total_units)?,
        ));
    }

    let mut payload = String::new();
    writeln!(&mut payload, "fsring-locked-cargo-attestation")
        .and_then(|_| writeln!(&mut payload, "format=2"))
        .and_then(|_| writeln!(&mut payload, "nonce_utf16={nonce}"))
        .and_then(|_| writeln!(&mut payload, "real_cargo_path_utf16={real_cargo_path}"))
        .and_then(|_| writeln!(&mut payload, "real_cargo_sha256={real_cargo_hash}"))
        .and_then(|_| {
            writeln!(
                &mut payload,
                "toolchain_cargo_path_utf16={toolchain_cargo_path}"
            )
        })
        .and_then(|_| {
            writeln!(
                &mut payload,
                "toolchain_cargo_sha256={toolchain_cargo_hash}"
            )
        })
        .and_then(|_| writeln!(&mut payload, "rustc_path_utf16={rustc_path}"))
        .and_then(|_| writeln!(&mut payload, "rustc_sha256={rustc_hash}"))
        .and_then(|_| writeln!(&mut payload, "rustup_home_utf16={rustup_home}"))
        .and_then(|_| writeln!(&mut payload, "target_dir_utf16={target_dir}"))
        .and_then(|_| writeln!(&mut payload, "toolchain_utf16={toolchain}"))
        .and_then(|_| writeln!(&mut payload, "argument_count={}", final_arguments.len()))
        .map_err(|error| format!("LOCKED-CARGO: FAIL: cannot format attestation: {error}"))?;

    for (index, argument) in encoded_arguments {
        writeln!(&mut payload, "argument_{index:04}_utf16={argument}")
            .map_err(|error| format!("LOCKED-CARGO: FAIL: cannot format attestation: {error}"))?;
    }

    let payload = payload.into_bytes();
    if payload.len() > MAX_ATTESTATION_BYTES {
        return Err(format!(
            "LOCKED-CARGO: FAIL: attestation exceeds {MAX_ATTESTATION_BYTES} bytes."
        ));
    }
    Ok(payload)
}

fn write_attestation(path: &Path, payload: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!(
                "LOCKED-CARGO: FAIL: create-new attestation refused {}: {error}",
                path.display()
            )
        })?;
    file.write_all(payload)
        .map_err(|error| format!("LOCKED-CARGO: FAIL: cannot write attestation: {error}"))?;
    file.flush()
        .map_err(|error| format!("LOCKED-CARGO: FAIL: cannot flush attestation: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("LOCKED-CARGO: FAIL: cannot sync attestation: {error}"))
}

fn reject_uncontrolled_environment() -> Result<(), String> {
    const FORBIDDEN_EXACT: &[&str] = &[
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTC_BOOTSTRAP",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "CARGO_BUILD_PROFILE",
        "CARGO_HOME",
        "RUSTDOC",
        "RUSTDOCFLAGS",
        "BINDGEN_EXTRA_CLANG_ARGS",
        "CC",
        "CXX",
        "AR",
        "RANLIB",
        "CFLAGS",
        "CXXFLAGS",
        "CL",
        "_CL_",
        "LINK",
        "_LINK_",
    ];
    for (name, value) in env::vars_os() {
        if value.is_empty() {
            continue;
        }
        let name = name.to_string_lossy().to_ascii_uppercase();
        if FORBIDDEN_EXACT.contains(&name.as_str())
            || (name.starts_with("CARGO_")
                && name != "CARGO_TARGET_DIR"
                && name != "CARGO_NET_OFFLINE")
            || (name.starts_with("CC_")
                || name.starts_with("CXX_")
                || name.starts_with("AR_")
                || name.starts_with("RANLIB_")
                || name.starts_with("CFLAGS_")
                || name.starts_with("CXXFLAGS_")
                || name.starts_with("BINDGEN_EXTRA_CLANG_ARGS_"))
        {
            return Err(format!(
                "LOCKED-CARGO: FAIL: uncontrolled build environment {name} is not permitted."
            ));
        }
    }
    Ok(())
}

fn run() -> Result<i32, String> {
    let real_cargo = PathBuf::from(required_env(REAL_CARGO_ENV)?);
    validate_absolute_file(&real_cargo, REAL_CARGO_ENV)?;
    let selected_cargo = PathBuf::from(required_env("CARGO")?);
    if !canonical_paths_match(&real_cargo, &selected_cargo) {
        return Err(format!(
            "LOCKED-CARGO: FAIL: CARGO must match exact {REAL_CARGO_ENV}."
        ));
    }

    let real_cargo_hash =
        validate_sha256(REAL_CARGO_HASH_ENV, &required_env(REAL_CARGO_HASH_ENV)?)?;
    verify_file_sha256(&real_cargo, &real_cargo_hash, REAL_CARGO_ENV)?;
    let selector = SelectorClosure {
        rustup_source: PathBuf::from(required_env(RUSTUP_PROXY_SOURCE_ENV)?),
        rustup_source_hash: validate_sha256(
            RUSTUP_PROXY_SOURCE_HASH_ENV,
            &required_env(RUSTUP_PROXY_SOURCE_HASH_ENV)?,
        )?,
        directory: PathBuf::from(required_env(RUSTUP_SELECTOR_DIR_ENV)?),
        cargo: real_cargo.clone(),
        cargo_hash: real_cargo_hash.clone(),
        rustc: PathBuf::from(required_env(RUSTUP_SELECTOR_RUSTC_ENV)?),
        rustc_hash: validate_sha256(
            RUSTUP_SELECTOR_RUSTC_HASH_ENV,
            &required_env(RUSTUP_SELECTOR_RUSTC_HASH_ENV)?,
        )?,
    };
    selector.validate()?;

    let toolchain_cargo = PathBuf::from(required_env(TOOLCHAIN_CARGO_ENV)?);
    validate_absolute_file(&toolchain_cargo, TOOLCHAIN_CARGO_ENV)?;
    let toolchain_cargo_hash = validate_sha256(
        TOOLCHAIN_CARGO_HASH_ENV,
        &required_env(TOOLCHAIN_CARGO_HASH_ENV)?,
    )?;
    verify_file_sha256(&toolchain_cargo, &toolchain_cargo_hash, TOOLCHAIN_CARGO_ENV)?;
    let rustc = PathBuf::from(required_env(RUSTC_ENV)?);
    validate_absolute_file(&rustc, RUSTC_ENV)?;
    let rustc_hash = validate_sha256(RUSTC_HASH_ENV, &required_env(RUSTC_HASH_ENV)?)?;
    verify_file_sha256(&rustc, &rustc_hash, RUSTC_ENV)?;
    let cargo_rustc = PathBuf::from(required_env("RUSTC")?);
    if !canonical_paths_match(&rustc, &cargo_rustc) {
        return Err(format!(
            "LOCKED-CARGO: FAIL: RUSTC must match exact {RUSTC_ENV}."
        ));
    }
    if rustc.parent().is_none()
        || toolchain_cargo.parent().is_none()
        || !canonical_paths_match(
            rustc.parent().expect("checked"),
            toolchain_cargo.parent().expect("checked"),
        )
    {
        return Err(
            "LOCKED-CARGO: FAIL: actual toolchain Cargo must be beside exact rustc.".into(),
        );
    }

    let rustup_home = PathBuf::from(required_env(RUSTUP_HOME_ENV)?);
    validate_absolute_directory(&rustup_home, RUSTUP_HOME_ENV)?;
    let selected_rustup_home = PathBuf::from(required_env("RUSTUP_HOME")?);
    if !canonical_paths_match(&rustup_home, &selected_rustup_home) {
        return Err(format!(
            "LOCKED-CARGO: FAIL: RUSTUP_HOME must match exact {RUSTUP_HOME_ENV}."
        ));
    }

    let target_dir = PathBuf::from(required_env(TARGET_DIR_ENV)?);
    validate_absolute_directory(&target_dir, TARGET_DIR_ENV)?;
    let cargo_target_dir = PathBuf::from(required_env("CARGO_TARGET_DIR")?);
    if !canonical_paths_match(&target_dir, &cargo_target_dir) {
        return Err(format!(
            "LOCKED-CARGO: FAIL: CARGO_TARGET_DIR must match exact {TARGET_DIR_ENV}."
        ));
    }

    let toolchain = required_env(TOOLCHAIN_ENV)?;
    if toolchain != OsStr::new(TOOLCHAIN) {
        return Err(format!(
            "LOCKED-CARGO: FAIL: {TOOLCHAIN_ENV} must be exactly {TOOLCHAIN}."
        ));
    }
    if required_env("RUSTUP_TOOLCHAIN")? != OsStr::new(TOOLCHAIN) {
        return Err("LOCKED-CARGO: FAIL: RUSTUP_TOOLCHAIN must be exactly 1.85.0.".into());
    }
    if required_env("CARGO_NET_OFFLINE")? != OsStr::new("true") {
        return Err("LOCKED-CARGO: FAIL: CARGO_NET_OFFLINE must be exactly true.".into());
    }
    reject_uncontrolled_environment()?;

    let original_arguments: Vec<OsString> = env::args_os().skip(1).collect();
    if original_arguments.first().map(OsString::as_os_str) != Some(OsStr::new("build")) {
        return Err(
            "LOCKED-CARGO: FAIL: only an exact first argument of build is permitted.".into(),
        );
    }
    if original_arguments.iter().any(|argument| {
        argument == OsStr::new("--locked")
            || argument == OsStr::new("--offline")
            || argument == OsStr::new("--target-dir")
            || argument
                .to_string_lossy()
                .to_ascii_lowercase()
                .starts_with("--target-dir=")
    }) {
        return Err(
            "LOCKED-CARGO: FAIL: caller-supplied lock/offline/target-dir flags are forbidden."
                .into(),
        );
    }

    let attestation_path = PathBuf::from(required_env(ATTESTATION_ENV)?);
    validate_attestation_path(&attestation_path)?;
    let nonce = required_env(NONCE_ENV)?;

    let mut final_arguments = Vec::with_capacity(original_arguments.len() + 5);
    final_arguments.push(OsString::from(format!("+{TOOLCHAIN}")));
    final_arguments.extend(original_arguments);
    final_arguments.push(OsString::from("--target-dir"));
    final_arguments.push(target_dir.as_os_str().to_owned());
    final_arguments.push(OsString::from("--locked"));
    final_arguments.push(OsString::from("--offline"));

    let attestation = build_attestation(
        &nonce,
        &real_cargo,
        &real_cargo_hash,
        &toolchain_cargo,
        &toolchain_cargo_hash,
        &rustc,
        &rustc_hash,
        &rustup_home,
        &target_dir,
        &final_arguments,
    )?;
    write_attestation(&attestation_path, &attestation)?;

    selector.validate()?;
    let mut child = Command::new(&real_cargo)
        .args(&final_arguments)
        .spawn()
        .map_err(|error| {
            format!(
                "LOCKED-CARGO: FAIL: cannot spawn exact real Cargo {}: {error}",
                real_cargo.display()
            )
        })?;
    if let Err(selector_error) = selector.validate() {
        let _ = child.kill();
        let reap_error = child.wait().err();
        return Err(match reap_error {
            Some(error) => format!(
                "{selector_error} LOCKED-CARGO: FAIL: contaminated child could not be reaped: {error}"
            ),
            None => selector_error,
        });
    }
    let wait_result = child.wait();
    selector.validate()?;
    let status = wait_result.map_err(|error| {
        format!(
            "LOCKED-CARGO: FAIL: cannot wait for exact real Cargo {}: {error}",
            real_cargo.display()
        )
    })?;
    Ok(status.code().unwrap_or(1))
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod sha256_tests {
    use super::{
        encode_sha256, normalized_windows_path_units, validate_selector_directory,
        validate_selector_entry_names, Sha256,
    };
    use std::{
        env,
        ffi::OsString,
        fs,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        time::{SystemTime, UNIX_EPOCH},
    };

    struct TestRoot(PathBuf);

    impl Drop for TestRoot {
        fn drop(&mut self) {
            assert!(
                self.0.starts_with(env::temp_dir()),
                "test cleanup escaped the temporary directory"
            );
            if self.0.exists() {
                fs::remove_dir_all(&self.0).expect("remove selector test root");
            }
        }
    }

    fn test_root(name: &str) -> TestRoot {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "fsring-r2-selector-{name}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create selector test root");
        TestRoot(root)
    }

    fn write_clean_selector(directory: &Path) {
        fs::create_dir_all(directory).expect("create selector directory");
        let executable = env::current_exe().expect("resolve test executable");
        fs::copy(&executable, directory.join("cargo.exe")).expect("copy cargo fixture");
        fs::copy(&executable, directory.join("rustc.exe")).expect("copy rustc fixture");
    }

    fn create_junction(link: &Path, target: &Path) {
        let status = Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("launch mklink");
        assert!(status.success(), "create test junction");
    }

    fn hash_parts(parts: &[&[u8]]) -> Result<String, String> {
        let mut sha256 = Sha256::new();
        for part in parts {
            sha256.update(part)?;
        }
        Ok(encode_sha256(sha256.finish()))
    }

    #[test]
    fn matches_empty_and_abc_known_vectors() {
        assert_eq!(
            hash_parts(&[b""]).unwrap(),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
        assert_eq!(
            hash_parts(&[b"abc"]).unwrap(),
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
    }

    #[test]
    fn matches_padding_boundary_vectors() {
        let vectors = [
            (
                55,
                "8963CC0AFD622CC7574AC2011F93A3059B3D65548A77542A1559E3D202E6AB00",
            ),
            (
                56,
                "6EA719CEFA4B31862035A7FA606B7CC3602F46231117D135CC7119B3C1412314",
            ),
            (
                63,
                "1B58D00F5B1FBD2A1884D666A2BE33C2FA7463DFF32CD60EF200C0F750A6B70F",
            ),
            (
                64,
                "D53EDA7A637C99CC7FB566D96E9FA109BF15C478410A3F5EB4D4C4E26CD081F6",
            ),
        ];
        for (length, expected) in vectors {
            let input = vec![b'A'; length];
            assert_eq!(hash_parts(&[&input]).unwrap(), expected, "length {length}");
        }
    }

    #[test]
    fn matches_multiblock_vector_across_streaming_boundaries() {
        let input = [b'A'; 128];
        let parts: [&[u8]; 6] = [
            &input[..1],
            &input[1..8],
            &input[8..56],
            &input[56..57],
            &input[57..64],
            &input[64..],
        ];
        assert_eq!(
            hash_parts(&parts).unwrap(),
            "B6AC3CC10386331C765F04F041C147D0F278F2AED8EAA021E2D0057FC6F6FF9E"
        );
    }

    #[test]
    fn rejects_sha256_bit_length_overflow() {
        let mut sha256 = Sha256::new();
        sha256.byte_len = u64::MAX / 8;
        assert_eq!(
            sha256.update(&[0]).unwrap_err(),
            "LOCKED-CARGO: FAIL: SHA-256 bit length overflow."
        );
    }

    #[test]
    fn normalizes_extended_drive_and_unc_paths_for_identity() {
        assert_eq!(
            normalized_windows_path_units(Path::new(r"\\?\C:\FsRing\SELECTOR")),
            normalized_windows_path_units(Path::new(r"c:\fsring\selector"))
        );
        assert_eq!(
            normalized_windows_path_units(Path::new(r"\\?\UNC\Server\Share\FsRing\SELECTOR")),
            normalized_windows_path_units(Path::new(r"\\server\share\fsring\selector"))
        );
    }

    #[test]
    fn selector_names_require_exact_distinct_cargo_and_rustc_entries() {
        assert!(validate_selector_entry_names(&[
            OsString::from("cargo.exe"),
            OsString::from("rustc.exe"),
        ])
        .is_ok());
        for rejected in [
            vec![OsString::from("cargo.exe")],
            vec![OsString::from("cargo.exe"), OsString::from("CARGO.EXE")],
            vec![OsString::from("cargo.exe"), OsString::from("wrong.exe")],
            vec![
                OsString::from("cargo.exe"),
                OsString::from("rustc.exe"),
                OsString::from("extra.dll"),
            ],
        ] {
            assert!(validate_selector_entry_names(&rejected).is_err());
        }
    }

    #[test]
    fn selector_directory_accepts_only_two_regular_entries() {
        let root = test_root("exact-entries");
        let selector = root.0.join("selector");
        write_clean_selector(&selector);
        validate_selector_directory(&selector).expect("accept exact selector");

        fs::write(selector.join("unapproved.dll"), b"not approved").expect("write unapproved DLL");
        assert!(validate_selector_directory(&selector).is_err());
        fs::remove_file(selector.join("unapproved.dll")).expect("remove unapproved DLL");

        fs::remove_file(selector.join("rustc.exe")).expect("remove rustc fixture");
        assert!(validate_selector_directory(&selector).is_err());
    }

    #[test]
    fn selector_directory_rejects_a_directory_entry() {
        let root = test_root("directory-entry");
        let selector = root.0.join("selector");
        write_clean_selector(&selector);
        fs::remove_file(selector.join("cargo.exe")).expect("remove cargo fixture");
        fs::create_dir(selector.join("cargo.exe")).expect("create directory entry");

        let error = validate_selector_directory(&selector).unwrap_err();
        assert!(error.contains("regular file"), "unexpected error: {error}");
    }

    #[test]
    fn selector_directory_rejects_a_reparse_leaf() {
        let root = test_root("reparse-leaf");
        let selector = root.0.join("selector");
        let target = root.0.join("junction-target");
        write_clean_selector(&selector);
        fs::remove_file(selector.join("cargo.exe")).expect("remove cargo fixture");
        fs::create_dir(&target).expect("create junction target");
        fs::write(target.join("sentinel.txt"), b"sentinel").expect("write sentinel");
        let link = selector.join("cargo.exe");
        create_junction(&link, &target);

        let error = validate_selector_directory(&selector).unwrap_err();
        assert!(error.contains("reparse"), "unexpected error: {error}");
        fs::remove_dir(&link).expect("remove exact junction");
        assert_eq!(
            fs::read(target.join("sentinel.txt")).expect("read sentinel"),
            b"sentinel"
        );
    }

    #[test]
    fn selector_directory_rejects_a_reparse_parent() {
        let root = test_root("reparse-parent");
        let outside = root.0.join("outside");
        let selector = outside.join("selector");
        write_clean_selector(&selector);
        let link = root.0.join("parent-link");
        create_junction(&link, &outside);

        let error = validate_selector_directory(&link.join("selector")).unwrap_err();
        assert!(error.contains("final path"), "unexpected error: {error}");
        fs::remove_dir(&link).expect("remove exact parent junction");
        assert!(selector.join("cargo.exe").is_file());
    }
}
