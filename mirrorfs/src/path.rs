use std::ffi::{OsStr, OsString};

use fsring_abi::validate::{completion_status, validate_stored_component_utf16};
use fsring_user::ProviderError;

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct Component {
    wide: Box<[u16]>,
    os: OsString,
    key: NormalizedName,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct NormalizedName(Box<[u16]>);

impl Component {
    pub(crate) fn key(&self) -> &NormalizedName {
        &self.key
    }

    pub(crate) fn as_os_str(&self) -> &OsStr {
        &self.os
    }
}

pub(crate) fn component_from_utf16le(bytes: &[u8]) -> Result<Component, ProviderError> {
    if validate_stored_component_utf16(bytes).is_err() {
        return Err(invalid_component());
    }

    let wide: Box<[u16]> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>()
        .into_boxed_slice();

    let os = os_string_from_wide(&wide);
    #[cfg(windows)]
    let key = NormalizedName(
        crate::windows::uppercase_invariant(&wide).map_err(|_| invalid_component())?,
    );
    #[cfg(not(windows))]
    let key = NormalizedName(ascii_case_key(&wide));
    Ok(Component { wide, os, key })
}

fn invalid_component() -> ProviderError {
    ProviderError::terminal(completion_status::DATA_ERROR)
}

#[cfg(windows)]
fn os_string_from_wide(wide: &[u16]) -> OsString {
    use std::os::windows::ffi::OsStringExt;

    OsString::from_wide(wide)
}

#[cfg(not(windows))]
fn os_string_from_wide(wide: &[u16]) -> OsString {
    OsString::from(String::from_utf16_lossy(wide))
}

// Pure non-Windows tests exercise only the approved ASCII normalization path;
// operational Windows builds use LCMapStringEx above.
#[cfg(not(windows))]
fn ascii_case_key(wide: &[u16]) -> Box<[u16]> {
    wide.iter()
        .copied()
        .map(|unit| {
            char::from_u32(u32::from(unit))
                .filter(char::is_ascii)
                .and_then(|value| value.to_uppercase().next())
                .and_then(|upper| u16::try_from(u32::from(upper)).ok())
                .unwrap_or(unit)
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

#[cfg(test)]
mod tests {
    use fsring_abi::validate::completion_status;

    use super::component_from_utf16le;

    fn utf16le(value: &str) -> Vec<u8> {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn utf16le_units(units: &[u16]) -> Vec<u8> {
        units.iter().copied().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn component_decodes_ordinary_unicode() {
        const UNICODE: &str = "Gr\u{fc}\u{df}e\u{732b}.txt";
        let expected: Vec<u16> = UNICODE.encode_utf16().collect();
        let component = component_from_utf16le(&utf16le(UNICODE)).unwrap();

        assert_eq!(component.wide.as_ref(), expected);
        assert_eq!(component.os.to_string_lossy(), UNICODE);
    }

    #[test]
    fn component_rejects_odd_byte_length() {
        let error = component_from_utf16le(&[b'a', 0, b'b']).unwrap_err();

        assert_eq!(error.status(), completion_status::DATA_ERROR);
    }

    #[test]
    fn component_rejects_empty_nul_separator_and_dot_names() {
        for invalid in ["", "a\0b", "a/b", "a\\b", ".", ".."] {
            let error = component_from_utf16le(&utf16le(invalid)).unwrap_err();
            assert_eq!(error.status(), completion_status::DATA_ERROR, "{invalid:?}");
        }
    }

    #[test]
    fn component_rejects_more_than_255_code_units() {
        let error = component_from_utf16le(&utf16le(&"a".repeat(256))).unwrap_err();

        assert_eq!(error.status(), completion_status::DATA_ERROR);
    }

    #[test]
    fn component_accepts_a_valid_surrogate_pair() {
        let units = [u16::from(b'a'), 0xd83d, 0xde00, u16::from(b'z')];
        let component = component_from_utf16le(&utf16le_units(&units)).unwrap();

        assert_eq!(component.wide.as_ref(), units);
    }

    #[test]
    fn component_rejects_unpaired_and_malformed_surrogates() {
        let invalid: &[(&str, &[u16])] = &[
            ("lone high surrogate", &[0xd800]),
            ("lone low surrogate", &[0xdc00]),
            (
                "high surrogate followed by a non-low unit",
                &[0xd800, u16::from(b'a')],
            ),
            ("reversed pair", &[0xdc00, 0xd800]),
            (
                "unclosed high before a valid pair",
                &[0xd800, 0xd800, 0xdc00],
            ),
        ];

        for (case, units) in invalid {
            let error = component_from_utf16le(&utf16le_units(units)).unwrap_err();
            assert_eq!(
                error.status(),
                completion_status::DATA_ERROR,
                "{case}: {units:x?}"
            );
        }
    }

    #[test]
    fn component_accepts_exactly_255_code_units() {
        let component = component_from_utf16le(&utf16le(&"a".repeat(255))).unwrap();

        assert_eq!(component.wide.len(), 255);
    }

    #[test]
    fn ascii_case_variants_have_the_same_normalized_key() {
        let mixed = component_from_utf16le(&utf16le("ReadMe.TXT")).unwrap();
        let lower = component_from_utf16le(&utf16le("readme.txt")).unwrap();

        assert_eq!(mixed.key, lower.key);
    }

    #[test]
    fn component_exposes_only_its_validated_owned_os_name() {
        let component = component_from_utf16le(&utf16le("child.txt")).unwrap();

        assert_eq!(component.as_os_str(), std::ffi::OsStr::new("child.txt"));
    }

    #[cfg(windows)]
    #[test]
    fn non_ascii_case_variants_use_windows_invariant_normalization() {
        let mixed = component_from_utf16le(&utf16le("Ångström.TXT")).unwrap();
        let lower = component_from_utf16le(&utf16le("ångström.txt")).unwrap();

        assert_eq!(mixed.key, lower.key);
    }
}
