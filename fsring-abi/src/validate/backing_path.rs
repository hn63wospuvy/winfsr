pub(crate) fn is_canonical_backing_device_path(path: &[u8]) -> bool {
    if path.len() % 2 != 0 || utf16_unit(path, 0) != Some(b'\\' as u16) {
        return false;
    }
    let unit_count = path.len() / 2;
    let mut index = 1usize;
    let mut component_count = 0usize;
    while index < unit_count {
        let component_start = index;
        while index < unit_count {
            let Some(unit) = utf16_unit(path, index) else {
                return false;
            };
            if unit == b'\\' as u16 {
                break;
            }
            if unit == 0 || unit == b'/' as u16 || unit == b':' as u16 {
                return false;
            }
            if (0xd800..=0xdbff).contains(&unit) {
                let Some(low) = utf16_unit(path, index + 1) else {
                    return false;
                };
                if !(0xdc00..=0xdfff).contains(&low) {
                    return false;
                }
                index += 2;
            } else {
                if (0xdc00..=0xdfff).contains(&unit) {
                    return false;
                }
                index += 1;
            }
        }
        if component_start == index {
            return false;
        }
        if component_count == 0 {
            if !utf16_component_eq_ascii(path, component_start, index, b"Device") {
                return false;
            }
        } else if utf16_component_is_dot(path, component_start, index) {
            return false;
        }
        component_count += 1;
        if index == unit_count {
            break;
        }
        index += 1;
        if index == unit_count {
            return false;
        }
    }
    component_count >= 2
}

fn utf16_unit(path: &[u8], index: usize) -> Option<u16> {
    let offset = index.checked_mul(2)?;
    let low = *path.get(offset)?;
    let high = *path.get(offset.checked_add(1)?)?;
    Some(u16::from_le_bytes([low, high]))
}

fn utf16_component_eq_ascii(path: &[u8], start: usize, end: usize, expected: &[u8]) -> bool {
    if end.checked_sub(start) != Some(expected.len()) {
        return false;
    }
    let mut relative = 0usize;
    while relative < expected.len() {
        let Some(unit) = utf16_unit(path, start + relative) else {
            return false;
        };
        if unit > 0x7f || ascii_lower(unit as u8) != ascii_lower(expected[relative]) {
            return false;
        }
        relative += 1;
    }
    true
}

fn ascii_lower(value: u8) -> u8 {
    if value.is_ascii_uppercase() {
        value + (b'a' - b'A')
    } else {
        value
    }
}

fn utf16_component_is_dot(path: &[u8], start: usize, end: usize) -> bool {
    let length = end - start;
    (length == 1 && utf16_unit(path, start) == Some(b'.' as u16))
        || (length == 2
            && utf16_unit(path, start) == Some(b'.' as u16)
            && utf16_unit(path, start + 1) == Some(b'.' as u16))
}
