//! Two rules this slice makes checkable rather than merely written down.
//!
//! 1. **Every hand-written `extern` block lives in `fsring-sys`.** That is what
//!    gives the import audit and its allowlists exactly one place to look; a
//!    stray `extern` in `fsring-fsd` would add an import nobody reviewed.
//! 2. **`RtlRandom` and `RtlRandomEx` appear nowhere.**
//!    `11-rust-implementation.md` section 4 forbids them as entropy in the same
//!    sentence that mandates `BCryptGenRandom` — and `wdk-sys` binds them while
//!    the compliant source is absent, so the forbidden one is one keystroke
//!    away. A rule that is only written down is not a rule.
//!
//! Those two legacy rules are line-based text scans with the same honest limits
//! as `fsring_core::allowscan`: they cannot understand `cfg` or macros. The C4
//! checks below use balanced C-parameter and identifier token scans where a
//! line-based match could confuse a prototype, alias, or multiline call.

/// A line that opens an FFI **block**.
///
/// Deliberately not "any line with `extern`": `extern "system" fn driver_entry`
/// and `extern "C" fn driver_unload` are function *definitions* with a calling
/// convention — an export and a callback — not imports of foreign symbols. The
/// first run of this test flagged both, which is what taught the distinction.
fn is_extern_block(line: &str) -> bool {
    let t = line.trim_start();
    let t = t.strip_prefix("pub ").unwrap_or(t);
    let t = t.strip_prefix("unsafe ").unwrap_or(t);
    t.starts_with("extern \"") && t.contains('{') && !t.contains("fn ")
}

/// A line that reaches for a forbidden randomness routine **in code**.
///
/// Comment lines are exempt: this project's own documentation names
/// `RtlRandom*` in order to forbid it, in four places including this file. A
/// scanner that flagged prose would punish exactly the behaviour it wants.
fn mentions_forbidden_random(line: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with("//") {
        return false;
    }
    t.contains("RtlRandomEx") || t.contains("RtlRandom")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RustCodeToken<'a> {
    Identifier(&'a str),
    Punctuation(u8),
}

fn matching_rust_delimiter(open: u8) -> Option<u8> {
    match open {
        b'(' => Some(b')'),
        b'[' => Some(b']'),
        b'{' => Some(b'}'),
        _ => None,
    }
}

fn skip_rust_nested_block_comment(bytes: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start.saturating_add(2);
    let mut depth = 1usize;
    while cursor < bytes.len() {
        if bytes.get(cursor..cursor.saturating_add(2)) == Some(b"/*") {
            depth = depth.saturating_add(1);
            cursor = cursor.saturating_add(2);
        } else if bytes.get(cursor..cursor.saturating_add(2)) == Some(b"*/") {
            depth = depth.checked_sub(1)?;
            cursor = cursor.saturating_add(2);
            if depth == 0 {
                return Some(cursor);
            }
        } else {
            cursor = cursor.saturating_add(1);
        }
    }
    None
}

fn skip_rust_quoted_literal(bytes: &[u8], quote: usize, allow_newline: bool) -> Option<usize> {
    let mut cursor = quote.saturating_add(1);
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            cursor = cursor.saturating_add(2);
        } else if bytes[cursor] == bytes[quote] {
            return Some(cursor.saturating_add(1));
        } else if bytes[cursor] == b'\n' && !allow_newline {
            return None;
        } else {
            cursor = cursor.saturating_add(1);
        }
    }
    None
}

fn rust_raw_string_open(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut cursor = if bytes.get(start) == Some(&b'r') {
        start.saturating_add(1)
    } else if matches!(
        bytes.get(start..start.saturating_add(2)),
        Some(b"br" | b"cr")
    ) {
        start.saturating_add(2)
    } else {
        return None;
    };
    let hashes_start = cursor;
    while bytes.get(cursor) == Some(&b'#') {
        cursor = cursor.saturating_add(1);
    }
    (bytes.get(cursor) == Some(&b'"')).then_some((cursor, cursor.saturating_sub(hashes_start)))
}

fn skip_rust_raw_string(bytes: &[u8], quote: usize, hashes: usize) -> Option<usize> {
    let mut cursor = quote.saturating_add(1);
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            let hashes_end = cursor.saturating_add(1).saturating_add(hashes);
            if hashes_end <= bytes.len()
                && bytes
                    .get(cursor.saturating_add(1)..hashes_end)
                    .is_some_and(|tail| tail.iter().all(|byte| *byte == b'#'))
            {
                return Some(hashes_end);
            }
        }
        cursor = cursor.saturating_add(1);
    }
    None
}

fn rust_character_literal_end(bytes: &[u8], quote: usize) -> Result<Option<usize>, ()> {
    let Some(first) = bytes.get(quote.saturating_add(1)).copied() else {
        return Err(());
    };
    if first == b'\\' {
        return skip_rust_quoted_literal(bytes, quote, false)
            .map(Some)
            .ok_or(());
    }
    if matches!(first, b'\n' | b'\r' | b'\'') {
        return Err(());
    }
    let width = match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => return Err(()),
    };
    let closing = quote.saturating_add(1).saturating_add(width);
    Ok((bytes.get(closing) == Some(&b'\'')).then_some(closing.saturating_add(1)))
}

fn rust_literal_end(bytes: &[u8], start: usize) -> Result<Option<usize>, ()> {
    if let Some((quote, hashes)) = rust_raw_string_open(bytes, start) {
        return skip_rust_raw_string(bytes, quote, hashes)
            .map(Some)
            .ok_or(());
    }
    if matches!(
        bytes.get(start..start.saturating_add(2)),
        Some(b"b\"" | b"c\"")
    ) {
        return skip_rust_quoted_literal(bytes, start.saturating_add(1), true)
            .map(Some)
            .ok_or(());
    }
    if bytes.get(start..start.saturating_add(2)) == Some(b"b'") {
        return skip_rust_quoted_literal(bytes, start.saturating_add(1), false)
            .map(Some)
            .ok_or(());
    }
    if bytes.get(start) == Some(&b'"') {
        return skip_rust_quoted_literal(bytes, start, true)
            .map(Some)
            .ok_or(());
    }
    if bytes.get(start) == Some(&b'\'') {
        return rust_character_literal_end(bytes, start);
    }
    Ok(None)
}

fn skip_rust_trivia(bytes: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start;
    loop {
        while bytes
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            cursor = cursor.saturating_add(1);
        }
        if bytes.get(cursor..cursor.saturating_add(2)) == Some(b"//") {
            cursor = cursor.saturating_add(2);
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor = cursor.saturating_add(1);
            }
        } else if bytes.get(cursor..cursor.saturating_add(2)) == Some(b"/*") {
            cursor = skip_rust_nested_block_comment(bytes, cursor)?;
        } else {
            return Some(cursor);
        }
    }
}

fn skip_balanced_rust_group(bytes: &[u8], open: usize) -> Option<usize> {
    let mut expected = vec![matching_rust_delimiter(*bytes.get(open)?)?];
    let mut cursor = open.saturating_add(1);
    while cursor < bytes.len() {
        cursor = skip_rust_trivia(bytes, cursor)?;
        if cursor >= bytes.len() {
            break;
        }
        if let Some(after_literal) = rust_literal_end(bytes, cursor).ok()? {
            cursor = after_literal;
            continue;
        }
        if let Some(close) = matching_rust_delimiter(bytes[cursor]) {
            expected.push(close);
            cursor = cursor.saturating_add(1);
            continue;
        }
        if matches!(bytes[cursor], b')' | b']' | b'}') {
            if expected.pop() != Some(bytes[cursor]) {
                return None;
            }
            cursor = cursor.saturating_add(1);
            if expected.is_empty() {
                return Some(cursor);
            }
            continue;
        }
        cursor = cursor.saturating_add(1);
    }
    None
}

fn rust_identifier_at(source: &str, start: usize) -> Option<(&str, usize)> {
    let bytes = source.as_bytes();
    let identifier_start = if bytes.get(start..start.saturating_add(2)) == Some(b"r#")
        && bytes
            .get(start.saturating_add(2))
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        start.saturating_add(2)
    } else {
        start
    };
    if !bytes
        .get(identifier_start)
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        return None;
    }
    let mut end = identifier_start.saturating_add(1);
    while bytes
        .get(end)
        .is_some_and(|byte| is_c_identifier_byte(*byte))
    {
        end = end.saturating_add(1);
    }
    Some((source.get(identifier_start..end)?, end))
}

fn rust_code_tokens(source: &str) -> Option<Vec<RustCodeToken<'_>>> {
    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    let mut expected = Vec::new();
    let mut tokens = Vec::new();

    while cursor < bytes.len() {
        cursor = skip_rust_trivia(bytes, cursor)?;
        if cursor >= bytes.len() {
            break;
        }
        if let Some(after_literal) = rust_literal_end(bytes, cursor).ok()? {
            cursor = after_literal;
            continue;
        }
        if bytes[cursor] == b'#' {
            let mut group = skip_rust_trivia(bytes, cursor.saturating_add(1))?;
            if bytes.get(group) == Some(&b'!') {
                group = skip_rust_trivia(bytes, group.saturating_add(1))?;
            }
            if bytes.get(group) == Some(&b'[') {
                cursor = skip_balanced_rust_group(bytes, group)?;
                continue;
            }
        }
        if let Some((identifier, after_identifier)) = rust_identifier_at(source, cursor) {
            tokens.push(RustCodeToken::Identifier(identifier));
            cursor = after_identifier;
            continue;
        }
        if bytes[cursor] == b'!' {
            let previous = match tokens.last() {
                Some(RustCodeToken::Identifier(identifier)) => Some(*identifier),
                _ => None,
            };
            if let Some(previous) = previous {
                let mut group = skip_rust_trivia(bytes, cursor.saturating_add(1))?;
                if previous == "macro_rules" {
                    let (_, after_name) = rust_identifier_at(source, group)?;
                    group = skip_rust_trivia(bytes, after_name)?;
                }
                if bytes
                    .get(group)
                    .and_then(|open| matching_rust_delimiter(*open))
                    .is_some()
                {
                    cursor = skip_balanced_rust_group(bytes, group)?;
                    continue;
                }
                if previous == "macro_rules" {
                    return None;
                }
            }
        }
        if let Some(close) = matching_rust_delimiter(bytes[cursor]) {
            expected.push(close);
        } else if matches!(bytes[cursor], b')' | b']' | b'}')
            && expected.pop() != Some(bytes[cursor])
        {
            return None;
        }
        tokens.push(RustCodeToken::Punctuation(bytes[cursor]));
        cursor = cursor.saturating_add(1);
    }

    expected.is_empty().then_some(tokens)
}

fn is_reserved_c4_rust_identifier(identifier: &str) -> bool {
    matches!(
        identifier,
        "MmProbeAndLockPages"
            | "MmMapLockedPagesSpecifyCache"
            | "FsRingProbeAndLockPagesSeh"
            | "FsRingMapLockedPagesSeh"
    )
}

fn scan_rust_macro_group(source: &str, open: usize) -> Option<(usize, Option<&str>)> {
    let bytes = source.as_bytes();
    let mut expected = vec![matching_rust_delimiter(*bytes.get(open)?)?];
    let mut cursor = open.saturating_add(1);
    let mut offender = None;

    while cursor < bytes.len() {
        cursor = skip_rust_trivia(bytes, cursor)?;
        if cursor >= bytes.len() {
            break;
        }
        if let Some(after_literal) = rust_literal_end(bytes, cursor).ok()? {
            cursor = after_literal;
            continue;
        }
        if let Some((identifier, after_identifier)) = rust_identifier_at(source, cursor) {
            if offender.is_none() && is_reserved_c4_rust_identifier(identifier) {
                offender = Some(identifier);
            }
            cursor = after_identifier;
            continue;
        }
        if let Some(close) = matching_rust_delimiter(bytes[cursor]) {
            expected.push(close);
            cursor = cursor.saturating_add(1);
            continue;
        }
        if matches!(bytes[cursor], b')' | b']' | b'}') {
            if expected.pop() != Some(bytes[cursor]) {
                return None;
            }
            cursor = cursor.saturating_add(1);
            if expected.is_empty() {
                return Some((cursor, offender));
            }
            continue;
        }
        cursor = cursor.saturating_add(1);
    }
    None
}

fn rust_macro_context_c4_offender(source: &str) -> Option<Option<&str>> {
    rust_code_tokens(source)?;

    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    let mut previous_identifier = None;
    let mut offender = None;
    while cursor < bytes.len() {
        cursor = skip_rust_trivia(bytes, cursor)?;
        if cursor >= bytes.len() {
            break;
        }
        if let Some(after_literal) = rust_literal_end(bytes, cursor).ok()? {
            previous_identifier = None;
            cursor = after_literal;
            continue;
        }
        if let Some((identifier, after_identifier)) = rust_identifier_at(source, cursor) {
            previous_identifier = Some(identifier);
            cursor = after_identifier;
            continue;
        }
        if bytes[cursor] == b'!' {
            if let Some(previous) = previous_identifier {
                let mut group = skip_rust_trivia(bytes, cursor.saturating_add(1))?;
                if previous == "macro_rules" {
                    let (_, after_name) = rust_identifier_at(source, group)?;
                    group = skip_rust_trivia(bytes, after_name)?;
                }
                if bytes
                    .get(group)
                    .and_then(|open| matching_rust_delimiter(*open))
                    .is_some()
                {
                    let (after_group, group_offender) = scan_rust_macro_group(source, group)?;
                    offender = offender.or(group_offender);
                    previous_identifier = None;
                    cursor = after_group;
                    continue;
                }
                if previous == "macro_rules" {
                    return None;
                }
            }
        }
        previous_identifier = None;
        cursor = cursor.saturating_add(1);
    }
    Some(offender)
}

fn is_reserved_c4_build_identifier(identifier: &str) -> bool {
    matches!(
        identifier,
        "cc" | "Build"
            | "build"
            | "new"
            | "include"
            | "define"
            | "file"
            | "files"
            | "object"
            | "objects"
            | "flag"
            | "flags"
            | "flag_if_supported"
            | "compiler"
            | "cpp"
            | "cargo_metadata"
            | "compile"
            | "OUT_DIR"
    )
}

fn scan_rust_build_macro_group(source: &str, open: usize) -> Option<(usize, Option<&str>)> {
    let bytes = source.as_bytes();
    let mut expected = vec![matching_rust_delimiter(*bytes.get(open)?)?];
    let mut cursor = open.saturating_add(1);
    let mut offender = None;

    while cursor < bytes.len() {
        cursor = skip_rust_trivia(bytes, cursor)?;
        if cursor >= bytes.len() {
            break;
        }
        if let Some(after_literal) = rust_literal_end(bytes, cursor).ok()? {
            cursor = after_literal;
            continue;
        }
        if let Some((identifier, after_identifier)) = rust_identifier_at(source, cursor) {
            if offender.is_none() && is_reserved_c4_build_identifier(identifier) {
                offender = Some(identifier);
            }
            cursor = after_identifier;
            continue;
        }
        if let Some(close) = matching_rust_delimiter(bytes[cursor]) {
            expected.push(close);
            cursor = cursor.saturating_add(1);
            continue;
        }
        if matches!(bytes[cursor], b')' | b']' | b'}') {
            if expected.pop() != Some(bytes[cursor]) {
                return None;
            }
            cursor = cursor.saturating_add(1);
            if expected.is_empty() {
                return Some((cursor, offender));
            }
            continue;
        }
        cursor = cursor.saturating_add(1);
    }
    None
}

fn rust_build_macro_context_offender(source: &str) -> Option<Option<&str>> {
    rust_code_tokens(source)?;

    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    let mut previous_identifier = None;
    let mut offender = None;
    while cursor < bytes.len() {
        cursor = skip_rust_trivia(bytes, cursor)?;
        if cursor >= bytes.len() {
            break;
        }
        if let Some(after_literal) = rust_literal_end(bytes, cursor).ok()? {
            previous_identifier = None;
            cursor = after_literal;
            continue;
        }
        if let Some((identifier, after_identifier)) = rust_identifier_at(source, cursor) {
            previous_identifier = Some(identifier);
            cursor = after_identifier;
            continue;
        }
        if bytes[cursor] == b'!' {
            if let Some(previous) = previous_identifier {
                let mut group = skip_rust_trivia(bytes, cursor.saturating_add(1))?;
                if previous == "macro_rules" {
                    let (_, after_name) = rust_identifier_at(source, group)?;
                    group = skip_rust_trivia(bytes, after_name)?;
                }
                if bytes
                    .get(group)
                    .and_then(|open| matching_rust_delimiter(*open))
                    .is_some()
                {
                    let (after_group, group_offender) = scan_rust_build_macro_group(source, group)?;
                    offender = offender.or(group_offender);
                    previous_identifier = None;
                    cursor = after_group;
                    continue;
                }
                if previous == "macro_rules" {
                    return None;
                }
            }
        }
        previous_identifier = None;
        cursor = cursor.saturating_add(1);
    }
    Some(offender)
}

fn rust_attribute_context_c4_offender(source: &str) -> Option<Option<&str>> {
    rust_code_tokens(source)?;

    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    let mut offender = None;
    while cursor < bytes.len() {
        cursor = skip_rust_trivia(bytes, cursor)?;
        if cursor >= bytes.len() {
            break;
        }
        if let Some(after_literal) = rust_literal_end(bytes, cursor).ok()? {
            cursor = after_literal;
            continue;
        }
        if bytes[cursor] == b'#' {
            let mut group = skip_rust_trivia(bytes, cursor.saturating_add(1))?;
            if bytes.get(group) == Some(&b'!') {
                group = skip_rust_trivia(bytes, group.saturating_add(1))?;
            }
            if bytes.get(group) == Some(&b'[') {
                let (after_group, group_offender) = scan_rust_macro_group(source, group)?;
                offender = offender.or(group_offender);
                cursor = after_group;
                continue;
            }
        }
        cursor = cursor.saturating_add(1);
    }
    Some(offender)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RustSourceClosureOffender {
    IncludeMacro,
    PathAttribute,
}

fn scan_rust_attribute_group_for_assignment(
    source: &str,
    open: usize,
    assignment_identifier: &str,
) -> Option<(usize, bool)> {
    let bytes = source.as_bytes();
    let mut expected = vec![matching_rust_delimiter(*bytes.get(open)?)?];
    let mut cursor = open.saturating_add(1);
    let mut has_assignment = false;

    while cursor < bytes.len() {
        cursor = skip_rust_trivia(bytes, cursor)?;
        if cursor >= bytes.len() {
            break;
        }
        if let Some(after_literal) = rust_literal_end(bytes, cursor).ok()? {
            cursor = after_literal;
            continue;
        }
        if let Some((identifier, after_identifier)) = rust_identifier_at(source, cursor) {
            if identifier == assignment_identifier
                && bytes.get(skip_rust_trivia(bytes, after_identifier)?) == Some(&b'=')
            {
                has_assignment = true;
            }
            cursor = after_identifier;
            continue;
        }
        if let Some(close) = matching_rust_delimiter(bytes[cursor]) {
            expected.push(close);
            cursor = cursor.saturating_add(1);
            continue;
        }
        if matches!(bytes[cursor], b')' | b']' | b'}') {
            if expected.pop() != Some(bytes[cursor]) {
                return None;
            }
            cursor = cursor.saturating_add(1);
            if expected.is_empty() {
                return Some((cursor, has_assignment));
            }
            continue;
        }
        cursor = cursor.saturating_add(1);
    }
    None
}

fn rust_source_closure_offender(source: &str) -> Option<Option<RustSourceClosureOffender>> {
    rust_code_tokens(source)?;

    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        cursor = skip_rust_trivia(bytes, cursor)?;
        if cursor >= bytes.len() {
            break;
        }
        if let Some(after_literal) = rust_literal_end(bytes, cursor).ok()? {
            cursor = after_literal;
            continue;
        }
        if bytes[cursor] == b'#' {
            let mut group = skip_rust_trivia(bytes, cursor.saturating_add(1))?;
            if bytes.get(group) == Some(&b'!') {
                group = skip_rust_trivia(bytes, group.saturating_add(1))?;
            }
            if bytes.get(group) == Some(&b'[') {
                let (_, has_path_assignment) =
                    scan_rust_attribute_group_for_assignment(source, group, "path")?;
                if has_path_assignment {
                    return Some(Some(RustSourceClosureOffender::PathAttribute));
                }
            }
        }
        if let Some((identifier, after_identifier)) = rust_identifier_at(source, cursor) {
            if identifier == "include" {
                let bang = skip_rust_trivia(bytes, after_identifier)?;
                if bytes.get(bang) == Some(&b'!') {
                    let group = skip_rust_trivia(bytes, bang.saturating_add(1))?;
                    if bytes
                        .get(group)
                        .and_then(|open| matching_rust_delimiter(*open))
                        .is_some()
                    {
                        return Some(Some(RustSourceClosureOffender::IncludeMacro));
                    }
                }
            }
            cursor = after_identifier;
            continue;
        }
        cursor = cursor.saturating_add(1);
    }
    Some(None)
}

fn count_structural_rust_link_name_attributes(source: &str) -> Option<usize> {
    rust_code_tokens(source)?;

    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    let mut link_names = 0usize;
    while cursor < bytes.len() {
        cursor = skip_rust_trivia(bytes, cursor)?;
        if cursor >= bytes.len() {
            break;
        }
        if let Some(after_literal) = rust_literal_end(bytes, cursor).ok()? {
            cursor = after_literal;
            continue;
        }
        if bytes[cursor] == b'#' {
            let mut group = skip_rust_trivia(bytes, cursor.saturating_add(1))?;
            if bytes.get(group) == Some(&b'!') {
                group = skip_rust_trivia(bytes, group.saturating_add(1))?;
            }
            if bytes.get(group) == Some(&b'[') {
                let (after_group, has_link_name) =
                    scan_rust_attribute_group_for_assignment(source, group, "link_name")?;
                link_names = link_names.saturating_add(usize::from(has_link_name));
                cursor = after_group;
                continue;
            }
        }
        cursor = cursor.saturating_add(1);
    }
    Some(link_names)
}

fn count_structural_rust_extern_blocks(source: &str) -> Option<usize> {
    rust_code_tokens(source)?;

    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    let mut blocks = 0usize;
    while cursor < bytes.len() {
        cursor = skip_rust_trivia(bytes, cursor)?;
        if cursor >= bytes.len() {
            break;
        }
        if let Some(after_literal) = rust_literal_end(bytes, cursor).ok()? {
            cursor = after_literal;
            continue;
        }
        let Some((identifier, after_identifier)) = rust_identifier_at(source, cursor) else {
            cursor = cursor.saturating_add(1);
            continue;
        };
        cursor = after_identifier;
        if identifier != "extern" {
            continue;
        }

        let mut next = skip_rust_trivia(bytes, cursor)?;
        if let Some(after_abi) = rust_literal_end(bytes, next).ok()? {
            next = skip_rust_trivia(bytes, after_abi)?;
        }
        loop {
            if bytes.get(next) != Some(&b'#') {
                break;
            }
            let mut group = skip_rust_trivia(bytes, next.saturating_add(1))?;
            if bytes.get(group) == Some(&b'!') {
                group = skip_rust_trivia(bytes, group.saturating_add(1))?;
            }
            if bytes.get(group) != Some(&b'[') {
                break;
            }
            next = skip_rust_trivia(bytes, skip_balanced_rust_group(bytes, group)?)?;
        }
        if bytes.get(next) == Some(&b'{') {
            blocks = blocks.saturating_add(1);
        }
    }
    Some(blocks)
}

fn exact_unsafe_extern_c_block_bodies(source: &str) -> Option<Vec<&str>> {
    rust_code_tokens(source)?;

    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    let mut bodies = Vec::new();
    while cursor < bytes.len() {
        cursor = skip_rust_trivia(bytes, cursor)?;
        if cursor >= bytes.len() {
            break;
        }
        if let Some(after_literal) = rust_literal_end(bytes, cursor).ok()? {
            cursor = after_literal;
            continue;
        }
        let Some((identifier, after_identifier)) = rust_identifier_at(source, cursor) else {
            cursor = cursor.saturating_add(1);
            continue;
        };
        cursor = after_identifier;
        if identifier != "unsafe" {
            continue;
        }
        let extern_start = skip_rust_trivia(bytes, cursor)?;
        let Some(("extern", after_extern)) = rust_identifier_at(source, extern_start) else {
            continue;
        };
        let abi_start = skip_rust_trivia(bytes, after_extern)?;
        let Some(after_abi) = rust_literal_end(bytes, abi_start).ok()? else {
            continue;
        };
        if source.get(abi_start..after_abi) != Some("\"C\"") {
            continue;
        }
        let open = skip_rust_trivia(bytes, after_abi)?;
        if bytes.get(open) != Some(&b'{') {
            continue;
        }
        let after_block = skip_balanced_rust_group(bytes, open)?;
        let close = after_block.checked_sub(1)?;
        bodies.push(source.get(open.saturating_add(1)..close)?);
        cursor = after_block;
    }
    Some(bodies)
}

fn rust_token_matches_text(token: &RustCodeToken<'_>, expected: &str) -> bool {
    match token {
        RustCodeToken::Identifier(actual) => *actual == expected,
        RustCodeToken::Punctuation(actual) => expected.as_bytes() == [*actual],
    }
}

fn rust_foreign_parameters_match(
    parameters: &[RustCodeToken<'_>],
    expected_types: &[&[&str]],
) -> bool {
    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    for (index, token) in parameters.iter().enumerate() {
        match token {
            RustCodeToken::Punctuation(b'(' | b'[' | b'{') => depth = depth.saturating_add(1),
            RustCodeToken::Punctuation(b')' | b']' | b'}') => {
                let Some(next_depth) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next_depth;
            }
            RustCodeToken::Punctuation(b',') if depth == 0 => {
                if start != index {
                    segments.push(&parameters[start..index]);
                }
                start = index.saturating_add(1);
            }
            _ => {}
        }
    }
    if depth != 0 {
        return false;
    }
    if start != parameters.len() {
        segments.push(&parameters[start..]);
    }
    if segments.len() != expected_types.len() {
        return false;
    }

    segments
        .iter()
        .zip(expected_types)
        .all(|(actual, expected)| {
            actual.len() == expected.len().saturating_add(2)
                && matches!(actual.first(), Some(RustCodeToken::Identifier(_)))
                && matches!(actual.get(1), Some(RustCodeToken::Punctuation(b':')))
                && actual[2..]
                    .iter()
                    .zip(*expected)
                    .all(|(token, expected)| rust_token_matches_text(token, expected))
        })
}

fn rust_foreign_fn_matches(
    tokens: &[RustCodeToken<'_>],
    fn_index: usize,
    symbol: &str,
    expected_parameter_types: &[&[&str]],
    expected_return_type: &[&str],
) -> bool {
    if !matches!(
        tokens.get(fn_index.saturating_sub(1)),
        Some(RustCodeToken::Identifier("pub"))
    ) || !matches!(
        tokens.get(fn_index.saturating_add(1)),
        Some(RustCodeToken::Identifier(candidate)) if *candidate == symbol
    ) || !matches!(
        tokens.get(fn_index.saturating_add(2)),
        Some(RustCodeToken::Punctuation(b'('))
    ) {
        return false;
    }

    let open = fn_index.saturating_add(2);
    let mut depth = 0usize;
    let mut close = None;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token {
            RustCodeToken::Punctuation(b'(') => depth = depth.saturating_add(1),
            RustCodeToken::Punctuation(b')') => {
                let Some(next_depth) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next_depth;
                if depth == 0 {
                    close = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close) = close else {
        return false;
    };
    if !rust_foreign_parameters_match(
        &tokens[open.saturating_add(1)..close],
        expected_parameter_types,
    ) || !matches!(
        tokens.get(close.saturating_add(1)..close.saturating_add(3)),
        Some([
            RustCodeToken::Punctuation(b'-'),
            RustCodeToken::Punctuation(b'>')
        ])
    ) {
        return false;
    }
    let return_start = close.saturating_add(3);
    let return_end = return_start.saturating_add(expected_return_type.len());
    tokens.get(return_start..return_end).is_some_and(|actual| {
        actual
            .iter()
            .zip(expected_return_type)
            .all(|(token, expected)| rust_token_matches_text(token, expected))
    }) && matches!(
        tokens.get(return_end),
        Some(RustCodeToken::Punctuation(b';'))
    )
}

fn count_canonical_rust_shim_foreign_declarations(
    source: &str,
    symbol: &str,
    expected_parameter_types: &[&[&str]],
    expected_return_type: &[&str],
) -> Option<usize> {
    let bodies = exact_unsafe_extern_c_block_bodies(source)?;
    if bodies.len() != 1 {
        return Some(0);
    }
    let tokens = rust_code_tokens(bodies[0])?;
    let mut depth = 0usize;
    let mut declarations = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        if depth == 0
            && matches!(token, RustCodeToken::Identifier("fn"))
            && rust_foreign_fn_matches(
                &tokens,
                index,
                symbol,
                expected_parameter_types,
                expected_return_type,
            )
        {
            declarations = declarations.saturating_add(1);
        }
        match token {
            RustCodeToken::Punctuation(b'(' | b'[' | b'{') => depth = depth.saturating_add(1),
            RustCodeToken::Punctuation(b')' | b']' | b'}') => depth = depth.checked_sub(1)?,
            _ => {}
        }
    }
    Some(declarations)
}

fn rust_c4_has_exact_foreign_item_roster(source: &str) -> Option<bool> {
    const EXPECTED: [&str; 4] = [
        "FsRingMapLockedPagesSeh",
        "FsRingProbeAndLockPagesSeh",
        "MmSectionObjectType",
        "ZwQuerySection",
    ];

    if count_structural_rust_extern_blocks(source)? != 1 {
        return Some(false);
    }
    let bodies = exact_unsafe_extern_c_block_bodies(source)?;
    if bodies.len() != 1 {
        return Some(false);
    }
    let tokens = rust_code_tokens(bodies[0])?;
    let mut depth = 0usize;
    let mut item_start = 0usize;
    let mut names = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if depth == 0 && matches!(token, RustCodeToken::Punctuation(b';')) {
            let item = tokens.get(item_start..=index)?;
            let name = match item {
                [
                    RustCodeToken::Identifier("pub"),
                    RustCodeToken::Identifier("fn"),
                    RustCodeToken::Identifier(name),
                    RustCodeToken::Punctuation(b'('),
                    ..,
                    RustCodeToken::Punctuation(b';'),
                ] => *name,
                [
                    RustCodeToken::Identifier("pub"),
                    RustCodeToken::Identifier("static"),
                    RustCodeToken::Identifier("mut"),
                    RustCodeToken::Identifier(name),
                    RustCodeToken::Punctuation(b':'),
                    ..,
                    RustCodeToken::Punctuation(b';'),
                ] => *name,
                _ => return Some(false),
            };
            if item[..item.len().saturating_sub(1)]
                .iter()
                .any(|token| matches!(token, RustCodeToken::Punctuation(b'{' | b'}' | b';')))
            {
                return Some(false);
            }
            names.push(name);
            item_start = index.saturating_add(1);
        }
        match token {
            RustCodeToken::Punctuation(b'(' | b'[' | b'{') => depth = depth.saturating_add(1),
            RustCodeToken::Punctuation(b')' | b']' | b'}') => depth = depth.checked_sub(1)?,
            _ => {}
        }
    }
    names.sort_unstable();
    Some(depth == 0 && item_start == tokens.len() && names == EXPECTED)
}

fn rust_range_is_exact_plain_string(
    source: &str,
    start: usize,
    end: usize,
    expected: &str,
) -> Option<bool> {
    let bytes = source.as_bytes();
    let literal = skip_rust_trivia(bytes, start)?;
    let Some(after_literal) = rust_literal_end(bytes, literal).ok()? else {
        return Some(false);
    };
    Some(
        source.get(literal..after_literal) == Some(expected)
            && skip_rust_trivia(bytes, after_literal)? == end,
    )
}

fn rust_cc_file_argument_is_canonical(source: &str, start: usize, end: usize) -> Option<bool> {
    const C_SOURCE_LITERAL: &str = "\"native/c4_seh.c\"";
    if rust_range_is_exact_plain_string(source, start, end, C_SOURCE_LITERAL)? {
        return Some(true);
    }

    let bytes = source.as_bytes();
    let path = skip_rust_trivia(bytes, start)?;
    let Some(("Path", after_path)) = rust_identifier_at(source, path) else {
        return Some(false);
    };
    let first_colon = skip_rust_trivia(bytes, after_path)?;
    if bytes.get(first_colon..first_colon.saturating_add(2)) != Some(b"::") {
        return Some(false);
    }
    let new = skip_rust_trivia(bytes, first_colon.saturating_add(2))?;
    let Some(("new", after_new)) = rust_identifier_at(source, new) else {
        return Some(false);
    };
    let open = skip_rust_trivia(bytes, after_new)?;
    if bytes.get(open) != Some(&b'(') {
        return Some(false);
    }
    let after_group = skip_balanced_rust_group(bytes, open)?;
    let close = after_group.checked_sub(1)?;
    Some(
        skip_rust_trivia(bytes, after_group)? == end
            && rust_range_is_exact_plain_string(
                source,
                open.saturating_add(1),
                close,
                C_SOURCE_LITERAL,
            )?,
    )
}

fn rust_range_has_exact_tokens(
    source: &str,
    start: usize,
    end: usize,
    expected: &[&str],
) -> Option<bool> {
    let tokens = rust_code_tokens(source.get(start..end)?)?;
    Some(
        tokens.len() == expected.len()
            && tokens
                .iter()
                .zip(expected)
                .all(|(token, expected)| rust_token_matches_text(token, expected)),
    )
}

fn matching_rust_code_token_group(tokens: &[RustCodeToken<'_>], open: usize) -> Option<usize> {
    let expected_close = match tokens.get(open) {
        Some(RustCodeToken::Punctuation(b'(')) => b')',
        Some(RustCodeToken::Punctuation(b'[')) => b']',
        Some(RustCodeToken::Punctuation(b'{')) => b'}',
        _ => return None,
    };
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token {
            RustCodeToken::Punctuation(b'(' | b'[' | b'{') => depth = depth.saturating_add(1),
            RustCodeToken::Punctuation(close) if matches!(close, b')' | b']' | b'}') => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return (*close == expected_close).then_some(index);
                }
            }
            _ => {}
        }
    }
    None
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RustBuildChoreography {
    Full,
    MinimalWithW4,
    MinimalInput,
    Rejected,
}

fn rust_build_token_choreography(tokens: &[RustCodeToken<'_>]) -> Option<RustBuildChoreography> {
    let mut build_declarations = 0usize;
    let mut build_chains = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if matches!(token, RustCodeToken::Identifier("mod")) {
            return Some(RustBuildChoreography::Rejected);
        }
        if matches!(token, RustCodeToken::Identifier("Build")) {
            let canonical_new = matches!(
                tokens.get(index.saturating_sub(3)..index.saturating_add(6)),
                Some([
                    RustCodeToken::Identifier("cc"),
                    RustCodeToken::Punctuation(b':'),
                    RustCodeToken::Punctuation(b':'),
                    RustCodeToken::Identifier("Build"),
                    RustCodeToken::Punctuation(b':'),
                    RustCodeToken::Punctuation(b':'),
                    RustCodeToken::Identifier("new"),
                    RustCodeToken::Punctuation(b'('),
                    RustCodeToken::Punctuation(b')'),
                ])
            );
            if !canonical_new {
                return Some(RustBuildChoreography::Rejected);
            }
        }
        if !matches!(token, RustCodeToken::Identifier("build")) {
            continue;
        }
        if matches!(
            tokens.get(index.saturating_sub(2)..index.saturating_add(2)),
            Some([
                RustCodeToken::Identifier("let"),
                RustCodeToken::Identifier("mut"),
                RustCodeToken::Identifier("build"),
                RustCodeToken::Punctuation(b'='),
            ])
        ) {
            if !matches!(
                tokens.get(index.saturating_add(1)..index.saturating_add(12)),
                Some([
                    RustCodeToken::Punctuation(b'='),
                    RustCodeToken::Identifier("cc"),
                    RustCodeToken::Punctuation(b':'),
                    RustCodeToken::Punctuation(b':'),
                    RustCodeToken::Identifier("Build"),
                    RustCodeToken::Punctuation(b':'),
                    RustCodeToken::Punctuation(b':'),
                    RustCodeToken::Identifier("new"),
                    RustCodeToken::Punctuation(b'('),
                    RustCodeToken::Punctuation(b')'),
                    RustCodeToken::Punctuation(b';'),
                ])
            ) {
                return Some(RustBuildChoreography::Rejected);
            }
            build_declarations = build_declarations.saturating_add(1);
            continue;
        }
        if !matches!(
            tokens.get(index.saturating_add(1)),
            Some(RustCodeToken::Punctuation(b'.'))
        ) {
            return Some(RustBuildChoreography::Rejected);
        }
        let mut cursor = index.saturating_add(1);
        let mut methods = Vec::new();
        while matches!(tokens.get(cursor), Some(RustCodeToken::Punctuation(b'.'))) {
            let Some(RustCodeToken::Identifier(method)) = tokens.get(cursor.saturating_add(1))
            else {
                return Some(RustBuildChoreography::Rejected);
            };
            let open = cursor.saturating_add(2);
            if !matches!(tokens.get(open), Some(RustCodeToken::Punctuation(b'('))) {
                return Some(RustBuildChoreography::Rejected);
            }
            methods.push(*method);
            cursor = matching_rust_code_token_group(tokens, open)?.saturating_add(1);
        }
        if !matches!(tokens.get(cursor), Some(RustCodeToken::Punctuation(b';'))) {
            return Some(RustBuildChoreography::Rejected);
        }
        build_chains.push(methods);
    }

    const COMPILE_CHAIN: [&str; 8] = [
        "file", "flag", "flag", "flag", "flag", "flag", "flag", "compile",
    ];
    let build_type_count = tokens
        .iter()
        .filter(|token| matches!(token, RustCodeToken::Identifier("Build")))
        .count();
    let common = tokens
        .iter()
        .filter(|token| matches!(token, RustCodeToken::Identifier("file")))
        .count()
        == 1
        && !tokens.iter().any(|token| {
            matches!(
                token,
                RustCodeToken::Identifier("files" | "object" | "objects")
            )
        });
    Some(if !common {
        RustBuildChoreography::Rejected
    } else if build_declarations == 1
        && build_type_count == 1
        && build_chains == [vec!["include"], vec!["define"], COMPILE_CHAIN.to_vec()]
    {
        RustBuildChoreography::Full
    } else if build_declarations == 1
        && build_type_count == 1
        && build_chains == [vec!["file", "flag", "compile"]]
    {
        RustBuildChoreography::MinimalWithW4
    } else if build_declarations <= 1
        && build_type_count == build_declarations
        && build_chains == [vec!["file", "compile"]]
    {
        RustBuildChoreography::MinimalInput
    } else {
        RustBuildChoreography::Rejected
    })
}

fn rust_build_script_c4_cc_choreography(source: &str) -> Option<RustBuildChoreography> {
    let tokens = rust_code_tokens(source)?;
    let choreography = rust_build_token_choreography(&tokens)?;
    if choreography == RustBuildChoreography::Rejected {
        return Some(RustBuildChoreography::Rejected);
    }

    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    let mut file_calls = 0usize;
    let mut include_calls = 0usize;
    let mut define_calls = 0usize;
    let mut flags = Vec::new();
    let mut compile_calls = 0usize;
    while cursor < bytes.len() {
        cursor = skip_rust_trivia(bytes, cursor)?;
        if cursor >= bytes.len() {
            break;
        }
        if let Some(after_literal) = rust_literal_end(bytes, cursor).ok()? {
            cursor = after_literal;
            continue;
        }
        if bytes[cursor] != b'.' {
            cursor = cursor.saturating_add(1);
            continue;
        }
        let method_start = skip_rust_trivia(bytes, cursor.saturating_add(1))?;
        let Some((method, after_method)) = rust_identifier_at(source, method_start) else {
            cursor = cursor.saturating_add(1);
            continue;
        };
        if !matches!(
            method,
            "include" | "define" | "file" | "files" | "object" | "objects" | "flag" | "compile"
        ) {
            cursor = after_method;
            continue;
        }
        let open = skip_rust_trivia(bytes, after_method)?;
        if bytes.get(open) != Some(&b'(') {
            return Some(RustBuildChoreography::Rejected);
        }
        let after_group = skip_balanced_rust_group(bytes, open)?;
        let close = after_group.checked_sub(1)?;
        match method {
            "include" => {
                include_calls = include_calls.saturating_add(1);
                if !rust_range_has_exact_tokens(
                    source,
                    open.saturating_add(1),
                    close,
                    &["include_path"],
                )? {
                    return Some(RustBuildChoreography::Rejected);
                }
            }
            "define" => {
                define_calls = define_calls.saturating_add(1);
                if !rust_range_has_exact_tokens(
                    source,
                    open.saturating_add(1),
                    close,
                    &["&", "name", ",", "value", ".", "as_deref", "(", ")"],
                )? {
                    return Some(RustBuildChoreography::Rejected);
                }
            }
            "file" => {
                file_calls = file_calls.saturating_add(1);
                if !rust_cc_file_argument_is_canonical(source, open.saturating_add(1), close)? {
                    return Some(RustBuildChoreography::Rejected);
                }
            }
            "flag" => {
                let literal = skip_rust_trivia(bytes, open.saturating_add(1))?;
                let Some(after_literal) = rust_literal_end(bytes, literal).ok()? else {
                    return Some(RustBuildChoreography::Rejected);
                };
                if skip_rust_trivia(bytes, after_literal)? != close {
                    return Some(RustBuildChoreography::Rejected);
                }
                flags.push(source.get(literal..after_literal)?);
            }
            "compile" => {
                compile_calls = compile_calls.saturating_add(1);
                if !rust_range_is_exact_plain_string(
                    source,
                    open.saturating_add(1),
                    close,
                    "\"fsring_c4_seh\"",
                )? {
                    return Some(RustBuildChoreography::Rejected);
                }
            }
            "files" | "object" | "objects" => {
                return Some(RustBuildChoreography::Rejected);
            }
            _ => return Some(RustBuildChoreography::Rejected),
        }
        cursor = after_group;
    }
    let arguments_match = match choreography {
        RustBuildChoreography::Full => {
            include_calls == 1
                && define_calls == 1
                && file_calls == 1
                && flags
                    == [
                        "\"/kernel\"",
                        "\"/Zl\"",
                        "\"/GS-\"",
                        "\"/W4\"",
                        "\"/WX\"",
                        "\"/wd4117\"",
                    ]
                && compile_calls == 1
        }
        RustBuildChoreography::MinimalWithW4 => {
            include_calls == 0
                && define_calls == 0
                && file_calls == 1
                && flags == ["\"/W4\""]
                && compile_calls == 1
        }
        RustBuildChoreography::MinimalInput => {
            include_calls == 0
                && define_calls == 0
                && file_calls == 1
                && flags.is_empty()
                && compile_calls == 1
        }
        RustBuildChoreography::Rejected => false,
    };
    Some(if arguments_match {
        choreography
    } else {
        RustBuildChoreography::Rejected
    })
}

fn rust_build_script_has_exact_c4_cc_input(source: &str) -> Option<bool> {
    Some(rust_build_script_c4_cc_choreography(source)? != RustBuildChoreography::Rejected)
}

fn rust_build_script_has_exact_c4_build_choreography(source: &str) -> Option<bool> {
    if rust_build_macro_context_offender(source)?.is_some() {
        return Some(false);
    }
    Some(rust_build_script_c4_cc_choreography(source)? == RustBuildChoreography::Full)
}

fn count_rust_shim_declaration_tokens(tokens: &[RustCodeToken<'_>], symbol: &str) -> usize {
    tokens
        .windows(3)
        .filter(|window| {
            matches!(
                window,
                [
                    RustCodeToken::Identifier("fn"),
                    RustCodeToken::Identifier(candidate),
                    RustCodeToken::Punctuation(b'(')
                ] if *candidate == symbol
            )
        })
        .count()
}

fn count_rust_shim_declarations(source: &str, symbol: &str) -> Option<usize> {
    Some(count_rust_shim_declaration_tokens(
        &rust_code_tokens(source)?,
        symbol,
    ))
}

fn count_typed_rust_shim_call_tokens(tokens: &[RustCodeToken<'_>], symbol: &str) -> usize {
    tokens
        .windows(5)
        .filter(|window| {
            matches!(
                window,
                [
                    RustCodeToken::Identifier("fsring_sys"),
                    RustCodeToken::Punctuation(b':'),
                    RustCodeToken::Punctuation(b':'),
                    RustCodeToken::Identifier(candidate),
                    RustCodeToken::Punctuation(b'(')
                ] if *candidate == symbol
            )
        })
        .count()
}

fn count_typed_rust_shim_calls(source: &str, symbol: &str) -> Option<usize> {
    Some(count_typed_rust_shim_call_tokens(
        &rust_code_tokens(source)?,
        symbol,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
enum ShimReferenceRole {
    Declaration,
    ReExport,
    AbiAssertion,
    DirectCall,
}

const SHIM_REFERENCE_ROLE_COUNT: usize = 4;

#[derive(Debug, PartialEq, Eq)]
struct ShimReferenceAudit {
    roles: [usize; SHIM_REFERENCE_ROLE_COUNT],
    unapproved: usize,
}

fn rust_statement_start(tokens: &[RustCodeToken<'_>], index: usize) -> usize {
    tokens[..index]
        .iter()
        .rposition(|token| matches!(token, RustCodeToken::Punctuation(b';')))
        .map_or(0, |position| position.saturating_add(1))
}

fn is_structural_shim_reexport(tokens: &[RustCodeToken<'_>], index: usize) -> bool {
    let start = rust_statement_start(tokens, index);
    if !matches!(
        tokens.get(start..start.saturating_add(6)),
        Some([
            RustCodeToken::Identifier("pub"),
            RustCodeToken::Identifier("use"),
            RustCodeToken::Identifier("c4"),
            RustCodeToken::Punctuation(b':'),
            RustCodeToken::Punctuation(b':'),
            RustCodeToken::Punctuation(b'{'),
        ])
    ) || !matches!(
        tokens.get(index.saturating_sub(1)),
        Some(RustCodeToken::Punctuation(b'{' | b','))
    ) || !matches!(
        tokens.get(index.saturating_add(1)),
        Some(RustCodeToken::Punctuation(b',' | b'}'))
    ) {
        return false;
    }

    let mut depth = 0usize;
    let mut candidate_depth = None;
    for (position, token) in tokens.iter().enumerate().skip(start.saturating_add(5)) {
        match token {
            RustCodeToken::Punctuation(b'{') => depth = depth.saturating_add(1),
            RustCodeToken::Punctuation(b'}') => {
                let Some(next_depth) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next_depth;
                if depth == 0 {
                    return candidate_depth == Some(1)
                        && matches!(
                            tokens.get(position.saturating_add(1)),
                            Some(RustCodeToken::Punctuation(b';'))
                        );
                }
            }
            _ => {}
        }
        if position == index {
            candidate_depth = Some(depth);
        }
    }
    false
}

fn is_structural_shim_abi_assertion(tokens: &[RustCodeToken<'_>], index: usize) -> bool {
    let start = rust_statement_start(tokens, index);
    matches!(
        tokens.get(start..start.saturating_add(7)),
        Some([
            RustCodeToken::Identifier("const"),
            RustCodeToken::Identifier("_"),
            RustCodeToken::Punctuation(b':'),
            RustCodeToken::Identifier("unsafe"),
            RustCodeToken::Identifier("extern"),
            RustCodeToken::Identifier("fn"),
            RustCodeToken::Punctuation(b'('),
        ])
    ) && matches!(
        tokens.get(index.saturating_sub(4)..index),
        Some([
            RustCodeToken::Punctuation(b'='),
            RustCodeToken::Identifier("fsring_sys"),
            RustCodeToken::Punctuation(b':'),
            RustCodeToken::Punctuation(b':'),
        ])
    ) && matches!(
        tokens.get(index.saturating_add(1)),
        Some(RustCodeToken::Punctuation(b';'))
    )
}

fn shim_reference_role(
    tokens: &[RustCodeToken<'_>],
    index: usize,
    path: &std::path::Path,
    root: &std::path::Path,
) -> Option<ShimReferenceRole> {
    if is_rust_shim_declaration_owner(path, root)
        && matches!(
            tokens.get(index.saturating_sub(1)),
            Some(RustCodeToken::Identifier("fn"))
        )
        && matches!(
            tokens.get(index.saturating_add(1)),
            Some(RustCodeToken::Punctuation(b'('))
        )
    {
        return Some(ShimReferenceRole::Declaration);
    }
    if path_is_exactly_under_root(path, root, &["fsring-sys", "src", "lib.rs"])
        && is_structural_shim_reexport(tokens, index)
    {
        return Some(ShimReferenceRole::ReExport);
    }
    if path_is_exactly_under_root(path, root, &["fsring-fsd", "src", "lib.rs"])
        && is_structural_shim_abi_assertion(tokens, index)
    {
        return Some(ShimReferenceRole::AbiAssertion);
    }
    if is_typed_rust_shim_call_owner(path, root)
        && matches!(
            tokens.get(index.saturating_sub(3)..index),
            Some([
                RustCodeToken::Identifier("fsring_sys"),
                RustCodeToken::Punctuation(b':'),
                RustCodeToken::Punctuation(b':'),
            ])
        )
        && matches!(
            tokens.get(index.saturating_add(1)),
            Some(RustCodeToken::Punctuation(b'('))
        )
    {
        return Some(ShimReferenceRole::DirectCall);
    }
    None
}

fn audit_rust_shim_reference_tokens(
    tokens: &[RustCodeToken<'_>],
    path: &std::path::Path,
    root: &std::path::Path,
    symbol: &str,
) -> ShimReferenceAudit {
    let mut audit = ShimReferenceAudit {
        roles: [0; SHIM_REFERENCE_ROLE_COUNT],
        unapproved: 0,
    };
    for (index, token) in tokens.iter().enumerate() {
        if !matches!(token, RustCodeToken::Identifier(candidate) if *candidate == symbol) {
            continue;
        }
        if let Some(role) = shim_reference_role(tokens, index, path, root) {
            audit.roles[role as usize] = audit.roles[role as usize].saturating_add(1);
        } else {
            audit.unapproved = audit.unapproved.saturating_add(1);
        }
    }
    audit
}

fn audit_rust_shim_references(
    source: &str,
    path: &std::path::Path,
    root: &std::path::Path,
    symbol: &str,
) -> Option<ShimReferenceAudit> {
    Some(audit_rust_shim_reference_tokens(
        &rust_code_tokens(source)?,
        path,
        root,
        symbol,
    ))
}

fn rust_tokens_mention_raising_mapping_symbol(tokens: &[RustCodeToken<'_>]) -> bool {
    tokens.iter().any(|token| {
        matches!(
            token,
            RustCodeToken::Identifier("MmProbeAndLockPages" | "MmMapLockedPagesSpecifyCache")
        )
    })
}

fn rust_source_mentions_raising_mapping_symbol(source: &str) -> Option<bool> {
    Some(rust_tokens_mention_raising_mapping_symbol(
        &rust_code_tokens(source)?,
    ))
}

/// Whether source contains one of the two WDK routine identifiers whose
/// documented fault path must stay behind the C SEH boundary. Malformed source
/// fails closed so a broken delimiter cannot hide a raising call.
fn mentions_raising_mapping_call(source: &str) -> bool {
    rust_source_mentions_raising_mapping_symbol(source).unwrap_or(true)
}

fn is_rust_shim_declaration(source: &str, symbol: &str) -> bool {
    count_rust_shim_declarations(source, symbol) == Some(1)
}

fn is_c_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_c_quoted(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut cursor = start.saturating_add(1);
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            cursor = cursor.saturating_add(2);
        } else if bytes[cursor] == quote {
            return cursor.saturating_add(1);
        } else {
            cursor = cursor.saturating_add(1);
        }
    }
    bytes.len()
}

fn skip_c_trivia(bytes: &[u8], start: usize) -> usize {
    let mut cursor = start;
    loop {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor = cursor.saturating_add(1);
        }
        if bytes.get(cursor..cursor.saturating_add(2)) == Some(b"//") {
            cursor = cursor.saturating_add(2);
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor = cursor.saturating_add(1);
            }
        } else if bytes.get(cursor..cursor.saturating_add(2)) == Some(b"/*") {
            cursor = cursor.saturating_add(2);
            while cursor.saturating_add(1) < bytes.len()
                && bytes.get(cursor..cursor.saturating_add(2)) != Some(b"*/")
            {
                cursor = cursor.saturating_add(1);
            }
            cursor = cursor.saturating_add(2).min(bytes.len());
        } else {
            return cursor;
        }
    }
}

fn skip_c_logical_preprocessor_line(bytes: &[u8], start: usize) -> usize {
    let mut cursor = start;
    while cursor < bytes.len() {
        if bytes.get(cursor..cursor.saturating_add(2)) == Some(b"\\\n") {
            cursor = cursor.saturating_add(2);
        } else if bytes.get(cursor..cursor.saturating_add(3)) == Some(b"\\\r\n") {
            cursor = cursor.saturating_add(3);
        } else if bytes[cursor] == b'\n' {
            return cursor.saturating_add(1);
        } else {
            cursor = cursor.saturating_add(1);
        }
    }
    bytes.len()
}

fn c_owner_has_exact_preprocessor_contract(source: &str) -> bool {
    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    let mut includes = 0usize;
    let mut line_has_code = false;

    while cursor < bytes.len() {
        if bytes.get(cursor..cursor.saturating_add(2)) == Some(b"//") {
            cursor = cursor.saturating_add(2);
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor = cursor.saturating_add(1);
            }
        } else if bytes.get(cursor..cursor.saturating_add(2)) == Some(b"/*") {
            let comment_start = cursor;
            cursor = cursor.saturating_add(2);
            while cursor.saturating_add(1) < bytes.len()
                && bytes.get(cursor..cursor.saturating_add(2)) != Some(b"*/")
            {
                cursor = cursor.saturating_add(1);
            }
            cursor = cursor.saturating_add(2).min(bytes.len());
            if bytes
                .get(comment_start..cursor)
                .is_some_and(|comment| comment.contains(&b'\n'))
            {
                line_has_code = false;
            }
        } else if matches!(bytes[cursor], b'"' | b'\'') {
            line_has_code = true;
            cursor = skip_c_quoted(bytes, cursor, bytes[cursor]);
        } else if bytes[cursor] == b'#' {
            if line_has_code {
                return false;
            }
            let after_directive = skip_c_logical_preprocessor_line(bytes, cursor);
            let Some(directive) = source.get(cursor..after_directive) else {
                return false;
            };
            let directive = directive.trim();
            if directive != "#include <ntifs.h>" {
                return false;
            }
            includes = includes.saturating_add(1);
            cursor = after_directive;
            line_has_code = false;
        } else if !line_has_code && bytes.get(cursor..cursor.saturating_add(2)) == Some(b"%:") {
            let _after_directive = skip_c_logical_preprocessor_line(bytes, cursor);
            return false;
        } else {
            if bytes[cursor] == b'\n' {
                line_has_code = false;
            } else if !bytes[cursor].is_ascii_whitespace() {
                line_has_code = true;
            }
            cursor = cursor.saturating_add(1);
        }
    }

    includes == 1
}

fn skip_balanced_c_parameters(bytes: &[u8], open: usize) -> Option<usize> {
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut cursor = open;
    let mut depth = 0usize;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'"' | b'\'' => cursor = skip_c_quoted(bytes, cursor, bytes[cursor]),
            b'/' if bytes.get(cursor.saturating_add(1)) == Some(&b'/') => {
                cursor = skip_c_trivia(bytes, cursor)
            }
            b'/' if bytes.get(cursor.saturating_add(1)) == Some(&b'*') => {
                cursor = skip_c_trivia(bytes, cursor)
            }
            b'(' => {
                depth = depth.saturating_add(1);
                cursor = cursor.saturating_add(1);
            }
            b')' => {
                depth = depth.checked_sub(1)?;
                cursor = cursor.saturating_add(1);
                if depth == 0 {
                    return Some(cursor);
                }
            }
            _ => cursor = cursor.saturating_add(1),
        }
    }
    None
}

fn count_all_c_shim_definitions(source: &str, symbol: &str) -> usize {
    let Some(tokens) = c_code_tokens(source) else {
        return 0;
    };
    let Some(definitions) = c_function_definitions(&tokens) else {
        return 0;
    };
    definitions
        .iter()
        .filter(|definition| {
            matches!(
                tokens.get(definition.name),
                Some(CCodeToken::Identifier(name)) if *name == symbol
            )
        })
        .count()
}

fn c_parameter_types_match(
    bytes: &[u8],
    open: usize,
    after_parameters: usize,
    expected: &[&[&str]],
) -> bool {
    let Some(close) = after_parameters.checked_sub(1) else {
        return false;
    };
    if bytes.get(open) != Some(&b'(') || bytes.get(close) != Some(&b')') {
        return false;
    }

    let mut cursor = open.saturating_add(1);
    for (parameter_index, expected_type) in expected.iter().enumerate() {
        for expected_token in *expected_type {
            cursor = skip_c_trivia(bytes, cursor);
            if cursor >= close {
                return false;
            }
            let token_end = if is_c_identifier_byte(bytes[cursor]) {
                let mut end = cursor.saturating_add(1);
                while end < close && is_c_identifier_byte(bytes[end]) {
                    end = end.saturating_add(1);
                }
                end
            } else {
                cursor.saturating_add(1)
            };
            if bytes.get(cursor..token_end) != Some(expected_token.as_bytes()) {
                return false;
            }
            cursor = token_end;
        }

        cursor = skip_c_trivia(bytes, cursor);
        if !bytes
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        {
            return false;
        }
        cursor = cursor.saturating_add(1);
        while cursor < close && is_c_identifier_byte(bytes[cursor]) {
            cursor = cursor.saturating_add(1);
        }
        cursor = skip_c_trivia(bytes, cursor);
        if parameter_index.saturating_add(1) == expected.len() {
            if cursor != close {
                return false;
            }
        } else if bytes.get(cursor) == Some(&b',') {
            cursor = cursor.saturating_add(1);
        } else {
            return false;
        }
    }
    expected.is_empty() && skip_c_trivia(bytes, cursor) == close || !expected.is_empty()
}

fn count_c_shim_definitions(source: &str, return_type: &str, symbol: &str) -> usize {
    count_c_shim_definitions_matching(source, return_type, symbol, None)
}

fn count_canonical_c_shim_definitions(
    source: &str,
    return_type: &str,
    symbol: &str,
    expected_parameter_types: &[&[&str]],
) -> usize {
    count_c_shim_definitions_matching(source, return_type, symbol, Some(expected_parameter_types))
}

fn count_c_shim_definitions_matching(
    source: &str,
    return_type: &str,
    symbol: &str,
    expected_parameter_types: Option<&[&[&str]]>,
) -> usize {
    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    let mut definitions = 0usize;
    let mut parentheses = 0usize;
    let mut braces = 0usize;
    let mut brackets = 0usize;
    let mut declaration_start = true;

    while cursor < bytes.len() {
        cursor = skip_c_trivia(bytes, cursor);
        if cursor >= bytes.len() {
            break;
        }
        if bytes[cursor] == b'#' {
            cursor = skip_c_logical_preprocessor_line(bytes, cursor);
            continue;
        }
        if matches!(bytes[cursor], b'"' | b'\'') {
            if parentheses == 0 && braces == 0 && brackets == 0 {
                declaration_start = false;
            }
            cursor = skip_c_quoted(bytes, cursor, bytes[cursor]);
            continue;
        }
        match bytes[cursor] {
            b'(' => {
                if parentheses == 0 && braces == 0 && brackets == 0 {
                    declaration_start = false;
                }
                parentheses = parentheses.saturating_add(1);
                cursor = cursor.saturating_add(1);
                continue;
            }
            b')' => {
                let Some(depth) = parentheses.checked_sub(1) else {
                    return 0;
                };
                parentheses = depth;
                cursor = cursor.saturating_add(1);
                continue;
            }
            b'{' => {
                if parentheses == 0 && braces == 0 && brackets == 0 {
                    declaration_start = false;
                }
                braces = braces.saturating_add(1);
                cursor = cursor.saturating_add(1);
                continue;
            }
            b'}' => {
                let Some(depth) = braces.checked_sub(1) else {
                    return 0;
                };
                braces = depth;
                if parentheses == 0 && braces == 0 && brackets == 0 {
                    declaration_start = true;
                }
                cursor = cursor.saturating_add(1);
                continue;
            }
            b'[' => {
                if parentheses == 0 && braces == 0 && brackets == 0 {
                    declaration_start = false;
                }
                brackets = brackets.saturating_add(1);
                cursor = cursor.saturating_add(1);
                continue;
            }
            b']' => {
                let Some(depth) = brackets.checked_sub(1) else {
                    return 0;
                };
                brackets = depth;
                cursor = cursor.saturating_add(1);
                continue;
            }
            _ => {}
        }
        if !is_c_identifier_byte(bytes[cursor]) {
            if parentheses == 0 && braces == 0 && brackets == 0 {
                declaration_start = bytes[cursor] == b';';
            }
            cursor = cursor.saturating_add(1);
            continue;
        }

        let token_start = cursor;
        while cursor < bytes.len() && is_c_identifier_byte(bytes[cursor]) {
            cursor = cursor.saturating_add(1);
        }
        let begins_top_level_declaration =
            parentheses == 0 && braces == 0 && brackets == 0 && declaration_start;
        if parentheses == 0 && braces == 0 && brackets == 0 {
            declaration_start = false;
        }
        if !begins_top_level_declaration
            || bytes.get(token_start..cursor) != Some(return_type.as_bytes())
        {
            continue;
        }

        let symbol_start = skip_c_trivia(bytes, cursor);
        let symbol_end = symbol_start.saturating_add(symbol.len());
        if bytes.get(symbol_start..symbol_end) != Some(symbol.as_bytes())
            || bytes
                .get(symbol_end)
                .is_some_and(|byte| is_c_identifier_byte(*byte))
        {
            continue;
        }
        let open = skip_c_trivia(bytes, symbol_end);
        if bytes.get(open) != Some(&b'(') {
            continue;
        }
        let Some(after_parameters) = skip_balanced_c_parameters(bytes, open) else {
            break;
        };
        let parameters_match = expected_parameter_types.is_none_or(|expected| {
            c_parameter_types_match(bytes, open, after_parameters, expected)
        });
        let after_parameters = skip_c_trivia(bytes, after_parameters);
        if parameters_match && bytes.get(after_parameters) == Some(&b'{') {
            definitions = definitions.saturating_add(1);
        }
        cursor = after_parameters;
    }
    definitions
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CCodeToken<'a> {
    Identifier(&'a str),
    Punctuation(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CFunctionDefinition {
    name: usize,
    parameters_open: usize,
    parameters_close: usize,
    body_open: usize,
    body_close: usize,
}

fn c_code_tokens(source: &str) -> Option<Vec<CCodeToken<'_>>> {
    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    let mut expected = Vec::new();
    let mut tokens = Vec::new();
    while cursor < bytes.len() {
        cursor = skip_c_trivia(bytes, cursor);
        if cursor >= bytes.len() {
            break;
        }
        if bytes[cursor] == b'#' {
            cursor = skip_c_logical_preprocessor_line(bytes, cursor);
            continue;
        }
        if matches!(bytes[cursor], b'"' | b'\'') {
            cursor = skip_c_quoted(bytes, cursor, bytes[cursor]);
            continue;
        }
        if is_c_identifier_byte(bytes[cursor]) {
            let start = cursor;
            while cursor < bytes.len() && is_c_identifier_byte(bytes[cursor]) {
                cursor = cursor.saturating_add(1);
            }
            tokens.push(CCodeToken::Identifier(source.get(start..cursor)?));
            continue;
        }
        if let Some(close) = match bytes[cursor] {
            b'(' => Some(b')'),
            b'[' => Some(b']'),
            b'{' => Some(b'}'),
            _ => None,
        } {
            expected.push(close);
        } else if matches!(bytes[cursor], b')' | b']' | b'}')
            && expected.pop() != Some(bytes[cursor])
        {
            return None;
        }
        tokens.push(CCodeToken::Punctuation(bytes[cursor]));
        cursor = cursor.saturating_add(1);
    }
    expected.is_empty().then_some(tokens)
}

fn matching_c_token_group(tokens: &[CCodeToken<'_>], open: usize) -> Option<usize> {
    let expected_close = match tokens.get(open) {
        Some(CCodeToken::Punctuation(b'(')) => b')',
        Some(CCodeToken::Punctuation(b'[')) => b']',
        Some(CCodeToken::Punctuation(b'{')) => b'}',
        _ => return None,
    };
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token {
            CCodeToken::Punctuation(b'(' | b'[' | b'{') => depth = depth.saturating_add(1),
            CCodeToken::Punctuation(close) if matches!(close, b')' | b']' | b'}') => {
                let next_depth = depth.checked_sub(1)?;
                depth = next_depth;
                if depth == 0 {
                    return (*close == expected_close).then_some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn parenthesized_c_declarator_name(
    tokens: &[CCodeToken<'_>],
    open: usize,
) -> Option<(usize, usize)> {
    let close = matching_c_token_group(tokens, open)?;
    let first = open.saturating_add(1);
    if first.saturating_add(1) == close
        && matches!(tokens.get(first), Some(CCodeToken::Identifier(_)))
    {
        return Some((first, close));
    }
    if matches!(tokens.get(first), Some(CCodeToken::Punctuation(b'('))) {
        let (name, nested_close) = parenthesized_c_declarator_name(tokens, first)?;
        if nested_close.saturating_add(1) == close {
            return Some((name, close));
        }
    }
    None
}

fn c_function_definitions(tokens: &[CCodeToken<'_>]) -> Option<Vec<CFunctionDefinition>> {
    let mut definitions = Vec::new();
    let mut parentheses = 0usize;
    let mut braces = 0usize;
    let mut brackets = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        if parentheses == 0 && braces == 0 && brackets == 0 {
            let candidate = match token {
                CCodeToken::Identifier(_)
                    if matches!(
                        tokens.get(index.saturating_add(1)),
                        Some(CCodeToken::Punctuation(b'('))
                    ) =>
                {
                    Some((index, index.saturating_add(1)))
                }
                CCodeToken::Punctuation(b'(') => parenthesized_c_declarator_name(tokens, index)
                    .and_then(|(name, declarator_close)| {
                        let parameters_open = declarator_close.saturating_add(1);
                        matches!(
                            tokens.get(parameters_open),
                            Some(CCodeToken::Punctuation(b'('))
                        )
                        .then_some((name, parameters_open))
                    }),
                _ => None,
            };
            if let Some((name, parameters_open)) = candidate {
                let parameters_close = matching_c_token_group(tokens, parameters_open)?;
                let body_open = parameters_close.saturating_add(1);
                if matches!(tokens.get(body_open), Some(CCodeToken::Punctuation(b'{'))) {
                    definitions.push(CFunctionDefinition {
                        name,
                        parameters_open,
                        parameters_close,
                        body_open,
                        body_close: matching_c_token_group(tokens, body_open)?,
                    });
                }
            }
        }
        match token {
            CCodeToken::Punctuation(b'(') => parentheses = parentheses.saturating_add(1),
            CCodeToken::Punctuation(b')') => parentheses = parentheses.checked_sub(1)?,
            CCodeToken::Punctuation(b'{') => braces = braces.saturating_add(1),
            CCodeToken::Punctuation(b'}') => braces = braces.checked_sub(1)?,
            CCodeToken::Punctuation(b'[') => brackets = brackets.saturating_add(1),
            CCodeToken::Punctuation(b']') => brackets = brackets.checked_sub(1)?,
            _ => {}
        }
    }
    (parentheses == 0 && braces == 0 && brackets == 0).then_some(definitions)
}

fn c_token_matches_text(token: &CCodeToken<'_>, expected: &str) -> bool {
    match token {
        CCodeToken::Identifier(actual) => *actual == expected,
        CCodeToken::Punctuation(actual) => expected.as_bytes() == [*actual],
    }
}

fn c_parameter_names<'a>(
    tokens: &'a [CCodeToken<'a>],
    definition: CFunctionDefinition,
    expected_types: &[&[&str]],
) -> Option<Vec<&'a str>> {
    let parameters =
        tokens.get(definition.parameters_open.saturating_add(1)..definition.parameters_close)?;
    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    for (index, token) in parameters.iter().enumerate() {
        match token {
            CCodeToken::Punctuation(b'(' | b'[' | b'{') => depth = depth.saturating_add(1),
            CCodeToken::Punctuation(b')' | b']' | b'}') => depth = depth.checked_sub(1)?,
            CCodeToken::Punctuation(b',') if depth == 0 => {
                segments.push(parameters.get(start..index)?);
                start = index.saturating_add(1);
            }
            _ => {}
        }
    }
    if start != parameters.len() {
        segments.push(parameters.get(start..)?);
    }
    if depth != 0 || segments.len() != expected_types.len() {
        return None;
    }

    let mut names = Vec::new();
    for (actual, expected_type) in segments.iter().zip(expected_types) {
        if actual.len() != expected_type.len().saturating_add(1)
            || !actual[..expected_type.len()]
                .iter()
                .zip(*expected_type)
                .all(|(token, expected)| c_token_matches_text(token, expected))
        {
            return None;
        }
        let Some(CCodeToken::Identifier(name)) = actual.last() else {
            return None;
        };
        names.push(*name);
    }
    Some(names)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CSehShimKind {
    ProbeAndLock,
    MapLockedPages,
}

type C4ShimContractSpec = (
    &'static str,
    &'static str,
    &'static [&'static [&'static str]],
    &'static [&'static [&'static str]],
    &'static [&'static str],
    CSehShimKind,
);

fn c_body_matches(tokens: &[CCodeToken<'_>], expected: &[&str]) -> bool {
    tokens.len() == expected.len()
        && tokens
            .iter()
            .zip(expected)
            .all(|(token, expected)| c_token_matches_text(token, expected))
}

fn c_shim_has_exact_seh_contract(source: &str, kind: CSehShimKind) -> bool {
    const PROBE_TYPES: &[&[&str]] = &[&["PMDL"], &["KPROCESSOR_MODE"], &["LOCK_OPERATION"]];
    const MAP_TYPES: &[&[&str]] = &[
        &["PMDL"],
        &["KPROCESSOR_MODE"],
        &["MEMORY_CACHING_TYPE"],
        &["PVOID"],
        &["ULONG"],
        &["ULONG"],
        &["NTSTATUS", "*"],
    ];
    let (symbol, parameter_types) = match kind {
        CSehShimKind::ProbeAndLock => ("FsRingProbeAndLockPagesSeh", PROBE_TYPES),
        CSehShimKind::MapLockedPages => ("FsRingMapLockedPagesSeh", MAP_TYPES),
    };
    let Some(tokens) = c_code_tokens(source) else {
        return false;
    };
    let Some(definitions) = c_function_definitions(&tokens) else {
        return false;
    };
    let matching = definitions
        .into_iter()
        .filter(|definition| {
            matches!(
                tokens.get(definition.name),
                Some(CCodeToken::Identifier(name)) if *name == symbol
            )
        })
        .collect::<Vec<_>>();
    let [definition] = matching.as_slice() else {
        return false;
    };
    let Some(names) = c_parameter_names(&tokens, *definition, parameter_types) else {
        return false;
    };
    let Some(body) = tokens.get(definition.body_open..=definition.body_close) else {
        return false;
    };

    match kind {
        CSehShimKind::ProbeAndLock => c_body_matches(
            body,
            &[
                "{",
                "__try",
                "{",
                "MmProbeAndLockPages",
                "(",
                names[0],
                ",",
                names[1],
                ",",
                names[2],
                ")",
                ";",
                "return",
                "STATUS_SUCCESS",
                ";",
                "}",
                "__except",
                "(",
                "EXCEPTION_EXECUTE_HANDLER",
                ")",
                "{",
                "return",
                "STATUS_INSUFFICIENT_RESOURCES",
                ";",
                "}",
                "}",
            ],
        ),
        CSehShimKind::MapLockedPages => c_body_matches(
            body,
            &[
                "{",
                "__try",
                "{",
                "PVOID",
                "address",
                "=",
                "MmMapLockedPagesSpecifyCache",
                "(",
                names[0],
                ",",
                names[1],
                ",",
                names[2],
                ",",
                names[3],
                ",",
                names[4],
                ",",
                names[5],
                ")",
                ";",
                "*",
                names[6],
                "=",
                "address",
                "!",
                "=",
                "NULL",
                "?",
                "STATUS_SUCCESS",
                ":",
                "STATUS_INSUFFICIENT_RESOURCES",
                ";",
                "return",
                "address",
                ";",
                "}",
                "__except",
                "(",
                "EXCEPTION_EXECUTE_HANDLER",
                ")",
                "{",
                "*",
                names[6],
                "=",
                "STATUS_INSUFFICIENT_RESOURCES",
                ";",
                "return",
                "NULL",
                ";",
                "}",
                "}",
            ],
        ),
    }
}

fn c_has_exact_top_level_function_roster(source: &str, expected: &[&str]) -> bool {
    let Some(tokens) = c_code_tokens(source) else {
        return false;
    };
    let Some(definitions) = c_function_definitions(&tokens) else {
        return false;
    };
    let mut actual = definitions
        .iter()
        .filter_map(|definition| match tokens.get(definition.name) {
            Some(CCodeToken::Identifier(name)) => Some(*name),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    actual == expected
}

fn is_rust_shim_declaration_owner(path: &std::path::Path, root: &std::path::Path) -> bool {
    path_is_exactly_under_root(path, root, &["fsring-sys", "src", "c4.rs"])
}

fn is_c_shim_definition_owner(path: &std::path::Path, root: &std::path::Path) -> bool {
    path_is_exactly_under_root(path, root, &["fsring-fsd", "native", "c4_seh.c"])
}

fn is_c4_build_script(path: &std::path::Path, root: &std::path::Path) -> bool {
    path_is_exactly_under_root(path, root, &["fsring-fsd", "build.rs"])
}

fn is_typed_rust_shim_call_owner(path: &std::path::Path, root: &std::path::Path) -> bool {
    path_is_exactly_under_root(path, root, &["fsring-fsd", "src", "seh.rs"])
}

fn is_extern_quarantine_test(path: &std::path::Path, root: &std::path::Path) -> bool {
    path_is_exactly_under_root(
        path,
        root,
        &["fsring-core", "tests", "extern_quarantine.rs"],
    )
}

fn exact_root_relative_components<'a>(
    path: &'a std::path::Path,
    root: &std::path::Path,
) -> Option<Vec<&'a std::ffi::OsStr>> {
    if path
        .as_os_str()
        .to_string_lossy()
        .split(['/', '\\'])
        .any(|component| matches!(component, "." | ".."))
    {
        return None;
    }
    let relative = path.strip_prefix(root).ok()?;
    relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(value) => Some(value),
            std::path::Component::Prefix(_)
            | std::path::Component::RootDir
            | std::path::Component::CurDir
            | std::path::Component::ParentDir => None,
        })
        .collect()
}

fn path_is_exactly_under_root(
    path: &std::path::Path,
    root: &std::path::Path,
    expected: &[&str],
) -> bool {
    let Some(actual) = exact_root_relative_components(path, root) else {
        return false;
    };
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| *actual == *expected)
}

fn path_is_under_root_subtree(
    path: &std::path::Path,
    root: &std::path::Path,
    expected: &[&str],
) -> bool {
    let Some(actual) = exact_root_relative_components(path, root) else {
        return false;
    };
    actual.len() >= expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| *actual == *expected)
}

fn is_fsring_sys_tree(path: &std::path::Path, root: &std::path::Path) -> bool {
    path_is_under_root_subtree(path, root, &["fsring-sys"])
}

fn is_fsring_fsd_tree(path: &std::path::Path, root: &std::path::Path) -> bool {
    path_is_under_root_subtree(path, root, &["fsring-fsd"])
}

fn is_compile_fail_fixture(path: &std::path::Path, root: &std::path::Path) -> bool {
    path_is_under_root_subtree(path, root, &["tests", "compile-fail"])
}

fn is_typed_rust_shim_call(source: &str, symbol: &str) -> bool {
    count_typed_rust_shim_calls(source, symbol) == Some(1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WalkEntryKind {
    Directory,
    File,
    RejectedLinkOrReparse,
    Unsupported,
}

fn classify_walk_entry_flags(
    is_symlink: bool,
    is_directory: bool,
    is_file: bool,
    is_reparse_point: bool,
) -> WalkEntryKind {
    if is_symlink || is_reparse_point {
        WalkEntryKind::RejectedLinkOrReparse
    } else if is_directory {
        WalkEntryKind::Directory
    } else if is_file {
        WalkEntryKind::File
    } else {
        WalkEntryKind::Unsupported
    }
}

#[cfg(windows)]
fn metadata_is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn read_security_text(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| {
        std::format!(
            "cannot read UTF-8 security input {}: {error}",
            path.display()
        )
    })
}

fn walk_security_files(
    root: &std::path::Path,
    dir: &std::path::Path,
    include_c: bool,
    f: &mut dyn FnMut(&std::path::Path) -> Result<(), String>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|error| std::format!("cannot read directory {}: {error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            std::format!("cannot enumerate an entry under {}: {error}", dir.display())
        })?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            std::format!(
                "cannot inspect security-walk entry {}: {error}",
                path.display()
            )
        })?;
        let file_type = metadata.file_type();
        match classify_walk_entry_flags(
            file_type.is_symlink(),
            metadata.is_dir(),
            metadata.is_file(),
            metadata_is_windows_reparse_point(&metadata),
        ) {
            WalkEntryKind::RejectedLinkOrReparse => {
                return Err(std::format!(
                    "refusing symlink or reparse-point security-walk entry {}",
                    path.display()
                ));
            }
            WalkEntryKind::Directory => {
                if path == root.join("target") {
                    continue;
                }
                walk_security_files(root, &path, include_c, f)?;
            }
            WalkEntryKind::File => {
                if path
                    .extension()
                    .is_some_and(|extension| extension == "rs" || (include_c && extension == "c"))
                {
                    f(&path)?;
                }
            }
            WalkEntryKind::Unsupported => {
                return Err(std::format!(
                    "refusing unsupported security-walk entry {}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn walk(
    dir: &std::path::Path,
    f: &mut dyn FnMut(&std::path::Path) -> Result<(), String>,
) -> Result<(), String> {
    walk_security_files(dir, dir, false, f)
}

fn walk_rust_and_c(
    dir: &std::path::Path,
    f: &mut dyn FnMut(&std::path::Path) -> Result<(), String>,
) -> Result<(), String> {
    walk_security_files(dir, dir, true, f)
}

fn driver_root() -> std::path::PathBuf {
    let Some(root) = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent() else {
        panic!("the crate directory has no parent; the walk root is wrong")
    };
    root.to_path_buf()
}

#[test]
fn the_scanners_discriminate() {
    assert!(is_extern_block("unsafe extern \"C\" {"));
    assert!(is_extern_block("    pub unsafe extern \"system\" {"));
    assert!(is_extern_block("extern \"C\" {"));
    assert!(!is_extern_block("// unsafe extern is discussed here"));
    assert!(!is_extern_block("pub fn externally_visible() {}"));
    // Definitions with a calling convention are exports and callbacks, not
    // imports; flagging them would make the rule unsatisfiable.
    assert!(!is_extern_block(
        "pub unsafe extern \"system\" fn driver_entry("
    ));
    assert!(!is_extern_block(
        "extern \"C\" fn driver_unload(_d: *mut u8) {}"
    ));

    assert!(mentions_forbidden_random("let x = RtlRandomEx(&mut seed);"));
    assert!(mentions_forbidden_random("    RtlRandom(&mut seed);"));
    assert!(!mentions_forbidden_random("BCryptGenRandom"));
    // Prose forbidding it must not be flagged, or the rule punishes the
    // documentation that states it.
    assert!(!mentions_forbidden_random(
        "//! RtlRandom* is never entropy."
    ));
    assert!(!mentions_forbidden_random(
        "    /// `RtlRandom` is forbidden."
    ));

    assert!(mentions_raising_mapping_call(
        "MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);"
    ));
    assert!(mentions_raising_mapping_call(
        "let p = MmMapLockedPagesSpecifyCache(mdl, UserMode, MmCached, 0, 0, priority);"
    ));
    assert!(!mentions_raising_mapping_call(
        "// MmProbeAndLockPages is fault-contained."
    ));
    assert!(!mentions_raising_mapping_call(
        "FsRingProbeAndLockPagesSeh()"
    ));

    assert!(is_rust_shim_declaration(
        "    pub fn FsRingProbeAndLockPagesSeh();",
        "FsRingProbeAndLockPagesSeh"
    ));
    assert!(!is_rust_shim_declaration(
        "fsring_sys::FsRingProbeAndLockPagesSeh();",
        "FsRingProbeAndLockPagesSeh"
    ));
    assert_eq!(
        count_c_shim_definitions(
            "NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl) { return 0; }",
            "NTSTATUS",
            "FsRingProbeAndLockPagesSeh"
        ),
        1
    );
    assert_eq!(
        count_c_shim_definitions(
            "NTSTATUS (*FsRingProbeAndLockPagesSeh)(PMDL);",
            "NTSTATUS",
            "FsRingProbeAndLockPagesSeh"
        ),
        0
    );
    assert!(is_typed_rust_shim_call(
        "let status = fsring_sys::FsRingProbeAndLockPagesSeh();",
        "FsRingProbeAndLockPagesSeh"
    ));
    assert!(!is_typed_rust_shim_call(
        "let status = FsRingProbeAndLockPagesSeh();",
        "FsRingProbeAndLockPagesSeh"
    ));
}

#[test]
fn a_complete_multiline_c_prototype_is_not_a_definition() {
    let prototype = "NTSTATUS FsRingProbeAndLockPagesSeh(\n\
        PMDL mdl,\n\
        NTSTATUS (*translate)(NTSTATUS status)\n\
    );";
    assert_eq!(
        count_c_shim_definitions(prototype, "NTSTATUS", "FsRingProbeAndLockPagesSeh"),
        0
    );
}

#[test]
fn a_complete_multiline_c_body_after_balanced_parameters_is_a_definition() {
    let body = "NTSTATUS FsRingProbeAndLockPagesSeh(\n\
        PMDL mdl,\n\
        NTSTATUS (*translate)(NTSTATUS status)\n\
    )\n\
    {\n\
        return translate(0);\n\
    }";
    assert_eq!(
        count_c_shim_definitions(body, "NTSTATUS", "FsRingProbeAndLockPagesSeh"),
        1
    );
}

#[test]
fn c_definition_scans_distinguish_qualified_additions_from_replacements() {
    const PARAMETERS: &[&[&str]] = &[&["PMDL"]];
    let canonical = "NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl) { return 0; }";

    assert_eq!(
        count_all_c_shim_definitions(canonical, "FsRingProbeAndLockPagesSeh"),
        1
    );
    assert_eq!(
        count_canonical_c_shim_definitions(
            canonical,
            "NTSTATUS",
            "FsRingProbeAndLockPagesSeh",
            PARAMETERS,
        ),
        1
    );

    for qualified in [
        "static NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl) { return 0; }",
        "extern NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl) { return 0; }",
        "__declspec(noinline) NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl) { return 0; }",
        "NTSTATUS NTAPI FsRingProbeAndLockPagesSeh(PMDL mdl) { return 0; }",
        "_IRQL_requires_max_(APC_LEVEL) NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl) { return 0; }",
    ] {
        let added = std::format!("{canonical}\n{qualified}");
        assert_eq!(
            count_all_c_shim_definitions(&added, "FsRingProbeAndLockPagesSeh"),
            2,
            "an added qualified definition must increase the aggregate"
        );
        assert_eq!(
            count_all_c_shim_definitions(qualified, "FsRingProbeAndLockPagesSeh"),
            1,
            "a qualified replacement is still a C definition"
        );
        assert_eq!(
            count_canonical_c_shim_definitions(
                qualified,
                "NTSTATUS",
                "FsRingProbeAndLockPagesSeh",
                PARAMETERS,
            ),
            0,
            "a qualified replacement must not satisfy the canonical export contract"
        );
    }
}

#[test]
fn round5_parenthesized_c_declarators_are_aggregate_definitions_but_not_canonical() {
    const PARAMETERS: &[&[&str]] = &[&["PMDL"]];
    let canonical = "NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl) { return 0; }";
    let parenthesized = "static NTSTATUS (FsRingProbeAndLockPagesSeh)(PMDL mdl) { return 0; }";

    assert_eq!(
        count_all_c_shim_definitions(
            &std::format!("{canonical}\n{parenthesized}"),
            "FsRingProbeAndLockPagesSeh",
        ),
        2,
        "a redundant parenthesized function name must not hide a second definition"
    );
    assert_eq!(
        count_all_c_shim_definitions(parenthesized, "FsRingProbeAndLockPagesSeh"),
        1,
        "a parenthesized replacement remains an aggregate definition"
    );
    assert_eq!(
        count_canonical_c_shim_definitions(
            parenthesized,
            "NTSTATUS",
            "FsRingProbeAndLockPagesSeh",
            PARAMETERS,
        ),
        0,
        "the canonical export must retain its exact unparenthesized spelling"
    );

    for non_definition in [
        "NTSTATUS (FsRingProbeAndLockPagesSeh)(PMDL mdl);",
        "NTSTATUS (*FsRingProbeAndLockPagesSeh)(PMDL mdl);",
        "NTSTATUS (*FsRingProbeAndLockPagesSeh)(PMDL mdl) = NULL;",
    ] {
        assert_eq!(
            count_all_c_shim_definitions(non_definition, "FsRingProbeAndLockPagesSeh"),
            0,
            "a prototype or function-pointer variable is not a function definition: {non_definition}"
        );
    }
}

#[test]
fn round5_parenthesized_c_helpers_break_the_exact_owner_roster() {
    let owner = r#"
        NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl) { return 0; }
        PVOID FsRingMapLockedPagesSeh(PMDL mdl) { return NULL; }
    "#;
    assert!(c_has_exact_top_level_function_roster(
        owner,
        &["FsRingProbeAndLockPagesSeh", "FsRingMapLockedPagesSeh"],
    ));

    let hidden_helper = std::format!("{owner}\nNTSTATUS (HiddenProbe)(PMDL mdl) {{ return 0; }}");
    assert!(
        !c_has_exact_top_level_function_roster(
            &hidden_helper,
            &["FsRingProbeAndLockPagesSeh", "FsRingMapLockedPagesSeh"],
        ),
        "a redundant parenthesized helper name must remain in the top-level roster"
    );
}

#[test]
fn c_definition_scans_preserve_prototype_pointer_macro_literal_and_nested_decoys() {
    let decoys = [
        "NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl);",
        "NTSTATUS (*FsRingProbeAndLockPagesSeh)(PMDL mdl);",
        "#define DECLARE_PROBE NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl) { return 0; }",
        concat!(
            "#define DECLARE_PROBE() \\\n",
            "    NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl) \\\n",
            "    { return 0; }\n",
            "DECLARE_PROBE()"
        ),
        "/* NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl) { return 0; } */",
        "const char *text = \"NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl) { return 0; }\";",
        "void outer(void) { NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl) { return 0; } }",
        "EMIT(NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl) { return 0; })",
    ];

    for decoy in decoys {
        assert_eq!(
            count_all_c_shim_definitions(decoy, "FsRingProbeAndLockPagesSeh"),
            0,
            "non-definition context must remain invisible: {decoy}"
        );
    }
}

#[test]
fn canonical_c_definition_requires_the_exact_unqualified_signature() {
    const PARAMETERS: &[&[&str]] = &[&["PMDL"], &["KPROCESSOR_MODE"], &["LOCK_OPERATION"]];
    let canonical = "NTSTATUS FsRingProbeAndLockPagesSeh(\n\
        PMDL mdl,\n\
        KPROCESSOR_MODE access_mode,\n\
        LOCK_OPERATION operation)\n\
        { return 0; }";
    assert_eq!(
        count_canonical_c_shim_definitions(
            canonical,
            "NTSTATUS",
            "FsRingProbeAndLockPagesSeh",
            PARAMETERS,
        ),
        1
    );
    let renamed_parameters = "NTSTATUS FsRingProbeAndLockPagesSeh(\n\
        PMDL descriptor,\n\
        KPROCESSOR_MODE mode,\n\
        LOCK_OPERATION lock_operation)\n\
        { return 0; }";
    assert_eq!(
        count_canonical_c_shim_definitions(
            renamed_parameters,
            "NTSTATUS",
            "FsRingProbeAndLockPagesSeh",
            PARAMETERS,
        ),
        1,
        "parameter names are not part of the C ABI signature"
    );

    for replacement in [
        "static NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl, KPROCESSOR_MODE access_mode, LOCK_OPERATION operation) { return 0; }",
        "NTSTATUS NTAPI FsRingProbeAndLockPagesSeh(PMDL mdl, KPROCESSOR_MODE access_mode, LOCK_OPERATION operation) { return 0; }",
        "NTSTATUS FsRingProbeAndLockPagesSeh(PVOID mdl, KPROCESSOR_MODE access_mode, LOCK_OPERATION operation) { return 0; }",
        "NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl, LOCK_OPERATION operation, KPROCESSOR_MODE access_mode) { return 0; }",
    ] {
        assert_eq!(
            count_canonical_c_shim_definitions(
                replacement,
                "NTSTATUS",
                "FsRingProbeAndLockPagesSeh",
                PARAMETERS,
            ),
            0,
            "a qualified or signature-altered replacement is not canonical"
        );
    }
}

#[test]
fn c_seh_body_contract_locks_probe_try_except_and_failure_behavior() {
    let canonical = r#"
        NTSTATUS FsRingProbeAndLockPagesSeh(
            PMDL mdl,
            KPROCESSOR_MODE access_mode,
            LOCK_OPERATION operation)
        {
            __try {
                MmProbeAndLockPages(mdl, access_mode, operation);
                return STATUS_SUCCESS;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
    "#;
    assert!(c_shim_has_exact_seh_contract(
        canonical,
        CSehShimKind::ProbeAndLock
    ));
    let renamed = canonical
        .replace("mdl", "descriptor")
        .replace("access_mode", "mode")
        .replace("operation", "lock_operation");
    assert!(
        c_shim_has_exact_seh_contract(&renamed, CSehShimKind::ProbeAndLock),
        "consistent C parameter renames must preserve the body contract"
    );

    for rejected in [
        canonical.replace(
            "} __except (EXCEPTION_EXECUTE_HANDLER) {\n                return STATUS_INSUFFICIENT_RESOURCES;\n            }",
            "}",
        ),
        canonical.replace(
            "__try {\n                MmProbeAndLockPages(mdl, access_mode, operation);",
            "MmProbeAndLockPages(mdl, access_mode, operation);\n            __try {",
        ),
        canonical.replace(
            "} __except",
            "}\n            MmProbeAndLockPages(mdl, access_mode, operation);\n            __except",
        ),
        canonical.replace("EXCEPTION_EXECUTE_HANDLER", "EXCEPTION_CONTINUE_SEARCH"),
        canonical.replace("STATUS_INSUFFICIENT_RESOURCES", "STATUS_UNSUCCESSFUL"),
        canonical.replace("return STATUS_SUCCESS;", "return STATUS_UNSUCCESSFUL;"),
    ] {
        assert!(
            !c_shim_has_exact_seh_contract(&rejected, CSehShimKind::ProbeAndLock),
            "probe body mutation escaped the SEH contract: {rejected}"
        );
    }
}

#[test]
fn c_seh_body_contract_locks_map_status_null_and_exception_behavior() {
    let canonical = r#"
        PVOID FsRingMapLockedPagesSeh(
            PMDL mdl,
            KPROCESSOR_MODE access_mode,
            MEMORY_CACHING_TYPE cache_type,
            PVOID requested_address,
            ULONG bugcheck_on_failure,
            ULONG priority,
            NTSTATUS *status)
        {
            __try {
                PVOID address = MmMapLockedPagesSpecifyCache(
                    mdl, access_mode, cache_type, requested_address,
                    bugcheck_on_failure, priority);
                *status = address != NULL ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
                return address;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                *status = STATUS_INSUFFICIENT_RESOURCES;
                return NULL;
            }
        }
    "#;
    assert!(c_shim_has_exact_seh_contract(
        canonical,
        CSehShimKind::MapLockedPages
    ));
    let renamed = canonical
        .replace("mdl", "descriptor")
        .replace("access_mode", "mode")
        .replace("cache_type", "cache")
        .replace("requested_address", "requested")
        .replace("bugcheck_on_failure", "bugcheck")
        .replace("priority", "page_priority")
        .replace("status", "result_status");
    assert!(
        c_shim_has_exact_seh_contract(&renamed, CSehShimKind::MapLockedPages),
        "consistent map parameter renames must preserve the body contract"
    );

    for rejected in [
        canonical.replace(
            "__try {\n                PVOID address = MmMapLockedPagesSpecifyCache(",
            "MmMapLockedPagesSpecifyCache(mdl, access_mode, cache_type, requested_address, bugcheck_on_failure, priority);\n            __try {\n                PVOID address = MmMapLockedPagesSpecifyCache(",
        ),
        canonical.replace("EXCEPTION_EXECUTE_HANDLER", "EXCEPTION_CONTINUE_SEARCH"),
        canonical.replace(
            "*status = address != NULL ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;",
            "*status = STATUS_SUCCESS;",
        ),
        canonical.replace(
            "*status = STATUS_INSUFFICIENT_RESOURCES;\n                return NULL;",
            "return NULL;",
        ),
        canonical.replace("return NULL;", "return address;"),
        canonical.replace("STATUS_INSUFFICIENT_RESOURCES", "STATUS_UNSUCCESSFUL"),
    ] {
        assert!(
            !c_shim_has_exact_seh_contract(&rejected, CSehShimKind::MapLockedPages),
            "map body mutation escaped the SEH contract: {rejected}"
        );
    }
}

#[test]
fn c_owner_function_roster_rejects_helpers_and_raw_ddi_adapters() {
    let shims = r#"
        NTSTATUS FsRingProbeAndLockPagesSeh(PMDL mdl) { return 0; }
        PVOID FsRingMapLockedPagesSeh(PMDL mdl) { return NULL; }
    "#;
    let expected = ["FsRingProbeAndLockPagesSeh", "FsRingMapLockedPagesSeh"];
    assert!(c_has_exact_top_level_function_roster(shims, &expected));
    assert!(!c_has_exact_top_level_function_roster(
        &std::format!(
            "{shims}\nNTSTATUS HiddenProbe(PMDL mdl) {{ MmProbeAndLockPages(mdl, 0, 0); return 0; }}"
        ),
        &expected,
    ));
    assert!(!c_has_exact_top_level_function_roster(
        &std::format!(
            "{shims}\nPVOID HiddenMap(PMDL mdl) {{ return MmMapLockedPagesSpecifyCache(mdl, 0, 0, 0, 0, 0); }}"
        ),
        &expected,
    ));
    assert!(c_has_exact_top_level_function_roster(
        &std::format!(
            "#define HIDDEN() NTSTATUS HiddenProbe(PMDL mdl) {{ return 0; }}\n{shims}\nNTSTATUS HiddenProbe(PMDL mdl);"
        ),
        &expected,
    ));
}

#[test]
fn c_definition_scan_ignores_directive_text_and_nested_macro_choreography() {
    let direct_macro =
        "#define DECLARE_PROBE NTSTATUS FsRingProbeAndLockPagesSeh(void) { return 0; }";
    assert_eq!(
        count_c_shim_definitions(direct_macro, "NTSTATUS", "FsRingProbeAndLockPagesSeh"),
        0
    );

    let continued_macro = concat!(
        "#define DECLARE_PROBE() \\\n",
        "    NTSTATUS FsRingProbeAndLockPagesSeh(void) \\\n",
        "    { return 0; }\n",
        "DECLARE_PROBE()"
    );
    assert_eq!(
        count_c_shim_definitions(continued_macro, "NTSTATUS", "FsRingProbeAndLockPagesSeh"),
        0
    );

    let nested_macro_argument = "EMIT(NTSTATUS FsRingProbeAndLockPagesSeh(void) { return 0; })";
    assert_eq!(
        count_c_shim_definitions(
            nested_macro_argument,
            "NTSTATUS",
            "FsRingProbeAndLockPagesSeh"
        ),
        0
    );

    let internal_linkage = "static NTSTATUS FsRingProbeAndLockPagesSeh(void) { return 0; }";
    assert_eq!(
        count_c_shim_definitions(internal_linkage, "NTSTATUS", "FsRingProbeAndLockPagesSeh"),
        0
    );
}

#[test]
fn c_owner_requires_one_exact_include_and_no_preprocessor_choreography() {
    assert!(c_owner_has_exact_preprocessor_contract(
        "#include <ntifs.h>\nNTSTATUS ordinary_code;"
    ));
    assert!(c_owner_has_exact_preprocessor_contract(
        "/* #if 0 */\n#include <ntifs.h>\n// #define DECOY\nconst char *text = \"#endif\";"
    ));

    for rejected in [
        "NTSTATUS no_include;",
        "#include <ntifs.h>\n#include <ntifs.h>",
        "#include <wdm.h>",
        "NTSTATUS code; #include <ntifs.h>",
        "#include <ntifs.h>\n   #define DECLARE_SHIM NTSTATUS",
        concat!(
            "#include <ntifs.h>\n",
            "#define DECLARE_SHIM() \\\n",
            "    NTSTATUS generated\n"
        ),
        "#include <ntifs.h>\n#if 0\nNTSTATUS hidden;\n#endif",
    ] {
        assert!(!c_owner_has_exact_preprocessor_contract(rejected));
    }
}

#[test]
fn round5_c_owner_rejects_msvc_digraph_preprocessor_directives() {
    let canonical = "#include <ntifs.h>\nNTSTATUS owner_code;\n";
    assert!(c_owner_has_exact_preprocessor_contract(canonical));
    assert!(c_owner_has_exact_preprocessor_contract(
        "#include <ntifs.h>\nconst char *text = \"%:include <ntddk.h>\";\n/* %:if 0 */\n// %:endif\n"
    ));

    for digraph in [
        "%:include <ntddk.h>\n",
        "%:if 0\nNTSTATUS hidden;\n%:endif\n",
    ] {
        let mutated = std::format!("{canonical}{digraph}");
        assert!(
            !c_owner_has_exact_preprocessor_contract(&mutated),
            "MSVC-active digraph preprocessing escaped the exact owner contract: {digraph}"
        );
    }
}

#[test]
fn raising_mapping_symbol_scan_catches_alias_whitespace_and_multiline_bypasses() {
    assert!(mentions_raising_mapping_call(
        "use wdk_sys::ntddk::MmProbeAndLockPages as probe_and_lock;"
    ));
    assert!(mentions_raising_mapping_call(
        "MmProbeAndLockPages   (mdl, KernelMode, IoReadAccess);"
    ));
    assert!(mentions_raising_mapping_call(
        "MmMapLockedPagesSpecifyCache\n    (mdl, UserMode, MmCached, 0, 0, priority);"
    ));
    assert!(!mentions_raising_mapping_call(
        "let MmProbeAndLockPagesWrapper = contained_probe;"
    ));
}

#[test]
fn rust_declaration_tokens_ignore_decoys_and_count_formatted_declarations() {
    let source = r####"
        #[doc = "pub fn FsRingProbeAndLockPagesSeh("]
        #[cfg_attr(any(), doc = r#"pub fn FsRingProbeAndLockPagesSeh("#)]
        pub
        fn
        FsRingProbeAndLockPagesSeh
        /* formatting is immaterial */
        (
            mdl: *mut MDL,
        );

        // pub fn FsRingProbeAndLockPagesSeh();
        /* outer /* pub fn FsRingProbeAndLockPagesSeh(); */ still outer */
        const TEXT: &str = "pub fn FsRingProbeAndLockPagesSeh(";
        const RAW: &str = r###"pub fn FsRingProbeAndLockPagesSeh("###;
        const BYTES: &[u8] = b"pub fn FsRingProbeAndLockPagesSeh(";
        const RAW_BYTES: &[u8] = br###"pub fn FsRingProbeAndLockPagesSeh("###;
        const CHARACTER: char = 'p';
        const BYTE: u8 = b'p';
        pub fn FsRingProbeAndLockPagesSehWrapper();
    "####;

    assert_eq!(
        count_rust_shim_declarations(source, "FsRingProbeAndLockPagesSeh"),
        Some(1)
    );
}

#[test]
fn rust_declaration_tokens_count_every_structural_fn_form_and_raw_identifier() {
    for declaration in [
        "pub(crate) fn FsRingProbeAndLockPagesSeh(mdl: *mut MDL);",
        "pub unsafe fn FsRingProbeAndLockPagesSeh(mdl: *mut MDL);",
        "unsafe extern \"C\" fn r#FsRingProbeAndLockPagesSeh(mdl: *mut MDL);",
    ] {
        assert_eq!(
            count_rust_shim_declarations(declaration, "FsRingProbeAndLockPagesSeh"),
            Some(1),
            "valid structural declaration was not counted: {declaration}"
        );
    }
}

#[test]
fn rust_shim_reference_audit_rejects_alias_binding_and_parenthesized_call_bypasses() {
    let root = std::path::Path::new("driver");
    let source = r#"
        unsafe { fsring_sys::FsRingProbeAndLockPagesSeh(mdl, mode, operation); }
        use fsring_sys::FsRingProbeAndLockPagesSeh as hidden_probe;
        unsafe { hidden_probe(mdl, mode, operation); }
        let probe = fsring_sys::FsRingProbeAndLockPagesSeh;
        unsafe { probe(mdl, mode, operation); }
        unsafe { (fsring_sys::FsRingProbeAndLockPagesSeh)(mdl, mode, operation); }
    "#;

    assert_eq!(
        audit_rust_shim_references(
            source,
            std::path::Path::new("driver/fsring-fsd/src/seh.rs"),
            root,
            "FsRingProbeAndLockPagesSeh"
        ),
        Some(ShimReferenceAudit {
            roles: [0, 0, 0, 1],
            unapproved: 3,
        })
    );
}

#[test]
fn rust_shim_reference_audit_accepts_only_the_four_exact_roles_and_paths() {
    let root = std::path::Path::new("driver");
    for (path, source, roles) in [
        (
            "driver/fsring-sys/src/c4.rs",
            "pub unsafe fn r#FsRingMapLockedPagesSeh(mdl: *mut MDL);",
            [1, 0, 0, 0],
        ),
        (
            "driver/fsring-sys/src/lib.rs",
            "pub use c4::{FsRingMapLockedPagesSeh, Other};",
            [0, 1, 0, 0],
        ),
        (
            "driver/fsring-fsd/src/lib.rs",
            "const _: unsafe extern \"C\" fn() = fsring_sys::FsRingMapLockedPagesSeh;",
            [0, 0, 1, 0],
        ),
        (
            "driver/fsring-fsd/src/seh.rs",
            "unsafe { fsring_sys::FsRingMapLockedPagesSeh() };",
            [0, 0, 0, 1],
        ),
    ] {
        assert_eq!(
            audit_rust_shim_references(
                source,
                std::path::Path::new(path),
                root,
                "FsRingMapLockedPagesSeh"
            ),
            Some(ShimReferenceAudit {
                roles,
                unapproved: 0,
            }),
            "approved structural role was not recognized at {path}"
        );
    }

    assert_eq!(
        audit_rust_shim_references(
            "let map = fsring_sys::r#FsRingMapLockedPagesSeh;",
            std::path::Path::new("driver/fsring-fsd/src/seh.rs"),
            root,
            "FsRingMapLockedPagesSeh"
        ),
        Some(ShimReferenceAudit {
            roles: [0; 4],
            unapproved: 1,
        })
    );
}

#[test]
fn canonical_rust_shim_declaration_requires_one_foreign_c_item_without_a_body() {
    const PARAMETERS: &[&[&str]] = &[
        &["*", "mut", "MDL"],
        &["KPROCESSOR_MODE"],
        &["LOCK_OPERATION"],
    ];
    let canonical = r#"
        unsafe extern "C" {
            pub fn FsRingProbeAndLockPagesSeh(
                mdl: *mut MDL,
                access_mode: KPROCESSOR_MODE,
                operation: LOCK_OPERATION,
            ) -> NTSTATUS;
        }
    "#;
    assert_eq!(
        count_canonical_rust_shim_foreign_declarations(
            canonical,
            "FsRingProbeAndLockPagesSeh",
            PARAMETERS,
            &["NTSTATUS"],
        ),
        Some(1)
    );
    let renamed = r#"
        unsafe extern "C" {
            pub fn FsRingProbeAndLockPagesSeh(
                descriptor: *mut MDL,
                mode: KPROCESSOR_MODE,
                lock_operation: LOCK_OPERATION,
            ) -> NTSTATUS;
        }
    "#;
    assert_eq!(
        count_canonical_rust_shim_foreign_declarations(
            renamed,
            "FsRingProbeAndLockPagesSeh",
            PARAMETERS,
            &["NTSTATUS"],
        ),
        Some(1),
        "foreign parameter names are not part of the Rust ABI"
    );

    for replacement in [
        r#"pub unsafe fn FsRingProbeAndLockPagesSeh(mdl: *mut MDL, access_mode: KPROCESSOR_MODE, operation: LOCK_OPERATION) -> NTSTATUS { MmProbeAndLockPages(mdl, access_mode, operation); STATUS_SUCCESS }"#,
        r#"unsafe extern "system" { pub fn FsRingProbeAndLockPagesSeh(mdl: *mut MDL, access_mode: KPROCESSOR_MODE, operation: LOCK_OPERATION) -> NTSTATUS; }"#,
        r#"extern "C" { pub fn FsRingProbeAndLockPagesSeh(mdl: *mut MDL, access_mode: KPROCESSOR_MODE, operation: LOCK_OPERATION) -> NTSTATUS; }"#,
        r#"unsafe extern "C" { pub fn FsRingProbeAndLockPagesSeh(mdl: *mut MDL, operation: LOCK_OPERATION, access_mode: KPROCESSOR_MODE) -> NTSTATUS; }"#,
        r#"unsafe extern "C" { pub fn FsRingProbeAndLockPagesSeh(mdl: *mut MDL, access_mode: KPROCESSOR_MODE, operation: LOCK_OPERATION) -> PVOID; }"#,
        r#"unsafe extern "C" { pub fn FsRingProbeAndLockPagesSeh(mdl: *mut MDL, access_mode: KPROCESSOR_MODE, operation: LOCK_OPERATION) -> NTSTATUS {} }"#,
        r#"unsafe extern "C" { pub fn FsRingProbeAndLockPagesSeh(mdl: *mut MDL, access_mode: KPROCESSOR_MODE, operation: LOCK_OPERATION) -> NTSTATUS; } unsafe extern "C" {}"#,
    ] {
        assert_eq!(
            count_canonical_rust_shim_foreign_declarations(
                replacement,
                "FsRingProbeAndLockPagesSeh",
                PARAMETERS,
                &["NTSTATUS"],
            ),
            Some(0),
            "non-foreign, wrong-ABI, wrong-signature, body, or second-block replacement was accepted: {replacement}"
        );
    }
    assert_eq!(
        count_canonical_rust_shim_foreign_declarations(
            r#"unsafe extern "C" { pub fn FsRingProbeAndLockPagesSeh("#,
            "FsRingProbeAndLockPagesSeh",
            PARAMETERS,
            &["NTSTATUS"],
        ),
        None
    );
}

#[test]
fn c4_rust_foreign_item_roster_is_exact_and_closed() {
    let canonical = r#"
        unsafe extern "C" {
            pub fn ZwQuerySection();
            pub static mut MmSectionObjectType: *mut POBJECT_TYPE;
            pub fn FsRingProbeAndLockPagesSeh(mdl: *mut MDL) -> NTSTATUS;
            pub fn FsRingMapLockedPagesSeh(mdl: *mut MDL) -> PVOID;
        }
    "#;
    assert_eq!(rust_c4_has_exact_foreign_item_roster(canonical), Some(true));
    for rejected in [
        canonical.replace(
            "pub fn ZwQuerySection();",
            "pub fn ZwQuerySection(); pub fn HiddenProbe();",
        ),
        canonical.replace(
            "pub static mut MmSectionObjectType: *mut POBJECT_TYPE;",
            "pub static mut MmSectionObjectType: *mut POBJECT_TYPE; pub static mut Hidden: usize;",
        ),
        canonical.replace("pub fn ZwQuerySection();", ""),
        std::format!("{canonical}\nunsafe extern \"C\" {{ pub fn HiddenProbe(); }}"),
    ] {
        assert_eq!(
            rust_c4_has_exact_foreign_item_roster(&rejected),
            Some(false),
            "extra, missing, or second-block foreign item escaped the C4 roster: {rejected}"
        );
    }
    assert_eq!(
        rust_c4_has_exact_foreign_item_roster(r#"unsafe extern "C" { pub fn ZwQuerySection();"#),
        None
    );
}

#[test]
fn round5_rust_c4_roster_rejects_extra_abi_blocks_and_item_macros() {
    let owner_path = driver_root().join("fsring-sys/src/c4.rs");
    let canonical = read_security_text(&owner_path).expect("the Rust C4 owner must be readable");
    assert_eq!(
        rust_c4_has_exact_foreign_item_roster(&canonical),
        Some(true)
    );

    for extra_block in [
        r#"unsafe extern "system" { pub fn HiddenSystemForeign(); }"#,
        r#"unsafe extern "C-unwind" { pub fn HiddenUnwindForeign(); }"#,
    ] {
        let mutated = std::format!("{canonical}\n{extra_block}\n");
        assert_eq!(
            rust_c4_has_exact_foreign_item_roster(&mutated),
            Some(false),
            "an additional structural extern block escaped: {extra_block}"
        );
    }

    let with_item_macro = canonical.replacen(
        "\n}\n\nconst _: ()",
        "\n    hidden_foreign_items! {}\n}\n\nconst _: ()",
        1,
    );
    assert_ne!(
        with_item_macro, canonical,
        "the owner mutation must be live"
    );
    assert_eq!(
        rust_c4_has_exact_foreign_item_roster(&with_item_macro),
        Some(false),
        "an item-macro invocation inside the approved block must break the exact roster"
    );
}

#[test]
fn rust_typed_call_tokens_count_every_real_call_and_ignore_decoys() {
    let source = r####"
        #[doc = "fsring_sys::FsRingMapLockedPagesSeh("]
        /* outer /* fsring_sys::FsRingMapLockedPagesSeh() */ still outer */
        let _ = "fsring_sys::FsRingMapLockedPagesSeh(";
        let _ = r###"fsring_sys::FsRingMapLockedPagesSeh("###;
        let _ = b"fsring_sys::FsRingMapLockedPagesSeh(";
        let _ = br###"fsring_sys::FsRingMapLockedPagesSeh("###;
        let _ = other_fsring_sys::FsRingMapLockedPagesSeh();
        let _ = fsring_sys::FsRingMapLockedPagesSehWrapper();
        let _ = fsring_sys :: FsRingMapLockedPagesSeh (first); let _ = fsring_sys::FsRingMapLockedPagesSeh(second);
    "####;

    assert_eq!(
        count_typed_rust_shim_calls(source, "FsRingMapLockedPagesSeh"),
        Some(2)
    );
}

#[test]
fn rust_raising_symbol_tokens_ignore_literal_comment_and_substring_decoys() {
    let decoys = r####"
        #[doc = "MmProbeAndLockPages"]
        // MmProbeAndLockPages
        /* outer /* MmMapLockedPagesSpecifyCache */ still outer */
        let _ = "MmProbeAndLockPages";
        let _ = r###"MmMapLockedPagesSpecifyCache"###;
        let _ = b"MmProbeAndLockPages";
        let _ = br###"MmMapLockedPagesSpecifyCache"###;
        let _ = 'M';
        let _ = b'M';
        let MmProbeAndLockPagesWrapper = contained_probe;
    "####;
    assert_eq!(
        rust_source_mentions_raising_mapping_symbol(decoys),
        Some(false)
    );
    assert_eq!(
        rust_source_mentions_raising_mapping_symbol(
            "use wdk_sys::ntddk::MmProbeAndLockPages as probe;"
        ),
        Some(true)
    );
}

#[test]
fn rust_macro_audit_rejects_raising_ddis_in_active_definitions_and_invocations() {
    for (source, expected) in [
        (
            r#"
                macro_rules! hidden_raising_call {
                    () => { MmProbeAndLockPages(mdl, mode, operation); };
                }
                hidden_raising_call!();
            "#,
            "MmProbeAndLockPages",
        ),
        (
            r#"
                macro_rules! expand_tokens {
                    ($($tokens:tt)*) => { $($tokens)* };
                }
                expand_tokens! {
                    MmMapLockedPagesSpecifyCache(mdl, mode, cache, address, 0, priority)
                }
            "#,
            "MmMapLockedPagesSpecifyCache",
        ),
    ] {
        assert_eq!(
            rust_macro_context_c4_offender(source),
            Some(Some(expected)),
            "active macro raising call escaped the audit"
        );
    }
}

#[test]
fn rust_macro_audit_rejects_typed_shim_calls_in_active_definitions_and_invocations() {
    for (source, expected) in [
        (
            r#"
                macro_rules! hidden_typed_call {
                    () => { fsring_sys::FsRingMapLockedPagesSeh(); };
                }
                hidden_typed_call!();
            "#,
            "FsRingMapLockedPagesSeh",
        ),
        (
            r#"
                macro_rules! expand_tokens {
                    ($($tokens:tt)*) => { $($tokens)* };
                }
                expand_tokens! { fsring_sys::FsRingProbeAndLockPagesSeh(); }
            "#,
            "FsRingProbeAndLockPagesSeh",
        ),
    ] {
        assert_eq!(
            rust_macro_context_c4_offender(source),
            Some(Some(expected)),
            "active macro typed shim call escaped the audit"
        );
    }
}

#[test]
fn rust_macro_audit_rejects_generated_shim_declarations_and_raw_identifiers() {
    for (source, expected) in [
        (
            r#"
                macro_rules! hidden_declaration {
                    () => { pub unsafe fn FsRingProbeAndLockPagesSeh(); };
                }
                hidden_declaration!();
            "#,
            "FsRingProbeAndLockPagesSeh",
        ),
        (
            r#"
                macro_rules! emit_item {
                    ($item:item) => { $item };
                }
                emit_item! { pub(crate) fn r#FsRingMapLockedPagesSeh(); }
            "#,
            "FsRingMapLockedPagesSeh",
        ),
    ] {
        assert_eq!(
            rust_macro_context_c4_offender(source),
            Some(Some(expected)),
            "active macro shim declaration escaped the audit"
        );
    }
}

#[test]
fn rust_macro_audit_ignores_literal_comment_and_identifier_substring_decoys() {
    let decoys = r####"
        macro_rules! literal_decoys {
            () => {{
                // MmProbeAndLockPages FsRingProbeAndLockPagesSeh
                /* outer /* MmMapLockedPagesSpecifyCache */ FsRingMapLockedPagesSeh */
                let _ = "MmProbeAndLockPages FsRingProbeAndLockPagesSeh";
                let _ = r###"MmMapLockedPagesSpecifyCache FsRingMapLockedPagesSeh"###;
                let _ = b"MmProbeAndLockPages FsRingProbeAndLockPagesSeh";
                let _ = br###"MmMapLockedPagesSpecifyCache FsRingMapLockedPagesSeh"###;
                let MmProbeAndLockPagesWrapper = FsRingProbeAndLockPagesSehWrapper;
            }};
        }
        literal_decoys!("MmProbeAndLockPages", r###"FsRingMapLockedPagesSeh"###);
    "####;

    assert_eq!(rust_macro_context_c4_offender(decoys), Some(None));
    assert_eq!(
        rust_macro_context_c4_offender("emit!({ MmProbeAndLockPages(mdl) "),
        None
    );
}

#[test]
fn rust_token_scans_accept_valid_raw_macro_rules_names() {
    let source = r#"
        macro_rules! r#emit_tokens {
            () => { let ordinary = 1; };
        }
        r#emit_tokens!();
    "#;

    assert!(rust_code_tokens(source).is_some());
    assert_eq!(rust_macro_context_c4_offender(source), Some(None));
}

#[test]
fn rust_token_scans_ignore_c_raw_string_decoys_and_fail_closed() {
    let source = r#####"
        const C_RAW: &core::ffi::CStr = cr###"embedded " quote
            FsRingProbeAndLockPagesSeh MmProbeAndLockPages
            include!("hidden.rs") #[path = "hidden.rs"] extern "C" {
        "###;
    "#####;
    let tokens = rust_code_tokens(source).expect("a valid C raw string must remain one literal");
    assert!(!rust_tokens_mention_raising_mapping_symbol(&tokens));
    assert_eq!(
        count_rust_shim_declarations(source, "FsRingProbeAndLockPagesSeh"),
        Some(0)
    );
    assert_eq!(rust_macro_context_c4_offender(source), Some(None));
    assert_eq!(rust_attribute_context_c4_offender(source), Some(None));
    assert_eq!(rust_source_closure_offender(source), Some(None));
    assert_eq!(rust_code_tokens(r#"cr###"unterminated"#), None);
}

#[test]
fn rust_attribute_audit_rejects_outer_inner_nested_and_raw_reserved_identifiers() {
    for (source, expected) in [
        (
            "#[task(FsRingProbeAndLockPagesSeh)] fn outer() {}",
            "FsRingProbeAndLockPagesSeh",
        ),
        (
            "#![task(MmProbeAndLockPages)] mod inner {}",
            "MmProbeAndLockPages",
        ),
        (
            "#[cfg_attr(any(), task(nested(MmMapLockedPagesSpecifyCache)))] fn nested() {}",
            "MmMapLockedPagesSpecifyCache",
        ),
        (
            "#[task(r#FsRingMapLockedPagesSeh)] fn raw() {}",
            "FsRingMapLockedPagesSeh",
        ),
    ] {
        assert_eq!(
            rust_attribute_context_c4_offender(source),
            Some(Some(expected)),
            "reserved attribute token escaped the audit: {source}"
        );
    }
}

#[test]
fn rust_attribute_audit_ignores_literal_comment_and_substring_decoys_and_fails_closed() {
    let decoys = r####"
        #[task(
            "MmProbeAndLockPages",
            r###"MmMapLockedPagesSpecifyCache"###,
            b"FsRingProbeAndLockPagesSeh",
            br###"FsRingMapLockedPagesSeh"###,
            MmProbeAndLockPagesWrapper,
            /* FsRingProbeAndLockPagesSeh */
        )]
        fn decoys() {}
    "####;
    assert_eq!(rust_attribute_context_c4_offender(decoys), Some(None));
    assert_eq!(
        rust_attribute_context_c4_offender("#[task(FsRingProbeAndLockPagesSeh) fn broken() {}"),
        None
    );
}

#[test]
fn rust_source_closure_audit_rejects_include_macros_in_every_token_context() {
    for source in [
        r#"include!("hidden.inc");"#,
        r#"include ! (concat!(env!("OUT_DIR"), "/hidden.rs"));"#,
        r#"outer!({ include!("hidden.rs"); });"#,
        r#"macro_rules! emit { () => { include!("hidden.rs"); }; }"#,
        r#"r#include!("hidden.rs");"#,
    ] {
        assert_eq!(
            rust_source_closure_offender(source),
            Some(Some(RustSourceClosureOffender::IncludeMacro)),
            "structural include! escaped the source-closure audit: {source}"
        );
    }
}

#[test]
fn rust_source_closure_audit_rejects_outer_inner_nested_and_raw_path_attributes() {
    for source in [
        r#"#[path = "hidden.rs"] mod hidden;"#,
        r#"#![path = "hidden.rs"]"#,
        r#"#[cfg_attr(windows, path = "hidden.rs")] mod hidden;"#,
        r#"#[cfg_attr(windows, cfg_attr(test, r#path = "hidden.rs"))] mod hidden;"#,
        r#"#[path = "../../../tests/compile-fail/hidden.rs"] mod hidden;"#,
        r#"#[path = "../../../../outside.rs"] mod hidden;"#,
    ] {
        assert_eq!(
            rust_source_closure_offender(source),
            Some(Some(RustSourceClosureOffender::PathAttribute)),
            "structural path attribute escaped the source-closure audit: {source}"
        );
    }
}

#[test]
fn rust_source_closure_audit_ignores_decoys_and_fails_closed_on_malformed_syntax() {
    let decoys = r####"
        // include!("comment.rs");
        /* #[path = "comment.rs"] */
        const TEXT: &str = "include!(\"string.rs\") #[path = \"string.rs\"]";
        const RAW: &str = r###"include!("raw.rs") #[path = "raw.rs"]"###;
        const BYTES: &[u8] = b"include!(\"bytes.rs\")";
        include_bytes!("data.bin");
        let include_wrapper = 1;
        #[doc = "path = hidden.rs"]
        fn ordinary() {}
    "####;
    assert_eq!(rust_source_closure_offender(decoys), Some(None));

    for malformed in [
        r#"include!("unterminated.rs""#,
        r#"#[path = "unterminated.rs" mod hidden;"#,
        r#"outer!({ include!("hidden.rs"); }"#,
    ] {
        assert_eq!(
            rust_source_closure_offender(malformed),
            None,
            "malformed source-closure syntax must fail closed: {malformed}"
        );
    }
}

#[test]
fn structural_rust_extern_scan_finds_multiline_and_token_tree_blocks() {
    for source in [
        "unsafe\nextern \"C\"\n{ fn hidden(); }",
        "pub unsafe extern \"system\" { fn hidden(); }",
        "extern \"C\"\n#[cfg(any())]\n{ fn hidden(); }",
        "emit!({ extern \"C\" { fn hidden(); } });",
        "#[tokens(extern \"C\" { fn hidden(); })] fn item() {}",
    ] {
        assert_eq!(
            count_structural_rust_extern_blocks(source),
            Some(1),
            "extern block escaped the structural scan: {source}"
        );
    }

    for source in [
        "pub unsafe extern \"C\" fn exported() {}",
        "extern \"C\"\n#[cfg(any())]\nfn exported() {}",
        "extern crate alloc;",
        r#"const TEXT: &str = "extern \"C\" { fn hidden(); }";"#,
    ] {
        assert_eq!(
            count_structural_rust_extern_blocks(source),
            Some(0),
            "extern function/decoy was misclassified as a block: {source}"
        );
    }
}

#[test]
fn structural_rust_extern_scan_rejects_link_name_aliases_and_fails_closed() {
    for source in [
        r#"#[link_name = "FsRingMapLockedPagesSeh"] fn hidden();"#,
        r#"#[cfg_attr(windows, link_name = "FsRingProbeAndLockPagesSeh")] fn hidden();"#,
        r#"#[cfg_attr(windows, cfg_attr(test, r#link_name = "ordinary"))] fn hidden();"#,
    ] {
        assert_eq!(
            count_structural_rust_link_name_attributes(source),
            Some(1),
            "link_name alias escaped the structural scan: {source}"
        );
    }
    let decoys = r####"
        // #[link_name = "FsRingMapLockedPagesSeh"]
        /* link_name = "FsRingProbeAndLockPagesSeh" */
        #[doc = "link_name = FsRingMapLockedPagesSeh"]
        const TEXT: &str = r###"#[link_name = "FsRingProbeAndLockPagesSeh"]"###;
    "####;
    assert_eq!(count_structural_rust_link_name_attributes(decoys), Some(0));

    for malformed in [
        "extern \"C\" { fn hidden();",
        r#"#[link_name = "unterminated" fn hidden();"#,
        "emit!({ extern \"C\" { fn hidden(); }",
    ] {
        assert_eq!(count_structural_rust_extern_blocks(malformed), None);
        assert_eq!(count_structural_rust_link_name_attributes(malformed), None);
    }
}

#[test]
fn build_script_cc_input_is_exactly_the_single_c4_source() {
    let canonical = r#"
        let mut build = cc::Build::new();
        build
            .file(Path::new("native/c4_seh.c"))
            .flag("/W4")
            .compile("fsring_c4_seh");
    "#;
    assert_eq!(
        rust_build_script_has_exact_c4_cc_input(canonical),
        Some(true)
    );

    for rejected in [
        canonical.replace(".flag(\"/W4\")", ".file(\"native/extra.c\").flag(\"/W4\")"),
        canonical.replace(
            ".flag(\"/W4\")",
            ".files([\"native/extra.c\"]).flag(\"/W4\")",
        ),
        canonical.replace(
            ".flag(\"/W4\")",
            ".object(\"native/extra.obj\").flag(\"/W4\")",
        ),
        canonical.replace(
            ".flag(\"/W4\")",
            ".objects([\"native/extra.obj\"]).flag(\"/W4\")",
        ),
        canonical.replace(
            "Path::new(\"native/c4_seh.c\")",
            "out_dir.join(\"generated.c\")",
        ),
        canonical.replace(
            "Path::new(\"native/c4_seh.c\")",
            "Path::new(concat!(env!(\"OUT_DIR\"), \"/generated.c\"))",
        ),
    ] {
        assert_eq!(
            rust_build_script_has_exact_c4_cc_input(&rejected),
            Some(false),
            "extra, object, generated, or dynamic cc input escaped: {rejected}"
        );
    }

    let decoys = r####"
        // build.file("native/extra.c");
        const TEXT: &str = r###".files(["native/extra.c"])"###;
        build.file(Path::new("native/c4_seh.c")).compile("fsring_c4_seh");
    "####;
    assert_eq!(rust_build_script_has_exact_c4_cc_input(decoys), Some(true));
    assert_eq!(
        rust_build_script_has_exact_c4_cc_input(
            r#"build.file(Path::new("native/c4_seh.c")); emit!({"#
        ),
        None
    );
}

#[test]
fn round5_build_choreography_rejects_ufcs_delegation_and_source_flags() {
    let build_path = driver_root().join("fsring-fsd/build.rs");
    let canonical = read_security_text(&build_path).expect("the fsd build script must be readable");
    assert_eq!(
        rust_build_script_has_exact_c4_build_choreography(&canonical),
        Some(true)
    );

    let mutations = [
        canonical.replacen(
            "let mut build = cc::Build::new();",
            "let mut build = cc::Build::new();\n    cc::Build::file(&mut build, \"native/extra.c\");",
            1,
        ),
        canonical.replacen(
            "let mut build = cc::Build::new();",
            "let mut build = cc::Build::new();\n    let add = cc::Build::file;\n    add(&mut build, \"native/extra.c\");",
            1,
        ),
        std::format!(
            "mod task9_helper;\n{}",
            canonical.replacen(
                "let mut build = cc::Build::new();",
                "let mut build = cc::Build::new();\n    task9_helper::add(&mut build);",
                1,
            )
        ),
        canonical.replacen(
            ".compile(\"fsring_c4_seh\")",
            ".flag(\"/FInative/extra.h\").compile(\"fsring_c4_seh\")",
            1,
        ),
        canonical.replacen(
            ".compile(\"fsring_c4_seh\")",
            ".flag(\"@native/extra.rsp\").compile(\"fsring_c4_seh\")",
            1,
        ),
        canonical.replacen(
            ".compile(\"fsring_c4_seh\")",
            ".flag(\"/Tcnative/extra.c\").compile(\"fsring_c4_seh\")",
            1,
        ),
    ];
    for mutation in mutations {
        assert_ne!(
            mutation, canonical,
            "the build-script mutation must be live"
        );
        assert_eq!(
            rust_build_script_has_exact_c4_build_choreography(&mutation),
            Some(false),
            "unapproved cc choreography escaped:\n{mutation}"
        );
    }

    let decoys = std::format!(
        r####"{canonical}
            // cc::Build::file(&mut build, "native/extra.c");
            const ROUND5_DECOY: &str = r###"mod helper; .flag("/FIextra.h") @extra.rsp /Tcextra.c"###;
        "####
    );
    assert_eq!(
        rust_build_script_has_exact_c4_build_choreography(&decoys),
        Some(true)
    );
}

#[test]
fn round5_build_choreography_rejects_initializer_chains() {
    let build_path = driver_root().join("fsring-fsd/build.rs");
    let canonical = read_security_text(&build_path).expect("the fsd build script must be readable");
    assert_eq!(
        rust_build_script_has_exact_c4_build_choreography(&canonical),
        Some(true)
    );

    for chained_initializer in [
        "let mut build = cc::Build::new().cpp(true);",
        "let mut build = cc::Build::new().compiler(\"wrapper\");",
        "let mut build = cc::Build::new().cargo_metadata(false);",
    ] {
        let mutation =
            canonical.replacen("let mut build = cc::Build::new();", chained_initializer, 1);
        assert_ne!(mutation, canonical, "the initializer mutation must be live");
        assert_eq!(
            rust_build_script_has_exact_c4_build_choreography(&mutation),
            Some(false),
            "a chained Build::new initializer escaped: {chained_initializer}"
        );
    }
}

#[test]
fn round5_build_choreography_rejects_macro_hidden_configuration() {
    let build_path = driver_root().join("fsring-fsd/build.rs");
    let canonical = read_security_text(&build_path).expect("the fsd build script must be readable");
    assert_eq!(
        rust_build_script_has_exact_c4_build_choreography(&canonical),
        Some(true),
        "the real println! format-string macros must remain valid decoys"
    );

    for hidden_configuration in [
        r#"
    macro_rules! hidden_ufcs_input {
        ($builder:expr) => { cc::Build::file($builder, "native/extra.c"); };
    }
    hidden_ufcs_input!(&mut build);"#,
        r#"
    macro_rules! hidden_dot_input {
        ($builder:expr) => { $builder.file("native/extra.c"); };
    }
    hidden_dot_input!(&mut build);"#,
        r#"
    macro_rules! hidden_source_flag {
        ($builder:expr) => { $builder.flag("/FInative/extra.h"); };
    }
    hidden_source_flag!(&mut build);"#,
    ] {
        let mutation = canonical.replacen(
            "let mut build = cc::Build::new();",
            &std::format!("let mut build = cc::Build::new();{hidden_configuration}"),
            1,
        );
        assert_ne!(mutation, canonical, "the macro mutation must be live");
        assert_eq!(
            rust_build_script_has_exact_c4_build_choreography(&mutation),
            Some(false),
            "macro-hidden build configuration escaped:\n{hidden_configuration}"
        );
    }
}

#[test]
fn rust_token_scan_skips_nested_groups_without_losing_following_code_and_fails_closed() {
    let nested_then_real = r#"
        emit!({ [ (fsring_sys::FsRingProbeAndLockPagesSeh()) ] });
        #[allow(dead_code)]
        let _ = fsring_sys :: FsRingProbeAndLockPagesSeh ();
    "#;
    assert_eq!(
        count_typed_rust_shim_calls(nested_then_real, "FsRingProbeAndLockPagesSeh"),
        Some(1)
    );

    for malformed in [
        "emit!({ fsring_sys::FsRingProbeAndLockPagesSeh() ",
        "#[allow(dead_code) let _ = fsring_sys::FsRingProbeAndLockPagesSeh();",
        "\"unterminated",
        "r###\"unterminated",
        "/* unterminated",
        "let _ = fsring_sys::FsRingProbeAndLockPagesSeh());",
    ] {
        assert_eq!(
            count_typed_rust_shim_calls(malformed, "FsRingProbeAndLockPagesSeh"),
            None
        );
    }
}

#[test]
fn rust_token_scan_accepts_multiline_strings_without_losing_following_code() {
    let source = "let _ = \"ordinary\nstring\";\n\
        let _ = c\"C\nstring\";\n\
        let _ = fsring_sys::FsRingProbeAndLockPagesSeh();";
    assert_eq!(
        count_typed_rust_shim_calls(source, "FsRingProbeAndLockPagesSeh"),
        Some(1)
    );
}

#[test]
fn shim_ownership_requires_the_exact_rust_and_c_paths() {
    let root = std::path::Path::new("driver");
    assert!(is_rust_shim_declaration_owner(
        std::path::Path::new("driver/fsring-sys/src/c4.rs"),
        root
    ));
    assert!(is_c_shim_definition_owner(
        std::path::Path::new("driver/fsring-fsd/native/c4_seh.c"),
        root
    ));

    assert!(!is_rust_shim_declaration_owner(
        std::path::Path::new("driver/fsring-sys-decoy/src/c4.rs"),
        root
    ));
    assert!(!is_rust_shim_declaration_owner(
        std::path::Path::new("driver/fsring-sys/src/not_c4.rs"),
        root
    ));
    assert!(!is_rust_shim_declaration_owner(
        std::path::Path::new("driver/nested/fsring-sys/src/c4.rs"),
        root
    ));
    assert!(!is_c_shim_definition_owner(
        std::path::Path::new("driver/fsring-fsd/native/not_c4_seh.c"),
        root
    ));
    assert!(!is_c_shim_definition_owner(
        std::path::Path::new("driver/elsewhere/c4_seh.c"),
        root
    ));
    assert!(!is_c_shim_definition_owner(
        std::path::Path::new("driver/nested/fsring-fsd/native/c4_seh.c"),
        root
    ));
}

#[test]
fn security_exemptions_require_exact_top_level_subtrees() {
    let root = std::path::Path::new("driver");
    assert!(is_fsring_sys_tree(
        std::path::Path::new("driver/fsring-sys/src/lib.rs"),
        root
    ));
    assert!(is_compile_fail_fixture(
        std::path::Path::new("driver/tests/compile-fail/nested/case.rs"),
        root
    ));

    for rejected in [
        "driver/nested/fsring-sys/src/lib.rs",
        "driver/fsring-sys-decoy/src/lib.rs",
        "driver/nested/fsring-sys-decoy/fsring-sys/src/lib.rs",
        "elsewhere/driver/fsring-sys/src/lib.rs",
    ] {
        assert!(!is_fsring_sys_tree(std::path::Path::new(rejected), root));
    }
    for rejected in [
        "driver/compile-fail/case.rs",
        "driver/nested/tests/compile-fail/case.rs",
        "driver/tests/compile-fail-decoy/case.rs",
        "driver/tests/compile-fail-decoy/compile-fail/case.rs",
        "elsewhere/driver/tests/compile-fail/case.rs",
    ] {
        assert!(!is_compile_fail_fixture(
            std::path::Path::new(rejected),
            root
        ));
    }
}

#[test]
fn security_path_predicates_reject_noncanonical_and_root_mismatched_inputs() {
    let root = std::path::Path::new("driver");

    for rejected in [
        "driver/fsring-sys/./src/c4.rs",
        "driver/fsring-sys/src/./c4.rs",
        "driver/fsring-sys/src/../src/c4.rs",
    ] {
        assert!(!is_rust_shim_declaration_owner(
            std::path::Path::new(rejected),
            root
        ));
    }
    for rejected in [
        "driver/./fsring-sys/src/lib.rs",
        "driver/fsring-sys/./src/lib.rs",
        "driver/fsring-sys/../fsring-sys/src/lib.rs",
        "driver/fsring-sys/src/../../fsring-sys/src/lib.rs",
        "/driver/fsring-sys/src/lib.rs",
        r"C:\driver\fsring-sys\src\lib.rs",
    ] {
        assert!(!is_fsring_sys_tree(std::path::Path::new(rejected), root));
    }
    assert!(!is_fsring_sys_tree(
        std::path::Path::new(r"C:\driver\fsring-sys\src\lib.rs"),
        std::path::Path::new(r"D:\driver")
    ));
}

#[test]
fn security_walk_fails_closed_on_missing_roots_and_link_or_reparse_entries() {
    let missing = std::env::temp_dir().join(std::format!(
        "fsring-task9-missing-walk-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must follow the Unix epoch")
            .as_nanos()
    ));
    let mut callback = |_path: &std::path::Path| Ok(());
    let rust_error = walk(&missing, &mut callback).expect_err("missing Rust walk root must fail");
    assert!(rust_error.contains(&missing.display().to_string()));
    assert!(rust_error.contains("cannot read directory"));
    let mixed_error =
        walk_rust_and_c(&missing, &mut callback).expect_err("missing Rust/C walk root must fail");
    assert!(mixed_error.contains(&missing.display().to_string()));

    assert_eq!(
        classify_walk_entry_flags(true, false, true, false),
        WalkEntryKind::RejectedLinkOrReparse
    );
    assert_eq!(
        classify_walk_entry_flags(false, true, false, true),
        WalkEntryKind::RejectedLinkOrReparse
    );
    assert_eq!(
        classify_walk_entry_flags(false, true, false, false),
        WalkEntryKind::Directory
    );
    assert_eq!(
        classify_walk_entry_flags(false, false, true, false),
        WalkEntryKind::File
    );
}

#[test]
fn security_walk_skips_only_the_exact_root_target_directory() {
    let directory = std::env::temp_dir().join(std::format!(
        "fsring-task9-target-scope-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must follow the Unix epoch")
            .as_nanos()
    ));
    let root_target = directory.join("target");
    let nested_target = directory.join("src").join("target");
    std::fs::create_dir_all(&root_target).expect("root target fixture must be creatable");
    std::fs::create_dir_all(&nested_target).expect("nested target fixture must be creatable");
    let skipped = root_target.join("skipped.rs");
    let visited = nested_target.join("visited.rs");
    std::fs::write(&skipped, "root build artifact").expect("root target fixture must be writable");
    std::fs::write(&visited, "ordinary nested module").expect("nested fixture must be writable");

    let mut seen = Vec::new();
    let walk_result = walk(&directory, &mut |path| {
        seen.push(path.to_path_buf());
        Ok(())
    });
    std::fs::remove_dir_all(&directory).expect("temporary target-scope tree must be removable");
    walk_result.expect("target-scope walk must succeed");

    assert!(
        !seen.contains(&skipped),
        "the root target directory must be skipped"
    );
    assert!(
        seen.contains(&visited),
        "an ordinary nested directory named target must be scanned"
    );
}

#[test]
fn security_walk_propagates_path_qualified_source_read_failures() {
    let directory = std::env::temp_dir().join(std::format!(
        "fsring-task9-invalid-source-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must follow the Unix epoch")
            .as_nanos()
    ));
    std::fs::create_dir(&directory).expect("temporary scanner directory must be creatable");
    let invalid = directory.join("invalid.rs");
    std::fs::write(&invalid, [0xff, 0xfe]).expect("invalid UTF-8 fixture must be writable");

    let direct_error = read_security_text(&invalid).expect_err("invalid UTF-8 must fail closed");
    assert!(direct_error.contains(&invalid.display().to_string()));
    assert!(direct_error.contains("cannot read UTF-8 security input"));

    let mut callback = |path: &std::path::Path| read_security_text(path).map(|_| ());
    let walk_error = walk(&directory, &mut callback).expect_err("callback read error must escape");
    std::fs::remove_file(&invalid).expect("temporary invalid source must be removable");
    std::fs::remove_dir(&directory).expect("temporary scanner directory must be removable");
    assert!(walk_error.contains(&invalid.display().to_string()));
}

#[test]
fn c4_seh_boundary_is_unique_typed_and_non_vacuous() {
    const SHIMS: [C4ShimContractSpec; 2] = [
        (
            "FsRingProbeAndLockPagesSeh",
            "NTSTATUS",
            &[&["PMDL"], &["KPROCESSOR_MODE"], &["LOCK_OPERATION"]],
            &[
                &["*", "mut", "MDL"],
                &["KPROCESSOR_MODE"],
                &["LOCK_OPERATION"],
            ],
            &["NTSTATUS"],
            CSehShimKind::ProbeAndLock,
        ),
        (
            "FsRingMapLockedPagesSeh",
            "PVOID",
            &[
                &["PMDL"],
                &["KPROCESSOR_MODE"],
                &["MEMORY_CACHING_TYPE"],
                &["PVOID"],
                &["ULONG"],
                &["ULONG"],
                &["NTSTATUS", "*"],
            ],
            &[
                &["*", "mut", "MDL"],
                &["KPROCESSOR_MODE"],
                &["MEMORY_CACHING_TYPE"],
                &["PVOID"],
                &["ULONG"],
                &["ULONG"],
                &["*", "mut", "NTSTATUS"],
            ],
            &["PVOID"],
            CSehShimKind::MapLockedPages,
        ),
    ];

    let root = driver_root();
    let mut scanned_rust = 0usize;
    let mut scanned_c = 0usize;
    let mut rust_declarations = [0usize; SHIMS.len()];
    let mut canonical_rust_declarations = [0usize; SHIMS.len()];
    let mut all_c_definitions = [0usize; SHIMS.len()];
    let mut canonical_c_definitions = [0usize; SHIMS.len()];
    let mut typed_calls = [0usize; SHIMS.len()];
    let mut shim_reference_roles = [[0usize; SHIM_REFERENCE_ROLE_COUNT]; SHIMS.len()];
    let mut ownership_offenders = Vec::new();
    let mut reference_offenders = Vec::new();
    let mut macro_context_offenders = Vec::new();
    let mut attribute_context_offenders = Vec::new();
    let mut source_closure_offenders = Vec::new();
    let mut contract_offenders = Vec::new();
    let mut direct_call_offenders = Vec::new();
    let mut saw_rust_owner = false;
    let mut saw_c_owner = false;
    let mut saw_build_script = false;

    walk_rust_and_c(&root, &mut |path| {
        let shown = path.display().to_string();
        let relative_shown = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string();
        if is_extern_quarantine_test(path, &root) || is_compile_fail_fixture(path, &root) {
            return Ok(());
        }
        let is_rust = path.extension().is_some_and(|extension| extension == "rs");
        let is_c = path.extension().is_some_and(|extension| extension == "c");
        scanned_rust = scanned_rust.saturating_add(usize::from(is_rust));
        scanned_c = scanned_c.saturating_add(usize::from(is_c));

        let text = read_security_text(path)?;
        let rust_tokens = if is_rust {
            let Some(tokens) = rust_code_tokens(&text) else {
                ownership_offenders.push(std::format!(
                    "{shown}: malformed Rust source prevents a complete C4 token scan"
                ));
                return Ok(());
            };
            let Some(macro_offender) = rust_macro_context_c4_offender(&text) else {
                macro_context_offenders.push(std::format!(
                    "{relative_shown}: malformed Rust source prevents a complete C4 macro-context scan"
                ));
                return Ok(());
            };
            if let Some(identifier) = macro_offender {
                macro_context_offenders.push(std::format!(
                    "{relative_shown}: reserved C4 identifier {identifier} appears inside a macro token tree"
                ));
            }
            let Some(attribute_offender) = rust_attribute_context_c4_offender(&text) else {
                attribute_context_offenders.push(std::format!(
                    "{relative_shown}: malformed Rust source prevents a complete C4 attribute-context scan"
                ));
                return Ok(());
            };
            if let Some(identifier) = attribute_offender {
                attribute_context_offenders.push(std::format!(
                    "{relative_shown}: reserved C4 identifier {identifier} appears inside an attribute token tree"
                ));
            }
            let Some(source_closure_offender) = rust_source_closure_offender(&text) else {
                source_closure_offenders.push(std::format!(
                    "{relative_shown}: malformed Rust source prevents a complete source-closure scan"
                ));
                return Ok(());
            };
            if let Some(offender) = source_closure_offender {
                let context = match offender {
                    RustSourceClosureOffender::IncludeMacro => "include! macro",
                    RustSourceClosureOffender::PathAttribute => "path attribute",
                };
                source_closure_offenders.push(std::format!(
                    "{relative_shown}: forbidden Rust source-closure construct: {context}"
                ));
            }
            if is_rust_shim_declaration_owner(path, &root) {
                saw_rust_owner = true;
                if rust_c4_has_exact_foreign_item_roster(&text) != Some(true) {
                    contract_offenders.push(std::format!(
                        "{relative_shown}: the exact C4 unsafe extern \"C\" roster must contain only ZwQuerySection, MmSectionObjectType, and the two FsRing shims"
                    ));
                }
                for (
                    symbol_index,
                    (symbol, _, _, rust_parameter_types, rust_return_type, _),
                ) in SHIMS.iter().enumerate()
                {
                    let declarations = count_canonical_rust_shim_foreign_declarations(
                        &text,
                        symbol,
                        rust_parameter_types,
                        rust_return_type,
                    )
                    .unwrap_or(0);
                    canonical_rust_declarations[symbol_index] =
                        canonical_rust_declarations[symbol_index].saturating_add(declarations);
                    if declarations != 1 {
                        contract_offenders.push(std::format!(
                            "{relative_shown}: {symbol} has {declarations} canonical foreign declaration(s); expected one semicolon item in the sole unsafe extern \"C\" block with the intended ABI signature"
                        ));
                    }
                }
            }
            if is_c4_build_script(path, &root) {
                saw_build_script = true;
                if rust_build_script_has_exact_c4_build_choreography(&text) != Some(true) {
                    contract_offenders.push(std::format!(
                        "{relative_shown}: cc input contract requires exactly one .file source native/c4_seh.c and forbids .files/.object(s)/generated inputs"
                    ));
                }
            }
            Some(tokens)
        } else {
            None
        };
        if is_c {
            let is_c_owner = is_c_shim_definition_owner(path, &root);
            if is_c_owner {
                saw_c_owner = true;
                if !c_owner_has_exact_preprocessor_contract(&text) {
                    ownership_offenders.push(std::format!(
                        "{shown}: the exact C shim owner must contain one #include <ntifs.h> and no other preprocessor directive"
                    ));
                }
                if !c_has_exact_top_level_function_roster(
                    &text,
                    &["FsRingProbeAndLockPagesSeh", "FsRingMapLockedPagesSeh"],
                ) {
                    contract_offenders.push(std::format!(
                        "{relative_shown}: top-level C function roster must contain only the two FsRing shim definitions"
                    ));
                }
                for (symbol, _, _, _, _, kind) in SHIMS {
                    if !c_shim_has_exact_seh_contract(&text, kind) {
                        contract_offenders.push(std::format!(
                            "{relative_shown}: {symbol} does not satisfy the exact __try/__except SEH body contract"
                        ));
                    }
                }
            }
            for (symbol_index, (symbol, return_type, parameter_types, _, _, _)) in
                SHIMS.iter().enumerate()
            {
                let definitions = count_all_c_shim_definitions(&text, symbol);
                if definitions == 0 {
                    continue;
                }
                all_c_definitions[symbol_index] =
                    all_c_definitions[symbol_index].saturating_add(definitions);
                if is_c_owner {
                    canonical_c_definitions[symbol_index] = canonical_c_definitions[symbol_index]
                        .saturating_add(count_canonical_c_shim_definitions(
                            &text,
                            return_type,
                            symbol,
                            parameter_types,
                        ));
                } else {
                    ownership_offenders.push(std::format!(
                        "{shown}: {definitions} definition(s) of {symbol} outside driver/fsring-fsd/native/c4_seh.c"
                    ));
                }
            }
        }
        let is_allowed_raising_site =
            is_fsring_sys_tree(path, &root) || is_c_shim_definition_owner(path, &root);
        let mentions_raising_symbol = rust_tokens.as_deref().map_or_else(
            || mentions_raising_mapping_call(&text),
            rust_tokens_mention_raising_mapping_symbol,
        );
        if !is_allowed_raising_site && mentions_raising_symbol {
            direct_call_offenders.push(shown.clone());
        }
        if let Some(tokens) = rust_tokens.as_deref() {
            for (symbol_index, (symbol, _, _, _, _, _)) in SHIMS.iter().enumerate() {
                let reference_audit =
                    audit_rust_shim_reference_tokens(tokens, path, &root, symbol);
                for (role_index, count) in reference_audit.roles.iter().enumerate() {
                    shim_reference_roles[symbol_index][role_index] =
                        shim_reference_roles[symbol_index][role_index].saturating_add(*count);
                }
                if reference_audit.unapproved != 0 {
                    reference_offenders.push(std::format!(
                        "{relative_shown}: {symbol} has {} unapproved reference(s)",
                        reference_audit.unapproved
                    ));
                }
                let declarations = count_rust_shim_declaration_tokens(tokens, symbol);
                if declarations != 0 {
                    if is_rust_shim_declaration_owner(path, &root) {
                        rust_declarations[symbol_index] =
                            rust_declarations[symbol_index].saturating_add(declarations);
                    } else {
                        ownership_offenders.push(std::format!(
                            "{shown}: {declarations} declaration(s) of {symbol} outside driver/fsring-sys/src/c4.rs"
                        ));
                    }
                }
                let calls = count_typed_rust_shim_call_tokens(tokens, symbol);
                if calls != 0 {
                    if is_typed_rust_shim_call_owner(path, &root) {
                        typed_calls[symbol_index] = typed_calls[symbol_index].saturating_add(calls);
                    } else {
                        ownership_offenders.push(std::format!(
                            "{shown}: {calls} typed call(s) to {symbol} outside driver/fsring-fsd/src/seh.rs"
                        ));
                    }
                }
            }
        }
        Ok(())
    })
    .unwrap_or_else(|error| panic!("C4 security traversal failed: {error}"));

    assert!(scanned_rust > 0, "the C4 scan found no Rust source");
    assert!(scanned_c > 0, "the C4 scan found no C source");
    assert!(
        saw_rust_owner,
        "the C4 scan did not reach fsring-sys/src/c4.rs"
    );
    assert!(
        saw_c_owner,
        "the C4 scan did not reach fsring-fsd/native/c4_seh.c"
    );
    assert!(
        saw_build_script,
        "the C4 scan did not reach fsring-fsd/build.rs"
    );
    assert!(
        ownership_offenders.is_empty(),
        "C4 shim declarations/definitions outside their exact owners:\n{}",
        ownership_offenders.join("\n")
    );
    assert!(
        contract_offenders.is_empty(),
        "C4 foreign/signature/SEH/build contracts failed:\n{}",
        contract_offenders.join("\n")
    );
    assert!(
        macro_context_offenders.is_empty(),
        "reserved C4 identifiers inside Rust macro token trees:\n{}",
        macro_context_offenders.join("\n")
    );
    assert!(
        attribute_context_offenders.is_empty(),
        "reserved C4 identifiers inside Rust attribute token trees:\n{}",
        attribute_context_offenders.join("\n")
    );
    assert!(
        source_closure_offenders.is_empty(),
        "forbidden Rust source-closure constructs:\n{}",
        source_closure_offenders.join("\n")
    );
    assert!(
        reference_offenders.is_empty(),
        "unapproved Rust shim references:\n{}",
        reference_offenders.join("\n")
    );
    const EXPECTED_REFERENCE_ROLES: [(&str, &str); SHIM_REFERENCE_ROLE_COUNT] = [
        ("declaration", "fsring-sys/src/c4.rs"),
        ("re-export", "fsring-sys/src/lib.rs"),
        ("ABI function-pointer assertion", "fsring-fsd/src/lib.rs"),
        ("direct call", "fsring-fsd/src/seh.rs"),
    ];
    for (index, (symbol, _, _, _, _, _)) in SHIMS.iter().enumerate() {
        for (role_index, (role, path)) in EXPECTED_REFERENCE_ROLES.iter().enumerate() {
            assert_eq!(
                shim_reference_roles[index][role_index], 1,
                "{path} must contain exactly one approved {role} reference to {symbol}"
            );
        }
        assert_eq!(
            rust_declarations[index], 1,
            "{symbol} must have exactly one Rust declaration in driver/fsring-sys/src/c4.rs"
        );
        assert_eq!(
            canonical_rust_declarations[index], 1,
            "driver/fsring-sys/src/c4.rs must contain exactly one canonical foreign declaration of {symbol}"
        );
        assert_eq!(
            all_c_definitions[index], 1,
            "{symbol} must have exactly one definition across all scanned C source"
        );
        assert_eq!(
            canonical_c_definitions[index], 1,
            "driver/fsring-fsd/native/c4_seh.c must contain exactly one unqualified exported definition of {symbol} with the intended ABI signature"
        );
        assert_eq!(
            typed_calls[index], 1,
            "fsring-fsd/src/seh.rs must make exactly one typed fsring-sys call to {symbol}"
        );
    }
    assert!(
        direct_call_offenders.is_empty(),
        "raising WDK mapping calls outside c4_seh.c/fsring-sys:\n{}",
        direct_call_offenders.join("\n")
    );
}

#[test]
fn every_extern_block_is_in_fsring_sys() {
    let root = driver_root();
    let mut offenders: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    let mut reached_fsd = false;
    let mut reached_sys = false;

    walk(&root, &mut |path| {
        // The fixtures under tests/compile-fail are deliberately broken code
        // compiled by their own runner, not part of the driver.
        if is_extern_quarantine_test(path, &root) || is_compile_fail_fixture(path, &root) {
            return Ok(());
        }
        let shown = path.display().to_string();
        scanned = scanned.saturating_add(1);
        if is_fsring_fsd_tree(path, &root) {
            reached_fsd = true;
        }
        if is_fsring_sys_tree(path, &root) {
            reached_sys = true;
        }
        let in_sys = is_fsring_sys_tree(path, &root);
        let text = read_security_text(path)?;
        let Some(extern_blocks) = count_structural_rust_extern_blocks(&text) else {
            offenders.push(format!(
                "{shown}: malformed Rust source prevents a complete structural extern-block scan"
            ));
            return Ok(());
        };
        if extern_blocks != 0 && !in_sys {
            offenders.push(format!(
                "{shown}: {extern_blocks} structural extern block(s) outside fsring-sys"
            ));
        }
        let Some(link_names) = count_structural_rust_link_name_attributes(&text) else {
            offenders.push(format!(
                "{shown}: malformed Rust source prevents a complete link_name attribute scan"
            ));
            return Ok(());
        };
        if link_names != 0 {
            offenders.push(format!(
                "{shown}: {link_names} forbidden structural link_name attribute(s)"
            ));
        }
        Ok(())
    })
    .unwrap_or_else(|error| panic!("extern-boundary security traversal failed: {error}"));

    assert!(
        scanned > 0,
        "the walk found no .rs files under {}",
        root.display()
    );
    assert!(
        reached_fsd && reached_sys,
        "the walk must reach both fsring-fsd and fsring-sys, or it proves nothing"
    );
    assert!(
        offenders.is_empty(),
        "extern blocks outside fsring-sys:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn no_driver_source_reaches_for_a_forbidden_random_source() {
    let root = driver_root();
    let mut offenders: Vec<String> = Vec::new();
    let mut scanned = 0usize;

    walk(&root, &mut |path| {
        let shown = path.display().to_string();
        scanned = scanned.saturating_add(1);
        let text = read_security_text(path)?;
        for (i, line) in text.lines().enumerate() {
            // This file names them in code (its own unit tests), which is the
            // one legitimate code-level mention in the tree.
            if is_extern_quarantine_test(path, &root) {
                continue;
            }
            if mentions_forbidden_random(line) {
                offenders.push(format!("{shown}:{}  {}", i.saturating_add(1), line.trim()));
            }
        }
        Ok(())
    })
    .unwrap_or_else(|error| panic!("random-source security traversal failed: {error}"));

    assert!(scanned > 0, "the walk found no .rs files");
    assert!(
        offenders.is_empty(),
        "RtlRandom* is forbidden as entropy by 11-rust-implementation.md section 4:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_driver_installs_no_global_allocator_and_no_inherited_panic_crate() {
    // Design section 6: an import-table diff CANNOT prove this. `wdk-alloc`
    // imports the same symbols its replacement would, `wdk-panic`'s handler is
    // a bare `loop {}` that imports nothing, and `lto = true` already
    // dead-strips an unused allocator - which is why the pre-slice image showed
    // only `DbgPrint`. So the property is proven structurally instead.
    let root = driver_root();
    let mut offenders: Vec<String> = Vec::new();
    let mut scanned = 0usize;

    walk(&root, &mut |path| {
        let shown = path.display().to_string();
        if is_compile_fail_fixture(path, &root) || is_extern_quarantine_test(path, &root) {
            return Ok(());
        }
        scanned = scanned.saturating_add(1);
        let text = read_security_text(path)?;
        for (i, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            if t.starts_with("#[global_allocator]")
                || t.contains("wdk_alloc")
                || t.contains("wdk_panic")
            {
                offenders.push(format!("{shown}:{}  {}", i.saturating_add(1), line.trim()));
            }
        }
        Ok(())
    })
    .unwrap_or_else(|error| panic!("allocator security traversal failed: {error}"));
    assert!(scanned > 0, "the walk found no .rs files");
    assert!(
        offenders.is_empty(),
        "11-rust-implementation.md section 5 forbids an allocator that aborts on          out-of-memory, and a #[global_allocator] exists to make alloc's infallible          APIs work:
{}",
        offenders.join("
")
    );

    // And the crates themselves must be gone from the resolved graph, not merely
    // unreferenced in source.
    let lock_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.lock");
    let lock = read_security_text(std::path::Path::new(lock_path))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(!lock.is_empty(), "cannot read {lock_path}");
    for banned in ["wdk-alloc", "wdk-panic"] {
        assert!(
            !lock.contains(&std::format!("name = \"{banned}\"")),
            "{banned} is still in driver/Cargo.lock"
        );
    }
    // Guard against a vacuous pass if the lock parse or path ever breaks.
    assert!(
        lock.contains("name = \"fsring-sys\""),
        "the lock read is not seeing this workspace"
    );
}

#[test]
fn the_checked_in_resolver_table_matches_the_code() {
    // driver/scripts/audit_sys.sh reads the file; fsring_core::resolver drives
    // the runtime resolution. If they drift, the audit stops guarding the
    // symbols the driver actually resolves - silently.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../audit/resolver-names.allow");
    let text =
        read_security_text(std::path::Path::new(path)).unwrap_or_else(|error| panic!("{error}"));
    assert!(!text.is_empty(), "cannot read {path}");

    let mut from_file: Vec<String> = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    from_file.sort();

    let mut from_code: Vec<String> = fsring_core::resolver::RESOLVER_TABLE
        .iter()
        .map(|d| d.name.to_string())
        .collect();
    from_code.sort();

    assert_eq!(
        from_file, from_code,
        "driver/audit/resolver-names.allow and fsring_core::resolver::RESOLVER_TABLE disagree"
    );
    assert!(
        !from_code.is_empty(),
        "an empty table would make the audit rule vacuous"
    );
}
