//! `11-rust-implementation.md` section 5 permits a local suppression of the
//! four denied lints **only with a written proof-of-safety comment**. This
//! mechanizes the omission case so review never has to catch it by eye.
//!
//! Both `#[allow(...)]` and `#[expect(...)]` are checked. `expect` is a
//! first-class lint-level attribute since Rust 1.81 (the driver pins 1.85) and
//! suppresses a `deny` exactly as `allow` does — and clippy's own
//! `allow_attributes` lint actively pushes contributors toward it — so a
//! scanner that saw only `allow` would be a complete, silent bypass of the one
//! rule this module exists to enforce.
//!
//! The whole module is `#[cfg(test)]`: it is a test tool, nothing in the kernel
//! image calls it, and keeping it out of `no_std` builds avoids inventing a
//! placeholder string type for a diagnostic that only tests ever print.
//!
//! **Honest limits.** This is a line-based text scan. It cannot understand
//! `cfg`, macros, or a proof comment that is present but vacuous. It makes the
//! *missing* comment impossible; it does not judge a comment's quality.
//!
//! It does not see a suppression hidden inside `cfg_attr(..., allow(...))`,
//! and it cannot tell code from a string literal: a source line that *begins*
//! with `#[allow(clippy::…)]` inside a string is indistinguishable from the
//! real attribute. The tree scan caught exactly that in this module's own test
//! fixtures, which is why they are written on one physical line each. Erring
//! toward a false positive is the right direction for this check — it fails
//! loudly and is fixed by reformatting, whereas the alternative would be to
//! start parsing Rust.

/// One `#[allow]` of a denied lint with no proof comment above it.
#[derive(Debug, PartialEq, Eq)]
pub struct Violation {
    /// 1-based line number of the offending attribute.
    pub line: usize,
    /// The attribute text, trimmed.
    pub text: String,
}

/// Attribute forms that suppress a lint level. `expect` counts: it silences a
/// `deny` exactly as `allow` does.
pub const SUPPRESSION_PREFIXES: [&str; 4] = ["#[allow(", "#![allow(", "#[expect(", "#![expect("];

/// How many physical lines a single suppression attribute may span before the
/// scanner stops joining. Generous; real attributes are one or two lines.
const MAX_ATTRIBUTE_LINES: usize = 8;

/// The lints `11-rust-implementation.md` section 5 denies. A suppression naming
/// any of them needs a written proof of safety.
pub const DENIED_LINTS: [&str; 4] = [
    "clippy::unwrap_used",
    "clippy::expect_used",
    "clippy::indexing_slicing",
    "clippy::arithmetic_side_effects",
];

/// Scan one source file's text.
///
/// A violation is an `#[allow(...)]`, `#![allow(...)]`, `#[expect(...)]` or
/// `#![expect(...)]` naming a denied lint whose nearest preceding non-blank
/// line is not a `//` comment. Multi-line attributes are joined before the
/// lint names are tested.
pub fn scan_source(text: &str) -> Vec<Violation> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();

    for (idx, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        if !SUPPRESSION_PREFIXES.iter().any(|p| line.starts_with(p)) {
            continue;
        }

        // A suppression may span lines. Join forward to the closing `)]` before
        // testing which lints it names, so an attribute whose lint list sits on
        // its own continuation line is not a silent bypass.
        let mut joined = String::new();
        for part in lines.iter().skip(idx).take(MAX_ATTRIBUTE_LINES) {
            joined.push_str(part.trim());
            if part.contains(")]") {
                break;
            }
        }

        if !DENIED_LINTS.iter().any(|l| joined.contains(l)) {
            continue;
        }

        // The nearest preceding non-blank line must be a `//` comment.
        // Written with iterators and saturating arithmetic rather than an index
        // walk: this module polices the four lints of
        // `11-rust-implementation.md` section 5, so it obeys them itself.
        let justified = lines
            .iter()
            .take(idx)
            .rev()
            .map(|s| s.trim())
            .find(|s| !s.is_empty())
            .is_some_and(|prev| prev.starts_with("//"));

        if !justified {
            out.push(Violation {
                line: idx.saturating_add(1),
                text: line.to_string(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_allow_without_a_proof_comment_is_a_violation() {
        let src = "fn a() {}\n#[allow(clippy::unwrap_used)]\nfn b() {}\n";
        let v = scan_source(src);
        assert_eq!(v.len(), 1, "expected one violation, got {v:?}");
        assert_eq!(v.first().map(|x| x.line), Some(2));
    }

    // Each fixture below is written on ONE physical line on purpose: a line that
    // begins with the attribute text, even inside a string literal, is what this
    // line-based scanner is built to notice. See the module documentation.

    #[test]
    fn an_allow_with_a_proof_comment_is_accepted() {
        let src = "// SAFETY: bounded by the caller's assertion.\n#[allow(clippy::indexing_slicing)]\nfn b() {}\n";
        assert!(scan_source(src).is_empty(), "a justified allow must pass");
    }

    #[test]
    fn a_blank_line_between_the_comment_and_the_attribute_is_tolerated() {
        let src = "// SAFETY: bounded above.\n\n#[allow(clippy::indexing_slicing)]\nfn b() {}\n";
        assert!(scan_source(src).is_empty());
    }

    #[test]
    fn an_allow_of_an_undenied_lint_is_ignored() {
        let src = "#[allow(dead_code)]\nfn b() {}\n";
        assert!(scan_source(src).is_empty());
    }

    #[test]
    fn an_expect_is_scanned_like_an_allow() {
        let src = "#[expect(clippy::unwrap_used)]\nfn b() {}\n";
        assert_eq!(
            scan_source(src).len(),
            1,
            "expect suppresses a deny exactly as allow does"
        );
    }

    #[test]
    fn a_justified_expect_is_accepted() {
        let src = "// SAFETY: non-empty by construction.\n#[expect(clippy::indexing_slicing)]\nfn b() {}\n";
        assert!(scan_source(src).is_empty());
    }

    #[test]
    fn a_multi_line_suppression_is_joined_before_matching() {
        let src = "#[allow(\n    clippy::unwrap_used,\n)]\nfn b() {}\n";
        assert_eq!(
            scan_source(src).len(),
            1,
            "a lint named on a continuation line must still be found"
        );
    }

    #[test]
    fn an_inner_allow_is_scanned_too() {
        let src = "#![allow(clippy::expect_used)]\n";
        assert_eq!(scan_source(src).len(), 1);
    }

    #[test]
    fn the_driver_workspace_has_no_unjustified_allows() {
        // `expect` is denied crate-wide, including in tests, so destructure.
        let Some(root) = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent() else {
            panic!("the crate directory has no parent; the walk root is wrong")
        };
        let mut offenders: Vec<String> = Vec::new();
        let mut scanned = 0usize;

        let mut reached_fsd = false;
        walk(root, &mut |path: &std::path::Path| {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            scanned = scanned.saturating_add(1);
            // Separator-agnostic: the walk yields native paths.
            let shown = path.display().to_string();
            if shown.contains("fsring-fsd") && shown.ends_with("lib.rs") {
                reached_fsd = true;
            }
            for v in scan_source(&text) {
                offenders.push(format!("{}:{}  {}", path.display(), v.line, v.text));
            }
        });

        // `scanned > 0` alone rules out only a TOTAL walk failure: `walk`
        // returns silently on an unreadable directory, so losing the very
        // subtree this check polices would still leave fsring-core's own files
        // and pass. Assert the driver crate was actually reached.
        assert!(
            scanned > 0,
            "the walk found no .rs files under {}; the scan would be vacuous",
            root.display()
        );
        assert!(
            reached_fsd,
            "the walk never reached fsring-fsd/src/lib.rs under {}; the scan is              not covering the crate it exists to police",
            root.display()
        );
        assert!(
            offenders.is_empty(),
            "unjustified #[allow]s of denied lints:\n{}",
            offenders.join("\n")
        );
    }

    fn walk(dir: &std::path::Path, f: &mut dyn FnMut(&std::path::Path)) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                walk(&path, f);
            } else if path.extension().is_some_and(|e| e == "rs") {
                f(&path);
            }
        }
    }
}
