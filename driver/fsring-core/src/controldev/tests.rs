//! Tests for the control device's decidable half.
//!
//! `09-security.md` section 1's precedence is **parsed**: the section is sliced
//! by its heading, its numbered list is read in document order, and the oracle
//! the sweep compares against is built from that parse. The two documents that
//! restate the precedence are parsed the same way -- `05-irp-dispatch.md`
//! section 4's ordered table and `02-transport.md` section 10's ordered prose
//! -- and all three are required to yield the same sequence.
//!
//! **What is parsed, and what is not.** The parse supplies the *order* of the
//! rules and the *status each names*. Which requests a rule refuses -- the
//! predicate -- is hand-written in [`RuleKind::refuses`], bound to the document
//! only by the tokens [`kind_of`] looks for. A reviewer must read that one
//! function against section 1 directly; nothing here can check it.
//!
//! C1's review found a design claiming to parse sections that nothing parsed.
//! C2's first round found the same claim repeated in this module: the
//! precedence was four quoted sentences plus a hand restatement, and reversing
//! section 1's rules left every test green. This is the second attempt, and the
//! boundary above is stated so there need not be a third.

use super::*;
use fsring_abi::control::status;

/// `09-security.md`, the normative home of the CREATE precedence.
const SECURITY: &str = include_str!("../../../../docs/design/09-security.md");
/// `05-irp-dispatch.md`, which restates it as an ordered table.
const DISPATCH: &str = include_str!("../../../../docs/design/05-irp-dispatch.md");
/// `02-transport.md`, which restates it as ordered prose.
const TRANSPORT: &str = include_str!("../../../../docs/design/02-transport.md");
/// `10-lifecycle.md`, which **declines** to restate it.
///
/// C2's first round found this document counted as a fourth agreeing
/// restatement, though it says the CREATE rules *"are defined by
/// `09-security.md` section 1 and are not restated here"*. The whole-file
/// substring check that produced that agreement had matched an unrelated
/// hot-restart sentence. It is read here only to assert it still declines.
const LIFECYCLE: &str = include_str!("../../../../docs/design/10-lifecycle.md");

/// The heading of `09-security.md`'s precedence section.
const SECURITY_SECTION: &str = "## 1. Control device authorization";
/// The heading of `05-irp-dispatch.md`'s restatement.
const DISPATCH_SECTION: &str = "## 4. IRP_MJ_CREATE";
/// The heading of `02-transport.md`'s restatement.
const TRANSPORT_SECTION: &str = "## 10. Authenticated control registry and lifecycle";

/// The sentence all three documents use to introduce the precedence.
const LEAD_IN: &str = "behavior is closed and uses this precedence:";

const AUTHORIZATION_START: &str = "Every subsequent SETUP/ATTACH/IOCTL";
const AUTHORIZATION_END: &str = "IOCTL executes.";
const AUTHORIZATION_STATEMENT: &str = concat!(
    "Every subsequent SETUP/ATTACH/IOCTL on that handle \u{2014} including ",
    "`IOCTL_FSRING_DONATE_SECURITY_CONTEXT` (function `0x804`, `0x0022e010`) \u{2014} ",
    "requires both `RequestorMode == UserMode` **and** the current IRP's ",
    "requestor `EPROCESS` matching the one captured at CREATE. A duplicated or ",
    "inherited handle presented from a different process is `ACCESS_DENIED`, ",
    "with no mapping or side effect, even before the first IOCTL executes."
);

/// The cell where section 1 rules 1 and 2 both apply, and only precedence
/// decides it.
const OVERLAPPING_CELL: CreateRequest = CreateRequest {
    mode: RequestorMode::KernelMode,
    file_name_empty: false,
    related_file_object_null: false,
    context_alloc_ok: true,
};

/// Slice a document to the body of one `##` section.
///
/// **Panics if the heading is absent.** A renamed section must break the checks
/// that read it rather than silently widening them to the whole file -- that
/// widening is exactly what let C2's first cross-document check pass while
/// matching text about something else.
fn section<'a>(doc: &'a str, heading: &str) -> &'a str {
    let needle = format!("\n{heading}\n");
    // **The heading must be unique.** Round 2 of C2's review reversed the real
    // rules 1 and 2 in `09-security.md` §1 AND inserted a second
    // `## 1. Control device authorization` above it holding a correct "Summary"
    // copy; `find` took the decoy and all 18 tests passed, restoring round-1's
    // sharpest finding through a one-line document edit. Defending only against
    // a MISSING heading, as the previous comment here did, is not enough: a
    // parser that silently reads the first of several copies reports on a
    // document nobody has to keep normative.
    let matches = doc.matches(&needle).count();
    assert_eq!(
        matches, 1,
        "{heading:?} occurs {matches} times; a precedence parsed from a duplicated heading reads whichever copy comes first"
    );
    let start = doc
        .find(&needle)
        .unwrap_or_else(|| panic!("no section headed {heading:?}"));
    let body = &doc[start.saturating_add(needle.len())..];
    match body.find("\n## ") {
        Some(end) => &body[..end],
        None => body,
    }
}

/// The heading of `02-transport.md`'s IOCTL numeric registry.
const TRANSPORT_IOCTL_SUBSECTION: &str = "### 10.2 IOCTL numeric registry";

/// Slice a document to the body of one `###` subsection.
///
/// Same uniqueness rule as [`section`], and the same reason. Round 2 of C2's
/// review moved the seven-row IOCTL table out of section 10.2 into a fabricated
/// section at the end of the file; `parsed_ioctl_table` read the whole document,
/// found the rows wherever they were, and all 18 tests passed while three
/// documents and this module's own rustdoc claimed the codes were "parsed from
/// section 10.2".
fn subsection<'a>(doc: &'a str, heading: &str) -> &'a str {
    let needle = format!("\n{heading}\n");
    let matches = doc.matches(&needle).count();
    assert_eq!(
        matches, 1,
        "{heading:?} occurs {matches} times; a table parsed from a duplicated heading reads whichever copy comes first"
    );
    let start = doc
        .find(&needle)
        .unwrap_or_else(|| panic!("no subsection headed {heading:?}"));
    let body = &doc[start.saturating_add(needle.len())..];
    // A `###` subsection ends at the next heading of either level.
    let end = [body.find("\n## "), body.find("\n### ")]
        .into_iter()
        .flatten()
        .min();
    match end {
        Some(e) => &body[..e],
        None => body,
    }
}

/// The `[A-Za-z0-9_]` words of a fragment, in order of occurrence.
fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

/// The SCREAMING_SNAKE_CASE words of a fragment, in order of occurrence.
///
/// An underscore is required except for the ABI's bare `SUCCESS`, so
/// `UserMode` and `EPROCESS` do not register as statuses.
fn status_words(text: &str) -> Vec<String> {
    words(text)
        .into_iter()
        .filter(|w| {
            w == "SUCCESS"
                || (w.contains('_')
                    && w.chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
        })
        .collect()
}

/// The `0x...` literals of a fragment, in order of occurrence.
fn hex_words(text: &str) -> Vec<String> {
    words(text)
        .into_iter()
        .filter(|w| w.len() > 2 && w.starts_with("0x"))
        .collect()
}

/// One failure rule of a CREATE precedence, as some document states it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedRule {
    /// The status the rule names, e.g. `ACCESS_DENIED`.
    status_name: String,
    /// The number the document gives that status, where it gives one.
    status_hex: Option<String>,
    /// The rule's own text, with list wrapping joined.
    text: String,
}

/// Build a rule from one document fragment.
///
/// Requires exactly one status name: a fragment naming none is not a rule, and
/// one naming two cannot be resolved to a single outcome.
fn rule_from_text(text: &str) -> ParsedRule {
    let names = status_words(text);
    assert_eq!(
        names.len(),
        1,
        "a precedence rule must name exactly one status; {text:?} names {names:?}"
    );
    let hexes = hex_words(text);
    assert!(
        hexes.len() <= 1,
        "{text:?} carries more than one number: {hexes:?}"
    );
    let Some(name) = names.first() else {
        panic!("a precedence rule must name a status: {text:?}")
    };
    ParsedRule {
        status_name: name.clone(),
        status_hex: hexes.first().cloned(),
        text: text.to_string(),
    }
}

fn unique_substring_start(text: &str, anchor: &str, name: &str) -> usize {
    let mut matches = text.match_indices(anchor);
    let Some((at, _)) = matches.next() else {
        panic!("{name} is gone")
    };
    assert!(
        matches.next().is_none(),
        "{name} appears more than once; selecting the first would accept a decoy"
    );
    at
}

fn flat(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn exact_statement(section: &str, start: &str, end: &str, name: &str) -> String {
    let normalized = flat(section);
    let start_at = unique_substring_start(&normalized, start, &format!("{name} start"));
    let end_at = unique_substring_start(&normalized, end, &format!("{name} end"));
    assert!(start_at <= end_at, "{name} end precedes its start");
    let inclusive_end = end_at.saturating_add(end.len());
    normalized
        .get(start_at..inclusive_end)
        .unwrap_or("")
        .to_string()
}

fn tail_after_unique<'a>(text: &'a str, anchor: &str, name: &str) -> &'a str {
    let at = unique_substring_start(text, anchor, name);
    text.get(at.saturating_add(anchor.len())..).unwrap_or("")
}

/// Parse a numbered precedence list (`09-security.md` section 1's form).
fn parse_numbered_precedence(sec: &str) -> Vec<ParsedRule> {
    let mut items: Vec<(usize, String)> = Vec::new();
    for line in tail_after_unique(sec, LEAD_IN, "the numbered precedence lead-in").lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let head = (line == trimmed)
            .then(|| trimmed.split_once(". "))
            .flatten()
            .filter(|(n, _)| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
        match head {
            Some((n, rest)) => {
                let Ok(number) = n.parse::<usize>() else {
                    panic!("{n:?} is not a list number")
                };
                items.push((number, rest.trim().to_string()));
            }
            None if items.is_empty() => {
                panic!("the first nonblank text after the lead-in is not item 1")
            }
            None if line != trimmed => {
                let Some(last) = items.last_mut() else {
                    panic!("a continuation line before any numbered item")
                };
                last.1.push(' ');
                last.1.push_str(trimmed);
            }
            None => break,
        }
    }
    for (i, (n, _)) in items.iter().enumerate() {
        assert_eq!(
            *n,
            i.saturating_add(1),
            "the numbered list is not 1..n in order"
        );
    }
    items.iter().map(|(_, t)| rule_from_text(t)).collect()
}

/// Parse an ordered precedence table (`05-irp-dispatch.md` section 4's form).
///
/// The success row is dropped, so the result is comparable with the
/// failure-only lists the other two documents state.
fn parse_table_precedence(sec: &str) -> Vec<ParsedRule> {
    let mut rows: Vec<(usize, String, String)> = Vec::new();
    for line in tail_after_unique(sec, LEAD_IN, "the table precedence lead-in").lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 5 {
            if rows.is_empty() {
                continue;
            }
            break;
        }
        let (Some(order_cell), Some(condition), Some(status_cell)) =
            (cells.get(1), cells.get(2), cells.get(3))
        else {
            continue;
        };
        let Ok(order) = order_cell.parse::<usize>() else {
            continue;
        };
        rows.push((
            order,
            format!("{condition} {status_cell}"),
            (*status_cell).to_string(),
        ));
    }
    for (i, (n, _, _)) in rows.iter().enumerate() {
        assert_eq!(
            *n,
            i.saturating_add(1),
            "the table's Order column is not 1..n"
        );
    }
    // The table's last row is the success case. It is checked and then dropped,
    // so the comparison against the other two documents is failure-to-failure;
    // dropping it silently would let a table that lost its success row still
    // agree.
    let Some((_, _, last)) = rows.pop() else {
        panic!("the precedence table has no rows")
    };
    assert_eq!(
        last, "SUCCESS",
        "the precedence table must end with the success row"
    );
    assert_eq!(
        status_number(&last),
        SUCCESS,
        "the table's success row does not name the ABI's SUCCESS"
    );
    rows.iter().map(|(_, t, _)| rule_from_text(t)).collect()
}

/// Parse an ordered prose precedence (`02-transport.md` section 10's form).
///
/// The clauses are separated by `; then `, and the list ends at the sentence
/// beginning "Every such failure".
fn parse_prose_precedence(sec: &str) -> Vec<ParsedRule> {
    let flat = sec.split_whitespace().collect::<Vec<_>>().join(" ");
    let tail = tail_after_unique(&flat, LEAD_IN, "the prose precedence lead-in");
    let end = unique_substring_start(
        tail,
        "Every such failure",
        "the prose precedence terminator",
    );
    let body = tail.get(..end).unwrap_or("");
    body.split("; then ")
        .map(|c| rule_from_text(c.trim().trim_end_matches('.')))
        .collect()
}

/// Which requests a precedence rule refuses.
///
/// **This is the hand-written half.** The parse supplies order and status; this
/// supplies meaning. Each variant is recognised in a document by the tokens
/// [`kind_of`] looks for, and nothing here can check that the predicate is the
/// one the sentence describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleKind {
    /// Rule 1: a non-`UserMode` create.
    NonUserMode,
    /// Rule 2: a nonempty name or a non-null related file object.
    NonRootName,
    /// Rule 3: the per-file context could not be allocated or referenced.
    ContextAllocationFailed,
}

impl RuleKind {
    /// Does this rule refuse the given request?
    fn refuses(self, r: CreateRequest) -> bool {
        match self {
            Self::NonUserMode => !matches!(r.mode, RequestorMode::UserMode),
            Self::NonRootName => !r.file_name_empty || !r.related_file_object_null,
            Self::ContextAllocationFailed => !r.context_alloc_ok,
        }
    }
}

/// Identify a parsed rule's kind from tokens in its own text.
///
/// Exactly one kind must match: a rule matching none is unrecognised, and one
/// matching two is ambiguous. Both panic rather than defaulting.
fn kind_of(rule: &ParsedRule) -> RuleKind {
    let t = &rule.text;
    let mode = t.contains("UserMode");
    let name = t.contains("FileName") || t.contains("RelatedFileObject") || t.contains("non-root");
    let alloc = t.contains("alloc");
    match (mode, name, alloc) {
        (true, false, false) => RuleKind::NonUserMode,
        (false, true, false) => RuleKind::NonRootName,
        (false, false, true) => RuleKind::ContextAllocationFailed,
        other => panic!("rule {t:?} matches {other:?}; a rule must match exactly one kind"),
    }
}

/// Resolve a status name the documents use to the frozen ABI's number.
fn status_number(name: &str) -> i32 {
    match name {
        "ACCESS_DENIED" => status::ACCESS_DENIED,
        "OBJECT_NAME_NOT_FOUND" => status::OBJECT_NAME_NOT_FOUND,
        "INSUFFICIENT_RESOURCES" => status::INSUFFICIENT_RESOURCES,
        "SUCCESS" => status::SUCCESS,
        other => panic!("the documents name a status this module cannot resolve: {other}"),
    }
}

/// The precedence `09-security.md` section 1 states, parsed.
fn security_precedence() -> Vec<ParsedRule> {
    parse_numbered_precedence(section(SECURITY, SECURITY_SECTION))
}

/// The precedence `05-irp-dispatch.md` section 4 restates, parsed.
fn dispatch_precedence() -> Vec<ParsedRule> {
    parse_table_precedence(section(DISPATCH, DISPATCH_SECTION))
}

/// The precedence `02-transport.md` section 10 restates, parsed.
fn transport_precedence() -> Vec<ParsedRule> {
    parse_prose_precedence(section(TRANSPORT, TRANSPORT_SECTION))
}

/// Decide a create by applying a parsed precedence in its document order.
fn oracle_from(rules: &[ParsedRule], request: CreateRequest) -> CreateOutcome {
    for rule in rules {
        if kind_of(rule).refuses(request) {
            return CreateOutcome {
                status: status_number(&rule.status_name),
                information: 0,
                context_installed: false,
            };
        }
    }
    CreateOutcome {
        status: SUCCESS,
        information: 0,
        context_installed: true,
    }
}

/// The oracle the sweep compares [`decide_create`] against, derived from
/// `09-security.md` section 1's parse.
fn oracle_create(request: CreateRequest) -> CreateOutcome {
    oracle_from(&security_precedence(), request)
}

#[test]
fn security_section_one_parses_to_three_ordered_failure_rules() {
    let rules = security_precedence();
    assert_eq!(
        rules.len(),
        3,
        "section 1's precedence is three failure rules"
    );
    let kinds: Vec<RuleKind> = rules.iter().map(kind_of).collect();
    assert_eq!(
        kinds,
        vec![
            RuleKind::NonUserMode,
            RuleKind::NonRootName,
            RuleKind::ContextAllocationFailed
        ]
    );
    let names: Vec<&str> = rules.iter().map(|r| r.status_name.as_str()).collect();
    assert_eq!(
        names,
        [
            "ACCESS_DENIED",
            "OBJECT_NAME_NOT_FOUND",
            "INSUFFICIENT_RESOURCES"
        ]
    );
}

#[test]
fn a_duplicate_precedence_lead_in_is_ambiguous() {
    let source = format!(
        "{LEAD_IN}\n\n\
         1. A non-`UserMode` create returns `ACCESS_DENIED`.\n\
         2. A non-root create returns `OBJECT_NAME_NOT_FOUND`.\n\
         3. A failed allocation returns `INSUFFICIENT_RESOURCES`.\n\n\
         {LEAD_IN}\n\n\
         1. A failed allocation returns `INSUFFICIENT_RESOURCES`.\n\
         2. A non-root create returns `OBJECT_NAME_NOT_FOUND`.\n\
         3. A non-`UserMode` create returns `ACCESS_DENIED`.\n"
    );
    assert!(
        std::panic::catch_unwind(|| parse_numbered_precedence(&source)).is_err(),
        "a first-match parser silently accepts a decoy precedence"
    );
}

#[test]
fn a_loose_numbered_list_does_not_end_at_its_first_blank_line() {
    let source = format!(
        "{LEAD_IN}\n\n\
         1. A non-`UserMode` create returns `ACCESS_DENIED`.\n\n\
         2. A non-root create returns `OBJECT_NAME_NOT_FOUND`.\n\
         3. A failed allocation returns `INSUFFICIENT_RESOURCES`.\n\n\
         4. A final case returns `SUCCESS`.\n"
    );
    assert_eq!(
        parse_numbered_precedence(&source).len(),
        4,
        "a blank line between Markdown list items does not end the list"
    );
}

#[test]
fn a_duplicate_table_precedence_lead_in_is_ambiguous() {
    let table = "| Order | Condition | Status |\n\
                 | 1 | A non-`UserMode` create | ACCESS_DENIED |\n\
                 | 2 | A non-root create | OBJECT_NAME_NOT_FOUND |\n\
                 | 3 | A failed allocation | INSUFFICIENT_RESOURCES |\n\
                 | 4 | A final case | SUCCESS |\n";
    let source = format!("{LEAD_IN}\n\n{table}\n{LEAD_IN}\n\n{table}");
    assert!(
        std::panic::catch_unwind(|| parse_table_precedence(&source)).is_err(),
        "a first-match table parser silently accepts a complete decoy precedence"
    );
}

#[test]
fn a_duplicate_prose_precedence_lead_in_is_ambiguous() {
    let prose = "A non-`UserMode` create returns `ACCESS_DENIED`; then \
                 a non-root create returns `OBJECT_NAME_NOT_FOUND`; then \
                 a failed allocation returns `INSUFFICIENT_RESOURCES`. Every such failure stops.";
    let source = format!("{LEAD_IN} {prose} {LEAD_IN} {prose}");
    assert!(
        std::panic::catch_unwind(|| parse_prose_precedence(&source)).is_err(),
        "a first-match prose parser silently accepts a complete decoy precedence"
    );
}

#[test]
fn a_duplicate_prose_precedence_terminator_is_ambiguous() {
    let source = format!(
        "{LEAD_IN} A non-`UserMode` create returns `ACCESS_DENIED`; then \
         a non-root create returns `OBJECT_NAME_NOT_FOUND`; then \
         a failed allocation returns `INSUFFICIENT_RESOURCES`. \
         Every such failure stops. Every such failure is final."
    );
    assert!(
        std::panic::catch_unwind(|| parse_prose_precedence(&source)).is_err(),
        "a first-match prose terminator silently accepts a decoy ending"
    );
}

/// The three documents that state the precedence must state the same one, in
/// the same order.
///
/// Each is parsed in its own form -- numbered list, ordered table, ordered
/// prose -- so reversing the rows of any one of them fails here. C2's first
/// round found the predecessor of this test asserting only that a name and a
/// hex spelling occurred *somewhere* in a whole file, which reversing
/// `05-irp-dispatch.md` section 4's rows left green.
#[test]
fn the_three_documents_state_the_same_precedence_in_the_same_order() {
    let nine = security_precedence();
    let five = dispatch_precedence();
    let two = transport_precedence();
    let ours: Vec<&str> = nine.iter().map(|r| r.status_name.as_str()).collect();
    let our_kinds: Vec<RuleKind> = nine.iter().map(kind_of).collect();
    for (name, rules) in [("05", &five), ("02", &two)] {
        let theirs: Vec<&str> = rules.iter().map(|r| r.status_name.as_str()).collect();
        assert_eq!(
            theirs, ours,
            "{name} states a different precedence than 09 section 1"
        );
        let their_kinds: Vec<RuleKind> = rules.iter().map(kind_of).collect();
        assert_eq!(
            their_kinds, our_kinds,
            "{name} orders the conditions differently"
        );
    }
}

/// Checks the optional `status_hex` fields of the nine parsed precedence
/// rules. Six currently carry a number. Other hexadecimal literals, including
/// section 10.2's separately parsed IOCTL table, are outside this test.
#[test]
fn every_number_the_precedence_parse_reads_matches_the_frozen_abi() {
    let mut checked = 0usize;
    for rules in [
        security_precedence(),
        dispatch_precedence(),
        transport_precedence(),
    ] {
        for rule in rules {
            let Some(hex) = rule.status_hex.as_deref() else {
                continue;
            };
            let parsed = u32::from_str_radix(hex.trim_start_matches("0x"), 16)
                .unwrap_or_else(|_| panic!("{hex:?} is not a hex literal"));
            assert_eq!(
                parsed as i32,
                status_number(&rule.status_name),
                "the documents number {} as {hex}, which is not the ABI's",
                rule.status_name
            );
            checked = checked.saturating_add(1);
        }
    }
    assert_eq!(
        checked, 6,
        "the corpus used to number six of the nine parsed rules; recount deliberately rather than relaxing this"
    );
}

/// `10-lifecycle.md` is excluded from the agreement check because it declines
/// to restate the rules. If it ever does restate them, it must be included.
#[test]
fn ten_lifecycle_still_declines_to_restate_the_rules() {
    assert!(
        LIFECYCLE.contains("are not restated here"),
        "10-lifecycle no longer declines to restate the CREATE rules"
    );
    assert!(
        !LIFECYCLE.contains(LEAD_IN),
        "10-lifecycle now states a CREATE precedence; it must join the agreement check rather than stay excluded from it"
    );
}

/// The row-reordering class, as a test rather than a claim.
///
/// The reordered document is synthesised from the **real rule texts**, so only
/// their order differs. C2's first round found the design, the plan and the
/// source all saying the mutation gate carried this class; no such operator
/// existed, and the reordering had been applied once by hand and reverted.
#[test]
fn reordering_the_rules_changes_the_derived_decision() {
    let rules = security_precedence();
    let (Some(first), Some(second), Some(third)) = (rules.first(), rules.get(1), rules.get(2))
    else {
        panic!("section 1 must parse to three rules before they can be reordered")
    };
    let reordered = format!(
        "{LEAD_IN}\n\n1. {}\n2. {}\n3. {}\n",
        second.text, first.text, third.text
    );
    let swapped = parse_numbered_precedence(&reordered);
    let names: Vec<&str> = swapped.iter().map(|r| r.status_name.as_str()).collect();
    assert_eq!(
        names,
        [
            "OBJECT_NAME_NOT_FOUND",
            "ACCESS_DENIED",
            "INSUFFICIENT_RESOURCES"
        ],
        "the synthesised document really did reorder"
    );

    assert_eq!(
        oracle_from(&rules, OVERLAPPING_CELL).status,
        status::ACCESS_DENIED,
        "as written, rule 1 wins the overlapping cell"
    );
    assert_eq!(
        oracle_from(&swapped, OVERLAPPING_CELL).status,
        status::OBJECT_NAME_NOT_FOUND,
        "reordered, rule 2 wins it -- so the decision follows the document's order, not this module's"
    );
}

/// The one place the documents differ is recorded, and asserted in **both**
/// directions so it cannot drift silently in either.
#[test]
fn the_recorded_asymmetry_holds_in_both_directions() {
    let nine = security_precedence();
    let Some(alloc9) = nine
        .iter()
        .find(|r| r.status_name == "INSUFFICIENT_RESOURCES")
    else {
        panic!("09 section 1 no longer states an allocation-failure rule")
    };
    assert!(
        alloc9.status_hex.is_none(),
        "09 section 1 now numbers INSUFFICIENT_RESOURCES; the recorded asymmetry is stale and this test's premise with it"
    );
    let five = dispatch_precedence();
    let Some(alloc5) = five
        .iter()
        .find(|r| r.status_name == "INSUFFICIENT_RESOURCES")
    else {
        panic!("05 section 4 no longer restates the allocation-failure rule")
    };
    assert_eq!(
        alloc5.status_hex.as_deref(),
        Some("0xc000009a"),
        "05 section 4 no longer numbers INSUFFICIENT_RESOURCES; the re-export in this module has lost its source"
    );
}

/// The sweep compares [`decide_create`] against the parsed precedence.
///
/// This is no longer two restatements agreeing: the oracle is built from
/// `09-security.md` section 1's own text, so the comparison is code against
/// document. What it still cannot check is [`RuleKind::refuses`].
/// The 16 listed cells are 16 **distinct** cells.
///
/// Round 2 of C2's review duplicated one entry of `ALL_CREATE_REQUESTS` and made
/// `decide_create` return `SUCCESS` with a context installed for the cell that
/// fell out of the array -- a `KernelMode` create succeeding, a direct violation
/// of `09-security.md` section 1 rule 1 -- and every test stayed green,
/// including the sweep, which asserts `cells == 16` by counting array slots.
/// `all_effects_has_no_duplicates` exists one module away for exactly this
/// reason; this is the same check for the same reason.
#[test]
fn the_sixteen_cells_are_distinct_and_cover_the_domain() {
    let mut seen: Vec<CreateRequest> = Vec::new();
    for request in ALL_CREATE_REQUESTS {
        assert!(
            !seen.contains(&request),
            "ALL_CREATE_REQUESTS lists {request:?} twice, so the sweep covers fewer cells than it reports"
        );
        seen.push(request);
    }
    assert_eq!(seen.len(), 16);
    // ...and the 16 distinct cells are the WHOLE domain: every combination of
    // the four booleans the precedence is stated over. A dup check alone would
    // still pass on 16 distinct cells that omitted one and repeated another
    // shape, so the domain is regenerated here and compared as a set.
    let mut expected = 0usize;
    for mode in ALL_REQUESTOR_MODES {
        for name in [true, false] {
            for rel in [true, false] {
                for alloc in [true, false] {
                    let cell = CreateRequest {
                        mode,
                        file_name_empty: name,
                        related_file_object_null: rel,
                        context_alloc_ok: alloc,
                    };
                    assert!(
                        ALL_CREATE_REQUESTS.contains(&cell),
                        "{cell:?} is a legal input the sweep never visits"
                    );
                    expected = expected.saturating_add(1);
                }
            }
        }
    }
    assert_eq!(expected, 16, "the domain is two modes times three booleans");
}

#[test]
fn decide_create_agrees_with_the_oracle_on_every_cell() {
    assert_eq!(ALL_CREATE_REQUESTS.len(), 16, "the domain is four booleans");
    let mut cells = 0usize;
    for request in ALL_CREATE_REQUESTS {
        cells = cells.saturating_add(1);
        assert_eq!(
            decide_create(request),
            oracle_create(request),
            "cell {request:?}"
        );
    }
    assert_eq!(cells, 16);
}

/// Every outcome the decision can return must be a status the frozen ABI calls
/// legal for a CREATE.
#[test]
fn every_outcome_is_a_legal_create_status() {
    for request in ALL_CREATE_REQUESTS {
        let outcome = decide_create(request);
        assert!(
            fsring_abi::control::is_legal_create_status(outcome.status),
            "{:#010x} is not a legal CREATE status ({request:?})",
            outcome.status
        );
    }
}

/// `09-security.md` section 1: *"Every one of these failures completes with
/// `IoStatus.Information = 0` and installs no file context."*
#[test]
fn every_failure_reports_zero_information_and_installs_nothing() {
    let mut failures = 0usize;
    let mut successes = 0usize;
    for request in ALL_CREATE_REQUESTS {
        let outcome = decide_create(request);
        assert_eq!(
            outcome.information, 0,
            "section 1: Information = 0 on every cell"
        );
        if outcome.status == SUCCESS {
            successes = successes.saturating_add(1);
            assert!(
                outcome.context_installed,
                "the success installs the context"
            );
        } else {
            failures = failures.saturating_add(1);
            assert!(
                !outcome.context_installed,
                "section 1: a failure installs no file context"
            );
        }
    }
    assert_eq!(successes, 1, "exactly one cell succeeds");
    assert_eq!(failures, 15);
}

/// The cell where rules 1 and 2 both apply, checked against the shipped code.
///
/// [`reordering_the_rules_changes_the_derived_decision`] is its companion: this
/// one pins [`decide_create`], that one pins the derivation.
#[test]
fn the_overlapping_cell_resolves_to_rule_one() {
    assert!(
        ALL_CREATE_REQUESTS.contains(&OVERLAPPING_CELL),
        "the overlapping cell must be in the swept domain"
    );
    assert_eq!(
        decide_create(OVERLAPPING_CELL).status,
        status::ACCESS_DENIED,
        "09 section 1 rule 1 precedes rule 2: a non-UserMode create is ACCESS_DENIED even when the name would also refuse it"
    );
}

/// Every one of the four outcomes must be reached by some cell, or the sweep
/// grades arms it never visits.
#[test]
fn every_outcome_is_reached() {
    let mut access_denied = false;
    let mut name_not_found = false;
    let mut insufficient = false;
    let mut success = false;
    for request in ALL_CREATE_REQUESTS {
        let s = decide_create(request).status;
        if s == status::ACCESS_DENIED {
            access_denied = true;
        } else if s == status::OBJECT_NAME_NOT_FOUND {
            name_not_found = true;
        } else if s == INSUFFICIENT_RESOURCES {
            insufficient = true;
        } else if s == SUCCESS {
            success = true;
        }
    }
    assert!(
        access_denied && name_not_found && insufficient && success,
        "an outcome no cell reaches: denied={access_denied} name={name_not_found} insufficient={insufficient} success={success}"
    );
}

/// The seven `(name, function, code)` rows of `02-transport.md` §10.2, parsed.
fn parsed_ioctl_table() -> Vec<(String, u32, u32)> {
    let mut rows = Vec::new();
    for line in subsection(TRANSPORT, TRANSPORT_IOCTL_SUBSECTION).lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let (Some(name), Some(func), Some(value)) = (cells.get(1), cells.get(2), cells.get(3))
        else {
            continue;
        };
        let strip = |c: &str| c.trim_matches('`').trim().to_string();
        let (n, f, v) = (strip(name), strip(func), strip(value));
        if !n.starts_with("IOCTL_FSRING_") {
            continue;
        }
        let (Some(fh), Some(vh)) = (f.strip_prefix("0x"), v.strip_prefix("0x")) else {
            continue;
        };
        let (Ok(fu), Ok(vu)) = (u32::from_str_radix(fh, 16), u32::from_str_radix(vh, 16)) else {
            continue;
        };
        rows.push((n, fu, vu));
    }
    rows
}

/// The seven codes agree across three sources, one of which is independent.
///
/// Source 1 is C2's own restatement of §10.2's arithmetic from public frozen
/// constants. Source 2 is `fsring-abi`'s `IOCTL_FSRING_*`, computed by its
/// **private** `control_ioctl`. Those are different code paths but the same
/// formula, so agreeing proves little by itself.
///
/// Source 3 is the **literal values tabulated in §10.2**, parsed at test time.
/// That leg is independent of the arithmetic, and it is what makes this a check
/// rather than a formula compared with itself — the same-source-twice defect
/// B2 was caught by.
#[test]
fn the_seven_codes_agree_across_three_sources() {
    use fsring_abi::control::{CONTROL_IOCTL_ACCESS, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED};
    let derive = |function: u32| {
        (FILE_DEVICE_UNKNOWN << 16)
            | (CONTROL_IOCTL_ACCESS << 14)
            | (function << 2)
            | METHOD_BUFFERED
    };
    let table = parsed_ioctl_table();
    assert_eq!(
        table.len(),
        ALL_CONTROL_IOCTLS.len(),
        "section 10.2 and the authored registry must have the same cardinality"
    );

    for ioctl in ALL_CONTROL_IOCTLS {
        let name = ioctl.doc_name();
        let Some((_, doc_function, doc_code)) = table.iter().find(|(n, _, _)| n == name) else {
            panic!("{name} is absent from §10.2")
        };
        assert_eq!(
            derive(ioctl.function()),
            ioctl.code(),
            "{name}: C2's derivation disagrees with fsring-abi"
        );
        assert_eq!(
            ioctl.code(),
            *doc_code,
            "{name}: fsring-abi disagrees with §10.2's tabulated value"
        );
        assert_eq!(ioctl.function(), *doc_function, "{name}: function number");
    }
}

/// The demux admits exactly the seven.
#[test]
fn demux_admits_exactly_the_seven() {
    for ioctl in ALL_CONTROL_IOCTLS {
        assert_eq!(
            demux(ioctl.code()),
            Some(ioctl),
            "{} must demux",
            ioctl.doc_name()
        );
    }
    // METHOD_BUFFERED is 0 and the codes step by 4, so +1..3 are the nearest
    // non-codes — the ones a sloppy range check would admit.
    for ioctl in ALL_CONTROL_IOCTLS {
        for delta in [1u32, 2, 3] {
            let near = ioctl.code().wrapping_add(delta);
            assert_eq!(demux(near), None, "{near:#010x} is not a control code");
        }
    }
    for probe in [0u32, 1, 0x0022_dffc, 0x0022_e01c, 0x0022_e100, u32::MAX] {
        assert_eq!(demux(probe), None, "{probe:#010x} is not a control code");
    }
}

/// No two entries share a code, a function or a name.
#[test]
fn the_registry_has_no_collisions() {
    for (i, a) in ALL_CONTROL_IOCTLS.iter().enumerate() {
        for b in ALL_CONTROL_IOCTLS.iter().skip(i.saturating_add(1)) {
            assert_ne!(a.code(), b.code(), "{a:?} and {b:?} share a code");
            assert_ne!(
                a.function(),
                b.function(),
                "{a:?} and {b:?} share a function"
            );
            assert_ne!(a.doc_name(), b.doc_name());
        }
    }
}

/// `09-security.md` §1's conjunction, with each half shown load-bearing.
#[test]
fn both_conditions_are_required_and_each_is_load_bearing() {
    let captured = RequestorId(0x1234);
    let other = RequestorId(0x5678);

    // Both hold.
    let ok = authorize(RequestorMode::UserMode, captured, captured);
    assert!(matches!(ok, Authorization::Admitted(_)));
    assert_eq!(ok.status(), SUCCESS);
    let Authorization::Admitted(handle) = ok else {
        panic!("just checked")
    };
    assert_eq!(handle.identity(), captured);

    // Mode alone fails — the identity matches.
    assert_eq!(
        authorize(RequestorMode::KernelMode, captured, captured),
        Authorization::Refused,
        "§1 requires RequestorMode == UserMode"
    );
    // Identity alone fails — the mode is right. §1's "duplicated or inherited
    // handle presented from a different process".
    assert_eq!(
        authorize(RequestorMode::UserMode, captured, other),
        Authorization::Refused,
        "§1 requires the current EPROCESS to match the one captured at CREATE"
    );
    // Neither holds.
    assert_eq!(
        authorize(RequestorMode::KernelMode, captured, other),
        Authorization::Refused
    );
    assert_eq!(Authorization::Refused.status(), status::ACCESS_DENIED);
}

/// The conjunction's sentence is still in the document.
fn assert_authorization_statement(sec: &str) {
    let actual = exact_statement(
        sec,
        AUTHORIZATION_START,
        AUTHORIZATION_END,
        "09-security.md section 1 authorization statement",
    );
    assert_eq!(actual, AUTHORIZATION_STATEMENT);
}

#[test]
fn the_authorization_sentences_are_still_in_the_document() {
    assert_authorization_statement(section(SECURITY, SECURITY_SECTION));
}

#[test]
fn the_authorization_selector_rejects_a_complete_decoy() {
    let changed = AUTHORIZATION_STATEMENT.replace(
        "matching the one captured at CREATE",
        "matching any process in the session",
    );
    let source = format!("{AUTHORIZATION_STATEMENT}\n\n{changed}");
    assert!(
        std::panic::catch_unwind(|| assert_authorization_statement(&source)).is_err(),
        "the selector accepted the first of two authorization statements"
    );
}

#[test]
fn the_authorization_checker_rejects_each_omitted_clause() {
    for changed in [
        AUTHORIZATION_STATEMENT.replace(
            "matching the one captured at CREATE",
            "matching any process in the session",
        ),
        AUTHORIZATION_STATEMENT.replace("`ACCESS_DENIED`", "`SUCCESS`"),
    ] {
        assert!(
            std::panic::catch_unwind(|| assert_authorization_statement(&changed)).is_err(),
            "a load-bearing authorization change was accepted"
        );
    }
}

/// A refusal cannot carry a mapping, and this states why no test asserts it.
///
/// `Authorization::Refused` is a fieldless variant, so "a refusal with a
/// mapping attached" is not a value that can be constructed. The property is
/// held by the type, not by an assertion — which is what §1's *"with no mapping
/// or side effect"* deserves. The compile-fail fixture
/// `refusal_carrying_a_mapping` is the structural proof.
#[test]
fn a_refusal_carries_nothing() {
    let refused = Authorization::Refused;
    assert_eq!(refused.status(), status::ACCESS_DENIED);
    // The only two shapes.
    match refused {
        Authorization::Admitted(_) => panic!("not admitted"),
        Authorization::Refused => {}
    }
}

const IOCTL_ACCESS_DENIED: i32 = 0xc000_0022u32 as i32;
const IOCTL_INVALID_PARAMETER: i32 = 0xc000_000du32 as i32;
const IOCTL_NOT_SUPPORTED: i32 = 0xc000_00bbu32 as i32;
const IOCTL_REVISION_MISMATCH: i32 = 0xc000_0059u32 as i32;

const IOCTL_CAPTURED: RequestorId = RequestorId(0x0123_4567_89ab_cdef);
const IOCTL_OTHER_PROCESS: RequestorId = RequestorId(0xfedc_ba98_7654_3210);

/// A hand-authored little-endian `DonateSecurityContextV1` image: size 32,
/// ABI revision 1, zero flags/reserved, and opaque nonzero payload values.
const IOCTL_VALID_DONATE: [u8; 32] = [
    0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn ioctl_decision(
    mode: RequestorMode,
    current: RequestorId,
    code: u32,
    input: &[u8],
) -> ControlDispatchDecision {
    decide_control_ioctl(ControlIoctlRequest {
        mode,
        captured: IOCTL_CAPTURED,
        current,
        code,
        input,
    })
}

fn assert_ioctl_completion(decision: ControlDispatchDecision, expected_status: i32) {
    assert_eq!(
        decision,
        ControlDispatchDecision::Complete(expected_status),
        "completion status"
    );
    assert_eq!(
        decision.information(),
        0,
        "IOCTL Information is always zero"
    );
}

/// Authorization precedes both demux and donation validation, so neither an
/// unknown code nor a malformed donation can disclose its later classification.
#[test]
fn ioctl_foreign_process_and_kernel_mode_are_denied_before_demux_or_validation() {
    for (mode, current, code, input) in [
        (
            RequestorMode::UserMode,
            IOCTL_OTHER_PROCESS,
            0x0022_e01c,
            &IOCTL_VALID_DONATE[..31],
        ),
        (
            RequestorMode::KernelMode,
            IOCTL_CAPTURED,
            0x0022_e01c,
            &IOCTL_VALID_DONATE[..31],
        ),
        (
            RequestorMode::UserMode,
            IOCTL_OTHER_PROCESS,
            fsring_abi::control::IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
            &IOCTL_VALID_DONATE[..31],
        ),
        (
            RequestorMode::KernelMode,
            IOCTL_CAPTURED,
            fsring_abi::control::IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
            &IOCTL_VALID_DONATE[..31],
        ),
    ] {
        assert_ioctl_completion(
            ioctl_decision(mode, current, code, input),
            IOCTL_ACCESS_DENIED,
        );
    }
}

#[test]
fn ioctl_unknown_code_is_classified_for_the_adapter() {
    let decision = ioctl_decision(
        RequestorMode::UserMode,
        IOCTL_CAPTURED,
        0x0022_e01c,
        &IOCTL_VALID_DONATE,
    );
    assert_eq!(decision, ControlDispatchDecision::Unknown);
    assert_eq!(decision.information(), 0);
}

#[test]
fn ioctl_setup_and_enter_are_handed_to_their_native_adapters() {
    // Both are implemented: the pure decision no longer completes them, it
    // names the adapter that owns the whole ordered choreography.
    assert_eq!(
        ioctl_decision(
            RequestorMode::UserMode,
            IOCTL_CAPTURED,
            fsring_abi::control::IOCTL_FSRING_SETUP,
            &IOCTL_VALID_DONATE,
        ),
        ControlDispatchDecision::DispatchSetup,
    );
    assert_eq!(
        ioctl_decision(
            RequestorMode::UserMode,
            IOCTL_CAPTURED,
            fsring_abi::control::IOCTL_FSRING_ENTER,
            &IOCTL_VALID_DONATE,
        ),
        ControlDispatchDecision::DispatchEnter,
    );
}

#[test]
fn an_unauthorized_setup_never_reaches_the_adapter() {
    // Authorization still precedes demux: a foreign process learns nothing
    // about which codes are implemented.
    for (mode, current) in [
        (RequestorMode::KernelMode, IOCTL_CAPTURED),
        (RequestorMode::UserMode, IOCTL_OTHER_PROCESS),
    ] {
        assert_eq!(
            ioctl_decision(
                mode,
                current,
                fsring_abi::control::IOCTL_FSRING_SETUP,
                &IOCTL_VALID_DONATE,
            ),
            ControlDispatchDecision::Complete(IOCTL_ACCESS_DENIED),
        );
    }
}

#[test]
fn a_dispatch_decision_carries_no_synchronous_completion() {
    let dispatched = ioctl_decision(
        RequestorMode::UserMode,
        IOCTL_CAPTURED,
        fsring_abi::control::IOCTL_FSRING_SETUP,
        &IOCTL_VALID_DONATE,
    );
    assert!(
        !dispatched.is_synchronous(),
        "an adapter-owned operation is not completed by the pure decision",
    );
    for synchronous in [
        ioctl_decision(
            RequestorMode::UserMode,
            IOCTL_CAPTURED,
            fsring_abi::control::IOCTL_FSRING_ATTACH,
            &IOCTL_VALID_DONATE,
        ),
        ioctl_decision(
            RequestorMode::UserMode,
            IOCTL_CAPTURED,
            0x0022_e01c,
            &IOCTL_VALID_DONATE,
        ),
    ] {
        assert!(synchronous.is_synchronous());
        assert_eq!(synchronous.information(), 0);
    }
}

#[test]
fn ioctl_all_known_non_donation_codes_are_not_supported() {
    for ioctl in [
        // SETUP and ENTER are implemented and are covered by their own tests
        // above; everything left in the registry is still refused here.
        ControlIoctl::Attach,
        ControlIoctl::DonateBacking,
        ControlIoctl::Detach,
        ControlIoctl::RetireMount,
    ] {
        assert_ioctl_completion(
            ioctl_decision(
                RequestorMode::UserMode,
                IOCTL_CAPTURED,
                ioctl.code(),
                &IOCTL_VALID_DONATE,
            ),
            IOCTL_NOT_SUPPORTED,
        );
    }
}

#[test]
fn ioctl_donate_short_body_is_invalid_parameter() {
    assert_ioctl_completion(
        ioctl_decision(
            RequestorMode::UserMode,
            IOCTL_CAPTURED,
            fsring_abi::control::IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
            &IOCTL_VALID_DONATE[..31],
        ),
        IOCTL_INVALID_PARAMETER,
    );
}

#[test]
fn ioctl_donate_wrong_abi_revision_is_revision_mismatch() {
    const WRONG_REVISION: [u8; 32] = [
        0x20, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
        0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    assert_ioctl_completion(
        ioctl_decision(
            RequestorMode::UserMode,
            IOCTL_CAPTURED,
            fsring_abi::control::IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
            &WRONG_REVISION,
        ),
        IOCTL_REVISION_MISMATCH,
    );
}

#[test]
fn ioctl_donate_nonzero_flags_or_reserved_are_invalid_parameter() {
    const NONZERO_FLAGS: [u8; 32] = [
        0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
        0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    const NONZERO_RESERVED: [u8; 32] = [
        0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
        0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00,
    ];
    for input in [&NONZERO_FLAGS[..], &NONZERO_RESERVED[..]] {
        assert_ioctl_completion(
            ioctl_decision(
                RequestorMode::UserMode,
                IOCTL_CAPTURED,
                fsring_abi::control::IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
                input,
            ),
            IOCTL_INVALID_PARAMETER,
        );
    }
}

#[test]
fn ioctl_well_formed_donate_body_is_not_supported() {
    assert_ioctl_completion(
        ioctl_decision(
            RequestorMode::UserMode,
            IOCTL_CAPTURED,
            fsring_abi::control::IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
            &IOCTL_VALID_DONATE,
        ),
        IOCTL_NOT_SUPPORTED,
    );
}

#[test]
fn ioctl_every_outcome_has_zero_information_and_no_side_effect_value() {
    let decisions = [
        ioctl_decision(
            RequestorMode::UserMode,
            IOCTL_OTHER_PROCESS,
            0x0022_e01c,
            &IOCTL_VALID_DONATE,
        ),
        ioctl_decision(
            RequestorMode::UserMode,
            IOCTL_CAPTURED,
            0x0022_e01c,
            &IOCTL_VALID_DONATE,
        ),
        ioctl_decision(
            RequestorMode::UserMode,
            IOCTL_CAPTURED,
            fsring_abi::control::IOCTL_FSRING_ATTACH,
            &IOCTL_VALID_DONATE,
        ),
        ioctl_decision(
            RequestorMode::UserMode,
            IOCTL_CAPTURED,
            fsring_abi::control::IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
            &IOCTL_VALID_DONATE[..31],
        ),
    ];
    for decision in decisions {
        assert_eq!(decision.information(), 0);
        // Exhaustive on purpose: a new decision variant must be classified
        // here rather than silently inheriting "zero information".
        match decision {
            ControlDispatchDecision::Complete(_) | ControlDispatchDecision::Unknown => {}
            ControlDispatchDecision::DispatchSetup | ControlDispatchDecision::DispatchEnter => {
                panic!("no synchronous decision above is adapter-owned")
            }
        }
    }
}

/// SETUP's refusal status follows `02-transport.md`'s precedence even when the
/// request's LENGTH is also wrong.
///
/// The driver used to check `input_length == SETUP_REQUEST_V1_SIZE` before it
/// read a single header byte, and to complete every validator refusal as
/// `INVALID_PARAMETER`. The normative text: "Once eight bytes are safely
/// available, an unknown version has precedence and maps to REVISION_MISMATCH,
/// then unsupported required flags map to NOT_SUPPORTED, then malformed
/// size/range/reserved bytes map to INVALID_PARAMETER. A length below eight
/// cannot expose a version and is INVALID_PARAMETER." (round-17 evidence E4)
///
/// Driven through the REAL frozen validator with a snapshot of exactly the
/// length `control_request_snapshot_len` answers, and with the profile and
/// masks `fsring-fsd` passes on the Win10-x64 image. Topology fields stay zero:
/// every case below is decided before the validator reaches the topology.
#[test]
fn setup_refusal_status_follows_transport_precedence_through_the_snapshot() {
    use fsring_abi::codec::try_encode;
    use fsring_abi::control::{SETUP_REQUEST_V1_SIZE, SetupRequestV1};
    use fsring_abi::features::{FeatureSet, PlatformProfile};
    use fsring_abi::msgs::common::{CONTROL_VERSION_V1, ControlHeader};
    use fsring_abi::validate::validate_setup_request_v1;

    const SECURITY: u64 = 0x10;
    const UNIMPLEMENTED_BIT: u64 = 0x8000_0000;
    let size = SETUP_REQUEST_V1_SIZE as usize;

    let request = |version: u16, required_flags: u16, offered: u64, required: u64| {
        let value = SetupRequestV1 {
            header: ControlHeader {
                struct_size: SETUP_REQUEST_V1_SIZE,
                struct_version: version,
                required_flags,
            },
            abi_major: 2,
            min_abi_minor: 1,
            max_abi_minor: 1,
            offered_features: FeatureSet {
                words: [offered, 0],
            },
            required_features: FeatureSet {
                words: [required, 0],
            },
            ..SetupRequestV1::default()
        };
        let mut bytes = vec![0u8; size.saturating_add(64)];
        assert!(matches!(try_encode(&value, &mut bytes), Ok(n) if n == size));
        bytes
    };
    // The status the driver completes for `input_length` bytes of `bytes`.
    let status_for = |bytes: &[u8], input_length: usize| -> i32 {
        let Some(n) = control_request_snapshot_len(input_length, size) else {
            return status::INVALID_PARAMETER;
        };
        let Some(snapshot) = bytes.get(..n) else {
            panic!("the snapshot fits the request");
        };
        match validate_setup_request_v1(
            snapshot,
            PlatformProfile::Win10X64,
            FeatureSet {
                words: [SECURITY, 0],
            },
            PlatformProfile::Win10X64.os_capability_mask(),
            true,
        ) {
            Ok(_) => status::SUCCESS,
            Err(error) => error.status(),
        }
    };

    let known = request(CONTROL_VERSION_V1, 0, SECURITY, SECURITY);
    let unknown_version = request(99, 0, SECURITY, SECURITY);
    let unknown_flag = request(CONTROL_VERSION_V1, 0x8000, SECURITY, SECURITY);
    let unimplemented = request(
        CONTROL_VERSION_V1,
        0,
        SECURITY | UNIMPLEMENTED_BIT,
        UNIMPLEMENTED_BIT,
    );
    let not_offered = request(CONTROL_VERSION_V1, 0, SECURITY, UNIMPLEMENTED_BIT);

    let rows: [(&str, &[u8], usize, i32); 10] = [
        (
            "seven bytes expose no version",
            &unknown_version,
            7,
            status::INVALID_PARAMETER,
        ),
        (
            "unknown version, short",
            &unknown_version,
            size.saturating_sub(4),
            status::REVISION_MISMATCH,
        ),
        (
            "unknown version, long",
            &unknown_version,
            size.saturating_add(64),
            status::REVISION_MISMATCH,
        ),
        (
            "unknown version, exact",
            &unknown_version,
            size,
            status::REVISION_MISMATCH,
        ),
        (
            "unknown required flag, long",
            &unknown_flag,
            size.saturating_add(64),
            status::NOT_SUPPORTED,
        ),
        (
            "known header, one byte long",
            &known,
            size.saturating_add(1),
            status::INVALID_PARAMETER,
        ),
        (
            "known header, far too long",
            &known,
            size.saturating_add(64),
            status::INVALID_PARAMETER,
        ),
        (
            "required but unimplemented",
            &unimplemented,
            size,
            status::NOT_SUPPORTED,
        ),
        // A copy truncated to the known size would reach the selector and answer
        // NOT_SUPPORTED; the caller's real length is one byte too many.
        (
            "required but unimplemented, one byte long",
            &unimplemented,
            size.saturating_add(1),
            status::INVALID_PARAMETER,
        ),
        (
            "required but not offered",
            &not_offered,
            size,
            status::INVALID_PARAMETER,
        ),
    ];
    for (name, bytes, input_length, expected) in rows {
        assert_eq!(status_for(bytes, input_length), expected, "{name}");
    }
}

/// The snapshot length itself: nothing below the header, the caller's length up
/// to one byte past the known size, and never more.
#[test]
fn control_request_snapshot_len_is_bounded() {
    assert_eq!(control_request_snapshot_len(0, 160), None);
    assert_eq!(control_request_snapshot_len(7, 160), None);
    assert_eq!(control_request_snapshot_len(8, 160), Some(8));
    assert_eq!(control_request_snapshot_len(160, 160), Some(160));
    assert_eq!(control_request_snapshot_len(161, 160), Some(161));
    assert_eq!(control_request_snapshot_len(usize::MAX, 160), Some(161));
    assert_eq!(control_request_snapshot_len(8, usize::MAX), Some(8));
}
