#!/usr/bin/env python3
"""Fail when a LIVE document says a CLOSED task will still do something.

Round 15's evidence review raised this as a HIGH. Two such statements had been
repaired one commit earlier, the shape was written down in the gate document,
and nobody swept for the rest: nine survived, two of them in this repository's
own gate manifest, asserting the very cutover the same round's new gate-document
entry proves never happened.

The defect shape has three forms, all of which say something false about the
tree as it stands today:

  1. a property held only "until Task N", where Task N is closed;
  2. a closed Task N named as what *will* first do something;
  3. a RETIRED staging gate named as what proves a property *today*.

WHY A GATE AND NOT A GREP. The round-15 finding was not that the statements
existed -- it was that finding two of them and describing the shape was mistaken
for sweeping. A grep run once decays the moment the next task closes. So the
live population the matcher REACHES is pinned in ADJUDICATED below: every
statement it finds carries a written reason, and any new or changed one fails
until a human adjudicates it. Its size is pinned too (`EXPECTED_STATEMENTS`), so
a scope or reader regression that makes statements disappear fails as loudly as
a new one.

WHAT IT DOES NOT REACH, stated because round 17 wrote "every surviving mention"
here and round 17's evidence review falsified it on the tree itself. This is a
lower bound on the defect population, not the population:

  * a promise that names no task number -- "until the R5 cutover" -- is not
    mapped to the task that performed that cutover;
  * one match per statement: a promise appended INSIDE the span an adjudicated
    needle covers inherits that needle's reason;
  * a closed task named as future in words no alternation lists;
  * prose outside the documents `is_live` names and the comment and string
    readers `blocks_for` implements.

WHY FIXTURES AND NOT THE LIVE SET FOR THE SELF-TEST. The first version of this
sweep missed two of the nine known statements: one because the possessive form
put two words between the task and its verb ("Task 25's atomic cutover is the
first"), one because the phrase was split across two `///` lines and the scan was
line-based. Both are fixtures below. A self-test that asserted "find the nine"
would have gone quiet the moment they were fixed; fixtures keep testing the
matcher's reach after the population is clean.

Usage:
    python driver/scripts/audit_c4_task_promises.py --self-test
    python driver/scripts/audit_c4_task_promises.py --check [--root .]
    python driver/scripts/audit_c4_task_promises.py --list  [--root .]
"""
import argparse
import ast
import os
import re
import subprocess

CLOSED_MAX = 29  # Tasks 1-29 closed. Task 30 is R7, NOT RUN, and may be future.

LIVE_GATE_DOC = "docs/superpowers/reviews/2026-08-08-driver-c4-recovery-gate.md"

# ---------------------------------------------------------------- matcher ----
#
# The bracketed run spans the words between a possessive task and its verb
# without crossing into the next sentence. Every match runs against a
# WHITESPACE-COLLAPSED block, so a phrase broken over several comment lines is
# already one string by the time it gets here.
#
# Round-16 E2(b) widened forms 1 and 2. Ten plants in the gate's own two forms
# were run against the previous expression and SEVEN passed silently: the
# possessive with a future verb, and the four prepositions below, each of which
# bounds a property by a task exactly as `until` does.
# Round-17 evidence E1(b) widened it again, after 22 of 24 plants passed:
#   * a task may be written `Task N Step M`, and plural as `Tasks N and M` or
#     `Tasks N-M` (the `(?:...)*` tails below);
#   * `until the Task N cutover` bounds as `until Task N` does;
#   * `is going to`, `should`, `left for` are futures and bounds too;
#   * a possessive may use U+2019 and its bracketed run may cross a comma.
# The TASK sub-expression carries every number it names into one group each, so
# the closed/future decision below sees all of them.
_TASK = (
    r"Tasks?\s+(?P<{0}>\d+)"
    r"(?:\s+Step\s+\d+)?"
    r"(?:\s*(?:,|-|–|and|or)\s*(?P<{0}2>\d+))*"
)
# The verbs that make a task a FUTURE actor, in one list used by both the plain
# and the possessive form. Round-18 evidence E2: they were two lists, and the
# possessive carried nine fewer verbs, so "Task 25's cutover gives it a caller"
# was invisible while "Task 25 gives it a caller" was caught.
_VERBS = (
    r"(?:will|is\s+going\s+to|should|gives|adds|consumes|wires|extends"
    r"|installs|enables|introduces|routes|has\s+to|makes\s+it|reaches\s+it"
    r"|onward\s+are|is\s+what|is\s+the\s+(?:first|commit|sole|one|only))"
)
# The words a statement may put between the task and its verb without leaving
# the clause. Bounded, and it may not cross a sentence end.
_RUN = r"(?:[\w`'’/:, -]|\.(?!\s)){0,48}?"
PROMISE = re.compile(
    r"until\s+(?:the\s+)?" + _TASK.format("u")
    + r"|(?:once|pending|before|deferred\s+to|left\s+for)\s+(?:the\s+)?"
    + _TASK.format("b")
    + r"|when\s+(?:the\s+rest\s+of\s+)?" + _TASK.format("w") + r"\s+lands?\b"
    # The possessive: "Task 25's cutover WILL bind the storage".
    + r"|Task\s+(?P<f>\d+)['’]s\s" + _RUN + r"\b" + _VERBS + r"\b"
    # The plain form, with the same bounded run. Round-18 evidence E2 again: a
    # noun between the task and the verb -- "The Task 25 cutover will bind the
    # storage" -- escaped a matcher that required the verb to follow the number
    # immediately.
    + r"|" + _TASK.format("c") + r"(?:\s" + _RUN + r")?\s\b" + _VERBS + r"\b"
    r"|today\s+the\s+staging\s+gate"
    r"|until\s+then\s+the\s+staging\s+gate",
    re.I,
)


# "until Task N" is a promise when the thing it bounds is still true, and plain
# history when it is not: "unreachable until Task 25" versus "it was 47 until
# Task 28's reconciliation". The discriminator is a past-tense verb in front of
# the "until", inside the same sentence.
#
# Round-16 E2(b): "deliberately narrow" was a claim, not a property. The window
# was 80 characters and crossed anything but `.` and `;`, so ONE listed verb
# anywhere in a long sentence suppressed a live promise later in it. Both of
# these were swallowed:
#
#   This was added in Task 18 and is production-unreachable until Task 25.
#   The slab had one owner and stays unreachable until Task 25.
#
# The verb has to govern the `until`, so the window is now 32 characters and may
# not cross a clause boundary -- `and`, `but`, `while`, `so`, `which`, `that`,
# `then` -- because a verb on the far side of one of those governs its own clause
# and not this one. The fixtures pin both directions: a genuine history that must
# stay suppressed, and these two that must not.
PAST_BEFORE_UNTIL = re.compile(
    r"\b(?:was|were|had|has\s+been|have\s+been|used\s+to|stayed|remained|"
    r"did|could\s+not|would)\b"
    # Round-17 evidence E1(b): a `,` or `:` ends the clause too -- "As it did
    # in R3, it stays unreachable until Task 25" was swallowed across a comma.
    r"(?:(?!\b(?:and|but|while|so|which|that|then)\b)[^.;,:])"
    r"{0,32}$",
    re.I,
)


def _is_historical_until(block, match):
    """True when this `until Task N` sits after a past-tense verb in its sentence."""
    if not (match.group("u")):
        return False
    head = block[: match.start()]
    sentence = re.split(r"[.;]\s", head)[-1] if head else ""
    return bool(PAST_BEFORE_UNTIL.search(sentence))


def promise_spans(block):
    """`(start, end)` of every promise-shaped statement naming a closed task.

    A hit naming no number at all -- "today the staging gate proves it" -- still
    counts: a retired gate asserted as current proof is form 3.

    SPANS, not a count per block. Adjudication used to be keyed on the block, and
    a comment block is as long as its author made it: the first version of this
    file adjudicated the block around `Task 3's consuming setup transition is the
    sole minting path`, and a planted `nothing reads this until Task 21 lands`
    inserted two lines above it was covered by that same entry and never
    reported. Every statement is now adjudicated on its own span.
    """
    out = []
    for m in PROMISE.finditer(block):
        if _is_historical_until(block, m):
            continue
        nums = [int(v) for v in m.groupdict().values() if v]
        # `min`, not `max`: a plural or listed form names several tasks, and a
        # statement about any closed one among them is the defect. With `max`,
        # "until Task 25, 400 bytes" read the size as Task 400 and was silent.
        if not nums or min(nums) <= CLOSED_MAX:
            out.append((m.start(), m.end()))
    return out


def promise_hits(block):
    """Backwards-compatible count of the spans above."""
    return promise_spans(block)


def adjudication_for(rel, block, start, end):
    """The recorded reason covering the statement at `[start, end)`, or None.

    An entry covers a statement only when the needle's own occurrence in the
    block CONTAINS that statement. A needle elsewhere in the same block -- even
    one word away -- covers nothing, which is what makes a newly added promise
    surface instead of inheriting its neighbour's reason.

    This is NOT on its own enough, and round-16 E2(a) is why: a verbatim COPY of
    an adjudicated sentence, in a brand-new block anywhere in the same file,
    contains the needle too and so inherits the excuse. `needle_occurrences`
    below closes that -- an entry is valid only while its needle still occurs the
    number of times it was adjudicated for, so the copy makes the count 2 and
    fails the run.
    """
    for (arel, needle), why in ADJUDICATED.items():
        if arel != rel:
            continue
        at = block.find(needle)
        while at != -1:
            if at <= start and end <= at + len(needle):
                return why
            at = block.find(needle, at + 1)
    return None


def needle_occurrences(root):
    """How many times each adjudication needle occurs in its file.

    Two failures this answers, neither of which the per-match keying can see:

    * a needle occurring MORE than once -- someone copied an adjudicated
      sentence, and the copy would silently inherit the original's reason
      (round-16 E2(a));
    * a needle occurring ZERO times -- a dead entry whose statement is gone, so
      the table carries a written reason for nothing. Round 16 shipped one: the
      `fence.rs` entry excused "Superseded wording retained inside the sentence
      that replaces it" about a phrase the same commit had deleted, so the
      reason was false and covered nothing (round-16 E2(d)).
    """
    counts = {}
    cache = {}
    for arel, needle in ADJUDICATED:
        if arel not in cache:
            path = os.path.join(root, arel.replace("/", os.sep))
            if os.path.isfile(path):
                raw = open(path, encoding="utf-8", errors="replace").read()
                # Count over the same BLOCKS the needles were taken from, not
                # over the raw file. Block text has its comment markers stripped,
                # so a needle spanning two `///` lines reads `... text more ...`
                # in a block and `... text /// more ...` in the file: counting
                # against the file reported fifteen live entries as dead.
                #
                # Using blocks also drops the need to exclude this file's own
                # ADJUDICATED table -- its needles are string literals, which are
                # neither a `#` comment nor a docstring, so no reader returns
                # them and a self-referential entry counts once.
                cache[arel] = [
                    " ".join(block.split()) for _line, block in blocks_for(arel, raw)
                ]
            else:
                cache[arel] = []
        wanted = " ".join(needle.split())
        counts[(arel, needle)] = sum(b.count(wanted) for b in cache[arel])
    return counts


# ------------------------------------------------------------------ blocks ---
COMMENT = re.compile(r"^\s*(?://[/!]?|#)\s?(.*)$")


def comment_blocks(text):
    """(start_line, text) for each run of consecutive comment lines."""
    blocks, start, buf = [], None, []
    for n, line in enumerate(text.split("\n"), 1):
        m = COMMENT.match(line)
        if m:
            if start is None:
                start = n
            buf.append(m.group(1))
        elif start is not None:
            blocks.append((start, " ".join(buf)))
            start, buf = None, []
    if start is not None:
        blocks.append((start, " ".join(buf)))
    return blocks


def json_string_blocks(text):
    """(line, value) for every JSON string long enough to be prose."""
    blocks = []
    for n, line in enumerate(text.split("\n"), 1):
        for m in re.finditer(r'"((?:[^"\\]|\\.){24,})"', line):
            blocks.append((n, m.group(1)))
    return blocks


def markdown_blocks(text):
    """(start_line, text) per blank-line-separated paragraph."""
    blocks, start, buf = [], None, []
    for n, line in enumerate(text.split("\n"), 1):
        if line.strip():
            if start is None:
                start = n
            buf.append(line.strip())
        elif start is not None:
            blocks.append((start, " ".join(buf)))
            start, buf = None, []
    if start is not None:
        blocks.append((start, " ".join(buf)))
    return blocks


RUST_BLOCK_COMMENT = re.compile(r"/\*(.*?)\*/", re.S)


def docstring_blocks(text):
    """(start_line, text) for every Python docstring.

    Round-16 E2(c): `comment_blocks` matches `#` lines only, so four
    promise-shaped statements sat unadjudicated in this very file's own module
    and function docstrings while its `#` comments were adjudicated on the stated
    principle that exempting the file would blind the sweep.

    PARSED, not regex-paired. The first version matched a triple-quote pair with
    `re.S`, which pairs the module docstring's closing quotes with the next
    triple quote anywhere below and hands back everything in between -- including
    this file's own ADJUDICATED table, as several hundred spurious statements. A
    docstring is a language construct; ask the language. (Writing that regex in
    this docstring also ended it early, which is the same lesson twice.)
    """
    blocks = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return blocks
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if not isinstance(first, ast.Expr):
            continue
        value = first.value
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            continue
        blocks.append((first.lineno, " ".join(value.value.split())))
    return blocks


def adjudicated_table_span(text):
    """`(first, last)` source lines of the ADJUDICATED assignment, or None.

    The table quotes the sentences it excuses, so every self-referential entry --
    one whose file IS this file -- would otherwise be counted twice by
    `needle_occurrences` and reported as a copied sentence. Excluding the table's
    own lines counts what is in the DOCUMENT rather than what is in the ledger
    about the document.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "ADJUDICATED" for t in node.targets
        ):
            return (node.lineno, getattr(node, "end_lineno", node.lineno))
    return None


def rust_block_comment_blocks(text):
    """(start_line, text) for every `/* ... */`. Also E2(c): never scanned."""
    blocks = []
    for m in RUST_BLOCK_COMMENT.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        blocks.append((line, " ".join(m.group(1).split())))
    return blocks


def trailing_slash_comments(text):
    """(line, text) for a `//` comment AFTER code on the same line.

    Round-17 evidence E1: `comment_blocks` reads lines that START with a comment
    marker, so `let x = 1; // nothing reads this until Task 25` was never read.
    A `//` inside a string literal is not a comment: the quotes before it on the
    line must balance, and a `://` is a URL, not a comment.
    """
    blocks = []
    for n, line in enumerate(text.split("\n"), 1):
        if COMMENT.match(line):
            continue
        at = line.find("//")
        while at != -1:
            head = line[:at]
            if head.count('"') % 2 == 0 and not head.endswith(":"):
                if head.strip():
                    blocks.append((n, line[at + 2:].lstrip("/!").strip()))
                break
            at = line.find("//", at + 2)
    return blocks


def python_trailing_comments(text):
    """(line, text) for a `#` comment AFTER code, found by the tokenizer.

    The tokenizer rather than a regex, because `#` inside a string is common in
    these tools and a regex cannot tell. A file that does not tokenize yields
    nothing here; its full-line comments are still read by `comment_blocks`.
    """
    import io
    import tokenize

    blocks = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return blocks
    for token in tokens:
        if token.type != tokenize.COMMENT:
            continue
        if token.line[: token.start[1]].strip():
            blocks.append((token.start[0], token.string.lstrip("#").strip()))
    return blocks


POWERSHELL_BLOCK_COMMENT = re.compile(r"<#(.*?)#>", re.S)


def powershell_block_comment_blocks(text):
    """(start_line, text) for every PowerShell `<# ... #>`. E1: never read."""
    blocks = []
    for m in POWERSHELL_BLOCK_COMMENT.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        blocks.append((line, " ".join(m.group(1).split())))
    return blocks


def blocks_for(rel, text):
    if rel.endswith((".rs", ".c")):
        return (
            comment_blocks(text)
            + rust_block_comment_blocks(text)
            + trailing_slash_comments(text)
        )
    if rel.endswith(".py"):
        return (
            comment_blocks(text)
            + docstring_blocks(text)
            + python_trailing_comments(text)
        )
    if rel.endswith(".json"):
        return json_string_blocks(text)
    if rel.endswith(".md"):
        return markdown_blocks(text)
    # Shell/batch/PowerShell tools: `#` and `rem` lines. The `#` half is already
    # what `comment_blocks` matches.
    if rel.endswith((".ps1", ".psm1", ".sh", ".cmd", ".bat")):
        # `::` is batch's other comment spelling (E1: a promise written with it
        # was never read), and `<# ... #>` is PowerShell's block comment.
        stripped = "\n".join(
            re.sub(r"^(\s*)(?:rem\b|::)", r"\1#", line, flags=re.I)
            for line in text.split("\n")
        )
        blocks = comment_blocks(stripped)
        if rel.endswith((".ps1", ".psm1")):
            blocks += powershell_block_comment_blocks(text)
        return blocks
    return []


# ------------------------------------------------------------------- scope ---
def is_live(rel):
    """A document is live if a running gate reads it, or a reviewer is sent to it.

    OUT, each for a reason: the PLAN defines the task sequence and must speak of
    it in the future; everything under c4-recovery-logs/ is a sealed attempt or a
    committed review, immutable and true as of its own date; dated gate and
    evidence documents likewise.

    Round-16 E2(c): this did not implement its own sentence. Outside it were the
    design documents a battery row reads and rows P10/R10 send reviewers to, the
    `fsring-abi` and `fsring-user` sources that four rows EXECUTE and that carry
    c4 mutants, every non-Python script tool, and `scripts/verify_spec.py` --
    which carried a live `Task 29 will execute`. All are in now.

    The design documents are in and the plan is not, and the line between them is
    the one the docstring already draws: `docs/design/` is normative about what
    the driver IS, and a reviewer is sent to it to check the source against it; a
    plan is a statement of intent about what will be built, where naming a future
    task is the point.
    """
    if rel == LIVE_GATE_DOC:
        return True
    if rel.startswith("docs/superpowers/plans/"):
        return False
    if rel.startswith("docs/superpowers/reviews/"):
        return False
    if re.fullmatch(r"docs/design/[^/]+\.md", rel):
        return True
    if rel.endswith(".rs") and (
        rel.startswith("driver/")
        or rel.startswith("fsring-abi/src/")
        or rel.startswith("fsring-user/src/")
    ):
        return not (rel.endswith("/tests.rs") or "/tests/" in rel)
    if re.fullmatch(r"driver/audit/[^/]+\.json", rel):
        return True
    # Round-17 evidence E1: `[^/]+` took no subdirectory, so the claim "every
    # script tool" was false at `driver/scripts/locked-cargo/`. Any depth now.
    if re.fullmatch(r"(driver/)?scripts/.+\.(py|ps1|psm1|sh|cmd|bat)", rel):
        return True
    # The READMEs rows P10 and R10 send a reviewer to, and the one native C
    # source the driver image links. Neither was read.
    if rel in ("README.md", "driver/README.md", "fsring-abi/README.md"):
        return True
    if re.fullmatch(r"driver/fsring-fsd/native/[^/]+\.c", rel):
        return True
    return False


# -------------------------------------------------------------- adjudicated --
# Every surviving live mention, with the reason it is not the defect. Keyed on
# (relative path, substring of the collapsed statement), so a line number moving
# does not invalidate an entry but an edited statement does.
#
# Round 16 swept the live population once. Nine statements were repaired because
# they were false on this tree; everything below is what survived, each with the
# reason it is not the defect. The largest class is new: a repaired statement
# that QUOTES the promise it replaced, so a reader can see what was wrong rather
# than finding a sentence that silently changed meaning between rounds. Those
# quotes keep matching, and that is correct -- the matcher cannot tell a quoted
# promise from a live one, and a human deciding which it is, once, is the whole
# mechanism this file implements.
HISTORY = (
    "A repair that quotes the promise it replaced. The quoted clause is the "
    "defect; the sentence around it says so and states what is true instead."
)
RETIRED_GATE_CONTRACT = (
    "The predecessor contract of a RETIRED gate or profile, retained so the "
    "retirement is a recorded decision rather than a deletion. Labelled retired "
    "at the top of its own note, and no live profile carries it."
)
PRESENT_TENSE = (
    "Present tense and true on this tree: it names the commit that introduced a "
    "mechanism, not a commit that is still to act."
)
OWN_EXAMPLE = (
    "An illustrative promise quoted inside this file's own documentation. This "
    "auditor is a live document and sweeps itself -- deliberately, because the "
    "round-15 population included one in `audit_c4_lifetime.py` -- so its "
    "examples match. Adjudicated rather than excluded: exempting the file would "
    "blind the sweep to a real promise written in it later."
)

ADJUDICATED = {
    # -- repairs that quote what they replaced -------------------------------
    ("docs/superpowers/reviews/2026-08-08-driver-c4-recovery-gate.md",
     'The field\'s doc had said "Task 25\'s cutover is what binds the storage"'):
        HISTORY,
    ("driver/audit/c4-production-graph.json",
     "that last clause read `until Task 25`"): HISTORY,
    ("driver/audit/c4-production-graph.json",
     "and R5 must stay unreachable until Task 25 -- both bounds have now"):
        HISTORY,
    ("driver/audit/c4-production-graph.json",
     "it read `Task 25's atomic cutover is the first production caller`"):
        HISTORY,
    ("driver/audit/c4-production-graph.json",
     "sentence previously read `until Task 25`"): HISTORY,
    ("driver/fsring-core/src/enter.rs",
     "credit preflight read it when the rest of Task 20 lands."): HISTORY,
    ("driver/fsring-core/src/enter.rs",
     "the stream it was handed when the rest of Task 20 lands."): HISTORY,
    ("driver/fsring-core/src/enter.rs",
     "is the only consumer until Task 19, and the staging gate"): HISTORY,
    ("driver/fsring-core/src/session.rs",
     'The previous wording, "Task 14 consumes it into `RingRuntimeParts`'):
        HISTORY,
    ("driver/fsring-core/src/session.rs",
     'The bound "until Task 19" has been removed'): HISTORY,
    ("driver/fsring-fsd/src/lifecycle.rs",
     'is still uninhabited until Task 10 introduces it".'): HISTORY,
    ("driver/fsring-fsd/src/pending_enter.rs",
     'The doc used to read "Task 19 gives it a production writer'): HISTORY,
    ("driver/fsring-fsd/src/pending_enter.rs",
     "Task 19 is the commit that first reaches it"): HISTORY,
    ("driver/fsring-fsd/src/pending_enter.rs",
     "until then the staging gate is what proves it.\" Bot"): HISTORY,
    ("driver/fsring-fsd/src/pending_enter.rs",
     "would be a trap Task 19 has to remember to remove ..."): HISTORY,
    ("driver/fsring-fsd/src/pending_enter.rs",
     'comment used to read "Task 20 is what adds CQ entries to it."'): HISTORY,
    ("driver/fsring-fsd/src/pending_enter.rs",
     'This doc used to read "Task 19 gives it a caller'): HISTORY,
    ("driver/fsring-fsd/src/pending_enter.rs",
     "today the staging gate proves it has none.\" Ta"): HISTORY,
    ("driver/fsring-fsd/src/lifecycle.rs",
     '"This is staged. Task 12 is the sole commit that routes production '
     'CLEANUP through it", described the tree before Task 12 landed.'): HISTORY,
    ("driver/fsring-fsd/src/lifecycle.rs",
     '"This is staged. Task 12 is the sole commit that routes production '
     'CLEANUP through it", described the tree before Task 12 landed; the graph'):
        HISTORY,

    # -- retired contracts, labelled as such ---------------------------------
    ("driver/audit/c4-production-graph.json",
     "R4 must stay unreachable until Task 19, and R5 must stay unrea"):
        RETIRED_GATE_CONTRACT,
    # NOT `RETIRED_GATE_CONTRACT`: round-16 E2(d) checked, and the
    # `task09_11_r3_staging_is_production_unreachable` note carries no "retired"
    # label in any case, nor does the `r3-stage` profile note that holds the
    # gate. The `task13_18`/`task20_24` notes and the `r4-cutover`/`r5-stage`
    # profile notes are labelled; this one is not. What is true of it is the
    # addendum, so that is what the reason says now.
    ("driver/audit/c4-production-graph.json",
     "production entry point until Task 12's atomic cutover"):
        "The predecessor contract of a gate Task 12's cutover superseded. The "
        "note carries its own NARROWED addendum naming the 35 rows that became "
        "production-reachable at that cutover and the 5 removed from the source "
        "entirely, so the sentence is bounded by a correction in the same note "
        "rather than by a label.",
    ("driver/audit/c4-production-graph.json",
     "is a staged target too until Task 12 binds it to run_termina"):
        "Same note, same NARROWED addendum; see above. Also not labelled "
        "retired, and round-16 E2(d) is why this reason no longer says it is.",
    ("driver/audit/c4-production-graph.json",
     "from a production root until Task 19's atomic cutover"):
        RETIRED_GATE_CONTRACT,
    ("driver/audit/c4-production-graph.json",
     "Names Task 20 adds or touches"):
        "Names a task as the author of a roster, not as a future actor. Task 20 "
        "did add these names; the sentence does not say anything is still to "
        "come.",

    # -- present tense, true on this tree ------------------------------------
    ("driver/fsring-core/src/adapter/lifecycle.rs",
     "Task 3's consuming setup transition is the sole minting path"):
        PRESENT_TENSE,
    ("driver/fsring-core/src/enter.rs",
     "Task 19's atomic cutover is the only thing permitted to cons"):
        PRESENT_TENSE + " The cutover exists and this is the permission it "
        "carries; it is not a wait for one.",
    ("driver/fsring-core/src/enter.rs",
     "Task 19's cutover is the only thing allowed to consum"):
        PRESENT_TENSE + " Same permission, stated at the readiness check.",
    ("driver/fsring-fsd/src/fence.rs",
     "Task 25's `run_kernel_fence` is the only production scheduler"):
        PRESENT_TENSE + " `run_kernel_fence` is live and is the scheduler; the "
        "task number identifies which commit brought it.",
    ("driver/fsring-fsd/src/lifecycle.rs",
     "Task 6 consumes it into unload guards."):
        PRESENT_TENSE + " The unload guards exist and take this variant.",
    ("driver/fsring-fsd/src/pending_enter.rs",
     "Task 18 adds all four **together wit"):
        PRESENT_TENSE + " A description of the order Task 18 used, which is why "
        "none of the four is ever reachable while uninitialized.",
    ("driver/fsring-fsd/src/pending_enter.rs",
     "Task 18 adds them together WITH the"):
        PRESENT_TENSE + " The same statement on the fields themselves.",
    ("driver/fsring-fsd/src/trace.rs",
     "Task 11 onward are their first callers"):
        PRESENT_TENSE + " The callers arrived: SETUP's "
        "`SetupEffect::EmitSessionPublished` arm calls `trace::emit`, and "
        "LOAD's `LoadEffect::RegisterEtw` arm calls `trace::register`. "
        "(This reason cited `session.rs:1400` and `driver.rs:481`; the "
        "first had moved to another line during round 17's own edits.)",
    ("driver/scripts/audit_c4_lifetime.py",
     "Task 23's two safe proof wrappers. Each is the sole caller of one raw DDI"):
        PRESENT_TENSE + " Both wrappers exist and the digests below pin them.",

    # -- this file's own illustrative examples -------------------------------
    # Round-17 evidence E1's plants, quoted where the matcher and readers were
    # widened to catch them.
    ("driver/scripts/audit_c4_task_promises.py",
     '"Task 25\'s cutover gives it a caller" was invisible while "Task 25 gives '
     'it a caller" was caught'): OWN_EXAMPLE,
    ("driver/scripts/audit_c4_task_promises.py",
     'The possessive: "Task 25\'s cutover WILL bind the storage"'): OWN_EXAMPLE,
    ("driver/scripts/audit_c4_task_promises.py",
     'a noun between the task and the verb -- "The Task 25 cutover will bind the '
     'storage" -- escaped a matcher'): OWN_EXAMPLE,
    ("driver/scripts/audit_c4_task_promises.py",
     "`Task 3 Step 2 will mint this` in `adapter/fence.rs` was newly reached"):
        OWN_EXAMPLE,
    ("driver/scripts/audit_c4_task_promises.py",
     'in R3, it stays unreachable until Task 25" was swallowed across a comma'):
        OWN_EXAMPLE,
    ("driver/scripts/audit_c4_task_promises.py",
     '"until Task 25, 400 bytes" read the size as Task 400'): OWN_EXAMPLE,
    ("driver/scripts/audit_c4_task_promises.py",
     "`let x = 1; // nothing reads this until Task 25` was never read"):
        OWN_EXAMPLE,
    ("driver/scripts/audit_c4_task_promises.py",
     '"unreachable until Task 25" versus'): OWN_EXAMPLE,

    # -- surfaces the round-17 widening brought into scope ------------------
    ("driver/fsring-core/src/lockrank.rs",
     "ing is not a listed edge. Before Task 20 the CQ role was reachable"):
        "Past tense about a lock-order edge, and true: it describes what the "
        "graph looked like before Task 20 added the CQ lane, as the justification "
        "for the edge that exists now. The suppressor cannot see it because the "
        "verb sits in the following clause.",
    ("driver/fsring-core/src/session.rs",
     "k has a production caller until Task 19's atomic cutover, and the"): HISTORY,
    ("driver/fsring-core/src/session.rs",
     "rding is the rest of it: \"until Task 19's cutover\" named a task t"):
        HISTORY,
    ("driver/fsring-fsd/src/session.rs",
     "ing -- \"No context exists before Task 19's cutover, so no right is"):
        HISTORY,
    ("driver/fsring-fsd/src/session.rs",
     " is no installed context \"until Task 19's cutover\" and cite \"the "):
        HISTORY,
    ("driver/scripts/audit_c4_task_promises.py",
     "is production-unreachable until Task 25. The slab had one owner a"):
        OWN_EXAMPLE,
    ("driver/scripts/audit_c4_task_promises.py",
     "ner and stays unreachable until Task 25. The verb has to govern t"):
        OWN_EXAMPLE,
    ("driver/scripts/audit_c4_task_promises.py",
     "n the task and its verb (\"Task 25's atomic cutover is the first\"), "
     "one because the phrase"):
        OWN_EXAMPLE,
    ("driver/scripts/audit_c4_task_promises.py",
     'ming no number at all -- "today the staging gate proves it" -- still count'):
        OWN_EXAMPLE,
    ("driver/scripts/audit_c4_task_promises.py",
     "dicated the block around `Task 3's consuming setup transition is the sole minting path`, and a plan"):
        OWN_EXAMPLE,
    ("driver/scripts/audit_c4_task_promises.py",
     "anted `nothing reads this until Task 21 lands` inserted two lines"):
        OWN_EXAMPLE,
    ("driver/scripts/audit_c4_task_promises.py",
     " -- which carried a live `Task 29 will execute`. All are in now."):
        OWN_EXAMPLE + " This one quotes the statement in `verify_spec.py` that "
        "the round-17 scope widening surfaced and this round repaired.",

    # -- normatively frozen --------------------------------------------------
    ("docs/superpowers/reviews/2026-08-08-driver-c4-recovery-gate.md",
     "this cell records no attempt, and a row is verified per attempt"):
        "Time-invariant, which is the repair round-16 E6 asked for: the cell no "
        "longer says how many attempts have run, it says where a row's verdict "
        "lives. The previous text read `no row is verified until Task 29 runs "
        "it` while 26 attempts existed -- a current-status sentence inside the "
        "one document section 1 requires to carry no attempt identity at all.",

    # -- newly reached by round 19's widened plain form and shared verb list --
    #
    # Each was read against the tree before it was excused; none is a promise.
    ("driver/fsring-core/src/adapter/lifecycle.rs",
     "Task 3's setup transition consumes the install-minted bind right"):
        PRESENT_TENSE + " The transition exists and consumes it today; Task 3 "
        "is named as the commit that introduced it.",
    ("driver/fsring-core/src/enter.rs",
     "Task 13 mints exactly one per ring, and holding it here is what"):
        PRESENT_TENSE + " `SessionRingSetInitializer::next_ring` mints one bind "
        "right per ring on this tree.",
    ("driver/fsring-fsd/src/session.rs",
     "Task 12's cutover routes process loss through the permanent cells"):
        PRESENT_TENSE + " The cutover landed at `ca67819`, which also deleted "
        "`captured_process_of`, and the permanent-cell route is what "
        "production runs. Round 19 dated it to `c235564`'s parent, a "
        "mutant-roster commit (round-20 evidence review, E3).",
    ("driver/scripts/audit_c4_lifetime.py",
     "Task 20's credit lane adds one"):
        PRESENT_TENSE + " A census line explaining a count this tree already "
        "carries.",
    ("driver/scripts/audit_c4_lifetime.py",
     "Task 25 native grant slab: the drained-proof callback is the only safe "
     "wrapper"):
        PRESENT_TENSE + " A frozen-digest heading naming what the callback is "
        "today.",
    ("driver/scripts/audit_c4_production_graph.py",
     "Task 12's cutover also has to delete a struct"):
        HISTORY + " It describes what that cutover had to do, in the paragraph "
        "explaining why `forbiddenText` exists beside `forbiddenSymbols`.",
    ("driver/scripts/mutation_sweep.py",
     "Task 8 closure adds the production-consumed retained mount scope"):
        PRESENT_TENSE + " A floor comment naming the closure that raised it.",

    # -- cfg(test), no production surface ------------------------------------
    ("driver/fsring-core/src/adapter/fence.rs",
     "Task 25's `KernelFenceOps::finish` is the only thing that will ever mi"):
        "True and live: `finish` reaches `package_completed_fence` "
        "(`adapter/fence.rs`), which is the sole construction of "
        "`FenceObligationsDischarged`. The future tense is about future mints, "
        "not about a commit that has yet to land.",
}


# ----------------------------------------------------------------- scanning --
def scan(root):
    tracked = [
        r for r in subprocess.run(
            ["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True
        ).stdout.split("\n") if r
    ]
    hits = []
    for rel in tracked:
        if not is_live(rel):
            continue
        path = os.path.join(root, rel.replace("/", os.sep))
        if not os.path.isfile(path):
            continue
        text = open(path, encoding="utf-8", errors="replace").read()
        for line, block in blocks_for(rel, text):
            collapsed = " ".join(block.split())
            for start, end in promise_spans(collapsed):
                hits.append((rel, line, collapsed, start, end))
    return hits


# ----------------------------------------------------------------- fixtures --
# The two marked ROUND-15-HOLE are the shapes that defeated the first version of
# this matcher; they are why the self-test is fixtures and not the live set.
FIXTURES = [
    ("plain-until",
     "/// Nothing calls this outside tests until Task 19.", True),
    ("possessive-two-words-ROUND-15-HOLE",
     '"note": "Tasks 20-24 stage the surface. Task 25\'s atomic cutover is the '
     'first production caller."', True),
    ("split-across-comment-lines-ROUND-15-HOLE",
     "/// Staged: `CqDrainAuthority` and the credit preflight read it when the\n"
     "/// rest of Task 20 lands. Kept rather than deleted.", True),
    ("retired-gate-as-current-proof",
     "/// Task 19 gives it a caller; today the staging gate proves it has none.",
     True),
    ("task-has-to-remember",
     "/// a bugcheck here would be a trap Task 19 has to remember to remove", True),
    ("task-is-what-adds",
     "// produce, and Task 20 is what adds CQ entries to it.", True),
    ("task-is-the-commit",
     "/// Task 19 is the commit that first reaches it.", True),
    ("task-consumes",
     "/// Task 14 consumes it into `RingRuntimeParts`.", True),
    ("until-then-the-staging-gate",
     "/// and until then the staging gate is what proves it.", True),
    # Round-16 E2(b). Seven of ten plants in forms 1-2 passed the previous
    # expression; these are all seven, each of which bounds a property by a task
    # exactly as `until` does.
    ("possessive-future-will",
     "/// Task 25's cutover will bind the storage.", True),
    ("once-task-lands",
     "/// The drain reads it once Task 25 lands.", True),
    ("pending-task",
     "/// Kept pending Task 25.", True),
    ("deferred-to-task",
     "/// The binding is deferred to Task 25.", True),
    ("before-task",
     "/// Nothing reaches it before Task 25.", True),
    ("suppressor-must-not-cross-a-clause",
     "/// This was added in Task 18 and is production-unreachable until Task 25.",
     True),
    ("suppressor-must-not-cross-a-clause-2",
     "/// The slab had one owner and stays unreachable until Task 25.", True),
    # ... and the suppressor must still suppress a genuine history, where the
    # past-tense verb really does govern the `until`.
    ("historical-close-past-verb-still-suppressed",
     "# The census was 47 until Task 28.", False),
    # Scanned surfaces that were invisible before (E2(c)).
    ("python-docstring-is-scanned",
     'def f():\n    \"\"\"Nothing reads this until Task 19.\"\"\"\n', True,
     "driver/scripts/__fixture.py"),
    # Anti-vacuity: the SAME text as Rust must NOT be caught -- no `//` line and
    # no `/* */`, so no reader there sees it. Without a control the fixture above
    # proves nothing about the docstring reader; the first version dispatched on
    # `text.startswith('"')`, sent `\"\"\"...\"\"\"` to the JSON reader, and passed
    # because that reader also happens to extract it.
    ("python-docstring-needs-its-reader",
     'def f():\n    \"\"\"Nothing reads this until Task 19.\"\"\"\n', False,
     "driver/fsring-core/src/__fixture.rs"),
    ("rust-block-comment-is-scanned",
     "/* Nothing reads this until Task 19. */", True,
     "driver/fsring-core/src/__fixture.rs"),
    ("rust-block-comment-needs-its-reader",
     "/* Nothing reads this until Task 19. */", False,
     "driver/scripts/__fixture.sh"),
    # Both "is the ..." forms, across the whole shared adjective list. The
    # possessive half of this was the gap: `one` and `commit` reached only the
    # plain form.
    ("possessive-is-the-one", "/// Task 3's setup transition is the one "
     "minting path.", True),
    ("possessive-is-the-only", "/// Task 3's setup transition is the only "
     "minting path.", True),
    ("possessive-is-the-commit", "/// Task 3's cutover is the commit that "
     "mints it.", True),
    ("plain-is-the-only", "/// Task 19 is the only thing that reaches it.",
     True),
    # The suppressor must not swallow a live "until": these four pin both sides
    # of it, because a suppressor that is too eager reopens the hole.
    ("until-with-no-verb-is-live",
     "/// Each is production-unreachable until Task 25.", True),
    ("until-present-tense-is-live",
     "/// Nothing in production reaches this until Task 19's cutover.", True),
    # Must NOT fire.
    ("historical-past-tense",
     "# It was 47 until Task 28's reconciliation.", False),
    ("historical-past-tense-stayed",
     "/// The census stayed at 12 until Task 19 raised it.", False),
    ("retired-correctly-described",
     '"note": "RETIRED by Task 19\'s cutover: this gate FAILS by design and no '
     'profile carries it any more."', False),
    ("task-30-is-genuinely-future",
     "/// Task 30 is the commit that first runs this live.", False),
    ("plain-mention",
     "/// The R4 cutover moved the runtime parts across in Task 19.", False),
    # Round-17 evidence E1(b): 22 of 24 plants passed the round-17 matcher and
    # readers. Every form below was one of them; each is retained here.
    # -- readers --------------------------------------------------------------
    ("rust-trailing-comment-is-scanned",
     "let x = 1; // nothing reads this until Task 25\n", True,
     "driver/fsring-core/src/__fixture.rs"),
    ("rust-trailing-slashes-in-a-string-are-not-a-comment",
     'let url = "until Task 25 // not a comment";\n', False,
     "driver/fsring-core/src/__fixture.rs"),
    ("python-trailing-comment-is-scanned",
     "x = 1  # nothing reads this until Task 25\n", True,
     "driver/scripts/__fixture.py"),
    ("python-hash-in-a-string-is-not-a-comment",
     'x = "# nothing reads this until Task 25"\n', False,
     "driver/scripts/__fixture.py"),
    ("powershell-block-comment-is-scanned",
     "<#\n  Nothing reads this until Task 25.\n#>\n", True,
     "driver/scripts/__fixture.ps1"),
    ("batch-double-colon-comment-is-scanned",
     ":: Nothing reads this until Task 25.\n", True,
     "driver/scripts/__fixture.cmd"),
    ("native-c-comment-is-scanned",
     "/* Nothing reads this until Task 25. */\n", True,
     "driver/fsring-fsd/native/__fixture.c"),
    # -- matcher forms --------------------------------------------------------
    ("until-the-task-cutover",
     "/// It stays unreachable until the Task 25 cutover.", True),
    ("possessive-typographic-apostrophe",
     "/// Task 25\u2019s cutover will bind the storage.", True),
    ("plural-tasks-and-will",
     "/// Tasks 24 and 25 will bind the storage.", True),
    ("plural-until-range-land",
     "/// Nothing reads it until Tasks 20-24 land.", True),
    ("task-step-will",
     "/// Task 25 Step 3 will bind the storage.", True),
    ("task-is-going-to",
     "/// Task 25 is going to bind the storage.", True),
    ("task-should",
     "/// Task 25 should bind the storage.", True),
    ("left-for-task",
     "/// The binding is left for Task 25.", True),
    ("possessive-with-a-comma-clause",
     "/// Task 25's cutover, when it lands, will bind the storage.", True),
    ("suppressor-must-not-cross-a-comma",
     "/// As it did in R3, it stays unreachable until Task 25.", True),
    ("suppressor-must-not-cross-a-colon",
     "/// Staged as it was built: unreachable until Task 25.", True),
    # ... while a genuine history across the same punctuation stays history.
    ("history-with-a-comma-still-suppressed",
     "# The census, as recorded, was 47 until Task 28.", False),
    # Round-18 evidence E2: a noun between the task and its verb, and the
    # possessive form's verb list being shorter than the plain form's. Both
    # escaped the round-18 matcher; both are one shared list and one shared
    # bounded run now.
    ("noun-between-task-and-verb",
     "/// The Task 25 cutover will bind the storage.", True),
    ("possessive-carries-the-plain-verb-list",
     "/// Task 25's cutover gives it a caller.", True),
    ("possessive-carries-the-plain-verb-list-2",
     "/// Task 25's transition consumes it into the runtime.", True),
    # ... and the run may not reach across a sentence into the next task.
    ("run-does-not-cross-a-sentence",
     "/// Task 19 closed. The registry will bind the storage.", False),
    # A number listed after a closed task must not turn the statement into a
    # future one: the decision is on the smallest task number named.
    ("a-listed-number-does-not-hide-a-closed-task",
     "/// It stays unreachable until Task 25, 400 bytes after the header.", True),
]


# ------------------------------------------------------------- mechanism ----
# Round-17 evidence E1(c). The fixtures above call `blocks_for` and
# `promise_hits` only, so the three MECHANISMS that decide what the gate reads
# and what an adjudication excuses had no observer: dropping `driver/` Rust from
# `is_live` took `--check` from 53 statements to 22 and PASSED, forcing
# `needle_occurrences` to 1 let a copied adjudicated sentence PASS, and widening
# `adjudication_for` to any needle in the file PASSED `--self-test`. The plants
# that graded round 17's scope and keying repairs lived in a scratch script and
# protected nothing after their commit. These are those plants, retained.
LIVE_SCOPE_FIXTURES = [
    ("driver/fsring-fsd/src/pending_enter.rs", True),
    ("driver/fsring-core/src/adapter/lifecycle.rs", True),
    ("fsring-abi/src/validate/session.rs", True),
    ("fsring-user/src/native.rs", True),
    ("docs/design/02-transport.md", True),
    ("driver/audit/c4-production-graph.json", True),
    ("driver/scripts/audit_c4_lifetime.py", True),
    ("scripts/verify_spec.py", True),
    (LIVE_GATE_DOC, True),
    # The two documents rows P10 and R10 send a reviewer to.
    ("README.md", True),
    ("driver/README.md", True),
    ("fsring-abi/README.md", True),
    # A script tool one directory down, and the one native C source.
    ("driver/scripts/locked-cargo/verify_attestation.ps1", True),
    ("driver/scripts/locked-cargo/cargo_shim.rs", True),
    ("driver/fsring-fsd/native/c4_seh.c", True),
    # OUT, each for the reason `is_live` gives.
    ("docs/superpowers/plans/2026-09-15-fsring-driver-c4-round18-mediums.md", False),
    ("docs/superpowers/reviews/evidence/c4-recovery-logs/README.md", False),
    ("driver/fsring-core/src/adapter/lifecycle/tests.rs", False),
    ("driver/fsring-core/src/adapter/lifecycle/tests/close_choreography.rs", False),
]


def mechanism_self_test():
    failures = []
    for rel, expected in LIVE_SCOPE_FIXTURES:
        if is_live(rel) != expected:
            failures.append("is_live(%s): expected %s" % (rel, expected))

    # `adjudication_for` covers a statement only inside the needle's own span:
    # a promise one sentence past an adjudicated needle is NOT excused.
    rel, needle = next(
        (arel, aneedle) for (arel, aneedle), why in ADJUDICATED.items() if why is HISTORY
    )
    wanted = " ".join(needle.split())
    planted = wanted + " Nothing in production reads this until Task 19."
    spans = promise_spans(planted)
    inside = [s for s in spans if s[1] <= len(wanted)]
    outside = [s for s in spans if s[0] >= len(wanted)]
    if not outside:
        failures.append("adjudication fixture: the planted promise did not match")
    for start, end in outside:
        if adjudication_for(rel, planted, start, end) is not None:
            failures.append(
                "adjudication_for excused a promise outside its needle's span")
    for start, end in inside:
        if adjudication_for(rel, planted, start, end) is None:
            failures.append(
                "adjudication_for failed to excuse the statement its needle names")

    # `needle_occurrences` counts a copied adjudicated sentence twice.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="c4-promises-") as work:
        target = os.path.join(work, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if rel.endswith(".rs"):
            text = "/// %s\n\nfn a() {}\n\n/// %s\n" % (wanted, wanted)
        elif rel.endswith(".json"):
            text = '{"a": "%s", "b": "%s"}\n' % (wanted, wanted)
        else:
            text = "%s\n\n%s\n" % (wanted, wanted)
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        counted = needle_occurrences(work).get((rel, needle))
        if counted != 2:
            failures.append(
                "needle_occurrences counted a copied adjudicated sentence %r "
                "times, not 2" % (counted,))
    return failures


def self_test():
    failures = []
    for row in FIXTURES:
        # A fixture may name the reader it is written for. Guessing from the
        # text was not good enough: `"""..."""` starts with `"`, so the docstring
        # fixture was dispatched to the JSON reader, which also happened to
        # extract it -- a fixture that passed without ever exercising the reader
        # it was added to test.
        if len(row) == 4:
            name, text, expected, rel = row
        else:
            name, text, expected = row
            rel = ("driver/fsring-core/src/__fixture.json"
                   if text.lstrip().startswith('"')
                   else "driver/fsring-core/src/__fixture.rs")
        caught = any(
            promise_hits(" ".join(block.split()))
            for _line, block in blocks_for(rel, text)
        )
        if caught != expected:
            failures.append(
                "%s: expected caught=%s, got %s" % (name, expected, caught))
    failures.extend("mechanism: %s" % f for f in mechanism_self_test())
    for f in failures:
        print("FAIL fixture %s" % f)
    # Matcher fixtures, scope fixtures, and the two keying/counting mechanisms.
    total = len(FIXTURES) + len(LIVE_SCOPE_FIXTURES) + 2
    print("audit_c4_task_promises self-test: %s (%d fixtures, %d failures)"
          % ("PASS" if not failures else "FAIL", total, len(failures)))
    return 1 if failures else 0


# The number of promise-shaped statements the matcher reaches in live documents
# on this tree. Pinned so that a change in SCOPE is visible: round-17 evidence
# E1(c) removed `driver/` Rust from `is_live`, the count fell from 53 to 22, and
# `--check` still passed, because nothing about 22 adjudicated statements is
# wrong. Moving it is a decision, recorded here with its reason.
#
#   53 -> 57, round 18: `Task 3 Step 2 will mint this` in `adapter/fence.rs` was
#   newly reached by the `Task N Step M` form and swept; three of this file's
#   own new comments quote the round-17 plants they were widened for, and this
#   comment quotes the swept statement (all four adjudicated OWN_EXAMPLE).
#
#   57 -> 65, round 19 (round-18 evidence E2): the plain form gained the same
#   bounded run the possessive has, and both now share one verb list. That
#   reaches eight statements that were invisible -- seven present-tense
#   descriptions across core, fsd and three auditors, and one history -- plus
#   this file's own three new examples, less the three examples the rewritten
#   matcher comment deleted. Round 19 wrote "None of the eight was false"
#   here; one was.
#
#   65 -> 64, round 21 (round-20 evidence E2): `PendingControlLinkRight`'s
#   seal comment said Task 14 destructures the field, and its adjudication
#   said the destructuring was in the tree. Nothing destructures it, and
#   removing the allow makes rustc report `field 'authority' is never read`.
#   The comment now says what is true and names no task, so the matcher no
#   longer reaches it, and the adjudication that excused it is deleted.
EXPECTED_STATEMENTS = 64


def check(root, list_only=False):
    hits = scan(root)
    unadjudicated = [
        (rel, line, block, start, end)
        for rel, line, block, start, end in hits
        if adjudication_for(rel, block, start, end) is None
    ]
    if list_only:
        print("audit_c4_task_promises list: %d promise-shaped statements in "
              "live documents" % len(hits))
        for rel, line, block, start, end in hits:
            print("  %s:%d" % (rel, line))
            print("      %s" % block[max(0, start - 40):end + 40])
        return 0
    # An adjudication is only as good as the statement it names. A needle that
    # occurs twice is a copied sentence silently inheriting an excuse; one that
    # occurs never is a written reason for nothing.
    occurrences = needle_occurrences(root)
    duplicated = sorted(k for k, n in occurrences.items() if n > 1)
    dead = sorted(k for k, n in occurrences.items() if n == 0)

    print("audit_c4_task_promises check: %d promise-shaped statements in live "
          "documents, %d unadjudicated, %d duplicated needles, %d dead entries"
          % (len(hits), len(unadjudicated), len(duplicated), len(dead)))
    miscounted = len(hits) != EXPECTED_STATEMENTS
    for rel, line, block, start, end in unadjudicated:
        print("  %s:%d" % (rel, line))
        print("      %s" % block[max(0, start - 60):end + 60])
    for rel, needle in duplicated:
        print("  DUPLICATED x%d  %s" % (occurrences[(rel, needle)], rel))
        print("      %s" % needle[:150])
    for rel, needle in dead:
        print("  DEAD ENTRY     %s" % rel)
        print("      %s" % needle[:150])
    if miscounted:
        print("  STATEMENT COUNT %d, pinned %d" % (len(hits), EXPECTED_STATEMENTS))
    if unadjudicated or duplicated or dead or miscounted:
        if miscounted:
            print("FAIL: the number of statements the matcher reaches moved. A "
                  "scope or reader regression makes statements disappear without "
                  "anything else failing; if the move is real, record it in "
                  "EXPECTED_STATEMENTS with its reason.")
        if unadjudicated:
            print("FAIL: a live document names a closed task as still to come, "
                  "or a retired gate as current proof.")
        if duplicated:
            print("FAIL: an adjudicated sentence occurs more than once, so a "
                  "copy of it inherits an excuse written for the original.")
        if dead:
            print("FAIL: an ADJUDICATED entry matches nothing; its reason "
                  "describes a statement that is no longer there.")
        return 1
    print("PASS")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--root", default=".")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if a.check:
        return check(os.path.abspath(a.root))
    if a.list:
        return check(os.path.abspath(a.root), list_only=True)
    ap.error("choose --self-test, --check or --list")


if __name__ == "__main__":
    raise SystemExit(main())
