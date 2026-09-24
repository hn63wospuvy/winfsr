//! `fsring-core` must stay WDK-free: the whole host-proof strategy rests on it.
//! This walks the driver workspace's lock file from `fsring-core` and fails if
//! any reachable package is a WDK or OS binding crate. It reads the lock rather
//! than running `cargo`, so it never contends on the build lock.
//!
//! **Why the walk subtracts `loom`.** A `Cargo.lock` records `cfg`-gated edges
//! unconditionally, because `cfg` expressions are not evaluable at resolution
//! time. `fsring-abi` carries `[target.'cfg(loom)'.dependencies] loom`, and
//! `loom`'s own subgraph reaches `libc`, `windows-sys`, `windows-link` and
//! `windows-result` — all of which appear in the lock's transitive closure from
//! `fsring-core` and **none of which any driver build ever compiles**, since
//! `cfg(loom)` is only ever set through `RUSTFLAGS`. Measured: a naive
//! transitive walk reports exactly those four as violations.
//!
//! So the walk removes the single `loom` edge and asserts over what remains.
//! That keeps the check transitive — a forbidden crate arriving through any
//! other path still fails — while not flagging packages that are locked but
//! never built. The subtraction is asserted to be real (`loom` must actually be
//! in the unsubtracted closure), so it can never become a silent escape hatch.

use std::collections::{BTreeMap, BTreeSet};

/// Package name -> its direct dependency names, parsed from a `Cargo.lock`.
fn parse_lock(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut name: Option<String> = None;
    let mut deps: Vec<String> = Vec::new();
    let mut in_deps = false;

    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            if let Some(n) = name.take() {
                // A lock is keyed by name AND version; this graph is keyed by
                // name alone. Where a name repeats, UNION the edges instead of
                // overwriting, so no edge unique to one version disappears.
                // Over-approximating is the safe direction for a fail-closed
                // check. This lock already has four duplicated names.
                graph
                    .entry(n)
                    .or_default()
                    .extend(std::mem::take(&mut deps));
            }
            deps = Vec::new();
            in_deps = false;
        } else if let Some(rest) = line.strip_prefix("name = ") {
            name = Some(rest.trim_matches('"').to_string());
            in_deps = false;
        } else if line == "dependencies = [" {
            in_deps = true;
        } else if in_deps {
            if line == "]" {
                in_deps = false;
            } else {
                // Entries look like `"loom",` or `"serde 1.0.0 (registry+...)",`.
                let entry = line.trim_end_matches(',').trim_matches('"');
                if let Some(first) = entry.split_whitespace().next() {
                    deps.push(first.to_string());
                }
            }
        }
    }
    if let Some(n) = name.take() {
        graph.entry(n).or_default().extend(deps);
    }
    graph
}

/// Transitive closure from `root`, never traversing *into* a cut package.
/// A cut package is still reported as reached, so the caller can assert the cut
/// was real rather than silently absent.
fn closure_cutting(
    graph: &BTreeMap<String, Vec<String>>,
    root: &str,
    cut: &[&str],
) -> BTreeSet<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut stack = vec![root.to_string()];
    while let Some(pkg) = stack.pop() {
        if !seen.insert(pkg.clone()) {
            continue;
        }
        if cut.contains(&pkg.as_str()) {
            continue; // reached, but not traversed
        }
        if let Some(deps) = graph.get(&pkg) {
            for d in deps {
                stack.push(d.clone());
            }
        }
    }
    seen
}

fn closure(graph: &BTreeMap<String, Vec<String>>, root: &str) -> BTreeSet<String> {
    closure_cutting(graph, root, &[])
}

/// `fsring-abi`'s `cfg(loom)` test dependency. Locked unconditionally, compiled
/// by no driver build. See the module documentation.
const CUT: [&str; 1] = ["loom"];

/// WDK bindings and OS binding crates. `fsring-core` may reach none of them.
fn is_forbidden(pkg: &str) -> bool {
    pkg.starts_with("wdk") || pkg.starts_with("windows") || pkg == "winapi" || pkg == "libc"
}

#[test]
fn fsring_core_dependency_closure_is_wdk_free() {
    let lock_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.lock");
    let text = match std::fs::read_to_string(lock_path) {
        Ok(t) => t,
        Err(e) => panic!("cannot read {lock_path}: {e}"),
    };
    let graph = parse_lock(&text);

    assert!(
        graph.contains_key("fsring-core"),
        "fsring-core is not in {lock_path}; the lock is stale"
    );

    // The direct dependency list is an allowlist: growing it is a reviewed
    // commit, exactly like driver/audit/kernel-modules.allow.
    let direct = graph
        .get("fsring-core")
        .map(Vec::as_slice)
        .unwrap_or_default();
    assert_eq!(
        direct,
        ["fsring-abi".to_string()],
        "fsring-core's direct dependencies are an allowlist; adding one is a reviewed decision"
    );

    let compiled = closure_cutting(&graph, "fsring-core", &CUT);
    let forbidden: Vec<&String> = compiled.iter().filter(|p| is_forbidden(p)).collect();
    assert!(
        forbidden.is_empty(),
        "fsring-core must stay WDK-free, but its compiled closure reaches: {forbidden:?}"
    );

    // Guard against a vacuous pass: the closure must actually contain the one
    // dependency the crate is supposed to have.
    assert!(
        compiled.contains("fsring-abi"),
        "closure walk found no fsring-abi; the lock parser is broken, not the crate"
    );

    // Guard against the cut becoming a silent escape hatch: `loom` must really
    // be reachable, so the subtraction is documented fact and not dead code.
    let uncut = closure(&graph, "fsring-core");
    assert!(
        uncut.contains("loom"),
        "the loom cut is no longer needed; remove CUT and this assertion together"
    );
    assert!(
        uncut.iter().any(|p| is_forbidden(p)),
        "the uncut closure reaches no forbidden crate, so the cut proves nothing; \
         re-verify why CUT exists before keeping it"
    );
}

#[test]
fn parser_and_forbidden_set_actually_discriminate() {
    let lock = r#"
[[package]]
name = "fsring-core"
version = "0.1.0"
dependencies = [
 "fsring-abi",
 "wdk-sys",
]

[[package]]
name = "wdk-sys"
version = "0.5.1"
"#;
    let graph = parse_lock(lock);
    let reachable = closure_cutting(&graph, "fsring-core", &CUT);
    assert!(
        reachable.contains("wdk-sys"),
        "a wdk-sys edge outside the cut must still be reached"
    );
    assert!(is_forbidden("wdk-sys"));
    assert!(!is_forbidden("fsring-abi"));
}

#[test]
fn a_duplicated_package_name_does_not_drop_edges() {
    // driver/Cargo.lock already contains four duplicated names (shlex, syn,
    // windows-result, windows-sys). Keying the graph by name alone must not
    // let the later entry erase the earlier one's edges, or a forbidden crate
    // reachable only through the dropped version would go unreported.
    let lock = r#"
[[package]]
name = "fsring-core"
version = "0.1.0"
dependencies = [
 "dup",
]

[[package]]
name = "dup"
version = "1.0.0"
dependencies = [
 "wdk-sys",
]

[[package]]
name = "dup"
version = "2.0.0"
dependencies = [
 "fsring-abi",
]

[[package]]
name = "wdk-sys"
version = "0.5.1"

[[package]]
name = "fsring-abi"
version = "0.2.1"
"#;
    let graph = parse_lock(lock);
    let reachable = closure_cutting(&graph, "fsring-core", &CUT);
    assert!(
        reachable.contains("wdk-sys"),
        "the v1 edge to wdk-sys must survive the v2 entry for the same name"
    );
}

#[test]
fn the_cut_does_not_hide_a_forbidden_crate_on_another_path() {
    // wdk-sys is reachable both through the cut package and directly. Cutting
    // must not make it disappear.
    let lock = r#"
[[package]]
name = "fsring-core"
version = "0.1.0"
dependencies = [
 "fsring-abi",
]

[[package]]
name = "fsring-abi"
version = "0.2.1"
dependencies = [
 "loom",
 "wdk-sys",
]

[[package]]
name = "loom"
version = "0.7.2"
dependencies = [
 "wdk-sys",
]

[[package]]
name = "wdk-sys"
version = "0.5.1"
"#;
    let graph = parse_lock(lock);
    let compiled = closure_cutting(&graph, "fsring-core", &CUT);
    assert!(
        compiled.iter().any(|p| is_forbidden(p)),
        "cutting loom must not hide a forbidden crate that is also reachable directly"
    );
}
