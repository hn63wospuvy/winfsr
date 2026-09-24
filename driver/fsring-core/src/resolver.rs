//! Optional-DDI resolution (`11-rust-implementation.md` section 3).
//!
//! `00-INDEX.md` section 5: the modern image may static-import only DDIs present
//! at the Windows 10 1507 baseline. A post-baseline DDI MUST be reached through
//! a typed pointer from `MmGetSystemRoutineAddress`, resolved and latched during
//! bring-up — never lazily on a hot path — and a null result clears the
//! capability and selects the complete legacy path.
//!
//! Guarding a direct call with an OS-version check is **FORBIDDEN**: the kernel
//! loader resolves the static import table before `DriverEntry` runs, so a
//! static import of an absent symbol fails the load outright and the `if` never
//! executes.
//!
//! `driver/scripts/audit_sys.sh` enforces the other half of the rule: no name in
//! [`RESOLVER_TABLE`] may appear in any image's static import directory.

/// Identity of an optional DDI.
///
/// An enum rather than a bare string so [`resolve_all`]'s match is exhaustive:
/// adding a table entry without wiring its result fails to COMPILE. The first
/// draft used a `debug_assert!` on a string catch-all, which is compiled out of
/// the `release` profile all three images are built with — so in the shipped
/// driver a new entry would have been silently skipped while `all_resolved()`
/// still reported success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptionalDdiId {
    ExAllocatePool2,
}

/// One optional DDI, named exactly as the kernel exports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptionalDdi {
    /// Which DDI this row is.
    pub id: OptionalDdiId,
    /// The exported symbol name, as it would appear in an import table.
    pub name: &'static str,
    /// The baseline that introduced it — why it cannot be a static import.
    pub introduced_in: &'static str,
}

/// The checked-in resolver-name table.
pub const RESOLVER_TABLE: [OptionalDdi; 1] = [OptionalDdi {
    id: OptionalDdiId::ExAllocatePool2,
    name: "ExAllocatePool2",
    introduced_in: "Windows 10 2004 (NTDDI_WIN10_VB)",
}];

/// What resolution produced. `None` means the capability is cleared and the
/// static path is selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ResolvedDdis {
    /// Address of `ExAllocatePool2`, or `None` on a pre-2004 kernel.
    pub ex_allocate_pool2: Option<usize>,
}

impl ResolvedDdis {
    /// True when every optional DDI resolved. The driver latches this once,
    /// during bring-up, before any mount is admitted.
    pub const fn all_resolved(&self) -> bool {
        self.ex_allocate_pool2.is_some()
    }
}

/// Resolve the whole table through an injected probe, so a test can return
/// nulls without a kernel.
pub fn resolve_all<F>(mut probe: F) -> ResolvedDdis
where
    F: FnMut(&str) -> Option<usize>,
{
    let mut out = ResolvedDdis::default();
    for entry in RESOLVER_TABLE.iter() {
        // Exhaustive over OptionalDdiId: a new variant that is not wired here
        // is a compile error, not a silently unprobed capability.
        match entry.id {
            OptionalDdiId::ExAllocatePool2 => out.ex_allocate_pool2 = probe(entry.name),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_probe_clears_the_capability() {
        let r = resolve_all(|_| None);
        assert!(!r.all_resolved());
        assert_eq!(r.ex_allocate_pool2, None);
    }

    #[test]
    fn a_resolving_probe_latches_the_address() {
        let r = resolve_all(|_| Some(0x1234));
        assert!(r.all_resolved());
        assert_eq!(r.ex_allocate_pool2, Some(0x1234));
    }

    #[test]
    fn the_probe_is_asked_for_every_table_entry() {
        let mut asked = 0usize;
        let _ = resolve_all(|_| {
            asked = asked.saturating_add(1);
            None
        });
        assert_eq!(asked, RESOLVER_TABLE.len());
    }

    #[test]
    fn the_probe_is_asked_by_exact_symbol_name() {
        let mut seen: Option<&str> = None;
        let _ = resolve_all(|name| {
            // The audit compares this string against an import table, so a
            // decorated or abbreviated name would silently defeat the rule.
            assert_eq!(name, "ExAllocatePool2");
            seen = Some("ExAllocatePool2");
            None
        });
        assert_eq!(seen, Some("ExAllocatePool2"));
    }

    #[test]
    fn the_table_names_are_unique_and_nonempty() {
        for (i, a) in RESOLVER_TABLE.iter().enumerate() {
            assert!(!a.name.is_empty());
            assert!(
                !a.introduced_in.is_empty(),
                "each entry states its baseline"
            );
            for b in RESOLVER_TABLE.iter().skip(i.saturating_add(1)) {
                assert_ne!(a.name, b.name);
            }
        }
    }
}
