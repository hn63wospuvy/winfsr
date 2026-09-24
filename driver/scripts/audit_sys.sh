#!/usr/bin/env bash
# Static PE audit for a FSRING driver image.
#
# Usage:
#   bash driver/scripts/audit_sys.sh [options] <path-to-image>
#
# Options:
#   --expect-machine x64|arm64  required PE machine (default: x64)
#   --expect-profile <name>     the image must contain this profile string
#   --modules-allow <file>      import-module allowlist
#                               (default: ../audit/kernel-modules.allow)
#   --allowlist <file>          imported-symbol allowlist, "module!symbol" lines
#   --resolver-table <file>     names that MUST NOT be statically imported
#   --expect-string <text>      text that MUST appear in the image, in ASCII or
#                               UTF-16LE; the encoding that matched is reported
#
# Checks; every failure sets exit 1:
#   1. PE machine matches --expect-machine, and subsystem is NATIVE
#   2. every imported MODULE is in the module allowlist
#   3. no C-runtime module is imported (redundant, explicit diagnostic)
#   4. DriverEntry is exported, matched EXACTLY (ntdll.dll exports ten names
#      containing "DriverEntry" and none of them is DriverEntry)
#   5. the --expect-profile string is present in the image, when given
#   6. every imported SYMBOL is in --allowlist, when given
#   7. no name in --resolver-table appears among the imported symbols. Those are
#      post-baseline DDIs reached through MmGetSystemRoutineAddress; a static
#      import of one fails the kernel loader on an older baseline, and nothing
#      on a machine that cannot load a driver would otherwise notice
#   8. the --expect-string text is present in ASCII or UTF-16LE, when given
#
# The PE stores an entry-point RVA, not a name; check 4 asserts the export,
# which is a real and checkable property, while /ENTRY:DriverEntry remains a
# build-configuration fact recorded in driver/README.md.
#
# No check uses `grep -q` in a pipeline. Under `set -o pipefail`, `grep -q`
# exits on its first match and the producer dies of SIGPIPE, so the pipeline
# reports failure even though the pattern WAS found: llvm-readobj over
# ntdll.dll's 2435 exports returns 74 that way. Every check therefore reads its
# producer to completion through a command substitution.
#
# Requires llvm-readobj (LLVM 18) on PATH or at the default LLVM location.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXPECT_MACHINE=x64
EXPECT_PROFILE=
MODULES_ALLOW="$SCRIPT_DIR/../audit/kernel-modules.allow"
SYMBOL_ALLOW=
RESOLVER_TABLE=
SYS=

while [ $# -gt 0 ]; do
  case "$1" in
    --expect-machine) EXPECT_MACHINE="${2:?--expect-machine needs a value}"; shift 2 ;;
    --expect-profile) EXPECT_PROFILE="${2:?--expect-profile needs a value}"; shift 2 ;;
    --modules-allow)  MODULES_ALLOW="${2:?--modules-allow needs a value}";  shift 2 ;;
    --allowlist)      SYMBOL_ALLOW="${2:?--allowlist needs a value}";       shift 2 ;;
    --resolver-table) RESOLVER_TABLE="${2:?--resolver-table needs a value}"; shift 2 ;;
    --expect-string)  EXPECT_STRING="${2:?--expect-string needs a value}"; shift 2 ;;
    -h|--help)        sed -n '2,40p' "$0"; exit 0 ;;
    -*)               echo "FAIL: unknown option: $1"; exit 2 ;;
    *)                SYS="$1"; shift ;;
  esac
done

[ -n "$SYS" ] || { echo "usage: audit_sys.sh [options] <path-to-image>"; exit 2; }
[ -f "$SYS" ] || { echo "FAIL: no such file: $SYS"; exit 2; }
[ -f "$MODULES_ALLOW" ] || { echo "FAIL: no such module allowlist: $MODULES_ALLOW"; exit 2; }
[ -z "$SYMBOL_ALLOW" ] || [ -f "$SYMBOL_ALLOW" ] || { echo "FAIL: no such symbol allowlist: $SYMBOL_ALLOW"; exit 2; }
[ -z "$RESOLVER_TABLE" ] || [ -f "$RESOLVER_TABLE" ] || { echo "FAIL: no such resolver table: $RESOLVER_TABLE"; exit 2; }

case "$EXPECT_MACHINE" in
  x64)   MACHINE_RE='IMAGE_FILE_MACHINE_AMD64|0x8664' ;;
  arm64) MACHINE_RE='IMAGE_FILE_MACHINE_ARM64|0xAA64' ;;
  *)     echo "FAIL: --expect-machine must be x64 or arm64, got: $EXPECT_MACHINE"; exit 2 ;;
esac

fail=0
note() { printf '%-32s %s\n' "$1" "$2"; }

READOBJ="$(command -v llvm-readobj || echo 'C:/Program Files/LLVM/bin/llvm-readobj.exe')"

# Normalize an allowlist: strip comments, blank lines, surrounding whitespace,
# and lowercase for case-insensitive comparison.
normalize_allow() {
  sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$1" \
    | grep -v '^$' | tr 'A-Z' 'a-z' | sort -u
}

# 1. Machine + subsystem.
hdr="$("$READOBJ" --file-headers "$SYS" 2>/dev/null)"
if [ -n "$(printf '%s\n' "$hdr" | grep -iE "Machine:.*($MACHINE_RE)")" ]; then
  note "machine $EXPECT_MACHINE" OK
else
  note "machine $EXPECT_MACHINE" FAIL
  echo "  actual: $(echo "$hdr" | grep -i 'Machine:' | head -1 | sed 's/^[[:space:]]*//')"
  fail=1
fi
if [ -n "$(printf '%s\n' "$hdr" | grep -iE 'Subsystem:.*NATIVE')" ]; then
  note "subsystem NATIVE" OK
else
  note "subsystem NATIVE" FAIL; fail=1
fi

# 2/3/6. Imports. Module names are "  Name:" lines inside Import blocks;
#        symbols are "  Symbol: <name> (<ordinal>)" lines under the last module.
imps="$("$READOBJ" --coff-imports "$SYS" 2>/dev/null)"
modules="$(echo "$imps" | sed -n 's/^  Name: //p' | tr 'A-Z' 'a-z' | sort -u)"
pairs="$(echo "$imps" | awk '
  /^  Name: /   { mod = substr($0, 9); next }
  /^  Symbol: / { sym = $2; if (mod != "") print mod "!" sym }
' | tr 'A-Z' 'a-z' | sort -u)"

if [ -z "$modules" ]; then
  note "module allowlist" FAIL
  echo "  the image imports no module at all; an empty import table makes this audit vacuous"
  fail=1
else
  extra_modules="$(comm -23 <(echo "$modules") <(normalize_allow "$MODULES_ALLOW"))"
  if [ -z "$extra_modules" ]; then
    note "module allowlist" OK
  else
    note "module allowlist" FAIL
    echo "$extra_modules" | sed 's/^/  not allowed: /'
    fail=1
  fi
fi

if [ -n "$(printf '%s\n' "$modules" | grep -E 'msvcrt|vcruntime|ucrtbase|api-ms-win-crt')" ]; then
  note "no CRT imports" FAIL
  echo "$modules" | grep -E 'msvcrt|vcruntime|ucrtbase|api-ms-win-crt' | sed 's/^/  offending: /'
  fail=1
else
  note "no CRT imports" OK
fi

if [ -n "$SYMBOL_ALLOW" ]; then
  extra_symbols="$(comm -23 <(echo "$pairs") <(normalize_allow "$SYMBOL_ALLOW"))"
  if [ -z "$extra_symbols" ]; then
    note "symbol allowlist" OK
  else
    note "symbol allowlist" FAIL
    echo "$extra_symbols" | sed 's/^/  not allowed: /'
    fail=1
  fi
fi

# 7. No resolver-table name may be a static import.
if [ -n "$RESOLVER_TABLE" ]; then
  imported_syms="$(printf '%s
' "$pairs" | sed 's/^.*!//' | sort -u)"
  banned="$(comm -12 <(printf '%s
' "$imported_syms") <(normalize_allow "$RESOLVER_TABLE"))"
  if [ -z "$banned" ]; then
    note "resolver names absent" OK
  else
    note "resolver names absent" FAIL
    echo "$banned" | sed 's/^/  statically imported, must be runtime-resolved: /'
    fail=1
  fi
fi

# 4. DriverEntry must be EXPORTED, matched EXACTLY. A substring match is not
#    good enough: ntdll.dll exports NtAddDriverEntry, ZwSetDriverEntryOrder and
#    eight more names containing "DriverEntry", and none of them is an entry
#    point.
exports="$("$READOBJ" --coff-exports "$SYS" 2>/dev/null | sed -n 's/^  Name: //p')"
if [ -n "$(printf '%s\n' "$exports" | grep -x 'DriverEntry')" ]; then
  note "DriverEntry exported" OK
else
  note "DriverEntry exported" FAIL
  fail=1
fi

# 5. Artifact-level profile identity.
if [ -n "$EXPECT_PROFILE" ]; then
  if grep -qa -- "$EXPECT_PROFILE" "$SYS"; then
    note "profile $EXPECT_PROFILE" OK
  else
    note "profile $EXPECT_PROFILE" FAIL
    fail=1
  fi
fi

# 8. An expected string is present, in ASCII or UTF-16LE.
#
# Both encodings, and the matching one is REPORTED. An ASCII-only check passes
# by absence the moment a name is stored as a wide literal for a
# UNICODE_STRING, and the images today contain no UTF-16LE strings at all -- so
# that failure would stay invisible until the first refactor introducing one.
#
# The wide search goes through `strings -e l`, not through a NUL-bearing grep
# pattern. Bash command substitution silently DROPS NUL bytes, so a pattern
# built that way degenerates to the ASCII one and the check reports
# "ASCII and UTF-16LE" while having searched ASCII twice. That is exactly what
# the first version of this check did, and it is why the wide leg carries its
# own self-test below: a mechanism that cannot find wide text would report
# "absent" forever and nobody would know.
if [ -n "${EXPECT_STRING:-}" ]; then
  ascii_hit=$(LC_ALL=C grep -c -a -F -- "$EXPECT_STRING" "$SYS" 2>/dev/null || true)

  wide_hit=0
  wide_usable=no
  if command -v strings >/dev/null 2>&1; then
    # Self-test the mechanism against a binary known to carry wide strings,
    # so "no wide match" cannot mean "the tool never works here".
    probe="${SYSTEMROOT:-C:\Windows}\System32\ntdll.dll"
    if [ -f "$probe" ] && [ "$(strings -e l "$probe" 2>/dev/null | head -1 | wc -l)" -gt 0 ]; then
      wide_usable=yes
      wide_hit=$(strings -e l "$SYS" 2>/dev/null | LC_ALL=C grep -c -F -- "$EXPECT_STRING" || true)
    fi
  fi

  if [ "${ascii_hit:-0}" -gt 0 ] && [ "${wide_hit:-0}" -gt 0 ]; then
    note "expect-string" "OK (ASCII and UTF-16LE)"
  elif [ "${ascii_hit:-0}" -gt 0 ]; then
    if [ "$wide_usable" = yes ]; then
      note "expect-string" "OK (ASCII; absent as UTF-16LE)"
    else
      note "expect-string" "OK (ASCII; UTF-16LE NOT SEARCHED - no usable strings)"
    fi
  elif [ "${wide_hit:-0}" -gt 0 ]; then
    note "expect-string" "OK (UTF-16LE)"
  else
    note "expect-string" FAIL
    if [ "$wide_usable" = yes ]; then
      echo "  absent in both ASCII and UTF-16LE: $EXPECT_STRING"
    else
      echo "  absent in ASCII; UTF-16LE NOT SEARCHED (no usable strings): $EXPECT_STRING"
    fi
    fail=1
  fi
fi


echo
[ "$fail" -eq 0 ] && echo "AUDIT: PASS" || echo "AUDIT: FAIL"
exit "$fail"
