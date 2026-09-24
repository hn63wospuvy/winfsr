#!/usr/bin/env bash
# Proves each audit_sys.sh check actually fires. A check that has never failed
# is not evidence (design section 5.4).
#
# Usage: bash driver/scripts/audit_selftest.sh <x64-image> [arm64-image]
#
# Every case states the image, the flags, and the outcome it demands. Cases
# that need an ARM64 image are skipped (loudly) when one is not supplied.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUDIT="$SCRIPT_DIR/audit_sys.sh"
X64="${1:?usage: audit_selftest.sh <x64-image> [arm64-image]}"
ARM64="${2:-}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

# expect_pass <label> <args...>
expect_pass() {
  local label="$1"; shift
  if bash "$AUDIT" "$@" >"$TMP/out" 2>&1; then
    printf 'ok    %s\n' "$label"; pass=$((pass + 1))
  else
    printf 'BAD   %s (expected exit 0, got %s)\n' "$label" "$?"
    sed 's/^/        /' "$TMP/out"
    fail=$((fail + 1))
  fi
}

# expect_fail <label> <line-regex-that-must-report-FAIL> <args...>
expect_fail() {
  local label="$1" re="$2"; shift 2
  bash "$AUDIT" "$@" >"$TMP/out" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    printf 'BAD   %s (expected nonzero exit, got 0)\n' "$label"
    sed 's/^/        /' "$TMP/out"
    fail=$((fail + 1))
  elif ! grep -qE "$re" "$TMP/out"; then
    printf 'BAD   %s (exited %s but no line matched /%s/)\n' "$label" "$rc" "$re"
    sed 's/^/        /' "$TMP/out"
    fail=$((fail + 1))
  else
    printf 'ok    %s\n' "$label"; pass=$((pass + 1))
  fi
}

MODULES_OK="$SCRIPT_DIR/../audit/kernel-modules.allow"
SYMBOLS_OK="$SCRIPT_DIR/../audit/win10-imports.allow"
printf '# fixture: deliberately omits ntoskrnl.exe\nhal.dll\n' >"$TMP/modules-bad.allow"
printf '# fixture: deliberately omits DbgPrint\nntoskrnl.exe!KeBugCheckEx\n' >"$TMP/symbols-bad.allow"
awk 'tolower($0) != "ntoskrnl.exe!iofcompleterequest"' \
  "$SYMBOLS_OK" >"$TMP/symbols-without-iofcomplete.allow"

# 1. Positive control: the real x64 image passes both shipped allowlists.
expect_pass 'x64 image passes' \
  --expect-machine x64 --modules-allow "$MODULES_OK" \
  --allowlist "$SYMBOLS_OK" "$X64"

# 2. Machine mismatch is a failure.
if [ -n "$ARM64" ]; then
  expect_fail 'arm64 image rejected as x64' 'machine .*FAIL' \
    --expect-machine x64 --modules-allow "$MODULES_OK" "$ARM64"
  expect_pass 'arm64 image passes as arm64' \
    --expect-machine arm64 --modules-allow "$MODULES_OK" \
    --allowlist "$SYMBOLS_OK" "$ARM64"
else
  printf 'SKIP  arm64 cases (no arm64 image supplied)\n'
fi

# 3. An imported module outside the allowlist is a failure.
expect_fail 'module outside allowlist rejected' 'module allowlist .*FAIL' \
  --expect-machine x64 --modules-allow "$TMP/modules-bad.allow" "$X64"

# 4. An imported symbol outside the symbol allowlist is a failure.
expect_fail 'symbol outside allowlist rejected' 'symbol allowlist .*FAIL' \
  --expect-machine x64 --modules-allow "$MODULES_OK" --allowlist "$TMP/symbols-bad.allow" "$X64"

# 5. Removing a newly required C3 import must identify that exact symbol. This
#    catches an audit that stops enforcing individual entries after the
#    expanded allowlist makes the real image pass.
expect_fail 'new C3 symbol omission rejected' \
  '^  not allowed: ntoskrnl\.exe!iofcompleterequest$' \
  --expect-machine x64 --modules-allow "$MODULES_OK" \
  --allowlist "$TMP/symbols-without-iofcomplete.allow" "$X64"

# 6. A missing DriverEntry export is a HARD failure, and a substring match on a
#    name like NtAddDriverEntry must not rescue it. ntdll.dll exports ten names
#    containing "DriverEntry" and none of them is DriverEntry.
expect_fail 'ntdll rejected: no DriverEntry export' 'DriverEntry .*FAIL' \
  --expect-machine x64 --modules-allow "$MODULES_OK" /c/Windows/System32/ntdll.dll

# 7. A wrong --expect-profile is a failure.
expect_fail 'wrong profile string rejected' 'profile .*FAIL' \
  --expect-machine x64 --modules-allow "$MODULES_OK" --expect-profile ThisProfileDoesNotExist "$X64"

# --- The three checks that had no expect_fail case until slice C2 ---
#
# C1's gate named check 7 (resolver names) as unproven and deferred the
# enumeration. Enumerated here, there were THREE: subsystem, no-CRT-imports, and
# resolver names. A check that has never failed is not evidence, and that is this
# script's own opening standard.
#
# cmd.exe supplies a natural negative for two of them: it is IMAGE_SUBSYSTEM_
# WINDOWS_CUI rather than NATIVE, and it imports msvcrt.dll.
CMD="${SYSTEMROOT:-C:\Windows}\System32\cmd.exe"
if [ -f "$CMD" ]; then
  expect_fail 'non-NATIVE subsystem rejected' 'subsystem NATIVE .*FAIL'     --expect-machine x64 --modules-allow "$MODULES_OK" "$CMD"
  expect_fail 'CRT import rejected' 'no CRT imports .*FAIL'     --expect-machine x64 --modules-allow "$MODULES_OK" "$CMD"
else
  printf 'SKIP  subsystem and CRT cases (no cmd.exe at %s)
' "$CMD"
fi

# The resolver check has no natural negative: its table holds ExAllocatePool2,
# which the images deliberately do NOT import, and no stock binary imports it
# either. So the negative is built from the other side -- feed it a resolver
# table naming a symbol the image DOES statically import. The check is "no name
# in the resolver table may be a static import", and this is exactly that
# violation.
RESOLVER_NEGATIVE="$(mktemp)"
printf 'ExAllocatePoolWithTag
' > "$RESOLVER_NEGATIVE"
expect_fail 'resolver name present as a static import rejected' 'resolver names absent .*FAIL'   --expect-machine x64 --modules-allow "$MODULES_OK"   --resolver-table "$RESOLVER_NEGATIVE" "$X64"
rm -f "$RESOLVER_NEGATIVE"

# --expect-string, both directions. A check that only ever passes is not
# evidence, and this one has two ways to be wrong: missing a string that is
# there, and claiming one that is not.
expect_pass 'expect-string finds an ASCII string'   --expect-machine x64 --modules-allow "$MODULES_OK" --expect-string 'FSRING' "$X64"
expect_fail 'expect-string rejects an absent string' 'expect-string .*FAIL'   --expect-machine x64 --modules-allow "$MODULES_OK"   --expect-string 'ThisStringIsNotInTheImage' "$X64"

printf '\nSELFTEST: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
