#!/usr/bin/env bash
# Compile-fail proofs for fsring-core (design section 5.3).
#
# Each fixture in driver/tests/compile-fail/ MUST fail to compile, and MUST fail
# with the message named in its .expected file. A fixture that compiles is a
# failure; a fixture that fails with the wrong message is a failure. Exit codes
# distinguish the two failure modes that matter:
#   0  every fixture behaved
#   1  a fixture misbehaved
#   2  the proof suite could not be RUN: fsring-core would not build, the
#      pinned rustc could not be resolved, or the fixture directory is missing
#      or empty. None of these is a proof failure.
#
# The fixtures are deliberately NOT workspace members: they are compiled by
# rustc against an rlib this runner builds into its own target directory, so a
# fixture that is supposed to fail can never break an ordinary `cargo build`.
set -uo pipefail

DRIVER="$(cd "$(dirname "$0")/.." && pwd)"
FIXDIR="$DRIVER/tests/compile-fail"
OUT="$DRIVER/target/compile-fail"
DEPS="$OUT/deps"
mkdir -p "$OUT"

[ -d "$FIXDIR" ] || { echo "FAIL: no fixture directory at $FIXDIR"; exit 2; }

# The pinned toolchain is a PAYLOAD, not a selector.
#
# `rustup which` is gone: it answers with whatever the ambient rustup
# configuration selects, so a proof suite that trusted it could compile the
# fixtures against a different rustc than the one the gate froze and never
# notice. Under the C4 source gate the three 1.85 payload paths and their
# SHA-256 values arrive in closed FSRING_C4_TOOL_* variables and are verified
# here before anything runs. Outside the gate the same payloads are resolved by
# validated filesystem path under RUSTUP_HOME, which still never invokes rustup.
export RUSTUP_AUTO_INSTALL=0

c4_require_tool() {
  command -v "$1" >/dev/null 2>&1 && return 0
  echo "BUILD FAILURE: this script needs '$1' on PATH" >&2
  return 1
}

# `C:\a\b` -> `/c/a/b`, in the shell itself.
#
# This used to call `cygpath`, and under the gate's closed child PATH that made
# the conversion depend on a second external tool: when it was not found the
# fallback handed `sha256sum` a Windows path, which is not a path bash can open,
# and the hash came back empty. A conversion the shell can do itself has no
# such failure mode. Verified equal to `cygpath -u` on the frozen payloads.
c4_win_to_posix() {
  local converted="${1//\\//}"
  case "$converted" in
    ?:/*)
      local drive="${converted%%:*}"
      local rest="${converted#*:}"
      printf '/%s%s' "$(printf '%s' "$drive" | tr 'A-Z' 'a-z')" "$rest"
      ;;
    *)
      printf '%s' "$converted"
      ;;
  esac
}

# An empty hash is not a hash. Returning one on failure is what let a missing
# tool look like a mismatching payload instead of a broken environment, so the
# refusal names both the original and the path it actually tried to read.
c4_sha256() {
  local posix raw status digest
  c4_require_tool sha256sum || return 1
  posix="$(c4_win_to_posix "$1")"
  # sha256sum's own stderr is kept, not discarded, and the pipe to `cut` is
  # gone: a `2>/dev/null | cut` swallows both the tool's reason for failing AND
  # the failure of `cut` itself, which is how "could not hash" ended up meaning
  # nothing in particular.
  # </dev/null is load-bearing. MSYS coreutils calls setmode() on STDIN even
  # when it is hashing a named file, and a captured child has no usable stdin,
  # so sha256sum aborts with "failed to set file descriptor text/binary mode:
  # Bad file descriptor" -- which arrives looking like a hash mismatch and has
  # nothing to do with the file being hashed.
  raw="$(sha256sum "$posix" </dev/null 2>&1)"
  status=$?
  if [ "$status" -ne 0 ] || [ -z "$raw" ]; then
    echo "BUILD FAILURE: sha256sum failed on $posix (status $status): $raw" >&2
    return 1
  fi
  digest="${raw%% *}"
  if [ "${#digest}" -ne 64 ]; then
    echo "BUILD FAILURE: sha256sum gave no digest for $posix: $raw" >&2
    return 1
  fi
  printf '%s' "$digest"
}

# A frozen role is used only after its bytes match the hash the runner froze.
# Checking that the path exists would prove nothing: the point is that the file
# at that path is still the file that was measured.
c4_frozen_role() {
  local suffix="$1"
  local path_var="FSRING_C4_TOOL_${suffix}"
  local hash_var="FSRING_C4_TOOL_${suffix}_SHA256"
  local path="${!path_var-}"
  local expected="${!hash_var-}"
  [ -n "$path" ] || return 1
  if [ -z "$expected" ]; then
    echo "BUILD FAILURE: ${path_var} has no frozen SHA-256" >&2
    return 1
  fi
  local actual
  actual="$(c4_sha256 "$path")" || return 1
  if [ "$actual" != "$expected" ]; then
    echo "BUILD FAILURE: ${path_var} does not match its frozen SHA-256" >&2
    return 1
  fi
  printf '%s' "$path"
}

C4_ROLE_SUFFIXES="CARGO_1_85_0 RUSTC_1_85_0 RUSTDOC_1_85_0"
C4_ROLE_NAMES="cargo-1.85.0 rustc-1.85.0 rustdoc-1.85.0"
PINNED_CARGO=""
RUSTC=""
PINNED_RUSTDOC=""
if [ -n "${FSRING_C4_TOOL_CARGO_1_85_0-}" ]; then
  # `|| exit 2` on each: a failure inside $( ) cannot exit this script by
  # itself, and without this the refusal text becomes the variable's value.
  PINNED_CARGO="$(c4_frozen_role CARGO_1_85_0)" || exit 2
  RUSTC="$(c4_frozen_role RUSTC_1_85_0)" || exit 2
  PINNED_RUSTDOC="$(c4_frozen_role RUSTDOC_1_85_0)" || exit 2
elif [ -n "${FSRING_C4_COMMAND_ID-}" ]; then
  # Keyed on the command ID, not the nonce. The nonce answers "do I owe a
  # marker?"; the command ID answers "is the gate running me?". A row that owns
  # a marker withholds the nonce from its children so only one PRE/POST pair
  # brackets the row, and keying this refusal on the nonce turned that
  # withholding into a silent fall-through to the developer path.
  echo "BUILD FAILURE: the C4 source gate did not supply the frozen 1.85 payload set"
  exit 2
else
  RUSTUP_ROOT="${RUSTUP_HOME:-${USERPROFILE:-$HOME}/.rustup}"
  BIN="$(c4_win_to_posix "$RUSTUP_ROOT")/toolchains/1.85.0-x86_64-pc-windows-msvc/bin"
  [ -d "$BIN" ] || { echo "BUILD FAILURE: no 1.85.0 toolchain payload directory at $BIN"; exit 2; }
  PINNED_CARGO="$BIN/cargo.exe"
  RUSTC="$BIN/rustc.exe"
  PINNED_RUSTDOC="$BIN/rustdoc.exe"
  for payload in "$PINNED_CARGO" "$RUSTC" "$PINNED_RUSTDOC"; do
    [ -x "$payload" ] || { echo "BUILD FAILURE: missing 1.85.0 payload $payload"; exit 2; }
  done
fi

# One sentinel-prefixed line per phase, naming every frozen role this script
# actually launches. The runner parses it out of raw stdout and compares the
# path and SHA-256 -- this script's own observations -- against its retained
# deny-write handle. The two native identity fields are echoed from the freeze
# because a POSIX shell cannot read an NTFS volume serial or file ID.
c4_emit_marker() {
  local phase="$1"
  [ -n "${FSRING_C4_MARKER_NONCE-}" ] || return 0
  local out='FSRING-C4-NESTED-TOOLS {"schema":"fsring-c4-nested-tools-marker/v1","version":1'
  out="${out},\"nonce\":\"${FSRING_C4_MARKER_NONCE}\",\"phase\":\"${phase}\""
  out="${out},\"commandId\":\"${FSRING_C4_COMMAND_ID-}\",\"tools\":["
  local first=1
  local index=1
  local suffix
  for suffix in $C4_ROLE_SUFFIXES; do
    local path_var="FSRING_C4_TOOL_${suffix}"
    local volume_var="FSRING_C4_TOOL_${suffix}_VOLUME"
    local fileid_var="FSRING_C4_TOOL_${suffix}_FILEID"
    local path="${!path_var-}"
    local role
    role="$(printf '%s' "$C4_ROLE_NAMES" | cut -d' ' -f"$index")"
    index=$((index + 1))
    [ -n "$path" ] || continue
    local escaped
    escaped="$(printf '%s' "$path" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
    [ "$first" -eq 1 ] || out="${out},"
    first=0
    out="${out}{\"role\":\"${role}\",\"path\":\"${escaped}\""
    out="${out},\"volumeSerial\":\"${!volume_var-}\",\"fileId\":\"${!fileid_var-}\""
    local digest
    digest="$(c4_sha256 "$path")" || exit 2
    out="${out},\"sha256\":\"${digest}\"}"
  done
  out="${out}],\"launchCounts\":[]}"
  printf '%s\n' "$out"
}

c4_emit_marker PRE

echo "building fsring-core for the fixtures..."
if ! (cd "$DRIVER" && CARGO="$PINNED_CARGO" RUSTC="$RUSTC" RUSTDOC="$PINNED_RUSTDOC" \
      "$PINNED_CARGO" build -p fsring-core --locked --offline --target-dir "$DEPS") >"$OUT/build.log" 2>&1; then
  echo "BUILD FAILURE: fsring-core could not be built; this is not a fixture failure"
  cat "$OUT/build.log"
  exit 2
fi

RLIB="$(ls "$DEPS"/debug/libfsring_core*.rlib 2>/dev/null | head -1)"
[ -n "$RLIB" ] || { echo "BUILD FAILURE: no fsring-core rlib under $DEPS/debug"; exit 2; }

# The fixtures use the exact rustc resolved above. A bare `rustc` would resolve
# to the machine's default toolchain and can produce E0514 against the rlib.

pass=0
fail=0
shopt -s nullglob
fixtures=("$FIXDIR"/*.rs)
shopt -u nullglob
[ "${#fixtures[@]}" -gt 0 ] || { echo "FAIL: no fixtures found in $FIXDIR"; exit 2; }

for fixture in "${fixtures[@]}"; do
  name="$(basename "$fixture" .rs)"
  expected_file="${fixture%.rs}.expected"
  if [ ! -f "$expected_file" ]; then
    printf 'BAD   %-26s no .expected file\n' "$name"
    fail=$((fail + 1))
    continue
  fi
  # EVERY non-empty line of .expected must appear in the output, not just the
  # first. A fixture that fails with the right error CODE for the wrong REASON
  # otherwise passes this gate silently: E0451 is E0451 whether the private
  # field belongs to the type under test or to something incidental. So an
  # .expected file carries the code AND the phrase that identifies the reason,
  # and both are checked here rather than by a human reading the log.
  needle_count=$(grep -c -v '^[[:space:]]*$' "$expected_file")
  # A code-only needle set is still vacuous about the property: E0451 is E0451
  # whether the intended field is private or an incidental private field was
  # reached first. Every fixture therefore needs at least the error code and
  # one property-specific diagnostic phrase.
  if [ "$needle_count" -lt 2 ]; then
    printf 'BAD   %-26s .expected has %s needle; need code + property phrase\n' \
           "$name" "$needle_count"
    fail=$((fail + 1))
    continue
  fi

  "$RUSTC" --edition 2024 --crate-type lib \
        --extern fsring_core="$RLIB" -L "dependency=$DEPS/debug/deps" \
        --out-dir "$OUT" "$fixture" >"$OUT/$name.txt" 2>&1
  rc=$?

  # `RequestTableId` privacy is resolved before the compiler reaches the
  # outer structs' private-field checks, so one rustc invocation cannot emit
  # both independent diagnostic families. Recompile this same manifest stem
  # under a cfg and combine the outputs. The fixture passes only when both
  # probes fail with every expected needle; no extra fixture stem is added.
  if [ "$name" = "forged_capture_token" ]; then
    "$RUSTC" --edition 2024 --crate-type lib \
          --cfg reqtab_request_table_id_probe \
          --extern fsring_core="$RLIB" -L "dependency=$DEPS/debug/deps" \
          --out-dir "$OUT" "$fixture" >>"$OUT/$name.txt" 2>&1
    privacy_rc=$?
    if [ "$rc" -eq 0 ] && [ "$privacy_rc" -eq 0 ]; then
      rc=0
    else
      rc=1
    fi
  fi

  if [ "$rc" -eq 0 ]; then
    printf 'BAD   %-26s COMPILED, but must not\n' "$name"
    fail=$((fail + 1))
    continue
  fi

  missing=""
  matched=0
  # Strip CR: a .expected committed with CRLF would otherwise carry a trailing
  # carriage return into every needle, and a fixed-string search for E0451<CR>
  # cannot match LF rustc output -- the fixture would report BAD for a reason
  # unrelated to the code. .gitattributes normalizes to LF today, so this
  # defends against that setting going away, not against a live bug.
  while IFS= read -r needle; do
    needle="${needle%$'\r'}"
    [ -n "$needle" ] || continue
    if grep -q -F -- "$needle" "$OUT/$name.txt"; then
      matched=$((matched + 1))
    else
      missing="$needle"
      break
    fi
  done < "$expected_file"

  if [ -n "$missing" ]; then
    printf 'BAD   %-26s failed, but no output contained "%s"\n' "$name" "$missing"
    sed 's/^/        /' "$OUT/$name.txt"
    fail=$((fail + 1))
  else
    first="$(grep -v '^[[:space:]]*$' "$expected_file" | head -1)"
    printf 'ok    %-26s rejected with %s (%s/%s needles)\n' \
           "$name" "$first" "$matched" "$needle_count"
    pass=$((pass + 1))
  fi
done

c4_emit_marker POST

printf '\nCOMPILE-FAIL: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
