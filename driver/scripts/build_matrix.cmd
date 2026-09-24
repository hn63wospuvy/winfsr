@echo off
setlocal
set "FSRING_R2_BATCH_PREFLIGHT=%~f0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$bytes = [IO.File]::ReadAllBytes($env:FSRING_R2_BATCH_PREFLIGHT); $hasCrLf = $false; $hasBareLf = $false; $hasBareCr = $false; for ($index = 0; $index -lt $bytes.Length; $index++) { if ($bytes[$index] -eq 10) { if ($index -gt 0 -and $bytes[$index - 1] -eq 13) { $hasCrLf = $true } else { $hasBareLf = $true } } elseif ($bytes[$index] -eq 13 -and ($index + 1 -ge $bytes.Length -or $bytes[$index + 1] -ne 10)) { $hasBareCr = $true } }; if (-not $hasCrLf -or $hasBareLf -or $hasBareCr) { exit 1 }"
if errorlevel 1 (
  echo FAIL: batch script must be CRLF-only before any CALL or label jump: "%~f0".
  endlocal
  exit /b 2
)
endlocal

rem --- the C4 source gate's frozen tool contract ----------------------------
rem
rem Rows 19 and 20 of the source battery launch this file, and the gate needs to
rem know which executables it actually reached. Freezing a path is not enough on
rem its own: this script drives PowerShell, Python, Git Bash, Cargo, Clippy,
rem cargo-wdk, InfVerif and SignTool, and any of those could otherwise come off
rem the ambient PATH. So under the gate every role arrives in a closed
rem FSRING_C4_TOOL_* variable, its bytes are verified against the SHA-256 the
rem runner measured through a retained deny-write handle, and one marker line is
rem printed before and after the whole run.
rem
rem Every role also has a default so an ordinary developer run still works. A
rem literal `python` or `powershell.exe` at a launch site below would defeat the
rem freeze, so there are none.
set "FSRING_C4_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "FSRING_C4_PY=python"
if defined FSRING_C4_TOOL_POWERSHELL set "FSRING_C4_PS=%FSRING_C4_TOOL_POWERSHELL%"
if defined FSRING_C4_TOOL_PYTHON set "FSRING_C4_PY=%FSRING_C4_TOOL_PYTHON%"
if defined FSRING_C4_TOOL_GIT_BASH set "FSRING_BASH=%FSRING_C4_TOOL_GIT_BASH%"
rem The Rust payloads are deliberately NOT bound to CARGO/RUSTC/RUSTDOC or
rem CLIPPY_DRIVER_PATH here. `:reject_ambient_build_environment` below refuses
rem the run when any of those is already set, and it is right to: this script
rem resolves its own cargo and rustc through the Rustup selector proxy, checks
rem both against a literal version string and SHA-256, and sets CARGO, RUSTC,
rem RUSTUP_HOME and CARGO_TARGET_DIR itself immediately before each Cargo run.
rem Binding them up here established a build environment BEFORE the guard that
rem exists to prove none was established, so the gate rows that run this file
rem failed with "uncontrolled environment: CARGO,...,RUSTC,RUSTDOC" -- refused
rem by this script, over variables this script had just set.
rem
rem The frozen set still arrives: `:c4_verify_frozen_roles` hashes every
rem FSRING_C4_TOOL_* payload before anything runs, and `:c4_emit_marker`
rem reports the roster. The Rust toolchain is therefore pinned twice over, by
rem two independent routes to the same files.

rem The wrapper re-enters this same file once with FSRING_C4_MARKER_WRAPPED set.
rem That is what makes the POST marker unconditional: this script has some fifty
rem `exit /b` sites and bracketing each one would miss the next one added.
if not defined FSRING_C4_MARKER_NONCE goto :c4_marker_ready
if defined FSRING_C4_MARKER_WRAPPED goto :c4_marker_ready
call :c4_verify_frozen_roles
if errorlevel 1 exit /b 2
call :c4_reset_launch_journal
if errorlevel 1 exit /b 2
call :c4_emit_marker PRE
set "FSRING_C4_MARKER_WRAPPED=1"
rem The nonce is withheld from everything below this line and restored only
rem to emit POST. `compile_fail.sh` -- which this file runs, and which owns
rem row 11's marker -- emits whenever it sees a nonce, so as a grandchild of
rem row 20 it inherited this row's nonce and printed a second PRE/POST pair
rem carrying this row's commandId. The gate counted four markers where the
rem contract above says two: one before and one after the whole run.
rem
rem Only the marker is suppressed. FSRING_C4_TOOL_* and FSRING_C4_COMMAND_ID
rem still reach every child, so the frozen payloads are still what they
rem launch and a child can still tell that the gate is running it.
set "FSRING_C4_MARKER_NONCE_HELD=%FSRING_C4_MARKER_NONCE%"
set "FSRING_C4_MARKER_NONCE="
call "%~f0" %*
set "FSRING_C4_WRAPPED_RC=%ERRORLEVEL%"
set "FSRING_C4_MARKER_NONCE=%FSRING_C4_MARKER_NONCE_HELD%"
set "FSRING_C4_MARKER_NONCE_HELD="
call :c4_emit_marker POST
exit /b %FSRING_C4_WRAPPED_RC%
:c4_marker_ready
if /I "%~1"=="--self-test" goto :R2_SELF_TEST
rem FSRING driver gate: three release images, their audits, the three negative
rem feature builds, and the four clippy configurations (three image profiles plus
rem fsring-core), and the core host proofs (design sections 5.5, 7).
rem
rem cargo-wdk has no --features flag, so the nondefault platform-win7 image goes
rem through a bare `cargo build --release`: it is an unpackaged, unsigned PE, but
rem the audited properties come from the linker, not from the packaging step.
rem
rem Ordinary commands are passed to _in_devenv.cmd as ONE quoted string. The two
rem package builds use a dedicated token and environment so no nested batch
rem quoting can alter their arguments.
rem
rem `where bash` on a machine with WSL resolves to C:\Windows\System32\bash.exe,
rem which is NOT Git Bash. Resolve it explicitly; override with FSRING_BASH.
setlocal EnableDelayedExpansion
set "SCRIPTS=%~dp0"
for %%I in ("%~dp0..") do set "DRIVER=%%~fI"
set "LOCKFILE=!DRIVER!\Cargo.lock"
set "FSRING_LOCKED_CARGO_SOURCE=%~dp0locked-cargo\cargo_shim.rs"
set "FSRING_ATTESTATION_VERIFIER=%~dp0locked-cargo\verify_attestation.ps1"
set "FSRING_NATIVE_DIRECTORY_GATE=%~dp0locked-cargo\native_directory_gate.ps1"
set "FSRING_LOCKED_CARGO_CONFIG=!DRIVER!\.cargo\config.toml"
set "FSRING_GENERATED_TOOLS_PARENT=!DRIVER!\target\fsring-generated-tools"
if not exist "%FSRING_ATTESTATION_VERIFIER%" (
  echo FAIL: tracked bounded attestation verifier is missing: "%FSRING_ATTESTATION_VERIFIER%".
  exit /b 2
)
if not exist "%FSRING_NATIVE_DIRECTORY_GATE%" (
  echo FAIL: tracked native-directory gate is missing: "%FSRING_NATIVE_DIRECTORY_GATE%".
  exit /b 2
)
call :hash_file "%FSRING_ATTESTATION_VERIFIER%" ATTESTATION_VERIFIER_HASH
if errorlevel 1 exit /b 2
call :hash_file "%FSRING_NATIVE_DIRECTORY_GATE%" NATIVE_DIRECTORY_GATE_HASH
if errorlevel 1 exit /b 2
call :reject_ambient_build_environment
if errorlevel 1 (
  echo FAIL: uncontrolled ambient Cargo/Rust build environment.
  exit /b 2
)
call :validate_cargo_configuration
if errorlevel 1 (
  echo FAIL: Cargo configuration discovery is not closed.
  exit /b 2
)
rem Established HERE, and not before the guard above: the guard proves no
rem build environment was inherited, and a determinism control set ahead of
rem it would be indistinguishable from the ambient setting it refuses. The
rem C4 source gate supplies this to every Cargo row it runs directly; a row
rem that runs THIS file is supplied nothing, so the control is re-established
rem on the far side of the proof. Deliberately one line rather than seven
rem beside the existing CARGO_TARGET_DIR sites, so a Cargo launch added later
rem inherits it too.
set "CARGO_INCREMENTAL=0"
call :create_fresh_native_directory FSRING_RUSTUP_SELECTOR_DIR
if errorlevel 1 (
  echo FAIL: fresh Rustup-selector directory could not be created.
  exit /b 2
)
set "FSRING_REAL_CARGO=!FSRING_RUSTUP_SELECTOR_DIR!\cargo.exe"
set "RUSTC_PROXY=!FSRING_RUSTUP_SELECTOR_DIR!\rustc.exe"
call :create_fresh_native_directory FSRING_LOCKED_CARGO_DIR
if errorlevel 1 (
  echo FAIL: fresh native application directory could not be created.
  exit /b 2
)
if /I "!FSRING_RUSTUP_SELECTOR_DIR!"=="!FSRING_LOCKED_CARGO_DIR!" (
  echo FAIL: Rustup selector and cargo-wdk application directories were reused.
  exit /b 2
)
set "FSRING_LOCKED_CARGO_TARGET_DIR=!FSRING_CONTROLLED_TARGET_DIR!"
set "FSRING_LOCKED_CARGO_EXE=!FSRING_LOCKED_CARGO_DIR!\cargo.exe"
set "FSRING_LOCKED_CARGO_TEST_EXE=!FSRING_LOCKED_CARGO_DIR!\sha256-tests.exe"
set "FSRING_LOCKED_CARGO_TEST_PDB=!FSRING_LOCKED_CARGO_DIR!\sha256-tests.pdb"
set "FSRING_CARGO_WDK_LAUNCH=!FSRING_LOCKED_CARGO_DIR!\cargo-wdk.exe"
set "CARGO_NET_OFFLINE=true"
set "EXPECTED_CARGO_VERSION=cargo 1.85.0 (d73d2caf9 2024-12-31)"
set "EXPECTED_WDK_VERSION=cargo wdk 0.1.1"
set "EXPECTED_RUSTC_VERSION=rustc 1.85.0 (4d91de4e4 2025-02-17)"

rem Resolve every executable before any PATH mutation.
call :resolve_rustup_proxy_source FSRING_RUSTUP_PROXY_SOURCE
if not defined FSRING_RUSTUP_PROXY_SOURCE (
  echo FAIL: rustup.exe was found neither on the original PATH nor at "%USERPROFILE%\.cargo\bin\rustup.exe".
  exit /b 2
)
call :require_absolute_file "%FSRING_RUSTUP_PROXY_SOURCE%"
if errorlevel 1 (
  echo FAIL: resolved Rustup proxy source is missing or not absolute: "%FSRING_RUSTUP_PROXY_SOURCE%".
  exit /b 2
)
call :check_native_identity File "%FSRING_RUSTUP_PROXY_SOURCE%"
if errorlevel 1 (
  echo FAIL: resolved Rustup proxy source native identity is not exact: "%FSRING_RUSTUP_PROXY_SOURCE%".
  exit /b 2
)
call :hash_file "%FSRING_RUSTUP_PROXY_SOURCE%" RUSTUP_PROXY_SOURCE_HASH
if errorlevel 1 (
  echo FAIL: resolved Rustup proxy source could not be hashed.
  exit /b 2
)
set "FSRING_RUSTUP_PROXY_SOURCE_SHA256=%RUSTUP_PROXY_SOURCE_HASH%"
call :prepare_rustup_selector_proxies
if errorlevel 1 (
  echo FAIL: fresh non-reparse Cargo/rustc selector proxies could not be prepared.
  exit /b 2
)
set "FSRING_RUSTUP_SELECTOR_RUSTC=%RUSTC_PROXY%"
set "FSRING_RUSTUP_SELECTOR_RUSTC_SHA256=%RUSTC_PROXY_HASH%"
call :resolve_cargo_wdk_source FSRING_CARGO_WDK_SOURCE
if not defined FSRING_CARGO_WDK_SOURCE (
  echo FAIL: cargo-wdk.exe was found neither as a frozen gate role, nor on the original PATH, nor at "%USERPROFILE%\.cargo\bin\cargo-wdk.exe".
  exit /b 2
)
call :require_absolute_file "%FSRING_CARGO_WDK_SOURCE%"
if errorlevel 1 (
  echo FAIL: resolved cargo-wdk is missing or not absolute: "%FSRING_CARGO_WDK_SOURCE%".
  exit /b 2
)
call :check_native_identity File "%FSRING_CARGO_WDK_SOURCE%"
if errorlevel 1 (
  echo FAIL: resolved cargo-wdk source native identity is not exact: "%FSRING_CARGO_WDK_SOURCE%".
  exit /b 2
)
call :require_absolute_file "%RUSTC_PROXY%"
if errorlevel 1 (
  echo FAIL: rustc selector proxy is missing or not absolute: "%RUSTC_PROXY%".
  exit /b 2
)
call :check_native_identity File "%RUSTC_PROXY%"
if errorlevel 1 (
  echo FAIL: rustc selector proxy native identity is not exact: "%RUSTC_PROXY%".
  exit /b 2
)
call :hash_file "%RUSTC_PROXY%" RUSTC_PROXY_HASH
if errorlevel 1 (
  echo FAIL: rustc selector proxy could not be hashed.
  exit /b 2
)
call :resolve_exact_rustc "%RUSTC_PROXY%" FSRING_RUSTC
if not defined FSRING_RUSTC (
  echo FAIL: exact Rust 1.85.0 compiler could not be resolved.
  exit /b 2
)
call :require_absolute_file "%FSRING_RUSTC%"
if errorlevel 1 (
  echo FAIL: resolved rustc is missing or not absolute: "%FSRING_RUSTC%".
  exit /b 2
)
call :check_native_identity File "%FSRING_RUSTC%"
if errorlevel 1 (
  echo FAIL: exact rustc native identity is not exact: "%FSRING_RUSTC%".
  exit /b 2
)
for %%I in ("%FSRING_RUSTC%") do set "FSRING_TOOLCHAIN_CARGO=%%~dpIcargo.exe"
call :require_absolute_file "%FSRING_TOOLCHAIN_CARGO%"
if errorlevel 1 (
  echo FAIL: actual Cargo 1.85.0 beside exact rustc is missing.
  exit /b 2
)
call :check_native_identity File "%FSRING_TOOLCHAIN_CARGO%"
if errorlevel 1 (
  echo FAIL: actual Cargo 1.85.0 native identity is not exact.
  exit /b 2
)
call :resolve_exact_rustup_home "%FSRING_RUSTC%" FSRING_RUSTUP_HOME
if not defined FSRING_RUSTUP_HOME (
  echo FAIL: exact default rustup home/toolchain selector could not be closed.
  exit /b 2
)
call :check_native_identity Directory "%FSRING_RUSTUP_HOME%"
if errorlevel 1 (
  echo FAIL: exact default Rustup-home native identity is not exact.
  exit /b 2
)
if not exist "%FSRING_LOCKED_CARGO_SOURCE%" (
  echo FAIL: tracked native locked-Cargo shim source is missing: "%FSRING_LOCKED_CARGO_SOURCE%".
  exit /b 2
)

call :hash_file "%FSRING_REAL_CARGO%" REAL_CARGO_HASH
if errorlevel 1 (
  echo FAIL: could not hash exact real Cargo: "%FSRING_REAL_CARGO%".
  exit /b 2
)
set "FSRING_REAL_CARGO_SHA256=%REAL_CARGO_HASH%"
call :check_real_cargo "%FSRING_REAL_CARGO%" "%REAL_CARGO_HASH%"
if errorlevel 1 (
  echo FAIL: "%FSRING_REAL_CARGO%" did not report exact !EXPECTED_CARGO_VERSION!.
  exit /b 2
)
call :hash_file "%FSRING_CARGO_WDK_SOURCE%" WDK_HASH
if errorlevel 1 (
  echo FAIL: could not hash cargo-wdk: "%FSRING_CARGO_WDK_SOURCE%".
  exit /b 2
)
call :check_native_identity File "%FSRING_CARGO_WDK_SOURCE%"
if errorlevel 1 (
  echo FAIL: cargo-wdk source native identity changed during initial hashing.
  exit /b 2
)
call :hash_file "%FSRING_RUSTC%" RUSTC_HASH
if errorlevel 1 (
  echo FAIL: could not hash exact rustc: "%FSRING_RUSTC%".
  exit /b 2
)
call :check_rustc_candidate "%FSRING_RUSTC%" "%RUSTC_HASH%"
if errorlevel 1 (
  echo FAIL: rustc path, version, or initial hash is invalid.
  exit /b 2
)
set "FSRING_RUSTC_SHA256=%RUSTC_HASH%"
call :hash_file "%FSRING_TOOLCHAIN_CARGO%" TOOLCHAIN_CARGO_HASH
if errorlevel 1 (
  echo FAIL: actual toolchain Cargo could not be hashed.
  exit /b 2
)
set "FSRING_TOOLCHAIN_CARGO_SHA256=%TOOLCHAIN_CARGO_HASH%"
call :check_toolchain_cargo "%FSRING_TOOLCHAIN_CARGO%" "%TOOLCHAIN_CARGO_HASH%"
if errorlevel 1 (
  echo FAIL: actual toolchain Cargo path, version, or hash is invalid.
  exit /b 2
)
call :hash_file "%FSRING_LOCKED_CARGO_CONFIG%" CONFIG_HASH
if errorlevel 1 (
  echo FAIL: tracked driver Cargo config could not be hashed.
  exit /b 2
)

call :prepare_native_shim
if errorlevel 1 exit /b 2

echo Rustup proxy source: "%FSRING_RUSTUP_PROXY_SOURCE%" SHA-256 %RUSTUP_PROXY_SOURCE_HASH%
echo fresh Rustup selector directory: "%FSRING_RUSTUP_SELECTOR_DIR%"
echo cargo selector copy: "%FSRING_REAL_CARGO%" [%EXPECTED_CARGO_VERSION%] SHA-256 %REAL_CARGO_HASH%
echo rustc selector copy: "%RUSTC_PROXY%" SHA-256 %RUSTC_PROXY_HASH%
echo cargo-wdk source: "%FSRING_CARGO_WDK_SOURCE%" [%EXPECTED_WDK_VERSION%] SHA-256 %WDK_HASH%
echo cargo-wdk launch copy: "%FSRING_CARGO_WDK%" [%EXPECTED_WDK_VERSION%] SHA-256 %WDK_HASH%
echo rustc: "%FSRING_RUSTC%" [%EXPECTED_RUSTC_VERSION%] SHA-256 %RUSTC_HASH%
echo actual toolchain Cargo: "%FSRING_TOOLCHAIN_CARGO%" [%EXPECTED_CARGO_VERSION%] SHA-256 %TOOLCHAIN_CARGO_HASH%
echo native locked-Cargo shim: "%FSRING_LOCKED_CARGO_EXE%" SHA-256 %SHIM_EXE_HASH%
echo driver Cargo config: "%FSRING_LOCKED_CARGO_CONFIG%" SHA-256 %CONFIG_HASH%
echo controlled Cargo target: "%FSRING_LOCKED_CARGO_TARGET_DIR%"
echo fresh native application directory: "%FSRING_LOCKED_CARGO_DIR%"

call :check_locked_metadata
if errorlevel 1 (
  echo FAIL: locked offline package-CWD metadata did not bind the controlled target.
  exit /b 2
)

call :hash_file "%LOCKFILE%" LOCK_HASH
if errorlevel 1 (
  echo FAIL: could not hash "%LOCKFILE%".
  exit /b 2
)
echo driver Cargo.lock SHA-256 %LOCK_HASH%

if "%FSRING_BASH%"=="" set "FSRING_BASH=%ProgramFiles%\Git\bin\bash.exe"
if not exist "%FSRING_BASH%" (
  echo FAIL: Git Bash not found at "%FSRING_BASH%"; set FSRING_BASH to override.
  exit /b 2
)
set "INFVERIF_DIR=C:\Program Files (x86)\Windows Kits\10\Tools\10.0.26100.0\x64"
if defined FSRING_C4_TOOL_INFVERIF for %%I in ("!FSRING_C4_TOOL_INFVERIF!") do set "INFVERIF_DIR=%%~dpI"
if defined FSRING_C4_TOOL_INFVERIF if "!INFVERIF_DIR:~-1!"=="\" set "INFVERIF_DIR=!INFVERIF_DIR:~0,-1!"
set "INF2CAT_DIR=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86"
if not exist "%INFVERIF_DIR%\infverif.exe" (
  echo FAIL: InfVerif 10.0.26100 not found at "%INFVERIF_DIR%\infverif.exe".
  exit /b 2
)
if not exist "%INF2CAT_DIR%\Inf2Cat.exe" (
  echo FAIL: Inf2Cat 10.0.26100 not found at "%INF2CAT_DIR%\Inf2Cat.exe".
  exit /b 2
)
set "PATH=%INFVERIF_DIR%;%INF2CAT_DIR%;%PATH%"
set "FSRING_LOCKED_CARGO_TOOLCHAIN=1.85.0"
set "FSRING_EXPECTED_MANIFEST=%DRIVER%\fsring-fsd\Cargo.toml"
set "FSRING_EXPECTED_X64_PACKAGE=%FSRING_CONTROLLED_TARGET_DIR%\x86_64-pc-windows-msvc\release\fsring_fsd_package"
set "FSRING_EXPECTED_ARM64_PACKAGE=%FSRING_CONTROLLED_TARGET_DIR%\aarch64-pc-windows-msvc\release\fsring_fsd_package"
set "FSRING_NATIVE_ALLOWED_EVIDENCE="
set "FAILED=0"
set "NEG=0"

set "R2_EVIDENCE=%DRIVER%\target\fsring-audit"
for %%L in (win10-x64 win10-arm64 win7-x64) do if not exist "%R2_EVIDENCE%\%%L" mkdir "%R2_EVIDENCE%\%%L"

rem cargo-wdk packages deps\fsring_fsd.map, and the named /MAP: that
rem fsring-fsd's build.rs appends overrides wdk-build's bare one -- so the
rem link must write THAT path or packaging fails with "Failed to copy
rem file". The evidence copy is taken from it afterwards, like the PDB.
set "FSRING_LINK_MAP_PATH=%DRIVER%\target\x86_64-pc-windows-msvc\release\deps\fsring_fsd.map"
echo === [1/3] build Win10 x64 release ^(packaged, test-signed^) ===
call :check_locked_metadata
if errorlevel 1 (
  echo BUILD REFUSED: win10-x64 package metadata is not closed
  exit /b 2
)
call :prepare_package_output "%FSRING_EXPECTED_X64_PACKAGE%"
if errorlevel 1 (
  echo BUILD REFUSED: win10-x64 package output could not be made fresh
  exit /b 2
)
call :prepare_build_attestation "%FSRING_LOCKED_CARGO_DIR%\attestation-x64.txt" win10-x64
if errorlevel 1 (
  echo BUILD REFUSED: win10-x64 attestation could not be prepared
  set "FAILED=1"
) else (
  call :check_package_inputs
  if errorlevel 1 (
    echo BUILD REFUSED: win10-x64 package input identity changed
    set "FAILED=1"
    call :clear_attestation_environment
  ) else (
    set "FSRING_CARGO_WDK_TARGET_ARCH="
    call "%SCRIPTS%_in_devenv.cmd" amd64 __fsring_locked_wdk__
    set "BUILD_RC=!ERRORLEVEL!"
    set "FSRING_NATIVE_ALLOWED_EVIDENCE=attestation-x64.txt"
    call :check_package_inputs
    if errorlevel 1 (
      echo FAIL: package input identity changed during win10-x64
      set "FAILED=1"
    )
    call :verify_attestation
    set "ATTEST_RC=!ERRORLEVEL!"
    if "!ATTEST_RC!"=="0" echo native-shim attestation valid [win10-x64]: nonce !FSRING_LOCKED_CARGO_NONCE! SHA-256 %SHIM_EXE_HASH%
    call :clear_attestation_environment
    call :check_lock "after win10-x64 package build"
    if errorlevel 1 set "FAILED=1"
    if not "!BUILD_RC!"=="0" (
      echo BUILD FAILED: win10-x64
      set "FAILED=1"
    )
    if not "!ATTEST_RC!"=="0" (
      echo BUILD FAILED: win10-x64 native-shim attestation missing or invalid
      set "FAILED=1"
    )
    if "!BUILD_RC!!ATTEST_RC!"=="00" (
      call :require_fresh_package_output "%FSRING_EXPECTED_X64_PACKAGE%"
      if errorlevel 1 (
        echo PACKAGE VERIFY REFUSED: win10-x64 output was not freshly produced
        set "FAILED=1"
      ) else (
        call :c4_note_launch powershell
        "%FSRING_C4_PS%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%verify_fsring_package.ps1" "%FSRING_EXPECTED_X64_PACKAGE%"
      )
      if errorlevel 1 (echo PACKAGE VERIFY FAILED: win10-x64 & set "FAILED=1")
    )
  )
)

copy /y "%DRIVER%\target\x86_64-pc-windows-msvc\release\fsring_fsd.pdb" "%R2_EVIDENCE%\win10-x64\fsring_fsd.pdb" >nul
if errorlevel 1 (echo FAIL: could not retain the win10-x64 PDB & set "FAILED=1")
copy /y "%DRIVER%\target\x86_64-pc-windows-msvc\release\deps\fsring_fsd.map" "%R2_EVIDENCE%\win10-x64\fsring_fsd.map" >nul
if errorlevel 1 (echo FAIL: could not retain the win10-x64 link map & set "FAILED=1")
set "FSRING_LINK_MAP_PATH=%DRIVER%\target\aarch64-pc-windows-msvc\release\deps\fsring_fsd.map"

echo === [2/3] build Win10 ARM64 release ^(packaged^) ===
call :check_locked_metadata
if errorlevel 1 (
  echo BUILD REFUSED: win10-arm64 package metadata is not closed
  exit /b 2
)
call :prepare_package_output "%FSRING_EXPECTED_ARM64_PACKAGE%"
if errorlevel 1 (
  echo BUILD REFUSED: win10-arm64 package output could not be made fresh
  exit /b 2
)
call :prepare_build_attestation "%FSRING_LOCKED_CARGO_DIR%\attestation-arm64.txt" win10-arm64
if errorlevel 1 (
  echo BUILD REFUSED: win10-arm64 attestation could not be prepared
  set "FAILED=1"
) else (
  call :check_package_inputs
  if errorlevel 1 (
    echo BUILD REFUSED: win10-arm64 package input identity changed
    set "FAILED=1"
    call :clear_attestation_environment
  ) else (
    set "FSRING_CARGO_WDK_TARGET_ARCH=arm64"
    call "%SCRIPTS%_in_devenv.cmd" arm64 __fsring_locked_wdk__
    set "BUILD_RC=!ERRORLEVEL!"
    set "FSRING_NATIVE_ALLOWED_EVIDENCE=attestation-x64.txt;attestation-arm64.txt"
    set "FSRING_CARGO_WDK_TARGET_ARCH="
    call :check_package_inputs
    if errorlevel 1 (
      echo FAIL: package input identity changed during win10-arm64
      set "FAILED=1"
    )
    call :verify_attestation
    set "ATTEST_RC=!ERRORLEVEL!"
    if "!ATTEST_RC!"=="0" echo native-shim attestation valid [win10-arm64]: nonce !FSRING_LOCKED_CARGO_NONCE! SHA-256 %SHIM_EXE_HASH%
    call :clear_attestation_environment
    call :check_lock "after win10-arm64 package build"
    if errorlevel 1 set "FAILED=1"
    if not "!BUILD_RC!"=="0" (
      echo BUILD FAILED: win10-arm64
      set "FAILED=1"
    )
    if not "!ATTEST_RC!"=="0" (
      echo BUILD FAILED: win10-arm64 native-shim attestation missing or invalid
      set "FAILED=1"
    )
    if "!BUILD_RC!!ATTEST_RC!"=="00" (
      call :require_fresh_package_output "%FSRING_EXPECTED_ARM64_PACKAGE%"
      if errorlevel 1 (
        echo PACKAGE VERIFY REFUSED: win10-arm64 output was not freshly produced
        set "FAILED=1"
      ) else (
        call :c4_note_launch powershell
        "%FSRING_C4_PS%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%verify_fsring_package.ps1" "%FSRING_EXPECTED_ARM64_PACKAGE%"
      )
      if errorlevel 1 (echo PACKAGE VERIFY FAILED: win10-arm64 & set "FAILED=1")
    )
  )
)

copy /y "%DRIVER%\target\aarch64-pc-windows-msvc\release\fsring_fsd.pdb" "%R2_EVIDENCE%\win10-arm64\fsring_fsd.pdb" >nul
copy /y "%DRIVER%\target\aarch64-pc-windows-msvc\release\deps\fsring_fsd.map" "%R2_EVIDENCE%\win10-arm64\fsring_fsd.map" >nul
if errorlevel 1 (echo FAIL: could not retain the win10-arm64 link map & set "FAILED=1")
if errorlevel 1 (echo FAIL: could not retain the win10-arm64 PDB & set "FAILED=1")
set "FSRING_LINK_MAP_PATH=%R2_EVIDENCE%\win7-x64\fsring_fsd.map"

echo === [3/3] build Win7 x64 release ^(bare PE; cargo-wdk cannot select features^) ===
call "%SCRIPTS%_in_devenv.cmd" amd64 "cargo build --locked --release --target x86_64-pc-windows-msvc --no-default-features --features platform-win7"
if errorlevel 1 (echo BUILD FAILED: win7-x64 & set "FAILED=1")
copy /y "%DRIVER%\target\x86_64-pc-windows-msvc\release\fsring_fsd.pdb" "%R2_EVIDENCE%\win7-x64\fsring_fsd.pdb" >nul
if errorlevel 1 (echo FAIL: could not retain the win7-x64 PDB & set "FAILED=1")
set "FSRING_LINK_MAP_PATH="

echo.
echo === audits ===
rem The two auditors' own self-tests run here as well as in --self-test mode.
rem This path exercises them against conformant artifacts, which can expose an
rem inverted check but never a deleted one; the self-tests are what plant the
rem defect. Before this they ran in neither mode when the matrix was run
rem normally.
call :c4_note_launch python
"%FSRING_C4_PY%" "%SCRIPTS%audit_c4_imports.py" --self-test
if errorlevel 1 set "FAILED=1"
call :c4_note_launch python
"%FSRING_C4_PY%" "%SCRIPTS%audit_c4_stack.py" --self-test
if errorlevel 1 set "FAILED=1"
rem The lifetime auditor was absent from this matrix entirely, and its only
rem other runner was the mutation sweep, which Task 27 had not yet wired. So a
rem change that broke its carrier grammar, its exact fsd file census, or a
rem Task 12 seal could be committed under a MATRIX: PASS that had never asked
rem it anything. One such regression was committed exactly that way. It reads
rem source rather than an image, so it needs no build and costs ~29 seconds
rem against a 25-35 minute matrix.
rem The closed-task promise gate. Round 16 added this auditor, graded it
rem with plants, repaired a real keying hole in it -- and wired it into
rem NOTHING. `git grep audit_c4_task_promises` found only the file itself:
rem no gate row, not this matrix, not the runner, not verify_spec.py. Its
rem PASS existed only in commit messages, which is the exact defect class it
rem was written to catch, one level up. It runs here now.
rem
rem BOTH modes, deliberately. `--self-test` proves the matcher still reaches
rem its fixtures; `--check` proves the live population is adjudicated. Either
rem alone is a gate that can go quiet: a green self-test says nothing about
rem the tree, and a green check says nothing about the matcher.
call :c4_note_launch python
"%FSRING_C4_PY%" "%SCRIPTS%audit_c4_task_promises.py" --self-test
if errorlevel 1 set "FAILED=1"
call :c4_note_launch python
"%FSRING_C4_PY%" "%SCRIPTS%audit_c4_task_promises.py" --check --root "%DRIVER%\.."
if errorlevel 1 set "FAILED=1"
call :c4_note_launch python
"%FSRING_C4_PY%" "%SCRIPTS%audit_c4_lifetime.py" --self-test
if errorlevel 1 set "FAILED=1"
call :c4_note_launch python
"%FSRING_C4_PY%" "%SCRIPTS%audit_c4_lifetime.py" --production-check --root "%DRIVER%\.." --source-root driver/fsring-core/src --source-root driver/fsring-fsd/src
if errorlevel 1 set "FAILED=1"
call :c4_note_launch git-bash
"%FSRING_BASH%" "%SCRIPTS%audit_sys.sh" --expect-machine x64 --expect-profile Win10X64 --allowlist "%DRIVER%\audit\win10-imports.allow" --resolver-table "%DRIVER%\audit\resolver-names.allow" "%DRIVER%\target\x86_64-pc-windows-msvc\release\fsring_fsd.sys"
if errorlevel 1 set "FAILED=1"
rem The allowlist above says which imports are PERMITTED. The two auditors
rem below say which are PRESENT: an allowlist stays green when a required
rem DDI is silently dead-stripped, and that is the failure they exist for.
call :c4_note_launch python
"%FSRING_C4_PY%" "%SCRIPTS%audit_c4_imports.py" --profile Win10X64 --manifest "%DRIVER%\audit\c4-imports-win10-x64.json" --edges "%DRIVER%\audit\c4-stack-roots.json" --image "%DRIVER%\target\x86_64-pc-windows-msvc\release\fsring_fsd.sys" --pdb "%R2_EVIDENCE%\win10-x64\fsring_fsd.pdb" --map "%R2_EVIDENCE%\win10-x64\fsring_fsd.map"
if errorlevel 1 set "FAILED=1"
call :c4_note_launch python
"%FSRING_C4_PY%" "%SCRIPTS%audit_c4_stack.py" --profile Win10X64 --roots "%DRIVER%\audit\c4-stack-roots.json" --source-root "%DRIVER%\fsring-fsd\src" --source-root "%DRIVER%\fsring-fsd\native" --source-root "%DRIVER%\fsring-core\src" --source-root "%DRIVER%\..\fsring-abi\src" --image "%DRIVER%\target\x86_64-pc-windows-msvc\release\fsring_fsd.sys" --map "%R2_EVIDENCE%\win10-x64\fsring_fsd.map" --imports "%DRIVER%\audit\c4-imports-win10-x64.json"
if errorlevel 1 set "FAILED=1"
call :c4_note_launch git-bash
"%FSRING_BASH%" "%SCRIPTS%audit_sys.sh" --expect-machine arm64 --expect-profile Win10Arm64 --allowlist "%DRIVER%\audit\win10-imports.allow" --resolver-table "%DRIVER%\audit\resolver-names.allow" "%DRIVER%\target\aarch64-pc-windows-msvc\release\fsring_fsd.sys"
if errorlevel 1 set "FAILED=1"
call :c4_note_launch python
"%FSRING_C4_PY%" "%SCRIPTS%audit_c4_imports.py" --profile Win10Arm64 --manifest "%DRIVER%\audit\c4-imports-win10-arm64.json" --edges "%DRIVER%\audit\c4-stack-roots.json" --image "%DRIVER%\target\aarch64-pc-windows-msvc\release\fsring_fsd.sys" --pdb "%R2_EVIDENCE%\win10-arm64\fsring_fsd.pdb" --map "%R2_EVIDENCE%\win10-arm64\fsring_fsd.map"
if errorlevel 1 set "FAILED=1"
call :c4_note_launch python
"%FSRING_C4_PY%" "%SCRIPTS%audit_c4_stack.py" --profile Win10Arm64 --roots "%DRIVER%\audit\c4-stack-roots.json" --source-root "%DRIVER%\fsring-fsd\src" --source-root "%DRIVER%\fsring-fsd\native" --source-root "%DRIVER%\fsring-core\src" --source-root "%DRIVER%\..\fsring-abi\src" --image "%DRIVER%\target\aarch64-pc-windows-msvc\release\fsring_fsd.sys" --map "%R2_EVIDENCE%\win10-arm64\fsring_fsd.map" --imports "%DRIVER%\audit\c4-imports-win10-arm64.json"
if errorlevel 1 set "FAILED=1"
call :c4_note_launch git-bash
"%FSRING_BASH%" "%SCRIPTS%audit_sys.sh" --expect-machine x64 --expect-profile Win7X64 --allowlist "%DRIVER%\audit\win7-sp1-imports.allow" --resolver-table "%DRIVER%\audit\resolver-names.allow" "%DRIVER%\target\x86_64-pc-windows-msvc\release\fsring_fsd.dll"
if errorlevel 1 set "FAILED=1"
rem The Win7 leg is a bare unsigned PE with no packaging step, so the
rem auditors below read fsring_fsd.dll directly, paired with the map and
rem PDB that leg retained.
call :c4_note_launch python
"%FSRING_C4_PY%" "%SCRIPTS%audit_c4_imports.py" --profile Win7X64 --manifest "%DRIVER%\audit\c4-imports-win7-x64.json" --edges "%DRIVER%\audit\c4-stack-roots.json" --image "%DRIVER%\target\x86_64-pc-windows-msvc\release\fsring_fsd.dll" --pdb "%R2_EVIDENCE%\win7-x64\fsring_fsd.pdb" --map "%R2_EVIDENCE%\win7-x64\fsring_fsd.map"
if errorlevel 1 set "FAILED=1"
call :c4_note_launch python
"%FSRING_C4_PY%" "%SCRIPTS%audit_c4_stack.py" --profile Win7X64 --roots "%DRIVER%\audit\c4-stack-roots.json" --source-root "%DRIVER%\fsring-fsd\src" --source-root "%DRIVER%\fsring-fsd\native" --source-root "%DRIVER%\fsring-core\src" --source-root "%DRIVER%\..\fsring-abi\src" --image "%DRIVER%\target\x86_64-pc-windows-msvc\release\fsring_fsd.dll" --map "%R2_EVIDENCE%\win7-x64\fsring_fsd.map" --imports "%DRIVER%\audit\c4-imports-win7-x64.json"
if errorlevel 1 set "FAILED=1"

echo.
echo === negative feature builds ^(message match, not exit code^) ===
call :negative "both features selected" "mutually exclusive" amd64 "cargo check --locked --features platform-win10,platform-win7"
call :negative "no feature selected" "exactly one of platform-win10" amd64 "cargo check --locked --no-default-features"
call :negative "win7 on arm64" "platform-win7 is x64-only" arm64 "cargo check --locked --no-default-features --features platform-win7 --target aarch64-pc-windows-msvc"

echo.
echo === clippy ^(four configurations; -D warnings^) ===
rem `cargo clippy` finds `cargo-clippy` as an external subcommand on PATH,
rem which under the gate resolved to the rustup proxy in the Cargo home --
rem NOT the frozen cargo-clippy-1.85.0 the gate leases. The proxy then picks a
rem toolchain by rustup rules at run time, so nothing sealed recorded which
rem clippy actually ran. Name the frozen payload when the gate supplied one,
rem the same order this file already uses for rustup and cargo-wdk: frozen
rem payload first, bare name only for a developer run.
set "FSRING_MATRIX_CLIPPY=cargo clippy"
if defined FSRING_C4_TOOL_CARGO_CLIPPY_1_85_0 set "FSRING_MATRIX_CLIPPY="%FSRING_C4_TOOL_CARGO_CLIPPY_1_85_0%" clippy"
call :c4_require_frozen_clippy
if errorlevel 2 exit /b 2
call "%SCRIPTS%_in_devenv.cmd" amd64 "%FSRING_MATRIX_CLIPPY% --locked --all-targets -- -D warnings"
if errorlevel 1 (echo CLIPPY FAILED: default x64 & set "FAILED=1")
call "%SCRIPTS%_in_devenv.cmd" amd64 "%FSRING_MATRIX_CLIPPY% --locked --all-targets --no-default-features --features platform-win7 -- -D warnings"
if errorlevel 1 (echo CLIPPY FAILED: platform-win7 & set "FAILED=1")
call "%SCRIPTS%_in_devenv.cmd" arm64 "%FSRING_MATRIX_CLIPPY% --locked --all-targets --target aarch64-pc-windows-msvc -- -D warnings"
if errorlevel 1 (echo CLIPPY FAILED: aarch64 & set "FAILED=1")

call "%SCRIPTS%_in_devenv.cmd" amd64 "%FSRING_MATRIX_CLIPPY% --locked -p fsring-core --all-targets -- -D warnings"
if errorlevel 1 (echo CLIPPY FAILED: fsring-core & set "FAILED=1")

echo.
echo === fsring-core host proofs ===
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%verify_c2_clearance_boundary.ps1"
if errorlevel 1 (echo C2 CLEARANCE BOUNDARY PROOF FAILED & set "FAILED=1")
call "%SCRIPTS%_in_devenv.cmd" amd64 "cargo test --locked -p fsring-core"
if errorlevel 1 (echo CORE TESTS FAILED & set "FAILED=1")
call :c4_note_launch git-bash
"%FSRING_BASH%" "%SCRIPTS%compile_fail.sh"
if errorlevel 1 (echo COMPILE-FAIL PROOFS FAILED & set "FAILED=1")

echo.
call :check_package_inputs
if errorlevel 1 (echo PACKAGE INPUT IDENTITY FAILED: final matrix exit & set "FAILED=1")
call :check_lock "at final matrix exit"
if errorlevel 1 set "FAILED=1"
if "%FAILED%"=="0" (echo MATRIX: PASS & exit /b 0) else (echo MATRIX: FAIL & exit /b 1)

:negative
rem %1 label, %2 required message substring, %3 arch, %4 quoted command
set /a NEG+=1
set "OUT=%TEMP%\fsring_negative_%NEG%.txt"
call "%SCRIPTS%_in_devenv.cmd" %3 %4 > "%OUT%" 2>&1
set "RC=%ERRORLEVEL%"
if "%RC%"=="0" (
  echo negative FAILED: %~1 -- build succeeded, expected a compile_error
  set "FAILED=1"
  exit /b 0
)
findstr /C:%2 "%OUT%" >nul
if errorlevel 1 (
  echo negative FAILED: %~1 -- exited %RC% but no line contained %2
  type "%OUT%"
  set "FAILED=1"
  exit /b 0
)
echo negative ok: %~1
exit /b 0

:reject_ambient_build_environment
setlocal
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "& { $exact = @('CARGO','RUSTC','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC_BOOTSTRAP','RUSTFLAGS','RUSTDOC','RUSTDOCFLAGS','RUSTUP_HOME','RUSTUP_TOOLCHAIN','BINDGEN_EXTRA_CLANG_ARGS','CC','CXX','AR','RANLIB','CFLAGS','CXXFLAGS','CL','_CL_','LINK','_LINK_'); $bad = @(Get-ChildItem Env: | Where-Object { $n = $_.Name.ToUpperInvariant(); -not [string]::IsNullOrEmpty($_.Value) -and ($exact -contains $n -or $n.StartsWith('CARGO_',[StringComparison]::Ordinal) -or $n -match '^(?:CC|CXX|AR|RANLIB|CFLAGS|CXXFLAGS|BINDGEN_EXTRA_CLANG_ARGS)_.+$') }); if ($bad.Count -ne 0) { [Console]::Error.WriteLine('uncontrolled environment: ' + (($bad | ForEach-Object Name | Sort-Object) -join ',')); exit 1 }; exit 0 }"
exit /b %ERRORLEVEL%

:validate_cargo_configuration
setlocal
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
if errorlevel 1 exit /b 1
set "FSRING_R2_PACKAGE_CWD=%DRIVER%\fsring-fsd"
set "FSRING_R2_EXPECTED_CONFIG=%FSRING_LOCKED_CARGO_CONFIG%"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -ExecutionPolicy Bypass -File "%FSRING_NATIVE_DIRECTORY_GATE%" -Mode CheckConfig
if errorlevel 1 exit /b 1
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
exit /b %ERRORLEVEL%

:create_fresh_native_directory
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
if errorlevel 1 exit /b 1
set "FSRING_R2_DRIVER_ROOT=%DRIVER%"
set "FSRING_R2_CREATED_TARGET="
set "FSRING_R2_CREATED_PARENT="
set "FSRING_R2_CREATED_RUN="
call :c4_note_launch powershell
for /f "usebackq tokens=1-3 delims=|" %%A in (`call "%FSRING_C4_PS%" -NoProfile -ExecutionPolicy Bypass -File "%FSRING_NATIVE_DIRECTORY_GATE%" -Mode CreateRun`) do (
  set "FSRING_R2_CREATED_TARGET=%%A"
  set "FSRING_R2_CREATED_PARENT=%%B"
  set "FSRING_R2_CREATED_RUN=%%C"
)
if not defined FSRING_R2_CREATED_RUN exit /b 1
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
if errorlevel 1 exit /b 1
set "FSRING_CONTROLLED_TARGET_DIR=%FSRING_R2_CREATED_TARGET%"
set "FSRING_GENERATED_TOOLS_PARENT=%FSRING_R2_CREATED_PARENT%"
set "%~1=%FSRING_R2_CREATED_RUN%"
for %%I in ("%FSRING_R2_CREATED_RUN%") do set "R2_RUN_ID=%%~nxI"
exit /b 0

:check_native_app_directory
setlocal
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
if errorlevel 1 exit /b 1
set "FSRING_R2_ALLOWED_NAMES=cargo.exe;cargo.pdb;cargo-wdk.exe"
if defined FSRING_NATIVE_ALLOWED_EVIDENCE set "FSRING_R2_ALLOWED_NAMES=%FSRING_R2_ALLOWED_NAMES%;%FSRING_NATIVE_ALLOWED_EVIDENCE%"
set "FSRING_R2_REQUIRED_NAMES=cargo.exe;cargo-wdk.exe"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -ExecutionPolicy Bypass -File "%FSRING_NATIVE_DIRECTORY_GATE%" -Mode Check -Directory "%FSRING_LOCKED_CARGO_DIR%"
if errorlevel 1 exit /b 1
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
exit /b %ERRORLEVEL%

:c4_require_frozen_clippy
rem Under the gate the frozen cargo-clippy payload is not optional.
rem Without this refusal, deleting the launcher line that names it would be
rem SILENT: the child PATH puts the 1.82.0 toolchain bin ahead of 1.85.0 and
rem it carries its own cargo-clippy.exe, so a bare cargo clippy still lints
rem and still exits 0 -- just not with the binary the gate leased and
rem re-hashed.
rem
rem Keyed on FSRING_C4_COMMAND_ID, NOT on the marker nonce. This file
rem deliberately deletes the nonce before re-entering itself (see the
rem wrapper at the top of this file), so a nonce-keyed guard in the
rem re-entered body never fires -- which is exactly what the first version
rem of this check did. The command id survives, as that wrapper states.
rem
rem A real subroutine so the self-test calls THIS code, not a copy of it.
rem
rem TWO refusals, because supplying the payload and LAUNCHING it are different
rem facts and only the first was ever checked. The gate leases this exact file,
rem hashes it before and after, and lists it in the row's nested-tool map -- but
rem the map is built from what was SUPPLIED, and the marker's launchCounts are
rem emitted empty, so no sealed byte said the matrix ran it. Deleting the
rem `set FSRING_MATRIX_CLIPPY=` line above would leave the payload supplied,
rem unused, and this run green. The second refusal compares the command that is
rem about to run against the leased path.
rem
rem Quotes are stripped from BOTH sides before the comparison. The launcher
rem value carries them and cmd's IF does not compare embedded quotes reliably;
rem stripping only the launcher side would make the check depend on the gate
rem supplying an unquoted payload path, which is true today and is not this
rem subroutine's to assume. The comparison runs inside SETLOCAL so no new name
rem reaches any child -- the gate validates the closed FSRING_C4_* set a child
rem sees.
if not defined FSRING_C4_COMMAND_ID exit /b 0
if not defined FSRING_C4_TOOL_CARGO_CLIPPY_1_85_0 (
  echo CLIPPY REFUSED: the gate supplied no frozen cargo-clippy payload
  exit /b 2
)
setlocal
set CLIPPY_LAUNCHED=%FSRING_MATRIX_CLIPPY:"=%
set CLIPPY_PAYLOAD=%FSRING_C4_TOOL_CARGO_CLIPPY_1_85_0:"=%
set CLIPPY_LEASED=%CLIPPY_PAYLOAD% clippy
if /I "%CLIPPY_LAUNCHED%"=="%CLIPPY_LEASED%" (
  endlocal
  exit /b 0
)
endlocal
echo CLIPPY REFUSED: the matrix clippy command does not name the frozen payload
exit /b 2

:check_empty_native_app_directory
setlocal
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
if errorlevel 1 exit /b 1
set "FSRING_R2_ALLOWED_NAMES="
set "FSRING_R2_REQUIRED_NAMES="
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -ExecutionPolicy Bypass -File "%FSRING_NATIVE_DIRECTORY_GATE%" -Mode Check -Directory "%FSRING_LOCKED_CARGO_DIR%"
if errorlevel 1 exit /b 1
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
exit /b %ERRORLEVEL%

:check_rustup_selector_directory
setlocal
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
if errorlevel 1 exit /b 1
set "FSRING_R2_ALLOWED_NAMES=cargo.exe;rustc.exe"
set "FSRING_R2_REQUIRED_NAMES=cargo.exe;rustc.exe"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -ExecutionPolicy Bypass -File "%FSRING_NATIVE_DIRECTORY_GATE%" -Mode Check -Directory "%FSRING_RUSTUP_SELECTOR_DIR%"
if errorlevel 1 exit /b 1
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
exit /b %ERRORLEVEL%

:check_empty_rustup_selector_directory
setlocal
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
if errorlevel 1 exit /b 1
set "FSRING_R2_ALLOWED_NAMES="
set "FSRING_R2_REQUIRED_NAMES="
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -ExecutionPolicy Bypass -File "%FSRING_NATIVE_DIRECTORY_GATE%" -Mode Check -Directory "%FSRING_RUSTUP_SELECTOR_DIR%"
if errorlevel 1 exit /b 1
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
exit /b %ERRORLEVEL%

:prepare_rustup_selector_proxies
call :check_empty_rustup_selector_directory
if errorlevel 1 exit /b 1
call :check_native_identity File "%FSRING_RUSTUP_PROXY_SOURCE%"
if errorlevel 1 exit /b 1
call :check_file_hash "%FSRING_RUSTUP_PROXY_SOURCE%" "%RUSTUP_PROXY_SOURCE_HASH%"
if errorlevel 1 exit /b 1
set "FSRING_R2_PROXY_COPY_SOURCE=%FSRING_RUSTUP_PROXY_SOURCE%"
set "FSRING_R2_PROXY_COPY_CARGO=%FSRING_REAL_CARGO%"
set "FSRING_R2_PROXY_COPY_RUSTC=%RUSTC_PROXY%"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "& { try { [IO.File]::Copy($env:FSRING_R2_PROXY_COPY_SOURCE,$env:FSRING_R2_PROXY_COPY_CARGO,$false); [IO.File]::Copy($env:FSRING_R2_PROXY_COPY_SOURCE,$env:FSRING_R2_PROXY_COPY_RUSTC,$false); exit 0 } catch { [Console]::Error.WriteLine('RUSTUP-SELECTOR: FAIL: ' + $_.Exception.Message); exit 1 } }"
if errorlevel 1 exit /b 1
call :check_native_identity File "%FSRING_RUSTUP_PROXY_SOURCE%"
if errorlevel 1 exit /b 1
call :check_file_hash "%FSRING_RUSTUP_PROXY_SOURCE%" "%RUSTUP_PROXY_SOURCE_HASH%"
if errorlevel 1 exit /b 1
call :check_native_identity File "%FSRING_REAL_CARGO%"
if errorlevel 1 exit /b 1
call :check_file_hash "%FSRING_REAL_CARGO%" "%RUSTUP_PROXY_SOURCE_HASH%"
if errorlevel 1 exit /b 1
call :check_native_identity File "%RUSTC_PROXY%"
if errorlevel 1 exit /b 1
call :check_file_hash "%RUSTC_PROXY%" "%RUSTUP_PROXY_SOURCE_HASH%"
if errorlevel 1 exit /b 1
call :check_rustup_selector_directory
if errorlevel 1 exit /b 1
set "RUSTC_PROXY_HASH=%RUSTUP_PROXY_SOURCE_HASH%"
exit /b 0

:check_security_helpers
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
if errorlevel 1 exit /b 1
call :check_file_hash "%FSRING_ATTESTATION_VERIFIER%" "%ATTESTATION_VERIFIER_HASH%"
exit /b %ERRORLEVEL%

:check_cargo_config
call :validate_cargo_configuration
if errorlevel 1 exit /b 1
call :check_file_hash "%FSRING_LOCKED_CARGO_CONFIG%" "%CONFIG_HASH%"
exit /b %ERRORLEVEL%

:check_locked_metadata
call :check_security_helpers
if errorlevel 1 exit /b 1
call :check_cargo_config
if errorlevel 1 exit /b 1
call :check_rustup_selector_directory
if errorlevel 1 exit /b 1
call :check_native_identity File "%FSRING_RUSTUP_PROXY_SOURCE%"
if errorlevel 1 exit /b 1
call :check_file_hash "%FSRING_RUSTUP_PROXY_SOURCE%" "%RUSTUP_PROXY_SOURCE_HASH%"
if errorlevel 1 exit /b 1
call :check_real_cargo "%FSRING_REAL_CARGO%" "%REAL_CARGO_HASH%"
if errorlevel 1 exit /b 1
call :check_rustc_candidate "%FSRING_RUSTC%" "%RUSTC_HASH%"
if errorlevel 1 exit /b 1
call :check_toolchain_cargo "%FSRING_TOOLCHAIN_CARGO%" "%TOOLCHAIN_CARGO_HASH%"
if errorlevel 1 exit /b 1
call :check_toolchain_selection
if errorlevel 1 exit /b 1
set "FSRING_METADATA_OUTPUT=%FSRING_CONTROLLED_TARGET_DIR%\fsring-r2-metadata-%R2_RUN_ID%.json"
call "%SCRIPTS%_in_devenv.cmd" amd64 __fsring_locked_metadata__
if errorlevel 1 exit /b 1
set "FSRING_R2_METADATA_PATH=%FSRING_METADATA_OUTPUT%"
set "FSRING_R2_METADATA_TARGET=%FSRING_CONTROLLED_TARGET_DIR%"
set "FSRING_R2_METADATA_WORKSPACE=%DRIVER%"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "& { try { $item = Get-Item -LiteralPath $env:FSRING_R2_METADATA_PATH -Force; if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -le 0 -or $item.Length -gt 1048576) { throw 'metadata file' }; $json = [IO.File]::ReadAllText($item.FullName,(New-Object Text.UTF8Encoding($false,$true))) | ConvertFrom-Json; $target = [IO.Path]::GetFullPath([string] $json.target_directory); $workspace = [IO.Path]::GetFullPath([string] $json.workspace_root); if (-not [string]::Equals($target,[IO.Path]::GetFullPath($env:FSRING_R2_METADATA_TARGET),[StringComparison]::OrdinalIgnoreCase) -or -not [string]::Equals($workspace,[IO.Path]::GetFullPath($env:FSRING_R2_METADATA_WORKSPACE),[StringComparison]::OrdinalIgnoreCase)) { throw 'metadata identity' }; exit 0 } catch { [Console]::Error.WriteLine('METADATA: FAIL: ' + $_.Exception.Message); exit 1 } }"
if errorlevel 1 exit /b 1
call :check_cargo_config
exit /b %ERRORLEVEL%

:prepare_package_output
setlocal
set "FSRING_R2_PACKAGE_PATH=%~1"
set "FSRING_R2_TARGET_PATH=%FSRING_CONTROLLED_TARGET_DIR%"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "& { try { $target = [IO.Path]::GetFullPath($env:FSRING_R2_TARGET_PATH).TrimEnd('\'); $targetItem = Get-Item -LiteralPath $target -Force; if (($targetItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not [string]::Equals((Resolve-Path -LiteralPath $target).Path,$target,[StringComparison]::OrdinalIgnoreCase)) { throw 'target final path' }; $package = [IO.Path]::GetFullPath($env:FSRING_R2_PACKAGE_PATH); if (-not $package.StartsWith($target + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'package containment' }; $relative = $package.Substring($target.Length).TrimStart('\'); if ($relative -cnotmatch '^(?:x86_64-pc-windows-msvc|aarch64-pc-windows-msvc)\\release\\fsring_fsd_package$') { throw 'package shape' }; $cursor = $target; foreach ($part in $relative.Split('\')) { $cursor = Join-Path $cursor $part; if (Test-Path -LiteralPath $cursor) { $item = Get-Item -LiteralPath $cursor -Force; if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('package reparse: ' + $cursor) } } }; if (Test-Path -LiteralPath $package) { if (-not [string]::Equals((Resolve-Path -LiteralPath $package).Path,$package,[StringComparison]::OrdinalIgnoreCase)) { throw 'package final path' }; $stack = New-Object 'Collections.Generic.Stack[string]'; $stack.Push($package); while ($stack.Count -ne 0) { $directory = $stack.Pop(); foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force)) { if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('package subtree reparse: ' + $child.FullName) }; if ($child.PSIsContainer) { $stack.Push($child.FullName) } } }; Remove-Item -LiteralPath $package -Recurse -Force }; if (Test-Path -LiteralPath $package) { throw 'package removal' }; exit 0 } catch { [Console]::Error.WriteLine('PACKAGE-FRESHNESS: FAIL: ' + $_.Exception.Message); exit 1 } }"
exit /b %ERRORLEVEL%

:require_fresh_package_output
setlocal
set "FSRING_R2_PACKAGE_PATH=%~1"
set "FSRING_R2_TARGET_PATH=%FSRING_CONTROLLED_TARGET_DIR%"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "& { try { $target = [IO.Path]::GetFullPath($env:FSRING_R2_TARGET_PATH).TrimEnd('\'); $package = [IO.Path]::GetFullPath($env:FSRING_R2_PACKAGE_PATH); if (-not $package.StartsWith($target + '\',[StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $package -PathType Container)) { throw 'package absent/escaped' }; $item = Get-Item -LiteralPath $package -Force; if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'package reparse' }; $resolved = (Resolve-Path -LiteralPath $package).Path; if (-not [string]::Equals($resolved,$package,[StringComparison]::OrdinalIgnoreCase)) { throw 'package final path' }; exit 0 } catch { [Console]::Error.WriteLine('PACKAGE-FRESHNESS: FAIL: ' + $_.Exception.Message); exit 1 } }"
exit /b %ERRORLEVEL%

:resolve_on_path
set "%~2="
for /f "delims=" %%I in ('where.exe "%~1" 2^>nul') do if not defined %~2 set "%~2=%%~fI"
exit /b 0

:resolve_rustup_proxy_source
rem PATH first, so an ordinary developer run resolves exactly as it always
rem has. Under the C4 source gate the closed child PATH deliberately excludes
rem the Cargo-home bin directory, and that exclusion is a sealed property: it
rem exists so no helper can resolve `cargo` or `rustc` by BARE NAME to a
rem rustup proxy, which is what made a `+1.85.0` selector row exit 101.
rem
rem Naming the proxy by its absolute path does not reopen that. Nothing here
rem is resolved by bare name, and the file goes through the same
rem require_absolute_file / check_native_identity / hash_file chain by either
rem route. It is the same move this file already makes for the Rustup HOME,
rem which :resolve_exact_rustup_home reads from %%USERPROFILE%%\.rustup.
set "%~1="
call :resolve_on_path rustup.exe %~1
if defined %~1 exit /b 0
if not defined USERPROFILE exit /b 0
if exist "%USERPROFILE%\.cargo\bin\rustup.exe" set "%~1=%USERPROFILE%\.cargo\bin\rustup.exe"
exit /b 0

:resolve_cargo_wdk_source
rem The frozen payload FIRST. `cargo-wdk-0.1.1` is one of the C4 source
rem gate's twenty frozen roles: the gate resolves it, holds it open under a
rem deny-write lease, and :c4_verify_frozen_roles re-hashes it against the
rem frozen SHA-256 before this file runs anything. Preferring a PATH copy
rem over that would resolve by bare name a payload already pinned by handle.
rem
rem Then PATH, so an ordinary developer run resolves as it always has, and
rem last the conventional absolute location -- the gate's closed child PATH
rem excludes the Cargo-home bin directory by design.
set "%~1="
if defined FSRING_C4_TOOL_CARGO_WDK_0_1_1 (
  set "%~1=%FSRING_C4_TOOL_CARGO_WDK_0_1_1%"
  exit /b 0
)
call :resolve_on_path cargo-wdk.exe %~1
if defined %~1 exit /b 0
if not defined USERPROFILE exit /b 0
if exist "%USERPROFILE%\.cargo\bin\cargo-wdk.exe" set "%~1=%USERPROFILE%\.cargo\bin\cargo-wdk.exe"
exit /b 0

:require_absolute_file
setlocal
set "FSRING_R2_PATH=%~1"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "if (-not [IO.Path]::IsPathRooted($env:FSRING_R2_PATH) -or -not (Test-Path -LiteralPath $env:FSRING_R2_PATH -PathType Leaf)) { exit 1 }"
exit /b %ERRORLEVEL%

:check_real_cargo
setlocal
set "FSRING_R2_EXE=%~1"
call :check_rustup_selector_directory
if errorlevel 1 exit /b 1
call :check_native_identity File "%~1"
if errorlevel 1 exit /b 1
call :check_file_hash "%~1" "%~2"
if errorlevel 1 exit /b 1
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "$o = @(& $env:FSRING_R2_EXE +1.85.0 --version 2>$null); if ($LASTEXITCODE -ne 0 -or $o.Count -ne 1 -or $o[0] -cne 'cargo 1.85.0 (d73d2caf9 2024-12-31)') { exit 1 }"
if errorlevel 1 exit /b 1
call :check_file_hash "%~1" "%~2"
if errorlevel 1 exit /b 1
call :check_native_identity File "%~1"
exit /b %ERRORLEVEL%

:resolve_exact_rustc
setlocal
set "FSRING_R2_RUSTC_PROXY=%~1"
set "FSRING_R2_EXACT_RUSTC="
call :check_rustup_selector_directory
if errorlevel 1 exit /b 1
call :check_native_identity File "%~1"
if errorlevel 1 exit /b 1
call :check_file_hash "%~1" "%RUSTC_PROXY_HASH%"
if errorlevel 1 exit /b 1
call :c4_note_launch powershell
for /f "usebackq delims=" %%I in (`call "%FSRING_C4_PS%" -NoProfile -Command "$o = @(& $env:FSRING_R2_RUSTC_PROXY +1.85.0 --print sysroot 2>$null); if ($LASTEXITCODE -ne 0 -or $o.Count -ne 1) { exit 1 }; $p = Join-Path $o[0] 'bin\rustc.exe'; if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { exit 1 }; (Resolve-Path -LiteralPath $p).Path" 2^>nul`) do set "FSRING_R2_EXACT_RUSTC=%%I"
call :check_file_hash "%~1" "%RUSTC_PROXY_HASH%"
if errorlevel 1 exit /b 1
call :check_native_identity File "%~1"
if errorlevel 1 exit /b 1
endlocal & set "%~2=%FSRING_R2_EXACT_RUSTC%" & exit /b 0

:resolve_exact_rustup_home
setlocal
set "FSRING_R2_SELECTED_RUSTC=%~1"
set "FSRING_R2_RUSTUP_HOME="
call :c4_note_launch powershell
for /f "usebackq delims=" %%I in (`call "%FSRING_C4_PS%" -NoProfile -Command "& { try { $rustupRoot = (Resolve-Path -LiteralPath (Join-Path $env:USERPROFILE '.rustup')).Path.TrimEnd('\'); $item = Get-Item -LiteralPath $rustupRoot -Force; if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'rustup home reparse' }; $rustc = (Resolve-Path -LiteralPath $env:FSRING_R2_SELECTED_RUSTC).Path; $expected = Join-Path $rustupRoot 'toolchains\1.85.0-x86_64-pc-windows-msvc\bin\rustc.exe'; if (-not [string]::Equals($rustc,$expected,[StringComparison]::OrdinalIgnoreCase)) { throw 'toolchain selector' }; $rustupRoot } catch { exit 1 } }" 2^>nul`) do set "FSRING_R2_RUSTUP_HOME=%%I"
endlocal & set "%~2=%FSRING_R2_RUSTUP_HOME%" & exit /b 0

:check_rustc_candidate
setlocal
set "FSRING_R2_RUSTC_PATH=%~1"
set "FSRING_R2_RUSTC_HASH=%~2"
call :check_native_identity File "%~1"
if errorlevel 1 exit /b 1
call :check_file_hash "%~1" "%~2"
if errorlevel 1 exit /b 1
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "$o = @(& $env:FSRING_R2_RUSTC_PATH --version 2>$null); if ($LASTEXITCODE -ne 0 -or $o.Count -ne 1 -or $o[0] -cne 'rustc 1.85.0 (4d91de4e4 2025-02-17)') { exit 1 }; $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $env:FSRING_R2_RUSTC_PATH).Hash.ToUpperInvariant(); if ($h -cne $env:FSRING_R2_RUSTC_HASH) { exit 1 }"
if errorlevel 1 exit /b 1
call :check_native_identity File "%~1"
exit /b %ERRORLEVEL%

:check_toolchain_cargo
setlocal
set "FSRING_R2_TOOLCHAIN_CARGO_PATH=%~1"
set "FSRING_R2_TOOLCHAIN_CARGO_HASH=%~2"
call :check_native_identity File "%~1"
if errorlevel 1 exit /b 1
call :check_file_hash "%~1" "%~2"
if errorlevel 1 exit /b 1
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "$o = @(& $env:FSRING_R2_TOOLCHAIN_CARGO_PATH --version 2>$null); if ($LASTEXITCODE -ne 0 -or $o.Count -ne 1 -or $o[0] -cne 'cargo 1.85.0 (d73d2caf9 2024-12-31)') { exit 1 }; $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $env:FSRING_R2_TOOLCHAIN_CARGO_PATH).Hash.ToUpperInvariant(); if ($h -cne $env:FSRING_R2_TOOLCHAIN_CARGO_HASH) { exit 1 }"
if errorlevel 1 exit /b 1
call :check_native_identity File "%~1"
exit /b %ERRORLEVEL%

:check_toolchain_selection
setlocal
call :check_rustup_selector_directory
if errorlevel 1 exit /b 1
call :check_native_identity File "%RUSTC_PROXY%"
if errorlevel 1 exit /b 1
call :check_file_hash "%RUSTC_PROXY%" "%RUSTC_PROXY_HASH%"
if errorlevel 1 exit /b 1
call :check_native_identity File "%FSRING_RUSTC%"
if errorlevel 1 exit /b 1
call :check_native_identity File "%FSRING_TOOLCHAIN_CARGO%"
if errorlevel 1 exit /b 1
call :resolve_exact_rustup_home "%FSRING_RUSTC%" FSRING_R2_CURRENT_RUSTUP_HOME
if not defined FSRING_R2_CURRENT_RUSTUP_HOME exit /b 1
if /I not "%FSRING_R2_CURRENT_RUSTUP_HOME%"=="%FSRING_RUSTUP_HOME%" exit /b 1
call :check_native_identity Directory "%FSRING_R2_CURRENT_RUSTUP_HOME%"
if errorlevel 1 exit /b 1
for %%I in ("%FSRING_RUSTC%") do set "FSRING_R2_CURRENT_TOOLCHAIN_CARGO=%%~dpIcargo.exe"
if /I not "%FSRING_R2_CURRENT_TOOLCHAIN_CARGO%"=="%FSRING_TOOLCHAIN_CARGO%" exit /b 1
exit /b 0

:hash_file
setlocal
set "FSRING_R2_HASH_PATH=%~1"
set "FSRING_R2_HASH_VALUE="
call :c4_note_launch powershell
for /f "usebackq delims=" %%H in (`call "%FSRING_C4_PS%" -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath $env:FSRING_R2_HASH_PATH).Hash.ToUpperInvariant()" 2^>nul`) do set "FSRING_R2_HASH_VALUE=%%H"
if not defined FSRING_R2_HASH_VALUE exit /b 1
endlocal & set "%~2=%FSRING_R2_HASH_VALUE%" & exit /b 0

:check_file_hash
setlocal
call :hash_file "%~1" FSRING_R2_CURRENT_HASH
if errorlevel 1 exit /b 1
if /I not "%FSRING_R2_CURRENT_HASH%"=="%~2" exit /b 1
exit /b 0

:check_wdk_candidate
setlocal
set "FSRING_R2_WDK_PATH=%~1"
set "FSRING_R2_WDK_HASH=%~2"
call :check_native_identity File "%~1"
if errorlevel 1 exit /b 1
call :check_file_hash "%~1" "%~2"
if errorlevel 1 exit /b 1
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "$o = @(& $env:FSRING_R2_WDK_PATH --version 2>$null); if ($LASTEXITCODE -ne 0 -or $o.Count -ne 1 -or $o[0] -cne 'cargo wdk 0.1.1') { exit 1 }; $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $env:FSRING_R2_WDK_PATH).Hash.ToUpperInvariant(); if ($h -cne $env:FSRING_R2_WDK_HASH) { exit 1 }"
if errorlevel 1 exit /b 1
call :check_native_identity File "%~1"
exit /b %ERRORLEVEL%

:check_lock
call :check_file_hash "%LOCKFILE%" "%LOCK_HASH%"
if errorlevel 1 (
  echo FAIL: driver Cargo.lock changed %~1; expected SHA-256 %LOCK_HASH%.
  exit /b 1
)
echo driver Cargo.lock unchanged %~1: %LOCK_HASH%
exit /b 0

:prepare_native_shim
call :check_empty_native_app_directory
if errorlevel 1 (
  echo FAIL: fresh native application directory is not empty and closed.
  exit /b 1
)
call :hash_file "%FSRING_LOCKED_CARGO_SOURCE%" SHIM_SOURCE_HASH
if errorlevel 1 (
  echo FAIL: native locked-Cargo shim source could not be hashed.
  exit /b 1
)
call :check_rustc_candidate "%FSRING_RUSTC%" "%RUSTC_HASH%"
if errorlevel 1 (
  echo FAIL: exact rustc changed before native shim compilation.
  exit /b 1
)
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
if errorlevel 1 (
  echo FAIL: tracked native-directory gate changed before SHA-256 tests.
  exit /b 1
)
call "%SCRIPTS%_in_devenv.cmd" amd64 __fsring_test_locked_cargo_sha256__
if errorlevel 1 (
  echo FAIL: dependency-free native SHA-256 unit tests failed.
  exit /b 1
)
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
if errorlevel 1 (
  echo FAIL: tracked native-directory gate changed during SHA-256 tests.
  exit /b 1
)
call :check_file_hash "%FSRING_LOCKED_CARGO_SOURCE%" "%SHIM_SOURCE_HASH%"
if errorlevel 1 (
  echo FAIL: native locked-Cargo shim source changed during SHA-256 tests.
  exit /b 1
)
call :check_rustc_candidate "%FSRING_RUSTC%" "%RUSTC_HASH%"
if errorlevel 1 (
  echo FAIL: exact rustc changed during native SHA-256 tests.
  exit /b 1
)
if exist "%FSRING_LOCKED_CARGO_TEST_EXE%" del /f /q "%FSRING_LOCKED_CARGO_TEST_EXE%" >nul 2>&1
if exist "%FSRING_LOCKED_CARGO_TEST_PDB%" del /f /q "%FSRING_LOCKED_CARGO_TEST_PDB%" >nul 2>&1
if exist "%FSRING_LOCKED_CARGO_TEST_EXE%" (
  echo FAIL: native SHA-256 test executable could not be removed from the fresh app directory.
  exit /b 1
)
if exist "%FSRING_LOCKED_CARGO_TEST_PDB%" (
  echo FAIL: native SHA-256 test PDB could not be removed from the fresh app directory.
  exit /b 1
)
call :check_empty_native_app_directory
if errorlevel 1 (
  echo FAIL: native SHA-256 tests left an unapproved app-local launch input.
  exit /b 1
)
call "%SCRIPTS%_in_devenv.cmd" amd64 __fsring_compile_locked_cargo__
if errorlevel 1 (
  echo FAIL: native locked-Cargo shim compilation failed.
  exit /b 1
)
call :check_file_hash "%FSRING_LOCKED_CARGO_SOURCE%" "%SHIM_SOURCE_HASH%"
if errorlevel 1 (
  echo FAIL: native locked-Cargo shim source changed during compilation.
  exit /b 1
)
call :check_rustc_candidate "%FSRING_RUSTC%" "%RUSTC_HASH%"
if errorlevel 1 (
  echo FAIL: exact rustc changed during native shim compilation.
  exit /b 1
)
call :require_absolute_file "%FSRING_LOCKED_CARGO_EXE%"
if errorlevel 1 (
  echo FAIL: generated native cargo.exe is missing or not absolute.
  exit /b 1
)
call :hash_file "%FSRING_LOCKED_CARGO_EXE%" SHIM_EXE_HASH
if errorlevel 1 (
  echo FAIL: generated native cargo.exe could not be hashed.
  exit /b 1
)
call :check_native_identity File "%FSRING_CARGO_WDK_SOURCE%"
if errorlevel 1 (
  echo FAIL: resolved cargo-wdk source native identity changed before launch-copy preparation.
  exit /b 1
)
call :check_file_hash "%FSRING_CARGO_WDK_SOURCE%" "%WDK_HASH%"
if errorlevel 1 (
  echo FAIL: resolved cargo-wdk source changed before launch-copy preparation.
  exit /b 1
)
set "FSRING_R2_WDK_COPY_SOURCE=%FSRING_CARGO_WDK_SOURCE%"
set "FSRING_R2_WDK_COPY_DESTINATION=%FSRING_CARGO_WDK_LAUNCH%"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "[IO.File]::Copy($env:FSRING_R2_WDK_COPY_SOURCE, $env:FSRING_R2_WDK_COPY_DESTINATION, $false)"
if errorlevel 1 (
  echo FAIL: byte-identical cargo-wdk launch copy could not be prepared.
  exit /b 1
)
set "FSRING_CARGO_WDK=%FSRING_CARGO_WDK_LAUNCH%"
call :check_file_hash "%FSRING_CARGO_WDK_SOURCE%" "%WDK_HASH%"
if errorlevel 1 (
  echo FAIL: resolved cargo-wdk source changed during launch-copy preparation.
  exit /b 1
)
call :check_native_identity File "%FSRING_CARGO_WDK_SOURCE%"
if errorlevel 1 (
  echo FAIL: resolved cargo-wdk source native identity changed during launch-copy preparation.
  exit /b 1
)
call :check_native_app_directory
if errorlevel 1 (
  echo FAIL: native application directory contains an unapproved launch input.
  exit /b 1
)
call :check_wdk_candidate "%FSRING_CARGO_WDK%" "%WDK_HASH%"
if errorlevel 1 (
  echo FAIL: generated cargo-wdk launch copy is not byte-identical and version-exact.
  exit /b 1
)
echo native shim source SHA-256 %SHIM_SOURCE_HASH%
exit /b 0

:check_package_inputs
call :check_security_helpers
if errorlevel 1 exit /b 1
if defined LOCK_HASH call :check_file_hash "%LOCKFILE%" "%LOCK_HASH%"
if errorlevel 1 exit /b 1
call :check_native_app_directory
if errorlevel 1 exit /b 1
call :check_cargo_config
if errorlevel 1 exit /b 1
call :check_rustup_selector_directory
if errorlevel 1 exit /b 1
call :check_native_identity File "%FSRING_RUSTUP_PROXY_SOURCE%"
if errorlevel 1 exit /b 1
call :check_file_hash "%FSRING_RUSTUP_PROXY_SOURCE%" "%RUSTUP_PROXY_SOURCE_HASH%"
if errorlevel 1 exit /b 1
call :check_native_identity File "%FSRING_RUSTUP_PROXY_SOURCE%"
if errorlevel 1 exit /b 1
call :check_native_identity File "%RUSTC_PROXY%"
if errorlevel 1 exit /b 1
call :check_file_hash "%RUSTC_PROXY%" "%RUSTC_PROXY_HASH%"
if errorlevel 1 exit /b 1
call :check_real_cargo "%FSRING_REAL_CARGO%" "%REAL_CARGO_HASH%"
if errorlevel 1 exit /b 1
call :check_rustc_candidate "%FSRING_RUSTC%" "%RUSTC_HASH%"
if errorlevel 1 exit /b 1
call :check_toolchain_cargo "%FSRING_TOOLCHAIN_CARGO%" "%TOOLCHAIN_CARGO_HASH%"
if errorlevel 1 exit /b 1
call :check_toolchain_selection
if errorlevel 1 exit /b 1
call :check_native_identity Directory "%FSRING_RUSTUP_HOME%"
if errorlevel 1 exit /b 1
call :check_native_identity File "%FSRING_CARGO_WDK_SOURCE%"
if errorlevel 1 exit /b 1
call :check_file_hash "%FSRING_CARGO_WDK_SOURCE%" "%WDK_HASH%"
if errorlevel 1 exit /b 1
call :check_native_identity File "%FSRING_CARGO_WDK_SOURCE%"
if errorlevel 1 exit /b 1
call :check_wdk_candidate "%FSRING_CARGO_WDK%" "%WDK_HASH%"
if errorlevel 1 exit /b 1
call :check_file_hash "%FSRING_LOCKED_CARGO_EXE%" "%SHIM_EXE_HASH%"
if errorlevel 1 exit /b 1
exit /b 0

:prepare_build_attestation
call :clear_attestation_environment
call :check_native_app_directory
if errorlevel 1 exit /b 1
set "FSRING_LOCKED_CARGO_ATTESTATION=%~1"
set "FSRING_ATTESTATION_KIND=%~2"
set "FSRING_R2_ATTESTATION_ROOT=%FSRING_LOCKED_CARGO_DIR%"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "$p = [IO.Path]::GetFullPath($env:FSRING_LOCKED_CARGO_ATTESTATION); $r = [IO.Path]::GetFullPath($env:FSRING_R2_ATTESTATION_ROOT); if (-not [IO.Path]::IsPathRooted($p) -or -not [string]::Equals([IO.Path]::GetDirectoryName($p), $r, [StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $p)) { exit 1 }"
if errorlevel 1 (
  call :clear_attestation_environment
  exit /b 1
)
set "FSRING_LOCKED_CARGO_NONCE="
call :c4_note_launch powershell
for /f "usebackq delims=" %%N in (`call "%FSRING_C4_PS%" -NoProfile -Command "[Guid]::NewGuid().ToString('N').ToUpperInvariant()"`) do set "FSRING_LOCKED_CARGO_NONCE=%%N"
if not defined FSRING_LOCKED_CARGO_NONCE (
  call :clear_attestation_environment
  exit /b 1
)
if exist "%FSRING_LOCKED_CARGO_ATTESTATION%" (
  call :clear_attestation_environment
  exit /b 1
)
exit /b 0

:verify_attestation
call :check_file_hash "%FSRING_ATTESTATION_VERIFIER%" "%ATTESTATION_VERIFIER_HASH%"
if errorlevel 1 exit /b 1
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -ExecutionPolicy Bypass -File "%FSRING_ATTESTATION_VERIFIER%"
set "FSRING_R2_ATTESTATION_RC=%ERRORLEVEL%"
call :check_file_hash "%FSRING_ATTESTATION_VERIFIER%" "%ATTESTATION_VERIFIER_HASH%"
if errorlevel 1 exit /b 1
exit /b %FSRING_R2_ATTESTATION_RC%

:clear_attestation_environment
set "FSRING_LOCKED_CARGO_ATTESTATION="
set "FSRING_LOCKED_CARGO_NONCE="
set "FSRING_ATTESTATION_KIND="
exit /b 0

:R2_SELF_TEST
setlocal EnableDelayedExpansion
set "SCRIPTS=%~dp0"
call :c4_selftest_launch_coverage
if errorlevel 1 exit /b 1
call :c4_note_launch python
"%FSRING_C4_PY%" "%~dp0audit_c4_imports.py" --self-test
if errorlevel 1 (
  echo FAIL: audit_c4_imports self-test failed.
  exit /b 1
)
call :c4_note_launch python
"%FSRING_C4_PY%" "%~dp0audit_c4_stack.py" --self-test
if errorlevel 1 (
  echo FAIL: audit_c4_stack self-test failed.
  exit /b 1
)
call :c4_note_launch python
"%FSRING_C4_PY%" "%~dp0audit_c4_lifetime.py" --self-test
if errorlevel 1 (
  echo FAIL: audit_c4_lifetime self-test failed.
  exit /b 1
)
for %%I in ("%~dp0..") do set "DRIVER=%%~fI"
set "LOCKFILE=!DRIVER!\Cargo.lock"
set "FSRING_LOCKED_CARGO_SOURCE=!SCRIPTS!locked-cargo\cargo_shim.rs"
set "FSRING_ATTESTATION_VERIFIER=!SCRIPTS!locked-cargo\verify_attestation.ps1"
set "FSRING_NATIVE_DIRECTORY_GATE=!SCRIPTS!locked-cargo\native_directory_gate.ps1"
set "FSRING_LOCKED_CARGO_CONFIG=!DRIVER!\.cargo\config.toml"
set "FSRING_GENERATED_TOOLS_PARENT=!DRIVER!\target\fsring-generated-tools"
call :hash_file "!FSRING_ATTESTATION_VERIFIER!" ATTESTATION_VERIFIER_HASH
if errorlevel 1 (
  echo SELF-TEST: FAIL: attestation verifier could not be hashed
  exit /b 1
)
call :hash_file "!FSRING_NATIVE_DIRECTORY_GATE!" NATIVE_DIRECTORY_GATE_HASH
if errorlevel 1 (
  echo SELF-TEST: FAIL: native-directory gate could not be hashed
  exit /b 1
)
call :create_fresh_native_directory FSRING_RUSTUP_SELECTOR_DIR
if errorlevel 1 (
  echo SELF-TEST: FAIL: fresh Rustup-selector directory could not be created
  exit /b 1
)
set "FSRING_REAL_CARGO=!FSRING_RUSTUP_SELECTOR_DIR!\cargo.exe"
set "RUSTC_PROXY=!FSRING_RUSTUP_SELECTOR_DIR!\rustc.exe"
call :create_fresh_native_directory FSRING_LOCKED_CARGO_DIR
if errorlevel 1 (
  echo SELF-TEST: FAIL: fresh native application directory could not be created
  exit /b 1
)
if /I "!FSRING_RUSTUP_SELECTOR_DIR!"=="!FSRING_LOCKED_CARGO_DIR!" (
  echo SELF-TEST: FAIL: Rustup selector and cargo-wdk application directories were reused
  exit /b 1
)
set "FSRING_LOCKED_CARGO_EXE=!FSRING_LOCKED_CARGO_DIR!\cargo.exe"
set "FSRING_LOCKED_CARGO_TEST_EXE=!FSRING_LOCKED_CARGO_DIR!\sha256-tests.exe"
set "FSRING_LOCKED_CARGO_TEST_PDB=!FSRING_LOCKED_CARGO_DIR!\sha256-tests.pdb"
set "FSRING_CARGO_WDK_LAUNCH=!FSRING_LOCKED_CARGO_DIR!\cargo-wdk.exe"
set "EXPECTED_CARGO_VERSION=cargo 1.85.0 (d73d2caf9 2024-12-31)"
set "EXPECTED_WDK_VERSION=cargo wdk 0.1.1"
set "EXPECTED_RUSTC_VERSION=rustc 1.85.0 (4d91de4e4 2025-02-17)"
set "R2_ZERO_HASH=0000000000000000000000000000000000000000000000000000000000000000"

call :self_test_build_environment
if errorlevel 1 exit /b 1
set "CARGO_NET_OFFLINE=true"
call :validate_cargo_configuration
if errorlevel 1 (
  echo SELF-TEST: FAIL: Cargo configuration discovery is not closed
  exit /b 1
)
call :hash_file "!FSRING_LOCKED_CARGO_CONFIG!" CONFIG_HASH
if errorlevel 1 (
  echo SELF-TEST: FAIL: tracked Cargo config fixture could not be hashed
  exit /b 1
)
call :self_test_fresh_native_directories
if errorlevel 1 exit /b 1

call :resolve_rustup_proxy_source FSRING_RUSTUP_PROXY_SOURCE
call :require_absolute_file "!FSRING_RUSTUP_PROXY_SOURCE!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: exact Rustup proxy source fixture is unavailable
  exit /b 1
)
call :check_native_identity File "!FSRING_RUSTUP_PROXY_SOURCE!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: exact Rustup proxy source native identity is unavailable
  exit /b 1
)
call :hash_file "!FSRING_RUSTUP_PROXY_SOURCE!" RUSTUP_PROXY_SOURCE_HASH
if errorlevel 1 (
  echo SELF-TEST: FAIL: exact Rustup proxy source fixture could not be hashed
  exit /b 1
)
set "FSRING_RUSTUP_PROXY_SOURCE_SHA256=!RUSTUP_PROXY_SOURCE_HASH!"
call :prepare_rustup_selector_proxies
if errorlevel 1 (
  echo SELF-TEST: FAIL: fresh native Cargo/rustc selector fixtures could not be prepared
  exit /b 1
)
set "FSRING_RUSTUP_SELECTOR_RUSTC=!RUSTC_PROXY!"
set "FSRING_RUSTUP_SELECTOR_RUSTC_SHA256=!RUSTC_PROXY_HASH!"
call :hash_file "!FSRING_REAL_CARGO!" REAL_CARGO_HASH
set "FSRING_REAL_CARGO_SHA256=!REAL_CARGO_HASH!"
call :check_real_cargo "!FSRING_REAL_CARGO!" "!REAL_CARGO_HASH!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: exact real Cargo fixture did not validate
  exit /b 1
)
set "R2_REAL_CARGO=!FSRING_REAL_CARGO!"

call :resolve_cargo_wdk_source FSRING_CARGO_WDK_SOURCE
call :require_absolute_file "!FSRING_CARGO_WDK_SOURCE!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: exact cargo-wdk fixture is unavailable
  exit /b 1
)
call :check_native_identity File "!FSRING_CARGO_WDK_SOURCE!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: exact cargo-wdk native identity is unavailable
  exit /b 1
)
call :hash_file "!FSRING_CARGO_WDK_SOURCE!" WDK_HASH
call :check_file_hash "!FSRING_CARGO_WDK_SOURCE!" "!R2_ZERO_HASH!" >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: changed cargo-wdk hash was accepted
  exit /b 1
)
echo self-test ok: changed cargo-wdk hash rejects

call :check_file_hash "!LOCKFILE!" "!R2_ZERO_HASH!" >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: changed lockfile hash was accepted
  exit /b 1
)
echo self-test ok: changed lockfile hash rejects

set "R2_RUSTC_PROXY=!RUSTC_PROXY!"
call :require_absolute_file "!R2_RUSTC_PROXY!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: rustc selector proxy fixture is unavailable
  exit /b 1
)
call :check_native_identity File "!R2_RUSTC_PROXY!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: rustc selector proxy native identity is unavailable
  exit /b 1
)
call :check_file_hash "!R2_RUSTC_PROXY!" "!RUSTC_PROXY_HASH!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: rustc selector proxy fixture hash changed
  exit /b 1
)
call :resolve_exact_rustc "!R2_RUSTC_PROXY!" FSRING_RUSTC
call :require_absolute_file "!FSRING_RUSTC!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: exact rustc fixture is unavailable
  exit /b 1
)
for %%I in ("!FSRING_RUSTC!") do set "FSRING_TOOLCHAIN_CARGO=%%~dpIcargo.exe"
call :require_absolute_file "!FSRING_TOOLCHAIN_CARGO!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: actual toolchain Cargo fixture is unavailable
  exit /b 1
)
call :resolve_exact_rustup_home "!FSRING_RUSTC!" FSRING_RUSTUP_HOME
if not defined FSRING_RUSTUP_HOME (
  echo SELF-TEST: FAIL: exact rustup selector fixture is unavailable
  exit /b 1
)
call :check_native_identity Directory "!FSRING_RUSTUP_HOME!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: exact Rustup-home native identity is unavailable
  exit /b 1
)
call :hash_file "!FSRING_RUSTC!" RUSTC_HASH
set "FSRING_RUSTC_SHA256=!RUSTC_HASH!"
call :check_rustc_candidate "!FSRING_RUSTC!" "!RUSTC_HASH!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: exact rustc fixture did not validate
  exit /b 1
)
call :check_rustc_candidate "!FSRING_RUSTC!" "!R2_ZERO_HASH!" >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: changed rustc hash was accepted
  exit /b 1
)
echo self-test ok: changed rustc hash rejects
call :hash_file "!FSRING_TOOLCHAIN_CARGO!" TOOLCHAIN_CARGO_HASH
set "FSRING_TOOLCHAIN_CARGO_SHA256=!TOOLCHAIN_CARGO_HASH!"
call :check_toolchain_cargo "!FSRING_TOOLCHAIN_CARGO!" "!TOOLCHAIN_CARGO_HASH!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: actual toolchain Cargo fixture did not validate
  exit /b 1
)
call :check_toolchain_cargo "!FSRING_TOOLCHAIN_CARGO!" "!R2_ZERO_HASH!" >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: changed actual toolchain Cargo hash was accepted
  exit /b 1
)
echo self-test ok: actual toolchain Cargo identity is exact

call :prepare_native_shim
if errorlevel 1 (
  echo SELF-TEST: FAIL: native cargo.exe could not be generated from tracked source
  exit /b 1
)
call :check_wdk_candidate "%SystemRoot%\System32\where.exe" "!WDK_HASH!" >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: wrong cargo-wdk executable/version was accepted
  exit /b 1
)
call :check_wdk_candidate "!FSRING_CARGO_WDK!" "!R2_ZERO_HASH!" >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: changed cargo-wdk launch-copy hash was accepted
  exit /b 1
)
echo self-test ok: exact fresh launch-copy cargo-wdk identity is required
call :self_test_native_app_allowlist
if errorlevel 1 exit /b 1

set "FSRING_LOCKED_CARGO_TARGET_DIR=!FSRING_CONTROLLED_TARGET_DIR!"
set "RUSTC=!FSRING_RUSTC!"
set "CARGO_TARGET_DIR=!FSRING_LOCKED_CARGO_TARGET_DIR!"
set "RUSTUP_HOME=!FSRING_RUSTUP_HOME!"
set "RUSTUP_TOOLCHAIN=1.85.0"
call "!SCRIPTS!_in_devenv.cmd" --self-test "!FSRING_LOCKED_CARGO_DIR!" "!FSRING_REAL_CARGO!" "!FSRING_LOCKED_CARGO_TARGET_DIR!" "!FSRING_RUSTC!" "!FSRING_RUSTUP_HOME!" "!FSRING_TOOLCHAIN_CARGO!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: native/ordinary PATH and metadata split
  exit /b 1
)

set "R2_SELFTEST_ROOT=!DRIVER!\target\fsring-r2-selftest\!R2_RUN_ID!"
set "FSRING_R2_SELFTEST_ROOT=!R2_SELFTEST_ROOT!"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "[IO.Directory]::CreateDirectory($env:FSRING_R2_SELFTEST_ROOT) | Out-Null"
if errorlevel 1 (
  echo SELF-TEST: FAIL: isolated self-test output root could not be created
  exit /b 1
)
call :self_test_native_tool_identities
if errorlevel 1 exit /b 1
call :self_test_selector_callsite_closure
if errorlevel 1 exit /b 1
call :check_locked_metadata
if errorlevel 1 (
  echo SELF-TEST: FAIL: package-CWD metadata did not bind the exact controlled target
  exit /b 1
)
call :self_test_package_freshness
if errorlevel 1 exit /b 1
set "R2_TEST_ATTESTATION=!FSRING_LOCKED_CARGO_DIR!\selftest-attestation.txt"
set "FSRING_LOCKED_CARGO_ATTESTATION=!R2_TEST_ATTESTATION!"
set "FSRING_LOCKED_CARGO_NONCE=SELFTEST-NONCE"
set "FSRING_LOCKED_CARGO_TOOLCHAIN=1.85.0"
set "CARGO=!FSRING_REAL_CARGO!"

set "FSRING_REAL_CARGO="
call "!FSRING_LOCKED_CARGO_EXE!" build >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim accepted absent real Cargo
  exit /b 1
)
set "FSRING_REAL_CARGO=relative\cargo.exe"
call "!FSRING_LOCKED_CARGO_EXE!" build >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim accepted non-rooted real Cargo
  exit /b 1
)
echo self-test ok: absent/non-rooted real Cargo rejects

rem Restore from the already validated path after the two rejection cases.
set "FSRING_REAL_CARGO=!R2_REAL_CARGO!"
set "FSRING_REAL_CARGO_SHA256=!REAL_CARGO_HASH!"

set "FSRING_REAL_CARGO_SHA256=not-a-sha256"
call "!FSRING_LOCKED_CARGO_EXE!" build >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim accepted malformed real-Cargo identity
  exit /b 1
)
set "FSRING_REAL_CARGO_SHA256=!R2_ZERO_HASH!"
call "!FSRING_LOCKED_CARGO_EXE!" build >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim accepted wrong real-Cargo identity
  exit /b 1
)
set "FSRING_REAL_CARGO_SHA256=!REAL_CARGO_HASH!"
set "FSRING_TOOLCHAIN_CARGO_SHA256=!R2_ZERO_HASH!"
call "!FSRING_LOCKED_CARGO_EXE!" build >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim accepted wrong actual-Cargo identity
  exit /b 1
)
set "FSRING_TOOLCHAIN_CARGO_SHA256=!TOOLCHAIN_CARGO_HASH!"
set "FSRING_RUSTC_SHA256=!R2_ZERO_HASH!"
call "!FSRING_LOCKED_CARGO_EXE!" build >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim accepted wrong rustc identity
  exit /b 1
)
set "FSRING_RUSTC_SHA256=!RUSTC_HASH!"
set "CARGO=%SystemRoot%\System32\where.exe"
call "!FSRING_LOCKED_CARGO_EXE!" build >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim accepted a substituted CARGO selector
  exit /b 1
)
set "CARGO=!FSRING_REAL_CARGO!"
set "RUSTC=%SystemRoot%\System32\where.exe"
call "!FSRING_LOCKED_CARGO_EXE!" build >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim accepted a substituted RUSTC selector
  exit /b 1
)
set "RUSTC=!FSRING_RUSTC!"
set "CARGO_TARGET_DIR=!R2_SELFTEST_ROOT!"
call "!FSRING_LOCKED_CARGO_EXE!" build >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim accepted a redirected CARGO_TARGET_DIR
  exit /b 1
)
set "CARGO_TARGET_DIR=!FSRING_LOCKED_CARGO_TARGET_DIR!"

set "FSRING_LOCKED_CARGO_TOOLCHAIN=1.84.0"
call "!FSRING_LOCKED_CARGO_EXE!" build >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim accepted wrong toolchain
  exit /b 1
)
set "FSRING_LOCKED_CARGO_TOOLCHAIN=1.85.0"

call "!FSRING_LOCKED_CARGO_EXE!" metadata >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim accepted a non-build first argument
  exit /b 1
)
echo self-test ok: malformed identities, selector substitutions, redirected target, and non-build command reject
call :self_test_native_shim_environment
if errorlevel 1 exit /b 1

set "FSRING_LOCKED_CARGO_ATTESTATION="
call "!FSRING_LOCKED_CARGO_EXE!" build >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim accepted missing attestation path
  exit /b 1
)
set "FSRING_LOCKED_CARGO_ATTESTATION=relative\attestation.txt"
call "!FSRING_LOCKED_CARGO_EXE!" build >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim accepted non-rooted attestation path
  exit /b 1
)
set "FSRING_LOCKED_CARGO_ATTESTATION=!R2_TEST_ATTESTATION!"
set "FSRING_LOCKED_CARGO_NONCE="
call "!FSRING_LOCKED_CARGO_EXE!" build >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim accepted missing attestation nonce
  exit /b 1
)
set "FSRING_LOCKED_CARGO_NONCE=SELFTEST-NONCE"
call :delete_selftest_attestation
> "!R2_TEST_ATTESTATION!" echo stale
call "!FSRING_LOCKED_CARGO_EXE!" build >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim overwrote a stale attestation
  exit /b 1
)
call :delete_selftest_attestation
echo self-test ok: missing/non-rooted/stale attestation and missing nonce reject

set "FSRING_FIXTURE_ROOT=!R2_SELFTEST_ROOT!\fixture with spaces"
set "FSRING_FIXTURE_MANIFEST=!FSRING_FIXTURE_ROOT!\Cargo.toml"
set "FSRING_FIXTURE_TARGET=!FSRING_FIXTURE_ROOT!\target with spaces"
set "FSRING_R2_FIXTURE_ROOT=!FSRING_FIXTURE_ROOT!"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "$utf8 = New-Object Text.UTF8Encoding($false); [IO.Directory]::CreateDirectory((Join-Path $env:FSRING_R2_FIXTURE_ROOT 'src')) | Out-Null; [IO.Directory]::CreateDirectory($env:FSRING_FIXTURE_TARGET) | Out-Null; [IO.File]::WriteAllText((Join-Path $env:FSRING_R2_FIXTURE_ROOT 'Cargo.toml'), \"[package]`nname = 'fsring-r2-shim-fixture'`nversion = '0.0.0'`nedition = '2021'`n`n[workspace]`n\", $utf8); [IO.File]::WriteAllText((Join-Path $env:FSRING_R2_FIXTURE_ROOT 'src\main.rs'), \"fn main() {}`n\", $utf8)"
if errorlevel 1 (
  echo SELF-TEST: FAIL: tiny native-shim fixture could not be written
  exit /b 1
)
"!FSRING_REAL_CARGO!" +1.85.0 generate-lockfile --manifest-path "!FSRING_FIXTURE_MANIFEST!" --offline >nul 2>&1
if errorlevel 1 (
  echo SELF-TEST: FAIL: tiny native-shim fixture lockfile could not be generated
  exit /b 1
)

set "FSRING_LOCKED_CARGO_ATTESTATION=!R2_TEST_ATTESTATION!"
set "FSRING_LOCKED_CARGO_NONCE=SELFTEST-BOUNDARY-NONCE"
set "FSRING_ATTESTATION_KIND=fixture"
set "FSRING_LOCKED_CARGO_TARGET_DIR=!FSRING_FIXTURE_TARGET!"
set "CARGO_TARGET_DIR=!FSRING_LOCKED_CARGO_TARGET_DIR!"
set "R2_SHIM_OUTPUT=!R2_SELFTEST_ROOT!\selftest-shim-output.txt"
call :delete_selftest_attestation
set "R2_OVERSIZED_ARGUMENT="
call :c4_note_launch powershell
for /f "usebackq delims=" %%A in (`call "%FSRING_C4_PS%" -NoProfile -Command "'A'.PadRight(2049,'A')"`) do set "R2_OVERSIZED_ARGUMENT=%%A"
call "!FSRING_LOCKED_CARGO_EXE!" build "!R2_OVERSIZED_ARGUMENT!" >"!R2_SHIM_OUTPUT!" 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: native shim accepted an oversized attested argument
  exit /b 1
)
if exist "!R2_TEST_ATTESTATION!" (
  echo SELF-TEST: FAIL: oversized writer input created a partial attestation
  exit /b 1
)
call "!FSRING_LOCKED_CARGO_EXE!" build --manifest-path "!FSRING_FIXTURE_MANIFEST!" >"!R2_SHIM_OUTPUT!" 2>&1
if errorlevel 1 (
  type "!R2_SHIM_OUTPUT!"
  echo SELF-TEST: FAIL: native shim could not drive the tiny locked/offline Cargo build
  exit /b 1
)
call :verify_attestation
if errorlevel 1 (
  echo SELF-TEST: FAIL: valid boundary-preserving attestation was rejected
  exit /b 1
)
set "FSRING_NATIVE_ALLOWED_EVIDENCE=selftest-attestation.txt"
call :check_native_app_directory
if errorlevel 1 (
  echo SELF-TEST: FAIL: valid attestation lifecycle broke the closed app directory
  exit /b 1
)
echo self-test ok: native argument boundaries preserved; exact target-dir/--locked/--offline appended

set "R2_GOOD_ATTESTATION=!R2_TEST_ATTESTATION!"
set "R2_MUTATION_DIR=!R2_SELFTEST_ROOT!\mutations"
set "FSRING_R2_MUTATION_DIR=!R2_MUTATION_DIR!"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "[IO.Directory]::CreateDirectory($env:FSRING_R2_MUTATION_DIR) | Out-Null"
for %%K in (wrong-nonce wrong-cargo wrong-toolchain-cargo wrong-rustc wrong-target missing-target duplicate-target malformed oversized-field oversized-count extra duplicate-field wrong-first missing-suffix reordered-suffix duplicated-suffix) do (
  set "R2_MUTATION_KIND=%%K"
  set "R2_MUTATION_PATH=!R2_MUTATION_DIR!\selftest-%%K.txt"
  call :mutate_attestation "!R2_GOOD_ATTESTATION!" "!R2_MUTATION_PATH!" "%%K"
  if errorlevel 1 (
    echo SELF-TEST: FAIL: could not create %%K attestation fixture
    exit /b 1
  )
  set "FSRING_LOCKED_CARGO_ATTESTATION=!R2_MUTATION_PATH!"
  call :verify_attestation >nul 2>&1
  if not errorlevel 1 (
    echo SELF-TEST: FAIL: %%K attestation was accepted
    exit /b 1
  )
)
call :self_test_attestation_bounds
if errorlevel 1 exit /b 1
set "FSRING_LOCKED_CARGO_ATTESTATION=!R2_TEST_ATTESTATION!"
echo self-test ok: wrong identity/target, bounded fields/counts, malformed/extra/duplicate fields, and suffix mutations reject

set "FSRING_LOCKED_CARGO_ATTESTATION="
set "FSRING_LOCKED_CARGO_NONCE=PLUGIN-MISSING-ATTESTATION"
set "R2_CMD_ONLY_DIR=!R2_SELFTEST_ROOT!\obsolete-cmd-only"
set "R2_OBSOLETE_CAPTURE=!R2_SELFTEST_ROOT!\obsolete-cmd-capture.txt"
set "R2_PLUGIN_OUTPUT=!R2_SELFTEST_ROOT!\plugin-missing-attestation.txt"
set "FSRING_R2_CMD_ONLY_DIR=!R2_CMD_ONLY_DIR!"
set "FSRING_R2_OBSOLETE_CAPTURE=!R2_OBSOLETE_CAPTURE!"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "$utf8 = New-Object Text.UTF8Encoding($false); $percent = [char]37; $content = '@echo off' + \"`r`n\" + 'copy /y nul ' + $percent + 'FSRING_OBSOLETE_CAPTURE' + $percent + \"`r`n\" + 'exit /b 91' + \"`r`n\"; [IO.Directory]::CreateDirectory($env:FSRING_R2_CMD_ONLY_DIR) | Out-Null; [IO.File]::WriteAllText((Join-Path $env:FSRING_R2_CMD_ONLY_DIR 'cargo.cmd'), $content, $utf8)"
if errorlevel 1 (
  echo SELF-TEST: FAIL: obsolete cargo.cmd-only fixture could not be written
  exit /b 1
)
if exist "!R2_OBSOLETE_CAPTURE!" del /f /q "!R2_OBSOLETE_CAPTURE!" >nul 2>&1
set "FSRING_OBSOLETE_CAPTURE=!R2_OBSOLETE_CAPTURE!"
set "R2_SAVED_PATH=!PATH!"
set "PATH=!R2_CMD_ONLY_DIR!;!FSRING_LOCKED_CARGO_DIR!;!R2_SAVED_PATH!"
set "CARGO=!FSRING_REAL_CARGO!"
set "RUSTC=!FSRING_RUSTC!"
set "RUSTUP_HOME=!FSRING_RUSTUP_HOME!"
set "RUSTUP_TOOLCHAIN=1.85.0"
set "CARGO_NET_OFFLINE=true"
set "CARGO_TARGET_DIR=!FSRING_LOCKED_CARGO_TARGET_DIR!"
call :check_native_app_directory
if errorlevel 1 (
  echo SELF-TEST: FAIL: plugin prelaunch app-directory gate rejected the exact lifecycle
  exit /b 1
)
pushd "!DRIVER!\fsring-fsd"
"!FSRING_CARGO_WDK!" build --profile release --target-arch arm64 >"!R2_PLUGIN_OUTPUT!" 2>&1
set "R2_PLUGIN_RC=!ERRORLEVEL!"
popd
set "PATH=!R2_SAVED_PATH!"
set "CARGO_TARGET_DIR="
if "!R2_PLUGIN_RC!"=="0" (
  echo SELF-TEST: FAIL: plugin-driven build counted success without an attestation
  exit /b 1
)
if exist "!R2_OBSOLETE_CAPTURE!" (
  echo SELF-TEST: FAIL: Rust native process resolution unexpectedly executed cargo.cmd
  exit /b 1
)
"%SystemRoot%\System32\findstr.exe" /L /C:"FSRING_LOCKED_CARGO_ATTESTATION is required" "!R2_PLUGIN_OUTPUT!" >nul
if errorlevel 1 (
  type "!R2_PLUGIN_OUTPUT!"
  echo SELF-TEST: FAIL: plugin-driven build did not reach native cargo.exe
  exit /b 1
)
echo self-test ok: cargo.cmd-only is bypassed; plugin success requires native attestation

rem A gated run without the frozen cargo-clippy payload must REFUSE, not
rem quietly fall back to the bare name. This calls the PRODUCTION
rem subroutine, not a transcribed copy of it: an earlier version of this
rem case wrote the four production lines into a temp .cmd and tested that,
rem so deleting the real refusal left the self-test green.
setlocal
set "FSRING_C4_COMMAND_ID=20-matrix-three-profile"
set "FSRING_C4_TOOL_CARGO_CLIPPY_1_85_0="
set "FSRING_MATRIX_CLIPPY=cargo clippy"
call :c4_require_frozen_clippy
if not errorlevel 2 (
  endlocal
  echo SELF-TEST: FAIL: a gated run accepted a withheld cargo-clippy payload
  exit /b 1
)
set "FSRING_C4_TOOL_CARGO_CLIPPY_1_85_0=C:\fixture\cargo-clippy.exe"
set "FSRING_MATRIX_CLIPPY="C:\fixture\cargo-clippy.exe" clippy"
call :c4_require_frozen_clippy
if errorlevel 1 (
  endlocal
  echo SELF-TEST: FAIL: a supplied cargo-clippy payload was refused
  exit /b 1
)
rem A payload path the gate happened to quote must still match. Both sides are
rem quote-stripped, so the check does not depend on the gate's spelling; the
rem launcher line builds this exact doubled-quote shape from a quoted value.
set FSRING_C4_TOOL_CARGO_CLIPPY_1_85_0="C:\fixture\cargo-clippy.exe"
set "FSRING_MATRIX_CLIPPY=""C:\fixture\cargo-clippy.exe"" clippy"
call :c4_require_frozen_clippy
if errorlevel 1 (
  endlocal
  echo SELF-TEST: FAIL: a quoted frozen cargo-clippy payload was refused
  exit /b 1
)
set "FSRING_C4_TOOL_CARGO_CLIPPY_1_85_0=C:\fixture\cargo-clippy.exe"
rem Supplied is not launched. The payload is present and the command line
rem still names the ambient proxy: that is the state deleting the launcher
rem line above produces, and it must refuse.
set "FSRING_MATRIX_CLIPPY=cargo clippy"
call :c4_require_frozen_clippy
if not errorlevel 2 (
  endlocal
  echo SELF-TEST: FAIL: a gated run accepted a clippy command that does not name the frozen payload
  exit /b 1
)
rem A different frozen-looking payload is not this run's payload either.
set "FSRING_MATRIX_CLIPPY="C:\other\cargo-clippy.exe" clippy"
call :c4_require_frozen_clippy
if not errorlevel 2 (
  endlocal
  echo SELF-TEST: FAIL: a gated run accepted a clippy command naming a different payload
  exit /b 1
)
set "FSRING_C4_COMMAND_ID="
set "FSRING_C4_TOOL_CARGO_CLIPPY_1_85_0="
set "FSRING_MATRIX_CLIPPY=cargo clippy"
call :c4_require_frozen_clippy
if errorlevel 1 (
  endlocal
  echo SELF-TEST: FAIL: a developer run was refused a bare-name clippy
  exit /b 1
)
endlocal
echo self-test ok: a gated run refuses a withheld or unlaunched frozen cargo-clippy

call :clear_attestation_environment
echo SELF-TEST: PASS
exit /b 0

:self_test_selector_callsite_closure
setlocal EnableDelayedExpansion
set "R2_SELECTOR_FAILURE=0"
set "R2_SELECTOR_ROOT=!R2_SELFTEST_ROOT!\selector-callsite"
set "R2_SELECTOR_OUTSIDE=!R2_SELFTEST_ROOT!\selector-callsite-outside"
set "R2_SELECTOR_JUNCTION=!R2_SELECTOR_ROOT!\junction-parent"
set "R2_CONTROLLED_SOURCE=!R2_SELECTOR_ROOT!\controlled-cargo.rs"
set "R2_CONTROLLED_SOURCE_EXE=!R2_SELECTOR_ROOT!\rustup.exe"
set "FSRING_R2_CONTROLLED_SOURCE_EXE=!R2_CONTROLLED_SOURCE_EXE!"
set "FSRING_R2_SELECTOR_ROOT=!R2_SELECTOR_ROOT!"
set "FSRING_R2_SELECTOR_OUTSIDE=!R2_SELECTOR_OUTSIDE!"
set "FSRING_R2_SELECTOR_JUNCTION=!R2_SELECTOR_JUNCTION!"
set "FSRING_R2_CONTROLLED_SOURCE=!R2_CONTROLLED_SOURCE!"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "& { try { $utf8 = New-Object Text.UTF8Encoding($false); [IO.Directory]::CreateDirectory($env:FSRING_R2_SELECTOR_ROOT) | Out-Null; [IO.Directory]::CreateDirectory($env:FSRING_R2_SELECTOR_OUTSIDE) | Out-Null; [IO.File]::WriteAllLines($env:FSRING_R2_CONTROLLED_SOURCE,@('use std::{env, fs};','fn main() {','    let marker = env::var_os(\"FSRING_R2_CONTROLLED_CARGO_MARKER\").expect(\"controlled marker\");','    fs::write(marker, b\"ran\").expect(\"write controlled marker\");','    if let Some(path) = env::var_os(\"FSRING_R2_CONTROLLED_CARGO_CONTAMINATION\").filter(|value| value.len() > 0) {','        fs::write(path, b\"unapproved\").expect(\"write controlled contamination\");','    }','}'),$utf8); [IO.File]::WriteAllText((Join-Path $env:FSRING_R2_SELECTOR_OUTSIDE 'sentinel.txt'),'sentinel',$utf8); exit 0 } catch { [Console]::Error.WriteLine('SELECTOR-SELFTEST: FAIL: ' + $_.Exception.Message); exit 1 } }"
if errorlevel 1 (
  echo SELF-TEST: FAIL: controlled selector source root could not be prepared
  set "R2_SELECTOR_FAILURE=1"
  goto :self_test_selector_cleanup
)
set "R2_PRODUCTION_SHIM=!FSRING_LOCKED_CARGO_EXE!"
set "R2_PRODUCTION_SOURCE=!FSRING_LOCKED_CARGO_SOURCE!"
set "FSRING_LOCKED_CARGO_SOURCE=!R2_CONTROLLED_SOURCE!"
set "FSRING_LOCKED_CARGO_EXE=!R2_CONTROLLED_SOURCE_EXE!"
call "!SCRIPTS!_in_devenv.cmd" amd64 __fsring_compile_locked_cargo__
set "R2_CONTROLLED_COMPILE_RC=!ERRORLEVEL!"
set "FSRING_LOCKED_CARGO_SOURCE=!R2_PRODUCTION_SOURCE!"
set "FSRING_LOCKED_CARGO_EXE=!R2_PRODUCTION_SHIM!"
if not "!R2_CONTROLLED_COMPILE_RC!"=="0" (
  echo SELF-TEST: FAIL: controlled selector executable could not be compiled
  set "R2_SELECTOR_FAILURE=1"
  goto :self_test_selector_cleanup
)
call :hash_file "!R2_CONTROLLED_SOURCE_EXE!" R2_CONTROLLED_HASH
if errorlevel 1 (
  echo SELF-TEST: FAIL: controlled selector executable could not be hashed
  set "R2_SELECTOR_FAILURE=1"
  goto :self_test_selector_cleanup
)
set "FSRING_R2_CONTROLLED_HASH=!R2_CONTROLLED_HASH!"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "& { try { $selectors = @('metadata-selector','shim-pre-selector','shim-post-selector','shim-clean-selector'); foreach ($name in $selectors) { $directory = Join-Path $env:FSRING_R2_SELECTOR_ROOT $name; [IO.Directory]::CreateDirectory($directory) | Out-Null; [IO.File]::Copy($env:FSRING_R2_CONTROLLED_SOURCE_EXE,(Join-Path $directory 'cargo.exe'),$false); [IO.File]::Copy($env:FSRING_R2_CONTROLLED_SOURCE_EXE,(Join-Path $directory 'rustc.exe'),$false) }; [IO.File]::WriteAllText((Join-Path $env:FSRING_R2_SELECTOR_ROOT 'metadata-selector\unapproved.dll'),'unapproved'); [IO.File]::WriteAllText((Join-Path $env:FSRING_R2_SELECTOR_ROOT 'shim-pre-selector\unapproved.dll'),'unapproved'); $junctionSelector = Join-Path $env:FSRING_R2_SELECTOR_OUTSIDE 'selector'; [IO.Directory]::CreateDirectory($junctionSelector) | Out-Null; [IO.File]::Copy($env:FSRING_R2_CONTROLLED_SOURCE_EXE,(Join-Path $junctionSelector 'cargo.exe'),$false); [IO.File]::Copy($env:FSRING_R2_CONTROLLED_SOURCE_EXE,(Join-Path $junctionSelector 'rustc.exe'),$false); New-Item -ItemType Junction -Path $env:FSRING_R2_SELECTOR_JUNCTION -Target $env:FSRING_R2_SELECTOR_OUTSIDE -ErrorAction Stop | Out-Null; exit 0 } catch { [Console]::Error.WriteLine('SELECTOR-SELFTEST: FAIL: ' + $_.Exception.Message); exit 1 } }"
if errorlevel 1 (
  echo SELF-TEST: FAIL: controlled selector directories could not be prepared
  set "R2_SELECTOR_FAILURE=1"
  goto :self_test_selector_cleanup
)

call :self_test_use_controlled_selector "!R2_SELECTOR_ROOT!\metadata-selector"
set "FSRING_METADATA_OUTPUT=!R2_SELECTOR_ROOT!\metadata-contaminated.json"
set "FSRING_R2_CONTROLLED_CARGO_MARKER=!R2_SELECTOR_ROOT!\metadata-contaminated.marker"
set "FSRING_R2_CONTROLLED_CARGO_CONTAMINATION="
call "!SCRIPTS!_in_devenv.cmd" amd64 __fsring_locked_metadata__ >"!R2_SELECTOR_ROOT!\metadata-contaminated.log" 2>&1
set "R2_METADATA_CONTAMINATED_RC=!ERRORLEVEL!"
if "!R2_METADATA_CONTAMINATED_RC!"=="0" (
  echo SELF-TEST: FAIL: final metadata call accepted a contaminated selector
  set "R2_SELECTOR_FAILURE=1"
)
if exist "!FSRING_METADATA_OUTPUT!" (
  echo SELF-TEST: FAIL: failed metadata precheck created metadata output
  set "R2_SELECTOR_FAILURE=1"
)
if exist "!FSRING_R2_CONTROLLED_CARGO_MARKER!" (
  echo SELF-TEST: FAIL: failed metadata precheck launched controlled Cargo
  set "R2_SELECTOR_FAILURE=1"
)

call :self_test_use_controlled_selector "!R2_SELECTOR_ROOT!\shim-pre-selector"
set "FSRING_LOCKED_CARGO_ATTESTATION=!FSRING_LOCKED_CARGO_DIR!\selector-pre-attestation.txt"
set "FSRING_LOCKED_CARGO_NONCE=SELECTOR-PRE-CONTAMINATION"
set "FSRING_R2_CONTROLLED_CARGO_MARKER=!R2_SELECTOR_ROOT!\shim-pre.marker"
set "FSRING_R2_CONTROLLED_CARGO_CONTAMINATION="
call "!R2_PRODUCTION_SHIM!" build >"!R2_SELECTOR_ROOT!\shim-pre.log" 2>&1
set "R2_SHIM_PRE_RC=!ERRORLEVEL!"
if "!R2_SHIM_PRE_RC!"=="0" (
  echo SELF-TEST: FAIL: native shim accepted a pre-spawn contaminated selector
  set "R2_SELECTOR_FAILURE=1"
)
if exist "!FSRING_LOCKED_CARGO_ATTESTATION!" (
  echo SELF-TEST: FAIL: pre-spawn selector rejection wrote attestation
  set "R2_SELECTOR_FAILURE=1"
)
if exist "!FSRING_R2_CONTROLLED_CARGO_MARKER!" (
  echo SELF-TEST: FAIL: pre-spawn selector rejection launched controlled Cargo
  set "R2_SELECTOR_FAILURE=1"
)
if exist "!FSRING_LOCKED_CARGO_ATTESTATION!" del /f /q "!FSRING_LOCKED_CARGO_ATTESTATION!" >nul 2>&1

call :self_test_use_controlled_selector "!R2_SELECTOR_ROOT!\shim-post-selector"
set "FSRING_LOCKED_CARGO_ATTESTATION=!FSRING_LOCKED_CARGO_DIR!\selector-post-attestation.txt"
set "FSRING_LOCKED_CARGO_NONCE=SELECTOR-POST-CONTAMINATION"
set "FSRING_R2_CONTROLLED_CARGO_MARKER=!R2_SELECTOR_ROOT!\shim-post.marker"
set "FSRING_R2_CONTROLLED_CARGO_CONTAMINATION=!FSRING_RUSTUP_SELECTOR_DIR!\unapproved.dll"
call "!R2_PRODUCTION_SHIM!" build >"!R2_SELECTOR_ROOT!\shim-post.log" 2>&1
set "R2_SHIM_POST_RC=!ERRORLEVEL!"
if "!R2_SHIM_POST_RC!"=="0" (
  echo SELF-TEST: FAIL: native shim accepted after-spawn selector contamination
  set "R2_SELECTOR_FAILURE=1"
)
if not exist "!FSRING_R2_CONTROLLED_CARGO_MARKER!" (
  echo SELF-TEST: FAIL: after-spawn fixture did not prove controlled Cargo ran
  set "R2_SELECTOR_FAILURE=1"
)
if not exist "!FSRING_R2_CONTROLLED_CARGO_CONTAMINATION!" (
  echo SELF-TEST: FAIL: after-spawn fixture did not leave its failed selector postcondition
  set "R2_SELECTOR_FAILURE=1"
)
if exist "!FSRING_LOCKED_CARGO_ATTESTATION!" del /f /q "!FSRING_LOCKED_CARGO_ATTESTATION!" >nul 2>&1

call :self_test_use_controlled_selector "!R2_SELECTOR_ROOT!\shim-clean-selector"
set "FSRING_LOCKED_CARGO_ATTESTATION=!FSRING_LOCKED_CARGO_DIR!\selector-clean-attestation.txt"
set "FSRING_LOCKED_CARGO_NONCE=SELECTOR-CLEAN"
set "FSRING_R2_CONTROLLED_CARGO_MARKER=!R2_SELECTOR_ROOT!\shim-clean.marker"
set "FSRING_R2_CONTROLLED_CARGO_CONTAMINATION="
call "!R2_PRODUCTION_SHIM!" build >"!R2_SELECTOR_ROOT!\shim-clean.log" 2>&1
set "R2_SHIM_CLEAN_RC=!ERRORLEVEL!"
if not "!R2_SHIM_CLEAN_RC!"=="0" (
  echo SELF-TEST: FAIL: native shim rejected a clean controlled selector child
  set "R2_SELECTOR_FAILURE=1"
)
if not exist "!FSRING_R2_CONTROLLED_CARGO_MARKER!" (
  echo SELF-TEST: FAIL: clean controlled Cargo child did not run
  set "R2_SELECTOR_FAILURE=1"
)
if not exist "!FSRING_LOCKED_CARGO_ATTESTATION!" (
  echo SELF-TEST: FAIL: clean controlled Cargo child did not write attestation
  set "R2_SELECTOR_FAILURE=1"
)
if exist "!FSRING_LOCKED_CARGO_ATTESTATION!" del /f /q "!FSRING_LOCKED_CARGO_ATTESTATION!" >nul 2>&1

call :self_test_use_controlled_selector "!R2_SELECTOR_JUNCTION!\selector"
set "FSRING_METADATA_OUTPUT=!R2_SELECTOR_ROOT!\metadata-junction.json"
set "FSRING_R2_CONTROLLED_CARGO_MARKER=!R2_SELECTOR_ROOT!\metadata-junction.marker"
set "FSRING_R2_CONTROLLED_CARGO_CONTAMINATION="
call "!SCRIPTS!_in_devenv.cmd" amd64 __fsring_locked_metadata__ >"!R2_SELECTOR_ROOT!\metadata-junction.log" 2>&1
set "R2_METADATA_JUNCTION_RC=!ERRORLEVEL!"
if "!R2_METADATA_JUNCTION_RC!"=="0" (
  echo SELF-TEST: FAIL: final metadata call accepted a reparse-parent selector
  set "R2_SELECTOR_FAILURE=1"
)
if exist "!FSRING_METADATA_OUTPUT!" (
  echo SELF-TEST: FAIL: reparse-parent metadata rejection created output
  set "R2_SELECTOR_FAILURE=1"
)
if exist "!FSRING_R2_CONTROLLED_CARGO_MARKER!" (
  echo SELF-TEST: FAIL: reparse-parent metadata rejection launched controlled Cargo
  set "R2_SELECTOR_FAILURE=1"
)

set "FSRING_LOCKED_CARGO_ATTESTATION=!FSRING_LOCKED_CARGO_DIR!\selector-junction-attestation.txt"
set "FSRING_LOCKED_CARGO_NONCE=SELECTOR-JUNCTION"
set "FSRING_R2_CONTROLLED_CARGO_MARKER=!R2_SELECTOR_ROOT!\shim-junction.marker"
call "!R2_PRODUCTION_SHIM!" build >"!R2_SELECTOR_ROOT!\shim-junction.log" 2>&1
set "R2_SHIM_JUNCTION_RC=!ERRORLEVEL!"
if "!R2_SHIM_JUNCTION_RC!"=="0" (
  echo SELF-TEST: FAIL: native shim accepted a reparse-parent selector
  set "R2_SELECTOR_FAILURE=1"
)
if exist "!FSRING_LOCKED_CARGO_ATTESTATION!" (
  echo SELF-TEST: FAIL: reparse-parent shim rejection wrote attestation
  set "R2_SELECTOR_FAILURE=1"
)
if exist "!FSRING_R2_CONTROLLED_CARGO_MARKER!" (
  echo SELF-TEST: FAIL: reparse-parent shim rejection launched controlled Cargo
  set "R2_SELECTOR_FAILURE=1"
)
if exist "!FSRING_LOCKED_CARGO_ATTESTATION!" del /f /q "!FSRING_LOCKED_CARGO_ATTESTATION!" >nul 2>&1

:self_test_selector_cleanup
set "FSRING_R2_SELECTOR_CLEANUP_ROOT=!R2_SELECTOR_ROOT!"
set "FSRING_R2_SELECTOR_CLEANUP_OUTSIDE=!R2_SELECTOR_OUTSIDE!"
set "FSRING_R2_SELECTOR_CLEANUP_LINK=!R2_SELECTOR_JUNCTION!"
set "FSRING_R2_SELECTOR_CLEANUP_PARENT=!R2_SELFTEST_ROOT!"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "& { try { $parent = [IO.Path]::GetFullPath($env:FSRING_R2_SELECTOR_CLEANUP_PARENT).TrimEnd('\'); $root = [IO.Path]::GetFullPath($env:FSRING_R2_SELECTOR_CLEANUP_ROOT).TrimEnd('\'); $outside = [IO.Path]::GetFullPath($env:FSRING_R2_SELECTOR_CLEANUP_OUTSIDE).TrimEnd('\'); $link = [IO.Path]::GetFullPath($env:FSRING_R2_SELECTOR_CLEANUP_LINK).TrimEnd('\'); if (-not [string]::Equals([IO.Path]::GetDirectoryName($root),$parent,[StringComparison]::OrdinalIgnoreCase) -or -not [string]::Equals([IO.Path]::GetDirectoryName($outside),$parent,[StringComparison]::OrdinalIgnoreCase) -or -not [string]::Equals([IO.Path]::GetDirectoryName($link),$root,[StringComparison]::OrdinalIgnoreCase)) { throw 'cleanup containment' }; if (Test-Path -LiteralPath $link) { $item = Get-Item -LiteralPath $link -Force; if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { throw 'cleanup link kind' }; [IO.Directory]::Delete($link,$false) }; if (Test-Path -LiteralPath $link) { throw 'cleanup link removal' }; if (Test-Path -LiteralPath $root) { foreach ($item in @(Get-ChildItem -LiteralPath $root -Recurse -Force)) { if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('unexpected cleanup reparse: ' + $item.FullName) } }; Remove-Item -LiteralPath $root -Recurse -Force }; if (Test-Path -LiteralPath $root) { throw 'cleanup root removal' }; $sentinel = Join-Path $outside 'sentinel.txt'; if (-not (Test-Path -LiteralPath $sentinel -PathType Leaf) -or [IO.File]::ReadAllText($sentinel) -cne 'sentinel') { throw 'outside sentinel changed' }; Remove-Item -LiteralPath $outside -Recurse -Force; if (Test-Path -LiteralPath $outside) { throw 'outside cleanup removal' }; exit 0 } catch { [Console]::Error.WriteLine('SELECTOR-SELFTEST-CLEANUP: FAIL: ' + $_.Exception.Message); exit 1 } }"
if errorlevel 1 (
  echo SELF-TEST: FAIL: selector call-site fixture cleanup was not contained
  endlocal & exit /b 1
)
if not "!R2_SELECTOR_FAILURE!"=="0" endlocal & exit /b 1
echo self-test ok: metadata and native-shim call sites close selector identity before/after spawn
endlocal & exit /b 0

:self_test_use_controlled_selector
set "FSRING_RUSTUP_PROXY_SOURCE=%R2_CONTROLLED_SOURCE_EXE%"
set "FSRING_RUSTUP_PROXY_SOURCE_SHA256=%R2_CONTROLLED_HASH%"
set "FSRING_RUSTUP_SELECTOR_DIR=%~1"
set "FSRING_REAL_CARGO=%~1\cargo.exe"
set "FSRING_REAL_CARGO_SHA256=%R2_CONTROLLED_HASH%"
set "FSRING_RUSTUP_SELECTOR_RUSTC=%~1\rustc.exe"
set "FSRING_RUSTUP_SELECTOR_RUSTC_SHA256=%R2_CONTROLLED_HASH%"
set "CARGO=%~1\cargo.exe"
set "RUSTC=%FSRING_RUSTC%"
set "CARGO_TARGET_DIR=%FSRING_LOCKED_CARGO_TARGET_DIR%"
set "RUSTUP_HOME=%FSRING_RUSTUP_HOME%"
set "RUSTUP_TOOLCHAIN=1.85.0"
set "CARGO_NET_OFFLINE=true"
set "FSRING_LOCKED_CARGO_TOOLCHAIN=1.85.0"
exit /b 0

:self_test_native_tool_identities
setlocal EnableDelayedExpansion
set "R2_IDENTITY_ROOT=!R2_SELFTEST_ROOT!\native-identity"
set "R2_IDENTITY_OUTSIDE=!R2_IDENTITY_ROOT!\outside"
set "R2_IDENTITY_LINK=!R2_IDENTITY_ROOT!\reparse-parent"
set "FSRING_R2_IDENTITY_ROOT=!R2_IDENTITY_ROOT!"
set "FSRING_R2_IDENTITY_OUTSIDE=!R2_IDENTITY_OUTSIDE!"
set "FSRING_R2_IDENTITY_LINK=!R2_IDENTITY_LINK!"
set "FSRING_R2_IDENTITY_PROXY_SOURCE=!FSRING_RUSTUP_PROXY_SOURCE!"
set "FSRING_R2_IDENTITY_CARGO=!FSRING_REAL_CARGO!"
set "FSRING_R2_IDENTITY_WDK=!FSRING_CARGO_WDK_SOURCE!"
set "FSRING_R2_IDENTITY_RUSTC_PROXY=!R2_RUSTC_PROXY!"
set "FSRING_R2_IDENTITY_RUSTC=!FSRING_RUSTC!"
set "FSRING_R2_IDENTITY_TOOLCHAIN_CARGO=!FSRING_TOOLCHAIN_CARGO!"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "& { try { [IO.Directory]::CreateDirectory($env:FSRING_R2_IDENTITY_OUTSIDE) | Out-Null; [IO.File]::WriteAllText((Join-Path $env:FSRING_R2_IDENTITY_OUTSIDE 'sentinel.txt'),'sentinel'); [IO.File]::Copy($env:FSRING_R2_IDENTITY_PROXY_SOURCE,(Join-Path $env:FSRING_R2_IDENTITY_OUTSIDE 'rustup-proxy-source.exe'),$false); [IO.File]::Copy($env:FSRING_R2_IDENTITY_CARGO,(Join-Path $env:FSRING_R2_IDENTITY_OUTSIDE 'cargo-proxy.exe'),$false); [IO.File]::Copy($env:FSRING_R2_IDENTITY_WDK,(Join-Path $env:FSRING_R2_IDENTITY_OUTSIDE 'cargo-wdk-source.exe'),$false); [IO.File]::Copy($env:FSRING_R2_IDENTITY_RUSTC_PROXY,(Join-Path $env:FSRING_R2_IDENTITY_OUTSIDE 'rustc-selector.exe'),$false); [IO.File]::Copy($env:FSRING_R2_IDENTITY_RUSTC,(Join-Path $env:FSRING_R2_IDENTITY_OUTSIDE 'exact-rustc.exe'),$false); [IO.File]::Copy($env:FSRING_R2_IDENTITY_TOOLCHAIN_CARGO,(Join-Path $env:FSRING_R2_IDENTITY_OUTSIDE 'toolchain-cargo.exe'),$false); [IO.Directory]::CreateDirectory((Join-Path $env:FSRING_R2_IDENTITY_OUTSIDE 'rustup-home')) | Out-Null; New-Item -ItemType Junction -Path $env:FSRING_R2_IDENTITY_LINK -Target $env:FSRING_R2_IDENTITY_OUTSIDE -ErrorAction Stop | Out-Null; exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 } }"
if errorlevel 1 (
  echo SELF-TEST: FAIL: native tool-identity reparse fixture could not be created
  exit /b 1
)
for %%P in (
  "!FSRING_RUSTUP_PROXY_SOURCE!"
  "!FSRING_REAL_CARGO!"
  "!FSRING_CARGO_WDK_SOURCE!"
  "!R2_RUSTC_PROXY!"
  "!FSRING_RUSTC!"
  "!FSRING_TOOLCHAIN_CARGO!"
) do (
  call :check_native_identity File "%%~P" >nul 2>&1
  if errorlevel 1 (
    echo SELF-TEST: FAIL: canonical native file identity was rejected: "%%~P"
    exit /b 1
  )
)
call :check_native_identity Directory "!FSRING_RUSTUP_HOME!" >nul 2>&1
if errorlevel 1 (
  echo SELF-TEST: FAIL: canonical Rustup-home identity was rejected
  exit /b 1
)
for %%P in (
  "!R2_IDENTITY_LINK!\rustup-proxy-source.exe"
  "!R2_IDENTITY_LINK!\cargo-proxy.exe"
  "!R2_IDENTITY_LINK!\cargo-wdk-source.exe"
  "!R2_IDENTITY_LINK!\rustc-selector.exe"
  "!R2_IDENTITY_LINK!\exact-rustc.exe"
  "!R2_IDENTITY_LINK!\toolchain-cargo.exe"
) do (
  call :check_native_identity File "%%~P" >nul 2>&1
  if not errorlevel 1 (
    echo SELF-TEST: FAIL: reparse-parent native file identity was accepted: "%%~P"
    exit /b 1
  )
)
call :check_native_identity Directory "!R2_IDENTITY_LINK!\rustup-home" >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: reparse-parent Rustup-home identity was accepted
  exit /b 1
)
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "& { try { $root = [IO.Path]::GetFullPath($env:FSRING_R2_IDENTITY_ROOT).TrimEnd('\'); $link = [IO.Path]::GetFullPath($env:FSRING_R2_IDENTITY_LINK); $outside = [IO.Path]::GetFullPath($env:FSRING_R2_IDENTITY_OUTSIDE); $sentinel = Join-Path $outside 'sentinel.txt'; if (-not $link.StartsWith($root + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'link containment' }; $item = Get-Item -LiteralPath $link -Force; if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { throw 'link identity' }; [IO.Directory]::Delete($link,$false); if ((Test-Path -LiteralPath $link) -or -not (Test-Path -LiteralPath $sentinel -PathType Leaf)) { throw 'cleanup/sentinel' }; exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 } }"
if errorlevel 1 (
  echo SELF-TEST: FAIL: native tool-identity fixture cleanup was not contained
  exit /b 1
)
echo self-test ok: native file/directory identities reject every reparse-parent tool route
exit /b 0

:check_native_identity
setlocal
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
if errorlevel 1 exit /b 1
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -ExecutionPolicy Bypass -File "%FSRING_NATIVE_DIRECTORY_GATE%" -Mode CheckIdentity -Kind "%~1" -Path "%~2"
set "FSRING_R2_IDENTITY_RC=%ERRORLEVEL%"
call :check_file_hash "%FSRING_NATIVE_DIRECTORY_GATE%" "%NATIVE_DIRECTORY_GATE_HASH%"
if errorlevel 1 exit /b 1
exit /b %FSRING_R2_IDENTITY_RC%

:self_test_native_shim_environment
setlocal EnableDelayedExpansion
set "R2_SHIM_ENV_OUTPUT=!R2_SELFTEST_ROOT!\native-shim-environment.txt"
for %%V in (
  BINDGEN_EXTRA_CLANG_ARGS
  CC
  CXX
  AR
  RANLIB
  CFLAGS
  CXXFLAGS
  bindgen_extra_clang_args_X86_64_PC_WINDOWS_MSVC
  Cc_x86_64_pc_windows_msvc
  cXX_AARCH64_PC_WINDOWS_MSVC
  Ar_X86_64_PC_WINDOWS_MSVC
  ranlib_aarch64_pc_windows_msvc
  Cflags_X86_64_PC_WINDOWS_MSVC
  cxxflags_aarch64_pc_windows_msvc
) do (
  call :delete_selftest_attestation
  set "%%V=R2-UNTRUSTED"
  call "!FSRING_LOCKED_CARGO_EXE!" build >"!R2_SHIM_ENV_OUTPUT!" 2>&1
  if not errorlevel 1 (
    echo SELF-TEST: FAIL: native shim accepted uncontrolled %%V
    exit /b 1
  )
  "%SystemRoot%\System32\findstr.exe" /I /L /C:"%%V" "!R2_SHIM_ENV_OUTPUT!" >nul
  if errorlevel 1 (
    type "!R2_SHIM_ENV_OUTPUT!"
    echo SELF-TEST: FAIL: native shim did not identify uncontrolled %%V before Cargo spawn
    exit /b 1
  )
  if exist "!R2_TEST_ATTESTATION!" (
    echo SELF-TEST: FAIL: native shim wrote evidence before rejecting uncontrolled %%V
    exit /b 1
  )
  set "%%V="
)
echo self-test ok: native shim rejects exact and target-qualified compiler/bindgen overrides before Cargo spawn
exit /b 0

:self_test_package_freshness
setlocal EnableDelayedExpansion
set "R2_FRESHNESS_TARGET=!R2_SELFTEST_ROOT!\freshness-target"
set "R2_FRESHNESS_PACKAGE=!R2_FRESHNESS_TARGET!\x86_64-pc-windows-msvc\release\fsring_fsd_package"
set "R2_FRESHNESS_OUTSIDE=!R2_FRESHNESS_TARGET!\outside"
set "R2_FRESHNESS_JUNCTION=!R2_FRESHNESS_PACKAGE!\escape"
set "FSRING_R2_FRESHNESS_TARGET=!R2_FRESHNESS_TARGET!"
set "FSRING_R2_FRESHNESS_PACKAGE=!R2_FRESHNESS_PACKAGE!"
set "FSRING_R2_FRESHNESS_OUTSIDE=!R2_FRESHNESS_OUTSIDE!"
set "FSRING_R2_FRESHNESS_JUNCTION=!R2_FRESHNESS_JUNCTION!"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "[IO.Directory]::CreateDirectory($env:FSRING_R2_FRESHNESS_PACKAGE) | Out-Null; [IO.File]::WriteAllText((Join-Path $env:FSRING_R2_FRESHNESS_PACKAGE 'stale.sys'),'stale'); [IO.Directory]::CreateDirectory($env:FSRING_R2_FRESHNESS_OUTSIDE) | Out-Null; [IO.File]::WriteAllText((Join-Path $env:FSRING_R2_FRESHNESS_OUTSIDE 'sentinel.txt'),'sentinel')"
if errorlevel 1 (
  echo SELF-TEST: FAIL: stale-package fixture could not be created
  exit /b 1
)
set "FSRING_CONTROLLED_TARGET_DIR=!R2_FRESHNESS_TARGET!"
call :prepare_package_output "!R2_FRESHNESS_PACKAGE!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: exact stale package could not be removed safely
  exit /b 1
)
if exist "!R2_FRESHNESS_PACKAGE!" (
  echo SELF-TEST: FAIL: stale package survived freshness preparation
  exit /b 1
)
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "[IO.Directory]::CreateDirectory($env:FSRING_R2_FRESHNESS_PACKAGE) | Out-Null; New-Item -ItemType Junction -Path $env:FSRING_R2_FRESHNESS_JUNCTION -Target $env:FSRING_R2_FRESHNESS_OUTSIDE -ErrorAction Stop | Out-Null"
if errorlevel 1 (
  echo SELF-TEST: FAIL: package-subtree reparse fixture could not be created
  exit /b 1
)
call :prepare_package_output "!R2_FRESHNESS_PACKAGE!" >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: package freshness deletion traversed a reparse subtree
  exit /b 1
)
if not exist "!R2_FRESHNESS_OUTSIDE!\sentinel.txt" (
  echo SELF-TEST: FAIL: reparse target sentinel was altered
  exit /b 1
)
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "$package = [IO.Path]::GetFullPath($env:FSRING_R2_FRESHNESS_PACKAGE).TrimEnd('\'); $link = [IO.Path]::GetFullPath($env:FSRING_R2_FRESHNESS_JUNCTION); $sentinel = Join-Path ([IO.Path]::GetFullPath($env:FSRING_R2_FRESHNESS_OUTSIDE)) 'sentinel.txt'; if (-not $link.StartsWith($package + '\',[StringComparison]::OrdinalIgnoreCase)) { exit 1 }; $item = Get-Item -LiteralPath $link -Force; if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { exit 1 }; [IO.Directory]::Delete($link,$false); if ((Test-Path -LiteralPath $link) -or -not (Test-Path -LiteralPath $sentinel -PathType Leaf)) { exit 1 }"
if errorlevel 1 (
  echo SELF-TEST: FAIL: exact package reparse fixture could not be removed
  exit /b 1
)
call :prepare_package_output "!R2_FRESHNESS_PACKAGE!"
if errorlevel 1 (
  echo SELF-TEST: FAIL: package fixture cleanup failed after reparse rejection
  exit /b 1
)
call :require_fresh_package_output "!R2_FRESHNESS_PACKAGE!" >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: absent normal-path package accepted redirected/stale evidence
  exit /b 1
)
echo self-test ok: stale package is removed, redirected output cannot pass, and reparse subtree deletion rejects
exit /b 0

:self_test_fresh_native_directories
setlocal EnableDelayedExpansion
call :create_fresh_native_directory R2_FIRST_APP_DIR
if errorlevel 1 (
  echo SELF-TEST: FAIL: first create-new native directory failed
  exit /b 1
)
call :create_fresh_native_directory R2_SECOND_APP_DIR
if errorlevel 1 (
  echo SELF-TEST: FAIL: second create-new native directory failed
  exit /b 1
)
if /I "!R2_FIRST_APP_DIR!"=="!R2_SECOND_APP_DIR!" (
  echo SELF-TEST: FAIL: two native setup invocations reused "!R2_FIRST_APP_DIR!"
  exit /b 1
)
set "R2_REPARSE_ROOT=!FSRING_CONTROLLED_TARGET_DIR!\fsring-r2-reparse-!R2_RUN_ID!"
set "R2_REPARSE_TARGET=!R2_REPARSE_ROOT!\target"
set "R2_REPARSE_LINK=!R2_REPARSE_ROOT!\link"
set "FSRING_R2_REPARSE_ROOT=!R2_REPARSE_ROOT!"
set "FSRING_R2_REPARSE_TARGET=!R2_REPARSE_TARGET!"
set "FSRING_R2_REPARSE_LINK=!R2_REPARSE_LINK!"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "[IO.Directory]::CreateDirectory($env:FSRING_R2_REPARSE_TARGET) | Out-Null; New-Item -ItemType Junction -Path $env:FSRING_R2_REPARSE_LINK -Target $env:FSRING_R2_REPARSE_TARGET -ErrorAction Stop | Out-Null"
if errorlevel 1 (
  echo SELF-TEST: FAIL: reparse-point fixture could not be created
  exit /b 1
)
set "FSRING_R2_ALLOWED_NAMES="
set "FSRING_R2_REQUIRED_NAMES="
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -ExecutionPolicy Bypass -File "!FSRING_NATIVE_DIRECTORY_GATE!" -Mode Check -Directory "!R2_REPARSE_LINK!" >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: reparse-point application directory was accepted
  exit /b 1
)
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "$root = [IO.Path]::GetFullPath($env:FSRING_R2_REPARSE_ROOT).TrimEnd('\'); $link = [IO.Path]::GetFullPath($env:FSRING_R2_REPARSE_LINK); $target = [IO.Path]::GetFullPath($env:FSRING_R2_REPARSE_TARGET); if (-not $link.StartsWith($root + '\',[StringComparison]::OrdinalIgnoreCase)) { exit 1 }; $item = Get-Item -LiteralPath $link -Force; if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { exit 1 }; [IO.Directory]::Delete($link,$false); if ((Test-Path -LiteralPath $link) -or -not (Test-Path -LiteralPath $target -PathType Container)) { exit 1 }"
if errorlevel 1 (
  echo SELF-TEST: FAIL: exact reparse-point fixture could not be removed
  exit /b 1
)
echo self-test ok: two native setup invocations are distinct and reparse paths reject
exit /b 0

:self_test_native_app_allowlist
setlocal EnableDelayedExpansion
call :create_fresh_native_directory R2_STALE_APP_DIR
if errorlevel 1 (
  echo SELF-TEST: FAIL: stale native application fixture could not be created
  exit /b 1
)
set "R2_STALE_PARENT_DLL=!R2_STALE_APP_DIR!\VCRUNTIME140.dll"
set "R2_INJECTED_APP_DLL=!FSRING_LOCKED_CARGO_DIR!\unapproved.dll"
set "FSRING_R2_STALE_PARENT_DLL=!R2_STALE_PARENT_DLL!"
set "FSRING_R2_INJECTED_APP_DLL=!R2_INJECTED_APP_DLL!"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "& { try { $stale = New-Object IO.FileStream($env:FSRING_R2_STALE_PARENT_DLL,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None); try { $stale.Write([byte[]](0x52,0x32),0,2) } finally { $stale.Dispose() }; $injected = New-Object IO.FileStream($env:FSRING_R2_INJECTED_APP_DLL,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None); try { $injected.Write([byte[]](0x52,0x32),0,2) } finally { $injected.Dispose() }; exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 } }"
if errorlevel 1 (
  echo SELF-TEST: FAIL: app-local DLL fixtures could not be written
  exit /b 1
)
if exist "!FSRING_LOCKED_CARGO_DIR!\VCRUNTIME140.dll" (
  echo SELF-TEST: FAIL: stale parent VCRUNTIME140.dll entered the fresh application directory
  exit /b 1
)
call :check_native_app_directory >nul 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: unapproved app-local DLL was accepted
  exit /b 1
)
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "$app = [IO.Path]::GetFullPath($env:FSRING_LOCKED_CARGO_DIR).TrimEnd('\'); $file = [IO.Path]::GetFullPath($env:FSRING_R2_INJECTED_APP_DLL); if (-not [string]::Equals([IO.Path]::GetDirectoryName($file),$app,[StringComparison]::OrdinalIgnoreCase)) { exit 1 }; Remove-Item -LiteralPath $file -Force"
if errorlevel 1 (
  echo SELF-TEST: FAIL: exact injected app-local DLL could not be removed
  exit /b 1
)
call :check_native_app_directory
if errorlevel 1 (
  echo SELF-TEST: FAIL: closed native application directory did not recover
  exit /b 1
)
echo self-test ok: stale-parent and injected app-local DLLs cannot enter a launch
exit /b 0

:self_test_attestation_bounds
setlocal EnableDelayedExpansion
set "R2_BOUNDS_OUTPUT=!R2_SELFTEST_ROOT!\attestation-bounds-output.txt"
set "R2_OVER_CAP=!R2_SELFTEST_ROOT!\attestation-over-cap.txt"
set "R2_AT_CAP=!R2_SELFTEST_ROOT!\attestation-at-cap.txt"
set "R2_INVALID_UTF8=!R2_SELFTEST_ROOT!\attestation-invalid-utf8.txt"
set "FSRING_R2_OVER_CAP=!R2_OVER_CAP!"
set "FSRING_R2_AT_CAP=!R2_AT_CAP!"
set "FSRING_R2_INVALID_UTF8=!R2_INVALID_UTF8!"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "[IO.File]::WriteAllBytes($env:FSRING_R2_OVER_CAP,[Text.Encoding]::ASCII.GetBytes('A'.PadRight(65537,'A'))); [IO.File]::WriteAllBytes($env:FSRING_R2_AT_CAP,[Text.Encoding]::ASCII.GetBytes('A'.PadRight(65536,'A'))); [IO.File]::WriteAllBytes($env:FSRING_R2_INVALID_UTF8,[byte[]](0xFF,0x0A))"
if errorlevel 1 (
  echo SELF-TEST: FAIL: bounded-reader fixtures could not be written
  exit /b 1
)
set "FSRING_LOCKED_CARGO_ATTESTATION=!R2_OVER_CAP!"
call :verify_attestation >"!R2_BOUNDS_OUTPUT!" 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: max-plus-one attestation was accepted
  exit /b 1
)
"%SystemRoot%\System32\findstr.exe" /L /C:"attestation size" "!R2_BOUNDS_OUTPUT!" >nul
if errorlevel 1 (
  type "!R2_BOUNDS_OUTPUT!"
  echo SELF-TEST: FAIL: max-plus-one attestation missed the pre-allocation byte gate
  exit /b 1
)
set "FSRING_LOCKED_CARGO_ATTESTATION=!R2_AT_CAP!"
call :verify_attestation >"!R2_BOUNDS_OUTPUT!" 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: invalid exact-cap attestation was accepted
  exit /b 1
)
"%SystemRoot%\System32\findstr.exe" /L /C:"attestation size" "!R2_BOUNDS_OUTPUT!" >nul
if not errorlevel 1 (
  type "!R2_BOUNDS_OUTPUT!"
  echo SELF-TEST: FAIL: exact-cap input was incorrectly classified as over-cap
  exit /b 1
)
set "FSRING_LOCKED_CARGO_ATTESTATION=!R2_INVALID_UTF8!"
call :verify_attestation >"!R2_BOUNDS_OUTPUT!" 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: malformed UTF-8 attestation was accepted
  exit /b 1
)
echo self-test ok: max-plus-one rejects before allocation; exact-cap and malformed UTF-8 reject safely
exit /b 0

:delete_selftest_attestation
if exist "%R2_TEST_ATTESTATION%" del /f /q "%R2_TEST_ATTESTATION%" >nul 2>&1
if exist "%R2_TEST_ATTESTATION%" exit /b 1
exit /b 0

:self_test_build_environment
setlocal EnableDelayedExpansion
set "R2_ENV_OUTPUT=%TEMP%\fsring-r2-environment-selftest.txt"
call :reject_ambient_build_environment >"!R2_ENV_OUTPUT!" 2>&1
if errorlevel 1 (
  type "!R2_ENV_OUTPUT!"
  echo SELF-TEST: FAIL: a clean package environment was rejected
  exit /b 1
)
for %%V in (
  CARGO_INCREMENTAL
  CARGO_TARGET_DIR
  RUSTC
  RUSTC_WRAPPER
  RUSTC_WORKSPACE_WRAPPER
  RUSTC_BOOTSTRAP
  CARGO_BUILD_RUSTC
  CARGO_BUILD_RUSTC_WRAPPER
  RUSTFLAGS
  CARGO_ENCODED_RUSTFLAGS
  RUSTDOCFLAGS
  CARGO_BUILD_TARGET
  CARGO_PROFILE_RELEASE_LTO
  CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER
  BINDGEN_EXTRA_CLANG_ARGS
  CC
  CXX
  AR
  RANLIB
  CFLAGS
  CXXFLAGS
  bindgen_extra_clang_args_X86_64_PC_WINDOWS_MSVC
  Cc_x86_64_pc_windows_msvc
  cXX_AARCH64_PC_WINDOWS_MSVC
  Ar_X86_64_PC_WINDOWS_MSVC
  ranlib_aarch64_pc_windows_msvc
  Cflags_X86_64_PC_WINDOWS_MSVC
  cxxflags_aarch64_pc_windows_msvc
  CL
  _CL_
  LINK
  _LINK_
) do (
  set "%%V=R2-UNTRUSTED"
)
call :reject_ambient_build_environment >"!R2_ENV_OUTPUT!" 2>&1
if not errorlevel 1 (
  echo SELF-TEST: FAIL: uncontrolled build environment was accepted
  exit /b 1
)
for %%V in (
  CARGO_INCREMENTAL
  CARGO_TARGET_DIR
  RUSTC
  RUSTC_WRAPPER
  RUSTC_WORKSPACE_WRAPPER
  RUSTC_BOOTSTRAP
  CARGO_BUILD_RUSTC
  CARGO_BUILD_RUSTC_WRAPPER
  RUSTFLAGS
  CARGO_ENCODED_RUSTFLAGS
  RUSTDOCFLAGS
  CARGO_BUILD_TARGET
  CARGO_PROFILE_RELEASE_LTO
  CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER
  BINDGEN_EXTRA_CLANG_ARGS
  CC
  CXX
  AR
  RANLIB
  CFLAGS
  CXXFLAGS
  bindgen_extra_clang_args_X86_64_PC_WINDOWS_MSVC
  Cc_x86_64_pc_windows_msvc
  cXX_AARCH64_PC_WINDOWS_MSVC
  Ar_X86_64_PC_WINDOWS_MSVC
  ranlib_aarch64_pc_windows_msvc
  Cflags_X86_64_PC_WINDOWS_MSVC
  cxxflags_aarch64_pc_windows_msvc
  CL
  _CL_
  LINK
  _LINK_
) do (
  "%SystemRoot%\System32\findstr.exe" /I /L /C:"%%V" "!R2_ENV_OUTPUT!" >nul
  if errorlevel 1 (
    type "!R2_ENV_OUTPUT!"
    echo SELF-TEST: FAIL: ambient %%V was not identified
    exit /b 1
  )
  set "%%V="
)
echo self-test ok: ambient compiler, wrapper, flags, target, target-dir, and profile overrides reject
exit /b 0

:mutate_attestation
setlocal
set "FSRING_R2_MUTATE_SOURCE=%~1"
set "FSRING_R2_MUTATE_DESTINATION=%~2"
set "FSRING_R2_MUTATE_KIND=%~3"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "& { try { $source = Get-Item -LiteralPath $env:FSRING_R2_MUTATE_SOURCE -Force; if ($source.PSIsContainer -or ($source.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $source.Length -le 0 -or $source.Length -gt 65536) { throw 'mutation source is not a bounded regular fixture' }; $utf8 = New-Object Text.UTF8Encoding($false, $true); $lines = [Collections.Generic.List[string]]::new([IO.File]::ReadAllLines($source.FullName, $utf8)); function Encode([string] $value) { return -join @($value.ToCharArray() | ForEach-Object { '{0:X4}' -f [int][char] $_ }) }; function FieldIndex([string] $name) { $prefix = $name + '='; for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i].StartsWith($prefix,[StringComparison]::Ordinal)) { return $i } }; throw ('missing fixture field ' + $name) }; $nonceIndex = FieldIndex 'nonce_utf16'; $cargoIndex = FieldIndex 'real_cargo_path_utf16'; $toolchainCargoIndex = FieldIndex 'toolchain_cargo_path_utf16'; $rustcIndex = FieldIndex 'rustc_path_utf16'; $targetIndex = FieldIndex 'target_dir_utf16'; $countIndex = FieldIndex 'argument_count'; switch -CaseSensitive ($env:FSRING_R2_MUTATE_KIND) { 'wrong-nonce' { $lines[$nonceIndex] = 'nonce_utf16=' + (Encode 'WRONG-NONCE') } 'wrong-cargo' { $lines[$cargoIndex] = 'real_cargo_path_utf16=' + (Encode 'C:\wrong\cargo.exe') } 'wrong-toolchain-cargo' { $lines[$toolchainCargoIndex] = 'toolchain_cargo_path_utf16=' + (Encode 'C:\wrong\actual-cargo.exe') } 'wrong-rustc' { $lines[$rustcIndex] = 'rustc_path_utf16=' + (Encode 'C:\wrong\rustc.exe') } 'wrong-target' { $lines[$targetIndex] = 'target_dir_utf16=' + (Encode 'C:\wrong\target') } 'missing-target' { $lines.RemoveAt($targetIndex) } 'duplicate-target' { $lines.Insert($targetIndex + 1,$lines[$targetIndex]) } 'malformed' { $lines[$nonceIndex] = 'nonce_utf16=0' } 'oversized-field' { $lines[$nonceIndex] = 'nonce_utf16=' + (-join @('0041' * 2049)) } 'oversized-count' { $lines[$countIndex] = 'argument_count=65' } 'extra' { $lines.Add('extra=1') } 'duplicate-field' { $lines.Insert($nonceIndex + 1,$lines[$nonceIndex]) } 'wrong-first' { $lines[$countIndex + 1] = 'argument_0000_utf16=' + (Encode 'wrong') } 'missing-suffix' { $count = [int] $lines[$countIndex].Substring('argument_count='.Length); $lines[$countIndex] = 'argument_count=' + ($count - 1); $lines.RemoveAt($lines.Count - 1) } 'reordered-suffix' { $last = $lines[$lines.Count - 1]; $lines[$lines.Count - 1] = $lines[$lines.Count - 2]; $lines[$lines.Count - 2] = $last } 'duplicated-suffix' { $count = [int] $lines[$countIndex].Substring('argument_count='.Length); $lines[$countIndex] = 'argument_count=' + ($count + 1); $lines.Add(('argument_{0:D4}_utf16=' -f $count) + (Encode '--offline')) } default { throw 'unknown mutation' } }; [IO.File]::WriteAllText($env:FSRING_R2_MUTATE_DESTINATION,([string]::Join(\"`n\",$lines) + \"`n\"),$utf8); exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 } }"
exit /b %ERRORLEVEL%
:c4_verify_frozen_roles
rem Refuse before anything runs if a role the gate named is missing or its bytes
rem drifted. The three roles below are the ones this file launches directly; the
rem runner's own literal per-row map is the oracle for which roles are allowed.
if not defined FSRING_C4_TOOL_POWERSHELL (
  echo FAIL: the C4 source gate supplied no frozen PowerShell.
  exit /b 1
)
if not defined FSRING_C4_TOOL_PYTHON (
  echo FAIL: the C4 source gate supplied no frozen Python.
  exit /b 1
)
if not defined FSRING_C4_TOOL_GIT_BASH (
  echo FAIL: the C4 source gate supplied no frozen Git Bash.
  exit /b 1
)
"%FSRING_C4_TOOL_POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -Command "$bad = @(); foreach ($entry in [Environment]::GetEnvironmentVariables().Keys) { $name = [string]$entry; if (-not $name.StartsWith('FSRING_C4_TOOL_')) { continue }; if ($name.EndsWith('_SHA256') -or $name.EndsWith('_VOLUME') -or $name.EndsWith('_FILEID')) { continue }; $path = [Environment]::GetEnvironmentVariable($name); $expected = [Environment]::GetEnvironmentVariable($name + '_SHA256'); if ([string]::IsNullOrWhiteSpace($expected)) { $bad += ($name + ': no frozen SHA-256'); continue }; if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $bad += ($name + ': absent'); continue }; $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(); if ($actual -cne $expected) { $bad += ($name + ': SHA-256 drifted') } }; if ($bad.Count -ne 0) { foreach ($b in $bad) { [Console]::Error.WriteLine('FAIL: ' + $b) }; exit 1 }; exit 0"
exit /b %ERRORLEVEL%



:c4_selftest_launch_coverage
rem Every launch of a frozen payload must record itself, or rows 19 and 20
rem seal a launch count smaller than the truth.
rem
rem This is not decoration. The runner's expected counts were MEASURED from an
rem instrumented run of this file, so a site that forgot its note would lower
rem both the measurement and the expectation together and agree with itself.
rem This check is the one thing in the loop that does not derive from the run.
rem
rem It is a check on the TEXT: every literal launch site of the three roles
rem this file launches directly. It cannot see a launch built at run time, and
rem it says nothing about Cargo, which arrives through the Rustup selector
rem rather than a FSRING_C4_TOOL_* variable. The floor of 60 sites is here so
rem that a scanner which silently stopped matching -- a renamed variable, a
rem reflowed line -- fails loudly instead of reporting universal compliance
rem across zero sites.
setlocal
set "FSRING_R2_COVERAGE_FILE=%~f0"
call :c4_note_launch powershell
"%FSRING_C4_PS%" -NoProfile -Command "$q=[string][char]34; $pc=[string][char]37; $bt=[string][char]96; $f=$env:FSRING_R2_COVERAGE_FILE; $lines=[IO.File]::ReadAllLines($f); $map=[ordered]@{}; $map.Add('FSRING_C4_PS','powershell'); $map.Add('FSRING_C4_PY','python'); $map.Add('FSRING_BASH','git-bash'); $bad=@(); $sites=0; for ($i=0; $i -lt $lines.Length; $i++) { $t=$lines[$i].Trim(); if ($t.StartsWith('rem ')) { continue } $role=$null; foreach ($k in $map.Keys) { $tok=$q+$pc+$k+$pc+$q; if ($t.StartsWith($tok+' ')) { $role=$map[$k]; break } if ($t -match ('^for /f .*\('+$bt+'call '+[regex]::Escape($tok)+' ')) { $role=$map[$k]; break } } if ($null -eq $role) { if ($t -match '^(powershell|python)(\.exe)?\s') { $bad+=('line '+($i+1)+': ambient '+$matches[1]+' launch where the gate supplies a frozen payload') } continue } $sites++; $j=$i-1; while ($j -ge 0 -and $lines[$j].Trim() -eq '') { $j-- } $prev=''; if ($j -ge 0) { $prev=$lines[$j].Trim() } if ($prev -cne ('call :c4_note_launch '+$role)) { $bad+=('line '+($i+1)+': launch of '+$role+' does not record its launch') } } if ($sites -lt 60) { $bad+=('only '+$sites+' launch sites were found; the scanner has stopped matching') } if ($bad.Count -gt 0) { foreach ($b in $bad) { [Console]::Out.Write('COVERAGE: '+$b+[char]10) }; exit 1 } [Console]::Out.Write('self-test ok: all '+$sites+' frozen-payload launch sites record their launch'+[char]10); exit 0"
if errorlevel 1 (
  echo SELF-TEST: FAIL: a frozen-payload launch site does not record its launch
  endlocal
  exit /b 1
)
endlocal
exit /b 0
:c4_note_launch
rem Record one launch of a frozen role for the POST marker's launchCounts.
rem
rem WHY A JOURNAL FILE. The wrapper at the top of this file re-enters the
rem script to make the POST marker unconditional, and withholds the nonce from
rem the re-entered body. A counter kept in a variable would also have to
rem survive that re-entry and every SETLOCAL below it; a file does, and the
rem path is DERIVED from FSRING_C4_COMMAND_ID -- which survives, as
rem :c4_require_frozen_clippy already relies on -- so no new name reaches a
rem child and the closed FSRING_C4_TOOL_* set is unchanged.
rem
rem WHY THIS IS NOT THE WHOLE MECHANISM. The oracle numbers in the runner are
rem derived from an instrumented run of this file, so a launch site that
rem forgot its note would simply produce a smaller number that then gets
rem frozen as though it were the truth. `:c4_selftest_launch_coverage` below
rem is the independent check: it reads this file and refuses if any launch of
rem a frozen payload is missing its note.
rem
rem NOT COUNTED, deliberately: the launches `:c4_emit_marker` and
rem `:c4_verify_frozen_roles` make themselves. They are the gate's own
rem bookkeeping rather than the row's work, and counting the marker's own
rem PowerShell inside the marker it is emitting is circular. The CRLF
rem preflight on line 4 runs before any frozen role is bound and launches the
rem system PowerShell by absolute path; it is not a frozen-payload launch.
if not defined FSRING_C4_COMMAND_ID exit /b 0
>>"%TEMP%\fsring-c4-launch-%FSRING_C4_COMMAND_ID%.txt" echo %~1
exit /b 0

:c4_reset_launch_journal
rem Start the row's journal empty, and prove it is writable BEFORE the row
rem runs. An unwritable journal would undercount silently, which is the one
rem failure mode this mechanism must not have.
if not defined FSRING_C4_COMMAND_ID exit /b 0
del /f /q "%TEMP%\fsring-c4-launch-%FSRING_C4_COMMAND_ID%.txt" >nul 2>&1
break > "%TEMP%\fsring-c4-launch-%FSRING_C4_COMMAND_ID%.txt"
if not exist "%TEMP%\fsring-c4-launch-%FSRING_C4_COMMAND_ID%.txt" (
  echo FAIL: the C4 launch journal could not be created under TEMP.
  exit /b 1
)
exit /b 0
:c4_emit_marker
rem One sentinel-prefixed canonical line per phase. `path` and `sha256` are read
rem here from the file this run would launch; the two native identity fields are
rem echoed from the freeze, because batch cannot read an NTFS volume serial.
set "FSRING_C4_MARKER_PHASE=%~1"
"%FSRING_C4_TOOL_POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -Command "$q=[string][char]34; $order=@('powershell','python','git','git-bash','cmd','cargo-1.82.0','rustc-1.82.0','rustdoc-1.82.0','cargo-fmt-1.82.0','rustfmt-1.82.0','cargo-1.85.0','rustc-1.85.0','rustdoc-1.85.0','cargo-fmt-1.85.0','rustfmt-1.85.0','cargo-clippy-1.85.0','clippy-driver-1.85.0','cargo-wdk-0.1.1','infverif','signtool'); $rows=@(); foreach ($role in $order) { $suffix=$role.ToUpperInvariant().Replace('-','_').Replace('.','_'); $path=[Environment]::GetEnvironmentVariable('FSRING_C4_TOOL_'+$suffix); if ([string]::IsNullOrWhiteSpace($path)) { continue }; $sha=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(); $p=$path.Replace('\','\\').Replace($q,'\'+$q); $vol=[Environment]::GetEnvironmentVariable('FSRING_C4_TOOL_'+$suffix+'_VOLUME'); $fid=[Environment]::GetEnvironmentVariable('FSRING_C4_TOOL_'+$suffix+'_FILEID'); $rows+=('{'+$q+'role'+$q+':'+$q+$role+$q+','+$q+'path'+$q+':'+$q+$p+$q+','+$q+'volumeSerial'+$q+':'+$q+$vol+$q+','+$q+'fileId'+$q+':'+$q+$fid+$q+','+$q+'sha256'+$q+':'+$q+$sha+$q+'}') }; $counts=@(); $cid=$env:FSRING_C4_COMMAND_ID; if ($cid) { $jp=$env:TEMP+'\fsring-c4-launch-'+$cid+'.txt'; if (Test-Path -LiteralPath $jp) { $seen=@{}; foreach ($ln in [IO.File]::ReadAllLines($jp)) { $r=$ln.Trim(); if ($r) { $seen[$r]=1+[int]$seen[$r] } }; foreach ($role in $order) { if ($seen.ContainsKey($role)) { $counts+=('{'+$q+'role'+$q+':'+$q+$role+$q+','+$q+'count'+$q+':'+[string]$seen[$role]+'}') } } } }; $t='FSRING-C4-NESTED-TOOLS {'+$q+'schema'+$q+':'+$q+'fsring-c4-nested-tools-marker/v1'+$q+','+$q+'version'+$q+':1,'+$q+'nonce'+$q+':'+$q+$env:FSRING_C4_MARKER_NONCE+$q+','+$q+'phase'+$q+':'+$q+$env:FSRING_C4_MARKER_PHASE+$q+','+$q+'commandId'+$q+':'+$q+$env:FSRING_C4_COMMAND_ID+$q+','+$q+'tools'+$q+':['+($rows -join ',')+'],'+$q+'launchCounts'+$q+':['+($counts -join ',')+']}'; [Console]::Out.Write($t+[char]10); [Console]::Out.Flush()"
exit /b 0
