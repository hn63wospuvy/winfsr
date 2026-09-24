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
if /I "%~1"=="--self-test" goto :SELF_TEST
rem Run one command inside a Visual Studio developer environment.
rem
rem   ordinary: _in_devenv.cmd <amd64|arm64> "<full command line>"
rem   package:  _in_devenv.cmd <amd64|arm64> __fsring_locked_wdk__
rem   metadata: _in_devenv.cmd amd64 __fsring_locked_metadata__
rem   shim:     _in_devenv.cmd amd64 __fsring_compile_locked_cargo__
rem   shim test:_in_devenv.cmd amd64 __fsring_test_locked_cargo_sha256__
rem
rem An ordinary command is ONE quoted argument, not a token list, for two
rem reasons cmd forces on us: a comma is a token delimiter, so an unquoted
rem `--features a,b` arrives split in half; and %2..%9 silently drops the tenth
rem token onward, which quietly truncated `-- -D warnings` into `-- -D`.
rem
rem The package token is deliberately not another quoted command. Its executable
rem and optional target architecture arrive in validated environment variables.
rem The fsring-fsd workspace member is the package working directory.
setlocal
set "LOCKED_WDK_MODE="
set "LOCKED_METADATA_MODE="
set "COMPILE_LOCKED_CARGO_MODE="
set "TEST_LOCKED_CARGO_MODE="
if /I "%~2"=="__fsring_locked_wdk__" set "LOCKED_WDK_MODE=1"
if /I "%~2"=="__fsring_locked_metadata__" set "LOCKED_METADATA_MODE=1"
if /I "%~2"=="__fsring_compile_locked_cargo__" set "COMPILE_LOCKED_CARGO_MODE=1"
if /I "%~2"=="__fsring_test_locked_cargo_sha256__" set "TEST_LOCKED_CARGO_MODE=1"
set "VSDEV=%ProgramFiles%\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
if not exist "%VSDEV%" (
  echo FAIL: VsDevCmd.bat not found at "%VSDEV%"
  exit /b 2
)
call "%VSDEV%" -arch=%~1 -host_arch=amd64 >nul 2>&1
set "LIBCLANG_PATH=%ProgramFiles%\LLVM\bin"
if defined TEST_LOCKED_CARGO_MODE goto :TEST_LOCKED_CARGO_SHA256
if defined COMPILE_LOCKED_CARGO_MODE goto :COMPILE_LOCKED_CARGO
if defined LOCKED_WDK_MODE goto :LOCKED_WDK
if defined LOCKED_METADATA_MODE goto :LOCKED_WDK
call :CONFIGURE_ORDINARY_PATH
cd /d "%~dp0.."
%~2
exit /b %ERRORLEVEL%

:COMPILE_LOCKED_CARGO
if /I not "%~1"=="amd64" (
  echo FAIL: native locked-Cargo shim compilation requires the amd64 developer environment.
  exit /b 2
)
if not defined FSRING_RUSTC (
  echo FAIL: native locked-Cargo shim compilation requires FSRING_RUSTC.
  exit /b 2
)
if not defined FSRING_LOCKED_CARGO_SOURCE (
  echo FAIL: native locked-Cargo shim compilation requires FSRING_LOCKED_CARGO_SOURCE.
  exit /b 2
)
if not defined FSRING_LOCKED_CARGO_EXE (
  echo FAIL: native locked-Cargo shim compilation requires FSRING_LOCKED_CARGO_EXE.
  exit /b 2
)
if not exist "%FSRING_RUSTC%" (
  echo FAIL: exact rustc executable is missing: "%FSRING_RUSTC%".
  exit /b 2
)
if not exist "%FSRING_LOCKED_CARGO_SOURCE%" (
  echo FAIL: native locked-Cargo shim source is missing: "%FSRING_LOCKED_CARGO_SOURCE%".
  exit /b 2
)
"%FSRING_RUSTC%" --edition=2021 -C opt-level=2 -C panic=abort --crate-name fsring_locked_cargo -o "%FSRING_LOCKED_CARGO_EXE%" "%FSRING_LOCKED_CARGO_SOURCE%"
exit /b %ERRORLEVEL%

:TEST_LOCKED_CARGO_SHA256
if /I not "%~1"=="amd64" (
  echo FAIL: native locked-Cargo SHA-256 tests require the amd64 developer environment.
  exit /b 2
)
if not defined FSRING_RUSTC (
  echo FAIL: native locked-Cargo SHA-256 tests require FSRING_RUSTC.
  exit /b 2
)
if not defined FSRING_LOCKED_CARGO_SOURCE (
  echo FAIL: native locked-Cargo SHA-256 tests require FSRING_LOCKED_CARGO_SOURCE.
  exit /b 2
)
if not defined FSRING_LOCKED_CARGO_DIR (
  echo FAIL: native locked-Cargo SHA-256 tests require FSRING_LOCKED_CARGO_DIR.
  exit /b 2
)
if not defined FSRING_LOCKED_CARGO_TEST_EXE (
  echo FAIL: native locked-Cargo SHA-256 tests require FSRING_LOCKED_CARGO_TEST_EXE.
  exit /b 2
)
if not defined FSRING_LOCKED_CARGO_TEST_PDB (
  echo FAIL: native locked-Cargo SHA-256 tests require FSRING_LOCKED_CARGO_TEST_PDB.
  exit /b 2
)
if not defined FSRING_NATIVE_DIRECTORY_GATE (
  echo FAIL: native locked-Cargo SHA-256 tests require FSRING_NATIVE_DIRECTORY_GATE.
  exit /b 2
)
if not defined NATIVE_DIRECTORY_GATE_HASH (
  echo FAIL: native locked-Cargo SHA-256 tests require NATIVE_DIRECTORY_GATE_HASH.
  exit /b 2
)
if not exist "%FSRING_RUSTC%" (
  echo FAIL: exact rustc executable is missing: "%FSRING_RUSTC%".
  exit /b 2
)
if not exist "%FSRING_LOCKED_CARGO_SOURCE%" (
  echo FAIL: native locked-Cargo shim source is missing: "%FSRING_LOCKED_CARGO_SOURCE%".
  exit /b 2
)
if not exist "%FSRING_NATIVE_DIRECTORY_GATE%" (
  echo FAIL: tracked native-directory gate is missing: "%FSRING_NATIVE_DIRECTORY_GATE%".
  exit /b 2
)
if /I not "%FSRING_LOCKED_CARGO_TEST_EXE%"=="%FSRING_LOCKED_CARGO_DIR%\sha256-tests.exe" (
  echo FAIL: native locked-Cargo SHA-256 test executable is not in the fresh app directory.
  exit /b 2
)
if /I not "%FSRING_LOCKED_CARGO_TEST_PDB%"=="%FSRING_LOCKED_CARGO_DIR%\sha256-tests.pdb" (
  echo FAIL: native locked-Cargo SHA-256 test PDB is not in the fresh app directory.
  exit /b 2
)
if exist "%FSRING_LOCKED_CARGO_TEST_EXE%" (
  echo FAIL: native locked-Cargo SHA-256 test executable already exists.
  exit /b 2
)
if exist "%FSRING_LOCKED_CARGO_TEST_PDB%" (
  echo FAIL: native locked-Cargo SHA-256 test PDB already exists.
  exit /b 2
)
set "FSRING_R2_GATE_PATH=%FSRING_NATIVE_DIRECTORY_GATE%"
set "FSRING_R2_GATE_EXPECTED_HASH=%NATIVE_DIRECTORY_GATE_HASH%"
powershell.exe -NoProfile -Command "$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $env:FSRING_R2_GATE_PATH).Hash.ToUpperInvariant(); if ($hash -cne $env:FSRING_R2_GATE_EXPECTED_HASH) { exit 1 }"
if errorlevel 1 (
  echo FAIL: tracked native-directory gate changed before SHA-256 test compilation.
  exit /b 2
)
"%FSRING_RUSTC%" --test --edition=2021 -C opt-level=2 -C debuginfo=0 --crate-name fsring_locked_cargo_tests -o "%FSRING_LOCKED_CARGO_TEST_EXE%" "%FSRING_LOCKED_CARGO_SOURCE%"
if errorlevel 1 exit /b %ERRORLEVEL%
set "FSRING_R2_ALLOWED_NAMES=sha256-tests.exe;sha256-tests.pdb"
set "FSRING_R2_REQUIRED_NAMES=sha256-tests.exe"
powershell.exe -NoProfile -Command "$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $env:FSRING_R2_GATE_PATH).Hash.ToUpperInvariant(); if ($hash -cne $env:FSRING_R2_GATE_EXPECTED_HASH) { exit 1 }"
if errorlevel 1 (
  echo FAIL: tracked native-directory gate changed during SHA-256 test compilation.
  exit /b 2
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%FSRING_NATIVE_DIRECTORY_GATE%" -Mode Check -Directory "%FSRING_LOCKED_CARGO_DIR%"
if errorlevel 1 (
  echo FAIL: SHA-256 test application directory is not closed immediately before launch.
  exit /b 2
)
powershell.exe -NoProfile -Command "$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $env:FSRING_R2_GATE_PATH).Hash.ToUpperInvariant(); if ($hash -cne $env:FSRING_R2_GATE_EXPECTED_HASH) { exit 1 }"
if errorlevel 1 (
  echo FAIL: tracked native-directory gate changed during the SHA-256 prelaunch check.
  exit /b 2
)
"%FSRING_LOCKED_CARGO_TEST_EXE%" --test-threads=1
set "FSRING_SHA256_TEST_RC=%ERRORLEVEL%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%FSRING_NATIVE_DIRECTORY_GATE%" -Mode Check -Directory "%FSRING_LOCKED_CARGO_DIR%"
if errorlevel 1 (
  echo FAIL: SHA-256 tests left an unapproved app-local input.
  exit /b 2
)
powershell.exe -NoProfile -Command "$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $env:FSRING_R2_GATE_PATH).Hash.ToUpperInvariant(); if ($hash -cne $env:FSRING_R2_GATE_EXPECTED_HASH) { exit 1 }"
if errorlevel 1 (
  echo FAIL: tracked native-directory gate changed during SHA-256 test execution.
  exit /b 2
)
exit /b %FSRING_SHA256_TEST_RC%

:LOCKED_WDK
if not defined FSRING_REAL_CARGO (
  echo FAIL: locked cargo-wdk mode requires FSRING_REAL_CARGO.
  exit /b 2
)
if defined LOCKED_WDK_MODE if not defined FSRING_CARGO_WDK (
  echo FAIL: locked cargo-wdk mode requires FSRING_CARGO_WDK.
  exit /b 2
)
if defined LOCKED_WDK_MODE if not defined FSRING_LOCKED_CARGO_EXE (
  echo FAIL: locked cargo-wdk mode requires FSRING_LOCKED_CARGO_EXE.
  exit /b 2
)
if not defined FSRING_LOCKED_CARGO_TARGET_DIR (
  echo FAIL: locked cargo-wdk mode requires FSRING_LOCKED_CARGO_TARGET_DIR.
  exit /b 2
)
if not defined FSRING_RUSTC (
  echo FAIL: locked cargo-wdk mode requires FSRING_RUSTC.
  exit /b 2
)
if not defined FSRING_TOOLCHAIN_CARGO (
  echo FAIL: locked cargo-wdk mode requires FSRING_TOOLCHAIN_CARGO.
  exit /b 2
)
if not defined FSRING_RUSTUP_HOME (
  echo FAIL: locked cargo-wdk mode requires FSRING_RUSTUP_HOME.
  exit /b 2
)
call :REQUIRE_ROOTED_FILE "%FSRING_REAL_CARGO%"
if errorlevel 1 (echo FAIL: exact real Cargo must be an absolute existing file. & exit /b 2)
if defined LOCKED_WDK_MODE call :REQUIRE_ROOTED_FILE "%FSRING_CARGO_WDK%"
if defined LOCKED_WDK_MODE if errorlevel 1 (echo FAIL: cargo-wdk must be an absolute existing file. & exit /b 2)
if defined LOCKED_WDK_MODE call :REQUIRE_ROOTED_FILE "%FSRING_LOCKED_CARGO_EXE%"
if defined LOCKED_WDK_MODE if errorlevel 1 (echo FAIL: native Cargo shim must be an absolute existing file. & exit /b 2)
call :REQUIRE_ROOTED_FILE "%FSRING_RUSTC%"
if errorlevel 1 (echo FAIL: exact rustc must be an absolute existing file. & exit /b 2)
call :REQUIRE_ROOTED_FILE "%FSRING_TOOLCHAIN_CARGO%"
if errorlevel 1 (echo FAIL: actual toolchain Cargo must be an absolute existing file. & exit /b 2)
call :REQUIRE_ROOTED_DIRECTORY "%FSRING_LOCKED_CARGO_TARGET_DIR%"
if errorlevel 1 (echo FAIL: controlled Cargo target must be an absolute existing directory. & exit /b 2)
call :REQUIRE_ROOTED_DIRECTORY "%FSRING_RUSTUP_HOME%"
if errorlevel 1 (echo FAIL: exact rustup home must be an absolute existing directory. & exit /b 2)
call :CONFIGURE_LOCKED_PATH
if errorlevel 1 (
  echo devenv self-test FAIL: locked PATH helper was not callable
  exit /b 1
)
cd /d "%~dp0..\fsring-fsd"
if defined LOCKED_METADATA_MODE goto :LOCKED_METADATA
if /I "%FSRING_CARGO_WDK_TARGET_ARCH%"=="arm64" goto :LOCKED_WDK_ARM64
if defined FSRING_CARGO_WDK_TARGET_ARCH (
  echo FAIL: unsupported cargo-wdk target architecture "%FSRING_CARGO_WDK_TARGET_ARCH%".
  exit /b 2
)
if /I not "%~1"=="amd64" (
  echo FAIL: x64 cargo-wdk mode requires the amd64 developer environment.
  exit /b 2
)
call :LOCKED_SELECTOR_CLOSURE
if errorlevel 1 (
  echo FAIL: x64 cargo-wdk selector closure failed immediately before launch.
  exit /b 2
)
"%FSRING_CARGO_WDK%" build --profile release --target-arch amd64
set "FSRING_LOCKED_CHILD_RC=%ERRORLEVEL%"
call :LOCKED_SELECTOR_CLOSURE
if errorlevel 1 (
  echo FAIL: x64 cargo-wdk selector closure failed immediately after launch.
  exit /b 2
)
exit /b %FSRING_LOCKED_CHILD_RC%

:LOCKED_WDK_ARM64
if /I not "%~1"=="arm64" (
  echo FAIL: ARM64 cargo-wdk mode requires the arm64 developer environment.
  exit /b 2
)
call :LOCKED_SELECTOR_CLOSURE
if errorlevel 1 (
  echo FAIL: ARM64 cargo-wdk selector closure failed immediately before launch.
  exit /b 2
)
"%FSRING_CARGO_WDK%" build --profile release --target-arch arm64
set "FSRING_LOCKED_CHILD_RC=%ERRORLEVEL%"
call :LOCKED_SELECTOR_CLOSURE
if errorlevel 1 (
  echo FAIL: ARM64 cargo-wdk selector closure failed immediately after launch.
  exit /b 2
)
exit /b %FSRING_LOCKED_CHILD_RC%

:LOCKED_METADATA
if not defined FSRING_METADATA_OUTPUT (
  echo FAIL: locked metadata mode requires FSRING_METADATA_OUTPUT.
  exit /b 2
)
for %%I in ("%FSRING_METADATA_OUTPUT%") do if not "%%~fI"=="%FSRING_METADATA_OUTPUT%" (
  echo FAIL: locked metadata output must be an absolute normalized path.
  exit /b 2
)
call :LOCKED_SELECTOR_CLOSURE
if errorlevel 1 (
  echo FAIL: locked metadata selector closure failed immediately before launch.
  exit /b 2
)
"%FSRING_REAL_CARGO%" +1.85.0 metadata --manifest-path "%CD%\Cargo.toml" --format-version 1 --no-deps --locked --offline > "%FSRING_METADATA_OUTPUT%"
set "FSRING_LOCKED_CHILD_RC=%ERRORLEVEL%"
call :LOCKED_SELECTOR_CLOSURE
if errorlevel 1 (
  echo FAIL: locked metadata selector closure failed immediately after launch.
  exit /b 2
)
exit /b %FSRING_LOCKED_CHILD_RC%

:LOCKED_SELECTOR_CLOSURE
setlocal
for %%V in (
  FSRING_NATIVE_DIRECTORY_GATE
  NATIVE_DIRECTORY_GATE_HASH
  FSRING_RUSTUP_PROXY_SOURCE
  FSRING_RUSTUP_PROXY_SOURCE_SHA256
  FSRING_RUSTUP_SELECTOR_DIR
  FSRING_REAL_CARGO
  FSRING_REAL_CARGO_SHA256
  FSRING_RUSTUP_SELECTOR_RUSTC
  FSRING_RUSTUP_SELECTOR_RUSTC_SHA256
) do if not defined %%V (
  echo LOCKED-SELECTOR: FAIL: %%V is required.
  exit /b 1
)
if not exist "%FSRING_NATIVE_DIRECTORY_GATE%" (
  echo LOCKED-SELECTOR: FAIL: tracked native-directory gate is missing.
  exit /b 1
)
set "FSRING_R2_GATE_PATH=%FSRING_NATIVE_DIRECTORY_GATE%"
set "FSRING_R2_GATE_EXPECTED_HASH=%NATIVE_DIRECTORY_GATE_HASH%"
powershell.exe -NoProfile -Command "$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $env:FSRING_R2_GATE_PATH).Hash.ToUpperInvariant(); if ($hash -cne $env:FSRING_R2_GATE_EXPECTED_HASH) { exit 1 }"
if errorlevel 1 (
  echo LOCKED-SELECTOR: FAIL: tracked native-directory gate changed before selector closure.
  exit /b 1
)
set "FSRING_R2_ALLOWED_NAMES=cargo.exe;rustc.exe"
set "FSRING_R2_REQUIRED_NAMES=cargo.exe;rustc.exe"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%FSRING_NATIVE_DIRECTORY_GATE%" -Mode Check -Directory "%FSRING_RUSTUP_SELECTOR_DIR%"
if errorlevel 1 (
  echo LOCKED-SELECTOR: FAIL: selector directory identity or exact allowlist is invalid.
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%FSRING_NATIVE_DIRECTORY_GATE%" -Mode CheckIdentity -Kind File -Path "%FSRING_RUSTUP_PROXY_SOURCE%"
if errorlevel 1 (
  echo LOCKED-SELECTOR: FAIL: canonical rustup.exe source identity is invalid.
  exit /b 1
)
powershell.exe -NoProfile -Command "& { try { $source = [IO.Path]::GetFullPath($env:FSRING_RUSTUP_PROXY_SOURCE); $selector = [IO.Path]::GetFullPath($env:FSRING_RUSTUP_SELECTOR_DIR).TrimEnd('\'); $cargo = [IO.Path]::GetFullPath($env:FSRING_REAL_CARGO); $rustc = [IO.Path]::GetFullPath($env:FSRING_RUSTUP_SELECTOR_RUSTC); if (-not [string]::Equals($source,$env:FSRING_RUSTUP_PROXY_SOURCE,[StringComparison]::OrdinalIgnoreCase) -or -not [string]::Equals($selector,$env:FSRING_RUSTUP_SELECTOR_DIR,[StringComparison]::OrdinalIgnoreCase) -or -not [string]::Equals($cargo,$env:FSRING_REAL_CARGO,[StringComparison]::OrdinalIgnoreCase) -or -not [string]::Equals($rustc,$env:FSRING_RUSTUP_SELECTOR_RUSTC,[StringComparison]::OrdinalIgnoreCase)) { throw 'paths are not absolute and normalized' }; if ([IO.Path]::GetFileName($source) -ine 'rustup.exe' -or [IO.Path]::GetFileName($cargo) -ine 'cargo.exe' -or [IO.Path]::GetFileName($rustc) -ine 'rustc.exe' -or -not [string]::Equals([IO.Path]::GetDirectoryName($cargo),$selector,[StringComparison]::OrdinalIgnoreCase) -or -not [string]::Equals([IO.Path]::GetDirectoryName($rustc),$selector,[StringComparison]::OrdinalIgnoreCase) -or [string]::Equals([IO.Path]::GetDirectoryName($source),$selector,[StringComparison]::OrdinalIgnoreCase)) { throw 'selector parent/name relationship' }; $hashes = @($env:FSRING_RUSTUP_PROXY_SOURCE_SHA256,$env:FSRING_REAL_CARGO_SHA256,$env:FSRING_RUSTUP_SELECTOR_RUSTC_SHA256); if (@($hashes | Where-Object { $_ -cnotmatch '^[0-9A-F]{64}$' }).Count -ne 0 -or $hashes[0] -cne $hashes[1] -or $hashes[0] -cne $hashes[2]) { throw 'selector expected hashes' }; if ((Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash.ToUpperInvariant() -cne $hashes[0] -or (Get-FileHash -Algorithm SHA256 -LiteralPath $cargo).Hash.ToUpperInvariant() -cne $hashes[1] -or (Get-FileHash -Algorithm SHA256 -LiteralPath $rustc).Hash.ToUpperInvariant() -cne $hashes[2]) { throw 'selector file hashes' }; exit 0 } catch { [Console]::Error.WriteLine('LOCKED-SELECTOR: FAIL: ' + $_.Exception.Message); exit 1 } }"
if errorlevel 1 exit /b 1
powershell.exe -NoProfile -Command "$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $env:FSRING_R2_GATE_PATH).Hash.ToUpperInvariant(); if ($hash -cne $env:FSRING_R2_GATE_EXPECTED_HASH) { exit 1 }"
if errorlevel 1 (
  echo LOCKED-SELECTOR: FAIL: tracked native-directory gate changed during selector closure.
  exit /b 1
)
exit /b 0

:CONFIGURE_ORDINARY_PATH
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
exit /b 0

:CONFIGURE_LOCKED_PATH
for %%I in ("%FSRING_LOCKED_CARGO_EXE%") do set "FSRING_LOCKED_CARGO_DIR=%%~dpI"
for /f "tokens=1 delims==" %%V in ('set CARGO_ 2^>nul') do set "%%V="
set "RUSTC_WRAPPER="
set "RUSTC_WORKSPACE_WRAPPER="
set "RUSTC_BOOTSTRAP="
set "CARGO_BUILD_RUSTC="
set "CARGO_BUILD_RUSTC_WRAPPER="
set "RUSTFLAGS="
set "CARGO_ENCODED_RUSTFLAGS="
set "CARGO_BUILD_TARGET="
set "CARGO_BUILD_PROFILE="
set "CARGO_HOME="
set "RUSTDOCFLAGS="
set "RUSTDOC="
set "BINDGEN_EXTRA_CLANG_ARGS="
set "CC="
set "CXX="
set "AR="
set "RANLIB="
set "CFLAGS="
set "CXXFLAGS="
for %%P in (CC_ CXX_ AR_ RANLIB_ CFLAGS_ CXXFLAGS_ BINDGEN_EXTRA_CLANG_ARGS_) do for /f "tokens=1 delims==" %%V in ('set %%P 2^>nul') do set "%%V="
set "CL="
set "_CL_="
set "LINK="
set "_LINK_="
set "CARGO=%FSRING_REAL_CARGO%"
set "RUSTC=%FSRING_RUSTC%"
set "CARGO_TARGET_DIR=%FSRING_LOCKED_CARGO_TARGET_DIR%"
set "RUSTUP_HOME=%FSRING_RUSTUP_HOME%"
set "RUSTUP_TOOLCHAIN=1.85.0"
set "CARGO_NET_OFFLINE=true"
set "PATH=%FSRING_LOCKED_CARGO_DIR%;%PATH%"
exit /b 0

:REQUIRE_ROOTED_FILE
set "FSRING_DEVENV_VALIDATE_PATH=%~1"
powershell.exe -NoProfile -Command "if (-not [IO.Path]::IsPathRooted($env:FSRING_DEVENV_VALIDATE_PATH) -or -not (Test-Path -LiteralPath $env:FSRING_DEVENV_VALIDATE_PATH -PathType Leaf)) { exit 1 }"
exit /b %ERRORLEVEL%

:REQUIRE_ROOTED_DIRECTORY
set "FSRING_DEVENV_VALIDATE_PATH=%~1"
powershell.exe -NoProfile -Command "if (-not [IO.Path]::IsPathRooted($env:FSRING_DEVENV_VALIDATE_PATH) -or -not (Test-Path -LiteralPath $env:FSRING_DEVENV_VALIDATE_PATH -PathType Container)) { exit 1 }"
exit /b %ERRORLEVEL%

:SELF_TEST
setlocal EnableDelayedExpansion
set "R2_NATIVE_DIR=%~2"
set "R2_REAL_CARGO=%~3"
set "R2_TARGET_DIR=%~4"
set "R2_RUSTC=%~5"
set "R2_RUSTUP_HOME=%~6"
set "R2_TOOLCHAIN_CARGO=%~7"
if not defined R2_NATIVE_DIR (
  echo devenv self-test FAIL: generated native shim directory is absent
  exit /b 1
)
if not exist "!R2_NATIVE_DIR!\cargo.exe" (
  echo devenv self-test FAIL: generated native cargo.exe is absent
  exit /b 1
)
if not defined R2_REAL_CARGO (
  echo devenv self-test FAIL: exact real Cargo path is absent
  exit /b 1
)
if not defined R2_TARGET_DIR (
  echo devenv self-test FAIL: controlled target directory is absent
  exit /b 1
)
if not defined R2_RUSTC (
  echo devenv self-test FAIL: exact rustc path is absent
  exit /b 1
)
if not defined R2_RUSTUP_HOME (
  echo devenv self-test FAIL: exact rustup home is absent
  exit /b 1
)
if not defined R2_TOOLCHAIN_CARGO (
  echo devenv self-test FAIL: actual toolchain Cargo is absent
  exit /b 1
)
set "R2_BASE_PATH=C:\r2-real-cargo-one;C:\r2-tools;C:\r2-real-cargo-two"
set "PATH=!R2_BASE_PATH!"
set "FSRING_LOCKED_CARGO_EXE=!R2_NATIVE_DIR!\cargo.exe"
set "FSRING_REAL_CARGO=!R2_REAL_CARGO!"
set "FSRING_RUSTC=!R2_RUSTC!"
set "FSRING_RUSTUP_HOME=!R2_RUSTUP_HOME!"
set "FSRING_TOOLCHAIN_CARGO=!R2_TOOLCHAIN_CARGO!"
set "FSRING_LOCKED_CARGO_TARGET_DIR=!R2_TARGET_DIR!"
set "CARGO_TARGET_DIR=C:\r2-untrusted-target"
set "RUSTC=C:\r2-untrusted-rustc.exe"
set "RUSTC_WRAPPER=C:\r2-untrusted-wrapper.exe"
set "RUSTFLAGS=-Ctarget-feature=+crt-static"
set "CARGO_BUILD_TARGET=i686-pc-windows-msvc"
set "CARGO_INCREMENTAL=1"
set "CARGO_PROFILE_RELEASE_LTO=false"
set "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER=C:\r2-untrusted-link.exe"
set "RUSTC_BOOTSTRAP=1"
set "RUSTDOCFLAGS=-Zunstable-options"
set "BINDGEN_EXTRA_CLANG_ARGS=-DR2_UNTRUSTED"
set "CC=C:\r2-untrusted-cc.exe"
set "CXX=C:\r2-untrusted-cxx.exe"
set "AR=C:\r2-untrusted-ar.exe"
set "RANLIB=C:\r2-untrusted-ranlib.exe"
set "CFLAGS=/DR2_UNTRUSTED"
set "CXXFLAGS=/DR2_UNTRUSTED"
set "bindgen_extra_clang_args_X86_64_PC_WINDOWS_MSVC=-DR2_TARGET_UNTRUSTED"
set "Cc_x86_64_pc_windows_msvc=C:\r2-target-untrusted-cc.exe"
set "cXX_AARCH64_PC_WINDOWS_MSVC=C:\r2-target-untrusted-cxx.exe"
set "Ar_X86_64_PC_WINDOWS_MSVC=C:\r2-target-untrusted-ar.exe"
set "ranlib_aarch64_pc_windows_msvc=C:\r2-target-untrusted-ranlib.exe"
set "Cflags_X86_64_PC_WINDOWS_MSVC=/DR2_TARGET_UNTRUSTED"
set "cxxflags_aarch64_pc_windows_msvc=/DR2_TARGET_UNTRUSTED"
set "CL=/DUNTRUSTED"
set "_CL_=/DUNTRUSTED"
set "LINK=/DEBUG"
set "_LINK_=/DEBUG"
set "RUSTUP_HOME=C:\r2-untrusted-rustup"
call :CONFIGURE_LOCKED_PATH
for /f "tokens=1 delims=;" %%P in ("!PATH!") do set "R2_FIRST=%%P"
if /I not "!R2_FIRST!"=="!R2_NATIVE_DIR!\" (
  echo devenv self-test FAIL: generated native shim is not first in special PATH
  exit /b 1
)
set "R2_FOUND_CARGO="
for /f "delims=" %%P in ('"%SystemRoot%\System32\where.exe" cargo.exe 2^>nul') do if not defined R2_FOUND_CARGO set "R2_FOUND_CARGO=%%~fP"
if /I not "!R2_FOUND_CARGO!"=="!R2_NATIVE_DIR!\cargo.exe" (
  echo devenv self-test FAIL: native cargo.exe did not win special PATH resolution
  exit /b 1
)
if /I not "!CARGO!"=="!R2_REAL_CARGO!" (
  echo devenv self-test FAIL: cargo-wdk metadata is not pinned to exact real Cargo
  exit /b 1
)
if not "!RUSTUP_TOOLCHAIN!"=="1.85.0" (
  echo devenv self-test FAIL: cargo-wdk metadata toolchain is not pinned to 1.85.0
  exit /b 1
)
if /I not "!CARGO_TARGET_DIR!"=="!R2_TARGET_DIR!" (
  echo devenv self-test FAIL: package target directory is not exact
  exit /b 1
)
if /I not "!RUSTC!"=="!R2_RUSTC!" (
  echo devenv self-test FAIL: package compiler is not exact
  exit /b 1
)
if /I not "!RUSTUP_HOME!"=="!R2_RUSTUP_HOME!" (
  echo devenv self-test FAIL: rustup selector home is not exact
  exit /b 1
)
for %%V in (
  RUSTC_WRAPPER
  RUSTFLAGS
  RUSTC_BOOTSTRAP
  RUSTDOCFLAGS
  CARGO_BUILD_TARGET
  CARGO_INCREMENTAL
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
) do if defined %%V (
  echo devenv self-test FAIL: uncontrolled %%V survived package environment setup
  exit /b 1
)

set "PATH=!R2_BASE_PATH!"
set "CARGO="
set "RUSTUP_TOOLCHAIN="
call :CONFIGURE_ORDINARY_PATH
if errorlevel 1 (
  echo devenv self-test FAIL: ordinary PATH helper was not callable
  exit /b 1
)
echo ;!PATH!;| "%SystemRoot%\System32\findstr.exe" /I /L /C:";!R2_NATIVE_DIR!\;" >nul
if not errorlevel 1 (
  echo devenv self-test FAIL: ordinary PATH contains the generated native shim
  exit /b 1
)
echo self-test ok: native cargo.exe wins only special PATH; metadata Cargo/toolchain/target/rustc are exact
exit /b 0
