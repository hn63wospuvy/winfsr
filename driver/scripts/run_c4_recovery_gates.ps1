# The C4 recovery source-gate runner (Task 28 step 5).
#
# One external, sealed, immutable attempt per invocation. The runner freezes
# twenty executable roles and the complete Cargo configuration search set
# BEFORE it accepts an attempt directory, then runs the closed 38-row source
# battery fail-stop and seals four canonical manifests whose hashes form a
# one-way chain: gate manifest -> tools.json -> command-index.json ->
# candidate-artifacts.json -> attempt-files.json -> attempt.json.
#
# Two rules shape everything below.
#
# 1. The manifest is data, not its own oracle. This script carries its own
#    literal 38-row table transcribed from the approved design, and validates
#    every field of `driver/audit/c4-source-gates.json` against it before row
#    01 runs. A runner that read its expectations out of the file it is
#    checking would agree with whatever that file said.
#
# 2. Freezing an executable path is not enough. A helper that launches Cargo
#    can reach a different payload through PATH, a rustup proxy, an ambient
#    selector variable, or an unsealed `.cargo/config.toml`. Each producing
#    row therefore carries a literal nested-tool map, the helper emits a
#    nonce-bound marker naming every role it actually launched, and the runner
#    validates the marker against that map and against the retained
#    deny-write/delete handles.
#
# The runner never writes into the repository. Task 29's recorder alone copies
# the sealed external attempt after this process exits.

[CmdletBinding(DefaultParameterSetName = 'Execute')]
param(
    [Parameter(ParameterSetName = 'SelfTest', Mandatory = $true)]
    [switch]$SelfTest,

    [Parameter(ParameterSetName = 'PrintToolVersion', Mandatory = $true)]
    [string]$PrintToolVersion,

    [Parameter(ParameterSetName = 'PrintToolVersion')]
    [string]$ToolPath,

    [Parameter(ParameterSetName = 'Execute', Mandatory = $true)]
    [string]$Manifest,

    [Parameter(ParameterSetName = 'Execute', Mandatory = $true)]
    [string]$AuthorizedExternalParent,

    [Parameter(ParameterSetName = 'Execute', Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(ParameterSetName = 'Execute', Mandatory = $true)]
    [string]$ScratchDirectory,

    [Parameter(ParameterSetName = 'Execute', Mandatory = $true)]
    [string]$AttemptId,

    [Parameter(ParameterSetName = 'Execute', Mandatory = $true)]
    [string]$ExpectedSourceCommit,

    [Parameter(ParameterSetName = 'Execute', Mandatory = $true)]
    [string]$ExpectedSourceTree
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Read the invocation shape before the import: dot-sourcing the capture helper
# runs in this scope and sets its own `C4EvidenceDotSourced`, so reading that
# flag afterwards would make direct execution do nothing.
$script:C4RunnerDotSourced = ($MyInvocation.InvocationName -eq '.')
$script:C4RunnerSavedSelfTest = [bool]$SelfTest
$script:C4RunnerSavedPrintToolVersion = [string]$PrintToolVersion
$script:C4RunnerSavedToolPath = [string]$ToolPath
if (-not (Get-Variable -Name C4EvidenceDotSourced -Scope Script -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'invoke_c4_evidence.ps1')
}
$SelfTest = [bool]$script:C4RunnerSavedSelfTest
$PrintToolVersion = [string]$script:C4RunnerSavedPrintToolVersion
$ToolPath = [string]$script:C4RunnerSavedToolPath

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

$script:GateManifestSchema = 'fsring-c4-source-gates/v1'
$script:ToolsSchema = 'fsring-c4-source-tools/v1'
$script:CommandIndexSchema = 'fsring-c4-source-command-index/v1'
$script:AttemptFilesSchema = 'fsring-c4-source-attempt-files/v1'
$script:AttemptSchema = 'fsring-c4-source-attempt/v1'
$script:FailureSchema = 'fsring-c4-source-failure/v1'
$script:CandidateSchema = 'fsring-c4-candidate-artifacts/v1'
$script:PackageCandidateSchema = 'fsring-c4-package-candidate/v1'
$script:PackageSetSchema = 'fsring-c4-package-set/v1'
$script:RunnerSelfTestObjectSchema = 'fsring-c4-source-runner-selftest/v1'
$script:SelfTestSchema = 'fsring-c4-source-runner-selftest-report/v1'
$script:NestedToolMarkerSchema = 'fsring-c4-nested-tools-marker/v1'
$script:NestedToolMarkerSentinel = 'FSRING-C4-NESTED-TOOLS '
$script:CapturedExitSchema = 'fsring-captured-exit/v1'
# The command ID the runner's own private observations carry. It is not a
# manifest row and never reaches the sealed evidence; it exists so a capture
# adapter can tell a private observation from a gate row without inferring.
$script:PrivateCaptureCommandId = 'private/runner-observation'

# ---------------------------------------------------------------------------
# The twenty frozen executable roles, in the one order every roster uses.
#
# Ordinals are 1-based and appear in the tool triplet paths, so the order is
# part of the sealed evidence rather than a presentation detail.
# ---------------------------------------------------------------------------

$script:ToolRoles = @(
    'powershell', 'python', 'git', 'git-bash', 'cmd',
    'cargo-1.82.0', 'rustc-1.82.0', 'rustdoc-1.82.0',
    'cargo-fmt-1.82.0', 'rustfmt-1.82.0',
    'cargo-1.85.0', 'rustc-1.85.0', 'rustdoc-1.85.0',
    'cargo-fmt-1.85.0', 'rustfmt-1.85.0',
    'cargo-clippy-1.85.0', 'clippy-driver-1.85.0',
    'cargo-wdk-0.1.1', 'infverif', 'signtool'
)

# The Rust payload roles resolve to an exact file below one canonical
# `RUSTUP_HOME/toolchains/<version>-x86_64-pc-windows-msvc/bin` directory. A
# shared `.cargo/bin` proxy is refused: it dispatches on a selector this runner
# has just removed from the environment, so it is not a payload identity.
$script:RustPayloads = [ordered]@{
    'cargo-1.82.0' = @{ Version = '1.82.0'; File = 'cargo.exe' }
    'rustc-1.82.0' = @{ Version = '1.82.0'; File = 'rustc.exe' }
    'rustdoc-1.82.0' = @{ Version = '1.82.0'; File = 'rustdoc.exe' }
    'cargo-fmt-1.82.0' = @{ Version = '1.82.0'; File = 'cargo-fmt.exe' }
    'rustfmt-1.82.0' = @{ Version = '1.82.0'; File = 'rustfmt.exe' }
    'cargo-1.85.0' = @{ Version = '1.85.0'; File = 'cargo.exe' }
    'rustc-1.85.0' = @{ Version = '1.85.0'; File = 'rustc.exe' }
    'rustdoc-1.85.0' = @{ Version = '1.85.0'; File = 'rustdoc.exe' }
    'cargo-fmt-1.85.0' = @{ Version = '1.85.0'; File = 'cargo-fmt.exe' }
    'rustfmt-1.85.0' = @{ Version = '1.85.0'; File = 'rustfmt.exe' }
    'cargo-clippy-1.85.0' = @{ Version = '1.85.0'; File = 'cargo-clippy.exe' }
    'clippy-driver-1.85.0' = @{ Version = '1.85.0'; File = 'clippy-driver.exe' }
}

# `versionArgv` templates. `{role}` expands to the frozen role path and
# `{self}` to this script's own canonical path; ordinals 19-20 launch the
# already frozen PowerShell and pass the WDK role path as a value, because a
# WDK binary must never be executed just to learn its version.
$script:VersionArgvTemplates = [ordered]@{
    'powershell' = @('{powershell}', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '{self}', '-PrintToolVersion', 'powershell')
    'python' = @('{role}', '--version')
    'git' = @('{role}', '--version')
    'git-bash' = @('{role}', '--version')
    'cmd' = @('{role}', '/d', '/c', 'ver')
    'cargo-1.82.0' = @('{role}', '--version', '--verbose')
    'rustc-1.82.0' = @('{role}', '--version', '--verbose')
    'rustdoc-1.82.0' = @('{role}', '--version', '--verbose')
    'cargo-fmt-1.82.0' = @('{role}', '--version')
    'rustfmt-1.82.0' = @('{role}', '--version')
    'cargo-1.85.0' = @('{role}', '--version', '--verbose')
    'rustc-1.85.0' = @('{role}', '--version', '--verbose')
    'rustdoc-1.85.0' = @('{role}', '--version', '--verbose')
    'cargo-fmt-1.85.0' = @('{role}', '--version')
    'rustfmt-1.85.0' = @('{role}', '--version')
    'cargo-clippy-1.85.0' = @('{role}', '--version')
    'clippy-driver-1.85.0' = @('{role}', '--version')
    'cargo-wdk-0.1.1' = @('{role}', '--version')
    'infverif' = @('{powershell}', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '{self}', '-PrintToolVersion', 'infverif', '-ToolPath', '{role}')
    'signtool' = @('{powershell}', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '{self}', '-PrintToolVersion', 'signtool', '-ToolPath', '{role}')
}

$script:ToolRowKeys = @(
    'role', 'path', 'volumeSerial', 'fileId', 'bytes', 'sha256',
    'versionArgv', 'versionStdout', 'versionStdoutBytes', 'versionStdoutSha256',
    'versionStderr', 'versionStderrBytes', 'versionStderrSha256',
    'versionExit', 'versionExitBytes', 'versionExitSha256', 'observedExit'
)

$script:CargoEnvironmentKeys = @(
    'cargoHome', 'cargoHomeBinExcluded', 'configCandidates',
    'inheritedSelectorNames', 'cargoIncremental', 'pathDirectories'
)

$script:ConfigCandidateKeys = @(
    'path', 'scope', 'present', 'sourceRelativePath', 'bytes', 'sha256'
)

$script:CommandRowKeys = @(
    'ordinal', 'id', 'argv', 'cwd', 'toolchain', 'nestedTools', 'expectedExit',
    'timeoutSeconds', 'stdout', 'stdoutBytes', 'stdoutSha256',
    'stderr', 'stderrBytes', 'stderrSha256',
    'exit', 'exitBytes', 'exitSha256', 'observedExit', 'timedOut', 'status'
)

$script:GateRowKeys = @(
    'id', 'argv', 'cwd', 'toolchain', 'expectedExit', 'timeoutSeconds',
    'stdout', 'stderr', 'exit'
)

$script:AttemptKeys = @(
    'schema', 'version', 'attemptId', 'sourceCommit', 'sourceTree',
    'gateManifestSha256', 'toolsSha256', 'commandIndexSha256',
    'candidateManifestSha256', 'attemptFilesSha256', 'gateStatus', 'failure'
)

$script:CommandStatuses = @('PASS', 'FAIL', 'TIMEOUT', 'IDENTITY_DRIFT', 'NOT_ISSUED')
$script:GateStatuses = @('PASS', 'FAIL', 'TIMEOUT', 'IDENTITY_DRIFT')
$script:FailureKinds = @(
    'PRE_ROSTER_IDENTITY', 'TOOL_FREEZE', 'COMMAND_FAIL', 'COMMAND_TIMEOUT',
    'COMMAND_START_FAILED', 'COMMAND_CAPTURE_FAILED', 'IDENTITY_DRIFT',
    'CANDIDATE_SEAL'
)

# The four auxiliary files, lexically ordered exactly as `auxiliaryFiles`
# requires them.
$script:AuxiliaryFileNames = @(
    'mutation-c4-list.json',
    'package-verifier.exit.json',
    'package-verifier.stderr.bin',
    'package-verifier.stdout.bin'
)

# The nine candidate artifact paths, in the order `candidate-artifacts.json`
# lists them.
$script:CandidateArtifactPaths = @(
    'artifacts/win10-x64-release/package/fsring_fsd.inf',
    'artifacts/win10-x64-release/package/fsring_fsd.sys',
    'artifacts/win10-x64-release/package/fsring_fsd.cat',
    'artifacts/win10-x64-release/package/fsring_fsd.pdb',
    'artifacts/win10-x64-release/package/fsring_fsd.map',
    'artifacts/win10-x64-release/package/WDRLocalTestCert.cer',
    'artifacts/win10-x64-release/fsring-control-smoke.exe',
    'artifacts/archives/fsring-abi.zip',
    'artifacts/archives/fsring-spec.zip'
)

$script:PackageMemberNames = @(
    'fsring_fsd.inf', 'fsring_fsd.sys', 'fsring_fsd.cat',
    'fsring_fsd.pdb', 'fsring_fsd.map', 'WDRLocalTestCert.cer'
)

$script:CandidateProfile = [ordered]@{
    id = 'win10-x64-release'
    target = 'x86_64-pc-windows-msvc'
    driverFeature = 'platform-win10'
    cargoProfile = 'release'
    machine = '0x8664'
}

$script:HarnessScratchRelativePath = 'harness/x86_64-pc-windows-msvc/release/fsring-control-smoke.exe'
$script:HarnessCandidateRelativePath = 'artifacts/win10-x64-release/fsring-control-smoke.exe'
$script:SmokeDriverRelativePath = 'driver/scripts/smoke_driver.ps1'
$script:MutationListRelativePath = 'mutation-c4-list.json'
$script:AuthoritativeMutationManifest = 'driver/audit/c4-mutations.json'

# Inherited selector names removed before every mapped launch. A helper that
# found any of these could reach a different payload without changing a single
# frozen path, which is why the roster is closed and matched case-insensitively.
$script:ForbiddenSelectorNames = @(
    'CARGO', 'CARGO_HOME', 'CARGO_INCREMENTAL', 'RUSTC', 'RUSTDOC', 'RUSTFMT',
    'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CLIPPY_DRIVER_PATH',
    'RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP',
    'RUSTUP_TOOLCHAIN', 'RUSTUP_HOME', 'RUSTUP_DIST_SERVER',
    'RUSTUP_UPDATE_ROOT', 'RUSTUP_IO_THREADS'
)
$script:ForbiddenSelectorPrefixes = @(
    'CARGO_ALIAS_', 'CARGO_BUILD_', 'CARGO_TARGET_', 'CARGO_PROFILE_'
)

# `build_matrix.cmd` refuses to run when any of these is set: it creates its own
# locked Cargo directory and treats a pre-set build environment as uncontrolled.
# A `cmd+*` row therefore receives NONE of them -- not the gate's own frozen
# selectors, and not one inherited from a Visual Studio developer prompt.
#
# This set is the runner's transcription of that guard. `Assert-MatrixRefusalSet`
# in the self-test reads the predicate back out of `build_matrix.cmd` itself, so
# a name added there and not here is a failure rather than a silent divergence.
$script:MatrixRefusedExactNames = @(
    'CARGO', 'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
    'RUSTC_BOOTSTRAP', 'RUSTFLAGS', 'RUSTDOC', 'RUSTDOCFLAGS', 'RUSTUP_HOME',
    'RUSTUP_TOOLCHAIN', 'BINDGEN_EXTRA_CLANG_ARGS', 'CC', 'CXX', 'AR',
    'RANLIB', 'CFLAGS', 'CXXFLAGS', 'CL', '_CL_', 'LINK', '_LINK_'
)
$script:MatrixRefusedPrefixes = @('CARGO_')
$script:MatrixRefusedSuffixPattern =
    '^(?:CC|CXX|AR|RANLIB|CFLAGS|CXXFLAGS|BINDGEN_EXTRA_CLANG_ARGS)_.+$'

# The one admissible tracked Cargo configuration. Its bytes must equal the
# `S,T` tree blob; every other present static candidate is a refusal.
$script:TrackedCargoConfigRelativePath = 'driver/.cargo/config.toml'

# ---------------------------------------------------------------------------
# The runner's own literal 38-row table
#
# Transcribed from the approved design's roster table, NOT from
# `c4-source-gates.json`. The manifest and this table are two independent
# transcriptions of the same normative source; validating one against the
# other is the check. Deriving this table from the file would make the
# validation vacuous.
# ---------------------------------------------------------------------------

function New-C4GateRowSpec {
    param(
        [string]$Id,
        [string[]]$Argv,
        [string]$Toolchain,
        [int]$TimeoutSeconds
    )
    return [ordered]@{
        id = $Id
        argv = @($Argv)
        cwd = '.'
        toolchain = $Toolchain
        expectedExit = 0
        timeoutSeconds = $TimeoutSeconds
    }
}

$script:ExpectedGateRows = @(
    (New-C4GateRowSpec 'source-runner-selftest' @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'driver/scripts/run_c4_recovery_gates.ps1', '-SelfTest') 'windows-powershell-recorded' 1800),
    (New-C4GateRowSpec 'capture-helper-selftest' @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'driver/scripts/invoke_c4_evidence.ps1', '-SelfTest') 'windows-powershell-recorded' 300),
    (New-C4GateRowSpec 'root-fmt' @('cargo-fmt', '--all', '--', '--check') 'rust-1.82.0' 300),
    (New-C4GateRowSpec 'root-check' @('cargo', 'check', '--workspace', '--all-targets', '--all-features', '--locked', '--offline') 'rust-1.82.0' 1800),
    (New-C4GateRowSpec 'root-test' @('cargo', 'test', '--workspace', '--all-targets', '--all-features', '--locked', '--offline') 'rust-1.82.0' 3600),
    (New-C4GateRowSpec 'driver-fmt' @('cargo-fmt', '--manifest-path', 'driver/Cargo.toml', '--all', '--', '--check') 'rust-1.85.0' 300),
    (New-C4GateRowSpec 'driver-core-clippy' @('cargo-clippy', '--manifest-path', 'driver/Cargo.toml', '-p', 'fsring-core', '--all-targets', '--locked', '--offline', '--', '-D', 'warnings') 'rust-1.85.0' 1800),
    (New-C4GateRowSpec 'driver-core-test' @('cargo', 'test', '--manifest-path', 'driver/Cargo.toml', '-p', 'fsring-core', '--all-targets', '--locked', '--offline') 'rust-1.85.0' 3600),
    (New-C4GateRowSpec 'c2-boundary' @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'driver/scripts/verify_c2_clearance_boundary.ps1') 'windows-powershell-recorded' 300),
    (New-C4GateRowSpec 'b5-manifest' @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'driver/scripts/verify_b5_compile_fail_manifest.ps1') 'windows-powershell-recorded' 300),
    (New-C4GateRowSpec 'compile-fail' @('{git-bash}', 'driver/scripts/compile_fail.sh') 'git-bash+rust-1.85.0' 3600),
    (New-C4GateRowSpec 'mutation-default' @('python', 'driver/scripts/mutation_sweep.py', '--no-resume') 'python3-recorded' 14400),
    (New-C4GateRowSpec 'mutation-c4-list' @('python', 'driver/scripts/mutation_sweep.py', '--suite', 'c4', '--list', '--json', '{attempt}/mutation-c4-list.json') 'python3-recorded' 300),
    (New-C4GateRowSpec 'mutation-c4' @('python', 'driver/scripts/mutation_sweep.py', '--suite', 'c4', '--no-resume') 'python3-recorded' 14400),
    (New-C4GateRowSpec 'lifetime-selftest' @('python', 'driver/scripts/audit_c4_lifetime.py', '--self-test') 'python3-recorded' 3600),
    (New-C4GateRowSpec 'lifetime-source' @('python', 'driver/scripts/audit_c4_lifetime.py', '--source-root', 'driver/fsring-fsd/src', '--source-root', 'driver/fsring-core/src') 'python3-recorded' 300),
    (New-C4GateRowSpec 'imports-selftest' @('python', 'driver/scripts/audit_c4_imports.py', '--self-test') 'python3-recorded' 300),
    (New-C4GateRowSpec 'stack-selftest' @('python', 'driver/scripts/audit_c4_stack.py', '--self-test') 'python3-recorded' 300),
    (New-C4GateRowSpec 'matrix-selftest' @('cmd.exe', '/d', '/c', 'call', 'driver/scripts/build_matrix.cmd', '--self-test') 'cmd+wdk-10.0.26100' 3600),
    (New-C4GateRowSpec 'matrix-three-profile' @('cmd.exe', '/d', '/c', 'call', 'driver/scripts/build_matrix.cmd') 'cmd+wdk-10.0.26100' 14400),
    (New-C4GateRowSpec 'package-win10-x64' @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'driver/scripts/package_c4_candidate.ps1', '-OutputDirectory', '{attempt}/artifacts/win10-x64-release/package', '-ExpectedSourceCommit', '{S}', '-ExpectedSourceTree', '{T}', '-Profile', 'win10-x64-release', '-InfVerifPath', '{infverif}', '-SignToolPath', '{signtool}') 'windows-powershell+wdk-10.0.26100' 3600),
    (New-C4GateRowSpec 'package-selftest' @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'driver/scripts/package_c4_candidate.ps1', '-SelfTest') 'windows-powershell-recorded' 300),
    (New-C4GateRowSpec 'smoke-selftest' @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'driver/scripts/smoke_driver.ps1', '-SelfTest') 'windows-powershell-recorded' 1800),
    (New-C4GateRowSpec 'native-session-test' @('cargo', 'test', '-p', 'fsring-user', '--test', 'native_session', '--locked', '--offline') 'rust-1.82.0' 1800),
    (New-C4GateRowSpec 'smoke-v2-test' @('cargo', 'test', '-p', 'fsring-user', '--test', 'smoke_v2', '--locked', '--offline') 'rust-1.82.0' 1800),
    (New-C4GateRowSpec 'smoke-live-test' @('cargo', 'test', '-p', 'fsring-user', '--test', 'smoke_live', '--locked', '--offline') 'rust-1.82.0' 1800),
    (New-C4GateRowSpec 'harness-win10-x64-release' @('cargo', 'build', '-p', 'fsring-user', '--bin', 'fsring-control-smoke', '--target', 'x86_64-pc-windows-msvc', '--release', '--target-dir', '{scratch}/harness', '--locked', '--offline') 'rust-1.82.0' 1800),
    (New-C4GateRowSpec 'verify-spec' @('python', 'scripts/verify_spec.py') 'python3-recorded' 300),
    (New-C4GateRowSpec 'verify-registry' @('python', 'scripts/verify_v21_registry.py') 'python3-recorded' 300),
    (New-C4GateRowSpec 'archives-generate' @('python', 'scripts/package_artifacts.py', '--output-directory', '{attempt}/artifacts/archives') 'python3-recorded' 300),
    (New-C4GateRowSpec 'archives-selftest' @('python', 'scripts/package_artifacts.py', '--self-test') 'python3-recorded' 300),
    (New-C4GateRowSpec 'archives-verify' @('python', 'scripts/package_artifacts.py', '--verify-existing', '--output-directory', '{attempt}/artifacts/archives') 'python3-recorded' 300),
    (New-C4GateRowSpec 'production-graph-selftest' @('python', 'driver/scripts/audit_c4_production_graph.py', '--self-test', '--manifest', 'driver/audit/c4-production-graph.json') 'python3-recorded' 300),
    (New-C4GateRowSpec 'production-graph-final' @('python', 'driver/scripts/audit_c4_production_graph.py', '--manifest', 'driver/audit/c4-production-graph.json', '--verify-current-attestation', '--profile', 'r5-cutover') 'python3-recorded' 300),
    (New-C4GateRowSpec 'diff-check' @('git', 'diff', '--check') 'git-for-windows-recorded' 300),
    (New-C4GateRowSpec 'clean-close' @('git', 'status', '--porcelain=v1', '--untracked-files=all') 'git-for-windows-recorded' 60),
    (New-C4GateRowSpec 'head-close' @('git', 'rev-parse', 'HEAD') 'git-for-windows-recorded' 60),
    (New-C4GateRowSpec 'tree-close' @('git', 'rev-parse', 'HEAD^{tree}') 'git-for-windows-recorded' 60)
)

# ---------------------------------------------------------------------------
# The per-row nested-tool map
#
# This is the second independent literal. A direct executable freeze cannot
# see what a producing helper launches, so each row names every frozen role
# its child roster is allowed to reach, in global tool-role order. An
# empty-map row must produce a marker with no tools at all.
# ---------------------------------------------------------------------------

$script:Rust182Base = @('cargo-1.82.0', 'rustc-1.82.0', 'rustdoc-1.82.0')
$script:Rust185Base = @('cargo-1.85.0', 'rustc-1.85.0', 'rustdoc-1.85.0')

$script:NestedToolMap = @{
    1 = @('powershell')
    2 = @()
    3 = @($script:Rust182Base + @('cargo-fmt-1.82.0', 'rustfmt-1.82.0'))
    4 = @($script:Rust182Base)
    5 = @($script:Rust182Base)
    6 = @($script:Rust185Base + @('cargo-fmt-1.85.0', 'rustfmt-1.85.0'))
    7 = @($script:Rust185Base + @('cargo-clippy-1.85.0', 'clippy-driver-1.85.0'))
    8 = @($script:Rust185Base)
    9 = @()
    10 = @()
    11 = @($script:Rust185Base)
    12 = @($script:Rust182Base + $script:Rust185Base)
    13 = @()
    14 = @(@('powershell', 'python') + $script:Rust182Base + $script:Rust185Base)
    15 = @()
    16 = @()
    17 = @()
    18 = @()
    19 = @(@('powershell', 'python', 'git-bash') + $script:Rust185Base + @('cargo-clippy-1.85.0', 'clippy-driver-1.85.0', 'cargo-wdk-0.1.1', 'infverif', 'signtool'))
    20 = @(@('powershell', 'python', 'git-bash') + $script:Rust185Base + @('cargo-clippy-1.85.0', 'clippy-driver-1.85.0', 'cargo-wdk-0.1.1', 'infverif', 'signtool'))
    21 = @('powershell', 'infverif', 'signtool')
    22 = @()
    23 = @()
    24 = @($script:Rust182Base)
    25 = @($script:Rust182Base)
    26 = @($script:Rust182Base)
    27 = @($script:Rust182Base)
    28 = @()
    29 = @()
    30 = @()
    31 = @()
    32 = @()
    33 = @($script:Rust185Base)
    34 = @($script:Rust185Base)
    35 = @()
    36 = @()
    37 = @()
    38 = @()
}

# The independent entry-count oracle. Counting the map would agree with
# whatever the map said; these numbers come from the design text.
#
# Rows 33 and 34 are the one place that claim needed repairing rather than
# repeating. The design text listed them in its empty-map roster while both this
# oracle and the map said 3, so the "independent" copy had been edited to agree
# with the copy it exists to falsify. The 3 is right --
# `audit_c4_production_graph.py` launches the frozen 1.85 Cargo payload to run
# each profile's property rows, and a `--self-test` and a
# `--verify-current-attestation` both recompute those rows rather than reading a
# recorded result -- so the design text was corrected to say 3 and this number
# now has the provenance it claims.
$script:NestedToolEntryCounts = @{
    1 = 1; 2 = 0; 3 = 5; 4 = 3; 5 = 3; 6 = 5; 7 = 5; 8 = 3; 9 = 0; 10 = 0
    11 = 3; 12 = 6; 13 = 0; 14 = 8; 15 = 0; 16 = 0; 17 = 0; 18 = 0
    19 = 11; 20 = 11; 21 = 3; 22 = 0; 23 = 0
    24 = 3; 25 = 3; 26 = 3; 27 = 3; 28 = 0; 29 = 0; 30 = 0; 31 = 0; 32 = 0
    33 = 3; 34 = 3; 35 = 0; 36 = 0; 37 = 0; 38 = 0
}

# The closed launch-count oracle. Unique roles and launch counts are separate
# facts: row 21 reaches three roles but launches SignTool three times.
$script:ExpectedMarkerLaunchCounts = @{
    1 = [ordered]@{ powershell = 2 }
    19 = [ordered]@{ powershell = 402; python = 3 }
    # python 10 -> 12: round 17's E1 repair wired `audit_c4_task_promises.py`
    # into `build_matrix.cmd`, both `--self-test` and `--check`. Round 16 had
    # written that auditor, graded it, repaired a keying hole in it and then
    # invoked it from nothing at all; making it run is what moved this number.
    # The oracle fired on the first attempt afterwards (row 20, IDENTITY_DRIFT,
    # ledger row 27) and refused to seal, which is exactly what a launch-count
    # oracle is for: a process appearing inside a gate has to be accounted for,
    # not absorbed.
    20 = [ordered]@{ powershell = 822; python = 12; 'git-bash' = 4 }
    # signtool 3 -> 6: the count is now tallied from the verifier's launch
    # journal rather than derived from its report, and the verifier makes
    # three kernel-policy probes plus three Authenticode probes.
    21 = [ordered]@{ powershell = 1; infverif = 1; signtool = 6 }
    33 = [ordered]@{ 'cargo-1.85.0' = 4; 'rustc-1.85.0' = 0; 'rustdoc-1.85.0' = 0 }
    34 = [ordered]@{ 'cargo-1.85.0' = 2; 'rustc-1.85.0' = 0; 'rustdoc-1.85.0' = 0 }
}

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

function Get-C4RunnerRepositoryRoot {
    $scripts = [IO.Path]::GetFullPath($PSScriptRoot)
    $driver = [IO.Path]::GetFullPath((Join-Path $scripts '..'))
    return [IO.Path]::GetFullPath((Join-Path $driver '..'))
}

function Assert-C4RunnerHex {
    param([string]$Value, [int]$Length, [string]$Name)
    if ($null -eq $Value -or $Value -cnotmatch ('^[0-9a-f]{' + $Length + '}$')) {
        throw ("{0} must be exactly {1} lowercase hexadecimal characters" -f $Name, $Length)
    }
    return $Value
}

function Assert-C4RunnerAttemptId {
    param([string]$Value)
    if ($null -eq $Value -or $Value -cnotmatch '^[0-9a-f]{32}$') {
        throw 'attempt ID must be a lowercase GUID-N (32 hexadecimal characters)'
    }
    return $Value
}

function Test-C4RunnerReparse {
    param([string]$Path)
    try {
        $attrs = [IO.File]::GetAttributes($Path)
    } catch {
        return $false
    }
    return (($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Assert-C4RunnerCanonicalAbsolutePath {
    param([string]$Path, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw ("{0} is required" -f $Name)
    }
    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw ("{0} must be absolute: {1}" -f $Name, $Path)
    }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -cne $Path) {
        throw ("{0} must be canonical: {1}" -f $Name, $Path)
    }
    if ($Path.Contains('..')) {
        throw ("{0} contains a relative segment: {1}" -f $Name, $Path)
    }
    return $full
}

function Assert-C4RunnerExactKeys {
    param($Object, [string[]]$Keys, [string]$Name)
    if ($null -eq $Object) { throw ("{0} is absent" -f $Name) }
    $actual = @()
    if ($Object -is [Collections.IDictionary]) {
        $actual = @($Object.Keys)
    } else {
        $actual = @($Object.PSObject.Properties | ForEach-Object { $_.Name })
    }
    if (@($actual).Count -ne @($Keys).Count) {
        throw ("{0} key count is {1}, expected {2}" -f $Name, @($actual).Count, @($Keys).Count)
    }
    for ($i = 0; $i -lt @($Keys).Count; $i++) {
        if ($actual[$i] -cne $Keys[$i]) {
            throw ("{0} key {1} is '{2}', expected '{3}'" -f $Name, $i, $actual[$i], $Keys[$i])
        }
    }
}

function Get-C4RunnerCanonicalBytes {
    param($Value)
    $utf8 = New-Object System.Text.UTF8Encoding $false
    return $utf8.GetBytes((ConvertTo-C4CanonicalJsonText $Value) + "`n")
}

function Get-C4RunnerSha256File {
    param([string]$Path)
    return (Get-C4EvidenceSha256Hex ([IO.File]::ReadAllBytes($Path)))
}

function Get-C4RunnerZeroBytesSha256 {
    return (Get-C4EvidenceSha256Hex (New-Object byte[] 0))
}

function Write-C4RunnerStdoutLine {
    param([string]$Text)
    if ($null -eq $Text) { return }
    [Console]::Out.Write($Text + "`n")
    [Console]::Out.Flush()
}

function Write-C4RunnerExclusiveBytes {
    param([string]$Path, [byte[]]$Bytes)
    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

function Get-C4RunnerCommandTripletNames {
    param([int]$Ordinal, [string]$Id)
    $stem = ('commands/{0:d2}-{1}' -f $Ordinal, $Id)
    return [pscustomobject]@{
        Stdout = ($stem + '.stdout.bin')
        Stderr = ($stem + '.stderr.bin')
        Exit = ($stem + '.exit.json')
    }
}

function Get-C4RunnerToolTripletNames {
    param([int]$Ordinal, [string]$Role)
    $stem = ('tools/{0:d2}-{1}.version' -f $Ordinal, $Role)
    return [pscustomobject]@{
        Stdout = ($stem + '.stdout.bin')
        Stderr = ($stem + '.stderr.bin')
        Exit = ($stem + '.exit.json')
    }
}

# ---------------------------------------------------------------------------
# Manifest validation
#
# Every field of every row is compared with this script's literal table before
# row 01 runs. The three capture paths are DERIVED from the ordinal and ID, so
# a manifest that renamed one is caught without a second literal.
# ---------------------------------------------------------------------------

function Test-C4RunnerManifestDocument {
    param($Document)

    Assert-C4RunnerExactKeys $Document @('schema', 'workingDirectory', 'commands') 'gate manifest'
    if ($Document.schema -cne $script:GateManifestSchema) {
        throw ("gate manifest schema is {0}, expected {1}" -f $Document.schema, $script:GateManifestSchema)
    }
    if ($Document.workingDirectory -cne '.') {
        throw 'gate manifest workingDirectory must be exactly "."'
    }
    $rows = @($Document.commands)
    if ($rows.Count -ne $script:ExpectedGateRows.Count) {
        throw ("gate manifest has {0} rows, expected {1}" -f $rows.Count, $script:ExpectedGateRows.Count)
    }
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $ordinal = $i + 1
        $row = $rows[$i]
        $spec = $script:ExpectedGateRows[$i]
        Assert-C4RunnerExactKeys $row $script:GateRowKeys ("gate manifest row {0:d2}" -f $ordinal)
        if ($row.id -cne $spec.id) {
            throw ("gate row {0:d2} is '{1}', expected '{2}'" -f $ordinal, $row.id, $spec.id)
        }
        $actualArgv = @($row.argv)
        $expectedArgv = @($spec.argv)
        # The token rules apply to the manifest's own values and run first: a
        # row that could name an arbitrary path through a token is a different
        # defect from one that merely disagrees with the literal table, and
        # running them against this script's own table would check nothing.
        Test-C4RunnerRowTokens -Ordinal $ordinal -Argv $actualArgv
        if ($actualArgv.Count -ne $expectedArgv.Count) {
            throw ("gate row {0:d2} argv has {1} elements, expected {2}" -f $ordinal, $actualArgv.Count, $expectedArgv.Count)
        }
        for ($j = 0; $j -lt $expectedArgv.Count; $j++) {
            if ([string]$actualArgv[$j] -cne [string]$expectedArgv[$j]) {
                throw ("gate row {0:d2} argv[{1}] is '{2}', expected '{3}'" -f $ordinal, $j, $actualArgv[$j], $expectedArgv[$j])
            }
        }
        if ($row.cwd -cne $spec.cwd) { throw ("gate row {0:d2} cwd drifted" -f $ordinal) }
        if ($row.toolchain -cne $spec.toolchain) {
            throw ("gate row {0:d2} toolchain is '{1}', expected '{2}'" -f $ordinal, $row.toolchain, $spec.toolchain)
        }
        if ([int]$row.expectedExit -ne [int]$spec.expectedExit) {
            throw ("gate row {0:d2} expectedExit drifted" -f $ordinal)
        }
        if ([int]$row.timeoutSeconds -ne [int]$spec.timeoutSeconds) {
            throw ("gate row {0:d2} timeoutSeconds is {1}, expected {2}" -f $ordinal, $row.timeoutSeconds, $spec.timeoutSeconds)
        }
        $names = Get-C4RunnerCommandTripletNames $ordinal $spec.id
        if ($row.stdout -cne $names.Stdout) { throw ("gate row {0:d2} stdout path drifted" -f $ordinal) }
        if ($row.stderr -cne $names.Stderr) { throw ("gate row {0:d2} stderr path drifted" -f $ordinal) }
        if ($row.exit -cne $names.Exit) { throw ("gate row {0:d2} exit path drifted" -f $ordinal) }
    }
}

# Only six tokens are legal, and four of them only in one exact position. A
# row that could name an arbitrary path through a token would let the manifest
# choose where evidence lands.
function Test-C4RunnerRowTokens {
    param([int]$Ordinal, [string[]]$Argv)

    for ($j = 0; $j -lt @($Argv).Count; $j++) {
        $value = [string]$Argv[$j]
        foreach ($token in @('{attempt}', '{scratch}', '{S}', '{T}', '{infverif}', '{signtool}', '{git-bash}')) {
            if (-not $value.Contains($token)) { continue }
            switch ($token) {
                '{git-bash}' {
                    if ($j -ne 0 -or $value -cne '{git-bash}') {
                        throw ("gate row {0:d2}: {{git-bash}} is legal only as argv[0]" -f $Ordinal)
                    }
                }
                '{scratch}' {
                    if ($Ordinal -ne 27 -or $value -cne '{scratch}/harness') {
                        throw ("gate row {0:d2}: {{scratch}} is legal only as row 27's exact target directory" -f $Ordinal)
                    }
                }
                '{infverif}' {
                    if ($Ordinal -ne 21 -or $value -cne '{infverif}' -or [string]$Argv[$j - 1] -cne '-InfVerifPath') {
                        throw ("gate row {0:d2}: {{infverif}} is legal only after row 21's -InfVerifPath" -f $Ordinal)
                    }
                }
                '{signtool}' {
                    if ($Ordinal -ne 21 -or $value -cne '{signtool}' -or [string]$Argv[$j - 1] -cne '-SignToolPath') {
                        throw ("gate row {0:d2}: {{signtool}} is legal only after row 21's -SignToolPath" -f $Ordinal)
                    }
                }
                default { }
            }
        }
        if ($value.Contains('%') -or $value.Contains('$') -or $value.Contains('*') -or $value.Contains('@')) {
            throw ("gate row {0:d2} argv[{1}] carries an environment, glob or response-file fragment" -f $Ordinal, $j)
        }
    }
}

# ---------------------------------------------------------------------------
# Tool resolution
#
# Resolution happens BEFORE the attempt directory is accepted, so a missing or
# aliased role is an invocation refusal that leaves no evidence behind rather
# than a sealed attempt nobody asked for.
#
# `$Overrides` exists for the self-test, which needs twenty deterministic
# stand-in executables. Production passes $null and every path comes from the
# machine. The resolver's own rules (reparse refusal, rustup-proxy refusal,
# cross-version payload refusal) have their own fixtures below and are not
# bypassed by an override.
# ---------------------------------------------------------------------------

function Get-C4RunnerRustupHome {
    # NOT `$home`/`$profile`: PowerShell variable names are case-insensitive and
    # $HOME is a read-only automatic, so the obvious local name is an assignment
    # to it and the whole invocation dies before it resolves anything.
    $rustupRoot = [string]$env:RUSTUP_HOME
    if ([string]::IsNullOrWhiteSpace($rustupRoot)) {
        $userProfile = [string]$env:USERPROFILE
        if ([string]::IsNullOrWhiteSpace($userProfile)) { throw 'neither RUSTUP_HOME nor USERPROFILE is set' }
        $rustupRoot = Join-Path $userProfile '.rustup'
    }
    return [IO.Path]::GetFullPath($rustupRoot)
}

function Resolve-C4RunnerOnPath {
    param([string]$FileName, [string[]]$Directories)
    foreach ($directory in $Directories) {
        if ([string]::IsNullOrWhiteSpace($directory)) { continue }
        $candidate = $null
        try {
            $candidate = [IO.Path]::GetFullPath((Join-Path $directory $FileName))
        } catch {
            continue
        }
        if ([IO.File]::Exists($candidate)) { return $candidate }
    }
    return $null
}

function Get-C4RunnerPathDirectories {
    $raw = [string]$env:PATH
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $ordered = New-Object System.Collections.ArrayList
    foreach ($entry in $raw.Split(';')) {
        $trimmed = $entry.Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        $full = $null
        try { $full = [IO.Path]::GetFullPath($trimmed) } catch { continue }
        if ($seen.Add($full.ToUpperInvariant())) { [void]$ordered.Add($full) }
    }
    return (,@($ordered))
}

function Resolve-C4RunnerRustPayload {
    param([string]$Role, [string]$RustupHome)
    $spec = $script:RustPayloads[$Role]
    $binDirectory = Join-Path $RustupHome ('toolchains/' + $spec.Version + '-x86_64-pc-windows-msvc/bin')
    $canonicalBin = [IO.Path]::GetFullPath($binDirectory)
    if (Test-C4RunnerReparse $canonicalBin) {
        throw ("Rust payload directory for {0} is a reparse point" -f $Role)
    }
    $payload = [IO.Path]::GetFullPath((Join-Path $canonicalBin $spec.File))
    if (-not [IO.File]::Exists($payload)) {
        throw ("Rust payload for {0} is absent: {1}" -f $Role, $payload)
    }
    # A `.cargo/bin` proxy dispatches on a selector this runner removes from
    # every child environment, so accepting one would freeze a path whose
    # behaviour the freeze cannot describe.
    if ($payload -match '(?i)\\\.cargo\\bin\\') {
        throw ("{0} resolved to a shared rustup proxy rather than a toolchain payload" -f $Role)
    }
    if ($payload -notmatch ('(?i)\\toolchains\\' + [regex]::Escape($spec.Version) + '-x86_64-pc-windows-msvc\\bin\\')) {
        throw ("{0} resolved outside its own toolchain directory: {1}" -f $Role, $payload)
    }
    return $payload
}

function Resolve-C4RunnerToolPaths {
    param([string]$RepoRoot, $Overrides)

    $resolved = [ordered]@{}
    $pathDirectories = Get-C4RunnerPathDirectories
    $rustupHome = $null
    foreach ($role in $script:ToolRoles) {
        if ($null -ne $Overrides -and $Overrides.Contains($role)) {
            $resolved[$role] = [IO.Path]::GetFullPath([string]$Overrides[$role])
            continue
        }
        $path = $null
        switch -Regex ($role) {
            '^powershell$' { $path = Join-Path $PSHOME 'powershell.exe' }
            '^python$' { $path = Resolve-C4RunnerOnPath 'python.exe' $pathDirectories }
            '^git$' { $path = Resolve-C4RunnerOnPath 'git.exe' $pathDirectories }
            '^git-bash$' {
                $path = [string]$env:FSRING_BASH
                if ([string]::IsNullOrWhiteSpace($path)) {
                    $path = Join-Path ([string]$env:ProgramFiles) 'Git\bin\bash.exe'
                }
            }
            '^cmd$' { $path = Join-Path ([string]$env:SystemRoot) 'System32\cmd.exe' }
            '^cargo-wdk' { $path = Resolve-C4RunnerOnPath 'cargo-wdk.exe' $pathDirectories }
            '^infverif$' { $path = 'C:\Program Files (x86)\Windows Kits\10\Tools\10.0.26100.0\x64\infverif.exe' }
            '^signtool$' { $path = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe' }
            default {
                if ($null -eq $rustupHome) { $rustupHome = Get-C4RunnerRustupHome }
                $path = Resolve-C4RunnerRustPayload $role $rustupHome
            }
        }
        if ([string]::IsNullOrWhiteSpace($path)) {
            throw ("frozen role {0} could not be resolved" -f $role)
        }
        $resolved[$role] = [IO.Path]::GetFullPath($path)
    }
    return $resolved
}

# Every one of the twenty canonical files is opened once with sharing limited
# to read -- denying write and delete -- and the handle is retained until the
# attempt is sealed. Assert-C4HeldFileLease then re-reads native identity from
# that same handle, so a midpoint replacement cannot be hidden by restoring
# the endpoint bytes.
function Open-C4RunnerToolLeases {
    param($ResolvedPaths)

    $leases = [ordered]@{}
    try {
        foreach ($role in $script:ToolRoles) {
            $path = [string]$ResolvedPaths[$role]
            if (Test-C4RunnerReparse $path) {
                throw ("frozen role {0} is a reparse point: {1}" -f $role, $path)
            }
            $leases[$role] = Open-C4HeldFileLease -Path $path -ExpectedSha256 (Get-C4RunnerSha256File $path)
        }
    } catch {
        foreach ($role in @($leases.Keys)) { Close-C4HeldFileLease $leases[$role] }
        throw
    }
    return $leases
}

function Assert-C4RunnerToolLeases {
    param($Leases)
    foreach ($role in $script:ToolRoles) {
        Assert-C4HeldFileLease $Leases[$role]
    }
}

function Close-C4RunnerToolLeases {
    param($Leases)
    if ($null -eq $Leases) { return }
    foreach ($role in @($Leases.Keys)) { Close-C4HeldFileLease $Leases[$role] }
}

# ---------------------------------------------------------------------------
# -PrintToolVersion
#
# Three closed behaviours. The WDK variants read a version RESOURCE and never
# execute the binary: running InfVerif or SignTool just to learn a version
# would launch a privileged-adjacent tool for no evidentiary gain.
# ---------------------------------------------------------------------------

function Invoke-C4RunnerPrintToolVersion {
    param([string]$Role, [string]$Path)

    if ($Role -ceq 'powershell') {
        if (-not [string]::IsNullOrWhiteSpace($Path)) {
            throw '-PrintToolVersion powershell takes no -ToolPath'
        }
        Write-C4RunnerStdoutLine ([string]$PSVersionTable.PSVersion)
        return
    }
    if ($Role -cne 'infverif' -and $Role -cne 'signtool') {
        throw ("-PrintToolVersion accepts only powershell, infverif or signtool, not '{0}'" -f $Role)
    }
    $canonical = Assert-C4RunnerCanonicalAbsolutePath $Path '-ToolPath'
    if (-not [IO.File]::Exists($canonical)) {
        throw ("-ToolPath names no file: {0}" -f $canonical)
    }
    if (Test-C4RunnerReparse $canonical) {
        throw ("-ToolPath is a reparse point: {0}" -f $canonical)
    }
    # Leasing the file proves the canonical path is not an alias for another
    # payload before a single byte of its version resource is read.
    $lease = Open-C4HeldFileLease -Path $canonical -ExpectedSha256 (Get-C4RunnerSha256File $canonical)
    try {
        $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($canonical)
        $file = [string]$info.FileVersion
        $product = [string]$info.ProductVersion
        foreach ($pair in @(@('FileVersion', $file), @('ProductVersion', $product))) {
            if ([string]::IsNullOrWhiteSpace($pair[1])) {
                throw ("{0} version resource component {1} is blank" -f $Role, $pair[0])
            }
            foreach ($char in $pair[1].ToCharArray()) {
                if ([int]$char -lt 32 -or [int]$char -eq 127) {
                    throw ("{0} version resource component {1} carries a control character" -f $Role, $pair[0])
                }
            }
            if ($pair[1].Contains('|')) {
                throw ("{0} version resource component {1} carries the field separator" -f $Role, $pair[0])
            }
        }
        Assert-C4HeldFileLease $lease
        Write-C4RunnerStdoutLine ($file + '|' + $product)
    } finally {
        Close-C4HeldFileLease $lease
    }
}

# ---------------------------------------------------------------------------
# Tool version capture and semantics
# ---------------------------------------------------------------------------

function Expand-C4RunnerVersionArgv {
    param([string]$Role, $Leases, [string]$SelfPath)
    $expanded = New-Object System.Collections.ArrayList
    foreach ($element in @($script:VersionArgvTemplates[$Role])) {
        $value = [string]$element
        $value = $value.Replace('{powershell}', $Leases['powershell'].Path)
        $value = $value.Replace('{self}', $SelfPath)
        $value = $value.Replace('{role}', $Leases[$Role].Path)
        [void]$expanded.Add($value)
    }
    return (,@($expanded))
}

# The semantic oracle. A capture that exits zero but names a different release
# is exactly the drift a path freeze cannot see, so each class is checked
# against what its own output must say.
function Test-C4RunnerVersionSemantics {
    param($VersionText)

    $text = [ordered]@{}
    foreach ($role in $script:ToolRoles) { $text[$role] = [string]$VersionText[$role] }

    foreach ($pair in @(
        @('cargo-1.82.0', '1.82.0'), @('rustc-1.82.0', '1.82.0'), @('rustdoc-1.82.0', '1.82.0'),
        @('cargo-1.85.0', '1.85.0'), @('rustc-1.85.0', '1.85.0'), @('rustdoc-1.85.0', '1.85.0'))) {
        $role = $pair[0]
        $version = $pair[1]
        if (-not $text[$role].Contains('release: ' + $version)) {
            throw ("TOOL_FREEZE: {0} does not report release {1}" -f $role, $version)
        }
        if (-not $text[$role].Contains('commit-hash: ')) {
            throw ("TOOL_FREEZE: {0} does not report a commit hash" -f $role)
        }
        if (-not $text[$role].Contains('host: ')) {
            throw ("TOOL_FREEZE: {0} does not report a host triple" -f $role)
        }
    }
    foreach ($pair in @(@('cargo-fmt-1.82.0', 'rustfmt-1.82.0'), @('cargo-fmt-1.85.0', 'rustfmt-1.85.0'))) {
        if ($text[$pair[0]].Trim() -cne $text[$pair[1]].Trim()) {
            throw ("TOOL_FREEZE: {0} and {1} report different rustfmt identities" -f $pair[0], $pair[1])
        }
    }
    foreach ($role in @('cargo-clippy-1.85.0', 'clippy-driver-1.85.0')) {
        if (-not $text[$role].Contains('0.1.85')) {
            throw ("TOOL_FREEZE: {0} does not report Clippy 0.1.85" -f $role)
        }
    }
    if ($text['cargo-wdk-0.1.1'].Trim() -cne 'cargo wdk 0.1.1') {
        throw 'TOOL_FREEZE: cargo-wdk does not report exactly "cargo wdk 0.1.1"'
    }
    foreach ($role in @('infverif', 'signtool')) {
        if ($text[$role].Trim() -cnotmatch '^[^|]+\|[^|]+$') {
            throw ("TOOL_FREEZE: {0} did not report FileVersion|ProductVersion" -f $role)
        }
    }
    if ($text['python'] -cnotmatch '(?m)Python 3\.') {
        throw 'TOOL_FREEZE: python does not report a 3.x version'
    }
    if (-not $text['git'].Contains('git version ')) {
        throw 'TOOL_FREEZE: git does not report a version'
    }
    if (-not $text['git-bash'].Contains('GNU bash')) {
        throw 'TOOL_FREEZE: git-bash does not report GNU bash'
    }
    if (-not $text['cmd'].Contains('Microsoft Windows')) {
        throw 'TOOL_FREEZE: cmd built-in ver did not name Microsoft Windows'
    }
    if ([string]::IsNullOrWhiteSpace($text['powershell'])) {
        throw 'TOOL_FREEZE: powershell reported no version'
    }
}

# ---------------------------------------------------------------------------
# Cargo environment and the sealed configuration candidate set
#
# A frozen `cargo.exe` still reads `.cargo/config.toml` from its working
# directory upward and from Cargo home. An unsealed one of those can inject a
# wrapper, rustflags, a target linker, an alias, or an external subcommand --
# every one of which changes what actually ran without changing one frozen
# path. So the complete candidate set is enumerated, hashed, and sealed, and
# exactly one present source-tracked file is admissible.
# ---------------------------------------------------------------------------

function Get-C4RunnerCargoHome {
    param($Overrides)
    if ($null -ne $Overrides -and $Overrides.Contains('cargoHome')) {
        return [IO.Path]::GetFullPath([string]$Overrides['cargoHome'])
    }
    # See Get-C4RunnerRustupHome: `$home` is $HOME, which is read-only.
    $cargoRoot = [string]$env:CARGO_HOME
    if ([string]::IsNullOrWhiteSpace($cargoRoot)) {
        $userProfile = [string]$env:USERPROFILE
        if ([string]::IsNullOrWhiteSpace($userProfile)) { throw 'neither CARGO_HOME nor USERPROFILE is set' }
        $cargoRoot = Join-Path $userProfile '.cargo'
    }
    $full = [IO.Path]::GetFullPath($cargoRoot)
    if (Test-C4RunnerReparse $full) { throw 'Cargo home is a reparse point' }
    return $full
}

# The preaccept-known static positions. Every manifest row runs at the
# repository root, so the root and its ancestors are the search chain; `driver`
# is included because rows 19-20 launch a helper documented to run there and
# rows 06-08 name `driver/Cargo.toml`, which makes it a statically known
# position rather than a runtime discovery.
function Get-C4RunnerConfigSearchDirectories {
    param([string]$RepoRoot, [string]$CargoHome)

    $directories = New-Object System.Collections.ArrayList
    [void]$directories.Add($CargoHome)
    $cursor = [IO.Path]::GetFullPath((Join-Path $RepoRoot 'driver'))
    while ($true) {
        [void]$directories.Add($cursor)
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $cursor) { break }
        $cursor = $parent
    }
    return (,@($directories))
}

function Read-C4RunnerConfigCandidates {
    param([string]$RepoRoot, [string]$CargoHome, [string]$TrackedConfigSha256)

    $rows = New-Object System.Collections.ArrayList
    $trackedPath = [IO.Path]::GetFullPath((Join-Path $RepoRoot $script:TrackedCargoConfigRelativePath))
    foreach ($directory in (Get-C4RunnerConfigSearchDirectories $RepoRoot $CargoHome)) {
        foreach ($name in @('config', 'config.toml')) {
            $candidate = $null
            if ($directory -ceq $CargoHome) {
                $candidate = [IO.Path]::GetFullPath((Join-Path $directory $name))
            } else {
                $candidate = [IO.Path]::GetFullPath((Join-Path $directory ('.cargo/' + $name)))
            }
            $present = [IO.File]::Exists($candidate)
            $isTracked = ($candidate -ceq $trackedPath)
            $scope = 'EXTERNAL'
            if ($isTracked) { $scope = 'SOURCE_TRACKED' }
            $bytes = 0
            $sha = $null
            $sourceRelative = $null
            if ($present) {
                if (Test-C4RunnerReparse $candidate) {
                    throw ("Cargo configuration candidate is a reparse point: {0}" -f $candidate)
                }
                if (-not $isTracked) {
                    throw ("an unsealed Cargo configuration is present: {0}" -f $candidate)
                }
                $raw = [IO.File]::ReadAllBytes($candidate)
                $bytes = [int64]$raw.Length
                $sha = Get-C4EvidenceSha256Hex $raw
                $sourceRelative = $script:TrackedCargoConfigRelativePath
                if ($sha -cne $TrackedConfigSha256) {
                    throw 'the tracked Cargo configuration does not match its committed tree blob'
                }
            }
            [void]$rows.Add([ordered]@{
                path = $candidate
                scope = $scope
                present = [bool]$present
                sourceRelativePath = $sourceRelative
                bytes = [int64]$bytes
                sha256 = $sha
            })
        }
    }
    $ordered = @($rows | Sort-Object -Property { [string]$_.path } -CaseSensitive)
    return (,@($ordered))
}

function Assert-C4RunnerConfigCandidatesUnchanged {
    param([string]$RepoRoot, [string]$CargoHome, [string]$TrackedConfigSha256, $Sealed)
    $now = Read-C4RunnerConfigCandidates $RepoRoot $CargoHome $TrackedConfigSha256
    $left = (ConvertTo-C4CanonicalJsonText @($Sealed))
    $right = (ConvertTo-C4CanonicalJsonText @($now))
    if ($left -cne $right) {
        throw 'IDENTITY_DRIFT: the Cargo configuration candidate set changed'
    }
}

function New-C4RunnerCargoEnvironment {
    param([string]$CargoHome, $ConfigCandidates, [string[]]$PathDirectories)
    return [ordered]@{
        cargoHome = $CargoHome
        cargoHomeBinExcluded = $true
        configCandidates = @($ConfigCandidates)
        inheritedSelectorNames = @()
        cargoIncremental = '0'
        pathDirectories = @($PathDirectories)
    }
}

# The child PATH is closed: the directory of every frozen role, minus Cargo
# home's `bin`. A helper that could reach an unfrozen executable through PATH
# would make the freeze descriptive rather than binding.
function Get-C4RunnerChildPathDirectories {
    param($Leases, [string]$CargoHome)

    $cargoBin = [IO.Path]::GetFullPath((Join-Path $CargoHome 'bin')).ToUpperInvariant()
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $ordered = New-Object System.Collections.ArrayList
    foreach ($role in $script:ToolRoles) {
        $directory = [IO.Path]::GetDirectoryName($Leases[$role].Path)
        if ($directory.ToUpperInvariant() -ceq $cargoBin) { continue }
        if ($seen.Add($directory.ToUpperInvariant())) { [void]$ordered.Add($directory) }
    }
    # System32 carries the OS payloads a normal child process needs before it
    # can reach any frozen role at all; it is recorded like every other entry.
    $system32 = [IO.Path]::GetFullPath((Join-Path ([string]$env:SystemRoot) 'System32'))
    if ($seen.Add($system32.ToUpperInvariant())) { [void]$ordered.Add($system32) }
    # The Git distribution's own utilities. `git-bash` is Git\bin\bash.exe but
    # `cygpath` and `sha256sum` live in Git\usr\bin, and row 11's shell helper
    # needs both to hash the payloads it is about to launch. Without this the
    # helper found neither and reported an empty hash rather than failing --
    # the marker carried "sha256":"" and the identity check compared a real
    # value against nothing. The directory holds no cargo, rustc or rustdoc, so
    # it is not a route to an unfrozen Rust payload, which is the property the
    # closed PATH exists to protect.
    $bashDirectory = [IO.Path]::GetDirectoryName($Leases['git-bash'].Path)
    $gitRoot = [IO.Path]::GetDirectoryName($bashDirectory)
    $gitUsrBin = [IO.Path]::GetFullPath((Join-Path $gitRoot 'usr\bin'))
    if ([IO.Directory]::Exists($gitUsrBin) -and $seen.Add($gitUsrBin.ToUpperInvariant())) {
        [void]$ordered.Add($gitUsrBin)
    }
    return (,@($ordered))
}

# ---------------------------------------------------------------------------
# Child environment
# ---------------------------------------------------------------------------

function Get-C4RunnerInheritedSelectorNames {
    $found = New-Object System.Collections.ArrayList
    foreach ($entry in [Environment]::GetEnvironmentVariables().Keys) {
        $name = [string]$entry
        $upper = $name.ToUpperInvariant()
        $hit = $false
        if ($script:ForbiddenSelectorNames -contains $upper) { $hit = $true }
        foreach ($prefix in $script:ForbiddenSelectorPrefixes) {
            if ($upper.StartsWith($prefix, [StringComparison]::Ordinal)) { $hit = $true }
        }
        if ($hit) { [void]$found.Add($name) }
    }
    return (,@($found | Sort-Object -CaseSensitive))
}

function Remove-C4RunnerInheritedSelectors {
    foreach ($name in (Get-C4RunnerInheritedSelectorNames)) {
        Set-Item -LiteralPath ('Env:' + $name) -Value '' -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ('Env:' + $name) -ErrorAction SilentlyContinue
    }
}

function Get-C4RunnerRoleEnvironmentSuffix {
    param([string]$Role)
    return $Role.ToUpperInvariant().Replace('-', '_').Replace('.', '_')
}

# The row's payload set travels in closed `FSRING_C4_*` variables. A helper
# that ignores one is caught by its own marker: the roster it reports would not
# name the role the map requires.
function Test-C4RunnerMatrixRefusedName {
    param([string]$Name)
    $upper = $Name.ToUpperInvariant()
    if ($script:MatrixRefusedExactNames -contains $upper) { return $true }
    foreach ($prefix in $script:MatrixRefusedPrefixes) {
        if ($upper.StartsWith($prefix, [StringComparison]::Ordinal)) { return $true }
    }
    return ($upper -match $script:MatrixRefusedSuffixPattern)
}

# A `cmd+*` row hands its work to `build_matrix.cmd`, which owns its build
# environment and refuses a pre-set one. Clearing is what LETS that row run.
function Remove-C4RunnerMatrixRefusedVariables {
    $names = New-Object System.Collections.ArrayList
    foreach ($entry in [Environment]::GetEnvironmentVariables().Keys) {
        if (Test-C4RunnerMatrixRefusedName ([string]$entry)) { [void]$names.Add([string]$entry) }
    }
    foreach ($name in $names) {
        Set-Item -LiteralPath ('Env:' + $name) -Value '' -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ('Env:' + $name) -ErrorAction SilentlyContinue
    }
}

function Set-C4RunnerChildEnvironment {
    param($Leases, $CargoEnvironment, [int]$Ordinal, [string]$CommandId, [string]$Nonce,
          [string[]]$Roles, [string]$Toolchain)

    # Decided by the row's TOOLCHAIN CLASS. The nested-tool map is the wrong
    # signal: rows 19 and 20 hold exactly one Rust version in their map, which
    # is what made them look like single-version Cargo rows and set the very
    # selectors `build_matrix.cmd` refuses.
    $ownsItsBuildEnvironment = $Toolchain.StartsWith('cmd+', [StringComparison]::Ordinal)

    Remove-C4RunnerInheritedSelectors
    if (-not $ownsItsBuildEnvironment) {
        $env:CARGO_HOME = [string]$CargoEnvironment.cargoHome
        $env:CARGO_INCREMENTAL = [string]$CargoEnvironment.cargoIncremental
    }
    $env:PATH = (@($CargoEnvironment.pathDirectories) -join ';')
    # Cleared, not set to '': a helper that tests whether the variable is set
    # would otherwise be told yes and emit a marker with an empty nonce.
    if ([string]::IsNullOrEmpty($Nonce)) {
        Remove-Item -LiteralPath Env:FSRING_C4_MARKER_NONCE -ErrorAction SilentlyContinue
    } else {
        $env:FSRING_C4_MARKER_NONCE = $Nonce
    }
    $env:FSRING_C4_COMMAND_ID = $CommandId

    foreach ($role in $script:ToolRoles) {
        $suffix = Get-C4RunnerRoleEnvironmentSuffix $role
        foreach ($tail in @('', '_SHA256', '_VOLUME', '_FILEID')) {
            Remove-Item -LiteralPath ('Env:FSRING_C4_TOOL_' + $suffix + $tail) -ErrorAction SilentlyContinue
        }
    }
    # A helper's marker must carry all five identity fields, but a POSIX or
    # batch helper cannot read an NTFS volume serial or file ID. Path and
    # SHA-256 are the helper's OWN observations of what it launched, and the
    # runner checks both against its retained handle; the two identity fields
    # are echoed from the freeze so every producer emits the same shape.
    # A PowerShell helper takes its own lease and observes all four.
    foreach ($role in @($Roles)) {
        $suffix = Get-C4RunnerRoleEnvironmentSuffix $role
        Set-Item -LiteralPath ('Env:FSRING_C4_TOOL_' + $suffix) -Value $Leases[$role].Path
        Set-Item -LiteralPath ('Env:FSRING_C4_TOOL_' + $suffix + '_SHA256') -Value $Leases[$role].Sha256
        Set-Item -LiteralPath ('Env:FSRING_C4_TOOL_' + $suffix + '_VOLUME') -Value $Leases[$role].VolumeSerial
        Set-Item -LiteralPath ('Env:FSRING_C4_TOOL_' + $suffix + '_FILEID') -Value $Leases[$role].FileId
    }

    # A single-version Cargo row also sets the exact unsuffixed selectors; a
    # mixed row must not, because an unversioned fallback there would let a
    # helper pick whichever payload it happened to find first.
    foreach ($name in @('CARGO', 'RUSTC', 'RUSTDOC', 'RUSTFMT', 'CLIPPY_DRIVER_PATH')) {
        Remove-Item -LiteralPath ('Env:' + $name) -ErrorAction SilentlyContinue
    }
    $versions = New-Object System.Collections.Generic.HashSet[string]
    foreach ($role in @($Roles)) {
        if ($role -match '-(1\.\d+\.\d+)$') { [void]$versions.Add($Matches[1]) }
    }
    if ($versions.Count -eq 1 -and -not $ownsItsBuildEnvironment) {
        $version = @($versions)[0]
        if (@($Roles) -contains ('cargo-' + $version)) { $env:CARGO = $Leases['cargo-' + $version].Path }
        if (@($Roles) -contains ('rustc-' + $version)) { $env:RUSTC = $Leases['rustc-' + $version].Path }
        if (@($Roles) -contains ('rustdoc-' + $version)) { $env:RUSTDOC = $Leases['rustdoc-' + $version].Path }
        if (@($Roles) -contains ('rustfmt-' + $version)) { $env:RUSTFMT = $Leases['rustfmt-' + $version].Path }
        if (@($Roles) -contains ('clippy-driver-' + $version)) {
            $env:CLIPPY_DRIVER_PATH = $Leases['clippy-driver-' + $version].Path
        }
    }

    # Last, so nothing above can reintroduce a refused name. This clears more
    # than the runner sets: the matrix also refuses CL, LINK, AR and CFLAGS,
    # which a Visual Studio developer prompt exports and the runner's own
    # inherited-selector scrub does not cover.
    if ($ownsItsBuildEnvironment) { Remove-C4RunnerMatrixRefusedVariables }
}

# ---------------------------------------------------------------------------
# The nested-tool marker protocol
#
# Rows 03-08 and 24-27 launch a frozen payload directly, so their nested roles
# are enforced by the closed environment and PATH rather than by a marker:
# Cargo cannot emit one. Row 11 is NOT one of them -- it appears in the list
# below and the evidence shows it emitting two markers; naming it in both
# places was a documentation defect a review caught, not a second policy.
# The nine rows below DO drive their own child roster, and each is required
# to report it.
# ---------------------------------------------------------------------------

$script:MarkerProducingOrdinals = @(1, 11, 12, 14, 19, 20, 21, 33, 34)

function Read-C4RunnerMarkers {
    param([byte[]]$StdoutBytes, [string]$Nonce, [string]$CommandId)

    $utf8 = New-Object System.Text.UTF8Encoding $false
    $text = $utf8.GetString($StdoutBytes)
    $markers = New-Object System.Collections.ArrayList
    foreach ($line in $text.Split("`n")) {
        $trimmed = $line.TrimEnd("`r")
        if (-not $trimmed.StartsWith($script:NestedToolMarkerSentinel, [StringComparison]::Ordinal)) { continue }
        $json = $trimmed.Substring($script:NestedToolMarkerSentinel.Length)
        $parsed = $null
        try {
            $parsed = $json | ConvertFrom-Json
        } catch {
            throw 'IDENTITY_DRIFT: a nested-tool marker is not parseable JSON'
        }
        if ($parsed.schema -cne $script:NestedToolMarkerSchema) {
            throw 'IDENTITY_DRIFT: a nested-tool marker carries the wrong schema'
        }
        if ($parsed.nonce -cne $Nonce) {
            throw 'IDENTITY_DRIFT: a nested-tool marker carries a foreign nonce'
        }
        if ($parsed.commandId -cne $CommandId) {
            throw 'IDENTITY_DRIFT: a nested-tool marker names a different command'
        }
        [void]$markers.Add($parsed)
    }
    return (,@($markers))
}

function Test-C4RunnerMarkerRoster {
    param([int]$Ordinal, $Markers, $Leases)

    $expectedRoles = @($script:NestedToolMap[$Ordinal])
    if ($script:MarkerProducingOrdinals -notcontains $Ordinal) {
        if (@($Markers).Count -ne 0) {
            throw ("IDENTITY_DRIFT: row {0:d2} emitted a nested-tool marker it does not own" -f $Ordinal)
        }
        return
    }
    if (@($Markers).Count -ne 2) {
        throw ("IDENTITY_DRIFT: row {0:d2} reported {1} nested-tool markers, expected exactly PRE and POST" -f $Ordinal, @($Markers).Count)
    }
    if ($Markers[0].phase -cne 'PRE' -or $Markers[1].phase -cne 'POST') {
        throw ("IDENTITY_DRIFT: row {0:d2} nested-tool markers are not PRE then POST" -f $Ordinal)
    }
    foreach ($marker in $Markers) {
        $roles = @(@($marker.tools) | ForEach-Object { [string]$_.role })
        if ($roles.Count -ne $expectedRoles.Count) {
            throw ("IDENTITY_DRIFT: row {0:d2} marker names {1} roles, expected {2}" -f $Ordinal, $roles.Count, $expectedRoles.Count)
        }
        for ($i = 0; $i -lt $expectedRoles.Count; $i++) {
            if ($roles[$i] -cne $expectedRoles[$i]) {
                throw ("IDENTITY_DRIFT: row {0:d2} marker role {1} is '{2}', expected '{3}'" -f $Ordinal, $i, $roles[$i], $expectedRoles[$i])
            }
            $entry = @($marker.tools)[$i]
            $lease = $Leases[$expectedRoles[$i]]
            if ([string]$entry.path -cne $lease.Path -or
                [string]$entry.volumeSerial -cne $lease.VolumeSerial -or
                [string]$entry.fileId -cne $lease.FileId -or
                [string]$entry.sha256 -cne $lease.Sha256) {
                throw ("IDENTITY_DRIFT: row {0:d2} marker identity for {1} does not match the retained handle" -f $Ordinal, $expectedRoles[$i])
            }
        }
    }
    # PRE and POST must be identical rosters: a helper that swapped a payload
    # midway would otherwise report the truth twice and hide the swap.
    if ((ConvertTo-C4CanonicalJsonText @($Markers[0].tools)) -cne (ConvertTo-C4CanonicalJsonText @($Markers[1].tools))) {
        throw ("IDENTITY_DRIFT: row {0:d2} PRE and POST marker rosters differ" -f $Ordinal)
    }
    if ($script:ExpectedMarkerLaunchCounts.ContainsKey($Ordinal)) {
        $expectedCounts = $script:ExpectedMarkerLaunchCounts[$Ordinal]
        $observed = @($Markers[1].launchCounts)
        if ($observed.Count -ne @($expectedCounts.Keys).Count) {
            throw ("IDENTITY_DRIFT: row {0:d2} reported {1} launch counts, expected {2}" -f $Ordinal, $observed.Count, @($expectedCounts.Keys).Count)
        }
        $index = 0
        foreach ($role in @($expectedCounts.Keys)) {
            if ([string]$observed[$index].role -cne $role) {
                throw ("IDENTITY_DRIFT: row {0:d2} launch count {1} names '{2}', expected '{3}'" -f $Ordinal, $index, $observed[$index].role, $role)
            }
            if ([int]$observed[$index].count -ne [int]$expectedCounts[$role]) {
                throw ("IDENTITY_DRIFT: row {0:d2} launched {1} {2} times, expected {3}" -f $Ordinal, $role, $observed[$index].count, $expectedCounts[$role])
            }
            $index += 1
        }
    }
}

# ---------------------------------------------------------------------------
# Argv expansion
#
# The literal `powershell.exe`, `python`, `cargo`, `cargo-fmt`, `cargo-clippy`,
# `cmd.exe`, `git` and `{git-bash}` at argv[0] are replaced with the frozen
# payload for the row's toolchain class. Cargo never finds `cargo-fmt` or
# `cargo-clippy` as an ambient external subcommand.
# ---------------------------------------------------------------------------

function Get-C4RunnerLaunchRole {
    param([int]$Ordinal, [string]$Argv0, [string]$Toolchain)

    switch ($Argv0) {
        'powershell.exe' { return 'powershell' }
        'python' { return 'python' }
        'cmd.exe' { return 'cmd' }
        'git' { return 'git' }
        '{git-bash}' { return 'git-bash' }
        'cargo-fmt' {
            if ($Toolchain -ceq 'rust-1.82.0') { return 'cargo-fmt-1.82.0' }
            return 'cargo-fmt-1.85.0'
        }
        'cargo-clippy' { return 'cargo-clippy-1.85.0' }
        'cargo' {
            if ($Toolchain -ceq 'rust-1.82.0') { return 'cargo-1.82.0' }
            return 'cargo-1.85.0'
        }
        default {
            throw ("gate row {0:d2} argv[0] '{1}' is not a frozen role" -f $Ordinal, $Argv0)
        }
    }
}

# The external-subcommand word cargo would have supplied.
#
# `cargo clippy ARGS` is dispatched by cargo as `cargo-clippy clippy ARGS`, and
# cargo-clippy strips that first word. Launching the frozen payload directly
# without it makes clippy forward the row's flags to `cargo check`, which
# answers `unexpected argument 'driver/Cargo.toml' found`. The manifest keeps
# the design's exact argv; the runner supplies the word when it substitutes
# argv[0], and the sealed `argv` records what actually ran.
#
# `cargo-fmt` is deliberately NOT in this map. It accepts its flags without the
# `fmt` word, rows 03 and 06 pass as written, and adding a word a passing row
# does not need would be a change made for symmetry rather than for a reason.
$script:ExternalSubcommandWords = @{
    'cargo-clippy' = 'clippy'
}

function Expand-C4RunnerRowArgv {
    param([int]$Ordinal, $Spec, $Leases, $Context)

    $literal = [string]@($Spec.argv)[0]
    $role = Get-C4RunnerLaunchRole $Ordinal $literal ([string]$Spec.toolchain)
    $expanded = New-Object System.Collections.ArrayList
    [void]$expanded.Add($Leases[$role].Path)
    if ($script:ExternalSubcommandWords.ContainsKey($literal)) {
        [void]$expanded.Add([string]$script:ExternalSubcommandWords[$literal])
    }
    for ($i = 1; $i -lt @($Spec.argv).Count; $i++) {
        $value = [string]@($Spec.argv)[$i]
        $value = $value.Replace('{attempt}', ($Context.AttemptRoot -replace '\\', '/'))
        $value = $value.Replace('{scratch}', ($Context.ScratchRoot -replace '\\', '/'))
        $value = $value.Replace('{S}', $Context.SourceCommit)
        $value = $value.Replace('{T}', $Context.SourceTree)
        $value = $value.Replace('{infverif}', $Leases['infverif'].Path)
        $value = $value.Replace('{signtool}', $Leases['signtool'].Path)
        [void]$expanded.Add($value)
    }
    return [pscustomobject]@{
        Role = $role
        Argv = @($expanded)
    }
}

# ---------------------------------------------------------------------------
# Adapters
#
# One seam. Production drives real children through the committed capture
# helper; the self-test substitutes a deterministic writer so 38 fixtures do
# not each rebuild the workspace. Everything this script actually owns --
# manifest validation, the tool freeze, leases, markers, the fail-stop ladder
# and the four sealed manifests -- runs identically on both sides. The real
# process capture is owned and separately self-tested by
# `invoke_c4_evidence.ps1`, which is row 02.
# ---------------------------------------------------------------------------

function New-C4RunnerProductionAdapters {
    return [pscustomobject]@{
        CaptureProcess = {
            param($Executable, $Arguments, $WorkingDirectory, $TimeoutMilliseconds, $StdoutPath, $StderrPath, $ExitPath)
            Invoke-C4EvidenceProcess -Executable $Executable -Arguments @($Arguments) `
                -WorkingDirectory $WorkingDirectory -TimeoutMilliseconds $TimeoutMilliseconds `
                -StdoutPath $StdoutPath -StderrPath $StderrPath -ExitPath $ExitPath `
                -ExitFormat CanonicalJson
        }
    }
}

function Invoke-C4RunnerCapture {
    param($Adapters, [string]$Executable, [string[]]$Arguments, [string]$WorkingDirectory,
          [int]$TimeoutMilliseconds, [string]$StdoutPath, [string]$StderrPath, [string]$ExitPath)
    & $Adapters.CaptureProcess $Executable @($Arguments) $WorkingDirectory $TimeoutMilliseconds `
        $StdoutPath $StderrPath $ExitPath
}

function Read-C4RunnerCapturedExit {
    param([string]$ExitPath)
    return (ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($ExitPath)) `
        -ExpectedSchema $script:CapturedExitSchema)
}

# A runner-private git observation. It is deliberately NOT evidence: rows
# 35-38 capture the sealed git facts. This exists only so the pre-accept
# refusals can read a clean tree and the tracked config blob without inventing
# a second git implementation.
function Invoke-C4RunnerPrivateCapture {
    param($Adapters, [string]$Executable, [string[]]$Arguments, [string]$WorkingDirectory, [int]$TimeoutMilliseconds = 120000)

    $root = Join-Path ([IO.Path]::GetTempPath()) ('c4gr-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    [void][IO.Directory]::CreateDirectory($root)
    $savedCommandId = [string]$env:FSRING_C4_COMMAND_ID
    try {
        # An explicit sentinel, not an inference. These captures happen before
        # any row sets its own command ID, so under the gate they would inherit
        # the PARENT runner's value and look like whichever row launched this
        # process -- which is exactly how row 01's self-test once answered
        # `git status` with row 1's nested-tool markers and read them as a
        # dirty tree.
        $env:FSRING_C4_COMMAND_ID = $script:PrivateCaptureCommandId
        $out = Join-Path $root 'o.bin'
        $err = Join-Path $root 'e.bin'
        $exit = Join-Path $root 'x.json'
        Invoke-C4RunnerCapture $Adapters $Executable @($Arguments) $WorkingDirectory $TimeoutMilliseconds $out $err $exit
        $record = Read-C4RunnerCapturedExit $exit
        $utf8 = New-Object System.Text.UTF8Encoding $false
        return [pscustomobject]@{
            Termination = [string]$record.termination
            ExitCode = $record.observedExit
            Stdout = $utf8.GetString([IO.File]::ReadAllBytes($out))
            StdoutBytes = [IO.File]::ReadAllBytes($out)
            Stderr = $utf8.GetString([IO.File]::ReadAllBytes($err))
        }
    } finally {
        if ([string]::IsNullOrEmpty($savedCommandId)) {
            Remove-Item -LiteralPath Env:FSRING_C4_COMMAND_ID -ErrorAction SilentlyContinue
        } else {
            $env:FSRING_C4_COMMAND_ID = $savedCommandId
        }
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Pre-acceptance
# ---------------------------------------------------------------------------

function Test-C4RunnerPathContainment {
    param([string]$Outer, [string]$Inner)
    $left = $Outer.TrimEnd('\') + '\'
    return $Inner.StartsWith($left, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-C4RunnerExternalTargets {
    param([string]$RepoRoot, [string]$AuthorizedParent, [string]$AttemptRoot, [string]$ScratchRoot)

    $parent = Assert-C4RunnerCanonicalAbsolutePath $AuthorizedParent '-AuthorizedExternalParent'
    if (-not [IO.Directory]::Exists($parent)) {
        throw '-AuthorizedExternalParent must be an existing directory'
    }
    if (Test-C4RunnerReparse $parent) { throw '-AuthorizedExternalParent is a reparse point' }
    $attempt = Assert-C4RunnerCanonicalAbsolutePath $AttemptRoot '-OutputDirectory'
    $scratch = Assert-C4RunnerCanonicalAbsolutePath $ScratchRoot '-ScratchDirectory'
    foreach ($pair in @(@('-OutputDirectory', $attempt), @('-ScratchDirectory', $scratch))) {
        $name = $pair[0]
        $path = $pair[1]
        if ([IO.Path]::GetDirectoryName($path) -cne $parent) {
            throw ("{0} must be a direct child of the authorized external parent" -f $name)
        }
        if ([IO.Directory]::Exists($path) -or [IO.File]::Exists($path)) {
            throw ("{0} must be absent" -f $name)
        }
        if (Test-C4RunnerPathContainment $RepoRoot $path -or $path -ceq $RepoRoot) {
            throw ("{0} must be outside the repository" -f $name)
        }
    }
    if ($attempt -ceq $scratch) { throw 'attempt and scratch must be different directories' }
    if ((Test-C4RunnerPathContainment $attempt $scratch) -or (Test-C4RunnerPathContainment $scratch $attempt)) {
        throw 'scratch must be a sibling of the attempt, never inside it'
    }
    return [pscustomobject]@{ Parent = $parent; Attempt = $attempt; Scratch = $scratch }
}

function Get-C4RunnerTrackedConfigBlobSha256 {
    param($Adapters, $Leases, [string]$RepoRoot, [string]$SourceTree)

    $show = Invoke-C4RunnerPrivateCapture $Adapters $Leases['git'].Path `
        @('show', ($SourceTree + ':' + $script:TrackedCargoConfigRelativePath)) $RepoRoot
    if ($show.Termination -cne 'NORMAL' -or [int]$show.ExitCode -ne 0) {
        throw ('the tracked Cargo configuration is absent from tree ' + $SourceTree)
    }
    return (Get-C4EvidenceSha256Hex $show.StdoutBytes)
}

function Assert-C4RunnerCleanSourceIdentity {
    param($Adapters, $Leases, [string]$RepoRoot, [string]$ExpectedCommit, [string]$ExpectedTree)

    $status = Invoke-C4RunnerPrivateCapture $Adapters $Leases['git'].Path `
        @('status', '--porcelain=v1', '--untracked-files=all') $RepoRoot
    if ($status.Termination -cne 'NORMAL' -or [int]$status.ExitCode -ne 0) {
        throw 'git status did not complete'
    }
    if ($status.StdoutBytes.Length -ne 0) {
        throw 'the source tree is dirty; the gate runner requires a clean worktree'
    }
    $head = Invoke-C4RunnerPrivateCapture $Adapters $Leases['git'].Path @('rev-parse', 'HEAD') $RepoRoot
    if ($head.Termination -cne 'NORMAL' -or [int]$head.ExitCode -ne 0) { throw 'git rev-parse HEAD failed' }
    if ($head.Stdout.Trim() -cne $ExpectedCommit) {
        throw 'HEAD does not equal -ExpectedSourceCommit'
    }
    $tree = Invoke-C4RunnerPrivateCapture $Adapters $Leases['git'].Path @('rev-parse', 'HEAD^{tree}') $RepoRoot
    if ($tree.Termination -cne 'NORMAL' -or [int]$tree.ExitCode -ne 0) { throw 'git rev-parse HEAD^{tree} failed' }
    if ($tree.Stdout.Trim() -cne $ExpectedTree) {
        throw 'HEAD^{tree} does not equal -ExpectedSourceTree'
    }
}

# ---------------------------------------------------------------------------
# Sealed manifests
# ---------------------------------------------------------------------------

function New-C4RunnerToolRow {
    param([int]$Ordinal, [string]$Role, $Lease, [string[]]$VersionArgv, $Triplet, $AttemptRoot, $ExitRecord)

    $stdoutBytes = [IO.File]::ReadAllBytes((Join-Path $AttemptRoot $Triplet.Stdout))
    $stderrBytes = [IO.File]::ReadAllBytes((Join-Path $AttemptRoot $Triplet.Stderr))
    $exitBytes = [IO.File]::ReadAllBytes((Join-Path $AttemptRoot $Triplet.Exit))
    $observed = $null
    if ([string]$ExitRecord.termination -ceq 'NORMAL') { $observed = [int]$ExitRecord.observedExit }
    return [ordered]@{
        role = $Role
        path = $Lease.Path
        volumeSerial = $Lease.VolumeSerial
        fileId = $Lease.FileId
        bytes = [int64]$Lease.Length
        sha256 = $Lease.Sha256
        versionArgv = @($VersionArgv)
        versionStdout = $Triplet.Stdout
        versionStdoutBytes = [int64]$stdoutBytes.Length
        versionStdoutSha256 = (Get-C4EvidenceSha256Hex $stdoutBytes)
        versionStderr = $Triplet.Stderr
        versionStderrBytes = [int64]$stderrBytes.Length
        versionStderrSha256 = (Get-C4EvidenceSha256Hex $stderrBytes)
        versionExit = $Triplet.Exit
        versionExitBytes = [int64]$exitBytes.Length
        versionExitSha256 = (Get-C4EvidenceSha256Hex $exitBytes)
        observedExit = $observed
    }
}

function New-C4RunnerNotIssuedRow {
    param([int]$Ordinal, $Spec)
    $names = Get-C4RunnerCommandTripletNames $Ordinal $Spec.id
    $zero = Get-C4RunnerZeroBytesSha256
    $exitBytes = Get-C4RunnerCanonicalBytes ([ordered]@{
        schema = $script:CapturedExitSchema
        version = 1
        observedExit = $null
        timedOut = $false
        termination = 'NOT_ISSUED'
    })
    return [pscustomobject]@{
        Names = $names
        ExitBytes = $exitBytes
        ZeroSha256 = $zero
    }
}

function New-C4RunnerFailureDocument {
    # $CommandId is deliberately untyped: `[string]$null` collapses to '', and
    # the spec requires null for every pre-roster, tool-freeze and
    # candidate-seal failure. The typed version wrote "" into failure.json
    # while attempt.json's untyped copy wrote null -- two files disagreeing
    # about the same fact.
    param([string]$Kind, $CommandId, [string]$Detail)
    if ($script:FailureKinds -cnotcontains $Kind) { throw ("illegal failure kind {0}" -f $Kind) }
    if ([string]::IsNullOrWhiteSpace($Detail)) { throw 'a failure detail is required' }
    $single = $Detail -replace '[\r\n]+', ' '
    foreach ($char in $single.ToCharArray()) {
        if ([int]$char -lt 32 -or [int]$char -eq 127) {
            $single = ($single -replace '[\x00-\x1f\x7f]', ' ')
            break
        }
    }
    return [ordered]@{
        schema = $script:FailureSchema
        version = 1
        kind = $Kind
        commandId = $CommandId
        detail = $single.Trim()
    }
}

# The closed state-specific allowed-path set. `attempt-files.json` refuses any
# present file outside it, so bytes a failing row left behind cannot slip into
# a sealed attempt just because they look harmless.
function Get-C4RunnerAllowedPaths {
    param([string]$State, $CommandIndex, [bool]$CandidateSealed, $IssuedOrdinals)

    $allowed = New-Object System.Collections.Generic.HashSet[string]
    [void]$allowed.Add('failure.json')
    if ($State -ceq 'PRE_ROSTER') { return $allowed }

    for ($i = 0; $i -lt $script:ToolRoles.Count; $i++) {
        $triplet = Get-C4RunnerToolTripletNames ($i + 1) $script:ToolRoles[$i]
        [void]$allowed.Add($triplet.Stdout)
        [void]$allowed.Add($triplet.Stderr)
        [void]$allowed.Add($triplet.Exit)
    }
    [void]$allowed.Add('tools.json')
    if ($State -ceq 'TOOL_FREEZE') { return $allowed }

    for ($i = 0; $i -lt $script:ExpectedGateRows.Count; $i++) {
        $triplet = Get-C4RunnerCommandTripletNames ($i + 1) $script:ExpectedGateRows[$i].id
        [void]$allowed.Add($triplet.Stdout)
        [void]$allowed.Add($triplet.Stderr)
        [void]$allowed.Add($triplet.Exit)
    }
    [void]$allowed.Add('command-index.json')
    if ($null -ne $CommandIndex) {
        foreach ($row in @($CommandIndex.auxiliaryFiles)) {
            if ([bool]$row.present) { [void]$allowed.Add([string]$row.relativePath) }
        }
    }
    # Candidate artifact paths are admitted only when their producing row was
    # issued: rows 21 (package), 27 plus sealing (harness) and 30 (archives).
    if (@($IssuedOrdinals) -contains 21) {
        foreach ($path in $script:CandidateArtifactPaths[0..5]) { [void]$allowed.Add($path) }
    }
    if (@($IssuedOrdinals) -contains 27) {
        [void]$allowed.Add($script:HarnessCandidateRelativePath)
    }
    if (@($IssuedOrdinals) -contains 30) {
        [void]$allowed.Add('artifacts/archives/fsring-abi.zip')
        [void]$allowed.Add('artifacts/archives/fsring-spec.zip')
    }
    if ($CandidateSealed) { [void]$allowed.Add('candidate-artifacts.json') }
    return $allowed
}

function New-C4RunnerAttemptFiles {
    param([string]$AttemptRoot, [string]$AttemptId, $Allowed)

    $rows = New-Object System.Collections.ArrayList
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $prefix = $AttemptRoot.TrimEnd('\') + '\'
    foreach ($file in [IO.Directory]::EnumerateFiles($AttemptRoot, '*', [IO.SearchOption]::AllDirectories)) {
        $full = [IO.Path]::GetFullPath($file)
        if (-not $full.StartsWith($prefix, [StringComparison]::Ordinal)) {
            throw ('attempt roster escaped the attempt directory: ' + $full)
        }
        if (Test-C4RunnerReparse $full) {
            throw ('attempt roster reached a reparse point: ' + $full)
        }
        $relative = $full.Substring($prefix.Length).Replace('\', '/')
        if ($relative -ceq 'attempt-files.json' -or $relative -ceq 'attempt.json') { continue }
        if (-not $Allowed.Contains($relative)) {
            throw ('an unexpected file is present in the sealed attempt: ' + $relative)
        }
        if (-not $seen.Add($relative)) {
            throw ('duplicate attempt path alias: ' + $relative)
        }
        $bytes = [IO.File]::ReadAllBytes($full)
        [void]$rows.Add([ordered]@{
            relativePath = $relative
            bytes = [int64]$bytes.Length
            sha256 = (Get-C4EvidenceSha256Hex $bytes)
        })
    }
    $ordered = @($rows | Sort-Object -Property { [string]$_.relativePath } -CaseSensitive)
    return [ordered]@{
        schema = $script:AttemptFilesSchema
        version = 1
        attemptId = $AttemptId
        files = @($ordered)
    }
}

function New-C4RunnerAttemptManifest {
    param(
        [string]$AttemptId, [string]$SourceCommit, [string]$SourceTree,
        [string]$GateManifestSha256, $ToolsSha256, $CommandIndexSha256,
        $CandidateManifestSha256, $AttemptFilesSha256, [string]$GateStatus, $Failure
    )
    if ($script:GateStatuses -cnotcontains $GateStatus) {
        throw ("illegal gate status {0}" -f $GateStatus)
    }
    $failureRow = $null
    if ($null -ne $Failure) {
        $failureRow = [ordered]@{
            kind = [string]$Failure.kind
            commandId = $Failure.commandId
            detailRelativePath = 'failure.json'
            detailSha256 = [string]$Failure.detailSha256
        }
    }
    return [ordered]@{
        schema = $script:AttemptSchema
        version = 1
        attemptId = $AttemptId
        sourceCommit = $SourceCommit
        sourceTree = $SourceTree
        gateManifestSha256 = $GateManifestSha256
        toolsSha256 = $ToolsSha256
        commandIndexSha256 = $CommandIndexSha256
        candidateManifestSha256 = $CandidateManifestSha256
        attemptFilesSha256 = $AttemptFilesSha256
        gateStatus = $GateStatus
        failure = $failureRow
    }
}

# The closed status mapping. Every other cross-product is unreachable by
# construction rather than by assertion: the kind decides the status here and
# nowhere else.
function Get-C4RunnerGateStatusForKind {
    param([string]$Kind, [string]$ToolFreezeSubreason)

    switch ($Kind) {
        'PRE_ROSTER_IDENTITY' { return 'IDENTITY_DRIFT' }
        'IDENTITY_DRIFT' { return 'IDENTITY_DRIFT' }
        'COMMAND_TIMEOUT' { return 'TIMEOUT' }
        'COMMAND_FAIL' { return 'FAIL' }
        'COMMAND_START_FAILED' { return 'FAIL' }
        'COMMAND_CAPTURE_FAILED' { return 'FAIL' }
        'CANDIDATE_SEAL' { return 'FAIL' }
        'TOOL_FREEZE' {
            switch ($ToolFreezeSubreason) {
                'TIMEOUT' { return 'TIMEOUT' }
                'IDENTITY' { return 'IDENTITY_DRIFT' }
                default { return 'FAIL' }
            }
        }
        default { throw ("no status mapping for kind {0}" -f $Kind) }
    }
}

# ---------------------------------------------------------------------------
# Candidate sealing
# ---------------------------------------------------------------------------

function Get-C4RunnerPackageSetSha256 {
    param($MemberRows)
    return (Get-C4EvidenceSha256Hex (Get-C4RunnerCanonicalBytes ([ordered]@{
        schema = $script:PackageSetSchema
        version = 1
        members = @($MemberRows)
    })))
}

function New-C4RunnerFileRow {
    param([string]$AttemptRoot, [string]$RelativePath)
    $full = Join-Path $AttemptRoot ($RelativePath -replace '/', '\')
    if (-not [IO.File]::Exists($full)) {
        throw ("candidate artifact is absent: {0}" -f $RelativePath)
    }
    if (Test-C4RunnerReparse $full) {
        throw ("candidate artifact is a reparse point: {0}" -f $RelativePath)
    }
    $bytes = [IO.File]::ReadAllBytes($full)
    return [ordered]@{
        relativePath = $RelativePath
        bytes = [int64]$bytes.Length
        sha256 = (Get-C4EvidenceSha256Hex $bytes)
    }
}

function New-C4RunnerCandidateManifest {
    param($State, $PackageCandidate, $SmokeDriverRow)

    $attemptRoot = $State.AttemptRoot
    $memberRows = New-Object System.Collections.ArrayList
    foreach ($relative in $script:CandidateArtifactPaths[0..5]) {
        [void]$memberRows.Add((New-C4RunnerFileRow $attemptRoot $relative))
    }
    $setSha = Get-C4RunnerPackageSetSha256 @($memberRows)
    if ($setSha -cne [string]$PackageCandidate.package.setSha256) {
        throw 'the package set hash does not match the packager report'
    }
    $harnessRow = New-C4RunnerFileRow $attemptRoot $script:HarnessCandidateRelativePath
    $abiRow = New-C4RunnerFileRow $attemptRoot 'artifacts/archives/fsring-abi.zip'
    $specRow = New-C4RunnerFileRow $attemptRoot 'artifacts/archives/fsring-spec.zip'

    $artifacts = [ordered]@{
        package = [ordered]@{
            relativePath = 'artifacts/win10-x64-release/package'
            setSha256 = $setSha
            members = @($memberRows)
        }
        inf = $memberRows[0]
        sys = $memberRows[1]
        cat = $memberRows[2]
        pdb = $memberRows[3]
        map = $memberRows[4]
        certificate = $memberRows[5]
        harness = $harnessRow
        abiArchive = $abiRow
        specArchive = $specRow
    }
    $artifactSetSha = Get-C4EvidenceSha256Hex (Get-C4RunnerCanonicalBytes $artifacts)

    return [ordered]@{
        schema = $script:CandidateSchema
        version = 1
        attemptId = $State.AttemptId
        sourceCommit = $State.SourceCommit
        sourceTree = $State.SourceTree
        gateManifestSha256 = $State.GateManifestSha256
        commandIndexSha256 = $State.CommandIndexSha256
        profile = $script:CandidateProfile
        tools = @($State.ToolRows)
        packageVerifier = $PackageCandidate.packageVerifier
        smokeDriver = $SmokeDriverRow
        artifacts = $artifacts
        artifactSetSha256 = $artifactSetSha
    }
}

# ---------------------------------------------------------------------------
# Sealing
#
# Always. Once both directory reservations succeed the attempt is accepted and
# every exit from here writes the complete four-file chain, because an
# unsealed accepted attempt is indistinguishable from one that never ran.
# ---------------------------------------------------------------------------

function Complete-C4RunnerAttempt {
    param($State)

    $attemptRoot = $State.AttemptRoot
    $failureRecord = $null
    if ($null -ne $State.FailureKind) {
        $document = New-C4RunnerFailureDocument $State.FailureKind $State.FailureCommandId $State.FailureDetail
        $bytes = Get-C4RunnerCanonicalBytes $document
        $failurePath = Join-Path $attemptRoot 'failure.json'
        if (-not [IO.File]::Exists($failurePath)) {
            Write-C4RunnerExclusiveBytes $failurePath $bytes
        }
        $failureRecord = [pscustomobject]@{
            kind = $State.FailureKind
            commandId = $State.FailureCommandId
            detailSha256 = (Get-C4EvidenceSha256Hex $bytes)
        }
    }
    $allowed = Get-C4RunnerAllowedPaths $State.AllowedState $State.CommandIndex `
        ([bool]$State.CandidateSealed) @($State.IssuedOrdinals)
    $roster = New-C4RunnerAttemptFiles $attemptRoot $State.AttemptId $allowed
    $rosterBytes = Get-C4RunnerCanonicalBytes $roster
    Write-C4RunnerExclusiveBytes (Join-Path $attemptRoot 'attempt-files.json') $rosterBytes

    $status = 'PASS'
    if ($null -ne $State.FailureKind) {
        $status = Get-C4RunnerGateStatusForKind $State.FailureKind ([string]$State.ToolFreezeSubreason)
    }
    $manifest = New-C4RunnerAttemptManifest `
        -AttemptId $State.AttemptId -SourceCommit $State.SourceCommit -SourceTree $State.SourceTree `
        -GateManifestSha256 $State.GateManifestSha256 -ToolsSha256 $State.ToolsSha256 `
        -CommandIndexSha256 $State.CommandIndexSha256 `
        -CandidateManifestSha256 $State.CandidateManifestSha256 `
        -AttemptFilesSha256 (Get-C4EvidenceSha256Hex $rosterBytes) `
        -GateStatus $status -Failure $failureRecord
    Assert-C4RunnerExactKeys $manifest $script:AttemptKeys 'sealed attempt.json'
    Write-C4RunnerExclusiveBytes (Join-Path $attemptRoot 'attempt.json') (Get-C4RunnerCanonicalBytes $manifest)
    $State.GateStatus = $status
    return $manifest
}

# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------

function New-C4RunnerState {
    param([string]$AttemptId, [string]$AttemptRoot, [string]$ScratchRoot,
          [string]$SourceCommit, [string]$SourceTree, [string]$GateManifestSha256)
    return [pscustomobject]@{
        AttemptId = $AttemptId
        AttemptRoot = $AttemptRoot
        ScratchRoot = $ScratchRoot
        SourceCommit = $SourceCommit
        SourceTree = $SourceTree
        GateManifestSha256 = $GateManifestSha256
        ToolsSha256 = $null
        ToolRows = @()
        CommandIndexSha256 = $null
        CommandIndex = $null
        CandidateManifestSha256 = $null
        CandidateSealed = $false
        AllowedState = 'PRE_ROSTER'
        IssuedOrdinals = @()
        FailureKind = $null
        FailureCommandId = $null
        FailureDetail = $null
        ToolFreezeSubreason = $null
        GateStatus = $null
    }
}

function Set-C4RunnerFailure {
    param($State, [string]$Kind, $CommandId, [string]$Detail, [string]$ToolFreezeSubreason)
    if ($null -ne $State.FailureKind) { return }
    $State.FailureKind = $Kind
    $State.FailureCommandId = $CommandId
    $State.FailureDetail = $Detail
    $State.ToolFreezeSubreason = $ToolFreezeSubreason
}

function Invoke-C4RunnerToolFreeze {
    param($State, $Options, $Leases, $CargoEnvironment)

    $attemptRoot = $State.AttemptRoot
    [void][IO.Directory]::CreateDirectory((Join-Path $attemptRoot 'tools'))
    $rows = New-Object System.Collections.ArrayList
    $versionText = [ordered]@{}
    for ($i = 0; $i -lt $script:ToolRoles.Count; $i++) {
        $ordinal = $i + 1
        $role = $script:ToolRoles[$i]
        $triplet = Get-C4RunnerToolTripletNames $ordinal $role
        $argv = Expand-C4RunnerVersionArgv $role $Leases $Options.SelfPath
        Set-C4RunnerChildEnvironment $Leases $CargoEnvironment 0 ('tools/' + $role) '' @() 'version-capture'
        Invoke-C4RunnerCapture $Options.Adapters $argv[0] (@($argv)[1..($argv.Count - 1)]) `
            $Options.RepoRoot 60000 `
            (Join-Path $attemptRoot $triplet.Stdout) `
            (Join-Path $attemptRoot $triplet.Stderr) `
            (Join-Path $attemptRoot $triplet.Exit)
        $record = Read-C4RunnerCapturedExit (Join-Path $attemptRoot $triplet.Exit)
        if ([string]$record.termination -ceq 'TIMEOUT') {
            throw ('TOOL_FREEZE_TIMEOUT: version capture for ' + $role + ' timed out')
        }
        if ([string]$record.termination -cne 'NORMAL' -or [int]$record.observedExit -ne 0) {
            throw ('TOOL_FREEZE_FAIL: version capture for ' + $role + ' terminated ' + $record.termination)
        }
        Assert-C4HeldFileLease $Leases[$role]
        $utf8 = New-Object System.Text.UTF8Encoding $false
        $versionText[$role] = $utf8.GetString([IO.File]::ReadAllBytes((Join-Path $attemptRoot $triplet.Stdout)))
        [void]$rows.Add((New-C4RunnerToolRow $ordinal $role $Leases[$role] $argv $triplet $attemptRoot $record))
    }
    Test-C4RunnerVersionSemantics $versionText
    Assert-C4RunnerToolLeases $Leases

    $tools = [ordered]@{
        schema = $script:ToolsSchema
        version = 1
        cargoEnvironment = $CargoEnvironment
        tools = @($rows)
    }
    $bytes = Get-C4RunnerCanonicalBytes $tools
    Write-C4RunnerExclusiveBytes (Join-Path $attemptRoot 'tools.json') $bytes
    $State.ToolsSha256 = Get-C4EvidenceSha256Hex $bytes
    $State.ToolRows = @($rows)
    return $tools
}

function New-C4RunnerNestedToolEntries {
    param([int]$Ordinal, $Leases)
    $entries = New-Object System.Collections.ArrayList
    foreach ($role in @($script:NestedToolMap[$Ordinal])) {
        [void]$entries.Add([ordered]@{
            role = $role
            path = $Leases[$role].Path
            volumeSerial = $Leases[$role].VolumeSerial
            fileId = $Leases[$role].FileId
            sha256 = $Leases[$role].Sha256
        })
    }
    if (@($entries).Count -ne [int]$script:NestedToolEntryCounts[$Ordinal]) {
        throw ("row {0:d2} nested-tool entry count is {1}, expected {2}" -f $Ordinal, @($entries).Count, $script:NestedToolEntryCounts[$Ordinal])
    }
    return (,@($entries))
}

function Invoke-C4RunnerCommandRows {
    param($State, $Options, $Leases, $CargoEnvironment)

    $attemptRoot = $State.AttemptRoot
    [void][IO.Directory]::CreateDirectory((Join-Path $attemptRoot 'commands'))
    $rows = New-Object System.Collections.ArrayList
    $issued = New-Object System.Collections.ArrayList
    $stopped = $false
    $packageCandidate = $null

    for ($i = 0; $i -lt $script:ExpectedGateRows.Count; $i++) {
        $ordinal = $i + 1
        $spec = $script:ExpectedGateRows[$i]
        $commandId = ('{0:d2}-{1}' -f $ordinal, $spec.id)
        $names = Get-C4RunnerCommandTripletNames $ordinal $spec.id
        $nested = New-C4RunnerNestedToolEntries $ordinal $Leases
        $zero = Get-C4RunnerZeroBytesSha256

        if ($stopped) {
            $exitBytes = Get-C4RunnerCanonicalBytes ([ordered]@{
                schema = $script:CapturedExitSchema
                version = 1
                observedExit = $null
                timedOut = $false
                termination = 'NOT_ISSUED'
            })
            Write-C4RunnerExclusiveBytes (Join-Path $attemptRoot $names.Stdout) (New-Object byte[] 0)
            Write-C4RunnerExclusiveBytes (Join-Path $attemptRoot $names.Stderr) (New-Object byte[] 0)
            Write-C4RunnerExclusiveBytes (Join-Path $attemptRoot $names.Exit) $exitBytes
            [void]$rows.Add([ordered]@{
                ordinal = $ordinal
                id = $spec.id
                argv = @()
                cwd = $spec.cwd
                toolchain = $spec.toolchain
                nestedTools = @($nested)
                expectedExit = [int]$spec.expectedExit
                timeoutSeconds = [int]$spec.timeoutSeconds
                stdout = $names.Stdout
                stdoutBytes = [int64]0
                stdoutSha256 = $zero
                stderr = $names.Stderr
                stderrBytes = [int64]0
                stderrSha256 = $zero
                exit = $names.Exit
                exitBytes = [int64]$exitBytes.Length
                exitSha256 = (Get-C4EvidenceSha256Hex $exitBytes)
                observedExit = $null
                timedOut = $false
                status = 'NOT_ISSUED'
            })
            continue
        }

        $status = 'PASS'
        $observedExit = $null
        $timedOut = $false
        $detail = $null
        $failureKind = $null
        $expanded = $null

        try {
            Assert-C4RunnerToolLeases $Leases
            Assert-C4RunnerConfigCandidatesUnchanged $Options.RepoRoot $CargoEnvironment.cargoHome `
                $Options.TrackedConfigSha256 $CargoEnvironment.configCandidates
        } catch {
            $status = 'IDENTITY_DRIFT'
            $failureKind = 'IDENTITY_DRIFT'
            $detail = ('pre-launch identity drift at ' + $commandId + ': ' + $_.Exception.Message)
        }

        if ($status -ceq 'PASS') {
            $expanded = Expand-C4RunnerRowArgv $ordinal $spec $Leases $State
            # Only a marker-producing row gets a nonce. A helper with no nonce
            # has nothing to bind a marker to and stays quiet, which is how the
            # closed empty-map roster is enforced by construction.
            $nonce = ''
            if ($script:MarkerProducingOrdinals -contains $ordinal) {
                $nonce = [Guid]::NewGuid().ToString('N').ToUpperInvariant()
            }
            Set-C4RunnerChildEnvironment $Leases $CargoEnvironment $ordinal $commandId $nonce @($script:NestedToolMap[$ordinal]) ([string]$spec.toolchain)
            [void]$issued.Add($ordinal)
            try {
                Invoke-C4RunnerCapture $Options.Adapters $expanded.Argv[0] `
                    (@($expanded.Argv)[1..($expanded.Argv.Count - 1)]) $Options.RepoRoot `
                    ([int]$spec.timeoutSeconds * 1000) `
                    (Join-Path $attemptRoot $names.Stdout) `
                    (Join-Path $attemptRoot $names.Stderr) `
                    (Join-Path $attemptRoot $names.Exit)
            } catch {
                $status = 'FAIL'
                $failureKind = 'COMMAND_CAPTURE_FAILED'
                $detail = ('capture failed at ' + $commandId + ': ' + $_.Exception.Message)
                # A capture that died before it created its destinations still
                # owes the three files: a missing triplet reads exactly like a
                # deleted one.
                foreach ($pair in @(@($names.Stdout, $null), @($names.Stderr, $null))) {
                    $path = Join-Path $attemptRoot $pair[0]
                    if (-not [IO.File]::Exists($path)) {
                        Write-C4RunnerExclusiveBytes $path (New-Object byte[] 0)
                    }
                }
                $exitFile = Join-Path $attemptRoot $names.Exit
                if (-not [IO.File]::Exists($exitFile)) {
                    Write-C4RunnerExclusiveBytes $exitFile (Get-C4RunnerCanonicalBytes ([ordered]@{
                        schema = $script:CapturedExitSchema
                        version = 1
                        observedExit = $null
                        timedOut = $false
                        termination = 'CAPTURE_FAILED'
                    }))
                }
            }
            if ($status -ceq 'PASS') {
                $record = Read-C4RunnerCapturedExit (Join-Path $attemptRoot $names.Exit)
                $timedOut = [bool]$record.timedOut
                switch ([string]$record.termination) {
                    'NORMAL' {
                        $observedExit = [int]$record.observedExit
                        if ($observedExit -ne [int]$spec.expectedExit) {
                            $status = 'FAIL'
                            $failureKind = 'COMMAND_FAIL'
                            $detail = ('row ' + $commandId + ' exited ' + $observedExit + ', expected ' + $spec.expectedExit)
                        }
                    }
                    'TIMEOUT' {
                        $status = 'TIMEOUT'
                        $failureKind = 'COMMAND_TIMEOUT'
                        $detail = ('row ' + $commandId + ' timed out')
                    }
                    'START_FAILED' {
                        $status = 'FAIL'
                        $failureKind = 'COMMAND_START_FAILED'
                        $detail = ('row ' + $commandId + ' could not be started')
                    }
                    'CAPTURE_FAILED' {
                        $status = 'FAIL'
                        $failureKind = 'COMMAND_CAPTURE_FAILED'
                        $detail = ('row ' + $commandId + ' capture failed')
                    }
                    default {
                        $status = 'FAIL'
                        $failureKind = 'COMMAND_FAIL'
                        $detail = ('row ' + $commandId + ' reported an unknown termination')
                    }
                }
            }
            if ($status -ceq 'PASS') {
                try {
                    Assert-C4RunnerToolLeases $Leases
                    Assert-C4RunnerConfigCandidatesUnchanged $Options.RepoRoot $CargoEnvironment.cargoHome `
                        $Options.TrackedConfigSha256 $CargoEnvironment.configCandidates
                    $markers = Read-C4RunnerMarkers ([IO.File]::ReadAllBytes((Join-Path $attemptRoot $names.Stdout))) $nonce $commandId
                    Test-C4RunnerMarkerRoster $ordinal $markers $Leases
                } catch {
                    $status = 'IDENTITY_DRIFT'
                    $failureKind = 'IDENTITY_DRIFT'
                    $detail = ('post-launch identity drift at ' + $commandId + ': ' + $_.Exception.Message)
                }
            }
            if ($status -ceq 'PASS') {
                try {
                    $outcome = Test-C4RunnerRowPostcondition $State $Options $ordinal $commandId $attemptRoot $names $Leases
                    if ($ordinal -eq 21) { $packageCandidate = $outcome }
                } catch {
                    $status = 'FAIL'
                    $failureKind = 'COMMAND_FAIL'
                    $detail = ('row ' + $commandId + ' postcondition failed: ' + $_.Exception.Message)
                }
            }
        } else {
            # An unlaunched drifted row still needs its three files, because a
            # missing triplet is indistinguishable from a deleted one.
            Write-C4RunnerExclusiveBytes (Join-Path $attemptRoot $names.Stdout) (New-Object byte[] 0)
            Write-C4RunnerExclusiveBytes (Join-Path $attemptRoot $names.Stderr) (New-Object byte[] 0)
            Write-C4RunnerExclusiveBytes (Join-Path $attemptRoot $names.Exit) (Get-C4RunnerCanonicalBytes ([ordered]@{
                schema = $script:CapturedExitSchema
                version = 1
                observedExit = $null
                timedOut = $false
                termination = 'NOT_ISSUED'
            }))
        }

        $stdoutBytes = [IO.File]::ReadAllBytes((Join-Path $attemptRoot $names.Stdout))
        $stderrBytes = [IO.File]::ReadAllBytes((Join-Path $attemptRoot $names.Stderr))
        $exitBytes = [IO.File]::ReadAllBytes((Join-Path $attemptRoot $names.Exit))
        [void]$rows.Add([ordered]@{
            ordinal = $ordinal
            id = $spec.id
            argv = $(if ($null -eq $expanded) { @() } else { @($expanded.Argv) })
            cwd = $spec.cwd
            toolchain = $spec.toolchain
            nestedTools = @($nested)
            expectedExit = [int]$spec.expectedExit
            timeoutSeconds = [int]$spec.timeoutSeconds
            stdout = $names.Stdout
            stdoutBytes = [int64]$stdoutBytes.Length
            stdoutSha256 = (Get-C4EvidenceSha256Hex $stdoutBytes)
            stderr = $names.Stderr
            stderrBytes = [int64]$stderrBytes.Length
            stderrSha256 = (Get-C4EvidenceSha256Hex $stderrBytes)
            exit = $names.Exit
            exitBytes = [int64]$exitBytes.Length
            exitSha256 = (Get-C4EvidenceSha256Hex $exitBytes)
            observedExit = $observedExit
            timedOut = [bool]$timedOut
            status = $status
        })

        if ($status -cne 'PASS') {
            Set-C4RunnerFailure $State $failureKind $commandId $detail $null
            $stopped = $true
        }
    }

    $State.IssuedOrdinals = @($issued)
    # `present` means the producing row was issued and the file is retained.
    # A row whose semantic postcondition failed still keeps its bytes: the
    # verdict lives in that row's status, and deleting the evidence to keep a
    # roster tidy would be the wrong trade.
    $auxiliary = New-Object System.Collections.ArrayList
    $zero = Get-C4RunnerZeroBytesSha256
    $mutationListPresent = (@($issued) -contains 13)
    $verifierPresent = (@($issued) -contains 21)
    foreach ($name in $script:AuxiliaryFileNames) {
        $present = $false
        if ($name -ceq $script:MutationListRelativePath) { $present = $mutationListPresent }
        else { $present = $verifierPresent }
        $full = Join-Path $attemptRoot $name
        if ($present -and -not [IO.File]::Exists($full)) { $present = $false }
        $bytes = [int64]0
        $sha = $zero
        if ($present) {
            $raw = [IO.File]::ReadAllBytes($full)
            $bytes = [int64]$raw.Length
            $sha = Get-C4EvidenceSha256Hex $raw
        }
        [void]$auxiliary.Add([ordered]@{
            relativePath = $name
            present = [bool]$present
            bytes = $bytes
            sha256 = $sha
        })
    }

    $gateStatus = 'PASS'
    if ($null -ne $State.FailureKind) {
        $gateStatus = Get-C4RunnerGateStatusForKind $State.FailureKind $null
    }
    $index = [ordered]@{
        schema = $script:CommandIndexSchema
        version = 1
        attemptId = $State.AttemptId
        sourceCommit = $State.SourceCommit
        sourceTree = $State.SourceTree
        gateManifestSha256 = $State.GateManifestSha256
        toolsSha256 = $State.ToolsSha256
        commands = @($rows)
        auxiliaryFiles = @($auxiliary)
        gateStatus = $gateStatus
    }
    foreach ($row in @($rows)) {
        Assert-C4RunnerExactKeys $row $script:CommandRowKeys ('command index row ' + $row.ordinal)
        if ($script:CommandStatuses -cnotcontains [string]$row.status) {
            throw ('illegal command status ' + $row.status)
        }
    }
    $bytes = Get-C4RunnerCanonicalBytes $index
    Write-C4RunnerExclusiveBytes (Join-Path $attemptRoot 'command-index.json') $bytes
    $State.CommandIndexSha256 = Get-C4EvidenceSha256Hex $bytes
    $State.CommandIndex = $index
    return [pscustomobject]@{ Index = $index; PackageCandidate = $packageCandidate }
}

# ---------------------------------------------------------------------------
# Row postconditions
#
# Seven rows say something the exit code cannot. Each is checked against the
# retained bytes, never against a value the same row supplied twice.
# ---------------------------------------------------------------------------

function Test-C4RunnerRowPostcondition {
    param($State, $Options, [int]$Ordinal, [string]$CommandId, [string]$AttemptRoot, $Names, $Leases)

    $stdoutPath = Join-Path $AttemptRoot $Names.Stdout
    $stderrPath = Join-Path $AttemptRoot $Names.Stderr
    switch ($Ordinal) {
        12 {
            # Row 12 had row 14's exposure exactly, and it was found the way row
            # 14's was: an interrupted battery left a journal keyed to this tree,
            # and the next attempt replayed all 369 verdicts in seconds and
            # sealed PASS. Only row 14 carried `--no-resume`; this row now does
            # too, and this postcondition is what makes the flag more than a
            # claim about intent.
            #
            # The default sweep marks a replayed mutant in its own stdout, so the
            # detection is the sweep's word rather than an inference: one
            # ` (replayed)` is one mutant this attempt did not run.
            $utf8 = New-Object System.Text.UTF8Encoding $false
            $out = $utf8.GetString([IO.File]::ReadAllBytes($stdoutPath))
            if ($out -cmatch '\(replayed\)') {
                throw 'row 12 replayed journalled verdicts instead of executing the mutants'
            }
            $err = $utf8.GetString([IO.File]::ReadAllBytes($stderrPath))
            if ($err -cmatch 'resume: replaying') {
                throw 'row 12 opened a resume journal instead of executing the mutants'
            }
            if ($out -cnotmatch '(?m)^\s+\d+/\d+\s+(CAUGHT|SURVIVED|HARNESS)') {
                throw 'row 12 recorded no per-mutant verdict rows, so it did not execute the sweep'
            }
            # `\r?$`, because a Windows Python process writes CRLF and `$`
            # matches only immediately before the `\n`. The first version of
            # this line anchored on a bare `$` and refused a perfectly good row
            # after 104 minutes: the self-test passed because the fake stdout
            # joins its lines with LF, so the fixture was the one byte shape
            # production never emits. The healthy row-12 fixture now carries
            # CRLF for exactly that reason.
            if ($out -cnotmatch '(?m)^MUTATION SWEEP: PASS\r?$') {
                throw 'row 12 stdout carries no mutation sweep verdict line'
            }
            return $null
        }
        14 {
            # Row 14 is the only row whose exit code can be earned without doing
            # the work: `mutation_sweep` resumes from a crash journal keyed to
            # the tree fingerprint, so a sweep run locally on the candidate tree
            # just before the battery makes this row replay in seconds and still
            # print `c4 suite: PASS`. Two sealed attempts did exactly that. The
            # row carries `--no-resume`, but a flag is a claim about intent;
            # this reads the bytes and requires evidence of execution.
            $utf8 = New-Object System.Text.UTF8Encoding $false
            $err = $utf8.GetString([IO.File]::ReadAllBytes($stderrPath))
            if ($err -cmatch 'C4 resume: replaying') {
                throw 'row 14 replayed journalled verdicts instead of executing the mutants'
            }
            if ($err -cnotmatch 'C4 progress \d+/\d+') {
                throw 'row 14 recorded no per-mutant progress, so it did not execute the suite'
            }
            $out = $utf8.GetString([IO.File]::ReadAllBytes($stdoutPath))
            if ($out -cnotmatch 'c4 suite: PASS \(\d+ mandatory, \d+ caught\)') {
                throw 'row 14 stdout carries no c4 suite verdict line'
            }
            return $null
        }
        13 {
            $external = Join-Path $AttemptRoot $script:MutationListRelativePath
            if (-not [IO.File]::Exists($external)) {
                throw 'row 13 did not write the external mutation list'
            }
            $authoritative = Join-Path $Options.RepoRoot ($script:AuthoritativeMutationManifest -replace '/', '\')
            $left = ([IO.File]::ReadAllText($external) | ConvertFrom-Json)
            $right = ([IO.File]::ReadAllText($authoritative) | ConvertFrom-Json)
            if ((ConvertTo-C4CanonicalJsonText $left) -cne (ConvertTo-C4CanonicalJsonText $right)) {
                throw 'the external mutation list is not canonically identical to the authoritative manifest'
            }
            $leftIds = @(@($left.mutants) | ForEach-Object { [string]$_.id + '@' + [string]$_.anchorCount })
            $rightIds = @(@($right.mutants) | ForEach-Object { [string]$_.id + '@' + [string]$_.anchorCount })
            if (($leftIds -join '|') -cne ($rightIds -join '|')) {
                throw 'the external mutation list has different ordered mutant IDs or anchors'
            }
            return $null
        }
        21 {
            $bytes = [IO.File]::ReadAllBytes($stdoutPath)
            $utf8 = New-Object System.Text.UTF8Encoding $false
            $text = $utf8.GetString($bytes)
            $object = $null
            foreach ($line in $text.Split("`n")) {
                $trimmed = $line.TrimEnd("`r")
                if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
                if ($trimmed.StartsWith($script:NestedToolMarkerSentinel, [StringComparison]::Ordinal)) { continue }
                $object = $trimmed | ConvertFrom-Json
            }
            if ($null -eq $object -or $object.schema -cne $script:PackageCandidateSchema) {
                throw 'row 21 did not emit one canonical package-candidate object'
            }
            if ([string]$object.sourceCommit -cne $State.SourceCommit -or
                [string]$object.sourceTree -cne $State.SourceTree) {
                throw 'row 21 reported a different source identity'
            }
            if ([string]$object.status -cne 'PASS') {
                throw 'row 21 did not report a PASS package candidate'
            }
            foreach ($name in @('package-verifier.stdout.bin', 'package-verifier.stderr.bin', 'package-verifier.exit.json')) {
                if (-not [IO.File]::Exists((Join-Path $AttemptRoot $name))) {
                    throw ('row 21 did not retain ' + $name)
                }
            }
            $verifierExit = ConvertFrom-C4CanonicalJsonBytes `
                -Bytes ([IO.File]::ReadAllBytes((Join-Path $AttemptRoot 'package-verifier.exit.json'))) `
                -ExpectedSchema $script:CapturedExitSchema
            if ([string]$verifierExit.termination -cne 'NORMAL' -or [int]$verifierExit.observedExit -ne 0) {
                throw 'the package verifier capture is not a normal zero exit'
            }
            return $object
        }
        27 {
            $selected = Join-Path $State.ScratchRoot ($script:HarnessScratchRelativePath -replace '/', '\')
            $canonical = [IO.Path]::GetFullPath($selected)
            if (-not [IO.File]::Exists($canonical)) {
                throw 'row 27 did not produce the exact selected harness executable'
            }
            if (Test-C4RunnerReparse $canonical) { throw 'the selected harness executable is a reparse point' }
            if (-not (Test-C4RunnerPathContainment $State.ScratchRoot $canonical)) {
                throw 'the selected harness executable is outside scratch'
            }
            Assert-C4HeldFileLease $Leases['cargo-1.82.0']
            Assert-C4HeldFileLease $Leases['rustc-1.82.0']
            return $null
        }
        33 {
            # The auditor's own verdict line, with its counts, not the word
            # `PASS` anywhere in the output. A bare substring match accepted any
            # line that happened to contain it -- including a failure report
            # naming a passing row -- and accepted a self-test that ran zero
            # checks. The count is required to be non-zero for the same reason
            # the lifetime auditor's summary is: a self-test that asserts
            # nothing passes trivially.
            $utf8 = New-Object System.Text.UTF8Encoding $false
            $text = $utf8.GetString([IO.File]::ReadAllBytes($stdoutPath))
            $verdict = [regex]::Match(
                $text, '(?m)^audit_c4_production_graph self-test: PASS \((\d+) checks, 0 failures\)\r?$')
            if (-not $verdict.Success) {
                throw 'row 33 did not report a production-graph self-test PASS'
            }
            if ([int]$verdict.Groups[1].Value -le 0) {
                throw 'row 33 reported a production-graph self-test that ran no checks'
            }
            return $null
        }
        34 {
            $utf8 = New-Object System.Text.UTF8Encoding $false
            $raw = $utf8.GetString([IO.File]::ReadAllBytes($stdoutPath))
            # Row 34 is a marker-producing row, so its stdout carries the PRE
            # and POST nested-tool lines as well as the report. They are not
            # part of the JSON document and are dropped here, exactly as the
            # marker reader and the row-hashing path drop them.
            $jsonLines = New-Object System.Collections.ArrayList
            foreach ($line in $raw.Split("`n")) {
                $trimmed = $line.TrimEnd("`r")
                if ($trimmed.StartsWith($script:NestedToolMarkerSentinel, [StringComparison]::Ordinal)) { continue }
                [void]$jsonLines.Add($trimmed)
            }
            $text = ($jsonLines -join "`n").Trim()
            $object = $text | ConvertFrom-Json
            if ([string]$object.result -cne 'PASS') {
                throw 'row 34 did not report a same-artifact attestation PASS'
            }
            if ([string]$object.profile -cne 'r5-cutover') {
                throw 'row 34 verified a different profile'
            }
            if ([string]::IsNullOrWhiteSpace([string]$object.sourceIdentity)) {
                throw 'row 34 reported no source identity'
            }
            # Both graph rows read the same `c4-production-graph.json` out of
            # the same frozen clean tree that rows 35-38 prove unchanged, so
            # the same-artifact property is carried by the freeze. The runner
            # additionally binds the manifest bytes it can measure itself.
            $manifestPath = Join-Path $Options.RepoRoot 'driver\audit\c4-production-graph.json'
            $State.ProductionGraphManifestSha256 = Get-C4RunnerSha256File $manifestPath
            $State.ProductionGraphSourceIdentity = [string]$object.sourceIdentity

            # Recording those two was all this row used to do with them, and
            # nothing ever read them back -- so the "same-artifact" check the
            # design names did not exist. Cross-check row 34's own claim against
            # the attestation committed in the frozen tree: the row says the
            # attestation verifies and names this source identity and manifest,
            # and the runner independently reads the same file and requires it
            # to agree. A stale, forged or wrong-profile row 34 stdout no longer
            # passes on its own say-so.
            $attestationPath = Join-Path $Options.RepoRoot 'driver\audit\c4-production-attestation.json'
            if (-not [IO.File]::Exists($attestationPath)) {
                throw 'row 34 has no committed attestation to agree with'
            }
            $attestation = ($utf8.GetString([IO.File]::ReadAllBytes($attestationPath))) | ConvertFrom-Json
            if ([string]$attestation.profile -cne 'r5-cutover') {
                throw 'the committed attestation is not the r5-cutover profile'
            }
            # Compared case-insensitively on purpose: the attestation stores
            # uppercase hex and `Get-C4RunnerSha256File` returns lowercase, so a
            # case-sensitive compare here would fail on presentation rather than
            # on identity.
            if ([string]$attestation.sourceIdentity.ToUpperInvariant() -cne
                    [string]$object.sourceIdentity.ToUpperInvariant()) {
                throw ('row 34 reported source identity {0}, the committed attestation names {1}' -f
                    [string]$object.sourceIdentity, [string]$attestation.sourceIdentity)
            }
            if ([string]$attestation.manifestSha256.ToUpperInvariant() -cne
                    $State.ProductionGraphManifestSha256.ToUpperInvariant()) {
                throw ('the committed attestation names manifest {0}, the frozen tree carries {1}' -f
                    [string]$attestation.manifestSha256, $State.ProductionGraphManifestSha256)
            }
            return $null
        }
        36 {
            if ((Get-Item -LiteralPath $stdoutPath).Length -ne 0) {
                throw 'row 36 proved the worktree is not clean'
            }
            return $null
        }
        37 {
            $utf8 = New-Object System.Text.UTF8Encoding $false
            if ($utf8.GetString([IO.File]::ReadAllBytes($stdoutPath)) -cne ($State.SourceCommit + "`n")) {
                throw 'row 37 did not return the expected source commit'
            }
            return $null
        }
        38 {
            $utf8 = New-Object System.Text.UTF8Encoding $false
            if ($utf8.GetString([IO.File]::ReadAllBytes($stdoutPath)) -cne ($State.SourceTree + "`n")) {
                throw 'row 38 did not return the expected source tree'
            }
            return $null
        }
        default { return $null }
    }
}

# ---------------------------------------------------------------------------
# Invocation
# ---------------------------------------------------------------------------

function Invoke-C4SourceGateRun {
    param($Options)

    $repoRoot = $Options.RepoRoot
    $attemptId = Assert-C4RunnerAttemptId $Options.AttemptId
    $commit = Assert-C4RunnerHex $Options.ExpectedSourceCommit 40 '-ExpectedSourceCommit'
    $tree = Assert-C4RunnerHex $Options.ExpectedSourceTree 40 '-ExpectedSourceTree'

    # --- pre-acceptance: refusals leave nothing behind ---------------------
    $targets = Assert-C4RunnerExternalTargets $repoRoot $Options.AuthorizedExternalParent `
        $Options.OutputDirectory $Options.ScratchDirectory

    if ($Options.ManifestRelative -match '^[A-Za-z]:' -or $Options.ManifestRelative.StartsWith('\') -or
        $Options.ManifestRelative.StartsWith('/') -or $Options.ManifestRelative.Contains('..')) {
        throw '-Manifest must be a repository-relative file path'
    }
    $manifestPath = [IO.Path]::GetFullPath((Join-Path $repoRoot $Options.ManifestRelative))
    if (-not [IO.File]::Exists($manifestPath)) { throw '-Manifest names no file' }
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    $gateManifestSha256 = Get-C4EvidenceSha256Hex $manifestBytes
    $utf8 = New-Object System.Text.UTF8Encoding $false
    $document = ($utf8.GetString($manifestBytes)) | ConvertFrom-Json
    Test-C4RunnerManifestDocument $document

    $resolved = Resolve-C4RunnerToolPaths $repoRoot $Options.ToolOverrides
    $leases = Open-C4RunnerToolLeases $resolved
    $state = $null
    try {
        Remove-C4RunnerInheritedSelectors
        $inherited = Get-C4RunnerInheritedSelectorNames
        if (@($inherited).Count -ne 0) {
            throw ('inherited Cargo/rustup selectors could not be removed: ' + (@($inherited) -join ','))
        }
        Assert-C4RunnerCleanSourceIdentity $Options.Adapters $leases $repoRoot $commit $tree
        $cargoHome = Get-C4RunnerCargoHome $Options.CargoOverrides
        $trackedConfigSha = Get-C4RunnerTrackedConfigBlobSha256 $Options.Adapters $leases $repoRoot $tree
        $Options | Add-Member -NotePropertyName TrackedConfigSha256 -NotePropertyValue $trackedConfigSha -Force
        $candidates = Read-C4RunnerConfigCandidates $repoRoot $cargoHome $trackedConfigSha
        $childPath = Get-C4RunnerChildPathDirectories $leases $cargoHome
        $cargoEnvironment = New-C4RunnerCargoEnvironment $cargoHome $candidates $childPath
        Assert-C4RunnerExactKeys $cargoEnvironment $script:CargoEnvironmentKeys 'cargoEnvironment'
        foreach ($row in @($candidates)) {
            Assert-C4RunnerExactKeys $row $script:ConfigCandidateKeys 'Cargo configuration candidate'
        }

        # --- the acceptance cut -------------------------------------------
        [void][IO.Directory]::CreateDirectory($targets.Attempt)
        try {
            [void][IO.Directory]::CreateDirectory($targets.Scratch)
        } catch {
            # Only the still-empty just-created attempt is removed. An attempt
            # that ever held a byte is sealed, never deleted.
            Remove-Item -LiteralPath $targets.Attempt -Force -ErrorAction SilentlyContinue
            throw
        }

        $state = New-C4RunnerState $attemptId $targets.Attempt $targets.Scratch $commit $tree $gateManifestSha256
        $state | Add-Member -NotePropertyName ProductionGraphManifestSha256 -NotePropertyValue $null -Force
        $state | Add-Member -NotePropertyName ProductionGraphSourceIdentity -NotePropertyValue $null -Force

        # Everything below always seals.
        try {
            Assert-C4RunnerToolLeases $leases
            Assert-C4RunnerCleanSourceIdentity $Options.Adapters $leases $repoRoot $commit $tree
            Assert-C4RunnerConfigCandidatesUnchanged $repoRoot $cargoHome $trackedConfigSha $candidates
            if ((Get-C4RunnerSha256File $manifestPath) -cne $gateManifestSha256) {
                throw 'the gate manifest changed between validation and acceptance'
            }
        } catch {
            Set-C4RunnerFailure $state 'PRE_ROSTER_IDENTITY' $null ('pre-roster identity drift: ' + $_.Exception.Message) $null
            return (Complete-C4RunnerAttempt $state)
        }

        try {
            [void](Invoke-C4RunnerToolFreeze $state $Options $leases $cargoEnvironment)
            $state.AllowedState = 'TOOL_FREEZE'
        } catch {
            $state.AllowedState = 'TOOL_FREEZE'
            $subreason = 'FAIL'
            $message = [string]$_.Exception.Message
            if ($message.StartsWith('TOOL_FREEZE_TIMEOUT:', [StringComparison]::Ordinal)) { $subreason = 'TIMEOUT' }
            elseif ($message.StartsWith('TOOL_FREEZE:', [StringComparison]::Ordinal)) { $subreason = 'IDENTITY' }
            elseif ($message.Contains('drift')) { $subreason = 'IDENTITY' }
            Set-C4RunnerFailure $state 'TOOL_FREEZE' $null ('tool freeze failed: ' + $message) $subreason
            return (Complete-C4RunnerAttempt $state)
        }

        $state.AllowedState = 'COMMANDS'
        $commandOutcome = Invoke-C4RunnerCommandRows $state $Options $leases $cargoEnvironment
        if ($null -ne $state.FailureKind) {
            return (Complete-C4RunnerAttempt $state)
        }

        # --- candidate sealing --------------------------------------------
        try {
            $harnessSource = [IO.Path]::GetFullPath((Join-Path $state.ScratchRoot ($script:HarnessScratchRelativePath -replace '/', '\')))
            if (-not [IO.File]::Exists($harnessSource)) { throw 'the selected harness executable disappeared' }
            if (Test-C4RunnerReparse $harnessSource) { throw 'the selected harness executable became a reparse point' }
            if (-not (Test-C4RunnerPathContainment $state.ScratchRoot $harnessSource)) {
                throw 'the selected harness executable left scratch'
            }
            $harnessTarget = Join-Path $state.AttemptRoot ($script:HarnessCandidateRelativePath -replace '/', '\')
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($harnessTarget))
            Write-C4RunnerExclusiveBytes $harnessTarget ([IO.File]::ReadAllBytes($harnessSource))

            $smokePath = Join-Path $repoRoot ($script:SmokeDriverRelativePath -replace '/', '\')
            $smokeBytes = [IO.File]::ReadAllBytes($smokePath)
            $smokeRow = [ordered]@{
                relativePath = $script:SmokeDriverRelativePath
                bytes = [int64]$smokeBytes.Length
                sha256 = (Get-C4EvidenceSha256Hex $smokeBytes)
            }
            $candidate = New-C4RunnerCandidateManifest $state $commandOutcome.PackageCandidate $smokeRow
            $candidateBytes = Get-C4RunnerCanonicalBytes $candidate
            Write-C4RunnerExclusiveBytes (Join-Path $state.AttemptRoot 'candidate-artifacts.json') $candidateBytes
            $state.CandidateManifestSha256 = Get-C4EvidenceSha256Hex $candidateBytes
            $state.CandidateSealed = $true
        } catch {
            # The command index is already sealed PASS and stays that way: the
            # rows really did pass. Only the attempt fails.
            Set-C4RunnerFailure $state 'CANDIDATE_SEAL' $null ('candidate sealing failed: ' + $_.Exception.Message) $null
            return (Complete-C4RunnerAttempt $state)
        }
        return (Complete-C4RunnerAttempt $state)
    } finally {
        Close-C4RunnerToolLeases $leases
    }
}

# ---------------------------------------------------------------------------
# Self-test
#
# The fixtures never build the workspace: they drive the real state machine
# with a deterministic capture adapter and twenty stand-in tool files, then
# mutate one thing at a time. What is NOT faked is everything this script
# owns -- manifest validation, the held leases and their native identities,
# the Cargo candidate seal, marker parsing, the fail-stop ladder, the allowed
# path set, and the four sealed manifests. The real process capture is row 02's
# subject and has its own suite.
#
# `$script:FakeState` is a script-scope record rather than a closure, because a
# scriptblock closure would hide which fixture actually set a behaviour.
# ---------------------------------------------------------------------------

$script:FakeState = $null

function Reset-C4RunnerFakeState {
    param($World)
    $script:FakeState = [pscustomobject]@{
        World = $World
        RowTermination = @{}
        RowExit = @{}
        RowStdout = @{}
        RowStdoutBody = @{}
        # Body-only override for a producing row, so a negative case can change
        # what the row REPORTED without also deleting the marker it EMITTED.
        RowBody = @{}
        # Row 14 must look like a sweep that actually ran, because its
        # postcondition requires per-mutant progress in stderr. The default is
        # the healthy shape; a negative case overrides it with a replay banner.
        RowStderr = @{ 14 = "C4 parallel: 4 workers, 465 mutants remaining`nC4 progress 1/465 CAUGHT fixture`n" }
        MarkerNonceOverride = @{}
        MarkerRoles = @{}
        MarkerCounts = @{}
        MarkerSuppress = @{}
        MarkerPostRoles = @{}
        ToolTermination = @{}
        ToolExit = @{}
        ToolStdout = @{}
        BeforeRow = @{}
        AfterRow = @{}
        ExtraAttemptFile = $null
        GitStatusDirty = $false
        GitHead = $World.Commit
        GitTree = $World.Tree
        ConfigBlobOverride = $null
        BreakPackageReport = $false
    }
}

function Save-C4RunnerEnvironment {
    $saved = @{}
    foreach ($entry in [Environment]::GetEnvironmentVariables().Keys) {
        $saved[[string]$entry] = [string][Environment]::GetEnvironmentVariable([string]$entry)
    }
    return $saved
}

function Restore-C4RunnerEnvironment {
    param($Saved)
    foreach ($entry in @([Environment]::GetEnvironmentVariables().Keys)) {
        $name = [string]$entry
        if (-not $Saved.ContainsKey($name)) {
            Remove-Item -LiteralPath ('Env:' + $name) -ErrorAction SilentlyContinue
        }
    }
    foreach ($name in @($Saved.Keys)) {
        Set-Item -LiteralPath ('Env:' + $name) -Value $Saved[$name] -ErrorAction SilentlyContinue
    }
}

function New-C4RunnerFakeMarkerLine {
    param([string]$Phase, [string]$CommandId, [string]$Nonce, [string[]]$Roles, $Counts)

    $tools = New-Object System.Collections.ArrayList
    foreach ($role in @($Roles)) {
        $suffix = Get-C4RunnerRoleEnvironmentSuffix $role
        $path = [string][Environment]::GetEnvironmentVariable('FSRING_C4_TOOL_' + $suffix)
        if ([string]::IsNullOrWhiteSpace($path)) {
            $path = [string]$script:FakeState.World.ToolPaths[$role]
        }
        $lease = Open-C4HeldFileLease -Path $path -ExpectedSha256 (Get-C4RunnerSha256File $path)
        try {
            [void]$tools.Add([ordered]@{
                role = $role
                path = $lease.Path
                volumeSerial = $lease.VolumeSerial
                fileId = $lease.FileId
                sha256 = $lease.Sha256
            })
        } finally {
            Close-C4HeldFileLease $lease
        }
    }
    # `$counts` would BE `$Counts`: PowerShell variable names are
    # case-insensitive, so the local assignment overwrites the parameter and
    # the next line reads .Keys off an ArrayList.
    $countRows = New-Object System.Collections.ArrayList
    if ($null -ne $Counts) {
        foreach ($role in @($Counts.Keys)) {
            [void]$countRows.Add([ordered]@{ role = $role; count = [int]$Counts[$role] })
        }
    }
    return ($script:NestedToolMarkerSentinel + (ConvertTo-C4CanonicalJsonText ([ordered]@{
        schema = $script:NestedToolMarkerSchema
        version = 1
        nonce = $Nonce
        phase = $Phase
        commandId = $CommandId
        tools = @($tools)
        launchCounts = @($countRows)
    })))
}

function New-C4RunnerFakePackageCandidate {
    param($World, [int]$Ordinal)

    $attempt = $World.AttemptRoot
    $packageDirectory = Join-Path $attempt 'artifacts\win10-x64-release\package'
    [void][IO.Directory]::CreateDirectory($packageDirectory)
    $memberRows = New-Object System.Collections.ArrayList
    foreach ($name in $script:PackageMemberNames) {
        $target = Join-Path $packageDirectory $name
        if (-not [IO.File]::Exists($target)) {
            $utf8 = New-Object System.Text.UTF8Encoding $false
            [IO.File]::WriteAllBytes($target, $utf8.GetBytes('fixture:' + $name))
        }
        $bytes = [IO.File]::ReadAllBytes($target)
        [void]$memberRows.Add([ordered]@{
            relativePath = ('artifacts/win10-x64-release/package/' + $name)
            bytes = [int64]$bytes.Length
            sha256 = (Get-C4EvidenceSha256Hex $bytes)
        })
    }
    foreach ($aux in @('package-verifier.stdout.bin', 'package-verifier.stderr.bin')) {
        $path = Join-Path $attempt $aux
        if (-not [IO.File]::Exists($path)) { [IO.File]::WriteAllBytes($path, (New-Object byte[] 0)) }
    }
    $exitPath = Join-Path $attempt 'package-verifier.exit.json'
    if (-not [IO.File]::Exists($exitPath)) {
        [IO.File]::WriteAllBytes($exitPath, (Get-C4RunnerCanonicalBytes ([ordered]@{
            schema = $script:CapturedExitSchema
            version = 1
            observedExit = 0
            timedOut = $false
            termination = 'NORMAL'
        })))
    }
    return [ordered]@{
        schema = $script:PackageCandidateSchema
        version = 1
        sourceCommit = $World.Commit
        sourceTree = $World.Tree
        profile = $script:CandidateProfile
        package = [ordered]@{
            relativePath = 'artifacts/win10-x64-release/package'
            setSha256 = (Get-C4RunnerPackageSetSha256 @($memberRows))
            members = @($memberRows)
        }
        packageVerifier = [ordered]@{
            schema = 'fsring-c4-package-verification/v1'
            scriptRelativePath = 'driver/scripts/verify_fsring_package.ps1'
            scriptSha256 = ('a' * 64)
            toolRole = 'powershell'
            toolSha256 = ('b' * 64)
            argv = @('powershell', '-File', 'verify_fsring_package.ps1')
            exitCode = 0
            semanticStatus = 'PASS'
            profile = 'win10-x64-release'
            machine = '0x8664'
            packageRelativePath = 'artifacts/win10-x64-release/package'
            memberNames = @($script:PackageMemberNames)
            signatureStatus = 'PASS'
            catalogStatus = 'PASS'
            stdout = 'package-verifier.stdout.bin'
            stdoutBytes = [int64]0
            stdoutSha256 = (Get-C4RunnerZeroBytesSha256)
            stderr = 'package-verifier.stderr.bin'
            stderrBytes = [int64]0
            stderrSha256 = (Get-C4RunnerZeroBytesSha256)
            exit = 'package-verifier.exit.json'
            exitBytes = [int64]([IO.File]::ReadAllBytes($exitPath)).Length
            exitSha256 = (Get-C4RunnerSha256File $exitPath)
        }
        status = 'PASS'
    }
}

function Get-C4RunnerFakeRowStdout {
    param([int]$Ordinal, [string]$CommandId, [string]$Nonce)

    $world = $script:FakeState.World
    $lines = New-Object System.Collections.ArrayList
    $roles = @($script:NestedToolMap[$Ordinal])
    if ($script:FakeState.MarkerRoles.ContainsKey($Ordinal)) { $roles = @($script:FakeState.MarkerRoles[$Ordinal]) }
    $postRoles = $roles
    if ($script:FakeState.MarkerPostRoles.ContainsKey($Ordinal)) { $postRoles = @($script:FakeState.MarkerPostRoles[$Ordinal]) }
    $counts = $null
    if ($script:ExpectedMarkerLaunchCounts.ContainsKey($Ordinal)) { $counts = $script:ExpectedMarkerLaunchCounts[$Ordinal] }
    if ($script:FakeState.MarkerCounts.ContainsKey($Ordinal)) { $counts = $script:FakeState.MarkerCounts[$Ordinal] }
    $markerNonce = $Nonce
    if ($script:FakeState.MarkerNonceOverride.ContainsKey($Ordinal)) { $markerNonce = [string]$script:FakeState.MarkerNonceOverride[$Ordinal] }
    $emit = ($script:MarkerProducingOrdinals -contains $Ordinal)
    if ($script:FakeState.MarkerSuppress.ContainsKey($Ordinal)) { $emit = -not [bool]$script:FakeState.MarkerSuppress[$Ordinal] }

    if ($emit) {
        [void]$lines.Add((New-C4RunnerFakeMarkerLine 'PRE' $CommandId $markerNonce $roles $null))
    }
    # `RowStdout` replaces the WHOLE stream, which for a marker-producing row
    # also deletes its PRE/POST pair -- so a fixture meant to test a
    # postcondition would instead test the marker check and seal IDENTITY_DRIFT.
    # `RowStdoutBody` changes only what the row reported and leaves the markers
    # alone. It replaces the row's default body, so it also skips whatever side
    # effect that row's arm performs; only rows whose arm just emits text
    # (33, 34, 37, 38) may use it.
    $bodyOrdinal = $Ordinal
    if ($script:FakeState.RowStdoutBody.ContainsKey($Ordinal)) {
        [void]$lines.Add([string]$script:FakeState.RowStdoutBody[$Ordinal])
        $bodyOrdinal = -1
    }
    switch ($bodyOrdinal) {
        13 {
            $external = Join-Path $world.AttemptRoot $script:MutationListRelativePath
            $authoritative = Join-Path $world.RepoRoot 'driver\audit\c4-mutations.json'
            [IO.File]::WriteAllBytes($external, [IO.File]::ReadAllBytes($authoritative))
        }
        21 {
            $report = New-C4RunnerFakePackageCandidate $world $Ordinal
            if ($script:FakeState.BreakPackageReport) { $report['status'] = 'FAIL' }
            [void]$lines.Add((ConvertTo-C4CanonicalJsonText $report))
        }
        27 {
            $harness = Join-Path $world.ScratchRoot ($script:HarnessScratchRelativePath -replace '/', '\')
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($harness))
            $utf8 = New-Object System.Text.UTF8Encoding $false
            [IO.File]::WriteAllBytes($harness, $utf8.GetBytes('fixture-harness'))
            # A similarly named intermediate proves only the exact selected
            # path is copied.
            $decoy = Join-Path $world.ScratchRoot 'harness\x86_64-pc-windows-msvc\release\deps\fsring-control-smoke.exe'
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($decoy))
            [IO.File]::WriteAllBytes($decoy, $utf8.GetBytes('decoy'))
        }
        30 {
            $archives = Join-Path $world.AttemptRoot 'artifacts\archives'
            [void][IO.Directory]::CreateDirectory($archives)
            $utf8 = New-Object System.Text.UTF8Encoding $false
            foreach ($name in @('fsring-abi.zip', 'fsring-spec.zip')) {
                $path = Join-Path $archives $name
                if (-not [IO.File]::Exists($path)) { [IO.File]::WriteAllBytes($path, $utf8.GetBytes('zip:' + $name)) }
            }
        }
        12 {
            # The healthy shape row 12's postcondition requires: per-mutant
            # verdict rows with no replay marker, then the verdict line.
            #
            # A negative case overrides the BODY, not the whole stdout: row 12
            # is a producing row, so replacing its stdout wholesale would drop
            # the nonce-bound marker and fail the row on marker drift instead of
            # on the postcondition under test -- a case that goes red for a
            # reason it is not testing proves nothing about the check it names.
            # Each line carries a trailing CR so the `-join "`n"` below produces
            # CRLF, which is what a Windows Python process actually writes. A
            # fixture in the one byte shape production never emits cannot
            # exercise the postcondition production runs into: the first version
            # of this fixture used bare LF, the self-test passed, and the real
            # row was refused after 104 minutes on a `$` that could not match
            # across the `\r`.
            if ($script:FakeState.RowBody.ContainsKey(12)) {
                foreach ($line in @($script:FakeState.RowBody[12])) { [void]$lines.Add([string]$line + "`r") }
            } else {
                [void]$lines.Add("    1/2  CAUGHT      [A] fixture guard one`r")
                [void]$lines.Add("    2/2  CAUGHT      [A] fixture guard two`r")
                [void]$lines.Add("MUTATION SWEEP: PASS`r")
            }
        }
        14 { [void]$lines.Add('c4 suite: PASS (465 mandatory, 465 caught)') }
        33 {
            # Production's exact line, CRLF included: a fixture in a byte
            # shape the real auditor never emits cannot exercise the check
            # the real row runs into.
            if ($script:FakeState.RowBody.ContainsKey(33)) {
                foreach ($line in @($script:FakeState.RowBody[33])) {
                    [void]$lines.Add([string]$line + "`r")
                }
            } else {
                [void]$lines.Add("audit_c4_production_graph self-test: PASS (220 checks, 0 failures)`r")
            }
        }
        34 {
            [void]$lines.Add((ConvertTo-C4CanonicalJsonText ([ordered]@{
                mode = 'verify-current-attestation'
                profile = 'r5-cutover'
                result = 'PASS'
                rowCount = 5
                sourceIdentity = ('c' * 64)
            })))
        }
        37 { [void]$lines.Add($world.Commit) }
        38 { [void]$lines.Add($world.Tree) }
        default { }
    }
    if ($emit) {
        [void]$lines.Add((New-C4RunnerFakeMarkerLine 'POST' $CommandId $markerNonce $postRoles $counts))
    }
    $utf8 = New-Object System.Text.UTF8Encoding $false
    # The comma is load-bearing: a PowerShell function unrolls a returned
    # array, so an empty byte[] would arrive as $null and a one-byte one as a
    # bare byte.
    if (@($lines).Count -eq 0) { return (,(New-Object byte[] 0)) }
    return (,($utf8.GetBytes((@($lines) -join "`n") + "`n")))
}

function Get-C4RunnerFakeToolStdout {
    param([string]$Role)
    $text = switch -Regex ($Role) {
        '^powershell$' { "5.1.19041.1" }
        '^python$' { "Python 3.12.1" }
        '^git$' { "git version 2.45.0.windows.1" }
        '^git-bash$' { "GNU bash, version 5.2.21(1)-release" }
        '^cmd$' { "Microsoft Windows [Version 10.0.19045.1]" }
        '^cargo-fmt-1\.82\.0$' { "rustfmt 1.7.0-stable (fixture 1.82.0)" }
        '^rustfmt-1\.82\.0$' { "rustfmt 1.7.0-stable (fixture 1.82.0)" }
        '^cargo-fmt-1\.85\.0$' { "rustfmt 1.8.0-stable (fixture 1.85.0)" }
        '^rustfmt-1\.85\.0$' { "rustfmt 1.8.0-stable (fixture 1.85.0)" }
        '^cargo-clippy-1\.85\.0$' { "clippy 0.1.85 (fixture)" }
        '^clippy-driver-1\.85\.0$' { "clippy 0.1.85 (fixture)" }
        '^cargo-wdk-0\.1\.1$' { "cargo wdk 0.1.1" }
        '^infverif$' { "10.0.26100.1|10.0.26100.1" }
        '^signtool$' { "10.0.22000.1|10.0.22000.1" }
        default {
            $version = '1.85.0'
            if ($Role.EndsWith('-1.82.0', [StringComparison]::Ordinal)) { $version = '1.82.0' }
            $name = $Role -replace '-1\.\d+\.\d+$', ''
            ("{0} {1} (fixture)`nbinary: {0}`nrelease: {1}`ncommit-hash: 0123456789abcdef`nhost: x86_64-pc-windows-msvc" -f $name, $version)
        }
    }
    $utf8 = New-Object System.Text.UTF8Encoding $false
    return (,($utf8.GetBytes($text + "`n")))
}

function New-C4RunnerFakeAdapters {
    return [pscustomobject]@{
        CaptureProcess = {
            param($Executable, $Arguments, $WorkingDirectory, $TimeoutMilliseconds, $StdoutPath, $StderrPath, $ExitPath)
            $state = $script:FakeState
            $world = $state.World
            $commandId = [string]$env:FSRING_C4_COMMAND_ID
            $nonce = [string]$env:FSRING_C4_MARKER_NONCE

            $stdout = New-Object byte[] 0
            $termination = 'NORMAL'
            $exitCode = 0
            $utf8 = New-Object System.Text.UTF8Encoding $false

            # The private-observation sentinel is checked first and is exact.
            # Inferring it twice went wrong: "not a tool and not a row" made a
            # git call look like row 01 under the gate, and dispatching on the
            # executable instead swept up the git ROLE's own version capture
            # and rows 35-38, which legitimately launch git.
            if ($commandId -ceq $script:PrivateCaptureCommandId) {
                $joined = (@($Arguments) -join ' ')
                if ($joined.StartsWith('status', [StringComparison]::Ordinal)) {
                    if ($state.GitStatusDirty) { $stdout = $utf8.GetBytes(" M driver/fsring-core/src/lib.rs`n") }
                } elseif ($joined -ceq 'rev-parse HEAD') {
                    $stdout = $utf8.GetBytes([string]$state.GitHead + "`n")
                } elseif ($joined -ceq 'rev-parse HEAD^{tree}') {
                    $stdout = $utf8.GetBytes([string]$state.GitTree + "`n")
                } elseif ($joined.StartsWith('show ', [StringComparison]::Ordinal)) {
                    $stdout = [IO.File]::ReadAllBytes((Join-Path $world.RepoRoot 'driver\.cargo\config.toml'))
                    if ($null -ne $state.ConfigBlobOverride) {
                        $stdout = $utf8.GetBytes([string]$state.ConfigBlobOverride)
                    }
                }
            } elseif ($commandId.StartsWith('tools/', [StringComparison]::Ordinal)) {
                $role = $commandId.Substring(6)
                $stdout = Get-C4RunnerFakeToolStdout $role
                if ($state.ToolStdout.ContainsKey($role)) { $stdout = $utf8.GetBytes([string]$state.ToolStdout[$role]) }
                if ($state.ToolTermination.ContainsKey($role)) { $termination = [string]$state.ToolTermination[$role] }
                if ($state.ToolExit.ContainsKey($role)) { $exitCode = [int]$state.ToolExit[$role] }
            } elseif ($commandId -match '^(\d\d)-') {
                $ordinal = [int]$Matches[1]
                if ($state.BeforeRow.ContainsKey($ordinal)) { & $state.BeforeRow[$ordinal] }
                $stdout = Get-C4RunnerFakeRowStdout $ordinal $commandId $nonce
                if ($state.RowStdout.ContainsKey($ordinal)) { $stdout = $utf8.GetBytes([string]$state.RowStdout[$ordinal]) }
                if ($state.RowTermination.ContainsKey($ordinal)) { $termination = [string]$state.RowTermination[$ordinal] }
                if ($state.RowExit.ContainsKey($ordinal)) { $exitCode = [int]$state.RowExit[$ordinal] }
                if ($state.AfterRow.ContainsKey($ordinal)) { & $state.AfterRow[$ordinal] }
            } else {
                # Every launch the runner makes is either a version capture, a
                # numbered row, or a git observation. Answering an unrecognised
                # one with empty bytes would let a dispatch gap pass as a
                # legitimately silent command.
                throw ('the fixture adapter cannot classify a launch of ' + $Executable)
            }

            [IO.File]::WriteAllBytes($StdoutPath, [byte[]]$stdout)
            # Row 14's postcondition reads stderr for evidence that the sweep
            # executed, so the fixture must be able to produce it -- and to
            # produce a replay banner instead, which is what the negative case
            # below drives.
            $stderrBytes = New-Object byte[] 0
            if ($state.RowStderr.ContainsKey($ordinal)) {
                $stderrBytes = (New-Object System.Text.UTF8Encoding $false).GetBytes([string]$state.RowStderr[$ordinal])
            }
            [IO.File]::WriteAllBytes($StderrPath, $stderrBytes)
            $observed = $null
            if ($termination -ceq 'NORMAL') { $observed = $exitCode }
            [IO.File]::WriteAllBytes($ExitPath, (Get-C4RunnerCanonicalBytes ([ordered]@{
                schema = $script:CapturedExitSchema
                version = 1
                observedExit = $observed
                timedOut = ($termination -ceq 'TIMEOUT')
                termination = $termination
            })))
        }
    }
}

function New-C4RunnerTestWorld {
    param([string]$Root, [string]$Name)

    $world = Join-Path $Root $Name
    $repo = Join-Path $world 'repo'
    $tools = Join-Path $world 'tools'
    $cargo = Join-Path $world 'cargo'
    $external = Join-Path $world 'ext'
    foreach ($directory in @($repo, $tools, $cargo, $external,
        (Join-Path $repo 'driver\audit'), (Join-Path $repo 'driver\scripts'),
        (Join-Path $repo 'driver\.cargo'), (Join-Path $repo 'scripts'))) {
        [void][IO.Directory]::CreateDirectory($directory)
    }
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [IO.File]::WriteAllBytes((Join-Path $repo 'driver\.cargo\config.toml'),
        $utf8.GetBytes("[build]`nrustflags = [`'-C`', `'target-feature=+crt-static`']`n"))
    [IO.File]::WriteAllBytes((Join-Path $repo 'driver\scripts\smoke_driver.ps1'),
        $utf8.GetBytes("# fixture smoke driver`n"))
    [IO.File]::WriteAllBytes((Join-Path $repo 'driver\audit\c4-production-graph.json'),
        $utf8.GetBytes("{}`n"))
    # The attestation row 34's postcondition cross-checks against. It must agree
    # with the fixture's own graph manifest bytes and with the sourceIdentity the
    # fixture stdout reports, or this fixture would be asserting the check is
    # unreachable rather than exercising it.
    $fixtureGraphSha = (Get-C4EvidenceSha256Hex ($utf8.GetBytes("{}`n"))).ToUpperInvariant()
    [IO.File]::WriteAllBytes((Join-Path $repo 'driver\audit\c4-production-attestation.json'),
        $utf8.GetBytes((ConvertTo-C4CanonicalJsonText ([ordered]@{
            schema = 'fsring-c4-production-attestation/v1'
            version = 1
            profile = 'r5-cutover'
            sourceIdentity = ('C' * 64)
            manifestSha256 = $fixtureGraphSha
        })) + "`n"))
    [IO.File]::WriteAllBytes((Join-Path $repo 'driver\audit\c4-mutations.json'),
        $utf8.GetBytes('{"schema":"fsring-c4-mutations/v1","mutants":[{"id":"fixture-mutant","anchorCount":1}]}' + "`n"))
    Copy-Item -LiteralPath (Join-Path (Get-C4RunnerRepositoryRoot) 'driver\audit\c4-source-gates.json') `
        -Destination (Join-Path $repo 'driver\audit\c4-source-gates.json') -Force

    $toolPaths = [ordered]@{}
    for ($i = 0; $i -lt $script:ToolRoles.Count; $i++) {
        $role = $script:ToolRoles[$i]
        $path = Join-Path $tools ('{0:d2}-{1}.tool' -f ($i + 1), $role)
        [IO.File]::WriteAllBytes($path, $utf8.GetBytes('tool:' + $role))
        $toolPaths[$role] = [IO.Path]::GetFullPath($path)
    }
    $attemptId = '0123456789abcdef0123456789abcdef'
    return [pscustomobject]@{
        Root = [IO.Path]::GetFullPath($world)
        RepoRoot = [IO.Path]::GetFullPath($repo)
        ToolPaths = $toolPaths
        CargoHome = [IO.Path]::GetFullPath($cargo)
        External = [IO.Path]::GetFullPath($external)
        AttemptId = $attemptId
        AttemptRoot = [IO.Path]::GetFullPath((Join-Path $external ('attempt-' + $attemptId)))
        ScratchRoot = [IO.Path]::GetFullPath((Join-Path $external ('scratch-' + $attemptId)))
        Commit = ('1' * 40)
        Tree = ('2' * 40)
    }
}

function New-C4RunnerTestOptions {
    param($World)
    return [pscustomobject]@{
        RepoRoot = $World.RepoRoot
        ManifestRelative = 'driver/audit/c4-source-gates.json'
        AuthorizedExternalParent = $World.External
        OutputDirectory = $World.AttemptRoot
        ScratchDirectory = $World.ScratchRoot
        AttemptId = $World.AttemptId
        ExpectedSourceCommit = $World.Commit
        ExpectedSourceTree = $World.Tree
        Adapters = (New-C4RunnerFakeAdapters)
        ToolOverrides = $World.ToolPaths
        CargoOverrides = @{ cargoHome = $World.CargoHome }
        SelfPath = [IO.Path]::GetFullPath($PSCommandPath)
        TrackedConfigSha256 = $null
    }
}

function Invoke-C4RunnerSelfTests {
    # Short world names on purpose: the attempt roster nests three levels and
    # Windows path limits bite long before the fixtures run out.
    $root = Join-Path $env:TEMP ('c4gr-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    [void][IO.Directory]::CreateDirectory($root)
    $checks = New-Object System.Collections.ArrayList
    $failures = New-Object System.Collections.ArrayList
    $ordinal = [ref]0

    function Note { param([string]$Name) [void]$checks.Add($Name) }
    function Fail { param([string]$Name, [string]$Why) [void]$failures.Add($Name + ': ' + $Why) }
    function Assert-Ok {
        param([string]$Name, [bool]$Condition, [string]$Why = 'condition was false')
        Note $Name
        if (-not $Condition) { Fail $Name $Why }
    }
    # A refusal counts only when it is the refusal the fixture aimed at: a bare
    # "it threw" would let a fixture that broke its own setup pass for the
    # wrong reason.
    function Assert-Refuses {
        param([string]$Name, [scriptblock]$Action, [string]$Expect)
        Note $Name
        $saved = Save-C4RunnerEnvironment
        try {
            # The action's own return value must not reach this function's
            # pipeline: a leaked object would ride out of Invoke-C4RunnerSelfTests
            # and turn its result into an array.
            [void](& $Action)
            Fail $Name 'accepted what it must refuse'
        } catch {
            if ([string]$_.Exception.Message -cnotmatch [regex]::Escape($Expect)) {
                Fail $Name ('refused for the wrong reason (' + $_.Exception.Message + ')')
            }
        } finally {
            Restore-C4RunnerEnvironment $saved
        }
    }

    function New-World {
        $ordinal.Value += 1
        $world = New-C4RunnerTestWorld $root ('w' + $ordinal.Value.ToString())
        Reset-C4RunnerFakeState $world
        return $world
    }

    function Invoke-Run {
        param($Options)
        $saved = Save-C4RunnerEnvironment
        try {
            return (Invoke-C4SourceGateRun $Options)
        } finally {
            Restore-C4RunnerEnvironment $saved
        }
    }

    function Read-Sealed {
        param($World, [string]$Name)
        $path = Join-Path $World.AttemptRoot $Name
        if (-not [IO.File]::Exists($path)) { return $null }
        return (ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($path)))
    }

    function Assert-Sealed {
        param([string]$Name, $World, [string]$Status, [string]$Kind, $CommandId)
        Note $Name
        $manifest = Read-Sealed $World 'attempt.json'
        if ($null -eq $manifest) { Fail $Name 'no attempt.json was sealed'; return $null }
        if ([string]$manifest.gateStatus -cne $Status) {
            Fail $Name ('gateStatus is ' + $manifest.gateStatus + ', expected ' + $Status)
            return $manifest
        }
        if ([string]::IsNullOrEmpty($Kind)) {
            if ($null -ne $manifest.failure) { Fail $Name 'a PASS carries a failure record' }
            return $manifest
        }
        if ($null -eq $manifest.failure) { Fail $Name 'no failure record was sealed'; return $manifest }
        if ([string]$manifest.failure.kind -cne $Kind) {
            Fail $Name ('failure kind is ' + $manifest.failure.kind + ', expected ' + $Kind)
        }
        if ($null -ne $CommandId -and [string]$manifest.failure.commandId -cne [string]$CommandId) {
            Fail $Name ('failure commandId is ' + $manifest.failure.commandId + ', expected ' + $CommandId)
        }
        return $manifest
    }

    # Under the gate this suite runs as row 01, so the parent's nonce and
    # command ID are in the environment. Clear them: every fixture sets its own
    # through Set-C4RunnerChildEnvironment, and an inherited value can only be
    # a value some fixture did not choose.
    $inheritedNonce = [string]$env:FSRING_C4_MARKER_NONCE
    $inheritedCommandId = [string]$env:FSRING_C4_COMMAND_ID
    Remove-Item -LiteralPath Env:FSRING_C4_MARKER_NONCE -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Env:FSRING_C4_COMMAND_ID -ErrorAction SilentlyContinue

    try {
        # --- a cmd+* row owns its own build environment --------------------
        # Row 19 sealed `uncontrolled environment: CARGO,CARGO_HOME,...`
        # because the map, not the toolchain class, decided who is a Cargo row.
        #
        # A row spec carries no ordinal; the ordinal IS its position.
        $cmdOrdinals = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt @($script:ExpectedGateRows).Count; $i++) {
            if (([string]$script:ExpectedGateRows[$i].toolchain).StartsWith('cmd+', [StringComparison]::Ordinal)) {
                [void]$cmdOrdinals.Add($i + 1)
            }
        }
        Assert-Ok 'the matrix rows are the cmd rows' ((@($cmdOrdinals) -join ',') -ceq '19,20')
        Assert-Ok 'a Cargo row is named by its toolchain class' (
            [string]$script:ExpectedGateRows[2].toolchain -ceq 'rust-1.82.0' -and
            [string]$script:ExpectedGateRows[6].toolchain -ceq 'rust-1.85.0')

        # The refusal predicate is read back out of `build_matrix.cmd` itself.
        # Restating it here would make the runner agree with its own copy --
        # the exact shape of a check written from the same source as the thing
        # it checks.
        Note 'the runner covers every name build_matrix.cmd refuses'
        $matrixPath = Join-Path $PSScriptRoot 'build_matrix.cmd'
        if (-not (Test-Path -LiteralPath $matrixPath)) {
            Fail 'the runner covers every name build_matrix.cmd refuses' 'build_matrix.cmd is absent'
        } else {
            $matrixText = [IO.File]::ReadAllText($matrixPath)
            # Anchored on a line start: the bare name's FIRST occurrence is the
            # `call` site hundreds of lines above the label, and a window taken
            # from there contains no guard at all.
            $labelMatch = [regex]::Match($matrixText, '(?m)^:reject_ambient_build_environment\s*$')
            if (-not $labelMatch.Success) {
                Fail 'the runner covers every name build_matrix.cmd refuses' 'the guard label is absent'
            } else {
                $guardStart = $labelMatch.Index
                $guardText = $matrixText.Substring($guardStart, [Math]::Min(3000, $matrixText.Length - $guardStart))
                $exactMatch = [regex]::Match($guardText, '\$exact = @\(([^)]*)\)')
                if (-not $exactMatch.Success) {
                    Fail 'the runner covers every name build_matrix.cmd refuses' 'the refused list is not in the expected form'
                } else {
                    $refused = @([regex]::Matches($exactMatch.Groups[1].Value, "'([^']+)'") |
                        ForEach-Object { $_.Groups[1].Value })
                    if (@($refused).Count -lt 15) {
                        Fail 'the runner covers every name build_matrix.cmd refuses' (
                            'only ' + @($refused).Count + ' names parsed out of the guard')
                    }
                    $uncovered = @(@($refused) | Where-Object { -not (Test-C4RunnerMatrixRefusedName $_) })
                    if (@($uncovered).Count -ne 0) {
                        Fail 'the runner covers every name build_matrix.cmd refuses' (
                            'not suppressed: ' + (@($uncovered) -join ','))
                    }
                    # The guard also refuses a CARGO_ prefix and a <TOOL>_ suffix
                    # form; both must be covered, and neither is in the exact list.
                    Assert-Ok 'the runner covers the guard prefix and suffix rules' (
                        (Test-C4RunnerMatrixRefusedName 'CARGO_TARGET_DIR') -and
                        (Test-C4RunnerMatrixRefusedName 'CFLAGS_x86_64_pc_windows_msvc'))
                    # Anti-vacuity: the predicate must be able to say no.
                    Assert-Ok 'the refusal predicate is not universally true' (
                        -not (Test-C4RunnerMatrixRefusedName 'PATH') -and
                        -not (Test-C4RunnerMatrixRefusedName 'FSRING_C4_TOOL_CARGO_1_85_0'))
                }
            }
        }

        # The real function, on synthetic leases: what a row is HANDED is the
        # property, and it does not need the payloads to exist on disk.
        $savedChildEnv = Save-C4RunnerEnvironment
        try {
            $fakeLeases = @{}
            foreach ($role in $script:ToolRoles) {
                $fakeLeases[$role] = [pscustomobject]@{
                    Path = ('C:/frozen/' + $role + '.exe')
                    Sha256 = ('0' * 64)
                    VolumeSerial = 'DEADBEEF'
                    FileId = ('1' * 32)
                }
            }
            $fakeCargo = New-C4RunnerCargoEnvironment 'C:/frozen/cargo-home' @() @('C:/Windows/System32')

            # An ambient developer prompt is simulated, because the matrix
            # refuses those too and the runner's own selector scrub does not
            # reach them.
            $env:CL = '/W4'
            $env:CARGO_TARGET_DIR = 'C:/ambient/target'
            Set-C4RunnerChildEnvironment $fakeLeases $fakeCargo 19 '19-matrix-selftest' '' @($script:NestedToolMap[19]) 'cmd+wdk-10.0.26100'
            $survivors = New-Object System.Collections.ArrayList
            foreach ($entry in [Environment]::GetEnvironmentVariables().Keys) {
                if (Test-C4RunnerMatrixRefusedName ([string]$entry)) { [void]$survivors.Add([string]$entry) }
            }
            Note 'a cmd row is handed nothing the matrix refuses'
            if (@($survivors).Count -ne 0) {
                Fail 'a cmd row is handed nothing the matrix refuses' (
                    'survived: ' + ((@($survivors) | Sort-Object) -join ','))
            }
            Assert-Ok 'a cmd row still receives its frozen payload set' (
                [string]$env:FSRING_C4_TOOL_CARGO_1_85_0 -ceq 'C:/frozen/cargo-1.85.0.exe' -and
                [string]$env:FSRING_C4_TOOL_SIGNTOOL -ceq 'C:/frozen/signtool.exe' -and
                [string]$env:PATH -ceq 'C:/Windows/System32')

            # Anti-vacuity: the suppression is row-specific. If it were global,
            # every Cargo row would silently lose its frozen selectors and the
            # check above would still pass.
            Set-C4RunnerChildEnvironment $fakeLeases $fakeCargo 7 '07-driver-core-clippy' '' @($script:NestedToolMap[7]) 'rust-1.85.0'
            Assert-Ok 'a Cargo row is still handed its single-version selectors' (
                [string]$env:CARGO -ceq 'C:/frozen/cargo-1.85.0.exe' -and
                [string]$env:RUSTC -ceq 'C:/frozen/rustc-1.85.0.exe' -and
                [string]$env:CLIPPY_DRIVER_PATH -ceq 'C:/frozen/clippy-driver-1.85.0.exe' -and
                [string]$env:CARGO_HOME -ceq 'C:/frozen/cargo-home')

            # And row 11 keeps the map-derived rule it already passes under.
            Set-C4RunnerChildEnvironment $fakeLeases $fakeCargo 11 '11-compile-fail' '' @($script:NestedToolMap[11]) 'git-bash+rust-1.85.0'
            Assert-Ok 'a git-bash Cargo row keeps its map-derived selectors' (
                [string]$env:CARGO -ceq 'C:/frozen/cargo-1.85.0.exe' -and
                [string]$env:CARGO_HOME -ceq 'C:/frozen/cargo-home')
        } finally {
            Restore-C4RunnerEnvironment $savedChildEnv
        }

        # --- the reference PASS -------------------------------------------
        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $manifest = Invoke-Run $options
        $sealed = Assert-Sealed 'baseline seals PASS' $world 'PASS' $null $null
        Assert-Ok 'baseline binds the source identity' (
            $null -ne $sealed -and [string]$sealed.sourceCommit -ceq $world.Commit -and
            [string]$sealed.sourceTree -ceq $world.Tree)
        Assert-Ok 'baseline seals all four downstream hashes' (
            $null -ne $sealed -and
            $sealed.toolsSha256 -cmatch '^[0-9a-f]{64}$' -and
            $sealed.commandIndexSha256 -cmatch '^[0-9a-f]{64}$' -and
            $sealed.candidateManifestSha256 -cmatch '^[0-9a-f]{64}$' -and
            $sealed.attemptFilesSha256 -cmatch '^[0-9a-f]{64}$')
        $index = Read-Sealed $world 'command-index.json'
        Assert-Ok 'baseline command index carries 38 PASS rows' (
            $null -ne $index -and @($index.commands).Count -eq 38 -and
            @(@($index.commands) | Where-Object { $_.status -cne 'PASS' }).Count -eq 0 -and
            [string]$index.gateStatus -ceq 'PASS')
        Assert-Ok 'baseline command index binds tools.json' (
            $null -ne $index -and [string]$index.toolsSha256 -ceq [string]$sealed.toolsSha256)
        Assert-Ok 'baseline nested-tool entry counts are the closed oracle' (
            $null -ne $index -and
            (@(@($index.commands) | ForEach-Object {
                @($_.nestedTools).Count -eq [int]$script:NestedToolEntryCounts[[int]$_.ordinal]
            } | Where-Object { -not $_ }).Count -eq 0))
        $tools = Read-Sealed $world 'tools.json'
        Assert-Ok 'tools.json carries twenty ordered roles' (
            $null -ne $tools -and @($tools.tools).Count -eq 20 -and
            ((@($tools.tools) | ForEach-Object { [string]$_.role }) -join ',') -ceq ($script:ToolRoles -join ','))
        Assert-Ok 'tools.json seals the Cargo environment' (
            $null -ne $tools -and [string]$tools.cargoEnvironment.cargoIncremental -ceq '0' -and
            [bool]$tools.cargoEnvironment.cargoHomeBinExcluded -and
            @($tools.cargoEnvironment.inheritedSelectorNames).Count -eq 0)
        Assert-Ok 'the tracked Cargo config is the only present candidate' (
            $null -ne $tools -and
            @(@($tools.cargoEnvironment.configCandidates) | Where-Object { [bool]$_.present }).Count -eq 1 -and
            @(@($tools.cargoEnvironment.configCandidates) | Where-Object { [bool]$_.present })[0].scope -ceq 'SOURCE_TRACKED')
        $candidate = Read-Sealed $world 'candidate-artifacts.json'
        Assert-Ok 'the candidate binds the command index' (
            $null -ne $candidate -and
            [string]$candidate.commandIndexSha256 -ceq [string]$sealed.commandIndexSha256)
        Assert-Ok 'the candidate carries nine artifact rows' (
            $null -ne $candidate -and @($candidate.artifacts.package.members).Count -eq 6 -and
            $null -ne $candidate.artifacts.harness -and $null -ne $candidate.artifacts.abiArchive -and
            $null -ne $candidate.artifacts.specArchive)
        Assert-Ok 'the candidate names the exact smoke driver' (
            $null -ne $candidate -and
            [string]$candidate.smokeDriver.relativePath -ceq $script:SmokeDriverRelativePath)
        $roster = Read-Sealed $world 'attempt-files.json'
        Assert-Ok 'the file roster excludes only itself and attempt.json' (
            $null -ne $roster -and
            @(@($roster.files) | Where-Object { $_.relativePath -ceq 'attempt.json' -or $_.relativePath -ceq 'attempt-files.json' }).Count -eq 0)
        Assert-Ok 'the file roster never enumerates scratch' (
            $null -ne $roster -and
            @(@($roster.files) | Where-Object { ([string]$_.relativePath).Contains('harness/x86_64') }).Count -eq 0)
        Assert-Ok 'only the exact selected harness reached the attempt' (
            [IO.File]::Exists((Join-Path $world.AttemptRoot ($script:HarnessCandidateRelativePath -replace '/', '\'))) -and
            -not [IO.Directory]::Exists((Join-Path $world.AttemptRoot 'artifacts\win10-x64-release\deps')))

        # An external cargo subcommand needs the word cargo would have passed.
        # Without it clippy forwards the row's flags to `cargo check`, which is
        # how row 07 failed on the real gate while every fixture was green.
        Note 'row 07 carries the clippy subcommand word'
        $world = New-World
        $leaseStubs = [ordered]@{}
        foreach ($role in $script:ToolRoles) {
            $leaseStubs[$role] = [pscustomobject]@{ Path = [string]$world.ToolPaths[$role] }
        }
        $expandContext = [pscustomobject]@{
            AttemptRoot = $world.AttemptRoot
            ScratchRoot = $world.ScratchRoot
            SourceCommit = $world.Commit
            SourceTree = $world.Tree
        }
        $clippyArgv = @((Expand-C4RunnerRowArgv 7 $script:ExpectedGateRows[6] $leaseStubs $expandContext).Argv)
        if ([string]$clippyArgv[1] -cne 'clippy') {
            Fail 'row 07 carries the clippy subcommand word' ('argv[1] is ' + $clippyArgv[1])
        }
        Assert-Ok 'row 03 does not gain a subcommand word it does not need' (
            [string]@((Expand-C4RunnerRowArgv 3 $script:ExpectedGateRows[2] $leaseStubs $expandContext).Argv)[1] -ceq '--all')

        # An empty-map row must never be handed a nonce: that is what makes a
        # compliant helper stay quiet instead of reporting a roster it does not
        # own. Row 13 of the real gate emitted one because every row was given
        # a nonce, and the drift was caught after the fact rather than
        # prevented.
        Assert-Ok 'a marker-producing row is in the closed roster' (
            ($script:MarkerProducingOrdinals -contains 21) -and
            ($script:MarkerProducingOrdinals -contains 12))
        # Rows 33 and 34 recompute the attestation, and two of its rows are
        # `cargo +1.85.0 test`. The map decides which roles reach the child and
        # the nonce decides whether a marker is owed; those stay different
        # questions, but both answers are now yes for these two rows.
        Assert-Ok 'the graph rows carry the 1.85 base they actually launch' (
            @($script:NestedToolMap[33]).Count -eq 3 -and
            @($script:NestedToolMap[34]).Count -eq 3 -and
            (@($script:NestedToolMap[34]) -join ',') -ceq 'cargo-1.85.0,rustc-1.85.0,rustdoc-1.85.0')
        # This assertion used to read `still owe no marker`, which encoded the
        # gap R09 named as though it were an invariant. A row that observes
        # nothing cannot be caught not observing.
        Assert-Ok 'the graph rows owe a marker' (
            ($script:MarkerProducingOrdinals -contains 33) -and
            ($script:MarkerProducingOrdinals -contains 34))
        # NOT every marker-producing row: 11, 12 and 14 report their counts and
        # are deliberately unpinned, because a sweep launches a payload once per
        # mutant and the number is a property of the roster, not of the row.
        # These four are the ones R09 named, and all four are pinned.
        Assert-Ok 'the four rows R09 named carry a launch-count oracle' (
            @(@(19, 20, 33, 34) | Where-Object {
                -not $script:ExpectedMarkerLaunchCounts.ContainsKey($_) }).Count -eq 0)
        Assert-Ok 'an empty-map row is not a marker-producing row' (
            ($script:MarkerProducingOrdinals -notcontains 13) -and
            ($script:MarkerProducingOrdinals -notcontains 28) -and
            @($script:NestedToolMap[13]).Count -eq 0)

        # --- pre-acceptance refusals --------------------------------------
        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.GitStatusDirty = $true
        Assert-Refuses 'a dirty source tree refuses' { Invoke-Run $options } 'the source tree is dirty'
        Assert-Ok 'a refused dirty run created no attempt' (-not [IO.Directory]::Exists($world.AttemptRoot))

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.GitHead = ('9' * 40)
        Assert-Refuses 'a different HEAD refuses' { Invoke-Run $options } 'HEAD does not equal'

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.GitTree = ('9' * 40)
        Assert-Refuses 'a different tree refuses' { Invoke-Run $options } 'HEAD^{tree} does not equal'

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        [void][IO.Directory]::CreateDirectory($world.AttemptRoot)
        Assert-Refuses 'an existing attempt directory refuses' { Invoke-Run $options } '-OutputDirectory must be absent'

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $options.ScratchDirectory = Join-Path $world.AttemptRoot 'scratch'
        Assert-Refuses 'scratch inside the attempt refuses' { Invoke-Run $options } 'direct child of the authorized external parent'

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $options.AuthorizedExternalParent = $world.RepoRoot
        $options.OutputDirectory = Join-Path $world.RepoRoot 'attempt'
        $options.ScratchDirectory = Join-Path $world.RepoRoot 'scratch'
        Assert-Refuses 'an in-repository attempt refuses' { Invoke-Run $options } 'must be outside the repository'

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $options.OutputDirectory = Join-Path $world.Root 'stray-attempt'
        Assert-Refuses 'an attempt outside the authorized parent refuses' { Invoke-Run $options } 'direct child of the authorized external parent'

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $options.AttemptId = 'not-a-guid'
        Assert-Refuses 'a malformed attempt ID refuses' { Invoke-Run $options } 'attempt ID must be a lowercase GUID-N'

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $options.ManifestRelative = 'C:/manifest.json'
        Assert-Refuses 'an absolute manifest refuses' { Invoke-Run $options } '-Manifest must be a repository-relative file path'

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $overrides = [ordered]@{}
        foreach ($role in $script:ToolRoles) { $overrides[$role] = $world.ToolPaths[$role] }
        $overrides['signtool'] = Join-Path $world.Root 'absent-signtool.exe'
        $options.ToolOverrides = $overrides
        Assert-Refuses 'a missing frozen role refuses' { Invoke-Run $options } 'Could not find file'

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $utf8 = New-Object System.Text.UTF8Encoding $false
        [IO.File]::WriteAllBytes((Join-Path $world.CargoHome 'config.toml'), $utf8.GetBytes("[build]`n"))
        Assert-Refuses 'an unsealed Cargo home configuration refuses' { Invoke-Run $options } 'an unsealed Cargo configuration is present'

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.ConfigBlobOverride = "[build]`ndifferent = true`n"
        Assert-Refuses 'tracked Cargo config drift refuses' { Invoke-Run $options } 'does not match its committed tree blob'

        # --- manifest drift -----------------------------------------------
        function Set-ManifestField {
            param($World, [scriptblock]$Mutate)
            $path = Join-Path $World.RepoRoot 'driver\audit\c4-source-gates.json'
            $document = [IO.File]::ReadAllText($path) | ConvertFrom-Json
            & $Mutate $document
            $utf8 = New-Object System.Text.UTF8Encoding $false
            [IO.File]::WriteAllBytes($path, $utf8.GetBytes(($document | ConvertTo-Json -Depth 12)))
        }

        foreach ($case in @(
            @('a drifted row id', { param($d) $d.commands[6].id = 'renamed' }, "gate row 07 is 'renamed'"),
            @('a drifted argv element', { param($d) $d.commands[3].argv[1] = 'build' }, 'gate row 04 argv[1]'),
            @('a drifted cwd', { param($d) $d.commands[0].cwd = 'driver' }, 'gate row 01 cwd drifted'),
            @('a drifted toolchain', { param($d) $d.commands[10].toolchain = 'python3-recorded' }, 'gate row 11 toolchain'),
            @('a drifted expected exit', { param($d) $d.commands[34].expectedExit = 1 }, 'gate row 35 expectedExit drifted'),
            @('a drifted timeout', { param($d) $d.commands[11].timeoutSeconds = 60 }, 'gate row 12 timeoutSeconds is 60'),
            @('a drifted stdout path', { param($d) $d.commands[1].stdout = 'commands/02-other.stdout.bin' }, 'gate row 02 stdout path drifted'),
            @('a drifted stderr path', { param($d) $d.commands[1].stderr = 'commands/02-other.stderr.bin' }, 'gate row 02 stderr path drifted'),
            @('a drifted exit path', { param($d) $d.commands[1].exit = 'commands/02-other.exit.json' }, 'gate row 02 exit path drifted'),
            @('a wrong schema', { param($d) $d.schema = 'other/v1' }, 'gate manifest schema is'),
            @('a wrong working directory', { param($d) $d.workingDirectory = 'driver' }, 'workingDirectory must be exactly'),
            @('a removed row', { param($d) $d.commands = @($d.commands[0..36]) }, 'gate manifest has 37 rows'),
            @('an extra row', { param($d) $d.commands = @($d.commands) + @($d.commands[0]) }, 'gate manifest has 39 rows'),
            @('reordered rows', { param($d) $t = $d.commands[2]; $d.commands[2] = $d.commands[3]; $d.commands[3] = $t }, "gate row 03 is 'root-check'")
        )) {
            $world = New-World
            $options = New-C4RunnerTestOptions $world
            Set-ManifestField $world $case[1]
            Assert-Refuses ('manifest drift: ' + $case[0]) { Invoke-Run $options } $case[2]
        }

        # A token that could name an arbitrary path is a different class of
        # defect from a changed literal, so each position rule has its own
        # fixture.
        foreach ($case in @(
            @('{scratch} outside row 27', { param($d) $d.commands[3].argv[1] = '{scratch}/harness' }, '{scratch} is legal only as row 27'),
            @('{git-bash} away from argv[0]', { param($d) $d.commands[3].argv[1] = '{git-bash}' }, '{git-bash} is legal only as argv[0]'),
            @('{infverif} away from -InfVerifPath', { param($d) $d.commands[3].argv[1] = '{infverif}' }, '{infverif} is legal only after'),
            @('{signtool} away from -SignToolPath', { param($d) $d.commands[3].argv[1] = '{signtool}' }, '{signtool} is legal only after'),
            @('an environment fragment', { param($d) $d.commands[3].argv[1] = '%PATH%' }, 'environment, glob or response-file fragment')
        )) {
            $world = New-World
            $options = New-C4RunnerTestOptions $world
            Set-ManifestField $world $case[1]
            Assert-Refuses ('token drift: ' + $case[0]) { Invoke-Run $options } $case[2]
        }

        # --- tool freeze --------------------------------------------------
        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.ToolExit['python'] = 3
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a nonzero tool version seals TOOL_FREEZE FAIL' $world 'FAIL' 'TOOL_FREEZE' $null)
        Assert-Ok 'a TOOL_FREEZE attempt has no command index' (
            $null -eq (Read-Sealed $world 'command-index.json'))
        Assert-Ok 'a TOOL_FREEZE attempt still seals its file roster' (
            $null -ne (Read-Sealed $world 'attempt-files.json'))

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.ToolTermination['git'] = 'TIMEOUT'
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a tool version timeout seals TOOL_FREEZE TIMEOUT' $world 'TIMEOUT' 'TOOL_FREEZE' $null)

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.ToolStdout['cargo-1.82.0'] = "cargo 1.85.0`nrelease: 1.85.0`ncommit-hash: 0`nhost: x86_64-pc-windows-msvc"
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a cross-version payload seals TOOL_FREEZE IDENTITY_DRIFT' $world 'IDENTITY_DRIFT' 'TOOL_FREEZE' $null)

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.ToolStdout['rustfmt-1.85.0'] = "rustfmt 9.9.9-stable (other)"
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a mismatching fmt pair seals TOOL_FREEZE IDENTITY_DRIFT' $world 'IDENTITY_DRIFT' 'TOOL_FREEZE' $null)

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.ToolStdout['cargo-wdk-0.1.1'] = 'cargo wdk 0.2.0'
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a wrong cargo-wdk seals TOOL_FREEZE IDENTITY_DRIFT' $world 'IDENTITY_DRIFT' 'TOOL_FREEZE' $null)

        # --- command fail-stop --------------------------------------------
        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowExit[7] = 101
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a nonzero row seals COMMAND_FAIL' $world 'FAIL' 'COMMAND_FAIL' '07-driver-core-clippy')
        $index = Read-Sealed $world 'command-index.json'
        Assert-Ok 'the failing row is FAIL and later rows are NOT_ISSUED' (
            $null -ne $index -and
            [string]@($index.commands)[6].status -ceq 'FAIL' -and
            [string]@($index.commands)[7].status -ceq 'NOT_ISSUED' -and
            [string]@($index.commands)[37].status -ceq 'NOT_ISSUED')
        Assert-Ok 'unissued rows carry the NOT_ISSUED exit record' (
            $null -ne $index -and [int]@($index.commands)[37].stdoutBytes -eq 0 -and
            $null -eq @($index.commands)[37].observedExit)
        Assert-Ok 'a failing attempt has no candidate hash' (
            $null -eq (Read-Sealed $world 'attempt.json').candidateManifestSha256)
        Assert-Ok 'a failing attempt marks every auxiliary absent' (
            $null -ne $index -and
            @(@($index.auxiliaryFiles) | Where-Object { [bool]$_.present }).Count -eq 0)

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowTermination[12] = 'TIMEOUT'
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a timed-out row seals COMMAND_TIMEOUT' $world 'TIMEOUT' 'COMMAND_TIMEOUT' '12-mutation-default')

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowTermination[5] = 'START_FAILED'
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'an unstartable row seals COMMAND_START_FAILED' $world 'FAIL' 'COMMAND_START_FAILED' '05-root-test')

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowTermination[9] = 'CAPTURE_FAILED'
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a failed capture seals COMMAND_CAPTURE_FAILED' $world 'FAIL' 'COMMAND_CAPTURE_FAILED' '09-c2-boundary')

        # --- nested-tool markers -------------------------------------------
        foreach ($case in @(
            @('a suppressed marker', 21, { $script:FakeState.MarkerSuppress[21] = $true }, '21-package-win10-x64'),
            @('a foreign nonce', 21, { $script:FakeState.MarkerNonceOverride[21] = 'FOREIGN' }, '21-package-win10-x64'),
            @('a missing marker role', 21, { $script:FakeState.MarkerRoles[21] = @('powershell', 'infverif') }, '21-package-win10-x64'),
            @('an extra marker role', 19, { $script:FakeState.MarkerRoles[19] = @(@($script:NestedToolMap[19]) + @('python')) }, '19-matrix-selftest'),
            @('a reordered marker roster', 12, { $script:FakeState.MarkerRoles[12] = @(@($script:NestedToolMap[12])[3..5] + @($script:NestedToolMap[12])[0..2]) }, '12-mutation-default'),
            @('a PRE/POST roster split', 14, { $script:FakeState.MarkerPostRoles[14] = @(@($script:NestedToolMap[14])[0..6]) }, '14-mutation-c4'),
            @('a marker on an empty-map row', 28, { $script:FakeState.MarkerSuppress[28] = $false }, '28-verify-spec'),
            @('a wrong row-01 launch count', 1, { $script:FakeState.MarkerCounts[1] = [ordered]@{ powershell = 1 } }, '01-source-runner-selftest'),
            @('a wrong row-21 powershell count', 21, { $script:FakeState.MarkerCounts[21] = [ordered]@{ powershell = 2; infverif = 1; signtool = 6 } }, '21-package-win10-x64'),
            @('a wrong row-21 infverif count', 21, { $script:FakeState.MarkerCounts[21] = [ordered]@{ powershell = 1; infverif = 2; signtool = 6 } }, '21-package-win10-x64'),
            @('a wrong row-21 signtool count', 21, { $script:FakeState.MarkerCounts[21] = [ordered]@{ powershell = 1; infverif = 1; signtool = 5 } }, '21-package-win10-x64'),
            @('an empty row-19 launch count', 19, { $script:FakeState.MarkerCounts[19] = [ordered]@{} }, '19-matrix-selftest'),
            @('a wrong row-19 python count', 19, { $script:FakeState.MarkerCounts[19] = [ordered]@{ powershell = 402; python = 1 } }, '19-matrix-selftest'),
            @('an empty row-20 launch count', 20, { $script:FakeState.MarkerCounts[20] = [ordered]@{} }, '20-matrix-three-profile'),
            @('a row-20 count missing git-bash', 20, { $script:FakeState.MarkerCounts[20] = [ordered]@{ powershell = 822; python = 10 } }, '20-matrix-three-profile'),
            @('a suppressed row-33 marker', 33, { $script:FakeState.MarkerSuppress[33] = $true }, '33-production-graph-selftest'),
            @('a wrong row-33 cargo count', 33, { $script:FakeState.MarkerCounts[33] = [ordered]@{ 'cargo-1.85.0' = 1; 'rustc-1.85.0' = 0; 'rustdoc-1.85.0' = 0 } }, '33-production-graph-selftest'),
            @('a suppressed row-34 marker', 34, { $script:FakeState.MarkerSuppress[34] = $true }, '34-production-graph-final'),
            @('a row-34 count claiming rustc ran', 34, { $script:FakeState.MarkerCounts[34] = [ordered]@{ 'cargo-1.85.0' = 2; 'rustc-1.85.0' = 1; 'rustdoc-1.85.0' = 0 } }, '34-production-graph-final')
        )) {
            $world = New-World
            $options = New-C4RunnerTestOptions $world
            & $case[2]
            [void](Invoke-Run $options)
            [void](Assert-Sealed ('marker drift: ' + $case[0]) $world 'IDENTITY_DRIFT' 'IDENTITY_DRIFT' $case[3])
        }

        # --- postconditions -------------------------------------------------
        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.AfterRow[13] = {
            $path = Join-Path $script:FakeState.World.AttemptRoot $script:MutationListRelativePath
            $utf8 = New-Object System.Text.UTF8Encoding $false
            [IO.File]::WriteAllBytes($path, $utf8.GetBytes('{"schema":"fsring-c4-mutations/v1","mutants":[]}' + "`n"))
        }
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a drifted mutation list fails row 13' $world 'FAIL' 'COMMAND_FAIL' '13-mutation-c4-list')

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowStdout[36] = " M driver/fsring-core/src/lib.rs`n"
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a dirty clean-close fails row 36' $world 'FAIL' 'COMMAND_FAIL' '36-clean-close')

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowStdout[37] = (('8' * 40) + "`n")
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a wrong head-close fails row 37' $world 'FAIL' 'COMMAND_FAIL' '37-head-close')

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowStdout[38] = (('8' * 40) + "`n")
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a wrong tree-close fails row 38' $world 'FAIL' 'COMMAND_FAIL' '38-tree-close')

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowStdoutBody[34] = (ConvertTo-C4CanonicalJsonText ([ordered]@{
            mode = 'verify-current-attestation'; profile = 'r4-cutover'; result = 'PASS'
            rowCount = 5; sourceIdentity = ('c' * 64)
        }))
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a wrong graph profile fails row 34' $world 'FAIL' 'COMMAND_FAIL' '34-production-graph-final')

        # Row 14 can pass its exit code without doing the work: the sweep
        # resumes from a journal keyed to the tree, and two sealed attempts
        # replayed in seconds while still printing `c4 suite: PASS`. The
        # `--no-resume` flag is a claim about intent; these two cases prove the
        # postcondition reads the bytes.
        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowStderr[14] = "C4 resume: replaying 465 journalled verdicts from J`n"
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a replayed row 14 fails' $world 'FAIL' 'COMMAND_FAIL' '14-mutation-c4')

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowStderr[14] = "C4 parallel: 4 workers, 465 mutants remaining`n"
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a row 14 with no per-mutant progress fails' $world 'FAIL' 'COMMAND_FAIL' '14-mutation-c4')

        # Row 12 had the identical exposure and it was found the same way: an
        # interrupted battery left a journal keyed to this tree and the next
        # attempt replayed 369 of 369 verdicts and sealed PASS. One case per
        # comparison the postcondition makes, so deleting any of them turns this
        # self-test red.
        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowBody[12] = @('    1/2  CAUGHT    (replayed)  [A] fixture guard one', 'MUTATION SWEEP: PASS')
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a replayed row 12 fails' $world 'FAIL' 'COMMAND_FAIL' '12-mutation-default')

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowStderr[12] = "resume: replaying 369 journalled verdicts from J`n"
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a row 12 that opened a resume journal fails' $world 'FAIL' 'COMMAND_FAIL' '12-mutation-default')

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowBody[12] = @('MUTATION SWEEP: PASS')
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a row 12 with no per-mutant verdict rows fails' $world 'FAIL' 'COMMAND_FAIL' '12-mutation-default')

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowBody[12] = @('    1/2  CAUGHT      [A] fixture guard one')
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a row 12 with no sweep verdict line fails' $world 'FAIL' 'COMMAND_FAIL' '12-mutation-default')

        # Row 33 was checked by `.Contains('PASS')`, which any line carrying the
        # word satisfies -- including a failure report that names a passing row,
        # and a self-test that ran zero checks. One case per half of the
        # replacement.
        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowBody[33] = @('audit_c4_production_graph gate row nine: PASS')
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a row 33 without the self-test verdict line fails' $world 'FAIL' 'COMMAND_FAIL' '33-production-graph-selftest')

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowBody[33] = @('audit_c4_production_graph self-test: PASS (0 checks, 0 failures)')
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a row 33 self-test that ran no checks fails' $world 'FAIL' 'COMMAND_FAIL' '33-production-graph-selftest')

        # Row 34's same-artifact cross-check has three comparisons, and each one
        # is deletable without any other test noticing. One negative case per
        # comparison, so removing any of them turns this self-test red.
        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.RowStdoutBody[34] = (ConvertTo-C4CanonicalJsonText ([ordered]@{
            mode = 'verify-current-attestation'; profile = 'r5-cutover'; result = 'PASS'
            rowCount = 5; sourceIdentity = ('d' * 64)
        }))
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'row 34 disagreeing with the attestation identity fails' $world 'FAIL' 'COMMAND_FAIL' '34-production-graph-final')

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $utf8Neg = New-Object System.Text.UTF8Encoding $false
        [IO.File]::WriteAllBytes((Join-Path $world.RepoRoot 'driver\audit\c4-production-attestation.json'),
            $utf8Neg.GetBytes((ConvertTo-C4CanonicalJsonText ([ordered]@{
                schema = 'fsring-c4-production-attestation/v1'
                version = 1
                profile = 'r5-cutover'
                sourceIdentity = ('C' * 64)
                manifestSha256 = ('E' * 64)
            })) + "`n"))
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'an attestation naming a foreign manifest fails row 34' $world 'FAIL' 'COMMAND_FAIL' '34-production-graph-final')

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        [IO.File]::WriteAllBytes((Join-Path $world.RepoRoot 'driver\audit\c4-production-attestation.json'),
            $utf8Neg.GetBytes((ConvertTo-C4CanonicalJsonText ([ordered]@{
                schema = 'fsring-c4-production-attestation/v1'
                version = 1
                profile = 'r4-cutover'
                sourceIdentity = ('C' * 64)
                manifestSha256 = (Get-C4EvidenceSha256Hex ($utf8Neg.GetBytes("{}`n"))).ToUpperInvariant()
            })) + "`n"))
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a wrong-profile attestation fails row 34' $world 'FAIL' 'COMMAND_FAIL' '34-production-graph-final')

        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.AfterRow[27] = {
            Remove-Item -LiteralPath (Join-Path $script:FakeState.World.ScratchRoot ($script:HarnessScratchRelativePath -replace '/', '\')) -Force
        }
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a missing harness fails row 27' $world 'FAIL' 'COMMAND_FAIL' '27-harness-win10-x64-release')

        # The report is corrupted INSIDE the fake's row-21 branch so the two
        # markers still surround it: replacing the whole stream would trip the
        # marker gate first and the postcondition would never be reached.
        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.BreakPackageReport = $true
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a malformed package report fails row 21' $world 'FAIL' 'COMMAND_FAIL' '21-package-win10-x64')

        # --- mid-run identity drift ----------------------------------------
        #
        # A payload swap does not need to be *detected*: the retained lease
        # denies write and delete, so it cannot happen while the row is in
        # flight. This fixture proves that refusal is real rather than assuming
        # the handle helps, which is the difference between a guard and a
        # comment.
        Note 'a held payload cannot be replaced mid-run'
        $world = New-World
        $pythonPath = [string]$world.ToolPaths['python']
        $lease = Open-C4HeldFileLease -Path $pythonPath -ExpectedSha256 (Get-C4RunnerSha256File $pythonPath)
        try {
            $blocked = $false
            try {
                [IO.File]::WriteAllBytes($pythonPath, (New-Object byte[] 4))
            } catch {
                $blocked = $true
            }
            if (-not $blocked) {
                Fail 'a held payload cannot be replaced mid-run' 'the deny-write lease allowed a replacement'
            }
        } finally {
            Close-C4HeldFileLease $lease
        }

        # A Cargo configuration is NOT leased -- nothing holds a handle on a
        # file that does not exist yet -- so this is the drift the row checks
        # actually have to catch, and it is caught by the row that was running
        # when the file appeared.
        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.AfterRow[4] = {
            $utf8 = New-Object System.Text.UTF8Encoding $false
            [IO.File]::WriteAllBytes((Join-Path $script:FakeState.World.CargoHome 'config'), $utf8.GetBytes("[build]`n"))
        }
        [void](Invoke-Run $options)
        [void](Assert-Sealed 'a Cargo config injected mid-run seals IDENTITY_DRIFT' $world 'IDENTITY_DRIFT' 'IDENTITY_DRIFT' '04-root-check')

        # --- the sealed file roster is closed ------------------------------
        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.AfterRow[38] = {
            $utf8 = New-Object System.Text.UTF8Encoding $false
            [IO.File]::WriteAllBytes((Join-Path $script:FakeState.World.AttemptRoot 'stray.txt'), $utf8.GetBytes('x'))
        }
        Assert-Refuses 'an unexpected attempt file refuses sealing' { Invoke-Run $options } 'an unexpected file is present in the sealed attempt'

        # --- candidate sealing ---------------------------------------------
        $world = New-World
        $options = New-C4RunnerTestOptions $world
        $script:FakeState.AfterRow[38] = {
            Remove-Item -LiteralPath (Join-Path $script:FakeState.World.ScratchRoot ($script:HarnessScratchRelativePath -replace '/', '\')) -Force
        }
        [void](Invoke-Run $options)
        $sealed = Assert-Sealed 'a post-row-38 harness loss seals CANDIDATE_SEAL' $world 'FAIL' 'CANDIDATE_SEAL' $null
        $index = Read-Sealed $world 'command-index.json'
        Assert-Ok 'CANDIDATE_SEAL leaves the immutable command index at PASS' (
            $null -ne $index -and [string]$index.gateStatus -ceq 'PASS')
        Assert-Ok 'CANDIDATE_SEAL leaves the candidate hash null' (
            $null -ne $sealed -and $null -eq $sealed.candidateManifestSha256)
        Assert-Ok 'CANDIDATE_SEAL still seals a file roster hash' (
            $null -ne $sealed -and $sealed.attemptFilesSha256 -cmatch '^[0-9a-f]{64}$')

        # --- -PrintToolVersion ---------------------------------------------
        Assert-Refuses 'an unknown -PrintToolVersion role refuses' {
            Invoke-C4RunnerPrintToolVersion 'python' ''
        } 'accepts only powershell, infverif or signtool'
        Assert-Refuses '-PrintToolVersion powershell refuses a tool path' {
            Invoke-C4RunnerPrintToolVersion 'powershell' 'C:\Windows\System32\cmd.exe'
        } 'takes no -ToolPath'
        Assert-Refuses '-PrintToolVersion infverif refuses a missing file' {
            Invoke-C4RunnerPrintToolVersion 'infverif' (Join-Path $root 'absent.exe')
        } '-ToolPath names no file'
        Assert-Refuses '-PrintToolVersion infverif refuses a relative path' {
            Invoke-C4RunnerPrintToolVersion 'infverif' 'infverif.exe'
        } '-ToolPath must be absolute'
        Note '-PrintToolVersion reads a real version resource'
        $probe = Join-Path $PSHOME 'powershell.exe'
        $captured = $null
        try {
            $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($probe)
            $captured = ([string]$info.FileVersion + '|' + [string]$info.ProductVersion)
        } catch {
            Fail '-PrintToolVersion reads a real version resource' $_.Exception.Message
        }
        if ($null -ne $captured -and $captured -cnotmatch '^[^|]+\|[^|]+$') {
            Fail '-PrintToolVersion reads a real version resource' 'the probe did not yield two components'
        }
    } finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        if (-not [string]::IsNullOrEmpty($inheritedNonce)) {
            Set-Item -LiteralPath Env:FSRING_C4_MARKER_NONCE -Value $inheritedNonce
        }
        if (-not [string]::IsNullOrEmpty($inheritedCommandId)) {
            Set-Item -LiteralPath Env:FSRING_C4_COMMAND_ID -Value $inheritedCommandId
        }
    }
    return [pscustomobject]@{ Checks = @($checks); Failures = @($failures) }
}

# ---------------------------------------------------------------------------
# Row 01: the same-artifact umbrella
#
# The 38-row roster is closed, so the two newly committed orchestrators cannot
# each get their own row. Instead this script's own `-SelfTest` runs them as
# children and reports all four script hashes in one canonical object, which
# row 01's captured stdout then binds to the candidate. Task 30 authenticates
# that object before it will use any candidate script hash.
# ---------------------------------------------------------------------------

function Invoke-C4RunnerNestedSelfTest {
    param($PowerShellLease, [string]$ScriptPath, [string]$Workspace, [string]$Stem)

    $out = Join-Path $Workspace ($Stem + '.stdout.bin')
    $err = Join-Path $Workspace ($Stem + '.stderr.bin')
    $exit = Join-Path $Workspace ($Stem + '.exit.json')
    $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath, '-SelfTest')
    Invoke-C4EvidenceProcess -Executable $PowerShellLease.Path -Arguments $arguments `
        -WorkingDirectory ([IO.Path]::GetDirectoryName($ScriptPath)) `
        -TimeoutMilliseconds 900000 `
        -StdoutPath $out -StderrPath $err -ExitPath $exit -ExitFormat CanonicalJson
    $record = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($exit)) `
        -ExpectedSchema $script:CapturedExitSchema
    if ([string]$record.termination -cne 'NORMAL') {
        throw ($Stem + ' self-test terminated ' + $record.termination)
    }
    return [pscustomobject]@{
        ExitCode = [int]$record.observedExit
        StdoutSha256 = (Get-C4RunnerSha256File $out)
        StderrSha256 = (Get-C4RunnerSha256File $err)
        StderrText = ([IO.File]::ReadAllText($err))
    }
}

function Invoke-C4RunnerSelfTestEntry {
    param([string]$SelfPath)

    $scriptsDirectory = [IO.Path]::GetDirectoryName($SelfPath)
    $nativeRunner = [IO.Path]::GetFullPath((Join-Path $scriptsDirectory 'run_c4_native_attempt.ps1'))
    $captureHelper = [IO.Path]::GetFullPath((Join-Path $scriptsDirectory 'invoke_c4_evidence.ps1'))
    $recorder = [IO.Path]::GetFullPath((Join-Path $scriptsDirectory 'record_c4_evidence.ps1'))
    foreach ($path in @($nativeRunner, $captureHelper, $recorder)) {
        if (-not [IO.File]::Exists($path)) {
            throw ('the row-01 umbrella requires ' + $path)
        }
    }

    $outcome = Invoke-C4RunnerSelfTests
    $status = 'PASS'
    if (@($outcome.Failures).Count -ne 0) { $status = 'FAIL' }
    foreach ($failure in @($outcome.Failures)) {
        [Console]::Error.WriteLine('SOURCE-RUNNER SELF-TEST: ' + $failure)
    }

    # Under the gate the parent supplies the exact frozen host; standalone it
    # is this process's own. Reading $PSHOME would usually agree -- the child
    # was launched through that very file -- but "usually agrees" is not the
    # property row 01 is supposed to bind.
    $powerShellPath = [string]$env:FSRING_C4_TOOL_POWERSHELL
    if ([string]::IsNullOrWhiteSpace($powerShellPath)) {
        $powerShellPath = Join-Path $PSHOME 'powershell.exe'
    }
    $powerShellPath = [IO.Path]::GetFullPath($powerShellPath)
    $powerShellLease = Open-C4HeldFileLease -Path $powerShellPath -ExpectedSha256 (Get-C4RunnerSha256File $powerShellPath)
    $workspace = Join-Path $env:TEMP ('c4gr-nested-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    [void][IO.Directory]::CreateDirectory($workspace)
    $nonce = [string]$env:FSRING_C4_MARKER_NONCE
    $commandId = [string]$env:FSRING_C4_COMMAND_ID
    try {
        $markerRoster = @([pscustomobject]@{ Role = 'powershell'; Lease = $powerShellLease })
        Write-C4RunnerStdoutLine (New-C4RunnerMarkerText 'PRE' $nonce $commandId $markerRoster $null)
        # The count is OBSERVED, not asserted: a hard-coded 2 would still say 2
        # if one nested self-test silently stopped being launched.
        $launched = 0
        $native = Invoke-C4RunnerNestedSelfTest $powerShellLease $nativeRunner $workspace 'native'
        $launched += 1
        $recorded = Invoke-C4RunnerNestedSelfTest $powerShellLease $recorder $workspace 'recorder'
        $launched += 1
        Assert-C4HeldFileLease $powerShellLease
        Write-C4RunnerStdoutLine (New-C4RunnerMarkerText 'POST' $nonce $commandId $markerRoster ([ordered]@{ powershell = $launched }))

        if ($native.ExitCode -ne 0) {
            $status = 'FAIL'
            [Console]::Error.WriteLine('SOURCE-RUNNER SELF-TEST: nested native orchestrator failed: ' + $native.StderrText)
        }
        if ($recorded.ExitCode -ne 0) {
            $status = 'FAIL'
            [Console]::Error.WriteLine('SOURCE-RUNNER SELF-TEST: nested recorder failed: ' + $recorded.StderrText)
        }
        $object = [ordered]@{
            schema = $script:RunnerSelfTestObjectSchema
            version = 1
            sourceRunnerSha256 = (Get-C4RunnerSha256File $SelfPath)
            nativeRunnerSha256 = (Get-C4RunnerSha256File $nativeRunner)
            captureHelperSha256 = (Get-C4RunnerSha256File $captureHelper)
            recorderSha256 = (Get-C4RunnerSha256File $recorder)
            nativeExit = [int]$native.ExitCode
            nativeStdoutSha256 = $native.StdoutSha256
            nativeStderrSha256 = $native.StderrSha256
            recorderExit = [int]$recorded.ExitCode
            recorderStdoutSha256 = $recorded.StdoutSha256
            recorderStderrSha256 = $recorded.StderrSha256
            status = $status
        }
        Write-C4RunnerStdoutLine (ConvertTo-C4CanonicalJsonText $object)
        [Console]::Error.WriteLine('SOURCE-RUNNER SELF-TEST: ' + @($outcome.Checks).Count + ' checks, ' +
            @($outcome.Failures).Count + ' failures')
        if ($status -ceq 'PASS') { return 0 }
        return 1
    } finally {
        Close-C4HeldFileLease $powerShellLease
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function New-C4RunnerMarkerText {
    param([string]$Phase, [string]$Nonce, [string]$CommandId, $ToolLeases, $LaunchCounts)

    if ([string]::IsNullOrWhiteSpace($Nonce)) { return $null }
    $tools = New-Object System.Collections.ArrayList
    foreach ($entry in @($ToolLeases)) {
        Assert-C4HeldFileLease $entry.Lease
        [void]$tools.Add([ordered]@{
            role = $entry.Role
            path = $entry.Lease.Path
            volumeSerial = $entry.Lease.VolumeSerial
            fileId = $entry.Lease.FileId
            sha256 = $entry.Lease.Sha256
        })
    }
    $counts = New-Object System.Collections.ArrayList
    if ($null -ne $LaunchCounts) {
        foreach ($role in @($LaunchCounts.Keys)) {
            [void]$counts.Add([ordered]@{ role = $role; count = [int]$LaunchCounts[$role] })
        }
    }
    return ($script:NestedToolMarkerSentinel + (ConvertTo-C4CanonicalJsonText ([ordered]@{
        schema = $script:NestedToolMarkerSchema
        version = 1
        nonce = $Nonce
        phase = $Phase
        commandId = $CommandId
        tools = @($tools)
        launchCounts = @($counts)
    })))
}

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

if ($script:C4RunnerDotSourced) { return }

[Console]::OutputEncoding = (New-Object System.Text.UTF8Encoding $false)

if ($SelfTest) {
    try {
        exit (Invoke-C4RunnerSelfTestEntry ([IO.Path]::GetFullPath($PSCommandPath)))
    } catch {
        # A harness fault is not a fixture verdict, so the stack goes out too:
        # without it this reads like a refusal the suite intended.
        [Console]::Error.WriteLine('SOURCE-RUNNER SELF-TEST: FAIL: ' + $_.Exception.Message)
        [Console]::Error.WriteLine($_.ScriptStackTrace)
        exit 1
    }
}

if (-not [string]::IsNullOrWhiteSpace($PrintToolVersion)) {
    try {
        Invoke-C4RunnerPrintToolVersion $PrintToolVersion $ToolPath
        exit 0
    } catch {
        [Console]::Error.WriteLine('SOURCE-RUNNER TOOL-VERSION: FAIL: ' + $_.Exception.Message)
        exit 1
    }
}

try {
    $options = [pscustomobject]@{
        RepoRoot = (Get-C4RunnerRepositoryRoot)
        ManifestRelative = $Manifest
        AuthorizedExternalParent = $AuthorizedExternalParent
        OutputDirectory = $OutputDirectory
        ScratchDirectory = $ScratchDirectory
        AttemptId = $AttemptId
        ExpectedSourceCommit = $ExpectedSourceCommit
        ExpectedSourceTree = $ExpectedSourceTree
        Adapters = (New-C4RunnerProductionAdapters)
        ToolOverrides = $null
        CargoOverrides = $null
        SelfPath = [IO.Path]::GetFullPath($PSCommandPath)
        TrackedConfigSha256 = $null
    }
    $manifestObject = Invoke-C4SourceGateRun $options
    Write-C4RunnerStdoutLine (ConvertTo-C4CanonicalJsonText $manifestObject)
    if ([string]$manifestObject.gateStatus -ceq 'PASS') { exit 0 }
    exit 1
} catch {
    [Console]::Error.WriteLine('SOURCE-GATE RUNNER: FAIL: ' + $_.Exception.Message)
    exit 2
}
