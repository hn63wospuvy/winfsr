# The only Task 30 (R7) state-machine entry point.
#
# Six mutually exclusive modes drive one immutable native attempt:
#
#   Inspect      resolve the eligible candidate, verify artifacts and local
#                tools, run the read-only preflight, and either seal a complete
#                FAIL/NOT RUN attempt or publish a runnable pending state
#   Authorize    record fresh explicit user authority for that exact tuple
#   SealNotRun   the only close path when authority is declined or absent
#   Run          revalidate, run the one live command, and seal
#   CleanupOnly  bounded owned-resource recovery after a contained live child
#   SelfTest     fixtures only; never touches a real service, DOS name or
#                evidence root
#
# Three rules shape everything below.
#
# 1. Nothing here is a hash oracle for itself. Every expected value comes from
#    the caller-pinned bootstrap pair `B,BT`, the committed candidate ledger, or
#    row 01's authenticated self-test object -- never from current bytes and
#    never from current HEAD.
#
# 2. An issued child that cannot be proved contained is unsealable. A created
#    live or cleanup process that ended TIMEOUT/CAPTURE_FAILED without its exact
#    PASS containment proof does not produce an attempt, a recorder call or a
#    commit; it stops, because sealing it would claim a bounded outcome nobody
#    observed.
#
# 3. Zero mutation is a proof, not a default. NOT RUN at LIVE is legal only when
#    START_FAILED proves no child existed, or a valid diagnostics journal plus a
#    PASS containment proof shows exactly zero mutation attempts.

[CmdletBinding(DefaultParameterSetName = 'SelfTest')]
param(
    [Parameter(ParameterSetName = 'SelfTest', Mandatory = $true)]
    [switch]$SelfTest,

    [Parameter(ParameterSetName = 'Inspect', Mandatory = $true)]
    [Parameter(ParameterSetName = 'Authorize', Mandatory = $true)]
    [Parameter(ParameterSetName = 'SealNotRun', Mandatory = $true)]
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)]
    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [ValidateSet('Inspect', 'Authorize', 'SealNotRun', 'Run', 'CleanupOnly')]
    [string]$Mode,

    [Parameter(ParameterSetName = 'Inspect', Mandatory = $true)]
    [string]$AuthorizedExternalParent,

    [Parameter(ParameterSetName = 'Inspect', Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(ParameterSetName = 'Inspect', Mandatory = $true)]
    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [string]$AttemptId,

    [Parameter(ParameterSetName = 'Inspect', Mandatory = $true)]
    [string]$BootstrapSourceCommit,

    [Parameter(ParameterSetName = 'Inspect', Mandatory = $true)]
    [string]$BootstrapSourceTree,

    [Parameter(ParameterSetName = 'Inspect', Mandatory = $true)]
    [Parameter(ParameterSetName = 'Authorize', Mandatory = $true)]
    [Parameter(ParameterSetName = 'SealNotRun', Mandatory = $true)]
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)]
    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [string]$ExpectedNativeRunnerSha256,

    [Parameter(ParameterSetName = 'Inspect', Mandatory = $true)]
    [string]$ExpectedCaptureHelperSha256,

    [Parameter(ParameterSetName = 'Inspect', Mandatory = $true)]
    [string]$ExpectedRecorderSha256,

    [Parameter(ParameterSetName = 'Inspect')]
    [string]$PackageDirectory,

    [Parameter(ParameterSetName = 'Inspect')]
    [string]$HarnessPath,

    [Parameter(ParameterSetName = 'Authorize', Mandatory = $true)]
    [Parameter(ParameterSetName = 'SealNotRun', Mandatory = $true)]
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)]
    [string]$AttemptDirectory,

    [Parameter(ParameterSetName = 'Authorize', Mandatory = $true)]
    [Parameter(ParameterSetName = 'SealNotRun', Mandatory = $true)]
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)]
    [string]$ExpectedInspectionSha256,

    [Parameter(ParameterSetName = 'Authorize', Mandatory = $true)]
    [string]$AuthorizationReference,

    [Parameter(ParameterSetName = 'Run', Mandatory = $true)]
    [string]$ExpectedAuthorizationSha256,

    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [string]$CandidateManifestPath,

    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [string]$ExpectedCandidateManifestSha256,

    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [string]$DiagnosticsJournalPath,

    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [string]$ContainmentProofPath,

    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [string]$ExpectedContainmentProofSha256,

    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [string]$CleanupEvidencePath,

    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [string]$OwnedServiceName,

    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [string]$OwnedDosName,

    [Parameter(ParameterSetName = 'CleanupOnly')]
    [string]$AttemptDirectoryForCleanup
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:C4NativeDotSourced = ($MyInvocation.InvocationName -eq '.')
$script:C4NativeSavedSelfTest = [bool]$SelfTest
if (-not (Get-Variable -Name C4EvidenceDotSourced -Scope Script -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'invoke_c4_evidence.ps1')
}
$SelfTest = [bool]$script:C4NativeSavedSelfTest

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

$script:BootstrapSchema = 'fsring-c4-native-bootstrap/v1'
$script:PendingInspectionSchema = 'fsring-c4-native-pending-inspection/v1'
$script:InspectionResultSchema = 'fsring-c4-native-inspection-result/v1'
$script:AuthorizationSchema = 'fsring-c4-native-authorization/v1'
$script:AuthorizationResultSchema = 'fsring-c4-native-authorization-result/v1'
$script:ArtifactCheckSchema = 'fsring-c4-native-artifact-check/v1'
$script:PreflightSidecarSchema = 'fsring-c4-preflight-sidecars/v1'
$script:NotRunSchema = 'fsring-c4-native-not-run/v1'
$script:NativeAttemptSchema = 'fsring-c4-native-attempt/v1'
$script:NativeAttemptFilesSchema = 'fsring-c4-native-attempt-files/v1'
$script:CleanupResultSchema = 'fsring-c4-native-cleanup-recovery/v1'
$script:ContainmentSchema = 'fsring-c4-process-containment/v1'
$script:CapturedExitSchema = 'fsring-captured-exit/v1'
$script:CandidateSchema = 'fsring-c4-candidate-artifacts/v1'
$script:SourceIndexSchema = 'fsring-c4-source-attempt-index/v1'
$script:SourceRunnerSelfTestSchema = 'fsring-c4-source-runner-selftest/v1'
$script:PublicSmokeSchema = 'fsring-control-smoke/v2'
$script:SelfTestSchema = 'fsring-c4-native-attempt-selftest/v1'

# ---------------------------------------------------------------------------
# Closed rosters
# ---------------------------------------------------------------------------

# The eight operations authority is granted for, in execution order. No
# wildcard and no free-form operation is legal, so an authorization cannot
# quietly widen between the prompt and the run.
$script:AuthorizationOperations = @(
    'SERVICE_INSTALL', 'SERVICE_START_DRIVER_LOAD', 'DOS_LINK_CREATE',
    'SMOKE_TRAFFIC', 'DRIVER_UNLOAD', 'DOS_LINK_REMOVE', 'SERVICE_DELETE',
    'OWNED_CLEANUP'
)

# The closed native reason roster, in canonical order. `reasonCodes` is always
# the unique applicable subset in THIS order, so two attempts that observed the
# same facts serialize identically.
$script:ReasonRoster = @(
    'ELIGIBLE_CANDIDATE_MISSING', 'SOURCE_LEDGER_INVALID', 'CANDIDATE_MANIFEST_INVALID',
    'SOURCE_CONTRACT_VIOLATION',
    'ARTIFACT_MISSING', 'ARTIFACT_EXTRA', 'ARTIFACT_HASH_MISMATCH',
    'PACKAGE_SET_MISMATCH', 'ARTIFACT_SET_MISMATCH',
    'TOOL_MISSING', 'TOOL_HASH_MISMATCH',
    'PACKAGE_VERIFIER_TIMEOUT', 'PACKAGE_VERIFIER_START_FAILED',
    'PACKAGE_VERIFIER_CAPTURE_FAILED', 'PACKAGE_VERIFIER_FAILED',
    'OS_UNSUPPORTED', 'PROCESS_NOT_X64', 'NOT_ELEVATED',
    'CODE_INTEGRITY_NOT_READY', 'TEST_SIGNING_NOT_READY', 'REBOOT_PENDING',
    'PACKAGE_NOT_TRUST_READY', 'SERVICE_NAME_OCCUPIED', 'DOS_NAME_OCCUPIED',
    'PREFLIGHT_TIMEOUT', 'PREFLIGHT_START_FAILED', 'PREFLIGHT_CAPTURE_FAILED',
    'PREFLIGHT_OUTPUT_INVALID', 'PREFLIGHT_NOT_RUNNABLE',
    'PREFLIGHT_SIDECAR_DETECTED', 'PREFLIGHT_MUTATION_DETECTED',
    'AUTHORIZATION_MISSING', 'AUTHORIZATION_TUPLE_MISMATCH',
    'HOST_IDENTITY_DRIFT', 'BOOT_IDENTITY_DRIFT', 'SOURCE_IDENTITY_DRIFT',
    'CANDIDATE_IDENTITY_DRIFT', 'PROFILE_DRIFT', 'ARTIFACT_DRIFT',
    'LIVE_TIMEOUT', 'LIVE_START_FAILED', 'LIVE_CAPTURE_FAILED',
    'LIVE_OUTPUT_INVALID', 'LIVE_MUTATION_STATE_UNKNOWN',
    'LIVE_RECOVERY_CLEANUP_REFUSED', 'LIVE_RECOVERY_CLEANUP_FAILED',
    'LIVE_PREMUTATION_FAILURE', 'LIVE_WORKFLOW_FAILED'
)

$script:Phases = @(
    'ARTIFACT_INITIAL', 'PREFLIGHT_INITIAL', 'AUTHORIZATION',
    'ARTIFACT_FINAL', 'PREFLIGHT_FINAL', 'LIVE', 'COMPLETE'
)
$script:NotRunPhases = @(
    'ARTIFACT_INITIAL', 'PREFLIGHT_INITIAL', 'AUTHORIZATION',
    'ARTIFACT_FINAL', 'PREFLIGHT_FINAL', 'LIVE'
)
$script:NativeStatuses = @('PASS', 'FAIL', 'NOT_RUN')
$script:InspectionStates = @('PENDING_AUTHORIZATION', 'SEALED_FAIL', 'SEALED_NOT_RUN')

# The nine candidate artifact roles, in the order both the candidate manifest
# and the artifact check list them.
$script:ArtifactRoles = @(
    'inf', 'sys', 'cat', 'pdb', 'map', 'certificate', 'harness',
    'abiArchive', 'specArchive'
)
$script:PackageArtifactRoles = @('inf', 'sys', 'cat', 'pdb', 'map', 'certificate')
$script:LocalToolRoles = @('powershell', 'infverif', 'signtool')
$script:SourceInputRoles = @('candidate-manifest', 'native-runner', 'capture-helper', 'recorder')

$script:BootstrapKeys = @('schema', 'version', 'sourceCommit', 'sourceTree', 'files', 'powerShell')
$script:BootstrapFileKeys = @('role', 'relativePath', 'gitBlob', 'path', 'volumeSerial', 'fileId', 'bytes', 'sha256')
$script:BootstrapPowerShellKeys = @('path', 'volumeSerial', 'fileId', 'bytes', 'sha256')

$script:PendingInspectionKeys = @(
    'schema', 'version', 'attemptId', 'sourceAttemptId', 'sourceCommit', 'sourceTree',
    'candidateManifestSha256', 'artifactSetSha256', 'packageSetSha256',
    'hostIdentity', 'bootIdentity', 'ownedServiceName', 'ownedDosPattern',
    'authorizationOperations', 'runnable'
)
$script:InspectionResultKeys = @(
    'schema', 'version', 'attemptId', 'bootstrapSha256', 'state', 'runnable', 'inspectionSha256'
)
$script:AuthorizationKeys = @(
    'schema', 'version', 'attemptId', 'authorizedAtUtc', 'authorizationReference',
    'operations', 'hostIdentity', 'bootIdentity', 'sourceAttemptId', 'sourceCommit',
    'sourceTree', 'candidateManifestSha256', 'artifactSetSha256', 'packageSetSha256'
)
$script:AuthorizationResultKeys = @(
    'schema', 'version', 'attemptId', 'inspectionSha256', 'authorizationSha256'
)
$script:ArtifactCheckKeys = @(
    'schema', 'version', 'attemptId', 'phase', 'sourceAttemptId', 'sourceCommit',
    'sourceTree', 'candidateManifestSha256', 'hostIdentity', 'bootIdentity',
    'profile', 'expected', 'actual', 'sourceInputs', 'smokeDriver', 'tools',
    'packageVerifier', 'status', 'reasonCodes'
)
$script:SidecarKeys = @(
    'schema', 'version', 'attemptId', 'phase', 'status', 'truncated',
    'entryCountLowerBound', 'bytesLowerBound', 'entries'
)
$script:SidecarEntryKeys = @(
    'relativePath', 'kind', 'volumeSerial', 'fileId', 'linkCount', 'bytes',
    'sha256', 'contentBase64'
)
# Every nested object of the artifact check has its own closed key set. A root
# key check alone would let a field be dropped or renamed one level down --
# which is exactly where the recorder and Task 30's coordinator read from.
$script:ExpectedArtifactKeys = @('artifactSetSha256', 'packageSetSha256', 'files')
$script:ExpectedArtifactRowKeys = @('role', 'relativePath', 'bytes', 'sha256')
$script:ActualArtifactKeys = @('artifactSetSha256', 'packageSetSha256', 'files', 'extraPaths')
$script:ActualArtifactRowKeys = @('role', 'relativePath', 'present', 'bytes', 'sha256')
$script:SourceInputRowKeys = @(
    'role', 'relativePath', 'expectedSha256', 'present', 'path',
    'volumeSerial', 'fileId', 'bytes', 'sha256'
)
$script:SmokeDriverKeys = @(
    'relativePath', 'expectedBytes', 'expectedSha256', 'present', 'path',
    'volumeSerial', 'fileId', 'actualBytes', 'actualSha256'
)
$script:LocalToolRowKeys = @(
    'role', 'present', 'path', 'volumeSerial', 'fileId', 'bytes', 'sha256'
)
$script:PackageVerifierKeys = @(
    'issued', 'scriptRelativePath', 'scriptSha256', 'scriptVolumeSerial',
    'scriptFileId', 'toolRole', 'toolSha256', 'argv',
    'stdout', 'stdoutBytes', 'stdoutSha256',
    'stderr', 'stderrBytes', 'stderrSha256',
    'exit', 'exitBytes', 'exitSha256',
    'termination', 'observedExit', 'semanticStatus', 'signatureStatus', 'catalogStatus'
)
$script:CommandIssuedKeys = @('initialPreflight', 'finalPreflight', 'live')
$script:NotRunKeys = @(
    'schema', 'version', 'phase', 'reasonCodes', 'commandIssued', 'liveIssued', 'mutationAttempts'
)
$script:NativeAttemptKeys = @(
    'schema', 'version', 'attemptId', 'bootstrapSourceCommit', 'bootstrapSourceTree',
    'bootstrapSha256', 'sourceAttemptId', 'sourceCommit', 'sourceTree',
    'candidateManifestSha256', 'nativeReviewSha256', 'evidenceReviewSha256',
    'artifactSetSha256', 'packageSetSha256', 'hostIdentity', 'bootIdentity',
    'status', 'phase', 'reasonCodes', 'commandIssued', 'liveIssued',
    'mutationAttempts', 'attemptFilesSha256'
)
$script:HostIdentityKeys = @(
    'machineGuid', 'computerName', 'osBuild', 'architecture', 'processArchitecture'
)
$script:BootIdentityKeys = @('bootId', 'bootTimeUtc')
$script:CandidateIdentityKeys = @(
    'sourceAttemptId', 'sourceCommit', 'sourceTree', 'candidateManifestSha256',
    'nativeReviewSha256', 'evidenceReviewSha256', 'artifactSetSha256', 'packageSetSha256'
)

# Bounds for the preflight scratch scan. Even hostile or oversized output has
# exactly one bounded, sealable observation instead of an unknown file inside
# the immutable attempt.
$script:SidecarMaxEntries = 64
$script:SidecarMaxFileBytes = 1048576
$script:SidecarMaxAggregateBytes = 8388608

$script:EvidenceRootRelative = 'docs/superpowers/reviews/evidence/c4-recovery-logs'
$script:NativeRunnerRelativePath = 'driver/scripts/run_c4_native_attempt.ps1'
$script:CaptureHelperRelativePath = 'driver/scripts/invoke_c4_evidence.ps1'
$script:RecorderRelativePath = 'driver/scripts/record_c4_evidence.ps1'
$script:VerifierRelativePath = 'driver/scripts/verify_fsring_package.ps1'
$script:SmokeDriverRelativePath = 'driver/scripts/smoke_driver.ps1'
$script:CandidateName = 'candidate-artifacts.json'
$script:SourceIndexName = 'index.json'

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

function Get-C4NativeRepositoryRoot {
    $scripts = [IO.Path]::GetFullPath($PSScriptRoot)
    $driver = [IO.Path]::GetFullPath((Join-Path $scripts '..'))
    return [IO.Path]::GetFullPath((Join-Path $driver '..'))
}

function Assert-C4NativeHex {
    param([string]$Value, [int]$Length, [string]$Name)
    if ($null -eq $Value -or $Value -cnotmatch ('^[0-9a-f]{' + $Length + '}$')) {
        throw ("{0} must be exactly {1} lowercase hexadecimal characters" -f $Name, $Length)
    }
    return $Value
}

function Assert-C4NativeAttemptId {
    param([string]$Value)
    if ($null -eq $Value -or $Value -cnotmatch '^[0-9a-f]{32}$') {
        throw 'attempt ID must be a lowercase GUID-N (32 hexadecimal characters)'
    }
    return $Value
}

function Test-C4NativeReparse {
    param([string]$Path)
    try { $attrs = [IO.File]::GetAttributes($Path) } catch { return $false }
    return (($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Assert-C4NativeAbsolutePath {
    param([string]$Path, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw ("{0} is required" -f $Name) }
    if (-not [IO.Path]::IsPathRooted($Path)) { throw ("{0} must be absolute: {1}" -f $Name, $Path) }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -cne $Path) { throw ("{0} must be canonical: {1}" -f $Name, $Path) }
    if ($Path.Contains('..')) { throw ("{0} contains a relative segment: {1}" -f $Name, $Path) }
    return $full
}

function Assert-C4NativeExactKeys {
    param($Object, [string[]]$Keys, [string]$Name)
    if ($null -eq $Object) { throw ("{0} is absent" -f $Name) }
    $actual = @()
    if ($Object -is [Collections.IDictionary]) { $actual = @($Object.Keys) }
    else { $actual = @($Object.PSObject.Properties | ForEach-Object { $_.Name }) }
    if (@($actual).Count -ne @($Keys).Count) {
        throw ("{0} key count is {1}, expected {2}" -f $Name, @($actual).Count, @($Keys).Count)
    }
    for ($i = 0; $i -lt @($Keys).Count; $i++) {
        if ($actual[$i] -cne $Keys[$i]) {
            throw ("{0} key {1} is '{2}', expected '{3}'" -f $Name, $i, $actual[$i], $Keys[$i])
        }
    }
}

function Get-C4NativeCanonicalBytes {
    param($Value)
    $utf8 = New-Object System.Text.UTF8Encoding $false
    return $utf8.GetBytes((ConvertTo-C4CanonicalJsonText $Value) + "`n")
}

function Get-C4NativeSha256File {
    param([string]$Path)
    return (Get-C4EvidenceSha256Hex ([IO.File]::ReadAllBytes($Path)))
}

function Get-C4NativeZeroSha256 {
    return (Get-C4EvidenceSha256Hex (New-Object byte[] 0))
}

function Write-C4NativeStdoutLine {
    param([string]$Text)
    if ($null -eq $Text) { return }
    [Console]::Out.Write($Text + "`n")
    [Console]::Out.Flush()
}

function Write-C4NativeExclusiveBytes {
    param([string]$Path, [byte[]]$Bytes)
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

# Reasons are always emitted as the unique applicable subset in roster order.
# Sorting by observation order would make two attempts that saw the same facts
# serialize differently.
function Get-C4NativeOrderedReasons {
    param([string[]]$Reasons)
    $seen = New-Object System.Collections.Generic.HashSet[string]
    foreach ($reason in @($Reasons)) {
        if ([string]::IsNullOrWhiteSpace($reason)) { continue }
        if ($script:ReasonRoster -cnotcontains $reason) {
            throw ("illegal native reason code {0}" -f $reason)
        }
        [void]$seen.Add($reason)
    }
    $ordered = New-Object System.Collections.ArrayList
    foreach ($reason in $script:ReasonRoster) {
        if ($seen.Contains($reason)) { [void]$ordered.Add($reason) }
    }
    return @($ordered)
}

function New-C4NativeFileRowFromLease {
    param([string]$Role, $Lease)
    return [ordered]@{
        role = $Role
        present = $true
        path = $Lease.Path
        volumeSerial = $Lease.VolumeSerial
        fileId = $Lease.FileId
        bytes = [int64]$Lease.Length
        sha256 = $Lease.Sha256
    }
}

function New-C4NativeAbsentToolRow {
    param([string]$Role)
    return [ordered]@{
        role = $Role
        present = $false
        path = $null
        volumeSerial = $null
        fileId = $null
        bytes = $null
        sha256 = $null
    }
}

# ---------------------------------------------------------------------------
# Adapters
#
# One seam per external effect. Production reaches the real Git, the real host
# registry, and the real capture helper; the self-test substitutes fakes so no
# fixture can install a service, create a DOS name, or write a real evidence
# root. Everything the orchestrator itself decides runs identically on both
# sides.
# ---------------------------------------------------------------------------

# .NET Framework 4.x -- the runtime Windows PowerShell 5.1 runs on -- has no
# ProcessStartInfo argument collection, so the command line is built here by
# CommandLineToArgvW's own quoting rules: a run of backslashes is doubled only
# when a quote (or the closing quote) follows it.
function ConvertTo-C4NativeCommandLineArgument {
    param([string]$Value)
    if (-not [string]::IsNullOrEmpty($Value) -and
        $Value.IndexOfAny([char[]]@([char]32, [char]9, [char]34)) -lt 0) {
        return $Value
    }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append([char]34)
    $pendingSlashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]92) { $pendingSlashes += 1; continue }
        if ($character -eq [char]34) {
            [void]$builder.Append([char]92, ($pendingSlashes * 2) + 1)
            [void]$builder.Append([char]34)
        } else {
            [void]$builder.Append([char]92, $pendingSlashes)
            [void]$builder.Append($character)
        }
        $pendingSlashes = 0
    }
    [void]$builder.Append([char]92, $pendingSlashes * 2)
    [void]$builder.Append([char]34)
    return $builder.ToString()
}

function ConvertTo-C4NativeCommandLine {
    param([string[]]$Arguments)
    return ((@($Arguments) |
        ForEach-Object { ConvertTo-C4NativeCommandLineArgument ([string]$_) }) -join ' ')
}

function New-C4NativeProductionAdapters {
    param([string]$RepoRoot)
    return [pscustomobject]@{
        RepoRoot = $RepoRoot
        CaptureProcess = {
            param($Executable, $Arguments, $WorkingDirectory, $TimeoutMilliseconds,
                  $StdoutPath, $StderrPath, $ExitPath, $ExitFormat,
                  $ContainmentEvidencePath, $ContainmentRole, $ContainmentAttemptId)
            $splat = @{
                Executable = $Executable
                Arguments = @($Arguments)
                WorkingDirectory = $WorkingDirectory
                TimeoutMilliseconds = $TimeoutMilliseconds
                StdoutPath = $StdoutPath
                StderrPath = $StderrPath
                ExitPath = $ExitPath
                ExitFormat = $ExitFormat
            }
            if (-not [string]::IsNullOrWhiteSpace($ContainmentEvidencePath)) {
                $splat['ContainmentEvidencePath'] = $ContainmentEvidencePath
                $splat['ContainmentRole'] = $ContainmentRole
                $splat['ContainmentAttemptId'] = $ContainmentAttemptId
            }
            Invoke-C4EvidenceProcess @splat
        }
        Git = {
            param([string[]]$Arguments, [string]$WorkingDirectory)
            $psi = New-Object Diagnostics.ProcessStartInfo
            $psi.FileName = 'git'
            $psi.Arguments = ConvertTo-C4NativeCommandLine @($Arguments)
            $psi.WorkingDirectory = $WorkingDirectory
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false
            $process = [Diagnostics.Process]::Start($psi)
            $out = $process.StandardOutput.ReadToEnd()
            $err = $process.StandardError.ReadToEnd()
            $process.WaitForExit()
            return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $out; Stderr = $err }
        }
        HostIdentity = {
            $machineGuid = $null
            try {
                $machineGuid = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
            } catch {
                $machineGuid = $null
            }
            if ([string]::IsNullOrWhiteSpace($machineGuid)) { throw 'the host machine GUID is unavailable' }
            return [ordered]@{
                machineGuid = $machineGuid
                computerName = [string]$env:COMPUTERNAME
                osBuild = [string]([Environment]::OSVersion.Version.Build)
                architecture = [string]$env:PROCESSOR_ARCHITECTURE
                processArchitecture = $(if ([Environment]::Is64BitProcess) { 'AMD64' } else { 'X86' })
            }
        }
        BootIdentity = {
            $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
            $utc = ([datetime]$bootTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            # The boot identity must change across a reboot; a stable machine
            # GUID plus the boot instant is the pair that does.
            $bootId = (Get-C4EvidenceSha256Hex (
                (New-Object System.Text.UTF8Encoding $false).GetBytes(
                    [string]$env:COMPUTERNAME + '|' + $utc))).Substring(0, 32)
            return [ordered]@{ bootId = $bootId; bootTimeUtc = $utc }
        }
    }
}

function Invoke-C4NativeGit {
    param($Adapters, [string[]]$Arguments)
    return (& $Adapters.Git @($Arguments) $Adapters.RepoRoot)
}

function Invoke-C4NativeCapture {
    param($Adapters, [string]$Executable, [string[]]$Arguments, [string]$WorkingDirectory,
          [int]$TimeoutMilliseconds, [string]$StdoutPath, [string]$StderrPath, [string]$ExitPath,
          [string]$ExitFormat = 'CanonicalJson', [string]$ContainmentEvidencePath = '',
          [string]$ContainmentRole = '', [string]$ContainmentAttemptId = '')
    & $Adapters.CaptureProcess $Executable @($Arguments) $WorkingDirectory $TimeoutMilliseconds `
        $StdoutPath $StderrPath $ExitPath $ExitFormat `
        $ContainmentEvidencePath $ContainmentRole $ContainmentAttemptId
}

function Read-C4NativeCapturedExit {
    param([string]$ExitPath, [string]$ExitFormat = 'CanonicalJson')
    if ($ExitFormat -ceq 'CodeText') {
        $text = ([IO.File]::ReadAllText($ExitPath)).Trim()
        $termination = 'NORMAL'
        $observed = $null
        switch ($text) {
            'TIMEOUT' { $termination = 'TIMEOUT' }
            'START_FAILED' { $termination = 'START_FAILED' }
            'CAPTURE_FAILED' { $termination = 'CAPTURE_FAILED' }
            'NOT_ISSUED' { $termination = 'NOT_ISSUED' }
            default { $observed = [int]$text }
        }
        return [pscustomobject]@{ termination = $termination; observedExit = $observed; timedOut = ($termination -ceq 'TIMEOUT') }
    }
    return (ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($ExitPath)) `
        -ExpectedSchema $script:CapturedExitSchema)
}

# ---------------------------------------------------------------------------
# Bootstrap
#
# The pinned `B,BT` pair is the ONLY hash oracle. Current HEAD is used for one
# thing -- proving `B` is an ancestor and that nothing outside the evidence
# tree changed since -- and never to supply an expected value.
# ---------------------------------------------------------------------------

function Assert-C4NativeBootstrapAncestry {
    param($Adapters, [string]$Commit, [string]$Tree)

    $head = Invoke-C4NativeGit $Adapters @('rev-parse', 'HEAD')
    if ($head.ExitCode -ne 0) { throw 'current HEAD is unavailable' }
    $ancestor = Invoke-C4NativeGit $Adapters @('merge-base', '--is-ancestor', $Commit, $head.Stdout.Trim())
    if ($ancestor.ExitCode -ne 0) {
        throw 'the pinned bootstrap commit is not an ancestor of current HEAD'
    }
    $bootstrapTree = Invoke-C4NativeGit $Adapters @('rev-parse', ($Commit + '^{tree}'))
    if ($bootstrapTree.ExitCode -ne 0 -or $bootstrapTree.Stdout.Trim() -cne $Tree) {
        throw 'the pinned bootstrap tree does not belong to the pinned bootstrap commit'
    }
    $diff = Invoke-C4NativeGit $Adapters @('diff', '--name-only', $Commit, $head.Stdout.Trim())
    if ($diff.ExitCode -ne 0) { throw 'the bootstrap-to-HEAD diff is unavailable' }
    foreach ($line in $diff.Stdout.Split("`n")) {
        $path = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        if (-not $path.StartsWith('docs/superpowers/reviews/evidence/', [StringComparison]::Ordinal)) {
            throw ('a non-evidence path changed since the pinned bootstrap: ' + $path)
        }
    }
    return $head.Stdout.Trim()
}

function Get-C4NativeGitBlobId {
    param($Adapters, [string]$Tree, [string]$RelativePath)
    $result = Invoke-C4NativeGit $Adapters @('rev-parse', ($Tree + ':' + $RelativePath))
    if ($result.ExitCode -ne 0) {
        throw ('the pinned bootstrap tree carries no ' + $RelativePath)
    }
    return $result.Stdout.Trim()
}

function New-C4NativeBootstrap {
    param($Adapters, [string]$RepoRoot, [string]$Commit, [string]$Tree, $ExpectedHashes, $Leases)

    $rows = New-Object System.Collections.ArrayList
    $roleMap = [ordered]@{
        'native-runner' = $script:NativeRunnerRelativePath
        'capture-helper' = $script:CaptureHelperRelativePath
        'recorder' = $script:RecorderRelativePath
    }
    foreach ($role in @($roleMap.Keys)) {
        $relative = [string]$roleMap[$role]
        $blob = Get-C4NativeGitBlobId $Adapters $Tree $relative
        $lease = $Leases[$role]
        if ($lease.GitBlobId -cne $blob) {
            throw ($role + ' does not equal its pinned bootstrap blob')
        }
        if ($lease.Sha256 -cne [string]$ExpectedHashes[$role]) {
            throw ($role + ' does not equal its mandatory expected SHA-256')
        }
        [void]$rows.Add([ordered]@{
            role = $role
            relativePath = $relative
            gitBlob = $blob
            path = $lease.Path
            volumeSerial = $lease.VolumeSerial
            fileId = $lease.FileId
            bytes = [int64]$lease.Length
            sha256 = $lease.Sha256
        })
    }
    foreach ($row in @($rows)) {
        Assert-C4NativeExactKeys $row $script:BootstrapFileKeys 'bootstrap file row'
    }
    $powerShell = $Leases['powershell']
    $document = [ordered]@{
        schema = $script:BootstrapSchema
        version = 1
        sourceCommit = $Commit
        sourceTree = $Tree
        files = @($rows)
        powerShell = [ordered]@{
            path = $powerShell.Path
            volumeSerial = $powerShell.VolumeSerial
            fileId = $powerShell.FileId
            bytes = [int64]$powerShell.Length
            sha256 = $powerShell.Sha256
        }
    }
    Assert-C4NativeExactKeys $document $script:BootstrapKeys 'bootstrap.json'
    Assert-C4NativeExactKeys $document.powerShell $script:BootstrapPowerShellKeys 'bootstrap powerShell'
    return $document
}

# ---------------------------------------------------------------------------
# Candidate resolution
#
# Deliberately fallible. An absent pointer, an unparseable ledger, or an
# invalid candidate manifest is an in-attempt sealed NOT RUN observation, not a
# coordinator refusal: the whole point of the independent bootstrap above is
# that a broken candidate can still reach a trusted Inspect and be recorded.
# ---------------------------------------------------------------------------

function Resolve-C4NativeCandidate {
    param([string]$RepoRoot)

    $evidenceRoot = Join-Path $RepoRoot ($script:EvidenceRootRelative -replace '/', '\')
    $indexPath = Join-Path $evidenceRoot $script:SourceIndexName
    if (-not [IO.File]::Exists($indexPath)) {
        return [pscustomobject]@{ Resolved = $false; Reason = 'ELIGIBLE_CANDIDATE_MISSING'; Detail = 'no source ledger' }
    }
    $index = $null
    try {
        $index = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($indexPath)) `
            -ExpectedSchema $script:SourceIndexSchema
    } catch {
        return [pscustomobject]@{ Resolved = $false; Reason = 'SOURCE_LEDGER_INVALID'; Detail = $_.Exception.Message }
    }
    $eligible = $null
    try { $eligible = [string]$index.eligibleCandidateAttemptId } catch { $eligible = $null }
    if ([string]::IsNullOrWhiteSpace($eligible)) {
        return [pscustomobject]@{ Resolved = $false; Reason = 'ELIGIBLE_CANDIDATE_MISSING'; Detail = 'no eligible candidate is published' }
    }
    $row = $null
    foreach ($entry in @($index.attempts)) {
        if ([string]$entry.attemptId -ceq $eligible) { $row = $entry }
    }
    if ($null -eq $row) {
        return [pscustomobject]@{ Resolved = $false; Reason = 'SOURCE_LEDGER_INVALID'; Detail = 'the eligible pointer names no attempt row' }
    }
    if ([string]$row.gateStatus -cne 'PASS' -or [string]$row.reviewStatus -cne 'PASS' -or
        [string]$row.sourceVerdict -cne 'PASS') {
        return [pscustomobject]@{ Resolved = $false; Reason = 'SOURCE_LEDGER_INVALID'; Detail = 'the eligible row is not a reviewed PASS' }
    }
    $candidatePath = Join-Path $evidenceRoot $script:CandidateName
    if (-not [IO.File]::Exists($candidatePath)) {
        return [pscustomobject]@{ Resolved = $false; Reason = 'CANDIDATE_MANIFEST_INVALID'; Detail = 'the promoted candidate manifest is absent' }
    }
    $candidateBytes = [IO.File]::ReadAllBytes($candidatePath)
    if ((Get-C4EvidenceSha256Hex $candidateBytes) -cne [string]$row.candidateManifestSha256) {
        return [pscustomobject]@{ Resolved = $false; Reason = 'CANDIDATE_MANIFEST_INVALID'; Detail = 'the promoted candidate does not match the ledger hash' }
    }
    $candidate = $null
    try {
        $candidate = ConvertFrom-C4CanonicalJsonBytes -Bytes $candidateBytes -ExpectedSchema $script:CandidateSchema
    } catch {
        return [pscustomobject]@{ Resolved = $false; Reason = 'CANDIDATE_MANIFEST_INVALID'; Detail = $_.Exception.Message }
    }
    $attemptRelative = [string]$row.relativePath
    return [pscustomobject]@{
        Resolved = $true
        Reason = $null
        Detail = $null
        Row = $row
        Candidate = $candidate
        CandidateSha256 = (Get-C4EvidenceSha256Hex $candidateBytes)
        CandidatePath = $candidatePath
        AttemptDirectory = (Join-Path $evidenceRoot ($attemptRelative -replace '/', '\'))
        EvidenceRoot = $evidenceRoot
    }
}

# Row 01's captured stdout is the only source of an expected script hash. It is
# already bound to the exact `S,T` tree by the candidate's command index, so
# reading it here is not a current-bytes oracle.
function Read-C4NativeRow01SelfTestObject {
    param([string]$CandidateAttemptDirectory)

    $stdout = Join-Path $CandidateAttemptDirectory 'commands\01-source-runner-selftest.stdout.bin'
    $exit = Join-Path $CandidateAttemptDirectory 'commands\01-source-runner-selftest.exit.json'
    if (-not [IO.File]::Exists($stdout) -or -not [IO.File]::Exists($exit)) {
        throw 'the eligible attempt does not retain row 01'
    }
    $record = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($exit)) `
        -ExpectedSchema $script:CapturedExitSchema
    if ([string]$record.termination -cne 'NORMAL' -or [int]$record.observedExit -ne 0) {
        throw 'row 01 is not a NORMAL zero capture'
    }
    $utf8 = New-Object System.Text.UTF8Encoding $false
    $text = $utf8.GetString([IO.File]::ReadAllBytes($stdout))
    $object = $null
    foreach ($line in $text.Split("`n")) {
        $trimmed = $line.TrimEnd("`r")
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed.StartsWith('FSRING-C4-NESTED-TOOLS ', [StringComparison]::Ordinal)) { continue }
        $object = $trimmed | ConvertFrom-Json
    }
    if ($null -eq $object -or $object.schema -cne $script:SourceRunnerSelfTestSchema) {
        throw 'row 01 does not carry one source-runner self-test object'
    }
    if ([string]$object.status -cne 'PASS') {
        throw 'row 01 did not report a self-test PASS'
    }
    return $object
}

# ---------------------------------------------------------------------------
# Local tool identity
#
# These are R7-host observations, deliberately NOT compared with the source
# build host: an InfVerif on this machine has no reason to be the same file
# that ran at Task 29. What they must be is present, leased, and identical
# between INITIAL and FINAL.
# ---------------------------------------------------------------------------

function Open-C4NativeLocalToolLeases {
    param($Overrides)

    $paths = [ordered]@{
        powershell = (Join-Path $PSHOME 'powershell.exe')
        infverif = 'C:\Program Files (x86)\Windows Kits\10\Tools\10.0.26100.0\x64\infverif.exe'
        signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe'
    }
    if ($null -ne $Overrides) {
        foreach ($role in $script:LocalToolRoles) {
            if ($Overrides.Contains($role)) { $paths[$role] = [string]$Overrides[$role] }
        }
    }
    $leases = [ordered]@{}
    foreach ($role in $script:LocalToolRoles) {
        $path = [string]$paths[$role]
        $leases[$role] = $null
        if ([string]::IsNullOrWhiteSpace($path) -or -not [IO.File]::Exists($path)) { continue }
        if (Test-C4NativeReparse $path) { continue }
        try {
            $leases[$role] = Open-C4HeldFileLease -Path ([IO.Path]::GetFullPath($path)) `
                -ExpectedSha256 (Get-C4NativeSha256File $path)
        } catch {
            $leases[$role] = $null
        }
    }
    return $leases
}

function Close-C4NativeLeaseMap {
    param($Leases)
    if ($null -eq $Leases) { return }
    foreach ($role in @($Leases.Keys)) {
        if ($null -ne $Leases[$role]) { Close-C4HeldFileLease $Leases[$role] }
    }
}

# ---------------------------------------------------------------------------
# The artifact check
#
# `expected` is copied from the candidate; `actual` is measured from the
# retained or staged bytes. Missing and extra bytes are representable without
# inventing zero-byte rows, and every unavailable set hash stays null rather
# than being computed from an incomplete member list.
# ---------------------------------------------------------------------------

function Get-C4NativeArtifactSourcePath {
    param($Context, [string]$Role, [string]$CandidateRelativePath)

    if ($script:PackageArtifactRoles -contains $Role) {
        $name = $CandidateRelativePath.Substring($CandidateRelativePath.LastIndexOf('/') + 1)
        if (-not [string]::IsNullOrWhiteSpace($Context.PackageDirectory)) {
            return (Join-Path $Context.PackageDirectory $name)
        }
        return (Join-Path $Context.CandidateAttemptDirectory ($CandidateRelativePath -replace '/', '\'))
    }
    if ($Role -ceq 'harness' -and -not [string]::IsNullOrWhiteSpace($Context.HarnessPath)) {
        return $Context.HarnessPath
    }
    return (Join-Path $Context.CandidateAttemptDirectory ($CandidateRelativePath -replace '/', '\'))
}

function New-C4NativeExpectedArtifacts {
    param($Candidate)

    $rows = New-Object System.Collections.ArrayList
    foreach ($role in $script:ArtifactRoles) {
        $row = $Candidate.artifacts.$role
        [void]$rows.Add([ordered]@{
            role = $role
            relativePath = [string]$row.relativePath
            bytes = [int64]$row.bytes
            sha256 = [string]$row.sha256
        })
    }
    return [ordered]@{
        artifactSetSha256 = [string]$Candidate.artifactSetSha256
        packageSetSha256 = [string]$Candidate.artifacts.package.setSha256
        files = @($rows)
    }
}

function New-C4NativeActualArtifacts {
    param($Context, $Expected, [ref]$Reasons, [ref]$Leases)

    $rows = New-Object System.Collections.ArrayList
    $extra = New-Object System.Collections.ArrayList
    $allPresent = $true
    foreach ($expectedRow in @($Expected.files)) {
        $role = [string]$expectedRow.role
        $relative = [string]$expectedRow.relativePath
        $source = Get-C4NativeArtifactSourcePath $Context $role $relative
        $present = (-not [string]::IsNullOrWhiteSpace($source)) -and [IO.File]::Exists($source) -and
            (-not (Test-C4NativeReparse $source))
        $bytes = $null
        $sha = $null
        if ($present) {
            try {
                $lease = Open-C4HeldFileLease -Path ([IO.Path]::GetFullPath($source)) `
                    -ExpectedSha256 (Get-C4NativeSha256File $source)
                $Leases.Value[$role] = $lease
                $bytes = [int64]$lease.Length
                $sha = $lease.Sha256
            } catch {
                $present = $false
            }
        }
        if (-not $present) {
            $allPresent = $false
            $Reasons.Value += 'ARTIFACT_MISSING'
        } elseif ($sha -cne [string]$expectedRow.sha256 -or [int64]$bytes -ne [int64]$expectedRow.bytes) {
            $Reasons.Value += 'ARTIFACT_HASH_MISMATCH'
        }
        [void]$rows.Add([ordered]@{
            role = $role
            relativePath = $relative
            present = [bool]$present
            bytes = $bytes
            sha256 = $sha
        })
    }

    # An unexpected package member is representable without inventing a file:
    # the roster is closed, so anything else in that directory is extra.
    if (-not [string]::IsNullOrWhiteSpace($Context.PackageDirectory) -and
        [IO.Directory]::Exists($Context.PackageDirectory)) {
        $expectedNames = @(@($Expected.files) |
            Where-Object { $script:PackageArtifactRoles -contains [string]$_.role } |
            ForEach-Object { ([string]$_.relativePath).Substring(([string]$_.relativePath).LastIndexOf('/') + 1) })
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($Context.PackageDirectory)) {
            $name = [IO.Path]::GetFileName($entry)
            if ($expectedNames -ccontains $name) { continue }
            [void]$extra.Add($name)
        }
    }
    if (@($extra).Count -ne 0) { $Reasons.Value += 'ARTIFACT_EXTRA' }

    $packageSet = $null
    $artifactSet = $null
    if ($allPresent -and @($extra).Count -eq 0) {
        $memberRows = New-Object System.Collections.ArrayList
        foreach ($role in $script:PackageArtifactRoles) {
            $row = @($rows) | Where-Object { [string]$_.role -ceq $role }
            [void]$memberRows.Add([ordered]@{
                relativePath = [string]$row.relativePath
                bytes = [int64]$row.bytes
                sha256 = [string]$row.sha256
            })
        }
        $packageSet = Get-C4EvidenceSha256Hex (Get-C4NativeCanonicalBytes ([ordered]@{
            schema = 'fsring-c4-package-set/v1'
            version = 1
            members = @($memberRows)
        }))
        if ($packageSet -cne [string]$Expected.packageSetSha256) {
            $Reasons.Value += 'PACKAGE_SET_MISMATCH'
        }
        $artifacts = [ordered]@{
            package = [ordered]@{
                relativePath = 'artifacts/win10-x64-release/package'
                setSha256 = $packageSet
                members = @($memberRows)
            }
        }
        foreach ($role in $script:ArtifactRoles) {
            $row = @($rows) | Where-Object { [string]$_.role -ceq $role }
            $artifacts[$role] = [ordered]@{
                relativePath = [string]$row.relativePath
                bytes = [int64]$row.bytes
                sha256 = [string]$row.sha256
            }
        }
        $artifactSet = Get-C4EvidenceSha256Hex (Get-C4NativeCanonicalBytes $artifacts)
        if ($artifactSet -cne [string]$Expected.artifactSetSha256) {
            $Reasons.Value += 'ARTIFACT_SET_MISMATCH'
        }
    }
    return [ordered]@{
        artifactSetSha256 = $artifactSet
        packageSetSha256 = $packageSet
        files = @($rows)
        extraPaths = @(@($extra) | Sort-Object -CaseSensitive)
    }
}

function New-C4NativeSourceInputRows {
    param($Context, $ExpectedHashes, [ref]$Reasons)

    $rows = New-Object System.Collections.ArrayList
    $paths = [ordered]@{
        'candidate-manifest' = $Context.CandidatePath
        'native-runner' = (Join-Path $Context.RepoRoot ($script:NativeRunnerRelativePath -replace '/', '\'))
        'capture-helper' = (Join-Path $Context.RepoRoot ($script:CaptureHelperRelativePath -replace '/', '\'))
        'recorder' = (Join-Path $Context.RepoRoot ($script:RecorderRelativePath -replace '/', '\'))
    }
    $relatives = [ordered]@{
        'candidate-manifest' = ($script:EvidenceRootRelative + '/' + $script:CandidateName)
        'native-runner' = $script:NativeRunnerRelativePath
        'capture-helper' = $script:CaptureHelperRelativePath
        'recorder' = $script:RecorderRelativePath
    }
    foreach ($role in $script:SourceInputRoles) {
        $path = [string]$paths[$role]
        $expected = [string]$ExpectedHashes[$role]
        $present = (-not [string]::IsNullOrWhiteSpace($path)) -and [IO.File]::Exists($path) -and
            (-not (Test-C4NativeReparse $path))
        $row = [ordered]@{
            role = $role
            relativePath = [string]$relatives[$role]
            expectedSha256 = $expected
            present = [bool]$present
            path = $null
            volumeSerial = $null
            fileId = $null
            bytes = $null
            sha256 = $null
        }
        if ($present) {
            $lease = $null
            try {
                $lease = Open-C4HeldFileLease -Path ([IO.Path]::GetFullPath($path)) `
                    -ExpectedSha256 (Get-C4NativeSha256File $path)
            } catch {
                $lease = $null
            }
            if ($null -eq $lease) {
                $row['present'] = $false
                $present = $false
            } else {
                try {
                    $row['path'] = $lease.Path
                    $row['volumeSerial'] = $lease.VolumeSerial
                    $row['fileId'] = $lease.FileId
                    $row['bytes'] = [int64]$lease.Length
                    $row['sha256'] = $lease.Sha256
                } finally {
                    Close-C4HeldFileLease $lease
                }
            }
        }
        if (-not $present -or [string]$row['sha256'] -cne $expected) {
            if ($role -ceq 'candidate-manifest') { $Reasons.Value += 'CANDIDATE_IDENTITY_DRIFT' }
            else { $Reasons.Value += 'SOURCE_IDENTITY_DRIFT' }
        }
        [void]$rows.Add($row)
    }
    return @($rows)
}

function New-C4NativeSmokeDriverRow {
    param($Context, $Candidate, [ref]$Reasons)

    $relative = [string]$Candidate.smokeDriver.relativePath
    $path = Join-Path $Context.RepoRoot ($relative -replace '/', '\')
    $present = [IO.File]::Exists($path) -and (-not (Test-C4NativeReparse $path))
    $row = [ordered]@{
        relativePath = $relative
        expectedBytes = [int64]$Candidate.smokeDriver.bytes
        expectedSha256 = [string]$Candidate.smokeDriver.sha256
        present = [bool]$present
        path = $null
        volumeSerial = $null
        fileId = $null
        actualBytes = $null
        actualSha256 = $null
    }
    if ($present) {
        $lease = Open-C4HeldFileLease -Path ([IO.Path]::GetFullPath($path)) -ExpectedSha256 (Get-C4NativeSha256File $path)
        try {
            $row['path'] = $lease.Path
            $row['volumeSerial'] = $lease.VolumeSerial
            $row['fileId'] = $lease.FileId
            $row['actualBytes'] = [int64]$lease.Length
            $row['actualSha256'] = $lease.Sha256
        } finally {
            Close-C4HeldFileLease $lease
        }
    }
    if (-not $present -or [string]$row['actualSha256'] -cne [string]$row['expectedSha256']) {
        $Reasons.Value += 'SOURCE_IDENTITY_DRIFT'
    }
    return $row
}

# ---------------------------------------------------------------------------
# The package verifier
#
# Not an opaque subprocess: the exact argv, the three retained streams, the
# termination, and the three parsed semantic statuses all become evidence. An
# environment-dependent stdout hash is deliberately NOT compared with Task 29's
# -- this is the R7 observation, not a replay.
# ---------------------------------------------------------------------------

function New-C4NativeNotIssuedVerifierRow {
    param($Context, [string]$Phase, $ScriptRow, $ToolRow, [string]$Reason, [ref]$Reasons)

    $stem = 'package-verifier-' + $Phase.ToLowerInvariant()
    $zero = Get-C4NativeZeroSha256
    $exitPath = Join-Path $Context.AttemptRoot ($stem + '.exit.txt')
    $utf8 = New-Object System.Text.UTF8Encoding $false
    $exitBytes = $utf8.GetBytes("NOT_ISSUED`n")
    foreach ($pair in @(@(($stem + '.stdout.bin'), (New-Object byte[] 0)), @(($stem + '.stderr.bin'), (New-Object byte[] 0)))) {
        $path = Join-Path $Context.AttemptRoot $pair[0]
        if (-not [IO.File]::Exists($path)) { Write-C4NativeExclusiveBytes $path $pair[1] }
    }
    if (-not [IO.File]::Exists($exitPath)) { Write-C4NativeExclusiveBytes $exitPath $exitBytes }
    if (-not [string]::IsNullOrWhiteSpace($Reason)) { $Reasons.Value += $Reason }
    return [ordered]@{
        issued = $false
        scriptRelativePath = $script:VerifierRelativePath
        scriptSha256 = $ScriptRow.Sha256
        scriptVolumeSerial = $ScriptRow.VolumeSerial
        scriptFileId = $ScriptRow.FileId
        toolRole = 'powershell'
        toolSha256 = $ToolRow
        argv = $null
        stdout = ($stem + '.stdout.bin')
        stdoutBytes = [int64]0
        stdoutSha256 = $zero
        stderr = ($stem + '.stderr.bin')
        stderrBytes = [int64]0
        stderrSha256 = $zero
        exit = ($stem + '.exit.txt')
        exitBytes = [int64]$exitBytes.Length
        exitSha256 = (Get-C4EvidenceSha256Hex $exitBytes)
        termination = 'NOT_ISSUED'
        observedExit = $null
        semanticStatus = $null
        signatureStatus = $null
        catalogStatus = $null
    }
}

# verify_fsring_package.ps1 emits exactly schema/overall/errors/warnings/
# trustReady/artifacts/tools -- it has never emitted semanticStatus,
# signatureStatus or catalogStatus. `trustReady` is a host trust property the
# preflight owns (PACKAGE_NOT_TRUST_READY); what this phase decides is whether
# the signature and catalog evidence themselves are intact, using the same
# closed states smoke_driver.ps1 accepts.
function Get-C4NativeVerifierSemantics {
    param($Parsed)
    $semantic = $null
    $signature = $null
    $catalog = $null
    if ($null -eq $Parsed) {
        return [pscustomobject]@{ Semantic = $null; Signature = $null; Catalog = $null }
    }
    $rootNames = @($Parsed.PSObject.Properties.Name)
    if ($rootNames -contains 'overall' -and [string]$Parsed.overall -cmatch '^(PASS|FAIL)$') {
        $semantic = [string]$Parsed.overall
    }
    $signtool = $null
    $membership = $null
    if ($rootNames -contains 'tools' -and $null -ne $Parsed.tools) {
        $toolNames = @($Parsed.tools.PSObject.Properties.Name)
        if ($toolNames -contains 'signtool') { $signtool = $Parsed.tools.signtool }
        if ($toolNames -contains 'catalogMembership') { $membership = $Parsed.tools.catalogMembership }
    }
    if ($null -ne $signtool) {
        $signature = 'FAIL'
        $signtoolNames = @($signtool.PSObject.Properties.Name)
        $complete = $true
        foreach ($required in @('policy', 'sysExitCode', 'sysMode', 'catExitCode',
                                'catMode', 'catalogMemberExitCode', 'catalogMemberMode')) {
            if ($signtoolNames -notcontains $required) { $complete = $false }
        }
        if ($complete -and [string]$signtool.policy -ceq 'KernelMode') {
            $modes = @([string]$signtool.sysMode, [string]$signtool.catMode,
                       [string]$signtool.catalogMemberMode)
            $exits = @([int64]$signtool.sysExitCode, [int64]$signtool.catExitCode,
                       [int64]$signtool.catalogMemberExitCode)
            $trusted = (@($modes | Where-Object { $_ -ceq 'Trusted' }).Count -eq 3 -and
                        @($exits | Where-Object { $_ -eq 0 }).Count -eq 3)
            $untrusted = (@($modes | Where-Object { $_ -ceq 'UntrustedTestRoot' }).Count -eq 3 -and
                          @($exits | Where-Object { $_ -eq 1 }).Count -eq 3)
            # The third closed state: the signer chains to a locally installed
            # test root, so /kp's only remaining objection is that the root is
            # not a Microsoft one. Signature evidence is intact; whether the
            # host may load it stays the preflight's trustReady decision.
            $locallyTrusted = (@($modes | Where-Object { $_ -ceq 'TestSignedLocallyTrusted' }).Count -eq 3 -and
                               @($exits | Where-Object { $_ -eq 1 }).Count -eq 3)
            if ($trusted -or $untrusted -or $locallyTrusted) { $signature = 'PASS' }
        }
    }
    if ($null -ne $membership) {
        $catalog = 'FAIL'
        $membershipNames = @($membership.PSObject.Properties.Name)
        if ($membershipNames -contains 'mechanism' -and $membershipNames -contains 'valid' -and
            $membershipNames -contains 'memberHash' -and
            [string]$membership.mechanism -ceq 'Windows CryptCAT member-hash' -and
            $membership.valid -is [bool] -and [bool]$membership.valid -and
            [string]$membership.memberHash -cmatch '^[0-9A-F]{64}$') {
            $catalog = 'PASS'
        }
    }
    return [pscustomobject]@{ Semantic = $semantic; Signature = $signature; Catalog = $catalog }
}

function Invoke-C4NativePackageVerifier {
    param($Context, [string]$Phase, $PowerShellLease, $InfVerifLease, $SignToolLease, [ref]$Reasons)

    $stem = 'package-verifier-' + $Phase.ToLowerInvariant()
    $verifierPath = Join-Path $Context.RepoRoot ($script:VerifierRelativePath -replace '/', '\')
    $scriptRow = [pscustomobject]@{ Sha256 = $null; VolumeSerial = $null; FileId = $null }
    if (-not [IO.File]::Exists($verifierPath) -or (Test-C4NativeReparse $verifierPath)) {
        return (New-C4NativeNotIssuedVerifierRow $Context $Phase $scriptRow $null 'SOURCE_IDENTITY_DRIFT' $Reasons)
    }
    $verifierLease = Open-C4HeldFileLease -Path ([IO.Path]::GetFullPath($verifierPath)) `
        -ExpectedSha256 (Get-C4NativeSha256File $verifierPath)
    try {
        $scriptRow = [pscustomobject]@{
            Sha256 = $verifierLease.Sha256
            VolumeSerial = $verifierLease.VolumeSerial
            FileId = $verifierLease.FileId
        }
        if ($verifierLease.Sha256 -cne [string]$Context.ExpectedVerifierSha256) {
            return (New-C4NativeNotIssuedVerifierRow $Context $Phase $scriptRow $null 'SOURCE_IDENTITY_DRIFT' $Reasons)
        }
        if ($null -eq $PowerShellLease -or $null -eq $InfVerifLease -or $null -eq $SignToolLease) {
            return (New-C4NativeNotIssuedVerifierRow $Context $Phase $scriptRow $null $null $Reasons)
        }
        if ([string]::IsNullOrWhiteSpace($Context.PackageDirectoryForVerifier) -or
            -not [IO.Directory]::Exists($Context.PackageDirectoryForVerifier)) {
            return (New-C4NativeNotIssuedVerifierRow $Context $Phase $scriptRow $PowerShellLease.Sha256 $null $Reasons)
        }

        $argv = @(
            $PowerShellLease.Path, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $verifierLease.Path,
            '-PackageDirectory', $Context.PackageDirectoryForVerifier,
            '-InfVerifPath', $InfVerifLease.Path,
            '-SignToolPath', $SignToolLease.Path
        )
        $stdoutPath = Join-Path $Context.AttemptRoot ($stem + '.stdout.bin')
        $stderrPath = Join-Path $Context.AttemptRoot ($stem + '.stderr.bin')
        $exitPath = Join-Path $Context.AttemptRoot ($stem + '.exit.txt')
        Assert-C4HeldFileLease $InfVerifLease
        Assert-C4HeldFileLease $SignToolLease
        Invoke-C4NativeCapture $Context.Adapters $argv[0] (@($argv)[1..($argv.Count - 1)]) `
            $Context.RepoRoot 1800000 $stdoutPath $stderrPath $exitPath 'CodeText'
        Assert-C4HeldFileLease $verifierLease
        Assert-C4HeldFileLease $InfVerifLease
        Assert-C4HeldFileLease $SignToolLease

        $record = Read-C4NativeCapturedExit $exitPath 'CodeText'
        $stdoutBytes = [IO.File]::ReadAllBytes($stdoutPath)
        $stderrBytes = [IO.File]::ReadAllBytes($stderrPath)
        $exitBytes = [IO.File]::ReadAllBytes($exitPath)
        $semantic = $null
        $signature = $null
        $catalog = $null
        switch ([string]$record.termination) {
            'TIMEOUT' { $Reasons.Value += 'PACKAGE_VERIFIER_TIMEOUT' }
            'START_FAILED' { $Reasons.Value += 'PACKAGE_VERIFIER_START_FAILED' }
            'CAPTURE_FAILED' { $Reasons.Value += 'PACKAGE_VERIFIER_CAPTURE_FAILED' }
            'NORMAL' {
                $parsed = $null
                try {
                    $utf8 = New-Object System.Text.UTF8Encoding $false
                    $parsed = ($utf8.GetString($stdoutBytes)).Trim() | ConvertFrom-Json
                } catch {
                    $parsed = $null
                }
                if ([int]$record.observedExit -ne 0 -or $null -eq $parsed -or
                    $parsed.schema -cne 'fsring-package-verifier/v1') {
                    $Reasons.Value += 'PACKAGE_VERIFIER_FAILED'
                } else {
                    $semantics = Get-C4NativeVerifierSemantics $parsed
                    $semantic = $semantics.Semantic
                    $signature = $semantics.Signature
                    $catalog = $semantics.Catalog
                    if ([string]$semantic -cne 'PASS' -or [string]$signature -cne 'PASS' -or
                        [string]$catalog -cne 'PASS') {
                        $Reasons.Value += 'PACKAGE_VERIFIER_FAILED'
                    }
                }
            }
            default { $Reasons.Value += 'PACKAGE_VERIFIER_FAILED' }
        }
        return [ordered]@{
            issued = $true
            scriptRelativePath = $script:VerifierRelativePath
            scriptSha256 = $verifierLease.Sha256
            scriptVolumeSerial = $verifierLease.VolumeSerial
            scriptFileId = $verifierLease.FileId
            toolRole = 'powershell'
            toolSha256 = $PowerShellLease.Sha256
            argv = @($argv)
            stdout = ($stem + '.stdout.bin')
            stdoutBytes = [int64]$stdoutBytes.Length
            stdoutSha256 = (Get-C4EvidenceSha256Hex $stdoutBytes)
            stderr = ($stem + '.stderr.bin')
            stderrBytes = [int64]$stderrBytes.Length
            stderrSha256 = (Get-C4EvidenceSha256Hex $stderrBytes)
            exit = ($stem + '.exit.txt')
            exitBytes = [int64]$exitBytes.Length
            exitSha256 = (Get-C4EvidenceSha256Hex $exitBytes)
            termination = [string]$record.termination
            observedExit = $(if ([string]$record.termination -ceq 'NORMAL') { [int]$record.observedExit } else { $null })
            semanticStatus = $semantic
            signatureStatus = $signature
            catalogStatus = $catalog
        }
    } finally {
        Close-C4HeldFileLease $verifierLease
    }
}

function New-C4NativeArtifactCheck {
    param($Context, [string]$Phase, $ToolLeases, [ref]$ArtifactLeases)

    $reasons = @()
    $reasonRef = [ref]$reasons
    $candidate = $Context.Candidate

    $toolRows = New-Object System.Collections.ArrayList
    foreach ($role in $script:LocalToolRoles) {
        $lease = $ToolLeases[$role]
        if ($null -eq $lease) {
            $reasons += 'TOOL_MISSING'
            [void]$toolRows.Add((New-C4NativeAbsentToolRow $role))
        } else {
            [void]$toolRows.Add((New-C4NativeFileRowFromLease $role $lease))
        }
    }

    if ($null -eq $candidate) {
        # No eligible tuple resolved: every candidate-bound field is null
        # together, which is the one legal all-null cross-product.
        $reasons += [string]$Context.CandidateFailureReason
        return [ordered]@{
            schema = $script:ArtifactCheckSchema
            version = 1
            attemptId = $Context.AttemptId
            phase = $Phase
            sourceAttemptId = $null
            sourceCommit = $null
            sourceTree = $null
            candidateManifestSha256 = $null
            hostIdentity = $Context.HostIdentity
            bootIdentity = $Context.BootIdentity
            profile = $null
            expected = $null
            actual = $null
            sourceInputs = $null
            smokeDriver = $null
            tools = @($toolRows)
            packageVerifier = $null
            status = 'FAIL'
            reasonCodes = (Get-C4NativeOrderedReasons $reasons)
        }
    }

    $expected = New-C4NativeExpectedArtifacts $candidate
    $actual = New-C4NativeActualArtifacts $Context $expected $reasonRef $ArtifactLeases
    $reasons = $reasonRef.Value
    $sourceInputs = New-C4NativeSourceInputRows $Context $Context.ExpectedSourceInputHashes $reasonRef
    $reasons = $reasonRef.Value
    $smokeDriver = New-C4NativeSmokeDriverRow $Context $candidate $reasonRef
    $reasons = $reasonRef.Value

    if ([string]$candidate.profile.id -cne 'win10-x64-release' -or
        [string]$candidate.profile.target -cne 'x86_64-pc-windows-msvc' -or
        [string]$candidate.profile.machine -cne '0x8664') {
        $reasons += 'PROFILE_DRIFT'
    }

    $verifier = Invoke-C4NativePackageVerifier $Context $Phase `
        $ToolLeases['powershell'] $ToolLeases['infverif'] $ToolLeases['signtool'] $reasonRef
    $reasons = $reasonRef.Value

    $status = 'PASS'
    if (@($reasons).Count -ne 0) { $status = 'FAIL' }
    $document = [ordered]@{
        schema = $script:ArtifactCheckSchema
        version = 1
        attemptId = $Context.AttemptId
        phase = $Phase
        sourceAttemptId = [string]$candidate.attemptId
        sourceCommit = [string]$candidate.sourceCommit
        sourceTree = [string]$candidate.sourceTree
        candidateManifestSha256 = [string]$Context.CandidateSha256
        hostIdentity = $Context.HostIdentity
        bootIdentity = $Context.BootIdentity
        profile = $candidate.profile
        expected = $expected
        actual = $actual
        sourceInputs = @($sourceInputs)
        smokeDriver = $smokeDriver
        tools = @($toolRows)
        packageVerifier = $verifier
        status = $status
        reasonCodes = (Get-C4NativeOrderedReasons $reasons)
    }
    Assert-C4NativeExactKeys $document $script:ArtifactCheckKeys ('artifact-' + $Phase.ToLowerInvariant() + '.json')
    Assert-C4NativeExactKeys $document.expected $script:ExpectedArtifactKeys 'artifact expected'
    Assert-C4NativeExactKeys $document.actual $script:ActualArtifactKeys 'artifact actual'
    foreach ($row in @($document.expected.files)) {
        Assert-C4NativeExactKeys $row $script:ExpectedArtifactRowKeys 'expected artifact row'
    }
    foreach ($row in @($document.actual.files)) {
        Assert-C4NativeExactKeys $row $script:ActualArtifactRowKeys 'actual artifact row'
    }
    foreach ($row in @($document.sourceInputs)) {
        Assert-C4NativeExactKeys $row $script:SourceInputRowKeys 'source-input row'
    }
    Assert-C4NativeExactKeys $document.smokeDriver $script:SmokeDriverKeys 'smokeDriver row'
    foreach ($row in @($document.tools)) {
        Assert-C4NativeExactKeys $row $script:LocalToolRowKeys 'local tool row'
    }
    Assert-C4NativeExactKeys $document.packageVerifier $script:PackageVerifierKeys 'packageVerifier'
    return $document
}

# ---------------------------------------------------------------------------
# The bounded preflight scratch scan
#
# A conforming preflight emits no script-owned sidecar, so the expected
# observation is EMPTY. Anything else is a source-contract violation -- but it
# still has to be RECORDED, bounded, without following a reparse point and
# without copying an oversized or hostile object into the immutable attempt.
# ---------------------------------------------------------------------------

function New-C4NativePreflightSidecars {
    param([string]$AttemptId, [string]$Phase, [string]$ScratchDirectory)

    $entries = New-Object System.Collections.ArrayList
    $status = 'EMPTY'
    $truncated = $false
    $countLowerBound = 0
    $bytesLowerBound = [int64]0
    $aggregate = [int64]0

    $found = New-Object System.Collections.ArrayList
    if ([IO.Directory]::Exists($ScratchDirectory)) {
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($ScratchDirectory, '*', [IO.SearchOption]::AllDirectories)) {
            [void]$found.Add($entry)
        }
    }
    $prefix = $ScratchDirectory.TrimEnd('\') + '\'
    $ordered = @(@($found) | Sort-Object -CaseSensitive)
    foreach ($full in $ordered) {
        $countLowerBound += 1
        if (@($entries).Count -ge $script:SidecarMaxEntries) {
            $status = 'OVERFLOW'
            $truncated = $true
            continue
        }
        $relative = ([string]$full).Substring($prefix.Length).Replace('\', '/')
        $kind = 'OTHER'
        $volumeSerial = $null
        $fileId = $null
        $linkCount = $null
        $bytes = $null
        $sha = $null
        $content = $null
        if (Test-C4NativeReparse $full) {
            $kind = 'REPARSE'
            if ($status -ceq 'EMPTY' -or $status -ceq 'CAPTURED') { $status = 'UNSAFE' }
        } elseif ([IO.Directory]::Exists($full)) {
            $kind = 'DIRECTORY'
            if ($status -ceq 'EMPTY' -or $status -ceq 'CAPTURED') { $status = 'UNSAFE' }
        } elseif ([IO.File]::Exists($full)) {
            $kind = 'FILE'
            $lease = $null
            try {
                $lease = Open-C4HeldFileLease -Path ([IO.Path]::GetFullPath($full)) `
                    -ExpectedSha256 (Get-C4NativeSha256File $full)
            } catch {
                $lease = $null
            }
            if ($null -eq $lease) {
                if ($status -ceq 'EMPTY' -or $status -ceq 'CAPTURED') { $status = 'UNSAFE' }
            } else {
                try {
                    $volumeSerial = $lease.VolumeSerial
                    $fileId = $lease.FileId
                    $linkCount = [int]$lease.NumberOfLinks
                    $bytes = [int64]$lease.Length
                    if ($linkCount -ne 1) {
                        if ($status -ceq 'EMPTY' -or $status -ceq 'CAPTURED') { $status = 'UNSAFE' }
                    } elseif ($bytes -gt $script:SidecarMaxFileBytes -or
                              ($aggregate + $bytes) -gt $script:SidecarMaxAggregateBytes) {
                        $status = 'OVERFLOW'
                        $truncated = $true
                    } else {
                        $raw = [IO.File]::ReadAllBytes($full)
                        $sha = Get-C4EvidenceSha256Hex $raw
                        if ($sha -cne $lease.Sha256) {
                            if ($status -ceq 'EMPTY' -or $status -ceq 'CAPTURED') { $status = 'UNSAFE' }
                            $sha = $null
                        } else {
                            $content = [Convert]::ToBase64String($raw)
                            $aggregate += $bytes
                            $bytesLowerBound += $bytes
                            if ($status -ceq 'EMPTY') { $status = 'CAPTURED' }
                        }
                    }
                } finally {
                    Close-C4HeldFileLease $lease
                }
            }
        } else {
            if ($status -ceq 'EMPTY' -or $status -ceq 'CAPTURED') { $status = 'UNSAFE' }
        }
        $row = [ordered]@{
            relativePath = $relative
            kind = $kind
            volumeSerial = $volumeSerial
            fileId = $fileId
            linkCount = $linkCount
            bytes = $bytes
            sha256 = $sha
            contentBase64 = $content
        }
        Assert-C4NativeExactKeys $row $script:SidecarEntryKeys 'preflight sidecar entry'
        [void]$entries.Add($row)
    }
    if ($status -ceq 'OVERFLOW') { $truncated = $true }
    if ($status -ceq 'CAPTURED') { $truncated = $false }
    $document = [ordered]@{
        schema = $script:PreflightSidecarSchema
        version = 1
        attemptId = $AttemptId
        phase = $Phase
        status = $status
        truncated = [bool]$truncated
        entryCountLowerBound = [int]$countLowerBound
        bytesLowerBound = [int64]$bytesLowerBound
        entries = @($entries)
    }
    Assert-C4NativeExactKeys $document $script:SidecarKeys 'preflight sidecars'
    return $document
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

function Invoke-C4NativePreflight {
    param($Context, [string]$Phase, $ToolLeases, $SmokeDriverRow, [ref]$Reasons)

    $lower = $Phase.ToLowerInvariant()
    $stem = 'preflight-' + $lower
    $scratch = Join-Path $Context.ExternalParent ($stem + '-' + $Context.AttemptId)
    if ([IO.Directory]::Exists($scratch) -or [IO.File]::Exists($scratch)) {
        throw ('the preflight scratch sibling must be absent: ' + $scratch)
    }
    [void][IO.Directory]::CreateDirectory($scratch)
    if (Test-C4NativeReparse $scratch) { throw 'the preflight scratch sibling is a reparse point' }

    $smokePath = Join-Path $Context.RepoRoot ($script:SmokeDriverRelativePath -replace '/', '\')
    $harnessPath = $Context.HarnessResolvedPath
    $expectedHarnessSha = ([string]$Context.Candidate.artifacts.harness.sha256).ToUpperInvariant()
    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $smokePath,
        '-C4', '-PreflightOnly',
        '-PackageDirectory', $Context.PackageDirectoryForVerifier,
        '-HarnessPath', $harnessPath,
        '-ExpectedHarnessSha256', $expectedHarnessSha,
        '-AttemptId', $Context.AttemptId,
        '-CandidateManifestPath', $Context.CandidatePath,
        '-ExpectedCandidateManifestSha256', $Context.CandidateSha256,
        '-EvidenceDirectory', $scratch
    )
    $stdoutPath = Join-Path $Context.AttemptRoot ($stem + '.stdout.json')
    $stderrPath = Join-Path $Context.AttemptRoot ($stem + '.stderr.txt')
    $exitPath = Join-Path $Context.AttemptRoot ($stem + '.exit.txt')
    $containmentPath = Join-Path $Context.AttemptRoot ($stem + '-process-containment.json')
    $role = 'PREFLIGHT_' + $Phase
    Invoke-C4NativeCapture $Context.Adapters $ToolLeases['powershell'].Path $arguments `
        $Context.RepoRoot 1800000 $stdoutPath $stderrPath $exitPath 'CodeText' `
        $containmentPath $role $Context.AttemptId

    $record = Read-C4NativeCapturedExit $exitPath 'CodeText'
    $termination = [string]$record.termination
    $runnable = $false
    $mutationAttempts = 0
    $envelope = $null
    switch ($termination) {
        'TIMEOUT' { $Reasons.Value += 'PREFLIGHT_TIMEOUT' }
        'START_FAILED' { $Reasons.Value += 'PREFLIGHT_START_FAILED' }
        'CAPTURE_FAILED' { $Reasons.Value += 'PREFLIGHT_CAPTURE_FAILED' }
        'NORMAL' {
            $parsed = $null
            try {
                $utf8 = New-Object System.Text.UTF8Encoding $false
                $parsed = ($utf8.GetString([IO.File]::ReadAllBytes($stdoutPath))).Trim() | ConvertFrom-Json
            } catch {
                $parsed = $null
            }
            if ([int]$record.observedExit -ne 2 -or $null -eq $parsed) {
                $Reasons.Value += 'PREFLIGHT_OUTPUT_INVALID'
            } elseif ($parsed.schema -ceq $script:PublicSmokeSchema) {
                # A preflight that parses as the public result would be a live
                # claim from a command that never ran one.
                $Reasons.Value += 'PREFLIGHT_OUTPUT_INVALID'
            } elseif ([string]$parsed.overall -cne 'NOT RUN') {
                $Reasons.Value += 'PREFLIGHT_OUTPUT_INVALID'
            } elseif ([string]$parsed.sourceCommit -cne [string]$Context.Candidate.sourceCommit -or
                      [string]$parsed.sourceTree -cne [string]$Context.Candidate.sourceTree -or
                      [string]$parsed.candidateManifestSha256 -cne [string]$Context.CandidateSha256) {
                $Reasons.Value += 'PREFLIGHT_OUTPUT_INVALID'
            } elseif (@($parsed.PSObject.Properties.Name) -notcontains 'preflight' -or
                      @($parsed.PSObject.Properties.Name) -notcontains 'ownership') {
                $Reasons.Value += 'PREFLIGHT_OUTPUT_INVALID'
            } else {
                $envelope = $parsed
                $mutationAttempts = [int]$parsed.ownership.mutationAttempts
                $runnable = [bool]$parsed.preflight.runnable
                if ($mutationAttempts -ne 0) {
                    $Reasons.Value += 'PREFLIGHT_MUTATION_DETECTED'
                    $Reasons.Value += 'SOURCE_CONTRACT_VIOLATION'
                }
                if (-not $runnable) {
                    $Reasons.Value += 'PREFLIGHT_NOT_RUNNABLE'
                    # An envelope that names no reason is still a refusal;
                    # reading a key nobody promised is how this file already
                    # lost the package verifier.
                    if (@($parsed.preflight.PSObject.Properties.Name) -contains 'reasonCodes') {
                        foreach ($reason in @($parsed.preflight.reasonCodes)) {
                            if ($script:ReasonRoster -ccontains [string]$reason) {
                                $Reasons.Value += [string]$reason
                            }
                        }
                    }
                }
            }
        }
        default { $Reasons.Value += 'PREFLIGHT_OUTPUT_INVALID' }
    }

    # A created child that timed out or lost its capture is sealable only with
    # its exact-role PASS containment proof. Without it the attempt is not
    # sealed at all -- see the unsealable fail-stop below.
    $containmentPass = $true
    if ($termination -ceq 'TIMEOUT' -or $termination -ceq 'CAPTURE_FAILED') {
        $containmentPass = Test-C4NativeContainmentProof $containmentPath $role $Context.AttemptId
    }

    $sidecars = New-C4NativePreflightSidecars $Context.AttemptId $Phase $scratch
    Write-C4NativeExclusiveBytes (Join-Path $Context.AttemptRoot ($stem + '-sidecars.json')) `
        (Get-C4NativeCanonicalBytes $sidecars)
    if ([string]$sidecars.status -cne 'EMPTY') {
        $Reasons.Value += 'PREFLIGHT_SIDECAR_DETECTED'
        $Reasons.Value += 'SOURCE_CONTRACT_VIOLATION'
    }
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue

    return [pscustomobject]@{
        Termination = $termination
        Runnable = $runnable
        MutationAttempts = $mutationAttempts
        Envelope = $envelope
        ContainmentPass = $containmentPass
        SidecarStatus = [string]$sidecars.status
    }
}

function Test-C4NativeContainmentProof {
    param([string]$Path, [string]$Role, [string]$AttemptId, [string]$ExpectedPid)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.File]::Exists($Path)) { return $false }
    $proof = $null
    try {
        $proof = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($Path)) `
            -ExpectedSchema $script:ContainmentSchema
    } catch {
        return $false
    }
    if ([string]$proof.status -cne 'PASS') { return $false }
    if ([string]$proof.captureRole -cne $Role) { return $false }
    if ([string]$proof.attemptId -cne $AttemptId) { return $false }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedPid) -and
        [string]$proof.childProcessId -cne $ExpectedPid) {
        return $false
    }
    return $true
}

# ---------------------------------------------------------------------------
# Sealing
#
# `attempt-files.json` closes over every present file except itself and
# `attempt.json`; `attempt.json` then hashes that roster. Nothing downstream is
# included in an upstream hash, so the chain has no cycle.
# ---------------------------------------------------------------------------

function New-C4NativeAttemptFiles {
    param([string]$AttemptRoot, [string]$AttemptId)

    $rows = New-Object System.Collections.ArrayList
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $prefix = $AttemptRoot.TrimEnd('\') + '\'
    foreach ($file in [IO.Directory]::EnumerateFiles($AttemptRoot, '*', [IO.SearchOption]::AllDirectories)) {
        $full = [IO.Path]::GetFullPath($file)
        if (-not $full.StartsWith($prefix, [StringComparison]::Ordinal)) {
            throw ('the native attempt roster escaped its directory: ' + $full)
        }
        if (Test-C4NativeReparse $full) {
            throw ('the native attempt roster reached a reparse point: ' + $full)
        }
        $relative = $full.Substring($prefix.Length).Replace('\', '/')
        if ($relative -ceq 'attempt.json' -or $relative -ceq 'attempt-files.json') { continue }
        if (-not $seen.Add($relative)) { throw ('duplicate native attempt path: ' + $relative) }
        $bytes = [IO.File]::ReadAllBytes($full)
        [void]$rows.Add([ordered]@{
            relativePath = $relative
            bytes = [int64]$bytes.Length
            sha256 = (Get-C4EvidenceSha256Hex $bytes)
        })
    }
    return [ordered]@{
        schema = $script:NativeAttemptFilesSchema
        version = 1
        attemptId = $AttemptId
        files = @(@($rows) | Sort-Object -Property { [string]$_.relativePath } -CaseSensitive)
    }
}

function New-C4NativeNotRunDocument {
    param([string]$Phase, [string[]]$Reasons, $CommandIssued, [int]$MutationAttempts)

    if ($script:NotRunPhases -cnotcontains $Phase) {
        throw ("NOT RUN phase {0} is not one of the six prevented phases" -f $Phase)
    }
    $ordered = Get-C4NativeOrderedReasons $Reasons
    if (@($ordered).Count -eq 0) { throw 'a NOT RUN attempt requires at least one reason' }
    if ($MutationAttempts -ne 0) { throw 'a NOT RUN attempt requires zero mutation attempts' }
    $document = [ordered]@{
        schema = $script:NotRunSchema
        version = 1
        phase = $Phase
        reasonCodes = @($ordered)
        commandIssued = $CommandIssued
        liveIssued = [bool]$CommandIssued.live
        mutationAttempts = [int]$MutationAttempts
    }
    Assert-C4NativeExactKeys $document $script:NotRunKeys 'not-run.json'
    return $document
}

function Complete-C4NativeAttempt {
    param($Context, [string]$Status, [string]$Phase, [string[]]$Reasons, $CommandIssued,
          [int]$MutationAttempts, $CandidateIdentity)

    if ($script:NativeStatuses -cnotcontains $Status) { throw ("illegal native status {0}" -f $Status) }
    if ($script:Phases -cnotcontains $Phase) { throw ("illegal native phase {0}" -f $Phase) }
    $ordered = Get-C4NativeOrderedReasons $Reasons
    if ($Status -ceq 'PASS') {
        if (@($ordered).Count -ne 0) { throw 'a PASS attempt carries no reasons' }
        if ($Phase -cne 'COMPLETE') { throw 'a PASS attempt is COMPLETE' }
        if ($MutationAttempts -le 0) { throw 'a PASS attempt has positive mutation attempts' }
    } else {
        if (@($ordered).Count -eq 0) { throw 'a FAIL or NOT_RUN attempt requires at least one reason' }
    }
    if ($Status -ceq 'NOT_RUN') {
        $notRun = New-C4NativeNotRunDocument $Phase $ordered $CommandIssued $MutationAttempts
        $path = Join-Path $Context.AttemptRoot 'not-run.json'
        if (-not [IO.File]::Exists($path)) {
            Write-C4NativeExclusiveBytes $path (Get-C4NativeCanonicalBytes $notRun)
        }
    }

    $roster = New-C4NativeAttemptFiles $Context.AttemptRoot $Context.AttemptId
    $rosterBytes = Get-C4NativeCanonicalBytes $roster
    Write-C4NativeExclusiveBytes (Join-Path $Context.AttemptRoot 'attempt-files.json') $rosterBytes

    # All eight candidate identity fields are bound together or null together;
    # a mixture is unpublishable and the recorder refuses it.
    $identity = [ordered]@{}
    foreach ($key in $script:CandidateIdentityKeys) { $identity[$key] = $null }
    if ($null -ne $CandidateIdentity) {
        foreach ($key in $script:CandidateIdentityKeys) { $identity[$key] = $CandidateIdentity[$key] }
    }
    $bound = @(@($script:CandidateIdentityKeys) | Where-Object { $null -ne $identity[$_] }).Count
    if ($bound -ne 0 -and $bound -ne @($script:CandidateIdentityKeys).Count) {
        throw 'the eight candidate identity fields are all bound or all null'
    }

    $manifest = [ordered]@{
        schema = $script:NativeAttemptSchema
        version = 1
        attemptId = $Context.AttemptId
        bootstrapSourceCommit = $Context.BootstrapCommit
        bootstrapSourceTree = $Context.BootstrapTree
        bootstrapSha256 = $Context.BootstrapSha256
        sourceAttemptId = $identity['sourceAttemptId']
        sourceCommit = $identity['sourceCommit']
        sourceTree = $identity['sourceTree']
        candidateManifestSha256 = $identity['candidateManifestSha256']
        nativeReviewSha256 = $identity['nativeReviewSha256']
        evidenceReviewSha256 = $identity['evidenceReviewSha256']
        artifactSetSha256 = $identity['artifactSetSha256']
        packageSetSha256 = $identity['packageSetSha256']
        hostIdentity = $Context.HostIdentity
        bootIdentity = $Context.BootIdentity
        status = $Status
        phase = $Phase
        reasonCodes = @($ordered)
        commandIssued = $CommandIssued
        liveIssued = [bool]$CommandIssued.live
        mutationAttempts = [int]$MutationAttempts
        attemptFilesSha256 = (Get-C4EvidenceSha256Hex $rosterBytes)
    }
    Assert-C4NativeExactKeys $manifest $script:NativeAttemptKeys 'sealed native attempt.json'
    Assert-C4NativeExactKeys $manifest.hostIdentity $script:HostIdentityKeys 'hostIdentity'
    Assert-C4NativeExactKeys $manifest.bootIdentity $script:BootIdentityKeys 'bootIdentity'
    Assert-C4NativeExactKeys $manifest.commandIssued $script:CommandIssuedKeys 'commandIssued'
    Write-C4NativeExclusiveBytes (Join-Path $Context.AttemptRoot 'attempt.json') `
        (Get-C4NativeCanonicalBytes $manifest)
    return $manifest
}

function New-C4NativeCommandIssued {
    param([bool]$InitialPreflight, [bool]$FinalPreflight, [bool]$Live)
    return [ordered]@{
        initialPreflight = [bool]$InitialPreflight
        finalPreflight = [bool]$FinalPreflight
        live = [bool]$Live
    }
}

function New-C4NativeCandidateIdentity {
    param($Context)
    $row = $Context.CandidateRow
    $identity = [ordered]@{
        sourceAttemptId = [string]$Context.Candidate.attemptId
        sourceCommit = [string]$Context.Candidate.sourceCommit
        sourceTree = [string]$Context.Candidate.sourceTree
        candidateManifestSha256 = [string]$Context.CandidateSha256
        nativeReviewSha256 = [string]$row.nativeReviewSha256
        evidenceReviewSha256 = [string]$row.evidenceReviewSha256
        artifactSetSha256 = [string]$Context.Candidate.artifactSetSha256
        packageSetSha256 = [string]$Context.Candidate.artifacts.package.setSha256
    }
    # All eight or none. The resolver already requires a reviewed PASS, so a
    # blank review hash should be unreachable -- but reaching it should seal an
    # unbound attempt, not throw halfway through sealing one.
    foreach ($key in $script:CandidateIdentityKeys) {
        if ([string]::IsNullOrWhiteSpace([string]$identity[$key])) { return $null }
    }
    return $identity
}

# The one nonreturning state. Reaching it means a created child could not be
# proved contained, so there is nothing safe to say about the machine: no
# attempt, no recorder call, no commit.
#
# It throws a sentinel rather than calling `exit` so a fixture can observe that
# NOTHING was sealed; the entry point maps this exact sentinel to exit 3 and
# prints the recovery notice. A bare `exit` here would make the property
# untestable, which is how a safety fail-stop quietly stops being one.
$script:UnsealableSentinel = 'FSRING-C4-UNSEALABLE: '

function Stop-C4NativeUnsealable {
    param([string]$Why)
    throw ($script:UnsealableSentinel + $Why)
}

# ---------------------------------------------------------------------------
# Inspect
# ---------------------------------------------------------------------------

function Invoke-C4NativeInspect {
    param($Options)

    $repoRoot = $Options.RepoRoot
    $attemptId = Assert-C4NativeAttemptId $Options.AttemptId
    $commit = Assert-C4NativeHex $Options.BootstrapSourceCommit 40 '-BootstrapSourceCommit'
    $tree = Assert-C4NativeHex $Options.BootstrapSourceTree 40 '-BootstrapSourceTree'
    $expectedNative = Assert-C4NativeHex $Options.ExpectedNativeRunnerSha256 64 '-ExpectedNativeRunnerSha256'
    $expectedHelper = Assert-C4NativeHex $Options.ExpectedCaptureHelperSha256 64 '-ExpectedCaptureHelperSha256'
    $expectedRecorder = Assert-C4NativeHex $Options.ExpectedRecorderSha256 64 '-ExpectedRecorderSha256'

    # Ancestry and the evidence-only diff are proved BEFORE the output
    # directory is accepted, and independently of whether a candidate resolves.
    [void](Assert-C4NativeBootstrapAncestry $Options.Adapters $commit $tree)

    $parent = Assert-C4NativeAbsolutePath $Options.AuthorizedExternalParent '-AuthorizedExternalParent'
    if (-not [IO.Directory]::Exists($parent)) { throw '-AuthorizedExternalParent must be an existing directory' }
    $attemptRoot = Assert-C4NativeAbsolutePath $Options.OutputDirectory '-OutputDirectory'
    if ([IO.Path]::GetDirectoryName($attemptRoot) -cne $parent) {
        throw '-OutputDirectory must be a direct child of the authorized external parent'
    }
    if ([IO.Directory]::Exists($attemptRoot) -or [IO.File]::Exists($attemptRoot)) {
        throw '-OutputDirectory must be absent'
    }

    $scriptLeases = [ordered]@{}
    $toolLeases = $null
    $artifactLeases = [ordered]@{}
    try {
        $paths = [ordered]@{
            'native-runner' = (Join-Path $repoRoot ($script:NativeRunnerRelativePath -replace '/', '\'))
            'capture-helper' = (Join-Path $repoRoot ($script:CaptureHelperRelativePath -replace '/', '\'))
            'recorder' = (Join-Path $repoRoot ($script:RecorderRelativePath -replace '/', '\'))
        }
        foreach ($role in @($paths.Keys)) {
            $path = [string]$paths[$role]
            if (-not [IO.File]::Exists($path)) { throw ('the ' + $role + ' script is absent') }
            $scriptLeases[$role] = Open-C4HeldFileLease -Path ([IO.Path]::GetFullPath($path)) `
                -ExpectedSha256 (Get-C4NativeSha256File $path)
        }
        $toolLeases = Open-C4NativeLocalToolLeases $Options.ToolOverrides
        if ($null -eq $toolLeases['powershell']) { throw 'the local PowerShell host could not be leased' }
        $scriptLeases['powershell'] = $toolLeases['powershell']

        $expectedHashes = [ordered]@{
            'native-runner' = $expectedNative
            'capture-helper' = $expectedHelper
            'recorder' = $expectedRecorder
        }
        $bootstrap = New-C4NativeBootstrap $Options.Adapters $repoRoot $commit $tree $expectedHashes $scriptLeases

        # --- the acceptance cut -------------------------------------------
        [void][IO.Directory]::CreateDirectory($attemptRoot)
        $bootstrapBytes = Get-C4NativeCanonicalBytes $bootstrap
        Write-C4NativeExclusiveBytes (Join-Path $attemptRoot 'bootstrap.json') $bootstrapBytes
        $bootstrapSha = Get-C4EvidenceSha256Hex $bootstrapBytes

        $resolution = Resolve-C4NativeCandidate $repoRoot
        $context = [pscustomobject]@{
            RepoRoot = $repoRoot
            Adapters = $Options.Adapters
            AttemptId = $attemptId
            AttemptRoot = $attemptRoot
            ExternalParent = $parent
            BootstrapCommit = $commit
            BootstrapTree = $tree
            BootstrapSha256 = $bootstrapSha
            HostIdentity = (& $Options.Adapters.HostIdentity)
            BootIdentity = (& $Options.Adapters.BootIdentity)
            Candidate = $null
            CandidateRow = $null
            CandidateSha256 = $null
            CandidatePath = $null
            CandidateAttemptDirectory = $null
            CandidateFailureReason = $resolution.Reason
            ExpectedSourceInputHashes = $null
            ExpectedVerifierSha256 = $null
            PackageDirectory = $Options.PackageDirectory
            HarnessPath = $Options.HarnessPath
            PackageDirectoryForVerifier = $null
            HarnessResolvedPath = $null
        }
        Assert-C4NativeExactKeys $context.HostIdentity $script:HostIdentityKeys 'hostIdentity'
        Assert-C4NativeExactKeys $context.BootIdentity $script:BootIdentityKeys 'bootIdentity'

        if ($resolution.Resolved) {
            $context.Candidate = $resolution.Candidate
            $context.CandidateRow = $resolution.Row
            $context.CandidateSha256 = $resolution.CandidateSha256
            $context.CandidatePath = $resolution.CandidatePath
            $context.CandidateAttemptDirectory = $resolution.AttemptDirectory
            $row01 = $null
            try {
                $row01 = Read-C4NativeRow01SelfTestObject $resolution.AttemptDirectory
            } catch {
                $row01 = $null
            }
            if ($null -eq $row01) {
                $context.Candidate = $null
                $context.CandidateFailureReason = 'CANDIDATE_MANIFEST_INVALID'
            } elseif ([string]$resolution.Candidate.sourceCommit -cne $commit -or
                      [string]$resolution.Candidate.sourceTree -cne $tree) {
                # The pinned bootstrap and the candidate must describe the same
                # tree, or the scripts about to run are not the reviewed ones.
                $context.Candidate = $null
                $context.CandidateFailureReason = 'CANDIDATE_MANIFEST_INVALID'
            } elseif ([string]$row01.nativeRunnerSha256 -cne $expectedNative -or
                      [string]$row01.captureHelperSha256 -cne $expectedHelper -or
                      [string]$row01.recorderSha256 -cne $expectedRecorder) {
                $context.Candidate = $null
                $context.CandidateFailureReason = 'CANDIDATE_MANIFEST_INVALID'
            } else {
                $context.ExpectedSourceInputHashes = [ordered]@{
                    'candidate-manifest' = $resolution.CandidateSha256
                    'native-runner' = [string]$row01.nativeRunnerSha256
                    'capture-helper' = [string]$row01.captureHelperSha256
                    'recorder' = [string]$row01.recorderSha256
                }
                $context.ExpectedVerifierSha256 = [string]$resolution.Candidate.packageVerifier.scriptSha256
                $context.PackageDirectoryForVerifier = $context.PackageDirectory
                if ([string]::IsNullOrWhiteSpace($context.PackageDirectoryForVerifier)) {
                    $context.PackageDirectoryForVerifier = Join-Path $resolution.AttemptDirectory 'artifacts\win10-x64-release\package'
                }
                $context.HarnessResolvedPath = $context.HarnessPath
                if ([string]::IsNullOrWhiteSpace($context.HarnessResolvedPath)) {
                    $context.HarnessResolvedPath = Join-Path $resolution.AttemptDirectory 'artifacts\win10-x64-release\fsring-control-smoke.exe'
                }
            }
        }

        $artifactRef = [ref]$artifactLeases
        $artifact = New-C4NativeArtifactCheck $context 'INITIAL' $toolLeases $artifactRef
        Write-C4NativeExclusiveBytes (Join-Path $attemptRoot 'artifact-initial.json') `
            (Get-C4NativeCanonicalBytes $artifact)

        $identity = $null
        if ($null -ne $context.Candidate) { $identity = New-C4NativeCandidateIdentity $context }

        if ([string]$artifact.status -cne 'PASS') {
            # A source-contract violation is FAIL; everything else at this
            # phase is an unmet prerequisite, which is NOT RUN.
            $status = 'NOT_RUN'
            if (@($artifact.reasonCodes) -ccontains 'SOURCE_CONTRACT_VIOLATION') { $status = 'FAIL' }
            $issued = New-C4NativeCommandIssued $false $false $false
            $manifest = Complete-C4NativeAttempt $context $status 'ARTIFACT_INITIAL' `
                @($artifact.reasonCodes) $issued 0 $identity
            return (Write-C4NativeInspectionResult $context $bootstrapSha `
                $(if ($status -ceq 'FAIL') { 'SEALED_FAIL' } else { 'SEALED_NOT_RUN' }) $null)
        }

        $reasons = @()
        $reasonRef = [ref]$reasons
        $preflight = Invoke-C4NativePreflight $context 'INITIAL' $toolLeases $artifact.smokeDriver $reasonRef
        $reasons = $reasonRef.Value
        if (-not $preflight.ContainmentPass) {
            Stop-C4NativeUnsealable 'the initial preflight child could not be proved contained'
        }
        if (@($reasons).Count -ne 0 -or -not $preflight.Runnable) {
            $status = 'NOT_RUN'
            if (@($reasons) -ccontains 'SOURCE_CONTRACT_VIOLATION') { $status = 'FAIL' }
            if (@($reasons).Count -eq 0) { $reasons = @('PREFLIGHT_NOT_RUNNABLE') }
            $issued = New-C4NativeCommandIssued $true $false $false
            [void](Complete-C4NativeAttempt $context $status 'PREFLIGHT_INITIAL' $reasons $issued 0 $identity)
            return (Write-C4NativeInspectionResult $context $bootstrapSha `
                $(if ($status -ceq 'FAIL') { 'SEALED_FAIL' } else { 'SEALED_NOT_RUN' }) $null)
        }

        # Runnable: publish the pending state and exit without mutation.
        $pending = [ordered]@{
            schema = $script:PendingInspectionSchema
            version = 1
            attemptId = $attemptId
            sourceAttemptId = [string]$context.Candidate.attemptId
            sourceCommit = [string]$context.Candidate.sourceCommit
            sourceTree = [string]$context.Candidate.sourceTree
            candidateManifestSha256 = [string]$context.CandidateSha256
            artifactSetSha256 = [string]$context.Candidate.artifactSetSha256
            packageSetSha256 = [string]$context.Candidate.artifacts.package.setSha256
            hostIdentity = $context.HostIdentity
            bootIdentity = $context.BootIdentity
            ownedServiceName = ('fsring-c4-' + $attemptId)
            # The literal parent-design pattern, not one preflight worker's
            # transient name: the PID is only known per invocation.
            ownedDosPattern = 'Global\FsRingC4-<retained-worker-pid:08X>-<uppercase-attemptId>'
            authorizationOperations = @($script:AuthorizationOperations)
            runnable = $true
        }
        Assert-C4NativeExactKeys $pending $script:PendingInspectionKeys 'pending-inspection.json'
        $pendingBytes = Get-C4NativeCanonicalBytes $pending
        Write-C4NativeExclusiveBytes (Join-Path $attemptRoot 'pending-inspection.json') $pendingBytes
        return (Write-C4NativeInspectionResult $context $bootstrapSha 'PENDING_AUTHORIZATION' `
            (Get-C4EvidenceSha256Hex $pendingBytes))
    } finally {
        Close-C4NativeLeaseMap $scriptLeases
        Close-C4NativeLeaseMap $artifactLeases
        if ($null -ne $toolLeases) {
            foreach ($role in @($toolLeases.Keys)) {
                if ($role -ceq 'powershell') { continue }
                if ($null -ne $toolLeases[$role]) { Close-C4HeldFileLease $toolLeases[$role] }
            }
        }
    }
}

function Write-C4NativeInspectionResult {
    param($Context, [string]$BootstrapSha256, [string]$State, $InspectionSha256)

    if ($script:InspectionStates -cnotcontains $State) { throw ("illegal inspection state {0}" -f $State) }
    $runnable = ($State -ceq 'PENDING_AUTHORIZATION')
    if ($runnable -and [string]::IsNullOrWhiteSpace([string]$InspectionSha256)) {
        throw 'a pending inspection requires its pending-file hash'
    }
    if (-not $runnable) { $InspectionSha256 = $null }
    $document = [ordered]@{
        schema = $script:InspectionResultSchema
        version = 1
        attemptId = $Context.AttemptId
        bootstrapSha256 = $BootstrapSha256
        state = $State
        runnable = [bool]$runnable
        inspectionSha256 = $InspectionSha256
    }
    Assert-C4NativeExactKeys $document $script:InspectionResultKeys 'inspection-result.json'
    Write-C4NativeExclusiveBytes (Join-Path $Context.AttemptRoot 'inspection-result.json') `
        (Get-C4NativeCanonicalBytes $document)
    return $document
}

# ---------------------------------------------------------------------------
# Pending-state revalidation
#
# Every mode after Inspect re-reads the whole immutable prefix rather than
# trusting a scalar it was handed: bootstrap, its hash, the pending state, and
# the inspection result all have to agree before any later step runs.
# ---------------------------------------------------------------------------

function Read-C4NativePendingState {
    param([string]$AttemptRoot, [string]$ExpectedInspectionSha256, [string]$ExpectedNativeRunnerSha256, $Options)

    $root = Assert-C4NativeAbsolutePath $AttemptRoot '-AttemptDirectory'
    if (-not [IO.Directory]::Exists($root)) { throw '-AttemptDirectory names no directory' }
    foreach ($name in @('attempt.json', 'attempt-files.json')) {
        if ([IO.File]::Exists((Join-Path $root $name))) {
            throw ('the attempt is already sealed: ' + $name)
        }
    }
    $bootstrapPath = Join-Path $root 'bootstrap.json'
    if (-not [IO.File]::Exists($bootstrapPath)) { throw 'the attempt carries no bootstrap.json' }
    $bootstrapBytes = [IO.File]::ReadAllBytes($bootstrapPath)
    $bootstrap = ConvertFrom-C4CanonicalJsonBytes -Bytes $bootstrapBytes -ExpectedSchema $script:BootstrapSchema
    Assert-C4NativeExactKeys $bootstrap $script:BootstrapKeys 'bootstrap.json'
    $native = @($bootstrap.files) | Where-Object { [string]$_.role -ceq 'native-runner' }
    if ($null -eq $native -or [string]$native.sha256 -cne $ExpectedNativeRunnerSha256) {
        throw 'the sealed bootstrap does not name this native runner'
    }
    $resultPath = Join-Path $root 'inspection-result.json'
    if (-not [IO.File]::Exists($resultPath)) { throw 'the attempt carries no inspection-result.json' }
    $result = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($resultPath)) `
        -ExpectedSchema $script:InspectionResultSchema
    Assert-C4NativeExactKeys $result $script:InspectionResultKeys 'inspection-result.json'
    if ([string]$result.bootstrapSha256 -cne (Get-C4EvidenceSha256Hex $bootstrapBytes)) {
        throw 'the inspection result does not hash this bootstrap'
    }
    if ([string]$result.state -cne 'PENDING_AUTHORIZATION') {
        throw 'the attempt is not in the pending-authorization state'
    }
    $pendingPath = Join-Path $root 'pending-inspection.json'
    if (-not [IO.File]::Exists($pendingPath)) { throw 'the attempt carries no pending-inspection.json' }
    $pendingBytes = [IO.File]::ReadAllBytes($pendingPath)
    $pendingSha = Get-C4EvidenceSha256Hex $pendingBytes
    if ($pendingSha -cne $ExpectedInspectionSha256 -or [string]$result.inspectionSha256 -cne $pendingSha) {
        throw 'the pending inspection does not match its expected hash'
    }
    $pending = ConvertFrom-C4CanonicalJsonBytes -Bytes $pendingBytes -ExpectedSchema $script:PendingInspectionSchema
    Assert-C4NativeExactKeys $pending $script:PendingInspectionKeys 'pending-inspection.json'
    if (-not [bool]$pending.runnable) { throw 'the pending inspection is not runnable' }
    if ((@($pending.authorizationOperations) -join "`n") -cne ($script:AuthorizationOperations -join "`n")) {
        throw 'the pending authorization operation roster is not the closed eight-item roster'
    }
    return [pscustomobject]@{
        AttemptRoot = $root
        Bootstrap = $bootstrap
        BootstrapSha256 = (Get-C4EvidenceSha256Hex $bootstrapBytes)
        Pending = $pending
        PendingSha256 = $pendingSha
        Result = $result
    }
}

function New-C4NativeContextFromPending {
    param($State, $Options)
    return [pscustomobject]@{
        RepoRoot = $Options.RepoRoot
        Adapters = $Options.Adapters
        AttemptId = [string]$State.Pending.attemptId
        AttemptRoot = $State.AttemptRoot
        ExternalParent = ([IO.Path]::GetDirectoryName($State.AttemptRoot))
        BootstrapCommit = [string]$State.Bootstrap.sourceCommit
        BootstrapTree = [string]$State.Bootstrap.sourceTree
        BootstrapSha256 = $State.BootstrapSha256
        HostIdentity = (& $Options.Adapters.HostIdentity)
        BootIdentity = (& $Options.Adapters.BootIdentity)
        Candidate = $null
        CandidateRow = $null
        CandidateSha256 = [string]$State.Pending.candidateManifestSha256
        CandidatePath = $null
        CandidateAttemptDirectory = $null
        CandidateFailureReason = $null
        ExpectedSourceInputHashes = $null
        ExpectedVerifierSha256 = $null
        PackageDirectory = $Options.PackageDirectory
        HarnessPath = $Options.HarnessPath
        PackageDirectoryForVerifier = $null
        HarnessResolvedPath = $null
    }
}

# ---------------------------------------------------------------------------
# Authorize
#
# Records authority; performs no privileged operation. The retained handle on
# the newly created file is held until the one stdout object is written, so a
# replacement between creation and reporting cannot be laundered into `Run`.
# ---------------------------------------------------------------------------

function Invoke-C4NativeAuthorize {
    param($Options)

    $expectedInspection = Assert-C4NativeHex $Options.ExpectedInspectionSha256 64 '-ExpectedInspectionSha256'
    $expectedNative = Assert-C4NativeHex $Options.ExpectedNativeRunnerSha256 64 '-ExpectedNativeRunnerSha256'
    $reference = [string]$Options.AuthorizationReference
    if ([string]::IsNullOrWhiteSpace($reference) -or $reference -match '[\r\n]' -or
        $reference -cnotmatch '^[\x20-\x7e]+$') {
        throw '-AuthorizationReference must be a nonempty printable single-line string'
    }
    $state = Read-C4NativePendingState $Options.AttemptDirectory $expectedInspection $expectedNative $Options
    $authorizationPath = Join-Path $state.AttemptRoot 'authorization.json'
    if ([IO.File]::Exists($authorizationPath)) {
        throw 'this attempt is already authorized'
    }
    $pending = $state.Pending
    $document = [ordered]@{
        schema = $script:AuthorizationSchema
        version = 1
        attemptId = [string]$pending.attemptId
        authorizedAtUtc = $Options.AuthorizedAtUtc
        authorizationReference = $reference
        operations = @($script:AuthorizationOperations)
        hostIdentity = $pending.hostIdentity
        bootIdentity = $pending.bootIdentity
        sourceAttemptId = [string]$pending.sourceAttemptId
        sourceCommit = [string]$pending.sourceCommit
        sourceTree = [string]$pending.sourceTree
        candidateManifestSha256 = [string]$pending.candidateManifestSha256
        artifactSetSha256 = [string]$pending.artifactSetSha256
        packageSetSha256 = [string]$pending.packageSetSha256
    }
    Assert-C4NativeExactKeys $document $script:AuthorizationKeys 'authorization.json'
    if ($document.authorizedAtUtc -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') {
        throw 'authorizedAtUtc must be normalized RFC 3339 UTC with Z'
    }
    $bytes = Get-C4NativeCanonicalBytes $document
    Write-C4NativeExclusiveBytes $authorizationPath $bytes

    $lease = Open-C4HeldFileLease -Path ([IO.Path]::GetFullPath($authorizationPath)) `
        -ExpectedSha256 (Get-C4EvidenceSha256Hex $bytes)
    try {
        $result = [ordered]@{
            schema = $script:AuthorizationResultSchema
            version = 1
            attemptId = [string]$pending.attemptId
            inspectionSha256 = $state.PendingSha256
            authorizationSha256 = $lease.Sha256
        }
        Assert-C4NativeExactKeys $result $script:AuthorizationResultKeys 'authorization result'
        Assert-C4HeldFileLease $lease
        Write-C4NativeStdoutLine (ConvertTo-C4CanonicalJsonText $result)
        return $result
    } finally {
        Close-C4HeldFileLease $lease
    }
}

# ---------------------------------------------------------------------------
# SealNotRun
#
# The only close path when authority is declined or absent. It never touches a
# service, a DOS name, or the driver.
# ---------------------------------------------------------------------------

function Invoke-C4NativeSealNotRun {
    param($Options)

    $expectedInspection = Assert-C4NativeHex $Options.ExpectedInspectionSha256 64 '-ExpectedInspectionSha256'
    $expectedNative = Assert-C4NativeHex $Options.ExpectedNativeRunnerSha256 64 '-ExpectedNativeRunnerSha256'
    $state = Read-C4NativePendingState $Options.AttemptDirectory $expectedInspection $expectedNative $Options
    $context = New-C4NativeContextFromPending $state $Options
    $pending = $state.Pending
    if ([string]$context.HostIdentity.machineGuid -cne [string]$pending.hostIdentity.machineGuid) {
        # Sealing a decline on a different host would attribute this NOT RUN to
        # a machine that never saw the attempt.
        throw 'the host identity changed since the pending inspection'
    }
    $identity = [ordered]@{
        sourceAttemptId = [string]$pending.sourceAttemptId
        sourceCommit = [string]$pending.sourceCommit
        sourceTree = [string]$pending.sourceTree
        candidateManifestSha256 = [string]$pending.candidateManifestSha256
        nativeReviewSha256 = [string]$Options.NativeReviewSha256
        evidenceReviewSha256 = [string]$Options.EvidenceReviewSha256
        artifactSetSha256 = [string]$pending.artifactSetSha256
        packageSetSha256 = [string]$pending.packageSetSha256
    }
    if ([string]::IsNullOrWhiteSpace([string]$identity['nativeReviewSha256']) -or
        [string]::IsNullOrWhiteSpace([string]$identity['evidenceReviewSha256'])) {
        # Without both review hashes the eight fields cannot all be bound, and a
        # mixture is unpublishable -- so this seals unbound.
        $identity = $null
    }
    $issued = New-C4NativeCommandIssued $true $false $false
    return (Complete-C4NativeAttempt $context 'NOT_RUN' 'AUTHORIZATION' @('AUTHORIZATION_MISSING') $issued 0 $identity)
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

function Read-C4NativeDiagnosticsJournal {
    param([string]$Path, [string]$AttemptId)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.File]::Exists($Path)) {
        return [pscustomobject]@{ Valid = $false; MutationAttempts = 0 }
    }
    $lines = @()
    try {
        $lines = @([IO.File]::ReadAllLines($Path))
    } catch {
        return [pscustomobject]@{ Valid = $false; MutationAttempts = 0 }
    }
    $header = $null
    $count = 0
    $expected = 1
    foreach ($line in $lines) {
        $trimmed = ([string]$line).Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        $record = $null
        try { $record = $trimmed | ConvertFrom-Json } catch { return [pscustomobject]@{ Valid = $false; MutationAttempts = $count } }
        if ($null -eq $header) {
            $header = $record
            if ([string]$record.attemptId -cne $AttemptId) {
                return [pscustomobject]@{ Valid = $false; MutationAttempts = 0 }
            }
            continue
        }
        # The ordinals are monotonic from one: a gap means a record was lost,
        # and a lost record is exactly the case where the count is a lower
        # bound nobody can trust.
        if ([int]$record.ordinal -ne $expected) {
            return [pscustomobject]@{ Valid = $false; MutationAttempts = $count }
        }
        $expected += 1
        $count += 1
    }
    if ($null -eq $header) { return [pscustomobject]@{ Valid = $false; MutationAttempts = 0 } }
    return [pscustomobject]@{ Valid = $true; MutationAttempts = $count }
}

function Invoke-C4NativeRun {
    param($Options)

    $expectedInspection = Assert-C4NativeHex $Options.ExpectedInspectionSha256 64 '-ExpectedInspectionSha256'
    $expectedAuthorization = Assert-C4NativeHex $Options.ExpectedAuthorizationSha256 64 '-ExpectedAuthorizationSha256'
    $expectedNative = Assert-C4NativeHex $Options.ExpectedNativeRunnerSha256 64 '-ExpectedNativeRunnerSha256'
    $state = Read-C4NativePendingState $Options.AttemptDirectory $expectedInspection $expectedNative $Options
    $pending = $state.Pending

    $authorizationPath = Join-Path $state.AttemptRoot 'authorization.json'
    if (-not [IO.File]::Exists($authorizationPath)) {
        throw 'Run requires an authorization recorded for this exact attempt'
    }
    $authorizationBytes = [IO.File]::ReadAllBytes($authorizationPath)
    if ((Get-C4EvidenceSha256Hex $authorizationBytes) -cne $expectedAuthorization) {
        throw 'the recorded authorization does not match its expected hash'
    }
    $authorization = ConvertFrom-C4CanonicalJsonBytes -Bytes $authorizationBytes -ExpectedSchema $script:AuthorizationSchema
    Assert-C4NativeExactKeys $authorization $script:AuthorizationKeys 'authorization.json'
    foreach ($field in @('attemptId', 'sourceAttemptId', 'sourceCommit', 'sourceTree',
                         'candidateManifestSha256', 'artifactSetSha256', 'packageSetSha256')) {
        if ([string]$authorization.$field -cne [string]$pending.$field) {
            throw ('the authorization tuple does not match the pending inspection: ' + $field)
        }
    }

    $context = New-C4NativeContextFromPending $state $Options
    $identityBase = [ordered]@{
        sourceAttemptId = [string]$pending.sourceAttemptId
        sourceCommit = [string]$pending.sourceCommit
        sourceTree = [string]$pending.sourceTree
        candidateManifestSha256 = [string]$pending.candidateManifestSha256
        nativeReviewSha256 = [string]$Options.NativeReviewSha256
        evidenceReviewSha256 = [string]$Options.EvidenceReviewSha256
        artifactSetSha256 = [string]$pending.artifactSetSha256
        packageSetSha256 = [string]$pending.packageSetSha256
    }
    $identity = $identityBase
    if ([string]::IsNullOrWhiteSpace([string]$identityBase['nativeReviewSha256']) -or
        [string]::IsNullOrWhiteSpace([string]$identityBase['evidenceReviewSha256'])) {
        $identity = $null
    }

    $reasons = @()
    if ([string]$context.HostIdentity.machineGuid -cne [string]$pending.hostIdentity.machineGuid -or
        [string]$context.HostIdentity.computerName -cne [string]$pending.hostIdentity.computerName) {
        $reasons += 'HOST_IDENTITY_DRIFT'
        $reasons += 'AUTHORIZATION_TUPLE_MISMATCH'
    }
    if ([string]$context.BootIdentity.bootId -cne [string]$pending.bootIdentity.bootId) {
        $reasons += 'BOOT_IDENTITY_DRIFT'
        $reasons += 'AUTHORIZATION_TUPLE_MISMATCH'
    }
    if (@($reasons).Count -ne 0) {
        $issued = New-C4NativeCommandIssued $true $false $false
        return (Complete-C4NativeAttempt $context 'NOT_RUN' 'AUTHORIZATION' $reasons $issued 0 $identity)
    }

    # --- resolve the candidate again for the FINAL artifact check ----------
    $resolution = Resolve-C4NativeCandidate $Options.RepoRoot
    if (-not $resolution.Resolved -or [string]$resolution.CandidateSha256 -cne [string]$pending.candidateManifestSha256) {
        $issued = New-C4NativeCommandIssued $true $false $false
        return (Complete-C4NativeAttempt $context 'NOT_RUN' 'ARTIFACT_FINAL' @('CANDIDATE_IDENTITY_DRIFT') $issued 0 $identity)
    }
    $row01 = $null
    try { $row01 = Read-C4NativeRow01SelfTestObject $resolution.AttemptDirectory } catch { $row01 = $null }
    if ($null -eq $row01) {
        $issued = New-C4NativeCommandIssued $true $false $false
        return (Complete-C4NativeAttempt $context 'NOT_RUN' 'ARTIFACT_FINAL' @('CANDIDATE_MANIFEST_INVALID') $issued 0 $identity)
    }
    $context.Candidate = $resolution.Candidate
    $context.CandidateRow = $resolution.Row
    $context.CandidatePath = $resolution.CandidatePath
    $context.CandidateAttemptDirectory = $resolution.AttemptDirectory
    $context.ExpectedSourceInputHashes = [ordered]@{
        'candidate-manifest' = $resolution.CandidateSha256
        'native-runner' = [string]$row01.nativeRunnerSha256
        'capture-helper' = [string]$row01.captureHelperSha256
        'recorder' = [string]$row01.recorderSha256
    }
    $context.ExpectedVerifierSha256 = [string]$resolution.Candidate.packageVerifier.scriptSha256
    $context.PackageDirectoryForVerifier = $context.PackageDirectory
    if ([string]::IsNullOrWhiteSpace($context.PackageDirectoryForVerifier)) {
        $context.PackageDirectoryForVerifier = Join-Path $resolution.AttemptDirectory 'artifacts\win10-x64-release\package'
    }
    $context.HarnessResolvedPath = $context.HarnessPath
    if ([string]::IsNullOrWhiteSpace($context.HarnessResolvedPath)) {
        $context.HarnessResolvedPath = Join-Path $resolution.AttemptDirectory 'artifacts\win10-x64-release\fsring-control-smoke.exe'
    }

    $toolLeases = Open-C4NativeLocalToolLeases $Options.ToolOverrides
    $artifactLeases = [ordered]@{}
    try {
        $artifactRef = [ref]$artifactLeases
        $artifact = New-C4NativeArtifactCheck $context 'FINAL' $toolLeases $artifactRef
        Write-C4NativeExclusiveBytes (Join-Path $context.AttemptRoot 'artifact-final.json') `
            (Get-C4NativeCanonicalBytes $artifact)
        if ([string]$artifact.status -cne 'PASS') {
            $status = 'NOT_RUN'
            if (@($artifact.reasonCodes) -ccontains 'SOURCE_CONTRACT_VIOLATION') { $status = 'FAIL' }
            $issued = New-C4NativeCommandIssued $true $false $false
            return (Complete-C4NativeAttempt $context $status 'ARTIFACT_FINAL' @($artifact.reasonCodes) $issued 0 $identity)
        }

        $reasons = @()
        $reasonRef = [ref]$reasons
        $preflight = Invoke-C4NativePreflight $context 'FINAL' $toolLeases $artifact.smokeDriver $reasonRef
        $reasons = $reasonRef.Value
        if (-not $preflight.ContainmentPass) {
            Stop-C4NativeUnsealable 'the final preflight child could not be proved contained'
        }
        if (@($reasons).Count -ne 0 -or -not $preflight.Runnable) {
            $status = 'NOT_RUN'
            if (@($reasons) -ccontains 'SOURCE_CONTRACT_VIOLATION') { $status = 'FAIL' }
            if (@($reasons).Count -eq 0) { $reasons = @('PREFLIGHT_NOT_RUNNABLE') }
            $issued = New-C4NativeCommandIssued $true $true $false
            $mutations = 0
            if ($preflight.MutationAttempts -gt 0) { $mutations = [int]$preflight.MutationAttempts }
            if ($status -ceq 'FAIL') {
                return (Complete-C4NativeAttempt $context 'FAIL' 'PREFLIGHT_FINAL' $reasons $issued $mutations $identity)
            }
            return (Complete-C4NativeAttempt $context 'NOT_RUN' 'PREFLIGHT_FINAL' $reasons $issued 0 $identity)
        }

        return (Invoke-C4NativeLive $context $Options $toolLeases $artifact $identity)
    } finally {
        Close-C4NativeLeaseMap $artifactLeases
        Close-C4NativeLeaseMap $toolLeases
    }
}

function Invoke-C4NativeLive {
    param($Context, $Options, $ToolLeases, $Artifact, $Identity)

    $liveDirectory = Join-Path $Context.AttemptRoot 'live'
    [void][IO.Directory]::CreateDirectory($liveDirectory)
    $smokePath = Join-Path $Context.RepoRoot ($script:SmokeDriverRelativePath -replace '/', '\')
    $expectedHarnessSha = ([string]$Context.Candidate.artifacts.harness.sha256).ToUpperInvariant()
    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $smokePath,
        '-C4',
        '-PackageDirectory', $Context.PackageDirectoryForVerifier,
        '-HarnessPath', $Context.HarnessResolvedPath,
        '-ExpectedHarnessSha256', $expectedHarnessSha,
        '-AttemptId', $Context.AttemptId,
        '-CandidateManifestPath', $Context.CandidatePath,
        '-ExpectedCandidateManifestSha256', $Context.CandidateSha256,
        '-EvidenceDirectory', $liveDirectory
    )
    $stdoutPath = Join-Path $Context.AttemptRoot 'live.stdout.json'
    $stderrPath = Join-Path $Context.AttemptRoot 'live.stderr.txt'
    $exitPath = Join-Path $Context.AttemptRoot 'live.exit.txt'
    $containmentPath = Join-Path $liveDirectory 'process-containment.json'
    $issued = New-C4NativeCommandIssued $true $true $true

    Invoke-C4NativeCapture $Context.Adapters $ToolLeases['powershell'].Path $arguments `
        $Context.RepoRoot 3600000 $stdoutPath $stderrPath $exitPath 'CodeText' `
        $containmentPath 'LIVE' $Context.AttemptId

    $record = Read-C4NativeCapturedExit $exitPath 'CodeText'
    $termination = [string]$record.termination
    $journalPath = Join-Path $liveDirectory 'diagnostics.sidecar.jsonl'
    $journal = Read-C4NativeDiagnosticsJournal $journalPath $Context.AttemptId

    if ($termination -ceq 'START_FAILED') {
        # No child existed, so zero mutation is proved rather than assumed.
        return (Complete-C4NativeAttempt $Context 'NOT_RUN' 'LIVE' `
            @('LIVE_START_FAILED', 'LIVE_PREMUTATION_FAILURE') $issued 0 $Identity)
    }

    if ($termination -ceq 'TIMEOUT' -or $termination -ceq 'CAPTURE_FAILED') {
        if (-not (Test-C4NativeContainmentProof $containmentPath 'LIVE' $Context.AttemptId)) {
            Stop-C4NativeUnsealable 'the live child could not be proved contained'
        }
        $recovery = Invoke-C4NativeCleanupRecovery $Context $Options $ToolLeases $journalPath $containmentPath
        $reasons = @()
        if ($termination -ceq 'TIMEOUT') { $reasons += 'LIVE_TIMEOUT' } else { $reasons += 'LIVE_CAPTURE_FAILED' }
        if ($null -ne $recovery) {
            if ([string]$recovery.Status -ceq 'REFUSED') { $reasons += 'LIVE_RECOVERY_CLEANUP_REFUSED' }
            elseif ([string]$recovery.Status -cne 'PASS') { $reasons += 'LIVE_RECOVERY_CLEANUP_FAILED' }
        }
        if (-not $journal.Valid) {
            $reasons += 'LIVE_MUTATION_STATE_UNKNOWN'
            $reasons += 'LIVE_WORKFLOW_FAILED'
            return (Complete-C4NativeAttempt $Context 'FAIL' 'LIVE' $reasons $issued 0 $Identity)
        }
        if ([int]$journal.MutationAttempts -eq 0) {
            $reasons += 'LIVE_PREMUTATION_FAILURE'
            return (Complete-C4NativeAttempt $Context 'NOT_RUN' 'LIVE' $reasons $issued 0 $Identity)
        }
        $reasons += 'LIVE_WORKFLOW_FAILED'
        return (Complete-C4NativeAttempt $Context 'FAIL' 'LIVE' $reasons $issued ([int]$journal.MutationAttempts) $Identity)
    }

    # NORMAL. The public object is the only thing that can carry a PASS.
    $parsed = $null
    try {
        $utf8 = New-Object System.Text.UTF8Encoding $false
        $parsed = ($utf8.GetString([IO.File]::ReadAllBytes($stdoutPath))).Trim() | ConvertFrom-Json
    } catch {
        $parsed = $null
    }
    $mutations = 0
    if ($journal.Valid) { $mutations = [int]$journal.MutationAttempts }
    if ([int]$record.observedExit -ne 0 -or $null -eq $parsed -or
        $parsed.schema -cne $script:PublicSmokeSchema) {
        $reasons = @('LIVE_OUTPUT_INVALID')
        if (-not $journal.Valid) {
            $reasons += 'LIVE_MUTATION_STATE_UNKNOWN'
            $reasons += 'LIVE_WORKFLOW_FAILED'
            return (Complete-C4NativeAttempt $Context 'FAIL' 'LIVE' $reasons $issued 0 $Identity)
        }
        if ($mutations -eq 0) {
            $reasons += 'LIVE_PREMUTATION_FAILURE'
            return (Complete-C4NativeAttempt $Context 'NOT_RUN' 'LIVE' $reasons $issued 0 $Identity)
        }
        $reasons += 'LIVE_WORKFLOW_FAILED'
        return (Complete-C4NativeAttempt $Context 'FAIL' 'LIVE' $reasons $issued $mutations $Identity)
    }
    $probes = @($parsed.probes)
    $failing = @(@($probes) | Where-Object { [string]$_.status -cne 'PASS' })
    if (@($probes).Count -ne 27 -or @($failing).Count -ne 0 -or [string]$parsed.overall -cne 'PASS') {
        $reasons = @('LIVE_WORKFLOW_FAILED')
        if (-not $journal.Valid) { $reasons += 'LIVE_MUTATION_STATE_UNKNOWN' }
        return (Complete-C4NativeAttempt $Context 'FAIL' 'LIVE' $reasons $issued $mutations $Identity)
    }
    if (-not $journal.Valid -or $mutations -le 0) {
        # A PASS needs positive authenticated mutation attempts: a workflow that
        # claims success without a journal proved nothing about the machine.
        return (Complete-C4NativeAttempt $Context 'FAIL' 'LIVE' `
            @('LIVE_MUTATION_STATE_UNKNOWN', 'LIVE_WORKFLOW_FAILED') $issued 0 $Identity)
    }
    if ($null -eq $Identity) {
        throw 'a PASS attempt requires the complete bound candidate identity'
    }
    return (Complete-C4NativeAttempt $Context 'PASS' 'COMPLETE' @() $issued $mutations $Identity)
}

# ---------------------------------------------------------------------------
# CleanupOnly
#
# Bounded owned-resource recovery, delegated to the smoke driver's private
# cleanup parameter set. It proves only that the named service and DOS name
# were released after successful process containment; it never converts a
# post-mutation live failure into NOT RUN.
# ---------------------------------------------------------------------------

function Invoke-C4NativeCleanupRecovery {
    param($Context, $Options, $ToolLeases, [string]$JournalPath, [string]$ContainmentProofPath)

    $liveDirectory = Join-Path $Context.AttemptRoot 'live'
    $dosName = Get-C4NativeOwnedDosNameFromJournal $JournalPath $Context.AttemptId
    if ([string]::IsNullOrWhiteSpace($dosName)) {
        # `UNAVAILABLE` is never supplied as an argument: it is the semantic
        # result of a header that cannot yield a name, and it forces REFUSED
        # with zero cleanup mutation.
        $result = [ordered]@{
            schema = $script:CleanupResultSchema
            version = 1
            attemptId = $Context.AttemptId
            status = 'REFUSED'
            reason = 'the diagnostics header yielded no owned DOS name'
            ownedServiceName = ('fsring-c4-' + $Context.AttemptId)
            ownedDosName = 'UNAVAILABLE'
        }
        Write-C4NativeExclusiveBytes (Join-Path $liveDirectory 'cleanup-recovery.json') `
            (Get-C4NativeCanonicalBytes $result)
        return [pscustomobject]@{ Status = 'REFUSED' }
    }

    $nativeRunner = Join-Path $Context.RepoRoot ($script:NativeRunnerRelativePath -replace '/', '\')
    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $nativeRunner,
        '-Mode', 'CleanupOnly',
        '-AttemptDirectory', $Context.AttemptRoot,
        '-AttemptId', $Context.AttemptId,
        '-ExpectedNativeRunnerSha256', (Get-C4NativeSha256File $nativeRunner),
        '-CandidateManifestPath', $Context.CandidatePath,
        '-ExpectedCandidateManifestSha256', $Context.CandidateSha256,
        '-DiagnosticsJournalPath', $JournalPath,
        '-ContainmentProofPath', $ContainmentProofPath,
        '-ExpectedContainmentProofSha256', (Get-C4NativeSha256File $ContainmentProofPath),
        '-CleanupEvidencePath', (Join-Path $liveDirectory 'cleanup-recovery.json'),
        '-OwnedServiceName', ('fsring-c4-' + $Context.AttemptId),
        '-OwnedDosName', $dosName
    )
    $stdoutPath = Join-Path $Context.AttemptRoot 'cleanup-recovery.stdout.bin'
    $stderrPath = Join-Path $Context.AttemptRoot 'cleanup-recovery.stderr.bin'
    $exitPath = Join-Path $Context.AttemptRoot 'cleanup-recovery.exit.json'
    $cleanupContainment = Join-Path $Context.AttemptRoot 'cleanup-process-containment.json'
    Invoke-C4NativeCapture $Context.Adapters $ToolLeases['powershell'].Path $arguments `
        $Context.RepoRoot 900000 $stdoutPath $stderrPath $exitPath 'CanonicalJson' `
        $cleanupContainment 'CLEANUP_RECOVERY' $Context.AttemptId

    $record = Read-C4NativeCapturedExit $exitPath
    $termination = [string]$record.termination
    if ($termination -ceq 'TIMEOUT' -or $termination -ceq 'CAPTURE_FAILED') {
        if (-not (Test-C4NativeContainmentProof $cleanupContainment 'CLEANUP_RECOVERY' $Context.AttemptId)) {
            Stop-C4NativeUnsealable 'the cleanup recovery child could not be proved contained'
        }
        return [pscustomobject]@{ Status = 'FAILED' }
    }
    if ($termination -ceq 'START_FAILED') {
        return [pscustomobject]@{ Status = 'REFUSED' }
    }
    $resultPath = Join-Path $liveDirectory 'cleanup-recovery.json'
    if (-not [IO.File]::Exists($resultPath)) { return [pscustomobject]@{ Status = 'FAILED' } }
    $result = $null
    try {
        $result = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($resultPath)) `
            -ExpectedSchema $script:CleanupResultSchema
    } catch {
        return [pscustomobject]@{ Status = 'FAILED' }
    }
    return [pscustomobject]@{ Status = [string]$result.status }
}

function Get-C4NativeOwnedDosNameFromJournal {
    param([string]$Path, [string]$AttemptId)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.File]::Exists($Path)) { return $null }
    $lines = @()
    try { $lines = @([IO.File]::ReadAllLines($Path)) } catch { return $null }
    foreach ($line in $lines) {
        $trimmed = ([string]$line).Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        $header = $null
        try { $header = $trimmed | ConvertFrom-Json } catch { return $null }
        if ([string]$header.attemptId -cne $AttemptId) { return $null }
        $name = $null
        try { $name = [string]$header.ownedDosName } catch { $name = $null }
        if ([string]::IsNullOrWhiteSpace($name)) { return $null }
        # The name is never rediscovered by enumeration: it must be the exact
        # PID/GUID shape the parent design fixes.
        if ($name -cnotmatch ('^Global\\FsRingC4-[0-9A-F]{8}-' + $AttemptId.ToUpperInvariant() + '$')) {
            return $null
        }
        return $name
    }
    return $null
}

function Invoke-C4NativeCleanupOnly {
    param($Options)

    $attemptId = Assert-C4NativeAttemptId $Options.AttemptId
    [void](Assert-C4NativeHex $Options.ExpectedNativeRunnerSha256 64 '-ExpectedNativeRunnerSha256')
    $candidatePath = Assert-C4NativeAbsolutePath $Options.CandidateManifestPath '-CandidateManifestPath'
    if (-not [IO.File]::Exists($candidatePath)) { throw '-CandidateManifestPath names no file' }
    if ((Get-C4NativeSha256File $candidatePath) -cne [string]$Options.ExpectedCandidateManifestSha256) {
        throw 'the candidate manifest does not match its expected hash'
    }
    $journalPath = Assert-C4NativeAbsolutePath $Options.DiagnosticsJournalPath '-DiagnosticsJournalPath'
    $proofPath = Assert-C4NativeAbsolutePath $Options.ContainmentProofPath '-ContainmentProofPath'
    if ((Get-C4NativeSha256File $proofPath) -cne [string]$Options.ExpectedContainmentProofSha256) {
        throw 'the live containment proof does not match its expected hash'
    }
    if (-not (Test-C4NativeContainmentProof $proofPath 'LIVE' $attemptId)) {
        throw 'the live containment proof is not an exact PASS for this attempt'
    }
    $evidencePath = Assert-C4NativeAbsolutePath $Options.CleanupEvidencePath '-CleanupEvidencePath'
    if ([IO.File]::Exists($evidencePath)) { throw '-CleanupEvidencePath must be absent' }
    if ([string]$Options.OwnedServiceName -cne ('fsring-c4-' + $attemptId)) {
        throw '-OwnedServiceName must be the attempt-bound service name'
    }
    $dosName = [string]$Options.OwnedDosName
    if ($dosName -ceq 'UNAVAILABLE' -or [string]::IsNullOrWhiteSpace($dosName)) {
        $result = [ordered]@{
            schema = $script:CleanupResultSchema
            version = 1
            attemptId = $attemptId
            status = 'REFUSED'
            reason = 'no owned DOS name was supplied'
            ownedServiceName = [string]$Options.OwnedServiceName
            ownedDosName = 'UNAVAILABLE'
        }
        Write-C4NativeExclusiveBytes $evidencePath (Get-C4NativeCanonicalBytes $result)
        Write-C4NativeStdoutLine (ConvertTo-C4CanonicalJsonText $result)
        return $result
    }

    $journal = Read-C4NativeDiagnosticsJournal $journalPath $attemptId
    if (-not $journal.Valid) {
        $result = [ordered]@{
            schema = $script:CleanupResultSchema
            version = 1
            attemptId = $attemptId
            status = 'REFUSED'
            reason = 'the diagnostics journal is missing or invalid'
            ownedServiceName = [string]$Options.OwnedServiceName
            ownedDosName = $dosName
        }
        Write-C4NativeExclusiveBytes $evidencePath (Get-C4NativeCanonicalBytes $result)
        Write-C4NativeStdoutLine (ConvertTo-C4CanonicalJsonText $result)
        return $result
    }

    $smokePath = Join-Path $Options.RepoRoot ($script:SmokeDriverRelativePath -replace '/', '\')
    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $smokePath,
        '-CleanupOnly', '-C4',
        '-AttemptId', $attemptId,
        '-CandidateManifestPath', $candidatePath,
        '-ExpectedCandidateManifestSha256', [string]$Options.ExpectedCandidateManifestSha256,
        '-DiagnosticsJournalPath', $journalPath,
        '-ContainmentProofPath', $proofPath,
        '-ExpectedContainmentProofSha256', [string]$Options.ExpectedContainmentProofSha256,
        '-CleanupEvidencePath', $evidencePath,
        '-OwnedServiceName', [string]$Options.OwnedServiceName,
        '-OwnedDosName', $dosName
    )
    $workspace = [IO.Path]::GetDirectoryName($evidencePath)
    $stdoutPath = Join-Path $workspace 'cleanup-delegate.stdout.bin'
    $stderrPath = Join-Path $workspace 'cleanup-delegate.stderr.bin'
    $exitPath = Join-Path $workspace 'cleanup-delegate.exit.json'
    $powerShell = Join-Path $PSHOME 'powershell.exe'
    if ($null -ne $Options.ToolOverrides -and $Options.ToolOverrides.Contains('powershell')) {
        $powerShell = [string]$Options.ToolOverrides['powershell']
    }
    Invoke-C4NativeCapture $Options.Adapters $powerShell $arguments $Options.RepoRoot 900000 `
        $stdoutPath $stderrPath $exitPath 'CanonicalJson'
    $record = Read-C4NativeCapturedExit $exitPath
    $status = 'FAILED'
    if ([string]$record.termination -ceq 'NORMAL' -and [int]$record.observedExit -eq 0) { $status = 'PASS' }
    if (-not [IO.File]::Exists($evidencePath)) {
        $result = [ordered]@{
            schema = $script:CleanupResultSchema
            version = 1
            attemptId = $attemptId
            status = $status
            reason = ('the smoke driver cleanup terminated ' + $record.termination)
            ownedServiceName = [string]$Options.OwnedServiceName
            ownedDosName = $dosName
        }
        Write-C4NativeExclusiveBytes $evidencePath (Get-C4NativeCanonicalBytes $result)
        Write-C4NativeStdoutLine (ConvertTo-C4CanonicalJsonText $result)
        return $result
    }
    $result = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($evidencePath)) `
        -ExpectedSchema $script:CleanupResultSchema
    Write-C4NativeStdoutLine (ConvertTo-C4CanonicalJsonText $result)
    return $result
}

# ---------------------------------------------------------------------------
# Self-test
#
# Fake SCM, DOS, process, package and preflight adapters. No fixture installs a
# service, creates a DOS name, loads a driver, or writes a real evidence root.
# What is NOT faked is every decision this script owns: the bootstrap rules,
# candidate resolution, the artifact check, the bounded sidecar scan, the
# containment gates, the reason roster ordering, and the sealed manifests.
#
# `$script:NativeFakeState` is a script-scope record rather than a closure so
# that a fixture's behaviour is visible at the call site instead of captured.
# ---------------------------------------------------------------------------

$script:NativeFakeState = $null

function Reset-C4NativeFakeState {
    param($World)
    $script:NativeFakeState = [pscustomobject]@{
        World = $World
        IsAncestor = $true
        DiffPaths = @('docs/superpowers/reviews/evidence/c4-recovery-native/index.json')
        HeadCommit = ('a' * 40)
        HostIdentity = $World.HostIdentity
        BootIdentity = $World.BootIdentity
        VerifierTermination = 'NORMAL'
        VerifierExit = 0
        VerifierSemantic = 'PASS'
        VerifierSignatureMode = 'UntrustedTestRoot'
        VerifierCatalogValid = $true
        PreflightTermination = 'NORMAL'
        PreflightExit = 2
        PreflightRunnable = $true
        PreflightEmitReasonCodes = $true
        PreflightMutations = 0
        PreflightSidecarFiles = @()
        PreflightContainmentPass = $true
        LiveTermination = 'NORMAL'
        LiveExit = 0
        LiveProbeFailures = 0
        LiveContainmentPass = $true
        LiveJournalRecords = 3
        LiveJournalValid = $true
        LiveJournalDosName = $null
        CleanupTermination = 'NORMAL'
        CleanupStatus = 'PASS'
    }
}

function New-C4NativeFakeAdapters {
    param([string]$RepoRoot)
    return [pscustomobject]@{
        RepoRoot = $RepoRoot
        Git = {
            param([string[]]$Arguments, [string]$WorkingDirectory)
            $state = $script:NativeFakeState
            $joined = (@($Arguments) -join ' ')
            if ($joined -ceq 'rev-parse HEAD') {
                return [pscustomobject]@{ ExitCode = 0; Stdout = ($state.HeadCommit + "`n"); Stderr = '' }
            }
            if ($joined.StartsWith('merge-base --is-ancestor', [StringComparison]::Ordinal)) {
                return [pscustomobject]@{ ExitCode = $(if ($state.IsAncestor) { 0 } else { 1 }); Stdout = ''; Stderr = '' }
            }
            if ($joined.StartsWith('diff --name-only', [StringComparison]::Ordinal)) {
                return [pscustomobject]@{ ExitCode = 0; Stdout = ((@($state.DiffPaths) -join "`n") + "`n"); Stderr = '' }
            }
            if ($joined -ceq ('rev-parse ' + $state.World.BootstrapCommit + '^{tree}')) {
                return [pscustomobject]@{ ExitCode = 0; Stdout = ($state.World.BootstrapTree + "`n"); Stderr = '' }
            }
            if ($joined.StartsWith('rev-parse ', [StringComparison]::Ordinal) -and $joined.Contains(':')) {
                $spec = $joined.Substring('rev-parse '.Length)
                $relative = $spec.Substring($spec.IndexOf(':') + 1)
                $path = Join-Path $state.World.RepoRoot ($relative -replace '/', '\')
                if (-not [IO.File]::Exists($path)) {
                    return [pscustomobject]@{ ExitCode = 1; Stdout = ''; Stderr = 'no such path' }
                }
                $blob = Get-C4GitBlobId ([IO.File]::ReadAllBytes($path))
                if ($state.World.BlobOverrides.Contains($relative)) {
                    $blob = [string]$state.World.BlobOverrides[$relative]
                }
                return [pscustomobject]@{ ExitCode = 0; Stdout = ($blob + "`n"); Stderr = '' }
            }
            return [pscustomobject]@{ ExitCode = 1; Stdout = ''; Stderr = 'unhandled fixture git call' }
        }
        HostIdentity = { return $script:NativeFakeState.HostIdentity }
        BootIdentity = { return $script:NativeFakeState.BootIdentity }
        CaptureProcess = {
            param($Executable, $Arguments, $WorkingDirectory, $TimeoutMilliseconds,
                  $StdoutPath, $StderrPath, $ExitPath, $ExitFormat,
                  $ContainmentEvidencePath, $ContainmentRole, $ContainmentAttemptId)
            $state = $script:NativeFakeState
            $joined = (@($Arguments) -join ' ')
            $utf8 = New-Object System.Text.UTF8Encoding $false
            $stdout = New-Object byte[] 0
            $termination = 'NORMAL'
            $observed = 0
            $containmentPass = $true

            if ($joined.Contains('verify_fsring_package.ps1')) {
                $termination = $state.VerifierTermination
                $observed = [int]$state.VerifierExit
                if ($termination -ceq 'NORMAL') {
                    # This is the exact shape verify_fsring_package.ps1 emits.
                    # A fixture that invents friendlier keys cannot see the
                    # orchestrator reading keys nobody produces.
                    $signMode = [string]$state.VerifierSignatureMode
                    $signExit = $(if ($signMode -ceq 'Trusted') { 0 } else { 1 })
                    $stdout = $utf8.GetBytes((ConvertTo-C4CanonicalJsonText ([ordered]@{
                        schema = 'fsring-package-verifier/v1'
                        overall = [string]$state.VerifierSemantic
                        errors = @()
                        warnings = @()
                        trustReady = $false
                        artifacts = [ordered]@{
                            'fsring_fsd.inf' = $true
                            'fsring_fsd.sys' = $true
                            'fsring_fsd.cat' = $true
                        }
                        tools = [ordered]@{
                            infverif = [ordered]@{
                                path = 'C:/fixture/infverif.exe'
                                productVersion = '10.0.0.0'
                                fileVersion = '10.0.0.0'
                                exitCode = 0
                            }
                            signtool = [ordered]@{
                                path = 'C:/fixture/signtool.exe'
                                productVersion = '10.0.0.0'
                                fileVersion = '10.0.0.0'
                                policy = 'KernelMode'
                                sysExitCode = $signExit
                                sysMode = $signMode
                                catExitCode = $signExit
                                catMode = $signMode
                                catalogMemberExitCode = $signExit
                                catalogMemberMode = $signMode
                            }
                            catalogMembership = [ordered]@{
                                mechanism = 'Windows CryptCAT member-hash'
                                valid = [bool]$state.VerifierCatalogValid
                                memberHash = ('0' * 64)
                            }
                        }
                    })) + "`n")
                }
            } elseif ($joined.Contains('-PreflightOnly')) {
                $termination = $state.PreflightTermination
                $observed = [int]$state.PreflightExit
                $containmentPass = [bool]$state.PreflightContainmentPass
                $evidenceDirectory = Get-C4NativeFakeArgumentValue $Arguments '-EvidenceDirectory'
                foreach ($name in @($state.PreflightSidecarFiles)) {
                    $path = Join-Path $evidenceDirectory $name
                    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
                    [IO.File]::WriteAllBytes($path, $utf8.GetBytes('sidecar:' + $name))
                }
                if ($termination -ceq 'NORMAL') {
                    $stdout = $utf8.GetBytes((ConvertTo-C4CanonicalJsonText ([ordered]@{
                        schema = 'fsring-c4-preflight-orchestration/v1'
                        version = 1
                        overall = 'NOT RUN'
                        sourceCommit = $state.World.CandidateCommit
                        sourceTree = $state.World.CandidateTree
                        candidateManifestSha256 = $state.World.CandidateSha256
                        preflight = $(if ($state.PreflightEmitReasonCodes) {
                            [ordered]@{
                                runnable = [bool]$state.PreflightRunnable
                                reasonCodes = @(@() + $(if ($state.PreflightRunnable) { @() } else { @('NOT_ELEVATED') }))
                            }
                        } else {
                            [ordered]@{ runnable = [bool]$state.PreflightRunnable }
                        })
                        ownership = [ordered]@{ mutationAttempts = [int]$state.PreflightMutations }
                    })) + "`n")
                }
            } elseif ($joined.Contains('-CleanupOnly')) {
                $termination = $state.CleanupTermination
                $observed = 0
                $evidencePath = Get-C4NativeFakeArgumentValue $Arguments '-CleanupEvidencePath'
                if ($termination -ceq 'NORMAL' -and -not [string]::IsNullOrWhiteSpace($evidencePath)) {
                    Write-C4NativeExclusiveBytes $evidencePath (Get-C4NativeCanonicalBytes ([ordered]@{
                        schema = $script:CleanupResultSchema
                        version = 1
                        attemptId = (Get-C4NativeFakeArgumentValue $Arguments '-AttemptId')
                        status = [string]$state.CleanupStatus
                        reason = 'fixture cleanup'
                        ownedServiceName = (Get-C4NativeFakeArgumentValue $Arguments '-OwnedServiceName')
                        ownedDosName = (Get-C4NativeFakeArgumentValue $Arguments '-OwnedDosName')
                    }))
                }
            } elseif ($joined.Contains('smoke_driver.ps1')) {
                $termination = $state.LiveTermination
                $observed = [int]$state.LiveExit
                $containmentPass = [bool]$state.LiveContainmentPass
                $evidenceDirectory = Get-C4NativeFakeArgumentValue $Arguments '-EvidenceDirectory'
                $attemptId = Get-C4NativeFakeArgumentValue $Arguments '-AttemptId'
                if (-not [string]::IsNullOrWhiteSpace($evidenceDirectory)) {
                    New-C4NativeFakeJournal $evidenceDirectory $attemptId $state
                }
                if ($termination -ceq 'NORMAL') {
                    $probes = New-Object System.Collections.ArrayList
                    for ($i = 1; $i -le 27; $i++) {
                        $status = 'PASS'
                        if ($i -le [int]$state.LiveProbeFailures) { $status = 'FAIL' }
                        [void]$probes.Add([ordered]@{ ordinal = $i; status = $status })
                    }
                    $overall = 'PASS'
                    if ([int]$state.LiveProbeFailures -gt 0) { $overall = 'FAIL' }
                    $stdout = $utf8.GetBytes((ConvertTo-C4CanonicalJsonText ([ordered]@{
                        schema = $script:PublicSmokeSchema
                        version = 2
                        overall = $overall
                        probes = @($probes)
                    })) + "`n")
                }
            } elseif ($joined.Contains('run_c4_native_attempt.ps1')) {
                # The nested CleanupOnly child. The fixture answers it directly
                # rather than re-entering this script, so a recursion bug cannot
                # hide behind a green run.
                $termination = $state.CleanupTermination
                $observed = 0
                $evidencePath = Get-C4NativeFakeArgumentValue $Arguments '-CleanupEvidencePath'
                if ($termination -ceq 'NORMAL' -and -not [string]::IsNullOrWhiteSpace($evidencePath) -and
                    -not [IO.File]::Exists($evidencePath)) {
                    Write-C4NativeExclusiveBytes $evidencePath (Get-C4NativeCanonicalBytes ([ordered]@{
                        schema = $script:CleanupResultSchema
                        version = 1
                        attemptId = (Get-C4NativeFakeArgumentValue $Arguments '-AttemptId')
                        status = [string]$state.CleanupStatus
                        reason = 'fixture nested cleanup'
                        ownedServiceName = (Get-C4NativeFakeArgumentValue $Arguments '-OwnedServiceName')
                        ownedDosName = (Get-C4NativeFakeArgumentValue $Arguments '-OwnedDosName')
                    }))
                }
            }

            [IO.File]::WriteAllBytes($StdoutPath, [byte[]]$stdout)
            [IO.File]::WriteAllBytes($StderrPath, (New-Object byte[] 0))
            if ($ExitFormat -ceq 'CodeText') {
                $text = switch ($termination) {
                    'NORMAL' { ([int]$observed).ToString() + "`n" }
                    default { $termination + "`n" }
                }
                [IO.File]::WriteAllBytes($ExitPath, $utf8.GetBytes($text))
            } else {
                $exitValue = $null
                if ($termination -ceq 'NORMAL') { $exitValue = [int]$observed }
                [IO.File]::WriteAllBytes($ExitPath, (Get-C4NativeCanonicalBytes ([ordered]@{
                    schema = $script:CapturedExitSchema
                    version = 1
                    observedExit = $exitValue
                    timedOut = ($termination -ceq 'TIMEOUT')
                    termination = $termination
                })))
            }
            if (-not [string]::IsNullOrWhiteSpace($ContainmentEvidencePath) -and
                ($termination -ceq 'TIMEOUT' -or $termination -ceq 'CAPTURE_FAILED')) {
                if ($containmentPass) {
                    Write-C4NativeExclusiveBytes $ContainmentEvidencePath (Get-C4NativeCanonicalBytes ([ordered]@{
                        schema = $script:ContainmentSchema
                        version = 1
                        attemptId = $ContainmentAttemptId
                        captureRole = $ContainmentRole
                        childProcessId = 4242
                        createdSuspended = $true
                        jobKillOnClose = $true
                        breakawayDisabled = $true
                        jobAssignedBeforeResume = $true
                        mainThreadResumed = $true
                        terminationAttempted = $true
                        treeExited = $true
                        streamsClosed = $true
                        status = 'PASS'
                    }))
                }
            }
        }
    }
}

function Get-C4NativeFakeArgumentValue {
    param($Arguments, [string]$Name)
    $list = @($Arguments)
    for ($i = 0; $i -lt $list.Count - 1; $i++) {
        if ([string]$list[$i] -ceq $Name) { return [string]$list[$i + 1] }
    }
    return $null
}

function New-C4NativeFakeJournal {
    param([string]$EvidenceDirectory, [string]$AttemptId, $State)

    if (-not $State.LiveJournalValid) { return }
    [void][IO.Directory]::CreateDirectory($EvidenceDirectory)
    $dos = [string]$State.LiveJournalDosName
    if ([string]::IsNullOrWhiteSpace($dos)) {
        $dos = 'Global\FsRingC4-0000109A-' + $AttemptId.ToUpperInvariant()
    }
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add((ConvertTo-C4CanonicalJsonText ([ordered]@{
        schema = 'fsring-c4-live-diagnostics/v1'
        version = 1
        attemptId = $AttemptId
        ownedDosName = $dos
    })))
    for ($i = 1; $i -le [int]$State.LiveJournalRecords; $i++) {
        [void]$lines.Add((ConvertTo-C4CanonicalJsonText ([ordered]@{
            ordinal = $i
            operation = 'MUTATION_ATTEMPT'
        })))
    }
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [IO.File]::WriteAllBytes((Join-Path $EvidenceDirectory 'diagnostics.sidecar.jsonl'),
        $utf8.GetBytes((@($lines) -join "`n") + "`n"))
}

function New-C4NativeTestWorld {
    param([string]$Root, [string]$Name)

    $world = Join-Path $Root $Name
    $repo = Join-Path $world 'repo'
    $tools = Join-Path $world 'tools'
    $external = Join-Path $world 'ext'
    $evidence = Join-Path $repo ($script:EvidenceRootRelative -replace '/', '\')
    $attemptId = '00112233445566778899aabbccddeeff'
    $candidateAttemptId = 'ffeeddccbbaa99887766554433221100'
    $candidateCommit = ('b' * 40)
    $candidateTree = ('c' * 40)
    $candidateRelative = ('attempt-' + $candidateTree + '-' + $candidateAttemptId)
    $candidateAttempt = Join-Path $evidence $candidateRelative
    foreach ($directory in @($repo, $tools, $external, $evidence, $candidateAttempt,
        (Join-Path $repo 'driver\scripts'),
        (Join-Path $candidateAttempt 'commands'),
        (Join-Path $candidateAttempt 'artifacts\win10-x64-release\package'),
        (Join-Path $candidateAttempt 'artifacts\archives'))) {
        [void][IO.Directory]::CreateDirectory($directory)
    }
    $utf8 = New-Object System.Text.UTF8Encoding $false

    $scriptFiles = [ordered]@{
        'run_c4_native_attempt.ps1' = '# fixture native runner'
        'invoke_c4_evidence.ps1' = '# fixture capture helper'
        'record_c4_evidence.ps1' = '# fixture recorder'
        'verify_fsring_package.ps1' = '# fixture package verifier'
        'smoke_driver.ps1' = '# fixture smoke driver'
    }
    foreach ($name in @($scriptFiles.Keys)) {
        [IO.File]::WriteAllBytes((Join-Path $repo ('driver\scripts\' + $name)),
            $utf8.GetBytes([string]$scriptFiles[$name] + "`n"))
    }
    $hash = { param([string]$Relative) return (Get-C4NativeSha256File (Join-Path $repo ($Relative -replace '/', '\'))) }

    # --- the candidate artifacts ---------------------------------------
    $memberRows = New-Object System.Collections.ArrayList
    foreach ($name in @('fsring_fsd.inf', 'fsring_fsd.sys', 'fsring_fsd.cat', 'fsring_fsd.pdb', 'fsring_fsd.map', 'WDRLocalTestCert.cer')) {
        $path = Join-Path $candidateAttempt ('artifacts\win10-x64-release\package\' + $name)
        [IO.File]::WriteAllBytes($path, $utf8.GetBytes('member:' + $name))
        $bytes = [IO.File]::ReadAllBytes($path)
        [void]$memberRows.Add([ordered]@{
            relativePath = ('artifacts/win10-x64-release/package/' + $name)
            bytes = [int64]$bytes.Length
            sha256 = (Get-C4EvidenceSha256Hex $bytes)
        })
    }
    $harnessPath = Join-Path $candidateAttempt 'artifacts\win10-x64-release\fsring-control-smoke.exe'
    [IO.File]::WriteAllBytes($harnessPath, $utf8.GetBytes('harness'))
    $abiPath = Join-Path $candidateAttempt 'artifacts\archives\fsring-abi.zip'
    [IO.File]::WriteAllBytes($abiPath, $utf8.GetBytes('abi-zip'))
    $specPath = Join-Path $candidateAttempt 'artifacts\archives\fsring-spec.zip'
    [IO.File]::WriteAllBytes($specPath, $utf8.GetBytes('spec-zip'))

    $fileRow = {
        param([string]$Relative, [string]$Absolute)
        $bytes = [IO.File]::ReadAllBytes($Absolute)
        return [ordered]@{
            relativePath = $Relative
            bytes = [int64]$bytes.Length
            sha256 = (Get-C4EvidenceSha256Hex $bytes)
        }
    }
    $packageSet = Get-C4EvidenceSha256Hex (Get-C4NativeCanonicalBytes ([ordered]@{
        schema = 'fsring-c4-package-set/v1'; version = 1; members = @($memberRows)
    }))
    $artifacts = [ordered]@{
        package = [ordered]@{
            relativePath = 'artifacts/win10-x64-release/package'
            setSha256 = $packageSet
            members = @($memberRows)
        }
        inf = $memberRows[0]; sys = $memberRows[1]; cat = $memberRows[2]
        pdb = $memberRows[3]; map = $memberRows[4]; certificate = $memberRows[5]
        harness = (& $fileRow 'artifacts/win10-x64-release/fsring-control-smoke.exe' $harnessPath)
        abiArchive = (& $fileRow 'artifacts/archives/fsring-abi.zip' $abiPath)
        specArchive = (& $fileRow 'artifacts/archives/fsring-spec.zip' $specPath)
    }
    $smokeBytes = [IO.File]::ReadAllBytes((Join-Path $repo 'driver\scripts\smoke_driver.ps1'))
    $candidate = [ordered]@{
        schema = $script:CandidateSchema
        version = 1
        attemptId = $candidateAttemptId
        sourceCommit = $candidateCommit
        sourceTree = $candidateTree
        gateManifestSha256 = ('d' * 64)
        commandIndexSha256 = ('e' * 64)
        profile = [ordered]@{
            id = 'win10-x64-release'; target = 'x86_64-pc-windows-msvc'
            driverFeature = 'platform-win10'; cargoProfile = 'release'; machine = '0x8664'
        }
        tools = @()
        packageVerifier = [ordered]@{
            schema = 'fsring-c4-package-verification/v1'
            scriptRelativePath = $script:VerifierRelativePath
            scriptSha256 = (& $hash $script:VerifierRelativePath)
        }
        smokeDriver = [ordered]@{
            relativePath = $script:SmokeDriverRelativePath
            bytes = [int64]$smokeBytes.Length
            sha256 = (Get-C4EvidenceSha256Hex $smokeBytes)
        }
        artifacts = $artifacts
        artifactSetSha256 = (Get-C4EvidenceSha256Hex (Get-C4NativeCanonicalBytes $artifacts))
    }
    $candidateBytes = Get-C4NativeCanonicalBytes $candidate
    [IO.File]::WriteAllBytes((Join-Path $evidence $script:CandidateName), $candidateBytes)
    $candidateSha = Get-C4EvidenceSha256Hex $candidateBytes

    # --- row 01's authenticated self-test object -------------------------
    $row01 = [ordered]@{
        schema = $script:SourceRunnerSelfTestSchema
        version = 1
        sourceRunnerSha256 = ('1' * 64)
        nativeRunnerSha256 = (& $hash $script:NativeRunnerRelativePath)
        captureHelperSha256 = (& $hash $script:CaptureHelperRelativePath)
        recorderSha256 = (& $hash $script:RecorderRelativePath)
        nativeExit = 0
        nativeStdoutSha256 = ('2' * 64)
        nativeStderrSha256 = ('3' * 64)
        recorderExit = 0
        recorderStdoutSha256 = ('4' * 64)
        recorderStderrSha256 = ('5' * 64)
        status = 'PASS'
    }
    [IO.File]::WriteAllBytes((Join-Path $candidateAttempt 'commands\01-source-runner-selftest.stdout.bin'),
        $utf8.GetBytes((ConvertTo-C4CanonicalJsonText $row01) + "`n"))
    [IO.File]::WriteAllBytes((Join-Path $candidateAttempt 'commands\01-source-runner-selftest.exit.json'),
        (Get-C4NativeCanonicalBytes ([ordered]@{
            schema = $script:CapturedExitSchema; version = 1
            observedExit = 0; timedOut = $false; termination = 'NORMAL'
        })))

    # --- the ledger --------------------------------------------------------
    $index = [ordered]@{
        schema = $script:SourceIndexSchema
        attempts = @(@([ordered]@{
            attemptId = $candidateAttemptId
            sourceCommit = $candidateCommit
            sourceTree = $candidateTree
            relativePath = $candidateRelative
            gateStatus = 'PASS'
            attemptManifestSha256 = ('6' * 64)
            candidateManifestSha256 = $candidateSha
            nativeReviewRelativePath = ('reviews/' + $candidateAttemptId + '/native-review.md')
            nativeReviewSha256 = ('7' * 64)
            evidenceReviewRelativePath = ('reviews/' + $candidateAttemptId + '/evidence-review.md')
            evidenceReviewSha256 = ('8' * 64)
            reviewStatus = 'PASS'
            sourceVerdictRelativePath = ('reviews/' + $candidateAttemptId + '/source-verdict.md')
            sourceVerdictSha256 = ('9' * 64)
            sourceVerdict = 'PASS'
        }))
        eligibilityEvents = @(@([ordered]@{
            ordinal = 1
            previousAttemptId = $null
            eligibleAttemptId = $candidateAttemptId
            candidateManifestSha256 = $candidateSha
            reason = 'INITIAL_PASS'
            sourceVerdictSha256 = ('9' * 64)
        }))
        eligibleCandidateAttemptId = $candidateAttemptId
    }
    [IO.File]::WriteAllBytes((Join-Path $evidence $script:SourceIndexName), (Get-C4NativeCanonicalBytes $index))

    $toolPaths = [ordered]@{}
    foreach ($role in $script:LocalToolRoles) {
        $path = Join-Path $tools ($role + '.tool')
        [IO.File]::WriteAllBytes($path, $utf8.GetBytes('local:' + $role))
        $toolPaths[$role] = [IO.Path]::GetFullPath($path)
    }

    return [pscustomobject]@{
        Root = [IO.Path]::GetFullPath($world)
        RepoRoot = [IO.Path]::GetFullPath($repo)
        External = [IO.Path]::GetFullPath($external)
        EvidenceRoot = [IO.Path]::GetFullPath($evidence)
        CandidateAttempt = [IO.Path]::GetFullPath($candidateAttempt)
        CandidateSha256 = $candidateSha
        CandidateAttemptId = $candidateAttemptId
        CandidateCommit = $candidateCommit
        CandidateTree = $candidateTree
        AttemptId = $attemptId
        AttemptRoot = [IO.Path]::GetFullPath((Join-Path $external ('native-' + $attemptId)))
        BootstrapCommit = $candidateCommit
        BootstrapTree = $candidateTree
        ToolPaths = $toolPaths
        BlobOverrides = [ordered]@{}
        HostIdentity = [ordered]@{
            machineGuid = '11111111-2222-3333-4444-555555555555'
            computerName = 'C4-SELFTEST'
            osBuild = '19045'
            architecture = 'AMD64'
            processArchitecture = 'AMD64'
        }
        BootIdentity = [ordered]@{
            bootId = '66666666777788889999000011112222'
            bootTimeUtc = '2026-08-24T00:00:00Z'
        }
        ExpectedNativeRunnerSha256 = (Get-C4NativeSha256File (Join-Path $repo ($script:NativeRunnerRelativePath -replace '/', '\')))
        ExpectedCaptureHelperSha256 = (Get-C4NativeSha256File (Join-Path $repo ($script:CaptureHelperRelativePath -replace '/', '\')))
        ExpectedRecorderSha256 = (Get-C4NativeSha256File (Join-Path $repo ($script:RecorderRelativePath -replace '/', '\')))
    }
}

function New-C4NativeTestOptions {
    param($World, [string]$Mode = 'Inspect')
    return [pscustomobject]@{
        Mode = $Mode
        RepoRoot = $World.RepoRoot
        Adapters = (New-C4NativeFakeAdapters $World.RepoRoot)
        AuthorizedExternalParent = $World.External
        OutputDirectory = $World.AttemptRoot
        AttemptId = $World.AttemptId
        BootstrapSourceCommit = $World.BootstrapCommit
        BootstrapSourceTree = $World.BootstrapTree
        ExpectedNativeRunnerSha256 = $World.ExpectedNativeRunnerSha256
        ExpectedCaptureHelperSha256 = $World.ExpectedCaptureHelperSha256
        ExpectedRecorderSha256 = $World.ExpectedRecorderSha256
        PackageDirectory = $null
        HarnessPath = $null
        AttemptDirectory = $World.AttemptRoot
        ExpectedInspectionSha256 = $null
        ExpectedAuthorizationSha256 = $null
        AuthorizationReference = 'fixture authority 2026-08-24'
        AuthorizedAtUtc = '2026-08-24T12:00:00Z'
        NativeReviewSha256 = ('7' * 64)
        EvidenceReviewSha256 = ('8' * 64)
        ToolOverrides = $World.ToolPaths
        CandidateManifestPath = $null
        ExpectedCandidateManifestSha256 = $null
        DiagnosticsJournalPath = $null
        ContainmentProofPath = $null
        ExpectedContainmentProofSha256 = $null
        CleanupEvidencePath = $null
        OwnedServiceName = $null
        OwnedDosName = $null
    }
}

function Invoke-C4NativeSelfTests {
    $root = Join-Path $env:TEMP ('c4na-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
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
    # A refusal counts only when it is the refusal the fixture aimed at.
    function Assert-Refuses {
        param([string]$Name, [scriptblock]$Action, [string]$Expect)
        Note $Name
        try {
            [void](& $Action)
            Fail $Name 'accepted what it must refuse'
        } catch {
            if ([string]$_.Exception.Message -cnotmatch [regex]::Escape($Expect)) {
                Fail $Name ('refused for the wrong reason (' + $_.Exception.Message + ')')
            }
        }
    }
    function New-World {
        $ordinal.Value += 1
        $world = New-C4NativeTestWorld $root ('n' + $ordinal.Value.ToString())
        Reset-C4NativeFakeState $world
        return $world
    }
    function Read-Sealed {
        param($World, [string]$Name)
        $path = Join-Path $World.AttemptRoot $Name
        if (-not [IO.File]::Exists($path)) { return $null }
        return (ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($path)))
    }
    function Assert-SealedAttempt {
        param([string]$Name, $World, [string]$Status, [string]$Phase, [string[]]$Reasons)
        Note $Name
        $manifest = Read-Sealed $World 'attempt.json'
        if ($null -eq $manifest) { Fail $Name 'no attempt.json was sealed'; return $null }
        if ([string]$manifest.status -cne $Status) {
            Fail $Name ('status is ' + $manifest.status + ', expected ' + $Status)
            return $manifest
        }
        if ([string]$manifest.phase -cne $Phase) {
            Fail $Name ('phase is ' + $manifest.phase + ', expected ' + $Phase)
            return $manifest
        }
        foreach ($reason in @($Reasons)) {
            if (@($manifest.reasonCodes) -cnotcontains $reason) {
                Fail $Name ('reason ' + $reason + ' is absent from ' + (@($manifest.reasonCodes) -join ','))
            }
        }
        return $manifest
    }

    try {
        # --- Inspect: the runnable reference path -------------------------
        $world = New-World
        $options = New-C4NativeTestOptions $world
        $result = Invoke-C4NativeInspect $options
        Assert-Ok 'a runnable inspection publishes PENDING_AUTHORIZATION' (
            [string]$result.state -ceq 'PENDING_AUTHORIZATION' -and [bool]$result.runnable)
        $pending = Read-Sealed $world 'pending-inspection.json'
        Assert-Ok 'the pending state carries the closed eight-operation roster' (
            $null -ne $pending -and
            ((@($pending.authorizationOperations) -join ',') -ceq ($script:AuthorizationOperations -join ',')))
        Assert-Ok 'the pending state names the attempt-bound service' (
            $null -ne $pending -and [string]$pending.ownedServiceName -ceq ('fsring-c4-' + $world.AttemptId))
        Assert-Ok 'the pending state carries the literal DOS pattern, not a transient name' (
            $null -ne $pending -and
            [string]$pending.ownedDosPattern -ceq 'Global\FsRingC4-<retained-worker-pid:08X>-<uppercase-attemptId>')
        Assert-Ok 'a runnable inspection seals no attempt' (
            $null -eq (Read-Sealed $world 'attempt.json'))
        $bootstrap = Read-Sealed $world 'bootstrap.json'
        Assert-Ok 'bootstrap.json binds the pinned pair and three script blobs' (
            $null -ne $bootstrap -and
            [string]$bootstrap.sourceCommit -ceq $world.BootstrapCommit -and
            [string]$bootstrap.sourceTree -ceq $world.BootstrapTree -and
            @($bootstrap.files).Count -eq 3)
        $artifact = Read-Sealed $world 'artifact-initial.json'
        Assert-Ok 'the initial artifact check passes with nine expected rows' (
            $null -ne $artifact -and [string]$artifact.status -ceq 'PASS' -and
            @($artifact.expected.files).Count -eq 9 -and @($artifact.actual.files).Count -eq 9)
        Assert-Ok 'the artifact check records three local tool rows' (
            $null -ne $artifact -and @($artifact.tools).Count -eq 3)
        Assert-Ok 'the artifact check records four source-input rows' (
            $null -ne $artifact -and @($artifact.sourceInputs).Count -eq 4)
        $sidecars = Read-Sealed $world 'preflight-initial-sidecars.json'
        Assert-Ok 'a conforming preflight leaves an EMPTY sidecar observation' (
            $null -ne $sidecars -and [string]$sidecars.status -ceq 'EMPTY' -and
            [int]$sidecars.entryCountLowerBound -eq 0 -and -not [bool]$sidecars.truncated)

        $pendingWorld = $world
        $pendingSha = (Get-C4NativeSha256File (Join-Path $world.AttemptRoot 'pending-inspection.json'))

        # --- Authorize / SealNotRun ---------------------------------------
        $authorizeOptions = New-C4NativeTestOptions $pendingWorld 'Authorize'
        $authorizeOptions.ExpectedInspectionSha256 = $pendingSha
        $authorization = Invoke-C4NativeAuthorize $authorizeOptions
        Assert-Ok 'authorization reports the pending and authorization hashes' (
            [string]$authorization.inspectionSha256 -ceq $pendingSha -and
            [string]$authorization.authorizationSha256 -cmatch '^[0-9a-f]{64}$')
        $authorizationDocument = Read-Sealed $pendingWorld 'authorization.json'
        Assert-Ok 'authorization records the closed operation roster in order' (
            $null -ne $authorizationDocument -and
            ((@($authorizationDocument.operations) -join ',') -ceq ($script:AuthorizationOperations -join ',')))
        Assert-Refuses 'a second authorization refuses' {
            Invoke-C4NativeAuthorize $authorizeOptions
        } 'already authorized'

        $wrongHashOptions = New-C4NativeTestOptions $pendingWorld 'Authorize'
        $wrongHashOptions.ExpectedInspectionSha256 = ('0' * 64)
        Assert-Refuses 'a wrong inspection hash refuses authorization' {
            Invoke-C4NativeAuthorize $wrongHashOptions
        } 'does not match its expected hash'

        # --- Inspect refusals ---------------------------------------------
        $world = New-World
        $options = New-C4NativeTestOptions $world
        $script:NativeFakeState.IsAncestor = $false
        Assert-Refuses 'a nonancestor bootstrap refuses' { Invoke-C4NativeInspect $options } 'not an ancestor of current HEAD'
        Assert-Ok 'a nonancestor refusal creates no attempt' (-not [IO.Directory]::Exists($world.AttemptRoot))

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $script:NativeFakeState.DiffPaths = @('driver/fsring-core/src/lib.rs')
        Assert-Refuses 'a non-evidence diff refuses' { Invoke-C4NativeInspect $options } 'a non-evidence path changed'

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $options.ExpectedRecorderSha256 = ('0' * 64)
        Assert-Refuses 'a wrong expected recorder hash refuses' {
            Invoke-C4NativeInspect $options
        } 'does not equal its mandatory expected SHA-256'

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $world.BlobOverrides['driver/scripts/invoke_c4_evidence.ps1'] = ('f' * 40)
        Assert-Refuses 'a bootstrap blob mismatch refuses' {
            Invoke-C4NativeInspect $options
        } 'does not equal its pinned bootstrap blob'

        $world = New-World
        $options = New-C4NativeTestOptions $world
        [void][IO.Directory]::CreateDirectory($world.AttemptRoot)
        Assert-Refuses 'an existing output directory refuses' { Invoke-C4NativeInspect $options } '-OutputDirectory must be absent'

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $options.AttemptId = 'not-a-guid'
        Assert-Refuses 'a malformed attempt ID refuses' { Invoke-C4NativeInspect $options } 'attempt ID must be a lowercase GUID-N'

        # --- Inspect: unbound NOT RUN branches ------------------------------
        foreach ($case in @(
            @('no ledger', { param($w) Remove-Item -LiteralPath (Join-Path $w.EvidenceRoot 'index.json') -Force }, 'ELIGIBLE_CANDIDATE_MISSING'),
            @('an unparseable ledger', { param($w)
                $utf8 = New-Object System.Text.UTF8Encoding $false
                [IO.File]::WriteAllBytes((Join-Path $w.EvidenceRoot 'index.json'), $utf8.GetBytes("not json`n")) }, 'SOURCE_LEDGER_INVALID'),
            @('a drifted candidate manifest', { param($w)
                $utf8 = New-Object System.Text.UTF8Encoding $false
                [IO.File]::WriteAllBytes((Join-Path $w.EvidenceRoot 'candidate-artifacts.json'), $utf8.GetBytes("{}`n")) }, 'CANDIDATE_MANIFEST_INVALID')
        )) {
            $world = New-World
            $options = New-C4NativeTestOptions $world
            & $case[1] $world
            $result = Invoke-C4NativeInspect $options
            Assert-Ok ('an invalid candidate seals NOT RUN: ' + $case[0]) (
                [string]$result.state -ceq 'SEALED_NOT_RUN' -and -not [bool]$result.runnable -and
                $null -eq $result.inspectionSha256)
            $manifest = Assert-SealedAttempt ('the sealed reason names the cause: ' + $case[0]) `
                $world 'NOT_RUN' 'ARTIFACT_INITIAL' @($case[2])
            Assert-Ok ('an unbound attempt nulls all eight identity fields: ' + $case[0]) (
                $null -ne $manifest -and
                @(@($script:CandidateIdentityKeys) | Where-Object { $null -ne $manifest.$_ }).Count -eq 0)
            Assert-Ok ('an unbound attempt still binds the bootstrap: ' + $case[0]) (
                $null -ne $manifest -and
                [string]$manifest.bootstrapSourceCommit -ceq $world.BootstrapCommit -and
                [string]$manifest.bootstrapSha256 -cmatch '^[0-9a-f]{64}$')
            $notRun = Read-Sealed $world 'not-run.json'
            Assert-Ok ('not-run.json mirrors the attempt reasons: ' + $case[0]) (
                $null -ne $notRun -and $null -ne $manifest -and
                ((@($notRun.reasonCodes) -join ',') -ceq (@($manifest.reasonCodes) -join ',')) -and
                [int]$notRun.mutationAttempts -eq 0)
        }

        # --- Inspect: artifact observations ---------------------------------
        $world = New-World
        $options = New-C4NativeTestOptions $world
        Remove-Item -LiteralPath (Join-Path $world.CandidateAttempt 'artifacts\archives\fsring-abi.zip') -Force
        [void](Invoke-C4NativeInspect $options)
        $manifest = Assert-SealedAttempt 'a missing artifact seals ARTIFACT_MISSING' `
            $world 'NOT_RUN' 'ARTIFACT_INITIAL' @('ARTIFACT_MISSING')
        $artifact = Read-Sealed $world 'artifact-initial.json'
        Assert-Ok 'a missing artifact keeps its logical path and nulls its measurements' (
            $null -ne $artifact -and
            (@(@($artifact.actual.files) | Where-Object { -not [bool]$_.present })[0].relativePath -ceq 'artifacts/archives/fsring-abi.zip') -and
            $null -eq @(@($artifact.actual.files) | Where-Object { -not [bool]$_.present })[0].sha256)
        Assert-Ok 'a missing artifact leaves both set hashes null' (
            $null -ne $artifact -and $null -eq $artifact.actual.artifactSetSha256 -and
            $null -eq $artifact.actual.packageSetSha256)

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $utf8 = New-Object System.Text.UTF8Encoding $false
        [IO.File]::WriteAllBytes((Join-Path $world.CandidateAttempt 'artifacts\archives\fsring-spec.zip'), $utf8.GetBytes('tampered'))
        [void](Invoke-C4NativeInspect $options)
        [void](Assert-SealedAttempt 'a tampered artifact seals ARTIFACT_HASH_MISMATCH' `
            $world 'NOT_RUN' 'ARTIFACT_INITIAL' @('ARTIFACT_HASH_MISMATCH'))

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $options.PackageDirectory = (Join-Path $world.CandidateAttempt 'artifacts\win10-x64-release\package')
        [IO.File]::WriteAllBytes((Join-Path $options.PackageDirectory 'extra.bin'), $utf8.GetBytes('extra'))
        [void](Invoke-C4NativeInspect $options)
        [void](Assert-SealedAttempt 'an extra package member seals ARTIFACT_EXTRA' `
            $world 'NOT_RUN' 'ARTIFACT_INITIAL' @('ARTIFACT_EXTRA'))

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $overrides = [ordered]@{}
        foreach ($role in $script:LocalToolRoles) { $overrides[$role] = $world.ToolPaths[$role] }
        $overrides['signtool'] = Join-Path $world.Root 'absent-signtool.exe'
        $options.ToolOverrides = $overrides
        [void](Invoke-C4NativeInspect $options)
        [void](Assert-SealedAttempt 'a missing local tool seals TOOL_MISSING' `
            $world 'NOT_RUN' 'ARTIFACT_INITIAL' @('TOOL_MISSING'))

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $script:NativeFakeState.VerifierTermination = 'TIMEOUT'
        [void](Invoke-C4NativeInspect $options)
        [void](Assert-SealedAttempt 'a verifier timeout seals PACKAGE_VERIFIER_TIMEOUT' `
            $world 'NOT_RUN' 'ARTIFACT_INITIAL' @('PACKAGE_VERIFIER_TIMEOUT'))

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $script:NativeFakeState.VerifierSemantic = 'FAIL'
        [void](Invoke-C4NativeInspect $options)
        [void](Assert-SealedAttempt 'a verifier semantic failure seals PACKAGE_VERIFIER_FAILED' `
            $world 'NOT_RUN' 'ARTIFACT_INITIAL' @('PACKAGE_VERIFIER_FAILED'))

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $script:NativeFakeState.VerifierSignatureMode = 'PartiallyTrusted'
        [void](Invoke-C4NativeInspect $options)
        [void](Assert-SealedAttempt 'an out-of-roster signature mode seals PACKAGE_VERIFIER_FAILED' `
            $world 'NOT_RUN' 'ARTIFACT_INITIAL' @('PACKAGE_VERIFIER_FAILED'))

        # A WDRLocalTestCert package on a host prepared for test signing reports
        # the Microsoft-root policy refusal on all three kernel-policy probes.
        # That triple is intact signature evidence, not a verifier failure.
        function New-LocalTrustVerifierFixture {
            param([string]$SysMode, [string]$CatMode, [string]$MemberMode, [int]$Exit)
            return [pscustomobject]@{
                overall = 'PASS'
                tools = [pscustomobject]@{
                    signtool = [pscustomobject]@{
                        policy = 'KernelMode'
                        sysExitCode = $Exit
                        sysMode = $SysMode
                        catExitCode = $Exit
                        catMode = $CatMode
                        catalogMemberExitCode = $Exit
                        catalogMemberMode = $MemberMode
                    }
                    catalogMembership = [pscustomobject]@{
                        mechanism = 'Windows CryptCAT member-hash'
                        valid = $true
                        memberHash = ('A' * 64)
                    }
                }
            }
        }
        Assert-Ok 'a locally trusted kernel-policy triple is intact signature evidence' (
            (Get-C4NativeVerifierSemantics (New-LocalTrustVerifierFixture 'TestSignedLocallyTrusted' 'TestSignedLocallyTrusted' 'TestSignedLocallyTrusted' 1)).Signature -ceq 'PASS')
        Assert-Ok 'a locally trusted mode mixed with an untrusted mode is not intact' (
            (Get-C4NativeVerifierSemantics (New-LocalTrustVerifierFixture 'TestSignedLocallyTrusted' 'UntrustedTestRoot' 'TestSignedLocallyTrusted' 1)).Signature -ceq 'FAIL')
        Assert-Ok 'a locally trusted mode reported with exit zero is not intact' (
            (Get-C4NativeVerifierSemantics (New-LocalTrustVerifierFixture 'TestSignedLocallyTrusted' 'TestSignedLocallyTrusted' 'TestSignedLocallyTrusted' 0)).Signature -ceq 'FAIL')

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $script:NativeFakeState.VerifierSignatureMode = 'TestSignedLocallyTrusted'
        $locallyTrustedResult = Invoke-C4NativeInspect $options
        Assert-Ok 'a locally trusted package reaches a runnable pending inspection' (
            [string]$locallyTrustedResult.state -ceq 'PENDING_AUTHORIZATION' -and [bool]$locallyTrustedResult.runnable)

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $script:NativeFakeState.PreflightRunnable = $false
        $script:NativeFakeState.PreflightEmitReasonCodes = $false
        [void](Invoke-C4NativeInspect $options)
        [void](Assert-SealedAttempt 'a preflight without reasonCodes still seals PREFLIGHT_NOT_RUNNABLE' `
            $world 'NOT_RUN' 'PREFLIGHT_INITIAL' @('PREFLIGHT_NOT_RUNNABLE'))

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $script:NativeFakeState.VerifierCatalogValid = $false
        [void](Invoke-C4NativeInspect $options)
        [void](Assert-SealedAttempt 'an invalid catalog membership seals PACKAGE_VERIFIER_FAILED' `
            $world 'NOT_RUN' 'ARTIFACT_INITIAL' @('PACKAGE_VERIFIER_FAILED'))

        $world = New-World
        $options = New-C4NativeTestOptions $world
        [IO.File]::WriteAllBytes((Join-Path $world.RepoRoot 'driver\scripts\smoke_driver.ps1'), $utf8.GetBytes('# swapped'))
        [void](Invoke-C4NativeInspect $options)
        [void](Assert-SealedAttempt 'a swapped smoke driver seals SOURCE_IDENTITY_DRIFT' `
            $world 'NOT_RUN' 'ARTIFACT_INITIAL' @('SOURCE_IDENTITY_DRIFT'))

        # --- Inspect: preflight observations ---------------------------------
        $world = New-World
        $options = New-C4NativeTestOptions $world
        $script:NativeFakeState.PreflightRunnable = $false
        [void](Invoke-C4NativeInspect $options)
        [void](Assert-SealedAttempt 'a not-runnable preflight seals PREFLIGHT_NOT_RUNNABLE' `
            $world 'NOT_RUN' 'PREFLIGHT_INITIAL' @('PREFLIGHT_NOT_RUNNABLE', 'NOT_ELEVATED'))

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $script:NativeFakeState.PreflightMutations = 2
        [void](Invoke-C4NativeInspect $options)
        [void](Assert-SealedAttempt 'a mutating preflight seals FAIL with a contract violation' `
            $world 'FAIL' 'PREFLIGHT_INITIAL' @('PREFLIGHT_MUTATION_DETECTED', 'SOURCE_CONTRACT_VIOLATION'))

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $script:NativeFakeState.PreflightSidecarFiles = @('stray.bin')
        [void](Invoke-C4NativeInspect $options)
        [void](Assert-SealedAttempt 'a preflight sidecar seals FAIL with a contract violation' `
            $world 'FAIL' 'PREFLIGHT_INITIAL' @('PREFLIGHT_SIDECAR_DETECTED', 'SOURCE_CONTRACT_VIOLATION'))
        $sidecars = Read-Sealed $world 'preflight-initial-sidecars.json'
        Assert-Ok 'an unexpected sidecar is captured within the bounds' (
            $null -ne $sidecars -and [string]$sidecars.status -ceq 'CAPTURED' -and
            @($sidecars.entries).Count -eq 1 -and
            [string]@($sidecars.entries)[0].kind -ceq 'FILE' -and
            -not [string]::IsNullOrWhiteSpace([string]@($sidecars.entries)[0].contentBase64))

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $script:NativeFakeState.PreflightSidecarFiles = @(1..70 | ForEach-Object { 'f' + $_ + '.bin' })
        [void](Invoke-C4NativeInspect $options)
        $sidecars = Read-Sealed $world 'preflight-initial-sidecars.json'
        Assert-Ok 'an oversized sidecar set is bounded as OVERFLOW' (
            $null -ne $sidecars -and [string]$sidecars.status -ceq 'OVERFLOW' -and
            [bool]$sidecars.truncated -and @($sidecars.entries).Count -le $script:SidecarMaxEntries -and
            [int]$sidecars.entryCountLowerBound -ge 70)

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $script:NativeFakeState.PreflightTermination = 'TIMEOUT'
        [void](Invoke-C4NativeInspect $options)
        [void](Assert-SealedAttempt 'a contained preflight timeout seals PREFLIGHT_TIMEOUT' `
            $world 'NOT_RUN' 'PREFLIGHT_INITIAL' @('PREFLIGHT_TIMEOUT'))

        $world = New-World
        $options = New-C4NativeTestOptions $world
        $script:NativeFakeState.PreflightTermination = 'TIMEOUT'
        $script:NativeFakeState.PreflightContainmentPass = $false
        Assert-Refuses 'an unproved preflight tree is unsealable' {
            Invoke-C4NativeInspect $options
        } 'could not be proved contained'
        Assert-Ok 'an unsealable preflight seals nothing' (
            $null -eq (Read-Sealed $world 'attempt.json'))

        # --- Run -------------------------------------------------------------
        function New-AuthorizedWorld {
            $world = New-World
            $options = New-C4NativeTestOptions $world
            [void](Invoke-C4NativeInspect $options)
            $sha = (Get-C4NativeSha256File (Join-Path $world.AttemptRoot 'pending-inspection.json'))
            $authorize = New-C4NativeTestOptions $world 'Authorize'
            $authorize.ExpectedInspectionSha256 = $sha
            [void](Invoke-C4NativeAuthorize $authorize)
            $run = New-C4NativeTestOptions $world 'Run'
            $run.ExpectedInspectionSha256 = $sha
            $run.ExpectedAuthorizationSha256 = (Get-C4NativeSha256File (Join-Path $world.AttemptRoot 'authorization.json'))
            return [pscustomobject]@{ World = $world; RunOptions = $run; PendingSha256 = $sha }
        }

        $case = New-AuthorizedWorld
        [void](Invoke-C4NativeRun $case.RunOptions)
        $manifest = Assert-SealedAttempt 'a complete live workflow seals PASS' `
            $case.World 'PASS' 'COMPLETE' @()
        Assert-Ok 'a PASS binds all eight candidate identity fields' (
            $null -ne $manifest -and
            @(@($script:CandidateIdentityKeys) | Where-Object { $null -eq $manifest.$_ }).Count -eq 0)
        Assert-Ok 'a PASS issues all three commands and counts mutations' (
            $null -ne $manifest -and [bool]$manifest.commandIssued.initialPreflight -and
            [bool]$manifest.commandIssued.finalPreflight -and [bool]$manifest.commandIssued.live -and
            [bool]$manifest.liveIssued -and [int]$manifest.mutationAttempts -eq 3)
        Assert-Ok 'a PASS writes no not-run.json' (
            $null -eq (Read-Sealed $case.World 'not-run.json'))
        $roster = Read-Sealed $case.World 'attempt-files.json'
        Assert-Ok 'the native roster excludes itself and attempt.json' (
            $null -ne $roster -and
            @(@($roster.files) | Where-Object { $_.relativePath -ceq 'attempt.json' -or $_.relativePath -ceq 'attempt-files.json' }).Count -eq 0)

        $case = New-AuthorizedWorld
        $script:NativeFakeState.HostIdentity = [ordered]@{
            machineGuid = '99999999-8888-7777-6666-555555555555'
            computerName = 'OTHER-HOST'; osBuild = '19045'
            architecture = 'AMD64'; processArchitecture = 'AMD64'
        }
        [void](Invoke-C4NativeRun $case.RunOptions)
        [void](Assert-SealedAttempt 'a host change seals HOST_IDENTITY_DRIFT' `
            $case.World 'NOT_RUN' 'AUTHORIZATION' @('HOST_IDENTITY_DRIFT', 'AUTHORIZATION_TUPLE_MISMATCH'))

        $case = New-AuthorizedWorld
        $script:NativeFakeState.BootIdentity = [ordered]@{
            bootId = 'aaaabbbbccccddddeeeeffff00001111'; bootTimeUtc = '2026-08-25T00:00:00Z'
        }
        [void](Invoke-C4NativeRun $case.RunOptions)
        [void](Assert-SealedAttempt 'a reboot seals BOOT_IDENTITY_DRIFT' `
            $case.World 'NOT_RUN' 'AUTHORIZATION' @('BOOT_IDENTITY_DRIFT', 'AUTHORIZATION_TUPLE_MISMATCH'))

        $case = New-AuthorizedWorld
        $script:NativeFakeState.LiveTermination = 'START_FAILED'
        [void](Invoke-C4NativeRun $case.RunOptions)
        [void](Assert-SealedAttempt 'an unstartable live child seals pre-mutation NOT RUN' `
            $case.World 'NOT_RUN' 'LIVE' @('LIVE_START_FAILED', 'LIVE_PREMUTATION_FAILURE'))

        $case = New-AuthorizedWorld
        $script:NativeFakeState.LiveTermination = 'TIMEOUT'
        $script:NativeFakeState.LiveJournalRecords = 0
        [void](Invoke-C4NativeRun $case.RunOptions)
        [void](Assert-SealedAttempt 'a contained live timeout with zero journalled mutations is NOT RUN' `
            $case.World 'NOT_RUN' 'LIVE' @('LIVE_TIMEOUT', 'LIVE_PREMUTATION_FAILURE'))

        $case = New-AuthorizedWorld
        $script:NativeFakeState.LiveTermination = 'TIMEOUT'
        $script:NativeFakeState.LiveJournalRecords = 4
        [void](Invoke-C4NativeRun $case.RunOptions)
        $manifest = Assert-SealedAttempt 'a contained live timeout after mutation is FAIL' `
            $case.World 'FAIL' 'LIVE' @('LIVE_TIMEOUT', 'LIVE_WORKFLOW_FAILED')
        Assert-Ok 'a post-mutation live failure keeps its authenticated count' (
            $null -ne $manifest -and [int]$manifest.mutationAttempts -eq 4)

        $case = New-AuthorizedWorld
        $script:NativeFakeState.LiveTermination = 'TIMEOUT'
        $script:NativeFakeState.LiveJournalValid = $false
        [void](Invoke-C4NativeRun $case.RunOptions)
        [void](Assert-SealedAttempt 'an unknown mutation state after containment is FAIL, never NOT RUN' `
            $case.World 'FAIL' 'LIVE' @('LIVE_MUTATION_STATE_UNKNOWN', 'LIVE_WORKFLOW_FAILED'))

        $case = New-AuthorizedWorld
        $script:NativeFakeState.LiveTermination = 'TIMEOUT'
        $script:NativeFakeState.LiveContainmentPass = $false
        Assert-Refuses 'an unproved live tree is unsealable' {
            Invoke-C4NativeRun $case.RunOptions
        } 'could not be proved contained'
        Assert-Ok 'an unsealable live attempt seals nothing' (
            $null -eq (Read-Sealed $case.World 'attempt.json'))

        $case = New-AuthorizedWorld
        $script:NativeFakeState.LiveProbeFailures = 1
        [void](Invoke-C4NativeRun $case.RunOptions)
        [void](Assert-SealedAttempt 'a failing probe seals LIVE_WORKFLOW_FAILED' `
            $case.World 'FAIL' 'LIVE' @('LIVE_WORKFLOW_FAILED'))

        $case = New-AuthorizedWorld
        $script:NativeFakeState.LiveJournalValid = $false
        [void](Invoke-C4NativeRun $case.RunOptions)
        [void](Assert-SealedAttempt 'a claimed PASS without a journal is FAIL' `
            $case.World 'FAIL' 'LIVE' @('LIVE_MUTATION_STATE_UNKNOWN', 'LIVE_WORKFLOW_FAILED'))

        $case = New-AuthorizedWorld
        $script:NativeFakeState.LiveTermination = 'TIMEOUT'
        $script:NativeFakeState.LiveJournalDosName = 'Global\WrongName'
        $script:NativeFakeState.LiveJournalRecords = 2
        [void](Invoke-C4NativeRun $case.RunOptions)
        $recovery = $null
        $recoveryPath = Join-Path $case.World.AttemptRoot 'live\cleanup-recovery.json'
        if ([IO.File]::Exists($recoveryPath)) {
            $recovery = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($recoveryPath))
        }
        Assert-Ok 'an unusable DOS name forces REFUSED with zero cleanup mutation' (
            $null -ne $recovery -and [string]$recovery.status -ceq 'REFUSED' -and
            [string]$recovery.ownedDosName -ceq 'UNAVAILABLE')

        # --- SealNotRun -------------------------------------------------------
        $world = New-World
        $options = New-C4NativeTestOptions $world
        [void](Invoke-C4NativeInspect $options)
        $sealOptions = New-C4NativeTestOptions $world 'SealNotRun'
        $sealOptions.ExpectedInspectionSha256 = (Get-C4NativeSha256File (Join-Path $world.AttemptRoot 'pending-inspection.json'))
        [void](Invoke-C4NativeSealNotRun $sealOptions)
        $manifest = Assert-SealedAttempt 'a declined authority seals AUTHORIZATION_MISSING' `
            $world 'NOT_RUN' 'AUTHORIZATION' @('AUTHORIZATION_MISSING')
        Assert-Ok 'a declined attempt issues no live command' (
            $null -ne $manifest -and -not [bool]$manifest.liveIssued -and
            -not [bool]$manifest.commandIssued.finalPreflight)

        $world = New-World
        $options = New-C4NativeTestOptions $world
        [void](Invoke-C4NativeInspect $options)
        $runOptions = New-C4NativeTestOptions $world 'Run'
        $runOptions.ExpectedInspectionSha256 = (Get-C4NativeSha256File (Join-Path $world.AttemptRoot 'pending-inspection.json'))
        $runOptions.ExpectedAuthorizationSha256 = ('0' * 64)
        Assert-Refuses 'Run without an authorization refuses' {
            Invoke-C4NativeRun $runOptions
        } 'requires an authorization recorded for this exact attempt'

        # --- CleanupOnly -------------------------------------------------------
        $world = New-World
        $cleanupOptions = New-C4NativeTestOptions $world 'CleanupOnly'
        $cleanupOptions.AttemptId = $world.AttemptId
        $cleanupOptions.CandidateManifestPath = (Join-Path $world.EvidenceRoot 'candidate-artifacts.json')
        $cleanupOptions.ExpectedCandidateManifestSha256 = $world.CandidateSha256
        $workspace = Join-Path $world.External 'cleanup'
        [void][IO.Directory]::CreateDirectory($workspace)
        $journalPath = Join-Path $workspace 'diagnostics.sidecar.jsonl'
        New-C4NativeFakeJournal $workspace $world.AttemptId $script:NativeFakeState
        $proofPath = Join-Path $workspace 'process-containment.json'
        Write-C4NativeExclusiveBytes $proofPath (Get-C4NativeCanonicalBytes ([ordered]@{
            schema = $script:ContainmentSchema; version = 1
            attemptId = $world.AttemptId; captureRole = 'LIVE'; childProcessId = 4242
            createdSuspended = $true; jobKillOnClose = $true; breakawayDisabled = $true
            jobAssignedBeforeResume = $true; mainThreadResumed = $true
            terminationAttempted = $true; treeExited = $true; streamsClosed = $true
            status = 'PASS'
        }))
        $cleanupOptions.DiagnosticsJournalPath = $journalPath
        $cleanupOptions.ContainmentProofPath = $proofPath
        $cleanupOptions.ExpectedContainmentProofSha256 = (Get-C4NativeSha256File $proofPath)
        $cleanupOptions.CleanupEvidencePath = (Join-Path $workspace 'cleanup-recovery.json')
        $cleanupOptions.OwnedServiceName = ('fsring-c4-' + $world.AttemptId)
        $cleanupOptions.OwnedDosName = ('Global\FsRingC4-0000109A-' + $world.AttemptId.ToUpperInvariant())
        $cleanup = Invoke-C4NativeCleanupOnly $cleanupOptions
        Assert-Ok 'a bounded cleanup reports PASS through the smoke driver' (
            [string]$cleanup.status -ceq 'PASS')

        $unavailableOptions = New-C4NativeTestOptions $world 'CleanupOnly'
        foreach ($name in @('AttemptId', 'CandidateManifestPath', 'ExpectedCandidateManifestSha256',
                            'DiagnosticsJournalPath', 'ContainmentProofPath',
                            'ExpectedContainmentProofSha256', 'OwnedServiceName')) {
            $unavailableOptions.$name = $cleanupOptions.$name
        }
        $unavailableOptions.CleanupEvidencePath = (Join-Path $workspace 'cleanup-unavailable.json')
        $unavailableOptions.OwnedDosName = 'UNAVAILABLE'
        $refused = Invoke-C4NativeCleanupOnly $unavailableOptions
        Assert-Ok 'an UNAVAILABLE DOS name refuses with zero mutation' (
            [string]$refused.status -ceq 'REFUSED' -and [string]$refused.ownedDosName -ceq 'UNAVAILABLE')

        $badProofOptions = New-C4NativeTestOptions $world 'CleanupOnly'
        foreach ($name in @('AttemptId', 'CandidateManifestPath', 'ExpectedCandidateManifestSha256',
                            'DiagnosticsJournalPath', 'ContainmentProofPath', 'OwnedServiceName', 'OwnedDosName')) {
            $badProofOptions.$name = $cleanupOptions.$name
        }
        $badProofOptions.ExpectedContainmentProofSha256 = ('0' * 64)
        $badProofOptions.CleanupEvidencePath = (Join-Path $workspace 'cleanup-badproof.json')
        Assert-Refuses 'a mismatching containment proof refuses cleanup' {
            Invoke-C4NativeCleanupOnly $badProofOptions
        } 'does not match its expected hash'

        # --- roster ordering ---------------------------------------------------
        Note 'reason codes serialize in roster order, not observation order'
        $ordered = Get-C4NativeOrderedReasons @('LIVE_WORKFLOW_FAILED', 'ARTIFACT_MISSING', 'TOOL_MISSING', 'ARTIFACT_MISSING')
        if ((@($ordered) -join ',') -cne 'ARTIFACT_MISSING,TOOL_MISSING,LIVE_WORKFLOW_FAILED') {
            Fail 'reason codes serialize in roster order, not observation order' (@($ordered) -join ',')
        }
        Assert-Refuses 'an unknown reason code refuses' {
            Get-C4NativeOrderedReasons @('NOT_A_REASON')
        } 'illegal native reason code'

        # --- production adapters ----------------------------------------
        # Every fixture above drives a fake adapter, and a fake adapter
        # cannot see a .NET API that does not exist on this host. These
        # cases call the real production adapter Inspect actually uses.
        $productionAdapters = New-C4NativeProductionAdapters $root
        $gitVersion = $null
        $gitVersionError = $null
        try { $gitVersion = & $productionAdapters.Git @('--version') $root }
        catch { $gitVersionError = [string]$_.Exception.Message }
        Assert-Ok 'the production Git adapter starts a real child on this host' ($null -eq $gitVersionError) ('adapter threw: ' + [string]$gitVersionError)
        Assert-Ok 'the production Git adapter reports a real exit code and stdout' ($null -ne $gitVersion -and [int]$gitVersion.ExitCode -eq 0 -and [string]$gitVersion.Stdout -cmatch 'git version')
        # Round-trip tricky argument values through git's own echo so the
        # command line this adapter builds is checked, not just its exit.
        foreach ($awkward in @('fs ring', 'fs"ring', 'C:\\dir\\', 'plain')) {
            $name = 'the production Git adapter round-trips [' + $awkward + ']'
            $echoed = $null
            $echoedError = $null
            try {
                $echoed = & $productionAdapters.Git @('-c', ('user.name=' + $awkward), 'config', '--get', 'user.name') $root
            } catch { $echoedError = [string]$_.Exception.Message }
            Assert-Ok $name ($null -eq $echoedError -and $null -ne $echoed -and [int]$echoed.ExitCode -eq 0 -and ([string]$echoed.Stdout).TrimEnd("`r`n") -ceq $awkward) ('error=[' + [string]$echoedError + '] stdout=[' + [string]$(if ($null -ne $echoed) { ([string]$echoed.Stdout).TrimEnd("`r`n") }) + ']')
        }
    } finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
    return [pscustomobject]@{ Checks = @($checks); Failures = @($failures) }
}

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

if ($script:C4NativeDotSourced) { return }

[Console]::OutputEncoding = (New-Object System.Text.UTF8Encoding $false)

if ($SelfTest) {
    try {
        $outcome = Invoke-C4NativeSelfTests
    } catch {
        [Console]::Error.WriteLine('NATIVE-ATTEMPT SELF-TEST: FAIL: ' + $_.Exception.Message)
        [Console]::Error.WriteLine($_.ScriptStackTrace)
        exit 1
    }
    $status = 'PASS'
    if (@($outcome.Failures).Count -ne 0) { $status = 'FAIL' }
    foreach ($failure in @($outcome.Failures)) {
        [Console]::Error.WriteLine('NATIVE-ATTEMPT SELF-TEST: ' + $failure)
    }
    Write-C4NativeStdoutLine (ConvertTo-C4CanonicalJsonText ([ordered]@{
        schema = $script:SelfTestSchema
        version = 1
        checks = [int]@($outcome.Checks).Count
        failures = @($outcome.Failures)
        status = $status
    }))
    if ($status -ceq 'PASS') { exit 0 }
    exit 1
}

try {
    $repoRoot = Get-C4NativeRepositoryRoot
    $options = [pscustomobject]@{
        Mode = $Mode
        RepoRoot = $repoRoot
        Adapters = (New-C4NativeProductionAdapters $repoRoot)
        AuthorizedExternalParent = $AuthorizedExternalParent
        OutputDirectory = $OutputDirectory
        AttemptId = $AttemptId
        BootstrapSourceCommit = $BootstrapSourceCommit
        BootstrapSourceTree = $BootstrapSourceTree
        ExpectedNativeRunnerSha256 = $ExpectedNativeRunnerSha256
        ExpectedCaptureHelperSha256 = $ExpectedCaptureHelperSha256
        ExpectedRecorderSha256 = $ExpectedRecorderSha256
        PackageDirectory = $PackageDirectory
        HarnessPath = $HarnessPath
        AttemptDirectory = $AttemptDirectory
        ExpectedInspectionSha256 = $ExpectedInspectionSha256
        ExpectedAuthorizationSha256 = $ExpectedAuthorizationSha256
        AuthorizationReference = $AuthorizationReference
        AuthorizedAtUtc = ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
        # The two review hashes come from the eligible ledger row, which
        # Inspect already authenticated; a bound attempt needs both.
        NativeReviewSha256 = $null
        EvidenceReviewSha256 = $null
        ToolOverrides = $null
        CandidateManifestPath = $CandidateManifestPath
        ExpectedCandidateManifestSha256 = $ExpectedCandidateManifestSha256
        DiagnosticsJournalPath = $DiagnosticsJournalPath
        ContainmentProofPath = $ContainmentProofPath
        ExpectedContainmentProofSha256 = $ExpectedContainmentProofSha256
        CleanupEvidencePath = $CleanupEvidencePath
        OwnedServiceName = $OwnedServiceName
        OwnedDosName = $OwnedDosName
    }
    if ($Mode -ceq 'Authorize' -or $Mode -ceq 'SealNotRun' -or $Mode -ceq 'Run') {
        $resolution = Resolve-C4NativeCandidate $repoRoot
        if ($resolution.Resolved) {
            $options.NativeReviewSha256 = [string]$resolution.Row.nativeReviewSha256
            $options.EvidenceReviewSha256 = [string]$resolution.Row.evidenceReviewSha256
        }
    }

    $result = $null
    switch ($Mode) {
        'Inspect' { $result = Invoke-C4NativeInspect $options }
        'Authorize' { $result = Invoke-C4NativeAuthorize $options }
        'SealNotRun' { $result = Invoke-C4NativeSealNotRun $options }
        'Run' { $result = Invoke-C4NativeRun $options }
        'CleanupOnly' { $result = Invoke-C4NativeCleanupOnly $options }
        default { throw ('unreachable mode ' + $Mode) }
    }
    if ($Mode -cne 'Authorize' -and $Mode -cne 'CleanupOnly') {
        Write-C4NativeStdoutLine (ConvertTo-C4CanonicalJsonText $result)
    }
    exit 0
} catch {
    $message = [string]$_.Exception.Message
    if ($message.StartsWith($script:UnsealableSentinel, [StringComparison]::Ordinal)) {
        [Console]::Error.WriteLine('NATIVE-ATTEMPT: UNSEALABLE: ' +
            $message.Substring($script:UnsealableSentinel.Length))
        [Console]::Error.WriteLine('NATIVE-ATTEMPT: nothing was sealed, recorded or committed; recover this host by hand.')
        exit 3
    }
    [Console]::Error.WriteLine('NATIVE-ATTEMPT: FAIL: ' + $message)
    exit 1
}
