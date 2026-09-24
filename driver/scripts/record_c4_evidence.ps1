# The only repository evidence copier, ledger writer, candidate promoter and
# withdrawer, and native publisher for the C4 recovery (Task 28 step 5b).
#
# Nothing else may write under the two evidence roots. Every recording mode
# freezes its own bytes first, verifies the whole incoming hash chain before it
# touches the repository, installs immutable objects with CreateNew semantics,
# and commits through one ledger-last transaction that is recoverable in a
# single direction from any crash cut. `StageReceipt` then re-derives the exact
# changed-path roster from the committed poststate -- not from the receipt it is
# checking -- and stages precisely that.

[CmdletBinding(DefaultParameterSetName = 'SelfTest')]
param(
    [Parameter(ParameterSetName = 'SelfTest', Mandatory = $true)]
    [switch]$SelfTest,

    [Parameter(ParameterSetName = 'RecordSourceAttempt', Mandatory = $true)]
    [Parameter(ParameterSetName = 'FinalizeSourceReview', Mandatory = $true)]
    [Parameter(ParameterSetName = 'WithdrawSourceCandidate', Mandatory = $true)]
    [Parameter(ParameterSetName = 'RecordNativeAttempt', Mandatory = $true)]
    [Parameter(ParameterSetName = 'StageReceipt', Mandatory = $true)]
    [ValidateSet('RecordSourceAttempt', 'FinalizeSourceReview',
        'WithdrawSourceCandidate', 'RecordNativeAttempt', 'StageReceipt')]
    [string]$Mode,

    # Mandatory in every mode: the recorder's own bytes are the trust anchor.
    [Parameter(ParameterSetName = 'RecordSourceAttempt', Mandatory = $true)]
    [Parameter(ParameterSetName = 'FinalizeSourceReview', Mandatory = $true)]
    [Parameter(ParameterSetName = 'WithdrawSourceCandidate', Mandatory = $true)]
    [Parameter(ParameterSetName = 'RecordNativeAttempt', Mandatory = $true)]
    [Parameter(ParameterSetName = 'StageReceipt', Mandatory = $true)]
    [string]$ExpectedRecorderSha256,

    [Parameter(ParameterSetName = 'RecordSourceAttempt', Mandatory = $true)]
    [Parameter(ParameterSetName = 'RecordNativeAttempt', Mandatory = $true)]
    [string]$ExternalAttemptDirectory,

    [Parameter(ParameterSetName = 'RecordSourceAttempt', Mandatory = $true)]
    [Parameter(ParameterSetName = 'FinalizeSourceReview', Mandatory = $true)]
    [Parameter(ParameterSetName = 'RecordNativeAttempt', Mandatory = $true)]
    [Parameter(ParameterSetName = 'StageReceipt', Mandatory = $true)]
    [string]$ExpectedAttemptId,

    [Parameter(ParameterSetName = 'RecordSourceAttempt', Mandatory = $true)]
    [string]$ExpectedSourceCommit,

    [Parameter(ParameterSetName = 'RecordSourceAttempt', Mandatory = $true)]
    [string]$ExpectedSourceTree,

    [Parameter(ParameterSetName = 'RecordSourceAttempt', Mandatory = $true)]
    [Parameter(ParameterSetName = 'FinalizeSourceReview', Mandatory = $true)]
    [Parameter(ParameterSetName = 'WithdrawSourceCandidate', Mandatory = $true)]
    [Parameter(ParameterSetName = 'RecordNativeAttempt', Mandatory = $true)]
    [Parameter(ParameterSetName = 'StageReceipt', Mandatory = $true)]
    [string]$RepositoryEvidenceRoot,

    [Parameter(ParameterSetName = 'RecordSourceAttempt', Mandatory = $true)]
    [Parameter(ParameterSetName = 'FinalizeSourceReview', Mandatory = $true)]
    [Parameter(ParameterSetName = 'WithdrawSourceCandidate', Mandatory = $true)]
    [Parameter(ParameterSetName = 'RecordNativeAttempt', Mandatory = $true)]
    [string]$ReceiptPath,

    [Parameter(ParameterSetName = 'FinalizeSourceReview', Mandatory = $true)]
    [string]$ExpectedCheckpointACommit,

    [Parameter(ParameterSetName = 'FinalizeSourceReview', Mandatory = $true)]
    [string]$NativeReviewPath,

    [Parameter(ParameterSetName = 'FinalizeSourceReview', Mandatory = $true)]
    [string]$EvidenceReviewPath,

    [Parameter(ParameterSetName = 'FinalizeSourceReview', Mandatory = $true)]
    [string]$SourceVerdictPath,

    [Parameter(ParameterSetName = 'WithdrawSourceCandidate', Mandatory = $true)]
    [string]$ExpectedEligibleAttemptId,

    [Parameter(ParameterSetName = 'WithdrawSourceCandidate', Mandatory = $true)]
    [string]$ExpectedCandidateManifestSha256,

    [Parameter(ParameterSetName = 'RecordNativeAttempt', Mandatory = $true)]
    [string]$ExpectedBootstrapSourceCommit,

    [Parameter(ParameterSetName = 'RecordNativeAttempt', Mandatory = $true)]
    [string]$ExpectedBootstrapSourceTree,

    [Parameter(ParameterSetName = 'RecordNativeAttempt', Mandatory = $true)]
    [string]$ExpectedBootstrapSha256,

    [Parameter(ParameterSetName = 'RecordNativeAttempt', Mandatory = $true)]
    [string]$NativeSummaryPath,

    [Parameter(ParameterSetName = 'StageReceipt', Mandatory = $true)]
    [string]$InputReceiptPath,

    [Parameter(ParameterSetName = 'StageReceipt', Mandatory = $true)]
    [ValidateSet('RecordSourceAttempt', 'FinalizeSourceReview',
        'WithdrawSourceCandidate', 'RecordNativeAttempt')]
    [string]$ExpectedRecordedMode
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Read before the import: dot-sourcing the capture helper runs in this scope and
# sets its own `C4EvidenceDotSourced`, so that flag cannot answer "was *this*
# file dot-sourced".
$script:C4RecorderDotSourced = ($MyInvocation.InvocationName -eq '.')
$script:C4RecorderSavedSelfTest = [bool]$SelfTest
if (-not (Get-Variable -Name C4EvidenceDotSourced -Scope Script -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'invoke_c4_evidence.ps1')
}
$SelfTest = [bool]$script:C4RecorderSavedSelfTest

$script:ReceiptSchema = 'fsring-c4-evidence-recorder-receipt/v1'
$script:TransactionSchema = 'fsring-c4-recorder-transaction/v1'
$script:SourceIndexSchema = 'fsring-c4-source-attempt-index/v1'
$script:NativeIndexSchema = 'fsring-c4-native-attempt-index/v1'
$script:SourceAttemptSchema = 'fsring-c4-source-attempt/v1'
$script:SourceAttemptFilesSchema = 'fsring-c4-source-attempt-files/v1'
$script:NativeAttemptSchema = 'fsring-c4-native-attempt/v1'
$script:NativeAttemptFilesSchema = 'fsring-c4-native-attempt-files/v1'
$script:CandidateSchema = 'fsring-c4-candidate-artifacts/v1'
$script:SelfTestSchema = 'fsring-c4-evidence-recorder-selftest/v1'

$script:MarkerFileName = 'c4-recorder-transaction.json'
# Git-private pathspec list for StageReceipt. A PASS source roster is ~194
# paths at ~180 bytes each; putting that array on `git add` argv exceeds
# Windows CreateProcess's 32767-character command line.
$script:StagePathspecFileName = 'fsring-c4-stage.pathspec'
$script:SourceIndexName = 'index.json'
$script:NativeIndexName = 'index.json'
$script:CandidateName = 'candidate-artifacts.json'
$script:LogsReadmeName = 'README.md'
$script:AttemptManifestName = 'attempt.json'
$script:AttemptFilesName = 'attempt-files.json'
$script:BootstrapName = 'bootstrap.json'

# The three maintained top-level latest pointers. They carry only the immutable
# relative path, hash, attempt ID and source tree -- never the evidence object a
# historical row cites.
$script:LatestPointerNames = [ordered]@{
    nativeReview = '2026-08-08-c4-recovery-native-review.md'
    evidenceReview = '2026-08-08-c4-recovery-evidence-review.md'
    sourceVerdict = '2026-08-08-c4-recovery-source-verdict.md'
}

# No mode owns this file. It is the R1-R6 evidence narrative, maintained by the
# owning task, and a recorder that staged it could smuggle a source change into
# an evidence-only checkpoint.
$script:UnownedEvidencePaths = @(
    'docs/superpowers/reviews/evidence/2026-08-08-c4-recovery-r1-r6.md'
)

$script:SourceAttemptRowKeys = @(
    'attemptId', 'sourceCommit', 'sourceTree', 'relativePath', 'gateStatus',
    'attemptManifestSha256', 'candidateManifestSha256',
    'nativeReviewRelativePath', 'nativeReviewSha256',
    'evidenceReviewRelativePath', 'evidenceReviewSha256', 'reviewStatus',
    'sourceVerdictRelativePath', 'sourceVerdictSha256', 'sourceVerdict'
)

$script:SourceEventKeys = @(
    'ordinal', 'previousAttemptId', 'eligibleAttemptId',
    'candidateManifestSha256', 'reason', 'sourceVerdictSha256'
)

$script:NativeIndexRowKeys = @(
    'attemptId', 'relativePath', 'bootstrapSourceCommit', 'bootstrapSourceTree',
    'bootstrapSha256', 'sourceAttemptId', 'sourceCommit', 'sourceTree',
    'candidateManifestSha256', 'nativeReviewSha256', 'evidenceReviewSha256',
    'artifactSetSha256', 'packageSetSha256', 'hostIdentity', 'bootIdentity',
    'status', 'attemptFilesSha256', 'attemptJsonSha256'
)

# The eight candidate identity fields of a native row obey one all-null-or-all-
# bound rule; a mixture is unpublishable.
$script:NativeCandidateIdentityKeys = @(
    'sourceAttemptId', 'sourceCommit', 'sourceTree', 'candidateManifestSha256',
    'nativeReviewSha256', 'evidenceReviewSha256', 'artifactSetSha256',
    'packageSetSha256'
)

$script:UnboundNativeReasons = @(
    'ELIGIBLE_CANDIDATE_MISSING', 'SOURCE_LEDGER_INVALID',
    'CANDIDATE_MANIFEST_INVALID'
)

$script:ReceiptKeys = @(
    'schema', 'version', 'transactionId', 'recorderSha256', 'mode', 'attemptId',
    'bootstrapSourceCommit', 'bootstrapSourceTree', 'bootstrapSha256',
    'checkpointACommit', 'sourceVerdict', 'attemptStatus', 'changedPaths'
)

$script:SourceAttemptKeys = @(
    'schema', 'version', 'attemptId', 'sourceCommit', 'sourceTree',
    'gateManifestSha256', 'toolsSha256', 'commandIndexSha256',
    'candidateManifestSha256', 'attemptFilesSha256', 'gateStatus', 'failure'
)

$script:NativeAttemptKeys = @(
    'schema', 'version', 'attemptId', 'bootstrapSourceCommit', 'bootstrapSourceTree',
    'bootstrapSha256', 'sourceAttemptId', 'sourceCommit', 'sourceTree',
    'candidateManifestSha256', 'nativeReviewSha256', 'evidenceReviewSha256',
    'artifactSetSha256', 'packageSetSha256', 'hostIdentity', 'bootIdentity',
    'status', 'phase', 'reasonCodes', 'commandIssued', 'liveIssued',
    'mutationAttempts', 'attemptFilesSha256'
)

$script:NativeHostIdentityKeys = @(
    'machineGuid', 'computerName', 'osBuild', 'architecture', 'processArchitecture'
)
$script:NativeBootIdentityKeys = @('bootId', 'bootTimeUtc')

$script:SourceGateStatuses = @('PASS', 'FAIL', 'TIMEOUT', 'IDENTITY_DRIFT')
$script:NativeStatuses = @('PASS', 'FAIL', 'NOT_RUN')
$script:Verdicts = @('PASS', 'FAIL', 'PENDING')

function Assert-C4RecorderHex {
    param([string]$Value, [int]$Length, [string]$Name)
    if ($null -eq $Value -or $Value -cnotmatch ('^[0-9a-f]{' + $Length + '}$')) {
        throw ("{0} must be exactly {1} lowercase hexadecimal characters" -f $Name, $Length)
    }
}

function Assert-C4RecorderAttemptId {
    param([string]$Value, [string]$Name)
    # GUID-N: 32 lowercase hex digits, no braces or dashes.
    if ($null -eq $Value -or $Value -cnotmatch '^[0-9a-f]{32}$') {
        throw ("{0} must be a GUID-N attempt ID (32 lowercase hex digits)" -f $Name)
    }
}

function Get-C4RecorderSha256File {
    param([string]$Path)
    return (Get-C4EvidenceSha256Hex ([IO.File]::ReadAllBytes($Path)))
}

function Get-C4RecorderCanonicalBytes {
    param($Value)
    $utf8 = New-Object System.Text.UTF8Encoding $false
    return $utf8.GetBytes((ConvertTo-C4CanonicalJsonText $Value) + "`n")
}

function Assert-C4RecorderExactKeys {
    param($Object, [string[]]$Keys, [string]$What)
    $actual = @($Object.PSObject.Properties | ForEach-Object { $_.Name })
    if (($actual -join ',') -cne ($Keys -join ',')) {
        throw ("{0} keys are not the exact closed ordered set: {1}" -f $What, ($actual -join ','))
    }
}

function Test-C4RecorderReparse {
    param([string]$Path)
    if (-not ([IO.File]::Exists($Path) -or [IO.Directory]::Exists($Path))) { return $false }
    return ((([IO.File]::GetAttributes($Path)) -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

# Every path this script accepts is canonicalized the same way, and separators
# are normalized first: the frozen gate manifest and the Task 29 snippets both
# spell repository-relative paths with forward slashes.
function Assert-C4RecorderAbsolutePath {
    param([string]$Path, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw ("{0} is required" -f $Name) }
    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw ("{0} must be absolute: {1}" -f $Name, $Path)
    }
    if ($Path.Contains('..')) {
        throw ("{0} must not contain a relative segment: {1}" -f $Name, $Path)
    }
    $normalized = $Path.Replace('/', '\')
    $full = [IO.Path]::GetFullPath($normalized)
    if ($full -cne $normalized) {
        throw ("{0} is not canonical: {1}" -f $Name, $Path)
    }
    return $full
}

function Assert-C4RecorderRelativePath {
    param([string]$Path, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw ("{0} is required" -f $Name) }
    $value = $Path.Replace('\', '/')
    if ($value.StartsWith('/') -or $value.Contains('..') -or $value.Contains('//')) {
        throw ("{0} must be a clean repository-relative path: {1}" -f $Name, $Path)
    }
    if ([IO.Path]::IsPathRooted($value)) {
        throw ("{0} must be repository-relative, not absolute: {1}" -f $Name, $Path)
    }
    return $value
}

# ---------------------------------------------------------------------------
# Self-freeze
#
# This check is deliberately not the trust bootstrap. A swapped recorder could
# simply omit it. What makes it meaningful is that the calling Task 29/30 shell
# independently opens this same canonical file with its own deny-write/delete
# handle and holds it across the recording call *and* the StageReceipt that
# follows -- so StageReceipt cannot run under different bytes than the mode it
# is validating. This half proves the process is reading the file it was
# launched from, and keeps proving it until the transaction returns.
# ---------------------------------------------------------------------------

function Open-C4RecorderSelfLease {
    param([string]$ExpectedSha256)

    Assert-C4RecorderHex $ExpectedSha256 64 'ExpectedRecorderSha256'
    $command = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($command)) {
        throw 'the recorder cannot resolve its own script path'
    }
    $canonical = Assert-C4RecorderAbsolutePath $command 'recorder script path'
    if (Test-C4RecorderReparse $canonical) {
        throw 'the recorder script path is a reparse point'
    }
    # Open-C4HeldFileLease proves canonical-path identity through the handle,
    # denies write and delete for the lease's whole life, and refuses an alias.
    $lease = Open-C4HeldFileLease -Path $canonical -ExpectedSha256 $ExpectedSha256
    return $lease
}

# ---------------------------------------------------------------------------
# Git adapter
# ---------------------------------------------------------------------------

function New-C4RecorderGitAdapter {
    param([string]$RepositoryRoot)

    $root = $RepositoryRoot
    return [pscustomobject]@{
        RepositoryRoot = $root
        Run = {
            param([string[]]$Arguments)
            $previous = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                $output = & git -C $root @Arguments 2>&1
            } finally {
                $ErrorActionPreference = $previous
            }
            $code = $LASTEXITCODE
            $lines = @(@($output) | ForEach-Object { [string]$_ })
            return [pscustomobject]@{
                ExitCode = [int]$code
                Lines = $lines
                Text = ($lines -join "`n")
            }
        }.GetNewClosure()
    }
}

function Invoke-C4RecorderGit {
    param($Git, [string[]]$Arguments, [switch]$AllowFailure)
    $result = & $Git.Run $Arguments
    if (-not $AllowFailure -and $result.ExitCode -ne 0) {
        throw ("git {0} failed: {1}" -f ($Arguments -join ' '), $result.Text)
    }
    return $result
}

function Get-C4RecorderGitPath {
    param($Git, [string]$Name)
    $result = Invoke-C4RecorderGit $Git @('rev-parse', '--git-path', $Name)
    $value = ([string]$result.Lines[0]).Trim()
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw 'git rev-parse --git-path returned nothing'
    }
    if ([IO.Path]::IsPathRooted($value)) { return [IO.Path]::GetFullPath($value) }
    return [IO.Path]::GetFullPath((Join-Path $Git.RepositoryRoot $value))
}

function Invoke-C4RecorderGitAddRoster {
    param($Git, [string[]]$RelativePaths)

    $paths = @(@($RelativePaths) | ForEach-Object { [string]$_ })
    if ($paths.Count -eq 0) {
        throw 'StageReceipt derived an empty git-add pathspec'
    }
    foreach ($path in $paths) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            throw 'StageReceipt roster contains an empty pathspec'
        }
        if ($path.IndexOfAny(@([char]10, [char]13, [char]0)) -ge 0) {
            throw 'StageReceipt roster path contains a line break'
        }
    }

    # Write inside the Git dir so the option value is not itself a worktree
    # pathspec. UTF-8 (no BOM) and no trailing empty line: Windows PowerShell's
    # default Set-Content is UTF-16, which makes git add succeed and stage
    # nothing; a blank line is "empty string is not a valid pathspec".
    $pathspecPath = Get-C4RecorderGitPath $Git $script:StagePathspecFileName
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [IO.File]::WriteAllBytes($pathspecPath, $utf8.GetBytes(([string]::Join("`n", $paths) + "`n")))
    try {
        $fromFile = $pathspecPath.Replace('\', '/')
        [void](Invoke-C4RecorderGit $Git @(
            'add', '-A', ('--pathspec-from-file=' + $fromFile)))
    } finally {
        if ([IO.File]::Exists($pathspecPath)) {
            [IO.File]::Delete($pathspecPath)
        }
    }
}

# ---------------------------------------------------------------------------
# Transaction engine
#
# There is no filesystem-wide atomic multi-file write, so publication is a
# recoverable ledger-last transaction instead of a claim of atomicity:
#
#   1. Write the Git-private marker and the external journal, both PREPARED and
#      both carrying the ledger preimage hash and the complete ordered roster.
#   2. Install every immutable object with CreateNew. These are safe orphans:
#      nothing in the ledger points at them yet.
#   3. Back up every mutable pointer or top-level candidate to a
#      transaction-owned sibling, then write its new bytes.
#   4. Write the new ledger to an exclusive sibling and atomically replace it.
#      *That replace is the sole logical commit point.*
#   5. Rehash the ledger postimage, discard backups and temps, write the receipt
#      with CreateNew, mark COMMITTED, remove the marker.
#
# Recovery reads the ledger and compares it to the two recorded hashes, so the
# direction is never a guess: preimage means roll back, postimage means roll
# forward, and anything else is manual corruption rather than a repair attempt.
# ---------------------------------------------------------------------------

$script:OperationKeys = @('operation', 'relativePath', 'sha256')

function New-C4RecorderOperation {
    param(
        [ValidateSet('CREATE', 'REPLACE', 'DELETE')]
        [string]$Operation,
        [string]$RelativePath,
        [ValidateSet('IMMUTABLE', 'MUTABLE', 'LEDGER', 'WORKTREE')]
        [string]$Class,
        $OldSha256,
        $NewSha256,
        [byte[]]$NewBytes,
        [string]$SourcePath
    )
    $old = $OldSha256
    if ($old -is [string] -and [string]::IsNullOrWhiteSpace($old)) { $old = $null }
    $new = $NewSha256
    if ($new -is [string] -and [string]::IsNullOrWhiteSpace($new)) { $new = $null }
    return [pscustomobject]@{
        Operation = $Operation
        RelativePath = $RelativePath
        Class = $Class
        OldSha256 = $old
        NewSha256 = $new
        NewBytes = $NewBytes
        SourcePath = $SourcePath
    }
}

function Get-C4RecorderTransactionSuffix {
    param([string]$TransactionId)
    return ('.c4txn-' + $TransactionId)
}

function New-C4RecorderTransactionRecord {
    param(
        [string]$TransactionId,
        [string]$Mode,
        [string]$AttemptId,
        [string]$LedgerRelativePath,
        $LedgerPreimageSha256,
        $LedgerPostimageSha256,
        [string]$ReceiptPath,
        $Operations,
        $Receipt,
        [string]$State
    )

    $rows = New-Object System.Collections.ArrayList
    foreach ($operation in $Operations) {
        [void]$rows.Add([ordered]@{
            operation = $operation.Operation
            relativePath = $operation.RelativePath
            class = $operation.Class
            oldSha256 = $operation.OldSha256
            newSha256 = $operation.NewSha256
        })
    }
    # A [string] parameter would turn $null into '', and '' is not null: a
    # first-ever ledger has no preimage and recovery has to be able to see that.
    $preimage = $LedgerPreimageSha256
    if ($preimage -is [string] -and [string]::IsNullOrWhiteSpace($preimage)) { $preimage = $null }
    $postimage = $LedgerPostimageSha256
    if ($postimage -is [string] -and [string]::IsNullOrWhiteSpace($postimage)) { $postimage = $null }
    return [ordered]@{
        schema = $script:TransactionSchema
        version = 1
        transactionId = $TransactionId
        mode = $Mode
        attemptId = $AttemptId
        ledgerRelativePath = $LedgerRelativePath
        ledgerPreimageSha256 = $preimage
        ledgerPostimageSha256 = $postimage
        receiptPath = $ReceiptPath
        operations = @($rows)
        receipt = $Receipt
        state = $State
    }
}

function Write-C4RecorderExclusiveFile {
    param([string]$Path, [byte[]]$Bytes)
    $stream = New-Object IO.FileStream(
        $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

function Write-C4RecorderOverwriteFile {
    param([string]$Path, [byte[]]$Bytes)
    $stream = New-Object IO.FileStream(
        $Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

function Invoke-C4RecorderCrashPoint {
    param($Context, [string]$Label)
    if ($null -eq $Context.CrashAt) { return }
    if ($Context.CrashAt -cne $Label) { return }
    # A simulated crash leaves the marker, journal and every partial byte
    # exactly where a killed process would: no unwinding, no cleanup.
    throw ('C4-RECORDER-SIMULATED-CRASH:' + $Label)
}

function Invoke-C4RecorderTransaction {
    param(
        $Context,
        [string]$Mode,
        [string]$AttemptId,
        [string]$LedgerRelativePath,
        [byte[]]$LedgerNewBytes,
        $Operations,
        $Receipt
    )

    $repoRoot = $Context.RepositoryRoot
    $transactionId = [Guid]::NewGuid().ToString('N')
    $suffix = Get-C4RecorderTransactionSuffix $transactionId
    $markerPath = $Context.MarkerPath
    $journalPath = $Context.JournalPath
    $receiptPath = $Context.ReceiptPath

    $ledgerAbsolute = $null
    $ledgerPreimage = $null
    $ledgerPostimage = $null
    if ($LedgerRelativePath) {
        $ledgerAbsolute = [IO.Path]::GetFullPath(
            (Join-Path $repoRoot ($LedgerRelativePath.Replace('/', '\'))))
        if ([IO.File]::Exists($ledgerAbsolute)) {
            $ledgerPreimage = Get-C4RecorderSha256File $ledgerAbsolute
        }
        $ledgerPostimage = Get-C4EvidenceSha256Hex $LedgerNewBytes
        if ($null -ne $ledgerPreimage -and $ledgerPreimage -ceq $ledgerPostimage) {
            # With identical images, recovery could not tell roll back from roll
            # forward, so there would be no single deterministic direction.
            throw 'the transaction would not change the ledger; there is nothing to record'
        }
    }

    if ([IO.File]::Exists($markerPath)) {
        throw ('a prior recorder transaction marker is still present; recovery must run first: ' + $markerPath)
    }
    if ([IO.File]::Exists($journalPath)) {
        throw ('a prior recorder transaction journal is still present: ' + $journalPath)
    }
    if ([IO.File]::Exists($receiptPath)) {
        throw 'the receipt path already exists'
    }

    # The receipt is finalized before the marker goes down, so the transaction
    # record is self-sufficient: forward recovery can write it verbatim.
    $receiptObject = $Receipt
    $receiptObject['transactionId'] = $transactionId

    $prepared = New-C4RecorderTransactionRecord -TransactionId $transactionId -Mode $Mode `
        -AttemptId $AttemptId -LedgerRelativePath $LedgerRelativePath `
        -LedgerPreimageSha256 $ledgerPreimage -LedgerPostimageSha256 $ledgerPostimage `
        -ReceiptPath $receiptPath -Operations $Operations -Receipt $receiptObject `
        -State 'PREPARED'
    $preparedBytes = Get-C4RecorderCanonicalBytes $prepared

    # The marker goes down first and exclusively: two recorders cannot both be
    # mid-transaction in one repository.
    Write-C4RecorderExclusiveFile $markerPath $preparedBytes
    Invoke-C4RecorderCrashPoint $Context 'AFTER_MARKER'
    Write-C4RecorderExclusiveFile $journalPath $preparedBytes
    Invoke-C4RecorderCrashPoint $Context 'AFTER_JOURNAL'

    $backups = New-Object System.Collections.ArrayList
    $temps = New-Object System.Collections.ArrayList

    # --- 2. immutable objects, CreateNew, safe orphans ---------------------
    foreach ($operation in @($Operations | Where-Object { $_.Class -ceq 'IMMUTABLE' })) {
        $target = [IO.Path]::GetFullPath(
            (Join-Path $repoRoot ($operation.RelativePath.Replace('/', '\'))))
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
        if ([IO.File]::Exists($target)) {
            # Adoption, not overwrite: an identical object left by an
            # interrupted same-input attempt is reused; a different one is a
            # replay that must not be papered over.
            if ((Get-C4RecorderSha256File $target) -cne $operation.NewSha256) {
                throw ("immutable object already exists with different bytes: {0}" -f
                    $operation.RelativePath)
            }
        } else {
            $bytes = $operation.NewBytes
            if ($null -eq $bytes) { $bytes = [IO.File]::ReadAllBytes($operation.SourcePath) }
            Write-C4RecorderExclusiveFile $target $bytes
            if ((Get-C4RecorderSha256File $target) -cne $operation.NewSha256) {
                throw ("installed immutable object does not hash to its planned value: {0}" -f
                    $operation.RelativePath)
            }
        }
        Invoke-C4RecorderCrashPoint $Context 'AFTER_IMMUTABLE'
    }
    Invoke-C4RecorderCrashPoint $Context 'AFTER_ALL_IMMUTABLE'

    # --- 3. mutable pointers and the top-level candidate ------------------
    foreach ($operation in @($Operations | Where-Object { $_.Class -ceq 'MUTABLE' })) {
        $target = [IO.Path]::GetFullPath(
            (Join-Path $repoRoot ($operation.RelativePath.Replace('/', '\'))))
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
        if ([IO.File]::Exists($target)) {
            $backup = $target + $suffix + '.bak'
            [IO.File]::Copy($target, $backup, $false)
            [void]$backups.Add([pscustomobject]@{ Target = $target; Backup = $backup })
            Invoke-C4RecorderCrashPoint $Context 'AFTER_BACKUP'
        } elseif ($operation.Operation -cne 'CREATE') {
            throw ("cannot {0} an absent path: {1}" -f $operation.Operation, $operation.RelativePath)
        }
        if ($operation.Operation -ceq 'DELETE') {
            [IO.File]::Delete($target)
            Invoke-C4RecorderCrashPoint $Context 'AFTER_DELETE'
            continue
        }
        $bytes = $operation.NewBytes
        if ($null -eq $bytes) { $bytes = [IO.File]::ReadAllBytes($operation.SourcePath) }
        Write-C4RecorderOverwriteFile $target $bytes
        if ((Get-C4RecorderSha256File $target) -cne $operation.NewSha256) {
            throw ("written mutable object does not hash to its planned value: {0}" -f
                $operation.RelativePath)
        }
        Invoke-C4RecorderCrashPoint $Context 'AFTER_MUTABLE'
    }
    Invoke-C4RecorderCrashPoint $Context 'AFTER_ALL_MUTABLE'

    # --- 4. the ledger, written aside and then replaced --------------------
    if ($ledgerAbsolute) {
        $ledgerTemp = $ledgerAbsolute + $suffix + '.tmp'
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($ledgerAbsolute))
        Write-C4RecorderExclusiveFile $ledgerTemp $LedgerNewBytes
        [void]$temps.Add($ledgerTemp)
        Invoke-C4RecorderCrashPoint $Context 'AFTER_LEDGER_TEMP'
        if ([IO.File]::Exists($ledgerAbsolute)) {
            $ledgerBackup = $ledgerAbsolute + $suffix + '.bak'
            [IO.File]::Copy($ledgerAbsolute, $ledgerBackup, $false)
            [void]$backups.Add([pscustomobject]@{
                Target = $ledgerAbsolute; Backup = $ledgerBackup })
            Invoke-C4RecorderCrashPoint $Context 'AFTER_LEDGER_BACKUP'
        }
        # This move is the commit point. Everything above it is discardable and
        # everything below it is completion work.
        [IO.File]::Copy($ledgerTemp, $ledgerAbsolute, $true)
        Invoke-C4RecorderCrashPoint $Context 'AFTER_LEDGER_REPLACE'
        if ((Get-C4RecorderSha256File $ledgerAbsolute) -cne $ledgerPostimage) {
            throw 'the replaced ledger does not hash to its recorded postimage'
        }
    }

    # --- 5. completion ----------------------------------------------------
    foreach ($temp in $temps) {
        if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
    }
    foreach ($entry in $backups) {
        if ([IO.File]::Exists($entry.Backup)) { [IO.File]::Delete($entry.Backup) }
    }
    Invoke-C4RecorderCrashPoint $Context 'AFTER_CLEANUP'

    $receiptBytes = Get-C4RecorderCanonicalBytes $receiptObject
    Write-C4RecorderExclusiveFile $receiptPath $receiptBytes
    Invoke-C4RecorderCrashPoint $Context 'AFTER_RECEIPT'

    $committed = New-C4RecorderTransactionRecord -TransactionId $transactionId -Mode $Mode `
        -AttemptId $AttemptId -LedgerRelativePath $LedgerRelativePath `
        -LedgerPreimageSha256 $ledgerPreimage -LedgerPostimageSha256 $ledgerPostimage `
        -ReceiptPath $receiptPath -Operations $Operations -Receipt $receiptObject `
        -State 'COMMITTED'
    $committedBytes = Get-C4RecorderCanonicalBytes $committed
    Write-C4RecorderOverwriteFile $journalPath $committedBytes
    Invoke-C4RecorderCrashPoint $Context 'AFTER_JOURNAL_COMMITTED'
    Write-C4RecorderOverwriteFile $markerPath $committedBytes
    [IO.File]::Delete($markerPath)
    return $receiptObject
}

# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------

function Invoke-C4RecorderRecovery {
    param($Context)

    $markerPath = $Context.MarkerPath
    if (-not [IO.File]::Exists($markerPath)) {
        return [pscustomobject]@{ Direction = 'NONE'; TransactionId = $null }
    }
    $record = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($markerPath)) `
        -ExpectedSchema $script:TransactionSchema
    $repoRoot = $Context.RepositoryRoot
    $suffix = Get-C4RecorderTransactionSuffix $record.transactionId

    $ledgerAbsolute = $null
    if (-not [string]::IsNullOrWhiteSpace($record.ledgerRelativePath)) {
        $ledgerAbsolute = [IO.Path]::GetFullPath(
            (Join-Path $repoRoot (([string]$record.ledgerRelativePath).Replace('/', '\'))))
    }
    $current = $null
    if ($null -ne $ledgerAbsolute -and [IO.File]::Exists($ledgerAbsolute)) {
        $current = Get-C4RecorderSha256File $ledgerAbsolute
    }

    $recordedPre = $record.ledgerPreimageSha256
    if ($recordedPre -is [string] -and [string]::IsNullOrWhiteSpace($recordedPre)) {
        $recordedPre = $null
    }
    $recordedPost = $record.ledgerPostimageSha256
    if ($recordedPost -is [string] -and [string]::IsNullOrWhiteSpace($recordedPost)) {
        $recordedPost = $null
    }
    $direction = $null
    if ($null -ne $recordedPost -and $current -ceq $recordedPost) {
        $direction = 'FORWARD'
    } elseif (($null -eq $current -and $null -eq $recordedPre) -or
              ($null -ne $current -and $current -ceq $recordedPre)) {
        $direction = 'BACKWARD'
    } else {
        # Neither image matches, so there is no deterministic direction. Guessing
        # here is what would destroy evidence; refusing is the only safe answer.
        throw ('recorder transaction ' + $record.transactionId +
            ' cannot be recovered: the ledger matches neither its preimage nor its ' +
            'postimage. Manual repair is required; no mutation was performed.')
    }

    if ($direction -ceq 'BACKWARD') {
        # Restore every mutable pointer and the candidate from its
        # transaction-owned backup, and drop temps. Immutable objects are left
        # where they are: they are orphans until a ledger points at them, and a
        # same-input retry adopts them byte-for-byte.
        foreach ($row in @($record.operations)) {
            if ($row.class -cne 'MUTABLE' -and $row.class -cne 'LEDGER') { continue }
            $target = [IO.Path]::GetFullPath(
                (Join-Path $repoRoot (([string]$row.relativePath).Replace('/', '\'))))
            $backup = $target + $suffix + '.bak'
            if ([IO.File]::Exists($backup)) {
                [IO.File]::Copy($backup, $target, $true)
                [IO.File]::Delete($backup)
            } elseif ([string]::IsNullOrWhiteSpace([string]$row.oldSha256) -and
                      [IO.File]::Exists($target)) {
                # It had no prior bytes, so rolling back means removing it.
                [IO.File]::Delete($target)
            }
            $temp = $target + $suffix + '.tmp'
            if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
        }
        if ($null -ne $ledgerAbsolute) {
            $ledgerBackup = $ledgerAbsolute + $suffix + '.bak'
            if ([IO.File]::Exists($ledgerBackup)) {
                [IO.File]::Copy($ledgerBackup, $ledgerAbsolute, $true)
                [IO.File]::Delete($ledgerBackup)
            }
            $ledgerTemp = $ledgerAbsolute + $suffix + '.tmp'
            if ([IO.File]::Exists($ledgerTemp)) { [IO.File]::Delete($ledgerTemp) }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$record.receiptPath) -and
            [IO.File]::Exists([string]$record.receiptPath)) {
            [IO.File]::Delete([string]$record.receiptPath)
        }
        [IO.File]::Delete($markerPath)
        $journal = [string]$record.receiptPath + '.transaction.json'
        if ([IO.File]::Exists($journal)) { [IO.File]::Delete($journal) }
        return [pscustomobject]@{ Direction = 'BACKWARD'; TransactionId = $record.transactionId }
    }

    # FORWARD: the ledger already carries the postimage, so this transaction is
    # logically committed. Finish exactly the completion work.
    foreach ($row in @($record.operations)) {
        $target = [IO.Path]::GetFullPath(
            (Join-Path $repoRoot (([string]$row.relativePath).Replace('/', '\'))))
        if ($row.class -ceq 'MUTABLE' -or $row.class -ceq 'LEDGER') {
            if ($row.operation -ceq 'DELETE') {
                if ([IO.File]::Exists($target)) { [IO.File]::Delete($target) }
            } elseif (-not [string]::IsNullOrWhiteSpace([string]$row.newSha256)) {
                $backup = $target + $suffix + '.bak'
                $temp = $target + $suffix + '.tmp'
                if (-not [IO.File]::Exists($target) -or
                    (Get-C4RecorderSha256File $target) -cne [string]$row.newSha256) {
                    if ([IO.File]::Exists($temp)) {
                        [IO.File]::Copy($temp, $target, $true)
                    } elseif ([IO.File]::Exists($backup)) {
                        throw ('recorder transaction ' + $record.transactionId +
                            ' committed but ' + $row.relativePath +
                            ' carries neither its new bytes nor a temp to complete from')
                    }
                }
                if ([IO.File]::Exists($backup)) { [IO.File]::Delete($backup) }
                if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
            }
        }
    }
    $receiptPath = [string]$record.receiptPath
    if (-not [IO.File]::Exists($receiptPath)) {
        # The ledger already carries the postimage, so this transaction is
        # committed and its receipt is completion work, not a decision. The
        # record carries the exact bytes.
        Write-C4RecorderExclusiveFile $receiptPath (Get-C4RecorderCanonicalBytes $record.receipt)
    } elseif ((Get-C4RecorderSha256File $receiptPath) -cne
              (Get-C4EvidenceSha256Hex (Get-C4RecorderCanonicalBytes $record.receipt))) {
        throw ('recorder transaction ' + $record.transactionId +
            ' committed but the receipt on disk is not the one it recorded')
    }
    $journalPath = $receiptPath + '.transaction.json'
    $committed = New-C4RecorderTransactionRecord -TransactionId $record.transactionId `
        -Mode ([string]$record.mode) -AttemptId ([string]$record.attemptId) `
        -LedgerRelativePath ([string]$record.ledgerRelativePath) `
        -LedgerPreimageSha256 ([string]$record.ledgerPreimageSha256) `
        -LedgerPostimageSha256 ([string]$record.ledgerPostimageSha256) `
        -ReceiptPath $receiptPath -Receipt $record.receipt `
        -Operations @($record.operations | ForEach-Object {
            [pscustomobject]@{
                Operation = [string]$_.operation
                RelativePath = [string]$_.relativePath
                Class = [string]$_.class
                OldSha256 = $_.oldSha256
                NewSha256 = $_.newSha256
            }
        }) -State 'COMMITTED'
    $committedBytes = Get-C4RecorderCanonicalBytes $committed
    Write-C4RecorderOverwriteFile $journalPath $committedBytes
    [IO.File]::Delete($markerPath)
    return [pscustomobject]@{ Direction = 'FORWARD'; TransactionId = $record.transactionId }
}

# ---------------------------------------------------------------------------
# The append-only source ledger
#
# Rows and events are never removed, reordered, reused or rewritten. The
# identity/path/gate/attempt/candidate fields are final at insertion; each
# review, verdict path, hash and status transitions null-to-final exactly once.
# A later outcome needs a new attempt, not an edited row.
# ---------------------------------------------------------------------------

function New-C4EmptySourceIndex {
    return [ordered]@{
        schema = $script:SourceIndexSchema
        attempts = @()
        eligibilityEvents = @()
        eligibleCandidateAttemptId = $null
    }
}

function ConvertTo-C4SourceIndexOrdered {
    param($Index)

    $attempts = New-Object System.Collections.ArrayList
    foreach ($row in @($Index.attempts)) {
        $ordered = [ordered]@{}
        foreach ($key in $script:SourceAttemptRowKeys) { $ordered[$key] = $row.$key }
        [void]$attempts.Add($ordered)
    }
    $events = New-Object System.Collections.ArrayList
    foreach ($row in @($Index.eligibilityEvents)) {
        $ordered = [ordered]@{}
        foreach ($key in $script:SourceEventKeys) { $ordered[$key] = $row.$key }
        [void]$events.Add($ordered)
    }
    return [ordered]@{
        schema = $script:SourceIndexSchema
        attempts = @($attempts)
        eligibilityEvents = @($events)
        eligibleCandidateAttemptId = $Index.eligibleCandidateAttemptId
    }
}

function Read-C4SourceIndex {
    param([string]$Path)

    if (-not [IO.File]::Exists($Path)) { return (New-C4EmptySourceIndex) }
    $index = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($Path)) `
        -ExpectedSchema $script:SourceIndexSchema
    Assert-C4RecorderExactKeys $index @(
        'schema', 'attempts', 'eligibilityEvents', 'eligibleCandidateAttemptId') 'source index'

    $seen = @{}
    foreach ($row in @($index.attempts)) {
        Assert-C4RecorderExactKeys $row $script:SourceAttemptRowKeys 'source index attempt row'
        Assert-C4RecorderAttemptId ([string]$row.attemptId) 'source index attemptId'
        if ($seen.ContainsKey([string]$row.attemptId)) {
            throw 'the source index carries a duplicate attempt row'
        }
        $seen[[string]$row.attemptId] = $true
        if ($script:SourceGateStatuses -cnotcontains [string]$row.gateStatus) {
            throw ("source index row {0} has an unknown gateStatus" -f $row.attemptId)
        }
        if ([string]$row.gateStatus -cne 'PASS' -and $null -ne $row.candidateManifestSha256) {
            throw ("source index row {0} is not gate PASS but carries a candidate hash" -f
                $row.attemptId)
        }
    }

    # Events are ordinal-one upward with no gaps, and the pointer is exactly the
    # last event's eligible attempt.
    $expectedOrdinal = 1
    $pointer = $null
    foreach ($row in @($index.eligibilityEvents)) {
        Assert-C4RecorderExactKeys $row $script:SourceEventKeys 'source index eligibility event'
        if ([int]$row.ordinal -ne $expectedOrdinal) {
            throw 'source index eligibility events are not ordinal-contiguous from one'
        }
        $expectedOrdinal += 1
        if (([string]$row.previousAttemptId) -cne ([string]$pointer)) {
            throw ("eligibility event {0} does not name the pointer that preceded it" -f $row.ordinal)
        }
        $reason = [string]$row.reason
        if (@('INITIAL_PASS', 'SUPERSEDE_PASS') -ccontains $reason) {
            foreach ($field in @('eligibleAttemptId', 'candidateManifestSha256',
                    'sourceVerdictSha256')) {
                if ([string]::IsNullOrWhiteSpace([string]$row.$field)) {
                    throw ("eligibility event {0} is a PASS reason with a null {1}" -f
                        $row.ordinal, $field)
                }
            }
        } elseif ($reason -ceq 'WITHDRAW_SOURCE_DEFECT') {
            foreach ($field in @('eligibleAttemptId', 'candidateManifestSha256',
                    'sourceVerdictSha256')) {
                if ($null -ne $row.$field) {
                    throw ("withdrawal event {0} must have a null {1}" -f $row.ordinal, $field)
                }
            }
            if ([string]::IsNullOrWhiteSpace([string]$row.previousAttemptId)) {
                throw ("withdrawal event {0} must name a previous attempt" -f $row.ordinal)
            }
        } else {
            throw ("eligibility event {0} has an unknown reason" -f $row.ordinal)
        }
        $pointer = $row.eligibleAttemptId
    }
    if (([string]$index.eligibleCandidateAttemptId) -cne ([string]$pointer)) {
        throw 'the source index pointer does not equal the last eligibility event'
    }
    return $index
}

function Get-C4SourceIndexRow {
    param($Index, [string]$AttemptId)
    foreach ($row in @($Index.attempts)) {
        if (([string]$row.attemptId) -ceq $AttemptId) { return $row }
    }
    return $null
}

# A prior history that changed is the thing this comparison exists to catch: a
# transaction validated against one ledger must not commit on top of another.
function Assert-C4SourceHistoryUnchanged {
    param($Before, $After)
    $beforeRows = @($Before.attempts)
    $afterRows = @($After.attempts)
    if ($afterRows.Count -lt $beforeRows.Count) {
        throw 'the source index lost attempt rows'
    }
    for ($i = 0; $i -lt $beforeRows.Count; $i++) {
        foreach ($key in @('attemptId', 'sourceCommit', 'sourceTree', 'relativePath',
                'gateStatus', 'attemptManifestSha256', 'candidateManifestSha256')) {
            if (([string]$beforeRows[$i].$key) -cne ([string]$afterRows[$i].$key)) {
                throw ("immutable field {0} of attempt row {1} changed" -f $key, $i)
            }
        }
        # A non-null review/verdict value can never be changed or cleared.
        foreach ($key in @('nativeReviewRelativePath', 'nativeReviewSha256',
                'evidenceReviewRelativePath', 'evidenceReviewSha256', 'reviewStatus',
                'sourceVerdictRelativePath', 'sourceVerdictSha256', 'sourceVerdict')) {
            if ($null -ne $beforeRows[$i].$key -and
                ([string]$beforeRows[$i].$key) -cne ([string]$afterRows[$i].$key)) {
                throw ("already-final field {0} of attempt row {1} was rewritten" -f $key, $i)
            }
        }
    }
    $beforeEvents = @($Before.eligibilityEvents)
    $afterEvents = @($After.eligibilityEvents)
    if ($afterEvents.Count -lt $beforeEvents.Count) {
        throw 'the source index lost eligibility events'
    }
    for ($i = 0; $i -lt $beforeEvents.Count; $i++) {
        foreach ($key in $script:SourceEventKeys) {
            if (([string]$beforeEvents[$i].$key) -cne ([string]$afterEvents[$i].$key)) {
                throw ("eligibility event {0} was rewritten" -f $i)
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Reading a sealed external attempt
#
# Nothing is copied until the whole incoming chain closes: the file roster
# hashes what is on disk, `attempt.json` hashes the roster, and the manifests it
# names hash to the values it claims.
# ---------------------------------------------------------------------------

function Read-C4SealedAttempt {
    param(
        [string]$Directory,
        [string]$AttemptSchema,
        [string]$FilesSchema
    )

    $root = Assert-C4RecorderAbsolutePath $Directory 'ExternalAttemptDirectory'
    if (-not [IO.Directory]::Exists($root)) {
        throw ("the external attempt directory does not exist: {0}" -f $root)
    }
    if (Test-C4RecorderReparse $root) {
        throw 'the external attempt directory is a reparse point'
    }
    $manifestPath = Join-Path $root $script:AttemptManifestName
    $filesPath = Join-Path $root $script:AttemptFilesName
    foreach ($required in @($manifestPath, $filesPath)) {
        if (-not [IO.File]::Exists($required)) {
            throw ("the external attempt is not sealed: {0} is missing" -f
                [IO.Path]::GetFileName($required))
        }
    }
    $filesBytes = [IO.File]::ReadAllBytes($filesPath)
    $roster = ConvertFrom-C4CanonicalJsonBytes -Bytes $filesBytes -ExpectedSchema $FilesSchema
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    $manifest = ConvertFrom-C4CanonicalJsonBytes -Bytes $manifestBytes -ExpectedSchema $AttemptSchema

    $rosterSha = Get-C4EvidenceSha256Hex $filesBytes
    if (([string]$manifest.attemptFilesSha256) -cne $rosterSha) {
        throw 'attempt.json::attemptFilesSha256 does not hash the sealed file roster'
    }

    # Every declared row must be on disk with exactly those bytes...
    $declared = New-Object System.Collections.ArrayList
    foreach ($row in @($roster.files)) {
        Assert-C4RecorderExactKeys $row @('relativePath', 'bytes', 'sha256') 'attempt file row'
        $relative = Assert-C4RecorderRelativePath ([string]$row.relativePath) 'attempt file row path'
        $absolute = [IO.Path]::GetFullPath((Join-Path $root ($relative.Replace('/', '\'))))
        if (-not $absolute.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw ("attempt file row escapes the attempt: {0}" -f $relative)
        }
        if (-not [IO.File]::Exists($absolute)) {
            throw ("the sealed roster names a missing file: {0}" -f $relative)
        }
        if (Test-C4RecorderReparse $absolute) {
            throw ("the sealed roster names a reparse point: {0}" -f $relative)
        }
        $bytes = [IO.File]::ReadAllBytes($absolute)
        if ([int64]$bytes.Length -ne [int64]$row.bytes) {
            throw ("sealed file {0} has {1} bytes, not the recorded {2}" -f
                $relative, $bytes.Length, $row.bytes)
        }
        if ((Get-C4EvidenceSha256Hex $bytes) -cne ([string]$row.sha256)) {
            throw ("sealed file {0} does not hash to its recorded value" -f $relative)
        }
        if ($declared -ccontains $relative) {
            throw ("the sealed roster lists {0} twice" -f $relative)
        }
        [void]$declared.Add($relative)
    }

    # ...and nothing else may be present. The roster excludes only itself and
    # attempt.json, so an extra byte anywhere else is unaccounted evidence.
    $present = New-Object System.Collections.ArrayList
    $stack = New-Object 'Collections.Generic.Stack[string]'
    $stack.Push($root)
    while ($stack.Count -ne 0) {
        $directory = $stack.Pop()
        foreach ($child in @([IO.Directory]::GetDirectories($directory))) {
            if (Test-C4RecorderReparse $child) {
                throw ("the sealed attempt carries a reparse directory: {0}" -f $child)
            }
            $stack.Push($child)
        }
        foreach ($file in @([IO.Directory]::GetFiles($directory))) {
            $relative = $file.Substring($root.Length + 1).Replace('\', '/')
            [void]$present.Add($relative)
        }
    }
    $expected = @(@($declared) + @($script:AttemptFilesName, $script:AttemptManifestName) |
        Sort-Object -CaseSensitive)
    $actual = @(@($present) | Sort-Object -CaseSensitive)
    if (($expected -join '|') -cne ($actual -join '|')) {
        $extra = @(@($actual) | Where-Object { $expected -cnotcontains $_ })
        $missing = @(@($expected) | Where-Object { $actual -cnotcontains $_ })
        throw ("the sealed attempt content is not its closed roster (extra: {0}; missing: {1})" -f
            ($extra -join ','), ($missing -join ','))
    }

    return [pscustomobject]@{
        Root = $root
        Manifest = $manifest
        ManifestBytes = $manifestBytes
        ManifestSha256 = (Get-C4EvidenceSha256Hex $manifestBytes)
        Roster = $roster
        RosterSha256 = $rosterSha
        Files = @($declared)
    }
}

function Assert-C4SealedSourceChain {
    param($Sealed)
    $manifest = $Sealed.Manifest
    Assert-C4RecorderExactKeys $manifest $script:SourceAttemptKeys 'sealed source attempt.json'
    foreach ($pair in @(
            @{ Field = 'commandIndexSha256'; File = 'command-index.json' },
            @{ Field = 'candidateManifestSha256'; File = 'candidate-artifacts.json' })) {
        $value = $manifest.($pair.Field)
        $path = Join-Path $Sealed.Root $pair.File
        if ([string]::IsNullOrWhiteSpace([string]$value)) {
            if ([IO.File]::Exists($path)) {
                throw ("{0} is null but {1} is present" -f $pair.Field, $pair.File)
            }
            continue
        }
        if (-not [IO.File]::Exists($path)) {
            throw ("{0} is non-null but {1} is absent" -f $pair.Field, $pair.File)
        }
        if ((Get-C4RecorderSha256File $path) -cne ([string]$value)) {
            throw ("{0} does not hash {1}" -f $pair.Field, $pair.File)
        }
    }
    if ($script:SourceGateStatuses -cnotcontains ([string]$manifest.gateStatus)) {
        throw 'the sealed source attempt carries an unknown gateStatus'
    }
    if (([string]$manifest.gateStatus) -cne 'PASS' -and
        -not [string]::IsNullOrWhiteSpace([string]$manifest.candidateManifestSha256)) {
        throw 'a non-PASS source attempt must not carry a candidate manifest hash'
    }
}

# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------

function New-C4RecorderReceipt {
    param(
        [string]$RecorderSha256,
        [string]$Mode,
        [string]$AttemptId,
        $BootstrapSourceCommit,
        $BootstrapSourceTree,
        $BootstrapSha256,
        $CheckpointACommit,
        $SourceVerdict,
        $AttemptStatus,
        $Operations
    )

    # A [string] parameter would coerce $null to '', and '' is a present value.
    function Get-NullableText {
        param($Value)
        if ($null -eq $Value) { return $null }
        if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) { return $null }
        return [string]$Value
    }

    $rows = New-Object System.Collections.ArrayList
    foreach ($operation in $Operations) {
        $sha = $operation.NewSha256
        if ($operation.Operation -ceq 'DELETE') { $sha = $null }
        [void]$rows.Add([ordered]@{
            operation = $operation.Operation
            relativePath = $operation.RelativePath
            sha256 = $sha
        })
    }
    return [ordered]@{
        schema = $script:ReceiptSchema
        version = 1
        transactionId = $null
        recorderSha256 = $RecorderSha256
        mode = $Mode
        attemptId = $AttemptId
        bootstrapSourceCommit = (Get-NullableText $BootstrapSourceCommit)
        bootstrapSourceTree = (Get-NullableText $BootstrapSourceTree)
        bootstrapSha256 = (Get-NullableText $BootstrapSha256)
        checkpointACommit = (Get-NullableText $CheckpointACommit)
        sourceVerdict = (Get-NullableText $SourceVerdict)
        attemptStatus = (Get-NullableText $AttemptStatus)
        changedPaths = @($rows)
    }
}

$script:LogsReadmeBody = @'
# C4 recovery source-gate attempt logs

Every directory here is one immutable source-gate attempt, copied whole from an
external run by `driver/scripts/record_c4_evidence.ps1` and never edited
afterwards. `index.json` is the append-only ledger: rows and eligibility events
are only ever appended, and a row's review, verdict and status fields each go
from null to final exactly once.

`candidate-artifacts.json` at this level, when present, is a byte-for-byte copy
of the eligible attempt's own candidate manifest. It is a pointer, not a second
source of truth -- the attempt-local copy preserves all superseded history.

Do not add, edit, move or delete anything under this directory by hand. The
recorder is the only writer, and every path it touches is proved against a hash
chain that starts at the sealed external attempt.
'@

# ---------------------------------------------------------------------------
# Mode: RecordSourceAttempt -- Checkpoint A's attempt copy and initial row
# ---------------------------------------------------------------------------

function Invoke-C4RecordSourceAttempt {
    param($Context)

    Assert-C4RecorderAttemptId $Context.ExpectedAttemptId 'ExpectedAttemptId'
    Assert-C4RecorderHex $Context.ExpectedSourceCommit 40 'ExpectedSourceCommit'
    Assert-C4RecorderHex $Context.ExpectedSourceTree 40 'ExpectedSourceTree'

    $sealed = Read-C4SealedAttempt -Directory $Context.ExternalAttemptDirectory `
        -AttemptSchema $script:SourceAttemptSchema -FilesSchema $script:SourceAttemptFilesSchema
    Assert-C4SealedSourceChain $sealed
    $manifest = $sealed.Manifest

    foreach ($pair in @(
            @{ Name = 'attemptId'; Expected = $Context.ExpectedAttemptId },
            @{ Name = 'sourceCommit'; Expected = $Context.ExpectedSourceCommit },
            @{ Name = 'sourceTree'; Expected = $Context.ExpectedSourceTree })) {
        if (([string]$manifest.($pair.Name)) -cne $pair.Expected) {
            throw ("the sealed attempt's {0} is {1}, not the expected {2}" -f
                $pair.Name, $manifest.($pair.Name), $pair.Expected)
        }
    }
    if (([string]$sealed.Roster.attemptId) -cne $Context.ExpectedAttemptId) {
        throw 'the sealed file roster names a different attempt'
    }

    $evidenceRoot = $Context.EvidenceRootRelative
    $attemptRelative = ('{0}/attempt-{1}-{2}' -f
        $evidenceRoot, $Context.ExpectedSourceTree, $Context.ExpectedAttemptId)

    $index = Read-C4SourceIndex $Context.LedgerAbsolutePath
    if ($null -ne (Get-C4SourceIndexRow $index $Context.ExpectedAttemptId)) {
        throw ("the source index already carries attempt {0}; this is a replay" -f
            $Context.ExpectedAttemptId)
    }

    $operations = New-Object System.Collections.ArrayList

    # The attempt itself, plus its two manifests, in one lexical order so the
    # receipt roster is reproducible.
    $allFiles = @(@($sealed.Files) + @($script:AttemptFilesName, $script:AttemptManifestName) |
        Sort-Object -CaseSensitive)
    foreach ($relative in $allFiles) {
        $source = [IO.Path]::GetFullPath(
            (Join-Path $sealed.Root ($relative.Replace('/', '\'))))
        [void]$operations.Add((New-C4RecorderOperation -Operation 'CREATE' `
            -RelativePath ($attemptRelative + '/' + $relative) -Class 'IMMUTABLE' `
            -OldSha256 $null -NewSha256 (Get-C4RecorderSha256File $source) `
            -SourcePath $source))
    }

    # The logs README is written once, the first time this root is populated.
    $readmeRelative = $evidenceRoot + '/' + $script:LogsReadmeName
    $readmeAbsolute = [IO.Path]::GetFullPath(
        (Join-Path $Context.RepositoryRoot ($readmeRelative.Replace('/', '\'))))
    if (-not [IO.File]::Exists($readmeAbsolute)) {
        $utf8 = New-Object System.Text.UTF8Encoding $false
        $readmeBytes = $utf8.GetBytes(($script:LogsReadmeBody -replace "`r`n", "`n") + "`n")
        [void]$operations.Add((New-C4RecorderOperation -Operation 'CREATE' `
            -RelativePath $readmeRelative -Class 'IMMUTABLE' -OldSha256 $null `
            -NewSha256 (Get-C4EvidenceSha256Hex $readmeBytes) -NewBytes $readmeBytes))
    }

    $row = [ordered]@{}
    foreach ($key in $script:SourceAttemptRowKeys) { $row[$key] = $null }
    $row['attemptId'] = $Context.ExpectedAttemptId
    $row['sourceCommit'] = $Context.ExpectedSourceCommit
    $row['sourceTree'] = $Context.ExpectedSourceTree
    $row['relativePath'] = ('attempt-{0}-{1}' -f
        $Context.ExpectedSourceTree, $Context.ExpectedAttemptId)
    $row['gateStatus'] = [string]$manifest.gateStatus
    $row['attemptManifestSha256'] = $sealed.ManifestSha256
    $row['candidateManifestSha256'] = $manifest.candidateManifestSha256

    $updated = ConvertTo-C4SourceIndexOrdered $index
    $updated['attempts'] = @(@($updated['attempts']) + @($row))
    Assert-C4SourceHistoryUnchanged $index $updated
    $ledgerBytes = Get-C4RecorderCanonicalBytes $updated
    $ledgerRelative = $evidenceRoot + '/' + $script:SourceIndexName
    $ledgerOld = $null
    if ([IO.File]::Exists($Context.LedgerAbsolutePath)) {
        $ledgerOld = Get-C4RecorderSha256File $Context.LedgerAbsolutePath
    }
    $ledgerOperation = 'REPLACE'
    if ($null -eq $ledgerOld) { $ledgerOperation = 'CREATE' }
    [void]$operations.Add((New-C4RecorderOperation -Operation $ledgerOperation `
        -RelativePath $ledgerRelative -Class 'LEDGER' -OldSha256 $ledgerOld `
        -NewSha256 (Get-C4EvidenceSha256Hex $ledgerBytes) -NewBytes $ledgerBytes))

    $receipt = New-C4RecorderReceipt -RecorderSha256 $Context.RecorderSha256 `
        -Mode 'RecordSourceAttempt' -AttemptId $Context.ExpectedAttemptId `
        -BootstrapSourceCommit $null -BootstrapSourceTree $null -BootstrapSha256 $null `
        -CheckpointACommit $null -SourceVerdict $null `
        -AttemptStatus ([string]$manifest.gateStatus) -Operations @($operations)

    return (Invoke-C4RecorderTransaction -Context $Context -Mode 'RecordSourceAttempt' `
        -AttemptId $Context.ExpectedAttemptId -LedgerRelativePath $ledgerRelative `
        -LedgerNewBytes $ledgerBytes -Operations @($operations) -Receipt $receipt)
}

# ---------------------------------------------------------------------------
# Mode: FinalizeSourceReview
#
# Machine-enforced checks are bounded on purpose. The recorder validates closed
# headers, post-Checkpoint-A tuple binding, different declared reviewer IDs,
# roles and output parents, and verdict/count consistency. It does *not* claim
# to detect hidden conversation inheritance, filesystem reads, or a
# self-selected identity: a missing, false or unverifiable isolation attestation
# forces PENDING rather than pretending to have proved isolation.
# ---------------------------------------------------------------------------

$script:ReviewHeaderKeys = @(
    'reviewRole', 'attemptId', 'sourceCommit', 'sourceTree', 'checkpointACommit',
    'reviewerContextId', 'reviewerInstanceId', 'outputParent', 'freshContext',
    'sharedDraft', 'otherReviewRead', 'blockerFindings', 'highFindings', 'verdict'
)

function Read-C4ReviewDocument {
    param([string]$Path, [string]$ExpectedRole)

    $absolute = Assert-C4RecorderAbsolutePath $Path ('review document ' + $ExpectedRole)
    if (-not [IO.File]::Exists($absolute)) {
        throw ("the {0} review document does not exist: {1}" -f $ExpectedRole, $absolute)
    }
    $bytes = [IO.File]::ReadAllBytes($absolute)
    $utf8 = Get-C4EvidenceUtf8
    $text = $utf8.GetString($bytes)
    $header = @{}
    foreach ($line in @($text.Split(@("`r`n", "`n"), [StringSplitOptions]::None))) {
        if ($line -cnotmatch '^<!--\s*c4-review:([A-Za-z]+)\s*=\s*(.*?)\s*-->$') { continue }
        $key = $Matches[1]
        $value = $Matches[2]
        if ($header.ContainsKey($key)) {
            throw ("the {0} review declares {1} twice" -f $ExpectedRole, $key)
        }
        $header[$key] = $value
    }
    foreach ($key in $script:ReviewHeaderKeys) {
        if (-not $header.ContainsKey($key)) {
            throw ("the {0} review header is missing {1}" -f $ExpectedRole, $key)
        }
    }
    foreach ($key in @($header.Keys)) {
        if ($script:ReviewHeaderKeys -cnotcontains $key) {
            throw ("the {0} review header carries the unknown key {1}" -f $ExpectedRole, $key)
        }
    }
    if ($header['reviewRole'] -cne $ExpectedRole) {
        throw ("the review at {0} declares role {1}, not {2}" -f
            $absolute, $header['reviewRole'], $ExpectedRole)
    }
    if ($script:Verdicts -cnotcontains $header['verdict']) {
        throw ("the {0} review verdict is not PASS, FAIL or PENDING" -f $ExpectedRole)
    }
    foreach ($key in @('freshContext', 'sharedDraft', 'otherReviewRead')) {
        if (@('true', 'false') -cnotcontains $header[$key]) {
            throw ("the {0} review's {1} attestation is not the literal true or false" -f
                $ExpectedRole, $key)
        }
    }
    foreach ($key in @('blockerFindings', 'highFindings')) {
        if ($header[$key] -cnotmatch '^(0|[1-9][0-9]{0,3})$') {
            throw ("the {0} review's {1} count is not a plain integer" -f $ExpectedRole, $key)
        }
    }
    return [pscustomobject]@{
        Path = $absolute
        Bytes = $bytes
        Sha256 = (Get-C4EvidenceSha256Hex $bytes)
        Header = $header
    }
}

function Get-C4ReviewIsolationVerdict {
    param($Review)
    # An attestation of inherited, shared or cross-read state is a declared
    # failure of isolation, and it forces PENDING rather than FAIL: the review
    # may be entirely correct, it just cannot be counted as independent.
    if ($Review.Header['freshContext'] -cne 'true') { return $false }
    if ($Review.Header['sharedDraft'] -cne 'false') { return $false }
    if ($Review.Header['otherReviewRead'] -cne 'false') { return $false }
    return $true
}

$script:VerdictHeaderKeys = @(
    'attemptId', 'sourceCommit', 'sourceTree', 'checkpointACommit', 'rowsPass',
    'rowsTotal', 'unresolvedBlockerFindings', 'unresolvedHighFindings', 'verdict'
)

function Read-C4SourceVerdictDocument {
    param([string]$Path)

    $absolute = Assert-C4RecorderAbsolutePath $Path 'SourceVerdictPath'
    if (-not [IO.File]::Exists($absolute)) {
        throw ("the source verdict document does not exist: {0}" -f $absolute)
    }
    $bytes = [IO.File]::ReadAllBytes($absolute)
    $text = (Get-C4EvidenceUtf8).GetString($bytes)
    $header = @{}
    foreach ($line in @($text.Split(@("`r`n", "`n"), [StringSplitOptions]::None))) {
        if ($line -cnotmatch '^<!--\s*c4-verdict:([A-Za-z]+)\s*=\s*(.*?)\s*-->$') { continue }
        if ($header.ContainsKey($Matches[1])) {
            throw ("the source verdict declares {0} twice" -f $Matches[1])
        }
        $header[$Matches[1]] = $Matches[2]
    }
    foreach ($key in $script:VerdictHeaderKeys) {
        if (-not $header.ContainsKey($key)) {
            throw ("the source verdict header is missing {0}" -f $key)
        }
    }
    foreach ($key in @($header.Keys)) {
        if ($script:VerdictHeaderKeys -cnotcontains $key) {
            throw ("the source verdict header carries the unknown key {0}" -f $key)
        }
    }
    if ($script:Verdicts -cnotcontains $header['verdict']) {
        throw 'the source verdict is not PASS, FAIL or PENDING'
    }
    foreach ($key in @('rowsPass', 'rowsTotal', 'unresolvedBlockerFindings',
            'unresolvedHighFindings')) {
        if ($header[$key] -cnotmatch '^(0|[1-9][0-9]{0,3})$') {
            throw ("the source verdict's {0} is not a plain integer" -f $key)
        }
    }
    # The 21 rows are the parent C4 section 13 ten and the recovery section 16
    # eleven. A verdict that does not account for all of them cannot be PASS,
    # and one that claims more rows than exist is not describing this gate.
    if ([int]$header['rowsTotal'] -ne 21) {
        throw ("the source verdict covers {0} rows, not the 21 verdict rows" -f
            $header['rowsTotal'])
    }
    if ([int]$header['rowsPass'] -gt 21) {
        throw 'the source verdict claims more passing rows than exist'
    }
    return [pscustomobject]@{
        Path = $absolute
        Bytes = $bytes
        Sha256 = (Get-C4EvidenceSha256Hex $bytes)
        Header = $header
    }
}

function New-C4LatestPointerBytes {
    param(
        [string]$Kind,
        [string]$RelativePath,
        [string]$Sha256,
        [string]$AttemptId,
        [string]$SourceTree
    )
    # A latest pointer carries only identity. It is deliberately not the
    # evidence object an old ledger row cites, so overwriting it can never
    # rewrite history.
    $lines = @(
        ('# C4 recovery latest {0}' -f $Kind),
        '',
        'This file is a maintained pointer, not evidence. The immutable object is:',
        '',
        ('- relativePath: `{0}`' -f $RelativePath),
        ('- sha256: `{0}`' -f $Sha256),
        ('- attemptId: `{0}`' -f $AttemptId),
        ('- sourceTree: `{0}`' -f $SourceTree),
        '',
        'Historical rows in `c4-recovery-logs/index.json` cite their own immutable',
        'per-attempt files and are never redirected here.'
    )
    $utf8 = New-Object System.Text.UTF8Encoding $false
    return $utf8.GetBytes((($lines -join "`n") + "`n"))
}

function Invoke-C4FinalizeSourceReview {
    param($Context)

    Assert-C4RecorderAttemptId $Context.ExpectedAttemptId 'ExpectedAttemptId'
    Assert-C4RecorderHex $Context.ExpectedCheckpointACommit 40 'ExpectedCheckpointACommit'

    $index = Read-C4SourceIndex $Context.LedgerAbsolutePath
    $row = Get-C4SourceIndexRow $index $Context.ExpectedAttemptId
    if ($null -eq $row) {
        throw ("the source index has no row for attempt {0}; Checkpoint A must run first" -f
            $Context.ExpectedAttemptId)
    }
    if (([string]$row.gateStatus) -cne 'PASS') {
        throw 'only a gate-PASS attempt enters review finalization'
    }
    foreach ($key in @('nativeReviewRelativePath', 'nativeReviewSha256',
            'evidenceReviewRelativePath', 'evidenceReviewSha256', 'reviewStatus',
            'sourceVerdictRelativePath', 'sourceVerdictSha256', 'sourceVerdict')) {
        if ($null -ne $row.$key) {
            throw ("attempt {0} already has a final {1}; a later outcome needs a new attempt" -f
                $Context.ExpectedAttemptId, $key)
        }
    }

    # Checkpoint A must already be in history: reviews are bound to the commit
    # that published the attempt, not to a tree that could still change.
    $ancestry = Invoke-C4RecorderGit $Context.Git `
        @('merge-base', '--is-ancestor', $Context.ExpectedCheckpointACommit, 'HEAD') -AllowFailure
    if ($ancestry.ExitCode -ne 0) {
        throw 'ExpectedCheckpointACommit is not an ancestor of HEAD'
    }

    $native = Read-C4ReviewDocument $Context.NativeReviewPath 'native'
    $evidence = Read-C4ReviewDocument $Context.EvidenceReviewPath 'evidence'
    $verdict = Read-C4SourceVerdictDocument $Context.SourceVerdictPath

    foreach ($document in @($native, $evidence, $verdict)) {
        foreach ($pair in @(
                @{ Key = 'attemptId'; Expected = $Context.ExpectedAttemptId },
                @{ Key = 'sourceCommit'; Expected = [string]$row.sourceCommit },
                @{ Key = 'sourceTree'; Expected = [string]$row.sourceTree },
                @{ Key = 'checkpointACommit'; Expected = $Context.ExpectedCheckpointACommit })) {
            if ($document.Header[$pair.Key] -cne $pair.Expected) {
                throw ("a review or verdict document binds {0}={1}, not the row's {2}" -f
                    $pair.Key, $document.Header[$pair.Key], $pair.Expected)
            }
        }
    }

    # Two reviewers, not one reviewer twice. The recorder can only check that
    # the declared identities, roles and output parents differ.
    foreach ($key in @('reviewerContextId', 'reviewerInstanceId', 'outputParent')) {
        if ($native.Header[$key] -ceq $evidence.Header[$key]) {
            throw ("both reviews declare the same {0}; they are not independent" -f $key)
        }
    }
    if ($native.Sha256 -ceq $evidence.Sha256) {
        throw 'both review documents are byte-identical'
    }

    $reviewStatus = 'FAIL'
    if ($native.Header['verdict'] -ceq 'PASS' -and $evidence.Header['verdict'] -ceq 'PASS') {
        $reviewStatus = 'PASS'
    }
    $isolated = (Get-C4ReviewIsolationVerdict $native) -and (Get-C4ReviewIsolationVerdict $evidence)

    $sourceVerdict = $verdict.Header['verdict']
    if ($sourceVerdict -ceq 'PASS') {
        if ($reviewStatus -cne 'PASS') {
            throw 'a PASS source verdict requires both reviews to PASS'
        }
        if (-not $isolated) {
            throw ('a PASS source verdict requires both reviews to attest a fresh, ' +
                'unshared, uncross-read context; a missing or false attestation forces PENDING')
        }
        if ([int]$verdict.Header['rowsPass'] -ne 21) {
            throw 'a PASS source verdict requires all 21 verdict rows to PASS'
        }
        foreach ($key in @('unresolvedBlockerFindings', 'unresolvedHighFindings')) {
            if ([int]$verdict.Header[$key] -ne 0) {
                throw ("a PASS source verdict requires zero {0}" -f $key)
            }
        }
        foreach ($review in @($native, $evidence)) {
            foreach ($key in @('blockerFindings', 'highFindings')) {
                if ([int]$review.Header[$key] -ne 0) {
                    throw ("a PASS source verdict is refused while a review reports {0}" -f $key)
                }
            }
        }
        if ([string]::IsNullOrWhiteSpace([string]$row.candidateManifestSha256)) {
            throw 'a PASS source verdict requires the row to carry its candidate manifest hash'
        }
    }

    $evidenceRoot = $Context.EvidenceRootRelative
    $reviewsRelative = ('{0}/reviews/{1}' -f $evidenceRoot, $Context.ExpectedAttemptId)
    $operations = New-Object System.Collections.ArrayList

    $installs = @(
        @{ Name = 'native-review.md'; Document = $native },
        @{ Name = 'evidence-review.md'; Document = $evidence },
        @{ Name = 'source-verdict.md'; Document = $verdict }
    )
    foreach ($install in $installs) {
        [void]$operations.Add((New-C4RecorderOperation -Operation 'CREATE' `
            -RelativePath ($reviewsRelative + '/' + $install.Name) -Class 'IMMUTABLE' `
            -OldSha256 $null -NewSha256 $install.Document.Sha256 `
            -SourcePath $install.Document.Path))
    }

    # The three maintained latest pointers live beside the evidence root, one
    # level up: they are top-level fixed-date files, not per-attempt objects.
    $evidenceParent = $evidenceRoot.Substring(0, $evidenceRoot.LastIndexOf('/'))
    $pointers = @(
        @{ Key = 'nativeReview'; Kind = 'native review'
           Relative = ($reviewsRelative + '/native-review.md'); Sha = $native.Sha256 },
        @{ Key = 'evidenceReview'; Kind = 'evidence review'
           Relative = ($reviewsRelative + '/evidence-review.md'); Sha = $evidence.Sha256 },
        @{ Key = 'sourceVerdict'; Kind = 'source verdict'
           Relative = ($reviewsRelative + '/source-verdict.md'); Sha = $verdict.Sha256 }
    )
    foreach ($pointer in $pointers) {
        $relative = $evidenceParent + '/' + $script:LatestPointerNames[$pointer.Key]
        $absolute = [IO.Path]::GetFullPath(
            (Join-Path $Context.RepositoryRoot ($relative.Replace('/', '\'))))
        $bytes = New-C4LatestPointerBytes -Kind $pointer.Kind -RelativePath $pointer.Relative `
            -Sha256 $pointer.Sha -AttemptId $Context.ExpectedAttemptId `
            -SourceTree ([string]$row.sourceTree)
        $old = $null
        $operation = 'CREATE'
        if ([IO.File]::Exists($absolute)) {
            $old = Get-C4RecorderSha256File $absolute
            $operation = 'REPLACE'
        }
        [void]$operations.Add((New-C4RecorderOperation -Operation $operation `
            -RelativePath $relative -Class 'MUTABLE' -OldSha256 $old `
            -NewSha256 (Get-C4EvidenceSha256Hex $bytes) -NewBytes $bytes))
    }

    # Promotion is PASS-only, and it copies the attempt-local candidate manifest
    # byte-for-byte rather than regenerating it.
    $candidateRelative = $evidenceRoot + '/' + $script:CandidateName
    $candidateAbsolute = [IO.Path]::GetFullPath(
        (Join-Path $Context.RepositoryRoot ($candidateRelative.Replace('/', '\'))))
    $promote = ($sourceVerdict -ceq 'PASS')
    if ($promote) {
        $attemptCandidate = [IO.Path]::GetFullPath((Join-Path $Context.RepositoryRoot (($evidenceRoot + '/' + [string]$row.relativePath + '/' + $script:CandidateName).Replace('/', '\'))))
        if (-not [IO.File]::Exists($attemptCandidate)) {
            throw 'the eligible attempt does not carry its own candidate manifest'
        }
        $candidateBytes = [IO.File]::ReadAllBytes($attemptCandidate)
        $candidateSha = Get-C4EvidenceSha256Hex $candidateBytes
        if ($candidateSha -cne ([string]$row.candidateManifestSha256)) {
            throw 'the attempt-local candidate manifest does not match the ledger row hash'
        }
        [void](ConvertFrom-C4CanonicalJsonBytes -Bytes $candidateBytes `
            -ExpectedSchema $script:CandidateSchema)
        $old = $null
        $operation = 'CREATE'
        if ([IO.File]::Exists($candidateAbsolute)) {
            $old = Get-C4RecorderSha256File $candidateAbsolute
            $operation = 'REPLACE'
        }
        [void]$operations.Add((New-C4RecorderOperation -Operation $operation `
            -RelativePath $candidateRelative -Class 'MUTABLE' -OldSha256 $old `
            -NewSha256 $candidateSha -NewBytes $candidateBytes))
    }

    $updated = ConvertTo-C4SourceIndexOrdered $index
    $rows = @($updated['attempts'])
    for ($i = 0; $i -lt $rows.Count; $i++) {
        if (([string]$rows[$i]['attemptId']) -cne $Context.ExpectedAttemptId) { continue }
        $rows[$i]['nativeReviewRelativePath'] = ('reviews/{0}/native-review.md' -f
            $Context.ExpectedAttemptId)
        $rows[$i]['nativeReviewSha256'] = $native.Sha256
        $rows[$i]['evidenceReviewRelativePath'] = ('reviews/{0}/evidence-review.md' -f
            $Context.ExpectedAttemptId)
        $rows[$i]['evidenceReviewSha256'] = $evidence.Sha256
        $rows[$i]['reviewStatus'] = $reviewStatus
        $rows[$i]['sourceVerdictRelativePath'] = ('reviews/{0}/source-verdict.md' -f
            $Context.ExpectedAttemptId)
        $rows[$i]['sourceVerdictSha256'] = $verdict.Sha256
        $rows[$i]['sourceVerdict'] = $sourceVerdict
    }
    $updated['attempts'] = @($rows)

    if ($promote) {
        $previous = $updated['eligibleCandidateAttemptId']
        $reason = 'INITIAL_PASS'
        if (-not [string]::IsNullOrWhiteSpace([string]$previous)) { $reason = 'SUPERSEDE_PASS' }
        $event = [ordered]@{
            ordinal = (@($updated['eligibilityEvents']).Count + 1)
            previousAttemptId = $previous
            eligibleAttemptId = $Context.ExpectedAttemptId
            candidateManifestSha256 = [string]$row.candidateManifestSha256
            reason = $reason
            sourceVerdictSha256 = $verdict.Sha256
        }
        $updated['eligibilityEvents'] = @(@($updated['eligibilityEvents']) + @($event))
        $updated['eligibleCandidateAttemptId'] = $Context.ExpectedAttemptId
    }

    Assert-C4SourceHistoryUnchanged $index $updated
    $ledgerBytes = Get-C4RecorderCanonicalBytes $updated
    $ledgerRelative = $evidenceRoot + '/' + $script:SourceIndexName
    [void]$operations.Add((New-C4RecorderOperation -Operation 'REPLACE' `
        -RelativePath $ledgerRelative -Class 'LEDGER' `
        -OldSha256 (Get-C4RecorderSha256File $Context.LedgerAbsolutePath) `
        -NewSha256 (Get-C4EvidenceSha256Hex $ledgerBytes) -NewBytes $ledgerBytes))

    $receipt = New-C4RecorderReceipt -RecorderSha256 $Context.RecorderSha256 `
        -Mode 'FinalizeSourceReview' -AttemptId $Context.ExpectedAttemptId `
        -BootstrapSourceCommit $null -BootstrapSourceTree $null -BootstrapSha256 $null `
        -CheckpointACommit $Context.ExpectedCheckpointACommit -SourceVerdict $sourceVerdict `
        -AttemptStatus $null -Operations @($operations)

    return (Invoke-C4RecorderTransaction -Context $Context -Mode 'FinalizeSourceReview' `
        -AttemptId $Context.ExpectedAttemptId -LedgerRelativePath $ledgerRelative `
        -LedgerNewBytes $ledgerBytes -Operations @($operations) -Receipt $receipt)
}

# ---------------------------------------------------------------------------
# Mode: WithdrawSourceCandidate
#
# Appends only WITHDRAW_SOURCE_DEFECT and removes only the promoted top-level
# copy. The attempt, its reviews, its verdict and its own candidate manifest all
# stay exactly where they are: withdrawal changes eligibility, never history.
# ---------------------------------------------------------------------------

function Invoke-C4WithdrawSourceCandidate {
    param($Context)

    Assert-C4RecorderAttemptId $Context.ExpectedEligibleAttemptId 'ExpectedEligibleAttemptId'
    Assert-C4RecorderHex $Context.ExpectedCandidateManifestSha256 64 'ExpectedCandidateManifestSha256'

    $index = Read-C4SourceIndex $Context.LedgerAbsolutePath
    if (([string]$index.eligibleCandidateAttemptId) -cne $Context.ExpectedEligibleAttemptId) {
        throw ("the eligible candidate is {0}, not the expected {1}; this pointer is stale" -f
            $index.eligibleCandidateAttemptId, $Context.ExpectedEligibleAttemptId)
    }
    $row = Get-C4SourceIndexRow $index $Context.ExpectedEligibleAttemptId
    if ($null -eq $row) { throw 'the eligible attempt has no ledger row' }
    if (([string]$row.candidateManifestSha256) -cne $Context.ExpectedCandidateManifestSha256) {
        throw 'the eligible row does not carry the expected candidate manifest hash'
    }

    $evidenceRoot = $Context.EvidenceRootRelative
    $candidateRelative = $evidenceRoot + '/' + $script:CandidateName
    $candidateAbsolute = [IO.Path]::GetFullPath(
        (Join-Path $Context.RepositoryRoot ($candidateRelative.Replace('/', '\'))))
    if (-not [IO.File]::Exists($candidateAbsolute)) {
        throw 'there is no promoted top-level candidate manifest to withdraw'
    }
    $promotedSha = Get-C4RecorderSha256File $candidateAbsolute
    if ($promotedSha -cne $Context.ExpectedCandidateManifestSha256) {
        throw 'the promoted candidate manifest does not match its expected identity'
    }

    $operations = New-Object System.Collections.ArrayList
    [void]$operations.Add((New-C4RecorderOperation -Operation 'DELETE' `
        -RelativePath $candidateRelative -Class 'MUTABLE' -OldSha256 $promotedSha `
        -NewSha256 $null))

    $updated = ConvertTo-C4SourceIndexOrdered $index
    $event = [ordered]@{
        ordinal = (@($updated['eligibilityEvents']).Count + 1)
        previousAttemptId = $Context.ExpectedEligibleAttemptId
        eligibleAttemptId = $null
        candidateManifestSha256 = $null
        reason = 'WITHDRAW_SOURCE_DEFECT'
        sourceVerdictSha256 = $null
    }
    $updated['eligibilityEvents'] = @(@($updated['eligibilityEvents']) + @($event))
    $updated['eligibleCandidateAttemptId'] = $null
    Assert-C4SourceHistoryUnchanged $index $updated

    $ledgerBytes = Get-C4RecorderCanonicalBytes $updated
    $ledgerRelative = $evidenceRoot + '/' + $script:SourceIndexName
    [void]$operations.Add((New-C4RecorderOperation -Operation 'REPLACE' `
        -RelativePath $ledgerRelative -Class 'LEDGER' `
        -OldSha256 (Get-C4RecorderSha256File $Context.LedgerAbsolutePath) `
        -NewSha256 (Get-C4EvidenceSha256Hex $ledgerBytes) -NewBytes $ledgerBytes))

    $receipt = New-C4RecorderReceipt -RecorderSha256 $Context.RecorderSha256 `
        -Mode 'WithdrawSourceCandidate' -AttemptId $Context.ExpectedEligibleAttemptId `
        -BootstrapSourceCommit $null -BootstrapSourceTree $null -BootstrapSha256 $null `
        -CheckpointACommit $null -SourceVerdict $null -AttemptStatus $null `
        -Operations @($operations)

    return (Invoke-C4RecorderTransaction -Context $Context -Mode 'WithdrawSourceCandidate' `
        -AttemptId $Context.ExpectedEligibleAttemptId -LedgerRelativePath $ledgerRelative `
        -LedgerNewBytes $ledgerBytes -Operations @($operations) -Receipt $receipt)
}

# ---------------------------------------------------------------------------
# Mode: RecordNativeAttempt
#
# Two legal branches and nothing between them. The **bound** branch requires all
# eight candidate identity fields non-null and reparses the source ledger, the
# eligible row, both reviews and the candidate to prove the attempt names the
# authenticated candidate. The **unbound** branch exists only for a sealed
# zero-mutation NOT RUN whose closed reason is that the candidate could not be
# resolved; it validates the bootstrap and the native ledger but deliberately
# does not require the invalid source bytes to parse, because the sealed attempt
# has already summarized them as a bounded read-only observation.
# ---------------------------------------------------------------------------

function New-C4EmptyNativeIndex {
    return [ordered]@{
        schema = $script:NativeIndexSchema
        version = 1
        attempts = @()
    }
}

function ConvertTo-C4NativeIndexOrdered {
    param($Index)
    $rows = New-Object System.Collections.ArrayList
    foreach ($row in @($Index.attempts)) {
        $ordered = [ordered]@{}
        foreach ($key in $script:NativeIndexRowKeys) { $ordered[$key] = $row.$key }
        [void]$rows.Add($ordered)
    }
    return [ordered]@{
        schema = $script:NativeIndexSchema
        version = 1
        attempts = @($rows)
    }
}

function Read-C4NativeIndex {
    param([string]$Path)
    if (-not [IO.File]::Exists($Path)) { return (New-C4EmptyNativeIndex) }
    $index = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($Path)) `
        -ExpectedSchema $script:NativeIndexSchema
    Assert-C4RecorderExactKeys $index @('schema', 'version', 'attempts') 'native index'
    $seen = @{}
    foreach ($row in @($index.attempts)) {
        Assert-C4RecorderExactKeys $row $script:NativeIndexRowKeys 'native index row'
        Assert-C4RecorderAttemptId ([string]$row.attemptId) 'native index attemptId'
        if ($seen.ContainsKey([string]$row.attemptId)) {
            throw 'the native index carries a duplicate attempt row'
        }
        $seen[[string]$row.attemptId] = $true
        if ($script:NativeStatuses -cnotcontains [string]$row.status) {
            throw ("native index row {0} has an unknown status" -f $row.attemptId)
        }
        $bound = @($script:NativeCandidateIdentityKeys |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$row.$_) }).Count
        if ($bound -ne 0 -and $bound -ne $script:NativeCandidateIdentityKeys.Count) {
            throw ("native index row {0} is neither fully bound nor fully null" -f $row.attemptId)
        }
    }
    return $index
}

function Invoke-C4RecordNativeAttempt {
    param($Context)

    Assert-C4RecorderAttemptId $Context.ExpectedAttemptId 'ExpectedAttemptId'
    Assert-C4RecorderHex $Context.ExpectedBootstrapSourceCommit 40 'ExpectedBootstrapSourceCommit'
    Assert-C4RecorderHex $Context.ExpectedBootstrapSourceTree 40 'ExpectedBootstrapSourceTree'
    Assert-C4RecorderHex $Context.ExpectedBootstrapSha256 64 'ExpectedBootstrapSha256'

    $sealed = Read-C4SealedAttempt -Directory $Context.ExternalAttemptDirectory `
        -AttemptSchema $script:NativeAttemptSchema -FilesSchema $script:NativeAttemptFilesSchema
    $manifest = $sealed.Manifest
    Assert-C4RecorderExactKeys $manifest $script:NativeAttemptKeys 'sealed native attempt.json'
    Assert-C4RecorderExactKeys $manifest.hostIdentity $script:NativeHostIdentityKeys `
        'native hostIdentity'
    Assert-C4RecorderExactKeys $manifest.bootIdentity $script:NativeBootIdentityKeys `
        'native bootIdentity'
    if (([string]$manifest.attemptId) -cne $Context.ExpectedAttemptId) {
        throw 'the sealed native attempt names a different attempt'
    }

    # bootstrap.json is inside the sealed roster and its three fields must equal
    # the mandatory expected arguments.
    $bootstrapPath = Join-Path $sealed.Root $script:BootstrapName
    if (-not [IO.File]::Exists($bootstrapPath)) {
        throw 'the sealed native attempt does not carry bootstrap.json'
    }
    $bootstrapBytes = [IO.File]::ReadAllBytes($bootstrapPath)
    $bootstrapSha = Get-C4EvidenceSha256Hex $bootstrapBytes
    if ($bootstrapSha -cne $Context.ExpectedBootstrapSha256) {
        throw 'bootstrap.json does not hash to the expected bootstrap SHA-256'
    }
    $bootstrap = ConvertFrom-C4CanonicalJsonBytes -Bytes $bootstrapBytes `
        -ExpectedSchema 'fsring-c4-native-bootstrap/v1'
    if (([string]$bootstrap.sourceCommit) -cne $Context.ExpectedBootstrapSourceCommit -or
        ([string]$bootstrap.sourceTree) -cne $Context.ExpectedBootstrapSourceTree) {
        throw 'bootstrap.json does not name the expected B,BT'
    }
    foreach ($pair in @(
            @{ Key = 'bootstrapSourceCommit'; Expected = $Context.ExpectedBootstrapSourceCommit },
            @{ Key = 'bootstrapSourceTree'; Expected = $Context.ExpectedBootstrapSourceTree },
            @{ Key = 'bootstrapSha256'; Expected = $Context.ExpectedBootstrapSha256 })) {
        if (([string]$manifest.($pair.Key)) -cne $pair.Expected) {
            throw ("the sealed native attempt.json {0} does not equal its expected value" -f
                $pair.Key)
        }
    }

    if ($script:NativeStatuses -cnotcontains ([string]$manifest.status)) {
        throw 'the sealed native attempt has an unknown status'
    }
    $bound = @($script:NativeCandidateIdentityKeys |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$manifest.$_) }).Count
    if ($bound -ne 0 -and $bound -ne $script:NativeCandidateIdentityKeys.Count) {
        throw 'the sealed native attempt is neither fully bound nor fully null'
    }
    $isBound = ($bound -ne 0)

    if ($isBound) {
        # Reparse the source side from scratch: the candidate this attempt claims
        # must be the one the source ledger actually authenticated.
        $sourceLedger = [IO.Path]::GetFullPath((Join-Path $Context.RepositoryRoot (($Context.SourceEvidenceRootRelative + '/' + $script:SourceIndexName).Replace('/', '\'))))
        $sourceIndex = Read-C4SourceIndex $sourceLedger
        $eligible = [string]$sourceIndex.eligibleCandidateAttemptId
        if ([string]::IsNullOrWhiteSpace($eligible)) {
            throw 'a bound native attempt requires an eligible source candidate'
        }
        if ($eligible -cne ([string]$manifest.sourceAttemptId)) {
            throw 'the native attempt names a source attempt that is not the eligible candidate'
        }
        $sourceRow = Get-C4SourceIndexRow $sourceIndex $eligible
        if ($null -eq $sourceRow) { throw 'the eligible source attempt has no ledger row' }
        foreach ($pair in @(
                @{ Native = 'sourceCommit'; Source = 'sourceCommit' },
                @{ Native = 'sourceTree'; Source = 'sourceTree' },
                @{ Native = 'candidateManifestSha256'; Source = 'candidateManifestSha256' },
                @{ Native = 'nativeReviewSha256'; Source = 'nativeReviewSha256' },
                @{ Native = 'evidenceReviewSha256'; Source = 'evidenceReviewSha256' })) {
            if (([string]$manifest.($pair.Native)) -cne ([string]$sourceRow.($pair.Source))) {
                throw ("the native attempt's {0} does not equal the authenticated candidate's {1}" -f
                    $pair.Native, $pair.Source)
            }
        }
        if (([string]$sourceRow.sourceVerdict) -cne 'PASS' -or
            ([string]$sourceRow.reviewStatus) -cne 'PASS') {
            throw 'a bound native attempt requires a PASS review status and source verdict'
        }
    } else {
        if (([string]$manifest.status) -cne 'NOT_RUN') {
            throw 'an unbound native attempt is publishable only as NOT_RUN'
        }
        if (([string]$manifest.phase) -cne 'ARTIFACT_INITIAL') {
            throw 'an unbound native attempt must be sealed at ARTIFACT_INITIAL'
        }
        if ([int]$manifest.mutationAttempts -ne 0) {
            throw 'an unbound native attempt must record zero mutation attempts'
        }
        # `commandIssued` is an object of three booleans and `liveIssued` is the
        # separate boolean beside it, so each is read by name.
        foreach ($field in @('initialPreflight', 'finalPreflight', 'live')) {
            if ($manifest.commandIssued.$field -ne $false) {
                throw ("an unbound native attempt must have commandIssued.{0} false" -f $field)
            }
        }
        if ($manifest.liveIssued -ne $false) {
            throw 'an unbound native attempt must have liveIssued false'
        }
        $reasons = @($manifest.reasonCodes)
        if ($reasons.Count -ne 1 -or $script:UnboundNativeReasons -cnotcontains ([string]$reasons[0])) {
            throw ('an unbound native attempt must carry exactly one of the three closed ' +
                'missing/invalid reason codes')
        }
    }

    $nativeRoot = $Context.EvidenceRootRelative
    $attemptRelative = ('{0}/attempt-{1}' -f $nativeRoot, $Context.ExpectedAttemptId)
    $index = Read-C4NativeIndex $Context.LedgerAbsolutePath
    foreach ($existing in @($index.attempts)) {
        if (([string]$existing.attemptId) -ceq $Context.ExpectedAttemptId) {
            throw 'the native index already carries this attempt; this is a replay'
        }
    }

    $operations = New-Object System.Collections.ArrayList
    $allFiles = @(@($sealed.Files) + @($script:AttemptFilesName, $script:AttemptManifestName) |
        Sort-Object -CaseSensitive)
    foreach ($relative in $allFiles) {
        $source = [IO.Path]::GetFullPath((Join-Path $sealed.Root ($relative.Replace('/', '\'))))
        [void]$operations.Add((New-C4RecorderOperation -Operation 'CREATE' `
            -RelativePath ($attemptRelative + '/' + $relative) -Class 'IMMUTABLE' `
            -OldSha256 $null -NewSha256 (Get-C4RecorderSha256File $source) -SourcePath $source))
    }

    # The native summary is authored by the coordinator in the worktree. The
    # recorder does not write its prose -- it proves the file is there, hashes
    # it, and puts it in the roster so StageReceipt stages exactly it.
    $summaryRelative = Assert-C4RecorderRelativePath $Context.NativeSummaryPath 'NativeSummaryPath'
    $summaryAbsolute = [IO.Path]::GetFullPath(
        (Join-Path $Context.RepositoryRoot ($summaryRelative.Replace('/', '\'))))
    if (-not [IO.File]::Exists($summaryAbsolute)) {
        throw ("the native summary does not exist: {0}" -f $summaryRelative)
    }
    $summarySha = Get-C4RecorderSha256File $summaryAbsolute
    $summaryHead = Invoke-C4RecorderGit $Context.Git `
        @('cat-file', '-e', ('HEAD:' + $summaryRelative)) -AllowFailure
    # A WORKTREE row carries no old hash: the recorder never wrote those bytes,
    # so it has no prior value of its own to record. Whether HEAD carried the
    # path is exactly what the CREATE/REPLACE word says, and StageReceipt
    # re-derives it from HEAD rather than trusting this row.
    $summaryOperation = 'CREATE'
    if ($summaryHead.ExitCode -eq 0) { $summaryOperation = 'REPLACE' }
    [void]$operations.Add((New-C4RecorderOperation -Operation $summaryOperation `
        -RelativePath $summaryRelative -Class 'WORKTREE' -OldSha256 $null `
        -NewSha256 $summarySha))

    $row = [ordered]@{}
    $manifestKeys = @($manifest.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($key in $script:NativeIndexRowKeys) {
        # Only copy what attempt.json actually carries: `relativePath` and
        # `attemptJsonSha256` are index-row fields the recorder computes, and
        # under StrictMode reading an absent property is a terminating error.
        if ($manifestKeys -ccontains $key) { $row[$key] = $manifest.$key } else { $row[$key] = $null }
    }
    $row['attemptId'] = $Context.ExpectedAttemptId
    $row['relativePath'] = ('attempt-{0}' -f $Context.ExpectedAttemptId)
    $row['bootstrapSourceCommit'] = $Context.ExpectedBootstrapSourceCommit
    $row['bootstrapSourceTree'] = $Context.ExpectedBootstrapSourceTree
    $row['bootstrapSha256'] = $Context.ExpectedBootstrapSha256
    $row['status'] = [string]$manifest.status
    $row['attemptFilesSha256'] = $sealed.RosterSha256
    $row['attemptJsonSha256'] = $sealed.ManifestSha256

    $updated = ConvertTo-C4NativeIndexOrdered $index
    $updated['attempts'] = @(@($updated['attempts']) + @($row))
    $ledgerBytes = Get-C4RecorderCanonicalBytes $updated
    $ledgerRelative = $nativeRoot + '/' + $script:NativeIndexName
    $ledgerOld = $null
    if ([IO.File]::Exists($Context.LedgerAbsolutePath)) {
        $ledgerOld = Get-C4RecorderSha256File $Context.LedgerAbsolutePath
    }
    $ledgerOperation = 'REPLACE'
    if ($null -eq $ledgerOld) { $ledgerOperation = 'CREATE' }
    [void]$operations.Add((New-C4RecorderOperation -Operation $ledgerOperation `
        -RelativePath $ledgerRelative -Class 'LEDGER' -OldSha256 $ledgerOld `
        -NewSha256 (Get-C4EvidenceSha256Hex $ledgerBytes) -NewBytes $ledgerBytes))

    $receipt = New-C4RecorderReceipt -RecorderSha256 $Context.RecorderSha256 `
        -Mode 'RecordNativeAttempt' -AttemptId $Context.ExpectedAttemptId `
        -BootstrapSourceCommit $Context.ExpectedBootstrapSourceCommit `
        -BootstrapSourceTree $Context.ExpectedBootstrapSourceTree `
        -BootstrapSha256 $Context.ExpectedBootstrapSha256 -CheckpointACommit $null `
        -SourceVerdict $null -AttemptStatus ([string]$manifest.status) `
        -Operations @($operations)

    return (Invoke-C4RecorderTransaction -Context $Context -Mode 'RecordNativeAttempt' `
        -AttemptId $Context.ExpectedAttemptId -LedgerRelativePath $ledgerRelative `
        -LedgerNewBytes $ledgerBytes -Operations @($operations) -Receipt $receipt)
}

$script:NativeSummaryName = '2026-08-08-c4-recovery-native.md'

# ---------------------------------------------------------------------------
# Mode: StageReceipt
#
# This mode performs no evidence-content mutation. Its whole job is to decide,
# independently of the receipt it is checking, which paths the committed
# poststate says should be staged -- then stage exactly those and prove the
# index agrees.
#
# "Independently" is the load-bearing word. The roster is reconstructed from the
# installed `attempt-files.json`, the ledger, and the fixed path constants; each
# path's operation comes from whether HEAD carries that path, not from the word
# the receipt used. A scalar check of the receipt, or a hard-coded superset,
# would let a receipt that lied about its own roster through.
# ---------------------------------------------------------------------------

function Get-C4StagePathsFromInstalledAttempt {
    param([string]$RepositoryRoot, [string]$AttemptDirectoryRelative)

    $absolute = [IO.Path]::GetFullPath(
        (Join-Path $RepositoryRoot ($AttemptDirectoryRelative.Replace('/', '\'))))
    $filesPath = Join-Path $absolute $script:AttemptFilesName
    if (-not [IO.File]::Exists($filesPath)) {
        throw ("the installed attempt has no {0}" -f $script:AttemptFilesName)
    }
    $roster = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($filesPath))
    $names = New-Object System.Collections.ArrayList
    foreach ($row in @($roster.files)) { [void]$names.Add([string]$row.relativePath) }
    [void]$names.Add($script:AttemptFilesName)
    [void]$names.Add($script:AttemptManifestName)
    $ordered = @(@($names) | Sort-Object -CaseSensitive)
    return @($ordered | ForEach-Object { $AttemptDirectoryRelative + '/' + $_ })
}

function Find-C4InstalledAttemptDirectory {
    param([string]$RepositoryRoot, [string]$EvidenceRootRelative, [string]$Pattern)

    $rootAbsolute = [IO.Path]::GetFullPath(
        (Join-Path $RepositoryRoot ($EvidenceRootRelative.Replace('/', '\'))))
    if (-not [IO.Directory]::Exists($rootAbsolute)) {
        throw ("the evidence root does not exist: {0}" -f $EvidenceRootRelative)
    }
    $matches = @([IO.Directory]::GetDirectories($rootAbsolute, $Pattern) |
        ForEach-Object { [IO.Path]::GetFileName($_) })
    if ($matches.Count -ne 1) {
        throw ("{0} installed attempt directories match {1}; exactly one is required" -f
            $matches.Count, $Pattern)
    }
    return ($EvidenceRootRelative + '/' + $matches[0])
}

function Get-C4DerivedStageRoster {
    param($Context, $Receipt)

    $mode = [string]$Receipt.mode
    $attemptId = [string]$Receipt.attemptId
    $evidenceRoot = $Context.EvidenceRootRelative
    $evidenceParent = $evidenceRoot.Substring(0, $evidenceRoot.LastIndexOf('/'))
    $paths = New-Object System.Collections.ArrayList

    if ($mode -ceq 'RecordSourceAttempt') {
        $attemptDirectory = Find-C4InstalledAttemptDirectory -RepositoryRoot $Context.RepositoryRoot `
            -EvidenceRootRelative $evidenceRoot -Pattern ('attempt-*-' + $attemptId)
        foreach ($path in (Get-C4StagePathsFromInstalledAttempt `
                -RepositoryRoot $Context.RepositoryRoot `
                -AttemptDirectoryRelative $attemptDirectory)) {
            [void]$paths.Add($path)
        }
        $readme = $evidenceRoot + '/' + $script:LogsReadmeName
        if (-not (Test-C4PathInHead $Context $readme)) { [void]$paths.Add($readme) }
        [void]$paths.Add($evidenceRoot + '/' + $script:SourceIndexName)
    } elseif ($mode -ceq 'FinalizeSourceReview') {
        $reviews = ('{0}/reviews/{1}' -f $evidenceRoot, $attemptId)
        foreach ($name in @('native-review.md', 'evidence-review.md', 'source-verdict.md')) {
            [void]$paths.Add($reviews + '/' + $name)
        }
        foreach ($key in @($script:LatestPointerNames.Keys)) {
            [void]$paths.Add($evidenceParent + '/' + $script:LatestPointerNames[$key])
        }
        # The promotion is visible in the committed poststate: the ledger's own
        # pointer decides whether the top-level candidate is part of this
        # transaction, so a receipt cannot invent or suppress it.
        $ledger = Read-C4SourceIndex $Context.LedgerAbsolutePath
        if (([string]$ledger.eligibleCandidateAttemptId) -ceq $attemptId) {
            [void]$paths.Add($evidenceRoot + '/' + $script:CandidateName)
        }
        [void]$paths.Add($evidenceRoot + '/' + $script:SourceIndexName)
    } elseif ($mode -ceq 'WithdrawSourceCandidate') {
        [void]$paths.Add($evidenceRoot + '/' + $script:CandidateName)
        [void]$paths.Add($evidenceRoot + '/' + $script:SourceIndexName)
    } elseif ($mode -ceq 'RecordNativeAttempt') {
        $attemptDirectory = Find-C4InstalledAttemptDirectory -RepositoryRoot $Context.RepositoryRoot `
            -EvidenceRootRelative $evidenceRoot -Pattern ('attempt-' + $attemptId)
        foreach ($path in (Get-C4StagePathsFromInstalledAttempt `
                -RepositoryRoot $Context.RepositoryRoot `
                -AttemptDirectoryRelative $attemptDirectory)) {
            [void]$paths.Add($path)
        }
        [void]$paths.Add($evidenceParent + '/' + $script:NativeSummaryName)
        [void]$paths.Add($evidenceRoot + '/' + $script:NativeIndexName)
    } else {
        throw ("StageReceipt cannot derive a roster for mode {0}" -f $mode)
    }

    foreach ($unowned in $script:UnownedEvidencePaths) {
        if (@($paths) -ccontains $unowned) {
            throw ("no recorder mode owns {0}; it must never be staged here" -f $unowned)
        }
    }
    return @($paths)
}

function Test-C4PathInHead {
    param($Context, [string]$RelativePath)
    $result = Invoke-C4RecorderGit $Context.Git @('cat-file', '-e', ('HEAD:' + $RelativePath)) `
        -AllowFailure
    return ($result.ExitCode -eq 0)
}

function Get-C4DerivedOperation {
    param($Context, [string]$RelativePath)

    $absolute = [IO.Path]::GetFullPath(
        (Join-Path $Context.RepositoryRoot ($RelativePath.Replace('/', '\'))))
    $inHead = Test-C4PathInHead $Context $RelativePath
    $present = [IO.File]::Exists($absolute)
    if ($present -and -not $inHead) { return 'CREATE' }
    if ($present -and $inHead) { return 'REPLACE' }
    if (-not $present -and $inHead) { return 'DELETE' }
    throw ("{0} is neither in HEAD nor in the worktree: it was created and removed " +
        "without an intervening commit, so there is nothing to stage for it" -f $RelativePath)
}

function Invoke-C4StageReceipt {
    param($Context)

    Assert-C4RecorderAttemptId $Context.ExpectedAttemptId 'ExpectedAttemptId'
    $receiptPath = Assert-C4RecorderAbsolutePath $Context.InputReceiptPath 'InputReceiptPath'
    if (-not [IO.File]::Exists($receiptPath)) {
        throw 'InputReceiptPath does not exist'
    }
    $receipt = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($receiptPath)) `
        -ExpectedSchema $script:ReceiptSchema
    Assert-C4RecorderExactKeys $receipt $script:ReceiptKeys 'receipt'
    if ([int]$receipt.version -ne 1) { throw 'the receipt is not version 1' }

    # self-handle hash == -ExpectedRecorderSha256 == receipt.recorderSha256
    if (([string]$receipt.recorderSha256) -cne $Context.RecorderSha256) {
        throw 'the receipt was written by different recorder bytes than these'
    }
    if (([string]$receipt.mode) -cne $Context.ExpectedRecordedMode) {
        throw ("the receipt records mode {0}, not the expected {1}" -f
            $receipt.mode, $Context.ExpectedRecordedMode)
    }
    if (([string]$receipt.attemptId) -cne $Context.ExpectedAttemptId) {
        throw 'the receipt records a different attempt'
    }

    $derived = Get-C4DerivedStageRoster $Context $receipt
    $claimed = @(@($receipt.changedPaths) | ForEach-Object { [string]$_.relativePath })
    if (($derived -join '|') -cne ($claimed -join '|')) {
        throw ("the receipt roster is not the roster the committed poststate implies" +
            [Environment]::NewLine + '  derived: ' + ($derived -join ',') +
            [Environment]::NewLine + '  receipt: ' + ($claimed -join ','))
    }

    $index = 0
    foreach ($row in @($receipt.changedPaths)) {
        Assert-C4RecorderExactKeys $row $script:OperationKeys 'receipt changed-path row'
        $relative = [string]$row.relativePath
        $operation = Get-C4DerivedOperation $Context $relative
        if (([string]$row.operation) -cne $operation) {
            throw ("{0} is a {1} in the committed poststate, not the receipt's {2}" -f
                $relative, $operation, $row.operation)
        }
        $absolute = [IO.Path]::GetFullPath(
            (Join-Path $Context.RepositoryRoot ($relative.Replace('/', '\'))))
        if ($operation -ceq 'DELETE') {
            if ($null -ne $row.sha256) {
                throw ("{0} is a DELETE and must carry a null hash" -f $relative)
            }
            if ([IO.File]::Exists($absolute)) {
                throw ("{0} is recorded DELETE but still present" -f $relative)
            }
        } else {
            if ([string]::IsNullOrWhiteSpace([string]$row.sha256)) {
                throw ("{0} is a {1} and must carry a hash" -f $relative, $operation)
            }
            if ((Get-C4RecorderSha256File $absolute) -cne ([string]$row.sha256)) {
                throw ("{0} does not hash to the value the receipt records" -f $relative)
            }
        }
        $index += 1
    }

    # Nothing may already be staged, and the working tree must be dirty in
    # exactly this roster: an unrelated edit riding along in the same commit is
    # what this refusal exists to stop.
    $staged = Invoke-C4RecorderGit $Context.Git @('diff', '--cached', '--name-only')
    $stagedPaths = @(@($staged.Lines) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($stagedPaths.Count -ne 0) {
        throw ("the index already carries staged paths: {0}" -f ($stagedPaths -join ','))
    }
    $status = Invoke-C4RecorderGit $Context.Git @('status', '--porcelain', '--untracked-files=all')
    $dirty = New-Object System.Collections.ArrayList
    foreach ($line in @($status.Lines)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $path = $line.Substring(3).Trim()
        if ($path.StartsWith('"') -and $path.EndsWith('"')) {
            $path = $path.Substring(1, $path.Length - 2)
        }
        [void]$dirty.Add($path.Replace('\', '/'))
    }
    $dirtySorted = @(@($dirty) | Sort-Object -CaseSensitive)
    $derivedSorted = @(@($derived) | Sort-Object -CaseSensitive)
    $extra = @(@($dirtySorted) | Where-Object { $derivedSorted -cnotcontains $_ })
    if ($extra.Count -ne 0) {
        throw ("the working tree is dirty outside this transaction's roster: {0}" -f
            ($extra -join ','))
    }
    $missing = @(@($derivedSorted) | Where-Object { $dirtySorted -cnotcontains $_ })
    if ($missing.Count -ne 0) {
        throw ("the working tree does not carry every rostered change: {0}" -f
            ($missing -join ','))
    }

    Invoke-C4RecorderGitAddRoster $Context.Git $derivedSorted
    # Mandated backstop, deliberately unreachable from the suite: every way the
    # index could come back different from the validated roster is refused by a
    # check above. An ignored roster path is not in the dirty set (and `git add`
    # exits nonzero on it anyway); an unchanged path is not dirty either; a path
    # in neither HEAD nor the worktree fails operation derivation. This exists
    # against a change in git's behaviour, and the self-test does not claim to
    # exercise it.
    $after = Invoke-C4RecorderGit $Context.Git @('diff', '--cached', '--name-only')
    $afterPaths = @(@($after.Lines) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { ([string]$_).Replace('\', '/') } |
        Sort-Object -CaseSensitive)
    if (($afterPaths -join '|') -cne ($derivedSorted -join '|')) {
        throw ("the index after staging is not the validated roster: {0}" -f
            ($afterPaths -join ','))
    }

    return [ordered]@{
        schema = 'fsring-c4-evidence-recorder-staging/v1'
        version = 1
        recorderSha256 = $Context.RecorderSha256
        mode = [string]$receipt.mode
        attemptId = [string]$receipt.attemptId
        stagedPaths = @($derivedSorted)
        status = 'PASS'
    }
}

# ---------------------------------------------------------------------------
# Self-test
#
# The fixtures build a real throwaway Git repository, copy this script and the
# capture helper into it, and drive the *real entry point* as a child process.
# Nothing about git, the repository-root resolution, the self-freeze, the
# transaction or the staging validation is faked -- only the world is. No real
# evidence root is ever written, and no driver, service or DOS object is touched.
# ---------------------------------------------------------------------------

function New-C4RecorderTestWorld {
    param([string]$Root, [string]$Name)

    $world = Join-Path $Root $Name
    [void][IO.Directory]::CreateDirectory($world)
    $scripts = Join-Path $world 'driver\scripts'
    [void][IO.Directory]::CreateDirectory($scripts)
    # NOT $name: PowerShell variable names are case-insensitive, so a loop over
    # $name would overwrite this function's own $Name parameter and every world
    # after the first would be built under the last copied file's name.
    foreach ($scriptName in @('record_c4_evidence.ps1', 'invoke_c4_evidence.ps1')) {
        [IO.File]::Copy(
            (Join-Path $PSScriptRoot $scriptName), (Join-Path $scripts $scriptName), $false)
    }
    $external = [IO.Path]::GetFullPath((Join-Path $Root ($Name + '-external')))
    [void][IO.Directory]::CreateDirectory($external)

    $git = New-C4RecorderGitAdapter $world
    [void](Invoke-C4RecorderGit $git @('init', '--quiet'))
    [void](Invoke-C4RecorderGit $git @('config', 'user.email', 'selftest@example.invalid'))
    [void](Invoke-C4RecorderGit $git @('config', 'user.name', 'C4 Recorder Self Test'))
    [void](Invoke-C4RecorderGit $git @('config', 'core.autocrlf', 'false'))
    # An attempt directory is `attempt-<40 hex>-<32 hex>`, so a fixture world
    # under %TEMP% can push a path past MAX_PATH even though the real evidence
    # root never would.
    [void](Invoke-C4RecorderGit $git @('config', 'core.longpaths', 'true'))
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [IO.File]::WriteAllBytes((Join-Path $world '.gitattributes'),
        $utf8.GetBytes("* text=auto eol=lf`ndocs/superpowers/reviews/evidence/c4-recovery-logs/** -text`ndocs/superpowers/reviews/evidence/c4-recovery-native/** -text`n"))
    [void][IO.Directory]::CreateDirectory((Join-Path $world 'docs\superpowers\reviews\evidence'))
    [IO.File]::WriteAllBytes((Join-Path $world 'docs\superpowers\reviews\evidence\.keep'),
        $utf8.GetBytes(""))
    [void](Invoke-C4RecorderGit $git @('add', '-A'))
    [void](Invoke-C4RecorderGit $git @('commit', '--quiet', '-m', 'baseline'))

    $recorderPath = Join-Path $scripts 'record_c4_evidence.ps1'
    return [pscustomobject]@{
        Root = $world
        Git = $git
        Scripts = $scripts
        RecorderPath = $recorderPath
        RecorderSha256 = (Get-C4RecorderSha256File $recorderPath)
        External = $external
        SourceEvidenceRoot = 'docs/superpowers/reviews/evidence/c4-recovery-logs'
        NativeEvidenceRoot = 'docs/superpowers/reviews/evidence/c4-recovery-native'
    }
}

function Invoke-C4RecorderChild {
    param($World, [string[]]$Arguments, [string]$CrashAt)

    $scratch = Join-Path $World.External ('child-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($scratch)
    $out = Join-Path $scratch 'stdout.txt'
    $err = Join-Path $scratch 'stderr.txt'
    $previous = $env:FSRING_C4_RECORDER_CRASH_AT
    if ([string]::IsNullOrWhiteSpace($CrashAt)) {
        Remove-Item Env:\FSRING_C4_RECORDER_CRASH_AT -ErrorAction SilentlyContinue
    } else {
        $env:FSRING_C4_RECORDER_CRASH_AT = $CrashAt
    }
    try {
        $process = Start-Process -FilePath 'powershell.exe' -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $out -RedirectStandardError $err `
            -ArgumentList (@('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                '-File', $World.RecorderPath) + $Arguments)
        return [pscustomobject]@{
            ExitCode = [int]$process.ExitCode
            Stdout = [IO.File]::ReadAllText($out)
            Stderr = [IO.File]::ReadAllText($err)
        }
    } finally {
        if ([string]::IsNullOrWhiteSpace($previous)) {
            Remove-Item Env:\FSRING_C4_RECORDER_CRASH_AT -ErrorAction SilentlyContinue
        } else {
            $env:FSRING_C4_RECORDER_CRASH_AT = $previous
        }
    }
}

# --- fixture builders ------------------------------------------------------

function New-C4TestSealedSourceAttempt {
    param(
        [string]$Directory,
        [string]$AttemptId,
        [string]$Commit,
        [string]$Tree,
        [string]$GateStatus = 'PASS',
        [switch]$NoCandidate,
        [switch]$ForceCandidateOnNonPass,
        [string]$TamperFile,
        [string]$TruncateFile,
        [string]$ExtraFile,
        [switch]$BreakRosterHash
    )

    [void][IO.Directory]::CreateDirectory($Directory)
    $utf8 = New-Object System.Text.UTF8Encoding $false
    $commandIndex = [ordered]@{
        schema = 'fsring-c4-source-command-index/v1'
        version = 1
        attemptId = $AttemptId
        gateStatus = $GateStatus
    }
    $commandBytes = Get-C4RecorderCanonicalBytes $commandIndex
    [IO.File]::WriteAllBytes((Join-Path $Directory 'command-index.json'), $commandBytes)

    $files = New-Object System.Collections.ArrayList
    [void]$files.Add('command-index.json')

    $candidateSha = $null
    if (-not $NoCandidate -and ($GateStatus -ceq 'PASS' -or $ForceCandidateOnNonPass)) {
        $candidate = [ordered]@{
            schema = 'fsring-c4-candidate-artifacts/v1'
            version = 1
            attemptId = $AttemptId
            sourceCommit = $Commit
            sourceTree = $Tree
        }
        $candidateBytes = Get-C4RecorderCanonicalBytes $candidate
        [IO.File]::WriteAllBytes((Join-Path $Directory 'candidate-artifacts.json'), $candidateBytes)
        $candidateSha = Get-C4EvidenceSha256Hex $candidateBytes
        [void]$files.Add('candidate-artifacts.json')
    }
    if ($ExtraFile) {
        [IO.File]::WriteAllBytes((Join-Path $Directory $ExtraFile), $utf8.GetBytes("stray`n"))
    }

    $rows = New-Object System.Collections.ArrayList
    foreach ($name in @(@($files) | Sort-Object -CaseSensitive)) {
        $path = Join-Path $Directory $name
        $bytes = [IO.File]::ReadAllBytes($path)
        [void]$rows.Add([ordered]@{
            relativePath = $name
            bytes = [int64]$bytes.Length
            sha256 = (Get-C4EvidenceSha256Hex $bytes)
        })
    }
    $roster = [ordered]@{
        schema = 'fsring-c4-source-attempt-files/v1'
        version = 1
        attemptId = $AttemptId
        files = @($rows)
    }
    $rosterBytes = Get-C4RecorderCanonicalBytes $roster
    [IO.File]::WriteAllBytes((Join-Path $Directory 'attempt-files.json'), $rosterBytes)
    $rosterSha = Get-C4EvidenceSha256Hex $rosterBytes
    if ($BreakRosterHash) { $rosterSha = ('0' * 64) }

    $manifest = [ordered]@{
        schema = 'fsring-c4-source-attempt/v1'
        version = 1
        attemptId = $AttemptId
        sourceCommit = $Commit
        sourceTree = $Tree
        gateManifestSha256 = ('a' * 64)
        toolsSha256 = ('b' * 64)
        commandIndexSha256 = (Get-C4EvidenceSha256Hex $commandBytes)
        candidateManifestSha256 = $candidateSha
        attemptFilesSha256 = $rosterSha
        gateStatus = $GateStatus
        failure = $null
    }
    [IO.File]::WriteAllBytes((Join-Path $Directory 'attempt.json'),
        (Get-C4RecorderCanonicalBytes $manifest))

    # Tampering happens last so the roster records the honest bytes and the
    # mismatch is what the recorder has to notice.
    if ($TamperFile) {
        # Equal-length bytes on purpose: the size comparison would otherwise
        # fire first and this fixture would never reach the hash comparison.
        $original = [IO.File]::ReadAllBytes((Join-Path $Directory $TamperFile))
        $flipped = [byte[]]::new($original.Length)
        [Array]::Copy($original, $flipped, $original.Length)
        $flipped[0] = [byte](($flipped[0] -bxor 0x20))
        [IO.File]::WriteAllBytes((Join-Path $Directory $TamperFile), $flipped)
    }
    if ($TruncateFile) {
        [IO.File]::WriteAllBytes((Join-Path $Directory $TruncateFile), $utf8.GetBytes("x"))
    }
    return $Directory
}

function New-C4TestReviewDocument {
    param(
        [string]$Path,
        [string]$Role,
        [string]$AttemptId,
        [string]$Commit,
        [string]$Tree,
        [string]$CheckpointA,
        [string]$ContextId,
        [string]$InstanceId,
        [string]$OutputParent,
        [string]$Verdict = 'PASS',
        [string]$FreshContext = 'true',
        [string]$SharedDraft = 'false',
        [string]$OtherReviewRead = 'false',
        [int]$Blockers = 0,
        [int]$Highs = 0
    )

    $lines = @(
        ('<!-- c4-review:reviewRole = {0} -->' -f $Role),
        ('<!-- c4-review:attemptId = {0} -->' -f $AttemptId),
        ('<!-- c4-review:sourceCommit = {0} -->' -f $Commit),
        ('<!-- c4-review:sourceTree = {0} -->' -f $Tree),
        ('<!-- c4-review:checkpointACommit = {0} -->' -f $CheckpointA),
        ('<!-- c4-review:reviewerContextId = {0} -->' -f $ContextId),
        ('<!-- c4-review:reviewerInstanceId = {0} -->' -f $InstanceId),
        ('<!-- c4-review:outputParent = {0} -->' -f $OutputParent),
        ('<!-- c4-review:freshContext = {0} -->' -f $FreshContext),
        ('<!-- c4-review:sharedDraft = {0} -->' -f $SharedDraft),
        ('<!-- c4-review:otherReviewRead = {0} -->' -f $OtherReviewRead),
        ('<!-- c4-review:blockerFindings = {0} -->' -f $Blockers),
        ('<!-- c4-review:highFindings = {0} -->' -f $Highs),
        ('<!-- c4-review:verdict = {0} -->' -f $Verdict),
        '',
        ('# C4 recovery {0} review' -f $Role),
        '',
        ('Fixture body for {0} / {1}.' -f $Role, $ContextId)
    )
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [IO.File]::WriteAllBytes($Path, $utf8.GetBytes((($lines -join "`n") + "`n")))
    return $Path
}

function New-C4TestVerdictDocument {
    param(
        [string]$Path,
        [string]$AttemptId,
        [string]$Commit,
        [string]$Tree,
        [string]$CheckpointA,
        [string]$Verdict = 'PASS',
        [int]$RowsPass = 21,
        [int]$RowsTotal = 21,
        [int]$Blockers = 0,
        [int]$Highs = 0
    )
    $lines = @(
        ('<!-- c4-verdict:attemptId = {0} -->' -f $AttemptId),
        ('<!-- c4-verdict:sourceCommit = {0} -->' -f $Commit),
        ('<!-- c4-verdict:sourceTree = {0} -->' -f $Tree),
        ('<!-- c4-verdict:checkpointACommit = {0} -->' -f $CheckpointA),
        ('<!-- c4-verdict:rowsPass = {0} -->' -f $RowsPass),
        ('<!-- c4-verdict:rowsTotal = {0} -->' -f $RowsTotal),
        ('<!-- c4-verdict:unresolvedBlockerFindings = {0} -->' -f $Blockers),
        ('<!-- c4-verdict:unresolvedHighFindings = {0} -->' -f $Highs),
        ('<!-- c4-verdict:verdict = {0} -->' -f $Verdict),
        '',
        '# C4 recovery source verdict',
        '',
        'Fixture body covering the ten parent rows and the eleven recovery rows.'
    )
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [IO.File]::WriteAllBytes($Path, $utf8.GetBytes((($lines -join "`n") + "`n")))
    return $Path
}

$script:TestAuthorizationOperations = @(
    'SERVICE_INSTALL', 'SERVICE_START_DRIVER_LOAD', 'DOS_LINK_CREATE', 'SMOKE_TRAFFIC',
    'DRIVER_UNLOAD', 'DOS_LINK_REMOVE', 'SERVICE_DELETE', 'OWNED_CLEANUP'
)

function New-C4TestNativeIdentity {
    return [pscustomobject]@{
        Host = [ordered]@{
            machineGuid = '11111111-2222-3333-4444-555555555555'
            computerName = 'C4-SELFTEST'
            osBuild = '19045'
            architecture = 'AMD64'
            processArchitecture = 'AMD64'
        }
        Boot = [ordered]@{
            bootId = '66666666-7777-8888-9999-000000000000'
            bootTimeUtc = '2026-08-24T00:00:00Z'
        }
    }
}

function New-C4TestSealedNativeAttempt {
    param(
        [string]$Directory,
        [string]$AttemptId,
        [string]$BootstrapCommit,
        [string]$BootstrapTree,
        [string]$Status = 'NOT_RUN',
        [string]$Phase = 'ARTIFACT_INITIAL',
        [string[]]$Reasons = @('ELIGIBLE_CANDIDATE_MISSING'),
        [int]$MutationAttempts = 0,
        [bool]$LiveIssued = $false,
        $Bound,
        [switch]$HalfBound,
        [switch]$BreakBootstrapHash,
        [string]$ExtraKey,
        [string]$DropKey,
        [switch]$BreakHostIdentity,
        [switch]$BreakBootIdentity
    )

    [void][IO.Directory]::CreateDirectory($Directory)
    $identity = New-C4TestNativeIdentity
    if ($BreakHostIdentity) { $identity.Host['unexpected'] = 'x' }
    if ($BreakBootIdentity) { $identity.Boot.Remove('bootTimeUtc') }

    # bootstrap.json is written first: its hash is a field of attempt.json and
    # it is also a row of the sealed roster.
    $bootstrap = [ordered]@{
        schema = 'fsring-c4-native-bootstrap/v1'
        version = 1
        sourceCommit = $BootstrapCommit
        sourceTree = $BootstrapTree
        files = @()
        powerShell = [ordered]@{
            path = 'C:\fixture\powershell.exe'
            volumeSerial = '0123456789ABCDEF'
            fileId = ('0' * 32)
            bytes = 1
            sha256 = ('1' * 64)
        }
    }
    $bootstrapBytes = Get-C4RecorderCanonicalBytes $bootstrap
    [IO.File]::WriteAllBytes((Join-Path $Directory 'bootstrap.json'), $bootstrapBytes)
    $bootstrapSha = Get-C4EvidenceSha256Hex $bootstrapBytes
    if ($BreakBootstrapHash) { $bootstrapSha = ('9' * 64) }

    $rows = New-Object System.Collections.ArrayList
    foreach ($name in @('bootstrap.json')) {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $Directory $name))
        [void]$rows.Add([ordered]@{
            relativePath = $name
            bytes = [int64]$bytes.Length
            sha256 = (Get-C4EvidenceSha256Hex $bytes)
        })
    }
    $roster = [ordered]@{
        schema = 'fsring-c4-native-attempt-files/v1'
        version = 1
        attemptId = $AttemptId
        files = @($rows)
    }
    $rosterBytes = Get-C4RecorderCanonicalBytes $roster
    [IO.File]::WriteAllBytes((Join-Path $Directory 'attempt-files.json'), $rosterBytes)

    $candidate = [ordered]@{
        sourceAttemptId = $null; sourceCommit = $null; sourceTree = $null
        candidateManifestSha256 = $null; nativeReviewSha256 = $null
        evidenceReviewSha256 = $null; artifactSetSha256 = $null; packageSetSha256 = $null
    }
    if ($null -ne $Bound) {
        foreach ($key in @($candidate.Keys)) { $candidate[$key] = $Bound.$key }
    }
    if ($HalfBound) { $candidate['packageSetSha256'] = $null }

    $manifest = [ordered]@{
        schema = 'fsring-c4-native-attempt/v1'
        version = 1
        attemptId = $AttemptId
        bootstrapSourceCommit = $BootstrapCommit
        bootstrapSourceTree = $BootstrapTree
        bootstrapSha256 = $bootstrapSha
        sourceAttemptId = $candidate['sourceAttemptId']
        sourceCommit = $candidate['sourceCommit']
        sourceTree = $candidate['sourceTree']
        candidateManifestSha256 = $candidate['candidateManifestSha256']
        nativeReviewSha256 = $candidate['nativeReviewSha256']
        evidenceReviewSha256 = $candidate['evidenceReviewSha256']
        artifactSetSha256 = $candidate['artifactSetSha256']
        packageSetSha256 = $candidate['packageSetSha256']
        hostIdentity = $identity.Host
        bootIdentity = $identity.Boot
        status = $Status
        phase = $Phase
        reasonCodes = @($Reasons)
        commandIssued = [ordered]@{
            initialPreflight = $false; finalPreflight = $false; live = $LiveIssued
        }
        liveIssued = $LiveIssued
        mutationAttempts = $MutationAttempts
        attemptFilesSha256 = (Get-C4EvidenceSha256Hex $rosterBytes)
    }
    if ($ExtraKey) { $manifest[$ExtraKey] = 'extra' }
    if ($DropKey) { $manifest.Remove($DropKey) }
    [IO.File]::WriteAllBytes((Join-Path $Directory 'attempt.json'),
        (Get-C4RecorderCanonicalBytes $manifest))
    return $bootstrapSha
}

function Invoke-C4RecorderSelfTests {
    # Short names on purpose: see the core.longpaths note in the world builder.
    $root = Join-Path $env:TEMP ('c4r-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    [void][IO.Directory]::CreateDirectory($root)
    $checks = New-Object System.Collections.ArrayList
    $failures = New-Object System.Collections.ArrayList
    # A plain `$n += 1` inside a nested function writes a *local* copy, so the
    # counter has to be held by reference or every world reuses one name.
    $worldOrdinal = [ref]0

    function Note {
        param([string]$Name)
        [void]$checks.Add($Name)
    }
    function Fail {
        param([string]$Name, [string]$Why)
        [void]$failures.Add(($Name + ': ' + $Why))
    }
    function Assert-Ok {
        param([string]$Name, [bool]$Condition, [string]$Why = 'condition was false')
        Note $Name
        if (-not $Condition) { Fail $Name $Why }
    }
    # A refusal counts only when it is the refusal the fixture aimed at. A bare
    # nonzero exit would let a fixture that broke its own setup pass for the
    # wrong reason, which is exactly how a suite goes green while measuring
    # nothing.
    function Assert-Refused {
        param([string]$Name, $Result, [string]$Expect)
        Note $Name
        if ($Result.ExitCode -eq 0) {
            Fail $Name 'accepted what it must refuse'
            return
        }
        if ($Result.Stderr.IndexOf($Expect, [StringComparison]::Ordinal) -lt 0) {
            Fail $Name ('refused for the wrong reason (' + $Result.Stderr.Trim() + ')')
        }
    }
    function Assert-Accepted {
        param([string]$Name, $Result)
        Note $Name
        if ($Result.ExitCode -ne 0) {
            Fail $Name ('refused what it must accept (' + $Result.Stderr.Trim() + ')')
            return $null
        }
        return $Result
    }
    function New-World {
        $worldOrdinal.Value += 1
        return (New-C4RecorderTestWorld $root ('w' + $worldOrdinal.Value.ToString()))
    }

    $commit = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0'
    $tree = 'f0e1d2c3b4a5968778695a4b3c2d1e0f00112233'
    $attemptId = '0123456789abcdef0123456789abcdef'

    function Get-SourceRecordArguments {
        param($World, [string]$Attempt, [string]$External, [string]$Receipt,
              [string]$Commit, [string]$Tree, [string]$RecorderSha)
        return @(
            '-Mode', 'RecordSourceAttempt',
            '-ExpectedRecorderSha256', $RecorderSha,
            '-ExternalAttemptDirectory', $External,
            '-ExpectedAttemptId', $Attempt,
            '-ExpectedSourceCommit', $Commit,
            '-ExpectedSourceTree', $Tree,
            '-RepositoryEvidenceRoot', $World.SourceEvidenceRoot,
            '-ReceiptPath', $Receipt
        )
    }

    function New-RecordedWorld {
        # A world that has already run Checkpoint A and committed it, which is
        # the precondition for every finalize and withdrawal fixture.
        $world = New-World
        $external = Join-Path $world.External 'attempt'
        [void](New-C4TestSealedSourceAttempt -Directory $external -AttemptId $attemptId `
            -Commit $commit -Tree $tree -GateStatus 'PASS')
        $receipt = Join-Path $world.External 'record-source.json'
        $result = Invoke-C4RecorderChild $world (Get-SourceRecordArguments $world $attemptId `
            $external $receipt $commit $tree $world.RecorderSha256)
        if ($result.ExitCode -ne 0) { throw ('fixture Checkpoint A failed: ' + $result.Stderr) }
        $stage = Invoke-C4RecorderChild $world @(
            '-Mode', 'StageReceipt', '-ExpectedRecorderSha256', $world.RecorderSha256,
            '-InputReceiptPath', $receipt, '-ExpectedRecordedMode', 'RecordSourceAttempt',
            '-ExpectedAttemptId', $attemptId,
            '-RepositoryEvidenceRoot', $world.SourceEvidenceRoot)
        if ($stage.ExitCode -ne 0) { throw ('fixture staging failed: ' + $stage.Stderr) }
        [void](Invoke-C4RecorderGit $world.Git @('commit', '--quiet', '-m', 'checkpoint a'))
        $checkpointA = ([string](Invoke-C4RecorderGit $world.Git @('rev-parse', 'HEAD')).Lines[0]).Trim()
        return [pscustomobject]@{
            World = $world
            External = $external
            Receipt = $receipt
            CheckpointA = $checkpointA
        }
    }

    function New-FinalizeArguments {
        param($Recorded, [string]$Receipt, [hashtable]$Overrides = @{})
        $world = $Recorded.World
        $native = Join-Path $world.External ('native-' + [Guid]::NewGuid().ToString('N') + '.md')
        $evidence = Join-Path $world.External ('evidence-' + [Guid]::NewGuid().ToString('N') + '.md')
        $verdict = Join-Path $world.External ('verdict-' + [Guid]::NewGuid().ToString('N') + '.md')
        $nativeArgs = @{
            Path = $native; Role = 'native'; AttemptId = $attemptId; Commit = $commit
            Tree = $tree; CheckpointA = $Recorded.CheckpointA; ContextId = 'ctx-native'
            InstanceId = 'inst-native'; OutputParent = 'out-native'
        }
        $evidenceArgs = @{
            Path = $evidence; Role = 'evidence'; AttemptId = $attemptId; Commit = $commit
            Tree = $tree; CheckpointA = $Recorded.CheckpointA; ContextId = 'ctx-evidence'
            InstanceId = 'inst-evidence'; OutputParent = 'out-evidence'
        }
        $verdictArgs = @{
            Path = $verdict; AttemptId = $attemptId; Commit = $commit; Tree = $tree
            CheckpointA = $Recorded.CheckpointA
        }
        foreach ($key in @($Overrides.Keys)) {
            if ($key.StartsWith('Native')) { $nativeArgs[$key.Substring(6)] = $Overrides[$key] }
            elseif ($key.StartsWith('Evidence')) { $evidenceArgs[$key.Substring(8)] = $Overrides[$key] }
            elseif ($key.StartsWith('Verdict')) { $verdictArgs[$key.Substring(7)] = $Overrides[$key] }
        }
        [void](New-C4TestReviewDocument @nativeArgs)
        [void](New-C4TestReviewDocument @evidenceArgs)
        [void](New-C4TestVerdictDocument @verdictArgs)
        $checkpoint = $Recorded.CheckpointA
        if ($Overrides.ContainsKey('CheckpointArgument')) {
            $checkpoint = $Overrides['CheckpointArgument']
        }
        return @(
            '-Mode', 'FinalizeSourceReview',
            '-ExpectedRecorderSha256', $world.RecorderSha256,
            '-ExpectedAttemptId', $attemptId,
            '-ExpectedCheckpointACommit', $checkpoint,
            '-NativeReviewPath', $native,
            '-EvidenceReviewPath', $evidence,
            '-SourceVerdictPath', $verdict,
            '-RepositoryEvidenceRoot', $world.SourceEvidenceRoot,
            '-ReceiptPath', $Receipt
        )
    }

    try {
        # =================================================================
        # A0. StageReceipt cannot put a PASS source roster on git-add argv.
        # =================================================================
        $lw = New-World
        $longDir = Join-Path $lw.Root (($lw.SourceEvidenceRoot).Replace('/', '\'))
        [void][IO.Directory]::CreateDirectory($longDir)
        $longPaths = New-Object System.Collections.ArrayList
        $longUtf8 = New-Object System.Text.UTF8Encoding $false
        $longPad = 'x' * 80
        for ($i = 0; $i -lt 220; $i++) {
            $longName = ('gate-{0:D3}-{1}.stdout.bin' -f $i, $longPad)
            $longRelative = $lw.SourceEvidenceRoot + '/' + $longName
            [IO.File]::WriteAllBytes((Join-Path $longDir $longName), $longUtf8.GetBytes('payload'))
            [void]$longPaths.Add($longRelative)
        }
        $longArgv = 'git add -A -- ' + (@($longPaths) -join ' ')
        Assert-Ok 'a sealed source roster exceeds the Windows argv ceiling' (
            $longArgv.Length -gt 32767)
        Invoke-C4RecorderGitAddRoster $lw.Git @($longPaths)
        $longStaged = @((Invoke-C4RecorderGit $lw.Git @('diff', '--cached', '--name-only')).Lines |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        Assert-Ok 'pathspec-from-file stages the whole argv-overflow roster' (
            $longStaged.Count -eq $longPaths.Count)
        Assert-Ok 'the Git-private pathspec file does not survive staging' (
            -not [IO.File]::Exists((Get-C4RecorderGitPath $lw.Git $script:StagePathspecFileName)))

        # =================================================================
        # A. The honest end-to-end path must actually work.
        # =================================================================
        $world = New-World
        $external = Join-Path $world.External 'attempt'
        [void](New-C4TestSealedSourceAttempt -Directory $external -AttemptId $attemptId `
            -Commit $commit -Tree $tree -GateStatus 'PASS')
        $receipt = Join-Path $world.External 'record-source.json'
        $recorded = Assert-Accepted 'Checkpoint A records a sealed PASS attempt' `
            (Invoke-C4RecorderChild $world (Get-SourceRecordArguments $world $attemptId `
                $external $receipt $commit $tree $world.RecorderSha256))

        if ($null -ne $recorded) {
            $receiptObject = ConvertFrom-C4CanonicalJsonBytes `
                -Bytes ([IO.File]::ReadAllBytes($receipt)) -ExpectedSchema $script:ReceiptSchema
            Assert-Ok 'the receipt names its mode and attempt' (
                ([string]$receiptObject.mode) -ceq 'RecordSourceAttempt' -and
                ([string]$receiptObject.attemptId) -ceq $attemptId)
            Assert-Ok 'the receipt carries the recorder hash it ran as' (
                ([string]$receiptObject.recorderSha256) -ceq $world.RecorderSha256)
            Assert-Ok 'the receipt records the attempt gate status' (
                ([string]$receiptObject.attemptStatus) -ceq 'PASS')
            Assert-Ok 'bootstrap fields are null outside the native mode' (
                $null -eq $receiptObject.bootstrapSourceCommit -and
                $null -eq $receiptObject.bootstrapSourceTree -and
                $null -eq $receiptObject.bootstrapSha256 -and
                $null -eq $receiptObject.checkpointACommit -and
                $null -eq $receiptObject.sourceVerdict)
            $ledgerPath = Join-Path $world.Root (
                ($world.SourceEvidenceRoot + '/' + $script:SourceIndexName).Replace('/', '\'))
            $ledger = Read-C4SourceIndex $ledgerPath
            Assert-Ok 'the ledger carries exactly one attempt row' (
                @($ledger.attempts).Count -eq 1 -and
                ([string]@($ledger.attempts)[0].attemptId) -ceq $attemptId)
            Assert-Ok 'the new row has null review and verdict fields' (
                $null -eq @($ledger.attempts)[0].reviewStatus -and
                $null -eq @($ledger.attempts)[0].sourceVerdict -and
                $null -eq @($ledger.attempts)[0].nativeReviewSha256)
            Assert-Ok 'eligibility starts empty' (
                @($ledger.eligibilityEvents).Count -eq 0 -and
                $null -eq $ledger.eligibleCandidateAttemptId)
            Assert-Ok 'the one-time logs README was installed' (
                [IO.File]::Exists((Join-Path $world.Root ($world.SourceEvidenceRoot + '\' + $script:LogsReadmeName).Replace('/', '\'))))
            Assert-Ok 'no transaction marker survives a committed transaction' (
                -not [IO.File]::Exists((Get-C4RecorderGitPath $world.Git $script:MarkerFileName)))
            Assert-Ok 'the journal is marked COMMITTED' (
                (ConvertFrom-C4CanonicalJsonBytes `
                    -Bytes ([IO.File]::ReadAllBytes($receipt + '.transaction.json')) `
                    -ExpectedSchema $script:TransactionSchema).state -ceq 'COMMITTED')
        }

        $staged = Assert-Accepted 'StageReceipt stages the derived roster' `
            (Invoke-C4RecorderChild $world @(
                '-Mode', 'StageReceipt', '-ExpectedRecorderSha256', $world.RecorderSha256,
                '-InputReceiptPath', $receipt, '-ExpectedRecordedMode', 'RecordSourceAttempt',
                '-ExpectedAttemptId', $attemptId,
                '-RepositoryEvidenceRoot', $world.SourceEvidenceRoot))
        if ($null -ne $staged) {
            $cached = @((Invoke-C4RecorderGit $world.Git @('diff', '--cached', '--name-only')).Lines |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            Assert-Ok 'the index holds the attempt, README and ledger' (
                $cached.Count -eq 6 -and
                @($cached | Where-Object { $_.EndsWith('/index.json') }).Count -eq 1 -and
                @($cached | Where-Object { $_.EndsWith('/README.md') }).Count -eq 1)
            Assert-Ok 'the R1-R6 narrative is never staged by the recorder' (
                @($cached | Where-Object { $_ -cmatch 'c4-recovery-r1-r6' }).Count -eq 0)
        }
        [void](Invoke-C4RecorderGit $world.Git @('commit', '--quiet', '-m', 'checkpoint a'))
        $checkpointA = ([string](Invoke-C4RecorderGit $world.Git @('rev-parse', 'HEAD')).Lines[0]).Trim()
        Assert-Ok 'Checkpoint A leaves a clean tree' (
            @((Invoke-C4RecorderGit $world.Git @('status', '--porcelain')).Lines |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0)

        $finalizeReceipt = Join-Path $world.External 'finalize.json'
        $recordedWorld = [pscustomobject]@{
            World = $world; External = $external; Receipt = $receipt; CheckpointA = $checkpointA }
        $finalized = Assert-Accepted 'FinalizeSourceReview installs reviews and promotes a PASS' `
            (Invoke-C4RecorderChild $world (New-FinalizeArguments $recordedWorld $finalizeReceipt))
        if ($null -ne $finalized) {
            $ledgerPath = Join-Path $world.Root (
                ($world.SourceEvidenceRoot + '/' + $script:SourceIndexName).Replace('/', '\'))
            $ledger = Read-C4SourceIndex $ledgerPath
            $row = @($ledger.attempts)[0]
            Assert-Ok 'the row transitioned to PASS review and verdict' (
                ([string]$row.reviewStatus) -ceq 'PASS' -and
                ([string]$row.sourceVerdict) -ceq 'PASS' -and
                ([string]$row.nativeReviewRelativePath) -ceq
                    ('reviews/' + $attemptId + '/native-review.md'))
            Assert-Ok 'an INITIAL_PASS eligibility event was appended' (
                @($ledger.eligibilityEvents).Count -eq 1 -and
                ([string]@($ledger.eligibilityEvents)[0].reason) -ceq 'INITIAL_PASS' -and
                $null -eq @($ledger.eligibilityEvents)[0].previousAttemptId -and
                ([string]$ledger.eligibleCandidateAttemptId) -ceq $attemptId)
            $promoted = Join-Path $world.Root (
                ($world.SourceEvidenceRoot + '/' + $script:CandidateName).Replace('/', '\'))
            Assert-Ok 'the candidate manifest was promoted byte-for-byte' (
                [IO.File]::Exists($promoted) -and
                (Get-C4RecorderSha256File $promoted) -ceq ([string]$row.candidateManifestSha256))
            $pointer = Join-Path $world.Root (
                'docs\superpowers\reviews\evidence\' + $script:LatestPointerNames['sourceVerdict'])
            Assert-Ok 'the source-verdict latest pointer carries only identity' (
                [IO.File]::Exists($pointer) -and
                ((Get-C4EvidenceUtf8).GetString([IO.File]::ReadAllBytes($pointer))
                    ).Contains('maintained pointer, not evidence'))
        }

        $stagedFinalize = Assert-Accepted 'StageReceipt stages the finalize roster' `
            (Invoke-C4RecorderChild $world @(
                '-Mode', 'StageReceipt', '-ExpectedRecorderSha256', $world.RecorderSha256,
                '-InputReceiptPath', $finalizeReceipt,
                '-ExpectedRecordedMode', 'FinalizeSourceReview',
                '-ExpectedAttemptId', $attemptId,
                '-RepositoryEvidenceRoot', $world.SourceEvidenceRoot))
        if ($null -ne $stagedFinalize) {
            $cached = @((Invoke-C4RecorderGit $world.Git @('diff', '--cached', '--name-only')).Lines |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            Assert-Ok 'the finalize index is the eight promotion paths' ($cached.Count -eq 8)
        }
        [void](Invoke-C4RecorderGit $world.Git @('commit', '--quiet', '-m', 'checkpoint b'))

        $candidateSha = (Get-C4RecorderSha256File (Join-Path $world.Root ($world.SourceEvidenceRoot + '/' + $script:CandidateName).Replace('/', '\')))
        $withdrawReceipt = Join-Path $world.External 'withdraw.json'
        $withdrawn = Assert-Accepted 'WithdrawSourceCandidate removes only the promoted copy' `
            (Invoke-C4RecorderChild $world @(
                '-Mode', 'WithdrawSourceCandidate',
                '-ExpectedRecorderSha256', $world.RecorderSha256,
                '-ExpectedEligibleAttemptId', $attemptId,
                '-ExpectedCandidateManifestSha256', $candidateSha,
                '-RepositoryEvidenceRoot', $world.SourceEvidenceRoot,
                '-ReceiptPath', $withdrawReceipt))
        if ($null -ne $withdrawn) {
            $ledger = Read-C4SourceIndex (Join-Path $world.Root ($world.SourceEvidenceRoot + '/' + $script:SourceIndexName).Replace('/', '\'))
            Assert-Ok 'withdrawal nulls the pointer and appends its event' (
                @($ledger.eligibilityEvents).Count -eq 2 -and
                ([string]@($ledger.eligibilityEvents)[1].reason) -ceq 'WITHDRAW_SOURCE_DEFECT' -and
                $null -eq $ledger.eligibleCandidateAttemptId)
            Assert-Ok 'withdrawal keeps the attempt row and its verdict' (
                ([string]@($ledger.attempts)[0].sourceVerdict) -ceq 'PASS')
            Assert-Ok 'withdrawal keeps the attempt-local candidate manifest' (
                [IO.File]::Exists((Join-Path $world.Root ($world.SourceEvidenceRoot + '/attempt-' + $tree + '-' + $attemptId +
                     '/candidate-artifacts.json').Replace('/', '\'))))
            Assert-Ok 'the promoted top-level copy is gone' (
                -not [IO.File]::Exists((Join-Path $world.Root ($world.SourceEvidenceRoot + '/' + $script:CandidateName).Replace('/', '\'))))
            $withdrawObject = ConvertFrom-C4CanonicalJsonBytes `
                -Bytes ([IO.File]::ReadAllBytes($withdrawReceipt)) `
                -ExpectedSchema $script:ReceiptSchema
            $deleteRow = @(@($withdrawObject.changedPaths) |
                Where-Object { ([string]$_.operation) -ceq 'DELETE' })
            Assert-Ok 'a DELETE row carries a null hash' (
                $deleteRow.Count -eq 1 -and $null -eq $deleteRow[0].sha256)
        }
        Assert-Accepted 'StageReceipt stages the withdrawal roster' `
            (Invoke-C4RecorderChild $world @(
                '-Mode', 'StageReceipt', '-ExpectedRecorderSha256', $world.RecorderSha256,
                '-InputReceiptPath', $withdrawReceipt,
                '-ExpectedRecordedMode', 'WithdrawSourceCandidate',
                '-ExpectedAttemptId', $attemptId,
                '-RepositoryEvidenceRoot', $world.SourceEvidenceRoot)) | Out-Null

        # =================================================================
        # B. Refusals. Each names the message it must produce, so a fixture
        #    that breaks its own setup cannot pass for the guard under test.
        # =================================================================

        $w = New-World
        $ext = Join-Path $w.External 'attempt'
        [void](New-C4TestSealedSourceAttempt -Directory $ext -AttemptId $attemptId `
            -Commit $commit -Tree $tree)
        Assert-Refused 'a wrong expected recorder hash is refused' (
            Invoke-C4RecorderChild $w (Get-SourceRecordArguments $w $attemptId $ext `
                (Join-Path $w.External 'r.json') $commit $tree ('0' * 64))
        ) 'held lease SHA-256 drifted'

        Assert-Refused 'a receipt inside the repository is refused' (
            Invoke-C4RecorderChild $w (Get-SourceRecordArguments $w $attemptId $ext `
                (Join-Path $w.Root 'receipt.json') $commit $tree $w.RecorderSha256)
        ) 'ReceiptPath must live outside the repository'

        Assert-Refused 'a source commit mismatch is refused' (
            Invoke-C4RecorderChild $w (Get-SourceRecordArguments $w $attemptId $ext `
                (Join-Path $w.External 'r2.json') ('b' * 40) $tree $w.RecorderSha256)
        ) "sealed attempt's sourceCommit is"

        Assert-Refused 'an attempt id mismatch is refused' (
            Invoke-C4RecorderChild $w (Get-SourceRecordArguments $w ('f' * 32) $ext `
                (Join-Path $w.External 'r3.json') $commit $tree $w.RecorderSha256)
        ) "sealed attempt's attemptId is"

        Assert-Refused 'a non-GUID-N attempt id is refused' (
            Invoke-C4RecorderChild $w (Get-SourceRecordArguments $w 'not-a-guid' $ext `
                (Join-Path $w.External 'r4.json') $commit $tree $w.RecorderSha256)
        ) 'ExpectedAttemptId must be a GUID-N attempt ID'

        $w = New-World
        $extra = Join-Path $w.External 'attempt-extra'
        [void](New-C4TestSealedSourceAttempt -Directory $extra -AttemptId $attemptId `
            -Commit $commit -Tree $tree -ExtraFile 'stray.txt')
        Assert-Refused 'an unrostered file in the sealed attempt is refused' (
            Invoke-C4RecorderChild $w (Get-SourceRecordArguments $w $attemptId $extra `
                (Join-Path $w.External 'r.json') $commit $tree $w.RecorderSha256)
        ) 'is not its closed roster'

        $tampered = Join-Path $w.External 'attempt-tampered'
        [void](New-C4TestSealedSourceAttempt -Directory $tampered -AttemptId $attemptId `
            -Commit $commit -Tree $tree -TamperFile 'command-index.json')
        Assert-Refused 'a tampered sealed file is refused' (
            Invoke-C4RecorderChild $w (Get-SourceRecordArguments $w $attemptId $tampered `
                (Join-Path $w.External 'r2.json') $commit $tree $w.RecorderSha256)
        ) 'does not hash to its recorded value'

        $brokenRoster = Join-Path $w.External 'attempt-roster'
        [void](New-C4TestSealedSourceAttempt -Directory $brokenRoster -AttemptId $attemptId `
            -Commit $commit -Tree $tree -BreakRosterHash)
        $truncated = Join-Path $w.External 'attempt-truncated'
        [void](New-C4TestSealedSourceAttempt -Directory $truncated -AttemptId $attemptId `
            -Commit $commit -Tree $tree -TruncateFile 'command-index.json')
        Assert-Refused 'a truncated sealed file is refused on size' (
            Invoke-C4RecorderChild $w (Get-SourceRecordArguments $w $attemptId $truncated `
                (Join-Path $w.External 'r2b.json') $commit $tree $w.RecorderSha256)
        ) 'not the recorded'

        Assert-Refused 'a roster hash that does not match attempt.json is refused' (
            Invoke-C4RecorderChild $w (Get-SourceRecordArguments $w $attemptId $brokenRoster `
                (Join-Path $w.External 'r3.json') $commit $tree $w.RecorderSha256)
        ) 'does not hash the sealed file roster'

        $w = New-World
        $failAttempt = Join-Path $w.External 'attempt-fail'
        [void](New-C4TestSealedSourceAttempt -Directory $failAttempt -AttemptId $attemptId `
            -Commit $commit -Tree $tree -GateStatus 'FAIL')
        $failReceipt = Join-Path $w.External 'fail.json'
        Assert-Accepted 'a FAIL attempt is still recordable' (
            Invoke-C4RecorderChild $w (Get-SourceRecordArguments $w $attemptId $failAttempt `
                $failReceipt $commit $tree $w.RecorderSha256)) | Out-Null
        $failLedger = Read-C4SourceIndex (Join-Path $w.Root ($w.SourceEvidenceRoot + '/' +
            $script:SourceIndexName).Replace('/', '\'))
        Assert-Ok 'a FAIL row carries a null candidate hash' (
            ([string]@($failLedger.attempts)[0].gateStatus) -ceq 'FAIL' -and
            $null -eq @($failLedger.attempts)[0].candidateManifestSha256)
        Assert-Refused 'recording the same attempt twice is refused as a replay' (
            Invoke-C4RecorderChild $w (Get-SourceRecordArguments $w $attemptId $failAttempt `
                (Join-Path $w.External 'again.json') $commit $tree $w.RecorderSha256)
        ) 'this is a replay'

        # --- finalize refusals ---------------------------------------------
        $r = New-RecordedWorld
        Assert-Refused 'a finalize whose reviews share a context id is refused' (
            Invoke-C4RecorderChild $r.World (New-FinalizeArguments $r `
                (Join-Path $r.World.External 'f1.json') @{ EvidenceContextId = 'ctx-native' })
        ) 'declare the same reviewerContextId'

        Assert-Refused 'a PASS verdict over a FAIL review is refused' (
            Invoke-C4RecorderChild $r.World (New-FinalizeArguments $r `
                (Join-Path $r.World.External 'f2.json') @{ NativeVerdict = 'FAIL' })
        ) 'requires both reviews to PASS'

        Assert-Refused 'a PASS verdict over a shared draft is refused' (
            Invoke-C4RecorderChild $r.World (New-FinalizeArguments $r `
                (Join-Path $r.World.External 'f3.json') @{ NativeSharedDraft = 'true' })
        ) 'forces PENDING'

        Assert-Refused 'a PASS verdict with a cross-read review is refused' (
            Invoke-C4RecorderChild $r.World (New-FinalizeArguments $r `
                (Join-Path $r.World.External 'f4.json') @{ EvidenceOtherReviewRead = 'true' })
        ) 'forces PENDING'

        Assert-Refused 'a PASS verdict short of 21 passing rows is refused' (
            Invoke-C4RecorderChild $r.World (New-FinalizeArguments $r `
                (Join-Path $r.World.External 'f5.json') @{ VerdictRowsPass = 20 })
        ) 'requires all 21 verdict rows to PASS'

        Assert-Refused 'a verdict that does not cover 21 rows is refused' (
            Invoke-C4RecorderChild $r.World (New-FinalizeArguments $r `
                (Join-Path $r.World.External 'f6.json') @{ VerdictRowsTotal = 20 })
        ) 'not the 21 verdict rows'

        Assert-Refused 'a PASS verdict with an unresolved blocker is refused' (
            Invoke-C4RecorderChild $r.World (New-FinalizeArguments $r `
                (Join-Path $r.World.External 'f7.json') @{ VerdictBlockers = 1 })
        ) 'requires zero unresolvedBlockerFindings'

        Assert-Refused 'a PASS verdict while a review reports a blocker is refused' (
            Invoke-C4RecorderChild $r.World (New-FinalizeArguments $r `
                (Join-Path $r.World.External 'f8.json') @{ NativeBlockers = 2 })
        ) 'refused while a review reports blockerFindings'

        Assert-Refused 'a review bound to the wrong attempt is refused' (
            Invoke-C4RecorderChild $r.World (New-FinalizeArguments $r `
                (Join-Path $r.World.External 'f9.json') @{ EvidenceAttemptId = ('c' * 32) })
        ) "not the row's"

        Assert-Refused 'a checkpoint commit outside history is refused' (
            Invoke-C4RecorderChild $r.World (New-FinalizeArguments $r `
                (Join-Path $r.World.External 'f10.json') @{
                    CheckpointArgument = ('d' * 40); NativeCheckpointA = ('d' * 40)
                    EvidenceCheckpointA = ('d' * 40); VerdictCheckpointA = ('d' * 40) })
        ) 'not an ancestor of HEAD'

        # A FAIL verdict is legal, closes the row, and must not promote.
        $rFail = New-RecordedWorld
        $failFinalize = Join-Path $rFail.World.External 'finalize-fail.json'
        Assert-Accepted 'a FAIL source verdict finalizes without promoting' (
            Invoke-C4RecorderChild $rFail.World (New-FinalizeArguments $rFail $failFinalize `
                @{ NativeVerdict = 'FAIL'; VerdictVerdict = 'FAIL'; NativeBlockers = 1
                   VerdictBlockers = 1; VerdictRowsPass = 19 })) | Out-Null
        $failLedger2 = Read-C4SourceIndex (Join-Path $rFail.World.Root ($rFail.World.SourceEvidenceRoot + '/' + $script:SourceIndexName).Replace('/', '\'))
        Assert-Ok 'a FAIL finalize sets reviewStatus FAIL and promotes nothing' (
            ([string]@($failLedger2.attempts)[0].reviewStatus) -ceq 'FAIL' -and
            ([string]@($failLedger2.attempts)[0].sourceVerdict) -ceq 'FAIL' -and
            @($failLedger2.eligibilityEvents).Count -eq 0 -and
            $null -eq $failLedger2.eligibleCandidateAttemptId -and
            -not [IO.File]::Exists((Join-Path $rFail.World.Root ($rFail.World.SourceEvidenceRoot + '/' + $script:CandidateName).Replace('/', '\'))))
        Assert-Refused 'finalizing an already-final row is refused' (
            Invoke-C4RecorderChild $rFail.World (New-FinalizeArguments $rFail `
                (Join-Path $rFail.World.External 'again.json'))
        ) 'a later outcome needs a new attempt'

        # --- withdrawal refusals --------------------------------------------
        Assert-Refused 'withdrawing against a stale eligible pointer is refused' (
            Invoke-C4RecorderChild $rFail.World @(
                '-Mode', 'WithdrawSourceCandidate',
                '-ExpectedRecorderSha256', $rFail.World.RecorderSha256,
                '-ExpectedEligibleAttemptId', $attemptId,
                '-ExpectedCandidateManifestSha256', ('e' * 64),
                '-RepositoryEvidenceRoot', $rFail.World.SourceEvidenceRoot,
                '-ReceiptPath', (Join-Path $rFail.World.External 'w.json'))
        ) 'this pointer is stale'

        # =================================================================
        # C. Crash cuts. Each label leaves the marker and partial bytes where a
        #    killed process would; the next entry must recover in exactly one
        #    direction, decided by the ledger rather than by anything the dying
        #    process managed to tidy up.
        # =================================================================

        function Test-CrashCut {
            param([string]$Label, [string]$ExpectedDirection)

            $cw = New-World
            $cext = Join-Path $cw.External 'attempt'
            [void](New-C4TestSealedSourceAttempt -Directory $cext -AttemptId $attemptId `
                -Commit $commit -Tree $tree)
            $creceipt = Join-Path $cw.External 'record.json'
            $arguments = Get-SourceRecordArguments $cw $attemptId $cext $creceipt `
                $commit $tree $cw.RecorderSha256
            $crashed = Invoke-C4RecorderChild $cw $arguments -CrashAt $Label
            Note ('crash at ' + $Label + ' aborts the run')
            if ($crashed.ExitCode -eq 0) {
                Fail ('crash at ' + $Label + ' aborts the run') 'the injected crash did not fire'
                return
            }
            $marker = Get-C4RecorderGitPath $cw.Git $script:MarkerFileName
            Assert-Ok ('crash at ' + $Label + ' leaves the marker behind') (
                [IO.File]::Exists($marker))

            $retry = Invoke-C4RecorderChild $cw $arguments
            Note ('crash at ' + $Label + ' recovers ' + $ExpectedDirection)
            if ($retry.Stdout.IndexOf('"direction":"' + $ExpectedDirection + '"',
                    [StringComparison]::Ordinal) -lt 0) {
                Fail ('crash at ' + $Label + ' recovers ' + $ExpectedDirection) (
                    'stdout was ' + $retry.Stdout.Trim() + ' / ' + $retry.Stderr.Trim())
                return
            }
            Assert-Ok ('crash at ' + $Label + ' clears the marker') (
                -not [IO.File]::Exists($marker))

            $ledgerPath = Join-Path $cw.Root ($cw.SourceEvidenceRoot + '/' +
                $script:SourceIndexName).Replace('/', '\')
            if ($ExpectedDirection -ceq 'BACKWARD') {
                # Rolled back, so the retry is a fresh transaction that succeeds
                # and leaves exactly one row.
                Assert-Ok ('crash at ' + $Label + ' rolls back and the retry succeeds') (
                    $retry.ExitCode -eq 0)
                if ($retry.ExitCode -eq 0) {
                    $l = Read-C4SourceIndex $ledgerPath
                    Assert-Ok ('crash at ' + $Label + ' leaves exactly one row') (
                        @($l.attempts).Count -eq 1)
                }
            } else {
                # Rolled forward: the transaction was already committed, so the
                # retry must refuse as a replay rather than double-append.
                Assert-Ok ('crash at ' + $Label + ' rolls forward and refuses a replay') (
                    $retry.ExitCode -ne 0 -and
                    $retry.Stderr.IndexOf('this is a replay', [StringComparison]::Ordinal) -ge 0)
                $l = Read-C4SourceIndex $ledgerPath
                Assert-Ok ('crash at ' + $Label + ' leaves exactly one row') (
                    @($l.attempts).Count -eq 1)
                Assert-Ok ('crash at ' + $Label + ' completes the receipt') (
                    [IO.File]::Exists($creceipt))
                $stageAfter = Invoke-C4RecorderChild $cw @(
                    '-Mode', 'StageReceipt', '-ExpectedRecorderSha256', $cw.RecorderSha256,
                    '-InputReceiptPath', $creceipt,
                    '-ExpectedRecordedMode', 'RecordSourceAttempt',
                    '-ExpectedAttemptId', $attemptId,
                    '-RepositoryEvidenceRoot', $cw.SourceEvidenceRoot)
                Assert-Ok ('crash at ' + $Label + ' still yields a stageable receipt') (
                    $stageAfter.ExitCode -eq 0) ($stageAfter.Stderr.Trim())
            }
        }

        foreach ($label in @('AFTER_MARKER', 'AFTER_JOURNAL', 'AFTER_IMMUTABLE',
                'AFTER_ALL_IMMUTABLE', 'AFTER_LEDGER_TEMP')) {
            Test-CrashCut $label 'BACKWARD'
        }
        foreach ($label in @('AFTER_LEDGER_REPLACE', 'AFTER_CLEANUP', 'AFTER_RECEIPT',
                'AFTER_JOURNAL_COMMITTED')) {
            Test-CrashCut $label 'FORWARD'
        }

        # The mutable and delete cuts only exist in the modes that own mutable
        # objects, so they are driven where they actually fire.
        function Test-FinalizeCrashCut {
            param([string]$Label, [string]$ExpectedDirection)
            $fr = New-RecordedWorld
            $freceipt = Join-Path $fr.World.External 'finalize.json'
            $arguments = New-FinalizeArguments $fr $freceipt
            $crashed = Invoke-C4RecorderChild $fr.World $arguments -CrashAt $Label
            Note ('finalize crash at ' + $Label + ' aborts the run')
            if ($crashed.ExitCode -eq 0) {
                Fail ('finalize crash at ' + $Label + ' aborts the run') 'the crash did not fire'
                return
            }
            $retry = Invoke-C4RecorderChild $fr.World $arguments
            Note ('finalize crash at ' + $Label + ' recovers ' + $ExpectedDirection)
            if ($retry.Stdout.IndexOf('"direction":"' + $ExpectedDirection + '"',
                    [StringComparison]::Ordinal) -lt 0) {
                Fail ('finalize crash at ' + $Label + ' recovers ' + $ExpectedDirection) (
                    'stdout was ' + $retry.Stdout.Trim() + ' / ' + $retry.Stderr.Trim())
                return
            }
            $ledger = Read-C4SourceIndex (Join-Path $fr.World.Root ($fr.World.SourceEvidenceRoot + '/' + $script:SourceIndexName).Replace('/', '\'))
            Assert-Ok ('finalize crash at ' + $Label + ' never doubles the event roster') (
                @($ledger.eligibilityEvents).Count -le 1)
        }
        Test-FinalizeCrashCut 'AFTER_MUTABLE' 'BACKWARD'
        Test-FinalizeCrashCut 'AFTER_ALL_MUTABLE' 'BACKWARD'
        Test-FinalizeCrashCut 'AFTER_LEDGER_BACKUP' 'BACKWARD'

        # The backup and delete cuts live in withdrawal, and each needs its own
        # promoted candidate: a retry completes the withdrawal it recovered, so
        # the pointer is null afterwards and a second label would have nothing
        # to remove.
        function Test-WithdrawCrashCut {
            param([string]$Label)

            $dw = New-RecordedWorld
            [void](Invoke-C4RecorderChild $dw.World (New-FinalizeArguments $dw `
                (Join-Path $dw.World.External 'finalize.json')))
            $candidate = Join-Path $dw.World.Root ($dw.World.SourceEvidenceRoot + '/' +
                $script:CandidateName).Replace('/', '\')
            Note ('the ' + $Label + ' fixture has a promoted candidate')
            if (-not [IO.File]::Exists($candidate)) {
                Fail ('the ' + $Label + ' fixture has a promoted candidate') 'nothing was promoted'
                return
            }
            $arguments = @(
                '-Mode', 'WithdrawSourceCandidate',
                '-ExpectedRecorderSha256', $dw.World.RecorderSha256,
                '-ExpectedEligibleAttemptId', $attemptId,
                '-ExpectedCandidateManifestSha256', (Get-C4RecorderSha256File $candidate),
                '-RepositoryEvidenceRoot', $dw.World.SourceEvidenceRoot,
                '-ReceiptPath', (Join-Path $dw.World.External 'withdraw.json'))

            $crashed = Invoke-C4RecorderChild $dw.World $arguments -CrashAt $Label
            Assert-Ok ('crash at ' + $Label + ' aborts the withdrawal') ($crashed.ExitCode -ne 0)
            $marker = Get-C4RecorderGitPath $dw.World.Git $script:MarkerFileName
            Assert-Ok ('crash at ' + $Label + ' leaves the marker behind') (
                [IO.File]::Exists($marker))
            # State observed *before* the retry, which is the only point at
            # which the rollback itself is visible.
            if ($Label -ceq 'AFTER_BACKUP') {
                Assert-Ok 'a crash after the backup has not yet deleted the candidate' (
                    [IO.File]::Exists($candidate))
            } else {
                Assert-Ok 'a crash after the delete has removed the candidate' (
                    -not [IO.File]::Exists($candidate))
            }
            $backups = @([IO.Directory]::GetFiles(
                [IO.Path]::GetDirectoryName($candidate), '*.c4txn-*'))
            Assert-Ok ('crash at ' + $Label + ' leaves a transaction-owned backup') (
                $backups.Count -ge 1)

            $retry = Invoke-C4RecorderChild $dw.World $arguments
            Assert-Ok ('crash at ' + $Label + ' recovers BACKWARD') (
                $retry.Stdout.IndexOf('"direction":"BACKWARD"',
                    [StringComparison]::Ordinal) -ge 0) ($retry.Stderr.Trim())
            Assert-Ok ('crash at ' + $Label + ' then completes the withdrawal') (
                $retry.ExitCode -eq 0 -and -not [IO.File]::Exists($candidate)) (
                $retry.Stderr.Trim())
            Assert-Ok ('crash at ' + $Label + ' leaves no transaction scratch behind') (
                @([IO.Directory]::GetFiles(
                    [IO.Path]::GetDirectoryName($candidate), '*.c4txn-*')).Count -eq 0)
            Assert-Ok ('crash at ' + $Label + ' appends exactly one withdrawal event') (
                @((Read-C4SourceIndex (Join-Path $dw.World.Root ($dw.World.SourceEvidenceRoot + '/' +
                     $script:SourceIndexName).Replace('/', '\'))).eligibilityEvents).Count -eq 2)
        }
        Test-WithdrawCrashCut 'AFTER_BACKUP'
        Test-WithdrawCrashCut 'AFTER_DELETE'

        # Anti-vacuity for the whole crash battery: with no label injected the
        # same command completes and leaves no marker at all.
        $qw = New-World
        $qext = Join-Path $qw.External 'attempt'
        [void](New-C4TestSealedSourceAttempt -Directory $qext -AttemptId $attemptId `
            -Commit $commit -Tree $tree)
        $quiet = Invoke-C4RecorderChild $qw (Get-SourceRecordArguments $qw $attemptId $qext `
            (Join-Path $qw.External 'r.json') $commit $tree $qw.RecorderSha256)
        Assert-Ok 'without an injected crash the transaction completes silently' (
            $quiet.ExitCode -eq 0 -and
            $quiet.Stdout.IndexOf('recorder-recovery', [StringComparison]::Ordinal) -lt 0 -and
            -not [IO.File]::Exists((Get-C4RecorderGitPath $qw.Git $script:MarkerFileName)))
        Assert-Refused 'an unknown crash label is refused' (
            Invoke-C4RecorderChild $qw (Get-SourceRecordArguments $qw ('a' * 32) $qext `
                (Join-Path $qw.External 'r2.json') $commit $tree $qw.RecorderSha256) `
                -CrashAt 'AFTER_NOTHING'
        ) 'unknown crash cut'

        # =================================================================
        # D. RecordNativeAttempt. Two legal branches and nothing between them.
        # =================================================================

        function New-NativeWorld {
            # A world whose native evidence root is ready and whose summary the
            # coordinator has already authored in the worktree, which is what
            # the recorder expects to find.
            $nw = New-World
            $summaryRelative = 'docs/superpowers/reviews/evidence/2026-08-08-c4-recovery-native.md'
            $summaryAbsolute = Join-Path $nw.Root $summaryRelative.Replace('/', '\\')
            $utf8 = New-Object System.Text.UTF8Encoding $false
            [IO.File]::WriteAllBytes($summaryAbsolute,
                $utf8.GetBytes("# C4 native attempt`\n`\nFixture summary.`\n"))
            return [pscustomobject]@{
                World = $nw
                SummaryRelative = $summaryRelative
                SummaryAbsolute = $summaryAbsolute
            }
        }

        function Get-NativeArguments {
            param($NativeWorld, [string]$External, [string]$Receipt, [string]$BootstrapSha,
                  [string]$Commit = $commit, [string]$Tree = $tree, [string]$Attempt = $attemptId,
                  [string]$Summary)
            $summary = $Summary
            if ([string]::IsNullOrWhiteSpace($summary)) { $summary = $NativeWorld.SummaryRelative }
            return @(
                '-Mode', 'RecordNativeAttempt',
                '-ExpectedRecorderSha256', $NativeWorld.World.RecorderSha256,
                '-ExpectedBootstrapSourceCommit', $Commit,
                '-ExpectedBootstrapSourceTree', $Tree,
                '-ExpectedBootstrapSha256', $BootstrapSha,
                '-ExternalAttemptDirectory', $External,
                '-ExpectedAttemptId', $Attempt,
                '-RepositoryEvidenceRoot', $NativeWorld.World.NativeEvidenceRoot,
                '-NativeSummaryPath', $summary,
                '-ReceiptPath', $Receipt)
        }

        # --- the unbound NOT RUN branch -------------------------------------
        $nw = New-NativeWorld
        $nExternal = Join-Path $nw.World.External 'native'
        $nSha = New-C4TestSealedNativeAttempt -Directory $nExternal -AttemptId $attemptId `
            -BootstrapCommit $commit -BootstrapTree $tree
        $nReceipt = Join-Path $nw.World.External 'native.json'
        $nRecorded = Assert-Accepted 'an unbound NOT RUN native attempt publishes' (
            Invoke-C4RecorderChild $nw.World (Get-NativeArguments $nw $nExternal $nReceipt $nSha))
        if ($null -ne $nRecorded) {
            $nIndex = Read-C4NativeIndex (Join-Path $nw.World.Root ($nw.World.NativeEvidenceRoot +
                '/' + $script:NativeIndexName).Replace('/', '\\'))
            Assert-Ok 'the native index carries one row' (@($nIndex.attempts).Count -eq 1)
            $nRow = @($nIndex.attempts)[0]
            Assert-Ok 'the native row copies the three bootstrap fields' (
                ([string]$nRow.bootstrapSourceCommit) -ceq $commit -and
                ([string]$nRow.bootstrapSourceTree) -ceq $tree -and
                ([string]$nRow.bootstrapSha256) -ceq $nSha)
            Assert-Ok 'the native row is fully null on all eight candidate fields' (
                @($script:NativeCandidateIdentityKeys |
                    Where-Object { $null -ne $nRow.$_ }).Count -eq 0)
            Assert-Ok 'the native row records its own relative path and manifest hash' (
                ([string]$nRow.relativePath) -ceq ('attempt-' + $attemptId) -and
                ([string]$nRow.attemptJsonSha256) -cmatch '^[0-9a-f]{64}$')
            $nReceiptObject = ConvertFrom-C4CanonicalJsonBytes `
                -Bytes ([IO.File]::ReadAllBytes($nReceipt)) -ExpectedSchema $script:ReceiptSchema
            Assert-Ok 'the native receipt carries the three bootstrap fields' (
                ([string]$nReceiptObject.bootstrapSourceCommit) -ceq $commit -and
                ([string]$nReceiptObject.bootstrapSha256) -ceq $nSha -and
                ([string]$nReceiptObject.attemptStatus) -ceq 'NOT_RUN')
        }
        Assert-Accepted 'StageReceipt stages the native roster' (
            Invoke-C4RecorderChild $nw.World @(
                '-Mode', 'StageReceipt', '-ExpectedRecorderSha256', $nw.World.RecorderSha256,
                '-InputReceiptPath', $nReceipt, '-ExpectedRecordedMode', 'RecordNativeAttempt',
                '-ExpectedAttemptId', $attemptId,
                '-RepositoryEvidenceRoot', $nw.World.NativeEvidenceRoot)) | Out-Null

        Assert-Refused 'replaying a native attempt is refused' (
            Invoke-C4RecorderChild $nw.World (Get-NativeArguments $nw $nExternal `
                (Join-Path $nw.World.External 'again.json') $nSha)
        ) 'this is a replay'

        # --- unbound-branch refusals ----------------------------------------
        $nw2 = New-NativeWorld
        foreach ($case in @(
                @{ Name = 'an unbound PASS is refused'; Expect = 'publishable only as NOT_RUN'
                   Status = 'PASS'; Phase = 'ARTIFACT_INITIAL'
                   Reasons = @('ELIGIBLE_CANDIDATE_MISSING'); Mutations = 0; Live = $false },
                @{ Name = 'an unbound attempt past ARTIFACT_INITIAL is refused'
                   Expect = 'sealed at ARTIFACT_INITIAL'; Status = 'NOT_RUN'; Phase = 'LIVE'
                   Reasons = @('ELIGIBLE_CANDIDATE_MISSING'); Mutations = 0; Live = $false },
                @{ Name = 'an unbound attempt with a mutation is refused'
                   Expect = 'zero mutation attempts'; Status = 'NOT_RUN'
                   Phase = 'ARTIFACT_INITIAL'; Reasons = @('ELIGIBLE_CANDIDATE_MISSING')
                   Mutations = 1; Live = $false },
                @{ Name = 'an unbound attempt with an issued live command is refused'
                   Expect = 'commandIssued.live false'; Status = 'NOT_RUN'
                   Phase = 'ARTIFACT_INITIAL'; Reasons = @('ELIGIBLE_CANDIDATE_MISSING')
                   Mutations = 0; Live = $true },
                @{ Name = 'an unbound reason outside the closed three is refused'
                   Expect = 'closed'; Status = 'NOT_RUN'; Phase = 'ARTIFACT_INITIAL'
                   Reasons = @('SOMETHING_ELSE'); Mutations = 0; Live = $false },
                @{ Name = 'an unbound attempt with two reasons is refused'
                   Expect = 'exactly one'; Status = 'NOT_RUN'; Phase = 'ARTIFACT_INITIAL'
                   Reasons = @('ELIGIBLE_CANDIDATE_MISSING', 'SOURCE_LEDGER_INVALID')
                   Mutations = 0; Live = $false })) {
            $dir = Join-Path $nw2.World.External ('n-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
            $sha = New-C4TestSealedNativeAttempt -Directory $dir -AttemptId $attemptId `
                -BootstrapCommit $commit -BootstrapTree $tree -Status $case.Status `
                -Phase $case.Phase -Reasons $case.Reasons -MutationAttempts $case.Mutations `
                -LiveIssued $case.Live
            Assert-Refused $case.Name (
                Invoke-C4RecorderChild $nw2.World (Get-NativeArguments $nw2 $dir `
                    (Join-Path $nw2.World.External ([Guid]::NewGuid().ToString('N') + '.json')) $sha)
            ) $case.Expect
        }

        $halfDir = Join-Path $nw2.World.External 'n-half'
        $halfSha = New-C4TestSealedNativeAttempt -Directory $halfDir -AttemptId $attemptId `
            -BootstrapCommit $commit -BootstrapTree $tree -Bound ([pscustomobject]@{
                sourceAttemptId = $attemptId; sourceCommit = $commit; sourceTree = $tree
                candidateManifestSha256 = ('a' * 64); nativeReviewSha256 = ('b' * 64)
                evidenceReviewSha256 = ('c' * 64); artifactSetSha256 = ('d' * 64)
                packageSetSha256 = ('e' * 64) }) -HalfBound
        Assert-Refused 'a half-bound native attempt is refused' (
            Invoke-C4RecorderChild $nw2.World (Get-NativeArguments $nw2 $halfDir `
                (Join-Path $nw2.World.External 'half.json') $halfSha)
        ) 'neither fully bound nor fully null'

        $badBootstrap = Join-Path $nw2.World.External 'n-bootstrap'
        $badSha = New-C4TestSealedNativeAttempt -Directory $badBootstrap -AttemptId $attemptId `
            -BootstrapCommit $commit -BootstrapTree $tree -BreakBootstrapHash
        Assert-Refused 'a bootstrap hash mismatch is refused' (
            Invoke-C4RecorderChild $nw2.World (Get-NativeArguments $nw2 $badBootstrap `
                (Join-Path $nw2.World.External 'bs.json') $badSha)
        ) 'does not hash to the expected bootstrap'

        $okDir = Join-Path $nw2.World.External 'n-ok'
        $okSha = New-C4TestSealedNativeAttempt -Directory $okDir -AttemptId $attemptId `
            -BootstrapCommit $commit -BootstrapTree $tree
        Assert-Refused 'a bootstrap commit mismatch is refused' (
            Invoke-C4RecorderChild $nw2.World (Get-NativeArguments $nw2 $okDir `
                (Join-Path $nw2.World.External 'bc.json') $okSha -Commit ('b' * 40))
        ) 'does not name the expected B,BT'

        Assert-Refused 'a native summary outside the fixed sibling is refused' (
            Invoke-C4RecorderChild $nw2.World (Get-NativeArguments $nw2 $okDir `
                (Join-Path $nw2.World.External 'ns.json') $okSha `
                -Summary 'docs/superpowers/reviews/evidence/other.md')
        ) 'NativeSummaryPath must be exactly'

        [IO.File]::Delete($nw2.SummaryAbsolute)
        Assert-Refused 'an absent native summary is refused' (
            Invoke-C4RecorderChild $nw2.World (Get-NativeArguments $nw2 $okDir `
                (Join-Path $nw2.World.External 'nm.json') $okSha)
        ) 'native summary does not exist'

        # --- the bound branch -----------------------------------------------
        $bw = New-RecordedWorld
        [void](Invoke-C4RecorderChild $bw.World (New-FinalizeArguments $bw `
            (Join-Path $bw.World.External 'finalize.json')))
        $bLedger = Read-C4SourceIndex (Join-Path $bw.World.Root ($bw.World.SourceEvidenceRoot +
            '/' + $script:SourceIndexName).Replace('/', '\\'))
        $bRow = @($bLedger.attempts)[0]
        Note 'the bound fixture has an eligible PASS candidate'
        if (([string]$bLedger.eligibleCandidateAttemptId) -cne $attemptId) {
            Fail 'the bound fixture has an eligible PASS candidate' 'nothing became eligible'
        } else {
            $bSummaryRelative = 'docs/superpowers/reviews/evidence/2026-08-08-c4-recovery-native.md'
            $utf8 = New-Object System.Text.UTF8Encoding $false
            [IO.File]::WriteAllBytes((Join-Path $bw.World.Root $bSummaryRelative.Replace('/', '\\')),
                $utf8.GetBytes("# C4 native attempt`\n`\nBound fixture summary.`\n"))
            $bNative = [pscustomobject]@{
                World = $bw.World; SummaryRelative = $bSummaryRelative
                SummaryAbsolute = (Join-Path $bw.World.Root $bSummaryRelative.Replace('/', '\\'))
            }
            $bound = [pscustomobject]@{
                sourceAttemptId = $attemptId
                sourceCommit = [string]$bRow.sourceCommit
                sourceTree = [string]$bRow.sourceTree
                candidateManifestSha256 = [string]$bRow.candidateManifestSha256
                nativeReviewSha256 = [string]$bRow.nativeReviewSha256
                evidenceReviewSha256 = [string]$bRow.evidenceReviewSha256
                artifactSetSha256 = ('d' * 64)
                packageSetSha256 = ('e' * 64)
            }
            $bDir = Join-Path $bw.World.External 'native-bound'
            $bSha = New-C4TestSealedNativeAttempt -Directory $bDir -AttemptId $attemptId `
                -BootstrapCommit $commit -BootstrapTree $tree -Status 'PASS' -Phase 'COMPLETE' `
                -Reasons @() -MutationAttempts 3 -LiveIssued $true -Bound $bound
            Assert-Accepted 'a bound native attempt publishes against the eligible candidate' (
                Invoke-C4RecorderChild $bw.World (Get-NativeArguments $bNative $bDir `
                    (Join-Path $bw.World.External 'bound.json') $bSha)) | Out-Null

            $wrongBound = [pscustomobject]@{
                sourceAttemptId = $attemptId; sourceCommit = [string]$bRow.sourceCommit
                sourceTree = [string]$bRow.sourceTree
                candidateManifestSha256 = ('f' * 64)
                nativeReviewSha256 = [string]$bRow.nativeReviewSha256
                evidenceReviewSha256 = [string]$bRow.evidenceReviewSha256
                artifactSetSha256 = ('d' * 64); packageSetSha256 = ('e' * 64)
            }
            $wDir = Join-Path $bw.World.External 'native-wrong'
            $wSha = New-C4TestSealedNativeAttempt -Directory $wDir -AttemptId ('a' * 32) `
                -BootstrapCommit $commit -BootstrapTree $tree -Status 'PASS' -Phase 'COMPLETE' `
                -Reasons @() -MutationAttempts 3 -LiveIssued $true -Bound $wrongBound
            Assert-Refused 'a bound attempt naming the wrong candidate hash is refused' (
                Invoke-C4RecorderChild $bw.World (Get-NativeArguments $bNative $wDir `
                    (Join-Path $bw.World.External 'wrong.json') $wSha -Attempt ('a' * 32))
            ) 'does not equal the authenticated'
        }


        # =================================================================
        # E. Guards that nothing could reach.
        #
        # A falsification sweep found each of these disabled with no fixture
        # noticing: the guard was live, but no input in the suite was malformed
        # in the one way it refuses. A guard whose failure mode is unreachable
        # is indistinguishable from a guard that is not there.
        # =================================================================

        # --- a non-PASS attempt carrying a candidate hash -------------------
        $sw = New-World
        $sExternal = Join-Path $sw.External 'attempt-failcand'
        [void](New-C4TestSealedSourceAttempt -Directory $sExternal -AttemptId $attemptId `
            -Commit $commit -Tree $tree -GateStatus 'FAIL' -ForceCandidateOnNonPass)
        Assert-Refused 'a non-PASS attempt carrying a candidate hash is refused' (
            Invoke-C4RecorderChild $sw (Get-SourceRecordArguments $sw $attemptId $sExternal `
                (Join-Path $sw.External 'fc.json') $commit $tree $sw.RecorderSha256)
        ) 'must not carry a candidate manifest hash'

        # --- an orphan immutable object with different bytes ----------------
        # A crash before the commit point rolls back but deliberately leaves the
        # already-installed immutable objects: they are orphans, and a
        # same-input retry adopts them byte-for-byte. If one has been altered,
        # adopting it would launder a changed object into the attempt.
        $ow = New-World
        $oExternal = Join-Path $ow.External 'attempt'
        [void](New-C4TestSealedSourceAttempt -Directory $oExternal -AttemptId $attemptId `
            -Commit $commit -Tree $tree)
        $oReceipt = Join-Path $ow.External 'record.json'
        $oArguments = Get-SourceRecordArguments $ow $attemptId $oExternal $oReceipt `
            $commit $tree $ow.RecorderSha256
        $oCrash = Invoke-C4RecorderChild $ow $oArguments -CrashAt 'AFTER_ALL_IMMUTABLE'
        Assert-Ok 'the orphan fixture crashed before the commit point' ($oCrash.ExitCode -ne 0)
        $orphan = Join-Path $ow.Root ($ow.SourceEvidenceRoot + '/attempt-' + $tree + '-' +
            $attemptId + '/command-index.json').Replace('/', '\')
        Assert-Ok 'a crash after the immutables leaves them installed' (
            [IO.File]::Exists($orphan))
        $utf8 = New-Object System.Text.UTF8Encoding $false
        [IO.File]::WriteAllBytes($orphan, $utf8.GetBytes("altered orphan`n"))
        Assert-Refused 'an altered orphan immutable object is not adopted' (
            Invoke-C4RecorderChild $ow $oArguments
        ) 'already exists with different bytes'

        # --- StageReceipt against a tampered receipt ------------------------
        function Test-TamperedReceipt {
            param([string]$Name, [string]$Expect, [scriptblock]$Tamper)

            $tw = New-World
            $tExternal = Join-Path $tw.External 'attempt'
            [void](New-C4TestSealedSourceAttempt -Directory $tExternal -AttemptId $attemptId `
                -Commit $commit -Tree $tree)
            $tReceipt = Join-Path $tw.External 'record.json'
            $recorded = Invoke-C4RecorderChild $tw (Get-SourceRecordArguments $tw $attemptId `
                $tExternal $tReceipt $commit $tree $tw.RecorderSha256)
            Note ($Name + ' fixture records an attempt')
            if ($recorded.ExitCode -ne 0) {
                Fail ($Name + ' fixture records an attempt') $recorded.Stderr.Trim()
                return
            }
            $receipt = ConvertFrom-C4CanonicalJsonBytes `
                -Bytes ([IO.File]::ReadAllBytes($tReceipt)) -ExpectedSchema $script:ReceiptSchema
            $mutated = & $Tamper $receipt
            [IO.File]::WriteAllBytes($tReceipt, (Get-C4RecorderCanonicalBytes $mutated))
            Assert-Refused $Name (
                Invoke-C4RecorderChild $tw @(
                    '-Mode', 'StageReceipt', '-ExpectedRecorderSha256', $tw.RecorderSha256,
                    '-InputReceiptPath', $tReceipt,
                    '-ExpectedRecordedMode', 'RecordSourceAttempt',
                    '-ExpectedAttemptId', $attemptId,
                    '-RepositoryEvidenceRoot', $tw.SourceEvidenceRoot)
            ) $Expect
        }

        function ConvertTo-OrderedReceipt {
            param($Receipt, $ChangedPaths)
            $ordered = [ordered]@{}
            foreach ($key in $script:ReceiptKeys) { $ordered[$key] = $Receipt.$key }
            if ($null -ne $ChangedPaths) { $ordered['changedPaths'] = @($ChangedPaths) }
            return $ordered
        }

        function ConvertTo-OrderedRows {
            param($Rows)
            $out = New-Object System.Collections.ArrayList
            foreach ($row in $Rows) {
                [void]$out.Add([ordered]@{
                    operation = $row.operation
                    relativePath = $row.relativePath
                    sha256 = $row.sha256
                })
            }
            return @($out)
        }

        Test-TamperedReceipt 'StageReceipt refuses a receipt with a dropped row' `
            'not the roster the committed poststate implies' {
            param($Receipt)
            $rows = @(ConvertTo-OrderedRows @($Receipt.changedPaths))
            ConvertTo-OrderedReceipt $Receipt @($rows[0..($rows.Count - 2)])
        }

        Test-TamperedReceipt 'StageReceipt refuses a receipt with an extra row' `
            'not the roster the committed poststate implies' {
            param($Receipt)
            $rows = @(ConvertTo-OrderedRows @($Receipt.changedPaths))
            $extra = [ordered]@{
                operation = 'CREATE'
                relativePath = 'docs/superpowers/reviews/evidence/c4-recovery-logs/extra.json'
                sha256 = ('a' * 64)
            }
            ConvertTo-OrderedReceipt $Receipt (@($rows) + @($extra))
        }

        Test-TamperedReceipt 'StageReceipt refuses a reordered receipt roster' `
            'not the roster the committed poststate implies' {
            param($Receipt)
            $rows = @(ConvertTo-OrderedRows @($Receipt.changedPaths))
            $swapped = @($rows[1], $rows[0]) + @($rows[2..($rows.Count - 1)])
            ConvertTo-OrderedReceipt $Receipt $swapped
        }

        Test-TamperedReceipt 'StageReceipt refuses a receipt whose operation word is wrong' `
            'in the committed poststate, not the receipt' {
            param($Receipt)
            $rows = @(ConvertTo-OrderedRows @($Receipt.changedPaths))
            $rows[0]['operation'] = 'REPLACE'
            ConvertTo-OrderedReceipt $Receipt $rows
        }

        Test-TamperedReceipt 'StageReceipt refuses a receipt row whose hash is wrong' `
            'does not hash to the value the receipt records' {
            param($Receipt)
            $rows = @(ConvertTo-OrderedRows @($Receipt.changedPaths))
            $rows[0]['sha256'] = ('b' * 64)
            ConvertTo-OrderedReceipt $Receipt $rows
        }

        Test-TamperedReceipt 'StageReceipt refuses a CREATE row with a null hash' `
            'must carry a hash' {
            param($Receipt)
            $rows = @(ConvertTo-OrderedRows @($Receipt.changedPaths))
            $rows[0]['sha256'] = $null
            ConvertTo-OrderedReceipt $Receipt $rows
        }

        Test-TamperedReceipt 'StageReceipt refuses a receipt recording a different recorder' `
            'written by different recorder bytes' {
            param($Receipt)
            $ordered = ConvertTo-OrderedReceipt $Receipt (ConvertTo-OrderedRows @($Receipt.changedPaths))
            $ordered['recorderSha256'] = ('c' * 64)
            return $ordered
        }

        # A DELETE row with a hash only exists in the withdrawal roster, so that
        # is where the null-hash rule is exercised.
        $dwr = New-RecordedWorld
        [void](Invoke-C4RecorderChild $dwr.World (New-FinalizeArguments $dwr `
            (Join-Path $dwr.World.External 'finalize.json')))
        # Checkpoint B is committed before a withdrawal in the real workflow, and
        # the DELETE derivation depends on it: a path created and removed inside
        # one uncommitted state is in neither HEAD nor the worktree.
        [void](Invoke-C4RecorderGit $dwr.World.Git @('add', '-A'))
        [void](Invoke-C4RecorderGit $dwr.World.Git @('commit', '--quiet', '-m', 'checkpoint b'))
        $dwrCandidate = Join-Path $dwr.World.Root ($dwr.World.SourceEvidenceRoot + '/' +
            $script:CandidateName).Replace('/', '\')
        Note 'the DELETE-hash fixture has a promoted candidate'
        if (-not [IO.File]::Exists($dwrCandidate)) {
            Fail 'the DELETE-hash fixture has a promoted candidate' 'nothing was promoted'
        } else {
            $dwrReceipt = Join-Path $dwr.World.External 'withdraw.json'
            $dwrRun = Invoke-C4RecorderChild $dwr.World @(
                '-Mode', 'WithdrawSourceCandidate',
                '-ExpectedRecorderSha256', $dwr.World.RecorderSha256,
                '-ExpectedEligibleAttemptId', $attemptId,
                '-ExpectedCandidateManifestSha256', (Get-C4RecorderSha256File $dwrCandidate),
                '-RepositoryEvidenceRoot', $dwr.World.SourceEvidenceRoot,
                '-ReceiptPath', $dwrReceipt)
            Assert-Ok 'the DELETE-hash fixture withdraws' ($dwrRun.ExitCode -eq 0) (
                $dwrRun.Stderr.Trim())
            if ($dwrRun.ExitCode -eq 0) {
                $dwrObject = ConvertFrom-C4CanonicalJsonBytes `
                    -Bytes ([IO.File]::ReadAllBytes($dwrReceipt)) `
                    -ExpectedSchema $script:ReceiptSchema
                $dwrRows = @(ConvertTo-OrderedRows @($dwrObject.changedPaths))
                foreach ($row in $dwrRows) {
                    if (([string]$row['operation']) -ceq 'DELETE') { $row['sha256'] = ('d' * 64) }
                }
                $dwrOrdered = ConvertTo-OrderedReceipt $dwrObject $dwrRows
                [IO.File]::WriteAllBytes($dwrReceipt, (Get-C4RecorderCanonicalBytes $dwrOrdered))
                Assert-Refused 'StageReceipt refuses a DELETE row carrying a hash' (
                    Invoke-C4RecorderChild $dwr.World @(
                        '-Mode', 'StageReceipt',
                        '-ExpectedRecorderSha256', $dwr.World.RecorderSha256,
                        '-InputReceiptPath', $dwrReceipt,
                        '-ExpectedRecordedMode', 'WithdrawSourceCandidate',
                        '-ExpectedAttemptId', $attemptId,
                        '-RepositoryEvidenceRoot', $dwr.World.SourceEvidenceRoot)
                ) 'must carry a null hash'
            }
        }

        # --- an unrelated dirty path, and an already-staged path ------------
        $uw = New-World
        $uExternal = Join-Path $uw.External 'attempt'
        [void](New-C4TestSealedSourceAttempt -Directory $uExternal -AttemptId $attemptId `
            -Commit $commit -Tree $tree)
        $uReceipt = Join-Path $uw.External 'record.json'
        $uRecorded = Invoke-C4RecorderChild $uw (Get-SourceRecordArguments $uw $attemptId `
            $uExternal $uReceipt $commit $tree $uw.RecorderSha256)
        Assert-Ok 'the dirty-path fixture records an attempt' ($uRecorded.ExitCode -eq 0) (
            $uRecorded.Stderr.Trim())
        $strayPath = Join-Path $uw.Root 'unrelated.txt'
        [IO.File]::WriteAllBytes($strayPath, $utf8.GetBytes("unrelated edit`n"))
        $uStageArgs = @(
            '-Mode', 'StageReceipt', '-ExpectedRecorderSha256', $uw.RecorderSha256,
            '-InputReceiptPath', $uReceipt, '-ExpectedRecordedMode', 'RecordSourceAttempt',
            '-ExpectedAttemptId', $attemptId,
            '-RepositoryEvidenceRoot', $uw.SourceEvidenceRoot)
        Assert-Refused 'StageReceipt refuses an unrelated dirty path' (
            Invoke-C4RecorderChild $uw $uStageArgs
        ) 'dirty outside this transaction'
        [IO.File]::Delete($strayPath)

        [IO.File]::WriteAllBytes((Join-Path $uw.Root 'staged.txt'),
            $utf8.GetBytes("already staged`n"))
        [void](Invoke-C4RecorderGit $uw.Git @('add', '--', 'staged.txt'))
        Assert-Refused 'StageReceipt refuses an already-staged path' (
            Invoke-C4RecorderChild $uw $uStageArgs
        ) 'index already carries staged paths'
        [void](Invoke-C4RecorderGit $uw.Git @('reset', '--quiet'))
        [IO.File]::Delete((Join-Path $uw.Root 'staged.txt'))
        Assert-Accepted 'StageReceipt accepts the same roster once the tree is clean again' (
            Invoke-C4RecorderChild $uw $uStageArgs) | Out-Null


        # =================================================================
        # F. The native attempt's exact ordered key set, and the ignored
        #    roster path that a missing ZIP negation would produce.
        # =================================================================

        $kw = New-NativeWorld
        foreach ($keyCase in @(
                @{ Name = 'a native attempt with an extra key is refused'; Extra = 'surprise'
                   Drop = '' },
                @{ Name = 'a native attempt missing a key is refused'; Extra = ''
                   Drop = 'liveIssued' })) {
            $kDir = Join-Path $kw.World.External ('k-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
            $kSha = New-C4TestSealedNativeAttempt -Directory $kDir -AttemptId $attemptId `
                -BootstrapCommit $commit -BootstrapTree $tree `
                -ExtraKey $keyCase.Extra -DropKey $keyCase.Drop
            Assert-Refused $keyCase.Name (
                Invoke-C4RecorderChild $kw.World (Get-NativeArguments $kw $kDir `
                    (Join-Path $kw.World.External ([Guid]::NewGuid().ToString('N') + '.json')) $kSha)
            ) 'exact closed ordered set'
        }

        foreach ($shape in @(
                @{ Name = 'a native hostIdentity with an extra key is refused'
                   Host = $true; Boot = $false; Expect = 'native hostIdentity keys' },
                @{ Name = 'a native bootIdentity missing a key is refused'
                   Host = $false; Boot = $true; Expect = 'native bootIdentity keys' })) {
            $sDir = Join-Path $kw.World.External ('s-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
            $sSha = New-C4TestSealedNativeAttempt -Directory $sDir -AttemptId $attemptId `
                -BootstrapCommit $commit -BootstrapTree $tree `
                -BreakHostIdentity:$shape.Host -BreakBootIdentity:$shape.Boot
            Assert-Refused $shape.Name (
                Invoke-C4RecorderChild $kw.World (Get-NativeArguments $kw $sDir `
                    (Join-Path $kw.World.External ([Guid]::NewGuid().ToString('N') + '.json')) $sSha)
            ) $shape.Expect
        }

        # A roster path the repository ignores is what a missing ZIP negation
        # under the evidence root looks like. It never reaches `git add`: an
        # ignored file is absent from `git status --untracked-files=all`, so the
        # dirty-set equality refuses it first, naming the roster entry the tree
        # does not carry.
        $gw = New-World
        $gExternal = Join-Path $gw.External 'attempt'
        [void](New-C4TestSealedSourceAttempt -Directory $gExternal -AttemptId $attemptId `
            -Commit $commit -Tree $tree)
        $gReceipt = Join-Path $gw.External 'record.json'
        $gRecorded = Invoke-C4RecorderChild $gw (Get-SourceRecordArguments $gw $attemptId `
            $gExternal $gReceipt $commit $tree $gw.RecorderSha256)
        Assert-Ok 'the ignored-path fixture records an attempt' ($gRecorded.ExitCode -eq 0) (
            $gRecorded.Stderr.Trim())
        $utf8Ignore = New-Object System.Text.UTF8Encoding $false
        [IO.File]::WriteAllBytes((Join-Path $gw.Root '.gitignore'),
            $utf8Ignore.GetBytes("command-index.json`n"))
        [void](Invoke-C4RecorderGit $gw.Git @('add', '--', '.gitignore'))
        [void](Invoke-C4RecorderGit $gw.Git @('commit', '--quiet', '-m', 'ignore a roster path'))
        Assert-Refused 'StageReceipt refuses a roster path the repository ignores' (
            Invoke-C4RecorderChild $gw @(
                '-Mode', 'StageReceipt', '-ExpectedRecorderSha256', $gw.RecorderSha256,
                '-InputReceiptPath', $gReceipt, '-ExpectedRecordedMode', 'RecordSourceAttempt',
                '-ExpectedAttemptId', $attemptId,
                '-RepositoryEvidenceRoot', $gw.SourceEvidenceRoot)
        ) 'does not carry every rostered change'

    } catch {
        # A harness fault is reported as a failure rather than rethrown: the
        # fixtures that already ran have verdicts worth printing, and the usual
        # cause is an earlier refusal cascading into a broken precondition.
        Fail 'self-test harness' ($_.Exception.Message + ' @ ' + $_.ScriptStackTrace)
    } finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }

    return [pscustomobject]@{ Checks = @($checks); Failures = @($failures) }
}

$script:SourceEvidenceRootName = 'c4-recovery-logs'

# The closed set of crash cuts the self-test drives. Each one leaves the marker,
# the journal and every partial byte exactly where a killed process would, so
# recovery has to decide its direction from the ledger rather than from anything
# the dying process managed to tidy up.
$script:CrashLabels = @(
    'AFTER_MARKER', 'AFTER_JOURNAL', 'AFTER_IMMUTABLE', 'AFTER_ALL_IMMUTABLE',
    'AFTER_BACKUP', 'AFTER_MUTABLE', 'AFTER_DELETE', 'AFTER_ALL_MUTABLE',
    'AFTER_LEDGER_TEMP', 'AFTER_LEDGER_BACKUP', 'AFTER_LEDGER_REPLACE',
    'AFTER_CLEANUP', 'AFTER_RECEIPT', 'AFTER_JOURNAL_COMMITTED'
)

function Get-C4RecorderRepositoryRoot {
    $scripts = [IO.Path]::GetFullPath($PSScriptRoot)
    $driver = [IO.Path]::GetFullPath((Join-Path $scripts '..'))
    return [IO.Path]::GetFullPath((Join-Path $driver '..'))
}

function New-C4RecorderContext {
    param(
        [string]$Mode,
        [string]$RecorderSha256,
        [string]$EvidenceRootRelative,
        [string]$ReceiptPath,
        [string]$CrashAt
    )

    $repoRoot = Get-C4RecorderRepositoryRoot
    if (-not [IO.Directory]::Exists((Join-Path $repoRoot '.git'))) {
        throw ("the recorder must run inside a Git repository: {0}" -f $repoRoot)
    }
    $git = New-C4RecorderGitAdapter $repoRoot

    $evidenceRoot = Assert-C4RecorderRelativePath $EvidenceRootRelative 'RepositoryEvidenceRoot'
    if ($evidenceRoot.LastIndexOf('/') -lt 1) {
        throw 'RepositoryEvidenceRoot must be nested under the evidence tree'
    }
    $evidenceAbsolute = [IO.Path]::GetFullPath(
        (Join-Path $repoRoot ($evidenceRoot.Replace('/', '\'))))
    if (-not $evidenceAbsolute.StartsWith($repoRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'RepositoryEvidenceRoot escapes the repository'
    }
    if (Test-C4RecorderReparse $evidenceAbsolute) {
        throw 'RepositoryEvidenceRoot is a reparse point'
    }

    $ledgerName = $script:SourceIndexName
    $context = [pscustomobject]@{
        Mode = $Mode
        RepositoryRoot = $repoRoot
        Git = $git
        RecorderSha256 = $RecorderSha256
        EvidenceRootRelative = $evidenceRoot
        EvidenceRootAbsolute = $evidenceAbsolute
        SourceEvidenceRootRelative = ($evidenceRoot.Substring(0, $evidenceRoot.LastIndexOf('/')) +
            '/' + $script:SourceEvidenceRootName)
        LedgerAbsolutePath = (Join-Path $evidenceAbsolute $ledgerName)
        MarkerPath = (Get-C4RecorderGitPath $git $script:MarkerFileName)
        ReceiptPath = $null
        JournalPath = $null
        CrashAt = $null
        ExpectedAttemptId = $null
        ExpectedSourceCommit = $null
        ExpectedSourceTree = $null
        ExternalAttemptDirectory = $null
        ExpectedCheckpointACommit = $null
        NativeReviewPath = $null
        EvidenceReviewPath = $null
        SourceVerdictPath = $null
        ExpectedEligibleAttemptId = $null
        ExpectedCandidateManifestSha256 = $null
        ExpectedBootstrapSourceCommit = $null
        ExpectedBootstrapSourceTree = $null
        ExpectedBootstrapSha256 = $null
        NativeSummaryPath = $null
        InputReceiptPath = $null
        ExpectedRecordedMode = $null
    }
    if (-not [string]::IsNullOrWhiteSpace($ReceiptPath)) {
        $receipt = Assert-C4RecorderAbsolutePath $ReceiptPath 'ReceiptPath'
        if ($receipt.StartsWith($repoRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'ReceiptPath must live outside the repository'
        }
        $context.ReceiptPath = $receipt
        $context.JournalPath = $receipt + '.transaction.json'
    }
    if (-not [string]::IsNullOrWhiteSpace($CrashAt)) { $context.CrashAt = $CrashAt }
    return $context
}

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

if ($script:C4RecorderDotSourced) { return }

[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false

function Write-C4RecorderStdoutLine {
    param([string]$Text)
    if ($null -eq $Text) { return }
    [Console]::Out.Write($Text + "`n")
    [Console]::Out.Flush()
}

if ($SelfTest) {
    try {
        $outcome = Invoke-C4RecorderSelfTests
    } catch {
        [Console]::Error.WriteLine('EVIDENCE-RECORDER SELF-TEST: FAIL: ' + $_.Exception.Message)
        [Console]::Error.WriteLine($_.ScriptStackTrace)
        exit 1
    }
    $status = 'PASS'
    if (@($outcome.Failures).Count -ne 0) { $status = 'FAIL' }
    Write-C4RecorderStdoutLine (ConvertTo-C4CanonicalJsonText ([ordered]@{
        schema = $script:SelfTestSchema
        version = 1
        checks = [int]@($outcome.Checks).Count
        failures = @($outcome.Failures)
        status = $status
    }))
    if ($status -ceq 'PASS') { exit 0 }
    exit 1
}

$selfLease = $null
try {
    # Freeze this script's bytes before anything else, and keep the handle until
    # the transaction or the staging validation has returned.
    $selfLease = Open-C4RecorderSelfLease $ExpectedRecorderSha256

    $crashAt = $env:FSRING_C4_RECORDER_CRASH_AT
    if (-not [string]::IsNullOrWhiteSpace($crashAt) -and
        $script:CrashLabels -cnotcontains $crashAt) {
        throw ("unknown crash cut: {0}" -f $crashAt)
    }

    $receiptArgument = $null
    if ($Mode -cne 'StageReceipt') { $receiptArgument = $ReceiptPath }
    $context = New-C4RecorderContext -Mode $Mode -RecorderSha256 $selfLease.Sha256 `
        -EvidenceRootRelative $RepositoryEvidenceRoot -ReceiptPath $receiptArgument `
        -CrashAt $crashAt

    # Recovery runs on every entry, before this invocation can mutate anything.
    # An interrupted predecessor is resolved in exactly one direction or refused.
    $recovered = Invoke-C4RecorderRecovery $context
    if ($recovered.Direction -cne 'NONE') {
        Write-C4RecorderStdoutLine (ConvertTo-C4CanonicalJsonText ([ordered]@{
            schema = 'fsring-c4-evidence-recorder-recovery/v1'
            version = 1
            direction = $recovered.Direction
            transactionId = $recovered.TransactionId
        }))
    }

    Assert-C4HeldFileLease $selfLease

    $result = $null
    switch ($Mode) {
        'RecordSourceAttempt' {
            $context.ExternalAttemptDirectory = $ExternalAttemptDirectory
            $context.ExpectedAttemptId = $ExpectedAttemptId
            $context.ExpectedSourceCommit = $ExpectedSourceCommit
            $context.ExpectedSourceTree = $ExpectedSourceTree
            $result = Invoke-C4RecordSourceAttempt $context
        }
        'FinalizeSourceReview' {
            $context.ExpectedAttemptId = $ExpectedAttemptId
            $context.ExpectedCheckpointACommit = $ExpectedCheckpointACommit
            $context.NativeReviewPath = $NativeReviewPath
            $context.EvidenceReviewPath = $EvidenceReviewPath
            $context.SourceVerdictPath = $SourceVerdictPath
            $result = Invoke-C4FinalizeSourceReview $context
        }
        'WithdrawSourceCandidate' {
            $context.ExpectedEligibleAttemptId = $ExpectedEligibleAttemptId
            $context.ExpectedCandidateManifestSha256 = $ExpectedCandidateManifestSha256
            $result = Invoke-C4WithdrawSourceCandidate $context
        }
        'RecordNativeAttempt' {
            $context.ExternalAttemptDirectory = $ExternalAttemptDirectory
            $context.ExpectedAttemptId = $ExpectedAttemptId
            $context.ExpectedBootstrapSourceCommit = $ExpectedBootstrapSourceCommit
            $context.ExpectedBootstrapSourceTree = $ExpectedBootstrapSourceTree
            $context.ExpectedBootstrapSha256 = $ExpectedBootstrapSha256
            # The summary is a fixed sibling of the evidence root. Accepting an
            # arbitrary path here would let a caller enrol any worktree file in
            # an evidence-only checkpoint.
            $expectedSummary = ($context.EvidenceRootRelative.Substring(
                0, $context.EvidenceRootRelative.LastIndexOf('/')) + '/' +
                $script:NativeSummaryName)
            $supplied = Assert-C4RecorderRelativePath $NativeSummaryPath 'NativeSummaryPath'
            if ($supplied -cne $expectedSummary) {
                throw ("NativeSummaryPath must be exactly {0}" -f $expectedSummary)
            }
            $context.NativeSummaryPath = $supplied
            $result = Invoke-C4RecordNativeAttempt $context
        }
        'StageReceipt' {
            $context.ExpectedAttemptId = $ExpectedAttemptId
            $context.InputReceiptPath = $InputReceiptPath
            $context.ExpectedRecordedMode = $ExpectedRecordedMode
            $result = Invoke-C4StageReceipt $context
        }
        default { throw ("unreachable mode {0}" -f $Mode) }
    }

    Assert-C4HeldFileLease $selfLease
    Write-C4RecorderStdoutLine (ConvertTo-C4CanonicalJsonText $result)
    exit 0
} catch {
    [Console]::Error.WriteLine('EVIDENCE-RECORDER: FAIL: ' + $_.Exception.Message)
    exit 1
} finally {
    Close-C4HeldFileLease $selfLease
}
