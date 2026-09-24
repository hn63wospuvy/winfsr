# Exact Win10 x64 release package extraction, verification, and identity
# binding for the C4 recovery source gate (Task 28 row 21/22).
#
# This script copies only the row-20 build outputs, requires the exact
# six-member package roster, and invokes the committed package verifier with
# the frozen InfVerif/SignTool paths supplied by row 21. Every one of those
# five refusal classes -- source identity, build root, profile, package
# member timestamp/identity, and verifier tool identity -- is a hard stop
# before any candidate byte is produced.
#
# It emits exactly one canonical `fsring-c4-package-candidate/v1` object on
# stdout. The verifier's own bytes are never re-printed: they are captured
# whole into the attempt's `package-verifier.*` auxiliary triplet, so the
# package script produces no uncaptured verifier output.

[CmdletBinding(DefaultParameterSetName = 'Package')]
param(
    [Parameter(ParameterSetName = 'SelfTest', Mandatory = $true)]
    [switch]$SelfTest,

    [Parameter(ParameterSetName = 'Package', Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(ParameterSetName = 'Package', Mandatory = $true)]
    [string]$ExpectedSourceCommit,

    [Parameter(ParameterSetName = 'Package', Mandatory = $true)]
    [string]$ExpectedSourceTree,

    [Parameter(ParameterSetName = 'Package', Mandatory = $true)]
    [string]$Profile,

    [Parameter(ParameterSetName = 'Package', Mandatory = $true)]
    [string]$InfVerifPath,

    [Parameter(ParameterSetName = 'Package', Mandatory = $true)]
    [string]$SignToolPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Whether *this* script was dot-sourced has to be read before the import: a
# dot-source runs in the caller's scope, so importing the capture helper sets
# its own `C4EvidenceDotSourced` to true here regardless of how this file was
# invoked. Reading that flag instead would make direct execution do nothing.
$script:C4PackageDotSourced = ($MyInvocation.InvocationName -eq '.')

# Dot-sourcing the capture helper redefines $SelfTest inside this scope, so
# the switch is saved across the import exactly the way smoke_driver.ps1 does.
$script:C4PackageSavedSelfTest = [bool]$SelfTest
if (-not (Get-Variable -Name C4EvidenceDotSourced -Scope Script -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'invoke_c4_evidence.ps1')
}
$SelfTest = [bool]$script:C4PackageSavedSelfTest

$script:PackageCandidateSchema = 'fsring-c4-package-candidate/v1'
$script:PackageVerificationSchema = 'fsring-c4-package-verification/v1'
$script:PackageSetSchema = 'fsring-c4-package-set/v1'
$script:PackageVerifierSchema = 'fsring-package-verifier/v1'
$script:NestedToolMarkerSchema = 'fsring-c4-nested-tools-marker/v1'
$script:NestedToolMarkerSentinel = 'FSRING-C4-NESTED-TOOLS '
$script:SelfTestSchema = 'fsring-c4-package-candidate-selftest/v1'

# The closed six-member package roster, in the one order the candidate
# manifest's `memberNames` and `members` array require.
$script:PackageMemberNames = @(
    'fsring_fsd.inf',
    'fsring_fsd.sys',
    'fsring_fsd.cat',
    'fsring_fsd.pdb',
    'fsring_fsd.map',
    'WDRLocalTestCert.cer'
)

# The one accepted profile. `machine` is the PE header value the packaged
# .sys must actually report; it is read from the copied bytes, not asserted.
$script:PackageProfiles = @{
    'win10-x64-release' = [ordered]@{
        id = 'win10-x64-release'
        target = 'x86_64-pc-windows-msvc'
        driverFeature = 'platform-win10'
        cargoProfile = 'release'
        machine = '0x8664'
    }
}

$script:VerifierScriptRelativePath = 'driver/scripts/verify_fsring_package.ps1'
$script:PackageRelativePath = 'artifacts/win10-x64-release/package'
$script:PackageRelativeWindowsPath = 'artifacts\win10-x64-release\package'
$script:VerifierStdoutName = 'package-verifier.stdout.bin'
$script:VerifierStderrName = 'package-verifier.stderr.bin'
$script:VerifierExitName = 'package-verifier.exit.json'
# Not a sealed attempt member: it is the working file this row's launch counts
# are tallied from, and the tally -- not the file -- is what the marker seals.
# It therefore lives in a disposable directory of its own, OUTSIDE the attempt.
# The runner's attempt-file roster is a closed set that refuses any file it does
# not name, and it builds that roster only after the last row: a journal left in
# the attempt root fails sealing when all 38 rows have already passed, and an
# unsealed attempt cannot be recorded at all -- not even as the FAIL it was.
$script:VerifierLaunchJournalName = 'package-verifier.launches.txt'

# Row 21's closed nested-launch oracle. The packager launches PowerShell once;
# the verifier launches InfVerif once and SignTool three times. Each count is
# read back out of the verifier's own report rather than assumed.
# The closed oracle for this row's MEASURED launch counts. Derived from an
# instrumented run, not from the shape of the verifier's report: `signtool` is
# six because the verifier makes three kernel-policy probes and three
# Authenticode corroboration probes per package.
$script:ExpectedNestedLaunchCounts = [ordered]@{
    powershell = 1
    infverif = 1
    signtool = 6
}

function Get-C4PackageRepositoryRoot {
    $scripts = [IO.Path]::GetFullPath($PSScriptRoot)
    $driver = [IO.Path]::GetFullPath((Join-Path $scripts '..'))
    return [IO.Path]::GetFullPath((Join-Path $driver '..'))
}

function Assert-C4PackageHex {
    param([string]$Value, [int]$Length, [string]$Name)
    if ($null -eq $Value -or $Value -cnotmatch ('^[0-9a-f]{' + $Length + '}$')) {
        throw ("{0} must be exactly {1} lowercase hexadecimal characters" -f $Name, $Length)
    }
}

function Assert-C4PackageCanonicalAbsolutePath {
    param([string]$Path, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw ("{0} is required" -f $Name)
    }
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

function Test-C4PackageReparsePoint {
    param([string]$Path)
    $attributes = [IO.File]::GetAttributes($Path)
    return (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Get-C4PackageFileSha256 {
    param([string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    return [pscustomobject]@{
        Bytes = [int64]$bytes.Length
        Sha256 = (Get-C4EvidenceSha256Hex $bytes)
    }
}

# A held lease needs its expected hash up front, so the bytes are measured
# once and then re-proved through the retained deny-write/delete handle. The
# lease is what makes a midpoint swap visible: it fails on identity, hard
# link, alias, or byte drift, not merely on a second hash agreeing with a
# first one this process computed.
function Open-C4PackageMeasuredLease {
    param([string]$Path, [string]$Name)
    $canonical = Assert-C4PackageCanonicalAbsolutePath $Path $Name
    if (-not [IO.File]::Exists($canonical)) {
        throw ("{0} is not an existing file: {1}" -f $Name, $canonical)
    }
    if (Test-C4PackageReparsePoint $canonical) {
        throw ("{0} is a reparse point: {1}" -f $Name, $canonical)
    }
    $measured = Get-C4PackageFileSha256 $canonical
    return Open-C4HeldFileLease -Path $canonical -ExpectedSha256 $measured.Sha256
}

function Get-C4PackagePeMachine {
    param([string]$Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $reader = New-Object IO.BinaryReader($stream)
        if ($stream.Length -lt 64) { throw 'packaged .sys is too small to carry a PE header' }
        $stream.Position = 0
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'packaged .sys is not an MZ image' }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -le 0 -or ($peOffset + 6) -gt $stream.Length) {
            throw 'packaged .sys carries an out-of-range PE header offset'
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw 'packaged .sys is missing the PE signature' }
        return ('0x{0:X4}' -f $reader.ReadUInt16())
    } finally {
        $stream.Dispose()
    }
}

# The nested-tool marker is how the runner learns which frozen executables a
# helper actually touched. It is a single sentinel-prefixed canonical JSON
# line on raw stdout, emitted once before the child roster and once after, so
# the runner can prove the identities it froze are the identities that ran and
# that the closed launch counts were met. The nonce is supplied by the runner;
# without it there is nothing to bind a marker to, so none is emitted and a
# standalone invocation stays quiet.
function New-C4NestedToolMarkerText {
    param(
        [ValidateSet('PRE', 'POST')]
        [string]$Phase,
        [string]$Nonce,
        [string]$CommandId,
        $ToolLeases,
        $LaunchCounts
    )

    if ([string]::IsNullOrWhiteSpace($Nonce)) { return $null }
    $tools = New-Object System.Collections.ArrayList
    foreach ($entry in $ToolLeases) {
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
    $marker = [ordered]@{
        schema = $script:NestedToolMarkerSchema
        version = 1
        nonce = $Nonce
        phase = $Phase
        commandId = $CommandId
        tools = @($tools)
        launchCounts = @($counts)
    }
    return ($script:NestedToolMarkerSentinel + (ConvertTo-C4CanonicalJsonText $marker))
}

# Markers and the final object go straight to the process's stdout stream
# rather than through Write-Output. Write-Output feeds the *enclosing
# function's* pipeline, so a marker emitted that way would be folded into
# Invoke-C4PackageCandidate's return value and never reach the runner. Writing
# an explicit LF also keeps the raw bytes the runner hashes independent of the
# host's newline.
function Write-C4PackageStdoutLine {
    param([string]$Text)
    if ($null -eq $Text) { return }
    [Console]::Out.Write($Text + "`n")
    [Console]::Out.Flush()
}

function Write-C4NestedToolMarker {
    param(
        [ValidateSet('PRE', 'POST')]
        [string]$Phase,
        [string]$Nonce,
        [string]$CommandId,
        $ToolLeases,
        $LaunchCounts
    )

    $text = New-C4NestedToolMarkerText -Phase $Phase -Nonce $Nonce -CommandId $CommandId `
        -ToolLeases $ToolLeases -LaunchCounts $LaunchCounts
    Write-C4PackageStdoutLine $text
}

# The build root is the one directory row 20 produces. Its content must be
# exactly the six-member roster: an extra file, a missing member, a
# subdirectory, or a reparse entry all refuse before a byte is copied,
# because a package that is not exactly this set is not the package the
# candidate claims to be.
function Read-C4PackageBuildRoot {
    param([string]$BuildRoot)

    $canonical = Assert-C4PackageCanonicalAbsolutePath $BuildRoot 'build root'
    if (-not [IO.Directory]::Exists($canonical)) {
        throw ("build root is not an existing directory: {0}" -f $canonical)
    }
    if (Test-C4PackageReparsePoint $canonical) {
        throw ("build root is a reparse point: {0}" -f $canonical)
    }
    $resolved = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $canonical).Path)
    if (-not $resolved.Equals($canonical, [StringComparison]::OrdinalIgnoreCase)) {
        throw ("build root is an alias: {0}" -f $canonical)
    }
    $directories = @([IO.Directory]::GetDirectories($canonical))
    if ($directories.Count -ne 0) {
        throw ("build root carries {0} unexpected subdirectory(ies)" -f $directories.Count)
    }
    $observed = @(
        [IO.Directory]::GetFiles($canonical) |
            ForEach-Object { [IO.Path]::GetFileName($_) } |
            Sort-Object -CaseSensitive
    )
    $expected = @($script:PackageMemberNames | Sort-Object -CaseSensitive)
    $missing = @($expected | Where-Object { $observed -cnotcontains $_ })
    if ($missing.Count -ne 0) {
        throw ("build root is missing package member(s): {0}" -f ($missing -join ', '))
    }
    $extra = @($observed | Where-Object { $expected -cnotcontains $_ })
    if ($extra.Count -ne 0) {
        throw ("build root carries member(s) outside the closed roster: {0}" -f ($extra -join ', '))
    }

    # Roster order, not directory order: the candidate manifest's member array
    # is ordered, so the leases are taken in that same declared order.
    $leases = New-Object System.Collections.ArrayList
    try {
        foreach ($name in $script:PackageMemberNames) {
            $path = Join-Path $canonical $name
            [void]$leases.Add([pscustomobject]@{
                Name = $name
                Lease = (Open-C4PackageMeasuredLease $path ('package member ' + $name))
            })
        }
    } catch {
        foreach ($held in $leases) { Close-C4HeldFileLease $held.Lease }
        throw
    }
    return [pscustomobject]@{ BuildRoot = $canonical; Members = @($leases) }
}

# CreateNew for every destination: the packager owns these bytes, so an
# already-present output file is a refusal rather than something to overwrite.
function Copy-C4PackageMembers {
    param(
        $SourceMembers,
        [string]$Destination,
        [ValidateSet('', 'TruncateDestination')]
        [string]$FaultInjection = ''
    )

    $rows = New-Object System.Collections.ArrayList
    foreach ($member in $SourceMembers) {
        Assert-C4HeldFileLease $member.Lease
        $target = Join-Path $Destination $member.Name
        $stream = New-Object IO.FileStream(
            $target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        try {
            $bytes = [IO.File]::ReadAllBytes($member.Lease.Path)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        if ($FaultInjection -ceq 'TruncateDestination') {
            $truncate = New-Object IO.FileStream(
                $target, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $truncate.SetLength(0) } finally { $truncate.Dispose() }
        }
        # The copy is proved against the retained source handle, so a source
        # replaced between the roster read and this write cannot be laundered
        # into the attempt by agreeing with itself.
        Assert-C4HeldFileLease $member.Lease
        $copied = Get-C4PackageFileSha256 $target
        if ($copied.Sha256 -cne $member.Lease.Sha256 -or $copied.Bytes -ne $member.Lease.Length) {
            throw ("copied package member drifted from its held source: {0}" -f $member.Name)
        }
        [void]$rows.Add([ordered]@{
            relativePath = ($script:PackageRelativePath + '/' + $member.Name)
            bytes = [int64]$copied.Bytes
            sha256 = $copied.Sha256
        })
    }
    return @($rows)
}

function Get-C4PackageSetSha256 {
    param($MemberRows)
    $object = [ordered]@{
        schema = $script:PackageSetSchema
        version = 1
        members = @($MemberRows)
    }
    $utf8 = New-Object System.Text.UTF8Encoding $false
    $bytes = $utf8.GetBytes((ConvertTo-C4CanonicalJsonText $object) + "`n")
    return (Get-C4EvidenceSha256Hex $bytes)
}

# The verifier speaks compact JSON on one line and terminates it with the
# host's newline, so the bytes are decoded and trimmed rather than required to
# be canonical. Anything other than exactly one object line is a refusal:
# extra output would mean the package script had let uncaptured or
# unaccounted-for verifier text through.
function Read-C4PackageVerifierReport {
    param([byte[]]$StdoutBytes)

    if ($null -eq $StdoutBytes -or $StdoutBytes.Length -eq 0) {
        throw 'package verifier produced no stdout'
    }
    if ($StdoutBytes.Length -gt 1048576) {
        throw 'package verifier stdout overflowed 1048576 bytes'
    }
    if ($StdoutBytes[0] -eq 0xEF) {
        throw 'package verifier stdout carries a BOM'
    }
    $utf8 = Get-C4EvidenceUtf8
    $text = $utf8.GetString($StdoutBytes)
    if ($text.Contains([char]0)) { throw 'package verifier stdout contains NUL' }
    $lines = @($text.Split(@("`r`n", "`n"), [StringSplitOptions]::None) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -ne 1) {
        throw ("package verifier stdout is not one object line ({0} lines)" -f $lines.Count)
    }
    $report = $lines[0] | ConvertFrom-Json
    if ($report.schema -cne $script:PackageVerifierSchema) {
        throw ("package verifier stdout schema is {0}, not {1}" -f
            $report.schema, $script:PackageVerifierSchema)
    }
    return $report
}

# Three separate statuses, each read out of the verifier's own report. The
# verifier only reports overall PASS with an empty error list, but folding
# signature and catalog evidence into that one word would leave the candidate
# manifest unable to say which of them was actually observed.
function Get-C4PackageVerifierStatuses {
    param($Report)

    $semantic = [string]$Report.overall
    if ($semantic -cne 'PASS' -and $semantic -cne 'FAIL') {
        throw ("package verifier overall is {0}, not PASS or FAIL" -f $semantic)
    }

    $signature = 'FAIL'
    $signtool = $null
    if ($null -ne $Report.tools -and
        $null -ne $Report.tools.PSObject.Properties['signtool']) {
        $signtool = $Report.tools.signtool
    }
    if ($null -ne $signtool) {
        $codes = New-Object System.Collections.ArrayList
        foreach ($field in @('sysExitCode', 'catExitCode', 'catalogMemberExitCode')) {
            if ($null -eq $signtool.PSObject.Properties[$field]) {
                throw ("package verifier report omits signtool.{0}" -f $field)
            }
            [void]$codes.Add([int]$signtool.$field)
        }
        # Signature INTEGRITY, not local trust. The verifier separates the two
        # deliberately: a missing catalog membership, a wrong signing
        # certificate, a tampered binary, or three probes that disagree are each
        # an ERROR, which makes `overall` FAIL. A signing root that is simply
        # not trusted on THIS machine is a WARNING with `trustReady = false`,
        # and it makes every kernel-policy probe exit nonzero while the
        # signature itself is intact.
        #
        # Reading nonzero exits as a failed signature made this row require
        # local trust -- a precondition the plan assigns to the separately
        # authorized host, where `run_c4_native_attempt.ps1` enforces it as
        # PACKAGE_NOT_TRUST_READY. `trustReady` is recorded below either way, so
        # the evidence still says which host state was observed.
        $distinct = @($codes | Sort-Object -Unique)
        if ($semantic -ceq 'PASS' -and $distinct.Count -eq 1) { $signature = 'PASS' }
    }

    # The launch COUNT is measured from the journal, but the report must still
    # say the tool produced a result: a verifier that never reached InfVerif
    # has not verified the INF, whatever its launch tally says.
    if ($null -eq $Report.tools -or
        $null -eq $Report.tools.PSObject.Properties['infverif'] -or
        $null -eq $Report.tools.infverif.PSObject.Properties['exitCode']) {
        throw 'package verifier report omits tools.infverif.exitCode'
    }

    $catalog = 'FAIL'
    if ($null -ne $Report.tools -and
        $null -ne $Report.tools.PSObject.Properties['catalogMembership'] -and
        $Report.tools.catalogMembership.valid -eq $true) {
        $catalog = 'PASS'
    }


    # Recorded, never required here. Task 30 requires it on the authorized host.
    $trustReady = $false
    if ($null -ne $Report.PSObject.Properties['trustReady']) {
        $trustReady = [bool]$Report.trustReady
    }

    return [pscustomobject]@{
        SemanticStatus = $semantic
        SignatureStatus = $signature
        CatalogStatus = $catalog
        TrustReady = $trustReady
    }
}

# Tally the launch journal into the three closed roles.
#
# This is the row's launch evidence, and it is deliberately NOT derivable from
# the verifier's report: a count taken from the report's shape agrees with
# whatever shape the report has, which is how this row came to seal three
# signtool launches while six were performed. A path outside the three frozen
# executables is a refusal rather than an unnamed row, because an unrecognised
# launch is exactly what these counts exist to make visible.
# Refuse a verifier whose launches this row cannot see.
#
# The tally is only as complete as the choke point that writes it, and a launch
# site added outside `Invoke-PackageTool` would lower the measurement and the
# expectation together -- the shape where a number agrees with itself. So the
# verifier's own source is read: exactly one launch may reach a native tool,
# it must be the one inside `Invoke-PackageTool`, and that function must still
# append to the journal. The self-test's re-entrant `& powershell.exe -File
# $PSCommandPath` is named as the single exemption, because it launches this
# same script rather than a package tool.
#
# WHAT THIS DOES NOT DO. Two rounds running, this comment claimed a boundary
# and a review falsified the claim -- first "an invocation cannot hide behind
# its spelling" (seven constructs passed), then "reflection is the class no
# sweep closes" (seven more passed, including module-qualified spellings of
# the very cmdlets whose aliases had just been closed). The lesson is not
# that the list was short. It is that the list is the wrong instrument:
# PowerShell resolves names, and the set of ways to name a launch is open.
#
# So this sweep is stated as what it is -- a deterrent that raises the cost
# of an unjournalled launch -- and NOT as a boundary. No enumeration here
# should be read as complete, and none is claimed to be.
#
# The guarantee lives elsewhere and is narrower: `Get-C4PackageLaunchTally`
# refuses any journalled path outside the frozen roster, and
# `Assert-C4PackageLaunchCounts` refuses a tally that differs from the closed
# oracle. The residual is ANY launch that is never journalled -- of a frozen
# tool or of a foreign binary, the tally cannot tell the difference because
# it never sees either. Closing it needs a count this driver does not produce:
# the capture helper already runs every child inside a job object, whose
# `TotalProcesses` accounting counts process creations at the OS level,
# independently of what the verifier chooses to write down. That is the fix,
# and it is owed rather than done.
function Assert-C4PackageVerifierLaunchCoverage {
    param([string]$VerifierPath)

    $text = [IO.File]::ReadAllText($VerifierPath)
    $lines = @($text.Split(@("`r`n", "`n"), [StringSplitOptions]::None))
    $unnoted = New-Object System.Collections.ArrayList
    for ($index = 0; $index -lt $lines.Count; $index++) {
        $line = $lines[$index]
        if ($line -notmatch '(?<![`\w])&\s+[\$\w]') { continue }
        if ($line -match '&\s+\$Path\s+@Arguments') { continue }
        if ($line -match 'Invoke-PackageTool') { continue }
        if ($line -match '&\s+powershell\.exe[^
]*\$PSCommandPath') { continue }
        [void]$unnoted.Add(('line {0}: {1}' -f ($index + 1), $line.Trim()))
    }
    if ($unnoted.Count -ne 0) {
        throw ("package verifier launches outside the noted choke point: {0}" -f ($unnoted -join '; '))
    }

    # The scan above only sees the `&` call operator followed by a space. A
    # launch reaches a native tool through several other shapes -- Start-Process,
    # [Diagnostics.Process]::Start, a bare `tool.exe` command word, `&$x` with no
    # space, `& "$x"` -- and every one of them would lower the measurement and
    # leave the expectation alone, which is the self-agreeing number this guard
    # exists to prevent. So the same question is put to the parse tree, where an
    # invocation cannot hide behind its spelling.
    $parseErrors = $null
    $parseTokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $VerifierPath, [ref]$parseTokens, [ref]$parseErrors)
    if ($null -ne $parseErrors -and @($parseErrors).Count -ne 0) {
        throw ("package verifier does not parse: {0}" -f @($parseErrors)[0].Message)
    }
    $unseen = New-Object System.Collections.ArrayList
    $chokePoints = 0
    $commandNodes = $ast.FindAll(
        { param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($node in $commandNodes) {
        $commandName = $node.GetCommandName()
        $isAmpersand = ([string]$node.InvocationOperator -ceq 'Ampersand')
        # An extension is not what makes a word a launch: `signtool` and `cmd`
        # resolve through PATH exactly as `signtool.exe` does, and a review
        # showed three of this guard's own fixtures passing once respelled.
        $isExternalWord = ($null -ne $commandName) -and
            (($commandName -match '\.(exe|com|cmd|bat)$') -or
             ($commandName -match '^(cmd|signtool|infverif|powershell|pwsh|rundll32|wmic|reg)$'))
        # Aliases are the same cmdlet under another name; PowerShell resolves
        # them before anything this sweep could see.
        $isLauncherCmdlet = ($null -ne $commandName) -and
            ($commandName -match '^(Start-Process|Start-Job|Start-ThreadJob|Invoke-Expression|Invoke-Item|saps|start|iex|ii)$')
        if (-not ($isAmpersand -or $isExternalWord -or $isLauncherCmdlet)) { continue }
        $nodeText = [string]$node.Extent.Text
        if ($nodeText -match '^&\s*\$Path\s+@Arguments') {
            $chokePoints = $chokePoints + 1
            continue
        }
        # The re-entrant self-test launch runs this same script, not a package
        # tool, and is the one exemption the line scan already names.
        if ($nodeText -match '\$PSCommandPath') { continue }
        [void]$unseen.Add(('line {0}: {1}' -f $node.Extent.StartLineNumber, $nodeText))
    }
    $memberNodes = $ast.FindAll(
        { param($node) $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)
    foreach ($node in $memberNodes) {
        # A member name assembled at run time -- `::('St'+'art')` -- is not a
        # spelling this sweep can read, so the name being non-constant is
        # itself the refusal. A constant name is refused only when it is
        # `Start`.
        if ($node.Member -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
            [void]$unseen.Add(
                ('line {0}: {1}' -f $node.Extent.StartLineNumber, [string]$node.Extent.Text))
            continue
        }
        if ([string]$node.Member.Value -cne 'Start') { continue }
        [void]$unseen.Add(
            ('line {0}: {1}' -f $node.Extent.StartLineNumber, [string]$node.Extent.Text))
    }
    if ($unseen.Count -ne 0) {
        throw ("package verifier launches through a construct the line scan cannot see: {0}" -f ($unseen -join '; '))
    }
    if ($chokePoints -ne 1) {
        throw ("package verifier parses to {0} choke-point launches, not exactly one" -f $chokePoints)
    }
    if ($text -notmatch [regex]::Escape('[IO.File]::AppendAllText($script:LaunchJournal, ($Path + [Environment]::NewLine))')) {
        throw 'package verifier no longer notes its launches into the journal'
    }
    if (([regex]::Matches($text, [regex]::Escape('& $Path @Arguments'))).Count -ne 1) {
        throw 'package verifier has more than one native launch site'
    }
}

function Get-C4PackageLaunchTally {
    param([string]$JournalPath, $Roles)

    if (-not [IO.File]::Exists($JournalPath)) {
        throw ("package verifier launch journal is missing: {0}" -f $JournalPath)
    }
    $tally = [ordered]@{}
    foreach ($entry in $Roles) { $tally[$entry.Role] = 0 }
    $byPath = @{}
    foreach ($entry in $Roles) { $byPath[$entry.Lease.Path.ToLowerInvariant()] = $entry.Role }
    foreach ($line in [IO.File]::ReadAllLines($JournalPath)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $key = ([IO.Path]::GetFullPath($line.Trim())).ToLowerInvariant()
        if (-not $byPath.ContainsKey($key)) {
            throw ("package verifier launched an executable outside the frozen roster: {0}" -f $line.Trim())
        }
        $role = $byPath[$key]
        $tally[$role] = [int]$tally[$role] + 1
    }
    return $tally
}

function Assert-C4PackageLaunchCounts {
    param($Observed)
    foreach ($role in @($script:ExpectedNestedLaunchCounts.Keys)) {
        $expected = [int]$script:ExpectedNestedLaunchCounts[$role]
        $actual = [int]$Observed[$role]
        if ($actual -ne $expected) {
            throw ("nested {0} launch count is {1}, not the closed {2}" -f $role, $actual, $expected)
        }
    }
}

function New-C4PackageProductionAdapters {
    param([string]$RepoRoot)

    $verifier = [IO.Path]::GetFullPath(
        (Join-Path $RepoRoot ($script:VerifierScriptRelativePath -replace '/', '\')))

    # The real verifier only. A tally is only as complete as the choke point
    # that writes it, so this row refuses a verifier whose launches it could
    # not see, before that verifier is ever handed to a run.
    Assert-C4PackageVerifierLaunchCoverage $verifier
    $buildRoot = [IO.Path]::GetFullPath(
        (Join-Path $RepoRoot 'driver\target\x86_64-pc-windows-msvc\release\fsring_fsd_package'))
    # The runner launched this process from the frozen PowerShell payload, so
    # the host executable is that same frozen path. Rediscovering it through
    # PATH would hand the closed role back to the ambient environment.
    $hostExecutable = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

    return [pscustomobject]@{
        BuildRoot = $buildRoot
        VerifierScriptPath = $verifier
        HostPowerShellPath = [IO.Path]::GetFullPath($hostExecutable)
        ObserveSource = {
            param([string]$Root)
            $porcelain = & git -C $Root status --porcelain
            if ($LASTEXITCODE -ne 0) { throw 'git status failed' }
            $commit = (& git -C $Root rev-parse HEAD)
            if ($LASTEXITCODE -ne 0) { throw 'git rev-parse HEAD failed' }
            $tree = (& git -C $Root rev-parse 'HEAD^{tree}')
            if ($LASTEXITCODE -ne 0) { throw 'git rev-parse HEAD^{tree} failed' }
            $dirtyLines = @(@($porcelain) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            return [pscustomobject]@{
                Commit = ([string]$commit).Trim()
                Tree = ([string]$tree).Trim()
                Dirty = ($dirtyLines.Count -ne 0)
            }
        }
        RunVerifier = {
            param($Request)
            Invoke-C4EvidenceProcess `
                -Executable $Request.Executable `
                -Arguments $Request.ArgumentList `
                -WorkingDirectory $Request.WorkingDirectory `
                -TimeoutMilliseconds 1800000 `
                -StdoutPath $Request.StdoutPath `
                -StderrPath $Request.StderrPath `
                -ExitPath $Request.ExitPath `
                -ExitFormat CanonicalJson
        }
    }
}

# The one production path. Every refusal below happens before the destination
# directory is created, or -- once bytes exist -- propagates out so the runner
# records row 21 as a failure instead of a reusable PASS.
function Invoke-C4PackageCandidate {
    param(
        [Parameter(Mandatory = $true)] [string]$RepoRoot,
        [Parameter(Mandatory = $true)] [string]$OutputDirectory,
        [Parameter(Mandatory = $true)] [string]$ExpectedSourceCommit,
        [Parameter(Mandatory = $true)] [string]$ExpectedSourceTree,
        [Parameter(Mandatory = $true)] [string]$ProfileId,
        [Parameter(Mandatory = $true)] [string]$InfVerifPath,
        [Parameter(Mandatory = $true)] [string]$SignToolPath,
        [Parameter(Mandatory = $true)] $Adapters,
        [string]$MarkerNonce,
        [string]$CommandId,
        [ValidateSet('', 'TruncateDestination')]
        [string]$FaultInjection = ''
    )

    # 1. Profile. An unknown profile has no closed target/feature/machine
    #    tuple, so there is nothing to bind the bytes to.
    if (-not $script:PackageProfiles.Contains($ProfileId)) {
        throw ("profile {0} is not the closed win10-x64-release profile" -f $ProfileId)
    }
    $profileRow = $script:PackageProfiles[$ProfileId]

    Assert-C4PackageHex $ExpectedSourceCommit 40 'ExpectedSourceCommit'
    Assert-C4PackageHex $ExpectedSourceTree 40 'ExpectedSourceTree'

    # 2. Source identity. A dirty tree or a commit/tree other than the one the
    #    caller pinned means these bytes cannot be attributed to S,T.
    $source = & $Adapters.ObserveSource $RepoRoot
    if ($source.Dirty) {
        throw 'source tree is dirty; the package candidate must come from a clean S,T'
    }
    if ($source.Commit -cne $ExpectedSourceCommit) {
        throw ("source commit is {0}, not the expected {1}" -f $source.Commit, $ExpectedSourceCommit)
    }
    if ($source.Tree -cne $ExpectedSourceTree) {
        throw ("source tree is {0}, not the expected {1}" -f $source.Tree, $ExpectedSourceTree)
    }

    # 3. Destination shape. The output directory is the attempt-relative
    #    package path, so the attempt root is derivable and the verifier
    #    capture triplet lands where the auxiliary roster expects it.
    $output = Assert-C4PackageCanonicalAbsolutePath $OutputDirectory 'OutputDirectory'
    if ([IO.Directory]::Exists($output) -or [IO.File]::Exists($output)) {
        throw ("OutputDirectory already exists: {0}" -f $output)
    }
    $expectedSuffix = $script:PackageRelativeWindowsPath
    if (-not $output.EndsWith('\' + $expectedSuffix, [StringComparison]::OrdinalIgnoreCase)) {
        throw ("OutputDirectory must end with {0}: {1}" -f $expectedSuffix, $output)
    }
    $attemptRoot = $output.Substring(0, $output.Length - $expectedSuffix.Length - 1)
    # Containment is judged before existence: a destination inside the
    # repository is refused whether or not its parent happens to be there, so
    # this refusal cannot be masked by an absent-parent message.
    $repoFull = [IO.Path]::GetFullPath($RepoRoot)
    if ($output.StartsWith($repoFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'the package candidate must not be written inside the repository'
    }
    if (-not [IO.Directory]::Exists($attemptRoot)) {
        throw ("attempt root is not an existing directory: {0}" -f $attemptRoot)
    }

    # 4. Build root roster, taken under retained handles before anything is
    #    created. This is the build-root refusal class.
    $buildRoot = Read-C4PackageBuildRoot $Adapters.BuildRoot
    $memberLeases = $buildRoot.Members

    $infverifLease = $null
    $signtoolLease = $null
    $powershellLease = $null
    $verifierLease = $null
    $journalRoot = $null
    try {
        # 5. Verifier tool identity. All four executables and the verifier
        #    script are held for the whole call.
        $infverifLease = Open-C4PackageMeasuredLease $InfVerifPath 'InfVerifPath'
        $signtoolLease = Open-C4PackageMeasuredLease $SignToolPath 'SignToolPath'
        $powershellLease = Open-C4PackageMeasuredLease $Adapters.HostPowerShellPath 'frozen PowerShell'
        $verifierLease = Open-C4PackageMeasuredLease $Adapters.VerifierScriptPath 'package verifier script'

        # 6. Create the destination and copy only the roster bytes.
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($output))
        $created = [IO.Directory]::CreateDirectory($output)
        if (-not $created.Exists) {
            throw ("could not create OutputDirectory: {0}" -f $output)
        }
        $memberRows = Copy-C4PackageMembers $memberLeases $output $FaultInjection

        # 7. The copied image must actually be the profile's machine. Reading
        #    it from the bytes just written is the only way this is evidence
        #    rather than a restatement of the -Profile argument.
        $machine = Get-C4PackagePeMachine (Join-Path $output 'fsring_fsd.sys')
        if ($machine -cne $profileRow.machine) {
            throw ("packaged .sys reports machine {0}, not the profile's {1}" -f $machine, $profileRow.machine)
        }

        $stdoutPath = Join-Path $attemptRoot $script:VerifierStdoutName
        $stderrPath = Join-Path $attemptRoot $script:VerifierStderrName
        $exitPath = Join-Path $attemptRoot $script:VerifierExitName

        # The launch journal. Every native launch the verifier makes appends
        # one absolute executable path to it, at the launch, and this row's
        # sealed counts are the tally of that file. It is created in a fresh
        # directory of its own outside the attempt, so no crash between here
        # and the finally can leave a file the sealer's closed roster refuses.
        # Reserved CreateNew in that fresh directory so a leftover from an
        # earlier run can never be read as this run's evidence.
        $journalRoot = Join-Path ([IO.Path]::GetTempPath()) (
            'fsring-c4-package-launches-' + [Guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($journalRoot)
        $journalPath = Join-Path $journalRoot $script:VerifierLaunchJournalName
        $journalStream = [IO.File]::Open(
            $journalPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        $journalStream.Dispose()

        $verifierArgs = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
            $verifierLease.Path,
            '-PackageDirectory', $output,
            '-InfVerifPath', $infverifLease.Path,
            '-SignToolPath', $signtoolLease.Path,
            '-LaunchJournalPath', $journalPath
        )
        $argv = @($powershellLease.Path) + $verifierArgs

        $markerRoster = @(
            [pscustomobject]@{ Role = 'powershell'; Lease = $powershellLease },
            [pscustomobject]@{ Role = 'infverif'; Lease = $infverifLease },
            [pscustomobject]@{ Role = 'signtool'; Lease = $signtoolLease }
        )
        Write-C4NestedToolMarker -Phase 'PRE' -Nonce $MarkerNonce -CommandId $CommandId -ToolLeases $markerRoster -LaunchCounts $null

        # 8. Rehash immediately before the call, and again immediately after,
        #    so a swap that only exists for the duration of the child is still
        #    visible at both endpoints.
        foreach ($entry in $markerRoster) { Assert-C4HeldFileLease $entry.Lease }
        Assert-C4HeldFileLease $verifierLease

        # This launch is this script's own, and it is noted here rather than
        # asserted later: the count that gets sealed has to come from the point
        # where something actually starts.
        [IO.File]::AppendAllText($journalPath, ($powershellLease.Path + [Environment]::NewLine))

        [void](& $Adapters.RunVerifier ([pscustomobject]@{
            Executable = $powershellLease.Path
            ArgumentList = $verifierArgs
            WorkingDirectory = $repoFull
            StdoutPath = $stdoutPath
            StderrPath = $stderrPath
            ExitPath = $exitPath
        }))

        foreach ($entry in $markerRoster) { Assert-C4HeldFileLease $entry.Lease }
        Assert-C4HeldFileLease $verifierLease

        foreach ($path in @($stdoutPath, $stderrPath, $exitPath)) {
            if (-not [IO.File]::Exists($path)) {
                throw ("package verifier capture is missing: {0}" -f [IO.Path]::GetFileName($path))
            }
        }
        $stdoutBytes = [IO.File]::ReadAllBytes($stdoutPath)
        $stderrBytes = [IO.File]::ReadAllBytes($stderrPath)
        $exitBytes = [IO.File]::ReadAllBytes($exitPath)

        $exitRecord = ConvertFrom-C4CanonicalJsonBytes -Bytes $exitBytes -ExpectedSchema 'fsring-captured-exit/v1'
        if ($exitRecord.termination -cne 'NORMAL') {
            throw ("package verifier terminated {0}, not NORMAL" -f $exitRecord.termination)
        }
        if ([int]$exitRecord.observedExit -ne 0) {
            throw ("package verifier exited {0}, not zero" -f $exitRecord.observedExit)
        }

        $report = Read-C4PackageVerifierReport $stdoutBytes
        $statuses = Get-C4PackageVerifierStatuses $report
        # The tally is read from the journal the launches wrote, then checked
        # against the closed oracle. Both halves matter: a launch nobody noted
        # would lower the tally, and an unexpected launch would raise it.
        $launchCounts = Get-C4PackageLaunchTally $journalPath $markerRoster
        Assert-C4PackageLaunchCounts $launchCounts
        foreach ($field in @('SemanticStatus', 'SignatureStatus', 'CatalogStatus')) {
            if ($statuses.$field -cne 'PASS') {
                throw ("package verifier {0} is {1}, not PASS" -f $field, $statuses.$field)
            }
        }

        Write-C4NestedToolMarker -Phase 'POST' -Nonce $MarkerNonce -CommandId $CommandId -ToolLeases $markerRoster -LaunchCounts $launchCounts

        $setSha256 = Get-C4PackageSetSha256 $memberRows
        $verifierRow = [ordered]@{
            schema = $script:PackageVerificationSchema
            scriptRelativePath = $script:VerifierScriptRelativePath
            scriptSha256 = $verifierLease.Sha256
            toolRole = 'powershell'
            toolSha256 = $powershellLease.Sha256
            argv = @($argv)
            exitCode = [int]$exitRecord.observedExit
            semanticStatus = $statuses.SemanticStatus
            profile = $profileRow.id
            machine = $machine
            packageRelativePath = $script:PackageRelativePath
            memberNames = @($script:PackageMemberNames)
            signatureStatus = $statuses.SignatureStatus
            catalogStatus = $statuses.CatalogStatus
            trustReady = $statuses.TrustReady
            stdout = $script:VerifierStdoutName
            stdoutBytes = [int64]$stdoutBytes.Length
            stdoutSha256 = (Get-C4EvidenceSha256Hex $stdoutBytes)
            stderr = $script:VerifierStderrName
            stderrBytes = [int64]$stderrBytes.Length
            stderrSha256 = (Get-C4EvidenceSha256Hex $stderrBytes)
            exit = $script:VerifierExitName
            exitBytes = [int64]$exitBytes.Length
            exitSha256 = (Get-C4EvidenceSha256Hex $exitBytes)
        }

        return [ordered]@{
            schema = $script:PackageCandidateSchema
            version = 1
            sourceCommit = $ExpectedSourceCommit
            sourceTree = $ExpectedSourceTree
            profile = $profileRow
            package = [ordered]@{
                relativePath = $script:PackageRelativePath
                setSha256 = $setSha256
                members = @($memberRows)
            }
            packageVerifier = $verifierRow
            status = 'PASS'
        }
    } finally {
        foreach ($lease in @($verifierLease, $powershellLease, $signtoolLease, $infverifLease)) {
            Close-C4HeldFileLease $lease
        }
        foreach ($member in $memberLeases) { Close-C4HeldFileLease $member.Lease }
        if ($null -ne $journalRoot) {
            Remove-Item -LiteralPath $journalRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------------
# Self-test
#
# The fixtures use a disposable build root, a generated stand-in verifier, and
# pinned source observations. They never touch the real WDK, the real package,
# or the repository. What is NOT faked is the parts under test: the roster
# read, the held leases, the CreateNew copy, the PE machine read, the real
# Invoke-C4EvidenceProcess capture of a real child, the report parse, and the
# closed launch-count oracle.
# ---------------------------------------------------------------------------

function New-C4PackageFakePeImage {
    param([uint16]$Machine = 0x8664, [switch]$BreakMzSignature)
    $bytes = New-Object byte[] 512
    if (-not $BreakMzSignature) {
        $bytes[0] = 0x4D
        $bytes[1] = 0x5A
    }
    [Array]::Copy([BitConverter]::GetBytes([int32]0x80), 0, $bytes, 0x3C, 4)
    $bytes[0x80] = 0x50
    $bytes[0x81] = 0x45
    [Array]::Copy([BitConverter]::GetBytes($Machine), 0, $bytes, 0x84, 2)
    return $bytes
}

function New-C4PackageFakeBuildRoot {
    param(
        [string]$Root,
        [uint16]$Machine = 0x8664,
        [switch]$BreakMzSignature,
        [string]$OmitMember,
        [string]$ExtraMember,
        [string]$ExtraDirectory
    )

    [void][IO.Directory]::CreateDirectory($Root)
    foreach ($name in $script:PackageMemberNames) {
        if ($OmitMember -and $name -ceq $OmitMember) { continue }
        $target = Join-Path $Root $name
        if ($name -ceq 'fsring_fsd.sys') {
            [IO.File]::WriteAllBytes(
                $target, (New-C4PackageFakePeImage -Machine $Machine -BreakMzSignature:$BreakMzSignature))
        } else {
            [IO.File]::WriteAllBytes(
                $target, ([Text.Encoding]::ASCII.GetBytes('fixture:' + $name + "`n")))
        }
    }
    if ($ExtraMember) {
        [IO.File]::WriteAllBytes(
            (Join-Path $Root $ExtraMember), ([Text.Encoding]::ASCII.GetBytes("extra`n")))
    }
    if ($ExtraDirectory) {
        [void][IO.Directory]::CreateDirectory((Join-Path $Root $ExtraDirectory))
    }
    return $Root
}

function New-C4PackageFakeReport {
    param(
        [string]$Overall = 'PASS',
        [int]$SysExit = 0,
        [int]$CatExit = 0,
        [int]$MemberExit = 0,
        [bool]$CatalogValid = $true,
        [bool]$TrustReady = $true,
        [switch]$OmitInfVerif,
        [switch]$OmitCatalogMemberExit,
        [switch]$OmitCatalogMembership,
        [string]$Schema = 'fsring-package-verifier/v1'
    )

    $tools = New-Object System.Collections.Specialized.OrderedDictionary
    if (-not $OmitInfVerif) {
        $tools['infverif'] = [ordered]@{ path = 'fixture'; exitCode = 0 }
    }
    $signtool = [ordered]@{ path = 'fixture'; sysExitCode = $SysExit; catExitCode = $CatExit }
    if (-not $OmitCatalogMemberExit) { $signtool['catalogMemberExitCode'] = $MemberExit }
    $tools['signtool'] = $signtool
    if (-not $OmitCatalogMembership) {
        $tools['catalogMembership'] = [ordered]@{ valid = $CatalogValid; memberHash = 'fixture' }
    }
    $report = [ordered]@{
        schema = $Schema
        overall = $Overall
        errors = @()
        warnings = @()
        trustReady = $TrustReady
        artifacts = [ordered]@{}
        tools = $tools
    }
    return ($report | ConvertTo-Json -Depth 8 -Compress)
}

# The stand-in verifier is a real child process launched through the real
# capture helper. `-SabotagePath` lets a fixture replace a frozen tool's bytes
# while the child owns the call, which is the only way to prove the endpoint
# rehash actually sees a midpoint swap.
function New-C4PackageFakeVerifierScript {
    param(
        [string]$Path,
        [string]$ReportJson,
        [int]$ExitCode = 0,
        [string]$SabotagePath,
        [switch]$EmitTwoLines,
        [switch]$EmitNothing,
        [int]$InfVerifLaunches = 1,
        [int]$SignToolLaunches = 6
    )

    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add('param([string]$PackageDirectory, [string]$InfVerifPath, [string]$SignToolPath, [string]$LaunchJournalPath)')
    [void]$lines.Add('$ErrorActionPreference = ''Stop''')
    # The fake notes the same launches the real verifier makes -- one InfVerif
    # and six SignTool probes -- because a fixture that writes a different
    # shape from the producer certifies the caller against a shape nobody
    # emits. `$LaunchCount` lets a case emit a wrong tally deliberately.
    [void]$lines.Add('if (-not [string]::IsNullOrWhiteSpace($LaunchJournalPath)) {')
    [void]$lines.Add(('    [IO.File]::AppendAllText($LaunchJournalPath, ($InfVerifPath + [Environment]::NewLine) * {0})' -f $InfVerifLaunches))
    [void]$lines.Add(('    [IO.File]::AppendAllText($LaunchJournalPath, ($SignToolPath + [Environment]::NewLine) * {0})' -f $SignToolLaunches))
    [void]$lines.Add('}')
    if ($SabotagePath) {
        [void]$lines.Add(
            ('[IO.File]::WriteAllBytes(''{0}'', [Text.Encoding]::ASCII.GetBytes("swapped`n"))' -f $SabotagePath))
    }
    if (-not $EmitNothing) {
        [void]$lines.Add(('Write-Output ''{0}''' -f $ReportJson.Replace("'", "''")))
        if ($EmitTwoLines) {
            [void]$lines.Add(('Write-Output ''{0}''' -f $ReportJson.Replace("'", "''")))
        }
    }
    [void]$lines.Add(('exit {0}' -f $ExitCode))
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [IO.File]::WriteAllBytes($Path, $utf8.GetBytes((($lines -join "`n") + "`n")))
    return $Path
}

function New-C4PackageSelfTestContext {
    param([string]$Root, [string]$Name)

    $case = Join-Path $Root $Name
    [void][IO.Directory]::CreateDirectory($case)
    $attempt = Join-Path $case 'attempt'
    [void][IO.Directory]::CreateDirectory($attempt)
    $tools = Join-Path $case 'tools'
    [void][IO.Directory]::CreateDirectory($tools)
    $infverif = Join-Path $tools 'infverif.exe'
    $signtool = Join-Path $tools 'signtool.exe'
    [IO.File]::WriteAllBytes($infverif, ([Text.Encoding]::ASCII.GetBytes("infverif-fixture`n")))
    [IO.File]::WriteAllBytes($signtool, ([Text.Encoding]::ASCII.GetBytes("signtool-fixture`n")))
    return [pscustomobject]@{
        CaseRoot = $case
        AttemptRoot = $attempt
        OutputDirectory = (Join-Path $attempt $script:PackageRelativeWindowsPath)
        BuildRoot = (Join-Path $case 'build')
        VerifierPath = (Join-Path $case 'fake_verifier.ps1')
        InfVerifPath = $infverif
        SignToolPath = $signtool
    }
}

function New-C4PackageFakeAdapters {
    param(
        $Context,
        [string]$Commit,
        [string]$Tree,
        [bool]$Dirty = $false
    )

    $commitValue = $Commit
    $treeValue = $Tree
    $dirtyValue = $Dirty
    return [pscustomobject]@{
        BuildRoot = $Context.BuildRoot
        VerifierScriptPath = $Context.VerifierPath
        HostPowerShellPath = ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
        ObserveSource = {
            param([string]$Root)
            [pscustomobject]@{ Commit = $commitValue; Tree = $treeValue; Dirty = $dirtyValue }
        }.GetNewClosure()
        RunVerifier = {
            param($Request)
            Invoke-C4EvidenceProcess `
                -Executable $Request.Executable `
                -Arguments $Request.ArgumentList `
                -WorkingDirectory $Request.WorkingDirectory `
                -TimeoutMilliseconds 120000 `
                -StdoutPath $Request.StdoutPath `
                -StderrPath $Request.StderrPath `
                -ExitPath $Request.ExitPath `
                -ExitFormat CanonicalJson
        }
    }
}

function Invoke-C4PackageSelfTests {
    $commit = '0123456789abcdef0123456789abcdef01234567'
    $tree = 'fedcba9876543210fedcba9876543210fedcba98'
    $root = Join-Path $env:TEMP ('fsring-c4-package-selftest-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($root)
    $repoRoot = Get-C4PackageRepositoryRoot
    $checks = New-Object System.Collections.ArrayList
    $failures = New-Object System.Collections.ArrayList

    # Each case builds its own disposable world, so no fixture can inherit
    # another's leftover bytes and pass for the wrong reason.
    function New-Case {
        param([string]$Name)
        $context = New-C4PackageSelfTestContext $root $Name
        [void](New-C4PackageFakeBuildRoot -Root $context.BuildRoot)
        [void](New-C4PackageFakeVerifierScript -Path $context.VerifierPath -ReportJson (New-C4PackageFakeReport))
        return $context
    }

    function Invoke-Case {
        param($Context, $Adapters, [hashtable]$Override = @{})
        $arguments = @{
            RepoRoot = $repoRoot
            OutputDirectory = $Context.OutputDirectory
            ExpectedSourceCommit = $commit
            ExpectedSourceTree = $tree
            ProfileId = 'win10-x64-release'
            InfVerifPath = $Context.InfVerifPath
            SignToolPath = $Context.SignToolPath
            Adapters = $Adapters
        }
        foreach ($key in @($Override.Keys)) { $arguments[$key] = $Override[$key] }
        return (Invoke-C4PackageCandidate @arguments)
    }

    # A refusal is only evidence when it is the refusal the fixture aimed at.
    # `-Expect` is mandatory: without it a fixture that fails during its own
    # setup -- a typo in a path, a missing stand-in -- would be indistinguishable
    # from the guard under test firing, and the whole suite could go green while
    # measuring nothing.
    function Assert-Refuses {
        param(
            [string]$Name,
            [string]$Expect,
            [scriptblock]$Action
        )
        [void]$checks.Add($Name)
        if ([string]::IsNullOrWhiteSpace($Expect)) {
            [void]$failures.Add(($Name + ': fixture declared no expected refusal'))
            return
        }
        try {
            # Discarded, not emitted. A case that stops refusing returns its
            # value into this suite's own pipeline, which corrupts the single
            # JSON line the harness is graded by -- so the suite loses its
            # voice exactly when it has something to say.
            [void](& $Action)
            [void]$failures.Add(($Name + ': accepted what it must refuse'))
        } catch {
            $message = [string]$_.Exception.Message
            if ($message.IndexOf($Expect, [StringComparison]::Ordinal) -lt 0) {
                [void]$failures.Add(
                    ($Name + ': refused for the wrong reason (' + $message + ')'))
            }
        }
    }

    function Assert-True {
        param([string]$Name, [bool]$Condition)
        [void]$checks.Add($Name)
        if (-not $Condition) { [void]$failures.Add(($Name + ': condition was false')) }
    }

    try {
        # --- anti-vacuity: the honest tuple must actually pass ---------------
        $baseline = New-Case 'baseline'
        $baselineAdapters = New-C4PackageFakeAdapters $baseline $commit $tree
        $result = Invoke-Case $baseline $baselineAdapters
        Assert-True 'baseline PASSes' ($result.status -ceq 'PASS')
        Assert-True 'baseline schema' ($result.schema -ceq $script:PackageCandidateSchema)
        Assert-True 'baseline profile machine' ($result.profile.machine -ceq '0x8664')
        Assert-True 'baseline member count' (@($result.package.members).Count -eq 6)
        Assert-True 'baseline member order' (
            @($result.package.members)[0].relativePath -ceq
                ($script:PackageRelativePath + '/fsring_fsd.inf') -and
            @($result.package.members)[5].relativePath -ceq
                ($script:PackageRelativePath + '/WDRLocalTestCert.cer'))
        Assert-True 'baseline verifier statuses' (
            $result.packageVerifier.semanticStatus -ceq 'PASS' -and
            $result.packageVerifier.signatureStatus -ceq 'PASS' -and
            $result.packageVerifier.catalogStatus -ceq 'PASS')
        Assert-True 'baseline verifier argv carries both frozen tools' (
            @($result.packageVerifier.argv) -ccontains $baseline.InfVerifPath -and
            @($result.packageVerifier.argv) -ccontains $baseline.SignToolPath)
        Assert-True 'baseline argv element zero is the frozen host' (
            @($result.packageVerifier.argv)[0] -ceq
                ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName))
        Assert-True 'baseline memberNames is the closed roster' (
            (@($result.packageVerifier.memberNames) -join ',') -ceq
                ($script:PackageMemberNames -join ','))
        Assert-True 'baseline auxiliary triplet exists' (
            [IO.File]::Exists((Join-Path $baseline.AttemptRoot $script:VerifierStdoutName)) -and
            [IO.File]::Exists((Join-Path $baseline.AttemptRoot $script:VerifierStderrName)) -and
            [IO.File]::Exists((Join-Path $baseline.AttemptRoot $script:VerifierExitName)))

        # Those three are also the ONLY files this call may leave at the
        # attempt root. The runner seals an attempt by matching every file it
        # finds there against a closed roster it alone owns, and it does that
        # only after the last row -- so a working file left behind here fails
        # the seal when all 38 rows have already passed, and the attempt
        # cannot be recorded even as a FAIL. Asked as `exactly these three`
        # rather than `not the journal`, so a stray nobody has thought of yet
        # is caught by the same check.
        $rootFiles = @([IO.Directory]::EnumerateFiles(
            $baseline.AttemptRoot, '*', [IO.SearchOption]::TopDirectoryOnly)) |
            ForEach-Object { [IO.Path]::GetFileName($_) } | Sort-Object
        Assert-True 'the attempt root holds exactly the auxiliary triplet' (
            (@($rootFiles) -join ',') -ceq ((@(
                $script:VerifierExitName,
                $script:VerifierStderrName,
                $script:VerifierStdoutName) | Sort-Object) -join ','))

        # The copy must be the source bytes, and the set hash must be a
        # function of those rows rather than of the directory listing order.
        $copiedSys = Get-C4PackageFileSha256 (Join-Path $baseline.OutputDirectory 'fsring_fsd.sys')
        $sourceSys = Get-C4PackageFileSha256 (Join-Path $baseline.BuildRoot 'fsring_fsd.sys')
        Assert-True 'copied .sys equals the build-root bytes' (
            $copiedSys.Sha256 -ceq $sourceSys.Sha256)
        Assert-True 'setSha256 is reproducible from the member rows' (
            (Get-C4PackageSetSha256 @($result.package.members)) -ceq $result.package.setSha256)
        Assert-True 'setSha256 is sensitive to a member hash' (
            (Get-C4PackageSetSha256 @(
                [ordered]@{ relativePath = 'x'; bytes = 1; sha256 = 'a' })) -cne
                    $result.package.setSha256)

        # The frozen manifest's row-21 argv reaches this script with forward
        # slashes after the expanded {attempt} prefix, so that exact form has to
        # be accepted -- and the refusals the strict comparison used to carry
        # have to keep firing.
        $slashCase = New-Case 'output-forward-slashes'
        $slashOutput = $slashCase.AttemptRoot + '/artifacts/win10-x64-release/package'
        $slashResult = Invoke-Case $slashCase (New-C4PackageFakeAdapters $slashCase $commit $tree) `
            @{ OutputDirectory = $slashOutput }
        Assert-True 'the manifest separator form is accepted' ($slashResult.status -ceq 'PASS')
        Assert-True 'the manifest separator form still writes the canonical path' (
            [IO.Directory]::Exists($slashCase.OutputDirectory))

        Assert-Refuses 'a doubled separator is still refused' 'is not canonical' {
            $case = New-Case 'output-doubled'
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree) `
                @{ OutputDirectory = ($case.AttemptRoot + '\\artifacts\win10-x64-release\package') }
        }
        Assert-Refuses 'a relative segment is still refused' 'relative segment' {
            $case = New-Case 'output-dotdot'
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree) `
                @{ OutputDirectory = ($case.AttemptRoot + '\x\..\' + $script:PackageRelativeWindowsPath) }
        }

        # --- profile and identity refusals ---------------------------------
        Assert-Refuses 'unknown profile' 'is not the closed win10-x64-release profile' {
            $case = New-Case 'profile-unknown'
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree) `
                @{ ProfileId = 'win10-arm64-release' }
        }
        Assert-Refuses 'uppercase expected commit' 'ExpectedSourceCommit must be exactly 40' {
            $case = New-Case 'commit-case'
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit.ToUpperInvariant() $tree) `
                @{ ExpectedSourceCommit = $commit.ToUpperInvariant() }
        }
        Assert-Refuses 'short expected tree' 'ExpectedSourceTree must be exactly 40' {
            $case = New-Case 'tree-short'
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit 'abc') `
                @{ ExpectedSourceTree = 'abc' }
        }
        Assert-Refuses 'dirty source tree' 'source tree is dirty' {
            $case = New-Case 'dirty'
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree $true)
        }
        Assert-Refuses 'source commit mismatch' 'source commit is' {
            $case = New-Case 'commit-drift'
            Invoke-Case $case (New-C4PackageFakeAdapters $case ('f' * 40) $tree)
        }
        Assert-Refuses 'source tree mismatch' 'source tree is' {
            $case = New-Case 'tree-drift'
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit ('e' * 40))
        }

        # --- destination refusals ------------------------------------------
        Assert-Refuses 'relative output directory' 'OutputDirectory must be absolute' {
            $case = New-Case 'output-relative'
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree) `
                @{ OutputDirectory = 'artifacts\win10-x64-release\package' }
        }
        Assert-Refuses 'existing output directory' 'OutputDirectory already exists' {
            $case = New-Case 'output-exists'
            [void][IO.Directory]::CreateDirectory($case.OutputDirectory)
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree)
        }
        Assert-Refuses 'wrong output directory suffix' 'OutputDirectory must end with' {
            $case = New-Case 'output-suffix'
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree) `
                @{ OutputDirectory = (Join-Path $case.AttemptRoot 'artifacts\win10-x64-release\pkg') }
        }
        Assert-Refuses 'absent attempt root' 'attempt root is not an existing directory' {
            $case = New-Case 'output-orphan'
            $orphan = Join-Path $case.CaseRoot ('missing\' + $script:PackageRelativeWindowsPath)
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree) `
                @{ OutputDirectory = $orphan }
        }
        Assert-Refuses 'output inside the repository' 'must not be written inside the repository' {
            $case = New-Case 'output-in-repo'
            $inside = Join-Path $repoRoot ('c4-selftest-scratch\' + $script:PackageRelativeWindowsPath)
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree) `
                @{ OutputDirectory = $inside }
        }

        # --- build-root roster refusals ------------------------------------
        Assert-Refuses 'build root missing a member' 'build root is missing package member' {
            $case = New-C4PackageSelfTestContext $root 'roster-missing'
            [void](New-C4PackageFakeBuildRoot -Root $case.BuildRoot -OmitMember 'fsring_fsd.cat')
            [void](New-C4PackageFakeVerifierScript -Path $case.VerifierPath -ReportJson (New-C4PackageFakeReport))
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree)
        }
        Assert-Refuses 'build root with an extra file' 'outside the closed roster' {
            $case = New-C4PackageSelfTestContext $root 'roster-extra'
            [void](New-C4PackageFakeBuildRoot -Root $case.BuildRoot -ExtraMember 'fsring_fsd.txt')
            [void](New-C4PackageFakeVerifierScript -Path $case.VerifierPath -ReportJson (New-C4PackageFakeReport))
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree)
        }
        Assert-Refuses 'build root with a subdirectory' 'unexpected subdirectory' {
            $case = New-C4PackageSelfTestContext $root 'roster-subdir'
            [void](New-C4PackageFakeBuildRoot -Root $case.BuildRoot -ExtraDirectory 'nested')
            [void](New-C4PackageFakeVerifierScript -Path $case.VerifierPath -ReportJson (New-C4PackageFakeReport))
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree)
        }
        Assert-Refuses 'absent build root' 'build root is not an existing directory' {
            $case = New-C4PackageSelfTestContext $root 'roster-absent'
            [void](New-C4PackageFakeVerifierScript -Path $case.VerifierPath -ReportJson (New-C4PackageFakeReport))
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree)
        }

        # --- packaged image refusals ---------------------------------------
        Assert-Refuses 'wrong PE machine' 'not the profile''s 0x8664' {
            $case = New-C4PackageSelfTestContext $root 'machine-arm64'
            [void](New-C4PackageFakeBuildRoot -Root $case.BuildRoot -Machine 0xAA64)
            [void](New-C4PackageFakeVerifierScript -Path $case.VerifierPath -ReportJson (New-C4PackageFakeReport))
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree)
        }
        Assert-Refuses 'packaged .sys is not an MZ image' 'not an MZ image' {
            $case = New-C4PackageSelfTestContext $root 'machine-nonmz'
            [void](New-C4PackageFakeBuildRoot -Root $case.BuildRoot -BreakMzSignature)
            [void](New-C4PackageFakeVerifierScript -Path $case.VerifierPath -ReportJson (New-C4PackageFakeReport))
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree)
        }

        # --- an untrusted signing root is not a failed signature ------------
        # This is the state of any host without the test certificate in its
        # trust stores, and it is what row 21 met: the verifier reports overall
        # PASS with zero errors, catalog membership valid, `trustReady` false,
        # and all three kernel-policy probes exiting nonzero because the root is
        # not trusted. Load-readiness is a Task 30 precondition, enforced there
        # as PACKAGE_NOT_TRUST_READY on the separately authorized host.
        #
        # Without this case the packager's 92 checks all described a host with
        # the certificate installed, which is why they passed on a machine where
        # the row could not.
        $untrusted = New-C4PackageSelfTestContext $root 'untrusted-root'
        [void](New-C4PackageFakeBuildRoot -Root $untrusted.BuildRoot)
        [void](New-C4PackageFakeVerifierScript -Path $untrusted.VerifierPath `
            -ReportJson (New-C4PackageFakeReport -SysExit 1 -CatExit 1 -MemberExit 1 -TrustReady $false))
        $untrustedResult = Invoke-Case $untrusted (New-C4PackageFakeAdapters $untrusted $commit $tree)
        Assert-True 'an untrusted root still PASSes the row' (
            $untrustedResult.status -ceq 'PASS')
        Assert-True 'an untrusted root is recorded as signature-valid' (
            $untrustedResult.packageVerifier.signatureStatus -ceq 'PASS')
        Assert-True 'an untrusted root is recorded as not trust-ready' (
            $untrustedResult.packageVerifier.trustReady -eq $false)
        # Anti-vacuity: the trust field must be capable of being true, or the
        # assertion above would hold for a field that is always false.
        Assert-True 'a trusted root is recorded as trust-ready' (
            $result.packageVerifier.trustReady -eq $true)

        # --- verifier-report refusals --------------------------------------
        # Each row names the refusal it must produce. Several of these differ
        # only in which field of the verifier's report was spoiled, so an
        # unqualified "it threw" would let one guard cover for another.
        $reportCases = @(
            @{ Name = 'verifier overall FAIL'; Expect = 'SemanticStatus is FAIL'; Report = (New-C4PackageFakeReport -Overall 'FAIL'); Exit = 0 },
            @{ Name = 'verifier nonzero exit'; Expect = 'package verifier exited 1'; Report = (New-C4PackageFakeReport); Exit = 1 },
            @{ Name = 'kernel-policy probes disagree on the sys'; Expect = 'SignatureStatus is FAIL'; Report = (New-C4PackageFakeReport -SysExit 1); Exit = 0 },
            @{ Name = 'kernel-policy probes disagree on the catalog member'; Expect = 'SignatureStatus is FAIL'; Report = (New-C4PackageFakeReport -MemberExit 2); Exit = 0 },
            @{ Name = 'uniform nonzero probes with a failed verifier verdict'; Expect = 'SemanticStatus is FAIL'; Report = (New-C4PackageFakeReport -Overall 'FAIL' -SysExit 1 -CatExit 1 -MemberExit 1 -TrustReady $false); Exit = 0 },
            @{ Name = 'catalog membership invalid'; Expect = 'CatalogStatus is FAIL'; Report = (New-C4PackageFakeReport -CatalogValid $false); Exit = 0 },
            @{ Name = 'catalog membership absent'; Expect = 'CatalogStatus is FAIL'; Report = (New-C4PackageFakeReport -OmitCatalogMembership); Exit = 0 },
            @{ Name = 'verifier report omits infverif'; Expect = 'report omits tools.infverif'; Report = (New-C4PackageFakeReport -OmitInfVerif); Exit = 0 },
            @{ Name = 'signtool exit codes are incomplete'; Expect = 'omits signtool.catalogMemberExitCode'; Report = (New-C4PackageFakeReport -OmitCatalogMemberExit); Exit = 0 },
            @{ Name = 'verifier wrong schema'; Expect = 'stdout schema is'; Report = (New-C4PackageFakeReport -Schema 'fsring-package-verifier/v2'); Exit = 0 }
        )
        foreach ($reportCase in $reportCases) {
            $name = [string]$reportCase.Name
            $expect = [string]$reportCase.Expect
            $json = [string]$reportCase.Report
            $exitCode = [int]$reportCase.Exit
            Assert-Refuses $name $expect {
                $case = New-C4PackageSelfTestContext $root ('report-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
                [void](New-C4PackageFakeBuildRoot -Root $case.BuildRoot)
                [void](New-C4PackageFakeVerifierScript -Path $case.VerifierPath -ReportJson $json -ExitCode $exitCode)
                Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree)
            }
        }
        # --- the coverage guard is itself exercised ------------------------
        $realVerifier = [IO.Path]::GetFullPath(
            (Join-Path $repoRoot ($script:VerifierScriptRelativePath -replace '/', '\\')))
        Assert-True 'the shipped verifier passes its launch coverage' (
            $null -eq (Assert-C4PackageVerifierLaunchCoverage $realVerifier))
        $verifierText = [IO.File]::ReadAllText($realVerifier)
        $coverageCases = @(
            @{ Name = 'an unnoted launch site is refused'; Expect = 'launches outside the noted choke point';
               Text = ($verifierText + "`n& $env:ComSpec /d /c echo hi`n") },
            @{ Name = 'a verifier that stopped noting launches is refused'; Expect = 'no longer notes its launches';
               Text = $verifierText.Replace('[IO.File]::AppendAllText($script:LaunchJournal, ($Path + [Environment]::NewLine))', '$null = $Path') },
            # Every one of these is invisible to the line scan -- no `&` with a
            # space anywhere -- and each one launches a native tool the tally
            # would then not count, leaving the sealed number agreeing with the
            # oracle while more launches were performed.
            @{ Name = 'a Start-Process launch is refused'; Expect = 'construct the line scan cannot see';
               Text = ($verifierText + "`n" + 'Start-Process -FilePath $Path -Wait' + "`n") },
            @{ Name = 'a [Diagnostics.Process]::Start launch is refused'; Expect = 'construct the line scan cannot see';
               Text = ($verifierText + "`n" + '$null = [Diagnostics.Process]::Start($Path)' + "`n") },
            @{ Name = 'a bare executable command word is refused'; Expect = 'construct the line scan cannot see';
               Text = ($verifierText + "`n" + 'signtool.exe verify /pa $Path' + "`n") },
            @{ Name = 'a second choke-point launch without a space is refused'; Expect = 'not exactly one';
               Text = ($verifierText + "`n" + '&$Path @Arguments' + "`n") },
            # A review demonstrated these passing the first AST pass. Three are
            # one-token respellings of the fixtures above, which is exactly the
            # shape a construct sweep is bad at, so each respelling is named.
            @{ Name = 'the Start-Process alias saps is refused'; Expect = 'construct the line scan cannot see';
               Text = ($verifierText + "`n" + 'saps -FilePath $Path -Wait' + "`n") },
            @{ Name = 'the Start-Process alias start is refused'; Expect = 'construct the line scan cannot see';
               Text = ($verifierText + "`n" + 'start $Path' + "`n") },
            @{ Name = 'an extensionless tool word is refused'; Expect = 'construct the line scan cannot see';
               Text = ($verifierText + "`n" + 'signtool verify /pa $Path' + "`n") },
            @{ Name = 'a cmd shell-out is refused'; Expect = 'construct the line scan cannot see';
               Text = ($verifierText + "`n" + 'cmd /c $Path' + "`n") },
            @{ Name = 'Invoke-Expression under its alias is refused'; Expect = 'construct the line scan cannot see';
               Text = ($verifierText + "`n" + 'iex $Path' + "`n") },
            @{ Name = 'a member name assembled at run time is refused'; Expect = 'construct the line scan cannot see';
               Text = ($verifierText + "`n" + '$null = [Diagnostics.Process]::(''St''+''art'')($Path)' + "`n") }
        )
        foreach ($coverageCase in $coverageCases) {
            $name = [string]$coverageCase.Name
            $expect = [string]$coverageCase.Expect
            $text = [string]$coverageCase.Text
            Assert-Refuses $name $expect {
                $doctored = Join-Path $root ('coverage-' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.ps1')
                [IO.File]::WriteAllText($doctored, $text)
                Assert-C4PackageVerifierLaunchCoverage $doctored
            }
        }

        # The launch counts are a tally of the journal, so the refusals that
        # matter are a tool that never ran and a tool that ran more often than
        # the closed oracle allows. Neither is expressible through the report's
        # shape, which is exactly why the old report-derived counts could seal
        # three signtool launches while six were performed.
        $launchCases = @(
            @{ Name = 'infverif never launched'; Expect = 'nested infverif launch count is 0'; InfVerif = 0; SignTool = 6 },
            @{ Name = 'signtool launched too few times'; Expect = 'nested signtool launch count is 3'; InfVerif = 1; SignTool = 3 },
            @{ Name = 'signtool launched too many times'; Expect = 'nested signtool launch count is 7'; InfVerif = 1; SignTool = 7 }
        )
        foreach ($launchCase in $launchCases) {
            $name = [string]$launchCase.Name
            $expect = [string]$launchCase.Expect
            $infCount = [int]$launchCase.InfVerif
            $signCount = [int]$launchCase.SignTool
            Assert-Refuses $name $expect {
                $case = New-C4PackageSelfTestContext $root ('launch-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
                [void](New-C4PackageFakeBuildRoot -Root $case.BuildRoot)
                [void](New-C4PackageFakeVerifierScript -Path $case.VerifierPath `
                    -ReportJson (New-C4PackageFakeReport) `
                    -InfVerifLaunches $infCount -SignToolLaunches $signCount)
                Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree)
            }
        }

        Assert-Refuses 'verifier emits two object lines' 'is not one object line' {
            $case = New-C4PackageSelfTestContext $root 'report-two-lines'
            [void](New-C4PackageFakeBuildRoot -Root $case.BuildRoot)
            [void](New-C4PackageFakeVerifierScript -Path $case.VerifierPath `
                -ReportJson (New-C4PackageFakeReport) -EmitTwoLines)
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree)
        }
        Assert-Refuses 'verifier emits no stdout' 'produced no stdout' {
            $case = New-C4PackageSelfTestContext $root 'report-silent'
            [void](New-C4PackageFakeBuildRoot -Root $case.BuildRoot)
            [void](New-C4PackageFakeVerifierScript -Path $case.VerifierPath `
                -ReportJson (New-C4PackageFakeReport) -EmitNothing)
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree)
        }

        # --- frozen tool refusals ------------------------------------------
        Assert-Refuses 'absent InfVerif path' 'InfVerifPath is not an existing file' {
            $case = New-Case 'tool-infverif-absent'
            [IO.File]::Delete($case.InfVerifPath)
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree)
        }
        Assert-Refuses 'absent SignTool path' 'SignToolPath is not an existing file' {
            $case = New-Case 'tool-signtool-absent'
            [IO.File]::Delete($case.SignToolPath)
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree)
        }
        Assert-Refuses 'relative InfVerif path' 'InfVerifPath must be absolute' {
            $case = New-Case 'tool-infverif-relative'
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree) `
                @{ InfVerifPath = 'infverif.exe' }
        }

        # A frozen tool cannot be substituted for the duration of the call: the
        # retained lease denies write and delete, so a child that tries to swap
        # SignTool under itself fails outright and the row never reaches PASS.
        Assert-Refuses 'child cannot swap the frozen SignTool it was handed' 'package verifier exited 1, not zero' {
            $case = New-C4PackageSelfTestContext $root 'tool-midpoint-swap'
            [void](New-C4PackageFakeBuildRoot -Root $case.BuildRoot)
            [void](New-C4PackageFakeVerifierScript -Path $case.VerifierPath `
                -ReportJson (New-C4PackageFakeReport) -SabotagePath $case.SignToolPath)
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree)
        }

        # The same denial, observed directly rather than through a child's exit
        # code, so a future change that let the write through would be reported
        # here as well as at the row level.
        Assert-Refuses 'a leased frozen tool rejects an in-process rewrite' 'used by another process' {
            $case = New-Case 'lease-deny-write'
            $lease = Open-C4PackageMeasuredLease $case.SignToolPath 'signtool'
            try {
                [IO.File]::WriteAllBytes($case.SignToolPath,
                    ([Text.Encoding]::ASCII.GetBytes("swapped`n")))
            } finally {
                Close-C4HeldFileLease $lease
            }
        }

        # A copy that does not land is caught by comparing the destination
        # bytes against the retained source handle. Without this seam the
        # comparison had nothing that could make it fail, so disabling it left
        # the suite green.
        Assert-Refuses 'a truncated destination copy is refused' 'drifted from its held source' {
            $case = New-Case 'copy-truncated'
            Invoke-Case $case (New-C4PackageFakeAdapters $case $commit $tree) `
                @{ FaultInjection = 'TruncateDestination' }
        }

        # --- nested-tool marker --------------------------------------------
        $markerCase = New-Case 'marker'
        $markerLeases = @(
            [pscustomobject]@{
                Role = 'signtool'
                Lease = (Open-C4PackageMeasuredLease $markerCase.SignToolPath 'signtool')
            }
        )
        try {
            $quiet = New-C4NestedToolMarkerText -Phase 'PRE' -Nonce '' -CommandId '21-x' `
                -ToolLeases $markerLeases -LaunchCounts $null
            Assert-True 'no nonce emits no marker' ($null -eq $quiet)
            $emitted = New-C4NestedToolMarkerText -Phase 'POST' -Nonce 'ABCD' -CommandId '21-x' `
                -ToolLeases $markerLeases -LaunchCounts $script:ExpectedNestedLaunchCounts
            Assert-True 'marker carries the sentinel' (
                $emitted.StartsWith($script:NestedToolMarkerSentinel, [StringComparison]::Ordinal))
            $markerJson = $emitted.Substring($script:NestedToolMarkerSentinel.Length) | ConvertFrom-Json
            Assert-True 'marker schema and nonce' (
                $markerJson.schema -ceq $script:NestedToolMarkerSchema -and
                $markerJson.nonce -ceq 'ABCD' -and $markerJson.phase -ceq 'POST')
            Assert-True 'marker records native identity' (
                $markerJson.tools[0].role -ceq 'signtool' -and
                $markerJson.tools[0].sha256 -ceq $markerLeases[0].Lease.Sha256 -and
                -not [string]::IsNullOrWhiteSpace($markerJson.tools[0].fileId))
            Assert-True 'marker carries the closed launch counts' (
                @($markerJson.launchCounts).Count -eq 3)
        } finally {
            foreach ($entry in $markerLeases) { Close-C4HeldFileLease $entry.Lease }
        }

        # --- launch-count oracle is independently sensitive ------------------
        foreach ($role in @('powershell', 'infverif', 'signtool')) {
            $mutatedRole = $role
            Assert-Refuses ('launch count oracle rejects a wrong ' + $role) 'launch count is' {
                $observed = [ordered]@{ powershell = 1; infverif = 1; signtool = 3 }
                $observed[$mutatedRole] = [int]$observed[$mutatedRole] + 1
                Assert-C4PackageLaunchCounts $observed
            }
        }
    } finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        $strays = Join-Path $repoRoot 'c4-selftest-scratch'
        if ([IO.Directory]::Exists($strays)) {
            Remove-Item -LiteralPath $strays -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    return [pscustomobject]@{
        Checks = @($checks)
        Failures = @($failures)
    }
}

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

if ($script:C4PackageDotSourced) { return }

$utf8Out = New-Object System.Text.UTF8Encoding $false
[Console]::OutputEncoding = $utf8Out

if ($SelfTest) {
    try {
        $outcome = Invoke-C4PackageSelfTests
    } catch {
        # A harness fault is not a fixture verdict, so print where it happened:
        # without the stack this reads like a refusal the suite intended.
        [Console]::Error.WriteLine('PACKAGE-CANDIDATE SELF-TEST: FAIL: ' + $_.Exception.Message)
        [Console]::Error.WriteLine($_.ScriptStackTrace)
        exit 1
    }
    $status = 'PASS'
    if (@($outcome.Failures).Count -ne 0) { $status = 'FAIL' }
    $object = [ordered]@{
        schema = $script:SelfTestSchema
        version = 1
        checks = [int]@($outcome.Checks).Count
        failures = @($outcome.Failures)
        status = $status
    }
    Write-C4PackageStdoutLine (ConvertTo-C4CanonicalJsonText $object)
    if ($status -ceq 'PASS') { exit 0 }
    exit 1
}

try {
    $repoRoot = Get-C4PackageRepositoryRoot
    $adapters = New-C4PackageProductionAdapters $repoRoot
    $nonce = $env:FSRING_C4_MARKER_NONCE
    $commandId = $env:FSRING_C4_COMMAND_ID
    $candidate = Invoke-C4PackageCandidate `
        -RepoRoot $repoRoot `
        -OutputDirectory $OutputDirectory `
        -ExpectedSourceCommit $ExpectedSourceCommit `
        -ExpectedSourceTree $ExpectedSourceTree `
        -ProfileId $Profile `
        -InfVerifPath $InfVerifPath `
        -SignToolPath $SignToolPath `
        -Adapters $adapters `
        -MarkerNonce $nonce `
        -CommandId $commandId
    Write-C4PackageStdoutLine (ConvertTo-C4CanonicalJsonText $candidate)
    exit 0
} catch {
    [Console]::Error.WriteLine('PACKAGE-CANDIDATE: FAIL: ' + $_.Exception.Message)
    exit 1
}
