[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Slice C1 generalized this script from "base + B5" to "base + one manifest per
# slice". The change is strictly stronger than the alternative, which was to let
# later slices add fixtures the script does not check: the exact-set property is
# kept, and every slice that adds a fixture must DECLARE it in its own manifest
# rather than be tolerated. B5's own guarantees are unchanged -- its 26 stems
# must still be present, paired, disjoint from the legacy base, and its manifest
# must still have exactly 26 sorted unique lines.
$immutableBase = '7f02833f20ed05a4f42016866b17bf12189cd00b'
$fixtureRelativePath = 'driver/tests/compile-fail'
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$fixtureDirectory = Join-Path $repositoryRoot $fixtureRelativePath

# name, file, frozen line count (0 = not frozen).
$sliceManifests = @(
    @{ Name = 'B5'; File = 'b5-manifest.txt'; FrozenCount = 26 }
    @{ Name = 'C1'; File = 'c1-manifest.txt'; FrozenCount = 4 }
    # 3 -> 6 in C2's second round: the clearance's forgeability, duplicability
    # and context lifetime each gained a fixture after review round 1 found the
    # token's claims outrunning the one fixture behind them. Rev 4 adds two
    # raw-sink boundary fixtures.
    @{ Name = 'C2'; File = 'c2-manifest.txt'; FrozenCount = 8 }
    # Task 12 closes the readiness/deposit and native-owner mint boundaries.
    @{ Name = 'C4'; File = 'c4-manifest.txt'; FrozenCount = 27 }
)

function Stop-ManifestVerification {
    param([Parameter(Mandatory)][string]$Message)

    Write-Error "COMPILE-FAIL MANIFEST: FAIL - $Message"
    exit 1
}

function Get-PathStems {
    param(
        [Parameter(Mandatory)][string[]]$Paths,
        [Parameter(Mandatory)][string]$Extension
    )

    @(
        $Paths |
            Where-Object { $_.EndsWith($Extension, [StringComparison]::Ordinal) } |
            ForEach-Object { [IO.Path]::GetFileNameWithoutExtension($_) } |
            Sort-Object -CaseSensitive -Unique
    )
}

function Assert-ExactStemSet {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string[]]$Actual,
        [Parameter(Mandatory)][string[]]$Expected
    )

    $missing = @($Expected | Where-Object { $_ -cnotin $Actual })
    $extra = @($Actual | Where-Object { $_ -cnotin $Expected })
    if ($missing.Count -ne 0 -or $extra.Count -ne 0) {
        $parts = @()
        if ($missing.Count -ne 0) {
            $parts += "missing: $($missing -join ', ')"
        }
        if ($extra.Count -ne 0) {
            $parts += "extra: $($extra -join ', ')"
        }
        Stop-ManifestVerification "$Label stems differ from the exact base-plus-slices union ($($parts -join '; '))"
    }
}

$declaredStems = @()
$manifestSummary = @()
foreach ($slice in $sliceManifests) {
    $manifestPath = Join-Path $fixtureDirectory $slice.File
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        Stop-ManifestVerification "missing manifest: $manifestPath"
    }

    $manifest = @(Get-Content -LiteralPath $manifestPath)
    if ($slice.FrozenCount -ne 0 -and $manifest.Count -ne $slice.FrozenCount) {
        Stop-ManifestVerification "$($slice.Name) manifest must contain exactly $($slice.FrozenCount) lines; found $($manifest.Count)"
    }

    for ($index = 0; $index -lt $manifest.Count; $index++) {
        $stem = $manifest[$index]
        if ($stem -cne $stem.Trim() -or $stem -cnotmatch '^[a-z0-9_]+$') {
            Stop-ManifestVerification "$($slice.Name) manifest line $($index + 1) is blank, commented, padded, or not a lower-case fixture stem"
        }
    }

    $duplicates = @(
        $manifest |
            Group-Object -CaseSensitive |
            Where-Object { $_.Count -ne 1 } |
            ForEach-Object Name
    )
    if ($duplicates.Count -ne 0) {
        Stop-ManifestVerification "$($slice.Name) manifest contains duplicate stems: $($duplicates -join ', ')"
    }

    $sortedManifest = @($manifest | Sort-Object -CaseSensitive)
    for ($index = 0; $index -lt $manifest.Count; $index++) {
        if ($manifest[$index] -cne $sortedManifest[$index]) {
            Stop-ManifestVerification "$($slice.Name) manifest is not sorted at line $($index + 1): expected '$($sortedManifest[$index])', found '$($manifest[$index])'"
        }
    }

    $collision = @($manifest | Where-Object { $_ -cin $declaredStems })
    if ($collision.Count -ne 0) {
        Stop-ManifestVerification "$($slice.Name) manifest re-declares stems another slice already owns: $($collision -join ', ')"
    }

    $declaredStems += $manifest
    $manifestSummary += ('{0} {1}' -f $manifest.Count, $slice.Name)
}

$basePaths = @(
    & git -C $repositoryRoot ls-tree -r --name-only $immutableBase -- $fixtureRelativePath
)
if ($LASTEXITCODE -ne 0) {
    Stop-ManifestVerification "git ls-tree failed for immutable base $immutableBase"
}

$legacyRsStems = @(Get-PathStems -Paths $basePaths -Extension '.rs')
$legacyExpectedStems = @(Get-PathStems -Paths $basePaths -Extension '.expected')
if ($legacyRsStems.Count -eq 0) {
    Stop-ManifestVerification "immutable base $immutableBase contains no legacy Rust fixtures"
}
Assert-ExactStemSet -Label 'immutable-base .expected' -Actual $legacyExpectedStems -Expected $legacyRsStems

$overlap = @($declaredStems | Where-Object { $_ -cin $legacyRsStems })
if ($overlap.Count -ne 0) {
    Stop-ManifestVerification "a slice manifest overlaps immutable legacy stems: $($overlap -join ', ')"
}

$expectedUnion = @(($legacyRsStems + $declaredStems) | Sort-Object -CaseSensitive -Unique)
if ($expectedUnion.Count -ne ($legacyRsStems.Count + $declaredStems.Count)) {
    Stop-ManifestVerification 'the base-plus-slices union is not disjoint'
}

$currentRsStems = @(
    Get-ChildItem -LiteralPath $fixtureDirectory -File -Filter '*.rs' |
        ForEach-Object BaseName |
        Sort-Object -CaseSensitive -Unique
)
$currentExpectedStems = @(
    Get-ChildItem -LiteralPath $fixtureDirectory -File -Filter '*.expected' |
        ForEach-Object BaseName |
        Sort-Object -CaseSensitive -Unique
)

foreach ($stem in $declaredStems) {
    $sourcePath = Join-Path $fixtureDirectory "$stem.rs"
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        Stop-ManifestVerification "declared fixture '$stem' is missing source: $sourcePath"
    }

    $expectedPath = Join-Path $fixtureDirectory "$stem.expected"
    if (-not (Test-Path -LiteralPath $expectedPath -PathType Leaf)) {
        Stop-ManifestVerification "declared fixture '$stem' is missing expected needles: $expectedPath"
    }

    $needles = @(
        Get-Content -LiteralPath $expectedPath |
            Where-Object { $_.Trim().Length -ne 0 }
    )
    if ($needles.Count -lt 2) {
        Stop-ManifestVerification "declared fixture '$stem' expected file must contain at least two nonempty needles; found $($needles.Count)"
    }
}

Assert-ExactStemSet -Label 'current .rs' -Actual $currentRsStems -Expected $expectedUnion
Assert-ExactStemSet -Label 'current .expected' -Actual $currentExpectedStems -Expected $expectedUnion

Write-Output (
    'COMPILE-FAIL MANIFEST: PASS ({0} legacy + {1} = {2} paired stems)' -f
        $legacyRsStems.Count,
        ($manifestSummary -join ' + '),
        $expectedUnion.Count
)
