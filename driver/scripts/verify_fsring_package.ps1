[CmdletBinding(DefaultParameterSetName = 'Package')]
param(
    [Parameter(ParameterSetName = 'Package', Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$PackageDirectory,

    [Parameter(ParameterSetName = 'SelfTest', Mandatory = $true)]
    [switch]$SelfTest,

    [string]$InfVerifPath,
    [string]$SignToolPath,
    # Where to note every native tool launch, one absolute executable path per
    # line, appended AT the launch. The caller tallies the file afterwards, so
    # the sealed launch counts are a measurement of what ran rather than a
    # number derived from the shape of this script's own report.
    [string]$LaunchJournalPath
)

Set-StrictMode -Version 2.0

# Declared before anything can read it: `Invoke-PackageTool` consults it on
# every launch, including from the self-test entry, and StrictMode makes an
# undeclared read a hard error rather than an empty string.
$script:LaunchJournal = ''
$ErrorActionPreference = 'Stop'

$Schema = 'fsring-package-verifier/v1'
$RequiredFiles = @('fsring_fsd.inf', 'fsring_fsd.sys', 'fsring_fsd.cat')

function New-Result {
    param([string]$Overall)
    [ordered]@{
        schema = $Schema
        overall = $Overall
        errors = New-Object System.Collections.ArrayList
        warnings = New-Object System.Collections.ArrayList
        trustReady = $false
        artifacts = [ordered]@{}
        tools = [ordered]@{}
    }
}

function Add-ResultError {
    param($Result, [string]$Message)
    [void]$Result.errors.Add($Message)
}

function Add-ResultWarning {
    param($Result, [string]$Message)
    [void]$Result.warnings.Add($Message)
}

function ConvertTo-InfValue {
    param([string]$Value)
    $value = $Value.Trim()
    if ($value.Length -ge 2 -and $value[0] -eq '"' -and $value[$value.Length - 1] -eq '"') {
        return $value.Substring(1, $value.Length - 2)
    }
    return $value
}

function Remove-InfComment {
    param([string]$Line)
    $quoted = $false
    for ($i = 0; $i -lt $Line.Length; $i++) {
        if ($Line[$i] -eq '"') { $quoted = -not $quoted }
        if (-not $quoted -and $Line[$i] -eq ';') { return $Line.Substring(0, $i) }
    }
    return $Line
}

function Parse-FsringInf {
    param([Parameter(Mandatory = $true)][string]$Text)

    $sections = New-Object System.Collections.ArrayList
    $current = $null
    $sourceLines = @($Text -split "`r?`n")
    for ($lineIndex = 0; $lineIndex -lt $sourceLines.Count; $lineIndex++) {
        $lineNumber = $lineIndex + 1
        $line = (Remove-InfComment $sourceLines[$lineIndex]).Trim()
        while ($line.EndsWith('\')) {
            if ($lineIndex + 1 -ge $sourceLines.Count) {
                throw "INF has unterminated INF line continuation at line $lineNumber."
            }
            $line = $line.Substring(0, $line.Length - 1)
            $lineIndex++
            $continued = (Remove-InfComment $sourceLines[$lineIndex]).Trim()
            $line = $line + $continued
        }
        if ($line.Length -eq 0) { continue }
        if ($line -match '^\[(?<name>[^\]]+)\]$') {
            $current = [pscustomobject]@{
                Name = $Matches.name.Trim()
                Directives = (New-Object System.Collections.ArrayList)
                BareValues = (New-Object System.Collections.ArrayList)
            }
            [void]$sections.Add($current)
            continue
        }
        if ($line.StartsWith('[') -or $line.EndsWith(']')) {
            throw "Malformed INF section header at line $lineNumber."
        }
        if ($null -eq $current) {
            throw "INF content appears before a section at line $lineNumber."
        }
        $equals = $line.IndexOf('=')
        if ($equals -ge 0) {
            if ([string]::IsNullOrWhiteSpace($line.Substring(0, $equals))) {
                throw "INF directive has an empty key at line $lineNumber."
            }
            [void]$current.Directives.Add([pscustomobject]@{
                Key = $line.Substring(0, $equals).Trim()
                Value = $line.Substring($equals + 1).Trim()
                Line = $lineNumber
            })
        } else {
            [void]$current.BareValues.Add([pscustomobject]@{ Value = $line; Line = $lineNumber })
        }
    }
    return [pscustomobject]@{ Sections = $sections }
}

function Get-InfSections {
    param($Inf, [string]$Name)
    return @($Inf.Sections | Where-Object { $_.Name -ieq $Name })
}

function Get-InfDirectiveValues {
    param($Section, [string]$Key)
    if ($null -eq $Section) { return @() }
    return @($Section.Directives | Where-Object { $_.Key -ieq $Key } | ForEach-Object { ConvertTo-InfValue $_.Value })
}

function Expand-InfStringValue {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][hashtable]$StringTable,
        [string[]]$Stack = @()
    )
    $expanded = $Value
    while ($true) {
        $token = @([regex]::Matches($expanded, '%(?<name>[^%]+)%') |
            Where-Object { $_.Groups['name'].Value -notmatch '^\d+$' } |
            Select-Object -First 1)
        if ($token.Count -eq 0) { return $expanded }
        $name = $token[0].Groups['name'].Value
        if (-not $StringTable.ContainsKey($name)) {
            throw ('INF has unresolved string substitution %{0}%.' -f $name)
        }
        if (@($Stack | Where-Object { $_ -ieq $name }).Count -gt 0) {
            throw ('INF has recursive string substitution: {0} -> {1}.' -f ($Stack -join ' -> '), $name)
        }
        $replacement = Expand-InfStringValue $StringTable[$name] $StringTable (@($Stack) + $name)
        $pattern = '(?i)' + [regex]::Escape($token[0].Value)
        $expanded = [regex]::Replace(
            $expanded,
            $pattern,
            [System.Text.RegularExpressions.MatchEvaluator]{ param($match) $replacement }
        )
    }
}

function Expand-FsringInf {
    param([Parameter(Mandatory = $true)]$Inf)

    $errors = New-Object System.Collections.ArrayList
    $stringsSections = @(Get-InfSections $Inf 'Strings')
    $stringTable = @{}
    foreach ($stringsSection in $stringsSections) {
        foreach ($directive in $stringsSection.Directives) {
            if ([string]::IsNullOrWhiteSpace($directive.Key)) {
                [void]$errors.Add(('INF [Strings] has an empty key at line {0}.' -f $directive.Line))
            } elseif ($stringTable.ContainsKey($directive.Key)) {
                [void]$errors.Add(('INF [Strings] defines duplicate key {0}.' -f $directive.Key))
            } else {
                $stringTable[$directive.Key] = ConvertTo-InfValue $directive.Value
            }
        }
    }
    foreach ($name in @($stringTable.Keys)) {
        try {
            $null = Expand-InfStringValue $stringTable[$name] $stringTable @($name)
        } catch {
            if (-not $errors.Contains($_.Exception.Message)) { [void]$errors.Add($_.Exception.Message) }
        }
    }

    $expandedSections = New-Object System.Collections.ArrayList
    foreach ($section in $Inf.Sections) {
        $expandedSection = [pscustomobject]@{
            Name = $section.Name
            Directives = (New-Object System.Collections.ArrayList)
            BareValues = (New-Object System.Collections.ArrayList)
        }
        foreach ($directive in $section.Directives) {
            try {
                $key = Expand-InfStringValue $directive.Key $stringTable
                $value = Expand-InfStringValue $directive.Value $stringTable
            } catch {
                if (-not $errors.Contains($_.Exception.Message)) { [void]$errors.Add($_.Exception.Message) }
                $key = $directive.Key
                $value = $directive.Value
            }
            [void]$expandedSection.Directives.Add([pscustomobject]@{
                Key = $key
                Value = $value
                Line = $directive.Line
            })
        }
        foreach ($bare in $section.BareValues) {
            try {
                $value = Expand-InfStringValue $bare.Value $stringTable
            } catch {
                if (-not $errors.Contains($_.Exception.Message)) { [void]$errors.Add($_.Exception.Message) }
                $value = $bare.Value
            }
            [void]$expandedSection.BareValues.Add([pscustomobject]@{ Value = $value; Line = $bare.Line })
        }
        [void]$expandedSections.Add($expandedSection)
    }
    return [pscustomobject]@{
        Inf = [pscustomobject]@{ Sections = $expandedSections }
        Errors = @($errors)
    }
}

function Get-PackageArchitectureSectionSuffix {
    param([Parameter(Mandatory = $true)][string]$SysPath)
    # FileShare.Read, not the 3-argument overload's implicit FileShare.None:
    # the native orchestrator holds its own read lease on this file.
    $stream = [System.IO.File]::Open(
        $SysPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $reader = New-Object System.IO.BinaryReader($stream)
        if ($stream.Length -lt 64) {
            throw ('SYS is too small for a DOS header (length {0}).' -f $stream.Length)
        }
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'SYS does not have an MZ header.' }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -lt 64 -or [uint64]$peOffset + 6 -gt [uint64]$stream.Length) {
            throw ('SYS PE header offset {0} is outside file length {1}.' -f $peOffset, $stream.Length)
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw 'SYS does not have a PE header.' }
        $machine = $reader.ReadUInt16()
        switch ($machine) {
            0x8664 { return 'NTamd64' }
            0xAA64 { return 'NTarm64' }
            default { throw ('SYS has unsupported PE machine 0x{0:X4}.' -f $machine) }
        }
    } finally {
        $stream.Dispose()
    }
}

function Test-FsringInfSemantics {
    param(
        [Parameter(Mandatory = $true)]$Inf,
        [Parameter(Mandatory = $true)][string]$ArchitectureSuffix
    )

    $errors = New-Object System.Collections.ArrayList
    $expansion = Expand-FsringInf $Inf
    $Inf = $expansion.Inf
    foreach ($expansionError in $expansion.Errors) { [void]$errors.Add($expansionError) }
    foreach ($sectionGroup in @($Inf.Sections | Group-Object { $_.Name.ToLowerInvariant() })) {
        if ($sectionGroup.Count -gt 1) {
            [void]$errors.Add(('INF contains duplicate INF section [{0}].' -f $sectionGroup.Group[0].Name))
        }
    }
    if (@(Get-InfSections $Inf 'Manufacturer').Count -gt 0) {
        [void]$errors.Add('INF contains prohibited [Manufacturer] PnP content.')
    }
    if (@($Inf.Sections | Where-Object { $_.Name -match '(?i)(^|\.)Models($|\.)' }).Count -gt 0) {
        [void]$errors.Add('INF contains prohibited [Models] PnP content.')
    }
    foreach ($section in @($Inf.Sections | Where-Object { $_.Name -ine 'Strings' })) {
        foreach ($entry in @($section.Directives) + @($section.BareValues)) {
            $content = if ($entry.PSObject.Properties.Name -contains 'Key') { $entry.Key + '=' + $entry.Value } else { $entry.Value }
            if ($content -match '(?i)\bROOT\\') {
                [void]$errors.Add(('INF contains prohibited root-enumerated hardware ID in [{0}] at line {1}.' -f $section.Name, $entry.Line))
            }
        }
    }

    $installName = 'DefaultInstall.' + $ArchitectureSuffix
    $installServicesName = $installName + '.Services'
    $uninstallName = 'DefaultUninstall.' + $ArchitectureSuffix
    $uninstallServicesName = $uninstallName + '.Services'
    $serviceSectionName = 'fsring_fsd_Service_Inst'

    $destinationSections = @(Get-InfSections $Inf 'DestinationDirs')
    if ($destinationSections.Count -eq 0) {
        [void]$errors.Add('INF [DestinationDirs] must contain exact Drivers_Dir=13.')
    } elseif ($destinationSections.Count -eq 1) {
        $destination = $destinationSections[0]
        $driverDestinations = @(Get-InfDirectiveValues $destination 'Drivers_Dir')
        if ($driverDestinations.Count -ne 1) {
            [void]$errors.Add(('INF [DestinationDirs] must contain exactly one Drivers_Dir=13 directive; found {0}.' -f $driverDestinations.Count))
        } elseif ($driverDestinations[0] -ine '13') {
            [void]$errors.Add(('INF [DestinationDirs] requires exact Drivers_Dir=13 with no subdirectory; found {0}.' -f $driverDestinations[0]))
        }
        if ($destination.Directives.Count -ne 1 -or $destination.BareValues.Count -ne 0) {
            [void]$errors.Add('INF [DestinationDirs] may contain only Drivers_Dir=13.')
        }
    }

    foreach ($decoratedSourceDiskSection in @($Inf.Sections | Where-Object {
        $_.Name -match '(?i)^SourceDisks(?:Names|Files)\..+$'
    })) {
        [void]$errors.Add(('INF contains prohibited decorated source-disk section [{0}].' -f $decoratedSourceDiskSection.Name))
    }

    $sourceNameSections = @(Get-InfSections $Inf 'SourceDisksNames')
    if ($sourceNameSections.Count -ne 1) {
        [void]$errors.Add(('INF must contain exactly one undecorated [SourceDisksNames] section with exact disk 1 mapping; found {0}.' -f $sourceNameSections.Count))
    } else {
        $sourceNames = $sourceNameSections[0]
        $diskOneNames = @(Get-InfDirectiveValues $sourceNames '1')
        if ($diskOneNames.Count -ne 1) {
            [void]$errors.Add(('INF [SourceDisksNames] must contain exactly one disk 1 mapping; found {0}.' -f $diskOneNames.Count))
        } elseif ($diskOneNames[0] -ine 'FSRING Driver Installation Disk') {
            if ($diskOneNames[0] -match ',') {
                [void]$errors.Add('INF [SourceDisksNames] disk 1 must have no cab, tag, or path.')
            } else {
                [void]$errors.Add(('INF [SourceDisksNames] disk 1 must be FSRING Driver Installation Disk; found {0}.' -f $diskOneNames[0]))
            }
        }
        if ($sourceNames.Directives.Count -ne 1 -or $sourceNames.BareValues.Count -ne 0) {
            [void]$errors.Add('INF [SourceDisksNames] may contain only disk 1.')
        }
    }

    $sourceFileSections = @(Get-InfSections $Inf 'SourceDisksFiles')
    if ($sourceFileSections.Count -ne 1) {
        [void]$errors.Add(('INF must contain exactly one undecorated [SourceDisksFiles] section with exact fsring_fsd.sys=1 mapping; found {0}.' -f $sourceFileSections.Count))
    } else {
        $sourceFiles = $sourceFileSections[0]
        $driverSources = @(Get-InfDirectiveValues $sourceFiles 'fsring_fsd.sys')
        if ($driverSources.Count -ne 1) {
            [void]$errors.Add(('INF [SourceDisksFiles] must contain exactly one fsring_fsd.sys=1 mapping; found {0}.' -f $driverSources.Count))
        } elseif ($driverSources[0] -ine '1') {
            if ($driverSources[0] -match ',') {
                [void]$errors.Add('INF [SourceDisksFiles] fsring_fsd.sys=1 must have no subdirectory.')
            } else {
                [void]$errors.Add(('INF [SourceDisksFiles] requires exact fsring_fsd.sys=1; found {0}.' -f $driverSources[0]))
            }
        }
        if ($sourceFiles.Directives.Count -ne 1 -or $sourceFiles.BareValues.Count -ne 0) {
            [void]$errors.Add('INF [SourceDisksFiles] may contain only fsring_fsd.sys=1.')
        }
    }

    $installSections = @(Get-InfSections $Inf $installName)
    if ($installSections.Count -eq 0) {
        [void]$errors.Add(('INF is missing required [{0}] section.' -f $installName))
    } elseif ($installSections.Count -eq 1) {
        $install = $installSections[0]
        $copyFiles = @(Get-InfDirectiveValues $install 'CopyFiles')
        if ($copyFiles.Count -ne 1) {
            [void]$errors.Add(('INF [{0}] must contain exactly one CopyFiles=Drivers_Dir directive; found {1}.' -f $installName, $copyFiles.Count))
        } elseif ($copyFiles[0] -ine 'Drivers_Dir') {
            [void]$errors.Add(('INF [{0}] requires exact CopyFiles=Drivers_Dir; found {1}.' -f $installName, $copyFiles[0]))
        }
        if ($install.Directives.Count -ne 1 -or $install.BareValues.Count -ne 0) {
            [void]$errors.Add(('INF [{0}] may contain only CopyFiles=Drivers_Dir.' -f $installName))
        }
    }

    $driverFileSections = @(Get-InfSections $Inf 'Drivers_Dir')
    if ($driverFileSections.Count -eq 0) {
        [void]$errors.Add('INF is missing required [Drivers_Dir] section.')
    } elseif ($driverFileSections.Count -eq 1) {
        $driverFiles = $driverFileSections[0]
        $bareDriverFiles = @($driverFiles.BareValues | ForEach-Object { ConvertTo-InfValue $_.Value })
        if ($bareDriverFiles.Count -ne 1 -or $bareDriverFiles[0] -ine 'fsring_fsd.sys') {
            [void]$errors.Add('INF [Drivers_Dir] must contain exactly one bare fsring_fsd.sys entry.')
        }
        if ($driverFiles.Directives.Count -ne 0) {
            [void]$errors.Add('INF [Drivers_Dir] may contain only the one bare fsring_fsd.sys entry.')
        }
    }

    $installServicesSections = @(Get-InfSections $Inf $installServicesName)
    if ($installServicesSections.Count -eq 0) {
        [void]$errors.Add(('INF is missing required [{0}] section.' -f $installServicesName))
    } elseif ($installServicesSections.Count -eq 1) {
        $installServices = $installServicesSections[0]
        $addService = @(Get-InfDirectiveValues $installServices 'AddService')
        $fsringAddService = @($addService | Where-Object { $_ -match '(?i)^\s*fsring_fsd\s*,' })
        $matchingAddService = @($addService | Where-Object { $_ -match '(?i)^\s*fsring_fsd\s*,\s*,\s*fsring_fsd_Service_Inst\s*$' })
        if ($addService.Count -ne 1) {
            [void]$errors.Add(('INF [{0}] must contain exactly one total AddService directive; found {1}.' -f $installServicesName, $addService.Count))
        }
        if ($fsringAddService.Count -ne 1) {
            [void]$errors.Add(('INF [{0}] must contain exactly one AddService for fsring_fsd; found {1}.' -f $installServicesName, $fsringAddService.Count))
        }
        if ($addService.Count -eq 1 -and $matchingAddService.Count -ne 1) {
            [void]$errors.Add(('INF [{0}] requires exact AddService=fsring_fsd,,fsring_fsd_Service_Inst.' -f $installServicesName))
        }
        if ($installServices.Directives.Count -ne 1 -or $installServices.BareValues.Count -ne 0) {
            [void]$errors.Add(('INF [{0}] may contain only the exact AddService=fsring_fsd,,fsring_fsd_Service_Inst directive.' -f $installServicesName))
        }
    }

    $uninstallSections = @(Get-InfSections $Inf $uninstallName)
    if ($uninstallSections.Count -eq 0) {
        [void]$errors.Add(('INF is missing required [{0}] section.' -f $uninstallName))
    } elseif ($uninstallSections.Count -eq 1) {
        $uninstall = $uninstallSections[0]
        $legacyUninstall = @(Get-InfDirectiveValues $uninstall 'LegacyUninstall')
        if ($legacyUninstall.Count -ne 1) {
            [void]$errors.Add(('INF [{0}] must contain exactly one LegacyUninstall=1 directive; found {1}.' -f $uninstallName, $legacyUninstall.Count))
        } elseif ($legacyUninstall[0] -ine '1') {
            [void]$errors.Add(('INF [{0}] requires exact LegacyUninstall=1; found {1}.' -f $uninstallName, $legacyUninstall[0]))
        }
        if ($uninstall.Directives.Count -ne 1 -or $uninstall.BareValues.Count -ne 0) {
            [void]$errors.Add(('INF [{0}] may contain only LegacyUninstall=1.' -f $uninstallName))
        }
    }

    $uninstallServicesSections = @(Get-InfSections $Inf $uninstallServicesName)
    if ($uninstallServicesSections.Count -eq 0) {
        [void]$errors.Add(('INF is missing required [{0}] section.' -f $uninstallServicesName))
    } elseif ($uninstallServicesSections.Count -eq 1) {
        $uninstallServices = $uninstallServicesSections[0]
        $delService = @(Get-InfDirectiveValues $uninstallServices 'DelService')
        $matchingDelService = @($delService | Where-Object { $_ -match '(?i)^\s*fsring_fsd\s*,\s*0x200\s*$' })
        if ($delService.Count -ne 1) {
            [void]$errors.Add(('INF [{0}] must contain exactly one DelService directive; found {1}.' -f $uninstallServicesName, $delService.Count))
        } elseif ($matchingDelService.Count -ne 1) {
            [void]$errors.Add(('INF [{0}] requires exact DelService=fsring_fsd,0x200.' -f $uninstallServicesName))
        }
        if ($uninstallServices.Directives.Count -ne 1 -or $uninstallServices.BareValues.Count -ne 0) {
            [void]$errors.Add(('INF [{0}] may contain only exact DelService=fsring_fsd,0x200.' -f $uninstallServicesName))
        }
    }

    $allAddService = @()
    $allDelService = @()
    $allLegacyUninstall = @()
    foreach ($section in $Inf.Sections) {
        foreach ($directive in $section.Directives) {
            if ($directive.Key -ieq 'AddService') { $allAddService += $directive }
            if ($directive.Key -ieq 'DelService') { $allDelService += $directive }
            if ($directive.Key -ieq 'LegacyUninstall') { $allLegacyUninstall += $directive }
            if ($directive.Key -ieq 'CopyFiles' -and $section.Name -ine $installName) {
                [void]$errors.Add(('INF contains additional CopyFiles mutation in [{0}] at line {1}.' -f $section.Name, $directive.Line))
            }
            if ($directive.Key -match '(?i)^(DelFiles|RenFiles|CopyINF)$') {
                [void]$errors.Add(('INF contains prohibited {0} mutation in [{1}] at line {2}.' -f $directive.Key, $section.Name, $directive.Line))
            }
        }
    }
    if ($allAddService.Count -ne 1) {
        [void]$errors.Add(('INF must contain exactly one AddService across the entire INF; found {0}.' -f $allAddService.Count))
    }
    if ($allDelService.Count -ne 1) {
        [void]$errors.Add(('INF must contain exactly one DelService across the entire INF; found {0}.' -f $allDelService.Count))
    }
    if ($allLegacyUninstall.Count -ne 1) {
        [void]$errors.Add(('INF must contain exactly one LegacyUninstall across the entire INF; found {0}.' -f $allLegacyUninstall.Count))
    }

    $serviceSections = @(Get-InfSections $Inf $serviceSectionName)
    if ($serviceSections.Count -ne 1) {
        [void]$errors.Add(('INF must contain exactly one service-install section [{0}]; found {1}.' -f $serviceSectionName, $serviceSections.Count))
    } else {
        $service = $serviceSections[0]
        $expected = [ordered]@{
            DisplayName = 'FSRING Filesystem Driver Service'
            ServiceType = '2'
            StartType = '3'
            ErrorControl = '1'
            LoadOrderGroup = 'File System'
            ServiceBinary = '%13%\fsring_fsd.sys'
        }
        foreach ($key in $expected.Keys) {
            $values = @(Get-InfDirectiveValues $service $key)
            if ($values.Count -ne 1) {
                [void]$errors.Add(('INF [{0}] must contain exactly one {1}={2}; found {3}.' -f $serviceSectionName, $key, $expected[$key], $values.Count))
            } elseif ($values[0] -ine $expected[$key]) {
                if ($key -ieq 'ServiceBinary') {
                    [void]$errors.Add(('INF [{0}] requires exact ServiceBinary=%13%\fsring_fsd.sys.' -f $serviceSectionName))
                } else {
                    [void]$errors.Add(('INF [{0}] requires {1}={2}; found {3}.' -f $serviceSectionName, $key, $expected[$key], $values[0]))
                }
            }
        }
        if ($service.Directives.Count -ne $expected.Count -or $service.BareValues.Count -ne 0) {
            [void]$errors.Add(('INF [{0}] contains an unknown or extra service-install directive.' -f $serviceSectionName))
        }
    }
    return @($errors)
}

function Test-PackageArtifacts {
    param([Parameter(Mandatory = $true)][string]$Directory)
    $errors = New-Object System.Collections.ArrayList
    $artifacts = [ordered]@{}
    foreach ($name in $RequiredFiles) {
        $path = Join-Path $Directory $name
        $present = Test-Path -LiteralPath $path -PathType Leaf
        $artifacts[$name] = $present
        if (-not $present) { [void]$errors.Add(('Package artifact is absent: {0}.' -f $name)) }
    }
    return [pscustomobject]@{ Errors = @($errors); Artifacts = $artifacts }
}

function Resolve-PackageTool {
    param(
        [string]$ProvidedPath,
        [string]$DefaultPath,
        [string]$Name,
        [string]$ExpectedOriginalFilename,
        [string]$ExpectedProductVersionPrefix
    )
    $candidate = if ([string]::IsNullOrWhiteSpace($ProvidedPath)) { $DefaultPath } else { $ProvidedPath }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw ('{0} was not found at explicit path: {1}' -f $Name, $candidate)
    }
    $path = (Resolve-Path -LiteralPath $candidate).Path
    $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
    if ($versionInfo.OriginalFilename -ine $ExpectedOriginalFilename) {
        throw ('{0} identity mismatch at {1}: expected OriginalFilename={2}, found {3}.' -f $Name, $path, $ExpectedOriginalFilename, $versionInfo.OriginalFilename)
    }
    if ([string]::IsNullOrWhiteSpace($versionInfo.ProductVersion) -or
        -not $versionInfo.ProductVersion.StartsWith($ExpectedProductVersionPrefix + '.', [StringComparison]::Ordinal)) {
        throw ('{0} version mismatch at {1}: expected {2}.x, found {3}.' -f $Name, $path, $ExpectedProductVersionPrefix, $versionInfo.ProductVersion)
    }
    return [pscustomobject]@{
        Path = $path
        ProductVersion = $versionInfo.ProductVersion
        FileVersion = $versionInfo.FileVersion
        OriginalFilename = $versionInfo.OriginalFilename
    }
}

function Invoke-PackageTool {
    param([string]$Path, [string[]]$Arguments, [string]$TargetPath)
    # Note the launch BEFORE it happens. A tool that starts and then crashes
    # still ran, and a count taken afterwards would lose it; this is also the
    # single choke point every native launch in this script goes through, which
    # is what makes the tally complete rather than merely plausible.
    if (-not [string]::IsNullOrWhiteSpace($script:LaunchJournal)) {
        [IO.File]::AppendAllText($script:LaunchJournal, ($Path + [Environment]::NewLine))
    }
    $savedErrorActionPreference = $ErrorActionPreference
    $rawOutput = @()
    $exitCode = $null
    try {
        # Native verification tools report expected trust failures on stderr.
        # Capture both streams without allowing the script-wide Stop policy to
        # turn a classifiable process result into NativeCommandError.
        $ErrorActionPreference = 'Continue'
        $rawOutput = @(& $Path @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    if ($null -eq $exitCode) {
        throw ('Native tool did not return a process exit code: {0}' -f $Path)
    }
    $output = New-Object System.Collections.ArrayList
    $errorOutput = New-Object System.Collections.ArrayList
    foreach ($record in $rawOutput) {
        if ($record -is [System.Management.Automation.ErrorRecord] -and
            [string]::IsNullOrWhiteSpace($record.Exception.Message) -and
            [string]::IsNullOrWhiteSpace([string]$record.TargetObject)) {
            continue
        }
        $text = [regex]::Replace($record.ToString(), '\s+', ' ').Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        if ($record -is [System.Management.Automation.ErrorRecord]) {
            [void]$errorOutput.Add($text)
            continue
        }
        [void]$output.Add($text)
    }
    # PowerShell may interleave stdout records between wrapped native stderr
    # records. Preserve each stream's order, then append stderr as one
    # normalized diagnostic so classification is deterministic.
    if ($errorOutput.Count -gt 0) { [void]$output.Add((@($errorOutput) -join ' ')) }
    return [pscustomobject]@{
        TargetPath = $TargetPath
        Arguments = @($Arguments)
        ExitCode = $exitCode
        Output = (@($output) -join "`n")
    }
}

function Initialize-CatalogNative {
    if ('FsringCatalogNative' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

public static class FsringCatalogNative
{
    [StructLayout(LayoutKind.Sequential)]
    private struct CryptAttrBlob
    {
        public uint cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptCatMember
    {
        public uint cbStruct;
        public IntPtr pwszReferenceTag;
        public IntPtr pwszFileName;
        public Guid gSubjectType;
        public uint fdwMemberFlags;
        public IntPtr pIndirectData;
        public uint dwCertVersion;
        public uint dwReserved;
        public IntPtr hReserved;
        public CryptAttrBlob sEncodedIndirectData;
        public CryptAttrBlob sEncodedMemberInfo;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CryptCATOpen(
        string fileName,
        uint openFlags,
        IntPtr provider,
        uint publicVersion,
        uint encodingType);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATClose(IntPtr catalog);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATEnumerateMember(IntPtr catalog, IntPtr previousMember);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr catalogAdmin,
        IntPtr subsystem,
        string hashAlgorithm,
        IntPtr strongHashPolicy,
        uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr catalogAdmin,
        IntPtr fileHandle,
        ref uint hashSize,
        byte[] hash,
        uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr catalogAdmin, uint flags);

    private static string CalculateHash(string filePath, string algorithm)
    {
        IntPtr admin;
        if (!CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptCATAdminAcquireContext2 failed for " + algorithm);
        try
        {
            using (FileStream stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                uint size = 0;
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, stream.SafeFileHandle.DangerousGetHandle(), ref size, null, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Catalog hash sizing failed for " + algorithm);
                byte[] hash = new byte[size];
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, stream.SafeFileHandle.DangerousGetHandle(), ref size, hash, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Catalog hash calculation failed for " + algorithm);
                return BitConverter.ToString(hash).Replace("-", "");
            }
        }
        finally
        {
            CryptCATAdminReleaseContext(admin, 0);
        }
    }

    public static string FindMemberHash(string sysPath, string catPath)
    {
        // Windows SDK mscat.h: CRYPTCAT_VERSION_1 is 0x100.
        const uint CryptCatVersion1 = 0x00000100;
        const uint Encoding = 0x00010001;
        IntPtr catalog = CryptCATOpen(catPath, 0, IntPtr.Zero, CryptCatVersion1, Encoding);
        if (catalog == IntPtr.Zero || catalog == new IntPtr(-1))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptCATOpen failed");
        try
        {
            HashSet<string> tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            IntPtr member = IntPtr.Zero;
            while ((member = CryptCATEnumerateMember(catalog, member)) != IntPtr.Zero)
            {
                CryptCatMember value = (CryptCatMember)Marshal.PtrToStructure(member, typeof(CryptCatMember));
                string tag = Marshal.PtrToStringUni(value.pwszReferenceTag);
                if (!String.IsNullOrWhiteSpace(tag))
                    tags.Add(tag);
            }
            foreach (string algorithm in new[] { "SHA256", "SHA1" })
            {
                string hash = CalculateHash(sysPath, algorithm);
                if (tags.Contains(hash))
                    return hash;
            }
            return null;
        }
        finally
        {
            CryptCATClose(catalog);
        }
    }
}
'@
}

function Test-WindowsCatalogMembership {
    param([string]$SysPath, [string]$CatPath)
    $resolvedSys = [System.IO.Path]::GetFullPath($SysPath)
    $resolvedCat = [System.IO.Path]::GetFullPath($CatPath)
    try {
        Initialize-CatalogNative
        $memberHash = [FsringCatalogNative]::FindMemberHash($resolvedSys, $resolvedCat)
        if ([string]::IsNullOrWhiteSpace($memberHash)) {
            return [pscustomobject]@{
                Valid = $false
                SysPath = $resolvedSys
                CatPath = $resolvedCat
                MemberHash = $null
                Error = 'Packaged SYS hash is absent from the exact catalog.'
            }
        }
        return [pscustomobject]@{
            Valid = $true
            SysPath = $resolvedSys
            CatPath = $resolvedCat
            MemberHash = $memberHash
            Error = $null
        }
    } catch {
        return [pscustomobject]@{
            Valid = $false
            SysPath = $resolvedSys
            CatPath = $resolvedCat
            MemberHash = $null
            Error = ('Windows catalog membership verification failed: ' + $_.Exception.Message)
        }
    }
}

function Test-SamePackagePath {
    param([string]$Left, [string]$Right)
    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) { return $false }
    try {
        return [string]::Equals(
            [System.IO.Path]::GetFullPath($Left).TrimEnd('\'),
            [System.IO.Path]::GetFullPath($Right).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        )
    } catch {
        return $false
    }
}

function Get-SignToolOutputLines {
    param([string]$Output)

    if ($null -eq $Output) { return }
    foreach ($line in [regex]::Split($Output, '\r\n|\n|\r')) {
        $normalizedLine = $line.Trim()
        if (-not [string]::IsNullOrWhiteSpace($normalizedLine)) {
            Write-Output $normalizedLine
        }
    }
}

function Test-SignToolLinePattern {
    param([string]$Line, [string]$Pattern)

    return [regex]::IsMatch(
        $Line,
        '\A(?:' + $Pattern + ')\z',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
}

function Test-SignToolLineGrammar {
    param(
        [string[]]$Lines,
        [string[]]$OrderedPatterns,
        [string[]]$UnorderedTailPatterns
    )

    $actualLines = @($Lines)
    $ordered = @($OrderedPatterns)
    $tailPatterns = @($UnorderedTailPatterns)
    if ($actualLines.Count -ne ($ordered.Count + $tailPatterns.Count)) {
        return $false
    }

    for ($index = 0; $index -lt $ordered.Count; $index++) {
        if (-not (Test-SignToolLinePattern $actualLines[$index] $ordered[$index])) {
            return $false
        }
    }

    $remainingTail = New-Object System.Collections.ArrayList
    for ($index = $ordered.Count; $index -lt $actualLines.Count; $index++) {
        [void]$remainingTail.Add($actualLines[$index])
    }
    foreach ($pattern in $tailPatterns) {
        $matchedIndex = -1
        for ($index = 0; $index -lt $remainingTail.Count; $index++) {
            if (Test-SignToolLinePattern ([string]$remainingTail[$index]) $pattern) {
                $matchedIndex = $index
                break
            }
        }
        if ($matchedIndex -lt 0) {
            return $false
        }
        $remainingTail.RemoveAt($matchedIndex)
    }
    return $remainingTail.Count -eq 0
}

function Get-SignToolPathLinePattern {
    param([string]$Prefix, [string]$Path)

    return (
        [regex]::Escape($Prefix) +
        '(?i:' + [regex]::Escape([System.IO.Path]::GetFullPath($Path)) + ')'
    )
}

function Get-SignToolTimestampChainPatterns {
    $dateToken = '(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?:0[1-9]|[12][0-9]|3[01]) (?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] [0-9]{4}'
    return @(
        [regex]::Escape('Signing Certificate Chain:')
        [regex]::Escape('Issued to: WDRLocalTestCert')
        [regex]::Escape('Issued by: WDRLocalTestCert')
        ([regex]::Escape('Expires: ') + $dateToken)
        [regex]::Escape('SHA1 hash: C3E805E2841D2C68790A7F4E8E93DB121EB0C046')
        ([regex]::Escape('The signature is timestamped: ') + $dateToken)
        [regex]::Escape('Timestamp Verified by:')
        [regex]::Escape('Issued to: DigiCert Assured ID Root CA')
        [regex]::Escape('Issued by: DigiCert Assured ID Root CA')
        ([regex]::Escape('Expires: ') + $dateToken)
        [regex]::Escape('SHA1 hash: 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43')
        [regex]::Escape('Issued to: DigiCert Trusted Root G4')
        [regex]::Escape('Issued by: DigiCert Assured ID Root CA')
        ([regex]::Escape('Expires: ') + $dateToken)
        [regex]::Escape('SHA1 hash: A99D5B79E9F1CDA59CDAB6373169D5353F5874C6')
        [regex]::Escape('Issued to: DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1')
        [regex]::Escape('Issued by: DigiCert Trusted Root G4')
        ([regex]::Escape('Expires: ') + $dateToken)
        [regex]::Escape('SHA1 hash: 07894D00FC194A17DB273AEB5CF8FACEF14423A4')
        # The responder leaf is the one block DigiCert rotates on its own
        # schedule -- the same package re-signed a day later carried
        # "Responder 2026 1" with a new thumbprint and expiry. Pinning it
        # literally broke every future re-signature over a certificate that
        # says nothing about our signer. What binds the chain is the issuing CA
        # on the next line, which stays exactly pinned, as do the timestamp
        # root, the cross certificate, and the WDRLocalTestCert signer above.
        ([regex]::Escape('Issued to: ') + '\S.*')
        [regex]::Escape('Issued by: DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1')
        ([regex]::Escape('Expires: ') + $dateToken)
        ([regex]::Escape('SHA1 hash: ') + '[0-9A-F]{40}')
    )
}

function Get-SignToolDirectUntrustedTailPatterns {
    $knownRootDiagnostic = 'SignTool Error: A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider.'
    return @(
        [regex]::Escape('Number of files successfully Verified: 0')
        [regex]::Escape('Number of warnings: 0')
        [regex]::Escape('Number of errors: 1')
        [regex]::Escape($knownRootDiagnostic)
    )
}

function Get-SignToolCatalogUntrustedTailPatterns {
    param([string]$SysPath)

    $knownRootDiagnostic = 'SignTool Error: A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider.'
    $combinedDiagnosticPattern = (
        [regex]::Escape($knownRootDiagnostic + ' SignTool Error: File not valid: ') +
        '(?i:' + [regex]::Escape([System.IO.Path]::GetFullPath($SysPath)) + ')'
    )
    return @(
        [regex]::Escape('Number of files successfully Verified: 0')
        [regex]::Escape('Number of warnings: 0')
        [regex]::Escape('Number of errors: 1')
        $combinedDiagnosticPattern
    )
}

# The kernel-mode policy refusal observed once WDRLocalTestCert is installed in
# LocalMachine\Root: chain building now succeeds, so SignTool stops reporting an
# untrusted root and reports that the root is not a Microsoft one. /kp can never
# accept a self-signed test root, so this sentence -- not exit 0 -- is the real
# terminal observation for a test-signed package on a prepared host.
function Get-SignToolMicrosoftRootDiagnostic {
    return 'SignTool Error: Signing Cert does not chain to a Microsoft Root Cert.'
}

# One fixed literal, exact-matched by smoke_driver.ps1's closed verifier-state
# partition. It names every measured fact behind trustReady=true and the exact
# condition the readiness gate must still enforce.
function Get-LocallyTrustedTestRootWarning {
    return 'WDRLocalTestCert C3E805E2841D2C68790A7F4E8E93DB121EB0C046 is installed in LocalMachine\Root and LocalMachine\TrustedPublisher and Authenticode policy verifies all three artifacts; the kernel-mode policy still refuses a non-Microsoft root, so this package is load-ready only while TESTSIGNING is active.'
}

function Get-SignToolDirectLocallyTrustedTailPatterns {
    return @(
        [regex]::Escape('Number of files successfully Verified: 0')
        [regex]::Escape('Number of warnings: 0')
        [regex]::Escape('Number of errors: 1')
        [regex]::Escape((Get-SignToolMicrosoftRootDiagnostic))
    )
}

function Get-SignToolCatalogLocallyTrustedTailPatterns {
    param([string]$SysPath)

    $combinedDiagnosticPattern = (
        [regex]::Escape((Get-SignToolMicrosoftRootDiagnostic) + ' SignTool Error: File not valid: ') +
        '(?i:' + [regex]::Escape([System.IO.Path]::GetFullPath($SysPath)) + ')'
    )
    return @(
        [regex]::Escape('Number of files successfully Verified: 0')
        [regex]::Escape('Number of warnings: 0')
        [regex]::Escape('Number of errors: 1')
        $combinedDiagnosticPattern
    )
}

function Test-SignToolDirectTrustedGrammar {
    param([string[]]$Lines, [string]$ExpectedPath)

    $patterns = @(
        (Get-SignToolPathLinePattern 'Verifying: ' $ExpectedPath)
        [regex]::Escape('Signature Index: 0 (Primary Signature)')
        (Get-SignToolPathLinePattern 'Successfully verified: ' $ExpectedPath)
        [regex]::Escape('Number of files successfully Verified: 1')
        [regex]::Escape('Number of warnings: 0')
        [regex]::Escape('Number of errors: 0')
    )
    return (Test-SignToolLineGrammar $Lines $patterns @())
}

function Test-SignToolCatalogTrustedGrammar {
    param([string[]]$Lines, [string]$SysPath, [string]$CatPath)

    $patterns = @(
        (Get-SignToolPathLinePattern 'Verifying: ' $SysPath)
        (Get-SignToolPathLinePattern 'File is signed in catalog: ' $CatPath)
        (Get-SignToolPathLinePattern 'Successfully verified: ' $SysPath)
        [regex]::Escape('Number of files successfully Verified: 1')
        [regex]::Escape('Number of warnings: 0')
        [regex]::Escape('Number of errors: 0')
    )
    return (Test-SignToolLineGrammar $Lines $patterns @())
}

function Test-SignToolDirectUntrustedMinimalGrammar {
    param([string[]]$Lines, [string]$ExpectedPath)

    $ordered = @(
        (Get-SignToolPathLinePattern 'Verifying: ' $ExpectedPath)
        [regex]::Escape('Signature Index: 0 (Primary Signature)')
        [regex]::Escape('Issued to: WDRLocalTestCert')
        [regex]::Escape('Issued by: WDRLocalTestCert')
    )
    return (Test-SignToolLineGrammar $Lines $ordered @(Get-SignToolDirectUntrustedTailPatterns))
}

function Test-SignToolCatalogUntrustedMinimalGrammar {
    param([string[]]$Lines, [string]$SysPath, [string]$CatPath)

    $ordered = @(
        (Get-SignToolPathLinePattern 'Verifying: ' $SysPath)
        (Get-SignToolPathLinePattern 'File is signed in catalog: ' $CatPath)
        [regex]::Escape('Issued to: WDRLocalTestCert')
        [regex]::Escape('Issued by: WDRLocalTestCert')
    )
    return (Test-SignToolLineGrammar $Lines $ordered @(Get-SignToolCatalogUntrustedTailPatterns $SysPath))
}

function Test-SignToolDirectUntrustedTimestampGrammar {
    param([string[]]$Lines, [string]$ExpectedPath)

    $ordered = @(
        (Get-SignToolPathLinePattern 'Verifying: ' $ExpectedPath)
        [regex]::Escape('Signature Index: 0 (Primary Signature)')
        ([regex]::Escape('Hash of file (sha256): ') + '[0-9A-F]{64}')
    ) + @(Get-SignToolTimestampChainPatterns)
    return (Test-SignToolLineGrammar $Lines $ordered @(Get-SignToolDirectUntrustedTailPatterns))
}

function Test-SignToolCatalogUntrustedTimestampGrammar {
    param([string[]]$Lines, [string]$SysPath, [string]$CatPath)

    $ordered = @(
        (Get-SignToolPathLinePattern 'Verifying: ' $SysPath)
        (Get-SignToolPathLinePattern 'File is signed in catalog: ' $CatPath)
        ([regex]::Escape('Hash of file (sha1): ') + '[0-9A-F]{40}')
    ) + @(Get-SignToolTimestampChainPatterns)
    return (Test-SignToolLineGrammar $Lines $ordered @(Get-SignToolCatalogUntrustedTailPatterns $SysPath))
}

function Test-SignToolDirectLocallyTrustedMinimalGrammar {
    param([string[]]$Lines, [string]$ExpectedPath)

    $ordered = @(
        (Get-SignToolPathLinePattern 'Verifying: ' $ExpectedPath)
        [regex]::Escape('Signature Index: 0 (Primary Signature)')
        [regex]::Escape('Issued to: WDRLocalTestCert')
        [regex]::Escape('Issued by: WDRLocalTestCert')
    )
    return (Test-SignToolLineGrammar $Lines $ordered @(Get-SignToolDirectLocallyTrustedTailPatterns))
}

function Test-SignToolDirectLocallyTrustedTimestampGrammar {
    param([string[]]$Lines, [string]$ExpectedPath)

    $ordered = @(
        (Get-SignToolPathLinePattern 'Verifying: ' $ExpectedPath)
        [regex]::Escape('Signature Index: 0 (Primary Signature)')
        ([regex]::Escape('Hash of file (sha256): ') + '[0-9A-F]{64}')
    ) + @(Get-SignToolTimestampChainPatterns)
    return (Test-SignToolLineGrammar $Lines $ordered @(Get-SignToolDirectLocallyTrustedTailPatterns))
}

function Test-SignToolCatalogLocallyTrustedMinimalGrammar {
    param([string[]]$Lines, [string]$SysPath, [string]$CatPath)

    $ordered = @(
        (Get-SignToolPathLinePattern 'Verifying: ' $SysPath)
        (Get-SignToolPathLinePattern 'File is signed in catalog: ' $CatPath)
        [regex]::Escape('Issued to: WDRLocalTestCert')
        [regex]::Escape('Issued by: WDRLocalTestCert')
    )
    return (Test-SignToolLineGrammar $Lines $ordered @(Get-SignToolCatalogLocallyTrustedTailPatterns $SysPath))
}

function Test-SignToolCatalogLocallyTrustedTimestampGrammar {
    param([string[]]$Lines, [string]$SysPath, [string]$CatPath)

    $ordered = @(
        (Get-SignToolPathLinePattern 'Verifying: ' $SysPath)
        (Get-SignToolPathLinePattern 'File is signed in catalog: ' $CatPath)
        ([regex]::Escape('Hash of file (sha1): ') + '[0-9A-F]{40}')
    ) + @(Get-SignToolTimestampChainPatterns)
    return (Test-SignToolLineGrammar $Lines $ordered @(Get-SignToolCatalogLocallyTrustedTailPatterns $SysPath))
}

# The Authenticode-policy corroboration grammars. They exist only to prove that
# the local chain really validates, so the sole remaining kernel-policy
# objection is the Microsoft-root rule. They are never accepted in place of a
# kernel-policy probe: Test-SignToolTargetEvidence still refuses /pa argv.
function Test-SignToolDirectTrustedTimestampGrammar {
    param([string[]]$Lines, [string]$ExpectedPath)

    $ordered = @(
        (Get-SignToolPathLinePattern 'Verifying: ' $ExpectedPath)
        [regex]::Escape('Signature Index: 0 (Primary Signature)')
        ([regex]::Escape('Hash of file (sha256): ') + '[0-9A-F]{64}')
    ) + @(Get-SignToolTimestampChainPatterns) + @(
        (Get-SignToolPathLinePattern 'Successfully verified: ' $ExpectedPath)
        [regex]::Escape('Number of files successfully Verified: 1')
        [regex]::Escape('Number of warnings: 0')
        [regex]::Escape('Number of errors: 0')
    )
    return (Test-SignToolLineGrammar $Lines $ordered @())
}

function Test-SignToolCatalogTrustedTimestampGrammar {
    param([string[]]$Lines, [string]$SysPath, [string]$CatPath)

    $ordered = @(
        (Get-SignToolPathLinePattern 'Verifying: ' $SysPath)
        (Get-SignToolPathLinePattern 'File is signed in catalog: ' $CatPath)
        ([regex]::Escape('Hash of file (sha1): ') + '[0-9A-F]{40}')
    ) + @(Get-SignToolTimestampChainPatterns) + @(
        (Get-SignToolPathLinePattern 'Successfully verified: ' $SysPath)
        [regex]::Escape('Number of files successfully Verified: 1')
        [regex]::Escape('Number of warnings: 0')
        [regex]::Escape('Number of errors: 0')
    )
    return (Test-SignToolLineGrammar $Lines $ordered @())
}

function Test-SignToolAuthenticodeTargetEvidence {
    param([string]$ExpectedPath, $Evidence)

    if ($null -eq $Evidence -or
        -not ($Evidence.PSObject.Properties.Name -contains 'TargetPath') -or
        -not ($Evidence.PSObject.Properties.Name -contains 'Arguments') -or
        -not ($Evidence.PSObject.Properties.Name -contains 'ExitCode') -or
        -not ($Evidence.PSObject.Properties.Name -contains 'Output') -or
        -not (Test-SamePackagePath $ExpectedPath $Evidence.TargetPath)) {
        return $false
    }
    $arguments = @($Evidence.Arguments)
    if ($arguments.Count -ne 4 -or
        -not [string]::Equals([string]$arguments[0], 'verify', [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string]$arguments[1], '/v', [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string]$arguments[2], '/pa', [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-SamePackagePath $ExpectedPath ([string]$arguments[3]))) {
        return $false
    }
    if ($null -eq $Evidence.Output -or $Evidence.ExitCode -ne 0) { return $false }
    $lines = @(Get-SignToolOutputLines $Evidence.Output)
    return (
        (Test-SignToolDirectTrustedGrammar $lines $ExpectedPath) -or
        (Test-SignToolDirectTrustedTimestampGrammar $lines $ExpectedPath)
    )
}

function Test-SignToolAuthenticodeCatalogMemberEvidence {
    param([string]$SysPath, [string]$CatPath, $Evidence)

    if ($null -eq $Evidence -or
        -not ($Evidence.PSObject.Properties.Name -contains 'TargetPath') -or
        -not ($Evidence.PSObject.Properties.Name -contains 'Arguments') -or
        -not ($Evidence.PSObject.Properties.Name -contains 'ExitCode') -or
        -not ($Evidence.PSObject.Properties.Name -contains 'Output') -or
        -not (Test-SamePackagePath $SysPath $Evidence.TargetPath)) {
        return $false
    }
    $arguments = @($Evidence.Arguments)
    if ($arguments.Count -ne 6 -or
        -not [string]::Equals([string]$arguments[0], 'verify', [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string]$arguments[1], '/v', [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string]$arguments[2], '/pa', [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string]$arguments[3], '/c', [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-SamePackagePath $CatPath ([string]$arguments[4])) -or
        -not (Test-SamePackagePath $SysPath ([string]$arguments[5]))) {
        return $false
    }
    if ($null -eq $Evidence.Output -or $Evidence.ExitCode -ne 0) { return $false }
    $lines = @(Get-SignToolOutputLines $Evidence.Output)
    return (
        (Test-SignToolCatalogTrustedGrammar $lines $SysPath $CatPath) -or
        (Test-SignToolCatalogTrustedTimestampGrammar $lines $SysPath $CatPath)
    )
}

# Reads the two machine stores that decide whether a test-signed driver package
# can install and load. A store that cannot be opened is an explicit invalid
# observation, never an assumed presence.
function Get-WDRLocalTestCertStoreEvidence {
    $thumbprint = 'C3E805E2841D2C68790A7F4E8E93DB121EB0C046'
    $evidence = [ordered]@{
        Valid = $false
        Thumbprint = $thumbprint
        RootStorePresent = $false
        TrustedPublisherPresent = $false
        Error = $null
    }
    try {
        foreach ($probe in @(
                [pscustomobject]@{ Path = 'Cert:\LocalMachine\Root'; Key = 'RootStorePresent' },
                [pscustomobject]@{ Path = 'Cert:\LocalMachine\TrustedPublisher'; Key = 'TrustedPublisherPresent' }
            )) {
            $present = $false
            foreach ($certificate in @(Get-ChildItem -Path $probe.Path -ErrorAction Stop)) {
                if ([string]$certificate.Thumbprint -ceq $thumbprint) { $present = $true }
            }
            $evidence[$probe.Key] = $present
        }
        $evidence.Valid = $true
    } catch {
        $evidence.Valid = $false
        $evidence.Error = $_.Exception.Message
    }
    return [pscustomobject]$evidence
}

# Load readiness for a locally trusted test root is a measured property, not an
# inference from one SignTool sentence: the exact signer certificate must be in
# both machine stores AND Authenticode policy must verify all three artifacts.
function Test-LocalTrustEvidence {
    param([string]$SysPath, [string]$CatPath, $LocalTrust)

    if ($null -eq $LocalTrust) {
        return [pscustomobject]@{ Valid = $false; Error = 'Locally trusted classification requires measured local trust evidence.' }
    }
    $names = @($LocalTrust.PSObject.Properties.Name)
    foreach ($required in @('Certificate', 'AuthenticodeSys', 'AuthenticodeCat', 'AuthenticodeCatalogMember')) {
        if ($names -notcontains $required) {
            return [pscustomobject]@{ Valid = $false; Error = 'Local trust evidence is missing a required observation.' }
        }
    }
    $certificate = $LocalTrust.Certificate
    if ($null -eq $certificate) {
        return [pscustomobject]@{ Valid = $false; Error = 'Local trust certificate evidence is absent.' }
    }
    $certificateNames = @($certificate.PSObject.Properties.Name)
    foreach ($required in @('Valid', 'Thumbprint', 'RootStorePresent', 'TrustedPublisherPresent', 'Error')) {
        if ($certificateNames -notcontains $required) {
            return [pscustomobject]@{ Valid = $false; Error = 'Local trust certificate evidence schema is invalid.' }
        }
    }
    if ($certificate.Valid -isnot [bool] -or -not $certificate.Valid -or
        -not [string]::IsNullOrWhiteSpace([string]$certificate.Error)) {
        return [pscustomobject]@{ Valid = $false; Error = 'Local trust certificate evidence is not valid.' }
    }
    if ([string]$certificate.Thumbprint -cne 'C3E805E2841D2C68790A7F4E8E93DB121EB0C046') {
        return [pscustomobject]@{ Valid = $false; Error = 'Local trust evidence names another signer certificate than WDRLocalTestCert.' }
    }
    if ($certificate.RootStorePresent -isnot [bool] -or -not $certificate.RootStorePresent) {
        return [pscustomobject]@{ Valid = $false; Error = 'WDRLocalTestCert is not installed in LocalMachine\Root.' }
    }
    if ($certificate.TrustedPublisherPresent -isnot [bool] -or -not $certificate.TrustedPublisherPresent) {
        return [pscustomobject]@{ Valid = $false; Error = 'WDRLocalTestCert is not installed in LocalMachine\TrustedPublisher.' }
    }
    if (-not (Test-SignToolAuthenticodeTargetEvidence $SysPath $LocalTrust.AuthenticodeSys)) {
        return [pscustomobject]@{ Valid = $false; Error = 'Authenticode-policy SYS corroboration did not match the closed trusted grammar.' }
    }
    if (-not (Test-SignToolAuthenticodeTargetEvidence $CatPath $LocalTrust.AuthenticodeCat)) {
        return [pscustomobject]@{ Valid = $false; Error = 'Authenticode-policy CAT corroboration did not match the closed trusted grammar.' }
    }
    if (-not (Test-SignToolAuthenticodeCatalogMemberEvidence $SysPath $CatPath $LocalTrust.AuthenticodeCatalogMember)) {
        return [pscustomobject]@{ Valid = $false; Error = 'Authenticode-policy catalog-member corroboration did not match the closed trusted grammar.' }
    }
    return [pscustomobject]@{ Valid = $true; Error = $null }
}

function Test-SignToolTargetEvidence {
    param([string]$ExpectedPath, $Evidence)

    if ($null -eq $Evidence -or
        -not ($Evidence.PSObject.Properties.Name -contains 'TargetPath') -or
        -not ($Evidence.PSObject.Properties.Name -contains 'Arguments') -or
        -not ($Evidence.PSObject.Properties.Name -contains 'ExitCode') -or
        -not ($Evidence.PSObject.Properties.Name -contains 'Output') -or
        -not (Test-SamePackagePath $ExpectedPath $Evidence.TargetPath)) {
        return [pscustomobject]@{ Valid = $false; Mode = $null; Error = 'SignTool evidence target does not match the resolved package artifact.' }
    }
    $arguments = @($Evidence.Arguments)
    if ($arguments.Count -ne 4 -or
        -not [string]::Equals([string]$arguments[0], 'verify', [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string]$arguments[1], '/v', [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string]$arguments[2], '/kp', [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-SamePackagePath $ExpectedPath ([string]$arguments[3]))) {
        return [pscustomobject]@{ Valid = $false; Mode = $null; Error = 'SignTool target probe did not use exact verify /v /kp arguments.' }
    }
    if ($null -eq $Evidence.Output) {
        return [pscustomobject]@{ Valid = $false; Mode = $null; Error = 'SignTool target probe returned no output.' }
    }

    $lines = @(Get-SignToolOutputLines $Evidence.Output)
    # Fail closed: a future SignTool output or signer-chain change requires an
    # explicit measured fixture and grammar update before it can be trusted.
    if ($Evidence.ExitCode -eq 0) {
        if (Test-SignToolDirectTrustedGrammar $lines $ExpectedPath) {
            return [pscustomobject]@{ Valid = $true; Mode = 'Trusted'; Error = $null }
        }
        return [pscustomobject]@{ Valid = $false; Mode = $null; Error = 'SignTool exit 0 did not match the closed direct Trusted grammar.' }
    }

    if ($Evidence.ExitCode -eq 1 -and
        ((Test-SignToolDirectUntrustedMinimalGrammar $lines $ExpectedPath) -or
         (Test-SignToolDirectUntrustedTimestampGrammar $lines $ExpectedPath))) {
        return [pscustomobject]@{ Valid = $true; Mode = 'UntrustedTestRoot'; Error = $null }
    }

    if ($Evidence.ExitCode -eq 1 -and
        ((Test-SignToolDirectLocallyTrustedMinimalGrammar $lines $ExpectedPath) -or
         (Test-SignToolDirectLocallyTrustedTimestampGrammar $lines $ExpectedPath))) {
        return [pscustomobject]@{ Valid = $true; Mode = 'TestSignedLocallyTrusted'; Error = $null }
    }
    return [pscustomobject]@{ Valid = $false; Mode = $null; Error = ('SignTool exit {0} did not match a closed direct signature grammar.' -f $Evidence.ExitCode) }
}

function Test-SignToolCatalogMemberEvidence {
    param(
        [string]$SysPath,
        [string]$CatPath,
        $Evidence,
        $CatalogMembership
    )

    if ($null -eq $Evidence -or
        -not ($Evidence.PSObject.Properties.Name -contains 'TargetPath') -or
        -not ($Evidence.PSObject.Properties.Name -contains 'Arguments') -or
        -not ($Evidence.PSObject.Properties.Name -contains 'ExitCode') -or
        -not ($Evidence.PSObject.Properties.Name -contains 'Output') -or
        -not (Test-SamePackagePath $SysPath $Evidence.TargetPath)) {
        return [pscustomobject]@{ Valid = $false; Mode = $null; Error = 'SignTool catalog-member evidence target does not match the resolved SYS.' }
    }
    $arguments = @($Evidence.Arguments)
    if ($arguments.Count -ne 6 -or
        -not [string]::Equals([string]$arguments[0], 'verify', [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string]$arguments[1], '/v', [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string]$arguments[2], '/kp', [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string]$arguments[3], '/c', [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-SamePackagePath $CatPath ([string]$arguments[4])) -or
        -not (Test-SamePackagePath $SysPath ([string]$arguments[5]))) {
        return [pscustomobject]@{ Valid = $false; Mode = $null; Error = 'SignTool catalog-member probe did not use exact verify /v /kp /c CAT SYS arguments.' }
    }
    if ($null -eq $Evidence.Output) {
        return [pscustomobject]@{ Valid = $false; Mode = $null; Error = 'SignTool catalog-member probe returned no output.' }
    }

    $lines = @(Get-SignToolOutputLines $Evidence.Output)
    if ($Evidence.ExitCode -eq 0) {
        if (Test-SignToolCatalogTrustedGrammar $lines $SysPath $CatPath) {
            return [pscustomobject]@{ Valid = $true; Mode = 'Trusted'; Error = $null }
        }
        return [pscustomobject]@{ Valid = $false; Mode = $null; Error = 'SignTool catalog-member exit 0 did not match the closed catalog-member Trusted grammar.' }
    }

    if ($null -eq $CatalogMembership -or
        -not ($CatalogMembership.PSObject.Properties.Name -contains 'Valid') -or
        -not $CatalogMembership.Valid -or
        -not (Test-SamePackagePath $SysPath $CatalogMembership.SysPath) -or
        -not (Test-SamePackagePath $CatPath $CatalogMembership.CatPath) -or
        [string]::IsNullOrWhiteSpace($CatalogMembership.MemberHash) -or
        -not [string]::IsNullOrWhiteSpace($CatalogMembership.Error)) {
        return [pscustomobject]@{ Valid = $false; Mode = $null; Error = 'Catalog-bound SignTool failure lacks valid independent CryptCAT membership.' }
    }

    if ($Evidence.ExitCode -eq 1 -and
        ((Test-SignToolCatalogUntrustedMinimalGrammar $lines $SysPath $CatPath) -or
         (Test-SignToolCatalogUntrustedTimestampGrammar $lines $SysPath $CatPath))) {
        return [pscustomobject]@{ Valid = $true; Mode = 'UntrustedTestRoot'; Error = $null }
    }

    if ($Evidence.ExitCode -eq 1 -and
        ((Test-SignToolCatalogLocallyTrustedMinimalGrammar $lines $SysPath $CatPath) -or
         (Test-SignToolCatalogLocallyTrustedTimestampGrammar $lines $SysPath $CatPath))) {
        return [pscustomobject]@{ Valid = $true; Mode = 'TestSignedLocallyTrusted'; Error = $null }
    }
    return [pscustomobject]@{ Valid = $false; Mode = $null; Error = ('SignTool catalog-member exit {0} did not match a closed catalog-member signature grammar.' -f $Evidence.ExitCode) }
}

function Test-SignatureEvidence {
    param(
        [string]$SysPath,
        [string]$CatPath,
        $SysKernel,
        $CatKernel,
        $CatalogMemberKernel,
        $CatalogMembership,
        $LocalTrust
    )
    if ($null -eq $CatalogMembership -or
        -not ($CatalogMembership.PSObject.Properties.Name -contains 'Valid') -or
        -not ($CatalogMembership.PSObject.Properties.Name -contains 'SysPath') -or
        -not ($CatalogMembership.PSObject.Properties.Name -contains 'CatPath') -or
        -not ($CatalogMembership.PSObject.Properties.Name -contains 'MemberHash') -or
        -not ($CatalogMembership.PSObject.Properties.Name -contains 'Error') -or
        -not $CatalogMembership.Valid -or
        -not (Test-SamePackagePath $SysPath $CatalogMembership.SysPath) -or
        -not (Test-SamePackagePath $CatPath $CatalogMembership.CatPath) -or
        [string]::IsNullOrWhiteSpace($CatalogMembership.MemberHash) -or
        -not [string]::IsNullOrWhiteSpace($CatalogMembership.Error)) {
        $membershipError = if ($null -ne $CatalogMembership -and -not [string]::IsNullOrWhiteSpace($CatalogMembership.Error)) { $CatalogMembership.Error } else { 'Catalog evidence is not bound to the exact SYS and CAT.' }
        return [pscustomobject]@{ Valid = $false; TrustReady = $false; SysMode = $null; CatMode = $null; CatalogMemberMode = $null; Warning = $null; Error = $membershipError }
    }
    $sysResult = Test-SignToolTargetEvidence $SysPath $SysKernel
    if (-not $sysResult.Valid) {
        return [pscustomobject]@{ Valid = $false; TrustReady = $false; SysMode = $sysResult.Mode; CatMode = $null; CatalogMemberMode = $null; Warning = $null; Error = ('SYS signature evidence failed: ' + $sysResult.Error) }
    }
    $catResult = Test-SignToolTargetEvidence $CatPath $CatKernel
    if (-not $catResult.Valid) {
        return [pscustomobject]@{ Valid = $false; TrustReady = $false; SysMode = $sysResult.Mode; CatMode = $catResult.Mode; CatalogMemberMode = $null; Warning = $null; Error = ('CAT signature evidence failed: ' + $catResult.Error) }
    }
    $catalogMemberResult = Test-SignToolCatalogMemberEvidence $SysPath $CatPath $CatalogMemberKernel $CatalogMembership
    if (-not $catalogMemberResult.Valid) {
        return [pscustomobject]@{ Valid = $false; TrustReady = $false; SysMode = $sysResult.Mode; CatMode = $catResult.Mode; CatalogMemberMode = $catalogMemberResult.Mode; Warning = $null; Error = ('Catalog-member signature evidence failed: ' + $catalogMemberResult.Error) }
    }
    if ($sysResult.Mode -ne $catResult.Mode -or $sysResult.Mode -ne $catalogMemberResult.Mode) {
        return [pscustomobject]@{ Valid = $false; TrustReady = $false; SysMode = $sysResult.Mode; CatMode = $catResult.Mode; CatalogMemberMode = $catalogMemberResult.Mode; Warning = $null; Error = 'The three kernel-policy probes have inconsistent trust outcomes.' }
    }
    if ($sysResult.Mode -eq 'Trusted') {
        return [pscustomobject]@{ Valid = $true; TrustReady = $true; SysMode = $sysResult.Mode; CatMode = $catResult.Mode; CatalogMemberMode = $catalogMemberResult.Mode; Warning = $null; Error = $null }
    }
    if ($sysResult.Mode -eq 'TestSignedLocallyTrusted') {
        $localTrustResult = Test-LocalTrustEvidence $SysPath $CatPath $LocalTrust
        if (-not $localTrustResult.Valid) {
            return [pscustomobject]@{ Valid = $false; TrustReady = $false; SysMode = $sysResult.Mode; CatMode = $catResult.Mode; CatalogMemberMode = $catalogMemberResult.Mode; Warning = $null; Error = $localTrustResult.Error }
        }
        return [pscustomobject]@{
            Valid = $true
            TrustReady = $true
            SysMode = $sysResult.Mode
            CatMode = $catResult.Mode
            CatalogMemberMode = $catalogMemberResult.Mode
            Warning = (Get-LocallyTrustedTestRootWarning)
            Error = $null
        }
    }
    return [pscustomobject]@{
        Valid = $true
        TrustReady = $false
        SysMode = $sysResult.Mode
        CatMode = $catResult.Mode
        CatalogMemberMode = $catalogMemberResult.Mode
        Warning = 'Exact catalog membership and WDRLocalTestCert signature integrity are present, but the signing root is not trusted locally; package is not load-ready.'
        Error = $null
    }
}

function ConvertTo-CompactJson { param($Object) return ($Object | ConvertTo-Json -Depth 8 -Compress) }

function Assert-SelfTest {
    param([bool]$Condition, [string]$Name)
    if (-not $Condition) { throw ('Self-test failed: ' + $Name) }
}

function Invoke-SelfTests {
    $validInf = @'
[Version]
Signature = "$WINDOWS NT$"
Class = "System"
ClassGuid = {4d36e97d-e325-11ce-bfc1-08002be10318}
Provider = %ProviderString%
PnpLockdown = 1
CatalogFile = fsring_fsd.cat

[DestinationDirs]
Drivers_Dir = 13

[SourceDisksNames]
1 = %DiskName%

[SourceDisksFiles]
fsring_fsd.sys = 1

[DefaultInstall.NTamd64]
CopyFiles = Drivers_Dir

[Drivers_Dir]
fsring_fsd.sys

[DefaultInstall.NTamd64.Services]
AddService = fsring_fsd,,fsring_fsd_Service_Inst

[DefaultUninstall.NTamd64]
LegacyUninstall = 1

[DefaultUninstall.NTamd64.Services]
DelService = fsring_fsd,0x200

[fsring_fsd_Service_Inst]
DisplayName = %ServiceDesc%
ServiceType = 2
StartType = 3
ErrorControl = 1
LoadOrderGroup = "File System"
ServiceBinary = %13%\fsring_fsd.sys

[Strings]
ProviderString = "FSRING"
DiskName = "FSRING Driver Installation Disk"
ServiceDesc = "FSRING Filesystem Driver Service"
'@
    $tests = New-Object System.Collections.ArrayList
    $parsed = Parse-FsringInf $validInf
    $validErrors = @(Test-FsringInfSemantics $parsed 'NTamd64')
    Assert-SelfTest ($validErrors.Count -eq 0) 'valid legacy filesystem INF is accepted'
    [void]$tests.Add('valid legacy filesystem INF')

    $exactInfCases = @(
        [pscustomobject]@{ Name = 'missing Drivers_Dir destination'; Text = ($validInf -replace "(?ms)\r?\n\[DestinationDirs\]\r?\nDrivers_Dir = 13\r?\n", ''); Expected = 'DestinationDirs.*Drivers_Dir=13' },
        [pscustomobject]@{ Name = 'duplicate Drivers_Dir destination'; Text = ($validInf -replace 'Drivers_Dir = 13', "Drivers_Dir = 13`nDrivers_Dir = 13"); Expected = 'DestinationDirs.*exactly one' },
        [pscustomobject]@{ Name = 'wrong Drivers_Dir destination'; Text = ($validInf -replace 'Drivers_Dir = 13', 'Drivers_Dir = 12'); Expected = 'Drivers_Dir=13' },
        [pscustomobject]@{ Name = 'Drivers_Dir destination subdirectory'; Text = ($validInf -replace 'Drivers_Dir = 13', 'Drivers_Dir = 13,subdir'); Expected = 'Drivers_Dir=13' },
        [pscustomobject]@{ Name = 'extra destination mapping'; Text = ($validInf -replace 'Drivers_Dir = 13', "Drivers_Dir = 13`nOther_Dir = 13"); Expected = 'DestinationDirs.*only Drivers_Dir=13' },
        [pscustomobject]@{ Name = 'missing install CopyFiles'; Text = ($validInf -replace 'CopyFiles = Drivers_Dir', ''); Expected = 'DefaultInstall\.NTamd64.*CopyFiles=Drivers_Dir' },
        [pscustomobject]@{ Name = 'duplicate install CopyFiles'; Text = ($validInf -replace 'CopyFiles = Drivers_Dir', "CopyFiles = Drivers_Dir`nCopyFiles = Drivers_Dir"); Expected = 'DefaultInstall\.NTamd64.*exactly one CopyFiles' },
        [pscustomobject]@{ Name = 'wrong install CopyFiles'; Text = ($validInf -replace 'CopyFiles = Drivers_Dir', 'CopyFiles = Other_Dir'); Expected = 'CopyFiles=Drivers_Dir' },
        [pscustomobject]@{ Name = 'missing Drivers_Dir section'; Text = ($validInf -replace "(?ms)\r?\n\[Drivers_Dir\]\r?\nfsring_fsd\.sys\r?\n", ''); Expected = 'missing required \[Drivers_Dir\]' },
        [pscustomobject]@{ Name = 'duplicate Drivers_Dir file'; Text = ($validInf -replace "(?m)^fsring_fsd\.sys$", "fsring_fsd.sys`nfsring_fsd.sys"); Expected = 'Drivers_Dir.*exactly one bare fsring_fsd\.sys' },
        [pscustomobject]@{ Name = 'wrong Drivers_Dir file'; Text = ($validInf -replace "(?m)^fsring_fsd\.sys$", 'other.sys'); Expected = 'Drivers_Dir.*exactly one bare fsring_fsd\.sys' },
        [pscustomobject]@{ Name = 'extra Drivers_Dir file'; Text = ($validInf -replace "(?m)^fsring_fsd\.sys$", "fsring_fsd.sys`nother.sys"); Expected = 'Drivers_Dir.*exactly one bare fsring_fsd\.sys' },
        [pscustomobject]@{ Name = 'directive in Drivers_Dir'; Text = ($validInf -replace "(?m)^fsring_fsd\.sys$", 'fsring_fsd.sys = 1'); Expected = 'Drivers_Dir.*only.*bare' },
        [pscustomobject]@{ Name = 'missing source disk name mapping'; Text = ($validInf -replace "(?ms)\r?\n\[SourceDisksNames\]\r?\n1 = %DiskName%\r?\n", ''); Expected = 'SourceDisksNames.*disk 1' },
        [pscustomobject]@{ Name = 'wrong source disk name'; Text = ($validInf -replace '1 = %DiskName%', '1 = Other Disk'); Expected = 'SourceDisksNames.*FSRING Driver Installation Disk' },
        [pscustomobject]@{ Name = 'source disk cab tag'; Text = ($validInf -replace '1 = %DiskName%', '1 = %DiskName%,tag.cab'); Expected = 'SourceDisksNames.*no cab, tag, or path' },
        [pscustomobject]@{ Name = 'duplicate source disk name mapping'; Text = ($validInf -replace '1 = %DiskName%', "1 = %DiskName%`n1 = %DiskName%"); Expected = 'SourceDisksNames.*exactly one' },
        [pscustomobject]@{ Name = 'extra source disk name mapping'; Text = ($validInf -replace '1 = %DiskName%', "1 = %DiskName%`n2 = Other Disk"); Expected = 'SourceDisksNames.*only disk 1' },
        [pscustomobject]@{ Name = 'missing source disk file mapping'; Text = ($validInf -replace "(?ms)\r?\n\[SourceDisksFiles\]\r?\nfsring_fsd\.sys = 1\r?\n", ''); Expected = 'SourceDisksFiles.*fsring_fsd\.sys=1' },
        [pscustomobject]@{ Name = 'wrong source disk ID'; Text = ($validInf -replace 'fsring_fsd\.sys = 1', 'fsring_fsd.sys = 2'); Expected = 'SourceDisksFiles.*fsring_fsd\.sys=1' },
        [pscustomobject]@{ Name = 'source disk file subdirectory'; Text = ($validInf -replace 'fsring_fsd\.sys = 1', 'fsring_fsd.sys = 1,subdir'); Expected = 'SourceDisksFiles.*no subdirectory' },
        [pscustomobject]@{ Name = 'duplicate source disk file mapping'; Text = ($validInf -replace 'fsring_fsd\.sys = 1', "fsring_fsd.sys = 1`nfsring_fsd.sys = 1"); Expected = 'SourceDisksFiles.*exactly one' },
        [pscustomobject]@{ Name = 'extra source disk file mapping'; Text = ($validInf -replace 'fsring_fsd\.sys = 1', "fsring_fsd.sys = 1`nother.sys = 1"); Expected = 'SourceDisksFiles.*only fsring_fsd\.sys=1' },
        [pscustomobject]@{ Name = 'decorated amd64 source disk name override'; Text = ($validInf + "`n[SourceDisksNames.amd64]`n1 = Alternate Driver Disk,,,amd64"); Expected = 'prohibited decorated source-disk section \[SourceDisksNames\.amd64\]' },
        [pscustomobject]@{ Name = 'decorated amd64 source disk file override'; Text = ($validInf + "`n[SourceDisksFiles.amd64]`nfsring_fsd.sys = 1,amd64"); Expected = 'prohibited decorated source-disk section \[SourceDisksFiles\.amd64\]' },
        [pscustomobject]@{ Name = 'decorated arm64 source disk name override'; Text = ($validInf + "`n[SourceDisksNames.arm64]`n1 = Alternate Driver Disk,,,arm64"); Expected = 'prohibited decorated source-disk section \[SourceDisksNames\.arm64\]' },
        [pscustomobject]@{ Name = 'decorated arm64 source disk file override'; Text = ($validInf + "`n[SourceDisksFiles.arm64]`nfsring_fsd.sys = 2,arm64"); Expected = 'prohibited decorated source-disk section \[SourceDisksFiles\.arm64\]' },
        [pscustomobject]@{ Name = 'case-variant decorated source disk name override'; Text = ($validInf + "`n[sOuRcEdIsKsNaMeS.AmD64]`n1 = Alternate Driver Disk,,,case-variant"); Expected = 'prohibited decorated source-disk section \[sOuRcEdIsKsNaMeS\.AmD64\]' },
        [pscustomobject]@{ Name = 'case-variant decorated source disk file override'; Text = ($validInf + "`n[sOuRcEdIsKsFiLeS.ArM64]`nfsring_fsd.sys = 1,case-variant"); Expected = 'prohibited decorated source-disk section \[sOuRcEdIsKsFiLeS\.ArM64\]' },
        [pscustomobject]@{ Name = 'empty decorated source disk name sibling'; Text = ($validInf + "`n[SourceDisksNames.empty]"); Expected = 'prohibited decorated source-disk section \[SourceDisksNames\.empty\]' },
        [pscustomobject]@{ Name = 'empty decorated source disk file sibling'; Text = ($validInf + "`n[SourceDisksFiles.empty]"); Expected = 'prohibited decorated source-disk section \[SourceDisksFiles\.empty\]' },
        [pscustomobject]@{ Name = 'missing AddService'; Text = ($validInf -replace 'AddService = fsring_fsd,,fsring_fsd_Service_Inst', ''); Expected = 'DefaultInstall\.NTamd64\.Services.*exactly one AddService' },
        [pscustomobject]@{ Name = 'AddService flags'; Text = ($validInf -replace 'AddService = fsring_fsd,,fsring_fsd_Service_Inst', 'AddService = fsring_fsd,0x2,fsring_fsd_Service_Inst'); Expected = 'exact AddService=fsring_fsd,,fsring_fsd_Service_Inst' },
        [pscustomobject]@{ Name = 'AddService target'; Text = ($validInf -replace 'AddService = fsring_fsd,,fsring_fsd_Service_Inst', 'AddService = fsring_fsd,,Other_Service_Inst'); Expected = 'exact AddService=fsring_fsd,,fsring_fsd_Service_Inst' },
        [pscustomobject]@{ Name = 'missing decorated uninstall'; Text = ($validInf -replace "(?ms)\r?\n\[DefaultUninstall\.NTamd64\]\r?\nLegacyUninstall = 1\r?\n", ''); Expected = 'missing required \[DefaultUninstall\.NTamd64\]' },
        [pscustomobject]@{ Name = 'missing LegacyUninstall'; Text = ($validInf -replace 'LegacyUninstall = 1', ''); Expected = 'DefaultUninstall\.NTamd64.*LegacyUninstall=1' },
        [pscustomobject]@{ Name = 'wrong LegacyUninstall'; Text = ($validInf -replace 'LegacyUninstall = 1', 'LegacyUninstall = 0'); Expected = 'LegacyUninstall=1' },
        [pscustomobject]@{ Name = 'duplicate LegacyUninstall'; Text = ($validInf -replace 'LegacyUninstall = 1', "LegacyUninstall = 1`nLegacyUninstall = 1"); Expected = 'exactly one LegacyUninstall' },
        [pscustomobject]@{ Name = 'missing decorated uninstall Services'; Text = ($validInf -replace "(?ms)\r?\n\[DefaultUninstall\.NTamd64\.Services\]\r?\nDelService = fsring_fsd,0x200\r?\n", ''); Expected = 'missing required \[DefaultUninstall\.NTamd64\.Services\]' },
        [pscustomobject]@{ Name = 'missing DelService'; Text = ($validInf -replace 'DelService = fsring_fsd,0x200', ''); Expected = 'DefaultUninstall\.NTamd64\.Services.*exactly one DelService' },
        [pscustomobject]@{ Name = 'wrong DelService name'; Text = ($validInf -replace 'DelService = fsring_fsd,0x200', 'DelService = other,0x200'); Expected = 'exact DelService=fsring_fsd,0x200' },
        [pscustomobject]@{ Name = 'wrong DelService flag'; Text = ($validInf -replace 'DelService = fsring_fsd,0x200', 'DelService = fsring_fsd,0'); Expected = 'exact DelService=fsring_fsd,0x200' },
        [pscustomobject]@{ Name = 'duplicate DelService'; Text = ($validInf -replace 'DelService = fsring_fsd,0x200', "DelService = fsring_fsd,0x200`nDelService = fsring_fsd,0x200"); Expected = 'exactly one DelService across the entire INF' },
        [pscustomobject]@{ Name = 'foreign CopyFiles mutation'; Text = ($validInf + "`n[ForeignInstall]`nCopyFiles = Drivers_Dir"); Expected = 'additional CopyFiles mutation' },
        [pscustomobject]@{ Name = 'foreign DelFiles mutation'; Text = ($validInf + "`n[ForeignInstall]`nDelFiles = Drivers_Dir"); Expected = 'prohibited DelFiles mutation' },
        [pscustomobject]@{ Name = 'foreign AddService mutation'; Text = ($validInf + "`n[ForeignInstall.Services]`nAddService = other,,Other_Service_Inst"); Expected = 'exactly one AddService across the entire INF' },
        [pscustomobject]@{ Name = 'foreign DelService mutation'; Text = ($validInf + "`n[ForeignUninstall.Services]`nDelService = other,0x200"); Expected = 'exactly one DelService across the entire INF' }
    )
    foreach ($case in $exactInfCases) {
        $caseErrors = @(Test-FsringInfSemantics (Parse-FsringInf $case.Text) 'NTamd64')
        Assert-SelfTest (@($caseErrors | Where-Object { $_ -match $case.Expected }).Count -gt 0) ('reject ' + $case.Name)
        [void]$tests.Add('reject ' + $case.Name)
    }

    foreach ($field in @('DisplayName', 'ServiceType', 'StartType', 'ErrorControl', 'LoadOrderGroup', 'ServiceBinary')) {
        $line = @($validInf -split "`r?`n" | Where-Object { $_ -match ('^' + [regex]::Escape($field) + '\s*=') })[0]
        $duplicateField = Parse-FsringInf ($validInf -replace ('(?m)^' + [regex]::Escape($line) + '$'), ($line + "`n" + $line))
        $fieldErrors = @(Test-FsringInfSemantics $duplicateField 'NTamd64')
        Assert-SelfTest (@($fieldErrors | Where-Object { $_ -match ('exactly one ' + [regex]::Escape($field)) }).Count -gt 0) ('reject duplicate service-install ' + $field)
        [void]$tests.Add('reject duplicate service-install ' + $field)
    }

    $manufacturer = Parse-FsringInf ($validInf + "`n[Manufacturer]`n%M%=Models`n[Models]`n%Name%=Install,ROOT\fsring_fsd")
    Assert-SelfTest (@(Test-FsringInfSemantics $manufacturer 'NTamd64' | Where-Object { $_ -match 'Manufacturer|Models|root-enumerated' }).Count -eq 3) 'PnP Manufacturer/Models/root content is rejected'
    [void]$tests.Add('reject PnP Manufacturer/Models/root content')

    $badService = Parse-FsringInf ($validInf -replace 'ServiceType = 2', 'ServiceType = 1')
    Assert-SelfTest (@(Test-FsringInfSemantics $badService 'NTamd64' | Where-Object { $_ -match 'ServiceType=2; found 1' }).Count -eq 1) 'ServiceType=1 is rejected'
    [void]$tests.Add('reject ServiceType=1')

    $uncBinary = Parse-FsringInf ($validInf -replace '%13%\\fsring_fsd\.sys', '\\server\share\fsring_fsd.sys')
    Assert-SelfTest (@(Test-FsringInfSemantics $uncBinary 'NTamd64' | Where-Object { $_ -match 'exact ServiceBinary=%13%\\fsring_fsd\.sys' }).Count -eq 1) 'UNC ServiceBinary suffix is rejected'
    [void]$tests.Add('reject non-package ServiceBinary suffix')

    $stringsRoot = Parse-FsringInf ($validInf + "`n[DeviceModels]`n%Device%=Install,%RootId%`n[Strings]`nDevice=FsRing`nPrefix=RO`nSuffix=OT\fsring_fsd`nRootId=%Prefix%%Suffix%")
    Assert-SelfTest (@(Test-FsringInfSemantics $stringsRoot 'NTamd64' | Where-Object { $_ -match 'root-enumerated' }).Count -eq 1) 'Strings expansion cannot hide a root hardware ID'
    [void]$tests.Add('expand Strings before root-PnP checks')

    $unresolvedStrings = Parse-FsringInf ($validInf -replace '%13%\\fsring_fsd\.sys', '%MissingDestination%')
    Assert-SelfTest (@(Test-FsringInfSemantics $unresolvedStrings 'NTamd64' | Where-Object { $_ -match 'unresolved string substitution %MissingDestination%' }).Count -eq 1) 'unresolved Strings substitution is rejected'
    [void]$tests.Add('reject unresolved Strings substitution')

    $recursiveStrings = Parse-FsringInf ($validInf + "`n[Strings]`nFirst=%Second%`nSecond=%First%")
    Assert-SelfTest (@(Test-FsringInfSemantics $recursiveStrings 'NTamd64' | Where-Object { $_ -match 'recursive string substitution' }).Count -gt 0) 'recursive Strings substitution is rejected'
    [void]$tests.Add('reject recursive Strings substitution')

    $duplicateInstall = Parse-FsringInf ($validInf + "`n[defaultinstall.ntamd64]`nCopyFiles=Other")
    Assert-SelfTest (@(Test-FsringInfSemantics $duplicateInstall 'NTamd64' | Where-Object { $_ -match 'duplicate INF section \[DefaultInstall.NTamd64\]' }).Count -eq 1) 'duplicate decorated install section is rejected'
    [void]$tests.Add('reject duplicate decorated section')

    $duplicateAddService = Parse-FsringInf ($validInf -replace 'AddService = fsring_fsd,,fsring_fsd_Service_Inst', "AddService = fsring_fsd,,fsring_fsd_Service_Inst`nAddService = fsring_fsd,,other_Service_Inst")
    Assert-SelfTest (@(Test-FsringInfSemantics $duplicateAddService 'NTamd64' | Where-Object { $_ -match 'exactly one AddService for fsring_fsd; found 2' }).Count -eq 1) 'multiple matching AddService entries are rejected'
    [void]$tests.Add('reject multiple matching AddService entries')

    $extraAddService = Parse-FsringInf ($validInf -replace 'AddService = fsring_fsd,,fsring_fsd_Service_Inst', "AddService = fsring_fsd,,fsring_fsd_Service_Inst`nAddService = unrelated,,unrelated_Service_Inst")
    Assert-SelfTest (@(Test-FsringInfSemantics $extraAddService 'NTamd64' | Where-Object { $_ -match 'exactly one total AddService directive; found 2' }).Count -eq 1) 'extra non-fsring AddService entry is rejected'
    [void]$tests.Add('reject extra non-fsring AddService entry')

    $duplicateServiceTarget = Parse-FsringInf ($validInf + "`n[FSRING_FSD_SERVICE_INST]`nServiceType=2`nStartType=3`nErrorControl=1`nLoadOrderGroup=File System`nServiceBinary=%13%\fsring_fsd.sys")
    Assert-SelfTest (@(Test-FsringInfSemantics $duplicateServiceTarget 'NTamd64' | Where-Object { $_ -match 'exactly one service-install section .* found 2' }).Count -eq 1) 'duplicate service-install target is rejected'
    [void]$tests.Add('reject duplicate service-install target')

    $continuedInf = Parse-FsringInf ($validInf -replace 'AddService = fsring_fsd,,fsring_fsd_Service_Inst', "AddService = fsring_fsd,,\`n    fsring_fsd_Service_Inst")
    Assert-SelfTest (@(Test-FsringInfSemantics $continuedInf 'NTamd64').Count -eq 0) 'valid continued AddService directive is parsed'
    [void]$tests.Add('parse continued relevant directive')

    $malformedContinuationRejected = $false
    try {
        $null = Parse-FsringInf ($validInf + "`nAddService = fsring_fsd,,\")
    } catch {
        $malformedContinuationRejected = $_.Exception.Message -match 'unterminated INF line continuation'
    }
    Assert-SelfTest $malformedContinuationRejected 'unterminated relevant continuation has a stable diagnostic'
    [void]$tests.Add('reject unterminated continuation')

    $malformedSectionRejected = $false
    try {
        $null = Parse-FsringInf ($validInf + "`n[BrokenSection")
    } catch {
        $malformedSectionRejected = $_.Exception.Message -match 'malformed INF section header'
    }
    Assert-SelfTest $malformedSectionRejected 'malformed relevant section header has a stable diagnostic'
    [void]$tests.Add('reject malformed section header')

    $peFixture = Join-Path ([System.IO.Path]::GetTempPath()) ('fsring-pe-selftest-' + [Guid]::NewGuid().ToString('N') + '.sys')
    try {
        $peBytes = New-Object byte[] 64
        $peBytes[0] = 0x4d
        $peBytes[1] = 0x5a
        [Array]::Copy([BitConverter]::GetBytes([uint32]4096), 0, $peBytes, 0x3c, 4)
        [System.IO.File]::WriteAllBytes($peFixture, $peBytes)
        $peBoundsRejected = $false
        try {
            $null = Get-PackageArchitectureSectionSuffix $peFixture
        } catch {
            $peBoundsRejected = $_.Exception.Message -eq 'SYS PE header offset 4096 is outside file length 64.'
        }
        Assert-SelfTest $peBoundsRejected 'out-of-bounds PE offset has a stable diagnostic'
        [void]$tests.Add('reject out-of-bounds PE header')
    } finally {
        if (Test-Path -LiteralPath $peFixture) { Remove-Item -LiteralPath $peFixture -Force }
    }

    # The native orchestrator holds a deny-write/delete lease on every package
    # member for this verifier's whole run, so every read here must tolerate a
    # FileShare.Read handle that is already open on the same file.
    $leasedFixture = Join-Path ([System.IO.Path]::GetTempPath()) ('fsring-leased-sys-' + [Guid]::NewGuid().ToString('N') + '.sys')
    $leaseStream = $null
    try {
        $leasedBytes = New-Object byte[] 512
        $leasedBytes[0] = 0x4d
        $leasedBytes[1] = 0x5a
        [Array]::Copy([BitConverter]::GetBytes([uint32]128), 0, $leasedBytes, 0x3c, 4)
        [Array]::Copy([BitConverter]::GetBytes([uint32]0x00004550), 0, $leasedBytes, 128, 4)
        [Array]::Copy([BitConverter]::GetBytes([uint16]0x8664), 0, $leasedBytes, 132, 2)
        [System.IO.File]::WriteAllBytes($leasedFixture, $leasedBytes)
        $leaseStream = [System.IO.File]::Open($leasedFixture, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $leasedSuffix = $null
        $leasedError = $null
        try { $leasedSuffix = Get-PackageArchitectureSectionSuffix $leasedFixture }
        catch { $leasedError = $_.Exception.Message }
        Assert-SelfTest ($null -eq $leasedError -and $leasedSuffix -ceq 'NTamd64') ('read the SYS while a deny-write lease is held: ' + [string]$leasedError)
        [void]$tests.Add('read the SYS while a deny-write lease is held')
    } finally {
        if ($null -ne $leaseStream) { $leaseStream.Dispose() }
        if (Test-Path -LiteralPath $leasedFixture) { Remove-Item -LiteralPath $leasedFixture -Force }
    }

    $installedInfVerif = 'C:\Program Files (x86)\Windows Kits\10\Tools\10.0.26100.0\x64\infverif.exe'
    $installedSignTool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe'
    $infTool = Resolve-PackageTool $installedInfVerif $installedInfVerif 'InfVerif 10.0.26100' 'infverif.exe' '10.0.26100'
    $signTool = Resolve-PackageTool $installedSignTool $installedSignTool 'SignTool' 'SIGNTOOL.EXE' '10.0.22000'
    Assert-SelfTest ($infTool.ProductVersion -match '^10\.0\.26100\.' -and $signTool.ProductVersion -match '^10\.0\.22000\.') 'installed tool identities and versions are accepted'
    [void]$tests.Add('validate installed tool identity and version')

    $wrongToolRejected = $false
    try {
        $null = Resolve-PackageTool $installedSignTool $installedSignTool 'InfVerif 10.0.26100' 'infverif.exe' '10.0.26100'
    } catch {
        $wrongToolRejected = $_.Exception.Message -match 'identity mismatch'
    }
    Assert-SelfTest $wrongToolRejected 'tool override with wrong executable identity is rejected'
    [void]$tests.Add('reject wrong tool override identity')

    $wrongVersionRejected = $false
    try {
        $null = Resolve-PackageTool $installedSignTool $installedSignTool 'SignTool' 'SIGNTOOL.EXE' '10.0.99999'
    } catch {
        $wrongVersionRejected = $_.Exception.Message -match 'version mismatch'
    }
    Assert-SelfTest $wrongVersionRejected 'tool override with wrong product version is rejected'
    [void]$tests.Add('reject wrong tool override version')

    $nativeFailure = Invoke-PackageTool $env:ComSpec @('/d', '/c', 'echo native-stderr 1>&2 & exit /b 7') $env:ComSpec
    Assert-SelfTest ($nativeFailure.ExitCode -eq 7 -and $nativeFailure.Output -match 'native-stderr') 'native stderr and nonzero exit are returned for classification'
    [void]$tests.Add('capture native stderr and nonzero exit')
    $nativeTrailingBlank = Invoke-PackageTool $env:ComSpec @('/d', '/c', 'echo native-stderr 1>&2 & echo. 1>&2 & exit /b 7') $env:ComSpec
    Assert-SelfTest ($nativeTrailingBlank.ExitCode -eq 7 -and $nativeTrailingBlank.Output -eq 'native-stderr') 'empty native stderr wrapper records are omitted'
    [void]$tests.Add('omit empty native stderr wrapper record')
    Assert-SelfTest ($ErrorActionPreference.ToString() -eq 'Stop') 'native invocation restores ErrorActionPreference'
    [void]$tests.Add('restore native error-action policy')

    $semanticCases = @(
        [pscustomobject]@{ Name = 'missing architecture-decorated install pair'; Text = ($validInf -replace 'DefaultInstall\.NTamd64', 'DefaultInstall.NTlegacy'); Expected = 'missing required \[DefaultInstall\.NTamd64\]' },
        [pscustomobject]@{ Name = 'StartType mismatch'; Text = ($validInf -replace 'StartType = 3', 'StartType = 2'); Expected = 'StartType=3; found 2' },
        [pscustomobject]@{ Name = 'ErrorControl mismatch'; Text = ($validInf -replace 'ErrorControl = 1', 'ErrorControl = 0'); Expected = 'ErrorControl=1; found 0' },
        [pscustomobject]@{ Name = 'LoadOrderGroup mismatch'; Text = ($validInf -replace 'File System', 'Base'); Expected = 'LoadOrderGroup=File System; found Base' },
        [pscustomobject]@{ Name = 'ServiceBinary mismatch'; Text = ($validInf -replace 'fsring_fsd\.sys', 'other.sys'); Expected = 'exact ServiceBinary=%13%\\fsring_fsd\.sys' }
    )
    foreach ($case in $semanticCases) {
        $caseErrors = @(Test-FsringInfSemantics (Parse-FsringInf $case.Text) 'NTamd64')
        Assert-SelfTest (@($caseErrors | Where-Object { $_ -match $case.Expected }).Count -gt 0) ('reject ' + $case.Name)
        [void]$tests.Add('reject ' + $case.Name)
    }

    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ('fsring-package-selftest-' + [Guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -ItemType Directory -Path $temp)
        Set-Content -LiteralPath (Join-Path $temp 'fsring_fsd.inf') -Value $validInf -Encoding ASCII
        $artifactCheck = Test-PackageArtifacts $temp
        Assert-SelfTest ($artifactCheck.Errors.Count -eq 2 -and $artifactCheck.Errors -contains 'Package artifact is absent: fsring_fsd.sys.' -and $artifactCheck.Errors -contains 'Package artifact is absent: fsring_fsd.cat.') 'absent package artifacts are rejected before tools'
        $childOutput = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath $temp -InfVerifPath 'Z:\missing\infverif.exe' 2>&1)
        $childExit = $LASTEXITCODE
        $childResult = ($childOutput -join "`n") | ConvertFrom-Json
        Assert-SelfTest ($childExit -eq 1 -and @($childResult.errors).Count -eq 2 -and @($childResult.tools.PSObject.Properties).Count -eq 0) 'absent package files prevent tool resolution'
        [void]$tests.Add('reject absent package files before tools')
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
    }

    $fixtureSysPath = 'C:\package\fsring_fsd.sys'
    $fixtureCatPath = 'C:\package\fsring_fsd.cat'
    $trustedSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = @('verify', '/v', '/kp', $fixtureSysPath); ExitCode = 0; Output = "Verifying: $fixtureSysPath`nSignature Index: 0 (Primary Signature)`nSuccessfully verified: $fixtureSysPath`nNumber of files successfully Verified: 1`nNumber of warnings: 0`nNumber of errors: 0" }
    $trustedCat = [pscustomobject]@{ TargetPath = $fixtureCatPath; Arguments = @('verify', '/v', '/kp', $fixtureCatPath); ExitCode = 0; Output = "Verifying: $fixtureCatPath`nSignature Index: 0 (Primary Signature)`nSuccessfully verified: $fixtureCatPath`nNumber of files successfully Verified: 1`nNumber of warnings: 0`nNumber of errors: 0" }
    $trustedCatalogMember = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = @('verify', '/v', '/kp', '/c', $fixtureCatPath, $fixtureSysPath); ExitCode = 0; Output = "Verifying: $fixtureSysPath`nFile is signed in catalog: $fixtureCatPath`nSuccessfully verified: $fixtureSysPath`nNumber of files successfully Verified: 1`nNumber of warnings: 0`nNumber of errors: 0" }
    $membership = [pscustomobject]@{ Valid = $true; SysPath = $fixtureSysPath; CatPath = $fixtureCatPath; MemberHash = '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF'; Error = $null }

    $authenticodeSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = @('verify', '/v', '/pa', $fixtureSysPath); ExitCode = $trustedSys.ExitCode; Output = $trustedSys.Output }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $authenticodeSys $trustedCat $trustedCatalogMember $membership).Valid) 'Authenticode policy evidence is rejected'
    [void]$tests.Add('reject Authenticode policy evidence')

    $trusted = Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $trustedSys $trustedCat $trustedCatalogMember $membership
    Assert-SelfTest ($trusted.Valid -and $trusted.TrustReady -and
        $trusted.SysMode -eq 'Trusted' -and $trusted.CatMode -eq 'Trusted' -and
        $trusted.CatalogMemberMode -eq 'Trusted') 'three trusted exact kernel-policy probes are accepted'
    [void]$tests.Add('accept three trusted kernel-policy probes')

    $trustedWarningSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $trustedSys.Arguments; ExitCode = 0; Output = $trustedSys.Output + "`nSignTool Warning: unrelated warning" }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $trustedWarningSys $trustedCat $trustedCatalogMember $membership).Valid) 'trusted target evidence with a SignTool warning is rejected'
    [void]$tests.Add('reject trusted target SignTool warning')

    $trustedWarningCatalogMember = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $trustedCatalogMember.Arguments; ExitCode = 0; Output = $trustedCatalogMember.Output + "`nSignTool Warning: unrelated warning" }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $trustedSys $trustedCat $trustedWarningCatalogMember $membership).Valid) 'trusted catalog-member evidence with a SignTool warning is rejected'
    [void]$tests.Add('reject trusted catalog-member SignTool warning')

    $trustedInvalidSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $trustedSys.Arguments; ExitCode = 0; Output = $trustedSys.Output + "`nThe signature is invalid." }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $trustedInvalidSys $trustedCat $trustedCatalogMember $membership).Valid) 'trusted SYS evidence with an invalid-signature diagnostic is rejected'
    [void]$tests.Add('reject trusted SYS invalid-signature diagnostic')

    $trustedInvalidCat = [pscustomobject]@{ TargetPath = $fixtureCatPath; Arguments = $trustedCat.Arguments; ExitCode = 0; Output = $trustedCat.Output + "`nThe signature is invalid." }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $trustedSys $trustedInvalidCat $trustedCatalogMember $membership).Valid) 'trusted CAT evidence with an invalid-signature diagnostic is rejected'
    [void]$tests.Add('reject trusted CAT invalid-signature diagnostic')

    $trustedInvalidCatalogMember = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $trustedCatalogMember.Arguments; ExitCode = 0; Output = $trustedCatalogMember.Output + "`nThe signature is invalid." }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $trustedSys $trustedCat $trustedInvalidCatalogMember $membership).Valid) 'trusted catalog-member evidence with an invalid-signature diagnostic is rejected'
    [void]$tests.Add('reject trusted catalog-member invalid-signature diagnostic')

    $untrustedText = "Signature Index: 0 (Primary Signature)`nIssued to: WDRLocalTestCert`nIssued by: WDRLocalTestCert`nNumber of files successfully Verified: 0`nNumber of warnings: 0`nNumber of errors: 1`nSignTool Error: A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider."
    $untrustedSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = @('verify', '/v', '/kp', $fixtureSysPath); ExitCode = 1; Output = "Verifying: $fixtureSysPath`n$untrustedText" }
    $untrustedCat = [pscustomobject]@{ TargetPath = $fixtureCatPath; Arguments = @('verify', '/v', '/kp', $fixtureCatPath); ExitCode = 1; Output = "Verifying: $fixtureCatPath`n$untrustedText" }
    $untrustedCatalogMemberText = "Issued to: WDRLocalTestCert`nIssued by: WDRLocalTestCert`nNumber of files successfully Verified: 0`nNumber of warnings: 0`nNumber of errors: 1`nSignTool Error: A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider."
    $untrustedCatalogMember = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = @('verify', '/v', '/kp', '/c', $fixtureCatPath, $fixtureSysPath); ExitCode = 1; Output = "Verifying: $fixtureSysPath`nFile is signed in catalog: $fixtureCatPath`n$untrustedCatalogMemberText SignTool Error: File not valid: $fixtureSysPath" }
    $untrusted = Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $untrustedSys $untrustedCat $untrustedCatalogMember $membership
    Assert-SelfTest ($untrusted.Valid -and -not $untrusted.TrustReady -and
        $untrusted.SysMode -eq 'UntrustedTestRoot' -and $untrusted.CatMode -eq 'UntrustedTestRoot' -and
        $untrusted.CatalogMemberMode -eq 'UntrustedTestRoot') 'three exact WDRLocalTestCert kernel-policy outcomes are classified, not load-ready'
    [void]$tests.Add('classify three exact untrusted test-root probes')

    $timestampSignerBlock = "Signing Certificate Chain:`nIssued to: WDRLocalTestCert`nIssued by: WDRLocalTestCert`nExpires: Sun Jan 01 06:59:59 2040`nSHA1 hash: C3E805E2841D2C68790A7F4E8E93DB121EB0C046`nThe signature is timestamped: Thu Jul 30 05:21:40 2026`nTimestamp Verified by:`nIssued to: DigiCert Assured ID Root CA`nIssued by: DigiCert Assured ID Root CA`nExpires: Mon Nov 10 07:00:00 2031`nSHA1 hash: 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43`nIssued to: DigiCert Trusted Root G4`nIssued by: DigiCert Assured ID Root CA`nExpires: Mon Nov 10 06:59:59 2031`nSHA1 hash: A99D5B79E9F1CDA59CDAB6373169D5353F5874C6`nIssued to: DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1`nIssued by: DigiCert Trusted Root G4`nExpires: Fri Jan 15 06:59:59 2038`nSHA1 hash: 07894D00FC194A17DB273AEB5CF8FACEF14423A4`nIssued to: DigiCert SHA256 RSA4096 Timestamp Responder 2025 1`nIssued by: DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1`nExpires: Thu Sep 04 06:59:59 2036`nSHA1 hash: DD6230AC860A2D306BDA38B16879523007FB417E"
    $timestampedUntrustedSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $untrustedSys.Arguments; ExitCode = 1; Output = "Verifying: $fixtureSysPath`nSignature Index: 0 (Primary Signature)`nHash of file (sha256): 86A994E5A495C584A4F97EF078BA7A75C0B9A390A0D45F37EBDCB96CD0474274`n$timestampSignerBlock`nNumber of files successfully Verified: 0`nNumber of warnings: 0`nNumber of errors: 1`nSignTool Error: A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider." }
    $timestampedUntrustedCat = [pscustomobject]@{ TargetPath = $fixtureCatPath; Arguments = $untrustedCat.Arguments; ExitCode = 1; Output = "Verifying: $fixtureCatPath`nSignature Index: 0 (Primary Signature)`nHash of file (sha256): A30D858B549562A66ACA3BDABB756549BDA4F5971BD75C9953DE08A23C3DA153`n$timestampSignerBlock`nNumber of files successfully Verified: 0`nNumber of warnings: 0`nNumber of errors: 1`nSignTool Error: A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider." }
    $timestampedUntrustedCatalogMember = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $untrustedCatalogMember.Arguments; ExitCode = 1; Output = "Verifying: $fixtureSysPath`nFile is signed in catalog: $fixtureCatPath`nHash of file (sha1): 9F8631BBF85B73E426145A929BD70A37ED9CBD64`n$timestampSignerBlock`nNumber of files successfully Verified: 0`nNumber of warnings: 0`nNumber of errors: 1`nSignTool Error: A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider. SignTool Error: File not valid: $fixtureSysPath" }
    Assert-SelfTest (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $timestampedUntrustedSys $timestampedUntrustedCat $timestampedUntrustedCatalogMember $membership).Valid 'measured timestamp signer chain is accepted without weakening primary signer markers'
    [void]$tests.Add('accept measured timestamp signer chain')

    # A WDRLocalTestCert package can never satisfy the kernel-mode driver
    # signing policy: /kp requires the chain to terminate in a Microsoft root,
    # which a self-signed test root is not. Once the operator installs that
    # exact certificate into LocalMachine\Root and LocalMachine\TrustedPublisher
    # -- the documented prerequisite for loading a test-signed driver -- SignTool
    # stops reporting an untrusted root and reports the Microsoft-root policy
    # refusal instead. That third observation is the only one under which the
    # kernel will actually load the package, so it is classified separately and
    # corroborated by measured store presence plus an Authenticode-policy pass.
    $microsoftRootDiagnostic = 'SignTool Error: Signing Cert does not chain to a Microsoft Root Cert.'
    $localRootText = "Signature Index: 0 (Primary Signature)`nIssued to: WDRLocalTestCert`nIssued by: WDRLocalTestCert`nNumber of files successfully Verified: 0`nNumber of warnings: 0`nNumber of errors: 1`n$microsoftRootDiagnostic"
    $localSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = @('verify', '/v', '/kp', $fixtureSysPath); ExitCode = 1; Output = "Verifying: $fixtureSysPath`n$localRootText" }
    $localCat = [pscustomobject]@{ TargetPath = $fixtureCatPath; Arguments = @('verify', '/v', '/kp', $fixtureCatPath); ExitCode = 1; Output = "Verifying: $fixtureCatPath`n$localRootText" }
    $localCatalogMemberText = "Issued to: WDRLocalTestCert`nIssued by: WDRLocalTestCert`nNumber of files successfully Verified: 0`nNumber of warnings: 0`nNumber of errors: 1`n$microsoftRootDiagnostic"
    $localCatalogMember = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = @('verify', '/v', '/kp', '/c', $fixtureCatPath, $fixtureSysPath); ExitCode = 1; Output = "Verifying: $fixtureSysPath`nFile is signed in catalog: $fixtureCatPath`n$localCatalogMemberText SignTool Error: File not valid: $fixtureSysPath" }

    $localCertificate = [pscustomobject]@{ Valid = $true; Thumbprint = 'C3E805E2841D2C68790A7F4E8E93DB121EB0C046'; RootStorePresent = $true; TrustedPublisherPresent = $true; Error = $null }
    $authenticodeSysPass = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = @('verify', '/v', '/pa', $fixtureSysPath); ExitCode = 0; Output = "Verifying: $fixtureSysPath`nSignature Index: 0 (Primary Signature)`nSuccessfully verified: $fixtureSysPath`nNumber of files successfully Verified: 1`nNumber of warnings: 0`nNumber of errors: 0" }
    $authenticodeCatPass = [pscustomobject]@{ TargetPath = $fixtureCatPath; Arguments = @('verify', '/v', '/pa', $fixtureCatPath); ExitCode = 0; Output = "Verifying: $fixtureCatPath`nSignature Index: 0 (Primary Signature)`nSuccessfully verified: $fixtureCatPath`nNumber of files successfully Verified: 1`nNumber of warnings: 0`nNumber of errors: 0" }
    $authenticodeMemberPass = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = @('verify', '/v', '/pa', '/c', $fixtureCatPath, $fixtureSysPath); ExitCode = 0; Output = "Verifying: $fixtureSysPath`nFile is signed in catalog: $fixtureCatPath`nSuccessfully verified: $fixtureSysPath`nNumber of files successfully Verified: 1`nNumber of warnings: 0`nNumber of errors: 0" }
    $localTrust = [pscustomobject]@{ Certificate = $localCertificate; AuthenticodeSys = $authenticodeSysPass; AuthenticodeCat = $authenticodeCatPass; AuthenticodeCatalogMember = $authenticodeMemberPass }

    $locallyTrusted = Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $localSys $localCat $localCatalogMember $membership $localTrust
    Assert-SelfTest ($locallyTrusted.Valid -and $locallyTrusted.TrustReady -and
        $locallyTrusted.SysMode -eq 'TestSignedLocallyTrusted' -and
        $locallyTrusted.CatMode -eq 'TestSignedLocallyTrusted' -and
        $locallyTrusted.CatalogMemberMode -eq 'TestSignedLocallyTrusted') 'three exact locally trusted test-root probes are load-ready under TESTSIGNING'
    [void]$tests.Add('classify three locally trusted test-root probes')

    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $localSys $localCat $localCatalogMember $membership $null).Valid) 'locally trusted classification without local trust evidence is rejected'
    [void]$tests.Add('reject locally trusted mode with no local trust evidence')

    foreach ($storeCase in @(
            [pscustomobject]@{ Name = 'root store'; Property = 'RootStorePresent' },
            [pscustomobject]@{ Name = 'trusted publisher store'; Property = 'TrustedPublisherPresent' }
        )) {
        $brokenCertificate = [pscustomobject]@{ Valid = $true; Thumbprint = $localCertificate.Thumbprint; RootStorePresent = $true; TrustedPublisherPresent = $true; Error = $null }
        $brokenCertificate.$($storeCase.Property) = $false
        $brokenTrust = [pscustomobject]@{ Certificate = $brokenCertificate; AuthenticodeSys = $authenticodeSysPass; AuthenticodeCat = $authenticodeCatPass; AuthenticodeCatalogMember = $authenticodeMemberPass }
        Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $localSys $localCat $localCatalogMember $membership $brokenTrust).Valid) ('locally trusted classification without the certificate in the ' + $storeCase.Name + ' is rejected')
        [void]$tests.Add('reject locally trusted mode missing ' + $storeCase.Name)
    }

    $wrongThumbprintCertificate = [pscustomobject]@{ Valid = $true; Thumbprint = ('A' * 40); RootStorePresent = $true; TrustedPublisherPresent = $true; Error = $null }
    $wrongThumbprintTrust = [pscustomobject]@{ Certificate = $wrongThumbprintCertificate; AuthenticodeSys = $authenticodeSysPass; AuthenticodeCat = $authenticodeCatPass; AuthenticodeCatalogMember = $authenticodeMemberPass }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $localSys $localCat $localCatalogMember $membership $wrongThumbprintTrust).Valid) 'locally trusted classification for another certificate thumbprint is rejected'
    [void]$tests.Add('reject locally trusted mode for another thumbprint')

    $authenticodeSysFail = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $authenticodeSysPass.Arguments; ExitCode = 1; Output = "Verifying: $fixtureSysPath`n$localRootText" }
    $authenticodeFailTrust = [pscustomobject]@{ Certificate = $localCertificate; AuthenticodeSys = $authenticodeSysFail; AuthenticodeCat = $authenticodeCatPass; AuthenticodeCatalogMember = $authenticodeMemberPass }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $localSys $localCat $localCatalogMember $membership $authenticodeFailTrust).Valid) 'locally trusted classification without an Authenticode-policy pass is rejected'
    [void]$tests.Add('reject locally trusted mode without Authenticode pass')

    $kernelArgvInAuthenticodeSlot = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = @('verify', '/v', '/kp', $fixtureSysPath); ExitCode = 0; Output = $authenticodeSysPass.Output }
    $kernelArgvTrust = [pscustomobject]@{ Certificate = $localCertificate; AuthenticodeSys = $kernelArgvInAuthenticodeSlot; AuthenticodeCat = $authenticodeCatPass; AuthenticodeCatalogMember = $authenticodeMemberPass }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $localSys $localCat $localCatalogMember $membership $kernelArgvTrust).Valid) 'Authenticode corroboration that used kernel-policy arguments is rejected'
    [void]$tests.Add('reject kernel-policy argv in the Authenticode slot')

    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $localSys $untrustedCat $untrustedCatalogMember $membership $localTrust).Valid) 'mixed locally trusted and untrusted kernel-policy outcomes are rejected'
    [void]$tests.Add('reject mixed locally trusted and untrusted modes')

    $extraLocalError = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $localSys.Arguments; ExitCode = 1; Output = $localSys.Output + "`nSignTool Error: unexpected policy failure" }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $extraLocalError $localCat $localCatalogMember $membership $localTrust).Valid) 'locally trusted evidence with an extra SignTool error is rejected'
    [void]$tests.Add('reject additional locally trusted SignTool error')

    $timestampedLocalSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $localSys.Arguments; ExitCode = 1; Output = "Verifying: $fixtureSysPath`nSignature Index: 0 (Primary Signature)`nHash of file (sha256): EB99484A4F3E5358A536AA7E759E7E58FD5BBF6B379BE4A88897FDF17EE1B08B`n$timestampSignerBlock`nNumber of files successfully Verified: 0`nNumber of warnings: 0`nNumber of errors: 1`n$microsoftRootDiagnostic" }
    $timestampedLocalCat = [pscustomobject]@{ TargetPath = $fixtureCatPath; Arguments = $localCat.Arguments; ExitCode = 1; Output = "Verifying: $fixtureCatPath`nSignature Index: 0 (Primary Signature)`nHash of file (sha256): 170C8278C52412196B85FEDC3B2B5657FEF18D4F91E5873E06BA7CE14C7AAFB0`n$timestampSignerBlock`nNumber of files successfully Verified: 0`nNumber of warnings: 0`nNumber of errors: 1`n$microsoftRootDiagnostic" }
    $timestampedLocalCatalogMember = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $localCatalogMember.Arguments; ExitCode = 1; Output = "Verifying: $fixtureSysPath`nFile is signed in catalog: $fixtureCatPath`nHash of file (sha1): 1A298C2EC2DBF9E485BB9F576B85EEFB7154C84F`n$timestampSignerBlock`nNumber of files successfully Verified: 0`nNumber of warnings: 0`nNumber of errors: 1`n$microsoftRootDiagnostic SignTool Error: File not valid: $fixtureSysPath" }
    $timestampedLocalTrust = [pscustomobject]@{
        Certificate = $localCertificate
        AuthenticodeSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $authenticodeSysPass.Arguments; ExitCode = 0; Output = "Verifying: $fixtureSysPath`nSignature Index: 0 (Primary Signature)`nHash of file (sha256): EB99484A4F3E5358A536AA7E759E7E58FD5BBF6B379BE4A88897FDF17EE1B08B`n$timestampSignerBlock`nSuccessfully verified: $fixtureSysPath`nNumber of files successfully Verified: 1`nNumber of warnings: 0`nNumber of errors: 0" }
        AuthenticodeCat = [pscustomobject]@{ TargetPath = $fixtureCatPath; Arguments = $authenticodeCatPass.Arguments; ExitCode = 0; Output = "Verifying: $fixtureCatPath`nSignature Index: 0 (Primary Signature)`nHash of file (sha256): 170C8278C52412196B85FEDC3B2B5657FEF18D4F91E5873E06BA7CE14C7AAFB0`n$timestampSignerBlock`nSuccessfully verified: $fixtureCatPath`nNumber of files successfully Verified: 1`nNumber of warnings: 0`nNumber of errors: 0" }
        AuthenticodeCatalogMember = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $authenticodeMemberPass.Arguments; ExitCode = 0; Output = "Verifying: $fixtureSysPath`nFile is signed in catalog: $fixtureCatPath`nHash of file (sha1): 1A298C2EC2DBF9E485BB9F576B85EEFB7154C84F`n$timestampSignerBlock`nSuccessfully verified: $fixtureSysPath`nNumber of files successfully Verified: 1`nNumber of warnings: 0`nNumber of errors: 0" }
    }
    $timestampedLocal = Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $timestampedLocalSys $timestampedLocalCat $timestampedLocalCatalogMember $membership $timestampedLocalTrust
    Assert-SelfTest ($timestampedLocal.Valid -and $timestampedLocal.TrustReady -and
        $timestampedLocal.SysMode -eq 'TestSignedLocallyTrusted') 'measured locally trusted timestamp signer chain is accepted'
    [void]$tests.Add('accept measured locally trusted timestamp chain')

    # DigiCert rotates the timestamp *responder* leaf on its own schedule: the
    # same package re-signed on 2026-09-04 carried "Responder 2026 1" where the
    # 2026-09-03 signature carried "Responder 2025 1", with a different SHA1 and
    # expiry. Pinning that leaf literally made every future re-signature fail a
    # grammar that has nothing to say about our signer. The responder's issuing
    # CA stays pinned, so the chain must still terminate in the same authority.
    $rotatedTimestampSignerBlock = $timestampSignerBlock.
        Replace('Timestamp Responder 2025 1', 'Timestamp Responder 2026 1').
        Replace('Expires: Thu Sep 04 06:59:59 2036', 'Expires: Thu Nov 05 06:59:59 2037').
        Replace('DD6230AC860A2D306BDA38B16879523007FB417E', '51D9ABDA034973D84F4266ACA48248E6B369C439')
    Assert-SelfTest ($rotatedTimestampSignerBlock -cne $timestampSignerBlock) 'rotated responder fixture is identical to the frozen one, so it proves nothing'
    [void]$tests.Add('rotated responder fixture actually differs')

    $rotatedLocalSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $localSys.Arguments; ExitCode = 1; Output = "Verifying: $fixtureSysPath`nSignature Index: 0 (Primary Signature)`nHash of file (sha256): 11CF6298A974E53886DA81C082FC565B2310B9F1677C9E0AEF55278ACAE1FE8C`n$rotatedTimestampSignerBlock`nNumber of files successfully Verified: 0`nNumber of warnings: 0`nNumber of errors: 1`n$microsoftRootDiagnostic" }
    Assert-SelfTest (Test-SignToolTargetEvidence $fixtureSysPath $rotatedLocalSys).Valid 'a rotated DigiCert timestamp responder was rejected'
    [void]$tests.Add('accept a rotated timestamp responder leaf')

    $rotatedUntrustedSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $untrustedSys.Arguments; ExitCode = 1; Output = "Verifying: $fixtureSysPath`nSignature Index: 0 (Primary Signature)`nHash of file (sha256): 11CF6298A974E53886DA81C082FC565B2310B9F1677C9E0AEF55278ACAE1FE8C`n$rotatedTimestampSignerBlock`nNumber of files successfully Verified: 0`nNumber of warnings: 0`nNumber of errors: 1`nSignTool Error: A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider." }
    Assert-SelfTest (Test-SignToolTargetEvidence $fixtureSysPath $rotatedUntrustedSys).Valid 'a rotated responder was rejected on the untrusted-root path'
    [void]$tests.Add('accept a rotated responder on the untrusted path')

    $foreignIssuerBlock = $rotatedTimestampSignerBlock.Replace(
        'Issued by: DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1',
        'Issued by: Unrelated Timestamping CA')
    $foreignIssuerSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $localSys.Arguments; ExitCode = 1; Output = "Verifying: $fixtureSysPath`nSignature Index: 0 (Primary Signature)`nHash of file (sha256): 11CF6298A974E53886DA81C082FC565B2310B9F1677C9E0AEF55278ACAE1FE8C`n$foreignIssuerBlock`nNumber of files successfully Verified: 0`nNumber of warnings: 0`nNumber of errors: 1`n$microsoftRootDiagnostic" }
    Assert-SelfTest (-not (Test-SignToolTargetEvidence $fixtureSysPath $foreignIssuerSys).Valid) 'a responder issued by another authority was accepted'
    [void]$tests.Add('reject a responder issued by another authority')

    $rotatedSignerBlock = $rotatedTimestampSignerBlock.Replace(
        'SHA1 hash: C3E805E2841D2C68790A7F4E8E93DB121EB0C046',
        'SHA1 hash: 0000000000000000000000000000000000000000')
    $rotatedSignerSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $localSys.Arguments; ExitCode = 1; Output = "Verifying: $fixtureSysPath`nSignature Index: 0 (Primary Signature)`nHash of file (sha256): 11CF6298A974E53886DA81C082FC565B2310B9F1677C9E0AEF55278ACAE1FE8C`n$rotatedSignerBlock`nNumber of files successfully Verified: 0`nNumber of warnings: 0`nNumber of errors: 1`n$microsoftRootDiagnostic" }
    Assert-SelfTest (-not (Test-SignToolTargetEvidence $fixtureSysPath $rotatedSignerSys).Valid) 'a different signing certificate thumbprint was accepted'
    [void]$tests.Add('keep the signer thumbprint exactly pinned')

    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $untrustedSys $untrustedCat $untrustedCatalogMember $membership $localTrust).TrustReady) 'untrusted-root evidence is never load-ready even with local trust evidence supplied'
    [void]$tests.Add('keep untrusted-root evidence not load-ready')

    $unconsumedLineCases = @(
        [pscustomobject]@{ Name = 'revoked-certificate diagnostic'; Text = 'A certificate was revoked by its issuer.' },
        [pscustomobject]@{ Name = 'malformed timestamp-verifier marker'; Text = 'Timestamp Verified by: UnrelatedSigner' },
        [pscustomobject]@{ Name = 'malformed signing-chain marker'; Text = 'Signing Certificate Chain: UnrelatedSigner' },
        [pscustomobject]@{ Name = 'malformed Issued to marker'; Text = 'Issued to : UnrelatedSigner' },
        [pscustomobject]@{ Name = 'malformed Issued by marker'; Text = 'Issued by : UnrelatedSigner' },
        [pscustomobject]@{ Name = 'malformed signature-index marker'; Text = 'Signature Index : 1' },
        [pscustomobject]@{ Name = 'generic unknown line'; Text = 'FSRING UNKNOWN SENTINEL' }
    )
    foreach ($case in $unconsumedLineCases) {
        $adversarialTimestampedSys = [pscustomobject]@{
            TargetPath = $fixtureSysPath
            Arguments = $timestampedUntrustedSys.Arguments
            ExitCode = 1
            Output = $timestampedUntrustedSys.Output + "`n" + $case.Text
        }
        Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $adversarialTimestampedSys $timestampedUntrustedCat $timestampedUntrustedCatalogMember $membership).Valid) ('direct timestamped evidence with ' + $case.Name + ' is rejected')
        [void]$tests.Add('reject direct timestamped ' + $case.Name)

        $adversarialTimestampedCatalogMember = [pscustomobject]@{
            TargetPath = $fixtureSysPath
            Arguments = $timestampedUntrustedCatalogMember.Arguments
            ExitCode = 1
            Output = $timestampedUntrustedCatalogMember.Output + "`n" + $case.Text
        }
        Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $timestampedUntrustedSys $timestampedUntrustedCat $adversarialTimestampedCatalogMember $membership).Valid) ('catalog-member timestamped evidence with ' + $case.Name + ' is rejected')
        [void]$tests.Add('reject catalog-member timestamped ' + $case.Name)
    }

    $interleavedText = "Signature Index: 0 (Primary Signature)`nIssued to: WDRLocalTestCert`nIssued by: WDRLocalTestCert`nSignTool Error: A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider.`nNumber of files successfully Verified: 0`nNumber of warnings: 0`nNumber of errors: 1"
    $interleavedSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = @('verify', '/v', '/kp', $fixtureSysPath); ExitCode = 1; Output = "Verifying: $fixtureSysPath`n$interleavedText" }
    Assert-SelfTest (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $interleavedSys $untrustedCat $untrustedCatalogMember $membership).Valid 'separately captured stderr diagnostic may precede stdout counters'
    [void]$tests.Add('classify interleaved native stderr record')

    $directUntrustedAdversarialSuffixes = @(
        [pscustomobject]@{ Name = 'non-prefixed hash diagnostic'; Text = 'Hash mismatch for unrelated payload' },
        [pscustomobject]@{ Name = 'non-prefixed fatal diagnostic'; Text = 'Fatal: unrelated verification failure' },
        [pscustomobject]@{ Name = 'extra certificate-validity diagnostic'; Text = 'A required certificate is not within its validity period.' },
        [pscustomobject]@{ Name = 'extra signature index'; Text = 'Signature Index: 1' },
        [pscustomobject]@{ Name = 'duplicate Issued to marker'; Text = 'Issued to: WDRLocalTestCert' },
        [pscustomobject]@{ Name = 'extra Issued to marker'; Text = 'Issued to: UnrelatedSigner' },
        [pscustomobject]@{ Name = 'duplicate Issued by marker'; Text = 'Issued by: WDRLocalTestCert' },
        [pscustomobject]@{ Name = 'extra Issued by marker'; Text = 'Issued by: UnrelatedSigner' }
    )
    foreach ($case in $directUntrustedAdversarialSuffixes) {
        $adversarialSys = [pscustomobject]@{
            TargetPath = $fixtureSysPath
            Arguments = $untrustedSys.Arguments
            ExitCode = 1
            Output = $untrustedSys.Output + "`n" + $case.Text
        }
        Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $adversarialSys $untrustedCat $untrustedCatalogMember $membership).Valid) ('direct untrusted-root evidence with ' + $case.Name + ' is rejected')
        [void]$tests.Add('reject direct untrusted ' + $case.Name)
    }

    $catalogMemberUntrustedAdversarialSuffixes = @(
        [pscustomobject]@{ Name = 'non-prefixed hash diagnostic'; Text = 'Hash mismatch for unrelated payload' },
        [pscustomobject]@{ Name = 'non-prefixed fatal diagnostic'; Text = 'Fatal: unrelated verification failure' },
        [pscustomobject]@{ Name = 'extra certificate-validity diagnostic'; Text = 'A required certificate is not within its validity period.' },
        [pscustomobject]@{ Name = 'duplicate Issued to marker'; Text = 'Issued to: WDRLocalTestCert' },
        [pscustomobject]@{ Name = 'extra Issued to marker'; Text = 'Issued to: UnrelatedSigner' },
        [pscustomobject]@{ Name = 'duplicate Issued by marker'; Text = 'Issued by: WDRLocalTestCert' },
        [pscustomobject]@{ Name = 'extra Issued by marker'; Text = 'Issued by: UnrelatedSigner' }
    )
    foreach ($case in $catalogMemberUntrustedAdversarialSuffixes) {
        $adversarialCatalogMember = [pscustomobject]@{
            TargetPath = $fixtureSysPath
            Arguments = $untrustedCatalogMember.Arguments
            ExitCode = 1
            Output = $untrustedCatalogMember.Output + "`n" + $case.Text
        }
        Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $untrustedSys $untrustedCat $adversarialCatalogMember $membership).Valid) ('catalog-member untrusted-root evidence with ' + $case.Name + ' is rejected')
        [void]$tests.Add('reject catalog-member untrusted ' + $case.Name)
    }

    $tamperedMembership = [pscustomobject]@{ Valid = $false; SysPath = $fixtureSysPath; CatPath = $fixtureCatPath; MemberHash = $null; Error = 'Packaged SYS hash is absent from the exact catalog.' }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $untrustedSys $untrustedCat $untrustedCatalogMember $tamperedMembership).Valid) 'catalog-bound failure without independent membership is rejected'
    [void]$tests.Add('reject catalog-bound failure without independent membership')
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $trustedSys $trustedCat $trustedCatalogMember $tamperedMembership).Valid) 'tampered catalog member is rejected'
    [void]$tests.Add('reject tampered catalog member')

    $wrongPathSys = [pscustomobject]@{ TargetPath = 'C:\other\fsring_fsd.sys'; Arguments = $trustedSys.Arguments; ExitCode = 0; Output = $trustedSys.Output }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $wrongPathSys $trustedCat $trustedCatalogMember $membership).Valid) 'path-mismatched signature evidence is rejected'
    [void]$tests.Add('reject path-mismatched signature evidence')

    $wrongArgumentSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = @('verify', '/v', '/kp', 'C:\other\fsring_fsd.sys'); ExitCode = 0; Output = $trustedSys.Output }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $wrongArgumentSys $trustedCat $trustedCatalogMember $membership).Valid) 'wrong SignTool target argument is rejected'
    [void]$tests.Add('reject wrong SignTool target argument')

    $wrongCatalogArgument = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = @('verify', '/v', '/kp', '/c', 'C:\other\fsring_fsd.cat', $fixtureSysPath); ExitCode = 0; Output = $trustedCatalogMember.Output }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $trustedSys $trustedCat $wrongCatalogArgument $membership).Valid) 'wrong catalog argument is rejected'
    [void]$tests.Add('reject wrong catalog argument')

    $wrongCatalogBinding = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $trustedCatalogMember.Arguments; ExitCode = 0; Output = ($trustedCatalogMember.Output -replace [regex]::Escape($fixtureCatPath), 'C:\other\fsring_fsd.cat') }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $trustedSys $trustedCat $wrongCatalogBinding $membership).Valid) 'wrong catalog binding output is rejected'
    [void]$tests.Add('reject wrong catalog binding output')

    $wrongExitSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $untrustedSys.Arguments; ExitCode = 0; Output = $untrustedSys.Output }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $wrongExitSys $untrustedCat $untrustedCatalogMember $membership).Valid) 'inconsistent SignTool exit and counters are rejected'
    [void]$tests.Add('reject inconsistent SignTool exit and counters')

    $wrongCounterCat = [pscustomobject]@{ TargetPath = $fixtureCatPath; Arguments = $trustedCat.Arguments; ExitCode = 0; Output = ($trustedCat.Output -replace 'Number of files successfully Verified: 1', 'Number of files successfully Verified: 0') }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $trustedSys $wrongCounterCat $trustedCatalogMember $membership).Valid) 'inconsistent SignTool success counters are rejected'
    [void]$tests.Add('reject inconsistent SignTool success counters')

    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $trustedSys $untrustedCat $untrustedCatalogMember $membership).Valid) 'mixed target trust modes are rejected'
    [void]$tests.Add('reject mixed target trust modes')
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $untrustedSys $untrustedCat $trustedCatalogMember $membership).Valid) 'mixed catalog-member trust mode is rejected'
    [void]$tests.Add('reject mixed catalog-member trust mode')

    $extraErrorSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $untrustedSys.Arguments; ExitCode = 1; Output = $untrustedSys.Output + "`nSignTool Error: unexpected policy failure" }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $extraErrorSys $untrustedCat $untrustedCatalogMember $membership).Valid) 'untrusted-root evidence with an extra error is rejected'
    [void]$tests.Add('reject additional SignTool error')

    $extraWarningSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $untrustedSys.Arguments; ExitCode = 1; Output = $untrustedSys.Output + "`nSignTool Warning: unexpected policy warning" }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $extraWarningSys $untrustedCat $untrustedCatalogMember $membership).Valid) 'untrusted-root evidence with an extra warning is rejected'
    [void]$tests.Add('reject additional SignTool warning')

    $extraCatalogMemberError = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $untrustedCatalogMember.Arguments; ExitCode = 1; Output = $untrustedCatalogMember.Output + ' SignTool Error: unexpected policy failure' }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $untrustedSys $untrustedCat $extraCatalogMemberError $membership).Valid) 'catalog-member evidence with an extra diagnostic is rejected'
    [void]$tests.Add('reject additional catalog-member diagnostic')

    $wrongFileNotValid = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $untrustedCatalogMember.Arguments; ExitCode = 1; Output = ($untrustedCatalogMember.Output -replace ('File not valid: ' + [regex]::Escape($fixtureSysPath)), 'File not valid: C:\other\fsring_fsd.sys') }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $untrustedSys $untrustedCat $wrongFileNotValid $membership).Valid) 'catalog-bound failure for another SYS is rejected'
    [void]$tests.Add('reject wrong File not valid target')

    $appendedRootErrorSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $untrustedSys.Arguments; ExitCode = 1; Output = $untrustedSys.Output + ' A required certificate is not within its validity period.' }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $appendedRootErrorSys $untrustedCat $untrustedCatalogMember $membership).Valid) 'known root sentence with same-line appended error is rejected'
    [void]$tests.Add('reject text appended to known root error')

    $genericRootSys = [pscustomobject]@{ TargetPath = $fixtureSysPath; Arguments = $untrustedSys.Arguments; ExitCode = 1; Output = "Verifying: $fixtureSysPath`nSuccessfully verified: arbitrary.bin`nroot certificate is not trusted" }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $genericRootSys $untrustedCat $untrustedCatalogMember $membership).Valid) 'generic success text plus an untrusted-root phrase is rejected'
    [void]$tests.Add('reject generic success plus root phrase')

    $wrongExitCat = [pscustomobject]@{ TargetPath = $fixtureCatPath; Arguments = $untrustedCat.Arguments; ExitCode = 2; Output = $untrustedCat.Output }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $untrustedSys $wrongExitCat $untrustedCatalogMember $membership).Valid) 'individual SignTool exit failure is rejected'
    [void]$tests.Add('reject individual SignTool exit failure')

    $wrongCatalogMembership = [pscustomobject]@{ Valid = $true; SysPath = $fixtureSysPath; CatPath = 'C:\other\fsring_fsd.cat'; MemberHash = $membership.MemberHash; Error = $null }
    Assert-SelfTest (-not (Test-SignatureEvidence $fixtureSysPath $fixtureCatPath $trustedSys $trustedCat $trustedCatalogMember $wrongCatalogMembership).Valid) 'membership evidence for another catalog is rejected'
    [void]$tests.Add('reject catalog path mismatch')

    # The store reader is the one part of local trust evidence that cannot be
    # a fixture. Cross-check it against a different mechanism than the one it
    # uses: this reads the stores through X509Store, the reader uses the Cert:
    # provider. The assertion is agreement, not presence, so it holds on a host
    # that has never installed the certificate.
    $storeEvidence = Get-WDRLocalTestCertStoreEvidence
    Assert-SelfTest (
        [string]::Join("`n", @($storeEvidence.PSObject.Properties.Name)) -ceq
        [string]::Join("`n", @('Valid', 'Thumbprint', 'RootStorePresent', 'TrustedPublisherPresent', 'Error'))
    ) 'certificate store evidence carries the exact ordered schema'
    [void]$tests.Add('exact certificate store evidence schema')

    Assert-SelfTest ([string]$storeEvidence.Thumbprint -ceq 'C3E805E2841D2C68790A7F4E8E93DB121EB0C046') 'certificate store evidence names WDRLocalTestCert'
    [void]$tests.Add('certificate store evidence names WDRLocalTestCert')

    foreach ($storeProbe in @(
            [pscustomobject]@{ StoreName = 'Root'; Property = 'RootStorePresent' },
            [pscustomobject]@{ StoreName = 'TrustedPublisher'; Property = 'TrustedPublisherPresent' }
        )) {
        $independentPresent = $false
        $independentStore = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeProbe.StoreName, 'LocalMachine')
        try {
            $independentStore.Open('ReadOnly')
            foreach ($candidate in $independentStore.Certificates) {
                if ([string]$candidate.Thumbprint -ceq 'C3E805E2841D2C68790A7F4E8E93DB121EB0C046') { $independentPresent = $true }
            }
        } finally { $independentStore.Close() }
        Assert-SelfTest ($storeEvidence.$($storeProbe.Property) -is [bool] -and
            [bool]$storeEvidence.$($storeProbe.Property) -eq $independentPresent) ('certificate store evidence agrees with an independent LocalMachine\' + $storeProbe.StoreName + ' read')
        [void]$tests.Add('agree with independent ' + $storeProbe.StoreName + ' read')
    }

    Write-Output (ConvertTo-CompactJson ([ordered]@{ schema = $Schema; overall = 'PASS'; tests = @($tests) }))
}

if ($SelfTest) {
    Invoke-SelfTests
    exit 0
}

$result = New-Result 'FAIL'
# Bind the launch journal before any tool can run. An unwritable or relative
# path is refused here rather than silently producing an empty tally, because a
# tally nobody could write reads exactly like a run that launched nothing.
if (-not [string]::IsNullOrWhiteSpace($LaunchJournalPath)) {
    if (-not [IO.Path]::IsPathRooted($LaunchJournalPath)) {
        Write-Error 'the launch journal path must be absolute'
        exit 2
    }
    $script:LaunchJournal = [IO.Path]::GetFullPath($LaunchJournalPath)
    [IO.File]::AppendAllText($script:LaunchJournal, '')
}
$packagePath = [System.IO.Path]::GetFullPath($PackageDirectory)
$artifactCheck = Test-PackageArtifacts $packagePath
$result.artifacts = $artifactCheck.Artifacts
foreach ($errorMessage in $artifactCheck.Errors) { Add-ResultError $result $errorMessage }
if ($result.errors.Count -gt 0) {
    Write-Output (ConvertTo-CompactJson $result)
    exit 1
}

try {
    $infPath = Join-Path $packagePath 'fsring_fsd.inf'
    $sysPath = Join-Path $packagePath 'fsring_fsd.sys'
    $catPath = Join-Path $packagePath 'fsring_fsd.cat'
    $architecture = Get-PackageArchitectureSectionSuffix $sysPath
    $inf = Parse-FsringInf ([System.IO.File]::ReadAllText($infPath))
    foreach ($errorMessage in (Test-FsringInfSemantics $inf $architecture)) { Add-ResultError $result $errorMessage }
    if ($result.errors.Count -gt 0) {
        Write-Output (ConvertTo-CompactJson $result)
        exit 1
    }

    $infverif = Resolve-PackageTool $InfVerifPath 'C:\Program Files (x86)\Windows Kits\10\Tools\10.0.26100.0\x64\infverif.exe' 'InfVerif 10.0.26100' 'infverif.exe' '10.0.26100'
    $signtool = Resolve-PackageTool $SignToolPath 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe' 'SignTool' 'SIGNTOOL.EXE' '10.0.22000'
    $infverifRun = Invoke-PackageTool $infverif.Path @('/v', '/w', $infPath) $infPath
    $result.tools.infverif = [ordered]@{
        path = $infverif.Path
        productVersion = $infverif.ProductVersion
        fileVersion = $infverif.FileVersion
        exitCode = $infverifRun.ExitCode
    }
    if ($infverifRun.ExitCode -ne 0) { Add-ResultError $result 'InfVerif rejected the built INF.' }

    $sysRun = Invoke-PackageTool $signtool.Path @('verify', '/v', '/kp', $sysPath) $sysPath
    $catRun = Invoke-PackageTool $signtool.Path @('verify', '/v', '/kp', $catPath) $catPath
    $catalogMemberRun = Invoke-PackageTool $signtool.Path @('verify', '/v', '/kp', '/c', $catPath, $sysPath) $sysPath
    $membershipRun = Test-WindowsCatalogMembership $sysPath $catPath
    # Authenticode-policy corroboration for the locally trusted test-root state.
    # These never substitute for the kernel-policy probes above; they only prove
    # the local chain validates, so the sole /kp objection is the Microsoft-root
    # rule. A package that is Trusted or UntrustedTestRoot ignores them.
    $authenticodeSysRun = Invoke-PackageTool $signtool.Path @('verify', '/v', '/pa', $sysPath) $sysPath
    $authenticodeCatRun = Invoke-PackageTool $signtool.Path @('verify', '/v', '/pa', $catPath) $catPath
    $authenticodeMemberRun = Invoke-PackageTool $signtool.Path @('verify', '/v', '/pa', '/c', $catPath, $sysPath) $sysPath
    $localTrustRun = [pscustomobject]@{
        Certificate = (Get-WDRLocalTestCertStoreEvidence)
        AuthenticodeSys = $authenticodeSysRun
        AuthenticodeCat = $authenticodeCatRun
        AuthenticodeCatalogMember = $authenticodeMemberRun
    }
    $signature = Test-SignatureEvidence $sysPath $catPath $sysRun $catRun $catalogMemberRun $membershipRun $localTrustRun
    $result.tools.signtool = [ordered]@{
        path = $signtool.Path
        productVersion = $signtool.ProductVersion
        fileVersion = $signtool.FileVersion
        policy = 'KernelMode'
        sysExitCode = $sysRun.ExitCode
        sysMode = $signature.SysMode
        catExitCode = $catRun.ExitCode
        catMode = $signature.CatMode
        catalogMemberExitCode = $catalogMemberRun.ExitCode
        catalogMemberMode = $signature.CatalogMemberMode
    }
    $result.tools.catalogMembership = [ordered]@{
        mechanism = 'Windows CryptCAT member-hash'
        valid = $membershipRun.Valid
        memberHash = $membershipRun.MemberHash
    }
    if (-not $signature.Valid) { Add-ResultError $result $signature.Error }
    if ($null -ne $signature.Warning) { Add-ResultWarning $result $signature.Warning }
    $result.trustReady = $signature.TrustReady
} catch {
    Add-ResultError $result $_.Exception.Message
}

if ($result.errors.Count -eq 0) { $result.overall = 'PASS' }
Write-Output (ConvertTo-CompactJson $result)
if ($result.overall -eq 'PASS') { exit 0 }
exit 1
