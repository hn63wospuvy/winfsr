[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$MaxAttestationBytes = 64 * 1024
$MaxArguments = 64
$MaxFieldUtf16Units = 2048
$MaxTotalUtf16Units = 8192

if (-not ('Fsring.LockedCargo.NativePath' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Fsring.LockedCargo
{
    public static class NativePath
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(
            SafeFileHandle handle,
            StringBuilder path,
            uint pathLength,
            uint flags);

        public static string GetFinalPath(SafeFileHandle handle)
        {
            var buffer = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandleW(
                handle,
                buffer,
                (uint)buffer.Capacity,
                0);
            if (length == 0 || length >= buffer.Capacity)
            {
                throw new System.ComponentModel.Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetFinalPathNameByHandleW failed.");
            }
            return buffer.ToString();
        }
    }
}
'@
}

function Convert-NativePathToDosPath {
    param([Parameter(Mandatory = $true)][string] $Path)

    if ($Path.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
        return '\\' + $Path.Substring(8)
    }
    if ($Path.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) {
        return $Path.Substring(4)
    }
    return $Path
}

function Read-BoundedAttestation {
    param([Parameter(Mandatory = $true)][string] $Path)

    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw 'attestation path'
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $fullPath -Force
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'attestation regular file'
    }

    $stream = New-Object IO.FileStream(
        $fullPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::None,
        4096,
        [IO.FileOptions]::SequentialScan)
    try {
        $finalPath = Convert-NativePathToDosPath (
            [Fsring.LockedCargo.NativePath]::GetFinalPath($stream.SafeFileHandle))
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath($finalPath),
                $fullPath,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'attestation final path'
        }

        $length = $stream.Length
        if ($length -le 0 -or $length -gt $MaxAttestationBytes) {
            throw 'attestation size'
        }

        $bytes = New-Object byte[] ([int] $length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw 'attestation truncated'
            }
            $offset += $read
        }
        if ($stream.Length -ne $length -or $stream.ReadByte() -ne -1) {
            throw 'attestation changed'
        }
    } finally {
        $stream.Dispose()
    }

    if ($bytes.Length -ge 3 -and
        $bytes[0] -eq 0xEF -and
        $bytes[1] -eq 0xBB -and
        $bytes[2] -eq 0xBF) {
        throw 'attestation BOM'
    }
    $encoding = New-Object Text.UTF8Encoding($false, $true)
    $text = $encoding.GetString($bytes)
    if ($text.IndexOf([char] 0) -ge 0 -or
        $text.IndexOf("`r", [StringComparison]::Ordinal) -ge 0 -or
        -not $text.EndsWith("`n", [StringComparison]::Ordinal)) {
        throw 'attestation text'
    }

    $segments = $text.Split(
        [string[]] @("`n"),
        [StringSplitOptions]::None)
    if ($segments.Count -lt 2 -or $segments[-1] -cne '') {
        throw 'attestation lines'
    }
    return @($segments[0..($segments.Count - 2)])
}

function Decode-Hex {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Hex,
        [Parameter(Mandatory = $true)][string] $Field
    )

    if (($Hex.Length -band 3) -ne 0 -or
        $Hex -cnotmatch '^(?:[0-9A-F]{4})*$') {
        throw ('utf16 ' + $Field)
    }
    $units = [int] ($Hex.Length / 4)
    if ($units -gt $MaxFieldUtf16Units) {
        throw ('field size ' + $Field)
    }
    $script:DecodedUtf16Units += $units
    if ($script:DecodedUtf16Units -gt $MaxTotalUtf16Units) {
        throw 'decoded size'
    }

    $builder = New-Object Text.StringBuilder
    for ($index = 0; $index -lt $Hex.Length; $index += 4) {
        $unit = [Convert]::ToUInt16($Hex.Substring($index, 4), 16)
        if ($unit -ge 0xD800 -and $unit -le 0xDBFF) {
            if ($index + 4 -ge $Hex.Length) {
                throw ('utf16 surrogate ' + $Field)
            }
            $next = [Convert]::ToUInt16($Hex.Substring($index + 4, 4), 16)
            if ($next -lt 0xDC00 -or $next -gt 0xDFFF) {
                throw ('utf16 surrogate ' + $Field)
            }
            [void] $builder.Append([char] $unit)
            [void] $builder.Append([char] $next)
            $index += 4
        } elseif ($unit -ge 0xDC00 -and $unit -le 0xDFFF) {
            throw ('utf16 surrogate ' + $Field)
        } else {
            [void] $builder.Append([char] $unit)
        }
    }
    return $builder.ToString()
}

try {
    $lines = @(Read-BoundedAttestation -Path $env:FSRING_LOCKED_CARGO_ATTESTATION)
    if ($lines.Count -lt 13 -or
        $lines.Count -gt (13 + $MaxArguments) -or
        $lines[0] -cne 'fsring-locked-cargo-attestation') {
        throw 'header/count'
    }

    $script:LineIndex = 1
    $script:DecodedUtf16Units = 0
    function Read-Field {
        param([Parameter(Mandatory = $true)][string] $Name)

        $prefix = $Name + '='
        if ($script:LineIndex -ge $lines.Count) {
            throw ('missing ' + $Name)
        }
        $line = $lines[$script:LineIndex]
        $script:LineIndex++
        if (-not $line.StartsWith($prefix, [StringComparison]::Ordinal)) {
            throw ('field ' + $Name)
        }
        return $line.Substring($prefix.Length)
    }

    if ((Read-Field -Name 'format') -cne '2') {
        throw 'format'
    }
    $nonce = Decode-Hex (Read-Field -Name 'nonce_utf16') 'nonce'
    $realCargo = Decode-Hex (
        Read-Field -Name 'real_cargo_path_utf16') 'real_cargo_path'
    $realCargoHash = Read-Field -Name 'real_cargo_sha256'
    $toolchainCargo = Decode-Hex (
        Read-Field -Name 'toolchain_cargo_path_utf16') 'toolchain_cargo_path'
    $toolchainCargoHash = Read-Field -Name 'toolchain_cargo_sha256'
    $rustc = Decode-Hex (Read-Field -Name 'rustc_path_utf16') 'rustc_path'
    $rustcHash = Read-Field -Name 'rustc_sha256'
    $rustupHome = Decode-Hex (
        Read-Field -Name 'rustup_home_utf16') 'rustup_home'
    $targetDir = Decode-Hex (
        Read-Field -Name 'target_dir_utf16') 'target_dir'
    $toolchain = Decode-Hex (
        Read-Field -Name 'toolchain_utf16') 'toolchain'
    $countText = Read-Field -Name 'argument_count'

    if ($realCargoHash -cnotmatch '^[0-9A-F]{64}$' -or
        $toolchainCargoHash -cnotmatch '^[0-9A-F]{64}$' -or
        $rustcHash -cnotmatch '^[0-9A-F]{64}$') {
        throw 'hash syntax'
    }
    if ($countText -cnotmatch '^(?:0|[1-9][0-9]*)$') {
        throw 'argument count syntax'
    }
    $count = [int] $countText
    if ($count -gt $MaxArguments -or $lines.Count -ne (13 + $count)) {
        throw 'argument count'
    }

    $final = @()
    for ($index = 0; $index -lt $count; $index++) {
        $final += ,(Decode-Hex (
            Read-Field -Name ('argument_{0:D4}_utf16' -f $index)) (
            'argument_{0:D4}' -f $index))
    }
    if ($script:LineIndex -ne $lines.Count) {
        throw 'extra field'
    }

    if ($nonce -cne $env:FSRING_LOCKED_CARGO_NONCE -or
        $realCargo -cne $env:FSRING_REAL_CARGO -or
        $realCargoHash -cne $env:FSRING_REAL_CARGO_SHA256 -or
        $toolchainCargo -cne $env:FSRING_TOOLCHAIN_CARGO -or
        $toolchainCargoHash -cne $env:FSRING_TOOLCHAIN_CARGO_SHA256 -or
        $rustc -cne $env:FSRING_RUSTC -or
        $rustcHash -cne $env:FSRING_RUSTC_SHA256 -or
        $rustupHome -cne $env:FSRING_RUSTUP_HOME -or
        $targetDir -cne $env:FSRING_LOCKED_CARGO_TARGET_DIR -or
        $toolchain -cne '1.85.0') {
        throw 'identity'
    }
    if ($final.Count -lt 6 -or
        $final[0] -cne '+1.85.0' -or
        $final[1] -cne 'build' -or
        $final[-4] -cne '--target-dir' -or
        $final[-3] -cne $env:FSRING_LOCKED_CARGO_TARGET_DIR -or
        $final[-2] -cne '--locked' -or
        $final[-1] -cne '--offline') {
        throw 'boundary'
    }
    foreach ($singleton in @('--target-dir', '--locked', '--offline')) {
        if (@($final | Where-Object { $_ -ceq $singleton }).Count -ne 1) {
            throw ('suffix cardinality ' + $singleton)
        }
    }

    switch -CaseSensitive ($env:FSRING_ATTESTATION_KIND) {
        'win10-x64' {
            $expected = @(
                '+1.85.0', 'build', '-p', 'fsring-fsd',
                '--manifest-path', $env:FSRING_EXPECTED_MANIFEST,
                '--profile', 'release',
                '--target', 'x86_64-pc-windows-msvc',
                '--target-dir', $env:FSRING_LOCKED_CARGO_TARGET_DIR,
                '--locked', '--offline')
        }
        'win10-arm64' {
            $expected = @(
                '+1.85.0', 'build', '-p', 'fsring-fsd',
                '--manifest-path', $env:FSRING_EXPECTED_MANIFEST,
                '--profile', 'release',
                '--target', 'aarch64-pc-windows-msvc',
                '--target-dir', $env:FSRING_LOCKED_CARGO_TARGET_DIR,
                '--locked', '--offline')
        }
        'fixture' {
            $expected = @(
                '+1.85.0', 'build',
                '--manifest-path', $env:FSRING_FIXTURE_MANIFEST,
                '--target-dir', $env:FSRING_LOCKED_CARGO_TARGET_DIR,
                '--locked', '--offline')
        }
        default {
            throw 'kind'
        }
    }
    if ($final.Count -ne $expected.Count) {
        throw 'expected count'
    }
    for ($index = 0; $index -lt $expected.Count; $index++) {
        if ($final[$index] -cne $expected[$index]) {
            throw ('argument ' + $index)
        }
    }
    exit 0
} catch {
    [Console]::Error.WriteLine(
        'ATTESTATION: FAIL: ' + $_.Exception.Message)
    exit 1
}
