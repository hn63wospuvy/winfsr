[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('CreateRun', 'Check', 'CheckConfig', 'CheckIdentity')]
    [string] $Mode,

    [Parameter()]
    [string] $Directory,

    [Parameter()]
    [string] $Path,

    [Parameter()]
    [ValidateSet('File', 'Directory')]
    [string] $Kind,

    [Parameter()]
    [string[]] $AllowedName = @(),

    [Parameter()]
    [string[]] $RequiredName = @()
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if (-not ('Fsring.LockedCargo.DirectoryNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Fsring.LockedCargo
{
    public static class DirectoryNative
    {
        private const uint FILE_READ_ATTRIBUTES = 0x00000080;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateDirectoryW(
            string path,
            IntPtr securityAttributes);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(
            SafeFileHandle handle,
            StringBuilder path,
            uint pathLength,
            uint flags);

        public static string GetFinalDirectoryPath(string path)
        {
            using (SafeFileHandle handle = CreateFileW(
                path,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "CreateFileW(directory) failed.");
                }
                var buffer = new StringBuilder(32768);
                uint length = GetFinalPathNameByHandleW(
                    handle,
                    buffer,
                    (uint)buffer.Capacity,
                    0);
                if (length == 0 || length >= buffer.Capacity)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "GetFinalPathNameByHandleW(directory) failed.");
                }
                return buffer.ToString();
            }
        }

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
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetFinalPathNameByHandleW(file) failed.");
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

function Get-CheckedDirectory {
    param([Parameter(Mandatory = $true)][string] $Path)

    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw ('directory is not rooted: ' + $Path)
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $fullPath -Force
    if (-not $item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw ('directory is missing or a reparse point: ' + $fullPath)
    }
    $finalPath = Convert-NativePathToDosPath (
        [Fsring.LockedCargo.DirectoryNative]::GetFinalDirectoryPath($fullPath))
    $finalPath = [IO.Path]::GetFullPath($finalPath)
    if (-not [string]::Equals(
            $fullPath,
            $finalPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw ('directory final path differs: ' + $fullPath)
    }
    return $finalPath.TrimEnd('\')
}

function Test-DirectChild {
    param(
        [Parameter(Mandatory = $true)][string] $Parent,
        [Parameter(Mandatory = $true)][string] $Child
    )

    $prefix = $Parent.TrimEnd('\') + '\'
    return $Child.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -and
        $Child.Substring($prefix.Length).IndexOf('\') -lt 0
}

function Get-CheckedFile {
    param([Parameter(Mandatory = $true)][string] $Path)

    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw ('file is not rooted: ' + $Path)
    }
    $full = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $full -Force
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw ('file is missing or a reparse point: ' + $full)
    }
    $stream = New-Object IO.FileStream(
        $full,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $native = [Fsring.LockedCargo.DirectoryNative]::GetFinalPath(
            $stream.SafeFileHandle)
        $final = [IO.Path]::GetFullPath(
            (Convert-NativePathToDosPath $native))
        if (-not [string]::Equals(
                $full,
                $final,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw ('file final path differs: ' + $full)
        }
    } finally {
        $stream.Dispose()
    }
    return $full
}

try {
    if ($Mode -ceq 'CheckIdentity') {
        if ([string]::IsNullOrWhiteSpace($Path) -or
            [string]::IsNullOrWhiteSpace($Kind)) {
            throw 'identity mode requires Path and Kind'
        }
        if ($Kind -ceq 'File') {
            [void] (Get-CheckedFile -Path $Path)
        } else {
            [void] (Get-CheckedDirectory -Path $Path)
        }
        exit 0
    }

    if ($Mode -ceq 'CreateRun') {
        $driver = Get-CheckedDirectory -Path $env:FSRING_R2_DRIVER_ROOT
        $targetPath = [IO.Path]::GetFullPath(
            (Join-Path $driver 'target'))
        if (-not (Test-Path -LiteralPath $targetPath)) {
            if (-not [Fsring.LockedCargo.DirectoryNative]::CreateDirectoryW(
                    $targetPath,
                    [IntPtr]::Zero)) {
                throw ('CreateDirectoryW(target) failed: ' +
                    [Runtime.InteropServices.Marshal]::GetLastWin32Error())
            }
        }
        $target = Get-CheckedDirectory -Path $targetPath
        if (-not (Test-DirectChild -Parent $driver -Child $target)) {
            throw 'controlled target escaped the driver workspace'
        }

        $parentPath = [IO.Path]::GetFullPath(
            (Join-Path $target 'fsring-generated-tools'))
        if (-not (Test-Path -LiteralPath $parentPath)) {
            if (-not [Fsring.LockedCargo.DirectoryNative]::CreateDirectoryW(
                    $parentPath,
                    [IntPtr]::Zero)) {
                throw ('CreateDirectoryW(generated parent) failed: ' +
                    [Runtime.InteropServices.Marshal]::GetLastWin32Error())
            }
        }
        $parent = Get-CheckedDirectory -Path $parentPath
        if (-not (Test-DirectChild -Parent $target -Child $parent)) {
            throw 'generated-tools parent escaped the controlled target'
        }

        $runName = 'run-' + [Guid]::NewGuid().ToString('N')
        $runPath = [IO.Path]::GetFullPath((Join-Path $parent $runName))
        if (-not [Fsring.LockedCargo.DirectoryNative]::CreateDirectoryW(
                $runPath,
                [IntPtr]::Zero)) {
            throw ('CreateDirectoryW(create-new run) failed: ' +
                [Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
        $run = Get-CheckedDirectory -Path $runPath
        if (-not (Test-DirectChild -Parent $parent -Child $run)) {
            throw 'fresh run directory escaped the generated-tools parent'
        }

        [Console]::Out.WriteLine($target + '|' + $parent + '|' + $run)
        exit 0
    }

    if ($Mode -ceq 'CheckConfig') {
        $packageDirectory = Get-CheckedDirectory -Path $env:FSRING_R2_PACKAGE_CWD
        $expected = [IO.Path]::GetFullPath($env:FSRING_R2_EXPECTED_CONFIG)
        $found = New-Object 'Collections.Generic.HashSet[string]' (
            [StringComparer]::OrdinalIgnoreCase)

        $cursor = New-Object IO.DirectoryInfo($packageDirectory)
        while ($null -ne $cursor) {
            $cargoDirectory = Join-Path $cursor.FullName '.cargo'
            if (Test-Path -LiteralPath $cargoDirectory) {
                $cargoDirectory = Get-CheckedDirectory -Path $cargoDirectory
                foreach ($name in @('config', 'config.toml')) {
                    $candidate = Join-Path $cargoDirectory $name
                    if (Test-Path -LiteralPath $candidate) {
                        [void] $found.Add((Get-CheckedFile -Path $candidate))
                    }
                }
            }
            $cursor = $cursor.Parent
        }

        $defaultCargoHome = Join-Path $env:USERPROFILE '.cargo'
        if (Test-Path -LiteralPath $defaultCargoHome) {
            $defaultCargoHome = Get-CheckedDirectory -Path $defaultCargoHome
            foreach ($name in @('config', 'config.toml')) {
                $candidate = Join-Path $defaultCargoHome $name
                if (Test-Path -LiteralPath $candidate) {
                    [void] $found.Add((Get-CheckedFile -Path $candidate))
                }
            }
        }

        if ($found.Count -ne 1 -or -not $found.Contains($expected)) {
            throw ('unexpected Cargo config set: ' +
                (($found | Sort-Object) -join ','))
        }
        [void] (Get-CheckedFile -Path $expected)
        exit 0
    }

    if ([string]::IsNullOrWhiteSpace($Directory)) {
        throw 'check mode requires Directory'
    }
    if ($AllowedName.Count -eq 0 -and
        -not [string]::IsNullOrWhiteSpace($env:FSRING_R2_ALLOWED_NAMES)) {
        $AllowedName = @($env:FSRING_R2_ALLOWED_NAMES.Split(';'))
    }
    if ($RequiredName.Count -eq 0 -and
        -not [string]::IsNullOrWhiteSpace($env:FSRING_R2_REQUIRED_NAMES)) {
        $RequiredName = @($env:FSRING_R2_REQUIRED_NAMES.Split(';'))
    }
    $checked = Get-CheckedDirectory -Path $Directory
    $allowed = New-Object 'Collections.Generic.HashSet[string]' (
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $AllowedName) {
        if ([string]::IsNullOrWhiteSpace($name) -or
            $name.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0 -or
            -not $allowed.Add($name)) {
            throw ('invalid/duplicate allowed name: ' + $name)
        }
    }
    $required = New-Object 'Collections.Generic.HashSet[string]' (
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $RequiredName) {
        if (-not $allowed.Contains($name) -or -not $required.Add($name)) {
            throw ('invalid/duplicate required name: ' + $name)
        }
    }

    $seen = New-Object 'Collections.Generic.HashSet[string]' (
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($item in @(Get-ChildItem -LiteralPath $checked -Force)) {
        if ($item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            -not $allowed.Contains($item.Name) -or
            -not $seen.Add($item.Name)) {
            throw ('unapproved application-directory entry: ' + $item.Name)
        }
        $full = [IO.Path]::GetFullPath($item.FullName)
        $stream = New-Object IO.FileStream(
            $full,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        try {
            $native = [Fsring.LockedCargo.DirectoryNative]::GetFinalPath(
                $stream.SafeFileHandle)
            $final = [IO.Path]::GetFullPath(
                (Convert-NativePathToDosPath $native))
            if (-not [string]::Equals(
                    $full,
                    $final,
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw ('application entry final path differs: ' + $item.Name)
            }
        } finally {
            $stream.Dispose()
        }
    }
    foreach ($name in $required) {
        if (-not $seen.Contains($name)) {
            throw ('required application entry missing: ' + $name)
        }
    }
    exit 0
} catch {
    [Console]::Error.WriteLine(
        'NATIVE-DIRECTORY: FAIL: ' + $_.Exception.Message)
    exit 1
}
