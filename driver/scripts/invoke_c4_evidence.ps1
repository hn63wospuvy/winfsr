# Binary-safe C4 evidence process capture, held-file leases, and containment
# proofs. Dot-sourcing defines functions only. Direct execution accepts -SelfTest.

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:C4EvidenceDotSourced = ($MyInvocation.InvocationName -eq '.')

if ($null -eq ('FsringC4EvidenceNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class FsringC4EvidenceNative
{
    public const uint CreateSuspended = 0x00000004;
    public const uint CreateBreakawayFromJob = 0x01000000;
    public const uint JobObjectExtendedLimitInformationClass = 9;
    public const uint JobObjectLimitKillOnJobClose = 0x00002000;
    public const uint JobObjectLimitBreakawayOk = 0x00000800;
    public const uint JobObjectLimitSilentBreakawayOk = 0x00001000;
    public const uint StartfUseStdHandles = 0x00000100;
    public const uint GenericRead = 0x80000000;
    public const uint FileShareRead = 0x00000001;
    public const uint OpenExisting = 3;
    public const uint FileFlagBackupSemantics = 0x02000000;
    public const int FileIdInfoClass = 18;
    public const int FileAttributeTagInfo = 9;
    public const uint HandleFlagInherit = 0x00000001;
    public const uint DriveRemote = 4;
    public const uint VolumeNameDos = 0;
    public const uint JobObjectBasicAccountingInformationClass = 1;
    public const uint WaitAbandoned = 0x00000080;
    public const uint WaitTimeout = 258;
    public const uint WaitFailed = 0xFFFFFFFF;
    public const int StillActive = 259;

    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct StartupInfo
    {
        public int Cb;
        public IntPtr Reserved;
        public IntPtr Desktop;
        public IntPtr Title;
        public int X;
        public int Y;
        public int XSize;
        public int YSize;
        public int XCountChars;
        public int YCountChars;
        public int FillAttribute;
        public uint Flags;
        public short ShowWindow;
        public short Reserved2;
        public IntPtr Reserved3;
        public IntPtr StdInput;
        public IntPtr StdOutput;
        public IntPtr StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileIdInfo
    {
        public ulong VolumeSerialNumber;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] FileId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public uint CreationTimeLow;
        public uint CreationTimeHigh;
        public uint LastAccessTimeLow;
        public uint LastAccessTimeHigh;
        public uint LastWriteTimeLow;
        public uint LastWriteTimeHigh;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectBasicAccountingInformation
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateJobObject(IntPtr attributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetInformationJobObject(
        IntPtr job,
        uint className,
        ref JobObjectExtendedLimitInformation info,
        int length);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool QueryInformationJobObject(
        IntPtr job,
        uint className,
        ref JobObjectExtendedLimitInformation info,
        int length,
        IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DuplicateHandle(
        IntPtr sourceProcess,
        IntPtr sourceHandle,
        IntPtr targetProcess,
        out IntPtr targetHandle,
        uint desiredAccess,
        bool inheritHandle,
        uint options);

    public const uint DuplicateSameAccess = 2;
    public const uint ProcessTerminate = 0x0001;
    public const uint ProcessSynchronize = 0x00100000;

    public static IntPtr DuplicateSame(IntPtr handle)
    {
        if (handle == IntPtr.Zero)
        {
            return IntPtr.Zero;
        }
        IntPtr copy;
        if (!DuplicateHandle(
                GetCurrentProcess(),
                handle,
                GetCurrentProcess(),
                out copy,
                0,
                false,
                DuplicateSameAccess))
        {
            return IntPtr.Zero;
        }
        return copy;
    }

    public sealed class JobTimeoutWatchdog
    {
        public volatile bool Fired;
        readonly Thread thread;

        public JobTimeoutWatchdog(IntPtr job, int timeoutMilliseconds, ManualResetEventSlim done)
        {
            thread = new Thread(() =>
            {
                int wait = timeoutMilliseconds < 0 ? 0 : timeoutMilliseconds;
                if (!done.Wait(wait))
                {
                    Fired = true;
                    if (job != IntPtr.Zero)
                    {
                        TerminateJobObject(job, 1);
                    }
                }
            });
            thread.IsBackground = true;
            thread.Start();
        }

        public void Join()
        {
            thread.Join(5000);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreatePipe(
        out IntPtr readPipe,
        out IntPtr writePipe,
        ref SecurityAttributes attributes,
        uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr process, out int exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr security,
        uint creationDisposition,
        uint flags,
        IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFileInformationByHandleEx(
        IntPtr file,
        int className,
        out FileIdInfo info,
        int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFileInformationByHandle(
        IntPtr file,
        out ByHandleFileInformation info);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern uint GetDriveTypeW(string rootPathName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateHardLinkW(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "QueryInformationJobObject")]
    public static extern bool QueryJobAccounting(
        IntPtr job,
        uint className,
        ref JobObjectBasicAccountingInformation info,
        int length,
        IntPtr returnLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool DefineDosDeviceW(uint flags, string deviceName, string targetPath);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint QueryDosDeviceW(string deviceName, StringBuilder targetPath, uint max);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetFinalPathNameByHandleW(
        IntPtr file,
        StringBuilder path,
        uint length,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadFile(
        IntPtr handle,
        byte[] buffer,
        int bytesToRead,
        out int bytesRead,
        IntPtr overlapped);

    public static Thread StartCopyHandle(IntPtr source, Stream dest)
    {
        Thread thread = new Thread(() =>
        {
            byte[] buffer = new byte[8192];
            int read;
            while (ReadFile(source, buffer, buffer.Length, out read, IntPtr.Zero) && read > 0)
            {
                dest.Write(buffer, 0, read);
            }
            dest.Flush();
        });
        thread.IsBackground = true;
        thread.Start();
        return thread;
    }

    // Windows command-line quoting, by the CRT's actual rule.
    //
    // Two things here are load-bearing, and both were learned from a failure.
    //
    // 1. An argument is quoted only when it needs to be. Quoting everything is
    //    right for a CRT argv parse and WRONG for a `cmd.exe /c` child, which
    //    takes its tail raw: `/c "ver"` reaches cmd as `"ver` and it answers
    //    '"ver' is not recognized. Row 05 (`cmd /d /c ver`) and rows 19/20
    //    (`cmd /d /c call build_matrix.cmd`) all died on that.
    //
    // 2. A backslash is only special immediately before a quote. Doubling
    //    every backslash corrupts any quoted path: InfVerif arrived as
    //    C:\\Program Files (x86)\\... and the receiving script rejected it as
    //    non-canonical. Filesystem APIs collapse redundant separators, which
    //    is why this hid for so long -- everything that merely OPENED the path
    //    worked, and only a script that compared it to GetFullPath noticed.
    //
    // The rule: a run of N backslashes becomes 2N before a quote or at the end
    // of a quoted argument, and stays N everywhere else.
    public static bool NeedsQuoting(string argument)
    {
        if (argument.Length == 0) { return true; }
        for (int i = 0; i < argument.Length; i++)
        {
            char c = argument[i];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '"') { return true; }
        }
        return false;
    }

    public static void AppendArgument(StringBuilder builder, string argument)
    {
        if (!NeedsQuoting(argument))
        {
            builder.Append(argument);
            return;
        }
        builder.Append('"');
        int index = 0;
        while (index < argument.Length)
        {
            int slashes = 0;
            while (index < argument.Length && argument[index] == '\\')
            {
                slashes++;
                index++;
            }
            if (index == argument.Length)
            {
                builder.Append('\\', slashes * 2);
                break;
            }
            if (argument[index] == '"')
            {
                builder.Append('\\', slashes * 2 + 1);
                builder.Append('"');
            }
            else
            {
                builder.Append('\\', slashes);
                builder.Append(argument[index]);
            }
            index++;
        }
        builder.Append('"');
    }

    public static string BuildCommandLine(string executable, string[] arguments)
    {
        StringBuilder builder = new StringBuilder();
        builder.Append('"').Append(executable).Append('"');
        if (arguments != null)
        {
            for (int i = 0; i < arguments.Length; i++)
            {
                builder.Append(' ');
                AppendArgument(builder, arguments[i]);
            }
        }
        return builder.ToString();
    }
}
'@
}

function Get-C4EvidenceUtf8 {
    return New-Object System.Text.UTF8Encoding $false, $true
}

function Get-C4EvidenceSha256Hex {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha.Dispose()
    }
}

function Get-C4GitBlobId {
    param([byte[]]$Bytes)
    $prefix = [Text.Encoding]::ASCII.GetBytes(('blob {0}' -f $Bytes.Length))
    $preimage = New-Object byte[] ($prefix.Length + 1 + $Bytes.Length)
    [Array]::Copy($prefix, 0, $preimage, 0, $prefix.Length)
    $preimage[$prefix.Length] = 0
    if ($Bytes.Length -gt 0) {
        [Array]::Copy($Bytes, 0, $preimage, $prefix.Length + 1, $Bytes.Length)
    }
    $sha1 = [Security.Cryptography.SHA1]::Create()
    try {
        return (($sha1.ComputeHash($preimage) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha1.Dispose()
    }
}

function ConvertTo-C4CanonicalJsonText {
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [string]) {
        $escaped = $Value.Replace('\', '\\').Replace('"', '\"')
        return ('"{0}"' -f $escaped)
    }
    if ($Value -is [byte] -or $Value -is [int] -or $Value -is [long] -or
        $Value -is [uint32] -or $Value -is [int64] -or $Value -is [decimal]) {
        return ([int64]$Value).ToString()
    }
    if ($Value -is [System.Array]) {
        $parts = @($Value | ForEach-Object { ConvertTo-C4CanonicalJsonText $_ })
        return ('[{0}]' -f ($parts -join ','))
    }
    if ($Value -is [Collections.IDictionary]) {
        $pairs = New-Object System.Collections.ArrayList
        foreach ($key in @($Value.Keys)) {
            [void]$pairs.Add(('"{0}":{1}' -f $key, (ConvertTo-C4CanonicalJsonText $Value[$key])))
        }
        return ('{{{0}}}' -f ($pairs -join ','))
    }
    $pairs = @(
        $Value.PSObject.Properties | ForEach-Object {
            '"{0}":{1}' -f $_.Name, (ConvertTo-C4CanonicalJsonText $_.Value)
        }
    )
    return ('{{{0}}}' -f ($pairs -join ','))
}

function ConvertFrom-C4CanonicalJsonBytes {
    param(
        [byte[]]$Bytes,
        [string]$ExpectedSchema
    )

    if ($null -eq $Bytes -or $Bytes.Length -lt 2) {
        throw 'canonical JSON is empty'
    }
    if ($Bytes[0] -eq 0xEF -and $Bytes.Length -ge 3 -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        throw 'canonical JSON carries a BOM'
    }
    if ($Bytes[$Bytes.Length - 1] -ne 10) {
        throw 'canonical JSON is missing a trailing LF'
    }
    $utf8 = Get-C4EvidenceUtf8
    $text = $utf8.GetString($Bytes, 0, $Bytes.Length - 1)
    if ($text.Contains([char]0)) { throw 'canonical JSON contains NUL' }
    $parsed = $text | ConvertFrom-Json
    if ($ExpectedSchema -and $parsed.schema -cne $ExpectedSchema) {
        throw ("schema is {0}, not {1}" -f $parsed.schema, $ExpectedSchema)
    }
    $reencoded = (ConvertTo-C4CanonicalJsonText $parsed) + "`n"
    $rebytes = (New-Object System.Text.UTF8Encoding $false).GetBytes($reencoded)
    if ($rebytes.Length -ne $Bytes.Length) {
        throw 'canonical JSON re-encoding length drifted'
    }
    for ($i = 0; $i -lt $Bytes.Length; $i++) {
        if ($rebytes[$i] -ne $Bytes[$i]) {
            throw 'canonical JSON re-encoding drifted'
        }
    }
    return $parsed
}

function Open-C4HeldFileLease {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string]$ExpectedSha256,
        [string]$ExpectedGitBlobId
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedSha256) -and [string]::IsNullOrWhiteSpace($ExpectedGitBlobId)) {
        throw 'a held lease requires SHA-256 and/or a Git blob ID'
    }
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) {
        throw 'held lease path must be absolute'
    }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -cne $Path) {
        throw 'held lease path is not canonical'
    }
    if ($full.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase) -or
        ($full.StartsWith('\\', [StringComparison]::Ordinal) -and
            -not $full.StartsWith('\\?\', [StringComparison]::Ordinal))) {
        throw 'held lease path is nonlocal'
    }
    $root = [IO.Path]::GetPathRoot($full)
    if ([FsringC4EvidenceNative]::GetDriveTypeW($root) -eq [FsringC4EvidenceNative]::DriveRemote) {
        throw 'held lease path is nonlocal'
    }
    $attrs = [IO.File]::GetAttributes($full)
    if (($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'held lease path is a reparse point'
    }
    $stream = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $bytes = New-Object byte[] $stream.Length
    $read = 0
    while ($read -lt $bytes.Length) {
        $got = $stream.Read($bytes, $read, $bytes.Length - $read)
        if ($got -le 0) { break }
        $read += $got
    }
    $sha = Get-C4EvidenceSha256Hex $bytes
    $blob = Get-C4GitBlobId $bytes
    if ($ExpectedSha256 -and $sha -cne $ExpectedSha256) {
        $stream.Dispose()
        throw 'held lease SHA-256 drifted'
    }
    if ($ExpectedGitBlobId -and $blob -cne $ExpectedGitBlobId) {
        $stream.Dispose()
        throw 'held lease Git blob ID drifted'
    }
    $handle = $stream.SafeFileHandle.DangerousGetHandle()
    $info = New-Object FsringC4EvidenceNative+FileIdInfo
    $ok = [FsringC4EvidenceNative]::GetFileInformationByHandleEx(
        $handle,
        [FsringC4EvidenceNative]::FileIdInfoClass,
        [ref]$info,
        [Runtime.InteropServices.Marshal]::SizeOf($info)
    )
    if (-not $ok) {
        $stream.Dispose()
        throw 'held lease native identity query failed'
    }
    $byHandle = New-Object FsringC4EvidenceNative+ByHandleFileInformation
    $linksOk = [FsringC4EvidenceNative]::GetFileInformationByHandle($handle, [ref]$byHandle)
    if (-not $linksOk) {
        $stream.Dispose()
        throw 'held lease link query failed'
    }
    # The link count is recorded, not required to be one. Windows keeps its own
    # system binaries hard-linked into the WinSxS component store, so demanding
    # a single link made the real powershell.exe, InfVerif.exe and signtool.exe
    # unleasable -- which is why this helper's own self-test had to lease a
    # *copy* of powershell.exe. What actually defends against reaching a
    # payload under another name is the GetFinalPathNameByHandleW equality
    # below, which returns the canonical opened path even for a file with
    # several links. Drift in the count is still a refusal: see
    # Assert-C4HeldFileLease, where a link added or removed after the lease was
    # taken fails.
    $observedLinks = [int]$byHandle.NumberOfLinks
    if ($observedLinks -lt 1) {
        $stream.Dispose()
        throw 'held lease reported no hard links'
    }
    $finalBuilder = New-Object System.Text.StringBuilder 32768
    $finalLen = [FsringC4EvidenceNative]::GetFinalPathNameByHandleW(
        $handle,
        $finalBuilder,
        [uint32]$finalBuilder.Capacity,
        [FsringC4EvidenceNative]::VolumeNameDos
    )
    if ($finalLen -eq 0) {
        $stream.Dispose()
        throw 'held lease final path query failed'
    }
    $finalPath = $finalBuilder.ToString()
    if ($finalPath.StartsWith('\\?\', [StringComparison]::Ordinal)) {
        $finalPath = $finalPath.Substring(4)
    }
    $finalFull = [IO.Path]::GetFullPath($finalPath)
    if (-not $finalFull.Equals($full, [StringComparison]::OrdinalIgnoreCase)) {
        $stream.Dispose()
        throw 'held lease path is an alias'
    }
    return [pscustomobject]@{
        Path = $full
        Stream = $stream
        Length = [int64]$bytes.Length
        Sha256 = $sha
        GitBlobId = $blob
        VolumeSerial = ('{0:X}' -f $info.VolumeSerialNumber).ToUpperInvariant()
        FileId = (($info.FileId | ForEach-Object { $_.ToString('X2') }) -join '')
        NumberOfLinks = $observedLinks
        ExpectedSha256 = $ExpectedSha256
        ExpectedGitBlobId = $ExpectedGitBlobId
    }
}

function Assert-C4HeldFileLease {
    param($Lease)
    $stream = $Lease.Stream
    $canonical = [IO.Path]::GetFullPath($Lease.Path)
    if ($Lease.Path -cne $canonical) { throw 'held lease path drifted' }
    $handle = $stream.SafeFileHandle.DangerousGetHandle()
    $info = New-Object FsringC4EvidenceNative+FileIdInfo
    $ok = [FsringC4EvidenceNative]::GetFileInformationByHandleEx(
        $handle,
        [FsringC4EvidenceNative]::FileIdInfoClass,
        [ref]$info,
        [Runtime.InteropServices.Marshal]::SizeOf($info)
    )
    if (-not $ok) { throw 'held lease native identity re-query failed' }
    $volume = ('{0:X}' -f $info.VolumeSerialNumber).ToUpperInvariant()
    $fileId = (($info.FileId | ForEach-Object { $_.ToString('X2') }) -join '')
    if ($volume -cne $Lease.VolumeSerial -or $fileId -cne $Lease.FileId) {
        throw 'held lease native identity drifted'
    }
    $byHandle = New-Object FsringC4EvidenceNative+ByHandleFileInformation
    if (-not [FsringC4EvidenceNative]::GetFileInformationByHandle($handle, [ref]$byHandle)) {
        throw 'held lease link re-query failed'
    }
    if ([int]$byHandle.NumberOfLinks -ne [int]$Lease.NumberOfLinks) {
        throw 'held lease hard link count drifted'
    }
    $finalBuilder = New-Object System.Text.StringBuilder 32768
    $finalLen = [FsringC4EvidenceNative]::GetFinalPathNameByHandleW(
        $handle,
        $finalBuilder,
        [uint32]$finalBuilder.Capacity,
        [FsringC4EvidenceNative]::VolumeNameDos
    )
    if ($finalLen -eq 0) { throw 'held lease final path re-query failed' }
    $finalPath = $finalBuilder.ToString()
    if ($finalPath.StartsWith('\\?\', [StringComparison]::Ordinal)) {
        $finalPath = $finalPath.Substring(4)
    }
    if (-not [IO.Path]::GetFullPath($finalPath).Equals($Lease.Path, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'held lease canonical path drifted'
    }
    $stream.Position = 0
    $bytes = New-Object byte[] $stream.Length
    $read = 0
    while ($read -lt $bytes.Length) {
        $got = $stream.Read($bytes, $read, $bytes.Length - $read)
        if ($got -le 0) { break }
        $read += $got
    }
    $sha = Get-C4EvidenceSha256Hex $bytes
    $blob = Get-C4GitBlobId $bytes
    if ($sha -cne $Lease.Sha256 -or [int64]$bytes.Length -ne [int64]$Lease.Length) { throw 'held lease bytes drifted' }
    if ($Lease.ExpectedSha256 -and $sha -cne $Lease.ExpectedSha256) { throw 'held lease expected SHA-256 drifted' }
    if ($Lease.ExpectedGitBlobId -and $blob -cne $Lease.ExpectedGitBlobId) { throw 'held lease expected blob drifted' }
}

function Close-C4HeldFileLease {
    param($Lease)
    if ($null -ne $Lease -and $null -ne $Lease.Stream) {
        $Lease.Stream.Dispose()
    }
}

function Write-C4CapturedExit {
    param(
        [string]$ExitPath,
        [ValidateSet('CanonicalJson', 'CodeText')]
        [string]$ExitFormat,
        [string]$Termination,
        $ObservedExit,
        [bool]$TimedOut
    )

    $utf8 = New-Object System.Text.UTF8Encoding $false
    if ($ExitFormat -ceq 'CodeText') {
        $text = switch ($Termination) {
            'NORMAL' { ([int]$ObservedExit).ToString() + "`n" }
            'TIMEOUT' { "TIMEOUT`n" }
            'START_FAILED' { "START_FAILED`n" }
            'CAPTURE_FAILED' { "CAPTURE_FAILED`n" }
            'NOT_ISSUED' { "NOT_ISSUED`n" }
            default { throw 'unknown CodeText termination' }
        }
        [IO.File]::WriteAllBytes($ExitPath, $utf8.GetBytes($text))
        return
    }
    $exitValue = $null
    if ($Termination -ceq 'NORMAL') { $exitValue = [int]$ObservedExit }
    $object = [ordered]@{
        schema = 'fsring-captured-exit/v1'
        version = 1
        observedExit = $exitValue
        timedOut = [bool]$TimedOut
        termination = $Termination
    }
    $json = (ConvertTo-C4CanonicalJsonText $object) + "`n"
    [IO.File]::WriteAllBytes($ExitPath, $utf8.GetBytes($json))
}

function Wait-C4OwnedProcessTree {
    param(
        [IntPtr]$Job,
        [IntPtr]$Process,
        [uint32]$TimeoutMilliseconds = 5000
    )

    $processExited = $false
    if ($Process -ne [IntPtr]::Zero) {
        $wait = [FsringC4EvidenceNative]::WaitForSingleObject($Process, $TimeoutMilliseconds)
        if ($wait -eq 0) {
            $code = 259
            [void][FsringC4EvidenceNative]::GetExitCodeProcess($Process, [ref]$code)
            if ($code -ne [FsringC4EvidenceNative]::StillActive) {
                $processExited = $true
            }
        }
    }
    $jobIdle = $false
    if ($Job -ne [IntPtr]::Zero) {
        $acct = New-Object FsringC4EvidenceNative+JobObjectBasicAccountingInformation
        $queried = [FsringC4EvidenceNative]::QueryJobAccounting(
            $Job,
            [FsringC4EvidenceNative]::JobObjectBasicAccountingInformationClass,
            [ref]$acct,
            [Runtime.InteropServices.Marshal]::SizeOf($acct),
            [IntPtr]::Zero
        )
        if ($queried) {
            $jobIdle = ($acct.ActiveProcesses -eq 0)
        }
    }
    if ($Job -eq [IntPtr]::Zero) {
        return $processExited
    }
    return ($processExited -and $jobIdle)
}

function Invoke-C4EvidenceProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,
        [int]$TimeoutMilliseconds = 30000,
        [Parameter(Mandatory = $true)]
        [string]$StdoutPath,
        [Parameter(Mandatory = $true)]
        [string]$StderrPath,
        [Parameter(Mandatory = $true)]
        [string]$ExitPath,
        [ValidateSet('CanonicalJson', 'CodeText')]
        [string]$ExitFormat = 'CanonicalJson',
        [string]$ContainmentEvidencePath,
        [ValidateSet('PREFLIGHT_INITIAL', 'PREFLIGHT_FINAL', 'LIVE', 'CLEANUP_RECOVERY')]
        [string]$ContainmentRole,
        [string]$ContainmentAttemptId,
        [scriptblock]$DuplexHandler,
        [scriptblock]$BeforeResume,
        [scriptblock]$BeforeAssign,
        [ValidateSet('', 'JobConfig', 'Assign', 'Resume', 'UnconfirmedWait')]
        [string]$FaultInjection = ''
    )

    $triple = @(
        [string]$ContainmentEvidencePath,
        [string]$ContainmentRole,
        [string]$ContainmentAttemptId
    )
    $supplied = @($triple | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
    if ($supplied -ne 0 -and $supplied -ne 3) {
        throw 'containment triple is all-or-none'
    }

    foreach ($path in @($StdoutPath, $StderrPath, $ExitPath)) {
        if (-not [IO.Path]::IsPathRooted($path)) {
            throw ("destination is not absolute: {0}" -f $path)
        }
        $full = [IO.Path]::GetFullPath($path)
        if ($full -cne $path -or $path.Contains('..')) {
            throw ("destination path escape: {0}" -f $path)
        }
        if ([IO.File]::Exists($path)) {
            throw ("destination already exists: {0}" -f $path)
        }
    }
    if ($StdoutPath -ceq $StderrPath -or $StdoutPath -ceq $ExitPath -or $StderrPath -ceq $ExitPath) {
        throw 'merged capture streams are refused'
    }
    try {
        $stdout = New-Object IO.FileStream($StdoutPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read, 4096, $false)
        $stderr = New-Object IO.FileStream($StderrPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read, 4096, $false)
        $exitReserved = New-Object IO.FileStream($ExitPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read, 4096, $false)
        $exitReserved.Dispose()
    } catch {
        throw ("failed opening capture destinations stdout=$StdoutPath stderr=$StderrPath exit=$ExitPath : " + $_.Exception.Message)
    }
    $created = $false
    $job = [IntPtr]::Zero
    $process = [IntPtr]::Zero
    $thread = [IntPtr]::Zero
    $stdoutRead = [IntPtr]::Zero
    $stdoutWrite = [IntPtr]::Zero
    $stderrRead = [IntPtr]::Zero
    $stderrWrite = [IntPtr]::Zero
    $stdinRead = [IntPtr]::Zero
    $stdinWrite = [IntPtr]::Zero
    $termination = 'START_FAILED'
    $observedExit = $null
    $timedOut = $false
    $pidValue = 0
    $createdSuspended = $false
    $jobKill = $false
    $breakawayDisabled = $false
    $assigned = $false
    $resumed = $false
    $terminationAttempted = $false
    $treeExited = $false
    $streamsClosed = $false

    try {
        if (-not [IO.File]::Exists($Executable)) {
            $stdout.Dispose(); $stderr.Dispose()
            Write-C4CapturedExit $ExitPath $ExitFormat 'START_FAILED' $null $false
            return
        }
        $sa = New-Object FsringC4EvidenceNative+SecurityAttributes
        $sa.Length = [Runtime.InteropServices.Marshal]::SizeOf($sa)
        $sa.InheritHandle = 1
        if (-not [FsringC4EvidenceNative]::CreatePipe([ref]$stdoutRead, [ref]$stdoutWrite, [ref]$sa, 0)) {
            throw 'CreatePipe stdout failed'
        }
        if (-not [FsringC4EvidenceNative]::CreatePipe([ref]$stderrRead, [ref]$stderrWrite, [ref]$sa, 0)) {
            throw 'CreatePipe stderr failed'
        }
        [void][FsringC4EvidenceNative]::SetHandleInformation($stdoutRead, [FsringC4EvidenceNative]::HandleFlagInherit, 0)
        [void][FsringC4EvidenceNative]::SetHandleInformation($stderrRead, [FsringC4EvidenceNative]::HandleFlagInherit, 0)
        if ($null -ne $DuplexHandler) {
            if (-not [FsringC4EvidenceNative]::CreatePipe([ref]$stdinRead, [ref]$stdinWrite, [ref]$sa, 0)) {
                throw 'CreatePipe stdin failed'
            }
            [void][FsringC4EvidenceNative]::SetHandleInformation($stdinWrite, [FsringC4EvidenceNative]::HandleFlagInherit, 0)
        }

        $startup = New-Object FsringC4EvidenceNative+StartupInfo
        $startup.Cb = [Runtime.InteropServices.Marshal]::SizeOf($startup)
        $startup.Flags = [FsringC4EvidenceNative]::StartfUseStdHandles
        $startup.StdOutput = $stdoutWrite
        $startup.StdError = $stderrWrite
        if ($null -ne $DuplexHandler) {
            $startup.StdInput = $stdinRead
        }
        $command = [FsringC4EvidenceNative]::BuildCommandLine($Executable, $Arguments)
        $builder = New-Object System.Text.StringBuilder $command
        $info = New-Object FsringC4EvidenceNative+ProcessInformation
        $createdOk = [FsringC4EvidenceNative]::CreateProcessW(
            $Executable,
            $builder,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            $true,
            [FsringC4EvidenceNative]::CreateSuspended,
            [IntPtr]::Zero,
            $WorkingDirectory,
            [ref]$startup,
            [ref]$info
        )
        if (-not $createdOk) {
            $stdout.Dispose(); $stderr.Dispose()
            Write-C4CapturedExit $ExitPath $ExitFormat 'START_FAILED' $null $false
            return
        }
        $created = $true
        $createdSuspended = $true
        $process = $info.Process
        $thread = $info.Thread
        $pidValue = [int]$info.ProcessId
        [void][FsringC4EvidenceNative]::CloseHandle($stdoutWrite)
        [void][FsringC4EvidenceNative]::CloseHandle($stderrWrite)
        $stdoutWrite = [IntPtr]::Zero
        $stderrWrite = [IntPtr]::Zero

        $job = [FsringC4EvidenceNative]::CreateJobObject([IntPtr]::Zero, $null)
        if ($job -eq [IntPtr]::Zero) {
            $termination = 'CAPTURE_FAILED'
            throw 'CreateJobObject failed'
        }
        $limit = New-Object FsringC4EvidenceNative+JobObjectExtendedLimitInformation
        $limit.BasicLimitInformation.LimitFlags = [FsringC4EvidenceNative]::JobObjectLimitKillOnJobClose
        if (-not [FsringC4EvidenceNative]::SetInformationJobObject(
                $job,
                [FsringC4EvidenceNative]::JobObjectExtendedLimitInformationClass,
                [ref]$limit,
                [Runtime.InteropServices.Marshal]::SizeOf($limit)
            )) {
            $termination = 'CAPTURE_FAILED'
            throw 'SetInformationJobObject failed'
        }
        $jobKill = $true
        $queried = New-Object FsringC4EvidenceNative+JobObjectExtendedLimitInformation
        [void][FsringC4EvidenceNative]::QueryInformationJobObject(
            $job,
            [FsringC4EvidenceNative]::JobObjectExtendedLimitInformationClass,
            [ref]$queried,
            [Runtime.InteropServices.Marshal]::SizeOf($queried),
            [IntPtr]::Zero
        )
        $flags = $queried.BasicLimitInformation.LimitFlags
        $breakawayDisabled = (
            ($flags -band [FsringC4EvidenceNative]::JobObjectLimitBreakawayOk) -eq 0 -and
            ($flags -band [FsringC4EvidenceNative]::JobObjectLimitSilentBreakawayOk) -eq 0
        )
        if ($FaultInjection -ceq 'JobConfig') {
            $jobKill = $false
            $termination = 'CAPTURE_FAILED'
            throw 'SetInformationJobObject failed'
        }
        if ($null -ne $BeforeAssign) {
            & $BeforeAssign ([pscustomobject]@{ ProcessId = $pidValue; Process = $process; Thread = $thread })
        }
        if ($FaultInjection -ceq 'Assign' -or
            -not [FsringC4EvidenceNative]::AssignProcessToJobObject($job, $process)) {
            $termination = 'CAPTURE_FAILED'
            throw 'AssignProcessToJobObject failed'
        }
        $assigned = $true
        if ($null -ne $BeforeResume) {
            & $BeforeResume ([pscustomobject]@{
                ProcessId = $pidValue
                Process = $process
                Job = $job
                Thread = $thread
            })
        }
        if ($FaultInjection -ceq 'Resume') {
            $termination = 'CAPTURE_FAILED'
            throw 'ResumeThread failed'
        }
        $resume = [FsringC4EvidenceNative]::ResumeThread($thread)
        if ($resume -eq [uint32]::MaxValue) {
            $termination = 'CAPTURE_FAILED'
            throw 'ResumeThread failed'
        }
        $resumed = $true
        [void][FsringC4EvidenceNative]::CloseHandle($thread)
        $thread = [IntPtr]::Zero
        if ($stdinRead -ne [IntPtr]::Zero) {
            [void][FsringC4EvidenceNative]::CloseHandle($stdinRead)
            $stdinRead = [IntPtr]::Zero
        }

        $duplexWatchdog = $null
        $startedUtc = [DateTime]::UtcNow
        if ($null -ne $DuplexHandler) {
            $duplexDone = New-Object System.Threading.ManualResetEventSlim $false
            $duplexWatchdog = New-Object FsringC4EvidenceNative+JobTimeoutWatchdog(
                $job,
                [int]$TimeoutMilliseconds,
                $duplexDone
            )
            $duplex = [pscustomobject]@{
                ProcessId = $pidValue
                StdinWrite = $stdinWrite
                StdoutRead = $stdoutRead
                StderrRead = $stderrRead
                StdoutStream = $stdout
                StderrStream = $stderr
                TimeoutMilliseconds = $TimeoutMilliseconds
            }
            try {
                & $DuplexHandler $duplex
            } catch {
                if (-not $duplexWatchdog.Fired) { throw }
            } finally {
                $duplexDone.Set()
                $duplexWatchdog.Join()
            }
            if ($stdinWrite -ne [IntPtr]::Zero) {
                [void][FsringC4EvidenceNative]::CloseHandle($stdinWrite)
                $stdinWrite = [IntPtr]::Zero
            }
            if ($duplexWatchdog.Fired) {
                $timedOut = $true
                $termination = 'TIMEOUT'
                $terminationAttempted = $true
            }
        }

        $outThread = [FsringC4EvidenceNative]::StartCopyHandle($stdoutRead, $stdout)
        $errThread = [FsringC4EvidenceNative]::StartCopyHandle($stderrRead, $stderr)
        $elapsedMs = [int]([DateTime]::UtcNow - $startedUtc).TotalMilliseconds
        if ($elapsedMs -lt 0) { $elapsedMs = 0 }
        $remainingMs = [int]$TimeoutMilliseconds - $elapsedMs
        if ($remainingMs -lt 0) { $remainingMs = 0 }
        if ($timedOut) {
            $wait = 258
        } else {
            $wait = [FsringC4EvidenceNative]::WaitForSingleObject($process, [uint32]$remainingMs)
        }
        if ($wait -eq 258) {
            $timedOut = $true
            $termination = 'TIMEOUT'
            $terminationAttempted = $true
            [void][FsringC4EvidenceNative]::TerminateJobObject($job, 1)
            if ($FaultInjection -cne 'UnconfirmedWait') {
                $treeExited = Wait-C4OwnedProcessTree -Job $job -Process $process -TimeoutMilliseconds 5000
            }
        } else {
            $code = 259
            $deadline = [DateTime]::UtcNow.AddSeconds(5)
            while ($code -eq 259 -and [DateTime]::UtcNow -lt $deadline) {
                [void][FsringC4EvidenceNative]::GetExitCodeProcess($process, [ref]$code)
                if ($code -eq 259) { Start-Sleep -Milliseconds 20 }
            }
            $observedExit = $code
            $termination = 'NORMAL'
        }
        [void]$outThread.Join(5000)
        [void]$errThread.Join(5000)
        if ($stdoutRead -ne [IntPtr]::Zero) {
            [void][FsringC4EvidenceNative]::CloseHandle($stdoutRead)
            $stdoutRead = [IntPtr]::Zero
        }
        if ($stderrRead -ne [IntPtr]::Zero) {
            [void][FsringC4EvidenceNative]::CloseHandle($stderrRead)
            $stderrRead = [IntPtr]::Zero
        }
        $streamsClosed = $true
        if ($termination -ceq 'NORMAL') {
            $treeExited = Wait-C4OwnedProcessTree -Job $job -Process $process -TimeoutMilliseconds 5000
        }
        if ($termination -ceq 'NORMAL' -and $timedOut) { $termination = 'TIMEOUT' }
    } catch {
        if ($created) { $termination = 'CAPTURE_FAILED' }
        if ($job -ne [IntPtr]::Zero -or $process -ne [IntPtr]::Zero) {
            $terminationAttempted = $true
            if ($job -ne [IntPtr]::Zero) {
                [void][FsringC4EvidenceNative]::TerminateJobObject($job, 1)
            }
            if ($process -ne [IntPtr]::Zero) {
                [void][FsringC4EvidenceNative]::TerminateProcess($process, 1)
            }
            if ($FaultInjection -cne 'UnconfirmedWait') {
                $treeExited = Wait-C4OwnedProcessTree -Job $job -Process $process -TimeoutMilliseconds 5000
            }
        }
    } finally {
        $jobHandle = $job
        $processHandle = $process
        if ($thread -ne [IntPtr]::Zero) { [void][FsringC4EvidenceNative]::CloseHandle($thread); $thread = [IntPtr]::Zero }
        if ($stdinWrite -ne [IntPtr]::Zero) { [void][FsringC4EvidenceNative]::CloseHandle($stdinWrite); $stdinWrite = [IntPtr]::Zero }
        if ($stdinRead -ne [IntPtr]::Zero) { [void][FsringC4EvidenceNative]::CloseHandle($stdinRead); $stdinRead = [IntPtr]::Zero }
        try { $stdout.Dispose() } catch {}
        try { $stderr.Dispose() } catch {}
        $streamsClosed = $true
        $unconfirmed = (
            $created -and
            ($termination -ceq 'TIMEOUT' -or $termination -ceq 'CAPTURE_FAILED') -and
            -not $treeExited
        )
        $sealable = -not ($unconfirmed -and $supplied -ne 3)
        if ($processHandle -ne [IntPtr]::Zero) { [void][FsringC4EvidenceNative]::CloseHandle($processHandle); $process = [IntPtr]::Zero }
        if ($jobHandle -ne [IntPtr]::Zero) { [void][FsringC4EvidenceNative]::CloseHandle($jobHandle); $job = [IntPtr]::Zero }
        if ($sealable -and (
                $termination -ceq 'START_FAILED' -or
                $termination -ceq 'CAPTURE_FAILED' -or
                $termination -ceq 'TIMEOUT' -or
                $termination -ceq 'NORMAL')) {
            Write-C4CapturedExit $ExitPath $ExitFormat $termination $observedExit $timedOut
        }
        if ($supplied -eq 3 -and $created -and ($termination -ceq 'TIMEOUT' -or $termination -ceq 'CAPTURE_FAILED')) {
            $allTrue = (
                $createdSuspended -and $jobKill -and $breakawayDisabled -and
                $assigned -and $resumed -and $terminationAttempted -and
                $treeExited -and $streamsClosed
            )
            $proof = [ordered]@{
                schema = 'fsring-c4-process-containment/v1'
                version = 1
                attemptId = $ContainmentAttemptId
                captureRole = $ContainmentRole
                childProcessId = $pidValue
                createdSuspended = [bool]$createdSuspended
                jobKillOnClose = [bool]$jobKill
                breakawayDisabled = [bool]$breakawayDisabled
                jobAssignedBeforeResume = [bool]$assigned
                mainThreadResumed = [bool]$resumed
                terminationAttempted = [bool]$terminationAttempted
                treeExited = [bool]$treeExited
                streamsClosed = [bool]$streamsClosed
                status = $(if ($allTrue) { 'PASS' } else { 'FAIL' })
            }
            $json = (ConvertTo-C4CanonicalJsonText $proof) + "`n"
            $utf8 = New-Object System.Text.UTF8Encoding $false
            $tmp = [IO.File]::Open($ContainmentEvidencePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $bytes = $utf8.GetBytes($json)
                $tmp.Write($bytes, 0, $bytes.Length)
                $tmp.Flush()
            } finally {
                $tmp.Dispose()
            }
        }
    }
    if ($created -and
        ($termination -ceq 'TIMEOUT' -or $termination -ceq 'CAPTURE_FAILED') -and
        -not $treeExited -and
        $supplied -ne 3) {
        throw 'owned tree or stream closure was not confirmed'
    }
}

function Invoke-C4HeldPowerShellScript {
    param($PowerShellLease, $ScriptLease, [string[]]$Arguments)
    Assert-C4HeldFileLease $PowerShellLease
    Assert-C4HeldFileLease $ScriptLease
    $root = Join-Path $env:TEMP ('fsring-c4-held-script-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($root)
    try {
        $out = Join-Path $root 'stdout.bin'
        $err = Join-Path $root 'stderr.bin'
        $exit = Join-Path $root 'exit.json'
        $argList = @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $ScriptLease.Path
        ) + @($Arguments)
        Invoke-C4EvidenceProcess -Executable $PowerShellLease.Path -Arguments $argList `
            -WorkingDirectory ([IO.Path]::GetDirectoryName($ScriptLease.Path)) `
            -TimeoutMilliseconds 120000 `
            -StdoutPath $out -StderrPath $err -ExitPath $exit -ExitFormat CanonicalJson
        Assert-C4HeldFileLease $PowerShellLease
        Assert-C4HeldFileLease $ScriptLease
        $obj = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($exit)) -ExpectedSchema 'fsring-captured-exit/v1'
        if ($obj.termination -cne 'NORMAL') {
            throw ("held powershell termination was {0}" -f $obj.termination)
        }
        return [int]$obj.observedExit
    } finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-C4HeldPowerShellJson {
    param($PowerShellLease, $ScriptLease, [string[]]$Arguments)
    Assert-C4HeldFileLease $PowerShellLease
    Assert-C4HeldFileLease $ScriptLease
    $root = Join-Path $env:TEMP ('fsring-c4-held-json-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($root)
    try {
        $out = Join-Path $root 'stdout.bin'
        $err = Join-Path $root 'stderr.bin'
        $exit = Join-Path $root 'exit.json'
        $argList = @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $ScriptLease.Path
        ) + @($Arguments)
        Invoke-C4EvidenceProcess -Executable $PowerShellLease.Path -Arguments $argList `
            -WorkingDirectory ([IO.Path]::GetDirectoryName($ScriptLease.Path)) `
            -TimeoutMilliseconds 120000 `
            -StdoutPath $out -StderrPath $err -ExitPath $exit -ExitFormat CanonicalJson
        $stdoutBytes = [IO.File]::ReadAllBytes($out)
        $stderrBytes = [IO.File]::ReadAllBytes($err)
        if ($stdoutBytes.Length -gt 65536 -or $stderrBytes.Length -gt 65536) {
            throw 'held JSON capture overflowed 65536 bytes'
        }
        Assert-C4HeldFileLease $PowerShellLease
        Assert-C4HeldFileLease $ScriptLease
        $obj = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($exit)) -ExpectedSchema 'fsring-captured-exit/v1'
        if ($obj.termination -cne 'NORMAL') {
            throw ("held powershell json termination was {0}" -f $obj.termination)
        }
        return [pscustomobject]@{
            ExitCode = [int]$obj.observedExit
            StdoutBytes = $stdoutBytes
            StderrBytes = $stderrBytes
        }
    } finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-C4EvidenceSelfTests {
    $root = Join-Path $env:TEMP ('fsring-c4-evidence-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($root)
    $failures = New-Object System.Collections.ArrayList
    function Assert-Ev([bool]$Condition, [string]$Message) {
        if (-not $Condition) { throw $Message }
    }
    try {
        $cmd = Join-Path $PSHOME 'powershell.exe'
        $out = Join-Path $root 'stdout.bin'
        $err = Join-Path $root 'stderr.bin'
        $exit = Join-Path $root 'exit.json'
        Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-NonInteractive', '-Command', 'Write-Output hello; exit 0') `
            -WorkingDirectory $root -TimeoutMilliseconds 20000 `
            -StdoutPath $out -StderrPath $err -ExitPath $exit -ExitFormat CanonicalJson
        $exitObj = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($exit)) -ExpectedSchema 'fsring-captured-exit/v1'
        Assert-Ev ($exitObj.termination -ceq 'NORMAL') 'normal exit was not NORMAL'
        Assert-Ev ($exitObj.observedExit -eq 0) ('normal observedExit drifted: ' + [string]$exitObj.observedExit)
        Assert-Ev ([IO.File]::ReadAllBytes($out).Length -gt 0) 'stdout was empty'

        $out2 = Join-Path $root 'stdout2.bin'
        $err2 = Join-Path $root 'stderr2.bin'
        $exit2 = Join-Path $root 'exit2.txt'
        Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-NonInteractive', '-Command', 'exit 7') `
            -WorkingDirectory $root -TimeoutMilliseconds 20000 `
            -StdoutPath $out2 -StderrPath $err2 -ExitPath $exit2 -ExitFormat CodeText
        $codeText = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($exit2))
        Assert-Ev ($codeText -ceq "7`n") "CodeText nonzero drifted: $codeText"

        $out3 = Join-Path $root 'stdout3.bin'
        $err3 = Join-Path $root 'stderr3.bin'
        $exit3 = Join-Path $root 'exit3.json'
        Invoke-C4EvidenceProcess -Executable (Join-Path $root 'missing.exe') -Arguments @() `
            -WorkingDirectory $root -TimeoutMilliseconds 5000 `
            -StdoutPath $out3 -StderrPath $err3 -ExitPath $exit3 -ExitFormat CanonicalJson
        $start = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($exit3)) -ExpectedSchema 'fsring-captured-exit/v1'
        Assert-Ev ($start.termination -ceq 'START_FAILED') 'missing exe was not START_FAILED'
        Assert-Ev ($null -eq $start.observedExit) 'START_FAILED carried an exit'
        Assert-Ev ([IO.File]::ReadAllBytes($out3).Length -eq 0) 'START_FAILED stdout was not zero'

        $nulOut = Join-Path $root 'binary.stdout.bin'
        $nulErr = Join-Path $root 'binary.stderr.bin'
        $nulExit = Join-Path $root 'binary.exit.json'
        Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-NonInteractive', '-Command', '[Console]::OpenStandardOutput().Write([byte[]](0,1,255),0,3)') `
            -WorkingDirectory $root -TimeoutMilliseconds 20000 `
            -StdoutPath $nulOut -StderrPath $nulErr -ExitPath $nulExit -ExitFormat CanonicalJson

        $pre = Join-Path $root 'preexists.txt'
        [IO.File]::WriteAllText($pre, 'x')
        $caught = $false
        try {
            Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-Command', 'exit 0') `
                -WorkingDirectory $root -TimeoutMilliseconds 5000 `
                -StdoutPath $pre -StderrPath (Join-Path $root 'x.err') -ExitPath (Join-Path $root 'x.exit') `
                -ExitFormat CodeText
        } catch {
            $caught = $true
        }
        Assert-Ev $caught 'pre-existing destination was not refused'

        $timeoutOut = Join-Path $root 't.out'
        $timeoutErr = Join-Path $root 't.err'
        $timeoutExit = Join-Path $root 't.exit.json'
        $proof = Join-Path $root 'live-process-containment.json'
        $attempt = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
        Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 20') `
            -WorkingDirectory $root -TimeoutMilliseconds 400 `
            -StdoutPath $timeoutOut -StderrPath $timeoutErr -ExitPath $timeoutExit `
            -ExitFormat CanonicalJson `
            -ContainmentEvidencePath $proof -ContainmentRole LIVE -ContainmentAttemptId $attempt
        $timeoutObj = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($timeoutExit)) -ExpectedSchema 'fsring-captured-exit/v1'
        Assert-Ev ($timeoutObj.termination -ceq 'TIMEOUT' -and $timeoutObj.timedOut -eq $true) 'timeout was not TIMEOUT'
        Assert-Ev (Test-Path -LiteralPath $proof) 'TIMEOUT did not write containment proof'
        $proofObj = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($proof)) -ExpectedSchema 'fsring-c4-process-containment/v1'
        Assert-Ev ($proofObj.captureRole -ceq 'LIVE') 'containment role drifted'
        Assert-Ev ($proofObj.attemptId -ceq $attempt) 'containment attempt drifted'

        $duplexOut = Join-Path $root 'duplex.out'
        $duplexErr = Join-Path $root 'duplex.err'
        $duplexExit = Join-Path $root 'duplex.exit.json'
        $duplexProof = Join-Path $root 'duplex-process-containment.json'
        Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 20') `
            -WorkingDirectory $root -TimeoutMilliseconds 400 `
            -StdoutPath $duplexOut -StderrPath $duplexErr -ExitPath $duplexExit `
            -ExitFormat CanonicalJson `
            -ContainmentEvidencePath $duplexProof -ContainmentRole LIVE -ContainmentAttemptId $attempt `
            -DuplexHandler {
                param($duplex)
                $buf = New-Object byte[] 4
                $got = 0
                [void][FsringC4EvidenceNative]::ReadFile($duplex.StdoutRead, $buf, $buf.Length, [ref]$got, [IntPtr]::Zero)
            }
        $duplexObj = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($duplexExit)) -ExpectedSchema 'fsring-captured-exit/v1'
        Assert-Ev ($duplexObj.termination -ceq 'TIMEOUT' -and $duplexObj.timedOut -eq $true) 'blocking DuplexHandler ignored helper timeout'
        Assert-Ev (Test-Path -LiteralPath $duplexProof) 'DuplexHandler TIMEOUT did not contain the tree'

        $leaseFile = [IO.Path]::GetFullPath((Join-Path $root 'lease.txt'))
        $payload = [Text.Encoding]::UTF8.GetBytes("held-bytes`n")
        [IO.File]::WriteAllBytes($leaseFile, $payload)
        $sha = Get-C4EvidenceSha256Hex $payload
        $blob = Get-C4GitBlobId $payload
        $lease = Open-C4HeldFileLease -Path $leaseFile -ExpectedSha256 $sha -ExpectedGitBlobId $blob
        Assert-C4HeldFileLease $lease
        Close-C4HeldFileLease $lease

        $notIssuedJson = [ordered]@{
            schema = 'fsring-captured-exit/v1'
            version = 1
            observedExit = $null
            timedOut = $false
            termination = 'NOT_ISSUED'
        }
        $niPath = Join-Path $root 'not-issued.json'
        $niBytes = (New-Object System.Text.UTF8Encoding $false).GetBytes((ConvertTo-C4CanonicalJsonText $notIssuedJson) + "`n")
        [IO.File]::WriteAllBytes($niPath, $niBytes)
        $ni = ConvertFrom-C4CanonicalJsonBytes -Bytes $niBytes -ExpectedSchema 'fsring-captured-exit/v1'
        Assert-Ev ($ni.termination -ceq 'NOT_ISSUED' -and $null -eq $ni.observedExit) 'NOT_ISSUED canonical drifted'
        $niText = Join-Path $root 'not-issued.txt'
        [IO.File]::WriteAllBytes($niText, [Text.Encoding]::ASCII.GetBytes("NOT_ISSUED`n"))
        Assert-Ev (([Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($niText))) -ceq "NOT_ISSUED`n") 'NOT_ISSUED CodeText drifted'

        $psLeasePath = [IO.Path]::GetFullPath((Join-Path $root 'powershell-copy.exe'))
        [IO.File]::Copy((Join-Path $PSHOME 'powershell.exe'), $psLeasePath, $true)
        $self = $PSCommandPath
        if ([string]::IsNullOrWhiteSpace($self)) { $self = $MyInvocation.MyCommand.Path }
        $self = [IO.Path]::GetFullPath($self)
        $scriptBytes = [IO.File]::ReadAllBytes($self)
        $psBytes = [IO.File]::ReadAllBytes($psLeasePath)
        $psLease = Open-C4HeldFileLease -Path $psLeasePath -ExpectedSha256 (Get-C4EvidenceSha256Hex $psBytes)
        $scriptLease = Open-C4HeldFileLease -Path $self -ExpectedSha256 (Get-C4EvidenceSha256Hex $scriptBytes)
        Close-C4HeldFileLease $psLease
        Close-C4HeldFileLease $scriptLease

        $heldScript = Join-Path $root 'held-exit.ps1'
        $heldScript = [IO.Path]::GetFullPath($heldScript)
        [IO.File]::WriteAllText($heldScript, "exit 11`n")
        $heldBytes = [IO.File]::ReadAllBytes($heldScript)
        $heldLease = Open-C4HeldFileLease -Path $heldScript -ExpectedSha256 (Get-C4EvidenceSha256Hex $heldBytes)
        $psHeld = Open-C4HeldFileLease -Path $psLeasePath -ExpectedSha256 (Get-C4EvidenceSha256Hex $psBytes)
        $heldExit = Invoke-C4HeldPowerShellScript -PowerShellLease $psHeld -ScriptLease $heldLease -Arguments @()
        Assert-Ev ($heldExit -eq 11) ('held script used Start-Process or drifted exit: ' + [string]$heldExit)
        Close-C4HeldFileLease $heldLease
        Close-C4HeldFileLease $psHeld

        $nulBytes = [IO.File]::ReadAllBytes($nulOut)
        Assert-Ev ($nulBytes.Length -ge 3 -and $nulBytes[0] -eq 0) 'binary NUL stdout was not preserved'

        $largeOut = Join-Path $root 'large.out'
        $largeErr = Join-Path $root 'large.err'
        $largeExit = Join-Path $root 'large.exit.json'
        $largeCmd = '$o = New-Object byte[] 200000; [Console]::OpenStandardOutput().Write($o,0,$o.Length); $e = New-Object byte[] 200000; [Console]::OpenStandardError().Write($e,0,$e.Length)'
        Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-NonInteractive', '-Command', $largeCmd) `
            -WorkingDirectory $root -TimeoutMilliseconds 30000 `
            -StdoutPath $largeOut -StderrPath $largeErr -ExitPath $largeExit -ExitFormat CanonicalJson
        Assert-Ev ([IO.File]::ReadAllBytes($largeOut).Length -ge 200000) 'large stdout was truncated'
        Assert-Ev ([IO.File]::ReadAllBytes($largeErr).Length -ge 200000) 'large stderr was truncated'

        $bomOut = Join-Path $root 'bom.out'
        $bomErr = Join-Path $root 'bom.err'
        $bomExit = Join-Path $root 'bom.exit.json'
        Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-NonInteractive', '-Command', '[Console]::OpenStandardOutput().Write([byte[]](0xEF,0xBB,0xBF,0x61),0,4)') `
            -WorkingDirectory $root -TimeoutMilliseconds 20000 `
            -StdoutPath $bomOut -StderrPath $bomErr -ExitPath $bomExit -ExitFormat CanonicalJson
        $bomBytes = [IO.File]::ReadAllBytes($bomOut)
        Assert-Ev ($bomBytes.Length -ge 4 -and $bomBytes[0] -eq 0xEF -and $bomBytes[1] -eq 0xBB -and $bomBytes[2] -eq 0xBF) 'UTF-8 BOM was not preserved'

        $metaOut = Join-Path $root 'meta.out'
        $metaErr = Join-Path $root 'meta.err'
        $metaExit = Join-Path $root 'meta.exit.json'
        Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-NonInteractive', '-Command', 'Write-Output ''ok''; exit 0', '&', '|', '>', '<', '^', '%TEMP%') `
            -WorkingDirectory $root -TimeoutMilliseconds 20000 `
            -StdoutPath $metaOut -StderrPath $metaErr -ExitPath $metaExit -ExitFormat CanonicalJson
        $metaObj = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($metaExit)) -ExpectedSchema 'fsring-captured-exit/v1'
        Assert-Ev ($metaObj.termination -ceq 'NORMAL') 'metacharacter arguments were not passed as argv'

        $mergedCaught = $false
        try {
            Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-Command', 'exit 0') `
                -WorkingDirectory $root -TimeoutMilliseconds 5000 `
                -StdoutPath (Join-Path $root 'same.bin') -StderrPath (Join-Path $root 'same.bin') -ExitPath (Join-Path $root 'same.exit') `
                -ExitFormat CodeText
        } catch {
            $mergedCaught = [string]$_ -cmatch 'merged'
        }
        Assert-Ev $mergedCaught 'merged stdout/stderr streams were accepted'

        $escapeCaught = $false
        try {
            Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-Command', 'exit 0') `
                -WorkingDirectory $root -TimeoutMilliseconds 5000 `
                -StdoutPath (Join-Path $root '..\escape.out') -StderrPath (Join-Path $root 'escape.err') -ExitPath (Join-Path $root 'escape.exit') `
                -ExitFormat CodeText
        } catch {
            $escapeCaught = $true
        }
        Assert-Ev $escapeCaught 'path escape destination was accepted'

        foreach ($fault in @('JobConfig', 'Assign', 'Resume')) {
            $fOut = Join-Path $root ("fault-$fault.out")
            $fErr = Join-Path $root ("fault-$fault.err")
            $fExit = Join-Path $root ("fault-$fault.exit.json")
            $fProof = Join-Path $root ("fault-$fault.json")
            Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-NonInteractive', '-Command', 'exit 0') `
                -WorkingDirectory $root -TimeoutMilliseconds 10000 `
                -StdoutPath $fOut -StderrPath $fErr -ExitPath $fExit -ExitFormat CanonicalJson `
                -ContainmentEvidencePath $fProof -ContainmentRole LIVE -ContainmentAttemptId $attempt `
                -FaultInjection $fault
            $faultExit = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($fExit)) -ExpectedSchema 'fsring-captured-exit/v1'
            Assert-Ev ($faultExit.termination -ceq 'CAPTURE_FAILED') "$fault was not CAPTURE_FAILED"
            Assert-Ev (Test-Path -LiteralPath $fProof) "$fault did not write containment proof"
            $faultProof = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($fProof)) -ExpectedSchema 'fsring-c4-process-containment/v1'
            Assert-Ev ($faultProof.status -ceq 'FAIL') "$fault proof was PASS"
        }

        $preOut = Join-Path $root 'pre.out'
        $preErr = Join-Path $root 'pre.err'
        $preExit = Join-Path $root 'pre.exit.json'
        $ran = Join-Path $root 'child-ran.txt'
        Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-NonInteractive', '-Command', "Set-Content -LiteralPath '$ran' -Value ran") `
            -WorkingDirectory $root -TimeoutMilliseconds 10000 `
            -StdoutPath $preOut -StderrPath $preErr -ExitPath $preExit -ExitFormat CanonicalJson `
            -FaultInjection Assign `
            -BeforeAssign {
                param($info)
                Assert-Ev (-not (Test-Path -LiteralPath $ran)) 'child ran before job assignment'
            }.GetNewClosure()
        Assert-Ev (-not (Test-Path -LiteralPath $ran)) 'pre-assignment child executed its entry point'

        $breakOut = Join-Path $root 'break.out'
        $breakErr = Join-Path $root 'break.err'
        $breakExit = Join-Path $root 'break.exit.json'
        $breakProof = Join-Path $root 'break.json'
        $escaped = Join-Path $root 'escaped.txt'
        $breakCmd = "Start-Process -FilePath '$cmd' -ArgumentList '-NoProfile -NonInteractive -Command Set-Content -LiteralPath ''$escaped'' -Value escaped' -WindowStyle Hidden; Start-Sleep -Seconds 20"
        Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-NonInteractive', '-Command', $breakCmd) `
            -WorkingDirectory $root -TimeoutMilliseconds 800 `
            -StdoutPath $breakOut -StderrPath $breakErr -ExitPath $breakExit -ExitFormat CanonicalJson `
            -ContainmentEvidencePath $breakProof -ContainmentRole LIVE -ContainmentAttemptId $attempt
        Start-Sleep -Milliseconds 400
        Assert-Ev (-not (Test-Path -LiteralPath $escaped)) 'breakaway descendant escaped the job'

        $partOut = Join-Path $root 'partial.out'
        $partErr = Join-Path $root 'partial.err'
        $partExit = Join-Path $root 'partial.exit.json'
        $partCmd = '$b = New-Object byte[] 64; for ($i=0; $i -lt 64; $i++) { $b[$i] = $i }; [Console]::OpenStandardOutput().Write($b,0,64); [Console]::Out.Flush(); Start-Sleep -Seconds 20'
        Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-NonInteractive', '-Command', $partCmd) `
            -WorkingDirectory $root -TimeoutMilliseconds 4000 `
            -StdoutPath $partOut -StderrPath $partErr -ExitPath $partExit -ExitFormat CanonicalJson
        $partial = [IO.File]::ReadAllBytes($partOut)
        Assert-Ev ($partial.Length -gt 0 -and $partial.Length -le 64) ('mid-stream capture lost partial bytes: ' + $partial.Length)

        $roles = @('PREFLIGHT_INITIAL', 'PREFLIGHT_FINAL', 'LIVE', 'CLEANUP_RECOVERY')
        $proofs = @{}
        foreach ($role in $roles) {
            $rOut = Join-Path $root ("role-$role.out")
            $rErr = Join-Path $root ("role-$role.err")
            $rExit = Join-Path $root ("role-$role.exit.json")
            $rProof = Join-Path $root ("role-$role.json")
            Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 20') `
                -WorkingDirectory $root -TimeoutMilliseconds 400 `
                -StdoutPath $rOut -StderrPath $rErr -ExitPath $rExit -ExitFormat CanonicalJson `
                -ContainmentEvidencePath $rProof -ContainmentRole $role -ContainmentAttemptId $attempt
            $roleProof = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($rProof)) -ExpectedSchema 'fsring-c4-process-containment/v1'
            Assert-Ev ($roleProof.captureRole -ceq $role) "containment role $role drifted"
            $proofs[$role] = $roleProof
        }
        foreach ($role in $roles) {
            foreach ($other in $roles) {
                if ($role -ceq $other) { continue }
                Assert-Ev ($proofs[$role].captureRole -cne $other) "role $role proof substituted $other"
            }
        }

        $pwOut = Join-Path $root 'pw.out'
        $pwErr = Join-Path $root 'pw.err'
        $pwExit = Join-Path $root 'pw.exit.json'
        $pwProof = Join-Path $root 'pw.json'
        [IO.File]::WriteAllText($pwProof, 'occupied')
        $pwCaught = $false
        try {
            Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 20') `
                -WorkingDirectory $root -TimeoutMilliseconds 400 `
                -StdoutPath $pwOut -StderrPath $pwErr -ExitPath $pwExit -ExitFormat CanonicalJson `
                -ContainmentEvidencePath $pwProof -ContainmentRole LIVE -ContainmentAttemptId $attempt
        } catch {
            $pwCaught = $true
        }
        Assert-Ev $pwCaught 'proof-write CreateNew collision was accepted'

        $ucOut = Join-Path $root 'uc.out'
        $ucErr = Join-Path $root 'uc.err'
        $ucExit = Join-Path $root 'uc.exit.json'
        $ucCaught = $false
        try {
            Invoke-C4EvidenceProcess -Executable $cmd -Arguments @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 20') `
                -WorkingDirectory $root -TimeoutMilliseconds 400 `
                -StdoutPath $ucOut -StderrPath $ucErr -ExitPath $ucExit -ExitFormat CanonicalJson `
                -FaultInjection UnconfirmedWait
        } catch {
            $ucCaught = [string]$_ -cmatch 'not confirmed'
        }
        Assert-Ev $ucCaught 'unconfirmed verifier teardown returned a sealable capture'
        $ucBytes = [IO.File]::ReadAllBytes($ucExit)
        Assert-Ev ($ucBytes.Length -eq 0) 'unconfirmed verifier wrote a sealable exit record'

        $swapFile = [IO.Path]::GetFullPath((Join-Path $root 'swap-lease.txt'))
        [IO.File]::WriteAllText($swapFile, "original`n")
        $swapBytes = [IO.File]::ReadAllBytes($swapFile)
        $swapLease = Open-C4HeldFileLease -Path $swapFile -ExpectedSha256 (Get-C4EvidenceSha256Hex $swapBytes)
        $writeBlocked = $false
        try {
            [IO.File]::WriteAllText($swapFile, "changed-bytes`n")
        } catch {
            $writeBlocked = $true
        }
        Assert-Ev $writeBlocked 'leased bytes were overwritten while the handle was held'
        Assert-C4HeldFileLease $swapLease
        Close-C4HeldFileLease $swapLease
        [IO.File]::WriteAllText($swapFile, "changed-bytes`n")
        $staleCaught = $false
        try {
            $null = Open-C4HeldFileLease -Path $swapFile -ExpectedSha256 (Get-C4EvidenceSha256Hex $swapBytes)
        } catch {
            $staleCaught = $true
        }
        Assert-Ev $staleCaught 'lease swap after close was accepted with the old hash'

        # A multi-link file is leasable, and the canonical path is still what
        # binds it. Windows hard-links its own system binaries into WinSxS, so
        # requiring exactly one link made the real frozen powershell/InfVerif/
        # SignTool roles unleasable. The final-path check is what refuses an
        # alias, and it is exercised here on a file that genuinely has two
        # names.
        $linkTarget = [IO.Path]::GetFullPath((Join-Path $root 'link-target.txt'))
        [IO.File]::WriteAllText($linkTarget, "linked`n")
        $linkAlias = [IO.Path]::GetFullPath((Join-Path $root 'link-alias.txt'))
        $linkMade = [FsringC4EvidenceNative]::CreateHardLinkW($linkAlias, $linkTarget, [IntPtr]::Zero)
        Assert-Ev $linkMade 'the hard-link fixture could not be created'
        $linkBytes = [IO.File]::ReadAllBytes($linkTarget)
        $linkSha = Get-C4EvidenceSha256Hex $linkBytes
        $linkLease = Open-C4HeldFileLease -Path $linkTarget -ExpectedSha256 $linkSha
        try {
            Assert-Ev ($linkLease.NumberOfLinks -eq 2) 'the lease did not record two hard links'
            Assert-Ev ($linkLease.Path -ceq $linkTarget) 'the lease did not bind the requested name'
            Assert-C4HeldFileLease $linkLease

            # The alias reaches the same bytes, but its lease binds its own
            # canonical name: one lease can never stand in for the other.
            $aliasLease = Open-C4HeldFileLease -Path $linkAlias -ExpectedSha256 $linkSha
            try {
                Assert-Ev ($aliasLease.Path -ceq $linkAlias) 'the alias lease bound the wrong name'
                Assert-Ev ($aliasLease.FileId -ceq $linkLease.FileId) 'the alias is not the same file'
            } finally {
                Close-C4HeldFileLease $aliasLease
            }

            # Count drift is the refusal that replaces the old "must be one"
            # rule: removing a link while the lease is held must be seen.
            [IO.File]::Delete($linkAlias)
            $driftCaught = $false
            try {
                Assert-C4HeldFileLease $linkLease
            } catch {
                $driftCaught = [string]$_ -cmatch 'hard link count drifted'
            }
            Assert-Ev $driftCaught 'a removed hard link did not fail the held lease'
        } finally {
            Close-C4HeldFileLease $linkLease
        }

        # The canonical final-path check is what refuses a payload reached under
        # another name, and it is now the only thing standing in for the
        # withdrawn "exactly one hard link" rule -- so it needs a fixture of its
        # own. A directory junction gives an ordinary, non-reparse file a second
        # reachable path without any privilege: GetFinalPathNameByHandleW
        # reports the real name, which no longer equals the requested one.
        $aliasRoot = [IO.Path]::GetFullPath((Join-Path $root 'alias-real'))
        [void][IO.Directory]::CreateDirectory($aliasRoot)
        $aliasReal = [IO.Path]::GetFullPath((Join-Path $aliasRoot 'payload.txt'))
        [IO.File]::WriteAllText($aliasReal, "payload`n")
        $aliasSha = Get-C4EvidenceSha256Hex ([IO.File]::ReadAllBytes($aliasReal))
        $junction = [IO.Path]::GetFullPath((Join-Path $root 'alias-junction'))
        # mklink prints the two absolute paths, and this fixture's paths carry a
        # fresh GUID. Row 02 of the source gate captures and hashes this script's
        # raw stdout, so that banner would make a recorded artifact differ run to
        # run for no reason. Send it to a file nobody reads.
        $mklinkLog = Join-Path $root 'mklink.txt'
        $mklink = Start-Process -FilePath $env:ComSpec `
            -ArgumentList @('/d', '/c', 'mklink', '/J', $junction, $aliasRoot) `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $mklinkLog -RedirectStandardError ($mklinkLog + '.err')
        Assert-Ev ($mklink.ExitCode -eq 0) 'the junction fixture could not be created'
        $viaJunction = [IO.Path]::GetFullPath((Join-Path $junction 'payload.txt'))
        Assert-Ev ([IO.File]::Exists($viaJunction)) 'the junction fixture does not reach the payload'
        $aliasAttributes = [IO.File]::GetAttributes($viaJunction)
        Assert-Ev ((($aliasAttributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) `
            'the aliased payload is itself a reparse point, so this fixture proves nothing'
        $aliasCaught = $false
        try {
            $null = Open-C4HeldFileLease -Path $viaJunction -ExpectedSha256 $aliasSha
        } catch {
            $aliasCaught = [string]$_ -cmatch 'alias'
        }
        Assert-Ev $aliasCaught 'a payload leased through a junction was accepted'
        $directAlias = Open-C4HeldFileLease -Path $aliasReal -ExpectedSha256 $aliasSha
        try {
            Assert-Ev ($directAlias.Path -ceq $aliasReal) 'the real name did not lease'
        } finally {
            Close-C4HeldFileLease $directAlias
        }

        # Assert-C4HeldFileLease's byte comparison cannot be reached by writing
        # to the file -- the lease denies write and delete for its whole life, on
        # the file object rather than the name, so no second path reaches it
        # either. What can still be wrong is the recorded value, so the
        # comparison is exercised against a lease whose record was tampered
        # with. Without this, disabling that comparison outright left the suite
        # green.
        $recordFile = [IO.Path]::GetFullPath((Join-Path $root 'record-drift.txt'))
        [IO.File]::WriteAllText($recordFile, "recorded`n")
        $recordSha = Get-C4EvidenceSha256Hex ([IO.File]::ReadAllBytes($recordFile))
        $recordLease = Open-C4HeldFileLease -Path $recordFile -ExpectedSha256 $recordSha
        try {
            Assert-C4HeldFileLease $recordLease
            $tampered = [pscustomobject]@{
                Path = $recordLease.Path
                Stream = $recordLease.Stream
                Length = $recordLease.Length
                Sha256 = ('0' * 64)
                GitBlobId = $recordLease.GitBlobId
                VolumeSerial = $recordLease.VolumeSerial
                FileId = $recordLease.FileId
                NumberOfLinks = $recordLease.NumberOfLinks
                ExpectedSha256 = $recordLease.ExpectedSha256
                ExpectedGitBlobId = $recordLease.ExpectedGitBlobId
            }
            $recordCaught = $false
            try {
                Assert-C4HeldFileLease $tampered
            } catch {
                $recordCaught = [string]$_ -cmatch 'bytes drifted'
            }
            Assert-Ev $recordCaught 'a lease whose recorded hash disagreed with its bytes was accepted'
        } finally {
            Close-C4HeldFileLease $recordLease
        }
    } catch {
        [void]$failures.Add($_.Exception.Message)
    } finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($failures.Count -ne 0) {
        Write-Output ($failures -join "`n")
        exit 1
    }
    Write-Output 'invoke_c4_evidence self-test PASS'
    exit 0
}

if (-not $script:C4EvidenceDotSourced) {
    if ($SelfTest) {
        Invoke-C4EvidenceSelfTests
    } else {
        throw 'direct execution of invoke_c4_evidence.ps1 accepts only -SelfTest'
    }
}
