[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(ParameterSetName = 'SelfTest', Mandatory = $true)]
    [switch]$SelfTest,

    [Parameter(ParameterSetName = 'Preflight', Mandatory = $true)]
    [switch]$PreflightOnly,

    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [switch]$CleanupOnly,

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'Preflight')]
    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [switch]$C4,

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'Preflight')]
    [string]$PackageDirectory,

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'Preflight')]
    [string]$HarnessPath,

    [Parameter(ParameterSetName = 'Live', Mandatory = $true)]
    [Parameter(ParameterSetName = 'Preflight', Mandatory = $true)]
    [ValidateScript({
        if ($_ -isnot [string] -or
            $_ -cnotmatch '^[0-9A-F]{64}$') {
            throw (
                'ExpectedHarnessSha256 must be exactly 64 uppercase ' +
                'hexadecimal characters.'
            )
        }
        return $true
    })]
    [string]$ExpectedHarnessSha256,

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'Preflight')]
    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [string]$AttemptId,

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'Preflight')]
    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [string]$CandidateManifestPath,

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'Preflight')]
    [Parameter(ParameterSetName = 'CleanupOnly', Mandatory = $true)]
    [string]$ExpectedCandidateManifestSha256,

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'Preflight')]
    [string]$EvidenceDirectory,

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
    [string]$OwnedDosName
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:C4SavedSelfTest = [bool]$SelfTest
if (-not (Get-Variable -Name C4EvidenceDotSourced -Scope Script -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'invoke_c4_evidence.ps1')
}
$SelfTest = [bool]$script:C4SavedSelfTest

$script:FinalOutputEncodingInitializationCount = 0
function Set-BomlessUtf8ConsoleOutput {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $script:FinalOutputEncodingInitializationCount += 1
}
Set-BomlessUtf8ConsoleOutput

# The exact warning verify_fsring_package.ps1 emits for a locally trusted test
# root. A WDRLocalTestCert package can never pass the kernel-mode policy, whose
# /kp probe demands a Microsoft root, so this third state -- not exit 0 -- is
# the only one under which a test-signed driver is actually load-ready, and it
# is load-ready only while TESTSIGNING is active. Get-PreflightDecision already
# refuses to be runnable without an ENABLED signing state, which is what keeps
# that qualifier honest.
$script:LocallyTrustedTestRootWarning = 'WDRLocalTestCert C3E805E2841D2C68790A7F4E8E93DB121EB0C046 is installed in LocalMachine\Root and LocalMachine\TrustedPublisher and Authenticode policy verifies all three artifacts; the kernel-mode policy still refuses a non-Microsoft root, so this package is load-ready only while TESTSIGNING is active.'
$script:Schema = 'fsring-driver-smoke/v1'
$script:ServiceName = 'fsring_fsd'
$script:VerifierSchema = 'fsring-package-verifier/v1'
$script:HarnessSchema = 'fsring-control-smoke/v1'
$script:ClientTimeoutMilliseconds = 120000
$script:HarnessTimeoutMilliseconds = 30000
$script:ScCommandTimeoutMilliseconds = 30000
$script:ContainmentTimeoutMilliseconds = 5000
$script:ClientStreamCapBytes = 65536
$script:RetainedClientLeases = New-Object System.Collections.ArrayList
$script:RetainedHarnessPins = New-Object System.Collections.ArrayList
$script:RetainedScPins = New-Object System.Collections.ArrayList
$script:NormalProbeNames = @(
    'root-open',
    'trailing-open',
    'unknown-ioctl',
    'setup',
    'donate-short',
    'donate-wrong-version',
    'donate',
    'child-inherited-handle',
    'parent-handle-after-child'
)
$script:NormalProbeErrors = @($null, 2, 1, 50, 87, 1306, 50, 5, 50)
$script:AbsentProbeNames = @('device-absent')
$script:AbsentProbeErrors = @(2)

# --- C4 public v2 and private worker protocol -------------------------------
#
# The v1 constants above are untouched: C3's regression schema stays exactly
# what it was, and the two are never mixed.
$script:C4HarnessSchemaV2 = 'fsring-control-smoke/v2'
$script:C4WorkerSchema = 'fsring-c4-worker/v1'
$script:C4FrameMin = 2
$script:C4FrameMax = 262144
$script:C4PrivateEventMax = 8
$script:C4ReasonMaxEntries = 35
$script:C4ReasonMaxBytes = 512
$script:C4InfrastructurePrefix = 'INFRASTRUCTURE:'
$script:C4FrameTimeoutMilliseconds = 30000
$script:C4CumulativeOutputCapBytes = 262144
$script:C4ProbeOutcomes = @('PASS', 'FAIL', 'NOT RUN')
$script:C4EventNames = @(
    'SESSION_PUBLISHED',
    'MOUNT_PUBLISHED',
    'VERIFY_SUCCEEDED',
    'SESSION_FENCED'
)
$script:C4ProbeRoster = @(
    'root-open',
    'trailing-open',
    'unknown-ioctl',
    'donate-short',
    'donate-wrong-version',
    'donate',
    'child-inherited-handle',
    'parent-handle-after-child',
    'fscontrol-acl',
    'setup-required-unavailable',
    'setup-optional-downgrade',
    'setup-security',
    'setup-duplicate',
    'session-layout',
    'view-protections',
    'vdo-acl',
    'vdo-mount',
    'enter-poll',
    'enter-timeout',
    'enter-dual-role',
    'enter-notify-credit',
    'enter-contention',
    'enter-cancel',
    'protocol-abort',
    'cleanup-close',
    'unload-transients',
    'bootcontext-persistent'
)
# Index 25 belongs to the runner alone: it spans a service stop no contained
# worker is alive for.
$script:C4RunnerOnlyProbe = 'unload-transients'
$script:C4PrivateProbeRanges = @{
    'STAGED' = @(0, 14)
    'LIVE_CLEANED' = @(15, 24)
    'POST_UNLOAD' = @(26, 26)
}
$script:C4InfrastructureStages = @(
    'LIVE_STAGED',
    'DOS_LINK_CREATE',
    'LIVE_COMMAND',
    'LIVE_CLEANED',
    'LIVE_CONTAINMENT',
    'DOS_LINK_REMOVE',
    'SCM_CLEANUP',
    'POST_UNLOAD',
    'POST_CONTAINMENT'
)
$script:C4InfrastructureDomains = @('runner', 'win32', 'ntstatus')
$script:DDD_RAW_TARGET_PATH = 0x00000001
$script:DDD_REMOVE_DEFINITION = 0x00000002
$script:DDD_EXACT_MATCH_ON_REMOVE = 0x00000004
$script:DDD_NO_BROADCAST_SYSTEM = 0x00000008
$script:C4CleanupOrder = @('contain-worker', 'remove-dos-link', 'stop-service', 'delete-service', 'post-unload')
$script:C4DosRemoveFlags = $script:DDD_REMOVE_DEFINITION -bor $script:DDD_EXACT_MATCH_ON_REMOVE -bor $script:DDD_RAW_TARGET_PATH -bor $script:DDD_NO_BROADCAST_SYSTEM
$script:C4UnloadMergeKeys = @('serviceStopped', 'providerOpenNtstatus', 'fscontrolOpenNtstatus', 'vdoOpenNtstatus', 'dosLinkQueryWin32Code', 'formerAliasRangesFree', 'ownedHandlesClosed')
$script:C4WorkerReasonLimit = 26

if ($null -eq ('FsringStrictJsonValidator' -as [type])) {
    $strictJsonValidatorSource = @'
using System;
using System.Collections.Generic;
using System.Text;

public static class FsringStrictJsonValidator
{
    public static string Validate(string json, int maxUtf8Bytes, int maxDepth)
    {
        if (json == null)
        {
            return "JSON input is null.";
        }
        if (maxUtf8Bytes < 0 || maxDepth < 1)
        {
            return "JSON validator limits are invalid.";
        }

        try
        {
            int byteCount = new UTF8Encoding(false, true).GetByteCount(json);
            if (byteCount > maxUtf8Bytes)
            {
                return "JSON exceeds the UTF-8 byte limit.";
            }
        }
        catch (EncoderFallbackException)
        {
            return "JSON contains invalid UTF-16.";
        }

        if (json.IndexOf('\r') >= 0 || json.IndexOf('\n') >= 0)
        {
            return "JSON contains a raw CR or LF.";
        }

        try
        {
            new Parser(json, maxDepth).ParseRootObject();
            return null;
        }
        catch (JsonValidationException exception)
        {
            return exception.Message;
        }
    }

    private sealed class JsonValidationException : Exception
    {
        internal JsonValidationException(string message)
            : base(message)
        {
        }
    }

    private sealed class Parser
    {
        private readonly string json;
        private readonly int maxDepth;
        private int position;

        internal Parser(string json, int maxDepth)
        {
            this.json = json;
            this.maxDepth = maxDepth;
            this.position = 0;
        }

        internal void ParseRootObject()
        {
            SkipWhitespace();
            if (AtEnd || Current != '{')
            {
                throw Error("JSON root must be an object.");
            }
            ParseObject(1);
            SkipWhitespace();
            if (!AtEnd)
            {
                throw Error("JSON has trailing content.");
            }
        }

        private bool AtEnd
        {
            get { return position >= json.Length; }
        }

        private char Current
        {
            get { return json[position]; }
        }

        private JsonValidationException Error(string reason)
        {
            return new JsonValidationException(
                "JSON validation failed at offset " +
                position.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                ": " +
                reason);
        }

        private void SkipWhitespace()
        {
            while (!AtEnd)
            {
                char value = Current;
                if (value != ' ' && value != '\t' && value != '\r' && value != '\n')
                {
                    break;
                }
                position++;
            }
        }

        private bool Consume(char expected)
        {
            if (!AtEnd && Current == expected)
            {
                position++;
                return true;
            }
            return false;
        }

        private void Expect(char expected)
        {
            if (!Consume(expected))
            {
                throw Error("Expected '" + expected + "'.");
            }
        }

        private void ParseObject(int depth)
        {
            if (depth > maxDepth)
            {
                throw Error("JSON container depth exceeds the limit.");
            }
            Expect('{');
            SkipWhitespace();
            if (Consume('}'))
            {
                return;
            }

            HashSet<string> names = new HashSet<string>(StringComparer.Ordinal);
            while (true)
            {
                if (AtEnd || Current != '"')
                {
                    throw Error("JSON object property name is missing.");
                }
                string name = ParseString();
                if (!names.Add(name))
                {
                    throw Error("JSON object contains a duplicate property name.");
                }
                SkipWhitespace();
                Expect(':');
                SkipWhitespace();
                ParseValue(depth);
                SkipWhitespace();
                if (Consume('}'))
                {
                    return;
                }
                Expect(',');
                SkipWhitespace();
            }
        }

        private void ParseArray(int depth)
        {
            if (depth > maxDepth)
            {
                throw Error("JSON container depth exceeds the limit.");
            }
            Expect('[');
            SkipWhitespace();
            if (Consume(']'))
            {
                return;
            }

            while (true)
            {
                ParseValue(depth);
                SkipWhitespace();
                if (Consume(']'))
                {
                    return;
                }
                Expect(',');
                SkipWhitespace();
            }
        }

        private void ParseValue(int parentDepth)
        {
            if (AtEnd)
            {
                throw Error("JSON value is missing.");
            }

            switch (Current)
            {
                case '{':
                    ParseObject(parentDepth + 1);
                    return;
                case '[':
                    ParseArray(parentDepth + 1);
                    return;
                case '"':
                    ParseString();
                    return;
                case 't':
                    ParseLiteral("true");
                    return;
                case 'f':
                    ParseLiteral("false");
                    return;
                case 'n':
                    ParseLiteral("null");
                    return;
                default:
                    if (Current == '-' || (Current >= '0' && Current <= '9'))
                    {
                        ParseNumber();
                        return;
                    }
                    throw Error("JSON value token is invalid.");
            }
        }

        private void ParseLiteral(string literal)
        {
            for (int index = 0; index < literal.Length; index++)
            {
                if (AtEnd || Current != literal[index])
                {
                    throw Error("JSON literal is invalid.");
                }
                position++;
            }
        }

        private void ParseNumber()
        {
            Consume('-');
            if (AtEnd)
            {
                throw Error("JSON number is incomplete.");
            }

            if (Consume('0'))
            {
                if (!AtEnd && Current >= '0' && Current <= '9')
                {
                    throw Error("JSON number has a leading zero.");
                }
            }
            else
            {
                if (Current < '1' || Current > '9')
                {
                    throw Error("JSON number integer part is invalid.");
                }
                while (!AtEnd && Current >= '0' && Current <= '9')
                {
                    position++;
                }
            }

            if (Consume('.'))
            {
                if (AtEnd || Current < '0' || Current > '9')
                {
                    throw Error("JSON number fraction is incomplete.");
                }
                while (!AtEnd && Current >= '0' && Current <= '9')
                {
                    position++;
                }
            }

            if (!AtEnd && (Current == 'e' || Current == 'E'))
            {
                position++;
                if (!AtEnd && (Current == '+' || Current == '-'))
                {
                    position++;
                }
                if (AtEnd || Current < '0' || Current > '9')
                {
                    throw Error("JSON number exponent is incomplete.");
                }
                while (!AtEnd && Current >= '0' && Current <= '9')
                {
                    position++;
                }
            }
        }

        private string ParseString()
        {
            Expect('"');
            StringBuilder builder = new StringBuilder();
            bool hasHighSurrogate = false;
            char highSurrogate = '\0';

            while (!AtEnd)
            {
                char source = Current;
                position++;
                if (source == '"')
                {
                    if (hasHighSurrogate)
                    {
                        throw Error("JSON string ends with an isolated high surrogate.");
                    }
                    return builder.ToString();
                }

                char decoded;
                if (source == '\\')
                {
                    if (AtEnd)
                    {
                        throw Error("JSON string escape is incomplete.");
                    }
                    char escape = Current;
                    position++;
                    switch (escape)
                    {
                        case '"':
                        case '\\':
                        case '/':
                            decoded = escape;
                            break;
                        case 'b':
                            decoded = '\b';
                            break;
                        case 'f':
                            decoded = '\f';
                            break;
                        case 'n':
                            decoded = '\n';
                            break;
                        case 'r':
                            decoded = '\r';
                            break;
                        case 't':
                            decoded = '\t';
                            break;
                        case 'u':
                            decoded = ParseUnicodeEscape();
                            break;
                        default:
                            throw Error("JSON string escape is invalid.");
                    }
                }
                else
                {
                    if (source < 0x20)
                    {
                        throw Error("JSON string contains an unescaped control character.");
                    }
                    decoded = source;
                }

                if (hasHighSurrogate)
                {
                    if (!char.IsLowSurrogate(decoded))
                    {
                        throw Error("JSON string contains an isolated high surrogate.");
                    }
                    builder.Append(highSurrogate);
                    builder.Append(decoded);
                    hasHighSurrogate = false;
                    highSurrogate = '\0';
                }
                else if (char.IsHighSurrogate(decoded))
                {
                    hasHighSurrogate = true;
                    highSurrogate = decoded;
                }
                else if (char.IsLowSurrogate(decoded))
                {
                    throw Error("JSON string contains an isolated low surrogate.");
                }
                else
                {
                    builder.Append(decoded);
                }
            }

            throw Error("JSON string is unterminated.");
        }

        private char ParseUnicodeEscape()
        {
            if (json.Length - position < 4)
            {
                throw Error("JSON Unicode escape is incomplete.");
            }

            int value = 0;
            for (int index = 0; index < 4; index++)
            {
                char digit = Current;
                position++;
                int hex;
                if (digit >= '0' && digit <= '9')
                {
                    hex = digit - '0';
                }
                else if (digit >= 'a' && digit <= 'f')
                {
                    hex = digit - 'a' + 10;
                }
                else if (digit >= 'A' && digit <= 'F')
                {
                    hex = digit - 'A' + 10;
                }
                else
                {
                    throw Error("JSON Unicode escape contains a nonhex digit.");
                }
                value = (value * 16) + hex;
            }
            return (char)value;
        }
    }
}
'@
    Add-Type -TypeDefinition $strictJsonValidatorSource -Language CSharp -ErrorAction Stop
}

if ($null -eq ('FsringNativeReadiness' -as [type])) {
    $nativeReadinessSource = @'
using System;
using System.Runtime.InteropServices;

public sealed class FsringNativeReadinessObservation
{
    public int RtlStatus { get; set; }
    public uint OsInputSize { get; set; }
    public uint OsReturnedSize { get; set; }
    public uint OsPlatformId { get; set; }
    public uint OsMajor { get; set; }
    public uint OsMinor { get; set; }
    public uint OsBuild { get; set; }
    public uint SystemInfoSize { get; set; }
    public ushort NativeArchitecture { get; set; }
    public bool Is64BitProcess { get; set; }
    public int CodeIntegrityStatus { get; set; }
    public uint CodeIntegrityBufferSize { get; set; }
    public uint CodeIntegrityInputLength { get; set; }
    public uint CodeIntegrityReturnLength { get; set; }
    public uint CodeIntegrityReturnedLength { get; set; }
    public uint CodeIntegrityOptions { get; set; }
    public int BootEnvironmentStatus { get; set; }
    public uint BootEnvironmentBufferSize { get; set; }
    public uint BootEnvironmentReturnLength { get; set; }
    public Guid BootIdentifier { get; set; }
    public uint FirmwareType { get; set; }
    public ulong BootFlags { get; set; }
}

public static class FsringNativeReadiness
{
    private const int QueryFailure = unchecked((int)0xC0000001);
    private const int SystemCodeIntegrityInformationClass = 103;
    private const int SystemBootEnvironmentInformationClass = 90;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RtlOsVersionInfoW
    {
        internal uint Size;
        internal uint Major;
        internal uint Minor;
        internal uint Build;
        internal uint PlatformId;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        internal string ServicePack;
    }

    [StructLayout(LayoutKind.Explicit, Size = 48)]
    private struct SystemInfo
    {
        [FieldOffset(0)]
        internal ushort ProcessorArchitecture;

        [FieldOffset(2)]
        internal ushort Reserved;

        [FieldOffset(4)]
        internal uint PageSize;

        [FieldOffset(8)]
        internal IntPtr MinimumApplicationAddress;

        [FieldOffset(16)]
        internal IntPtr MaximumApplicationAddress;

        [FieldOffset(24)]
        internal UIntPtr ActiveProcessorMask;

        [FieldOffset(32)]
        internal uint NumberOfProcessors;

        [FieldOffset(36)]
        internal uint ProcessorType;

        [FieldOffset(40)]
        internal uint AllocationGranularity;

        [FieldOffset(44)]
        internal ushort ProcessorLevel;

        [FieldOffset(46)]
        internal ushort ProcessorRevision;
    }

    [StructLayout(LayoutKind.Explicit, Size = 8)]
    private struct SystemCodeIntegrityInformation
    {
        [FieldOffset(0)]
        internal uint Length;

        [FieldOffset(4)]
        internal uint CodeIntegrityOptions;
    }

    [StructLayout(LayoutKind.Explicit, Size = 32)]
    private struct SystemBootEnvironmentInformation
    {
        [FieldOffset(0)]
        internal Guid BootIdentifier;

        [FieldOffset(16)]
        internal uint FirmwareType;

        [FieldOffset(24)]
        internal ulong BootFlags;
    }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int RtlGetVersion(ref RtlOsVersionInfoW version);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern void GetNativeSystemInfo(out SystemInfo systemInfo);

    [DllImport(
        "ntdll.dll",
        EntryPoint = "NtQuerySystemInformation",
        ExactSpelling = true)]
    private static extern int NtQueryCodeIntegrityInformation(
        int informationClass,
        ref SystemCodeIntegrityInformation information,
        uint informationLength,
        out uint returnLength);

    [DllImport(
        "ntdll.dll",
        EntryPoint = "NtQuerySystemInformation",
        ExactSpelling = true)]
    private static extern int NtQueryBootEnvironmentInformation(
        int informationClass,
        ref SystemBootEnvironmentInformation information,
        uint informationLength,
        out uint returnLength);

    public static int GetRtlOsVersionInfoSize()
    {
        return Marshal.SizeOf(typeof(RtlOsVersionInfoW));
    }

    public static int GetSystemInfoSize()
    {
        return Marshal.SizeOf(typeof(SystemInfo));
    }

    public static int GetCodeIntegrityInfoSize()
    {
        return Marshal.SizeOf(typeof(SystemCodeIntegrityInformation));
    }

    public static int GetBootEnvironmentInfoSize()
    {
        return Marshal.SizeOf(typeof(SystemBootEnvironmentInformation));
    }

    public static int GetBootIdentifierOffset()
    {
        return checked((int)Marshal.OffsetOf(
            typeof(SystemBootEnvironmentInformation),
            "BootIdentifier"));
    }

    public static int GetFirmwareTypeOffset()
    {
        return checked((int)Marshal.OffsetOf(
            typeof(SystemBootEnvironmentInformation),
            "FirmwareType"));
    }

    public static int GetBootFlagsOffset()
    {
        return checked((int)Marshal.OffsetOf(
            typeof(SystemBootEnvironmentInformation),
            "BootFlags"));
    }

    public static FsringNativeReadinessObservation Query()
    {
        FsringNativeReadinessObservation observed =
            new FsringNativeReadinessObservation();
        observed.RtlStatus = QueryFailure;
        observed.OsInputSize = checked((uint)GetRtlOsVersionInfoSize());
        observed.SystemInfoSize = checked((uint)GetSystemInfoSize());
        observed.NativeArchitecture = ushort.MaxValue;
        observed.Is64BitProcess = Environment.Is64BitProcess;
        observed.CodeIntegrityStatus = QueryFailure;
        observed.CodeIntegrityBufferSize =
            checked((uint)GetCodeIntegrityInfoSize());
        observed.CodeIntegrityInputLength =
            observed.CodeIntegrityBufferSize;
        observed.BootEnvironmentStatus = QueryFailure;
        observed.BootEnvironmentBufferSize =
            checked((uint)GetBootEnvironmentInfoSize());
        observed.BootIdentifier = Guid.Empty;

        try
        {
            RtlOsVersionInfoW version = new RtlOsVersionInfoW();
            version.Size = observed.OsInputSize;
            observed.RtlStatus = RtlGetVersion(ref version);
            observed.OsReturnedSize = version.Size;
            observed.OsPlatformId = version.PlatformId;
            observed.OsMajor = version.Major;
            observed.OsMinor = version.Minor;
            observed.OsBuild = version.Build;
        }
        catch (DllNotFoundException)
        {
        }
        catch (EntryPointNotFoundException)
        {
        }
        catch (BadImageFormatException)
        {
        }

        try
        {
            SystemInfo systemInfo;
            GetNativeSystemInfo(out systemInfo);
            observed.NativeArchitecture = systemInfo.ProcessorArchitecture;
        }
        catch (DllNotFoundException)
        {
        }
        catch (EntryPointNotFoundException)
        {
        }
        catch (BadImageFormatException)
        {
        }

        try
        {
            SystemCodeIntegrityInformation codeIntegrity =
                new SystemCodeIntegrityInformation();
            codeIntegrity.Length = observed.CodeIntegrityInputLength;
            uint returnLength;
            observed.CodeIntegrityStatus =
                NtQueryCodeIntegrityInformation(
                    SystemCodeIntegrityInformationClass,
                    ref codeIntegrity,
                    observed.CodeIntegrityBufferSize,
                    out returnLength);
            observed.CodeIntegrityReturnLength = returnLength;
            observed.CodeIntegrityReturnedLength = codeIntegrity.Length;
            observed.CodeIntegrityOptions =
                codeIntegrity.CodeIntegrityOptions;
        }
        catch (DllNotFoundException)
        {
        }
        catch (EntryPointNotFoundException)
        {
        }
        catch (BadImageFormatException)
        {
        }

        try
        {
            SystemBootEnvironmentInformation bootEnvironment =
                new SystemBootEnvironmentInformation();
            uint returnLength;
            observed.BootEnvironmentStatus =
                NtQueryBootEnvironmentInformation(
                    SystemBootEnvironmentInformationClass,
                    ref bootEnvironment,
                    observed.BootEnvironmentBufferSize,
                    out returnLength);
            observed.BootEnvironmentReturnLength = returnLength;
            observed.BootIdentifier = bootEnvironment.BootIdentifier;
            observed.FirmwareType = bootEnvironment.FirmwareType;
            observed.BootFlags = bootEnvironment.BootFlags;
        }
        catch (DllNotFoundException)
        {
        }
        catch (EntryPointNotFoundException)
        {
        }
        catch (BadImageFormatException)
        {
        }

        return observed;
    }
}
'@
    Add-Type -TypeDefinition $nativeReadinessSource -Language CSharp -ErrorAction Stop
}

if ($null -eq ('FsringContainedClientRunner' -as [type])) {
    $containedClientRunnerSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public sealed class FsringHarnessIdentityCheck
{
    public bool Attempted { get; internal set; }
    public bool Valid { get; internal set; }
    public string Stage { get; internal set; }
    public string Sha256 { get; internal set; }
    public long Length { get; internal set; }
    public ushort Machine { get; internal set; }
    public string VolumeSerial { get; internal set; }
    public string FileId { get; internal set; }
    public string FinalPath { get; internal set; }
    public string Detail { get; internal set; }
}

public sealed class FsringHarnessPin : IDisposable
{
    private const long MaximumHarnessBytes = 64L * 1024L * 1024L;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int FileAttributeTagInfoClass = 9;
    private const int FileIdInfoClass = 18;

    private readonly object sync = new object();
    private IntPtr handle;
    private bool disposed;

    public string ExpectedSha256 { get; private set; }
    public string ObservedSha256 { get; private set; }
    public long Length { get; private set; }
    public ushort Machine { get; private set; }
    public string VolumeSerial { get; private set; }
    public string FileId { get; private set; }
    public string FinalPath { get; private set; }
    public bool HandleInheritable { get; private set; }

    public long DangerousHandleValueForTest
    {
        get
        {
            lock (sync)
            {
                EnsureOpen();
                return handle.ToInt64();
            }
        }
    }

    private FsringHarnessPin()
    {
    }

    public static FsringHarnessPin Open(
        string requestedPath,
        string expectedSha256)
    {
        ValidateExpectedHash(expectedSha256);
        string fullPath = RequireAbsoluteNormalizedPath(requestedPath);
        RejectReparseComponents(fullPath);

        IntPtr pinned = FsringContainedClientNative.CreateFileNoInherit(
            fullPath,
            FsringContainedClientNative.GenericRead,
            FsringContainedClientNative.FileShareRead,
            IntPtr.Zero,
            FsringContainedClientNative.OpenExisting,
            0,
            IntPtr.Zero);
        if (pinned == FsringContainedClientNative.InvalidHandleValue)
        {
            throw NewWin32(
                "Opening the retained read-only harness pin failed.");
        }

        FsringHarnessPin result = new FsringHarnessPin();
        result.handle = pinned;
        result.ExpectedSha256 = expectedSha256;
        try
        {
            uint handleFlags;
            if (!FsringContainedClientNative.GetHandleInformation(
                pinned,
                out handleFlags))
            {
                throw NewWin32(
                    "Reading the retained harness handle flags failed.");
            }
            result.HandleInheritable =
                (handleFlags &
                    FsringContainedClientNative.HandleFlagInherit) != 0;
            if (result.HandleInheritable)
            {
                throw new IOException(
                    "The retained harness pin is inheritable.");
            }

            FsringPinnedMeasurement measurement =
                MeasurePinnedHandle(pinned);
            if (measurement.Machine != 0x8664)
            {
                throw new BadImageFormatException(
                    "The smoke harness PE machine is not AMD64.");
            }
            if (!String.Equals(
                measurement.Sha256,
                expectedSha256,
                StringComparison.Ordinal))
            {
                throw new IOException(
                    "The observed harness SHA-256 does not match the exact expected hash.");
            }
            result.ObservedSha256 = measurement.Sha256;
            result.Length = measurement.Length;
            result.Machine = measurement.Machine;
            result.VolumeSerial = measurement.VolumeSerial;
            result.FileId = measurement.FileId;
            result.FinalPath = measurement.FinalPath;

            FsringHarnessIdentityCheck reopened =
                result.Recheck(fullPath, "initial");
            if (!reopened.Valid)
            {
                throw new IOException(reopened.Detail);
            }
            return result;
        }
        catch
        {
            result.Dispose();
            throw;
        }
    }

    internal static FsringHarnessPin OpenNativeSystemTool(
        string leafName)
    {
        if (String.IsNullOrWhiteSpace(leafName) ||
            !String.Equals(
                Path.GetFileName(leafName),
                leafName,
                StringComparison.Ordinal) ||
            leafName.IndexOf('\0') >= 0)
        {
            throw new ArgumentException(
                "The native system-tool leaf name is invalid.");
        }

        StringBuilder systemDirectory = new StringBuilder(32768);
        uint written = FsringContainedClientNative.GetSystemDirectory(
            systemDirectory,
            checked((uint)systemDirectory.Capacity));
        if (written == 0 ||
            written >= systemDirectory.Capacity)
        {
            throw NewWin32(
                "Resolving the native Windows system directory failed.");
        }

        string requestedPath = Path.Combine(
            systemDirectory.ToString(),
            leafName);
        string fullPath = RequireAbsoluteNormalizedPath(
            Path.GetFullPath(requestedPath));
        RejectReparseComponents(fullPath);

        IntPtr pinned = FsringContainedClientNative.CreateFileNoInherit(
            fullPath,
            FsringContainedClientNative.GenericRead,
            FsringContainedClientNative.FileShareRead,
            IntPtr.Zero,
            FsringContainedClientNative.OpenExisting,
            0,
            IntPtr.Zero);
        if (pinned == FsringContainedClientNative.InvalidHandleValue)
        {
            throw NewWin32(
                "Opening the retained native system-tool pin failed.");
        }

        FsringHarnessPin result = new FsringHarnessPin();
        result.handle = pinned;
        try
        {
            uint handleFlags;
            if (!FsringContainedClientNative.GetHandleInformation(
                pinned,
                out handleFlags) ||
                (handleFlags &
                    FsringContainedClientNative.HandleFlagInherit) != 0)
            {
                throw NewWin32(
                    "The retained native system-tool pin is not proven non-inheritable.");
            }
            result.HandleInheritable = false;

            FsringPinnedMeasurement measurement =
                MeasurePinnedHandle(pinned);
            if (measurement.Machine != 0x8664)
            {
                throw new BadImageFormatException(
                    "The native system tool PE machine is not AMD64.");
            }
            result.ExpectedSha256 = measurement.Sha256;
            result.ObservedSha256 = measurement.Sha256;
            result.Length = measurement.Length;
            result.Machine = measurement.Machine;
            result.VolumeSerial = measurement.VolumeSerial;
            result.FileId = measurement.FileId;
            result.FinalPath = measurement.FinalPath;

            FsringHarnessIdentityCheck reopened =
                result.Recheck(fullPath, "sc-initial");
            if (!reopened.Valid)
            {
                throw new IOException(reopened.Detail);
            }
            return result;
        }
        catch
        {
            result.Dispose();
            throw;
        }
    }

    public FsringHarnessIdentityCheck Recheck(
        string requestedPath,
        string stage)
    {
        FsringHarnessIdentityCheck check =
            new FsringHarnessIdentityCheck();
        check.Attempted = true;
        check.Stage = stage;
        try
        {
            if (String.IsNullOrEmpty(stage))
            {
                throw new ArgumentException(
                    "The harness identity stage is empty.");
            }
            string fullPath =
                RequireAbsoluteNormalizedPath(requestedPath);
            RejectReparseComponents(fullPath);

            lock (sync)
            {
                EnsureOpen();
                FsringPinnedMeasurement retained =
                    MeasurePinnedHandle(handle);
                check.Sha256 = retained.Sha256;
                check.Length = retained.Length;
                check.Machine = retained.Machine;
                check.VolumeSerial = retained.VolumeSerial;
                check.FileId = retained.FileId;
                check.FinalPath = retained.FinalPath;

                if (!String.Equals(
                    retained.Sha256,
                    ExpectedSha256,
                    StringComparison.Ordinal) ||
                    retained.Length != Length ||
                    retained.Machine != Machine ||
                    !String.Equals(
                        retained.VolumeSerial,
                        VolumeSerial,
                        StringComparison.Ordinal) ||
                    !String.Equals(
                        retained.FileId,
                        FileId,
                        StringComparison.Ordinal) ||
                    !String.Equals(
                        retained.FinalPath,
                        FinalPath,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new IOException(
                        "The retained harness image bytes or native identity changed.");
                }

                IntPtr reopened =
                    FsringContainedClientNative.CreateFileNoInherit(
                        fullPath,
                        FsringContainedClientNative.GenericRead,
                        FsringContainedClientNative.FileShareRead,
                        IntPtr.Zero,
                        FsringContainedClientNative.OpenExisting,
                        0,
                        IntPtr.Zero);
                if (reopened ==
                    FsringContainedClientNative.InvalidHandleValue)
                {
                    throw NewWin32(
                        "Reopening the requested harness path failed.");
                }
                try
                {
                    uint reopenedFlags;
                    if (!FsringContainedClientNative
                        .GetHandleInformation(
                            reopened,
                            out reopenedFlags) ||
                        (reopenedFlags &
                            FsringContainedClientNative
                                .HandleFlagInherit) != 0)
                    {
                        throw NewWin32(
                            "The reopened harness handle is not proven non-inheritable.");
                    }
                    FsringPinnedIdentity identity =
                        ReadIdentity(reopened);
                    if (!String.Equals(
                        identity.VolumeSerial,
                        VolumeSerial,
                        StringComparison.Ordinal) ||
                        !String.Equals(
                            identity.FileId,
                            FileId,
                            StringComparison.Ordinal) ||
                        !String.Equals(
                            identity.FinalPath,
                            FinalPath,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        throw new IOException(
                            "The requested harness path no longer resolves to the retained native identity.");
                    }
                }
                finally
                {
                    FsringContainedClientNative.CloseHandle(reopened);
                }
            }
            check.Valid = true;
            check.Detail =
                "The retained harness bytes and reopened native identity match.";
        }
        catch (Exception exception)
        {
            check.Valid = false;
            check.Detail = exception.Message;
        }
        return check;
    }

    internal FsringHarnessIdentityCheck PrepareLaunch(
        string requestedPath,
        string stage)
    {
        FsringHarnessIdentityCheck check =
            Recheck(requestedPath, stage);
        if (!check.Valid)
        {
            throw new IOException(
                "Harness launch identity check failed at " +
                stage +
                ": " +
                check.Detail);
        }
        return check;
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (disposed)
            {
                return;
            }
            disposed = true;
            IntPtr owned = handle;
            handle = IntPtr.Zero;
            if (owned != IntPtr.Zero &&
                owned !=
                    FsringContainedClientNative.InvalidHandleValue)
            {
                FsringContainedClientNative.CloseHandle(owned);
            }
        }
        GC.SuppressFinalize(this);
    }

    ~FsringHarnessPin()
    {
        Dispose();
    }

    private void EnsureOpen()
    {
        if (disposed ||
            handle == IntPtr.Zero ||
            handle == FsringContainedClientNative.InvalidHandleValue)
        {
            throw new ObjectDisposedException("FsringHarnessPin");
        }
    }

    private static void ValidateExpectedHash(string expectedSha256)
    {
        if (expectedSha256 == null ||
            expectedSha256.Length != 64)
        {
            throw new ArgumentException(
                "Expected harness SHA-256 must be 64 uppercase hexadecimal characters.");
        }
        foreach (char value in expectedSha256)
        {
            if (!((value >= '0' && value <= '9') ||
                (value >= 'A' && value <= 'F')))
            {
                throw new ArgumentException(
                    "Expected harness SHA-256 must be 64 uppercase hexadecimal characters.");
            }
        }
    }

    private static string RequireAbsoluteNormalizedPath(
        string requestedPath)
    {
        if (String.IsNullOrWhiteSpace(requestedPath) ||
            requestedPath.IndexOf('\0') >= 0 ||
            !Path.IsPathRooted(requestedPath))
        {
            throw new ArgumentException(
                "The harness path must be absolute.");
        }
        string fullPath = Path.GetFullPath(requestedPath);
        if (!String.Equals(
            requestedPath,
            fullPath,
            StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The harness path must already be normalized.");
        }
        return fullPath;
    }

    private static void RejectReparseComponents(string fullPath)
    {
        string root = Path.GetPathRoot(fullPath);
        if (String.IsNullOrEmpty(root))
        {
            throw new ArgumentException(
                "The harness path root is invalid.");
        }
        string remainder = fullPath.Substring(root.Length);
        string[] components = remainder.Split(
            new char[] {
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar
            },
            StringSplitOptions.RemoveEmptyEntries);
        if (components.Length == 0)
        {
            throw new ArgumentException(
                "The harness path has no leaf.");
        }

        string current = root;
        for (int index = 0; index < components.Length; index++)
        {
            current = Path.Combine(current, components[index]);
            uint flags = FileFlagOpenReparsePoint;
            if (index + 1 < components.Length)
            {
                flags |= FileFlagBackupSemantics;
            }
            IntPtr component =
                FsringContainedClientNative.CreateFileNoInherit(
                    current,
                    FsringContainedClientNative.FileReadAttributes,
                    FsringContainedClientNative.FileShareRead |
                        FsringContainedClientNative.FileShareWrite |
                        FsringContainedClientNative.FileShareDelete,
                    IntPtr.Zero,
                    FsringContainedClientNative.OpenExisting,
                    flags,
                    IntPtr.Zero);
            if (component ==
                FsringContainedClientNative.InvalidHandleValue)
            {
                throw NewWin32(
                    "Opening a harness path component without following reparse points failed.");
            }
            try
            {
                FsringContainedClientNative.FileAttributeTagInfo
                    attributes =
                    new FsringContainedClientNative
                        .FileAttributeTagInfo();
                if (!FsringContainedClientNative
                    .GetFileInformationByHandleEx(
                        component,
                        FileAttributeTagInfoClass,
                        ref attributes,
                        checked((uint)Marshal.SizeOf(
                            typeof(
                                FsringContainedClientNative
                                    .FileAttributeTagInfo)))))
                {
                    throw NewWin32(
                        "Reading a harness path component attribute tag failed.");
                }
                if ((attributes.FileAttributes &
                    FileAttributeReparsePoint) != 0)
                {
                    throw new IOException(
                        "The harness path contains a reparse-point component.");
                }
                bool directory =
                    (attributes.FileAttributes &
                        FileAttributeDirectory) != 0;
                if (index + 1 < components.Length &&
                    !directory)
                {
                    throw new IOException(
                        "A non-leaf harness path component is not a directory.");
                }
                if (index + 1 == components.Length &&
                    directory)
                {
                    throw new IOException(
                        "The harness path leaf is a directory.");
                }
            }
            finally
            {
                FsringContainedClientNative.CloseHandle(component);
            }
        }
    }

    private static FsringPinnedMeasurement MeasurePinnedHandle(
        IntPtr handle)
    {
        FsringPinnedMeasurement measurement =
            new FsringPinnedMeasurement();
        FsringPinnedIdentity identity = ReadIdentity(handle);
        measurement.VolumeSerial = identity.VolumeSerial;
        measurement.FileId = identity.FileId;
        measurement.FinalPath = identity.FinalPath;

        SafeFileHandle safeHandle =
            new SafeFileHandle(handle, false);
        using (FileStream stream = new FileStream(
            safeHandle,
            FileAccess.Read,
            65536,
            false))
        {
            measurement.Length = stream.Length;
            if (measurement.Length < 64 ||
                measurement.Length > MaximumHarnessBytes)
            {
                throw new BadImageFormatException(
                    "The smoke harness size is outside the bounded PE range.");
            }

            stream.Position = 0;
            using (SHA256 sha256 = SHA256.Create())
            {
                measurement.Sha256 =
                    ToHex(sha256.ComputeHash(stream));
            }

            stream.Position = 0;
            using (BinaryReader reader = new BinaryReader(
                stream,
                Encoding.UTF8,
                true))
            {
                if (reader.ReadUInt16() != 0x5A4D)
                {
                    throw new BadImageFormatException(
                        "The smoke harness has no MZ header.");
                }
                stream.Position = 0x3C;
                long peOffset = reader.ReadUInt32();
                RequirePeRange(
                    peOffset,
                    24,
                    measurement.Length,
                    "The smoke harness PE and COFF headers are outside the bounded file.");
                stream.Position = peOffset;
                if (reader.ReadUInt32() != 0x00004550)
                {
                    throw new BadImageFormatException(
                        "The smoke harness has no PE signature.");
                }
                measurement.Machine = reader.ReadUInt16();
                ushort numberOfSections = reader.ReadUInt16();
                reader.ReadUInt32();
                uint pointerToSymbolTable = reader.ReadUInt32();
                uint numberOfSymbols = reader.ReadUInt32();
                ushort sizeOfOptionalHeader = reader.ReadUInt16();
                ushort characteristics = reader.ReadUInt16();

                if (numberOfSections < 1 ||
                    numberOfSections > 96)
                {
                    throw new BadImageFormatException(
                        "The smoke harness COFF section count is outside the bounded range.");
                }
                if ((characteristics & 0x0002) == 0)
                {
                    throw new BadImageFormatException(
                        "The smoke harness COFF header is not executable.");
                }
                if ((characteristics & 0x2000) != 0 ||
                    (characteristics & 0x1000) != 0)
                {
                    throw new BadImageFormatException(
                        "The smoke harness COFF header identifies a DLL or system image.");
                }
                if ((pointerToSymbolTable == 0) !=
                    (numberOfSymbols == 0))
                {
                    throw new BadImageFormatException(
                        "The smoke harness COFF symbol-table fields are inconsistent.");
                }
                if (pointerToSymbolTable != 0)
                {
                    long symbolBytes = checked(
                        (long)numberOfSymbols * 18L);
                    long stringTableOffset = checked(
                        (long)pointerToSymbolTable +
                        symbolBytes);
                    RequirePeRange(
                        pointerToSymbolTable,
                        checked(symbolBytes + 4L),
                        measurement.Length,
                        "The smoke harness COFF symbol table is outside the bounded file.");
                    stream.Position = stringTableOffset;
                    uint stringTableBytes = reader.ReadUInt32();
                    if (stringTableBytes < 4)
                    {
                        throw new BadImageFormatException(
                            "The smoke harness COFF string-table size is invalid.");
                    }
                    RequirePeRange(
                        stringTableOffset,
                        stringTableBytes,
                        measurement.Length,
                        "The smoke harness COFF string table is outside the bounded file.");
                }

                const ushort MinimumPe32PlusOptionalHeader = 112;
                const ushort MaximumOptionalHeader = 4096;
                if (sizeOfOptionalHeader <
                        MinimumPe32PlusOptionalHeader ||
                    sizeOfOptionalHeader > MaximumOptionalHeader)
                {
                    throw new BadImageFormatException(
                        "The smoke harness optional-header size is outside the bounded PE32+ range.");
                }

                long optionalOffset = checked(peOffset + 24L);
                RequirePeRange(
                    optionalOffset,
                    sizeOfOptionalHeader,
                    measurement.Length,
                    "The smoke harness PE32+ optional header is outside the bounded file.");
                stream.Position = optionalOffset;
                if (reader.ReadUInt16() != 0x020B)
                {
                    throw new BadImageFormatException(
                        "The smoke harness optional header is not PE32+.");
                }

                stream.Position = checked(optionalOffset + 16L);
                uint addressOfEntryPoint = reader.ReadUInt32();
                stream.Position = checked(optionalOffset + 32L);
                uint sectionAlignment = reader.ReadUInt32();
                uint fileAlignment = reader.ReadUInt32();
                stream.Position = checked(optionalOffset + 56L);
                uint sizeOfImage = reader.ReadUInt32();
                uint sizeOfHeaders = reader.ReadUInt32();
                stream.Position = checked(optionalOffset + 68L);
                ushort subsystem = reader.ReadUInt16();
                stream.Position = checked(optionalOffset + 108L);
                uint numberOfRvaAndSizes = reader.ReadUInt32();

                if (numberOfRvaAndSizes > 16 ||
                    checked(112L +
                        ((long)numberOfRvaAndSizes * 8L)) >
                        sizeOfOptionalHeader)
                {
                    throw new BadImageFormatException(
                        "The smoke harness PE32+ data-directory roster is outside the optional header.");
                }
                if (subsystem != 2 && subsystem != 3)
                {
                    throw new BadImageFormatException(
                        "The smoke harness subsystem is not Windows GUI or CUI.");
                }
                if (!IsPePowerOfTwo(fileAlignment) ||
                    fileAlignment < 512 ||
                    fileAlignment > 65536 ||
                    !IsPePowerOfTwo(sectionAlignment) ||
                    sectionAlignment < fileAlignment)
                {
                    throw new BadImageFormatException(
                        "The smoke harness PE32+ file or section alignment is invalid.");
                }
                if (sizeOfImage == 0 ||
                    sizeOfHeaders == 0 ||
                    sizeOfHeaders > measurement.Length ||
                    sizeOfHeaders > sizeOfImage ||
                    sizeOfHeaders % fileAlignment != 0 ||
                    sizeOfImage % sectionAlignment != 0 ||
                    addressOfEntryPoint >= sizeOfImage)
                {
                    throw new BadImageFormatException(
                        "The smoke harness PE32+ image, header, or entry-point bounds are invalid.");
                }

                uint clrDirectoryRva = 0;
                uint clrDirectorySize = 0;
                if (numberOfRvaAndSizes > 14)
                {
                    stream.Position = checked(optionalOffset + 224L);
                    clrDirectoryRva = reader.ReadUInt32();
                    clrDirectorySize = reader.ReadUInt32();
                }

                long sectionTableOffset = checked(
                    optionalOffset + sizeOfOptionalHeader);
                long sectionTableBytes = checked(
                    (long)numberOfSections * 40L);
                RequirePeRange(
                    sectionTableOffset,
                    sectionTableBytes,
                    measurement.Length,
                    "The smoke harness section table is outside the bounded file.");
                long sectionTableEnd = checked(
                    sectionTableOffset + sectionTableBytes);
                if (sectionTableEnd > sizeOfHeaders)
                {
                    throw new BadImageFormatException(
                        "The smoke harness section table is not contained in SizeOfHeaders.");
                }

                bool executableSection = false;
                bool entryPointValid = false;
                uint[] sectionVirtualAddresses =
                    new uint[numberOfSections];
                uint[] sectionVirtualSizes =
                    new uint[numberOfSections];
                uint[] sectionRawSizes =
                    new uint[numberOfSections];
                uint[] sectionRawPointers =
                    new uint[numberOfSections];
                ulong previousVirtualEnd = sizeOfHeaders;
                long previousRawEnd = sizeOfHeaders;
                for (int index = 0;
                    index < numberOfSections;
                    index++)
                {
                    long sectionOffset = checked(
                        sectionTableOffset + ((long)index * 40L));
                    stream.Position = checked(sectionOffset + 8L);
                    uint virtualSize = reader.ReadUInt32();
                    uint virtualAddress = reader.ReadUInt32();
                    uint sizeOfRawData = reader.ReadUInt32();
                    uint pointerToRawData = reader.ReadUInt32();
                    stream.Position = checked(sectionOffset + 36L);
                    uint sectionCharacteristics =
                        reader.ReadUInt32();
                    sectionVirtualAddresses[index] = virtualAddress;
                    sectionVirtualSizes[index] = virtualSize;
                    sectionRawSizes[index] = sizeOfRawData;
                    sectionRawPointers[index] = pointerToRawData;

                    if (virtualSize == 0 && sizeOfRawData == 0)
                    {
                        throw new BadImageFormatException(
                            "The smoke harness contains an empty section.");
                    }
                    if (virtualAddress == 0 ||
                        virtualAddress % sectionAlignment != 0)
                    {
                        throw new BadImageFormatException(
                            "A smoke harness section has a misaligned or zero RVA.");
                    }
                    if (sizeOfRawData != 0)
                    {
                        if (pointerToRawData < sizeOfHeaders ||
                            pointerToRawData % fileAlignment != 0 ||
                            sizeOfRawData % fileAlignment != 0 ||
                            pointerToRawData < previousRawEnd)
                        {
                            throw new BadImageFormatException(
                                "A smoke harness section has overlapping or misaligned raw bytes.");
                        }
                        RequirePeRange(
                            pointerToRawData,
                            sizeOfRawData,
                            measurement.Length,
                            "A smoke harness section has raw bytes outside the bounded file.");
                        previousRawEnd = checked(
                            (long)pointerToRawData +
                            sizeOfRawData);
                    }
                    ulong mappedBytes = Math.Max(
                        (ulong)virtualSize,
                        (ulong)sizeOfRawData);
                    ulong virtualEnd = checked(
                        (ulong)virtualAddress + mappedBytes);
                    if ((ulong)virtualAddress <
                            previousVirtualEnd ||
                        virtualEnd >
                        (ulong)sizeOfImage)
                    {
                        throw new BadImageFormatException(
                            "A smoke harness section overlaps or exceeds SizeOfImage.");
                    }
                    previousVirtualEnd = virtualEnd;
                    if ((sectionCharacteristics &
                        0x20000000U) != 0)
                    {
                        executableSection = true;
                        if ((ulong)addressOfEntryPoint >=
                                (ulong)virtualAddress &&
                            (ulong)addressOfEntryPoint <
                                virtualEnd)
                        {
                            entryPointValid = true;
                        }
                    }
                }
                if (addressOfEntryPoint == 0)
                {
                    entryPointValid = HasValidManagedEntryPoint(
                        reader,
                        stream,
                        measurement.Length,
                        sizeOfImage,
                        clrDirectoryRva,
                        clrDirectorySize,
                        sectionVirtualAddresses,
                        sectionVirtualSizes,
                        sectionRawSizes,
                        sectionRawPointers);
                }
                if (!executableSection ||
                    !entryPointValid)
                {
                    throw new BadImageFormatException(
                        "The smoke harness has no executable section or its native entry point is outside executable sections.");
                }
            }
        }
        return measurement;
    }

    private static bool HasValidManagedEntryPoint(
        BinaryReader reader,
        Stream stream,
        long fileLength,
        uint sizeOfImage,
        uint clrDirectoryRva,
        uint clrDirectorySize,
        uint[] sectionVirtualAddresses,
        uint[] sectionVirtualSizes,
        uint[] sectionRawSizes,
        uint[] sectionRawPointers)
    {
        const uint CorHeaderSize = 72;
        const uint ComImageFlagsIlOnly = 0x00000001;
        const uint ComImageFlags32BitRequired = 0x00000002;
        const uint ComImageFlagsIlLibrary = 0x00000004;
        const uint ComImageFlagsNativeEntryPoint = 0x00000010;
        const uint ComImageFlags32BitPreferred = 0x00020000;
        const uint UnsupportedManagedLaunchFlags =
            ComImageFlags32BitRequired |
            ComImageFlagsIlLibrary |
            ComImageFlagsNativeEntryPoint |
            ComImageFlags32BitPreferred;
        if (clrDirectoryRva == 0 ||
            clrDirectorySize != CorHeaderSize ||
            (ulong)clrDirectoryRva + CorHeaderSize >
                (ulong)sizeOfImage)
        {
            return false;
        }

        long clrOffset;
        if (!TryMapPeRva(
            clrDirectoryRva,
            CorHeaderSize,
            sectionVirtualAddresses,
            sectionVirtualSizes,
            sectionRawSizes,
            sectionRawPointers,
            fileLength,
            out clrOffset))
        {
            return false;
        }

        stream.Position = clrOffset;
        uint headerSize = reader.ReadUInt32();
        ushort runtimeMajor = reader.ReadUInt16();
        reader.ReadUInt16();
        uint metadataRva = reader.ReadUInt32();
        uint metadataSize = reader.ReadUInt32();
        uint flags = reader.ReadUInt32();
        uint entryPointToken = reader.ReadUInt32();
        if (headerSize != CorHeaderSize ||
            runtimeMajor < 2 ||
            metadataRva == 0 ||
            metadataSize < 16 ||
            (flags & ComImageFlagsIlOnly) == 0 ||
            (flags & UnsupportedManagedLaunchFlags) != 0 ||
            (entryPointToken & 0xFF000000U) != 0x06000000U ||
            (entryPointToken & 0x00FFFFFFU) == 0)
        {
            return false;
        }

        long metadataOffset;
        if (!TryMapPeRva(
            metadataRva,
            metadataSize,
            sectionVirtualAddresses,
            sectionVirtualSizes,
            sectionRawSizes,
            sectionRawPointers,
            fileLength,
            out metadataOffset))
        {
            return false;
        }
        stream.Position = metadataOffset;
        return reader.ReadUInt32() == 0x424A5342U;
    }

    private static bool TryMapPeRva(
        uint rva,
        uint requiredBytes,
        uint[] sectionVirtualAddresses,
        uint[] sectionVirtualSizes,
        uint[] sectionRawSizes,
        uint[] sectionRawPointers,
        long fileLength,
        out long fileOffset)
    {
        fileOffset = 0;
        if (rva == 0 || requiredBytes == 0)
        {
            return false;
        }
        for (int index = 0;
            index < sectionVirtualAddresses.Length;
            index++)
        {
            ulong virtualAddress = sectionVirtualAddresses[index];
            ulong mappedBytes = Math.Max(
                (ulong)sectionVirtualSizes[index],
                (ulong)sectionRawSizes[index]);
            ulong candidateRva = rva;
            if (candidateRva < virtualAddress)
            {
                continue;
            }
            ulong delta = candidateRva - virtualAddress;
            ulong requiredEnd = delta + requiredBytes;
            if (requiredEnd > mappedBytes ||
                requiredEnd > sectionRawSizes[index])
            {
                continue;
            }
            ulong candidateOffset =
                (ulong)sectionRawPointers[index] + delta;
            if (candidateOffset > (ulong)fileLength ||
                requiredBytes >
                    (ulong)fileLength - candidateOffset)
            {
                continue;
            }
            fileOffset = checked((long)candidateOffset);
            return true;
        }
        return false;
    }

    private static void RequirePeRange(
        long offset,
        long count,
        long length,
        string message)
    {
        if (offset < 0 ||
            count < 0 ||
            offset > length ||
            count > length - offset)
        {
            throw new BadImageFormatException(message);
        }
    }

    private static bool IsPePowerOfTwo(uint value)
    {
        return value != 0 &&
            (value & (value - 1)) == 0;
    }

    private static FsringPinnedIdentity ReadIdentity(
        IntPtr handle)
    {
        FsringContainedClientNative.FileIdInfo nativeId =
            new FsringContainedClientNative.FileIdInfo();
        uint size = checked((uint)Marshal.SizeOf(
            typeof(FsringContainedClientNative.FileIdInfo)));
        if (size != 24 ||
            !FsringContainedClientNative
                .GetFileInformationByHandleEx(
                    handle,
                    FileIdInfoClass,
                    ref nativeId,
                    size))
        {
            throw NewWin32(
                "Reading 128-bit FILE_ID_INFO failed.");
        }

        FsringPinnedIdentity identity =
            new FsringPinnedIdentity();
        identity.VolumeSerial =
            nativeId.VolumeSerialNumber.ToString("X16");
        byte[] fileIdBytes = new byte[16];
        Buffer.BlockCopy(
            BitConverter.GetBytes(nativeId.FileIdLow),
            0,
            fileIdBytes,
            0,
            8);
        Buffer.BlockCopy(
            BitConverter.GetBytes(nativeId.FileIdHigh),
            0,
            fileIdBytes,
            8,
            8);
        identity.FileId = ToHex(fileIdBytes);
        identity.FinalPath =
            NormalizeFinalPath(ReadFinalPath(handle));
        return identity;
    }

    private static string ReadFinalPath(IntPtr handle)
    {
        uint required =
            FsringContainedClientNative.GetFinalPathNameByHandle(
                handle,
                null,
                0,
                0);
        if (required == 0 || required > 32768)
        {
            throw NewWin32(
                "Sizing the harness final path failed.");
        }
        StringBuilder buffer =
            new StringBuilder(checked((int)required + 1));
        uint written =
            FsringContainedClientNative.GetFinalPathNameByHandle(
                handle,
                buffer,
                checked((uint)buffer.Capacity),
                0);
        if (written == 0 ||
            written >= buffer.Capacity)
        {
            throw NewWin32(
                "Reading the harness final path failed.");
        }
        return buffer.ToString();
    }

    private static string NormalizeFinalPath(string path)
    {
        const string uncPrefix = @"\\?\UNC\";
        const string drivePrefix = @"\\?\";
        if (path.StartsWith(
            uncPrefix,
            StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + path.Substring(uncPrefix.Length);
        }
        if (path.StartsWith(
            drivePrefix,
            StringComparison.OrdinalIgnoreCase))
        {
            return path.Substring(drivePrefix.Length);
        }
        return path;
    }

    private static string ToHex(byte[] bytes)
    {
        StringBuilder builder =
            new StringBuilder(bytes.Length * 2);
        foreach (byte value in bytes)
        {
            builder.Append(value.ToString("X2"));
        }
        return builder.ToString();
    }

    private static Win32Exception NewWin32(string message)
    {
        return new Win32Exception(
            Marshal.GetLastWin32Error(),
            message);
    }

    private sealed class FsringPinnedMeasurement
    {
        internal string Sha256;
        internal long Length;
        internal ushort Machine;
        internal string VolumeSerial;
        internal string FileId;
        internal string FinalPath;
    }

    private sealed class FsringPinnedIdentity
    {
        internal string VolumeSerial;
        internal string FileId;
        internal string FinalPath;
    }
}

public static class FsringNativeSystemTool
{
    public static FsringHarnessPin OpenScPin()
    {
        return FsringHarnessPin.OpenNativeSystemTool("sc.exe");
    }

    public static string ResolveScPath()
    {
        using (FsringHarnessPin pin = OpenScPin())
        {
            return pin.FinalPath;
        }
    }
}

internal sealed class FsringSafeJobHandle :
    SafeHandleZeroOrMinusOneIsInvalid
{
    internal FsringSafeJobHandle()
        : base(true)
    {
    }

    protected override bool ReleaseHandle()
    {
        return FsringContainedClientNative.CloseHandle(handle);
    }
}

public sealed class FsringContainedClientLease : IDisposable
{
    private FsringSafeJobHandle job;
    private FsringContainedClientDrain stdoutDrain;
    private FsringContainedClientDrain stderrDrain;
    private int disposed;

    internal FsringContainedClientLease(
        FsringSafeJobHandle jobHandle,
        FsringContainedClientDrain stdout,
        FsringContainedClientDrain stderr)
    {
        if (jobHandle == null ||
            jobHandle.IsInvalid ||
            jobHandle.IsClosed)
        {
            throw new ArgumentException(
                "The retained private job owner is invalid.");
        }
        job = jobHandle;
        stdoutDrain = stdout;
        stderrDrain = stderr;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        FsringSafeJobHandle ownedJob = job;
        job = null;
        if (ownedJob != null)
        {
            try
            {
                if (!ownedJob.IsInvalid &&
                    !ownedJob.IsClosed)
                {
                    FsringContainedClientNative.TerminateJobObject(
                        ownedJob,
                        unchecked((uint)0xC000013A));
                }
            }
            catch
            {
            }
            try
            {
                ownedJob.Dispose();
            }
            catch
            {
            }
        }

        FsringContainedClientDrain ownedStdout = stdoutDrain;
        stdoutDrain = null;
        if (ownedStdout != null)
        {
            try
            {
                ownedStdout.Dispose();
            }
            catch
            {
            }
        }
        FsringContainedClientDrain ownedStderr = stderrDrain;
        stderrDrain = null;
        if (ownedStderr != null)
        {
            try
            {
                ownedStderr.Dispose();
            }
            catch
            {
            }
        }
    }
}

public sealed class FsringContainedClientResult
{
    public int? ExitCode { get; internal set; }
    public string[] Stdout { get; internal set; }
    public string[] Stderr { get; internal set; }
    public bool TimedOut { get; internal set; }
    public bool ContainmentConfirmed { get; internal set; }
    public bool OutputTruncated { get; internal set; }
    public bool StdoutTruncated { get; internal set; }
    public bool StderrTruncated { get; internal set; }
    public int StdoutByteCount { get; internal set; }
    public int StderrByteCount { get; internal set; }
    public long StdoutTotalByteCount { get; internal set; }
    public long StderrTotalByteCount { get; internal set; }
    public bool ProtocolValid { get; internal set; }
    public bool OutputFinalized { get; internal set; }
    public string Error { get; internal set; }
    public FsringContainedClientLease Lease { get; internal set; }
    public FsringHarnessIdentityCheck IdentityCheck { get; internal set; }

    internal FsringContainedClientResult()
    {
        Stdout = new string[0];
        Stderr = new string[0];
        ProtocolValid = true;
    }
}

internal sealed class FsringContainedClientDrain : IDisposable
{
    private readonly FileStream stream;
    private readonly int cap;
    private readonly MemoryStream stored;
    private readonly Thread thread;
    private Exception failure;
    private long total;
    private int disposed;

    private FsringContainedClientDrain(
        FileStream ownedStream,
        MemoryStream ownedStored,
        int byteCap)
    {
        stream = ownedStream;
        cap = byteCap;
        stored = ownedStored;
        thread = new Thread(Drain);
        thread.IsBackground = true;
        thread.Name = "fsring-contained-client-drain";
    }

    internal static FsringContainedClientDrain Create(
        ref IntPtr readHandle,
        int byteCap,
        bool injectFailure)
    {
        IntPtr transferred = readHandle;
        readHandle = IntPtr.Zero;
        if (transferred == IntPtr.Zero ||
            transferred ==
                FsringContainedClientNative.InvalidHandleValue)
        {
            throw new ArgumentException(
                "The redirected read handle is invalid.");
        }

        SafeFileHandle safeHandle = null;
        FileStream ownedStream = null;
        MemoryStream ownedStored = null;
        try
        {
            safeHandle = new SafeFileHandle(transferred, true);
            ownedStream = new FileStream(
                safeHandle,
                FileAccess.Read,
                4096,
                false);
            safeHandle = null;
            if (injectFailure)
            {
                throw new IOException(
                    "Injected drain construction failure.");
            }
            ownedStored = new MemoryStream(byteCap);
            FsringContainedClientDrain result =
                new FsringContainedClientDrain(
                    ownedStream,
                    ownedStored,
                    byteCap);
            ownedStream = null;
            ownedStored = null;
            return result;
        }
        finally
        {
            if (ownedStored != null)
            {
                ownedStored.Dispose();
            }
            if (ownedStream != null)
            {
                ownedStream.Dispose();
            }
            else if (safeHandle != null)
            {
                safeHandle.Dispose();
            }
        }
    }

    internal void Start()
    {
        thread.Start();
    }

    private void Drain()
    {
        byte[] buffer = new byte[8192];
        try
        {
            while (true)
            {
                int read = stream.Read(buffer, 0, buffer.Length);
                if (read == 0)
                {
                    break;
                }
                total += read;
                int remaining = cap - checked((int)stored.Length);
                if (remaining > 0)
                {
                    int retained = Math.Min(remaining, read);
                    stored.Write(buffer, 0, retained);
                }
            }
        }
        catch (ObjectDisposedException)
        {
            if (Volatile.Read(ref disposed) == 0)
            {
                failure = new IOException(
                    "A redirected stream was disposed before EOF.");
            }
        }
        catch (Exception exception)
        {
            failure = exception;
        }
    }

    internal bool Join(int milliseconds)
    {
        return thread.Join(milliseconds);
    }

    internal byte[] GetBytes()
    {
        return stored.ToArray();
    }

    internal long Total
    {
        get { return total; }
    }

    internal bool Truncated
    {
        get { return total > stored.Length; }
    }

    internal Exception Failure
    {
        get { return failure; }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }
        try
        {
            stream.Dispose();
        }
        catch
        {
        }
        try
        {
            if (thread.IsAlive)
            {
                thread.Join(1000);
            }
        }
        catch
        {
        }
        try
        {
            stored.Dispose();
        }
        catch
        {
        }
    }
}

internal static class FsringContainedClientNative
{
    internal const uint CreateSuspended = 0x00000004;
    internal const uint ExtendedStartupInfoPresent = 0x00080000;
    internal const uint StartfUseStdHandles = 0x00000100;
    internal const uint HandleFlagInherit = 0x00000001;
    internal const uint GenericRead = 0x80000000;
    internal const uint FileReadAttributes = 0x00000080;
    internal const uint FileShareRead = 0x00000001;
    internal const uint FileShareWrite = 0x00000002;
    internal const uint FileShareDelete = 0x00000004;
    internal const uint OpenExisting = 3;
    internal const uint JobObjectLimitKillOnJobClose = 0x00002000;
    internal const int JobObjectBasicAccountingInformationClass = 1;
    internal const int JobObjectExtendedLimitInformationClass = 9;
    internal static readonly IntPtr InvalidHandleValue = new IntPtr(-1);
    internal static readonly IntPtr ProcThreadAttributeHandleList =
        new IntPtr(0x00020002);
    internal static readonly IntPtr ProcThreadAttributeJobList =
        new IntPtr(0x0002000D);

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityAttributes
    {
        internal int Length;
        internal IntPtr SecurityDescriptor;
        internal int InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FileAttributeTagInfo
    {
        internal uint FileAttributes;
        internal uint ReparseTag;
    }

    [StructLayout(LayoutKind.Explicit, Size = 24)]
    internal struct FileIdInfo
    {
        [FieldOffset(0)]
        internal ulong VolumeSerialNumber;

        [FieldOffset(8)]
        internal ulong FileIdLow;

        [FieldOffset(16)]
        internal ulong FileIdHigh;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct StartupInfo
    {
        internal int Size;
        internal IntPtr Reserved;
        internal IntPtr Desktop;
        internal IntPtr Title;
        internal int X;
        internal int Y;
        internal int XSize;
        internal int YSize;
        internal int XCountChars;
        internal int YCountChars;
        internal int FillAttribute;
        internal uint Flags;
        internal short ShowWindow;
        internal short Reserved2Size;
        internal IntPtr Reserved2;
        internal IntPtr StandardInput;
        internal IntPtr StandardOutput;
        internal IntPtr StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct StartupInfoEx
    {
        internal StartupInfo StartupInfo;
        internal IntPtr AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessInformation
    {
        internal IntPtr Process;
        internal IntPtr Thread;
        internal uint ProcessId;
        internal uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectBasicLimitInformation
    {
        internal long PerProcessUserTimeLimit;
        internal long PerJobUserTimeLimit;
        internal uint LimitFlags;
        internal UIntPtr MinimumWorkingSetSize;
        internal UIntPtr MaximumWorkingSetSize;
        internal uint ActiveProcessLimit;
        internal UIntPtr Affinity;
        internal uint PriorityClass;
        internal uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IoCounters
    {
        internal ulong ReadOperationCount;
        internal ulong WriteOperationCount;
        internal ulong OtherOperationCount;
        internal ulong ReadTransferCount;
        internal ulong WriteTransferCount;
        internal ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectExtendedLimitInformation
    {
        internal JobObjectBasicLimitInformation BasicLimitInformation;
        internal IoCounters IoInfo;
        internal UIntPtr ProcessMemoryLimit;
        internal UIntPtr JobMemoryLimit;
        internal UIntPtr PeakProcessMemoryUsed;
        internal UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectBasicAccountingInformation
    {
        internal long TotalUserTime;
        internal long TotalKernelTime;
        internal long ThisPeriodTotalUserTime;
        internal long ThisPeriodTotalKernelTime;
        internal uint TotalPageFaultCount;
        internal uint TotalProcesses;
        internal uint ActiveProcesses;
        internal uint TotalTerminatedProcesses;
    }

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    internal static extern FsringSafeJobHandle CreateJobObject(
        IntPtr jobAttributes,
        string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetInformationJobObject(
        FsringSafeJobHandle job,
        int informationClass,
        ref JobObjectExtendedLimitInformation information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryInformationJobObject(
        FsringSafeJobHandle job,
        int informationClass,
        ref JobObjectExtendedLimitInformation information,
        uint informationLength,
        out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryInformationJobObject(
        FsringSafeJobHandle job,
        int informationClass,
        ref JobObjectBasicAccountingInformation information,
        uint informationLength,
        out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateJobObject(
        FsringSafeJobHandle job,
        uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreatePipe(
        out IntPtr readPipe,
        out IntPtr writePipe,
        ref SecurityAttributes pipeAttributes,
        uint size);

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    internal static extern IntPtr CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        ref SecurityAttributes securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "CreateFileW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    internal static extern IntPtr CreateFileNoInherit(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileInformationByHandleEx(
        IntPtr file,
        int informationClass,
        ref FileAttributeTagInfo information,
        uint bufferSize);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFileInformationByHandleEx",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileInformationByHandleEx(
        IntPtr file,
        int informationClass,
        ref FileIdInfo information,
        uint bufferSize);

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    internal static extern uint GetSystemDirectory(
        StringBuilder buffer,
        uint size);

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    internal static extern uint GetFinalPathNameByHandle(
        IntPtr file,
        StringBuilder filePath,
        uint filePathLength,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetHandleInformation(
        IntPtr handle,
        uint mask,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetHandleInformation(
        IntPtr handle,
        out uint flags);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetHandleInformation",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetHandleInformation(
        FsringSafeJobHandle handle,
        out uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool InitializeProcThreadAttributeList(
        IntPtr attributeList,
        int attributeCount,
        int flags,
        ref UIntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool UpdateProcThreadAttribute(
        IntPtr attributeList,
        uint flags,
        IntPtr attribute,
        IntPtr value,
        UIntPtr valueSize,
        IntPtr previousValue,
        IntPtr returnSize);

    [DllImport("kernel32.dll")]
    internal static extern void DeleteProcThreadAttributeList(
        IntPtr attributeList);

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateProcess(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref StartupInfoEx startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint WaitForSingleObject(
        IntPtr handle,
        uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetExitCodeProcess(
        IntPtr process,
        out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);
}

public static class FsringContainedClientRunner
{
    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 258;
    private const uint StillActive = 259;
    private const uint TerminatedExitCode = 0xC000013A;

    public static int GetStartupInfoExSize()
    {
        return Marshal.SizeOf(
            typeof(FsringContainedClientNative.StartupInfoEx));
    }

    public static int GetProcessInformationSize()
    {
        return Marshal.SizeOf(
            typeof(FsringContainedClientNative.ProcessInformation));
    }

    public static int GetJobExtendedLimitInformationSize()
    {
        return Marshal.SizeOf(
            typeof(
                FsringContainedClientNative
                    .JobObjectExtendedLimitInformation));
    }

    public static int GetJobAccountingInformationSize()
    {
        return Marshal.SizeOf(
            typeof(
                FsringContainedClientNative
                    .JobObjectBasicAccountingInformation));
    }

    public static int GetSecurityAttributesSize()
    {
        return Marshal.SizeOf(
            typeof(FsringContainedClientNative.SecurityAttributes));
    }

    public static string QuoteArgumentForTest(string argument)
    {
        return QuoteArgument(argument);
    }

    public static IntPtr OpenInheritableFileForTest(string path)
    {
        FsringContainedClientNative.SecurityAttributes attributes =
            new FsringContainedClientNative.SecurityAttributes();
        attributes.Length = GetSecurityAttributesSize();
        attributes.InheritHandle = 1;
        IntPtr handle = FsringContainedClientNative.CreateFile(
            path,
            FsringContainedClientNative.GenericRead,
            FsringContainedClientNative.FileShareRead,
            ref attributes,
            FsringContainedClientNative.OpenExisting,
            0,
            IntPtr.Zero);
        if (handle ==
            FsringContainedClientNative.InvalidHandleValue)
        {
            throw NewWin32(
                "Opening the inheritable test handle failed.");
        }
        return handle;
    }

    public static void CloseHandleForTest(IntPtr handle)
    {
        if (handle != IntPtr.Zero &&
            handle != FsringContainedClientNative.InvalidHandleValue)
        {
            FsringContainedClientNative.CloseHandle(handle);
        }
    }

    public static bool TestFailedAttributeInitializationCleanup()
    {
        IntPtr attributeList = Marshal.AllocHGlobal(64);
        bool initialized = false;
        IntPtr jobValue = IntPtr.Zero;
        IntPtr handleValues = IntPtr.Zero;
        FsringSafeJobHandle job = null;
        bool jobAttributeBorrowed = false;
        DeleteAttributeList(
            ref attributeList,
            ref initialized,
            ref jobValue,
            ref handleValues,
            job,
            ref jobAttributeBorrowed);
        return attributeList == IntPtr.Zero &&
            !initialized &&
            !jobAttributeBorrowed;
    }

    public static bool TestDrainConstructionFailureOwnership()
    {
        IntPtr readPipe = IntPtr.Zero;
        IntPtr writePipe = IntPtr.Zero;
        FsringContainedClientNative.SecurityAttributes attributes =
            new FsringContainedClientNative.SecurityAttributes();
        attributes.Length = GetSecurityAttributesSize();
        attributes.InheritHandle = 1;
        if (!FsringContainedClientNative.CreatePipe(
            out readPipe,
            out writePipe,
            ref attributes,
            0))
        {
            throw NewWin32(
                "Creating the drain ownership test pipe failed.");
        }
        try
        {
            if (!FsringContainedClientNative.SetHandleInformation(
                readPipe,
                FsringContainedClientNative.HandleFlagInherit,
                0))
            {
                throw NewWin32(
                    "Making the drain ownership test reader non-inheritable failed.");
            }
            IntPtr transferred = readPipe;
            bool failed = false;
            try
            {
                FsringContainedClientDrain.Create(
                    ref readPipe,
                    1024,
                    true);
            }
            catch (IOException)
            {
                failed = true;
            }
            GC.Collect();
            GC.WaitForPendingFinalizers();
            uint flags;
            bool stillOpen =
                FsringContainedClientNative.GetHandleInformation(
                    transferred,
                    out flags);
            return failed &&
                readPipe == IntPtr.Zero &&
                !stillOpen;
        }
        finally
        {
            Close(ref readPipe);
            Close(ref writePipe);
        }
    }

    public static FsringContainedClientResult Run(
        string applicationPath,
        string[] arguments,
        int timeoutMilliseconds,
        int containmentTimeoutMilliseconds,
        int streamCapBytes,
        object launchPin,
        bool injectContainmentQueryFailure)
    {
        return RunCore(
            applicationPath,
            arguments,
            timeoutMilliseconds,
            containmentTimeoutMilliseconds,
            streamCapBytes,
            launchPin,
            injectContainmentQueryFailure,
            false,
            false,
            false,
            0,
            0,
            0,
            null,
            "runner",
            true);
    }

    public static FsringContainedClientResult RunPinned(
        FsringHarnessPin launchPin,
        string applicationPath,
        string launchStage,
        string[] arguments,
        int timeoutMilliseconds,
        int containmentTimeoutMilliseconds,
        int streamCapBytes)
    {
        if (launchPin == null)
        {
            throw new ArgumentNullException("launchPin");
        }
        return RunCore(
            applicationPath,
            arguments,
            timeoutMilliseconds,
            containmentTimeoutMilliseconds,
            streamCapBytes,
            launchPin,
            false,
            false,
            false,
            false,
            0,
            0,
            0,
            null,
            launchStage,
            true);
    }

    public static FsringContainedClientResult RunOpaquePinned(
        FsringHarnessPin launchPin,
        string applicationPath,
        string launchStage,
        string[] arguments,
        int timeoutMilliseconds,
        int containmentTimeoutMilliseconds,
        int streamCapBytes)
    {
        if (launchPin == null)
        {
            throw new ArgumentNullException("launchPin");
        }
        return RunCore(
            applicationPath,
            arguments,
            timeoutMilliseconds,
            containmentTimeoutMilliseconds,
            streamCapBytes,
            launchPin,
            false,
            false,
            false,
            false,
            0,
            0,
            0,
            null,
            launchStage,
            false);
    }

    public static FsringContainedClientResult RunHandleProbeForTest(
        string applicationPath,
        long ambientHandle,
        long pinnedHandle,
        int timeoutMilliseconds,
        int containmentTimeoutMilliseconds,
        int streamCapBytes,
        FsringHarnessPin launchPin)
    {
        return RunCore(
            applicationPath,
            new string[0],
            timeoutMilliseconds,
            containmentTimeoutMilliseconds,
            streamCapBytes,
            launchPin,
            false,
            false,
            false,
            true,
            ambientHandle,
            pinnedHandle,
            0,
            null,
            "handle-probe",
            true);
    }

    public static FsringContainedClientResult RunWithFailuresForTest(
        string applicationPath,
        string[] arguments,
        int timeoutMilliseconds,
        int containmentTimeoutMilliseconds,
        int streamCapBytes,
        bool injectContainmentQueryFailure,
        bool injectTerminateFailure,
        bool injectDrainJoinFailure)
    {
        return RunCore(
            applicationPath,
            arguments,
            timeoutMilliseconds,
            containmentTimeoutMilliseconds,
            streamCapBytes,
            null,
            injectContainmentQueryFailure,
            injectTerminateFailure,
            injectDrainJoinFailure,
            false,
            0,
            0,
            0,
            null,
            "failure-test",
            true);
    }

    public static FsringContainedClientResult
        RunWithPostCreateDelayForTest(
            string applicationPath,
            string[] arguments,
            int timeoutMilliseconds,
            int containmentTimeoutMilliseconds,
            int streamCapBytes,
            int postCreateDelayMilliseconds,
            string resumedSentinelPath)
    {
        return RunCore(
            applicationPath,
            arguments,
            timeoutMilliseconds,
            containmentTimeoutMilliseconds,
            streamCapBytes,
            null,
            false,
            false,
            false,
            false,
            0,
            0,
            postCreateDelayMilliseconds,
            resumedSentinelPath,
            "post-create-deadline-test",
            true);
    }

    [System.Runtime.CompilerServices.MethodImpl(
        System.Runtime.CompilerServices.MethodImplOptions.NoInlining |
        System.Runtime.CompilerServices.MethodImplOptions.NoOptimization)]
    public static WeakReference[] AbandonUnconfirmedResultForTest(
        string applicationPath,
        string sentinelPath,
        string readyPath,
        int childDelayMilliseconds)
    {
        FsringContainedClientResult abandoned = RunCore(
            applicationPath,
            new string[] {
                "root-exits",
                sentinelPath,
                readyPath,
                childDelayMilliseconds.ToString(
                    System.Globalization.CultureInfo.InvariantCulture)
            },
            5000,
            250,
            65536,
            null,
            true,
            true,
            true,
            false,
            0,
            0,
            0,
            null,
            "abandoned-result-test",
            true);
        if (abandoned == null ||
            abandoned.ContainmentConfirmed ||
            abandoned.OutputFinalized ||
            abandoned.Lease == null)
        {
            if (abandoned != null && abandoned.Lease != null)
            {
                abandoned.Lease.Dispose();
            }
            throw new InvalidOperationException(
                "The abandoned-result seam did not obtain an unconfirmed live lease.");
        }

        FsringContainedClientLease abandonedLease = abandoned.Lease;
        WeakReference[] references = new WeakReference[] {
            new WeakReference(abandoned),
            new WeakReference(abandonedLease)
        };
        abandoned = null;
        abandonedLease = null;
        return references;
    }

    private static FsringContainedClientResult RunCore(
        string applicationPath,
        string[] arguments,
        int timeoutMilliseconds,
        int containmentTimeoutMilliseconds,
        int streamCapBytes,
        object launchPin,
        bool injectContainmentQueryFailure,
        bool injectTerminateFailure,
        bool injectDrainJoinFailure,
        bool handleProbe,
        long ambientHandle,
        long pinnedHandle,
        int postCreateDelayMilliseconds,
        string resumedSentinelPath,
        string launchStage,
        bool decodeOutput)
    {
        FsringContainedClientResult result =
            new FsringContainedClientResult();
        FsringSafeJobHandle job = null;
        IntPtr standardInput = IntPtr.Zero;
        IntPtr stdoutRead = IntPtr.Zero;
        IntPtr stdoutWrite = IntPtr.Zero;
        IntPtr stderrRead = IntPtr.Zero;
        IntPtr stderrWrite = IntPtr.Zero;
        IntPtr attributeList = IntPtr.Zero;
        bool attributeListInitialized = false;
        IntPtr jobValue = IntPtr.Zero;
        IntPtr handleValues = IntPtr.Zero;
        FsringContainedClientNative.ProcessInformation processInformation =
            new FsringContainedClientNative.ProcessInformation();
        FsringContainedClientDrain stdoutDrain = null;
        FsringContainedClientDrain stderrDrain = null;
        bool processCreated = false;
        bool rootHandleClosed = false;
        bool jobTransferred = false;
        bool jobAttributeBorrowed = false;
        FsringSafeJobHandle jobAttributeOwner = null;

        try
        {
            ValidateInputs(
                applicationPath,
                arguments,
                timeoutMilliseconds,
                containmentTimeoutMilliseconds,
                streamCapBytes,
                launchPin,
                postCreateDelayMilliseconds,
                resumedSentinelPath);
            ValidateLayouts();

            job = CreateVerifiedJob();
            if (handleProbe)
            {
                arguments = new string[] {
                    "handles",
                    ambientHandle.ToString(
                        System.Globalization.CultureInfo.InvariantCulture),
                    pinnedHandle.ToString(
                        System.Globalization.CultureInfo.InvariantCulture),
                    GetJobHandleValueForTest(job).ToString(
                        System.Globalization.CultureInfo.InvariantCulture)
                };
            }
            CreateRedirectedHandles(
                out standardInput,
                out stdoutRead,
                out stdoutWrite,
                out stderrRead,
                out stderrWrite);
            jobAttributeOwner = job;
            CreateAttributeList(
                job,
                standardInput,
                stdoutWrite,
                stderrWrite,
                out attributeList,
                out attributeListInitialized,
                out jobValue,
                out handleValues,
                ref jobAttributeBorrowed);

            FsringContainedClientNative.StartupInfoEx startupInfo =
                new FsringContainedClientNative.StartupInfoEx();
            startupInfo.StartupInfo.Size = GetStartupInfoExSize();
            startupInfo.StartupInfo.Flags =
                FsringContainedClientNative.StartfUseStdHandles;
            startupInfo.StartupInfo.StandardInput = standardInput;
            startupInfo.StartupInfo.StandardOutput = stdoutWrite;
            startupInfo.StartupInfo.StandardError = stderrWrite;
            startupInfo.AttributeList = attributeList;

            FsringHarnessPin typedPin =
                launchPin as FsringHarnessPin;
            if (typedPin != null)
            {
                result.IdentityCheck = typedPin.Recheck(
                    applicationPath,
                    launchStage);
                if (!result.IdentityCheck.Valid)
                {
                    throw new IOException(
                        "Harness launch identity check failed at " +
                        launchStage +
                        ": " +
                        result.IdentityCheck.Detail);
                }
                applicationPath = typedPin.FinalPath;
            }
            StringBuilder commandLine = BuildCommandLine(
                applicationPath,
                arguments);
            string currentDirectory =
                Path.GetDirectoryName(applicationPath);
            if (!FsringContainedClientNative.CreateProcess(
                applicationPath,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                FsringContainedClientNative.CreateSuspended |
                    FsringContainedClientNative
                        .ExtendedStartupInfoPresent,
                IntPtr.Zero,
                currentDirectory,
                ref startupInfo,
                out processInformation))
            {
                throw NewWin32("CreateProcessW failed.");
            }
            processCreated = true;
            Stopwatch deadline = Stopwatch.StartNew();
            if (postCreateDelayMilliseconds != 0)
            {
                Thread.Sleep(postCreateDelayMilliseconds);
            }

            Close(ref standardInput);
            Close(ref stdoutWrite);
            Close(ref stderrWrite);
            DeleteAttributeList(
                ref attributeList,
                ref attributeListInitialized,
                ref jobValue,
                ref handleValues,
                jobAttributeOwner,
                ref jobAttributeBorrowed);
            jobAttributeOwner = null;

            stdoutDrain =
                FsringContainedClientDrain.Create(
                    ref stdoutRead,
                    streamCapBytes,
                    false);
            stderrDrain =
                FsringContainedClientDrain.Create(
                    ref stderrRead,
                    streamCapBytes,
                    false);
            stdoutDrain.Start();
            stderrDrain.Start();

            bool protocolFailure = false;
            if (deadline.ElapsedMilliseconds >= timeoutMilliseconds)
            {
                result.TimedOut = true;
                result.ProtocolValid = false;
                result.Error =
                    "The monotonic whole-job deadline expired before the suspended root could be resumed.";
                protocolFailure = true;
            }
            else
            {
                uint previousSuspendCount =
                    FsringContainedClientNative.ResumeThread(
                        processInformation.Thread);
                Close(ref processInformation.Thread);
                if (resumedSentinelPath != null)
                {
                    Stopwatch sentinelDeadline = Stopwatch.StartNew();
                    while (!File.Exists(resumedSentinelPath) &&
                        sentinelDeadline.ElapsedMilliseconds < 3000)
                    {
                        Thread.Sleep(10);
                    }
                }
                if (previousSuspendCount != 1)
                {
                    result.ProtocolValid = false;
                    result.Error =
                        "ResumeThread did not return the exact suspend count 1.";
                    protocolFailure = true;
                }
            }

            bool rootExited = false;
            while (!protocolFailure &&
                deadline.ElapsedMilliseconds < timeoutMilliseconds)
            {
                if (rootExited)
                {
                    uint activeProcesses;
                    if (!TryQueryActiveProcesses(
                        job,
                        injectContainmentQueryFailure,
                        out activeProcesses))
                    {
                        protocolFailure = true;
                        result.ProtocolValid = false;
                        result.Error =
                            "The private job active-process count could not be queried.";
                        break;
                    }
                    if (activeProcesses == 0)
                    {
                        result.ContainmentConfirmed = true;
                        break;
                    }
                    Thread.Sleep(10);
                    continue;
                }

                uint wait = FsringContainedClientNative.WaitForSingleObject(
                    processInformation.Process,
                    10);
                if (wait == WaitObject0)
                {
                    uint exitCode;
                    if (!FsringContainedClientNative.GetExitCodeProcess(
                        processInformation.Process,
                        out exitCode) ||
                        exitCode == StillActive)
                    {
                        protocolFailure = true;
                        result.ProtocolValid = false;
                        result.Error =
                            "The root exit code could not be read.";
                        break;
                    }
                    result.ExitCode = unchecked((int)exitCode);
                    Close(ref processInformation.Process);
                    rootHandleClosed = true;
                    rootExited = true;

                    uint activeProcesses;
                    if (!TryQueryActiveProcesses(
                        job,
                        injectContainmentQueryFailure,
                        out activeProcesses))
                    {
                        protocolFailure = true;
                        result.ProtocolValid = false;
                        result.Error =
                            "The private job active-process count could not be queried.";
                        break;
                    }
                    if (activeProcesses == 0)
                    {
                        result.ContainmentConfirmed = true;
                        break;
                    }
                }
                else if (wait != WaitTimeout)
                {
                    protocolFailure = true;
                    result.ProtocolValid = false;
                    result.Error =
                        "WaitForSingleObject failed for the root process.";
                    break;
                }
            }

            if (!result.ContainmentConfirmed)
            {
                if (!protocolFailure)
                {
                    result.TimedOut = true;
                    result.ProtocolValid = false;
                    result.Error =
                        "The monotonic whole-job deadline expired.";
                }
                if (!TryTerminateJob(
                    job,
                    injectTerminateFailure))
                {
                    result.ProtocolValid = false;
                    SetErrorIfEmpty(
                        result,
                        "TerminateJobObject failed.");
                }
                Close(ref processInformation.Thread);
                Close(ref processInformation.Process);
                rootHandleClosed = true;

                result.ContainmentConfirmed = ConfirmJobEmpty(
                    job,
                    containmentTimeoutMilliseconds,
                    injectContainmentQueryFailure);
            }

            bool stdoutEnded = SafeJoin(
                stdoutDrain,
                containmentTimeoutMilliseconds,
                injectDrainJoinFailure);
            bool stderrEnded = SafeJoin(
                stderrDrain,
                containmentTimeoutMilliseconds,
                injectDrainJoinFailure);
            PopulateJoinedOutput(
                result,
                stdoutDrain,
                stdoutEnded,
                stderrDrain,
                stderrEnded,
                decodeOutput);
            if (!stdoutEnded || !stderrEnded)
            {
                result.ContainmentConfirmed = false;
                result.ProtocolValid = false;
                SetErrorIfEmpty(
                    result,
                    "A redirected stream did not reach EOF.");
            }

            if (result.ContainmentConfirmed &&
                stdoutEnded &&
                stderrEnded)
            {
                stdoutDrain.Dispose();
                stdoutDrain = null;
                stderrDrain.Dispose();
                stderrDrain = null;
                DisposeJob(ref job);
            }
            else
            {
                result.Lease = new FsringContainedClientLease(
                    job,
                    stdoutDrain,
                    stderrDrain);
                jobTransferred = true;
                stdoutDrain = null;
                stderrDrain = null;
            }

            return result;
        }
        catch (Exception exception)
        {
            result.ProtocolValid = false;
            SetErrorIfEmpty(result, exception.Message);
            if (processCreated && HasOpenJob(job))
            {
                TryTerminateJob(
                    job,
                    injectTerminateFailure);
            }
            Close(ref processInformation.Thread);
            Close(ref processInformation.Process);
            rootHandleClosed = true;
            if (HasOpenJob(job))
            {
                result.ContainmentConfirmed = ConfirmJobEmpty(
                    job,
                    containmentTimeoutMilliseconds,
                    injectContainmentQueryFailure);
            }

            bool stdoutEnded = SafeJoin(
                stdoutDrain,
                containmentTimeoutMilliseconds,
                injectDrainJoinFailure);
            bool stderrEnded = SafeJoin(
                stderrDrain,
                containmentTimeoutMilliseconds,
                injectDrainJoinFailure);
            PopulateJoinedOutput(
                result,
                stdoutDrain,
                stdoutEnded,
                stderrDrain,
                stderrEnded,
                decodeOutput);
            if (!stdoutEnded || !stderrEnded)
            {
                result.ContainmentConfirmed = false;
                result.ProtocolValid = false;
                SetErrorIfEmpty(
                    result,
                    "A redirected stream did not reach EOF.");
            }
            if (result.ContainmentConfirmed &&
                stdoutEnded &&
                stderrEnded)
            {
                if (stdoutDrain != null)
                {
                    stdoutDrain.Dispose();
                    stdoutDrain = null;
                }
                if (stderrDrain != null)
                {
                    stderrDrain.Dispose();
                    stderrDrain = null;
                }
                DisposeJob(ref job);
            }
            else if (HasOpenJob(job))
            {
                result.Lease = new FsringContainedClientLease(
                    job,
                    stdoutDrain,
                    stderrDrain);
                jobTransferred = true;
                stdoutDrain = null;
                stderrDrain = null;
            }
            return result;
        }
        finally
        {
            DeleteAttributeList(
                ref attributeList,
                ref attributeListInitialized,
                ref jobValue,
                ref handleValues,
                jobAttributeOwner,
                ref jobAttributeBorrowed);
            Close(ref standardInput);
            Close(ref stdoutRead);
            Close(ref stdoutWrite);
            Close(ref stderrRead);
            Close(ref stderrWrite);
            Close(ref processInformation.Thread);
            if (!rootHandleClosed)
            {
                Close(ref processInformation.Process);
            }
            if (!jobTransferred)
            {
                DisposeJob(ref job);
            }
            if (stdoutDrain != null)
            {
                stdoutDrain.Dispose();
            }
            if (stderrDrain != null)
            {
                stderrDrain.Dispose();
            }
        }
    }

    private static void ValidateInputs(
        string applicationPath,
        string[] arguments,
        int timeoutMilliseconds,
        int containmentTimeoutMilliseconds,
        int streamCapBytes,
        object launchPin,
        int postCreateDelayMilliseconds,
        string resumedSentinelPath)
    {
        if (String.IsNullOrWhiteSpace(applicationPath) ||
            !Path.IsPathRooted(applicationPath) ||
            !String.Equals(
                Path.GetFullPath(applicationPath),
                applicationPath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The application path must be an absolute normalized path.");
        }
        if (arguments == null)
        {
            throw new ArgumentNullException("arguments");
        }
        foreach (string argument in arguments)
        {
            if (argument == null || argument.IndexOf('\0') >= 0)
            {
                throw new ArgumentException(
                    "Client arguments must be non-null and contain no NUL.");
            }
        }
        if (timeoutMilliseconds < 1 ||
            containmentTimeoutMilliseconds < 1)
        {
            throw new ArgumentOutOfRangeException(
                "Process deadlines must be positive.");
        }
        if (streamCapBytes < 1 || streamCapBytes > 65536)
        {
            throw new ArgumentOutOfRangeException(
                "Each redirected stream cap must be 1 through 65536 bytes.");
        }
        if (postCreateDelayMilliseconds < 0 ||
            postCreateDelayMilliseconds > 5000)
        {
            throw new ArgumentOutOfRangeException(
                "The post-create self-test delay must be 0 through 5000 milliseconds.");
        }
        if (resumedSentinelPath != null &&
            (postCreateDelayMilliseconds == 0 ||
                !Path.IsPathRooted(resumedSentinelPath) ||
                !String.Equals(
                    Path.GetFullPath(resumedSentinelPath),
                    resumedSentinelPath,
                    StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(
                "The resumed-sentinel self-test path is invalid.");
        }
        if (launchPin != null &&
            !(launchPin is FsringHarnessPin))
        {
            throw new ArgumentException(
                "The launch pin has an invalid runtime type.");
        }
    }

    private static void ValidateLayouts()
    {
        if (IntPtr.Size != 8 ||
            GetStartupInfoExSize() != 112 ||
            GetProcessInformationSize() != 24 ||
            GetJobExtendedLimitInformationSize() != 144 ||
            GetJobAccountingInformationSize() != 48 ||
            GetSecurityAttributesSize() != 24)
        {
            throw new PlatformNotSupportedException(
                "The contained client runner requires the exact AMD64 native layouts.");
        }
    }

    private static bool HasOpenJob(FsringSafeJobHandle job)
    {
        return job != null &&
            !job.IsInvalid &&
            !job.IsClosed;
    }

    private static void DisposeJob(ref FsringSafeJobHandle job)
    {
        FsringSafeJobHandle owned = job;
        job = null;
        if (owned != null)
        {
            owned.Dispose();
        }
    }

    private static long GetJobHandleValueForTest(
        FsringSafeJobHandle job)
    {
        if (!HasOpenJob(job))
        {
            throw new ArgumentException(
                "The private job owner is invalid.");
        }
        bool borrowed = false;
        try
        {
            job.DangerousAddRef(ref borrowed);
            return job.DangerousGetHandle().ToInt64();
        }
        finally
        {
            if (borrowed)
            {
                job.DangerousRelease();
            }
        }
    }

    private static FsringSafeJobHandle CreateVerifiedJob()
    {
        FsringSafeJobHandle job =
            FsringContainedClientNative.CreateJobObject(
            IntPtr.Zero,
            null);
        if (!HasOpenJob(job))
        {
            if (job != null)
            {
                job.Dispose();
            }
            throw NewWin32("CreateJobObjectW failed.");
        }

        try
        {
            uint handleFlags;
            if (!FsringContainedClientNative.GetHandleInformation(
                job,
                out handleFlags) ||
                (handleFlags &
                    FsringContainedClientNative.HandleFlagInherit) != 0)
            {
                throw NewWin32(
                    "The private job handle is not proven non-inheritable.");
            }

            FsringContainedClientNative
                .JobObjectExtendedLimitInformation requested =
                new FsringContainedClientNative
                    .JobObjectExtendedLimitInformation();
            requested.BasicLimitInformation.LimitFlags =
                FsringContainedClientNative
                    .JobObjectLimitKillOnJobClose;
            uint size = checked((uint)
                GetJobExtendedLimitInformationSize());
            if (!FsringContainedClientNative.SetInformationJobObject(
                job,
                FsringContainedClientNative
                    .JobObjectExtendedLimitInformationClass,
                ref requested,
                size))
            {
                throw NewWin32(
                    "SetInformationJobObject failed.");
            }

            FsringContainedClientNative
                .JobObjectExtendedLimitInformation observed =
                new FsringContainedClientNative
                    .JobObjectExtendedLimitInformation();
            uint returned;
            if (!FsringContainedClientNative.QueryInformationJobObject(
                job,
                FsringContainedClientNative
                    .JobObjectExtendedLimitInformationClass,
                ref observed,
                size,
                out returned) ||
                returned != size ||
                observed.BasicLimitInformation.LimitFlags !=
                    FsringContainedClientNative
                        .JobObjectLimitKillOnJobClose)
            {
                throw NewWin32(
                    "The private job limits did not prove exact kill-on-close without breakaway.");
            }
            return job;
        }
        catch
        {
            job.Dispose();
            throw;
        }
    }

    private static void CreateRedirectedHandles(
        out IntPtr standardInput,
        out IntPtr stdoutRead,
        out IntPtr stdoutWrite,
        out IntPtr stderrRead,
        out IntPtr stderrWrite)
    {
        standardInput = IntPtr.Zero;
        stdoutRead = IntPtr.Zero;
        stdoutWrite = IntPtr.Zero;
        stderrRead = IntPtr.Zero;
        stderrWrite = IntPtr.Zero;

        FsringContainedClientNative.SecurityAttributes attributes =
            new FsringContainedClientNative.SecurityAttributes();
        attributes.Length = GetSecurityAttributesSize();
        attributes.InheritHandle = 1;

        standardInput = FsringContainedClientNative.CreateFile(
            "NUL",
            FsringContainedClientNative.GenericRead,
            FsringContainedClientNative.FileShareRead |
                FsringContainedClientNative.FileShareWrite,
            ref attributes,
            FsringContainedClientNative.OpenExisting,
            0,
            IntPtr.Zero);
        if (standardInput ==
            FsringContainedClientNative.InvalidHandleValue)
        {
            standardInput = IntPtr.Zero;
            throw NewWin32("Opening inherited NUL stdin failed.");
        }
        if (!FsringContainedClientNative.CreatePipe(
            out stdoutRead,
            out stdoutWrite,
            ref attributes,
            0))
        {
            throw NewWin32("Creating the stdout pipe failed.");
        }
        if (!FsringContainedClientNative.CreatePipe(
            out stderrRead,
            out stderrWrite,
            ref attributes,
            0))
        {
            throw NewWin32("Creating the stderr pipe failed.");
        }
        if (!FsringContainedClientNative.SetHandleInformation(
            stdoutRead,
            FsringContainedClientNative.HandleFlagInherit,
            0) ||
            !FsringContainedClientNative.SetHandleInformation(
                stderrRead,
                FsringContainedClientNative.HandleFlagInherit,
                0))
        {
            throw NewWin32(
                "Making the parent pipe readers non-inheritable failed.");
        }
    }

    private static void CreateAttributeList(
        FsringSafeJobHandle job,
        IntPtr standardInput,
        IntPtr stdoutWrite,
        IntPtr stderrWrite,
        out IntPtr attributeList,
        out bool attributeListInitialized,
        out IntPtr jobValue,
        out IntPtr handleValues,
        ref bool jobAttributeBorrowed)
    {
        attributeList = IntPtr.Zero;
        attributeListInitialized = false;
        jobValue = IntPtr.Zero;
        handleValues = IntPtr.Zero;
        UIntPtr bytes = UIntPtr.Zero;
        FsringContainedClientNative.InitializeProcThreadAttributeList(
            IntPtr.Zero,
            2,
            0,
            ref bytes);
        if (bytes == UIntPtr.Zero)
        {
            throw NewWin32(
                "Sizing the process attribute list failed.");
        }

        attributeList = Marshal.AllocHGlobal(
            checked((int)bytes.ToUInt64()));
        if (!FsringContainedClientNative
            .InitializeProcThreadAttributeList(
                attributeList,
                2,
                0,
                ref bytes))
        {
            throw NewWin32(
                "Initializing the process attribute list failed.");
        }
        attributeListInitialized = true;

        if (!HasOpenJob(job))
        {
            throw new ArgumentException(
                "The private job owner is invalid.");
        }
        job.DangerousAddRef(ref jobAttributeBorrowed);
        jobValue = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteIntPtr(
            jobValue,
            job.DangerousGetHandle());
        if (!FsringContainedClientNative.UpdateProcThreadAttribute(
            attributeList,
            0,
            FsringContainedClientNative
                .ProcThreadAttributeJobList,
            jobValue,
            new UIntPtr(checked((uint)IntPtr.Size)),
            IntPtr.Zero,
            IntPtr.Zero))
        {
            throw NewWin32(
                "Installing PROC_THREAD_ATTRIBUTE_JOB_LIST failed.");
        }

        handleValues = Marshal.AllocHGlobal(
            checked(IntPtr.Size * 3));
        Marshal.WriteIntPtr(
            handleValues,
            0,
            standardInput);
        Marshal.WriteIntPtr(
            handleValues,
            IntPtr.Size,
            stdoutWrite);
        Marshal.WriteIntPtr(
            handleValues,
            IntPtr.Size * 2,
            stderrWrite);
        if (!FsringContainedClientNative.UpdateProcThreadAttribute(
            attributeList,
            0,
            FsringContainedClientNative
                .ProcThreadAttributeHandleList,
            handleValues,
            new UIntPtr(checked((uint)(IntPtr.Size * 3))),
            IntPtr.Zero,
            IntPtr.Zero))
        {
            throw NewWin32(
                "Installing PROC_THREAD_ATTRIBUTE_HANDLE_LIST failed.");
        }
    }

    private static void DeleteAttributeList(
        ref IntPtr attributeList,
        ref bool attributeListInitialized,
        ref IntPtr jobValue,
        ref IntPtr handleValues,
        FsringSafeJobHandle job,
        ref bool jobAttributeBorrowed)
    {
        try
        {
            if (attributeList != IntPtr.Zero)
            {
                if (attributeListInitialized)
                {
                    FsringContainedClientNative
                        .DeleteProcThreadAttributeList(attributeList);
                }
                Marshal.FreeHGlobal(attributeList);
                attributeList = IntPtr.Zero;
            }
            attributeListInitialized = false;
            if (jobValue != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(jobValue);
                jobValue = IntPtr.Zero;
            }
            if (handleValues != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(handleValues);
                handleValues = IntPtr.Zero;
            }
        }
        finally
        {
            bool releaseJob = jobAttributeBorrowed;
            jobAttributeBorrowed = false;
            if (releaseJob)
            {
                job.DangerousRelease();
            }
        }
    }

    private static bool TryQueryActiveProcesses(
        FsringSafeJobHandle job,
        bool injectFailure,
        out uint activeProcesses)
    {
        activeProcesses = 0;
        if (injectFailure)
        {
            return false;
        }

        FsringContainedClientNative
            .JobObjectBasicAccountingInformation accounting =
            new FsringContainedClientNative
                .JobObjectBasicAccountingInformation();
        uint size = checked((uint)
            GetJobAccountingInformationSize());
        uint returned;
        if (!FsringContainedClientNative.QueryInformationJobObject(
            job,
            FsringContainedClientNative
                .JobObjectBasicAccountingInformationClass,
            ref accounting,
            size,
            out returned) ||
            returned != size)
        {
            return false;
        }
        activeProcesses = accounting.ActiveProcesses;
        return true;
    }

    private static bool ConfirmJobEmpty(
        FsringSafeJobHandle job,
        int timeoutMilliseconds,
        bool injectFailure)
    {
        if (!HasOpenJob(job))
        {
            return false;
        }
        Stopwatch deadline = Stopwatch.StartNew();
        while (deadline.ElapsedMilliseconds < timeoutMilliseconds)
        {
            uint activeProcesses;
            if (!TryQueryActiveProcesses(
                job,
                injectFailure,
                out activeProcesses))
            {
                return false;
            }
            if (activeProcesses == 0)
            {
                return true;
            }
            Thread.Sleep(10);
        }
        uint finalActiveProcesses;
        return TryQueryActiveProcesses(
            job,
            injectFailure,
            out finalActiveProcesses) &&
            finalActiveProcesses == 0;
    }

    private static bool TryTerminateJob(
        FsringSafeJobHandle job,
        bool injectFailure)
    {
        if (!HasOpenJob(job) || injectFailure)
        {
            return false;
        }
        try
        {
            return FsringContainedClientNative.TerminateJobObject(
                job,
                TerminatedExitCode);
        }
        catch
        {
            return false;
        }
    }

    private static bool SafeJoin(
        FsringContainedClientDrain drain,
        int milliseconds,
        bool injectFailure)
    {
        if (drain == null)
        {
            return true;
        }
        if (injectFailure)
        {
            return false;
        }
        try
        {
            return drain.Join(milliseconds);
        }
        catch
        {
            return false;
        }
    }

    private static void PopulateJoinedOutput(
        FsringContainedClientResult result,
        FsringContainedClientDrain stdoutDrain,
        bool stdoutEnded,
        FsringContainedClientDrain stderrDrain,
        bool stderrEnded,
        bool decodeOutput)
    {
        try
        {
            PopulateOutput(
                result,
                stdoutEnded ? stdoutDrain : null,
                stderrEnded ? stderrDrain : null,
                decodeOutput);
            result.OutputFinalized = stdoutEnded && stderrEnded;
        }
        catch (Exception exception)
        {
            result.ProtocolValid = false;
            result.OutputFinalized = false;
            SetErrorIfEmpty(
                result,
                "Finalizing redirected output failed: " +
                exception.Message);
        }
    }

    private static void SetErrorIfEmpty(
        FsringContainedClientResult result,
        string error)
    {
        if (String.IsNullOrEmpty(result.Error))
        {
            result.Error = error;
        }
    }

    private static void PopulateOutput(
        FsringContainedClientResult result,
        FsringContainedClientDrain stdoutDrain,
        FsringContainedClientDrain stderrDrain,
        bool decodeOutput)
    {
        if (stdoutDrain != null)
        {
            byte[] bytes = stdoutDrain.GetBytes();
            result.StdoutByteCount = bytes.Length;
            result.StdoutTotalByteCount = stdoutDrain.Total;
            result.StdoutTruncated = stdoutDrain.Truncated;
            if (stdoutDrain.Failure != null)
            {
                result.ProtocolValid = false;
                if (String.IsNullOrEmpty(result.Error))
                {
                    result.Error =
                        "The stdout drain failed: " +
                        stdoutDrain.Failure.Message;
                }
            }
            if (decodeOutput)
            {
                DecodeLines(result, bytes, true);
            }
        }
        if (stderrDrain != null)
        {
            byte[] bytes = stderrDrain.GetBytes();
            result.StderrByteCount = bytes.Length;
            result.StderrTotalByteCount = stderrDrain.Total;
            result.StderrTruncated = stderrDrain.Truncated;
            if (stderrDrain.Failure != null)
            {
                result.ProtocolValid = false;
                if (String.IsNullOrEmpty(result.Error))
                {
                    result.Error =
                        "The stderr drain failed: " +
                        stderrDrain.Failure.Message;
                }
            }
            if (decodeOutput)
            {
                DecodeLines(result, bytes, false);
            }
        }
        result.OutputTruncated =
            result.StdoutTruncated ||
            result.StderrTruncated;
        if (!decodeOutput && result.OutputTruncated)
        {
            result.ProtocolValid = false;
            SetErrorIfEmpty(
                result,
                "Opaque redirected output exceeded its bounded cap.");
        }
    }

    private static void DecodeLines(
        FsringContainedClientResult result,
        byte[] bytes,
        bool stdout)
    {
        try
        {
            string text =
                new UTF8Encoding(false, true).GetString(bytes);
            string[] lines = SplitPhysicalLines(text);
            if (stdout)
            {
                result.Stdout = lines;
            }
            else
            {
                result.Stderr = lines;
            }
        }
        catch (DecoderFallbackException)
        {
            result.ProtocolValid = false;
            if (String.IsNullOrEmpty(result.Error))
            {
                result.Error =
                    (stdout ? "stdout" : "stderr") +
                    " is not strict UTF-8.";
            }
        }
    }

    private static string[] SplitPhysicalLines(string text)
    {
        if (text.Length == 0)
        {
            return new string[0];
        }
        List<string> lines = new List<string>();
        int start = 0;
        int index = 0;
        while (index < text.Length)
        {
            if (text[index] == '\r' || text[index] == '\n')
            {
                lines.Add(text.Substring(start, index - start));
                if (text[index] == '\r' &&
                    index + 1 < text.Length &&
                    text[index + 1] == '\n')
                {
                    index++;
                }
                index++;
                start = index;
            }
            else
            {
                index++;
            }
        }
        if (start < text.Length)
        {
            lines.Add(text.Substring(start));
        }
        return lines.ToArray();
    }

    private static StringBuilder BuildCommandLine(
        string applicationPath,
        string[] arguments)
    {
        StringBuilder commandLine = new StringBuilder();
        commandLine.Append(QuoteArgument(applicationPath));
        foreach (string argument in arguments)
        {
            commandLine.Append(' ');
            commandLine.Append(QuoteArgument(argument));
        }
        return commandLine;
    }

    private static string QuoteArgument(string argument)
    {
        if (argument.Length != 0 &&
            argument.IndexOfAny(
                new char[] { ' ', '\t', '"' }) < 0)
        {
            return argument;
        }

        StringBuilder quoted = new StringBuilder();
        quoted.Append('"');
        int backslashes = 0;
        foreach (char value in argument)
        {
            if (value == '\\')
            {
                backslashes++;
            }
            else if (value == '"')
            {
                quoted.Append('\\', (backslashes * 2) + 1);
                quoted.Append('"');
                backslashes = 0;
            }
            else
            {
                quoted.Append('\\', backslashes);
                backslashes = 0;
                quoted.Append(value);
            }
        }
        quoted.Append('\\', backslashes * 2);
        quoted.Append('"');
        return quoted.ToString();
    }

    private static Win32Exception NewWin32(string message)
    {
        int error = Marshal.GetLastWin32Error();
        return new Win32Exception(error, message);
    }

    private static void Close(ref IntPtr handle)
    {
        IntPtr owned = handle;
        handle = IntPtr.Zero;
        if (owned != IntPtr.Zero &&
            owned != FsringContainedClientNative.InvalidHandleValue)
        {
            FsringContainedClientNative.CloseHandle(owned);
        }
    }
}
'@
    Add-Type -TypeDefinition $containedClientRunnerSource -Language CSharp `
        -ErrorAction Stop
}

if ($null -eq ('FsringNativeService' -as [type])) {
    $nativeServiceSource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public sealed class FsringNativeServiceObservation
{
    public bool QuerySucceeded { get; internal set; }
    public bool Exists { get; internal set; }
    public bool MarkedForDelete { get; internal set; }
    public int Win32Error { get; internal set; }
    public uint State { get; internal set; }
    public uint ServiceType { get; internal set; }
    public uint StartType { get; internal set; }
    public string BinaryPath { get; internal set; }
    public string LoadOrderGroup { get; internal set; }
    public string Detail { get; internal set; }

    internal FsringNativeServiceObservation()
    {
        BinaryPath = String.Empty;
        LoadOrderGroup = String.Empty;
        Detail = String.Empty;
    }
}

public static class FsringNativeService
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorServiceDoesNotExist = 1060;
    private const int ErrorServiceMarkedForDelete = 1072;
    private const uint MaximumConfigBytes = 65536;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        internal uint ServiceType;
        internal uint CurrentState;
        internal uint ControlsAccepted;
        internal uint Win32ExitCode;
        internal uint ServiceSpecificExitCode;
        internal uint CheckPoint;
        internal uint WaitHint;
        internal uint ProcessId;
        internal uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryServiceConfigNative
    {
        internal uint ServiceType;
        internal uint StartType;
        internal uint ErrorControl;
        internal IntPtr BinaryPathName;
        internal IntPtr LoadOrderGroup;
        internal uint TagId;
        internal IntPtr Dependencies;
        internal IntPtr ServiceStartName;
        internal IntPtr DisplayName;
    }

    [DllImport(
        "advapi32.dll",
        EntryPoint = "OpenSCManagerW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern IntPtr OpenScManager(
        string machineName,
        string databaseName,
        uint desiredAccess);

    [DllImport(
        "advapi32.dll",
        EntryPoint = "OpenServiceW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern IntPtr OpenService(
        IntPtr manager,
        string serviceName,
        uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(
        IntPtr service,
        int informationLevel,
        ref ServiceStatusProcess status,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport(
        "advapi32.dll",
        EntryPoint = "QueryServiceConfigW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig(
        IntPtr service,
        IntPtr config,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    public static FsringNativeServiceObservation Query(
        string serviceName)
    {
        FsringNativeServiceObservation observed =
            new FsringNativeServiceObservation();
        if (String.IsNullOrWhiteSpace(serviceName) ||
            serviceName.IndexOf('\0') >= 0)
        {
            observed.Win32Error = 87;
            observed.Detail = "The service name is invalid.";
            return observed;
        }

        IntPtr manager = IntPtr.Zero;
        IntPtr service = IntPtr.Zero;
        IntPtr configBuffer = IntPtr.Zero;
        try
        {
            manager = OpenScManager(
                null,
                null,
                ScManagerConnect);
            if (manager == IntPtr.Zero)
            {
                SetFailure(
                    observed,
                    Marshal.GetLastWin32Error(),
                    "OpenSCManagerW failed.");
                return observed;
            }

            service = OpenService(
                manager,
                serviceName,
                ServiceQueryConfig | ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == ErrorServiceDoesNotExist)
                {
                    observed.QuerySucceeded = true;
                    observed.Exists = false;
                    observed.Win32Error = error;
                    observed.Detail =
                        "The exact service name is absent.";
                }
                else if (error == ErrorServiceMarkedForDelete)
                {
                    observed.QuerySucceeded = true;
                    observed.Exists = true;
                    observed.MarkedForDelete = true;
                    observed.Win32Error = error;
                    observed.Detail =
                        "The exact service name is marked for deletion.";
                }
                else
                {
                    SetFailure(
                        observed,
                        error,
                        "OpenServiceW failed.");
                }
                return observed;
            }

            ServiceStatusProcess status =
                new ServiceStatusProcess();
            uint statusBytes;
            if (!QueryServiceStatusEx(
                service,
                ScStatusProcessInfo,
                ref status,
                checked((uint)Marshal.SizeOf(
                    typeof(ServiceStatusProcess))),
                out statusBytes))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == ErrorServiceMarkedForDelete)
                {
                    observed.QuerySucceeded = true;
                    observed.Exists = true;
                    observed.MarkedForDelete = true;
                    observed.Win32Error = error;
                    observed.Detail =
                        "The exact service name is marked for deletion.";
                }
                else
                {
                    SetFailure(
                        observed,
                        error,
                        "QueryServiceStatusEx failed.");
                }
                return observed;
            }

            uint required;
            bool sizing = QueryServiceConfig(
                service,
                IntPtr.Zero,
                0,
                out required);
            int sizingError = Marshal.GetLastWin32Error();
            if (sizing ||
                sizingError != ErrorInsufficientBuffer ||
                required <
                    Marshal.SizeOf(typeof(QueryServiceConfigNative)) ||
                required > MaximumConfigBytes)
            {
                SetFailure(
                    observed,
                    sizingError,
                    "QueryServiceConfigW sizing was invalid.");
                return observed;
            }

            configBuffer = Marshal.AllocHGlobal(
                checked((int)required));
            uint returned;
            if (!QueryServiceConfig(
                service,
                configBuffer,
                required,
                out returned) ||
                returned > required)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == ErrorServiceMarkedForDelete)
                {
                    observed.QuerySucceeded = true;
                    observed.Exists = true;
                    observed.MarkedForDelete = true;
                    observed.Win32Error = error;
                    observed.Detail =
                        "The exact service name is marked for deletion.";
                }
                else
                {
                    SetFailure(
                        observed,
                        error,
                        "QueryServiceConfigW failed.");
                }
                return observed;
            }

            QueryServiceConfigNative config =
                (QueryServiceConfigNative)Marshal.PtrToStructure(
                    configBuffer,
                    typeof(QueryServiceConfigNative));
            observed.QuerySucceeded = true;
            observed.Exists = true;
            observed.State = status.CurrentState;
            observed.ServiceType = config.ServiceType;
            observed.StartType = config.StartType;
            observed.BinaryPath =
                Marshal.PtrToStringUni(config.BinaryPathName) ??
                    String.Empty;
            observed.LoadOrderGroup =
                Marshal.PtrToStringUni(config.LoadOrderGroup) ??
                    String.Empty;
            observed.Detail =
                "Native SCM status and configuration query succeeded.";
            return observed;
        }
        catch (Exception exception)
        {
            observed.QuerySucceeded = false;
            observed.Detail =
                "Native SCM query failed: " + exception.Message;
            return observed;
        }
        finally
        {
            if (configBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(configBuffer);
            }
            if (service != IntPtr.Zero)
            {
                CloseServiceHandle(service);
            }
            if (manager != IntPtr.Zero)
            {
                CloseServiceHandle(manager);
            }
        }
    }

    private static void SetFailure(
        FsringNativeServiceObservation observed,
        int error,
        string stage)
    {
        observed.QuerySucceeded = false;
        observed.Win32Error = error;
        observed.Detail =
            stage + " Win32 error " +
            error.ToString(
                System.Globalization.CultureInfo.InvariantCulture) +
            ".";
    }
}
'@
    Add-Type -TypeDefinition $nativeServiceSource -Language CSharp `
        -ErrorAction Stop
}

function New-StepResult {
    return [ordered]@{
        attempted = $false
        success = $false
        exitCode = $null
        timedOut = $false
        containmentConfirmed = $false
        outputFinalized = $false
        protocolValid = $false
        absent = $false
        detail = $null
    }
}

function New-HarnessResult {
    return [ordered]@{
        attempted = $false
        valid = $false
        exitCode = $null
        timedOut = $false
        containmentConfirmed = $false
        outputTruncated = $false
        outputFinalized = $false
        protocolValid = $false
        overall = $null
        probes = @()
        identityRecheck = $null
        detail = $null
    }
}

function New-SmokeResult {
    param(
        [string]$Mode,
        [string]$ResolvedPackageDirectory,
        [string]$ResolvedHarnessPath
    )

    return [ordered]@{
        schema = $script:Schema
        mode = $Mode
        overall = 'FAIL'
        exitCode = 1
        preflight = [ordered]@{
            pathResolutionValid = $true
            hostWindows = $false
            osVersionQueryValid = $false
            osMajor = $null
            osMinor = $null
            osBuild = $null
            windows10OrLater = $false
            nativeArchitecture = $null
            hostX64 = $false
            elevated = $false
            codeIntegrityQueryValid = $false
            codeIntegrityOptions = $null
            codeIntegrityEnabled = $false
            testSigningActive = $false
            bootEnvironmentQueryValid = $false
            bootIdentifier = $null
            bootConfigurationAttempted = $false
            bootConfigurationValid = $false
            testSigningConfigured = $false
            rebootRequired = $false
            signingState = 'UNKNOWN'
            packageDirectory = $ResolvedPackageDirectory
            harnessPath = $ResolvedHarnessPath
            packageDirectoryPresent = $false
            infPresent = $false
            sysPresent = $false
            catPresent = $false
            harnessPresent = $false
            harnessPinValid = $false
            verifierScriptPresent = $false
            powershellPresent = $false
            scPresent = $false
            scPinValid = $false
            scIdentity = [ordered]@{
                sha256 = $null
                size = $null
                machine = $null
                volumeSerial = $null
                fileId = $null
                finalPath = $null
                handleInheritable = $null
                initial = $null
                detail = $null
            }
            sysMachine = $null
            sysAmd64 = $false
            sysSha256 = $null
            verifierValid = $false
            verifierExitCode = $null
            verifierOverall = $null
            trustReady = $false
            serviceChecked = $false
            serviceAbsent = $false
            serviceQueryExitCode = $null
            runnable = $false
            artifacts = [ordered]@{}
            harnessIdentity = [ordered]@{
                expectedSha256 = $null
                observedSha256 = $null
                size = $null
                machine = $null
                volumeSerial = $null
                fileId = $null
                finalPath = $null
                handleInheritable = $null
                initial = $null
                rechecks = [ordered]@{
                    preMain = $null
                    preAbsence = $null
                    postAbsence = $null
                }
                detail = $null
                scope = (
                    'Accidental/stale/TOCTOU identity boundary; ' +
                    'not protection from a malicious local administrator.'
                )
            }
            verifier = [ordered]@{}
            service = [ordered]@{}
            identityRecheck = [ordered]@{
                attempted = $false
                success = $false
                detail = $null
            }
        }
        ownership = [ordered]@{
            createdByThisRun = $false
            servicePresent = $false
            mutationAttempts = 0
            createDisposition = 'NOT_ATTEMPTED'
            reconciliation = [ordered]@{
                attempted = $false
                exact = $false
                detail = $null
            }
        }
        containment = [ordered]@{
            allClientsConfirmed = $true
            cleanupBlocked = $false
            leasesRetained = 0
        }
        live = [ordered]@{
            preCreateServiceQuery = New-StepResult
            create = New-StepResult
            start = New-StepResult
            waitRunning = New-StepResult
        }
        mainHarness = New-HarnessResult
        cleanup = [ordered]@{
            attempted = $false
            mutationAmbiguous = $false
            continuity = [ordered]@{
                attempted = $false
                success = $false
                checks = 0
                lost = $false
                detail = $null
            }
            stop = New-StepResult
            waitStopped = New-StepResult
            delete = New-StepResult
            waitAbsent = New-StepResult
            success = $false
        }
        absenceHarness = New-HarnessResult
        commands = New-Object System.Collections.ArrayList
        transitions = New-Object System.Collections.ArrayList
        reasons = New-Object System.Collections.ArrayList
        tests = @()
        failures = @()
    }
}

function Add-Reason {
    param($Result, [string]$Message)

    if (-not $Result.reasons.Contains($Message)) {
        [void]$Result.reasons.Add($Message)
    }
}

function Add-Transition {
    param($Result, [string]$State, [string]$Detail)

    [void]$Result.transitions.Add([ordered]@{
        state = $State
        detail = $Detail
    })
}

function Complete-SmokeResult {
    param($Result, [string]$Overall)

    $Result.overall = $Overall
    switch ($Overall) {
        'PASS' { $Result.exitCode = 0 }
        'FAIL' { $Result.exitCode = 1 }
        'NOT RUN' { $Result.exitCode = 2 }
        default { throw "Unknown overall result '$Overall'." }
    }
    return $Result
}

function Test-ExactPropertySet {
    param($Object, [string[]]$ExpectedNames)

    if ($null -eq $Object -or $Object -is [System.Array] -or
        $Object -is [string] -or $Object -is [ValueType]) {
        return $false
    }
    $actualNames = @($Object.PSObject.Properties | ForEach-Object { $_.Name })
    if ($actualNames.Count -ne $ExpectedNames.Count) {
        return $false
    }
    foreach ($expectedName in $ExpectedNames) {
        if (-not ($actualNames -ccontains $expectedName)) {
            return $false
        }
    }
    return $true
}

function Test-ExactRuntimeType {
    param($Value, [Type]$ExpectedType)

    return ($null -ne $Value -and $Value.GetType() -eq $ExpectedType)
}

function New-InvalidNativeReadiness {
    return [pscustomobject]@{
        OsVersionQueryValid = $false
        OsMajor = $null
        OsMinor = $null
        OsBuild = $null
        Windows10OrLater = $false
        NativeArchitecture = $null
        HostX64 = $false
        CodeIntegrityQueryValid = $false
        CodeIntegrityOptions = $null
        CodeIntegrityEnabled = $false
        TestSigningActive = $false
        BootEnvironmentQueryValid = $false
        BootIdentifier = $null
        BootIdentifierGuid = [Guid]::Empty
    }
}

function ConvertFrom-NativeReadinessObservation {
    param($Observation)

    $derived = New-InvalidNativeReadiness
    $expectedNames = @(
        'RtlStatus',
        'OsInputSize',
        'OsReturnedSize',
        'OsPlatformId',
        'OsMajor',
        'OsMinor',
        'OsBuild',
        'SystemInfoSize',
        'NativeArchitecture',
        'Is64BitProcess',
        'CodeIntegrityStatus',
        'CodeIntegrityBufferSize',
        'CodeIntegrityInputLength',
        'CodeIntegrityReturnLength',
        'CodeIntegrityReturnedLength',
        'CodeIntegrityOptions',
        'BootEnvironmentStatus',
        'BootEnvironmentBufferSize',
        'BootEnvironmentReturnLength',
        'BootIdentifier',
        'FirmwareType',
        'BootFlags'
    )
    if (-not (Test-ExactPropertySet $Observation $expectedNames)) {
        return $derived
    }
    $typed = (
        (Test-ExactRuntimeType $Observation.RtlStatus ([int32])) -and
        (Test-ExactRuntimeType $Observation.OsInputSize ([uint32])) -and
        (Test-ExactRuntimeType $Observation.OsReturnedSize ([uint32])) -and
        (Test-ExactRuntimeType $Observation.OsPlatformId ([uint32])) -and
        (Test-ExactRuntimeType $Observation.OsMajor ([uint32])) -and
        (Test-ExactRuntimeType $Observation.OsMinor ([uint32])) -and
        (Test-ExactRuntimeType $Observation.OsBuild ([uint32])) -and
        (Test-ExactRuntimeType $Observation.SystemInfoSize ([uint32])) -and
        (Test-ExactRuntimeType $Observation.NativeArchitecture ([uint16])) -and
        (Test-ExactRuntimeType $Observation.Is64BitProcess ([bool])) -and
        (Test-ExactRuntimeType $Observation.CodeIntegrityStatus ([int32])) -and
        (Test-ExactRuntimeType $Observation.CodeIntegrityBufferSize ([uint32])) -and
        (Test-ExactRuntimeType $Observation.CodeIntegrityInputLength ([uint32])) -and
        (Test-ExactRuntimeType $Observation.CodeIntegrityReturnLength ([uint32])) -and
        (Test-ExactRuntimeType $Observation.CodeIntegrityReturnedLength ([uint32])) -and
        (Test-ExactRuntimeType $Observation.CodeIntegrityOptions ([uint32])) -and
        (Test-ExactRuntimeType $Observation.BootEnvironmentStatus ([int32])) -and
        (Test-ExactRuntimeType $Observation.BootEnvironmentBufferSize ([uint32])) -and
        (Test-ExactRuntimeType $Observation.BootEnvironmentReturnLength ([uint32])) -and
        (Test-ExactRuntimeType $Observation.BootIdentifier ([Guid])) -and
        (Test-ExactRuntimeType $Observation.FirmwareType ([uint32])) -and
        (Test-ExactRuntimeType $Observation.BootFlags ([uint64]))
    )
    if (-not $typed) {
        return $derived
    }

    $derived.OsVersionQueryValid = (
        $Observation.RtlStatus -eq 0 -and
        $Observation.OsInputSize -eq 276 -and
        $Observation.OsReturnedSize -eq 276 -and
        $Observation.OsPlatformId -eq 2 -and
        $Observation.OsMajor -ge 1 -and
        $Observation.OsMajor -le 99 -and
        $Observation.OsMinor -le 99 -and
        $Observation.OsBuild -gt 0
    )
    if ($derived.OsVersionQueryValid) {
        $derived.OsMajor = $Observation.OsMajor
        $derived.OsMinor = $Observation.OsMinor
        $derived.OsBuild = $Observation.OsBuild
    }
    $derived.Windows10OrLater = (
        $derived.OsVersionQueryValid -and
        (
            $Observation.OsMajor -gt 10 -or
            ($Observation.OsMajor -eq 10 -and $Observation.OsMinor -ge 0)
        )
    )
    $derived.NativeArchitecture = [uint32]$Observation.NativeArchitecture
    $derived.HostX64 = (
        $Observation.SystemInfoSize -eq 48 -and
        $Observation.NativeArchitecture -eq 9 -and
        $Observation.Is64BitProcess
    )
    $derived.CodeIntegrityQueryValid = (
        $Observation.CodeIntegrityStatus -eq 0 -and
        $Observation.CodeIntegrityBufferSize -eq 8 -and
        $Observation.CodeIntegrityInputLength -eq 8 -and
        $Observation.CodeIntegrityReturnLength -eq 8 -and
        $Observation.CodeIntegrityReturnedLength -eq 8
    )
    if ($derived.CodeIntegrityQueryValid) {
        $derived.CodeIntegrityOptions = $Observation.CodeIntegrityOptions
        $derived.CodeIntegrityEnabled = (
            ($Observation.CodeIntegrityOptions -band [uint32]0x01) -ne 0
        )
        $derived.TestSigningActive = (
            ($Observation.CodeIntegrityOptions -band [uint32]0x02) -ne 0
        )
    }
    $derived.BootEnvironmentQueryValid = (
        $Observation.BootEnvironmentStatus -eq 0 -and
        $Observation.BootEnvironmentBufferSize -eq 32 -and
        $Observation.BootEnvironmentReturnLength -eq 32 -and
        $Observation.BootIdentifier -ne [Guid]::Empty
    )
    if ($derived.BootEnvironmentQueryValid) {
        $derived.BootIdentifierGuid = $Observation.BootIdentifier
        $derived.BootIdentifier = $Observation.BootIdentifier.ToString('B')
    }
    return $derived
}

function Test-ExactBootIdentifier {
    param($Value, [Guid]$Expected)

    if (-not (Test-ExactRuntimeType $Value ([string]))) {
        return $false
    }
    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParseExact($Value, 'B', [ref]$parsed)) {
        return $false
    }
    return ($parsed -eq $Expected)
}

function Test-BcdElementTypeRoster {
    param($ElementTypes)

    $invalid = [pscustomobject]@{
        Valid = $false
        ShouldGetElement = $false
    }
    if (-not ($ElementTypes -is [System.Array])) {
        return $invalid
    }
    $seen = New-Object 'System.Collections.Generic.HashSet[uint32]'
    $testSigningTypeCount = 0
    foreach ($elementType in @($ElementTypes)) {
        if (-not (Test-ExactRuntimeType $elementType ([uint32])) -or
            -not $seen.Add([uint32]$elementType)) {
            return $invalid
        }
        if ($elementType -eq [uint32]0x16000049) {
            $testSigningTypeCount++
        }
    }
    return [pscustomobject]@{
        Valid = $true
        ShouldGetElement = ($testSigningTypeCount -eq 1)
    }
}

function ConvertFrom-BcdReadOnlyObservation {
    param($Observation, [Guid]$ExpectedBootIdentifier)

    $invalid = [pscustomobject]@{
        Valid = $false
        Configured = $false
    }
    $expectedNames = @(
        'ProviderSucceeded',
        'OpenStoreReturn',
        'StoreClass',
        'StoreFilePath',
        'OpenObjectReturn',
        'ObjectClass',
        'ObjectId',
        'ObjectStoreFilePath',
        'ObjectType',
        'EnumerateElementTypesReturn',
        'ElementTypes',
        'GetElementAttempted',
        'GetElementReturn',
        'ElementClass',
        'ElementType',
        'ElementObjectId',
        'ElementStoreFilePath',
        'ElementBoolean'
    )
    if (-not (Test-ExactPropertySet $Observation $expectedNames)) {
        return $invalid
    }
    if (-not (Test-ExactRuntimeType $Observation.ProviderSucceeded ([bool])) -or
        -not $Observation.ProviderSucceeded -or
        -not (Test-ExactRuntimeType $Observation.OpenStoreReturn ([bool])) -or
        -not $Observation.OpenStoreReturn -or
        -not (Test-ExactRuntimeType $Observation.StoreClass ([string])) -or
        $Observation.StoreClass -cne 'BcdStore' -or
        -not (Test-ExactRuntimeType $Observation.StoreFilePath ([string])) -or
        $Observation.StoreFilePath -cne '' -or
        -not (Test-ExactRuntimeType $Observation.OpenObjectReturn ([bool])) -or
        -not $Observation.OpenObjectReturn -or
        -not (Test-ExactRuntimeType $Observation.ObjectClass ([string])) -or
        $Observation.ObjectClass -cne 'BcdObject' -or
        -not (Test-ExactBootIdentifier $Observation.ObjectId $ExpectedBootIdentifier) -or
        -not (Test-ExactRuntimeType $Observation.ObjectStoreFilePath ([string])) -or
        $Observation.ObjectStoreFilePath -cne '' -or
        -not (Test-ExactRuntimeType $Observation.ObjectType ([uint32])) -or
        $Observation.ObjectType -ne [uint32]0x10200003 -or
        -not (Test-ExactRuntimeType $Observation.EnumerateElementTypesReturn ([bool])) -or
        -not $Observation.EnumerateElementTypesReturn -or
        -not ($Observation.ElementTypes -is [System.Array]) -or
        -not (Test-ExactRuntimeType $Observation.GetElementAttempted ([bool]))) {
        return $invalid
    }

    $roster = Test-BcdElementTypeRoster $Observation.ElementTypes
    if (-not $roster.Valid) {
        return $invalid
    }
    if (-not $roster.ShouldGetElement) {
        if ($Observation.GetElementAttempted -or
            $null -ne $Observation.GetElementReturn -or
            $null -ne $Observation.ElementClass -or
            $null -ne $Observation.ElementType -or
            $null -ne $Observation.ElementObjectId -or
            $null -ne $Observation.ElementStoreFilePath -or
            $null -ne $Observation.ElementBoolean) {
            return $invalid
        }
        return [pscustomobject]@{
            Valid = $true
            Configured = $false
        }
    }
    if (-not $Observation.GetElementAttempted -or
        -not (Test-ExactRuntimeType $Observation.GetElementReturn ([bool])) -or
        -not $Observation.GetElementReturn -or
        -not (Test-ExactRuntimeType $Observation.ElementClass ([string])) -or
        $Observation.ElementClass -cne 'BcdBooleanElement' -or
        -not (Test-ExactRuntimeType $Observation.ElementType ([uint32])) -or
        $Observation.ElementType -ne [uint32]0x16000049 -or
        -not (Test-ExactBootIdentifier $Observation.ElementObjectId $ExpectedBootIdentifier) -or
        -not (Test-ExactRuntimeType $Observation.ElementStoreFilePath ([string])) -or
        $Observation.ElementStoreFilePath -cne '' -or
        -not (Test-ExactRuntimeType $Observation.ElementBoolean ([bool]))) {
        return $invalid
    }
    return [pscustomobject]@{
        Valid = $true
        Configured = [bool]$Observation.ElementBoolean
    }
}

function Set-SigningReadinessState {
    param($Facts)

    $Facts.rebootRequired = $false
    $Facts.signingState = 'UNKNOWN'
    if (-not $Facts.codeIntegrityQueryValid -or
        -not $Facts.bootEnvironmentQueryValid -or
        -not $Facts.bootConfigurationValid) {
        return
    }
    if (-not $Facts.testSigningActive -and -not $Facts.testSigningConfigured) {
        $Facts.signingState = 'DISABLED'
    } elseif (-not $Facts.testSigningActive -and $Facts.testSigningConfigured) {
        $Facts.rebootRequired = $true
        $Facts.signingState = 'ENABLE_REBOOT_REQUIRED'
    } elseif ($Facts.testSigningActive -and -not $Facts.testSigningConfigured) {
        $Facts.rebootRequired = $true
        $Facts.signingState = 'DISABLE_REBOOT_REQUIRED'
    } else {
        $Facts.signingState = 'ENABLED'
    }
}

function Invoke-ReadinessFactCollection {
    param($Adapter, $Facts)

    $Facts.osVersionQueryValid = $false
    $Facts.osMajor = $null
    $Facts.osMinor = $null
    $Facts.osBuild = $null
    $Facts.windows10OrLater = $false
    $Facts.nativeArchitecture = $null
    $Facts.hostX64 = $false
    $Facts.codeIntegrityQueryValid = $false
    $Facts.codeIntegrityOptions = $null
    $Facts.codeIntegrityEnabled = $false
    $Facts.testSigningActive = $false
    $Facts.bootEnvironmentQueryValid = $false
    $Facts.bootIdentifier = $null
    $Facts.bootConfigurationAttempted = $false
    $Facts.bootConfigurationValid = $false
    $Facts.testSigningConfigured = $false
    $Facts.rebootRequired = $false
    $Facts.signingState = 'UNKNOWN'
    if (-not $Facts.hostWindows) {
        return
    }

    try {
        $observation = & $Adapter.ReadNativeReadiness
        $native = ConvertFrom-NativeReadinessObservation $observation
        $Facts.osVersionQueryValid = [bool]$native.OsVersionQueryValid
        $Facts.osMajor = $native.OsMajor
        $Facts.osMinor = $native.OsMinor
        $Facts.osBuild = $native.OsBuild
        $Facts.windows10OrLater = [bool]$native.Windows10OrLater
        $Facts.nativeArchitecture = $native.NativeArchitecture
        $Facts.hostX64 = [bool]$native.HostX64
        $Facts.codeIntegrityQueryValid = [bool]$native.CodeIntegrityQueryValid
        $Facts.codeIntegrityOptions = $native.CodeIntegrityOptions
        $Facts.codeIntegrityEnabled = [bool]$native.CodeIntegrityEnabled
        $Facts.testSigningActive = [bool]$native.TestSigningActive
        $Facts.bootEnvironmentQueryValid = [bool]$native.BootEnvironmentQueryValid
        $Facts.bootIdentifier = $native.BootIdentifier
    } catch {
        Set-SigningReadinessState $Facts
        return
    }

    if ($Facts.osVersionQueryValid -and
        $Facts.windows10OrLater -and
        $Facts.hostX64 -and
        $Facts.elevated -and
        $Facts.bootEnvironmentQueryValid) {
        $Facts.bootConfigurationAttempted = $true
        try {
            $bcdObservation = & $Adapter.ReadBootConfiguration $native.BootIdentifierGuid
            $bcd = ConvertFrom-BcdReadOnlyObservation $bcdObservation $native.BootIdentifierGuid
            $Facts.bootConfigurationValid = [bool]$bcd.Valid
            if ($bcd.Valid) {
                $Facts.testSigningConfigured = [bool]$bcd.Configured
            }
        } catch {
            $Facts.bootConfigurationValid = $false
            $Facts.testSigningConfigured = $false
        }
    }
    Set-SigningReadinessState $Facts
}

function Test-JsonInteger {
    param($Value)

    return (
        $Value -is [sbyte] -or
        $Value -is [byte] -or
        $Value -is [int16] -or
        $Value -is [uint16] -or
        $Value -is [int32] -or
        $Value -is [uint32] -or
        $Value -is [int64] -or
        $Value -is [uint64]
    )
}

function Test-JsonStringArray {
    param($Value)

    if ($Value -isnot [System.Array]) {
        return $false
    }
    foreach ($item in @($Value)) {
        if ($item -isnot [string]) {
            return $false
        }
    }
    return $true
}

function Test-NonemptyJsonString {
    param($Value)

    return ($Value -is [string] -and -not [string]::IsNullOrWhiteSpace($Value))
}

function Test-FullyQualifiedToolPath {
    param(
        $Value,
        [string]$ExpectedLeaf
    )

    if (-not (Test-NonemptyJsonString $Value)) {
        return $false
    }
    try {
        if (-not [System.IO.Path]::IsPathRooted($Value)) {
            return $false
        }
        $root = [System.IO.Path]::GetPathRoot($Value)
        if ([string]::IsNullOrWhiteSpace($root) -or $root.Length -le 1 -or
            ($root.Length -eq 2 -and $root[1] -eq ':')) {
            return $false
        }
        $fullPath = [System.IO.Path]::GetFullPath($Value)
        return (
            $fullPath -ceq $Value -and
            [System.IO.Path]::GetFileName($Value) -ceq $ExpectedLeaf
        )
    } catch {
        return $false
    }
}

function New-ParseFailure {
    param([string]$Reason)

    return [pscustomobject]@{
        Valid = $false
        Reason = $Reason
        ExitCode = $null
        Overall = $null
        TrustReady = $false
        Probes = @()
    }
}

function ConvertFrom-StrictSingleJson {
    param(
        $CommandResult,
        [string]$Label
    )

    $stdout = @($CommandResult.Stdout)
    $stderr = @($CommandResult.Stderr)
    if ($stderr.Count -ne 0) {
        return New-ParseFailure "$Label wrote to stderr."
    }
    if ($stdout.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$stdout[0])) {
        return New-ParseFailure "$Label must emit exactly one nonempty stdout line."
    }
    $json = [string]$stdout[0]
    try {
        $validationError = [FsringStrictJsonValidator]::Validate($json, 65536, 32)
    } catch {
        return New-ParseFailure "$Label JSON lexical validation failed."
    }
    if (-not [string]::IsNullOrEmpty($validationError)) {
        return New-ParseFailure "$Label emitted invalid JSON: $validationError"
    }
    try {
        $parsed = $json | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return New-ParseFailure "$Label emitted malformed JSON."
    }
    if ($null -eq $parsed -or $parsed -is [System.Array] -or
        $parsed -is [string] -or $parsed -is [ValueType]) {
        return New-ParseFailure "$Label JSON must be one object."
    }
    return [pscustomobject]@{
        Valid = $true
        Reason = $null
        Parsed = $parsed
    }
}

function Test-ContainedClientEnvelope {
    param(
        $CommandResult,
        [string]$Label
    )

    $containmentProperty = (
        $CommandResult.PSObject.Properties['ContainmentConfirmed']
    )
    if ($null -eq $containmentProperty) {
        # Pure parser fixtures predate the process envelope and do not launch.
        return [pscustomobject]@{
            Valid = $true
            Reason = $null
        }
    }
    $required = @(
        'TimedOut',
        'ContainmentConfirmed',
        'OutputTruncated',
        'ProtocolValid',
        'OutputFinalized',
        'Lease'
    )
    foreach ($name in $required) {
        if ($null -eq $CommandResult.PSObject.Properties[$name]) {
            return [pscustomobject]@{
                Valid = $false
                Reason = "$Label contained-client envelope is incomplete."
            }
        }
    }
    $valid = (
        (Test-ExactRuntimeType $CommandResult.TimedOut ([bool])) -and
        (Test-ExactRuntimeType `
            $CommandResult.ContainmentConfirmed ([bool])) -and
        (Test-ExactRuntimeType `
            $CommandResult.OutputTruncated ([bool])) -and
        (Test-ExactRuntimeType `
            $CommandResult.ProtocolValid ([bool])) -and
        (Test-ExactRuntimeType `
            $CommandResult.OutputFinalized ([bool])) -and
        -not $CommandResult.TimedOut -and
        $CommandResult.ContainmentConfirmed -and
        -not $CommandResult.OutputTruncated -and
        $CommandResult.ProtocolValid -and
        $CommandResult.OutputFinalized -and
        $null -eq $CommandResult.Lease
    )
    return [pscustomobject]@{
        Valid = [bool]$valid
        Reason = if ($valid) {
            $null
        } else {
            "$Label process envelope is not safely completed and contained."
        }
    }
}

function Test-PackageVerifierResult {
    param($CommandResult)

    $envelope = Test-ContainedClientEnvelope `
        $CommandResult 'Package verifier'
    if (-not $envelope.Valid) {
        return New-ParseFailure $envelope.Reason
    }
    $single = ConvertFrom-StrictSingleJson $CommandResult 'Package verifier'
    if (-not $single.Valid) {
        return $single
    }
    if ($CommandResult.ExitCode -ne 0) {
        return New-ParseFailure 'Package verifier process exit is not zero.'
    }

    $parsed = $single.Parsed
    $properties = @('schema', 'overall', 'errors', 'warnings', 'trustReady', 'artifacts', 'tools')
    if (-not (Test-ExactPropertySet $parsed $properties)) {
        return New-ParseFailure 'Package verifier JSON has a missing or extra property.'
    }
    if ($parsed.schema -isnot [string] -or $parsed.schema -cne $script:VerifierSchema) {
        return New-ParseFailure 'Package verifier schema is not fsring-package-verifier/v1.'
    }
    if ($parsed.overall -isnot [string] -or $parsed.overall -cne 'PASS') {
        return New-ParseFailure 'Package verifier overall is not PASS.'
    }
    if ($parsed.trustReady -isnot [bool]) {
        return New-ParseFailure 'Package verifier trustReady is not a Boolean.'
    }
    if (-not (Test-JsonStringArray $parsed.errors) -or
        -not (Test-JsonStringArray $parsed.warnings)) {
        return New-ParseFailure 'Package verifier errors and warnings must be JSON string arrays.'
    }
    if (@($parsed.errors).Count -ne 0) {
        return New-ParseFailure 'Package verifier PASS contains errors.'
    }

    if (-not (Test-ExactPropertySet $parsed.artifacts @('fsring_fsd.inf', 'fsring_fsd.sys', 'fsring_fsd.cat'))) {
        return New-ParseFailure 'Package verifier PASS artifact roster is invalid.'
    }
    foreach ($artifactName in @('fsring_fsd.inf', 'fsring_fsd.sys', 'fsring_fsd.cat')) {
        $artifactValue = $parsed.artifacts.PSObject.Properties[$artifactName].Value
        if ($artifactValue -isnot [bool] -or -not $artifactValue) {
            return New-ParseFailure "Package verifier PASS did not affirm $artifactName."
        }
    }

    if (-not (Test-ExactPropertySet $parsed.tools @('infverif', 'signtool', 'catalogMembership'))) {
        return New-ParseFailure 'Package verifier PASS tool roster is invalid.'
    }

    $infverif = $parsed.tools.infverif
    if (-not (Test-ExactPropertySet $infverif @('path', 'productVersion', 'fileVersion', 'exitCode'))) {
        return New-ParseFailure 'Package verifier InfVerif evidence schema is invalid.'
    }
    if (-not (Test-FullyQualifiedToolPath $infverif.path 'infverif.exe')) {
        return New-ParseFailure 'Package verifier InfVerif path is not fully qualified to infverif.exe.'
    }
    if (-not (Test-NonemptyJsonString $infverif.productVersion) -or
        -not (Test-NonemptyJsonString $infverif.fileVersion)) {
        return New-ParseFailure 'Package verifier InfVerif version evidence is invalid.'
    }
    if (-not (Test-JsonInteger $infverif.exitCode) -or [int64]$infverif.exitCode -ne 0) {
        return New-ParseFailure 'Package verifier InfVerif exitCode is not integer zero.'
    }

    $signtool = $parsed.tools.signtool
    $signtoolProperties = @(
        'path',
        'productVersion',
        'fileVersion',
        'policy',
        'sysExitCode',
        'sysMode',
        'catExitCode',
        'catMode',
        'catalogMemberExitCode',
        'catalogMemberMode'
    )
    if (-not (Test-ExactPropertySet $signtool $signtoolProperties)) {
        return New-ParseFailure 'Package verifier SignTool evidence schema is invalid.'
    }
    if (-not (Test-FullyQualifiedToolPath $signtool.path 'signtool.exe')) {
        return New-ParseFailure 'Package verifier SignTool path is not fully qualified to signtool.exe.'
    }
    if (-not (Test-NonemptyJsonString $signtool.productVersion) -or
        -not (Test-NonemptyJsonString $signtool.fileVersion)) {
        return New-ParseFailure 'Package verifier SignTool version evidence is invalid.'
    }
    if ($signtool.policy -isnot [string] -or $signtool.policy -cne 'KernelMode') {
        return New-ParseFailure 'Package verifier SignTool policy is not KernelMode.'
    }
    foreach ($exitName in @('sysExitCode', 'catExitCode', 'catalogMemberExitCode')) {
        if (-not (Test-JsonInteger $signtool.PSObject.Properties[$exitName].Value)) {
            return New-ParseFailure "Package verifier SignTool $exitName is not an integer."
        }
    }
    foreach ($modeName in @('sysMode', 'catMode', 'catalogMemberMode')) {
        if ($signtool.PSObject.Properties[$modeName].Value -isnot [string]) {
            return New-ParseFailure "Package verifier SignTool $modeName is not a string."
        }
    }

    $catalogMembership = $parsed.tools.catalogMembership
    if (-not (Test-ExactPropertySet $catalogMembership @('mechanism', 'valid', 'memberHash'))) {
        return New-ParseFailure 'Package verifier catalog-membership evidence schema is invalid.'
    }
    if ($catalogMembership.mechanism -isnot [string] -or
        $catalogMembership.mechanism -cne 'Windows CryptCAT member-hash') {
        return New-ParseFailure 'Package verifier catalog-membership mechanism is invalid.'
    }
    if ($catalogMembership.valid -isnot [bool] -or -not $catalogMembership.valid) {
        return New-ParseFailure 'Package verifier catalog membership is not valid.'
    }
    if ($catalogMembership.memberHash -isnot [string] -or
        $catalogMembership.memberHash -cnotmatch '^[0-9A-F]{64}$') {
        return New-ParseFailure 'Package verifier catalog member hash is not 64 uppercase hexadecimal characters.'
    }

    $warning = 'Exact catalog membership and WDRLocalTestCert signature integrity are present, but the signing root is not trusted locally; package is not load-ready.'
    $warnings = @($parsed.warnings)
    $trustedState = (
        [int64]$signtool.sysExitCode -eq 0 -and
        [int64]$signtool.catExitCode -eq 0 -and
        [int64]$signtool.catalogMemberExitCode -eq 0 -and
        $signtool.sysMode -ceq 'Trusted' -and
        $signtool.catMode -ceq 'Trusted' -and
        $signtool.catalogMemberMode -ceq 'Trusted' -and
        $parsed.trustReady -and
        $warnings.Count -eq 0
    )
    $untrustedState = (
        [int64]$signtool.sysExitCode -eq 1 -and
        [int64]$signtool.catExitCode -eq 1 -and
        [int64]$signtool.catalogMemberExitCode -eq 1 -and
        $signtool.sysMode -ceq 'UntrustedTestRoot' -and
        $signtool.catMode -ceq 'UntrustedTestRoot' -and
        $signtool.catalogMemberMode -ceq 'UntrustedTestRoot' -and
        -not $parsed.trustReady -and
        $warnings.Count -eq 1 -and
        $warnings[0] -is [string] -and
        $warnings[0] -ceq $warning
    )
    # The third closed state: chain building succeeded against the local machine
    # stores, so the only remaining kernel-policy objection is that the root is
    # not a Microsoft one. This is the state a WDRLocalTestCert package actually
    # reaches on a host prepared for test signing, and the only one in which it
    # is load-ready. Get-PreflightDecision still refuses to be runnable unless
    # the signing state is ENABLED, so trustReady here never bypasses TESTSIGNING.
    $locallyTrustedState = (
        [int64]$signtool.sysExitCode -eq 1 -and
        [int64]$signtool.catExitCode -eq 1 -and
        [int64]$signtool.catalogMemberExitCode -eq 1 -and
        $signtool.sysMode -ceq 'TestSignedLocallyTrusted' -and
        $signtool.catMode -ceq 'TestSignedLocallyTrusted' -and
        $signtool.catalogMemberMode -ceq 'TestSignedLocallyTrusted' -and
        $parsed.trustReady -and
        $warnings.Count -eq 1 -and
        $warnings[0] -is [string] -and
        $warnings[0] -ceq $script:LocallyTrustedTestRootWarning
    )
    if (-not $trustedState -and -not $untrustedState -and -not $locallyTrustedState) {
        return New-ParseFailure 'Package verifier signature state is not one exact trusted, locally trusted, or untrusted-test-root state.'
    }

    return [pscustomobject]@{
        Valid = $true
        Reason = $null
        ExitCode = 0
        Overall = 'PASS'
        TrustReady = [bool]$parsed.trustReady
        Probes = @()
    }
}

function Test-HarnessResult {
    param(
        $CommandResult,
        [ValidateSet('Normal', 'Absent')]
        [string]$Kind
    )

    $envelope = Test-ContainedClientEnvelope `
        $CommandResult 'Control smoke harness'
    if (-not $envelope.Valid) {
        return New-ParseFailure $envelope.Reason
    }
    $single = ConvertFrom-StrictSingleJson $CommandResult 'Control smoke harness'
    if (-not $single.Valid) {
        return $single
    }
    $parsed = $single.Parsed
    $properties = @('schema', 'overall', 'exitCode', 'probes', 'reasons')
    if (-not (Test-ExactPropertySet $parsed $properties)) {
        return New-ParseFailure 'Control smoke harness JSON has a missing or extra property.'
    }
    if (-not (Test-ExactRuntimeType $parsed.schema ([string])) -or
        $parsed.schema -cne $script:HarnessSchema) {
        return New-ParseFailure 'Control smoke harness schema is not fsring-control-smoke/v1.'
    }
    if (-not (Test-JsonInteger $parsed.exitCode)) {
        return New-ParseFailure 'Control smoke harness exitCode is not an integer.'
    }
    if ([int64]$parsed.exitCode -ne [int64]$CommandResult.ExitCode) {
        return New-ParseFailure 'Control smoke harness process exit is inconsistent with JSON exitCode.'
    }
    if ($CommandResult.ExitCode -ne 0 -or
        $parsed.exitCode -ne 0 -or
        -not (Test-ExactRuntimeType $parsed.overall ([string])) -or
        $parsed.overall -cne 'PASS') {
        return New-ParseFailure 'Control smoke harness did not report PASS with exit 0.'
    }
    if ($parsed.reasons -isnot [System.Array] -or @($parsed.reasons).Count -ne 0) {
        return New-ParseFailure 'Control smoke harness PASS contains reasons.'
    }

    $expectedNames = $script:NormalProbeNames
    $expectedErrors = $script:NormalProbeErrors
    if ($Kind -ceq 'Absent') {
        $expectedNames = $script:AbsentProbeNames
        $expectedErrors = $script:AbsentProbeErrors
    }
    if ($parsed.probes -isnot [System.Array]) {
        return New-ParseFailure 'Control smoke harness probes must be a JSON array.'
    }
    $probes = @($parsed.probes)
    if ($probes.Count -ne $expectedNames.Count) {
        return New-ParseFailure "Control smoke harness $Kind probe count is invalid."
    }
    for ($index = 0; $index -lt $expectedNames.Count; $index++) {
        $probe = $probes[$index]
        if (-not (Test-ExactPropertySet $probe @('name', 'outcome', 'expected', 'actual'))) {
            return New-ParseFailure "Control smoke harness probe $index has a missing or extra property."
        }
        if (-not (Test-ExactRuntimeType $probe.name ([string])) -or
            $probe.name -cne $expectedNames[$index] -or
            -not (Test-ExactRuntimeType $probe.outcome ([string])) -or
            $probe.outcome -cne 'PASS') {
            return New-ParseFailure "Control smoke harness $Kind probe roster or outcome is invalid."
        }
        $expectedError = $expectedErrors[$index]
        if ($null -eq $expectedError) {
            if ($null -ne $probe.expected -or $null -ne $probe.actual) {
                return New-ParseFailure "Control smoke harness probe '$($probe.name)' has an invalid success oracle."
            }
        } elseif (-not (Test-JsonInteger $probe.expected) -or
            -not (Test-JsonInteger $probe.actual) -or
            [int64]$probe.expected -ne [int64]$expectedError -or
            [int64]$probe.actual -ne [int64]$expectedError) {
            return New-ParseFailure "Control smoke harness probe '$($probe.name)' has an invalid error oracle."
        }
    }
    return [pscustomobject]@{
        Valid = $true
        Reason = $null
        ExitCode = 0
        Overall = 'PASS'
        TrustReady = $false
        Probes = $probes
    }
}

function Test-C4HexString {
    param($Value, [int]$Digits)

    if (-not (Test-ExactRuntimeType $Value ([string]))) { return $false }
    $text = [string]$Value
    if ($text.Length -ne ($Digits + 2)) { return $false }
    if (-not $text.StartsWith('0x', [StringComparison]::Ordinal)) { return $false }
    foreach ($ch in $text.Substring(2).ToCharArray()) {
        if (-not (($ch -ge '0' -and $ch -le '9') -or ($ch -ge 'A' -and $ch -le 'F'))) {
            return $false
        }
    }
    return $true
}

function Get-C4HexValue {
    param([string]$Value)

    return [uint64]::Parse($Value.Substring(2), [Globalization.NumberStyles]::HexNumber)
}

function Test-C4Identity {
    param($Value)

    if ($null -eq $Value) { return $false }
    if (-not (Test-ExactPropertySet $Value @('bootInstanceId', 'mountId', 'sessionEpoch'))) {
        return $false
    }
    foreach ($half in @($Value.bootInstanceId, $Value.mountId)) {
        if (-not (Test-ExactPropertySet $half @('lo', 'hi'))) { return $false }
        if (-not (Test-C4HexString $half.lo 16) -or -not (Test-C4HexString $half.hi 16)) {
            return $false
        }
    }
    return (Test-C4HexString $Value.sessionEpoch 16)
}

function Test-C4IdentityEqual {
    param($Left, $Right)

    if ($null -eq $Left -or $null -eq $Right) { return $false }
    return (
        $Left.bootInstanceId.lo -ceq $Right.bootInstanceId.lo -and
        $Left.bootInstanceId.hi -ceq $Right.bootInstanceId.hi -and
        $Left.mountId.lo -ceq $Right.mountId.lo -and
        $Left.mountId.hi -ceq $Right.mountId.hi -and
        $Left.sessionEpoch -ceq $Right.sessionEpoch
    )
}

function Test-C4Reason {
    param($Value, [bool]$AllowInfrastructure)

    if (-not (Test-ExactRuntimeType $Value ([string]))) { return $false }
    $text = [string]$Value
    if ($text.Length -lt 1 -or
        [Text.Encoding]::UTF8.GetByteCount($text) -gt $script:C4ReasonMaxBytes) {
        return $false
    }
    foreach ($ch in $text.ToCharArray()) {
        if ([int]$ch -lt 0x20 -or [int]$ch -eq 0x7F) { return $false }
    }
    if (-not $AllowInfrastructure -and
        $text.StartsWith($script:C4InfrastructurePrefix, [StringComparison]::Ordinal)) {
        return $false
    }
    return $true
}

function Test-C4Oracle {
    param($Value)

    if ($null -eq $Value) { return $false }
    if ($null -eq $Value.PSObject.Properties['kind']) { return $false }
    switch -CaseSensitive ($Value.kind) {
        'status' {
            if (-not (Test-ExactPropertySet $Value @('kind', 'domain', 'code', 'information'))) {
                return $false
            }
            if ($Value.domain -cne 'ntstatus' -and $Value.domain -cne 'win32') { return $false }
            if (-not (Test-C4HexString $Value.code 8)) { return $false }
            if ($null -ne $Value.information -and -not (Test-C4HexString $Value.information 16)) {
                return $false
            }
            return $true
        }
        'facts' {
            if (-not (Test-ExactPropertySet $Value @('kind', 'values'))) { return $false }
            return (Test-C4FactValues $Value.values)
        }
        'events' {
            if (-not (Test-ExactPropertySet $Value @('kind', 'names', 'identity'))) { return $false }
            if ($Value.names -isnot [System.Array]) { return $false }
            foreach ($name in @($Value.names)) {
                if ($script:C4EventNames -cnotcontains $name) { return $false }
            }
            return (Test-C4Identity $Value.identity)
        }
        'compound' {
            if (-not (Test-ExactPropertySet $Value @('kind', 'facts', 'events'))) { return $false }
            if ($Value.facts.kind -cne 'facts' -or $Value.events.kind -cne 'events') { return $false }
            return ((Test-C4Oracle $Value.facts) -and (Test-C4Oracle $Value.events))
        }
        default { return $false }
    }
}

function Test-C4FactValues {
    param($Values)

    if ($null -eq $Values) { return $false }
    foreach ($property in $Values.PSObject.Properties) {
        $value = $property.Value
        if ($value -is [bool]) { continue }
        if ((Test-C4HexString $value 8) -or (Test-C4HexString $value 16)) { continue }
        # A free-form detail field is not an oracle: only Booleans and
        # fixed-width uppercase hex are admissible facts.
        return $false
    }
    return $true
}

function Get-C4CanonicalJson {
    param($Value)

    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [string]) { return '"' + $Value + '"' }
    if ($Value -is [System.Array]) {
        $parts = @($Value | ForEach-Object { Get-C4CanonicalJson $_ })
        return '[' + ($parts -join ',') + ']'
    }
    $pairs = @(
        $Value.PSObject.Properties | ForEach-Object {
            '"' + $_.Name + '":' + (Get-C4CanonicalJson $_.Value)
        }
    )
    return '{' + ($pairs -join ',') + '}'
}

function Test-C4OracleEqual {
    param($Left, $Right)

    if ($null -eq $Left -or $null -eq $Right) { return $false }
    # Canonical bytes, in the order the producer emitted them: a reordered key
    # set is a different oracle, not the same one written differently.
    return ((Get-C4CanonicalJson $Left) -ceq (Get-C4CanonicalJson $Right))
}

function New-C4Continuity {
    param([bool]$Valid, [string]$Reason)

    return [pscustomobject]@{ Valid = $Valid; Reason = $Reason }
}

function Test-C4FrameContinuity {
    param(
        $Frame,
        [int]$ExpectedSequence,
        [string]$ExpectedStage,
        [string]$Nonce,
        $RootIdentity,
        $DisposableIdentity,
        [string]$VdoNativeName,
        [string]$DosName
    )

    if ($null -eq $Frame) { return (New-C4Continuity $false 'worker frame is absent') }
    if ($Frame.schema -cne $script:C4WorkerSchema) {
        return (New-C4Continuity $false 'worker frame schema is not fsring-c4-worker/v1')
    }
    if (-not (Test-JsonInteger $Frame.sequence) -or
        [int64]$Frame.sequence -ne [int64]$ExpectedSequence) {
        return (New-C4Continuity $false 'worker frame sequence is out of order')
    }
    if ($Frame.stage -cne $ExpectedStage) {
        return (New-C4Continuity $false 'worker frame stage does not match its sequence')
    }
    if ($Frame.nonce -cne $Nonce) {
        return (New-C4Continuity $false 'worker frame nonce does not match this invocation')
    }
    if (-not (Test-C4Identity $Frame.rootIdentity)) {
        return (New-C4Continuity $false 'worker frame root identity is malformed')
    }
    if ($null -ne $RootIdentity -and -not (Test-C4IdentityEqual $Frame.rootIdentity $RootIdentity)) {
        return (New-C4Continuity $false 'worker frame root identity drifted')
    }
    if ($null -ne $DisposableIdentity) {
        if (-not (Test-C4Identity $Frame.disposableIdentity) -or
            -not (Test-C4IdentityEqual $Frame.disposableIdentity $DisposableIdentity)) {
            return (New-C4Continuity $false 'worker frame disposable identity drifted')
        }
    }
    if ($VdoNativeName -and $Frame.vdoNativeName -cne $VdoNativeName) {
        return (New-C4Continuity $false 'worker frame VDO name drifted')
    }
    if ($DosName -and $Frame.dosName -cne $DosName) {
        return (New-C4Continuity $false 'worker frame DOS name drifted')
    }
    $range = $script:C4PrivateProbeRanges[$ExpectedStage]
    if ($null -ne $range) {
        if ($Frame.probes -isnot [System.Array]) {
            return (New-C4Continuity $false 'worker frame probes must be an array')
        }
        $probes = @($Frame.probes)
        $expectedNames = @($script:C4ProbeRoster[$range[0]..$range[1]])
        if ($probes.Count -ne $expectedNames.Count) {
            return (New-C4Continuity $false 'worker frame probe slice has the wrong length')
        }
        for ($index = 0; $index -lt $expectedNames.Count; $index++) {
            $probe = $probes[$index]
            if (-not (Test-ExactPropertySet $probe @('name', 'outcome', 'expected', 'actual'))) {
                return (New-C4Continuity $false 'worker frame probe has a missing or extra key')
            }
            if ($probe.name -cne $expectedNames[$index]) {
                return (New-C4Continuity $false 'worker frame probe slice is reordered')
            }
            if ($script:C4RunnerOnlyProbe -ceq $probe.name) {
                return (New-C4Continuity $false 'a worker may not observe the unload transients')
            }
            if ($script:C4ProbeOutcomes -cnotcontains $probe.outcome) {
                return (New-C4Continuity $false 'worker frame probe outcome is not closed')
            }
            if (-not (Test-C4Oracle $probe.expected)) {
                return (New-C4Continuity $false 'worker frame probe expected oracle is malformed')
            }
            if ($null -eq $probe.actual) {
                if ($probe.outcome -cne 'NOT RUN') {
                    return (New-C4Continuity $false 'an executed worker probe must carry an actual')
                }
            } else {
                if ($probe.outcome -ceq 'NOT RUN') {
                    return (New-C4Continuity $false 'a NOT RUN worker probe may not carry an actual')
                }
                if (-not (Test-C4Oracle $probe.actual) -or
                    $probe.actual.kind -cne $probe.expected.kind) {
                    return (New-C4Continuity $false 'worker frame probe actual oracle is malformed')
                }
            }
        }
    }
    if ($null -ne $Frame.PSObject.Properties['events']) {
        if ($Frame.events -isnot [System.Array]) {
            return (New-C4Continuity $false 'worker frame events must be an array')
        }
        $events = @($Frame.events)
        if ($events.Count -gt $script:C4PrivateEventMax) {
            return (New-C4Continuity $false 'worker frame carries too many events')
        }
        $seen = @()
        foreach ($event in $events) {
            if (-not (Test-ExactPropertySet $event @(
                        'name', 'id', 'version', 'keyword', 'identity', 'reason'))) {
                return (New-C4Continuity $false 'worker frame event has a missing or extra key')
            }
            if ($script:C4EventNames -cnotcontains $event.name) {
                return (New-C4Continuity $false 'worker frame event name is not closed')
            }
            $expectedId = ([array]::IndexOf($script:C4EventNames, $event.name)) + 1
            if (-not (Test-JsonInteger $event.id) -or [int64]$event.id -ne [int64]$expectedId) {
                return (New-C4Continuity $false 'worker frame event id is not its name')
            }
            if (-not (Test-JsonInteger $event.version) -or [int64]$event.version -ne 1) {
                return (New-C4Continuity $false 'worker frame event version is not 1')
            }
            if (-not (Test-C4HexString $event.keyword 16) -or
                (Get-C4HexValue $event.keyword) -ne 1) {
                return (New-C4Continuity $false 'worker frame event keyword is not 0x1')
            }
            if (-not (Test-C4Identity $event.identity)) {
                return (New-C4Continuity $false 'worker frame event identity is malformed')
            }
            if (-not (Test-JsonInteger $event.reason)) {
                return (New-C4Continuity $false 'worker frame event reason is not an integer')
            }
            $reason = [int64]$event.reason
            $reasonOk = if ($event.name -ceq 'SESSION_FENCED') {
                $reason -ge 1 -and $reason -le 4
            } else {
                $reason -eq 0
            }
            if (-not $reasonOk) {
                return (New-C4Continuity $false 'worker frame event reason does not match its name')
            }
            $key = Get-C4CanonicalJson $event
            if ($seen -ccontains $key) {
                return (New-C4Continuity $false 'worker frame repeats an event')
            }
            $seen += $key
        }
    }
    if ($null -ne $Frame.PSObject.Properties['cleanup']) {
        $cleanupProbe = @($Frame.probes) | Where-Object { $_.name -ceq 'cleanup-close' }
        if ($null -eq $cleanupProbe -or $null -eq $cleanupProbe.actual) {
            return (New-C4Continuity $false 'a live record must carry an observed cleanup-close probe')
        }
        $summary = Get-C4CanonicalJson $Frame.cleanup
        $facts = Get-C4CanonicalJson $cleanupProbe.actual.values
        if ($summary -cne $facts) {
            return (New-C4Continuity $false 'the cleanup summary disagrees with its own probe facts')
        }
    }
    return (New-C4Continuity $true $null)
}

function Assert-C4Continuity {
    param($Frame, $Expectation, $Emitted, [string]$Stage)

    # The single rejection branch. Every frame transition goes through it, and
    # a caller may not compare a subset or continue past an invalid result:
    # that is why the check lives here and not at each call site.
    $c4Continuity = Test-C4FrameContinuity $Frame `
        $Expectation.Sequence $Expectation.Stage $Expectation.Nonce `
        $Expectation.RootIdentity $Expectation.DisposableIdentity `
        $Expectation.VdoNativeName $Expectation.DosName
    if (-not $c4Continuity.Valid) {
        $Emitted = Add-C4InfrastructureReason $Emitted $Stage 'runner' 2
        return [pscustomobject]@{
            Accepted = $false
            Reason = $c4Continuity.Reason
            Emitted = $Emitted
        }
    }
    return [pscustomobject]@{ Accepted = $true; Reason = $null; Emitted = $Emitted }
}

function Read-C4Frame {
    param([IO.Stream]$Stream, [int]$TimeoutMilliseconds = 30000)

    $header = New-Object byte[] 4
    if (-not (Read-C4Exact $Stream $header $TimeoutMilliseconds)) {
        return [pscustomobject]@{ Valid = $false; Reason = 'unexpected EOF'; Frame = $null }
    }
    $length = [BitConverter]::ToUInt32($header, 0)
    if ($length -lt $script:C4FrameMin -or $length -gt $script:C4FrameMax) {
        return [pscustomobject]@{ Valid = $false; Reason = 'frame length out of bounds'; Frame = $null }
    }
    $payload = New-Object byte[] $length
    if (-not (Read-C4Exact $Stream $payload $TimeoutMilliseconds)) {
        return [pscustomobject]@{ Valid = $false; Reason = 'unexpected EOF'; Frame = $null }
    }
    if ($payload.Length -ge 3 -and
        $payload[0] -eq 0xEF -and $payload[1] -eq 0xBB -and $payload[2] -eq 0xBF) {
        return [pscustomobject]@{ Valid = $false; Reason = 'frame carries a BOM'; Frame = $null }
    }
    foreach ($byte in $payload) {
        if ($byte -eq 0) {
            return [pscustomobject]@{ Valid = $false; Reason = 'frame carries a NUL'; Frame = $null }
        }
    }
    $text = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($payload)
    $parsed = ConvertFrom-StrictSingleJson (
        [pscustomobject]@{ ExitCode = 0; Stdout = @($text); Stderr = @() }
    ) 'C4 worker frame'
    if (-not $parsed.Valid) {
        return [pscustomobject]@{ Valid = $false; Reason = $parsed.Reason; Frame = $null }
    }
    return [pscustomobject]@{ Valid = $true; Reason = $null; Frame = $parsed.Parsed }
}

function Read-C4Exact {
    param([IO.Stream]$Stream, [byte[]]$Buffer, [int]$TimeoutMilliseconds)

    $filled = 0
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ($filled -lt $Buffer.Length) {
        if ([DateTime]::UtcNow -gt $deadline) { return $false }
        $read = $Stream.Read($Buffer, $filled, $Buffer.Length - $filled)
        if ($read -le 0) { return $false }
        $filled += $read
    }
    return $true
}

function Write-C4Frame {
    param([IO.Stream]$Stream, [string]$Payload)

    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Payload)
    if ($bytes.Length -lt $script:C4FrameMin -or $bytes.Length -gt $script:C4FrameMax) {
        return $false
    }
    $Stream.Write([BitConverter]::GetBytes([uint32]$bytes.Length), 0, 4)
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
    return $true
}

function New-C4DosName {
    param([int]$ProcessId, [string]$GuidN)

    return ('Global\FsRingC4-{0:X8}-{1}' -f $ProcessId, $GuidN)
}

function Complete-C4PostUnloadEvidence {
    param($LiveSeed, $PostObservation, [bool]$ServiceStopped, $DosLinkQueryWin32Code)

    # PowerShell alone constructs probe index 25, from exactly three sources.
    # A missing fragment leaves the probe NOT RUN; nothing here supplies a
    # default, because a defaulted teardown fact is indistinguishable from an
    # observed one in the report.
    if ($null -eq $LiveSeed -or $null -eq $PostObservation -or $null -eq $DosLinkQueryWin32Code) {
        return [pscustomobject]@{ Valid = $false; Values = $null }
    }
    if (-not (Test-ExactPropertySet $LiveSeed @('formerAliasRangesFree', 'ownedHandlesClosed'))) {
        return [pscustomobject]@{ Valid = $false; Values = $null }
    }
    if (-not (Test-ExactPropertySet $PostObservation @(
                'providerOpenNtstatus', 'fscontrolOpenNtstatus', 'vdoOpenNtstatus'))) {
        return [pscustomobject]@{ Valid = $false; Values = $null }
    }
    if ($LiveSeed.formerAliasRangesFree -isnot [bool] -or
        $LiveSeed.ownedHandlesClosed -isnot [bool]) {
        return [pscustomobject]@{ Valid = $false; Values = $null }
    }
    foreach ($key in @('providerOpenNtstatus', 'fscontrolOpenNtstatus', 'vdoOpenNtstatus')) {
        if (-not (Test-C4HexString $PostObservation.$key 8)) {
            return [pscustomobject]@{ Valid = $false; Values = $null }
        }
    }
    $values = [ordered]@{
        serviceStopped = $ServiceStopped
        providerOpenNtstatus = $PostObservation.providerOpenNtstatus
        fscontrolOpenNtstatus = $PostObservation.fscontrolOpenNtstatus
        vdoOpenNtstatus = $PostObservation.vdoOpenNtstatus
        dosLinkQueryWin32Code = $DosLinkQueryWin32Code
        formerAliasRangesFree = $LiveSeed.formerAliasRangesFree
        ownedHandlesClosed = $LiveSeed.ownedHandlesClosed
    }
    $ordered = @($values.Keys)
    if (($ordered -join ',') -cne ($script:C4UnloadMergeKeys -join ',')) {
        return [pscustomobject]@{ Valid = $false; Values = $null }
    }
    return [pscustomobject]@{
        Valid = $true
        Values = [pscustomobject]$values
    }
}

function Complete-C4ScmCleanup {
    param($scmCleanup, $Emitted, [uint32]$Win32Code)

    # An SCM stop/delete that did not succeed is an infrastructure failure, not
    # a probe outcome: it forces the aggregate verdict from outside the roster
    # and leaves the post-unload observations unmerged. Swallowing it would
    # turn a service that is still running into a clean PASS.
    if (-not $scmCleanup.Success) {
        $Emitted = Add-C4InfrastructureReason $Emitted 'SCM_CLEANUP' 'win32' $Win32Code
        return [pscustomobject]@{ Emitted = $Emitted; ServiceStopped = $false }
    }
    return [pscustomobject]@{ Emitted = $Emitted; ServiceStopped = $true }
}

function Test-HarnessResultV2 {
    param($CommandResult)

    $envelope = Test-ContainedClientEnvelope $CommandResult 'C4 smoke harness'
    if (-not $envelope.Valid) { return New-ParseFailure $envelope.Reason }
    $single = ConvertFrom-StrictSingleJson $CommandResult 'C4 smoke harness'
    if (-not $single.Valid) { return $single }
    $parsed = $single.Parsed
    if (-not (Test-ExactPropertySet $parsed @(
                'schema', 'overall', 'exitCode', 'identity', 'probes', 'reasons'))) {
        return New-ParseFailure 'C4 smoke report has a missing or extra root key.'
    }
    if ($parsed.schema -cne $script:C4HarnessSchemaV2) {
        return New-ParseFailure 'C4 smoke report schema is not fsring-control-smoke/v2.'
    }
    if ($script:C4ProbeOutcomes -cnotcontains $parsed.overall) {
        return New-ParseFailure 'C4 smoke report overall is not closed.'
    }
    if (-not (Test-JsonInteger $parsed.exitCode)) {
        return New-ParseFailure 'C4 smoke report exitCode is not an integer.'
    }
    if ($null -ne $parsed.identity -and -not (Test-C4Identity $parsed.identity)) {
        return New-ParseFailure 'C4 smoke report identity is malformed.'
    }
    if ($parsed.probes -isnot [System.Array]) {
        return New-ParseFailure 'C4 smoke report probes must be an array.'
    }
    $probes = @($parsed.probes)
    if ($probes.Count -ne $script:C4ProbeRoster.Count) {
        return New-ParseFailure 'C4 smoke report roster length is invalid.'
    }
    if ($parsed.reasons -isnot [System.Array]) {
        return New-ParseFailure 'C4 smoke report reasons must be an array.'
    }
    $reasons = @($parsed.reasons)
    if ($reasons.Count -gt $script:C4ReasonMaxEntries) {
        return New-ParseFailure 'C4 smoke report exceeds the reason bound.'
    }
    foreach ($reason in $reasons) {
        if (-not (Test-C4Reason $reason $true)) {
            return New-ParseFailure 'C4 smoke report reason is malformed.'
        }
    }

    $passedProbeCount = 0
    $notRunCount = 0
    $failed = $false
    for ($index = 0; $index -lt $probes.Count; $index++) {
        $probe = $probes[$index]
        if (-not (Test-ExactPropertySet $probe @('name', 'outcome', 'expected', 'actual'))) {
            return New-ParseFailure "C4 smoke report probe $index has a missing or extra key."
        }
        if ($probe.name -cne $script:C4ProbeRoster[$index]) {
            return New-ParseFailure 'C4 smoke report roster is reordered.'
        }
        if ($script:C4ProbeOutcomes -cnotcontains $probe.outcome) {
            return New-ParseFailure 'C4 smoke report probe outcome is not closed.'
        }
        if (-not (Test-C4Oracle $probe.expected)) {
            return New-ParseFailure "C4 smoke report probe '$($probe.name)' has a malformed expectation."
        }
        if ($null -eq $probe.actual) {
            $notRunCount++
            continue
        }
        if (-not (Test-C4Oracle $probe.actual)) {
            return New-ParseFailure "C4 smoke report probe '$($probe.name)' has a malformed observation."
        }
        # The comparison is redone here; the reported outcome string is never
        # trusted, and neither is the top-level overall.
        if (Test-C4OracleEqual $probe.expected $probe.actual) {
            $passedProbeCount++
        } else {
            $failed = $true
        }
    }
    $reasonCount = $reasons.Count
    $rootIdentity = $parsed.identity
    foreach ($reason in $reasons) {
        if ($reason.StartsWith($script:C4InfrastructurePrefix, [StringComparison]::Ordinal)) {
            $failed = $true
        }
    }

    $derived = 'NOT RUN'
    if ($passedProbeCount -eq 27 -and $reasonCount -eq 0) {
        $derived = 'PASS'
    } elseif ($failed) {
        $derived = 'FAIL'
    } elseif ($rootIdentity -ne $null -and $notRunCount -ne 0) {
        $derived = 'FAIL'
    } elseif ($reasonCount -ne 0) {
        $derived = 'FAIL'
    }
    $derivedExit = switch -CaseSensitive ($derived) {
        'PASS' { 0 }
        'FAIL' { 1 }
        default { 2 }
    }
    return [pscustomobject]@{
        Valid = $true
        Reason = $null
        Overall = $derived
        ExitCode = $derivedExit
        Probes = $probes
        Identity = $rootIdentity
        PassedProbeCount = $passedProbeCount
        NotRunCount = $notRunCount
    }
}

function Add-C4WorkerReasons {
    param($Accepted, $Reasons)

    # One cumulative budget across the whole invocation, checked *before* a
    # frame is accepted: an overflowing frame is rejected whole, so it
    # contributes neither its reasons nor its facts.
    $candidate = @($Accepted) + @($Reasons)
    if ($candidate.Count -gt $script:C4WorkerReasonLimit) {
        return [pscustomobject]@{ Accepted = $false; Reasons = @($Accepted) }
    }
    foreach ($reason in @($Reasons)) {
        if (-not (Test-C4Reason $reason $false)) {
            return [pscustomobject]@{ Accepted = $false; Reasons = @($Accepted) }
        }
    }
    return [pscustomobject]@{ Accepted = $true; Reasons = $candidate }
}

function New-C4InfrastructureReason {
    param([string]$Stage, [string]$Domain, [uint32]$Code)

    if ($script:C4InfrastructureStages -cnotcontains $Stage) { return $null }
    if ($script:C4InfrastructureDomains -cnotcontains $Domain) { return $null }
    return ('{0}{1}:{2}:0x{3:X8}' -f $script:C4InfrastructurePrefix, $Stage, $Domain, $Code)
}

function Add-C4InfrastructureReason {
    param($Emitted, [string]$Stage, [string]$Domain, [uint32]$Code)

    # At most the first reason for each of the nine closed stages, in stage
    # order, so the public 35-entry bound is lossless rather than truncating.
    $reason = New-C4InfrastructureReason $Stage $Domain $Code
    if ($null -eq $reason) { return $Emitted }
    if ($Emitted.ContainsKey($Stage)) { return $Emitted }
    $Emitted[$Stage] = $reason
    return $Emitted
}

function Get-C4InfrastructureReasons {
    param($Emitted)

    $ordered = @()
    foreach ($stage in $script:C4InfrastructureStages) {
        if ($Emitted.ContainsKey($stage)) { $ordered += $Emitted[$stage] }
    }
    return $ordered
}

$script:C4PreflightOrchestrationSchema = 'fsring-c4-preflight-orchestration/v1'
$script:C4DiagnosticsJournalSchema = 'fsring-c4-diagnostics-journal/v1'
$script:C4CleanupRecoverySchema = 'fsring-c4-cleanup-recovery/v1'
$script:C4ProcessContainmentSchema = 'fsring-c4-process-containment/v1'
$script:C4CleanupLastError = $null
$script:C4LiveSidecarNames = @(
    'etw.sidecar.jsonl',
    'worker-frames.sidecar.bin',
    'cleanup.sidecar.json',
    'diagnostics.sidecar.jsonl'
)
$script:C4MutationOperations = @(
    'SERVICE_CREATE',
    'SERVICE_START_DRIVER_LOAD',
    'DOS_LINK_CREATE',
    'SMOKE_TRAFFIC',
    'DOS_LINK_REMOVE',
    'SERVICE_STOP',
    'SERVICE_DELETE',
    'RECOVERY_DOS_LINK_REMOVE',
    'RECOVERY_SERVICE_STOP',
    'RECOVERY_SERVICE_DELETE'
)
$script:C4CleanupRefusalReasons = @(
    'PROCESS_CONTAINMENT_UNPROVED',
    'JOURNAL_MISSING',
    'JOURNAL_TRUNCATED',
    'JOURNAL_NONCANONICAL',
    'JOURNAL_CHAIN_INVALID',
    'JOURNAL_REPLAY',
    'TUPLE_MISMATCH',
    'OWNED_NAME_MISMATCH',
    'SERVICE_OWNERSHIP_AMBIGUOUS',
    'DOS_OWNERSHIP_AMBIGUOUS'
)
$script:C4ServiceStates = @(
    'STOPPED',
    'START_PENDING',
    'STOP_PENDING',
    'RUNNING',
    'CONTINUE_PENDING',
    'PAUSE_PENDING',
    'PAUSED'
)

function Get-C4ProductionModeSelector {
    param(
        [bool]$C4,
        [ValidateSet('Live', 'PreflightOnly', 'CleanupOnly', 'SelfTest')]
        [string]$Mode
    )

    if (-not $C4) {
        return [pscustomobject]@{
            PublicSchema = 'fsring-driver-smoke/v1'
            Mode = $Mode
        }
    }
    if ($Mode -ceq 'PreflightOnly') {
        return [pscustomobject]@{
            PublicSchema = $script:C4PreflightOrchestrationSchema
            Mode = $Mode
        }
    }
    if ($Mode -ceq 'CleanupOnly') {
        return [pscustomobject]@{
            PublicSchema = $script:C4CleanupRecoverySchema
            Mode = $Mode
        }
    }
    return [pscustomobject]@{
        PublicSchema = $script:C4HarnessSchemaV2
        Mode = $Mode
    }
}

function Get-C4LiveSidecarNames {
    return @($script:C4LiveSidecarNames)
}

function Test-C4AttemptId {
    param([string]$Value)
    return ($Value -is [string] -and $Value -cmatch '^[0-9a-f]{32}$')
}

function Get-C4OwnedServiceName {
    param([string]$AttemptId)
    return ('fsring-c4-{0}' -f $AttemptId)
}

function Get-C4OwnedDosName {
    param([int]$ProcessId, [string]$AttemptId)
    return ('Global\FsRingC4-{0:X8}-{1}' -f $ProcessId, $AttemptId.ToUpperInvariant())
}

function Get-C4Sha256Hex {
    param([byte[]]$Bytes, [switch]$Upper)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Bytes)
        $hex = ($hash | ForEach-Object { $_.ToString('x2') }) -join ''
        if ($Upper) { return $hex.ToUpperInvariant() }
        return $hex
    } finally {
        $sha.Dispose()
    }
}

function Get-C4Utf8NoBom {
    param([string]$Text)
    return (New-Object System.Text.UTF8Encoding $false).GetBytes($Text)
}

function Get-C4FileSha256Lower {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.File]::Exists($Path)) {
        return $null
    }
    return Get-C4Sha256Hex ([IO.File]::ReadAllBytes($Path))
}

function Get-C4ClosedJournalReason {
    param([string]$Reason)
    if ([string]::IsNullOrWhiteSpace($Reason)) {
        return 'JOURNAL_NONCANONICAL'
    }
    if ($script:C4CleanupRefusalReasons -ccontains $Reason) {
        return $Reason
    }
    $base = $Reason.Split(':', 2)[0]
    if ($script:C4CleanupRefusalReasons -ccontains $base) {
        return $base
    }
    return 'JOURNAL_NONCANONICAL'
}

function Get-C4ServiceStateName {
    param([uint32]$State)
    switch ([int]$State) {
        1 { return 'STOPPED' }
        2 { return 'START_PENDING' }
        3 { return 'STOP_PENDING' }
        4 { return 'RUNNING' }
        5 { return 'CONTINUE_PENDING' }
        6 { return 'PAUSE_PENDING' }
        7 { return 'PAUSED' }
        default { return $null }
    }
}

function Invoke-C4NativeTool {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [int]$TimeoutMilliseconds = 30000
    )
    $dir = Join-Path $env:TEMP ('fsring-c4-tool-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($dir)
    try {
        $out = Join-Path $dir 'stdout.bin'
        $err = Join-Path $dir 'stderr.bin'
        $exit = Join-Path $dir 'exit.json'
        Invoke-C4EvidenceProcess -Executable $FilePath -Arguments @($Arguments) `
            -WorkingDirectory $dir `
            -TimeoutMilliseconds $TimeoutMilliseconds `
            -StdoutPath $out -StderrPath $err -ExitPath $exit -ExitFormat CanonicalJson
        if (-not [IO.File]::Exists($exit) -or ((Get-Item -LiteralPath $exit).Length -eq 0)) {
            return [pscustomobject]@{
                Success = $false
                Win32Code = 1
                Termination = 'CAPTURE_FAILED'
            }
        }
        $obj = ConvertFrom-C4CanonicalJsonBytes -Bytes ([IO.File]::ReadAllBytes($exit)) -ExpectedSchema 'fsring-captured-exit/v1'
        $code = 1
        if ($obj.termination -ceq 'NORMAL' -and $null -ne $obj.observedExit) {
            $code = [int]$obj.observedExit
        }
        return [pscustomobject]@{
            Success = ($obj.termination -ceq 'NORMAL' -and $code -eq 0)
            Win32Code = $code
            Termination = [string]$obj.termination
        }
    } finally {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-C4CanonicalServiceBinaryPath {
    param([string]$BinaryPath)
    if ([string]::IsNullOrWhiteSpace($BinaryPath)) { return $null }
    $path = $BinaryPath.Trim()
    if ($path.Length -ge 2 -and $path.StartsWith('"') -and $path.EndsWith('"')) {
        $path = $path.Substring(1, $path.Length - 2)
    }
    if ($path.StartsWith('\??\')) { $path = $path.Substring(4) }
    return $path
}

function Test-C4ServiceBinaryMatchesTuple {
    param([string]$BinaryPath, [string]$ExpectedFileSha256)
    if ([string]::IsNullOrWhiteSpace($ExpectedFileSha256)) { return $false }
    $path = Get-C4CanonicalServiceBinaryPath $BinaryPath
    if ([string]::IsNullOrWhiteSpace($path) -or -not [IO.File]::Exists($path)) { return $false }
    $hash = Get-C4FileSha256Lower $path
    return ($hash -ceq $ExpectedFileSha256)
}

function Test-C4DosTargetMatchesTuple {
    param([string]$Target, [string]$ExpectedTarget)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedTarget)) {
        return ($Target -ceq $ExpectedTarget)
    }
    return [bool]($Target -cmatch '^\\Device\\FsRingVolume-[0-9A-Fa-f]{16}-[0-9A-Fa-f]{16}$')
}

function Get-C4RealServiceQuery {
    param(
        [string]$ServiceName,
        [string]$ExpectedBinaryFileSha256
    )
    try {
        $obs = [FsringNativeService]::Query($ServiceName)
        if (-not $obs.QuerySucceeded) {
            return [pscustomobject]@{
                Observable = $false
                Present = $null
                Owned = $null
                State = $null
                Target = $null
                BinaryPathSha256 = $null
                Ambiguous = $true
                Win32Code = [int]$obs.Win32Error
            }
        }
        if (-not $obs.Exists) {
            return [pscustomobject]@{
                Observable = $true
                Present = $false
                Owned = $false
                State = $null
                Target = $null
                BinaryPathSha256 = $null
                Ambiguous = $false
                Win32Code = 1060
            }
        }
        $state = Get-C4ServiceStateName $obs.State
        $hash = $null
        if (-not [string]::IsNullOrWhiteSpace($obs.BinaryPath)) {
            $hash = Get-C4Sha256Hex (Get-C4Utf8NoBom ([string]$obs.BinaryPath))
        }
        $owned = Test-C4ServiceBinaryMatchesTuple ([string]$obs.BinaryPath) $ExpectedBinaryFileSha256
        return [pscustomobject]@{
            Observable = $true
            Present = $true
            Owned = [bool]$owned
            State = $state
            Target = $null
            BinaryPathSha256 = $hash
            Ambiguous = ((-not $owned) -or ($null -eq $state))
            Win32Code = [int]$obs.Win32Error
            BinaryPath = [string]$obs.BinaryPath
        }
    } catch {
        return [pscustomobject]@{
            Observable = $false
            Present = $null
            Owned = $null
            State = $null
            Target = $null
            BinaryPathSha256 = $null
            Ambiguous = $true
            Win32Code = 1
        }
    }
}

function Get-C4ExpectedVdoTargetFromJournal {
    param([string]$JournalPath)
    if ([string]::IsNullOrWhiteSpace($JournalPath) -or -not [IO.File]::Exists($JournalPath)) {
        return $null
    }
    $dir = [IO.Path]::GetDirectoryName($JournalPath)
    if ([string]::IsNullOrWhiteSpace($dir)) { return $null }
    $frames = Join-Path $dir 'worker-frames.sidecar.bin'
    if (-not [IO.File]::Exists($frames)) { return $null }
    try {
        $fs = [IO.File]::Open($frames, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $parsed = Read-C4Frame $fs 1000
            if ($parsed.Valid -and $null -ne $parsed.Frame -and
                $null -ne $parsed.Frame.PSObject.Properties['vdoNativeName'] -and
                -not [string]::IsNullOrWhiteSpace([string]$parsed.Frame.vdoNativeName)) {
                return [string]$parsed.Frame.vdoNativeName
            }
            if ($parsed.Valid -and $null -ne $parsed.Frame -and
                $null -ne $parsed.Frame.PSObject.Properties['rootIdentity']) {
                $id = $parsed.Frame.rootIdentity
                if ($null -ne $id -and $null -ne $id.mountId) {
                    $lo = Get-C4HexValue ([string]$id.mountId.lo)
                    $hi = Get-C4HexValue ([string]$id.mountId.hi)
                    return ('\Device\FsRingVolume-{0:X16}-{1:X16}' -f $lo, $hi)
                }
            }
        } finally {
            $fs.Dispose()
        }
    } catch {
        return $null
    }
    return $null
}

function Get-C4RealDosQuery {
    param(
        [string]$DosName,
        [string]$ExpectedTarget
    )
    try {
        if ([string]::IsNullOrWhiteSpace($DosName) -or $DosName -ceq 'UNAVAILABLE') {
            return [pscustomobject]@{
                Observable = $true
                Present = $false
                Owned = $false
                State = $null
                Target = $null
                BinaryPathSha256 = $null
                Ambiguous = $false
                Win32Code = 2
            }
        }
        $builder = New-Object System.Text.StringBuilder 32768
        $n = [FsringC4EvidenceNative]::QueryDosDeviceW($DosName, $builder, [uint32]$builder.Capacity)
        if ($n -eq 0) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($err -eq 0) { $err = 2 }
            return [pscustomobject]@{
                Observable = $true
                Present = $false
                Owned = $false
                State = $null
                Target = $null
                BinaryPathSha256 = $null
                Ambiguous = $false
                Win32Code = [int]$err
            }
        }
        $target = $builder.ToString().Trim([char]0)
        $owned = Test-C4DosTargetMatchesTuple $target $ExpectedTarget
        return [pscustomobject]@{
            Observable = $true
            Present = $true
            Owned = [bool]$owned
            State = $null
            Target = $target
            BinaryPathSha256 = $null
            Ambiguous = (-not $owned)
            Win32Code = 0
        }
    } catch {
        return [pscustomobject]@{
            Observable = $false
            Present = $null
            Owned = $null
            State = $null
            Target = $null
            BinaryPathSha256 = $null
            Ambiguous = $true
            Win32Code = 1
        }
    }
}

function Invoke-C4RealMutation {
    param(
        [string]$Operation,
        [string]$Target,
        [string]$SysPath,
        [string]$DosTarget
    )
    $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
    switch -CaseSensitive ($Operation) {
        'SERVICE_CREATE' {
            $native = Invoke-C4NativeTool $sc @(
                'create', $Target, 'type=', 'filesys', 'start=', 'demand',
                'group=', 'File System', 'binPath=', $SysPath
            )
            return [pscustomobject]@{ Success = [bool]$native.Success; Win32Code = $native.Win32Code; Result = $(if ($native.Success) { 'SUCCEEDED' } else { 'FAILED' }) }
        }
        'SERVICE_START_DRIVER_LOAD' {
            $native = Invoke-C4NativeTool $sc @('start', $Target)
            return [pscustomobject]@{ Success = [bool]$native.Success; Win32Code = $native.Win32Code; Result = $(if ($native.Success) { 'SUCCEEDED' } else { 'FAILED' }) }
        }
        'SERVICE_STOP' {
            $q = Get-C4RealServiceQuery $Target
            if ($q.Observable -and -not $q.Present) {
                return [pscustomobject]@{ Success = $true; Win32Code = $null; Result = 'ALREADY_ABSENT' }
            }
            if ($q.Present -and $q.State -ceq 'STOPPED') {
                return [pscustomobject]@{ Success = $true; Win32Code = $null; Result = 'ALREADY_ABSENT' }
            }
            $native = Invoke-C4NativeTool $sc @('stop', $Target)
            $ok = $native.Success -or $native.Win32Code -eq 1062 -or $native.Win32Code -eq 1060
            return [pscustomobject]@{
                Success = $ok
                Win32Code = $native.Win32Code
                Result = $(if ($native.Win32Code -eq 1060 -or $native.Win32Code -eq 1062) { 'ALREADY_ABSENT' } elseif ($ok) { 'SUCCEEDED' } else { 'FAILED' })
            }
        }
        'SERVICE_DELETE' {
            $q = Get-C4RealServiceQuery $Target
            if ($q.Observable -and -not $q.Present) {
                return [pscustomobject]@{ Success = $true; Win32Code = $null; Result = 'ALREADY_ABSENT' }
            }
            $native = Invoke-C4NativeTool $sc @('delete', $Target)
            $ok = $native.Success -or $native.Win32Code -eq 1060
            return [pscustomobject]@{
                Success = $ok
                Win32Code = $(if ($native.Win32Code -eq 1060) { $null } else { $native.Win32Code })
                Result = $(if ($native.Win32Code -eq 1060) { 'ALREADY_ABSENT' } elseif ($ok) { 'SUCCEEDED' } else { 'FAILED' })
            }
        }
        'DOS_LINK_CREATE' {
            $flags = [uint32]($script:DDD_RAW_TARGET_PATH -bor $script:DDD_NO_BROADCAST_SYSTEM)
            $ok = [FsringC4EvidenceNative]::DefineDosDeviceW($flags, $Target, $DosTarget)
            $err = if ($ok) { 0 } else { [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
            return [pscustomobject]@{ Success = [bool]$ok; Win32Code = $err; Result = $(if ($ok) { 'SUCCEEDED' } else { 'FAILED' }) }
        }
        'DOS_LINK_REMOVE' {
            $q = Get-C4RealDosQuery -DosName $Target -ExpectedTarget $DosTarget
            if ($q.Observable -and -not $q.Present) {
                return [pscustomobject]@{ Success = $true; Win32Code = $null; Result = 'ALREADY_ABSENT' }
            }
            $ok = [FsringC4EvidenceNative]::DefineDosDeviceW([uint32]$script:C4DosRemoveFlags, $Target, $DosTarget)
            $err = if ($ok) { 0 } else { [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
            if (-not $ok -and $err -eq 2) {
                return [pscustomobject]@{ Success = $true; Win32Code = $null; Result = 'ALREADY_ABSENT' }
            }
            return [pscustomobject]@{ Success = [bool]$ok; Win32Code = $err; Result = $(if ($ok) { 'SUCCEEDED' } else { 'FAILED' }) }
        }
        'RECOVERY_DOS_LINK_REMOVE' {
            return Invoke-C4RealMutation -Operation 'DOS_LINK_REMOVE' -Target $Target -DosTarget $DosTarget
        }
        'RECOVERY_SERVICE_STOP' {
            return Invoke-C4RealMutation -Operation 'SERVICE_STOP' -Target $Target
        }
        'RECOVERY_SERVICE_DELETE' {
            return Invoke-C4RealMutation -Operation 'SERVICE_DELETE' -Target $Target
        }
        default {
            return [pscustomobject]@{ Success = $true; Win32Code = $null; Result = 'ALREADY_ABSENT' }
        }
    }
}

function ConvertTo-C4OracleObject {
    param($Json)
    return (Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json)
}

function Get-C4IndependentExpectedOracle {
    param([string]$Name, $Identity)
    $idJson = if ($null -ne $Identity) {
        Get-C4CanonicalJson $Identity
    } else {
        New-C4TestIdentityJson
    }
    $status = {
        param($Code, $Info)
        if ($null -eq $Info) {
            return ("{`"kind`":`"status`",`"domain`":`"win32`",`"code`":`"$Code`",`"information`":null}")
        }
        return ("{`"kind`":`"status`",`"domain`":`"win32`",`"code`":`"$Code`",`"information`":`"$Info`"}")
    }
    $json = switch -CaseSensitive ($Name) {
        'root-open' { '{"kind":"facts","values":{"opened":true}}' }
        'trailing-open' { & $status '0x00000002' $null }
        'unknown-ioctl' { & $status '0x00000001' '0x0000000000000000' }
        'donate-short' { & $status '0x00000057' '0x0000000000000000' }
        'donate-wrong-version' { & $status '0x0000051A' '0x0000000000000000' }
        'donate' { & $status '0x00000032' '0x0000000000000000' }
        'child-inherited-handle' { & $status '0x00000005' '0x0000000000000000' }
        'parent-handle-after-child' { & $status '0x00000032' '0x0000000000000000' }
        'fscontrol-acl' { '{"kind":"facts","values":{"elevatedNtstatus":"0x00000000","unprivilegedChildNtstatus":"0xC0000022"}}' }
        'setup-required-unavailable' { '{"kind":"facts","values":{"win32Code":"0x00000032","information":"0x0000000000000000","mountSequenceDelta":"0x0000000000000000"}}' }
        'setup-optional-downgrade' { '{"kind":"facts","values":{"win32Code":"0x00000000","selectedMask":"0x0000000000000010","unavailableSelectedMask":"0x0000000000000000","cleanupFenceMatched":true,"transientsRemoved":true,"identityDistinctFromRoot":true}}' }
        'setup-security' { '{"kind":"facts","values":{"win32Code":"0x00000000","resultSizeMatches":true,"selectedMask":"0x0000000000000010","identityNonzero":true}}' }
        'setup-duplicate' { & $status '0x000000AA' '0x0000000000000000' }
        'session-layout' { '{"kind":"facts","values":{"independentParser":true,"exactLengths":true,"zeroPadding":true,"zeroCursors":true,"descriptorCountsMatch":true}}' }
        'view-protections' { '{"kind":"facts","values":{"virtualQueryCoverage":true,"exactProtections":true,"overlapCount":"0x0000000000000000","executableRangeCount":"0x0000000000000000"}}' }
        'vdo-acl' { '{"kind":"facts","values":{"unprivilegedChildCode":"0x00000005"}}' }
        'vdo-mount' {
            '{"kind":"compound","facts":{"kind":"facts","values":{"createFileCode":"0x00000000","rootVolumeHandle":true}},"events":{"kind":"events","names":["SESSION_PUBLISHED","MOUNT_PUBLISHED"],"identity":' + $idJson + '}}'
        }
        'enter-poll' { '{"kind":"facts","values":{"win32Code":"0x00000000","information":"0x0000000000000030","flags":"0x00000000","cqDrained":"0x00000000","returnedCredits":"0x00000000"}}' }
        'enter-timeout' { '{"kind":"facts","values":{"win32Code":"0x00000000","information":"0x0000000000000030","flags":"0x00000004","cqDrained":"0x00000000","returnedCredits":"0x00000000"}}' }
        'enter-dual-role' { '{"kind":"facts","values":{"firstWaitPending":true,"concurrentDrainWin32Code":"0x00000000","conflictingWaitWin32Code":"0x000000AA","rolesReleased":true}}' }
        'enter-notify-credit' { '{"kind":"facts","values":{"win32Code":"0x00000000","cqDrained":"0x00000001","returnedCredits":"0x00000001","oldGeneration":"0x0000000000000001","newGeneration":"0x0000000000000002"}}' }
        'enter-contention' { '{"kind":"facts","values":{"win32Code":"0x00000000","flags":"0x00000010","bounded":true}}' }
        'enter-cancel' { '{"kind":"facts","values":{"win32Code":"0x000003E3","information":"0x0000000000000000","exactOverlapped":true,"completedOnce":true}}' }
        'protocol-abort' {
            '{"kind":"compound","facts":{"kind":"facts","values":{"enterWin32Code":"0x00000000","fenceReason":"0x00000003","sessionAbsent":true}},"events":{"kind":"events","names":["SESSION_FENCED"],"identity":' + $idJson + '}}'
        }
        'cleanup-close' { '{"kind":"facts","values":{"pendingEnterCount":"0x00000000","aliasCount":"0x00000000","ownedHandleCount":"0x00000000","completedOnce":true}}' }
        'unload-transients' { $null }
        'bootcontext-persistent' { '{"kind":"facts","values":{"sectionOpenNtstatus":"0xC0000022","eventOpenNtstatus":"0xC0000022","objectsPersistAndRemainKernelOnly":true}}' }
        default { '{"kind":"facts","values":{"observed":true}}' }
    }
    if ($Name -ceq 'unload-transients') {
        return [pscustomobject]@{
            kind = 'facts'
            values = [pscustomobject]([ordered]@{
                    serviceStopped = $true
                    providerOpenNtstatus = '0xC0000034'
                    fscontrolOpenNtstatus = '0xC0000034'
                    vdoOpenNtstatus = '0xC0000034'
                    dosLinkQueryWin32Code = '0x00000002'
                    formerAliasRangesFree = $true
                    ownedHandlesClosed = $true
                })
        }
    }
    return (ConvertTo-C4OracleObject $json)
}

function New-C4WorkerEventJson {
    param([string]$Name, $Identity, [int]$Reason = 0)
    $id = ([array]::IndexOf($script:C4EventNames, $Name)) + 1
    $idJson = Get-C4CanonicalJson $Identity
    return (
        '{"name":"' + $Name + '","id":' + $id +
        ',"version":1,"keyword":"0x0000000000000001","identity":' + $idJson +
        ',"reason":' + $Reason + '}'
    )
}

function ConvertTo-C4CanonicalJson {
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
        $parts = @($Value | ForEach-Object { ConvertTo-C4CanonicalJson $_ })
        return '[' + ($parts -join ',') + ']'
    }
    if ($Value -is [Collections.IDictionary]) {
        $pairs = New-Object System.Collections.ArrayList
        foreach ($key in @($Value.Keys)) {
            [void]$pairs.Add(('"{0}":{1}' -f $key, (ConvertTo-C4CanonicalJson $Value[$key])))
        }
        return '{' + ($pairs -join ',') + '}'
    }
    return (Get-C4CanonicalJson $Value)
}

function New-C4DiagnosticsHeader {
    param(
        [string]$AttemptId,
        [string]$SourceCommit,
        [string]$SourceTree,
        [string]$CandidateManifestSha256,
        [string]$PackageSetSha256,
        [string]$HarnessSha256,
        [int]$WorkerProcessId,
        [string]$OwnedServiceName,
        [string]$OwnedDosName,
        [string]$OwnershipPreflightSha256
    )

    return [ordered]@{
        schema = $script:C4DiagnosticsJournalSchema
        version = 1
        recordType = 'HEADER'
        attemptId = $AttemptId
        sourceCommit = $SourceCommit
        sourceTree = $SourceTree
        candidateManifestSha256 = $CandidateManifestSha256
        packageSetSha256 = $PackageSetSha256
        harnessSha256 = $HarnessSha256
        workerProcessId = $WorkerProcessId
        ownedServiceName = $OwnedServiceName
        ownedDosName = $OwnedDosName
        ownershipPreflightSha256 = $OwnershipPreflightSha256
        sequence = 0
        previousRecordSha256 = $null
    }
}

function New-C4MutationAttemptRecord {
    param(
        [string]$AttemptId,
        [int]$Sequence,
        [string]$PreviousRecordSha256,
        [string]$Operation,
        [string]$Target,
        [ValidateSet('LIVE', 'RECOVERY')]
        [string]$Phase
    )

    return [ordered]@{
        schema = $script:C4DiagnosticsJournalSchema
        version = 1
        recordType = 'MUTATION_ATTEMPT'
        attemptId = $AttemptId
        sequence = $Sequence
        previousRecordSha256 = $PreviousRecordSha256
        operation = $Operation
        target = $Target
        phase = $Phase
    }
}

function Test-C4DiagnosticsJournalBytes {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$JournalBytes,
        [string]$ExpectedAttemptId
    )

    $Bytes = $JournalBytes
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_MISSING'; Header = $null; Records = @() }
    }
    $text = (New-Object System.Text.UTF8Encoding $false).GetString($Bytes)
    if ($text.Length -eq 0 -or $text[0] -ne '{') {
        return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_NONCANONICAL'; Header = $null; Records = @() }
    }
    if (-not $text.EndsWith("`n")) {
        return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_TRUNCATED'; Header = $null; Records = @() }
    }
    $lines = $text.Split([char]10)
    $complete = @()
    foreach ($line in $lines) {
        if ($line.Length -eq 0) { continue }
        $complete += $line
    }
    if ($complete.Count -eq 0) {
        return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_MISSING'; Header = $null; Records = @() }
    }
    $records = New-Object System.Collections.ArrayList
    $previousHash = $null
    $offset = 0
    for ($index = 0; $index -lt $complete.Count; $index++) {
        $line = $complete[$index]
        $canonical = $line + "`n"
        $lineBytes = Get-C4Utf8NoBom $canonical
        $parsed = $null
        try {
            $parsed = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $line
        } catch {
            return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_NONCANONICAL'; Header = $null; Records = @() }
        }
        if ($null -eq $parsed) {
            return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_NONCANONICAL'; Header = $null; Records = @() }
        }
        if ($index -eq 0) {
            $headerPrefix = '{"schema":"fsring-c4-diagnostics-journal/v1","version":1,"recordType":"HEADER","attemptId":'
            if (-not $line.StartsWith($headerPrefix)) {
                return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_NONCANONICAL'; Header = $null; Records = @() }
            }
            if ($parsed.schema -cne $script:C4DiagnosticsJournalSchema) {
                return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_NONCANONICAL'; Header = $null; Records = @() }
            }
            if ([int]$parsed.version -ne 1) {
                return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_NONCANONICAL'; Header = $null; Records = @() }
            }
            if ($parsed.recordType -cne 'HEADER') {
                return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_NONCANONICAL'; Header = $null; Records = @() }
            }
            if ([int]$parsed.sequence -ne 0) {
                return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_NONCANONICAL'; Header = $null; Records = @() }
            }
            if ($null -ne $parsed.previousRecordSha256) {
                return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_NONCANONICAL'; Header = $null; Records = @() }
            }
            if (-not (Test-C4AttemptId ([string]$parsed.attemptId))) {
                return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_NONCANONICAL'; Header = $null; Records = @() }
            }
            if ($ExpectedAttemptId -and ([string]$parsed.attemptId) -cne $ExpectedAttemptId) {
                return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_NONCANONICAL'; Header = $null; Records = @() }
            }
            if ([int]$parsed.workerProcessId -le 0) {
                return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_NONCANONICAL'; Header = $null; Records = @() }
            }
        } else {
            $mutationPrefix = '{"schema":"fsring-c4-diagnostics-journal/v1","version":1,"recordType":"MUTATION_ATTEMPT","attemptId":'
            if (-not $line.StartsWith($mutationPrefix)) {
                return [pscustomobject]@{ Valid = $false; Reason = 'JOURNAL_NONCANONICAL'; Header = $null; Records = @() }
            }
            if ($parsed.schema -cne $script:C4DiagnosticsJournalSchema -or
                [int]$parsed.version -ne 1 -or
                $parsed.recordType -cne 'MUTATION_ATTEMPT' -or
                $parsed.attemptId -cne $records[0].attemptId -or
                $parsed.sequence -ne $index -or
                $parsed.previousRecordSha256 -cne $previousHash -or
                $script:C4MutationOperations -cnotcontains $parsed.operation -or
                $parsed.phase -cnotin @('LIVE', 'RECOVERY')) {
                $reason = 'JOURNAL_CHAIN_INVALID'
                if ($parsed.attemptId -cne $records[0].attemptId) { $reason = 'JOURNAL_REPLAY' }
                return [pscustomobject]@{ Valid = $false; Reason = $reason; Header = $records[0]; Records = $records }
            }
        }
        $previousHash = Get-C4Sha256Hex $lineBytes
        [void]$records.Add($parsed)
        $offset += $lineBytes.Length
    }
    return [pscustomobject]@{
        Valid = $true
        Reason = $null
        Header = $records[0]
        Records = $records
        PrefixSha256 = (Get-C4Sha256Hex $Bytes)
    }
}

function New-C4CleanupObservation {
    param(
        [bool]$Observable,
        [bool]$Present,
        $Owned,
        $StateOrTarget,
        $BinaryPathSha256,
        [switch]$Service
    )

    if (-not $Observable) {
        if ($Service) {
            return [ordered]@{
                observable = $false
                present = $null
                owned = $null
                state = $null
                binaryPathSha256 = $null
            }
        }
        return [ordered]@{
            observable = $false
            present = $null
            owned = $null
            target = $null
        }
    }
    if (-not $Present) {
        if ($Service) {
            return [ordered]@{
                observable = $true
                present = $false
                owned = $false
                state = $null
                binaryPathSha256 = $null
            }
        }
        return [ordered]@{
            observable = $true
            present = $false
            owned = $false
            target = $null
        }
    }
    if ($Service) {
        return [ordered]@{
            observable = $true
            present = $true
            owned = [bool]$Owned
            state = $StateOrTarget
            binaryPathSha256 = $BinaryPathSha256
        }
    }
    return [ordered]@{
        observable = $true
        present = $true
        owned = [bool]$Owned
        target = $StateOrTarget
    }
}

function New-C4CleanupRecoveryObject {
    param(
        [string]$AttemptId,
        [string]$CandidateManifestSha256,
        $ContainmentProofSha256,
        $OwnedServiceName,
        $OwnedDosName,
        $JournalPrefixSha256,
        $JournalFinalSha256,
        $Operations,
        $Before,
        $After,
        [ValidateSet('PASS', 'FAIL', 'REFUSED')]
        [string]$Status,
        $RefusalReason
    )

    return [ordered]@{
        schema = $script:C4CleanupRecoverySchema
        version = 1
        attemptId = $AttemptId
        candidateManifestSha256 = $CandidateManifestSha256
        containmentProofSha256 = $ContainmentProofSha256
        ownedServiceName = $OwnedServiceName
        ownedDosName = $OwnedDosName
        journalPrefixSha256 = $JournalPrefixSha256
        journalFinalSha256 = $JournalFinalSha256
        operations = @($Operations)
        before = $Before
        after = $After
        status = $Status
        refusalReason = $RefusalReason
    }
}

function Test-C4ProcessContainmentProof {
    param($Object, [string]$AttemptId, [string]$Role)

    $expected = @(
        'schema', 'version', 'attemptId', 'captureRole', 'childProcessId',
        'createdSuspended', 'jobKillOnClose', 'breakawayDisabled',
        'jobAssignedBeforeResume', 'mainThreadResumed', 'terminationAttempted',
        'treeExited', 'streamsClosed', 'status'
    )
    if (-not (Test-ExactPropertySet $Object $expected)) { return $false }
    if ($Object.schema -cne $script:C4ProcessContainmentSchema) { return $false }
    if ([int]$Object.version -ne 1) { return $false }
    if ($Object.attemptId -cne $AttemptId) { return $false }
    if ($Object.captureRole -cne $Role) { return $false }
    if ([int]$Object.childProcessId -le 0) { return $false }
    foreach ($flag in @(
            'createdSuspended', 'jobKillOnClose', 'breakawayDisabled',
            'jobAssignedBeforeResume', 'mainThreadResumed', 'terminationAttempted',
            'treeExited', 'streamsClosed'
        )) {
        if ($Object.$flag -isnot [bool]) { return $false }
    }
    if ($Object.status -cnotin @('PASS', 'FAIL')) { return $false }
    $allTrue = $true
    foreach ($flag in @(
            'createdSuspended', 'jobKillOnClose', 'breakawayDisabled',
            'jobAssignedBeforeResume', 'mainThreadResumed', 'terminationAttempted',
            'treeExited', 'streamsClosed'
        )) {
        if (-not $Object.$flag) { $allTrue = $false }
    }
    if ($Object.status -ceq 'PASS' -and -not $allTrue) { return $false }
    return $true
}

function New-C4PreflightEnvelope {
    param(
        [string]$AttemptId,
        [string]$SourceCommit,
        [string]$SourceTree,
        [string]$CandidateManifestSha256,
        $Profile,
        [string]$PackageSetSha256,
        [string]$ArtifactSetSha256,
        [string]$ExpectedHarnessSha256,
        [string]$ActualHarnessSha256,
        $Preflight,
        $Ownership
    )

    return [ordered]@{
        schema = $script:C4PreflightOrchestrationSchema
        version = 1
        overall = 'NOT RUN'
        exitCode = 2
        attemptId = $AttemptId
        sourceCommit = $SourceCommit
        sourceTree = $SourceTree
        candidateManifestSha256 = $CandidateManifestSha256
        profile = $Profile
        packageSetSha256 = $PackageSetSha256
        artifactSetSha256 = $ArtifactSetSha256
        expectedHarnessSha256 = $ExpectedHarnessSha256
        actualHarnessSha256 = $ActualHarnessSha256
        ownedServiceName = (Get-C4OwnedServiceName $AttemptId)
        ownedDosPattern = 'Global\FsRingC4-<retained-worker-pid:08X>-<UPPERCASE-attemptId>'
        preflight = $Preflight
        ownership = $Ownership
    }
}

# The native reason roster's preflight subset, derived from the same facts
# Get-PreflightDecision judges. Emitted only for a decision that is not
# runnable, so a runnable preflight never carries a blocker.
function Get-C4PreflightReasonCodes {
    param($Facts, $Decision)
    if ($null -eq $Facts -or $null -eq $Decision -or [bool]$Decision.Runnable) { return @() }
    $codes = New-Object System.Collections.ArrayList
    if (-not $Facts.hostWindows -or -not $Facts.osVersionQueryValid -or
        -not $Facts.windows10OrLater) { [void]$codes.Add('OS_UNSUPPORTED') }
    if (-not $Facts.hostX64) { [void]$codes.Add('PROCESS_NOT_X64') }
    if (-not $Facts.elevated) { [void]$codes.Add('NOT_ELEVATED') }
    if (-not $Facts.codeIntegrityQueryValid -or -not $Facts.codeIntegrityEnabled) {
        [void]$codes.Add('CODE_INTEGRITY_NOT_READY')
    }
    if (-not ($Facts.testSigningActive -and $Facts.testSigningConfigured -and
              $Facts.signingState -ceq 'ENABLED')) {
        [void]$codes.Add('TEST_SIGNING_NOT_READY')
    }
    if ($Facts.rebootRequired) { [void]$codes.Add('REBOOT_PENDING') }
    if (-not $Facts.trustReady) { [void]$codes.Add('PACKAGE_NOT_TRUST_READY') }
    if ($Facts.serviceChecked -and -not $Facts.serviceAbsent) {
        [void]$codes.Add('SERVICE_NAME_OCCUPIED')
    }
    return @($codes)
}

# StrictMode-safe read of one property that may not exist on a parsed object.
function Get-C4OptionalProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if (@($Object.PSObject.Properties.Name) -notcontains $Name) { return $null }
    return $Object.$Name
}

# The preflight envelope's source identity is the CANDIDATE's, never this
# checkout's. Task 30 requires the bootstrap commit to be a strict ancestor of
# HEAD, so a live `git rev-parse HEAD` here can never equal the value the
# native orchestrator compares the envelope against. Everything bindable is
# read from the manifest this run was handed.
function New-C4PreflightOnlyEnvelope {
    param(
        [string]$AttemptId,
        [string]$CandidateManifestPath,
        [string]$ExpectedCandidateManifestSha256,
        [string]$PackageDirectory,
        [string]$HarnessPath,
        [string]$ExpectedHarnessSha256,
        $Facts
    )

    $emptyHash = Get-C4Sha256Hex ([byte[]](New-Object byte[] 0))
    $candidateHash = Get-C4FileSha256Lower $CandidateManifestPath
    if ($null -eq $candidateHash) { $candidateHash = $emptyHash }

    $manifest = $null
    if ([IO.File]::Exists($CandidateManifestPath)) {
        try {
            $manifestUtf8 = New-Object System.Text.UTF8Encoding $false
            $manifest = $manifestUtf8.GetString(
                [IO.File]::ReadAllBytes($CandidateManifestPath)) | ConvertFrom-Json
        } catch {
            $manifest = $null
        }
    }
    $sourceCommit = [string](Get-C4OptionalProperty $manifest 'sourceCommit')
    $sourceTree = [string](Get-C4OptionalProperty $manifest 'sourceTree')
    $profileId = [string](Get-C4OptionalProperty (Get-C4OptionalProperty $manifest 'profile') 'id')
    $artifactSet = [string](Get-C4OptionalProperty $manifest 'artifactSetSha256')
    $packageSet = [string](Get-C4OptionalProperty (Get-C4OptionalProperty (
        Get-C4OptionalProperty $manifest 'artifacts') 'package') 'setSha256')

    $packageRoot = $PackageDirectory
    if ([string]::IsNullOrWhiteSpace($packageRoot)) {
        $packageRoot = Join-Path $PSScriptRoot '..\target\x86_64-pc-windows-msvc\release\fsring_fsd_package'
    }
    $harnessFile = $HarnessPath
    if ([string]::IsNullOrWhiteSpace($harnessFile)) {
        $harnessFile = Join-Path $PSScriptRoot '..\..\target\debug\fsring-control-smoke.exe'
    }
    $actualHarness = Get-C4FileSha256Lower $harnessFile
    if ($null -eq $actualHarness) { $actualHarness = $emptyHash }
    $actualHarnessUpper = $actualHarness.ToUpperInvariant()

    # File identity is necessary but never sufficient: the whole point of a
    # read-only preflight is that nobody authorizes mutation on a host that
    # cannot load the driver, so the readiness gate decides too.
    $identityBound = (
        $candidateHash -ceq $ExpectedCandidateManifestSha256 -and
        [IO.File]::Exists($CandidateManifestPath) -and
        [IO.File]::Exists($harnessFile) -and
        $actualHarnessUpper -ceq $ExpectedHarnessSha256
    )
    $decision = $null
    if ($null -ne $Facts) { $decision = Get-PreflightDecision $Facts }
    $runnable = ($identityBound -and $null -ne $decision -and [bool]$decision.Runnable)
    $reasonCodes = @(Get-C4PreflightReasonCodes $Facts $decision)
    $ownership = [ordered]@{
        createdByThisRun = $false
        servicePresent = $false
        mutationAttempts = 0
        ownedServiceName = (Get-C4OwnedServiceName $AttemptId)
    }
    return (New-C4PreflightEnvelope `
        $AttemptId $sourceCommit $sourceTree $candidateHash `
        ([ordered]@{ id = $profileId }) $packageSet `
        $artifactSet $ExpectedHarnessSha256 $actualHarnessUpper `
        ([ordered]@{ runnable = [bool]$runnable; reasonCodes = @($reasonCodes) }) $ownership)
}

function Invoke-C4CleanupOnlyCore {
    param(
        [string]$AttemptId,
        [string]$CandidateManifestPath,
        [string]$ExpectedCandidateManifestSha256,
        [string]$DiagnosticsJournalPath,
        [string]$ContainmentProofPath,
        [string]$ExpectedContainmentProofSha256,
        [string]$CleanupEvidencePath,
        [string]$OwnedServiceName,
        [string]$OwnedDosName,
        $Adapters
    )

    $utf8 = New-Object System.Text.UTF8Encoding $false
    $reserved = $null
    $status = 'REFUSED'
    $refusal = 'JOURNAL_MISSING'
    $script:C4RecoveryAppended = $false
    $operations = New-Object System.Collections.ArrayList
    $containmentHash = $null
    $prefixHash = $null
    $finalHash = $null
    $dosNameOut = $null
    if ($OwnedDosName -cne 'UNAVAILABLE') { $dosNameOut = $OwnedDosName }
    $before = [ordered]@{
        service = (New-C4CleanupObservation -Observable:$false -Present:$false -Service)
        dos = (New-C4CleanupObservation -Observable:$false -Present:$false)
    }
    $after = [ordered]@{
        service = (New-C4CleanupObservation -Observable:$false -Present:$false -Service)
        dos = (New-C4CleanupObservation -Observable:$false -Present:$false)
    }

    function Write-CleanupResult {
        param($Object)
        $bytes = Get-C4Utf8NoBom ((ConvertTo-C4CanonicalJson $Object) + "`n")
        if ($null -ne $reserved) {
            $reserved.Position = 0
            $reserved.SetLength(0)
            $reserved.Write($bytes, 0, $bytes.Length)
            $reserved.Flush()
            $reserved.Dispose()
        }
    }

    try {
        if (-not (Test-C4AttemptId $AttemptId)) {
            throw 'attempt id is not lowercase GUID-N'
        }
        $parent = [IO.Path]::GetDirectoryName($CleanupEvidencePath)
        if (-not [IO.Directory]::Exists($parent)) {
            throw 'cleanup evidence parent is missing'
        }
        $reserved = [IO.File]::Open(
            $CleanupEvidencePath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )

        $unavailableDos = $OwnedDosName -ceq 'UNAVAILABLE'
        $unavailableProof = (
            $ContainmentProofPath -ceq 'UNAVAILABLE' -and
            $ExpectedContainmentProofSha256 -ceq 'UNAVAILABLE'
        )
        if ($unavailableDos -or $unavailableProof) {
            $refusal = if ($unavailableProof) {
                'PROCESS_CONTAINMENT_UNPROVED'
            } else {
                'OWNED_NAME_MISMATCH'
            }
            $result = New-C4CleanupRecoveryObject `
                $AttemptId $ExpectedCandidateManifestSha256 $null `
                $OwnedServiceName $dosNameOut $null $null @() `
                $before $after 'REFUSED' $refusal
            Write-CleanupResult $result
            return $result
        }

        $proofBytes = $null
        if (-not [IO.File]::Exists($ContainmentProofPath)) {
            $result = New-C4CleanupRecoveryObject `
                $AttemptId $ExpectedCandidateManifestSha256 $null `
                $OwnedServiceName $dosNameOut $null $null @() `
                $before $after 'REFUSED' 'PROCESS_CONTAINMENT_UNPROVED'
            Write-CleanupResult $result
            return $result
        }
        $proofBytes = [IO.File]::ReadAllBytes($ContainmentProofPath)
        $proofHash = Get-C4Sha256Hex $proofBytes
        if ($proofHash -cne $ExpectedContainmentProofSha256) {
            $result = New-C4CleanupRecoveryObject `
                $AttemptId $ExpectedCandidateManifestSha256 $null `
                $OwnedServiceName $dosNameOut $null $null @() `
                $before $after 'REFUSED' 'PROCESS_CONTAINMENT_UNPROVED'
            Write-CleanupResult $result
            return $result
        }
        $proofText = $utf8.GetString($proofBytes)
        if ($proofText.EndsWith("`n")) {
            $proofText = $proofText.Substring(0, $proofText.Length - 1)
        }
        $proofObject = $proofText | ConvertFrom-Json
        if (-not (Test-C4ProcessContainmentProof $proofObject $AttemptId 'LIVE') -or
            $proofObject.status -cne 'PASS') {
            $result = New-C4CleanupRecoveryObject `
                $AttemptId $ExpectedCandidateManifestSha256 $null `
                $OwnedServiceName $dosNameOut $null $null @() `
                $before $after 'REFUSED' 'PROCESS_CONTAINMENT_UNPROVED'
            Write-CleanupResult $result
            return $result
        }
        $containmentHash = $proofHash

        if (-not [IO.File]::Exists($DiagnosticsJournalPath)) {
            $result = New-C4CleanupRecoveryObject `
                $AttemptId $ExpectedCandidateManifestSha256 $containmentHash `
                $OwnedServiceName $dosNameOut $null $null @() `
                $before $after 'REFUSED' 'JOURNAL_MISSING'
            Write-CleanupResult $result
            return $result
        }
        $journalBytes = [IO.File]::ReadAllBytes($DiagnosticsJournalPath)
        $journal = Test-C4DiagnosticsJournalBytes -JournalBytes $journalBytes -ExpectedAttemptId $AttemptId
        if (-not $journal.Valid) {
            $result = New-C4CleanupRecoveryObject `
                $AttemptId $ExpectedCandidateManifestSha256 $containmentHash `
                $OwnedServiceName $dosNameOut $null $null @() `
                $before $after 'REFUSED' (Get-C4ClosedJournalReason $journal.Reason)
            Write-CleanupResult $result
            return $result
        }
        $header = $journal.Header
        if ($header.ownedServiceName -cne $OwnedServiceName -or
            $header.ownedDosName -cne $OwnedDosName -or
            $header.candidateManifestSha256 -cne $ExpectedCandidateManifestSha256) {
            $reason = 'TUPLE_MISMATCH'
            if ($header.ownedServiceName -cne $OwnedServiceName -or
                $header.ownedDosName -cne $OwnedDosName) {
                $reason = 'OWNED_NAME_MISMATCH'
            }
            $result = New-C4CleanupRecoveryObject `
                $AttemptId $ExpectedCandidateManifestSha256 $containmentHash `
                $OwnedServiceName $dosNameOut $journal.PrefixSha256 $journal.PrefixSha256 `
                @() $before $after 'REFUSED' $reason
            Write-CleanupResult $result
            return $result
        }
        $prefixHash = $journal.PrefixSha256
        $finalHash = $prefixHash

        $expectedVdo = Get-C4ExpectedVdoTargetFromJournal $DiagnosticsJournalPath
        $query = {
            param($Kind)
            if ($null -ne $Adapters -and $null -ne $Adapters.Query) {
                return & $Adapters.Query $Kind
            }
            if ($Kind -ceq 'service') {
                return Get-C4RealServiceQuery -ServiceName $OwnedServiceName -ExpectedBinaryFileSha256 ([string]$header.packageSetSha256)
            }
            return Get-C4RealDosQuery -DosName $OwnedDosName -ExpectedTarget $expectedVdo
        }.GetNewClosure()
        $mutate = {
            param($Operation, $Target)
            if ($null -ne $Adapters -and $null -ne $Adapters.Mutate) {
                return & $Adapters.Mutate $Operation $Target
            }
            $dosTarget = $null
            if ($Operation -ceq 'RECOVERY_DOS_LINK_REMOVE' -or $Operation -ceq 'DOS_LINK_REMOVE') {
                $look = Get-C4RealDosQuery -DosName $Target -ExpectedTarget $expectedVdo
                if ($look.Present) { $dosTarget = $look.Target }
            }
            return Invoke-C4RealMutation -Operation $Operation -Target $Target -DosTarget $dosTarget
        }.GetNewClosure()
        $script:C4RecoveryAppended = $false
        $appendRecovery = {
            param($Operation, $Target)
            if ($null -ne $Adapters -and
                $null -ne $Adapters.PSObject.Properties['SkipJournalAppend'] -and
                $Adapters.SkipJournalAppend) {
                $script:C4RecoveryAppended = $true
                return $true
            }
            $next = @($journal.Records).Count
            $prev = @($journal.Records)[$next - 1]
            $prevLine = (ConvertTo-C4CanonicalJson $prev) + "`n"
            $prevHash = Get-C4Sha256Hex (Get-C4Utf8NoBom $prevLine)
            $record = New-C4MutationAttemptRecord `
                $AttemptId $next $prevHash $Operation $Target 'RECOVERY'
            $line = (ConvertTo-C4CanonicalJson $record) + "`n"
            [IO.File]::AppendAllText($DiagnosticsJournalPath, $line, $utf8)
            if ($journal.Records -is [Collections.IList]) {
                [void]$journal.Records.Add($record)
            } else {
                $journal.Records = @($journal.Records) + @($record)
            }
            $all = [IO.File]::ReadAllBytes($DiagnosticsJournalPath)
            $script:C4LastJournalFinal = Get-C4Sha256Hex $all
            $script:C4RecoveryAppended = $true
            return $true
        }

        $serviceBefore = & $query 'service'
        $dosBefore = & $query 'dos'
        if ($serviceBefore.Ambiguous) {
            $result = New-C4CleanupRecoveryObject `
                $AttemptId $ExpectedCandidateManifestSha256 $containmentHash `
                $OwnedServiceName $dosNameOut $prefixHash $prefixHash `
                @() $before $after 'REFUSED' 'SERVICE_OWNERSHIP_AMBIGUOUS'
            Write-CleanupResult $result
            return $result
        }
        if ($dosBefore.Ambiguous) {
            $result = New-C4CleanupRecoveryObject `
                $AttemptId $ExpectedCandidateManifestSha256 $containmentHash `
                $OwnedServiceName $dosNameOut $prefixHash $prefixHash `
                @() $before $after 'REFUSED' 'DOS_OWNERSHIP_AMBIGUOUS'
            Write-CleanupResult $result
            return $result
        }
        $before = [ordered]@{
            service = (New-C4CleanupObservation -Observable:([bool]$serviceBefore.Observable) -Present:([bool]$serviceBefore.Present) -Owned:$serviceBefore.Owned -StateOrTarget $serviceBefore.State -BinaryPathSha256 $serviceBefore.BinaryPathSha256 -Service)
            dos = (New-C4CleanupObservation -Observable:([bool]$dosBefore.Observable) -Present:([bool]$dosBefore.Present) -Owned:$dosBefore.Owned -StateOrTarget $dosBefore.Target)
        }

        $status = 'PASS'
        $refusal = $null
        $journalUnreadable = $false
        $recoveryOps = @(
            @{ Operation = 'RECOVERY_DOS_LINK_REMOVE'; Target = $OwnedDosName; Kind = 'dos' },
            @{ Operation = 'RECOVERY_SERVICE_STOP'; Target = $OwnedServiceName; Kind = 'service' },
            @{ Operation = 'RECOVERY_SERVICE_DELETE'; Target = $OwnedServiceName; Kind = 'service' }
        )
        foreach ($spec in $recoveryOps) {
            [void](& $appendRecovery $spec.Operation $spec.Target)
            if ($null -ne $Adapters -and
                $null -ne $Adapters.PSObject.Properties['FailRereadBefore'] -and
                $Adapters.FailRereadBefore -ceq $spec.Operation) {
                $journalUnreadable = $true
                $status = 'FAIL'
            }
            $native = & $mutate $spec.Operation $spec.Target
            $row = [ordered]@{
                sequence = $operations.Count + $journal.Header.sequence + 1
                operation = $spec.Operation
                target = $spec.Target
                result = $native.Result
                win32Code = $native.Win32Code
            }
            if ($journal.Records.Count -gt 0) {
                $row.sequence = $journal.Records[$journal.Records.Count - 1].sequence
            }
            [void]$operations.Add([pscustomobject]$row)
            if ($native.Result -ceq 'FAILED') { $status = 'FAIL' }
            if ($null -ne $Adapters -and
                $null -ne $Adapters.PSObject.Properties['FailRereadAfter'] -and
                $Adapters.FailRereadAfter -ceq $spec.Operation) {
                $journalUnreadable = $true
                $status = 'FAIL'
            }
            if ($journalUnreadable) {
                $finalHash = $null
            } elseif ($null -ne $script:C4LastJournalFinal) {
                $finalHash = $script:C4LastJournalFinal
            }
        }

        $serviceAfter = & $query 'service'
        $dosAfter = & $query 'dos'
        $after = [ordered]@{
            service = (New-C4CleanupObservation -Observable:([bool]$serviceAfter.Observable) -Present:([bool]$serviceAfter.Present) -Owned:$serviceAfter.Owned -StateOrTarget $serviceAfter.State -BinaryPathSha256 $serviceAfter.BinaryPathSha256 -Service)
            dos = (New-C4CleanupObservation -Observable:([bool]$dosAfter.Observable) -Present:([bool]$dosAfter.Present) -Owned:$dosAfter.Owned -StateOrTarget $dosAfter.Target)
        }
        if ($serviceAfter.Ambiguous -or $dosAfter.Ambiguous) {
            $status = 'FAIL'
        }
        if ($status -ceq 'PASS') {
            if (-not $serviceAfter.Observable -or $serviceAfter.Present -or
                -not $dosAfter.Observable -or $dosAfter.Present) {
                $status = 'FAIL'
            }
        }
        if ($journalUnreadable) {
            $finalHash = $null
        } elseif ($null -eq $finalHash) {
            $finalHash = $prefixHash
        }
        $result = New-C4CleanupRecoveryObject `
            $AttemptId $ExpectedCandidateManifestSha256 $containmentHash `
            $OwnedServiceName $dosNameOut $prefixHash $finalHash `
            @($operations) $before $after $status $null
        Write-CleanupResult $result
        return $result
    } catch {
        $script:C4CleanupLastError = [string]$_
        if ($null -ne $reserved) {
            if ($script:C4RecoveryAppended) {
                $result = New-C4CleanupRecoveryObject `
                    $AttemptId $ExpectedCandidateManifestSha256 $containmentHash `
                    $OwnedServiceName $dosNameOut $prefixHash $finalHash `
                    @($operations) $before $after 'FAIL' $null
            } else {
                $result = New-C4CleanupRecoveryObject `
                    $AttemptId $ExpectedCandidateManifestSha256 $containmentHash `
                    $OwnedServiceName $dosNameOut $prefixHash $finalHash `
                    @($operations) $before $after 'REFUSED' (Get-C4ClosedJournalReason 'JOURNAL_MISSING')
            }
            try { Write-CleanupResult $result } catch { $reserved.Dispose() }
            return $result
        }
        throw
    }
}

function Save-C4JournalLine {
    param(
        [string]$Path,
        $Record,
        [switch]$CreateNew
    )

    $text = (ConvertTo-C4CanonicalJson $Record) + "`n"
    $bytes = Get-C4Utf8NoBom $text
    if ($CreateNew) {
        if ([IO.File]::Exists($Path) -and ((Get-Item -LiteralPath $Path).Length -eq 0)) {
            $mode = [IO.FileMode]::Truncate
        } else {
            $mode = [IO.FileMode]::CreateNew
        }
    } else {
        $mode = [IO.FileMode]::Append
    }
    $stream = [IO.File]::Open($Path, $mode, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        $flushToDisk = $stream.GetType().GetMethod('Flush', [type[]]@([bool]))
        if ($null -ne $flushToDisk) {
            [void]$flushToDisk.Invoke($stream, @($true))
        }
    } finally {
        $stream.Dispose()
    }
    return Get-C4Sha256Hex $bytes
}

function New-C4SidecarBinding {
    param(
        [string]$SourceCommit,
        [string]$SourceTree,
        [string]$CandidateManifestSha256,
        [string]$PackageSetSha256,
        [string]$ArtifactSetSha256,
        [string]$ExpectedHarnessSha256,
        [string]$ActualHarnessSha256
    )

    return [ordered]@{
        sourceCommit = $SourceCommit
        sourceTree = $SourceTree
        candidateManifestSha256 = $CandidateManifestSha256
        profile = 'win10-x64'
        packageSetSha256 = $PackageSetSha256
        expectedArtifactSha256 = $ArtifactSetSha256
        actualArtifactSha256 = $ArtifactSetSha256
        expectedHarnessSha256 = $ExpectedHarnessSha256
        actualHarnessSha256 = $ActualHarnessSha256
    }
}

function New-C4NotRunProbe {
    param([string]$Name)
    return [pscustomobject]@{
        name = $Name
        outcome = 'NOT RUN'
        expected = [pscustomobject]@{ kind = 'facts'; values = [pscustomobject]@{ observed = $true } }
        actual = $null
    }
}

function Read-C4PipeFrame {
    param([IntPtr]$Handle, [int]$TimeoutMilliseconds)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    $header = New-Object byte[] 4
    $filled = 0
    while ($filled -lt 4) {
        if ([DateTime]::UtcNow -gt $deadline) { return $null }
        $chunk = New-Object byte[] (4 - $filled)
        $got = 0
        $ok = [FsringC4EvidenceNative]::ReadFile($Handle, $chunk, $chunk.Length, [ref]$got, [IntPtr]::Zero)
        if (-not $ok -or $got -le 0) { return $null }
        [Array]::Copy($chunk, 0, $header, $filled, $got)
        $filled += $got
    }
    $length = [BitConverter]::ToUInt32($header, 0)
    if ($length -lt $script:C4FrameMin -or $length -gt $script:C4FrameMax) { return $null }
    $payload = New-Object byte[] $length
    $filled = 0
    while ($filled -lt $length) {
        if ([DateTime]::UtcNow -gt $deadline) { return $null }
        $chunk = New-Object byte[] ($length - $filled)
        $got = 0
        $ok = [FsringC4EvidenceNative]::ReadFile($Handle, $chunk, $chunk.Length, [ref]$got, [IntPtr]::Zero)
        if (-not $ok -or $got -le 0) { return $null }
        [Array]::Copy($chunk, 0, $payload, $filled, $got)
        $filled += $got
    }
    $text = (New-Object System.Text.UTF8Encoding $false, $true).GetString($payload)
    return (Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $text)
}

function Write-C4PipeFrame {
    param([IntPtr]$Handle, $Frame)
    $payload = (ConvertTo-C4CanonicalJson $Frame)
    $bytes = Get-C4Utf8NoBom $payload
    $len = [BitConverter]::GetBytes([uint32]$bytes.Length)
    $wrote = 0
    [void][FsringC4EvidenceNative]::ReadFile
    $safe = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($Handle, $false)
    $stream = New-Object IO.FileStream($safe, [IO.FileAccess]::Write)
    try {
        $stream.Write($len, 0, 4)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
    } finally {
        $stream.Dispose()
    }
}

function Start-C4ContainedLiveWorker {
    param(
        [string]$HarnessPath,
        [string]$WorkingDirectory,
        [string]$Nonce,
        [int]$TimeoutMilliseconds = 120000
    )
    $sync = [hashtable]::Synchronized(@{
        ProcessId = 0
        Staged = $null
        Live = $null
        RunMount = $null
        Error = $null
        Job = [IntPtr]::Zero
        Process = [IntPtr]::Zero
    })
    $pidReady = New-Object System.Threading.ManualResetEventSlim $false
    $resumeGate = New-Object System.Threading.ManualResetEventSlim $false
    $stagedReady = New-Object System.Threading.ManualResetEventSlim $false
    $liveReady = New-Object System.Threading.ManualResetEventSlim $false
    $runMountReady = New-Object System.Threading.ManualResetEventSlim $false
    $finished = New-Object System.Threading.ManualResetEventSlim $false
    $capture = Join-Path $env:TEMP ('fsring-c4-live-cap-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($capture)
    $evidence = Join-Path $PSScriptRoot 'invoke_c4_evidence.ps1'
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $runspace
    [void]$ps.AddScript({
        param($Sync, $PidReady, $ResumeGate, $StagedReady, $LiveReady, $RunMountReady, $Finished, $Harness, $WorkDir, $NonceValue, $Capture, $Timeout, $EvidencePath)
        function Read-C4PipeFrameLocal {
            param([IntPtr]$Handle, [int]$TimeoutMilliseconds)
            $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
            $header = New-Object byte[] 4
            $filled = 0
            while ($filled -lt 4) {
                if ([DateTime]::UtcNow -gt $deadline) { return $null }
                $chunk = New-Object byte[] (4 - $filled)
                $got = 0
                $ok = [FsringC4EvidenceNative]::ReadFile($Handle, $chunk, $chunk.Length, [ref]$got, [IntPtr]::Zero)
                if (-not $ok -or $got -le 0) { return $null }
                [Array]::Copy($chunk, 0, $header, $filled, $got)
                $filled += $got
            }
            $length = [BitConverter]::ToUInt32($header, 0)
            if ($length -lt 2 -or $length -gt 262144) { return $null }
            $payload = New-Object byte[] $length
            $filled = 0
            while ($filled -lt $length) {
                if ([DateTime]::UtcNow -gt $deadline) { return $null }
                $chunk = New-Object byte[] ($length - $filled)
                $got = 0
                $ok = [FsringC4EvidenceNative]::ReadFile($Handle, $chunk, $chunk.Length, [ref]$got, [IntPtr]::Zero)
                if (-not $ok -or $got -le 0) { return $null }
                [Array]::Copy($chunk, 0, $payload, $filled, $got)
                $filled += $got
            }
            $text = (New-Object System.Text.UTF8Encoding $false, $true).GetString($payload)
            return (Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $text)
        }
        try {
            . $EvidencePath
            $out = Join-Path $Capture 'stdout.bin'
            $err = Join-Path $Capture 'stderr.bin'
            $exit = Join-Path $Capture 'exit.json'
            Invoke-C4EvidenceProcess -Executable $Harness `
                -Arguments @('--c4-live-worker', '--nonce', $NonceValue) `
                -WorkingDirectory $WorkDir `
                -TimeoutMilliseconds $Timeout `
                -StdoutPath $out -StderrPath $err -ExitPath $exit -ExitFormat CanonicalJson `
                -BeforeResume {
                    param($info)
                    $Sync.ProcessId = [int]$info.ProcessId
                    $Sync.Job = [FsringC4EvidenceNative]::DuplicateSame($info.Job)
                    $Sync.Process = [FsringC4EvidenceNative]::DuplicateSame($info.Process)
                    [void]$PidReady.Set()
                    [void]$ResumeGate.Wait()
                }.GetNewClosure() `
                -DuplexHandler {
                    param($duplex)
                    $staged = Read-C4PipeFrameLocal $duplex.StdoutRead 30000
                    $Sync.Staged = $staged
                    [void]$StagedReady.Set()
                    [void]$RunMountReady.Wait()
                    if ($null -ne $Sync.RunMount) {
                        $payload = [Text.Encoding]::UTF8.GetBytes([string]$Sync.RunMount)
                        $len = [BitConverter]::GetBytes([uint32]$payload.Length)
                        $safe = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($duplex.StdinWrite, $false)
                        $stream = New-Object IO.FileStream($safe, [IO.FileAccess]::Write)
                        try {
                            $stream.Write($len, 0, 4)
                            $stream.Write($payload, 0, $payload.Length)
                            $stream.Flush()
                        } finally {
                            $stream.Dispose()
                        }
                    }
                    $live = Read-C4PipeFrameLocal $duplex.StdoutRead 30000
                    $Sync.Live = $live
                    [void]$LiveReady.Set()
                }.GetNewClosure()
        } catch {
            $Sync.Error = [string]$_
            if ($Sync.ProcessId -le 0) { $Sync.ProcessId = 0 }
            [void]$PidReady.Set()
            [void]$StagedReady.Set()
            [void]$LiveReady.Set()
        } finally {
            [void]$Finished.Set()
        }
    }).AddArgument($sync).AddArgument($pidReady).AddArgument($resumeGate).AddArgument($stagedReady).AddArgument($liveReady).AddArgument($runMountReady).AddArgument($finished).AddArgument($HarnessPath).AddArgument($WorkingDirectory).AddArgument($Nonce).AddArgument($capture).AddArgument($TimeoutMilliseconds).AddArgument($evidence)
    $handle = $ps.BeginInvoke()
    [void]$pidReady.Wait(30000)
    return [pscustomobject]@{
        ProcessId = [int]$sync.ProcessId
        Arguments = @('--c4-live-worker', '--nonce', $Nonce)
        Sync = $sync
        PidReady = $pidReady
        ResumeGate = $resumeGate
        StagedReady = $stagedReady
        LiveReady = $liveReady
        RunMountReady = $runMountReady
        Finished = $finished
        PowerShell = $ps
        Handle = $handle
        Capture = $capture
        Runspace = $runspace
        Job = $sync.Job
        Process = $sync.Process
        MainThreadResumed = $false
    }
}

function Invoke-C4LiveWorkflow {
    param(
        [string]$AttemptId,
        [string]$CandidateManifestPath,
        [string]$ExpectedCandidateManifestSha256,
        [string]$ExpectedHarnessSha256,
        [string]$ActualHarnessSha256,
        [string]$EvidenceDirectory,
        [string]$HarnessPath,
        [string]$WorkingDirectory,
        [string]$SourceCommit,
        [string]$SourceTree,
        [string]$PackageSetSha256,
        [string]$ArtifactSetSha256,
        [string]$SysPath,
        [string]$ServiceName,
        [string]$DosName,
        $Adapters
    )

    if (-not [string]::IsNullOrWhiteSpace($ServiceName) -or
        -not [string]::IsNullOrWhiteSpace($DosName)) {
        throw 'C4 live rejects caller service/DOS name overrides'
    }
    if (-not (Test-C4AttemptId $AttemptId)) {
        throw 'AttemptId must be lowercase GUID-N.'
    }

    $ownedService = Get-C4OwnedServiceName $AttemptId
    $mutationStarted = $false
    $mutations = New-Object System.Collections.ArrayList
    $emitted = @{}
    $reasons = New-Object System.Collections.ArrayList
    $probesByIndex = New-Object object[] 27
    $identity = $null
    $nonce = $null
    $ownedDos = $null
    $workerPid = 0
    $overall = 'NOT RUN'
    $launchArgs = $null
    $workerContained = $false

    $script:C4LiveNativeSession = $null
    $script:C4LiveDosTarget = $null
    $script:C4LiveNonce = $null
    $nonceValue = ([Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')).Substring(0, 32).ToUpperInvariant()
    $mutate = {
        param($Operation, $Target)
        if ($null -ne $Adapters -and $null -ne $Adapters.Mutate) {
            return & $Adapters.Mutate $Operation $Target
        }
        return Invoke-C4RealMutation -Operation $Operation -Target $Target -SysPath $SysPath -DosTarget $script:C4LiveDosTarget
    }.GetNewClosure()
    $startWorker = {
        if ($null -ne $Adapters -and $null -ne $Adapters.StartWorker) {
            return & $Adapters.StartWorker
        }
        if ([string]::IsNullOrWhiteSpace($HarnessPath) -or -not [IO.File]::Exists($HarnessPath)) {
            throw 'C4 live harness path is missing'
        }
        $session = Start-C4ContainedLiveWorker -HarnessPath $HarnessPath -WorkingDirectory $WorkingDirectory -Nonce $nonceValue
        $script:C4LiveNativeSession = $session
        if ([int]$session.ProcessId -le 0) {
            throw ('C4 live worker failed to start: ' + [string]$session.Sync.Error)
        }
        return [pscustomobject]@{
            ProcessId = [int]$session.ProcessId
            Arguments = @($session.Arguments)
        }
    }.GetNewClosure()
    $readFrame = {
        param([string]$Stage)
        if ($null -ne $Adapters -and $null -ne $Adapters.ReadFrame) {
            return & $Adapters.ReadFrame $Stage
        }
        $session = $script:C4LiveNativeSession
        if ($null -eq $session) { return $null }
        if ($Stage -ceq 'STAGED') {
            [void]$session.StagedReady.Wait(30000)
            return $session.Sync.Staged
        }
        if ($Stage -ceq 'LIVE_CLEANED') {
            [void]$session.LiveReady.Wait(120000)
            return $session.Sync.Live
        }
        return $null
    }
    $writeFrame = {
        param($Frame)
        if ($null -ne $Adapters -and $null -ne $Adapters.WriteFrame) {
            return & $Adapters.WriteFrame $Frame
        }
        $session = $script:C4LiveNativeSession
        if ($null -eq $session) { return $false }
        $session.Sync.RunMount = (ConvertTo-C4CanonicalJson $Frame)
        [void]$session.RunMountReady.Set()
        return $true
    }
    $containWorker = {
        if ($null -ne $Adapters -and $null -ne $Adapters.ContainWorker) {
            return & $Adapters.ContainWorker
        }
        $session = $script:C4LiveNativeSession
        if ($null -eq $session) { return [pscustomobject]@{ Success = $true } }
        $alreadyResumed = $false
        if ($null -ne $session.PSObject.Properties['MainThreadResumed']) {
            $alreadyResumed = [bool]$session.MainThreadResumed
        }
        $job = [IntPtr]::Zero
        $process = [IntPtr]::Zero
        if ($null -ne $session.PSObject.Properties['Job'] -and $null -ne $session.Job) {
            $job = [IntPtr]$session.Job
        }
        if ($null -ne $session.PSObject.Properties['Process'] -and $null -ne $session.Process) {
            $process = [IntPtr]$session.Process
        }
        if ($job -ne [IntPtr]::Zero) {
            [void][FsringC4EvidenceNative]::TerminateJobObject($job, 1)
        }
        if ($process -ne [IntPtr]::Zero) {
            [void][FsringC4EvidenceNative]::TerminateProcess($process, 1)
        } elseif ([int]$session.ProcessId -gt 0) {
            $opened = [FsringC4EvidenceNative]::OpenProcess(
                ([FsringC4EvidenceNative]::ProcessTerminate -bor [FsringC4EvidenceNative]::ProcessSynchronize),
                $false,
                [uint32]$session.ProcessId
            )
            if ($opened -ne [IntPtr]::Zero) {
                [void][FsringC4EvidenceNative]::TerminateProcess($opened, 1)
                $process = $opened
            }
        }
        $treeExited = Wait-C4OwnedProcessTree -Job $job -Process $process -TimeoutMilliseconds 5000
        if (-not $alreadyResumed) {
            try { [void]$session.ResumeGate.Set() } catch {}
        }
        try { [void]$session.RunMountReady.Set() } catch {}
        try { [void]$session.StagedReady.Set() } catch {}
        try { [void]$session.LiveReady.Set() } catch {}
        $helperFinished = $false
        if ($null -ne $session.Finished) {
            $helperFinished = [bool]$session.Finished.Wait(120000)
        }
        try { $session.PowerShell.Stop() } catch {}
        try { $session.PowerShell.EndInvoke($session.Handle) } catch {}
        try { $session.PowerShell.Dispose() } catch {}
        try { $session.Runspace.Close() } catch {}
        if ($job -ne [IntPtr]::Zero) {
            [void][FsringC4EvidenceNative]::CloseHandle($job)
        }
        if ($process -ne [IntPtr]::Zero) {
            [void][FsringC4EvidenceNative]::CloseHandle($process)
        }
        Remove-Item -LiteralPath $session.Capture -Recurse -Force -ErrorAction SilentlyContinue
        $script:C4LiveNativeSession = $null
        return [pscustomobject]@{ Success = [bool]$treeExited }
    }
    $postUnload = {
        param($Root, $Vdo, $Dos)
        if ($null -ne $Adapters -and $null -ne $Adapters.PostUnload) {
            return & $Adapters.PostUnload $Root $Vdo $Dos
        }
        if ([string]::IsNullOrWhiteSpace($HarnessPath) -or -not [IO.File]::Exists($HarnessPath)) {
            return $null
        }
        $dir = Join-Path $env:TEMP ('fsring-c4-post-' + [Guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($dir)
        try {
            $out = Join-Path $dir 'stdout.bin'
            $err = Join-Path $dir 'stderr.bin'
            $exit = Join-Path $dir 'exit.json'
            $args = @(
                '--c4-post-unload',
                '--nonce', $script:C4LiveNonce,
                '--boot-lo', ('{0:X16}' -f [uint64](Get-C4HexValue $Root.bootInstanceId.lo)),
                '--boot-hi', ('{0:X16}' -f [uint64](Get-C4HexValue $Root.bootInstanceId.hi)),
                '--mount-lo', ('{0:X16}' -f [uint64](Get-C4HexValue $Root.mountId.lo)),
                '--mount-hi', ('{0:X16}' -f [uint64](Get-C4HexValue $Root.mountId.hi)),
                '--session-epoch', ('{0:X16}' -f [uint64](Get-C4HexValue $Root.sessionEpoch)),
                '--vdo-native-name', [string]$Vdo,
                '--dos-name', [string]$Dos
            )
            Invoke-C4EvidenceProcess -Executable $HarnessPath -Arguments $args `
                -WorkingDirectory $WorkingDirectory -TimeoutMilliseconds 30000 `
                -StdoutPath $out -StderrPath $err -ExitPath $exit -ExitFormat CanonicalJson
            if (-not [IO.File]::Exists($out) -or ((Get-Item -LiteralPath $out).Length -lt 6)) {
                return $null
            }
            $ms = New-Object IO.MemoryStream (,[IO.File]::ReadAllBytes($out))
            $parsed = Read-C4Frame $ms 1000
            if ($parsed.Valid) { return $parsed.Frame }
            return $null
        } finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }.GetNewClosure()
    $queryDosWin32 = {
        if ($null -ne $Adapters -and $null -ne $Adapters.DosLinkQueryWin32) {
            return [uint32]$Adapters.DosLinkQueryWin32
        }
        if ([string]::IsNullOrWhiteSpace($ownedDos)) { return [uint32]2 }
        $q = Get-C4RealDosQuery -DosName $ownedDos -ExpectedTarget $script:C4LiveDosTarget
        return [uint32]$q.Win32Code
    }

    $addSlice = {
        param($Slice)
        foreach ($probe in @($Slice)) {
            $index = [array]::IndexOf($script:C4ProbeRoster, [string]$probe.name)
            if ($index -ge 0) {
                $probesByIndex[$index] = $probe
            }
        }
    }

    try {
        if (-not [string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
            if (-not [IO.Directory]::Exists($EvidenceDirectory)) {
                throw 'C4 live EvidenceDirectory must exist and be empty.'
            }
            $existing = @(Get-ChildItem -LiteralPath $EvidenceDirectory -Force)
            if ($existing.Count -ne 0) {
                throw 'C4 live EvidenceDirectory must be empty.'
            }
            foreach ($name in @(Get-C4LiveSidecarNames)) {
                $sidecar = Join-Path $EvidenceDirectory $name
                $created = [IO.File]::Open(
                    $sidecar,
                    [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write,
                    [IO.FileShare]::Read
                )
                $created.Dispose()
            }
        }

        $started = & $startWorker
        $workerPid = [int]$started.ProcessId
        if ($workerPid -le 0) {
            throw 'C4 live worker process id is not positive'
        }
        $ownedDos = Get-C4OwnedDosName $workerPid $AttemptId
        $launchArgs = @($started.Arguments)
        if ($launchArgs.Count -gt 0 -and ($launchArgs -notcontains '--c4-live-worker')) {
            throw 'C4 live worker must be launched with --c4-live-worker'
        }

        $measuredHarness = $ActualHarnessSha256
        if ([string]::IsNullOrWhiteSpace($measuredHarness)) {
            $measuredHarness = Get-C4FileSha256Lower $HarnessPath
            if ($null -eq $measuredHarness) {
                $measuredHarness = Get-C4Sha256Hex ([byte[]](New-Object byte[] 0))
            }
        }
        $binding = New-C4SidecarBinding `
            $SourceCommit $SourceTree $ExpectedCandidateManifestSha256 `
            $PackageSetSha256 $ArtifactSetSha256 `
            $ExpectedHarnessSha256 $measuredHarness
        $journalPath = $null
        $etwPath = $null
        $framesPath = $null
        $cleanupPath = $null
        if (-not [string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
            $journalPath = Join-Path $EvidenceDirectory 'diagnostics.sidecar.jsonl'
            $etwPath = Join-Path $EvidenceDirectory 'etw.sidecar.jsonl'
            $framesPath = Join-Path $EvidenceDirectory 'worker-frames.sidecar.bin'
            $cleanupPath = Join-Path $EvidenceDirectory 'cleanup.sidecar.json'
        }

        $header = New-C4DiagnosticsHeader `
            $AttemptId $SourceCommit $SourceTree $ExpectedCandidateManifestSha256 `
            $PackageSetSha256 $ExpectedHarnessSha256 $workerPid $ownedService $ownedDos `
            ('0' * 64)
        if ($null -ne $journalPath) {
            $null = Save-C4JournalLine -Path $journalPath -Record $header -CreateNew
        }
        $previousHash = Get-C4Sha256Hex (Get-C4Utf8NoBom ((ConvertTo-C4CanonicalJson $header) + "`n"))
        $sequence = 0

        $liveOps = @(
            @{ Operation = 'SERVICE_CREATE'; Target = $ownedService },
            @{ Operation = 'SERVICE_START_DRIVER_LOAD'; Target = $ownedService }
        )
        foreach ($spec in $liveOps) {
            $sequence++
            $record = New-C4MutationAttemptRecord $AttemptId $sequence $previousHash $spec.Operation $spec.Target 'LIVE'
            if ($null -ne $journalPath) {
                $previousHash = Save-C4JournalLine -Path $journalPath -Record $record
            } else {
                $previousHash = Get-C4Sha256Hex (Get-C4Utf8NoBom ((ConvertTo-C4CanonicalJson $record) + "`n"))
            }
            $mutationStarted = $true
            [void]$mutations.Add($spec.Operation)
            $native = & $mutate $spec.Operation $spec.Target
            if ($null -eq $native -or -not $native.Success) {
                throw ("mutation {0} failed" -f $spec.Operation)
            }
        }
        if ($null -ne $script:C4LiveNativeSession) {
            $script:C4LiveNativeSession.MainThreadResumed = $true
            [void]$script:C4LiveNativeSession.ResumeGate.Set()
        }

        $staged = & $readFrame 'STAGED'
        if ($null -eq $staged) { throw 'STAGED frame is absent' }
        $nonce = [string]$staged.nonce
        $script:C4LiveNonce = $nonce
        $stagedCheck = Test-C4FrameContinuity $staged 1 'STAGED' $nonce $null $null $null $null
        if (-not $stagedCheck.Valid) {
            $emitted = Add-C4InfrastructureReason $emitted 'LIVE_STAGED' 'runner' 2
            throw $stagedCheck.Reason
        }
        $identity = $staged.rootIdentity
        $script:C4LiveDosTarget = [string]$staged.vdoNativeName
        & $addSlice $staged.probes
        if ($null -ne $framesPath) {
            $fs = [IO.File]::Open($framesPath, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            try { [void](Write-C4Frame $fs (ConvertTo-C4CanonicalJson $staged)) } finally { $fs.Dispose() }
        }

        $sequence++
        $dosRecord = New-C4MutationAttemptRecord $AttemptId $sequence $previousHash 'DOS_LINK_CREATE' $ownedDos 'LIVE'
        if ($null -ne $journalPath) {
            $previousHash = Save-C4JournalLine -Path $journalPath -Record $dosRecord
        } else {
            $previousHash = Get-C4Sha256Hex (Get-C4Utf8NoBom ((ConvertTo-C4CanonicalJson $dosRecord) + "`n"))
        }
        [void]$mutations.Add('DOS_LINK_CREATE')
        $native = & $mutate 'DOS_LINK_CREATE' $ownedDos
        if ($null -eq $native -or -not $native.Success) {
            $emitted = Add-C4InfrastructureReason $emitted 'DOS_LINK_CREATE' 'win32' 1
            throw 'DOS_LINK_CREATE failed'
        }

        $runMount = [pscustomobject]@{
            schema = $script:C4WorkerSchema
            sequence = 2
            stage = 'RUN_MOUNT'
            nonce = $nonce
            rootIdentity = $identity
            vdoNativeName = [string]$staged.vdoNativeName
            dosName = $ownedDos
        }
        [void](& $writeFrame $runMount)
        $sequence++
        $traffic = New-C4MutationAttemptRecord $AttemptId $sequence $previousHash 'SMOKE_TRAFFIC' 'BOUND_SMOKE_WORKFLOW' 'LIVE'
        if ($null -ne $journalPath) {
            $previousHash = Save-C4JournalLine -Path $journalPath -Record $traffic
        } else {
            $previousHash = Get-C4Sha256Hex (Get-C4Utf8NoBom ((ConvertTo-C4CanonicalJson $traffic) + "`n"))
        }
        [void]$mutations.Add('SMOKE_TRAFFIC')

        $live = & $readFrame 'LIVE_CLEANED'
        $liveCheck = Test-C4FrameContinuity $live 3 'LIVE_CLEANED' $nonce $identity $staged.disposableIdentity $staged.vdoNativeName $ownedDos
        if (-not $liveCheck.Valid) {
            $emitted = Add-C4InfrastructureReason $emitted 'LIVE_CLEANED' 'runner' 2
            throw $liveCheck.Reason
        }
        & $addSlice $live.probes
        if ($null -ne $framesPath) {
            $fs = [IO.File]::Open($framesPath, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            try { [void](Write-C4Frame $fs (ConvertTo-C4CanonicalJson $live)) } finally { $fs.Dispose() }
        }

        $contained = & $containWorker
        $workerContained = $true
        if ($null -eq $contained -or -not $contained.Success) {
            $emitted = Add-C4InfrastructureReason $emitted 'LIVE_CONTAINMENT' 'runner' 1
            throw 'worker containment failed'
        }

        foreach ($spec in @(
                @{ Operation = 'DOS_LINK_REMOVE'; Target = $ownedDos; Stage = 'DOS_LINK_REMOVE' },
                @{ Operation = 'SERVICE_STOP'; Target = $ownedService; Stage = 'SCM_CLEANUP' },
                @{ Operation = 'SERVICE_DELETE'; Target = $ownedService; Stage = 'SCM_CLEANUP' }
            )) {
            $sequence++
            $record = New-C4MutationAttemptRecord $AttemptId $sequence $previousHash $spec.Operation $spec.Target 'LIVE'
            if ($null -ne $journalPath) {
                $previousHash = Save-C4JournalLine -Path $journalPath -Record $record
            } else {
                $previousHash = Get-C4Sha256Hex (Get-C4Utf8NoBom ((ConvertTo-C4CanonicalJson $record) + "`n"))
            }
            [void]$mutations.Add($spec.Operation)
            $native = & $mutate $spec.Operation $spec.Target
            if ($null -eq $native -or -not $native.Success) {
                $emitted = Add-C4InfrastructureReason $emitted $spec.Stage 'win32' 1
                throw ("mutation {0} failed" -f $spec.Operation)
            }
        }

        $post = & $postUnload $identity $staged.vdoNativeName $ownedDos
        $postCheck = Test-C4FrameContinuity $post 4 'POST_UNLOAD' $nonce $identity $null $staged.vdoNativeName $ownedDos
        if (-not $postCheck.Valid) {
            $emitted = Add-C4InfrastructureReason $emitted 'POST_UNLOAD' 'runner' 2
            throw $postCheck.Reason
        }
        & $addSlice $post.probes

        $dosQuery = & $queryDosWin32
        $dosHex = if ($dosQuery -is [string] -and $dosQuery.StartsWith('0x')) {
            $dosQuery
        } else {
            '0x{0:X8}' -f [uint32]$dosQuery
        }
        $merged = Complete-C4PostUnloadEvidence `
            $live.unloadSeed $post.unloadObservation $true $dosHex
        $unloadIndex = [array]::IndexOf($script:C4ProbeRoster, $script:C4RunnerOnlyProbe)
        $expectedUnload = Get-C4IndependentExpectedOracle $script:C4RunnerOnlyProbe $identity
        if (-not $merged.Valid) {
            $probesByIndex[$unloadIndex] = [pscustomobject]@{
                name = $script:C4RunnerOnlyProbe
                outcome = 'NOT RUN'
                expected = $expectedUnload
                actual = $null
            }
            throw 'unload-transients merge failed'
        }
        $actualUnload = [pscustomobject]@{ kind = 'facts'; values = $merged.Values }
        $unloadPass = Test-C4OracleEqual $expectedUnload $actualUnload
        $probesByIndex[$unloadIndex] = [pscustomobject]@{
            name = $script:C4RunnerOnlyProbe
            outcome = $(if ($unloadPass) { 'PASS' } else { 'FAIL' })
            expected = $expectedUnload
            actual = $actualUnload
        }
        if (-not $unloadPass) {
            throw 'unload-transients actual disagreed with the independent oracle'
        }

        if ($null -ne $etwPath) {
            $etwLines = New-Object System.Collections.ArrayList
            foreach ($frame in @($staged, $live, $post)) {
                if ($null -eq $frame) { continue }
                $evProp = $frame.PSObject.Properties['events']
                if ($null -eq $evProp -or $null -eq $frame.events) { continue }
                foreach ($event in @($frame.events)) {
                    $record = [ordered]@{
                        provider = '{76A354FE-986E-4968-B41E-BB1209D57157}'
                        name = [string]$event.name
                        id = [int]$event.id
                        version = [int]$event.version
                        keyword = [string]$event.keyword
                        identity = $event.identity
                        reason = [int]$event.reason
                    }
                    [void]$etwLines.Add((ConvertTo-C4CanonicalJson $record) + "`n")
                }
            }
            if ($etwLines.Count -gt 0) {
                [IO.File]::WriteAllBytes($etwPath, (Get-C4Utf8NoBom (-join $etwLines)))
            }
        }

        if ($null -ne $cleanupPath) {
            $cleanupObject = [ordered]@{}
            foreach ($key in @($binding.Keys)) { $cleanupObject[$key] = $binding[$key] }
            $cleanupObject['ownedServiceName'] = $ownedService
            $cleanupObject['ownedDosName'] = $ownedDos
            $cleanupObject['mutations'] = @($mutations)
            [IO.File]::WriteAllBytes($cleanupPath, (Get-C4Utf8NoBom ((ConvertTo-C4CanonicalJson $cleanupObject) + "`n")))
        }
        $overall = 'PASS'
    } catch {
        [void]$reasons.Add([string]$_)
        if ($mutationStarted) {
            $overall = 'FAIL'
            if ($emitted.Count -eq 0) {
                $emitted = Add-C4InfrastructureReason $emitted 'LIVE_COMMAND' 'runner' 1
            }
        } else {
            $overall = 'NOT RUN'
        }
    } finally {
        if ($workerPid -gt 0 -and -not $workerContained) {
            try { $null = & $containWorker } catch {}
            $workerContained = $true
        }
    }

    for ($index = 0; $index -lt 27; $index++) {
        if ($null -eq $probesByIndex[$index]) {
            $probesByIndex[$index] = New-C4NotRunProbe $script:C4ProbeRoster[$index]
        }
    }
    $infra = @(Get-C4InfrastructureReasons $emitted)
    $allReasons = @($infra) + @($reasons)
    $reportProbes = @($probesByIndex)
    $passed = 0
    $notRun = 0
    $mismatch = $false
    foreach ($probe in $reportProbes) {
        if ($null -eq $probe.actual) {
            $notRun++
            continue
        }
        if (Test-C4OracleEqual $probe.expected $probe.actual) {
            $passed++
        } else {
            $mismatch = $true
        }
    }
    if ($allReasons.Count -ne 0) { $mismatch = $true }
    if ($passed -eq 27 -and $allReasons.Count -eq 0 -and -not $mismatch) {
        $overall = 'PASS'
    } elseif ($mutationStarted -or $mismatch -or ($null -ne $identity -and $notRun -ne 0)) {
        $overall = 'FAIL'
    } else {
        $overall = 'NOT RUN'
    }
    $report = [ordered]@{
        schema = $script:C4HarnessSchemaV2
        overall = $overall
        exitCode = $(switch ($overall) { 'PASS' { 0 } 'FAIL' { 1 } default { 2 } })
        identity = $identity
        probes = $reportProbes
        reasons = @($allReasons)
    }

    return [pscustomobject]@{
        Report = $report
        Json = ((ConvertTo-C4CanonicalJson $report) + "`n")
        OwnedServiceName = $ownedService
        OwnedDosName = $ownedDos
        WorkerProcessId = $workerPid
        MutationStarted = $mutationStarted
        Mutations = @($mutations)
        ExitCode = [int]$report.exitCode
    }
}

function Test-ServiceInspectionEligible {
    param($Facts)

    return (
        $Facts.hostWindows -and
        $Facts.osVersionQueryValid -and
        $Facts.windows10OrLater -and
        $Facts.hostX64
    )
}

function Get-PreflightDecision {
    param($Facts)

    $fatal = New-Object System.Collections.ArrayList
    $notRun = New-Object System.Collections.ArrayList
    if (-not $Facts.pathResolutionValid) {
        [void]$fatal.Add('Package or harness path could not be resolved.')
    }
    if (-not $Facts.packageDirectoryPresent) {
        [void]$fatal.Add('Exact package directory is absent.')
    }
    if (-not $Facts.infPresent) {
        [void]$fatal.Add('Exact package INF is absent.')
    }
    if (-not $Facts.sysPresent) {
        [void]$fatal.Add('Exact package SYS is absent.')
    }
    if (-not $Facts.catPresent) {
        [void]$fatal.Add('Exact package CAT is absent.')
    }
    if (-not $Facts.harnessPresent) {
        [void]$fatal.Add('Exact smoke harness is absent.')
    } elseif (-not $Facts.harnessPinValid) {
        [void]$fatal.Add(
            'Exact smoke harness identity pin is invalid.'
        )
    }
    if (-not $Facts.verifierScriptPresent -or -not $Facts.powershellPresent) {
        [void]$fatal.Add('Exact repository package verifier cannot be invoked.')
    }
    if ($Facts.sysPresent -and -not $Facts.sysAmd64) {
        [void]$fatal.Add('Package SYS PE machine is not AMD64.')
    }
    if ($Facts.packageDirectoryPresent -and $Facts.infPresent -and $Facts.sysPresent -and
        $Facts.catPresent -and $Facts.verifierScriptPresent -and $Facts.powershellPresent) {
        if (-not $Facts.verifierValid) {
            [void]$fatal.Add('Package verifier output or exit was invalid.')
        } elseif ($Facts.verifierOverall -cne 'PASS') {
            [void]$fatal.Add('Package verifier did not PASS.')
        }
    }
    if (Test-ServiceInspectionEligible $Facts) {
        if (-not $Facts.scPresent -or -not $Facts.serviceChecked) {
            [void]$fatal.Add('Existing fsring_fsd service state could not be inspected.')
        } elseif (-not $Facts.serviceAbsent) {
            [void]$fatal.Add('An fsring_fsd service already exists; it is not owned by this run.')
        }
    }
    if ($fatal.Count -ne 0) {
        return [pscustomobject]@{
            Overall = 'FAIL'
            Runnable = $false
            Reasons = @($fatal)
        }
    }

    if (-not $Facts.hostWindows) {
        [void]$notRun.Add('Live driver smoke requires Windows.')
    } elseif (-not $Facts.osVersionQueryValid) {
        [void]$notRun.Add('The real Windows version could not be validated through RtlGetVersion.')
    } elseif (-not $Facts.windows10OrLater) {
        [void]$notRun.Add('Live driver smoke requires Windows 10 or later.')
    }
    if ($Facts.hostWindows -and -not $Facts.hostX64) {
        [void]$notRun.Add('Live driver smoke requires native AMD64 architecture and a 64-bit process.')
    }
    if (-not $Facts.elevated) {
        [void]$notRun.Add('Live driver smoke requires an elevated administrator token.')
    }
    if ($Facts.hostWindows -and -not $Facts.codeIntegrityQueryValid) {
        [void]$notRun.Add('The active Code Integrity state could not be validated.')
    } elseif ($Facts.hostWindows -and -not $Facts.codeIntegrityEnabled) {
        [void]$notRun.Add('Kernel-mode Code Integrity is not active.')
    }
    if ($Facts.hostWindows -and -not $Facts.bootEnvironmentQueryValid) {
        [void]$notRun.Add('The current boot environment identity could not be validated.')
    }
    $bcdEligible = (
        $Facts.hostWindows -and
        $Facts.osVersionQueryValid -and
        $Facts.windows10OrLater -and
        $Facts.hostX64 -and
        $Facts.elevated -and
        $Facts.bootEnvironmentQueryValid
    )
    if ($bcdEligible) {
        if (-not $Facts.bootConfigurationAttempted -or
            -not $Facts.bootConfigurationValid) {
            [void]$notRun.Add('The read-only system BCD TESTSIGNING state could not be validated.')
        } elseif ($Facts.signingState -cne 'ENABLED' -or
            $Facts.rebootRequired -or
            -not $Facts.testSigningActive -or
            -not $Facts.testSigningConfigured) {
            [void]$notRun.Add(
                "Active/configured TESTSIGNING is not ready: $($Facts.signingState)."
            )
        }
    }
    if ($Facts.verifierValid -and $Facts.verifierOverall -ceq 'PASS' -and -not $Facts.trustReady) {
        [void]$notRun.Add('Package integrity passed, but trustReady is false; no trust policy is changed.')
    }
    if ($notRun.Count -ne 0) {
        return [pscustomobject]@{
            Overall = 'NOT RUN'
            Runnable = $false
            Reasons = @($notRun)
        }
    }
    return [pscustomobject]@{
        Overall = 'PASS'
        Runnable = $true
        Reasons = @()
    }
}

function Get-PeMachine {
    param([string]$LiteralPath)

    $stream = $null
    $reader = $null
    try {
        $stream = [System.IO.File]::Open(
            $LiteralPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        if ($stream.Length -lt 64) {
            throw 'SYS is too short to contain a PE header.'
        }
        $reader = New-Object System.IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5a4d) {
            throw 'SYS has no MZ header.'
        }
        $stream.Position = 0x3c
        $peOffset = [int64]$reader.ReadUInt32()
        if ($peOffset -lt 0 -or $peOffset + 6 -gt $stream.Length) {
            throw 'SYS PE header offset is outside the file.'
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw 'SYS has no PE signature.'
        }
        return [uint16]$reader.ReadUInt16()
    } finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        } elseif ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function New-NativeCommandResult {
    param(
        [int]$ExitCode,
        [object[]]$Stdout,
        [object[]]$Stderr
    )

    return [pscustomobject]@{
        ExitCode = $ExitCode
        Stdout = @($Stdout)
        Stderr = @($Stderr)
    }
}

function New-EmptyBcdReadOnlyObservation {
    return [pscustomobject][ordered]@{
        ProviderSucceeded = [bool]$false
        OpenStoreReturn = $null
        StoreClass = $null
        StoreFilePath = $null
        OpenObjectReturn = $null
        ObjectClass = $null
        ObjectId = $null
        ObjectStoreFilePath = $null
        ObjectType = $null
        EnumerateElementTypesReturn = $null
        ElementTypes = $null
        GetElementAttempted = [bool]$false
        GetElementReturn = $null
        ElementClass = $null
        ElementType = $null
        ElementObjectId = $null
        ElementStoreFilePath = $null
        ElementBoolean = $null
    }
}

function New-ReadOnlyBcdStoreManagementClass {
    $options = [System.Management.ConnectionOptions]::new()
    $options.Impersonation = [System.Management.ImpersonationLevel]::Impersonate
    $options.EnablePrivileges = $true

    $scope = [System.Management.ManagementScope]::new('\\.\root\WMI', $options)
    $scope.Connect()
    return [System.Management.ManagementClass]::new(
        $scope,
        [System.Management.ManagementPath]::new('BcdStore'),
        $null
    )
}

function Invoke-ReadOnlyBcdProviderQuery {
    param([Guid]$BootIdentifier)

    $evidence = New-EmptyBcdReadOnlyObservation
    $storeClass = $null
    try {
        $storeClass = New-ReadOnlyBcdStoreManagementClass
        $openedStore = $storeClass.OpenStore('')
        $evidence.ProviderSucceeded = [bool]$true
        $evidence.OpenStoreReturn = $openedStore.ReturnValue
        if (-not (Test-ExactRuntimeType $openedStore.ReturnValue ([bool])) -or
            -not $openedStore.ReturnValue -or
            $null -eq $openedStore.Store) {
            return $evidence
        }

        $store = $openedStore.Store
        $evidence.StoreClass = [string]$store.__CLASS
        $evidence.StoreFilePath = $store.FilePath
        if ($evidence.StoreClass -cne 'BcdStore' -or
            -not (Test-ExactRuntimeType $store.FilePath ([string])) -or
            $store.FilePath -cne '') {
            return $evidence
        }

        $identifier = $BootIdentifier.ToString('B')
        $openedObject = $store.OpenObject($identifier)
        $evidence.OpenObjectReturn = $openedObject.ReturnValue
        if (-not (Test-ExactRuntimeType $openedObject.ReturnValue ([bool])) -or
            -not $openedObject.ReturnValue -or
            $null -eq $openedObject.Object) {
            return $evidence
        }

        $bcdObject = $openedObject.Object
        $evidence.ObjectClass = [string]$bcdObject.__CLASS
        $evidence.ObjectId = $bcdObject.Id
        $evidence.ObjectStoreFilePath = $bcdObject.StoreFilePath
        $evidence.ObjectType = $bcdObject.Type
        if ($evidence.ObjectClass -cne 'BcdObject' -or
            -not (Test-ExactBootIdentifier $bcdObject.Id $BootIdentifier) -or
            -not (Test-ExactRuntimeType $bcdObject.StoreFilePath ([string])) -or
            $bcdObject.StoreFilePath -cne '' -or
            -not (Test-ExactRuntimeType $bcdObject.Type ([uint32])) -or
            $bcdObject.Type -ne [uint32]0x10200003) {
            return $evidence
        }

        $enumerated = $bcdObject.EnumerateElementTypes()
        $evidence.EnumerateElementTypesReturn = $enumerated.ReturnValue
        $evidence.ElementTypes = $enumerated.Types
        if (-not (Test-ExactRuntimeType $enumerated.ReturnValue ([bool])) -or
            -not $enumerated.ReturnValue -or
            -not ($enumerated.Types -is [System.Array])) {
            return $evidence
        }

        $roster = Test-BcdElementTypeRoster $enumerated.Types
        if (-not $roster.Valid -or -not $roster.ShouldGetElement) {
            return $evidence
        }

        $evidence.GetElementAttempted = [bool]$true
        $elementResult = $bcdObject.GetElement([uint32]0x16000049)
        $evidence.GetElementReturn = $elementResult.ReturnValue
        if (-not (Test-ExactRuntimeType $elementResult.ReturnValue ([bool])) -or
            -not $elementResult.ReturnValue -or
            $null -eq $elementResult.Element) {
            return $evidence
        }

        $element = $elementResult.Element
        $evidence.ElementClass = [string]$element.__CLASS
        $evidence.ElementType = $element.Type
        $evidence.ElementObjectId = $element.ObjectId
        $evidence.ElementStoreFilePath = $element.StoreFilePath
        $evidence.ElementBoolean = $element.Boolean
        return $evidence
    } catch {
        return $evidence
    } finally {
        if ($null -ne $storeClass) {
            $storeClass.Dispose()
        }
    }
}

function Test-ExactNativeServiceObservation {
    param($Observation)

    if ($null -eq $Observation -or
        -not (Test-ExactPropertySet $Observation @(
            'QuerySucceeded',
            'Exists',
            'MarkedForDelete',
            'Win32Error',
            'State',
            'ServiceType',
            'StartType',
            'BinaryPath',
            'LoadOrderGroup',
            'Detail'
        ))) {
        return $false
    }
    return (
        (Test-ExactRuntimeType $Observation.QuerySucceeded ([bool])) -and
        (Test-ExactRuntimeType $Observation.Exists ([bool])) -and
        (Test-ExactRuntimeType $Observation.MarkedForDelete ([bool])) -and
        (Test-JsonInteger $Observation.Win32Error) -and
        (Test-JsonInteger $Observation.State) -and
        (Test-JsonInteger $Observation.ServiceType) -and
        (Test-JsonInteger $Observation.StartType) -and
        (Test-ExactRuntimeType $Observation.BinaryPath ([string])) -and
        (Test-ExactRuntimeType $Observation.LoadOrderGroup ([string])) -and
        (Test-ExactRuntimeType $Observation.Detail ([string])) -and
        -not [string]::IsNullOrWhiteSpace($Observation.Detail)
    )
}

function Test-ExactOwnedServiceObservation {
    param($Observation, [string]$SysPath)

    return (
        (Test-ExactNativeServiceObservation $Observation) -and
        $Observation.QuerySucceeded -and
        $Observation.Exists -and
        -not $Observation.MarkedForDelete -and
        [uint32]$Observation.ServiceType -eq [uint32]2 -and
        [uint32]$Observation.StartType -eq [uint32]3 -and
        $Observation.BinaryPath -ieq $SysPath -and
        $Observation.LoadOrderGroup -ceq 'File System'
    )
}

function New-InvalidNativeServiceObservation {
    param([string]$Detail)

    return [pscustomobject][ordered]@{
        QuerySucceeded = [bool]$false
        Exists = [bool]$false
        MarkedForDelete = [bool]$false
        Win32Error = [int32]9009
        State = [uint32]0
        ServiceType = [uint32]0
        StartType = [uint32]0
        BinaryPath = ''
        LoadOrderGroup = ''
        Detail = $Detail
    }
}

function New-RealAdapter {
    param(
        [int]$CommandTimeoutMilliseconds =
            $script:ScCommandTimeoutMilliseconds
    )

    if ($CommandTimeoutMilliseconds -lt 1) {
        throw 'SCM command timeout must be positive.'
    }
    $commandTimeout = $CommandTimeoutMilliseconds
    $commandContainmentTimeout = (
        $script:ContainmentTimeoutMilliseconds
    )
    $commandStreamCap = $script:ClientStreamCapBytes
    $scPinState = [pscustomobject]@{ Pin = $null }
    $run = {
        param([string]$FilePath, [object[]]$Arguments)

        $nativeArguments = [string[]]@(
            $Arguments | ForEach-Object { [string]$_ }
        )
        return [FsringContainedClientRunner]::Run(
            $FilePath,
            $nativeArguments,
            $commandTimeout,
            $commandContainmentTimeout,
            $commandStreamCap,
            $null,
            $false
        )
    }.GetNewClosure()
    $runScm = {
        param(
            [string]$FilePath,
            [object[]]$Arguments,
            [string]$IdentityStage
        )

        if ($null -eq $scPinState.Pin) {
            throw 'The retained sc.exe pin is absent.'
        }
        $nativeArguments = [string[]]@(
            $Arguments | ForEach-Object { [string]$_ }
        )
        return [FsringContainedClientRunner]::RunOpaquePinned(
            $scPinState.Pin,
            $FilePath,
            $IdentityStage,
            $nativeArguments,
            $commandTimeout,
            $commandContainmentTimeout,
            $commandStreamCap
        )
    }.GetNewClosure()
    $readService = {
        param([string]$ServiceName)
        return [FsringNativeService]::Query($ServiceName)
    }
    $runClient = {
        param(
            [string]$FilePath,
            [object[]]$Arguments,
            $HarnessPin,
            [string]$IdentityStage
        )

        $nativeArguments = [string[]]@(
            $Arguments | ForEach-Object { [string]$_ }
        )
        if ($null -ne $HarnessPin) {
            return [FsringContainedClientRunner]::RunPinned(
                $HarnessPin,
                $FilePath,
                $IdentityStage,
                $nativeArguments,
                $script:HarnessTimeoutMilliseconds,
                $script:ContainmentTimeoutMilliseconds,
                $script:ClientStreamCapBytes
            )
        }
        return [FsringContainedClientRunner]::Run(
            $FilePath,
            $nativeArguments,
            $script:ClientTimeoutMilliseconds,
            $script:ContainmentTimeoutMilliseconds,
            $script:ClientStreamCapBytes,
            $null,
            $false
        )
    }
    $sleep = {
        param([int]$Milliseconds)
        Start-Sleep -Milliseconds $Milliseconds
    }
    $verifyIdentity = {
        param([string]$SysPath, [string]$ExpectedSha256)

        try {
            $actualHash = (Get-FileHash -LiteralPath $SysPath -Algorithm SHA256).Hash
            $machine = Get-PeMachine $SysPath
            $valid = ($actualHash -ceq $ExpectedSha256 -and $machine -eq 0x8664)
            return [pscustomobject]@{
                Valid = $valid
                Detail = if ($valid) { 'Exact SYS hash and AMD64 machine are unchanged.' } else { 'Exact SYS hash or AMD64 machine changed after preflight.' }
            }
        } catch {
            return [pscustomobject]@{
                Valid = $false
                Detail = $_.Exception.Message
            }
        }
    }
    $verifyServiceIdentity = {
        param([string]$SysPath)

        try {
            $observation = [FsringNativeService]::Query(
                $script:ServiceName
            )
            $valid = Test-ExactOwnedServiceObservation `
                $observation $SysPath
            return [pscustomobject]@{
                Valid = $valid
                Detail = if ($valid) {
                    'Native SCM identity matches the exact SYS, type, start, and group.'
                } else {
                    "Native SCM identity mismatch: $($observation.Detail)"
                }
            }
        } catch {
            return [pscustomobject]@{
                Valid = $false
                Detail = $_.Exception.Message
            }
        }
    }
    $readNativeReadiness = {
        return [FsringNativeReadiness]::Query()
    }
    $readBootConfiguration = {
        param([Guid]$BootIdentifier)

        return Invoke-ReadOnlyBcdProviderQuery $BootIdentifier
    }
    $recheckHarnessIdentity = {
        param(
            $HarnessPin,
            [string]$HarnessPath,
            [string]$IdentityStage
        )

        if ($null -eq $HarnessPin) {
            throw 'The retained harness pin is absent.'
        }
        return $HarnessPin.Recheck(
            $HarnessPath,
            $IdentityStage
        )
    }
    return [pscustomobject]@{
        Run = $run
        RunScm = $runScm
        ReadService = $readService
        ScPinState = $scPinState
        RequireScIdentity = [bool]$true
        AllowLegacyCommandResults = [bool]$false
        RunClient = $runClient
        HarnessPin = $null
        RecheckHarnessIdentity = $recheckHarnessIdentity
        Sleep = $sleep
        VerifyIdentity = $verifyIdentity
        VerifyServiceIdentity = $verifyServiceIdentity
        ReadNativeReadiness = $readNativeReadiness
        ReadBootConfiguration = $readBootConfiguration
        PollAttempts = 61
    }
}

function ConvertTo-ScriptedNativeServiceObservation {
    param($Raw)

    if (Test-ExactNativeServiceObservation $Raw) {
        return $Raw
    }
    if ($null -eq $Raw -or
        -not (Test-ExactPropertySet $Raw @(
            'ExitCode',
            'Stdout',
            'Stderr'
        ))) {
        return New-InvalidNativeServiceObservation `
            'Scripted native SCM observation shape is invalid.'
    }

    $exitCode = [int]$Raw.ExitCode
    if ($exitCode -eq 1060) {
        return [pscustomobject][ordered]@{
            QuerySucceeded = [bool]$true
            Exists = [bool]$false
            MarkedForDelete = [bool]$false
            Win32Error = [int32]1060
            State = [uint32]0
            ServiceType = [uint32]0
            StartType = [uint32]0
            BinaryPath = ''
            LoadOrderGroup = ''
            Detail = 'Scripted exact service name is absent.'
        }
    }
    if ($exitCode -eq 1072) {
        return [pscustomobject][ordered]@{
            QuerySucceeded = [bool]$true
            Exists = [bool]$true
            MarkedForDelete = [bool]$true
            Win32Error = [int32]1072
            State = [uint32]0
            ServiceType = [uint32]0
            StartType = [uint32]0
            BinaryPath = ''
            LoadOrderGroup = ''
            Detail = 'Scripted exact service is marked for deletion.'
        }
    }
    $stateCode = Get-ScriptedServiceStateCode $Raw
    if ($exitCode -ne 0 -or $null -eq $stateCode) {
        return New-InvalidNativeServiceObservation (
            "Scripted native SCM query failed with exit $exitCode."
        )
    }
    return [pscustomobject][ordered]@{
        QuerySucceeded = [bool]$true
        Exists = [bool]$true
        MarkedForDelete = [bool]$false
        Win32Error = [int32]0
        State = [uint32]$stateCode
        ServiceType = [uint32]2
        StartType = [uint32]3
        BinaryPath = 'C:\package\fsring_fsd.sys'
        LoadOrderGroup = 'File System'
        Detail = 'Scripted native SCM status and configuration query succeeded.'
    }
}

function New-ScriptedAdapter {
    param(
        [object[]]$Results,
        [bool]$IdentityValid = $true,
        [int]$PollAttempts = 2,
        [ValidateSet(
            'Pass',
            'Fail',
            'Throw',
            'PassThenFail',
            'PassThenThrow'
        )]
        [string]$ServiceIdentityMode = 'Pass',
        [bool]$SleepThrows = $false,
        [bool]$PostIdentityValid = $true
    )

    $state = [pscustomobject]@{
        Results = @($Results)
        Index = 0
        CommandCalls = 0
        ClientCalls = 0
        IdentityRecheckCalls = 0
    }
    $run = {
        param([string]$FilePath, [object[]]$Arguments)

        $state.CommandCalls++
        if ($state.Index -ge $state.Results.Count) {
            throw "Scripted command adapter exhausted at $FilePath."
        }
        $next = $state.Results[$state.Index]
        $state.Index++
        return $next
    }.GetNewClosure()
    $runScm = {
        param(
            [string]$FilePath,
            [object[]]$Arguments,
            [string]$IdentityStage
        )
        return & $run $FilePath $Arguments
    }.GetNewClosure()
    $readService = {
        param([string]$ServiceName)

        $state.CommandCalls++
        if ($state.Index -ge $state.Results.Count) {
            throw (
                'Scripted native SCM adapter exhausted at ' +
                $ServiceName + '.'
            )
        }
        $next = $state.Results[$state.Index]
        $state.Index++
        return ConvertTo-ScriptedNativeServiceObservation $next
    }.GetNewClosure()
    $postIdentityState = [pscustomobject]@{
        Valid = $PostIdentityValid
    }
    $recheckHarnessIdentity = {
        param(
            $HarnessPin,
            [string]$HarnessPath,
            [string]$IdentityStage
        )

        $state.IdentityRecheckCalls++
        return New-FakeHarnessIdentityCheck `
            $IdentityStage $postIdentityState.Valid
    }.GetNewClosure()
    $runClient = {
        param(
            [string]$FilePath,
            [object[]]$Arguments,
            $HarnessPin,
            [string]$IdentityStage
        )

        $state.ClientCalls++
        if ($state.Index -ge $state.Results.Count) {
            throw "Scripted client adapter exhausted at $FilePath."
        }
        $next = $state.Results[$state.Index]
        $state.Index++
        if (Test-ExactPropertySet $next @(
            'ExitCode',
            'Stdout',
            'Stderr'
        )) {
            return New-FakeClientResult $next.ExitCode `
                @($next.Stdout) @($next.Stderr)
        }
        return $next
    }.GetNewClosure()
    $sleepState = [pscustomobject]@{ Throws = $SleepThrows }
    $sleep = {
        param([int]$Milliseconds)
        if ($sleepState.Throws) {
            throw 'Scripted cleanup sleep failure.'
        }
    }.GetNewClosure()
    $identityState = [pscustomobject]@{ Valid = $IdentityValid }
    $verifyIdentity = {
        param([string]$SysPath, [string]$ExpectedSha256)

        return [pscustomobject]@{
            Valid = $identityState.Valid
            Detail = if ($identityState.Valid) { 'Scripted identity PASS.' } else { 'Scripted identity FAIL.' }
        }
    }.GetNewClosure()
    $serviceIdentityState = [pscustomobject]@{
        Mode = $ServiceIdentityMode
        Checks = 0
    }
    $verifyServiceIdentity = {
        param([string]$SysPath)

        $serviceIdentityState.Checks++
        $effectiveMode = $serviceIdentityState.Mode
        if ($effectiveMode -ceq 'PassThenFail') {
            $effectiveMode = if (
                $serviceIdentityState.Checks -eq 1
            ) {
                'Pass'
            } else {
                'Fail'
            }
        } elseif ($effectiveMode -ceq 'PassThenThrow') {
            $effectiveMode = if (
                $serviceIdentityState.Checks -eq 1
            ) {
                'Pass'
            } else {
                'Throw'
            }
        }
        if ($effectiveMode -ceq 'Throw') {
            throw 'Scripted service identity failure.'
        }
        $valid = ($effectiveMode -ceq 'Pass')
        return [pscustomobject]@{
            Valid = $valid
            Detail = if ($valid) { 'Scripted service identity PASS.' } else { 'Scripted service identity FAIL.' }
        }
    }.GetNewClosure()
    return [pscustomobject]@{
        Run = $run
        RunScm = $runScm
        ReadService = $readService
        ScPinState = [pscustomobject]@{ Pin = $null }
        RequireScIdentity = [bool]$false
        AllowLegacyCommandResults = [bool]$true
        RunClient = $runClient
        HarnessPin = $null
        RecheckHarnessIdentity = $recheckHarnessIdentity
        Sleep = $sleep
        VerifyIdentity = $verifyIdentity
        VerifyServiceIdentity = $verifyServiceIdentity
        PollAttempts = $PollAttempts
        State = $state
        ServiceIdentityState = $serviceIdentityState
    }
}

function Test-ContainedExternalResult {
    param($Raw)

    if ($null -eq $Raw -or
        -not (Test-ExactPropertySet $Raw @(
            'ExitCode',
            'Stdout',
            'Stderr',
            'TimedOut',
            'ContainmentConfirmed',
            'OutputTruncated',
            'StdoutTruncated',
            'StderrTruncated',
            'StdoutByteCount',
            'StderrByteCount',
            'StdoutTotalByteCount',
            'StderrTotalByteCount',
            'ProtocolValid',
            'OutputFinalized',
            'Error',
            'Lease',
            'IdentityCheck'
        ))) {
        return $false
    }
    return (
        ($null -eq $Raw.ExitCode -or
            (Test-JsonInteger $Raw.ExitCode)) -and
        $Raw.Stdout -is [System.Array] -and
        $Raw.Stderr -is [System.Array] -and
        (Test-ExactRuntimeType $Raw.TimedOut ([bool])) -and
        (Test-ExactRuntimeType $Raw.ContainmentConfirmed ([bool])) -and
        (Test-ExactRuntimeType $Raw.OutputTruncated ([bool])) -and
        (Test-ExactRuntimeType $Raw.StdoutTruncated ([bool])) -and
        (Test-ExactRuntimeType $Raw.StderrTruncated ([bool])) -and
        (Test-JsonInteger $Raw.StdoutByteCount) -and
        (Test-JsonInteger $Raw.StderrByteCount) -and
        (Test-JsonInteger $Raw.StdoutTotalByteCount) -and
        (Test-JsonInteger $Raw.StderrTotalByteCount) -and
        (Test-ExactRuntimeType $Raw.ProtocolValid ([bool])) -and
        (Test-ExactRuntimeType $Raw.OutputFinalized ([bool])) -and
        ($null -eq $Raw.Error -or $Raw.Error -is [string]) -and
        (($Raw.ContainmentConfirmed -and $null -eq $Raw.Lease) -or
            (-not $Raw.ContainmentConfirmed -and
                $null -ne $Raw.Lease))
    )
}

function Test-SafeScCommandCompletion {
    param($CommandResult)

    return (
        $null -ne $CommandResult.ExitCode -and
        -not $CommandResult.TimedOut -and
        $CommandResult.ContainmentConfirmed -and
        -not $CommandResult.OutputTruncated -and
        $CommandResult.OutputFinalized -and
        $CommandResult.ProtocolValid
    )
}

function Invoke-AdapterCommand {
    param(
        $Adapter,
        $Result,
        [string]$Operation,
        [string]$FilePath,
        [object[]]$Arguments,
        [switch]$Mutation
    )

    if (-not $Result.containment.allClientsConfirmed -or
        $Result.containment.cleanupBlocked) {
        throw (
            "External command '$Operation' was withheld because a prior " +
            'process tree is not confirmed empty.'
        )
    }
    if ($Mutation) {
        $Result.ownership.mutationAttempts = [int]$Result.ownership.mutationAttempts + 1
    }
    $adapterFailure = $null
    $raw = $null
    $rawLease = $null
    $rawLeaseRetained = $false
    $identityStage = "sc-$Operation"
    try {
        $raw = & $Adapter.RunScm `
            $FilePath $Arguments $identityStage
    } catch {
        $adapterFailure = $_.Exception.Message
    }
    if ($null -ne $raw) {
        try {
            $leaseProperty = $raw.PSObject.Properties['Lease']
            if ($null -ne $leaseProperty) {
                $rawLease = $leaseProperty.Value
                if ($null -ne $rawLease) {
                    [void]$script:RetainedClientLeases.Add(
                        $rawLease
                    )
                    $Result.containment.leasesRetained = (
                        [int]$Result.containment.leasesRetained + 1
                    )
                    $rawLeaseRetained = $true
                }
            }
        } catch {
            if ($null -eq $adapterFailure) {
                $adapterFailure = (
                    'SCM adapter Lease could not be observed safely.'
                )
            }
        }
    }

    $allowsLegacyShape = (
        $null -ne $Adapter.PSObject.Properties[
            'AllowLegacyCommandResults'
        ] -and
        [bool]$Adapter.AllowLegacyCommandResults
    )
    $legacyShape = (
        $allowsLegacyShape -and
        $null -eq $adapterFailure -and
        $null -ne $raw -and
        (Test-ExactPropertySet $raw @(
            'ExitCode',
            'Stdout',
            'Stderr'
        ))
    )
    if ($legacyShape) {
        $raw = [pscustomobject][ordered]@{
            ExitCode = [int]$raw.ExitCode
            Stdout = @($raw.Stdout)
            Stderr = @($raw.Stderr)
            TimedOut = [bool]$false
            ContainmentConfirmed = [bool]$true
            OutputTruncated = [bool]$false
            StdoutTruncated = [bool]$false
            StderrTruncated = [bool]$false
            StdoutByteCount = [int32]0
            StderrByteCount = [int32]0
            StdoutTotalByteCount = [int64]0
            StderrTotalByteCount = [int64]0
            ProtocolValid = [bool]$true
            OutputFinalized = [bool]$true
            Error = $null
            Lease = $null
            IdentityCheck = $null
        }
    }

    $shapeValid = (
        $null -eq $adapterFailure -and
        (Test-ContainedExternalResult $raw)
    )
    $requiresIdentity = (
        $null -ne $Adapter.PSObject.Properties[
            'RequireScIdentity'
        ] -and
        [bool]$Adapter.RequireScIdentity
    )
    $identityValid = -not $requiresIdentity
    if ($shapeValid -and $requiresIdentity) {
        $identityValid = Test-ExactExecutableIdentityCheck `
            $raw.IdentityCheck $identityStage
        if (-not $identityValid) {
            $adapterFailure = (
                'SCM launch lacks exact successful retained sc.exe ' +
                "identity evidence for $identityStage."
            )
        }
    }
    if (-not $shapeValid) {
        if ($null -eq $adapterFailure) {
            $adapterFailure = (
                'SCM adapter returned an invalid contained-result shape.'
            )
        }
        $raw = [pscustomobject][ordered]@{
            ExitCode = $null
            Stdout = @()
            Stderr = @($adapterFailure)
            TimedOut = [bool]$false
            ContainmentConfirmed = [bool]$false
            OutputTruncated = [bool]$false
            StdoutTruncated = [bool]$false
            StderrTruncated = [bool]$false
            StdoutByteCount = [int32]0
            StderrByteCount = [int32]0
            StdoutTotalByteCount = [int64]0
            StderrTotalByteCount = [int64]0
            ProtocolValid = [bool]$false
            OutputFinalized = [bool]$false
            Error = $adapterFailure
            Lease = $rawLease
            IdentityCheck = $null
        }
    } elseif (-not $identityValid) {
        $raw.ProtocolValid = [bool]$false
        $raw.Error = $adapterFailure
    }

    if (-not $raw.ContainmentConfirmed) {
        $Result.containment.allClientsConfirmed = $false
        $Result.containment.cleanupBlocked = $true
    }
    if (-not $rawLeaseRetained -and
        $null -ne $raw.Lease) {
        [void]$script:RetainedClientLeases.Add($raw.Lease)
        $Result.containment.leasesRetained = (
            [int]$Result.containment.leasesRetained + 1
        )
    }

    $stdout = @($raw.Stdout | ForEach-Object { [string]$_ })
    $stderr = @($raw.Stderr | ForEach-Object { [string]$_ })
    $exitCode = $null
    if ($null -ne $raw.ExitCode) {
        $exitCode = [int]$raw.ExitCode
    }
    $record = [ordered]@{
        operation = $Operation
        mutating = [bool]$Mutation
        filePath = $FilePath
        arguments = @($Arguments | ForEach-Object { [string]$_ })
        identityStage = $identityStage
        exitCode = $exitCode
        timedOut = [bool]$raw.TimedOut
        containmentConfirmed = [bool]$raw.ContainmentConfirmed
        outputTruncated = [bool]$raw.OutputTruncated
        outputFinalized = [bool]$raw.OutputFinalized
        protocolValid = [bool]$raw.ProtocolValid
        identityRecheck = $raw.IdentityCheck
        error = $raw.Error
        stdout = $stdout
        stderr = $stderr
    }
    [void]$Result.commands.Add($record)
    return [pscustomobject][ordered]@{
        ExitCode = $exitCode
        Stdout = $stdout
        Stderr = $stderr
        TimedOut = [bool]$raw.TimedOut
        ContainmentConfirmed = [bool]$raw.ContainmentConfirmed
        OutputTruncated = [bool]$raw.OutputTruncated
        StdoutTruncated = [bool]$raw.StdoutTruncated
        StderrTruncated = [bool]$raw.StderrTruncated
        StdoutByteCount = [int]$raw.StdoutByteCount
        StderrByteCount = [int]$raw.StderrByteCount
        StdoutTotalByteCount = [int64]$raw.StdoutTotalByteCount
        StderrTotalByteCount = [int64]$raw.StderrTotalByteCount
        ProtocolValid = [bool]$raw.ProtocolValid
        OutputFinalized = [bool]$raw.OutputFinalized
        Error = $raw.Error
        Lease = $raw.Lease
        IdentityCheck = $raw.IdentityCheck
    }
}

function Invoke-AdapterClientCommand {
    param(
        $Adapter,
        $Result,
        [string]$Operation,
        [string]$FilePath,
        [object[]]$Arguments,
        $HarnessPin,
        [string]$IdentityStage
    )

    $expectedProperties = @(
        'ExitCode',
        'Stdout',
        'Stderr',
        'TimedOut',
        'ContainmentConfirmed',
        'OutputTruncated',
        'StdoutTruncated',
        'StderrTruncated',
        'StdoutByteCount',
        'StderrByteCount',
        'StdoutTotalByteCount',
        'StderrTotalByteCount',
        'ProtocolValid',
        'OutputFinalized',
        'Error',
        'Lease',
        'IdentityCheck'
    )
    $adapterFailure = $null
    $raw = $null
    $rawLease = $null
    $rawLeaseRetained = $false
    try {
        $raw = & $Adapter.RunClient `
            $FilePath $Arguments $HarnessPin $IdentityStage
    } catch {
        $adapterFailure = $_.Exception.Message
    }
    if ($null -ne $raw) {
        try {
            $leaseProperty = $raw.PSObject.Properties['Lease']
            if ($null -ne $leaseProperty) {
                $rawLease = $leaseProperty.Value
                if ($null -ne $rawLease) {
                    [void]$script:RetainedClientLeases.Add($rawLease)
                    $Result.containment.leasesRetained = (
                        [int]$Result.containment.leasesRetained + 1
                    )
                    $rawLeaseRetained = $true
                }
            }
        } catch {
            if ($null -eq $adapterFailure) {
                $adapterFailure = (
                    'Client adapter Lease could not be observed safely.'
                )
            }
        }
    }

    $shapeValid = (
        $null -eq $adapterFailure -and
        $null -ne $raw -and
        (Test-ExactPropertySet $raw $expectedProperties)
    )
    if ($shapeValid) {
        $shapeValid = (
            ($null -eq $raw.ExitCode -or
                (Test-JsonInteger $raw.ExitCode)) -and
            $raw.Stdout -is [System.Array] -and
            $raw.Stderr -is [System.Array] -and
            (Test-ExactRuntimeType $raw.TimedOut ([bool])) -and
            (Test-ExactRuntimeType $raw.ContainmentConfirmed ([bool])) -and
            (Test-ExactRuntimeType $raw.OutputTruncated ([bool])) -and
            (Test-ExactRuntimeType $raw.StdoutTruncated ([bool])) -and
            (Test-ExactRuntimeType $raw.StderrTruncated ([bool])) -and
            (Test-JsonInteger $raw.StdoutByteCount) -and
            (Test-JsonInteger $raw.StderrByteCount) -and
            (Test-JsonInteger $raw.StdoutTotalByteCount) -and
            (Test-JsonInteger $raw.StderrTotalByteCount) -and
            (Test-ExactRuntimeType $raw.ProtocolValid ([bool])) -and
            (Test-ExactRuntimeType $raw.OutputFinalized ([bool])) -and
            ($null -eq $raw.Error -or $raw.Error -is [string]) -and
            (($raw.ContainmentConfirmed -and $null -eq $raw.Lease) -or
                (-not $raw.ContainmentConfirmed -and
                    $null -ne $raw.Lease))
        )
    }
    if (-not $shapeValid) {
        if ($null -eq $adapterFailure) {
            $adapterFailure = (
                'Client adapter returned an invalid contained-result shape.'
            )
        }
        $raw = [pscustomobject][ordered]@{
            ExitCode = $null
            Stdout = @()
            Stderr = @($adapterFailure)
            TimedOut = $false
            ContainmentConfirmed = $false
            OutputTruncated = $false
            StdoutTruncated = $false
            StderrTruncated = $false
            StdoutByteCount = 0
            StderrByteCount = 0
            StdoutTotalByteCount = 0
            StderrTotalByteCount = 0
            ProtocolValid = $false
            OutputFinalized = $false
            Error = $adapterFailure
            Lease = $rawLease
            IdentityCheck = $null
        }
    }

    if (-not $raw.ContainmentConfirmed) {
        $Result.containment.allClientsConfirmed = $false
        $Result.containment.cleanupBlocked = $true
    }
    if (-not $rawLeaseRetained -and $null -ne $raw.Lease) {
        [void]$script:RetainedClientLeases.Add($raw.Lease)
        $Result.containment.leasesRetained = (
            [int]$Result.containment.leasesRetained + 1
        )
    }
    if ($null -ne $raw.IdentityCheck -and
        ($IdentityStage -ceq 'preMain' -or
            $IdentityStage -ceq 'preAbsence')) {
        $Result.preflight.harnessIdentity.rechecks[$IdentityStage] = (
            ConvertTo-HarnessIdentityCheckEvidence `
                $raw.IdentityCheck
        )
    }

    $stdout = @($raw.Stdout | ForEach-Object { [string]$_ })
    $stderr = @($raw.Stderr | ForEach-Object { [string]$_ })
    $exitCode = $null
    if ($null -ne $raw.ExitCode) {
        $exitCode = [int]$raw.ExitCode
    }
    $record = [ordered]@{
        operation = $Operation
        mutating = $false
        filePath = $FilePath
        arguments = @($Arguments | ForEach-Object { [string]$_ })
        identityStage = $IdentityStage
        exitCode = $exitCode
        timedOut = [bool]$raw.TimedOut
        containmentConfirmed = [bool]$raw.ContainmentConfirmed
        outputTruncated = [bool]$raw.OutputTruncated
        outputFinalized = [bool]$raw.OutputFinalized
        protocolValid = [bool]$raw.ProtocolValid
        identityRecheck = $raw.IdentityCheck
        stdout = $stdout
        stderr = $stderr
    }
    [void]$Result.commands.Add($record)
    return [pscustomobject][ordered]@{
        ExitCode = $exitCode
        Stdout = $stdout
        Stderr = $stderr
        TimedOut = [bool]$raw.TimedOut
        ContainmentConfirmed = [bool]$raw.ContainmentConfirmed
        OutputTruncated = [bool]$raw.OutputTruncated
        StdoutTruncated = [bool]$raw.StdoutTruncated
        StderrTruncated = [bool]$raw.StderrTruncated
        StdoutByteCount = [int]$raw.StdoutByteCount
        StderrByteCount = [int]$raw.StderrByteCount
        StdoutTotalByteCount = [int64]$raw.StdoutTotalByteCount
        StderrTotalByteCount = [int64]$raw.StderrTotalByteCount
        ProtocolValid = [bool]$raw.ProtocolValid
        OutputFinalized = [bool]$raw.OutputFinalized
        Error = $raw.Error
        Lease = $raw.Lease
        IdentityCheck = $raw.IdentityCheck
    }
}

function Invoke-AdapterServiceObservation {
    param(
        $Adapter,
        $Result,
        [string]$Operation
    )

    if (-not $Result.containment.allClientsConfirmed -or
        $Result.containment.cleanupBlocked) {
        throw (
            "Native SCM observation '$Operation' was withheld because " +
            'a prior process tree is not confirmed empty.'
        )
    }
    $failure = $null
    $observation = $null
    try {
        $observation = & $Adapter.ReadService `
            $script:ServiceName
    } catch {
        $failure = $_.Exception.Message
    }
    if ($null -ne $failure -or
        -not (Test-ExactNativeServiceObservation $observation)) {
        if ($null -eq $failure) {
            $failure = (
                'Native SCM adapter returned an invalid observation.'
            )
        }
        $observation = New-InvalidNativeServiceObservation $failure
    }

    $exitCode = [int]$observation.Win32Error
    if ($observation.QuerySucceeded -and
        $observation.Exists -and
        -not $observation.MarkedForDelete) {
        $exitCode = 0
    } elseif ($observation.QuerySucceeded -and
        -not $observation.Exists) {
        $exitCode = 1060
    } elseif ($observation.QuerySucceeded -and
        $observation.MarkedForDelete) {
        $exitCode = 1072
    } elseif ($exitCode -eq 0) {
        $exitCode = 9009
    }

    [void]$Result.commands.Add([ordered]@{
        operation = $Operation
        mutating = $false
        filePath = 'advapi32!QueryServiceStatusEx/QueryServiceConfigW'
        arguments = @($script:ServiceName)
        identityStage = $null
        exitCode = $exitCode
        timedOut = $false
        containmentConfirmed = $true
        outputTruncated = $false
        outputFinalized = $true
        protocolValid = [bool]$observation.QuerySucceeded
        identityRecheck = $null
        error = if ($observation.QuerySucceeded) {
            $null
        } else {
            $observation.Detail
        }
        stdout = @()
        stderr = @()
        serviceObservation = [ordered]@{
            querySucceeded = [bool]$observation.QuerySucceeded
            exists = [bool]$observation.Exists
            markedForDelete = [bool]$observation.MarkedForDelete
            win32Error = [int]$observation.Win32Error
            state = [uint32]$observation.State
            serviceType = [uint32]$observation.ServiceType
            startType = [uint32]$observation.StartType
            binaryPath = [string]$observation.BinaryPath
            loadOrderGroup = [string]$observation.LoadOrderGroup
            detail = [string]$observation.Detail
        }
    })
    return $observation
}

function Test-ServiceAbsentResult {
    param($CommandResult)

    return ($CommandResult.ExitCode -eq 1060)
}

function Test-ServiceAbsentObservation {
    param($Observation)

    return (
        (Test-ExactNativeServiceObservation $Observation) -and
        $Observation.QuerySucceeded -and
        -not $Observation.Exists -and
        -not $Observation.MarkedForDelete -and
        $Observation.Win32Error -eq 1060
    )
}

function Test-ServiceAlreadyStoppedResult {
    param($CommandResult)

    return ($CommandResult.ExitCode -eq 1062 -or $CommandResult.ExitCode -eq 1060)
}

function Set-StepCommandEnvelope {
    param(
        $Target,
        $CommandResult,
        [bool]$Success
    )

    $Target.attempted = $true
    $Target.success = $Success
    $Target.exitCode = $CommandResult.ExitCode
    $Target.timedOut = [bool]$CommandResult.TimedOut
    $Target.containmentConfirmed = (
        [bool]$CommandResult.ContainmentConfirmed
    )
    $Target.outputFinalized = [bool]$CommandResult.OutputFinalized
    $Target.protocolValid = [bool]$CommandResult.ProtocolValid
}

function Get-ScriptedServiceStateCode {
    param($CommandResult)

    # SelfTest compatibility only. Production service decisions use typed
    # QueryServiceStatusEx/QueryServiceConfigW observations and never parse
    # localized sc.exe text.
    if ($CommandResult.ExitCode -ne 0) {
        return $null
    }
    $text = (@($CommandResult.Stdout) + @($CommandResult.Stderr)) -join "`n"
    # sc.exe prints TYPE first and STATE second. Select the second numeric
    # colon-delimited field so classification does not depend on localized
    # prose such as "STATE", "RUNNING", or "STOPPED".
    $matches = [regex]::Matches($text, '(?m)^\s*[^:\r\n]+:\s*(\d+)(?:\s|$)')
    if ($matches.Count -lt 2) {
        return $null
    }
    return [int]$matches[1].Groups[1].Value
}

function Wait-ServiceCondition {
    param(
        $Adapter,
        $Result,
        [ValidateSet('Running', 'Stopped', 'Absent')]
        [string]$Condition
    )

    $newStep = {
        param(
            [bool]$Success,
            $ExitCode,
            [bool]$TimedOut,
            [bool]$Absent,
            [bool]$ProtocolValid,
            [string]$Detail
        )
        return [ordered]@{
            attempted = $true
            success = $Success
            exitCode = $ExitCode
            timedOut = $TimedOut
            containmentConfirmed = $true
            outputFinalized = $true
            protocolValid = $ProtocolValid
            absent = $Absent
            detail = $Detail
        }
    }
    $lastDetail = $null
    $lastExitCode = $null
    for ($attempt = 1; $attempt -le $Adapter.PollAttempts; $attempt++) {
        $observation = Invoke-AdapterServiceObservation `
            $Adapter $Result `
            "wait-$($Condition.ToLowerInvariant())"
        $lastExitCode = if ($observation.QuerySucceeded -and
            -not $observation.Exists) {
            1060
        } elseif ($observation.MarkedForDelete) {
            1072
        } elseif ($observation.QuerySucceeded) {
            0
        } else {
            [int]$observation.Win32Error
        }
        if (Test-ServiceAbsentObservation $observation) {
            if ($Condition -ceq 'Stopped' -or $Condition -ceq 'Absent') {
                return & $newStep `
                    $true 1060 $false $true $true `
                    "Service is absent after $attempt poll(s)."
            }
            return & $newStep `
                $false 1060 $false $true $true `
                'Service disappeared while waiting for RUNNING.'
        }
        if ($Condition -ceq 'Absent' -and
            $observation.QuerySucceeded -and
            $observation.MarkedForDelete) {
            $lastDetail = 'Service is marked for deletion (exit 1072).'
            if ($attempt -lt $Adapter.PollAttempts) {
                try {
                    & $Adapter.Sleep 500
                } catch {
                    return & $newStep `
                        $false 1072 $false $false $true `
                        "Absence-poll sleep failed: $($_.Exception.Message)"
                }
            }
            continue
        }
        if (-not $observation.QuerySucceeded -or
            -not $observation.Exists -or
            $observation.MarkedForDelete) {
            return & $newStep `
                $false $lastExitCode $false $false $false `
                'Native service query state/configuration was invalid.'
        }
        $stateCode = [uint32]$observation.State
        if ($Condition -ceq 'Running' -and $stateCode -eq 4) {
            return & $newStep `
                $true 0 $false $false $true `
                "Service reached numeric state 4 after $attempt poll(s)."
        }
        if ($Condition -ceq 'Stopped' -and $stateCode -eq 1) {
            return & $newStep `
                $true 0 $false $false $true `
                "Service reached numeric state 1 after $attempt poll(s)."
        }
        $lastDetail = "Last numeric service state was $stateCode."
        if ($attempt -lt $Adapter.PollAttempts) {
            try {
                & $Adapter.Sleep 500
            } catch {
                return & $newStep `
                    $false $lastExitCode $false $false $true `
                    "Service-poll sleep failed: $($_.Exception.Message)"
            }
        }
    }
    return & $newStep `
        $false $lastExitCode $true $false $true `
        "Timed out after $($Adapter.PollAttempts) polls. $lastDetail"
}

function Test-OwnedServiceContinuity {
    param(
        $Adapter,
        $Result,
        [string]$SysPath,
        [string]$Stage
    )

    $Result.cleanup.continuity.attempted = $true
    $Result.cleanup.continuity.checks = [int]$Result.cleanup.continuity.checks + 1
    try {
        $identity = & $Adapter.VerifyServiceIdentity $SysPath
    } catch {
        $identity = [pscustomobject]@{
            Valid = $false
            Detail = $_.Exception.Message
        }
    }
    if (-not $identity.Valid) {
        $Result.cleanup.continuity.success = $false
        $Result.cleanup.continuity.lost = $true
        $Result.cleanup.continuity.detail = "$Stage continuity check failed: $($identity.Detail)"
        Add-Reason $Result $Result.cleanup.continuity.detail
        return $false
    }
    $Result.cleanup.continuity.success = $true
    $Result.cleanup.continuity.detail = "$Stage continuity check passed: $($identity.Detail)"
    return $true
}

function Set-CleanupAlreadyAbsent {
    param(
        $Result,
        [int]$ExitCode,
        [string]$Detail
    )

    $Result.cleanup.continuity.attempted = $true
    $Result.cleanup.continuity.success = $true
    $Result.cleanup.continuity.detail = $Detail
    $Result.cleanup.stop.success = $true
    $Result.cleanup.stop.detail = 'Stop skipped because the owned service name was already absent.'
    $Result.cleanup.waitStopped.attempted = $true
    $Result.cleanup.waitStopped.success = $true
    $Result.cleanup.waitStopped.exitCode = $ExitCode
    $Result.cleanup.waitStopped.absent = $true
    $Result.cleanup.waitStopped.detail = $Detail
    $Result.cleanup.delete.success = $true
    $Result.cleanup.delete.detail = 'Delete skipped because absence was already proved.'
    $Result.cleanup.waitAbsent.attempted = $true
    $Result.cleanup.waitAbsent.success = $true
    $Result.cleanup.waitAbsent.exitCode = $ExitCode
    $Result.cleanup.waitAbsent.absent = $true
    $Result.cleanup.waitAbsent.detail = $Detail
    $Result.cleanup.success = $true
    $Result.ownership.servicePresent = $false
    Add-Transition $Result 'service-absent' $Detail
}

function Invoke-OwnedCleanup {
    param(
        $Adapter,
        $Result,
        [string]$ScPath,
        [string]$SysPath
    )

    if (-not $Result.ownership.createdByThisRun) {
        return $Result.cleanup
    }
    $Result.cleanup.attempted = $true
    Add-Transition $Result 'cleanup-started' 'Owned fsring_fsd cleanup began.'

    $continuityObservation = Invoke-AdapterServiceObservation `
        $Adapter $Result 'cleanup-continuity-query'
    if (Test-ServiceAbsentObservation $continuityObservation) {
        Set-CleanupAlreadyAbsent `
            $Result 1060 `
            'Pre-stop native SCM observation proved the owned service name already absent.'
        return $Result.cleanup
    }
    if ($continuityObservation.QuerySucceeded -and
        $continuityObservation.MarkedForDelete) {
        $Result.cleanup.continuity.attempted = $true
        $Result.cleanup.continuity.success = $true
        $Result.cleanup.continuity.detail = 'Pre-stop query found the service already marked for deletion.'
        $Result.cleanup.stop.success = $true
        $Result.cleanup.stop.detail = 'Stop skipped because the service is already marked for deletion.'
        $Result.cleanup.waitStopped.attempted = $true
        $Result.cleanup.waitStopped.success = $true
        $Result.cleanup.waitStopped.exitCode = 1072
        $Result.cleanup.waitStopped.detail = 'Service is already marked for deletion.'
        $Result.cleanup.delete.success = $true
        $Result.cleanup.delete.detail = 'Delete skipped because the service is already marked for deletion.'
        $Result.cleanup.waitAbsent = Wait-ServiceCondition `
            $Adapter $Result 'Absent'
        $Result.cleanup.success = $Result.cleanup.waitAbsent.success
        if ($Result.cleanup.waitAbsent.success) {
            $Result.ownership.servicePresent = $false
            Add-Transition $Result 'service-absent' 'Marked-for-delete service reached numeric exit 1060.'
        } else {
            Add-Reason $Result $Result.cleanup.waitAbsent.detail
        }
        return $Result.cleanup
    }
    if (-not $continuityObservation.QuerySucceeded -or
        -not $continuityObservation.Exists -or
        $continuityObservation.MarkedForDelete -or
        [uint32]$continuityObservation.State -lt [uint32]1 -or
        [uint32]$continuityObservation.State -gt [uint32]7) {
        $Result.cleanup.continuity.attempted = $true
        $Result.cleanup.continuity.success = $false
        $Result.cleanup.continuity.lost = $true
        $Result.cleanup.continuity.detail = 'Pre-stop service state was absent, inaccessible, or invalid; no name-based mutation is safe.'
        Add-Reason $Result $Result.cleanup.continuity.detail
        return $Result.cleanup
    }
    if (-not (Test-OwnedServiceContinuity $Adapter $Result $SysPath 'Pre-stop')) {
        return $Result.cleanup
    }

    $stop = Invoke-AdapterCommand $Adapter $Result 'stop' $ScPath @('stop', $script:ServiceName) -Mutation
    $stopSafe = Test-SafeScCommandCompletion $stop
    $stopAccepted = (
        $stopSafe -and
        ($stop.ExitCode -eq 0 -or
            (Test-ServiceAlreadyStoppedResult $stop))
    )
    Set-StepCommandEnvelope `
        $Result.cleanup.stop $stop $stopAccepted
    if (-not $stopSafe) {
        $Result.cleanup.mutationAmbiguous = $true
    }
    if (-not $Result.cleanup.stop.success) {
        $Result.cleanup.stop.detail = (
            'Owned service stop failed or was ambiguous; native ' +
            'state reconciliation is required before delete.'
        )
        Add-Reason $Result (
            "Owned service stop failed or was ambiguous with exit " +
            "$($stop.ExitCode)."
        )
    }

    $Result.cleanup.waitStopped = Wait-ServiceCondition `
        $Adapter $Result 'Stopped'
    if (-not $Result.cleanup.waitStopped.success) {
        Add-Reason $Result $Result.cleanup.waitStopped.detail
        return $Result.cleanup
    }

    if ($Result.cleanup.waitStopped.absent) {
        $Result.cleanup.delete.success = $true
        $Result.cleanup.delete.detail = 'Delete skipped because the stop poll proved absence.'
        $Result.cleanup.waitAbsent = $Result.cleanup.waitStopped
        $Result.cleanup.success = ($Result.cleanup.stop.success -and $Result.cleanup.waitStopped.success)
        $Result.ownership.servicePresent = $false
        Add-Transition $Result 'service-absent' 'Stop polling reached numeric sc.exe exit 1060; delete was skipped.'
        return $Result.cleanup
    }
    if (-not (Test-OwnedServiceContinuity $Adapter $Result $SysPath 'Pre-delete')) {
        return $Result.cleanup
    }

    $delete = Invoke-AdapterCommand $Adapter $Result 'delete' $ScPath @('delete', $script:ServiceName) -Mutation
    $deleteSafe = Test-SafeScCommandCompletion $delete
    $deleteAccepted = (
        $deleteSafe -and
        ($delete.ExitCode -eq 0 -or
            (Test-ServiceAbsentResult $delete))
    )
    Set-StepCommandEnvelope `
        $Result.cleanup.delete $delete $deleteAccepted
    if (-not $deleteSafe) {
        $Result.cleanup.mutationAmbiguous = $true
    }
    if (-not $Result.cleanup.delete.success) {
        $Result.cleanup.delete.detail = 'Owned service delete failed; cleanup continues with absence polling.'
        Add-Reason $Result "Owned service delete failed with exit $($delete.ExitCode)."
    }

    $Result.cleanup.waitAbsent = Wait-ServiceCondition `
        $Adapter $Result 'Absent'
    if (-not $Result.cleanup.waitAbsent.success) {
        Add-Reason $Result $Result.cleanup.waitAbsent.detail
    } else {
        if (-not $Result.cleanup.delete.success) {
            $Result.cleanup.delete.success = $true
            $Result.cleanup.delete.detail = (
                'Delete result was ambiguous, but native SCM ' +
                'observation proved exact-name absence.'
            )
        }
        $Result.ownership.servicePresent = $false
        Add-Transition $Result 'service-absent' (
            'Native SCM observation proved the owned service name absent.'
        )
    }

    $Result.cleanup.success = (
        $Result.cleanup.stop.success -and
        $Result.cleanup.waitStopped.success -and
        $Result.cleanup.delete.success -and
        $Result.cleanup.waitAbsent.success
    )
    return $Result.cleanup
}

function Set-HarnessResult {
    param(
        $Target,
        $CommandResult,
        $Parsed
    )

    $Target.attempted = $true
    $Target.valid = [bool]$Parsed.Valid
    $Target.exitCode = $null
    if ($null -ne $CommandResult.ExitCode) {
        $Target.exitCode = [int]$CommandResult.ExitCode
    }
    $Target.timedOut = [bool]$CommandResult.TimedOut
    $Target.containmentConfirmed = [bool]$CommandResult.ContainmentConfirmed
    $Target.outputTruncated = [bool]$CommandResult.OutputTruncated
    $Target.outputFinalized = [bool]$CommandResult.OutputFinalized
    $Target.protocolValid = [bool]$CommandResult.ProtocolValid
    $Target.identityRecheck = $CommandResult.IdentityCheck
    $Target.overall = $Parsed.Overall
    $Target.probes = @($Parsed.Probes)
    $Target.detail = $Parsed.Reason
}

function Test-EmergencyCleanupAllowed {
    param($Result)

    return (
        $Result.ownership.createdByThisRun -and
        -not $Result.cleanup.success -and
        -not $Result.cleanup.continuity.lost -and
        $Result.containment.allClientsConfirmed -and
        -not $Result.containment.cleanupBlocked
    )
}

function Test-ExactExecutableIdentityCheck {
    param(
        $Check,
        [string]$ExpectedStage
    )

    if ($null -eq $Check -or
        -not (Test-ExactPropertySet $Check @(
            'Attempted',
            'Valid',
            'Stage',
            'Sha256',
            'Length',
            'Machine',
            'VolumeSerial',
            'FileId',
            'FinalPath',
            'Detail'
        ))) {
        return $false
    }
    return (
        (Test-ExactRuntimeType $Check.Attempted ([bool])) -and
        $Check.Attempted -and
        (Test-ExactRuntimeType $Check.Valid ([bool])) -and
        $Check.Valid -and
        (Test-ExactRuntimeType $Check.Stage ([string])) -and
        $Check.Stage -ceq $ExpectedStage -and
        (Test-ExactRuntimeType $Check.Sha256 ([string])) -and
        $Check.Sha256 -cmatch '^[0-9A-F]{64}$' -and
        (Test-ExactRuntimeType $Check.Length ([int64])) -and
        $Check.Length -gt 0 -and
        (Test-ExactRuntimeType $Check.Machine ([uint16])) -and
        $Check.Machine -eq [uint16]0x8664 -and
        (Test-ExactRuntimeType $Check.VolumeSerial ([string])) -and
        $Check.VolumeSerial -cmatch '^[0-9A-F]{16}$' -and
        (Test-ExactRuntimeType $Check.FileId ([string])) -and
        $Check.FileId -cmatch '^[0-9A-F]{32}$' -and
        (Test-ExactRuntimeType $Check.FinalPath ([string])) -and
        [System.IO.Path]::IsPathRooted($Check.FinalPath) -and
        (Test-ExactRuntimeType $Check.Detail ([string])) -and
        -not [string]::IsNullOrWhiteSpace($Check.Detail)
    )
}

function Test-ExactHarnessIdentityCheck {
    param(
        $Check,
        [ValidateSet('preMain', 'preAbsence', 'postAbsence')]
        [string]$ExpectedStage
    )

    return Test-ExactExecutableIdentityCheck `
        $Check $ExpectedStage
}

function Invoke-Orchestration {
    param(
        [ValidateSet('Live', 'PreflightOnly')]
        [string]$Mode,
        $Adapter,
        $Result,
        $Paths
    )

    $decision = Get-PreflightDecision $Result.preflight
    $Result.preflight.runnable = [bool]$decision.Runnable
    foreach ($reason in @($decision.Reasons)) {
        Add-Reason $Result $reason
    }
    if (-not $decision.Runnable) {
        return Complete-SmokeResult $Result $decision.Overall
    }
    if ($Mode -ceq 'PreflightOnly') {
        Add-Reason $Result 'Read-only preflight passed; live mutation was not requested.'
        return Complete-SmokeResult $Result 'NOT RUN'
    }

    $mainAccepted = $false
    $clientCleanupAllowed = $true
    $harnessIdentityHealthy = $true
    $harnessPin = $null
    $harnessPinProperty = $Adapter.PSObject.Properties['HarnessPin']
    if ($null -ne $harnessPinProperty) {
        $harnessPin = $harnessPinProperty.Value
    }
    try {
        $Result.preflight.identityRecheck.attempted = $true
        $identity = & $Adapter.VerifyIdentity $Paths.SysPath $Result.preflight.sysSha256
        $Result.preflight.identityRecheck.success = [bool]$identity.Valid
        $Result.preflight.identityRecheck.detail = [string]$identity.Detail
        if (-not $identity.Valid) {
            Add-Reason $Result 'Exact package SYS identity changed after preflight; no service mutation occurred.'
        } else {
            $raceQuery = Invoke-AdapterServiceObservation `
                $Adapter $Result 'pre-create-query'
            $Result.live.preCreateServiceQuery.attempted = $true
            $Result.live.preCreateServiceQuery.exitCode = if (
                Test-ServiceAbsentObservation $raceQuery
            ) {
                1060
            } elseif ($raceQuery.QuerySucceeded -and
                $raceQuery.MarkedForDelete) {
                1072
            } elseif ($raceQuery.QuerySucceeded) {
                0
            } else {
                [int]$raceQuery.Win32Error
            }
            $Result.live.preCreateServiceQuery.timedOut = $false
            $Result.live.preCreateServiceQuery.containmentConfirmed = $true
            $Result.live.preCreateServiceQuery.outputFinalized = $true
            $Result.live.preCreateServiceQuery.protocolValid = (
                [bool]$raceQuery.QuerySucceeded
            )
            $Result.live.preCreateServiceQuery.success = (
                Test-ServiceAbsentObservation $raceQuery
            )
            if (-not $Result.live.preCreateServiceQuery.success) {
                $Result.live.preCreateServiceQuery.detail = 'fsring_fsd was no longer provably absent immediately before create.'
                Add-Reason $Result 'fsring_fsd appeared or could not be inspected immediately before create; it remains unowned.'
            } else {
                $createArguments = @(
                    'create',
                    $script:ServiceName,
                    'type=',
                    'filesys',
                    'start=',
                    'demand',
                    'group=',
                    'File System',
                    'binPath=',
                    $Paths.SysPath
                )
                $create = Invoke-AdapterCommand `
                    $Adapter $Result 'create' `
                    $Paths.ScPath $createArguments -Mutation
                $createSafe = Test-SafeScCommandCompletion $create
                $createExitAccepted = (
                    $createSafe -and $create.ExitCode -eq 0
                )
                Set-StepCommandEnvelope `
                    $Result.live.create $create $false
                if (-not $create.ContainmentConfirmed) {
                    $Result.ownership.createDisposition = (
                        'UNCONFIRMED_CONTAINMENT'
                    )
                    $Result.live.create.detail = (
                        'Create outcome is unknown and its process tree ' +
                        'is not confirmed empty; reconciliation and ' +
                        'cleanup were withheld.'
                    )
                    Add-Reason $Result $Result.live.create.detail
                } elseif ($null -ne $create.ExitCode -and
                    $create.ExitCode -ne 0) {
                    $Result.ownership.createDisposition = (
                        'UNOWNED_FAILED'
                    )
                    $Result.live.create.detail = (
                        'Contained sc.exe create returned known nonzero ' +
                        "exit $($create.ExitCode); regardless of other " +
                        'envelope uncertainty, the service name remains ' +
                        'unowned and no cleanup authority was acquired.'
                    )
                    Add-Reason $Result $Result.live.create.detail
                } else {
                    $Result.ownership.reconciliation.attempted = $true
                    $postCreateIdentity = $null
                    try {
                        $postCreateIdentity = (
                            & $Adapter.VerifyServiceIdentity `
                                $Paths.SysPath
                        )
                    } catch {
                        $postCreateIdentity = [pscustomobject]@{
                            Valid = $false
                            Detail = $_.Exception.Message
                        }
                    }
                    $Result.ownership.reconciliation.exact = (
                        [bool]$postCreateIdentity.Valid
                    )
                    $Result.ownership.reconciliation.detail = (
                        [string]$postCreateIdentity.Detail
                    )
                    if ($postCreateIdentity.Valid) {
                        $Result.ownership.createdByThisRun = $true
                        $Result.ownership.servicePresent = $true
                        if ($createExitAccepted) {
                            $Result.ownership.createDisposition = (
                                'CREATED'
                            )
                            $Result.live.create.success = $true
                            Add-Transition $Result `
                                'ownership-acquired' (
                                    'Contained sc.exe create returned exit ' +
                                    '0 and native SCM reconciliation ' +
                                    'proved the exact service identity.'
                                )
                        } else {
                            $Result.ownership.createDisposition = (
                                'RECONCILED_OWNED'
                            )
                            $Result.live.create.detail = (
                                'Create result was unsafe or ambiguous, ' +
                                'but native SCM reconciliation proved ' +
                                'the exact service identity; cleanup only.'
                            )
                            Add-Reason $Result $Result.live.create.detail
                            Add-Transition $Result `
                                'ownership-reconciled' (
                                    'Exact post-create native SCM identity ' +
                                    'established cleanup authority.'
                                )
                        }
                    } else {
                        $Result.ownership.createDisposition = (
                            'UNOWNED_AMBIGUOUS'
                        )
                        $Result.live.create.detail = (
                            'Post-create native SCM reconciliation did ' +
                            'not prove the exact service identity; no ' +
                            'cleanup authority was acquired.'
                        )
                        Add-Reason $Result (
                            $Result.live.create.detail + ' ' +
                            $postCreateIdentity.Detail
                        )
                    }
                }
                if ($Result.live.create.success) {
                    $start = Invoke-AdapterCommand $Adapter $Result 'start' $Paths.ScPath @('start', $script:ServiceName) -Mutation
                    $startAccepted = (
                        (Test-SafeScCommandCompletion $start) -and
                        $start.ExitCode -eq 0
                    )
                    Set-StepCommandEnvelope `
                        $Result.live.start $start $startAccepted
                    if (-not $Result.live.start.success) {
                        if (-not (Test-SafeScCommandCompletion $start)) {
                            $Result.cleanup.mutationAmbiguous = $true
                        }
                        Add-Reason $Result (
                            'Owned service start failed or was ambiguous ' +
                            "with exit $($start.ExitCode)."
                        )
                    } else {
                            $Result.live.waitRunning = Wait-ServiceCondition `
                                $Adapter $Result 'Running'
                        if (-not $Result.live.waitRunning.success) {
                            Add-Reason $Result $Result.live.waitRunning.detail
                        } else {
                            $main = Invoke-AdapterClientCommand `
                                $Adapter $Result 'main-harness' `
                                $Paths.HarnessPath @() `
                                $harnessPin 'preMain'
                            if (-not $main.ContainmentConfirmed) {
                                $clientCleanupAllowed = $false
                            }
                            $mainIdentityAccepted = (
                                Test-ExactHarnessIdentityCheck `
                                    $main.IdentityCheck 'preMain'
                            )
                            if (-not $mainIdentityAccepted) {
                                $harnessIdentityHealthy = $false
                                Add-Reason $Result (
                                    'Main harness launch lacks exact successful ' +
                                    'preMain identity evidence.'
                                )
                            }
                            $parsedMain = Test-HarnessResult $main 'Normal'
                            Set-HarnessResult $Result.mainHarness $main $parsedMain
                            if ($parsedMain.Valid -and
                                $mainIdentityAccepted) {
                                $mainAccepted = $true
                            } else {
                                if (-not $parsedMain.Valid) {
                                    Add-Reason $Result $parsedMain.Reason
                                }
                            }
                        }
                    }
                }
            }
        }
    } finally {
        if ($Result.ownership.createdByThisRun -and
            $clientCleanupAllowed -and
            $Result.containment.allClientsConfirmed -and
            -not $Result.containment.cleanupBlocked) {
            $null = Invoke-OwnedCleanup $Adapter $Result $Paths.ScPath $Paths.SysPath
        } elseif ($Result.ownership.createdByThisRun) {
            $Result.containment.cleanupBlocked = $true
            Add-Reason $Result (
                'Owned service cleanup was withheld because a client ' +
                'process tree was not confirmed empty.'
            )
        }
    }

    $absenceAccepted = $false
    $postAbsenceIdentityAccepted = $false
    if ($Result.ownership.createdByThisRun -and
        $Result.cleanup.waitAbsent.success -and
        $harnessIdentityHealthy) {
        $absence = Invoke-AdapterClientCommand `
            $Adapter $Result 'absence-harness' `
            $Paths.HarnessPath @('--expect-absent') `
            $harnessPin 'preAbsence'
        $absenceIdentityAccepted = (
            Test-ExactHarnessIdentityCheck `
                $absence.IdentityCheck 'preAbsence'
        )
        if (-not $absenceIdentityAccepted) {
            $harnessIdentityHealthy = $false
            Add-Reason $Result (
                'Absence harness launch lacks exact successful ' +
                'preAbsence identity evidence.'
            )
        }
        $parsedAbsence = Test-HarnessResult $absence 'Absent'
        Set-HarnessResult $Result.absenceHarness $absence $parsedAbsence
        if ($parsedAbsence.Valid -and $absenceIdentityAccepted) {
            $absenceAccepted = $true
        } else {
            if (-not $parsedAbsence.Valid) {
                Add-Reason $Result $parsedAbsence.Reason
            }
        }

        $absenceReachedImage = (
            $absence.ContainmentConfirmed -and
            $absence.OutputFinalized -and
            $absenceIdentityAccepted
        )
        if ($absenceReachedImage) {
            $postCheck = $null
            try {
                $postCheck = & $Adapter.RecheckHarnessIdentity `
                    $harnessPin $Paths.HarnessPath 'postAbsence'
            } catch {
                $postCheck = [pscustomobject][ordered]@{
                    Attempted = $true
                    Valid = $false
                    Stage = 'postAbsence'
                    Sha256 = $null
                    Length = [int64]0
                    Machine = [uint16]0
                    VolumeSerial = $null
                    FileId = $null
                    FinalPath = $null
                    Detail = $_.Exception.Message
                }
            }
            $Result.preflight.harnessIdentity.rechecks.postAbsence = (
                ConvertTo-HarnessIdentityCheckEvidence $postCheck
            )
            $postAbsenceIdentityAccepted = (
                Test-ExactHarnessIdentityCheck `
                    $postCheck 'postAbsence'
            )
            if (-not $postAbsenceIdentityAccepted) {
                Add-Reason $Result (
                    'Post-absence retained harness identity recheck failed.'
                )
            }
        }
    }

    if ($mainAccepted -and $Result.ownership.createdByThisRun -and
        $Result.cleanup.success -and $absenceAccepted -and
        $postAbsenceIdentityAccepted -and
        $Result.ownership.createDisposition -ceq 'CREATED' -and
        -not $Result.cleanup.mutationAmbiguous) {
        return Complete-SmokeResult $Result 'PASS'
    }
    return Complete-SmokeResult $Result 'FAIL'
}

function Resolve-LiteralFullPath {
    param(
        [string]$Value,
        [string]$DefaultValue
    )

    $selected = $Value
    if ([string]::IsNullOrWhiteSpace($selected)) {
        $selected = $DefaultValue
    }
    if (-not [System.IO.Path]::IsPathRooted($selected)) {
        $selected = Join-Path ((Get-Location).Path) $selected
    }
    return [System.IO.Path]::GetFullPath($selected)
}

function ConvertTo-HarnessIdentityCheckEvidence {
    param($Check)

    if ($null -eq $Check) {
        return $null
    }
    return [ordered]@{
        attempted = [bool]$Check.Attempted
        valid = [bool]$Check.Valid
        stage = [string]$Check.Stage
        sha256 = $Check.Sha256
        size = [int64]$Check.Length
        machine = ('0x{0:X4}' -f [uint16]$Check.Machine)
        volumeSerial = $Check.VolumeSerial
        fileId = $Check.FileId
        finalPath = $Check.FinalPath
        detail = $Check.Detail
    }
}

function Initialize-ScPin {
    param(
        $Adapter,
        $Result,
        $Paths
    )

    $facts = $Result.preflight
    $pin = $null
    try {
        $pin = [FsringNativeSystemTool]::OpenScPin()
        $initial = $pin.Recheck(
            $pin.FinalPath,
            'sc-initial'
        )
        if (-not (Test-ExactExecutableIdentityCheck `
            $initial 'sc-initial')) {
            throw 'The initial retained sc.exe identity check failed.'
        }
        $Paths.ScPath = $pin.FinalPath
        $Adapter.ScPinState.Pin = $pin
        $facts.scIdentity.sha256 = $pin.ObservedSha256
        $facts.scIdentity.size = [int64]$pin.Length
        $facts.scIdentity.machine = (
            '0x{0:X4}' -f [uint16]$pin.Machine
        )
        $facts.scIdentity.volumeSerial = $pin.VolumeSerial
        $facts.scIdentity.fileId = $pin.FileId
        $facts.scIdentity.finalPath = $pin.FinalPath
        $facts.scIdentity.handleInheritable = (
            [bool]$pin.HandleInheritable
        )
        $facts.scIdentity.initial = (
            ConvertTo-HarnessIdentityCheckEvidence $initial
        )
        $facts.scIdentity.detail = (
            'Native System32 sc.exe is retained read-only and ' +
            'reparse-free through final JSON flush.'
        )
        $facts.scPinValid = $true
        [void]$script:RetainedScPins.Add($pin)
        return $true
    } catch {
        $facts.scPinValid = $false
        $facts.scIdentity.detail = $_.Exception.Message
        if ($null -ne $pin) {
            $pin.Dispose()
        }
        return $false
    }
}

function Initialize-HarnessPin {
    param(
        $Adapter,
        $Result,
        $Paths,
        [string]$ExpectedSha256
    )

    $facts = $Result.preflight
    $facts.harnessIdentity.expectedSha256 = $ExpectedSha256
    $pin = $null
    try {
        $pin = [FsringHarnessPin]::Open(
            $Paths.HarnessPath,
            $ExpectedSha256
        )
        $initial = $pin.Recheck($Paths.HarnessPath, 'initial')
        if (-not $initial.Valid) {
            throw $initial.Detail
        }
        $facts.harnessIdentity.observedSha256 = $pin.ObservedSha256
        $facts.harnessIdentity.size = [int64]$pin.Length
        $facts.harnessIdentity.machine = (
            '0x{0:X4}' -f [uint16]$pin.Machine
        )
        $facts.harnessIdentity.volumeSerial = $pin.VolumeSerial
        $facts.harnessIdentity.fileId = $pin.FileId
        $facts.harnessIdentity.finalPath = $pin.FinalPath
        $facts.harnessIdentity.handleInheritable = (
            [bool]$pin.HandleInheritable
        )
        $facts.harnessIdentity.initial = (
            ConvertTo-HarnessIdentityCheckEvidence $initial
        )
        $facts.harnessIdentity.detail = (
            'Exact retained read-only harness pin initialized before ' +
            'external process invocation.'
        )
        $facts.harnessPinValid = $true
        $Adapter.HarnessPin = $pin
        [void]$script:RetainedHarnessPins.Add($pin)
        return $true
    } catch {
        $facts.harnessPinValid = $false
        $facts.harnessIdentity.detail = $_.Exception.Message
        if ($null -ne $pin) {
            $pin.Dispose()
        }
        return $false
    }
}

function Invoke-ReadOnlyPreflight {
    param(
        $Adapter,
        $Result,
        $Paths,
        [string]$ExpectedSha256
    )

    $facts = $Result.preflight
    $facts.hostWindows = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
    if ($facts.hostWindows) {
        try {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($identity)
            $facts.elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch {
            $facts.elevated = $false
        }
    }
    Invoke-ReadinessFactCollection $Adapter $facts
    $serviceInspectionEligible = (
        Test-ServiceInspectionEligible $facts
    )
    if ($serviceInspectionEligible) {
        [void](Initialize-ScPin $Adapter $Result $Paths)
    } else {
        $facts.scIdentity.detail = (
            'sc.exe pinning and service inspection were skipped because ' +
            'the host is not proven Windows 10+ native AMD64 in a ' +
            '64-bit process.'
        )
    }

    $facts.packageDirectoryPresent = Test-Path -LiteralPath $Paths.PackageDirectory -PathType Container
    $facts.infPresent = Test-Path -LiteralPath $Paths.InfPath -PathType Leaf
    $facts.sysPresent = Test-Path -LiteralPath $Paths.SysPath -PathType Leaf
    $facts.catPresent = Test-Path -LiteralPath $Paths.CatPath -PathType Leaf
    $facts.harnessPresent = Test-Path -LiteralPath $Paths.HarnessPath -PathType Leaf
    $facts.verifierScriptPresent = Test-Path -LiteralPath $Paths.VerifierPath -PathType Leaf
    $facts.powershellPresent = Test-Path -LiteralPath $Paths.PowerShellPath -PathType Leaf
    $facts.scPresent = (
        $facts.hostWindows -and
        $facts.scPinValid -and
        -not [string]::IsNullOrWhiteSpace($Paths.ScPath) -and
        (Test-Path -LiteralPath $Paths.ScPath -PathType Leaf)
    )
    $facts.artifacts = [ordered]@{
        inf = [ordered]@{ path = $Paths.InfPath; present = $facts.infPresent }
        sys = [ordered]@{ path = $Paths.SysPath; present = $facts.sysPresent }
        cat = [ordered]@{ path = $Paths.CatPath; present = $facts.catPresent }
        harness = [ordered]@{ path = $Paths.HarnessPath; present = $facts.harnessPresent }
        verifier = [ordered]@{ path = $Paths.VerifierPath; present = $facts.verifierScriptPresent }
    }

    if ($facts.harnessPresent) {
        [void](Initialize-HarnessPin `
            $Adapter $Result $Paths $ExpectedSha256)
    } else {
        $facts.harnessIdentity.expectedSha256 = $ExpectedSha256
        $facts.harnessIdentity.detail = (
            'Exact harness path is absent; pin initialization was not attempted.'
        )
    }

    if ($facts.sysPresent) {
        try {
            $machine = Get-PeMachine $Paths.SysPath
            $facts.sysMachine = ('0x{0:X4}' -f $machine)
            $facts.sysAmd64 = ($machine -eq 0x8664)
            $facts.sysSha256 = (Get-FileHash -LiteralPath $Paths.SysPath -Algorithm SHA256).Hash
        } catch {
            $facts.sysMachine = 'INVALID'
            $facts.sysAmd64 = $false
        }
    }

    if ($facts.packageDirectoryPresent -and $facts.infPresent -and $facts.sysPresent -and
        $facts.catPresent -and $facts.harnessPinValid -and
        $facts.verifierScriptPresent -and $facts.powershellPresent) {
        $verifierCommand = Invoke-AdapterClientCommand `
            $Adapter $Result 'package-verifier' $Paths.PowerShellPath @(
            '-NoProfile',
            '-ExecutionPolicy',
            'Bypass',
            '-File',
            $Paths.VerifierPath,
            $Paths.PackageDirectory
        ) $null 'verifier'
        $verifier = Test-PackageVerifierResult $verifierCommand
        $facts.verifierValid = [bool]$verifier.Valid
        $facts.verifierExitCode = $verifierCommand.ExitCode
        $facts.verifierOverall = $verifier.Overall
        $facts.trustReady = [bool]$verifier.TrustReady
        $facts.verifier = [ordered]@{
            path = $Paths.VerifierPath
            attempted = $true
            valid = [bool]$verifier.Valid
            exitCode = $verifierCommand.ExitCode
            overall = $verifier.Overall
            trustReady = [bool]$verifier.TrustReady
            detail = $verifier.Reason
        }
        if (-not $verifier.Valid) {
            return
        }
    } else {
        $facts.verifier = [ordered]@{
            path = $Paths.VerifierPath
            attempted = $false
            valid = $false
            exitCode = $null
            overall = $null
            trustReady = $false
            detail = 'Required exact paths were absent.'
        }
    }

    if ($serviceInspectionEligible -and $facts.scPresent -and
        $facts.harnessPinValid) {
        $serviceQuery = Invoke-AdapterServiceObservation `
            $Adapter $Result 'preflight-service-query'
        $facts.serviceChecked = [bool]$serviceQuery.QuerySucceeded
        $facts.serviceAbsent = (
            Test-ServiceAbsentObservation $serviceQuery
        )
        $facts.serviceQueryExitCode = if (
            $facts.serviceAbsent
        ) {
            1060
        } elseif ($serviceQuery.QuerySucceeded -and
            $serviceQuery.MarkedForDelete) {
            1072
        } elseif ($serviceQuery.QuerySucceeded) {
            0
        } else {
            [int]$serviceQuery.Win32Error
        }
        $facts.service = [ordered]@{
            name = $script:ServiceName
            checked = $facts.serviceChecked
            absent = $facts.serviceAbsent
            exitCode = $facts.serviceQueryExitCode
        }
    } else {
        $facts.service = [ordered]@{
            name = $script:ServiceName
            checked = $false
            absent = $false
            exitCode = $null
        }
    }
}

function Write-FinalJsonAndDispose {
    param(
        $Result,
        [System.IO.TextWriter]$Writer,
        [object[]]$Resources
    )

    try {
        $json = $Result | ConvertTo-Json -Depth 12 -Compress
        $Writer.WriteLine($json)
        $Writer.Flush()
    } finally {
        foreach ($resource in @($Resources)) {
            if ($null -eq $resource) {
                continue
            }
            try {
                if ($resource -is [IDisposable] -or
                    $null -ne $resource.PSObject.Methods['Dispose']) {
                    [void]$resource.Dispose()
                }
            } catch {
                # Final evidence is already durably flushed. Disposal is the
                # kill-on-close/read-pin fallback and remains best effort.
            }
        }
    }
}

function Write-FinalSmokeResult {
    param($Result)

    $resources = @(
        @($script:RetainedClientLeases) +
        @($script:RetainedHarnessPins) +
        @($script:RetainedScPins)
    )
    $script:RetainedClientLeases.Clear()
    $script:RetainedHarnessPins.Clear()
    $script:RetainedScPins.Clear()
    Write-FinalJsonAndDispose `
        $Result ([Console]::Out) $resources
}

function Assert-SelfTest {
    param([bool]$Condition, [string]$Message)

    if (-not $Condition) {
        throw $Message
    }
}

$script:ValidNormalHarnessJson = '{"schema":"fsring-control-smoke/v1","overall":"PASS","exitCode":0,"probes":[{"name":"root-open","outcome":"PASS","expected":null,"actual":null},{"name":"trailing-open","outcome":"PASS","expected":2,"actual":2},{"name":"unknown-ioctl","outcome":"PASS","expected":1,"actual":1},{"name":"setup","outcome":"PASS","expected":50,"actual":50},{"name":"donate-short","outcome":"PASS","expected":87,"actual":87},{"name":"donate-wrong-version","outcome":"PASS","expected":1306,"actual":1306},{"name":"donate","outcome":"PASS","expected":50,"actual":50},{"name":"child-inherited-handle","outcome":"PASS","expected":5,"actual":5},{"name":"parent-handle-after-child","outcome":"PASS","expected":50,"actual":50}],"reasons":[]}'
$script:ValidAbsentHarnessJson = '{"schema":"fsring-control-smoke/v1","overall":"PASS","exitCode":0,"probes":[{"name":"device-absent","outcome":"PASS","expected":2,"actual":2}],"reasons":[]}'
$script:FailingNormalHarnessJson = '{"schema":"fsring-control-smoke/v1","overall":"FAIL","exitCode":1,"probes":[{"name":"root-open","outcome":"FAIL","expected":null,"actual":2},{"name":"trailing-open","outcome":"NOT RUN","expected":2,"actual":null},{"name":"unknown-ioctl","outcome":"NOT RUN","expected":1,"actual":null},{"name":"setup","outcome":"NOT RUN","expected":50,"actual":null},{"name":"donate-short","outcome":"NOT RUN","expected":87,"actual":null},{"name":"donate-wrong-version","outcome":"NOT RUN","expected":1306,"actual":null},{"name":"donate","outcome":"NOT RUN","expected":50,"actual":null},{"name":"child-inherited-handle","outcome":"NOT RUN","expected":5,"actual":null},{"name":"parent-handle-after-child","outcome":"NOT RUN","expected":50,"actual":null}],"reasons":["root-open failed"]}'


function New-C4TestIdentityJson {
    param([string]$MountLo = '0000000000000003')

    return (
        '{"bootInstanceId":{"lo":"0x0000000000000001","hi":"0x0000000000000002"},' +
        '"mountId":{"lo":"0x' + $MountLo + '","hi":"0x0000000000000004"},' +
        '"sessionEpoch":"0x0000000000000005"}'
    )
}

function New-C4TestProbeJson {
    param([string]$Name, [string]$Outcome, [bool]$WithActual, [bool]$MutateActual)

    $identity = ConvertTo-C4OracleObject (New-C4TestIdentityJson)
    $expectedObj = Get-C4IndependentExpectedOracle $Name $identity
    $expected = ConvertTo-C4CanonicalJson $expectedObj
    $actual = 'null'
    if ($WithActual) {
        if ($MutateActual) {
            $actual = '{"kind":"facts","values":{"observed":false}}'
        } else {
            $actual = $expected
        }
    }
    return (
        '{"name":"' + $Name + '","outcome":"' + $Outcome +
        '","expected":' + $expected + ',"actual":' + $actual + '}'
    )
}

function New-C4TestReport {
    param(
        [switch]$MutateFirstActual,
        [switch]$NotRunLast,
        [switch]$NullIdentity,
        [string]$Reason
    )

    $probes = @()
    for ($index = 0; $index -lt $script:C4ProbeRoster.Count; $index++) {
        $name = $script:C4ProbeRoster[$index]
        $mutate = ($MutateFirstActual.IsPresent -and $index -eq 0)
        $withActual = -not ($NotRunLast.IsPresent -and
            $index -eq ($script:C4ProbeRoster.Count - 1))
        $outcome = if ($withActual) { 'PASS' } else { 'NOT RUN' }
        $probes += (New-C4TestProbeJson $name $outcome $withActual $mutate)
    }
    $identity = if ($NullIdentity.IsPresent) { 'null' } else { New-C4TestIdentityJson }
    $reasons = if ($Reason) { '["' + $Reason + '"]' } else { '[]' }
    return (
        '{"schema":"fsring-control-smoke/v2","overall":"PASS","exitCode":0,"identity":' +
        $identity + ',"probes":[' + ($probes -join ',') + '],"reasons":' + $reasons + '}'
    )
}

function New-C4TestStagedFrame {
    param([string]$Nonce)

    $probes = @()
    $range = $script:C4PrivateProbeRanges['STAGED']
    foreach ($name in @($script:C4ProbeRoster[$range[0]..$range[1]])) {
        $probes += (New-C4TestProbeJson $name 'PASS' $true $false)
    }
    $json = (
        '{"schema":"fsring-c4-worker/v1","sequence":1,"stage":"STAGED","nonce":"' + $Nonce +
        '","rootIdentity":' + (New-C4TestIdentityJson) +
        ',"disposableIdentity":' + (New-C4TestIdentityJson '0000000000000007') +
        ',"vdoNativeName":"\\Device\\FsRingVolume-0000000000000003-0000000000000004"' +
        ',"probes":[' + ($probes -join ',') + '],"events":[' +
        (New-C4WorkerEventJson 'SESSION_PUBLISHED' (ConvertTo-C4OracleObject (New-C4TestIdentityJson)) 0) +
        '],"reasons":[]}'
    )
    return (ConvertFrom-Json $json)
}

function New-C4TestLiveCleanedFrame {
    param([string]$Nonce, [string]$DosName)

    $probes = @()
    $range = $script:C4PrivateProbeRanges['LIVE_CLEANED']
    $cleanupFacts = '{"pendingEnterCount":"0x00000000","aliasCount":"0x00000000","ownedHandleCount":"0x00000000","completedOnce":true}'
    foreach ($name in @($script:C4ProbeRoster[$range[0]..$range[1]])) {
        if ($name -ceq 'cleanup-close') {
            $probes += (
                '{"name":"cleanup-close","outcome":"PASS","expected":{"kind":"facts","values":' +
                $cleanupFacts + '},"actual":{"kind":"facts","values":' + $cleanupFacts + '}}'
            )
        } else {
            $probes += (New-C4TestProbeJson $name 'PASS' $true $false)
        }
    }
    $json = (
        '{"schema":"fsring-c4-worker/v1","sequence":3,"stage":"LIVE_CLEANED","nonce":"' + $Nonce +
        '","rootIdentity":' + (New-C4TestIdentityJson) +
        ',"disposableIdentity":' + (New-C4TestIdentityJson '0000000000000007') +
        ',"vdoNativeName":"\\Device\\FsRingVolume-0000000000000003-0000000000000004"' +
        ',"dosName":"' + $DosName.Replace('\', '\\') + '"' +
        ',"probes":[' + ($probes -join ',') +
        '],"events":[' +
        (New-C4WorkerEventJson 'MOUNT_PUBLISHED' (ConvertTo-C4OracleObject (New-C4TestIdentityJson)) 0) + ',' +
        (New-C4WorkerEventJson 'SESSION_FENCED' (ConvertTo-C4OracleObject (New-C4TestIdentityJson)) 3) +
        '],"cleanup":' + $cleanupFacts +
        ',"unloadSeed":{"formerAliasRangesFree":true,"ownedHandlesClosed":true},"reasons":[]}'
    )
    return (ConvertFrom-Json $json)
}

function New-C4TestPostUnloadFrame {
    param([string]$Nonce, [string]$DosName)

    $probe = (New-C4TestProbeJson 'bootcontext-persistent' 'PASS' $true $false)
    $obs = '{"providerOpenNtstatus":"0xC0000034","fscontrolOpenNtstatus":"0xC0000034","vdoOpenNtstatus":"0xC0000034"}'
    $json = (
        '{"schema":"fsring-c4-worker/v1","sequence":4,"stage":"POST_UNLOAD","nonce":"' + $Nonce +
        '","rootIdentity":' + (New-C4TestIdentityJson) +
        ',"vdoNativeName":"\\Device\\FsRingVolume-0000000000000003-0000000000000004"' +
        ',"dosName":"' + $DosName.Replace('\', '\\') + '"' +
        ',"unloadObservation":' + $obs +
        ',"probes":[' + $probe + '],"reasons":[]}'
    )
    return (ConvertFrom-Json $json)
}

function New-C4LiveFakeAdapters {
    param(
        [string]$AttemptId,
        [int]$ProcessId = 4660,
        [switch]$MalformedAfterMutation
    )

    $nonce = '0123456789ABCDEF0123456789ABCDEF'
    $dos = Get-C4OwnedDosName $ProcessId $AttemptId
    $staged = New-C4TestStagedFrame $nonce
    $live = New-C4TestLiveCleanedFrame $nonce $dos
    $post = New-C4TestPostUnloadFrame $nonce $dos
    $written = New-Object System.Collections.ArrayList
    $mutated = New-Object System.Collections.ArrayList
    $contained = New-Object System.Collections.ArrayList
    return [pscustomobject]@{
        StartWorker = {
            [pscustomobject]@{
                ProcessId = $ProcessId
                Arguments = @('--c4-live-worker', '--nonce', $nonce)
            }
        }.GetNewClosure()
        ReadFrame = {
            param([string]$Stage)
            if ($MalformedAfterMutation -and $Stage -ceq 'STAGED') {
                return [pscustomobject]@{ schema = 'nope' }
            }
            switch ($Stage) {
                'STAGED' { return $staged }
                'LIVE_CLEANED' { return $live }
                default { return $null }
            }
        }.GetNewClosure()
        WriteFrame = {
            param($Frame)
            [void]$written.Add($Frame)
            return $true
        }.GetNewClosure()
        ContainWorker = {
            [void]$contained.Add('contain')
            [pscustomobject]@{ Success = $true }
        }.GetNewClosure()
        PostUnload = { param($Root, $Vdo, $Dos) $post }.GetNewClosure()
        Mutate = {
            param($Operation, $Target)
            [void]$mutated.Add($Operation)
            [pscustomobject]@{ Success = $true; Win32Code = 0; Target = $Target }
        }.GetNewClosure()
        DosLinkQueryWin32 = [uint32]2
        Written = $written
        Mutated = $mutated
        Contained = $contained
    }
}

function New-C4CleanupAcceptedInputs {
    param(
        [string]$Root,
        [string]$AttemptId,
        [int]$ProcessId = 4660
    )

    $service = Get-C4OwnedServiceName $AttemptId
    $dos = Get-C4OwnedDosName $ProcessId $AttemptId
    $header = New-C4DiagnosticsHeader `
        $AttemptId ('a' * 40) ('b' * 40) ('ab' * 32) ('d' * 64) ('e' * 64) `
        $ProcessId $service $dos ('f' * 64)
    $journalPath = Join-Path $Root 'diagnostics.sidecar.jsonl'
    [IO.File]::WriteAllText($journalPath, ((ConvertTo-C4CanonicalJson $header) + "`n"), (New-Object System.Text.UTF8Encoding $false))
    $proof = [ordered]@{
        schema = $script:C4ProcessContainmentSchema
        version = 1
        attemptId = $AttemptId
        captureRole = 'LIVE'
        childProcessId = $ProcessId
        createdSuspended = $true
        jobKillOnClose = $true
        breakawayDisabled = $true
        jobAssignedBeforeResume = $true
        mainThreadResumed = $true
        terminationAttempted = $true
        treeExited = $true
        streamsClosed = $true
        status = 'PASS'
    }
    $proofBytes = Get-C4Utf8NoBom ((ConvertTo-C4CanonicalJson $proof) + "`n")
    $proofPath = Join-Path $Root 'containment.json'
    [IO.File]::WriteAllBytes($proofPath, $proofBytes)
    return [pscustomobject]@{
        Service = $service
        Dos = $dos
        JournalPath = $journalPath
        ProofPath = $proofPath
        ProofHash = (Get-C4Sha256Hex $proofBytes)
        ManifestSha = ('ab' * 32)
    }
}

function Invoke-C4CleanupFixture {
    param(
        [string]$Root,
        [string]$AttemptId,
        $Inputs,
        $Adapters
    )

    return Invoke-C4CleanupOnlyCore `
        -AttemptId $AttemptId `
        -CandidateManifestPath (Join-Path $Root 'candidate.json') `
        -ExpectedCandidateManifestSha256 $Inputs.ManifestSha `
        -DiagnosticsJournalPath $Inputs.JournalPath `
        -ContainmentProofPath $Inputs.ProofPath `
        -ExpectedContainmentProofSha256 $Inputs.ProofHash `
        -CleanupEvidencePath (Join-Path $Root 'cleanup.json') `
        -OwnedServiceName $Inputs.Service `
        -OwnedDosName $Inputs.Dos `
        -Adapters $Adapters
}

function New-FakeResult {
    param(
        [int]$ExitCode,
        [string[]]$Stdout = @(),
        [string[]]$Stderr = @()
    )

    return New-NativeCommandResult $ExitCode $Stdout $Stderr
}

function New-FakeClientResult {
    param(
        $ExitCode,
        [string[]]$Stdout = @(),
        [string[]]$Stderr = @(),
        [bool]$TimedOut = $false,
        [bool]$ContainmentConfirmed = $true,
        [bool]$ProtocolValid = $true,
        [bool]$OutputTruncated = $false,
        [bool]$OutputFinalized = $true,
        $Lease = $null,
        $IdentityCheck = $null
    )

    return [pscustomobject][ordered]@{
        ExitCode = $ExitCode
        Stdout = @($Stdout)
        Stderr = @($Stderr)
        TimedOut = $TimedOut
        ContainmentConfirmed = $ContainmentConfirmed
        OutputTruncated = $OutputTruncated
        StdoutTruncated = $OutputTruncated
        StderrTruncated = $false
        StdoutByteCount = 0
        StderrByteCount = 0
        StdoutTotalByteCount = 0
        StderrTotalByteCount = 0
        ProtocolValid = $ProtocolValid
        OutputFinalized = $OutputFinalized
        Error = if ($TimedOut) {
            'The monotonic whole-job deadline expired.'
        } else {
            $null
        }
        Lease = $Lease
        IdentityCheck = $IdentityCheck
    }
}

function New-FakeHarnessIdentityCheck {
    param(
        [string]$Stage,
        [bool]$Valid
    )

    return [pscustomobject][ordered]@{
        Attempted = $true
        Valid = $Valid
        Stage = $Stage
        Sha256 = ('A' * 64)
        Length = [int64]4096
        Machine = [uint16]0x8664
        VolumeSerial = ('B' * 16)
        FileId = ('C' * 32)
        FinalPath = 'C:\harness.exe'
        Detail = if ($Valid) {
            'Scripted harness identity PASS.'
        } else {
            'Scripted harness identity FAIL.'
        }
    }
}

function New-FakePinnedHarnessResult {
    param(
        [ValidateSet('Normal', 'Absent')]
        [string]$Kind,
        $IdentityCheck
    )

    $json = $script:ValidNormalHarnessJson
    if ($Kind -ceq 'Absent') {
        $json = $script:ValidAbsentHarnessJson
    }
    return New-FakeClientResult 0 @($json) @() `
        $false $true $true $false $true $null $IdentityCheck
}

function New-TestVerifierObject {
    param(
        [ValidateSet('Trusted', 'Untrusted', 'LocallyTrusted')]
        [string]$State
    )

    $untrusted = ($State -ceq 'Untrusted')
    $locallyTrusted = ($State -ceq 'LocallyTrusted')
    $warnings = @()
    if ($untrusted) {
        $warnings = @(
            'Exact catalog membership and WDRLocalTestCert signature integrity are present, but the signing root is not trusted locally; package is not load-ready.'
        )
    }
    if ($locallyTrusted) {
        $warnings = @($script:LocallyTrustedTestRootWarning)
    }
    $exitCode = if ($untrusted -or $locallyTrusted) { 1 } else { 0 }
    $mode = if ($untrusted) {
        'UntrustedTestRoot'
    } elseif ($locallyTrusted) {
        'TestSignedLocallyTrusted'
    } else {
        'Trusted'
    }
    return [ordered]@{
        schema = 'fsring-package-verifier/v1'
        overall = 'PASS'
        errors = @()
        warnings = $warnings
        trustReady = (-not $untrusted)
        artifacts = [ordered]@{
            'fsring_fsd.inf' = $true
            'fsring_fsd.sys' = $true
            'fsring_fsd.cat' = $true
        }
        tools = [ordered]@{
            infverif = [ordered]@{
                path = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\infverif.exe'
                productVersion = '10.0.26100.0'
                fileVersion = '10.0.26100.2454'
                exitCode = 0
            }
            signtool = [ordered]@{
                path = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
                productVersion = '10.0.26100.0'
                fileVersion = '10.0.26100.2454'
                policy = 'KernelMode'
                sysExitCode = $exitCode
                sysMode = $mode
                catExitCode = $exitCode
                catMode = $mode
                catalogMemberExitCode = $exitCode
                catalogMemberMode = $mode
            }
            catalogMembership = [ordered]@{
                mechanism = 'Windows CryptCAT member-hash'
                valid = $true
                memberHash = ('0123456789ABCDEF' * 4)
            }
        }
    }
}

function ConvertTo-TestVerifierJson {
    param($Object)

    return ($Object | ConvertTo-Json -Depth 8 -Compress)
}

function Get-TestVerifierContainer {
    param(
        $Object,
        [ValidateSet('top', 'artifacts', 'tools', 'infverif', 'signtool', 'catalogMembership')]
        [string]$Name
    )

    switch ($Name) {
        'top' { return $Object }
        'artifacts' { return $Object.artifacts }
        'tools' { return $Object.tools }
        'infverif' { return $Object.tools.infverif }
        'signtool' { return $Object.tools.signtool }
        'catalogMembership' { return $Object.tools.catalogMembership }
        default { throw "Unknown test verifier container '$Name'." }
    }
}

function New-TestStructuralFacts {
    $seed = New-SmokeResult 'Live' 'C:\package' 'C:\harness.exe'
    $facts = $seed.preflight
    $facts.hostWindows = $true
    $facts.hostX64 = $true
    $facts.elevated = $true
    $facts.packageDirectoryPresent = $true
    $facts.infPresent = $true
    $facts.sysPresent = $true
    $facts.catPresent = $true
    $facts.harnessPresent = $true
    $facts.harnessPinValid = $true
    $facts.verifierScriptPresent = $true
    $facts.powershellPresent = $true
    $facts.scPresent = $true
    $facts.sysMachine = '0x8664'
    $facts.sysAmd64 = $true
    $facts.sysSha256 = '001122'
    $facts.verifierValid = $true
    $facts.verifierExitCode = 0
    $facts.verifierOverall = 'PASS'
    $facts.trustReady = $true
    $facts.serviceChecked = $true
    $facts.serviceAbsent = $true
    $facts.serviceQueryExitCode = 1060
    return $facts
}

function New-TestFacts {
    $facts = New-TestStructuralFacts
    $adapter = New-TestReadinessAdapter (
        New-TestNativeReadinessObservation
    ) (
        New-TestBcdObservation
    )
    Invoke-ReadinessFactCollection $adapter $facts
    return $facts
}

function New-TestNativeReadinessObservation {
    param(
        [uint32]$OsMajor = 10,
        [uint32]$OsMinor = 0,
        [uint32]$OsBuild = 19045,
        [uint32]$CodeIntegrityOptions = 3,
        [Guid]$BootIdentifier = [Guid]'01234567-89ab-cdef-0123-456789abcdef'
    )

    return [pscustomobject][ordered]@{
        RtlStatus = [int32]0
        OsInputSize = [uint32]276
        OsReturnedSize = [uint32]276
        OsPlatformId = [uint32]2
        OsMajor = $OsMajor
        OsMinor = $OsMinor
        OsBuild = $OsBuild
        SystemInfoSize = [uint32]48
        NativeArchitecture = [uint16]9
        Is64BitProcess = [bool]$true
        CodeIntegrityStatus = [int32]0
        CodeIntegrityBufferSize = [uint32]8
        CodeIntegrityInputLength = [uint32]8
        CodeIntegrityReturnLength = [uint32]8
        CodeIntegrityReturnedLength = [uint32]8
        CodeIntegrityOptions = $CodeIntegrityOptions
        BootEnvironmentStatus = [int32]0
        BootEnvironmentBufferSize = [uint32]32
        BootEnvironmentReturnLength = [uint32]32
        BootIdentifier = $BootIdentifier
        FirmwareType = [uint32]2
        BootFlags = [uint64]0
    }
}

function New-TestBcdObservation {
    param(
        [Guid]$BootIdentifier = [Guid]'01234567-89ab-cdef-0123-456789abcdef',
        [ValidateSet('Absent', 'False', 'True')]
        [string]$Configured = 'True'
    )

    $identifier = $BootIdentifier.ToString('B')
    $elementTypes = @([uint32]0x12000004)
    $getElementAttempted = $false
    $getElementReturn = $null
    $elementClass = $null
    $elementType = $null
    $elementObjectId = $null
    $elementStoreFilePath = $null
    $elementBoolean = $null
    if ($Configured -cne 'Absent') {
        $elementTypes = @([uint32]0x12000004, [uint32]0x16000049)
        $getElementAttempted = $true
        $getElementReturn = [bool]$true
        $elementClass = 'BcdBooleanElement'
        $elementType = [uint32]0x16000049
        $elementObjectId = $identifier
        $elementStoreFilePath = ''
        $elementBoolean = [bool]($Configured -ceq 'True')
    }

    return [pscustomobject][ordered]@{
        ProviderSucceeded = [bool]$true
        OpenStoreReturn = [bool]$true
        StoreClass = 'BcdStore'
        StoreFilePath = ''
        OpenObjectReturn = [bool]$true
        ObjectClass = 'BcdObject'
        ObjectId = $identifier
        ObjectStoreFilePath = ''
        ObjectType = [uint32]0x10200003
        EnumerateElementTypesReturn = [bool]$true
        ElementTypes = [object[]]$elementTypes
        GetElementAttempted = [bool]$getElementAttempted
        GetElementReturn = $getElementReturn
        ElementClass = $elementClass
        ElementType = $elementType
        ElementObjectId = $elementObjectId
        ElementStoreFilePath = $elementStoreFilePath
        ElementBoolean = $elementBoolean
    }
}

function New-TestReadinessAdapter {
    param(
        $NativeObservation,
        $BcdObservation,
        [bool]$ThrowOnBcd = $false
    )

    $state = [pscustomobject]@{
        NativeCalls = 0
        BcdCalls = 0
        MutatingCalls = 0
        BootIdentifierArgument = $null
    }
    $nativeState = [pscustomobject]@{ Observation = $NativeObservation }
    $readNative = {
        $state.NativeCalls++
        return $nativeState.Observation
    }.GetNewClosure()
    $bcdState = [pscustomobject]@{
        Observation = $BcdObservation
        Throw = $ThrowOnBcd
    }
    $readBcd = {
        param([Guid]$BootIdentifier)

        $state.BcdCalls++
        $state.BootIdentifierArgument = $BootIdentifier
        if ($bcdState.Throw) {
            throw 'BCD adapter must not have been called.'
        }
        return $bcdState.Observation
    }.GetNewClosure()
    return [pscustomobject]@{
        ReadNativeReadiness = $readNative
        ReadBootConfiguration = $readBcd
        State = $state
    }
}

function Invoke-TestReadinessCollection {
    param(
        $NativeObservation,
        $BcdObservation,
        [bool]$Elevated = $true,
        [bool]$HostWindows = $true,
        [bool]$ThrowOnBcd = $false
    )

    $facts = New-TestStructuralFacts
    $facts.hostWindows = $HostWindows
    $facts.elevated = $Elevated
    $adapter = New-TestReadinessAdapter $NativeObservation $BcdObservation $ThrowOnBcd
    Invoke-ReadinessFactCollection $adapter $facts
    return [pscustomobject]@{
        Facts = $facts
        Adapter = $adapter
    }
}

function Assert-TestReadinessNotRunnable {
    param($Facts, [string]$Message)

    $run = Invoke-TestWorkflow $Facts 'Live' @()
    Assert-SelfTest (
        $run.Result.overall -ceq 'NOT RUN' -and
        -not $run.Result.preflight.runnable -and
        $run.Result.ownership.mutationAttempts -eq 0 -and
        $run.Result.commands.Count -eq 0
    ) $Message
}

function Assert-TestReadinessRunnable {
    param($Facts, [string]$Message)

    $run = Invoke-TestWorkflow $Facts 'PreflightOnly' @()
    Assert-SelfTest (
        $run.Result.overall -ceq 'NOT RUN' -and
        $run.Result.preflight.runnable -and
        $run.Result.ownership.mutationAttempts -eq 0 -and
        $run.Result.commands.Count -eq 0
    ) $Message
}

function New-TestPaths {
    return [pscustomobject]@{
        PackageDirectory = 'C:\package'
        InfPath = 'C:\package\fsring_fsd.inf'
        SysPath = 'C:\package\fsring_fsd.sys'
        CatPath = 'C:\package\fsring_fsd.cat'
        HarnessPath = 'C:\harness.exe'
        VerifierPath = 'C:\repo\driver\scripts\verify_fsring_package.ps1'
        PowerShellPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        ScPath = 'C:\Windows\System32\sc.exe'
    }
}

function Invoke-TestWorkflow {
    param(
        $Facts,
        [ValidateSet('Live', 'PreflightOnly')]
        [string]$Mode,
        [object[]]$Responses,
        [bool]$IdentityValid = $true,
        [int]$PollAttempts = 2,
        [ValidateSet(
            'Pass',
            'Fail',
            'Throw',
            'PassThenFail',
            'PassThenThrow'
        )]
        [string]$ServiceIdentityMode = 'Pass',
        [bool]$SleepThrows = $false,
        [bool]$PostIdentityValid = $true
    )

    $paths = New-TestPaths
    $result = New-SmokeResult $Mode $paths.PackageDirectory $paths.HarnessPath
    $result.preflight = $Facts
    $adapter = New-ScriptedAdapter `
        $Responses $IdentityValid $PollAttempts `
        $ServiceIdentityMode $SleepThrows $PostIdentityValid
    $completed = Invoke-Orchestration $Mode $adapter $result $paths
    return [pscustomobject]@{
        Result = $completed
        Adapter = $adapter
    }
}

function New-AbsentServiceResult {
    return New-FakeResult 1060
}

function New-ServiceStateResult {
    param([int]$StateCode)

    return New-FakeResult 0 @(
        'TYPE               : 2  FILE_SYSTEM_DRIVER',
        "STATE              : $StateCode"
    )
}

$script:TestContainedClientFixtureRoot = $null
$script:TestContainedClientFixture = $null

function Get-TestContainedClientFixture {
    if (-not [string]::IsNullOrWhiteSpace($script:TestContainedClientFixture)) {
        return $script:TestContainedClientFixture
    }

    $selfTestRoot = [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\target')
    )
    [void][System.IO.Directory]::CreateDirectory($selfTestRoot)
    $root = Join-Path $selfTestRoot (
        'fsring-r6-selftest-' + [Guid]::NewGuid().ToString('N')
    )
    [void][System.IO.Directory]::CreateDirectory($root)
    $fixturePath = Join-Path $root 'fsring-contained-client-fixture.exe'
    $script:TestContainedClientFixtureRoot = $root
    $source = @'
using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class FsringFixtureHandle
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint HandleFlagInherit = 0x00000001;

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        internal int Length;
        internal IntPtr SecurityDescriptor;
        internal int InheritHandle;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        ref SecurityAttributes securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static IntPtr OpenInheritable(string path)
    {
        SecurityAttributes attributes = new SecurityAttributes();
        attributes.Length = Marshal.SizeOf(typeof(SecurityAttributes));
        attributes.InheritHandle = 1;
        IntPtr handle = CreateFile(
            path,
            GenericRead,
            FileShareRead,
            ref attributes,
            OpenExisting,
            0,
            IntPtr.Zero);
        if (handle == new IntPtr(-1))
        {
            throw new System.ComponentModel.Win32Exception(
                Marshal.GetLastWin32Error());
        }
        return handle;
    }

    public static void Close(IntPtr handle)
    {
        if (handle != IntPtr.Zero && handle != new IntPtr(-1))
        {
            CloseHandle(handle);
        }
    }
}

public static class FsringContainedClientFixture
{
    private const int StdInputHandle = -10;
    private const int StdOutputHandle = -11;
    private const int StdErrorHandle = -12;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int standardHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetHandleInformation(
        IntPtr handle,
        out uint flags);

    private static string Quote(string argument)
    {
        return "\"" + argument.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }

    private static Process StartSelf(params string[] arguments)
    {
        ProcessStartInfo start = new ProcessStartInfo();
        start.FileName = Assembly.GetExecutingAssembly().Location;
        StringBuilder commandLine = new StringBuilder();
        foreach (string argument in arguments)
        {
            if (commandLine.Length != 0)
            {
                commandLine.Append(' ');
            }
            commandLine.Append(Quote(argument));
        }
        start.Arguments = commandLine.ToString();
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        return Process.Start(start);
    }

    private static bool IsValidHandle(IntPtr handle)
    {
        uint flags;
        return GetHandleInformation(handle, out flags);
    }

    public static int Main(string[] arguments)
    {
        if (arguments.Length == 0)
        {
            return 64;
        }

        if (arguments[0] == "delayed-sentinel")
        {
            Thread.Sleep(
                int.Parse(arguments[2], CultureInfo.InvariantCulture));
            File.WriteAllText(arguments[1], "grandchild");
            return 0;
        }

        if (arguments[0] == "immediate-sentinel")
        {
            File.WriteAllText(arguments[1], "resumed");
            return 0;
        }

        if (arguments[0] == "blocked-tree" ||
            arguments[0] == "root-exits")
        {
            Process child = StartSelf(
                "delayed-sentinel",
                arguments[1],
                arguments[3]);
            child.Dispose();
            File.WriteAllText(arguments[2], "ready");
            if (arguments[0] == "blocked-tree")
            {
                Thread.Sleep(30000);
            }
            return 0;
        }

        if (arguments[0] == "flood")
        {
            byte[] stdoutBytes = new byte[262144];
            byte[] stderrBytes = new byte[262144];
            for (int index = 0; index < stdoutBytes.Length; index++)
            {
                stdoutBytes[index] = (byte)'O';
                stderrBytes[index] = (byte)'E';
            }
            Thread stdoutThread = new Thread(delegate()
            {
                Stream stream = Console.OpenStandardOutput();
                stream.Write(stdoutBytes, 0, stdoutBytes.Length);
                stream.Flush();
            });
            Thread stderrThread = new Thread(delegate()
            {
                Stream stream = Console.OpenStandardError();
                stream.Write(stderrBytes, 0, stderrBytes.Length);
                stream.Flush();
            });
            stdoutThread.Start();
            stderrThread.Start();
            stdoutThread.Join();
            stderrThread.Join();
            return 23;
        }

        if (arguments[0] == "echo")
        {
            UTF8Encoding utf8 = new UTF8Encoding(false, true);
            for (int index = 1; index < arguments.Length; index++)
            {
                Console.WriteLine(
                    Convert.ToBase64String(utf8.GetBytes(arguments[index])));
            }
            return 0;
        }

        if (arguments[0] == "invalid-utf8")
        {
            Stream stream = Console.OpenStandardOutput();
            stream.WriteByte(0xff);
            stream.Flush();
            return 0;
        }

        if (arguments[0] == "line-boundaries")
        {
            byte[] bytes = new UTF8Encoding(false, true).GetBytes(
                "alpha\r\n\r\nomega\n");
            Stream stream = Console.OpenStandardOutput();
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush();
            return 0;
        }

        if (arguments[0] == "handles")
        {
            IntPtr ambient = new IntPtr(
                long.Parse(arguments[1], CultureInfo.InvariantCulture));
            IntPtr pin = new IntPtr(
                long.Parse(arguments[2], CultureInfo.InvariantCulture));
            IntPtr job = new IntPtr(
                long.Parse(arguments[3], CultureInfo.InvariantCulture));
            Console.WriteLine(
                "stdin={0};stdout={1};stderr={2};ambient={3};pin={4};job={5}",
                IsValidHandle(GetStdHandle(StdInputHandle)),
                IsValidHandle(GetStdHandle(StdOutputHandle)),
                IsValidHandle(GetStdHandle(StdErrorHandle)),
                IsValidHandle(ambient),
                IsValidHandle(pin),
                IsValidHandle(job));
            return 0;
        }

        return 65;
    }
}
'@
    $provider = New-Object Microsoft.CSharp.CSharpCodeProvider
    try {
        $parameters = New-Object System.CodeDom.Compiler.CompilerParameters
        $parameters.GenerateExecutable = $true
        $parameters.GenerateInMemory = $false
        $parameters.IncludeDebugInformation = $false
        $parameters.OutputAssembly = $fixturePath
        $parameters.CompilerOptions = '/platform:x64 /optimize+ /nologo'
        [void]$parameters.ReferencedAssemblies.Add('System.dll')
        $compiled = $provider.CompileAssemblyFromSource(
            $parameters,
            [string[]]@($source)
        )
        if ($compiled.Errors.HasErrors) {
            $messages = @(
                $compiled.Errors | ForEach-Object {
                    "$($_.ErrorNumber): $($_.ErrorText)"
                }
            )
            throw (
                'Contained-client fixture compile failed: ' +
                ($messages -join '; ')
            )
        }
    } catch {
        if (Test-Path -LiteralPath $root -PathType Container) {
            [System.IO.Directory]::Delete($root, $true)
        }
        $script:TestContainedClientFixtureRoot = $null
        throw
    } finally {
        $provider.Dispose()
    }
    $script:TestContainedClientFixture = $fixturePath
    return $fixturePath
}

function Wait-TestPath {
    param(
        [string]$LiteralPath,
        [int]$Milliseconds
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($stopwatch.ElapsedMilliseconds -lt $Milliseconds) {
        try {
            if (Test-Path -LiteralPath $LiteralPath -PathType Leaf) {
                return $true
            }
        } catch {
            # The fixture may still have the just-created sentinel open.
        }
        Start-Sleep -Milliseconds 20
    }
    try {
        return (Test-Path -LiteralPath $LiteralPath -PathType Leaf)
    } catch {
        return $false
    }
}

function Remove-TestFileWithRetry {
    param([string]$LiteralPath)

    for ($attempt = 1; $attempt -le 50; $attempt++) {
        if (-not (Test-Path -LiteralPath $LiteralPath)) {
            return
        }
        try {
            Remove-Item -LiteralPath $LiteralPath -Force `
                -ErrorAction Stop
            return
        } catch {
            if ($attempt -eq 50) {
                throw
            }
            Start-Sleep -Milliseconds 20
        }
    }
}

function Remove-TestContainedClientFixture {
    if ([string]::IsNullOrWhiteSpace($script:TestContainedClientFixtureRoot)) {
        return
    }
    $resolvedRoot = [System.IO.Path]::GetFullPath(
        $script:TestContainedClientFixtureRoot
    )
    $resolvedTemp = [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\target')
    )
    if (-not $resolvedRoot.StartsWith(
        $resolvedTemp,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Refusing to remove a self-test directory outside the temp root.'
    }
    Remove-Item -LiteralPath $resolvedRoot -Recurse -Force -ErrorAction Stop
    $script:TestContainedClientFixtureRoot = $null
    $script:TestContainedClientFixture = $null
}

function Get-SuccessResponses {
    return @(
        (New-AbsentServiceResult),
        (New-FakeResult 0),
        (New-FakeResult 0),
        (New-ServiceStateResult 4),
        (New-FakePinnedHarnessResult 'Normal' (
            New-FakeHarnessIdentityCheck 'preMain' $true
        )),
        (New-ServiceStateResult 4),
        (New-FakeResult 0),
        (New-ServiceStateResult 1),
        (New-FakeResult 0),
        (New-AbsentServiceResult),
        (New-FakePinnedHarnessResult 'Absent' (
            New-FakeHarnessIdentityCheck 'preAbsence' $true
        ))
    )
}

function Invoke-SelfTests {
    $cases = @(
        [pscustomobject]@{
            Name = 'native sc identity ignores blank and poisoned SystemRoot'
            Body = {
                $scPin = $null
                $originalSystemRoot = [Environment]::GetEnvironmentVariable(
                    'SystemRoot',
                    [EnvironmentVariableTarget]::Process
                )
                try {
                    $baseline = [FsringNativeSystemTool]::ResolveScPath()
                    [Environment]::SetEnvironmentVariable(
                        'SystemRoot',
                        '',
                        [EnvironmentVariableTarget]::Process
                    )
                    $blank = [FsringNativeSystemTool]::ResolveScPath()
                    [Environment]::SetEnvironmentVariable(
                        'SystemRoot',
                        'C:\fsring-poison-system-root',
                        [EnvironmentVariableTarget]::Process
                    )
                    $poisoned = [FsringNativeSystemTool]::ResolveScPath()
                    $scPin = [FsringNativeSystemTool]::OpenScPin()
                    $pinCheck = $scPin.Recheck(
                        $scPin.FinalPath,
                        'sc-selftest'
                    )
                    Assert-SelfTest (
                        [System.IO.Path]::IsPathRooted($baseline) -and
                        [System.IO.Path]::GetFullPath($baseline) -ceq
                            $baseline -and
                        [System.IO.Path]::GetFileName($baseline) -ceq
                            'sc.exe' -and
                        (Test-Path -LiteralPath $baseline -PathType Leaf) -and
                        $blank -ceq $baseline -and
                        $poisoned -ceq $baseline -and
                        $scPin.FinalPath -ceq $baseline -and
                        $scPin.ObservedSha256 -cmatch
                            '^[0-9A-F]{64}$' -and
                        $scPin.Length -gt 0 -and
                        $scPin.Machine -eq [uint16]0x8664 -and
                        -not $scPin.HandleInheritable -and
                        (Test-ExactExecutableIdentityCheck `
                            $pinCheck 'sc-selftest')
                    ) 'SystemRoot redirected or destabilized the native sc.exe identity'
                } finally {
                    if ($null -ne $scPin) {
                        $scPin.Dispose()
                    }
                    [Environment]::SetEnvironmentVariable(
                        'SystemRoot',
                        $originalSystemRoot,
                        [EnvironmentVariableTarget]::Process
                    )
                }
            }
        },
        [pscustomobject]@{
            Name = 'real command adapter bounds a hung process tree'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $root = [System.IO.Path]::GetDirectoryName($fixture)
                $sentinel = Join-Path $root (
                    'scm-adapter-sentinel-' +
                    [Guid]::NewGuid().ToString('N')
                )
                $ready = Join-Path $root (
                    'scm-adapter-ready-' +
                    [Guid]::NewGuid().ToString('N')
                )
                $run = $null
                $opaque = $null
                $opaquePin = $null
                try {
                    $adapter = New-RealAdapter `
                        -CommandTimeoutMilliseconds 350
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    $run = & $adapter.Run $fixture @(
                        'blocked-tree',
                        $sentinel,
                        $ready,
                        '1200'
                    )
                    $stopwatch.Stop()
                    Start-Sleep -Milliseconds 1500
                    Assert-SelfTest (
                        $run.TimedOut -and
                        $run.ContainmentConfirmed -and
                        $null -eq $run.ExitCode -and
                        $null -eq $run.Lease -and
                        $stopwatch.ElapsedMilliseconds -lt 3000 -and
                        -not (Test-Path -LiteralPath $sentinel)
                    ) 'hung command adapter execution escaped its bounded job'

                    $fixtureHash = (
                        Get-FileHash -LiteralPath $fixture `
                            -Algorithm SHA256
                    ).Hash
                    $opaquePin = [FsringHarnessPin]::Open(
                        $fixture,
                        $fixtureHash
                    )
                    $adapter.ScPinState.Pin = $opaquePin
                    $opaque = & $adapter.RunScm `
                        $fixture @('invalid-utf8') `
                        'sc-opaque-selftest'
                    Assert-SelfTest (
                        $opaque.ExitCode -eq 0 -and
                        -not $opaque.TimedOut -and
                        $opaque.ContainmentConfirmed -and
                        $opaque.ProtocolValid -and
                        $opaque.OutputFinalized -and
                        -not $opaque.OutputTruncated -and
                        $opaque.StdoutByteCount -eq 1 -and
                        $opaque.Stdout.Count -eq 0 -and
                        (Test-ExactExecutableIdentityCheck `
                            $opaque.IdentityCheck `
                            'sc-opaque-selftest')
                    ) 'opaque pinned SCM runner parsed or rejected non-UTF8 output'
                } finally {
                    if ($null -ne $opaque -and
                        $null -ne $opaque.Lease) {
                        $opaque.Lease.Dispose()
                    }
                    if ($null -ne $opaquePin) {
                        $opaquePin.Dispose()
                    }
                    if ($null -ne $run -and
                        $null -ne $run.PSObject.Properties['Lease'] -and
                        $null -ne $run.Lease) {
                        $run.Lease.Dispose()
                    }
                    foreach ($path in @($ready, $sentinel)) {
                        Remove-TestFileWithRetry $path
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'SCM timeout records containment and blocks cleanup'
            Body = {
                $lease = New-Object System.IO.MemoryStream
                try {
                    $raw = New-FakeClientResult `
                        $null @() @() $true $false $false `
                        $false $false $lease
                    $adapter = New-ScriptedAdapter @($raw)
                    $paths = New-TestPaths
                    $result = New-SmokeResult `
                        'Live' $paths.PackageDirectory $paths.HarnessPath
                    $observed = Invoke-AdapterCommand `
                        $adapter $result 'query-timeout' `
                        $paths.ScPath @('query', $script:ServiceName)
                    $record = $result.commands[0]
                    Assert-SelfTest (
                        $null -eq $observed.ExitCode -and
                        $observed.TimedOut -and
                        -not $observed.ContainmentConfirmed -and
                        $record.timedOut -and
                        -not $record.containmentConfirmed -and
                        -not $result.containment.allClientsConfirmed -and
                        $result.containment.cleanupBlocked -and
                        $result.containment.leasesRetained -eq 1
                    ) 'SCM timeout/containment evidence was discarded'
                } finally {
                    [void]$script:RetainedClientLeases.Remove($lease)
                    $lease.Dispose()
                }
            }
        },
        [pscustomobject]@{
            Name = 'ambiguous contained create reconciles exact ownership'
            Body = {
                $ambiguousCreate = New-FakeClientResult `
                    $null @() @() $true $true $false `
                    $false $true
                $responses = @(
                    (New-AbsentServiceResult),
                    $ambiguousCreate,
                    (New-ServiceStateResult 1),
                    (New-FakeResult 1062),
                    (New-ServiceStateResult 1),
                    (New-FakeResult 0),
                    (New-AbsentServiceResult),
                    (New-FakePinnedHarnessResult 'Absent' (
                        New-FakeHarnessIdentityCheck `
                            'preAbsence' $true
                    ))
                )
                $owned = Invoke-TestWorkflow `
                    (New-TestFacts) 'Live' $responses `
                    $true 2 'Pass'
                $operations = @(
                    $owned.Result.commands |
                        ForEach-Object { $_.operation }
                )
                Assert-SelfTest (
                    $owned.Result.overall -ceq 'FAIL' -and
                    $owned.Result.ownership.createdByThisRun -and
                    $owned.Result.ownership.createDisposition -ceq
                        'RECONCILED_OWNED' -and
                    $owned.Result.cleanup.attempted -and
                    $owned.Result.cleanup.success -and
                    $owned.Result.live.create.timedOut -and
                    $owned.Result.live.create.containmentConfirmed -and
                    -not ($operations -ccontains 'start') -and
                    -not ($operations -ccontains 'main-harness') -and
                    $owned.Adapter.ServiceIdentityState.Checks -eq 3
                ) 'exact post-timeout service identity did not acquire cleanup authority'

                foreach ($knownFailure in @(
                    [pscustomobject]@{
                        Name = 'safe'
                        Result = New-FakeClientResult `
                            1073 @() @() $false $true $true `
                            $false $true
                    },
                    [pscustomobject]@{
                        Name = 'protocol-uncertain'
                        Result = New-FakeClientResult `
                            1073 @() @() $false $true $false `
                            $false $true
                    }
                )) {
                    $nonzero = Invoke-TestWorkflow `
                        (New-TestFacts) 'Live' @(
                            (New-AbsentServiceResult),
                            $knownFailure.Result
                        ) $true 2 'Pass'
                    $nonzeroMutations = @(
                        $nonzero.Result.commands |
                            Where-Object { $_.mutating }
                    )
                    Assert-SelfTest (
                        $nonzero.Result.overall -ceq 'FAIL' -and
                        -not $nonzero.Result.ownership.createdByThisRun -and
                        $nonzero.Result.ownership.createDisposition -ceq
                            'UNOWNED_FAILED' -and
                        -not $nonzero.Result.cleanup.attempted -and
                        -not $nonzero.Result.live.start.attempted -and
                        $nonzero.Result.commands.Count -eq 2 -and
                        $nonzeroMutations.Count -eq 1 -and
                        $nonzeroMutations[0].operation -ceq 'create'
                    ) (
                        "$($knownFailure.Name) nonzero create acquired " +
                        'ownership or reached a later mutation'
                    )
                }

                $unowned = Invoke-TestWorkflow `
                    (New-TestFacts) 'Live' @(
                        (New-AbsentServiceResult),
                        $ambiguousCreate
                    ) $true 2 'Fail'
                Assert-SelfTest (
                    -not $unowned.Result.ownership.createdByThisRun -and
                    $unowned.Result.ownership.createDisposition -ceq
                        'UNOWNED_AMBIGUOUS' -and
                    -not $unowned.Result.cleanup.attempted -and
                    $unowned.Result.ownership.mutationAttempts -eq 1 -and
                    $unowned.Result.commands.Count -eq 2
                ) 'failed exact identity reconciliation gained cleanup authority'
            }
        },
        [pscustomobject]@{
            Name = 'unconfirmed create containment withholds all cleanup'
            Body = {
                $lease = New-Object System.IO.MemoryStream
                try {
                    $unconfirmedCreate = New-FakeClientResult `
                        $null @() @() $true $false $false `
                        $false $false $lease
                    $run = Invoke-TestWorkflow `
                        (New-TestFacts) 'Live' @(
                            (New-AbsentServiceResult),
                            $unconfirmedCreate
                        ) $true 2 'Pass'
                    Assert-SelfTest (
                        $run.Result.overall -ceq 'FAIL' -and
                        $run.Result.containment.cleanupBlocked -and
                        -not $run.Result.containment.allClientsConfirmed -and
                        -not $run.Result.cleanup.attempted -and
                        $run.Result.ownership.mutationAttempts -eq 1 -and
                        $run.Result.commands.Count -eq 2
                    ) 'unconfirmed SCM containment reached cleanup or another mutation'
                } finally {
                    [void]$script:RetainedClientLeases.Remove($lease)
                    $lease.Dispose()
                }
            }
        },
        [pscustomobject]@{
            Name = 'legacy root-only termination leaks a delayed grandchild'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $root = [System.IO.Path]::GetDirectoryName($fixture)
                $sentinel = Join-Path $root (
                    'legacy-sentinel-' + [Guid]::NewGuid().ToString('N')
                )
                $ready = Join-Path $root (
                    'legacy-ready-' + [Guid]::NewGuid().ToString('N')
                )
                $process = New-Object System.Diagnostics.Process
                $process.StartInfo.FileName = $fixture
                $process.StartInfo.Arguments = (
                    '"blocked-tree" "' + $sentinel + '" "' + $ready +
                    '" "700"'
                )
                $process.StartInfo.UseShellExecute = $false
                $process.StartInfo.CreateNoWindow = $true
                try {
                    Assert-SelfTest $process.Start() 'legacy negative-control root did not start'
                    Assert-SelfTest (Wait-TestPath $ready 3000) 'legacy negative-control grandchild did not become ready'
                    $process.Kill()
                    [void]$process.WaitForExit(3000)
                    Assert-SelfTest (
                        Wait-TestPath $sentinel 3000
                    ) 'root-only kill unexpectedly contained the delayed grandchild'
                } finally {
                    $process.Dispose()
                    foreach ($path in @($ready, $sentinel)) {
                        Remove-TestFileWithRetry $path
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'contained runner times out blocked root and kills delayed grandchild'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $root = [System.IO.Path]::GetDirectoryName($fixture)
                $sentinel = Join-Path $root (
                    'contained-sentinel-' + [Guid]::NewGuid().ToString('N')
                )
                $ready = Join-Path $root (
                    'contained-ready-' + [Guid]::NewGuid().ToString('N')
                )
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $run = $null
                try {
                    $run = [FsringContainedClientRunner]::Run(
                        $fixture,
                        [string[]]@('blocked-tree', $sentinel, $ready, '1200'),
                        350,
                        1000,
                        65536,
                        $null,
                        $false
                    )
                    $stopwatch.Stop()
                    Start-Sleep -Milliseconds 1500
                    Assert-SelfTest (
                        $run.TimedOut -and
                        $run.ContainmentConfirmed -and
                        $null -eq $run.ExitCode -and
                        $null -eq $run.Lease -and
                        $stopwatch.ElapsedMilliseconds -lt 3000 -and
                        -not (Test-Path -LiteralPath $sentinel)
                    ) 'blocked-root containment did not return at deadline with a confirmed empty job'
                } finally {
                    if ($null -ne $run -and $null -ne $run.Lease) {
                        $run.Lease.Dispose()
                    }
                    foreach ($path in @($ready, $sentinel)) {
                        if (Test-Path -LiteralPath $path) {
                            Remove-Item -LiteralPath $path -Force
                        }
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'contained runner waits for root-exited live grandchild'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $root = [System.IO.Path]::GetDirectoryName($fixture)
                $sentinel = Join-Path $root (
                    'root-exit-sentinel-' + [Guid]::NewGuid().ToString('N')
                )
                $ready = Join-Path $root (
                    'root-exit-ready-' + [Guid]::NewGuid().ToString('N')
                )
                $run = $null
                try {
                    $run = [FsringContainedClientRunner]::Run(
                        $fixture,
                        [string[]]@('root-exits', $sentinel, $ready, '1200'),
                        350,
                        1000,
                        65536,
                        $null,
                        $false
                    )
                    Start-Sleep -Milliseconds 1500
                    Assert-SelfTest (
                        $run.TimedOut -and
                        $run.ContainmentConfirmed -and
                        $run.ExitCode -eq 0 -and
                        $null -eq $run.Lease -and
                        -not (Test-Path -LiteralPath $sentinel)
                    ) 'root exit was mistaken for whole-job completion'
                } finally {
                    if ($null -ne $run -and $null -ne $run.Lease) {
                        $run.Lease.Dispose()
                    }
                    foreach ($path in @($ready, $sentinel)) {
                        if (Test-Path -LiteralPath $path) {
                            Remove-Item -LiteralPath $path -Force
                        }
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'contained runner drains both pipes past exact independent caps'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $run = [FsringContainedClientRunner]::Run(
                    $fixture,
                    [string[]]@('flood'),
                    5000,
                    1000,
                    65536,
                    $null,
                    $false
                )
                try {
                    Assert-SelfTest (
                        -not $run.TimedOut -and
                        $run.ContainmentConfirmed -and
                        $run.ExitCode -eq 23 -and
                        $run.OutputTruncated -and
                        $run.StdoutTruncated -and
                        $run.StderrTruncated -and
                        $run.StdoutByteCount -eq 65536 -and
                        $run.StderrByteCount -eq 65536
                    ) 'simultaneous stdout/stderr flood deadlocked or violated an independent cap'
                } finally {
                    if ($null -ne $run.Lease) {
                        $run.Lease.Dispose()
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'contained runner preserves CRT argv and strict stream boundaries'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $arguments = [string[]]@(
                    '',
                    'plain',
                    'space value',
                    "tab`tvalue",
                    'embedded"quote',
                    'trailing\',
                    'two\\',
                    'slashes\\"quote'
                )
                $echo = [FsringContainedClientRunner]::Run(
                    $fixture,
                    [string[]](@('echo') + $arguments),
                    5000,
                    1000,
                    65536,
                    $null,
                    $false
                )
                $lines = [FsringContainedClientRunner]::Run(
                    $fixture,
                    [string[]]@('line-boundaries'),
                    5000,
                    1000,
                    65536,
                    $null,
                    $false
                )
                $invalid = [FsringContainedClientRunner]::Run(
                    $fixture,
                    [string[]]@('invalid-utf8'),
                    5000,
                    1000,
                    65536,
                    $null,
                    $false
                )
                try {
                    $decoded = @(
                        $echo.Stdout | ForEach-Object {
                            [Text.Encoding]::UTF8.GetString(
                                [Convert]::FromBase64String($_)
                            )
                        }
                    )
                    Assert-SelfTest (
                        $echo.ProtocolValid -and
                        $decoded.Count -eq $arguments.Count -and
                        (@(Compare-Object $arguments $decoded -SyncWindow 0).Count -eq 0)
                    ) 'CRT quoting changed an empty, whitespace, quote, or trailing-backslash argument'
                    Assert-SelfTest (
                        $lines.ProtocolValid -and
                        $lines.Stdout.Count -eq 3 -and
                        $lines.Stdout[0] -ceq 'alpha' -and
                        $lines.Stdout[1] -ceq '' -and
                        $lines.Stdout[2] -ceq 'omega'
                    ) 'stdout physical line boundaries were trimmed or collapsed'
                    Assert-SelfTest (
                        -not $invalid.ProtocolValid -and
                        $invalid.ContainmentConfirmed
                    ) 'invalid UTF-8 was accepted or lost containment'
                } finally {
                    foreach ($run in @($echo, $lines, $invalid)) {
                        if ($null -ne $run.Lease) {
                            $run.Lease.Dispose()
                        }
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'contained runner retains a lease when zero confirmation is injected to fail'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $root = [System.IO.Path]::GetDirectoryName($fixture)
                $sentinel = Join-Path $root (
                    'unknown-sentinel-' + [Guid]::NewGuid().ToString('N')
                )
                $ready = Join-Path $root (
                    'unknown-ready-' + [Guid]::NewGuid().ToString('N')
                )
                $run = [FsringContainedClientRunner]::Run(
                    $fixture,
                    [string[]]@('blocked-tree', $sentinel, $ready, '1200'),
                    350,
                    350,
                    65536,
                    $null,
                    $true
                )
                try {
                    Assert-SelfTest (
                        $run.TimedOut -and
                        -not $run.ContainmentConfirmed -and
                        $null -ne $run.Lease
                    ) 'injected zero-confirmation failure did not retain the kill-on-close job lease'
                } finally {
                    if ($null -ne $run.Lease) {
                        $run.Lease.Dispose()
                    }
                    Start-Sleep -Milliseconds 1500
                    Assert-SelfTest (
                        -not (Test-Path -LiteralPath $sentinel)
                    ) 'disposing the retained job lease did not preserve kill-on-close containment'
                    foreach ($path in @($ready, $sentinel)) {
                        if (Test-Path -LiteralPath $path) {
                            Remove-Item -LiteralPath $path -Force
                        }
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'abandoned unconfirmed result finalization kills a delayed real child tree'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $root = [System.IO.Path]::GetDirectoryName($fixture)
                $sentinel = Join-Path $root (
                    'abandoned-sentinel-' + [Guid]::NewGuid().ToString('N')
                )
                $ready = Join-Path $root (
                    'abandoned-ready-' + [Guid]::NewGuid().ToString('N')
                )
                $cleanupClock = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $weakReferences = (
                        [FsringContainedClientRunner]::AbandonUnconfirmedResultForTest(
                            $fixture,
                            $sentinel,
                            $ready,
                            1200
                        )
                    )
                    Assert-SelfTest (
                        $weakReferences.Count -eq 2 -and
                        (Wait-TestPath $ready 3000)
                    ) 'abandoned-result seam did not start a real delayed child tree'

                    [GC]::Collect()
                    [GC]::WaitForPendingFinalizers()
                    [GC]::Collect()
                    Assert-SelfTest (
                        -not $weakReferences[0].IsAlive -and
                        -not $weakReferences[1].IsAlive
                    ) 'forced GC retained the intentionally abandoned result or lease'

                    Start-Sleep -Milliseconds 1600
                    Assert-SelfTest (
                        -not (Test-Path -LiteralPath $sentinel)
                    ) 'finalization did not close the abandoned kill-on-close job before the delayed child wrote its sentinel'
                } finally {
                    $remaining = 2000 - $cleanupClock.ElapsedMilliseconds
                    if ($remaining -gt 0) {
                        Start-Sleep -Milliseconds $remaining
                    }
                    foreach ($path in @($ready, $sentinel)) {
                        if (Test-Path -LiteralPath $path) {
                            Remove-Item -LiteralPath $path -Force
                        }
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'post-attribute launch failure releases the safe job borrow without escaping'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $root = [System.IO.Path]::GetDirectoryName($fixture)
                $missing = Join-Path $root (
                    'missing-client-' + [Guid]::NewGuid().ToString('N') +
                    '.exe'
                )
                $run = $null
                $escaped = $null
                try {
                    $run = [FsringContainedClientRunner]::Run(
                        $missing,
                        [string[]]@(),
                        1000,
                        500,
                        65536,
                        $null,
                        $false
                    )
                } catch {
                    $escaped = $_.Exception
                }
                try {
                    Assert-SelfTest (
                        $null -eq $escaped -and
                        $null -ne $run -and
                        -not $run.ProtocolValid -and
                        $run.ContainmentConfirmed -and
                        $run.OutputFinalized -and
                        $null -eq $run.Lease -and
                        $run.Error -cmatch 'CreateProcessW failed'
                    ) 'CreateProcessW failure escaped while releasing the live JOB_LIST safe-handle borrow'
                } finally {
                    if ($null -ne $run -and $null -ne $run.Lease) {
                        $run.Lease.Dispose()
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'contained runner failure seams preserve primary error and unsnapshotted lease'
            Body = {
                Assert-SelfTest (
                    [FsringContainedClientRunner]::TestFailedAttributeInitializationCleanup()
                ) 'failed attribute-list initialization was deleted as if initialized'
                Assert-SelfTest (
                    [FsringContainedClientRunner]::TestDrainConstructionFailureOwnership()
                ) 'failed drain construction retained duplicate ownership of a raw pipe handle'

                $fixture = Get-TestContainedClientFixture
                $root = [System.IO.Path]::GetDirectoryName($fixture)
                $sentinel = Join-Path $root (
                    'terminate-failure-sentinel-' +
                    [Guid]::NewGuid().ToString('N')
                )
                $ready = Join-Path $root (
                    'terminate-failure-ready-' +
                    [Guid]::NewGuid().ToString('N')
                )
                $run = [FsringContainedClientRunner]::RunWithFailuresForTest(
                    $fixture,
                    [string[]]@(
                        'blocked-tree',
                        $sentinel,
                        $ready,
                        '1200'
                    ),
                    200,
                    200,
                    65536,
                    $false,
                    $true,
                    $true
                )
                try {
                    Assert-SelfTest (
                        $run.TimedOut -and
                        -not $run.ContainmentConfirmed -and
                        $null -ne $run.Lease -and
                        -not $run.OutputFinalized -and
                        $run.StdoutByteCount -eq 0 -and
                        $run.StderrByteCount -eq 0 -and
                        $run.Error -cmatch 'deadline'
                    ) 'termination/drain failure did not preserve the primary deadline and rooted lease'
                } finally {
                    if ($null -ne $run.Lease) {
                        $run.Lease.Dispose()
                    }
                    Start-Sleep -Milliseconds 1500
                    Assert-SelfTest (
                        -not (Test-Path -LiteralPath $sentinel)
                    ) 'kill-on-close fallback did not contain the injected termination failure'
                    foreach ($path in @($ready, $sentinel)) {
                        if (Test-Path -LiteralPath $path) {
                            Remove-Item -LiteralPath $path -Force
                        }
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'confirmed-zero job with an unjoined drain remains unconfirmed and leased'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $run = [FsringContainedClientRunner]::RunWithFailuresForTest(
                    $fixture,
                    [string[]]@('echo', 'drain-must-reach-eof'),
                    5000,
                    500,
                    65536,
                    $false,
                    $false,
                    $true
                )
                try {
                    Assert-SelfTest (
                        $run.ExitCode -eq 0 -and
                        -not $run.TimedOut -and
                        -not $run.ContainmentConfirmed -and
                        -not $run.OutputFinalized -and
                        $null -ne $run.Lease
                    ) 'job zero was treated as confirmed even though redirected output never proved EOF'
                } finally {
                    if ($null -ne $run.Lease) {
                        $run.Lease.Dispose()
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'expired post-create deadline never resumes the suspended root'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $root = [System.IO.Path]::GetDirectoryName($fixture)
                $sentinel = Join-Path $root (
                    'expired-resume-' + [Guid]::NewGuid().ToString('N')
                )
                $run = $null
                try {
                    $run = [FsringContainedClientRunner]::RunWithPostCreateDelayForTest(
                        $fixture,
                        [string[]]@('immediate-sentinel', $sentinel),
                        100,
                        1000,
                        65536,
                        300,
                        $sentinel
                    )
                    Assert-SelfTest (
                        $run.TimedOut -and
                        $null -eq $run.ExitCode -and
                        $run.ContainmentConfirmed -and
                        $run.OutputFinalized -and
                        $null -eq $run.Lease -and
                        -not (Test-Path -LiteralPath $sentinel)
                    ) 'an expired post-create deadline resumed the real suspended root'
                } finally {
                    if ($null -ne $run -and $null -ne $run.Lease) {
                        $run.Lease.Dispose()
                    }
                    if (Test-Path -LiteralPath $sentinel) {
                        [System.IO.File]::Delete($sentinel)
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'harness pin measures one retained AMD64 image and rejects wrong hash'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $expected = (
                    Get-FileHash -LiteralPath $fixture -Algorithm SHA256
                ).Hash
                $pin = $null
                try {
                    $pin = [FsringHarnessPin]::Open($fixture, $expected)
                    Assert-SelfTest (
                        $pin.ExpectedSha256 -ceq $expected -and
                        $pin.ObservedSha256 -ceq $expected -and
                        $pin.Length -gt 0 -and
                        $pin.Machine -eq 0x8664 -and
                        $pin.VolumeSerial -cmatch '^[0-9A-F]{16}$' -and
                        $pin.FileId -cmatch '^[0-9A-F]{32}$' -and
                        [System.IO.Path]::IsPathRooted($pin.FinalPath) -and
                        -not $pin.HandleInheritable
                    ) 'retained pin evidence is incomplete or not bound to one AMD64 image'
                    $recheck = $pin.Recheck($fixture, 'unit')
                    Assert-SelfTest (
                        $recheck.Valid -and
                        $recheck.Stage -ceq 'unit' -and
                        $recheck.Sha256 -ceq $expected -and
                        $recheck.VolumeSerial -ceq $pin.VolumeSerial -and
                        $recheck.FileId -ceq $pin.FileId
                    ) 'retained pin did not remeasure bytes and reopen the same native identity'
                } finally {
                    if ($null -ne $pin) {
                        $pin.Dispose()
                    }
                }

                foreach ($wrong in @(
                    ('0' * 64),
                    $expected.ToLowerInvariant()
                )) {
                    $accepted = $false
                    $candidate = $null
                    try {
                        $candidate = [FsringHarnessPin]::Open(
                            $fixture,
                            $wrong
                        )
                        $accepted = $true
                    } catch {
                    } finally {
                        if ($null -ne $candidate) {
                            $candidate.Dispose()
                        }
                    }
                    Assert-SelfTest (
                        -not $accepted
                    ) "harness pin accepted invalid expected hash '$wrong'"
                }
            }
        },
        [pscustomobject]@{
            Name = 'harness pin rejects non-AMD64 bytes and writable-handle conflicts'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $root = [System.IO.Path]::GetDirectoryName($fixture)
                $baseline = [FsringHarnessPin]::Open(
                    $fixture,
                    (
                        Get-FileHash -LiteralPath $fixture `
                            -Algorithm SHA256
                    ).Hash
                )
                $baseline.Dispose()
                $nonAmd64 = Join-Path $root (
                    'non-amd64-' + [Guid]::NewGuid().ToString('N') + '.exe'
                )
                [System.IO.File]::Copy($fixture, $nonAmd64, $false)
                $stream = $null
                $reader = $null
                $writer = $null
                try {
                    $stream = [System.IO.File]::Open(
                        $nonAmd64,
                        [System.IO.FileMode]::Open,
                        [System.IO.FileAccess]::ReadWrite,
                        [System.IO.FileShare]::Read
                    )
                    $reader = New-Object System.IO.BinaryReader(
                        $stream,
                        [Text.Encoding]::UTF8,
                        $true
                    )
                    $writer = New-Object System.IO.BinaryWriter(
                        $stream,
                        [Text.Encoding]::UTF8,
                        $true
                    )
                    $stream.Position = 0x3c
                    $peOffset = [int64]$reader.ReadUInt32()
                    $stream.Position = $peOffset + 4
                    $writer.Write([uint16]0x014c)
                    $writer.Flush()
                } finally {
                    if ($null -ne $writer) {
                        $writer.Dispose()
                    }
                    if ($null -ne $reader) {
                        $reader.Dispose()
                    }
                    if ($null -ne $stream) {
                        $stream.Dispose()
                    }
                }
                $nonAmd64Hash = (
                    Get-FileHash -LiteralPath $nonAmd64 -Algorithm SHA256
                ).Hash
                $acceptedNonAmd64 = $false
                $candidate = $null
                try {
                    $candidate = [FsringHarnessPin]::Open(
                        $nonAmd64,
                        $nonAmd64Hash
                    )
                    $acceptedNonAmd64 = $true
                } catch {
                } finally {
                    if ($null -ne $candidate) {
                        $candidate.Dispose()
                    }
                    [System.IO.File]::Delete($nonAmd64)
                }
                Assert-SelfTest (
                    -not $acceptedNonAmd64
                ) 'harness pin accepted an x86 PE image'

                $writable = $null
                $acceptedWritable = $false
                try {
                    $writable = [System.IO.File]::Open(
                        $fixture,
                        [System.IO.FileMode]::Open,
                        [System.IO.FileAccess]::ReadWrite,
                        [System.IO.FileShare]::ReadWrite
                    )
                    $candidate = [FsringHarnessPin]::Open(
                        $fixture,
                        (
                            Get-FileHash -LiteralPath $fixture `
                                -Algorithm SHA256
                        ).Hash
                    )
                    $acceptedWritable = $true
                } catch {
                } finally {
                    if ($null -ne $candidate) {
                        $candidate.Dispose()
                    }
                    if ($null -ne $writable) {
                        $writable.Dispose()
                    }
                }
                Assert-SelfTest (
                    -not $acceptedWritable
                ) 'harness pin opened while a writable handle already existed'
            }
        },
        [pscustomobject]@{
            Name = 'harness pin rejects malformed AMD64 COFF optional and section tables before commands'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $root = [System.IO.Path]::GetDirectoryName($fixture)
                $original = [System.IO.File]::ReadAllBytes($fixture)
                $peOffset = [int][BitConverter]::ToUInt32(
                    $original,
                    0x3c
                )
                $optionalSize = [int][BitConverter]::ToUInt16(
                    $original,
                    $peOffset + 20
                )
                $sectionTable = $peOffset + 24 + $optionalSize
                $mutations = @(
                    [pscustomobject]@{
                        Name = 'zero-sections'
                        Offset = $peOffset + 6
                        Bytes = [BitConverter]::GetBytes([uint16]0)
                    },
                    [pscustomobject]@{
                        Name = 'zero-optional-header'
                        Offset = $peOffset + 20
                        Bytes = [BitConverter]::GetBytes([uint16]0)
                    },
                    [pscustomobject]@{
                        Name = 'pe32-optional-magic'
                        Offset = $peOffset + 24
                        Bytes = [BitConverter]::GetBytes([uint16]0x010b)
                    },
                    [pscustomobject]@{
                        Name = 'raw-section-outside-file'
                        Offset = $sectionTable + 16
                        Bytes = [BitConverter]::GetBytes([uint32](
                            $original.Length
                        ))
                    },
                    [pscustomobject]@{
                        Name = 'raw-section-overlaps-headers'
                        Offset = $sectionTable + 20
                        Bytes = [BitConverter]::GetBytes([uint32]0)
                    },
                    [pscustomobject]@{
                        Name = 'misaligned-section-rva'
                        Offset = $sectionTable + 12
                        Bytes = [BitConverter]::GetBytes([uint32]0x1001)
                    }
                )
                $accepted = New-Object System.Collections.ArrayList
                foreach ($mutation in $mutations) {
                    $bytes = [byte[]]$original.Clone()
                    [Buffer]::BlockCopy(
                        $mutation.Bytes,
                        0,
                        $bytes,
                        $mutation.Offset,
                        $mutation.Bytes.Length
                    )
                    $path = Join-Path $root (
                        'malformed-' + $mutation.Name + '-' +
                        [Guid]::NewGuid().ToString('N') + '.exe'
                    )
                    [System.IO.File]::WriteAllBytes($path, $bytes)
                    $paths = New-TestPaths
                    $paths.HarnessPath = $path
                    $adapter = New-ScriptedAdapter @()
                    $result = New-SmokeResult `
                        'PreflightOnly' 'C:\package' $path
                    try {
                        $hash = (
                            Get-FileHash -LiteralPath $path `
                                -Algorithm SHA256
                        ).Hash
                        if (Initialize-HarnessPin `
                            $adapter $result $paths $hash) {
                            [void]$accepted.Add($mutation.Name)
                        }
                        Assert-SelfTest (
                            $adapter.State.ClientCalls -eq 0 -and
                            $adapter.State.CommandCalls -eq 0 -and
                            $result.ownership.mutationAttempts -eq 0
                        ) "malformed $($mutation.Name) reached an external command"
                    } finally {
                        if ($adapter.HarnessPin -is [IDisposable]) {
                            $adapter.HarnessPin.Dispose()
                            [void]$script:RetainedHarnessPins.Remove(
                                $adapter.HarnessPin
                            )
                        }
                        [System.IO.File]::Delete($path)
                    }
                }
                Assert-SelfTest (
                    $accepted.Count -eq 0
                ) (
                    'malformed AMD64 PE structures accepted: ' +
                    (@($accepted) -join ', ')
                )
            }
        },
        [pscustomobject]@{
            Name = 'harness pin rejects non-launchable AMD64 PE kinds before commands'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $root = [System.IO.Path]::GetDirectoryName($fixture)
                $original = [System.IO.File]::ReadAllBytes($fixture)
                $peOffset = [int][BitConverter]::ToUInt32(
                    $original,
                    0x3c
                )
                $optionalOffset = $peOffset + 24
                $characteristics = [BitConverter]::ToUInt16(
                    $original,
                    $peOffset + 22
                )
                $sectionCount = [int][BitConverter]::ToUInt16(
                    $original,
                    $peOffset + 6
                )
                $optionalSize = [int][BitConverter]::ToUInt16(
                    $original,
                    $peOffset + 20
                )
                $addressOfEntryPoint = [BitConverter]::ToUInt32(
                    $original,
                    $optionalOffset + 16
                )
                $clrRva = [BitConverter]::ToUInt32(
                    $original,
                    $optionalOffset + 224
                )
                $clrSize = [BitConverter]::ToUInt32(
                    $original,
                    $optionalOffset + 228
                )
                $sectionTableOffset =
                    $optionalOffset + $optionalSize
                $clrOffset = $null
                for (
                    $sectionIndex = 0
                    $sectionIndex -lt $sectionCount
                    $sectionIndex++
                ) {
                    $sectionOffset =
                        $sectionTableOffset + ($sectionIndex * 40)
                    $virtualAddress = [BitConverter]::ToUInt32(
                        $original,
                        $sectionOffset + 12
                    )
                    $rawSize = [BitConverter]::ToUInt32(
                        $original,
                        $sectionOffset + 16
                    )
                    $rawPointer = [BitConverter]::ToUInt32(
                        $original,
                        $sectionOffset + 20
                    )
                    if ([uint64]$clrRva -ge
                            [uint64]$virtualAddress) {
                        $delta =
                            [uint64]$clrRva -
                            [uint64]$virtualAddress
                        if ($delta + [uint64]72 -le
                                [uint64]$rawSize) {
                            $clrOffset = [int](
                                [uint64]$rawPointer + $delta
                            )
                        }
                    }
                }
                Assert-SelfTest (
                    $addressOfEntryPoint -eq 0 -and
                    $clrSize -eq 72 -and
                    $null -ne $clrOffset
                ) 'managed launch fixture does not exercise the bounded zero-entrypoint CLR path'

                $clrFlags = [BitConverter]::ToUInt32(
                    $original,
                    $clrOffset + 16
                )
                $entryPointToken = [BitConverter]::ToUInt32(
                    $original,
                    $clrOffset + 20
                )
                $metadataRva = [BitConverter]::ToUInt32(
                    $original,
                    $clrOffset + 8
                )
                $metadataSize = [BitConverter]::ToUInt32(
                    $original,
                    $clrOffset + 12
                )
                $metadataOffset = $null
                for (
                    $sectionIndex = 0
                    $sectionIndex -lt $sectionCount
                    $sectionIndex++
                ) {
                    $sectionOffset =
                        $sectionTableOffset + ($sectionIndex * 40)
                    $virtualAddress = [BitConverter]::ToUInt32(
                        $original,
                        $sectionOffset + 12
                    )
                    $rawSize = [BitConverter]::ToUInt32(
                        $original,
                        $sectionOffset + 16
                    )
                    $rawPointer = [BitConverter]::ToUInt32(
                        $original,
                        $sectionOffset + 20
                    )
                    if ([uint64]$metadataRva -ge
                            [uint64]$virtualAddress) {
                        $delta =
                            [uint64]$metadataRva -
                            [uint64]$virtualAddress
                        if ($delta + [uint64]$metadataSize -le
                                [uint64]$rawSize) {
                            $metadataOffset = [int](
                                [uint64]$rawPointer + $delta
                            )
                        }
                    }
                }
                Assert-SelfTest (
                    [BitConverter]::ToUInt32(
                        $original,
                        $clrOffset
                    ) -eq 72 -and
                    ($clrFlags -band [uint32]1) -ne 0 -and
                    ($entryPointToken -band [uint32]4294967040) -eq
                        [uint32]0x06000000 -and
                    ($entryPointToken -band [uint32]0x00FFFFFF) -ne 0 -and
                    $metadataSize -ge 16 -and
                    $null -ne $metadataOffset -and
                    [BitConverter]::ToUInt32(
                        $original,
                        $metadataOffset
                    ) -eq [uint32]0x424A5342
                ) 'managed launch fixture has no bounded CLR MethodDef/metadata descriptor'
                $mutations = @(
                    [pscustomobject]@{
                        Name = 'dll-image'
                        Writes = @(
                            [pscustomobject]@{
                                Offset = $peOffset + 22
                                Bytes = [BitConverter]::GetBytes(
                                    [uint16]($characteristics -bor 0x2000)
                                )
                            }
                        )
                    },
                    [pscustomobject]@{
                        Name = 'system-image'
                        Writes = @(
                            [pscustomobject]@{
                                Offset = $peOffset + 22
                                Bytes = [BitConverter]::GetBytes(
                                    [uint16]($characteristics -bor 0x1000)
                                )
                            }
                        )
                    },
                    [pscustomobject]@{
                        Name = 'native-subsystem'
                        Writes = @(
                            [pscustomobject]@{
                                Offset = $optionalOffset + 68
                                Bytes = [BitConverter]::GetBytes(
                                    [uint16]1
                                )
                            }
                        )
                    },
                    [pscustomobject]@{
                        Name = 'zero-entrypoint-without-clr'
                        Writes = @(
                            [pscustomobject]@{
                                Offset = $optionalOffset + 16
                                Bytes = [BitConverter]::GetBytes(
                                    [uint32]0
                                )
                            },
                            [pscustomobject]@{
                                Offset = $optionalOffset + 224
                                Bytes = [byte[]](0, 0, 0, 0, 0, 0, 0, 0)
                            }
                        )
                    },
                    [pscustomobject]@{
                        Name = 'managed-clr-directory-short'
                        Writes = @(
                            [pscustomobject]@{
                                Offset = $optionalOffset + 228
                                Bytes = [BitConverter]::GetBytes(
                                    [uint32]71
                                )
                            }
                        )
                    },
                    [pscustomobject]@{
                        Name = 'managed-clr-header-short'
                        Writes = @(
                            [pscustomobject]@{
                                Offset = $clrOffset
                                Bytes = [BitConverter]::GetBytes(
                                    [uint32]71
                                )
                            }
                        )
                    },
                    [pscustomobject]@{
                        Name = 'managed-missing-ilonly'
                        Writes = @(
                            [pscustomobject]@{
                                Offset = $clrOffset + 16
                                Bytes = [BitConverter]::GetBytes(
                                    [uint32](
                                        $clrFlags -band
                                        [uint32]4294967294
                                    )
                                )
                            }
                        )
                    },
                    [pscustomobject]@{
                        Name = 'managed-32bit-required'
                        Writes = @(
                            [pscustomobject]@{
                                Offset = $clrOffset + 16
                                Bytes = [BitConverter]::GetBytes(
                                    [uint32](
                                        $clrFlags -bor [uint32]0x00000002
                                    )
                                )
                            }
                        )
                    },
                    [pscustomobject]@{
                        Name = 'managed-il-library'
                        Writes = @(
                            [pscustomobject]@{
                                Offset = $clrOffset + 16
                                Bytes = [BitConverter]::GetBytes(
                                    [uint32](
                                        $clrFlags -bor [uint32]0x00000004
                                    )
                                )
                            }
                        )
                    },
                    [pscustomobject]@{
                        Name = 'managed-native-entrypoint'
                        Writes = @(
                            [pscustomobject]@{
                                Offset = $clrOffset + 16
                                Bytes = [BitConverter]::GetBytes(
                                    [uint32](
                                        $clrFlags -bor [uint32]0x00000010
                                    )
                                )
                            }
                        )
                    },
                    [pscustomobject]@{
                        Name = 'managed-32bit-preferred'
                        Writes = @(
                            [pscustomobject]@{
                                Offset = $clrOffset + 16
                                Bytes = [BitConverter]::GetBytes(
                                    [uint32](
                                        $clrFlags -bor [uint32]0x00020000
                                    )
                                )
                            }
                        )
                    },
                    [pscustomobject]@{
                        Name = 'managed-methoddef-zero-rid'
                        Writes = @(
                            [pscustomobject]@{
                                Offset = $clrOffset + 20
                                Bytes = [BitConverter]::GetBytes(
                                    [uint32]0x06000000
                                )
                            }
                        )
                    },
                    [pscustomobject]@{
                        Name = 'managed-metadata-out-of-range'
                        Writes = @(
                            [pscustomobject]@{
                                Offset = $clrOffset + 12
                                Bytes = [BitConverter]::GetBytes(
                                    [uint32]::MaxValue
                                )
                            }
                        )
                    },
                    [pscustomobject]@{
                        Name = 'managed-metadata-without-bsjb'
                        Writes = @(
                            [pscustomobject]@{
                                Offset = $metadataOffset
                                Bytes = [BitConverter]::GetBytes(
                                    [uint32]0
                                )
                            }
                        )
                    }
                )
                $accepted = New-Object System.Collections.ArrayList
                foreach ($mutation in $mutations) {
                    $bytes = [byte[]]$original.Clone()
                    foreach ($write in $mutation.Writes) {
                        [Buffer]::BlockCopy(
                            $write.Bytes,
                            0,
                            $bytes,
                            $write.Offset,
                            $write.Bytes.Length
                        )
                    }
                    $path = Join-Path $root (
                        'non-launchable-' + $mutation.Name + '-' +
                        [Guid]::NewGuid().ToString('N') + '.exe'
                    )
                    [System.IO.File]::WriteAllBytes($path, $bytes)
                    $paths = New-TestPaths
                    $paths.HarnessPath = $path
                    $adapter = New-ScriptedAdapter @()
                    $result = New-SmokeResult `
                        'PreflightOnly' 'C:\package' $path
                    try {
                        $hash = (
                            Get-FileHash -LiteralPath $path `
                                -Algorithm SHA256
                        ).Hash
                        if (Initialize-HarnessPin `
                            $adapter $result $paths $hash) {
                            [void]$accepted.Add($mutation.Name)
                        }
                        Assert-SelfTest (
                            $adapter.State.ClientCalls -eq 0 -and
                            $adapter.State.CommandCalls -eq 0 -and
                            $result.ownership.mutationAttempts -eq 0
                        ) "non-launchable $($mutation.Name) reached an external command"
                    } finally {
                        if ($adapter.HarnessPin -is [IDisposable]) {
                            $adapter.HarnessPin.Dispose()
                            [void]$script:RetainedHarnessPins.Remove(
                                $adapter.HarnessPin
                            )
                        }
                        [System.IO.File]::Delete($path)
                    }
                }
                Assert-SelfTest (
                    $accepted.Count -eq 0
                ) (
                    'non-launchable AMD64 PE images accepted: ' +
                    (@($accepted) -join ', ')
                )
            }
        },
        [pscustomobject]@{
            Name = 'retained harness pin blocks overwrite and rename until disposal'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $root = [System.IO.Path]::GetDirectoryName($fixture)
                $expected = (
                    Get-FileHash -LiteralPath $fixture -Algorithm SHA256
                ).Hash
                $renamed = Join-Path $root (
                    'renamed-' + [Guid]::NewGuid().ToString('N') + '.exe'
                )
                $pin = [FsringHarnessPin]::Open($fixture, $expected)
                try {
                    $overwriteRejected = $false
                    $renameRejected = $false
                    try {
                        $write = [System.IO.File]::Open(
                            $fixture,
                            [System.IO.FileMode]::Open,
                            [System.IO.FileAccess]::Write,
                            [System.IO.FileShare]::ReadWrite
                        )
                        $write.Dispose()
                    } catch {
                        $overwriteRejected = $true
                    }
                    try {
                        [System.IO.File]::Move($fixture, $renamed)
                    } catch {
                        $renameRejected = $true
                    }
                    $recheck = $pin.Recheck($fixture, 'after-share-tests')
                    Assert-SelfTest (
                        $overwriteRejected -and
                        $renameRejected -and
                        $recheck.Valid
                    ) 'retained share-read pin allowed overwrite/rename or lost identity'
                } finally {
                    $pin.Dispose()
                    if (Test-Path -LiteralPath $renamed -PathType Leaf) {
                        [System.IO.File]::Move($renamed, $fixture)
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'harness pin rejects a reparse leaf and junction parent'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $root = [System.IO.Path]::GetDirectoryName($fixture)
                $baseline = [FsringHarnessPin]::Open(
                    $fixture,
                    (
                        Get-FileHash -LiteralPath $fixture `
                            -Algorithm SHA256
                    ).Hash
                )
                $baseline.Dispose()
                $targetDirectory = Join-Path $root (
                    'junction-target-' + [Guid]::NewGuid().ToString('N')
                )
                $junction = Join-Path $root (
                    'junction-parent-' + [Guid]::NewGuid().ToString('N')
                )
                [void][System.IO.Directory]::CreateDirectory($targetDirectory)
                $junctionFixture = Join-Path $targetDirectory 'fixture.exe'
                [System.IO.File]::Copy($fixture, $junctionFixture, $false)
                $junctionItem = New-Item -ItemType Junction -Path $junction `
                    -Target $targetDirectory -ErrorAction Stop
                $throughJunction = Join-Path $junction 'fixture.exe'
                $junctionHash = (
                    Get-FileHash -LiteralPath $throughJunction `
                        -Algorithm SHA256
                ).Hash
                $acceptedJunction = $false
                $candidate = $null
                try {
                    $candidate = [FsringHarnessPin]::Open(
                        $throughJunction,
                        $junctionHash
                    )
                    $acceptedJunction = $true
                } catch {
                } finally {
                    if ($null -ne $candidate) {
                        $candidate.Dispose()
                    }
                    if (Test-Path -LiteralPath $junction) {
                        [System.IO.Directory]::Delete($junction)
                    }
                    [System.IO.File]::Delete($junctionFixture)
                    [System.IO.Directory]::Delete($targetDirectory)
                }
                Assert-SelfTest (
                    -not $acceptedJunction
                ) 'harness pin followed a junction parent'

                $reparseLeaf = Join-Path $env:LOCALAPPDATA (
                    'Microsoft\WindowsApps\python.exe'
                )
                Assert-SelfTest (
                    (Test-Path -LiteralPath $reparseLeaf) -and
                    (
                        (Get-Item -LiteralPath $reparseLeaf -Force).Attributes `
                            -band [System.IO.FileAttributes]::ReparsePoint
                    )
                ) 'the current host lacks the expected file reparse-leaf fixture'
                $acceptedLeaf = $false
                $candidate = $null
                try {
                    $candidate = [FsringHarnessPin]::Open(
                        $reparseLeaf,
                        ('0' * 64)
                    )
                    $acceptedLeaf = $true
                } catch {
                } finally {
                    if ($null -ne $candidate) {
                        $candidate.Dispose()
                    }
                }
                Assert-SelfTest (
                    -not $acceptedLeaf
                ) 'harness pin followed a file reparse leaf'
            }
        },
        [pscustomobject]@{
            Name = 'child inherits only NUL stdout stderr and excludes ambient job pin handles'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $expected = (
                    Get-FileHash -LiteralPath $fixture -Algorithm SHA256
                ).Hash
                $pin = [FsringHarnessPin]::Open($fixture, $expected)
                $ambient = [IntPtr]::Zero
                $run = $null
                try {
                    $ambient = [FsringContainedClientRunner]::OpenInheritableFileForTest(
                        $fixture
                    )
                    $run = [FsringContainedClientRunner]::RunHandleProbeForTest(
                        $fixture,
                        $ambient.ToInt64(),
                        $pin.DangerousHandleValueForTest,
                        5000,
                        1000,
                        65536,
                        $pin
                    )
                    Assert-SelfTest (
                        $run.ProtocolValid -and
                        $run.ContainmentConfirmed -and
                        $run.ExitCode -eq 0 -and
                        $run.Stdout.Count -eq 1 -and
                        $run.Stdout[0] -ceq (
                            'stdin=True;stdout=True;stderr=True;' +
                            'ambient=False;pin=False;job=False'
                        )
                    ) 'explicit HANDLE_LIST leaked an ambient, job, or pin handle'
                } finally {
                    if ($null -ne $run -and $null -ne $run.Lease) {
                        $run.Lease.Dispose()
                    }
                    if ($ambient -ne [IntPtr]::Zero) {
                        [FsringContainedClientRunner]::CloseHandleForTest(
                            $ambient
                        )
                    }
                    $pin.Dispose()
                }
            }
        },
        [pscustomobject]@{
            Name = 'client adapter preserves nullable exit timeout and containment facts'
            Body = {
                $raw = New-FakeClientResult $null @() @() `
                    $true $true $false $false $true
                $adapter = New-ScriptedAdapter @($raw)
                $result = New-SmokeResult 'Live' 'C:\package' 'C:\harness.exe'
                $observed = Invoke-AdapterClientCommand $adapter $result `
                    'bounded-client' 'C:\client.exe' @() $null 'unit'
                Assert-SelfTest (
                    $null -eq $observed.ExitCode -and
                    $observed.TimedOut -and
                    $observed.ContainmentConfirmed -and
                    -not $observed.ProtocolValid -and
                    $adapter.State.ClientCalls -eq 1 -and
                    $adapter.State.CommandCalls -eq 0 -and
                    $result.commands.Count -eq 1 -and
                    $null -eq $result.commands[0].exitCode -and
                    $result.commands[0].timedOut -and
                    $result.commands[0].containmentConfirmed
                ) 'client adapter invented an exit code or discarded timeout/containment facts'
            }
        },
        [pscustomobject]@{
            Name = 'malformed client envelope retains its raw lease exactly through final flush'
            Body = {
                $stream = New-Object System.IO.MemoryStream
                $writer = New-Object System.IO.StreamWriter(
                    $stream,
                    (New-Object System.Text.UTF8Encoding($false)),
                    1024,
                    $true
                )
                $state = [pscustomobject]@{
                    DisposeCount = 0
                    LengthAtDispose = [int64]0
                    LastByteAtDispose = [int]-1
                }
                $lease = New-Object psobject
                $dispose = {
                    $state.DisposeCount++
                    $state.LengthAtDispose = $stream.Length
                    if ($stream.Length -gt 0) {
                        $position = $stream.Position
                        $stream.Position = $stream.Length - 1
                        $state.LastByteAtDispose = $stream.ReadByte()
                        $stream.Position = $position
                    }
                }.GetNewClosure()
                Add-Member -InputObject $lease `
                    -MemberType ScriptMethod -Name Dispose `
                    -Value $dispose

                $raw = New-FakeClientResult $null @() @() `
                    $true $false $false $false $false $lease
                $raw.TimedOut = 'true'
                $adapter = New-ScriptedAdapter @($raw)
                $result = New-SmokeResult `
                    'Live' 'C:\package' 'C:\harness.exe'
                $before = $script:RetainedClientLeases.Count
                try {
                    $observed = Invoke-AdapterClientCommand `
                        $adapter $result 'malformed-client' `
                        'C:\client.exe' @() $null 'unit'
                    Assert-SelfTest (
                        -not $observed.ContainmentConfirmed -and
                        $null -ne $observed.Lease -and
                        [object]::ReferenceEquals(
                            $observed.Lease,
                            $lease
                        ) -and
                        $script:RetainedClientLeases.Count -eq (
                            $before + 1
                        ) -and
                        [object]::ReferenceEquals(
                            $script:RetainedClientLeases[
                                $script:RetainedClientLeases.Count - 1
                            ],
                            $lease
                        )
                    ) 'shape normalization discarded or duplicated the raw rooted lease'

                    [void]$script:RetainedClientLeases.Remove($lease)
                    $completed = Complete-SmokeResult $result 'FAIL'
                    Write-FinalJsonAndDispose `
                        $completed $writer @($lease)
                    Assert-SelfTest (
                        $state.DisposeCount -eq 1 -and
                        $state.LengthAtDispose -gt 0 -and
                        $state.LastByteAtDispose -eq 10
                    ) 'raw lease was not held through flush or was disposed more than once'
                } finally {
                    [void]$script:RetainedClientLeases.Remove($lease)
                    if ($state.DisposeCount -eq 0) {
                        $lease.Dispose()
                    }
                    $writer.Dispose()
                    $stream.Dispose()
                }
            }
        },
        [pscustomobject]@{
            Name = 'confirmed main timeout permits only owned cleanup'
            Body = {
                $responses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 0),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 4),
                    (New-FakeClientResult $null @() @() `
                        $true $true $false $false $true $null `
                        (New-FakeHarnessIdentityCheck `
                            'preMain' $true)),
                    (New-ServiceStateResult 4),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 1),
                    (New-FakeResult 0),
                    (New-AbsentServiceResult),
                    (New-FakePinnedHarnessResult 'Absent' (
                        New-FakeHarnessIdentityCheck `
                            'preAbsence' $true
                    ))
                )
                $run = Invoke-TestWorkflow (
                    New-TestFacts
                ) 'Live' $responses
                Assert-SelfTest (
                    $run.Result.overall -ceq 'FAIL' -and
                    $run.Result.mainHarness.attempted -and
                    $run.Result.mainHarness.timedOut -and
                    $run.Result.mainHarness.containmentConfirmed -and
                    $null -eq $run.Result.mainHarness.exitCode -and
                    $run.Result.cleanup.attempted -and
                    $run.Result.cleanup.success -and
                    $run.Result.absenceHarness.valid -and
                    $run.Adapter.State.ClientCalls -eq 2
                ) 'confirmed main timeout did not preserve null exit and permit owned cleanup'
            }
        },
        [pscustomobject]@{
            Name = 'unconfirmed main tree forbids cleanup and later client launch'
            Body = {
                $leaseMarker = [pscustomobject]@{ Retained = $true }
                $responses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 0),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 4),
                    (New-FakeClientResult $null @() @() `
                        $true $false $false $false $false `
                        $leaseMarker (
                            New-FakeHarnessIdentityCheck `
                                'preMain' $true
                        ))
                )
                $run = Invoke-TestWorkflow (
                    New-TestFacts
                ) 'Live' $responses
                Assert-SelfTest (
                    $run.Result.overall -ceq 'FAIL' -and
                    $run.Result.mainHarness.attempted -and
                    -not $run.Result.mainHarness.containmentConfirmed -and
                    -not $run.Result.cleanup.attempted -and
                    -not $run.Result.absenceHarness.attempted -and
                    $run.Result.ownership.servicePresent -and
                    $run.Adapter.State.Index -eq 5 -and
                    $run.Adapter.State.ClientCalls -eq 1
                ) 'unconfirmed client tree entered service cleanup or a later client launch'
            }
        },
        [pscustomobject]@{
            Name = 'verifier client timeout is fatal with zero mutation'
            Body = {
                $adapter = New-ScriptedAdapter @(
                    (New-FakeClientResult $null @() @() `
                        $true $true $false)
                )
                $paths = New-TestPaths
                $result = New-SmokeResult 'Live' `
                    $paths.PackageDirectory $paths.HarnessPath
                $result.preflight = New-TestFacts
                $verifierCommand = Invoke-AdapterClientCommand `
                    $adapter $result 'package-verifier' `
                    $paths.PowerShellPath @('-File', $paths.VerifierPath) `
                    $null 'verifier'
                $verifier = Test-PackageVerifierResult $verifierCommand
                $result.preflight.verifierValid = [bool]$verifier.Valid
                $result.preflight.verifierOverall = $verifier.Overall
                $result.preflight.verifierExitCode = $verifierCommand.ExitCode
                $completed = Invoke-Orchestration `
                    'Live' $adapter $result $paths
                Assert-SelfTest (
                    $completed.overall -ceq 'FAIL' -and
                    $completed.ownership.mutationAttempts -eq 0 -and
                    $completed.commands.Count -eq 1 -and
                    $adapter.State.ClientCalls -eq 1 -and
                    $adapter.State.CommandCalls -eq 0
                ) 'verifier timeout reached a mutation or synchronous command adapter'
            }
        },
        [pscustomobject]@{
            Name = 'valid JSON cannot bypass an unsafe client envelope'
            Body = {
                $trustedJson = ConvertTo-TestVerifierJson (
                    New-TestVerifierObject 'Trusted'
                )
                $leaseMarker = [pscustomobject]@{ Retained = $true }
                $unsafeVerifier = @(
                    (New-FakeClientResult 0 @($trustedJson) @() `
                        $false $false $true $false $true `
                        $leaseMarker),
                    (New-FakeClientResult 0 @($trustedJson) @() `
                        $true $true $false $false $true),
                    (New-FakeClientResult 0 @($trustedJson) @() `
                        $false $true $false $false $true),
                    (New-FakeClientResult 0 @($trustedJson) @() `
                        $false $true $true $true $true),
                    (New-FakeClientResult 0 @($trustedJson) @() `
                        $false $false $true $false $false `
                        $leaseMarker)
                )
                $acceptedVerifier = @(
                    $unsafeVerifier |
                        Where-Object {
                            (Test-PackageVerifierResult $_).Valid
                        }
                )

                $unsafeHarness = @(
                    (New-FakeClientResult 0 @(
                        $script:ValidNormalHarnessJson
                    ) @() $true $true $false $false $true $null `
                        (New-FakeHarnessIdentityCheck `
                            'preMain' $true)),
                    (New-FakeClientResult 0 @(
                        $script:ValidNormalHarnessJson
                    ) @() $false $true $false $false $true),
                    (New-FakeClientResult 0 @(
                        $script:ValidNormalHarnessJson
                    ) @() $false $true $true $true $true),
                    (New-FakeClientResult 0 @(
                        $script:ValidNormalHarnessJson
                    ) @() $false $false $true $false $false `
                        $leaseMarker)
                )
                $acceptedHarness = @(
                    $unsafeHarness |
                        Where-Object {
                            (Test-HarnessResult $_ 'Normal').Valid
                        }
                )
                Assert-SelfTest (
                    $acceptedVerifier.Count -eq 0 -and
                    $acceptedHarness.Count -eq 0
                ) 'valid verifier/harness JSON bypassed an unsafe contained-client envelope'

                $responses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 0),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 4),
                    (New-FakeClientResult 0 @(
                        $script:ValidNormalHarnessJson
                    ) @() $true $true $false $false $true $null `
                        (New-FakeHarnessIdentityCheck `
                            'preMain' $true)),
                    (New-ServiceStateResult 4),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 1),
                    (New-FakeResult 0),
                    (New-AbsentServiceResult),
                    (New-FakePinnedHarnessResult 'Absent' (
                        New-FakeHarnessIdentityCheck `
                            'preAbsence' $true
                    ))
                )
                $run = Invoke-TestWorkflow (
                    New-TestFacts
                ) 'Live' $responses
                Assert-SelfTest (
                    $run.Result.overall -ceq 'FAIL' -and
                    -not $run.Result.mainHarness.valid -and
                    $run.Result.cleanup.success -and
                    $run.Result.absenceHarness.valid
                ) 'unsafe main PASS JSON was accepted or suppressed confirmed cleanup'

                $facts = New-TestFacts
                $parsed = Test-PackageVerifierResult `
                    $unsafeVerifier[0]
                $facts.verifierValid = [bool]$parsed.Valid
                $facts.verifierOverall = $parsed.Overall
                $paths = New-TestPaths
                $result = New-SmokeResult 'Live' `
                    $paths.PackageDirectory $paths.HarnessPath
                $result.preflight = $facts
                $adapter = New-ScriptedAdapter @()
                $completed = Invoke-Orchestration `
                    'Live' $adapter $result $paths
                Assert-SelfTest (
                    $completed.overall -ceq 'FAIL' -and
                    $completed.ownership.mutationAttempts -eq 0 -and
                    $completed.commands.Count -eq 0
                ) 'unsafe verifier PASS JSON reached a later external command'
            }
        },
        [pscustomobject]@{
            Name = 'unsafe verifier envelope ends the full read-only preflight immediately'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $root = [System.IO.Path]::GetDirectoryName($fixture)
                $package = Join-Path $root (
                    'preflight-package-' +
                    [Guid]::NewGuid().ToString('N')
                )
                [void][System.IO.Directory]::CreateDirectory($package)
                $paths = [pscustomobject]@{
                    PackageDirectory = $package
                    InfPath = Join-Path $package 'fsring_fsd.inf'
                    SysPath = Join-Path $package 'fsring_fsd.sys'
                    CatPath = Join-Path $package 'fsring_fsd.cat'
                    HarnessPath = $fixture
                    VerifierPath = Join-Path $package 'verify.ps1'
                    PowerShellPath = [System.IO.Path]::GetFullPath(
                        (Join-Path $PSHOME 'powershell.exe')
                    )
                    ScPath = [System.IO.Path]::GetFullPath(
                        (Join-Path $PSHOME 'powershell.exe')
                    )
                }
                [System.IO.File]::WriteAllText(
                    $paths.InfPath,
                    'test inf'
                )
                [System.IO.File]::Copy(
                    $fixture,
                    $paths.SysPath,
                    $false
                )
                [System.IO.File]::WriteAllText(
                    $paths.CatPath,
                    'test cat'
                )
                [System.IO.File]::WriteAllText(
                    $paths.VerifierPath,
                    '# never executed by the scripted adapter'
                )
                $expected = (
                    Get-FileHash -LiteralPath $fixture -Algorithm SHA256
                ).Hash
                $trustedJson = ConvertTo-TestVerifierJson (
                    New-TestVerifierObject 'Trusted'
                )

                $leaseA = [pscustomobject]@{ Name = 'unconfirmed' }
                $leaseB = [pscustomobject]@{ Name = 'malformed' }
                $unconfirmed = New-FakeClientResult 0 @($trustedJson) @() `
                    $false $false $true $false $true $leaseA
                $timedOut = New-FakeClientResult $null @() @() `
                    $true $true $false $false $true
                $malformed = New-FakeClientResult 0 @($trustedJson) @() `
                    $false $false $true $false $true $leaseB
                $malformed.ProtocolValid = 'true'

                foreach ($unsafe in @(
                    $unconfirmed,
                    $timedOut,
                    $malformed
                )) {
                    $adapter = New-ScriptedAdapter @($unsafe)
                    $result = New-SmokeResult `
                        'Live' $package $fixture
                    try {
                        Invoke-ReadOnlyPreflight `
                            $adapter $result $paths $expected
                        Assert-SelfTest (
                            $adapter.State.ClientCalls -eq 1 -and
                            $adapter.State.CommandCalls -eq 0 -and
                            $result.ownership.mutationAttempts -eq 0 -and
                            $result.commands.Count -eq 1 -and
                            $result.commands[0].operation -ceq `
                                'package-verifier' -and
                            -not $result.preflight.serviceChecked
                        ) 'unsafe verifier envelope reached sc.exe or another client'
                    } finally {
                        if ($adapter.HarnessPin -is [IDisposable]) {
                            $adapter.HarnessPin.Dispose()
                            [void]$script:RetainedHarnessPins.Remove(
                                $adapter.HarnessPin
                            )
                        }
                        foreach ($lease in @($leaseA, $leaseB)) {
                            [void]$script:RetainedClientLeases.Remove(
                                $lease
                            )
                        }
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'pre-main pre-absence and post-absence identity failures are independent'
            Body = {
                $preMainResponses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 0),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 4),
                    (New-FakeClientResult $null @() @() `
                        $false $true $false $false $true $null `
                        (New-FakeHarnessIdentityCheck 'preMain' $false)),
                    (New-ServiceStateResult 4),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 1),
                    (New-FakeResult 0),
                    (New-AbsentServiceResult)
                )
                $preMain = Invoke-TestWorkflow (
                    New-TestFacts
                ) 'Live' $preMainResponses
                Assert-SelfTest (
                    $preMain.Result.overall -ceq 'FAIL' -and
                    $preMain.Result.cleanup.success -and
                    -not $preMain.Result.absenceHarness.attempted -and
                    -not $preMain.Result.preflight.harnessIdentity.rechecks.preMain.valid -and
                    $preMain.Adapter.State.ClientCalls -eq 1
                ) 'pre-main identity failure skipped cleanup or reached a later harness launch'

                $preAbsenceResponses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 0),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 4),
                    (New-FakeClientResult 0 @(
                        $script:ValidNormalHarnessJson
                    ) @() $false $true $true $false $true $null `
                        (New-FakeHarnessIdentityCheck 'preMain' $true)),
                    (New-ServiceStateResult 4),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 1),
                    (New-FakeResult 0),
                    (New-AbsentServiceResult),
                    (New-FakeClientResult $null @() @() `
                        $false $true $false $false $true $null `
                        (New-FakeHarnessIdentityCheck 'preAbsence' $false))
                )
                $preAbsence = Invoke-TestWorkflow (
                    New-TestFacts
                ) 'Live' $preAbsenceResponses
                Assert-SelfTest (
                    $preAbsence.Result.overall -ceq 'FAIL' -and
                    $preAbsence.Result.mainHarness.valid -and
                    $preAbsence.Result.cleanup.success -and
                    $preAbsence.Result.absenceHarness.attempted -and
                    -not $preAbsence.Result.preflight.harnessIdentity.rechecks.preAbsence.valid -and
                    $null -eq $preAbsence.Result.preflight.harnessIdentity.rechecks.postAbsence
                ) 'pre-absence identity failure was conflated with another stage'

                $postResponses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 0),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 4),
                    (New-FakeClientResult 0 @(
                        $script:ValidNormalHarnessJson
                    ) @() $false $true $true $false $true $null `
                        (New-FakeHarnessIdentityCheck 'preMain' $true)),
                    (New-ServiceStateResult 4),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 1),
                    (New-FakeResult 0),
                    (New-AbsentServiceResult),
                    (New-FakeClientResult 0 @(
                        $script:ValidAbsentHarnessJson
                    ) @() $false $true $true $false $true $null `
                        (New-FakeHarnessIdentityCheck 'preAbsence' $true))
                )
                $post = Invoke-TestWorkflow (
                    New-TestFacts
                ) 'Live' $postResponses `
                    $true 2 'Pass' $false $false
                Assert-SelfTest (
                    $post.Result.overall -ceq 'FAIL' -and
                    $post.Result.mainHarness.valid -and
                    $post.Result.absenceHarness.valid -and
                    -not $post.Result.preflight.harnessIdentity.rechecks.postAbsence.valid -and
                    $post.Adapter.State.IdentityRecheckCalls -eq 1
                ) 'post-absence identity failure did not independently prevent PASS'
            }
        },
        [pscustomobject]@{
            Name = 'live PASS requires exact successful identity evidence at all three stages'
            Body = {
                $validMain = New-FakeHarnessIdentityCheck `
                    'preMain' $true
                $validAbsence = New-FakeHarnessIdentityCheck `
                    'preAbsence' $true
                $validPost = New-FakeHarnessIdentityCheck `
                    'postAbsence' $true

                $success = @(Get-SuccessResponses)
                $success[4] = New-FakePinnedHarnessResult `
                    'Normal' $validMain
                $success[10] = New-FakePinnedHarnessResult `
                    'Absent' $validAbsence
                $baseline = Invoke-TestWorkflow `
                    (New-TestFacts) 'Live' $success
                Assert-SelfTest (
                    $baseline.Result.overall -ceq 'PASS'
                ) 'exact three-stage identity evidence did not permit PASS'

                $mainChecks = @(
                    $null,
                    (New-FakeHarnessIdentityCheck `
                        'wrongMain' $true),
                    (New-FakeHarnessIdentityCheck `
                        'preMain' $false),
                    (New-FakeHarnessIdentityCheck `
                        'preMain' $true)
                )
                $mainChecks[2].Valid = $true
                $mainChecks[2].Attempted = $false
                $mainChecks[3].Valid = $false
                foreach ($check in $mainChecks) {
                    $responses = @(Get-SuccessResponses)
                    $responses[4] = New-FakePinnedHarnessResult `
                        'Normal' $check
                    $responses[10] = New-FakePinnedHarnessResult `
                        'Absent' $validAbsence
                    $run = Invoke-TestWorkflow `
                        (New-TestFacts) 'Live' $responses
                    Assert-SelfTest (
                        $run.Result.overall -ceq 'FAIL'
                    ) 'missing, wrong-stage, unattempted, or invalid preMain evidence reached PASS'
                }

                $absenceChecks = @(
                    $null,
                    (New-FakeHarnessIdentityCheck `
                        'wrongAbsence' $true),
                    (New-FakeHarnessIdentityCheck `
                        'preAbsence' $false),
                    (New-FakeHarnessIdentityCheck `
                        'preAbsence' $true)
                )
                $absenceChecks[2].Valid = $true
                $absenceChecks[2].Attempted = $false
                $absenceChecks[3].Valid = $false
                foreach ($check in $absenceChecks) {
                    $responses = @(Get-SuccessResponses)
                    $responses[4] = New-FakePinnedHarnessResult `
                        'Normal' $validMain
                    $responses[10] = New-FakePinnedHarnessResult `
                        'Absent' $check
                    $run = Invoke-TestWorkflow `
                        (New-TestFacts) 'Live' $responses
                    Assert-SelfTest (
                        $run.Result.overall -ceq 'FAIL'
                    ) 'missing, wrong-stage, unattempted, or invalid preAbsence evidence reached PASS'
                }

                $postChecks = @(
                    $null,
                    (New-FakeHarnessIdentityCheck `
                        'wrongPost' $true),
                    (New-FakeHarnessIdentityCheck `
                        'postAbsence' $false),
                    (New-FakeHarnessIdentityCheck `
                        'postAbsence' $true)
                )
                $postChecks[2].Valid = $true
                $postChecks[2].Attempted = $false
                $postChecks[3].Valid = $false
                foreach ($check in $postChecks) {
                    $responses = @(Get-SuccessResponses)
                    $responses[4] = New-FakePinnedHarnessResult `
                        'Normal' $validMain
                    $responses[10] = New-FakePinnedHarnessResult `
                        'Absent' $validAbsence
                    $paths = New-TestPaths
                    $result = New-SmokeResult `
                        'Live' $paths.PackageDirectory `
                        $paths.HarnessPath
                    $result.preflight = New-TestFacts
                    $adapter = New-ScriptedAdapter $responses
                    $state = $adapter.State
                    $postValue = $check
                    $adapter.RecheckHarnessIdentity = {
                        param(
                            $HarnessPin,
                            [string]$HarnessPath,
                            [string]$IdentityStage
                        )
                        $state.IdentityRecheckCalls++
                        return $postValue
                    }.GetNewClosure()
                    $completed = Invoke-Orchestration `
                        'Live' $adapter $result $paths
                    Assert-SelfTest (
                        $completed.overall -ceq 'FAIL'
                    ) 'missing, wrong-stage, unattempted, or invalid postAbsence evidence reached PASS'
                }
            }
        },
        [pscustomobject]@{
            Name = 'emergency cleanup is forbidden after any unconfirmed client'
            Body = {
                $result = New-SmokeResult `
                    'Live' 'C:\package' 'C:\harness.exe'
                $result.ownership.createdByThisRun = $true
                $result.ownership.servicePresent = $true
                $result.containment.allClientsConfirmed = $false
                $result.containment.cleanupBlocked = $true
                Assert-SelfTest (
                    -not (Test-EmergencyCleanupAllowed $result)
                ) 'bottom-level exception cleanup could bypass the unconfirmed-client gate'
            }
        },
        [pscustomobject]@{
            Name = 'final JSON newline and flush precede every lease and pin disposal'
            Body = {
                Assert-SelfTest (
                    $script:FinalOutputEncodingInitializationCount -eq 1 -and
                    [Console]::OutputEncoding.CodePage -eq 65001 -and
                    [Console]::OutputEncoding.GetPreamble().Length -eq 0
                ) 'script startup did not set final stdout to BOM-free UTF-8'
                $stream = New-Object System.IO.MemoryStream
                $writer = New-Object System.IO.StreamWriter(
                    $stream,
                    (New-Object System.Text.UTF8Encoding($false)),
                    1024,
                    $true
                )
                $state = [pscustomobject]@{
                    Disposed = $false
                    LengthAtDispose = [int64]0
                    LastByteAtDispose = [int]-1
                }
                $resource = New-Object psobject
                $dispose = {
                    $state.Disposed = $true
                    $state.LengthAtDispose = $stream.Length
                    if ($stream.Length -gt 0) {
                        $position = $stream.Position
                        $stream.Position = $stream.Length - 1
                        $state.LastByteAtDispose = $stream.ReadByte()
                        $stream.Position = $position
                    }
                }.GetNewClosure()
                Add-Member -InputObject $resource `
                    -MemberType ScriptMethod -Name Dispose `
                    -Value $dispose
                try {
                    $probe = Complete-SmokeResult (
                        New-SmokeResult `
                            'SelfTest' '<injected>' '<injected>'
                    ) 'PASS'
                    $emitted = @(
                        Write-FinalJsonAndDispose `
                            $probe $writer @($resource)
                    )
                    Assert-SelfTest (
                        $emitted.Count -eq 0 -and
                        $state.Disposed -and
                        $state.LengthAtDispose -gt 0 -and
                        $state.LastByteAtDispose -eq 10
                    ) 'resource disposal ran before final JSON newline/flush'
                } finally {
                    $writer.Dispose()
                    $stream.Dispose()
                }
            }
        },
        [pscustomobject]@{
            Name = 'finalizer disposes resources when JSON serialization fails'
            Body = {
                $stream = New-Object System.IO.MemoryStream
                $writer = New-Object System.IO.StreamWriter(
                    $stream,
                    (New-Object System.Text.UTF8Encoding($false)),
                    1024,
                    $true
                )
                $state = [pscustomobject]@{
                    Disposed = $false
                }
                $resource = New-Object psobject
                $dispose = {
                    $state.Disposed = $true
                }.GetNewClosure()
                Add-Member -InputObject $resource `
                    -MemberType ScriptMethod -Name Dispose `
                    -Value $dispose
                $invalid = New-Object `
                    'System.Collections.Generic.Dictionary[object,object]'
                $invalid.Add([object]1, [object]'unsupported-key')
                $serializationFailed = $false
                try {
                    try {
                        Write-FinalJsonAndDispose `
                            $invalid $writer @($resource)
                    } catch {
                        $serializationFailed = $true
                    }
                    Assert-SelfTest (
                        $serializationFailed -and
                        $state.Disposed -and
                        $stream.Length -eq 0
                    ) 'serialization failure did not dispose without output'
                } finally {
                    $writer.Dispose()
                    $stream.Dispose()
                }
            }
        },
        [pscustomobject]@{
            Name = 'expected harness hash is mandatory uppercase outside SelfTest'
            Body = {
                $command = Get-Command -Name $PSCommandPath `
                    -CommandType ExternalScript -ErrorAction Stop
                $parameter = $command.Parameters['ExpectedHarnessSha256']
                Assert-SelfTest (
                    $null -ne $parameter
                ) 'ExpectedHarnessSha256 parameter is missing'
                $sets = @(
                    $parameter.Attributes |
                        Where-Object {
                            $_ -is [System.Management.Automation.ParameterAttribute]
                        }
                )
                $live = @(
                    $sets |
                        Where-Object {
                            $_.ParameterSetName -ceq 'Live' -and
                            $_.Mandatory
                        }
                )
                $preflight = @(
                    $sets |
                        Where-Object {
                            $_.ParameterSetName -ceq 'Preflight' -and
                            $_.Mandatory
                        }
                )
                $validators = @(
                    $parameter.Attributes |
                        Where-Object {
                            $_ -is [System.Management.Automation.ValidateScriptAttribute]
                        }
                )
                $upperAccepted = $false
                $lowerRejected = $false
                if ($validators.Count -eq 1) {
                    $underscore = New-Object `
                        System.Management.Automation.PSVariable(
                            '_',
                            ('A' * 64)
                        )
                    $variables = New-Object (
                        'System.Collections.Generic.List[' +
                        'System.Management.Automation.PSVariable]'
                    )
                    $variables.Add($underscore)
                    $upperAccepted = [bool](
                        $validators[0].ScriptBlock.InvokeWithContext(
                            $null,
                            $variables,
                            @()
                        )
                    )
                    try {
                        $underscore.Value = ('a' * 64)
                        [void]$validators[0].ScriptBlock.InvokeWithContext(
                            $null,
                            $variables,
                            @()
                        )
                    } catch {
                        $lowerRejected = $true
                    }
                }
                Assert-SelfTest (
                    $live.Count -eq 1 -and
                    $preflight.Count -eq 1 -and
                    $validators.Count -eq 1 -and
                    $upperAccepted -and
                    $lowerRejected
                ) 'ExpectedHarnessSha256 is not mandatory with case-sensitive uppercase validation'
            }
        },
        [pscustomobject]@{
            Name = 'preflight harness pin initializes before any external command'
            Body = {
                $fixture = Get-TestContainedClientFixture
                $expected = (
                    Get-FileHash -LiteralPath $fixture -Algorithm SHA256
                ).Hash
                $paths = New-TestPaths
                $paths.HarnessPath = $fixture
                $adapter = New-ScriptedAdapter @()
                $result = New-SmokeResult 'PreflightOnly' `
                    $paths.PackageDirectory $paths.HarnessPath
                try {
                    $valid = Initialize-HarnessPin `
                        $adapter $result $paths $expected
                    Assert-SelfTest (
                        $valid -and
                        $result.preflight.harnessPinValid -and
                        $adapter.HarnessPin -is [FsringHarnessPin] -and
                        $result.preflight.harnessIdentity.expectedSha256 `
                            -ceq $expected -and
                        $result.preflight.harnessIdentity.observedSha256 `
                            -ceq $expected -and
                        $result.preflight.harnessIdentity.machine `
                            -ceq '0x8664' -and
                        $result.preflight.harnessIdentity.size -gt 0 -and
                        $result.preflight.harnessIdentity.volumeSerial `
                            -cmatch '^[0-9A-F]{16}$' -and
                        $result.preflight.harnessIdentity.fileId `
                            -cmatch '^[0-9A-F]{32}$' -and
                        $adapter.State.ClientCalls -eq 0 -and
                        $adapter.State.CommandCalls -eq 0
                    ) 'preflight pin did not publish initial same-handle identity before commands'
                } finally {
                    if ($adapter.HarnessPin -is [IDisposable]) {
                        $adapter.HarnessPin.Dispose()
                    }
                }

                $wrongAdapter = New-ScriptedAdapter @()
                $wrongResult = New-SmokeResult 'PreflightOnly' `
                    $paths.PackageDirectory $paths.HarnessPath
                $wrong = Initialize-HarnessPin `
                    $wrongAdapter $wrongResult $paths ('0' * 64)
                Assert-SelfTest (
                    -not $wrong -and
                    -not $wrongResult.preflight.harnessPinValid -and
                    $null -eq $wrongAdapter.HarnessPin -and
                    $wrongAdapter.State.ClientCalls -eq 0 -and
                    $wrongAdapter.State.CommandCalls -eq 0
                ) 'wrong expected hash reached an external command'
            }
        },
        [pscustomobject]@{
            Name = 'native readiness helper has exact x64 layouts and raw query contract'
            Body = {
                Assert-SelfTest ($null -ne ('FsringNativeReadiness' -as [type])) 'FsringNativeReadiness helper is missing'
                Assert-SelfTest ([FsringNativeReadiness]::GetRtlOsVersionInfoSize() -eq 276) 'RTL_OSVERSIONINFOW size is not 276'
                Assert-SelfTest ([FsringNativeReadiness]::GetSystemInfoSize() -eq 48) 'SYSTEM_INFO size is not 48'
                Assert-SelfTest ([FsringNativeReadiness]::GetCodeIntegrityInfoSize() -eq 8) 'SYSTEM_CODEINTEGRITY_INFORMATION size is not 8'
                Assert-SelfTest ([FsringNativeReadiness]::GetBootEnvironmentInfoSize() -eq 32) 'SYSTEM_BOOT_ENVIRONMENT_INFORMATION size is not 32'
                Assert-SelfTest ([FsringNativeReadiness]::GetBootIdentifierOffset() -eq 0) 'BootIdentifier offset is not 0'
                Assert-SelfTest ([FsringNativeReadiness]::GetFirmwareTypeOffset() -eq 16) 'FirmwareType offset is not 16'
                Assert-SelfTest ([FsringNativeReadiness]::GetBootFlagsOffset() -eq 24) 'BootFlags offset is not 24'
                $observed = [FsringNativeReadiness]::Query()
                $native = ConvertFrom-NativeReadinessObservation $observed
                Assert-SelfTest $native.OsVersionQueryValid 'current RtlGetVersion observation was rejected'
                Assert-SelfTest ($native.NativeArchitecture -eq 9 -and $native.HostX64) 'current GetNativeSystemInfo observation was not native AMD64'
                Assert-SelfTest $native.CodeIntegrityQueryValid 'current class-103 observation was rejected'
                Assert-SelfTest $native.BootEnvironmentQueryValid 'current class-90 observation was rejected'
            }
        },
        [pscustomobject]@{
            Name = 'BCD store scope enables privileges at Impersonate without provider calls'
            Body = {
                $storeClass = $null
                try {
                    $storeClass = New-ReadOnlyBcdStoreManagementClass
                    $scope = $storeClass.Scope
                    Assert-SelfTest (
                        $storeClass -is [System.Management.ManagementClass] -and
                        $storeClass.Path.ClassName -ceq 'BcdStore' -and
                        $scope.IsConnected -and
                        $scope.Path.Path -ceq '\\.\root\WMI' -and
                        $scope.Options.EnablePrivileges -and
                        $scope.Options.Impersonation -eq [System.Management.ImpersonationLevel]::Impersonate -and
                        [string]::IsNullOrEmpty($scope.Options.Username) -and
                        [string]::IsNullOrEmpty($scope.Options.Authority)
                    ) 'BCD store scope did not connect locally with privileges enabled at Impersonate'
                } finally {
                    if ($null -ne $storeClass) {
                        $storeClass.Dispose()
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'Windows 7 x64 leaves BCD unattempted and is NOT RUN'
            Body = {
                $native = New-TestNativeReadinessObservation 6 1 7601
                $collected = Invoke-TestReadinessCollection $native (New-TestBcdObservation) $true $true $true
                Assert-SelfTest (
                    $collected.Facts.osVersionQueryValid -and
                    -not $collected.Facts.windows10OrLater -and
                    -not $collected.Facts.bootConfigurationAttempted -and
                    $collected.Adapter.State.BcdCalls -eq 0
                ) 'Windows 7 attempted BCD or produced invalid OS facts'
                Assert-TestReadinessNotRunnable $collected.Facts 'Windows 7 readiness was runnable or mutated'
            }
        },
        [pscustomobject]@{
            Name = 'raw native status size length and GUID failures fail closed'
            Body = {
                $invalidCases = @(
                    [pscustomobject]@{ Name = 'Rtl status'; Property = 'RtlStatus'; Value = [int32]-1; Invalid = 'os' },
                    [pscustomobject]@{ Name = 'Rtl input size'; Property = 'OsInputSize'; Value = [uint32]275; Invalid = 'os' },
                    [pscustomobject]@{ Name = 'Rtl returned size'; Property = 'OsReturnedSize'; Value = [uint32]275; Invalid = 'os' },
                    [pscustomobject]@{ Name = 'Rtl platform'; Property = 'OsPlatformId'; Value = [uint32]1; Invalid = 'os' },
                    [pscustomobject]@{ Name = 'Rtl version'; Property = 'OsMajor'; Value = [uint32]0; Invalid = 'os' },
                    [pscustomobject]@{ Name = 'CI status'; Property = 'CodeIntegrityStatus'; Value = [int32]-1; Invalid = 'ci' },
                    [pscustomobject]@{ Name = 'CI buffer size'; Property = 'CodeIntegrityBufferSize'; Value = [uint32]7; Invalid = 'ci' },
                    [pscustomobject]@{ Name = 'CI input Length'; Property = 'CodeIntegrityInputLength'; Value = [uint32]7; Invalid = 'ci' },
                    [pscustomobject]@{ Name = 'CI ReturnLength'; Property = 'CodeIntegrityReturnLength'; Value = [uint32]7; Invalid = 'ci' },
                    [pscustomobject]@{ Name = 'CI returned Length'; Property = 'CodeIntegrityReturnedLength'; Value = [uint32]7; Invalid = 'ci' },
                    [pscustomobject]@{ Name = 'boot status'; Property = 'BootEnvironmentStatus'; Value = [int32]-1; Invalid = 'boot' },
                    [pscustomobject]@{ Name = 'boot buffer size'; Property = 'BootEnvironmentBufferSize'; Value = [uint32]31; Invalid = 'boot' },
                    [pscustomobject]@{ Name = 'boot ReturnLength'; Property = 'BootEnvironmentReturnLength'; Value = [uint32]31; Invalid = 'boot' },
                    [pscustomobject]@{ Name = 'empty boot GUID'; Property = 'BootIdentifier'; Value = [Guid]::Empty; Invalid = 'boot' }
                )
                foreach ($case in $invalidCases) {
                    $native = New-TestNativeReadinessObservation
                    $native.($case.Property) = $case.Value
                    $throwOnBcd = ($case.Invalid -ceq 'os' -or $case.Invalid -ceq 'boot')
                    $collected = Invoke-TestReadinessCollection $native (New-TestBcdObservation) $true $true $throwOnBcd
                    if ($case.Invalid -ceq 'os') {
                        Assert-SelfTest (
                            -not $collected.Facts.osVersionQueryValid -and
                            $null -eq $collected.Facts.osMajor -and
                            $null -eq $collected.Facts.osMinor -and
                            $null -eq $collected.Facts.osBuild
                        ) "$($case.Name) was accepted or emitted unknown version numbers as known"
                    } elseif ($case.Invalid -ceq 'ci') {
                        Assert-SelfTest (
                            -not $collected.Facts.codeIntegrityQueryValid -and
                            $null -eq $collected.Facts.codeIntegrityOptions
                        ) "$($case.Name) was accepted or emitted unknown CI options as known"
                    } else {
                        Assert-SelfTest (
                            -not $collected.Facts.bootEnvironmentQueryValid -and
                            $null -eq $collected.Facts.bootIdentifier -and
                            -not $collected.Facts.bootConfigurationAttempted -and
                            $collected.Adapter.State.BcdCalls -eq 0
                        ) "$($case.Name) was accepted or reached BCD"
                    }
                    Assert-SelfTest (
                        $collected.Facts.signingState -ceq 'UNKNOWN' -and
                        -not $collected.Facts.rebootRequired
                    ) "$($case.Name) did not derive UNKNOWN without a reboot claim"
                    Assert-TestReadinessNotRunnable $collected.Facts "$($case.Name) was runnable or mutated"
                }
            }
        },
        [pscustomobject]@{
            Name = 'native architecture requires AMD64 value 9 and a 64-bit process'
            Body = {
                foreach ($mutation in @(
                    [pscustomobject]@{ Name = 'ARM64'; Property = 'NativeArchitecture'; Value = [uint16]12 },
                    [pscustomobject]@{ Name = 'x86'; Property = 'NativeArchitecture'; Value = [uint16]0 },
                    [pscustomobject]@{ Name = '32-bit process'; Property = 'Is64BitProcess'; Value = [bool]$false },
                    [pscustomobject]@{ Name = 'wrong SYSTEM_INFO size'; Property = 'SystemInfoSize'; Value = [uint32]47 }
                )) {
                    $native = New-TestNativeReadinessObservation
                    $native.($mutation.Property) = $mutation.Value
                    $collected = Invoke-TestReadinessCollection $native (New-TestBcdObservation) $true $true $true
                    Assert-SelfTest (
                        -not $collected.Facts.hostX64 -and
                        -not $collected.Facts.bootConfigurationAttempted -and
                        $collected.Adapter.State.BcdCalls -eq 0
                    ) "$($mutation.Name) was classified as native AMD64 or reached BCD"
                    Assert-TestReadinessNotRunnable $collected.Facts "$($mutation.Name) was runnable or mutated"
                }
            }
        },
        [pscustomobject]@{
            Name = 'non-elevated readiness adapter never queries BCD'
            Body = {
                $collected = Invoke-TestReadinessCollection (New-TestNativeReadinessObservation) (New-TestBcdObservation) $false $true $true
                Assert-SelfTest (
                    -not $collected.Facts.bootConfigurationAttempted -and
                    $collected.Adapter.State.BcdCalls -eq 0
                ) 'non-elevated readiness called the throwing BCD adapter'
                Assert-TestReadinessNotRunnable $collected.Facts 'non-elevated readiness was runnable or mutated'
            }
        },
        [pscustomobject]@{
            Name = 'BCD provider transcript failures are invalid and never configured-off'
            Body = {
                $duplicateDecision = Test-BcdElementTypeRoster (
                    [object[]]@(
                        [uint32]0x12000004,
                        [uint32]0x12000004,
                        [uint32]0x16000049
                    )
                )
                Assert-SelfTest (
                    -not $duplicateDecision.Valid -and
                    -not $duplicateDecision.ShouldGetElement
                ) 'a duplicate roster could reach the optional GetElement call'
                $mutations = @(
                    [pscustomobject]@{ Name = 'provider failure'; Property = 'ProviderSucceeded'; Value = [bool]$false },
                    [pscustomobject]@{ Name = 'OpenStore false'; Property = 'OpenStoreReturn'; Value = [bool]$false },
                    [pscustomobject]@{ Name = 'OpenStore non-Boolean'; Property = 'OpenStoreReturn'; Value = [int32]1 },
                    [pscustomobject]@{ Name = 'wrong store class'; Property = 'StoreClass'; Value = 'Other' },
                    [pscustomobject]@{ Name = 'non-system store'; Property = 'StoreFilePath'; Value = 'C:\other.bcd' },
                    [pscustomobject]@{ Name = 'OpenObject false'; Property = 'OpenObjectReturn'; Value = [bool]$false },
                    [pscustomobject]@{ Name = 'OpenObject non-Boolean'; Property = 'OpenObjectReturn'; Value = [int32]1 },
                    [pscustomobject]@{ Name = 'wrong object class'; Property = 'ObjectClass'; Value = 'Other' },
                    [pscustomobject]@{ Name = 'wrong object identity'; Property = 'ObjectId'; Value = '{11111111-1111-1111-1111-111111111111}' },
                    [pscustomobject]@{ Name = 'wrong object store'; Property = 'ObjectStoreFilePath'; Value = 'C:\other.bcd' },
                    [pscustomobject]@{ Name = 'wrong object type'; Property = 'ObjectType'; Value = [uint32]0x10200002 },
                    [pscustomobject]@{ Name = 'non-UInt32 object type'; Property = 'ObjectType'; Value = [int64]0x10200003 },
                    [pscustomobject]@{ Name = 'enumeration false'; Property = 'EnumerateElementTypesReturn'; Value = [bool]$false },
                    [pscustomobject]@{ Name = 'enumeration non-Boolean'; Property = 'EnumerateElementTypesReturn'; Value = [int32]1 },
                    [pscustomobject]@{ Name = 'non-UInt32 roster'; Property = 'ElementTypes'; Value = [object[]]@([int64]0x16000049) },
                    [pscustomobject]@{ Name = 'duplicate roster'; Property = 'ElementTypes'; Value = [object[]]@([uint32]0x16000049, [uint32]0x16000049) },
                    [pscustomobject]@{ Name = 'GetElement false'; Property = 'GetElementReturn'; Value = [bool]$false },
                    [pscustomobject]@{ Name = 'GetElement non-Boolean'; Property = 'GetElementReturn'; Value = [int32]1 },
                    [pscustomobject]@{ Name = 'wrong element class'; Property = 'ElementClass'; Value = 'BcdIntegerElement' },
                    [pscustomobject]@{ Name = 'wrong element type'; Property = 'ElementType'; Value = [uint32]0x16000048 },
                    [pscustomobject]@{ Name = 'non-UInt32 element type'; Property = 'ElementType'; Value = [int64]0x16000049 },
                    [pscustomobject]@{ Name = 'wrong element identity'; Property = 'ElementObjectId'; Value = '{11111111-1111-1111-1111-111111111111}' },
                    [pscustomobject]@{ Name = 'wrong element store'; Property = 'ElementStoreFilePath'; Value = 'C:\other.bcd' },
                    [pscustomobject]@{ Name = 'non-Boolean element value'; Property = 'ElementBoolean'; Value = [int32]1 }
                )
                foreach ($mutation in $mutations) {
                    $bcd = New-TestBcdObservation
                    $bcd.($mutation.Property) = $mutation.Value
                    $collected = Invoke-TestReadinessCollection (New-TestNativeReadinessObservation) $bcd
                    Assert-SelfTest (
                        $collected.Facts.bootConfigurationAttempted -and
                        -not $collected.Facts.bootConfigurationValid -and
                        -not $collected.Facts.testSigningConfigured -and
                        $collected.Facts.signingState -ceq 'UNKNOWN' -and
                        -not $collected.Facts.rebootRequired
                    ) "$($mutation.Name) was accepted or inferred configured-off"
                    Assert-TestReadinessNotRunnable $collected.Facts "$($mutation.Name) was runnable or mutated"
                }
            }
        },
        [pscustomobject]@{
            Name = 'absent BCD TESTSIGNING element is validly configured false'
            Body = {
                $bcd = New-TestBcdObservation -Configured Absent
                $collected = Invoke-TestReadinessCollection (New-TestNativeReadinessObservation -CodeIntegrityOptions 1) $bcd
                Assert-SelfTest (
                    $collected.Facts.bootConfigurationAttempted -and
                    $collected.Facts.bootConfigurationValid -and
                    -not $collected.Facts.testSigningConfigured -and
                    $collected.Facts.signingState -ceq 'DISABLED' -and
                    -not $collected.Facts.rebootRequired -and
                    $collected.Adapter.State.BcdCalls -eq 1
                ) 'absent TESTSIGNING element was not validly configured false'
                Assert-TestReadinessNotRunnable $collected.Facts 'disabled TESTSIGNING was runnable or mutated'
            }
        },
        [pscustomobject]@{
            Name = 'present BCD roster with failed GetElement is UNKNOWN'
            Body = {
                $bcd = New-TestBcdObservation
                $bcd.GetElementReturn = [bool]$false
                $collected = Invoke-TestReadinessCollection (New-TestNativeReadinessObservation) $bcd
                Assert-SelfTest (
                    -not $collected.Facts.bootConfigurationValid -and
                    -not $collected.Facts.testSigningConfigured -and
                    $collected.Facts.signingState -ceq 'UNKNOWN' -and
                    -not $collected.Facts.rebootRequired
                ) 'failed GetElement was inferred as configured false'
                Assert-TestReadinessNotRunnable $collected.Facts 'failed GetElement was runnable or mutated'
            }
        },
        [pscustomobject]@{
            Name = 'active configured TESTSIGNING truth table is exact'
            Body = {
                $matrix = @(
                    [pscustomobject]@{ Active = $false; Configured = 'False'; State = 'DISABLED'; Reboot = $false; Runnable = $false },
                    [pscustomobject]@{ Active = $false; Configured = 'True'; State = 'ENABLE_REBOOT_REQUIRED'; Reboot = $true; Runnable = $false },
                    [pscustomobject]@{ Active = $true; Configured = 'False'; State = 'DISABLE_REBOOT_REQUIRED'; Reboot = $true; Runnable = $false },
                    [pscustomobject]@{ Active = $true; Configured = 'True'; State = 'ENABLED'; Reboot = $false; Runnable = $true }
                )
                foreach ($row in $matrix) {
                    $options = if ($row.Active) { [uint32]3 } else { [uint32]1 }
                    $collected = Invoke-TestReadinessCollection (New-TestNativeReadinessObservation -CodeIntegrityOptions $options) (New-TestBcdObservation -Configured $row.Configured)
                    Assert-SelfTest (
                        $collected.Facts.testSigningActive -eq $row.Active -and
                        $collected.Facts.testSigningConfigured -eq ($row.Configured -ceq 'True') -and
                        $collected.Facts.signingState -ceq $row.State -and
                        $collected.Facts.rebootRequired -eq $row.Reboot
                    ) "truth-table row $($row.Active)/$($row.Configured) is wrong"
                    if ($row.Runnable) {
                        Assert-TestReadinessRunnable $collected.Facts 'fully ready TESTSIGNING row was not runnable'
                    } else {
                        Assert-TestReadinessNotRunnable $collected.Facts "truth-table row $($row.State) was runnable or mutated"
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'unknown CI bits are accepted while CI-disabled and trust blockers fail closed'
            Body = {
                $unknownBits = Invoke-TestReadinessCollection (New-TestNativeReadinessObservation -CodeIntegrityOptions ([uint32]0xE003)) (New-TestBcdObservation)
                Assert-SelfTest (
                    $unknownBits.Facts.codeIntegrityQueryValid -and
                    $unknownBits.Facts.codeIntegrityOptions -eq [uint32]0xE003 -and
                    $unknownBits.Facts.codeIntegrityEnabled -and
                    $unknownBits.Facts.testSigningActive
                ) 'unknown Code Integrity bits invalidated the known enabled/testsign bits'
                Assert-TestReadinessRunnable $unknownBits.Facts 'known CI bits with unrelated bits were not runnable'

                $ciDisabled = Invoke-TestReadinessCollection (New-TestNativeReadinessObservation -CodeIntegrityOptions 2) (New-TestBcdObservation)
                Assert-SelfTest (
                    -not $ciDisabled.Facts.codeIntegrityEnabled -and
                    $ciDisabled.Facts.testSigningActive -and
                    $ciDisabled.Facts.signingState -ceq 'ENABLED'
                ) 'CI-disabled fixture did not preserve active/configured truth facts'
                Assert-TestReadinessNotRunnable $ciDisabled.Facts 'Code Integrity disabled fixture was runnable or mutated'

                $untrusted = Invoke-TestReadinessCollection (New-TestNativeReadinessObservation) (New-TestBcdObservation)
                $untrusted.Facts.trustReady = $false
                Assert-TestReadinessNotRunnable $untrusted.Facts 'untrusted otherwise-ready package was runnable or mutated'
            }
        },
        [pscustomobject]@{
            Name = 'invalid package retains FAIL precedence over readiness blocker'
            Body = {
                $native = New-TestNativeReadinessObservation 6 1 7601
                $collected = Invoke-TestReadinessCollection $native (New-TestBcdObservation) $true $true $true
                $collected.Facts.infPresent = $false
                $run = Invoke-TestWorkflow $collected.Facts 'Live' @()
                Assert-SelfTest (
                    $run.Result.overall -ceq 'FAIL' -and
                    -not $run.Result.preflight.runnable -and
                    $run.Result.ownership.mutationAttempts -eq 0 -and
                    $run.Result.commands.Count -eq 0
                ) 'invalid package plus Windows 7 did not retain structural FAIL precedence'
            }
        },
        [pscustomobject]@{
            Name = 'non-elevated preflight is NOT RUN with zero mutation'
            Body = {
                $facts = New-TestFacts
                $facts.elevated = $false
                $run = Invoke-TestWorkflow $facts 'Live' @()
                Assert-SelfTest ($run.Result.overall -ceq 'NOT RUN') 'non-elevated result was not NOT RUN'
                Assert-SelfTest ($run.Result.ownership.mutationAttempts -eq 0 -and $run.Result.commands.Count -eq 0) 'non-elevated path invoked a command or mutation'
            }
        },
        [pscustomobject]@{
            Name = 'C4 preflight binds source identity to the candidate manifest'
            Body = {
                $fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('fsring-c4-pf-' + [Guid]::NewGuid().ToString('N'))
                [void][IO.Directory]::CreateDirectory($fixtureRoot)
                try {
                    $utf8 = New-Object System.Text.UTF8Encoding $false
                    $manifestPath = Join-Path $fixtureRoot 'candidate-artifacts.json'
                    $manifest = [ordered]@{
                        schema = 'fsring-c4-candidate-artifacts/v1'
                        version = 1
                        sourceCommit = ('b' * 40)
                        sourceTree = ('c' * 40)
                        profile = [ordered]@{ id = 'win10-x64-release' }
                        artifacts = [ordered]@{ package = [ordered]@{ setSha256 = ('e' * 64) } }
                        artifactSetSha256 = ('d' * 64)
                    }
                    [IO.File]::WriteAllBytes($manifestPath, $utf8.GetBytes((ConvertTo-C4CanonicalJson $manifest) + "`n"))
                    $manifestHash = Get-C4FileSha256Lower $manifestPath
                    $harnessPath = Join-Path $fixtureRoot 'fsring-control-smoke.exe'
                    [IO.File]::WriteAllBytes($harnessPath, $utf8.GetBytes('harness'))
                    $harnessHash = (Get-C4FileSha256Lower $harnessPath).ToUpperInvariant()
                    $envelope = New-C4PreflightOnlyEnvelope -AttemptId '00112233445566778899aabbccddeeff' -CandidateManifestPath $manifestPath -ExpectedCandidateManifestSha256 $manifestHash -PackageDirectory $fixtureRoot -HarnessPath $harnessPath -ExpectedHarnessSha256 $harnessHash -Facts (New-TestFacts)
                    Assert-SelfTest ($envelope.sourceCommit -ceq ('b' * 40)) 'preflight sourceCommit did not come from the candidate manifest'
                    Assert-SelfTest ($envelope.sourceTree -ceq ('c' * 40)) 'preflight sourceTree did not come from the candidate manifest'
                    Assert-SelfTest ($envelope.profile.id -ceq 'win10-x64-release') 'preflight profile did not come from the candidate manifest'
                    Assert-SelfTest ($envelope.artifactSetSha256 -ceq ('d' * 64)) 'preflight artifactSetSha256 did not come from the candidate manifest'
                    Assert-SelfTest ($envelope.packageSetSha256 -ceq ('e' * 64)) 'preflight packageSetSha256 did not come from the candidate manifest'
                } finally {
                    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        },
        [pscustomobject]@{
            Name = 'C4 preflight runnable follows host readiness not file identity'
            Body = {
                $fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('fsring-c4-pf-' + [Guid]::NewGuid().ToString('N'))
                [void][IO.Directory]::CreateDirectory($fixtureRoot)
                try {
                    $utf8 = New-Object System.Text.UTF8Encoding $false
                    $manifestPath = Join-Path $fixtureRoot 'candidate-artifacts.json'
                    [IO.File]::WriteAllBytes($manifestPath, $utf8.GetBytes((ConvertTo-C4CanonicalJson ([ordered]@{
                        schema = 'fsring-c4-candidate-artifacts/v1'
                        sourceCommit = ('b' * 40)
                        sourceTree = ('c' * 40)
                    })) + "`n"))
                    $manifestHash = Get-C4FileSha256Lower $manifestPath
                    $harnessPath = Join-Path $fixtureRoot 'fsring-control-smoke.exe'
                    [IO.File]::WriteAllBytes($harnessPath, $utf8.GetBytes('harness'))
                    $harnessHash = (Get-C4FileSha256Lower $harnessPath).ToUpperInvariant()
                    $unready = New-TestFacts
                    $unready.elevated = $false
                    $blocked = New-C4PreflightOnlyEnvelope -AttemptId '00112233445566778899aabbccddeeff' -CandidateManifestPath $manifestPath -ExpectedCandidateManifestSha256 $manifestHash -PackageDirectory $fixtureRoot -HarnessPath $harnessPath -ExpectedHarnessSha256 $harnessHash -Facts $unready
                    Assert-SelfTest (-not $blocked.preflight.runnable) 'an unready host was still reported runnable'
                    Assert-SelfTest (@($blocked.preflight.reasonCodes) -ccontains 'NOT_ELEVATED') 'preflight did not report NOT_ELEVATED'
                    $ready = New-C4PreflightOnlyEnvelope -AttemptId '00112233445566778899aabbccddeeff' -CandidateManifestPath $manifestPath -ExpectedCandidateManifestSha256 $manifestHash -PackageDirectory $fixtureRoot -HarnessPath $harnessPath -ExpectedHarnessSha256 $harnessHash -Facts (New-TestFacts)
                    Assert-SelfTest ([bool]$ready.preflight.runnable) 'a ready host with exact files was not runnable'
                    Assert-SelfTest (@($ready.preflight.reasonCodes).Count -eq 0) 'a runnable preflight still reported reason codes'
                } finally {
                    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        },
        [pscustomobject]@{
            Name = 'wrong host architecture is NOT RUN with zero mutation'
            Body = {
                $facts = New-TestFacts
                $facts.hostX64 = $false
                $facts.scPinValid = $false
                $facts.scPresent = $false
                $facts.serviceChecked = $false
                $facts.serviceAbsent = $false
                $run = Invoke-TestWorkflow $facts 'Live' @()
                Assert-SelfTest (
                    $run.Result.overall -ceq 'NOT RUN' -and
                    -not $run.Result.preflight.runnable -and
                    $run.Result.ownership.mutationAttempts -eq 0 -and
                    $run.Result.commands.Count -eq 0
                ) 'unsupported host without sc/service inspection did not remain NOT RUN'
            }
        },
        [pscustomobject]@{
            Name = 'wrong package architecture fails before mutation'
            Body = {
                $facts = New-TestFacts
                $facts.sysAmd64 = $false
                $facts.sysMachine = '0xAA64'
                $run = Invoke-TestWorkflow $facts 'Live' @()
                Assert-SelfTest ($run.Result.overall -ceq 'FAIL' -and $run.Result.ownership.mutationAttempts -eq 0) 'wrong package architecture did not fail closed'
            }
        },
        [pscustomobject]@{
            Name = 'missing package or harness fails before mutation'
            Body = {
                foreach ($property in @('packageDirectoryPresent', 'infPresent', 'sysPresent', 'catPresent', 'harnessPresent')) {
                    $facts = New-TestFacts
                    $facts[$property] = $false
                    $run = Invoke-TestWorkflow $facts 'Live' @()
                    Assert-SelfTest ($run.Result.overall -ceq 'FAIL' -and $run.Result.ownership.mutationAttempts -eq 0) "missing $property did not fail closed"
                }
            }
        },
        [pscustomobject]@{
            Name = 'verifier failure is fatal before mutation'
            Body = {
                $facts = New-TestFacts
                $facts.verifierExitCode = 1
                $facts.verifierOverall = 'FAIL'
                $run = Invoke-TestWorkflow $facts 'Live' @()
                Assert-SelfTest ($run.Result.overall -ceq 'FAIL' -and $run.Result.commands.Count -eq 0) 'verifier failure reached live commands'
            }
        },
        [pscustomobject]@{
            Name = 'integrity PASS with trustReady false is NOT RUN'
            Body = {
                $facts = New-TestFacts
                $facts.trustReady = $false
                $run = Invoke-TestWorkflow $facts 'Live' @()
                Assert-SelfTest ($run.Result.overall -ceq 'NOT RUN' -and $run.Result.ownership.mutationAttempts -eq 0) 'trustReady false was load-ready'
            }
        },
        [pscustomobject]@{
            # A locally trusted test root is load-ready only while TESTSIGNING
            # is active, so prove the two conditions are independent and that
            # the signing gate -- not the trust gate -- is what refuses here.
            # The positive control keeps this from passing vacuously.
            Name = 'trustReady true is still not runnable without TESTSIGNING'
            Body = {
                $ready = New-TestFacts
                $ready.trustReady = $true
                $readyDecision = Get-PreflightDecision $ready
                Assert-SelfTest ($readyDecision.Runnable -and
                    @(Get-C4PreflightReasonCodes $ready $readyDecision).Count -eq 0) 'positive control is not runnable, so the signing assertion below proves nothing'

                $facts = New-TestFacts
                $facts.trustReady = $true
                $facts.testSigningActive = $false
                $facts.testSigningConfigured = $false
                Set-SigningReadinessState $facts
                $decision = Get-PreflightDecision $facts
                Assert-SelfTest (-not $decision.Runnable) 'trustReady true was runnable with TESTSIGNING disabled'
                $codes = @(Get-C4PreflightReasonCodes $facts $decision)
                Assert-SelfTest ($codes -ccontains 'TEST_SIGNING_NOT_READY') 'TESTSIGNING refusal did not report TEST_SIGNING_NOT_READY'
                Assert-SelfTest (-not ($codes -ccontains 'PACKAGE_NOT_TRUST_READY')) 'a trustReady package still reported PACKAGE_NOT_TRUST_READY'
            }
        },
        [pscustomobject]@{
            Name = 'existing service is never stopped or deleted'
            Body = {
                $facts = New-TestFacts
                $facts.serviceAbsent = $false
                $facts.serviceQueryExitCode = 0
                $run = Invoke-TestWorkflow $facts 'Live' @()
                Assert-SelfTest ($run.Result.overall -ceq 'FAIL' -and $run.Result.commands.Count -eq 0) 'existing service reached command workflow'
                Assert-SelfTest (-not $run.Result.cleanup.attempted) 'existing service entered cleanup'
            }
        },
        [pscustomobject]@{
            Name = 'PreflightOnly never mutates even when runnable'
            Body = {
                $run = Invoke-TestWorkflow (New-TestFacts) 'PreflightOnly' @()
                Assert-SelfTest ($run.Result.overall -ceq 'NOT RUN' -and $run.Result.preflight.runnable) 'runnable PreflightOnly classification is wrong'
                Assert-SelfTest ($run.Result.ownership.mutationAttempts -eq 0 -and $run.Result.commands.Count -eq 0) 'PreflightOnly invoked live commands'
            }
        },
        [pscustomobject]@{
            Name = 'cleanup is inert without run ownership'
            Body = {
                $paths = New-TestPaths
                $result = New-SmokeResult 'Live' $paths.PackageDirectory $paths.HarnessPath
                $adapter = New-ScriptedAdapter @()
                $cleanup = Invoke-OwnedCleanup $adapter $result $paths.ScPath
                Assert-SelfTest (-not $cleanup.attempted -and $result.commands.Count -eq 0) 'unowned cleanup invoked a command'
            }
        },
        [pscustomobject]@{
            Name = 'identity change and pre-create service race grant no ownership'
            Body = {
                $identityRun = Invoke-TestWorkflow (New-TestFacts) 'Live' @() $false
                Assert-SelfTest ($identityRun.Result.ownership.mutationAttempts -eq 0 -and -not $identityRun.Result.ownership.createdByThisRun) 'identity failure mutated service state'

                $raceRun = Invoke-TestWorkflow (New-TestFacts) 'Live' @((New-ServiceStateResult 1))
                Assert-SelfTest ($raceRun.Result.overall -ceq 'FAIL' -and $raceRun.Result.ownership.mutationAttempts -eq 0) 'pre-create service race mutated service state'
                Assert-SelfTest ($raceRun.Result.commands.Count -eq 1 -and $raceRun.Result.commands[0].operation -ceq 'pre-create-query') 'pre-create race command log is not exact'
            }
        },
        [pscustomobject]@{
            Name = 'create failure grants no ownership or cleanup'
            Body = {
                $responses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 1073)
                )
                $run = Invoke-TestWorkflow `
                    (New-TestFacts) 'Live' $responses `
                    $true 2 'Fail'
                Assert-SelfTest ($run.Result.overall -ceq 'FAIL' -and -not $run.Result.ownership.createdByThisRun) 'create failure acquired ownership'
                Assert-SelfTest (-not $run.Result.cleanup.attempted) 'create failure ran owned cleanup'
                $mutations = @($run.Result.commands | Where-Object { $_.mutating })
                Assert-SelfTest ($mutations.Count -eq 1 -and $mutations[0].operation -ceq 'create') 'create failure attempted stop/delete'
                Assert-SelfTest ($run.Result.commands.Count -eq 2 -and -not $run.Result.absenceHarness.attempted) 'create failure touched the harness after foreign-state ambiguity'
            }
        },
        [pscustomobject]@{
            Name = 'start and wait failures execute owned cleanup'
            Body = {
                $startResponses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 0),
                    (New-FakeResult 1058),
                    (New-ServiceStateResult 1),
                    (New-FakeResult 1062),
                    (New-ServiceStateResult 1),
                    (New-FakeResult 0),
                    (New-AbsentServiceResult),
                    (New-FakePinnedHarnessResult 'Absent' (
                        New-FakeHarnessIdentityCheck `
                            'preAbsence' $true
                    ))
                )
                $startRun = Invoke-TestWorkflow (New-TestFacts) 'Live' $startResponses
                Assert-SelfTest ($startRun.Result.overall -ceq 'FAIL' -and $startRun.Result.cleanup.success) 'start failure did not complete owned cleanup'

                $waitResponses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 0),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 2),
                    (New-ServiceStateResult 2),
                    (New-ServiceStateResult 2),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 1),
                    (New-FakeResult 0),
                    (New-AbsentServiceResult),
                    (New-FakePinnedHarnessResult 'Absent' (
                        New-FakeHarnessIdentityCheck `
                            'preAbsence' $true
                    ))
                )
                $waitRun = Invoke-TestWorkflow (New-TestFacts) 'Live' $waitResponses
                Assert-SelfTest ($waitRun.Result.overall -ceq 'FAIL' -and $waitRun.Result.live.waitRunning.timedOut) 'wait failure did not time out'
                Assert-SelfTest ($waitRun.Result.cleanup.success) 'wait failure did not complete owned cleanup'
            }
        },
        [pscustomobject]@{
            Name = 'failing main harness still executes owned cleanup'
            Body = {
                $responses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 0),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 4),
                    (New-FakeClientResult 1 @(
                        $script:FailingNormalHarnessJson
                    ) @() $false $true $true $false $true $null `
                        (New-FakeHarnessIdentityCheck `
                            'preMain' $true)),
                    (New-ServiceStateResult 4),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 1),
                    (New-FakeResult 0),
                    (New-AbsentServiceResult),
                    (New-FakePinnedHarnessResult 'Absent' (
                        New-FakeHarnessIdentityCheck `
                            'preAbsence' $true
                    ))
                )
                $run = Invoke-TestWorkflow (New-TestFacts) 'Live' $responses
                Assert-SelfTest ($run.Result.overall -ceq 'FAIL' -and $run.Result.cleanup.success) 'main harness failure skipped cleanup'
                Assert-SelfTest ($run.Result.absenceHarness.valid) 'post-cleanup absence proof was skipped'
            }
        },
        [pscustomobject]@{
            Name = 'live PASS requires exact calls, main, cleanup, and absence'
            Body = {
                $responses = @(Get-SuccessResponses)
                $run = Invoke-TestWorkflow (New-TestFacts) 'Live' $responses
                Assert-SelfTest ($run.Result.overall -ceq 'PASS' -and $run.Result.exitCode -eq 0) 'complete live workflow did not PASS'
                Assert-SelfTest ($run.Result.ownership.createdByThisRun -and $run.Result.cleanup.success) 'PASS lacks owned cleanup'
                Assert-SelfTest ($run.Result.mainHarness.valid -and $run.Result.absenceHarness.valid) 'PASS lacks a harness proof'
                Assert-SelfTest ($run.Result.ownership.mutationAttempts -eq 4) 'PASS mutation count is not create/start/stop/delete'
                $operations = @($run.Result.commands | ForEach-Object { $_.operation })
                $expectedOperations = @('pre-create-query', 'create', 'start', 'wait-running', 'main-harness', 'cleanup-continuity-query', 'stop', 'wait-stopped', 'delete', 'wait-absent', 'absence-harness')
                Assert-SelfTest (($operations -join '|') -ceq ($expectedOperations -join '|')) 'PASS command order is not exact'
                $createArguments = $run.Result.commands[1].arguments -join '|'
                Assert-SelfTest ($createArguments -ceq 'create|fsring_fsd|type=|filesys|start=|demand|group=|File System|binPath=|C:\package\fsring_fsd.sys') 'create arguments are not exact'
                Assert-SelfTest ($run.Result.commands[4].arguments.Count -eq 0) 'main harness received arguments'
                Assert-SelfTest (($run.Result.commands[10].arguments -join '|') -ceq '--expect-absent') 'absence harness argument is wrong'
                Assert-SelfTest ($run.Adapter.State.Index -eq $responses.Count) 'scripted adapter did not consume its exact queue'
            }
        },
        [pscustomobject]@{
            Name = 'cleanup failure or timeout prevents PASS but still deletes'
            Body = {
                $failureResponses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 0),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 4),
                    (New-FakePinnedHarnessResult 'Normal' (
                        New-FakeHarnessIdentityCheck `
                            'preMain' $true
                    )),
                    (New-ServiceStateResult 4),
                    (New-FakeResult 5),
                    (New-ServiceStateResult 1),
                    (New-FakeResult 0),
                    (New-AbsentServiceResult),
                    (New-FakePinnedHarnessResult 'Absent' (
                        New-FakeHarnessIdentityCheck `
                            'preAbsence' $true
                    ))
                )
                $failureRun = Invoke-TestWorkflow (New-TestFacts) 'Live' $failureResponses
                Assert-SelfTest ($failureRun.Result.overall -ceq 'FAIL' -and -not $failureRun.Result.cleanup.success) 'stop failure did not fail the run'
                Assert-SelfTest ($failureRun.Result.cleanup.delete.attempted) 'delete was skipped after stop failure'

                $timeoutResponses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 0),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 4),
                    (New-FakePinnedHarnessResult 'Normal' (
                        New-FakeHarnessIdentityCheck `
                            'preMain' $true
                    )),
                    (New-ServiceStateResult 4),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 4),
                    (New-ServiceStateResult 4),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 4),
                    (New-ServiceStateResult 4)
                )
                $timeoutRun = Invoke-TestWorkflow (New-TestFacts) 'Live' $timeoutResponses
                Assert-SelfTest ($timeoutRun.Result.overall -ceq 'FAIL' -and $timeoutRun.Result.cleanup.waitStopped.timedOut) 'cleanup stop timeout did not fail'
                Assert-SelfTest (
                    -not $timeoutRun.Result.cleanup.delete.attempted -and
                    -not $timeoutRun.Result.cleanup.waitAbsent.attempted
                ) 'cleanup timeout deleted a service not proven stopped'
            }
        },
        [pscustomobject]@{
            Name = 'cleanup continuity loss never mutates replacement state'
            Body = {
                foreach ($identityMode in @(
                    'PassThenFail',
                    'PassThenThrow'
                )) {
                    $responses = @(
                        (New-AbsentServiceResult),
                        (New-FakeResult 0),
                        (New-FakeResult 0),
                        (New-ServiceStateResult 4),
                        (New-FakePinnedHarnessResult 'Normal' (
                            New-FakeHarnessIdentityCheck `
                                'preMain' $true
                        )),
                        (New-ServiceStateResult 1)
                    )
                    $run = Invoke-TestWorkflow (New-TestFacts) 'Live' $responses $true 2 $identityMode
                    Assert-SelfTest ($run.Result.overall -ceq 'FAIL' -and $run.Result.cleanup.continuity.lost) "$identityMode continuity loss did not fail closed"
                    $cleanupMutations = @($run.Result.commands | Where-Object { $_.operation -in @('stop', 'delete') })
                    Assert-SelfTest ($cleanupMutations.Count -eq 0 -and -not $run.Result.absenceHarness.attempted) "$identityMode continuity loss touched replacement state"
                }
            }
        },
        [pscustomobject]@{
            Name = 'cleanup skips mutation when owned name is already absent'
            Body = {
                $responses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 0),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 4),
                    (New-FakePinnedHarnessResult 'Normal' (
                        New-FakeHarnessIdentityCheck `
                            'preMain' $true
                    )),
                    (New-AbsentServiceResult),
                    (New-FakePinnedHarnessResult 'Absent' (
                        New-FakeHarnessIdentityCheck `
                            'preAbsence' $true
                    ))
                )
                $run = Invoke-TestWorkflow (New-TestFacts) 'Live' $responses
                Assert-SelfTest ($run.Result.overall -ceq 'PASS' -and $run.Result.cleanup.success) 'already-absent owned service did not complete safely'
                $cleanupMutations = @($run.Result.commands | Where-Object { $_.operation -in @('stop', 'delete') })
                Assert-SelfTest ($cleanupMutations.Count -eq 0 -and $run.Result.absenceHarness.valid) 'already-absent cleanup mutated by name or skipped absence proof'
            }
        },
        [pscustomobject]@{
            Name = 'marked-for-delete cleanup polls 1072 until true absence'
            Body = {
                $responses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 0),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 4),
                    (New-FakePinnedHarnessResult 'Normal' (
                        New-FakeHarnessIdentityCheck `
                            'preMain' $true
                    )),
                    (New-FakeResult 1072),
                    (New-FakeResult 1072),
                    (New-AbsentServiceResult),
                    (New-FakePinnedHarnessResult 'Absent' (
                        New-FakeHarnessIdentityCheck `
                            'preAbsence' $true
                    ))
                )
                $run = Invoke-TestWorkflow (New-TestFacts) 'Live' $responses
                Assert-SelfTest ($run.Result.overall -ceq 'PASS' -and $run.Result.cleanup.waitAbsent.success) '1072 to 1060 removal was not accepted'
                $cleanupMutations = @($run.Result.commands | Where-Object { $_.operation -in @('stop', 'delete') })
                Assert-SelfTest ($cleanupMutations.Count -eq 0 -and $run.Result.commands[6].exitCode -eq 1072 -and $run.Result.commands[7].exitCode -eq 1060) 'marked-for-delete polling or mutation log is wrong'
            }
        },
        [pscustomobject]@{
            Name = 'throwing cleanup sleep cannot suppress owned delete attempt'
            Body = {
                $responses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 0),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 4),
                    (New-FakePinnedHarnessResult 'Normal' (
                        New-FakeHarnessIdentityCheck `
                            'preMain' $true
                    )),
                    (New-ServiceStateResult 4),
                    (New-FakeResult 0),
                    (New-ServiceStateResult 4),
                    (New-FakeResult 0),
                    (New-AbsentServiceResult),
                    (New-FakePinnedHarnessResult 'Absent' (
                        New-FakeHarnessIdentityCheck `
                            'preAbsence' $true
                    ))
                )
                $run = Invoke-TestWorkflow (New-TestFacts) 'Live' $responses $true 2 'Pass' $true
                Assert-SelfTest (
                    $run.Result.overall -ceq 'FAIL' -and
                    -not $run.Result.cleanup.delete.attempted -and
                    -not $run.Result.absenceHarness.attempted
                ) 'throwing cleanup sleep reached unproven delete or absence harness'
            }
        },
        [pscustomobject]@{
            Name = 'strict harness JSON and exit validation fails closed'
            Body = {
                $invalidResults = @(
                    (New-FakeResult 0),
                    (New-FakeResult 0 @('not-json')),
                    (New-FakeResult 0 @($script:ValidNormalHarnessJson, $script:ValidNormalHarnessJson)),
                    (New-FakeResult 1 @($script:ValidNormalHarnessJson)),
                    (New-FakeResult 0 @($script:ValidNormalHarnessJson) @('stderr')),
                    (New-FakeResult 0 @($script:ValidNormalHarnessJson.Replace('"trailing-open"', '"root-open"')))
                )
                foreach ($invalid in $invalidResults) {
                    $parsed = Test-HarnessResult $invalid 'Normal'
                    Assert-SelfTest (-not $parsed.Valid) 'invalid harness output was accepted'
                }
                $extraPropertyJson = $script:ValidAbsentHarnessJson.Replace(',"reasons":[]}', ',"reasons":[],"extra":true}')
                Assert-SelfTest (-not (Test-HarnessResult (New-FakeResult 0 @($extraPropertyJson)) 'Absent').Valid) 'extra harness JSON property was accepted'

                $nonStringFields = @(
                    [pscustomobject]@{
                        Name = 'root schema empty array'
                        Json = $script:ValidNormalHarnessJson.Replace(
                            '"schema":"fsring-control-smoke/v1"',
                            '"schema":[]'
                        )
                    },
                    [pscustomobject]@{
                        Name = 'root schema single-element string array'
                        Json = $script:ValidNormalHarnessJson.Replace(
                            '"schema":"fsring-control-smoke/v1"',
                            '"schema":["fsring-control-smoke/v1"]'
                        )
                    },
                    [pscustomobject]@{
                        Name = 'root overall empty array'
                        Json = $script:ValidNormalHarnessJson.Replace(
                            '"overall":"PASS"',
                            '"overall":[]'
                        )
                    },
                    [pscustomobject]@{
                        Name = 'root overall single-element string array'
                        Json = $script:ValidNormalHarnessJson.Replace(
                            '"overall":"PASS"',
                            '"overall":["PASS"]'
                        )
                    },
                    [pscustomobject]@{
                        Name = 'probe name empty array'
                        Json = $script:ValidNormalHarnessJson.Replace(
                            '"name":"root-open"',
                            '"name":[]'
                        )
                    },
                    [pscustomobject]@{
                        Name = 'probe name single-element string array'
                        Json = $script:ValidNormalHarnessJson.Replace(
                            '"name":"root-open"',
                            '"name":["root-open"]'
                        )
                    },
                    [pscustomobject]@{
                        Name = 'probe outcome empty array'
                        Json = $script:ValidNormalHarnessJson.Replace(
                            '"name":"root-open","outcome":"PASS"',
                            '"name":"root-open","outcome":[]'
                        )
                    },
                    [pscustomobject]@{
                        Name = 'probe outcome single-element string array'
                        Json = $script:ValidNormalHarnessJson.Replace(
                            '"name":"root-open","outcome":"PASS"',
                            '"name":"root-open","outcome":["PASS"]'
                        )
                    }
                )
                $acceptedNonStringFields =
                    New-Object System.Collections.ArrayList
                foreach ($fixture in $nonStringFields) {
                    $parsed = Test-HarnessResult (
                        New-FakeResult 0 @($fixture.Json)
                    ) 'Normal'
                    if ($parsed.Valid) {
                        [void]$acceptedNonStringFields.Add($fixture.Name)
                    }
                }
                Assert-SelfTest (
                    $acceptedNonStringFields.Count -eq 0
                ) (
                    'non-string harness JSON fields accepted: ' +
                    (@($acceptedNonStringFields) -join ', ')
                )
            }
        },
        [pscustomobject]@{
            Name = 'strict JSON lexical rejection matrix fails closed'
            Body = {
                $depth33 = '{"v":' + ('[' * 32) + 'null' + (']' * 32) + '}'
                $size65537 = '{"v":"' + ('a' * 65529) + '"}'
                $multibyte65537 = '{"v":"' + (([string][char]0x00E9) * 32764) + 'x"}'
                $literalHigh = '{"v":"' + ([string][char]0xD800) + '"}'
                $literalLow = '{"v":"' + ([string][char]0xDC00) + '"}'
                $invalidJson = @(
                    [pscustomobject]@{ Name = 'duplicate root name'; Json = '{"schema":"first","schema":"second"}' },
                    [pscustomobject]@{ Name = 'duplicate nested name'; Json = '{"outer":{"value":1,"value":2}}' },
                    [pscustomobject]@{ Name = 'escape-equivalent root name'; Json = '{"schema":"first","\u0073chema":"second"}' },
                    [pscustomobject]@{ Name = 'duplicate object name inside array'; Json = '{"outer":[{"value":1,"value":2}]}' },
                    [pscustomobject]@{ Name = 'malformed escape'; Json = '{"v":"\x"}' },
                    [pscustomobject]@{ Name = 'short Unicode escape'; Json = '{"v":"\u123"}' },
                    [pscustomobject]@{ Name = 'nonhex Unicode escape'; Json = '{"v":"\u12G4"}' },
                    [pscustomobject]@{ Name = 'unterminated string'; Json = '{"v":"unterminated}' },
                    [pscustomobject]@{ Name = 'unescaped tab in string'; Json = ('{"v":"a' + "`t" + 'b"}') },
                    [pscustomobject]@{ Name = 'unescaped NUL in string'; Json = ('{"v":"a' + ([string][char]0) + 'b"}') },
                    [pscustomobject]@{ Name = 'escaped isolated high surrogate'; Json = '{"v":"\uD800"}' },
                    [pscustomobject]@{ Name = 'escaped isolated low surrogate'; Json = '{"v":"\uDC00"}' },
                    [pscustomobject]@{ Name = 'escaped high surrogate followed by scalar'; Json = '{"v":"\uD800A"}' },
                    [pscustomobject]@{ Name = 'literal isolated high surrogate'; Json = $literalHigh },
                    [pscustomobject]@{ Name = 'literal isolated low surrogate'; Json = $literalLow },
                    [pscustomobject]@{ Name = 'uppercase true token'; Json = '{"v":True}' },
                    [pscustomobject]@{ Name = 'truncated true token'; Json = '{"v":tru}' },
                    [pscustomobject]@{ Name = 'undefined token'; Json = '{"v":undefined}' },
                    [pscustomobject]@{ Name = 'leading plus number'; Json = '{"v":+1}' },
                    [pscustomobject]@{ Name = 'leading zero number'; Json = '{"v":01}' },
                    [pscustomobject]@{ Name = 'negative leading zero number'; Json = '{"v":-01}' },
                    [pscustomobject]@{ Name = 'missing integer number'; Json = '{"v":.1}' },
                    [pscustomobject]@{ Name = 'missing fraction number'; Json = '{"v":1.}' },
                    [pscustomobject]@{ Name = 'missing exponent number'; Json = '{"v":1e}' },
                    [pscustomobject]@{ Name = 'missing signed exponent number'; Json = '{"v":1e+}' },
                    [pscustomobject]@{ Name = 'unterminated object'; Json = '{"v":1' },
                    [pscustomobject]@{ Name = 'unterminated array'; Json = '{"v":[1}' },
                    [pscustomobject]@{ Name = 'trailing content'; Json = '{"v":1}{"v":2}' },
                    [pscustomobject]@{ Name = 'raw carriage return'; Json = ('{"v":' + "`r" + '1}') },
                    [pscustomobject]@{ Name = 'raw line feed'; Json = ('{"v":' + "`n" + '1}') },
                    [pscustomobject]@{ Name = 'container depth 33'; Json = $depth33 },
                    [pscustomobject]@{ Name = 'UTF-8 size 65537 ASCII'; Json = $size65537 },
                    [pscustomobject]@{ Name = 'UTF-8 size 65537 multibyte'; Json = $multibyte65537 },
                    [pscustomobject]@{ Name = 'root array'; Json = '[]' },
                    [pscustomobject]@{ Name = 'root scalar'; Json = 'true' }
                )

                $accepted = New-Object System.Collections.ArrayList
                foreach ($fixture in $invalidJson) {
                    $parsed = ConvertFrom-StrictSingleJson (New-FakeResult 0 @($fixture.Json)) 'Lexical self-test'
                    if ($parsed.Valid) {
                        [void]$accepted.Add($fixture.Name)
                    }
                }
                Assert-SelfTest ($accepted.Count -eq 0) ("strict JSON parser accepted: " + (@($accepted) -join ', '))
            }
        },
        [pscustomobject]@{
            Name = 'strict JSON positive boundaries are accepted'
            Body = {
                $depth32 = '{"v":' + ('[' * 31) + 'null' + (']' * 31) + '}'
                $size65536 = '{"v":"' + ('a' * 65528) + '"}'
                $multibyte65536 = '{"v":"' + (([string][char]0x00E9) * 32764) + '"}'
                $literalPair = '{"v":"' + ([string][char]0xD83D) + ([string][char]0xDE00) + '"}'
                $validJson = @(
                    [pscustomobject]@{ Name = 'UTF-8 size 65536 ASCII'; Json = $size65536 },
                    [pscustomobject]@{ Name = 'UTF-8 size 65536 multibyte'; Json = $multibyte65536 },
                    [pscustomobject]@{ Name = 'container depth 32'; Json = $depth32 },
                    [pscustomobject]@{ Name = 'same name in sibling objects'; Json = '{"left":{"same":1},"right":{"same":2}}' },
                    [pscustomobject]@{ Name = 'all legal escapes'; Json = '{"v":"quote: \" reverse: \\ solidus: \/ controls: \b\f\n\r\t unicode: \u0041 pair: \uD83D\uDE00"}' },
                    [pscustomobject]@{ Name = 'literal surrogate pair'; Json = $literalPair }
                )
                foreach ($fixture in $validJson) {
                    $parsed = ConvertFrom-StrictSingleJson (New-FakeResult 0 @($fixture.Json)) 'Lexical self-test'
                    Assert-SelfTest $parsed.Valid ("strict JSON parser rejected valid " + $fixture.Name)
                }
            }
        },
        [pscustomobject]@{
            Name = 'exact package verifier schema and state matrix fails closed'
            Body = {
                $trustedJson = ConvertTo-TestVerifierJson (New-TestVerifierObject 'Trusted')
                $trusted = Test-PackageVerifierResult (New-FakeResult 0 @($trustedJson))
                Assert-SelfTest ($trusted.Valid -and $trusted.Overall -ceq 'PASS' -and $trusted.TrustReady) 'exact trusted verifier fixture was rejected'

                $untrustedJson = ConvertTo-TestVerifierJson (New-TestVerifierObject 'Untrusted')
                $untrusted = Test-PackageVerifierResult (New-FakeResult 0 @($untrustedJson))
                Assert-SelfTest ($untrusted.Valid -and $untrusted.Overall -ceq 'PASS' -and -not $untrusted.TrustReady) 'exact known-untrusted verifier fixture was rejected'

                $locallyTrustedJson = ConvertTo-TestVerifierJson (New-TestVerifierObject 'LocallyTrusted')
                $locallyTrusted = Test-PackageVerifierResult (New-FakeResult 0 @($locallyTrustedJson))
                Assert-SelfTest ($locallyTrusted.Valid -and $locallyTrusted.Overall -ceq 'PASS' -and $locallyTrusted.TrustReady) 'exact locally trusted verifier fixture was rejected'

                $accepted = New-Object System.Collections.ArrayList
                $oldEmptyTools = '{"schema":"fsring-package-verifier/v1","overall":"PASS","errors":[],"warnings":[],"trustReady":false,"artifacts":{"fsring_fsd.inf":true,"fsring_fsd.sys":true,"fsring_fsd.cat":true},"tools":{"infverif":{},"signtool":{},"catalogMembership":{}}}'
                if ((Test-PackageVerifierResult (New-FakeResult 0 @($oldEmptyTools))).Valid) {
                    [void]$accepted.Add('old empty tool schema')
                }

                $fieldSpecs = @(
                    [pscustomobject]@{ Container = 'top'; Field = 'schema'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'top'; Field = 'overall'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'top'; Field = 'errors'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'top'; Field = 'warnings'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'top'; Field = 'trustReady'; Wrong = 'true' },
                    [pscustomobject]@{ Container = 'top'; Field = 'artifacts'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'top'; Field = 'tools'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'artifacts'; Field = 'fsring_fsd.inf'; Wrong = 'true' },
                    [pscustomobject]@{ Container = 'artifacts'; Field = 'fsring_fsd.sys'; Wrong = 'true' },
                    [pscustomobject]@{ Container = 'artifacts'; Field = 'fsring_fsd.cat'; Wrong = 'true' },
                    [pscustomobject]@{ Container = 'tools'; Field = 'infverif'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'tools'; Field = 'signtool'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'tools'; Field = 'catalogMembership'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'infverif'; Field = 'path'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'infverif'; Field = 'productVersion'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'infverif'; Field = 'fileVersion'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'infverif'; Field = 'exitCode'; Wrong = '0' },
                    [pscustomobject]@{ Container = 'signtool'; Field = 'path'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'signtool'; Field = 'productVersion'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'signtool'; Field = 'fileVersion'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'signtool'; Field = 'policy'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'signtool'; Field = 'sysExitCode'; Wrong = '0' },
                    [pscustomobject]@{ Container = 'signtool'; Field = 'sysMode'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'signtool'; Field = 'catExitCode'; Wrong = '0' },
                    [pscustomobject]@{ Container = 'signtool'; Field = 'catMode'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'signtool'; Field = 'catalogMemberExitCode'; Wrong = '0' },
                    [pscustomobject]@{ Container = 'signtool'; Field = 'catalogMemberMode'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'catalogMembership'; Field = 'mechanism'; Wrong = 17 },
                    [pscustomobject]@{ Container = 'catalogMembership'; Field = 'valid'; Wrong = 'true' },
                    [pscustomobject]@{ Container = 'catalogMembership'; Field = 'memberHash'; Wrong = 17 }
                )
                foreach ($spec in $fieldSpecs) {
                    foreach ($mutation in @('missing', 'null', 'wrong type')) {
                        $fixture = New-TestVerifierObject 'Trusted'
                        $container = Get-TestVerifierContainer $fixture $spec.Container
                        if ($mutation -ceq 'missing') {
                            $container.Remove($spec.Field)
                        } elseif ($mutation -ceq 'null') {
                            $container[$spec.Field] = $null
                        } else {
                            $container[$spec.Field] = $spec.Wrong
                        }
                        $json = ConvertTo-TestVerifierJson $fixture
                        if ((Test-PackageVerifierResult (New-FakeResult 0 @($json))).Valid) {
                            [void]$accepted.Add("$mutation $($spec.Container).$($spec.Field)")
                        }
                    }
                }

                foreach ($containerName in @('top', 'artifacts', 'tools', 'infverif', 'signtool', 'catalogMembership')) {
                    $fixture = New-TestVerifierObject 'Trusted'
                    $container = Get-TestVerifierContainer $fixture $containerName
                    $container['unexpected'] = $true
                    $json = ConvertTo-TestVerifierJson $fixture
                    if ((Test-PackageVerifierResult (New-FakeResult 0 @($json))).Valid) {
                        [void]$accepted.Add("extra property in $containerName")
                    }
                }

                $invariantCases = @(
                    [pscustomobject]@{ Name = 'wrong schema'; State = 'Trusted'; Container = 'top'; Field = 'schema'; Value = 'fsring-package-verifier/v2' },
                    [pscustomobject]@{ Name = 'overall FAIL'; State = 'Trusted'; Container = 'top'; Field = 'overall'; Value = 'FAIL' },
                    [pscustomobject]@{ Name = 'errors contains non-string'; State = 'Trusted'; Container = 'top'; Field = 'errors'; Value = @(17) },
                    [pscustomobject]@{ Name = 'warnings contains non-string'; State = 'Trusted'; Container = 'top'; Field = 'warnings'; Value = @($true) },
                    [pscustomobject]@{ Name = 'artifact false'; State = 'Trusted'; Container = 'artifacts'; Field = 'fsring_fsd.sys'; Value = $false },
                    [pscustomobject]@{ Name = 'empty infverif path'; State = 'Trusted'; Container = 'infverif'; Field = 'path'; Value = '' },
                    [pscustomobject]@{ Name = 'relative infverif path'; State = 'Trusted'; Container = 'infverif'; Field = 'path'; Value = 'relative\infverif.exe' },
                    [pscustomobject]@{ Name = 'wrong infverif leaf'; State = 'Trusted'; Container = 'infverif'; Field = 'path'; Value = 'C:\tools\other.exe' },
                    [pscustomobject]@{ Name = 'empty infverif product version'; State = 'Trusted'; Container = 'infverif'; Field = 'productVersion'; Value = '' },
                    [pscustomobject]@{ Name = 'blank infverif file version'; State = 'Trusted'; Container = 'infverif'; Field = 'fileVersion'; Value = ' ' },
                    [pscustomobject]@{ Name = 'nonzero infverif exit'; State = 'Trusted'; Container = 'infverif'; Field = 'exitCode'; Value = 1 },
                    [pscustomobject]@{ Name = 'empty signtool path'; State = 'Trusted'; Container = 'signtool'; Field = 'path'; Value = '' },
                    [pscustomobject]@{ Name = 'relative signtool path'; State = 'Trusted'; Container = 'signtool'; Field = 'path'; Value = 'relative\signtool.exe' },
                    [pscustomobject]@{ Name = 'wrong signtool leaf'; State = 'Trusted'; Container = 'signtool'; Field = 'path'; Value = 'C:\tools\other.exe' },
                    [pscustomobject]@{ Name = 'empty signtool product version'; State = 'Trusted'; Container = 'signtool'; Field = 'productVersion'; Value = '' },
                    [pscustomobject]@{ Name = 'blank signtool file version'; State = 'Trusted'; Container = 'signtool'; Field = 'fileVersion'; Value = ' ' },
                    [pscustomobject]@{ Name = 'Authenticode policy'; State = 'Trusted'; Container = 'signtool'; Field = 'policy'; Value = 'Authenticode' },
                    [pscustomobject]@{ Name = 'unknown trusted mode'; State = 'Trusted'; Container = 'signtool'; Field = 'sysMode'; Value = 'Unknown' },
                    [pscustomobject]@{ Name = 'trusted mixed exit'; State = 'Trusted'; Container = 'signtool'; Field = 'catExitCode'; Value = 1 },
                    [pscustomobject]@{ Name = 'trusted mixed mode'; State = 'Trusted'; Container = 'signtool'; Field = 'catalogMemberMode'; Value = 'UntrustedTestRoot' },
                    [pscustomobject]@{ Name = 'wrong membership mechanism'; State = 'Trusted'; Container = 'catalogMembership'; Field = 'mechanism'; Value = 'SHA256' },
                    [pscustomobject]@{ Name = 'false membership'; State = 'Trusted'; Container = 'catalogMembership'; Field = 'valid'; Value = $false },
                    [pscustomobject]@{ Name = 'lowercase member hash'; State = 'Trusted'; Container = 'catalogMembership'; Field = 'memberHash'; Value = ('abcdef0123456789' * 4) },
                    [pscustomobject]@{ Name = 'nonhex member hash'; State = 'Trusted'; Container = 'catalogMembership'; Field = 'memberHash'; Value = ('G' * 64) },
                    [pscustomobject]@{ Name = '63-character member hash'; State = 'Trusted'; Container = 'catalogMembership'; Field = 'memberHash'; Value = ('A' * 63) },
                    [pscustomobject]@{ Name = '65-character member hash'; State = 'Trusted'; Container = 'catalogMembership'; Field = 'memberHash'; Value = ('A' * 65) },
                    [pscustomobject]@{ Name = 'trusted trustReady false'; State = 'Trusted'; Container = 'top'; Field = 'trustReady'; Value = $false },
                    [pscustomobject]@{ Name = 'trusted warning present'; State = 'Trusted'; Container = 'top'; Field = 'warnings'; Value = @('unexpected') },
                    [pscustomobject]@{ Name = 'untrusted trustReady true'; State = 'Untrusted'; Container = 'top'; Field = 'trustReady'; Value = $true },
                    [pscustomobject]@{ Name = 'untrusted warning absent'; State = 'Untrusted'; Container = 'top'; Field = 'warnings'; Value = @() },
                    [pscustomobject]@{ Name = 'untrusted warning wrong'; State = 'Untrusted'; Container = 'top'; Field = 'warnings'; Value = @('wrong') },
                    [pscustomobject]@{ Name = 'untrusted extra warning'; State = 'Untrusted'; Container = 'top'; Field = 'warnings'; Value = @('Exact catalog membership and WDRLocalTestCert signature integrity are present, but the signing root is not trusted locally; package is not load-ready.', 'extra') },
                    [pscustomobject]@{ Name = 'untrusted mixed exit'; State = 'Untrusted'; Container = 'signtool'; Field = 'sysExitCode'; Value = 0 },
                    [pscustomobject]@{ Name = 'untrusted mixed mode'; State = 'Untrusted'; Container = 'signtool'; Field = 'catMode'; Value = 'Trusted' },
                    [pscustomobject]@{ Name = 'locally trusted trustReady false'; State = 'LocallyTrusted'; Container = 'top'; Field = 'trustReady'; Value = $false },
                    [pscustomobject]@{ Name = 'locally trusted warning absent'; State = 'LocallyTrusted'; Container = 'top'; Field = 'warnings'; Value = @() },
                    [pscustomobject]@{ Name = 'locally trusted warning wrong'; State = 'LocallyTrusted'; Container = 'top'; Field = 'warnings'; Value = @('wrong') },
                    [pscustomobject]@{ Name = 'locally trusted untrusted warning'; State = 'LocallyTrusted'; Container = 'top'; Field = 'warnings'; Value = @('Exact catalog membership and WDRLocalTestCert signature integrity are present, but the signing root is not trusted locally; package is not load-ready.') },
                    [pscustomobject]@{ Name = 'locally trusted extra warning'; State = 'LocallyTrusted'; Container = 'top'; Field = 'warnings'; Value = @($script:LocallyTrustedTestRootWarning, 'extra') },
                    [pscustomobject]@{ Name = 'locally trusted mixed exit'; State = 'LocallyTrusted'; Container = 'signtool'; Field = 'sysExitCode'; Value = 0 },
                    [pscustomobject]@{ Name = 'locally trusted mixed mode'; State = 'LocallyTrusted'; Container = 'signtool'; Field = 'catMode'; Value = 'UntrustedTestRoot' },
                    [pscustomobject]@{ Name = 'locally trusted Authenticode policy'; State = 'LocallyTrusted'; Container = 'signtool'; Field = 'policy'; Value = 'Authenticode' }
                )
                foreach ($case in $invariantCases) {
                    $fixture = New-TestVerifierObject $case.State
                    $container = Get-TestVerifierContainer $fixture $case.Container
                    $container[$case.Field] = $case.Value
                    $json = ConvertTo-TestVerifierJson $fixture
                    $commandExit = if ($case.Name -ceq 'overall FAIL') { 1 } else { 0 }
                    if ((Test-PackageVerifierResult (New-FakeResult $commandExit @($json))).Valid) {
                        [void]$accepted.Add($case.Name)
                    }
                }

                $floatingInfverifExit = $trustedJson.Replace('"exitCode":0', '"exitCode":0.0')
                if ((Test-PackageVerifierResult (New-FakeResult 0 @($floatingInfverifExit))).Valid) {
                    [void]$accepted.Add('non-integer infverif exit')
                }
                if ((Test-PackageVerifierResult (New-FakeResult 1 @($trustedJson))).Valid) {
                    [void]$accepted.Add('trusted process exit mismatch')
                }

                $partialFail = New-TestVerifierObject 'Trusted'
                $partialFail.overall = 'FAIL'
                $partialFail.errors = @('verification failed')
                $partialFail.trustReady = $false
                $partialFail.tools = [ordered]@{}
                $partialFailJson = ConvertTo-TestVerifierJson $partialFail
                if ((Test-PackageVerifierResult (New-FakeResult 1 @($partialFailJson))).Valid) {
                    [void]$accepted.Add('partial verifier FAIL schema')
                }

                Assert-SelfTest ($accepted.Count -eq 0) ("package verifier parser accepted: " + (@($accepted) -join ', '))
            }
        },
        [pscustomobject]@{
            Name = 'post-cleanup absence harness failure prevents PASS'
            Body = {
                $responses = @(Get-SuccessResponses)
                $responses[$responses.Count - 1] = (
                    New-FakeClientResult 1 @(
                        $script:FailingNormalHarnessJson
                    ) @() $false $true $true $false $true $null `
                        (New-FakeHarnessIdentityCheck `
                            'preAbsence' $true)
                )
                $run = Invoke-TestWorkflow (New-TestFacts) 'Live' $responses
                Assert-SelfTest ($run.Result.mainHarness.valid -and $run.Result.cleanup.success) 'absence negative control did not reach a valid main/cleanup state'
                Assert-SelfTest ($run.Result.overall -ceq 'FAIL' -and -not $run.Result.absenceHarness.valid) 'absence harness failure did not override main PASS'
            }
        },
        [pscustomobject]@{
            Name = 'scripted adapter exhaustion fails closed'
            Body = {
                $responses = @(
                    (New-AbsentServiceResult),
                    (New-FakeResult 0),
                    (New-FakeResult 1058)
                )
                $run = Invoke-TestWorkflow (New-TestFacts) 'Live' $responses
                Assert-SelfTest ($run.Result.overall -ceq 'FAIL') 'adapter exhaustion did not fail the run'
                $exhaustionRecords = @(
                    $run.Result.commands |
                        Where-Object {
                            $serviceDetail = $null
                            if ($null -ne $_.PSObject.Properties[
                                'serviceObservation'
                            ]) {
                                $serviceDetail = (
                                    $_.serviceObservation.detail
                                )
                            }
                            $_.error -match 'adapter exhausted' -or
                            $serviceDetail -match
                                'adapter exhausted'
                        }
                )
                Assert-SelfTest ($exhaustionRecords.Count -gt 0) 'adapter exhaustion was not recorded'
                Assert-SelfTest ($run.Result.cleanup.continuity.lost -and -not $run.Result.cleanup.delete.attempted) 'adapter exhaustion did not fail closed on lost continuity'
            }
        },
        [pscustomobject]@{
            Name = 'C4 v2 roster, cleanup order, and DOS flags are exact'
            Body = {
                Assert-SelfTest ($script:C4ProbeRoster.Count -eq 27) 'the v2 roster is not 27 probes'
                Assert-SelfTest ($script:C4ProbeRoster[25] -ceq 'unload-transients') 'index 25 is not the runner-only probe'
                Assert-SelfTest (
                    ($script:C4CleanupOrder -join ',') -ceq
                    'contain-worker,remove-dos-link,stop-service,delete-service,post-unload'
                ) 'the C4 cleanup order drifted'
                Assert-SelfTest ($script:C4DosRemoveFlags -eq 15) 'the DOS removal flag word is not all four required flags'
                Assert-SelfTest (
                    ($script:C4UnloadMergeKeys -join ',') -ceq
                    'serviceStopped,providerOpenNtstatus,fscontrolOpenNtstatus,vdoOpenNtstatus,dosLinkQueryWin32Code,formerAliasRangesFree,ownedHandlesClosed'
                ) 'the unload merge key order drifted'
                Assert-SelfTest ($script:C4WorkerReasonLimit -eq 26) 'the worker reason budget drifted'
                foreach ($stage in @('STAGED', 'LIVE_CLEANED', 'POST_UNLOAD')) {
                    $range = $script:C4PrivateProbeRanges[$stage]
                    $names = @($script:C4ProbeRoster[$range[0]..$range[1]])
                    Assert-SelfTest (
                        -not ($names -ccontains $script:C4RunnerOnlyProbe)
                    ) "the $stage slice contains the runner-only probe"
                }
            }
        },
        [pscustomobject]@{
            Name = 'C4 v2 parser derives PASS only from twenty-seven matching probes'
            Body = {
                $report = New-C4TestReport
                $result = Test-HarnessResultV2 (New-FakeResult 0 @($report))
                Assert-SelfTest $result.Valid "a canonical v2 report did not parse: $($result.Reason)"
                Assert-SelfTest ($result.Overall -ceq 'PASS') 'a canonical v2 report did not derive PASS'
                Assert-SelfTest ($result.ExitCode -eq 0) 'a PASS report did not derive exit 0'
                Assert-SelfTest ($result.PassedProbeCount -eq 27) 'the pass count is wrong'
            }
        },
        [pscustomobject]@{
            Name = 'C4 v2 parser ignores a self-reported PASS'
            Body = {
                $report = New-C4TestReport -MutateFirstActual
                $result = Test-HarnessResultV2 (New-FakeResult 0 @($report))
                Assert-SelfTest $result.Valid "the mutated report did not parse: $($result.Reason)"
                Assert-SelfTest (
                    $result.Overall -ceq 'FAIL'
                ) 'a probe whose actual disagrees with its expectation was accepted as PASS'
            }
        },
        [pscustomobject]@{
            Name = 'C4 v2 parser fails a NOT RUN probe once an identity exists'
            Body = {
                $withIdentity = Test-HarnessResultV2 (
                    New-FakeResult 0 @((New-C4TestReport -NotRunLast))
                )
                Assert-SelfTest $withIdentity.Valid "the not-run report did not parse: $($withIdentity.Reason)"
                Assert-SelfTest (
                    $withIdentity.Overall -ceq 'FAIL'
                ) 'a gap after mutation was not a failure'
                $withoutIdentity = Test-HarnessResultV2 (
                    New-FakeResult 0 @((New-C4TestReport -NotRunLast -NullIdentity))
                )
                Assert-SelfTest (
                    $withoutIdentity.Overall -ceq 'NOT RUN'
                ) 'a gap before mutation was not NOT RUN'
                Assert-SelfTest ($withoutIdentity.ExitCode -eq 2) 'NOT RUN did not derive exit 2'
            }
        },
        [pscustomobject]@{
            Name = 'C4 v2 parser rejects a reordered roster and a bad root key set'
            Body = {
                $reordered = (New-C4TestReport) -creplace
                    '"name":"root-open"', '"name":"trailing-open"'
                $result = Test-HarnessResultV2 (New-FakeResult 0 @($reordered))
                Assert-SelfTest (-not $result.Valid) 'a reordered roster was accepted'
                $extra = (New-C4TestReport).Replace(
                    '"reasons":[]', '"reasons":[],"extra":1')
                $result = Test-HarnessResultV2 (New-FakeResult 0 @($extra))
                Assert-SelfTest (-not $result.Valid) 'an extra root key was accepted'
            }
        },
        [pscustomobject]@{
            Name = 'C4 infrastructure reasons are closed, first-per-stage, and force failure'
            Body = {
                Assert-SelfTest (
                    $null -eq (New-C4InfrastructureReason 'NOT_A_STAGE' 'runner' 1)
                ) 'an unknown stage produced a reason'
                Assert-SelfTest (
                    $null -eq (New-C4InfrastructureReason 'LIVE_STAGED' 'nonsense' 1)
                ) 'an unknown domain produced a reason'
                $emitted = @{}
                $emitted = Add-C4InfrastructureReason $emitted 'SCM_CLEANUP' 'win32' 5
                $emitted = Add-C4InfrastructureReason $emitted 'LIVE_STAGED' 'runner' 1
                $emitted = Add-C4InfrastructureReason $emitted 'LIVE_STAGED' 'runner' 2
                $ordered = Get-C4InfrastructureReasons $emitted
                Assert-SelfTest ($ordered.Count -eq 2) 'a stage emitted more than one reason'
                Assert-SelfTest (
                    $ordered[0] -ceq 'INFRASTRUCTURE:LIVE_STAGED:runner:0x00000001'
                ) 'infrastructure reasons are not in stage order'
                Assert-SelfTest (
                    $ordered[1] -ceq 'INFRASTRUCTURE:SCM_CLEANUP:win32:0x00000005'
                ) 'the second stage reason is wrong'
                $report = New-C4TestReport -Reason 'INFRASTRUCTURE:LIVE_STAGED:runner:0x00000001'
                $result = Test-HarnessResultV2 (New-FakeResult 0 @($report))
                Assert-SelfTest (
                    $result.Overall -ceq 'FAIL'
                ) 'a reserved infrastructure reason did not force failure'
            }
        },
        [pscustomobject]@{
            Name = 'C4 worker reasons are bounded cumulatively and reject the reserved prefix'
            Body = {
                $accepted = @()
                for ($index = 0; $index -lt 26; $index++) {
                    $step = Add-C4WorkerReasons $accepted @("reason $index")
                    Assert-SelfTest $step.Accepted "reason $index was rejected below the budget"
                    $accepted = $step.Reasons
                }
                Assert-SelfTest ($accepted.Count -eq 26) 'the accepted budget is not 26'
                $overflow = Add-C4WorkerReasons $accepted @('one too many')
                Assert-SelfTest (
                    -not $overflow.Accepted -and $overflow.Reasons.Count -eq 26
                ) 'the 27th ordinary reason was accepted'
                $reserved = Add-C4WorkerReasons @() @(
                    'INFRASTRUCTURE:LIVE_STAGED:runner:0x00000001')
                Assert-SelfTest (
                    -not $reserved.Accepted
                ) 'a worker was allowed to emit the reserved prefix'
            }
        },
        [pscustomobject]@{
            Name = 'C4 frame continuity covers sequence, nonce, identity, slice, and cleanup'
            Body = {
                $nonce = '0123456789ABCDEF0123456789ABCDEF'
                $frame = New-C4TestStagedFrame $nonce
                $expectation = [pscustomobject]@{
                    Sequence = 1
                    Stage = 'STAGED'
                    Nonce = $nonce
                    RootIdentity = $null
                    DisposableIdentity = $null
                    VdoNativeName = ''
                    DosName = ''
                }
                # Through the production helper: a build that disabled its
                # rejection branch must fail here, not merely here-and-nowhere.
                $accepted = Assert-C4Continuity $frame $expectation @{} 'LIVE_STAGED'
                Assert-SelfTest $accepted.Accepted "a canonical STAGED frame was rejected: $($accepted.Reason)"
                $drifted = New-C4TestStagedFrame $nonce
                $drifted.sequence = 3
                $rejected = Assert-C4Continuity $drifted $expectation @{} 'LIVE_STAGED'
                Assert-SelfTest (-not $rejected.Accepted) 'a drifted frame was accepted'
                Assert-SelfTest (
                    @(Get-C4InfrastructureReasons $rejected.Emitted).Count -eq 1
                ) 'a rejected frame did not record its malformed-record reason'
                $wrongSequence = New-C4TestStagedFrame $nonce
                $wrongSequence.sequence = 3
                $c4Continuity = Test-C4FrameContinuity $wrongSequence 1 'STAGED' $nonce $null $null '' ''
                Assert-SelfTest (-not $c4Continuity.Valid) 'a wrong sequence was accepted'
                $wrongNonce = New-C4TestStagedFrame $nonce
                $c4Continuity = Test-C4FrameContinuity $wrongNonce 1 'STAGED' `
                    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' $null $null '' ''
                Assert-SelfTest (-not $c4Continuity.Valid) 'a foreign nonce was accepted'
                $runnerOnly = New-C4TestStagedFrame $nonce
                $runnerOnly.probes[0].name = 'unload-transients'
                $c4Continuity = Test-C4FrameContinuity $runnerOnly 1 'STAGED' $nonce $null $null '' ''
                Assert-SelfTest (
                    -not $c4Continuity.Valid
                ) 'a worker was allowed to observe the unload transients'
            }
        },
        [pscustomobject]@{
            Name = 'C4 SCM cleanup failure is an infrastructure reason, not a probe'
            Body = {
                $failed = Complete-C4ScmCleanup ([pscustomobject]@{ Success = $false }) @{} 5
                Assert-SelfTest (
                    -not $failed.ServiceStopped
                ) 'a failed SCM cleanup still reported the service stopped'
                $reasons = @(Get-C4InfrastructureReasons $failed.Emitted)
                Assert-SelfTest (
                    $reasons.Count -eq 1 -and
                    $reasons[0] -ceq 'INFRASTRUCTURE:SCM_CLEANUP:win32:0x00000005'
                ) 'a failed SCM cleanup did not emit its exact infrastructure reason'
                # And it must block PASS through the ordinary derivation.
                $report = New-C4TestReport -Reason $reasons[0]
                Assert-SelfTest (
                    (Test-HarnessResultV2 (New-FakeResult 0 @($report))).Overall -ceq 'FAIL'
                ) 'a failed SCM cleanup did not force an aggregate failure'

                $ok = Complete-C4ScmCleanup ([pscustomobject]@{ Success = $true }) @{} 0
                Assert-SelfTest $ok.ServiceStopped 'a successful SCM cleanup did not report stopped'
                Assert-SelfTest (
                    @(Get-C4InfrastructureReasons $ok.Emitted).Count -eq 0
                ) 'a successful SCM cleanup emitted an infrastructure reason'
            }
        },
        [pscustomobject]@{
            Name = 'C4 unload-transients merges exactly three sources or stays NOT RUN'
            Body = {
                $seed = [pscustomobject]@{
                    formerAliasRangesFree = $true
                    ownedHandlesClosed = $true
                }
                $post = [pscustomobject]@{
                    providerOpenNtstatus = '0xC0000034'
                    fscontrolOpenNtstatus = '0xC0000034'
                    vdoOpenNtstatus = '0xC0000034'
                }
                $merged = Complete-C4PostUnloadEvidence $seed $post $true '0x00000002'
                Assert-SelfTest $merged.Valid 'a complete merge was rejected'
                $keys = @($merged.Values.PSObject.Properties.Name)
                Assert-SelfTest (
                    ($keys -join ',') -ceq ($script:C4UnloadMergeKeys -join ',')
                ) 'the merged key order is not canonical'
                Assert-SelfTest (
                    -not (Complete-C4PostUnloadEvidence $null $post $true '0x00000002').Valid
                ) 'a missing live seed still produced a merged probe'
                Assert-SelfTest (
                    -not (Complete-C4PostUnloadEvidence $seed $null $true '0x00000002').Valid
                ) 'a missing post observation still produced a merged probe'
                Assert-SelfTest (
                    -not (Complete-C4PostUnloadEvidence $seed $post $true $null).Valid
                ) 'a missing DOS query code still produced a merged probe'
            }
        },
        [pscustomobject]@{
            Name = 'C4 frame codec round-trips and refuses out-of-bound lengths'
            Body = {
                $payload = '{"schema":"fsring-c4-worker/v1"}'
                $stream = New-Object System.IO.MemoryStream
                Assert-SelfTest (Write-C4Frame $stream $payload) 'a canonical frame did not write'
                $bytes = $stream.ToArray()
                Assert-SelfTest (
                    [BitConverter]::ToUInt32($bytes, 0) -eq $payload.Length
                ) 'the little-endian length prefix is wrong'
                $reader = New-Object System.IO.MemoryStream(, $bytes)
                $read = Read-C4Frame $reader 1000
                Assert-SelfTest $read.Valid "a canonical frame did not read: $($read.Reason)"
                Assert-SelfTest (
                    $read.Frame.schema -ceq 'fsring-c4-worker/v1'
                ) 'the round-tripped frame lost its schema'

                $truncated = New-Object System.IO.MemoryStream(, $bytes[0..($bytes.Length - 2)])
                $short = Read-C4Frame $truncated 200
                Assert-SelfTest (-not $short.Valid) 'a truncated frame was accepted'

                $oversize = New-Object System.IO.MemoryStream
                $oversize.Write([BitConverter]::GetBytes([uint32]($script:C4FrameMax + 1)), 0, 4)
                $oversize.Position = 0
                $big = Read-C4Frame $oversize 200
                Assert-SelfTest (
                    -not $big.Valid -and $big.Reason -cmatch 'out of bounds'
                ) 'an oversize declared length was accepted'
            }
        },
        [pscustomobject]@{
            Name = 'C4 DOS name is derived from the exact retained PID and GUID'
            Body = {
                $name = New-C4DosName 4660 '0123456789ABCDEF0123456789ABCDEF'
                Assert-SelfTest (
                    $name -ceq 'Global\FsRingC4-00001234-0123456789ABCDEF0123456789ABCDEF'
                ) "the DOS name is not canonical: $name"
            }
        },
        [pscustomobject]@{
            Name = 'c4_live_mode_routes_to_public_v2_not_the_v1_harness'
            Body = {
                $selected = Get-C4ProductionModeSelector -C4 $true -Mode 'Live'
                Assert-SelfTest (
                    $selected.PublicSchema -ceq 'fsring-control-smoke/v2'
                ) "C4 live still selected $($selected.PublicSchema)"
                Assert-SelfTest (
                    $selected.PublicSchema -cne $script:Schema -or
                    $script:Schema -ceq 'fsring-driver-smoke/v1'
                ) 'SelfTest wrapper schema must remain v1'
                Assert-SelfTest (
                    $selected.PublicSchema -cne 'fsring-driver-smoke/v1'
                ) 'C4 live still reaches the v1 harness schema'
            }
        },
        [pscustomobject]@{
            Name = 'preflight_uses_orchestration_envelope_not_public_v2_schema'
            Body = {
                $selected = Get-C4ProductionModeSelector -C4 $true -Mode 'PreflightOnly'
                Assert-SelfTest (
                    $selected.PublicSchema -ceq 'fsring-c4-preflight-orchestration/v1'
                ) "C4 preflight selected $($selected.PublicSchema)"
                Assert-SelfTest (
                    $selected.PublicSchema -cne 'fsring-control-smoke/v2'
                ) 'C4 preflight leaked the public v2 schema'
            }
        },
        [pscustomobject]@{
            Name = 'v1_selftest_and_c3_regression_never_parse_as_v2'
            Body = {
                $v1 = Test-HarnessResultV2 (
                    New-FakeResult 0 @($script:ValidNormalHarnessJson)
                )
                Assert-SelfTest (-not $v1.Valid) 'a C3 v1 harness parsed as public v2'
                $selfTest = Test-HarnessResultV2 (
                    New-FakeResult 0 @(
                        '{"schema":"fsring-driver-smoke/v1","mode":"SelfTest","overall":"PASS","exitCode":0}'
                    )
                )
                Assert-SelfTest (-not $selfTest.Valid) 'the v1 SelfTest wrapper parsed as public v2'
            }
        },
        [pscustomobject]@{
            Name = 'live_stdout_is_one_json_object_and_raw_etw_goes_to_sidecars'
            Body = {
                $names = @(Get-C4LiveSidecarNames)
                Assert-SelfTest (
                    ($names -join ',') -ceq
                    'etw.sidecar.jsonl,worker-frames.sidecar.bin,cleanup.sidecar.json,diagnostics.sidecar.jsonl'
                ) "live sidecar roster drifted: $($names -join ',')"
            }
        },
        [pscustomobject]@{
            Name = 'C4 attempt service and DOS derivation reject caller overrides'
            Body = {
                $attempt = '0123456789abcdef0123456789abcdef'
                Assert-SelfTest (Test-C4AttemptId $attempt) 'lowercase GUID-N was refused'
                Assert-SelfTest (-not (Test-C4AttemptId '0123456789ABCDEF0123456789ABCDEF')) 'uppercase GUID-N was accepted'
                $service = Get-C4OwnedServiceName $attempt
                Assert-SelfTest ($service -ceq 'fsring-c4-0123456789abcdef0123456789abcdef') "service drifted: $service"
                $dos = Get-C4OwnedDosName 4660 $attempt
                Assert-SelfTest (
                    $dos -ceq 'Global\FsRingC4-00001234-0123456789ABCDEF0123456789ABCDEF'
                ) "DOS drifted: $dos"
                $selector = Get-C4ProductionModeSelector -C4 $true -Mode 'Live'
                Assert-SelfTest ($selector.PublicSchema -ceq 'fsring-control-smoke/v2') 'live selector is not v2'
                $c3 = Get-C4ProductionModeSelector -C4 $false -Mode 'Live'
                Assert-SelfTest ($c3.PublicSchema -ceq 'fsring-driver-smoke/v1') 'non-C4 live lost the C3 schema'
            }
        },
        [pscustomobject]@{
            Name = 'C4 diagnostics journal header and hash chain are exact'
            Body = {
                $attempt = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                $header = New-C4DiagnosticsHeader `
                    $attempt ('a' * 40) ('b' * 40) ('c' * 64) ('d' * 64) ('e' * 64) `
                    4660 (Get-C4OwnedServiceName $attempt) (Get-C4OwnedDosName 4660 $attempt) ('f' * 64)
                $line = (ConvertTo-C4CanonicalJson $header) + "`n"
                Assert-SelfTest ($line.StartsWith('{"schema":"fsring-c4-diagnostics-journal/v1"')) ("header json: " + $line)
                $bytes = [byte[]](Get-C4Utf8NoBom $line)
                $parsed = Test-C4DiagnosticsJournalBytes -JournalBytes $bytes -ExpectedAttemptId $attempt
                Assert-SelfTest $parsed.Valid ("canonical header refused: $($parsed.Reason) json=$line bytes=$($bytes.Length)")
                $mut = New-C4MutationAttemptRecord $attempt 1 (Get-C4Sha256Hex $bytes) 'SERVICE_CREATE' (Get-C4OwnedServiceName $attempt) 'LIVE'
                $mutLine = (ConvertTo-C4CanonicalJson $mut) + "`n"
                $both = $bytes + (Get-C4Utf8NoBom $mutLine)
                $chain = Test-C4DiagnosticsJournalBytes -JournalBytes $both -ExpectedAttemptId $attempt
                Assert-SelfTest $chain.Valid "hash chain refused: $($chain.Reason)"
                $bad = $bytes + (Get-C4Utf8NoBom ((ConvertTo-C4CanonicalJson $mut) + "`nextra"))
                $tail = Test-C4DiagnosticsJournalBytes -JournalBytes $bad -ExpectedAttemptId $attempt
                Assert-SelfTest (-not $tail.Valid) 'non-LF tail was accepted'
            }
        },
        [pscustomobject]@{
            Name = 'C4 CleanupOnly first-step refusal is REFUSED with zero mutation'
            Body = {
                $root = Join-Path $env:TEMP ('fsring-c4-cleanup-' + [Guid]::NewGuid().ToString('N'))
                [void][IO.Directory]::CreateDirectory($root)
                try {
                    $attempt = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
                    $out = Join-Path $root 'cleanup.json'
                    $result = Invoke-C4CleanupOnlyCore `
                        -AttemptId $attempt `
                        -CandidateManifestPath (Join-Path $root 'missing-manifest.json') `
                        -ExpectedCandidateManifestSha256 ('ab' * 32) `
                        -DiagnosticsJournalPath (Join-Path $root 'missing-journal.jsonl') `
                        -ContainmentProofPath 'UNAVAILABLE' `
                        -ExpectedContainmentProofSha256 'UNAVAILABLE' `
                        -CleanupEvidencePath $out `
                        -OwnedServiceName (Get-C4OwnedServiceName $attempt) `
                        -OwnedDosName 'UNAVAILABLE'
                    Assert-SelfTest ($result.status -ceq 'REFUSED') "status $($result.status)"
                    Assert-SelfTest ($result.refusalReason -ceq 'PROCESS_CONTAINMENT_UNPROVED') $result.refusalReason
                    Assert-SelfTest (@($result.operations).Count -eq 0) 'REFUSED grew operations'
                    Assert-SelfTest (Test-Path -LiteralPath $out) 'cleanup evidence was not reserved'
                } finally {
                    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        },
        [pscustomobject]@{
            Name = 'C4 CleanupOnly accepted path is PASS only when both names are absent'
            Body = {
                $root = Join-Path $env:TEMP ('fsring-c4-cleanup-pass-' + [Guid]::NewGuid().ToString('N'))
                [void][IO.Directory]::CreateDirectory($root)
                try {
                    $attempt = 'cccccccccccccccccccccccccccccccc'
                    $service = Get-C4OwnedServiceName $attempt
                    $dos = Get-C4OwnedDosName 4660 $attempt
                    $header = New-C4DiagnosticsHeader `
                        $attempt ('a' * 40) ('b' * 40) ('ab' * 32) ('d' * 64) ('e' * 64) `
                        4660 $service $dos ('f' * 64)
                    $journalPath = Join-Path $root 'diagnostics.sidecar.jsonl'
                    [IO.File]::WriteAllText($journalPath, ((ConvertTo-C4CanonicalJson $header) + "`n"), (New-Object System.Text.UTF8Encoding $false))
                    $proof = [ordered]@{
                        schema = $script:C4ProcessContainmentSchema
                        version = 1
                        attemptId = $attempt
                        captureRole = 'LIVE'
                        childProcessId = 4660
                        createdSuspended = $true
                        jobKillOnClose = $true
                        breakawayDisabled = $true
                        jobAssignedBeforeResume = $true
                        mainThreadResumed = $true
                        terminationAttempted = $true
                        treeExited = $true
                        streamsClosed = $true
                        status = 'PASS'
                    }
                    $proofBytes = Get-C4Utf8NoBom ((ConvertTo-C4CanonicalJson $proof) + "`n")
                    $proofPath = Join-Path $root 'containment.json'
                    [IO.File]::WriteAllBytes($proofPath, $proofBytes)
                    $proofHash = Get-C4Sha256Hex $proofBytes
                    $absent = {
                        param($Kind)
                        [pscustomobject]@{
                            Observable = $true
                            Present = $false
                            Owned = $false
                            State = $null
                            Target = $null
                            BinaryPathSha256 = $null
                            Ambiguous = $false
                        }
                    }
                    $already = {
                        param($Operation, $Target)
                        [pscustomobject]@{ Result = 'ALREADY_ABSENT'; Win32Code = $null }
                    }
                    $out = Join-Path $root 'cleanup.json'
                    $result = Invoke-C4CleanupOnlyCore `
                        -AttemptId $attempt `
                        -CandidateManifestPath (Join-Path $root 'candidate.json') `
                        -ExpectedCandidateManifestSha256 ('ab' * 32) `
                        -DiagnosticsJournalPath $journalPath `
                        -ContainmentProofPath $proofPath `
                        -ExpectedContainmentProofSha256 $proofHash `
                        -CleanupEvidencePath $out `
                        -OwnedServiceName $service `
                        -OwnedDosName $dos `
                        -Adapters ([pscustomobject]@{ Query = $absent; Mutate = $already })
                    $cleanupErr = ''
                    if ($null -ne $script:C4CleanupLastError) { $cleanupErr = [string]$script:C4CleanupLastError }
                    Assert-SelfTest ($result.status -ceq 'PASS') ("status=" + $result.status + " reason=" + $result.refusalReason + " err=" + $cleanupErr)
                    Assert-SelfTest ($null -eq $result.refusalReason) 'PASS carried a refusal'
                    Assert-SelfTest ($result.operations.Count -eq 3) 'PASS did not record three recovery rows'
                    Assert-SelfTest (-not $result.after.service.present -and -not $result.after.dos.present) 'after-state still present'
                } finally {
                    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        },
        [pscustomobject]@{
            Name = 'C4 CleanupOnly cannot reach install start load or link-create'
            Body = {
                $commands = @(
                    ${function:Invoke-C4CleanupOnlyCore}.ToString()
                ) -join "`n"
                foreach ($forbidden in @(
                        'SERVICE_CREATE',
                        'SERVICE_START_DRIVER_LOAD',
                        'DOS_LINK_CREATE',
                        'SMOKE_TRAFFIC'
                    )) {
                    Assert-SelfTest (
                        $commands -notmatch [regex]::Escape($forbidden)
                    ) "CleanupOnly core mentions $forbidden"
                }
            }
        },
        [pscustomobject]@{
            Name = 'C4 live fake happy path emits public v2 PASS with 27 actuals'
            Body = {
                $root = Join-Path $env:TEMP ('fsring-c4-live-pass-' + [Guid]::NewGuid().ToString('N'))
                [void][IO.Directory]::CreateDirectory($root)
                try {
                    $attempt = '11111111111111111111111111111111'
                    $adapters = New-C4LiveFakeAdapters -AttemptId $attempt
                    $live = Invoke-C4LiveWorkflow `
                        -AttemptId $attempt `
                        -CandidateManifestPath (Join-Path $root 'candidate.json') `
                        -ExpectedCandidateManifestSha256 ('ab' * 32) `
                        -ExpectedHarnessSha256 ('A' * 64) `
                        -EvidenceDirectory $root `
                        -HarnessPath (Join-Path $root 'fsring-control-smoke.exe') `
                        -WorkingDirectory $root `
                        -SourceCommit ('a' * 40) `
                        -SourceTree ('b' * 40) `
                        -PackageSetSha256 ('c' * 64) `
                        -ArtifactSetSha256 ('d' * 64) `
                        -Adapters $adapters
                    Assert-SelfTest ($live.ExitCode -eq 0) ("exit $($live.ExitCode) overall=$($live.Report.overall)")
                    Assert-SelfTest ($live.Report.schema -ceq 'fsring-control-smoke/v2') $live.Report.schema
                    Assert-SelfTest ($live.Report.overall -ceq 'PASS') $live.Report.overall
                    Assert-SelfTest ($live.Report.probes.Count -eq 27) "probe count $($live.Report.probes.Count)"
                    foreach ($probe in @($live.Report.probes)) {
                        Assert-SelfTest ($null -ne $probe.actual) "$($probe.name) actual was null"
                    }
                    Assert-SelfTest ($live.Mutations -contains 'SERVICE_CREATE') 'SERVICE_CREATE was not journaled/mutated'
                    Assert-SelfTest ($live.Mutations -contains 'DOS_LINK_CREATE') 'DOS_LINK_CREATE missing'
                    Assert-SelfTest ($live.OwnedServiceName -ceq (Get-C4OwnedServiceName $attempt)) $live.OwnedServiceName
                    Assert-SelfTest ($live.OwnedDosName -ceq (Get-C4OwnedDosName 4660 $attempt)) $live.OwnedDosName
                    $journal = Test-C4DiagnosticsJournalBytes -JournalBytes ([IO.File]::ReadAllBytes((Join-Path $root 'diagnostics.sidecar.jsonl'))) -ExpectedAttemptId $attempt
                    Assert-SelfTest $journal.Valid "journal invalid: $($journal.Reason)"
                    Assert-SelfTest ($journal.Header.recordType -ceq 'HEADER') 'journal header missing'
                    Assert-SelfTest ($journal.Records.Count -ge 2) 'no MUTATION_ATTEMPT records'
                    foreach ($name in @(Get-C4LiveSidecarNames)) {
                        Assert-SelfTest (Test-Path -LiteralPath (Join-Path $root $name)) "$name missing"
                    }
                    $cleanupText = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes((Join-Path $root 'cleanup.sidecar.json')))
                    $cleanupObj = ConvertFrom-Json $cleanupText
                    Assert-SelfTest ($cleanupObj.expectedHarnessSha256 -ceq ('A' * 64)) 'expected harness hash drifted'
                    Assert-SelfTest (
                        $cleanupObj.actualHarnessSha256 -cne $cleanupObj.expectedHarnessSha256
                    ) 'sidecar copied ExpectedHarnessSha256 as actual'
                } finally {
                    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        },
        [pscustomobject]@{
            Name = 'C4 live after mutation malformed frame is FAIL not NOT RUN'
            Body = {
                $root = Join-Path $env:TEMP ('fsring-c4-live-fail-' + [Guid]::NewGuid().ToString('N'))
                [void][IO.Directory]::CreateDirectory($root)
                try {
                    $attempt = '22222222222222222222222222222222'
                    $adapters = New-C4LiveFakeAdapters -AttemptId $attempt -MalformedAfterMutation
                    $live = Invoke-C4LiveWorkflow `
                        -AttemptId $attempt `
                        -CandidateManifestPath (Join-Path $root 'candidate.json') `
                        -ExpectedCandidateManifestSha256 ('ab' * 32) `
                        -ExpectedHarnessSha256 ('A' * 64) `
                        -EvidenceDirectory $root `
                        -HarnessPath (Join-Path $root 'fsring-control-smoke.exe') `
                        -WorkingDirectory $root `
                        -SourceCommit ('a' * 40) `
                        -SourceTree ('b' * 40) `
                        -PackageSetSha256 ('c' * 64) `
                        -ArtifactSetSha256 ('d' * 64) `
                        -Adapters $adapters
                    Assert-SelfTest ($live.MutationStarted) 'mutation did not start'
                    Assert-SelfTest ($live.Report.overall -ceq 'FAIL') "overall=$($live.Report.overall)"
                    Assert-SelfTest ($live.ExitCode -eq 1) "exit $($live.ExitCode)"
                    Assert-SelfTest ($live.Report.overall -cne 'NOT RUN') 'post-mutation outcome was NOT RUN'
                    Assert-SelfTest ($adapters.Contained.Count -ge 1) 'unadapted live failure never contained the worker'
                } finally {
                    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        },
        [pscustomobject]@{
            Name = 'C4 live rejects caller service and DOS name overrides'
            Body = {
                $caught = $false
                try {
                    $null = Invoke-C4LiveWorkflow `
                        -AttemptId '33333333333333333333333333333333' `
                        -CandidateManifestPath 'C:\candidate.json' `
                        -ExpectedCandidateManifestSha256 ('ab' * 32) `
                        -ExpectedHarnessSha256 ('A' * 64) `
                        -ServiceName 'fsring_fsd' `
                        -DosName 'Global\FsRing'
                } catch {
                    $caught = [string]$_ -cmatch 'rejects caller'
                }
                Assert-SelfTest $caught 'caller name overrides were accepted'
            }
        },
        [pscustomobject]@{
            Name = 'C4 CleanupOnly success then ownership ambiguity is FAIL'
            Body = {
                $root = Join-Path $env:TEMP ('fsring-c4-amb-' + [Guid]::NewGuid().ToString('N'))
                [void][IO.Directory]::CreateDirectory($root)
                try {
                    $attempt = '44444444444444444444444444444444'
                    $inputs = New-C4CleanupAcceptedInputs $root $attempt
                    $n = @{ i = 0 }
                    $query = {
                        param($Kind)
                        $n.i++
                        if ($n.i -le 2) {
                            return [pscustomobject]@{ Observable = $true; Present = $false; Owned = $false; State = $null; Target = $null; BinaryPathSha256 = $null; Ambiguous = $false }
                        }
                        return [pscustomobject]@{ Observable = $true; Present = $true; Owned = $true; State = 'RUNNING'; Target = '\Device\X'; BinaryPathSha256 = ('ab' * 32); Ambiguous = $true }
                    }.GetNewClosure()
                    $already = { param($Operation, $Target) [pscustomobject]@{ Result = 'ALREADY_ABSENT'; Win32Code = $null } }
                    $result = Invoke-C4CleanupFixture $root $attempt $inputs ([pscustomobject]@{ Query = $query; Mutate = $already })
                    Assert-SelfTest ($result.status -ceq 'FAIL') "status=$($result.status) reason=$($result.refusalReason)"
                    Assert-SelfTest ($null -eq $result.refusalReason) 'FAIL carried a refusal'
                    Assert-SelfTest ($result.operations.Count -eq 3) 'operations were dropped'
                } finally {
                    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        },
        [pscustomobject]@{
            Name = 'C4 CleanupOnly all-success then unobservable after is FAIL'
            Body = {
                $root = Join-Path $env:TEMP ('fsring-c4-unobs-' + [Guid]::NewGuid().ToString('N'))
                [void][IO.Directory]::CreateDirectory($root)
                try {
                    $attempt = '55555555555555555555555555555555'
                    $inputs = New-C4CleanupAcceptedInputs $root $attempt
                    $n = @{ i = 0 }
                    $query = {
                        param($Kind)
                        $n.i++
                        if ($n.i -le 2) {
                            return [pscustomobject]@{ Observable = $true; Present = $false; Owned = $false; State = $null; Target = $null; BinaryPathSha256 = $null; Ambiguous = $false }
                        }
                        return [pscustomobject]@{ Observable = $false; Present = $null; Owned = $null; State = $null; Target = $null; BinaryPathSha256 = $null; Ambiguous = $false }
                    }.GetNewClosure()
                    $already = { param($Operation, $Target) [pscustomobject]@{ Result = 'SUCCEEDED'; Win32Code = 0 } }
                    $result = Invoke-C4CleanupFixture $root $attempt $inputs ([pscustomobject]@{ Query = $query; Mutate = $already })
                    Assert-SelfTest ($result.status -ceq 'FAIL') "status=$($result.status)"
                    Assert-SelfTest ($null -eq $result.refusalReason) 'FAIL carried a refusal'
                    Assert-SelfTest (-not $result.after.service.observable) 'after service stayed observable'
                } finally {
                    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        },
        [pscustomobject]@{
            Name = 'C4 CleanupOnly delayed service deletion is FAIL'
            Body = {
                $root = Join-Path $env:TEMP ('fsring-c4-delay-' + [Guid]::NewGuid().ToString('N'))
                [void][IO.Directory]::CreateDirectory($root)
                try {
                    $attempt = '66666666666666666666666666666666'
                    $inputs = New-C4CleanupAcceptedInputs $root $attempt
                    $n = @{ i = 0 }
                    $query = {
                        param($Kind)
                        $n.i++
                        if ($Kind -ceq 'dos') {
                            return [pscustomobject]@{ Observable = $true; Present = $false; Owned = $false; State = $null; Target = $null; BinaryPathSha256 = $null; Ambiguous = $false }
                        }
                        if ($n.i -le 2) {
                            return [pscustomobject]@{ Observable = $true; Present = $true; Owned = $true; State = 'STOP_PENDING'; Target = $null; BinaryPathSha256 = ('ab' * 32); Ambiguous = $false }
                        }
                        return [pscustomobject]@{ Observable = $true; Present = $true; Owned = $true; State = 'STOP_PENDING'; Target = $null; BinaryPathSha256 = ('ab' * 32); Ambiguous = $false }
                    }.GetNewClosure()
                    $already = { param($Operation, $Target) [pscustomobject]@{ Result = 'SUCCEEDED'; Win32Code = 0 } }
                    $result = Invoke-C4CleanupFixture $root $attempt $inputs ([pscustomobject]@{ Query = $query; Mutate = $already })
                    Assert-SelfTest ($result.status -ceq 'FAIL') "status=$($result.status)"
                    Assert-SelfTest ($result.after.service.present) 'delayed delete was treated as absent'
                } finally {
                    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        },
        [pscustomobject]@{
            Name = 'C4 CleanupOnly journal reread failure before and after each operation is FAIL'
            Body = {
                foreach ($when in @('FailRereadBefore', 'FailRereadAfter')) {
                    foreach ($op in @('RECOVERY_DOS_LINK_REMOVE', 'RECOVERY_SERVICE_STOP', 'RECOVERY_SERVICE_DELETE')) {
                        $root = Join-Path $env:TEMP ('fsring-c4-jr-' + [Guid]::NewGuid().ToString('N'))
                        [void][IO.Directory]::CreateDirectory($root)
                        try {
                            $attempt = '77777777777777777777777777777777'
                            $inputs = New-C4CleanupAcceptedInputs $root $attempt
                            $absent = {
                                param($Kind)
                                [pscustomobject]@{ Observable = $true; Present = $false; Owned = $false; State = $null; Target = $null; BinaryPathSha256 = $null; Ambiguous = $false }
                            }
                            $already = { param($Operation, $Target) [pscustomobject]@{ Result = 'ALREADY_ABSENT'; Win32Code = $null } }
                            $props = @{ Query = $absent; Mutate = $already }
                            $props[$when] = $op
                            $result = Invoke-C4CleanupFixture $root $attempt $inputs ([pscustomobject]$props)
                            Assert-SelfTest ($result.status -ceq 'FAIL') "$when $op status=$($result.status)"
                            Assert-SelfTest ($null -eq $result.journalFinalSha256) "$when $op kept a final hash"
                            Assert-SelfTest ($null -eq $result.refusalReason) "$when $op was REFUSED"
                            Assert-SelfTest ($result.operations.Count -ge 1) "$when $op dropped receipts"
                        } finally {
                            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'C4 CleanupOnly each FAILED operation is FAIL with that row'
            Body = {
                foreach ($op in @('RECOVERY_DOS_LINK_REMOVE', 'RECOVERY_SERVICE_STOP', 'RECOVERY_SERVICE_DELETE')) {
                    $root = Join-Path $env:TEMP ('fsring-c4-failop-' + [Guid]::NewGuid().ToString('N'))
                    [void][IO.Directory]::CreateDirectory($root)
                    try {
                        $attempt = '88888888888888888888888888888888'
                        $inputs = New-C4CleanupAcceptedInputs $root $attempt
                        $absent = {
                            param($Kind)
                            [pscustomobject]@{ Observable = $true; Present = $false; Owned = $false; State = $null; Target = $null; BinaryPathSha256 = $null; Ambiguous = $false }
                        }
                        $mutate = {
                            param($Operation, $Target)
                            if ($Operation -ceq $op) {
                                return [pscustomobject]@{ Result = 'FAILED'; Win32Code = 5 }
                            }
                            return [pscustomobject]@{ Result = 'ALREADY_ABSENT'; Win32Code = $null }
                        }.GetNewClosure()
                        $result = Invoke-C4CleanupFixture $root $attempt $inputs ([pscustomobject]@{ Query = $absent; Mutate = $mutate })
                        Assert-SelfTest ($result.status -ceq 'FAIL') "$op status=$($result.status)"
                        Assert-SelfTest ($null -eq $result.refusalReason) "$op was REFUSED"
                        $failed = @($result.operations | Where-Object { $_.result -ceq 'FAILED' })
                        Assert-SelfTest ($failed.Count -eq 1) "$op FAILED row count $($failed.Count)"
                        Assert-SelfTest ($failed[0].operation -ceq $op) "$op row was $($failed[0].operation)"
                    } finally {
                        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        },
        [pscustomobject]@{
            Name = 'C4 preflight envelope is orchestration not public v2'
            Body = {
                $attempt = 'dddddddddddddddddddddddddddddddd'
                $envelope = New-C4PreflightEnvelope `
                    $attempt ('a' * 40) ('b' * 40) ('c' * 64) `
                    ([ordered]@{ id = 'win10-x64' }) ('d' * 64) ('e' * 64) `
                    ('A' * 64) ('A' * 64) `
                    ([ordered]@{ runnable = $false }) `
                    ([ordered]@{ mutationAttempts = 0 })
                $json = ConvertTo-C4CanonicalJson $envelope
                Assert-SelfTest ($envelope.schema -ceq $script:C4PreflightOrchestrationSchema) $envelope.schema
                Assert-SelfTest ($envelope.overall -ceq 'NOT RUN' -and $envelope.exitCode -eq 2) 'preflight overall drifted'
                Assert-SelfTest ($json -notmatch 'fsring-control-smoke/v2') 'preflight leaked public v2'
                Assert-SelfTest ($envelope.ownership.mutationAttempts -eq 0) 'preflight claimed a mutation'
            }
        },
        [pscustomobject]@{
            Name = 'C4 live default route launches via Invoke-C4EvidenceProcess'
            Body = {
                $live = ${function:Invoke-C4LiveWorkflow}.ToString()
                Assert-SelfTest (
                    $live -match 'Invoke-C4EvidenceProcess' -and
                    $live -match 'Start-C4ContainedLiveWorker'
                ) 'unadapted C4 live does not call Invoke-C4EvidenceProcess'
                Assert-SelfTest (
                    $live -notmatch 'issued only through an explicit adapter'
                ) 'C4 live still throws on unadapted Mutate'
                $start = ${function:Start-C4ContainedLiveWorker}.ToString()
                Assert-SelfTest (
                    $start -match 'CreateSuspended' -or $start -match 'Invoke-C4EvidenceProcess'
                ) 'contained live worker helper is missing'
                Assert-SelfTest (
                    $live -match 'workerContained' -and
                    $live -match 'finally'
                ) 'live failure after resume never contains the job-owned worker'
                Assert-SelfTest (
                    $live -notmatch '\[void\]\$session\.Finished\.Wait'
                ) 'default containWorker discards the wait result'
                $containStart = $live.IndexOf('$containWorker = {')
                $containEnd = $live.IndexOf('$postUnload = {')
                Assert-SelfTest ($containStart -ge 0 -and $containEnd -gt $containStart) 'containWorker block is missing'
                $contain = $live.Substring($containStart, $containEnd - $containStart)
                $termAt = $contain.IndexOf('TerminateJobObject')
                $resumeAt = $contain.IndexOf('ResumeGate.Set')
                Assert-SelfTest ($termAt -ge 0) 'default containWorker does not terminate the job'
                Assert-SelfTest (
                    $resumeAt -lt 0 -or $resumeAt -gt $termAt
                ) 'default containWorker sets ResumeGate before TerminateJobObject'
                Assert-SelfTest (
                    $contain -notmatch 'treeExited -or'
                ) 'containWorker success treats helper finish as tree exit'
                Assert-SelfTest (
                    $contain -match 'Success = \[bool\]\$treeExited'
                ) 'containWorker success is not confirmed tree exit'
            }
        },
        [pscustomobject]@{
            Name = 'C4 CleanupOnly default Query and Mutate inspect journal-proven objects'
            Body = {
                $core = ${function:Invoke-C4CleanupOnlyCore}.ToString()
                Assert-SelfTest ($core -match 'Get-C4RealServiceQuery') 'CleanupOnly default Query is still a Present=false stub'
                Assert-SelfTest ($core -match 'Invoke-C4RealMutation') 'CleanupOnly default Mutate is still ALREADY_ABSENT'
                Assert-SelfTest ($core -match 'C4RecoveryAppended') 'CleanupOnly does not track post-recovery FAIL'
                Assert-SelfTest ($core -match 'ExpectedBinaryFileSha256') 'CleanupOnly service query is name-only'
                Assert-SelfTest ($core -match 'packageSetSha256') 'CleanupOnly service query ignores the journal package tuple'
                Assert-SelfTest ($core -match 'ExpectedTarget') 'CleanupOnly DOS query omits ExpectedTarget'
                Assert-SelfTest ($core -match 'Get-C4ExpectedVdoTargetFromJournal') 'CleanupOnly DOS query has no attempt VDO identity'
                $svc = ${function:Get-C4RealServiceQuery}.ToString()
                $dos = ${function:Get-C4RealDosQuery}.ToString()
                Assert-SelfTest ($svc -match 'Test-C4ServiceBinaryMatchesTuple') 'service query still sets Owned by name existence'
                Assert-SelfTest ($dos -match 'Test-C4DosTargetMatchesTuple') 'DOS query still sets Owned by name existence'
                $file = Join-Path $env:TEMP ('fsring-c4-own-' + [Guid]::NewGuid().ToString('N') + '.bin')
                try {
                    [IO.File]::WriteAllBytes($file, [byte[]](1, 2, 3, 4))
                    $hash = Get-C4FileSha256Lower $file
                    Assert-SelfTest (Test-C4ServiceBinaryMatchesTuple $file $hash) 'owned SYS hash did not match'
                    Assert-SelfTest (-not (Test-C4ServiceBinaryMatchesTuple $file ('ab' * 32))) 'unowned SYS hash was treated as owned'
                    Assert-SelfTest (Test-C4DosTargetMatchesTuple '\Device\FsRingVolume-0000000000000003-0000000000000004' $null) 'bound VDO target was not owned'
                    Assert-SelfTest (-not (Test-C4DosTargetMatchesTuple '\Device\Other' $null)) 'foreign DOS target was treated as owned'
                    Assert-SelfTest (-not (Test-C4DosTargetMatchesTuple '\Device\FsRingVolume-0000000000000003-0000000000000004' '\Device\Other')) 'DOS target ignored the expected tuple'
                } finally {
                    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
                }
            }
        }
    )

    $newCaseNames = @(
        'C4 v2 roster, cleanup order, and DOS flags are exact',
        'C4 v2 parser derives PASS only from twenty-seven matching probes',
        'C4 v2 parser ignores a self-reported PASS',
        'C4 v2 parser fails a NOT RUN probe once an identity exists',
        'C4 v2 parser rejects a reordered roster and a bad root key set',
        'C4 infrastructure reasons are closed, first-per-stage, and force failure',
        'C4 worker reasons are bounded cumulatively and reject the reserved prefix',
        'C4 frame continuity covers sequence, nonce, identity, slice, and cleanup',
        'C4 SCM cleanup failure is an infrastructure reason, not a probe',
        'C4 unload-transients merges exactly three sources or stays NOT RUN',
        'C4 frame codec round-trips and refuses out-of-bound lengths',
        'C4 DOS name is derived from the exact retained PID and GUID',
        'c4_live_mode_routes_to_public_v2_not_the_v1_harness',
        'preflight_uses_orchestration_envelope_not_public_v2_schema',
        'v1_selftest_and_c3_regression_never_parse_as_v2',
        'live_stdout_is_one_json_object_and_raw_etw_goes_to_sidecars',
        'C4 attempt service and DOS derivation reject caller overrides',
        'C4 diagnostics journal header and hash chain are exact',
        'C4 CleanupOnly first-step refusal is REFUSED with zero mutation',
        'C4 CleanupOnly accepted path is PASS only when both names are absent',
        'C4 CleanupOnly cannot reach install start load or link-create',
        'C4 live fake happy path emits public v2 PASS with 27 actuals',
        'C4 live after mutation malformed frame is FAIL not NOT RUN',
        'C4 live rejects caller service and DOS name overrides',
        'C4 CleanupOnly success then ownership ambiguity is FAIL',
        'C4 CleanupOnly all-success then unobservable after is FAIL',
        'C4 CleanupOnly delayed service deletion is FAIL',
        'C4 CleanupOnly journal reread failure before and after each operation is FAIL',
        'C4 CleanupOnly each FAILED operation is FAIL with that row',
        'C4 preflight envelope is orchestration not public v2',
        'C4 live default route launches via Invoke-C4EvidenceProcess',
        'C4 CleanupOnly default Query and Mutate inspect journal-proven objects',
        'native sc identity ignores blank and poisoned SystemRoot',
        'real command adapter bounds a hung process tree',
        'SCM timeout records containment and blocks cleanup',
        'ambiguous contained create reconciles exact ownership',
        'unconfirmed create containment withholds all cleanup',
        'C4 preflight binds source identity to the candidate manifest',
        'C4 preflight runnable follows host readiness not file identity',
        'trustReady true is still not runnable without TESTSIGNING'
    )
    $caseNames = @($cases | ForEach-Object { $_.Name })
    $legacyNames = [string[]]@(
        $caseNames | Where-Object {
            -not ($newCaseNames -ccontains $_)
        }
    )
    [Array]::Sort($legacyNames, [StringComparer]::Ordinal)
    $rosterBytes = (
        New-Object System.Text.UTF8Encoding($false)
    ).GetBytes(($legacyNames -join "`n"))
    $rosterSha = [Security.Cryptography.SHA256]::Create()
    try {
        $legacyRosterHash = (
            $rosterSha.ComputeHash($rosterBytes) |
                ForEach-Object { $_.ToString('X2') }
        ) -join ''
    } finally {
        $rosterSha.Dispose()
    }
    $rosterValid = (
        $cases.Count -eq 109 -and
        @($caseNames | Select-Object -Unique).Count -eq 109 -and
        $legacyNames.Count -eq 69 -and
        $legacyRosterHash -ceq (
            '581CAFD09FF0C5B723FFFABDBB41860A32101DC4909F240D4E1C5868223A7753'
        )
    )

    $passed = New-Object System.Collections.ArrayList
    $failures = New-Object System.Collections.ArrayList
    if (-not $rosterValid) {
        [void]$failures.Add(
            'self-test roster: expected exact 69-case legacy roster plus 5 remediation, 12 C4 parser, 20 C4 production-route, 2 C4 preflight, and 1 trust-readiness case'
        )
    }
    foreach ($case in $cases) {
        try {
            & $case.Body
            [void]$passed.Add($case.Name)
        } catch {
            [void]$failures.Add("$($case.Name): $($_.Exception.Message)")
        }
    }
    try {
        Remove-TestContainedClientFixture
    } catch {
        [void]$failures.Add(
            "contained client fixture cleanup: $($_.Exception.Message)"
        )
    }

    $result = New-SmokeResult 'SelfTest' '<injected>' '<injected>'
    $result.tests = @($passed)
    $result.failures = @($failures)
    if ($failures.Count -eq 0) {
        $result = Complete-SmokeResult $result 'PASS'
    } else {
        foreach ($failure in $failures) {
            Add-Reason $result $failure
        }
        $result = Complete-SmokeResult $result 'FAIL'
    }
    Write-FinalSmokeResult $result
    exit $result.exitCode
}

if ($SelfTest) {
    Invoke-SelfTests
}

if ($CleanupOnly) {
    $cleanup = Invoke-C4CleanupOnlyCore `
        -AttemptId $AttemptId `
        -CandidateManifestPath $CandidateManifestPath `
        -ExpectedCandidateManifestSha256 $ExpectedCandidateManifestSha256 `
        -DiagnosticsJournalPath $DiagnosticsJournalPath `
        -ContainmentProofPath $ContainmentProofPath `
        -ExpectedContainmentProofSha256 $ExpectedContainmentProofSha256 `
        -CleanupEvidencePath $CleanupEvidencePath `
        -OwnedServiceName $OwnedServiceName `
        -OwnedDosName $OwnedDosName
    $payload = (ConvertTo-C4CanonicalJson $cleanup) + "`n"
    $utf8 = New-Object System.Text.UTF8Encoding $false
    $bytes = $utf8.GetBytes($payload)
    $stdout = [Console]::OpenStandardOutput()
    $stdout.Write($bytes, 0, $bytes.Length)
    $stdout.Flush()
    if ($cleanup.status -ceq 'PASS') { exit 0 }
    if ($cleanup.status -ceq 'REFUSED') { exit 2 }
    exit 1
}

if ($C4) {
    if (-not (Test-C4AttemptId $AttemptId)) {
        throw 'AttemptId must be lowercase GUID-N.'
    }
    if ([string]::IsNullOrWhiteSpace($CandidateManifestPath) -or
        $ExpectedCandidateManifestSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'C4 mode requires CandidateManifestPath and lowercase ExpectedCandidateManifestSha256.'
    }
    if ($PreflightOnly) {
        if (-not [string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
            if (-not [IO.Directory]::Exists($EvidenceDirectory)) {
                throw 'C4 preflight EvidenceDirectory must exist and be empty.'
            }
            $entries = @(Get-ChildItem -LiteralPath $EvidenceDirectory -Force)
            if ($entries.Count -ne 0) {
                throw 'C4 preflight EvidenceDirectory must be empty.'
            }
        }
        $c4DefaultPackage = Join-Path $PSScriptRoot '..\target\x86_64-pc-windows-msvc\release\fsring_fsd_package'
        $c4DefaultHarness = Join-Path $PSScriptRoot '..\..\target\debug\fsring-control-smoke.exe'
        $c4Package = Resolve-LiteralFullPath $PackageDirectory $c4DefaultPackage
        $c4Harness = Resolve-LiteralFullPath $HarnessPath $c4DefaultHarness
        $c4Paths = [pscustomobject]@{
            PackageDirectory = $c4Package
            InfPath = [System.IO.Path]::GetFullPath((Join-Path $c4Package 'fsring_fsd.inf'))
            SysPath = [System.IO.Path]::GetFullPath((Join-Path $c4Package 'fsring_fsd.sys'))
            CatPath = [System.IO.Path]::GetFullPath((Join-Path $c4Package 'fsring_fsd.cat'))
            HarnessPath = $c4Harness
            VerifierPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'verify_fsring_package.ps1'))
            PowerShellPath = [System.IO.Path]::GetFullPath((Join-Path $PSHOME 'powershell.exe'))
            ScPath = $null
        }
        $c4Result = New-SmokeResult 'PreflightOnly' $c4Package $c4Harness
        Invoke-ReadOnlyPreflight (New-RealAdapter) $c4Result $c4Paths $ExpectedHarnessSha256
        $envelope = New-C4PreflightOnlyEnvelope -AttemptId $AttemptId `
            -CandidateManifestPath $CandidateManifestPath `
            -ExpectedCandidateManifestSha256 $ExpectedCandidateManifestSha256 `
            -PackageDirectory $PackageDirectory -HarnessPath $HarnessPath `
            -ExpectedHarnessSha256 $ExpectedHarnessSha256 -Facts $c4Result.preflight
        $payload = (ConvertTo-C4CanonicalJson $envelope) + "`n"
        $utf8 = New-Object System.Text.UTF8Encoding $false
        $bytes = $utf8.GetBytes($payload)
        $stdout = [Console]::OpenStandardOutput()
        $stdout.Write($bytes, 0, $bytes.Length)
        $stdout.Flush()
        exit 2
    }

    $sourceCommit = (& git rev-parse HEAD).Trim()
    $sourceTree = (& git rev-parse 'HEAD^{tree}').Trim()
    $defaultPackage = Join-Path $PSScriptRoot '..\target\x86_64-pc-windows-msvc\release\fsring_fsd_package'
    $packageRoot = $PackageDirectory
    if ([string]::IsNullOrWhiteSpace($packageRoot)) { $packageRoot = $defaultPackage }
    $sysPath = [IO.Path]::GetFullPath((Join-Path $packageRoot 'fsring_fsd.sys'))
    $harnessFile = $HarnessPath
    if ([string]::IsNullOrWhiteSpace($harnessFile)) {
        $harnessFile = Join-Path $PSScriptRoot '..\..\target\debug\fsring-control-smoke.exe'
    }
    $packageHash = Get-C4FileSha256Lower $sysPath
    if ($null -eq $packageHash) { $packageHash = Get-C4Sha256Hex ([byte[]](New-Object byte[] 0)) }
    $actualHarness = Get-C4FileSha256Lower $harnessFile
    if ($null -eq $actualHarness) { $actualHarness = Get-C4Sha256Hex ([byte[]](New-Object byte[] 0)) }
    $live = Invoke-C4LiveWorkflow `
        -AttemptId $AttemptId `
        -CandidateManifestPath $CandidateManifestPath `
        -ExpectedCandidateManifestSha256 $ExpectedCandidateManifestSha256 `
        -ExpectedHarnessSha256 $ExpectedHarnessSha256 `
        -ActualHarnessSha256 $actualHarness `
        -EvidenceDirectory $EvidenceDirectory `
        -HarnessPath ([IO.Path]::GetFullPath($harnessFile)) `
        -WorkingDirectory ((Get-Location).Path) `
        -SourceCommit $sourceCommit `
        -SourceTree $sourceTree `
        -PackageSetSha256 $packageHash `
        -ArtifactSetSha256 $packageHash `
        -SysPath $sysPath
    $liveBytes = Get-C4Utf8NoBom $live.Json
    $liveOut = [Console]::OpenStandardOutput()
    $liveOut.Write($liveBytes, 0, $liveBytes.Length)
    $liveOut.Flush()
    exit [int]$live.ExitCode
}

$mode = 'Live'
if ($PreflightOnly) {
    $mode = 'PreflightOnly'
}
$defaultPackage = Join-Path $PSScriptRoot '..\target\x86_64-pc-windows-msvc\release\fsring_fsd_package'
$defaultHarness = Join-Path $PSScriptRoot '..\..\target\debug\fsring-control-smoke.exe'
$resolvedPackage = $PackageDirectory
$resolvedHarness = $HarnessPath
try {
    $resolvedPackage = Resolve-LiteralFullPath $PackageDirectory $defaultPackage
    $resolvedHarness = Resolve-LiteralFullPath $HarnessPath $defaultHarness
} catch {
    $result = New-SmokeResult $mode ([string]$resolvedPackage) ([string]$resolvedHarness)
    $result.preflight.pathResolutionValid = $false
    Add-Reason $result $_.Exception.Message
    $result = Complete-SmokeResult $result 'FAIL'
    Write-FinalSmokeResult $result
    exit $result.exitCode
}

$verifierPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'verify_fsring_package.ps1'))
$powerShellPath = [System.IO.Path]::GetFullPath((Join-Path $PSHOME 'powershell.exe'))
$paths = [pscustomobject]@{
    PackageDirectory = $resolvedPackage
    InfPath = [System.IO.Path]::GetFullPath((Join-Path $resolvedPackage 'fsring_fsd.inf'))
    SysPath = [System.IO.Path]::GetFullPath((Join-Path $resolvedPackage 'fsring_fsd.sys'))
    CatPath = [System.IO.Path]::GetFullPath((Join-Path $resolvedPackage 'fsring_fsd.cat'))
    HarnessPath = $resolvedHarness
    VerifierPath = $verifierPath
    PowerShellPath = $powerShellPath
    ScPath = $null
}
$result = New-SmokeResult $mode $resolvedPackage $resolvedHarness
$adapter = New-RealAdapter
try {
    Invoke-ReadOnlyPreflight `
        $adapter $result $paths $ExpectedHarnessSha256
    $result = Invoke-Orchestration $mode $adapter $result $paths
} catch {
    Add-Reason $result $_.Exception.Message
    if (Test-EmergencyCleanupAllowed $result) {
        try {
            $null = Invoke-OwnedCleanup $adapter $result $paths.ScPath $paths.SysPath
        } catch {
            Add-Reason $result "Emergency owned cleanup failed: $($_.Exception.Message)"
        }
    }
    $result = Complete-SmokeResult $result 'FAIL'
}
Write-FinalSmokeResult $result
exit $result.exitCode
