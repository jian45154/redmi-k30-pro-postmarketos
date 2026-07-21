param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Preflight", "Execute", "Postwrite")]
    [string]$Mode,
    [Parameter(Mandatory = $true)]
    [string]$RepoRoot,
    [Parameter(Mandatory = $true)]
    [string]$ProfilePath,
    [Parameter(Mandatory = $true)]
    [string]$ResultPath,
    [Parameter(Mandatory = $true)]
    [string]$JournalPath,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedHelperSha256,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedProfileSha256,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedArtifactHashesJson,
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$ExpectedApprovalClaimSha256,
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$ExpectedIntentInitialSha256,
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$ExpectedNativeStagePath
)

# This helper is intentionally narrow.  The Python gate performs the full
# schema/attestation audit first.  Preflight independently locks every Windows
# input and prepares the candidate; Execute locks only the small repository
# contract plus the exact prepared NTFS candidate.  Both own the device lock,
# repeat device checks, and only Execute may start one literal userdata write.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$FastbootPathSemantics = "localappdata/lmi-p2-d114/fastboot-r37.0.0/fastboot.exe"
$FastbootPath = $null
$FastbootSize = 2199704L
$FastbootSha256 = "dd55fef77ab2753b6423f37f39d91cb00ce53ab4539a2431577f07c4abcaa32a"
$FastbootArchiveOfficialSha1 = "f29bfb58d0d6f9a57d7dbcba6cc259f9ca6f58f1"
$FastbootArchiveSha256 = "4fe305812db074cea32903a489d061eb4454cbc90a49e8fea677f4b7af764918"
$FastbootArchiveSize = 8092164L
$FastbootArchiveUrl = "https://dl.google.com/android/repository/platform-tools_r37.0.0-win.zip"
$FastbootArchiveRelativePath = "private/lmi-p1/recovery/d110-d114/third-party/platform-tools-r37.0.0/platform-tools_r37.0.0-win.zip"
$FastbootArchiveEntryCount = 15
$FastbootSignerLeafSha256 = "2029505d14baf18af60a0d1a7d8b56447db643b32faa849d4c08d2ab1ff3a4fd"
$FastbootStagingRootSemantics = "localappdata/lmi-p2-d114/fastboot-r37.0.0"
$NativeStagingRootSemantics = "localappdata/lmi-p2-d114/userdata-staging"
$ResultSchema = "lmi-p2-d114-userdata-powershell-result/v5"
$ProfileSchema = "lmi-p2-d114-userdata-deploy-profile/v2"
$MappingSchema = "lmi-d114-physical-userdata-mapping/v2"
$DeployPolicySchema = "lmi-p2-d114-userdata-deploy-policy-lock/v4"
$ResultPrefix = "LMI_P2_D114_RESULT_JSON_BASE64="
$QueryTimeoutMs = 10000
$WriteTimeoutMs = 300000
$ApprovalTtlSeconds = 120L
$Locked = @{}
$LockedMetadata = @{}
$LockStream = $null
$FlashAttempts = 0
$FlashAssignmentConfirmed = $false
$FlashExit = $null
$TransportCompleted = $false
$FlashSendingOkay = 0
$FlashStarted = $false
$FlashTimedOut = $false
$FlashTreeQuiescent = $false
$FlashWritingOkay = 0
$Reason = $null
$Route = "REFUSED_NO_STATE_CHANGE"
$AttemptJournalDurable = $false
$IntentStream = $null
$IntentApprovalIssuedAtUnix = $null
$IntentApprovalExpiresAtUnix = $null
$IntentPreflightCreatedAtUnix = $null
$FlashBoundaryEntered = $false
$NativeStagePath = $null
$LockedInputsIntact = $true
$Device = [ordered]@{
    battery_mv = $null
    identity_match = $false
    is_logical_userdata = $null
    max_download_size = $null
    partition_size = $null
    partition_type = $null
    physical_mapping_evidence_override = $false
    product = $null
    soc_ok = $null
    unlocked = $null
    userspace = $null
}

function Fail([string]$Code) {
    if ($Code -notmatch '^[A-Z0-9_]{1,96}$') {
        throw "unsafe internal refusal code"
    }
    throw [System.InvalidOperationException]::new($Code)
}

function Require-ExactKeys($Object, [string[]]$Keys, [string]$Code) {
    if ($null -eq $Object) { Fail $Code }
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Keys | Sort-Object)
    if (($actual -join "`n") -cne ($wanted -join "`n")) { Fail $Code }
}

function Require-PositiveJsonUInt64($Value, [string]$Code) {
    if (($Value -isnot [int]) -and ($Value -isnot [long])) { Fail $Code }
    $signed = [int64]$Value
    if ($signed -le 0) { Fail $Code }
    return [uint64]$signed
}

function Open-ReadLocked([string]$Path, [string]$Label) {
    if (-not [System.IO.Path]::IsPathRooted($Path)) { Fail "UNSAFE_$Label" }
    try {
        $full = [System.IO.Path]::GetFullPath($Path)
        $attributes = [System.IO.File]::GetAttributes($full)
        if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "UNSAFE_$Label" }
        $stream = [System.IO.File]::Open(
            $full,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        if ($stream.Length -le 0) {
            $stream.Dispose()
            Fail "EMPTY_$Label"
        }
        return $stream
    } catch [System.InvalidOperationException] {
        throw
    } catch {
        Fail "OPEN_$Label"
    }
}

function Hash-Stream([System.IO.FileStream]$Stream) {
    $position = $Stream.Position
    try {
        $Stream.Position = 0
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha.ComputeHash($Stream))).Replace("-", "").ToLowerInvariant()
        } finally {
            $sha.Dispose()
        }
    } finally {
        $Stream.Position = $position
    }
}

function Read-JsonLocked([System.IO.FileStream]$Stream, [string]$Code) {
    $Stream.Position = 0
    $bytes = New-Object byte[] $Stream.Length
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $count = $Stream.Read($bytes, $offset, $bytes.Length - $offset)
        if ($count -le 0) { Fail $Code }
        $offset += $count
    }
    $Stream.Position = 0
    try {
        $encoding = [System.Text.UTF8Encoding]::new($false, $true)
        return ($encoding.GetString($bytes) | ConvertFrom-Json)
    } catch {
        Fail $Code
    }
}

function Resolve-RepoFile([string]$Relative, [string]$Code) {
    if ([string]::IsNullOrWhiteSpace($Relative) -or [System.IO.Path]::IsPathRooted($Relative) -or $Relative.Contains("\") -or $Relative.Contains("..")) {
        Fail $Code
    }
    $root = [System.IO.Path]::GetFullPath($RepoRoot).TrimEnd('\')
    $path = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($root, $Relative.Replace('/', '\')))
    if (-not $path.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) { Fail $Code }
    return $path
}

function Assert-LockedIdentity([string]$Name, $Spec) {
    $stream = $Locked[$Name]
    if ($stream.Length -ne [int64]$Spec.size) { Fail "SIZE_$($Name.ToUpperInvariant())" }
    if ((Hash-Stream $stream) -cne [string]$Spec.sha256) { Fail "HASH_$($Name.ToUpperInvariant())" }
}

function Remember-LockedIdentity([string]$Name) {
    $stream = $Locked[$Name]
    $info = [System.IO.FileInfo]::new($stream.Name)
    $LockedMetadata[$Name] = [ordered]@{
        path = $info.FullName
        length = $info.Length
        creation_ticks = $info.CreationTimeUtc.Ticks
        sha256 = Hash-Stream $stream
        write_ticks = $info.LastWriteTimeUtc.Ticks
    }
}

function Assert-LockedStillSame([string]$Name) {
    $stream = $Locked[$Name]
    $before = $LockedMetadata[$Name]
    $info = [System.IO.FileInfo]::new($stream.Name)
    $postHash = Hash-Stream $stream
    if (
        $stream.Length -ne [int64]$before.length -or
        $info.FullName -cne [string]$before.path -or
        $info.Length -ne [int64]$before.length -or
        $info.CreationTimeUtc.Ticks -ne [int64]$before.creation_ticks -or
        $info.LastWriteTimeUtc.Ticks -ne [int64]$before.write_ticks -or
        $postHash -cne [string]$before.sha256 -or
        (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    ) { Fail "POST_IDENTITY_$($Name.ToUpperInvariant())" }
    return $postHash
}

function Quote-WindowsArgument([string]$Value) {
    if ($Value -notmatch '[\s"]') { return $Value }
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashes += 1
        } elseif ($character -eq '"') {
            [void]$builder.Append(('\' * (2 * $slashes + 1)))
            [void]$builder.Append('"')
            $slashes = 0
        } else {
            if ($slashes) { [void]$builder.Append(('\' * $slashes)); $slashes = 0 }
            [void]$builder.Append($character)
        }
    }
    if ($slashes) { [void]$builder.Append(('\' * (2 * $slashes))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

public sealed class LmiNativeRunResult {
    public bool AssignmentConfirmed;
    public int? ExitCode;
    public string FailureCode;
    public string Output;
    public bool Started;
    public bool TimedOut;
    public bool TransitionDurable;
    public bool TreeQuiescent;
}

public static class LmiNativeRunner {
    const uint CREATE_NO_WINDOW = 0x08000000;
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    const uint HANDLE_FLAG_INHERIT = 0x00000001;
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    const uint STARTF_USESTDHANDLES = 0x00000100;
    const uint WAIT_OBJECT_0 = 0;
    const uint WAIT_TIMEOUT = 258;
    static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES { public int Length; public IntPtr SecurityDescriptor; public int InheritHandle; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct STARTUPINFO { public int cb; public string lpReserved; public string lpDesktop; public string lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    struct BASIC_LIMIT { public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)]
    struct IO_COUNTERS { public ulong ReadOperationCount; public ulong WriteOperationCount; public ulong OtherOperationCount; public ulong ReadTransferCount; public ulong WriteTransferCount; public ulong OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)]
    struct EXTENDED_LIMIT { public BASIC_LIMIT BasicLimitInformation; public IO_COUNTERS IoInfo; public UIntPtr ProcessMemoryLimit; public UIntPtr JobMemoryLimit; public UIntPtr PeakProcessMemoryUsed; public UIntPtr PeakJobMemoryUsed; }
    [StructLayout(LayoutKind.Sequential)]
    struct BASIC_ACCOUNTING { public long TotalUserTime; public long TotalKernelTime; public long ThisPeriodTotalUserTime; public long ThisPeriodTotalKernelTime; public uint TotalPageFaultCount; public uint TotalProcesses; public uint ActiveProcesses; public uint TotalTerminatedProcesses; }

    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SECURITY_ATTRIBUTES attributes, uint size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcessW(string application, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string currentDirectory, ref STARTUPINFO startup, out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length, IntPtr returnedLength);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);

    static bool ConfigureKillOnClose(IntPtr job) {
        EXTENDED_LIMIT limits = new EXTENDED_LIMIT();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        int size = Marshal.SizeOf(typeof(EXTENDED_LIMIT));
        IntPtr pointer = Marshal.AllocHGlobal(size);
        try { Marshal.StructureToPtr(limits, pointer, false); return SetInformationJobObject(job, 9, pointer, (uint)size); }
        finally { Marshal.FreeHGlobal(pointer); }
    }

    static uint ActiveProcesses(IntPtr job) {
        int size = Marshal.SizeOf(typeof(BASIC_ACCOUNTING));
        IntPtr pointer = Marshal.AllocHGlobal(size);
        try {
            if (!QueryInformationJobObject(job, 1, pointer, (uint)size, IntPtr.Zero)) return UInt32.MaxValue;
            return ((BASIC_ACCOUNTING)Marshal.PtrToStructure(pointer, typeof(BASIC_ACCOUNTING))).ActiveProcesses;
        } finally { Marshal.FreeHGlobal(pointer); }
    }

    static bool WaitForQuiescence(IntPtr job, int milliseconds) {
        int waited = 0;
        while (waited <= milliseconds) {
            if (ActiveProcesses(job) == 0) return true;
            Thread.Sleep(25); waited += 25;
        }
        return false;
    }

    static bool ApprovalWindowFresh(long issuedAtUnix, long expiresAtUnix, long preflightCreatedAtUnix) {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (issuedAtUnix < 0 || expiresAtUnix < issuedAtUnix || preflightCreatedAtUnix < 0 || expiresAtUnix - issuedAtUnix != 120) return false;
        if ((issuedAtUnix > now && issuedAtUnix - now > 5) || now > expiresAtUnix) return false;
        if ((preflightCreatedAtUnix > now && preflightCreatedAtUnix - now > 5) || (now >= preflightCreatedAtUnix && now - preflightCreatedAtUnix > 120)) return false;
        return true;
    }

    static void Close(ref IntPtr handle) { if (handle != IntPtr.Zero && handle != INVALID_HANDLE_VALUE) { CloseHandle(handle); handle = IntPtr.Zero; } }

    public static LmiNativeRunResult Run(string application, string commandLine, string workingDirectory, string environmentBlock, int timeoutMilliseconds, FileStream transitionStream, byte[] transitionBytes, long approvalIssuedAtUnix, long approvalExpiresAtUnix, long preflightCreatedAtUnix) {
        LmiNativeRunResult result = new LmiNativeRunResult { FailureCode = null, Output = "", TreeQuiescent = false };
        IntPtr job = IntPtr.Zero, stdoutRead = IntPtr.Zero, stdoutWrite = IntPtr.Zero, stderrRead = IntPtr.Zero, stderrWrite = IntPtr.Zero, stdinRead = IntPtr.Zero, stdinWrite = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;
        PROCESS_INFORMATION process = new PROCESS_INFORMATION();
        StreamReader stdoutReader = null, stderrReader = null;
        Task<string> stdoutTask = null, stderrTask = null;
        try {
            job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero || !ConfigureKillOnClose(job)) { result.FailureCode = "JOB_SETUP_FAILED"; return result; }
            SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES { Length = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)), InheritHandle = 1 };
            if (!CreatePipe(out stdoutRead, out stdoutWrite, ref security, 0) || !CreatePipe(out stderrRead, out stderrWrite, ref security, 0) || !CreatePipe(out stdinRead, out stdinWrite, ref security, 0)) { result.FailureCode = "PIPE_SETUP_FAILED"; return result; }
            if (!SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0) || !SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0) || !SetHandleInformation(stdinWrite, HANDLE_FLAG_INHERIT, 0)) { result.FailureCode = "PIPE_INHERITANCE_FAILED"; return result; }
            STARTUPINFO startup = new STARTUPINFO { cb = Marshal.SizeOf(typeof(STARTUPINFO)), dwFlags = (int)STARTF_USESTDHANDLES, hStdInput = stdinRead, hStdOutput = stdoutWrite, hStdError = stderrWrite };
            environment = Marshal.StringToHGlobalUni(environmentBlock);
            if (!CreateProcessW(application, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero, true, CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, environment, workingDirectory, ref startup, out process)) { result.FailureCode = "CREATE_PROCESS_SUSPENDED_FAILED"; return result; }
            Close(ref stdoutWrite); Close(ref stderrWrite); Close(ref stdinRead); Close(ref stdinWrite);
            if (!AssignProcessToJobObject(job, process.hProcess)) { result.FailureCode = "JOB_ASSIGN_FAILED"; TerminateJobObject(job, 1460); result.TreeQuiescent = WaitForQuiescence(job, 10000); return result; }
            bool confirmed;
            if (!IsProcessInJob(process.hProcess, job, out confirmed) || !confirmed) { result.FailureCode = "JOB_ASSIGN_UNCONFIRMED"; TerminateJobObject(job, 1460); result.TreeQuiescent = WaitForQuiescence(job, 10000); return result; }
            result.AssignmentConfirmed = true;
            stdoutReader = new StreamReader(new FileStream(new SafeFileHandle(stdoutRead, true), FileAccess.Read), Encoding.UTF8, true); stdoutRead = IntPtr.Zero;
            stderrReader = new StreamReader(new FileStream(new SafeFileHandle(stderrRead, true), FileAccess.Read), Encoding.UTF8, true); stderrRead = IntPtr.Zero;
            stdoutTask = stdoutReader.ReadToEndAsync(); stderrTask = stderrReader.ReadToEndAsync();
            if (transitionStream != null) {
                if (!ApprovalWindowFresh(approvalIssuedAtUnix, approvalExpiresAtUnix, preflightCreatedAtUnix)) { result.FailureCode = "APPROVAL_WINDOW_EXPIRED_BEFORE_TRANSITION"; TerminateJobObject(job, 1460); result.TreeQuiescent = WaitForQuiescence(job, 10000); return result; }
                transitionStream.Position = transitionStream.Length;
                transitionStream.Write(transitionBytes, 0, transitionBytes.Length);
                transitionStream.Flush(true);
                result.TransitionDurable = true;
                if (!ApprovalWindowFresh(approvalIssuedAtUnix, approvalExpiresAtUnix, preflightCreatedAtUnix)) { result.FailureCode = "APPROVAL_WINDOW_EXPIRED_BEFORE_RESUME"; TerminateJobObject(job, 1460); result.TreeQuiescent = WaitForQuiescence(job, 10000); return result; }
            }
            if (ResumeThread(process.hThread) == UInt32.MaxValue) { result.FailureCode = "RESUME_THREAD_FAILED"; TerminateJobObject(job, 1460); result.TreeQuiescent = WaitForQuiescence(job, 10000); return result; }
            result.Started = true;
            uint wait = WaitForSingleObject(process.hProcess, (uint)timeoutMilliseconds);
            if (wait == WAIT_TIMEOUT) { result.TimedOut = true; result.FailureCode = "PROCESS_TREE_TIMEOUT"; TerminateJobObject(job, 1460); }
            else if (wait != WAIT_OBJECT_0) { result.FailureCode = "PROCESS_WAIT_FAILED"; TerminateJobObject(job, 1460); }
            else { uint code; if (GetExitCodeProcess(process.hProcess, out code)) result.ExitCode = unchecked((int)code); else result.FailureCode = "PROCESS_EXIT_CODE_FAILED"; }
            if (!WaitForQuiescence(job, 10000)) { if (result.FailureCode == null) result.FailureCode = "PROCESS_TREE_REMAINED_ACTIVE"; TerminateJobObject(job, 1460); }
            result.TreeQuiescent = WaitForQuiescence(job, 10000);
            Task[] readers = new Task[] { stdoutTask, stderrTask };
            if (result.TreeQuiescent && Task.WaitAll(readers, 10000) && stdoutTask.IsCompleted && stderrTask.IsCompleted && !stdoutTask.IsFaulted && !stderrTask.IsFaulted) {
                result.Output = stdoutTask.GetAwaiter().GetResult() + "\n" + stderrTask.GetAwaiter().GetResult();
            } else if (result.FailureCode == null) result.FailureCode = "OUTPUT_DRAIN_UNCONFIRMED";
            return result;
        } catch {
            if (job != IntPtr.Zero) { TerminateJobObject(job, 1460); result.TreeQuiescent = WaitForQuiescence(job, 10000); }
            if (result.FailureCode == null) result.FailureCode = "NATIVE_RUNNER_FAILURE";
            return result;
        } finally {
            if (stdoutReader != null) stdoutReader.Dispose(); if (stderrReader != null) stderrReader.Dispose();
            Close(ref stdoutRead); Close(ref stdoutWrite); Close(ref stderrRead); Close(ref stderrWrite); Close(ref stdinRead); Close(ref stdinWrite);
            Close(ref process.hThread); Close(ref process.hProcess); Close(ref job);
            if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
        }
    }
}
'@

function Invoke-Fastboot([string[]]$Arguments, [int]$TimeoutMs, [System.IO.FileStream]$IntentStream = $null, [byte[]]$TransitionBytes = $null, [int64]$ApprovalIssuedAtUnix = 0, [int64]$ApprovalExpiresAtUnix = 0, [int64]$PreflightCreatedAtUnix = 0) {
    if ($null -eq $FastbootPath -or -not $Locked.ContainsKey('fastboot')) { Fail 'FASTBOOT_NOT_RUNTIME_LOCKED' }
    $fastbootDirectory = [System.IO.Path]::GetDirectoryName($FastbootPath)
    $systemRoot = [System.Environment]::GetEnvironmentVariable('SystemRoot')
    if ([string]::IsNullOrWhiteSpace($systemRoot) -or -not [System.IO.Path]::IsPathRooted($systemRoot)) { Fail 'SAFE_ENVIRONMENT_SYSTEMROOT_INVALID' }
    $temporary = [System.IO.Path]::GetTempPath().TrimEnd('\')
    if (-not [System.IO.Path]::IsPathRooted($temporary)) { Fail 'SAFE_ENVIRONMENT_TEMP_INVALID' }
    $safeEnvironment = @(
        'LOCALAPPDATA=' + [System.Environment]::GetEnvironmentVariable('LOCALAPPDATA'),
        'PATH=' + $fastbootDirectory + ';' + [System.IO.Path]::Combine($systemRoot, 'System32') + ';' + $systemRoot,
        'PATHEXT=.COM;.EXE;.BAT;.CMD',
        'SystemDrive=' + [System.IO.Path]::GetPathRoot($systemRoot).TrimEnd('\'),
        'SystemRoot=' + $systemRoot,
        'TEMP=' + $temporary,
        'TMP=' + $temporary,
        'WINDIR=' + $systemRoot
    )
    $environmentBlock = (($safeEnvironment | Sort-Object) -join [char]0) + [char]0 + [char]0
    $commandLine = (Quote-WindowsArgument $FastbootPath) + ' ' + (($Arguments | ForEach-Object { Quote-WindowsArgument $_ }) -join ' ')
    $native = [LmiNativeRunner]::Run($FastbootPath, $commandLine, $fastbootDirectory, $environmentBlock, $TimeoutMs, $IntentStream, $TransitionBytes, $ApprovalIssuedAtUnix, $ApprovalExpiresAtUnix, $PreflightCreatedAtUnix)
    return [ordered]@{
        assignment_confirmed = [bool]$native.AssignmentConfirmed
        exit_code = $native.ExitCode
        failure_code = $native.FailureCode
        output = ([string]$native.Output -replace "`r", "")
        started = [bool]$native.Started
        timed_out = [bool]$native.TimedOut
        transition_durable = [bool]$native.TransitionDurable
        tree_quiescent = [bool]$native.TreeQuiescent
    }
}

function Get-FastbootVariable([string]$Serial, [string]$Name, [switch]$AllowUnsupported) {
    $result = Invoke-Fastboot @('-s', $Serial, 'getvar', $Name) $QueryTimeoutMs
    if ($result.timed_out) { Fail "QUERY_TIMEOUT" }
    if (-not $result.started -or -not $result.assignment_confirmed -or -not $result.tree_quiescent -or $null -ne $result.failure_code) { Fail "QUERY_PROCESS_CONTAINMENT_FAILED" }
    $escaped = [regex]::Escape($Name)
    $reasonName = $Name.ToUpperInvariant() -replace '[^A-Z0-9]', '_'
    # Current platform-tools prints a standalone getvar as `name: value`.
    # Some bootloaders instead surface the same response with the historical
    # `(bootloader)` INFO prefix.  Bind every accepted transcript to this key,
    # one result line, one r37 footer, and no other non-whitespace output.
    $valuePattern = "(?im)^(?:\(bootloader\)[ \t]+)?${escaped}:[ \t]*([^\r\n]*?)[ \t]*$"
    $failurePattern = "(?im)^getvar:${escaped}[ \t]+FAILED[ \t]+\([ \t]*remote:[ \t]*'(?:GetVar[ \t]+Variable[ \t]+Not[ \t]+found|Unknown[ \t]+variable|Variable[ \t]+Not[ \t]+found|Unsupported)'[ \t]*\)[ \t]*$"
    $footerPattern = '(?im)^Finished\. Total time:[ \t]+[0-9]+(?:\.[0-9]+)?s[ \t]*$'
    $valueMatches = @([regex]::Matches($result.output, $valuePattern))
    $failureMatches = @([regex]::Matches($result.output, $failurePattern))
    $footerMatches = @([regex]::Matches($result.output, $footerPattern))
    if ($valueMatches.Count -gt 1 -or $failureMatches.Count -gt 1 -or $footerMatches.Count -ne 1) {
        Fail ("GETVAR_FAILED_" + $reasonName)
    }
    if ($result.exit_code -eq 0 -and $valueMatches.Count -eq 1 -and $failureMatches.Count -eq 0) {
        $remainder = [regex]::Replace($result.output, $valuePattern, '')
        $remainder = [regex]::Replace($remainder, $footerPattern, '')
        $value = $valueMatches[0].Groups[1].Value.Trim()
        if ([string]::IsNullOrWhiteSpace($remainder) -and $value.Length -gt 0) { return $value }
    }
    if ($AllowUnsupported -and $result.exit_code -eq 0 -and $valueMatches.Count -eq 0 -and $failureMatches.Count -eq 1) {
        $remainder = [regex]::Replace($result.output, $failurePattern, '')
        $remainder = [regex]::Replace($remainder, $footerPattern, '')
        if ([string]::IsNullOrWhiteSpace($remainder)) { return "unsupported" }
    }
    Fail ("GETVAR_FAILED_" + $reasonName)
}

function Parse-UInt64([string]$Value, [string]$Code) {
    try {
        if ($Value -match '^0[xX][0-9a-fA-F]+$') {
            return [Convert]::ToUInt64($Value.Substring(2), 16)
        }
        if ($Value -match '^[0-9]+$') { return [Convert]::ToUInt64($Value, 10) }
    } catch {}
    Fail $Code
}

function Device-Identity([string]$Nonce, [string]$Serial) {
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Nonce + [char]0 + $Serial)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Check-Device($Profile, $IdentityPolicy, $Mapping) {
    $devices = Invoke-Fastboot @('devices') $QueryTimeoutMs
    if ($devices.timed_out -or -not $devices.started -or -not $devices.assignment_confirmed -or -not $devices.tree_quiescent -or $null -ne $devices.failure_code -or $devices.exit_code -ne 0) { Fail "DEVICES_QUERY_FAILED" }
    $lines = @($devices.output -split "`n" | Where-Object { $_.Trim().Length -gt 0 })
    $serials = @()
    foreach ($line in $lines) {
        if ($line -notmatch '^([^\s]+)\s+fastboot$') { Fail "DEVICES_OUTPUT_INVALID" }
        $serials += $Matches[1]
    }
    if ($serials.Count -ne 1) { Fail "DEVICE_COUNT_NOT_ONE" }
    $serial = [string]$serials[0]
    if ($serial -notmatch '^[A-Za-z0-9._:-]{1,128}$') { Fail "DEVICE_SERIAL_INVALID" }
    $serialNo = Get-FastbootVariable $serial 'serialno'
    if ($serialNo -cne $serial) { Fail "DEVICE_SERIAL_MISMATCH" }

    $history = $IdentityPolicy.historical_identity
    $identity = Device-Identity ([string]$history.privacy_nonce) $serial
    if ($identity -cne [string]$history.expected_nonce_scoped_serial_sha256) { Fail "DEVICE_IDENTITY_MISMATCH" }
    $product = Get-FastbootVariable $serial 'product'
    $unlocked = Get-FastbootVariable $serial 'unlocked'
    $userspace = Get-FastbootVariable $serial 'is-userspace'
    $logical = Get-FastbootVariable $serial 'is-logical:userdata' -AllowUnsupported
    $partitionType = Get-FastbootVariable $serial 'partition-type:userdata'
    $partitionSize = Parse-UInt64 (Get-FastbootVariable $serial 'partition-size:userdata') 'PARTITION_SIZE_INVALID'
    $battery = Parse-UInt64 (Get-FastbootVariable $serial 'battery-voltage') 'BATTERY_INVALID'
    $soc = Get-FastbootVariable $serial 'battery-soc-ok'
    $maxDownload = Parse-UInt64 (Get-FastbootVariable $serial 'max-download-size') 'MAX_DOWNLOAD_INVALID'

    if ($product -cne 'lmi') { Fail "PRODUCT_MISMATCH" }
    if ($unlocked -cne 'yes') { Fail "BOOTLOADER_NOT_UNLOCKED" }
    if ($userspace -cne 'no') { Fail "USERSPACE_FASTBOOT_FORBIDDEN" }
    $override = $false
    if ($logical -ceq 'yes') { Fail "LOGICAL_USERDATA_FORBIDDEN" }
    elseif ($logical -ceq 'no') {}
    elseif ($logical -ceq 'unsupported') {
        if (
            $Mapping.schema -cne $MappingSchema -or
            $Mapping.override.allowed_getvar_result -cne 'unsupported' -or
            $Mapping.override.fastboot_mode -cne 'bootloader' -or
            $Mapping.override.partition -cne 'userdata' -or
            $Mapping.override.partition_type -cne 'f2fs' -or
            $Mapping.override.super_or_fastbootd_fallback_allowed -ne $false -or
            $Mapping.userdata.block_device -cne '/dev/sda34' -or
            [uint64]$Mapping.userdata.capacity_bytes -ne [uint64]$Profile.device.expected_userdata_capacity
        ) { Fail "PHYSICAL_MAPPING_OVERRIDE_INVALID" }
        $override = $true
    } else { Fail "IS_LOGICAL_UNKNOWN" }
    if ($partitionType -cne 'f2fs') { Fail "PARTITION_TYPE_MISMATCH" }
    if (
        $partitionSize -ne [uint64]$Profile.device.expected_userdata_capacity -or
        $partitionSize -lt [uint64]$Profile.artifacts.candidate.logical_size -or
        $partitionSize -lt [uint64]$Profile.artifacts.rollback.logical_size
    ) { Fail "PARTITION_CAPACITY_MISMATCH" }
    if ($battery -lt [uint64]$Profile.device.minimum_battery_mv) { Fail "BATTERY_TOO_LOW" }
    if ($soc -cne 'yes') { Fail "BATTERY_SOC_NOT_OK" }
    if ($maxDownload -lt [uint64]$Profile.device.minimum_max_download_size) { Fail "MAX_DOWNLOAD_TOO_SMALL" }

    $validatedDevice = [ordered]@{
        battery_mv = [int64]$battery
        identity_match = $true
        is_logical_userdata = $logical
        max_download_size = [int64]$maxDownload
        partition_size = [int64]$partitionSize
        partition_type = $partitionType
        physical_mapping_evidence_override = $override
        product = $product
        soc_ok = $soc
        unlocked = $unlocked
        userspace = $userspace
    }
    # The locked helper runs as a child ScriptBlock of bootstrap.ps1.  Scope 1
    # is the helper caller; script: would incorrectly target the bootstrap.
    Set-Variable -Name Device -Scope 1 -Value $validatedDevice
    return $serial
}

function Set-And-AssertPrivateAcl([string]$Path, [bool]$Directory) {
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $inheritance = if ($Directory) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [System.Security.AccessControl.InheritanceFlags]::None }
    $security = if ($Directory) { [System.Security.AccessControl.DirectorySecurity]::new() } else { [System.Security.AccessControl.FileSecurity]::new() }
    $security.SetOwner($current)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($current, $system)) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    if ($Directory) { [System.IO.Directory]::SetAccessControl($Path, $security) }
    else { [System.IO.File]::SetAccessControl($Path, $security) }
    $actual = if ($Directory) { [System.IO.Directory]::GetAccessControl($Path) } else { [System.IO.File]::GetAccessControl($Path) }
    if (-not $actual.AreAccessRulesProtected -or $actual.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -cne $current.Value) { Fail 'NATIVE_STAGE_ACL_OWNER_OR_PROTECTION_MISMATCH' }
    $rules = @($actual.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { Fail 'NATIVE_STAGE_ACL_RULE_COUNT_MISMATCH' }
    $wanted = @($current.Value, $system.Value) | Sort-Object
    $observed = @()
    foreach ($rule in $rules) {
        if (
            $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne $inheritance -or
            $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None
        ) { Fail 'NATIVE_STAGE_ACL_RULE_MISMATCH' }
        $observed += $rule.IdentityReference.Value
    }
    if ((@($observed | Sort-Object) -join "`n") -cne ($wanted -join "`n")) { Fail 'NATIVE_STAGE_ACL_PRINCIPAL_MISMATCH' }
}

function Assert-NativeNtfsDirectory([string]$Path) {
    try {
        $full = [System.IO.Path]::GetFullPath($Path)
        $drive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($full))
        if (
            -not $drive.IsReady -or
            $drive.DriveType -ne [System.IO.DriveType]::Fixed -or
            $drive.DriveFormat -cne 'NTFS'
        ) { Fail 'NATIVE_STAGE_VOLUME_NOT_FIXED_NTFS' }
        $directory = [System.IO.DirectoryInfo]::new($full)
        while ($null -ne $directory) {
            if (-not $directory.Exists -or ($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail 'NATIVE_STAGE_DIRECTORY_CHAIN_UNSAFE'
            }
            $directory = $directory.Parent
        }
    } catch [System.InvalidOperationException] {
        throw
    } catch {
        Fail 'NATIVE_STAGE_VOLUME_INSPECTION_FAILED'
    }
}

function Read-LockedBytes([System.IO.FileStream]$Stream, [int64]$Maximum, [string]$Code) {
    if ($Stream.Length -le 0 -or $Stream.Length -gt $Maximum -or $Stream.Length -gt [int]::MaxValue) { Fail $Code }
    $position = $Stream.Position
    try {
        $Stream.Position = 0
        $bytes = New-Object byte[] ([int]$Stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $Stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -le 0) { Fail $Code }
            $offset += $count
        }
        return ,$bytes
    } finally { $Stream.Position = $position }
}

function Assert-SafeFastbootZip([System.IO.FileStream]$Stream) {
    if (-not [System.BitConverter]::IsLittleEndian) { Fail 'ZIP_HOST_ENDIAN_UNSUPPORTED' }
    $bytes = Read-LockedBytes $Stream 16MB 'ZIP_READ_FAILED'
    $minimum = [Math]::Max(0, $bytes.Length - 65557)
    $eocd = -1
    for ($index = $bytes.Length - 22; $index -ge $minimum; $index -= 1) {
        if ([System.BitConverter]::ToUInt32($bytes, $index) -eq 0x06054b50) {
            $commentLength = [System.BitConverter]::ToUInt16($bytes, $index + 20)
            if (($index + 22 + $commentLength) -eq $bytes.Length) { $eocd = $index; break }
        }
    }
    if ($eocd -lt 0) { Fail 'ZIP_EOCD_INVALID' }
    $disk = [System.BitConverter]::ToUInt16($bytes, $eocd + 4)
    $centralDisk = [System.BitConverter]::ToUInt16($bytes, $eocd + 6)
    $diskEntries = [System.BitConverter]::ToUInt16($bytes, $eocd + 8)
    $totalEntries = [System.BitConverter]::ToUInt16($bytes, $eocd + 10)
    $centralSize = [System.BitConverter]::ToUInt32($bytes, $eocd + 12)
    $centralOffset = [System.BitConverter]::ToUInt32($bytes, $eocd + 16)
    if (
        $disk -ne 0 -or $centralDisk -ne 0 -or
        $diskEntries -ne $FastbootArchiveEntryCount -or
        $totalEntries -ne $FastbootArchiveEntryCount -or
        $centralOffset -ge $eocd -or
        ([uint64]$centralOffset + [uint64]$centralSize) -ne [uint64]$eocd
    ) { Fail 'ZIP_CENTRAL_DIRECTORY_INVALID' }
    $ordinal = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $folded = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $required = @{
        'platform-tools/fastboot.exe' = [ordered]@{ size = $FastbootSize; sha256 = $FastbootSha256; leaf = 'fastboot.exe' }
        'platform-tools/AdbWinApi.dll' = [ordered]@{ size = 108184L; sha256 = '120bef587119c6cb926b86b9be90fdfbce38937588eae28cd91a94ce63c7b965'; leaf = 'AdbWinApi.dll' }
        'platform-tools/AdbWinUsbApi.dll' = [ordered]@{ size = 73368L; sha256 = '6ca69a2ca0e31309c087d288f058977d421ad03500e4c3e1dbd981241a069c60'; leaf = 'AdbWinUsbApi.dll' }
    }
    $found = @{}
    $cursor = [int]$centralOffset
    for ($entryIndex = 0; $entryIndex -lt $totalEntries; $entryIndex += 1) {
        if ($cursor -lt 0 -or ($cursor + 46) -gt $eocd -or [System.BitConverter]::ToUInt32($bytes, $cursor) -ne 0x02014b50) { Fail 'ZIP_CENTRAL_ENTRY_INVALID' }
        $flags = [System.BitConverter]::ToUInt16($bytes, $cursor + 8)
        $method = [System.BitConverter]::ToUInt16($bytes, $cursor + 10)
        $uncompressed = [System.BitConverter]::ToUInt32($bytes, $cursor + 24)
        $nameLength = [System.BitConverter]::ToUInt16($bytes, $cursor + 28)
        $extraLength = [System.BitConverter]::ToUInt16($bytes, $cursor + 30)
        $entryCommentLength = [System.BitConverter]::ToUInt16($bytes, $cursor + 32)
        $diskStart = [System.BitConverter]::ToUInt16($bytes, $cursor + 34)
        $next = [uint64]$cursor + 46L + [uint64]$nameLength + [uint64]$extraLength + [uint64]$entryCommentLength
        if ($flags -ne 0) { Fail 'ZIP_ENCRYPTED_OR_UNSUPPORTED_FLAGS' }
        if ($method -ne 0 -and $method -ne 8) { Fail 'ZIP_COMPRESSION_UNSUPPORTED' }
        if ($diskStart -ne 0 -or $nameLength -le 0 -or $next -gt [uint64]$eocd) { Fail 'ZIP_CENTRAL_ENTRY_INVALID' }
        $nameBytes = New-Object byte[] $nameLength
        [System.Array]::Copy($bytes, $cursor + 46, $nameBytes, 0, $nameLength)
        if (@($nameBytes | Where-Object { $_ -gt 0x7f }).Count -ne 0) { Fail 'ZIP_PATH_NON_ASCII' }
        $name = [System.Text.Encoding]::ASCII.GetString($nameBytes)
        $trimmed = $name.TrimEnd('/')
        if (
            [string]::IsNullOrWhiteSpace($trimmed) -or
            $name.StartsWith('/') -or $name.Contains('\') -or $name.Contains(':') -or $name.Contains('//') -or
            @($trimmed.Split('/') | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' }).Count -ne 0
        ) { Fail 'ZIP_PATH_UNSAFE' }
        if (-not $ordinal.Add($name)) { Fail 'ZIP_DUPLICATE_PATH' }
        if (-not $folded.Add($name)) { Fail 'ZIP_CASE_COLLISION' }
        if ($required.ContainsKey($name)) {
            if ($found.ContainsKey($name) -or [int64]$uncompressed -ne [int64]$required[$name].size) { Fail 'ZIP_REQUIRED_MEMBER_IDENTITY_MISMATCH' }
            $found[$name] = $true
        }
        $cursor = [int]$next
    }
    if ($cursor -ne $eocd -or $found.Count -ne $required.Count) { Fail 'ZIP_REQUIRED_MEMBER_SET_MISMATCH' }
}

function Resolve-LocalAppDataRoot {
    $value = [System.Environment]::GetEnvironmentVariable('LOCALAPPDATA')
    if ([string]::IsNullOrWhiteSpace($value) -or -not [System.IO.Path]::IsPathRooted($value)) { Fail 'LOCALAPPDATA_INVALID' }
    $full = [System.IO.Path]::GetFullPath($value).TrimEnd('\')
    Assert-NativeNtfsDirectory $full
    return $full
}

function Ensure-ProtectedDirectory([string]$Path) {
    if ([System.IO.File]::Exists($Path)) { Fail 'STAGING_DIRECTORY_COLLIDES_WITH_FILE' }
    if (-not [System.IO.Directory]::Exists($Path)) { [void][System.IO.Directory]::CreateDirectory($Path) }
    Assert-NativeNtfsDirectory $Path
    Set-And-AssertPrivateAcl $Path $true
}

function Initialize-RuntimeFastboot {
    Add-Type -AssemblyName System.IO.Compression
    $archivePath = Resolve-RepoFile $FastbootArchiveRelativePath 'FASTBOOT_ARCHIVE_PATH'
    $Locked.fastboot_archive = Open-ReadLocked $archivePath 'FASTBOOT_ARCHIVE'
    Remember-LockedIdentity 'fastboot_archive'
    if ($Locked.fastboot_archive.Length -ne $FastbootArchiveSize -or (Hash-Stream $Locked.fastboot_archive) -cne $FastbootArchiveSha256) { Fail 'FASTBOOT_ARCHIVE_IDENTITY_MISMATCH' }
    Assert-SafeFastbootZip $Locked.fastboot_archive

    $local = Resolve-LocalAppDataRoot
    $base = [System.IO.Path]::Combine($local, 'lmi-p2-d114')
    $stage = [System.IO.Path]::Combine($base, 'fastboot-r37.0.0')
    Ensure-ProtectedDirectory $base
    $created = -not [System.IO.Directory]::Exists($stage)
    Ensure-ProtectedDirectory $stage
    $members = @(
        [ordered]@{ archive_member = 'platform-tools/fastboot.exe'; leaf = 'fastboot.exe'; locked_name = 'fastboot'; sha256 = $FastbootSha256; size = $FastbootSize },
        [ordered]@{ archive_member = 'platform-tools/AdbWinApi.dll'; leaf = 'AdbWinApi.dll'; locked_name = 'fastboot_dll_adbwinapi.dll'; sha256 = '120bef587119c6cb926b86b9be90fdfbce38937588eae28cd91a94ce63c7b965'; size = 108184L },
        [ordered]@{ archive_member = 'platform-tools/AdbWinUsbApi.dll'; leaf = 'AdbWinUsbApi.dll'; locked_name = 'fastboot_dll_adbwinusbapi.dll'; sha256 = '6ca69a2ca0e31309c087d288f058977d421ad03500e4c3e1dbd981241a069c60'; size = 73368L }
    )
    if ($created) {
        $Locked.fastboot_archive.Position = 0
        $zip = [System.IO.Compression.ZipArchive]::new($Locked.fastboot_archive, [System.IO.Compression.ZipArchiveMode]::Read, $true)
        try {
            foreach ($member in $members) {
                $matches = @($zip.Entries | Where-Object { $_.FullName -ceq [string]$member.archive_member })
                if ($matches.Count -ne 1) { Fail 'ZIP_REQUIRED_MEMBER_SET_MISMATCH' }
                $target = [System.IO.Path]::Combine($stage, [string]$member.leaf)
                $input = $matches[0].Open()
                $output = $null
                try {
                    $output = [System.IO.File]::Open($target, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                    $input.CopyTo($output, 1MB)
                    $output.Flush($true)
                } finally {
                    if ($null -ne $output) { $output.Dispose() }
                    $input.Dispose()
                }
                Set-And-AssertPrivateAcl $target $false
            }
        } finally { $zip.Dispose(); $Locked.fastboot_archive.Position = 0 }
    }
    $actual = @([System.IO.Directory]::EnumerateFileSystemEntries($stage) | ForEach-Object { [System.IO.Path]::GetFileName($_) } | Sort-Object)
    $wanted = @('AdbWinApi.dll', 'AdbWinUsbApi.dll', 'fastboot.exe')
    if (($actual -join "`n") -cne ($wanted -join "`n")) { Fail 'FASTBOOT_STAGE_NOT_EXACTLY_THREE_FILES' }
    foreach ($member in $members) {
        $target = [System.IO.Path]::Combine($stage, [string]$member.leaf)
        $lockedName = [string]$member.locked_name
        Set-And-AssertPrivateAcl $target $false
        $Locked[$lockedName] = Open-ReadLocked $target 'FASTBOOT_STAGE_MEMBER'
        Remember-LockedIdentity $lockedName
        if ($Locked[$lockedName].Length -ne [int64]$member.size -or (Hash-Stream $Locked[$lockedName]) -cne [string]$member.sha256) { Fail 'FASTBOOT_STAGE_MEMBER_IDENTITY_MISMATCH' }
    }
    Set-Variable -Name FastbootPath -Scope 1 -Value ([System.IO.Path]::Combine($stage, 'fastboot.exe'))
    Assert-Authenticode 'fastboot'
    Assert-Authenticode 'fastboot_dll_adbwinapi.dll'
    Assert-Authenticode 'fastboot_dll_adbwinusbapi.dll'
}

function Assert-Authenticode([string]$LockedName) {
    $path = $Locked[$LockedName].Name
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) { Fail 'AUTHENTICODE_NOT_VALID' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $leaf = ([System.BitConverter]::ToString($sha.ComputeHash($signature.SignerCertificate.RawData))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
    if (
        $leaf -cne [string]$DeployPolicy.fastboot.authenticode.signer_leaf_certificate_sha256 -or
        $signature.SignerCertificate.Subject -notmatch '(^|,\s*)CN=Google LLC(,|$)'
    ) { Fail 'AUTHENTICODE_SIGNER_MISMATCH' }
    foreach ($certificate in @($signature.SignerCertificate, $signature.TimeStamperCertificate)) {
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        try {
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
            $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
            $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
            $chain.ChainPolicy.UrlRetrievalTimeout = [System.TimeSpan]::FromSeconds(15)
            if (-not $chain.Build($certificate)) { Fail 'AUTHENTICODE_ONLINE_REVOCATION_CHAIN_FAILED' }
        } finally { $chain.Dispose() }
    }
}

function Test-ApprovalWindowFresh([int64]$IssuedAtUnix, [int64]$ExpiresAtUnix, [int64]$PreflightCreatedAtUnix) {
    $now = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if (
        $IssuedAtUnix -lt 0 -or
        $ExpiresAtUnix -lt $IssuedAtUnix -or
        ($ExpiresAtUnix - $IssuedAtUnix) -ne $ApprovalTtlSeconds -or
        $PreflightCreatedAtUnix -lt 0
    ) { return $false }
    if (
        ($IssuedAtUnix -gt $now -and ($IssuedAtUnix - $now) -gt 5) -or
        $now -gt $ExpiresAtUnix
    ) { return $false }
    if (
        ($PreflightCreatedAtUnix -gt $now -and ($PreflightCreatedAtUnix - $now) -gt 5) -or
        ($now -ge $PreflightCreatedAtUnix -and ($now - $PreflightCreatedAtUnix) -gt $ApprovalTtlSeconds)
    ) { return $false }
    return $true
}

function Assert-ApprovalWindowFresh {
    if (-not (Test-ApprovalWindowFresh $IntentApprovalIssuedAtUnix $IntentApprovalExpiresAtUnix $IntentPreflightCreatedAtUnix)) {
        Fail 'APPROVAL_WINDOW_EXPIRED_BEFORE_FLASH'
    }
}

function Write-TerminalNoAttempt([string]$Code) {
    if (
        $Mode -ne 'Execute' -or
        $null -eq $IntentStream -or
        $FlashBoundaryEntered -or
        $FlashAttempts -ne 0 -or
        $Code -notmatch '^[A-Z0-9_]{1,96}$' -or
        (Hash-Stream $IntentStream) -cne $ExpectedIntentInitialSha256
    ) { Fail 'TERMINAL_JOURNAL_PRECONDITION_FAILED' }
    $terminal = [ordered]@{
        approval_claim_sha256 = $ExpectedApprovalClaimSha256
        helper_sha256 = $ExpectedHelperSha256
        intent_initial_sha256 = $ExpectedIntentInitialSha256
        reason = $Code
        schema = 'lmi-p2-d114-userdata-intent-terminal/v1'
        state = 'HELPER_TERMINATED_BEFORE_FLASH_BOUNDARY'
    }
    $bytes = [System.Text.Encoding]::ASCII.GetBytes((($terminal | ConvertTo-Json -Compress -Depth 8) + "`n"))
    $IntentStream.Position = $IntentStream.Length
    $IntentStream.Write($bytes, 0, $bytes.Length)
    $IntentStream.Flush($true)
}

function Open-And-ValidateIntent($Profile, $IdentityPolicy) {
    if (
        $Mode -ne 'Execute' -or
        $ExpectedApprovalClaimSha256 -notmatch '^[0-9a-f]{64}$' -or
        $ExpectedIntentInitialSha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]::IsNullOrWhiteSpace($ExpectedNativeStagePath)
    ) { Fail 'INTENT_BINDING_MISSING' }
    $stream = [System.IO.File]::Open(
        [System.IO.Path]::GetFullPath($JournalPath),
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::Read
    )
    try {
        if ((Hash-Stream $stream) -cne $ExpectedIntentInitialSha256) { Fail 'INTENT_INITIAL_HASH_MISMATCH' }
        $intent = Read-JsonLocked $stream 'INTENT_JSON_INVALID'
        Require-ExactKeys $intent @('approval_claim_sha256', 'approval_window', 'candidate_source', 'command', 'created_at_unix', 'identity_policy_sha256', 'native_stage', 'preflight_created_at_unix', 'preflight_report_sha256', 'profile', 'schema', 'state') 'INTENT_FIELDS_MISMATCH'
        Require-ExactKeys $intent.approval_window @('expires_at_unix', 'issued_at_unix') 'INTENT_APPROVAL_WINDOW_FIELDS_MISMATCH'
        Require-ExactKeys $intent.candidate_source @('path', 'sha256', 'size') 'INTENT_CANDIDATE_FIELDS_MISMATCH'
        Require-ExactKeys $intent.native_stage @('acl_policy', 'path', 'sha256', 'size') 'INTENT_STAGE_FIELDS_MISMATCH'
        Require-ExactKeys $intent.profile @('id', 'sha256') 'INTENT_PROFILE_FIELDS_MISMATCH'
        if (
            $intent.schema -cne 'lmi-p2-d114-userdata-preattempt-intent/v5' -or
            $intent.state -cne 'PREAUTHORIZED_HELPER_MAY_START_ONCE' -or
            $intent.approval_claim_sha256 -cne $ExpectedApprovalClaimSha256 -or
            $intent.identity_policy_sha256 -cne [string]$Mapping.evidence.private_identity_policy.sha256 -or
            $intent.profile.id -cne [string]$Profile.profile_id -or
            $intent.profile.sha256 -cne $ExpectedProfileSha256 -or
            $intent.candidate_source.path -cne [string]$Profile.artifacts.candidate.path -or
            $intent.candidate_source.sha256 -cne [string]$Profile.artifacts.candidate.sha256 -or
            [int64]$intent.candidate_source.size -ne [int64]$Profile.artifacts.candidate.size -or
            $intent.native_stage.path -cne $ExpectedNativeStagePath -or
            $intent.native_stage.sha256 -cne [string]$Profile.artifacts.candidate.sha256 -or
            [int64]$intent.native_stage.size -ne [int64]$Profile.artifacts.candidate.size -or
            $intent.native_stage.acl_policy -cne [string]$DeployPolicy.native_staging.acl_policy -or
            (@($intent.command) -join "`n") -cne (@('-s', '<identity-policy-matched-device>', 'flash', 'userdata', $ExpectedNativeStagePath) -join "`n")
        ) { Fail 'INTENT_BINDING_MISMATCH' }
        try {
            $issued = [int64]$intent.approval_window.issued_at_unix
            $expires = [int64]$intent.approval_window.expires_at_unix
            $preflightCreated = [int64]$intent.preflight_created_at_unix
            $created = [int64]$intent.created_at_unix
        } catch { Fail 'INTENT_APPROVAL_WINDOW_INVALID' }
        if (
            $issued -lt 0 -or
            $expires -lt $issued -or
            ($expires - $issued) -ne $ApprovalTtlSeconds -or
            $preflightCreated -lt 0 -or
            $created -lt ($issued - 5) -or
            $created -gt $expires -or
            $preflightCreated -gt ($created + 5) -or
            ($created - $preflightCreated) -gt $ApprovalTtlSeconds
        ) { Fail 'INTENT_APPROVAL_WINDOW_INVALID' }
        Set-Variable -Name IntentApprovalIssuedAtUnix -Scope 1 -Value $issued
        Set-Variable -Name IntentApprovalExpiresAtUnix -Scope 1 -Value $expires
        Set-Variable -Name IntentPreflightCreatedAtUnix -Scope 1 -Value $preflightCreated
        $stream.Position = $stream.Length
        return $stream
    } catch {
        $stream.Dispose()
        throw
    }
}

function Assert-PrivateAcl([string]$Path, [bool]$Directory) {
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $inheritance = if ($Directory) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [System.Security.AccessControl.InheritanceFlags]::None }
    $actual = if ($Directory) { [System.IO.Directory]::GetAccessControl($Path) } else { [System.IO.File]::GetAccessControl($Path) }
    if (-not $actual.AreAccessRulesProtected -or $actual.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -cne $current.Value) { Fail 'NATIVE_STAGE_ACL_OWNER_OR_PROTECTION_MISMATCH' }
    $rules = @($actual.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { Fail 'NATIVE_STAGE_ACL_RULE_COUNT_MISMATCH' }
    $wanted = @($current.Value, $system.Value) | Sort-Object
    $observed = @()
    foreach ($rule in $rules) {
        if (
            $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne $inheritance -or
            $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None
        ) { Fail 'NATIVE_STAGE_ACL_RULE_MISMATCH' }
        $observed += $rule.IdentityReference.Value
    }
    if ((@($observed | Sort-Object) -join "`n") -cne ($wanted -join "`n")) { Fail 'NATIVE_STAGE_ACL_PRINCIPAL_MISMATCH' }
}

function Resolve-NativeCandidateStage($Profile) {
    $prefix = $NativeStagingRootSemantics + '/'
    $relative = if ($ExpectedNativeStagePath.StartsWith($prefix, [System.StringComparison]::Ordinal)) { $ExpectedNativeStagePath.Substring($prefix.Length) } else { '' }
    $parts = @($relative.Split('/'))
    $profileHash = if ($parts.Count -eq 3) { [string]$parts[0] } else { '' }
    $candidateHash = if ($parts.Count -eq 3) { [string]$parts[1] } else { '' }
    $leaf = if ($parts.Count -eq 3) { [string]$parts[2] } else { '' }
    if (
        $DeployPolicy.native_staging.acl_policy -cne 'protected-current-user-and-local-system-full-control-only' -or
        $DeployPolicy.native_staging.root_semantics -cne $NativeStagingRootSemantics -or
        $DeployPolicy.native_staging.filename -cne $leaf -or
        $profileHash -cne $ExpectedProfileSha256 -or
        $candidateHash -cne [string]$Profile.artifacts.candidate.sha256 -or
        $ExpectedNativeStagePath -cne ($NativeStagingRootSemantics + '/' + $ExpectedProfileSha256 + '/' + [string]$Profile.artifacts.candidate.sha256 + '/' + [string]$DeployPolicy.native_staging.filename)
    ) { Fail 'NATIVE_STAGE_PATH_POLICY_MISMATCH' }
    $local = Resolve-LocalAppDataRoot
    $base = [System.IO.Path]::Combine($local, 'lmi-p2-d114')
    $root = [System.IO.Path]::Combine($base, 'userdata-staging')
    $profileDirectory = [System.IO.Path]::Combine($root, $profileHash)
    $candidateDirectory = [System.IO.Path]::Combine($profileDirectory, $candidateHash)
    $stage = [System.IO.Path]::Combine($candidateDirectory, [string]$DeployPolicy.native_staging.filename)
    return [ordered]@{
        base = $base
        candidate_directory = $candidateDirectory
        path = $stage
        profile_directory = $profileDirectory
        root = $root
        semantics = $ExpectedNativeStagePath
    }
}

function Open-And-ValidatePreparedCandidate($Profile, [bool]$MayCreate) {
    $resolved = Resolve-NativeCandidateStage $Profile
    if ($MayCreate) {
        Ensure-ProtectedDirectory ([string]$resolved.base)
        Ensure-ProtectedDirectory ([string]$resolved.root)
        Ensure-ProtectedDirectory ([string]$resolved.profile_directory)
        if (-not [System.IO.Directory]::Exists([string]$resolved.candidate_directory)) {
            [void][System.IO.Directory]::CreateDirectory([string]$resolved.candidate_directory)
            Set-And-AssertPrivateAcl ([string]$resolved.candidate_directory) $true
            $output = [System.IO.File]::Open([string]$resolved.path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try {
                $Locked.candidate.Position = 0
                $Locked.candidate.CopyTo($output, 4MB)
                $output.Flush($true)
            } finally { $output.Dispose(); $Locked.candidate.Position = 0 }
            Set-And-AssertPrivateAcl ([string]$resolved.path) $false
        }
    }
    foreach ($directory in @($resolved.base, $resolved.root, $resolved.profile_directory, $resolved.candidate_directory)) {
        Assert-NativeNtfsDirectory ([string]$directory)
        Assert-PrivateAcl ([string]$directory) $true
    }
    $profileEntries = @([System.IO.Directory]::EnumerateFileSystemEntries([string]$resolved.profile_directory) | ForEach-Object { [System.IO.Path]::GetFileName($_) })
    if ($profileEntries.Count -ne 1 -or $profileEntries[0] -cne [string]$Profile.artifacts.candidate.sha256) { Fail 'NATIVE_STAGE_PROFILE_DIRECTORY_CONTENTS_MISMATCH' }
    $candidateEntries = @([System.IO.Directory]::EnumerateFileSystemEntries([string]$resolved.candidate_directory) | ForEach-Object { [System.IO.Path]::GetFileName($_) })
    if ($candidateEntries.Count -ne 1 -or $candidateEntries[0] -cne [string]$DeployPolicy.native_staging.filename) { Fail 'NATIVE_STAGE_CANDIDATE_DIRECTORY_CONTENTS_MISMATCH' }
    Assert-PrivateAcl ([string]$resolved.path) $false
    $Locked.native_stage = Open-ReadLocked ([string]$resolved.path) 'NATIVE_STAGE'
    Remember-LockedIdentity 'native_stage'
    $spec = [pscustomobject]@{ size = [int64]$Profile.artifacts.candidate.size; sha256 = [string]$Profile.artifacts.candidate.sha256 }
    Assert-LockedIdentity 'native_stage' $spec
    Assert-PrivateAcl ([string]$resolved.path) $false
    Set-Variable -Name NativeStagePath -Scope 1 -Value $ExpectedNativeStagePath
    return [string]$resolved.path
}

function Write-Result($Value) {
    $parent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($ResultPath))
    if (-not [System.IO.Directory]::Exists($parent)) { Fail "RESULT_DIRECTORY_MISSING" }
    $json = ($Value | ConvertTo-Json -Compress -Depth 12) + "`n"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($json)
    $stream = [System.IO.File]::Open(
        $ResultPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
    $encoded = [Convert]::ToBase64String($bytes)
    [Console]::Out.WriteLine($ResultPrefix + $encoded)
    [Console]::Out.Flush()
}

try {
    $Locked.profile = Open-ReadLocked ([System.IO.Path]::GetFullPath($ProfilePath)) 'PROFILE'
    Remember-LockedIdentity 'profile'
    if ((Hash-Stream $Locked.profile) -cne $ExpectedProfileSha256) { Fail "PROFILE_EXPECTED_HASH_MISMATCH" }
    try { $ExpectedArtifactHashes = $ExpectedArtifactHashesJson | ConvertFrom-Json } catch { Fail "EXPECTED_HASHES_JSON_INVALID" }
    $Profile = Read-JsonLocked $Locked.profile 'PROFILE_JSON_INVALID'
    Require-ExactKeys $Profile @('artifacts', 'compatibility', 'device', 'execution', 'fastboot', 'profile_id', 'schema') 'PROFILE_FIELDS_MISMATCH'
    Require-ExactKeys $Profile.artifacts @('assembly_attestation', 'candidate', 'candidate_raw', 'deploy_policy_lock', 'p2_injection_attestation', 'physical_mapping_evidence', 'rollback', 'source_lock') 'PROFILE_ARTIFACT_FIELDS_MISMATCH'
    Require-ExactKeys $Profile.execution @('automatic_retry', 'command', 'max_attempts', 'operation', 'partition', 'write_timeout_seconds') 'PROFILE_EXECUTION_FIELDS_MISMATCH'
    Require-ExactKeys $Profile.fastboot @('path', 'sha256', 'size') 'PROFILE_FASTBOOT_FIELDS_MISMATCH'
    if ($Profile.schema -cne $ProfileSchema) { Fail "PROFILE_SCHEMA_MISMATCH" }
    if (
        $Profile.fastboot.path -cne $FastbootPathSemantics -or
        [int64]$Profile.fastboot.size -ne $FastbootSize -or
        $Profile.fastboot.sha256 -cne $FastbootSha256 -or
        (@($Profile.execution.command) -join "`n") -cne (@('-s', '<identity-policy-matched-device>', 'flash', 'userdata', '<candidate-path>') -join "`n") -or
        $Profile.execution.operation -cne 'flash' -or
        $Profile.execution.partition -cne 'userdata' -or
        $Profile.execution.automatic_retry -ne $false -or
        [int]$Profile.execution.max_attempts -ne 1 -or
        [int]$Profile.execution.write_timeout_seconds -ne 300
    ) { Fail "PROFILE_EXECUTION_MISMATCH" }

    $allArtifactNames = @('candidate', 'candidate_raw', 'rollback', 'source_lock', 'assembly_attestation', 'deploy_policy_lock', 'p2_injection_attestation', 'physical_mapping_evidence')
    foreach ($name in $allArtifactNames) {
        $expected = [string]$ExpectedArtifactHashes.$name
        if ($expected -notmatch '^[0-9a-f]{64}$' -or $expected -cne [string]$Profile.artifacts.$name.sha256) { Fail 'EXPECTED_ARTIFACT_HASH_MISMATCH' }
    }
    $windowsArtifactNames = if ($Mode -eq 'Execute') {
        @('source_lock', 'assembly_attestation', 'deploy_policy_lock', 'p2_injection_attestation', 'physical_mapping_evidence')
    } else { $allArtifactNames }
    foreach ($name in $windowsArtifactNames) {
        $spec = $Profile.artifacts.$name
        $path = Resolve-RepoFile ([string]$spec.path) "PATH_$($name.ToUpperInvariant())"
        $Locked[$name] = Open-ReadLocked $path $name.ToUpperInvariant()
        Remember-LockedIdentity $name
        Assert-LockedIdentity $name $spec
    }
    foreach ($name in @('profile') + $windowsArtifactNames) {
        $expected = if ($name -eq 'profile') { $ExpectedProfileSha256 } else { [string]$ExpectedArtifactHashes.$name }
        if ($expected -notmatch '^[0-9a-f]{64}$' -or $expected -cne (Hash-Stream $Locked[$name])) { Fail "EXPECTED_ARTIFACT_HASH_MISMATCH" }
    }
    $DeployPolicy = Read-JsonLocked $Locked.deploy_policy_lock 'DEPLOY_POLICY_JSON_INVALID'
    Require-ExactKeys $DeployPolicy @('acquisition', 'fastboot', 'hardware_test_only', 'hardware_test_readiness', 'helper', 'native_staging', 'repo_bindings', 'schema', 'tool_staging') 'DEPLOY_POLICY_FIELDS_MISMATCH'
    Require-ExactKeys $DeployPolicy.acquisition @('archive', 'evidence', 'evidence_scope', 'schema') 'DEPLOY_POLICY_ACQUISITION_FIELDS_MISMATCH'
    Require-ExactKeys $DeployPolicy.acquisition.archive @('official_sha1', 'path', 'sha256', 'size', 'url') 'DEPLOY_POLICY_ARCHIVE_FIELDS_MISMATCH'
    Require-ExactKeys $DeployPolicy.fastboot @('authenticode', 'bundled_android_dll_closure', 'closure_scope', 'executable') 'DEPLOY_POLICY_FASTBOOT_FIELDS_MISMATCH'
    Require-ExactKeys $DeployPolicy.fastboot.authenticode @('applies_to', 'revocation_policy', 'runtime_gate', 'signer_leaf_certificate_sha256', 'signer_subject_cn') 'DEPLOY_POLICY_AUTHENTICODE_FIELDS_MISMATCH'
    Require-ExactKeys $DeployPolicy.fastboot.executable @('path', 'sha256', 'size') 'DEPLOY_POLICY_EXECUTABLE_FIELDS_MISMATCH'
    Require-ExactKeys $DeployPolicy.native_staging @('acl_policy', 'filename', 'identity_semantics', 'lifecycle', 'report_path_policy', 'root_semantics', 'volume_policy') 'DEPLOY_POLICY_STAGING_FIELDS_MISMATCH'
    Require-ExactKeys $DeployPolicy.tool_staging @('acl_policy', 'contents', 'reuse_policy', 'root_semantics', 'volume_policy') 'DEPLOY_POLICY_TOOL_STAGING_FIELDS_MISMATCH'
    Require-ExactKeys $DeployPolicy.hardware_test_readiness @('accepted_residual_risks', 'blocking_gates', 'closure_scope', 'production_claim', 'reproducibility_claim', 'status') 'DEPLOY_POLICY_READINESS_FIELDS_MISMATCH'
    Require-ExactKeys $DeployPolicy.repo_bindings @('apk_build_attestation', 'assembler', 'candidate_rebuild_lock', 'fastboot_windows_provenance_lock', 'injection_policy_lock', 'injector', 'injector_launcher', 'injector_runtime_lock', 'physical_userdata_mapping', 'public_key', 'sparse_tools_lock', 'userdata_deploy_profile_template') 'DEPLOY_POLICY_BINDING_FIELDS_MISMATCH'
    if (
        $DeployPolicy.schema -cne $DeployPolicySchema -or
        $DeployPolicy.hardware_test_only -ne $true -or
        $DeployPolicy.helper.sha256 -cne $ExpectedHelperSha256 -or
        $DeployPolicy.fastboot.executable.path -cne $FastbootPathSemantics -or
        [int64]$DeployPolicy.fastboot.executable.size -ne $FastbootSize -or
        $DeployPolicy.fastboot.executable.sha256 -cne $FastbootSha256 -or
        $DeployPolicy.fastboot.closure_scope -cne 'application-local-non-system-payload-only' -or
        $DeployPolicy.fastboot.authenticode.applies_to -cne 'all-three-extracted-members' -or
        $DeployPolicy.fastboot.authenticode.revocation_policy -cne 'online-entire-chain-no-ignore-flags-for-signer-and-timestamp' -or
        $DeployPolicy.fastboot.authenticode.runtime_gate -cne 'require-windows-status-valid-before-any-device-query' -or
        $DeployPolicy.fastboot.authenticode.signer_leaf_certificate_sha256 -cne $FastbootSignerLeafSha256 -or
        $DeployPolicy.fastboot.authenticode.signer_subject_cn -cne 'Google LLC' -or
        $DeployPolicy.acquisition.schema -cne 'lmi-d110-fastboot-official-acquisition/v1' -or
        $DeployPolicy.acquisition.evidence_scope -cne 'fastboot-exe-member-only-does-not-attest-the-two-dll-members' -or
        $DeployPolicy.acquisition.archive.official_sha1 -cne $FastbootArchiveOfficialSha1 -or
        $DeployPolicy.acquisition.archive.path -cne $FastbootArchiveRelativePath -or
        $DeployPolicy.acquisition.archive.sha256 -cne $FastbootArchiveSha256 -or
        [int64]$DeployPolicy.acquisition.archive.size -ne $FastbootArchiveSize -or
        $DeployPolicy.acquisition.archive.url -cne $FastbootArchiveUrl -or
        $DeployPolicy.native_staging.acl_policy -cne 'protected-current-user-and-local-system-full-control-only' -or
        $DeployPolicy.native_staging.filename -cne 'userdata.android-sparse.img' -or
        $DeployPolicy.native_staging.identity_semantics -cne 'profile-sha256/candidate-sha256/fixed-filename' -or
        $DeployPolicy.native_staging.lifecycle -cne 'preflight-prepare-or-reuse-execute-revalidate-only' -or
        $DeployPolicy.native_staging.report_path_policy -cne 'semantic-only-no-absolute-user-path' -or
        $DeployPolicy.native_staging.root_semantics -cne $NativeStagingRootSemantics -or
        $DeployPolicy.native_staging.volume_policy -cne 'fixed-ntfs-without-reparse-directory-ancestors' -or
        $DeployPolicy.tool_staging.acl_policy -cne 'protected-current-user-and-local-system-full-control-only' -or
        $DeployPolicy.tool_staging.root_semantics -cne $FastbootStagingRootSemantics -or
        $DeployPolicy.tool_staging.reuse_policy -cne 'reuse-only-after-full-revalidation-and-read-lock' -or
        $DeployPolicy.tool_staging.volume_policy -cne 'fixed-ntfs-without-reparse-directory-ancestors' -or
        (@($DeployPolicy.tool_staging.contents) -join "`n") -cne (@('AdbWinApi.dll', 'AdbWinUsbApi.dll', 'fastboot.exe') -join "`n") -or
        $DeployPolicy.repo_bindings.physical_userdata_mapping.path -cne 'config/lmi-p2-d114/physical-userdata-mapping.json' -or
        $DeployPolicy.repo_bindings.physical_userdata_mapping.sha256 -cne $Profile.artifacts.physical_mapping_evidence.sha256 -or
        [int64]$DeployPolicy.repo_bindings.physical_userdata_mapping.size -ne [int64]$Profile.artifacts.physical_mapping_evidence.size -or
        $DeployPolicy.repo_bindings.userdata_deploy_profile_template.path -cne 'config/lmi-p2-d114/userdata-deploy-profile.template.json'
    ) { Fail "DEPLOY_POLICY_MISMATCH" }
    if (
        $DeployPolicy.hardware_test_readiness.status -cne 'ready-for-explicitly-approved-hardware-test-only' -or
        @($DeployPolicy.hardware_test_readiness.blocking_gates).Count -ne 0 -or
        $DeployPolicy.hardware_test_readiness.closure_scope -cne 'application-local-non-system-payload-only' -or
        $DeployPolicy.hardware_test_readiness.production_claim -ne $false -or
        $DeployPolicy.hardware_test_readiness.reproducibility_claim -ne $false -or
        (@($DeployPolicy.hardware_test_readiness.accepted_residual_risks) -join "`n") -cne (@('official-exact-r37-source-commit-and-build-manifest-unavailable', 'windows-system-and-runtime-module-closure-not-attested') -join "`n")
    ) { Fail 'HARDWARE_TEST_READINESS_BLOCKED' }
    $expectedDlls = @(
        [ordered]@{ archive_member = 'platform-tools/AdbWinApi.dll'; filename = 'AdbWinApi.dll'; sha256 = '120bef587119c6cb926b86b9be90fdfbce38937588eae28cd91a94ce63c7b965'; size = 108184L },
        [ordered]@{ archive_member = 'platform-tools/AdbWinUsbApi.dll'; filename = 'AdbWinUsbApi.dll'; sha256 = '6ca69a2ca0e31309c087d288f058977d421ad03500e4c3e1dbd981241a069c60'; size = 73368L }
    )
    $actualDlls = @($DeployPolicy.fastboot.bundled_android_dll_closure)
    if ($actualDlls.Count -ne $expectedDlls.Count) { Fail 'FASTBOOT_DLL_CLOSURE_COUNT_MISMATCH' }
    for ($index = 0; $index -lt $expectedDlls.Count; $index += 1) {
        Require-ExactKeys $actualDlls[$index] @('archive_member', 'filename', 'sha256', 'size') 'FASTBOOT_DLL_CLOSURE_FIELDS_MISMATCH'
        if (
            [string]$actualDlls[$index].archive_member -cne [string]$expectedDlls[$index].archive_member -or
            [string]$actualDlls[$index].filename -cne [string]$expectedDlls[$index].filename -or
            [string]$actualDlls[$index].sha256 -cne [string]$expectedDlls[$index].sha256 -or
            [int64]$actualDlls[$index].size -ne [int64]$expectedDlls[$index].size
        ) { Fail 'FASTBOOT_DLL_CLOSURE_MISMATCH' }
    }
    $acquisitionPath = Resolve-RepoFile ([string]$DeployPolicy.acquisition.evidence.path) 'FASTBOOT_ACQUISITION_PATH'
    $Locked.fastboot_acquisition = Open-ReadLocked $acquisitionPath 'FASTBOOT_ACQUISITION'
    Remember-LockedIdentity 'fastboot_acquisition'
    if ($Locked.fastboot_acquisition.Length -ne [int64]$DeployPolicy.acquisition.evidence.size -or (Hash-Stream $Locked.fastboot_acquisition) -cne [string]$DeployPolicy.acquisition.evidence.sha256) { Fail "FASTBOOT_ACQUISITION_IDENTITY_MISMATCH" }
    $Acquisition = Read-JsonLocked $Locked.fastboot_acquisition 'FASTBOOT_ACQUISITION_JSON_INVALID'
    Require-ExactKeys $Acquisition @('archive', 'device_action_performed', 'installed_copy', 'member', 'observed_local_date', 'repository_metadata', 'schema') 'FASTBOOT_ACQUISITION_FIELDS_MISMATCH'
    Require-ExactKeys $Acquisition.archive @('filename', 'sha1', 'sha256', 'size', 'url') 'FASTBOOT_ACQUISITION_ARCHIVE_FIELDS_MISMATCH'
    Require-ExactKeys $Acquisition.member @('path', 'sha256', 'size') 'FASTBOOT_ACQUISITION_MEMBER_FIELDS_MISMATCH'
    Require-ExactKeys $Acquisition.installed_copy @('byte_identical_to_archive_member', 'path', 'sha256', 'size') 'FASTBOOT_ACQUISITION_COPY_FIELDS_MISMATCH'
    Require-ExactKeys $Acquisition.repository_metadata @('package', 'url') 'FASTBOOT_ACQUISITION_REPOSITORY_FIELDS_MISMATCH'
    if (
        $Acquisition.schema -cne [string]$DeployPolicy.acquisition.schema -or
        $Acquisition.archive.filename -cne 'platform-tools_r37.0.0-win.zip' -or
        $Acquisition.archive.sha1 -cne [string]$DeployPolicy.acquisition.archive.official_sha1 -or
        $Acquisition.archive.sha256 -cne [string]$DeployPolicy.acquisition.archive.sha256 -or
        [int64]$Acquisition.archive.size -ne [int64]$DeployPolicy.acquisition.archive.size -or
        $Acquisition.archive.url -cne [string]$DeployPolicy.acquisition.archive.url -or
        $Acquisition.device_action_performed -ne $false -or
        $Acquisition.observed_local_date -cne '2026-07-20' -or
        $Acquisition.repository_metadata.package -cne 'platform-tools 37.0.0 Windows' -or
        $Acquisition.repository_metadata.url -cne 'https://dl.google.com/android/repository/repository2-3.xml' -or
        $Acquisition.member.path -cne 'platform-tools/fastboot.exe' -or
        $Acquisition.member.sha256 -cne $FastbootSha256 -or
        [int64]$Acquisition.member.size -ne $FastbootSize -or
        $Acquisition.installed_copy.sha256 -cne $FastbootSha256 -or
        [int64]$Acquisition.installed_copy.size -ne $FastbootSize -or
        $Acquisition.installed_copy.byte_identical_to_archive_member -ne $true
    ) { Fail "FASTBOOT_ACQUISITION_BINDING_MISMATCH" }
    foreach ($property in @($DeployPolicy.repo_bindings.PSObject.Properties)) {
        $name = 'policy_' + $property.Name
        $spec = $property.Value
        $Locked[$name] = Open-ReadLocked (Resolve-RepoFile ([string]$spec.path) 'POLICY_BINDING_PATH') $name.ToUpperInvariant()
        Remember-LockedIdentity $name
        if ($Locked[$name].Length -ne [int64]$spec.size -or (Hash-Stream $Locked[$name]) -cne [string]$spec.sha256) { Fail "POLICY_BINDING_IDENTITY_MISMATCH" }
    }
    $Provenance = Read-JsonLocked $Locked.policy_fastboot_windows_provenance_lock 'FASTBOOT_PROVENANCE_JSON_INVALID'
    Require-ExactKeys $Provenance @('accepted_residual_risks', 'archive', 'authenticode', 'closure_scope', 'limitations', 'members', 'official_repository_metadata', 'pe_closure', 'schema') 'FASTBOOT_PROVENANCE_FIELDS_MISMATCH'
    Require-ExactKeys $Provenance.archive @('filename', 'locally_derived_sha256', 'retained_path', 'size', 'url', 'zip_validation') 'FASTBOOT_PROVENANCE_ARCHIVE_FIELDS_MISMATCH'
    Require-ExactKeys $Provenance.archive.zip_validation @('allowed_compression_methods', 'case_collisions', 'duplicate_paths', 'encrypted_entries', 'entry_count', 'path_traversal_entries', 'unsupported_entries') 'FASTBOOT_PROVENANCE_ZIP_FIELDS_MISMATCH'
    Require-ExactKeys $Provenance.closure_scope @('asserted', 'production_claim', 'reproducibility_claim', 'windows_system_modules_in_scope') 'FASTBOOT_PROVENANCE_SCOPE_FIELDS_MISMATCH'
    if (
        $Provenance.schema -cne 'lmi-p2-d114-fastboot-windows-provenance/v2' -or
        $Provenance.archive.locally_derived_sha256 -cne $FastbootArchiveSha256 -or
        $Provenance.archive.retained_path -cne $FastbootArchiveRelativePath -or
        [int64]$Provenance.archive.size -ne $FastbootArchiveSize -or
        $Provenance.archive.url -cne $FastbootArchiveUrl -or
        [int]$Provenance.archive.zip_validation.entry_count -ne $FastbootArchiveEntryCount -or
        (@($Provenance.archive.zip_validation.allowed_compression_methods) -join "`n") -cne (@('store', 'deflate') -join "`n") -or
        $Provenance.archive.zip_validation.case_collisions -ne $false -or
        $Provenance.archive.zip_validation.duplicate_paths -ne $false -or
        $Provenance.archive.zip_validation.encrypted_entries -ne $false -or
        $Provenance.archive.zip_validation.path_traversal_entries -ne $false -or
        $Provenance.archive.zip_validation.unsupported_entries -ne $false -or
        $Provenance.official_repository_metadata.archive_checksum -cne $FastbootArchiveOfficialSha1 -or
        $Provenance.official_repository_metadata.archive_checksum_type -cne 'sha1' -or
        $Provenance.official_repository_metadata.official_sha256_found -ne $false -or
        $Provenance.official_repository_metadata.detached_archive_signature_found -ne $false -or
        $Provenance.authenticode.static_validation_status -cne 'unverified' -or
        $Provenance.authenticode.runtime_revocation_policy -cne 'online-entire-chain-no-ignore-flags-for-signer-and-timestamp' -or
        $Provenance.authenticode.runtime_gate -cne 'require-windows-status-valid-before-any-device-query' -or
        $Provenance.authenticode.signer_leaf_certificate_sha256 -cne $FastbootSignerLeafSha256 -or
        $Provenance.authenticode.signer_subject_cn -cne 'Google LLC' -or
        $Provenance.closure_scope.asserted -cne 'application-local-non-system-payload-only' -or
        $Provenance.closure_scope.production_claim -ne $false -or
        $Provenance.closure_scope.reproducibility_claim -ne $false -or
        $Provenance.closure_scope.windows_system_modules_in_scope -ne $false -or
        (@($Provenance.accepted_residual_risks) -join "`n") -cne (@('official-exact-r37-source-commit-and-build-manifest-unavailable', 'windows-system-and-runtime-module-closure-not-attested') -join "`n") -or
        @($Provenance.limitations).Count -ne 3 -or
        (@($Provenance.pe_closure.runtime_bundled_dll_closure) -join "`n") -cne (@('AdbWinApi.dll', 'AdbWinUsbApi.dll') -join "`n") -or
        (@($Provenance.pe_closure.'fastboot.exe'.non_system_static_imports) -join "`n") -cne 'AdbWinApi.dll' -or
        $Provenance.pe_closure.'AdbWinApi.dll'.dynamic_edge.target -cne 'AdbWinUsbApi.dll'
    ) { Fail 'FASTBOOT_PROVENANCE_BINDING_MISMATCH' }
    $provenanceMembers = @($Provenance.members)
    $expectedMembers = @(
        [ordered]@{ path = 'platform-tools/fastboot.exe'; sha256 = $FastbootSha256; size = $FastbootSize },
        [ordered]@{ path = 'platform-tools/AdbWinApi.dll'; sha256 = [string]$expectedDlls[0].sha256; size = [int64]$expectedDlls[0].size },
        [ordered]@{ path = 'platform-tools/AdbWinUsbApi.dll'; sha256 = [string]$expectedDlls[1].sha256; size = [int64]$expectedDlls[1].size }
    )
    if ($provenanceMembers.Count -ne $expectedMembers.Count) { Fail 'FASTBOOT_PROVENANCE_MEMBER_COUNT_MISMATCH' }
    for ($index = 0; $index -lt $expectedMembers.Count; $index += 1) {
        Require-ExactKeys $provenanceMembers[$index] @('path', 'sha256', 'size') 'FASTBOOT_PROVENANCE_MEMBER_FIELDS_MISMATCH'
        if (
            [string]$provenanceMembers[$index].path -cne [string]$expectedMembers[$index].path -or
            [string]$provenanceMembers[$index].sha256 -cne [string]$expectedMembers[$index].sha256 -or
            [int64]$provenanceMembers[$index].size -ne [int64]$expectedMembers[$index].size
        ) { Fail 'FASTBOOT_PROVENANCE_MEMBER_MISMATCH' }
    }
    # Archive identity, ZIP structure, extraction, three-file staging closure,
    # read locks, and online Authenticode validation all complete before the
    # first possible Invoke-Fastboot call below.
    Initialize-RuntimeFastboot
    if ($Mode -ne 'Execute') {
        $bundlePaths = @(
            $Locked.candidate_raw.Name,
            $Locked.candidate.Name,
            $Locked.assembly_attestation.Name,
            $Locked.p2_injection_attestation.Name
        )
        $bundleParents = @($bundlePaths | ForEach-Object { [System.IO.Path]::GetDirectoryName($_) } | Select-Object -Unique)
        $bundleLeaves = @($bundlePaths | ForEach-Object { [System.IO.Path]::GetFileName($_) } | Sort-Object)
        $wantedLeaves = @('assembly-attestation.json', 'injection-attestation.json', 'userdata.android-sparse.img', 'userdata.raw')
        if ($bundleParents.Count -ne 1 -or ($bundleLeaves -join "`n") -cne ($wantedLeaves -join "`n")) { Fail "CANDIDATE_BUNDLE_MISMATCH" }
        $actualLeaves = @([System.IO.Directory]::EnumerateFileSystemEntries($bundleParents[0]) | ForEach-Object { [System.IO.Path]::GetFileName($_) } | Sort-Object)
        if (($actualLeaves -join "`n") -cne ($wantedLeaves -join "`n")) { Fail "CANDIDATE_BUNDLE_CONTENTS_MISMATCH" }
    }
    $Mapping = Read-JsonLocked $Locked.physical_mapping_evidence 'MAPPING_JSON_INVALID'
    Require-ExactKeys $Mapping @('cross_bindings', 'evidence', 'identity_binding', 'override', 'schema', 'userdata') 'MAPPING_FIELDS_MISMATCH'
    Require-ExactKeys $Mapping.userdata @(
        'backup_gpt_entries',
        'backup_gpt_header_lba',
        'block_device',
        'block_major',
        'block_minor',
        'by_name_path',
        'by_name_target',
        'by_partlabel_path',
        'by_partlabel_target',
        'capacity_bytes',
        'disk_sector_count',
        'gpt_logical_sector_size',
        'last_lba',
        'loop_backing_device',
        'partlabel',
        'partition_entry_count',
        'partition_entry_size',
        'reported_512_byte_sectors'
    ) 'MAPPING_USERDATA_FIELDS_MISMATCH'
    Require-ExactKeys $Mapping.userdata.backup_gpt_entries @('first_lba', 'last_lba', 'sector_count') 'MAPPING_BACKUP_GPT_ENTRIES_FIELDS_MISMATCH'
    $mappingCapacity = Require-PositiveJsonUInt64 $Mapping.userdata.capacity_bytes 'MAPPING_CAPACITY_INVALID'
    $mappingSectorSize = Require-PositiveJsonUInt64 $Mapping.userdata.gpt_logical_sector_size 'MAPPING_SECTOR_SIZE_INVALID'
    $mappingDiskSectorCount = Require-PositiveJsonUInt64 $Mapping.userdata.disk_sector_count 'MAPPING_DISK_SECTOR_COUNT_INVALID'
    $mappingLastLba = Require-PositiveJsonUInt64 $Mapping.userdata.last_lba 'MAPPING_LAST_LBA_INVALID'
    $mappingBackupHeaderLba = Require-PositiveJsonUInt64 $Mapping.userdata.backup_gpt_header_lba 'MAPPING_BACKUP_HEADER_LBA_INVALID'
    $mappingEntryCount = Require-PositiveJsonUInt64 $Mapping.userdata.partition_entry_count 'MAPPING_ENTRY_COUNT_INVALID'
    $mappingEntrySize = Require-PositiveJsonUInt64 $Mapping.userdata.partition_entry_size 'MAPPING_ENTRY_SIZE_INVALID'
    $mappingBackupFirstLba = Require-PositiveJsonUInt64 $Mapping.userdata.backup_gpt_entries.first_lba 'MAPPING_BACKUP_FIRST_LBA_INVALID'
    $mappingBackupLastLba = Require-PositiveJsonUInt64 $Mapping.userdata.backup_gpt_entries.last_lba 'MAPPING_BACKUP_LAST_LBA_INVALID'
    $mappingBackupSectorCount = Require-PositiveJsonUInt64 $Mapping.userdata.backup_gpt_entries.sector_count 'MAPPING_BACKUP_SECTOR_COUNT_INVALID'
    $mappingReported512Sectors = Require-PositiveJsonUInt64 $Mapping.userdata.reported_512_byte_sectors 'MAPPING_REPORTED_SECTORS_INVALID'
    # PowerShell arithmetic division produces Double and real-to-integer casts
    # round instead of truncate.  Keep all geometry arithmetic exact so the
    # ceil division and UInt64 overflow boundaries cannot change by rounding.
    $mappingUInt64MaxBig = [System.Numerics.BigInteger]([uint64]::MaxValue)
    $mappingEntryCountBig = [System.Numerics.BigInteger]$mappingEntryCount
    $mappingEntrySizeBig = [System.Numerics.BigInteger]$mappingEntrySize
    $mappingSectorSizeBig = [System.Numerics.BigInteger]$mappingSectorSize
    $mappingEntryBytesBig = $mappingEntryCountBig * $mappingEntrySizeBig
    if ($mappingEntryBytesBig -gt $mappingUInt64MaxBig) { Fail 'MAPPING_ENTRY_GEOMETRY_OVERFLOW' }
    $mappingEntryBytes = [uint64]$mappingEntryBytesBig
    $mappingEntrySectorsBig = [System.Numerics.BigInteger]::Divide(
        ($mappingEntryBytesBig + $mappingSectorSizeBig - [System.Numerics.BigInteger]::One),
        $mappingSectorSizeBig
    )
    if ($mappingEntrySectorsBig -gt $mappingUInt64MaxBig) { Fail 'MAPPING_ENTRY_GEOMETRY_OVERFLOW' }
    $mappingEntrySectors = [uint64]$mappingEntrySectorsBig
    $mappingCapacityBig = [System.Numerics.BigInteger]$mappingCapacity
    $mappingCapacitySectors = [uint64]([System.Numerics.BigInteger]::Divide($mappingCapacityBig, $mappingSectorSizeBig))
    $mappingReportedBytesBig = [System.Numerics.BigInteger]$mappingReported512Sectors * [System.Numerics.BigInteger]512
    if ($mappingReportedBytesBig -gt $mappingUInt64MaxBig) { Fail 'MAPPING_ENTRY_GEOMETRY_OVERFLOW' }
    $mappingReportedBytes = [uint64]$mappingReportedBytesBig
    if (
        $Mapping.schema -cne $MappingSchema -or
        $mappingCapacity -ne 114898743296L -or
        $mappingSectorSize -ne 4096L -or
        ($mappingCapacity % $mappingSectorSize) -ne 0 -or
        $mappingDiskSectorCount -ne $mappingCapacitySectors -or
        $mappingDiskSectorCount -ne 28051451L -or
        $mappingLastLba -ne ($mappingDiskSectorCount - 1) -or
        $mappingLastLba -ne 28051450L -or
        $mappingBackupHeaderLba -ne $mappingLastLba -or
        $mappingEntryCount -ne 128L -or
        $mappingEntrySize -ne 128L -or
        $mappingBackupSectorCount -ne $mappingEntrySectors -or
        $mappingBackupSectorCount -ne 4L -or
        $mappingBackupLastLba -ne ($mappingBackupHeaderLba - 1) -or
        $mappingBackupLastLba -ne 28051449L -or
        $mappingBackupFirstLba -ne ($mappingBackupHeaderLba - $mappingEntrySectors) -or
        $mappingBackupFirstLba -ne 28051446L -or
        ($mappingBackupLastLba - $mappingBackupFirstLba + 1) -ne $mappingBackupSectorCount -or
        $mappingReported512Sectors -ne 224411608L -or
        $mappingReportedBytes -ne $mappingCapacity
    ) { Fail "MAPPING_GEOMETRY_MISMATCH" }
    foreach ($name in @('d198_contract', 'd198_write_report', 'd199_preflight_report', 'd199_replug_attestation', 'private_identity_policy', 'runtime_storage_log')) {
        $spec = $Mapping.evidence.$name
        $path = Resolve-RepoFile ([string]$spec.path) "PATH_EVIDENCE_$($name.ToUpperInvariant())"
        $key = "mapping_$name"
        $Locked[$key] = Open-ReadLocked $path $key.ToUpperInvariant()
        Remember-LockedIdentity $key
        if ($Locked[$key].Length -ne [int64]$spec.size -or (Hash-Stream $Locked[$key]) -cne [string]$spec.sha256) { Fail "MAPPING_EVIDENCE_IDENTITY_MISMATCH" }
    }
    $IdentityPolicy = Read-JsonLocked $Locked.mapping_private_identity_policy 'IDENTITY_POLICY_INVALID'
    if ($IdentityPolicy.schema -cne 'lmi-d110-recovery-policy/v2' -or $IdentityPolicy.device.product -cne 'lmi') { Fail "IDENTITY_POLICY_MISMATCH" }

    $lockPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "lmi-p2-d114-userdata-device.lock")
    try {
        $LockStream = [System.IO.File]::Open(
            $lockPath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )
    } catch {
        Fail "DEVICE_LOCK_BUSY"
    }

    if ($Mode -eq 'Execute') {
        # Owning this sole writer handle is the durable helper lease.  Only a
        # helper that acquired it may later certify terminal/no-attempt state.
        $IntentStream = Open-And-ValidateIntent $Profile $IdentityPolicy
        $candidatePath = Open-And-ValidatePreparedCandidate $Profile $false
    } elseif ($Mode -eq 'Preflight') {
        # The expensive repository audit and candidate copy/reuse complete
        # before the first device query.  The report is publishable only while
        # this exact prepared candidate remains read-locked.
        $candidatePath = Open-And-ValidatePreparedCandidate $Profile $true
    }
    $serial = Check-Device $Profile $IdentityPolicy $Mapping
    if ($Mode -eq 'Preflight') {
        $Route = 'PREFLIGHT_PASSED_NO_STATE_CHANGE'
    } elseif ($Mode -eq 'Postwrite') {
        $Route = 'POSTWRITE_DEVICE_REVALIDATED_NO_STATE_CHANGE'
    } else {
        $immediateSerial = Check-Device $Profile $IdentityPolicy $Mapping
        if ($immediateSerial -cne $serial) { Fail 'PREWRITE_DEVICE_CHANGED' }
        $transition = [ordered]@{
            approval_claim_sha256 = $ExpectedApprovalClaimSha256
            containment_confirmed = $true
            identity_match = $true
            native_stage_path_semantics = $ExpectedNativeStagePath
            schema = 'lmi-p2-d114-userdata-intent-transition/v1'
            snapshot_identity_confirmed = $true
            state = 'ATTEMPT_STARTING_CONSERVATIVE'
        }
        $transitionBytes = [System.Text.Encoding]::ASCII.GetBytes((($transition | ConvertTo-Json -Compress -Depth 8) + "`n"))
        # Execute only revalidated the already-prepared fixed-NTFS candidate;
        # no WSL large artifact was opened or copied in this mode.  The native
        # runner repeats the UTC check around the durable transition.
        Assert-ApprovalWindowFresh
        $FlashBoundaryEntered = $true
        $write = Invoke-Fastboot @('-s', $serial, 'flash', 'userdata', $candidatePath) $WriteTimeoutMs $IntentStream $transitionBytes $IntentApprovalIssuedAtUnix $IntentApprovalExpiresAtUnix $IntentPreflightCreatedAtUnix
        $FlashAttempts = if ($write.transition_durable -or $write.started) { 1 } else { 0 }
        $AttemptJournalDurable = [bool]$write.transition_durable
        $FlashAssignmentConfirmed = [bool]$write.assignment_confirmed
        $FlashStarted = [bool]$write.started
        $FlashExit = $write.exit_code
        $FlashTimedOut = [bool]$write.timed_out
        $FlashTreeQuiescent = [bool]$write.tree_quiescent
        if (-not $write.timed_out -and $write.started -and $write.assignment_confirmed -and $write.tree_quiescent -and $null -eq $write.failure_code) {
            $sending = @($write.output -split "`n" | Where-Object { $_ -match '^Sending(?: sparse)?\s+''userdata''' })
            $writing = @($write.output -split "`n" | Where-Object { $_ -match '^Writing\s+''userdata''' })
            $FlashSendingOkay = @($sending | Where-Object { $_ -match '\sOKAY(?:\s|\[|$)' }).Count
            $FlashWritingOkay = @($writing | Where-Object { $_ -match '\sOKAY(?:\s|\[|$)' }).Count
            $finished = @([regex]::Matches($write.output, '(?m)^Finished\. Total time: [0-9]+(?:\.[0-9]+)?s\s*$')).Count
            $TransportCompleted = (
                $write.exit_code -eq 0 -and
                $finished -eq 1 -and
                $sending.Count -ge 1 -and
                $writing.Count -ge 1 -and
                $FlashWritingOkay -eq $writing.Count -and
                $FlashSendingOkay -eq $sending.Count -and
                $write.output -notmatch '(?im)^FAILED'
            )
        }
        if ($TransportCompleted) {
            try {
                $afterSerial = Check-Device $Profile $IdentityPolicy $Mapping
                if ($afterSerial -cne $serial) { Fail "POSTWRITE_DEVICE_CHANGED" }
                $Route = 'USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATED'
            } catch {
                $Route = 'USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING'
                $Reason = 'DEVICE_REVALIDATION_UNAVAILABLE_OR_MISMATCH'
            }
        } elseif ($FlashAttempts -eq 0) {
            $Route = 'REFUSED_NO_STATE_CHANGE'
            $Reason = if ($null -ne $write.failure_code) { [string]$write.failure_code } else { 'PROCESS_NOT_STARTED' }
        } else {
            $Route = 'WRITE_ATTEMPTED_RESULT_UNKNOWN'
            $Reason = if ($FlashTimedOut) { 'PROCESS_TREE_TIMEOUT_SAME_CLAIM_CONSUMED' } elseif (-not $FlashTreeQuiescent) { 'PROCESS_TREE_QUIESCENCE_UNPROVEN_SAME_CLAIM_CONSUMED' } else { 'TRANSPORT_TRANSCRIPT_INCOMPLETE_SAME_CLAIM_CONSUMED' }
        }
    }
} catch [System.InvalidOperationException] {
    if ($null -eq $Reason) { $Reason = $_.Exception.Message }
    if ($FlashAttempts -eq 0) { $Route = 'REFUSED_NO_STATE_CHANGE' }
    else { $Route = 'WRITE_ATTEMPTED_RESULT_UNKNOWN' }
} catch {
    if ($null -eq $Reason) { $Reason = 'UNEXPECTED_HELPER_FAILURE' }
    if ($FlashAttempts -eq 0) { $Route = 'REFUSED_NO_STATE_CHANGE' }
    else { $Route = 'WRITE_ATTEMPTED_RESULT_UNKNOWN' }
} finally {
    $postHashes = @{}
    foreach ($name in @($Locked.Keys)) {
        try {
            $postHashes[$name] = Assert-LockedStillSame $name
        } catch {
            $LockedInputsIntact = $false
            $postHashes[$name] = [string]$LockedMetadata[$name].sha256
        }
    }
    if (-not $LockedInputsIntact) {
        $Reason = 'POST_LOCKED_INPUT_IDENTITY_MISMATCH'
        if ($FlashAttempts -eq 0) { $Route = 'REFUSED_NO_STATE_CHANGE' }
        elseif ($TransportCompleted) { $Route = 'USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING' }
        else { $Route = 'WRITE_ATTEMPTED_RESULT_UNKNOWN' }
    }
    if ($Mode -eq 'Execute' -and $null -ne $IntentStream -and -not $FlashBoundaryEntered -and $FlashAttempts -eq 0) {
        Write-TerminalNoAttempt $Reason
    }
    $artifactHashes = [ordered]@{}
    if ($Locked.ContainsKey('profile')) {
        $artifactHashes.profile = $postHashes.profile
    }
    foreach ($name in @('assembly_attestation', 'candidate', 'candidate_raw', 'deploy_policy_lock', 'p2_injection_attestation', 'physical_mapping_evidence', 'rollback', 'source_lock')) {
        if ($Locked.ContainsKey($name)) {
            $artifactHashes[$name] = $postHashes[$name]
        } else {
            $artifactHashes[$name] = [string]$ExpectedArtifactHashes.$name
        }
    }
    $result = [ordered]@{
        approval_claim_sha256 = if ($Mode -eq 'Execute') { $ExpectedApprovalClaimSha256 } else { $null }
        artifact_hashes = $artifactHashes
        attempt_journal_durable = $AttemptJournalDurable
        device = $Device
        flash = [ordered]@{
            assignment_confirmed = $FlashAssignmentConfirmed
            attempts = $FlashAttempts
            exit_code = $FlashExit
            sending_okay = $FlashSendingOkay
            started = $FlashStarted
            timed_out = $FlashTimedOut
            transport_completed = $TransportCompleted
            tree_quiescent = $FlashTreeQuiescent
            writing_okay = $FlashWritingOkay
        }
        intent_initial_sha256 = if ($Mode -eq 'Execute') { $ExpectedIntentInitialSha256 } else { $null }
        locked_inputs_intact = $LockedInputsIntact
        mode = $Mode
        native_stage = if ($null -ne $NativeStagePath) {
            [ordered]@{
                acl_verified = $true
                deny_write_delete_handle_held = $Locked.ContainsKey('native_stage')
                path_semantics = $NativeStagePath
                sha256 = [string]$Profile.artifacts.candidate.sha256
                size = [int64]$Profile.artifacts.candidate.size
            }
        } else { $null }
        reason = $Reason
        recovered_from_intent_journal = $false
        route_status = $Route
        schema = $ResultSchema
        windows_validation_scope = if ($Mode -eq 'Execute') {
            'small-repository-contract-and-prepared-candidate'
        } elseif ($Mode -eq 'Preflight') {
            'full-repository-artifacts-and-prepared-candidate'
        } else {
            'full-repository-artifacts'
        }
    }
    try { Write-Result $result } catch {}
    if ($null -ne $IntentStream) { try { $IntentStream.Dispose() } catch {} }
    foreach ($entry in @($Locked.GetEnumerator())) {
        try { $entry.Value.Dispose() } catch {}
    }
    if ($null -ne $LockStream) { try { $LockStream.Dispose() } catch {} }
}

if ($Route -eq 'REFUSED_NO_STATE_CHANGE') { exit 2 }
if ($Route -eq 'USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING' -or $Route -eq 'WRITE_ATTEMPTED_RESULT_UNKNOWN') { exit 3 }
exit 0
