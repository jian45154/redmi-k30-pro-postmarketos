param(
    [Parameter(Mandatory = $true)]
    [string]$ContractJsonBase64
)

# Strictly read-only postwrite device revalidation.  The WSL caller owns and
# rechecks the small profile/report/mapping/identity/provenance locks.  This
# helper locks only the existing three-file official fastboot closure and runs
# one fixed devices query followed by ten fixed getvar queries.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$InputSchema = 'lmi-p2-d114-postwrite-helper-input/v1'
$ResultSchema = 'lmi-p2-d114-postwrite-powershell-result/v1'
$ResultPrefix = 'LMI_P2_D114_POSTWRITE_RESULT_JSON_BASE64='
$QueryTimeoutMs = 10000
$Locked = @{}
$LockedMetadata = @{}
$FastbootPath = $null
$DeviceLockStream = $null
$LockedInputsIntact = $false
$Reason = $null
$Route = 'REFUSED_NO_STATE_CHANGE'
$QueriesAttempted = [System.Collections.Generic.List[string]]::new()
$QueriesCompleted = [System.Collections.Generic.List[string]]::new()
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
    if ($Code -notmatch '^[A-Z0-9_]{1,96}$') { throw 'UNSAFE_INTERNAL_CODE' }
    throw [System.InvalidOperationException]::new($Code)
}

function Require-ExactKeys($Object, [string[]]$Keys, [string]$Code) {
    if ($null -eq $Object) { Fail $Code }
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Keys | Sort-Object)
    if (($actual -join "`n") -cne ($wanted -join "`n")) { Fail $Code }
}

function Hash-Stream([System.IO.FileStream]$Stream) {
    $position = $Stream.Position
    try {
        $Stream.Position = 0
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant()
        } finally { $sha.Dispose() }
    } finally { $Stream.Position = $position }
}

function Assert-PrivateAcl([string]$Path, [bool]$Directory) {
    try {
        $attributes = [System.IO.File]::GetAttributes($Path)
        if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { Fail 'FASTBOOT_REPARSE_POINT_FORBIDDEN' }
        $acl = Get-Acl -LiteralPath $Path
        $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
        if ($owner -ne $current -or -not $acl.AreAccessRulesProtected) { Fail 'FASTBOOT_ACL_NOT_PRIVATE' }
        $rules = @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
        if ($rules.Count -ne 2) { Fail 'FASTBOOT_ACL_NOT_PRIVATE' }
        foreach ($rule in $rules) {
            if (
                $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
                ($rule.IdentityReference -ne $current -and $rule.IdentityReference -ne $system) -or
                (($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne [System.Security.AccessControl.FileSystemRights]::FullControl)
            ) { Fail 'FASTBOOT_ACL_NOT_PRIVATE' }
        }
        if (-not $Directory -and -not [System.IO.File]::Exists($Path)) { Fail 'FASTBOOT_MEMBER_MISSING' }
        if ($Directory -and -not [System.IO.Directory]::Exists($Path)) { Fail 'FASTBOOT_DIRECTORY_MISSING' }
    } catch [System.InvalidOperationException] { throw } catch { Fail 'FASTBOOT_ACL_INSPECTION_FAILED' }
}

function Open-ReadLocked([string]$Path, [string]$Name, [int64]$Size, [string]$Sha256) {
    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
    } catch { Fail 'FASTBOOT_MEMBER_LOCK_FAILED' }
    try {
        if ($stream.Length -ne $Size -or (Hash-Stream $stream) -cne $Sha256) { Fail 'FASTBOOT_MEMBER_IDENTITY_MISMATCH' }
        $info = [System.IO.FileInfo]::new($stream.Name)
        $Locked[$Name] = $stream
        $LockedMetadata[$Name] = [ordered]@{
            creation_ticks = $info.CreationTimeUtc.Ticks
            length = $info.Length
            sha256 = $Sha256
            write_ticks = $info.LastWriteTimeUtc.Ticks
        }
    } catch {
        $stream.Dispose()
        throw
    }
}

function Assert-LockedStillSame([string]$Name) {
    $stream = $Locked[$Name]
    $before = $LockedMetadata[$Name]
    $info = [System.IO.FileInfo]::new($stream.Name)
    if (
        $stream.Length -ne [int64]$before.length -or
        $info.Length -ne [int64]$before.length -or
        $info.CreationTimeUtc.Ticks -ne [int64]$before.creation_ticks -or
        $info.LastWriteTimeUtc.Ticks -ne [int64]$before.write_ticks -or
        (Hash-Stream $stream) -cne [string]$before.sha256 -or
        (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    ) { Fail 'FASTBOOT_MEMBER_POST_IDENTITY_MISMATCH' }
}

function Parse-UInt64([string]$Value, [string]$Code) {
    try {
        if ($Value -match '^0[xX][0-9a-fA-F]+$') { return [Convert]::ToUInt64($Value.Substring(2), 16) }
        if ($Value -match '^[0-9]+$') { return [Convert]::ToUInt64($Value, 10) }
    } catch {}
    Fail $Code
}

function Device-Identity([string]$Nonce, [string]$Serial) {
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Nonce + [char]0 + $Serial)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
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

# This is the same suspended-process/job-object containment used by the locked
# deploy helper.  Every child is assigned before resume; kill-on-close and
# explicit active-process accounting make tree quiescence part of the result.
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

public sealed class LmiPostwriteNativeRunResult {
    public bool AssignmentConfirmed;
    public int? ExitCode;
    public string FailureCode;
    public string Output;
    public bool Started;
    public bool TimedOut;
    public bool TreeQuiescent;
}

public static class LmiPostwriteNativeRunner {
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

    static void Close(ref IntPtr handle) { if (handle != IntPtr.Zero && handle != INVALID_HANDLE_VALUE) { CloseHandle(handle); handle = IntPtr.Zero; } }

    public static LmiPostwriteNativeRunResult Run(string application, string commandLine, string workingDirectory, string environmentBlock, int timeoutMilliseconds) {
        LmiPostwriteNativeRunResult result = new LmiPostwriteNativeRunResult { FailureCode = null, Output = "", TreeQuiescent = false };
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

function Invoke-Fastboot {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'devices',
            'serialno',
            'product',
            'unlocked',
            'is-userspace',
            'is-logical:userdata',
            'partition-type:userdata',
            'partition-size:userdata',
            'battery-voltage',
            'battery-soc-ok',
            'max-download-size'
        )]
        [string]$Query,
        [string]$Serial = ''
    )
    if ($null -eq $FastbootPath -or -not $Locked.ContainsKey('fastboot.exe')) { Fail 'FASTBOOT_NOT_LOCKED' }
    if ($Query -ne 'devices' -and $Serial -notmatch '^[A-Za-z0-9._:-]{1,128}$') { Fail 'DEVICE_SERIAL_INVALID' }
    $tokens = switch ($Query) {
        'devices' { @('devices') }
        'serialno' { @('-s', $Serial, 'getvar', 'serialno') }
        'product' { @('-s', $Serial, 'getvar', 'product') }
        'unlocked' { @('-s', $Serial, 'getvar', 'unlocked') }
        'is-userspace' { @('-s', $Serial, 'getvar', 'is-userspace') }
        'is-logical:userdata' { @('-s', $Serial, 'getvar', 'is-logical:userdata') }
        'partition-type:userdata' { @('-s', $Serial, 'getvar', 'partition-type:userdata') }
        'partition-size:userdata' { @('-s', $Serial, 'getvar', 'partition-size:userdata') }
        'battery-voltage' { @('-s', $Serial, 'getvar', 'battery-voltage') }
        'battery-soc-ok' { @('-s', $Serial, 'getvar', 'battery-soc-ok') }
        'max-download-size' { @('-s', $Serial, 'getvar', 'max-download-size') }
        default { Fail 'FASTBOOT_QUERY_NOT_FIXED' }
    }
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
    $commandLine = (Quote-WindowsArgument $FastbootPath) + ' ' + (($tokens | ForEach-Object { Quote-WindowsArgument $_ }) -join ' ')
    [void]$QueriesAttempted.Add($Query)
    $native = [LmiPostwriteNativeRunner]::Run($FastbootPath, $commandLine, $fastbootDirectory, $environmentBlock, $QueryTimeoutMs)
    if (
        -not $native.AssignmentConfirmed -or -not $native.Started -or
        $native.TimedOut -or -not $native.TreeQuiescent -or
        $null -ne $native.FailureCode -or $null -eq $native.ExitCode
    ) { Fail 'FASTBOOT_QUERY_CONTAINMENT_FAILED' }
    [void]$QueriesCompleted.Add($Query)
    return [ordered]@{
        exit_code = $native.ExitCode
        output = ([string]$native.Output -replace "`r", '')
    }
}

function Get-FastbootVariable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Serial,
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'serialno', 'product', 'unlocked', 'is-userspace',
            'is-logical:userdata', 'partition-type:userdata',
            'partition-size:userdata', 'battery-voltage',
            'battery-soc-ok', 'max-download-size'
        )]
        [string]$Name,
        [switch]$AllowUnsupported
    )
    $result = Invoke-Fastboot -Query $Name -Serial $Serial
    $escaped = [regex]::Escape($Name)
    $code = $Name.ToUpperInvariant() -replace '[^A-Z0-9]', '_'
    $valuePattern = "(?im)^(?:\(bootloader\)[ \t]+)?${escaped}:[ \t]*([^\r\n]*?)[ \t]*$"
    $failurePattern = "(?im)^getvar:${escaped}[ \t]+FAILED[ \t]+\([ \t]*remote:[ \t]*'(?:GetVar[ \t]+Variable[ \t]+Not[ \t]+found|Unknown[ \t]+variable|Variable[ \t]+Not[ \t]+found|Unsupported)'[ \t]*\)[ \t]*$"
    $footerPattern = '(?im)^Finished\. Total time:[ \t]+[0-9]+(?:\.[0-9]+)?s[ \t]*$'
    $values = @([regex]::Matches($result.output, $valuePattern))
    $failures = @([regex]::Matches($result.output, $failurePattern))
    $footers = @([regex]::Matches($result.output, $footerPattern))
    if ($values.Count -gt 1 -or $failures.Count -gt 1 -or $footers.Count -ne 1) { Fail ("GETVAR_FAILED_" + $code) }
    if ($result.exit_code -eq 0 -and $values.Count -eq 1 -and $failures.Count -eq 0) {
        $remainder = [regex]::Replace($result.output, $valuePattern, '')
        $remainder = [regex]::Replace($remainder, $footerPattern, '')
        $value = $values[0].Groups[1].Value.Trim()
        if ([string]::IsNullOrWhiteSpace($remainder) -and $value.Length -gt 0) { return $value }
    }
    if ($AllowUnsupported -and $result.exit_code -eq 0 -and $values.Count -eq 0 -and $failures.Count -eq 1) {
        $remainder = [regex]::Replace($result.output, $failurePattern, '')
        $remainder = [regex]::Replace($remainder, $footerPattern, '')
        if ([string]::IsNullOrWhiteSpace($remainder)) { return 'unsupported' }
    }
    Fail ("GETVAR_FAILED_" + $code)
}

function Check-Device($Contract) {
    $listed = Invoke-Fastboot -Query 'devices'
    if ($listed.exit_code -ne 0) { Fail 'DEVICES_QUERY_FAILED' }
    $lines = @($listed.output -split "`n" | Where-Object { $_.Trim().Length -gt 0 })
    $serials = @()
    foreach ($line in $lines) {
        if ($line -notmatch '^([^\s]+)\s+fastboot$') { Fail 'DEVICES_OUTPUT_INVALID' }
        $serials += $Matches[1]
    }
    if ($serials.Count -ne 1) { Fail 'DEVICE_COUNT_NOT_ONE' }
    $serial = [string]$serials[0]
    if ($serial -notmatch '^[A-Za-z0-9._:-]{1,128}$') { Fail 'DEVICE_SERIAL_INVALID' }
    if ((Get-FastbootVariable $serial 'serialno') -cne $serial) { Fail 'DEVICE_SERIAL_MISMATCH' }
    if ((Device-Identity ([string]$Contract.identity.privacy_nonce) $serial) -cne [string]$Contract.identity.expected_nonce_scoped_serial_sha256) { Fail 'DEVICE_IDENTITY_MISMATCH' }
    $product = Get-FastbootVariable $serial 'product'
    $unlocked = Get-FastbootVariable $serial 'unlocked'
    $userspace = Get-FastbootVariable $serial 'is-userspace'
    $logical = Get-FastbootVariable $serial 'is-logical:userdata' -AllowUnsupported
    $partitionType = Get-FastbootVariable $serial 'partition-type:userdata'
    $partitionSize = Parse-UInt64 (Get-FastbootVariable $serial 'partition-size:userdata') 'PARTITION_SIZE_INVALID'
    $battery = Parse-UInt64 (Get-FastbootVariable $serial 'battery-voltage') 'BATTERY_INVALID'
    $soc = Get-FastbootVariable $serial 'battery-soc-ok'
    $maxDownload = Parse-UInt64 (Get-FastbootVariable $serial 'max-download-size') 'MAX_DOWNLOAD_INVALID'
    if ($product -cne [string]$Contract.device.expected_product) { Fail 'PRODUCT_MISMATCH' }
    if ($unlocked -cne 'yes') { Fail 'BOOTLOADER_NOT_UNLOCKED' }
    if ($userspace -cne 'no') { Fail 'USERSPACE_FASTBOOT_FORBIDDEN' }
    $override = $false
    if ($logical -ceq 'yes') { Fail 'LOGICAL_USERDATA_FORBIDDEN' }
    elseif ($logical -ceq 'no') {}
    elseif ($logical -ceq 'unsupported') {
        if (
            $Contract.mapping.allowed_getvar_result -cne 'unsupported' -or
            $Contract.mapping.fastboot_mode -cne 'bootloader' -or
            $Contract.mapping.partition -cne 'userdata' -or
            $Contract.mapping.partition_type -cne 'f2fs' -or
            $Contract.mapping.super_or_fastbootd_fallback_allowed -ne $false -or
            $Contract.mapping.block_device -cne '/dev/sda34' -or
            [uint64]$Contract.mapping.capacity_bytes -ne [uint64]$Contract.device.expected_userdata_capacity
        ) { Fail 'PHYSICAL_MAPPING_OVERRIDE_INVALID' }
        $override = $true
    } else { Fail 'IS_LOGICAL_UNKNOWN' }
    if ($partitionType -cne [string]$Contract.device.partition_type) { Fail 'PARTITION_TYPE_MISMATCH' }
    if (
        $partitionSize -ne [uint64]$Contract.device.expected_userdata_capacity -or
        $partitionSize -lt [uint64]$Contract.candidate.logical_size
    ) { Fail 'PARTITION_CAPACITY_MISMATCH' }
    if ($battery -lt [uint64]$Contract.device.minimum_battery_mv) { Fail 'BATTERY_TOO_LOW' }
    if ($soc -cne 'yes') { Fail 'BATTERY_SOC_NOT_OK' }
    if ($maxDownload -lt [uint64]$Contract.device.minimum_max_download_size) { Fail 'MAX_DOWNLOAD_TOO_SMALL' }
    Set-Variable -Name Device -Scope 1 -Value ([ordered]@{
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
    })
}

$Contract = $null
try {
    try {
        $bytes = [Convert]::FromBase64String($ContractJsonBase64)
        $encoding = [System.Text.UTF8Encoding]::new($false, $true)
        $Contract = $encoding.GetString($bytes) | ConvertFrom-Json
    } catch { Fail 'HELPER_INPUT_INVALID' }
    Require-ExactKeys $Contract @('candidate', 'device', 'fastboot', 'identity', 'mapping', 'physical_replug_confirmed', 'prior_write', 'profile', 'schema') 'HELPER_INPUT_FIELDS_MISMATCH'
    if ($Contract.schema -cne $InputSchema -or $Contract.physical_replug_confirmed -ne $true) { Fail 'HELPER_INPUT_BINDING_MISMATCH' }
    Require-ExactKeys $Contract.identity @('expected_nonce_scoped_serial_sha256', 'privacy_nonce') 'IDENTITY_FIELDS_MISMATCH'
    if (
        $Contract.identity.privacy_nonce -notmatch '^[0-9a-f]{64}$' -or
        $Contract.identity.expected_nonce_scoped_serial_sha256 -notmatch '^[0-9a-f]{64}$'
    ) { Fail 'IDENTITY_VALUE_INVALID' }
    $members = @($Contract.fastboot.members)
    if ($members.Count -ne 3) { Fail 'FASTBOOT_MEMBER_COUNT_MISMATCH' }
    $local = [System.Environment]::GetEnvironmentVariable('LOCALAPPDATA')
    if ([string]::IsNullOrWhiteSpace($local) -or -not [System.IO.Path]::IsPathRooted($local)) { Fail 'LOCALAPPDATA_INVALID' }
    $directory = [System.IO.Path]::Combine([System.IO.Path]::GetFullPath($local), 'lmi-p2-d114', 'fastboot-r37.0.0')
    Assert-PrivateAcl $directory $true
    $actual = @([System.IO.Directory]::EnumerateFileSystemEntries($directory) | ForEach-Object { [System.IO.Path]::GetFileName($_) } | Sort-Object)
    if (($actual -join "`n") -cne (@('AdbWinApi.dll', 'AdbWinUsbApi.dll', 'fastboot.exe') -join "`n")) { Fail 'FASTBOOT_DIRECTORY_CLOSURE_MISMATCH' }
    $expected = @(
        [ordered]@{ name = 'fastboot.exe'; size = 2199704L; sha256 = 'dd55fef77ab2753b6423f37f39d91cb00ce53ab4539a2431577f07c4abcaa32a' },
        [ordered]@{ name = 'AdbWinApi.dll'; size = 108184L; sha256 = '120bef587119c6cb926b86b9be90fdfbce38937588eae28cd91a94ce63c7b965' },
        [ordered]@{ name = 'AdbWinUsbApi.dll'; size = 73368L; sha256 = '6ca69a2ca0e31309c087d288f058977d421ad03500e4c3e1dbd981241a069c60' }
    )
    for ($index = 0; $index -lt 3; $index += 1) {
        Require-ExactKeys $members[$index] @('name', 'sha256', 'size') 'FASTBOOT_MEMBER_FIELDS_MISMATCH'
        if (
            [string]$members[$index].name -cne [string]$expected[$index].name -or
            [int64]$members[$index].size -ne [int64]$expected[$index].size -or
            [string]$members[$index].sha256 -cne [string]$expected[$index].sha256
        ) { Fail 'FASTBOOT_MEMBER_CONTRACT_MISMATCH' }
        $path = [System.IO.Path]::Combine($directory, [string]$expected[$index].name)
        Assert-PrivateAcl $path $false
        Open-ReadLocked $path ([string]$expected[$index].name) ([int64]$expected[$index].size) ([string]$expected[$index].sha256)
    }
    $FastbootPath = [System.IO.Path]::Combine($directory, 'fastboot.exe')
    $deviceLockPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'lmi-p2-d114-userdata-device.lock')
    try {
        $DeviceLockStream = [System.IO.File]::Open(
            $deviceLockPath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )
    } catch { Fail 'DEVICE_LOCK_BUSY' }
    Check-Device $Contract
    foreach ($name in @('fastboot.exe', 'AdbWinApi.dll', 'AdbWinUsbApi.dll')) { Assert-LockedStillSame $name }
    $LockedInputsIntact = $true
    $Reason = $null
    $Route = 'POSTWRITE_DEVICE_REVALIDATED_NO_STATE_CHANGE'
} catch {
    $message = [string]$_.Exception.Message
    $Reason = if ($message -match '^[A-Z0-9_]{1,96}$') { $message } else { 'READONLY_HELPER_FAILURE' }
    try {
        if ($Locked.Count -eq 3) {
            foreach ($name in @('fastboot.exe', 'AdbWinApi.dll', 'AdbWinUsbApi.dll')) { Assert-LockedStillSame $name }
            $LockedInputsIntact = $true
        }
    } catch { $LockedInputsIntact = $false }
    $Route = 'REFUSED_NO_STATE_CHANGE'
} finally {
    if ($null -ne $DeviceLockStream) { $DeviceLockStream.Dispose() }
    foreach ($stream in $Locked.Values) { $stream.Dispose() }
}

if ($null -eq $Contract) { throw 'HELPER_INPUT_UNAVAILABLE' }
$result = [ordered]@{
    candidate = [ordered]@{
        logical_size = [int64]$Contract.candidate.logical_size
        sha256 = [string]$Contract.candidate.sha256
        size = [int64]$Contract.candidate.size
    }
    device = $Device
    fastboot_members = @($Contract.fastboot.members)
    fastboot_queries_attempted = @($QueriesAttempted)
    fastboot_queries_completed = @($QueriesCompleted)
    flash = [ordered]@{ attempts = 0 }
    input_binding = [ordered]@{
        physical_replug_confirmed = $true
        prior_write_report_sha256 = [string]$Contract.prior_write.sha256
        profile_sha256 = [string]$Contract.profile.sha256
    }
    locked_inputs_intact = $LockedInputsIntact
    mode = 'PostwriteRevalidate'
    reason = $Reason
    route_status = $Route
    schema = $ResultSchema
    serial_disclosed = $false
}
$json = ($result | ConvertTo-Json -Compress -Depth 8)
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
Write-Output ($ResultPrefix + $encoded)
