<#
Exercise the real A1 application UI without replacing assets or IPC handlers.
The UI phase uses a temporary, restored profile: static-manual, empty recovery
records, no camera target, outputs disabled. Both native confirmations Cancel.
Hardware qualification is separate and must name the controlled devices.
#>
param(
    [ValidateSet('Run', 'CancelDialog')][string]$Mode = 'Run',
    [string]$AdapterMac,
    [string]$PrimaryAddress,
    [int]$OwnerPid,
    [string]$ExpectedText,
    [string]$RunDirectory,
    [string]$Executable,
    [string]$ArtifactRecord = 'docs\runtime-evidence\privilege-v2-a1.json',
    [switch]$CheckSecondInstance
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Executable) { $Executable = Join-Path $repoRoot 'src-tauri\target\debug\pocketstream-desktop.exe' }
$Executable = (Resolve-Path -LiteralPath $Executable).Path

function Read-LiveLog([string]$Path) {
    # Start-Process keeps redirected output open for writing. ReadAllText's
    # default sharing can fail while that process is still alive.
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $reader = New-Object IO.StreamReader $stream
    try { $reader.ReadToEnd() } finally { $reader.Dispose() }
}

function Get-LiveLogHash([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose(); $stream.Dispose() }
}

function Initialize-NativeWindowApi {
    if ('PocketStream.A1Smoke.Windows' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
namespace PocketStream.A1Smoke {
    public static class Windows {
        public delegate bool WindowCallback(IntPtr hwnd, IntPtr data);
        [DllImport("user32.dll")] static extern bool EnumWindows(WindowCallback cb, IntPtr data);
        [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr hwnd, WindowCallback cb, IntPtr data);
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr hwnd, StringBuilder text, int max);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int max);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
        [DllImport("user32.dll")] static extern bool PostMessage(IntPtr hwnd, uint message, IntPtr wparam, IntPtr lparam);
        [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern IntPtr SendMessageTimeoutW(IntPtr hwnd, uint message, UIntPtr wparam,
            StringBuilder text, uint flags, uint timeout, out UIntPtr result);
        [DllImport("user32.dll")] static extern int GetDlgCtrlID(IntPtr hwnd);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
        public static uint ExitCode(IntPtr process) {
            uint code;
            if (!GetExitCodeProcess(process, out code)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return code;
        }
        public class WindowInfo {
            public long Handle;
            public string Class;
            public string Text;
            public int Id;
            public bool Visible;
            public List<WindowInfo> Children = new List<WindowInfo>();
        }
        static bool Owned(IntPtr window, uint expected) {
            uint actual; GetWindowThreadProcessId(window, out actual);
            return actual == expected;
        }
        static WindowInfo Describe(IntPtr window) {
            var kind = new StringBuilder(128); GetClassName(window, kind, kind.Capacity);
            var text = new StringBuilder(4096); UIntPtr result;
            // GetWindowText does not read another process's control text.
            SendMessageTimeoutW(window, 0xD, new UIntPtr((uint)text.Capacity), text,
                0x2, 300, out result);
            return new WindowInfo {Handle=window.ToInt64(), Class=kind.ToString(),
                Text=text.ToString(), Id=GetDlgCtrlID(window), Visible=IsWindowVisible(window)};
        }
        public static WindowInfo[] Snapshot(uint owner) {
            var found = new List<WindowInfo>();
            EnumWindows((window, _) => {
                if (!Owned(window, owner) || found.Count >= 32) return true;
                var info = Describe(window);
                if (info.Class == "#32770") EnumChildWindows(window, (child, data) => {
                    if (Owned(child, owner) && info.Children.Count < 32) info.Children.Add(Describe(child));
                    return true;
                }, IntPtr.Zero);
                found.Add(info); return true;
            }, IntPtr.Zero);
            return found.ToArray();
        }
        public static bool AcknowledgeBusy(IntPtr dialog, uint owner) {
            if (!Owned(dialog, owner)) throw new InvalidOperationException("Foreign dialog");
            var text = Describe(dialog).Text;
            EnumChildWindows(dialog, (child, _) => {
                if (Owned(child, owner)) text += "\n" + Describe(child).Text;
                return true;
            }, IntPtr.Zero);
            if (!text.Contains("PocketStream is already running")) return false;
            IntPtr button = IntPtr.Zero;
            EnumChildWindows(dialog, (child, _) => {
                if (!Owned(child, owner)) return true;
                var info = Describe(child);
                if (info.Class == "Button" && info.Id > 0 && info.Id <= 65535 && info.Text.Replace("&", "") == "OK") button = child;
                return true;
            }, IntPtr.Zero);
            if (button == IntPtr.Zero) return false;
            // Send the actual verified OK button's BN_CLICKED notification.
            // MainWindowHandle can name the development console instead.
            return PostMessage(dialog, 0x111, new IntPtr(GetDlgCtrlID(button)), button);
        }
        public static IntPtr[] Dialogs(uint owner) {
            var found = new List<IntPtr>();
            EnumWindows((window, _) => {
                uint pid; GetWindowThreadProcessId(window, out pid);
                if (pid == owner) {
                    var kind = new StringBuilder(128); GetClassName(window, kind, kind.Capacity);
                    if (kind.ToString() == "#32770") found.Add(window);
                }
                return true;
            }, IntPtr.Zero);
            return found.ToArray();
        }
        public static bool PostCancel(IntPtr window) { return PostMessage(window, 0x111, new IntPtr(2), IntPtr.Zero); }
        public static string CancelDialog(uint owner, string expected) {
            string observed = null;
            EnumWindows((window, _) => {
                uint pid; GetWindowThreadProcessId(window, out pid);
                if (pid != owner) return true;
                var kind = new StringBuilder(128); GetClassName(window, kind, kind.Capacity);
                if (kind.ToString() != "#32770") return true;
                var text = new StringBuilder();
                EnumChildWindows(window, (child, data) => {
                    var part = new StringBuilder(2048); GetWindowText(child, part, part.Capacity);
                    if (part.Length > 0 && text.Length < 8192) text.AppendLine(part.ToString());
                    return true;
                }, IntPtr.Zero);
                if (text.ToString().IndexOf(expected, StringComparison.Ordinal) < 0) return true;
                if (!PostMessage(window, 0x111, new IntPtr(2), IntPtr.Zero)) return true;
                observed = text.ToString(); return false;
            }, IntPtr.Zero);
            return observed;
        }
        public static void CloseOwnWindows(uint owner) {
            EnumWindows((window, _) => {
                uint pid; GetWindowThreadProcessId(window, out pid);
                if (pid == owner && IsWindowVisible(window)) {
                    var kind = new StringBuilder(128); GetClassName(window, kind, kind.Capacity);
                    if (kind.ToString() == "#32770") PostMessage(window, 0x111, new IntPtr(2), IntPtr.Zero);
                    else PostMessage(window, 0x10, IntPtr.Zero, IntPtr.Zero);
                }
                return true;
            }, IntPtr.Zero);
        }
    }
}
'@
}

if ($Mode -eq 'CancelDialog') {
    if ($OwnerPid -le 0 -or -not $ExpectedText) { throw 'CancelDialog requires owner PID and expected prompt text.' }
    Initialize-NativeWindowApi
    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes
    $deadline = [DateTime]::UtcNow.AddSeconds(12)
    $lastObserved = ''
    do {
        $owner = Get-Process -Id $OwnerPid -ErrorAction Stop
        if ($owner.Path -ne $Executable) { throw 'Dialog owner is not the expected application image.' }
        $text = [PocketStream.A1Smoke.Windows]::CancelDialog([uint32]$OwnerPid, $ExpectedText)
        if ($null -eq $text) {
            # TaskDialog's DirectUI controls may expose their text through
            # accessibility rather than GetWindowText. Inspect only own dialogs.
            foreach ($window in [PocketStream.A1Smoke.Windows]::Dialogs([uint32]$OwnerPid)) {
                $root = [Windows.Automation.AutomationElement]::FromHandle($window)
                $nodes = $root.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition)
                $names = @($root.Current.Name) + @($nodes | ForEach-Object { $_.Current.Name })
                $lastObserved = ($names -join "`n")
                if ($lastObserved.Contains($ExpectedText) -and [PocketStream.A1Smoke.Windows]::PostCancel($window)) { $text=$lastObserved; break }
            }
        }
        if ($null -ne $text) {
            [pscustomobject]@{ observed = $true; owner_pid = $OwnerPid; text = $text; action = 'Cancel' } | ConvertTo-Json -Compress
            exit 0
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "The expected production confirmation was not observed; no other dialog was dismissed. Last own-dialog text: $lastObserved"
}

if ($AdapterMac -notmatch '^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$') { throw 'Specify the controlled Ethernet MAC.' }
$AdapterMac = $AdapterMac.Replace('-', ':').ToLowerInvariant()
if ($PrimaryAddress -notmatch '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') { throw 'Specify an existing primary IPv4 CIDR.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This development UI phase runs at medium integrity; elevated production/hardware qualification is separate.'
}
if (@(Get-Process -Name 'pocketstream-desktop' -ErrorAction SilentlyContinue).Count) { throw 'Close the existing PocketStream host before the controlled smoke.' }
$baseline = Get-Content -LiteralPath (Join-Path $repoRoot $ArtifactRecord) -Raw | ConvertFrom-Json
$recordedArtifact = $baseline.artifacts.development
if ($null -eq $recordedArtifact) { $recordedArtifact = $baseline.artifacts.development_application }
$artifactHash = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant()
if ($artifactHash -ne $recordedArtifact.sha256) { throw 'Executable differs from the recorded development artifact; record and review it before running.' }
$adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.MacAddress.Replace('-', ':').ToLowerInvariant() -eq $AdapterMac })
if ($adapters.Count -ne 1 -or -not $adapters[0].HardwareInterface -or $adapters[0].InterfaceDescription -match 'Wi-Fi|Wireless') {
    throw 'Controlled MAC must resolve uniquely to a physical Ethernet adapter.'
}
$adapter = $adapters[0]
$address = $PrimaryAddress.Split('/')[0]
$prefix = [int]$PrimaryAddress.Split('/')[1]
if (-not (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -ErrorAction Stop | Where-Object { $_.IPAddress -eq $address -and $_.PrefixLength -eq $prefix })) {
    throw 'The requested confirmation target is not already assigned to this adapter; no address will be added.'
}

function Native-Snapshot {
    [ordered]@{
        adapter_guid = [string]$adapter.InterfaceGuid
        adapter_mac = $AdapterMac
        interface_index = [int]$adapter.ifIndex
        addresses = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -ErrorAction Stop |
            Sort-Object IPAddress,PrefixLength | Select-Object IPAddress,PrefixLength,PrefixOrigin)
        dhcp = [string](Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -ErrorAction Stop).Dhcp
        dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -ErrorAction Stop | ForEach-Object { $_.ServerAddresses })
        routes = @(Get-NetRoute -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -ErrorAction Stop |
            Sort-Object DestinationPrefix,NextHop | Select-Object DestinationPrefix,NextHop,RouteMetric,Protocol)
    }
}

$runFolder = if ($CheckSecondInstance) { 'src-tauri\target\privilege-a2' } else { 'src-tauri\target\privilege-a1' }
if (-not $RunDirectory) { $RunDirectory = Join-Path $repoRoot ($runFolder + '\production-smoke-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')) }
$RunDirectory = [IO.Path]::GetFullPath($RunDirectory)
$allowedRunRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot $runFolder)) + [IO.Path]::DirectorySeparatorChar
if (-not $RunDirectory.StartsWith($allowedRunRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Run directory must stay under the selected target evidence folder.' }
if (Test-Path -LiteralPath $RunDirectory) { throw 'Use a fresh run directory; existing evidence will not be overwritten.' }
New-Item -ItemType Directory -Path $RunDirectory | Out-Null
Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $RunDirectory 'fixture.ps1')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'verify-a1-production-smoke.mjs') -Destination (Join-Path $RunDirectory 'fixture.mjs')
$backupDir = Join-Path $RunDirectory 'private-profile-backup'
New-Item -ItemType Directory -Path $backupDir | Out-Null
$profileDir = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'PocketStream'
$logDir = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'PocketStream\logs'
$files = @(
    (Join-Path $profileDir 'config.toml'), (Join-Path $profileDir 'device_cache.toml'), (Join-Path $profileDir '.key'),
    (Join-Path $logDir 'pocketstream.log'), (Join-Path $logDir 'pocketstream.log.1')
)
$backups = @()
foreach ($file in $files) {
    $copy = Join-Path $backupDir ([string]$backups.Count)
    $existed = Test-Path -LiteralPath $file
    $hash = $null
    if ($existed) { Copy-Item -LiteralPath $file -Destination $copy; $hash = (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant() }
    $backups += [pscustomobject]@{ path=$file; backup=$copy; existed=$existed; sha256=$hash }
}
$backups | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $backupDir 'recovery.json') -Encoding UTF8
$before = Native-Snapshot
$record = [ordered]@{
    gate = 'A1 production workflows'; status = 'pending'; started_at_utc = [DateTime]::UtcNow.ToString('o')
    artifact = [ordered]@{ path=$Executable; sha256=$artifactHash; profile='development'; execution_level='asInvoker'; production_ui_and_handlers=$true; replaced_assets_or_handlers=$false }
    fixture = [ordered]@{ adapter_mac=$AdapterMac; adapter_guid=[string]$adapter.InterfaceGuid; alias=[string]$adapter.Name; interface_index=[int]$adapter.ifIndex; initial_link_state=[string]$adapter.Status; primary_address=$PrimaryAddress; native_mutation_policy='both destructive confirmations Cancel; no listener starts' }
    native_before=$before; native_after=$null; native_state_unchanged=$false; profile_restored=$false
    ui=$null; hardware=[ordered]@{ discovery='pending'; playback='pending'; ptu='pending'; reason='Controlled connected hardware and explicit PTU identity required' }
    diagnostic=$null
}
if ($CheckSecondInstance) { $record.gate = 'Local production second-instance dismissal and continuing workflows' }
$app = $null
$second = $null
$profileChanged = $false
$oldArgs = [Environment]::GetEnvironmentVariable('WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS', 'Process')
$oldData = [Environment]::GetEnvironmentVariable('WEBVIEW2_USER_DATA_FOLDER', 'Process')
try {
    # No retained/pending address records, cached devices, automatic discovery or
    # listener enablement can cause startup policy changes in this profile.
    $profile = @"
selected_adapter_mac = "$AdapterMac"
network_mode = "static_manual"
restream_protocol = "rtsp"
pending_addresses = []
manual_nodes = []
[primary_addresses]
"$AdapterMac" = "$PrimaryAddress"
[stream]
protocol = "rtsp"
rtsp_port = 554
rtsp_path = "/z3-1.sdp"
udp_port = 8600
camera_ip = ""
audio_muted = true
[rtsp_server]
enabled = false
port = 8554
token = "0123456789abcdef"
bind_interface = ""
[credentials]
username = ""
password = ""
"@
    if (@(Get-Process -Name 'pocketstream-desktop' -ErrorAction SilentlyContinue).Count) { throw 'A host started during preflight; profile remains untouched.' }
    [IO.File]::WriteAllText($files[0], $profile, (New-Object Text.UTF8Encoding $false))
    $profileChanged = $true
    [IO.File]::WriteAllText($files[1], "devices = []`n", (New-Object Text.UTF8Encoding $false))
    $listener = New-Object Net.Sockets.TcpListener ([Net.IPAddress]::Loopback),0
    $listener.Start(); $port = $listener.LocalEndpoint.Port; $listener.Stop()
    $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=$port --remote-debugging-address=127.0.0.1"
    $env:WEBVIEW2_USER_DATA_FOLDER = Join-Path $RunDirectory 'webview-data'
    $app = Start-Process -FilePath $Executable -WorkingDirectory (Split-Path -Parent $Executable) -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $RunDirectory 'application.stdout.log') -RedirectStandardError (Join-Path $RunDirectory 'application.stderr.log')
    $appHandle = $app.Handle
    $context = [ordered]@{ pid=$app.Id; executable=$Executable; port=$port; adapter_mac=$AdapterMac; expected_address=$address; expected_cidr=$PrimaryAddress; alias=[string]$adapter.Name; powershell=(Join-Path $PSHOME 'powershell.exe'); native_helper=$PSCommandPath }
    $contextPath = Join-Path $RunDirectory 'context.json'
    $context | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $contextPath -Encoding UTF8
    if ($CheckSecondInstance) {
        & node (Join-Path $PSScriptRoot 'verify-a1-production-smoke.mjs') $contextPath --ready-only
        if ($LASTEXITCODE -ne 0) { throw 'Original production UI did not become ready.' }
        $startupDeadline = [DateTime]::UtcNow.AddSeconds(15)
        do {
            $startupSettled = (Read-LiveLog (Join-Path $RunDirectory 'application.stderr.log')).Contains('Started ICMP ping-dot loop')
            if ($startupSettled) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $startupDeadline)
        if (-not $startupSettled) { throw 'Original startup/reconciliation did not finish before the contender.' }
        Start-Sleep -Milliseconds 300
        $profileBeforeSecond = (Get-FileHash -LiteralPath $files[0] -Algorithm SHA256).Hash.ToLowerInvariant()
        $cacheBeforeSecond = (Get-FileHash -LiteralPath $files[1] -Algorithm SHA256).Hash.ToLowerInvariant()
        $logBeforeSecond = Get-LiveLogHash $files[3]
        $secondError = Join-Path $RunDirectory 'second-instance.stderr.log'
        $second = Start-Process -FilePath $Executable -WorkingDirectory (Split-Path -Parent $Executable) -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Join-Path $RunDirectory 'second-instance.stdout.log') -RedirectStandardError $secondError
        $secondHandle = $second.Handle
        $record['second_instance'] = [ordered]@{pid=$second.Id; artifact_sha256=$artifactHash; windows=@(); busy_observed=$false; acknowledged=$false; exited=$false}
        Initialize-NativeWindowApi
        $deadline = [DateTime]::UtcNow.AddSeconds(12)
        do {
            if ($second.HasExited) { break }
            if ((Get-Process -Id $second.Id -ErrorAction Stop).Path -ne $Executable) { throw 'Second-process image changed.' }
            $windows = [PocketStream.A1Smoke.Windows]::Snapshot([uint32]$second.Id)
            if ($windows.Count) { $record.second_instance.windows = @($windows) }
            $diagnostic = Read-LiveLog $secondError
            if ($diagnostic.Trim() -eq 'PocketStream is already running: Busy') {
                $record.second_instance.busy_observed = $true
                foreach ($window in $windows) {
                    if ($window.Class -eq '#32770' -and [PocketStream.A1Smoke.Windows]::AcknowledgeBusy([IntPtr]$window.Handle, [uint32]$second.Id)) {
                        $record.second_instance.acknowledged = $true
                        $record.second_instance['dismissal'] = 'verified native OK button BN_CLICKED'
                        break
                    }
                }
            }
            if ($second.WaitForExit(100)) { break }
        } while ([DateTime]::UtcNow -lt $deadline)
        $record.second_instance.exited = $second.HasExited
        $record.second_instance['profile_unchanged'] = $profileBeforeSecond -eq (Get-FileHash -LiteralPath $files[0] -Algorithm SHA256).Hash.ToLowerInvariant()
        $record.second_instance['cache_unchanged'] = $cacheBeforeSecond -eq (Get-FileHash -LiteralPath $files[1] -Algorithm SHA256).Hash.ToLowerInvariant()
        $record.second_instance['log_unchanged'] = $logBeforeSecond -eq (Get-LiveLogHash $files[3])
        $record.second_instance['no_initialization_banner'] = -not (Read-LiveLog $secondError).Contains('starting')
        if (-not $record.second_instance.busy_observed -or -not $record.second_instance.acknowledged -or -not $second.HasExited) { throw 'Second-instance refusal/dismissal did not complete; inspect its window snapshot.' }
        $record.second_instance['exit_code'] = [PocketStream.A1Smoke.Windows]::ExitCode($secondHandle)
        if ($record.second_instance.exit_code -ne 0 -or -not $record.second_instance.profile_unchanged -or -not $record.second_instance.cache_unchanged -or -not $record.second_instance.log_unchanged) { throw 'Second-instance refusal changed shared files or returned an unexpected exit code.' }
        if ($app.HasExited) { throw 'Original instance exited during second-instance refusal.' }
        $record['original_usable_after_refusal'] = 'pending production settings and confirmation workflows below'
    }
    Write-Output "Production UI smoke: PID $($app.Id), artifact $artifactHash, run $RunDirectory"
    & node (Join-Path $PSScriptRoot 'verify-a1-production-smoke.mjs') $contextPath
    $uiExit = $LASTEXITCODE
    $uiPath = Join-Path $RunDirectory 'ui-result.json'
    if (Test-Path -LiteralPath $uiPath) { $record.ui = Get-Content -LiteralPath $uiPath -Raw | ConvertFrom-Json }
    if ($uiExit -ne 0) { throw "Production UI smoke returned $uiExit; inspect the recorded workflow results." }
    if ($CheckSecondInstance) { $record.original_usable_after_refusal = 'passed production settings/readback and both native Cancel workflows' }
    $record.status = 'partial: production settings and confirmation Cancel paths passed; hardware gates pending'
} catch {
    $record.diagnostic = $_.Exception.Message
    Write-Output "Production smoke pending/failed: $($record.diagnostic)"
} finally {
    [Environment]::SetEnvironmentVariable('WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS', $oldArgs, 'Process')
    [Environment]::SetEnvironmentVariable('WEBVIEW2_USER_DATA_FOLDER', $oldData, 'Process')
    if ($null -ne $app -and -not $app.WaitForExit(5000)) {
        & node (Join-Path $PSScriptRoot 'verify-a1-production-smoke.mjs') $contextPath --close-only
    }
    $stopped = $true
    if ($null -ne $app) {
        # The CDP driver requests the real #btn-close action first. WM_CLOSE is
        # only a cooperative recovery request when that action did not finish.
        if (-not $app.WaitForExit(5000)) {
            Initialize-NativeWindowApi
            [PocketStream.A1Smoke.Windows]::CloseOwnWindows([uint32]$app.Id)
            $stopped = $app.WaitForExit(15000)
        }
        $record['application_pid'] = $app.Id
        $record['graceful_exit'] = $stopped
        if ($CheckSecondInstance -and $stopped) {
            $record['original_exit_code'] = [PocketStream.A1Smoke.Windows]::ExitCode($appHandle)
        }
    }
    if ($null -ne $second -and -not $second.HasExited) {
        Initialize-NativeWindowApi
        foreach ($window in [PocketStream.A1Smoke.Windows]::Snapshot([uint32]$second.Id)) {
            if ($window.Class -eq '#32770') { $null = [PocketStream.A1Smoke.Windows]::AcknowledgeBusy([IntPtr]$window.Handle, [uint32]$second.Id) }
        }
        if (-not $second.WaitForExit(3000)) { $stopped = $false; $record['second_instance_still_alive'] = $true }
    }
    if ($stopped -and $profileChanged) {
        # Preserve this run's app log before restoring the user's original log.
        if (Test-Path -LiteralPath $files[3]) { Copy-Item -LiteralPath $files[3] -Destination (Join-Path $RunDirectory 'production-app.log') }
        foreach ($backup in $backups) {
            if ($backup.existed) { Copy-Item -LiteralPath $backup.backup -Destination $backup.path -Force }
            elseif (Test-Path -LiteralPath $backup.path) { Remove-Item -LiteralPath $backup.path }
        }
        $record.profile_restored = @($backups | Where-Object {
            if ($_.existed) { -not (Test-Path -LiteralPath $_.path) -or (Get-FileHash -LiteralPath $_.path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $_.sha256 }
            else { Test-Path -LiteralPath $_.path }
        }).Count -eq 0
    } elseif (-not $stopped) {
        $record.diagnostic = 'Host did not exit cooperatively; no force-kill or profile restore was attempted. Private recovery backup is retained.'
    }
    $record.native_after = Native-Snapshot
    $record.native_state_unchanged = ($record.native_before | ConvertTo-Json -Depth 8 -Compress) -eq ($record.native_after | ConvertTo-Json -Depth 8 -Compress)
    if (-not $record.native_state_unchanged -or ($profileChanged -and -not $record.profile_restored)) { $record.status = 'failed: cleanup/native-state verification requires review' }
    $record['finished_at_utc'] = [DateTime]::UtcNow.ToString('o')
    $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $RunDirectory 'result.json') -Encoding UTF8
    Write-Output "Result: $($record.status); profile restored=$($record.profile_restored); selected-adapter state unchanged=$($record.native_state_unchanged)"
}
if ($record.diagnostic) { exit 1 }
exit 0
