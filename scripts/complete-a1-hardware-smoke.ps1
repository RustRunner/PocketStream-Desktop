<# Operator qualification fixture, not an application entry point.
   Record the exact running release. -Finish requires same-account elevation,
   requests normal application shutdown, and restores only the output-enable
   field changed by start-a1-hardware-smoke.ps1. Never force-kill the host. #>
param([Parameter(Mandatory=$true)][string]$ContextPath, [switch]$Finish)
$ErrorActionPreference = 'Stop'
$stage = Split-Path -Parent (Resolve-Path -LiteralPath $ContextPath).Path
$context = Get-Content -LiteralPath $ContextPath -Raw | ConvertFrom-Json
$launch = Get-Content -LiteralPath (Join-Path $stage 'launch-result.json') -Raw | ConvertFrom-Json
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class A1Image {
    delegate bool EnumProc(IntPtr h, IntPtr p);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr p, uint flags, StringBuilder name, ref uint size);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc p, IntPtr l);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    public static IntPtr MainWindow(uint target) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((h,p) => {
            uint pid; GetWindowThreadProcessId(h, out pid);
            var name = new StringBuilder(256); GetClassName(h, name, 256);
            if (pid == target && name.ToString() == "Tauri Window") { found=h; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
    public static string Path(uint pid) {
        var p = OpenProcess(0x1000, false, pid);
        if (p == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        try {
            var s = new StringBuilder(32768); uint n = (uint)s.Capacity;
            if (!QueryFullProcessImageName(p, 0, s, ref n)) throw new System.ComponentModel.Win32Exception();
            return s.ToString();
        } finally { CloseHandle(p); }
    }
}
'@
function Test-BoundTcp([string]$Source, [string]$Target) {
    $client = New-Object Net.Sockets.TcpClient
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $client.Client.Bind((New-Object Net.IPEndPoint ([Net.IPAddress]::Parse($Source)),0))
        $task = $client.ConnectAsync($Target,80)
        if (-not $task.Wait(2000)) { $status='timeout' } else { $null=$task.GetAwaiter().GetResult(); $status='connected' }
        return [ordered]@{source=$Source;target=$Target;port=80;status=$status;elapsed_ms=$watch.ElapsedMilliseconds}
    } catch {
        return [ordered]@{source=$Source;target=$Target;port=80;status='failed';reason=$_.Exception.GetBaseException().Message;elapsed_ms=$watch.ElapsedMilliseconds}
    } finally { $client.Dispose() }
}
$recordPath = Join-Path $stage 'hardware-observations.json'
function Note-Step([string]$Step) { [IO.File]::WriteAllText((Join-Path $stage 'recorder-step.txt'), $Step) }
try {
    if ($Finish) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal $identity
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $identity.User.Value -ne $context.expected_sid) {
            throw 'Finish requires the same interactive account with elevation; no close or profile change attempted.'
        }
    }
    $app = Get-Process -Id $launch.application_pid -ErrorAction Stop
    Note-Step 'process identity'
    $image = [A1Image]::Path($app.Id)
    if ($image -ne $context.executable -or (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant() -ne $context.sha256) {
        throw 'Running process is not the selected A1 artifact; no close or profile change attempted.'
    }
    $log = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'PocketStream\logs\pocketstream.log'
    Copy-Item -LiteralPath $log -Destination (Join-Path $stage 'hardware-app-snapshot.log') -Force
    Note-Step 'log selection'
    $start = $app.StartTime.ToString('yyyy-MM-dd HH:mm:ss')
    $lines = @(Get-Content -LiteralPath (Join-Path $stage 'hardware-app-snapshot.log') -Encoding UTF8 | Where-Object { $_.Length -ge 19 -and $_.Substring(0,19) -ge $start })
    $selected = @($lines | Where-Object { $_ -match 'v0.6.7 starting|Found bundled GStreamer|GStreamer 1.26.11 initialized|event=capture_state|Playback pipeline set to Playing|event=playback_attempt|event=playback_recovery|PTU initialization|PTU init|event=node_transition' })
    $selected += @($lines | Where-Object { $_ -match 'Cache probe: fresh resolve of 192.168.1.74 failed closed|identity_probe.*172.31.169.84.*answered=true' } | Select-Object -Last 4)
    # Get-Content decorates strings with provider metadata in Windows
    # PowerShell 5.1. Keep only string values in nested JSON evidence.
    $selected = @($selected | ForEach-Object { [string]::Concat($_) })
    $selected | Set-Content -LiteralPath (Join-Path $stage 'hardware-observations.log') -Encoding UTF8
    Note-Step 'profile readback'
    $profile = [IO.File]::ReadAllText($launch.profile.path)
    $section = [regex]::Match($profile, '(?ms)^\[rtsp_server\]\r?\n.*?(?=^\[|\z)')
    $enabled = [regex]::Match($section.Value, '(?m)^enabled\s*=\s*(true|false)\s*$')
    if (-not $section.Success -or -not $enabled.Success) { throw 'Exact output-enable field not found.' }
    Note-Step 'native address observation'
    $addresses = @(Get-NetIPAddress -InterfaceIndex 15 -AddressFamily IPv4 | ForEach-Object { [ordered]@{IPAddress=[string]$_.IPAddress;PrefixLength=[int]$_.PrefixLength;PrefixOrigin=[int]$_.PrefixOrigin} })
    Note-Step 'neighbor observation'
    $neighbors = @(Get-NetNeighbor -InterfaceIndex 15 -AddressFamily IPv4 | Where-Object { $_.IPAddress -in @('172.31.169.84','192.168.1.74') } | ForEach-Object { [ordered]@{IPAddress=[string]$_.IPAddress;LinkLayerAddress=[string]$_.LinkLayerAddress;state=$_.State.ToString()} })
    Note-Step 'bound TCP observation'
    $tcp = @((Test-BoundTcp '172.31.169.102' '172.31.169.84'),(Test-BoundTcp '192.168.1.100' '192.168.1.74'))
    Note-Step 'listener observation'
    $listeners = @(Get-NetTCPConnection -OwningProcess $app.Id -State Listen -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{LocalAddress=[string]$_.LocalAddress;LocalPort=[int]$_.LocalPort} })
    Note-Step 'write observation record'
    $record = [ordered]@{
        at_utc=[DateTime]::UtcNow.ToString('o'); artifact=$launch.artifact
        application_pid=$app.Id; started_at_utc=$app.StartTime.ToUniversalTime().ToString('o')
        selected_observations=$selected
        camera_user_observation='User confirmed: Live video is visible, after selecting 172.31.169.84 as CAM and pressing Start Stream in this A1 build.'
        output_enabled_during_smoke=($enabled.Groups[1].Value -eq 'true')
        native_addresses=$addresses; neighbors=$neighbors; bound_tcp=$tcp; listeners=$listeners
        raw_log_sha256=(Get-FileHash -LiteralPath (Join-Path $stage 'hardware-app-snapshot.log') -Algorithm SHA256).Hash.ToLowerInvariant()
        profile_cleanup='pending while controlled session remains active'; firewall_install='not exercised'
    }
    $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $recordPath -Encoding UTF8
    if ($Finish) {
        if ((Get-FileHash -LiteralPath $launch.profile.private_backup -Algorithm SHA256).Hash.ToLowerInvariant() -ne $launch.profile.before_sha256) { throw 'Original private backup changed; no shutdown or profile change attempted.' }
        Add-Type -AssemblyName UIAutomationClient
        Add-Type -AssemblyName UIAutomationTypes
        $window = [A1Image]::MainWindow($app.Id)
        if ($window -eq [IntPtr]::Zero) { throw 'Owned Tauri window unavailable; session left running.' }
        $root = [Windows.Automation.AutomationElement]::FromHandle($window)
        $buttons = $root.FindAll([Windows.Automation.TreeScope]::Descendants,
            (New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::ControlTypeProperty),([Windows.Automation.ControlType]::Button)))
        $close = @($buttons | Where-Object { $_.Current.AutomationId -eq 'btn-close' -or ($_.Current.Name -eq 'Close' -and -not $_.Current.IsOffscreen) }) | Select-Object -First 1
        if (-not $close) { throw 'Production Close button unavailable; session left running.' }
        $close.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
        if (-not $app.WaitForExit(25000)) { throw 'Host is Busy or did not exit normally; profile unchanged, no force-kill.' }
        if (@(Get-Process -Name pocketstream-desktop -ErrorAction SilentlyContinue).Count) { throw 'Another host started; profile restoration deferred.' }
        # Read after shutdown so that normal persistence and all discovered
        # camera/binding changes are preserved. Restore the single fixture field.
        $current = [IO.File]::ReadAllText($launch.profile.path)
        $currentSection = [regex]::Match($current, '(?ms)^\[rtsp_server\]\r?\n.*?(?=^\[|\z)')
        if (-not [regex]::IsMatch($currentSection.Value, '(?m)^enabled\s*=\s*(true|false)\s*$')) { throw 'Post-shutdown output-enable field unavailable; restoration pending.' }
        $flag = $launch.profile.original_output_enabled.ToString().ToLowerInvariant()
        $restoredSection = [regex]::Replace($currentSection.Value, '(?m)^enabled\s*=\s*(true|false)\s*$', "enabled = $flag")
        $restored = $current.Substring(0,$currentSection.Index) + $restoredSection + $current.Substring($currentSection.Index+$currentSection.Length)
        [IO.File]::WriteAllText($launch.profile.path, $restored, (New-Object Text.UTF8Encoding $false))
        if ([IO.File]::ReadAllText($launch.profile.path) -ne $restored) { throw 'Profile restoration readback failed.' }
        $record['graceful_exit'] = $true
        $record['profile_cleanup'] = 'restored original output-enable flag; preserved all current credentials, camera and pending/retained binding records'
        $record['original_output_enabled_restored'] = $launch.profile.original_output_enabled
        $record['finished_at_utc'] = [DateTime]::UtcNow.ToString('o')
        $record['native_addresses_after'] = @(Get-NetIPAddress -InterfaceIndex 15 -AddressFamily IPv4 | ForEach-Object { [ordered]@{IPAddress=[string]$_.IPAddress;PrefixLength=[int]$_.PrefixLength;PrefixOrigin=[int]$_.PrefixOrigin} })
        $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $recordPath -Encoding UTF8
    }
    Write-Output $recordPath
} catch {
    [ordered]@{at_utc=[DateTime]::UtcNow.ToString('o');diagnostic=$_.Exception.Message;finish_requested=[bool]$Finish} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage 'completion-error.json') -Encoding UTF8
    throw
}
