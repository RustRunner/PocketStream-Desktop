<# Isolated Windows Sandbox fixture. Never dot-source or run on the host.
   Results are written continuously to the dedicated writable mapping. #>
[CmdletBinding()]
param(
    [ValidateSet('Preflight', 'Supported')][string]$Mode = 'Preflight',
    [ValidateSet('HostOwner', 'InstallGate')][string]$Hold,
    [string]$SignalRoot
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Check the real account, not the environment variable. All branches, including
# mutex helpers, must pass this guard before creating files or invoking providers.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.Name.Split('\')[-1] -ne 'WDAGUtilityAccount') { throw 'This fixture runs only inside Windows Sandbox; no host changes were attempted.' }
$inputRoot = 'C:\PocketStreamQualification\Inputs'
$resultsRoot = 'C:\PocketStreamQualification\Results'
$manifest = Get-Content -LiteralPath (Join-Path $inputRoot 'fixture.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.version -ne 1 -or $manifest.host_computer -eq [Environment]::MachineName -or $PSScriptRoot -ne $inputRoot) { throw 'Sandbox identity/mapping guard failed.' }
foreach ($file in $manifest.inputs) {
    if ([IO.Path]::GetFileName($file.name) -ne $file.name -or (Get-FileHash -LiteralPath (Join-Path $inputRoot $file.name) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256) { throw 'Read-only input verification failed.' }
}
try {
    $handle = [IO.File]::Open((Join-Path $inputRoot 'fixture.json'), [IO.FileMode]::Open, [IO.FileAccess]::Write)
    $handle.Dispose()
    throw 'Input mapping is writable; refusing to run.'
} catch [UnauthorizedAccessException] { } catch [IO.IOException] { }
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Sandbox requires an elevated administrator token.' }
if ($Hold) {
    if (!$SignalRoot -or !([IO.Path]::GetFullPath($SignalRoot)).StartsWith($resultsRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid fixture signal root.' }
    # MutexSecurity's SACL path requests an additional privilege. Match the
    # production CreateMutexExW security attributes and explicit access mask.
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace PocketStream.Qualification {
 public sealed class NativeMutexLease : IDisposable {
  [StructLayout(LayoutKind.Sequential)] struct Attributes { public uint Length; public IntPtr Descriptor; public int Inherit; }
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text,uint revision,out IntPtr descriptor,IntPtr size);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateMutexExW(ref Attributes attributes,string name,uint flags,uint access);
  [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReleaseMutex(IntPtr handle);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr handle);
  [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
  IntPtr handle; uint thread;
  public NativeMutexLease(string name) {
   IntPtr descriptor;
   if(!ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;0x001f0001;;;SY)(A;;0x001f0001;;;BA)(A;;0x00120001;;;IU)S:(ML;;NW;;;ME)",1,out descriptor,IntPtr.Zero))throw new Win32Exception(Marshal.GetLastWin32Error());
   try { var attributes=new Attributes {Length=(uint)Marshal.SizeOf(typeof(Attributes)),Descriptor=descriptor};handle=CreateMutexExW(ref attributes,name,0,0x120001);var error=Marshal.GetLastWin32Error();if(handle==IntPtr.Zero)throw new Win32Exception(error); }
   finally {LocalFree(descriptor);}
   var status=WaitForSingleObject(handle,5000);
   if(status!=0 && status!=128){CloseHandle(handle);handle=IntPtr.Zero;throw new InvalidOperationException("Fixture mutex acquisition failed: "+status);}
   thread=GetCurrentThreadId();
  }
  public void Dispose(){if(handle==IntPtr.Zero)return;if(thread!=GetCurrentThreadId())throw new InvalidOperationException("Fixture owner thread changed");var released=ReleaseMutex(handle);var error=Marshal.GetLastWin32Error();CloseHandle(handle);handle=IntPtr.Zero;if(!released)throw new Win32Exception(error);}
 }
}
'@
    $mutex = [PocketStream.Qualification.NativeMutexLease]::new(('Global\PocketStream.Desktop.' + $Hold + '.v2'))
    try {
        [IO.File]::WriteAllText((Join-Path $SignalRoot 'ready'), [string]$PID)
        $deadline = [DateTime]::UtcNow.AddMinutes(3)
        while (!(Test-Path -LiteralPath (Join-Path $SignalRoot 'release')) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
    } finally { $mutex.Dispose() }
    exit 0
}
$run = Join-Path $resultsRoot ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + $manifest.id)
New-Item -ItemType Directory -Path $run | Out-Null
$report = [ordered]@{version=1;fixture_id=$manifest.id;started_utc=[DateTime]::UtcNow.ToString('o');mode=$Mode;candidate=$manifest.candidate;effective_source_sha256=$manifest.effective_source_sha256;scenarios=@();pending=@();status='preflight';host_configuration_mutated=$false;production_eligibility_relaxed=$false}
$planned = @('fresh-destination-bounds','fresh-silent','reinstall-silent','reinstall-passive','reinstall-updater','strict-entry','legacy-migration-and-preservation','migration-failure-and-retry','exact-name-collision','installer-image-in-use','installer-hostowner-busy','installation-gate-admission','standalone-uninstall','install-after-uninstall','final-uninstall')
$planned += @('fresh-passive','standalone-uninstall-passive','fresh-updater','updater-standalone-uninstall','interactive-welcome-cancel')
if ($manifest.legacy_sha256) { $planned += @('legacy-installer-upgrade','upgraded-standalone-uninstall') }
$nativeStarted = $false
function Save-Report { $report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath (Join-Path $run 'results.json') -Encoding UTF8 }
function Assert([bool]$Condition, [string]$Reason) { if (!$Condition) { throw $Reason } }
function Snapshot([string]$Label) {
    $folder = Join-Path $run $Label
    New-Item -ItemType Directory -Path $folder | Out-Null
    $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
    $rules | Export-Clixml -LiteralPath (Join-Path $folder 'rules.xml')
    foreach ($name in @('Application','Port','Address','Interface','InterfaceType','Service','Security')) {
        $command = 'Get-NetFirewall' + $name + 'Filter'
        # Query each complete filter class once. Piping every rule causes a
        # separate CIM association request per row (414 rows in this fixture).
        @(& $command -All -PolicyStore PersistentStore -ErrorAction Stop) | Export-Clixml -LiteralPath (Join-Path $folder ($name + '.xml'))
    }
    Get-NetAdapter -IncludeHidden | Export-Clixml -LiteralPath (Join-Path $folder 'adapters.xml')
    Get-NetIPAddress | Export-Clixml -LiteralPath (Join-Path $folder 'addresses.xml')
    Get-NetIPInterface | Export-Clixml -LiteralPath (Join-Path $folder 'ip-interfaces.xml')
    Get-DnsClientServerAddress | Export-Clixml -LiteralPath (Join-Path $folder 'dns.xml')
    Get-NetRoute | Export-Clixml -LiteralPath (Join-Path $folder 'routes.xml')
    if (Test-Path -LiteralPath $installRoot) {
        Get-ChildItem -LiteralPath $installRoot -Filter '*.json' -File | Copy-Item -Destination $folder
    }
    return $folder
}
function Native([string]$Label, [string]$Image, [string]$Arguments, [int[]]$Expected = @(0)) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $Image -ArgumentList $Arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $run ($Label + '.stdout.log')) -RedirectStandardError (Join-Path $run ($Label + '.stderr.log'))
    # Retain the process handle before WaitForExit so its exit code is reliable.
    $null = $process.Handle
    if (!$process.WaitForExit(120000)) { throw "$Label timed out; process $($process.Id) was left for inspection, not killed." }
    $result = [ordered]@{image=$Image;arguments=$Arguments;pid=$process.Id;exit=$process.ExitCode;elapsed_ms=$watch.ElapsedMilliseconds;expected=$Expected}
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $run ($Label + '.process.json')) -Encoding UTF8
    Assert ($process.ExitCode -in $Expected) "$Label exit $($process.ExitCode), expected $($Expected -join ',')."
    return $result
}
function Scenario([string]$Name, [scriptblock]$Action) {
    $entry = [ordered]@{name=$Name;started_utc=[DateTime]::UtcNow.ToString('o');status='running'}
    $report.scenarios += $entry
    Save-Report
    try { $null = Snapshot ($Name + '-before'); & $Action; $entry.status='passed' }
    catch { $entry.status='failed';$entry.error=$_.Exception.Message;$entry.source_line=$_.InvocationInfo.ScriptLineNumber;$entry.script_stack=$_.ScriptStackTrace;throw }
    finally { $entry.finished_utc=[DateTime]::UtcNow.ToString('o');$null=Snapshot ($Name + '-after');Save-Report }
}
function With-FixtureOwner([string]$Role, [string]$Name, [scriptblock]$Action) {
    $signal=Join-Path $run $Name
    New-Item -ItemType Directory -Path $signal | Out-Null
    $holder=Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File '+$PSCommandPath+' -Hold '+$Role+' -SignalRoot "'+$signal+'"') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $signal 'stdout.log') -RedirectStandardError (Join-Path $signal 'stderr.log')
    $null=$holder.Handle
    try {
        $deadline=[DateTime]::UtcNow.AddSeconds(10)
        while (!(Test-Path -LiteralPath (Join-Path $signal 'ready')) -and !$holder.HasExited -and [DateTime]::UtcNow -lt $deadline) {Start-Sleep -Milliseconds 100}
        Assert (Test-Path -LiteralPath (Join-Path $signal 'ready')) 'Native ownership fixture did not acquire the mutex.'
        & $Action
    } finally {
        [IO.File]::WriteAllText((Join-Path $signal 'release'),'release')
        Assert ($holder.WaitForExit(10000)) 'Fixture owner did not release normally.'
    }
}
$installRoot = Join-Path $env:ProgramW6432 'PocketStream Desktop'
$image = Join-Path $installRoot 'pocketstream-desktop.exe'
$setup = Join-Path $inputRoot 'candidate-setup.exe'
$uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PocketStream Desktop'
$roles = @(@{name='PocketStream.RTSP.Inbound.v2';display='PocketStream RTSP Server';protocol='TCP';port='8554'},@{name='PocketStream.SRT.Inbound.v2';display='PocketStream SRT Server';protocol='UDP';port='8890'})
function Owned { @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Name -in $roles.name }) }
function Verify-Templates {
    $rules = @(Owned)
    Assert ($rules.Count -eq 2) 'Expected exactly two owned templates.'
    foreach ($role in $roles) {
        $rule = @($rules | Where-Object Name -eq $role.name)
        Assert ($rule.Count -eq 1) 'Template native name is ambiguous.'
        Assert ([string]$rule[0].Enabled -eq 'False' -and [string]$rule[0].Direction -eq 'Inbound' -and [string]$rule[0].Action -eq 'Allow' -and [string]$rule[0].Profile -eq 'Any' -and $rule[0].Group -ceq 'PocketStream.Desktop.Managed.v2' -and $rule[0].DisplayName -ceq $role.display) 'Template enabled/direction/action/profile/group/display mismatch.'
        $app = @($rule | Get-NetFirewallApplicationFilter)
        $port = @($rule | Get-NetFirewallPortFilter)
        $address = @($rule | Get-NetFirewallAddressFilter)
        $iface = @($rule | Get-NetFirewallInterfaceFilter)
        $type = @($rule | Get-NetFirewallInterfaceTypeFilter)
        $service = @($rule | Get-NetFirewallServiceFilter)
        $security = @($rule | Get-NetFirewallSecurityFilter)
        Assert ($app.Count -eq 1 -and $app[0].Program -ieq $image) 'Template Program mismatch.'
        Assert ($port.Count -eq 1 -and [string]$port[0].Protocol -in @($role.protocol, $(if ($role.protocol -eq 'TCP') {'6'} else {'17'})) -and [string]$port[0].LocalPort -eq $role.port -and [string]$port[0].RemotePort -eq 'Any' -and [string]$port[0].DynamicTarget -eq 'Any') 'Template port restriction mismatch.'
        Assert ($address.Count -eq 1 -and [string]$address[0].LocalAddress -eq 'Any' -and [string]$address[0].RemoteAddress -eq 'Any' -and $iface.Count -eq 1 -and [string]$iface[0].InterfaceAlias -eq 'Any' -and $type.Count -eq 1 -and [string]$type[0].InterfaceType -eq 'Any') 'Template address/interface restriction mismatch.'
        Assert ($service.Count -eq 1 -and [string]$service[0].Service -eq 'Any' -and $security.Count -eq 1 -and [string]$security[0].Authentication -eq 'NotRequired' -and [string]$security[0].Encryption -eq 'NotRequired' -and [string]$security[0].OverrideBlockRules -eq 'False') 'Template security/service mismatch.'
        Assert ([string]$app[0].Package -in @('Any','*','') -and [string]$rule[0].EdgeTraversalPolicy -eq 'Block' -and [string]$rule[0].LooseSourceMapping -eq 'False' -and [string]$rule[0].LocalOnlyMapping -eq 'False' -and @($rule[0].Platform | Where-Object {$_ -and $_ -ne 'Any'}).Count -eq 0 -and @($rule[0].RemoteDynamicKeywordAddresses | Where-Object {$_}).Count -eq 0) 'Unexpected package/platform/mapping/edge restriction.'
        Assert ([string]$security[0].LocalUser -in @('Any','*') -and [string]$security[0].RemoteUser -in @('Any','*') -and [string]$security[0].RemoteMachine -in @('Any','*')) 'Unexpected security identity restriction.'
    }
}
function Preserved([string[]]$Names) {
    @((Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object Name -in $Names) | Sort-Object Name | ForEach-Object {
        [ordered]@{rule=($_ | Select-Object Name,DisplayName,Group,Enabled,Direction,Action,Profile,EdgeTraversalPolicy,LooseSourceMapping,LocalOnlyMapping,Platform,RemoteDynamicKeywordAddresses);app=($_|Get-NetFirewallApplicationFilter|Select-Object Program,Package);port=($_|Get-NetFirewallPortFilter|Select-Object Protocol,LocalPort,RemotePort,DynamicTarget);address=($_|Get-NetFirewallAddressFilter|Select-Object LocalAddress,RemoteAddress);interface=($_|Get-NetFirewallInterfaceFilter|Select-Object InterfaceAlias);type=($_|Get-NetFirewallInterfaceTypeFilter|Select-Object InterfaceType);service=($_|Get-NetFirewallServiceFilter|Select-Object Service);security=($_|Get-NetFirewallSecurityFilter|Select-Object Authentication,Encryption,LocalUser,RemoteUser,RemoteMachine,OverrideBlockRules)}
    }) | ConvertTo-Json -Depth 12 -Compress
}
function Wait-Uninstalled {
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    do {
        # The standalone NSIS launcher can exit before its copied child. File,
        # registration and rule removal are distinct child completion steps.
        if (!(Test-Path -LiteralPath $image) -and !(Test-Path -LiteralPath $uninstallKey) -and @(Owned).Count -eq 0) { return }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Uninstall postconditions incomplete after bounded wait.'
}
try {
    Start-Transcript -LiteralPath (Join-Path $run 'transcript.log') | Out-Null
    $services = @(foreach ($name in @('BFE','MpsSvc','Winmgmt')) { $service=Get-Service -Name $name -ErrorAction SilentlyContinue; [ordered]@{name=$name;present=($null -ne $service);status=$(if ($service) {$service.Status.ToString()} else {'missing'})} })
    $modules = @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management','CimCmdlets','NetAdapter','NetTCPIP','NetSecurity')
    $moduleResults = @()
    foreach ($name in $modules) {
        $path=Join-Path $env:WINDIR ('System32\WindowsPowerShell\v1.0\Modules\' + $name + '\' + $name + '.psd1')
        $moduleResults += [ordered]@{name=$name;path=$path;present=(Test-Path -LiteralPath $path)}
    }
    $webview = @(foreach ($path in @('HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}','HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}')) { if (Test-Path -LiteralPath $path) { Get-ItemProperty -LiteralPath $path | Select-Object PSPath,pv } })
    $report.preflight=[ordered]@{identity=$identity.Name;computer=[Environment]::MachineName;elevated=$true;process_64bit=[Environment]::Is64BitProcess;windows=[Environment]::OSVersion.Version.ToString();powershell=$PSVersionTable.PSVersion.ToString();services=$services;modules=$moduleResults;webview=$webview;installer_bootstrap_network_required=($webview.Count -eq 0);program_files=$env:ProgramW6432;inputs_read_only=$true}
    $report.preflight.session_id=[Diagnostics.Process]::GetCurrentProcess().SessionId
    & "$env:WINDIR\System32\whoami.exe" /all | Set-Content -LiteralPath (Join-Path $run 'token-groups-privileges.txt') -Encoding UTF8
    & "$env:WINDIR\System32\whoami.exe" /logonid | Set-Content -LiteralPath (Join-Path $run 'logon-id.txt') -Encoding UTF8
    Get-Acl -LiteralPath $env:ProgramW6432 | Export-Clixml -LiteralPath (Join-Path $run 'program-files-acl.xml')
    Get-PSDrive -Name C | Select-Object Name,Used,Free | Export-Clixml -LiteralPath (Join-Path $run 'disk-space.xml')
    $report.preflight.pocketstream_profile_exists=Test-Path -LiteralPath (Join-Path $env:APPDATA 'PocketStream')
    Save-Report
    $missing = @($services | Where-Object { !$_.present -or $_.status -ne 'Running' })
    if ($missing.Count -or @($moduleResults | Where-Object { !$_.present }).Count -or ![Environment]::Is64BitProcess -or $PSVersionTable.PSVersion.Major -ne 5) {
        $report.status='pending: Sandbox prerequisites unavailable'
        $report.pending += 'Firewall/install matrix: required Windows services/modules/token/platform must be available; no substitute providers or weaker adapter checks were used.'
        return
    }
    foreach ($module in $moduleResults) { Import-Module -Name $module.path -ErrorAction Stop }
    $null = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
    $report.preflight.firewall_provider_observed=$true
    $report.preflight.adapters=@(Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceGuid,ifIndex,HardwareInterface,Status)
    $null = Snapshot 'baseline'
    if ($Mode -eq 'Preflight') { $report.status='preflight passed; supported matrix not requested';return }
    Assert (!(Test-Path -LiteralPath $uninstallKey) -and !(Test-Path -LiteralPath $image) -and @(Owned).Count -eq 0) 'Use a fresh Sandbox for a new supported run.'
    Assert (!$report.preflight.pocketstream_profile_exists) 'Unexpected pre-existing PocketStream profile; use a fresh Sandbox.'
    $nativeStarted = $true
    Scenario 'fresh-destination-bounds' {
        $outside=Join-Path $env:USERPROFILE 'Desktop\PocketStreamForbidden'
        $traversal=$env:ProgramW6432+'\..\PocketStreamForbidden'
        foreach($entry in @(@{name='outside-protected-root';path=$outside},@{name='traversal-outside-root';path=$traversal})) {
            $null=Native $entry.name $setup ('/S /D='+$entry.path) @(71)
        }
        Assert (!(Test-Path -LiteralPath $outside) -and !(Test-Path -LiteralPath 'C:\PocketStreamForbidden') -and !(Test-Path -LiteralPath $image) -and !(Test-Path -LiteralPath $uninstallKey) -and @(Owned).Count -eq 0) 'Rejected destination changed installed state.'
    }
    Scenario 'interactive-welcome-cancel' {
        $process=Start-Process -FilePath $setup -WindowStyle Normal -PassThru -RedirectStandardOutput (Join-Path $run 'welcome-cancel.stdout.log') -RedirectStandardError (Join-Path $run 'welcome-cancel.stderr.log')
        $null=$process.Handle
        $ack=& "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File (Join-Path $inputRoot 'verify-a1-production-smoke.ps1') -Mode CancelDialog -OwnerPid $process.Id -ExpectedText 'Welcome' -Executable $setup
        Assert ($LASTEXITCODE -eq 0) 'Interactive welcome cancellation was not observed.'
        Assert ($process.WaitForExit(10000)) 'Cancelled installer did not exit normally.'
        Assert (!(Test-Path -LiteralPath $image) -and !(Test-Path -LiteralPath $uninstallKey) -and @(Owned).Count -eq 0 -and !(Test-Path -LiteralPath (Join-Path $env:APPDATA 'PocketStream'))) 'Welcome cancellation changed installed/application state.'
        [ordered]@{pid=$process.Id;exit=$process.ExitCode;acknowledgement=($ack|Out-String|ConvertFrom-Json);installed=$false;profile_initialized=$false}|ConvertTo-Json -Depth 7|Set-Content -LiteralPath (Join-Path $run 'welcome-cancel.json') -Encoding UTF8
    }
    Scenario 'fresh-silent' {
        $null=Native 'fresh-silent' $setup ('/S /D=' + $installRoot)
        Assert (Test-Path -LiteralPath $image) 'Installed executable missing.'
        Assert ((Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant() -eq $manifest.candidate.embedded.sha256) 'Installed image is not the exact packaged candidate.'
        foreach ($file in $manifest.payload) { Assert ((Get-FileHash -LiteralPath (Join-Path $installRoot $file.path) -Algorithm SHA256).Hash.ToLowerInvariant() -eq $file.sha256) ('Installed payload mismatch: ' + $file.path) }
        Verify-Templates
        Assert (Test-Path -LiteralPath $uninstallKey) 'Uninstall registration missing.'
    }
    foreach ($modeEntry in @(@{name='reinstall-silent';args='/S'},@{name='reinstall-passive';args='/P'},@{name='reinstall-updater';args='/S /UPDATE'})) {
        Scenario $modeEntry.name { $null=Native $modeEntry.name $setup $modeEntry.args;Verify-Templates }
    }
    Scenario 'strict-entry' {
        foreach ($entry in @(@{name='unknown-argument';image=$image;args='--qualification-unknown';exit=64},@{name='malformed-maintenance';image=$image;args='--firewall-maintenance';exit=64},@{name='unprotected-maintenance';image=(Join-Path $inputRoot 'candidate-staged.exe');args='--firewall-maintenance install';exit=77})) {
            $null=Native $entry.name $entry.image $entry.args @($entry.exit)
        }
    }
    $seed = 'PocketStream.Qualification.' + $manifest.id
    $preserveNames = @(($seed+'.block'),($seed+'.foreign'),($seed+'.unrelated'))
    Scenario 'legacy-migration-and-preservation' {
        New-NetFirewallRule -Name $preserveNames[0] -DisplayName 'PocketStream Query User qualification' -Direction Inbound -Action Block -Program $image -Protocol TCP -LocalPort 18554 -Profile Any | Out-Null
        New-NetFirewallRule -Name $preserveNames[1] -DisplayName 'PocketStream RTSP Server' -Direction Inbound -Action Allow -Program (Join-Path $env:WINDIR 'System32\notepad.exe') -Protocol TCP -LocalPort 18555 -Profile Any | Out-Null
        New-NetFirewallRule -Name $preserveNames[2] -DisplayName 'Unrelated qualification block' -Direction Inbound -Action Block -Protocol UDP -LocalPort 18891 -Profile Private | Out-Null
        $before=Preserved $preserveNames
        $legacyNames=@()
        foreach ($role in $roles) {
            foreach ($suffix in @('enabled','disabled','scoped')) {
                $name=$seed+'.legacy.'+$role.protocol+'.'+$suffix;$legacyNames += $name
                $program=$(if($suffix -eq 'scoped'){$image}else{'Any'})
                New-NetFirewallRule -Name $name -DisplayName $role.display -Direction Inbound -Action Allow -Profile Any -Protocol $role.protocol -LocalPort 18554 -Program $program -Enabled $(if($suffix -eq 'disabled'){'False'}else{'True'}) | Out-Null
            }
        }
        $null=Native 'legacy-maintenance' $image '--firewall-maintenance install'
        Assert (@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object Name -in $legacyNames).Count -eq 0) 'Recognized legacy rules remain.'
        Verify-Templates
        Assert ((Preserved $preserveNames) -ceq $before) 'A deny or foreign rule/filter changed.'
        $null=Native 'repeat-maintenance' $image '--firewall-maintenance install'
        Verify-Templates
        Assert ((Preserved $preserveNames) -ceq $before) 'Repeated migration changed preserved policy.'
    }
    Scenario 'migration-failure-and-retry' {
        $name=$seed+'.conflict'
        New-NetFirewallRule -Name $name -DisplayName 'PocketStream SRT Server' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 18890 -Profile Private | Out-Null
        $before=Preserved (@($name)+$preserveNames)
        $null=Native 'conflict-maintenance' $image '--firewall-maintenance install' @(71)
        Assert ((Preserved (@($name)+$preserveNames)) -ceq $before) 'Conflict/foreign/deny policy changed.'
        Verify-Templates
        Get-NetFirewallRule -Name $name -PolicyStore PersistentStore | Remove-NetFirewallRule
        $null=Native 'conflict-retry' $image '--firewall-maintenance install'
        Verify-Templates
    }
    Scenario 'exact-name-collision' {
        Get-NetFirewallRule -Name $roles[0].name -PolicyStore PersistentStore | Remove-NetFirewallRule
        New-NetFirewallRule -Name $roles[0].name -DisplayName 'Foreign native name collision' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 18892 -Program (Join-Path $env:WINDIR 'System32\notepad.exe') -Group 'Foreign.Owner' -Profile Private | Out-Null
        $before=Preserved (@($roles[0].name)+$preserveNames)
        $null=Native 'collision-maintenance' $image '--firewall-maintenance install' @(71)
        Assert ((Preserved (@($roles[0].name)+$preserveNames)) -ceq $before) 'Colliding foreign rule/filter changed.'
        Get-NetFirewallRule -Name $roles[0].name -PolicyStore PersistentStore | Remove-NetFirewallRule
        $null=Native 'collision-retry' $image '--firewall-maintenance install'
        Verify-Templates
    }
    Scenario 'installer-image-in-use' {
        $before=(Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash
        $held=[IO.File]::Open($image,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try { $null=Native 'image-in-use' $setup '/S' @(71) } finally { $held.Dispose() }
        Assert ((Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash -eq $before) 'Preflight image-in-use changed the image.'
        Verify-Templates
        $null=Native 'after-image-in-use' $setup '/S'
    }
    Scenario 'installer-hostowner-busy' {
        With-FixtureOwner 'HostOwner' 'host-owner' {
            $before=(Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash
            $null=Native 'busy-maintenance' $image '--firewall-maintenance install' @(73)
            $null=Native 'busy-installer' $setup '/S' @(71)
            Assert ((Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash -eq $before) 'Busy installer replaced the image.'
        }
        $null=Native 'after-busy-reinstall' $setup '/S'
        Verify-Templates
    }
    Scenario 'installation-gate-admission' {
        With-FixtureOwner 'InstallGate' 'installation-gate' {
            $null=Native 'maintenance-under-installation-gate' $image '--firewall-maintenance install'
            Verify-Templates
            Assert (!(Test-Path -LiteralPath (Join-Path $env:APPDATA 'PocketStream'))) 'Maintenance initialized the application profile.'
            $out=Join-Path $run 'installer-busy-host.stdout.log'
            $err=Join-Path $run 'installer-busy-host.stderr.log'
            $hostProcess=Start-Process -FilePath $image -WindowStyle Normal -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
            $null=$hostProcess.Handle
            # Reuse the existing PID/image/text-bound native dialog fixture.
            $ack=& "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File (Join-Path $inputRoot 'verify-a1-production-smoke.ps1') -Mode CancelDialog -OwnerPid $hostProcess.Id -ExpectedText 'PocketStream installation is busy' -Executable $image
            Assert ($LASTEXITCODE -eq 0) 'InstallerBusy native message was not observed/dismissed.'
            Assert ($hostProcess.WaitForExit(10000)) 'Refused host did not exit after dismissal.'
            Assert ($hostProcess.ExitCode -eq 0 -and [IO.File]::ReadAllText($err).Contains('PocketStream installation is busy: Busy')) 'Host refusal was not the bounded installation Busy path.'
            Assert (!(Test-Path -LiteralPath (Join-Path $env:APPDATA 'PocketStream')) -and !(Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'PocketStream\logs'))) 'Refused host initialized profile/log state.'
            [ordered]@{pid=$hostProcess.Id;exit=$hostProcess.ExitCode;acknowledgement=($ack|Out-String|ConvertFrom-Json);profile_initialized=$false;log_initialized=$false}|ConvertTo-Json -Depth 7|Set-Content -LiteralPath (Join-Path $run 'installer-busy-host.json') -Encoding UTF8
        }
    }
    Scenario 'standalone-uninstall' {
        $before=Preserved $preserveNames
        $null=Native 'standalone-uninstall' (Join-Path $installRoot 'uninstall.exe') '/S'
        Wait-Uninstalled
        Assert (!(Test-Path -LiteralPath $image) -and !(Test-Path -LiteralPath $uninstallKey) -and @(Owned).Count -eq 0) 'Uninstall postconditions incomplete.'
        Assert ((Preserved $preserveNames) -ceq $before) 'Uninstall changed preserved rules/filters.'
    }
    Scenario 'install-after-uninstall' { $null=Native 'install-after-uninstall' $setup '/S';Verify-Templates }
    Scenario 'final-uninstall' {
        $null=Native 'final-uninstall' (Join-Path $installRoot 'uninstall.exe') '/S'
        Wait-Uninstalled
        Assert (!(Test-Path -LiteralPath $image) -and !(Test-Path -LiteralPath $uninstallKey) -and @(Owned).Count -eq 0) 'Final uninstall incomplete.'
    }
    foreach ($modeEntry in @(@{name='fresh-passive';args='/P';uninstall='standalone-uninstall-passive';uninstallArgs='/P'},@{name='fresh-updater';args='/S /UPDATE';uninstall='updater-standalone-uninstall';uninstallArgs='/S'})) {
        Scenario $modeEntry.name {
            $null=Native $modeEntry.name $setup ($modeEntry.args+' /D='+$installRoot)
            Assert ((Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant() -eq $manifest.candidate.embedded.sha256) 'Fresh mode installed a different image.'
            Verify-Templates
            Assert (!(Test-Path -LiteralPath (Join-Path $env:APPDATA 'PocketStream'))) 'Install without relaunch initialized the application profile.'
        }
        Scenario $modeEntry.uninstall {
            $before=Preserved $preserveNames
            $null=Native $modeEntry.uninstall (Join-Path $installRoot 'uninstall.exe') $modeEntry.uninstallArgs
            Wait-Uninstalled
            Assert ((Preserved $preserveNames) -ceq $before) 'Mode uninstall changed preserved rules/filters.'
        }
    }
    if ($manifest.legacy_sha256) {
        Scenario 'legacy-installer-upgrade' {
            $null=Native 'legacy-install' (Join-Path $inputRoot 'legacy-setup.exe') ('/S /D=' + $installRoot)
            Assert (Test-Path -LiteralPath $image) 'Legacy executable missing.'
            $legacyHash=(Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant()
            Assert ($legacyHash -ne $manifest.candidate.embedded.sha256) 'Legacy and candidate images are identical.'
            $report.legacy_installed_image_sha256=$legacyHash
            $legacyNames=@()
            foreach ($role in $roles) {
                $name=$seed+'.upgrade.'+$role.protocol;$legacyNames += $name
                New-NetFirewallRule -Name $name -DisplayName $role.display -Direction Inbound -Action Allow -Profile Any -Protocol $role.protocol -LocalPort 18556 | Out-Null
            }
            $before=Preserved $preserveNames
            $null=Native 'legacy-upgrade' $setup '/S /UPDATE'
            Assert ((Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant() -eq $manifest.candidate.embedded.sha256) 'Upgrade did not replace the legacy image.'
            Verify-Templates
            Assert (@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object Name -in $legacyNames).Count -eq 0 -and (Preserved $preserveNames) -ceq $before) 'Upgrade migration or preservation incomplete.'
        }
        Scenario 'upgraded-standalone-uninstall' {
            $null=Native 'upgraded-uninstall' (Join-Path $installRoot 'uninstall.exe') '/S'
            Wait-Uninstalled
            Assert (!(Test-Path -LiteralPath $image) -and !(Test-Path -LiteralPath $uninstallKey) -and @(Owned).Count -eq 0) 'Upgraded uninstall incomplete.'
        }
    } else { $report.pending += 'Actual legacy-installer upgrade: no independently hashed predecessor supplied.' }
    $report.status='supported automated subset passed; full qualification incomplete'
} catch { $report.status=$(if($nativeStarted){'supported scenario failed'}else{'preflight failed; native scenarios pending'});$report.error=$_.Exception.Message;$report.source_line=$_.InvocationInfo.ScriptLineNumber;$report.script_stack=$_.ScriptStackTrace }
finally {
    $report.pending += @('Interactive install/uninstall and cancellation, relaunch timing, every failure/exit path and continuous parent/child native mutex observation.','Legacy runtime rule emission (upgrade uses explicitly seeded documented historical shapes), locked payload Ignore/delete, child-uninstaller error propagation and partial-provider fault injection.','Listener lifecycle/Any reset/explicit physical adapter, all native address writes, cross-account/logon/integrity ownership, hardware/G3/signed update/endurance.','A successful conflict case is not partial-provider qualification; virtual adapters do not satisfy production physical-adapter eligibility.')
    $report.finished_utc=[DateTime]::UtcNow.ToString('o')
    $completed=@($report.scenarios | ForEach-Object {$_.name})
    $report.unexecuted_scenarios=@($planned | Where-Object {$_ -notin $completed} | ForEach-Object {[ordered]@{name=$_;status='pending'}})
    $report.cleanup=[ordered]@{pocketstream_profile_exists=(Test-Path -LiteralPath (Join-Path $env:APPDATA 'PocketStream'));installed_image_remains=(Test-Path -LiteralPath $image);uninstall_registration_remains=(Test-Path -LiteralPath $uninstallKey);sandbox_left_open=$true;seeded_policy_and_diagnostics='Preserved for inspection inside the disposable guest; close Sandbox only after exports are verified.'}
    $report.input_hashes_after=@(foreach($file in $manifest.inputs){[ordered]@{name=$file.name;sha256=(Get-FileHash -LiteralPath (Join-Path $inputRoot $file.name) -Algorithm SHA256).Hash.ToLowerInvariant();matches=((Get-FileHash -LiteralPath (Join-Path $inputRoot $file.name) -Algorithm SHA256).Hash.ToLowerInvariant() -eq $file.sha256)}})
    Save-Report
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    Write-Output (Join-Path $run 'results.json')
}
