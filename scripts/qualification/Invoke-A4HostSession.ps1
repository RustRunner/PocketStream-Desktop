<# Explicitly approved, reversible host smoke. No installation/migration, address,
   DHCP, DNS, route, adapter restart, Wi-Fi change, automated motion or reboot.
   The only native setup writes disable two exact historical product Allow rules;
   their original Enabled values and every profile file are restored on Close. #>
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$CandidateRecord,
 [Parameter(Mandatory=$true)][string]$InspectionRoot,
 [Parameter(Mandatory=$true)][string]$RunRoot,
 [switch]$AllowTemporaryRuleDisable,
 [switch]$AllowSecondaryAddressTest,
 [switch]$AllowRecordingTest
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if(!$AllowTemporaryRuleDisable){throw 'Specific operator approval for temporary rule disable is required.'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if($identity.User.Value -ne 'S-1-5-21-1244688789-2835658792-593928238-1001' -or !(New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Same-account elevated session required.'}
$repository=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$candidate=Get-Content -LiteralPath $CandidateRecord -Raw -Encoding UTF8|ConvertFrom-Json
$baseline=Get-Content -LiteralPath (Join-Path $InspectionRoot 'inspection.json') -Raw -Encoding UTF8|ConvertFrom-Json
if($baseline.status -ne 'read-only inspection complete; no host mutation authorized by this record' -or !$baseline.elevated -or !$baseline.profile_preconditions.pending_empty){throw 'Complete elevated inspection/recovery copies required.'}
if(Test-Path -LiteralPath $RunRoot){throw 'Use a new run directory.'}
New-Item -ItemType Directory -Path $RunRoot|Out-Null
$exe=Join-Path $repository $candidate.artifacts.staged.path
if((Get-FileHash -LiteralPath $exe).Hash.ToLowerInvariant() -ne $candidate.artifacts.staged.sha256){throw 'Candidate hash mismatch.'}
$names=@('{66a708dc-fe09-4619-90c6-ce1440a0ecf6}','{65fbdd22-e374-407a-a3fc-8934788c1c5a}')
$record=[ordered]@{started_utc=[DateTime]::UtcNow.ToString('o');status='preflight';candidate_sha256=$candidate.artifacts.staged.sha256;profile_restored=$false;rules_restored=$false;native_unchanged=$false;motion_automation=$false;wifi_configuration_writes=$false;launcher_address_writes=$false;secondary_address_test_permitted=$AllowSecondaryAddressTest.IsPresent;recording_test_permitted=$AllowRecordingTest.IsPresent;diagnostic=$null}
$originalRules=@();$profileChanged=$false;$app=$null
function Save([string]$Name){$record|ConvertTo-Json -Depth 14|Set-Content -LiteralPath (Join-Path $RunRoot $Name) -Encoding UTF8}
function Native-State {
 $nic=@(Get-NetAdapter|Where-Object {[string]$_.InterfaceGuid -eq '{812AD22F-3345-4817-B6D7-708D769E69AC}' -and $_.MacAddress -eq '40-C2-BA-CF-D5-75'})
 if($nic.Count -ne 1 -or $nic[0].ifIndex -ne 15){throw 'Ethernet identity changed.'}
 [ordered]@{adapters=@(Get-NetAdapter|Where-Object ifIndex -in @(8,15)|Sort-Object ifIndex|Select-Object ifIndex,InterfaceGuid,MacAddress,Status);
 addresses=@(Get-NetIPAddress -AddressFamily IPv4|Where-Object InterfaceIndex -in @(8,15)|Sort-Object InterfaceIndex,IPAddress|Select-Object InterfaceIndex,IPAddress,PrefixLength,PrefixOrigin,SkipAsSource);
 interfaces=@(Get-NetIPInterface -AddressFamily IPv4|Where-Object InterfaceIndex -in @(8,15)|Sort-Object InterfaceIndex|Select-Object InterfaceIndex,Dhcp,InterfaceMetric);
 dns=@(Get-DnsClientServerAddress -AddressFamily IPv4|Where-Object InterfaceIndex -in @(8,15)|Sort-Object InterfaceIndex|Select-Object InterfaceIndex,ServerAddresses);
 routes=@(Get-NetRoute -AddressFamily IPv4|Where-Object InterfaceIndex -in @(8,15)|Sort-Object InterfaceIndex,DestinationPrefix,NextHop|Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,Protocol)}
}
try{
 if(@(Get-Process -Name pocketstream-desktop -ErrorAction SilentlyContinue).Count){throw 'Another host exists; no changes made.'}
 foreach($f in $baseline.profile_files){if((Get-FileHash -LiteralPath $f.path).Hash.ToLowerInvariant() -ne $f.sha256 -or (Get-FileHash -LiteralPath $f.backup).Hash.ToLowerInvariant() -ne $f.sha256){throw 'Profile or private backup changed; refresh preflight.'}}
 $record.native_before=Native-State
 if($AllowSecondaryAddressTest){
  if(@(Get-NetIPAddress -AddressFamily IPv4|Where-Object IPAddress -eq '192.0.2.250').Count -or @(Get-NetRoute -AddressFamily IPv4|Where-Object DestinationPrefix -eq '192.0.2.0/24').Count){throw 'Test address/subnet is already present; no write test permitted.'}
  if(@(Get-NetRoute -InterfaceIndex 15 -AddressFamily IPv4|Where-Object DestinationPrefix -eq '0.0.0.0/0').Count){throw 'Ethernet acquired a default route; no write test permitted.'}
 }
 $all=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
 if(@($all|Where-Object {$_.Name -in @('PocketStream.RTSP.Inbound.v2','PocketStream.SRT.Inbound.v2')}).Count){throw 'Unexpected owned v2 rules; no startup writes approved.'}
 $originalRules=@($all|Where-Object Name -in $names)
 if($originalRules.Count -ne 2 -or @($originalRules|Where-Object {[string]$_.Enabled -ne 'True' -or [string]$_.Action -ne 'Allow' -or $_.Group -or $_.DisplayName -notin @('PocketStream RTSP Server','PocketStream SRT Server')}).Count){throw 'Exact approved legacy rules changed.'}
 $config=Join-Path $env:APPDATA 'PocketStream\config.toml';$text=[IO.File]::ReadAllText($config)
 if($text -notmatch '(?m)^network_mode\s*=\s*"static_auto"\s*$'){throw 'Original network mode changed.'}
 $updated=[regex]::Replace($text,'(?m)^network_mode\s*=\s*"static_auto"\s*$','network_mode = "static_manual"')
 $section=[regex]::Match($updated,'(?ms)^\[rtsp_server\]\r?\n.*?(?=^\[|\z)')
 if(!$section.Success -or $section.Value -notmatch '(?m)^enabled\s*=\s*(true|false)\s*$'){throw 'Output-enable field missing.'}
 $replacement=[regex]::Replace($section.Value,'(?m)^enabled\s*=\s*(true|false)\s*$','enabled = false')
 $updated=$updated.Substring(0,$section.Index)+$replacement+$updated.Substring($section.Index+$section.Length)
 [IO.File]::WriteAllText($config,$updated,[Text.UTF8Encoding]::new($false));$profileChanged=$true
 Disable-NetFirewallRule -Name $names -ErrorAction Stop
 if(@(Get-NetFirewallRule -Name $names|Where-Object {[string]$_.Enabled -ne 'False'}).Count){throw 'Temporary disable readback failed.'}
 $record.temporary_disabled_native_names=$names;$record.auto_adoption_disabled=$true;$record.output_disabled=$true
 $app=Start-Process -FilePath $exe -WorkingDirectory (Split-Path -Parent $exe) -WindowStyle Normal -PassThru -RedirectStandardOutput (Join-Path $RunRoot 'application.stdout.log') -RedirectStandardError (Join-Path $RunRoot 'application.stderr.log');$null=$app.Handle
 $record.application_pid=$app.Id;$record.status='running; approved setup applied, candidate observations pending';Save 'launch-result.json'
 $app.WaitForExit();$record.exit_code=$app.ExitCode
 $record.native_after=Native-State
 $record.native_unchanged=($record.native_before|ConvertTo-Json -Depth 10 -Compress) -ceq ($record.native_after|ConvertTo-Json -Depth 10 -Compress)
 $record.status='candidate exited; restoring approved setup'
}catch{$record.diagnostic=$_.Exception.Message;$record.status='incomplete; inspect diagnostic'}
finally{
 if($null -eq $app -or $app.HasExited){
  foreach($rule in $originalRules){Set-NetFirewallRule -Name $rule.Name -Enabled ([string]$rule.Enabled) -ErrorAction Stop}
  $record.rules_restored=$originalRules.Count -eq 2 -and @((Get-NetFirewallRule -Name $names)|Where-Object {[string]$_.Enabled -ne 'True'}).Count -eq 0
  if($profileChanged){
   $logs=Join-Path $RunRoot 'private-session-files';New-Item -ItemType Directory -Path $logs|Out-Null
   foreach($f in $baseline.profile_files){if(Test-Path -LiteralPath $f.path){Copy-Item -LiteralPath $f.path -Destination (Join-Path $logs ([IO.Path]::GetFileName($f.path)))};if((Get-FileHash -LiteralPath $f.backup).Hash.ToLowerInvariant() -ne $f.sha256){throw 'Backup changed; restoration halted'};Copy-Item -LiteralPath $f.backup -Destination $f.path -Force}
   $record.profile_restored=@($baseline.profile_files|Where-Object {(Get-FileHash -LiteralPath $_.path).Hash.ToLowerInvariant() -ne $_.sha256}).Count -eq 0
  }
  $all=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop);$all|Export-Clixml -LiteralPath (Join-Path $RunRoot 'rules-after.xml')
  foreach($name in @('Application','Port','Address','Interface','InterfaceType','Service','Security')){$cmd='Get-NetFirewall'+$name+'Filter';@(& $cmd -All -PolicyStore PersistentStore -ErrorAction Stop)|Export-Clixml -LiteralPath (Join-Path $RunRoot ($name+'-after.xml'))}
  $record.product_processes_remaining=@(Get-Process -Name pocketstream-desktop -ErrorAction SilentlyContinue|Select-Object Id,Path)
 }else{$record.status='candidate remains active; restoration deferred until normal Close'}
 $record.finished_utc=[DateTime]::UtcNow.ToString('o');Save 'completion-result.json'
}
