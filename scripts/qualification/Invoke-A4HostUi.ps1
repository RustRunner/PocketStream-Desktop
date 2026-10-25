<# Real candidate controls only. PTU motion is always left to the operator. #>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$RunRoot,[Parameter(Mandatory=$true)][string]$CandidateRecord,[ValidateSet('Inspect','Settings','Confirmations','Playback','Close','AddSecondary','RemoveSecondary','ConfirmTestRemoval','RecordStart','RecordStop')][string]$Mode='Inspect')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$id=[Security.Principal.WindowsIdentity]::GetCurrent();if($id.User.Value -ne 'S-1-5-21-1244688789-2835658792-593928238-1001' -or !(New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Same-account elevation required.'}
$repository=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$candidate=Get-Content -LiteralPath $CandidateRecord -Raw|ConvertFrom-Json
$launch=Get-Content -LiteralPath (Join-Path $RunRoot 'launch-result.json') -Raw|ConvertFrom-Json
if($Mode -in @('AddSecondary','RemoveSecondary','ConfirmTestRemoval') -and (!$launch.PSObject.Properties['secondary_address_test_permitted'] -or !$launch.secondary_address_test_permitted)){throw 'This host session is not authorized for secondary address writes.'}
if($Mode -in @('RecordStart','RecordStop') -and (!$launch.PSObject.Properties['recording_test_permitted'] -or !$launch.recording_test_permitted)){throw 'This host session is not authorized for recording.'}
$exe=Join-Path $repository $candidate.artifacts.staged.path
$app=Get-Process -Id $launch.application_pid
if($app.Path -ine $exe -or (Get-FileHash -LiteralPath $exe).Hash.ToLowerInvariant() -ne $launch.candidate_sha256){throw 'Unexpected candidate identity.'}
Add-Type -AssemblyName UIAutomationClient;Add-Type -AssemblyName UIAutomationTypes
$condition=New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::ProcessIdProperty),$app.Id
$tops=[Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children,$condition)
$root=@($tops|Where-Object {$_.Current.ClassName -eq 'Tauri Window'})|Select-Object -First 1
if(!$root){throw 'Owned candidate window missing.'}
function Element([string]$Id){$until=[DateTime]::UtcNow.AddSeconds(10);do{$e=$root.FindFirst([Windows.Automation.TreeScope]::Descendants,(New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::AutomationIdProperty),$Id));if($e){return $e};Start-Sleep -Milliseconds 100}while([DateTime]::UtcNow -lt $until);throw ('Missing control: '+$Id)}
function Click([string]$Id){$e=Element $Id;if(!$e.Current.IsEnabled -or $e.Current.IsOffscreen){throw ('Unavailable control: '+$Id)};$e.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()}
function Select-Radio([string]$Id){(Element $Id).GetCurrentPattern([Windows.Automation.SelectionItemPattern]::Pattern).Select()}
function Read-Shared([string]$Path){$s=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete));$r=New-Object IO.StreamReader $s;try{return $r.ReadToEnd()}finally{$r.Dispose()}}
function Cancel([string]$Text){$result=& "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repository 'scripts\verify-a1-production-smoke.ps1') -Mode CancelDialog -OwnerPid $app.Id -ExpectedText $Text -Executable $exe;if($LASTEXITCODE -ne 0){throw 'Actual native dialog Cancel failed.'};return ($result|Out-String|ConvertFrom-Json)}
$record=[ordered]@{mode=$Mode;started_utc=[DateTime]::UtcNow.ToString('o');pid=$app.Id;artifact_sha256=$launch.candidate_sha256;steps=@();status='pending';automated_motion=$false}
try{
 if($Mode -eq 'Inspect'){
  $record.controls=@($root.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)|Where-Object {!$_.Current.IsPassword -and ($_.Current.AutomationId -or $_.Current.ControlType -eq [Windows.Automation.ControlType]::Hyperlink)}|ForEach-Object {@{id=$_.Current.AutomationId;name=$_.Current.Name;type=$_.Current.ControlType.ProgrammaticName;enabled=$_.Current.IsEnabled;offscreen=$_.Current.IsOffscreen}})
 }
 if($Mode -eq 'Confirmations'){
  $log=Read-Shared (Join-Path $RunRoot 'application.stderr.log')
  if(!$log.Contains('Native startup reconciliation completed; conflicting writes available')){throw 'Successful native startup must precede confirmations.'}
  $config=Join-Path $env:APPDATA 'PocketStream\config.toml'
  $open=$root.FindFirst([Windows.Automation.TreeScope]::Descendants,(New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::AutomationIdProperty),'ip-config-close'))
  if(!$open -or $open.Current.IsOffscreen){Click 'btn-ip-config';Start-Sleep -Milliseconds 300}
  $primary=(Element 'static-ip').GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).Current.Value
  if($primary -ne '192.168.0.100'){throw 'Primary confirmation target changed.'}
  Click 'btn-remove-primary-ip';$record.steps+=@{action='actual primary-address confirmation Cancel';native=(Cancel ('Remove '+$primary+' from'));status='passed'}
  Select-Radio 'ip-mode-dhcp';Click 'ip-config-close'
  $record.steps+=@{action='actual DHCP confirmation Cancel';native=(Cancel 'Switching to DHCP removes manually configured addresses');status='passed'}
  Start-Sleep -Milliseconds 300
  if(!(Element 'ip-mode-static-manual').GetCurrentPattern([Windows.Automation.SelectionItemPattern]::Pattern).Current.IsSelected -or (Read-Shared $config) -notmatch '(?m)^network_mode\s*=\s*"static_manual"\s*$'){throw 'DHCP Cancel changed mode.'}
  Click 'ip-config-close'
 }
 if($Mode -eq 'Settings'){
  if((Element 'btn-toggle-stream').Current.Name -ne 'Start Stream'){throw 'Settings check requires stopped playback.'}
  if((Element 'rtsp-port').Current.IsOffscreen){Click 'menu-toggle';Start-Sleep -Milliseconds 300}
  $field=(Element 'rtsp-port').GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern)
  if($field.Current.Value -ne '554'){throw 'Original camera RTSP port changed.'}
  foreach($port in @(13554,554)){
   $field.SetValue([string]$port);Click 'save-settings';$until=[DateTime]::UtcNow.AddSeconds(10)
   do{$text=Read-Shared (Join-Path $env:APPDATA 'PocketStream\config.toml');$settingPersisted=[regex]::IsMatch($text,('(?m)^rtsp_port\s*=\s*'+$port+'\s*$'));if($settingPersisted){break};Start-Sleep -Milliseconds 100}while([DateTime]::UtcNow -lt $until)
   if(!$settingPersisted){throw 'Settings saved value did not persist.'}
  }
  $record.steps+=@{action='actual settings save/readback';values=@(554,13554,554);status='passed'};Click 'menu-toggle'
 }
 if($Mode -eq 'Playback'){if((Element 'btn-toggle-stream').Current.Name -ne 'Start Stream'){throw 'Unexpected playback control state.'};Click 'btn-toggle-stream';$record.steps+=@{action='production Start Stream';status='requested'}}
 if($Mode -eq 'ConfirmTestRemoval'){
  $matched=$false
  foreach($window in $tops){
   if($window.Current.ClassName -ne '#32770'){continue}
   $nodes=$window.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)
   $text=(@($window.Current.Name)+@($nodes|ForEach-Object {$_.Current.Name})) -join "`n"
   if(!$text.Contains('Remove 192.0.2.250/24 from')){continue}
   $buttons=@($nodes|Where-Object {$_.Current.ControlType -eq [Windows.Automation.ControlType]::Button -and $_.Current.Name -ceq 'OK'})
   if($buttons.Count -ne 1){throw 'Exact test-removal confirmation is ambiguous.'}
   $buttons[0].GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke();$matched=$true
   $record.steps+=@{action='confirm only approved test-address removal';native_text=$text;button='OK';status='confirmed'}
  }
  if(!$matched){throw 'Exact test-removal confirmation was not present; no button pressed.'}
  $until=[DateTime]::UtcNow.AddSeconds(45)
  do{$present=@(Get-NetIPAddress -InterfaceIndex 15 -AddressFamily IPv4|Where-Object IPAddress -eq '192.0.2.250').Count -gt 0;if(!$present){break};Start-Sleep -Milliseconds 200}while([DateTime]::UtcNow -lt $until)
  if($present){throw 'Confirmed candidate removal did not remove the test address; do not retry blindly.'}
  $record.steps+=@{action='candidate removal native postcondition';address='192.0.2.250/24';absent=$true;status='passed'}
  Start-Sleep -Milliseconds 500;Click 'ip-config-close'
 }
 if($Mode -in @('AddSecondary','RemoveSecondary')){
  $nic=@(Get-NetAdapter|Where-Object {$_.ifIndex -eq 15 -and [string]$_.InterfaceGuid -eq '{812AD22F-3345-4817-B6D7-708D769E69AC}' -and $_.MacAddress -eq '40-C2-BA-CF-D5-75'})
  if($nic.Count -ne 1){throw 'Ethernet identity changed; no write attempted.'}
  $config=Join-Path $env:APPDATA 'PocketStream\config.toml'
  if((Read-Shared $config) -notmatch '(?m)^network_mode\s*=\s*"static_manual"\s*$'){throw 'Static-Manual is required.'}
  $open=$root.FindFirst([Windows.Automation.TreeScope]::Descendants,(New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::AutomationIdProperty),'ip-config-close'))
  if(!$open -or $open.Current.IsOffscreen){Click 'btn-ip-config';Start-Sleep -Milliseconds 300}
  if($Mode -eq 'AddSecondary'){
   if(@(Get-NetIPAddress -AddressFamily IPv4|Where-Object IPAddress -eq '192.0.2.250').Count){throw 'Test address is already present.'}
   (Element 'add-sec-ip').GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).SetValue('192.0.2.250')
   (Element 'add-sec-mask').GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).SetValue('255.255.255.0')
   Click 'btn-add-sec-ip'
  }else{
   $addresses=@(Get-NetIPAddress -InterfaceIndex 15 -AddressFamily IPv4|Where-Object {$_.IPAddress -eq '192.0.2.250' -and $_.PrefixLength -eq 24})
   if($addresses.Count -ne 1){throw 'Exact test address/prefix is absent.'}
   $buttons=@($root.FindAll([Windows.Automation.TreeScope]::Descendants,(New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::ControlTypeProperty),([Windows.Automation.ControlType]::Button)))|Where-Object {$_.Current.Name -ceq 'Remove 192.0.2.250/24' -or $_.Current.HelpText -ceq 'Remove 192.0.2.250/24'})
   if($buttons.Count -ne 1){throw 'Exact test address Remove control missing/ambiguous.'};$buttons[0].GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
  }
  $until=[DateTime]::UtcNow.AddSeconds(45)
  do{$present=@(Get-NetIPAddress -InterfaceIndex 15 -AddressFamily IPv4|Where-Object {$_.IPAddress -eq '192.0.2.250' -and $_.PrefixLength -eq 24}).Count -eq 1;if($present -eq ($Mode -eq 'AddSecondary')){break};Start-Sleep -Milliseconds 200}while([DateTime]::UtcNow -lt $until)
  if($present -ne ($Mode -eq 'AddSecondary')){throw 'Candidate native address postcondition did not complete; no automatic retry.'}
  $record.steps+=@{action=$Mode;address='192.0.2.250/24';interface_index=15;native_postcondition_verified=$true;status='passed'}
  $until=[DateTime]::UtcNow.AddSeconds(15)
  do{$close=Element 'ip-config-close';$addField=Element 'add-sec-ip';$draft=$addField.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).Current.Value;if($close.Current.IsEnabled -and !$draft){break};Start-Sleep -Milliseconds 100}while([DateTime]::UtcNow -lt $until)
  if($draft){throw 'Secondary operation still has an uncommitted draft; no duplicate write requested.'}
  Click 'ip-config-close'
 }
 if($Mode -in @('RecordStart','RecordStop')){
  $log=Read-Shared (Join-Path $RunRoot 'application.stderr.log')
  $starts=[regex]::Matches($log,'\[frontend\] toast: Recording started').Count
  $stops=[regex]::Matches($log,'\[frontend\] toast: Recording saved:').Count
  if(($Mode -eq 'RecordStart' -and $starts -gt $stops) -or ($Mode -eq 'RecordStop' -and $starts -le $stops)){throw 'Recording state differs from the requested action.'}
  Click 'btn-record';$record.steps+=@{action=$Mode;status='requested';output_root=(Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::MyVideos)) 'PocketStream')}
 }
 if($Mode -eq 'Close'){Click 'btn-close';$record.steps+=@{action='normal production Close';status='requested'}}
 $record.status='completed requested controls; candidate/native result evidence evaluated separately'
}catch{$record.status='failed';$record.error=$_.Exception.Message;$record.stack=$_.ScriptStackTrace}
finally{$record.finished_utc=[DateTime]::UtcNow.ToString('o');$record|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $RunRoot ('ui-'+$Mode+'-'+[DateTime]::UtcNow.ToString('HHmmss')+'.json')) -Encoding UTF8}
