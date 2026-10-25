<# Supplemental native failure checks; only the disposable Sandbox may run them. #>
[CmdletBinding()]
param([string]$ExpectedSha256)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if($identity.Name.Split('\')[-1] -ne 'WDAGUtilityAccount'){throw 'This fixture runs only inside Windows Sandbox; no host changes were attempted.'}
$inputRoot='C:\PocketStreamQualification\Inputs'
$resultsRoot='C:\PocketStreamQualification\Results'
$manifest=Get-Content -LiteralPath (Join-Path $inputRoot 'fixture.json') -Raw -Encoding UTF8|ConvertFrom-Json
if($manifest.host_computer -eq [Environment]::MachineName -or $PSScriptRoot -notin @($inputRoot,'C:\PocketStreamQualification\FailureInputs')){throw 'Sandbox identity/mapping guard failed.'}
if($PSScriptRoot -eq $inputRoot){$ExpectedSha256=@($manifest.inputs|Where-Object name -eq 'Invoke-PrivilegeSandboxFailures.ps1')[0].sha256}
if(!$ExpectedSha256 -or (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedSha256){throw 'Supplemental fixture hash mismatch.'}
foreach($file in $manifest.inputs){if((Get-FileHash -LiteralPath (Join-Path $inputRoot $file.name) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256){throw 'Read-only input verification failed.'}}
try{$stream=[IO.File]::Open($PSCommandPath,[IO.FileMode]::Open,[IO.FileAccess]::Write);$stream.Dispose();throw 'Supplemental input must be read-only.'}catch [IO.IOException]{}catch [UnauthorizedAccessException]{}
if(!(New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Guest administrator token required.'}
$moduleRoot=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules'
foreach($module in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management','CimCmdlets','NetAdapter','NetTCPIP','NetSecurity')){Import-Module -Name (Join-Path $moduleRoot ($module+'\'+$module+'.psd1')) -ErrorAction Stop}
foreach($name in @('BFE','MpsSvc','Winmgmt')){if((Get-Service -Name $name).Status -ne 'Running'){throw 'Guest services prerequisite unavailable.'}}
# Reuse the hash-verified primary fixture's snapshot, native process and policy
# assertions, without executing its top-level installer scenarios again.
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $inputRoot 'Invoke-PrivilegeSandbox.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Primary fixture parse failed.'}
foreach($name in @('Assert','Save-Report','Snapshot','Native','Scenario','Owned','Verify-Templates','Preserved','Wait-Uninstalled')){
 $fn=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
 if(!$fn){throw 'Primary fixture function missing.'}
 . ([scriptblock]::Create($fn.Extent.Text))
}
$run=Join-Path $resultsRoot ('failures-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
New-Item -ItemType Directory -Path $run|Out-Null
$report=[ordered]@{version=1;fixture_id=$manifest.id;started_utc=[DateTime]::UtcNow.ToString('o');candidate=$manifest.candidate;scenarios=@();status='preflight';error=$null;host_configuration_mutated=$false;production_eligibility_relaxed=$false}
$installRoot=Join-Path $env:ProgramW6432 'PocketStream Desktop'
$image=Join-Path $installRoot 'pocketstream-desktop.exe'
$setup=Join-Path $inputRoot 'candidate-setup.exe'
$uninstallKey='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PocketStream Desktop'
$roles=@(@{name='PocketStream.RTSP.Inbound.v2';display='PocketStream RTSP Server';protocol='TCP';port='8554'},@{name='PocketStream.SRT.Inbound.v2';display='PocketStream SRT Server';protocol='UDP';port='8890'})
$seed='PocketStream.Qualification.'+$manifest.id
$preserveNames=@(($seed+'.block'),($seed+'.foreign'),($seed+'.unrelated'))
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
function Installer-Button([Diagnostics.Process]$Process,[string]$ExpectedText,[string]$Label){
 $deadline=[DateTime]::UtcNow.AddSeconds(30)
 do{
  Assert (!$Process.HasExited) 'Installer exited before its expected dialog.'
  $condition=New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::ProcessIdProperty),$Process.Id
  $windows=[Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children,$condition)
  foreach($window in $windows){
   if($window.Current.ClassName -ne '#32770'){continue}
   $nodes=$window.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)
   $text=(@($window.Current.Name)+@($nodes|ForEach-Object {$_.Current.Name})) -join "`n"
   if($text.IndexOf($ExpectedText,[StringComparison]::OrdinalIgnoreCase) -lt 0){continue}
   foreach($node in $nodes){if($node.Current.ControlType -eq [Windows.Automation.ControlType]::Button -and $node.Current.Name.Replace('&','') -ceq $Label -and $node.Current.IsEnabled){
    $record=[ordered]@{pid=$Process.Id;expected_text=$ExpectedText;observed_text=$text;button=$node.Current.Name;automation_id=$node.Current.AutomationId;at_utc=[DateTime]::UtcNow.ToString('o')}
    $node.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
    return $record
   }}
  }
  Start-Sleep -Milliseconds 100
 }while([DateTime]::UtcNow -lt $deadline)
 throw 'Expected owned installer dialog/button was not available; no arbitrary button was pressed.'
}
try{
 Start-Transcript -LiteralPath (Join-Path $run 'transcript.log')|Out-Null
 Assert (!(Test-Path -LiteralPath $image) -and !(Test-Path -LiteralPath $uninstallKey) -and @(Owned).Count -eq 0) 'Run after successful primary fixture cleanup.'
 $preserved=Preserved $preserveNames
 Scenario 'prepare-failure-install'{$null=Native 'prepare-install' $setup ('/S /D='+$installRoot);Verify-Templates}
 $payload=@($manifest.payload|Where-Object {$_.path.EndsWith('.dll',[StringComparison]::OrdinalIgnoreCase)})[0]
 $lockedPath=Join-Path $installRoot $payload.path
 Scenario 'resource-extraction-ignore-failure'{
  $held=[IO.File]::Open($lockedPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try{
   $process=Start-Process -FilePath $setup -ArgumentList '/P' -WindowStyle Normal -PassThru -RedirectStandardOutput (Join-Path $run 'ignore.stdout.log') -RedirectStandardError (Join-Path $run 'ignore.stderr.log')
   $null=$process.Handle
   $dialogs=@((Installer-Button $process ([IO.Path]::GetFileName($lockedPath)) 'Ignore'),(Installer-Button $process 'Resource replacement failed' 'OK'))
   Assert ($process.WaitForExit(10000)) 'Ignore failure did not exit normally.'
   Assert ($process.ExitCode -eq 71) 'Ignoring resource extraction falsely reported success.'
   [ordered]@{pid=$process.Id;exit=$process.ExitCode;locked_payload=$payload.path;dialogs=$dialogs}|ConvertTo-Json -Depth 7|Set-Content -LiteralPath (Join-Path $run 'ignore.process.json') -Encoding UTF8
  }finally{$held.Dispose()}
  $diagnostic=Get-Content -LiteralPath (Join-Path $installRoot 'pocketstream-transaction.json') -Raw|ConvertFrom-Json
  Assert ($diagnostic.state -eq 'incomplete' -and !$diagnostic.rollback_claimed) 'Incomplete replacement diagnostics missing.'
 }
 Scenario 'repair-after-ignore'{$null=Native 'repair-ignore' $setup '/S';Verify-Templates;foreach($file in $manifest.payload){Assert ((Get-FileHash -LiteralPath (Join-Path $installRoot $file.path) -Algorithm SHA256).Hash.ToLowerInvariant() -eq $file.sha256) 'Repair payload mismatch.'}}
 Scenario 'payload-delete-child-failure'{
  $uninstaller=Join-Path $installRoot 'uninstall.exe';$copy=Join-Path $run 'verified-uninstall-child.exe'
  Copy-Item -LiteralPath $uninstaller -Destination $copy
  Assert ((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $uninstaller -Algorithm SHA256).Hash) 'Uninstaller child copy mismatch.'
  $held=[IO.File]::Open($lockedPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try{$null=Native 'locked-uninstall-child' $copy ('/S _?='+$installRoot) @(71)}finally{$held.Dispose()}
  Assert ((Test-Path -LiteralPath $image) -and (Test-Path -LiteralPath $uninstallKey)) 'Failed payload deletion removed maintenance image or registration.'
  $diagnostic=Get-Content -LiteralPath (Join-Path $installRoot 'pocketstream-transaction.json') -Raw|ConvertFrom-Json
  Assert ($diagnostic.state -eq 'incomplete' -and !$diagnostic.rollback_claimed) 'Incomplete deletion diagnostics missing.'
 }
 Scenario 'repair-after-delete-failure'{$null=Native 'repair-delete' $setup '/S';Verify-Templates}
 Scenario 'failure-final-uninstall'{$null=Native 'failure-final-uninstall' (Join-Path $installRoot 'uninstall.exe') '/S';Wait-Uninstalled;Assert ((Preserved $preserveNames) -ceq $preserved) 'Failure matrix changed preserved rules/filters.'}
 $report.status='supported payload failure subset passed; full qualification incomplete'
}catch{$report.status='supplemental scenario failed';$report.error=$_.Exception.Message;$report.source_line=$_.InvocationInfo.ScriptLineNumber;$report.script_stack=$_.ScriptStackTrace}
finally{
 $report.finished_utc=[DateTime]::UtcNow.ToString('o')
 $report.cleanup=[ordered]@{installed_image_remains=(Test-Path -LiteralPath $image);uninstall_registration_remains=(Test-Path -LiteralPath $uninstallKey);owned_rules=@(Owned).Count;profile_initialized=(Test-Path -LiteralPath (Join-Path $env:APPDATA 'PocketStream'));sandbox_left_open=$true}
 $report.pending=@('Standalone uninstaller bootstrap-parent error propagation is separate from the directly observed child failure.','Actual partial-provider injection, relaunch/continuous ownership timing, cross-account/session, physical binding/native writes, installed hardware, signed update and endurance remain unqualified.')
 Save-Report
 Stop-Transcript -ErrorAction SilentlyContinue|Out-Null
}
