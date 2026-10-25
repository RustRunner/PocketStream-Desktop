<# Supplemental inspection/recovery of a known disposable qualification guest. #>
[CmdletBinding()]
param([ValidateSet('Inspect','FinishInteractive','CloseHost','Cleanup','ProbeLibraries','DismissPrerequisiteFailure')][string]$Mode='Inspect',[Parameter(Mandatory=$true)][string]$ExpectedSha256)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
if($id.Name.Split('\')[-1] -ne 'WDAGUtilityAccount'){throw 'This fixture runs only inside Windows Sandbox; no host changes were attempted.'}
$inputs='C:\PocketStreamQualification\Inputs';$control='C:\PocketStreamQualification\ControlInputs'
$manifest=Get-Content (Join-Path $inputs 'fixture.json') -Raw|ConvertFrom-Json
if($PSScriptRoot -ne $control -or $manifest.host_computer -eq [Environment]::MachineName -or (Get-FileHash $PSCommandPath).Hash.ToLowerInvariant() -ne $ExpectedSha256){throw 'Sandbox supplemental identity/hash guard failed.'}
try{$h=[IO.File]::Open($PSCommandPath,[IO.FileMode]::Open,[IO.FileAccess]::Write);$h.Dispose();throw 'Read-only mapping required.'}catch [UnauthorizedAccessException]{}catch [IO.IOException]{}
foreach($f in $manifest.inputs){if((Get-FileHash (Join-Path $inputs $f.name)).Hash.ToLowerInvariant() -ne $f.sha256){throw 'Primary immutable input changed.'}}
$root=Join-Path $env:ProgramW6432 'PocketStream Desktop';$image=Join-Path $root 'pocketstream-desktop.exe'
$run=Join-Path 'C:\PocketStreamQualification\Results' ('control-'+$Mode+'-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'));New-Item -ItemType Directory -Path $run|Out-Null
$record=[ordered]@{mode=$Mode;utc=[DateTime]::UtcNow.ToString('o');identity=$id.Name;session=[Diagnostics.Process]::GetCurrentProcess().SessionId;elevated=(New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);fixture_id=$manifest.id;script_sha256=$ExpectedSha256;status='running';actions=@()}
Add-Type -AssemblyName UIAutomationClient;Add-Type -AssemblyName UIAutomationTypes
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class A4OwnedButton {
 [DllImport("user32.dll")]static extern uint GetWindowThreadProcessId(IntPtr window,out uint process);
 [DllImport("user32.dll")]static extern IntPtr GetParent(IntPtr window);
 [DllImport("user32.dll")]static extern int GetDlgCtrlID(IntPtr window);
 [DllImport("user32.dll",SetLastError=true)]static extern IntPtr SendMessageTimeout(IntPtr window,uint message,IntPtr wparam,IntPtr lparam,uint flags,uint timeout,out IntPtr result);
 public static void Click(IntPtr window,int expected){uint actual;GetWindowThreadProcessId(window,out actual);var parent=GetParent(window);int id=GetDlgCtrlID(window);if(window==IntPtr.Zero||actual!=expected||parent==IntPtr.Zero||id<=0)throw new InvalidOperationException("Owned button identity mismatch");GetWindowThreadProcessId(parent,out actual);if(actual!=expected)throw new InvalidOperationException("Owned parent mismatch");IntPtr result;if(SendMessageTimeout(parent,0x111,(IntPtr)id,window,2,5000,out result)==IntPtr.Zero)throw new InvalidOperationException("Owned button notification timed out: "+Marshal.GetLastWin32Error());}
}
'@
function Processes {@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match 'pocketstream|candidate-setup|uninstall|Au_|consent|VC_redist|msiexec'}|Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,SessionId)}
function Windows {
 $rows=@();foreach($p in (Processes)){$cond=New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::ProcessIdProperty),([int]$p.ProcessId);foreach($w in [Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children,$cond)){$nodes=$w.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition);$rows+=@{pid=$p.ProcessId;name=$w.Current.Name;class=$w.Current.ClassName;controls=@($nodes|Where-Object {!$_.Current.IsPassword}|ForEach-Object {@{id=$_.Current.AutomationId;name=$_.Current.Name;type=$_.Current.ControlType.ProgrammaticName;enabled=$_.Current.IsEnabled}})}}};return $rows
}
function Click-Owned([int]$ProcessId,[string]$Text,[string]$Button,[string]$AutomationId=''){
 $p=Get-Process -Id $ProcessId
 $hash=(Get-FileHash -LiteralPath $p.Path).Hash.ToLowerInvariant()
 if($hash -notin @($manifest.candidate.package.sha256,$manifest.candidate.embedded.sha256)){throw 'Unexpected process image.'}
 $cond=New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::ProcessIdProperty),$ProcessId
 foreach($w in [Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children,$cond)){
  $nodes=$w.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition);$text=(@($w.Current.Name)+@($nodes|ForEach-Object {$_.Current.Name})) -join "`n"
  if(!$text.Contains($Text)){continue}
  $buttons=@($nodes|Where-Object {$_.Current.ControlType -eq [Windows.Automation.ControlType]::Button -and $_.Current.Name.Replace('&','') -ceq $Button -and (!$AutomationId -or $_.Current.AutomationId -eq $AutomationId) -and $_.Current.IsEnabled})
  if($buttons.Count -ne 1){throw 'Owned button missing/ambiguous.'}
  if($buttons[0].Current.NativeWindowHandle){[A4OwnedButton]::Click([IntPtr]$buttons[0].Current.NativeWindowHandle,$ProcessId)}else{$buttons[0].GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()}
  $record.actions+=@{pid=$ProcessId;button=$Button;text=$Text;native_notification='WM_COMMAND/BN_CLICKED to verified parent when HWND is present';utc=[DateTime]::UtcNow.ToString('o')};return
 }
 throw 'Expected owned window not found.'
}
try{
 $record.before=Processes;$record.windows_before=Windows
 if(Test-Path -LiteralPath $root){Get-ChildItem -LiteralPath $root -File|Where-Object {$_.Extension -in @('.json','.log')}|Copy-Item -Destination $run}
 $record.vc_versions=@(foreach($name in @('vcruntime140.dll','vcruntime140_1.dll','msvcp140.dll')){$file=Join-Path $env:WINDIR ('System32\'+$name);if(Test-Path -LiteralPath $file){$v=(Get-Item -LiteralPath $file).VersionInfo;@{name=$name;file_version=$v.FileVersion;major=$v.FileMajorPart;minor=$v.FileMinorPart;build=$v.FileBuildPart}}})
 if($Mode -eq 'DismissPrerequisiteFailure'){
  $installers=@(Processes|Where-Object Name -eq 'candidate-setup.exe');if($installers.Count -ne 1){throw 'Expected one failed installer.'}
  Click-Owned $installers[0].ProcessId 'Microsoft Visual C++ x64 runtime is unavailable after installation.' 'OK';Start-Sleep -Seconds 2
 }
 if($Mode -eq 'ProbeLibraries'){
  if(!(Test-Path -LiteralPath $image)){$p=Start-Process -FilePath (Join-Path $inputs 'candidate-setup.exe') -ArgumentList '/S' -WindowStyle Hidden -PassThru;$null=$p.Handle;if(!$p.WaitForExit(60000) -or $p.ExitCode -ne 0){throw 'Diagnostic setup failed.'}}
  if((Get-FileHash -LiteralPath $image).Hash.ToLowerInvariant() -ne $manifest.candidate.embedded.sha256){throw 'Installed image mismatch.'}
  Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class A4Load {
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]public static extern bool SetDllDirectory(string path);
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]public static extern IntPtr LoadLibrary(string path);
 [DllImport("kernel32.dll")]public static extern bool FreeLibrary(IntPtr h);
}
'@
  $bin=Join-Path $root 'resources\gstreamer\bin';$null=[A4Load]::SetDllDirectory($bin);$rows=@()
  foreach($file in (Get-ChildItem -LiteralPath $bin -Filter '*.dll' -File)){$h=[A4Load]::LoadLibrary($file.FullName);$code=[Runtime.InteropServices.Marshal]::GetLastWin32Error();$rows+=@{name=$file.Name;loaded=($h -ne [IntPtr]::Zero);win32_error=$(if($h -eq [IntPtr]::Zero){$code}else{0})};if($h -ne [IntPtr]::Zero){$null=[A4Load]::FreeLibrary($h)}}
  $record.library_probe=$rows
  $record.os_libraries=@(foreach($name in @('vcruntime140.dll','vcruntime140_1.dll','msvcp140.dll','mf.dll','mfplat.dll')){@{name=$name;exists=(Test-Path (Join-Path $env:WINDIR ('System32\'+$name)))}})
 }
 if($Mode -eq 'FinishInteractive'){
  foreach($p in (Processes|Where-Object Name -eq 'pocketstream-desktop.exe')){Click-Owned $p.ProcessId 'PocketStream installation is busy' 'OK';Start-Sleep -Milliseconds 500}
  $installers=@(Processes|Where-Object {$_.Name -eq 'candidate-setup.exe'});if($installers.Count -ne 1){throw 'Expected one interactive installer.'}
  Click-Owned $installers[0].ProcessId 'Completing PocketStream Desktop Setup' 'Finish' '1';Start-Sleep -Seconds 3
 }
 if($Mode -in @('CloseHost','Cleanup')){
  foreach($p in (Processes|Where-Object Name -eq 'pocketstream-desktop.exe')){
   $cond=New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::ProcessIdProperty),([int]$p.ProcessId)
   foreach($w in [Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children,$cond)){
    if($w.Current.ClassName -eq '#32770'){Click-Owned $p.ProcessId 'PocketStream installation is busy' 'OK'}
    elseif($w.Current.ClassName -eq 'Tauri Window'){
     $notice=$w.FindFirst([Windows.Automation.TreeScope]::Descendants,(New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::AutomationIdProperty),'listening-notice-ok'))
     if($notice -and !$notice.Current.IsOffscreen){$notice.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke();Start-Sleep -Milliseconds 500;$record.actions+=@{pid=$p.ProcessId;button='listening-notice-ok'}}
     $c=$w.FindFirst([Windows.Automation.TreeScope]::Descendants,(New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::AutomationIdProperty),'btn-close'));if($c){$c.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke();$record.actions+=@{pid=$p.ProcessId;button='btn-close'}}
    }
   }
   $proc=Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue;if($proc -and !$proc.WaitForExit(20000)){throw 'Guest candidate did not close normally; no force-kill used.'}
  }
 }
 if($Mode -eq 'Cleanup'){
  if(@(Processes|Where-Object {$_.Name -match 'pocketstream|candidate-setup'}).Count){throw 'Guest host/installer still exists; cleanup blocked.'}
  if(Test-Path -LiteralPath $image){$p=Start-Process -FilePath (Join-Path $root 'uninstall.exe') -ArgumentList '/S' -WindowStyle Hidden -PassThru;$null=$p.Handle;$null=$p.WaitForExit(30000);Start-Sleep -Seconds 3}
 }
 $record.after=Processes;$record.windows_after=Windows;$record.status='requested control completed; inspect evidence'
}catch{$record.status='failed';$record.error=$_.Exception.Message;$record.stack=$_.ScriptStackTrace}
finally{$record|ConvertTo-Json -Depth 12|Set-Content (Join-Path $run 'control.json') -Encoding UTF8;Get-NetFirewallRule -PolicyStore PersistentStore|Where-Object Group -eq 'PocketStream.Desktop.Managed.v2'|Export-Clixml (Join-Path $run 'owned-rules.xml')}
