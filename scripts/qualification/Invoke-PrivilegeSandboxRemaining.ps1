<# Remaining A4 cases. Destructive operations are guarded to the disposable
   Windows Sandbox, with immutable inputs and dedicated exported evidence. #>
[CmdletBinding()]
param([switch]$Resume,[switch]$NativeOnly,[switch]$ListenerOnly,[string]$ExpectedSha256)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if($identity.Name.Split('\')[-1] -ne 'WDAGUtilityAccount'){throw 'This fixture runs only inside Windows Sandbox; no host changes were attempted.'}
if($NativeOnly -and $ListenerOnly){throw 'Choose one bounded fixture subset.'}
$inputRoot='C:\PocketStreamQualification\Inputs'
$resultsRoot='C:\PocketStreamQualification\Results'
$manifest=Get-Content -LiteralPath (Join-Path $inputRoot 'fixture.json') -Raw -Encoding UTF8|ConvertFrom-Json
if($manifest.host_computer -eq [Environment]::MachineName -or $PSScriptRoot -notin @($inputRoot,'C:\PocketStreamQualification\ControlInputs')){throw 'Sandbox identity/mapping guard failed.'}
if($PSScriptRoot -ne $inputRoot -and (!$ExpectedSha256 -or (Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant() -ne $ExpectedSha256)){throw 'Supplemental fixture hash mismatch.'}
foreach($file in $manifest.inputs){if([IO.Path]::GetFileName($file.name) -ne $file.name -or (Get-FileHash -LiteralPath (Join-Path $inputRoot $file.name)).Hash.ToLowerInvariant() -ne $file.sha256){throw 'Immutable input hash mismatch.'}}
try{$h=[IO.File]::Open($PSCommandPath,[IO.FileMode]::Open,[IO.FileAccess]::Write);$h.Dispose();throw 'Input mapping must be read-only.'}catch [UnauthorizedAccessException]{}catch [IO.IOException]{}
if(!(New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated guest token required.'}
# Run only the existing prerequisite observations, never its 28 historical cases.
& (Join-Path $inputRoot 'Invoke-PrivilegeSandbox.ps1') -Mode Preflight
$preflight=Get-ChildItem -LiteralPath $resultsRoot -Filter results.json -Recurse | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
$prerequisite=Get-Content -LiteralPath $preflight.FullName -Raw -Encoding UTF8|ConvertFrom-Json
if($prerequisite.status -ne 'preflight passed; supported matrix not requested'){throw 'Guest prerequisites did not pass.'}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $inputRoot 'Invoke-PrivilegeSandbox.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Primary fixture parse failed.'}
foreach($name in @('Assert','Save-Report','Snapshot','Native','Standalone','Owned','Verify-Templates','Preserved','Wait-Uninstalled')){
 $fn=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
 if(!$fn){
  if($name -eq 'Standalone'){
   # Historical immutable primary inputs predate the registered bootstrap.
   function Standalone([string]$Label,[string]$Switches='',[int[]]$Expected=@(0)){return Native $Label (Join-Path $installRoot 'uninstall.exe') $Switches $Expected}
   continue
  }
  throw 'Required fixture function missing.'
 }
 . ([scriptblock]::Create($fn.Extent.Text))
}
$run=Join-Path $resultsRoot ('remaining-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
New-Item -ItemType Directory -Path $run|Out-Null
$report=[ordered]@{version=1;fixture_id=$manifest.id;started_utc=[DateTime]::UtcNow.ToString('o');candidate=$manifest.candidate;effective_source_sha256=$manifest.effective_source_sha256;scenarios=@();status='running';pending=@();host_configuration_mutated=$false;production_eligibility_relaxed=$false}
$report['scope']=$(if($ListenerOnly){'Bounded listener regression only; no A4 completion claim'}else{'Existing remaining qualification fixture'})
$installRoot=Join-Path $env:ProgramW6432 'PocketStream Desktop'
$image=Join-Path $installRoot 'pocketstream-desktop.exe'
$setup=Join-Path $inputRoot 'candidate-setup.exe'
$uninstallKey='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PocketStream Desktop'
$profile=Join-Path $env:APPDATA 'PocketStream'
$config=Join-Path $profile 'config.toml'
$roles=@(@{name='PocketStream.RTSP.Inbound.v2';display='PocketStream RTSP Server';protocol='TCP';port='8554'},@{name='PocketStream.SRT.Inbound.v2';display='PocketStream SRT Server';protocol='UDP';port='8890'})
$script:app=$null
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -TypeDefinition @'
using System; using System.IO; using System.Threading; using System.Diagnostics; using System.Runtime.InteropServices;
public static class A4Gate {
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr OpenMutex(uint access,bool inherit,string name);
 [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
 [DllImport("kernel32.dll")] static extern bool ReleaseMutex(IntPtr handle);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint process);
 [DllImport("user32.dll")] static extern IntPtr GetParent(IntPtr window);
 [DllImport("user32.dll")] static extern int GetDlgCtrlID(IntPtr window);
 [DllImport("user32.dll",SetLastError=true)] static extern IntPtr SendMessageTimeout(IntPtr window,uint message,IntPtr wparam,IntPtr lparam,uint flags,uint timeout,out IntPtr result);
 static Thread thread; static volatile bool stop;
 public static string State(string name) {var h=OpenMutex(0x100001,false,@"Global\PocketStream.Desktop."+name+".v2");if(h==IntPtr.Zero)return "missing:"+Marshal.GetLastWin32Error();try {var result=WaitForSingleObject(h,0);if(result==0||result==128)ReleaseMutex(h);return result.ToString();}finally{CloseHandle(h);}}
 public static void Start(string path) {stop=false;thread=new Thread(()=>{using(var w=new StreamWriter(path)){w.WriteLine("utc,ticks,InstallGate,HostOwner");while(!stop){w.WriteLine(DateTime.UtcNow.ToString("o")+","+Stopwatch.GetTimestamp()+","+State("InstallGate")+","+State("HostOwner"));w.Flush();Thread.Sleep(1);}}});thread.IsBackground=true;thread.Start();}
 public static void Stop(){stop=true;if(thread!=null)thread.Join();thread=null;}
 public static void Click(IntPtr window,int process){uint actual;GetWindowThreadProcessId(window,out actual);var parent=GetParent(window);int id=GetDlgCtrlID(window);if(window==IntPtr.Zero||actual!=process||parent==IntPtr.Zero||id<=0)throw new InvalidOperationException("Native button ownership mismatch");GetWindowThreadProcessId(parent,out actual);if(actual!=process)throw new InvalidOperationException("Native parent ownership mismatch");IntPtr result;if(SendMessageTimeout(parent,0x111,(IntPtr)id,window,2,5000,out result)==IntPtr.Zero)throw new InvalidOperationException("Owned native button notification did not respond: "+Marshal.GetLastWin32Error());}
}
'@
Add-Type -TypeDefinition @'
using System;using System.IO;using System.IO.MemoryMappedFiles;using System.Text;using System.Threading;using System.Runtime.InteropServices;
public static class A4DebugReceiver {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern void OutputDebugString(string text);
 static Thread thread;static volatile bool stop,seen;static Exception failure;
 public static void Start(string path){stop=false;seen=false;failure=null;thread=new Thread(()=>{
  try{bool a,b;using(var ready=new EventWaitHandle(false,EventResetMode.AutoReset,"DBWIN_BUFFER_READY",out a))
  using(var data=new EventWaitHandle(false,EventResetMode.AutoReset,"DBWIN_DATA_READY",out b)){
   if(!a||!b)throw new InvalidOperationException("Another debug collector already exists");
   using(var map=MemoryMappedFile.CreateNew("DBWIN_BUFFER",4096,MemoryMappedFileAccess.ReadWrite))
   using(var view=map.CreateViewAccessor())using(var writer=new StreamWriter(path,false,new UTF8Encoding(false))){
    ready.Set();while(!stop){if(!data.WaitOne(100))continue;uint pid=view.ReadUInt32(0);var bytes=new byte[4092];view.ReadArray(4,bytes,0,bytes.Length);int n=Array.IndexOf(bytes,(byte)0);if(n<0)n=bytes.Length;string text=Encoding.Default.GetString(bytes,0,n);ready.Set();
     if(text.StartsWith("PSOWN:v1 ",StringComparison.Ordinal)){writer.WriteLine(DateTime.UtcNow.ToString("o")+" native_pid="+pid+" "+text);writer.Flush();if(text.Contains("event=collector_selftest"))seen=true;}
    }
   }
  }}catch(Exception e){failure=e;}
 });thread.IsBackground=true;thread.Start();Thread.Sleep(100);OutputDebugString("PSOWN:v1 event=collector_selftest name=Collector result=1");
 for(int i=0;i<100&&!seen&&failure==null;i++)Thread.Sleep(10);
 if(failure!=null)throw failure;if(!seen)throw new InvalidOperationException("Native debug collector self-test failed");}
 public static void Stop(){stop=true;if(thread!=null)thread.Join();thread=null;if(failure!=null)throw failure;}
}
'@
function Write-Data([string]$Name,$Value){$Value|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $run $Name) -Encoding UTF8}
function Case([string]$Name,[scriptblock]$Action){
 $entry=[ordered]@{name=$Name;started_utc=[DateTime]::UtcNow.ToString('o');status='running'};$report.scenarios+=$entry;Save-Report
 try{$null=Snapshot ($Name+'-before');& $Action;$entry.status='passed'}
 catch{$entry.status='failed';$entry.error=$_.Exception.Message;$entry.stack=$_.ScriptStackTrace;$entry.line=$_.InvocationInfo.ScriptLineNumber;Capture-Failure $Name}
 finally{$entry.finished_utc=[DateTime]::UtcNow.ToString('o');$null=Snapshot ($Name+'-after');Save-Report}
}
function Wait-For([scriptblock]$Test,[string]$Reason,[int]$Seconds=30){$until=[DateTime]::UtcNow.AddSeconds($Seconds);do{if(& $Test){return};Start-Sleep -Milliseconds 100}while([DateTime]::UtcNow -lt $until);throw $Reason}
function Top([int]$ProcessId){$condition=New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::ProcessIdProperty),$ProcessId;return [Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children,$condition)}
function Find-Control($Root,[string]$Id){$c=New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::AutomationIdProperty),$Id;return $Root.FindFirst([Windows.Automation.TreeScope]::Descendants,$c)}
function App-Control([string]$Id){$root=@(Top $script:app.Id|Where-Object {$_.Current.ClassName -eq 'Tauri Window'})|Select-Object -First 1;if(!$root){return $null};Find-Control $root $Id}
function App-Click([string]$Id){Wait-For {$c=App-Control $Id;$null -ne $c -and $c.Current.IsEnabled} ('App control unavailable: '+$Id);$c=App-Control $Id;$c.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()}
function Read-Shared([string]$Path){$stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete));$reader=New-Object IO.StreamReader $stream;try{return $reader.ReadToEnd()}finally{$reader.Dispose()}}
function Protocol([string]$Name){
 $root=@(Top $script:app.Id|Where-Object {$_.Current.ClassName -eq 'Tauri Window'})|Select-Object -First 1
 $groups=$root.FindAll([Windows.Automation.TreeScope]::Descendants,(New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::NameProperty),'Re-stream output protocol'))
 Assert ($groups.Count -eq 1) 'Output protocol group missing/ambiguous.'
 $buttons=$groups[0].FindAll([Windows.Automation.TreeScope]::Descendants,(New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::ControlTypeProperty),([Windows.Automation.ControlType]::Button)))
 $button=@($buttons|Where-Object {$_.Current.Name -ceq $Name -and $_.Current.IsEnabled});Assert ($button.Count -eq 1) 'Output protocol button missing/ambiguous.'
 $patterns=@($button[0].GetSupportedPatterns())
 if($patterns -contains [Windows.Automation.InvokePattern]::Pattern){$button[0].GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()}
 elseif($patterns -contains [Windows.Automation.TogglePattern]::Pattern){$button[0].GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern).Toggle()}
 else{throw 'Protocol control does not expose a supported activation pattern.'}
}
function Close-App {
 if(!$script:app -or $script:app.HasExited){return}
 App-Click 'btn-close';Assert ($script:app.WaitForExit(20000)) 'Candidate did not exit after normal Close.'
 Write-Data ('close-'+$script:app.Id+'.json') @{pid=$script:app.Id;exit=$script:app.ExitCode;normal_close=$true}
 Assert ($script:app.ExitCode -eq 0) 'Candidate Close returned nonzero.';$script:app=$null
}
function Capture-App([string]$Label){
 $records=@(Get-CimInstance Win32_Process -Filter "Name='pocketstream-desktop.exe'"|Where-Object {$_.CommandLine -notmatch '--firewall-maintenance'})
 Assert ($records.Count -eq 1 -and $records[0].ExecutablePath -ieq $image) 'Expected one exact installed candidate.'
 Assert ((Get-FileHash -LiteralPath $image).Hash.ToLowerInvariant() -eq $manifest.candidate.embedded.sha256) 'Installed candidate hash mismatch.'
 if(!$script:app -or $script:app.Id -ne $records[0].ProcessId){$script:app=Get-Process -Id $records[0].ProcessId};$null=$script:app.Handle
 Write-Data ($Label+'-host.json') ($records|Select-Object ProcessId,ParentProcessId,ExecutablePath,SessionId,CreationDate)
 try{Wait-For {
  # The real first-launch modal exposes only its own accessibility subtree.
  # Reuse the production notice acknowledgement before looking for main controls.
  $notice=App-Control 'listening-notice-ok'
  if($notice -and !$notice.Current.IsOffscreen){$notice.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke();Write-Data ($Label+'-notice.json') @{pid=$script:app.Id;id='listening-notice-ok';utc=[DateTime]::UtcNow.ToString('o')}}
  $null -ne (App-Control 'btn-close')
 } 'Candidate UI not ready.' 45}catch{Capture-Failure $Label;throw}
}
function Capture-Failure([string]$Label){
 try{
  $processes=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match 'pocketstream|uninstall|Au_'}|Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,SessionId)
  $windows=@();if($script:app){foreach($w in (Top $script:app.Id)){$nodes=$w.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition);$windows+=@{class=$w.Current.ClassName;name=$w.Current.Name;text=@($nodes|ForEach-Object {$_.Current.Name})}}}
  $code=$null;if($script:app -and $script:app.HasExited){$code=$script:app.ExitCode}
  Write-Data ($Label+'-failure.json') @{processes=$processes;windows=$windows;candidate_exit=$code;utc=[DateTime]::UtcNow.ToString('o')}
  @(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=[DateTime]::UtcNow.AddMinutes(-15)} -ErrorAction SilentlyContinue|Select-Object TimeCreated,Id,ProviderName,Message)|Export-Clixml -LiteralPath (Join-Path $run ($Label+'-application-events.xml'))
 }catch{Write-Data ($Label+'-diagnostic-error.json') @{error=$_.Exception.Message}}
}
function Start-App([string]$Label){
 Assert (@(Get-Process -Name pocketstream-desktop -ErrorAction SilentlyContinue).Count -eq 0) 'Another host exists.'
 $script:app=Start-Process -FilePath $image -WorkingDirectory $installRoot -WindowStyle Normal -PassThru -RedirectStandardOutput (Join-Path $run ($Label+'.stdout.log')) -RedirectStandardError (Join-Path $run ($Label+'.stderr.log'));$null=$script:app.Handle
 Capture-App $Label
 Wait-For {(Read-Shared (Join-Path $run ($Label+'.stderr.log'))).Contains('Native startup reconciliation completed; conflicting writes available')} 'Candidate startup recovery did not complete; listener/write assertions remain untested.' 60
}
function Wizard([Diagnostics.Process]$Process,[string]$Label,[string]$CopiedHash=''){
 $until=[DateTime]::UtcNow.AddMinutes(15);$pages=@();$finished=$false
 do{
  $windows=@(Top $Process.Id)
  if($CopiedHash){
   $all=[Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children,[Windows.Automation.Condition]::TrueCondition)
   foreach($w in $all){if($w.Current.ClassName -ne '#32770' -or $w.Current.Name -notmatch 'PocketStream'){continue};$p=Get-Process -Id $w.Current.ProcessId -ErrorAction SilentlyContinue;if($p -and $p.Path -and (Get-FileHash -LiteralPath $p.Path).Hash -eq $CopiedHash){$windows+=,$w;Write-Data ($Label+'-child.json') @{pid=$p.Id;path=$p.Path;sha256=$CopiedHash}}}
  }
  foreach($window in $windows){
   if($window.Current.ClassName -ne '#32770'){continue}
   $nodes=$window.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)
   # NSIS wizard navigation uses native IDs 1/2/3. Exclude the title-bar Close
   # button, which is also exposed by UIAutomation even on the welcome page.
   $buttons=@($nodes|Where-Object {$_.Current.ControlType -eq [Windows.Automation.ControlType]::Button -and $_.Current.AutomationId -in @('1','2','3') -and $_.Current.IsEnabled})
   $advance=$null
   foreach($choice in @('Finish','Close','Uninstall','Install','I Agree','Next >','Next')){$advance=@($buttons|Where-Object {$_.Current.Name.Replace('&','') -ceq $choice})|Select-Object -First 1;if($advance){break}}
   if(!$advance){continue}
   $text=(@($window.Current.Name)+@($nodes|Where-Object {$_.Current.ControlType -eq [Windows.Automation.ControlType]::Text}|ForEach-Object {$_.Current.Name})) -join "`n"
   $action=$advance.Current.Name.Replace('&','')
   $pages+=@{utc=[DateTime]::UtcNow.ToString('o');pid=$window.Current.ProcessId;button=$action;text=$text;gate=[A4Gate]::State('InstallGate');owner=[A4Gate]::State('HostOwner')}
   Write-Data ($Label+'-pages.json') $pages
   if($action -eq 'Finish' -and !$CopiedHash){
    Assert ([A4Gate]::State('InstallGate') -eq '258') 'InstallGate was not held through finish page.';Assert (@(Get-Process -Name pocketstream-desktop -ErrorAction SilentlyContinue).Count -eq 0) 'Host launched before finish callbacks.'
    foreach($checkId in @('1203','1204')){
     $check=Find-Control $window $checkId
     Assert ($null -ne $check) 'Expected Run/desktop finish checkbox missing.'
     $toggle=$check.GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern)
     if($toggle.Current.ToggleState -eq [Windows.Automation.ToggleState]::Off){$toggle.Toggle()}
     Assert ($toggle.Current.ToggleState -eq [Windows.Automation.ToggleState]::On) 'Finish checkbox did not become checked.'
    }
   }
   [A4Gate]::Click([IntPtr]$advance.Current.NativeWindowHandle,$window.Current.ProcessId)
   if($action -in @('Finish','Close')){$finished=$true}
   Start-Sleep -Milliseconds 350
  }
  # Invoke can return before the native dialog processes its click. Keep
  # observing/retrying the same owned Finish/Close instead of declaring exit.
  if($finished -and $Process.HasExited){return}
  if($Process.HasExited -and !$CopiedHash){throw 'Installer exited before completion page.'}
  Start-Sleep -Milliseconds 100
 }while([DateTime]::UtcNow -lt $until)
 throw 'Expected installer wizard did not complete; no arbitrary button was pressed.'
}
function Gate-Free {Assert ([A4Gate]::State('InstallGate') -in @('0','missing:2')) 'InstallGate retained after terminal path.'}
function Set-Section([string]$Section,[string]$Field,[string]$Value){
 $text=[IO.File]::ReadAllText($config)
 if($Section -eq ''){$part=[regex]::Match($text,'(?ms)\A.*?(?=^\[|\z)')}else{$part=[regex]::Match($text,'(?ms)^\['+[regex]::Escape($Section)+'\]\r?\n.*?(?=^\[|\z)')}
 Assert $part.Success ('Missing section '+$Section)
 $pattern='(?m)^'+[regex]::Escape($Field)+'\s*=.*$';Assert ([regex]::IsMatch($part.Value,$pattern)) ('Missing field '+$Field)
 $updated=[regex]::Replace($part.Value,$pattern,($Field+' = '+$Value));[IO.File]::WriteAllText($config,$text.Substring(0,$part.Index)+$updated+$text.Substring($part.Index+$part.Length),[Text.UTF8Encoding]::new($false))
}
function Rule-State([string]$Role,[bool]$Enabled,[int]$Port=0){
 Wait-For {
  $observed=@(Owned|Where-Object Name -eq ('PocketStream.'+$Role+'.Inbound.v2'))
  $observed.Count -eq 1 -and [string]$observed[0].Enabled -eq $Enabled.ToString()
 } ('Rule did not reach expected Enabled state for '+$Role) 45
 $rule=@(Owned|Where-Object Name -eq ('PocketStream.'+$Role+'.Inbound.v2'));Assert ($rule.Count -eq 1) 'Owned rule missing/ambiguous.'
 Assert ([string]$rule[0].Enabled -eq $Enabled.ToString()) ('Unexpected rule Enabled for '+$Role)
 if($Port){$filter=$rule|Get-NetFirewallPortFilter;Assert ([string]$filter.LocalPort -eq [string]$Port) 'Owned rule port mismatch.'}
}
function Card([string]$Label){
 $root=@(Top $script:app.Id|Where-Object {$_.Current.ClassName -eq 'Tauri Window'})|Select-Object -First 1
 $text=@($root.FindAll([Windows.Automation.TreeScope]::Descendants,(New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::ControlTypeProperty),([Windows.Automation.ControlType]::Text)))|ForEach-Object {$_.Current.Name}|Where-Object {$_ -match '^(Bound on|Windows rule|No active listener|Failed|Unable|Address already)'})
 Write-Data ($Label+'-card.json') @{observed_text=$text;pid=$script:app.Id;utc=[DateTime]::UtcNow.ToString('o')}
}
try{
 Start-Transcript -LiteralPath (Join-Path $run 'transcript.log')|Out-Null
 [A4DebugReceiver]::Start((Join-Path $run 'ownership-native-debug.log'))
 $report['ownership_observability']='Native Windows debug output with PID/TID/tick and actual acquire/release/close results; separate sampled contention timeline. Collector self-test receives no candidate outcome credit.'
 if(!$Resume){Assert (!(Test-Path -LiteralPath $image) -and !(Test-Path -LiteralPath $uninstallKey) -and @(Owned).Count -eq 0 -and !(Test-Path -LiteralPath $profile)) 'Fresh Sandbox required.'}
 if($Resume){Assert ((Get-FileHash -LiteralPath $image).Hash.ToLowerInvariant() -eq $manifest.candidate.embedded.sha256 -and @(Get-Process -Name pocketstream-desktop -ErrorAction SilentlyContinue).Count -eq 0) 'Resume requires the verified installed candidate, with no host running.'}
 if(!$Resume -and !$ListenerOnly){Case 'interactive-install-queued-launch' {
  [A4Gate]::Start((Join-Path $run 'interactive-install-gates.csv'))
  try{$p=Start-Process -FilePath $setup -ArgumentList ('/D='+$installRoot) -WindowStyle Normal -PassThru;$null=$p.Handle;Wizard $p 'interactive-install';Assert ($p.WaitForExit(30000)) 'Interactive installer did not exit.';Assert ($p.ExitCode -eq 0) 'Interactive installation failed.';Gate-Free
   Wait-For { @(Get-Process -Name pocketstream-desktop -ErrorAction SilentlyContinue).Count -gt 0 } 'Finish-page queued host did not launch.';Capture-App 'queued-launch';Close-App
  }finally{[A4Gate]::Stop()}
  Verify-Templates
 }}
 if(!(Test-Path -LiteralPath $image)){Case 'setup-for-independent-cases' {$null=Native 'setup-independent' $setup ('/S /D='+$installRoot);Verify-Templates}}
 if(!$NativeOnly){
 if(!(Test-Path -LiteralPath $config)){Start-App 'initialize-profile';Close-App}
 if(!$ListenerOnly){
 Case 'lone-host-crash-successful-startup-reconciliation' {
  Start-App 'before-lone-crash';Enable-NetFirewallRule -Name $roles.name
  Assert ([A4Gate]::State('HostOwner') -eq '258') 'Lone candidate did not own HostOwner.'
  # No monitor/mutex helper survives this crash; every observation handle closes.
  Stop-Process -Id $script:app.Id;Assert ($script:app.WaitForExit(10000)) 'Lone host did not terminate.';$script:app=$null
  Start-Sleep -Milliseconds 300;Start-App 'after-lone-crash'
  Wait-For { @((Owned)|Where-Object {[string]$_.Enabled -eq 'True'}).Count -eq 0 } 'Stale owned enables were not reconciled.'
  Wait-For { (Read-Shared (Join-Path $run 'after-lone-crash.stderr.log')).Contains('Native startup reconciliation completed; conflicting writes available') } 'Successful startup completion not observed.'
  Close-App;Gate-Free
 }
 foreach($modeEntry in @(@{name='silent';args='/S /R'},@{name='passive';args='/P /R'},@{name='updater';args='/S /UPDATE /R'})){
  Case ($modeEntry.name+'-relaunch-after-release') {
   Close-App;[A4Gate]::Start((Join-Path $run ($modeEntry.name+'-relaunch-gates.csv')))
   try{$null=Native ($modeEntry.name+'-relaunch') $setup $modeEntry.args;Gate-Free;Wait-For { @(Get-Process -Name pocketstream-desktop -ErrorAction SilentlyContinue).Count -gt 0 } 'Requested /R host did not launch.';Capture-App ($modeEntry.name+'-relaunch');Close-App}finally{[A4Gate]::Stop()}
  }
 }
 }
 Case 'nondefault-protocol-replacement' {
  Close-App;Set-Section '' 'restream_protocol' '"rtsp"';Set-Section 'stream' 'protocol' '"udp"';Set-Section 'rtsp_server' 'enabled' 'true';Set-Section 'rtsp_server' 'port' '18554';Set-Section 'srt_server' 'port' '18890'
  Start-App 'protocol-replacement';App-Click 'btn-toggle-restream'
  Wait-For { @(Get-NetTCPConnection -State Listen -LocalPort 18554 -ErrorAction SilentlyContinue|Where-Object OwningProcess -eq $script:app.Id).Count -eq 1 } 'Initial RTSP socket missing.'
  Protocol 'SRT'
  Wait-For { @(Get-NetUDPEndpoint -LocalPort 18890 -ErrorAction SilentlyContinue|Where-Object OwningProcess -eq $script:app.Id).Count -eq 1 } 'Candidate SRT socket missing.'
  Rule-State 'RTSP' $false;Rule-State 'SRT' $true 18890
  Assert (@(Get-NetTCPConnection -State Listen -LocalPort 18554 -ErrorAction SilentlyContinue|Where-Object OwningProcess -eq $script:app.Id).Count -eq 0) 'Retired RTSP listener survived.'
  Card 'srt'
  Protocol 'RTSP'
  Wait-For { @(Get-NetTCPConnection -State Listen -LocalPort 18554 -ErrorAction SilentlyContinue|Where-Object OwningProcess -eq $script:app.Id).Count -eq 1 } 'Replacement RTSP socket missing.'
  Rule-State 'SRT' $false;Rule-State 'RTSP' $true 18554
  App-Click 'btn-toggle-restream';Wait-For { @((Owned)|Where-Object {[string]$_.Enabled -eq 'True'}).Count -eq 0 } 'Protocol replacement Stop left rule enabled.';Close-App
 }
 Case 'rtsp-nondefault-start-stop' {
  Close-App;Set-Section '' 'restream_protocol' '"rtsp"';Set-Section 'stream' 'protocol' '"udp"';Set-Section 'rtsp_server' 'enabled' 'true';Set-Section 'rtsp_server' 'port' '18554';Set-Section 'srt_server' 'port' '18890'
  Start-App 'listener';App-Click 'btn-toggle-restream'
  Wait-For { @(Get-NetTCPConnection -State Listen -LocalPort 18554 -ErrorAction SilentlyContinue|Where-Object OwningProcess -eq $script:app.Id).Count -eq 1 } 'Candidate RTSP socket not observed.'
  Rule-State 'RTSP' $true 18554;Rule-State 'SRT' $false
  Card 'rtsp'
  App-Click 'btn-toggle-restream';Wait-For { @((Owned)|Where-Object {[string]$_.Enabled -eq 'True'}).Count -eq 0 } 'Stop left owned rule enabled.'
  Assert (@(Get-NetTCPConnection -State Listen -LocalPort 18554 -ErrorAction SilentlyContinue|Where-Object OwningProcess -eq $script:app.Id).Count -eq 0) 'Stopped RTSP socket remained.';Close-App
 }
 Case 'rtsp-bind-failure-disables-rule' {
  Close-App;Set-Section '' 'restream_protocol' '"rtsp"';Set-Section 'stream' 'protocol' '"udp"';Set-Section 'rtsp_server' 'enabled' 'true';Set-Section 'rtsp_server' 'port' '18554'
  $occupied=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Any,18554);$occupied.Start()
  try{Start-App 'bind-failure';App-Click 'btn-toggle-restream';Wait-For {(Read-Shared (Join-Path $run 'bind-failure.stderr.log')).Contains('RTSP server socket failed:')} 'Candidate did not report an actual RTSP bind failure.';Rule-State 'RTSP' $false;Assert (@(Get-NetTCPConnection -State Listen -LocalPort 18554 -ErrorAction SilentlyContinue|Where-Object OwningProcess -eq $script:app.Id).Count -eq 0) 'Candidate unexpectedly bound occupied port.';Card 'bind-failure';Close-App}finally{$occupied.Stop()}
 }
 }
 if(!$ListenerOnly){
 Case 'standalone-bootstrap-parent-delete-failure' {
  Close-App;$lockedPath=Join-Path $installRoot 'resources\gstreamer\bin\avcodec-61.dll';$held=[IO.File]::Open($lockedPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try{
   $result=Standalone 'bootstrap-parent-locked-delete' '/S' @(0,71)
   Wait-For { (Test-Path -LiteralPath (Join-Path $installRoot 'pocketstream-transaction.json')) -and (Get-Content -LiteralPath (Join-Path $installRoot 'pocketstream-transaction.json') -Raw) -match 'incomplete' } 'Copied uninstall child did not retain failure diagnostic.'
   Assert ((Test-Path -LiteralPath $image) -and (Test-Path -LiteralPath $uninstallKey)) 'Failed deletion removed maintenance image/registration.'
   Assert ($result.exit -eq 71) 'DEFECT: standalone bootstrap parent returned success while copied child failed deletion.'
  }finally{$held.Dispose()}
 }
 Case 'repair-after-parent-failure' {$null=Native 'parent-failure-repair' $setup '/S';Verify-Templates;Gate-Free}
 Case 'passive-extraction-failure-owner-thread-release' {
  $failureAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $inputRoot 'Invoke-PrivilegeSandboxFailures.ps1'),[ref]$tokens,[ref]$errors)
  $button=$failureAst.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Installer-Button'},$true)
  Assert ($null -ne $button) 'Existing owned-dialog fixture missing.';. ([scriptblock]::Create($button.Extent.Text))
  $held=[IO.File]::Open((Join-Path $installRoot 'resources\gstreamer\bin\avcodec-61.dll'),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try{
   $p=Start-Process -FilePath $setup -ArgumentList '/P' -WindowStyle Normal -PassThru;$null=$p.Handle
   $ignore=Installer-Button $p 'Error opening file for writing' 'Ignore';Write-Data 'passive-extraction-ignore.json' $ignore
   $ok=Installer-Button $p 'Resource replacement failed' 'OK';Write-Data 'passive-extraction-fatal.json' $ok
   Assert ($p.WaitForExit(30000) -and $p.ExitCode -eq 71) 'Failed extraction did not return 71.';Gate-Free
  }finally{$held.Dispose()}
 }
 Case 'repair-after-passive-extraction-failure' {$null=Native 'repair-passive-extraction' $setup '/S';Verify-Templates;foreach($file in $manifest.payload){Assert ((Get-FileHash -LiteralPath (Join-Path $installRoot $file.path)).Hash.ToLowerInvariant() -eq $file.sha256) 'Repair payload mismatch.'}}
 Case 'interactive-standalone-uninstall' {
  Close-App;$uninstaller=Join-Path $installRoot 'uninstall.exe';$hash=(Get-FileHash -LiteralPath $uninstaller).Hash
  [A4Gate]::Start((Join-Path $run 'interactive-uninstall-gates.csv'))
  try{
   $bootstrap=Join-Path $installRoot 'uninstall-bootstrap.ps1'
   if(Test-Path -LiteralPath $bootstrap){$p=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+$bootstrap+'"') -WindowStyle Hidden -PassThru}
   else{$p=Start-Process -FilePath $uninstaller -WindowStyle Normal -PassThru}
   $null=$p.Handle;Wizard $p 'interactive-uninstall' $hash;Wait-Uninstalled;Gate-Free
  }finally{[A4Gate]::Stop()}
 }
 }
 $report.status='remaining supported cases executed; inspect individual results; A4 incomplete'
}catch{$report.status='fixture interrupted; qualification incomplete';$report.error=$_.Exception.Message;$report.stack=$_.ScriptStackTrace}
finally{
 [A4Gate]::Stop()
 try{Close-App}catch{$report.pending+=('Normal close needs inspection: '+$_.Exception.Message)}
 if((Test-Path -LiteralPath $image) -and @(Get-Process -Name pocketstream-desktop -ErrorAction SilentlyContinue).Count -eq 0){try{$null=Standalone 'cleanup-uninstall' '/S';Wait-Uninstalled}catch{$report.pending+=('Guest cleanup incomplete: '+$_.Exception.Message)}}
 $report.pending+=@('The sampler requests 1ms sleeps; actual intervals must be measured. Samples alone do not prove inter-sample ownership. Assess native acquisition/release traces and terminal callbacks separately.','Physical native-write/topology/partial-provider, multi-account/session/integrity, operator hardware and signed update/full G3 require separate evidence.')
 $report.cleanup=[ordered]@{product_processes=@(Get-Process -Name pocketstream-desktop -ErrorAction SilentlyContinue|Select-Object Id,Path);installed_image_remains=(Test-Path -LiteralPath $image);registration_remains=(Test-Path -LiteralPath $uninstallKey);owned_rules=@(Owned).Count;profile_remaining=(Test-Path -LiteralPath $profile);sandbox_left_open=$true}
 $report.finished_utc=[DateTime]::UtcNow.ToString('o');Save-Report
 foreach($file in $manifest.inputs){Assert ((Get-FileHash -LiteralPath (Join-Path $inputRoot $file.name)).Hash.ToLowerInvariant() -eq $file.sha256) 'Input changed during guest execution.'}
 Stop-Transcript -ErrorAction SilentlyContinue|Out-Null
 [A4DebugReceiver]::Stop()
}
