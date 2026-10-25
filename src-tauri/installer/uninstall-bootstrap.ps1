<# Fixed standalone entry. A verified NSIS copy runs with _?= so this parent
   can wait for its actual result while the installed files are deleted. #>
[CmdletBinding()]
param([switch]$Silent,[switch]$Passive)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($Silent -and $Passive){throw 'Choose one uninstall mode.'}
if(![Environment]::Is64BitProcess){throw 'Use the native 64-bit Windows PowerShell standalone entry.'}
# Resolve cmdlets only from the operating system, before any ACL/hash checks or
# elevation. Inherited per-user PSModulePath must not supply privileged code.
$system=[Environment]::SystemDirectory
$windows=[Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
if(!$system -or !$windows){throw 'Trusted Windows directories unavailable.'}
$moduleRoot=[IO.Path]::Combine($system,'WindowsPowerShell\v1.0\Modules')
$env:PSModulePath=$moduleRoot
foreach($module in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security')){
 Import-Module -Name ([IO.Path]::Combine($moduleRoot,$module,($module+'.psd1'))) -ErrorAction Stop
}
$root=[IO.Path]::GetFullPath($PSScriptRoot)
$programFiles=[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
if(!$root.StartsWith($programFiles.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or $root -match '["\r\n]'){throw 'Uninstall bootstrap requires its protected installation root.'}
function Assert-Protected([string]$Path,[bool]$InstallRoot=$false){
 if((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse uninstall path refused.'}
 $acl=Get-Acl -LiteralPath $Path
 $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
 if($InstallRoot -and $owner -notin @('S-1-5-18','S-1-5-32-544')){throw 'Uninstall root owner is not privileged.'}
 $trusted=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if($rule.AccessControlType -eq 'Allow' -and !($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and ([int64]$rule.FileSystemRights -band 0x500d0156) -and $rule.IdentityReference.Value -notin $trusted){throw 'Uninstall path has an unprivileged writer.'}
 }
}
$component=$root
while($component.Length -ge $programFiles.Length){Assert-Protected $component ($component -eq $root);if($component -ieq $programFiles){break};$component=Split-Path -Parent $component}
$powershell=Join-Path $system 'WindowsPowerShell\v1.0\powershell.exe'
$arguments='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+$PSCommandPath+'"'
if($Silent){$arguments+=' -Silent'}elseif($Passive){$arguments+=' -Passive'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(!(New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
 # UAC is the fixed standalone installer entry, never a native-operation fallback.
 try{$p=Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -PassThru;$null=$p.Handle;$p.WaitForExit();exit $p.ExitCode}catch{Write-Error 'Standalone uninstall elevation failed or was cancelled.';exit 1223}
}
$source=Join-Path $root 'uninstall.exe'
Assert-Protected $source
$parent=Join-Path $windows 'Temp'
if((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse temporary parent refused.'}
$scratch=Join-Path $parent ('PocketStream-Uninstall-'+[Guid]::NewGuid().ToString('N'))
if(Test-Path -LiteralPath $scratch){throw 'Temporary uninstall directory already exists.'}
$security=[Security.AccessControl.DirectorySecurity]::new()
$security.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
([IO.DirectoryInfo]::new($scratch)).Create($security)
$copy=Join-Path $scratch 'uninstall.exe';$exitCode=71
try{
 Assert-Protected $scratch $true
 $uninstallInput=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{$uninstallOutput=[IO.File]::Open($copy,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$uninstallInput.CopyTo($uninstallOutput)}finally{$uninstallOutput.Dispose()}}finally{$uninstallInput.Dispose()}
 $sha=(Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant()
 if($sha -ne (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()){throw 'Copied uninstaller changed.'}
 $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$copy;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.WorkingDirectory=$system
 $info.Arguments=$(if($Silent){'/S '}elseif($Passive){'/P '}else{''})+'_?='+$root
 $info.EnvironmentVariables.Clear()
 foreach($key in @('SystemRoot','WINDIR')){$info.EnvironmentVariables[$key]=$windows}
 $info.EnvironmentVariables['PATH']=$system;$info.EnvironmentVariables['TEMP']=$scratch;$info.EnvironmentVariables['TMP']=$scratch
 $p=[Diagnostics.Process]::new();$p.StartInfo=$info;if(!$p.Start()){throw 'Copied uninstaller did not start.'};$null=$p.Handle;$p.WaitForExit();$exitCode=$p.ExitCode
 if(Test-Path -LiteralPath $root){@{version=1;child_exit=$exitCode;child_sha256=$sha;waited_for_child=$true;rollback_claimed=$false}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'pocketstream-bootstrap.json') -Encoding UTF8}
}catch{Write-Error $_ -ErrorAction Continue;$exitCode=71}
finally{
 # Delete only the two exact paths created above; no recursive cleanup.
 if([IO.Path]::GetDirectoryName($copy) -cne $scratch -or [IO.Path]::GetDirectoryName($scratch) -ine $parent){throw 'Temporary cleanup bounds changed.'}
 if(Test-Path -LiteralPath $copy){[IO.File]::Delete($copy)}
 try{[IO.Directory]::Delete($scratch,$false)}catch{Write-Warning 'Protected uninstall diagnostics retained in Windows Temp.'}
}
exit $exitCode
