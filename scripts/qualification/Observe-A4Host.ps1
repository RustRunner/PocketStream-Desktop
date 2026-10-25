<# Read-only resource/status observation. Operator-approved duration is capped at
   ten minutes. This does not command motion, recording, playback or networking. #>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$RunRoot,[ValidateRange(1,600)][int]$DurationSeconds=600,[switch]$WaitForPlaying)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$launch=Get-Content -LiteralPath (Join-Path $RunRoot 'launch-result.json') -Raw|ConvertFrom-Json
$app=Get-Process -Id $launch.application_pid
Add-Type -TypeDefinition @'
using System;using System.Text;using System.Runtime.InteropServices;
public static class A4ReadProcess {
 [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder text,ref uint size);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 public static string Path(uint pid){var h=OpenProcess(0x1000,false,pid);if(h==IntPtr.Zero)throw new System.ComponentModel.Win32Exception();try{uint size=32768;var s=new StringBuilder((int)size);if(!QueryFullProcessImageName(h,0,s,ref size))throw new System.ComponentModel.Win32Exception();return s.ToString();}finally{CloseHandle(h);}}
}
'@
$observedPath=[A4ReadProcess]::Path([uint32]$app.Id)
if((Get-FileHash -LiteralPath $observedPath).Hash.ToLowerInvariant() -ne $launch.candidate_sha256){throw 'Unexpected candidate.'}
$path=Join-Path $RunRoot ('resource-observation-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmss')+'.json')
$record=[ordered]@{started_utc=[DateTime]::UtcNow.ToString('o');pid=$app.Id;sha256=$launch.candidate_sha256;requested_seconds=$DurationSeconds;status='observing';samples=@();candidate_still_running=$true;complete_duration=$false}
if($WaitForPlaying){
 $until=[DateTime]::UtcNow.AddMinutes(3);$playing=$false
 do{$stream=[IO.File]::Open((Join-Path $RunRoot 'application.stderr.log'),[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete));$reader=New-Object IO.StreamReader $stream;try{$playing=$reader.ReadToEnd().Contains('Playback pipeline set to Playing')}finally{$reader.Dispose()};if($playing){break};Start-Sleep -Milliseconds 500}while([DateTime]::UtcNow -lt $until)
 if(!$playing){throw 'Candidate Playing status was not observed; no resource-duration credit.'}
 $record.started_utc=[DateTime]::UtcNow.ToString('o')
}
$watch=[Diagnostics.Stopwatch]::StartNew()
try{
 do{
  $app.Refresh();if($app.HasExited){$record.candidate_still_running=$false;break}
  $record.samples+=@{utc=[DateTime]::UtcNow.ToString('o');elapsed_ms=$watch.ElapsedMilliseconds;cpu_seconds=$app.TotalProcessorTime.TotalSeconds;working_bytes=$app.WorkingSet64;private_bytes=$app.PrivateMemorySize64;handles=$app.HandleCount;threads=$app.Threads.Count}
  $record|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $path -Encoding UTF8
  $remaining=$DurationSeconds*1000-$watch.ElapsedMilliseconds;if($remaining -le 0){break};Start-Sleep -Milliseconds ([int][Math]::Min(5000,$remaining))
 }while($watch.Elapsed.TotalSeconds -lt $DurationSeconds)
 $record.complete_duration=$watch.Elapsed.TotalSeconds -ge $DurationSeconds -and $record.candidate_still_running
 $record.status=$(if($record.complete_duration){'ten-minute maximum observation completed; evaluate status/logs and resource samples'}else{'observation incomplete'})
}catch{$record.status='observation failed';$record['error']=$_.Exception.Message}
finally{$record['finished_utc']=[DateTime]::UtcNow.ToString('o');$record['elapsed_ms']=$watch.ElapsedMilliseconds;$record|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $path -Encoding UTF8}
