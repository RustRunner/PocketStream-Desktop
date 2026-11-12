$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'install.ps1')
$root = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) ('src-tauri/target/tsdemux-staging-tests-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression
function Digest([string]$path) { (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() }
function Check($condition,[string]$reason) { if (!$condition) { throw $reason } }
$stock = Join-Path $root 'staged-plugin.dll'; $replacement = Join-Path $root 'replacement.dll'
[IO.File]::WriteAllBytes($stock,[byte[]]@(1,2,3)); [IO.File]::WriteAllBytes($replacement,[byte[]]@(4,5,6))
$stockHash = Digest $stock; $replacementHash = Digest $replacement
$pins = @{ DllSha256=$replacementHash; StockDllSha256=$stockHash; BaseCommit=('a'*40); SourceCommit=('b'*40); PatchSha256=('c'*64) }
function Archive([string]$label,[string]$base=$pins.BaseCommit,[switch]$BadDll,[switch]$Traversal) {
 $path = Join-Path $root ($label+'.zip')
 $zip = [IO.Compression.ZipFile]::Open($path,[IO.Compression.ZipArchiveMode]::Create)
 try {
  $entry=$zip.CreateEntry('gstmpegtsdemux.dll');$stream=$entry.Open()
  try { $bytes=if($BadDll){[byte[]]@(7,8,9)}else{[IO.File]::ReadAllBytes($replacement)};$stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
  $entry=$zip.CreateEntry('provenance.json');$writer=New-Object IO.StreamWriter ($entry.Open())
  try { $writer.Write((@{schema=1;base_commit=$base;source_commit=$pins.SourceCommit;patch_sha256=$pins.PatchSha256;dll_sha256=$pins.DllSha256}|ConvertTo-Json)) } finally { $writer.Dispose() }
  $entry=$zip.CreateEntry('SHA256SUMS.txt');$writer=New-Object IO.StreamWriter ($entry.Open())
  try { $writer.Write($pins.DllSha256+'  gstmpegtsdemux.dll') } finally { $writer.Dispose() }
  if($Traversal){$entry=$zip.CreateEntry('../escaped.dll');$stream=$entry.Open();$stream.Dispose()}
 } finally { $zip.Dispose() }
 return $path
}
$results=@()
foreach($case in @('bad-archive','wrong-source','wrong-inner-dll','traversal')) {
 $path=switch($case){'wrong-source'{Archive $case -base ('d'*40)}'wrong-inner-dll'{Archive $case -BadDll}'traversal'{Archive $case -Traversal}default{Archive $case}}
 $pins.ArchiveSha256=if($case -eq 'bad-archive'){'e'*64}else{Digest $path}
 $failed=$false
 try { $null=Install-StagedTsdemux -ArchivePath $path -Demux $pins -DestinationPlugin $stock } catch { $failed=$true }
 Check $failed ('Unsafe archive accepted: '+$case)
 Check ((Digest $stock) -ceq $stockHash) ('Rejected archive changed staged vendor bytes: '+$case)
 Check (!(Test-Path -LiteralPath (Join-Path $root 'escaped.dll'))) 'ZIP path escaped staging'
 $results+=@{case=$case;rejected=$true;vendor_unchanged=$true}
}
$path=Archive 'valid';$pins.ArchiveSha256=Digest $path
$null=Install-StagedTsdemux -ArchivePath $path -Demux $pins -DestinationPlugin $stock
Check ((Digest $stock) -ceq $replacementHash) 'Verified replacement was not staged exactly'
$failed=$false
try { $null=Install-StagedTsdemux -ArchivePath $path -Demux $pins -DestinationPlugin $stock } catch { $failed=$true }
Check $failed 'Replacement accepted without original vendor precondition'
$results+=@{case='verified-replacement-and-vendor-precondition';passed=$true}
$results|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'results.json') -Encoding UTF8
Write-Output ('Passed 5 tsdemux staging cases; evidence '+$root)
