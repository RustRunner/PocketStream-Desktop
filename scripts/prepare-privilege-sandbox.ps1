<# Prepare immutable qualification inputs and a reusable .wsb file. This script
   never enables Windows features, runs an installer, or changes firewall policy.
   Run the generated launcher only after any required host restart. #>
[CmdletBinding()]
param(
    [string]$RunRoot,
    [string]$EvidencePath = 'docs/runtime-evidence/privilege-v2-final-qualification.json',
    [string]$LegacyInstaller,
    [string]$LegacySha256,
    [ValidateSet('Preflight', 'Supported', 'Remaining')][string]$Mode = 'Preflight',
    [switch]$ListenerOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path -Parent $PSScriptRoot
if($ListenerOnly -and $Mode -ne 'Remaining'){throw 'ListenerOnly requires the remaining-case fixture.'}
function Read-Json([string]$Path) { Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Verify($Reference) {
    $path = Join-Path $repository $Reference.path
    if ((Hash $path) -ne $Reference.sha256) { throw "Recorded input changed: $($Reference.path)" }
    return $path
}
function Write-Json($Value, [string]$Path) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 14) + "`n", [Text.UTF8Encoding]::new($false))
}
function Reject-Reparse([string]$Path) {
    $part = [IO.Path]::GetFullPath($Path)
    while ($part) {
        if ((Test-Path -LiteralPath $part) -and ((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Reparse fixture path is unsupported: $part"
        }
        $part = Split-Path -Parent $part
    }
}
if (!$RunRoot) { $RunRoot = Join-Path $repository ('src-tauri\target\privilege-final\sandbox-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')) }
$RunRoot = [IO.Path]::GetFullPath($RunRoot)
Reject-Reparse $RunRoot
if (Test-Path -LiteralPath $RunRoot) { throw 'Choose a new run folder; existing evidence is never overwritten.' }
if (![IO.Path]::IsPathRooted($EvidencePath)) { $EvidencePath = Join-Path $repository $EvidencePath }
$review = Read-Json $EvidencePath
$baseline = Read-Json (Join-Path $repository 'docs/runtime-evidence/privilege-v2-a3.json')
$sources = @{}
foreach ($file in @($baseline.source_inputs.application.files) + @($baseline.source_inputs.validation_tools.files) + @($review.source_inputs)) {
    $sources[$file.path] = $file
}
foreach ($file in $sources.Values) { $null = Verify $file }
$sourcePaths = [string[]]@($sources.Keys)
[Array]::Sort($sourcePaths, [StringComparer]::Ordinal)
$sourceLines = @($sourcePaths | ForEach-Object { $sources[$_].sha256 + '  ' + $_ + "`n" }) -join ''
$algorithm = [Security.Cryptography.SHA256]::Create()
try { $sourceDigest = ([BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($sourceLines)))).Replace('-', '').ToLowerInvariant() }
finally { $algorithm.Dispose() }
foreach ($entry in $review.artifacts.PSObject.Properties) { $null = Verify $entry.Value }
if ([bool]$LegacyInstaller -ne [bool]$LegacySha256) { throw 'A legacy installer requires its independently recorded SHA-256.' }
if ($LegacyInstaller -and (Hash $LegacyInstaller) -ne $LegacySha256.ToLowerInvariant()) { throw 'Legacy installer hash mismatch.' }
$inputs = Join-Path $RunRoot 'inputs'
$results = Join-Path $RunRoot 'results'
$inspection = Join-Path $RunRoot 'inspection'
New-Item -ItemType Directory -Path $inputs, $results, $inspection | Out-Null
$copies = [ordered]@{
    'candidate-setup.exe' = (Join-Path $repository $review.artifacts.package.path)
    'candidate-staged.exe' = (Join-Path $repository $review.artifacts.staged.path)
    'candidate-packaged.exe' = (Join-Path $repository $review.artifacts.embedded.path)
    'Invoke-PrivilegeSandbox.ps1' = (Join-Path $PSScriptRoot 'qualification\Invoke-PrivilegeSandbox.ps1')
    'Invoke-PrivilegeSandboxFailures.ps1' = (Join-Path $PSScriptRoot 'qualification\Invoke-PrivilegeSandboxFailures.ps1')
    'Invoke-PrivilegeSandboxRemaining.ps1' = (Join-Path $PSScriptRoot 'qualification\Invoke-PrivilegeSandboxRemaining.ps1')
    'verify-a1-production-smoke.ps1' = (Join-Path $PSScriptRoot 'verify-a1-production-smoke.ps1')
    'review.json' = $EvidencePath
}
if ($LegacyInstaller) { $copies['legacy-setup.exe'] = (Resolve-Path -LiteralPath $LegacyInstaller).Path }
foreach ($entry in $copies.GetEnumerator()) { Copy-Item -LiteralPath $entry.Value -Destination (Join-Path $inputs $entry.Key) }
# Extract manifest resources without loading application code or executing it.
$sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$mt = @(Get-ChildItem -LiteralPath $sdk -Directory | Sort-Object Name -Descending | ForEach-Object { Join-Path $_.FullName 'x64\mt.exe' } | Where-Object { Test-Path -LiteralPath $_ }) | Select-Object -First 1
if (!$mt) { throw 'Windows SDK mt.exe is required to inspect the exact image manifests.' }
foreach ($name in @('candidate-staged.exe', 'candidate-packaged.exe', 'candidate-setup.exe')) {
    $manifest = Join-Path $inspection ($name + '.manifest')
    & $mt -nologo ('-inputresource:' + (Join-Path $inputs $name) + ';#1') ('-out:' + $manifest)
    if ($LASTEXITCODE -ne 0) { throw "Manifest extraction failed: $name" }
    [xml]$xml = Get-Content -LiteralPath $manifest -Raw
    $level = $xml.SelectSingleNode("//*[local-name()='requestedExecutionLevel']")
    if (!$level -or $level.GetAttribute('level') -ne 'requireAdministrator') { throw "Administrator manifest missing: $name" }
    if (!$xml.SelectSingleNode("//*[local-name()='assemblyIdentity' and @name='Microsoft.Windows.Common-Controls']")) { throw "Common Controls manifest missing: $name" }
}
$staged = [IO.File]::ReadAllBytes((Join-Path $inputs 'candidate-staged.exe'))
$packaged = [IO.File]::ReadAllBytes((Join-Path $inputs 'candidate-packaged.exe'))
if ($staged.Length -ne $packaged.Length) { throw 'Executable sizes differ.' }
$offsets = @($review.marker_difference.offsets)
if ($offsets.Count -ne 3 -or [Text.Encoding]::ASCII.GetString($staged, $offsets[0], 3) -ne 'UNK' -or [Text.Encoding]::ASCII.GetString($packaged, $offsets[0], 3) -ne 'NSS') { throw 'Unexpected bundle marker.' }
foreach ($offset in $offsets) { $packaged[$offset] = $staged[$offset] }
$algorithm = [Security.Cryptography.SHA256]::Create()
try { $normalized = ([BitConverter]::ToString($algorithm.ComputeHash($packaged))).Replace('-', '').ToLowerInvariant() }
finally { $algorithm.Dispose() }
if ($normalized -ne $review.artifacts.staged.sha256) { throw 'Unexplained executable difference outside the three-byte bundle marker.' }
$sevenZip = Join-Path $env:ProgramFiles '7-Zip\7z.exe'
if (!(Test-Path -LiteralPath $sevenZip)) { throw '7-Zip is required for non-executing package inspection.' }
$extracted = Join-Path $inspection 'extracted'
& $sevenZip x '-y' ('-o' + $extracted) '--' (Join-Path $inputs 'candidate-setup.exe') | Set-Content -LiteralPath (Join-Path $inspection 'extraction.log') -Encoding UTF8
if ($LASTEXITCODE -ne 0) { throw 'Package extraction failed.' }
$payload = @(Get-ChildItem -LiteralPath $extracted -File -Recurse | ForEach-Object {
    $relative = $_.FullName.Substring($extracted.Length + 1)
    if ($relative -in @('pocketstream-desktop.exe','uninstall-bootstrap.ps1') -or $relative.StartsWith('resources\', [StringComparison]::OrdinalIgnoreCase)) { [ordered]@{path=$relative;sha256=(Hash $_.FullName);bytes=$_.Length} }
})
if (@($payload | Where-Object path -eq 'pocketstream-desktop.exe').Count -ne 1 -or $payload.Count -lt 90) { throw 'Unexpected extracted payload inventory.' }
$manifest = [ordered]@{
    version = 1; id = [Guid]::NewGuid().ToString(); prepared_utc = [DateTime]::UtcNow.ToString('o')
    host_computer = [Environment]::MachineName; source_count = $sources.Count; effective_source_sha256 = $sourceDigest
    source_digest_convention = 'Sort paths with StringComparer.Ordinal; SHA256 + two spaces + relative path + LF; review entries override baseline entries.'
    candidate = $review.artifacts; legacy_sha256 = $LegacySha256; mode = $Mode
    payload = $payload
    inputs = @(Get-ChildItem -LiteralPath $inputs -File | Sort-Object Name | ForEach-Object { [ordered]@{name=$_.Name;sha256=(Hash $_.FullName);bytes=$_.Length} })
}
Write-Json $manifest (Join-Path $inputs 'fixture.json')
$document = [xml]@'
<Configuration>
  <VGpu>Disable</VGpu><Networking>Enable</Networking><MemoryInMB>4096</MemoryInMB>
  <AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection><ClipboardRedirection>Disable</ClipboardRedirection>
  <MappedFolders>
    <MappedFolder><HostFolder/><SandboxFolder>C:\PocketStreamQualification\Inputs</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder/><SandboxFolder>C:\PocketStreamQualification\Results</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand><Command/></LogonCommand>
</Configuration>
'@
$mapped = $document.SelectNodes('/Configuration/MappedFolders/MappedFolder/HostFolder')
$mapped[0].InnerText = [string]$inputs
$mapped[1].InnerText = [string]$results
$document.SelectSingleNode('/Configuration/LogonCommand/Command').InnerText = 'powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File C:\PocketStreamQualification\Inputs\Invoke-PrivilegeSandbox.ps1 -Mode ' + $Mode
if ($Mode -eq 'Remaining') {
    $document.SelectSingleNode('/Configuration/LogonCommand/Command').InnerText = 'powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File C:\PocketStreamQualification\Inputs\Invoke-PrivilegeSandboxRemaining.ps1'
    if($ListenerOnly){$document.SelectSingleNode('/Configuration/LogonCommand/Command').InnerText += ' -ListenerOnly'}
}
$launcher = Join-Path $RunRoot 'PocketStream.wsb'
$document.Save($launcher)
Write-Json ([ordered]@{launcher=$launcher;launcher_sha256=(Hash $launcher);fixture_sha256=(Hash (Join-Path $inputs 'fixture.json'));source_count=$sources.Count;effective_source_sha256=$sourceDigest;inputs_read_only=$true;results=$results;mode=$Mode;launched=$false;installer_executed_on_host=$false}) (Join-Path $RunRoot 'prepared.json')
Write-Output $launcher
