<# Fetch/verify the pinned Microsoft x64 VC runtime. Never execute it here. #>
[CmdletBinding()]
param([switch]$VerifyOnly)
$ErrorActionPreference='Stop'
$directory=Join-Path (Split-Path -Parent $PSScriptRoot) 'src-tauri\installer\prerequisites'
$path=Join-Path $directory 'VC_redist.x64.exe'
$expected='8995548dfffcde7c49987029c764355612ba6850ee09a7b6f0fddc85bdc5c280'
if(!(Test-Path -LiteralPath $path)){
 if($VerifyOnly){throw 'Run scripts/prepare-installer-prerequisites.ps1 before packaging.'}
 New-Item -ItemType Directory -Path $directory -Force|Out-Null
 Invoke-WebRequest -UseBasicParsing -Uri 'https://aka.ms/vs/18/release/14.50.35719/VC_redist.x64.exe' -OutFile $path
}
if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected){throw 'Pinned VC runtime hash mismatch; existing input preserved.'}
$signature=Get-AuthenticodeSignature -FilePath $path
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'CN=Microsoft Corporation,'){throw 'Pinned VC runtime Microsoft signature validation failed.'}
Write-Output 'Pinned Microsoft VC runtime 14.50.35719 x64 verified; no installer executed.'
