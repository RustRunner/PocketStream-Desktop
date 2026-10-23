#Requires -Version 5.1
<#
.SYNOPSIS
Stages the complete, hash-pinned native source closure for publication.

.DESCRIPTION
Every bundled native component and its Cerbero build inputs are declared in
gstreamer-manifest.psd1. This script validates that contract, downloads or
copies each exact source asset, verifies SHA-256, and emits a deterministic
SHA256SUMS.txt. It never discovers versions or hashes from the network.

Publish the resulting directory only as the manifest-pinned prerelease:

  gh release create deps-src-gstreamer-1.26.11-srt-1.5.6-1 --prerelease `
    --title "Third-party source: GStreamer 1.26.11 + SRT 1.5.6" `
    --notes "Complete native source and build inputs for PocketStream Desktop. See SHA256SUMS.txt." `
    <staging-dir>\*

The tag must not match v*. After publication, confirm GitHub's releases/latest
still resolves to the newest application release.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File scripts\mirror-gstreamer-src.ps1 -OutDir C:\temp\pocketstream-source

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File scripts\mirror-gstreamer-src.ps1 -ValidateManifestOnly
#>

[CmdletBinding()]
param(
    [string]$OutDir,
    [switch]$ValidateManifestOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$ManifestPath = Join-Path $ScriptDir 'gstreamer-manifest.psd1'
$Manifest = Import-PowerShellDataFile $ManifestPath

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-Equal {
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Expected,
        [Parameter(Mandatory = $true)][string]$Description
    )
    if ([string]$Actual -cne [string]$Expected) {
        throw "$Description mismatch: expected '$Expected', got '$Actual'."
    }
}

function Assert-SourceManifest {
    param([Parameter(Mandatory = $true)][hashtable]$RootManifest)

    foreach ($key in @('SourceRelease', 'ComponentMetadata', 'DllComponents')) {
        if (-not $RootManifest.ContainsKey($key) -or $RootManifest[$key] -isnot [hashtable]) {
            throw "Manifest field '$key' is missing or is not a hashtable."
        }
    }

    $release = $RootManifest.SourceRelease
    foreach ($key in @('Tag', 'Url', 'IndexFile', 'IndexSha256', 'Assets')) {
        if (-not $release.ContainsKey($key) -or $null -eq $release[$key]) {
            throw "SourceRelease.$key is missing."
        }
    }
    if ($release.Tag -match '^[vV]' -or $release.Tag -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw "SourceRelease.Tag must be a non-v* dependency tag: $($release.Tag)"
    }
    $expectedUrl = "https://github.com/RustRunner/PocketStream-Desktop/releases/tag/$($release.Tag)"
    Assert-Equal -Actual $release.Url -Expected $expectedUrl -Description 'Source release URL'
    if ([System.IO.Path]::GetFileName([string]$release.IndexFile) -cne [string]$release.IndexFile) {
        throw 'SourceRelease.IndexFile must be one filename.'
    }
    if ([string]$release.IndexSha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$release.IndexSha256 -eq ('0' * 64)) {
        throw 'SourceRelease.IndexSha256 must be a non-zero lowercase SHA256 value.'
    }
    if ($release.Assets -isnot [hashtable] -or $release.Assets.Count -eq 0) {
        throw 'SourceRelease.Assets must be a non-empty hashtable.'
    }

    $seenFiles = @{}
    foreach ($assetId in @($release.Assets.Keys | Sort-Object)) {
        $asset = $release.Assets[$assetId]
        if ($asset -isnot [hashtable]) {
            throw "Source asset '$assetId' is not a hashtable."
        }
        foreach ($key in @('Version', 'SourceTag', 'File', 'Sha256')) {
            if (-not $asset.ContainsKey($key) -or
                [string]::IsNullOrWhiteSpace([string]$asset[$key])) {
                throw "Source asset '$assetId' field '$key' is missing or blank."
            }
        }
        if ([System.IO.Path]::GetFileName([string]$asset.File) -cne [string]$asset.File) {
            throw "Source asset '$assetId' File must be one filename."
        }
        $fileKey = ([string]$asset.File).ToLowerInvariant()
        if ($seenFiles.ContainsKey($fileKey)) {
            throw "Source assets '$assetId' and '$($seenFiles[$fileKey])' use the same filename."
        }
        $seenFiles[$fileKey] = $assetId
        if ([string]$asset.Sha256 -notmatch '^[0-9a-f]{64}$' -or
            [string]$asset.Sha256 -eq ('0' * 64)) {
            throw "Source asset '$assetId' must have a non-zero lowercase SHA256 value."
        }

        $hasUrl = $asset.ContainsKey('Url') -and
            -not [string]::IsNullOrWhiteSpace([string]$asset.Url)
        $hasRepositoryPath = $asset.ContainsKey('RepositoryPath') -and
            -not [string]::IsNullOrWhiteSpace([string]$asset.RepositoryPath)
        if ($hasUrl -eq $hasRepositoryPath) {
            throw "Source asset '$assetId' must declare exactly one of Url or RepositoryPath."
        }
        if ($hasUrl) {
            try {
                $uri = New-Object System.Uri([string]$asset.Url)
            } catch {
                throw "Source asset '$assetId' URL is invalid: $($asset.Url)"
            }
            if (-not $uri.IsAbsoluteUri -or $uri.Scheme -cne 'https') {
                throw "Source asset '$assetId' URL must use HTTPS."
            }
        } else {
            $sourcePath = [System.IO.Path]::GetFullPath((Join-Path $ProjectDir $asset.RepositoryPath))
            $projectPrefix = [System.IO.Path]::GetFullPath($ProjectDir).TrimEnd('\', '/') +
                [System.IO.Path]::DirectorySeparatorChar
            if (-not $sourcePath.StartsWith($projectPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Source asset '$assetId' resolves outside the repository: $sourcePath"
            }
            if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
                throw "Tracked source asset '$assetId' is missing: $sourcePath"
            }
            Assert-Equal -Actual (Get-Sha256 -Path $sourcePath) -Expected $asset.Sha256 `
                -Description "Tracked source asset '$assetId' SHA256"
        }
    }

    $components = @($RootManifest.DllComponents.Values | Sort-Object -Unique)
    $metadataComponents = @($RootManifest.ComponentMetadata.Keys | Sort-Object)
    $componentDelta = @(Compare-Object -ReferenceObject $components -DifferenceObject $metadataComponents)
    if ($componentDelta.Count -ne 0) {
        $details = @($componentDelta | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" })
        throw "ComponentMetadata must describe exactly every DllComponents value:`n$($details -join "`n")"
    }

    $referencedAssets = @{}
    foreach ($component in $components) {
        $metadata = $RootManifest.ComponentMetadata[$component]
        foreach ($key in @('Version', 'SourceAssets', 'BuildOrigin', 'BuildInputs')) {
            if (-not $metadata.ContainsKey($key) -or $null -eq $metadata[$key]) {
                throw "ComponentMetadata['$component'] field '$key' is missing."
            }
        }
        if ([string]::IsNullOrWhiteSpace([string]$metadata.Version) -or
            [string]::IsNullOrWhiteSpace([string]$metadata.BuildOrigin)) {
            throw "ComponentMetadata['$component'] has a blank version or build origin."
        }
        $sourceIds = @($metadata.SourceAssets)
        $buildIds = @($metadata.BuildInputs)
        if ($sourceIds.Count -eq 0 -or $buildIds.Count -eq 0) {
            throw "ComponentMetadata['$component'] must name source and build-input assets."
        }
        foreach ($assetId in @($sourceIds + $buildIds)) {
            if (-not $release.Assets.ContainsKey([string]$assetId)) {
                throw "ComponentMetadata['$component'] references unknown source asset '$assetId'."
            }
            $referencedAssets[[string]$assetId] = $true
        }
        foreach ($assetId in $sourceIds) {
            $sourceVersion = [string]$release.Assets[[string]$assetId].Version
            if ($sourceVersion -cne [string]$metadata.Version) {
                throw "Component '$component' version '$($metadata.Version)' does not match source '$assetId' version '$sourceVersion'."
            }
        }
    }
    foreach ($assetId in $release.Assets.Keys) {
        if (-not $referencedAssets.ContainsKey([string]$assetId)) {
            throw "Source asset '$assetId' is not referenced by any bundled component."
        }
    }

    Assert-Equal -Actual $release.Assets['srt'].Sha256 `
        -Expected $RootManifest.PatchedSrt.SourceArchiveSha256 `
        -Description 'SRT source inventory SHA256'
    Assert-Equal -Actual $release.Assets['srt-recipe-patch'].Sha256 `
        -Expected $RootManifest.PatchedSrt.RecipePatchSha256 `
        -Description 'SRT recipe source inventory SHA256'
}

function Get-RemoteFile {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    if (Test-Path -LiteralPath $Destination -PathType Leaf) {
        return
    }
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) {
        throw 'curl.exe is required to stage corresponding source.'
    }
    $downloadPath = "$Destination.$PID.$([Guid]::NewGuid().ToString('N')).download"
    try {
        & $curl.Source -fsSL --retry 3 --retry-delay 5 -o $downloadPath $Url
        if ($LASTEXITCODE -ne 0) {
            throw "download failed with exit $LASTEXITCODE`: $Url"
        }
        Move-Item -LiteralPath $downloadPath -Destination $Destination
    } finally {
        if (Test-Path -LiteralPath $downloadPath -PathType Leaf) {
            Remove-Item -LiteralPath $downloadPath -Force
        }
    }
}

Assert-SourceManifest -RootManifest $Manifest
if ($ValidateManifestOnly) {
    Write-Host ("Source manifest validation passed: {0} assets for {1} bundled components." -f `
        $Manifest.SourceRelease.Assets.Count, $Manifest.ComponentMetadata.Count) -ForegroundColor Green
    return
}

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path ([System.IO.Path]::GetTempPath()) $Manifest.SourceRelease.Tag
}
$OutDir = [System.IO.Path]::GetFullPath($OutDir).TrimEnd('\', '/')
if (Test-Path -LiteralPath $OutDir -PathType Leaf) {
    throw "Source staging path is a file: $OutDir"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Write-Host "Staging complete native source closure into $OutDir" -ForegroundColor Cyan

$expectedFiles = @($Manifest.SourceRelease.Assets.Values | ForEach-Object { [string]$_.File })
$expectedFiles += [string]$Manifest.SourceRelease.IndexFile
$unexpected = @(Get-ChildItem -LiteralPath $OutDir -File | Where-Object {
    $expectedFiles -cnotcontains $_.Name
})
if ($unexpected.Count -gt 0) {
    throw "Source staging directory contains unexpected files: $($unexpected.Name -join ', ')"
}

foreach ($assetId in @($Manifest.SourceRelease.Assets.Keys | Sort-Object)) {
    $asset = $Manifest.SourceRelease.Assets[$assetId]
    $destination = Join-Path $OutDir $asset.File
    Write-Host "Staging $($asset.File)" -ForegroundColor Green
    if ($asset.ContainsKey('RepositoryPath')) {
        $sourcePath = [System.IO.Path]::GetFullPath((Join-Path $ProjectDir $asset.RepositoryPath))
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
            Copy-Item -LiteralPath $sourcePath -Destination $destination
        }
    } else {
        Get-RemoteFile -Url $asset.Url -Destination $destination
    }
    Assert-Equal -Actual (Get-Sha256 -Path $destination) -Expected $asset.Sha256 `
        -Description "Staged source asset '$assetId' SHA256"
}

# Culture-sensitive sorting differs between Windows NLS and Linux ICU.
$sourceIds = [string[]]@($Manifest.SourceRelease.Assets.Keys)
[Array]::Sort($sourceIds, [StringComparer]::Ordinal)
$sumLines = foreach ($assetId in $sourceIds) {
    $asset = $Manifest.SourceRelease.Assets[$assetId]
    "$($asset.Sha256)  $($asset.File)"
}
$indexPath = Join-Path $OutDir $Manifest.SourceRelease.IndexFile
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($indexPath, (($sumLines -join "`n") + "`n"), $utf8NoBom)
Assert-Equal -Actual (Get-Sha256 -Path $indexPath) -Expected $Manifest.SourceRelease.IndexSha256 `
    -Description 'Staged source SHA256 index'

$actualFiles = @(Get-ChildItem -LiteralPath $OutDir -File | ForEach-Object { $_.Name } | Sort-Object)
$expectedFiles = @($expectedFiles | Sort-Object)
$delta = @(Compare-Object -ReferenceObject $expectedFiles -DifferenceObject $actualFiles)
if ($delta.Count -ne 0) {
    throw 'Staged source directory does not contain exactly the declared release assets.'
}

$totalBytes = (Get-ChildItem -LiteralPath $OutDir -File | Measure-Object Length -Sum).Sum
$totalMb = [Math]::Round($totalBytes / 1MB, 1)
Write-Host "Source closure passed: $($Manifest.SourceRelease.Assets.Count) assets + SHA256SUMS.txt ($totalMb MB)." -ForegroundColor Green
Write-Host "Publish as prerelease tag $($Manifest.SourceRelease.Tag)." -ForegroundColor Green
