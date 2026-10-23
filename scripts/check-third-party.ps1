#Requires -Version 5.1
<#
.SYNOPSIS
Validates the complete third-party runtime, metadata, source, and notices contract.

.DESCRIPTION
This offline compliance gate cross-checks the committed manifest and resources:

1. CoreDlls and Plugins are exactly represented by the 76-file SHA-256 lock.
2. Every DLL maps to one versioned component with build and source metadata.
3. Every source/build input is pinned, referenced, and included in the
   deterministic corresponding-source index.
4. Every component and runtime npm dependency has a notices entry, and every
   notices entry references installed license text.
5. Notices point at the manifest-pinned corresponding-source prerelease.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$ManifestPath = Join-Path $ScriptDir 'gstreamer-manifest.psd1'
$NoticesPath = Join-Path $ProjectDir 'src-tauri\resources\licenses\THIRD-PARTY-NOTICES.md'
$TextsDir = Join-Path $ProjectDir 'src-tauri\resources\licenses\texts'
$PackagePath = Join-Path $ProjectDir 'package.json'

foreach ($requiredPath in @($ManifestPath, $NoticesPath, $TextsDir, $PackagePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        Write-Error "Missing required path: $requiredPath"
        exit 1
    }
}

$Manifest = Import-PowerShellDataFile $ManifestPath
$Notices = Get-Content -LiteralPath $NoticesPath -Raw
$failures = @()

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# 1. Declared DLLs, component map, and exact bundle lock.
$allDlls = @($Manifest.CoreDlls) + @($Manifest.Plugins)
$declaredPaths = @()
foreach ($dll in $Manifest.CoreDlls) {
    $declaredPaths += "bin/$dll"
}
foreach ($plugin in $Manifest.Plugins) {
    $declaredPaths += "lib/gstreamer-1.0/$plugin"
}

if (-not $Manifest.ContainsKey('BundleClosure') -or $Manifest.BundleClosure -isnot [hashtable]) {
    $failures += 'manifest: BundleClosure is missing or is not a hashtable'
} else {
    $lockedPaths = @($Manifest.BundleClosure.Keys)
    $closureDelta = @(Compare-Object -CaseSensitive `
        -ReferenceObject @($declaredPaths | Sort-Object) `
        -DifferenceObject @($lockedPaths | Sort-Object))
    foreach ($item in $closureDelta) {
        $failures += "manifest: BundleClosure path delta $($item.SideIndicator) '$($item.InputObject)'"
    }
    foreach ($relativePath in $lockedPaths) {
        if ([string]$Manifest.BundleClosure[$relativePath] -notmatch '^[0-9a-f]{64}$') {
            $failures += "manifest: BundleClosure '$relativePath' has no lowercase SHA256"
        }
    }
    foreach ($relativePath in $Manifest.PatchedSrt.StagedClosure.Keys) {
        if (-not $Manifest.BundleClosure.ContainsKey($relativePath) -or
            [string]$Manifest.BundleClosure[$relativePath] -cne
                [string]$Manifest.PatchedSrt.StagedClosure[$relativePath]) {
            $failures += "manifest: SRT closure hash disagrees with BundleClosure for '$relativePath'"
        }
    }
}

foreach ($dll in $allDlls) {
    if (-not $Manifest.DllComponents.ContainsKey($dll)) {
        $failures += "manifest: '$dll' has no DllComponents entry"
    }
}
foreach ($dll in $Manifest.DllComponents.Keys) {
    if ($allDlls -cnotcontains $dll) {
        $failures += "manifest: DllComponents entry '$dll' is not in CoreDlls or Plugins"
    }
}

$components = @($Manifest.DllComponents.Values | Sort-Object -Unique)
foreach ($component in $components) {
    if ($Notices -notmatch "(?m)^## $([regex]::Escape($component))\s*$") {
        $failures += "notices: no '## $component' entry"
    }
}

# 2. Versioned component/build/source metadata.
$hasMetadata = $Manifest.ContainsKey('ComponentMetadata') -and
    $Manifest.ComponentMetadata -is [hashtable]
$hasSourceRelease = $Manifest.ContainsKey('SourceRelease') -and
    $Manifest.SourceRelease -is [hashtable]
if (-not $hasMetadata) {
    $failures += 'manifest: ComponentMetadata is missing or is not a hashtable'
}
if (-not $hasSourceRelease) {
    $failures += 'manifest: SourceRelease is missing or is not a hashtable'
}

if ($hasMetadata -and $hasSourceRelease) {
    $metadataDelta = @(Compare-Object -CaseSensitive `
        -ReferenceObject @($components | Sort-Object) `
        -DifferenceObject @($Manifest.ComponentMetadata.Keys | Sort-Object))
    foreach ($item in $metadataDelta) {
        $failures += "manifest: ComponentMetadata delta $($item.SideIndicator) '$($item.InputObject)'"
    }

    $assets = $Manifest.SourceRelease.Assets
    if ($assets -isnot [hashtable] -or $assets.Count -eq 0) {
        $failures += 'manifest: SourceRelease.Assets is missing or empty'
    } else {
        $referencedAssets = @{}
        foreach ($component in $components) {
            if (-not $Manifest.ComponentMetadata.ContainsKey($component)) {
                continue
            }
            $metadata = $Manifest.ComponentMetadata[$component]
            foreach ($field in @('Version', 'SourceAssets', 'BuildOrigin', 'BuildInputs')) {
                if (-not $metadata.ContainsKey($field) -or $null -eq $metadata[$field]) {
                    $failures += "manifest: component '$component' has no $field metadata"
                }
            }

            $version = [string]$metadata.Version
            if ([string]::IsNullOrWhiteSpace($version)) {
                $failures += "manifest: component '$component' has a blank version"
            } else {
                $sectionPattern = '(?ms)^## ' + [regex]::Escape($component) + '\s*$(.*?)(?=^## |\z)'
                $sectionMatch = [regex]::Match($Notices, $sectionPattern)
                if ($sectionMatch.Success) {
                    $versionMatch = [regex]::Match(
                        $sectionMatch.Groups[1].Value,
                        '(?m)^- Version:\s*(.+?)\s*$'
                    )
                    if (-not $versionMatch.Success) {
                        $failures += "notices: component '$component' has no Version field"
                    } elseif ($versionMatch.Groups[1].Value -cne $version) {
                        $failures += "notices: component '$component' version '$($versionMatch.Groups[1].Value)' does not match manifest '$version'"
                    }
                }
            }

            foreach ($assetId in @(@($metadata.SourceAssets) + @($metadata.BuildInputs))) {
                $assetId = [string]$assetId
                if (-not $assets.ContainsKey($assetId)) {
                    $failures += "manifest: component '$component' references unknown source asset '$assetId'"
                } else {
                    $referencedAssets[$assetId] = $true
                }
            }
            foreach ($assetId in @($metadata.SourceAssets)) {
                if ($assets.ContainsKey([string]$assetId) -and
                    [string]$assets[[string]$assetId].Version -cne $version) {
                    $failures += "manifest: component '$component' and source '$assetId' versions differ"
                }
            }
        }

        $seenSourceFiles = @{}
        foreach ($assetId in $assets.Keys) {
            $asset = $assets[$assetId]
            foreach ($field in @('Version', 'SourceTag', 'File', 'Sha256')) {
                if (-not $asset.ContainsKey($field) -or
                    [string]::IsNullOrWhiteSpace([string]$asset[$field])) {
                    $failures += "manifest: source asset '$assetId' has no $field"
                }
            }
            if ([string]$asset.Sha256 -notmatch '^[0-9a-f]{64}$' -or
                [string]$asset.Sha256 -eq ('0' * 64)) {
                $failures += "manifest: source asset '$assetId' has no non-zero lowercase SHA256"
            }
            if ([System.IO.Path]::GetFileName([string]$asset.File) -cne [string]$asset.File) {
                $failures += "manifest: source asset '$assetId' does not use one filename"
            }
            $sourceFileKey = ([string]$asset.File).ToLowerInvariant()
            if ($seenSourceFiles.ContainsKey($sourceFileKey)) {
                $failures += "manifest: source assets '$assetId' and '$($seenSourceFiles[$sourceFileKey])' share a filename"
            } else {
                $seenSourceFiles[$sourceFileKey] = $assetId
            }

            $hasUrl = $asset.ContainsKey('Url') -and
                -not [string]::IsNullOrWhiteSpace([string]$asset.Url)
            $hasRepositoryPath = $asset.ContainsKey('RepositoryPath') -and
                -not [string]::IsNullOrWhiteSpace([string]$asset.RepositoryPath)
            if ($hasUrl -eq $hasRepositoryPath) {
                $failures += "manifest: source asset '$assetId' must have exactly one URL or repository path"
            } elseif ($hasUrl -and [string]$asset.Url -notmatch '^https://') {
                $failures += "manifest: source asset '$assetId' URL is not HTTPS"
            } elseif ($hasRepositoryPath) {
                $trackedPath = [System.IO.Path]::GetFullPath((Join-Path $ProjectDir $asset.RepositoryPath))
                if (-not (Test-Path -LiteralPath $trackedPath -PathType Leaf)) {
                    $failures += "manifest: tracked source asset '$assetId' is missing"
                } elseif ((Get-Sha256 -Path $trackedPath) -cne [string]$asset.Sha256) {
                    $failures += "manifest: tracked source asset '$assetId' hash differs"
                }
            }
            if (-not $referencedAssets.ContainsKey([string]$assetId)) {
                $failures += "manifest: source asset '$assetId' is not referenced by component metadata"
            }
        }

        # The pinned index must have identical ordering on Windows and Linux.
        $sourceIds = [string[]]@($assets.Keys)
        [Array]::Sort($sourceIds, [StringComparer]::Ordinal)
        $sumLines = foreach ($assetId in $sourceIds) {
            $asset = $assets[$assetId]
            "$($asset.Sha256)  $($asset.File)"
        }
        $indexText = ($sumLines -join "`n") + "`n"
        $indexBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($indexText)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $indexHash = ($sha.ComputeHash($indexBytes) |
                ForEach-Object { $_.ToString('x2') }) -join ''
        } finally {
            $sha.Dispose()
        }
        if ($indexHash -cne [string]$Manifest.SourceRelease.IndexSha256) {
            $failures += "manifest: source index hash mismatch (expected $($Manifest.SourceRelease.IndexSha256), derived $indexHash)"
        }
    }
}

# 3. Every notices entry references installed license text.
$sections = [regex]::Matches($Notices, '(?ms)^## (\S+)\s*$(.*?)(?=^## |\z)')
foreach ($section in $sections) {
    $name = $section.Groups[1].Value
    $body = $section.Groups[2].Value
    $refs = @([regex]::Matches($body, 'texts/([\w\.\-]+)') |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
    if ($refs.Count -eq 0) {
        $failures += "notices: entry '$name' references no license text"
        continue
    }
    foreach ($ref in $refs) {
        if (-not (Test-Path -LiteralPath (Join-Path $TextsDir $ref) -PathType Leaf)) {
            $failures += "notices: entry '$name' references missing text '$ref'"
        }
    }
}

# 4. Runtime npm dependencies have notices entries.
$package = Get-Content -LiteralPath $PackagePath -Raw | ConvertFrom-Json
if ($package.dependencies) {
    foreach ($dependency in $package.dependencies.PSObject.Properties.Name) {
        if ($Notices -notmatch "(?m)^## $([regex]::Escape($dependency))\s*$") {
            $failures += "notices: no '## $dependency' entry for npm dependency"
        }
    }
}

# 5. Notices identify the exact complete-source release.
if ($hasSourceRelease) {
    $sourceTag = [string]$Manifest.SourceRelease.Tag
    if ($Notices -notmatch [regex]::Escape($sourceTag)) {
        $failures += "notices: no reference to corresponding-source tag '$sourceTag'"
    }
    if ($Notices -notmatch [regex]::Escape([string]$Manifest.SourceRelease.Url)) {
        $failures += "notices: no reference to corresponding-source URL '$($Manifest.SourceRelease.Url)'"
    }
}

if ($failures.Count -gt 0) {
    Write-Host "Third-party closure check FAILED ($($failures.Count)):" -ForegroundColor Red
    foreach ($failure in $failures) {
        Write-Host "  - $failure" -ForegroundColor Red
    }
    Write-Error 'Third-party runtime, source, and notices metadata are out of sync.'
    exit 1
}

Write-Host ("Third-party closure check passed: {0} hash-locked DLLs across {1} versioned components, {2} source assets, notices and npm dependencies covered." -f `
    $allDlls.Count, $components.Count, $Manifest.SourceRelease.Assets.Count) -ForegroundColor Green
