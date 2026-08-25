#Requires -Version 5.1
# bundle-gstreamer.ps1
# Collects the minimum GStreamer runtime DLLs needed by PocketStream Desktop
# into src-tauri/resources/gstreamer/ for bundling with the NSIS installer.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts/bundle-gstreamer.ps1
#
# Requires: GStreamer MSVC x86_64 runtime installed
#           (env var GSTREAMER_1_0_ROOT_MSVC_X86_64 must be set)

[CmdletBinding()]
param(
    [string]$DependencyCacheDir,
    [switch]$ValidateManifestOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# ── Load the bundle manifest ──────────────────────────────────────────
# The pinned version and DLL lists live in gstreamer-manifest.psd1 so the
# third-party notices check validates the same data this script ships.

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Manifest  = Import-PowerShellDataFile (Join-Path $ScriptDir "gstreamer-manifest.psd1")

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-FileSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $actual = Get-Sha256 -Path $Path
    if ($actual -cne $Expected) {
        throw "$Description SHA256 mismatch: expected $Expected, got $actual ($Path)"
    }
}

function Assert-PatchedSrtManifest {
    param([Parameter(Mandatory = $true)][hashtable]$Srt)

    $required = @(
        'Version', 'RuntimeVersionHex', 'ReleaseTag', 'ArchiveFile',
        'AssetUrl', 'ArchiveSha256', 'DllFile', 'DllSha256'
    )
    foreach ($key in $required) {
        if (-not $Srt.ContainsKey($key) -or
            [string]::IsNullOrWhiteSpace([string]$Srt[$key])) {
            throw "PatchedSrt manifest field '$key' is missing or blank."
        }
    }

    if ($Srt.Version -notmatch '^\d+\.\d+\.\d+$') {
        throw "PatchedSrt.Version is invalid: $($Srt.Version)"
    }
    if ($Srt.RuntimeVersionHex -notmatch '^0x[0-9A-Fa-f]{6}$') {
        throw "PatchedSrt.RuntimeVersionHex is invalid: $($Srt.RuntimeVersionHex)"
    }
    if ($Srt.ReleaseTag -match '^[vV]' -or
        $Srt.ReleaseTag -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw "PatchedSrt.ReleaseTag must be a non-v* dependency tag: $($Srt.ReleaseTag)"
    }
    if ([System.IO.Path]::GetFileName($Srt.ArchiveFile) -cne $Srt.ArchiveFile -or
        $Srt.ArchiveFile -notmatch '\.zip$') {
        throw "PatchedSrt.ArchiveFile must be one ZIP filename: $($Srt.ArchiveFile)"
    }
    if ($Srt.DllFile -cne 'libsrt.dll') {
        throw "PatchedSrt.DllFile must be exactly libsrt.dll, got '$($Srt.DllFile)'."
    }
    foreach ($hashKey in @('ArchiveSha256', 'DllSha256')) {
        if ([string]$Srt[$hashKey] -notmatch '^[0-9a-f]{64}$') {
            throw "PatchedSrt.$hashKey must be a lowercase SHA256 value."
        }
    }

    try {
        $assetUri = New-Object System.Uri([string]$Srt.AssetUrl)
    } catch {
        throw "PatchedSrt.AssetUrl is not a valid absolute URL: $($Srt.AssetUrl)"
    }
    if (-not $assetUri.IsAbsoluteUri -or $assetUri.Scheme -cne 'https') {
        throw "PatchedSrt.AssetUrl must use HTTPS: $($Srt.AssetUrl)"
    }
    $expectedUrl = "https://github.com/RustRunner/PocketStream-Desktop/releases/download/$($Srt.ReleaseTag)/$($Srt.ArchiveFile)"
    if ($Srt.AssetUrl -cne $expectedUrl) {
        throw "PatchedSrt.AssetUrl must match its immutable release tag and filename: expected $expectedUrl"
    }
}

function Get-VerifiedPatchedSrtArchive {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Srt,
        [string]$CacheDir
    )

    if ([string]::IsNullOrWhiteSpace($CacheDir)) {
        if (-not [string]::IsNullOrWhiteSpace($env:POCKETSTREAM_DEPENDENCY_CACHE)) {
            $CacheDir = $env:POCKETSTREAM_DEPENDENCY_CACHE
        } else {
            $CacheDir = Join-Path ([System.IO.Path]::GetTempPath()) 'pocketstream-dependencies'
        }
    }
    $cacheFull = [System.IO.Path]::GetFullPath($CacheDir)
    if (Test-Path -LiteralPath $cacheFull -PathType Leaf) {
        throw "Dependency cache path is a file: $cacheFull"
    }
    New-Item -ItemType Directory -Force -Path $cacheFull | Out-Null

    $archivePath = Join-Path $cacheFull $Srt.ArchiveFile
    if (Test-Path -LiteralPath $archivePath -PathType Leaf) {
        try {
            Assert-FileSha256 -Path $archivePath -Expected $Srt.ArchiveSha256 -Description 'Cached patched libsrt archive'
        } catch {
            throw "Patched libsrt cache drift detected. Refusing to overwrite '$archivePath'. $($_.Exception.Message)"
        }
        Write-Host "Patched libsrt archive: verified cache hit" -ForegroundColor Green
        return $archivePath
    }

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) {
        throw 'curl.exe was not found; it is required to download the pinned patched libsrt archive.'
    }
    $downloadPath = "$archivePath.$PID.$([Guid]::NewGuid().ToString('N')).download"
    try {
        Write-Host "Downloading patched SRT $($Srt.Version) dependency..." -ForegroundColor Cyan
        & $curl.Source -fsSL --retry 3 --retry-delay 5 -o $downloadPath $Srt.AssetUrl
        if ($LASTEXITCODE -ne 0) {
            throw "download failed with exit code $LASTEXITCODE`: $($Srt.AssetUrl)"
        }
        Assert-FileSha256 -Path $downloadPath -Expected $Srt.ArchiveSha256 -Description 'Downloaded patched libsrt archive'
        if (Test-Path -LiteralPath $archivePath) {
            throw "Dependency cache destination appeared during download: $archivePath"
        }
        Move-Item -LiteralPath $downloadPath -Destination $archivePath
    } finally {
        if (Test-Path -LiteralPath $downloadPath -PathType Leaf) {
            Remove-Item -LiteralPath $downloadPath -Force
        }
    }
    Assert-FileSha256 -Path $archivePath -Expected $Srt.ArchiveSha256 -Description 'Cached patched libsrt archive'
    Write-Host "Patched libsrt archive: downloaded and verified" -ForegroundColor Green
    return $archivePath
}

function Install-PatchedSrt {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][hashtable]$Srt,
        [Parameter(Mandatory = $true)][string]$DestinationBin
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
    $extractDir = Join-Path $tempRoot "pocketstream-libsrt-extract-$PID-$([Guid]::NewGuid().ToString('N'))"
    $extractFull = [System.IO.Path]::GetFullPath($extractDir)
    if (-not $extractFull.StartsWith($tempRoot + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to use extraction path outside the temporary directory: $extractFull"
    }
    New-Item -ItemType Directory -Path $extractFull | Out-Null

    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
        try {
            $entryNames = @($zip.Entries | ForEach-Object { $_.FullName })
        } finally {
            $zip.Dispose()
        }

        foreach ($requiredEntry in @($Srt.DllFile, 'provenance.json', 'SHA256SUMS.txt')) {
            $matches = @($entryNames | Where-Object { $_ -ceq $requiredEntry })
            if ($matches.Count -ne 1) {
                throw "Patched libsrt archive must contain exactly one root '$requiredEntry' entry."
            }
        }
        $dllEntries = @($entryNames | Where-Object { (($_ -split '/')[-1]) -ieq $Srt.DllFile })
        if ($dllEntries.Count -ne 1 -or $dllEntries[0] -cne $Srt.DllFile) {
            throw "Patched libsrt archive contains an ambiguous libsrt.dll path."
        }
        if (@($entryNames | Where-Object { (($_ -split '/')[-1]) -ieq 'srt.dll' }).Count -gt 0) {
            throw 'Patched libsrt archive contains prohibited srt.dll; the 1.26.11 filename must be libsrt.dll.'
        }

        Expand-Archive -LiteralPath $ArchivePath -DestinationPath $extractFull
        $artifactDll = Join-Path $extractFull $Srt.DllFile
        Assert-FileSha256 -Path $artifactDll -Expected $Srt.DllSha256 -Description 'Inner patched libsrt.dll'

        $provenance = Get-Content -LiteralPath (Join-Path $extractFull 'provenance.json') -Raw | ConvertFrom-Json
        if ([int]$provenance.schema_version -ne 1 -or
            [string]$provenance.component.version -cne $Srt.Version -or
            [string]$provenance.component.expected_runtime_version_hex -cne $Srt.RuntimeVersionHex -or
            [string]$provenance.artifact.file -cne $Srt.DllFile -or
            ([string]$provenance.artifact.sha256).ToLowerInvariant() -cne $Srt.DllSha256) {
            throw 'Patched libsrt provenance does not match the manifest version, runtime version, filename, and DLL hash.'
        }
        $expectedSumLine = "$($Srt.DllSha256)  $($Srt.DllFile)"
        $sumLines = @(Get-Content -LiteralPath (Join-Path $extractFull 'SHA256SUMS.txt'))
        if ($sumLines -cnotcontains $expectedSumLine) {
            throw "Patched libsrt SHA256SUMS.txt does not contain '$expectedSumLine'."
        }

        $destinationDll = Join-Path $DestinationBin $Srt.DllFile
        if (-not (Test-Path -LiteralPath $destinationDll -PathType Leaf)) {
            throw "Stock GStreamer did not stage exact $($Srt.DllFile) before replacement: $destinationDll"
        }
        $stockLength = (Get-Item -LiteralPath $destinationDll).Length
        Copy-Item -LiteralPath $artifactDll -Destination $destinationDll -Force
        Assert-FileSha256 -Path $destinationDll -Expected $Srt.DllSha256 -Description 'Staged patched libsrt.dll'
        $patchedLength = (Get-Item -LiteralPath $destinationDll).Length
        Write-Host "Replaced stock libsrt.dll with verified SRT $($Srt.Version) ($($Srt.DllSha256))" -ForegroundColor Green
        return [long]$patchedLength - [long]$stockLength
    } finally {
        if (Test-Path -LiteralPath $extractFull -PathType Container) {
            Remove-Item -LiteralPath $extractFull -Recurse -Force
        }
    }
}

if (-not $Manifest.ContainsKey('PatchedSrt')) {
    throw 'gstreamer-manifest.psd1 has no PatchedSrt dependency contract.'
}
Assert-PatchedSrtManifest -Srt $Manifest.PatchedSrt
if ($ValidateManifestOnly) {
    Write-Host "Patched SRT manifest validation passed for $($Manifest.PatchedSrt.ReleaseTag)." -ForegroundColor Green
    return
}

# ── Locate GStreamer ──────────────────────────────────────────────────

$GstRoot = $env:GSTREAMER_1_0_ROOT_MSVC_X86_64
if (-not $GstRoot -or -not (Test-Path $GstRoot)) {
    Write-Error @"
GStreamer MSVC x86_64 not found.
Install from https://gstreamer.freedesktop.org/download/
and ensure GSTREAMER_1_0_ROOT_MSVC_X86_64 is set.
"@
    exit 1
}

$GstBin     = Join-Path $GstRoot "bin"
$GstPlugins = Join-Path $GstRoot "lib\gstreamer-1.0"

Write-Host "GStreamer root: $GstRoot" -ForegroundColor Cyan

# ── Verify SDK version ────────────────────────────────────────────────
# The bundle must match the version CI builds and links against (see the
# pinned MSI in .github/workflows/ci.yml). A drifted local SDK would ship
# a bundle whose DLLs don't match the import libs the exe was linked with.

$ExpectedVersion = $Manifest.PinnedVersion
$GstInspect = Join-Path $GstBin "gst-inspect-1.0.exe"
if (-not (Test-Path $GstInspect)) {
    Write-Error "gst-inspect-1.0.exe not found in $GstBin -- cannot verify the SDK version."
    exit 1
}
$VersionOutput = & $GstInspect --version | Out-String
if ($VersionOutput -match 'GStreamer\s+(\d+\.\d+\.\d+)') {
    $InstalledVersion = $Matches[1]
} else {
    Write-Error "Could not parse the GStreamer version from gst-inspect output."
    exit 1
}
if ($InstalledVersion -ne $ExpectedVersion) {
    Write-Error @"
GStreamer version mismatch: installed $InstalledVersion, expected $ExpectedVersion.
The bundle must match the version CI builds against. Install $ExpectedVersion from
https://gstreamer.freedesktop.org/data/pkg/windows/$ExpectedVersion/msvc/ and retry.
"@
    exit 1
}
Write-Host "GStreamer version: $InstalledVersion (matches expected)" -ForegroundColor Green

# Resolve and verify the canonical archive before replacing the output tree.
# A corrupt cache fails closed and is never silently refreshed.
$PatchedSrtArchive = Get-VerifiedPatchedSrtArchive `
    -Srt $Manifest.PatchedSrt -CacheDir $DependencyCacheDir

# ── Output directories ────────────────────────────────────────────────

$ProjectDir = Split-Path -Parent $ScriptDir
$OutBin     = Join-Path $ProjectDir "src-tauri\resources\gstreamer\bin"
$OutPlugins = Join-Path $ProjectDir "src-tauri\resources\gstreamer\lib\gstreamer-1.0"

# Clean previous bundle
if (Test-Path (Join-Path $ProjectDir "src-tauri\resources\gstreamer")) {
    Remove-Item -Recurse -Force (Join-Path $ProjectDir "src-tauri\resources\gstreamer")
}
New-Item -ItemType Directory -Force -Path $OutBin     | Out-Null
New-Item -ItemType Directory -Force -Path $OutPlugins  | Out-Null

# ── DLL lists (from the manifest) ────────────────────────────────────
# Core DLLs come from <root>/bin, plugins from <root>/lib/gstreamer-1.0.
# The per-DLL rationale comments live in gstreamer-manifest.psd1.

$CoreDlls = $Manifest.CoreDlls
$Plugins  = $Manifest.Plugins

# ── Copy files ────────────────────────────────────────────────────────

$totalSize = 0
$copied = 0
$missing = @()

Write-Host "`nCopying core DLLs..." -ForegroundColor Green
foreach ($dll in $CoreDlls) {
    $src = Join-Path $GstBin $dll
    if (Test-Path $src) {
        Copy-Item $src -Destination $OutBin
        $size = (Get-Item $src).Length
        $totalSize += $size
        $copied++
    } else {
        if ($dll -ceq $Manifest.PatchedSrt.DllFile) {
            # GStreamer 1.26.11's exact drop-in name is libsrt.dll. Never
            # accept srt.dll or a wildcard match from another SDK layout.
            $missing += "bin/$dll"
            continue
        }
        # Try wildcard match for versioned DLLs (e.g., x264-164.dll may differ)
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($dll) -replace '-\d+$', ''
        $match = Get-ChildItem $GstBin -Filter "$baseName*.dll" | Select-Object -First 1
        if ($match) {
            Copy-Item $match.FullName -Destination $OutBin
            $size = $match.Length
            $totalSize += $size
            $copied++
            Write-Host "  (matched $($match.Name) for $dll)" -ForegroundColor DarkYellow
        } else {
            $missing += "bin/$dll"
        }
    }
}

Write-Host "Copying plugins..." -ForegroundColor Green
foreach ($plugin in $Plugins) {
    $src = Join-Path $GstPlugins $plugin
    if (Test-Path $src) {
        Copy-Item $src -Destination $OutPlugins
        $size = (Get-Item $src).Length
        $totalSize += $size
        $copied++
    } else {
        $missing += "plugins/$plugin"
    }
}

if ($missing.Count -gt 0) {
    Write-Host "`n  MISSING ($($missing.Count)):" -ForegroundColor Red
    foreach ($m in $missing) {
        Write-Host "    - $m" -ForegroundColor Red
    }
    # Fatal: a partial bundle ships a broken installer silently. Every
    # listed DLL is required by a pipeline the app actually runs.
    Write-Error @"
Bundle is incomplete -- $($missing.Count) required file(s) missing. Install the full
GStreamer $ExpectedVersion runtime + devel (complete install, ADDLOCAL=ALL) and re-run.
"@
    exit 1
}

# Replace the copied stock 1.5.4 DLL only after the complete stock closure
# is present. The archive, inner hash, provenance, and staged hash are all
# checked by Install-PatchedSrt.
$totalSize += Install-PatchedSrt `
    -ArchivePath $PatchedSrtArchive -Srt $Manifest.PatchedSrt -DestinationBin $OutBin

# ── Summary ───────────────────────────────────────────────────────────

$sizeMB = [math]::Round($totalSize / 1MB, 1)
Write-Host "`n--- Bundle Summary ---" -ForegroundColor Cyan
Write-Host "  Copied: $copied files ($sizeMB MB)"
Write-Host "  Output: src-tauri/resources/gstreamer/"

Write-Host "`nDone. Run 'cargo tauri build' to create the installer." -ForegroundColor Green
