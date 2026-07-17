# bundle-gstreamer.ps1
# Collects the minimum GStreamer runtime DLLs needed by PocketStream Desktop
# into src-tauri/resources/gstreamer/ for bundling with the NSIS installer.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts/bundle-gstreamer.ps1
#
# Requires: GStreamer MSVC x86_64 runtime installed
#           (env var GSTREAMER_1_0_ROOT_MSVC_X86_64 must be set)

$ErrorActionPreference = "Stop"

# ── Load the bundle manifest ──────────────────────────────────────────
# The pinned version and DLL lists live in gstreamer-manifest.psd1 so the
# third-party notices check validates the same data this script ships.

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Manifest  = Import-PowerShellDataFile (Join-Path $ScriptDir "gstreamer-manifest.psd1")

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

# ── Summary ───────────────────────────────────────────────────────────

$sizeMB = [math]::Round($totalSize / 1MB, 1)
Write-Host "`n--- Bundle Summary ---" -ForegroundColor Cyan
Write-Host "  Copied: $copied files ($sizeMB MB)"
Write-Host "  Output: src-tauri/resources/gstreamer/"

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

Write-Host "`nDone. Run 'cargo tauri build' to create the installer." -ForegroundColor Green
