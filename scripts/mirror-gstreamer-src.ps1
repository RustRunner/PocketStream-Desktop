# mirror-gstreamer-src.ps1
# Stages the corresponding source for every LGPL/GPL component in the
# bundled GStreamer runtime, ready to publish as a GitHub release. The
# staged set is what satisfies the source-availability terms of the
# LGPL-2.1 §6(d) / GPL-2 §3 "equivalent access" clauses for the DLLs
# the installer redistributes.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts/mirror-gstreamer-src.ps1 [-OutDir <dir>]
#
# After staging, publish (user step — note the tag rules below):
#
#   gh release create gst-src-<version> --prerelease `
#     --title "Third-party source: GStreamer <version> runtime" `
#     --notes "Corresponding source for the GStreamer runtime bundled with PocketStream Desktop releases. See SHA256SUMS.txt." `
#     <staging dir>\*
#
#   MUST be --prerelease: a plain release would become `releases/latest`
#   and break the updater, which resolves latest/download/latest.json.
#   The tag must NOT match `v*` or the release workflow would fire.
#   Afterwards, confirm `gh api repos/<owner>/<repo>/releases/latest`
#   still returns the newest application release.
#
# When the GStreamer pin bumps:
#   1. Update PinnedVersion in gstreamer-manifest.psd1 (the module
#      tarball URLs below derive from it).
#   2. Re-pin the four component tarballs below from the Cerbero
#      recipes at the new tag (github.com/GStreamer/cerbero,
#      recipes/{ffmpeg,x264,glib,proxy-libintl}.recipe — version and
#      tarball checksum fields).
#   3. Run this script, publish the new gst-src-<version> prerelease,
#      and update the release URL in THIRD-PARTY-NOTICES.md (the
#      notices check fails until the tag reference matches the pin).

param(
    [string]$OutDir
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Manifest  = Import-PowerShellDataFile (Join-Path $ScriptDir "gstreamer-manifest.psd1")
$Version   = $Manifest.PinnedVersion

if (-not $OutDir) {
    $OutDir = Join-Path $env:TEMP "gst-src-$Version"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Write-Host "Staging corresponding source for GStreamer $Version into $OutDir" -ForegroundColor Cyan

# ── Download list ─────────────────────────────────────────────────────

# GStreamer module tarballs: the release publishes a .sha256sum file
# next to each tarball; the expected hash is fetched from there.
$GstModules = @(
    "gstreamer"
    "gst-plugins-base"
    "gst-plugins-good"
    "gst-plugins-bad"
    "gst-plugins-ugly"
    "gst-libav"
    "gst-rtsp-server"
)

# Non-GStreamer copyleft components, pinned from the Cerbero recipes at
# tag $Version (see the pin-bump runbook above). The Sha256 values are
# the `tarball_checksum` fields of those recipes.
$Pinned = @(
    @{ File   = "ffmpeg-7.1.tar.xz"
       Url    = "https://ffmpeg.org/releases/ffmpeg-7.1.tar.xz"
       Sha256 = "40973d44970dbc83ef302b0609f2e74982be2d85916dd2ee7472d30678a7abe6" },
    @{ File   = "x264_0.164.3108+git31e19f9.orig.tar.gz"
       Url    = "https://gstreamer.freedesktop.org/src/mirror/x264_0.164.3108%2Bgit31e19f9.orig.tar.gz"
       Sha256 = "41606cb8e788a7f8c4514290646d4ba5c7bc68d9e1ccd1a73f446a90546913eb" },
    @{ File   = "glib-2.80.5.tar.xz"
       Url    = "https://download.gnome.org/sources/glib/2.80/glib-2.80.5.tar.xz"
       Sha256 = "9f23a9de803c695bbfde7e37d6626b18b9a83869689dd79019bf3ae66c3e6771" },
    @{ File   = "proxy-libintl-0.4.tar.gz"
       Url    = "https://github.com/frida/proxy-libintl/archive/refs/tags/0.4.tar.gz"
       Sha256 = "13ef3eea0a3bc0df55293be368dfbcff5a8dd5f4759280f28e030d1494a5dffb" }
)

# Cerbero (build recipes + patches — the scripts used to control
# compilation of the binary runtime). GitHub tag archives are not
# hash-stable across time, so this one is hashed at staging time; the
# uploaded asset plus SHA256SUMS.txt is the canonical artifact.
$CerberoFile = "cerbero-$Version.tar.gz"
$CerberoUrl  = "https://github.com/GStreamer/cerbero/archive/refs/tags/$Version.tar.gz"

# ── Helpers ───────────────────────────────────────────────────────────

function Get-RemoteFile {
    param([string]$Url, [string]$Dest)
    if (Test-Path $Dest) {
        Write-Host "  (already staged: $(Split-Path -Leaf $Dest))" -ForegroundColor DarkYellow
        return
    }
    curl.exe -fsSL --retry 3 --retry-delay 5 -o $Dest $Url
    if ($LASTEXITCODE -ne 0) {
        throw "download failed: $Url"
    }
}

function Assert-Sha256 {
    param([string]$Path, [string]$Expected)
    $actual = (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) {
        throw "SHA256 mismatch for $(Split-Path -Leaf $Path): expected $Expected, got $actual"
    }
}

$staged = @()

# ── GStreamer modules (hash from published .sha256sum) ───────────────

foreach ($module in $GstModules) {
    $file = "$module-$Version.tar.xz"
    $base = "https://gstreamer.freedesktop.org/src/$module/$file"
    Write-Host "Fetching $file" -ForegroundColor Green

    $sumText = curl.exe -fsSL --retry 3 --retry-delay 5 "$base.sha256sum"
    if ($LASTEXITCODE -ne 0) {
        throw "download failed: $base.sha256sum"
    }
    $expected = ($sumText -split '\s+')[0]
    if ($expected -notmatch '^[0-9a-fA-F]{64}$') {
        throw "could not parse expected hash for $file from '$sumText'"
    }

    $dest = Join-Path $OutDir $file
    Get-RemoteFile -Url $base -Dest $dest
    Assert-Sha256 -Path $dest -Expected $expected
    $staged += $file
}

# ── Pinned component tarballs ─────────────────────────────────────────

foreach ($item in $Pinned) {
    Write-Host "Fetching $($item.File)" -ForegroundColor Green
    $dest = Join-Path $OutDir $item.File
    Get-RemoteFile -Url $item.Url -Dest $dest
    Assert-Sha256 -Path $dest -Expected $item.Sha256
    $staged += $item.File
}

# ── Cerbero recipes ───────────────────────────────────────────────────

Write-Host "Fetching $CerberoFile" -ForegroundColor Green
$cerberoDest = Join-Path $OutDir $CerberoFile
Get-RemoteFile -Url $CerberoUrl -Dest $cerberoDest
$staged += $CerberoFile

# ── SHA256SUMS.txt ────────────────────────────────────────────────────

$sums = foreach ($file in $staged) {
    $hash = (Get-FileHash -Path (Join-Path $OutDir $file) -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $file"
}
Set-Content -Path (Join-Path $OutDir "SHA256SUMS.txt") -Value ($sums -join "`n") -Encoding ascii

# ── Summary ───────────────────────────────────────────────────────────

$totalMB = [math]::Round((Get-ChildItem $OutDir | Measure-Object Length -Sum).Sum / 1MB, 1)
Write-Host "`n--- Staging Summary ---" -ForegroundColor Cyan
Write-Host "  Staged: $($staged.Count) tarballs + SHA256SUMS.txt ($totalMB MB)"
Write-Host "  Output: $OutDir"
Write-Host "`nPublish with the gh release command in this script's header." -ForegroundColor Green
