# bundle-gstreamer.ps1
# Collects the minimum GStreamer runtime DLLs needed by PocketStream Desktop
# into src-tauri/resources/gstreamer/ for bundling with the NSIS installer.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts/bundle-gstreamer.ps1
#
# Requires: GStreamer MSVC x86_64 runtime installed
#           (env var GSTREAMER_1_0_ROOT_MSVC_X86_64 must be set)

$ErrorActionPreference = "Stop"

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

# ── Output directories ────────────────────────────────────────────────

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$OutBin     = Join-Path $ProjectDir "src-tauri\resources\gstreamer\bin"
$OutPlugins = Join-Path $ProjectDir "src-tauri\resources\gstreamer\lib\gstreamer-1.0"

# Clean previous bundle
if (Test-Path (Join-Path $ProjectDir "src-tauri\resources\gstreamer")) {
    Remove-Item -Recurse -Force (Join-Path $ProjectDir "src-tauri\resources\gstreamer")
}
New-Item -ItemType Directory -Force -Path $OutBin     | Out-Null
New-Item -ItemType Directory -Force -Path $OutPlugins  | Out-Null

# ── Core runtime DLLs (from bin/) ────────────────────────────────────
# These are the GStreamer + GLib shared libraries needed at runtime.

$CoreDlls = @(
    # GStreamer core
    "gstreamer-1.0-0.dll"
    "gstbase-1.0-0.dll"
    "gstapp-1.0-0.dll"
    "gstvideo-1.0-0.dll"
    "gstaudio-1.0-0.dll"
    "gstpbutils-1.0-0.dll"
    "gstnet-1.0-0.dll"
    "gsttag-1.0-0.dll"
    "gstrtp-1.0-0.dll"
    "gstrtsp-1.0-0.dll"
    "gstsdp-1.0-0.dll"
    "gstcodecparsers-1.0-0.dll"
    "gstgl-1.0-0.dll"
    "gstallocators-1.0-0.dll"
    "gstmpegts-1.0-0.dll"

    # RTSP server library
    "gstrtspserver-1.0-0.dll"

    # GLib / GObject / GIO
    "glib-2.0-0.dll"
    "gobject-2.0-0.dll"
    "gmodule-2.0-0.dll"
    "gio-2.0-0.dll"
    "intl-8.dll"
    "ffi-8.dll"
    "pcre2-8-0.dll"
    "z-1.dll"
    "orc-0.4-0.dll"

    # Crypto / TLS (needed by rtspsrc for SRTP/TLS)
    "gnutls-30.dll"
    "gmp-10.dll"
    "hogweed-6.dll"
    "nettle-8.dll"
    "p11-kit-0.dll"
    "tasn1-6.dll"

    # FFmpeg / libav (for avdec_h264)
    "avcodec-61.dll"
    "avutil-59.dll"
    "avfilter-10.dll"
    "swresample-5.dll"
    "swscale-8.dll"

    # x264 encoder
    "x264-164.dll"
)

# ── GStreamer plugins (from lib/gstreamer-1.0/) ──────────────────────
# Only the plugins actually used by PocketStream pipelines.

$Plugins = @(
    # Core elements: tee, queue, filesrc, filesink, identity
    "gstcoreelements.dll"

    # App elements: appsink, appsrc
    "gstapp.dll"

    # Auto-detect sinks: autovideosink, autoaudiosink
    "gstautodetect.dll"

    # Video convert + scale: videoconvert, videoscale
    "gstvideoconvertscale.dll"

    # Playback: decodebin, playbin, uridecodebin
    "gstplayback.dll"

    # Type-finding (required by decodebin)
    "gsttypefindfunctions.dll"

    # RTP: rtph264depay, rtph264pay
    "gstrtp.dll"

    # RTSP source: rtspsrc
    "gstrtsp.dll"

    # RTP session management (required by rtspsrc)
    "gstrtpmanager.dll"

    # UDP elements: udpsrc, udpsink
    "gstudp.dll"

    # TCP elements (used by RTSP interleaved transport)
    "gsttcp.dll"

    # MPEG-TS demuxer: tsdemux
    "gstmpegtsdemux.dll"

    # H.264 parser: h264parse
    "gstvideoparsersbad.dll"

    # FFmpeg/libav decoders: avdec_h264
    "gstlibav.dll"

    # x264 encoder: x264enc
    "gstx264.dll"

    # ISO MP4 muxer: mp4mux, qtmux
    "gstisomp4.dll"

    # Direct3D 11 video sink + decoder (Windows GPU-accelerated)
    "gstd3d11.dll"

    # OpenGL (fallback video rendering)
    "gstopengl.dll"

    # Raw video/audio capabilities
    "gstrawparse.dll"

    # Additional codecs decodebin may need
    "gstcodecalpha.dll"
)

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
    Write-Host "`n  Missing ($($missing.Count)):" -ForegroundColor Yellow
    foreach ($m in $missing) {
        Write-Host "    - $m" -ForegroundColor Yellow
    }
    Write-Host "`n  Missing DLLs are non-fatal -- the app may still work if" -ForegroundColor Yellow
    Write-Host "  those features aren't used, or a system GStreamer provides them." -ForegroundColor Yellow
}

Write-Host "`nDone. Run 'cargo tauri build' to create the installer." -ForegroundColor Green
