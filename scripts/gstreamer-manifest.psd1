# gstreamer-manifest.psd1
#
# Single source of truth for the bundled GStreamer runtime: the pinned
# version, the exact DLLs the installer ships, and the third-party
# component each DLL belongs to. Consumed by:
#   - bundle-gstreamer.ps1     (copies CoreDlls + Plugins, gates on PinnedVersion)
#   - check-third-party.ps1    (verifies every DLL maps to a component with a
#                               notices entry and a shipped license text)
#
# When adding a DLL, add it to CoreDlls or Plugins AND to DllComponents;
# the notices check fails the build if the map or the notices file lags.
@{
    PinnedVersion = '1.26.11'

    # ── Core runtime DLLs (from <root>/bin) ──────────────────────────
    # GStreamer + GLib shared libraries needed at runtime.
    CoreDlls = @(
        # GStreamer core
        'gstreamer-1.0-0.dll'
        'gstbase-1.0-0.dll'
        'gstapp-1.0-0.dll'
        'gstvideo-1.0-0.dll'
        'gstaudio-1.0-0.dll'
        'gstpbutils-1.0-0.dll'
        'gstnet-1.0-0.dll'
        'gsttag-1.0-0.dll'
        'gstrtp-1.0-0.dll'
        'gstrtsp-1.0-0.dll'
        'gstsdp-1.0-0.dll'
        'gstcodecparsers-1.0-0.dll'
        'gstgl-1.0-0.dll'
        'gstallocators-1.0-0.dll'
        'gstmpegts-1.0-0.dll'

        # D3D11 GPU decoding/rendering dependencies
        'gstd3d11-1.0-0.dll'
        'gstcodecs-1.0-0.dll'
        'gstd3dshader-1.0-0.dll'
        'gstdxva-1.0-0.dll'
        'gstcontroller-1.0-0.dll'
        'gstriff-1.0-0.dll'

        # OpenGL fallback + image format support
        'graphene-1.0-0.dll'
        'jpeg8.dll'
        'png16.dll'

        # RTSP server library
        'gstrtspserver-1.0-0.dll'

        # GLib / GObject / GIO
        'glib-2.0-0.dll'
        'gobject-2.0-0.dll'
        'gmodule-2.0-0.dll'
        'gio-2.0-0.dll'
        'intl-8.dll'
        'ffi-8.dll'
        'pcre2-8-0.dll'
        'z-1.dll'
        'orc-0.4-0.dll'

        # (No gnutls/nettle TLS stack: the MSVC runtime doesn't ship it and
        # the app streams over plain RTP/RTSP, not SRTP/TLS — a complete
        # install has none of these DLLs and the app runs fine without them.)

        # FFmpeg / libav (for avdec_h264)
        'avcodec-61.dll'
        'avutil-59.dll'
        'avfilter-10.dll'
        'avformat-61.dll'
        'bz2.dll'
        'swresample-5.dll'
        'swscale-8.dll'

        # x264 encoder
        'x264-164.dll'
    )

    # ── GStreamer plugins (from <root>/lib/gstreamer-1.0) ────────────
    # Only the plugins actually used by PocketStream pipelines.
    Plugins = @(
        # Core elements: tee, queue, filesrc, filesink, identity
        'gstcoreelements.dll'

        # App elements: appsink, appsrc
        'gstapp.dll'

        # Auto-detect sinks: autovideosink, autoaudiosink
        'gstautodetect.dll'

        # Video convert + scale: videoconvert, videoscale
        'gstvideoconvertscale.dll'

        # Playback: decodebin, playbin, uridecodebin
        'gstplayback.dll'

        # Type-finding (required by decodebin)
        'gsttypefindfunctions.dll'

        # RTP: rtph264depay, rtph264pay
        'gstrtp.dll'

        # RTSP source: rtspsrc
        'gstrtsp.dll'

        # RTP session management (required by rtspsrc)
        'gstrtpmanager.dll'

        # UDP elements: udpsrc, udpsink
        'gstudp.dll'

        # TCP elements (used by RTSP interleaved transport)
        'gsttcp.dll'

        # MPEG-TS demuxer: tsdemux
        'gstmpegtsdemux.dll'

        # H.264 parser: h264parse
        'gstvideoparsersbad.dll'

        # FFmpeg/libav decoders: avdec_h264
        'gstlibav.dll'

        # x264 encoder: x264enc
        'gstx264.dll'

        # ISO MP4 muxer: mp4mux, qtmux
        'gstisomp4.dll'

        # Direct3D 11 video sink + decoder (Windows GPU-accelerated)
        'gstd3d11.dll'

        # OpenGL (fallback video rendering)
        'gstopengl.dll'

        # Raw video/audio capabilities
        'gstrawparse.dll'

        # Additional codecs decodebin may need
        'gstcodecalpha.dll'

        # G.711 audio decoders: mulawdec, alawdec
        'gstmulaw.dll'
        'gstalaw.dll'

        # Audio branch plumbing: audioconvert, audioresample
        'gstaudioconvert.dll'
        'gstaudioresample.dll'

        # Audio mute control: volume
        'gstvolume.dll'

        # Windows audio sinks for autoaudiosink: wasapi2sink (primary),
        # directsoundsink (fallback on older images)
        'gstwasapi2.dll'
        'gstdirectsound.dll'
    )

    # ── DLL → third-party component ──────────────────────────────────
    # Component keys match the '## <component>' headings in
    # src-tauri/resources/licenses/THIRD-PARTY-NOTICES.md.
    DllComponents = @{
        # gstreamer (core)
        'gstreamer-1.0-0.dll'      = 'gstreamer'
        'gstbase-1.0-0.dll'        = 'gstreamer'
        'gstcontroller-1.0-0.dll'  = 'gstreamer'
        'gstnet-1.0-0.dll'         = 'gstreamer'
        'gstcoreelements.dll'      = 'gstreamer'

        # gst-plugins-base
        'gstapp-1.0-0.dll'         = 'gst-plugins-base'
        'gstvideo-1.0-0.dll'       = 'gst-plugins-base'
        'gstaudio-1.0-0.dll'       = 'gst-plugins-base'
        'gstpbutils-1.0-0.dll'     = 'gst-plugins-base'
        'gsttag-1.0-0.dll'         = 'gst-plugins-base'
        'gstrtp-1.0-0.dll'         = 'gst-plugins-base'
        'gstrtsp-1.0-0.dll'        = 'gst-plugins-base'
        'gstsdp-1.0-0.dll'         = 'gst-plugins-base'
        'gstgl-1.0-0.dll'          = 'gst-plugins-base'
        'gstallocators-1.0-0.dll'  = 'gst-plugins-base'
        'gstriff-1.0-0.dll'        = 'gst-plugins-base'
        'gstapp.dll'               = 'gst-plugins-base'
        'gstplayback.dll'          = 'gst-plugins-base'
        'gsttypefindfunctions.dll' = 'gst-plugins-base'
        'gstvideoconvertscale.dll' = 'gst-plugins-base'
        'gsttcp.dll'               = 'gst-plugins-base'
        'gstopengl.dll'            = 'gst-plugins-base'
        'gstaudioconvert.dll'      = 'gst-plugins-base'
        'gstaudioresample.dll'     = 'gst-plugins-base'
        'gstvolume.dll'            = 'gst-plugins-base'

        # gst-plugins-good
        'gstautodetect.dll'        = 'gst-plugins-good'
        'gstrtp.dll'               = 'gst-plugins-good'
        'gstrtsp.dll'              = 'gst-plugins-good'
        'gstrtpmanager.dll'        = 'gst-plugins-good'
        'gstudp.dll'               = 'gst-plugins-good'
        'gstisomp4.dll'            = 'gst-plugins-good'
        'gstmulaw.dll'             = 'gst-plugins-good'
        'gstalaw.dll'              = 'gst-plugins-good'
        'gstdirectsound.dll'       = 'gst-plugins-good'

        # gst-plugins-bad
        'gstcodecparsers-1.0-0.dll' = 'gst-plugins-bad'
        'gstmpegts-1.0-0.dll'      = 'gst-plugins-bad'
        'gstd3d11-1.0-0.dll'       = 'gst-plugins-bad'
        'gstcodecs-1.0-0.dll'      = 'gst-plugins-bad'
        'gstd3dshader-1.0-0.dll'   = 'gst-plugins-bad'
        'gstdxva-1.0-0.dll'        = 'gst-plugins-bad'
        'gstmpegtsdemux.dll'       = 'gst-plugins-bad'
        'gstvideoparsersbad.dll'   = 'gst-plugins-bad'
        'gstd3d11.dll'             = 'gst-plugins-bad'
        'gstrawparse.dll'          = 'gst-plugins-bad'
        'gstcodecalpha.dll'        = 'gst-plugins-bad'
        'gstwasapi2.dll'           = 'gst-plugins-bad'

        # gst-plugins-ugly
        'gstx264.dll'              = 'gst-plugins-ugly'

        # gst-libav
        'gstlibav.dll'             = 'gst-libav'

        # gst-rtsp-server
        'gstrtspserver-1.0-0.dll'  = 'gst-rtsp-server'

        # GLib
        'glib-2.0-0.dll'           = 'glib'
        'gobject-2.0-0.dll'        = 'glib'
        'gmodule-2.0-0.dll'        = 'glib'
        'gio-2.0-0.dll'            = 'glib'

        # Support libraries
        'intl-8.dll'               = 'proxy-libintl'
        'ffi-8.dll'                = 'libffi'
        'pcre2-8-0.dll'            = 'pcre2'
        'z-1.dll'                  = 'zlib'
        'orc-0.4-0.dll'            = 'orc'
        'graphene-1.0-0.dll'       = 'graphene'
        'jpeg8.dll'                = 'libjpeg-turbo'
        'png16.dll'                = 'libpng'
        'bz2.dll'                  = 'bzip2'

        # FFmpeg
        'avcodec-61.dll'           = 'ffmpeg'
        'avutil-59.dll'            = 'ffmpeg'
        'avfilter-10.dll'          = 'ffmpeg'
        'avformat-61.dll'          = 'ffmpeg'
        'swresample-5.dll'         = 'ffmpeg'
        'swscale-8.dll'            = 'ffmpeg'

        # x264
        'x264-164.dll'             = 'x264'
    }
}
