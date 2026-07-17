# Third-Party Notices

PocketStream Desktop is licensed under the GNU General Public License
v3.0 only (see the `LICENSE` file installed alongside the application).
This installation redistributes the third-party components listed below.

**GStreamer runtime.** The GStreamer 1.26.11 MSVC x86_64 runtime is
dynamically linked and installed under `resources\gstreamer\` in the
application directory. You may replace any of those DLLs with your own
builds of the same libraries (the mechanism required by LGPL-2.1 §6);
the application loads whatever compatible DLLs are present there.

**Corresponding source.** Complete source code for every LGPL/GPL
component below — including the build recipes used to produce the
binaries — is published at:
<https://github.com/RustRunner/PocketStream-Desktop/releases/tag/gst-src-1.26.11>

**License texts.** Full texts for every license referenced below are
installed under `resources\licenses\texts\`.

**Rust crates.** Notices for the Rust libraries compiled into the
application executable are generated at build time and installed as
`resources\licenses\generated\THIRD-PARTY-RUST.md`.

**Frontend.** The bundled web UI includes the npm packages listed at the
end of this file. The Tauri JavaScript API injected into the UI is part
of the Tauri Rust crates and is covered by the Rust crate notices.

---

## gstreamer

GStreamer core library and core elements.

- Version: 1.26.11
- License: LGPL-2.1-or-later — [texts/LGPL-2.1.txt](texts/LGPL-2.1.txt)
- Copyright © the GStreamer contributors
- Upstream: <https://gstreamer.freedesktop.org/>
- Source: gst-src-1.26.11 release (see above)

## gst-plugins-base

GStreamer base plugin libraries and elements (app, video, audio, RTP/RTSP
libraries, playback, OpenGL, and related plugins).

- Version: 1.26.11
- License: LGPL-2.1-or-later — [texts/LGPL-2.1.txt](texts/LGPL-2.1.txt)
- Copyright © the GStreamer contributors
- Upstream: <https://gstreamer.freedesktop.org/>
- Source: gst-src-1.26.11 release (see above)

## gst-plugins-good

GStreamer "good" plugins (RTP/RTSP handling, UDP, autodetect sinks,
ISO-MP4 muxing).

- Version: 1.26.11
- License: LGPL-2.1-or-later — [texts/LGPL-2.1.txt](texts/LGPL-2.1.txt)
- Copyright © the GStreamer contributors
- Upstream: <https://gstreamer.freedesktop.org/>
- Source: gst-src-1.26.11 release (see above)

## gst-plugins-bad

GStreamer "bad" plugin libraries and elements (codec parsers, MPEG-TS,
Direct3D 11, raw parsing).

- Version: 1.26.11
- License: LGPL-2.1-or-later — [texts/LGPL-2.1.txt](texts/LGPL-2.1.txt)
- Copyright © the GStreamer contributors
- Upstream: <https://gstreamer.freedesktop.org/>
- Source: gst-src-1.26.11 release (see above)

## gst-plugins-ugly

GStreamer "ugly" plugins (the x264 encoder element). The plugin code is
LGPL; because it links the GPL-licensed x264 library, the combination is
distributed under the GPL.

- Version: 1.26.11
- License: LGPL-2.1-or-later — [texts/LGPL-2.1.txt](texts/LGPL-2.1.txt)
  (combination with x264 distributed under [texts/GPL-2.0.txt](texts/GPL-2.0.txt))
- Copyright © the GStreamer contributors
- Upstream: <https://gstreamer.freedesktop.org/>
- Source: gst-src-1.26.11 release (see above)

## gst-libav

GStreamer FFmpeg wrapper plugin (H.264 decoding).

- Version: 1.26.11
- License: LGPL-2.1-or-later — [texts/LGPL-2.1.txt](texts/LGPL-2.1.txt)
- Copyright © the GStreamer contributors
- Upstream: <https://gstreamer.freedesktop.org/>
- Source: gst-src-1.26.11 release (see above)

## gst-rtsp-server

GStreamer RTSP server library.

- Version: 1.26.11
- License: LGPL-2.1-or-later — [texts/LGPL-2.1.txt](texts/LGPL-2.1.txt)
- Copyright © the GStreamer contributors
- Upstream: <https://gstreamer.freedesktop.org/>
- Source: gst-src-1.26.11 release (see above)

## glib

GLib, GObject, GModule, and GIO libraries.

- Version: 2.80.5
- License: LGPL-2.1-or-later — [texts/LGPL-2.1.txt](texts/LGPL-2.1.txt)
- Copyright © 1995 onwards Peter Mattis, Spencer Kimball, Josh MacDonald,
  and the GLib contributors
- Upstream: <https://gitlab.gnome.org/GNOME/glib>
- Source: gst-src-1.26.11 release (see above)

## proxy-libintl

Thin proxy for the gettext libintl API.

- Version: 0.4
- License: LGPL-2.0-or-later — [texts/LGPL-2.0.txt](texts/LGPL-2.0.txt)
- Copyright © 2008 Tor Lillqvist and the proxy-libintl contributors
- Upstream: <https://github.com/frida/proxy-libintl>
- Source: gst-src-1.26.11 release (see above)

## ffmpeg

FFmpeg libraries (libavcodec, libavutil, libavfilter, libavformat,
libswresample, libswscale), built in their LGPL configuration.

- Version: 7.1
- License: LGPL-2.1-or-later — [texts/LGPL-2.1.txt](texts/LGPL-2.1.txt)
- Copyright © the FFmpeg developers
- Upstream: <https://ffmpeg.org/>
- Source: gst-src-1.26.11 release (see above)

## x264

H.264/AVC encoder library.

- Version: 0.164.3108+git31e19f9
- License: GPL-2.0-or-later — [texts/GPL-2.0.txt](texts/GPL-2.0.txt)
- Copyright © 2003 onwards the x264 project
- Upstream: <https://www.videolan.org/developers/x264.html>
- Source: gst-src-1.26.11 release (see above)

## orc

Optimized Inner Loop Runtime Compiler.

- Version: 0.4.41
- License: BSD-3-Clause — [texts/BSD-3-Clause.txt](texts/BSD-3-Clause.txt)
- Copyright © 2002–2009 David A. Schleef
- Upstream: <https://gstreamer.freedesktop.org/modules/orc.html>

## libffi

Portable foreign-function interface library.

- Version: 3.2.9999
- License: MIT — [texts/MIT.txt](texts/MIT.txt)
- Copyright © 1996 onwards Anthony Green, Red Hat, Inc., and others
- Upstream: <https://sourceware.org/libffi/>

## pcre2

Perl-compatible regular expression library.

- Version: 10.42
- License: BSD-3-Clause — [texts/BSD-3-Clause.txt](texts/BSD-3-Clause.txt)
- Copyright © 1997 onwards University of Cambridge; © 2009 onwards
  Zoltán Herczeg
- Upstream: <https://github.com/PCRE2Project/pcre2>

## zlib

General-purpose compression library.

- Version: 1.3.1
- License: Zlib — [texts/Zlib.txt](texts/Zlib.txt)
- Copyright © 1995–2024 Jean-loup Gailly and Mark Adler
- Upstream: <https://zlib.net/>

## libjpeg-turbo

JPEG image codec library.

- Version: 3.1.0
- License: IJG, BSD-3-Clause, and Zlib (composite) —
  [texts/libjpeg-turbo-LICENSE.md](texts/libjpeg-turbo-LICENSE.md)
- Copyright © 2009 onwards the libjpeg-turbo Project; based in part on the
  work of the Independent JPEG Group
- Upstream: <https://libjpeg-turbo.org/>

## libpng

PNG reference library.

- Version: 1.6.55
- License: libpng-2.0 — [texts/libpng-2.0.txt](texts/libpng-2.0.txt)
- Copyright © 1995 onwards the PNG Reference Library Authors
- Upstream: <http://www.libpng.org/pub/png/libpng.html>

## bzip2

Block-sorting compression library.

- Version: 1.0.8
- License: bzip2-1.0.6 — [texts/bzip2.txt](texts/bzip2.txt)
- Copyright © 1996–2019 Julian Seward
- Upstream: <https://sourceware.org/bzip2/>

## graphene

Thin layer of graphic data types (vectors, matrices).

- Version: 1.10.8
- License: MIT — [texts/MIT.txt](texts/MIT.txt)
- Copyright © 2014 onwards Emmanuele Bassi
- Upstream: <https://github.com/ebassi/graphene>

## nsis

Nullsoft Scriptable Install System — the runtime embedded in the
application's setup executable.

- License: Zlib — [texts/Zlib.txt](texts/Zlib.txt)
- Copyright © 1999 onwards Contributors to the NSIS project
- Upstream: <https://nsis.sourceforge.io/>

## qrcode

QR code generation for the bundled web UI.

- Version: 1.5.4
- License: MIT — [texts/MIT.txt](texts/MIT.txt)
- Copyright © 2012 Ryan Day
- Upstream: <https://github.com/soldair/node-qrcode>

## dijkstrajs

Dijkstra path-finding (dependency of qrcode), adapted from the Dijkstar
Python project.

- Version: 1.0.3
- License: MIT — [texts/MIT.txt](texts/MIT.txt)
- Copyright © 2008 Wyatt Baldwin
- Upstream: <https://github.com/tcort/dijkstrajs>
