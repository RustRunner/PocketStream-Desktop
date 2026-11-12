# Pinned timestamp-bootstrap demux replacement

This is the 1.26.11 candidate tested in PocketStream evidence commit
`4d17a9945f28abd144bfdeb74c24de83d06941dd`. Its DLL is deliberately unchanged:
`824e7d9791aef8692a21eeced55637f304dcd7da4234c680c5753aad565e89f0`.
The plugin identifies itself as `1.26.11-peer-bootstrap-offline.1`; that metadata
is retained so the tested binary and its provenance stay exact.

Base source is GStreamer tag 1.26.11, commit
`e6ee9e63e033b9c8e343ba0bdfa7590ef81449ee`. Apply
`0001-tsdemux-bootstrap-and-tests.patch` to that source. The resulting local
source commit used for the binary was `d616643b9bab799e8e6f2c453722bc95f26cb813`.
The patch retains earlier untimestamped PES buffers and uses the first pending
PES with DTS or PTS for duration and clock-offset calculations. It neither
fabricates timestamps nor discards incomplete input.

Use an x64 MSVC 19.44.35224.0 / Windows SDK 10.0.26100.0 developer shell and the
official GStreamer 1.26.11 developer MSI headers and import libraries. Extract
the MSI as data; installing an SDK is unnecessary. Developer MSI SHA-256:
`af0a0720692052aaf5fb0cf2847ef34a87016ef0f914328d516f049e6c86f587`.
Runtime MSI SHA-256:
`31cbc21fa0950b5c1e79c80959b2799805cb05a7a35953a13a9f790776137605`.

Create a new evidence directory and its `runtime/patched/lib/gstreamer-1.0`
child, then run `Build-Peer.ps1 -Source <patched-tree> -Sdk <extracted-sdk>
-Evidence <new-output> -Condition patched`. The script records every argument,
source input, compiler identity and output. It builds only the six demux plugin
translation units and the focused upstream check executable. Build timestamps,
absolute PDB paths and compiler versions can change a rebuilt binary's hash;
an unpinned rebuild must not replace the declared release dependency.

The dependency ZIP contains exactly `gstmpegtsdemux.dll`, `provenance.json` and
`SHA256SUMS.txt`. Bundling verifies the complete ZIP, source/patch identities,
inner DLL and original vendor DLL before replacing only the staged plugin.
The other 75 bundled runtime DLLs remain unchanged. There is no runtime download
or installed-DLL patch operation in the application.

The complete corresponding-source inventory includes the original
`gst-plugins-bad-1.26.11.tar.xz`, this patch, build recipe and instructions,
alongside the existing native source closure. The upstream plugin's LGPL terms
and installed license notices continue to apply. Publish the verified source
prerelease before the application; draft readiness is not a published-source
G3 pass. No upstream submission is implied.
