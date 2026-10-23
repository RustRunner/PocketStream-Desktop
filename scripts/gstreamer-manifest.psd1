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

    # Canonical SRT 1.5.6 drop-in built by build-patched-libsrt.ps1. The
    # release tag is deliberately outside v* so it cannot trigger or become
    # an application update. bundle-gstreamer.ps1 verifies the archive and
    # inner DLL hashes before replacing the stock 1.5.4 libsrt.dll.
    PatchedSrt = @{
        Version           = '1.5.6'
        RuntimeVersionHex = '0x010506'
        ReleaseTag        = 'deps-libsrt-1.5.6-gstreamer-1.26.11-1'
        ArchiveFile       = 'pocketstream-libsrt-1.5.6-gstreamer-1.26.11-windows-x86_64.zip'
        AssetUrl          = 'https://github.com/RustRunner/PocketStream-Desktop/releases/download/deps-libsrt-1.5.6-gstreamer-1.26.11-1/pocketstream-libsrt-1.5.6-gstreamer-1.26.11-windows-x86_64.zip'
        ArchiveSha256     = '21aa68ef59e443509756b22421638ba48db206dcffb323e4b080399095af43c4'
        DllFile           = 'libsrt.dll'
        DllSha256         = '45d2508afcd922f64124671965a1dabf02bca2bcc295d8c82f70c4653aaeab30'

        # Reproducibility and stock-ABI pins consumed by the G1-R runtime
        # verifier. These duplicate the machine-readable dependency artifact
        # deliberately: disagreement between the repository contract and the
        # published artifact must fail closed.
        SourceArchiveSha256 = '2c4980c2c4cfd142d21b829d939dc51db9c6628af5967fff62fd7290769569c7'
        CerberoCommit       = 'cebb549ade5b73048fc29be5a45332246f1c14f6'
        PatchedRecipeBlob   = '80037d6b64bda97413e143ffb58b8604b9c5ad9b'
        RecipePatchSha256   = '40d311f06bbf5f2911696b65769c51a8aaa744d07809c06291baa8bb30cf6430'
        MinGwCompilerSha256 = '114d0947d549750b1273d765a4fe415e7f2fdd1eb2a3bb2671e2735f20c50cd8'
        StockRuntimeUrl     = 'https://gstreamer.freedesktop.org/data/pkg/windows/1.26.11/msvc/gstreamer-1.0-msvc-x86_64-1.26.11.msi'
        StockRuntimeSha256  = '31cbc21fa0950b5c1e79c80959b2799805cb05a7a35953a13a9f790776137605'
        StockDllSha256      = '2bf7e00787cc8006a81d65f875e46ae75855e255128f9509edef331011c1a8eb'
        GstInspectSha256    = '2fe64504131d3e66671c361d67fdb5ccf7876bc5d061a5f9b97d1f4c03d04acd'
        GstLaunchSha256     = 'fca9e1c7c020f94fc941f9391dc6b5b3de758a062ff92e77a053f4a589833e34'

        # Exact seven-file closure exercised by G1-R. The OpenSSL DLL comes
        # from the pinned official GStreamer MSI, not the Cerbero build
        # prefix, so its staged hash is intentionally distinct from the
        # build-time dependency hash recorded inside provenance.json.
        StagedClosure = @{
            'bin/libsrt.dll'                         = '45d2508afcd922f64124671965a1dabf02bca2bcc295d8c82f70c4653aaeab30'
            'bin/libcrypto-3-x64.dll'                = '8a0e2418a3106c814a2c117c591750f34c0c1b9bef23d2e95dd36c61558e37e0'
            'bin/libstdc++-6.dll'                    = '6d8c75b04fa69225ee34cb65cd06b1dd6757640fb646851d8d87c453c8895812'
            'bin/libgcc_s_seh-1.dll'                 = '323372c82a994267b23140681c41c44f3aee0d0032ff9d884d69b1a1ed7f2ac1'
            'bin/libwinpthread-1.dll'                = '1e165b3f54a3f0387e4e3c1b5ae6143652aee4e4afd6e9474fcfde2cd8a92bbb'
            'lib/gstreamer-1.0/gstsrt.dll'           = 'bd6f5fdc71d5c1878e143359fef0468a0edda832977f77228d7bf037ab2805a3'
            'lib/gstreamer-1.0/gstmpegtsmux.dll'     = '55ae613b0d278ff834565177fe889744333f6d60603a52363ecc3f7f85ddd6a5'
        }
    }

    # Every DLL copied into the installer is locked to the exact byte content
    # of the pinned 1.26.11 runtime MSI, except libsrt.dll which is replaced by
    # PatchedSrt above. bundle-gstreamer.ps1 rejects missing, extra, renamed,
    # or hash-drifted files before Tauri can package them.
    BundleClosure = @{
        'bin/avcodec-61.dll'                              = 'd871f203550e02de688e5aa17323b2ffb8365f2f6fe4603f330eb450d5cadc19'
        'bin/avfilter-10.dll'                             = 'ae40b79002b86c1e563f3f0374cc0adabfbcc3b0c90c78ea07dce1ef5db7f42d'
        'bin/avformat-61.dll'                             = '3dfd6b1a561d005748ceb07df01354668c7765609b1c44836a663be9275e9d0d'
        'bin/avutil-59.dll'                               = 'd20ee7c1dec0f4211360efb17bc7220863d2ac3b7bb20c7b2c1db0d14d592fc2'
        'bin/bz2.dll'                                     = '3de90277f29a6324abcf28c5e4a075f2d010be32276b9e1740abec23be860c6f'
        'bin/ffi-7.dll'                                   = '7d38c1319a2209a6293703bc605172cc64f24bece7f67e115520079b4b3b2058'
        'bin/gio-2.0-0.dll'                               = '54a725774a57a19cfeaf98cde26d9ec8783aa396caec1b058718de4190acca32'
        'bin/glib-2.0-0.dll'                              = '52ffcad1def38b1dfaa8a4aeb7abedf3f24b0825ff16cc168d25152a010eb4a4'
        'bin/gmodule-2.0-0.dll'                           = 'a5fc50c81d3c0f6d4409677358a439d3e2810e0af4a0ddb46f5948c3e3faebdd'
        'bin/gobject-2.0-0.dll'                           = '8306cc2c7ba5d1b64804784335015cb65ccd85296a64e9b55a027288868ef97a'
        'bin/graphene-1.0-0.dll'                          = 'd73f4bb3a299642e0c2cb0f2cf44668f244428467500045e72dcfd939a996711'
        'bin/gstallocators-1.0-0.dll'                     = 'aff56dc96468c4a2362b465a964b99e2cb7ad627d9c781bebe7a2b3ebbbb034f'
        'bin/gstapp-1.0-0.dll'                            = '957f3b1d5c63d4bbcad9360ee2c187245ae58159e6fcbeba8fc3c7700e3ef954'
        'bin/gstaudio-1.0-0.dll'                          = '8978f2f4d9b1c6430ba019fa3c6247106b559afb9dcffc66d342a7491307d9d5'
        'bin/gstbase-1.0-0.dll'                           = '33160d36af07a794b72d89b40238b6ee1c78aa1d3ad9de3cc68f78fb35a3aa93'
        'bin/gstcodecparsers-1.0-0.dll'                   = '633ea9199b73c9ce9ed1e243a2cfa868715a7a9abed4047054a005312a7ceae9'
        'bin/gstcodecs-1.0-0.dll'                         = '8396191cea8c897678a6a442b1fc737d53c613d3bb3ce8ddb790aac078649b5d'
        'bin/gstcontroller-1.0-0.dll'                     = '880e4c5d7e7a64edd9cbf4a5606699085a17f5618c24a472d66060f67d3082aa'
        'bin/gstd3d11-1.0-0.dll'                          = '15109e41ffd990308e4b46beb13db29f49e200b19da71191067bde4e550e699c'
        'bin/gstd3dshader-1.0-0.dll'                      = 'db6548bdcc334e9010162933004e7bdb566fb5d8889d256573367ccd185c0ecf'
        'bin/gstdxva-1.0-0.dll'                           = 'f202d1887d5d669d6dd7b298dcdec4e99a58e52094f9437323cb5e942640bc36'
        'bin/gstgl-1.0-0.dll'                             = '972713b681d24d4fcd31b307700b5a7474639adadeda6b34e7a4ff6df4ad6a36'
        'bin/gstmpegts-1.0-0.dll'                         = '5a8a00a8c9bb4e02c1cabefd76474f36f12e6344da8f6c39ff2f45da020dd6f0'
        'bin/gstnet-1.0-0.dll'                            = '744c6955841397176d61b9ab68ee570a942f3c07a2296c8602035ae51f9e531a'
        'bin/gstpbutils-1.0-0.dll'                        = '60da310de8d70ea4a059998801abfcbb0776e487dfe1685da59974e8f7b68a93'
        'bin/gstreamer-1.0-0.dll'                         = '2d5a4e511fa2d306811e24ee9fe7e373e01554b07089c9584bcb23342c27e588'
        'bin/gstriff-1.0-0.dll'                           = '1d4158345a250b82d615ba558177e9ad2e45613cae17b57b379c728c50dc5f11'
        'bin/gstrtp-1.0-0.dll'                            = '93e95ae5794db30eb79711e122554059a31e40d5c02b8fdffa5df1ca4cd012bb'
        'bin/gstrtsp-1.0-0.dll'                           = '0d02ccaf72f18bea159bde0e15c2775a97a8a5e00045229f8c22986af7af6a96'
        'bin/gstrtspserver-1.0-0.dll'                     = 'eb852e5eb6671de7d810265b0694de104a0c3dfc6e47df09f3848174a29081e1'
        'bin/gstsdp-1.0-0.dll'                            = 'e742b36fcaaff9aab42e0dd657cce57d7257139ad00fa1b76aa0ca22ee8e0cc5'
        'bin/gsttag-1.0-0.dll'                            = 'f2a95b392b5fbfa726a81195ea4f2fcb995284ded1c169e28302f02a5d3ba9d9'
        'bin/gstvideo-1.0-0.dll'                          = '712354d5711ba65e337f95d65bf835c14af261aa0e74f7a0dda42c4b4027b466'
        'bin/intl-8.dll'                                  = '3e754c4e378f6a4e44268233dcf18dd68d2ef05e8edc1670f28ffa64ff0e0bf7'
        'bin/jpeg8.dll'                                   = '930870255cac71ef7dd324a7314f9443fbaf49138257239ef9aad7f1e6a8379a'
        'bin/libcrypto-3-x64.dll'                         = '8a0e2418a3106c814a2c117c591750f34c0c1b9bef23d2e95dd36c61558e37e0'
        'bin/libgcc_s_seh-1.dll'                          = '323372c82a994267b23140681c41c44f3aee0d0032ff9d884d69b1a1ed7f2ac1'
        'bin/libsrt.dll'                                  = '45d2508afcd922f64124671965a1dabf02bca2bcc295d8c82f70c4653aaeab30'
        'bin/libstdc++-6.dll'                             = '6d8c75b04fa69225ee34cb65cd06b1dd6757640fb646851d8d87c453c8895812'
        'bin/libwinpthread-1.dll'                         = '1e165b3f54a3f0387e4e3c1b5ae6143652aee4e4afd6e9474fcfde2cd8a92bbb'
        'bin/orc-0.4-0.dll'                               = '42dcb7649c460395ed1f083a1dc3005fa7036f057ac89d30e5ce8947af24feef'
        'bin/pcre2-8-0.dll'                               = 'b7a66d42b86fa4203a58477bb458796a23c1f8923dbd44e897f2361703e5faf7'
        'bin/png16.dll'                                   = '7e18a3a24bb1c40879d36bf84672e06a6eebcbcf3c469e6fe2daeade545067f4'
        'bin/swresample-5.dll'                            = '090e39ac8a9145379b4d6b788b15b8586b075f2c47fb5c0c6e33facfe0be0a6d'
        'bin/swscale-8.dll'                               = 'da9ff19a16a413f891233a2d96d550f46ad15f279cede3c2f4e946ae9428f13d'
        'bin/x264-164.dll'                                = '4f5b1183cfa786e6d328a3d754b4342204c50cb0e9919cd1209a3f6d0812c506'
        'bin/z-1.dll'                                     = 'fee5151ba5e9bec7835051c54eb5545031edb55e2318b0138e36304fc14144a0'
        'lib/gstreamer-1.0/gstalaw.dll'                   = '09134165a8cc536d7baed12f76c06f81ed72ba51605108ecf27b4a65a46afdb9'
        'lib/gstreamer-1.0/gstapp.dll'                    = 'c1d53673bccf0653d935283d495d03250db699d084d0c51c3c13435c466d6d01'
        'lib/gstreamer-1.0/gstaudioconvert.dll'           = 'd7fba1a7427e34b225a93671dfac62bc6deda3ebbc7976d2f7e831d162580ec4'
        'lib/gstreamer-1.0/gstaudioresample.dll'          = '3c02bfe7aff0de91efa70797f5f9b735c38ccdcaf29aa31eb4d0f78a205acee9'
        'lib/gstreamer-1.0/gstautodetect.dll'             = '2c03159c3072f5137b06485f16761927ae1ceedfa1a49b4e5bd10b97329286de'
        'lib/gstreamer-1.0/gstcodecalpha.dll'             = 'fdd97c51db89f051d95253f5eacf924c15ea1110868c728e0968c26d05b42e5b'
        'lib/gstreamer-1.0/gstcoreelements.dll'           = '140e6cd93db3c6d06240360b69b0bab17f91ef693d1d051b154ad64ff0cb444a'
        'lib/gstreamer-1.0/gstd3d11.dll'                  = '4c3804eedd08ee1e72f18083f38ec454c0a0cb644e116db20929e3a877676776'
        'lib/gstreamer-1.0/gstdirectsound.dll'            = 'a7228380219a08a4e155ad03015fd8f35a6f3199c261e17612a1409da79362d0'
        'lib/gstreamer-1.0/gstisomp4.dll'                 = 'c6f1cd874b3ef54e4056a50ae9019c4678b51c4f98f78e2a0fdf853641c037d8'
        'lib/gstreamer-1.0/gstlibav.dll'                  = 'f84ab8e0568c7341cb3ef79631edc1da22b8f1396ab63d75a8b37ad4887ba67f'
        'lib/gstreamer-1.0/gstmpegtsdemux.dll'            = 'eb303caaa8a17f949a15f3cccbe59b95c1397987fce2d2a2e86b4805cef2726c'
        'lib/gstreamer-1.0/gstmpegtsmux.dll'              = '55ae613b0d278ff834565177fe889744333f6d60603a52363ecc3f7f85ddd6a5'
        'lib/gstreamer-1.0/gstmulaw.dll'                  = '90bfb95772c27775be14b86fe18e15029352d20035e590f1e74066919bfa5f60'
        'lib/gstreamer-1.0/gstopengl.dll'                 = '303a55600031b793831233e6c12f7597b4d14a4360d955daef446973ca2b0da2'
        'lib/gstreamer-1.0/gstplayback.dll'               = '199534e86bb36fe5228f02f0c2a98c963221ce63792d998b10b0530d38a5d4b9'
        'lib/gstreamer-1.0/gstrawparse.dll'               = '993caf3b3cba42e56f1d4ef6fe73b14cac744b05645628dafe25c5713519a3f6'
        'lib/gstreamer-1.0/gstrtp.dll'                    = 'e897da1f5d9ef538d09b6c42932b9210ac8585aa8c04430ac2b0217a895e33b1'
        'lib/gstreamer-1.0/gstrtpmanager.dll'             = 'e03a81a698eab4b9ff92dd14c6bc39502cbb0198216a6c89a3f3e8e01e6911a7'
        'lib/gstreamer-1.0/gstrtsp.dll'                   = '03dafcc9f8df8afc02728ff4cc7fc1d43ed50346d370617c81dc4e3472a5a411'
        'lib/gstreamer-1.0/gstsrt.dll'                    = 'bd6f5fdc71d5c1878e143359fef0468a0edda832977f77228d7bf037ab2805a3'
        'lib/gstreamer-1.0/gsttcp.dll'                    = '6c46bb0fd2dfbb57213a578dca8fee7daa48e2854163e3be696aaa858eb55f5a'
        'lib/gstreamer-1.0/gsttypefindfunctions.dll'      = '0c90120ae30b4a51f98010a4136e12b289e952a2c48c4975c0df3c360ef94594'
        'lib/gstreamer-1.0/gstudp.dll'                    = '41c6d78885920ef2df9a7d695dc3933938df058c311daa3943975a44511ec129'
        'lib/gstreamer-1.0/gstvideoconvertscale.dll'      = 'debf5b1c494433a30846068e5406ecf4208162c28f21ac73e9a1a08d80043e81'
        'lib/gstreamer-1.0/gstvideoparsersbad.dll'        = 'a672f214a3defbfbb81a184096d9177c292971891aed269044861cab5503a576'
        'lib/gstreamer-1.0/gstvolume.dll'                 = 'e68c2057d2755109047caa39180d350178f08a542ffc80310ab828cba457cecb'
        'lib/gstreamer-1.0/gstwasapi2.dll'                = 'a3b3cda7eb8d64b45f8761daf0357007cb47e80ccf3895432d130ac08983eeca'
        'lib/gstreamer-1.0/gstx264.dll'                   = 'e5edcdb3e36dececec46221e10c759632ff7875b4c7f2207a19338068a39b25e'
    }

    # SourceRelease is the complete, hash-pinned native source inventory for
    # the DLL components below and the Cerbero inputs used to build them. A new
    # prerelease tag is used instead of mutating the earlier GStreamer-only
    # mirror after the SRT closure was added.
    SourceRelease = @{
        Tag            = 'deps-src-gstreamer-1.26.11-srt-1.5.6-1'
        Url            = 'https://github.com/RustRunner/PocketStream-Desktop/releases/tag/deps-src-gstreamer-1.26.11-srt-1.5.6-1'
        IndexFile      = 'SHA256SUMS.txt'
        IndexSha256    = 'cd359e660d72946277feadf4d918ff004562060b570ef1fead083f9ef2750da4'
        Assets = @{
            'bzip2' = @{ Version = '1.0.8'; SourceTag = '1.0.8'; File = 'bzip2-1.0.8.tar.gz'; Url = 'https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz'; Sha256 = 'ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269' }
            'cerbero' = @{ Version = '1.26.11'; SourceTag = '1.26.11'; File = 'cerbero-1.26.11.tar.gz'; Url = 'https://github.com/GStreamer/cerbero/archive/refs/tags/1.26.11.tar.gz'; Sha256 = 'c385254bd01a975a48087f28a10e530ae8444ca4351b07831cda60ca8f9c858c' }
            'ffmpeg' = @{ Version = '7.1'; SourceTag = 'n7.1'; File = 'ffmpeg-7.1.tar.xz'; Url = 'https://ffmpeg.org/releases/ffmpeg-7.1.tar.xz'; Sha256 = '40973d44970dbc83ef302b0609f2e74982be2d85916dd2ee7472d30678a7abe6' }
            'gcc' = @{ Version = '14.2.0'; SourceTag = 'releases/gcc-14.2.0'; File = 'gcc-14.2.0.tar.xz'; Url = 'https://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz'; Sha256 = 'a7b39bc69cbf9e25826c5a60ab26477001f7c08d85cec04bc0e29cabed6f3cc9' }
            'glib' = @{ Version = '2.80.5'; SourceTag = '2.80.5'; File = 'glib-2.80.5.tar.xz'; Url = 'https://download.gnome.org/sources/glib/2.80/glib-2.80.5.tar.xz'; Sha256 = '9f23a9de803c695bbfde7e37d6626b18b9a83869689dd79019bf3ae66c3e6771' }
            'graphene' = @{ Version = '1.10.8'; SourceTag = '1.10.8'; File = 'graphene-1.10.8.tar.gz'; Url = 'https://github.com/ebassi/graphene/archive/1.10.8.tar.gz'; Sha256 = '922dc109d2dc5dc56617a29bd716c79dd84db31721a8493a13a5f79109a4a4ed' }
            'gst-libav' = @{ Version = '1.26.11'; SourceTag = '1.26.11'; File = 'gst-libav-1.26.11.tar.xz'; Url = 'https://gstreamer.freedesktop.org/src/gst-libav/gst-libav-1.26.11.tar.xz'; Sha256 = '9bb3d2681ef0de92d1b1a9d955186236ee22e64f372db9bfc0d22e2d0df19865' }
            'gst-plugins-bad' = @{ Version = '1.26.11'; SourceTag = '1.26.11'; File = 'gst-plugins-bad-1.26.11.tar.xz'; Url = 'https://gstreamer.freedesktop.org/src/gst-plugins-bad/gst-plugins-bad-1.26.11.tar.xz'; Sha256 = '110fb82795f0e569b1e27b12ab9699d35c7762e1ff4db95335d6ac8d1442af3d' }
            'gst-plugins-base' = @{ Version = '1.26.11'; SourceTag = '1.26.11'; File = 'gst-plugins-base-1.26.11.tar.xz'; Url = 'https://gstreamer.freedesktop.org/src/gst-plugins-base/gst-plugins-base-1.26.11.tar.xz'; Sha256 = 'fc50f885d41f5d0407ce0876ec7235d9e7b82d48db2f4bc72c5f244a4ac79263' }
            'gst-plugins-good' = @{ Version = '1.26.11'; SourceTag = '1.26.11'; File = 'gst-plugins-good-1.26.11.tar.xz'; Url = 'https://gstreamer.freedesktop.org/src/gst-plugins-good/gst-plugins-good-1.26.11.tar.xz'; Sha256 = '001deb0876d5d743cd3448abf74a27adec3fd850012fcb1b00994861bd6c1145' }
            'gst-plugins-ugly' = @{ Version = '1.26.11'; SourceTag = '1.26.11'; File = 'gst-plugins-ugly-1.26.11.tar.xz'; Url = 'https://gstreamer.freedesktop.org/src/gst-plugins-ugly/gst-plugins-ugly-1.26.11.tar.xz'; Sha256 = 'bf9c9f72ee374825cfd43868c285bcb01700df2584069e75d7af455fe48244f8' }
            'gst-rtsp-server' = @{ Version = '1.26.11'; SourceTag = '1.26.11'; File = 'gst-rtsp-server-1.26.11.tar.xz'; Url = 'https://gstreamer.freedesktop.org/src/gst-rtsp-server/gst-rtsp-server-1.26.11.tar.xz'; Sha256 = 'b61d4304d8ceaaaa1ba139fb1ce935f04f1a73d7e18243c0a05b2fb04305406f' }
            'gstreamer' = @{ Version = '1.26.11'; SourceTag = '1.26.11'; File = 'gstreamer-1.26.11.tar.xz'; Url = 'https://gstreamer.freedesktop.org/src/gstreamer/gstreamer-1.26.11.tar.xz'; Sha256 = '2e0bd192d0438ea606a6f76a95c8e16542167656ffec2c2bc3aaf6ee0837fbf6' }
            'libffi' = @{ Version = '3.2.9999'; SourceTag = 'meson-3.2.9999.3'; File = 'libffi-meson-3.2.9999.3.tar.gz'; Url = 'https://gitlab.freedesktop.org/gstreamer/meson-ports/libffi/-/archive/meson-3.2.9999.3/libffi-meson-3.2.9999.3.tar.gz'; Sha256 = '0113d0f27ffe795158d06f56c9a7340fafc768586095b82a701c687ecb8e3672' }
            'libjpeg-turbo' = @{ Version = '3.1.0'; SourceTag = '3.1.0'; File = 'libjpeg-turbo-3.1.0.tar.gz'; Url = 'https://github.com/libjpeg-turbo/libjpeg-turbo/releases/download/3.1.0/libjpeg-turbo-3.1.0.tar.gz'; Sha256 = '9564c72b1dfd1d6fe6274c5f95a8d989b59854575d4bbee44ade7bc17aa9bc93' }
            'libpng' = @{ Version = '1.6.55'; SourceTag = 'v1.6.55'; File = 'libpng-1.6.55.tar.xz'; Url = 'https://downloads.sourceforge.net/project/libpng/libpng16/1.6.55/libpng-1.6.55.tar.xz'; Sha256 = 'd925722864837ad5ae2a82070d4b2e0603dc72af44bd457c3962298258b8e82d' }
            'mingw-w64' = @{ Version = '12.0.0'; SourceTag = 'v12.0.0'; File = 'mingw-w64-v12.0.0.tar.bz2'; Url = 'https://downloads.sourceforge.net/project/mingw-w64/mingw-w64/mingw-w64-release/mingw-w64-v12.0.0.tar.bz2'; Sha256 = 'cc41898aac4b6e8dd5cffd7331b9d9515b912df4420a3a612b5ea2955bbeed2f' }
            'openssl' = @{ Version = '3.5.0'; SourceTag = 'openssl-3.5.0'; File = 'openssl-3.5.0.tar.gz'; Url = 'https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz'; Sha256 = '344d0a79f1a9b08029b0744e2cc401a43f9c90acd1044d09a530b4885a8e9fc0' }
            'orc' = @{ Version = '0.4.41'; SourceTag = '0.4.41'; File = 'orc-0.4.41.tar.xz'; Url = 'https://gstreamer.freedesktop.org/src/orc/orc-0.4.41.tar.xz'; Sha256 = 'cb1bfd4f655289cd39bc04642d597be9de5427623f0861c1fc19c08d98467fa2' }
            'pcre2' = @{ Version = '10.42'; SourceTag = 'pcre2-10.42'; File = 'pcre2-10.42.tar.bz2'; Url = 'https://github.com/PhilipHazel/pcre2/releases/download/pcre2-10.42/pcre2-10.42.tar.bz2'; Sha256 = '8d36cd8cb6ea2a4c2bb358ff6411b0c788633a2a45dabbf1aeb4b701d1b5e840' }
            'proxy-libintl' = @{ Version = '0.4'; SourceTag = '0.4'; File = 'proxy-libintl-0.4.tar.gz'; Url = 'https://github.com/frida/proxy-libintl/archive/refs/tags/0.4.tar.gz'; Sha256 = '13ef3eea0a3bc0df55293be368dfbcff5a8dd5f4759280f28e030d1494a5dffb' }
            'srt' = @{ Version = '1.5.6'; SourceTag = 'v1.5.6'; File = 'srt-1.5.6.tar.gz'; Url = 'https://github.com/Haivision/srt/archive/v1.5.6.tar.gz'; Sha256 = '2c4980c2c4cfd142d21b829d939dc51db9c6628af5967fff62fd7290769569c7' }
            'srt-recipe-patch' = @{ Version = '1'; SourceTag = 'repository'; File = 'cerbero-srt-1.5.6.patch'; RepositoryPath = 'scripts/patches/cerbero-srt-1.5.6.patch'; Sha256 = '40d311f06bbf5f2911696b65769c51a8aaa744d07809c06291baa8bb30cf6430' }
            'x264' = @{ Version = '0.164.3108+git31e19f9'; SourceTag = '31e19f9'; File = 'x264_0.164.3108+git31e19f9.orig.tar.gz'; Url = 'https://gstreamer.freedesktop.org/src/mirror/x264_0.164.3108%2Bgit31e19f9.orig.tar.gz'; Sha256 = '41606cb8e788a7f8c4514290646d4ba5c7bc68d9e1ccd1a73f446a90546913eb' }
            'zlib' = @{ Version = '1.3.1'; SourceTag = 'v1.3.1'; File = 'zlib-1.3.1.tar.gz'; Url = 'https://zlib.net/fossils/zlib-1.3.1.tar.gz'; Sha256 = '9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23' }
        }
    }

    # Every component named by DllComponents has an exact upstream version,
    # source archive, and build origin. The SRT replacement also names its
    # tracked recipe override; everything else originates in the pinned MSI.
    ComponentMetadata = @{
        'bzip2'             = @{ Version = '1.0.8'; SourceAssets = @('bzip2'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'ffmpeg'             = @{ Version = '7.1'; SourceAssets = @('ffmpeg'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'gcc-runtime'        = @{ Version = '14.2.0'; SourceAssets = @('gcc'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'glib'               = @{ Version = '2.80.5'; SourceAssets = @('glib'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'graphene'           = @{ Version = '1.10.8'; SourceAssets = @('graphene'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'gst-libav'          = @{ Version = '1.26.11'; SourceAssets = @('gst-libav'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'gst-plugins-bad'    = @{ Version = '1.26.11'; SourceAssets = @('gst-plugins-bad'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'gst-plugins-base'   = @{ Version = '1.26.11'; SourceAssets = @('gst-plugins-base'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'gst-plugins-good'   = @{ Version = '1.26.11'; SourceAssets = @('gst-plugins-good'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'gst-plugins-ugly'   = @{ Version = '1.26.11'; SourceAssets = @('gst-plugins-ugly'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'gstreamer'          = @{ Version = '1.26.11'; SourceAssets = @('gstreamer'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'gst-rtsp-server'    = @{ Version = '1.26.11'; SourceAssets = @('gst-rtsp-server'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'libffi'             = @{ Version = '3.2.9999'; SourceAssets = @('libffi'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'libjpeg-turbo'      = @{ Version = '3.1.0'; SourceAssets = @('libjpeg-turbo'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'libpng'             = @{ Version = '1.6.55'; SourceAssets = @('libpng'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'openssl'            = @{ Version = '3.5.0'; SourceAssets = @('openssl'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'orc'                = @{ Version = '0.4.41'; SourceAssets = @('orc'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'pcre2'              = @{ Version = '10.42'; SourceAssets = @('pcre2'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'proxy-libintl'      = @{ Version = '0.4'; SourceAssets = @('proxy-libintl'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'srt'                = @{ Version = '1.5.6'; SourceAssets = @('srt'); BuildOrigin = 'patched-libsrt-dependency'; BuildInputs = @('cerbero', 'srt-recipe-patch') }
        'winpthreads'        = @{ Version = '12.0.0'; SourceAssets = @('mingw-w64'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'x264'               = @{ Version = '0.164.3108+git31e19f9'; SourceAssets = @('x264'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
        'zlib'               = @{ Version = '1.3.1'; SourceAssets = @('zlib'); BuildOrigin = 'gstreamer-1.26.11-msi'; BuildInputs = @('cerbero') }
    }

    SecurityReview = @{
        RecordPath             = 'docs/runtime-evidence/g3-security-review-2026-08-25.md'
        CanonicalTextSha256    = '98cd53cee3d0798d5677c67daab6387641db866512c362d911b783dcc3144347'
        ReviewedAt             = '2026-08-25'
        MaxAgeDays             = 30
        SrtVersion             = '1.5.6'
        SrtDllSha256           = '45d2508afcd922f64124671965a1dabf02bca2bcc295d8c82f70c4653aaeab30'
        OpenSslVersion         = '3.5.0'
        OpenSslDllSha256       = '8a0e2418a3106c814a2c117c591750f34c0c1b9bef23d2e95dd36c61558e37e0'
        RequiredAdvisoryIds    = @('CVE-2026-55869', 'CVE-2026-55868')
        OpenSslAdvisoryUrl     = 'https://openssl-library.org/news/vulnerabilities-3.5/'
    }

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
        'ffi-7.dll'
        'pcre2-8-0.dll'
        'z-1.dll'
        'orc-0.4-0.dll'

        # SRT output, its OpenSSL AES backend, and MinGW runtime closure.
        # The stock libsrt.dll is copied first, then replaced only by the
        # hash-pinned 1.5.6 artifact above.
        'libsrt.dll'
        'libcrypto-3-x64.dll'
        'libstdc++-6.dll'
        'libgcc_s_seh-1.dll'
        'libwinpthread-1.dll'

        # GnuTLS/nettle remain absent. SRT encryption uses OpenSSL libcrypto.

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

        # MPEG-TS muxer and SRT listener sink
        'gstmpegtsmux.dll'
        'gstsrt.dll'

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
        'gstmpegtsmux.dll'         = 'gst-plugins-bad'
        'gstsrt.dll'               = 'gst-plugins-bad'

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
        'ffi-7.dll'                = 'libffi'
        'pcre2-8-0.dll'            = 'pcre2'
        'z-1.dll'                  = 'zlib'
        'orc-0.4-0.dll'            = 'orc'
        'graphene-1.0-0.dll'       = 'graphene'
        'jpeg8.dll'                = 'libjpeg-turbo'
        'png16.dll'                = 'libpng'
        'bz2.dll'                  = 'bzip2'

        # SRT and its native dependency closure
        'libsrt.dll'               = 'srt'
        'libcrypto-3-x64.dll'      = 'openssl'
        'libstdc++-6.dll'          = 'gcc-runtime'
        'libgcc_s_seh-1.dll'       = 'gcc-runtime'
        'libwinpthread-1.dll'      = 'winpthreads'

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
