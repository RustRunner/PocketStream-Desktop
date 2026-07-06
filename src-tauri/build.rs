fn main() {
    // Native library search path for Packet.lib. The ARP capture backend
    // is now the in-box PacketMonitor API (runtime LoadLibrary, no import
    // library), but `pnet` still links Packet.lib on Windows for its
    // interface layer — so this path and Packet.lib stay even though the
    // pcap crate and wpcap.lib are gone.
    let lib_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("lib");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    // Embed Windows manifest requesting administrator elevation (UAC)
    #[cfg(target_os = "windows")]
    {
        // Delay-load ALL native DLLs so the exe starts even when they
        // live in a subdirectory (resources/gstreamer/bin/).  Our Rust
        // startup code adds that directory to PATH before any GStreamer
        // function is actually called.
        println!("cargo:rustc-link-lib=delayimp");

        // Packet.dll (pnet's import). Delay-loaded so the exe starts
        // without Npcap present: interface enumeration goes through IP
        // Helper, never the capture path, so Packet.dll is never
        // actually loaded. wpcap.dll is gone with the pcap crate.
        println!("cargo:rustc-link-arg=/DELAYLOAD:Packet.dll");

        // GLib / GObject / GIO
        println!("cargo:rustc-link-arg=/DELAYLOAD:glib-2.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gobject-2.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gmodule-2.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gio-2.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:intl-8.dll");

        // GStreamer core
        println!("cargo:rustc-link-arg=/DELAYLOAD:gstreamer-1.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gstbase-1.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gstapp-1.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gstvideo-1.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gstaudio-1.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gstpbutils-1.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gstnet-1.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gsttag-1.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gstrtp-1.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gstrtsp-1.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gstsdp-1.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gstgl-1.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gstallocators-1.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gstcodecparsers-1.0-0.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:gstmpegts-1.0-0.dll");

        // GStreamer RTSP server
        println!("cargo:rustc-link-arg=/DELAYLOAD:gstrtspserver-1.0-0.dll");

        // The requireAdministrator manifest is embedded ONLY for release
        // builds. dev/test builds inherit it into the test harness too,
        // and running `cargo test` unelevated then fails with error 740.
        // The release workflow sets POCKETSTREAM_RELEASE; without it the
        // build runs asInvoker so tests work in any shell.
        println!("cargo:rerun-if-env-changed=POCKETSTREAM_RELEASE");
        let is_release = std::env::var_os("POCKETSTREAM_RELEASE").is_some();
        if is_release {
            let manifest =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("pocketstream.exe.manifest");
            println!("cargo:rerun-if-changed={}", manifest.display());
            let mut res = tauri_build::WindowsAttributes::new();
            res = res
                .app_manifest(std::fs::read_to_string(&manifest).expect("failed to read manifest"));
            tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(res))
                .expect("failed to run tauri-build");
        } else {
            tauri_build::build();
        }
        return;
    }

    #[allow(unreachable_code)]
    tauri_build::build()
}
