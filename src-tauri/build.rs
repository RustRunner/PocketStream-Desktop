// The application ACL is opt-in in Tauri 2. Keep this list in lockstep with
// generate_handler!, renderer wrappers and committed generated permissions.
const COMMANDS: &[&str] = &[
    "add_manual_node",
    "add_secondary_ip",
    "apply_restream_settings",
    "clear_manual_nodes",
    "control_cgi_zoom_direct",
    "create_video_window",
    "forget_device",
    "get_adapter_selection",
    "get_adoption_state",
    "get_capture_state",
    "get_config",
    "get_device_list",
    "get_dhcp_state",
    "get_host_ip_owners",
    "get_license_document",
    "get_network_mode",
    "get_startup_notices",
    // Renamed with the bind-inventory contract in A3.
    "list_vpn_interfaces",
    "log_frontend",
    "open_device_browser",
    "open_log_folder",
    "ptu_send",
    "refresh_adapter",
    "remove_adopted_subnet",
    "remove_manual_node",
    "remove_secondary_ip",
    "retry_playback",
    "scan_network",
    "select_adapter",
    "set_audio_muted",
    "set_device_alias",
    "set_network_mode",
    "set_video_visible",
    "set_zoom_position",
    "start_arp_discovery",
    "start_recording",
    "start_restream_server",
    "start_stream",
    "stop_recording",
    "stop_restream_server",
    "stop_stream",
    "switch_restream_protocol",
    "take_screenshot",
    "update_credentials",
    "update_stream_settings",
    "update_video_position",
];

fn main() {
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
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
        // `rustc-link-lib` is intentionally applied only to this package's
        // library target by Cargo. Example targets inherit the delay-load
        // linker arguments below, so they need the helper library explicitly.
        // G2's pre-production admission harness is an example target.
        println!("cargo:rustc-link-arg-examples=delayimp.lib");

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

        // The release workflow opts into administrator elevation. Development
        // and tests need Common Controls v6 for the dialog plugin, but must
        // remain runnable without a UAC prompt.
        println!("cargo:rerun-if-env-changed=POCKETSTREAM_RELEASE");
        let is_release = std::env::var_os("POCKETSTREAM_RELEASE").is_some();
        if is_release {
            let manifest =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("pocketstream.exe.manifest");
            println!("cargo:rerun-if-changed={}", manifest.display());
            let mut res = tauri_build::WindowsAttributes::new();
            res = res
                .app_manifest(std::fs::read_to_string(&manifest).expect("failed to read manifest"));
            tauri_build::try_build(attributes.windows_attributes(res))
                .expect("failed to run tauri-build");
        } else {
            // tauri-winres/embed-resource only links its resource into binary
            // targets when a package has src/main.rs. Library unit tests miss
            // that manifest and fail at process startup (TaskDialogIndirect).
            // Let the MSVC linker embed the development manifest in every
            // executable target, and omit it from Tauri's icon/version resource
            // to avoid defining manifest resource #1 twice.
            let manifest =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("pocketstream.dev.manifest");
            println!("cargo:rerun-if-changed={}", manifest.display());
            println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
            println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
            let windows = tauri_build::WindowsAttributes::new_without_app_manifest();
            tauri_build::try_build(attributes.windows_attributes(windows))
                .expect("failed to run tauri-build");
        }
        return;
    }

    #[allow(unreachable_code)]
    tauri_build::try_build(attributes).expect("failed to run tauri-build")
}
