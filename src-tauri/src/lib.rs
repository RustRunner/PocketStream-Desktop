mod camera;
mod commands;
mod config;
mod error;
mod network;
mod streaming;

use tauri::Manager;

pub use error::AppError;

/// Try to configure GStreamer from DLLs bundled alongside the executable.
/// Returns true if a bundled GStreamer was found and configured.
#[cfg(windows)]
fn setup_bundled_gstreamer() -> bool {
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let exe_dir = match exe_path.parent() {
        Some(d) => d,
        None => return false,
    };

    // Bundled layout (created by scripts/bundle-gstreamer.ps1):
    //   <install_dir>/resources/gstreamer/bin/          ← core DLLs
    //   <install_dir>/resources/gstreamer/lib/gstreamer-1.0/ ← plugins
    let gst_bin = exe_dir.join("resources").join("gstreamer").join("bin");
    let gst_plugins = exe_dir
        .join("resources")
        .join("gstreamer")
        .join("lib")
        .join("gstreamer-1.0");

    if !gst_bin.exists() || !gst_plugins.exists() {
        return false;
    }

    log::info!("Found bundled GStreamer at {}", gst_bin.display());

    // Prepend the bundled bin directory to PATH so the OS loader finds
    // GStreamer core DLLs (gstreamer-1.0-0.dll, glib-2.0-0.dll, etc.)
    let current_path = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{};{}", gst_bin.display(), current_path));

    // Tell GStreamer where to find plugins
    std::env::set_var("GST_PLUGIN_PATH", gst_plugins.to_str().unwrap_or_default());

    // Prevent GStreamer from scanning the system plugin path — use ONLY
    // our bundled plugins for a predictable, self-contained install.
    std::env::set_var("GST_PLUGIN_SYSTEM_PATH", "");

    // Store the plugin registry cache in AppData so it's writable even
    // when the install dir (Program Files) is read-only.
    if let Some(data_dir) = dirs::data_local_dir() {
        let registry = data_dir
            .join("PocketStream")
            .join("gstreamer-registry.bin");
        if let Some(parent) = registry.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::env::set_var("GST_REGISTRY", registry.to_str().unwrap_or_default());
    }

    true
}

/// Pre-load Npcap DLLs. Returns true if Npcap was loaded successfully.
#[cfg(windows)]
fn setup_npcap() -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let npcap_dir = r"C:\Windows\System32\Npcap";
    if !std::path::Path::new(npcap_dir).exists() {
        log::warn!(
            "Npcap not found at {}. ARP discovery will be unavailable.",
            npcap_dir
        );
        return false;
    }

    // Set the DLL search directory so dependencies resolve
    let dir_wide: Vec<u16> = OsStr::new(npcap_dir)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        windows_sys::Win32::System::LibraryLoader::SetDllDirectoryW(dir_wide.as_ptr());
    }

    let mut all_loaded = true;
    // Load Packet.dll first (dependency of wpcap.dll)
    for dll in &["Packet.dll", "wpcap.dll"] {
        let path = format!(r"{}\{}", npcap_dir, dll);
        let wide: Vec<u16> = OsStr::new(&path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            windows_sys::Win32::System::LibraryLoader::LoadLibraryW(wide.as_ptr())
        };
        if !handle.is_null() {
            log::info!("Loaded Npcap {}", dll);
        } else {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            log::warn!("Failed to load Npcap {} (error {})", dll, err);
            all_loaded = false;
        }
    }

    // Reset DLL directory so it doesn't interfere with other DLL loading
    unsafe {
        windows_sys::Win32::System::LibraryLoader::SetDllDirectoryW(std::ptr::null());
    }

    all_loaded
}

/// Background task that polls the active Ethernet interface every 3 seconds
/// via pnet (zero network traffic) and emits an event when status changes.
async fn watch_interface(mac: String, display_name: String, handle: tauri::AppHandle) {
    use tauri::Emitter;

    let mut prev_up = true;
    let mut prev_ips: Vec<String> = Vec::new();

    // Capture initial state
    if let Some((is_up, ips)) = network::interface::quick_status_by_mac(&mac) {
        prev_up = is_up;
        prev_ips = ips.iter().map(|ip| ip.address.clone()).collect();
    }

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        let (is_up, ips) = match network::interface::quick_status_by_mac(&mac) {
            Some(s) => s,
            None => (false, vec![]),
        };

        let current_ips: Vec<String> = ips.iter().map(|ip| ip.address.clone()).collect();
        if is_up == prev_up && current_ips == prev_ips {
            continue;
        }

        log::info!(
            "Interface '{}' changed: up={} ips={:?}",
            display_name,
            is_up,
            current_ips
        );

        let info = network::interface::InterfaceInfo {
            name: display_name.clone(),
            display_name: display_name.clone(),
            ips,
            mac: mac.clone(),
            is_up,
            is_ethernet: true,
            is_wifi: false,
            is_vpn: false,
        };

        let _ = handle.emit("interface-status-changed", &info);
        prev_up = is_up;
        prev_ips = current_ips;
    }
}

pub fn run() {
    env_logger::init();

    // ── Prerequisites ────────────────────────────────────────────────
    #[cfg(windows)]
    {
        let npcap_ok = setup_npcap();
        if !npcap_ok {
            log::warn!("Npcap is not installed — network discovery features will be limited");
        }

        let bundled = setup_bundled_gstreamer();
        if bundled {
            log::info!("Using bundled GStreamer runtime");
        } else {
            log::info!("No bundled GStreamer found, using system installation");
        }
    }

    // Initialize GStreamer once at startup
    gstreamer::init().expect(
        "Failed to initialize GStreamer. \
         Ensure GStreamer MSVC x86_64 runtime is installed \
         (https://gstreamer.freedesktop.org/download/)"
    );
    log::info!("GStreamer {} initialized", gstreamer::version_string());

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .manage(config::AppConfig::load_or_default())
        .manage(streaming::StreamManager::new())
        .manage(network::NetworkManager::new())
        .invoke_handler(tauri::generate_handler![
            // Config
            commands::get_config,
            commands::save_config,
            // Network
            commands::scan_network,
            commands::list_interfaces,
            commands::list_vpn_interfaces,
            commands::set_static_ip,
            commands::add_secondary_ip,
            commands::remove_secondary_ip,
            commands::get_interface_info,
            // ARP Discovery
            commands::start_arp_discovery,
            commands::stop_arp_discovery,
            commands::get_arp_devices,
            commands::get_adopted_subnets,
            commands::remove_adopted_subnet,
            // Streaming
            commands::start_stream,
            commands::stop_stream,
            commands::start_rtsp_server,
            commands::stop_rtsp_server,
            commands::get_stream_status,
            commands::take_screenshot,
            commands::start_recording,
            commands::stop_recording,
            // Video Embed
            commands::create_video_window,
            commands::update_video_position,
            commands::set_video_visible,
            // FLIR PTU
            commands::ptu_send,
            // Camera / PTZ
            commands::discover_onvif,
            commands::ptz_move,
            commands::ptz_stop,
            commands::ptz_goto_preset,
            commands::ptz_set_preset,
            commands::sony_cgi_zoom,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            // Load adopted subnets from config, then auto-start ARP discovery
            tauri::async_runtime::spawn(async move {
                let config: tauri::State<'_, config::AppConfig> = handle.state();
                let manager: tauri::State<'_, network::NetworkManager> = handle.state();
                manager.load_adopted_from_config(&config).await;

                match network::interface::list_physical() {
                    Ok(interfaces) => {
                        let eth = interfaces
                            .iter()
                            .find(|i| i.is_up && i.is_ethernet && !i.ips.is_empty());

                        if let Some(iface) = eth {
                            let name = iface.name.clone();
                            log::info!("Auto-starting ARP discovery on '{}'", name);

                            if let Err(e) = manager.start_arp_discovery(&name, handle.clone()).await
                            {
                                log::warn!("Failed to auto-start ARP discovery: {}", e);
                            }

                            // Start lightweight interface watcher (pnet-based,
                            // no network traffic — just reads OS adapter state).
                            let mac = iface.mac.clone();
                            let display = iface.display_name.clone();
                            let wh = handle.clone();
                            tokio::spawn(async move {
                                watch_interface(mac, display, wh).await;
                            });
                        } else {
                            log::info!("No active Ethernet interface found for ARP discovery");
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to enumerate interfaces for ARP: {}", e);
                    }
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running PocketStream Desktop");
}
