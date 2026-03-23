mod camera;
mod commands;
mod config;
mod error;
mod network;
mod streaming;

use tauri::Manager;

pub use error::AppError;

pub fn run() {
    env_logger::init();

    // Pre-load Npcap DLLs before any pcap operations.
    // Required when Npcap is NOT in WinPcap-compatible mode.
    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        // First set the DLL search directory so dependencies resolve
        let npcap_dir = r"C:\Windows\System32\Npcap";
        let dir_wide: Vec<u16> = OsStr::new(npcap_dir)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            windows_sys::Win32::System::LibraryLoader::SetDllDirectoryW(dir_wide.as_ptr());
        }

        // Load Packet.dll first (dependency of wpcap.dll)
        for dll in &["Packet.dll", "wpcap.dll"] {
            let path = format!(r"C:\Windows\System32\Npcap\{}", dll);
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
            }
        }
    }

    // Initialize GStreamer once at startup
    gstreamer::init().expect("Failed to initialize GStreamer");
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
            commands::set_static_ip,
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
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            // Auto-start ARP discovery on the first Ethernet interface
            tauri::async_runtime::spawn(async move {
                match network::interface::list_all() {
                    Ok(interfaces) => {
                        let eth = interfaces
                            .iter()
                            .find(|i| i.is_up && i.is_ethernet && !i.ips.is_empty());

                        if let Some(iface) = eth {
                            let name = iface.name.clone();
                            log::info!("Auto-starting ARP discovery on '{}'", name);

                            let manager: tauri::State<'_, network::NetworkManager> =
                                handle.state();
                            if let Err(e) = manager.start_arp_discovery(&name, handle.clone()).await
                            {
                                log::warn!("Failed to auto-start ARP discovery: {}", e);
                            }
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
