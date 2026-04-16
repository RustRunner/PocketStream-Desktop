mod camera;
mod commands;
mod config;
mod error;
mod network;
mod streaming;

use std::path::PathBuf;
use std::sync::OnceLock;
use tauri::Manager;

pub use error::AppError;

/// Lazily-initialized GStreamer result.  The background thread kicks off
/// `gstreamer::init()` early, but if a streaming command arrives before
/// it finishes, `ensure_gstreamer()` will block until init completes.
static GST_READY: OnceLock<Result<(), String>> = OnceLock::new();

/// Log directory path, set once during startup.
static LOG_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn ensure_gstreamer() -> Result<(), AppError> {
    let result = GST_READY.get_or_init(|| match gstreamer::init() {
        Ok(()) => {
            log::info!("GStreamer {} initialized", gstreamer::version_string());
            Ok(())
        }
        Err(e) => {
            let msg = format!(
                "Failed to initialize GStreamer: {}. \
                     Ensure GStreamer MSVC x86_64 runtime is installed \
                     (https://gstreamer.freedesktop.org/download/)",
                e
            );
            log::error!("{}", msg);
            Err(msg)
        }
    });
    result.clone().map_err(AppError::Stream)
}

/// Whether Npcap was successfully loaded at startup.
/// Checked before any pcap operations to avoid delay-load crashes.
static NPCAP_AVAILABLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn is_npcap_available() -> bool {
    NPCAP_AVAILABLE.load(std::sync::atomic::Ordering::Relaxed)
}

/// If Npcap is missing and a bundled installer exists, offer to install it.
/// Uses a Win32 MessageBox (no Tauri window needed — runs before app starts).
/// Returns true if Npcap was installed successfully.
#[cfg(windows)]
fn offer_npcap_install() -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let exe_dir = match std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    {
        Some(d) => d,
        None => return false,
    };

    let installer = exe_dir
        .join("resources")
        .join("prerequisites")
        .join("npcap-setup.exe");

    if !installer.exists() {
        log::info!("No bundled Npcap installer at {}", installer.display());
        return false;
    }

    let title: Vec<u16> = OsStr::new("PocketStream Desktop")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let msg: Vec<u16> = OsStr::new(
        "Npcap is required for network device discovery.\n\n\
         Would you like to install it now?\n\n\
         (During install, check \"Install Npcap in WinPcap API-compatible Mode\")",
    )
    .encode_wide()
    .chain(std::iter::once(0))
    .collect();

    // MB_YESNO (4) | MB_ICONQUESTION (0x20)
    let result = unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
            std::ptr::null_mut(),
            msg.as_ptr(),
            title.as_ptr(),
            0x00000004 | 0x00000020,
        )
    };

    if result != 6 {
        // User chose No
        return false;
    }

    log::info!("Launching bundled Npcap installer: {}", installer.display());
    match std::process::Command::new(&installer).status() {
        Ok(status) => {
            log::info!("Npcap installer exited with: {}", status);
            // Retry loading Npcap DLLs
            setup_npcap()
        }
        Err(e) => {
            log::warn!("Failed to launch Npcap installer: {}", e);
            false
        }
    }
}

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

    // Set the DLL search directory so transitive dependencies of plugins
    // (e.g. gstlibav.dll → avcodec-61.dll) are found by LoadLibrary.
    // This is more reliable than PATH for implicit DLL dependencies.
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        let dir_wide: Vec<u16> = OsStr::new(&gst_bin)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            windows_sys::Win32::System::LibraryLoader::SetDllDirectoryW(dir_wide.as_ptr());
        }
    }

    // Also prepend to PATH as a belt-and-suspenders approach
    let current_path = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{};{}", gst_bin.display(), current_path));

    // Tell GStreamer where to find plugins
    std::env::set_var("GST_PLUGIN_PATH", gst_plugins.to_str().unwrap_or_default());

    // Prevent GStreamer from scanning the system plugin path — use ONLY
    // our bundled plugins for a predictable, self-contained install.
    std::env::set_var("GST_PLUGIN_SYSTEM_PATH", "");

    // Store the plugin registry cache in AppData so it's writable even
    // when the install dir (Program Files) is read-only.
    //
    // Only invalidate the cache when the application binary is newer than
    // the registry (i.e. after an update).  Keeping the cache across normal
    // launches cuts GStreamer init from 5-15 s down to < 1 s, which is
    // critical for ARP discovery timing.
    if let Some(data_dir) = dirs::data_local_dir() {
        let registry = data_dir.join("PocketStream").join("gstreamer-registry.bin");
        if let Some(parent) = registry.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let should_invalidate = match (
            std::fs::metadata(&exe_path).and_then(|m| m.modified()),
            std::fs::metadata(&registry).and_then(|m| m.modified()),
        ) {
            (Ok(exe_time), Ok(reg_time)) => exe_time > reg_time,
            _ => true, // registry missing or metadata unreadable — rebuild
        };

        if should_invalidate {
            log::info!("Invalidating GStreamer registry cache (app binary is newer)");
            let _ = std::fs::remove_file(&registry);
        } else {
            log::info!("Using cached GStreamer registry");
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
        let handle =
            unsafe { windows_sys::Win32::System::LibraryLoader::LoadLibraryW(wide.as_ptr()) };
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

        let (raw_up, ips) = network::interface::quick_status_by_mac(&mac).unwrap_or_default();

        // On Windows, pnet's is_up() can report false for adapters that
        // are clearly operational (ARP/IP traffic is flowing). Treat the
        // interface as up if it has at least one IPv4 address assigned.
        let is_up = raw_up || !ips.is_empty();

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

/// Return the log directory (set at startup).
pub fn log_dir() -> Option<&'static PathBuf> {
    LOG_DIR.get()
}

/// Initialise logging: stderr (visible in dev) + rotating log file.
fn setup_logging() {
    let log_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("PocketStream")
        .join("logs");
    let _ = std::fs::create_dir_all(&log_dir);

    let log_file = log_dir.join("pocketstream.log");

    // Basic rotation: truncate if the file exceeds 10 MB.
    if let Ok(meta) = std::fs::metadata(&log_file) {
        if meta.len() > 10 * 1024 * 1024 {
            let _ = std::fs::remove_file(&log_file);
        }
    }

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file);

    let mut dispatch = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}] {} - {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.target(),
                message,
            ))
        })
        .level(log::LevelFilter::Info)
        .level_for("pocketstream_desktop", log::LevelFilter::Debug)
        .chain(std::io::stderr());

    if let Ok(f) = file {
        dispatch = dispatch.chain(f);
    }

    let _ = dispatch.apply();
    let _ = LOG_DIR.set(log_dir);
}

pub fn run() {
    setup_logging();

    // ── Prerequisites ────────────────────────────────────────────────
    #[cfg(windows)]
    {
        let mut npcap_ok = setup_npcap();
        if !npcap_ok {
            // Offer to install from bundled installer (shows a system dialog)
            npcap_ok = offer_npcap_install();
        }
        NPCAP_AVAILABLE.store(npcap_ok, std::sync::atomic::Ordering::Relaxed);
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

    // Start GStreamer init in background — it can take seconds when the
    // bundled plugin registry is cold.  ARP discovery (below) doesn't need
    // GStreamer, so letting them run in parallel eliminates the startup
    // blind window where ARP traffic goes uncaptured.
    std::thread::spawn(|| {
        if let Err(e) = ensure_gstreamer() {
            log::error!("Background GStreamer init failed: {}", e);
        }
    });

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(config::AppConfig::load_or_default())
        .manage(streaming::StreamManager::new())
        .manage(network::NetworkManager::new())
        .invoke_handler(tauri::generate_handler![
            // Logging
            commands::log_frontend,
            commands::open_log_folder,
            // Config
            commands::get_config,
            commands::save_config,
            // Device Cache
            commands::get_device_cache,
            commands::upsert_cached_device,
            commands::remove_cached_device,
            commands::clear_device_cache,
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
                            if is_npcap_available() {
                                let name = iface.name.clone();
                                log::info!("Auto-starting ARP discovery on '{}'", name);

                                if let Err(e) =
                                    manager.start_arp_discovery(&name, handle.clone()).await
                                {
                                    log::warn!("Failed to auto-start ARP discovery: {}", e);
                                }
                            } else {
                                log::info!("Skipping ARP discovery (Npcap not installed)");
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
        .build(tauri::generate_context!())
        .unwrap_or_else(|e| {
            log::error!("Fatal: failed to start PocketStream Desktop: {}", e);
            eprintln!("Fatal: failed to start PocketStream Desktop: {}", e);
            std::process::exit(1);
        })
        .run(|app_handle, event| {
            // Graceful-shutdown cleanup: remove every secondary IP that
            // auto-adopt added during this session, so they don't survive
            // across restarts and accumulate on the user's adapter when
            // moving between sites. After a hard crash this won't run;
            // the leftover IPs are recovered into in-memory state by
            // `load_adopted_from_config` on the next startup and cleaned
            // up by the next graceful exit (self-healing on one cycle).
            //
            // Bounded at 5 s total so a stalled netsh can't hang the
            // process. block_on is safe here — the event loop is already
            // exiting and there's no UI to keep responsive.
            if let tauri::RunEvent::ExitRequested { .. } = event {
                let manager: tauri::State<'_, network::NetworkManager> = app_handle.state();
                let _ = tauri::async_runtime::block_on(async {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        manager.cleanup_adopted_ips(),
                    )
                    .await
                });
            }
        });
}
