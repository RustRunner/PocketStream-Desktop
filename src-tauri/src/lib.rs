mod camera;
mod commands;
mod config;
mod error;
mod network;
mod streaming;
mod validation;

use std::path::PathBuf;
use std::sync::OnceLock;
use tauri::Manager;

pub use error::AppError;

/// Lazily-initialized GStreamer result.  The background thread kicks off
/// `gstreamer::init()` early, but if a streaming command arrives before
/// it finishes, `ensure_gstreamer()` will block until init completes
/// (bounded by `GST_INIT_TIMEOUT`).
static GST_READY: OnceLock<Result<(), String>> = OnceLock::new();

/// Hard upper bound on how long `gstreamer::init()` may run before we
/// give up. Init is a synchronous C call into GStreamer; a corrupt
/// plugin registry has been observed to make it spin indefinitely. 30s
/// is generous for cold-start on a slow disk while still fast enough
/// that the app fails loudly instead of appearing hung to the user.
const GST_INIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Log directory path, set once during startup.
static LOG_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn ensure_gstreamer() -> Result<(), AppError> {
    let result = GST_READY.get_or_init(|| {
        // Run gstreamer::init() on a dedicated OS thread so a hang in
        // GStreamer C code can't wedge the calling thread. recv_timeout
        // enforces a hard upper bound; if it expires the init thread is
        // leaked (still running, but unreachable). That's deliberate —
        // the alternative would be unsafe abort and we'd rather lose a
        // thread than risk UB.
        let (tx, rx) = std::sync::mpsc::channel();
        let spawn_result = std::thread::Builder::new()
            .name("gstreamer-init".into())
            .spawn(move || {
                let result = match gstreamer::init() {
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
                };
                let _ = tx.send(result);
            });

        if let Err(e) = spawn_result {
            let msg = format!("Failed to spawn GStreamer init thread: {}", e);
            log::error!("{}", msg);
            return Err(msg);
        }

        match rx.recv_timeout(GST_INIT_TIMEOUT) {
            Ok(result) => result,
            Err(_) => {
                let msg = format!(
                    "GStreamer initialization timed out after {}s. The plugin \
                     registry may be corrupt — try deleting the registry cache \
                     (Windows: %LOCALAPPDATA%\\gstreamer-1.0\\registry.x86_64.bin) \
                     and relaunching.",
                    GST_INIT_TIMEOUT.as_secs()
                );
                log::error!("{}", msg);
                Err(msg)
            }
        }
    });
    result.clone().map_err(AppError::Stream)
}

/// Whether the OS-native capture backend (PacketMonitor) is usable,
/// established once at startup by the behavioral probe. There is no
/// install path — the API is in-box on supported Windows or absent on
/// builds below its floor.
static DISCOVERY_AVAILABLE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn is_discovery_available() -> bool {
    DISCOVERY_AVAILABLE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Windows build number for diagnostics (the field-debug breadcrumb for
/// the PacketMonitor floor question). Uses `RtlGetVersion` from ntdll —
/// unlike `GetVersionEx` it isn't shimmed down by the app manifest.
/// Returns 0 if it can't be read; this is a log value, never a gate.
#[cfg(windows)]
fn os_build_number() -> u32 {
    #[repr(C)]
    struct OsVersionInfoW {
        dw_os_version_info_size: u32,
        dw_major_version: u32,
        dw_minor_version: u32,
        dw_build_number: u32,
        dw_platform_id: u32,
        sz_csd_version: [u16; 128],
    }
    unsafe {
        let Ok(ntdll) = libloading::Library::new("ntdll.dll") else {
            return 0;
        };
        let rtl_get_version: libloading::Symbol<
            unsafe extern "system" fn(*mut OsVersionInfoW) -> i32,
        > = match ntdll.get(b"RtlGetVersion") {
            Ok(s) => s,
            Err(_) => return 0,
        };
        let mut info: OsVersionInfoW = std::mem::zeroed();
        info.dw_os_version_info_size = std::mem::size_of::<OsVersionInfoW>() as u32;
        if rtl_get_version(&mut info) == 0 {
            info.dw_build_number
        } else {
            0
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
            is_virtual: false,
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

    // Trim to the last MAX_LOG_LINES lines on startup. Replaces the
    // previous "delete entire file at 10 MB" rotation, which nuked
    // all history at the worst possible moment. Within a long-running
    // session the file can still grow past this cap; the trim only
    // runs at process start, so the user sees a bounded file when
    // they next open the log. Read failures are non-fatal — leaving
    // the file alone is preferable to losing data on a transient
    // I/O error.
    const MAX_LOG_LINES: usize = 1000;
    if let Ok(content) = std::fs::read_to_string(&log_file) {
        let lines: Vec<&str> = content.lines().collect();
        if lines.len() > MAX_LOG_LINES {
            let kept = lines[lines.len() - MAX_LOG_LINES..].join("\n");
            let _ = std::fs::write(&log_file, format!("{}\n", kept));
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

    // Global panic hook. Without this a panic at the PacketMonitor FFI
    // boundary or inside any spawned task tears the process down with no
    // located breadcrumb. Route the payload, source location, and a
    // captured backtrace through the same fern sink as normal logging so
    // the next field crash is attributable to capture / adoption / restore
    // / streaming rather than "it just disappeared".
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown location".to_string());
        let payload = panic_payload_str(info.payload());
        let backtrace = std::backtrace::Backtrace::force_capture();
        log::error!("PANIC at {}: {}\n{}", location, payload, backtrace);
    }));

    let _ = LOG_DIR.set(log_dir);
}

/// Best-effort human string from a panic payload. `panic!` / `assert!`
/// carry either a `&str` (string literals) or a `String` (formatted
/// messages); anything else is a payload type we can only acknowledge.
fn panic_payload_str(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

pub fn run() {
    setup_logging();

    // Version banner — first line of every session so a log file (which
    // survives across launches and silent auto-updates) can always be
    // attributed to a build. Doubles as the session-boundary marker.
    log::info!(
        "PocketStream Desktop v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    // ── Prerequisites ────────────────────────────────────────────────
    #[cfg(windows)]
    {
        // Behavioral probe of the in-box PacketMonitor capture backend.
        // No install path — it's present on supported Windows or the
        // build is below its floor. The build number is logged as a
        // field-debug breadcrumb for the floor question, never as the
        // gate (the probe result is the gate).
        let build = os_build_number();
        match network::pktmon::probe() {
            Ok(()) => {
                DISCOVERY_AVAILABLE.store(true, std::sync::atomic::Ordering::Relaxed);
                log::info!("Device discovery available (PacketMonitor); Windows build {build}");
            }
            Err(reason) => {
                DISCOVERY_AVAILABLE.store(false, std::sync::atomic::Ordering::Relaxed);
                log::warn!("Device discovery unavailable on Windows build {build}: {reason}");
            }
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
        .manage(camera::flir_ptu::PtuController::new())
        .invoke_handler(tauri::generate_handler![
            // Logging
            commands::log_frontend,
            commands::open_log_folder,
            // Config
            commands::get_config,
            commands::save_config,
            commands::get_startup_notices,
            commands::update_stream_settings,
            commands::update_rtsp_settings,
            commands::update_credentials,
            // Network
            commands::scan_network,
            commands::list_interfaces,
            commands::list_vpn_interfaces,
            commands::set_static_ip,
            commands::add_secondary_ip,
            commands::remove_secondary_ip,
            commands::set_dhcp,
            commands::get_dhcp_state,
            commands::resolve_mac,
            commands::get_network_mode,
            commands::set_network_mode,
            commands::get_manual_nodes,
            commands::add_manual_node,
            commands::remove_manual_node,
            commands::clear_manual_nodes,
            commands::refresh_adapter,
            commands::get_interface_info,
            // ARP Discovery
            commands::start_arp_discovery,
            commands::stop_arp_discovery,
            commands::get_device_list,
            commands::report_scan_result,
            commands::set_device_alias,
            commands::set_device_status,
            commands::forget_device,
            commands::evict_phantom_device,
            commands::get_adopted_subnets,
            commands::remove_adopted_subnet,
            // Streaming
            commands::start_stream,
            commands::stop_stream,
            commands::start_rtsp_server,
            commands::stop_rtsp_server,
            commands::take_screenshot,
            commands::start_recording,
            commands::stop_recording,
            // Video Embed
            commands::create_video_window,
            commands::update_video_position,
            commands::set_video_visible,
            // FLIR PTU
            commands::ptu_send,
            commands::open_device_browser,
            // Camera / PTZ
            commands::discover_onvif,
            commands::ptz_move,
            commands::ptz_stop,
            commands::ptz_goto_preset,
            commands::ptz_set_preset,
            commands::sony_cgi_zoom,
            commands::control_cgi_zoom_direct,
            commands::control_cgi_probe_status,
            commands::set_zoom_position,
        ])
        .setup(|app| {
            let handle = app.handle().clone();

            // Spawn the stream-status emitter: a 1Hz internal ticker that
            // refreshes the watch channel snapshot, plus a broadcaster that
            // emits `stream-status` to the frontend on every change.
            // Replaces the old 1Hz frontend poll of get_stream_status.
            let stream_mgr: tauri::State<'_, streaming::StreamManager> = handle.state();
            stream_mgr.start_status_emitter(handle.clone());

            // Start event-driven NIC watcher (Windows NotifyIpInterfaceChange +
            // NotifyUnicastIpAddressChange). If it fails to register — or on
            // non-Windows platforms — fall back to the legacy per-MAC pnet
            // poller below. Successful registration makes the polling watcher
            // redundant and we skip spawning it to avoid duplicate events.
            let event_watcher_ok = network::watcher::start(handle.clone());

            // Load adopted subnets from config, then start discovery
            // subsystems gated on the user's chosen network mode.
            tauri::async_runtime::spawn(async move {
                let config: tauri::State<'_, config::AppConfig> = handle.state();
                let manager: tauri::State<'_, network::NetworkManager> = handle.state();

                // Init the emitter before any registry mutation so
                // hydration pokes land on a real emitter — required
                // for Static-Manual which never reaches start_arp_discovery
                // (the historic emitter init site).
                manager.init_emitter(handle.clone()).await;

                let mode = config.get_network_mode();
                log::info!("Network mode: {:?}", mode);

                // Static-Manual replaces the cache + ARP world entirely:
                // the Nodes panel reflects only the user's pinned list.
                // Hydrating the cache here would surface ghost entries
                // from the last Auto session.
                if mode == config::NetworkMode::StaticManual {
                    manager.hydrate_manual_nodes(&config).await;
                } else {
                    manager.hydrate_device_registry(&config).await;
                }
                manager.load_adopted_from_config(&config, &handle).await;

                match network::interface::list_physical().await {
                    Ok(interfaces) => {
                        let eth = interfaces.iter().find(|i| {
                            network::interface::is_wired_ethernet(i) && !i.ips.is_empty()
                        });

                        if let Some(iface) = eth {
                            // ARP discovery (and the auto-adopt loop it
                            // spawns internally) only runs in non-Manual
                            // modes. Static-Manual is intentionally quiet:
                            // no ARP, no auto-adopt, no port scanner.
                            if mode != config::NetworkMode::StaticManual {
                                if is_discovery_available() {
                                    let name = iface.name.clone();
                                    log::info!("Auto-starting ARP discovery on '{}'", name);

                                    if let Err(e) =
                                        manager.start_arp_discovery(&name, handle.clone()).await
                                    {
                                        log::warn!("Failed to auto-start ARP discovery: {}", e);
                                    }
                                } else {
                                    log::info!(
                                        "Skipping ARP discovery (packet capture unavailable)"
                                    );
                                }
                            } else {
                                log::info!(
                                    "Static-Manual mode — skipping ARP discovery / auto-adopt"
                                );
                            }

                            // Start lightweight interface watcher (pnet-based,
                            // no network traffic — just reads OS adapter state).
                            // Skipped when the event-driven watcher is active,
                            // since both would emit `interface-status-changed`
                            // and cause duplicate UI updates.
                            if !event_watcher_ok {
                                let mac = iface.mac.clone();
                                let display = iface.display_name.clone();
                                let wh = handle.clone();
                                tokio::spawn(async move {
                                    watch_interface(mac, display, wh).await;
                                });
                            }
                        } else {
                            log::info!("No active Ethernet interface found for ARP discovery");
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to enumerate interfaces for ARP: {}", e);
                    }
                }

                // ICMP pinger drives the green/red reachability dot in
                // every mode. Starts after registry hydration so the
                // first sweep has something to ping.
                manager.start_ping_dot(handle.clone()).await;
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
                    manager.stop_ping_dot().await;
                    tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        manager.cleanup_adopted_ips(),
                    )
                    .await
                });
            }
        });
}

#[cfg(test)]
mod panic_hook_tests {
    use super::panic_payload_str;

    #[test]
    fn extracts_str_literal_payload() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("boom");
        assert_eq!(panic_payload_str(&*payload), "boom");
    }

    #[test]
    fn extracts_string_payload() {
        let payload: Box<dyn std::any::Any + Send> = Box::new(String::from("boom 42"));
        assert_eq!(panic_payload_str(&*payload), "boom 42");
    }

    #[test]
    fn falls_back_for_non_string_payload() {
        let payload: Box<dyn std::any::Any + Send> = Box::new(42i32);
        assert_eq!(panic_payload_str(&*payload), "<non-string panic payload>");
    }
}
