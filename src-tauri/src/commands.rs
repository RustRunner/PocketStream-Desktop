use tauri::{Manager, State};

use crate::config::{AppConfig, AppSettings, CachedDevice};
use crate::error::AppError;
use crate::network::{ArpDevice, InterfaceInfo, NetworkManager, ScanResult};
use crate::streaming::{RtspServerInfo, StreamManager, StreamStatus};

// ── Logging Commands ─────────────────────────────────────────────────

#[tauri::command]
pub fn log_frontend(level: String, message: String) {
    match level.as_str() {
        "error" => log::error!("[frontend] {}", message),
        "warn" => log::warn!("[frontend] {}", message),
        "debug" => log::debug!("[frontend] {}", message),
        _ => log::info!("[frontend] {}", message),
    }
}

#[tauri::command]
pub fn open_log_folder() -> Result<(), AppError> {
    let dir = crate::log_dir()
        .ok_or_else(|| AppError::Config("Log directory not initialised".into()))?;

    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("explorer")
            .arg(dir.as_os_str())
            .spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open")
            .arg(dir.as_os_str())
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg(dir.as_os_str())
            .spawn();
    }

    Ok(())
}

// ── Config Commands ──────────────────────────────────────────────────

#[tauri::command]
pub async fn get_config(config: State<'_, AppConfig>) -> Result<AppSettings, AppError> {
    Ok(config.get())
}

#[tauri::command]
pub async fn save_config(
    config: State<'_, AppConfig>,
    settings: AppSettings,
) -> Result<(), AppError> {
    config.update(settings)
}

// ── Device Cache Commands ────────────────────────────────────────────

#[tauri::command]
pub async fn get_device_cache(
    config: State<'_, AppConfig>,
) -> Result<Vec<CachedDevice>, AppError> {
    Ok(config.get().device_cache)
}

#[tauri::command]
pub async fn upsert_cached_device(
    config: State<'_, AppConfig>,
    device: CachedDevice,
) -> Result<(), AppError> {
    config.upsert_cached_device(device)
}

#[tauri::command]
pub async fn remove_cached_device(
    config: State<'_, AppConfig>,
    mac: String,
) -> Result<(), AppError> {
    config.remove_cached_device(&mac)
}

#[tauri::command]
pub async fn clear_device_cache(
    config: State<'_, AppConfig>,
) -> Result<(), AppError> {
    config.clear_device_cache()
}

// ── Network Commands ─────────────────────────────────────────────────

#[tauri::command]
pub async fn scan_network(
    manager: State<'_, NetworkManager>,
    subnet: String,
) -> Result<Vec<ScanResult>, AppError> {
    manager.scan_subnet(&subnet).await
}

#[tauri::command]
pub async fn list_interfaces(
    manager: State<'_, NetworkManager>,
) -> Result<Vec<InterfaceInfo>, AppError> {
    manager.list_interfaces()
}

#[tauri::command]
pub async fn list_vpn_interfaces() -> Result<Vec<InterfaceInfo>, AppError> {
    crate::network::interface::list_vpn()
}

#[tauri::command]
pub async fn get_interface_info(
    manager: State<'_, NetworkManager>,
    name: String,
) -> Result<InterfaceInfo, AppError> {
    manager.get_interface(&name)
}

#[tauri::command]
pub async fn set_static_ip(
    name: String,
    ip: String,
    subnet_mask: String,
    gateway: Option<String>,
) -> Result<(), AppError> {
    crate::network::ip_config::assign_static_ip(&name, &ip, &subnet_mask, gateway.as_deref())
        .await
}

#[tauri::command]
pub async fn add_secondary_ip(
    name: String,
    ip: String,
    subnet_mask: String,
) -> Result<(), AppError> {
    crate::network::ip_config::add_secondary_ip(&name, &ip, &subnet_mask).await
}

#[tauri::command]
pub async fn remove_secondary_ip(
    name: String,
    ip: String,
) -> Result<(), AppError> {
    crate::network::ip_config::remove_secondary_ip(&name, &ip).await
}

// ── ARP Discovery Commands ───────────────────────────────────────────

#[tauri::command]
pub async fn start_arp_discovery(
    manager: State<'_, NetworkManager>,
    app: tauri::AppHandle,
    interface: String,
) -> Result<(), AppError> {
    if !crate::is_npcap_available() {
        return Err(AppError::Network(
            "Npcap is not installed -- ARP discovery requires Npcap \
             (https://npcap.com/#download)"
                .into(),
        ));
    }
    manager.start_arp_discovery(&interface, app).await
}

#[tauri::command]
pub async fn stop_arp_discovery(
    manager: State<'_, NetworkManager>,
) -> Result<(), AppError> {
    manager.stop_arp_discovery().await;
    Ok(())
}

#[tauri::command]
pub async fn get_arp_devices(
    manager: State<'_, NetworkManager>,
) -> Result<Vec<ArpDevice>, AppError> {
    Ok(manager.get_arp_devices().await)
}

#[tauri::command]
pub async fn get_adopted_subnets(
    manager: State<'_, NetworkManager>,
) -> Result<std::collections::HashMap<String, String>, AppError> {
    Ok(manager.get_adopted_ips().await)
}

#[tauri::command]
pub async fn remove_adopted_subnet(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    subnet: String,
) -> Result<(), AppError> {
    manager.remove_adopted_subnet(&subnet).await?;
    manager.save_adopted_to_config(&config).await;
    Ok(())
}

// ── Streaming Commands ───────────────────────────────────────────────

#[tauri::command]
pub async fn start_stream(
    stream: State<'_, StreamManager>,
    config: State<'_, AppConfig>,
    window_handle: Option<usize>,
) -> Result<(), AppError> {
    let settings = config.get();
    stream.start_playback(&settings, window_handle).await
}

#[tauri::command]
pub async fn stop_stream(
    window: tauri::WebviewWindow,
    stream: State<'_, StreamManager>,
) -> Result<(), AppError> {
    // Capture HWND before stopping (stop clears it)
    let hwnd = stream.get_video_child_hwnd();

    stream.stop_playback().await?;

    // Destroy the video child window on the main thread (must match creation thread)
    if let Some(h) = hwnd {
        let app = window.app_handle().clone();
        let _ = app.run_on_main_thread(move || {
            crate::streaming::video_embed::destroy_video_child(h);
        });
    }

    Ok(())
}

#[tauri::command]
pub async fn start_rtsp_server(
    stream: State<'_, StreamManager>,
    config: State<'_, AppConfig>,
) -> Result<RtspServerInfo, AppError> {
    let settings = config.get();
    stream.start_rtsp_server(&settings).await
}

#[tauri::command]
pub async fn stop_rtsp_server(stream: State<'_, StreamManager>) -> Result<(), AppError> {
    stream.stop_rtsp_server().await
}

#[tauri::command]
pub async fn get_stream_status(
    stream: State<'_, StreamManager>,
) -> Result<StreamStatus, AppError> {
    stream.get_status().await
}

#[tauri::command]
pub async fn take_screenshot(stream: State<'_, StreamManager>) -> Result<String, AppError> {
    stream.take_screenshot().await
}

#[tauri::command]
pub async fn start_recording(stream: State<'_, StreamManager>) -> Result<(), AppError> {
    stream.start_recording().await
}

#[tauri::command]
pub async fn stop_recording(stream: State<'_, StreamManager>) -> Result<String, AppError> {
    stream.stop_recording().await
}

// ── Video Embed Commands ─────────────────────────────────────────────

/// Create a child window for GStreamer to render into.
/// Returns the child HWND as a number so the frontend can pass it to start_stream.
/// The child window is created on the main UI thread so it gets proper message processing.
#[tauri::command]
pub async fn create_video_window(
    window: tauri::WebviewWindow,
    stream: State<'_, StreamManager>,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> Result<String, AppError> {
    let _ = &window;

    #[cfg(windows)]
    {
        use tauri::Manager;

        let hwnd = window
            .hwnd()
            .map_err(|e| AppError::Stream(format!("Failed to get window handle: {}", e)))?;
        let parent = hwnd.0 as isize;

        // Create the child window on the main thread so it gets messages processed
        let (tx, rx) = tokio::sync::oneshot::channel();
        let app = window.app_handle().clone();
        app.run_on_main_thread(move || {
            let result =
                crate::streaming::video_embed::create_video_child(parent, x, y, width, height);
            let _ = tx.send(result);
        })
        .map_err(|e| AppError::Stream(format!("Failed to run on main thread: {}", e)))?;

        let child = rx
            .await
            .map_err(|_| AppError::Stream("Main thread channel closed".into()))??;

        stream.set_video_child_hwnd(child);
        return Ok(child.to_string());
    }

    #[cfg(not(windows))]
    {
        let _ = (stream, x, y, width, height);
        return Err(AppError::Stream("Video embedding only supported on Windows".into()));
    }
}

#[tauri::command]
pub async fn update_video_position(
    stream: State<'_, StreamManager>,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> Result<(), AppError> {
    if let Some(hwnd) = stream.get_video_child_hwnd() {
        crate::streaming::video_embed::reposition(hwnd, x, y, width, height)?;
    }
    Ok(())
}

#[tauri::command]
pub async fn set_video_visible(
    stream: State<'_, StreamManager>,
    visible: bool,
) -> Result<(), AppError> {
    if let Some(hwnd) = stream.get_video_child_hwnd() {
        crate::streaming::video_embed::set_visible(hwnd, visible)?;
    }
    Ok(())
}

// ── FLIR PTU Commands ────────────────────────────────────────────────

#[tauri::command]
pub async fn ptu_send(ip: String, cmd: String) -> Result<std::collections::HashMap<String, String>, AppError> {
    let addr: std::net::Ipv4Addr = ip
        .parse()
        .map_err(|_| AppError::Network(format!("Invalid IP address: {}", ip)))?;
    if addr.is_loopback() || addr.is_link_local() || addr.is_broadcast() || addr.is_unspecified() {
        return Err(AppError::Network(format!("IP address not allowed: {}", ip)));
    }
    let base_url = format!("http://{}", addr);
    crate::camera::flir_ptu::send_command(&base_url, &cmd).await
}

// ── Camera / PTZ Commands ────────────────────────────────────────────

#[tauri::command]
pub async fn discover_onvif(
    subnet: Option<String>,
) -> Result<Vec<crate::camera::OnvifDevice>, AppError> {
    crate::camera::onvif::discover(subnet.as_deref()).await
}

#[tauri::command]
pub async fn ptz_move(
    camera_url: String,
    pan: f64,
    tilt: f64,
    zoom: f64,
) -> Result<(), AppError> {
    crate::camera::ptz::continuous_move(&camera_url, pan, tilt, zoom).await
}

#[tauri::command]
pub async fn ptz_stop(camera_url: String) -> Result<(), AppError> {
    crate::camera::ptz::stop(&camera_url).await
}

#[tauri::command]
pub async fn ptz_goto_preset(camera_url: String, preset: u32) -> Result<(), AppError> {
    crate::camera::ptz::goto_preset(&camera_url, preset).await
}

#[tauri::command]
pub async fn ptz_set_preset(
    camera_url: String,
    preset: u32,
    name: String,
) -> Result<(), AppError> {
    crate::camera::ptz::set_preset(&camera_url, preset, &name).await
}

#[tauri::command]
pub async fn sony_cgi_zoom(
    ip: String,
    zoom_speed: i32,
    username: String,
    password: String,
) -> Result<(), AppError> {
    // Validate `ip` as IPv4 and reject reserved ranges before building
    // the HTTP URL. Without this, a compromised webview could pivot to
    // arbitrary internal HTTP services via this IPC command (SSRF).
    // Mirrors the validation done by `ptu_send`.
    let addr: std::net::Ipv4Addr = ip
        .parse()
        .map_err(|_| AppError::Network(format!("Invalid IP address: {}", ip)))?;
    if addr.is_loopback() || addr.is_link_local() || addr.is_broadcast() || addr.is_unspecified() {
        return Err(AppError::Network(format!("IP address not allowed: {}", ip)));
    }

    let url = if zoom_speed == 0 {
        format!("http://{}/command/ptzf.cgi?ContinuousPanTiltZoom=0,0,0", addr)
    } else {
        let speed = zoom_speed.clamp(-100, 100);
        format!(
            "http://{}/command/ptzf.cgi?ContinuousPanTiltZoom=0,0,{}",
            addr, speed
        )
    };

    log::info!("Sony CGI zoom: speed={} → {}", zoom_speed, url);

    let client = reqwest::Client::new();
    let mut req = client.get(&url);
    if !username.is_empty() {
        req = req.basic_auth(&username, Some(&password));
    }

    let resp = req
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await
        .map_err(|e| AppError::Camera(format!("Sony CGI request failed: {}", e)))?;

    let status = resp.status();
    if !status.is_success() && status.as_u16() != 204 {
        return Err(AppError::Camera(format!(
            "Sony CGI returned HTTP {}",
            status
        )));
    }

    Ok(())
}
