use tauri::State;

use crate::config::{AppConfig, AppSettings};
use crate::error::AppError;
use crate::network::{InterfaceInfo, NetworkManager, ScanResult};
use crate::streaming::{StreamManager, StreamStatus};

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

// ── Streaming Commands ───────────────────────────────────────────────

#[tauri::command]
pub async fn start_stream(
    stream: State<'_, StreamManager>,
    config: State<'_, AppConfig>,
) -> Result<(), AppError> {
    let settings = config.get();
    stream.start_playback(&settings).await
}

#[tauri::command]
pub async fn stop_stream(stream: State<'_, StreamManager>) -> Result<(), AppError> {
    stream.stop_playback().await
}

#[tauri::command]
pub async fn start_rtsp_server(
    stream: State<'_, StreamManager>,
    config: State<'_, AppConfig>,
) -> Result<String, AppError> {
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
