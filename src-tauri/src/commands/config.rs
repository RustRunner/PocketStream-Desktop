//! Config persistence IPC handlers.
//!
//! The device-cache IPC handlers that used to live here are gone — the
//! cache is now exclusively a side-effect of DeviceRegistry mutations
//! on the backend (see `commands/network.rs::report_scan_result`,
//! `set_device_alias`, `forget_device`). Frontend reads device state
//! via `get_device_list` and the `device-list-changed` event.

use tauri::State;

use crate::config::{AppConfig, AppSettings, Credentials, RtspServerConfig, StreamConfig};
use crate::error::AppError;

#[tauri::command]
pub async fn get_config(config: State<'_, AppConfig>) -> Result<AppSettings, AppError> {
    Ok(config.get())
}

/// Save the user-editable sections of an `AppSettings` payload from the
/// frontend. Backend-owned fields (`adopted_subnets`, `zoom_positions`)
/// are preserved server-side regardless of what the caller sends. The
/// device cache lives in its own file (see `cache_path` in config.rs)
/// so this command is structurally incapable of touching it. New code
/// should prefer the narrower `update_stream_settings` /
/// `update_rtsp_settings` / `update_credentials` commands.
#[tauri::command]
pub async fn save_config(
    config: State<'_, AppConfig>,
    settings: AppSettings,
) -> Result<(), AppError> {
    config.merge_user_settings(settings)
}

#[tauri::command]
pub async fn update_stream_settings(
    config: State<'_, AppConfig>,
    stream: StreamConfig,
) -> Result<(), AppError> {
    config.update_stream(stream)
}

#[tauri::command]
pub async fn update_rtsp_settings(
    config: State<'_, AppConfig>,
    rtsp_server: RtspServerConfig,
) -> Result<(), AppError> {
    config.update_rtsp(rtsp_server)
}

#[tauri::command]
pub async fn update_credentials(
    config: State<'_, AppConfig>,
    credentials: Credentials,
) -> Result<(), AppError> {
    config.update_credentials(credentials)
}
