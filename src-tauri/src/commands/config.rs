//! Config persistence and device-cache IPC handlers.

use tauri::State;

use crate::config::{
    AppConfig, AppSettings, CachedDevice, Credentials, RtspServerConfig, StreamConfig,
};
use crate::error::AppError;

#[tauri::command]
pub async fn get_config(config: State<'_, AppConfig>) -> Result<AppSettings, AppError> {
    Ok(config.get())
}

/// Save the user-editable sections of an `AppSettings` payload from the
/// frontend. Backend-owned fields (`device_cache`, `adopted_subnets`,
/// `zoom_positions`) are preserved server-side regardless of what the
/// caller sends, so a frontend that forgets to round-trip them won't
/// wipe persistent state. New code should prefer the narrower
/// `update_stream_settings` / `update_rtsp_settings` / `update_credentials`
/// commands.
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

// ── Device Cache ────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_device_cache(config: State<'_, AppConfig>) -> Result<Vec<CachedDevice>, AppError> {
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
pub async fn clear_device_cache(config: State<'_, AppConfig>) -> Result<(), AppError> {
    config.clear_device_cache()
}
