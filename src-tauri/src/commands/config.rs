//! Config persistence IPC handlers.
//!
//! The device-cache IPC handlers that used to live here are gone — the
//! cache is now exclusively a side-effect of DeviceRegistry mutations
//! on the backend (see `commands/network.rs::report_scan_result`,
//! `set_device_alias`, `forget_device`). Frontend reads device state
//! via `get_device_list` and the `device-list-changed` event.

use tauri::State;

use crate::config::{
    AppConfig, AppSettingsView, Credentials, RestreamSettingsUpdate, StreamConfig,
};
use crate::error::AppError;
use crate::streaming::{RestreamOperationResult, StreamManager};

#[tauri::command]
pub async fn get_config(config: State<'_, AppConfig>) -> Result<AppSettingsView, AppError> {
    let settings = config.get();
    Ok(AppSettingsView::from(&settings))
}

#[tauri::command]
pub async fn update_stream_settings(
    config: State<'_, AppConfig>,
    stream: StreamConfig,
) -> Result<(), AppError> {
    config.update_stream(stream)
}

#[tauri::command]
pub async fn apply_restream_settings(
    config: State<'_, AppConfig>,
    stream: State<'_, StreamManager>,
    network: State<'_, crate::network::NetworkManager>,
    update: RestreamSettingsUpdate,
) -> Result<RestreamOperationResult, AppError> {
    let adopted = network.get_adopted_ips().await.into_values().collect();
    stream
        .apply_restream_settings(&config, update, &adopted)
        .await
}

#[tauri::command]
pub async fn update_credentials(
    config: State<'_, AppConfig>,
    credentials: Credentials,
) -> Result<(), AppError> {
    config.update_credentials(credentials)
}

/// Salvage actions taken while loading config files (quarantines,
/// resets). The frontend fetches this once at init and shows each entry
/// as an error toast.
#[tauri::command]
pub async fn get_startup_notices(config: State<'_, AppConfig>) -> Result<Vec<String>, AppError> {
    Ok(config.startup_notices())
}
