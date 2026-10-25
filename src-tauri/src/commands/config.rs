//! Config persistence IPC handlers.
//!
//! The device-cache IPC handlers that used to live here are gone — the
//! cache is now exclusively a side-effect of DeviceRegistry mutations
//! on the backend (scan completion, `set_device_alias`, `forget_device`).
//! Frontend reads device state
//! via `get_device_list` and the `device-list-changed` event.

use tauri::State;

use crate::config::{
    AppConfig, AppSettingsView, Credentials, RestreamSettingsUpdate, StreamConfig,
};
use crate::error::AppError;
use crate::streaming::{RestreamOperationResult, StreamManager};

#[tauri::command]
pub async fn get_config(
    config: State<'_, std::sync::Arc<AppConfig>>,
) -> Result<AppSettingsView, AppError> {
    crate::network::bindings::migrate(&config).await?;
    let settings = config.get();
    Ok(AppSettingsView::from(&settings))
}

#[tauri::command]
pub async fn update_stream_settings(
    config: State<'_, std::sync::Arc<AppConfig>>,
    stream: StreamConfig,
) -> Result<(), AppError> {
    config.update_stream(stream)
}

#[tauri::command]
pub async fn apply_restream_settings(
    config: State<'_, std::sync::Arc<AppConfig>>,
    stream: State<'_, std::sync::Arc<StreamManager>>,
    network: State<'_, std::sync::Arc<crate::network::NetworkManager>>,
    update: RestreamSettingsUpdate,
) -> Result<RestreamOperationResult, AppError> {
    let adopted = network.get_adopted_ips().await.into_values().collect();
    stream
        .apply_restream_settings(&config, update, &adopted)
        .await
}

#[tauri::command]
pub async fn update_credentials(
    config: State<'_, std::sync::Arc<AppConfig>>,
    credentials: Credentials,
) -> Result<(), AppError> {
    config.update_credentials(credentials)
}

/// Salvage actions taken while loading config files (quarantines,
/// resets). The frontend fetches this once at init and shows each entry
/// as an error toast.
#[tauri::command]
pub async fn get_startup_notices(
    config: State<'_, std::sync::Arc<AppConfig>>,
) -> Result<Vec<String>, AppError> {
    Ok(config.startup_notices())
}
