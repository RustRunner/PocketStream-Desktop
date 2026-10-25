//! Streaming, re-stream server, recording, and video-embed IPC handlers.

use tauri::State;

use crate::config::{AppConfig, RestreamProtocol};
use crate::error::AppError;
use crate::streaming::{RestreamOperationResult, RestreamServerInfo, StreamManager};

#[tauri::command]
pub async fn start_stream(
    window: tauri::WebviewWindow,
    stream: State<'_, std::sync::Arc<StreamManager>>,
    config: State<'_, std::sync::Arc<AppConfig>>,
    window_handle: Option<usize>,
) -> Result<(), AppError> {
    let _ = window;
    let surface = stream.video_surface().capture();
    let settings = config.get();
    let result = stream.start_playback(&settings, window_handle).await;

    if result.is_err() {
        stream.video_surface().release(surface);
    }

    result
}

#[tauri::command]
pub async fn stop_stream(
    window: tauri::WebviewWindow,
    stream: State<'_, std::sync::Arc<StreamManager>>,
) -> Result<(), AppError> {
    let _ = window;
    let surface = stream.video_surface().capture();
    stream.stop_playback().await?;
    stream.video_surface().release(surface);

    Ok(())
}

/// Retry existing desired playback; never choose a replacement by address.
#[tauri::command]
pub async fn retry_playback(
    stream: State<'_, std::sync::Arc<StreamManager>>,
    config: State<'_, std::sync::Arc<AppConfig>>,
    manual: Option<bool>,
) -> Result<(), AppError> {
    stream
        .retry_playback(manual.unwrap_or(true), Some(config.get()))
        .await
}

#[tauri::command]
pub async fn set_audio_muted(
    stream: State<'_, std::sync::Arc<StreamManager>>,
    config: State<'_, std::sync::Arc<AppConfig>>,
    muted: bool,
) -> Result<(), AppError> {
    // Persist first: a failed save errors out before the live pipeline
    // changes, so the stored preference and what the user hears cannot
    // disagree.
    config.set_audio_muted(muted)?;
    stream.set_audio_muted(muted).await;
    Ok(())
}

#[tauri::command]
pub async fn start_restream_server(
    stream: State<'_, std::sync::Arc<StreamManager>>,
    config: State<'_, std::sync::Arc<AppConfig>>,
    network: State<'_, std::sync::Arc<crate::network::NetworkManager>>,
) -> Result<RestreamServerInfo, AppError> {
    // Adopted camera-network secondaries must never be chosen as the RTSP
    // bind or advertise IP — pass them so selection can skip them. Tauri
    // injects the managed NetworkManager, so the JS invoke signature is
    // unchanged.
    let adopted: std::collections::HashSet<String> =
        network.get_adopted_ips().await.into_values().collect();
    stream.start_restream_server(&config, &adopted).await
}

#[tauri::command]
pub async fn stop_restream_server(
    stream: State<'_, std::sync::Arc<StreamManager>>,
) -> Result<(), AppError> {
    stream.stop_restream_server().await
}

#[tauri::command]
pub async fn switch_restream_protocol(
    stream: State<'_, std::sync::Arc<StreamManager>>,
    config: State<'_, std::sync::Arc<AppConfig>>,
    network: State<'_, std::sync::Arc<crate::network::NetworkManager>>,
    protocol: RestreamProtocol,
) -> Result<RestreamOperationResult, AppError> {
    let adopted = network.get_adopted_ips().await.into_values().collect();
    stream
        .switch_restream_protocol(&config, protocol, &adopted)
        .await
}

#[tauri::command]
pub async fn take_screenshot(
    stream: State<'_, std::sync::Arc<StreamManager>>,
) -> Result<String, AppError> {
    stream.take_screenshot().await
}

#[tauri::command]
pub async fn start_recording(
    stream: State<'_, std::sync::Arc<StreamManager>>,
) -> Result<(), AppError> {
    stream.start_recording().await
}

#[tauri::command]
pub async fn stop_recording(
    stream: State<'_, std::sync::Arc<StreamManager>>,
) -> Result<String, AppError> {
    stream.stop_recording().await
}

// ── Video Embed ─────────────────────────────────────────────────────

/// Create a child window for GStreamer to render into.
/// Returns the child HWND as a number so the frontend can pass it to start_stream.
/// The child window is created on the main UI thread so it gets proper message processing.
#[tauri::command]
pub async fn create_video_window(
    window: tauri::WebviewWindow,
    stream: State<'_, std::sync::Arc<StreamManager>>,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> Result<String, AppError> {
    let _ = &window;

    #[cfg(windows)]
    {
        let hwnd = window
            .hwnd()
            .map_err(|e| AppError::Stream(format!("Failed to get window handle: {}", e)))?;
        let parent = hwnd.0 as isize;

        stream
            .video_surface()
            .create(parent, [x, y, width, height])
            .await
    }

    #[cfg(not(windows))]
    {
        let _ = (stream, x, y, width, height);
        Err(AppError::Stream(
            "Video embedding only supported on Windows".into(),
        ))
    }
}

// Position/visibility ops hop to the main thread like create/destroy:
// SetWindowPos/ShowWindow from another thread degrade to synchronous
// inter-thread SendMessage — a stall or deadlock hazard against a busy
// UI thread. The inner Result comes back via the same oneshot pattern
// create_video_window uses.

#[tauri::command]
pub async fn update_video_position(
    window: tauri::WebviewWindow,
    stream: State<'_, std::sync::Arc<StreamManager>>,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> Result<(), AppError> {
    let _ = window;
    stream
        .video_surface()
        .reposition([x, y, width, height])
        .await
}

#[tauri::command]
pub async fn set_video_visible(
    window: tauri::WebviewWindow,
    stream: State<'_, std::sync::Arc<StreamManager>>,
    visible: bool,
) -> Result<(), AppError> {
    let _ = window;
    stream.video_surface().set_visible(visible).await
}
