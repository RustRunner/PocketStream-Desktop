//! Streaming, RTSP server, recording, and video-embed IPC handlers.

use tauri::{Manager, State};

use crate::config::AppConfig;
use crate::error::AppError;
use crate::streaming::{RtspServerInfo, StreamManager};

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

// ── Video Embed ─────────────────────────────────────────────────────

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
        Ok(child.to_string())
    }

    #[cfg(not(windows))]
    {
        let _ = (stream, x, y, width, height);
        Err(AppError::Stream(
            "Video embedding only supported on Windows".into(),
        ))
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
