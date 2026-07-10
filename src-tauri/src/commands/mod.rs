//! Tauri IPC handlers grouped by domain.
//!
//! Submodules contain the per-domain implementations; this module
//! re-exports them so `lib.rs::generate_handler!` keeps using
//! `commands::<name>` paths regardless of where each function lives.
//! Logging commands (`log_frontend`, `open_log_folder`) are kept here
//! at the top level — they're cross-cutting, not part of any domain.

mod camera;
mod config;
mod network;
mod streaming;

pub use camera::*;
pub use config::*;
pub use network::*;
pub use streaming::*;

use crate::error::AppError;

// ── Logging Commands ─────────────────────────────────────────────────

#[tauri::command]
pub fn log_frontend(level: String, message: String) {
    // Cap the mirrored line so a hot frontend error loop can't bloat the
    // log file. Char-based, not byte-based — a byte slice can land
    // mid-UTF-8 and panic.
    const MAX_CHARS: usize = 2000;
    let message = if message.chars().count() > MAX_CHARS {
        let mut m: String = message.chars().take(MAX_CHARS).collect();
        m.push_str("… [truncated]");
        m
    } else {
        message
    };
    match level.as_str() {
        "error" => log::error!("[frontend] {}", message),
        "warn" => log::warn!("[frontend] {}", message),
        "debug" => log::debug!("[frontend] {}", message),
        _ => log::info!("[frontend] {}", message),
    }
}

#[tauri::command]
pub fn open_log_folder() -> Result<(), AppError> {
    let dir =
        crate::log_dir().ok_or_else(|| AppError::Config("Log directory not initialised".into()))?;

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
