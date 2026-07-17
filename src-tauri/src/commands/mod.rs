//! Tauri IPC handlers grouped by domain.
//!
//! Submodules contain the per-domain implementations; this module
//! re-exports them so `lib.rs::generate_handler!` keeps using
//! `commands::<name>` paths regardless of where each function lives.
//! Logging and licensing commands (`log_frontend`, `open_log_folder`,
//! `get_license_document`) are kept here at the top level — they're
//! cross-cutting, not part of any domain.

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

// ── License Documents ────────────────────────────────────────────────

/// Ids the frontend may request via `get_license_document`; each maps to
/// one document shipped under `resources/licenses/`. Mirrored by
/// `LicenseDocumentId` in `src/lib/types.ts` (hand-maintained). Used by
/// the tests to pin every id to a committed resource.
#[cfg(test)]
const LICENSE_DOCUMENT_IDS: [&str; 12] = [
    "app-license",
    "third-party-notices",
    "rust-crates",
    "lgpl-2.1",
    "lgpl-2.0",
    "gpl-2.0",
    "mit",
    "bsd-3-clause",
    "zlib",
    "libpng",
    "libjpeg-turbo",
    "bzip2",
];

/// Resource-relative path for a license document id. Fixed allowlist —
/// the id is the only caller-controlled input and it never reaches the
/// filesystem as a path, so the command can't be steered outside the
/// shipped documents.
fn license_document_path(id: &str) -> Option<&'static str> {
    Some(match id {
        "app-license" => "licenses/texts/GPL-3.0.txt",
        "third-party-notices" => "licenses/THIRD-PARTY-NOTICES.md",
        "rust-crates" => "licenses/generated/THIRD-PARTY-RUST.md",
        "lgpl-2.1" => "licenses/texts/LGPL-2.1.txt",
        "lgpl-2.0" => "licenses/texts/LGPL-2.0.txt",
        "gpl-2.0" => "licenses/texts/GPL-2.0.txt",
        "mit" => "licenses/texts/MIT.txt",
        "bsd-3-clause" => "licenses/texts/BSD-3-Clause.txt",
        "zlib" => "licenses/texts/Zlib.txt",
        "libpng" => "licenses/texts/libpng-2.0.txt",
        "libjpeg-turbo" => "licenses/texts/libjpeg-turbo-LICENSE.md",
        "bzip2" => "licenses/texts/bzip2.txt",
        _ => return None,
    })
}

#[tauri::command]
pub fn get_license_document(app: tauri::AppHandle, id: String) -> Result<String, AppError> {
    use tauri::Manager;

    let rel = license_document_path(&id)
        .ok_or_else(|| AppError::Config(format!("Unknown license document '{id}'")))?;
    // The bundler preserves each resource's tauri.conf-relative path, so
    // an installed build ships the documents under `resources/` inside
    // the resource root (`<install_dir>\resources\licenses\...` — the
    // same layout the bundled-GStreamer loader addresses). Try that
    // first; fall back to the bare path for layouts that strip the
    // prefix.
    let resolve = |p: &str| {
        app.path()
            .resolve(p, tauri::path::BaseDirectory::Resource)
            .map_err(|e| AppError::Config(format!("Cannot resolve license document '{id}': {e}")))
    };
    let mut path = resolve(&format!("resources/{rel}"))?;
    if !path.exists() {
        let alt = resolve(rel)?;
        if alt.exists() {
            path = alt;
        } else {
            // The Rust-crate notices only exist in release builds (the
            // release workflow generates them); a dev build legitimately
            // lacks the file. The frontend keys off the "not generated"
            // marker to show a note instead of an error toast.
            return Err(AppError::Config(format!(
                "not generated: '{id}' is produced during release builds"
            )));
        }
    }

    std::fs::read_to_string(&path).map_err(AppError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every allowlisted id must resolve, and every resolved document
    /// except the build-generated one must exist as a committed
    /// resource — this pins the allowlist to the files the installer
    /// actually ships.
    #[test]
    fn license_documents_exist_in_committed_resources() {
        let resources = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("resources");
        for id in LICENSE_DOCUMENT_IDS {
            let rel = license_document_path(id)
                .unwrap_or_else(|| panic!("id '{id}' missing from license_document_path"));
            if rel.starts_with("licenses/generated/") {
                continue;
            }
            assert!(
                resources.join(rel).exists(),
                "license document '{id}' missing at resources/{rel}"
            );
        }
    }

    #[test]
    fn unknown_license_document_ids_are_rejected() {
        assert!(license_document_path("").is_none());
        assert!(license_document_path("APP-LICENSE").is_none());
        assert!(license_document_path("../../../etc/passwd").is_none());
        assert!(license_document_path("licenses/texts/MIT.txt").is_none());
    }
}
