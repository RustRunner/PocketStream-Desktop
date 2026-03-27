//! Screenshot and recording helpers.
//!
//! Screenshots are captured from the appsink in the playback pipeline.
//! Recording is handled by dynamically attaching/detaching a recording
//! branch to the pipeline's tee element.

use crate::error::AppError;
use std::fs;
use std::path::{Path, PathBuf};

/// Save raw RGB pixel data as a JPEG file.
pub fn save_screenshot_jpg(
    rgb_data: &[u8],
    width: u32,
    height: u32,
    output_dir: &Path,
) -> Result<PathBuf, AppError> {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("PS_Screenshot_{}.jpg", timestamp);
    let path = output_dir.join(&filename);

    fs::create_dir_all(output_dir)
        .map_err(|e| AppError::Stream(format!("Failed to create output dir: {}", e)))?;

    let img = image::RgbImage::from_raw(width, height, rgb_data.to_vec())
        .ok_or_else(|| AppError::Stream("RGB data size mismatch".into()))?;

    img.save_with_format(&path, image::ImageFormat::Jpeg)
        .map_err(|e| AppError::Stream(format!("Failed to save JPEG: {}", e)))?;

    log::info!("Screenshot saved: {}", path.display());
    Ok(path)
}

/// Generate a recording file path (doesn't create the file).
pub fn recording_path(output_dir: &Path) -> Result<PathBuf, AppError> {
    fs::create_dir_all(output_dir)
        .map_err(|e| AppError::Stream(format!("Failed to create output dir: {}", e)))?;

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("PS_Recording_{}.mp4", timestamp);
    Ok(output_dir.join(filename))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── save_screenshot_jpg ─────────────────────────────────────────

    #[test]
    fn save_screenshot_creates_dir_and_file() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("screenshots");
        let rgb = vec![0u8; 4 * 4 * 3]; // 4x4
        let path = save_screenshot_jpg(&rgb, 4, 4, &output).unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().contains("PS_Screenshot_"));
        assert_eq!(path.extension().unwrap(), "jpg");
    }

    // ── recording_path ──────────────────────────────────────────────

    #[test]
    fn recording_path_creates_dir() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("recordings");
        let path = recording_path(&output).unwrap();
        assert!(output.exists(), "Directory should be created");
        assert!(path.to_string_lossy().contains("PS_Recording_"));
        assert_eq!(path.extension().unwrap(), "mp4");
    }

    #[test]
    fn recording_path_unique_per_call() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = recording_path(dir.path()).unwrap();
        // Sleep briefly so timestamp differs
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let p2 = recording_path(dir.path()).unwrap();
        // Paths should differ (different timestamp)
        // Note: within the same second they'd be equal, hence the sleep
        assert_ne!(p1, p2);
    }
}
