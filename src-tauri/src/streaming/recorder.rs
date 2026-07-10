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
    // Millisecond precision so two captures in the same second don't
    // overwrite each other.
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S_%3f");
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

/// Minimum free space required to start a recording. Fragmented MP4 at
/// the pipeline's 4 Mbps is roughly 30 MB/min; 512 MB gives the
/// operator meaningful runway while leaving headroom for the rest of
/// the system. No automatic deletion ever — field footage may be
/// evidence; when space runs out the answer is a clear error, not a
/// reaper.
pub const RECORDING_MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;

/// True when a recording may start with `free` bytes available on the
/// recording volume.
pub fn recording_space_ok(free: u64) -> bool {
    free >= RECORDING_MIN_FREE_BYTES
}

/// Free bytes available to the current user on the volume containing
/// `path`. Walks up to the deepest existing ancestor first — the
/// recording directory itself may not exist yet. `None` when the probe
/// fails; callers should fail open (a broken probe must not block
/// recording).
#[cfg(windows)]
pub fn free_space_bytes(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let mut probe = path;
    while !probe.exists() {
        probe = probe.parent()?;
    }
    let wide: Vec<u16> = probe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut free_to_caller: u64 = 0;
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free_to_caller,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(free_to_caller)
}

#[cfg(not(windows))]
pub fn free_space_bytes(_path: &Path) -> Option<u64> {
    None
}

/// Generate a recording file path (doesn't create the file).
pub fn recording_path(output_dir: &Path) -> Result<PathBuf, AppError> {
    fs::create_dir_all(output_dir)
        .map_err(|e| AppError::Stream(format!("Failed to create output dir: {}", e)))?;

    // Millisecond precision so two recordings started in the same second
    // don't collide.
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S_%3f");
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

    // ── free-space pre-flight ───────────────────────────────────────

    #[test]
    fn space_floor_boundaries() {
        assert!(!recording_space_ok(0));
        assert!(!recording_space_ok(RECORDING_MIN_FREE_BYTES - 1));
        assert!(recording_space_ok(RECORDING_MIN_FREE_BYTES));
    }

    #[cfg(windows)]
    #[test]
    fn free_space_probe_returns_some_for_temp_dir() {
        assert!(free_space_bytes(&std::env::temp_dir()).is_some());
    }

    #[cfg(windows)]
    #[test]
    fn free_space_probe_walks_up_to_existing_ancestor() {
        let p = std::env::temp_dir()
            .join("ps-does-not-exist")
            .join("nested");
        assert!(free_space_bytes(&p).is_some());
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
        // A few ms is enough now that the name carries milliseconds —
        // no longer the full second the old second-resolution name needed.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let p2 = recording_path(dir.path()).unwrap();
        assert_ne!(p1, p2);
    }
}
