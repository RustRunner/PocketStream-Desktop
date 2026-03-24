//! Screenshot and recording helpers.
//!
//! Screenshots are captured from the appsink in the playback pipeline.
//! Recording is handled by dynamically attaching/detaching a recording
//! branch to the pipeline's tee element.

use crate::error::AppError;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Save raw RGB pixel data as a BMP file (no external image crate needed).
///
/// BMP is used because it can be written with zero dependencies.
/// For JPEG/PNG, add the `image` crate later.
pub fn save_screenshot_bmp(
    rgb_data: &[u8],
    width: u32,
    height: u32,
    output_dir: &Path,
) -> Result<PathBuf, AppError> {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("PS_Screenshot_{}.bmp", timestamp);
    let path = output_dir.join(&filename);

    fs::create_dir_all(output_dir)
        .map_err(|e| AppError::Stream(format!("Failed to create output dir: {}", e)))?;

    write_bmp(&path, rgb_data, width, height)?;

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

/// Write raw RGB data as a 24-bit BMP file.
fn write_bmp(path: &Path, rgb_data: &[u8], width: u32, height: u32) -> Result<(), AppError> {
    let row_size = ((width * 3 + 3) / 4) * 4; // rows padded to 4-byte boundary
    let pixel_data_size = row_size * height;
    let file_size = 54 + pixel_data_size;

    let mut file = fs::File::create(path)
        .map_err(|e| AppError::Stream(format!("Failed to create BMP: {}", e)))?;

    // BMP Header (14 bytes)
    file.write_all(b"BM")?;
    file.write_all(&file_size.to_le_bytes())?;
    file.write_all(&0u16.to_le_bytes())?; // reserved
    file.write_all(&0u16.to_le_bytes())?; // reserved
    file.write_all(&54u32.to_le_bytes())?; // pixel data offset

    // DIB Header — BITMAPINFOHEADER (40 bytes)
    file.write_all(&40u32.to_le_bytes())?; // header size
    file.write_all(&width.to_le_bytes())?;
    // Negative height = top-down row order (matches our RGB data)
    file.write_all(&(-(height as i32)).to_le_bytes())?;
    file.write_all(&1u16.to_le_bytes())?; // color planes
    file.write_all(&24u16.to_le_bytes())?; // bits per pixel
    file.write_all(&0u32.to_le_bytes())?; // compression (none)
    file.write_all(&pixel_data_size.to_le_bytes())?;
    file.write_all(&2835u32.to_le_bytes())?; // h resolution (72 DPI)
    file.write_all(&2835u32.to_le_bytes())?; // v resolution
    file.write_all(&0u32.to_le_bytes())?; // colors in palette
    file.write_all(&0u32.to_le_bytes())?; // important colors

    // Pixel data — BMP stores as BGR, our data is RGB
    let row_stride = (width * 3) as usize;
    let padding = vec![0u8; (row_size - width * 3) as usize];

    for y in 0..height as usize {
        let row_start = y * row_stride;
        let row_end = row_start + row_stride;

        if row_end > rgb_data.len() {
            break;
        }

        let row = &rgb_data[row_start..row_end];

        // Convert RGB to BGR for each pixel
        for x in 0..width as usize {
            let i = x * 3;
            file.write_all(&[row[i + 2], row[i + 1], row[i]])?; // BGR
        }
        file.write_all(&padding)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    // ── write_bmp ───────────────────────────────────────────────────

    #[test]
    fn write_bmp_creates_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bmp");
        // 2x2 red pixels: RGB(255,0,0) × 4
        let rgb = vec![
            255, 0, 0, 255, 0, 0,
            255, 0, 0, 255, 0, 0,
        ];
        write_bmp(&path, &rgb, 2, 2).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn write_bmp_magic_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("magic.bmp");
        let rgb = vec![0u8; 3]; // 1x1 black pixel
        write_bmp(&path, &rgb, 1, 1).unwrap();

        let mut file = fs::File::open(&path).unwrap();
        let mut header = [0u8; 2];
        file.read_exact(&mut header).unwrap();
        assert_eq!(&header, b"BM");
    }

    #[test]
    fn write_bmp_file_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("size.bmp");
        let width = 4u32;
        let height = 3u32;
        let rgb = vec![128u8; (width * height * 3) as usize];
        write_bmp(&path, &rgb, width, height).unwrap();

        let file_len = fs::metadata(&path).unwrap().len();
        // Row size = ((4*3 + 3)/4)*4 = 12 (no padding needed for width=4)
        // File size = 54 (header) + 12 * 3 (rows) = 90
        assert_eq!(file_len, 90);
    }

    #[test]
    fn write_bmp_row_padding() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pad.bmp");
        // Width 3: row_stride = 9 bytes, padded to 12 bytes
        let width = 3u32;
        let height = 1u32;
        let rgb = vec![0u8; 9]; // 3 pixels × 3 bytes
        write_bmp(&path, &rgb, width, height).unwrap();

        let file_len = fs::metadata(&path).unwrap().len();
        // Row size = ((3*3+3)/4)*4 = 12
        // File size = 54 + 12 = 66
        assert_eq!(file_len, 66);
    }

    #[test]
    fn write_bmp_rgb_to_bgr_conversion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("color.bmp");
        // 1x1 pixel: RGB(0xAA, 0xBB, 0xCC)
        let rgb = vec![0xAA, 0xBB, 0xCC];
        write_bmp(&path, &rgb, 1, 1).unwrap();

        let data = fs::read(&path).unwrap();
        // Pixel data starts at offset 54
        // BMP stores BGR, so: CC BB AA (+ 1 byte padding for width=1)
        assert_eq!(data[54], 0xCC); // Blue
        assert_eq!(data[55], 0xBB); // Green
        assert_eq!(data[56], 0xAA); // Red
    }

    #[test]
    fn write_bmp_dimensions_in_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dims.bmp");
        let rgb = vec![0u8; 10 * 5 * 3];
        write_bmp(&path, &rgb, 10, 5).unwrap();

        let data = fs::read(&path).unwrap();
        // Width at offset 18 (4 bytes LE)
        let w = u32::from_le_bytes([data[18], data[19], data[20], data[21]]);
        assert_eq!(w, 10);
        // Height at offset 22 (4 bytes LE, negative for top-down)
        let h = i32::from_le_bytes([data[22], data[23], data[24], data[25]]);
        assert_eq!(h, -5);
    }

    #[test]
    fn write_bmp_24_bits_per_pixel() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bpp.bmp");
        let rgb = vec![0u8; 3];
        write_bmp(&path, &rgb, 1, 1).unwrap();

        let data = fs::read(&path).unwrap();
        // Bits per pixel at offset 28 (2 bytes LE)
        let bpp = u16::from_le_bytes([data[28], data[29]]);
        assert_eq!(bpp, 24);
    }

    // ── save_screenshot_bmp ─────────────────────────────────────────

    #[test]
    fn save_screenshot_creates_dir_and_file() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("screenshots");
        let rgb = vec![0u8; 4 * 4 * 3]; // 4x4
        let path = save_screenshot_bmp(&rgb, 4, 4, &output).unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().contains("PS_Screenshot_"));
        assert!(path.extension().unwrap() == "bmp");
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
