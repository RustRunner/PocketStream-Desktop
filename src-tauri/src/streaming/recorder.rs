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
