//! Video embedding helpers.
//!
//! Provides functions to create, reposition, show/hide, and destroy
//! a child HWND that GStreamer renders into via VideoOverlay.
//! All window operations are performed on the calling thread — callers
//! must ensure they run on the main UI thread (see commands.rs).

use crate::error::AppError;

#[cfg(windows)]
use windows_sys::Win32::Foundation::*;
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::*;

/// Create a child window inside `parent_hwnd` at the given position.
/// MUST be called on the main UI thread.
/// Returns the child HWND as `isize`.
#[cfg(windows)]
pub fn create_video_child(
    parent_hwnd: isize,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> Result<isize, AppError> {
    unsafe {
        let parent = parent_hwnd as *mut std::ffi::c_void;
        let class_name: Vec<u16> = "Static\0".encode_utf16().collect();

        let child = CreateWindowExW(
            0,
            class_name.as_ptr(),
            std::ptr::null(),
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
            x,
            y,
            width,
            height,
            parent,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        if child.is_null() {
            let err = GetLastError();
            return Err(AppError::Stream(format!(
                "CreateWindowExW failed (error {})",
                err
            )));
        }

        // Bring to top of z-order so it's above WebView2
        SetWindowPos(
            child,
            0 as *mut std::ffi::c_void, // HWND_TOP = 0
            x,
            y,
            width,
            height,
            SWP_SHOWWINDOW,
        );

        let handle = child as isize;
        log::info!(
            "Created video child HWND 0x{:X} at ({},{} {}x{}) inside parent 0x{:X}",
            handle, x, y, width, height, parent_hwnd
        );

        Ok(handle)
    }
}

/// Reposition the child video window.
#[cfg(windows)]
pub fn reposition(child_hwnd: isize, x: i32, y: i32, width: i32, height: i32) -> Result<(), AppError> {
    unsafe {
        let hwnd = child_hwnd as *mut std::ffi::c_void;
        if IsWindow(hwnd) == 0 {
            return Err(AppError::Stream("Video child window no longer exists".into()));
        }
        SetWindowPos(
            hwnd,
            0 as *mut std::ffi::c_void, // HWND_TOP
            x,
            y,
            width,
            height,
            SWP_SHOWWINDOW,
        );
        Ok(())
    }
}

/// Show or hide the child video window.
#[cfg(windows)]
pub fn set_visible(child_hwnd: isize, visible: bool) -> Result<(), AppError> {
    unsafe {
        let hwnd = child_hwnd as *mut std::ffi::c_void;
        if IsWindow(hwnd) == 0 {
            return Err(AppError::Stream("Video child window no longer exists".into()));
        }
        ShowWindow(hwnd, if visible { SW_SHOW } else { SW_HIDE });
        Ok(())
    }
}

/// Destroy the child video window.
#[cfg(windows)]
pub fn destroy_video_child(child_hwnd: isize) {
    unsafe {
        let hwnd = child_hwnd as *mut std::ffi::c_void;
        if IsWindow(hwnd) != 0 {
            DestroyWindow(hwnd);
            log::info!("Destroyed video child HWND 0x{:X}", child_hwnd);
        }
    }
}

// ── Non-Windows stubs ──────────────────────────────────────────────

#[cfg(not(windows))]
pub fn create_video_child(_p: isize, _x: i32, _y: i32, _w: i32, _h: i32) -> Result<isize, AppError> {
    Err(AppError::Stream("Video embedding only supported on Windows".into()))
}

#[cfg(not(windows))]
pub fn reposition(_h: isize, _x: i32, _y: i32, _w: i32, _h2: i32) -> Result<(), AppError> {
    Err(AppError::Stream("Video embedding only supported on Windows".into()))
}

#[cfg(not(windows))]
pub fn set_visible(_h: isize, _v: bool) -> Result<(), AppError> {
    Err(AppError::Stream("Video embedding only supported on Windows".into()))
}

#[cfg(not(windows))]
pub fn destroy_video_child(_h: isize) {}
