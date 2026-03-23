//! Embed the GStreamer video window inside the Tauri application window.
//!
//! After `autovideosink` creates its own top-level window, we find it,
//! strip its decorations, reparent it as a child of the Tauri window,
//! and position it over the video card area.

use crate::error::AppError;

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use windows_sys::Win32::Foundation::*;
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::*;

#[cfg(windows)]
type HWND = *mut c_void;

#[cfg(windows)]
struct EnumData {
    pid: u32,
    parent: HWND,
    found: HWND,
}

#[cfg(windows)]
unsafe extern "system" fn enum_top_level_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let data = &mut *(lparam as *mut EnumData);

    let mut window_pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, &mut window_pid);

    if window_pid != data.pid {
        return TRUE;
    }

    // Skip our own main window
    if hwnd == data.parent {
        return TRUE;
    }

    // Only consider visible windows
    if IsWindowVisible(hwnd) == 0 {
        return TRUE;
    }

    // Check title for GStreamer renderer windows
    let mut title = [0u16; 256];
    let len = GetWindowTextW(hwnd, title.as_mut_ptr(), 256);
    if len > 0 {
        let title_str = String::from_utf16_lossy(&title[..len as usize]);
        if title_str.contains("Renderer")
            || title_str.contains("GStreamer")
            || title_str.contains("Direct3D")
        {
            data.found = hwnd;
            return FALSE; // stop
        }
    }

    TRUE
}

/// Find the GStreamer video window, reparent it as a child of `parent_hwnd`,
/// strip decorations, and position it at (x, y, width, height) within the parent.
/// Returns the GStreamer window handle (as isize for storage) for later repositioning.
#[cfg(windows)]
pub fn embed(parent_hwnd: isize, x: i32, y: i32, width: i32, height: i32) -> Result<isize, AppError> {
    unsafe {
        let pid = windows_sys::Win32::System::Threading::GetCurrentProcessId();
        let parent: HWND = parent_hwnd as HWND;

        let mut data = EnumData {
            pid,
            parent,
            found: std::ptr::null_mut(),
        };

        EnumWindows(Some(enum_top_level_cb), &mut data as *mut _ as LPARAM);

        if data.found.is_null() {
            return Err(AppError::Stream(
                "GStreamer video window not found — it may not have opened yet".into(),
            ));
        }

        let gst_hwnd: HWND = data.found;

        // Remove window decorations (caption, thick frame, popup) and add WS_CHILD
        let style = GetWindowLongPtrW(gst_hwnd, GWL_STYLE) as u32;
        let new_style = (style & !(WS_CAPTION | WS_THICKFRAME | WS_POPUP | WS_SYSMENU))
            | WS_CHILD
            | WS_CLIPSIBLINGS;
        SetWindowLongPtrW(gst_hwnd, GWL_STYLE, new_style as isize);

        // Remove extended border styles
        let ex_style = GetWindowLongPtrW(gst_hwnd, GWL_EXSTYLE) as u32;
        let new_ex = ex_style
            & !(WS_EX_DLGMODALFRAME
                | WS_EX_WINDOWEDGE
                | WS_EX_CLIENTEDGE
                | WS_EX_STATICEDGE);
        SetWindowLongPtrW(gst_hwnd, GWL_EXSTYLE, new_ex as isize);

        // Reparent
        SetParent(gst_hwnd, parent);

        // Position within parent's client area
        MoveWindow(gst_hwnd, x, y, width, height, TRUE);
        ShowWindow(gst_hwnd, SW_SHOW);

        let handle = gst_hwnd as isize;
        log::info!(
            "Embedded GStreamer window (hwnd=0x{:X}) into parent (hwnd=0x{:X}) at ({},{} {}x{})",
            handle, parent_hwnd, x, y, width, height
        );

        Ok(handle)
    }
}

/// Reposition an already-embedded video window.
#[cfg(windows)]
pub fn reposition(gst_hwnd_raw: isize, x: i32, y: i32, width: i32, height: i32) -> Result<(), AppError> {
    unsafe {
        let gst_hwnd: HWND = gst_hwnd_raw as HWND;
        if IsWindow(gst_hwnd) == 0 {
            return Err(AppError::Stream("Video window no longer exists".into()));
        }
        MoveWindow(gst_hwnd, x, y, width, height, TRUE);
        Ok(())
    }
}

/// Hide the embedded video window (e.g. when a modal dialog opens).
#[cfg(windows)]
pub fn set_visible(gst_hwnd_raw: isize, visible: bool) -> Result<(), AppError> {
    unsafe {
        let gst_hwnd: HWND = gst_hwnd_raw as HWND;
        if IsWindow(gst_hwnd) == 0 {
            return Err(AppError::Stream("Video window no longer exists".into()));
        }
        ShowWindow(gst_hwnd, if visible { SW_SHOW } else { SW_HIDE });
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn set_visible(_hwnd: isize, _visible: bool) -> Result<(), AppError> {
    Err(AppError::Stream("Video embedding is only supported on Windows".into()))
}

// Stubs for non-Windows platforms
#[cfg(not(windows))]
pub fn embed(_parent: isize, _x: i32, _y: i32, _w: i32, _h: i32) -> Result<isize, AppError> {
    Err(AppError::Stream("Video embedding is only supported on Windows".into()))
}

#[cfg(not(windows))]
pub fn reposition(_hwnd: isize, _x: i32, _y: i32, _w: i32, _h: i32) -> Result<(), AppError> {
    Err(AppError::Stream("Video embedding is only supported on Windows".into()))
}
