//! Video embedding helpers.
//!
//! Provides functions to create, reposition, show/hide, and destroy
//! a child HWND that GStreamer renders into via VideoOverlay.
//! All window operations are performed on the calling thread — callers
//! must ensure they run on the main UI thread (see commands.rs).
//!
//! The video window uses a custom window class that returns HTTRANSPARENT
//! for WM_NCHITTEST, making it fully input-transparent for both mouse
//! and touch.  All user interaction goes through the WebView underneath.

use crate::error::AppError;

#[cfg(windows)]
use windows_sys::Win32::Foundation::*;
#[cfg(windows)]
use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::*;

/// Custom WndProc that makes the window invisible to hit-testing.
/// Returns HTTRANSPARENT (-1) for WM_NCHITTEST so all mouse AND touch
/// input passes through to the WebView below.
#[cfg(windows)]
unsafe extern "system" fn video_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_NCHITTEST {
        return -1; // HTTRANSPARENT
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

/// Register the custom "PocketStreamVideo" window class (once).
#[cfg(windows)]
fn ensure_video_class() {
    use std::sync::Once;
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| {
        let class_name: Vec<u16> = "PocketStreamVideo\0".encode_utf16().collect();
        unsafe {
            let wc = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: 0,
                lpfnWndProc: Some(video_wndproc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: std::ptr::null_mut(),
                hIcon: std::ptr::null_mut(),
                hCursor: std::ptr::null_mut(),
                hbrBackground: std::ptr::null_mut(),
                lpszMenuName: std::ptr::null(),
                lpszClassName: class_name.as_ptr(),
                hIconSm: std::ptr::null_mut(),
            };
            RegisterClassExW(&wc);
        }
    });
}

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
    ensure_video_class();

    unsafe {
        let parent = parent_hwnd as HWND;
        let class_name: Vec<u16> = "PocketStreamVideo\0".encode_utf16().collect();

        let child = CreateWindowExW(
            WS_EX_TRANSPARENT,
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

        SetWindowPos(
            child,
            0 as HWND, // HWND_TOP
            x,
            y,
            width,
            height,
            SWP_SHOWWINDOW | SWP_NOACTIVATE,
        );

        // Disable the window so it receives NO input (mouse or touch).
        // GStreamer still renders to it via VideoOverlay — only input
        // routing is affected.  Touch events fall through to WebView.
        EnableWindow(child, 0); // FALSE

        let handle = child as isize;
        log::info!(
            "Created video child HWND 0x{:X} at ({},{} {}x{}) inside parent 0x{:X}",
            handle,
            x,
            y,
            width,
            height,
            parent_hwnd
        );

        Ok(handle)
    }
}

/// Reposition the child video window.
#[cfg(windows)]
pub fn reposition(
    child_hwnd: isize,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> Result<(), AppError> {
    unsafe {
        let hwnd = child_hwnd as *mut std::ffi::c_void;
        if IsWindow(hwnd) == 0 {
            return Err(AppError::Stream(
                "Video child window no longer exists".into(),
            ));
        }
        SetWindowPos(
            hwnd,
            std::ptr::null_mut::<std::ffi::c_void>(), // HWND_TOP
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
            return Err(AppError::Stream(
                "Video child window no longer exists".into(),
            ));
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
pub fn create_video_child(
    _p: isize,
    _x: i32,
    _y: i32,
    _w: i32,
    _h: i32,
) -> Result<isize, AppError> {
    Err(AppError::Stream(
        "Video embedding only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn reposition(_h: isize, _x: i32, _y: i32, _w: i32, _h2: i32) -> Result<(), AppError> {
    Err(AppError::Stream(
        "Video embedding only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn set_visible(_h: isize, _v: bool) -> Result<(), AppError> {
    Err(AppError::Stream(
        "Video embedding only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn destroy_video_child(_h: isize) {}
