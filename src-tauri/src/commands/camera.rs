//! Camera control IPC handlers — FLIR PTU, Nexus `control.cgi`, and
//! zoom-position persistence.

use tauri::State;

use crate::config::AppConfig;
use crate::error::AppError;
use crate::network::{route::CameraTarget, NetworkManager};
use crate::validation::parse_camera_ip;

/// Open a discovered device's web UI in the system browser.
///
/// Runs on the backend so the webview needs no shell-open capability —
/// the shell plugin isn't installed at all, so the webview process
/// can't be coerced into opening an arbitrary URL or path. The IP is
/// validated with fresh device identity evidence on the selected Ethernet.
/// A PC address conflict produces an actionable error instead of opening the
/// wrong host or disguising the conflict behind a loopback web address.
#[tauri::command]
pub async fn open_device_browser(
    target: CameraTarget,
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
) -> Result<(), AppError> {
    let addr = parse_camera_ip(&target.ip)?;
    let owners = crate::network::ip_conflict::local_ip_owners()?;
    if let Some(warning) = crate::network::ip_conflict::conflict_message(&target.ip, &owners) {
        return Err(AppError::Network(warning));
    }
    manager.camera_ready_now(&target, &config)?;
    let url = format!("http://{addr}/");
    #[cfg(target_os = "windows")]
    {
        crate::network::cmd("explorer")
            .arg(&url)
            .spawn()
            .map_err(|e| AppError::Network(format!("Unable to open device browser: {e}")))?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&url)
            .spawn()
            .map_err(|e| AppError::Network(format!("Unable to open device browser: {e}")))?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&url)
            .spawn()
            .map_err(|e| AppError::Network(format!("Unable to open device browser: {e}")))?;
    }
    Ok(())
}

// ── FLIR PTU ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn ptu_send(
    ptu: State<'_, crate::camera::flir_ptu::PtuController>,
    target: CameraTarget,
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    cmd: String,
) -> Result<std::collections::HashMap<String, String>, AppError> {
    parse_camera_ip(&target.ip)?;
    // Route through the backend controller: serializes all PTU sends at
    // the trust boundary (no frontend path can interleave) and enforces
    // velocity mode on speed commands.
    ptu.send(&manager, &config, &target, &cmd).await
}

// ── Nexus control.cgi ───────────────────────────────────────────────

/// Absolute-position zoom against a FLIR Nexus-style `/cgi-bin/control.cgi`
/// endpoint (used by the EV-7520 behind a Nexus encoder). `position` is the
/// raw integer the web UI emits — 0 = Wide end, 31424 = Telephoto end for
/// this hardware. The frontend maps its 0–100% slider into that range.
#[tauri::command]
pub async fn control_cgi_zoom_direct(
    target: CameraTarget,
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    position: i32,
) -> Result<(), AppError> {
    let addr = parse_camera_ip(&target.ip)?;
    let url = format!("http://{}/cgi-bin/control.cgi", addr);
    let command = format!("zoom_direct {}", position);
    let form = [
        ("action", "CameraControl"),
        ("command", command.as_str()),
        ("cam_index", "1"),
    ];

    log::info!("control.cgi zoom_direct: position={} → {}", position, url);

    // One retry on transient TCP-level failures. The camera's single-
    // threaded HTTP server occasionally refuses new connections while
    // still executing a previous zoom command; a 250ms backoff gives it
    // time to become available again. HTTP error responses (4xx/5xx)
    // aren't retried — those indicate the camera actually answered and
    // rejected us, so retrying would just hammer it.
    let mut last_err: Option<reqwest::Error> = None;
    let mut target = target;
    for attempt in 0..2 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        let path = manager.camera_ready(&target, &config).await?;
        target = path.target.clone(); // freeze a legacy manual binding for every retry
        let client = crate::camera::flir_ptu::client(&path)?;
        match client
            .post(&url)
            .header("X-Requested-With", "XMLHttpRequest")
            .form(&form)
            .timeout(std::time::Duration::from_secs(3))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() && status.as_u16() != 204 {
                    return Err(AppError::Camera(format!(
                        "control.cgi returned HTTP {}",
                        status
                    )));
                }
                return Ok(());
            }
            Err(e) => {
                log::warn!("control.cgi attempt {} failed: {}", attempt + 1, e);
                last_err = Some(e);
            }
        }
    }

    Err(AppError::Camera(format!(
        "control.cgi request failed: {}",
        last_err.expect("loop always sets last_err on failure")
    )))
}

// ── Zoom position persistence ───────────────────────────────────────

/// Persist the last zoom slider percent (0–100) for the given camera IP.
/// Stored in `zoom_positions` so the slider can restore to the right spot
/// on the next launch even though the camera firmware doesn't expose a
/// working query endpoint. IP keys don't need validation — they're already
/// in our adopted/discovered set by the time the slider is in use.
#[tauri::command]
pub async fn set_zoom_position(
    config: State<'_, AppConfig>,
    camera_ip: String,
    percent: i32,
) -> Result<(), AppError> {
    config.update_zoom_position(camera_ip, percent)
}
