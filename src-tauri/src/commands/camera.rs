//! Camera control IPC handlers — FLIR PTU, ONVIF/PTZ stubs, Sony CGI,
//! Nexus `control.cgi`, and zoom-position persistence.

use tauri::State;

use crate::config::AppConfig;
use crate::error::AppError;
use crate::network::NetworkManager;
use crate::validation::parse_known_camera_ip;

/// Resolve and validate a camera-control target. Camera-control commands
/// use the known-device validator so a FLIR that fell back to APIPA stays
/// controllable while it's discovered/adopted (see `parse_known_camera_ip`
/// for the exact conditions).
async fn control_target(
    ip: &str,
    manager: &NetworkManager,
) -> Result<std::net::Ipv4Addr, AppError> {
    let adopted: Vec<String> = manager.get_adopted_ips().await.into_keys().collect();
    parse_known_camera_ip(ip, &manager.registry(), &adopted)
}

// ── FLIR PTU ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn ptu_send(
    manager: State<'_, NetworkManager>,
    ptu: State<'_, crate::camera::flir_ptu::PtuController>,
    ip: String,
    cmd: String,
) -> Result<std::collections::HashMap<String, String>, AppError> {
    let addr = control_target(&ip, &manager).await?;
    let base_url = format!("http://{}", addr);
    // Route through the backend controller: serializes all PTU sends at
    // the trust boundary (no frontend path can interleave) and enforces
    // velocity mode on speed commands.
    ptu.send(&base_url, &cmd).await
}

// ── ONVIF / generic PTZ (stubs — return Err until implemented) ─────

#[tauri::command]
pub async fn discover_onvif(
    subnet: Option<String>,
) -> Result<Vec<crate::camera::OnvifDevice>, AppError> {
    crate::camera::onvif::discover(subnet.as_deref()).await
}

#[tauri::command]
pub async fn ptz_move(camera_url: String, pan: f64, tilt: f64, zoom: f64) -> Result<(), AppError> {
    crate::camera::ptz::continuous_move(&camera_url, pan, tilt, zoom).await
}

#[tauri::command]
pub async fn ptz_stop(camera_url: String) -> Result<(), AppError> {
    crate::camera::ptz::stop(&camera_url).await
}

#[tauri::command]
pub async fn ptz_goto_preset(camera_url: String, preset: u32) -> Result<(), AppError> {
    crate::camera::ptz::goto_preset(&camera_url, preset).await
}

#[tauri::command]
pub async fn ptz_set_preset(camera_url: String, preset: u32, name: String) -> Result<(), AppError> {
    crate::camera::ptz::set_preset(&camera_url, preset, &name).await
}

// ── Sony CGI ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn sony_cgi_zoom(
    manager: State<'_, NetworkManager>,
    ip: String,
    zoom_speed: i32,
    username: String,
    password: String,
) -> Result<(), AppError> {
    let addr = control_target(&ip, &manager).await?;

    let url = if zoom_speed == 0 {
        format!(
            "http://{}/command/ptzf.cgi?ContinuousPanTiltZoom=0,0,0",
            addr
        )
    } else {
        let speed = zoom_speed.clamp(-100, 100);
        format!(
            "http://{}/command/ptzf.cgi?ContinuousPanTiltZoom=0,0,{}",
            addr, speed
        )
    };

    log::info!("Sony CGI zoom: speed={} → {}", zoom_speed, url);

    let client = reqwest::Client::new();
    let mut req = client.get(&url);
    if !username.is_empty() {
        req = req.basic_auth(&username, Some(&password));
    }

    let resp = req
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await
        .map_err(|e| AppError::Camera(format!("Sony CGI request failed: {}", e)))?;

    let status = resp.status();
    if !status.is_success() && status.as_u16() != 204 {
        return Err(AppError::Camera(format!(
            "Sony CGI returned HTTP {}",
            status
        )));
    }

    Ok(())
}

// ── Nexus control.cgi ───────────────────────────────────────────────

/// Absolute-position zoom against a FLIR Nexus-style `/cgi-bin/control.cgi`
/// endpoint (used by the EV-7520 behind a Nexus encoder). `position` is the
/// raw integer the web UI emits — 0 = Wide end, 31424 = Telephoto end for
/// this hardware. The frontend maps its 0–100% slider into that range.
#[tauri::command]
pub async fn control_cgi_zoom_direct(
    manager: State<'_, NetworkManager>,
    ip: String,
    position: i32,
) -> Result<(), AppError> {
    let addr = control_target(&ip, &manager).await?;
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
    let client = reqwest::Client::new();
    let mut last_err: Option<reqwest::Error> = None;
    for attempt in 0..2 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
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

/// One-shot diagnostic: POSTs several plausible status-query bodies to the
/// camera and returns each probe's raw response, labelled. Used to figure
/// out which endpoint carries the current zoom position on this model so
/// we can wire up launch-time slider sync.
#[tauri::command]
pub async fn control_cgi_probe_status(
    manager: State<'_, NetworkManager>,
    ip: String,
) -> Result<String, AppError> {
    let addr = control_target(&ip, &manager).await?;
    let url = format!("http://{}/cgi-bin/control.cgi", addr);
    let client = reqwest::Client::new();

    // Small menu of queries the firmware might answer. The first one that
    // returns an integer in the 0..~31500 range is almost certainly the
    // zoom endpoint.
    let probes: &[&[(&str, &str)]] = &[
        &[("action", "GetStatus"), ("chn", "1")],
        &[("action", "GetStatus"), ("chn", "2")],
        &[("action", "GetStatus"), ("chn", "3")],
        &[("action", "GetStatus"), ("chn", "4")],
        &[("action", "GetCameraStatus"), ("cam_index", "1")],
        &[("action", "GetCameraInfo"), ("cam_index", "1")],
        &[
            ("action", "CameraControl"),
            ("command", "zoom_query"),
            ("cam_index", "1"),
        ],
        &[
            ("action", "CameraControl"),
            ("command", "get_zoom"),
            ("cam_index", "1"),
        ],
        &[
            ("action", "CameraControl"),
            ("command", "zoom_position"),
            ("cam_index", "1"),
        ],
        &[("action", "GetAll"), ("cam_index", "1")],
        &[("action", "GetConfig"), ("cam_index", "1")],
    ];

    let mut out = String::new();
    for form in probes {
        let body_summary = form
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        let resp = client
            .post(&url)
            .header("X-Requested-With", "XMLHttpRequest")
            .form(*form)
            .timeout(std::time::Duration::from_secs(3))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status();
                let text = r
                    .text()
                    .await
                    .unwrap_or_else(|e| format!("(body read err: {})", e));
                out.push_str(&format!(
                    "=== {} → HTTP {} ===\n{}\n\n",
                    body_summary, status, text
                ));
            }
            Err(e) => {
                out.push_str(&format!("=== {} → ERROR {} ===\n\n", body_summary, e));
            }
        }
    }

    log::info!("control.cgi probe_status result:\n{}", out);
    Ok(out)
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
