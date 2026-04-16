//! PTZ (Pan-Tilt-Zoom) control via ONVIF.
//!
//! Supports:
//! - Continuous move (pan/tilt/zoom with velocity)
//! - Stop movement
//! - Go to preset position
//! - Set/save preset positions
//!
//! # ONVIF PTZ SOAP Operations
//!
//! - ContinuousMove: Move camera at specified velocity
//! - Stop: Stop all PTZ movement
//! - GotoPreset: Move to a saved preset position
//! - SetPreset: Save current position as a preset
//! - GetPresets: List all saved presets
//!
//! # SECURITY — validate `camera_url` before adding HTTP client calls
//!
//! These functions are stubs today (`log::info!` only). When the SOAP
//! client lands, every function below MUST validate `camera_url` before
//! making any outbound request, or this becomes an SSRF vector reachable
//! from the IPC surface. Recommended check:
//!
//!   1. Parse with `url::Url`; reject if not http/https.
//!   2. Extract host; require it parses as `Ipv4Addr`.
//!   3. Reject loopback / link-local / broadcast / unspecified
//!      (mirror `commands::ptu_send` and `commands::sony_cgi_zoom`).
//!
//! If ONVIF discovery surfaces hostname-based `<XAddr>` URLs, the host
//! check needs to be revisited (resolve first, then validate the
//! resolved IP — don't blindly trust DNS).

use crate::camera::PtzPreset;
use crate::error::AppError;

/// Move the camera continuously at the given velocity.
///
/// - `pan`: -1.0 (left) to 1.0 (right)
/// - `tilt`: -1.0 (down) to 1.0 (up)
/// - `zoom`: -1.0 (out) to 1.0 (in)
pub async fn continuous_move(
    camera_url: &str,
    pan: f64,
    tilt: f64,
    zoom: f64,
) -> Result<(), AppError> {
    let pan = pan.clamp(-1.0, 1.0);
    let tilt = tilt.clamp(-1.0, 1.0);
    let zoom = zoom.clamp(-1.0, 1.0);

    log::info!(
        "PTZ move: pan={:.2}, tilt={:.2}, zoom={:.2} → {}",
        pan,
        tilt,
        zoom,
        camera_url
    );

    // TODO: Send ONVIF ContinuousMove SOAP request
    //
    // <ContinuousMove xmlns="http://www.onvif.org/ver20/ptz/wsdl">
    //   <ProfileToken>profile_token</ProfileToken>
    //   <Velocity>
    //     <PanTilt x="{pan}" y="{tilt}" xmlns="http://www.onvif.org/ver10/schema"/>
    //     <Zoom x="{zoom}" xmlns="http://www.onvif.org/ver10/schema"/>
    //   </Velocity>
    // </ContinuousMove>

    Ok(())
}

/// Stop all PTZ movement.
pub async fn stop(camera_url: &str) -> Result<(), AppError> {
    log::info!("PTZ stop → {}", camera_url);

    // TODO: Send ONVIF Stop SOAP request
    //
    // <Stop xmlns="http://www.onvif.org/ver20/ptz/wsdl">
    //   <ProfileToken>profile_token</ProfileToken>
    //   <PanTilt>true</PanTilt>
    //   <Zoom>true</Zoom>
    // </Stop>

    Ok(())
}

/// Move camera to a saved preset position.
pub async fn goto_preset(camera_url: &str, preset: u32) -> Result<(), AppError> {
    log::info!("PTZ goto preset {} → {}", preset, camera_url);

    // TODO: Send ONVIF GotoPreset SOAP request
    //
    // <GotoPreset xmlns="http://www.onvif.org/ver20/ptz/wsdl">
    //   <ProfileToken>profile_token</ProfileToken>
    //   <PresetToken>{preset}</PresetToken>
    // </GotoPreset>

    Ok(())
}

/// Save the current camera position as a preset.
pub async fn set_preset(camera_url: &str, preset: u32, name: &str) -> Result<(), AppError> {
    log::info!("PTZ set preset {} ('{}') → {}", preset, name, camera_url);

    // TODO: Send ONVIF SetPreset SOAP request
    //
    // <SetPreset xmlns="http://www.onvif.org/ver20/ptz/wsdl">
    //   <ProfileToken>profile_token</ProfileToken>
    //   <PresetName>{name}</PresetName>
    //   <PresetToken>{preset}</PresetToken>
    // </SetPreset>

    Ok(())
}

/// List all saved presets on the camera.
#[allow(dead_code)]
pub async fn get_presets(camera_url: &str) -> Result<Vec<PtzPreset>, AppError> {
    log::info!("PTZ get presets → {}", camera_url);

    // TODO: Send ONVIF GetPresets SOAP request

    Ok(vec![])
}
