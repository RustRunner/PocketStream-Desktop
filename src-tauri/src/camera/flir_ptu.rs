//! FLIR PTU (Pan-Tilt Unit) HTTP API client.
//!
//! The FLIR PTU exposes a simple HTTP API at `POST /API/PTCmd`.
//! Commands are sent as form-encoded data and responses are JSON.

use crate::network::{
    bound_http,
    route::{CameraTarget, ReadyPath},
    NetworkManager,
};
use std::collections::HashMap;

use crate::error::AppError;

/// Backend-owned PTU command gateway. Serializes every PTU send behind a
/// mutex so no two commands ever interleave at the wire — the ordering
/// guarantee enforced at the trust boundary, independent of the
/// frontend's own queue (which stays as belt-and-braces). Also normalizes
/// speed commands for mode safety before they leave.
#[derive(Default)]
pub struct PtuController {
    send_lock: tokio::sync::Mutex<()>,
}

impl PtuController {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize and send one PTU command. Held for the whole HTTP
    /// round-trip so commands complete in acquisition order and a stop
    /// can never overtake the move it's meant to end.
    pub async fn send(
        &self,
        manager: &NetworkManager,
        target: &CameraTarget,
        cmd: &str,
    ) -> Result<HashMap<String, String>, AppError> {
        let _guard = self.send_lock.lock().await;
        // Check after the FIFO wait, immediately before this request.
        let readiness = manager.readiness();
        let path = readiness.bound_now(target)?;
        let response = send_command(
            &path,
            || readiness.bound_now(&path.target),
            &normalize_ptu_cmd(cmd),
        )
        .await?;
        // Retain numeric readback only, never arbitrary device response text or
        // command payloads. A successful HTTP request alone is not position proof.
        if cmd == "PP&TP" {
            if let (Some(pan), Some(tilt)) = (
                response.get("PP").and_then(|v| v.parse::<i32>().ok()),
                response.get("TP").and_then(|v| v.parse::<i32>().ok()),
            ) {
                log::info!(
                    "PTU position reply: target={} source={} interface_index={} pan={} tilt={}",
                    path.target.ip,
                    path.source,
                    path.index,
                    pan,
                    tilt
                );
            }
        }
        Ok(response)
    }
}

/// Mode-safety normalization: a speed command (`PS=`/`TS=`) that doesn't
/// itself select a mode gets a `C=V` (velocity) prefix, so it can never
/// drive the unit while it's in `C=I` absolute-positioning mode — the
/// documented runaway-pan case. Commands that already pick a mode (a
/// `C=V` velocity move, a `C=I` goto) and pure queries pass through
/// untouched. This backstops the frontend, which already prefixes.
fn normalize_ptu_cmd(cmd: &str) -> String {
    let has_speed = cmd.contains("PS=") || cmd.contains("TS=");
    let selects_mode = cmd.contains("C=");
    if has_speed && !selects_mode {
        format!("C=V&{}", cmd)
    } else {
        cmd.to_string()
    }
}

/// Send a command to the FLIR PTU and return the JSON response.
async fn send_command(
    path: &ReadyPath,
    ready: impl Fn() -> Result<ReadyPath, AppError>,
    cmd: &str,
) -> Result<HashMap<String, String>, AppError> {
    let resp = bound_http::post_form(path, ready, "/API/PTCmd", cmd.to_string(), &[])
        .await
        .map_err(|e| e.error)?;

    if !resp.status.is_success() {
        return Err(AppError::Camera(format!(
            "PTU returned HTTP {}",
            resp.status
        )));
    }

    serde_json::from_slice(&resp.body)
        .map_err(|e| AppError::Camera(format!("PTU JSON parse error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::normalize_ptu_cmd;

    #[test]
    fn bare_speed_command_gets_velocity_prefix() {
        assert_eq!(normalize_ptu_cmd("PS=100&TS=0"), "C=V&PS=100&TS=0");
        assert_eq!(normalize_ptu_cmd("TS=-100"), "C=V&TS=-100");
    }

    #[test]
    fn stop_command_gets_velocity_prefix() {
        assert_eq!(normalize_ptu_cmd("PS=0&TS=0"), "C=V&PS=0&TS=0");
    }

    #[test]
    fn already_velocity_prefixed_is_unchanged() {
        assert_eq!(normalize_ptu_cmd("C=V&PS=100&TS=0"), "C=V&PS=100&TS=0");
    }

    #[test]
    fn goto_command_is_unchanged() {
        // C=I absolute goto must keep its speed as-is — the prefix would
        // fight the deliberate positioning mode.
        let goto = "C=I&PS=100&TS=100&PP=0&TP=0";
        assert_eq!(normalize_ptu_cmd(goto), goto);
    }

    #[test]
    fn queries_pass_through() {
        assert_eq!(normalize_ptu_cmd("PP&TP"), "PP&TP");
        assert_eq!(normalize_ptu_cmd("PU&TU&PL&TL"), "PU&TU&PL&TL");
        assert_eq!(normalize_ptu_cmd("C=V"), "C=V");
    }
}
