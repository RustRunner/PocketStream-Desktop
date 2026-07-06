//! FLIR PTU (Pan-Tilt Unit) HTTP API client.
//!
//! The FLIR PTU exposes a simple HTTP API at `POST /API/PTCmd`.
//! Commands are sent as form-encoded data and responses are JSON.

use std::collections::HashMap;
use std::sync::OnceLock;

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
        base_url: &str,
        cmd: &str,
    ) -> Result<HashMap<String, String>, AppError> {
        let _guard = self.send_lock.lock().await;
        send_command(base_url, &normalize_ptu_cmd(cmd)).await
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

/// Shared HTTP client — reused across all camera HTTP commands (PTU and
/// the Sony/Nexus CGI handlers) instead of building a fresh client per
/// call. `pub(crate)` so the CGI commands in `commands::camera` can share
/// it. A per-request `.timeout()` still applies on top of the client's.
pub(crate) fn client() -> Result<&'static reqwest::Client, AppError> {
    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(3))
                .pool_max_idle_per_host(2)
                .build()
                .map_err(|e| format!("Failed to build HTTP client: {}", e))
        })
        .as_ref()
        .map_err(|e| AppError::Camera(e.clone()))
}

/// Send a command to the FLIR PTU and return the JSON response.
///
/// `base_url` — e.g. `http://192.168.1.202`
/// `cmd`      — e.g. `PS=100&TS=0` or `PP&TP`
pub async fn send_command(base_url: &str, cmd: &str) -> Result<HashMap<String, String>, AppError> {
    let url = format!("{}/API/PTCmd", base_url.trim_end_matches('/'));

    let resp = client()?
        .post(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(cmd.to_string())
        .send()
        .await
        .map_err(|e| AppError::Camera(format!("PTU request failed: {}", e)))?;

    if !resp.status().is_success() {
        return Err(AppError::Camera(format!(
            "PTU returned HTTP {}",
            resp.status()
        )));
    }

    let json: HashMap<String, String> = resp
        .json()
        .await
        .map_err(|e| AppError::Camera(format!("PTU JSON parse error: {}", e)))?;

    Ok(json)
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
