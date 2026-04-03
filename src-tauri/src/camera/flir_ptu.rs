//! FLIR PTU (Pan-Tilt Unit) HTTP API client.
//!
//! The FLIR PTU exposes a simple HTTP API at `POST /API/PTCmd`.
//! Commands are sent as form-encoded data and responses are JSON.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::error::AppError;

/// Shared HTTP client — reused across all PTU commands.
fn client() -> Result<&'static reqwest::Client, AppError> {
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
        .map_err(|e| AppError::Stream(e.clone()))
}

/// Send a command to the FLIR PTU and return the JSON response.
///
/// `base_url` — e.g. `http://192.168.1.202`
/// `cmd`      — e.g. `PS=100&TS=0` or `PP&TP`
pub async fn send_command(
    base_url: &str,
    cmd: &str,
) -> Result<HashMap<String, String>, AppError> {
    let url = format!("{}/API/PTCmd", base_url.trim_end_matches('/'));

    let resp = client()?
        .post(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(cmd.to_string())
        .send()
        .await
        .map_err(|e| AppError::Stream(format!("PTU request failed: {}", e)))?;

    if !resp.status().is_success() {
        return Err(AppError::Stream(format!(
            "PTU returned HTTP {}",
            resp.status()
        )));
    }

    let json: HashMap<String, String> = resp
        .json()
        .await
        .map_err(|e| AppError::Stream(format!("PTU JSON parse error: {}", e)))?;

    Ok(json)
}
