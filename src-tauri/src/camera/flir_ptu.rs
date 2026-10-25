//! FLIR PTU (Pan-Tilt Unit) HTTP API client.
//!
//! The FLIR PTU exposes a simple HTTP API at `POST /API/PTCmd`.
//! Commands are sent as form-encoded data and responses are JSON.

use crate::config::AppConfig;
use crate::network::{
    route::{CameraTarget, ReadyPath},
    NetworkManager,
};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

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
        config: &AppConfig,
        target: &CameraTarget,
        cmd: &str,
    ) -> Result<HashMap<String, String>, AppError> {
        let _guard = self.send_lock.lock().await;
        // Check after the FIFO wait, immediately before this request.
        let path = manager.camera_ready(target, config).await?;
        let client = client(&path)?;
        let response = send_command(
            &client,
            &format!("http://{}", path.target.ip),
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

/// Shared HTTP client — reused across all camera HTTP commands (PTU and
/// the Sony/Nexus CGI handlers) instead of building a fresh client per
/// call. `pub(crate)` so the CGI commands in `commands::camera` can share
/// it. A per-request `.timeout()` still applies on top of the client's.
pub(crate) fn client(path: &ReadyPath) -> Result<reqwest::Client, AppError> {
    type Cached = Option<(u32, std::net::Ipv4Addr, String, reqwest::Client)>;
    static CLIENT: OnceLock<Mutex<Cached>> = OnceLock::new();
    let mut cache = CLIENT
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if path.fence.is_stale() {
        return Err(AppError::Camera("Ethernet adapter changed".into()));
    }
    let identity = path.target.expected_mac.clone().unwrap_or_default();
    if let Some((index, source, mac, client)) = cache.as_ref() {
        if *index == path.index && *source == path.source && *mac == identity {
            return Ok(client.clone());
        }
    }
    let client = reqwest::Client::builder()
        .local_address(std::net::IpAddr::V4(path.source))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(3))
        .pool_max_idle_per_host(2)
        .build()
        .map_err(|e| AppError::Camera(format!("Failed to build bound HTTP client: {e}")))?;
    *cache = Some((path.index, path.source, identity, client.clone()));
    Ok(client)
}

/// Send a command to the FLIR PTU and return the JSON response.
///
/// `base_url` — e.g. `http://192.168.1.202`
/// `cmd`      — e.g. `PS=100&TS=0` or `PP&TP`
pub async fn send_command(
    client: &reqwest::Client,
    base_url: &str,
    cmd: &str,
) -> Result<HashMap<String, String>, AppError> {
    let url = format!("{}/API/PTCmd", base_url.trim_end_matches('/'));

    let resp = client
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

    #[tokio::test]
    async fn bound_client_rebuilds_on_source_change_and_blocks_redirects() {
        use super::*;
        use std::sync::{
            atomic::{AtomicBool, AtomicU64},
            Arc,
        };
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let epoch = Arc::new(AtomicU64::new(1));
        let active = Arc::new(AtomicBool::new(true));
        let mut path = ReadyPath {
            target: CameraTarget {
                key: "aa:bb:cc:dd:ee:01".into(),
                expected_mac: Some("aa:bb:cc:dd:ee:01".into()),
                ip: "127.0.0.1".into(),
            },
            source: "127.0.0.2".parse().unwrap(),
            index: 1,
            fence: crate::network::SweepFence::new(1, epoch, active.clone()),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let redirect = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let location = redirect.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut peers = Vec::new();
            for _ in 0..2 {
                let (mut socket, peer) = listener.accept().await.unwrap();
                peers.push(peer.ip());
                let mut request = [0; 1024];
                assert!(socket.read(&mut request).await.unwrap() > 0);
                socket.write_all(format!("HTTP/1.1 302 Found\r\nLocation: http://{location}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            }
            peers
        });
        for source in ["127.0.0.2", "127.0.0.1"] {
            path.source = source.parse().unwrap();
            assert_eq!(
                client(&path)
                    .unwrap()
                    .get(format!("http://{address}/"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                302
            );
        }
        assert_eq!(
            server.await.unwrap(),
            vec![
                "127.0.0.2".parse::<std::net::IpAddr>().unwrap(),
                "127.0.0.1".parse().unwrap()
            ]
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), redirect.accept())
                .await
                .is_err()
        );
        active.store(false, std::sync::atomic::Ordering::Release);
        assert!(client(&path).is_err());
    }

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
