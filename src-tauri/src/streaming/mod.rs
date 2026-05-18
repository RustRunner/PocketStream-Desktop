pub mod recorder;
pub mod rtsp_client;
pub mod rtsp_server;
pub mod video_embed;

use serde::Serialize;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};

use crate::config::AppSettings;
use crate::error::AppError;

#[derive(Debug, Clone, Serialize)]
pub struct RtspServerInfo {
    pub rtsp_url: String,
    pub display_url: String,
}

use rtsp_client::PlaybackPipeline;
use rtsp_server::RtspRestreamer;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StreamStatus {
    pub playing: bool,
    pub rtsp_server_running: bool,
    pub rtsp_url: Option<String>,
    pub display_url: Option<String>,
    pub recording: bool,
    pub uptime_secs: u64,
    pub bandwidth_kbps: f64,
    pub error: Option<String>,
}

impl StreamStatus {
    fn idle() -> Self {
        Self {
            playing: false,
            rtsp_server_running: false,
            rtsp_url: None,
            display_url: None,
            recording: false,
            uptime_secs: 0,
            bandwidth_kbps: 0.0,
            error: None,
        }
    }
}

pub struct StreamManager {
    state: Arc<Mutex<StreamState>>,
    video_hwnd: Arc<std::sync::atomic::AtomicIsize>,
    status_tx: Arc<watch::Sender<StreamStatus>>,
}

struct StreamState {
    playback: Option<Arc<PlaybackPipeline>>,
    rtsp_server: Option<RtspRestreamer>,
    recording: bool,
    recording_path: Option<String>,
    start_time: Option<std::time::Instant>,
    rtsp_start_time: Option<std::time::Instant>,
    /// Cached IP resolved at RTSP server start — avoids running PowerShell every poll.
    rtsp_local_ip: Option<String>,
}

impl StreamManager {
    pub fn new() -> Self {
        let (status_tx, _) = watch::channel(StreamStatus::idle());
        Self {
            state: Arc::new(Mutex::new(StreamState {
                playback: None,
                rtsp_server: None,
                recording: false,
                recording_path: None,
                start_time: None,
                rtsp_start_time: None,
                rtsp_local_ip: None,
            })),
            video_hwnd: Arc::new(std::sync::atomic::AtomicIsize::new(0)),
            status_tx: Arc::new(status_tx),
        }
    }

    /// Redact credentials from a URL for safe logging.
    fn redact_url(url: &str) -> String {
        // rtsp://user:pass@host → rtsp://user:***@host
        // Only match when credentials appear between "://" and "@"
        let scheme_end = match url.find("://") {
            Some(i) => i + 3,
            None => return url.to_string(),
        };
        let authority = &url[scheme_end..];
        if let Some(at) = authority.find('@') {
            if let Some(colon) = authority[..at].find(':') {
                let mut redacted = String::with_capacity(url.len());
                redacted.push_str(&url[..scheme_end + colon + 1]);
                redacted.push_str("***");
                redacted.push_str(&url[scheme_end + at..]);
                return redacted;
            }
        }
        url.to_string()
    }

    /// Build the input URL from current settings.
    fn build_input_url(settings: &AppSettings) -> Result<String, AppError> {
        match settings.stream.protocol.as_str() {
            "udp" => Ok(format!("udp://@:{}", settings.stream.udp_port)),
            _ => {
                // Validate camera IP before building URL (defense in depth)
                if !settings.stream.camera_ip.is_empty() {
                    settings
                        .stream
                        .camera_ip
                        .parse::<std::net::Ipv4Addr>()
                        .map_err(|_| {
                            AppError::Stream(format!(
                                "Invalid camera IP: {}",
                                settings.stream.camera_ip
                            ))
                        })?;
                }
                let creds = if !settings.credentials.username.is_empty() {
                    format!(
                        "{}:{}@",
                        settings.credentials.username, settings.credentials.password
                    )
                } else {
                    String::new()
                };
                Ok(format!(
                    "rtsp://{}{}:{}{}",
                    creds,
                    settings.stream.camera_ip,
                    settings.stream.rtsp_port,
                    settings.stream.rtsp_path
                ))
            }
        }
    }

    pub async fn start_playback(
        &self,
        settings: &AppSettings,
        window_handle: Option<usize>,
    ) -> Result<(), AppError> {
        // GStreamer init runs in a background thread at startup; block here
        // until it's ready (usually instant, only slow on first cold launch).
        crate::ensure_gstreamer()?;

        let mut state = self.state.lock().await;

        // Stop existing playback if any
        if let Some(pipeline) = state.playback.take() {
            let _ = pipeline.stop();
        }

        let pipeline = match settings.stream.protocol.as_str() {
            "udp" => {
                log::info!("Starting UDP playback on port {}", settings.stream.udp_port);
                PlaybackPipeline::new_udp(settings.stream.udp_port, window_handle)?
            }
            _ => {
                let url = Self::build_input_url(settings)?;
                log::info!("Starting RTSP playback from: {}", Self::redact_url(&url));
                PlaybackPipeline::new_rtsp(
                    &url,
                    500,
                    true,
                    window_handle,
                    Some(settings.stream.camera_ip.clone()),
                )?
            }
        };

        pipeline.play()?;
        state.playback = Some(Arc::new(pipeline));
        state.start_time = Some(std::time::Instant::now());

        drop(state);
        self.refresh_status().await;
        Ok(())
    }

    pub async fn stop_playback(&self) -> Result<(), AppError> {
        // Take everything out of state under the lock, then do the slow
        // GStreamer transitions outside it. The pipeline is owned (not
        // borrowed) by the time we await, so the lock can drop cleanly.
        let (pipeline, was_recording) = {
            let mut state = self.state.lock().await;
            let was_recording = state.recording;
            let pb = state.playback.take();
            state.recording = false;
            state.recording_path = None;
            state.start_time = None;
            (pb, was_recording)
        };

        if let Some(p) = pipeline {
            if was_recording {
                // Must .await so the EOS flushes and the MP4 moov atom is written.
                let _ = p.detach_recording().await;
            }
            p.stop()?;
        }

        // Clear HWND — actual window destruction handled by the command layer
        // on the main thread to avoid cross-thread DestroyWindow hangs.
        self.clear_video_child_hwnd();
        self.refresh_status().await;

        Ok(())
    }

    pub async fn start_rtsp_server(
        &self,
        settings: &AppSettings,
    ) -> Result<RtspServerInfo, AppError> {
        crate::ensure_gstreamer()?;

        let port = settings.rtsp_server.port;

        // Ensure firewall allows inbound TCP on the RTSP port.
        // Non-fatal — server still works on localhost if this fails.
        if let Err(e) = crate::network::firewall::ensure_rtsp_allowed(port) {
            log::warn!("Firewall setup: {}", e);
        }

        let mut state = self.state.lock().await;

        // Stop existing server if any
        state.rtsp_server = None;
        let mount_path = format!("/stream-{}", settings.rtsp_server.token);

        // Resolve bind interface to an IP address
        let bind_address = if settings.rtsp_server.bind_interface.is_empty() {
            None
        } else {
            let iface =
                crate::network::interface::get_by_name(&settings.rtsp_server.bind_interface)?;
            let ip = iface
                .ips
                .first()
                .map(|ip| ip.address.clone())
                .ok_or_else(|| {
                    AppError::Stream(format!(
                        "Interface '{}' has no IPv4 address",
                        settings.rtsp_server.bind_interface
                    ))
                })?;
            Some(ip)
        };

        let server = match settings.stream.protocol.as_str() {
            "udp" => RtspRestreamer::start_from_udp(
                settings.stream.udp_port,
                port,
                &mount_path,
                bind_address.as_deref(),
            )?,
            _ => {
                let input_url = Self::build_input_url(settings)?;
                RtspRestreamer::start_from_rtsp(
                    &input_url,
                    port,
                    &mount_path,
                    bind_address.as_deref(),
                )?
            }
        };

        // Use bind address for client URL if set, otherwise detect local IP
        let local_ip =
            bind_address.unwrap_or_else(|| get_local_ip().unwrap_or_else(|| "0.0.0.0".into()));
        let info = RtspServerInfo {
            rtsp_url: server.client_url(&local_ip),
            display_url: server.display_url(&local_ip),
        };

        state.rtsp_server = Some(server);
        state.rtsp_start_time = Some(std::time::Instant::now());
        state.rtsp_local_ip = Some(local_ip);

        drop(state);
        self.refresh_status().await;
        Ok(info)
    }

    pub async fn stop_rtsp_server(&self) -> Result<(), AppError> {
        let mut state = self.state.lock().await;
        if let Some(server) = state.rtsp_server.take() {
            state.rtsp_start_time = None;
            state.rtsp_local_ip = None;
            // Drop the server in a blocking thread so GLib cleanup
            // (closing active RTSP sessions) doesn't block the async runtime.
            tokio::task::spawn_blocking(move || {
                drop(server);
                log::info!("RTSP server fully cleaned up");
            });
        }
        log::info!("RTSP server stopped");
        drop(state);
        self.refresh_status().await;
        Ok(())
    }

    /// Recompute status from internal state and publish to subscribers.
    /// Called after every command-side mutation, plus on the 1Hz ticker
    /// for uptime / bandwidth refresh.
    async fn refresh_status(&self) {
        let snapshot = compute_status(&self.state).await;
        self.status_tx.send_if_modified(|cur| {
            if *cur == snapshot {
                false
            } else {
                *cur = snapshot;
                true
            }
        });
    }

    /// Spawn the status ticker (1Hz refresh of uptime/bandwidth/health)
    /// and the broadcaster (emit `stream-status` to the frontend on every
    /// change). Idempotent only in the sense that the watch's
    /// `send_if_modified` deduplicates — calling twice would spawn two
    /// tickers, so call exactly once at app startup.
    ///
    /// Uses `tauri::async_runtime::spawn` rather than `tokio::spawn`
    /// because Tauri's `setup` hook runs on the main thread before any
    /// tokio runtime is bound to the current thread; a bare `tokio::spawn`
    /// here panics with "no reactor running."
    pub fn start_status_emitter(&self, handle: tauri::AppHandle) {
        let state_for_tick = self.state.clone();
        let tx_for_tick = self.status_tx.clone();
        tauri::async_runtime::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let snap = compute_status(&state_for_tick).await;
                tx_for_tick.send_if_modified(|cur| {
                    if *cur == snap {
                        false
                    } else {
                        *cur = snap;
                        true
                    }
                });
            }
        });

        let mut rx = self.status_tx.subscribe();
        tauri::async_runtime::spawn(async move {
            use tauri::Emitter;
            while rx.changed().await.is_ok() {
                let snap = rx.borrow().clone();
                let _ = handle.emit("stream-status", &snap);
            }
        });
    }

    pub async fn take_screenshot(&self) -> Result<String, AppError> {
        let pipeline = {
            let state = self.state.lock().await;
            state
                .playback
                .as_ref()
                .ok_or_else(|| AppError::Stream("No active playback for screenshot".into()))?
                .clone()
        };

        let (width, height, rgb_data) = pipeline.pull_snapshot()?;

        let output_dir = dirs::picture_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("PocketStream");

        let path = recorder::save_screenshot_jpg(&rgb_data, width, height, &output_dir)?;

        Ok(path.to_string_lossy().to_string())
    }

    pub async fn start_recording(&self) -> Result<(), AppError> {
        {
            let mut state = self.state.lock().await;

            if state.recording {
                return Err(AppError::Stream("Already recording".into()));
            }

            let pipeline = state
                .playback
                .as_ref()
                .ok_or_else(|| AppError::Stream("No active playback to record".into()))?
                .clone();

            let output_dir = dirs::video_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("PocketStream");

            let path = recorder::recording_path(&output_dir)?;
            let path_str = path.to_string_lossy().to_string();

            pipeline.attach_recording(&path_str)?;
            state.recording = true;
            state.recording_path = Some(path_str);
        }

        self.refresh_status().await;
        Ok(())
    }

    pub async fn stop_recording(&self) -> Result<String, AppError> {
        // Clone the pipeline Arc and capture path under the lock, then
        // drop the lock before awaiting on the slow EOS flush.
        let (pipeline, path) = {
            let mut state = self.state.lock().await;

            if !state.recording {
                return Err(AppError::Stream("Not currently recording".into()));
            }

            let pipeline = state
                .playback
                .as_ref()
                .ok_or_else(|| AppError::Stream("No active playback".into()))?
                .clone();

            state.recording = false;
            let path = state
                .recording_path
                .take()
                .unwrap_or_else(|| "unknown".into());
            (pipeline, path)
        };

        pipeline.detach_recording().await?;

        log::info!("Recording saved: {}", path);
        self.refresh_status().await;
        Ok(path)
    }

    #[allow(dead_code)] // called from commands.rs behind #[cfg(windows)]
    pub fn set_video_child_hwnd(&self, hwnd: isize) {
        self.video_hwnd
            .store(hwnd, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn get_video_child_hwnd(&self) -> Option<isize> {
        let val = self.video_hwnd.load(std::sync::atomic::Ordering::Relaxed);
        if val == 0 {
            None
        } else {
            Some(val)
        }
    }

    pub fn clear_video_child_hwnd(&self) {
        self.video_hwnd
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Compute a status snapshot from the underlying state. Lifted out of
/// `StreamManager` so the background ticker can call it without holding
/// a `StreamManager` reference (it only needs the state Arc).
async fn compute_status(state: &Arc<Mutex<StreamState>>) -> StreamStatus {
    let state = state.lock().await;
    let uptime = state
        .rtsp_start_time
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);

    let cached_ip = state.rtsp_local_ip.as_deref().unwrap_or("0.0.0.0");
    let bandwidth = state
        .rtsp_server
        .as_ref()
        .map(|s| s.bandwidth_kbps())
        .unwrap_or(0.0);

    let (playing, error) = match state.playback.as_ref() {
        Some(p) => match p.health_check() {
            Ok(healthy) => (healthy, None),
            Err(msg) => (false, Some(msg)),
        },
        None => (false, None),
    };

    StreamStatus {
        playing,
        rtsp_server_running: state.rtsp_server.is_some(),
        rtsp_url: state.rtsp_server.as_ref().map(|s| s.client_url(cached_ip)),
        display_url: state.rtsp_server.as_ref().map(|s| s.display_url(cached_ip)),
        recording: state.recording,
        uptime_secs: uptime,
        bandwidth_kbps: bandwidth,
        error,
    }
}

/// Get the local WiFi IPv4 address (preferred), falling back to any non-VPN interface.
///
/// The camera occupies the Ethernet port, so the RTSP server should bind to
/// WiFi or a VPN-over-WiFi interface for local network streaming.
fn get_local_ip() -> Option<String> {
    let interfaces = crate::network::interface::list_all().ok()?;

    // Prefer WiFi interfaces first
    let wifi_ip = interfaces
        .iter()
        .filter(|i| i.is_up && i.is_wifi && !i.is_vpn)
        .flat_map(|i| &i.ips)
        .next()
        .map(|ip| ip.address.clone());

    if wifi_ip.is_some() {
        return wifi_ip;
    }

    // Fallback: any non-VPN interface with an IP
    interfaces
        .iter()
        .filter(|i| i.is_up && !i.is_vpn)
        .flat_map(|i| &i.ips)
        .next()
        .map(|ip| ip.address.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    fn make_settings(
        protocol: &str,
        camera_ip: &str,
        username: &str,
        password: &str,
    ) -> AppSettings {
        AppSettings {
            stream: StreamConfig {
                protocol: protocol.into(),
                rtsp_port: 554,
                rtsp_path: "/live".into(),
                udp_port: 8600,
                camera_ip: camera_ip.into(),
            },
            rtsp_server: RtspServerConfig {
                enabled: false,
                port: 8554,
                token: "testtoken".into(),
                bind_interface: String::new(),
            },
            credentials: Credentials {
                username: username.into(),
                password: password.into(),
            },
            adopted_subnets: std::collections::HashMap::new(),
            zoom_positions: std::collections::HashMap::new(),
            network_mode: NetworkMode::default(),
            manual_nodes: Vec::new(),
        }
    }

    // ── redact_url ─────────────────────────────────────────────────

    #[test]
    fn redact_url_with_credentials() {
        let url = "rtsp://admin:hunter2@192.168.1.50:554/live";
        assert_eq!(
            StreamManager::redact_url(url),
            "rtsp://admin:***@192.168.1.50:554/live"
        );
    }

    #[test]
    fn redact_url_without_credentials() {
        let url = "rtsp://192.168.1.50:554/live";
        assert_eq!(StreamManager::redact_url(url), url);
    }

    #[test]
    fn redact_url_empty_password() {
        let url = "rtsp://admin:@192.168.1.50:554/live";
        assert_eq!(
            StreamManager::redact_url(url),
            "rtsp://admin:***@192.168.1.50:554/live"
        );
    }

    #[test]
    fn redact_url_udp() {
        let url = "udp://@:8600";
        assert_eq!(StreamManager::redact_url(url), url);
    }

    // ── build_input_url ─────────────────────────────────────────────

    #[test]
    fn build_url_rtsp_with_credentials() {
        let s = make_settings("rtsp", "192.168.1.10", "admin", "pass123");
        let url = StreamManager::build_input_url(&s).unwrap();
        assert_eq!(url, "rtsp://admin:pass123@192.168.1.10:554/live");
    }

    #[test]
    fn build_url_rtsp_without_credentials() {
        let s = make_settings("rtsp", "192.168.1.10", "", "");
        let url = StreamManager::build_input_url(&s).unwrap();
        assert_eq!(url, "rtsp://192.168.1.10:554/live");
    }

    #[test]
    fn build_url_rtsp_empty_password_still_has_creds() {
        // If username is set but password is empty, creds block is still added
        let s = make_settings("rtsp", "10.0.0.5", "admin", "");
        let url = StreamManager::build_input_url(&s).unwrap();
        assert_eq!(url, "rtsp://admin:@10.0.0.5:554/live");
    }

    #[test]
    fn build_url_udp() {
        let s = make_settings("udp", "", "", "");
        let url = StreamManager::build_input_url(&s).unwrap();
        assert_eq!(url, "udp://@:8600");
    }

    #[test]
    fn build_url_udp_ignores_camera_ip() {
        let s = make_settings("udp", "192.168.1.1", "admin", "pass");
        let url = StreamManager::build_input_url(&s).unwrap();
        assert_eq!(url, "udp://@:8600");
    }

    #[test]
    fn build_url_custom_port_and_path() {
        let mut s = make_settings("rtsp", "10.0.0.5", "", "");
        s.stream.rtsp_port = 8554;
        s.stream.rtsp_path = "/cam1/main".into();
        let url = StreamManager::build_input_url(&s).unwrap();
        assert_eq!(url, "rtsp://10.0.0.5:8554/cam1/main");
    }

    #[test]
    fn build_url_custom_udp_port() {
        let mut s = make_settings("udp", "", "", "");
        s.stream.udp_port = 9999;
        let url = StreamManager::build_input_url(&s).unwrap();
        assert_eq!(url, "udp://@:9999");
    }

    #[test]
    fn build_url_unknown_protocol_falls_to_rtsp() {
        // Any non-"udp" protocol defaults to RTSP path
        let s = make_settings("http", "1.2.3.4", "", "");
        let url = StreamManager::build_input_url(&s).unwrap();
        assert!(url.starts_with("rtsp://"));
    }

    #[test]
    fn build_url_rejects_invalid_camera_ip() {
        let s = make_settings("rtsp", "not-an-ip", "", "");
        assert!(StreamManager::build_input_url(&s).is_err());
    }

    #[test]
    fn build_url_rejects_pipeline_injection_in_ip() {
        let s = make_settings("rtsp", "192.168.1.1 ! filesrc location=/etc/passwd", "", "");
        assert!(StreamManager::build_input_url(&s).is_err());
    }

    // ── StreamStatus ────────────────────────────────────────────────

    #[test]
    fn stream_status_serializes() {
        let status = StreamStatus {
            playing: true,
            rtsp_server_running: false,
            rtsp_url: Some("rtsp://127.0.0.1:8554/stream-abc".into()),
            display_url: Some("rtsp://127.0.0.1:8554".into()),
            recording: false,
            uptime_secs: 120,
            bandwidth_kbps: 0.0,
            error: None,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"playing\":true"));
        assert!(json.contains("\"uptime_secs\":120"));
        assert!(json.contains("\"display_url\":"));
    }

    #[test]
    fn stream_status_default_values() {
        let status = StreamStatus {
            playing: false,
            rtsp_server_running: false,
            rtsp_url: None,
            display_url: None,
            recording: false,
            uptime_secs: 0,
            bandwidth_kbps: 0.0,
            error: None,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"rtsp_url\":null"));
        assert!(json.contains("\"display_url\":null"));
    }

    // ── StreamManager ───────────────────────────────────────────────

    #[tokio::test]
    async fn stream_manager_initial_status() {
        let mgr = StreamManager::new();
        let status = mgr.status_tx.borrow().clone();
        assert!(!status.playing);
        assert!(!status.rtsp_server_running);
        assert!(!status.recording);
        assert_eq!(status.uptime_secs, 0);
        assert!(status.rtsp_url.is_none());
    }

    #[tokio::test]
    async fn refresh_status_updates_watch_channel() {
        let mgr = StreamManager::new();
        let mut rx = mgr.status_tx.subscribe();
        // Mark recording without going through start_recording so we can
        // verify refresh_status actually publishes the new state.
        {
            let mut state = mgr.state.lock().await;
            state.recording = true;
        }
        mgr.refresh_status().await;
        let snap = rx.borrow_and_update().clone();
        assert!(snap.recording);
    }

    #[tokio::test]
    async fn refresh_status_dedupes_identical_snapshots() {
        let mgr = StreamManager::new();
        let mut rx = mgr.status_tx.subscribe();
        // Drain initial value so `has_changed` reflects only post-init events.
        rx.borrow_and_update();
        mgr.refresh_status().await;
        // No mutation happened — snapshot is identical to the initial one,
        // so the watch channel must not have ticked.
        assert!(!rx.has_changed().unwrap());
    }

    #[test]
    fn stream_manager_video_hwnd_roundtrip() {
        let mgr = StreamManager::new();
        assert!(mgr.get_video_child_hwnd().is_none());
        mgr.set_video_child_hwnd(0x12345);
        assert_eq!(mgr.get_video_child_hwnd(), Some(0x12345));
    }
}
