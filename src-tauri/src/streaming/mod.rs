pub mod recorder;
pub mod rtsp_client;
pub mod rtsp_server;
pub mod video_embed;

use serde::Serialize;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};

use crate::config::{AppSettings, StreamProtocol};
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
    /// Bumped on every `stop_rtsp_server` (even when no server is stored).
    /// `start_rtsp_server` captures it before its slow interface enumeration
    /// and, under the storage lock, refuses to store if it changed — so a
    /// stop that races a start wins instead of leaving a zombie server the
    /// user asked not to run.
    rtsp_epoch: std::sync::atomic::AtomicU64,
}

/// What a running consumer is ingesting, captured at start time. The
/// double-bind guard compares "what's running" against "what's being
/// started" using this — re-deriving it from settings would be wrong,
/// since settings can change between the two starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceMode {
    Udp { port: u16 },
    Rtsp,
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
    /// Source the running playback was started with (None when idle).
    playback_source: Option<SourceMode>,
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
                playback_source: None,
            })),
            video_hwnd: Arc::new(std::sync::atomic::AtomicIsize::new(0)),
            status_tx: Arc::new(status_tx),
            rtsp_epoch: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Redact credentials from a URL (or any text containing one) for
    /// safe logging. Rewrites the first `://user:pass@` occurrence;
    /// that's sufficient for log lines and bus error/debug text, which
    /// carry at most the input URL.
    pub(crate) fn redact_url(url: &str) -> String {
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

    /// Build the input URL from current settings. Credentials are NOT
    /// embedded — they're carried separately and set as `rtspsrc`
    /// `user-id`/`user-pw` properties by the pipeline builders, which
    /// keeps a password containing `@`/`:`/`/` from producing a
    /// malformed URL and keeps credentials out of pipeline-string logs.
    fn build_input_url(settings: &AppSettings) -> Result<String, AppError> {
        match settings.stream.protocol {
            StreamProtocol::Udp => Ok(format!("udp://@:{}", settings.stream.udp_port)),
            StreamProtocol::Rtsp => {
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
                Ok(format!(
                    "rtsp://{}:{}{}",
                    settings.stream.camera_ip, settings.stream.rtsp_port, settings.stream.rtsp_path
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

        // Take the old pipeline (and any recording state) out under the
        // lock; do the slow GStreamer teardown outside it — same
        // discipline as stop_playback.
        let (old_pipeline, was_recording, old_rec_path) = {
            let mut state = self.state.lock().await;

            // Double-bind guard (checked before touching the old
            // pipeline, so a refused start leaves it running): on
            // Windows only one socket receives a unicast UDP datagram,
            // so preview and the restreamer ingesting the same port
            // means one of them silently gets nothing. The restreamer's
            // udpsrc binds lazily on first client connect, which is why
            // this is guarded at start time rather than probed.
            if settings.stream.protocol == StreamProtocol::Udp {
                let conflict = state.rtsp_server.as_ref().and_then(|s| s.udp_ingest_port())
                    == Some(settings.stream.udp_port);
                if conflict {
                    return Err(AppError::Stream(format!(
                        "UDP port {} is already claimed by the RTSP re-stream \
                         server — only one consumer can receive a UDP stream. \
                         Stop the RTSP server first, or switch the input to RTSP.",
                        settings.stream.udp_port
                    )));
                }
            }

            let was_recording = state.recording;
            state.recording = false;
            let rec_path = state.recording_path.take();
            (state.playback.take(), was_recording, rec_path)
        };

        if let Some(p) = old_pipeline {
            if was_recording {
                // Finalize the MP4 before killing the pipeline. Restart
                // while recording (reconnect path) used to drop the old
                // pipeline without detaching: the file lost everything
                // after its last fragment AND recording stayed true
                // against a pipeline with no recording bin, making the
                // next stop_recording fail too.
                if let Err(e) = p.detach_recording().await {
                    log::error!(
                        "Recording finalize during stream restart failed ({}): {}",
                        old_rec_path.as_deref().unwrap_or("unknown path"),
                        e
                    );
                }
            }
            if let Err(e) = p.stop() {
                log::warn!("Old pipeline stop during restart failed: {}", e);
            }
        }

        let pipeline = match settings.stream.protocol {
            StreamProtocol::Udp => {
                log::info!("Starting UDP playback on port {}", settings.stream.udp_port);
                PlaybackPipeline::new_udp(settings.stream.udp_port, window_handle)?
            }
            StreamProtocol::Rtsp => {
                let url = Self::build_input_url(settings)?;
                log::info!("Starting RTSP playback from: {}", Self::redact_url(&url));
                PlaybackPipeline::new_rtsp(
                    &url,
                    500,
                    true,
                    window_handle,
                    Some(settings.stream.camera_ip.clone()),
                    &settings.credentials.username,
                    &settings.credentials.password,
                )?
            }
        };

        pipeline.play()?;

        // Second lock acquisition (take-old above, store-new here). The
        // window between them is harmless today — the frontend
        // serializes stream starts — but concurrent starts would race
        // to store their pipeline; revisit if that assumption changes.
        {
            let mut state = self.state.lock().await;
            state.playback = Some(Arc::new(pipeline));
            state.start_time = Some(std::time::Instant::now());
            state.playback_source = Some(match settings.stream.protocol {
                StreamProtocol::Udp => SourceMode::Udp {
                    port: settings.stream.udp_port,
                },
                StreamProtocol::Rtsp => SourceMode::Rtsp,
            });
        }

        self.refresh_status().await;
        Ok(())
    }

    pub async fn stop_playback(&self) -> Result<(), AppError> {
        // Take everything out of state under the lock, then do the slow
        // GStreamer transitions outside it. The pipeline is owned (not
        // borrowed) by the time we await, so the lock can drop cleanly.
        let (pipeline, was_recording, rec_path) = {
            let mut state = self.state.lock().await;
            let was_recording = state.recording;
            let pb = state.playback.take();
            state.recording = false;
            let rec_path = state.recording_path.take();
            state.start_time = None;
            state.playback_source = None;
            (pb, was_recording, rec_path)
        };

        if let Some(p) = pipeline {
            if was_recording {
                // Must .await so the EOS flushes and the file finalizes.
                // The stop itself proceeds either way, but a finalize
                // failure names the file instead of vanishing silently.
                if let Err(e) = p.detach_recording().await {
                    log::error!(
                        "Recording finalize during stop failed ({}): {}",
                        rec_path.as_deref().unwrap_or("unknown path"),
                        e
                    );
                }
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
        adopted: &std::collections::HashSet<String>,
    ) -> Result<RtspServerInfo, AppError> {
        crate::ensure_gstreamer()?;

        let port = settings.rtsp_server.port;

        // Ensure firewall allows inbound TCP on the RTSP port.
        // Non-fatal — server still works on localhost if this fails.
        if let Err(e) = crate::network::firewall::ensure_rtsp_allowed(port) {
            log::warn!("Firewall setup: {}", e);
        }

        // Capture the stop epoch before any slow work. stop_rtsp_server bumps
        // it unconditionally, so if it changes before we store the new server
        // a stop raced us and must win (see the storage step below).
        let start_epoch = self.rtsp_epoch.load(std::sync::atomic::Ordering::Acquire);

        // Replace path: tear any existing server down fully (outside the
        // lock) before binding the new one — dropping it in place left the
        // port claimed by a socket whose loop was still running, so quick
        // restarts hit "port in use".
        let old_server = {
            let mut state = self.state.lock().await;
            state.rtsp_server.take()
        };
        if let Some(old) = old_server {
            old.shutdown().await;
        }

        let mount_path = format!("/stream-{}", settings.rtsp_server.token);

        // Resolve the bind address and the advertised IP BEFORE taking the
        // storage lock — both are full interface enumerations (PowerShell)
        // and must not run under self.state, which the 1 Hz status ticker and
        // every stop/refresh also lock (holding it across them stalls status).
        let bind_address = if settings.rtsp_server.bind_interface.is_empty() {
            None
        } else {
            let iface =
                crate::network::interface::get_by_name(&settings.rtsp_server.bind_interface)
                    .await?;
            // Never bind the socket to an adopted camera-network secondary or
            // an APIPA address — either puts the server on the wrong network.
            // Error clearly instead of silently binding wrong.
            let ip = first_usable_ip(&iface.ips, adopted).ok_or_else(|| {
                AppError::Stream(format!(
                    "Interface '{}' has no usable (non-adopted, non-APIPA) IPv4 address to bind",
                    settings.rtsp_server.bind_interface
                ))
            })?;
            Some(ip)
        };

        // Advertised URL: for an explicit bind, advertise that IP; otherwise
        // pick the best client-facing address (WiFi/VPN, non-adopted,
        // non-APIPA), falling back to any usable address so an Ethernet-only
        // host still advertises its native client IP, not the camera
        // secondary.
        let local_ip = match &bind_address {
            Some(ip) => ip.clone(),
            None => get_display_ip(adopted)
                .await
                .unwrap_or_else(|| "0.0.0.0".into()),
        };
        log::info!(
            "RTSP bind selection: bind={:?} advertise={}",
            bind_address,
            local_ip
        );

        // Double-bind guard, mirror of the one in start_playback: the
        // restreamer's UDP ingest must not claim the port the running preview
        // is already receiving on. Checked under a short lock, then released
        // before the synchronous server build.
        if settings.stream.protocol == StreamProtocol::Udp {
            let state = self.state.lock().await;
            if let Some(SourceMode::Udp { port: pb_port }) = state.playback_source {
                if pb_port == settings.stream.udp_port {
                    return Err(AppError::Stream(format!(
                        "UDP port {} is already claimed by the running preview — \
                         only one consumer can receive a UDP stream. Stop the \
                         stream first, or switch the input to RTSP.",
                        pb_port
                    )));
                }
            }
        }

        let server = match settings.stream.protocol {
            StreamProtocol::Udp => RtspRestreamer::start_from_udp(
                settings.stream.udp_port,
                port,
                &mount_path,
                bind_address.as_deref(),
            )?,
            StreamProtocol::Rtsp => {
                let input_url = Self::build_input_url(settings)?;
                RtspRestreamer::start_from_rtsp(
                    &input_url,
                    port,
                    &mount_path,
                    bind_address.as_deref(),
                    &settings.credentials.username,
                    &settings.credentials.password,
                )?
            }
        };

        // Store under the lock — but only if no stop raced us since
        // `start_epoch` (a concurrent stop bumps the epoch even during the
        // take-old window above, when no server is stored). If it changed the
        // user asked for no server: free the one we just built and report the
        // supersession rather than leaving a zombie.
        let mut state = self.state.lock().await;
        if self.rtsp_epoch.load(std::sync::atomic::Ordering::Acquire) != start_epoch {
            drop(state);
            log::info!("RTSP start superseded by a concurrent stop — discarding built server");
            server.shutdown().await;
            return Err(AppError::Stream(
                "RTSP server start was superseded by a stop".into(),
            ));
        }
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
        // Record stop intent unconditionally, even when no server is stored:
        // start_rtsp_server takes the old server out before its slow
        // enumeration, so during that window rtsp_server is None and a stop
        // here would otherwise be invisible to the late start — which would
        // then store a zombie. Bumping the epoch makes the start observe it.
        self.rtsp_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let server = {
            let mut state = self.state.lock().await;
            let server = state.rtsp_server.take();
            if server.is_some() {
                state.rtsp_start_time = None;
                state.rtsp_local_ip = None;
            }
            server
        };
        if let Some(server) = server {
            // Await the full teardown (sessions filtered while the loop
            // is alive, loop quit, thread joined with a bound) so a
            // quick stop→start can't hit "port in use" against the old
            // socket.
            server.shutdown().await;
            log::info!("RTSP server fully cleaned up");
        }
        log::info!("RTSP server stopped");
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

        let output_dir = dirs::picture_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("PocketStream");

        // pull_snapshot blocks up to 500ms on try_pull_sample and the
        // JPEG encode is CPU-bound — run both off the async worker.
        let path = tokio::task::spawn_blocking(move || {
            let (width, height, rgb_data) = pipeline.pull_snapshot()?;
            recorder::save_screenshot_jpg(&rgb_data, width, height, &output_dir)
        })
        .await
        .map_err(|e| AppError::Stream(format!("Screenshot task failed: {}", e)))??;

        Ok(path.to_string_lossy().to_string())
    }

    pub async fn start_recording(&self) -> Result<(), AppError> {
        // Path computation involves filesystem I/O — keep it outside
        // the lock.
        let output_dir = dirs::video_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("PocketStream");
        let path = recorder::recording_path(&output_dir)?;
        let path_str = path.to_string_lossy().to_string();

        // Reserve the recording slot under the lock so a concurrent
        // start errors out instead of double-attaching; roll back on
        // attach failure below.
        let pipeline = {
            let mut state = self.state.lock().await;

            if state.recording {
                return Err(AppError::Stream("Already recording".into()));
            }

            let pipeline = state
                .playback
                .as_ref()
                .ok_or_else(|| AppError::Stream("No active playback to record".into()))?
                .clone();

            state.recording = true;
            state.recording_path = Some(path_str.clone());
            pipeline
        };

        // GStreamer pad request/link/state ops outside the lock — the
        // one lock discipline for StreamManager (stop_playback is the
        // model).
        if let Err(e) = pipeline.attach_recording(&path_str) {
            let mut state = self.state.lock().await;
            state.recording = false;
            state.recording_path = None;
            drop(state);
            self.refresh_status().await;
            return Err(e);
        }

        self.refresh_status().await;
        Ok(())
    }

    pub async fn stop_recording(&self) -> Result<String, AppError> {
        // Snapshot under the lock but do NOT clear the recording state
        // yet: a failed detach used to leave recording=false with the
        // path gone — status lied and the path only lived in the log.
        // State is cleared only after the finalize succeeds.
        let (pipeline, path) = {
            let state = self.state.lock().await;

            if !state.recording {
                return Err(AppError::Stream("Not currently recording".into()));
            }

            let pipeline = state
                .playback
                .as_ref()
                .ok_or_else(|| AppError::Stream("No active playback".into()))?
                .clone();

            let path = state
                .recording_path
                .clone()
                .unwrap_or_else(|| "unknown".into());
            (pipeline, path)
        };

        if let Err(e) = pipeline.detach_recording().await {
            return Err(AppError::Stream(format!(
                "Failed to finalize recording {}: {}",
                path, e
            )));
        }

        {
            let mut state = self.state.lock().await;
            state.recording = false;
            state.recording_path = None;
        }

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

/// True if `addr` is an APIPA (169.254.0.0/16) address — a DHCP-failure
/// fallback that can't carry usable client traffic.
fn is_apipa(addr: &str) -> bool {
    addr.starts_with("169.254.")
}

/// First IPv4 on `ips` that is neither an adopted camera-network secondary
/// nor APIPA. `None` if the interface carries only such addresses — the
/// caller turns that into a clear error rather than binding the RTSP socket
/// to the camera network.
fn first_usable_ip(
    ips: &[crate::network::interface::IpInfo],
    adopted: &std::collections::HashSet<String>,
) -> Option<String> {
    ips.iter()
        .map(|ip| ip.address.clone())
        .find(|addr| !adopted.contains(addr) && !is_apipa(addr))
}

/// Best client-facing IPv4 to advertise when no explicit bind interface is
/// set: prefer a WiFi or VPN address (the camera occupies Ethernet), else
/// any up interface, always skipping adopted secondaries and APIPA. Returns
/// `None` only if nothing usable exists (caller advertises 0.0.0.0).
async fn get_display_ip(adopted: &std::collections::HashSet<String>) -> Option<String> {
    let interfaces = crate::network::interface::list_all().await.ok()?;

    // Prefer WiFi / VPN — a client-facing URL should advertise the WiFi or
    // VPN address when there is one, not the Ethernet camera network.
    let preferred = interfaces
        .iter()
        .filter(|i| i.is_up && (i.is_wifi || i.is_vpn))
        .flat_map(|i| &i.ips)
        .find(|ip| !adopted.contains(&ip.address) && !is_apipa(&ip.address))
        .map(|ip| ip.address.clone());
    if preferred.is_some() {
        return preferred;
    }

    // Fallback: any up interface's first usable address — covers an
    // Ethernet-only host, where the native client IP sits alongside the
    // adopted camera secondary and we must advertise the native one.
    interfaces
        .iter()
        .filter(|i| i.is_up)
        .flat_map(|i| &i.ips)
        .find(|ip| !adopted.contains(&ip.address) && !is_apipa(&ip.address))
        .map(|ip| ip.address.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    fn ip(addr: &str) -> crate::network::interface::IpInfo {
        crate::network::interface::IpInfo {
            address: addr.into(),
            prefix: 24,
            subnet: "0.0.0.0/24".into(),
        }
    }

    fn adopted_set(addrs: &[&str]) -> std::collections::HashSet<String> {
        addrs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn bind_ip_prefers_native_over_adopted() {
        // Interface carries a native client IP and an adopted camera
        // secondary — the native must be chosen for the socket bind.
        let ips = vec![ip("192.168.1.50"), ip("10.20.30.100")];
        let adopted = adopted_set(&["10.20.30.100"]);
        assert_eq!(
            first_usable_ip(&ips, &adopted).as_deref(),
            Some("192.168.1.50")
        );
    }

    #[test]
    fn bind_ip_none_when_only_adopted() {
        // Only an adopted secondary — no usable bind IP, so the caller errors
        // instead of binding to the camera network.
        let ips = vec![ip("10.20.30.100")];
        let adopted = adopted_set(&["10.20.30.100"]);
        assert!(first_usable_ip(&ips, &adopted).is_none());
    }

    #[test]
    fn bind_ip_skips_apipa_but_takes_real_ip() {
        let adopted = adopted_set(&[]);
        // APIPA is never selected when a real, non-adopted IP exists...
        let mixed = vec![ip("169.254.5.5"), ip("192.168.1.50")];
        assert_eq!(
            first_usable_ip(&mixed, &adopted).as_deref(),
            Some("192.168.1.50")
        );
        // ...and an APIPA-only interface yields nothing usable.
        let apipa_only = vec![ip("169.254.5.5")];
        assert!(first_usable_ip(&apipa_only, &adopted).is_none());
    }

    fn make_settings(
        protocol: StreamProtocol,
        camera_ip: &str,
        username: &str,
        password: &str,
    ) -> AppSettings {
        AppSettings {
            stream: StreamConfig {
                protocol,
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

    #[test]
    fn redact_url_embedded_in_bus_debug_text() {
        // Bus error/debug payloads replay the input URL mid-sentence;
        // redaction must work there, not just on bare URLs.
        let text = "gstrtspsrc.c:1234: could not connect to rtsp://admin:hunter2@10.0.0.5:554/live (timeout)";
        let redacted = StreamManager::redact_url(text);
        assert!(!redacted.contains("hunter2"));
        assert!(redacted.contains("rtsp://admin:***@10.0.0.5:554/live"));
    }

    // ── build_input_url ─────────────────────────────────────────────

    #[test]
    fn build_url_rtsp_omits_credentials() {
        // Credentials are carried via rtspsrc user-id/user-pw now, never
        // embedded — so a password with URL-special characters can't
        // produce a malformed URL, and creds stay out of pipeline logs.
        let s = make_settings(StreamProtocol::Rtsp, "192.168.1.10", "admin", "p@ss:w/rd");
        let url = StreamManager::build_input_url(&s).unwrap();
        assert_eq!(url, "rtsp://192.168.1.10:554/live");
        assert!(!url.contains("admin"));
        assert!(!url.contains("p@ss"));
    }

    #[test]
    fn build_url_rtsp_without_credentials() {
        let s = make_settings(StreamProtocol::Rtsp, "192.168.1.10", "", "");
        let url = StreamManager::build_input_url(&s).unwrap();
        assert_eq!(url, "rtsp://192.168.1.10:554/live");
    }

    #[test]
    fn build_url_udp() {
        let s = make_settings(StreamProtocol::Udp, "", "", "");
        let url = StreamManager::build_input_url(&s).unwrap();
        assert_eq!(url, "udp://@:8600");
    }

    #[test]
    fn build_url_udp_ignores_camera_ip() {
        let s = make_settings(StreamProtocol::Udp, "192.168.1.1", "admin", "pass");
        let url = StreamManager::build_input_url(&s).unwrap();
        assert_eq!(url, "udp://@:8600");
    }

    #[test]
    fn build_url_custom_port_and_path() {
        let mut s = make_settings(StreamProtocol::Rtsp, "10.0.0.5", "", "");
        s.stream.rtsp_port = 8554;
        s.stream.rtsp_path = "/cam1/main".into();
        let url = StreamManager::build_input_url(&s).unwrap();
        assert_eq!(url, "rtsp://10.0.0.5:8554/cam1/main");
    }

    #[test]
    fn build_url_custom_udp_port() {
        let mut s = make_settings(StreamProtocol::Udp, "", "", "");
        s.stream.udp_port = 9999;
        let url = StreamManager::build_input_url(&s).unwrap();
        assert_eq!(url, "udp://@:9999");
    }

    #[test]
    fn build_url_rejects_invalid_camera_ip() {
        let s = make_settings(StreamProtocol::Rtsp, "not-an-ip", "", "");
        assert!(StreamManager::build_input_url(&s).is_err());
    }

    #[test]
    fn build_url_rejects_pipeline_injection_in_ip() {
        let s = make_settings(
            StreamProtocol::Rtsp,
            "192.168.1.1 ! filesrc location=/etc/passwd",
            "",
            "",
        );
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
