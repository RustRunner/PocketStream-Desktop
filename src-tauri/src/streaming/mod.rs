pub mod audio;
mod classify;
pub mod recorder;
mod relay;
pub mod rtsp_client;
pub mod rtsp_server;
pub mod video_embed;

use serde::Serialize;
use std::sync::Arc;
use tokio::sync::{watch, Mutex, Notify};

use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_rtsp_server as gst_rtsp_server;
use gstreamer_rtsp_server::prelude::*;

use crate::config::{AppSettings, StreamProtocol};
use crate::error::AppError;
use crate::network::route::{CameraTarget, ReadyPath};

/// Apply the required receive policy to an `rtspsrc` that is constrained to
/// TCP transport.  `set_property` panics for a missing or mismatched property,
/// so validate both properties first and return a normal typed stream error on
/// an unsupported runtime.
pub(super) fn configure_tcp_rtspsrc(src: &gst::Element) -> Result<(), AppError> {
    for property in ["tcp-timestamp", "drop-on-latency"] {
        let spec = src.find_property(property).ok_or_else(|| {
            AppError::Stream(format!(
                "The bundled GStreamer runtime does not support rtspsrc property '{property}'"
            ))
        })?;
        if spec.value_type() != glib::Type::BOOL {
            return Err(AppError::Stream(format!(
                "GStreamer rtspsrc property '{property}' has unexpected type '{}' (expected boolean)",
                spec.value_type()
            )));
        }
    }

    src.set_property("tcp-timestamp", true);
    src.set_property("drop-on-latency", true);
    Ok(())
}

/// Redact both camera URL credentials and this relay's token-bearing mount
/// path before retaining or logging callback error text.
pub(super) fn redact_relay_text(text: &str, mount_path: &str) -> String {
    let redacted = StreamManager::redact_url(text);
    if mount_path.is_empty() {
        redacted
    } else {
        redacted.replace(mount_path, "/stream-***")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RtspServerInfo {
    pub rtsp_url: String,
    pub display_url: String,
}

use relay::{PlaybackFault, PlaybackFaultKind, PlaybackHealth, PlaybackState};
use relay::{
    RelayEventReceiver, RelayEventSender, RelayFaultEvent, RelayRuntimeHealth, RelayState,
    RelaySupervisorEvent, ResolvedRtspStartSpec, ResolvedSource,
};
use rtsp_client::PlaybackPipeline;
use rtsp_server::{
    RtspBuildFailure, RtspBuildFailureKind, RtspRestreamer, RtspRuntimeContext, MAX_RTSP_CLIENTS,
};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StreamStatus {
    pub playing: bool,
    pub playback_desired: bool,
    pub playback_state: PlaybackState,
    pub playback_fault: Option<PlaybackFault>,
    pub playback_recovery_attempt: u32,
    pub playback_next_retry_secs: Option<u64>,
    pub recording_report: Option<String>,
    pub recording_finalized_path: Option<String>,
    pub rtsp_server_running: bool,
    pub rtsp_desired: bool,
    pub rtsp_relay_state: RelayState,
    pub rtsp_error: Option<String>,
    pub rtsp_recovery_attempt: u32,
    pub rtsp_url: Option<String>,
    pub display_url: Option<String>,
    pub recording: bool,
    pub uptime_secs: u64,
    pub bandwidth_kbps: f64,
    pub rtsp_connected_clients: u32,
    pub rtsp_client_limit: u32,
    pub error: Option<String>,
    /// True while the playback pipeline has a linked audio branch.
    pub audio_present: bool,
    /// Last recognized audio codec the camera offered. May be `Some`
    /// with `audio_present == false` when the codec was recognized but
    /// skipped (decoder chain unavailable).
    pub audio_codec: Option<String>,
}

impl StreamStatus {
    fn idle() -> Self {
        Self {
            playing: false,
            playback_desired: false,
            playback_state: PlaybackState::Stopped,
            playback_fault: None,
            playback_recovery_attempt: 0,
            playback_next_retry_secs: None,
            recording_report: None,
            recording_finalized_path: None,
            rtsp_server_running: false,
            rtsp_desired: false,
            rtsp_relay_state: RelayState::Stopped,
            rtsp_error: None,
            rtsp_recovery_attempt: 0,
            rtsp_url: None,
            display_url: None,
            recording: false,
            uptime_secs: 0,
            bandwidth_kbps: 0.0,
            rtsp_connected_clients: 0,
            rtsp_client_limit: MAX_RTSP_CLIENTS,
            error: None,
            audio_present: false,
            audio_codec: None,
        }
    }
}

fn publish_status_if_changed(tx: &watch::Sender<StreamStatus>, snapshot: StreamStatus) {
    tx.send_if_modified(|current| {
        if *current == snapshot {
            false
        } else {
            *current = snapshot;
            true
        }
    });
}

pub struct StreamManager {
    app_handle: std::sync::Mutex<Option<tauri::AppHandle>>,
    state: Arc<Mutex<StreamState>>,
    video_hwnd: Arc<std::sync::atomic::AtomicIsize>,
    status_tx: Arc<watch::Sender<StreamStatus>>,
    /// Bumped on every `stop_rtsp_server` (even when no server is stored).
    /// `start_rtsp_server` captures it before its slow interface enumeration
    /// and, under the storage lock, refuses to store if it changed — so a
    /// stop that races a start wins instead of leaving a zombie server the
    /// user asked not to run.
    rtsp_epoch: Arc<std::sync::atomic::AtomicU64>,
    /// Generation allocated by each full explicit Start. Automatic rebuilds
    /// remain in that generation; a newer Start invalidates older work.
    rtsp_generation: Arc<std::sync::atomic::AtomicU64>,
    /// Serializes listener take/shutdown/build/store work without ever holding
    /// the shared StreamState lock across a slow operation.
    relay_lifecycle: Arc<Mutex<()>>,
    /// Promptly wakes recovery backoff after Stop or a newer Start. Epoch and
    /// generation checks remain the cancellation authority.
    relay_wake: Arc<Notify>,
    relay_event_tx: RelayEventSender,
    relay_event_rx: std::sync::Mutex<Option<RelayEventReceiver>>,
    /// Same stop-beats-start protocol as `rtsp_epoch`, for the playback
    /// pipeline: bumped on every `stop_playback` (even when no pipeline is
    /// stored), captured by `start_playback` before its slow pipeline
    /// build, and re-checked under the storage lock.
    playback_epoch: Arc<std::sync::atomic::AtomicU64>,
    playback_lifecycle: Arc<Mutex<()>>,
    playback_wake: Arc<Notify>,
    playback_diagnostic: PlaybackDiagnostic,
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
    playback_target: Option<CameraTarget>,
    rtsp_target: Option<CameraTarget>,
    playback_settings: Option<AppSettings>,
    playback_health: Option<Arc<PlaybackHealth>>,
    playback_intent_epoch: Option<u64>,
    playback_instance: Option<(u64, u64)>,
    playback_window: Option<usize>,
    playback_adapter: Option<(Option<String>, Option<u32>)>,
    playback_ready: Option<(u32, std::net::Ipv4Addr)>,
    recording_report: Option<String>,
    recording_finalized_path: Option<String>,
    playback: Option<Arc<PlaybackPipeline>>,
    rtsp_server: Option<RtspRestreamer>,
    rtsp_desired: bool,
    rtsp_spec: Option<ResolvedRtspStartSpec>,
    rtsp_health: Option<Arc<RelayRuntimeHealth>>,
    /// RTSP epoch captured by the explicit Start that installed the current
    /// desired state.  This lets a Stop distinguish an older in-flight Start
    /// from a newer Start that began after the Stop invalidated the epoch.
    rtsp_intent_epoch: Option<u64>,
    recording: bool,
    recording_path: Option<String>,
    start_time: Option<std::time::Instant>,
    rtsp_start_time: Option<std::time::Instant>,
    /// Source the running playback was started with (None when idle).
    playback_source: Option<SourceMode>,
}

#[derive(Clone)]
struct RelaySupervisorContext {
    state: Arc<Mutex<StreamState>>,
    status_tx: Arc<watch::Sender<StreamStatus>>,
    rtsp_epoch: Arc<std::sync::atomic::AtomicU64>,
    relay_lifecycle: Arc<Mutex<()>>,
    relay_wake: Arc<Notify>,
    relay_event_tx: RelayEventSender,
    app_handle: tauri::AppHandle,
    rtsp_generation: Arc<std::sync::atomic::AtomicU64>,
}

impl StreamManager {
    pub fn new() -> Self {
        let (status_tx, _) = watch::channel(StreamStatus::idle());
        let (relay_event_tx, relay_event_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            app_handle: std::sync::Mutex::new(None),
            state: Arc::new(Mutex::new(StreamState {
                playback_target: None,
                rtsp_target: None,
                playback_settings: None,
                playback_health: None,
                playback_intent_epoch: None,
                playback_instance: None,
                playback_window: None,
                playback_adapter: None,
                playback_ready: None,
                recording_report: None,
                recording_finalized_path: None,
                playback: None,
                rtsp_server: None,
                rtsp_desired: false,
                rtsp_spec: None,
                rtsp_health: None,
                rtsp_intent_epoch: None,
                recording: false,
                recording_path: None,
                start_time: None,
                rtsp_start_time: None,
                playback_source: None,
            })),
            video_hwnd: Arc::new(std::sync::atomic::AtomicIsize::new(0)),
            status_tx: Arc::new(status_tx),
            rtsp_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            rtsp_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            relay_lifecycle: Arc::new(Mutex::new(())),
            relay_wake: Arc::new(Notify::new()),
            relay_event_tx,
            relay_event_rx: std::sync::Mutex::new(Some(relay_event_rx)),
            playback_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            playback_lifecycle: Arc::new(Mutex::new(())),
            playback_wake: Arc::new(Notify::new()),
            playback_diagnostic: Arc::new(std::sync::Mutex::new(None)),
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
                    crate::validation::parse_camera_ip(&settings.stream.camera_ip)
                        .map_err(|e| AppError::Stream(e.to_string()))?;
                }
                Ok(format!(
                    "rtsp://{}:{}{}",
                    settings.stream.camera_ip, settings.stream.rtsp_port, settings.stream.rtsp_path
                ))
            }
        }
    }

    /// Establish intent; the supervisor owns every connect/retry/teardown.
    /// Reasserting identical intent never replaces a starting/healthy pipeline.
    pub async fn start_playback(
        &self,
        settings: &AppSettings,
        window_handle: Option<usize>,
    ) -> Result<(), AppError> {
        let start_epoch = self
            .playback_epoch
            .load(std::sync::atomic::Ordering::Acquire);
        Self::build_input_url(settings)?;
        crate::ensure_gstreamer()?;
        let mut state = self.state.lock().await;
        if settings.stream.protocol == StreamProtocol::Udp
            && ((state.rtsp_desired
                && state
                    .rtsp_spec
                    .as_ref()
                    .and_then(ResolvedRtspStartSpec::udp_ingest_port)
                    == Some(settings.stream.udp_port))
                || state.rtsp_server.as_ref().and_then(|s| s.udp_ingest_port())
                    == Some(settings.stream.udp_port))
        {
            return Err(AppError::Stream(format!("UDP port {} is already claimed by the RTSP re-stream server. Stop it first or switch the input to RTSP.", settings.stream.udp_port)));
        }
        if state
            .playback_settings
            .as_ref()
            .is_some_and(|s| same_playback_source(s, settings))
        {
            drop(state);
            self.playback_wake.notify_one();
            return Ok(());
        }
        if self
            .playback_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != start_epoch
        {
            return Err(AppError::Stream("Playback start superseded by Stop".into()));
        }
        let epoch = start_epoch.wrapping_add(1);
        self.playback_epoch
            .compare_exchange(
                start_epoch,
                epoch,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map_err(|_| AppError::Stream("Playback start superseded by Stop".into()))?;
        if let Some(old) = &state.playback_health {
            old.stop();
        }
        cancel_playback_diagnostic(&self.playback_diagnostic);
        state.playback_settings = Some(settings.clone());
        state.playback_health = Some(Arc::new(PlaybackHealth::new()));
        state.playback_intent_epoch = Some(epoch);
        state.playback_target = stream_target(settings);
        state.playback_window =
            window_handle.or_else(|| self.get_video_child_hwnd().map(|h| h as usize));
        state.playback_adapter = None;
        state.playback_ready = None;
        state.playback_source = Some(match settings.stream.protocol {
            StreamProtocol::Udp => SourceMode::Udp {
                port: settings.stream.udp_port,
            },
            StreamProtocol::Rtsp => SourceMode::Rtsp,
        });
        drop(state);
        self.playback_wake.notify_one();
        self.refresh_status().await;
        Ok(())
    }

    pub async fn retry_playback(
        &self,
        manual: bool,
        settings: Option<AppSettings>,
    ) -> Result<(), AppError> {
        let requested_epoch = self
            .playback_epoch
            .load(std::sync::atomic::Ordering::Acquire);
        let mut state = self.state.lock().await;
        if self
            .playback_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != requested_epoch
        {
            return Err(AppError::Stream("Playback Retry superseded by Stop".into()));
        }
        // Manual Retry may apply corrected credentials/path, while the intended
        // camera key, endpoint and expected MAC remain owned by this playback.
        if manual {
            if let (Some(current), Some(mut desired)) = (settings, state.playback_settings.clone())
            {
                desired.credentials = current.credentials;
                if desired.stream.protocol == StreamProtocol::Rtsp {
                    desired.stream.rtsp_path = current.stream.rtsp_path;
                    desired.stream.rtsp_port = current.stream.rtsp_port;
                }
                if !same_playback_source(state.playback_settings.as_ref().unwrap(), &desired) {
                    let epoch = requested_epoch.wrapping_add(1);
                    self.playback_epoch
                        .compare_exchange(
                            requested_epoch,
                            epoch,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        )
                        .map_err(|_| {
                            AppError::Stream("Playback Retry superseded by Stop".into())
                        })?;
                    if let Some(old) = &state.playback_health {
                        old.stop();
                    }
                    cancel_playback_diagnostic(&self.playback_diagnostic);
                    state.playback_health = Some(Arc::new(PlaybackHealth::new()));
                    state.playback_settings = Some(desired);
                    state.playback_intent_epoch = Some(epoch);
                }
            }
        }
        let health = state
            .playback_health
            .as_ref()
            .ok_or_else(|| AppError::Stream("No desired playback to retry".into()))?;
        if manual {
            health.retry();
        } else {
            health.wake_ready();
        }
        drop(state);
        self.playback_wake.notify_one();
        self.refresh_status().await;
        Ok(())
    }

    pub async fn stop_playback(&self) -> Result<(), AppError> {
        let stop_epoch = self
            .playback_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .wrapping_add(1);
        self.playback_wake.notify_waiters();
        cancel_playback_diagnostic(&self.playback_diagnostic);
        {
            let mut state = self.state.lock().await;
            if state
                .playback_intent_epoch
                .is_none_or(|intent| intent < stop_epoch)
            {
                if let Some(health) = state.playback_health.take() {
                    health.stop();
                }
                state.playback_settings = None;
                state.playback_intent_epoch = None;
                state.playback_target = None;
                state.playback_adapter = None;
                state.playback_ready = None;
            }
        }
        let _lifecycle = self.playback_lifecycle.lock().await;
        let old_pipeline = self
            .state
            .lock()
            .await
            .playback_instance
            .is_none_or(|(epoch, _)| epoch < stop_epoch);
        if old_pipeline {
            retire_playback(&self.state, false).await;
        }
        let mut state = self.state.lock().await;
        if state.playback_settings.is_none() {
            state.playback_source = None;
        }
        drop(state);
        self.refresh_status().await;
        Ok(())
    }

    async fn resolve_rtsp_start_spec(
        settings: &AppSettings,
        adopted: &std::collections::HashSet<String>,
    ) -> Result<ResolvedRtspStartSpec, AppError> {
        let source = match settings.stream.protocol {
            StreamProtocol::Rtsp => ResolvedSource::Rtsp {
                url: Self::build_input_url(settings)?,
            },
            StreamProtocol::Udp => ResolvedSource::Udp {
                port: settings.stream.udp_port,
            },
        };
        let bind_interface = if settings.rtsp_server.bind_interface.is_empty() {
            None
        } else {
            Some(settings.rtsp_server.bind_interface.clone())
        };
        let bind_address = resolve_explicit_bind(bind_interface.as_deref(), adopted).await?;
        let advertised_ip = match &bind_address {
            Some(ip) => ip.clone(),
            None => get_display_ip(adopted)
                .await
                .unwrap_or_else(|| "0.0.0.0".into()),
        };
        log::info!(
            "RTSP bind selection: interface={:?} bind={:?} advertise={}",
            bind_interface,
            bind_address,
            advertised_ip
        );
        Ok(ResolvedRtspStartSpec {
            source,
            server_port: settings.rtsp_server.port,
            mount_path: format!("/stream-{}", settings.rtsp_server.token),
            bind_interface,
            bind_address,
            advertised_ip,
            username: settings.credentials.username.clone(),
            password: settings.credentials.password.clone(),
        })
    }

    fn build_rtsp_restreamer(
        spec: &ResolvedRtspStartSpec,
        health: Arc<RelayRuntimeHealth>,
        event_tx: RelayEventSender,
        recovering: bool,
        upstream_ready: Option<rtsp_server::UpstreamReady>,
    ) -> (u64, Result<RtspRestreamer, RtspBuildFailure>) {
        let server_instance = health.begin_server_instance(recovering);
        let runtime = RtspRuntimeContext {
            health,
            event_tx,
            server_instance,
            upstream_ready,
        };
        let result = match &spec.source {
            ResolvedSource::Udp { port } => RtspRestreamer::start_from_udp(
                *port,
                spec.server_port,
                &spec.mount_path,
                spec.bind_address.as_deref(),
                runtime,
            ),
            ResolvedSource::Rtsp { url } => RtspRestreamer::start_from_rtsp(
                url,
                spec.server_port,
                &spec.mount_path,
                spec.bind_address.as_deref(),
                &spec.username,
                &spec.password,
                runtime,
            ),
        };
        (server_instance, result)
    }

    pub async fn start_rtsp_server(
        &self,
        settings: &AppSettings,
        adopted: &std::collections::HashSet<String>,
    ) -> Result<RtspServerInfo, AppError> {
        let start_epoch = self.rtsp_epoch.load(std::sync::atomic::Ordering::Acquire);
        let handle = self
            .app_handle
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut target = stream_target(settings);
        if let Some(path) = preflight_target(handle.as_ref(), target.as_ref()).await? {
            target = Some(path.target);
        }
        let spec = Self::resolve_rtsp_start_spec(settings, adopted).await?;
        if self.rtsp_epoch.load(std::sync::atomic::Ordering::Acquire) != start_epoch {
            return Err(AppError::Stream(
                "RTSP server start was superseded by a stop".into(),
            ));
        }

        let info = RtspServerInfo {
            rtsp_url: spec.client_url(),
            display_url: spec.display_url(),
        };

        let (server_generation, health) = {
            let mut state = self.state.lock().await;
            if self.rtsp_epoch.load(std::sync::atomic::Ordering::Acquire) != start_epoch {
                return Err(AppError::Stream(
                    "RTSP server start was superseded by a stop".into(),
                ));
            }

            let health_snapshot = state.rtsp_health.as_ref().map(|health| health.snapshot());
            let healthy_noop = resolved_start_is_healthy_noop(
                state.rtsp_desired,
                state.rtsp_spec.as_ref(),
                &spec,
                health_snapshot.as_ref().map(|health| health.state),
                health_snapshot
                    .as_ref()
                    .map(|health| health.server_generation),
                state
                    .rtsp_server
                    .as_ref()
                    .map(RtspRestreamer::server_generation),
                state
                    .rtsp_server
                    .as_ref()
                    .is_some_and(RtspRestreamer::loop_alive),
            );
            if healthy_noop && state.rtsp_target == target {
                log::info!("RTSP explicit Start resolved to the healthy current endpoint; no-op");
                return Ok(info);
            }

            if let Some(udp_port) = spec.udp_ingest_port() {
                if state.playback_source == Some(SourceMode::Udp { port: udp_port }) {
                    return Err(AppError::Stream(format!(
                        "UDP port {} is already claimed by the running preview - only one consumer can receive a UDP stream. Stop the stream first, or switch the input to RTSP.",
                        udp_port
                    )));
                }
            }

            let server_generation = self
                .rtsp_generation
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
                .wrapping_add(1);
            let health = Arc::new(RelayRuntimeHealth::new(
                server_generation,
                spec.ingest_kind(),
            ));
            state.rtsp_desired = true;
            state.rtsp_spec = Some(spec.clone());
            state.rtsp_target = target.clone();
            state.rtsp_health = Some(health.clone());
            state.rtsp_intent_epoch = Some(start_epoch);
            state.rtsp_start_time = Some(std::time::Instant::now());
            (server_generation, health)
        };

        self.relay_wake.notify_waiters();
        self.refresh_status().await;

        let gst_error = crate::ensure_gstreamer().err();
        if let Err(error) = crate::network::firewall::ensure_rtsp_allowed(spec.server_port).await {
            log::warn!("Firewall setup: {}", error);
        }

        let _lifecycle = self.relay_lifecycle.lock().await;
        if !relay_is_current(
            &self.state,
            &self.rtsp_epoch,
            start_epoch,
            server_generation,
        )
        .await
        {
            return Err(AppError::Stream(
                "RTSP server start was superseded by a newer request".into(),
            ));
        }

        let old_server = {
            let mut state = self.state.lock().await;
            if !relay_state_is_generation(&state, server_generation)
                || state.rtsp_intent_epoch != Some(start_epoch)
            {
                return Err(AppError::Stream(
                    "RTSP server start was superseded by a newer request".into(),
                ));
            }
            state.rtsp_server.take()
        };
        if let Some(old_server) = old_server {
            old_server.shutdown().await;
        }

        if !relay_is_current(
            &self.state,
            &self.rtsp_epoch,
            start_epoch,
            server_generation,
        )
        .await
        {
            return Err(AppError::Stream(
                "RTSP server start was superseded by a newer request".into(),
            ));
        }

        if let Some(error) = gst_error {
            let server_instance = health.begin_server_instance(false);
            let reason = redact_relay_text(&error.to_string(), &spec.mount_path);
            health.mark_build_failed(server_instance, reason, false);
            let _ = self
                .relay_event_tx
                .send(RelaySupervisorEvent::RetryRequested { server_generation });
            drop(_lifecycle);
            self.refresh_status().await;
            return Err(error);
        }

        if let Err(error) = preflight_target(handle.as_ref(), target.as_ref()).await {
            health.mark_resolution_failed(error.to_string());
            let _ = self
                .relay_event_tx
                .send(RelaySupervisorEvent::RetryRequested { server_generation });
            drop(_lifecycle);
            self.refresh_status().await;
            return Err(error);
        }
        let (server_instance, built) = Self::build_rtsp_restreamer(
            &spec,
            health.clone(),
            self.relay_event_tx.clone(),
            false,
            relay_preflight(
                handle.clone(),
                target.clone(),
                self.rtsp_epoch.clone(),
                start_epoch,
                self.rtsp_generation.clone(),
                server_generation,
            ),
        );
        let server = match built {
            Ok(server) => server,
            Err(failure) => {
                let reason = redact_relay_text(&failure.error.to_string(), &spec.mount_path);
                health.mark_build_failed(
                    server_instance,
                    reason,
                    // The interface refresh rule counts failed automatic
                    // rebuilds; this explicit Start is the baseline attempt.
                    false,
                );
                let _ = self
                    .relay_event_tx
                    .send(RelaySupervisorEvent::RetryRequested { server_generation });
                drop(_lifecycle);
                self.refresh_status().await;
                return Err(failure.error);
            }
        };

        let mut candidate = Some(server);
        {
            let mut state = self.state.lock().await;
            if self.rtsp_epoch.load(std::sync::atomic::Ordering::Acquire) == start_epoch
                && state.rtsp_intent_epoch == Some(start_epoch)
                && relay_state_is_generation(&state, server_generation)
            {
                state.rtsp_server = candidate.take();
            }
        }
        if let Some(stale) = candidate {
            stale.shutdown().await;
            return Err(AppError::Stream(
                "RTSP server start was superseded by a newer request".into(),
            ));
        }

        drop(_lifecycle);
        self.refresh_status().await;
        Ok(info)
    }

    pub async fn stop_rtsp_server(&self) -> Result<(), AppError> {
        let stop_epoch = self
            .rtsp_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .wrapping_add(1);
        self.relay_wake.notify_waiters();

        let target_generation = {
            let mut state = self.state.lock().await;
            let desired_generation = state
                .rtsp_health
                .as_ref()
                .map(|health| health.server_generation());
            let live_generation = state
                .rtsp_server
                .as_ref()
                .map(RtspRestreamer::server_generation);
            let stops_desired = state.rtsp_desired
                && state
                    .rtsp_intent_epoch
                    .is_none_or(|intent_epoch| intent_epoch < stop_epoch);

            let target = if stops_desired {
                desired_generation.or(live_generation)
            } else if live_generation != desired_generation {
                live_generation
            } else {
                None
            };

            if stops_desired {
                state.rtsp_desired = false;
                state.rtsp_spec = None;
                state.rtsp_target = None;
                state.rtsp_health = None;
                state.rtsp_intent_epoch = None;
                state.rtsp_start_time = None;
            }
            target
        };
        self.refresh_status().await;

        let _lifecycle = self.relay_lifecycle.lock().await;
        let server = {
            let mut state = self.state.lock().await;
            if state
                .rtsp_server
                .as_ref()
                .is_some_and(|server| Some(server.server_generation()) == target_generation)
            {
                state.rtsp_server.take()
            } else {
                None
            }
        };
        if let Some(server) = server {
            server.shutdown().await;
            log::info!("RTSP server fully cleaned up");
        }
        drop(_lifecycle);
        self.refresh_status().await;
        log::info!("RTSP server stopped");
        Ok(())
    }

    /// Recompute status from internal state and publish to subscribers.
    /// Called after every command-side mutation, plus on the 1Hz ticker
    /// for uptime / bandwidth refresh.
    async fn refresh_status(&self) {
        let snapshot = compute_status(&self.state).await;
        publish_status_if_changed(self.status_tx.as_ref(), snapshot);
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
        *self.app_handle.lock().unwrap_or_else(|p| p.into_inner()) = Some(handle.clone());
        let relay_events = self
            .relay_event_rx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(relay_events) = relay_events {
            let supervisor = RelaySupervisorContext {
                state: self.state.clone(),
                status_tx: self.status_tx.clone(),
                rtsp_epoch: self.rtsp_epoch.clone(),
                relay_lifecycle: self.relay_lifecycle.clone(),
                relay_wake: self.relay_wake.clone(),
                relay_event_tx: self.relay_event_tx.clone(),
                app_handle: handle.clone(),
                rtsp_generation: self.rtsp_generation.clone(),
            };
            tauri::async_runtime::spawn(run_relay_supervisor(relay_events, supervisor));
        } else {
            log::warn!("RTSP relay supervisor was already started");
        }

        let playback = PlaybackSupervisorContext {
            state: self.state.clone(),
            status_tx: self.status_tx.clone(),
            epoch: self.playback_epoch.clone(),
            lifecycle: self.playback_lifecycle.clone(),
            wake: self.playback_wake.clone(),
            diagnostic: self.playback_diagnostic.clone(),
            app: Some(handle.clone()),
        };
        // Consume the backend watcher's selected-adapter events. Presence's
        // verified Notify independently wakes a camera reboot behind a switch.
        use tauri::Listener;
        let wake = playback.wake.clone();
        handle.listen("adapter-selection-changed", move |_| {
            wake.notify_one();
        });
        tauri::async_runtime::spawn(run_playback_supervisor(playback));

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
        let _lifecycle = self.playback_lifecycle.lock().await;
        // Path computation involves filesystem I/O — keep it outside
        // the lock. When the Videos folder is unavailable, fall back to
        // the per-user local-data dir — NOT the process CWD, which on an
        // installed build is Program Files and unwritable.
        let output_dir = dirs::video_dir()
            .unwrap_or_else(|| {
                let fallback = dirs::data_local_dir().unwrap_or_else(std::env::temp_dir);
                log::warn!(
                    "Videos directory unavailable; recording under {}",
                    fallback.display()
                );
                fallback
            })
            .join("PocketStream");

        // Pre-flight the recording volume: a disk that fills mid-write
        // surfaces as an opaque GStreamer bus error that reads like a
        // network failure, so refuse to start below a floor instead. A
        // failed probe fails open — it must not block recording.
        if let Some(free) = recorder::free_space_bytes(&output_dir) {
            if !recorder::recording_space_ok(free) {
                return Err(AppError::Stream(format!(
                    "Not enough disk space to record — {} MB free, {} MB required",
                    free / (1024 * 1024),
                    recorder::RECORDING_MIN_FREE_BYTES / (1024 * 1024)
                )));
            }
        } else {
            log::warn!(
                "Could not determine free space for {}; starting recording anyway",
                output_dir.display()
            );
        }

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
            if !state
                .playback_health
                .as_ref()
                .is_some_and(|h| h.snapshot().state == PlaybackState::Playing)
            {
                return Err(AppError::Stream(
                    "Playback has no usable frames to record".into(),
                ));
            }
            state.recording_report = None;
            state.recording_finalized_path = None;

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
        let _lifecycle = self.playback_lifecycle.lock().await;
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

    /// Apply the mute preference to live playback, if any. Persistence
    /// happens in the command layer; with no pipeline this is a no-op —
    /// the next start seeds the preference from config. Clone the
    /// pipeline Arc out under the lock, poke GStreamer outside it (the
    /// one lock discipline for StreamManager).
    pub async fn set_audio_muted(&self, muted: bool) {
        let pipeline = {
            let mut state = self.state.lock().await;
            if let Some(settings) = &mut state.playback_settings {
                settings.stream.audio_muted = muted;
            }
            state.playback.clone()
        };
        if let Some(p) = pipeline {
            p.set_audio_muted(muted);
        }
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

    /// Clear the native video handle only when it is still `expected`.
    /// A stop can spend time finalizing recording or transitioning an old
    /// GStreamer pipeline while a replacement window is created. An
    /// unconditional clear at the end of that stop would lose the new HWND.
    pub fn clear_video_child_hwnd_if(&self, expected: isize) -> bool {
        self.video_hwnd
            .compare_exchange(
                expected,
                0,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
    }
}

#[derive(Clone)]
struct PlaybackSupervisorContext {
    state: Arc<Mutex<StreamState>>,
    status_tx: Arc<watch::Sender<StreamStatus>>,
    epoch: Arc<std::sync::atomic::AtomicU64>,
    lifecycle: Arc<Mutex<()>>,
    wake: Arc<Notify>,
    diagnostic: PlaybackDiagnostic,
    app: Option<tauri::AppHandle>,
}

type PlaybackDiagnostic = Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>;

fn cancel_playback_diagnostic(slot: &PlaybackDiagnostic) {
    if let Some(task) = slot.lock().unwrap_or_else(|p| p.into_inner()).take() {
        task.abort();
    }
}

fn same_playback_source(a: &AppSettings, b: &AppSettings) -> bool {
    a.stream.protocol == b.stream.protocol
        && a.stream.camera_ip == b.stream.camera_ip
        && a.stream.camera_mac == b.stream.camera_mac
        && a.stream.rtsp_port == b.stream.rtsp_port
        && a.stream.rtsp_path == b.stream.rtsp_path
        && a.stream.udp_port == b.stream.udp_port
        && a.credentials.username == b.credentials.username
        && a.credentials.password == b.credentials.password
}

async fn playback_is_current(
    ctx: &PlaybackSupervisorContext,
    epoch: u64,
    health: &Arc<PlaybackHealth>,
) -> bool {
    let s = ctx.state.lock().await;
    ctx.epoch.load(std::sync::atomic::Ordering::Acquire) == epoch
        && s.playback_intent_epoch == Some(epoch)
        && s.playback_health
            .as_ref()
            .is_some_and(|h| Arc::ptr_eq(h, health))
        && s.playback_settings.is_some()
}

/// Caller holds the lifecycle gate. Recording never follows a replacement.
async fn retire_playback(state: &Arc<Mutex<StreamState>>, lost: bool) {
    let (pipeline, recording, path) = {
        let mut s = state.lock().await;
        let recording = std::mem::take(&mut s.recording);
        let path = s.recording_path.take();
        s.playback_instance = None;
        s.start_time = None;
        (s.playback.take(), recording, path)
    };
    let finalized = if recording {
        match &pipeline {
            Some(p) => p.detach_recording().await,
            None => Err(AppError::Stream("Recording pipeline unavailable".into())),
        }
    } else {
        Ok(())
    };
    if let Some(p) = pipeline {
        if let Err(e) = p.stop() {
            log::warn!(
                "Playback teardown: {}",
                StreamManager::redact_url(&e.to_string())
            );
        }
    }
    if recording {
        let mut s = state.lock().await;
        let reason = if lost {
            "recording stopped: stream lost"
        } else {
            "recording stopped"
        };
        s.recording_report = Some(match finalized {
            Ok(_) => reason.into(),
            Err(e) => format!(
                "{reason}; finalize incomplete: {}",
                StreamManager::redact_url(&e.to_string())
            ),
        });
        s.recording_finalized_path = path;
    }
}

async fn publish_playback_status(ctx: &PlaybackSupervisorContext) {
    publish_status_if_changed(ctx.status_tx.as_ref(), compute_status(&ctx.state).await);
}

async fn expected_device_wake(app: Option<&tauri::AppHandle>) {
    use tauri::Manager;
    if let Some(app) = app {
        app.state::<crate::network::NetworkManager>()
            .expected_device_verified()
            .await;
    } else {
        std::future::pending::<()>().await;
    }
}

async fn run_playback_supervisor(ctx: PlaybackSupervisorContext) {
    let mut logged = None;
    let mut recovery_started = None;
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tick.tick() => {},
            _ = wait_playback_ready(&ctx.wake, expected_device_wake(ctx.app.as_ref())) => {},
        }
        playback_step(&ctx).await;
        {
            let s = ctx.state.lock().await;
            if let Some(health) = &s.playback_health {
                let snapshot = health.snapshot();
                let cause = snapshot.fault.as_ref().map(|fault| fault.kind);
                let key = (
                    s.playback_intent_epoch,
                    snapshot.state,
                    snapshot.attempt,
                    cause,
                );
                if logged != Some(key) {
                    if logged.as_ref().is_some_and(
                        |old: &(Option<u64>, PlaybackState, u32, Option<PlaybackFaultKind>)| {
                            old.0 != key.0
                        },
                    ) {
                        recovery_started = None;
                    }
                    if matches!(
                        snapshot.state,
                        PlaybackState::Recovering | PlaybackState::Failed
                    ) {
                        recovery_started.get_or_insert_with(tokio::time::Instant::now);
                    }
                    let duration = recovery_started.map_or(0, |at| at.elapsed().as_millis());
                    let (mac, index) = s
                        .playback_adapter
                        .as_ref()
                        .map(|(m, i)| (m.as_deref().unwrap_or("unknown"), i.unwrap_or(0)))
                        .unwrap_or(("unknown", 0));
                    log::info!("event=playback_recovery adapter_mac={} interface_index={} state={} cause={} attempt={} duration_ms={}",
                        crate::network::log_value(mac), index, serde_json::to_string(&snapshot.state).unwrap(),
                        serde_json::to_string(&cause).unwrap(), snapshot.attempt, duration);
                    if matches!(
                        snapshot.state,
                        PlaybackState::Playing | PlaybackState::Stopped
                    ) {
                        recovery_started = None;
                    }
                    logged = Some(key);
                }
            }
        }
        publish_playback_status(&ctx).await;
    }
}

async fn wait_playback_ready(wake: &Notify, verified: impl std::future::Future<Output = ()>) {
    tokio::select! { _ = wake.notified() => {}, _ = verified => {} }
}

fn update_playback_readiness(
    previous: &mut Option<(u32, std::net::Ipv4Addr)>,
    next: Option<(u32, std::net::Ipv4Addr)>,
    health: &PlaybackHealth,
) -> bool {
    let changed = next.is_some() && *previous != next;
    *previous = next;
    if changed {
        health.wake_ready();
    }
    changed
}

async fn playback_step(ctx: &PlaybackSupervisorContext) {
    use std::sync::atomic::Ordering;
    use tauri::Manager;
    let _lifecycle = ctx.lifecycle.lock().await;
    let (mut epoch, health, settings, target, window) = {
        let s = ctx.state.lock().await;
        let (Some(epoch), Some(health), Some(settings)) = (
            s.playback_intent_epoch,
            s.playback_health.clone(),
            s.playback_settings.clone(),
        ) else {
            return;
        };
        (
            epoch,
            health,
            settings,
            s.playback_target.clone(),
            s.playback_window,
        )
    };
    if !playback_is_current(ctx, epoch, &health).await {
        return;
    }
    // Selected identity/index changes cancel prior work even if a replacement
    // adapter already has a usable route. No old-incarnation buffer is accepted.
    if target.is_some() {
        if let Some(app) = &ctx.app {
            let selection = app
                .state::<crate::network::NetworkManager>()
                .adapter_selection_state()
                .await;
            let identity = (selection.selected_mac, selection.interface_index);
            let mut s = ctx.state.lock().await;
            if ctx.epoch.load(Ordering::Acquire) != epoch || s.playback_intent_epoch != Some(epoch)
            {
                return;
            }
            if s.playback_adapter
                .as_ref()
                .is_some_and(|old| old != &identity)
            {
                let next = epoch.wrapping_add(1);
                if ctx
                    .epoch
                    .compare_exchange(epoch, next, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    return;
                }
                epoch = next;
                s.playback_intent_epoch = Some(epoch);
                cancel_playback_diagnostic(&ctx.diagnostic);
                let generation = health.snapshot().generation;
                health.record_fault(
                    generation,
                    PlaybackFault::new(
                        PlaybackFaultKind::DeviceLoss,
                        "Selected Ethernet adapter changed",
                        true,
                    ),
                );
            }
            s.playback_adapter = Some(identity);
        }
    }
    let pipeline = ctx.state.lock().await.playback.clone();
    if target.is_some() && health.snapshot().state != PlaybackState::Failed {
        // Recheck readiness on wake/tick, including a legacy manual target's
        // first learned identity. Repeated successful verification is not a
        // transition and cannot collapse transport backoff to the 5 s cadence.
        let checked = preflight_target(ctx.app.as_ref(), target.as_ref()).await;
        if !playback_is_current(ctx, epoch, &health).await {
            return;
        }
        let next = checked
            .as_ref()
            .ok()
            .and_then(|p| p.as_ref())
            .map(|p| (p.index, p.source));
        let mut s = ctx.state.lock().await;
        let previous = s.playback_ready;
        let changed = update_playback_readiness(&mut s.playback_ready, next, &health);
        drop(s);
        if let Err(e) = checked {
            if pipeline.is_some() {
                health.record_fault(
                    health.snapshot().generation,
                    PlaybackFault::new(PlaybackFaultKind::DeviceLoss, e.to_string(), true),
                );
            }
        } else if changed && previous.is_some() && pipeline.is_some() {
            health.record_fault(
                health.snapshot().generation,
                PlaybackFault::new(
                    PlaybackFaultKind::DeviceLoss,
                    "Selected Ethernet source address changed",
                    true,
                ),
            );
        }
    }
    if let Some(p) = &pipeline {
        if let Err(fault) = p.health_check() {
            if fault.kind == PlaybackFaultKind::FrameStall {
                if let Some(target) = &target {
                    let mut slot = ctx.diagnostic.lock().unwrap_or_else(|p| p.into_inner());
                    if ctx.epoch.load(Ordering::Acquire) == epoch {
                        if let Some(old) = slot.take() {
                            old.abort();
                        }
                        let ip = target.ip.clone();
                        let authority = ctx.epoch.clone();
                        *slot = Some(tokio::spawn(async move {
                            // Preserve the existing bound diagnostic. It never
                            // changes presence, readiness or retry policy.
                            let reachable = crate::network::ping_dot::probe(&ip).await;
                            if authority.load(Ordering::Acquire) == epoch {
                                log::info!("Playback stall diagnostic ip={ip} icmp={reachable}");
                            }
                        }));
                    }
                }
            }
        }
    }
    let snap = health.snapshot();
    let instance = ctx.state.lock().await.playback_instance;
    if pipeline.is_some() && (instance != Some((epoch, snap.generation)) || !snap.active) {
        retire_playback(&ctx.state, true).await;
        if !playback_is_current(ctx, epoch, &health).await {
            return;
        }
    }
    if snap.state == PlaybackState::Failed {
        return;
    }
    if !snap.active && snap.next_retry_secs.is_none() {
        health.schedule_recovery();
    }
    if !health.due(tokio::time::Instant::now()) {
        return;
    }
    let generation = health.begin_attempt();
    log::debug!(
        "event=playback_attempt generation={} attempt={}",
        generation,
        health.snapshot().attempt
    );
    let path = match preflight_target(ctx.app.as_ref(), target.as_ref()).await {
        Ok(path) => path,
        Err(e) => {
            health.record_fault(
                generation,
                PlaybackFault::new(PlaybackFaultKind::DeviceLoss, e.to_string(), true),
            );
            health.schedule_recovery();
            return;
        }
    };
    if !playback_is_current(ctx, epoch, &health).await {
        return;
    }
    let built = match settings.stream.protocol {
        StreamProtocol::Udp => {
            PlaybackPipeline::new_udp(settings.stream.udp_port, window, health.clone(), generation)
        }
        StreamProtocol::Rtsp => StreamManager::build_input_url(&settings).and_then(|url| {
            PlaybackPipeline::new_rtsp(
                &url,
                500,
                true,
                window,
                health.clone(),
                generation,
                &settings.credentials.username,
                &settings.credentials.password,
                settings.stream.audio_muted,
            )
        }),
    };
    let p = match built {
        Ok(p) => p,
        Err(e) => {
            health.record_fault(
                generation,
                PlaybackFault::new(
                    PlaybackFaultKind::Configuration,
                    StreamManager::redact_url(&e.to_string()),
                    false,
                ),
            );
            return;
        }
    };
    // Recheck after construction and immediately before any connection.
    let final_path = preflight_target(
        ctx.app.as_ref(),
        path.as_ref().map(|p| &p.target).or(target.as_ref()),
    )
    .await;
    if !playback_is_current(ctx, epoch, &health).await
        || path.as_ref().is_some_and(|p| p.fence.is_stale())
    {
        health.record_fault(
            generation,
            PlaybackFault::new(
                PlaybackFaultKind::DeviceLoss,
                "Ethernet session changed during playback build",
                true,
            ),
        );
        health.schedule_recovery();
        let _ = p.stop();
        return;
    }
    if let Err(e) = final_path {
        health.record_fault(
            generation,
            PlaybackFault::new(PlaybackFaultKind::DeviceLoss, e.to_string(), true),
        );
        let _ = p.stop();
        health.schedule_recovery();
        return;
    }
    if let Err(e) = p.play() {
        // A synchronous state failure may already have delivered a typed bus
        // fault. First-fault authority preserves that instead of replacing it.
        health.record_fault(
            generation,
            PlaybackFault::new(PlaybackFaultKind::Configuration, e.to_string(), false),
        );
    }
    let mut s = ctx.state.lock().await;
    if ctx.epoch.load(Ordering::Acquire) != epoch
        || s.playback_intent_epoch != Some(epoch)
        || path.as_ref().is_some_and(|p| p.fence.is_stale())
    {
        drop(s);
        health.record_fault(
            generation,
            PlaybackFault::new(
                PlaybackFaultKind::DeviceLoss,
                "Ethernet session changed during playback start",
                true,
            ),
        );
        health.schedule_recovery();
        let _ = p.stop();
        return;
    }
    if let Some(path) = path {
        s.playback_target = Some(path.target);
    }
    s.playback = Some(Arc::new(p));
    s.playback_instance = Some((epoch, generation));
    s.start_time = Some(std::time::Instant::now());
}

fn stream_target(settings: &AppSettings) -> Option<CameraTarget> {
    (settings.stream.protocol == StreamProtocol::Rtsp).then(|| CameraTarget {
        key: settings
            .stream
            .camera_mac
            .clone()
            .unwrap_or_else(|| format!("manual:{}", settings.stream.camera_ip)),
        expected_mac: settings.stream.camera_mac.clone(),
        ip: settings.stream.camera_ip.clone(),
    })
}

async fn preflight_target(
    handle: Option<&tauri::AppHandle>,
    target: Option<&CameraTarget>,
) -> Result<Option<ReadyPath>, AppError> {
    use tauri::Manager;
    let Some(target) = target else {
        return Ok(None);
    }; // UDP is exempt
    let handle =
        handle.ok_or_else(|| AppError::Stream("Ethernet readiness service unavailable".into()))?;
    handle
        .state::<crate::network::NetworkManager>()
        .camera_ready(target, &handle.state::<crate::config::AppConfig>())
        .await
        .map(Some)
}

fn relay_preflight(
    handle: Option<tauri::AppHandle>,
    target: Option<CameraTarget>,
    epoch: Arc<std::sync::atomic::AtomicU64>,
    expected_epoch: u64,
    generation: Arc<std::sync::atomic::AtomicU64>,
    expected_generation: u64,
) -> Option<rtsp_server::UpstreamReady> {
    use tauri::Manager;
    let target = target?; // UDP has no camera gate
    Some(Arc::new(move || {
        if epoch.load(std::sync::atomic::Ordering::Acquire) != expected_epoch
            || generation.load(std::sync::atomic::Ordering::Acquire) != expected_generation
        {
            return Err(AppError::Stream(
                "Relay connection superseded by Stop or a newer Start".into(),
            ));
        }
        let handle = handle
            .as_ref()
            .ok_or_else(|| AppError::Stream("Readiness service unavailable".into()))?;
        handle
            .state::<crate::network::NetworkManager>()
            .camera_ready_now(&target, &handle.state::<crate::config::AppConfig>())
            .map(|_| ())
    }))
}

fn resolved_start_is_healthy_noop(
    desired: bool,
    current_spec: Option<&ResolvedRtspStartSpec>,
    candidate_spec: &ResolvedRtspStartSpec,
    relay_state: Option<RelayState>,
    health_generation: Option<u64>,
    listener_generation: Option<u64>,
    listener_loop_alive: bool,
) -> bool {
    desired
        && current_spec == Some(candidate_spec)
        && matches!(
            relay_state,
            Some(RelayState::Listening | RelayState::Streaming)
        )
        && health_generation == listener_generation
        && health_generation.is_some()
        && listener_loop_alive
}

fn relay_state_is_generation(state: &StreamState, server_generation: u64) -> bool {
    state.rtsp_desired
        && state
            .rtsp_health
            .as_ref()
            .is_some_and(|health| health.server_generation() == server_generation)
}

async fn relay_is_current(
    state: &Arc<Mutex<StreamState>>,
    epoch: &Arc<std::sync::atomic::AtomicU64>,
    expected_epoch: u64,
    server_generation: u64,
) -> bool {
    if epoch.load(std::sync::atomic::Ordering::Acquire) != expected_epoch {
        return false;
    }
    let state = state.lock().await;
    epoch.load(std::sync::atomic::Ordering::Acquire) == expected_epoch
        && state.rtsp_intent_epoch == Some(expected_epoch)
        && relay_state_is_generation(&state, server_generation)
}

async fn wait_relay_backoff(
    state: &Arc<Mutex<StreamState>>,
    epoch: &Arc<std::sync::atomic::AtomicU64>,
    wake: &Arc<Notify>,
    expected_epoch: u64,
    server_generation: u64,
    delay: std::time::Duration,
) -> bool {
    // Register before the initial authority check. If Stop/new Start landed
    // earlier, the check sees it; if it lands afterward, this registered wake
    // prevents a lost notification from sleeping through a 60-second stage.
    let notified = wake.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();

    if !relay_is_current(state, epoch, expected_epoch, server_generation).await {
        return false;
    }
    if !delay.is_zero() {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = &mut notified => {}
        }
    }
    relay_is_current(state, epoch, expected_epoch, server_generation).await
}

async fn current_relay_context(
    ctx: &RelaySupervisorContext,
    server_generation: u64,
) -> Option<(u64, Arc<RelayRuntimeHealth>)> {
    let state = ctx.state.lock().await;
    if !relay_state_is_generation(&state, server_generation) {
        return None;
    }
    let expected_epoch = state.rtsp_intent_epoch?;
    if ctx.rtsp_epoch.load(std::sync::atomic::Ordering::Acquire) != expected_epoch {
        return None;
    }
    Some((expected_epoch, state.rtsp_health.as_ref()?.clone()))
}

async fn publish_relay_status(ctx: &RelaySupervisorContext) {
    let snapshot = compute_status(&ctx.state).await;
    publish_status_if_changed(ctx.status_tx.as_ref(), snapshot);
}

async fn poll_relay_fault(ctx: &RelaySupervisorContext) -> Option<RelayFaultEvent> {
    let health = {
        let state = ctx.state.lock().await;
        if !state.rtsp_desired {
            return None;
        }
        state.rtsp_health.as_ref()?.clone()
    };

    if let Some((server_instance, media_generation, weak_media)) = health.active_media() {
        if let Some(media) = weak_media.upgrade() {
            if media.status() == gst_rtsp_server::RTSPMediaStatus::Error {
                if let Some(event) = health.record_media_fault(
                    server_instance,
                    media_generation,
                    relay::RelayFaultKind::MediaStatusError,
                    "RTSP relay media entered error status".into(),
                ) {
                    return Some(event);
                }
            }
        }
    }

    health.evaluate_watchdog(tokio::time::Instant::now())
}

async fn run_relay_supervisor(mut events: RelayEventReceiver, ctx: RelaySupervisorContext) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut channel_open = true;

    loop {
        let event = tokio::select! {
            received = events.recv(), if channel_open => {
                match received {
                    Some(event) => Some(event),
                    None => {
                        channel_open = false;
                        None
                    }
                }
            }
            _ = interval.tick() => {
                poll_relay_fault(&ctx).await.map(RelaySupervisorEvent::Fault)
            }
        };

        let Some(event) = event else {
            continue;
        };
        match event {
            RelaySupervisorEvent::Fault(event) => {
                let generation = event.fault.server_generation;
                let Some((expected_epoch, health)) = current_relay_context(&ctx, generation).await
                else {
                    continue;
                };
                if !health.accept_fault(&event.fault) {
                    continue;
                }
                publish_relay_status(&ctx).await;
                recover_relay_generation(
                    &ctx,
                    expected_epoch,
                    generation,
                    event.fault.kind.as_str(),
                )
                .await;
            }
            RelaySupervisorEvent::RetryRequested { server_generation } => {
                let Some((expected_epoch, health)) =
                    current_relay_context(&ctx, server_generation).await
                else {
                    continue;
                };
                if health.snapshot().state != RelayState::Failed {
                    continue;
                }
                recover_relay_generation(&ctx, expected_epoch, server_generation, "explicit_retry")
                    .await;
            }
        }
    }
}

async fn adopted_ip_set(app_handle: &tauri::AppHandle) -> std::collections::HashSet<String> {
    use tauri::Manager;

    let manager: tauri::State<'_, crate::network::NetworkManager> = app_handle.state();
    manager.get_adopted_ips().await.into_values().collect()
}

async fn recover_relay_generation(
    ctx: &RelaySupervisorContext,
    expected_epoch: u64,
    server_generation: u64,
    cause: &'static str,
) {
    use tauri::Manager;
    let recovery_started = tokio::time::Instant::now();
    // Retire and fully release the failed listener before applying backoff.
    // The lifecycle gate is also the Stop completion barrier.
    {
        let _lifecycle = ctx.relay_lifecycle.lock().await;
        if !relay_is_current(
            &ctx.state,
            &ctx.rtsp_epoch,
            expected_epoch,
            server_generation,
        )
        .await
        {
            return;
        }
        let failed_server = {
            let mut state = ctx.state.lock().await;
            if state
                .rtsp_server
                .as_ref()
                .is_some_and(|server| server.server_generation() == server_generation)
            {
                state.rtsp_server.take()
            } else {
                None
            }
        };
        if let Some(failed_server) = failed_server {
            failed_server.shutdown().await;
        }
    }
    publish_relay_status(ctx).await;
    if current_relay_context(ctx, server_generation)
        .await
        .is_some_and(|(_, h)| {
            h.snapshot().state == RelayState::Failed && h.snapshot().error.is_some()
        })
    {
        // A typed permanent media error is terminal until explicit Start.
        let state = ctx.state.lock().await;
        if state
            .rtsp_health
            .as_ref()
            .is_some_and(|h| h.permanent_failure())
        {
            return;
        }
    }

    loop {
        let Some((current_epoch, health)) = current_relay_context(ctx, server_generation).await
        else {
            return;
        };
        if current_epoch != expected_epoch {
            return;
        }

        let (attempt, delay) = health.schedule_recovery_attempt();
        let selection = ctx
            .app_handle
            .state::<crate::network::NetworkManager>()
            .adapter_selection_state()
            .await;
        log::info!("event=relay_recovery adapter_mac={} interface_index={} generation={} cause={} attempt={} phase=backoff delay_ms={} duration_ms={}",
            crate::network::log_value(selection.selected_mac.as_deref().unwrap_or("unknown")), selection.interface_index.unwrap_or(0),
            server_generation, cause, attempt, delay.as_millis(), recovery_started.elapsed().as_millis());
        publish_relay_status(ctx).await;
        if !wait_relay_backoff(
            &ctx.state,
            &ctx.rtsp_epoch,
            &ctx.relay_wake,
            expected_epoch,
            server_generation,
            delay,
        )
        .await
        {
            return;
        }
        health.mark_recovery_in_progress();
        publish_relay_status(ctx).await;

        let base_spec = {
            let state = ctx.state.lock().await;
            let Some(spec) = state.rtsp_spec.as_ref() else {
                return;
            };
            spec.clone()
        };
        let mut build_spec = base_spec.clone();

        if health.should_reresolve_explicit_bind() {
            if let Some(interface_name) = base_spec.bind_interface.as_deref() {
                let adopted = adopted_ip_set(&ctx.app_handle).await;
                if !relay_is_current(
                    &ctx.state,
                    &ctx.rtsp_epoch,
                    expected_epoch,
                    server_generation,
                )
                .await
                {
                    return;
                }
                match resolve_explicit_bind(Some(interface_name), &adopted).await {
                    Ok(Some(new_address)) => {
                        build_spec.bind_address = Some(new_address.clone());
                        build_spec.advertised_ip = new_address;
                    }
                    Ok(None) => unreachable!("an explicit interface resolves to an address"),
                    Err(error) => {
                        let reason = redact_relay_text(
                            &format!(
                                "RTSP bind interface '{}' is unavailable: {}",
                                interface_name, error
                            ),
                            &base_spec.mount_path,
                        );
                        health.mark_resolution_failed(reason);
                        health.force_max_backoff();
                        publish_relay_status(ctx).await;
                        continue;
                    }
                }
            }
        }

        let _lifecycle = ctx.relay_lifecycle.lock().await;
        if !relay_is_current(
            &ctx.state,
            &ctx.rtsp_epoch,
            expected_epoch,
            server_generation,
        )
        .await
        {
            return;
        }

        // Normally the first retirement already emptied this slot.  Recheck
        // under the gate so a duplicate or unusual callback can never leave
        // two listeners alive for one generation.
        let prior = {
            let mut state = ctx.state.lock().await;
            if state
                .rtsp_server
                .as_ref()
                .is_some_and(|server| server.server_generation() == server_generation)
            {
                state.rtsp_server.take()
            } else {
                None
            }
        };
        if let Some(prior) = prior {
            prior.shutdown().await;
        }
        if !relay_is_current(
            &ctx.state,
            &ctx.rtsp_epoch,
            expected_epoch,
            server_generation,
        )
        .await
        {
            return;
        }

        if let Err(error) = crate::ensure_gstreamer() {
            let server_instance = health.begin_server_instance(true);
            let reason = redact_relay_text(&error.to_string(), &build_spec.mount_path);
            health.mark_build_failed(server_instance, reason, false);
            drop(_lifecycle);
            publish_relay_status(ctx).await;
            continue;
        }

        let target = ctx.state.lock().await.rtsp_target.clone();
        if let Err(error) = preflight_target(Some(&ctx.app_handle), target.as_ref()).await {
            health.mark_resolution_failed(error.to_string());
            drop(_lifecycle);
            publish_relay_status(ctx).await;
            continue;
        }
        if !relay_is_current(
            &ctx.state,
            &ctx.rtsp_epoch,
            expected_epoch,
            server_generation,
        )
        .await
        {
            return;
        }
        let (server_instance, result) = StreamManager::build_rtsp_restreamer(
            &build_spec,
            health.clone(),
            ctx.relay_event_tx.clone(),
            true,
            relay_preflight(
                Some(ctx.app_handle.clone()),
                target,
                ctx.rtsp_epoch.clone(),
                expected_epoch,
                ctx.rtsp_generation.clone(),
                server_generation,
            ),
        );
        let server = match result {
            Ok(server) => server,
            Err(failure) => {
                let reason = redact_relay_text(&failure.error.to_string(), &build_spec.mount_path);
                health.mark_build_failed(
                    server_instance,
                    reason,
                    failure.kind == RtspBuildFailureKind::Bind,
                );
                drop(_lifecycle);
                publish_relay_status(ctx).await;
                continue;
            }
        };

        let mut candidate = Some(server);
        {
            let mut state = ctx.state.lock().await;
            if ctx.rtsp_epoch.load(std::sync::atomic::Ordering::Acquire) == expected_epoch
                && state.rtsp_intent_epoch == Some(expected_epoch)
                && relay_state_is_generation(&state, server_generation)
            {
                // Publish a re-resolved address only after it bound
                // successfully. Port, interface, mount, token, and source are
                // byte-for-byte inherited from the desired specification.
                state.rtsp_spec = Some(build_spec);
                state.rtsp_server = candidate.take();
            }
        }
        if let Some(stale) = candidate {
            crate::network::note_fence_drop("relay_listener");
            stale.shutdown().await;
            return;
        }
        log::info!("event=relay_recovery generation={} cause={} attempt={} phase=listener_ready duration_ms={}",
            server_generation, cause, attempt, recovery_started.elapsed().as_millis());

        drop(_lifecycle);
        publish_relay_status(ctx).await;
        return;
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

    let health = state.rtsp_health.as_ref().map(|health| health.snapshot());
    let current_generation = health.as_ref().map(|health| health.server_generation);
    let current_server = state
        .rtsp_server
        .as_ref()
        .filter(|server| Some(server.server_generation()) == current_generation);
    let (bandwidth, connected_clients, client_limit, listener_alive) = match current_server {
        Some(server) => (
            server.bandwidth_kbps(),
            server.connected_clients(),
            server.client_limit(),
            server.loop_alive() && health.as_ref().is_some_and(|health| health.loop_alive),
        ),
        None => (0.0, 0, MAX_RTSP_CLIENTS, false),
    };

    let playback = state.playback_health.as_ref().map(|h| h.snapshot());
    let playing = playback
        .as_ref()
        .is_some_and(|h| h.state == PlaybackState::Playing);
    let error = playback
        .as_ref()
        .and_then(|h| h.fault.as_ref().map(|f| f.reason.clone()));

    // Idle/stopped playback reports no audio; the cells live on the
    // pipeline instance, so stop and camera-switch resets are
    // structural rather than an explicit clear.
    let (audio_present, audio_codec) = state
        .playback
        .as_ref()
        .map(|p| p.audio_status())
        .unwrap_or((false, None));

    StreamStatus {
        playing,
        playback_desired: state.playback_settings.is_some(),
        playback_state: playback
            .as_ref()
            .map_or(PlaybackState::Stopped, |h| h.state),
        playback_fault: playback.as_ref().and_then(|h| h.fault.clone()),
        playback_recovery_attempt: playback.as_ref().map_or(0, |h| h.attempt),
        playback_next_retry_secs: playback.as_ref().and_then(|h| h.next_retry_secs),
        recording_report: state.recording_report.clone(),
        recording_finalized_path: state.recording_finalized_path.clone(),
        rtsp_server_running: listener_alive,
        rtsp_desired: state.rtsp_desired,
        rtsp_relay_state: if state.rtsp_desired {
            health
                .as_ref()
                .map(|health| health.state)
                .unwrap_or(RelayState::Starting)
        } else {
            RelayState::Stopped
        },
        rtsp_error: if state.rtsp_desired {
            health.as_ref().and_then(|health| health.error.clone())
        } else {
            None
        },
        rtsp_recovery_attempt: if state.rtsp_desired {
            health
                .as_ref()
                .map(|health| health.recovery_attempt)
                .unwrap_or(0)
        } else {
            0
        },
        rtsp_url: state
            .rtsp_desired
            .then(|| {
                state
                    .rtsp_spec
                    .as_ref()
                    .map(ResolvedRtspStartSpec::client_url)
            })
            .flatten(),
        display_url: state
            .rtsp_desired
            .then(|| {
                state
                    .rtsp_spec
                    .as_ref()
                    .map(ResolvedRtspStartSpec::display_url)
            })
            .flatten(),
        recording: state.recording,
        uptime_secs: uptime,
        bandwidth_kbps: bandwidth,
        rtsp_connected_clients: connected_clients,
        rtsp_client_limit: client_limit,
        error,
        audio_present,
        audio_codec,
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

async fn resolve_explicit_bind(
    interface_name: Option<&str>,
    adopted: &std::collections::HashSet<String>,
) -> Result<Option<String>, AppError> {
    let Some(interface_name) = interface_name else {
        return Ok(None);
    };
    let interface = crate::network::interface::get_by_name(interface_name).await?;
    first_usable_ip(&interface.ips, adopted)
        .map(Some)
        .ok_or_else(|| {
            AppError::Stream(format!(
                "Interface '{}' has no usable (non-adopted, non-APIPA) IPv4 address to bind",
                interface_name
            ))
        })
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

    fn init_gstreamer() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| gst::init().expect("GStreamer test initialization failed"));
    }

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

    #[tokio::test]
    async fn udp_bypasses_camera_mac_route_and_service_gate() {
        let mut settings = AppSettings::default();
        settings.stream.protocol = StreamProtocol::Udp;
        settings.stream.camera_ip = "169.254.1.204".into();
        assert!(stream_target(&settings).is_none());
        assert!(preflight_target(None, stream_target(&settings).as_ref())
            .await
            .unwrap()
            .is_none());
        settings.stream.protocol = StreamProtocol::Rtsp;
        assert!(preflight_target(None, stream_target(&settings).as_ref())
            .await
            .is_err());
    }

    fn playback_context(manager: &StreamManager) -> PlaybackSupervisorContext {
        PlaybackSupervisorContext {
            state: manager.state.clone(),
            status_tx: manager.status_tx.clone(),
            epoch: manager.playback_epoch.clone(),
            lifecycle: manager.playback_lifecycle.clone(),
            wake: manager.playback_wake.clone(),
            diagnostic: manager.playback_diagnostic.clone(),
            app: None,
        }
    }

    async fn seed_playback(manager: &StreamManager) -> Arc<PlaybackHealth> {
        let health = Arc::new(PlaybackHealth::new());
        let mut settings = AppSettings::default();
        settings.stream.camera_ip = "192.0.2.20".into();
        settings.stream.camera_mac = Some("aa:bb:cc:dd:ee:01".into());
        let mut s = manager.state.lock().await;
        s.playback_target = stream_target(&settings);
        s.playback_settings = Some(settings);
        s.playback_health = Some(health.clone());
        s.playback_intent_epoch = Some(0);
        health
    }

    #[tokio::test(start_paused = true)]
    async fn playback_owner_recovers_stable_fault_with_relay_off_and_no_status_repeats() {
        let manager = StreamManager::new();
        let h = seed_playback(&manager).await;
        let g = h.begin_attempt();
        h.record_fault(
            g,
            PlaybackFault::new(PlaybackFaultKind::BusError, "transport read error", true),
        );
        let ctx = playback_context(&manager);
        publish_playback_status(&ctx).await;
        let mut status = manager.status_tx.subscribe();
        status.borrow_and_update();
        publish_playback_status(&ctx).await;
        assert!(!status.has_changed().unwrap());
        let owner = tokio::spawn(run_playback_supervisor(ctx));
        tokio::task::yield_now().await;
        assert_eq!(h.snapshot().state, PlaybackState::Recovering);
        assert!(h.snapshot().attempt >= 1);
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(h.snapshot().generation > g); // attempted readiness without another error event
        assert!(!manager.status_tx.borrow().rtsp_desired);
        manager.stop_playback().await.unwrap();
        tokio::time::advance(std::time::Duration::from_secs(120)).await;
        tokio::task::yield_now().await;
        assert!(!manager.status_tx.borrow().playback_desired);
        assert!(manager.state.lock().await.playback.is_none());
        owner.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn readiness_wake_interrupts_long_backoff_and_rechecks_expected_identity() {
        for verified in [false, true] {
            let manager = StreamManager::new();
            let h = seed_playback(&manager).await;
            for _ in 0..6 {
                let g = h.begin_attempt();
                h.record_fault(
                    g,
                    PlaybackFault::new(PlaybackFaultKind::DeviceLoss, "not ready", true),
                );
                h.schedule_recovery();
            }
            assert_eq!(h.snapshot().next_retry_secs, Some(60));
            let g = h.snapshot().generation;
            let nic = Arc::new(Notify::new());
            let presence = Arc::new(Notify::new());
            let (n, p) = (nic.clone(), presence.clone());
            let waiter = tokio::spawn(async move {
                tokio::select! {
                    _ = wait_playback_ready(&n, p.notified()) => true,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => false,
                }
            });
            tokio::task::yield_now().await;
            if verified {
                presence.notify_one();
            } else {
                nic.notify_one();
            }
            assert!(waiter.await.unwrap());
            let mut previous = None;
            assert!(update_playback_readiness(
                &mut previous,
                Some((7, "192.0.2.10".parse().unwrap())),
                &h
            ));
            playback_step(&playback_context(&manager)).await;
            assert!(h.snapshot().generation > g);
            assert_eq!(
                h.snapshot().fault.unwrap().kind,
                PlaybackFaultKind::DeviceLoss
            );
            // A wake is not proof and cannot authorize a connection.
            assert!(manager.state.lock().await.playback.is_none());
            assert_eq!(
                manager
                    .state
                    .lock()
                    .await
                    .playback_target
                    .as_ref()
                    .unwrap()
                    .expected_mac
                    .as_deref(),
                Some("aa:bb:cc:dd:ee:01")
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stop_and_new_source_fence_backoff_and_late_completions() {
        let manager = StreamManager::new();
        let old = seed_playback(&manager).await;
        let ctx = playback_context(&manager);
        assert!(playback_is_current(&ctx, 0, &old).await);
        manager.stop_playback().await.unwrap();
        assert!(!playback_is_current(&ctx, 0, &old).await);
        let newer = seed_playback(&manager).await;
        manager.state.lock().await.playback_intent_epoch = Some(1);
        assert!(playback_is_current(&ctx, 1, &newer).await);
        assert!(!playback_is_current(&ctx, 1, &old).await);
        assert!(!old.observe_buffer(1, tokio::time::Instant::now()));
        manager.stop_playback().await.unwrap();
        assert!(manager.retry_playback(true, None).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_fresh_proof_does_not_collapse_transport_backoff() {
        let h = PlaybackHealth::new();
        for _ in 0..6 {
            let g = h.begin_attempt();
            h.record_fault(
                g,
                PlaybackFault::new(PlaybackFaultKind::BusError, "refused", true),
            );
            h.schedule_recovery();
        }
        let signature = Some((7, "192.0.2.10".parse().unwrap()));
        let mut previous = signature;
        assert!(!update_playback_readiness(&mut previous, signature, &h));
        assert_eq!(h.snapshot().next_retry_secs, Some(60));
        update_playback_readiness(&mut previous, None, &h);
        assert!(update_playback_readiness(&mut previous, signature, &h));
        assert!(h.due(tokio::time::Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn stop_beats_an_inflight_start_waiting_for_state_lock() {
        init_gstreamer();
        let manager = Arc::new(StreamManager::new());
        let held = manager.state.lock().await;
        let m = manager.clone();
        let start =
            tokio::spawn(async move { m.start_playback(&AppSettings::default(), None).await });
        tokio::task::yield_now().await;
        let m = manager.clone();
        let stop = tokio::spawn(async move { m.stop_playback().await });
        tokio::task::yield_now().await;
        drop(held);
        assert!(start.await.unwrap().is_err());
        stop.await.unwrap().unwrap();
        assert!(!compute_status(&manager.state).await.playback_desired);
    }

    #[tokio::test(start_paused = true)]
    async fn stop_cancels_the_owned_stall_diagnostic() {
        let manager = StreamManager::new();
        let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = completed.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            flag.store(true, std::sync::atomic::Ordering::Release);
        });
        *manager.playback_diagnostic.lock().unwrap() = Some(task);
        tokio::task::yield_now().await;
        manager.stop_playback().await.unwrap();
        tokio::time::advance(std::time::Duration::from_secs(20)).await;
        tokio::task::yield_now().await;
        assert!(!completed.load(std::sync::atomic::Ordering::Acquire));
        assert!(manager.playback_diagnostic.lock().unwrap().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_start_after_stop_keeps_its_new_intent() {
        init_gstreamer();
        let manager = Arc::new(StreamManager::new());
        seed_playback(&manager).await;
        let held = manager.state.lock().await;
        let m = manager.clone();
        let stop = tokio::spawn(async move { m.stop_playback().await });
        tokio::task::yield_now().await;
        let m = manager.clone();
        let start =
            tokio::spawn(async move { m.start_playback(&AppSettings::default(), None).await });
        tokio::task::yield_now().await;
        drop(held);
        stop.await.unwrap().unwrap();
        start.await.unwrap().unwrap();
        assert!(compute_status(&manager.state).await.playback_desired);
        assert_eq!(manager.state.lock().await.playback_intent_epoch, Some(2));
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_playback_fault_does_not_retry_on_ticks_or_reconnect() {
        let manager = StreamManager::new();
        let h = seed_playback(&manager).await;
        let g = h.begin_attempt();
        h.record_fault(
            g,
            PlaybackFault::new(PlaybackFaultKind::BusError, "Check credentials", false),
        );
        manager.retry_playback(false, None).await.unwrap();
        for _ in 0..3 {
            playback_step(&playback_context(&manager)).await;
        }
        assert_eq!(h.snapshot().generation, g);
        assert_eq!(h.snapshot().state, PlaybackState::Failed);
        manager.retry_playback(true, None).await.unwrap();
        assert!(h.due(tokio::time::Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn manual_retry_applies_corrections_without_rebinding_to_another_selection() {
        let manager = StreamManager::new();
        let old = seed_playback(&manager).await;
        let mut settings = AppSettings::default();
        settings.credentials.password = "corrected".into();
        settings.stream.rtsp_path = "/correct-path".into();
        settings.stream.camera_ip = "192.0.2.99".into();
        settings.stream.camera_mac = Some("aa:bb:cc:dd:ee:99".into());
        manager.retry_playback(true, Some(settings)).await.unwrap();
        let state = manager.state.lock().await;
        let desired = state.playback_settings.as_ref().unwrap();
        assert_eq!(desired.credentials.password, "corrected");
        assert_eq!(desired.stream.rtsp_path, "/correct-path");
        assert_eq!(desired.stream.camera_ip, "192.0.2.20");
        assert_eq!(
            desired.stream.camera_mac.as_deref(),
            Some("aa:bb:cc:dd:ee:01")
        );
        assert_eq!(state.playback_intent_epoch, Some(1));
        assert!(!Arc::ptr_eq(state.playback_health.as_ref().unwrap(), &old));
        assert_eq!(old.snapshot().state, PlaybackState::Stopped);
    }

    #[tokio::test]
    async fn preview_loss_finalizes_recording_and_keeps_relay_intent_untouched() {
        init_gstreamer();
        let manager = StreamManager::new();
        let h = seed_playback(&manager).await;
        seed_desired_relay(&manager, 8, 0).await;
        let g = h.begin_attempt();
        let p = Arc::new(PlaybackPipeline::test_headless(h.clone(), g));
        p.play().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("interrupted.mp4");
        p.attach_recording(path.to_str().unwrap()).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(350)).await;
        {
            let mut s = manager.state.lock().await;
            s.playback = Some(p);
            s.playback_instance = Some((0, g));
            s.recording = true;
            s.recording_path = Some(path.to_string_lossy().to_string());
        }
        h.record_fault(
            g,
            PlaybackFault::new(PlaybackFaultKind::DeviceLoss, "route changed", true),
        );
        playback_step(&playback_context(&manager)).await;
        let status = compute_status(&manager.state).await;
        assert!(!status.recording);
        assert_eq!(
            status.recording_report.as_deref(),
            Some("recording stopped: stream lost")
        );
        assert_eq!(status.recording_finalized_path.as_deref(), path.to_str());
        assert!(path.metadata().unwrap().len() > 0);
        assert!(status.rtsp_desired);
        assert_eq!(status.rtsp_relay_state, RelayState::Starting);
        assert!(manager.state.lock().await.playback.is_none());
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
            selected_adapter_mac: None,
            primary_addresses: std::collections::HashMap::new(),
            stream: StreamConfig {
                camera_mac: None,
                protocol,
                rtsp_port: 554,
                rtsp_path: "/live".into(),
                udp_port: 8600,
                camera_ip: camera_ip.into(),
                audio_muted: false,
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
            adopted_meta: std::collections::HashMap::new(),
            pending_addresses: Vec::new(),
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

    #[test]
    fn relay_redaction_removes_credentials_and_mount_token() {
        let mount = "/stream-super-secret-token";
        let raw =
            format!("failure at rtsp://admin:hunter2@10.0.0.5:554/live while serving {mount}");
        let redacted = redact_relay_text(&raw, mount);
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("super-secret-token"));
        assert!(redacted.contains("rtsp://admin:***@10.0.0.5:554/live"));
        assert!(redacted.contains("/stream-***"));
    }

    #[test]
    fn tcp_receive_policy_matches_runtime_capability() {
        init_gstreamer();
        let source = gst::ElementFactory::make("rtspsrc").build().unwrap();
        let supports_policy = ["tcp-timestamp", "drop-on-latency"].iter().all(|property| {
            source
                .find_property(property)
                .is_some_and(|spec| spec.value_type() == glib::Type::BOOL)
        });

        let result = configure_tcp_rtspsrc(&source);
        if supports_policy {
            result.unwrap();
            assert!(source.property::<bool>("tcp-timestamp"));
            assert!(source.property::<bool>("drop-on-latency"));
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.kind(), "Stream");
            assert!(error.to_string().contains("GStreamer"));
        }
    }

    #[test]
    fn tcp_receive_policy_missing_property_returns_stream_error() {
        init_gstreamer();
        let source = gst::ElementFactory::make("fakesrc").build().unwrap();
        let error = configure_tcp_rtspsrc(&source).unwrap_err();
        assert_eq!(error.kind(), "Stream");
        assert!(error.to_string().contains("tcp-timestamp"));
    }

    #[test]
    fn explicit_start_noop_requires_identical_identity_and_healthy_listener() {
        let spec = ResolvedRtspStartSpec {
            source: ResolvedSource::Rtsp {
                url: "rtsp://192.0.2.20/live".into(),
            },
            server_port: 8554,
            mount_path: "/stream-token".into(),
            bind_interface: Some("VPN".into()),
            bind_address: Some("192.0.2.10".into()),
            advertised_ip: "192.0.2.10".into(),
            username: "camera".into(),
            password: "secret".into(),
        };
        let is_noop = |candidate: &ResolvedRtspStartSpec, relay_state, loop_alive| {
            resolved_start_is_healthy_noop(
                true,
                Some(&spec),
                candidate,
                Some(relay_state),
                Some(9),
                Some(9),
                loop_alive,
            )
        };

        assert!(is_noop(&spec, RelayState::Listening, true));
        assert!(is_noop(&spec, RelayState::Streaming, true));
        assert!(!is_noop(&spec, RelayState::Recovering, true));
        assert!(!is_noop(&spec, RelayState::Listening, false));

        let mut address_changed = spec.clone();
        address_changed.advertised_ip = "192.0.2.11".into();
        assert!(!is_noop(&address_changed, RelayState::Listening, true));

        let mut credentials_changed = spec.clone();
        credentials_changed.password = "new-secret".into();
        assert!(!is_noop(&credentials_changed, RelayState::Listening, true));
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
        let s = make_settings(StreamProtocol::Udp, "169.254.1.1", "admin", "pass");
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

    #[tokio::test]
    async fn build_url_rejects_apipa_for_preview_and_relay() {
        let s = make_settings(StreamProtocol::Rtsp, "169.254.73.42", "", "");
        let error = StreamManager::build_input_url(&s).unwrap_err().to_string();
        assert!(error.contains("routable IPv4 address first"));
        assert!(
            StreamManager::resolve_rtsp_start_spec(&s, &std::collections::HashSet::new())
                .await
                .is_err()
        );
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
            rtsp_desired: true,
            rtsp_relay_state: RelayState::Recovering,
            rtsp_error: Some("camera unavailable".into()),
            rtsp_recovery_attempt: 2,
            rtsp_url: Some("rtsp://127.0.0.1:8554/stream-abc".into()),
            display_url: Some("rtsp://127.0.0.1:8554".into()),
            recording: false,
            uptime_secs: 120,
            bandwidth_kbps: 0.0,
            rtsp_connected_clients: 3,
            rtsp_client_limit: MAX_RTSP_CLIENTS,
            error: None,
            audio_present: true,
            audio_codec: Some("PCMU".into()),
            ..StreamStatus::idle()
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"playing\":true"));
        assert!(json.contains("\"uptime_secs\":120"));
        assert!(json.contains("\"display_url\":"));
        assert!(json.contains("\"rtsp_relay_state\":\"recovering\""));
        assert!(json.contains("\"rtsp_recovery_attempt\":2"));
        assert!(json.contains("\"rtsp_connected_clients\":3"));
        assert!(json.contains("\"rtsp_client_limit\":10"));
        assert!(json.contains("\"audio_present\":true"));
        assert!(json.contains("\"audio_codec\":\"PCMU\""));
    }

    #[test]
    fn stream_status_default_values() {
        let status = StreamStatus::idle();
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"rtsp_url\":null"));
        assert!(json.contains("\"display_url\":null"));
        assert!(json.contains("\"rtsp_connected_clients\":0"));
        assert!(json.contains("\"rtsp_client_limit\":10"));
        // Idle/stopped/video-only playback: no audio, no codec.
        assert!(json.contains("\"audio_present\":false"));
        assert!(json.contains("\"audio_codec\":null"));
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
        assert_eq!(status.rtsp_connected_clients, 0);
        assert_eq!(status.rtsp_client_limit, MAX_RTSP_CLIENTS);
    }

    #[tokio::test]
    async fn recovery_status_keeps_desired_urls_without_a_listener() {
        let manager = StreamManager::new();
        let spec = ResolvedRtspStartSpec {
            source: ResolvedSource::Rtsp {
                url: "rtsp://192.0.2.20/live".into(),
            },
            server_port: 8554,
            mount_path: "/stream-stable-token".into(),
            bind_interface: Some("VPN".into()),
            bind_address: Some("192.0.2.10".into()),
            advertised_ip: "192.0.2.10".into(),
            username: "camera".into(),
            password: "password".into(),
        };
        let expected_client_url = spec.client_url();
        let expected_display_url = spec.display_url();
        let health = Arc::new(RelayRuntimeHealth::new(1, spec.ingest_kind()));
        health.schedule_recovery_attempt();
        health.mark_recovery_in_progress();
        {
            let mut state = manager.state.lock().await;
            state.rtsp_desired = true;
            state.rtsp_spec = Some(spec);
            state.rtsp_health = Some(health);
            state.rtsp_intent_epoch = Some(0);
            state.rtsp_start_time = Some(std::time::Instant::now());
        }

        let status = compute_status(&manager.state).await;
        assert!(status.rtsp_desired);
        assert!(!status.rtsp_server_running);
        assert_eq!(status.rtsp_relay_state, RelayState::Recovering);
        assert_eq!(
            status.rtsp_url.as_deref(),
            Some(expected_client_url.as_str())
        );
        assert_eq!(
            status.display_url.as_deref(),
            Some(expected_display_url.as_str())
        );
    }

    async fn seed_desired_relay(manager: &StreamManager, generation: u64, epoch: u64) {
        let mut state = manager.state.lock().await;
        state.rtsp_desired = true;
        state.rtsp_health = Some(Arc::new(RelayRuntimeHealth::new(
            generation,
            relay::RelayIngestKind::Rtsp,
        )));
        state.rtsp_intent_epoch = Some(epoch);
    }

    #[tokio::test(start_paused = true)]
    async fn stop_interrupts_every_nonzero_recovery_backoff() {
        for delay in relay::RECOVERY_DELAYS
            .into_iter()
            .filter(|delay| !delay.is_zero())
        {
            let manager = StreamManager::new();
            seed_desired_relay(&manager, 1, 0).await;
            let state = manager.state.clone();
            let epoch = manager.rtsp_epoch.clone();
            let wake = manager.relay_wake.clone();
            let started_at = tokio::time::Instant::now();
            let waiter = tokio::spawn(async move {
                wait_relay_backoff(&state, &epoch, &wake, 0, 1, delay).await
            });
            tokio::task::yield_now().await;

            manager
                .rtsp_epoch
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            manager.relay_wake.notify_waiters();
            assert!(!waiter.await.unwrap());
            assert!(tokio::time::Instant::now().duration_since(started_at) < delay);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn newer_manual_generation_interrupts_old_backoff() {
        let manager = StreamManager::new();
        seed_desired_relay(&manager, 1, 0).await;
        let state = manager.state.clone();
        let epoch = manager.rtsp_epoch.clone();
        let wake = manager.relay_wake.clone();
        let waiter = tokio::spawn(async move {
            wait_relay_backoff(
                &state,
                &epoch,
                &wake,
                0,
                1,
                std::time::Duration::from_secs(60),
            )
            .await
        });
        tokio::task::yield_now().await;

        {
            let mut state = manager.state.lock().await;
            state.rtsp_health = Some(Arc::new(RelayRuntimeHealth::new(
                2,
                relay::RelayIngestKind::Rtsp,
            )));
        }
        manager.relay_wake.notify_waiters();
        assert!(!waiter.await.unwrap());
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
    fn status_publisher_emits_when_only_client_count_changes() {
        let initial = StreamStatus::idle();
        let (tx, mut rx) = watch::channel(initial.clone());
        rx.borrow_and_update();

        let mut updated = initial;
        updated.rtsp_connected_clients = 1;
        publish_status_if_changed(&tx, updated.clone());

        assert!(rx.has_changed().unwrap());
        assert_eq!(rx.borrow_and_update().rtsp_connected_clients, 1);

        publish_status_if_changed(&tx, updated);
        assert!(!rx.has_changed().unwrap());
    }

    #[test]
    fn stream_manager_video_hwnd_roundtrip() {
        let mgr = StreamManager::new();
        assert!(mgr.get_video_child_hwnd().is_none());
        mgr.set_video_child_hwnd(0x12345);
        assert_eq!(mgr.get_video_child_hwnd(), Some(0x12345));
    }

    #[test]
    fn stale_stop_does_not_clear_replacement_video_hwnd() {
        let mgr = StreamManager::new();
        mgr.set_video_child_hwnd(0x12345);
        mgr.set_video_child_hwnd(0x67890);

        assert!(!mgr.clear_video_child_hwnd_if(0x12345));
        assert_eq!(mgr.get_video_child_hwnd(), Some(0x67890));
        assert!(mgr.clear_video_child_hwnd_if(0x67890));
        assert!(mgr.get_video_child_hwnd().is_none());
    }
}
