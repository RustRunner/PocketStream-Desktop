pub mod audio;
mod caller_registry;
mod classify;
pub mod recorder;
mod relay;
pub mod rtsp_client;
pub mod rtsp_server;
mod rtsp_transport;
mod srt_server;
pub mod video_embed;

use serde::Serialize;
use std::sync::Arc;
use tokio::sync::{watch, Mutex, Notify};

use gstreamer as gst;
use gstreamer::prelude::*;

use crate::config::{
    AppConfig, AppSettings, RestreamProtocol, RestreamSettingsUpdate, SrtPassphraseState,
    StreamProtocol,
};
use crate::error::AppError;
use crate::network::route::{CameraTarget, ReadyPath};
use crate::network::{
    bindings::{self, BindScope},
    firewall::{self, FirewallOutcome, FirewallRule},
};

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

/// Install the SETUP-time policy shared by RTSP and SRT outputs that ingest
/// from an RTSP camera. Only the first video stream is accepted; audio,
/// duplicate video, and other media are declined before their SETUP request.
pub(super) fn connect_video_only_select_stream(src: &gst::Element) -> glib::SignalHandlerId {
    let selection = audio::SelectionState::default();
    src.connect("select-stream", false, move |values| {
        let caps = values
            .get(2)
            .and_then(|value| value.get::<gst::Caps>().ok());
        let kind = caps
            .as_ref()
            .map(|caps| audio::classify_rtp_caps(caps).0)
            .unwrap_or(audio::MediaKind::Other);
        let accept = selection.select_video_only(kind);
        if !accept {
            log::info!("Re-stream: declining non-video stream at SETUP");
        }
        // Dynamic signal marshalling requires a gboolean return value.
        Some(accept.to_value())
    })
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
pub struct RestreamServerInfo {
    pub bind_scope: BindScope,
    pub firewall: FirewallOutcome,
    pub protocol: RestreamProtocol,
    pub server_url: String,
    pub display_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestreamOperationResult {
    pub selected_protocol: RestreamProtocol,
    pub desired: bool,
    pub server_info: Option<RestreamServerInfo>,
}

use relay::{PlaybackFault, PlaybackFaultKind, PlaybackHealth, PlaybackState};
use relay::{
    RelayEventReceiver, RelayEventSender, RelayFaultEvent, RelayRuntimeHealth, RelayState,
    RelaySupervisorEvent, ResolvedOutput, ResolvedSource, ResolvedStartSpec, RestreamBuildFailure,
    RestreamBuildFailureKind, RestreamRuntimeContext,
};
use rtsp_client::PlaybackPipeline;
use rtsp_server::{RtspRestreamer, RtspRuntimeProbe, MAX_RTSP_CLIENTS};
use srt_server::{SrtRestreamer, SrtRuntimeProbe};

enum RestreamServer {
    Rtsp(RtspRestreamer),
    Srt(SrtRestreamer),
}

#[derive(Clone)]
enum RelayFaultProbe {
    Rtsp(RtspRuntimeProbe),
    Srt(SrtRuntimeProbe),
}

impl RelayFaultProbe {
    fn poll_fault(&self) -> Option<RelayFaultEvent> {
        match self {
            Self::Rtsp(probe) => probe.poll_fault(),
            Self::Srt(probe) => probe.poll_fault(),
        }
    }
}

impl RestreamServer {
    fn protocol(&self) -> RestreamProtocol {
        match self {
            Self::Rtsp(_) => RestreamProtocol::Rtsp,
            Self::Srt(_) => RestreamProtocol::Srt,
        }
    }

    fn server_generation(&self) -> u64 {
        match self {
            Self::Rtsp(server) => server.server_generation(),
            Self::Srt(server) => server.server_generation(),
        }
    }

    fn connected_clients(&self) -> u32 {
        match self {
            Self::Rtsp(server) => server.connected_clients(),
            Self::Srt(server) => server.connected_clients(),
        }
    }

    fn client_limit(&self) -> u32 {
        match self {
            Self::Rtsp(server) => server.client_limit(),
            Self::Srt(server) => server.client_limit(),
        }
    }

    fn bandwidth_kbps(&self) -> f64 {
        match self {
            Self::Rtsp(server) => server.bandwidth_kbps(),
            Self::Srt(server) => server.bandwidth_kbps(),
        }
    }

    fn fault_probe(&self) -> RelayFaultProbe {
        match self {
            Self::Rtsp(server) => RelayFaultProbe::Rtsp(server.fault_probe()),
            Self::Srt(server) => RelayFaultProbe::Srt(server.fault_probe()),
        }
    }

    fn loop_alive(&self) -> bool {
        match self {
            Self::Rtsp(server) => server.loop_alive(),
            Self::Srt(server) => server.loop_alive(),
        }
    }

    fn udp_ingest_port(&self) -> Option<u16> {
        match self {
            Self::Rtsp(server) => server.udp_ingest_port(),
            Self::Srt(server) => server.udp_ingest_port(),
        }
    }

    async fn shutdown(&mut self) {
        match self {
            Self::Rtsp(server) => server.shutdown().await,
            Self::Srt(server) => server.shutdown().await,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StreamStatus {
    pub bind_scope: BindScope,
    pub firewall: FirewallOutcome,
    pub playing: bool,
    pub playback_desired: bool,
    pub playback_state: PlaybackState,
    pub playback_fault: Option<PlaybackFault>,
    pub playback_recovery_attempt: u32,
    pub playback_next_retry_secs: Option<u64>,
    pub recording_report: Option<String>,
    pub recording_finalized_path: Option<String>,
    pub selected_protocol: RestreamProtocol,
    pub active_protocol: Option<RestreamProtocol>,
    pub server_running: bool,
    pub desired: bool,
    pub relay_state: RelayState,
    pub relay_error: Option<String>,
    pub recovery_attempt: u32,
    pub server_url: Option<String>,
    pub display_url: Option<String>,
    pub recording: bool,
    pub uptime_secs: u64,
    pub bandwidth_kbps: f64,
    pub connected_clients: u32,
    pub client_limit: u32,
    pub error: Option<String>,
    /// True while the playback pipeline has a linked audio branch.
    pub audio_present: bool,
    /// Last recognized audio codec the camera offered. May be `Some`
    /// with `audio_present == false` when the codec was recognized but
    /// skipped (decoder chain unavailable).
    pub audio_codec: Option<String>,
}

impl StreamStatus {
    fn idle(selected_protocol: RestreamProtocol) -> Self {
        Self {
            bind_scope: BindScope::default(),
            firewall: FirewallOutcome::Inactive,
            playing: false,
            playback_desired: false,
            playback_state: PlaybackState::Stopped,
            playback_fault: None,
            playback_recovery_attempt: 0,
            playback_next_retry_secs: None,
            recording_report: None,
            recording_finalized_path: None,
            selected_protocol,
            active_protocol: None,
            server_running: false,
            desired: false,
            relay_state: RelayState::Stopped,
            relay_error: None,
            recovery_attempt: 0,
            server_url: None,
            display_url: None,
            recording: false,
            uptime_secs: 0,
            bandwidth_kbps: 0.0,
            connected_clients: 0,
            client_limit: MAX_RTSP_CLIENTS,
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
    /// Bumped when a user Start or Stop establishes a new desired-state
    /// intent. The intent is published before waiting on transaction or
    /// lifecycle serialization, so a later request invalidates slow interface
    /// resolution, recovery, or candidate construction immediately.
    restream_epoch: Arc<std::sync::atomic::AtomicU64>,
    /// Generation allocated by each full explicit Start. Automatic rebuilds
    /// remain in that generation; a newer Start invalidates older work.
    restream_generation: Arc<std::sync::atomic::AtomicU64>,
    /// Serializes complete user start/stop/settings/switch transactions.
    restream_transaction: Arc<Mutex<()>>,
    /// Serializes listener take/shutdown/build/store work without ever holding
    /// the shared StreamState lock across a slow operation.
    relay_lifecycle: Arc<Mutex<()>>,
    /// Promptly wakes recovery backoff after Stop or a newer Start. Epoch and
    /// generation checks remain the cancellation authority.
    relay_wake: Arc<Notify>,
    relay_event_tx: RelayEventSender,
    relay_event_rx: std::sync::Mutex<Option<RelayEventReceiver>>,
    /// Same stop-beats-start protocol as `restream_epoch`, for the playback
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
    firewall: FirewallOutcome,
    firewall_generation: Option<(u64, FirewallRule)>,
    playback_target: Option<CameraTarget>,
    restream_target: Option<CameraTarget>,
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
    selected_protocol: RestreamProtocol,
    restream_server: Option<RestreamServer>,
    restream_desired: bool,
    restream_spec: Option<ResolvedStartSpec>,
    restream_health: Option<Arc<RelayRuntimeHealth>>,
    /// Re-stream epoch captured by the explicit Start that installed the current
    /// desired state.  This lets a Stop distinguish an older in-flight Start
    /// from a newer Start that began after the Stop invalidated the epoch.
    restream_intent_epoch: Option<u64>,
    recording: bool,
    recording_path: Option<String>,
    start_time: Option<std::time::Instant>,
    restream_start_time: Option<std::time::Instant>,
    /// Source the running playback was started with (None when idle).
    playback_source: Option<SourceMode>,
}

#[derive(Debug, Clone, Copy)]
struct RestreamStopIntent {
    epoch: u64,
    target_generation: Option<u64>,
    firewall_generation: Option<u64>,
    was_desired: bool,
}

#[derive(Clone)]
struct RelaySupervisorContext {
    state: Arc<Mutex<StreamState>>,
    status_tx: Arc<watch::Sender<StreamStatus>>,
    restream_epoch: Arc<std::sync::atomic::AtomicU64>,
    relay_lifecycle: Arc<Mutex<()>>,
    relay_wake: Arc<Notify>,
    relay_event_tx: RelayEventSender,
    app_handle: tauri::AppHandle,
    restream_generation: Arc<std::sync::atomic::AtomicU64>,
}

impl StreamManager {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_selected_protocol(RestreamProtocol::Rtsp)
    }

    pub fn with_selected_protocol(selected_protocol: RestreamProtocol) -> Self {
        let (status_tx, _) = watch::channel(StreamStatus::idle(selected_protocol));
        let (relay_event_tx, relay_event_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            app_handle: std::sync::Mutex::new(None),
            state: Arc::new(Mutex::new(StreamState {
                playback_target: None,
                restream_target: None,
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
                selected_protocol,
                firewall: FirewallOutcome::Inactive,
                firewall_generation: None,
                restream_server: None,
                restream_desired: false,
                restream_spec: None,
                restream_health: None,
                restream_intent_epoch: None,
                recording: false,
                recording_path: None,
                start_time: None,
                restream_start_time: None,
                playback_source: None,
            })),
            video_hwnd: Arc::new(std::sync::atomic::AtomicIsize::new(0)),
            status_tx: Arc::new(status_tx),
            restream_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            restream_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            restream_transaction: Arc::new(Mutex::new(())),
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
            && ((state.restream_desired
                && state
                    .restream_spec
                    .as_ref()
                    .and_then(ResolvedStartSpec::udp_ingest_port)
                    == Some(settings.stream.udp_port))
                || state
                    .restream_server
                    .as_ref()
                    .and_then(|s| s.udp_ingest_port())
                    == Some(settings.stream.udp_port))
        {
            return Err(AppError::Stream(format!("UDP port {} is already claimed by the re-stream server. Stop it first or switch the input to RTSP.", settings.stream.udp_port)));
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

    async fn resolve_restream_start_spec(
        settings: &AppSettings,
        adopted: &std::collections::HashSet<String>,
    ) -> Result<ResolvedStartSpec, AppError> {
        let (bind_interface, output) = resolve_selected_restream_output(settings)?;
        let source = match settings.stream.protocol {
            StreamProtocol::Rtsp => ResolvedSource::Rtsp {
                url: Self::build_input_url(settings)?,
            },
            StreamProtocol::Udp => ResolvedSource::Udp {
                port: settings.stream.udp_port,
            },
        };
        let saved_id = match settings.restream_protocol {
            RestreamProtocol::Rtsp => settings.rtsp_server.bind_interface_id.as_deref(),
            RestreamProtocol::Srt => settings.srt_server.bind_interface_id.as_deref(),
        };
        // An unresolved legacy alias remains unavailable until explicitly chosen.
        if bind_interface.is_some() && saved_id.is_none() && !cfg!(test) {
            return Err(AppError::Stream(
                "Choose the unavailable saved bind interface again to establish its identity"
                    .into(),
            ));
        }
        let (bind_identity, bind_scope) =
            match bindings::resolve(bind_interface.as_deref(), saved_id, adopted).await {
                Ok(resolved) => resolved,
                Err(error) if bind_interface.is_none() => (
                    None,
                    BindScope::Unknown {
                        reason: error.to_string(),
                    },
                ),
                Err(error) => return Err(error),
            };
        let bind_address = match &bind_scope {
            BindScope::Interface { address, .. } => Some(address.clone()),
            _ => None,
        };
        let bind_interface = bind_identity
            .as_ref()
            .map(|i| i.alias.clone())
            .or(bind_interface);
        let advertised_ip = match &bind_address {
            Some(ip) => ip.clone(),
            None => get_display_ip(adopted)
                .await
                .unwrap_or_else(|| "0.0.0.0".into()),
        };
        log::info!(
            "Re-stream bind selection: interface={:?} bind={:?} advertise={}",
            bind_interface,
            bind_address,
            advertised_ip
        );
        Ok(ResolvedStartSpec {
            source,
            output,
            bind_interface,
            bind_identity,
            bind_scope,
            bind_address,
            advertised_ip,
            username: settings.credentials.username.clone(),
            password: settings.credentials.password.clone(),
        })
    }

    fn build_restream_server(
        spec: &ResolvedStartSpec,
        health: Arc<RelayRuntimeHealth>,
        event_tx: RelayEventSender,
        recovering: bool,
        upstream_ready: Option<rtsp_server::UpstreamReady>,
    ) -> (u64, Result<RestreamServer, RestreamBuildFailure>) {
        let server_instance = health.begin_server_instance(recovering);
        let runtime = RestreamRuntimeContext {
            health,
            event_tx,
            server_instance,
            upstream_ready,
        };
        let result = match (&spec.output, &spec.source) {
            (
                ResolvedOutput::Rtsp {
                    server_port,
                    mount_path,
                },
                ResolvedSource::Udp { port },
            ) => RtspRestreamer::start_from_udp(
                *port,
                *server_port,
                mount_path,
                spec.bind_address.as_deref(),
                runtime,
            )
            .map(RestreamServer::Rtsp),
            (
                ResolvedOutput::Rtsp {
                    server_port,
                    mount_path,
                },
                ResolvedSource::Rtsp { url },
            ) => RtspRestreamer::start_from_rtsp(
                url,
                *server_port,
                mount_path,
                spec.bind_address.as_deref(),
                &spec.username,
                &spec.password,
                runtime,
            )
            .map(RestreamServer::Rtsp),
            (
                ResolvedOutput::Srt {
                    server_port,
                    passphrase,
                    latency_ms,
                    stream_id,
                },
                ResolvedSource::Udp { port },
            ) => SrtRestreamer::start_from_udp(
                *port,
                *server_port,
                spec.bind_address.as_deref(),
                (!passphrase.is_empty()).then_some(passphrase.as_str()),
                *latency_ms,
                stream_id,
                runtime,
            )
            .map(RestreamServer::Srt),
            (
                ResolvedOutput::Srt {
                    server_port,
                    passphrase,
                    latency_ms,
                    stream_id,
                },
                ResolvedSource::Rtsp { url },
            ) => SrtRestreamer::start_from_rtsp(
                url,
                *server_port,
                spec.bind_address.as_deref(),
                &spec.username,
                &spec.password,
                (!passphrase.is_empty()).then_some(passphrase.as_str()),
                *latency_ms,
                stream_id,
                runtime,
            )
            .map(RestreamServer::Srt),
        };
        (server_instance, result)
    }

    async fn publish_restream_start_intent(&self, start_epoch: u64) -> Option<(u64, bool)> {
        self.relay_wake.notify_waiters();

        let preserve_prior_desired = {
            let mut state = self.state.lock().await;
            // A later Start/Stop may advance the epoch between this request's
            // atomic claim and its state-lock acquisition. Never let the
            // stale request reassert desired state after that newer intent.
            if self
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                != start_epoch
            {
                return None;
            }
            let preserve = state.restream_desired
                && state.restream_spec.is_some()
                && state.restream_health.is_some();
            state.restream_desired = true;
            state.restream_intent_epoch = Some(start_epoch);
            if !preserve {
                state.restream_start_time = Some(std::time::Instant::now());
            }
            preserve
        };
        self.refresh_status().await;
        Some((start_epoch, preserve_prior_desired))
    }

    async fn begin_restream_start_intent(&self) -> Option<(u64, bool)> {
        let start_epoch = self
            .restream_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .wrapping_add(1);
        self.publish_restream_start_intent(start_epoch).await
    }

    async fn begin_restream_start_intent_if_current(
        &self,
        expected_epoch: u64,
    ) -> Option<(u64, bool)> {
        let start_epoch = expected_epoch.wrapping_add(1);
        self.restream_epoch
            .compare_exchange(
                expected_epoch,
                start_epoch,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .ok()?;
        self.publish_restream_start_intent(start_epoch).await
    }

    async fn restream_intent_is_current(&self, expected_epoch: u64) -> bool {
        if self
            .restream_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != expected_epoch
        {
            return false;
        }
        let state = self.state.lock().await;
        self.restream_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            == expected_epoch
            && state.restream_desired
            && state.restream_intent_epoch == Some(expected_epoch)
    }

    async fn current_restream_epoch_and_desired(&self) -> (u64, bool) {
        loop {
            let epoch = self
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire);
            let desired = self.state.lock().await.restream_desired;
            if self
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                == epoch
            {
                return (epoch, desired);
            }
        }
    }

    async fn cancel_restream_start_intent(&self, start_epoch: u64, preserve_prior_desired: bool) {
        if self
            .restream_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != start_epoch
        {
            return;
        }

        let retry_generation = {
            let mut state = self.state.lock().await;
            if self
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                != start_epoch
                || state.restream_intent_epoch != Some(start_epoch)
            {
                return;
            }
            if preserve_prior_desired {
                state.restream_health.as_ref().and_then(|health| {
                    matches!(
                        health.snapshot().state,
                        RelayState::Failed | RelayState::Recovering
                    )
                    .then(|| health.server_generation())
                })
            } else {
                if let Some(health) = state.restream_health.as_ref() {
                    health.stop();
                }
                state.restream_desired = false;
                state.restream_spec = None;
                state.restream_health = None;
                state.restream_intent_epoch = None;
                state.restream_start_time = None;
                None
            }
        };

        if let Some(server_generation) = retry_generation {
            let _ = self
                .relay_event_tx
                .send(RelaySupervisorEvent::RetryRequested { server_generation });
        }
        self.refresh_status().await;
    }

    pub async fn start_restream_server(
        &self,
        config: &AppConfig,
        adopted: &std::collections::HashSet<String>,
    ) -> Result<RestreamServerInfo, AppError> {
        let initial = crate::settings_validation::validate_prospective_settings(config.get())?;
        if !initial.rtsp_server.enabled {
            return Err(AppError::Validation(
                "Re-stream Server Enable must be on before starting".into(),
            ));
        }
        validate_selected_restream_startable(&initial)?;

        // Publish intent before waiting for another user transaction or doing
        // interface resolution. A later Stop/Start can therefore supersede
        // this operation immediately by advancing the epoch.
        let Some((start_epoch, preserve_prior_desired)) = self.begin_restream_start_intent().await
        else {
            return Err(AppError::Stream(
                "Re-stream server start was superseded by a newer request".into(),
            ));
        };
        let _transaction = self.restream_transaction.lock().await;
        if !self.restream_intent_is_current(start_epoch).await {
            return Err(AppError::Stream(
                "Re-stream server start was superseded by a newer request".into(),
            ));
        }

        // Re-read after serialization so a settings apply that committed
        // while this Start was queued is authoritative.
        let settings = match crate::settings_validation::validate_prospective_settings(config.get())
        {
            Ok(settings) => settings,
            Err(error) => {
                self.cancel_restream_start_intent(start_epoch, preserve_prior_desired)
                    .await;
                return Err(error);
            }
        };
        if !settings.rtsp_server.enabled {
            self.cancel_restream_start_intent(start_epoch, false).await;
            return Err(AppError::Validation(
                "Re-stream Server Enable must be on before starting".into(),
            ));
        }
        if let Err(error) = validate_selected_restream_startable(&settings) {
            self.cancel_restream_start_intent(start_epoch, preserve_prior_desired)
                .await;
            return Err(error);
        }
        self.start_restream_server_inner(&settings, adopted, start_epoch, preserve_prior_desired)
            .await
    }

    async fn start_restream_server_inner(
        &self,
        settings: &AppSettings,
        adopted: &std::collections::HashSet<String>,
        start_epoch: u64,
        preserve_prior_desired: bool,
    ) -> Result<RestreamServerInfo, AppError> {
        let handle = self
            .app_handle
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut target = stream_target(settings);
        match preflight_target(handle.as_ref(), target.as_ref()).await {
            Ok(Some(path)) => target = Some(path.target),
            Ok(None) => {}
            Err(error) => {
                self.cancel_restream_start_intent(start_epoch, preserve_prior_desired)
                    .await;
                return Err(error);
            }
        }
        let spec = match Self::resolve_restream_start_spec(settings, adopted).await {
            Ok(spec) => spec,
            Err(error) => {
                self.cancel_restream_start_intent(start_epoch, preserve_prior_desired)
                    .await;
                return Err(error);
            }
        };
        if self
            .restream_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != start_epoch
        {
            return Err(AppError::Stream(
                "Re-stream server start was superseded by a stop".into(),
            ));
        }

        let mut info = RestreamServerInfo {
            bind_scope: spec.bind_scope.clone(),
            firewall: FirewallOutcome::Inactive,
            protocol: spec.protocol(),
            server_url: spec.client_url(),
            display_url: spec.display_url(),
        };

        let (server_generation, health) = {
            let mut state = self.state.lock().await;
            if self
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                != start_epoch
            {
                return Err(AppError::Stream(
                    "Re-stream server start was superseded by a stop".into(),
                ));
            }

            let health_snapshot = state
                .restream_health
                .as_ref()
                .map(|health| health.snapshot());
            let healthy_noop = resolved_start_is_healthy_noop(
                state.restream_desired,
                state.restream_spec.as_ref(),
                &spec,
                health_snapshot.as_ref().map(|health| health.state),
                health_snapshot
                    .as_ref()
                    .map(|health| health.server_generation),
                state
                    .restream_server
                    .as_ref()
                    .map(RestreamServer::server_generation),
                state
                    .restream_server
                    .as_ref()
                    .is_some_and(RestreamServer::loop_alive),
            );
            if healthy_noop && state.restream_target == target {
                log::info!(
                    "Explicit re-stream Start resolved to the healthy current endpoint; no-op"
                );
                info.firewall = state.firewall.clone();
                return Ok(info);
            }

            if let Some(udp_port) = spec.udp_ingest_port() {
                if state.playback_source == Some(SourceMode::Udp { port: udp_port }) {
                    let error = AppError::Stream(format!(
                        "UDP port {} is already claimed by the running preview - only one consumer can receive a UDP stream. Stop the stream first, or switch the input to RTSP.",
                        udp_port
                    ));
                    drop(state);
                    self.cancel_restream_start_intent(start_epoch, preserve_prior_desired)
                        .await;
                    return Err(error);
                }
            }

            let server_generation = self
                .restream_generation
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
                .wrapping_add(1);
            let health = Arc::new(RelayRuntimeHealth::new(
                server_generation,
                spec.ingest_kind(),
            ));
            state.restream_target = target.clone();
            state.restream_spec = Some(spec.clone());
            state.restream_health = Some(health.clone());
            state.restream_start_time = Some(std::time::Instant::now());
            (server_generation, health)
        };

        self.relay_wake.notify_waiters();
        self.refresh_status().await;

        let gst_error = preflight_restream(&spec).err();
        let _lifecycle = self.relay_lifecycle.lock().await;
        if !relay_is_current(
            &self.state,
            &self.restream_epoch,
            start_epoch,
            server_generation,
        )
        .await
        {
            return Err(AppError::Stream(
                "Re-stream server start was superseded by a newer request".into(),
            ));
        }

        let old_server = {
            let mut state = self.state.lock().await;
            if !relay_state_is_generation(&state, server_generation)
                || state.restream_intent_epoch != Some(start_epoch)
            {
                return Err(AppError::Stream(
                    "Re-stream server start was superseded by a newer request".into(),
                ));
            }
            state.restream_server.take()
        };
        if let Some(mut old_server) = old_server {
            let generation = old_server.server_generation();
            old_server.shutdown().await;
            retire_firewall(&self.state, generation).await;
        }

        if !relay_is_current(
            &self.state,
            &self.restream_epoch,
            start_epoch,
            server_generation,
        )
        .await
        {
            return Err(AppError::Stream(
                "Re-stream server start was superseded by a newer request".into(),
            ));
        }

        if let Some(error) = gst_error {
            let server_instance = health.begin_server_instance(false);
            let reason = redact_relay_text(&error.to_string(), spec.mount_path());
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
        if bindings::revision() != scope_revision(&spec.bind_scope) {
            health.mark_resolution_failed(
                "Bind topology changed during preflight; resolving again".into(),
            );
            let _ = self
                .relay_event_tx
                .send(RelaySupervisorEvent::RetryRequested { server_generation });
            return Err(AppError::Stream(
                "Bind topology changed; listener recovery is pending".into(),
            ));
        }
        info.firewall = apply_firewall(&self.state, &spec, server_generation).await;
        if !relay_is_current(
            &self.state,
            &self.restream_epoch,
            start_epoch,
            server_generation,
        )
        .await
            || bindings::revision() != scope_revision(&spec.bind_scope)
        {
            retire_firewall(&self.state, server_generation).await;
            if self
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                == start_epoch
            {
                health.mark_resolution_failed(
                    "Bind topology changed during policy reconciliation".into(),
                );
                let _ = self
                    .relay_event_tx
                    .send(RelaySupervisorEvent::RetryRequested { server_generation });
            }
            return Err(AppError::Stream(
                "Listener start superseded during Windows rule reconciliation".into(),
            ));
        }
        let (server_instance, built) = Self::build_restream_server(
            &spec,
            health.clone(),
            self.relay_event_tx.clone(),
            false,
            relay_preflight(
                handle.clone(),
                target.clone(),
                health.clone(),
                self.restream_generation.clone(),
                server_generation,
            ),
        );
        let server = match built {
            Ok(server) => server,
            Err(failure) => {
                retire_firewall(&self.state, server_generation).await;
                let reason = redact_relay_text(&failure.error.to_string(), spec.mount_path());
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
            if self
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                == start_epoch
                && state.restream_intent_epoch == Some(start_epoch)
                && relay_state_is_generation(&state, server_generation)
                && bindings::revision() == scope_revision(&spec.bind_scope)
            {
                state.restream_server = candidate.take();
            }
        }
        if let Some(mut stale) = candidate {
            stale.shutdown().await;
            retire_firewall(&self.state, server_generation).await;
            if self
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                == start_epoch
            {
                health.mark_resolution_failed(
                    "Bind topology changed during listener construction".into(),
                );
                let _ = self
                    .relay_event_tx
                    .send(RelaySupervisorEvent::RetryRequested { server_generation });
            }
            return Err(AppError::Stream(
                "Re-stream server start was superseded by a newer request".into(),
            ));
        }

        drop(_lifecycle);
        self.refresh_status().await;
        Ok(info)
    }

    pub async fn stop_restream_server(&self) -> Result<(), AppError> {
        // Invalidate an in-flight Start/recovery before waiting for the user
        // transaction gate. The teardown itself remains serialized below.
        let intent = self.begin_restream_stop_intent().await;
        let _transaction = self.restream_transaction.lock().await;
        match intent {
            Some(intent) => self.finish_restream_stop(intent).await,
            None => Ok(()),
        }
    }

    pub(crate) async fn startup_firewall_status(&self, outcome: FirewallOutcome) {
        let mut state = self.state.lock().await;
        if state.firewall_generation.is_none() {
            state.firewall = outcome;
        }
        drop(state);
        self.refresh_status().await;
    }

    pub(crate) async fn binding_topology_changed(&self, scope: BindScope, revision: u64) {
        let (spec, generation, instance, health) = {
            let state = self.state.lock().await;
            let (Some(spec), Some(health)) = (&state.restream_spec, &state.restream_health) else {
                return;
            };
            if !state.restream_desired {
                return;
            }
            if !matches!(scope, BindScope::Unknown { .. })
                && !matches!(spec.bind_scope, BindScope::Unknown { .. })
                && scope_revision(&spec.bind_scope) == revision
            {
                return;
            }
            let snapshot = health.snapshot();
            (
                spec.clone(),
                snapshot.server_generation,
                snapshot.server_instance,
                health.clone(),
            )
        };
        let resolved =
            if spec.bind_interface.is_none() || matches!(scope, BindScope::Unknown { .. }) {
                Ok((spec.bind_identity.clone(), scope))
            } else {
                let handle = self
                    .app_handle
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone();
                let adopted = match handle {
                    Some(handle) => adopted_ip_set(&handle).await,
                    None => Default::default(),
                };
                bindings::resolve(
                    spec.bind_interface.as_deref(),
                    spec.bind_identity.as_ref().map(|i| i.guid.as_str()),
                    &adopted,
                )
                .await
            };
        let _lifecycle = self.relay_lifecycle.lock().await;
        if bindings::revision() != revision {
            return;
        }
        let (identity, next) = resolved.unwrap_or_else(|error| {
            (
                spec.bind_identity.clone(),
                BindScope::Unknown {
                    reason: error.to_string(),
                },
            )
        });
        let rebind = spec.bind_interface.is_some()
            && match &next {
                BindScope::Interface { alias, address, .. } => {
                    Some(alias) != spec.bind_interface.as_ref()
                        || Some(address) != spec.bind_address.as_ref()
                        || identity != spec.bind_identity
                }
                _ => true,
            };
        {
            let mut state = self.state.lock().await;
            if !relay_state_is_generation(&state, generation)
                || health.snapshot().server_instance != instance
            {
                return;
            }
            if let Some(spec) = state.restream_spec.as_mut() {
                spec.bind_scope = if rebind {
                    BindScope::Unknown {
                        reason: "Resolving changed bind interface".into(),
                    }
                } else {
                    next
                };
            }
        }
        if rebind {
            health.mark_resolution_failed(
                "Bind topology changed; resolving the saved interface identity".into(),
            );
            let _ = self
                .relay_event_tx
                .send(RelaySupervisorEvent::RetryRequested {
                    server_generation: generation,
                });
        }
        drop(_lifecycle);
        self.refresh_status().await;
    }

    async fn publish_restream_stop_intent(&self, stop_epoch: u64) -> Option<RestreamStopIntent> {
        self.relay_wake.notify_waiters();

        let (target_generation, firewall_generation, was_desired) = {
            let mut state = self.state.lock().await;
            // A newer intent owns desired state and listener replacement.
            // This stale Stop must neither clear it nor tear down its server.
            if self
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                != stop_epoch
            {
                return None;
            }
            let desired_generation = state
                .restream_health
                .as_ref()
                .map(|health| health.server_generation());
            let live_generation = state
                .restream_server
                .as_ref()
                .map(RestreamServer::server_generation);
            let stops_desired = state.restream_desired;

            let target = restream_stop_target(stops_desired, desired_generation, live_generation)
                .or_else(|| state.firewall_generation.map(|(generation, _)| generation));

            if stops_desired {
                if let Some(health) = state.restream_health.as_ref() {
                    health.stop();
                }
                state.restream_desired = false;
                state.restream_spec = None;
                state.restream_health = None;
                state.restream_intent_epoch = None;
                state.restream_start_time = None;
                state.restream_target = None;
            }
            (
                target,
                state.firewall_generation.map(|(generation, _)| generation),
                stops_desired,
            )
        };
        self.refresh_status().await;

        Some(RestreamStopIntent {
            epoch: stop_epoch,
            target_generation,
            firewall_generation,
            was_desired,
        })
    }

    async fn begin_restream_stop_intent(&self) -> Option<RestreamStopIntent> {
        let stop_epoch = self
            .restream_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .wrapping_add(1);
        self.publish_restream_stop_intent(stop_epoch).await
    }

    async fn begin_restream_stop_intent_if_current(
        &self,
        expected_epoch: u64,
    ) -> Option<RestreamStopIntent> {
        let stop_epoch = expected_epoch.wrapping_add(1);
        self.restream_epoch
            .compare_exchange(
                expected_epoch,
                stop_epoch,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .ok()?;
        self.publish_restream_stop_intent(stop_epoch).await
    }

    async fn finish_restream_stop(&self, intent: RestreamStopIntent) -> Result<(), AppError> {
        let _lifecycle = self.relay_lifecycle.lock().await;
        let server =
            {
                let mut state = self.state.lock().await;
                if state.restream_server.as_ref().is_some_and(|server| {
                    Some(server.server_generation()) == intent.target_generation
                }) {
                    state.restream_server.take()
                } else {
                    None
                }
            };
        if let Some(mut server) = server {
            server.shutdown().await;
            log::info!("Re-stream server fully cleaned up");
        }
        if let Some(generation) = intent.target_generation {
            retire_firewall(&self.state, generation).await;
        }
        // A failed prior retirement can survive a replacement listener whose
        // automation is unavailable. Stop must retry that captured lease too;
        // retire_firewall still rejects a newer generation's lease.
        if intent.firewall_generation != intent.target_generation {
            if let Some(generation) = intent.firewall_generation {
                retire_firewall(&self.state, generation).await;
            }
        }
        drop(_lifecycle);
        self.refresh_status().await;
        log::info!("Re-stream server stopped (intent epoch={})", intent.epoch);
        Ok(())
    }

    async fn current_operation_result(&self) -> RestreamOperationResult {
        let state = self.state.lock().await;
        RestreamOperationResult {
            selected_protocol: state.selected_protocol,
            desired: state.restream_desired,
            server_info: state
                .restream_desired
                .then(|| {
                    state
                        .restream_spec
                        .as_ref()
                        .map(|spec| Self::info_from_spec(spec, state.firewall.clone()))
                })
                .flatten(),
        }
    }

    fn info_from_spec(spec: &ResolvedStartSpec, firewall: FirewallOutcome) -> RestreamServerInfo {
        RestreamServerInfo {
            bind_scope: spec.bind_scope.clone(),
            firewall,
            protocol: spec.protocol(),
            server_url: spec.client_url(),
            display_url: spec.display_url(),
        }
    }

    async fn restore_restream_after_transaction_error(
        &self,
        old_settings: &AppSettings,
        adopted: &std::collections::HashSet<String>,
        stop_intent: RestreamStopIntent,
        error: AppError,
    ) -> AppError {
        if !stop_intent.was_desired {
            return error;
        }
        let Some((start_epoch, preserve_prior_desired)) = self
            .begin_restream_start_intent_if_current(stop_intent.epoch)
            .await
        else {
            return error;
        };
        match self
            .start_restream_server_inner(old_settings, adopted, start_epoch, preserve_prior_desired)
            .await
        {
            Ok(_) => error,
            Err(restoration_error) => AppError::Config(format!(
                "{}; restoring the prior re-stream output also failed: {}",
                error, restoration_error
            )),
        }
    }

    /// Apply the shared Enable field and both complete protocol sections as
    /// one backend lifecycle transaction. Inactive-protocol edits persist
    /// without replacing the selected runtime.
    pub async fn apply_restream_settings(
        &self,
        config: &AppConfig,
        update: RestreamSettingsUpdate,
        adopted: &std::collections::HashSet<String>,
    ) -> Result<RestreamOperationResult, AppError> {
        self.apply_restream_settings_with(config, update, adopted, |config, prospective| {
            config.commit_restream_settings(
                prospective.rtsp_server.clone(),
                prospective.srt_server.clone(),
            )
        })
        .await
    }

    async fn apply_restream_settings_with<F>(
        &self,
        config: &AppConfig,
        update: RestreamSettingsUpdate,
        adopted: &std::collections::HashSet<String>,
        commit: F,
    ) -> Result<RestreamOperationResult, AppError>
    where
        F: FnOnce(&AppConfig, &AppSettings) -> Result<AppSettings, AppError>,
    {
        let initial_settings = config.get();
        let initial_prospective = crate::settings_validation::prospective_restream_settings(
            &initial_settings,
            update.clone(),
        )?;
        let (operation_epoch, initial_was_desired) =
            self.current_restream_epoch_and_desired().await;
        let initial_runtime_changed =
            selected_restream_runtime_changed(&initial_settings, &initial_prospective);
        let initial_will_restart = initial_was_desired
            && initial_runtime_changed
            && initial_prospective.rtsp_server.enabled;
        if initial_will_restart {
            validate_selected_restream_startable(&initial_prospective)?;
        }
        let initial_must_stop = initial_was_desired
            && (initial_runtime_changed || !initial_prospective.rtsp_server.enabled);

        // Claim the stop epoch before waiting for an in-flight Start. That
        // Start will observe the newer epoch before it can store a candidate.
        let mut stop_intent = if initial_must_stop {
            Some(
                self.begin_restream_stop_intent_if_current(operation_epoch)
                    .await
                    .ok_or_else(|| {
                        AppError::Stream(
                            "Re-stream settings apply was superseded by a newer request".into(),
                        )
                    })?,
            )
        } else {
            None
        };

        let _transaction = self.restream_transaction.lock().await;
        let expected_epoch = stop_intent
            .map(|intent| intent.epoch)
            .unwrap_or(operation_epoch);
        if self
            .restream_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != expected_epoch
        {
            return Err(AppError::Stream(
                "Re-stream settings apply was superseded by a newer request".into(),
            ));
        }

        // A transaction that already held the gate may have committed while
        // this request was waiting. Rebase the complete update on its result.
        let old_settings = crate::settings_validation::validate_prospective_settings(config.get())?;
        let prospective = match crate::settings_validation::prospective_restream_settings(
            &old_settings,
            update,
        ) {
            Ok(settings) => settings,
            Err(error) => {
                return Err(match stop_intent {
                    Some(intent) => {
                        self.restore_restream_after_transaction_error(
                            &old_settings,
                            adopted,
                            intent,
                            error,
                        )
                        .await
                    }
                    None => error,
                });
            }
        };
        let mut was_desired = stop_intent
            .map(|intent| intent.was_desired)
            .unwrap_or(self.state.lock().await.restream_desired);
        let runtime_changed = selected_restream_runtime_changed(&old_settings, &prospective);
        let will_restart = was_desired && runtime_changed && prospective.rtsp_server.enabled;
        if will_restart {
            if let Err(error) = validate_selected_restream_startable(&prospective) {
                return Err(match stop_intent {
                    Some(intent) => {
                        self.restore_restream_after_transaction_error(
                            &old_settings,
                            adopted,
                            intent,
                            error,
                        )
                        .await
                    }
                    None => error,
                });
            }
        }
        let must_stop = was_desired && (runtime_changed || !prospective.rtsp_server.enabled);
        if must_stop && stop_intent.is_none() {
            let intent = self
                .begin_restream_stop_intent_if_current(expected_epoch)
                .await
                .ok_or_else(|| {
                    AppError::Stream(
                        "Re-stream settings apply was superseded by a newer request".into(),
                    )
                })?;
            was_desired = intent.was_desired;
            stop_intent = Some(intent);
        }
        if let Some(intent) = stop_intent {
            self.finish_restream_stop(intent).await?;
        }

        let committed = match commit(config, &prospective) {
            Ok(settings) => settings,
            Err(persistence_error) => {
                return Err(match stop_intent {
                    Some(intent) => {
                        self.restore_restream_after_transaction_error(
                            &old_settings,
                            adopted,
                            intent,
                            persistence_error,
                        )
                        .await
                    }
                    None => persistence_error,
                });
            }
        };

        if was_desired && committed.rtsp_server.enabled {
            if let Some(intent) = stop_intent {
                if let Some((start_epoch, preserve_prior_desired)) = self
                    .begin_restream_start_intent_if_current(intent.epoch)
                    .await
                {
                    self.start_restream_server_inner(
                        &committed,
                        adopted,
                        start_epoch,
                        preserve_prior_desired,
                    )
                    .await?;
                }
            }
        }

        Ok(self.current_operation_result().await)
    }

    pub async fn switch_restream_protocol(
        &self,
        config: &AppConfig,
        protocol: RestreamProtocol,
        adopted: &std::collections::HashSet<String>,
    ) -> Result<RestreamOperationResult, AppError> {
        self.switch_restream_protocol_with(config, protocol, adopted, |config, protocol| {
            config.commit_restream_protocol(protocol)
        })
        .await
    }

    async fn switch_restream_protocol_with<F>(
        &self,
        config: &AppConfig,
        protocol: RestreamProtocol,
        adopted: &std::collections::HashSet<String>,
        commit: F,
    ) -> Result<RestreamOperationResult, AppError>
    where
        F: FnOnce(&AppConfig, RestreamProtocol) -> Result<AppSettings, AppError>,
    {
        let initial_settings =
            crate::settings_validation::validate_prospective_settings(config.get())?;
        let mut initial_prospective = initial_settings.clone();
        initial_prospective.restream_protocol = protocol;
        let initial_prospective =
            crate::settings_validation::validate_prospective_settings(initial_prospective)?;
        let (operation_epoch, initial_was_desired) =
            self.current_restream_epoch_and_desired().await;
        validate_restream_switch_target(&initial_prospective, initial_was_desired)?;

        // A different selector owns a new stop epoch as soon as validation
        // succeeds, before it waits for a Start that may be resolving a bind.
        let mut stop_intent = if initial_settings.restream_protocol != protocol {
            Some(
                self.begin_restream_stop_intent_if_current(operation_epoch)
                    .await
                    .ok_or_else(|| {
                        AppError::Stream(
                            "Re-stream protocol switch was superseded by a newer request".into(),
                        )
                    })?,
            )
        } else {
            None
        };

        let _transaction = self.restream_transaction.lock().await;
        let expected_epoch = stop_intent
            .map(|intent| intent.epoch)
            .unwrap_or(operation_epoch);
        if self
            .restream_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != expected_epoch
        {
            return Err(AppError::Stream(
                "Re-stream protocol switch was superseded by a newer request".into(),
            ));
        }

        let old_settings = crate::settings_validation::validate_prospective_settings(config.get())?;
        let mut prospective = old_settings.clone();
        prospective.restream_protocol = protocol;
        let prospective =
            match crate::settings_validation::validate_prospective_settings(prospective) {
                Ok(settings) => settings,
                Err(error) => {
                    return Err(match stop_intent {
                        Some(intent) => {
                            self.restore_restream_after_transaction_error(
                                &old_settings,
                                adopted,
                                intent,
                                error,
                            )
                            .await
                        }
                        None => error,
                    });
                }
            };
        let mut was_desired = stop_intent
            .map(|intent| intent.was_desired)
            .unwrap_or(self.state.lock().await.restream_desired);
        if let Err(error) = validate_restream_switch_target(&prospective, was_desired) {
            return Err(match stop_intent {
                Some(intent) => {
                    self.restore_restream_after_transaction_error(
                        &old_settings,
                        adopted,
                        intent,
                        error,
                    )
                    .await
                }
                None => error,
            });
        }

        if old_settings.restream_protocol == protocol {
            self.state.lock().await.selected_protocol = protocol;
            if let Some(intent) = stop_intent {
                self.finish_restream_stop(intent).await?;
            }
            if was_desired {
                let restart_epoch = stop_intent
                    .map(|intent| intent.epoch)
                    .unwrap_or(expected_epoch);
                let Some((start_epoch, preserve_prior_desired)) = self
                    .begin_restream_start_intent_if_current(restart_epoch)
                    .await
                else {
                    return Ok(self.current_operation_result().await);
                };
                self.start_restream_server_inner(
                    &prospective,
                    adopted,
                    start_epoch,
                    preserve_prior_desired,
                )
                .await?;
            } else {
                self.refresh_status().await;
            }
            return Ok(self.current_operation_result().await);
        }

        if stop_intent.is_none() {
            let intent = self
                .begin_restream_stop_intent_if_current(expected_epoch)
                .await
                .ok_or_else(|| {
                    AppError::Stream(
                        "Re-stream protocol switch was superseded by a newer request".into(),
                    )
                })?;
            was_desired = intent.was_desired;
            stop_intent = Some(intent);
        }
        let stop_intent = stop_intent.expect("a selector change must own a stop intent");
        self.finish_restream_stop(stop_intent).await?;

        let committed = match commit(config, protocol) {
            Ok(settings) => settings,
            Err(persistence_error) => {
                return Err(self
                    .restore_restream_after_transaction_error(
                        &old_settings,
                        adopted,
                        stop_intent,
                        persistence_error,
                    )
                    .await);
            }
        };

        self.state.lock().await.selected_protocol = protocol;
        self.refresh_status().await;

        if was_desired {
            if let Some((start_epoch, preserve_prior_desired)) = self
                .begin_restream_start_intent_if_current(stop_intent.epoch)
                .await
            {
                validate_selected_restream_startable(&committed)?;
                self.start_restream_server_inner(
                    &committed,
                    adopted,
                    start_epoch,
                    preserve_prior_desired,
                )
                .await?;
            }
        }
        Ok(self.current_operation_result().await)
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
                restream_epoch: self.restream_epoch.clone(),
                relay_lifecycle: self.relay_lifecycle.clone(),
                relay_wake: self.relay_wake.clone(),
                relay_event_tx: self.relay_event_tx.clone(),
                app_handle: handle.clone(),
                restream_generation: self.restream_generation.clone(),
            };
            tauri::async_runtime::spawn(run_relay_supervisor(relay_events, supervisor));
        } else {
            log::warn!("Re-stream relay supervisor was already started");
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

fn optional_bind_interface(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

fn resolve_selected_restream_output(
    settings: &AppSettings,
) -> Result<(Option<String>, ResolvedOutput), AppError> {
    validate_selected_restream_startable(settings)?;
    match settings.restream_protocol {
        RestreamProtocol::Rtsp => Ok((
            optional_bind_interface(&settings.rtsp_server.bind_interface),
            ResolvedOutput::Rtsp {
                server_port: settings.rtsp_server.port,
                mount_path: format!("/stream-{}", settings.rtsp_server.token),
            },
        )),
        RestreamProtocol::Srt => Ok((
            optional_bind_interface(&settings.srt_server.bind_interface),
            ResolvedOutput::Srt {
                server_port: settings.srt_server.port,
                passphrase: resolved_srt_passphrase(&settings.srt_server.passphrase)?,
                latency_ms: settings.srt_server.latency_ms,
                stream_id: settings.srt_server.stream_id.clone(),
            },
        )),
    }
}

fn resolved_srt_passphrase(passphrase: &SrtPassphraseState) -> Result<String, AppError> {
    match passphrase {
        SrtPassphraseState::Unencrypted => Ok(String::new()),
        SrtPassphraseState::Available(value) => Ok(value.clone()),
        SrtPassphraseState::Unavailable { .. } => {
            crate::settings_validation::validate_srt_startable_from_state(passphrase)?;
            unreachable!("unavailable SRT passphrase validation must fail")
        }
    }
}

fn validate_selected_restream_startable(settings: &AppSettings) -> Result<(), AppError> {
    if settings.restream_protocol == RestreamProtocol::Srt {
        crate::settings_validation::validate_srt_startable(settings)?;
    }
    Ok(())
}

fn validate_restream_switch_target(
    settings: &AppSettings,
    was_desired: bool,
) -> Result<(), AppError> {
    if !was_desired {
        return Ok(());
    }
    if !settings.rtsp_server.enabled {
        return Err(AppError::Validation(
            "Re-stream Server Enable must be on before switching".into(),
        ));
    }
    validate_selected_restream_startable(settings)
}

fn selected_restream_runtime_changed(old: &AppSettings, prospective: &AppSettings) -> bool {
    debug_assert_eq!(old.restream_protocol, prospective.restream_protocol);
    match old.restream_protocol {
        RestreamProtocol::Rtsp => old.rtsp_server != prospective.rtsp_server,
        RestreamProtocol::Srt => old.srt_server != prospective.srt_server,
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
            let mut pipeline = PlaybackPipeline::new_rtsp(
                &url,
                500,
                true,
                window,
                health.clone(),
                generation,
                &settings.credentials.username,
                &settings.credentials.password,
                settings.stream.audio_muted,
            )?;
            let camera = path
                .as_ref()
                .map(|p| p.target.clone())
                .ok_or_else(|| AppError::Stream("Camera Ethernet path unavailable".into()))?;
            let handle = ctx.app.clone();
            let current_epoch = ctx.epoch.clone();
            pipeline.bind_rtsp_transport(
                &url,
                Arc::new(move || {
                    if current_epoch.load(Ordering::Acquire) != epoch {
                        return Err(AppError::Stream("Playback connection superseded".into()));
                    }
                    camera_stream_path(handle.as_ref(), &camera)
                }),
            )?;
            Ok(pipeline)
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

/// Video eligibility is distinct from shared network readiness used by PTU
/// and presence probes. Saved endpoints never substitute for a CAM role.
fn require_cam_role(
    target: &CameraTarget,
    records: &[crate::network::DeviceRecord],
) -> Result<(), AppError> {
    let mut cameras = records.iter().filter(|record| record.alias == "CAM");
    match (cameras.next(), cameras.next()) {
        (Some(record), None)
            if record.mac.eq_ignore_ascii_case(&target.key) && record.ip == target.ip =>
        {
            Ok(())
        }
        _ => Err(AppError::Stream(
            "Assign this node as CAM in the Nodes dropdown before streaming".into(),
        )),
    }
}

async fn preflight_target(
    handle: Option<&tauri::AppHandle>,
    target: Option<&CameraTarget>,
) -> Result<Option<ReadyPath>, AppError> {
    let Some(target) = target else {
        return Ok(None);
    }; // UDP is exempt
    camera_stream_path(handle, target).map(Some)
}

fn camera_stream_path(
    handle: Option<&tauri::AppHandle>,
    target: &CameraTarget,
) -> Result<ReadyPath, AppError> {
    use tauri::Manager;
    let handle =
        handle.ok_or_else(|| AppError::Stream("Ethernet readiness service unavailable".into()))?;
    let manager = handle.state::<crate::network::NetworkManager>();
    let path =
        manager.camera_ready_bound_now(target, &handle.state::<crate::config::AppConfig>())?;
    require_cam_role(&path.target, &manager.registry().snapshot())?;
    Ok(path)
}

fn relay_preflight(
    handle: Option<tauri::AppHandle>,
    target: Option<CameraTarget>,
    health: Arc<RelayRuntimeHealth>,
    generation: Arc<std::sync::atomic::AtomicU64>,
    expected_generation: u64,
) -> Option<rtsp_server::UpstreamReady> {
    let target = target?; // UDP has no camera gate
    Some(guard_relay_upstream(
        health,
        generation,
        expected_generation,
        Arc::new(move || camera_stream_path(handle.as_ref(), &target)),
    ))
}

fn guard_relay_upstream(
    health: Arc<RelayRuntimeHealth>,
    generation: Arc<std::sync::atomic::AtomicU64>,
    expected_generation: u64,
    ready: rtsp_server::UpstreamReady,
) -> rtsp_server::UpstreamReady {
    Arc::new(move || {
        // User transaction epochs also advance on a healthy no-op Start.
        // Existing connections belong to the installed runtime generation;
        // Stop retires its health before listener teardown starts.
        if generation.load(std::sync::atomic::Ordering::Acquire) != expected_generation
            || !health.upstream_allowed()
        {
            return Err(AppError::Stream(
                "Relay connection superseded or retired".into(),
            ));
        }
        ready()
    })
}

fn resolved_start_is_healthy_noop(
    desired: bool,
    current_spec: Option<&ResolvedStartSpec>,
    candidate_spec: &ResolvedStartSpec,
    relay_state: Option<RelayState>,
    health_generation: Option<u64>,
    listener_generation: Option<u64>,
    listener_loop_alive: bool,
) -> bool {
    desired
        && current_spec.is_some_and(|current| {
            let mut candidate = candidate_spec.clone();
            candidate.bind_scope = current.bind_scope.clone();
            current == &candidate
        })
        && matches!(
            relay_state,
            Some(RelayState::Listening | RelayState::Streaming)
        )
        && health_generation == listener_generation
        && health_generation.is_some()
        && listener_loop_alive
}

fn restream_stop_target(
    stops_desired: bool,
    desired_generation: Option<u64>,
    live_generation: Option<u64>,
) -> Option<u64> {
    if stops_desired {
        // A newer desired generation can coexist briefly with the previous
        // stored listener while Start is resolving/building. The epoch makes
        // that candidate self-discard; teardown must target the listener that
        // is actually stored, not merely the newer health generation.
        live_generation
    } else if live_generation != desired_generation {
        // This Stop was superseded by a newer intent. It may still clean up a
        // listener that does not belong to that newer desired generation.
        live_generation
    } else {
        None
    }
}

fn relay_state_is_generation(state: &StreamState, server_generation: u64) -> bool {
    state.restream_desired
        && state
            .restream_health
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
        && state.restream_intent_epoch == Some(expected_epoch)
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
    let expected_epoch = state.restream_intent_epoch?;
    if ctx
        .restream_epoch
        .load(std::sync::atomic::Ordering::Acquire)
        != expected_epoch
    {
        return None;
    }
    Some((expected_epoch, state.restream_health.as_ref()?.clone()))
}

async fn publish_relay_status(ctx: &RelaySupervisorContext) {
    let snapshot = compute_status(&ctx.state).await;
    publish_status_if_changed(ctx.status_tx.as_ref(), snapshot);
}

async fn poll_relay_fault(ctx: &RelaySupervisorContext) -> Option<RelayFaultEvent> {
    let (health, probe) = {
        let state = ctx.state.lock().await;
        if !state.restream_desired {
            return None;
        }
        (
            state.restream_health.as_ref()?.clone(),
            state
                .restream_server
                .as_ref()
                .map(RestreamServer::fault_probe),
        )
    };

    if let Some(event) = probe.and_then(|probe| probe.poll_fault()) {
        return Some(event);
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
                if !matches!(
                    health.snapshot().state,
                    RelayState::Failed | RelayState::Recovering
                ) {
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
            &ctx.restream_epoch,
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
                .restream_server
                .as_ref()
                .is_some_and(|server| server.server_generation() == server_generation)
            {
                state.restream_server.take()
            } else {
                None
            }
        };
        if let Some(mut failed_server) = failed_server {
            failed_server.shutdown().await;
        }
        retire_firewall(&ctx.state, server_generation).await;
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
            .restream_health
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
            &ctx.restream_epoch,
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
            let Some(spec) = state.restream_spec.as_ref() else {
                return;
            };
            spec.clone()
        };
        let mut build_spec = base_spec.clone();

        if base_spec.bind_interface.is_none() {
            build_spec.bind_scope = bindings::resolve(None, None, &Default::default())
                .await
                .map(|(_, scope)| scope)
                .unwrap_or_else(|error| BindScope::Unknown {
                    reason: error.to_string(),
                });
        }

        if base_spec.bind_identity.is_some() || health.should_reresolve_explicit_bind() {
            if let Some(interface_name) = base_spec.bind_interface.as_deref() {
                let adopted = adopted_ip_set(&ctx.app_handle).await;
                if !relay_is_current(
                    &ctx.state,
                    &ctx.restream_epoch,
                    expected_epoch,
                    server_generation,
                )
                .await
                {
                    return;
                }
                let id = base_spec
                    .bind_identity
                    .as_ref()
                    .map(|identity| identity.guid.as_str());
                match bindings::resolve(Some(interface_name), id, &adopted).await {
                    Ok((identity, scope @ BindScope::Interface { .. })) => {
                        if let BindScope::Interface { address, alias, .. } = &scope {
                            build_spec.bind_address = Some(address.clone());
                            build_spec.advertised_ip = address.clone();
                            build_spec.bind_interface = Some(alias.clone());
                        }
                        build_spec.bind_identity = identity;
                        build_spec.bind_scope = scope;
                    }
                    Ok(_) => unreachable!("an explicit interface resolves to an address"),
                    Err(error) => {
                        let reason = redact_relay_text(
                            &format!(
                                "Re-stream bind interface '{}' is unavailable: {}",
                                interface_name, error
                            ),
                            base_spec.mount_path(),
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
            &ctx.restream_epoch,
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
                .restream_server
                .as_ref()
                .is_some_and(|server| server.server_generation() == server_generation)
            {
                state.restream_server.take()
            } else {
                None
            }
        };
        if let Some(mut prior) = prior {
            prior.shutdown().await;
        }
        if !relay_is_current(
            &ctx.state,
            &ctx.restream_epoch,
            expected_epoch,
            server_generation,
        )
        .await
        {
            return;
        }

        if let Err(error) = preflight_restream(&build_spec) {
            let server_instance = health.begin_server_instance(true);
            let reason = redact_relay_text(&error.to_string(), build_spec.mount_path());
            health.mark_build_failed(server_instance, reason, false);
            drop(_lifecycle);
            publish_relay_status(ctx).await;
            continue;
        }

        let target = ctx.state.lock().await.restream_target.clone();
        if let Err(error) = preflight_target(Some(&ctx.app_handle), target.as_ref()).await {
            health.mark_resolution_failed(error.to_string());
            drop(_lifecycle);
            publish_relay_status(ctx).await;
            continue;
        }
        if !relay_is_current(
            &ctx.state,
            &ctx.restream_epoch,
            expected_epoch,
            server_generation,
        )
        .await
        {
            return;
        }
        if bindings::revision() != scope_revision(&build_spec.bind_scope) {
            continue;
        }
        apply_firewall(&ctx.state, &build_spec, server_generation).await;
        if !relay_is_current(
            &ctx.state,
            &ctx.restream_epoch,
            expected_epoch,
            server_generation,
        )
        .await
            || bindings::revision() != scope_revision(&build_spec.bind_scope)
        {
            retire_firewall(&ctx.state, server_generation).await;
            continue;
        }
        let (server_instance, result) = StreamManager::build_restream_server(
            &build_spec,
            health.clone(),
            ctx.relay_event_tx.clone(),
            true,
            relay_preflight(
                Some(ctx.app_handle.clone()),
                target,
                health.clone(),
                ctx.restream_generation.clone(),
                server_generation,
            ),
        );
        let server = match result {
            Ok(server) => server,
            Err(failure) => {
                retire_firewall(&ctx.state, server_generation).await;
                let reason = redact_relay_text(&failure.error.to_string(), build_spec.mount_path());
                health.mark_build_failed(
                    server_instance,
                    reason,
                    failure.kind == RestreamBuildFailureKind::Bind,
                );
                drop(_lifecycle);
                publish_relay_status(ctx).await;
                continue;
            }
        };

        let mut candidate = Some(server);
        {
            let mut state = ctx.state.lock().await;
            if ctx
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                == expected_epoch
                && state.restream_intent_epoch == Some(expected_epoch)
                && relay_state_is_generation(&state, server_generation)
                && bindings::revision() == scope_revision(&build_spec.bind_scope)
            {
                // Publish a re-resolved address only after it bound
                // successfully. Port, interface, mount, token, and source are
                // byte-for-byte inherited from the desired specification.
                state.restream_spec = Some(build_spec);
                state.restream_server = candidate.take();
            }
        }
        if let Some(mut stale) = candidate {
            crate::network::note_fence_drop("relay_listener");
            stale.shutdown().await;
            retire_firewall(&ctx.state, server_generation).await;
            if ctx
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                == expected_epoch
            {
                health.mark_resolution_failed(
                    "Bind topology changed during listener construction".into(),
                );
                continue;
            }
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
fn scope_revision(scope: &BindScope) -> u64 {
    match scope {
        BindScope::AllAddresses {
            topology_revision, ..
        }
        | BindScope::Interface {
            topology_revision, ..
        } => *topology_revision,
        BindScope::Unknown { .. } => bindings::revision(),
    }
}

fn preflight_restream(spec: &ResolvedStartSpec) -> Result<(), AppError> {
    crate::ensure_gstreamer()?;
    let input: &[&str] = match spec.source {
        ResolvedSource::Rtsp { .. } => &["rtspsrc", "rtph264depay"],
        ResolvedSource::Udp { .. } => &["udpsrc", "tsdemux"],
    };
    let output: &[&str] = match spec.protocol() {
        RestreamProtocol::Rtsp => &["h264parse", "rtph264pay"],
        RestreamProtocol::Srt => &["h264parse", "mpegtsmux", "srtsink"],
    };
    for name in input.iter().chain(output) {
        if gst::ElementFactory::find(name).is_none() {
            return Err(AppError::Stream(format!(
                "Bundled GStreamer lacks required element '{name}'"
            )));
        }
    }
    if matches!(spec.source, ResolvedSource::Rtsp { .. }) {
        let source = gst::ElementFactory::make("rtspsrc")
            .build()
            .map_err(|_| AppError::Stream("RTSP source preflight failed".into()))?;
        configure_tcp_rtspsrc(&source)?;
    }
    if spec.protocol() == RestreamProtocol::Srt {
        srt_server::preflight().map_err(|failure| failure.error)?;
    }
    Ok(())
}

fn firewall_role(protocol: RestreamProtocol) -> FirewallRule {
    match protocol {
        RestreamProtocol::Rtsp => FirewallRule::Rtsp,
        RestreamProtocol::Srt => FirewallRule::Srt,
    }
}

// All callers hold relay_lifecycle. The lease is installed before dispatch, so
// cancellation cannot hide an enabled rule from Stop/startup reconciliation.
async fn apply_firewall(
    state: &Arc<Mutex<StreamState>>,
    spec: &ResolvedStartSpec,
    generation: u64,
) -> FirewallOutcome {
    let prior = state.lock().await.firewall_generation;
    if let Some((prior_generation, _)) = prior {
        if !retire_firewall(state, prior_generation).await {
            return state.lock().await.firewall.clone();
        }
    }
    let role = firewall_role(spec.protocol());
    {
        let mut state = state.lock().await;
        if !relay_state_is_generation(&state, generation) {
            return FirewallOutcome::Inactive;
        }
        state.firewall_generation = Some((generation, role));
    }
    let outcome = firewall::ensure(role, spec.server_port(), spec.bind_identity.clone()).await;
    let mut state = state.lock().await;
    if state.firewall_generation == Some((generation, role)) {
        state.firewall = outcome.clone();
    }
    outcome
}

async fn retire_firewall(state: &Arc<Mutex<StreamState>>, generation: u64) -> bool {
    let lease = {
        let state = state.lock().await;
        match state.firewall_generation {
            Some((current, role)) if current == generation => Some(role),
            _ => None,
        }
    };
    if let Some(role) = lease {
        let outcome = firewall::disable(role).await;
        let disabled = matches!(outcome, FirewallOutcome::Inactive);
        let mut state = state.lock().await;
        if state.firewall_generation == Some((generation, role)) {
            if disabled {
                state.firewall_generation = None;
            }
            state.firewall = outcome;
        }
        disabled
    } else {
        true
    }
}

async fn compute_status(state: &Arc<Mutex<StreamState>>) -> StreamStatus {
    let state = state.lock().await;
    let uptime = state
        .restream_start_time
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);

    let health = state
        .restream_health
        .as_ref()
        .map(|health| health.snapshot());
    let current_generation = health.as_ref().map(|health| health.server_generation);
    let current_server = state
        .restream_server
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
        bind_scope: if listener_alive {
            state
                .restream_spec
                .as_ref()
                .map(|s| s.bind_scope.clone())
                .unwrap_or_default()
        } else {
            BindScope::default()
        },
        firewall: state.firewall.clone(),
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
        selected_protocol: state.selected_protocol,
        active_protocol: state
            .restream_spec
            .as_ref()
            .map(ResolvedStartSpec::protocol)
            .or_else(|| state.restream_server.as_ref().map(RestreamServer::protocol)),
        server_running: listener_alive,
        desired: state.restream_desired,
        relay_state: if state.restream_desired {
            health
                .as_ref()
                .map(|health| health.state)
                .unwrap_or(RelayState::Starting)
        } else {
            RelayState::Stopped
        },
        relay_error: if state.restream_desired {
            health.as_ref().and_then(|health| health.error.clone())
        } else {
            None
        },
        recovery_attempt: if state.restream_desired {
            health
                .as_ref()
                .map(|health| health.recovery_attempt)
                .unwrap_or(0)
        } else {
            0
        },
        server_url: state
            .restream_desired
            .then(|| {
                state
                    .restream_spec
                    .as_ref()
                    .map(ResolvedStartSpec::client_url)
            })
            .flatten(),
        display_url: state
            .restream_desired
            .then(|| {
                state
                    .restream_spec
                    .as_ref()
                    .map(ResolvedStartSpec::display_url)
            })
            .flatten(),
        recording: state.recording,
        uptime_secs: uptime,
        bandwidth_kbps: bandwidth,
        connected_clients,
        client_limit,
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
/// caller turns that into a clear error rather than binding the output socket
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
/// set: prefer physical WiFi (the camera occupies Ethernet), else physical
/// Ethernet, always skipping adopted secondaries and APIPA. VPN addresses
/// require an explicit selection. Returns
/// `None` only if nothing usable exists (caller advertises 0.0.0.0).
async fn get_display_ip(adopted: &std::collections::HashSet<String>) -> Option<String> {
    let interfaces = crate::network::interface::list_all().await.ok()?;
    select_display_ip(&interfaces, adopted)
}

fn select_display_ip(
    interfaces: &[crate::network::InterfaceInfo],
    adopted: &std::collections::HashSet<String>,
) -> Option<String> {
    let physical = interfaces
        .iter()
        .filter(|i| i.is_up && !i.is_vpn && !i.is_virtual);
    physical
        .clone()
        .filter(|i| i.is_wifi)
        .chain(physical.filter(|i| i.is_ethernet && !i.is_wifi))
        .find_map(|i| first_usable_ip(&i.ips, adopted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    #[tokio::test]
    async fn stale_firewall_cleanup_cannot_retire_a_newer_listener_lease() {
        let manager = StreamManager::new();
        manager.state.lock().await.firewall_generation = Some((9, FirewallRule::Srt));
        retire_firewall(&manager.state, 8).await;
        assert_eq!(
            manager.state.lock().await.firewall_generation,
            Some((9, FirewallRule::Srt))
        );
        // The lib-test seam cannot invoke native firewall policy.
        retire_firewall(&manager.state, 9).await;
        assert!(manager.state.lock().await.firewall_generation.is_none());
    }

    #[tokio::test]
    async fn stopped_status_retains_startup_policy_failure() {
        let manager = StreamManager::new();
        let failed = FirewallOutcome::Failed {
            stage: "ownership".into(),
            reason: "Foreign program owns the native rule name".into(),
            uncertain: false,
        };
        manager.startup_firewall_status(failed.clone()).await;
        let status = compute_status(&manager.state).await;
        assert!(!status.server_running);
        assert_eq!(status.firewall, failed);
        manager.state.lock().await.firewall_generation = Some((2, FirewallRule::Rtsp));
        manager
            .startup_firewall_status(FirewallOutcome::Inactive)
            .await;
        assert_eq!(manager.state.lock().await.firewall, failed);
    }

    #[tokio::test]
    async fn stop_accounts_for_firewall_lease_even_without_a_bound_socket() {
        let manager = StreamManager::new();
        {
            let mut state = manager.state.lock().await;
            state.restream_desired = true;
            state.firewall_generation = Some((12, FirewallRule::Rtsp));
        }
        let intent = manager.begin_restream_stop_intent().await.unwrap();
        assert_eq!(intent.target_generation, Some(12));
        manager.finish_restream_stop(intent).await.unwrap();
        assert!(manager.state.lock().await.firewall_generation.is_none());
    }

    #[tokio::test]
    async fn delayed_topology_observation_cannot_overwrite_a_recovered_instance() {
        use std::future::{poll_fn, Future};
        use std::task::Poll;

        let manager = StreamManager::new();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        seed_desired_relay_state(&manager, &settings, RelayState::Recovering).await;
        let lifecycle = manager.relay_lifecycle.lock().await;
        let observation = manager.binding_topology_changed(
            BindScope::Unknown {
                reason: "earlier observation failed".into(),
            },
            bindings::revision(),
        );
        tokio::pin!(observation);
        // The observer has captured the old instance and waits for recovery.
        assert!(poll_fn(|cx| Poll::Ready(observation.as_mut().poll(cx)))
            .await
            .is_pending());
        let recovered_scope = BindScope::AllAddresses {
            family: bindings::SocketFamily::Ipv4,
            addresses: vec![],
            topology_revision: bindings::revision(),
        };
        {
            let mut state = manager.state.lock().await;
            let health = state.restream_health.as_ref().unwrap();
            let instance = health.begin_server_instance(true);
            health.mark_listener_bound(instance);
            state.restream_spec.as_mut().unwrap().bind_scope = recovered_scope.clone();
        }
        drop(lifecycle);
        observation.await;
        assert_eq!(
            manager
                .state
                .lock()
                .await
                .restream_spec
                .as_ref()
                .unwrap()
                .bind_scope,
            recovered_scope
        );
    }

    #[tokio::test]
    async fn successful_reobservation_repairs_unknown_binding_at_the_same_revision() {
        let manager = StreamManager::new();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        seed_desired_relay_state(&manager, &settings, RelayState::Listening).await;
        let revision = bindings::revision();
        let scope = BindScope::AllAddresses {
            family: bindings::SocketFamily::Ipv4,
            addresses: vec![],
            topology_revision: revision,
        };
        // The watcher already recorded this inventory before Start's separate
        // read failed. Its next identical observation must still repair Unknown.
        manager
            .binding_topology_changed(scope.clone(), revision)
            .await;
        let state = manager.state.lock().await;
        assert_eq!(state.restream_spec.as_ref().unwrap().bind_scope, scope);
        assert_eq!(
            state.restream_health.as_ref().unwrap().snapshot().state,
            RelayState::Listening
        );
    }

    #[tokio::test]
    async fn stop_retries_a_retained_policy_lease_from_an_older_listener() {
        init_gstreamer();
        let manager = StreamManager::new();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        let mut spec = resolved_spec_for_test(&settings);
        spec.bind_address = Some("127.0.0.1".into());
        seed_desired_relay_state(&manager, &settings, RelayState::Listening).await;
        let health = manager.state.lock().await.restream_health.clone().unwrap();
        let (_, built) = StreamManager::build_restream_server(
            &spec,
            health,
            manager.relay_event_tx.clone(),
            false,
            None,
        );
        {
            let mut state = manager.state.lock().await;
            state.restream_server =
                Some(built.unwrap_or_else(|failure| panic!("{}", failure.error)));
            // The prior SRT cleanup failed, so Start continued with unavailable
            // automation while retaining that older lease for a later retry.
            state.firewall_generation = Some((40, FirewallRule::Srt));
        }
        manager.stop_restream_server().await.unwrap();
        assert!(manager.state.lock().await.restream_server.is_none());
        assert!(manager.state.lock().await.firewall_generation.is_none());
    }

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

    fn unused_udp_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn unused_tcp_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn role_record(alias: &str) -> crate::network::DeviceRecord {
        crate::network::DeviceRecord {
            mac: "aa:bb:cc:dd:ee:01".into(),
            ip: "192.0.2.20".into(),
            subnet: "192.0.2.0/24".into(),
            alias: alias.into(),
            status: crate::network::DeviceStatus::Live,
            open_ports: vec![554],
            verified_by_mac: Some("aa:bb:cc:dd:ee:10".into()),
            last_verified_at: Some("now".into()),
            first_seen: "before".into(),
            last_seen: "now".into(),
        }
    }

    #[test]
    fn video_role_gate_requires_an_explicit_unique_cam() {
        let row = role_record("");
        let target = CameraTarget {
            key: row.mac.clone(),
            expected_mac: Some(row.mac.clone()),
            ip: row.ip.clone(),
        };
        for alias in ["", "PTU", "camera", "CAM"] {
            assert_eq!(
                require_cam_role(&target, &[role_record(alias)]).is_ok(),
                alias == "CAM"
            );
        }
        assert!(require_cam_role(&target, &[]).is_err());
        let cam = role_record("CAM");
        let mut other = cam.clone();
        other.mac = "aa:bb:cc:dd:ee:02".into();
        assert!(require_cam_role(&target, &[cam, other]).is_err());
    }

    #[test]
    fn video_role_gate_keeps_identity_and_clearing_role_blocks_reconnect() {
        let mut row = role_record("CAM");
        let mut target = CameraTarget {
            key: format!("manual:{}", row.ip),
            expected_mac: None,
            ip: row.ip.clone(),
        };
        assert!(require_cam_role(&target, &[row.clone()]).is_err());
        // Shared native readiness resolves a manual key through its saved MAC.
        target.key = row.mac.clone();
        target.expected_mac = Some(row.mac.clone());
        assert!(require_cam_role(&target, &[row.clone()]).is_ok());
        row.alias.clear();
        assert!(require_cam_role(&target, &[row.clone()]).is_err());
        row.alias = "CAM".into();
        row.mac = "aa:bb:cc:dd:ee:02".into();
        assert!(require_cam_role(&target, &[row.clone()]).is_err());
        row.mac = target.key.clone();
        row.ip = "192.0.2.21".into();
        assert!(require_cam_role(&target, &[row]).is_err());
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
        assert!(!manager.status_tx.borrow().desired);
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
        assert!(status.desired);
        assert_eq!(status.relay_state, RelayState::Starting);
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

    #[test]
    fn automatic_restream_url_never_selects_vpn_or_virtual_adapters() {
        use crate::network::InterfaceInfo;
        let ethernet = InterfaceInfo {
            name: "Ethernet".into(),
            display_name: "Ethernet".into(),
            description: "Physical".into(),
            mac: "aa:bb:cc:dd:ee:01".into(),
            ips: vec![ip("192.168.0.100"), ip("192.168.1.100")],
            is_up: true,
            is_ethernet: true,
            is_wifi: false,
            is_vpn: false,
            is_virtual: false,
        };
        let mut wifi = ethernet.clone();
        wifi.is_ethernet = false;
        wifi.is_wifi = true;
        wifi.ips = vec![ip("192.168.1.204")];
        let mut vpn = ethernet.clone();
        vpn.is_vpn = true;
        vpn.is_virtual = true;
        vpn.ips = vec![ip("10.147.18.99")];
        let mut virtual_adapter = ethernet.clone();
        virtual_adapter.is_virtual = true;
        virtual_adapter.ips = vec![ip("172.30.0.1")];
        let adopted = adopted_set(&["192.168.1.100"]);
        let mut interfaces = vec![vpn, virtual_adapter, ethernet, wifi];
        // Enumeration order must not let a VPN win over the Wi-Fi LAN.
        assert_eq!(
            select_display_ip(&interfaces, &adopted).as_deref(),
            Some("192.168.1.204")
        );
        interfaces.reverse();
        assert_eq!(
            select_display_ip(&interfaces, &adopted).as_deref(),
            Some("192.168.1.204")
        );
        interfaces[0].is_up = false;
        assert_eq!(
            select_display_ip(&interfaces, &adopted).as_deref(),
            Some("192.168.0.100")
        );
        interfaces[1].ips = vec![ip("169.254.1.10"), ip("192.168.1.100")];
        assert!(select_display_ip(&interfaces, &adopted).is_none());
        // Explicit VPN selection still has a usable bind/advertise address.
        assert_eq!(
            first_usable_ip(&interfaces[3].ips, &adopted).as_deref(),
            Some("10.147.18.99")
        );
    }

    fn make_settings(
        protocol: StreamProtocol,
        camera_ip: &str,
        username: &str,
        password: &str,
    ) -> AppSettings {
        AppSettings {
            bind_identity_migration_complete: true,
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
            restream_protocol: RestreamProtocol::Rtsp,
            rtsp_server: RtspServerConfig {
                enabled: false,
                port: 8554,
                token: "0123456789abcdef".into(),
                bind_interface: String::new(),
                bind_interface_id: None,
            },
            srt_server: SrtServerConfig::default(),
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

    fn restream_test_settings(protocol: RestreamProtocol) -> AppSettings {
        let mut settings = make_settings(StreamProtocol::Udp, "", "", "");
        settings.stream.udp_port = unused_udp_port();
        settings.restream_protocol = protocol;
        settings.rtsp_server.enabled = true;
        settings.rtsp_server.port = unused_tcp_port();
        settings.rtsp_server.token = "0123456789abcdef".into();
        settings.srt_server.port = unused_udp_port();
        while settings.srt_server.port == settings.stream.udp_port {
            settings.srt_server.port = unused_udp_port();
        }
        settings.srt_server.passphrase = SrtPassphraseState::Unencrypted;
        settings
    }

    fn restream_update_from(settings: &AppSettings, enabled: bool) -> RestreamSettingsUpdate {
        RestreamSettingsUpdate {
            enabled,
            rtsp_server: RtspServerUpdate {
                port: i64::from(settings.rtsp_server.port),
                token: settings.rtsp_server.token.clone(),
                bind_interface: settings.rtsp_server.bind_interface.clone(),
                bind_interface_id: settings.rtsp_server.bind_interface_id.clone(),
            },
            srt_server: SrtServerUpdate {
                port: i64::from(settings.srt_server.port),
                passphrase: SrtPassphraseUpdate::Keep,
                latency_ms: i64::from(settings.srt_server.latency_ms),
                stream_id: settings.srt_server.stream_id.clone(),
                bind_interface: settings.srt_server.bind_interface.clone(),
                bind_interface_id: settings.srt_server.bind_interface_id.clone(),
            },
        }
    }

    fn commit_restream_settings_in_memory(
        config: &AppConfig,
        prospective: &AppSettings,
    ) -> Result<AppSettings, AppError> {
        config.commit_restream_settings_with(
            prospective.rtsp_server.clone(),
            prospective.srt_server.clone(),
            |_| Ok(()),
        )
    }

    fn commit_restream_protocol_in_memory(
        config: &AppConfig,
        protocol: RestreamProtocol,
    ) -> Result<AppSettings, AppError> {
        config.commit_restream_protocol_with(protocol, |_| Ok(()))
    }

    async fn active_restream_generation(manager: &StreamManager) -> Option<u64> {
        manager
            .state
            .lock()
            .await
            .restream_server
            .as_ref()
            .map(RestreamServer::server_generation)
    }

    #[tokio::test]
    async fn upstream_guard_survives_reasserted_start_but_rejects_stop_and_replacement() {
        use std::sync::atomic::Ordering;
        let manager = StreamManager::new();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        seed_desired_relay_state(&manager, &settings, RelayState::Listening).await;
        manager.restream_generation.store(41, Ordering::Release);
        let health = manager.state.lock().await.restream_health.clone().unwrap();
        let ready_calls = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let calls = ready_calls.clone();
        let guard = guard_relay_upstream(
            health.clone(),
            manager.restream_generation.clone(),
            41,
            Arc::new(move || {
                calls.fetch_add(1, Ordering::AcqRel);
                Ok(crate::network::bound_tcp::test_path("192.0.2.1"))
            }),
        );
        guard().unwrap();
        manager.begin_restream_start_intent().await.unwrap();
        guard().unwrap();
        assert_eq!(ready_calls.load(Ordering::Acquire), 2);
        manager.restream_generation.store(42, Ordering::Release);
        assert!(guard().is_err());
        manager.restream_generation.store(41, Ordering::Release);
        manager.begin_restream_stop_intent().await.unwrap();
        assert!(guard().is_err());
        assert_eq!(ready_calls.load(Ordering::Acquire), 2);
    }

    fn resolved_spec_for_test(settings: &AppSettings) -> ResolvedStartSpec {
        let (_, output) = resolve_selected_restream_output(settings).unwrap();
        ResolvedStartSpec {
            source: ResolvedSource::Udp {
                port: settings.stream.udp_port,
            },
            output,
            bind_interface: None,
            bind_identity: None,
            bind_scope: crate::network::bindings::BindScope::default(),
            bind_address: None,
            advertised_ip: "127.0.0.1".into(),
            username: String::new(),
            password: String::new(),
        }
    }

    async fn seed_desired_relay_state(
        manager: &StreamManager,
        settings: &AppSettings,
        relay_state: RelayState,
    ) {
        let health = Arc::new(RelayRuntimeHealth::new(41, relay::RelayIngestKind::Udp));
        let instance = health.begin_server_instance(relay_state == RelayState::Recovering);
        match relay_state {
            RelayState::Starting => {}
            RelayState::Listening => health.mark_listener_bound(instance),
            RelayState::Streaming => {
                health.mark_listener_bound(instance);
                let generation = health.begin_data_generation(instance).unwrap();
                assert!(health.report_streaming_without_buffer(
                    instance,
                    generation,
                    tokio::time::Instant::now(),
                ));
            }
            RelayState::Recovering => health.mark_recovery_in_progress(),
            RelayState::Failed => {
                health.mark_build_failed(instance, "injected runtime failure".into(), false)
            }
            RelayState::Stopped => panic!("Stopped has no desired relay state"),
        }
        assert_eq!(health.snapshot().state, relay_state);

        let mut state = manager.state.lock().await;
        state.restream_desired = true;
        state.restream_spec = Some(resolved_spec_for_test(settings));
        state.restream_health = Some(health);
        state.restream_intent_epoch = Some(
            manager
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire),
        );
        state.restream_start_time = Some(std::time::Instant::now());
    }

    async fn wait_for_udp_rebind(port: u16) -> bool {
        for _ in 0..40 {
            if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        false
    }

    fn bind_udp_after_release(port: u16) -> std::net::UdpSocket {
        let mut last_error = None;
        for _ in 0..80 {
            match std::net::UdpSocket::bind(("0.0.0.0", port)) {
                Ok(socket) => return socket,
                Err(error) => last_error = Some(error),
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        panic!(
            "the old listener did not release UDP port {port}: {}",
            last_error.expect("at least one bind attempt must run")
        );
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
        let spec = ResolvedStartSpec {
            source: ResolvedSource::Rtsp {
                url: "rtsp://192.0.2.20/live".into(),
            },
            output: ResolvedOutput::Rtsp {
                server_port: 8554,
                mount_path: "/stream-token".into(),
            },
            bind_interface: Some("VPN".into()),
            bind_identity: None,
            bind_scope: crate::network::bindings::BindScope::default(),
            bind_address: Some("192.0.2.10".into()),
            advertised_ip: "192.0.2.10".into(),
            username: "camera".into(),
            password: "secret".into(),
        };
        let is_noop = |candidate: &ResolvedStartSpec, relay_state, loop_alive| {
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

    #[test]
    fn only_selected_protocol_settings_replace_the_runtime() {
        let old = make_settings(StreamProtocol::Rtsp, "192.0.2.20", "camera", "secret");

        let mut inactive_srt_changed = old.clone();
        inactive_srt_changed.srt_server.latency_ms = 250;
        assert!(!selected_restream_runtime_changed(
            &old,
            &inactive_srt_changed
        ));

        let mut active_rtsp_changed = old.clone();
        active_rtsp_changed.rtsp_server.port = 9_554;
        assert!(selected_restream_runtime_changed(
            &old,
            &active_rtsp_changed
        ));

        let mut old_srt = old;
        old_srt.restream_protocol = RestreamProtocol::Srt;
        let mut inactive_rtsp_changed = old_srt.clone();
        inactive_rtsp_changed.rtsp_server.port = 9_554;
        assert!(!selected_restream_runtime_changed(
            &old_srt,
            &inactive_rtsp_changed
        ));

        let mut active_srt_changed = old_srt.clone();
        active_srt_changed.srt_server.stream_id = "replacement".into();
        assert!(selected_restream_runtime_changed(
            &old_srt,
            &active_srt_changed
        ));
    }

    #[test]
    fn srt_output_resolution_is_complete_and_fail_closed() {
        let mut settings = make_settings(StreamProtocol::Rtsp, "192.0.2.20", "camera", "secret");
        settings.restream_protocol = RestreamProtocol::Srt;
        settings.srt_server.port = 9_000;
        settings.srt_server.passphrase = SrtPassphraseState::Available("strongPass1".into());
        settings.srt_server.latency_ms = 250;
        settings.srt_server.stream_id = "field unit".into();
        settings.srt_server.bind_interface = "ZeroTier".into();

        let (bind_interface, output) = resolve_selected_restream_output(&settings).unwrap();
        assert_eq!(bind_interface.as_deref(), Some("ZeroTier"));
        let ResolvedOutput::Srt {
            server_port,
            passphrase,
            latency_ms,
            stream_id,
        } = output
        else {
            panic!("SRT selection must resolve to an SRT output")
        };
        assert_eq!(server_port, 9_000);
        assert_eq!(passphrase, "strongPass1");
        assert_eq!(latency_ms, 250);
        assert_eq!(stream_id, "field unit");

        settings.srt_server.passphrase = SrtPassphraseState::Unavailable {
            preserved_ciphertext: "opaque-ciphertext".into(),
        };
        let error = match resolve_selected_restream_output(&settings) {
            Ok(_) => panic!("unavailable SRT encryption must fail before bind resolution"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), "SrtPassphraseUnavailable");
        assert!(!error.to_string().contains("opaque-ciphertext"));
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
            StreamManager::resolve_restream_start_spec(&s, &std::collections::HashSet::new())
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
            selected_protocol: RestreamProtocol::Rtsp,
            active_protocol: Some(RestreamProtocol::Rtsp),
            server_running: false,
            desired: true,
            relay_state: RelayState::Recovering,
            relay_error: Some("camera unavailable".into()),
            recovery_attempt: 2,
            server_url: Some("rtsp://127.0.0.1:8554/stream-abc".into()),
            display_url: Some("rtsp://127.0.0.1:8554".into()),
            recording: false,
            uptime_secs: 120,
            bandwidth_kbps: 0.0,
            connected_clients: 3,
            client_limit: MAX_RTSP_CLIENTS,
            error: None,
            audio_present: true,
            audio_codec: Some("PCMU".into()),
            ..StreamStatus::idle(RestreamProtocol::Rtsp)
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"playing\":true"));
        assert!(json.contains("\"selected_protocol\":\"rtsp\""));
        assert!(json.contains("\"active_protocol\":\"rtsp\""));
        assert!(json.contains("\"uptime_secs\":120"));
        assert!(json.contains("\"display_url\":"));
        assert!(json.contains("\"relay_state\":\"recovering\""));
        assert!(json.contains("\"recovery_attempt\":2"));
        assert!(json.contains("\"connected_clients\":3"));
        assert!(json.contains("\"client_limit\":10"));
        assert!(json.contains("\"audio_present\":true"));
        assert!(json.contains("\"audio_codec\":\"PCMU\""));
    }

    #[test]
    fn stream_status_default_values() {
        let status = StreamStatus::idle(RestreamProtocol::Rtsp);
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"server_url\":null"));
        assert!(json.contains("\"selected_protocol\":\"rtsp\""));
        assert!(json.contains("\"active_protocol\":null"));
        assert!(json.contains("\"display_url\":null"));
        assert!(json.contains("\"connected_clients\":0"));
        assert!(json.contains("\"client_limit\":10"));
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
        assert!(!status.server_running);
        assert_eq!(status.selected_protocol, RestreamProtocol::Rtsp);
        assert_eq!(status.active_protocol, None);
        assert!(!status.recording);
        assert_eq!(status.uptime_secs, 0);
        assert!(status.server_url.is_none());
        assert_eq!(status.connected_clients, 0);
        assert_eq!(status.client_limit, MAX_RTSP_CLIENTS);
    }

    #[tokio::test]
    async fn stopped_switch_can_select_unavailable_srt_but_start_remains_blocked() {
        let mut settings = restream_test_settings(RestreamProtocol::Rtsp);
        settings.srt_server.passphrase = SrtPassphraseState::Unavailable {
            preserved_ciphertext: "opaque-ciphertext".into(),
        };
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
        let adopted = adopted_set(&[]);

        let result = manager
            .switch_restream_protocol_with(
                &config,
                RestreamProtocol::Srt,
                &adopted,
                commit_restream_protocol_in_memory,
            )
            .await
            .unwrap();
        assert_eq!(result.selected_protocol, RestreamProtocol::Srt);
        assert!(!result.desired);
        assert!(result.server_info.is_none());
        assert_eq!(config.get().restream_protocol, RestreamProtocol::Srt);
        assert!(active_restream_generation(&manager).await.is_none());

        let error = manager
            .start_restream_server(&config, &adopted)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), "SrtPassphraseUnavailable");
        assert!(!error.to_string().contains("opaque-ciphertext"));
        let state = manager.state.lock().await;
        assert!(!state.restream_desired);
        assert!(state.restream_server.is_none());
    }

    #[tokio::test]
    async fn switch_invalidates_a_start_before_waiting_for_the_transaction_gate() {
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
        let gate = manager.restream_transaction.clone().lock_owned().await;
        let (start_epoch, _) = manager.begin_restream_start_intent().await.unwrap();
        let commit_called = std::sync::atomic::AtomicBool::new(false);
        let adopted = adopted_set(&[]);

        let operation = manager.switch_restream_protocol_with(
            &config,
            RestreamProtocol::Srt,
            &adopted,
            |config, protocol| {
                commit_called.store(true, std::sync::atomic::Ordering::Release);
                commit_restream_protocol_in_memory(config, protocol)
            },
        );
        let supersede = async {
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                loop {
                    if manager
                        .restream_epoch
                        .load(std::sync::atomic::Ordering::Acquire)
                        > start_epoch
                        && !manager.state.lock().await.restream_desired
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("switch must invalidate the old Start before waiting for the gate");
            assert!(!manager.restream_intent_is_current(start_epoch).await);
            manager
                .begin_restream_stop_intent()
                .await
                .expect("a newer Stop should supersede the waiting switch");
            drop(gate);
        };
        let (result, ()) = tokio::join!(operation, supersede);

        let error = result.unwrap_err();
        assert_eq!(error.kind(), "Stream");
        assert!(error.to_string().contains("superseded"));
        assert!(!commit_called.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(config.get().restream_protocol, RestreamProtocol::Rtsp);
        assert!(active_restream_generation(&manager).await.is_none());
    }

    #[tokio::test]
    async fn active_settings_apply_invalidates_start_before_waiting_for_the_gate() {
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        let mut update = restream_update_from(&settings, true);
        update.rtsp_server.token = "fedcba9876543210".into();
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
        let gate = manager.restream_transaction.clone().lock_owned().await;
        let (start_epoch, _) = manager.begin_restream_start_intent().await.unwrap();
        let commit_called = std::sync::atomic::AtomicBool::new(false);
        let adopted = adopted_set(&[]);

        let operation = manager.apply_restream_settings_with(
            &config,
            update,
            &adopted,
            |config, prospective| {
                commit_called.store(true, std::sync::atomic::Ordering::Release);
                commit_restream_settings_in_memory(config, prospective)
            },
        );
        let supersede = async {
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                loop {
                    if manager
                        .restream_epoch
                        .load(std::sync::atomic::Ordering::Acquire)
                        > start_epoch
                        && !manager.state.lock().await.restream_desired
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("settings apply must invalidate the old Start before waiting for the gate");
            manager
                .begin_restream_stop_intent()
                .await
                .expect("a newer Stop should supersede the waiting apply");
            drop(gate);
        };
        let (result, ()) = tokio::join!(operation, supersede);

        let error = result.unwrap_err();
        assert_eq!(error.kind(), "Stream");
        assert!(error.to_string().contains("superseded"));
        assert!(!commit_called.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(config.get().rtsp_server.token, "0123456789abcdef");
    }

    #[tokio::test]
    async fn live_switch_replaces_exactly_one_listener_in_each_direction() {
        init_gstreamer();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        let rtsp_port = settings.rtsp_server.port;
        let srt_port = settings.srt_server.port;
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
        let adopted = adopted_set(&[]);

        manager
            .start_restream_server(&config, &adopted)
            .await
            .unwrap();
        let initial_generation = active_restream_generation(&manager).await.unwrap();

        let srt_result = manager
            .switch_restream_protocol_with(
                &config,
                RestreamProtocol::Srt,
                &adopted,
                commit_restream_protocol_in_memory,
            )
            .await
            .unwrap();
        assert!(srt_result.desired);
        assert_eq!(srt_result.selected_protocol, RestreamProtocol::Srt);
        assert_eq!(
            srt_result.server_info.unwrap().protocol,
            RestreamProtocol::Srt
        );
        assert_eq!(
            active_restream_generation(&manager).await,
            Some(initial_generation + 1)
        );
        assert!(std::net::TcpListener::bind(("127.0.0.1", rtsp_port)).is_ok());

        let rtsp_result = manager
            .switch_restream_protocol_with(
                &config,
                RestreamProtocol::Rtsp,
                &adopted,
                commit_restream_protocol_in_memory,
            )
            .await
            .unwrap();
        assert!(rtsp_result.desired);
        assert_eq!(rtsp_result.selected_protocol, RestreamProtocol::Rtsp);
        assert_eq!(
            active_restream_generation(&manager).await,
            Some(initial_generation + 2)
        );
        assert!(wait_for_udp_rebind(srt_port).await);

        manager.stop_restream_server().await.unwrap();
        assert!(std::net::TcpListener::bind(("127.0.0.1", rtsp_port)).is_ok());
    }

    #[tokio::test]
    async fn desired_recovering_and_failed_outputs_switch_to_the_new_protocol() {
        init_gstreamer();
        for prior_state in [RelayState::Recovering, RelayState::Failed] {
            let settings = restream_test_settings(RestreamProtocol::Rtsp);
            let srt_port = settings.srt_server.port;
            let config = AppConfig::for_test(settings.clone());
            let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
            let adopted = adopted_set(&[]);
            seed_desired_relay_state(&manager, &settings, prior_state).await;
            assert_eq!(
                compute_status(&manager.state).await.relay_state,
                prior_state
            );

            let result = manager
                .switch_restream_protocol_with(
                    &config,
                    RestreamProtocol::Srt,
                    &adopted,
                    commit_restream_protocol_in_memory,
                )
                .await
                .unwrap();
            assert!(result.desired);
            assert_eq!(result.selected_protocol, RestreamProtocol::Srt);
            assert_eq!(result.server_info.unwrap().protocol, RestreamProtocol::Srt);
            let status = compute_status(&manager.state).await;
            assert!(status.desired);
            assert_eq!(status.active_protocol, Some(RestreamProtocol::Srt));
            assert!(status.server_running);

            manager.stop_restream_server().await.unwrap();
            assert!(wait_for_udp_rebind(srt_port).await);
        }
    }

    #[tokio::test]
    async fn settings_apply_restarts_only_active_changes_and_honors_enable() {
        init_gstreamer();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
        let adopted = adopted_set(&[]);
        manager
            .start_restream_server(&config, &adopted)
            .await
            .unwrap();
        let initial_generation = active_restream_generation(&manager).await.unwrap();

        let mut inactive_update = restream_update_from(&config.get(), true);
        inactive_update.srt_server.latency_ms = 250;
        let inactive_result = manager
            .apply_restream_settings_with(
                &config,
                inactive_update,
                &adopted,
                commit_restream_settings_in_memory,
            )
            .await
            .unwrap();
        assert!(inactive_result.desired);
        assert_eq!(config.get().srt_server.latency_ms, 250);
        assert_eq!(
            active_restream_generation(&manager).await,
            Some(initial_generation)
        );

        let mut active_update = restream_update_from(&config.get(), true);
        active_update.rtsp_server.token = "fedcba9876543210".into();
        let active_result = manager
            .apply_restream_settings_with(
                &config,
                active_update,
                &adopted,
                commit_restream_settings_in_memory,
            )
            .await
            .unwrap();
        assert!(active_result.desired);
        assert_eq!(
            active_restream_generation(&manager).await,
            Some(initial_generation + 1)
        );

        let disable_result = manager
            .apply_restream_settings_with(
                &config,
                restream_update_from(&config.get(), false),
                &adopted,
                commit_restream_settings_in_memory,
            )
            .await
            .unwrap();
        assert!(!disable_result.desired);
        assert!(disable_result.server_info.is_none());
        assert!(!config.get().rtsp_server.enabled);
        assert!(active_restream_generation(&manager).await.is_none());

        let enable_result = manager
            .apply_restream_settings_with(
                &config,
                restream_update_from(&config.get(), true),
                &adopted,
                commit_restream_settings_in_memory,
            )
            .await
            .unwrap();
        assert!(!enable_result.desired);
        assert!(enable_result.server_info.is_none());
        assert!(config.get().rtsp_server.enabled);
        assert!(active_restream_generation(&manager).await.is_none());
    }

    #[tokio::test]
    async fn persistence_failures_restore_settings_selection_and_runtime() {
        init_gstreamer();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
        let adopted = adopted_set(&[]);
        manager
            .start_restream_server(&config, &adopted)
            .await
            .unwrap();
        let initial_generation = active_restream_generation(&manager).await.unwrap();

        let mut update = restream_update_from(&config.get(), true);
        update.rtsp_server.token = "fedcba9876543210".into();
        let settings_error = manager
            .apply_restream_settings_with(&config, update, &adopted, |_, _| {
                Err(AppError::Config("injected settings write failure".into()))
            })
            .await
            .unwrap_err();
        assert_eq!(settings_error.kind(), "Config");
        assert_eq!(config.get().rtsp_server.token, "0123456789abcdef");
        assert_eq!(
            active_restream_generation(&manager).await,
            Some(initial_generation + 1)
        );
        {
            let state = manager.state.lock().await;
            assert!(state.restream_desired);
            assert_eq!(state.selected_protocol, RestreamProtocol::Rtsp);
            assert!(state
                .restream_server
                .as_ref()
                .is_some_and(|server| server.protocol() == RestreamProtocol::Rtsp));
        }

        let selector_error = manager
            .switch_restream_protocol_with(&config, RestreamProtocol::Srt, &adopted, |_, _| {
                Err(AppError::Config("injected selector write failure".into()))
            })
            .await
            .unwrap_err();
        assert_eq!(selector_error.kind(), "Config");
        assert_eq!(config.get().restream_protocol, RestreamProtocol::Rtsp);
        assert_eq!(
            active_restream_generation(&manager).await,
            Some(initial_generation + 2)
        );
        let status = compute_status(&manager.state).await;
        assert!(status.desired);
        assert_eq!(status.selected_protocol, RestreamProtocol::Rtsp);
        assert_eq!(status.active_protocol, Some(RestreamProtocol::Rtsp));

        manager.stop_restream_server().await.unwrap();
    }

    #[tokio::test]
    async fn persistence_and_restoration_failures_are_reported_together() {
        init_gstreamer();
        let settings = restream_test_settings(RestreamProtocol::Srt);
        let srt_port = settings.srt_server.port;
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Srt);
        let adopted = adopted_set(&[]);
        manager
            .start_restream_server(&config, &adopted)
            .await
            .unwrap();
        let occupied = std::sync::Mutex::new(None);

        let mut update = restream_update_from(&config.get(), true);
        update.srt_server.stream_id = "replacement".into();
        let error = manager
            .apply_restream_settings_with(&config, update, &adopted, |_, _| {
                let listener = bind_udp_after_release(srt_port);
                *occupied.lock().unwrap() = Some(listener);
                Err(AppError::Config("injected settings write failure".into()))
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), "Config");
        assert!(error
            .to_string()
            .contains("injected settings write failure"));
        assert!(
            error
                .to_string()
                .contains("restoring the prior re-stream output also failed"),
            "unexpected error: {error}"
        );
        assert!(config.get().srt_server.stream_id.is_empty());
        let status = compute_status(&manager.state).await;
        assert!(status.desired);
        assert_eq!(status.relay_state, RelayState::Failed);
        assert!(!status.server_running);

        occupied.lock().unwrap().take();
        manager.stop_restream_server().await.unwrap();
    }

    #[tokio::test]
    async fn unavailable_live_srt_switch_fails_before_disrupting_rtsp() {
        init_gstreamer();
        let mut settings = restream_test_settings(RestreamProtocol::Rtsp);
        settings.srt_server.passphrase = SrtPassphraseState::Unavailable {
            preserved_ciphertext: "opaque-ciphertext".into(),
        };
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
        let adopted = adopted_set(&[]);
        manager
            .start_restream_server(&config, &adopted)
            .await
            .unwrap();
        let generation = active_restream_generation(&manager).await.unwrap();
        let epoch = manager
            .restream_epoch
            .load(std::sync::atomic::Ordering::Acquire);
        let commit_called = std::sync::atomic::AtomicBool::new(false);

        let error = manager
            .switch_restream_protocol_with(
                &config,
                RestreamProtocol::Srt,
                &adopted,
                |config, protocol| {
                    commit_called.store(true, std::sync::atomic::Ordering::Release);
                    commit_restream_protocol_in_memory(config, protocol)
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), "SrtPassphraseUnavailable");
        assert!(!error.to_string().contains("opaque-ciphertext"));
        assert!(!commit_called.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(
            manager
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire),
            epoch
        );
        assert_eq!(active_restream_generation(&manager).await, Some(generation));
        let status = compute_status(&manager.state).await;
        assert!(status.desired);
        assert_eq!(status.selected_protocol, RestreamProtocol::Rtsp);
        assert_eq!(status.active_protocol, Some(RestreamProtocol::Rtsp));

        manager.stop_restream_server().await.unwrap();
    }

    #[tokio::test]
    async fn srt_dispatch_populates_protocol_neutral_status() {
        init_gstreamer();
        let udp_port = unused_udp_port();
        let mut server_port = unused_udp_port();
        while server_port == udp_port {
            server_port = unused_udp_port();
        }
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Srt);
        let spec = ResolvedStartSpec {
            source: ResolvedSource::Udp { port: udp_port },
            output: ResolvedOutput::Srt {
                server_port,
                passphrase: String::new(),
                latency_ms: 125,
                stream_id: "field unit".into(),
            },
            bind_interface: Some("ZeroTier".into()),
            bind_identity: None,
            bind_scope: crate::network::bindings::BindScope::default(),
            bind_address: Some("127.0.0.1".into()),
            advertised_ip: "127.0.0.1".into(),
            username: String::new(),
            password: String::new(),
        };
        let health = Arc::new(RelayRuntimeHealth::new(73, relay::RelayIngestKind::Udp));
        let (_, built) = StreamManager::build_restream_server(
            &spec,
            health.clone(),
            manager.relay_event_tx.clone(),
            false,
            None,
        );
        let server = match built {
            Ok(server) => server,
            Err(failure) => panic!("SRT dispatch failed: {}", failure.error),
        };
        assert_eq!(server.protocol(), RestreamProtocol::Srt);
        assert_eq!(server.client_limit(), 10);
        assert!(server.loop_alive());
        assert!(matches!(server.fault_probe(), RelayFaultProbe::Srt(_)));

        {
            let mut state = manager.state.lock().await;
            state.restream_desired = true;
            state.restream_spec = Some(spec);
            state.restream_health = Some(health);
            state.restream_server = Some(server);
            state.restream_intent_epoch = Some(0);
            state.restream_start_time = Some(std::time::Instant::now());
        }
        let status = compute_status(&manager.state).await;
        assert_eq!(status.selected_protocol, RestreamProtocol::Srt);
        assert_eq!(status.active_protocol, Some(RestreamProtocol::Srt));
        assert!(status.server_running);
        let expected_url = format!("srt://127.0.0.1:{server_port}?streamid=field%20unit");
        let expected_display_url = format!("srt://127.0.0.1:{server_port}");
        assert_eq!(status.server_url.as_deref(), Some(expected_url.as_str()));
        assert_eq!(
            status.display_url.as_deref(),
            Some(expected_display_url.as_str())
        );

        let mut server = {
            let mut state = manager.state.lock().await;
            state.restream_server.take().unwrap()
        };
        server.shutdown().await;
        assert!(!server.loop_alive());
    }

    #[tokio::test]
    async fn start_intent_is_visible_before_resolution_and_stop_supersedes_it() {
        let manager = StreamManager::new();
        let (start_epoch, preserve_prior_desired) = manager
            .begin_restream_start_intent()
            .await
            .expect("start intent should remain current");
        assert!(!preserve_prior_desired);

        {
            let state = manager.state.lock().await;
            assert!(state.restream_desired);
            assert_eq!(state.restream_intent_epoch, Some(start_epoch));
            assert!(state.restream_spec.is_none());
            assert!(state.restream_health.is_none());
        }
        let status = compute_status(&manager.state).await;
        assert!(status.desired);
        assert_eq!(status.relay_state, RelayState::Starting);
        assert_eq!(status.active_protocol, None);

        let stop_intent = manager
            .begin_restream_stop_intent()
            .await
            .expect("stop intent should remain current");
        assert!(stop_intent.epoch > start_epoch);
        assert!(!manager.restream_intent_is_current(start_epoch).await);
        manager
            .cancel_restream_start_intent(start_epoch, false)
            .await;

        let state = manager.state.lock().await;
        assert!(!state.restream_desired);
        assert!(state.restream_intent_epoch.is_none());
    }

    #[tokio::test]
    async fn failed_initial_start_clears_current_intent() {
        let manager = StreamManager::new();
        let (start_epoch, preserve_prior_desired) = manager
            .begin_restream_start_intent()
            .await
            .expect("start intent should remain current");
        assert!(!preserve_prior_desired);

        manager
            .cancel_restream_start_intent(start_epoch, preserve_prior_desired)
            .await;

        let state = manager.state.lock().await;
        assert!(!state.restream_desired);
        assert!(state.restream_intent_epoch.is_none());
        assert!(state.restream_spec.is_none());
        assert!(state.restream_health.is_none());
        assert!(state.restream_start_time.is_none());
    }

    #[tokio::test]
    async fn stale_start_publication_cannot_reassert_desired() {
        let manager = StreamManager::new();
        manager
            .restream_epoch
            .store(2, std::sync::atomic::Ordering::Release);

        assert!(manager.publish_restream_start_intent(1).await.is_none());
        let state = manager.state.lock().await;
        assert!(!state.restream_desired);
        assert!(state.restream_intent_epoch.is_none());
    }

    #[tokio::test]
    async fn settings_stop_claim_rejects_a_newer_start() {
        let manager = StreamManager::new();
        let operation_epoch = manager
            .restream_epoch
            .load(std::sync::atomic::Ordering::Acquire);
        let (newer_epoch, _) = manager
            .begin_restream_start_intent()
            .await
            .expect("newer start should publish");

        assert!(manager
            .begin_restream_stop_intent_if_current(operation_epoch)
            .await
            .is_none());
        let state = manager.state.lock().await;
        assert!(state.restream_desired);
        assert_eq!(state.restream_intent_epoch, Some(newer_epoch));
    }

    #[tokio::test]
    async fn transactional_restart_cannot_override_a_newer_stop() {
        let manager = StreamManager::new();
        manager
            .begin_restream_start_intent()
            .await
            .expect("initial start should publish");
        let transaction_stop = manager
            .begin_restream_stop_intent()
            .await
            .expect("transaction stop should publish");
        manager
            .begin_restream_stop_intent()
            .await
            .expect("newer stop should publish");

        assert!(manager
            .begin_restream_start_intent_if_current(transaction_stop.epoch)
            .await
            .is_none());
        let state = manager.state.lock().await;
        assert!(!state.restream_desired);
        assert!(state.restream_intent_epoch.is_none());
    }

    #[test]
    fn stop_tears_down_the_stored_listener_not_an_in_flight_generation() {
        assert_eq!(restream_stop_target(true, Some(2), Some(1)), Some(1));
        assert_eq!(restream_stop_target(true, Some(2), None), None);
        assert_eq!(restream_stop_target(false, Some(2), Some(2)), None);
        assert_eq!(restream_stop_target(false, Some(2), Some(1)), Some(1));
    }

    #[tokio::test]
    async fn recovery_status_keeps_desired_urls_without_a_listener() {
        let manager = StreamManager::new();
        let spec = ResolvedStartSpec {
            source: ResolvedSource::Rtsp {
                url: "rtsp://192.0.2.20/live".into(),
            },
            output: ResolvedOutput::Rtsp {
                server_port: 8554,
                mount_path: "/stream-stable-token".into(),
            },
            bind_interface: Some("VPN".into()),
            bind_identity: None,
            bind_scope: crate::network::bindings::BindScope::default(),
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
            state.restream_desired = true;
            state.restream_spec = Some(spec);
            state.restream_health = Some(health);
            state.restream_intent_epoch = Some(0);
            state.restream_start_time = Some(std::time::Instant::now());
        }

        let status = compute_status(&manager.state).await;
        assert!(status.desired);
        assert_eq!(status.active_protocol, Some(RestreamProtocol::Rtsp));
        assert!(!status.server_running);
        assert_eq!(status.relay_state, RelayState::Recovering);
        assert_eq!(
            status.server_url.as_deref(),
            Some(expected_client_url.as_str())
        );
        assert_eq!(
            status.display_url.as_deref(),
            Some(expected_display_url.as_str())
        );
    }

    async fn seed_desired_relay(manager: &StreamManager, generation: u64, epoch: u64) {
        let mut state = manager.state.lock().await;
        state.restream_desired = true;
        state.restream_health = Some(Arc::new(RelayRuntimeHealth::new(
            generation,
            relay::RelayIngestKind::Rtsp,
        )));
        state.restream_intent_epoch = Some(epoch);
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
            let epoch = manager.restream_epoch.clone();
            let wake = manager.relay_wake.clone();
            let started_at = tokio::time::Instant::now();
            let waiter = tokio::spawn(async move {
                wait_relay_backoff(&state, &epoch, &wake, 0, 1, delay).await
            });
            tokio::task::yield_now().await;

            manager
                .restream_epoch
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
        let epoch = manager.restream_epoch.clone();
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
            state.restream_health = Some(Arc::new(RelayRuntimeHealth::new(
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
        let initial = StreamStatus::idle(RestreamProtocol::Rtsp);
        let (tx, mut rx) = watch::channel(initial.clone());
        rx.borrow_and_update();

        let mut updated = initial;
        updated.connected_clients = 1;
        publish_status_if_changed(&tx, updated.clone());

        assert!(rx.has_changed().unwrap());
        assert_eq!(rx.borrow_and_update().connected_clients, 1);

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
