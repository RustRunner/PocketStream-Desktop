pub mod audio;
mod caller_registry;
pub mod recorder;
mod relay;
pub mod rtsp_client;
pub mod rtsp_server;
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
    pub playing: bool,
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
            playing: false,
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
    playback_epoch: std::sync::atomic::AtomicU64,
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
            state: Arc::new(Mutex::new(StreamState {
                playback: None,
                selected_protocol,
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
            playback_epoch: std::sync::atomic::AtomicU64::new(0),
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

        // Capture the stop epoch before any slow work. stop_playback bumps
        // it unconditionally, so if it changes before we store the new
        // pipeline a stop raced us and must win (see the storage step below).
        let start_epoch = self
            .playback_epoch
            .load(std::sync::atomic::Ordering::Acquire);

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
                let desired_conflict = state.restream_desired
                    && state
                        .restream_spec
                        .as_ref()
                        .and_then(ResolvedStartSpec::udp_ingest_port)
                        == Some(settings.stream.udp_port);
                let live_conflict = state
                    .restream_server
                    .as_ref()
                    .and_then(|s| s.udp_ingest_port())
                    == Some(settings.stream.udp_port);
                let conflict = desired_conflict || live_conflict;
                if conflict {
                    return Err(AppError::Stream(format!(
                        "UDP port {} is already claimed by the re-stream \
                         server — only one consumer can receive a UDP stream. \
                         Stop the re-stream server first, or switch the input to RTSP.",
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
                    settings.stream.audio_muted,
                )?
            }
        };

        pipeline.play()?;

        // Second lock acquisition (take-old above, store-new here). A stop
        // landing in the window between them "succeeds" against an empty
        // state, so store only if no stop raced us since `start_epoch` (a
        // concurrent stop bumps the epoch even during the take-old window
        // above, when no pipeline is stored). If it changed the user asked
        // for no playback: stop the pipeline we just built and report the
        // supersession rather than leaving a zombie preview.
        {
            let mut state = self.state.lock().await;
            if self
                .playback_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                != start_epoch
            {
                drop(state);
                log::info!(
                    "Playback start superseded by a concurrent stop — discarding built pipeline"
                );
                if let Err(e) = pipeline.stop() {
                    log::warn!("Stopping superseded playback pipeline failed: {}", e);
                }
                return Err(AppError::Stream(
                    "Playback start was superseded by a stop".into(),
                ));
            }
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
        // Record stop intent unconditionally, even when no pipeline is
        // stored: start_playback takes the old pipeline out before its slow
        // build, so during that window playback is None and a stop here
        // would otherwise be invisible to the late start — which would then
        // store a playing pipeline the user asked to stop. Bumping the
        // epoch makes the start observe it.
        self.playback_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
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

        // HWND ownership is reconciled by the command layer, which captured
        // the handle belonging to this stop before awaiting us. It clears
        // that exact value conditionally so a late old stop cannot erase a
        // replacement window's handle.
        self.refresh_status().await;

        Ok(())
    }

    async fn resolve_restream_start_spec(
        settings: &AppSettings,
        adopted: &std::collections::HashSet<String>,
    ) -> Result<ResolvedStartSpec, AppError> {
        let (bind_interface, output) = resolve_selected_restream_output(settings)?;
        let bind_address = resolve_explicit_bind(bind_interface.as_deref(), adopted).await?;
        let advertised_ip = match &bind_address {
            Some(ip) => ip.clone(),
            None => get_display_ip(adopted)
                .await
                .unwrap_or_else(|| "0.0.0.0".into()),
        };
        let source = match settings.stream.protocol {
            StreamProtocol::Rtsp => ResolvedSource::Rtsp {
                url: Self::build_input_url(settings)?,
            },
            StreamProtocol::Udp => ResolvedSource::Udp {
                port: settings.stream.udp_port,
            },
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
    ) -> (u64, Result<RestreamServer, RestreamBuildFailure>) {
        let server_instance = health.begin_server_instance(recovering);
        let runtime = RestreamRuntimeContext {
            health,
            event_tx,
            server_instance,
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

        let info = RestreamServerInfo {
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
            if healthy_noop {
                log::info!(
                    "Explicit re-stream Start resolved to the healthy current endpoint; no-op"
                );
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
            state.restream_spec = Some(spec.clone());
            state.restream_health = Some(health.clone());
            state.restream_start_time = Some(std::time::Instant::now());
            (server_generation, health)
        };

        self.relay_wake.notify_waiters();
        self.refresh_status().await;

        let gst_error = crate::ensure_gstreamer().err();
        let firewall_rule = match spec.protocol() {
            RestreamProtocol::Rtsp => crate::network::firewall::FirewallRule::Rtsp,
            RestreamProtocol::Srt => crate::network::firewall::FirewallRule::Srt,
        };
        if let Err(error) =
            crate::network::firewall::ensure_restream_allowed(firewall_rule, spec.server_port())
                .await
        {
            log::warn!("Firewall setup: {}", error);
        }

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
            old_server.shutdown().await;
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

        let (server_instance, built) =
            Self::build_restream_server(&spec, health.clone(), self.relay_event_tx.clone(), false);
        let server = match built {
            Ok(server) => server,
            Err(failure) => {
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
            {
                state.restream_server = candidate.take();
            }
        }
        if let Some(mut stale) = candidate {
            stale.shutdown().await;
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

    async fn publish_restream_stop_intent(&self, stop_epoch: u64) -> Option<RestreamStopIntent> {
        self.relay_wake.notify_waiters();

        let (target_generation, was_desired) = {
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

            let target = restream_stop_target(stops_desired, desired_generation, live_generation);

            if stops_desired {
                if let Some(health) = state.restream_health.as_ref() {
                    health.stop();
                }
                state.restream_desired = false;
                state.restream_spec = None;
                state.restream_health = None;
                state.restream_intent_epoch = None;
                state.restream_start_time = None;
            }
            (target, stops_desired)
        };
        self.refresh_status().await;

        Some(RestreamStopIntent {
            epoch: stop_epoch,
            target_generation,
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
                .then(|| state.restream_spec.as_ref().map(Self::info_from_spec))
                .flatten(),
        }
    }

    fn info_from_spec(spec: &ResolvedStartSpec) -> RestreamServerInfo {
        RestreamServerInfo {
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
            };
            tauri::async_runtime::spawn(run_relay_supervisor(relay_events, supervisor));
        } else {
            log::warn!("Re-stream relay supervisor was already started");
        }

        let state_for_tick = self.state.clone();
        let tx_for_tick = self.status_tx.clone();
        tauri::async_runtime::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let snap = compute_status(&state_for_tick).await;
                publish_status_if_changed(tx_for_tick.as_ref(), snap);
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

    /// Apply the mute preference to live playback, if any. Persistence
    /// happens in the command layer; with no pipeline this is a no-op —
    /// the next start seeds the preference from config. Clone the
    /// pipeline Arc out under the lock, poke GStreamer outside it (the
    /// one lock discipline for StreamManager).
    pub async fn set_audio_muted(&self, muted: bool) {
        let pipeline = {
            let state = self.state.lock().await;
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
        && current_spec == Some(candidate_spec)
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
                recover_relay_generation(&ctx, expected_epoch, generation).await;
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
                recover_relay_generation(&ctx, expected_epoch, server_generation).await;
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
) {
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
    }
    publish_relay_status(ctx).await;

    loop {
        let Some((current_epoch, health)) = current_relay_context(ctx, server_generation).await
        else {
            return;
        };
        if current_epoch != expected_epoch {
            return;
        }

        let (_attempt, delay) = health.schedule_recovery_attempt();
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

        if health.should_reresolve_explicit_bind() {
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
                match resolve_explicit_bind(Some(interface_name), &adopted).await {
                    Ok(Some(new_address)) => {
                        build_spec.bind_address = Some(new_address.clone());
                        build_spec.advertised_ip = new_address;
                    }
                    Ok(None) => unreachable!("an explicit interface resolves to an address"),
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

        if let Err(error) = crate::ensure_gstreamer() {
            let server_instance = health.begin_server_instance(true);
            let reason = redact_relay_text(&error.to_string(), build_spec.mount_path());
            health.mark_build_failed(server_instance, reason, false);
            drop(_lifecycle);
            publish_relay_status(ctx).await;
            continue;
        }

        let (server_instance, result) = StreamManager::build_restream_server(
            &build_spec,
            health.clone(),
            ctx.relay_event_tx.clone(),
            true,
        );
        let server = match result {
            Ok(server) => server,
            Err(failure) => {
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
            {
                // Publish a re-resolved address only after it bound
                // successfully. Port, interface, mount, token, and source are
                // byte-for-byte inherited from the desired specification.
                state.restream_spec = Some(build_spec);
                state.restream_server = candidate.take();
            }
        }
        if let Some(mut stale) = candidate {
            stale.shutdown().await;
            return;
        }

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

    let (playing, error) = match state.playback.as_ref() {
        Some(p) => match p.health_check() {
            Ok(healthy) => (healthy, None),
            Err(msg) => (false, Some(msg)),
        },
        None => (false, None),
    };

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
                audio_muted: false,
            },
            restream_protocol: RestreamProtocol::Rtsp,
            rtsp_server: RtspServerConfig {
                enabled: false,
                port: 8554,
                token: "0123456789abcdef".into(),
                bind_interface: String::new(),
            },
            srt_server: SrtServerConfig::default(),
            credentials: Credentials {
                username: username.into(),
                password: password.into(),
            },
            adopted_subnets: std::collections::HashMap::new(),
            adopted_meta: std::collections::HashMap::new(),
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
            },
            srt_server: SrtServerUpdate {
                port: i64::from(settings.srt_server.port),
                passphrase: SrtPassphraseUpdate::Keep,
                latency_ms: i64::from(settings.srt_server.latency_ms),
                stream_id: settings.srt_server.stream_id.clone(),
                bind_interface: settings.srt_server.bind_interface.clone(),
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

    fn resolved_spec_for_test(settings: &AppSettings) -> ResolvedStartSpec {
        let (_, output) = resolve_selected_restream_output(settings).unwrap();
        ResolvedStartSpec {
            source: ResolvedSource::Udp {
                port: settings.stream.udp_port,
            },
            output,
            bind_interface: None,
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
