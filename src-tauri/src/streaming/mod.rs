pub mod audio;
mod caller_registry;
mod classify;
mod playback;
mod relay_service;
use relay_service::RestreamServer;
#[cfg(test)]
use relay_service::*;
use state::StreamState;
pub mod recorder;
mod relay;
pub mod rtsp_client;
pub mod rtsp_server;
mod rtsp_transport;
mod source;
mod srt_server;
mod state;
mod status;
use source::*;
mod udp;
pub mod video_embed;
mod video_surface;
use playback::SourceMode;
#[cfg(test)]
use status::compute_status;

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
    let redacted = redact_url(text);
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

pub struct StreamManager {
    #[cfg(test)]
    state: Arc<Mutex<StreamState>>,
    surface: Arc<video_surface::VideoSurface>,
    bridge: Arc<dyn crate::bridge::AppBridge>,
    status: status::StatusPublisher,
    playback: Arc<playback::PlaybackService>,
    relay: Arc<relay_service::RelayService>,
}

impl StreamManager {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_selected_protocol(RestreamProtocol::Rtsp)
    }

    #[cfg(test)]
    pub fn with_selected_protocol(selected_protocol: RestreamProtocol) -> Self {
        Self::with_bridge(
            selected_protocol,
            Arc::new(crate::bridge::RecordingBridge::default()),
        )
    }

    pub(crate) fn with_bridge(
        selected_protocol: RestreamProtocol,
        bridge: Arc<dyn crate::bridge::AppBridge>,
    ) -> Self {
        let state = state::new(selected_protocol);
        let status = status::StatusPublisher::new(state.clone(), selected_protocol);
        let surface = Arc::new(video_surface::VideoSurface::new(bridge.clone()));
        let playback = Arc::new(playback::PlaybackService::new(
            state::PlaybackSlot::new(state.clone()),
            status.clone(),
            surface.clone(),
        ));
        let relay = Arc::new(relay_service::RelayService::new(
            state::RelaySlot::new(state.clone()),
            status.clone(),
        ));
        Self {
            #[cfg(test)]
            state,
            surface,
            bridge,
            status,
            playback,
            relay,
        }
    }

    pub async fn start_playback(
        &self,
        settings: &AppSettings,
        window_handle: Option<usize>,
    ) -> Result<(), AppError> {
        self.playback.start_playback(settings, window_handle).await
    }
    pub async fn retry_playback(
        &self,
        manual: bool,
        settings: Option<AppSettings>,
    ) -> Result<(), AppError> {
        self.playback.retry_playback(manual, settings).await
    }
    pub async fn stop_playback(&self) -> Result<(), AppError> {
        self.playback.stop_playback().await
    }
    pub async fn take_screenshot(&self) -> Result<String, AppError> {
        self.playback.take_screenshot().await
    }
    pub async fn start_recording(&self) -> Result<(), AppError> {
        self.playback.start_recording().await
    }
    pub async fn stop_recording(&self) -> Result<String, AppError> {
        self.playback.stop_recording().await
    }
    pub async fn set_audio_muted(&self, muted: bool) {
        self.playback.set_audio_muted(muted).await
    }

    pub async fn start_restream_server(
        &self,
        config: &AppConfig,
        adopted: &std::collections::HashSet<String>,
    ) -> Result<RestreamServerInfo, AppError> {
        self.relay.start_restream_server(config, adopted).await
    }
    pub async fn stop_restream_server(&self) -> Result<(), AppError> {
        self.relay.stop_restream_server().await
    }
    pub(crate) async fn startup_firewall_status(&self, outcome: FirewallOutcome) {
        self.relay.startup_firewall_status(outcome).await
    }
    pub(crate) async fn binding_topology_changed(&self, scope: BindScope, revision: u64) {
        self.relay.binding_topology_changed(scope, revision).await
    }
    pub async fn apply_restream_settings(
        &self,
        config: &AppConfig,
        update: RestreamSettingsUpdate,
        adopted: &std::collections::HashSet<String>,
    ) -> Result<RestreamOperationResult, AppError> {
        self.relay
            .apply_restream_settings(config, update, adopted)
            .await
    }
    pub async fn switch_restream_protocol(
        &self,
        config: &AppConfig,
        protocol: RestreamProtocol,
        adopted: &std::collections::HashSet<String>,
    ) -> Result<RestreamOperationResult, AppError> {
        self.relay
            .switch_restream_protocol(config, protocol, adopted)
            .await
    }

    /// Recompute status from internal state and publish to subscribers.
    /// Called after every command-side mutation, plus on the 1Hz ticker
    /// for uptime / bandwidth refresh.
    #[cfg(test)]
    async fn refresh_status(&self) {
        self.status.refresh().await;
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
    pub fn start_status_emitter(&self, readiness: Arc<crate::network::readiness::CameraReadiness>) {
        if let Some((events, context)) = self.relay.supervisor(readiness.clone()) {
            tauri::async_runtime::spawn(relay_service::run_relay_supervisor(events, context));
        } else {
            log::warn!("Re-stream relay supervisor was already started");
        }

        tauri::async_runtime::spawn(playback::run_playback_supervisor(
            self.playback.context(Some(readiness)),
        ));

        tauri::async_runtime::spawn(status::broadcast(
            self.status.tx.subscribe(),
            self.bridge.clone(),
        ));
    }

    pub(crate) fn video_surface(&self) -> &video_surface::VideoSurface {
        &self.surface
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    pub(super) fn init_gstreamer() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| gst::init().expect("GStreamer test initialization failed"));
    }

    pub(super) fn ip(addr: &str) -> crate::network::interface::IpInfo {
        crate::network::interface::IpInfo {
            address: addr.into(),
            prefix: 24,
            subnet: "0.0.0.0/24".into(),
        }
    }

    pub(super) fn adopted_set(addrs: &[&str]) -> std::collections::HashSet<String> {
        addrs.iter().map(|s| s.to_string()).collect()
    }

    pub(super) fn unused_udp_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    pub(super) fn unused_tcp_port() -> u16 {
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

    pub(super) fn make_settings(
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

    pub(super) fn restream_test_settings(protocol: RestreamProtocol) -> AppSettings {
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

    pub(super) fn restream_update_from(
        settings: &AppSettings,
        enabled: bool,
    ) -> RestreamSettingsUpdate {
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

    pub(super) fn commit_restream_settings_in_memory(
        config: &AppConfig,
        prospective: &AppSettings,
    ) -> Result<AppSettings, AppError> {
        config.commit_restream_settings_with(
            prospective.rtsp_server.clone(),
            prospective.srt_server.clone(),
            |_| Ok(()),
        )
    }

    pub(super) fn commit_restream_protocol_in_memory(
        config: &AppConfig,
        protocol: RestreamProtocol,
    ) -> Result<AppSettings, AppError> {
        config.commit_restream_protocol_with(protocol, |_| Ok(()))
    }

    pub(super) async fn active_restream_generation(manager: &StreamManager) -> Option<u64> {
        manager
            .state
            .lock()
            .await
            .relay_data
            .restream_server
            .as_ref()
            .map(RestreamServer::server_generation)
    }

    pub(super) fn resolved_spec_for_test(settings: &AppSettings) -> ResolvedStartSpec {
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

    pub(super) async fn seed_desired_relay_state(
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
        state.relay_data.restream_desired = true;
        state.relay_data.restream_spec = Some(resolved_spec_for_test(settings));
        state.relay_data.restream_health = Some(health);
        state.relay_data.restream_intent_epoch = Some(
            manager
                .relay
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire),
        );
        state.relay_data.restream_start_time = Some(std::time::Instant::now());
    }

    pub(super) async fn wait_for_udp_rebind(port: u16) -> bool {
        for _ in 0..40 {
            if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        false
    }

    pub(super) fn bind_udp_after_release(port: u16) -> std::net::UdpSocket {
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
        assert_eq!(redact_url(url), "rtsp://admin:***@192.168.1.50:554/live");
    }

    #[test]
    fn redact_url_without_credentials() {
        let url = "rtsp://192.168.1.50:554/live";
        assert_eq!(redact_url(url), url);
    }

    #[test]
    fn redact_url_empty_password() {
        let url = "rtsp://admin:@192.168.1.50:554/live";
        assert_eq!(redact_url(url), "rtsp://admin:***@192.168.1.50:554/live");
    }

    #[test]
    fn redact_url_udp() {
        let url = "udp://@:8600";
        assert_eq!(redact_url(url), url);
    }

    #[test]
    fn redact_url_embedded_in_bus_debug_text() {
        // Bus error/debug payloads replay the input URL mid-sentence;
        // redaction must work there, not just on bare URLs.
        let text = "gstrtspsrc.c:1234: could not connect to rtsp://admin:hunter2@10.0.0.5:554/live (timeout)";
        let redacted = redact_url(text);
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

    // ── build_input_url ─────────────────────────────────────────────

    #[test]
    fn build_url_rtsp_omits_credentials() {
        // Credentials are carried via rtspsrc user-id/user-pw now, never
        // embedded — so a password with URL-special characters can't
        // produce a malformed URL, and creds stay out of pipeline logs.
        let s = make_settings(StreamProtocol::Rtsp, "192.168.1.10", "admin", "p@ss:w/rd");
        let url = build_input_url(&s).unwrap();
        assert_eq!(url, "rtsp://192.168.1.10:554/live");
        assert!(!url.contains("admin"));
        assert!(!url.contains("p@ss"));
    }

    #[test]
    fn build_url_rtsp_without_credentials() {
        let s = make_settings(StreamProtocol::Rtsp, "192.168.1.10", "", "");
        let url = build_input_url(&s).unwrap();
        assert_eq!(url, "rtsp://192.168.1.10:554/live");
    }

    #[test]
    fn build_url_udp() {
        let s = make_settings(StreamProtocol::Udp, "", "", "");
        let url = build_input_url(&s).unwrap();
        assert_eq!(url, "udp://@:8600");
    }

    #[test]
    fn build_url_udp_ignores_camera_ip() {
        let s = make_settings(StreamProtocol::Udp, "169.254.1.1", "admin", "pass");
        let url = build_input_url(&s).unwrap();
        assert_eq!(url, "udp://@:8600");
    }

    #[test]
    fn build_url_custom_port_and_path() {
        let mut s = make_settings(StreamProtocol::Rtsp, "10.0.0.5", "", "");
        s.stream.rtsp_port = 8554;
        s.stream.rtsp_path = "/cam1/main".into();
        let url = build_input_url(&s).unwrap();
        assert_eq!(url, "rtsp://10.0.0.5:8554/cam1/main");
    }

    #[test]
    fn build_url_custom_udp_port() {
        let mut s = make_settings(StreamProtocol::Udp, "", "", "");
        s.stream.udp_port = 9999;
        let url = build_input_url(&s).unwrap();
        assert_eq!(url, "udp://@:9999");
    }

    #[test]
    fn build_url_rejects_invalid_camera_ip() {
        let s = make_settings(StreamProtocol::Rtsp, "not-an-ip", "", "");
        assert!(build_input_url(&s).is_err());
    }

    #[tokio::test]
    async fn build_url_rejects_apipa_for_preview_and_relay() {
        let s = make_settings(StreamProtocol::Rtsp, "169.254.73.42", "", "");
        let error = build_input_url(&s).unwrap_err().to_string();
        assert!(error.contains("routable IPv4 address first"));
        assert!(
            RelayService::resolve_restream_start_spec(&s, &std::collections::HashSet::new())
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
        assert!(build_input_url(&s).is_err());
    }

    // ── StreamStatus ────────────────────────────────────────────────

    // ── StreamManager ───────────────────────────────────────────────

    #[tokio::test]
    async fn stream_manager_initial_status() {
        let mgr = StreamManager::new();
        let status = mgr.status.tx.borrow().clone();
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

    pub(super) async fn seed_desired_relay(manager: &StreamManager, generation: u64, epoch: u64) {
        let mut state = manager.state.lock().await;
        state.relay_data.restream_desired = true;
        state.relay_data.restream_health = Some(Arc::new(RelayRuntimeHealth::new(
            generation,
            relay::RelayIngestKind::Rtsp,
        )));
        state.relay_data.restream_intent_epoch = Some(epoch);
    }

    #[tokio::test]
    async fn refresh_status_updates_watch_channel() {
        let mgr = StreamManager::new();
        let mut rx = mgr.status.tx.subscribe();
        // Mark recording without going through start_recording so we can
        // verify refresh_status actually publishes the new state.
        {
            let mut state = mgr.state.lock().await;
            state.playback_data.recording = true;
        }
        mgr.refresh_status().await;
        let snap = rx.borrow_and_update().clone();
        assert!(snap.recording);
    }

    #[tokio::test]
    async fn refresh_status_dedupes_identical_snapshots() {
        let mgr = StreamManager::new();
        let mut rx = mgr.status.tx.subscribe();
        // Drain initial value so `has_changed` reflects only post-init events.
        rx.borrow_and_update();
        mgr.refresh_status().await;
        // No mutation happened — snapshot is identical to the initial one,
        // so the watch channel must not have ticked.
        assert!(!rx.has_changed().unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_udp_starts_admit_only_one_owner() {
        init_gstreamer();
        let manager = StreamManager::new();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        let (epoch, preserve) = manager.relay.begin_restream_start_intent().await.unwrap();
        let adopted = Default::default();
        let (preview, relay) = tokio::join!(
            manager.start_playback(&settings, None),
            manager
                .relay
                .start_restream_server_inner(&settings, &adopted, epoch, preserve)
        );
        assert_ne!(
            preview.is_ok(),
            relay.is_ok(),
            "preview={preview:?} relay={relay:?}"
        );
        let error = match preview {
            Err(error) => error,
            Ok(()) => relay.unwrap_err(),
        };
        assert!(error.to_string().contains("already claimed"), "{error}");
        manager.stop_playback().await.unwrap();
        manager.stop_restream_server().await.unwrap();
    }

    #[tokio::test]
    async fn udp_failed_build_keeps_desired_claim_until_stop_and_stale_stop_preserves_replacement()
    {
        init_gstreamer();
        let manager = StreamManager::new();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        seed_desired_relay_state(&manager, &settings, RelayState::Failed).await;
        assert!(manager
            .start_playback(&settings, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("already claimed by the re-stream server"));
        let old_stop = manager.relay.begin_restream_stop_intent().await.unwrap();
        seed_desired_relay_state(&manager, &settings, RelayState::Recovering).await;
        let (epoch, _) = manager.relay.begin_restream_start_intent().await.unwrap();
        manager.state.lock().await.relay_data.restream_intent_epoch = Some(epoch);
        manager.relay.finish_restream_stop(old_stop).await.unwrap();
        assert!(manager.start_playback(&settings, None).await.is_err());
        manager.stop_restream_server().await.unwrap();
        manager.start_playback(&settings, None).await.unwrap();
        manager.stop_playback().await.unwrap();
        let state = manager.state.lock().await;
        udp::guard_relay(&state, settings.stream.udp_port).unwrap();
    }

    #[tokio::test]
    async fn coherent_status_waits_for_whole_cross_owner_transition() {
        let manager = StreamManager::new();
        let mut state = manager.state.lock().await;
        state.playback_data.playback_settings = Some(AppSettings::default());
        let snapshot = compute_status(&manager.state);
        tokio::pin!(snapshot);
        use std::{
            future::{poll_fn, Future},
            task::Poll,
        };
        assert!(poll_fn(|cx| Poll::Ready(snapshot.as_mut().poll(cx)))
            .await
            .is_pending());
        state.relay_data.restream_desired = true;
        state.relay_data.selected_protocol = RestreamProtocol::Srt;
        state.playback_data.recording_report = Some("transition completed".into());
        drop(state);
        let snapshot = snapshot.await;
        assert!(snapshot.playback_desired && snapshot.desired);
        assert_eq!(snapshot.selected_protocol, RestreamProtocol::Srt);
        assert_eq!(
            snapshot.recording_report.as_deref(),
            Some("transition completed")
        );
    }
}
