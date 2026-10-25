//! Streaming composition and unchanged command-facing delegation.
pub mod audio;
mod caller_registry;
mod classify;
mod playback;
pub mod recorder;
mod relay;
mod relay_service;
pub mod rtsp_client;
pub mod rtsp_server;
mod rtsp_transport;
mod source;
mod srt_server;
mod state;
mod status;
#[cfg(test)]
mod test_support;
mod udp;
pub mod video_embed;
mod video_surface;

use crate::{
    config::{AppConfig, AppSettings, RestreamProtocol, RestreamSettingsUpdate},
    error::AppError,
    network::{bindings::BindScope, firewall::FirewallOutcome},
};
#[cfg(test)]
use relay::{ResolvedOutput, ResolvedSource, ResolvedStartSpec};
#[cfg(test)]
use relay_service::RestreamServer;
pub use relay_service::{RestreamOperationResult, RestreamServerInfo};
pub(super) use source::{
    configure_tcp_rtspsrc, connect_video_only_select_stream, redact_relay_text,
};
#[cfg(test)]
use state::StreamState;
#[cfg(test)]
use status::compute_status;
pub use status::StreamStatus;
use std::sync::Arc;
#[cfg(test)]
use tokio::sync::Mutex;

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
        Self::construct(
            selected_protocol,
            Arc::new(crate::bridge::RecordingBridge::default()),
            None,
        )
    }

    pub(crate) fn with_dependencies(
        selected_protocol: RestreamProtocol,
        bridge: Arc<dyn crate::bridge::AppBridge>,
        readiness: Arc<crate::network::readiness::CameraReadiness>,
    ) -> Self {
        Self::construct(selected_protocol, bridge, Some(readiness))
    }

    fn construct(
        selected_protocol: RestreamProtocol,
        bridge: Arc<dyn crate::bridge::AppBridge>,
        readiness: Option<Arc<crate::network::readiness::CameraReadiness>>,
    ) -> Self {
        let state = state::new(selected_protocol);
        let status = status::StatusPublisher::new(state.clone(), selected_protocol);
        let surface = Arc::new(video_surface::VideoSurface::new(bridge.clone()));
        let playback = Arc::new(playback::PlaybackService::new(
            state::PlaybackSlot::new(state.clone()),
            status.clone(),
            surface.clone(),
            readiness.clone(),
        ));
        let relay = Arc::new(relay_service::RelayService::new(
            state::RelaySlot::new(state.clone()),
            status.clone(),
            readiness,
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

    pub fn start_status_emitter(&self) {
        if let Some((events, context)) = self.relay.supervisor() {
            tauri::async_runtime::spawn(relay_service::run_relay_supervisor(events, context));
        } else {
            log::warn!("Re-stream relay supervisor was already started");
        }

        tauri::async_runtime::spawn(playback::run_playback_supervisor(self.playback.context()));

        let receiver: tokio::sync::watch::Receiver<StreamStatus> = self.status.subscribe();
        tauri::async_runtime::spawn(status::broadcast(receiver, self.bridge.clone()));
    }

    pub(crate) fn video_surface(&self) -> &video_surface::VideoSurface {
        &self.surface
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_admission_preserves_errors_in_both_start_orders() {
        init_gstreamer();
        for relay_first in [false, true] {
            let manager = StreamManager::new();
            let settings = restream_test_settings(RestreamProtocol::Rtsp);
            let (epoch, preserve) = manager.relay.begin_restream_start_intent().await.unwrap();
            let port = settings.stream.udp_port;
            let error = if relay_first {
                manager
                    .relay
                    .start_restream_server_inner(&settings, &Default::default(), epoch, preserve)
                    .await
                    .unwrap();
                manager.start_playback(&settings, None).await.unwrap_err()
            } else {
                manager.start_playback(&settings, None).await.unwrap();
                manager
                    .relay
                    .start_restream_server_inner(&settings, &Default::default(), epoch, preserve)
                    .await
                    .unwrap_err()
            };
            let AppError::Stream(reason) = error else {
                panic!("wrong error variant")
            };
            assert_eq!(
                reason,
                if relay_first {
                    format!("UDP port {} is already claimed by the re-stream server. Stop it first or switch the input to RTSP.", port)
                } else {
                    format!("UDP port {} is already claimed by the running preview - only one consumer can receive a UDP stream. Stop the stream first, or switch the input to RTSP.", port)
                }
            );
            manager.stop_playback().await.unwrap();
            manager.stop_restream_server().await.unwrap();
        }
    }

    #[tokio::test]
    async fn failed_listener_construction_keeps_udp_occupancy_until_stop() {
        init_gstreamer();
        let manager = StreamManager::new();
        let occupied = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            use windows_sys::Win32::Networking::WinSock::{
                setsockopt, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
            };
            // GIO requests reuse. Windows otherwise permits a wildcard socket
            // alongside a specific-address bind. Reserve the same wildcard
            // endpoint exclusively rather than assuming a loopback conflict.
            let exclusive = 1i32;
            assert_eq!(
                unsafe {
                    setsockopt(
                        occupied.as_raw_socket() as _,
                        SOL_SOCKET,
                        SO_EXCLUSIVEADDRUSE,
                        (&exclusive as *const i32).cast(),
                        std::mem::size_of::<i32>() as i32,
                    )
                },
                0
            );
        }
        occupied
            .bind(&"0.0.0.0:0".parse::<std::net::SocketAddr>().unwrap().into())
            .unwrap();
        occupied.listen(1).unwrap();
        let mut settings = restream_test_settings(RestreamProtocol::Rtsp);
        settings.rtsp_server.port = occupied.local_addr().unwrap().as_socket().unwrap().port();
        assert!(std::net::TcpListener::bind(("0.0.0.0", settings.rtsp_server.port)).is_err());
        let (epoch, preserve) = manager.relay.begin_restream_start_intent().await.unwrap();
        let error = manager
            .relay
            .start_restream_server_inner(&settings, &Default::default(), epoch, preserve)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("RTSP server socket failed"),
            "{error}"
        );
        assert!(manager
            .start_playback(&settings, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("already claimed"));
        manager.stop_restream_server().await.unwrap();
        manager.start_playback(&settings, None).await.unwrap();
        manager.stop_playback().await.unwrap();
    }
    use crate::streaming::{relay::RelayState, rtsp_server::MAX_RTSP_CLIENTS, test_support::*};

    #[tokio::test]
    async fn stream_manager_initial_status() {
        let mgr = StreamManager::new();
        let status = mgr.status.latest();
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
