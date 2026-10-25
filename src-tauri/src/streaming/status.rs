//! One status watch, coherent snapshots and deduplicated publication.
use super::*;

#[derive(Clone)]
pub(super) struct StatusPublisher {
    state: Arc<Mutex<StreamState>>,
    pub(super) tx: Arc<watch::Sender<StreamStatus>>,
}

impl StatusPublisher {
    pub(super) fn new(state: Arc<Mutex<StreamState>>, selected_protocol: RestreamProtocol) -> Self {
        let (tx, _) = watch::channel(StreamStatus::idle(selected_protocol));
        Self {
            state,
            tx: Arc::new(tx),
        }
    }
    pub(super) async fn refresh(&self) {
        publish_status_if_changed(self.tx.as_ref(), compute_status(&self.state).await);
    }
}

pub(super) fn publish_status_if_changed(tx: &watch::Sender<StreamStatus>, snapshot: StreamStatus) {
    tx.send_if_modified(|current| {
        if *current == snapshot {
            false
        } else {
            *current = snapshot;
            true
        }
    });
}

pub(super) async fn compute_status(state: &Arc<Mutex<StreamState>>) -> StreamStatus {
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

    let playback = state
        .playback_data
        .playback_health
        .as_ref()
        .map(|h| h.snapshot());
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
        .playback_data
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
        playback_desired: state.playback_data.playback_settings.is_some(),
        playback_state: playback
            .as_ref()
            .map_or(PlaybackState::Stopped, |h| h.state),
        playback_fault: playback.as_ref().and_then(|h| h.fault.clone()),
        playback_recovery_attempt: playback.as_ref().map_or(0, |h| h.attempt),
        playback_next_retry_secs: playback.as_ref().and_then(|h| h.next_retry_secs),
        recording_report: state.playback_data.recording_report.clone(),
        recording_finalized_path: state.playback_data.recording_finalized_path.clone(),
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
        recording: state.playback_data.recording,
        uptime_secs: uptime,
        bandwidth_kbps: bandwidth,
        connected_clients,
        client_limit,
        error,
        audio_present,
        audio_codec,
    }
}

pub(super) async fn broadcast(
    mut rx: watch::Receiver<StreamStatus>,
    bridge: Arc<dyn crate::bridge::AppBridge>,
) {
    while rx.changed().await.is_ok() {
        let snap = rx.borrow().clone();
        let _ = crate::bridge::emit(bridge.as_ref(), "stream-status", &snap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
