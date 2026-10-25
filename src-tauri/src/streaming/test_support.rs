//! Shared in-memory/loopback scenario fixtures; never host policy operations.
use super::relay::{RelayRuntimeHealth, RelayState, ResolvedSource, ResolvedStartSpec};
use super::{
    relay,
    relay_service::{resolve_selected_restream_output, RestreamServer},
    StreamManager,
};
use crate::config::*;
use crate::error::AppError;
use gstreamer as gst;
use std::sync::Arc;

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
    state.relay_data.restream_intent_epoch = Some(manager.relay.test_epoch());
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

pub(super) async fn seed_desired_relay(manager: &StreamManager, generation: u64, epoch: u64) {
    let mut state = manager.state.lock().await;
    state.relay_data.restream_desired = true;
    state.relay_data.restream_health = Some(Arc::new(RelayRuntimeHealth::new(
        generation,
        relay::RelayIngestKind::Rtsp,
    )));
    state.relay_data.restream_intent_epoch = Some(epoch);
}
