//! Existing source identity, readiness and URL policy shared by media owners.
use super::audio;
use crate::{
    config::{AppSettings, StreamProtocol},
    error::AppError,
    network::route::{CameraTarget, ReadyPath},
};
use gstreamer as gst;
use gstreamer::prelude::*;
use std::sync::Arc;

/// Redact credentials from a URL (or any text containing one) for
/// safe logging. Rewrites the first `://user:pass@` occurrence;
/// that's sufficient for log lines and bus error/debug text, which
/// carry at most the input URL.
pub(super) fn redact_url(url: &str) -> String {
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
pub(super) fn build_input_url(settings: &AppSettings) -> Result<String, AppError> {
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

pub(super) fn stream_target(settings: &AppSettings) -> Option<CameraTarget> {
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
pub(super) fn require_cam_role(
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

pub(super) async fn preflight_target(
    handle: Option<&Arc<crate::network::readiness::CameraReadiness>>,
    target: Option<&CameraTarget>,
) -> Result<Option<ReadyPath>, AppError> {
    let Some(target) = target else {
        return Ok(None);
    }; // UDP is exempt
    camera_stream_path(handle, target).map(Some)
}

pub(super) fn camera_stream_path(
    handle: Option<&Arc<crate::network::readiness::CameraReadiness>>,
    target: &CameraTarget,
) -> Result<ReadyPath, AppError> {
    let handle =
        handle.ok_or_else(|| AppError::Stream("Ethernet readiness service unavailable".into()))?;
    let path = handle.bound_now(target)?;
    require_cam_role(&path.target, &handle.records())?;
    Ok(path)
}

/// Apply the required receive policy to an `rtspsrc` that is constrained to
/// TCP transport.  `set_property` panics for a missing or mismatched property,
/// so validate both properties first and return a normal typed stream error on
/// an unsupported runtime.
pub(crate) fn configure_tcp_rtspsrc(src: &gst::Element) -> Result<(), AppError> {
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
pub(crate) fn connect_video_only_select_stream(src: &gst::Element) -> glib::SignalHandlerId {
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
pub(crate) fn redact_relay_text(text: &str, mount_path: &str) -> String {
    let redacted = redact_url(text);
    if mount_path.is_empty() {
        redacted
    } else {
        redacted.replace(mount_path, "/stream-***")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::{relay_service::RelayService, test_support::*};
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
}
