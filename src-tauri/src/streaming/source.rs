//! Existing source identity, readiness and URL policy shared by media owners.
use super::*;

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
