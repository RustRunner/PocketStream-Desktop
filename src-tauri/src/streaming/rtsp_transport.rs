//! RTSP uses a loopback TCP endpoint to preserve the original camera URI
//! while the shared transport binds the upstream socket to Ethernet.
use super::rtsp_server::UpstreamReady;
use crate::error::AppError;
pub(super) use crate::network::bound_tcp::BoundTcpTransport as RtspTransport;
use crate::network::bound_tcp::BoundTcpTransport;
use gstreamer::{self as gst, prelude::*};

/// The caller must retain the returned owner until playback/media teardown.
pub(super) fn configure(
    source: &gst::Element,
    url: &str,
    ready: UpstreamReady,
) -> Result<BoundTcpTransport, AppError> {
    if source.find_property("proxy").map(|p| p.value_type()) != Some(glib::Type::STRING) {
        return Err(AppError::Stream(
            "GStreamer lacks the RTSP proxy transport property".into(),
        ));
    }
    let transport = BoundTcpTransport::start(url, ready)?;
    source.set_property("proxy", format!("http://{}", transport.address()));
    // Always interleave RTP/RTCP on the bound TCP connection. UDP negotiation
    // would bypass the interface binding and reintroduce ambiguous routing.
    source.set_property_from_str("protocols", "tcp");
    let ready = transport.readiness_check();
    source.connect("before-send", false, move |_| Some(ready().to_value()));
    source.set_property("location", url);
    Ok(transport)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::bound_tcp::test_path;
    use std::sync::Arc;
    /// Opt-in hardware check; uses no saved credentials or network mutations.
    /// Set POCKETSTREAM_RTSP_SMOKE_URL, _SOURCE and _INDEX explicitly.
    #[test]
    #[ignore = "requires an explicitly selected H.264 camera and Ethernet source"]
    fn camera_video_through_bound_transport() {
        gst::init().unwrap();
        let url = std::env::var("POCKETSTREAM_RTSP_SMOKE_URL").unwrap();
        let endpoint = reqwest::Url::parse(&url).unwrap();
        let mut path = test_path(endpoint.host_str().unwrap());
        path.source = std::env::var("POCKETSTREAM_RTSP_SMOKE_SOURCE")
            .unwrap()
            .parse()
            .unwrap();
        path.index = std::env::var("POCKETSTREAM_RTSP_SMOKE_INDEX")
            .unwrap()
            .parse()
            .unwrap();
        let pipeline = gst::parse::launch("rtspsrc name=src protocols=tcp latency=200 ! rtph264depay ! h264parse ! fakesink num-buffers=20 sync=false")
            .unwrap().downcast::<gst::Pipeline>().unwrap();
        let source = pipeline.by_name("src").unwrap();
        super::super::configure_tcp_rtspsrc(&source).unwrap();
        let transport = configure(&source, &url, Arc::new(move || Ok(path.clone()))).unwrap();
        pipeline.set_state(gst::State::Playing).unwrap();
        let outcome = pipeline.bus().unwrap().timed_pop_filtered(
            gst::ClockTime::from_seconds(25),
            &[gst::MessageType::Eos, gst::MessageType::Error],
        );
        transport.shutdown();
        pipeline.set_state(gst::State::Null).unwrap();
        match outcome.as_ref().map(|message| message.view()) {
            Some(gst::MessageView::Eos(_)) => {}
            Some(gst::MessageView::Error(error)) => {
                panic!("Camera video failed: {}", error.error())
            }
            _ => panic!("Timed out waiting for 20 H.264 buffers"),
        }
    }
}
