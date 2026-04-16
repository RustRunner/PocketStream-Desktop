//! RTSP/UDP playback pipeline via GStreamer.
//!
//! Builds a pipeline with a `tee` so the decoded stream can be:
//! 1. Displayed via d3d11videosink into a provided window handle
//! 2. Optionally recorded to MP4
//! 3. Snapshot-captured via an appsink

use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app as gst_app;

use gstreamer_video::prelude::VideoOverlayExtManual;

use crate::error::AppError;

/// A live playback pipeline with tee for recording/screenshots.
pub struct PlaybackPipeline {
    pub pipeline: gst::Pipeline,
    pub appsink: gst_app::AppSink,
}

impl PlaybackPipeline {
    /// Create a playback pipeline for an RTSP source.
    /// `window_handle`: if Some, render into that HWND via VideoOverlay.
    pub fn new_rtsp(
        url: &str,
        latency_ms: u32,
        use_tcp: bool,
        window_handle: Option<usize>,
    ) -> Result<Self, AppError> {
        let protocols = if use_tcp { "tcp" } else { "udp+tcp" };

        // User-controlled values (URL) are set as element properties below,
        // never interpolated into the pipeline description string, to prevent
        // GStreamer pipeline injection via crafted RTSP paths or credentials.
        let pipeline_str = format!(
            concat!(
                "rtspsrc name=src latency={latency} protocols={proto} ",
                "! decodebin name=dec ",
                "dec. ! videoconvert ! tee name=t ",
                "t. ! queue leaky=downstream max-size-buffers=2 ! autovideosink name=videosink sync=false ",
                "t. ! queue leaky=downstream max-size-buffers=1 ",
                "! videoconvert ! videoscale ",
                "! video/x-raw,format=RGB ",
                "! appsink name=snap emit-signals=false drop=true max-buffers=1"
            ),
            latency = latency_ms,
            proto = protocols,
        );

        let result = Self::from_pipeline_str(&pipeline_str, window_handle)?;

        // Set the URL via property (not pipeline-string interpolation) so
        // crafted RTSP paths/credentials can't inject GStreamer syntax.
        // The named element must exist if the pipeline parsed, but a
        // GStreamer plugin-version mismatch could in theory remove it —
        // return an error rather than panicking the streaming task.
        result
            .pipeline
            .by_name("src")
            .ok_or_else(|| {
                AppError::Stream(
                    "rtspsrc 'src' element not found in pipeline (GStreamer version mismatch?)"
                        .into(),
                )
            })?
            .set_property("location", url);

        Ok(result)
    }

    /// Create a playback pipeline for a UDP source.
    pub fn new_udp(port: u16, window_handle: Option<usize>) -> Result<Self, AppError> {
        let pipeline_str = format!(
            concat!(
                "udpsrc port={port} ",
                "! tsdemux name=demux ",
                "demux. ! h264parse ! decodebin ! videoconvert ! tee name=t ",
                "t. ! queue leaky=downstream max-size-buffers=2 ! autovideosink name=videosink sync=false ",
                "t. ! queue leaky=downstream max-size-buffers=1 ",
                "! videoconvert ! videoscale ",
                "! video/x-raw,format=RGB ",
                "! appsink name=snap emit-signals=false drop=true max-buffers=1"
            ),
            port = port,
        );

        Self::from_pipeline_str(&pipeline_str, window_handle)
    }

    fn from_pipeline_str(
        pipeline_str: &str,
        window_handle: Option<usize>,
    ) -> Result<Self, AppError> {
        let pipeline = gst::parse::launch(pipeline_str)
            .map_err(|e| AppError::Stream(format!("Pipeline parse error: {}", e)))?
            .downcast::<gst::Pipeline>()
            .map_err(|_| AppError::Stream("Failed to cast to Pipeline".into()))?;

        // If a window handle is provided, intercept the "prepare-window-handle"
        // bus message so GStreamer renders into our child HWND instead of
        // creating its own top-level window.
        if let Some(handle) = window_handle {
            let bus = pipeline
                .bus()
                .ok_or_else(|| AppError::Stream("Pipeline has no bus".into()))?;

            bus.set_sync_handler(move |_, msg| {
                if msg
                    .structure()
                    .is_some_and(|s| s.name() == "prepare-window-handle")
                {
                    if let Some(overlay) = msg
                        .src()
                        .and_then(|src| src.dynamic_cast_ref::<gstreamer_video::VideoOverlay>())
                    {
                        unsafe {
                            overlay.set_window_handle(handle);
                        }
                        log::info!(
                            "VideoOverlay: set window handle 0x{:X} on {}",
                            handle,
                            msg.src().map(|s| s.name().to_string()).unwrap_or_default()
                        );
                    }
                }
                gst::BusSyncReply::Pass
            });

            log::info!(
                "Bus sync handler installed for window handle 0x{:X}",
                handle
            );
        }

        let appsink = pipeline
            .by_name("snap")
            .ok_or_else(|| AppError::Stream("appsink 'snap' not found".into()))?
            .downcast::<gst_app::AppSink>()
            .map_err(|_| AppError::Stream("Failed to cast to AppSink".into()))?;

        Ok(Self { pipeline, appsink })
    }

    /// Start playback.
    pub fn play(&self) -> Result<(), AppError> {
        self.pipeline
            .set_state(gst::State::Playing)
            .map_err(|e| AppError::Stream(format!("Failed to start playback: {}", e)))?;
        log::info!("Playback pipeline set to Playing");
        Ok(())
    }

    /// Check if the pipeline is still actively playing.
    /// Returns Ok(true) if healthy, Ok(false) if not playing yet,
    /// or Err(message) with a user-friendly error description.
    pub fn health_check(&self) -> Result<bool, String> {
        // Always check bus first — errors may arrive before or after
        // the state transitions away from Playing.
        if let Some(bus) = self.pipeline.bus() {
            if let Some(msg) = bus.pop_filtered(&[gst::MessageType::Error, gst::MessageType::Eos]) {
                if let gst::MessageView::Error(err) = msg.view() {
                    let raw = err.error().to_string();
                    let debug = err.debug().map(|d| d.to_string()).unwrap_or_default();
                    return Err(friendly_rtsp_error(&raw, &debug));
                }
                return Err("End of stream".into());
            }
        }

        let (_, current, _) = self.pipeline.state(gst::ClockTime::from_mseconds(0));
        Ok(current == gst::State::Playing)
    }

    /// Stop and clean up.
    pub fn stop(&self) -> Result<(), AppError> {
        self.pipeline
            .set_state(gst::State::Null)
            .map_err(|e| AppError::Stream(format!("Failed to stop pipeline: {}", e)))?;
        log::info!("Playback pipeline stopped");
        Ok(())
    }

    /// Pull the latest frame from the appsink as raw RGB bytes.
    pub fn pull_snapshot(&self) -> Result<(u32, u32, Vec<u8>), AppError> {
        let sample = self
            .appsink
            .try_pull_sample(gst::ClockTime::from_mseconds(500))
            .ok_or_else(|| AppError::Stream("No frame available for screenshot".into()))?;

        let caps = sample
            .caps()
            .ok_or_else(|| AppError::Stream("Sample has no caps".into()))?;

        let structure = caps
            .structure(0)
            .ok_or_else(|| AppError::Stream("Caps has no structure".into()))?;

        let width = structure
            .get::<i32>("width")
            .map_err(|_| AppError::Stream("No width in caps".into()))? as u32;
        let height = structure
            .get::<i32>("height")
            .map_err(|_| AppError::Stream("No height in caps".into()))? as u32;

        let buffer = sample
            .buffer()
            .ok_or_else(|| AppError::Stream("Sample has no buffer".into()))?;

        let map = buffer
            .map_readable()
            .map_err(|_| AppError::Stream("Failed to map buffer".into()))?;

        Ok((width, height, map.to_vec()))
    }

    /// Dynamically add a recording branch to the tee.
    pub fn attach_recording(&self, file_path: &str) -> Result<String, AppError> {
        let tee = self
            .pipeline
            .by_name("t")
            .ok_or_else(|| AppError::Stream("Tee element not found".into()))?;

        let bin_name = "rec_bin";

        // File path is set as an element property below, not interpolated into
        // the pipeline string, to handle paths with spaces or special characters.
        let rec_bin_str = concat!(
            "queue name=rec_queue leaky=downstream ",
            "! videoconvert ",
            "! x264enc tune=zerolatency bitrate=4000 speed-preset=ultrafast ",
            "! h264parse ",
            "! mp4mux fragment-duration=1000 ",
            "! filesink name=rec_sink"
        );

        let rec_bin = gst::parse::bin_from_description(rec_bin_str, true)
            .map_err(|e| AppError::Stream(format!("Recording bin parse error: {}", e)))?;

        rec_bin
            .by_name("rec_sink")
            .expect("filesink 'rec_sink' not found in recording bin")
            .set_property("location", file_path);
        rec_bin.set_property("name", bin_name);

        self.pipeline
            .add(&rec_bin)
            .map_err(|e| AppError::Stream(format!("Failed to add recording bin: {}", e)))?;

        let bin_sink_pad = rec_bin
            .static_pad("sink")
            .ok_or_else(|| AppError::Stream("Recording bin has no sink pad".into()))?;

        let tee_src_pad = tee
            .request_pad_simple("src_%u")
            .ok_or_else(|| AppError::Stream("Failed to get tee src pad".into()))?;

        tee_src_pad
            .link(&bin_sink_pad)
            .map_err(|e| AppError::Stream(format!("Failed to link tee to recording: {}", e)))?;

        rec_bin
            .sync_state_with_parent()
            .map_err(|e| AppError::Stream(format!("Failed to sync recording bin: {}", e)))?;

        log::info!("Recording branch attached: {}", file_path);
        Ok(bin_name.into())
    }

    /// Detach the recording branch and finalize the MP4.
    pub async fn detach_recording(&self) -> Result<(), AppError> {
        let tee = self
            .pipeline
            .by_name("t")
            .ok_or_else(|| AppError::Stream("Tee element not found".into()))?;

        let rec_bin = self
            .pipeline
            .by_name("rec_bin")
            .ok_or_else(|| AppError::Stream("Recording bin not found".into()))?;

        let bin_sink_pad = rec_bin
            .static_pad("sink")
            .ok_or_else(|| AppError::Stream("Recording bin has no sink pad".into()))?;

        if let Some(tee_src_pad) = bin_sink_pad.peer() {
            tee_src_pad
                .unlink(&bin_sink_pad)
                .map_err(|e| AppError::Stream(format!("Failed to unlink recording: {}", e)))?;
            tee.release_request_pad(&tee_src_pad);
        }

        rec_bin.send_event(gst::event::Eos::new());
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        rec_bin
            .set_state(gst::State::Null)
            .map_err(|e| AppError::Stream(format!("Failed to stop recording bin: {}", e)))?;

        self.pipeline
            .remove(&rec_bin)
            .map_err(|e| AppError::Stream(format!("Failed to remove recording bin: {}", e)))?;

        log::info!("Recording branch detached and finalized");
        Ok(())
    }
}

/// Translate raw GStreamer/RTSP errors into user-friendly messages.
fn friendly_rtsp_error(error: &str, debug: &str) -> String {
    let combined = format!("{} {}", error, debug).to_lowercase();

    // Network-loss / mid-stream disconnect — checked first because
    // GStreamer's debug payload often replays the last RTSP exchange,
    // which can include cached 401/404 responses from earlier auth
    // negotiation. Pattern-matching those naively gives misleading
    // toasts ("bad credentials" when the cable was just unplugged).
    if combined.contains("could not read from")
        || combined.contains("connection reset")
        || combined.contains("connection lost")
        || combined.contains("no route to host")
        || combined.contains("network unreachable")
        || combined.contains("host unreachable")
        || combined.contains("internal data stream error")
        || combined.contains("internal data flow error")
        || combined.contains("broken pipe")
        || combined.contains("transport error")
    {
        return "Network connection lost. Check ethernet cable and camera link.".into();
    }

    // RTSP status codes
    if combined.contains("503") || combined.contains("service unavailable") {
        return "RTSP 503: wrong stream path or camera busy. Check the Path in settings.".into();
    }
    if combined.contains("404") || combined.contains("not found") {
        return "RTSP 404: stream path not found. Check the Path in settings.".into();
    }
    if combined.contains("401") || combined.contains("unauthorized") {
        return "RTSP 401: bad credentials. Check Username/Password in settings.".into();
    }
    if combined.contains("403") || combined.contains("forbidden") {
        return "RTSP 403: access denied. Check credentials and camera permissions.".into();
    }

    // Connection errors
    if combined.contains("could not connect") || combined.contains("connection refused") {
        return "Cannot reach camera. Check IP address and that RTSP is enabled on port 554."
            .into();
    }
    if combined.contains("timed out") || combined.contains("timeout") {
        return "Connection timed out. Camera may be unreachable or RTSP port blocked.".into();
    }

    // Codec / pipeline errors
    if combined.contains("no element") {
        return format!("Missing GStreamer plugin: {}", error);
    }
    if combined.contains("not negotiated") || combined.contains("not-negotiated") {
        return "Stream format not supported. Camera may use an unsupported codec.".into();
    }

    // Fallback: truncate long debug info
    if debug.len() > 120 {
        format!("{} ({}...)", error, &debug[..120])
    } else {
        format!("{} ({})", error, debug)
    }
}

#[cfg(test)]
mod tests {
    use super::friendly_rtsp_error;

    // Each pinned message is what the user sees in a toast — changing the
    // contract requires deliberately updating the expectation, not silently
    // editing the function.

    #[test]
    fn rtsp_503_recognized() {
        let msg = friendly_rtsp_error("Service Unavailable", "rtspsrc gstrtspsrc.c:1234");
        assert!(msg.contains("503"));
        assert!(msg.to_lowercase().contains("path"));
    }

    #[test]
    fn rtsp_503_via_status_phrase() {
        // Some cameras return the phrase without the numeric status.
        let msg = friendly_rtsp_error("RTSP server returned: service unavailable", "");
        assert!(msg.contains("503"));
    }

    #[test]
    fn rtsp_404_recognized() {
        let msg = friendly_rtsp_error("Not Found", "");
        assert!(msg.contains("404"));
        assert!(msg.to_lowercase().contains("path"));
    }

    #[test]
    fn rtsp_401_recognized() {
        let msg = friendly_rtsp_error("Unauthorized", "");
        assert!(msg.contains("401"));
        assert!(msg.to_lowercase().contains("credentials"));
    }

    #[test]
    fn rtsp_403_recognized() {
        let msg = friendly_rtsp_error("Forbidden", "");
        assert!(msg.contains("403"));
        assert!(msg.to_lowercase().contains("access denied"));
    }

    #[test]
    fn connection_refused_recognized() {
        let msg = friendly_rtsp_error("Could not connect to host", "");
        assert!(msg.to_lowercase().contains("cannot reach"));
    }

    #[test]
    fn timeout_recognized() {
        let msg = friendly_rtsp_error("Operation timed out", "");
        assert!(msg.to_lowercase().contains("timed out"));
    }

    #[test]
    fn missing_plugin_includes_original_error() {
        let raw = "no element \"h264parse\"";
        let msg = friendly_rtsp_error(raw, "");
        assert!(msg.to_lowercase().contains("missing gstreamer plugin"));
        // The raw error text is preserved so users can search for the
        // specific plugin name.
        assert!(msg.contains("h264parse"));
    }

    #[test]
    fn not_negotiated_recognized() {
        let msg = friendly_rtsp_error("not-negotiated", "");
        assert!(msg.to_lowercase().contains("format"));
    }

    #[test]
    fn fallback_includes_short_debug_verbatim() {
        let msg = friendly_rtsp_error("Some unknown error", "short debug");
        // No mapped category — falls through to the raw "(debug)" form.
        assert!(msg.contains("Some unknown error"));
        assert!(msg.contains("short debug"));
    }

    #[test]
    fn fallback_truncates_long_debug() {
        let long = "x".repeat(500);
        let msg = friendly_rtsp_error("err", &long);
        // 120-char cap + ellipsis suffix, plus the error prefix.
        assert!(msg.contains("..."));
        assert!(msg.len() < 200);
    }

    #[test]
    fn matching_is_case_insensitive() {
        // Real GStreamer messages mix case ("Connection Refused", etc.)
        let msg = friendly_rtsp_error("CONNECTION REFUSED", "");
        assert!(msg.to_lowercase().contains("cannot reach"));
    }

    #[test]
    fn debug_can_carry_the_signal() {
        // Sometimes the status phrase only appears in the debug field.
        // No network-loss keywords here, so 401 in debug should still win.
        let msg = friendly_rtsp_error("Stream error", "rtspsrc.c:9999: 401 unauthorized");
        assert!(msg.contains("401"));
    }

    // ── Network-loss / mid-stream disconnect ────────────────────────
    // These must short-circuit BEFORE the HTTP-status checks because
    // GStreamer's debug payload often replays a cached 401/404 from the
    // earlier auth handshake. Without this priority, yanking the cable
    // mid-stream surfaced "bad credentials" toasts to the user.

    #[test]
    fn mid_stream_disconnect_recognized_as_network_loss() {
        let msg = friendly_rtsp_error(
            "Internal data stream error",
            "gstrtspsrc.c:1234: could not read from resource",
        );
        assert!(msg.to_lowercase().contains("network"));
        assert!(!msg.contains("401"));
    }

    #[test]
    fn cable_unplug_with_cached_401_in_debug_still_says_network() {
        // The exact regression: cable yanked mid-stream, GStreamer
        // surfaces an Internal data stream error whose debug payload
        // includes the old 401 challenge from the initial DESCRIBE.
        let msg = friendly_rtsp_error(
            "Internal data stream error",
            "rtspsrc.c:5678: connection reset, last response was 401 unauthorized",
        );
        assert!(msg.to_lowercase().contains("network"));
        assert!(!msg.to_lowercase().contains("credentials"));
    }

    #[test]
    fn no_route_to_host_recognized() {
        let msg = friendly_rtsp_error("Could not write to resource", "no route to host");
        assert!(msg.to_lowercase().contains("network"));
    }

    #[test]
    fn broken_pipe_recognized() {
        let msg = friendly_rtsp_error("Stream error", "broken pipe");
        assert!(msg.to_lowercase().contains("network"));
    }
}
