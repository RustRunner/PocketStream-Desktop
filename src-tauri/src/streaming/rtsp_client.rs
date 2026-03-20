//! RTSP/UDP playback pipeline via GStreamer.
//!
//! Builds a pipeline with a `tee` so the decoded stream can be:
//! 1. Displayed via autovideosink (own window)
//! 2. Optionally recorded to MP4
//! 3. Snapshot-captured via an appsink

use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app as gst_app;

use crate::error::AppError;

/// A live playback pipeline with tee for recording/screenshots.
pub struct PlaybackPipeline {
    pub pipeline: gst::Pipeline,
    pub appsink: gst_app::AppSink,
}

impl PlaybackPipeline {
    /// Create a playback pipeline for an RTSP source.
    pub fn new_rtsp(url: &str, latency_ms: u32, use_tcp: bool) -> Result<Self, AppError> {
        gst::init().map_err(|e| AppError::Stream(e.to_string()))?;

        let protocols = if use_tcp { "tcp" } else { "udp+tcp" };

        let pipeline_str = format!(
            concat!(
                "rtspsrc location={url} latency={latency} protocols={proto} ",
                "! decodebin name=dec ",
                "dec. ! videoconvert ! tee name=t ",
                "t. ! queue leaky=downstream max-size-buffers=2 ! autovideosink sync=false ",
                "t. ! queue leaky=downstream max-size-buffers=1 ",
                "! videoconvert ! videoscale ",
                "! video/x-raw,format=RGB ",
                "! appsink name=snap emit-signals=false drop=true max-buffers=1"
            ),
            url = url,
            latency = latency_ms,
            proto = protocols,
        );

        Self::from_pipeline_str(&pipeline_str)
    }

    /// Create a playback pipeline for a UDP source.
    pub fn new_udp(port: u16) -> Result<Self, AppError> {
        gst::init().map_err(|e| AppError::Stream(e.to_string()))?;

        let pipeline_str = format!(
            concat!(
                "udpsrc port={port} ",
                "! tsdemux name=demux ",
                "demux. ! h264parse ! decodebin ! videoconvert ! tee name=t ",
                "t. ! queue leaky=downstream max-size-buffers=2 ! autovideosink sync=false ",
                "t. ! queue leaky=downstream max-size-buffers=1 ",
                "! videoconvert ! videoscale ",
                "! video/x-raw,format=RGB ",
                "! appsink name=snap emit-signals=false drop=true max-buffers=1"
            ),
            port = port,
        );

        Self::from_pipeline_str(&pipeline_str)
    }

    fn from_pipeline_str(pipeline_str: &str) -> Result<Self, AppError> {
        let pipeline = gst::parse::launch(pipeline_str)
            .map_err(|e| AppError::Stream(format!("Pipeline parse error: {}", e)))?
            .downcast::<gst::Pipeline>()
            .map_err(|_| AppError::Stream("Failed to cast to Pipeline".into()))?;

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

        let rec_bin_str = format!(
            concat!(
                "queue name=rec_queue leaky=downstream ",
                "! videoconvert ",
                "! x264enc tune=zerolatency bitrate=4000 speed-preset=ultrafast ",
                "! h264parse ",
                "! mp4mux fragment-duration=1000 ",
                "! filesink location={path}"
            ),
            path = file_path,
        );

        let rec_bin = gst::parse::bin_from_description(&rec_bin_str, true)
            .map_err(|e| AppError::Stream(format!("Recording bin parse error: {}", e)))?;
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
    pub fn detach_recording(&self) -> Result<(), AppError> {
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
        std::thread::sleep(std::time::Duration::from_millis(500));

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
