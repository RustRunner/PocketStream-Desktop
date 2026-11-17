//! Adapt camera and transport-stream video to the relay's H.264 output.
use crate::error::AppError;
use gstreamer as gst;
use gstreamer::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn failure(message: &str) -> AppError {
    AppError::Stream(message.into())
}

fn discard_pad(bin: &gst::Bin, pad: &gst::Pad) -> Result<(), AppError> {
    let sink = gst::ElementFactory::make("fakesink")
        .property("sync", false)
        .property("async", false)
        .build()
        .map_err(|_| failure("Re-stream discard sink is unavailable"))?;
    bin.add(&sink)
        .map_err(|_| failure("Cannot add re-stream discard sink"))?;
    let result = (|| {
        let target = sink
            .static_pad("sink")
            .ok_or_else(|| failure("Re-stream discard sink has no input pad"))?;
        pad.link(&target)
            .map_err(|_| failure("Cannot link unused re-stream track"))?;
        sink.sync_state_with_parent()
            .map_err(|_| failure("Cannot start re-stream discard sink"))
    })();
    if result.is_err() {
        let _ = sink.set_state(gst::State::Null);
        let _ = bin.remove(&sink);
    }
    result
}

fn transcode_pad(bin: &gst::Bin, pad: &gst::Pad, parser: &gst::Element) -> Result<(), AppError> {
    let branch = gst::parse::bin_from_description(
        "videoconvert ! video/x-raw,format=I420 \
         ! x264enc tune=zerolatency speed-preset=ultrafast bitrate=4000 key-int-max=30",
        true,
    )
    .map_err(|_| failure("Re-stream video conversion is unavailable"))?;
    branch.set_property("name", "relay_transcode");
    bin.add(&branch)
        .map_err(|_| failure("Cannot add re-stream video conversion"))?;
    let result = (|| {
        branch
            .link(parser)
            .map_err(|_| failure("Cannot link re-stream encoder to output"))?;
        let target = branch
            .static_pad("sink")
            .ok_or_else(|| failure("Re-stream conversion has no input pad"))?;
        pad.link(&target)
            .map_err(|_| failure("Cannot link decoded re-stream video"))?;
        branch
            .sync_state_with_parent()
            .map_err(|_| failure("Cannot start re-stream video conversion"))
    })();
    if result.is_err() {
        let _ = branch.set_state(gst::State::Null);
        let _ = bin.remove(&branch);
    }
    result
}

fn post_error(bin: &gst::Bin, error: &AppError) {
    gst::element_error!(bin, gst::StreamError::Format, ("{}", error));
}

pub(super) fn install(
    bin: &gst::Bin,
    source: &gst::Element,
    dynamic_source: bool,
) -> Result<Vec<(gst::Element, glib::SignalHandlerId)>, AppError> {
    let parser = bin
        .by_name("parse")
        .ok_or_else(|| failure("Re-stream output parser is unavailable"))?;
    let decoder = gst::ElementFactory::make("decodebin")
        .name("relay_input")
        .property("force-sw-decoders", true)
        // Stop before decoding H.264, including video extracted from MPEG-TS.
        .property(
            "caps",
            gst::Caps::builder_full()
                .structure(gst::Structure::new_empty("video/x-h264"))
                .structure(gst::Structure::new_empty("video/x-raw"))
                .build(),
        )
        .build()
        .map_err(|_| failure("Re-stream input decoder is unavailable"))?;
    bin.add(&decoder)
        .map_err(|_| failure("Cannot add re-stream input decoder"))?;
    let mut handlers = Vec::new();

    // Expose non-video tracks for disposal without requiring their decoders.
    let autoplug = decoder.connect("autoplug-continue", false, |values| {
        let keep_decoding = values
            .get(2)
            .and_then(|value| value.get::<gst::Caps>().ok())
            .and_then(|caps| caps.structure(0).map(|s| s.name().to_string()))
            .is_none_or(|name| {
                !(name.starts_with("audio/")
                    || name.starts_with("text/")
                    || name.starts_with("subpicture/")
                    || name.starts_with("meta/")
                    || name == "application/x-id3")
            });
        Some(keep_decoding.to_value())
    });
    handlers.push((decoder.clone(), autoplug));

    let video_linked = Arc::new(AtomicBool::new(false));
    let linked_for_pad = video_linked.clone();
    let bin_weak = bin.downgrade();
    let parser_weak = parser.downgrade();
    let pad_added = decoder.connect_pad_added(move |_decoder, pad| {
        let (Some(bin), Some(parser)) = (bin_weak.upgrade(), parser_weak.upgrade()) else {
            return;
        };
        let caps = pad.current_caps().unwrap_or_else(|| pad.query_caps(None));
        let name = caps.structure(0).map(|s| s.name().as_str());
        let video = matches!(name, Some("video/x-h264" | "video/x-raw"));
        let result = if !video || linked_for_pad.swap(true, Ordering::AcqRel) {
            discard_pad(&bin, pad)
        } else if name == Some("video/x-h264") {
            log::info!("event=relay_video_input route=h264_passthrough");
            parser
                .static_pad("sink")
                .ok_or_else(|| failure("Re-stream parser has no input pad"))
                .and_then(|target| {
                    pad.link(&target)
                        .map(|_| ())
                        .map_err(|_| failure("Cannot link H.264 re-stream video"))
                })
        } else {
            log::info!("event=relay_video_input route=h264_transcode");
            transcode_pad(&bin, pad, &parser)
        };
        if let Err(error) = result {
            post_error(&bin, &error);
        }
    });
    handlers.push((decoder.clone(), pad_added));

    let bin_weak = bin.downgrade();
    let no_more_pads = decoder.connect_no_more_pads(move |_decoder| {
        if !video_linked.load(Ordering::Acquire) {
            if let Some(bin) = bin_weak.upgrade() {
                post_error(
                    &bin,
                    &failure("Re-stream input contains no supported video"),
                );
            }
        }
    });
    handlers.push((decoder.clone(), no_more_pads));

    if dynamic_source {
        let input_linked = AtomicBool::new(false);
        let bin_weak = bin.downgrade();
        let decoder_weak = decoder.downgrade();
        let pad_added = source.connect_pad_added(move |_source, pad| {
            let (Some(bin), Some(decoder)) = (bin_weak.upgrade(), decoder_weak.upgrade()) else {
                return;
            };
            let caps = pad.current_caps().unwrap_or_else(|| pad.query_caps(None));
            let video = super::audio::classify_rtp_caps(&caps).0 == super::audio::MediaKind::Video;
            let result = if !video || input_linked.swap(true, Ordering::AcqRel) {
                discard_pad(&bin, pad)
            } else {
                decoder
                    .static_pad("sink")
                    .ok_or_else(|| failure("Re-stream input decoder has no input pad"))
                    .and_then(|target| {
                        pad.link(&target)
                            .map(|_| ())
                            .map_err(|_| failure("Cannot link camera video to re-stream input"))
                    })
            };
            if let Err(error) = result {
                post_error(&bin, &error);
            }
        });
        handlers.push((source.clone(), pad_added));
    } else {
        source
            .link(&decoder)
            .map_err(|_| failure("Cannot link transport stream to re-stream input"))?;
    }
    Ok(handlers)
}

#[cfg(test)]
#[path = "relay_input_loopback_tests.rs"]
mod loopback_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const VIDEO: &str =
        "videotestsrc num-buffers=12 ! video/x-raw,format=I420,width=160,height=120,framerate=15/1";
    const H264: &str = "x264enc tune=zerolatency speed-preset=ultrafast key-int-max=5 ! h264parse";

    struct StopPipeline(gst::Pipeline);
    impl Drop for StopPipeline {
        fn drop(&mut self) {
            let _ = self.0.set_state(gst::State::Null);
        }
    }

    fn exercise(input: &str, transcoded: bool) {
        gst::init().unwrap();
        let pipeline = gst::parse::launch(&format!(
            "{input} h264parse name=parse ! avdec_h264 ! appsink name=out sync=false"
        ))
        .unwrap()
        .downcast::<gst::Pipeline>()
        .unwrap();
        let _stop = StopPipeline(pipeline.clone());
        let source = pipeline.by_name("src").unwrap();
        let _handlers = install(pipeline.upcast_ref(), &source, false).unwrap();
        let output = pipeline
            .by_name("out")
            .unwrap()
            .downcast::<gstreamer_app::AppSink>()
            .unwrap();
        let bus = pipeline.bus().unwrap();
        pipeline.set_state(gst::State::Playing).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut frames = 0;
        while frames < 5 && Instant::now() < deadline {
            if let Some(sample) = output.try_pull_sample(gst::ClockTime::from_mseconds(100)) {
                let caps = sample.caps().unwrap().structure(0).unwrap();
                assert_eq!(caps.name(), "video/x-raw");
                assert_eq!(caps.get::<i32>("width").unwrap(), 160);
                assert_eq!(caps.get::<i32>("height").unwrap(), 120);
                assert!(sample.buffer().unwrap().size() > 0);
                frames += 1;
            }
            if let Some(message) = bus.pop_filtered(&[gst::MessageType::Error]) {
                let gst::MessageView::Error(error) = message.view() else {
                    unreachable!();
                };
                panic!("{input}: {} {:?}", error.error(), error.debug());
            }
        }
        assert!(
            frames >= 5,
            "{input}: received only {frames} decoded frames"
        );
        assert_eq!(pipeline.by_name("relay_transcode").is_some(), transcoded);
    }

    #[test]
    fn h264_rtp_and_transport_streams_remain_compressed() {
        for wrap in [
            "rtph264pay pt=96",
            "mpegtsmux alignment=7 ! rtpmp2tpay pt=33",
            "mpegtsmux alignment=7",
        ] {
            exercise(
                &format!("{VIDEO} ! {H264} ! {wrap} ! identity name=src"),
                false,
            );
        }
    }

    #[test]
    fn other_video_codecs_are_converted_to_h264() {
        for codec in [
            "jpegenc ! rtpjpegpay",
            "avenc_mpeg4 ! mpeg4videoparse ! rtpmp4vpay",
            "x265enc tune=zerolatency speed-preset=ultrafast ! h265parse ! rtph265pay",
        ] {
            exercise(&format!("{VIDEO} ! {codec} ! identity name=src"), true);
        }
    }

    #[test]
    fn transport_stream_audio_does_not_interrupt_video() {
        exercise(
            &format!(
                "mpegtsmux name=input_mux alignment=7 ! rtpmp2tpay pt=33 ! identity name=src \
                 {VIDEO} ! {H264} ! queue ! input_mux. \
                 audiotestsrc num-buffers=60 ! audioconvert ! avenc_aac ! aacparse ! queue ! input_mux."
            ),
            false,
        );
    }

    #[test]
    fn missing_video_reports_a_format_error() {
        gst::init().unwrap();
        let pipeline = gst::parse::launch(
            "audiotestsrc num-buffers=10 ! identity name=src \
             h264parse name=parse ! fakesink sync=false",
        )
        .unwrap()
        .downcast::<gst::Pipeline>()
        .unwrap();
        let _stop = StopPipeline(pipeline.clone());
        let _handlers = install(
            pipeline.upcast_ref(),
            &pipeline.by_name("src").unwrap(),
            false,
        )
        .unwrap();
        let bus = pipeline.bus().unwrap();
        let _ = pipeline.set_state(gst::State::Playing);
        let message = bus
            .timed_pop_filtered(gst::ClockTime::from_seconds(5), &[gst::MessageType::Error])
            .expect("audio-only input must fail without waiting for a video timeout");
        let gst::MessageView::Error(error) = message.view() else {
            unreachable!();
        };
        assert!(error.error().matches(gst::StreamError::Format));
    }
}
