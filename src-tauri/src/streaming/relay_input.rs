//! Adapt camera and transport-stream video to the relay's H.264 output.
use crate::error::AppError;
use gstreamer as gst;
use gstreamer::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn failure(message: &str) -> AppError {
    AppError::Stream(message.into())
}

fn video_decoders() -> glib::List<gst::ElementFactory> {
    gst::ElementFactory::factories_with_type(
        gst::ElementFactoryType::DECODER | gst::ElementFactoryType::MEDIA_VIDEO,
        gst::Rank::MARGINAL,
    )
}

fn is_video(caps: &gst::CapsRef) -> bool {
    caps.structure(0).is_some_and(|s| {
        matches!(s.name().as_str(), "video/x-h264" | "video/x-raw")
            || video_decoders()
                .iter()
                .any(|factory| factory.can_sink_all_caps(caps))
    })
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
        "decodebin name=relay_decoder force-sw-decoders=true ! videoconvert ! video/x-raw,format=I420 \
         ! x264enc name=relay_encoder tune=zerolatency speed-preset=ultrafast key-int-max=30",
        false,
    )
    .map_err(|_| failure("Re-stream video conversion is unavailable"))?;
    let encoder = branch
        .by_name("relay_encoder")
        .ok_or_else(|| failure("Re-stream encoder is unavailable"))?;
    let decoder = branch
        .by_name("relay_decoder")
        .ok_or_else(|| failure("Re-stream video decoder is unavailable"))?;
    for (element, name) in [(&decoder, "sink"), (&encoder, "src")] {
        let pad = element
            .static_pad(name)
            .ok_or_else(|| failure("Re-stream conversion pad is unavailable"))?;
        let ghost = gst::GhostPad::with_target(&pad)
            .map_err(|_| failure("Cannot expose re-stream conversion pad"))?;
        branch
            .add_pad(&ghost)
            .map_err(|_| failure("Cannot add re-stream conversion pad"))?;
    }
    encoder.set_property("bitrate", super::relay_bitrate::STARTUP_KBPS);
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
            .map_err(|_| failure("Cannot link encoded re-stream video"))?;
        super::relay_bitrate::follow_input(pad, &encoder);
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

    // Expose elementary video before decoding so its bitrate excludes other tracks.
    let autoplug = decoder.connect("autoplug-continue", false, |values| {
        let keep_decoding = values
            .get(2)
            .and_then(|value| value.get::<gst::Caps>().ok())
            .is_none_or(|caps| {
                !is_video(&caps)
                    && caps.structure(0).is_none_or(|s| {
                        let name = s.name().as_str();
                        !(name.starts_with("audio/")
                            || name.starts_with("text/")
                            || name.starts_with("subpicture/")
                            || name.starts_with("meta/")
                            || name == "application/x-id3")
                    })
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
        let video =
            name.is_some_and(|name| name.starts_with("video/") || name.starts_with("image/"));
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

    #[test]
    fn conversion_tracks_changing_video_rate_without_transport_stream_audio() {
        use std::sync::atomic::AtomicU64;

        gst::init().unwrap();
        let pipeline = gst::parse::launch(
            "mpegtsmux name=input_mux alignment=7 ! rtpmp2tpay pt=33 ! identity name=src \
             videotestsrc is-live=true pattern=snow \
             ! video/x-raw,format=I420,width=320,height=240,framerate=30/1 \
             ! x265enc name=input_encoder tune=zerolatency speed-preset=ultrafast bitrate=1000 key-int-max=30 \
             ! h265parse name=input_parse ! queue name=video_input ! input_mux. \
             audiotestsrc is-live=true ! audioconvert ! avenc_aac bitrate=320000 ! aacparse ! queue name=audio_input ! input_mux. \
             h264parse name=parse ! avdec_h264 ! appsink name=out sync=false",
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
        let bytes = Arc::new(AtomicU64::new(0));
        let counted = bytes.clone();
        pipeline
            .by_name("input_parse")
            .unwrap()
            .static_pad("src")
            .unwrap()
            .add_probe(gst::PadProbeType::BUFFER, move |_, info| {
                if let Some(gst::PadProbeData::Buffer(buffer)) = info.data.as_ref() {
                    counted.fetch_add(buffer.size() as u64, Ordering::Relaxed);
                }
                gst::PadProbeReturn::Ok
            });
        let input_encoder = pipeline.by_name("input_encoder").unwrap();
        // Exercise slower video encoder startup than audio.
        input_encoder
            .static_pad("sink")
            .unwrap()
            .add_probe(gst::PadProbeType::BUFFER, |_, _| {
                std::thread::sleep(Duration::from_millis(300));
                gst::PadProbeReturn::Remove
            });
        // Both encoded caps must reach the mux before it announces its initial program.
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(2);
        let mut input_probes = Vec::new();
        for name in ["video_input", "audio_input"] {
            let pad = pipeline.by_name(name).unwrap().static_pad("src").unwrap();
            let ready_tx = ready_tx.clone();
            let probe = pad
                .add_probe(
                    gst::PadProbeType::BLOCK | gst::PadProbeType::BUFFER,
                    move |_, _| {
                        let _ = ready_tx.try_send(());
                        gst::PadProbeReturn::Ok
                    },
                )
                .unwrap();
            input_probes.push((pad, probe));
        }
        let output_bytes = Arc::new(AtomicU64::new(0));
        let counted_output = output_bytes.clone();
        pipeline
            .by_name("parse")
            .unwrap()
            .static_pad("src")
            .unwrap()
            .add_probe(gst::PadProbeType::BUFFER, move |_, info| {
                if let Some(gst::PadProbeData::Buffer(buffer)) = info.data.as_ref() {
                    counted_output.fetch_add(buffer.size() as u64, Ordering::Relaxed);
                }
                gst::PadProbeReturn::Ok
            });
        let output = pipeline
            .by_name("out")
            .unwrap()
            .downcast::<gstreamer_app::AppSink>()
            .unwrap();
        let bus = pipeline.bus().unwrap();
        pipeline.set_state(gst::State::Playing).unwrap();
        let mut previous_target = 0;
        let inputs_ready = (0..2).all(|_| ready_rx.recv_timeout(Duration::from_secs(5)).is_ok());
        for (pad, probe) in input_probes {
            pad.remove_probe(probe);
        }
        assert!(
            inputs_ready,
            "both encoded tracks must be ready before muxing"
        );
        for input_kbps in [1000_u32, 3000, 500] {
            input_encoder.set_property("bitrate", input_kbps);
            let phase_started = Instant::now();
            let mut measured = None;
            let mut frames = 0;
            while phase_started.elapsed() < Duration::from_secs(6) {
                if output
                    .try_pull_sample(gst::ClockTime::from_mseconds(100))
                    .is_some()
                {
                    frames += 1;
                }
                if measured.is_none() && phase_started.elapsed() >= Duration::from_secs(4) {
                    measured = Some((
                        Instant::now(),
                        bytes.load(Ordering::Relaxed),
                        output_bytes.load(Ordering::Relaxed),
                    ));
                }
                if let Some(message) = bus.pop_filtered(&[gst::MessageType::Error]) {
                    panic!("Conversion failed: {:?}", message.view());
                }
            }
            assert!(
                frames > 60,
                "conversion must keep producing video during bitrate changes"
            );
            let (started, baseline, output_baseline) = measured.unwrap();
            let measured_kbps = (bytes.load(Ordering::Relaxed) - baseline) as f64 * 8.0
                / started.elapsed().as_secs_f64()
                / 1000.0;
            let output_kbps = (output_bytes.load(Ordering::Relaxed) - output_baseline) as f64 * 8.0
                / started.elapsed().as_secs_f64()
                / 1000.0;
            let encoder = pipeline.by_name("relay_encoder").unwrap();
            let target = encoder.property::<u32>("bitrate");
            assert!(
                (f64::from(target) - measured_kbps).abs() < measured_kbps * 0.2 + 30.0,
                "input={measured_kbps:.0} kbps but target={target} kbps"
            );
            assert!(
                output_kbps < measured_kbps * 1.35 + 50.0 && output_kbps > measured_kbps * 0.5,
                "input={measured_kbps:.0} kbps but converted output={output_kbps:.0} kbps"
            );
            if input_kbps == 1000 {
                assert!(
                    target < 1500,
                    "a low-rate input must not inherit a fixed floor"
                );
            } else if input_kbps == 3000 {
                assert!(target > previous_target * 2);
            } else {
                assert!(target < previous_target / 2);
            }
            previous_target = target;
        }
    }
}
