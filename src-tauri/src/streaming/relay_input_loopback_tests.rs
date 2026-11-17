use super::*;
use crate::streaming::relay::{RelayIngestKind, RelayRuntimeHealth, RestreamRuntimeContext};
use crate::streaming::rtsp_server::RtspRestreamer;
use crate::streaming::srt_server::SrtRestreamer;
use crate::streaming::test_support::{unused_tcp_port, unused_udp_port};
use gstreamer_rtsp_server::{self as rtsp, prelude::*};
use std::time::{Duration, Instant};

const VIDEO: &str =
    "videotestsrc is-live=true ! video/x-raw,format=I420,width=160,height=120,framerate=15/1";
const H264: &str = "x264enc tune=zerolatency speed-preset=ultrafast key-int-max=5 ! h264parse";

struct Camera {
    server: rtsp::RTSPServer,
    source: glib::Source,
    main_loop: glib::MainLoop,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Camera {
    fn new(codec: &str) -> Self {
        gst::init().unwrap();
        let server = rtsp::RTSPServer::new();
        server.set_address("127.0.0.1");
        server.set_service("0");
        let factory = rtsp::RTSPMediaFactory::new();
        factory.set_launch(&format!("( {VIDEO} ! {codec} name=pay0 pt=96 )"));
        factory.set_shared(true);
        server.mount_points().unwrap().add_factory("/test", factory);
        let source = server.create_source(gio::Cancellable::NONE).unwrap();
        let context = glib::MainContext::new();
        source.attach(Some(&context));
        let main_loop = glib::MainLoop::new(Some(&context), false);
        let run_loop = main_loop.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            context
                .with_thread_default(|| {
                    let ready =
                        glib::source::idle_source_new(None, glib::Priority::DEFAULT, move || {
                            let _ = ready_tx.send(());
                            glib::ControlFlow::Break
                        });
                    ready.attach(Some(&context));
                    run_loop.run();
                })
                .unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        Self {
            server,
            source,
            main_loop,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("rtsp://127.0.0.1:{}/test", self.server.bound_port())
    }
}

impl Drop for Camera {
    fn drop(&mut self) {
        self.server
            .session_pool()
            .unwrap()
            .filter(Some(&mut |_, _| rtsp::RTSPFilterResult::Remove));
        self.source.destroy();
        self.main_loop.quit();
        self.thread.take().unwrap().join().unwrap();
    }
}

struct StopPipeline(gst::Pipeline);
impl Drop for StopPipeline {
    fn drop(&mut self) {
        let _ = self.0.set_state(gst::State::Null);
    }
}

fn runtime(ingest: RelayIngestKind) -> RestreamRuntimeContext {
    let health = Arc::new(RelayRuntimeHealth::new(1, ingest));
    let server_instance = health.begin_server_instance(false);
    let (event_tx, _) = tokio::sync::mpsc::unbounded_channel();
    RestreamRuntimeContext {
        health,
        event_tx,
        server_instance,
        upstream_ready: Some(Arc::new(|| {
            Ok(crate::network::bound_tcp::test_path("127.0.0.1"))
        })),
    }
}

fn receive_video(input: &str) {
    let pipeline = gst::parse::launch(&format!(
        "{input} ! h264parse ! avdec_h264 ! appsink name=out sync=false"
    ))
    .unwrap()
    .downcast::<gst::Pipeline>()
    .unwrap();
    let _stop = StopPipeline(pipeline.clone());
    let sink = pipeline
        .by_name("out")
        .unwrap()
        .downcast::<gstreamer_app::AppSink>()
        .unwrap();
    pipeline.set_state(gst::State::Playing).unwrap();
    let bus = pipeline.bus().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut frames = 0;
    while frames < 5 && Instant::now() < deadline {
        if let Some(sample) = sink.try_pull_sample(gst::ClockTime::from_mseconds(100)) {
            let caps = sample.caps().unwrap().structure(0).unwrap();
            assert_eq!(caps.get::<i32>("width").unwrap(), 160);
            assert_eq!(caps.get::<i32>("height").unwrap(), 120);
            assert!(sample.buffer().unwrap().size() > 0);
            frames += 1;
        }
        if let Some(message) = bus.pop_filtered(&[gst::MessageType::Error]) {
            let gst::MessageView::Error(error) = message.view() else {
                unreachable!()
            };
            panic!("{input}: {} {:?}", error.error(), error.debug());
        }
    }
    assert!(
        frames >= 5,
        "{input}: received only {frames} decoded frames"
    );
}

#[tokio::test]
async fn rtsp_camera_formats_reach_rtsp_and_srt_viewers() {
    for codec in [
        format!("{H264} ! rtph264pay"),
        format!("{H264} ! mpegtsmux alignment=7 ! rtpmp2tpay"),
        "jpegenc ! rtpjpegpay".into(),
        "x265enc tune=zerolatency speed-preset=ultrafast key-int-max=5 ! h265parse ! rtph265pay"
            .into(),
    ] {
        let camera = Camera::new(&codec);
        let mut relay = RtspRestreamer::start_from_rtsp(
            &camera.url(),
            unused_tcp_port(),
            "/test",
            Some("127.0.0.1"),
            "",
            "",
            runtime(RelayIngestKind::Rtsp),
        )
        .unwrap_or_else(|e| panic!("{}", e.error));
        for _ in 0..2 {
            receive_video(&format!(
                "rtspsrc location=rtsp://127.0.0.1:{}/test protocols=tcp latency=0 ! rtph264depay",
                relay.port()
            ));
        }
        relay.shutdown().await;

        let port = unused_udp_port();
        let mut relay = SrtRestreamer::start_from_rtsp(
            &camera.url(),
            port,
            Some("127.0.0.1"),
            "",
            "",
            None,
            20,
            "test",
            runtime(RelayIngestKind::Rtsp),
        )
        .unwrap_or_else(|e| panic!("{}", e.error));
        receive_video(&format!(
            "srtsrc uri=\"srt://127.0.0.1:{port}?streamid=test\" latency=20 ! tsdemux"
        ));
        relay.shutdown().await;
    }
}

#[tokio::test]
async fn udp_transport_stream_reaches_both_outputs() {
    gst::init().unwrap();
    for srt in [false, true] {
        let udp_port = unused_udp_port();
        let output_port = if srt {
            unused_udp_port()
        } else {
            unused_tcp_port()
        };
        let sender = gst::parse::launch(&format!(
            "{VIDEO} ! {H264} ! mpegtsmux alignment=7 ! udpsink host=127.0.0.1 port={udp_port}"
        ))
        .unwrap()
        .downcast::<gst::Pipeline>()
        .unwrap();
        let _stop = StopPipeline(sender.clone());
        if srt {
            let mut relay = SrtRestreamer::start_from_udp(
                udp_port,
                output_port,
                Some("127.0.0.1"),
                None,
                20,
                "test",
                runtime(RelayIngestKind::Udp),
            )
            .unwrap_or_else(|e| panic!("{}", e.error));
            sender.set_state(gst::State::Playing).unwrap();
            receive_video(&format!(
                "srtsrc uri=\"srt://127.0.0.1:{output_port}?streamid=test\" latency=20 ! tsdemux"
            ));
            relay.shutdown().await;
        } else {
            let mut relay = RtspRestreamer::start_from_udp(
                udp_port,
                output_port,
                "/test",
                Some("127.0.0.1"),
                runtime(RelayIngestKind::Udp),
            )
            .unwrap_or_else(|e| panic!("{}", e.error));
            sender.set_state(gst::State::Playing).unwrap();
            receive_video(&format!(
                "rtspsrc location=rtsp://127.0.0.1:{output_port}/test protocols=tcp latency=0 ! rtph264depay"
            ));
            relay.shutdown().await;
        }
    }
}
