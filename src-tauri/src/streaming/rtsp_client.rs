//! RTSP/UDP playback pipeline via GStreamer.
//!
//! Builds a pipeline with a `tee` so the decoded stream can be:
//! 1. Displayed via d3d11videosink into a provided window handle
//! 2. Optionally recorded to MP4
//! 3. Snapshot-captured via an appsink

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app as gst_app;

use gstreamer_video::prelude::VideoOverlayExtManual;

use crate::error::AppError;

/// How long the pipeline can sit in `Playing` state with no buffers
/// arriving at the tee's sink pad before `health_check` declares the
/// stream stalled. Catches the failure mode where rtspsrc sits on a
/// TCP socket the OS still reports as Established but is no longer
/// carrying data — Windows' default 2-hour TCP keepalive means the OS
/// won't surface this in any usable timeframe, so the user sees a
/// frozen last frame and no error. 3s is well above the per-frame
/// gap on any normal RTSP stream (~30-66ms at 15-30fps) but tight
/// enough that an ASIX-style link flap surfaces as Stream Lost in
/// ~5s end-to-end instead of ~10s.
const STALL_THRESHOLD: Duration = Duration::from_secs(3);

/// How long the pipeline can sit at `current=Paused, pending=Playing`
/// before `health_check` declares the stream stalled. Catches the
/// failure mode where rtspsrc errors during SDP/SETUP (e.g., a
/// DESCRIBE timeout caused by a concurrent ping-sweep saturating the
/// USB Ethernet adapter): the bus error gets popped once on the
/// following health_check tick, but the pipeline state stays at
/// Paused indefinitely and the buffer-arrival watchdog never fires
/// because Playing was never reached. 10s is comfortably longer than
/// a normal RTSP handshake on a healthy network while still tripping
/// well before the user notices.
const PAUSED_STALL_THRESHOLD: Duration = Duration::from_secs(10);

/// A live playback pipeline with tee for recording/screenshots.
pub struct PlaybackPipeline {
    pub pipeline: gst::Pipeline,
    pub appsink: gst_app::AppSink,
    /// Updated by a buffer probe on the tee's sink pad on every decoded
    /// frame. Stays `None` until the first buffer arrives so the
    /// watchdog doesn't misfire during caps negotiation — pipelines
    /// that never reach Playing are already covered by the existing
    /// `playing=false` path in `health_check`.
    last_buffer_at: Arc<Mutex<Option<Instant>>>,
    /// First `Instant` we observed `current=Paused && pending=Playing`
    /// in the current stuck-state window. Cleared whenever the
    /// pipeline leaves that state (reaches Playing, or transitions
    /// somewhere unexpected). Used to time out a pipeline that
    /// silently fails to complete its Paused→Playing transition —
    /// the buffer-arrival watchdog can't catch that case because
    /// it gates on `current=Playing`.
    paused_pending_play_at: Arc<Mutex<Option<Instant>>>,
    /// Camera IP for the stall diagnostic ping. None for UDP receive,
    /// where there's no single peer to probe.
    camera_ip: Option<String>,
    /// Set when a diagnostic ping has already been issued for the
    /// current stall window. Cleared by the buffer pad probe when
    /// frames resume, so each fresh stall gets its own ping log.
    /// Distinguishes camera-side stalls (ping succeeds) from
    /// network/adapter stalls (ping fails) without the user having to
    /// guess.
    stall_diag_sent: Arc<Mutex<bool>>,
    /// First bus error seen on this pipeline, latched. Bus reads are
    /// destructive (`pop_filtered`), so without the latch the real
    /// error is visible for exactly one status tick and every later
    /// tick degrades to a generic "stalled"/not-playing verdict.
    /// Cleared on `play()` so a restarted pipeline reports fresh state.
    first_error: Arc<Mutex<Option<String>>>,
}

impl PlaybackPipeline {
    /// Create a playback pipeline for an RTSP source.
    /// `window_handle`: if Some, render into that HWND via VideoOverlay.
    pub fn new_rtsp(
        url: &str,
        latency_ms: u32,
        use_tcp: bool,
        window_handle: Option<usize>,
        camera_ip: Option<String>,
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

        let result = Self::from_pipeline_str(&pipeline_str, window_handle, camera_ip)?;

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

        Self::from_pipeline_str(&pipeline_str, window_handle, None)
    }

    fn from_pipeline_str(
        pipeline_str: &str,
        window_handle: Option<usize>,
        camera_ip: Option<String>,
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

        // Stall watchdog: probe the tee's sink pad so every decoded
        // buffer ticks `last_buffer_at`. The probe runs on a streaming
        // thread; the mutex is uncontended at frame rate. Tee sink
        // (rather than appsink) is the right tap point — appsink has
        // `drop=true max-buffers=1` and a leaky upstream queue, so
        // most frames never reach it; the tee input sees them all.
        let last_buffer_at = Arc::new(Mutex::new(None::<Instant>));
        let tee = pipeline
            .by_name("t")
            .ok_or_else(|| AppError::Stream("tee 't' not found in pipeline".into()))?;
        let tee_sink = tee
            .static_pad("sink")
            .ok_or_else(|| AppError::Stream("tee sink pad missing".into()))?;
        let stall_diag_sent = Arc::new(Mutex::new(false));
        let last_buffer_for_probe = last_buffer_at.clone();
        let stall_diag_for_probe = stall_diag_sent.clone();
        tee_sink.add_probe(gst::PadProbeType::BUFFER, move |_, _| {
            if let Ok(mut guard) = last_buffer_for_probe.lock() {
                *guard = Some(Instant::now());
            }
            // Frames are arriving — any active stall window is over.
            // Reset the diagnostic flag so the next stall (if any)
            // logs its own ping result.
            if let Ok(mut guard) = stall_diag_for_probe.lock() {
                if *guard {
                    *guard = false;
                }
            }
            gst::PadProbeReturn::Ok
        });

        Ok(Self {
            pipeline,
            appsink,
            last_buffer_at,
            paused_pending_play_at: Arc::new(Mutex::new(None::<Instant>)),
            camera_ip,
            stall_diag_sent,
            first_error: Arc::new(Mutex::new(None)),
        })
    }

    /// Start playback.
    pub fn play(&self) -> Result<(), AppError> {
        if let Ok(mut g) = self.first_error.lock() {
            *g = None;
        }
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
        // the state transitions away from Playing. Error and debug text
        // are redacted BEFORE any logging or storage: rtspsrc debug
        // payloads can replay the input URL including `user:pass@`.
        if let Some(bus) = self.pipeline.bus() {
            if let Some(msg) = bus.pop_filtered(&[gst::MessageType::Error, gst::MessageType::Eos]) {
                if let gst::MessageView::Error(err) = msg.view() {
                    let raw = super::StreamManager::redact_url(&err.error().to_string());
                    let debug = err
                        .debug()
                        .map(|d| super::StreamManager::redact_url(&d))
                        .unwrap_or_default();
                    log::warn!("Stream bus error: {} | debug: {}", raw, debug);
                    return Err(self.latch_error(friendly_rtsp_error(&raw, &debug)));
                }
                log::warn!("Stream bus EOS received");
                return Err(self.latch_error("End of stream".into()));
            }
        }

        // A previously-latched bus error beats any generic verdict the
        // state inspection below would produce — bus reads are
        // destructive, so this is the only way the real error survives
        // past its own tick.
        if let Ok(g) = self.first_error.lock() {
            if let Some(e) = g.as_ref() {
                return Err(e.clone());
            }
        }

        let (_, current, pending) = self.pipeline.state(gst::ClockTime::from_mseconds(0));
        let playing = current == gst::State::Playing;

        if playing {
            // Pipeline reached Playing — clear stuck-Paused tracking
            // so a future failed transition starts fresh.
            if let Ok(mut g) = self.paused_pending_play_at.lock() {
                *g = None;
            }
            // Buffer-arrival watchdog. Skipped while `last_buffer_at`
            // is None (haven't decoded a frame yet) so slow caps
            // negotiation doesn't trip it.
            if let Ok(guard) = self.last_buffer_at.lock() {
                if let Some(last) = *guard {
                    let elapsed = last.elapsed();
                    if elapsed >= STALL_THRESHOLD {
                        log::warn!(
                            "Stream stalled: pipeline Playing but no buffers for {:.1}s",
                            elapsed.as_secs_f32()
                        );
                        self.maybe_fire_stall_diag_ping();
                        return Err(format!(
                            "Stream stalled — no frames for {}s",
                            elapsed.as_secs()
                        ));
                    }
                }
            }
        } else if current == gst::State::Paused && pending == gst::State::Playing {
            // Stuck-Paused watchdog. rtspsrc may have errored during
            // SDP/SETUP — the bus error was popped above on whichever
            // tick happened to catch it, but the pipeline state stays
            // at Paused indefinitely afterward. Without this we'd
            // spam `not playing` warnings forever and never trigger
            // stall recovery (the buffer-arrival watchdog can't fire
            // because Playing was never reached).
            //
            // The `stalled` keyword in the returned error routes to
            // `isStallError` on the frontend, which schedules the
            // existing stall-recovery flow.
            let elapsed = match self.paused_pending_play_at.lock() {
                Ok(mut g) => g.get_or_insert_with(Instant::now).elapsed(),
                Err(_) => Duration::ZERO,
            };
            if elapsed >= PAUSED_STALL_THRESHOLD {
                log::warn!(
                    "Stream stalled: stuck Paused→Playing for {:.1}s",
                    elapsed.as_secs_f32()
                );
                return Err(format!(
                    "Stream stalled — pipeline stuck transitioning to Playing for {}s",
                    elapsed.as_secs()
                ));
            }
            log::warn!(
                "Stream health_check: not playing (current={:?}, pending={:?})",
                current,
                pending
            );
        } else {
            // Some other non-Playing state (Null/Ready/transitioning
            // elsewhere) — clear stuck-Paused tracking so the watchdog
            // only counts continuous time spent stuck specifically at
            // Paused→Playing.
            if let Ok(mut g) = self.paused_pending_play_at.lock() {
                *g = None;
            }
            log::warn!(
                "Stream health_check: not playing (current={:?}, pending={:?})",
                current,
                pending
            );
        }
        Ok(playing)
    }

    /// Latch the first error seen on this pipeline (later ones keep the
    /// original — the first is the root cause) and return the message
    /// for immediate use.
    fn latch_error(&self, msg: String) -> String {
        if let Ok(mut g) = self.first_error.lock() {
            if let Some(existing) = g.as_ref() {
                return existing.clone();
            }
            *g = Some(msg.clone());
        }
        msg
    }

    /// Fire a one-shot ICMP probe at the camera IP if we haven't
    /// already pinged for the current stall window. Result goes to
    /// the log so a successful ping (camera reachable, stream pause is
    /// RTSP/camera-side) is distinguishable from a failed ping (path
    /// loss, USB-Ethernet hiccup, cable). Each fresh stall gets a
    /// fresh ping — the buffer pad probe clears the flag when frames
    /// resume.
    fn maybe_fire_stall_diag_ping(&self) {
        let Some(ip) = self.camera_ip.clone() else {
            return;
        };
        let Ok(mut guard) = self.stall_diag_sent.lock() else {
            return;
        };
        if *guard {
            return;
        }
        *guard = true;
        tokio::spawn(async move {
            let reachable = crate::network::ping_dot::probe(&ip).await;
            if reachable {
                log::warn!(
                    "Stall diagnostic: {} responds to ICMP — stall is RTSP/camera-side, not network",
                    ip
                );
            } else {
                log::warn!(
                    "Stall diagnostic: {} unreachable (ICMP timeout) — stall is network/adapter-side",
                    ip
                );
            }
        });
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
    ///
    /// Teardown discipline (each step is load-bearing):
    /// 1. Unlink inside an IDLE pad probe on the tee's request pad, so
    ///    an in-flight buffer can't race the unlink.
    /// 2. Inject EOS into the bin's **sink pad** — sending it to the
    ///    bin routed it to the bin's source elements, of which a
    ///    queue→mux→filesink branch has none, so it never arrived and
    ///    only mp4mux's 1 s fragments saved recordings.
    /// 3. Wait (bounded) for the EOS to actually reach the filesink via
    ///    a pad probe there — the pipeline bus won't post EOS for one
    ///    branch while other sinks keep playing, and `health_check`
    ///    destructively pops the same bus, so a second bus consumer
    ///    would race it.
    pub async fn detach_recording(&self) -> Result<(), AppError> {
        const EOS_WAIT: Duration = Duration::from_secs(3);

        let rec_bin = self
            .pipeline
            .by_name("rec_bin")
            .ok_or_else(|| AppError::Stream("Recording bin not found".into()))?;

        let bin_sink_pad = rec_bin
            .static_pad("sink")
            .ok_or_else(|| AppError::Stream("Recording bin has no sink pad".into()))?;

        // EOS-arrival watcher on the filesink's sink pad, armed before
        // the EOS is injected so a fast flush can't be missed.
        let filesink_sink = rec_bin
            .downcast_ref::<gst::Bin>()
            .and_then(|b| b.by_name("rec_sink"))
            .and_then(|sink| sink.static_pad("sink"))
            .ok_or_else(|| AppError::Stream("Recording filesink pad not found".into()))?;
        let (eos_tx, eos_rx) = tokio::sync::oneshot::channel::<()>();
        let eos_tx = std::sync::Mutex::new(Some(eos_tx));
        filesink_sink.add_probe(gst::PadProbeType::EVENT_DOWNSTREAM, move |_, info| {
            if let Some(gst::PadProbeData::Event(ref ev)) = info.data {
                if ev.type_() == gst::EventType::Eos {
                    if let Ok(mut g) = eos_tx.lock() {
                        if let Some(tx) = g.take() {
                            let _ = tx.send(());
                        }
                    }
                    return gst::PadProbeReturn::Remove;
                }
            }
            gst::PadProbeReturn::Ok
        });

        if let Some(tee_src_pad) = bin_sink_pad.peer() {
            // Unlink from inside an IDLE probe: the callback runs when
            // the pad is not pushing data (immediately if idle), so an
            // in-flight buffer can't race the teardown.
            let (unlinked_tx, unlinked_rx) = tokio::sync::oneshot::channel::<()>();
            let unlinked_tx = std::sync::Mutex::new(Some(unlinked_tx));
            let bin_sink_for_probe = bin_sink_pad.clone();
            let tee = self
                .pipeline
                .by_name("t")
                .ok_or_else(|| AppError::Stream("Tee element not found".into()))?;
            tee_src_pad.add_probe(gst::PadProbeType::IDLE, move |pad, _| {
                let _ = pad.unlink(&bin_sink_for_probe);
                // EOS in through the now-unlinked branch's sink pad so
                // it drains queue→encoder→mux→filesink.
                let _ = bin_sink_for_probe.send_event(gst::event::Eos::new());
                tee.release_request_pad(pad);
                if let Ok(mut g) = unlinked_tx.lock() {
                    if let Some(tx) = g.take() {
                        let _ = tx.send(());
                    }
                }
                gst::PadProbeReturn::Remove
            });
            if tokio::time::timeout(EOS_WAIT, unlinked_rx).await.is_err() {
                return Err(AppError::Stream(
                    "Recording unlink timed out — branch never went idle".into(),
                ));
            }
        } else {
            // Already unlinked (shouldn't happen) — still flush the bin.
            let _ = bin_sink_pad.send_event(gst::event::Eos::new());
        }

        // Bounded wait for the EOS to reach the filesink instead of the
        // old unconditional 500 ms sleep. On timeout, proceed to Null —
        // fragmented MP4 keeps everything up to the last fragment, which
        // is no worse than the old behavior, but say so in the log.
        match tokio::time::timeout(EOS_WAIT, eos_rx).await {
            Ok(Ok(())) => log::info!("Recording EOS reached the file sink"),
            _ => log::warn!(
                "Recording EOS did not reach the file sink within {}s — finalizing anyway",
                EOS_WAIT.as_secs()
            ),
        }

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

    // Fallback: truncate long debug info. Char-based, not byte-based —
    // a byte slice at 120 panics on a multi-byte UTF-8 boundary, and
    // this runs inside the 1 Hz status ticker, which the panic would
    // kill permanently (UI status freeze).
    if debug.chars().count() > 120 {
        let truncated: String = debug.chars().take(120).collect();
        format!("{} ({}...)", error, truncated)
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
    fn fallback_truncation_survives_multibyte_utf8_at_boundary() {
        // 119 ASCII chars then a stream of 3-byte chars — a byte slice
        // at index 120 would land mid-€ and panic. This runs in the 1 Hz
        // status ticker, so a panic here permanently froze UI status.
        let debug = format!("{}{}", "x".repeat(119), "€".repeat(50));
        let msg = friendly_rtsp_error("err", &debug);
        assert!(msg.contains("..."));
        assert!(msg.contains('€'));
    }

    #[test]
    fn fallback_exact_120_chars_not_truncated() {
        let debug = "y".repeat(120);
        let msg = friendly_rtsp_error("err", &debug);
        assert!(!msg.contains("..."));
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
