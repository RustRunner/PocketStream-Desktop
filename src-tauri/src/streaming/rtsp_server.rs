//! RTSP re-streaming server via GStreamer RTSP Server.
//!
//! Takes the incoming camera stream (RTSP or UDP) and re-broadcasts it
//! as an RTSP endpoint on the local network.
//!
//! The server's GLib source is attached to a **dedicated** MainContext
//! (not the default one) to avoid conflicts with GStreamer's internal
//! use of the default context. A background thread runs a MainLoop on
//! this dedicated context to dispatch RTSP client requests.

use gstreamer as gst;
use gstreamer_rtsp as gst_rtsp;
use gstreamer_rtsp_server as gst_rtsp_server;
use gstreamer_rtsp_server::prelude::*;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::audio;
use crate::error::AppError;

/// Redact the RTSP access token embedded in a mount path for logging.
/// The path is `/stream-<token>` — the same capability secret
/// `display_url` deliberately hides from the UI — and `redact_url`
/// can't help here (no scheme, no credentials to match).
fn redact_mount_path(mount_path: &str) -> String {
    match mount_path.strip_prefix("/stream-") {
        Some(_) => "/stream-***".into(),
        None => mount_path.into(),
    }
}

pub struct RtspRestreamer {
    server: gst_rtsp_server::RTSPServer,
    main_loop: glib::MainLoop,
    /// The dedicated GLib loop thread. Joined by `shutdown`; a plain
    /// drop leaves it to exit on its own after the Drop-quit.
    loop_thread: Option<std::thread::JoinHandle<()>>,
    /// Signalled by the loop thread right before it exits — the only
    /// way to bound the join (`std::thread::JoinHandle` has no
    /// join-with-timeout).
    loop_done_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    port: u16,
    mount_path: String,
    /// UDP port the factory's `udpsrc` ingests from (None for the RTSP
    /// source mode). Captured at start time for the double-bind guard —
    /// the bind itself happens lazily on first client connect, so the
    /// claim isn't observable from the socket table at start.
    udp_ingest_port: Option<u16>,
    bytes_sent: Arc<AtomicU64>,
    /// (bytes counted, time) at the previous bandwidth poll, so
    /// `bandwidth_kbps` reports the rate over the last poll interval
    /// rather than a lifetime average. Single 1 Hz consumer, so the
    /// mutex is uncontended.
    bw_prev: std::sync::Mutex<(u64, std::time::Instant)>,
}

impl Drop for RtspRestreamer {
    fn drop(&mut self) {
        // Backstop only — the deliberate path is `shutdown`, which
        // tears sessions down while the loop can still dispatch and
        // then joins the thread.
        self.main_loop.quit();
        log::info!("RTSP server main loop quit signalled");
    }
}

impl RtspRestreamer {
    /// Attach a pad probe to the payloader inside the media pipeline to count
    /// outgoing bytes for bandwidth measurement.
    fn attach_bandwidth_probe(
        factory: &gst_rtsp_server::RTSPMediaFactory,
        bytes_sent: Arc<AtomicU64>,
    ) {
        factory.connect_media_constructed(move |_factory, media| {
            let element: gst::Element = media.element();
            let bin: gst::Bin = match element.downcast::<gst::Bin>() {
                Ok(b) => b,
                Err(_) => {
                    log::warn!("RTSP media element is not a Bin");
                    return;
                }
            };
            let pay0: gst::Element = match bin.by_name("pay0") {
                Some(e) => e,
                None => {
                    log::warn!("pay0 element not found in RTSP media pipeline");
                    return;
                }
            };
            let pad: gst::Pad = match pay0.static_pad("src") {
                Some(p) => p,
                None => {
                    log::warn!("pay0 has no src pad");
                    return;
                }
            };

            let bytes = bytes_sent.clone();
            pad.add_probe(gst::PadProbeType::BUFFER, move |_pad, info| {
                if let Some(gst::PadProbeData::Buffer(ref buffer)) = info.data {
                    bytes.fetch_add(buffer.size() as u64, Ordering::Relaxed);
                }
                gst::PadProbeReturn::Ok
            });
            log::info!("Bandwidth probe attached to RTSP server pipeline");
        });
    }

    /// Create the server source, attach to a dedicated context, and spawn
    /// a background thread running a MainLoop on that context. Returns
    /// the loop plus the thread handle and a completion channel so
    /// `shutdown` can join with a bound.
    fn attach_and_run(
        server: &gst_rtsp_server::RTSPServer,
    ) -> Result<
        (
            glib::MainLoop,
            std::thread::JoinHandle<()>,
            tokio::sync::oneshot::Receiver<()>,
        ),
        AppError,
    > {
        // create_source gives us the real error (port in use, permission denied, etc.)
        let source = server
            .create_source(gio::Cancellable::NONE)
            .map_err(|e| AppError::Stream(format!("RTSP server socket failed: {}", e)))?;

        // Use a dedicated context so we don't conflict with GStreamer's
        // internal use of the default GLib main context.
        let ctx = glib::MainContext::new();
        source.attach(Some(&ctx));

        let main_loop = glib::MainLoop::new(Some(&ctx), false);
        let loop_clone = main_loop.clone();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let handle = std::thread::Builder::new()
            .name("rtsp-server-glib".into())
            .spawn(move || {
                let _ = ctx.with_thread_default(|| {
                    log::info!("RTSP server GLib main loop running (dedicated context)");
                    loop_clone.run();
                    log::info!("RTSP server GLib main loop exited");
                });
                let _ = done_tx.send(());
            })
            .map_err(|e| AppError::Stream(format!("Failed to spawn RTSP server thread: {}", e)))?;

        Ok((main_loop, handle, done_rx))
    }

    /// Deterministic teardown. Ordering is load-bearing:
    /// 1. Remove the mount so no new client connects mid-teardown.
    /// 2. Filter every session out of the pool **while the loop is
    ///    still alive** — client and camera-side RTSP session teardown
    ///    dispatches on it; after quit they'd linger until TCP death
    ///    (which matters for Nexus encoders with session limits).
    /// 3. Quit the loop and join the thread, bounded by the completion
    ///    channel — if the loop never exits, leak the thread rather
    ///    than hang stop.
    pub async fn shutdown(mut self) {
        if let Some(mounts) = self.server.mount_points() {
            mounts.remove_factory(&self.mount_path);
        }

        if let Some(pool) = self.server.session_pool() {
            let removed = pool.filter(Some(&mut |_pool: &_, _session: &_| {
                gst_rtsp_server::RTSPFilterResult::Remove
            }));
            if !removed.is_empty() {
                log::info!("RTSP server: removed {} active session(s)", removed.len());
            }
        }

        self.main_loop.quit();

        let done_rx = self.loop_done_rx.take();
        let handle = self.loop_thread.take();
        let exited = match done_rx {
            Some(rx) => tokio::time::timeout(std::time::Duration::from_secs(3), rx)
                .await
                .is_ok(),
            None => false,
        };
        if exited {
            if let Some(h) = handle {
                let _ = tokio::task::spawn_blocking(move || h.join()).await;
            }
            log::info!("RTSP server loop thread joined");
        } else {
            log::warn!(
                "RTSP server loop did not exit within 3s — leaking its thread instead of hanging stop"
            );
            drop(handle);
        }
    }

    /// Start an RTSP server that re-streams from an RTSP source.
    pub fn start_from_rtsp(
        input_url: &str,
        port: u16,
        mount_path: &str,
        bind_address: Option<&str>,
        username: &str,
        password: &str,
    ) -> Result<Self, AppError> {
        let server = gst_rtsp_server::RTSPServer::new();
        server.set_service(&port.to_string());
        if let Some(addr) = bind_address {
            server.set_address(addr);
        }

        let factory = gst_rtsp_server::RTSPMediaFactory::new();

        // The RTSP source URL is set via a media-configure callback below,
        // not interpolated into the launch string, to prevent GStreamer
        // pipeline injection via crafted RTSP paths or credentials.
        let launch = "( rtspsrc name=src latency=200 protocols=tcp \
             ! rtph264depay ! h264parse \
             ! rtph264pay name=pay0 pt=96 )";

        factory.set_launch(launch);
        factory.set_shared(true);

        // Set the RTSP source URL each time the factory creates a new pipeline
        // (once per connecting client). Fires before media-constructed.
        // Credentials go on rtspsrc's user-id/user-pw properties, not the
        // URL, so special characters don't break it and creds stay out of
        // the launch string.
        let url_for_factory = input_url.to_string();
        let user_for_factory = username.to_string();
        let pw_for_factory = password.to_string();
        factory.connect_media_configure(move |_factory, media| {
            let element = media.element();
            if let Ok(bin) = element.downcast::<gst::Bin>() {
                if let Some(src) = bin.by_name("src") {
                    src.set_property("location", &url_for_factory);
                    if !user_for_factory.is_empty() {
                        src.set_property("user-id", &user_for_factory);
                        src.set_property("user-pw", &pw_for_factory);
                    }
                    // Accept only the first video stream at SETUP. The
                    // launch chain can only consume H.264 video; an
                    // audio pad would have no consumer and its
                    // GST_FLOW_NOT_LINKED would kill the re-stream
                    // pipeline the same way it killed playback. Fresh
                    // state per media — the factory is shared, and each
                    // media construction negotiates its own streams.
                    // media-configure fires before SDP/SETUP, so the
                    // handler lands in time.
                    let selection = audio::SelectionState::default();
                    src.connect("select-stream", false, move |values| {
                        let caps = values.get(2).and_then(|v| v.get::<gst::Caps>().ok());
                        let kind = caps
                            .as_ref()
                            .map(|c| audio::classify_rtp_caps(c).0)
                            .unwrap_or(audio::MediaKind::Other);
                        let accept = selection.select_video_only(kind);
                        if !accept {
                            log::info!("Re-stream: declining non-video stream at SETUP");
                        }
                        // A select-stream handler must return a gboolean
                        // Value — None panics in the closure marshal.
                        Some(accept.to_value())
                    });
                }
            }
        });
        factory.set_latency(200);
        // Force TCP interleaved transport — all RTP data goes through the
        // existing TCP connection on port 8554. No extra UDP ports needed,
        // works reliably across firewalls, VPNs, and NAT.
        factory.set_protocols(gst_rtsp::RTSPLowerTrans::TCP);

        let bytes_sent = Arc::new(AtomicU64::new(0));
        Self::attach_bandwidth_probe(&factory, bytes_sent.clone());

        let mounts = server
            .mount_points()
            .ok_or_else(|| AppError::Stream("Failed to get mount points".into()))?;
        mounts.add_factory(mount_path, factory);

        server.connect_client_connected(|_server, _client| {
            log::info!("RTSP client connected");
        });

        let (main_loop, loop_thread, loop_done_rx) = Self::attach_and_run(&server)?;

        log::info!(
            "RTSP server started on port {} at {}",
            port,
            redact_mount_path(mount_path)
        );

        Ok(Self {
            server,
            main_loop,
            loop_thread: Some(loop_thread),
            loop_done_rx: Some(loop_done_rx),
            port,
            mount_path: mount_path.into(),
            udp_ingest_port: None,
            bytes_sent,
            bw_prev: std::sync::Mutex::new((0, std::time::Instant::now())),
        })
    }

    /// Start an RTSP server that re-streams from a UDP source.
    pub fn start_from_udp(
        udp_port: u16,
        server_port: u16,
        mount_path: &str,
        bind_address: Option<&str>,
    ) -> Result<Self, AppError> {
        let server = gst_rtsp_server::RTSPServer::new();
        server.set_service(&server_port.to_string());
        if let Some(addr) = bind_address {
            server.set_address(addr);
        }

        let factory = gst_rtsp_server::RTSPMediaFactory::new();

        let launch = format!(
            "( udpsrc port={port} \
             ! tsdemux ! h264parse \
             ! rtph264pay name=pay0 pt=96 )",
            port = udp_port,
        );

        factory.set_launch(&launch);
        factory.set_shared(true);
        factory.set_protocols(gst_rtsp::RTSPLowerTrans::TCP);

        let bytes_sent = Arc::new(AtomicU64::new(0));
        Self::attach_bandwidth_probe(&factory, bytes_sent.clone());

        let mounts = server
            .mount_points()
            .ok_or_else(|| AppError::Stream("Failed to get mount points".into()))?;
        mounts.add_factory(mount_path, factory);

        let (main_loop, loop_thread, loop_done_rx) = Self::attach_and_run(&server)?;

        log::info!(
            "RTSP server (UDP source) started on port {} at {}",
            server_port,
            redact_mount_path(mount_path)
        );

        Ok(Self {
            server,
            main_loop,
            loop_thread: Some(loop_thread),
            loop_done_rx: Some(loop_done_rx),
            port: server_port,
            mount_path: mount_path.into(),
            udp_ingest_port: Some(udp_port),
            bytes_sent,
            bw_prev: std::sync::Mutex::new((0, std::time::Instant::now())),
        })
    }

    /// Get the full RTSP URL for clients (includes token path).
    pub fn client_url(&self, local_ip: &str) -> String {
        format!("rtsp://{}:{}{}", local_ip, self.port, self.mount_path)
    }

    /// Get the display URL (no token, for UI privacy).
    pub fn display_url(&self, local_ip: &str) -> String {
        format!("rtsp://{}:{}", local_ip, self.port)
    }

    /// Get the current average bandwidth in kbps since server start.
    /// Current throughput over the interval since the previous call, not
    /// a lifetime average (which never reflected the live rate).
    pub fn bandwidth_kbps(&self) -> f64 {
        let now = std::time::Instant::now();
        let bytes = self.bytes_sent.load(Ordering::Relaxed);
        let mut prev = self.bw_prev.lock().unwrap_or_else(|p| p.into_inner());
        let (prev_bytes, prev_time) = *prev;
        let elapsed = now.duration_since(prev_time).as_secs_f64();
        *prev = (bytes, now);
        if elapsed < 0.001 {
            return 0.0;
        }
        let delta_bits = bytes.saturating_sub(prev_bytes) as f64 * 8.0;
        delta_bits / elapsed / 1000.0
    }

    /// Get the port this server is listening on.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// UDP port the media factory ingests from, if this server was
    /// started in UDP source mode. Used by the double-bind guard.
    pub fn udp_ingest_port(&self) -> Option<u16> {
        self.udp_ingest_port
    }
}

#[cfg(test)]
mod tests {
    use super::redact_mount_path;

    #[test]
    fn mount_path_token_is_redacted() {
        assert_eq!(redact_mount_path("/stream-s3cr3ttoken"), "/stream-***");
    }

    #[test]
    fn non_token_paths_pass_through() {
        assert_eq!(redact_mount_path("/live"), "/live");
    }
}
