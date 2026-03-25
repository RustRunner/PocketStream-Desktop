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
use gst::prelude::*;
use gstreamer_rtsp as gst_rtsp;
use gstreamer_rtsp_server as gst_rtsp_server;
use gstreamer_rtsp_server::prelude::*;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::error::AppError;

pub struct RtspRestreamer {
    #[allow(dead_code)]
    server: gst_rtsp_server::RTSPServer,
    main_loop: glib::MainLoop,
    port: u16,
    mount_path: String,
    bytes_sent: Arc<AtomicU64>,
    bandwidth_start: std::time::Instant,
}

impl Drop for RtspRestreamer {
    fn drop(&mut self) {
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
    /// a background thread running a MainLoop on that context.
    fn attach_and_run(
        server: &gst_rtsp_server::RTSPServer,
    ) -> Result<glib::MainLoop, AppError> {
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

        std::thread::Builder::new()
            .name("rtsp-server-glib".into())
            .spawn(move || {
                let _ = ctx.with_thread_default(|| {
                    log::info!("RTSP server GLib main loop running (dedicated context)");
                    loop_clone.run();
                    log::info!("RTSP server GLib main loop exited");
                });
            })
            .map_err(|e| AppError::Stream(format!("Failed to spawn RTSP server thread: {}", e)))?;

        Ok(main_loop)
    }

    /// Start an RTSP server that re-streams from an RTSP source.
    pub fn start_from_rtsp(
        input_url: &str,
        port: u16,
        mount_path: &str,
        bind_address: Option<&str>,
    ) -> Result<Self, AppError> {
        let server = gst_rtsp_server::RTSPServer::new();
        server.set_service(&port.to_string());
        if let Some(addr) = bind_address {
            server.set_address(addr);
        }

        let factory = gst_rtsp_server::RTSPMediaFactory::new();

        let launch = format!(
            "( rtspsrc location={url} latency=200 protocols=tcp \
             ! rtph264depay ! h264parse \
             ! rtph264pay name=pay0 pt=96 )",
            url = input_url,
        );

        factory.set_launch(&launch);
        factory.set_shared(true);
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

        let main_loop = Self::attach_and_run(&server)?;

        log::info!("RTSP server started on port {} at {}", port, mount_path);

        Ok(Self {
            server,
            main_loop,
            port,
            mount_path: mount_path.into(),
            bytes_sent,
            bandwidth_start: std::time::Instant::now(),
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

        let main_loop = Self::attach_and_run(&server)?;

        log::info!(
            "RTSP server (UDP source) started on port {} at {}",
            server_port,
            mount_path
        );

        Ok(Self {
            server,
            main_loop,
            port: server_port,
            mount_path: mount_path.into(),
            bytes_sent,
            bandwidth_start: std::time::Instant::now(),
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
    pub fn bandwidth_kbps(&self) -> f64 {
        let elapsed = self.bandwidth_start.elapsed().as_secs_f64();
        if elapsed < 0.5 {
            return 0.0;
        }
        let bytes = self.bytes_sent.load(Ordering::Relaxed) as f64;
        (bytes * 8.0) / elapsed / 1000.0
    }

    /// Get the port this server is listening on.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }
}
