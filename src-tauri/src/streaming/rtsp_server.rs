//! RTSP re-streaming server via GStreamer RTSP Server.
//!
//! Takes the incoming camera stream (RTSP or UDP) and re-broadcasts it
//! as an RTSP endpoint on the local network.

use gstreamer_rtsp_server as gst_rtsp_server;
use gstreamer_rtsp_server::prelude::*;

use crate::error::AppError;

pub struct RtspRestreamer {
    #[allow(dead_code)]
    server: gst_rtsp_server::RTSPServer,
    _source_id: glib::SourceId,
    port: u16,
    mount_path: String,
}

impl RtspRestreamer {
    /// Start an RTSP server that re-streams from an RTSP source.
    pub fn start_from_rtsp(
        input_url: &str,
        port: u16,
        mount_path: &str,
    ) -> Result<Self, AppError> {
        let server = gst_rtsp_server::RTSPServer::new();
        server.set_service(&port.to_string());

        let factory = gst_rtsp_server::RTSPMediaFactory::new();

        // Re-stream: receive RTSP, repackage as RTP
        let launch = format!(
            "( rtspsrc location={url} latency=200 protocols=tcp \
             ! rtph264depay ! h264parse \
             ! rtph264pay name=pay0 pt=96 )",
            url = input_url,
        );

        factory.set_launch(&launch);
        factory.set_shared(true);
        factory.set_latency(200);

        let mounts = server
            .mount_points()
            .ok_or_else(|| AppError::Stream("Failed to get mount points".into()))?;
        mounts.add_factory(mount_path, factory);

        let source_id = server
            .attach(None)
            .map_err(|e| AppError::Stream(format!("Failed to attach RTSP server: {}", e)))?;

        log::info!(
            "RTSP server started on port {} at {}",
            port,
            mount_path
        );

        Ok(Self {
            server,
            _source_id: source_id,
            port,
            mount_path: mount_path.into(),
        })
    }

    /// Start an RTSP server that re-streams from a UDP source.
    pub fn start_from_udp(
        udp_port: u16,
        server_port: u16,
        mount_path: &str,
    ) -> Result<Self, AppError> {
        let server = gst_rtsp_server::RTSPServer::new();
        server.set_service(&server_port.to_string());

        let factory = gst_rtsp_server::RTSPMediaFactory::new();

        let launch = format!(
            "( udpsrc port={port} \
             ! tsdemux ! h264parse \
             ! rtph264pay name=pay0 pt=96 )",
            port = udp_port,
        );

        factory.set_launch(&launch);
        factory.set_shared(true);

        let mounts = server
            .mount_points()
            .ok_or_else(|| AppError::Stream("Failed to get mount points".into()))?;
        mounts.add_factory(mount_path, factory);

        let source_id = server
            .attach(None)
            .map_err(|e| AppError::Stream(format!("Failed to attach RTSP server: {}", e)))?;

        log::info!(
            "RTSP server (UDP source) started on port {} at {}",
            server_port,
            mount_path
        );

        Ok(Self {
            server,
            _source_id: source_id,
            port: server_port,
            mount_path: mount_path.into(),
        })
    }

    /// Get the full RTSP URL for clients.
    pub fn client_url(&self, local_ip: &str) -> String {
        format!("rtsp://{}:{}{}", local_ip, self.port, self.mount_path)
    }

    /// Get the port this server is listening on.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }
}

// The server is stopped when the RtspRestreamer is dropped,
// because dropping _source_id removes it from the main context
// and dropping the server cleans up its resources.
