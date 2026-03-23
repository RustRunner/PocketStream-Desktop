pub mod recorder;
pub mod rtsp_client;
pub mod rtsp_server;
pub mod video_embed;

use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config::AppSettings;
use crate::error::AppError;

use rtsp_client::PlaybackPipeline;
use rtsp_server::RtspRestreamer;

#[derive(Debug, Clone, Serialize)]
pub struct StreamStatus {
    pub playing: bool,
    pub rtsp_server_running: bool,
    pub rtsp_url: Option<String>,
    pub recording: bool,
    pub uptime_secs: u64,
    pub bandwidth_kbps: f64,
}

pub struct StreamManager {
    state: Arc<Mutex<StreamState>>,
}

struct StreamState {
    playback: Option<PlaybackPipeline>,
    rtsp_server: Option<RtspRestreamer>,
    recording: bool,
    recording_path: Option<String>,
    start_time: Option<std::time::Instant>,
    video_child_hwnd: Option<isize>,
}

impl StreamManager {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(StreamState {
                playback: None,
                rtsp_server: None,
                recording: false,
                recording_path: None,
                start_time: None,
                video_child_hwnd: None,
            })),
        }
    }

    /// Build the input URL from current settings.
    fn build_input_url(settings: &AppSettings) -> String {
        match settings.stream.protocol.as_str() {
            "udp" => format!("udp://@:{}", settings.stream.udp_port),
            _ => {
                let creds = if !settings.credentials.username.is_empty() {
                    format!(
                        "{}:{}@",
                        settings.credentials.username, settings.credentials.password
                    )
                } else {
                    String::new()
                };
                format!(
                    "rtsp://{}{}:{}{}",
                    creds,
                    settings.stream.camera_ip,
                    settings.stream.rtsp_port,
                    settings.stream.rtsp_path
                )
            }
        }
    }

    pub async fn start_playback(
        &self,
        settings: &AppSettings,
        window_handle: Option<usize>,
    ) -> Result<(), AppError> {
        let mut state = self.state.lock().await;

        // Stop existing playback if any
        if let Some(ref pipeline) = state.playback {
            let _ = pipeline.stop();
        }

        let pipeline = match settings.stream.protocol.as_str() {
            "udp" => {
                log::info!("Starting UDP playback on port {}", settings.stream.udp_port);
                PlaybackPipeline::new_udp(settings.stream.udp_port, window_handle)?
            }
            _ => {
                let url = Self::build_input_url(settings);
                log::info!("Starting RTSP playback from: {}", url);
                PlaybackPipeline::new_rtsp(&url, 200, true, window_handle)?
            }
        };

        pipeline.play()?;
        state.playback = Some(pipeline);
        state.start_time = Some(std::time::Instant::now());

        Ok(())
    }

    pub async fn stop_playback(&self) -> Result<(), AppError> {
        let mut state = self.state.lock().await;

        // Stop recording first if active
        if state.recording {
            if let Some(ref pipeline) = state.playback {
                let _ = pipeline.detach_recording();
            }
            state.recording = false;
            state.recording_path = None;
        }

        if let Some(ref pipeline) = state.playback {
            pipeline.stop()?;
        }
        state.playback = None;
        state.start_time = None;

        // Destroy the video child window
        if let Some(hwnd) = state.video_child_hwnd.take() {
            video_embed::destroy_video_child(hwnd);
        }

        Ok(())
    }

    pub async fn start_rtsp_server(&self, settings: &AppSettings) -> Result<String, AppError> {
        let mut state = self.state.lock().await;

        // Stop existing server if any
        state.rtsp_server = None;

        let port = settings.rtsp_server.port;
        let mount_path = format!("/stream-{}", settings.rtsp_server.token);

        let server = match settings.stream.protocol.as_str() {
            "udp" => RtspRestreamer::start_from_udp(
                settings.stream.udp_port,
                port,
                &mount_path,
            )?,
            _ => {
                let input_url = Self::build_input_url(settings);
                RtspRestreamer::start_from_rtsp(&input_url, port, &mount_path)?
            }
        };

        // Determine local IP for the URL shown to users
        let local_ip = get_local_ip().unwrap_or_else(|| "0.0.0.0".into());
        let client_url = server.client_url(&local_ip);

        state.rtsp_server = Some(server);
        if state.start_time.is_none() {
            state.start_time = Some(std::time::Instant::now());
        }

        Ok(client_url)
    }

    pub async fn stop_rtsp_server(&self) -> Result<(), AppError> {
        let mut state = self.state.lock().await;
        // Dropping the server stops it and detaches from the main context
        state.rtsp_server = None;
        log::info!("RTSP server stopped");
        Ok(())
    }

    pub async fn get_status(&self) -> Result<StreamStatus, AppError> {
        let state = self.state.lock().await;
        let uptime = state
            .start_time
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0);

        Ok(StreamStatus {
            playing: state.playback.is_some(),
            rtsp_server_running: state.rtsp_server.is_some(),
            rtsp_url: state.rtsp_server.as_ref().map(|s| {
                let ip = get_local_ip().unwrap_or_else(|| "0.0.0.0".into());
                s.client_url(&ip)
            }),
            recording: state.recording,
            uptime_secs: uptime,
            bandwidth_kbps: 0.0, // TODO: query pipeline stats
        })
    }

    pub async fn take_screenshot(&self) -> Result<String, AppError> {
        let state = self.state.lock().await;

        let pipeline = state
            .playback
            .as_ref()
            .ok_or_else(|| AppError::Stream("No active playback for screenshot".into()))?;

        let (width, height, rgb_data) = pipeline.pull_snapshot()?;

        let output_dir = dirs::picture_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("PocketStream");

        let path = recorder::save_screenshot_bmp(&rgb_data, width, height, &output_dir)?;

        Ok(path.to_string_lossy().to_string())
    }

    pub async fn start_recording(&self) -> Result<(), AppError> {
        let mut state = self.state.lock().await;

        if state.recording {
            return Err(AppError::Stream("Already recording".into()));
        }

        let pipeline = state
            .playback
            .as_ref()
            .ok_or_else(|| AppError::Stream("No active playback to record".into()))?;

        let output_dir = dirs::video_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("PocketStream");

        let path = recorder::recording_path(&output_dir)?;
        let path_str = path.to_string_lossy().to_string();

        pipeline.attach_recording(&path_str)?;
        state.recording = true;
        state.recording_path = Some(path_str);

        Ok(())
    }

    pub async fn stop_recording(&self) -> Result<String, AppError> {
        let mut state = self.state.lock().await;

        if !state.recording {
            return Err(AppError::Stream("Not currently recording".into()));
        }

        let pipeline = state
            .playback
            .as_ref()
            .ok_or_else(|| AppError::Stream("No active playback".into()))?;

        pipeline.detach_recording()?;

        state.recording = false;
        let path = state
            .recording_path
            .take()
            .unwrap_or_else(|| "unknown".into());

        log::info!("Recording saved: {}", path);
        Ok(path)
    }

    pub async fn set_video_child_hwnd(&self, hwnd: isize) {
        let mut state = self.state.lock().await;
        state.video_child_hwnd = Some(hwnd);
    }

    pub async fn get_video_child_hwnd(&self) -> Option<isize> {
        let state = self.state.lock().await;
        state.video_child_hwnd
    }
}

/// Get the first non-loopback IPv4 address on this machine.
fn get_local_ip() -> Option<String> {
    // Use the interface listing which works on all platforms
    crate::network::interface::list_all()
        .ok()?
        .into_iter()
        .filter(|i| i.is_up && i.is_ethernet)
        .flat_map(|i| i.ips)
        .next()
        .map(|ip| ip.address)
}
