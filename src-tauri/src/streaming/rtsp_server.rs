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
use gstreamer::prelude::*;
use gstreamer_rtsp as gst_rtsp;
use gstreamer_rtsp_server as gst_rtsp_server;
use gstreamer_rtsp_server::prelude::*;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use super::audio;
use super::relay::{RelayEventSender, RelayFaultKind, RelayRuntimeHealth, RelaySupervisorEvent};
use crate::error::AppError;

pub const MAX_RTSP_CLIENTS: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtspBuildFailureKind {
    Bind,
    Configuration,
}

pub struct RtspBuildFailure {
    pub kind: RtspBuildFailureKind,
    pub error: AppError,
}

pub struct RtspRuntimeContext {
    pub health: Arc<RelayRuntimeHealth>,
    pub event_tx: RelayEventSender,
    pub server_instance: u64,
}

impl RtspBuildFailure {
    fn bind(error: AppError) -> Self {
        Self {
            kind: RtspBuildFailureKind::Bind,
            error,
        }
    }

    fn configuration(error: AppError) -> Self {
        Self {
            kind: RtspBuildFailureKind::Configuration,
            error,
        }
    }
}

fn observed_probe_bytes(data: Option<&gst::PadProbeData<'_>>) -> u64 {
    match data {
        Some(gst::PadProbeData::Buffer(buffer)) => buffer.size() as u64,
        Some(gst::PadProbeData::BufferList(list)) => {
            list.iter().map(|buffer| buffer.size() as u64).sum()
        }
        _ => 0,
    }
}

fn observed_probe_arrival(data: Option<&gst::PadProbeData<'_>>) -> bool {
    matches!(
        data,
        Some(gst::PadProbeData::Buffer(_)) | Some(gst::PadProbeData::BufferList(_))
    )
}

fn calculate_bandwidth_kbps(
    current_bytes: u64,
    previous_bytes: u64,
    elapsed: std::time::Duration,
) -> f64 {
    let elapsed_secs = elapsed.as_secs_f64();
    if elapsed_secs < 0.001 {
        return 0.0;
    }

    let delta_bits = current_bytes.saturating_sub(previous_bytes) as f64 * 8.0;
    delta_bits / elapsed_secs / 1000.0
}

fn release_client_sessions(
    pool: &gst_rtsp_server::RTSPSessionPool,
    sessions: &std::sync::Mutex<Vec<glib::WeakRef<gst_rtsp_server::RTSPSession>>>,
) -> usize {
    let tracked = match sessions.lock() {
        Ok(mut guard) => std::mem::take(&mut *guard),
        Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
    };
    let mut removed = 0;
    for weak in tracked {
        let Some(session) = weak.upgrade() else {
            continue;
        };
        // A graceful TEARDOWN may already have removed it.  That is the
        // expected idempotent path, not an error worth logging.
        if pool.remove(&session).is_ok() {
            removed += 1;
        }
    }
    removed
}

fn emit_media_fault(
    health: &Arc<RelayRuntimeHealth>,
    event_tx: &RelayEventSender,
    server_instance: u64,
    media_generation: u64,
    reason: String,
) {
    if let Some(event) = health.record_media_fault(
        server_instance,
        media_generation,
        RelayFaultKind::GstError,
        reason,
    ) {
        let _ = event_tx.send(RelaySupervisorEvent::Fault(event));
    }
}

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
    server_generation: u64,
    server_instance: u64,
    health: Arc<RelayRuntimeHealth>,
    shutdown_requested: Arc<AtomicBool>,
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
        self.shutdown_requested.store(true, Ordering::Release);
        self.main_loop.quit();
        log::info!("RTSP server main loop quit signalled");
    }
}

impl RtspRestreamer {
    fn configure_session_pool(
        server: &gst_rtsp_server::RTSPServer,
    ) -> Result<gst_rtsp_server::RTSPSessionPool, AppError> {
        let pool = server
            .session_pool()
            .ok_or_else(|| AppError::Stream("Failed to get RTSP session pool".into()))?;
        pool.set_max_sessions(MAX_RTSP_CLIENTS);
        log::info!(
            "RTSP client limit configured: {} sessions",
            MAX_RTSP_CLIENTS
        );
        Ok(pool)
    }

    fn attach_session_logging(
        server: &gst_rtsp_server::RTSPServer,
        pool: &gst_rtsp_server::RTSPSessionPool,
    ) {
        pool.connect_session_removed(|pool, _session| {
            log::debug!(
                "RTSP session removed: {}/{}",
                pool.n_sessions(),
                MAX_RTSP_CLIENTS
            );
        });

        let pool_for_clients = pool.clone();
        server.connect_client_connected(move |_server, client| {
            log::info!("RTSP client connected");
            let pool = pool_for_clients.clone();
            let sessions = Arc::new(std::sync::Mutex::new(Vec::<
                glib::WeakRef<gst_rtsp_server::RTSPSession>,
            >::new()));
            let sessions_for_new = sessions.clone();
            let pool_for_new = pool.clone();
            client.connect_new_session(move |_client, session| {
                if let Ok(mut tracked) = sessions_for_new.lock() {
                    tracked.push(session.downgrade());
                }
                log::debug!(
                    "RTSP session added: {}/{}",
                    pool_for_new.n_sessions(),
                    MAX_RTSP_CLIENTS
                );
            });

            client.connect_closed(move |_client| {
                let removed = release_client_sessions(&pool, &sessions);
                log::info!(
                    "RTSP client closed; released {} session(s), pool={}/{}",
                    removed,
                    pool.n_sessions(),
                    MAX_RTSP_CLIENTS
                );
            });
        });
    }

    /// Observe media lifecycle/errors and attach the payloader byte/heartbeat
    /// probe.  Every callback is generation checked and performs bounded
    /// in-memory work only.
    fn attach_media_observers(
        factory: &gst_rtsp_server::RTSPMediaFactory,
        bytes_sent: Arc<AtomicU64>,
        health: Arc<RelayRuntimeHealth>,
        event_tx: RelayEventSender,
        server_instance: u64,
        mount_path: String,
    ) {
        factory.connect_media_constructed(move |_factory, media| {
            let Some(media_generation) = health.media_constructed(
                server_instance,
                media.downgrade(),
                tokio::time::Instant::now(),
            ) else {
                return;
            };

            let health_for_messages = health.clone();
            let tx_for_messages = event_tx.clone();
            let mount_for_messages = mount_path.clone();
            media.connect_handle_message(None, move |_media, message| {
                let observed = match message.view() {
                    gst::MessageView::Error(error) => {
                        let raw = super::redact_relay_text(
                            &error.error().to_string(),
                            &mount_for_messages,
                        );
                        let debug = error
                            .debug()
                            .map(|d| super::redact_relay_text(&d, &mount_for_messages))
                            .unwrap_or_default();
                        let friendly = super::rtsp_client::friendly_rtsp_error(&raw, &debug);
                        let reason = super::redact_relay_text(&friendly, &mount_for_messages);
                        log::warn!("RTSP relay media error: {} | debug: {}", raw, debug);
                        health_for_messages.record_media_fault(
                            server_instance,
                            media_generation,
                            RelayFaultKind::GstError,
                            reason,
                        )
                    }
                    gst::MessageView::Eos(..) => health_for_messages.record_media_fault(
                        server_instance,
                        media_generation,
                        RelayFaultKind::Eos,
                        "RTSP relay media reached end of stream".into(),
                    ),
                    _ => None,
                };
                if let Some(event) = observed {
                    let _ = tx_for_messages.send(RelaySupervisorEvent::Fault(event));
                }
                // Pass-through intent: GstRTSPMedia's normal class handler
                // continues to process the message.
                false
            });

            let health_for_prepared = health.clone();
            media.connect_prepared(move |_media| {
                health_for_prepared.media_prepared(
                    server_instance,
                    media_generation,
                    tokio::time::Instant::now(),
                );
            });

            let health_for_target = health.clone();
            media.connect_target_state(move |_media, state| {
                use glib::translate::IntoGlib;
                health_for_target.media_target_state(
                    server_instance,
                    media_generation,
                    state == gst::State::Playing.into_glib(),
                    tokio::time::Instant::now(),
                );
            });

            let health_for_state = health.clone();
            media.connect_new_state(move |_media, state| {
                use glib::translate::IntoGlib;
                health_for_state.media_target_state(
                    server_instance,
                    media_generation,
                    state == gst::State::Playing.into_glib(),
                    tokio::time::Instant::now(),
                );
            });

            let health_for_unprepared = health.clone();
            media.connect_unprepared(move |_media| {
                health_for_unprepared.media_unprepared(server_instance, media_generation);
            });

            let element: gst::Element = media.element();
            let bin: gst::Bin = match element.downcast::<gst::Bin>() {
                Ok(b) => b,
                Err(_) => {
                    emit_media_fault(
                        &health,
                        &event_tx,
                        server_instance,
                        media_generation,
                        "RTSP relay media element is not a Bin".into(),
                    );
                    return;
                }
            };
            let pay0: gst::Element = match bin.by_name("pay0") {
                Some(e) => e,
                None => {
                    emit_media_fault(
                        &health,
                        &event_tx,
                        server_instance,
                        media_generation,
                        "RTSP relay payloader was not constructed".into(),
                    );
                    return;
                }
            };
            let pad: gst::Pad = match pay0.static_pad("src") {
                Some(p) => p,
                None => {
                    emit_media_fault(
                        &health,
                        &event_tx,
                        server_instance,
                        media_generation,
                        "RTSP relay payloader has no source pad".into(),
                    );
                    return;
                }
            };

            let bytes = bytes_sent.clone();
            let health_for_probe = health.clone();
            pad.add_probe(
                gst::PadProbeType::BUFFER | gst::PadProbeType::BUFFER_LIST,
                move |_pad, info| {
                    let observed_bytes = observed_probe_bytes(info.data.as_ref());
                    if observed_bytes != 0 {
                        bytes.fetch_add(observed_bytes, Ordering::Relaxed);
                    }
                    if observed_probe_arrival(info.data.as_ref()) {
                        health_for_probe.observe_buffer(
                            server_instance,
                            media_generation,
                            tokio::time::Instant::now(),
                        );
                    }
                    gst::PadProbeReturn::Ok
                },
            );
            log::info!(
                "RTSP relay media={} byte/heartbeat probe attached",
                media_generation
            );
        });
    }

    /// Create the server source, attach to a dedicated context, and spawn
    /// a background thread running a MainLoop on that context. Returns
    /// the loop plus the thread handle and a completion channel so
    /// `shutdown` can join with a bound.
    fn attach_and_run(
        server: &gst_rtsp_server::RTSPServer,
        pool: &gst_rtsp_server::RTSPSessionPool,
        health: Arc<RelayRuntimeHealth>,
        event_tx: RelayEventSender,
        server_instance: u64,
        shutdown_requested: Arc<AtomicBool>,
    ) -> Result<
        (
            glib::MainLoop,
            std::thread::JoinHandle<()>,
            tokio::sync::oneshot::Receiver<()>,
        ),
        RtspBuildFailure,
    > {
        // create_source gives us the real error (port in use, permission denied, etc.)
        let source = server.create_source(gio::Cancellable::NONE).map_err(|e| {
            RtspBuildFailure::bind(AppError::Stream(format!(
                "RTSP server socket failed: {}",
                e
            )))
        })?;
        let cleanup_source = pool.create_watch(
            Some("pocketstream-rtsp-session-cleanup"),
            glib::Priority::DEFAULT,
            |pool| {
                let removed = pool.cleanup();
                if removed != 0 {
                    log::debug!("RTSP server: cleaned up {} expired session(s)", removed);
                }
                glib::ControlFlow::Continue
            },
        );

        // Use a dedicated context so we don't conflict with GStreamer's
        // internal use of the default GLib main context.
        let ctx = glib::MainContext::new();
        source.attach(Some(&ctx));
        cleanup_source.attach(Some(&ctx));

        let main_loop = glib::MainLoop::new(Some(&ctx), false);
        let loop_clone = main_loop.clone();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let health_for_loop = health.clone();
        let tx_for_loop = event_tx.clone();
        let shutdown_for_loop = shutdown_requested.clone();

        let handle = std::thread::Builder::new()
            .name("rtsp-server-glib".into())
            .spawn(move || {
                health_for_loop.loop_started(server_instance);
                let _ = ready_tx.send(());
                let _ = ctx.with_thread_default(|| {
                    log::info!("RTSP server GLib main loop running (dedicated context)");
                    loop_clone.run();
                    log::info!("RTSP server GLib main loop exited");
                });
                if let Some(event) = health_for_loop.loop_exited(
                    server_instance,
                    shutdown_for_loop.load(Ordering::Acquire),
                    "RTSP relay GLib listener loop exited unexpectedly".into(),
                ) {
                    let _ = tx_for_loop.send(RelaySupervisorEvent::Fault(event));
                }
                let _ = done_tx.send(());
            })
            .map_err(|e| {
                RtspBuildFailure::configuration(AppError::Stream(format!(
                    "Failed to spawn RTSP server thread: {}",
                    e
                )))
            })?;

        if ready_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .is_err()
        {
            shutdown_requested.store(true, Ordering::Release);
            main_loop.quit();
            drop(handle);
            return Err(RtspBuildFailure::configuration(AppError::Stream(
                "RTSP server loop thread did not start within 1 second".into(),
            )));
        }

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
        self.shutdown_requested.store(true, Ordering::Release);
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
        runtime: RtspRuntimeContext,
    ) -> Result<Self, RtspBuildFailure> {
        let RtspRuntimeContext {
            health,
            event_tx,
            server_instance,
        } = runtime;
        // The media factory is lazy, so validate the required runtime policy
        // now.  Without this preflight, an old runtime would panic or fail only
        // after a downstream viewer connected.
        let policy_probe = gst::ElementFactory::make("rtspsrc").build().map_err(|e| {
            RtspBuildFailure::configuration(AppError::Stream(format!(
                "Failed to create rtspsrc for TCP policy validation: {}",
                e
            )))
        })?;
        super::configure_tcp_rtspsrc(&policy_probe).map_err(RtspBuildFailure::configuration)?;

        let server = gst_rtsp_server::RTSPServer::new();
        server.set_service(&port.to_string());
        if let Some(addr) = bind_address {
            server.set_address(addr);
        }
        let session_pool =
            Self::configure_session_pool(&server).map_err(RtspBuildFailure::configuration)?;
        Self::attach_session_logging(&server, &session_pool);

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
                    if let Err(error) = super::configure_tcp_rtspsrc(&src) {
                        // The identical element type passed preflight above;
                        // retain a diagnostic if the runtime changed under us,
                        // but never panic on this GLib callback.
                        log::error!("RTSP relay TCP receive policy failed: {}", error);
                        return;
                    }
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
        Self::attach_media_observers(
            &factory,
            bytes_sent.clone(),
            health.clone(),
            event_tx.clone(),
            server_instance,
            mount_path.to_string(),
        );

        let mounts = server.mount_points().ok_or_else(|| {
            RtspBuildFailure::configuration(AppError::Stream("Failed to get mount points".into()))
        })?;
        mounts.add_factory(mount_path, factory);

        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let (main_loop, loop_thread, loop_done_rx) = Self::attach_and_run(
            &server,
            &session_pool,
            health.clone(),
            event_tx,
            server_instance,
            shutdown_requested.clone(),
        )?;
        health.mark_listener_bound(server_instance);

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
            server_generation: health.server_generation(),
            server_instance,
            health,
            shutdown_requested,
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
        runtime: RtspRuntimeContext,
    ) -> Result<Self, RtspBuildFailure> {
        let RtspRuntimeContext {
            health,
            event_tx,
            server_instance,
        } = runtime;
        let server = gst_rtsp_server::RTSPServer::new();
        server.set_service(&server_port.to_string());
        if let Some(addr) = bind_address {
            server.set_address(addr);
        }
        let session_pool =
            Self::configure_session_pool(&server).map_err(RtspBuildFailure::configuration)?;
        Self::attach_session_logging(&server, &session_pool);

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
        Self::attach_media_observers(
            &factory,
            bytes_sent.clone(),
            health.clone(),
            event_tx.clone(),
            server_instance,
            mount_path.to_string(),
        );

        let mounts = server.mount_points().ok_or_else(|| {
            RtspBuildFailure::configuration(AppError::Stream("Failed to get mount points".into()))
        })?;
        mounts.add_factory(mount_path, factory);

        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let (main_loop, loop_thread, loop_done_rx) = Self::attach_and_run(
            &server,
            &session_pool,
            health.clone(),
            event_tx,
            server_instance,
            shutdown_requested.clone(),
        )?;
        health.mark_listener_bound(server_instance);

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
            server_generation: health.server_generation(),
            server_instance,
            health,
            shutdown_requested,
            port: server_port,
            mount_path: mount_path.into(),
            udp_ingest_port: Some(udp_port),
            bytes_sent,
            bw_prev: std::sync::Mutex::new((0, std::time::Instant::now())),
        })
    }

    /// Get the current throughput in kbps over the interval since the
    /// previous call.
    pub fn bandwidth_kbps(&self) -> f64 {
        let now = std::time::Instant::now();
        let bytes = self.bytes_sent.load(Ordering::Relaxed);
        let mut prev = self.bw_prev.lock().unwrap_or_else(|p| p.into_inner());
        let (prev_bytes, prev_time) = *prev;
        let elapsed = now.duration_since(prev_time);
        *prev = (bytes, now);
        calculate_bandwidth_kbps(bytes, prev_bytes, elapsed)
    }

    /// Number of live RTSP sessions currently occupying client slots.
    pub fn connected_clients(&self) -> u32 {
        self.server
            .session_pool()
            .map(|pool| pool.n_sessions())
            .unwrap_or(0)
    }

    /// Maximum number of concurrent RTSP sessions accepted by this server.
    pub fn client_limit(&self) -> u32 {
        MAX_RTSP_CLIENTS
    }

    pub fn server_generation(&self) -> u64 {
        self.server_generation
    }

    pub fn loop_alive(&self) -> bool {
        self.health.loop_alive_for(self.server_instance)
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
    use super::*;

    fn init_gstreamer() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| gst::init().expect("GStreamer test initialization failed"));
    }

    fn restreamer_fixture(server: gst_rtsp_server::RTSPServer) -> RtspRestreamer {
        let context = glib::MainContext::new();
        let health = Arc::new(RelayRuntimeHealth::new(
            1,
            super::super::relay::RelayIngestKind::Rtsp,
        ));
        let server_instance = health.begin_server_instance(false);
        health.loop_started(server_instance);
        health.mark_listener_bound(server_instance);
        RtspRestreamer {
            server,
            main_loop: glib::MainLoop::new(Some(&context), false),
            loop_thread: None,
            loop_done_rx: None,
            server_generation: 1,
            server_instance,
            health,
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            port: 8554,
            mount_path: "/test".into(),
            udp_ingest_port: None,
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bw_prev: std::sync::Mutex::new((0, std::time::Instant::now())),
        }
    }

    #[test]
    fn mount_path_token_is_redacted() {
        assert_eq!(redact_mount_path("/stream-s3cr3ttoken"), "/stream-***");
    }

    #[test]
    fn non_token_paths_pass_through() {
        assert_eq!(redact_mount_path("/live"), "/live");
    }

    #[test]
    fn probe_byte_count_handles_buffers_lists_and_other_data() {
        init_gstreamer();

        let buffer_data = gst::PadProbeData::Buffer(gst::Buffer::with_size(256).unwrap());
        assert_eq!(observed_probe_bytes(Some(&buffer_data)), 256);
        assert!(observed_probe_arrival(Some(&buffer_data)));

        let mut list = gst::BufferList::new();
        {
            let list = list.get_mut().unwrap();
            list.add(gst::Buffer::with_size(100).unwrap());
            list.add(gst::Buffer::with_size(200).unwrap());
            list.add(gst::Buffer::with_size(300).unwrap());
        }
        let list_data = gst::PadProbeData::BufferList(list);
        assert_eq!(observed_probe_bytes(Some(&list_data)), 600);
        assert!(observed_probe_arrival(Some(&list_data)));

        let empty_list_data = gst::PadProbeData::BufferList(gst::BufferList::new());
        assert_eq!(observed_probe_bytes(Some(&empty_list_data)), 0);
        assert!(observed_probe_arrival(Some(&empty_list_data)));

        let event_data = gst::PadProbeData::Event(gst::event::Eos::new());
        assert_eq!(observed_probe_bytes(Some(&event_data)), 0);
        assert!(!observed_probe_arrival(Some(&event_data)));
        assert_eq!(observed_probe_bytes(None), 0);
        assert!(!observed_probe_arrival(None));
    }

    #[test]
    fn client_close_releases_sessions_and_graceful_teardown_is_idempotent() {
        init_gstreamer();
        let pool = gst_rtsp_server::RTSPSessionPool::new();
        let graceful = pool.create().unwrap();
        let ungraceful = pool.create().unwrap();
        let tracked = std::sync::Mutex::new(vec![graceful.downgrade(), ungraceful.downgrade()]);

        // TEARDOWN beat the client's closed signal for the first session.
        pool.remove(&graceful).unwrap();
        assert_eq!(pool.n_sessions(), 1);
        assert_eq!(release_client_sessions(&pool, &tracked), 1);
        assert_eq!(pool.n_sessions(), 0);
        assert_eq!(release_client_sessions(&pool, &tracked), 0);
    }

    #[test]
    fn bandwidth_rate_handles_normal_zero_and_rollback_samples() {
        assert_eq!(
            calculate_bandwidth_kbps(32_000, 0, std::time::Duration::from_secs(1)),
            256.0
        );
        assert_eq!(
            calculate_bandwidth_kbps(10_000, 10_000, std::time::Duration::from_secs(1)),
            0.0
        );
        assert_eq!(
            calculate_bandwidth_kbps(5_000, 10_000, std::time::Duration::from_secs(1)),
            0.0
        );
    }

    #[tokio::test]
    async fn session_pool_limit_slot_reuse_and_status_count() {
        init_gstreamer();
        assert_eq!(MAX_RTSP_CLIENTS, 10);

        let server = gst_rtsp_server::RTSPServer::new();
        let pool = RtspRestreamer::configure_session_pool(&server).unwrap();
        assert_eq!(pool.max_sessions(), MAX_RTSP_CLIENTS);

        let sessions: Vec<_> = (0..MAX_RTSP_CLIENTS)
            .map(|_| pool.create().expect("session within configured capacity"))
            .collect();
        assert_eq!(pool.n_sessions(), MAX_RTSP_CLIENTS);
        assert!(pool.create().is_err());

        pool.remove(&sessions[0]).unwrap();
        assert_eq!(pool.n_sessions(), MAX_RTSP_CLIENTS - 1);
        let _replacement = pool.create().expect("released slot should be reusable");
        assert_eq!(pool.n_sessions(), MAX_RTSP_CLIENTS);

        let restreamer = restreamer_fixture(server);
        assert_eq!(restreamer.connected_clients(), MAX_RTSP_CLIENTS);
        assert_eq!(restreamer.client_limit(), MAX_RTSP_CLIENTS);
        let health = restreamer.health.clone();

        let manager = super::super::StreamManager::new();
        {
            let mut state = manager.state.lock().await;
            state.rtsp_server = Some(restreamer);
            state.rtsp_desired = true;
            state.rtsp_spec = Some(super::super::ResolvedRtspStartSpec {
                source: super::super::ResolvedSource::Rtsp {
                    url: "rtsp://192.0.2.1/live".into(),
                },
                server_port: 8554,
                mount_path: "/test".into(),
                bind_interface: None,
                bind_address: None,
                advertised_ip: "127.0.0.1".into(),
                username: String::new(),
                password: String::new(),
            });
            state.rtsp_health = Some(health);
            state.rtsp_intent_epoch = Some(0);
            state.rtsp_start_time = Some(std::time::Instant::now());
        }
        let status = super::super::compute_status(&manager.state).await;
        assert!(status.rtsp_server_running);
        assert_eq!(status.rtsp_connected_clients, MAX_RTSP_CLIENTS);
        assert_eq!(status.rtsp_client_limit, MAX_RTSP_CLIENTS);
    }
}
