//! Playback/recording state, lifecycle and supervisor. No relay mutation authority.
use super::*;

/// What a running consumer is ingesting, captured at start time. The
/// double-bind guard compares "what's running" against "what's being
/// started" using this — re-deriving it from settings would be wrong,
/// since settings can change between the two starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SourceMode {
    Udp { port: u16 },
    Rtsp,
}

#[derive(Default)]
pub(super) struct PlaybackData {
    pub(super) playback_target: Option<CameraTarget>,
    pub(super) playback_settings: Option<AppSettings>,
    pub(super) playback_health: Option<Arc<PlaybackHealth>>,
    pub(super) playback_intent_epoch: Option<u64>,
    pub(super) playback_instance: Option<(u64, u64)>,
    pub(super) playback_window: Option<usize>,
    pub(super) playback_adapter: Option<(Option<String>, Option<u32>)>,
    pub(super) playback_ready: Option<(u32, std::net::Ipv4Addr)>,
    pub(super) recording_report: Option<String>,
    pub(super) recording_finalized_path: Option<String>,
    pub(super) playback: Option<Arc<PlaybackPipeline>>,
    pub(super) recording: bool,
    pub(super) recording_path: Option<String>,
    pub(super) start_time: Option<std::time::Instant>,
    pub(super) playback_source: Option<SourceMode>,
}

pub(super) struct PlaybackService {
    pub(super) state: state::PlaybackSlot,
    status: status::StatusPublisher,
    surface: Arc<video_surface::VideoSurface>,
    pub(super) playback_epoch: Arc<std::sync::atomic::AtomicU64>,
    pub(super) playback_lifecycle: Arc<Mutex<()>>,
    pub(super) playback_wake: Arc<Notify>,
    pub(super) playback_diagnostic: PlaybackDiagnostic,
}
impl PlaybackService {
    pub(super) fn new(
        state: state::PlaybackSlot,
        status: status::StatusPublisher,
        surface: Arc<video_surface::VideoSurface>,
    ) -> Self {
        Self {
            state,
            status,
            surface,
            playback_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            playback_lifecycle: Arc::new(Mutex::new(())),
            playback_wake: Arc::new(Notify::new()),
            playback_diagnostic: Arc::new(std::sync::Mutex::new(None)),
        }
    }
    pub(super) fn context(
        &self,
        readiness: Option<Arc<crate::network::readiness::CameraReadiness>>,
    ) -> PlaybackSupervisorContext {
        PlaybackSupervisorContext {
            state: self.state.clone(),
            status: self.status.clone(),
            epoch: self.playback_epoch.clone(),
            lifecycle: self.playback_lifecycle.clone(),
            wake: self.playback_wake.clone(),
            diagnostic: self.playback_diagnostic.clone(),
            selection: readiness.as_ref().map(|r| r.subscribe()),
            readiness,
        }
    }
    async fn refresh_status(&self) {
        self.status.refresh().await;
    }
    /// Establish intent; the supervisor owns every connect/retry/teardown.
    /// Reasserting identical intent never replaces a starting/healthy pipeline.
    pub async fn start_playback(
        &self,
        settings: &AppSettings,
        window_handle: Option<usize>,
    ) -> Result<(), AppError> {
        let start_epoch = self
            .playback_epoch
            .load(std::sync::atomic::Ordering::Acquire);
        build_input_url(settings)?;
        crate::ensure_gstreamer()?;
        let mut state = self
            .state
            .lock_for_start(
                (settings.stream.protocol == StreamProtocol::Udp)
                    .then_some(settings.stream.udp_port),
            )
            .await?;
        if state
            .playback_settings
            .as_ref()
            .is_some_and(|s| same_playback_source(s, settings))
        {
            drop(state);
            self.playback_wake.notify_one();
            return Ok(());
        }
        if self
            .playback_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != start_epoch
        {
            return Err(AppError::Stream("Playback start superseded by Stop".into()));
        }
        let epoch = start_epoch.wrapping_add(1);
        self.playback_epoch
            .compare_exchange(
                start_epoch,
                epoch,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map_err(|_| AppError::Stream("Playback start superseded by Stop".into()))?;
        if let Some(old) = &state.playback_health {
            old.stop();
        }
        cancel_playback_diagnostic(&self.playback_diagnostic);
        state.playback_settings = Some(settings.clone());
        state.playback_health = Some(Arc::new(PlaybackHealth::new()));
        state.playback_intent_epoch = Some(epoch);
        state.playback_target = stream_target(settings);
        state.playback_window = window_handle.or_else(|| self.surface.hwnd().map(|h| h as usize));
        state.playback_adapter = None;
        state.playback_ready = None;
        state.playback_source = Some(match settings.stream.protocol {
            StreamProtocol::Udp => SourceMode::Udp {
                port: settings.stream.udp_port,
            },
            StreamProtocol::Rtsp => SourceMode::Rtsp,
        });
        drop(state);
        self.playback_wake.notify_one();
        self.refresh_status().await;
        Ok(())
    }

    pub async fn retry_playback(
        &self,
        manual: bool,
        settings: Option<AppSettings>,
    ) -> Result<(), AppError> {
        let requested_epoch = self
            .playback_epoch
            .load(std::sync::atomic::Ordering::Acquire);
        let mut state = self.state.lock().await;
        if self
            .playback_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != requested_epoch
        {
            return Err(AppError::Stream("Playback Retry superseded by Stop".into()));
        }
        // Manual Retry may apply corrected credentials/path, while the intended
        // camera key, endpoint and expected MAC remain owned by this playback.
        if manual {
            if let (Some(current), Some(mut desired)) = (settings, state.playback_settings.clone())
            {
                desired.credentials = current.credentials;
                if desired.stream.protocol == StreamProtocol::Rtsp {
                    desired.stream.rtsp_path = current.stream.rtsp_path;
                    desired.stream.rtsp_port = current.stream.rtsp_port;
                }
                if !same_playback_source(state.playback_settings.as_ref().unwrap(), &desired) {
                    let epoch = requested_epoch.wrapping_add(1);
                    self.playback_epoch
                        .compare_exchange(
                            requested_epoch,
                            epoch,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        )
                        .map_err(|_| {
                            AppError::Stream("Playback Retry superseded by Stop".into())
                        })?;
                    if let Some(old) = &state.playback_health {
                        old.stop();
                    }
                    cancel_playback_diagnostic(&self.playback_diagnostic);
                    state.playback_health = Some(Arc::new(PlaybackHealth::new()));
                    state.playback_settings = Some(desired);
                    state.playback_intent_epoch = Some(epoch);
                }
            }
        }
        let health = state
            .playback_health
            .as_ref()
            .ok_or_else(|| AppError::Stream("No desired playback to retry".into()))?;
        if manual {
            health.retry();
        } else {
            health.wake_ready();
        }
        drop(state);
        self.playback_wake.notify_one();
        self.refresh_status().await;
        Ok(())
    }

    pub async fn stop_playback(&self) -> Result<(), AppError> {
        let stop_epoch = self
            .playback_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .wrapping_add(1);
        self.playback_wake.notify_waiters();
        cancel_playback_diagnostic(&self.playback_diagnostic);
        {
            let mut state = self.state.lock().await;
            if state
                .playback_intent_epoch
                .is_none_or(|intent| intent < stop_epoch)
            {
                if let Some(health) = state.playback_health.take() {
                    health.stop();
                }
                state.playback_settings = None;
                state.playback_intent_epoch = None;
                state.playback_target = None;
                state.playback_adapter = None;
                state.playback_ready = None;
            }
        }
        let _lifecycle = self.playback_lifecycle.lock().await;
        let old_pipeline = self
            .state
            .lock()
            .await
            .playback_instance
            .is_none_or(|(epoch, _)| epoch < stop_epoch);
        if old_pipeline {
            retire_playback(&self.state, false).await;
        }
        let mut state = self.state.lock().await;
        if state.playback_settings.is_none() {
            state.playback_source = None;
        }
        drop(state);
        self.refresh_status().await;
        Ok(())
    }

    pub async fn take_screenshot(&self) -> Result<String, AppError> {
        let pipeline = {
            let state = self.state.lock().await;
            state
                .playback
                .as_ref()
                .ok_or_else(|| AppError::Stream("No active playback for screenshot".into()))?
                .clone()
        };

        let output_dir = dirs::picture_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("PocketStream");

        // pull_snapshot blocks up to 500ms on try_pull_sample and the
        // JPEG encode is CPU-bound — run both off the async worker.
        let path = tokio::task::spawn_blocking(move || {
            let (width, height, rgb_data) = pipeline.pull_snapshot()?;
            recorder::save_screenshot_jpg(&rgb_data, width, height, &output_dir)
        })
        .await
        .map_err(|e| AppError::Stream(format!("Screenshot task failed: {}", e)))??;

        Ok(path.to_string_lossy().to_string())
    }

    pub async fn start_recording(&self) -> Result<(), AppError> {
        let _lifecycle = self.playback_lifecycle.lock().await;
        // Path computation involves filesystem I/O — keep it outside
        // the lock. When the Videos folder is unavailable, fall back to
        // the per-user local-data dir — NOT the process CWD, which on an
        // installed build is Program Files and unwritable.
        let output_dir = dirs::video_dir()
            .unwrap_or_else(|| {
                let fallback = dirs::data_local_dir().unwrap_or_else(std::env::temp_dir);
                log::warn!(
                    "Videos directory unavailable; recording under {}",
                    fallback.display()
                );
                fallback
            })
            .join("PocketStream");

        // Pre-flight the recording volume: a disk that fills mid-write
        // surfaces as an opaque GStreamer bus error that reads like a
        // network failure, so refuse to start below a floor instead. A
        // failed probe fails open — it must not block recording.
        if let Some(free) = recorder::free_space_bytes(&output_dir) {
            if !recorder::recording_space_ok(free) {
                return Err(AppError::Stream(format!(
                    "Not enough disk space to record — {} MB free, {} MB required",
                    free / (1024 * 1024),
                    recorder::RECORDING_MIN_FREE_BYTES / (1024 * 1024)
                )));
            }
        } else {
            log::warn!(
                "Could not determine free space for {}; starting recording anyway",
                output_dir.display()
            );
        }

        let path = recorder::recording_path(&output_dir)?;
        let path_str = path.to_string_lossy().to_string();

        // Reserve the recording slot under the lock so a concurrent
        // start errors out instead of double-attaching; roll back on
        // attach failure below.
        let pipeline = {
            let mut state = self.state.lock().await;

            if state.recording {
                return Err(AppError::Stream("Already recording".into()));
            }
            if !state
                .playback_health
                .as_ref()
                .is_some_and(|h| h.snapshot().state == PlaybackState::Playing)
            {
                return Err(AppError::Stream(
                    "Playback has no usable frames to record".into(),
                ));
            }
            state.recording_report = None;
            state.recording_finalized_path = None;

            let pipeline = state
                .playback
                .as_ref()
                .ok_or_else(|| AppError::Stream("No active playback to record".into()))?
                .clone();

            state.recording = true;
            state.recording_path = Some(path_str.clone());
            pipeline
        };

        // GStreamer pad request/link/state ops outside the lock — the
        // one lock discipline for StreamManager (stop_playback is the
        // model).
        if let Err(e) = pipeline.attach_recording(&path_str) {
            let mut state = self.state.lock().await;
            state.recording = false;
            state.recording_path = None;
            drop(state);
            self.refresh_status().await;
            return Err(e);
        }

        self.refresh_status().await;
        Ok(())
    }

    pub async fn stop_recording(&self) -> Result<String, AppError> {
        let _lifecycle = self.playback_lifecycle.lock().await;
        // Snapshot under the lock but do NOT clear the recording state
        // yet: a failed detach used to leave recording=false with the
        // path gone — status lied and the path only lived in the log.
        // State is cleared only after the finalize succeeds.
        let (pipeline, path) = {
            let state = self.state.lock().await;

            if !state.recording {
                return Err(AppError::Stream("Not currently recording".into()));
            }

            let pipeline = state
                .playback
                .as_ref()
                .ok_or_else(|| AppError::Stream("No active playback".into()))?
                .clone();

            let path = state
                .recording_path
                .clone()
                .unwrap_or_else(|| "unknown".into());
            (pipeline, path)
        };

        if let Err(e) = pipeline.detach_recording().await {
            return Err(AppError::Stream(format!(
                "Failed to finalize recording {}: {}",
                path, e
            )));
        }

        {
            let mut state = self.state.lock().await;
            state.recording = false;
            state.recording_path = None;
        }

        log::info!("Recording saved: {}", path);
        self.refresh_status().await;
        Ok(path)
    }

    /// Apply the mute preference to live playback, if any. Persistence
    /// happens in the command layer; with no pipeline this is a no-op —
    /// the next start seeds the preference from config. Clone the
    /// pipeline Arc out under the lock, poke GStreamer outside it (the
    /// one lock discipline for StreamManager).
    pub async fn set_audio_muted(&self, muted: bool) {
        let pipeline = {
            let mut state = self.state.lock().await;
            if let Some(settings) = &mut state.playback_settings {
                settings.stream.audio_muted = muted;
            }
            state.playback.clone()
        };
        if let Some(p) = pipeline {
            p.set_audio_muted(muted);
        }
    }
}

#[derive(Clone)]
pub(super) struct PlaybackSupervisorContext {
    pub(super) state: state::PlaybackSlot,
    pub(super) status: status::StatusPublisher,
    pub(super) epoch: Arc<std::sync::atomic::AtomicU64>,
    pub(super) lifecycle: Arc<Mutex<()>>,
    pub(super) wake: Arc<Notify>,
    pub(super) diagnostic: PlaybackDiagnostic,
    pub(super) readiness: Option<Arc<crate::network::readiness::CameraReadiness>>,
    pub(super) selection: Option<watch::Receiver<crate::network::AdapterSelection>>,
}

type PlaybackDiagnostic = Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>;

pub(super) fn cancel_playback_diagnostic(slot: &PlaybackDiagnostic) {
    if let Some(task) = slot.lock().unwrap_or_else(|p| p.into_inner()).take() {
        task.abort();
    }
}

pub(super) fn same_playback_source(a: &AppSettings, b: &AppSettings) -> bool {
    a.stream.protocol == b.stream.protocol
        && a.stream.camera_ip == b.stream.camera_ip
        && a.stream.camera_mac == b.stream.camera_mac
        && a.stream.rtsp_port == b.stream.rtsp_port
        && a.stream.rtsp_path == b.stream.rtsp_path
        && a.stream.udp_port == b.stream.udp_port
        && a.credentials.username == b.credentials.username
        && a.credentials.password == b.credentials.password
}

pub(super) async fn playback_is_current(
    ctx: &PlaybackSupervisorContext,
    epoch: u64,
    health: &Arc<PlaybackHealth>,
) -> bool {
    let s = ctx.state.lock().await;
    ctx.epoch.load(std::sync::atomic::Ordering::Acquire) == epoch
        && s.playback_intent_epoch == Some(epoch)
        && s.playback_health
            .as_ref()
            .is_some_and(|h| Arc::ptr_eq(h, health))
        && s.playback_settings.is_some()
}

/// Caller holds the lifecycle gate. Recording never follows a replacement.
pub(super) async fn retire_playback(state: &state::PlaybackSlot, lost: bool) {
    let (pipeline, recording, path) = {
        let mut s = state.lock().await;
        let recording = std::mem::take(&mut s.recording);
        let path = s.recording_path.take();
        s.playback_instance = None;
        s.start_time = None;
        (s.playback.take(), recording, path)
    };
    let finalized = if recording {
        match &pipeline {
            Some(p) => p.detach_recording().await,
            None => Err(AppError::Stream("Recording pipeline unavailable".into())),
        }
    } else {
        Ok(())
    };
    if let Some(p) = pipeline {
        if let Err(e) = p.stop() {
            log::warn!("Playback teardown: {}", redact_url(&e.to_string()));
        }
    }
    if recording {
        let mut s = state.lock().await;
        let reason = if lost {
            "recording stopped: stream lost"
        } else {
            "recording stopped"
        };
        s.recording_report = Some(match finalized {
            Ok(_) => reason.into(),
            Err(e) => format!(
                "{reason}; finalize incomplete: {}",
                redact_url(&e.to_string())
            ),
        });
        s.recording_finalized_path = path;
    }
}

pub(super) async fn publish_playback_status(ctx: &PlaybackSupervisorContext) {
    ctx.status.refresh().await;
}

pub(super) async fn expected_device_wake(
    app: Option<&Arc<crate::network::readiness::CameraReadiness>>,
) {
    if let Some(app) = app {
        app.verified().await;
    } else {
        std::future::pending::<()>().await;
    }
}

pub(super) async fn selection_wake(
    rx: &mut Option<watch::Receiver<crate::network::AdapterSelection>>,
) {
    if let Some(receiver) = rx {
        if receiver.changed().await.is_ok() {
            receiver.borrow_and_update();
            return;
        }
        *rx = None;
    }
    std::future::pending::<()>().await;
}

pub(super) async fn run_playback_supervisor(mut ctx: PlaybackSupervisorContext) {
    if let Some(rx) = &mut ctx.selection {
        rx.borrow_and_update();
    }
    let mut logged = None;
    let mut recovery_started = None;
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tick.tick() => {},
            _ = selection_wake(&mut ctx.selection) => {},
            _ = wait_playback_ready(&ctx.wake, expected_device_wake(ctx.readiness.as_ref())) => {},
        }
        playback_step(&ctx).await;
        {
            let s = ctx.state.lock().await;
            if let Some(health) = &s.playback_health {
                let snapshot = health.snapshot();
                let cause = snapshot.fault.as_ref().map(|fault| fault.kind);
                let key = (
                    s.playback_intent_epoch,
                    snapshot.state,
                    snapshot.attempt,
                    cause,
                );
                if logged != Some(key) {
                    if logged.as_ref().is_some_and(
                        |old: &(Option<u64>, PlaybackState, u32, Option<PlaybackFaultKind>)| {
                            old.0 != key.0
                        },
                    ) {
                        recovery_started = None;
                    }
                    if matches!(
                        snapshot.state,
                        PlaybackState::Recovering | PlaybackState::Failed
                    ) {
                        recovery_started.get_or_insert_with(tokio::time::Instant::now);
                    }
                    let duration = recovery_started.map_or(0, |at| at.elapsed().as_millis());
                    let (mac, index) = s
                        .playback_adapter
                        .as_ref()
                        .map(|(m, i)| (m.as_deref().unwrap_or("unknown"), i.unwrap_or(0)))
                        .unwrap_or(("unknown", 0));
                    log::info!("event=playback_recovery adapter_mac={} interface_index={} state={} cause={} attempt={} duration_ms={}",
                        crate::network::log_value(mac), index, serde_json::to_string(&snapshot.state).unwrap(),
                        serde_json::to_string(&cause).unwrap(), snapshot.attempt, duration);
                    if matches!(
                        snapshot.state,
                        PlaybackState::Playing | PlaybackState::Stopped
                    ) {
                        recovery_started = None;
                    }
                    logged = Some(key);
                }
            }
        }
        publish_playback_status(&ctx).await;
    }
}

pub(super) async fn wait_playback_ready(
    wake: &Notify,
    verified: impl std::future::Future<Output = ()>,
) {
    tokio::select! { _ = wake.notified() => {}, _ = verified => {} }
}

pub(super) fn update_playback_readiness(
    previous: &mut Option<(u32, std::net::Ipv4Addr)>,
    next: Option<(u32, std::net::Ipv4Addr)>,
    health: &PlaybackHealth,
) -> bool {
    let changed = next.is_some() && *previous != next;
    *previous = next;
    if changed {
        health.wake_ready();
    }
    changed
}

pub(super) async fn playback_step(ctx: &PlaybackSupervisorContext) {
    use std::sync::atomic::Ordering;
    let _lifecycle = ctx.lifecycle.lock().await;
    let (mut epoch, health, settings, target, window) = {
        let s = ctx.state.lock().await;
        let (Some(epoch), Some(health), Some(settings)) = (
            s.playback_intent_epoch,
            s.playback_health.clone(),
            s.playback_settings.clone(),
        ) else {
            return;
        };
        (
            epoch,
            health,
            settings,
            s.playback_target.clone(),
            s.playback_window,
        )
    };
    if !playback_is_current(ctx, epoch, &health).await {
        return;
    }
    // Selected identity/index changes cancel prior work even if a replacement
    // adapter already has a usable route. No old-incarnation buffer is accepted.
    if target.is_some() {
        if let Some(app) = &ctx.readiness {
            let selection = app.selection().await;
            let identity = (selection.selected_mac, selection.interface_index);
            let mut s = ctx.state.lock().await;
            if ctx.epoch.load(Ordering::Acquire) != epoch || s.playback_intent_epoch != Some(epoch)
            {
                return;
            }
            if s.playback_adapter
                .as_ref()
                .is_some_and(|old| old != &identity)
            {
                let next = epoch.wrapping_add(1);
                if ctx
                    .epoch
                    .compare_exchange(epoch, next, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    return;
                }
                epoch = next;
                s.playback_intent_epoch = Some(epoch);
                cancel_playback_diagnostic(&ctx.diagnostic);
                let generation = health.snapshot().generation;
                health.record_fault(
                    generation,
                    PlaybackFault::new(
                        PlaybackFaultKind::DeviceLoss,
                        "Selected Ethernet adapter changed",
                        true,
                    ),
                );
            }
            s.playback_adapter = Some(identity);
        }
    }
    let pipeline = ctx.state.lock().await.playback.clone();
    if target.is_some() && health.snapshot().state != PlaybackState::Failed {
        // Recheck readiness on wake/tick, including a legacy manual target's
        // first learned identity. Repeated successful verification is not a
        // transition and cannot collapse transport backoff to the 5 s cadence.
        let checked = preflight_target(ctx.readiness.as_ref(), target.as_ref()).await;
        if !playback_is_current(ctx, epoch, &health).await {
            return;
        }
        let next = checked
            .as_ref()
            .ok()
            .and_then(|p| p.as_ref())
            .map(|p| (p.index, p.source));
        let mut s = ctx.state.lock().await;
        let previous = s.playback_ready;
        let changed = update_playback_readiness(&mut s.playback_ready, next, &health);
        drop(s);
        if let Err(e) = checked {
            if pipeline.is_some() {
                health.record_fault(
                    health.snapshot().generation,
                    PlaybackFault::new(PlaybackFaultKind::DeviceLoss, e.to_string(), true),
                );
            }
        } else if changed && previous.is_some() && pipeline.is_some() {
            health.record_fault(
                health.snapshot().generation,
                PlaybackFault::new(
                    PlaybackFaultKind::DeviceLoss,
                    "Selected Ethernet source address changed",
                    true,
                ),
            );
        }
    }
    if let Some(p) = &pipeline {
        if let Err(fault) = p.health_check() {
            if fault.kind == PlaybackFaultKind::FrameStall {
                if let Some(target) = &target {
                    let mut slot = ctx.diagnostic.lock().unwrap_or_else(|p| p.into_inner());
                    if ctx.epoch.load(Ordering::Acquire) == epoch {
                        if let Some(old) = slot.take() {
                            old.abort();
                        }
                        let ip = target.ip.clone();
                        let authority = ctx.epoch.clone();
                        let readiness = ctx.readiness.clone();
                        *slot = Some(tokio::spawn(async move {
                            // Preserve the existing bound diagnostic. It never
                            // changes presence, readiness or retry policy.
                            let reachable = match readiness {
                                Some(readiness) => readiness.diagnostic_probe(&ip).await,
                                None => false,
                            };
                            if authority.load(Ordering::Acquire) == epoch {
                                log::info!("Playback stall diagnostic ip={ip} icmp={reachable}");
                            }
                        }));
                    }
                }
            }
        }
    }
    let snap = health.snapshot();
    let instance = ctx.state.lock().await.playback_instance;
    if pipeline.is_some() && (instance != Some((epoch, snap.generation)) || !snap.active) {
        retire_playback(&ctx.state, true).await;
        if !playback_is_current(ctx, epoch, &health).await {
            return;
        }
    }
    if snap.state == PlaybackState::Failed {
        return;
    }
    if !snap.active && snap.next_retry_secs.is_none() {
        health.schedule_recovery();
    }
    if !health.due(tokio::time::Instant::now()) {
        return;
    }
    let generation = health.begin_attempt();
    log::debug!(
        "event=playback_attempt generation={} attempt={}",
        generation,
        health.snapshot().attempt
    );
    let path = match preflight_target(ctx.readiness.as_ref(), target.as_ref()).await {
        Ok(path) => path,
        Err(e) => {
            health.record_fault(
                generation,
                PlaybackFault::new(PlaybackFaultKind::DeviceLoss, e.to_string(), true),
            );
            health.schedule_recovery();
            return;
        }
    };
    if !playback_is_current(ctx, epoch, &health).await {
        return;
    }
    let built = match settings.stream.protocol {
        StreamProtocol::Udp => {
            PlaybackPipeline::new_udp(settings.stream.udp_port, window, health.clone(), generation)
        }
        StreamProtocol::Rtsp => build_input_url(&settings).and_then(|url| {
            let mut pipeline = PlaybackPipeline::new_rtsp(
                &url,
                500,
                true,
                window,
                health.clone(),
                generation,
                &settings.credentials.username,
                &settings.credentials.password,
                settings.stream.audio_muted,
            )?;
            let camera = path
                .as_ref()
                .map(|p| p.target.clone())
                .ok_or_else(|| AppError::Stream("Camera Ethernet path unavailable".into()))?;
            let handle = ctx.readiness.clone();
            let current_epoch = ctx.epoch.clone();
            pipeline.bind_rtsp_transport(
                &url,
                Arc::new(move || {
                    if current_epoch.load(Ordering::Acquire) != epoch {
                        return Err(AppError::Stream("Playback connection superseded".into()));
                    }
                    camera_stream_path(handle.as_ref(), &camera)
                }),
            )?;
            Ok(pipeline)
        }),
    };
    let p = match built {
        Ok(p) => p,
        Err(e) => {
            health.record_fault(
                generation,
                PlaybackFault::new(
                    PlaybackFaultKind::Configuration,
                    redact_url(&e.to_string()),
                    false,
                ),
            );
            return;
        }
    };
    // Recheck after construction and immediately before any connection.
    let final_path = preflight_target(
        ctx.readiness.as_ref(),
        path.as_ref().map(|p| &p.target).or(target.as_ref()),
    )
    .await;
    if !playback_is_current(ctx, epoch, &health).await
        || path.as_ref().is_some_and(|p| p.fence.is_stale())
    {
        health.record_fault(
            generation,
            PlaybackFault::new(
                PlaybackFaultKind::DeviceLoss,
                "Ethernet session changed during playback build",
                true,
            ),
        );
        health.schedule_recovery();
        let _ = p.stop();
        return;
    }
    if let Err(e) = final_path {
        health.record_fault(
            generation,
            PlaybackFault::new(PlaybackFaultKind::DeviceLoss, e.to_string(), true),
        );
        let _ = p.stop();
        health.schedule_recovery();
        return;
    }
    if let Err(e) = p.play() {
        // A synchronous state failure may already have delivered a typed bus
        // fault. First-fault authority preserves that instead of replacing it.
        health.record_fault(
            generation,
            PlaybackFault::new(PlaybackFaultKind::Configuration, e.to_string(), false),
        );
    }
    let mut s = ctx.state.lock().await;
    if ctx.epoch.load(Ordering::Acquire) != epoch
        || s.playback_intent_epoch != Some(epoch)
        || path.as_ref().is_some_and(|p| p.fence.is_stale())
    {
        drop(s);
        health.record_fault(
            generation,
            PlaybackFault::new(
                PlaybackFaultKind::DeviceLoss,
                "Ethernet session changed during playback start",
                true,
            ),
        );
        health.schedule_recovery();
        let _ = p.stop();
        return;
    }
    if let Some(path) = path {
        s.playback_target = Some(path.target);
    }
    s.playback = Some(Arc::new(p));
    s.playback_instance = Some((epoch, generation));
    s.start_time = Some(std::time::Instant::now());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::tests::{init_gstreamer, seed_desired_relay};

    #[test]
    fn playback_construction_does_not_require_a_runtime() {
        assert!(tokio::runtime::Handle::try_current().is_err());
        let manager = StreamManager::new();
        assert!(manager
            .playback
            .playback_diagnostic
            .lock()
            .unwrap()
            .is_none());
        assert!(tokio::runtime::Handle::try_current().is_err());
    }

    #[tokio::test]
    async fn failed_recording_finalize_keeps_path_until_owned_retirement_reports_it() {
        init_gstreamer();
        let manager = StreamManager::new();
        let health = seed_playback(&manager).await;
        let generation = health.begin_attempt();
        {
            let mut state = manager.playback.state.lock().await;
            state.playback = Some(Arc::new(PlaybackPipeline::test_headless(
                health, generation,
            )));
            state.playback_instance = Some((0, generation));
            state.recording = true;
            state.recording_path = Some("retained.mp4".into());
        }
        // No recording branch: exercise the real detach error without writing a file.
        assert!(manager.stop_recording().await.is_err());
        {
            let state = manager.playback.state.lock().await;
            assert!(state.recording);
            assert_eq!(state.recording_path.as_deref(), Some("retained.mp4"));
        }
        manager.stop_playback().await.unwrap();
        let state = manager.playback.state.lock().await;
        assert!(!state.recording);
        assert!(state.playback.is_none());
        assert_eq!(
            state.recording_finalized_path.as_deref(),
            Some("retained.mp4")
        );
        assert!(state
            .recording_report
            .as_ref()
            .unwrap()
            .contains("finalize incomplete"));
    }

    #[tokio::test]
    async fn queued_old_retirement_preserves_new_intent_and_finalizes_only_old_recording() {
        use std::{
            future::{poll_fn, Future},
            task::Poll,
        };
        init_gstreamer();
        let manager = StreamManager::new();
        let health = seed_playback(&manager).await;
        let generation = health.begin_attempt();
        {
            let mut state = manager.playback.state.lock().await;
            state.playback = Some(Arc::new(PlaybackPipeline::test_headless(
                health, generation,
            )));
            state.playback_instance = Some((0, generation));
            state.recording = true;
            state.recording_path = Some("old-recording.mp4".into());
        }
        let lifecycle = manager.playback.playback_lifecycle.lock().await;
        let stop = manager.stop_playback();
        tokio::pin!(stop);
        assert!(poll_fn(|cx| Poll::Ready(stop.as_mut().poll(cx)))
            .await
            .is_pending());
        let mut replacement = AppSettings::default();
        replacement.stream.camera_ip = "192.0.2.22".into();
        manager.start_playback(&replacement, None).await.unwrap();
        drop(lifecycle);
        stop.await.unwrap();
        let state = manager.playback.state.lock().await;
        assert_eq!(
            state.playback_settings.as_ref().unwrap().stream.camera_ip,
            "192.0.2.22"
        );
        assert_eq!(state.playback_intent_epoch, Some(2));
        assert!(state.playback.is_none());
        assert!(!state.recording);
        assert_eq!(
            state.recording_finalized_path.as_deref(),
            Some("old-recording.mp4")
        );
    }
    #[tokio::test(start_paused = true)]
    async fn closed_selection_subscription_does_not_spin_the_supervisor() {
        let (tx, rx) = watch::channel(crate::network::AdapterSelection::default());
        let mut selection = Some(rx);
        tx.send_replace(crate::network::AdapterSelection::default());
        selection_wake(&mut selection).await;
        drop(tx);
        assert!(tokio::time::timeout(
            std::time::Duration::from_secs(1),
            selection_wake(&mut selection)
        )
        .await
        .is_err());
        assert!(selection.is_none());
    }

    fn playback_context(manager: &StreamManager) -> PlaybackSupervisorContext {
        manager.playback.context(None)
    }

    async fn seed_playback(manager: &StreamManager) -> Arc<PlaybackHealth> {
        let health = Arc::new(PlaybackHealth::new());
        let mut settings = AppSettings::default();
        settings.stream.camera_ip = "192.0.2.20".into();
        settings.stream.camera_mac = Some("aa:bb:cc:dd:ee:01".into());
        let mut s = manager.state.lock().await;
        s.playback_data.playback_target = stream_target(&settings);
        s.playback_data.playback_settings = Some(settings);
        s.playback_data.playback_health = Some(health.clone());
        s.playback_data.playback_intent_epoch = Some(0);
        health
    }

    #[tokio::test(start_paused = true)]
    async fn playback_owner_recovers_stable_fault_with_relay_off_and_no_status_repeats() {
        let manager = StreamManager::new();
        let h = seed_playback(&manager).await;
        let g = h.begin_attempt();
        h.record_fault(
            g,
            PlaybackFault::new(PlaybackFaultKind::BusError, "transport read error", true),
        );
        let ctx = playback_context(&manager);
        publish_playback_status(&ctx).await;
        let mut status = manager.status.tx.subscribe();
        status.borrow_and_update();
        publish_playback_status(&ctx).await;
        assert!(!status.has_changed().unwrap());
        let owner = tokio::spawn(run_playback_supervisor(ctx));
        tokio::task::yield_now().await;
        assert_eq!(h.snapshot().state, PlaybackState::Recovering);
        assert!(h.snapshot().attempt >= 1);
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(h.snapshot().generation > g); // attempted readiness without another error event
        assert!(!manager.status.tx.borrow().desired);
        manager.stop_playback().await.unwrap();
        tokio::time::advance(std::time::Duration::from_secs(120)).await;
        tokio::task::yield_now().await;
        assert!(!manager.status.tx.borrow().playback_desired);
        assert!(manager.state.lock().await.playback_data.playback.is_none());
        owner.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn readiness_wake_interrupts_long_backoff_and_rechecks_expected_identity() {
        for verified in [false, true] {
            let manager = StreamManager::new();
            let h = seed_playback(&manager).await;
            for _ in 0..6 {
                let g = h.begin_attempt();
                h.record_fault(
                    g,
                    PlaybackFault::new(PlaybackFaultKind::DeviceLoss, "not ready", true),
                );
                h.schedule_recovery();
            }
            assert_eq!(h.snapshot().next_retry_secs, Some(60));
            let g = h.snapshot().generation;
            let nic = Arc::new(Notify::new());
            let presence = Arc::new(Notify::new());
            let (n, p) = (nic.clone(), presence.clone());
            let waiter = tokio::spawn(async move {
                tokio::select! {
                    _ = wait_playback_ready(&n, p.notified()) => true,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => false,
                }
            });
            tokio::task::yield_now().await;
            if verified {
                presence.notify_one();
            } else {
                nic.notify_one();
            }
            assert!(waiter.await.unwrap());
            let mut previous = None;
            assert!(update_playback_readiness(
                &mut previous,
                Some((7, "192.0.2.10".parse().unwrap())),
                &h
            ));
            playback_step(&playback_context(&manager)).await;
            assert!(h.snapshot().generation > g);
            assert_eq!(
                h.snapshot().fault.unwrap().kind,
                PlaybackFaultKind::DeviceLoss
            );
            // A wake is not proof and cannot authorize a connection.
            assert!(manager.state.lock().await.playback_data.playback.is_none());
            assert_eq!(
                manager
                    .state
                    .lock()
                    .await
                    .playback_data
                    .playback_target
                    .as_ref()
                    .unwrap()
                    .expected_mac
                    .as_deref(),
                Some("aa:bb:cc:dd:ee:01")
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stop_and_new_source_fence_backoff_and_late_completions() {
        let manager = StreamManager::new();
        let old = seed_playback(&manager).await;
        let ctx = playback_context(&manager);
        assert!(playback_is_current(&ctx, 0, &old).await);
        manager.stop_playback().await.unwrap();
        assert!(!playback_is_current(&ctx, 0, &old).await);
        let newer = seed_playback(&manager).await;
        manager
            .state
            .lock()
            .await
            .playback_data
            .playback_intent_epoch = Some(1);
        assert!(playback_is_current(&ctx, 1, &newer).await);
        assert!(!playback_is_current(&ctx, 1, &old).await);
        assert!(!old.observe_buffer(1, tokio::time::Instant::now()));
        manager.stop_playback().await.unwrap();
        assert!(manager.retry_playback(true, None).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_fresh_proof_does_not_collapse_transport_backoff() {
        let h = PlaybackHealth::new();
        for _ in 0..6 {
            let g = h.begin_attempt();
            h.record_fault(
                g,
                PlaybackFault::new(PlaybackFaultKind::BusError, "refused", true),
            );
            h.schedule_recovery();
        }
        let signature = Some((7, "192.0.2.10".parse().unwrap()));
        let mut previous = signature;
        assert!(!update_playback_readiness(&mut previous, signature, &h));
        assert_eq!(h.snapshot().next_retry_secs, Some(60));
        update_playback_readiness(&mut previous, None, &h);
        assert!(update_playback_readiness(&mut previous, signature, &h));
        assert!(h.due(tokio::time::Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn stop_beats_an_inflight_start_waiting_for_state_lock() {
        init_gstreamer();
        let manager = Arc::new(StreamManager::new());
        let held = manager.state.lock().await;
        let m = manager.clone();
        let start =
            tokio::spawn(async move { m.start_playback(&AppSettings::default(), None).await });
        tokio::task::yield_now().await;
        let m = manager.clone();
        let stop = tokio::spawn(async move { m.stop_playback().await });
        tokio::task::yield_now().await;
        drop(held);
        assert!(start.await.unwrap().is_err());
        stop.await.unwrap().unwrap();
        assert!(!compute_status(&manager.state).await.playback_desired);
    }

    #[tokio::test(start_paused = true)]
    async fn stop_cancels_the_owned_stall_diagnostic() {
        let manager = StreamManager::new();
        let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = completed.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            flag.store(true, std::sync::atomic::Ordering::Release);
        });
        *manager.playback.playback_diagnostic.lock().unwrap() = Some(task);
        tokio::task::yield_now().await;
        manager.stop_playback().await.unwrap();
        tokio::time::advance(std::time::Duration::from_secs(20)).await;
        tokio::task::yield_now().await;
        assert!(!completed.load(std::sync::atomic::Ordering::Acquire));
        assert!(manager
            .playback
            .playback_diagnostic
            .lock()
            .unwrap()
            .is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_start_after_stop_keeps_its_new_intent() {
        init_gstreamer();
        let manager = Arc::new(StreamManager::new());
        seed_playback(&manager).await;
        let held = manager.state.lock().await;
        let m = manager.clone();
        let stop = tokio::spawn(async move { m.stop_playback().await });
        tokio::task::yield_now().await;
        let m = manager.clone();
        let start =
            tokio::spawn(async move { m.start_playback(&AppSettings::default(), None).await });
        tokio::task::yield_now().await;
        drop(held);
        stop.await.unwrap().unwrap();
        start.await.unwrap().unwrap();
        assert!(compute_status(&manager.state).await.playback_desired);
        assert_eq!(
            manager
                .state
                .lock()
                .await
                .playback_data
                .playback_intent_epoch,
            Some(2)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_playback_fault_does_not_retry_on_ticks_or_reconnect() {
        let manager = StreamManager::new();
        let h = seed_playback(&manager).await;
        let g = h.begin_attempt();
        h.record_fault(
            g,
            PlaybackFault::new(PlaybackFaultKind::BusError, "Check credentials", false),
        );
        manager.retry_playback(false, None).await.unwrap();
        for _ in 0..3 {
            playback_step(&playback_context(&manager)).await;
        }
        assert_eq!(h.snapshot().generation, g);
        assert_eq!(h.snapshot().state, PlaybackState::Failed);
        manager.retry_playback(true, None).await.unwrap();
        assert!(h.due(tokio::time::Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn manual_retry_applies_corrections_without_rebinding_to_another_selection() {
        let manager = StreamManager::new();
        let old = seed_playback(&manager).await;
        let mut settings = AppSettings::default();
        settings.credentials.password = "corrected".into();
        settings.stream.rtsp_path = "/correct-path".into();
        settings.stream.camera_ip = "192.0.2.99".into();
        settings.stream.camera_mac = Some("aa:bb:cc:dd:ee:99".into());
        manager.retry_playback(true, Some(settings)).await.unwrap();
        let state = manager.state.lock().await;
        let desired = state.playback_data.playback_settings.as_ref().unwrap();
        assert_eq!(desired.credentials.password, "corrected");
        assert_eq!(desired.stream.rtsp_path, "/correct-path");
        assert_eq!(desired.stream.camera_ip, "192.0.2.20");
        assert_eq!(
            desired.stream.camera_mac.as_deref(),
            Some("aa:bb:cc:dd:ee:01")
        );
        assert_eq!(state.playback_data.playback_intent_epoch, Some(1));
        assert!(!Arc::ptr_eq(
            state.playback_data.playback_health.as_ref().unwrap(),
            &old
        ));
        assert_eq!(old.snapshot().state, PlaybackState::Stopped);
    }

    #[tokio::test]
    async fn preview_loss_finalizes_recording_and_keeps_relay_intent_untouched() {
        init_gstreamer();
        let manager = StreamManager::new();
        let h = seed_playback(&manager).await;
        seed_desired_relay(&manager, 8, 0).await;
        let g = h.begin_attempt();
        let p = Arc::new(PlaybackPipeline::test_headless(h.clone(), g));
        p.play().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("interrupted.mp4");
        p.attach_recording(path.to_str().unwrap()).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(350)).await;
        {
            let mut s = manager.state.lock().await;
            s.playback_data.playback = Some(p);
            s.playback_data.playback_instance = Some((0, g));
            s.playback_data.recording = true;
            s.playback_data.recording_path = Some(path.to_string_lossy().to_string());
        }
        h.record_fault(
            g,
            PlaybackFault::new(PlaybackFaultKind::DeviceLoss, "route changed", true),
        );
        playback_step(&playback_context(&manager)).await;
        let status = compute_status(&manager.state).await;
        assert!(!status.recording);
        assert_eq!(
            status.recording_report.as_deref(),
            Some("recording stopped: stream lost")
        );
        assert_eq!(status.recording_finalized_path.as_deref(), path.to_str());
        assert!(path.metadata().unwrap().len() > 0);
        assert!(status.desired);
        assert_eq!(status.relay_state, RelayState::Starting);
        assert!(manager.state.lock().await.playback_data.playback.is_none());
    }
}
