//! RTSP relay health and recovery state.
//!
//! This module deliberately contains no `StreamManager` locking or slow
//! GStreamer/network work.  GStreamer and GLib callbacks update the small
//! in-memory health object and enqueue a fault; the async supervisor in
//! `streaming::mod` owns teardown, backoff, and rebuilding.

use gstreamer_rtsp_server as gst_rtsp_server;
use serde::Serialize;
use std::sync::{Mutex, MutexGuard};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

pub const FIRST_BUFFER_TIMEOUT: Duration = Duration::from_secs(15);
pub const STALL_WINDOW: Duration = Duration::from_secs(5);
pub const STALL_CONFIRMATION: Duration = Duration::from_secs(10);
pub const HEALTHY_RESET_WINDOW: Duration = Duration::from_secs(30);
pub const RECOVERY_DELAYS: [Duration; 6] = [
    Duration::ZERO,
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(15),
    Duration::from_secs(30),
    Duration::from_secs(60),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayState {
    Stopped,
    Listening,
    Starting,
    Streaming,
    Recovering,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayFaultKind {
    GstError,
    Eos,
    MediaStatusError,
    FirstBufferTimeout,
    BufferStall,
    MainLoopExited,
}

impl RelayFaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GstError => "gst_error",
            Self::Eos => "eos",
            Self::MediaStatusError => "media_status_error",
            Self::FirstBufferTimeout => "first_buffer_timeout",
            Self::BufferStall => "buffer_stall",
            Self::MainLoopExited => "main_loop_exited",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFault {
    pub kind: RelayFaultKind,
    /// This text has already passed through relay redaction.  Raw GStreamer
    /// text must never be put in this field.
    pub reason: String,
    pub server_generation: u64,
    pub media_generation: u64,
}

#[derive(Debug, Clone)]
pub struct RelayFaultEvent {
    pub fault: RelayFault,
}

#[derive(Debug, Clone)]
pub enum RelaySupervisorEvent {
    Fault(RelayFaultEvent),
    /// Used when an explicit start has established desired state but its
    /// initial listener build failed.  The supervisor then applies the same
    /// serialized retry policy as a runtime fault.
    RetryRequested {
        server_generation: u64,
    },
}

pub type RelayEventSender = mpsc::UnboundedSender<RelaySupervisorEvent>;
pub type RelayEventReceiver = mpsc::UnboundedReceiver<RelaySupervisorEvent>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayIngestKind {
    Rtsp,
    Udp,
}

/// Fully validated start identity.  Credentials deliberately participate in
/// `PartialEq`: changing camera authentication must replace the ingest even
/// when the public relay endpoint is otherwise identical.
///
/// Do not derive `Debug`; this structure contains credentials and the
/// token-bearing mount path.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedRtspStartSpec {
    pub source: ResolvedSource,
    pub server_port: u16,
    pub mount_path: String,
    pub bind_interface: Option<String>,
    pub bind_address: Option<String>,
    pub advertised_ip: String,
    pub username: String,
    pub password: String,
}

#[derive(Clone, PartialEq, Eq)]
pub enum ResolvedSource {
    Rtsp { url: String },
    Udp { port: u16 },
}

impl ResolvedRtspStartSpec {
    pub fn ingest_kind(&self) -> RelayIngestKind {
        match &self.source {
            ResolvedSource::Rtsp { .. } => RelayIngestKind::Rtsp,
            ResolvedSource::Udp { .. } => RelayIngestKind::Udp,
        }
    }

    pub fn udp_ingest_port(&self) -> Option<u16> {
        match &self.source {
            ResolvedSource::Udp { port } => Some(*port),
            ResolvedSource::Rtsp { .. } => None,
        }
    }

    pub fn client_url(&self) -> String {
        format!(
            "rtsp://{}:{}{}",
            self.advertised_ip, self.server_port, self.mount_path
        )
    }

    pub fn display_url(&self) -> String {
        format!("rtsp://{}:{}", self.advertised_ip, self.server_port)
    }
}

#[derive(Clone)]
pub struct RelayHealthSnapshot {
    pub server_generation: u64,
    pub state: RelayState,
    pub error: Option<String>,
    pub recovery_attempt: u32,
    pub loop_alive: bool,
}

struct RelayRuntimeInner {
    server_generation: u64,
    /// Monotonic across every lazy media pipeline and automatic listener
    /// replacement in this explicit-start generation.
    media_generation: u64,
    active_media_generation: Option<u64>,
    /// Distinguishes automatic replacement listener instances while the
    /// explicit-start generation remains stable.  It prevents a late loop or
    /// media callback from an old listener from changing replacement health.
    server_instance: u64,
    state: RelayState,
    ingest_kind: RelayIngestKind,
    target_playing: bool,
    media_constructed_at: Option<Instant>,
    playing_since: Option<Instant>,
    last_buffer_at: Option<Instant>,
    healthy_since: Option<Instant>,
    stall_warning_emitted: bool,
    first_fault: Option<RelayFault>,
    error: Option<String>,
    recovery_attempt: u32,
    consecutive_bind_failures: u32,
    loop_alive: bool,
    active_media: Option<glib::WeakRef<gst_rtsp_server::RTSPMedia>>,
}

/// Callback-safe relay health.  The mutex protects only a small in-memory
/// state record; no method awaits, enumerates interfaces, or performs network
/// or GStreamer lifecycle work while holding it.
pub struct RelayRuntimeHealth {
    inner: Mutex<RelayRuntimeInner>,
}

impl RelayRuntimeHealth {
    pub fn new(server_generation: u64, ingest_kind: RelayIngestKind) -> Self {
        Self {
            inner: Mutex::new(RelayRuntimeInner {
                server_generation,
                media_generation: 0,
                active_media_generation: None,
                server_instance: 0,
                state: RelayState::Starting,
                ingest_kind,
                target_playing: false,
                media_constructed_at: None,
                playing_since: None,
                last_buffer_at: None,
                healthy_since: None,
                stall_warning_emitted: false,
                first_fault: None,
                error: None,
                recovery_attempt: 0,
                consecutive_bind_failures: 0,
                loop_alive: false,
                active_media: None,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, RelayRuntimeInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn transition(
        inner: &mut RelayRuntimeInner,
        next: RelayState,
        fault_kind: Option<RelayFaultKind>,
        reason: Option<&str>,
    ) {
        let prior = inner.state;
        if prior == next {
            return;
        }
        log::info!(
            "RTSP relay generation={} media={} state {:?} -> {:?} fault={} attempt={} loop_alive={}{}",
            inner.server_generation,
            inner.media_generation,
            prior,
            next,
            fault_kind.map(RelayFaultKind::as_str).unwrap_or("none"),
            inner.recovery_attempt,
            inner.loop_alive,
            reason
                .map(|r| format!(": {r}"))
                .unwrap_or_default()
        );
        inner.state = next;
    }

    pub fn snapshot(&self) -> RelayHealthSnapshot {
        let inner = self.lock();
        RelayHealthSnapshot {
            server_generation: inner.server_generation,
            state: inner.state,
            error: inner.error.clone(),
            recovery_attempt: inner.recovery_attempt,
            loop_alive: inner.loop_alive,
        }
    }

    pub fn server_generation(&self) -> u64 {
        self.lock().server_generation
    }

    /// Reserve a new listener instance before a build begins.  Automatic
    /// replacements keep the explicit-start generation but receive a fresh
    /// instance id for late-callback rejection.
    pub fn begin_server_instance(&self, recovering: bool) -> u64 {
        let mut inner = self.lock();
        inner.server_instance = inner.server_instance.wrapping_add(1).max(1);
        inner.active_media_generation = None;
        inner.active_media = None;
        inner.target_playing = false;
        inner.media_constructed_at = None;
        inner.playing_since = None;
        inner.last_buffer_at = None;
        inner.healthy_since = None;
        inner.stall_warning_emitted = false;
        inner.first_fault = None;
        inner.loop_alive = false;
        let next = if recovering {
            RelayState::Recovering
        } else {
            RelayState::Starting
        };
        Self::transition(&mut inner, next, None, None);
        inner.server_instance
    }

    pub fn loop_started(&self, server_instance: u64) {
        let mut inner = self.lock();
        if inner.server_instance == server_instance {
            inner.loop_alive = true;
        }
    }

    pub fn loop_alive_for(&self, server_instance: u64) -> bool {
        let inner = self.lock();
        inner.server_instance == server_instance && inner.loop_alive
    }

    pub fn loop_exited(
        &self,
        server_instance: u64,
        intentional: bool,
        reason: String,
    ) -> Option<RelayFaultEvent> {
        let mut inner = self.lock();
        if inner.server_instance != server_instance {
            return None;
        }
        inner.loop_alive = false;
        if intentional {
            return None;
        }
        let media_generation = inner
            .active_media_generation
            .unwrap_or(inner.media_generation);
        Self::record_fault_locked(
            &mut inner,
            RelayFaultKind::MainLoopExited,
            reason,
            media_generation,
        )
    }

    pub fn mark_listener_bound(&self, server_instance: u64) {
        let mut inner = self.lock();
        if inner.server_instance != server_instance {
            return;
        }
        inner.error = None;
        inner.first_fault = None;
        inner.consecutive_bind_failures = 0;
        if inner.active_media_generation.is_none() {
            Self::transition(&mut inner, RelayState::Listening, None, None);
        }
    }

    pub fn mark_build_failed(&self, server_instance: u64, reason: String, bind_failure: bool) {
        let mut inner = self.lock();
        if inner.server_instance != server_instance {
            return;
        }
        inner.loop_alive = false;
        inner.error = Some(reason.clone());
        if bind_failure {
            inner.consecutive_bind_failures = inner.consecutive_bind_failures.saturating_add(1);
        } else {
            inner.consecutive_bind_failures = 0;
        }
        Self::transition(&mut inner, RelayState::Failed, None, Some(&reason));
    }

    pub fn schedule_recovery_attempt(&self) -> (u32, Duration) {
        let mut inner = self.lock();
        inner.recovery_attempt = inner.recovery_attempt.saturating_add(1);
        let attempt = inner.recovery_attempt;
        let delay = recovery_delay(attempt);
        log::info!(
            "RTSP relay recovery attempt={} delay={}s generation={}",
            attempt,
            delay.as_secs(),
            inner.server_generation
        );
        (attempt, delay)
    }

    pub fn mark_recovery_in_progress(&self) {
        let mut inner = self.lock();
        Self::transition(&mut inner, RelayState::Recovering, None, None);
    }

    /// Retain the bind-failure history when the configured interface cannot
    /// currently be resolved.  Re-resolution is part of recovery rather than
    /// a new explicit start, so losing that history would immediately fall
    /// back to retrying the stale address.
    pub fn mark_resolution_failed(&self, reason: String) {
        let mut inner = self.lock();
        inner.loop_alive = false;
        inner.error = Some(reason.clone());
        Self::transition(&mut inner, RelayState::Failed, None, Some(&reason));
    }

    /// Once explicit-bind re-resolution itself fails, retries stay on the
    /// bounded 60-second cadence until the interface has a usable address.
    pub fn force_max_backoff(&self) {
        let mut inner = self.lock();
        inner.recovery_attempt = inner.recovery_attempt.max(RECOVERY_DELAYS.len() as u32);
    }

    pub fn should_reresolve_explicit_bind(&self) -> bool {
        self.lock().consecutive_bind_failures >= 3
    }

    pub fn media_constructed(
        &self,
        server_instance: u64,
        media: glib::WeakRef<gst_rtsp_server::RTSPMedia>,
        now: Instant,
    ) -> Option<u64> {
        let mut inner = self.lock();
        if inner.server_instance != server_instance {
            return None;
        }
        inner.media_generation = inner.media_generation.wrapping_add(1).max(1);
        let media_generation = inner.media_generation;
        inner.active_media_generation = Some(media_generation);
        inner.active_media = Some(media);
        inner.target_playing = false;
        inner.media_constructed_at = Some(now);
        inner.playing_since = None;
        inner.last_buffer_at = None;
        inner.healthy_since = None;
        inner.stall_warning_emitted = false;
        inner.first_fault = None;
        inner.error = None;
        Self::transition(&mut inner, RelayState::Starting, None, None);
        Some(media_generation)
    }

    fn is_current_media(
        inner: &RelayRuntimeInner,
        server_instance: u64,
        media_generation: u64,
    ) -> bool {
        inner.server_instance == server_instance
            && inner.active_media_generation == Some(media_generation)
    }

    pub fn media_prepared(&self, server_instance: u64, media_generation: u64, now: Instant) {
        let mut inner = self.lock();
        if !Self::is_current_media(&inner, server_instance, media_generation) {
            return;
        }
        inner.media_constructed_at = Some(now);
        if inner.target_playing && inner.last_buffer_at.is_none() {
            inner.playing_since = Some(now);
        }
    }

    pub fn media_target_state(
        &self,
        server_instance: u64,
        media_generation: u64,
        playing: bool,
        now: Instant,
    ) {
        let mut inner = self.lock();
        if !Self::is_current_media(&inner, server_instance, media_generation) {
            return;
        }
        inner.target_playing = playing;
        if playing {
            inner.playing_since.get_or_insert(now);
            if inner.state == RelayState::Listening {
                Self::transition(&mut inner, RelayState::Starting, None, None);
            }
        } else {
            inner.playing_since = None;
        }
    }

    pub fn media_unprepared(&self, server_instance: u64, media_generation: u64) {
        let mut inner = self.lock();
        if !Self::is_current_media(&inner, server_instance, media_generation) {
            return;
        }
        inner.active_media_generation = None;
        inner.active_media = None;
        inner.target_playing = false;
        inner.media_constructed_at = None;
        inner.playing_since = None;
        inner.last_buffer_at = None;
        inner.healthy_since = None;
        inner.stall_warning_emitted = false;
        if inner.first_fault.is_none()
            && !matches!(inner.state, RelayState::Recovering | RelayState::Failed)
            && inner.loop_alive
        {
            Self::transition(&mut inner, RelayState::Listening, None, None);
        }
    }

    pub fn observe_buffer(
        &self,
        server_instance: u64,
        media_generation: u64,
        now: Instant,
    ) -> bool {
        let mut inner = self.lock();
        if !Self::is_current_media(&inner, server_instance, media_generation) {
            return false;
        }
        inner.last_buffer_at = Some(now);
        inner.stall_warning_emitted = false;
        inner.healthy_since.get_or_insert(now);
        if matches!(
            inner.state,
            RelayState::Starting | RelayState::Recovering | RelayState::Listening
        ) {
            Self::transition(&mut inner, RelayState::Streaming, None, None);
        }
        true
    }

    pub fn record_media_fault(
        &self,
        server_instance: u64,
        media_generation: u64,
        kind: RelayFaultKind,
        reason: String,
    ) -> Option<RelayFaultEvent> {
        let mut inner = self.lock();
        if !Self::is_current_media(&inner, server_instance, media_generation) {
            return None;
        }
        if kind == RelayFaultKind::Eos && !inner.target_playing {
            return None;
        }
        Self::record_fault_locked(&mut inner, kind, reason, media_generation)
    }

    fn record_fault_locked(
        inner: &mut RelayRuntimeInner,
        kind: RelayFaultKind,
        reason: String,
        media_generation: u64,
    ) -> Option<RelayFaultEvent> {
        if inner.first_fault.is_some() {
            return None;
        }
        let fault = RelayFault {
            kind,
            reason: reason.clone(),
            server_generation: inner.server_generation,
            media_generation,
        };
        inner.first_fault = Some(fault.clone());
        inner.error = Some(reason);
        Some(RelayFaultEvent { fault })
    }

    /// Verify and accept the first fault for the current media.  Retirement
    /// happens here, before teardown, so a late buffer from the failed media
    /// cannot mark the relay healthy again.
    pub fn accept_fault(&self, fault: &RelayFault) -> bool {
        let mut inner = self.lock();
        if inner.server_generation != fault.server_generation
            || inner.first_fault.as_ref() != Some(fault)
        {
            return false;
        }
        inner.active_media_generation = None;
        inner.active_media = None;
        inner.target_playing = false;
        inner.playing_since = None;
        inner.healthy_since = None;
        Self::transition(
            &mut inner,
            RelayState::Recovering,
            Some(fault.kind),
            Some(&fault.reason),
        );
        true
    }

    pub fn active_media(&self) -> Option<(u64, u64, glib::WeakRef<gst_rtsp_server::RTSPMedia>)> {
        let inner = self.lock();
        Some((
            inner.server_instance,
            inner.active_media_generation?,
            inner.active_media.as_ref()?.clone(),
        ))
    }

    /// Evaluate monotonic watchdog deadlines and the healthy reset window.
    /// The returned fault is already coalesced with callback faults.
    pub fn evaluate_watchdog(&self, now: Instant) -> Option<RelayFaultEvent> {
        let mut inner = self.lock();

        if inner.state == RelayState::Streaming {
            if let Some(since) = inner.healthy_since {
                if now.saturating_duration_since(since) >= HEALTHY_RESET_WINDOW
                    && inner.recovery_attempt != 0
                {
                    log::info!(
                        "RTSP relay generation={} healthy for {}s; recovery backoff reset",
                        inner.server_generation,
                        HEALTHY_RESET_WINDOW.as_secs()
                    );
                    inner.recovery_attempt = 0;
                }
            }
        }

        if inner.ingest_kind != RelayIngestKind::Rtsp
            || inner.first_fault.is_some()
            || inner.active_media_generation.is_none()
            || !inner.target_playing
        {
            return None;
        }

        let media_generation = inner.active_media_generation.unwrap_or(0);
        match inner.last_buffer_at {
            None => {
                let started = inner.playing_since?;
                let elapsed = now.saturating_duration_since(started);
                if elapsed >= FIRST_BUFFER_TIMEOUT {
                    return Self::record_fault_locked(
                        &mut inner,
                        RelayFaultKind::FirstBufferTimeout,
                        format!(
                            "RTSP relay produced no first RTP buffer for {}s",
                            elapsed.as_secs()
                        ),
                        media_generation,
                    );
                }
            }
            Some(last) => {
                let elapsed = now.saturating_duration_since(last);
                if elapsed >= STALL_WINDOW && !inner.stall_warning_emitted {
                    inner.stall_warning_emitted = true;
                    // A five-second gap interrupts the continuous healthy
                    // window even if it heals before the confirmation fault.
                    inner.healthy_since = None;
                    log::warn!(
                        "RTSP relay generation={} media={} no pay0 buffer for {:.1}s; waiting for second window",
                        inner.server_generation,
                        media_generation,
                        elapsed.as_secs_f32()
                    );
                }
                if elapsed >= STALL_CONFIRMATION {
                    return Self::record_fault_locked(
                        &mut inner,
                        RelayFaultKind::BufferStall,
                        format!(
                            "RTSP relay produced no RTP buffers for {:.1}s (two windows)",
                            elapsed.as_secs_f32()
                        ),
                        media_generation,
                    );
                }
            }
        }
        None
    }
}

pub fn recovery_delay(attempt: u32) -> Duration {
    let index = attempt.saturating_sub(1) as usize;
    RECOVERY_DELAYS[index.min(RECOVERY_DELAYS.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use glib::prelude::*;

    fn init_gstreamer() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| gstreamer::init().expect("GStreamer test initialization failed"));
    }

    fn construct_media(
        health: &RelayRuntimeHealth,
        server_instance: u64,
        now: Instant,
    ) -> (gst_rtsp_server::RTSPMedia, u64) {
        init_gstreamer();
        let media = gst_rtsp_server::RTSPMedia::new(gstreamer::Pipeline::new());
        let generation = health
            .media_constructed(server_instance, media.downgrade(), now)
            .expect("current listener should accept media");
        (media, generation)
    }

    #[test]
    fn backoff_sequence_is_bounded() {
        let actual: Vec<u64> = (1..=8)
            .map(|attempt| recovery_delay(attempt).as_secs())
            .collect();
        assert_eq!(actual, vec![0, 2, 5, 15, 30, 60, 60, 60]);
    }

    #[test]
    fn resolved_identity_includes_credentials() {
        let base = ResolvedRtspStartSpec {
            source: ResolvedSource::Rtsp {
                url: "rtsp://192.0.2.1/live".into(),
            },
            server_port: 8554,
            mount_path: "/stream-token".into(),
            bind_interface: None,
            bind_address: None,
            advertised_ip: "192.0.2.10".into(),
            username: "camera".into(),
            password: "old".into(),
        };
        let mut changed = base.clone();
        changed.password = "new".into();
        assert!(base != changed);
    }

    #[tokio::test(start_paused = true)]
    async fn relay_state_transition_table_covers_runtime_states() {
        let health = RelayRuntimeHealth::new(7, RelayIngestKind::Rtsp);
        assert_eq!(health.snapshot().state, RelayState::Starting);

        let instance = health.begin_server_instance(false);
        health.loop_started(instance);
        health.mark_listener_bound(instance);
        assert_eq!(health.snapshot().state, RelayState::Listening);

        let (_media, media_generation) = construct_media(&health, instance, Instant::now());
        health.media_target_state(instance, media_generation, true, Instant::now());
        assert_eq!(health.snapshot().state, RelayState::Starting);
        assert!(health.observe_buffer(instance, media_generation, Instant::now()));
        assert_eq!(health.snapshot().state, RelayState::Streaming);

        let event = health
            .record_media_fault(
                instance,
                media_generation,
                RelayFaultKind::Eos,
                "relay EOS".into(),
            )
            .expect("first fault");
        assert!(health.accept_fault(&event.fault));
        assert_eq!(health.snapshot().state, RelayState::Recovering);

        let replacement = health.begin_server_instance(true);
        health.mark_build_failed(replacement, "bind failed".into(), true);
        assert_eq!(health.snapshot().state, RelayState::Failed);
    }

    #[tokio::test(start_paused = true)]
    async fn first_buffer_timeout_starts_only_when_playing_is_expected() {
        let health = RelayRuntimeHealth::new(1, RelayIngestKind::Rtsp);
        let instance = health.begin_server_instance(false);
        health.loop_started(instance);
        health.mark_listener_bound(instance);
        let (_media, generation) = construct_media(&health, instance, Instant::now());

        tokio::time::advance(FIRST_BUFFER_TIMEOUT + Duration::from_secs(5)).await;
        assert!(health.evaluate_watchdog(Instant::now()).is_none());
        assert!(health
            .record_media_fault(
                instance,
                generation,
                RelayFaultKind::Eos,
                "idle media EOS".into(),
            )
            .is_none());

        health.media_target_state(instance, generation, true, Instant::now());
        health.media_prepared(instance, generation, Instant::now());
        tokio::time::advance(FIRST_BUFFER_TIMEOUT - Duration::from_millis(1)).await;
        assert!(health.evaluate_watchdog(Instant::now()).is_none());
        tokio::time::advance(Duration::from_millis(1)).await;
        let event = health
            .evaluate_watchdog(Instant::now())
            .expect("15 seconds without a first buffer should fault");
        assert_eq!(event.fault.kind, RelayFaultKind::FirstBufferTimeout);
    }

    #[tokio::test(start_paused = true)]
    async fn stall_needs_two_windows_and_any_buffer_resets_them() {
        let health = RelayRuntimeHealth::new(1, RelayIngestKind::Rtsp);
        let instance = health.begin_server_instance(false);
        health.loop_started(instance);
        health.mark_listener_bound(instance);
        let (_media, generation) = construct_media(&health, instance, Instant::now());
        health.media_target_state(instance, generation, true, Instant::now());
        assert!(health.observe_buffer(instance, generation, Instant::now()));

        tokio::time::advance(STALL_WINDOW).await;
        assert!(health.evaluate_watchdog(Instant::now()).is_none());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(health.observe_buffer(instance, generation, Instant::now()));

        tokio::time::advance(STALL_WINDOW).await;
        assert!(health.evaluate_watchdog(Instant::now()).is_none());
        tokio::time::advance(STALL_CONFIRMATION - STALL_WINDOW).await;
        let event = health
            .evaluate_watchdog(Instant::now())
            .expect("ten continuous silent seconds should fault");
        assert_eq!(event.fault.kind, RelayFaultKind::BufferStall);
    }

    #[tokio::test(start_paused = true)]
    async fn listener_without_downstream_media_never_stalls() {
        let health = RelayRuntimeHealth::new(1, RelayIngestKind::Rtsp);
        let instance = health.begin_server_instance(false);
        health.loop_started(instance);
        health.mark_listener_bound(instance);

        tokio::time::advance(Duration::from_secs(60 * 60)).await;
        assert!(health.evaluate_watchdog(Instant::now()).is_none());
        assert_eq!(health.snapshot().state, RelayState::Listening);
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_faults_and_stale_media_updates_are_ignored() {
        let health = RelayRuntimeHealth::new(1, RelayIngestKind::Rtsp);
        let instance = health.begin_server_instance(false);
        health.loop_started(instance);
        health.mark_listener_bound(instance);
        let (_old_media, old_generation) = construct_media(&health, instance, Instant::now());
        let (_new_media, new_generation) = construct_media(&health, instance, Instant::now());

        assert!(!health.observe_buffer(instance, old_generation, Instant::now()));
        assert_eq!(health.snapshot().state, RelayState::Starting);
        assert!(health.observe_buffer(instance, new_generation, Instant::now()));

        assert!(health
            .record_media_fault(
                instance,
                new_generation,
                RelayFaultKind::GstError,
                "first".into(),
            )
            .is_some());
        assert!(health
            .record_media_fault(
                instance,
                new_generation,
                RelayFaultKind::Eos,
                "duplicate".into(),
            )
            .is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn thirty_continuous_healthy_seconds_reset_backoff() {
        let health = RelayRuntimeHealth::new(1, RelayIngestKind::Rtsp);
        assert_eq!(health.schedule_recovery_attempt().0, 1);
        let instance = health.begin_server_instance(true);
        health.loop_started(instance);
        health.mark_listener_bound(instance);
        let (_media, generation) = construct_media(&health, instance, Instant::now());
        health.media_target_state(instance, generation, true, Instant::now());
        assert!(health.observe_buffer(instance, generation, Instant::now()));

        for _ in 0..29 {
            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(health.observe_buffer(instance, generation, Instant::now()));
            assert!(health.evaluate_watchdog(Instant::now()).is_none());
        }
        assert_eq!(health.snapshot().recovery_attempt, 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(health.observe_buffer(instance, generation, Instant::now()));
        assert!(health.evaluate_watchdog(Instant::now()).is_none());
        assert_eq!(health.snapshot().recovery_attempt, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn udp_is_exempt_from_silence_but_not_media_errors() {
        let health = RelayRuntimeHealth::new(1, RelayIngestKind::Udp);
        let instance = health.begin_server_instance(false);
        health.loop_started(instance);
        health.mark_listener_bound(instance);
        let (_media, generation) = construct_media(&health, instance, Instant::now());
        health.media_target_state(instance, generation, true, Instant::now());

        tokio::time::advance(Duration::from_secs(120)).await;
        assert!(health.evaluate_watchdog(Instant::now()).is_none());
        let event = health.record_media_fault(
            instance,
            generation,
            RelayFaultKind::GstError,
            "UDP media error".into(),
        );
        assert!(event.is_some());
    }

    #[test]
    fn explicit_bind_refresh_threshold_and_max_backoff_are_sticky() {
        let health = RelayRuntimeHealth::new(1, RelayIngestKind::Rtsp);
        for _ in 0..3 {
            let instance = health.begin_server_instance(true);
            health.mark_build_failed(instance, "bind failed".into(), true);
        }
        assert!(health.should_reresolve_explicit_bind());

        health.mark_resolution_failed("interface unavailable".into());
        assert!(health.should_reresolve_explicit_bind());
        health.force_max_backoff();
        assert_eq!(
            health.schedule_recovery_attempt().1,
            Duration::from_secs(60)
        );
        assert_eq!(health.snapshot().state, RelayState::Failed);

        let instance = health.begin_server_instance(true);
        health.loop_started(instance);
        health.mark_listener_bound(instance);
        assert!(!health.should_reresolve_explicit_bind());
    }
}
