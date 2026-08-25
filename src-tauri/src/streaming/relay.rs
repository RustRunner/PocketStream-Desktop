//! Protocol-neutral re-stream health and recovery state.
//!
//! This module deliberately contains no `StreamManager` locking or slow
//! GStreamer/network work.  GStreamer and GLib callbacks update the small
//! in-memory health object and enqueue a fault; the async supervisor in
//! `streaming::mod` owns teardown, backoff, and rebuilding.

use serde::Serialize;
use std::sync::{Mutex, MutexGuard};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

use crate::error::AppError;

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
    Capability,
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
            Self::Capability => "capability",
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
    pub data_generation: u64,
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
pub enum RestreamBuildFailureKind {
    Bind,
    Configuration,
}

pub struct RestreamBuildFailure {
    pub kind: RestreamBuildFailureKind,
    pub error: AppError,
}

impl RestreamBuildFailure {
    pub fn bind(error: AppError) -> Self {
        Self {
            kind: RestreamBuildFailureKind::Bind,
            error,
        }
    }

    pub fn configuration(error: AppError) -> Self {
        Self {
            kind: RestreamBuildFailureKind::Configuration,
            error,
        }
    }
}

/// Generation-scoped dependencies shared by eager and deferred output
/// adapters. It deliberately owns no protocol settings or secrets.
pub struct RestreamRuntimeContext {
    pub health: std::sync::Arc<RelayRuntimeHealth>,
    pub event_tx: RelayEventSender,
    pub server_instance: u64,
}

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
pub struct ResolvedStartSpec {
    pub source: ResolvedSource,
    pub output: ResolvedOutput,
    pub bind_interface: Option<String>,
    pub bind_address: Option<String>,
    pub advertised_ip: String,
    pub username: String,
    pub password: String,
}

#[derive(Clone, PartialEq, Eq)]
pub enum ResolvedOutput {
    Rtsp {
        server_port: u16,
        mount_path: String,
    },
}

#[derive(Clone, PartialEq, Eq)]
pub enum ResolvedSource {
    Rtsp { url: String },
    Udp { port: u16 },
}

impl ResolvedStartSpec {
    pub fn protocol(&self) -> crate::config::RestreamProtocol {
        match self.output {
            ResolvedOutput::Rtsp { .. } => crate::config::RestreamProtocol::Rtsp,
        }
    }

    pub fn server_port(&self) -> u16 {
        match self.output {
            ResolvedOutput::Rtsp { server_port, .. } => server_port,
        }
    }

    pub fn mount_path(&self) -> &str {
        match &self.output {
            ResolvedOutput::Rtsp { mount_path, .. } => mount_path,
        }
    }

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
            self.advertised_ip,
            self.server_port(),
            self.mount_path()
        )
    }

    pub fn display_url(&self) -> String {
        format!("rtsp://{}:{}", self.advertised_ip, self.server_port())
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
    /// Monotonic across protocol data pipelines and automatic output
    /// replacements in this explicit-start generation.
    data_generation: u64,
    active_data_generation: Option<u64>,
    /// Distinguishes automatic replacement listener instances while the
    /// explicit-start generation remains stable.  It prevents a late loop or
    /// media callback from an old listener from changing replacement health.
    server_instance: u64,
    state: RelayState,
    ingest_kind: RelayIngestKind,
    first_buffer_armed_at: Option<Instant>,
    last_buffer_at: Option<Instant>,
    healthy_since: Option<Instant>,
    stall_warning_emitted: bool,
    first_fault: Option<RelayFault>,
    error: Option<String>,
    recovery_attempt: u32,
    consecutive_bind_failures: u32,
    loop_alive: bool,
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
                data_generation: 0,
                active_data_generation: None,
                server_instance: 0,
                state: RelayState::Starting,
                ingest_kind,
                first_buffer_armed_at: None,
                last_buffer_at: None,
                healthy_since: None,
                stall_warning_emitted: false,
                first_fault: None,
                error: None,
                recovery_attempt: 0,
                consecutive_bind_failures: 0,
                loop_alive: false,
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
            "Re-stream generation={} data={} state {:?} -> {:?} fault={} attempt={} loop_alive={}{}",
            inner.server_generation,
            inner.data_generation,
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
        inner.active_data_generation = None;
        inner.first_buffer_armed_at = None;
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
        let data_generation = inner
            .active_data_generation
            .unwrap_or(inner.data_generation);
        Self::record_fault_locked(
            &mut inner,
            RelayFaultKind::MainLoopExited,
            reason,
            data_generation,
        )
    }

    pub fn mark_listener_bound(&self, server_instance: u64) {
        let mut inner = self.lock();
        if inner.server_instance != server_instance {
            return;
        }
        inner.consecutive_bind_failures = 0;
        // `begin_server_instance` already cleared prior-instance faults. Do
        // not erase a current callback fault that raced listener startup.
        if inner.first_fault.is_some() {
            return;
        }
        inner.error = None;
        if inner.active_data_generation.is_none() {
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
            "Re-stream recovery attempt={} delay={}s generation={}",
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

    /// Begin a protocol data generation. Callers choose when (or whether) to
    /// arm its first-buffer deadline: a deferred adapter constructs here but
    /// arms only when PLAYING is requested, while an eager adapter may arm
    /// immediately.
    pub fn begin_data_generation(&self, server_instance: u64) -> Option<u64> {
        let mut inner = self.lock();
        if inner.server_instance != server_instance {
            return None;
        }
        inner.data_generation = inner.data_generation.wrapping_add(1).max(1);
        let data_generation = inner.data_generation;
        inner.active_data_generation = Some(data_generation);
        inner.first_buffer_armed_at = None;
        inner.last_buffer_at = None;
        inner.healthy_since = None;
        inner.stall_warning_emitted = false;
        inner.first_fault = None;
        inner.error = None;
        Self::transition(&mut inner, RelayState::Starting, None, None);
        Some(data_generation)
    }

    fn is_current_data(
        inner: &RelayRuntimeInner,
        server_instance: u64,
        data_generation: u64,
    ) -> bool {
        inner.server_instance == server_instance
            && inner.active_data_generation == Some(data_generation)
    }

    /// Arm (or reconcile) the first-buffer deadline for the current data
    /// generation. Re-arming before the first buffer intentionally resets the
    /// deadline; a deferred adapter uses that at `prepared` after an earlier
    /// target-state notification.
    pub fn arm_first_buffer(&self, server_instance: u64, data_generation: u64, now: Instant) {
        let mut inner = self.lock();
        if !Self::is_current_data(&inner, server_instance, data_generation)
            || inner.last_buffer_at.is_some()
        {
            return;
        }
        inner.first_buffer_armed_at = Some(now);
        if inner.state == RelayState::Listening {
            Self::transition(&mut inner, RelayState::Starting, None, None);
        }
    }

    pub fn disarm_first_buffer(&self, server_instance: u64, data_generation: u64) {
        let mut inner = self.lock();
        if Self::is_current_data(&inner, server_instance, data_generation)
            && inner.last_buffer_at.is_none()
        {
            inner.first_buffer_armed_at = None;
        }
    }

    pub fn end_data_generation(&self, server_instance: u64, data_generation: u64) {
        let mut inner = self.lock();
        if !Self::is_current_data(&inner, server_instance, data_generation) {
            return;
        }
        inner.active_data_generation = None;
        inner.first_buffer_armed_at = None;
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

    pub fn observe_buffer(&self, server_instance: u64, data_generation: u64, now: Instant) -> bool {
        let mut inner = self.lock();
        if !Self::is_current_data(&inner, server_instance, data_generation)
            || inner.first_fault.is_some()
        {
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

    /// Mark an eager, silence-exempt source healthy when its output pipeline
    /// reaches PLAYING even if no payload has arrived yet.
    pub fn report_streaming_without_buffer(
        &self,
        server_instance: u64,
        data_generation: u64,
        now: Instant,
    ) -> bool {
        let mut inner = self.lock();
        if !Self::is_current_data(&inner, server_instance, data_generation)
            || inner.first_fault.is_some()
        {
            return false;
        }
        inner.first_buffer_armed_at = None;
        inner.healthy_since.get_or_insert(now);
        Self::transition(&mut inner, RelayState::Streaming, None, None);
        true
    }

    pub fn report_fault(
        &self,
        server_instance: u64,
        data_generation: u64,
        kind: RelayFaultKind,
        reason: String,
    ) -> Option<RelayFaultEvent> {
        let mut inner = self.lock();
        if !Self::is_current_data(&inner, server_instance, data_generation) {
            return None;
        }
        Self::record_fault_locked(&mut inner, kind, reason, data_generation)
    }

    fn record_fault_locked(
        inner: &mut RelayRuntimeInner,
        kind: RelayFaultKind,
        reason: String,
        data_generation: u64,
    ) -> Option<RelayFaultEvent> {
        if inner.first_fault.is_some() {
            return None;
        }
        let fault = RelayFault {
            kind,
            reason: reason.clone(),
            server_generation: inner.server_generation,
            data_generation,
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
        inner.active_data_generation = None;
        inner.first_buffer_armed_at = None;
        inner.healthy_since = None;
        Self::transition(
            &mut inner,
            RelayState::Recovering,
            Some(fault.kind),
            Some(&fault.reason),
        );
        true
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
                        "Re-stream generation={} healthy for {}s; recovery backoff reset",
                        inner.server_generation,
                        HEALTHY_RESET_WINDOW.as_secs()
                    );
                    inner.recovery_attempt = 0;
                }
            }
        }

        if inner.ingest_kind != RelayIngestKind::Rtsp
            || inner.first_fault.is_some()
            || inner.active_data_generation.is_none()
            || inner.first_buffer_armed_at.is_none() && inner.last_buffer_at.is_none()
        {
            return None;
        }

        let data_generation = inner.active_data_generation.unwrap_or(0);
        match inner.last_buffer_at {
            None => {
                let started = inner.first_buffer_armed_at?;
                let elapsed = now.saturating_duration_since(started);
                if elapsed >= FIRST_BUFFER_TIMEOUT {
                    return Self::record_fault_locked(
                        &mut inner,
                        RelayFaultKind::FirstBufferTimeout,
                        format!(
                            "Re-stream output produced no first buffer for {}s",
                            elapsed.as_secs()
                        ),
                        data_generation,
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
                        "Re-stream generation={} data={} has no output buffer for {:.1}s; waiting for second window",
                        inner.server_generation,
                        data_generation,
                        elapsed.as_secs_f32()
                    );
                }
                if elapsed >= STALL_CONFIRMATION {
                    return Self::record_fault_locked(
                        &mut inner,
                        RelayFaultKind::BufferStall,
                        format!(
                            "Re-stream output produced no buffers for {:.1}s (two windows)",
                            elapsed.as_secs_f32()
                        ),
                        data_generation,
                    );
                }
            }
        }
        None
    }

    pub fn stop(&self) {
        let mut inner = self.lock();
        inner.active_data_generation = None;
        inner.first_buffer_armed_at = None;
        inner.last_buffer_at = None;
        inner.healthy_since = None;
        inner.first_fault = None;
        inner.error = None;
        inner.loop_alive = false;
        Self::transition(&mut inner, RelayState::Stopped, None, None);
    }
}

pub fn recovery_delay(attempt: u32) -> Duration {
    let index = attempt.saturating_sub(1) as usize;
    RECOVERY_DELAYS[index.min(RECOVERY_DELAYS.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn begin_data(health: &RelayRuntimeHealth, server_instance: u64) -> u64 {
        health
            .begin_data_generation(server_instance)
            .expect("current output instance should accept data")
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
        let base = ResolvedStartSpec {
            source: ResolvedSource::Rtsp {
                url: "rtsp://192.0.2.1/live".into(),
            },
            output: ResolvedOutput::Rtsp {
                server_port: 8554,
                mount_path: "/stream-token".into(),
            },
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

        let data_generation = begin_data(&health, instance);
        health.arm_first_buffer(instance, data_generation, Instant::now());
        assert_eq!(health.snapshot().state, RelayState::Starting);
        assert!(health.observe_buffer(instance, data_generation, Instant::now()));
        assert_eq!(health.snapshot().state, RelayState::Streaming);

        let event = health
            .report_fault(
                instance,
                data_generation,
                RelayFaultKind::Eos,
                "output EOS".into(),
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
        let generation = begin_data(&health, instance);

        tokio::time::advance(FIRST_BUFFER_TIMEOUT + Duration::from_secs(5)).await;
        assert!(health.evaluate_watchdog(Instant::now()).is_none());

        health.arm_first_buffer(instance, generation, Instant::now());
        // Prepared-state reconciliation resets the same deferred clock.
        health.arm_first_buffer(instance, generation, Instant::now());
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
        let generation = begin_data(&health, instance);
        health.arm_first_buffer(instance, generation, Instant::now());
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
    async fn listener_without_downstream_data_never_stalls() {
        let health = RelayRuntimeHealth::new(1, RelayIngestKind::Rtsp);
        let instance = health.begin_server_instance(false);
        health.loop_started(instance);
        health.mark_listener_bound(instance);

        tokio::time::advance(Duration::from_secs(60 * 60)).await;
        assert!(health.evaluate_watchdog(Instant::now()).is_none());
        assert_eq!(health.snapshot().state, RelayState::Listening);
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_faults_and_stale_data_updates_are_ignored() {
        let health = RelayRuntimeHealth::new(1, RelayIngestKind::Rtsp);
        let instance = health.begin_server_instance(false);
        health.loop_started(instance);
        health.mark_listener_bound(instance);
        let old_generation = begin_data(&health, instance);
        let new_generation = begin_data(&health, instance);

        assert!(!health.observe_buffer(instance, old_generation, Instant::now()));
        assert_eq!(health.snapshot().state, RelayState::Starting);
        assert!(health.observe_buffer(instance, new_generation, Instant::now()));

        assert!(health
            .report_fault(
                instance,
                new_generation,
                RelayFaultKind::GstError,
                "first".into(),
            )
            .is_some());
        assert!(health
            .report_fault(
                instance,
                new_generation,
                RelayFaultKind::Eos,
                "duplicate".into(),
            )
            .is_none());
    }

    #[test]
    fn eager_success_signals_cannot_erase_an_earlier_fault() {
        let health = RelayRuntimeHealth::new(1, RelayIngestKind::Udp);
        let instance = health.begin_server_instance(false);
        let generation = begin_data(&health, instance);
        assert!(health
            .report_fault(
                instance,
                generation,
                RelayFaultKind::Capability,
                "early callback failure".into(),
            )
            .is_some());

        health.mark_listener_bound(instance);
        assert!(!health.observe_buffer(instance, generation, Instant::now()));
        assert!(!health.report_streaming_without_buffer(instance, generation, Instant::now()));
        assert_eq!(
            health.snapshot().error.as_deref(),
            Some("early callback failure")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn thirty_continuous_healthy_seconds_reset_backoff() {
        let health = RelayRuntimeHealth::new(1, RelayIngestKind::Rtsp);
        assert_eq!(health.schedule_recovery_attempt().0, 1);
        let instance = health.begin_server_instance(true);
        health.loop_started(instance);
        health.mark_listener_bound(instance);
        let generation = begin_data(&health, instance);
        health.arm_first_buffer(instance, generation, Instant::now());
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
    async fn udp_is_exempt_from_silence_but_not_runtime_errors() {
        let health = RelayRuntimeHealth::new(1, RelayIngestKind::Udp);
        let instance = health.begin_server_instance(false);
        health.loop_started(instance);
        health.mark_listener_bound(instance);
        let generation = begin_data(&health, instance);
        health.arm_first_buffer(instance, generation, Instant::now());

        tokio::time::advance(Duration::from_secs(120)).await;
        assert!(health.evaluate_watchdog(Instant::now()).is_none());
        let event = health.report_fault(
            instance,
            generation,
            RelayFaultKind::GstError,
            "UDP media error".into(),
        );
        assert!(event.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn eager_arming_faults_without_a_playing_notification() {
        let health = RelayRuntimeHealth::new(1, RelayIngestKind::Rtsp);
        let instance = health.begin_server_instance(false);
        let generation = begin_data(&health, instance);
        health.arm_first_buffer(instance, generation, Instant::now());

        tokio::time::advance(FIRST_BUFFER_TIMEOUT).await;
        let event = health
            .evaluate_watchdog(Instant::now())
            .expect("an eagerly armed output must not wait forever for PLAYING");
        assert_eq!(event.fault.kind, RelayFaultKind::FirstBufferTimeout);
    }

    #[tokio::test(start_paused = true)]
    async fn silence_exempt_output_can_become_healthy_without_a_buffer() {
        let health = RelayRuntimeHealth::new(1, RelayIngestKind::Udp);
        let instance = health.begin_server_instance(false);
        let generation = begin_data(&health, instance);
        assert!(health.report_streaming_without_buffer(instance, generation, Instant::now()));
        tokio::time::advance(Duration::from_secs(120)).await;
        assert!(health.evaluate_watchdog(Instant::now()).is_none());
        assert_eq!(health.snapshot().state, RelayState::Streaming);
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
