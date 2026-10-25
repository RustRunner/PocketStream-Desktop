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
    PermanentGstError,
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
            Self::PermanentGstError => "permanent_gst_error",
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
    pub upstream_ready: Option<super::rtsp_server::UpstreamReady>,
    pub health: std::sync::Arc<RelayRuntimeHealth>,
    pub event_tx: RelayEventSender,
    pub server_instance: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayIngestKind {
    Rtsp,
    Udp,
}

/// Fully validated start identity. Credentials and SRT access controls
/// deliberately participate in `PartialEq`: changing either must replace the
/// runtime even when the public relay endpoint is otherwise identical.
///
/// Do not derive `Debug`; this structure contains credentials, a passphrase,
/// and the token-bearing RTSP mount path.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedStartSpec {
    pub source: ResolvedSource,
    pub output: ResolvedOutput,
    pub bind_interface: Option<String>,
    pub bind_identity: Option<crate::network::interface::NativeIdentity>,
    pub bind_scope: crate::network::bindings::BindScope,
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
    Srt {
        server_port: u16,
        passphrase: String,
        latency_ms: u32,
        stream_id: String,
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
            ResolvedOutput::Srt { .. } => crate::config::RestreamProtocol::Srt,
        }
    }

    pub fn server_port(&self) -> u16 {
        match self.output {
            ResolvedOutput::Rtsp { server_port, .. } | ResolvedOutput::Srt { server_port, .. } => {
                server_port
            }
        }
    }

    pub fn mount_path(&self) -> &str {
        match &self.output {
            ResolvedOutput::Rtsp { mount_path, .. } => mount_path,
            ResolvedOutput::Srt { .. } => "",
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
        match &self.output {
            ResolvedOutput::Rtsp { .. } => format!(
                "rtsp://{}:{}{}",
                self.advertised_ip,
                self.server_port(),
                self.mount_path()
            ),
            ResolvedOutput::Srt { stream_id, .. } => {
                let endpoint = format!("srt://{}:{}", self.advertised_ip, self.server_port());
                if stream_id.is_empty() {
                    endpoint
                } else {
                    format!("{endpoint}?streamid={}", encode_query_value(stream_id))
                }
            }
        }
    }

    pub fn display_url(&self) -> String {
        let scheme = match self.output {
            ResolvedOutput::Rtsp { .. } => "rtsp",
            ResolvedOutput::Srt { .. } => "srt",
        };
        format!("{scheme}://{}:{}", self.advertised_ip, self.server_port())
    }
}

fn encode_query_value(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[(byte >> 4) as usize]));
            encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    encoded
}

#[derive(Clone)]
pub struct RelayHealthSnapshot {
    pub server_generation: u64,
    pub server_instance: u64,
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
            server_instance: inner.server_instance,
            state: inner.state,
            error: inner.error.clone(),
            recovery_attempt: inner.recovery_attempt,
            loop_alive: inner.loop_alive,
        }
    }

    pub fn server_generation(&self) -> u64 {
        self.lock().server_generation
    }

    pub fn permanent_failure(&self) -> bool {
        self.lock()
            .first_fault
            .as_ref()
            .is_some_and(|f| f.kind == RelayFaultKind::PermanentGstError)
    }

    pub fn upstream_allowed(&self) -> bool {
        let inner = self.lock();
        inner.state != RelayState::Stopped && inner.first_fault.is_none()
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
        if inner.server_instance != server_instance || inner.first_fault.is_some() {
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
            && inner.first_fault.is_none()
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
            if fault.kind == RelayFaultKind::PermanentGstError {
                RelayState::Failed
            } else {
                RelayState::Recovering
            },
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybackState {
    Stopped,
    Starting,
    Playing,
    Recovering,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybackFaultKind {
    BusError,
    Eos,
    FirstFrameTimeout,
    FrameStall,
    DeviceLoss,
    Configuration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlaybackFault {
    pub kind: PlaybackFaultKind,
    pub domain: Option<String>,
    pub code: Option<i32>,
    pub reason: String,
    pub retryable: bool,
}

impl PlaybackFault {
    pub fn new(kind: PlaybackFaultKind, reason: impl Into<String>, retryable: bool) -> Self {
        Self {
            kind,
            domain: None,
            code: None,
            reason: reason.into(),
            retryable,
        }
    }
}

pub struct PlaybackSnapshot {
    pub state: PlaybackState,
    pub fault: Option<PlaybackFault>,
    pub attempt: u32,
    pub next_retry_secs: Option<u64>,
    pub generation: u64,
    pub active: bool,
}

struct PlaybackInner {
    state: PlaybackState,
    generation: u64,
    active: bool,
    first_fault: Option<PlaybackFault>,
    fault: Option<PlaybackFault>,
    started: Option<Instant>,
    last_buffer: Option<Instant>,
    healthy_since: Option<Instant>,
    attempt: u32,
    next_retry: Option<Instant>,
}

/// Same first-fault retirement as the relay. Callbacks only touch this record;
/// the playback supervisor alone owns pipeline teardown, recording and retry.
pub struct PlaybackHealth {
    inner: Mutex<PlaybackInner>,
}

impl PlaybackHealth {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(PlaybackInner {
                state: PlaybackState::Starting,
                generation: 0,
                active: false,
                first_fault: None,
                fault: None,
                started: None,
                last_buffer: None,
                healthy_since: None,
                attempt: 0,
                next_retry: Some(Instant::now()),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, PlaybackInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn snapshot(&self) -> PlaybackSnapshot {
        let s = self.lock();
        PlaybackSnapshot {
            state: s.state,
            fault: s.fault.clone(),
            attempt: s.attempt,
            generation: s.generation,
            active: s.active,
            next_retry_secs: s.next_retry.map(|t| {
                let d = t.saturating_duration_since(Instant::now());
                d.as_secs() + u64::from(d.subsec_nanos() != 0)
            }),
        }
    }

    pub fn due(&self, now: Instant) -> bool {
        self.lock().next_retry.is_some_and(|t| now >= t)
    }

    pub fn begin_attempt(&self) -> u64 {
        let mut s = self.lock();
        s.generation = s.generation.wrapping_add(1).max(1);
        s.active = true;
        s.first_fault = None;
        s.started = None;
        s.last_buffer = None;
        s.healthy_since = None;
        s.next_retry = None;
        s.generation
    }

    pub fn pipeline_started(&self, generation: u64, now: Instant) {
        let mut s = self.lock();
        if s.active && s.generation == generation {
            s.started = Some(now);
        }
    }

    pub fn observe_buffer(&self, generation: u64, now: Instant) -> bool {
        let mut s = self.lock();
        if !s.active || s.generation != generation {
            return false;
        }
        if s.last_buffer
            .is_some_and(|last| now.saturating_duration_since(last) >= Duration::from_secs(3))
        {
            s.healthy_since = None;
        }
        s.last_buffer = Some(now);
        s.healthy_since.get_or_insert(now);
        s.state = PlaybackState::Playing;
        s.fault = None;
        true
    }

    pub fn record_fault(&self, generation: u64, fault: PlaybackFault) -> bool {
        let mut s = self.lock();
        if !s.active || s.generation != generation {
            return false;
        }
        // Retirement precedes slow detach/Null. A late buffer cannot recover it.
        s.active = false;
        s.first_fault = Some(fault.clone());
        s.state = if fault.retryable {
            PlaybackState::Recovering
        } else {
            PlaybackState::Failed
        };
        log::warn!(
            "Playback generation={} state={:?} fault={:?} attempt={} reason={}",
            generation,
            s.state,
            fault.kind,
            s.attempt,
            fault.reason
        );
        s.fault = Some(fault);
        s.healthy_since = None;
        s.next_retry = None;
        true
    }

    pub fn watchdog(&self, now: Instant, stall: Duration) -> Option<PlaybackFault> {
        let mut s = self.lock();
        if let Some(fault) = &s.first_fault {
            return Some(fault.clone());
        }
        if !s.active {
            return None;
        }
        let fault = match s.last_buffer {
            Some(last) if now.saturating_duration_since(last) >= stall => Some(PlaybackFault::new(
                PlaybackFaultKind::FrameStall,
                "No usable frames for 3 seconds",
                true,
            )),
            None if s
                .started
                .is_some_and(|t| now.saturating_duration_since(t) >= FIRST_BUFFER_TIMEOUT) =>
            {
                Some(PlaybackFault::new(
                    PlaybackFaultKind::FirstFrameTimeout,
                    "No first frame within 15 seconds",
                    true,
                ))
            }
            _ => None,
        };
        if fault.is_none()
            && s.healthy_since
                .is_some_and(|t| now.saturating_duration_since(t) >= HEALTHY_RESET_WINDOW)
        {
            s.attempt = 0;
        }
        let generation = s.generation;
        drop(s);
        if let Some(fault) = &fault {
            self.record_fault(generation, fault.clone());
        }
        fault
    }

    pub fn schedule_recovery(&self) {
        let mut s = self.lock();
        if s.state != PlaybackState::Recovering || s.next_retry.is_some() {
            return;
        }
        s.attempt = s.attempt.saturating_add(1);
        s.next_retry = Some(Instant::now() + recovery_delay(s.attempt));
    }

    pub fn wake_ready(&self) {
        let mut s = self.lock();
        if s.state == PlaybackState::Recovering && s.next_retry.is_some() {
            s.next_retry = Some(Instant::now());
        }
    }

    pub fn retry(&self) {
        let mut s = self.lock();
        if matches!(s.state, PlaybackState::Failed | PlaybackState::Recovering) {
            s.state = PlaybackState::Recovering;
            s.active = false;
            s.next_retry = Some(Instant::now());
            s.first_fault = None;
        }
    }

    pub fn stop(&self) {
        let mut s = self.lock();
        s.active = false;
        s.state = PlaybackState::Stopped;
        s.next_retry = None;
        s.first_fault = None;
    }
}

#[cfg(test)]
mod playback_tests {
    use super::*;
    const STALL: Duration = Duration::from_secs(3);

    fn fault(kind: PlaybackFaultKind) -> PlaybackFault {
        PlaybackFault::new(kind, "latched fault", true)
    }

    #[tokio::test(start_paused = true)]
    async fn stable_latched_error_retires_before_late_frame_without_repeat_events() {
        let h = PlaybackHealth::new();
        let generation = h.begin_attempt();
        h.pipeline_started(generation, Instant::now());
        assert!(h.record_fault(generation, fault(PlaybackFaultKind::BusError)));
        assert!(!h.observe_buffer(generation, Instant::now()));
        assert!(!h.record_fault(generation, fault(PlaybackFaultKind::Eos)));
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(1)).await;
            assert_eq!(
                h.watchdog(Instant::now(), STALL).unwrap().kind,
                PlaybackFaultKind::BusError
            );
        }
        h.schedule_recovery();
        assert_eq!(h.snapshot().attempt, 1);
        assert!(h.due(Instant::now()));
        let replacement = h.begin_attempt();
        assert!(!h.observe_buffer(generation, Instant::now()));
        assert_eq!(h.snapshot().state, PlaybackState::Recovering);
        assert!(h.observe_buffer(replacement, Instant::now()));
        assert_eq!(h.snapshot().state, PlaybackState::Playing);
    }

    #[tokio::test(start_paused = true)]
    async fn first_frame_deadline_covers_starting_and_handshake_without_frames() {
        let h = PlaybackHealth::new();
        let generation = h.begin_attempt();
        h.pipeline_started(generation, Instant::now());
        tokio::time::advance(FIRST_BUFFER_TIMEOUT - Duration::from_millis(1)).await;
        assert!(h.watchdog(Instant::now(), STALL).is_none());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(
            h.watchdog(Instant::now(), STALL).unwrap().kind,
            PlaybackFaultKind::FirstFrameTimeout
        );
        assert!(!h.observe_buffer(generation, Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn first_buffer_starts_playing_then_three_second_stall_retires_it() {
        let h = PlaybackHealth::new();
        let g = h.begin_attempt();
        h.pipeline_started(g, Instant::now());
        tokio::time::advance(Duration::from_secs(14)).await;
        h.observe_buffer(g, Instant::now());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(h.watchdog(Instant::now(), STALL).is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            h.watchdog(Instant::now(), STALL).unwrap().kind,
            PlaybackFaultKind::FrameStall
        );
        assert_eq!(h.snapshot().state, PlaybackState::Recovering);
    }

    #[tokio::test(start_paused = true)]
    async fn all_backoff_stages_cap_and_readiness_wakes_early() {
        let h = PlaybackHealth::new();
        for attempt in 1..=9 {
            let g = h.begin_attempt();
            h.record_fault(g, fault(PlaybackFaultKind::DeviceLoss));
            h.schedule_recovery();
            assert_eq!(h.snapshot().attempt, attempt);
            assert_eq!(
                h.snapshot().next_retry_secs,
                Some(recovery_delay(attempt).as_secs())
            );
            h.wake_ready();
            assert!(h.due(Instant::now()));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn continuous_frames_reset_attempts_only_after_thirty_seconds() {
        let h = PlaybackHealth::new();
        let g = h.begin_attempt();
        h.record_fault(g, fault(PlaybackFaultKind::Eos));
        h.schedule_recovery();
        let g = h.begin_attempt();
        h.observe_buffer(g, Instant::now());
        for _ in 0..29 {
            tokio::time::advance(Duration::from_secs(1)).await;
            h.observe_buffer(g, Instant::now());
            h.watchdog(Instant::now(), STALL);
        }
        assert_eq!(h.snapshot().attempt, 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        h.observe_buffer(g, Instant::now());
        h.watchdog(Instant::now(), STALL);
        assert_eq!(h.snapshot().attempt, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn permanent_failure_waits_for_manual_retry_even_after_readiness() {
        let h = PlaybackHealth::new();
        let g = h.begin_attempt();
        h.record_fault(
            g,
            PlaybackFault::new(
                PlaybackFaultKind::Configuration,
                "Check camera settings",
                false,
            ),
        );
        h.schedule_recovery();
        h.wake_ready();
        tokio::time::advance(Duration::from_secs(120)).await;
        assert_eq!(h.snapshot().state, PlaybackState::Failed);
        assert!(!h.due(Instant::now()));
        h.retry();
        assert!(h.due(Instant::now()));
        let replacement = h.begin_attempt();
        assert_eq!(h.snapshot().state, PlaybackState::Recovering);
        assert!(!h.observe_buffer(g, Instant::now()));
        assert!(h.observe_buffer(replacement, Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn stop_cancels_every_backoff_and_rejects_late_buffers() {
        for stage in 1..=RECOVERY_DELAYS.len() {
            let h = PlaybackHealth::new();
            let mut g = 0;
            for _ in 0..stage {
                g = h.begin_attempt();
                h.record_fault(g, fault(PlaybackFaultKind::BusError));
                h.schedule_recovery();
            }
            assert_eq!(
                h.snapshot().next_retry_secs,
                Some(RECOVERY_DELAYS[stage - 1].as_secs())
            );
            h.stop();
            h.wake_ready();
            tokio::time::advance(Duration::from_secs(120)).await;
            assert!(!h.due(Instant::now()));
            assert!(!h.observe_buffer(g, Instant::now()));
            assert_eq!(h.snapshot().state, PlaybackState::Stopped);
        }
    }
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
            bind_identity: None,

            bind_scope: crate::network::bindings::BindScope::default(),
            bind_address: None,
            advertised_ip: "192.0.2.10".into(),
            username: "camera".into(),
            password: "old".into(),
        };
        let mut changed = base.clone();
        changed.password = "new".into();
        assert!(base != changed);
    }

    #[test]
    fn srt_identity_includes_access_controls() {
        let base = ResolvedStartSpec {
            source: ResolvedSource::Udp { port: 8_600 },
            output: ResolvedOutput::Srt {
                server_port: 8_890,
                passphrase: "strongPass1".into(),
                latency_ms: 125,
                stream_id: "field unit".into(),
            },
            bind_interface: None,
            bind_identity: None,

            bind_scope: crate::network::bindings::BindScope::default(),
            bind_address: None,
            advertised_ip: "192.0.2.10".into(),
            username: String::new(),
            password: String::new(),
        };

        let mut passphrase_changed = base.clone();
        let ResolvedOutput::Srt { passphrase, .. } = &mut passphrase_changed.output else {
            unreachable!()
        };
        *passphrase = "replacement1".into();
        assert!(base != passphrase_changed);

        let mut stream_id_changed = base.clone();
        let ResolvedOutput::Srt { stream_id, .. } = &mut stream_id_changed.output else {
            unreachable!()
        };
        *stream_id = "other".into();
        assert!(base != stream_id_changed);
    }

    #[test]
    fn srt_urls_encode_stream_id_and_never_include_passphrase() {
        let mut spec = ResolvedStartSpec {
            source: ResolvedSource::Udp { port: 8_600 },
            output: ResolvedOutput::Srt {
                server_port: 8_890,
                passphrase: "strongPass1".into(),
                latency_ms: 125,
                stream_id: "#!::r=Pocket Stream/%#&=,snowman-☃".into(),
            },
            bind_interface: Some("ZeroTier".into()),
            bind_identity: None,

            bind_scope: crate::network::bindings::BindScope::default(),
            bind_address: Some("192.0.2.10".into()),
            advertised_ip: "192.0.2.10".into(),
            username: String::new(),
            password: String::new(),
        };

        assert_eq!(
            spec.client_url(),
            "srt://192.0.2.10:8890?streamid=%23%21%3A%3Ar%3DPocket%20Stream%2F%25%23%26%3D%2Csnowman-%E2%98%83"
        );
        assert_eq!(spec.display_url(), "srt://192.0.2.10:8890");
        assert!(!spec.client_url().contains("strongPass1"));

        let ResolvedOutput::Srt { stream_id, .. } = &mut spec.output else {
            unreachable!()
        };
        stream_id.clear();
        assert_eq!(spec.client_url(), "srt://192.0.2.10:8890");
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
    async fn permanent_media_fault_retires_and_stays_failed_until_explicit_start() {
        let health = RelayRuntimeHealth::new(1, RelayIngestKind::Rtsp);
        let instance = health.begin_server_instance(false);
        health.loop_started(instance);
        health.mark_listener_bound(instance);
        let generation = begin_data(&health, instance);
        let fault = health
            .report_fault(
                instance,
                generation,
                RelayFaultKind::PermanentGstError,
                "Check credentials".into(),
            )
            .unwrap();
        assert!(!health.observe_buffer(instance, generation, Instant::now()));
        assert!(health.begin_data_generation(instance).is_none());
        assert!(health.accept_fault(&fault.fault));
        assert!(health.permanent_failure());
        tokio::time::advance(Duration::from_secs(120)).await;
        assert!(health.evaluate_watchdog(Instant::now()).is_none());
        assert_eq!(health.snapshot().state, RelayState::Failed);
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
