//! Relay listener, settings transactions, topology and firewall-lease ownership.
use super::{
    relay::{
        RelayEventReceiver, RelayEventSender, RelayFaultEvent, RelayRuntimeHealth, RelayState,
        RelaySupervisorEvent, ResolvedOutput, ResolvedSource, ResolvedStartSpec,
        RestreamBuildFailure, RestreamBuildFailureKind, RestreamRuntimeContext,
    },
    rtsp_server,
    rtsp_server::{RtspRestreamer, RtspRuntimeProbe},
    source::{
        build_input_url, camera_stream_path, configure_tcp_rtspsrc, preflight_target,
        redact_relay_text, stream_target,
    },
    srt_server,
    srt_server::{SrtRestreamer, SrtRuntimeProbe},
    state, status,
};
use crate::{
    config::{
        AppConfig, AppSettings, RestreamProtocol, RestreamSettingsUpdate, SrtPassphraseState,
        StreamProtocol,
    },
    error::AppError,
    network::{
        bindings::{self, BindScope},
        firewall::{self, FirewallOutcome, FirewallRule, PolicyResult},
        interface::NativeIdentity,
        route::CameraTarget,
    },
};
use gstreamer as gst;
use serde::Serialize;
use std::sync::Arc;
use std::{collections::HashSet, future::Future, pin::Pin};
use tokio::sync::{Mutex, Notify};

type RelayFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
type BindingResolution = Result<(Option<NativeIdentity>, BindScope), AppError>;

// These instance boundaries are shared with the supervisor.
trait RelayBindings: Send + Sync {
    fn revision(&self) -> u64;
    fn resolve<'a>(
        &'a self,
        alias: Option<&'a str>,
        id: Option<&'a str>,
        adopted: &'a HashSet<String>,
    ) -> RelayFuture<'a, BindingResolution>;
}

struct NativeBindings;
impl RelayBindings for NativeBindings {
    fn revision(&self) -> u64 {
        bindings::revision()
    }
    fn resolve<'a>(
        &'a self,
        alias: Option<&'a str>,
        id: Option<&'a str>,
        adopted: &'a HashSet<String>,
    ) -> RelayFuture<'a, BindingResolution> {
        Box::pin(bindings::resolve(alias, id, adopted))
    }
}

trait RelayPolicy: Send + Sync {
    fn ensure<'a>(
        &'a self,
        rule: FirewallRule,
        port: u16,
        interface: Option<NativeIdentity>,
        abort: RelayFuture<'a, ()>,
    ) -> RelayFuture<'a, PolicyResult>;
    fn disable(&self, rule: FirewallRule) -> RelayFuture<'_, PolicyResult>;
}

struct NativePolicy;
impl RelayPolicy for NativePolicy {
    fn ensure<'a>(
        &'a self,
        rule: FirewallRule,
        port: u16,
        interface: Option<NativeIdentity>,
        abort: RelayFuture<'a, ()>,
    ) -> RelayFuture<'a, PolicyResult> {
        Box::pin(firewall::ensure(rule, port, interface, abort))
    }
    fn disable(&self, rule: FirewallRule) -> RelayFuture<'_, PolicyResult> {
        Box::pin(firewall::disable(rule, std::future::pending()))
    }
}

fn explicit_bind_changed(
    spec: &ResolvedStartSpec,
    identity: Option<&NativeIdentity>,
    next: &BindScope,
) -> bool {
    match next {
        BindScope::Interface { alias, address, .. } => {
            Some(alias) != spec.bind_interface.as_ref()
                || Some(address) != spec.bind_address.as_ref()
                || identity != spec.bind_identity.as_ref()
        }
        _ => true,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum BindValidity {
    Unchanged,
    Refreshed(BindScope),
    Invalidated(String),
}

fn classify_bind_validity(
    spec: &ResolvedStartSpec,
    observation: BindingResolution,
) -> BindValidity {
    match &spec.bind_scope {
        BindScope::Unknown { .. } => BindValidity::Unchanged,
        BindScope::AllAddresses { .. } => BindValidity::Refreshed(match observation {
            Ok((_, scope @ BindScope::AllAddresses { .. })) => scope,
            Ok(_) => BindScope::Unknown {
                reason: "Wildcard binding observation unavailable".into(),
            },
            Err(error) => BindScope::Unknown {
                reason: redact_relay_text(&error.to_string(), spec.mount_path()),
            },
        }),
        BindScope::Interface { .. } => match observation {
            Ok((identity, scope)) if !explicit_bind_changed(spec, identity.as_ref(), &scope) => {
                BindValidity::Refreshed(scope)
            }
            Ok(_) => {
                BindValidity::Invalidated("Selected bind identity, alias or address changed".into())
            }
            Err(error) => BindValidity::Invalidated(redact_relay_text(
                &format!("Selected bind resolution failed: {error}"),
                spec.mount_path(),
            )),
        },
    }
}

async fn bind_validity(
    provider: &dyn RelayBindings,
    spec: &ResolvedStartSpec,
    adopted: &HashSet<String>,
    generation: u64,
    phase: &str,
) -> BindValidity {
    let Some(captured) = scope_revision(&spec.bind_scope) else {
        return BindValidity::Unchanged;
    };
    let checked = provider.revision();
    if captured == checked {
        return BindValidity::Unchanged;
    }
    let explicit = matches!(spec.bind_scope, BindScope::Interface { .. });
    let observation = provider
        .resolve(
            if explicit {
                spec.bind_interface.as_deref()
            } else {
                None
            },
            if explicit {
                spec.bind_identity.as_ref().map(|i| i.guid.as_str())
            } else {
                None
            },
            adopted,
        )
        .await;
    let observed = observation
        .as_ref()
        .ok()
        .and_then(|(_, scope)| scope_revision(scope));
    let result = classify_bind_validity(spec, observation);
    let (label, reason) = match &result {
        BindValidity::Unchanged => return result,
        BindValidity::Refreshed(BindScope::Unknown { reason }) => ("refreshed", reason.as_str()),
        BindValidity::Refreshed(_) => ("refreshed", "none"),
        BindValidity::Invalidated(reason) => ("invalidated", reason.as_str()),
    };
    log::info!("event=relay_bind_validity generation={} phase={} scope={} result={} captured_revision={} checked_revision={} observed_revision={} reason={}",
        generation, phase, if explicit { "interface" } else { "all" }, label, captured, checked,
        observed.map_or_else(|| "unknown".into(), |r| r.to_string()),
        crate::network::log_value(&reason.chars().take(256).collect::<String>()));
    result
}

#[derive(Debug, Clone, Serialize)]
pub struct RestreamServerInfo {
    pub bind_scope: BindScope,
    pub firewall: FirewallOutcome,
    pub protocol: RestreamProtocol,
    pub server_url: String,
    pub display_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestreamOperationResult {
    pub selected_protocol: RestreamProtocol,
    pub desired: bool,
    pub server_info: Option<RestreamServerInfo>,
}

pub(super) enum RestreamServer {
    Rtsp(RtspRestreamer),
    Srt(SrtRestreamer),
}

#[derive(Clone)]
enum RelayFaultProbe {
    Rtsp(RtspRuntimeProbe),
    Srt(SrtRuntimeProbe),
}

impl RelayFaultProbe {
    pub(super) fn poll_fault(&self) -> Option<RelayFaultEvent> {
        match self {
            Self::Rtsp(probe) => probe.poll_fault(),
            Self::Srt(probe) => probe.poll_fault(),
        }
    }
}

impl RestreamServer {
    pub(super) fn protocol(&self) -> RestreamProtocol {
        match self {
            Self::Rtsp(_) => RestreamProtocol::Rtsp,
            Self::Srt(_) => RestreamProtocol::Srt,
        }
    }

    pub(super) fn server_generation(&self) -> u64 {
        match self {
            Self::Rtsp(server) => server.server_generation(),
            Self::Srt(server) => server.server_generation(),
        }
    }

    pub(super) fn connected_clients(&self) -> u32 {
        match self {
            Self::Rtsp(server) => server.connected_clients(),
            Self::Srt(server) => server.connected_clients(),
        }
    }

    pub(super) fn client_limit(&self) -> u32 {
        match self {
            Self::Rtsp(server) => server.client_limit(),
            Self::Srt(server) => server.client_limit(),
        }
    }

    pub(super) fn bandwidth_kbps(&self) -> f64 {
        match self {
            Self::Rtsp(server) => server.bandwidth_kbps(),
            Self::Srt(server) => server.bandwidth_kbps(),
        }
    }

    fn fault_probe(&self) -> RelayFaultProbe {
        match self {
            Self::Rtsp(server) => RelayFaultProbe::Rtsp(server.fault_probe()),
            Self::Srt(server) => RelayFaultProbe::Srt(server.fault_probe()),
        }
    }

    pub(super) fn loop_alive(&self) -> bool {
        match self {
            Self::Rtsp(server) => server.loop_alive(),
            Self::Srt(server) => server.loop_alive(),
        }
    }

    pub(super) fn udp_ingest_port(&self) -> Option<u16> {
        match self {
            Self::Rtsp(server) => server.udp_ingest_port(),
            Self::Srt(server) => server.udp_ingest_port(),
        }
    }

    pub(super) async fn shutdown(&mut self) {
        match self {
            Self::Rtsp(server) => server.shutdown().await,
            Self::Srt(server) => server.shutdown().await,
        }
    }
}

// One schedule and a lifetime failure budget per desired listener generation.
// This does not own a rule: firewall_generation remains the conservative lease.
struct PolicyRetry {
    generation: u64,
    admission_attempt: u32,
    transient_failures: u8,
    due: Option<tokio::time::Instant>,
}

impl PolicyRetry {
    fn new(generation: u64) -> Self {
        Self {
            generation,
            admission_attempt: 0,
            transient_failures: 0,
            due: None,
        }
    }

    fn observe(&mut self, result: &PolicyResult, retiring: bool, supervisor: bool) {
        // A cancellation sentinel says nothing about policy or the pending request.
        if !result.admitted && result.outcome == FirewallOutcome::Inactive {
            return;
        }
        if result.admitted {
            self.admission_attempt = 0;
        }
        let delay = match &result.outcome {
            FirewallOutcome::Failed {
                uncertain: true, ..
            } => None,
            FirewallOutcome::Unavailable { .. } if !result.admitted => {
                self.admission_attempt = self.admission_attempt.saturating_add(1);
                Some(super::relay::recovery_delay(
                    self.admission_attempt.saturating_add(1),
                ))
            }
            FirewallOutcome::Inactive if result.admitted && retiring => return,
            FirewallOutcome::Failed {
                stage,
                uncertain: false,
                ..
            } if result.admitted && retryable_policy_stage(stage, retiring) => {
                if supervisor {
                    self.transient_failures = self.transient_failures.saturating_add(1).min(5);
                }
                (self.transient_failures < 5).then_some(std::time::Duration::from_secs(60))
            }
            _ => None,
        };
        self.due = delay.map(|delay| tokio::time::Instant::now() + delay);
    }
}

fn retryable_policy_stage(stage: &str, retiring: bool) -> bool {
    matches!(
        stage,
        "shape"
            | "prepare"
            | "blocks"
            | "enable"
            | "readback"
            | "native_timeout"
            | "native_canceled"
            | "native_containment"
            | "native_output"
            | "native_report"
    ) || (retiring && stage == "disable")
}

fn clean_firewall(outcome: &FirewallOutcome) -> bool {
    matches!(outcome, FirewallOutcome::Applied { verified_shape: true, observed_block_rules, .. }
        if observed_block_rules.is_empty())
}

pub(super) struct RelayData {
    pub(super) firewall: FirewallOutcome,
    pub(super) firewall_generation: Option<(u64, FirewallRule)>,
    policy_retry: Option<PolicyRetry>,
    pub(super) restream_target: Option<CameraTarget>,
    pub(super) selected_protocol: RestreamProtocol,
    pub(super) restream_server: Option<RestreamServer>,
    pub(super) restream_desired: bool,
    pub(super) restream_spec: Option<ResolvedStartSpec>,
    pub(super) restream_health: Option<Arc<RelayRuntimeHealth>>,
    pub(super) restream_intent_epoch: Option<u64>,
    pub(super) restream_start_time: Option<std::time::Instant>,
}

impl RelayData {
    pub(super) fn new(selected_protocol: RestreamProtocol) -> Self {
        Self {
            selected_protocol,
            firewall: FirewallOutcome::Inactive,
            firewall_generation: None,
            policy_retry: None,
            restream_target: None,
            restream_server: None,
            restream_desired: false,
            restream_spec: None,
            restream_health: None,
            restream_intent_epoch: None,
            restream_start_time: None,
        }
    }

    fn eligible_policy_retry(&self) -> Option<(&PolicyRetry, &ResolvedStartSpec)> {
        if !self.restream_desired {
            return None;
        }
        let retry = self.policy_retry.as_ref()?;
        let health = self.restream_health.as_ref()?.snapshot();
        let server = self.restream_server.as_ref()?;
        let spec = self.restream_spec.as_ref()?;
        if retry.generation != health.server_generation
            || server.server_generation() != retry.generation
            || !server.loop_alive()
            || !health.loop_alive
            || health.error.is_some()
            || !matches!(health.state, RelayState::Listening | RelayState::Streaming)
            || (spec.bind_interface.is_some()
                && (spec.bind_identity.is_none() || spec.bind_address.is_none()))
        {
            return None;
        }
        Some((retry, spec))
    }

    pub(super) fn firewall_next_retry_secs(&self) -> Option<u64> {
        let (retry, _) = self.eligible_policy_retry()?;
        let remaining = retry
            .due?
            .saturating_duration_since(tokio::time::Instant::now());
        Some(
            remaining
                .as_secs()
                .saturating_add(u64::from(remaining.subsec_nanos() != 0)),
        )
    }
}

pub(super) struct RelayService {
    bindings: Arc<dyn RelayBindings>,
    policy: Arc<dyn RelayPolicy>,
    state: state::RelaySlot,
    status: status::StatusPublisher,
    readiness: Option<Arc<crate::network::readiness::CameraReadiness>>,
    restream_epoch: Arc<std::sync::atomic::AtomicU64>,
    restream_generation: Arc<std::sync::atomic::AtomicU64>,
    restream_transaction: Arc<Mutex<()>>,
    relay_lifecycle: Arc<Mutex<()>>,
    relay_wake: Arc<Notify>,
    relay_event_tx: RelayEventSender,
    relay_event_rx: std::sync::Mutex<Option<RelayEventReceiver>>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RestreamStopIntent {
    epoch: u64,
    target_generation: Option<u64>,
    firewall_generation: Option<u64>,
    was_desired: bool,
}

#[derive(Clone)]
pub(super) struct RelaySupervisorContext {
    bindings: Arc<dyn RelayBindings>,
    policy: Arc<dyn RelayPolicy>,
    state: state::RelaySlot,
    status: status::StatusPublisher,
    restream_epoch: Arc<std::sync::atomic::AtomicU64>,
    relay_lifecycle: Arc<Mutex<()>>,
    relay_wake: Arc<Notify>,
    relay_event_tx: RelayEventSender,
    readiness: Arc<crate::network::readiness::CameraReadiness>,
    restream_generation: Arc<std::sync::atomic::AtomicU64>,
}

impl RelayService {
    #[cfg(test)]
    pub(super) fn test_epoch(&self) -> u64 {
        self.restream_epoch
            .load(std::sync::atomic::Ordering::Acquire)
    }
    pub(super) fn new(
        state: state::RelaySlot,
        status: status::StatusPublisher,
        readiness: Option<Arc<crate::network::readiness::CameraReadiness>>,
    ) -> Self {
        Self::with_providers(
            state,
            status,
            readiness,
            Arc::new(NativeBindings),
            Arc::new(NativePolicy),
        )
    }

    fn with_providers(
        state: state::RelaySlot,
        status: status::StatusPublisher,
        readiness: Option<Arc<crate::network::readiness::CameraReadiness>>,
        bindings: Arc<dyn RelayBindings>,
        policy: Arc<dyn RelayPolicy>,
    ) -> Self {
        let (relay_event_tx, relay_event_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            bindings,
            policy,
            state,
            status,
            readiness,
            restream_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            restream_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            restream_transaction: Arc::new(Mutex::new(())),
            relay_lifecycle: Arc::new(Mutex::new(())),
            relay_wake: Arc::new(Notify::new()),
            relay_event_tx,
            relay_event_rx: std::sync::Mutex::new(Some(relay_event_rx)),
        }
    }
    pub(super) fn supervisor(&self) -> Option<(RelayEventReceiver, RelaySupervisorContext)> {
        let readiness = self.readiness.clone()?;
        let events = self
            .relay_event_rx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()?;
        Some((
            events,
            RelaySupervisorContext {
                bindings: self.bindings.clone(),
                policy: self.policy.clone(),
                state: self.state.clone(),
                status: self.status.clone(),
                restream_epoch: self.restream_epoch.clone(),
                relay_lifecycle: self.relay_lifecycle.clone(),
                relay_wake: self.relay_wake.clone(),
                relay_event_tx: self.relay_event_tx.clone(),
                readiness,
                restream_generation: self.restream_generation.clone(),
            },
        ))
    }
    async fn refresh_status(&self) {
        self.status.refresh().await;
    }
    #[cfg(test)]
    pub(super) async fn resolve_restream_start_spec(
        settings: &AppSettings,
        adopted: &std::collections::HashSet<String>,
    ) -> Result<ResolvedStartSpec, AppError> {
        Self::resolve_restream_start_spec_with(&NativeBindings, settings, adopted).await
    }

    async fn resolve_restream_start_spec_with(
        provider: &dyn RelayBindings,
        settings: &AppSettings,
        adopted: &HashSet<String>,
    ) -> Result<ResolvedStartSpec, AppError> {
        let (bind_interface, output) = resolve_selected_restream_output(settings)?;
        let source = match settings.stream.protocol {
            StreamProtocol::Rtsp => ResolvedSource::Rtsp {
                url: build_input_url(settings)?,
            },
            StreamProtocol::Udp => ResolvedSource::Udp {
                port: settings.stream.udp_port,
            },
        };
        let saved_id = match settings.restream_protocol {
            RestreamProtocol::Rtsp => settings.rtsp_server.bind_interface_id.as_deref(),
            RestreamProtocol::Srt => settings.srt_server.bind_interface_id.as_deref(),
        };
        // An unresolved legacy alias remains unavailable until explicitly chosen.
        if bind_interface.is_some() && saved_id.is_none() && !cfg!(test) {
            return Err(AppError::Stream(
                "Choose the unavailable saved bind interface again to establish its identity"
                    .into(),
            ));
        }
        let (bind_identity, bind_scope) = match provider
            .resolve(bind_interface.as_deref(), saved_id, adopted)
            .await
        {
            Ok(resolved) => resolved,
            Err(error) if bind_interface.is_none() => (
                None,
                BindScope::Unknown {
                    reason: error.to_string(),
                },
            ),
            Err(error) => return Err(error),
        };
        let bind_address = match &bind_scope {
            BindScope::Interface { address, .. } => Some(address.clone()),
            _ => None,
        };
        let bind_interface = bind_identity
            .as_ref()
            .map(|i| i.alias.clone())
            .or(bind_interface);
        let advertised_ip = match &bind_address {
            Some(ip) => ip.clone(),
            None => get_display_ip(adopted)
                .await
                .unwrap_or_else(|| "0.0.0.0".into()),
        };
        log::info!(
            "Re-stream bind selection: interface={:?} bind={:?} advertise={}",
            bind_interface,
            bind_address,
            advertised_ip
        );
        Ok(ResolvedStartSpec {
            source,
            output,
            bind_interface,
            bind_identity,
            bind_scope,
            bind_address,
            advertised_ip,
            username: settings.credentials.username.clone(),
            password: settings.credentials.password.clone(),
        })
    }

    pub(super) fn build_restream_server(
        spec: &ResolvedStartSpec,
        health: Arc<RelayRuntimeHealth>,
        event_tx: RelayEventSender,
        recovering: bool,
        upstream_ready: Option<rtsp_server::UpstreamReady>,
    ) -> (u64, Result<RestreamServer, RestreamBuildFailure>) {
        let server_instance = health.begin_server_instance(recovering);
        let runtime = RestreamRuntimeContext {
            health,
            event_tx,
            server_instance,
            upstream_ready,
        };
        let result = match (&spec.output, &spec.source) {
            (
                ResolvedOutput::Rtsp {
                    server_port,
                    mount_path,
                },
                ResolvedSource::Udp { port },
            ) => RtspRestreamer::start_from_udp(
                *port,
                *server_port,
                mount_path,
                spec.bind_address.as_deref(),
                runtime,
            )
            .map(RestreamServer::Rtsp),
            (
                ResolvedOutput::Rtsp {
                    server_port,
                    mount_path,
                },
                ResolvedSource::Rtsp { url },
            ) => RtspRestreamer::start_from_rtsp(
                url,
                *server_port,
                mount_path,
                spec.bind_address.as_deref(),
                &spec.username,
                &spec.password,
                runtime,
            )
            .map(RestreamServer::Rtsp),
            (
                ResolvedOutput::Srt {
                    server_port,
                    passphrase,
                    latency_ms,
                    stream_id,
                },
                ResolvedSource::Udp { port },
            ) => SrtRestreamer::start_from_udp(
                *port,
                *server_port,
                spec.bind_address.as_deref(),
                (!passphrase.is_empty()).then_some(passphrase.as_str()),
                *latency_ms,
                stream_id,
                runtime,
            )
            .map(RestreamServer::Srt),
            (
                ResolvedOutput::Srt {
                    server_port,
                    passphrase,
                    latency_ms,
                    stream_id,
                },
                ResolvedSource::Rtsp { url },
            ) => SrtRestreamer::start_from_rtsp(
                url,
                *server_port,
                spec.bind_address.as_deref(),
                &spec.username,
                &spec.password,
                (!passphrase.is_empty()).then_some(passphrase.as_str()),
                *latency_ms,
                stream_id,
                runtime,
            )
            .map(RestreamServer::Srt),
        };
        (server_instance, result)
    }

    pub(super) async fn publish_restream_start_intent(
        &self,
        start_epoch: u64,
    ) -> Option<(u64, bool)> {
        self.relay_wake.notify_waiters();

        let preserve_prior_desired = {
            let mut state = self.state.lock().await;
            // A later Start/Stop may advance the epoch between this request's
            // atomic claim and its state-lock acquisition. Never let the
            // stale request reassert desired state after that newer intent.
            if self
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                != start_epoch
            {
                return None;
            }
            let preserve = state.restream_desired
                && state.restream_spec.is_some()
                && state.restream_health.is_some();
            state.restream_desired = true;
            state.restream_intent_epoch = Some(start_epoch);
            if !preserve {
                state.restream_start_time = Some(std::time::Instant::now());
            }
            preserve
        };
        self.refresh_status().await;
        Some((start_epoch, preserve_prior_desired))
    }

    pub(super) async fn begin_restream_start_intent(&self) -> Option<(u64, bool)> {
        let start_epoch = self
            .restream_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .wrapping_add(1);
        self.publish_restream_start_intent(start_epoch).await
    }

    pub(super) async fn begin_restream_start_intent_if_current(
        &self,
        expected_epoch: u64,
    ) -> Option<(u64, bool)> {
        let start_epoch = expected_epoch.wrapping_add(1);
        self.restream_epoch
            .compare_exchange(
                expected_epoch,
                start_epoch,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .ok()?;
        self.publish_restream_start_intent(start_epoch).await
    }

    pub(super) async fn restream_intent_is_current(&self, expected_epoch: u64) -> bool {
        if self
            .restream_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != expected_epoch
        {
            return false;
        }
        let state = self.state.lock().await;
        self.restream_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            == expected_epoch
            && state.restream_desired
            && state.restream_intent_epoch == Some(expected_epoch)
    }

    pub(super) async fn current_restream_epoch_and_desired(&self) -> (u64, bool) {
        loop {
            let epoch = self
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire);
            let desired = self.state.lock().await.restream_desired;
            if self
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                == epoch
            {
                return (epoch, desired);
            }
        }
    }

    pub(super) async fn cancel_restream_start_intent(
        &self,
        start_epoch: u64,
        preserve_prior_desired: bool,
    ) {
        if self
            .restream_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != start_epoch
        {
            return;
        }

        let retry_generation = {
            let mut state = self.state.lock().await;
            if self
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                != start_epoch
                || state.restream_intent_epoch != Some(start_epoch)
            {
                return;
            }
            if preserve_prior_desired {
                state.restream_health.as_ref().and_then(|health| {
                    matches!(
                        health.snapshot().state,
                        RelayState::Failed | RelayState::Recovering
                    )
                    .then(|| health.server_generation())
                })
            } else {
                if let Some(health) = state.restream_health.as_ref() {
                    health.stop();
                }
                state.restream_desired = false;
                state.policy_retry = None;
                state.restream_spec = None;
                state.restream_health = None;
                state.restream_intent_epoch = None;
                state.restream_start_time = None;
                None
            }
        };

        if let Some(server_generation) = retry_generation {
            let _ = self
                .relay_event_tx
                .send(RelaySupervisorEvent::RetryRequested { server_generation });
        }
        self.refresh_status().await;
    }

    pub async fn start_restream_server(
        &self,
        config: &AppConfig,
        adopted: &std::collections::HashSet<String>,
    ) -> Result<RestreamServerInfo, AppError> {
        let initial = crate::settings_validation::validate_prospective_settings(config.get())?;
        if !initial.rtsp_server.enabled {
            return Err(AppError::Validation(
                "Re-stream Server Enable must be on before starting".into(),
            ));
        }
        validate_selected_restream_startable(&initial)?;

        // Publish intent before waiting for another user transaction or doing
        // interface resolution. A later Stop/Start can therefore supersede
        // this operation immediately by advancing the epoch.
        let Some((start_epoch, preserve_prior_desired)) = self.begin_restream_start_intent().await
        else {
            return Err(AppError::Stream(
                "Re-stream server start was superseded by a newer request".into(),
            ));
        };
        let _transaction = self.restream_transaction.lock().await;
        if !self.restream_intent_is_current(start_epoch).await {
            return Err(AppError::Stream(
                "Re-stream server start was superseded by a newer request".into(),
            ));
        }

        // Re-read after serialization so a settings apply that committed
        // while this Start was queued is authoritative.
        let settings = match crate::settings_validation::validate_prospective_settings(config.get())
        {
            Ok(settings) => settings,
            Err(error) => {
                self.cancel_restream_start_intent(start_epoch, preserve_prior_desired)
                    .await;
                return Err(error);
            }
        };
        if !settings.rtsp_server.enabled {
            self.cancel_restream_start_intent(start_epoch, false).await;
            return Err(AppError::Validation(
                "Re-stream Server Enable must be on before starting".into(),
            ));
        }
        if let Err(error) = validate_selected_restream_startable(&settings) {
            self.cancel_restream_start_intent(start_epoch, preserve_prior_desired)
                .await;
            return Err(error);
        }
        self.start_restream_server_inner(&settings, adopted, start_epoch, preserve_prior_desired)
            .await
    }

    pub(super) async fn start_restream_server_inner(
        &self,
        settings: &AppSettings,
        adopted: &std::collections::HashSet<String>,
        start_epoch: u64,
        preserve_prior_desired: bool,
    ) -> Result<RestreamServerInfo, AppError> {
        let handle = self.readiness.clone();
        let mut target = stream_target(settings);
        match preflight_target(handle.as_ref(), target.as_ref()).await {
            Ok(Some(path)) => target = Some(path.target),
            Ok(None) => {}
            Err(error) => {
                self.cancel_restream_start_intent(start_epoch, preserve_prior_desired)
                    .await;
                return Err(error);
            }
        }
        let mut spec =
            match Self::resolve_restream_start_spec_with(self.bindings.as_ref(), settings, adopted)
                .await
            {
                Ok(spec) => spec,
                Err(error) => {
                    self.cancel_restream_start_intent(start_epoch, preserve_prior_desired)
                        .await;
                    return Err(error);
                }
            };
        if self
            .restream_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != start_epoch
        {
            return Err(AppError::Stream(
                "Re-stream server start was superseded by a stop".into(),
            ));
        }

        let mut info = RestreamServerInfo {
            bind_scope: spec.bind_scope.clone(),
            firewall: FirewallOutcome::Inactive,
            protocol: spec.protocol(),
            server_url: spec.client_url(),
            display_url: spec.display_url(),
        };

        let (server_generation, health) = {
            let mut state = self.state.lock().await;
            if self
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                != start_epoch
            {
                return Err(AppError::Stream(
                    "Re-stream server start was superseded by a stop".into(),
                ));
            }

            let health_snapshot = state
                .restream_health
                .as_ref()
                .map(|health| health.snapshot());
            let healthy_noop = resolved_start_is_healthy_noop(
                state.restream_desired,
                state.restream_spec.as_ref(),
                &spec,
                health_snapshot.as_ref().map(|health| health.state),
                health_snapshot
                    .as_ref()
                    .map(|health| health.server_generation),
                state
                    .restream_server
                    .as_ref()
                    .map(RestreamServer::server_generation),
                state
                    .restream_server
                    .as_ref()
                    .is_some_and(RestreamServer::loop_alive),
            );
            if healthy_noop && state.restream_target == target {
                log::info!(
                    "Explicit re-stream Start resolved to the healthy current endpoint; no-op"
                );
                info.firewall = state.firewall.clone();
                if !clean_firewall(&state.firewall)
                    && !matches!(
                        state.firewall,
                        FirewallOutcome::Failed {
                            uncertain: true,
                            ..
                        }
                    )
                {
                    if let Some(retry) = state.policy_retry.as_mut() {
                        let now = tokio::time::Instant::now();
                        // A due/in-flight request stays due; manual requests coalesce.
                        retry.due = Some(retry.due.map_or(now, |due| due.min(now)));
                    }
                }
                drop(state);
                self.refresh_status().await;
                return Ok(info);
            }

            if let Some(udp_port) = spec.udp_ingest_port() {
                if let Err(error) = state.guard_udp(udp_port) {
                    drop(state);
                    self.cancel_restream_start_intent(start_epoch, preserve_prior_desired)
                        .await;
                    return Err(error);
                }
            }

            let server_generation = self
                .restream_generation
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
                .wrapping_add(1);
            let health = Arc::new(RelayRuntimeHealth::new(
                server_generation,
                spec.ingest_kind(),
            ));
            state.restream_target = target.clone();
            state.restream_spec = Some(spec.clone());
            state.restream_health = Some(health.clone());
            state.policy_retry = Some(PolicyRetry::new(server_generation));
            state.restream_start_time = Some(std::time::Instant::now());
            (server_generation, health)
        };

        self.relay_wake.notify_waiters();
        self.refresh_status().await;

        let gst_error = preflight_restream(&spec).err();
        let _lifecycle = self.relay_lifecycle.lock().await;
        if !relay_is_current(
            &self.state,
            &self.restream_epoch,
            start_epoch,
            server_generation,
        )
        .await
        {
            return Err(AppError::Stream(
                "Re-stream server start was superseded by a newer request".into(),
            ));
        }

        let old_server = {
            let mut state = self.state.lock().await;
            if !relay_state_is_current(&state, &self.restream_epoch, start_epoch, server_generation)
            {
                return Err(AppError::Stream(
                    "Re-stream server start was superseded by a newer request".into(),
                ));
            }
            state.restream_server.take()
        };
        if let Some(mut old_server) = old_server {
            let generation = old_server.server_generation();
            old_server.shutdown().await;
            retire_firewall(&self.state, self.policy.as_ref(), generation).await;
        }

        if !relay_is_current(
            &self.state,
            &self.restream_epoch,
            start_epoch,
            server_generation,
        )
        .await
        {
            return Err(AppError::Stream(
                "Re-stream server start was superseded by a newer request".into(),
            ));
        }

        if let Some(error) = gst_error {
            let server_instance = health.begin_server_instance(false);
            let reason = redact_relay_text(&error.to_string(), spec.mount_path());
            health.mark_build_failed(server_instance, reason, false);
            let _ = self
                .relay_event_tx
                .send(RelaySupervisorEvent::RetryRequested { server_generation });
            drop(_lifecycle);
            self.refresh_status().await;
            return Err(error);
        }

        if let Err(error) = preflight_target(handle.as_ref(), target.as_ref()).await {
            health.mark_resolution_failed(error.to_string());
            let _ = self
                .relay_event_tx
                .send(RelaySupervisorEvent::RetryRequested { server_generation });
            drop(_lifecycle);
            self.refresh_status().await;
            return Err(error);
        }
        if !relay_is_current(
            &self.state,
            &self.restream_epoch,
            start_epoch,
            server_generation,
        )
        .await
        {
            return Err(AppError::Stream(
                "Re-stream server start was superseded by a newer request".into(),
            ));
        }
        let validity = bind_validity(
            self.bindings.as_ref(),
            &spec,
            adopted,
            server_generation,
            "preflight",
        )
        .await;
        if !relay_is_current(
            &self.state,
            &self.restream_epoch,
            start_epoch,
            server_generation,
        )
        .await
        {
            return Err(AppError::Stream(
                "Re-stream server start was superseded by a newer request".into(),
            ));
        }
        match validity {
            BindValidity::Refreshed(scope) => spec.bind_scope = scope,
            BindValidity::Invalidated(reason) => {
                let current = record_bind_failure(
                    &self.state,
                    &self.restream_epoch,
                    start_epoch,
                    server_generation,
                    reason,
                    Some(&self.relay_event_tx),
                )
                .await;
                drop(_lifecycle);
                self.refresh_status().await;
                return Err(AppError::Stream(
                    if current {
                        "Bind topology changed; listener recovery is pending"
                    } else {
                        "Re-stream server start was superseded by a newer request"
                    }
                    .into(),
                ));
            }
            BindValidity::Unchanged => {}
        }
        info.firewall = apply_firewall(
            &self.state,
            self.policy.as_ref(),
            &spec,
            server_generation,
            &self.restream_epoch,
            start_epoch,
            &self.relay_wake,
            "start",
        )
        .await;
        if !relay_is_current(
            &self.state,
            &self.restream_epoch,
            start_epoch,
            server_generation,
        )
        .await
        {
            retire_firewall(&self.state, self.policy.as_ref(), server_generation).await;
            return Err(AppError::Stream(
                "Listener start superseded during Windows rule reconciliation".into(),
            ));
        }
        let validity = bind_validity(
            self.bindings.as_ref(),
            &spec,
            adopted,
            server_generation,
            "policy",
        )
        .await;
        if !relay_is_current(
            &self.state,
            &self.restream_epoch,
            start_epoch,
            server_generation,
        )
        .await
        {
            retire_firewall(&self.state, self.policy.as_ref(), server_generation).await;
            return Err(AppError::Stream(
                "Listener start superseded during Windows rule reconciliation".into(),
            ));
        }
        match validity {
            BindValidity::Refreshed(scope) => spec.bind_scope = scope,
            BindValidity::Invalidated(reason) => {
                retire_firewall(&self.state, self.policy.as_ref(), server_generation).await;
                let current = record_bind_failure(
                    &self.state,
                    &self.restream_epoch,
                    start_epoch,
                    server_generation,
                    reason,
                    Some(&self.relay_event_tx),
                )
                .await;
                drop(_lifecycle);
                self.refresh_status().await;
                return Err(AppError::Stream(
                    if current {
                        "Bind topology changed; listener recovery is pending"
                    } else {
                        "Listener start superseded during Windows rule reconciliation"
                    }
                    .into(),
                ));
            }
            BindValidity::Unchanged => {}
        }
        let (server_instance, built) = Self::build_restream_server(
            &spec,
            health.clone(),
            self.relay_event_tx.clone(),
            false,
            relay_preflight(
                handle.clone(),
                target.clone(),
                health.clone(),
                self.restream_generation.clone(),
                server_generation,
            ),
        );
        let server = match built {
            Ok(server) => server,
            Err(failure) => {
                retire_firewall(&self.state, self.policy.as_ref(), server_generation).await;
                let reason = redact_relay_text(&failure.error.to_string(), spec.mount_path());
                {
                    let state = self.state.lock().await;
                    if relay_state_is_current(
                        &state,
                        &self.restream_epoch,
                        start_epoch,
                        server_generation,
                    ) {
                        // Explicit Start remains the baseline build attempt.
                        health.mark_build_failed(server_instance, reason, false);
                        let _ = self
                            .relay_event_tx
                            .send(RelaySupervisorEvent::RetryRequested { server_generation });
                    }
                }
                drop(_lifecycle);
                self.refresh_status().await;
                return Err(failure.error);
            }
        };

        let mut candidate = Some(server);
        let validity = if relay_is_current(
            &self.state,
            &self.restream_epoch,
            start_epoch,
            server_generation,
        )
        .await
        {
            bind_validity(
                self.bindings.as_ref(),
                &spec,
                adopted,
                server_generation,
                "install",
            )
            .await
        } else {
            BindValidity::Unchanged
        };
        {
            let mut state = self.state.lock().await;
            if relay_state_is_current(&state, &self.restream_epoch, start_epoch, server_generation)
                && !matches!(validity, BindValidity::Invalidated(_))
            {
                if let BindValidity::Refreshed(scope) = &validity {
                    spec.bind_scope = scope.clone();
                }
                info.bind_scope = spec.bind_scope.clone();
                state.restream_spec = Some(spec);
                state.restream_server = candidate.take();
            }
        }
        if let Some(mut stale) = candidate {
            stale.shutdown().await;
            retire_firewall(&self.state, self.policy.as_ref(), server_generation).await;
            let topology_failure = if let BindValidity::Invalidated(reason) = validity {
                record_bind_failure(
                    &self.state,
                    &self.restream_epoch,
                    start_epoch,
                    server_generation,
                    reason,
                    Some(&self.relay_event_tx),
                )
                .await
            } else {
                false
            };
            drop(_lifecycle);
            self.refresh_status().await;
            return Err(AppError::Stream(
                if topology_failure {
                    "Bind topology changed; listener recovery is pending"
                } else {
                    "Re-stream server start was superseded by a newer request"
                }
                .into(),
            ));
        }

        drop(_lifecycle);
        self.refresh_status().await;
        Ok(info)
    }

    pub async fn stop_restream_server(&self) -> Result<(), AppError> {
        // Invalidate an in-flight Start/recovery before waiting for the user
        // transaction gate. The teardown itself remains serialized below.
        let intent = self.begin_restream_stop_intent().await;
        let _transaction = self.restream_transaction.lock().await;
        match intent {
            Some(intent) => self.finish_restream_stop(intent).await,
            None => Ok(()),
        }
    }

    #[cfg(any(windows, test))]
    pub(crate) async fn startup_firewall_status(&self, outcome: FirewallOutcome) {
        let mut state = self.state.lock().await;
        if state.firewall_generation.is_none() {
            state.firewall = outcome;
        }
        drop(state);
        self.refresh_status().await;
    }

    pub(crate) async fn binding_topology_changed(&self, scope: BindScope, revision: u64) {
        let (spec, generation, instance, health, intent) = {
            let state = self.state.lock().await;
            let (Some(spec), Some(health)) = (&state.restream_spec, &state.restream_health) else {
                return;
            };
            let Some(intent) = state.restream_intent_epoch else {
                return;
            };
            if !state.restream_desired
                || self
                    .restream_epoch
                    .load(std::sync::atomic::Ordering::Acquire)
                    != intent
            {
                return;
            }
            if !matches!(scope, BindScope::Unknown { .. })
                && !matches!(spec.bind_scope, BindScope::Unknown { .. })
                && scope_revision(&spec.bind_scope) == Some(revision)
            {
                return;
            }
            let snapshot = health.snapshot();
            (
                spec.clone(),
                snapshot.server_generation,
                snapshot.server_instance,
                health.clone(),
                intent,
            )
        };
        let resolved =
            if spec.bind_interface.is_none() || matches!(scope, BindScope::Unknown { .. }) {
                Ok((spec.bind_identity.clone(), scope))
            } else {
                let handle = self.readiness.clone();
                let adopted = match handle {
                    Some(handle) => adopted_ip_set(&handle).await,
                    None => Default::default(),
                };
                if !relay_is_current(&self.state, &self.restream_epoch, intent, generation).await {
                    return;
                }
                self.bindings
                    .resolve(
                        spec.bind_interface.as_deref(),
                        spec.bind_identity.as_ref().map(|i| i.guid.as_str()),
                        &adopted,
                    )
                    .await
            };
        let _lifecycle = self.relay_lifecycle.lock().await;
        if self.bindings.revision() != revision {
            return;
        }
        let (identity, next) = resolved.unwrap_or_else(|error| {
            (
                spec.bind_identity.clone(),
                BindScope::Unknown {
                    reason: error.to_string(),
                },
            )
        });
        {
            let mut state = self.state.lock().await;
            if !relay_state_is_current(&state, &self.restream_epoch, intent, generation)
                || health.snapshot().server_instance != instance
            {
                return;
            }
            if let Some(spec) = state.restream_spec.as_mut() {
                // Recovery can install a refreshed specification for this same
                // reserved instance while this observation waits for lifecycle.
                let rebind = spec.bind_interface.is_some()
                    && explicit_bind_changed(spec, identity.as_ref(), &next);
                spec.bind_scope = if rebind {
                    BindScope::Unknown {
                        reason: "Resolving changed bind interface".into(),
                    }
                } else {
                    next
                };
                if rebind {
                    health.mark_resolution_failed(
                        "Bind topology changed; resolving the saved interface identity".into(),
                    );
                    let _ = self
                        .relay_event_tx
                        .send(RelaySupervisorEvent::RetryRequested {
                            server_generation: generation,
                        });
                }
            }
        }
        drop(_lifecycle);
        self.refresh_status().await;
    }

    pub(super) async fn publish_restream_stop_intent(
        &self,
        stop_epoch: u64,
    ) -> Option<RestreamStopIntent> {
        self.relay_wake.notify_waiters();

        let (target_generation, firewall_generation, was_desired) = {
            let mut state = self.state.lock().await;
            // A newer intent owns desired state and listener replacement.
            // This stale Stop must neither clear it nor tear down its server.
            if self
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                != stop_epoch
            {
                return None;
            }
            let desired_generation = state
                .restream_health
                .as_ref()
                .map(|health| health.server_generation());
            let live_generation = state
                .restream_server
                .as_ref()
                .map(RestreamServer::server_generation);
            let stops_desired = state.restream_desired;

            let target = restream_stop_target(stops_desired, desired_generation, live_generation)
                .or_else(|| state.firewall_generation.map(|(generation, _)| generation));

            if stops_desired {
                if let Some(health) = state.restream_health.as_ref() {
                    health.stop();
                }
                state.restream_desired = false;
                state.policy_retry = None;
                state.restream_spec = None;
                state.restream_health = None;
                state.restream_intent_epoch = None;
                state.restream_start_time = None;
                state.restream_target = None;
            }
            (
                target,
                state.firewall_generation.map(|(generation, _)| generation),
                stops_desired,
            )
        };
        self.refresh_status().await;

        Some(RestreamStopIntent {
            epoch: stop_epoch,
            target_generation,
            firewall_generation,
            was_desired,
        })
    }

    pub(super) async fn begin_restream_stop_intent(&self) -> Option<RestreamStopIntent> {
        let stop_epoch = self
            .restream_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .wrapping_add(1);
        self.publish_restream_stop_intent(stop_epoch).await
    }

    pub(super) async fn begin_restream_stop_intent_if_current(
        &self,
        expected_epoch: u64,
    ) -> Option<RestreamStopIntent> {
        let stop_epoch = expected_epoch.wrapping_add(1);
        self.restream_epoch
            .compare_exchange(
                expected_epoch,
                stop_epoch,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .ok()?;
        self.publish_restream_stop_intent(stop_epoch).await
    }

    pub(super) async fn finish_restream_stop(
        &self,
        intent: RestreamStopIntent,
    ) -> Result<(), AppError> {
        let _lifecycle = self.relay_lifecycle.lock().await;
        let server =
            {
                let mut state = self.state.lock().await;
                if state.restream_server.as_ref().is_some_and(|server| {
                    Some(server.server_generation()) == intent.target_generation
                }) {
                    state.restream_server.take()
                } else {
                    None
                }
            };
        if let Some(mut server) = server {
            server.shutdown().await;
            log::info!("Re-stream server fully cleaned up");
        }
        if let Some(generation) = intent.target_generation {
            retire_firewall(&self.state, self.policy.as_ref(), generation).await;
        }
        // A failed prior retirement can survive a replacement listener whose
        // automation is unavailable. Stop must retry that captured lease too;
        // retire_firewall still rejects a newer generation's lease.
        if intent.firewall_generation != intent.target_generation {
            if let Some(generation) = intent.firewall_generation {
                retire_firewall(&self.state, self.policy.as_ref(), generation).await;
            }
        }
        drop(_lifecycle);
        self.refresh_status().await;
        log::info!("Re-stream server stopped (intent epoch={})", intent.epoch);
        Ok(())
    }

    pub(super) async fn current_operation_result(&self) -> RestreamOperationResult {
        let state = self.state.lock().await;
        RestreamOperationResult {
            selected_protocol: state.selected_protocol,
            desired: state.restream_desired,
            server_info: state
                .restream_desired
                .then(|| {
                    state
                        .restream_spec
                        .as_ref()
                        .map(|spec| Self::info_from_spec(spec, state.firewall.clone()))
                })
                .flatten(),
        }
    }

    pub(super) fn info_from_spec(
        spec: &ResolvedStartSpec,
        firewall: FirewallOutcome,
    ) -> RestreamServerInfo {
        RestreamServerInfo {
            bind_scope: spec.bind_scope.clone(),
            firewall,
            protocol: spec.protocol(),
            server_url: spec.client_url(),
            display_url: spec.display_url(),
        }
    }

    pub(super) async fn restore_restream_after_transaction_error(
        &self,
        old_settings: &AppSettings,
        adopted: &std::collections::HashSet<String>,
        stop_intent: RestreamStopIntent,
        error: AppError,
    ) -> AppError {
        if !stop_intent.was_desired {
            return error;
        }
        let Some((start_epoch, preserve_prior_desired)) = self
            .begin_restream_start_intent_if_current(stop_intent.epoch)
            .await
        else {
            return error;
        };
        match self
            .start_restream_server_inner(old_settings, adopted, start_epoch, preserve_prior_desired)
            .await
        {
            Ok(_) => error,
            Err(restoration_error) => AppError::Config(format!(
                "{}; restoring the prior re-stream output also failed: {}",
                error, restoration_error
            )),
        }
    }

    /// Apply the shared Enable field and both complete protocol sections as
    /// one backend lifecycle transaction. Inactive-protocol edits persist
    /// without replacing the selected runtime.
    pub async fn apply_restream_settings(
        &self,
        config: &AppConfig,
        update: RestreamSettingsUpdate,
        adopted: &std::collections::HashSet<String>,
    ) -> Result<RestreamOperationResult, AppError> {
        self.apply_restream_settings_with(config, update, adopted, |config, prospective| {
            config.commit_restream_settings(
                prospective.rtsp_server.clone(),
                prospective.srt_server.clone(),
            )
        })
        .await
    }

    pub(super) async fn apply_restream_settings_with<F>(
        &self,
        config: &AppConfig,
        update: RestreamSettingsUpdate,
        adopted: &std::collections::HashSet<String>,
        commit: F,
    ) -> Result<RestreamOperationResult, AppError>
    where
        F: FnOnce(&AppConfig, &AppSettings) -> Result<AppSettings, AppError>,
    {
        let initial_settings = config.get();
        let initial_prospective = crate::settings_validation::prospective_restream_settings(
            &initial_settings,
            update.clone(),
        )?;
        let (operation_epoch, initial_was_desired) =
            self.current_restream_epoch_and_desired().await;
        let initial_runtime_changed =
            selected_restream_runtime_changed(&initial_settings, &initial_prospective);
        let initial_will_restart = initial_was_desired
            && initial_runtime_changed
            && initial_prospective.rtsp_server.enabled;
        if initial_will_restart {
            validate_selected_restream_startable(&initial_prospective)?;
        }
        let initial_must_stop = initial_was_desired
            && (initial_runtime_changed || !initial_prospective.rtsp_server.enabled);

        // Claim the stop epoch before waiting for an in-flight Start. That
        // Start will observe the newer epoch before it can store a candidate.
        let mut stop_intent = if initial_must_stop {
            Some(
                self.begin_restream_stop_intent_if_current(operation_epoch)
                    .await
                    .ok_or_else(|| {
                        AppError::Stream(
                            "Re-stream settings apply was superseded by a newer request".into(),
                        )
                    })?,
            )
        } else {
            None
        };

        let _transaction = self.restream_transaction.lock().await;
        let expected_epoch = stop_intent
            .map(|intent| intent.epoch)
            .unwrap_or(operation_epoch);
        if self
            .restream_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != expected_epoch
        {
            return Err(AppError::Stream(
                "Re-stream settings apply was superseded by a newer request".into(),
            ));
        }

        // A transaction that already held the gate may have committed while
        // this request was waiting. Rebase the complete update on its result.
        let old_settings = crate::settings_validation::validate_prospective_settings(config.get())?;
        let prospective = match crate::settings_validation::prospective_restream_settings(
            &old_settings,
            update,
        ) {
            Ok(settings) => settings,
            Err(error) => {
                return Err(match stop_intent {
                    Some(intent) => {
                        self.restore_restream_after_transaction_error(
                            &old_settings,
                            adopted,
                            intent,
                            error,
                        )
                        .await
                    }
                    None => error,
                });
            }
        };
        let mut was_desired = stop_intent
            .map(|intent| intent.was_desired)
            .unwrap_or(self.state.lock().await.restream_desired);
        let runtime_changed = selected_restream_runtime_changed(&old_settings, &prospective);
        let will_restart = was_desired && runtime_changed && prospective.rtsp_server.enabled;
        if will_restart {
            if let Err(error) = validate_selected_restream_startable(&prospective) {
                return Err(match stop_intent {
                    Some(intent) => {
                        self.restore_restream_after_transaction_error(
                            &old_settings,
                            adopted,
                            intent,
                            error,
                        )
                        .await
                    }
                    None => error,
                });
            }
        }
        let must_stop = was_desired && (runtime_changed || !prospective.rtsp_server.enabled);
        if must_stop && stop_intent.is_none() {
            let intent = self
                .begin_restream_stop_intent_if_current(expected_epoch)
                .await
                .ok_or_else(|| {
                    AppError::Stream(
                        "Re-stream settings apply was superseded by a newer request".into(),
                    )
                })?;
            was_desired = intent.was_desired;
            stop_intent = Some(intent);
        }
        if let Some(intent) = stop_intent {
            self.finish_restream_stop(intent).await?;
        }

        let committed = match commit(config, &prospective) {
            Ok(settings) => settings,
            Err(persistence_error) => {
                return Err(match stop_intent {
                    Some(intent) => {
                        self.restore_restream_after_transaction_error(
                            &old_settings,
                            adopted,
                            intent,
                            persistence_error,
                        )
                        .await
                    }
                    None => persistence_error,
                });
            }
        };

        if was_desired && committed.rtsp_server.enabled {
            if let Some(intent) = stop_intent {
                if let Some((start_epoch, preserve_prior_desired)) = self
                    .begin_restream_start_intent_if_current(intent.epoch)
                    .await
                {
                    self.start_restream_server_inner(
                        &committed,
                        adopted,
                        start_epoch,
                        preserve_prior_desired,
                    )
                    .await?;
                }
            }
        }

        Ok(self.current_operation_result().await)
    }

    pub async fn switch_restream_protocol(
        &self,
        config: &AppConfig,
        protocol: RestreamProtocol,
        adopted: &std::collections::HashSet<String>,
    ) -> Result<RestreamOperationResult, AppError> {
        self.switch_restream_protocol_with(config, protocol, adopted, |config, protocol| {
            config.commit_restream_protocol(protocol)
        })
        .await
    }

    pub(super) async fn switch_restream_protocol_with<F>(
        &self,
        config: &AppConfig,
        protocol: RestreamProtocol,
        adopted: &std::collections::HashSet<String>,
        commit: F,
    ) -> Result<RestreamOperationResult, AppError>
    where
        F: FnOnce(&AppConfig, RestreamProtocol) -> Result<AppSettings, AppError>,
    {
        let initial_settings =
            crate::settings_validation::validate_prospective_settings(config.get())?;
        let mut initial_prospective = initial_settings.clone();
        initial_prospective.restream_protocol = protocol;
        let initial_prospective =
            crate::settings_validation::validate_prospective_settings(initial_prospective)?;
        let (operation_epoch, initial_was_desired) =
            self.current_restream_epoch_and_desired().await;
        validate_restream_switch_target(&initial_prospective, initial_was_desired)?;

        // A different selector owns a new stop epoch as soon as validation
        // succeeds, before it waits for a Start that may be resolving a bind.
        let mut stop_intent = if initial_settings.restream_protocol != protocol {
            Some(
                self.begin_restream_stop_intent_if_current(operation_epoch)
                    .await
                    .ok_or_else(|| {
                        AppError::Stream(
                            "Re-stream protocol switch was superseded by a newer request".into(),
                        )
                    })?,
            )
        } else {
            None
        };

        let _transaction = self.restream_transaction.lock().await;
        let expected_epoch = stop_intent
            .map(|intent| intent.epoch)
            .unwrap_or(operation_epoch);
        if self
            .restream_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != expected_epoch
        {
            return Err(AppError::Stream(
                "Re-stream protocol switch was superseded by a newer request".into(),
            ));
        }

        let old_settings = crate::settings_validation::validate_prospective_settings(config.get())?;
        let mut prospective = old_settings.clone();
        prospective.restream_protocol = protocol;
        let prospective =
            match crate::settings_validation::validate_prospective_settings(prospective) {
                Ok(settings) => settings,
                Err(error) => {
                    return Err(match stop_intent {
                        Some(intent) => {
                            self.restore_restream_after_transaction_error(
                                &old_settings,
                                adopted,
                                intent,
                                error,
                            )
                            .await
                        }
                        None => error,
                    });
                }
            };
        let mut was_desired = stop_intent
            .map(|intent| intent.was_desired)
            .unwrap_or(self.state.lock().await.restream_desired);
        if let Err(error) = validate_restream_switch_target(&prospective, was_desired) {
            return Err(match stop_intent {
                Some(intent) => {
                    self.restore_restream_after_transaction_error(
                        &old_settings,
                        adopted,
                        intent,
                        error,
                    )
                    .await
                }
                None => error,
            });
        }

        if old_settings.restream_protocol == protocol {
            self.state.lock().await.selected_protocol = protocol;
            if let Some(intent) = stop_intent {
                self.finish_restream_stop(intent).await?;
            }
            if was_desired {
                let restart_epoch = stop_intent
                    .map(|intent| intent.epoch)
                    .unwrap_or(expected_epoch);
                let Some((start_epoch, preserve_prior_desired)) = self
                    .begin_restream_start_intent_if_current(restart_epoch)
                    .await
                else {
                    return Ok(self.current_operation_result().await);
                };
                self.start_restream_server_inner(
                    &prospective,
                    adopted,
                    start_epoch,
                    preserve_prior_desired,
                )
                .await?;
            } else {
                self.refresh_status().await;
            }
            return Ok(self.current_operation_result().await);
        }

        if stop_intent.is_none() {
            let intent = self
                .begin_restream_stop_intent_if_current(expected_epoch)
                .await
                .ok_or_else(|| {
                    AppError::Stream(
                        "Re-stream protocol switch was superseded by a newer request".into(),
                    )
                })?;
            was_desired = intent.was_desired;
            stop_intent = Some(intent);
        }
        let stop_intent = stop_intent.expect("a selector change must own a stop intent");
        self.finish_restream_stop(stop_intent).await?;

        let committed = match commit(config, protocol) {
            Ok(settings) => settings,
            Err(persistence_error) => {
                return Err(self
                    .restore_restream_after_transaction_error(
                        &old_settings,
                        adopted,
                        stop_intent,
                        persistence_error,
                    )
                    .await);
            }
        };

        self.state.lock().await.selected_protocol = protocol;
        self.refresh_status().await;

        if was_desired {
            if let Some((start_epoch, preserve_prior_desired)) = self
                .begin_restream_start_intent_if_current(stop_intent.epoch)
                .await
            {
                validate_selected_restream_startable(&committed)?;
                self.start_restream_server_inner(
                    &committed,
                    adopted,
                    start_epoch,
                    preserve_prior_desired,
                )
                .await?;
            }
        }
        Ok(self.current_operation_result().await)
    }
}

fn optional_bind_interface(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

pub(super) fn resolve_selected_restream_output(
    settings: &AppSettings,
) -> Result<(Option<String>, ResolvedOutput), AppError> {
    validate_selected_restream_startable(settings)?;
    match settings.restream_protocol {
        RestreamProtocol::Rtsp => Ok((
            optional_bind_interface(&settings.rtsp_server.bind_interface),
            ResolvedOutput::Rtsp {
                server_port: settings.rtsp_server.port,
                mount_path: format!("/stream-{}", settings.rtsp_server.token),
            },
        )),
        RestreamProtocol::Srt => Ok((
            optional_bind_interface(&settings.srt_server.bind_interface),
            ResolvedOutput::Srt {
                server_port: settings.srt_server.port,
                passphrase: resolved_srt_passphrase(&settings.srt_server.passphrase)?,
                latency_ms: settings.srt_server.latency_ms,
                stream_id: settings.srt_server.stream_id.clone(),
            },
        )),
    }
}

fn resolved_srt_passphrase(passphrase: &SrtPassphraseState) -> Result<String, AppError> {
    match passphrase {
        SrtPassphraseState::Unencrypted => Ok(String::new()),
        SrtPassphraseState::Available(value) => Ok(value.clone()),
        SrtPassphraseState::Unavailable { .. } => {
            crate::settings_validation::validate_srt_startable_from_state(passphrase)?;
            unreachable!("unavailable SRT passphrase validation must fail")
        }
    }
}

fn validate_selected_restream_startable(settings: &AppSettings) -> Result<(), AppError> {
    if settings.restream_protocol == RestreamProtocol::Srt {
        crate::settings_validation::validate_srt_startable(settings)?;
    }
    Ok(())
}

fn validate_restream_switch_target(
    settings: &AppSettings,
    was_desired: bool,
) -> Result<(), AppError> {
    if !was_desired {
        return Ok(());
    }
    if !settings.rtsp_server.enabled {
        return Err(AppError::Validation(
            "Re-stream Server Enable must be on before switching".into(),
        ));
    }
    validate_selected_restream_startable(settings)
}

fn selected_restream_runtime_changed(old: &AppSettings, prospective: &AppSettings) -> bool {
    debug_assert_eq!(old.restream_protocol, prospective.restream_protocol);
    match old.restream_protocol {
        RestreamProtocol::Rtsp => old.rtsp_server != prospective.rtsp_server,
        RestreamProtocol::Srt => old.srt_server != prospective.srt_server,
    }
}

fn relay_preflight(
    handle: Option<Arc<crate::network::readiness::CameraReadiness>>,
    target: Option<CameraTarget>,
    health: Arc<RelayRuntimeHealth>,
    generation: Arc<std::sync::atomic::AtomicU64>,
    expected_generation: u64,
) -> Option<rtsp_server::UpstreamReady> {
    let target = target?; // UDP has no camera gate
    Some(guard_relay_upstream(
        health,
        generation,
        expected_generation,
        Arc::new(move || camera_stream_path(handle.as_ref(), &target)),
    ))
}

fn guard_relay_upstream(
    health: Arc<RelayRuntimeHealth>,
    generation: Arc<std::sync::atomic::AtomicU64>,
    expected_generation: u64,
    ready: rtsp_server::UpstreamReady,
) -> rtsp_server::UpstreamReady {
    Arc::new(move || {
        // User transaction epochs also advance on a healthy no-op Start.
        // Existing connections belong to the installed runtime generation;
        // Stop retires its health before listener teardown starts.
        if generation.load(std::sync::atomic::Ordering::Acquire) != expected_generation
            || !health.upstream_allowed()
        {
            return Err(AppError::Stream(
                "Relay connection superseded or retired".into(),
            ));
        }
        ready()
    })
}

fn resolved_start_is_healthy_noop(
    desired: bool,
    current_spec: Option<&ResolvedStartSpec>,
    candidate_spec: &ResolvedStartSpec,
    relay_state: Option<RelayState>,
    health_generation: Option<u64>,
    listener_generation: Option<u64>,
    listener_loop_alive: bool,
) -> bool {
    desired
        && current_spec.is_some_and(|current| {
            let mut candidate = candidate_spec.clone();
            candidate.bind_scope = current.bind_scope.clone();
            current == &candidate
        })
        && matches!(
            relay_state,
            Some(RelayState::Listening | RelayState::Streaming)
        )
        && health_generation == listener_generation
        && health_generation.is_some()
        && listener_loop_alive
}

fn restream_stop_target(
    stops_desired: bool,
    desired_generation: Option<u64>,
    live_generation: Option<u64>,
) -> Option<u64> {
    if stops_desired {
        // A newer desired generation can coexist briefly with the previous
        // stored listener while Start is resolving/building. The epoch makes
        // that candidate self-discard; teardown must target the listener that
        // is actually stored, not merely the newer health generation.
        live_generation
    } else if live_generation != desired_generation {
        // This Stop was superseded by a newer intent. It may still clean up a
        // listener that does not belong to that newer desired generation.
        live_generation
    } else {
        None
    }
}

fn relay_state_is_generation(state: &RelayData, server_generation: u64) -> bool {
    state.restream_desired
        && state
            .restream_health
            .as_ref()
            .is_some_and(|health| health.server_generation() == server_generation)
}

async fn relay_is_current(
    state: &state::RelaySlot,
    epoch: &Arc<std::sync::atomic::AtomicU64>,
    expected_epoch: u64,
    server_generation: u64,
) -> bool {
    if epoch.load(std::sync::atomic::Ordering::Acquire) != expected_epoch {
        return false;
    }
    let state = state.lock().await;
    relay_state_is_current(&state, epoch, expected_epoch, server_generation)
}

fn relay_state_is_current(
    state: &RelayData,
    epoch: &std::sync::atomic::AtomicU64,
    expected_epoch: u64,
    server_generation: u64,
) -> bool {
    epoch.load(std::sync::atomic::Ordering::Acquire) == expected_epoch
        && state.restream_intent_epoch == Some(expected_epoch)
        && relay_state_is_generation(state, server_generation)
}

// Attribute failure and retry together, only to the request that still owns
// desired state. Cleanup can await policy and lose that ownership.
async fn record_bind_failure(
    state: &state::RelaySlot,
    epoch: &std::sync::atomic::AtomicU64,
    expected_epoch: u64,
    generation: u64,
    reason: String,
    events: Option<&RelayEventSender>,
) -> bool {
    let mut state = state.lock().await;
    if !relay_state_is_current(&state, epoch, expected_epoch, generation) {
        return false;
    }
    if let Some(retry) = state.policy_retry.as_mut() {
        retry.due = None;
    }
    state
        .restream_health
        .as_ref()
        .unwrap()
        .mark_resolution_failed(reason);
    if let Some(events) = events {
        let _ = events.send(RelaySupervisorEvent::RetryRequested {
            server_generation: generation,
        });
    }
    true
}

async fn wait_relay_backoff(
    state: &state::RelaySlot,
    epoch: &Arc<std::sync::atomic::AtomicU64>,
    wake: &Arc<Notify>,
    expected_epoch: u64,
    server_generation: u64,
    delay: std::time::Duration,
) -> bool {
    // Register before the initial authority check. If Stop/new Start landed
    // earlier, the check sees it; if it lands afterward, this registered wake
    // prevents a lost notification from sleeping through a 60-second stage.
    let notified = wake.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();

    if !relay_is_current(state, epoch, expected_epoch, server_generation).await {
        return false;
    }
    if !delay.is_zero() {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = &mut notified => {}
        }
    }
    relay_is_current(state, epoch, expected_epoch, server_generation).await
}

async fn current_relay_context(
    ctx: &RelaySupervisorContext,
    server_generation: u64,
) -> Option<(u64, Arc<RelayRuntimeHealth>)> {
    let state = ctx.state.lock().await;
    if !relay_state_is_generation(&state, server_generation) {
        return None;
    }
    let expected_epoch = state.restream_intent_epoch?;
    if ctx
        .restream_epoch
        .load(std::sync::atomic::Ordering::Acquire)
        != expected_epoch
    {
        return None;
    }
    Some((expected_epoch, state.restream_health.as_ref()?.clone()))
}

async fn publish_relay_status(ctx: &RelaySupervisorContext) {
    ctx.status.refresh().await;
}

async fn poll_relay_fault(ctx: &RelaySupervisorContext) -> Option<RelayFaultEvent> {
    let (health, probe) = {
        let state = ctx.state.lock().await;
        if !state.restream_desired {
            return None;
        }
        (
            state.restream_health.as_ref()?.clone(),
            state
                .restream_server
                .as_ref()
                .map(RestreamServer::fault_probe),
        )
    };

    if let Some(event) = probe.and_then(|probe| probe.poll_fault()) {
        return Some(event);
    }

    health.evaluate_watchdog(tokio::time::Instant::now())
}

async fn poll_policy_retry(ctx: &RelaySupervisorContext) -> Option<(u64, u64)> {
    let state = ctx.state.lock().await;
    let (retry, _) = state.eligible_policy_retry()?;
    let epoch = state.restream_intent_epoch?;
    (retry.due? <= tokio::time::Instant::now()
        && relay_state_is_current(&state, &ctx.restream_epoch, epoch, retry.generation))
    .then_some((retry.generation, epoch))
}

async fn retry_relay_policy(ctx: &RelaySupervisorContext, generation: u64, epoch: u64) {
    if !relay_is_current(&ctx.state, &ctx.restream_epoch, epoch, generation).await {
        return;
    }
    let _lifecycle = ctx.relay_lifecycle.lock().await;
    let spec = {
        let state = ctx.state.lock().await;
        if !relay_state_is_current(&state, &ctx.restream_epoch, epoch, generation) {
            return;
        }
        let Some((retry, spec)) = state.eligible_policy_retry() else {
            return;
        };
        if !retry
            .due
            .is_some_and(|due| due <= tokio::time::Instant::now())
        {
            return;
        }
        spec.clone()
    };
    // A fault may have arrived while waiting for serialization. It owns recovery.
    if let Some(fault) = poll_relay_fault(ctx).await {
        let _ = ctx.relay_event_tx.send(RelaySupervisorEvent::Fault(fault));
        return;
    }
    publish_relay_status(ctx).await;
    apply_firewall(
        &ctx.state,
        ctx.policy.as_ref(),
        &spec,
        generation,
        &ctx.restream_epoch,
        epoch,
        &ctx.relay_wake,
        "retry",
    )
    .await;
    // Epoch-only supersession still owns this lease. Only Stop/replacement
    // warrants cleanup; an admitted result may satisfy the coalesced Start.
    let still_owned = {
        let state = ctx.state.lock().await;
        relay_state_is_generation(&state, generation)
    };
    if !still_owned {
        retire_firewall(&ctx.state, ctx.policy.as_ref(), generation).await;
    }
    drop(_lifecycle);
    publish_relay_status(ctx).await;
}

pub(super) async fn run_relay_supervisor(
    mut events: RelayEventReceiver,
    ctx: RelaySupervisorContext,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut channel_open = true;

    loop {
        let event = tokio::select! {
            biased;
            received = events.recv(), if channel_open => {
                match received {
                    Some(event) => Some(event),
                    None => {
                        channel_open = false;
                        None
                    }
                }
            }
            _ = interval.tick() => {
                if let Some(fault) = poll_relay_fault(&ctx).await {
                    Some(RelaySupervisorEvent::Fault(fault))
                } else {
                    if let Some((generation, epoch)) = poll_policy_retry(&ctx).await {
                        retry_relay_policy(&ctx, generation, epoch).await;
                    }
                    None
                }
            }
        };

        let Some(event) = event else {
            continue;
        };
        match event {
            RelaySupervisorEvent::Fault(event) => {
                let generation = event.fault.server_generation;
                let Some((expected_epoch, health)) = current_relay_context(&ctx, generation).await
                else {
                    continue;
                };
                if !health.accept_fault(&event.fault) {
                    continue;
                }
                publish_relay_status(&ctx).await;
                recover_relay_generation(
                    &ctx,
                    expected_epoch,
                    generation,
                    event.fault.kind.as_str(),
                )
                .await;
            }
            RelaySupervisorEvent::RetryRequested { server_generation } => {
                let Some((expected_epoch, health)) =
                    current_relay_context(&ctx, server_generation).await
                else {
                    continue;
                };
                if !matches!(
                    health.snapshot().state,
                    RelayState::Failed | RelayState::Recovering
                ) {
                    continue;
                }
                recover_relay_generation(&ctx, expected_epoch, server_generation, "explicit_retry")
                    .await;
            }
        }
    }
}

async fn adopted_ip_set(
    readiness: &Arc<crate::network::readiness::CameraReadiness>,
) -> std::collections::HashSet<String> {
    readiness.adopted_addresses().await
}

async fn recover_relay_generation(
    ctx: &RelaySupervisorContext,
    expected_epoch: u64,
    server_generation: u64,
    cause: &'static str,
) {
    let recovery_started = tokio::time::Instant::now();
    {
        let mut state = ctx.state.lock().await;
        if relay_state_is_current(
            &state,
            &ctx.restream_epoch,
            expected_epoch,
            server_generation,
        ) {
            if let Some(retry) = state.policy_retry.as_mut() {
                retry.due = None;
            }
        }
    }
    // Retire and fully release the failed listener before applying backoff.
    // The lifecycle gate is also the Stop completion barrier.
    {
        let _lifecycle = ctx.relay_lifecycle.lock().await;
        if !relay_is_current(
            &ctx.state,
            &ctx.restream_epoch,
            expected_epoch,
            server_generation,
        )
        .await
        {
            return;
        }
        let failed_server = {
            let mut state = ctx.state.lock().await;
            if state
                .restream_server
                .as_ref()
                .is_some_and(|server| server.server_generation() == server_generation)
            {
                state.restream_server.take()
            } else {
                None
            }
        };
        if let Some(mut failed_server) = failed_server {
            failed_server.shutdown().await;
        }
        retire_firewall(&ctx.state, ctx.policy.as_ref(), server_generation).await;
    }
    publish_relay_status(ctx).await;
    if current_relay_context(ctx, server_generation)
        .await
        .is_some_and(|(_, h)| {
            h.snapshot().state == RelayState::Failed && h.snapshot().error.is_some()
        })
    {
        // A typed permanent media error is terminal until explicit Start.
        let state = ctx.state.lock().await;
        if state
            .restream_health
            .as_ref()
            .is_some_and(|h| h.permanent_failure())
        {
            return;
        }
    }

    loop {
        let Some((current_epoch, health)) = current_relay_context(ctx, server_generation).await
        else {
            return;
        };
        if current_epoch != expected_epoch {
            return;
        }

        let (attempt, delay) = health.schedule_recovery_attempt();
        let selection = ctx.readiness.selection().await;
        log::info!("event=relay_recovery adapter_mac={} interface_index={} generation={} cause={} attempt={} phase=backoff delay_ms={} duration_ms={}",
            crate::network::log_value(selection.selected_mac.as_deref().unwrap_or("unknown")), selection.interface_index.unwrap_or(0),
            server_generation, cause, attempt, delay.as_millis(), recovery_started.elapsed().as_millis());
        publish_relay_status(ctx).await;
        if !wait_relay_backoff(
            &ctx.state,
            &ctx.restream_epoch,
            &ctx.relay_wake,
            expected_epoch,
            server_generation,
            delay,
        )
        .await
        {
            return;
        }
        health.mark_recovery_in_progress();
        publish_relay_status(ctx).await;

        let base_spec = {
            let state = ctx.state.lock().await;
            let Some(spec) = state.restream_spec.as_ref() else {
                return;
            };
            spec.clone()
        };
        let mut build_spec = base_spec.clone();

        // Keep one adopted-address set for initial resolution and every
        // validation in this attempt, all obtained before lifecycle.
        let adopted = if base_spec.bind_interface.is_some() {
            adopted_ip_set(&ctx.readiness).await
        } else {
            HashSet::new()
        };
        if !relay_is_current(
            &ctx.state,
            &ctx.restream_epoch,
            expected_epoch,
            server_generation,
        )
        .await
        {
            return;
        }
        if base_spec.bind_interface.is_none()
            || base_spec.bind_identity.is_some()
            || health.should_reresolve_explicit_bind()
        {
            let resolved = ctx
                .bindings
                .resolve(
                    base_spec.bind_interface.as_deref(),
                    base_spec.bind_identity.as_ref().map(|i| i.guid.as_str()),
                    &adopted,
                )
                .await;
            if !relay_is_current(
                &ctx.state,
                &ctx.restream_epoch,
                expected_epoch,
                server_generation,
            )
            .await
            {
                return;
            }
            match resolved {
                Ok((identity, scope @ BindScope::Interface { .. }))
                    if base_spec.bind_interface.is_some() =>
                {
                    if let BindScope::Interface { address, alias, .. } = &scope {
                        build_spec.bind_address = Some(address.clone());
                        build_spec.advertised_ip = address.clone();
                        build_spec.bind_interface = Some(alias.clone());
                    }
                    build_spec.bind_identity = identity;
                    build_spec.bind_scope = scope;
                }
                result if base_spec.bind_interface.is_none() => {
                    build_spec.bind_scope =
                        result
                            .map(|(_, scope)| scope)
                            .unwrap_or_else(|error| BindScope::Unknown {
                                reason: redact_relay_text(
                                    &error.to_string(),
                                    base_spec.mount_path(),
                                ),
                            });
                }
                result => {
                    let detail = match result {
                        Err(error) => error.to_string(),
                        Ok(_) => "Explicit binding did not resolve to an interface".into(),
                    };
                    let reason = redact_relay_text(
                        &format!("Re-stream bind interface is unavailable: {detail}"),
                        base_spec.mount_path(),
                    );
                    let state = ctx.state.lock().await;
                    if !relay_state_is_current(
                        &state,
                        &ctx.restream_epoch,
                        expected_epoch,
                        server_generation,
                    ) {
                        return;
                    }
                    health.mark_resolution_failed(reason);
                    health.force_max_backoff();
                    drop(state);
                    publish_relay_status(ctx).await;
                    continue;
                }
            }
        }

        let _lifecycle = ctx.relay_lifecycle.lock().await;
        if !relay_is_current(
            &ctx.state,
            &ctx.restream_epoch,
            expected_epoch,
            server_generation,
        )
        .await
        {
            return;
        }

        // Normally the first retirement already emptied this slot.  Recheck
        // under the gate so a duplicate or unusual callback can never leave
        // two listeners alive for one generation.
        let prior = {
            let mut state = ctx.state.lock().await;
            if state
                .restream_server
                .as_ref()
                .is_some_and(|server| server.server_generation() == server_generation)
            {
                state.restream_server.take()
            } else {
                None
            }
        };
        if let Some(mut prior) = prior {
            prior.shutdown().await;
        }
        if !relay_is_current(
            &ctx.state,
            &ctx.restream_epoch,
            expected_epoch,
            server_generation,
        )
        .await
        {
            return;
        }

        if let Err(error) = preflight_restream(&build_spec) {
            let server_instance = health.begin_server_instance(true);
            let reason = redact_relay_text(&error.to_string(), build_spec.mount_path());
            health.mark_build_failed(server_instance, reason, false);
            drop(_lifecycle);
            publish_relay_status(ctx).await;
            continue;
        }

        let target = ctx.state.lock().await.restream_target.clone();
        if let Err(error) = preflight_target(Some(&ctx.readiness), target.as_ref()).await {
            health.mark_resolution_failed(error.to_string());
            drop(_lifecycle);
            publish_relay_status(ctx).await;
            continue;
        }
        if !relay_is_current(
            &ctx.state,
            &ctx.restream_epoch,
            expected_epoch,
            server_generation,
        )
        .await
        {
            return;
        }
        let validity = bind_validity(
            ctx.bindings.as_ref(),
            &build_spec,
            &adopted,
            server_generation,
            "rebuild_preflight",
        )
        .await;
        if !relay_is_current(
            &ctx.state,
            &ctx.restream_epoch,
            expected_epoch,
            server_generation,
        )
        .await
        {
            return;
        }
        match validity {
            BindValidity::Refreshed(scope) => build_spec.bind_scope = scope,
            BindValidity::Invalidated(reason) => {
                if !record_bind_failure(
                    &ctx.state,
                    &ctx.restream_epoch,
                    expected_epoch,
                    server_generation,
                    reason,
                    None,
                )
                .await
                {
                    return;
                }
                drop(_lifecycle);
                publish_relay_status(ctx).await;
                continue;
            }
            BindValidity::Unchanged => {}
        }
        apply_firewall(
            &ctx.state,
            ctx.policy.as_ref(),
            &build_spec,
            server_generation,
            &ctx.restream_epoch,
            expected_epoch,
            &ctx.relay_wake,
            "rebuild",
        )
        .await;
        if !relay_is_current(
            &ctx.state,
            &ctx.restream_epoch,
            expected_epoch,
            server_generation,
        )
        .await
        {
            retire_firewall(&ctx.state, ctx.policy.as_ref(), server_generation).await;
            return;
        }
        let validity = bind_validity(
            ctx.bindings.as_ref(),
            &build_spec,
            &adopted,
            server_generation,
            "rebuild_policy",
        )
        .await;
        if !relay_is_current(
            &ctx.state,
            &ctx.restream_epoch,
            expected_epoch,
            server_generation,
        )
        .await
        {
            retire_firewall(&ctx.state, ctx.policy.as_ref(), server_generation).await;
            return;
        }
        match validity {
            BindValidity::Refreshed(scope) => build_spec.bind_scope = scope,
            BindValidity::Invalidated(reason) => {
                retire_firewall(&ctx.state, ctx.policy.as_ref(), server_generation).await;
                if !record_bind_failure(
                    &ctx.state,
                    &ctx.restream_epoch,
                    expected_epoch,
                    server_generation,
                    reason,
                    None,
                )
                .await
                {
                    return;
                }
                drop(_lifecycle);
                publish_relay_status(ctx).await;
                continue;
            }
            BindValidity::Unchanged => {}
        }
        let (server_instance, result) = RelayService::build_restream_server(
            &build_spec,
            health.clone(),
            ctx.relay_event_tx.clone(),
            true,
            relay_preflight(
                Some(ctx.readiness.clone()),
                target,
                health.clone(),
                ctx.restream_generation.clone(),
                server_generation,
            ),
        );
        let server = match result {
            Ok(server) => server,
            Err(failure) => {
                retire_firewall(&ctx.state, ctx.policy.as_ref(), server_generation).await;
                let reason = redact_relay_text(&failure.error.to_string(), build_spec.mount_path());
                {
                    let state = ctx.state.lock().await;
                    if !relay_state_is_current(
                        &state,
                        &ctx.restream_epoch,
                        expected_epoch,
                        server_generation,
                    ) {
                        return;
                    }
                    health.mark_build_failed(
                        server_instance,
                        reason,
                        failure.kind == RestreamBuildFailureKind::Bind,
                    );
                }
                drop(_lifecycle);
                publish_relay_status(ctx).await;
                continue;
            }
        };

        let mut candidate = Some(server);
        let validity = if relay_is_current(
            &ctx.state,
            &ctx.restream_epoch,
            expected_epoch,
            server_generation,
        )
        .await
        {
            bind_validity(
                ctx.bindings.as_ref(),
                &build_spec,
                &adopted,
                server_generation,
                "rebuild_install",
            )
            .await
        } else {
            BindValidity::Unchanged
        };
        {
            let mut state = ctx.state.lock().await;
            if relay_state_is_current(
                &state,
                &ctx.restream_epoch,
                expected_epoch,
                server_generation,
            ) && !matches!(validity, BindValidity::Invalidated(_))
            {
                if let BindValidity::Refreshed(scope) = &validity {
                    build_spec.bind_scope = scope.clone();
                }
                // Publish a re-resolved address only after it bound
                // successfully. Port, interface, mount, token, and source are
                // byte-for-byte inherited from the desired specification.
                state.restream_spec = Some(build_spec);
                state.restream_server = candidate.take();
            }
        }
        if let Some(mut stale) = candidate {
            crate::network::note_fence_drop("relay_listener");
            stale.shutdown().await;
            retire_firewall(&ctx.state, ctx.policy.as_ref(), server_generation).await;
            if let BindValidity::Invalidated(reason) = validity {
                if !record_bind_failure(
                    &ctx.state,
                    &ctx.restream_epoch,
                    expected_epoch,
                    server_generation,
                    reason,
                    None,
                )
                .await
                {
                    return;
                }
                drop(_lifecycle);
                publish_relay_status(ctx).await;
                continue;
            }
            return;
        }
        log::info!("event=relay_recovery generation={} cause={} attempt={} phase=listener_ready duration_ms={}",
            server_generation, cause, attempt, recovery_started.elapsed().as_millis());

        drop(_lifecycle);
        publish_relay_status(ctx).await;
        return;
    }
}

fn scope_revision(scope: &BindScope) -> Option<u64> {
    match scope {
        BindScope::AllAddresses {
            topology_revision, ..
        }
        | BindScope::Interface {
            topology_revision, ..
        } => Some(*topology_revision),
        BindScope::Unknown { .. } => None,
    }
}

fn preflight_restream(spec: &ResolvedStartSpec) -> Result<(), AppError> {
    crate::ensure_gstreamer()?;
    let input: &[&str] = match spec.source {
        ResolvedSource::Rtsp { .. } => &["rtspsrc", "rtph264depay"],
        ResolvedSource::Udp { .. } => &["udpsrc", "tsdemux"],
    };
    let output: &[&str] = match spec.protocol() {
        RestreamProtocol::Rtsp => &["h264parse", "rtph264pay"],
        RestreamProtocol::Srt => &["h264parse", "mpegtsmux", "srtsink"],
    };
    for name in input.iter().chain(output) {
        if gst::ElementFactory::find(name).is_none() {
            return Err(AppError::Stream(format!(
                "Bundled GStreamer lacks required element '{name}'"
            )));
        }
    }
    if matches!(spec.source, ResolvedSource::Rtsp { .. }) {
        let source = gst::ElementFactory::make("rtspsrc")
            .build()
            .map_err(|_| AppError::Stream("RTSP source preflight failed".into()))?;
        configure_tcp_rtspsrc(&source)?;
    }
    if spec.protocol() == RestreamProtocol::Srt {
        srt_server::preflight().map_err(|failure| failure.error)?;
    }
    Ok(())
}

fn firewall_role(protocol: RestreamProtocol) -> FirewallRule {
    match protocol {
        RestreamProtocol::Rtsp => FirewallRule::Rtsp,
        RestreamProtocol::Srt => FirewallRule::Srt,
    }
}

fn observe_policy_result(
    state: &mut RelayData,
    generation: u64,
    phase: &str,
    result: &PolicyResult,
    retiring: bool,
) {
    if relay_state_is_generation(state, generation) {
        if let Some(retry) = state
            .policy_retry
            .as_mut()
            .filter(|r| r.generation == generation)
        {
            retry.observe(result, retiring, phase == "retry");
        }
    }
}

fn log_relay_firewall(
    phase: &str,
    generation: u64,
    role: FirewallRule,
    result: &PolicyResult,
    retry: Option<&PolicyRetry>,
    spec: Option<&ResolvedStartSpec>,
) {
    let (outcome, action, verified, blocks, stage, uncertain, reason) = match &result.outcome {
        FirewallOutcome::Applied {
            action,
            verified_shape,
            observed_block_rules,
            ..
        } => (
            "applied",
            match action {
                firewall::RuleAction::Created => "created",
                firewall::RuleAction::Updated => "updated",
                firewall::RuleAction::Unchanged => "unchanged",
            },
            if *verified_shape { "true" } else { "false" },
            observed_block_rules.len(),
            "-",
            "-",
            "-",
        ),
        FirewallOutcome::Inactive => (
            "inactive",
            "-",
            "-",
            0,
            "-",
            "-",
            if result.admitted { "-" } else { "superseded" },
        ),
        FirewallOutcome::Unavailable { reason } => {
            ("unavailable", "-", "-", 0, "-", "-", reason.as_str())
        }
        FirewallOutcome::Failed {
            stage,
            reason,
            uncertain,
        } => (
            "failed",
            "-",
            "-",
            0,
            stage.as_str(),
            if *uncertain { "true" } else { "false" },
            reason.as_str(),
        ),
    };
    let mut reason = redact_relay_text(reason, spec.map_or("", ResolvedStartSpec::mount_path));
    if let Some(spec) = spec {
        for secret in [&spec.username, &spec.password]
            .into_iter()
            .chain(match &spec.output {
                ResolvedOutput::Srt { passphrase, .. } => Some(passphrase),
                _ => None,
            })
        {
            if !secret.is_empty() {
                reason = reason.replace(secret, "***");
            }
        }
    }
    let line = format!("event=relay_firewall phase={} generation={} role={} admitted={} outcome={} action={} verified={} blocks={} stage={} uncertain={} retry_for_generation={} next_retry_ms={} reason={}",
        phase, generation, match role { FirewallRule::Rtsp => "rtsp", FirewallRule::Srt => "srt" }, result.admitted,
        outcome, action, verified, blocks, crate::network::log_value(&stage.chars().take(64).collect::<String>()), uncertain,
        retry.map_or_else(|| "-".into(), |r| r.generation.to_string()),
        retry.and_then(|r| r.due).map_or_else(|| "-".into(), |due| due.saturating_duration_since(tokio::time::Instant::now()).as_millis().to_string()),
        crate::network::log_value(&reason.chars().take(256).collect::<String>()));
    if result.admitted
        && (clean_firewall(&result.outcome) || result.outcome == FirewallOutcome::Inactive)
    {
        log::info!("{line}");
    } else {
        log::warn!("{line}");
    }
}

// All callers hold relay_lifecycle. The lease is installed before dispatch, so
// cancellation cannot hide an enabled rule from Stop/startup reconciliation.
#[allow(clippy::too_many_arguments)] // Existing lifecycle/admission inputs plus the result's phase.
async fn apply_firewall(
    state: &state::RelaySlot,
    policy: &dyn RelayPolicy,
    spec: &ResolvedStartSpec,
    generation: u64,
    epoch: &Arc<std::sync::atomic::AtomicU64>,
    expected_epoch: u64,
    wake: &Notify,
    phase: &'static str,
) -> FirewallOutcome {
    if !relay_is_current(state, epoch, expected_epoch, generation).await {
        return FirewallOutcome::Inactive;
    }
    apply_firewall_with(
        state,
        spec,
        generation,
        phase,
        |r, p, i| {
            policy.ensure(
                r,
                p,
                i,
                Box::pin(obsolete_ensure(
                    state,
                    epoch,
                    expected_epoch,
                    generation,
                    wake,
                )),
            )
        },
        |r| policy.disable(r),
        relay_is_current(state, epoch, expected_epoch, generation),
    )
    .await
}

async fn obsolete_ensure(
    state: &state::RelaySlot,
    epoch: &Arc<std::sync::atomic::AtomicU64>,
    expected_epoch: u64,
    generation: u64,
    wake: &Notify,
) {
    loop {
        let notified = wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if !relay_is_current(state, epoch, expected_epoch, generation).await {
            return;
        }
        notified.await;
    }
}

// Focused policy-result seam. Production still awaits the existing shared
// retained native executor through firewall::{ensure, disable}, inline.
async fn apply_firewall_with<E, D>(
    state: &state::RelaySlot,
    spec: &ResolvedStartSpec,
    generation: u64,
    phase: &'static str,
    ensure: impl FnOnce(FirewallRule, u16, Option<crate::network::interface::NativeIdentity>) -> E,
    disable: impl FnOnce(FirewallRule) -> D,
    current: impl Future<Output = bool>,
) -> FirewallOutcome
where
    E: std::future::Future<Output = PolicyResult>,
    D: std::future::Future<Output = PolicyResult>,
{
    let role = firewall_role(spec.protocol());
    let prior = state.lock().await.firewall_generation;
    if let Some((prior_generation, _)) = prior.filter(|lease| *lease != (generation, role)) {
        if retire_firewall_with(state, prior_generation, Some((generation, phase)), disable)
            .await
            .is_err()
        {
            // In particular, never expose a cancellation sentinel as retirement.
            return state.lock().await.firewall.clone();
        }
    }
    let installed = {
        let mut state = state.lock().await;
        if !relay_state_is_generation(&state, generation) {
            return FirewallOutcome::Inactive;
        }
        let installed = state.firewall_generation != Some((generation, role));
        state.firewall_generation = Some((generation, role));
        installed
    };
    let result = ensure(role, spec.server_port(), spec.bind_identity.clone()).await;
    let obsolete = !result.admitted && !current.await;
    let mut state = state.lock().await;
    if state.firewall_generation == Some((generation, role)) {
        if installed && obsolete && result.outcome == FirewallOutcome::Inactive {
            state.firewall_generation = None;
        } else if result.admitted || result.outcome != FirewallOutcome::Inactive {
            state.firewall = result.outcome.clone();
        }
    }
    observe_policy_result(&mut state, generation, phase, &result, false);
    log_relay_firewall(
        phase,
        generation,
        role,
        &result,
        state
            .policy_retry
            .as_ref()
            .filter(|r| r.generation == generation),
        Some(spec),
    );
    result.outcome
}

async fn retire_firewall(
    state: &state::RelaySlot,
    policy: &dyn RelayPolicy,
    generation: u64,
) -> bool {
    retire_firewall_with(state, generation, None, |r| policy.disable(r))
        .await
        .is_ok()
}

async fn retire_firewall_with<D>(
    state: &state::RelaySlot,
    generation: u64,
    retry_for: Option<(u64, &'static str)>,
    disable: impl FnOnce(FirewallRule) -> D,
) -> Result<(), PolicyResult>
where
    D: std::future::Future<Output = PolicyResult>,
{
    let lease = {
        let state = state.lock().await;
        match state.firewall_generation {
            Some((current, role)) if current == generation => Some(role),
            _ => None,
        }
    };
    if let Some(role) = lease {
        let result = disable(role).await;
        let disabled = result.admitted && result.outcome == FirewallOutcome::Inactive;
        let mut state = state.lock().await;
        if state.firewall_generation == Some((generation, role)) {
            if disabled {
                state.firewall_generation = None;
            }
            if result.admitted || result.outcome != FirewallOutcome::Inactive {
                state.firewall = result.outcome.clone();
            }
        }
        if let Some((generation, phase)) = retry_for {
            observe_policy_result(&mut state, generation, phase, &result, true);
        }
        log_relay_firewall(
            "retire",
            generation,
            role,
            &result,
            retry_for.and_then(|(g, _)| state.policy_retry.as_ref().filter(|r| r.generation == g)),
            state.restream_spec.as_ref(),
        );
        if disabled {
            Ok(())
        } else {
            Err(result)
        }
    } else {
        Ok(())
    }
}

/// True if `addr` is an APIPA (169.254.0.0/16) address — a DHCP-failure
/// fallback that can't carry usable client traffic.
fn is_apipa(addr: &str) -> bool {
    addr.starts_with("169.254.")
}

/// First IPv4 on `ips` that is neither an adopted camera-network secondary
/// nor APIPA. `None` if the interface carries only such addresses — the
/// caller turns that into a clear error rather than binding the output socket
/// to the camera network.
fn first_usable_ip(
    ips: &[crate::network::interface::IpInfo],
    adopted: &std::collections::HashSet<String>,
) -> Option<String> {
    ips.iter()
        .map(|ip| ip.address.clone())
        .find(|addr| !adopted.contains(addr) && !is_apipa(addr))
}

/// Best client-facing IPv4 to advertise when no explicit bind interface is
/// set: prefer physical WiFi (the camera occupies Ethernet), else physical
/// Ethernet, always skipping adopted secondaries and APIPA. VPN addresses
/// require an explicit selection. Returns
/// `None` only if nothing usable exists (caller advertises 0.0.0.0).
async fn get_display_ip(adopted: &std::collections::HashSet<String>) -> Option<String> {
    let interfaces = crate::network::interface::list_all().await.ok()?;
    select_display_ip(&interfaces, adopted)
}

fn select_display_ip(
    interfaces: &[crate::network::InterfaceInfo],
    adopted: &std::collections::HashSet<String>,
) -> Option<String> {
    let physical = interfaces
        .iter()
        .filter(|i| i.is_up && !i.is_vpn && !i.is_virtual);
    physical
        .clone()
        .filter(|i| i.is_wifi)
        .chain(physical.filter(|i| i.is_ethernet && !i.is_wifi))
        .find_map(|i| first_usable_ip(&i.ips, adopted))
}

#[cfg(test)]
mod tests {
    use super::*;

    mod topology {
        use super::*;
        use std::collections::VecDeque;
        use std::sync::{
            atomic::{AtomicU64, Ordering},
            Mutex as SyncMutex,
        };

        #[derive(Default)]
        struct Barrier {
            entered: Notify,
            release: Notify,
        }
        impl Barrier {
            async fn wait(&self) {
                self.entered.notify_one();
                self.release.notified().await;
            }
        }

        struct Read {
            result: BindingResolution,
            barrier: Option<Arc<Barrier>>,
            revision_after: Option<u64>,
        }
        impl Read {
            fn ready(result: BindingResolution) -> Self {
                Self {
                    result,
                    barrier: None,
                    revision_after: None,
                }
            }
            fn blocked(result: BindingResolution, barrier: &Arc<Barrier>) -> Self {
                Self {
                    result,
                    barrier: Some(barrier.clone()),
                    revision_after: None,
                }
            }
        }

        #[derive(Debug, PartialEq, Eq)]
        struct Selection {
            alias: Option<String>,
            id: Option<String>,
            adopted: HashSet<String>,
        }
        struct Bindings {
            revision: AtomicU64,
            revision_reads: AtomicU64,
            samples: SyncMutex<VecDeque<u64>>,
            reads: SyncMutex<VecDeque<Read>>,
            selections: SyncMutex<Vec<Selection>>,
        }
        impl Bindings {
            fn new(samples: &[u64], reads: Vec<Read>) -> Arc<Self> {
                Arc::new(Self {
                    revision: AtomicU64::new(1),
                    revision_reads: AtomicU64::new(0),
                    samples: SyncMutex::new(samples.iter().copied().collect()),
                    reads: SyncMutex::new(reads.into()),
                    selections: SyncMutex::new(vec![]),
                })
            }
            fn read_count(&self) -> usize {
                self.selections.lock().unwrap().len()
            }
        }
        impl RelayBindings for Bindings {
            fn revision(&self) -> u64 {
                self.revision_reads.fetch_add(1, Ordering::AcqRel);
                if let Some(sample) = self.samples.lock().unwrap().pop_front() {
                    self.revision.store(sample, Ordering::Release);
                }
                self.revision.load(Ordering::Acquire)
            }
            fn resolve<'a>(
                &'a self,
                alias: Option<&'a str>,
                id: Option<&'a str>,
                adopted: &'a HashSet<String>,
            ) -> RelayFuture<'a, BindingResolution> {
                self.selections.lock().unwrap().push(Selection {
                    alias: alias.map(str::to_owned),
                    id: id.map(str::to_owned),
                    adopted: adopted.clone(),
                });
                let read = self
                    .reads
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected binding read");
                Box::pin(async move {
                    if let Some(barrier) = read.barrier {
                        barrier.wait().await;
                    }
                    if let Some(revision) = read.revision_after {
                        self.revision.store(revision, Ordering::Release);
                    }
                    read.result
                })
            }
        }

        #[derive(Default)]
        struct Policy {
            ensures: SyncMutex<Vec<(FirewallRule, u16, Option<NativeIdentity>)>>,
            disables: SyncMutex<Vec<FirewallRule>>,
            calls: SyncMutex<Vec<(&'static str, FirewallRule)>>,
            ensure_results: SyncMutex<VecDeque<PolicyResult>>,
            disable_results: SyncMutex<VecDeque<PolicyResult>>,
            ensure_barrier: SyncMutex<Option<Arc<Barrier>>>,
            admission_barrier: SyncMutex<Option<Arc<Barrier>>>,
            disable_barrier: SyncMutex<Option<Arc<Barrier>>>,
        }
        impl RelayPolicy for Policy {
            fn ensure<'a>(
                &'a self,
                rule: FirewallRule,
                port: u16,
                identity: Option<NativeIdentity>,
                abort: RelayFuture<'a, ()>,
            ) -> RelayFuture<'a, PolicyResult> {
                let admission = self.admission_barrier.lock().unwrap().take();
                let barrier = self.ensure_barrier.lock().unwrap().take();
                let result = self.ensure_results.lock().unwrap().pop_front();
                Box::pin(async move {
                    let availability = async {
                        if let Some(admission) = admission {
                            admission.wait().await;
                        }
                    };
                    tokio::select! {
                        biased;
                        () = abort => return PolicyResult { admitted: false, outcome: FirewallOutcome::Inactive },
                        () = availability => (),
                    }
                    self.ensures.lock().unwrap().push((rule, port, identity));
                    self.calls.lock().unwrap().push(("ensure", rule));
                    if let Some(barrier) = barrier {
                        barrier.wait().await;
                    }
                    result.unwrap_or_else(|| {
                        PolicyResult::accepted(FirewallOutcome::Applied {
                            rule_name: "owned-test-rule".into(),
                            action: firewall::RuleAction::Unchanged,
                            verified_shape: true,
                            observed_block_rules: vec![],
                        })
                    })
                })
            }
            fn disable(&self, rule: FirewallRule) -> RelayFuture<'_, PolicyResult> {
                self.disables.lock().unwrap().push(rule);
                self.calls.lock().unwrap().push(("disable", rule));
                let barrier = self.disable_barrier.lock().unwrap().take();
                let result = self.disable_results.lock().unwrap().pop_front();
                Box::pin(async move {
                    if let Some(barrier) = barrier {
                        barrier.wait().await;
                    }
                    result.unwrap_or_else(|| PolicyResult::accepted(FirewallOutcome::Inactive))
                })
            }
        }

        fn wildcard(revision: u64) -> BindingResolution {
            Ok((
                None,
                BindScope::AllAddresses {
                    family: bindings::SocketFamily::Ipv4,
                    addresses: vec![bindings::BoundAddress {
                        id: "unrelated".into(),
                        alias: "Other adapter".into(),
                        address: format!("192.0.2.{revision}"),
                    }],
                    topology_revision: revision,
                },
            ))
        }
        fn explicit(address: &str, revision: u64) -> BindingResolution {
            Ok((
                Some(NativeIdentity {
                    guid: "uplink".into(),
                    index: 7,
                    mac: "00:11:22:33:44:55".into(),
                    alias: "Uplink".into(),
                }),
                BindScope::Interface {
                    id: "uplink".into(),
                    alias: "Uplink".into(),
                    address: address.into(),
                    family: bindings::SocketFamily::Ipv4,
                    topology_revision: revision,
                },
            ))
        }
        fn observation(explicit_bind: bool, revision: u64) -> BindingResolution {
            if explicit_bind {
                explicit("127.0.0.1", revision)
            } else {
                wildcard(revision)
            }
        }
        fn failed() -> BindingResolution {
            Err(AppError::Network("inventory unavailable".into()))
        }
        fn spec(settings: &AppSettings, explicit_bind: bool, revision: u64) -> ResolvedStartSpec {
            let mut spec = resolved_spec_for_test(settings);
            let (identity, scope) = observation(explicit_bind, revision).unwrap();
            spec.bind_identity = identity;
            spec.bind_scope = scope;
            if explicit_bind {
                spec.bind_interface = Some("Uplink".into());
                spec.bind_address = Some("127.0.0.1".into());
            }
            spec
        }
        fn fixture(
            protocol: RestreamProtocol,
            explicit_bind: bool,
            bindings: Arc<Bindings>,
            policy: Arc<Policy>,
        ) -> (StreamManager, AppSettings) {
            init_gstreamer();
            let mut manager = StreamManager::with_selected_protocol(protocol);
            let readiness = crate::network::NetworkManager::new().readiness();
            manager.relay = Arc::new(RelayService::with_providers(
                manager.relay.state.clone(),
                manager.status.clone(),
                Some(readiness),
                bindings,
                policy,
            ));
            let mut settings = restream_test_settings(protocol);
            if explicit_bind {
                match protocol {
                    RestreamProtocol::Rtsp => {
                        settings.rtsp_server.bind_interface = "Uplink".into();
                        settings.rtsp_server.bind_interface_id = Some("uplink".into());
                    }
                    RestreamProtocol::Srt => {
                        settings.srt_server.bind_interface = "Uplink".into();
                        settings.srt_server.bind_interface_id = Some("uplink".into());
                    }
                }
            }
            (manager, settings)
        }
        async fn start(
            service: &RelayService,
            settings: &AppSettings,
        ) -> Result<RestreamServerInfo, AppError> {
            let (epoch, preserve) = service.begin_restream_start_intent().await.unwrap();
            service
                .start_restream_server_inner(
                    settings,
                    &HashSet::from(["192.0.2.254".into()]),
                    epoch,
                    preserve,
                )
                .await
        }
        fn spawn_start(
            manager: &StreamManager,
            settings: &AppSettings,
        ) -> tokio::task::JoinHandle<Result<RestreamServerInfo, AppError>> {
            let service = manager.relay.clone();
            let settings = settings.clone();
            tokio::spawn(async move { start(&service, &settings).await })
        }
        async fn seed(manager: &StreamManager, settings: &AppSettings, explicit_bind: bool) {
            seed_desired_relay_state(manager, settings, RelayState::Recovering).await;
            manager.relay.state.lock().await.restream_spec = Some(spec(settings, explicit_bind, 0));
            manager
                .relay
                .restream_generation
                .store(41, Ordering::Release);
        }
        fn assert_no_retry(events: &mut RelayEventReceiver) {
            assert!(matches!(
                events.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ));
        }
        async fn poll_pending<F: Future>(future: Pin<&mut F>) {
            let mut future = future;
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
        }

        #[tokio::test]
        async fn start_policy_waits_then_applies_or_cancels_on_stop_and_newer_start() {
            for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
                for supersession in 0..3 {
                    let barrier = Arc::new(Barrier::default());
                    let bindings = Bindings::new(&[], vec![Read::ready(wildcard(1))]);
                    let policy = Arc::new(Policy::default());
                    *policy.admission_barrier.lock().unwrap() = Some(barrier.clone());
                    let (manager, settings) = fixture(protocol, false, bindings, policy.clone());
                    let start_task = spawn_start(&manager, &settings);
                    barrier.entered.notified().await;
                    assert!(policy.ensures.lock().unwrap().is_empty());
                    assert!(manager
                        .relay
                        .state
                        .lock()
                        .await
                        .firewall_generation
                        .is_some());
                    let stop = match supersession {
                        1 => manager.relay.begin_restream_stop_intent().await,
                        2 => {
                            manager.relay.begin_restream_start_intent().await.unwrap();
                            None
                        }
                        _ => {
                            barrier.release.notify_one();
                            None
                        }
                    };
                    let result = start_task.await.unwrap();
                    assert_eq!(result.is_ok(), supersession == 0);
                    assert_eq!(
                        policy.ensures.lock().unwrap().len(),
                        usize::from(supersession == 0)
                    );
                    assert!(policy.disables.lock().unwrap().is_empty());
                    if supersession != 0 {
                        assert!(manager
                            .relay
                            .state
                            .lock()
                            .await
                            .firewall_generation
                            .is_none());
                        assert!(manager.relay.state.lock().await.restream_server.is_none());
                    }
                    if let Some(stop) = stop {
                        manager.relay.finish_restream_stop(stop).await.unwrap();
                    }
                    manager.stop_restream_server().await.unwrap();
                }
            }
        }

        include!("relay_policy_tests.rs");

        #[tokio::test]
        async fn obsolete_idle_ensure_and_intent_change_after_prior_retirement_never_dispatch() {
            for retire_prior in [false, true] {
                let barrier = Arc::new(Barrier::default());
                let bindings = Bindings::new(&[], vec![]);
                let policy = Arc::new(Policy::default());
                let (manager, settings) =
                    fixture(RestreamProtocol::Rtsp, false, bindings, policy.clone());
                seed_desired_relay_state(&manager, &settings, RelayState::Starting).await;
                if retire_prior {
                    manager.relay.state.lock().await.firewall_generation =
                        Some((40, FirewallRule::Srt));
                    *policy.disable_barrier.lock().unwrap() = Some(barrier.clone());
                } else {
                    manager.relay.begin_restream_start_intent().await.unwrap();
                }
                let service = manager.relay.clone();
                let spec = resolved_spec_for_test(&settings);
                let apply = tokio::spawn(async move {
                    apply_firewall(
                        &service.state,
                        service.policy.as_ref(),
                        &spec,
                        41,
                        &service.restream_epoch,
                        0,
                        &service.relay_wake,
                        "start",
                    )
                    .await
                });
                if retire_prior {
                    barrier.entered.notified().await;
                    manager.relay.begin_restream_start_intent().await.unwrap();
                    // Retirement remains awaited through supersession.
                    assert!(!apply.is_finished());
                    barrier.release.notify_one();
                }
                assert_eq!(apply.await.unwrap(), FirewallOutcome::Inactive);
                assert!(policy.ensures.lock().unwrap().is_empty());
                assert_eq!(
                    policy.disables.lock().unwrap().len(),
                    usize::from(retire_prior)
                );
                assert!(manager
                    .relay
                    .state
                    .lock()
                    .await
                    .firewall_generation
                    .is_none());
                manager.stop_restream_server().await.unwrap();
            }
        }

        #[test]
        fn explicit_predicate_checks_each_binding_component() {
            let settings = restream_test_settings(RestreamProtocol::Rtsp);
            let spec = spec(&settings, true, 1);
            let (identity, scope) = explicit("127.0.0.1", 99).unwrap();
            assert!(!explicit_bind_changed(&spec, identity.as_ref(), &scope));
            for part in 0..5 {
                let mut identity = identity.clone().unwrap();
                let mut scope = scope.clone();
                match part {
                    0 => identity.guid = "replacement".into(),
                    1 => identity.index += 1,
                    2 => identity.mac = "66:77:88:99:aa:bb".into(),
                    3 => {
                        if let BindScope::Interface { alias, .. } = &mut scope {
                            *alias = "Renamed".into();
                        }
                    }
                    _ => {
                        if let BindScope::Interface { address, .. } = &mut scope {
                            *address = "127.0.0.2".into();
                        }
                    }
                }
                assert!(
                    explicit_bind_changed(&spec, Some(&identity), &scope),
                    "component {part}"
                );
            }
            assert!(explicit_bind_changed(&spec, None, &scope));
            assert!(explicit_bind_changed(
                &spec,
                identity.as_ref(),
                &wildcard(2).unwrap().1
            ));
            assert!(explicit_bind_changed(
                &spec,
                identity.as_ref(),
                &BindScope::default()
            ));
        }

        #[tokio::test]
        async fn classification_fast_paths_and_bounded_observation_preserve_stamps() {
            let settings = restream_test_settings(RestreamProtocol::Rtsp);
            let mut spec = spec(&settings, false, 1);
            assert!(matches!(
                classify_bind_validity(&spec, wildcard(2)),
                BindValidity::Refreshed(BindScope::AllAddresses { .. })
            ));
            assert!(matches!(
                classify_bind_validity(&spec, failed()),
                BindValidity::Refreshed(BindScope::Unknown { .. })
            ));
            let provider = Bindings::new(&[1], vec![]);
            assert_eq!(
                bind_validity(provider.as_ref(), &spec, &HashSet::new(), 1, "preflight").await,
                BindValidity::Unchanged
            );
            spec.bind_scope = BindScope::default();
            assert_eq!(
                bind_validity(provider.as_ref(), &spec, &HashSet::new(), 1, "policy").await,
                BindValidity::Unchanged
            );
            assert_eq!(
                classify_bind_validity(&spec, failed()),
                BindValidity::Unchanged
            );
            assert_eq!(provider.read_count(), 0);
            assert_eq!(provider.revision_reads.load(Ordering::Acquire), 1);
            let explicit_spec = self::spec(&settings, true, 1);
            assert!(matches!(
                classify_bind_validity(&explicit_spec, explicit("127.0.0.1", 2)),
                BindValidity::Refreshed(_)
            ));
            for result in [explicit("127.0.0.2", 2), failed(), wildcard(2)] {
                assert!(matches!(
                    classify_bind_validity(&explicit_spec, result),
                    BindValidity::Invalidated(_)
                ));
            }
            let mut read = Read::ready(explicit("127.0.0.1", 2));
            read.revision_after = Some(3);
            let provider = Bindings::new(&[2], vec![read]);
            let result = bind_validity(
                provider.as_ref(),
                &explicit_spec,
                &HashSet::new(),
                1,
                "install",
            )
            .await;
            assert!(
                matches!(result, BindValidity::Refreshed(scope) if scope_revision(&scope) == Some(2))
            );
            assert_eq!(provider.revision.load(Ordering::Acquire), 3);
            assert_eq!(provider.read_count(), 1);
        }

        #[tokio::test]
        async fn start_refreshes_each_checkpoint_and_retains_lease_for_both_protocols() {
            for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
                for explicit_bind in [false, true] {
                    let bindings = Bindings::new(
                        &[2, 3, 4],
                        (1..=4)
                            .map(|r| Read::ready(observation(explicit_bind, r)))
                            .collect(),
                    );
                    let policy = Arc::new(Policy::default());
                    let (manager, settings) =
                        fixture(protocol, explicit_bind, bindings.clone(), policy.clone());
                    let (mut events, _) = manager.relay.supervisor().unwrap();
                    let info = start(&manager.relay, &settings).await.unwrap();
                    {
                        let state = manager.relay.state.lock().await;
                        assert_eq!(
                            state.restream_spec.as_ref().unwrap().bind_scope,
                            info.bind_scope
                        );
                        assert_eq!(scope_revision(&info.bind_scope), Some(4));
                        assert_eq!(state.restream_server.as_ref().unwrap().protocol(), protocol);
                        assert_eq!(
                            state.firewall_generation,
                            Some((1, firewall_role(protocol)))
                        );
                        assert!(matches!(
                            state.restream_health.as_ref().unwrap().snapshot().state,
                            RelayState::Listening | RelayState::Streaming
                        ));
                    }
                    assert_eq!(bindings.read_count(), 4);
                    {
                        let selections = bindings.selections.lock().unwrap();
                        for selection in selections.iter() {
                            assert_eq!(
                                selection.alias.as_deref(),
                                explicit_bind.then_some("Uplink")
                            );
                            assert_eq!(selection.id.as_deref(), explicit_bind.then_some("uplink"));
                            assert_eq!(selection.adopted, HashSet::from(["192.0.2.254".into()]));
                        }
                    }
                    assert_eq!(policy.ensures.lock().unwrap().len(), 1);
                    assert!(policy.disables.lock().unwrap().is_empty());
                    assert_no_retry(&mut events);
                    manager.stop_restream_server().await.unwrap();
                    assert_eq!(*policy.disables.lock().unwrap(), [firewall_role(protocol)]);
                }
            }
        }

        #[tokio::test]
        async fn wildcard_policy_read_failure_installs_unknown_and_watcher_repairs_same_revision() {
            for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
                let bindings = Bindings::new(
                    &[1, 2],
                    vec![Read::ready(wildcard(1)), Read::ready(failed())],
                );
                let policy = Arc::new(Policy::default());
                let (manager, settings) =
                    fixture(protocol, false, bindings.clone(), policy.clone());
                let info = start(&manager.relay, &settings).await.unwrap();
                assert!(matches!(info.bind_scope, BindScope::Unknown { .. }));
                assert_eq!(
                    manager
                        .relay
                        .state
                        .lock()
                        .await
                        .restream_spec
                        .as_ref()
                        .unwrap()
                        .bind_scope,
                    info.bind_scope
                );
                assert_eq!(bindings.read_count(), 2);
                let scope = wildcard(2).unwrap().1;
                manager.binding_topology_changed(scope.clone(), 2).await;
                assert_eq!(
                    manager
                        .relay
                        .state
                        .lock()
                        .await
                        .restream_spec
                        .as_ref()
                        .unwrap()
                        .bind_scope,
                    scope
                );
                assert!(policy.disables.lock().unwrap().is_empty());
                manager.stop_restream_server().await.unwrap();
            }
        }

        #[tokio::test]
        async fn churn_overlapping_ensure_refreshes_without_retiring_the_acquired_lease() {
            for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
                for explicit_bind in [false, true] {
                    let barrier = Arc::new(Barrier::default());
                    let bindings = Bindings::new(
                        &[],
                        vec![
                            Read::ready(observation(explicit_bind, 1)),
                            Read::ready(observation(explicit_bind, 2)),
                        ],
                    );
                    let policy = Arc::new(Policy::default());
                    *policy.ensure_barrier.lock().unwrap() = Some(barrier.clone());
                    let (manager, settings) =
                        fixture(protocol, explicit_bind, bindings.clone(), policy.clone());
                    let (mut events, _) = manager.relay.supervisor().unwrap();
                    let task = spawn_start(&manager, &settings);
                    barrier.entered.notified().await;
                    bindings.revision.store(2, Ordering::Release);
                    barrier.release.notify_one();
                    let info = task.await.unwrap().unwrap();
                    let state = manager.relay.state.lock().await;
                    assert_eq!(scope_revision(&info.bind_scope), Some(2));
                    assert_eq!(
                        state.restream_spec.as_ref().unwrap().bind_scope,
                        info.bind_scope
                    );
                    assert!(state.restream_server.is_some());
                    assert_eq!(
                        state.firewall_generation,
                        Some((1, firewall_role(protocol)))
                    );
                    drop(state);
                    assert_eq!(policy.ensures.lock().unwrap().len(), 1);
                    assert!(policy.disables.lock().unwrap().is_empty());
                    assert_no_retry(&mut events);
                    manager.stop_restream_server().await.unwrap();
                }
            }
        }

        #[tokio::test]
        async fn recovery_ensure_honors_stop_and_newer_start_without_another_attempt() {
            for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
                for newer_start in [false, true] {
                    let barrier = Arc::new(Barrier::default());
                    let bindings = Bindings::new(&[], vec![Read::ready(explicit("127.0.0.1", 1))]);
                    let policy = Arc::new(Policy::default());
                    *policy.ensure_barrier.lock().unwrap() = Some(barrier.clone());
                    let (manager, settings) = fixture(protocol, true, bindings, policy.clone());
                    seed(&manager, &settings, true).await;
                    let (mut events, ctx) = manager.relay.supervisor().unwrap();
                    let health = manager
                        .relay
                        .state
                        .lock()
                        .await
                        .restream_health
                        .clone()
                        .unwrap();
                    let task = tokio::spawn(async move {
                        recover_relay_generation(&ctx, 0, 41, "test_policy_supersession").await
                    });
                    barrier.entered.notified().await;
                    let stop = if newer_start {
                        manager.relay.begin_restream_start_intent().await.unwrap();
                        None
                    } else {
                        manager.relay.begin_restream_stop_intent().await
                    };
                    barrier.release.notify_one();
                    task.await.unwrap();
                    if let Some(stop) = stop {
                        manager.relay.finish_restream_stop(stop).await.unwrap();
                    }
                    assert!(manager.relay.state.lock().await.restream_server.is_none());
                    assert!(manager
                        .relay
                        .state
                        .lock()
                        .await
                        .firewall_generation
                        .is_none());
                    assert_eq!(policy.disables.lock().unwrap().len(), 1);
                    assert_eq!(health.snapshot().recovery_attempt, 1);
                    assert!(health.snapshot().error.is_none());
                    assert_no_retry(&mut events);
                    manager.stop_restream_server().await.unwrap();
                }
            }
        }

        #[tokio::test]
        async fn start_invalidates_real_change_or_read_failure_at_each_checkpoint_then_recovers() {
            for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
                for checkpoint in 0..3 {
                    for read_failure in [false, true] {
                        let mut samples = vec![1; checkpoint];
                        samples.push(2);
                        let bindings = Bindings::new(
                            &samples,
                            vec![
                                Read::ready(explicit("127.0.0.1", 1)),
                                Read::ready(if read_failure {
                                    failed()
                                } else {
                                    explicit("127.0.0.2", 2)
                                }),
                                // Recovery observes a settled replacement identity on a usable loopback socket.
                                Read::ready({
                                    let (mut identity, scope) = explicit("127.0.0.1", 2).unwrap();
                                    identity.as_mut().unwrap().index = 8;
                                    Ok((identity, scope))
                                }),
                            ],
                        );
                        let policy = Arc::new(Policy::default());
                        let (manager, settings) = fixture(protocol, true, bindings, policy.clone());
                        let (mut events, ctx) = manager.relay.supervisor().unwrap();
                        let error = start(&manager.relay, &settings).await.unwrap_err();
                        assert_eq!(
                            error.to_string(),
                            "Stream error: Bind topology changed; listener recovery is pending"
                        );
                        {
                            let state = manager.relay.state.lock().await;
                            assert!(state.restream_server.is_none());
                            assert!(state.firewall_generation.is_none());
                            assert_eq!(
                                state.restream_health.as_ref().unwrap().snapshot().state,
                                RelayState::Failed
                            );
                            assert_eq!(
                                scope_revision(&state.restream_spec.as_ref().unwrap().bind_scope),
                                Some(1)
                            );
                        }
                        assert_eq!(
                            policy.ensures.lock().unwrap().len(),
                            usize::from(checkpoint > 0)
                        );
                        assert_eq!(
                            policy.disables.lock().unwrap().len(),
                            usize::from(checkpoint > 0)
                        );
                        assert!(matches!(
                            events.try_recv(),
                            Ok(RelaySupervisorEvent::RetryRequested {
                                server_generation: 1
                            })
                        ));
                        recover_relay_generation(
                            &ctx,
                            manager.relay.test_epoch(),
                            1,
                            "test_change",
                        )
                        .await;
                        {
                            let state = manager.relay.state.lock().await;
                            assert!(state.restream_server.is_some());
                            assert_eq!(
                                state
                                    .restream_spec
                                    .as_ref()
                                    .unwrap()
                                    .bind_identity
                                    .as_ref()
                                    .unwrap()
                                    .index,
                                8
                            );
                            assert_eq!(
                                state
                                    .restream_health
                                    .as_ref()
                                    .unwrap()
                                    .snapshot()
                                    .recovery_attempt,
                                1
                            );
                        }
                        manager.stop_restream_server().await.unwrap();
                    }
                }
            }
        }

        #[tokio::test]
        async fn recovery_refreshes_all_checkpoints_without_extra_attempt_or_retirement() {
            for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
                for explicit_bind in [false, true] {
                    let bindings = Bindings::new(
                        &[2, 3, 4],
                        (1..=4)
                            .map(|r| Read::ready(observation(explicit_bind, r)))
                            .collect(),
                    );
                    let policy = Arc::new(Policy::default());
                    let (manager, settings) =
                        fixture(protocol, explicit_bind, bindings.clone(), policy.clone());
                    seed(&manager, &settings, explicit_bind).await;
                    let (mut events, ctx) = manager.relay.supervisor().unwrap();
                    recover_relay_generation(&ctx, 0, 41, "test_churn").await;
                    {
                        let state = manager.relay.state.lock().await;
                        let health = state.restream_health.as_ref().unwrap().snapshot();
                        assert_eq!(health.recovery_attempt, 1);
                        assert!(matches!(
                            health.state,
                            RelayState::Listening | RelayState::Streaming
                        ));
                        assert_eq!(
                            scope_revision(&state.restream_spec.as_ref().unwrap().bind_scope),
                            Some(4)
                        );
                        assert_eq!(
                            state.firewall_generation,
                            Some((41, firewall_role(protocol)))
                        );
                        assert!(state.restream_server.is_some());
                    }
                    assert_eq!(bindings.read_count(), 4);
                    assert!(policy.disables.lock().unwrap().is_empty());
                    assert_no_retry(&mut events);
                    manager.stop_restream_server().await.unwrap();
                }
            }
        }

        #[tokio::test]
        async fn start_binding_reads_honor_stop_and_newer_intent_before_interpreting_invalidation()
        {
            for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
                for checkpoint in 0..3 {
                    for newer_start in [false, true] {
                        let barrier = Arc::new(Barrier::default());
                        let mut samples = vec![1; checkpoint];
                        samples.push(2);
                        let bindings = Bindings::new(
                            &samples,
                            vec![
                                Read::ready(explicit("127.0.0.1", 1)),
                                Read::blocked(failed(), &barrier),
                                Read::ready(explicit("127.0.0.1", 2)),
                            ],
                        );
                        let policy = Arc::new(Policy::default());
                        let (manager, settings) = fixture(protocol, true, bindings, policy.clone());
                        let (mut events, _) = manager.relay.supervisor().unwrap();
                        let task = spawn_start(&manager, &settings);
                        barrier.entered.notified().await;
                        let health = manager
                            .relay
                            .state
                            .lock()
                            .await
                            .restream_health
                            .clone()
                            .unwrap();
                        let prior = health.snapshot();
                        let next = if newer_start {
                            Some(manager.relay.begin_restream_start_intent().await.unwrap())
                        } else {
                            None
                        };
                        let stop = if newer_start {
                            None
                        } else {
                            manager.relay.begin_restream_stop_intent().await
                        };
                        // A newer intent deliberately retains the old generation here.
                        if newer_start {
                            assert_eq!(
                                manager
                                    .relay
                                    .state
                                    .lock()
                                    .await
                                    .restream_health
                                    .as_ref()
                                    .unwrap()
                                    .server_generation(),
                                1
                            );
                        }
                        barrier.release.notify_one();
                        let error = task.await.unwrap().unwrap_err().to_string();
                        let expected = if checkpoint == 1 {
                            "Stream error: Listener start superseded during Windows rule reconciliation"
                        } else {
                            "Stream error: Re-stream server start was superseded by a newer request"
                        };
                        assert_eq!(error, expected);
                        assert!(manager.relay.state.lock().await.restream_server.is_none());
                        assert!(manager
                            .relay
                            .state
                            .lock()
                            .await
                            .firewall_generation
                            .is_none());
                        assert_no_retry(&mut events);
                        assert_eq!(
                            policy.disables.lock().unwrap().len(),
                            usize::from(checkpoint > 0)
                        );
                        if let Some((epoch, preserve)) = next {
                            assert_eq!(health.snapshot().state, prior.state);
                            assert_eq!(health.snapshot().error, prior.error);
                            assert_eq!(
                                scope_revision(
                                    &manager
                                        .relay
                                        .state
                                        .lock()
                                        .await
                                        .restream_spec
                                        .as_ref()
                                        .unwrap()
                                        .bind_scope
                                ),
                                Some(1)
                            );
                            let mut replacement = settings.clone();
                            replacement.stream.udp_port = unused_udp_port();
                            replacement.rtsp_server.port = unused_tcp_port();
                            replacement.srt_server.port = unused_udp_port();
                            manager
                                .relay
                                .start_restream_server_inner(
                                    &replacement,
                                    &HashSet::new(),
                                    epoch,
                                    preserve,
                                )
                                .await
                                .unwrap();
                            assert_eq!(
                                manager.relay.state.lock().await.firewall_generation,
                                Some((2, firewall_role(protocol)))
                            );
                            assert_eq!(
                                policy.disables.lock().unwrap().len(),
                                usize::from(checkpoint > 0)
                            );
                        } else {
                            manager
                                .relay
                                .finish_restream_stop(stop.unwrap())
                                .await
                                .unwrap();
                            assert!(manager.relay.state.lock().await.restream_spec.is_none());
                            assert_eq!(health.snapshot().state, RelayState::Stopped);
                        }
                        manager.stop_restream_server().await.unwrap();
                    }
                }
            }
        }

        #[tokio::test]
        async fn stop_and_newer_start_during_ensure_keep_synchronous_cleanup_and_replacement_lease()
        {
            for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
                for newer_start in [false, true] {
                    let barrier = Arc::new(Barrier::default());
                    let bindings = Bindings::new(
                        &[1],
                        vec![Read::ready(wildcard(1)), Read::ready(wildcard(2))],
                    );
                    let policy = Arc::new(Policy::default());
                    *policy.ensure_barrier.lock().unwrap() = Some(barrier.clone());
                    let (manager, settings) =
                        fixture(protocol, false, bindings.clone(), policy.clone());
                    let (mut events, _) = manager.relay.supervisor().unwrap();
                    let task = spawn_start(&manager, &settings);
                    barrier.entered.notified().await;
                    let next = if newer_start {
                        Some(manager.relay.begin_restream_start_intent().await.unwrap())
                    } else {
                        None
                    };
                    let stop = if newer_start {
                        None
                    } else {
                        manager.relay.begin_restream_stop_intent().await
                    };
                    let finish = async {
                        if let Some(stop) = stop {
                            manager.relay.finish_restream_stop(stop).await.unwrap();
                        }
                    };
                    tokio::pin!(finish);
                    if !newer_start {
                        poll_pending(finish.as_mut()).await;
                    }
                    barrier.release.notify_one();
                    assert_eq!(task.await.unwrap().unwrap_err().to_string(),
                        "Stream error: Listener start superseded during Windows rule reconciliation");
                    assert_no_retry(&mut events);
                    assert_eq!(policy.disables.lock().unwrap().len(), 1);
                    assert!(manager.relay.state.lock().await.restream_server.is_none());
                    assert!(manager
                        .relay
                        .state
                        .lock()
                        .await
                        .firewall_generation
                        .is_none());
                    finish.await;
                    bindings.revision.store(2, Ordering::Release);
                    if let Some((epoch, preserve)) = next {
                        manager
                            .relay
                            .start_restream_server_inner(
                                &settings,
                                &HashSet::new(),
                                epoch,
                                preserve,
                            )
                            .await
                            .unwrap();
                        assert_eq!(
                            manager.relay.state.lock().await.firewall_generation,
                            Some((2, firewall_role(protocol)))
                        );
                        assert_eq!(policy.disables.lock().unwrap().len(), 1);
                    }
                    manager.stop_restream_server().await.unwrap();
                }
            }
        }

        #[tokio::test]
        async fn supersession_during_invalidated_candidate_retirement_does_not_publish_failure() {
            for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
                for checkpoint in [1, 2] {
                    let barrier = Arc::new(Barrier::default());
                    let mut samples = vec![1; checkpoint];
                    samples.push(2);
                    let bindings = Bindings::new(
                        &samples,
                        vec![Read::ready(explicit("127.0.0.1", 1)), Read::ready(failed())],
                    );
                    let policy = Arc::new(Policy::default());
                    *policy.disable_barrier.lock().unwrap() = Some(barrier.clone());
                    let (manager, settings) = fixture(protocol, true, bindings, policy.clone());
                    let (mut events, _) = manager.relay.supervisor().unwrap();
                    let task = spawn_start(&manager, &settings);
                    barrier.entered.notified().await;
                    let health = manager
                        .relay
                        .state
                        .lock()
                        .await
                        .restream_health
                        .clone()
                        .unwrap();
                    let before = health.snapshot();
                    manager.relay.begin_restream_start_intent().await.unwrap();
                    barrier.release.notify_one();
                    let error = task.await.unwrap().unwrap_err().to_string();
                    assert!(error.contains("superseded"));
                    assert_eq!(health.snapshot().state, before.state);
                    assert_eq!(health.snapshot().error, before.error);
                    assert_eq!(
                        scope_revision(
                            &manager
                                .relay
                                .state
                                .lock()
                                .await
                                .restream_spec
                                .as_ref()
                                .unwrap()
                                .bind_scope
                        ),
                        Some(1)
                    );
                    assert_no_retry(&mut events);
                    assert_eq!(policy.disables.lock().unwrap().len(), 1);
                    manager.stop_restream_server().await.unwrap();
                }
            }
        }

        #[tokio::test]
        async fn recovery_binding_reads_and_cleanup_honor_supersession_at_each_checkpoint() {
            for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
                for checkpoint in 0..3 {
                    for during_cleanup in [false, true] {
                        if checkpoint == 0 && during_cleanup {
                            continue;
                        }
                        let barrier = Arc::new(Barrier::default());
                        let mut samples = vec![1; checkpoint];
                        samples.push(2);
                        let invalid = if during_cleanup {
                            Read::ready(failed())
                        } else {
                            Read::blocked(failed(), &barrier)
                        };
                        let bindings = Bindings::new(
                            &samples,
                            vec![Read::ready(explicit("127.0.0.1", 1)), invalid],
                        );
                        let policy = Arc::new(Policy::default());
                        if during_cleanup {
                            *policy.disable_barrier.lock().unwrap() = Some(barrier.clone());
                        }
                        let (manager, settings) = fixture(protocol, true, bindings, policy.clone());
                        seed(&manager, &settings, true).await;
                        let (mut events, ctx) = manager.relay.supervisor().unwrap();
                        let task = tokio::spawn(async move {
                            recover_relay_generation(&ctx, 0, 41, "test_supersession").await
                        });
                        barrier.entered.notified().await;
                        let health = manager
                            .relay
                            .state
                            .lock()
                            .await
                            .restream_health
                            .clone()
                            .unwrap();
                        let before = health.snapshot();
                        manager.relay.begin_restream_start_intent().await.unwrap();
                        barrier.release.notify_one();
                        task.await.unwrap();
                        assert_eq!(health.snapshot().state, before.state);
                        assert_eq!(health.snapshot().error, before.error);
                        assert_eq!(health.snapshot().recovery_attempt, 1);
                        assert!(manager.relay.state.lock().await.restream_server.is_none());
                        assert!(manager
                            .relay
                            .state
                            .lock()
                            .await
                            .firewall_generation
                            .is_none());
                        assert_eq!(
                            scope_revision(
                                &manager
                                    .relay
                                    .state
                                    .lock()
                                    .await
                                    .restream_spec
                                    .as_ref()
                                    .unwrap()
                                    .bind_scope
                            ),
                            Some(0)
                        );
                        assert_eq!(
                            policy.disables.lock().unwrap().len(),
                            usize::from(checkpoint > 0)
                        );
                        assert_no_retry(&mut events);
                        manager.stop_restream_server().await.unwrap();
                    }
                }
            }
        }

        #[tokio::test]
        async fn recovery_invalidates_each_checkpoint_cleans_up_and_resolves_next_attempt() {
            for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
                for checkpoint in 0..3 {
                    for read_failure in [false, true] {
                        let mut samples = vec![1; checkpoint];
                        samples.extend([2, 3, 3, 3]);
                        let mut replacement = explicit("127.0.0.1", 3).unwrap();
                        replacement.0.as_mut().unwrap().index = 8;
                        let bindings = Bindings::new(
                            &samples,
                            vec![
                                Read::ready(explicit("127.0.0.1", 1)),
                                Read::ready(if read_failure {
                                    failed()
                                } else {
                                    explicit("127.0.0.2", 2)
                                }),
                                Read::ready(Ok(replacement)),
                            ],
                        );
                        let policy = Arc::new(Policy::default());
                        let (manager, settings) = fixture(protocol, true, bindings, policy.clone());
                        seed(&manager, &settings, true).await;
                        let (mut events, ctx) = manager.relay.supervisor().unwrap();
                        recover_relay_generation(&ctx, 0, 41, "test_invalidation").await;
                        {
                            let state = manager.relay.state.lock().await;
                            let health = state.restream_health.as_ref().unwrap().snapshot();
                            assert_eq!(health.recovery_attempt, 2);
                            assert!(matches!(
                                health.state,
                                RelayState::Listening | RelayState::Streaming
                            ));
                            assert!(state.restream_server.is_some());
                            let spec = state.restream_spec.as_ref().unwrap();
                            assert_eq!(scope_revision(&spec.bind_scope), Some(3));
                            assert_eq!(spec.bind_identity.as_ref().unwrap().index, 8);
                            assert_eq!(
                                state.firewall_generation,
                                Some((41, firewall_role(protocol)))
                            );
                        }
                        assert_eq!(
                            policy.ensures.lock().unwrap().len(),
                            1 + usize::from(checkpoint > 0)
                        );
                        assert_eq!(
                            policy.disables.lock().unwrap().len(),
                            usize::from(checkpoint > 0)
                        );
                        assert_no_retry(&mut events);
                        manager.stop_restream_server().await.unwrap();
                    }
                }
            }
        }

        #[tokio::test]
        async fn recovery_keeps_final_observation_stamp_and_unknown_remains_repairable() {
            for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
                for explicit_bind in [false, true] {
                    let mut final_read = Read::ready(observation(explicit_bind, 2));
                    final_read.revision_after = Some(3);
                    let mut reads = vec![Read::ready(observation(explicit_bind, 1)), final_read];
                    if explicit_bind {
                        reads.push(Read::ready(observation(true, 3)));
                    }
                    let bindings = Bindings::new(&[1, 1, 2], reads);
                    let policy = Arc::new(Policy::default());
                    let (manager, settings) =
                        fixture(protocol, explicit_bind, bindings.clone(), policy.clone());
                    seed(&manager, &settings, explicit_bind).await;
                    let (mut events, ctx) = manager.relay.supervisor().unwrap();
                    recover_relay_generation(&ctx, 0, 41, "test_freshness").await;
                    assert_eq!(bindings.read_count(), 2);
                    assert_eq!(
                        scope_revision(
                            &manager
                                .relay
                                .state
                                .lock()
                                .await
                                .restream_spec
                                .as_ref()
                                .unwrap()
                                .bind_scope
                        ),
                        Some(2)
                    );
                    manager
                        .binding_topology_changed(wildcard(3).unwrap().1, 3)
                        .await;
                    assert_eq!(
                        scope_revision(
                            &manager
                                .relay
                                .state
                                .lock()
                                .await
                                .restream_spec
                                .as_ref()
                                .unwrap()
                                .bind_scope
                        ),
                        Some(3)
                    );
                    assert!(policy.disables.lock().unwrap().is_empty());
                    assert_no_retry(&mut events);
                    manager.stop_restream_server().await.unwrap();
                }
                let bindings = Bindings::new(&[], vec![Read::ready(failed())]);
                let policy = Arc::new(Policy::default());
                let (manager, settings) =
                    fixture(protocol, false, bindings.clone(), policy.clone());
                seed(&manager, &settings, false).await;
                let (mut events, ctx) = manager.relay.supervisor().unwrap();
                recover_relay_generation(&ctx, 0, 41, "test_unknown").await;
                assert!(matches!(
                    manager
                        .relay
                        .state
                        .lock()
                        .await
                        .restream_spec
                        .as_ref()
                        .unwrap()
                        .bind_scope,
                    BindScope::Unknown { .. }
                ));
                manager
                    .binding_topology_changed(wildcard(1).unwrap().1, 1)
                    .await;
                assert_eq!(
                    scope_revision(
                        &manager
                            .relay
                            .state
                            .lock()
                            .await
                            .restream_spec
                            .as_ref()
                            .unwrap()
                            .bind_scope
                    ),
                    Some(1)
                );
                assert_eq!(bindings.read_count(), 1);
                assert!(policy.disables.lock().unwrap().is_empty());
                assert_no_retry(&mut events);
                manager.stop_restream_server().await.unwrap();
            }
        }

        #[tokio::test]
        async fn explicit_unknown_scope_repairs_at_same_revision_without_broadening_socket() {
            let bindings = Bindings::new(&[], vec![Read::ready(explicit("127.0.0.1", 1))]);
            let policy = Arc::new(Policy::default());
            let (manager, settings) = fixture(RestreamProtocol::Rtsp, true, bindings, policy);
            seed(&manager, &settings, true).await;
            let (mut events, _) = manager.relay.supervisor().unwrap();
            manager
                .relay
                .state
                .lock()
                .await
                .restream_spec
                .as_mut()
                .unwrap()
                .bind_scope = BindScope::default();
            manager
                .binding_topology_changed(wildcard(1).unwrap().1, 1)
                .await;
            let state = manager.relay.state.lock().await;
            let spec = state.restream_spec.as_ref().unwrap();
            assert_eq!(scope_revision(&spec.bind_scope), Some(1));
            assert_eq!(spec.bind_address.as_deref(), Some("127.0.0.1"));
            assert!(spec.bind_identity.is_some());
            assert_no_retry(&mut events);
        }

        #[tokio::test]
        async fn same_instance_watcher_handoff_compares_installed_specification() {
            for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
                let barrier = Arc::new(Barrier::default());
                let bindings = Bindings::new(
                    &[1, 1, 2],
                    vec![
                        Read::ready(explicit("127.0.0.1", 1)),
                        Read::blocked(explicit("127.0.0.1", 2), &barrier),
                        Read::ready(explicit("127.0.0.1", 2)),
                    ],
                );
                let policy = Arc::new(Policy::default());
                let (manager, settings) = fixture(protocol, true, bindings.clone(), policy.clone());
                seed(&manager, &settings, true).await;
                // Published A remains while recovery constructs B and reserves N.
                {
                    let mut state = manager.relay.state.lock().await;
                    let spec = state.restream_spec.as_mut().unwrap();
                    spec.bind_address = Some("127.0.0.2".into());
                    if let BindScope::Interface { address, .. } = &mut spec.bind_scope {
                        *address = "127.0.0.2".into();
                    }
                }
                let (mut events, ctx) = manager.relay.supervisor().unwrap();
                let recovery = tokio::spawn(async move {
                    recover_relay_generation(&ctx, 0, 41, "test_handoff").await
                });
                barrier.entered.notified().await;
                let health = manager
                    .relay
                    .state
                    .lock()
                    .await
                    .restream_health
                    .clone()
                    .unwrap();
                let instance = health.snapshot().server_instance;
                let watcher = manager.binding_topology_changed(wildcard(2).unwrap().1, 2);
                tokio::pin!(watcher);
                poll_pending(watcher.as_mut()).await;
                assert_eq!(bindings.read_count(), 3);
                barrier.release.notify_one();
                recovery.await.unwrap();
                assert_eq!(health.snapshot().server_instance, instance);
                watcher.await;
                {
                    let state = manager.relay.state.lock().await;
                    assert!(state.restream_server.is_some());
                    assert_eq!(
                        state
                            .restream_spec
                            .as_ref()
                            .unwrap()
                            .bind_address
                            .as_deref(),
                        Some("127.0.0.1")
                    );
                    assert_eq!(
                        scope_revision(&state.restream_spec.as_ref().unwrap().bind_scope),
                        Some(2)
                    );
                }
                assert_eq!(health.snapshot().server_instance, instance);
                assert!(matches!(
                    health.snapshot().state,
                    RelayState::Listening | RelayState::Streaming
                ));
                assert!(health.snapshot().error.is_none());
                assert!(policy.disables.lock().unwrap().is_empty());
                assert_no_retry(&mut events);
                manager.stop_restream_server().await.unwrap();
            }
        }

        #[tokio::test]
        async fn final_observation_stamp_is_published_then_watcher_converges() {
            for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
                for explicit_bind in [false, true] {
                    let mut final_read = Read::ready(observation(explicit_bind, 2));
                    final_read.revision_after = Some(3);
                    let mut reads = vec![Read::ready(observation(explicit_bind, 1)), final_read];
                    if explicit_bind {
                        reads.push(Read::ready(observation(true, 3)));
                    }
                    let bindings = Bindings::new(&[1, 1, 2], reads);
                    let policy = Arc::new(Policy::default());
                    let (manager, settings) =
                        fixture(protocol, explicit_bind, bindings.clone(), policy.clone());
                    let (mut events, _) = manager.relay.supervisor().unwrap();
                    let info = start(&manager.relay, &settings).await.unwrap();
                    assert_eq!(scope_revision(&info.bind_scope), Some(2));
                    assert_eq!(bindings.read_count(), 2);
                    assert_eq!(bindings.revision.load(Ordering::Acquire), 3);
                    assert_eq!(
                        manager
                            .relay
                            .state
                            .lock()
                            .await
                            .restream_spec
                            .as_ref()
                            .unwrap()
                            .bind_scope,
                        info.bind_scope
                    );
                    manager
                        .binding_topology_changed(wildcard(3).unwrap().1, 3)
                        .await;
                    assert_eq!(
                        scope_revision(
                            &manager
                                .relay
                                .state
                                .lock()
                                .await
                                .restream_spec
                                .as_ref()
                                .unwrap()
                                .bind_scope
                        ),
                        Some(3)
                    );
                    assert!(policy.disables.lock().unwrap().is_empty());
                    assert_no_retry(&mut events);
                    manager.stop_restream_server().await.unwrap();
                }
            }
        }

        #[tokio::test]
        async fn delayed_watcher_rejects_newer_intent_with_the_same_generation_and_instance() {
            let bindings = Bindings::new(&[], vec![Read::ready(explicit("127.0.0.2", 1))]);
            let policy = Arc::new(Policy::default());
            let (manager, settings) =
                fixture(RestreamProtocol::Rtsp, true, bindings, policy.clone());
            seed(&manager, &settings, true).await;
            let (mut events, _) = manager.relay.supervisor().unwrap();
            let health = manager
                .relay
                .state
                .lock()
                .await
                .restream_health
                .clone()
                .unwrap();
            let before = health.snapshot();
            let lifecycle = manager.relay.relay_lifecycle.lock().await;
            let watcher = manager.binding_topology_changed(wildcard(1).unwrap().1, 1);
            tokio::pin!(watcher);
            poll_pending(watcher.as_mut()).await;
            manager.relay.begin_restream_start_intent().await.unwrap();
            drop(lifecycle);
            watcher.await;
            assert_eq!(
                scope_revision(
                    &manager
                        .relay
                        .state
                        .lock()
                        .await
                        .restream_spec
                        .as_ref()
                        .unwrap()
                        .bind_scope
                ),
                Some(0)
            );
            assert_eq!(health.snapshot().state, before.state);
            assert_eq!(health.snapshot().server_instance, before.server_instance);
            assert_eq!(health.snapshot().error, before.error);
            assert!(policy.disables.lock().unwrap().is_empty());
            assert_no_retry(&mut events);
            manager.stop_restream_server().await.unwrap();
        }
    }

    #[tokio::test]
    async fn old_stop_preserves_replacement_listener_udp_and_firewall_lease() {
        init_gstreamer();
        let manager = StreamManager::new();
        let old_settings = restream_test_settings(RestreamProtocol::Rtsp);
        seed_desired_relay_state(&manager, &old_settings, RelayState::Recovering).await;
        manager.relay.state.lock().await.firewall_generation = Some((41, FirewallRule::Rtsp));
        let stop = manager.relay.begin_restream_stop_intent().await.unwrap();
        let mut replacement = restream_test_settings(RestreamProtocol::Rtsp);
        while replacement.stream.udp_port == old_settings.stream.udp_port {
            replacement.stream.udp_port = unused_udp_port();
        }
        let (epoch, preserve) = manager.relay.begin_restream_start_intent().await.unwrap();
        manager
            .relay
            .start_restream_server_inner(&replacement, &Default::default(), epoch, preserve)
            .await
            .unwrap();
        let newer_lease = manager.relay.state.lock().await.firewall_generation;
        assert!(newer_lease.is_some_and(|(generation, _)| generation != 41));
        manager.relay.finish_restream_stop(stop).await.unwrap();
        assert_eq!(
            manager.relay.state.lock().await.firewall_generation,
            newer_lease
        );
        assert!(manager.relay.state.lock().await.restream_server.is_some());
        assert!(manager.start_playback(&replacement, None).await.is_err());
        manager.start_playback(&old_settings, None).await.unwrap();
        manager.stop_playback().await.unwrap();
        manager.stop_restream_server().await.unwrap();
    }
    use crate::config::*;
    use crate::streaming::test_support::*;
    use crate::streaming::{relay, status::compute_status, StreamManager};

    fn uncertain_policy() -> FirewallOutcome {
        FirewallOutcome::Failed {
            stage: "test_observation".into(),
            reason: "uncertain retirement".into(),
            uncertain: true,
        }
    }

    #[tokio::test]
    async fn unadmitted_inactive_never_retires_an_existing_lease() {
        let manager = StreamManager::new();
        let enabled = FirewallOutcome::Applied {
            rule_name: "owned".into(),
            action: firewall::RuleAction::Unchanged,
            verified_shape: true,
            observed_block_rules: vec![],
        };
        {
            let mut state = manager.relay.state.lock().await;
            state.firewall_generation = Some((41, FirewallRule::Rtsp));
            state.firewall = enabled.clone();
        }
        assert!(
            retire_firewall_with(&manager.relay.state, 41, None, |_| async {
                PolicyResult {
                    admitted: false,
                    outcome: FirewallOutcome::Inactive,
                }
            })
            .await
            .is_err()
        );
        assert_eq!(
            manager.relay.state.lock().await.firewall_generation,
            Some((41, FirewallRule::Rtsp))
        );
        assert_eq!(manager.relay.state.lock().await.firewall, enabled);
        assert!(
            retire_firewall_with(&manager.relay.state, 41, None, |_| async {
                PolicyResult::accepted(FirewallOutcome::Inactive)
            })
            .await
            .is_ok()
        );
        assert!(manager
            .relay
            .state
            .lock()
            .await
            .firewall_generation
            .is_none());
    }

    #[tokio::test]
    async fn only_matching_obsolete_unadmitted_provisional_lease_can_be_discarded() {
        for existing in [false, true] {
            for current in [false, true] {
                for admitted in [false, true] {
                    let manager = StreamManager::new();
                    let settings = restream_test_settings(RestreamProtocol::Rtsp);
                    seed_desired_relay_state(&manager, &settings, RelayState::Starting).await;
                    if existing {
                        manager.relay.state.lock().await.firewall_generation =
                            Some((41, FirewallRule::Rtsp));
                    }
                    apply_firewall_with(
                        &manager.relay.state,
                        &resolved_spec_for_test(&settings),
                        41,
                        "start",
                        |_, _, _| async {
                            PolicyResult {
                                admitted,
                                outcome: FirewallOutcome::Inactive,
                            }
                        },
                        |_| async { panic!("same lease re-ensure must not retire it") },
                        std::future::ready(current),
                    )
                    .await;
                    assert_eq!(
                        manager
                            .relay
                            .state
                            .lock()
                            .await
                            .firewall_generation
                            .is_none(),
                        !existing && !current && !admitted
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn current_ensure_refusal_retains_lease_for_later_stop() {
        let manager = StreamManager::new();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        seed_desired_relay_state(&manager, &settings, RelayState::Starting).await;
        let unavailable = FirewallOutcome::Unavailable {
            reason: "admission timeout".into(),
        };
        let result = apply_firewall_with(
            &manager.relay.state,
            &resolved_spec_for_test(&settings),
            41,
            "start",
            |_, _, _| async {
                PolicyResult {
                    admitted: false,
                    outcome: unavailable.clone(),
                }
            },
            |_| async { unreachable!() },
            std::future::ready(true),
        )
        .await;
        assert_eq!(result, unavailable);
        assert_eq!(
            manager.relay.state.lock().await.firewall_generation,
            Some((41, FirewallRule::Rtsp))
        );
        manager.stop_restream_server().await.unwrap();
        assert!(manager
            .relay
            .state
            .lock()
            .await
            .firewall_generation
            .is_none());
    }

    #[tokio::test]
    async fn cancelled_policy_caller_leaves_installed_lease_for_uncertain_retirement_and_stop() {
        let manager = Arc::new(StreamManager::new());
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        seed_desired_relay_state(&manager, &settings, RelayState::Starting).await;
        let spec = resolved_spec_for_test(&settings);
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let m = manager.clone();
        let caller = tokio::spawn(async move {
            let _lifecycle = m.relay.relay_lifecycle.lock().await;
            apply_firewall_with(
                &m.relay.state,
                &spec,
                41,
                "start",
                |role, _, _| async move {
                    entered_tx.send(role).unwrap();
                    std::future::pending::<PolicyResult>().await
                },
                |_| async { PolicyResult::accepted(FirewallOutcome::Inactive) },
                std::future::ready(true),
            )
            .await
        });
        assert_eq!(entered_rx.await.unwrap(), FirewallRule::Rtsp);
        assert_eq!(
            manager.relay.state.lock().await.firewall_generation,
            Some((41, FirewallRule::Rtsp))
        );
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert!(
            retire_firewall_with(&manager.relay.state, 41, None, |_| async {
                PolicyResult::accepted(uncertain_policy())
            })
            .await
            .is_err()
        );
        assert_eq!(
            manager.relay.state.lock().await.firewall,
            uncertain_policy()
        );
        assert_eq!(
            manager.relay.state.lock().await.firewall_generation,
            Some((41, FirewallRule::Rtsp))
        );
        manager.stop_restream_server().await.unwrap();
        assert!(manager
            .relay
            .state
            .lock()
            .await
            .firewall_generation
            .is_none());
        // This tests lease lifetime only; native cancellation/barrier behavior
        // remains covered by the unchanged retained-executor scenarios.
    }

    #[tokio::test]
    async fn failed_or_unavailable_prior_retirement_prevents_replacement_policy_dispatch() {
        for outcome in [
            uncertain_policy(),
            FirewallOutcome::Unavailable {
                reason: "busy".into(),
            },
            FirewallOutcome::Failed {
                stage: "disable".into(),
                reason: "failed".into(),
                uncertain: false,
            },
        ] {
            let manager = StreamManager::new();
            let settings = restream_test_settings(RestreamProtocol::Rtsp);
            seed_desired_relay_state(&manager, &settings, RelayState::Starting).await;
            manager.relay.state.lock().await.firewall_generation = Some((40, FirewallRule::Srt));
            let dispatched = std::sync::atomic::AtomicBool::new(false);
            let expected = outcome.clone();
            let actual = apply_firewall_with(
                &manager.relay.state,
                &resolved_spec_for_test(&settings),
                41,
                "start",
                |_, _, _| async {
                    dispatched.store(true, std::sync::atomic::Ordering::Release);
                    PolicyResult::accepted(FirewallOutcome::Inactive)
                },
                |_| async move { PolicyResult::accepted(outcome) },
                std::future::ready(true),
            )
            .await;
            assert_eq!(actual, expected);
            assert!(!dispatched.load(std::sync::atomic::Ordering::Acquire));
            assert_eq!(
                manager.relay.state.lock().await.firewall_generation,
                Some((40, FirewallRule::Srt))
            );
        }
    }

    #[tokio::test]
    async fn late_policy_completion_cannot_overwrite_a_newer_lease_or_outcome() {
        use std::{
            future::{poll_fn, Future},
            task::Poll,
        };
        let manager = StreamManager::new();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        seed_desired_relay_state(&manager, &settings, RelayState::Starting).await;
        let spec = resolved_spec_for_test(&settings);
        let (done, result) = tokio::sync::oneshot::channel();
        let apply = apply_firewall_with(
            &manager.relay.state,
            &spec,
            41,
            "start",
            |_, _, _| async { result.await.unwrap() },
            |_| async { PolicyResult::accepted(FirewallOutcome::Inactive) },
            std::future::ready(true),
        );
        tokio::pin!(apply);
        assert!(poll_fn(|cx| Poll::Ready(apply.as_mut().poll(cx)))
            .await
            .is_pending());
        assert_eq!(
            manager.relay.state.lock().await.firewall_generation,
            Some((41, FirewallRule::Rtsp))
        );
        let newer = FirewallOutcome::Unavailable {
            reason: "new listener outcome".into(),
        };
        {
            let mut state = manager.relay.state.lock().await;
            state.firewall_generation = Some((42, FirewallRule::Srt));
            state.firewall = newer.clone();
        }
        done.send(PolicyResult::accepted(uncertain_policy()))
            .unwrap();
        apply.await;
        let state = manager.relay.state.lock().await;
        assert_eq!(state.firewall_generation, Some((42, FirewallRule::Srt)));
        assert_eq!(state.firewall, newer);
    }

    #[tokio::test]
    async fn late_inactive_retirement_cannot_clear_a_newer_same_role_lease() {
        use std::{
            future::{poll_fn, Future},
            task::Poll,
        };
        let manager = StreamManager::new();
        manager.relay.state.lock().await.firewall_generation = Some((40, FirewallRule::Rtsp));
        let (done, result) = tokio::sync::oneshot::channel();
        let retire = retire_firewall_with(&manager.relay.state, 40, None, |_| async {
            result.await.unwrap()
        });
        tokio::pin!(retire);
        assert!(poll_fn(|cx| Poll::Ready(retire.as_mut().poll(cx)))
            .await
            .is_pending());
        let newer = uncertain_policy();
        {
            let mut state = manager.relay.state.lock().await;
            state.firewall_generation = Some((41, FirewallRule::Rtsp));
            state.firewall = newer.clone();
        }
        done.send(PolicyResult::accepted(FirewallOutcome::Inactive))
            .unwrap();
        assert!(retire.await.is_ok());
        let state = manager.relay.state.lock().await;
        assert_eq!(state.firewall_generation, Some((41, FirewallRule::Rtsp)));
        assert_eq!(state.firewall, newer);
    }

    #[tokio::test]
    async fn prior_policy_retires_before_installing_and_dispatching_replacement() {
        let manager = StreamManager::new();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        seed_desired_relay_state(&manager, &settings, RelayState::Starting).await;
        manager.relay.state.lock().await.firewall_generation = Some((40, FirewallRule::Srt));
        let calls = std::sync::Mutex::new(Vec::new());
        let expected = FirewallOutcome::Unavailable {
            reason: "automation unavailable".into(),
        };
        let actual = apply_firewall_with(
            &manager.relay.state,
            &resolved_spec_for_test(&settings),
            41,
            "start",
            |role, _, _| {
                calls.lock().unwrap().push(role);
                let state = manager.relay.state.clone();
                let outcome = expected.clone();
                async move {
                    assert_eq!(
                        state.lock().await.firewall_generation,
                        Some((41, FirewallRule::Rtsp))
                    );
                    PolicyResult::accepted(outcome)
                }
            },
            |role| {
                calls.lock().unwrap().push(role);
                std::future::ready(PolicyResult::accepted(FirewallOutcome::Inactive))
            },
            std::future::ready(true),
        )
        .await;
        assert_eq!(
            *calls.lock().unwrap(),
            [FirewallRule::Srt, FirewallRule::Rtsp]
        );
        assert_eq!(actual, expected);
        assert_eq!(manager.relay.state.lock().await.firewall, expected);
    }
    #[tokio::test]
    async fn stale_firewall_cleanup_cannot_retire_a_newer_listener_lease() {
        let manager = StreamManager::new();
        manager.state.lock().await.relay_data.firewall_generation = Some((9, FirewallRule::Srt));
        retire_firewall(&manager.relay.state, manager.relay.policy.as_ref(), 8).await;
        assert_eq!(
            manager.state.lock().await.relay_data.firewall_generation,
            Some((9, FirewallRule::Srt))
        );
        // The lib-test seam cannot invoke native firewall policy.
        retire_firewall(&manager.relay.state, manager.relay.policy.as_ref(), 9).await;
        assert!(manager
            .state
            .lock()
            .await
            .relay_data
            .firewall_generation
            .is_none());
    }

    #[tokio::test]
    async fn stopped_status_retains_startup_policy_failure() {
        let manager = StreamManager::new();
        let failed = FirewallOutcome::Failed {
            stage: "ownership".into(),
            reason: "Foreign program owns the native rule name".into(),
            uncertain: false,
        };
        manager.startup_firewall_status(failed.clone()).await;
        let status = compute_status(&manager.state).await;
        assert!(!status.server_running);
        assert_eq!(status.firewall, failed);
        manager.state.lock().await.relay_data.firewall_generation = Some((2, FirewallRule::Rtsp));
        manager
            .startup_firewall_status(FirewallOutcome::Inactive)
            .await;
        assert_eq!(manager.state.lock().await.relay_data.firewall, failed);
    }

    #[tokio::test]
    async fn stop_accounts_for_firewall_lease_even_without_a_bound_socket() {
        let manager = StreamManager::new();
        {
            let mut state = manager.state.lock().await;
            state.relay_data.restream_desired = true;
            state.relay_data.firewall_generation = Some((12, FirewallRule::Rtsp));
        }
        let intent = manager.relay.begin_restream_stop_intent().await.unwrap();
        assert_eq!(intent.target_generation, Some(12));
        manager.relay.finish_restream_stop(intent).await.unwrap();
        assert!(manager
            .state
            .lock()
            .await
            .relay_data
            .firewall_generation
            .is_none());
    }

    #[tokio::test]
    async fn delayed_topology_observation_cannot_overwrite_a_recovered_instance() {
        use std::future::{poll_fn, Future};
        use std::task::Poll;

        let manager = StreamManager::new();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        seed_desired_relay_state(&manager, &settings, RelayState::Recovering).await;
        let lifecycle = manager.relay.relay_lifecycle.lock().await;
        let observation = manager.binding_topology_changed(
            BindScope::Unknown {
                reason: "earlier observation failed".into(),
            },
            bindings::revision(),
        );
        tokio::pin!(observation);
        // The observer has captured the old instance and waits for recovery.
        assert!(poll_fn(|cx| Poll::Ready(observation.as_mut().poll(cx)))
            .await
            .is_pending());
        let recovered_scope = BindScope::AllAddresses {
            family: bindings::SocketFamily::Ipv4,
            addresses: vec![],
            topology_revision: bindings::revision(),
        };
        {
            let mut state = manager.state.lock().await;
            let health = state.relay_data.restream_health.as_ref().unwrap();
            let instance = health.begin_server_instance(true);
            health.mark_listener_bound(instance);
            state.relay_data.restream_spec.as_mut().unwrap().bind_scope = recovered_scope.clone();
        }
        drop(lifecycle);
        observation.await;
        assert_eq!(
            manager
                .state
                .lock()
                .await
                .relay_data
                .restream_spec
                .as_ref()
                .unwrap()
                .bind_scope,
            recovered_scope
        );
    }

    #[tokio::test]
    async fn successful_reobservation_repairs_unknown_binding_at_the_same_revision() {
        let manager = StreamManager::new();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        seed_desired_relay_state(&manager, &settings, RelayState::Listening).await;
        let revision = bindings::revision();
        let scope = BindScope::AllAddresses {
            family: bindings::SocketFamily::Ipv4,
            addresses: vec![],
            topology_revision: revision,
        };
        // The watcher already recorded this inventory before Start's separate
        // read failed. Its next identical observation must still repair Unknown.
        manager
            .binding_topology_changed(scope.clone(), revision)
            .await;
        let state = manager.state.lock().await;
        assert_eq!(
            state.relay_data.restream_spec.as_ref().unwrap().bind_scope,
            scope
        );
        assert_eq!(
            state
                .relay_data
                .restream_health
                .as_ref()
                .unwrap()
                .snapshot()
                .state,
            RelayState::Listening
        );
    }

    #[tokio::test]
    async fn stop_retries_a_retained_policy_lease_from_an_older_listener() {
        init_gstreamer();
        let manager = StreamManager::new();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        let mut spec = resolved_spec_for_test(&settings);
        spec.bind_address = Some("127.0.0.1".into());
        seed_desired_relay_state(&manager, &settings, RelayState::Listening).await;
        let health = manager
            .state
            .lock()
            .await
            .relay_data
            .restream_health
            .clone()
            .unwrap();
        let (_, built) = RelayService::build_restream_server(
            &spec,
            health,
            manager.relay.relay_event_tx.clone(),
            false,
            None,
        );
        {
            let mut state = manager.state.lock().await;
            state.relay_data.restream_server =
                Some(built.unwrap_or_else(|failure| panic!("{}", failure.error)));
            // The prior SRT cleanup failed, so Start continued with unavailable
            // automation while retaining that older lease for a later retry.
            state.relay_data.firewall_generation = Some((40, FirewallRule::Srt));
        }
        manager.stop_restream_server().await.unwrap();
        assert!(manager
            .state
            .lock()
            .await
            .relay_data
            .restream_server
            .is_none());
        assert!(manager
            .state
            .lock()
            .await
            .relay_data
            .firewall_generation
            .is_none());
    }

    #[test]
    fn bind_ip_prefers_native_over_adopted() {
        // Interface carries a native client IP and an adopted camera
        // secondary — the native must be chosen for the socket bind.
        let ips = vec![ip("192.168.1.50"), ip("10.20.30.100")];
        let adopted = adopted_set(&["10.20.30.100"]);
        assert_eq!(
            first_usable_ip(&ips, &adopted).as_deref(),
            Some("192.168.1.50")
        );
    }

    #[test]
    fn bind_ip_none_when_only_adopted() {
        // Only an adopted secondary — no usable bind IP, so the caller errors
        // instead of binding to the camera network.
        let ips = vec![ip("10.20.30.100")];
        let adopted = adopted_set(&["10.20.30.100"]);
        assert!(first_usable_ip(&ips, &adopted).is_none());
    }

    #[test]
    fn bind_ip_skips_apipa_but_takes_real_ip() {
        let adopted = adopted_set(&[]);
        // APIPA is never selected when a real, non-adopted IP exists...
        let mixed = vec![ip("169.254.5.5"), ip("192.168.1.50")];
        assert_eq!(
            first_usable_ip(&mixed, &adopted).as_deref(),
            Some("192.168.1.50")
        );
        // ...and an APIPA-only interface yields nothing usable.
        let apipa_only = vec![ip("169.254.5.5")];
        assert!(first_usable_ip(&apipa_only, &adopted).is_none());
    }

    #[test]
    fn automatic_restream_url_never_selects_vpn_or_virtual_adapters() {
        use crate::network::InterfaceInfo;
        let ethernet = InterfaceInfo {
            name: "Ethernet".into(),
            display_name: "Ethernet".into(),
            description: "Physical".into(),
            mac: "aa:bb:cc:dd:ee:01".into(),
            ips: vec![ip("192.168.0.100"), ip("192.168.1.100")],
            is_up: true,
            is_ethernet: true,
            is_wifi: false,
            is_vpn: false,
            is_virtual: false,
        };
        let mut wifi = ethernet.clone();
        wifi.is_ethernet = false;
        wifi.is_wifi = true;
        wifi.ips = vec![ip("192.168.1.204")];
        let mut vpn = ethernet.clone();
        vpn.is_vpn = true;
        vpn.is_virtual = true;
        vpn.ips = vec![ip("10.147.18.99")];
        let mut virtual_adapter = ethernet.clone();
        virtual_adapter.is_virtual = true;
        virtual_adapter.ips = vec![ip("172.30.0.1")];
        let adopted = adopted_set(&["192.168.1.100"]);
        let mut interfaces = vec![vpn, virtual_adapter, ethernet, wifi];
        // Enumeration order must not let a VPN win over the Wi-Fi LAN.
        assert_eq!(
            select_display_ip(&interfaces, &adopted).as_deref(),
            Some("192.168.1.204")
        );
        interfaces.reverse();
        assert_eq!(
            select_display_ip(&interfaces, &adopted).as_deref(),
            Some("192.168.1.204")
        );
        interfaces[0].is_up = false;
        assert_eq!(
            select_display_ip(&interfaces, &adopted).as_deref(),
            Some("192.168.0.100")
        );
        interfaces[1].ips = vec![ip("169.254.1.10"), ip("192.168.1.100")];
        assert!(select_display_ip(&interfaces, &adopted).is_none());
        // Explicit VPN selection still has a usable bind/advertise address.
        assert_eq!(
            first_usable_ip(&interfaces[3].ips, &adopted).as_deref(),
            Some("10.147.18.99")
        );
    }

    #[tokio::test]
    async fn upstream_guard_survives_reasserted_start_but_rejects_stop_and_replacement() {
        use std::sync::atomic::Ordering;
        let manager = StreamManager::new();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        seed_desired_relay_state(&manager, &settings, RelayState::Listening).await;
        manager
            .relay
            .restream_generation
            .store(41, Ordering::Release);
        let health = manager
            .state
            .lock()
            .await
            .relay_data
            .restream_health
            .clone()
            .unwrap();
        let ready_calls = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let calls = ready_calls.clone();
        let guard = guard_relay_upstream(
            health.clone(),
            manager.relay.restream_generation.clone(),
            41,
            Arc::new(move || {
                calls.fetch_add(1, Ordering::AcqRel);
                Ok(crate::network::bound_tcp::test_path("192.0.2.1"))
            }),
        );
        guard().unwrap();
        manager.relay.begin_restream_start_intent().await.unwrap();
        guard().unwrap();
        assert_eq!(ready_calls.load(Ordering::Acquire), 2);
        manager
            .relay
            .restream_generation
            .store(42, Ordering::Release);
        assert!(guard().is_err());
        manager
            .relay
            .restream_generation
            .store(41, Ordering::Release);
        manager.relay.begin_restream_stop_intent().await.unwrap();
        assert!(guard().is_err());
        assert_eq!(ready_calls.load(Ordering::Acquire), 2);
    }

    #[test]
    fn explicit_start_noop_requires_identical_identity_and_healthy_listener() {
        let spec = ResolvedStartSpec {
            source: ResolvedSource::Rtsp {
                url: "rtsp://192.0.2.20/live".into(),
            },
            output: ResolvedOutput::Rtsp {
                server_port: 8554,
                mount_path: "/stream-token".into(),
            },
            bind_interface: Some("VPN".into()),
            bind_identity: None,
            bind_scope: crate::network::bindings::BindScope::default(),
            bind_address: Some("192.0.2.10".into()),
            advertised_ip: "192.0.2.10".into(),
            username: "camera".into(),
            password: "secret".into(),
        };
        let is_noop = |candidate: &ResolvedStartSpec, relay_state, loop_alive| {
            resolved_start_is_healthy_noop(
                true,
                Some(&spec),
                candidate,
                Some(relay_state),
                Some(9),
                Some(9),
                loop_alive,
            )
        };

        assert!(is_noop(&spec, RelayState::Listening, true));
        assert!(is_noop(&spec, RelayState::Streaming, true));
        assert!(!is_noop(&spec, RelayState::Recovering, true));
        assert!(!is_noop(&spec, RelayState::Listening, false));

        let mut address_changed = spec.clone();
        address_changed.advertised_ip = "192.0.2.11".into();
        assert!(!is_noop(&address_changed, RelayState::Listening, true));

        let mut credentials_changed = spec.clone();
        credentials_changed.password = "new-secret".into();
        assert!(!is_noop(&credentials_changed, RelayState::Listening, true));
    }

    #[test]
    fn only_selected_protocol_settings_replace_the_runtime() {
        let old = make_settings(StreamProtocol::Rtsp, "192.0.2.20", "camera", "secret");

        let mut inactive_srt_changed = old.clone();
        inactive_srt_changed.srt_server.latency_ms = 250;
        assert!(!selected_restream_runtime_changed(
            &old,
            &inactive_srt_changed
        ));

        let mut active_rtsp_changed = old.clone();
        active_rtsp_changed.rtsp_server.port = 9_554;
        assert!(selected_restream_runtime_changed(
            &old,
            &active_rtsp_changed
        ));

        let mut old_srt = old;
        old_srt.restream_protocol = RestreamProtocol::Srt;
        let mut inactive_rtsp_changed = old_srt.clone();
        inactive_rtsp_changed.rtsp_server.port = 9_554;
        assert!(!selected_restream_runtime_changed(
            &old_srt,
            &inactive_rtsp_changed
        ));

        let mut active_srt_changed = old_srt.clone();
        active_srt_changed.srt_server.stream_id = "replacement".into();
        assert!(selected_restream_runtime_changed(
            &old_srt,
            &active_srt_changed
        ));
    }

    #[test]
    fn srt_output_resolution_is_complete_and_fail_closed() {
        let mut settings = make_settings(StreamProtocol::Rtsp, "192.0.2.20", "camera", "secret");
        settings.restream_protocol = RestreamProtocol::Srt;
        settings.srt_server.port = 9_000;
        settings.srt_server.passphrase = SrtPassphraseState::Available("strongPass1".into());
        settings.srt_server.latency_ms = 250;
        settings.srt_server.stream_id = "field unit".into();
        settings.srt_server.bind_interface = "ZeroTier".into();

        let (bind_interface, output) = resolve_selected_restream_output(&settings).unwrap();
        assert_eq!(bind_interface.as_deref(), Some("ZeroTier"));
        let ResolvedOutput::Srt {
            server_port,
            passphrase,
            latency_ms,
            stream_id,
        } = output
        else {
            panic!("SRT selection must resolve to an SRT output")
        };
        assert_eq!(server_port, 9_000);
        assert_eq!(passphrase, "strongPass1");
        assert_eq!(latency_ms, 250);
        assert_eq!(stream_id, "field unit");

        settings.srt_server.passphrase = SrtPassphraseState::Unavailable {
            preserved_ciphertext: "opaque-ciphertext".into(),
        };
        let error = match resolve_selected_restream_output(&settings) {
            Ok(_) => panic!("unavailable SRT encryption must fail before bind resolution"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), "SrtPassphraseUnavailable");
        assert!(!error.to_string().contains("opaque-ciphertext"));
    }

    #[tokio::test]
    async fn stopped_switch_can_select_unavailable_srt_but_start_remains_blocked() {
        let mut settings = restream_test_settings(RestreamProtocol::Rtsp);
        settings.srt_server.passphrase = SrtPassphraseState::Unavailable {
            preserved_ciphertext: "opaque-ciphertext".into(),
        };
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
        let adopted = adopted_set(&[]);

        let result = manager
            .relay
            .switch_restream_protocol_with(
                &config,
                RestreamProtocol::Srt,
                &adopted,
                commit_restream_protocol_in_memory,
            )
            .await
            .unwrap();
        assert_eq!(result.selected_protocol, RestreamProtocol::Srt);
        assert!(!result.desired);
        assert!(result.server_info.is_none());
        assert_eq!(config.get().restream_protocol, RestreamProtocol::Srt);
        assert!(active_restream_generation(&manager).await.is_none());

        let error = manager
            .start_restream_server(&config, &adopted)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), "SrtPassphraseUnavailable");
        assert!(!error.to_string().contains("opaque-ciphertext"));
        let state = manager.state.lock().await;
        assert!(!state.relay_data.restream_desired);
        assert!(state.relay_data.restream_server.is_none());
    }

    #[tokio::test]
    async fn switch_invalidates_a_start_before_waiting_for_the_transaction_gate() {
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
        let gate = manager
            .relay
            .restream_transaction
            .clone()
            .lock_owned()
            .await;
        let (start_epoch, _) = manager.relay.begin_restream_start_intent().await.unwrap();
        let commit_called = std::sync::atomic::AtomicBool::new(false);
        let adopted = adopted_set(&[]);

        let operation = manager.relay.switch_restream_protocol_with(
            &config,
            RestreamProtocol::Srt,
            &adopted,
            |config, protocol| {
                commit_called.store(true, std::sync::atomic::Ordering::Release);
                commit_restream_protocol_in_memory(config, protocol)
            },
        );
        let supersede = async {
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                loop {
                    if manager
                        .relay
                        .restream_epoch
                        .load(std::sync::atomic::Ordering::Acquire)
                        > start_epoch
                        && !manager.state.lock().await.relay_data.restream_desired
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("switch must invalidate the old Start before waiting for the gate");
            assert!(!manager.relay.restream_intent_is_current(start_epoch).await);
            manager
                .relay
                .begin_restream_stop_intent()
                .await
                .expect("a newer Stop should supersede the waiting switch");
            drop(gate);
        };
        let (result, ()) = tokio::join!(operation, supersede);

        let error = result.unwrap_err();
        assert_eq!(error.kind(), "Stream");
        assert!(error.to_string().contains("superseded"));
        assert!(!commit_called.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(config.get().restream_protocol, RestreamProtocol::Rtsp);
        assert!(active_restream_generation(&manager).await.is_none());
    }

    #[tokio::test]
    async fn active_settings_apply_invalidates_start_before_waiting_for_the_gate() {
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        let mut update = restream_update_from(&settings, true);
        update.rtsp_server.token = "fedcba9876543210".into();
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
        let gate = manager
            .relay
            .restream_transaction
            .clone()
            .lock_owned()
            .await;
        let (start_epoch, _) = manager.relay.begin_restream_start_intent().await.unwrap();
        let commit_called = std::sync::atomic::AtomicBool::new(false);
        let adopted = adopted_set(&[]);

        let operation = manager.relay.apply_restream_settings_with(
            &config,
            update,
            &adopted,
            |config, prospective| {
                commit_called.store(true, std::sync::atomic::Ordering::Release);
                commit_restream_settings_in_memory(config, prospective)
            },
        );
        let supersede = async {
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                loop {
                    if manager
                        .relay
                        .restream_epoch
                        .load(std::sync::atomic::Ordering::Acquire)
                        > start_epoch
                        && !manager.state.lock().await.relay_data.restream_desired
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("settings apply must invalidate the old Start before waiting for the gate");
            manager
                .relay
                .begin_restream_stop_intent()
                .await
                .expect("a newer Stop should supersede the waiting apply");
            drop(gate);
        };
        let (result, ()) = tokio::join!(operation, supersede);

        let error = result.unwrap_err();
        assert_eq!(error.kind(), "Stream");
        assert!(error.to_string().contains("superseded"));
        assert!(!commit_called.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(config.get().rtsp_server.token, "0123456789abcdef");
    }

    #[tokio::test]
    async fn live_switch_replaces_exactly_one_listener_in_each_direction() {
        init_gstreamer();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        let rtsp_port = settings.rtsp_server.port;
        let srt_port = settings.srt_server.port;
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
        let adopted = adopted_set(&[]);

        manager
            .start_restream_server(&config, &adopted)
            .await
            .unwrap();
        let initial_generation = active_restream_generation(&manager).await.unwrap();

        let srt_result = manager
            .relay
            .switch_restream_protocol_with(
                &config,
                RestreamProtocol::Srt,
                &adopted,
                commit_restream_protocol_in_memory,
            )
            .await
            .unwrap();
        assert!(srt_result.desired);
        assert_eq!(srt_result.selected_protocol, RestreamProtocol::Srt);
        assert_eq!(
            srt_result.server_info.unwrap().protocol,
            RestreamProtocol::Srt
        );
        assert_eq!(
            active_restream_generation(&manager).await,
            Some(initial_generation + 1)
        );
        assert!(std::net::TcpListener::bind(("127.0.0.1", rtsp_port)).is_ok());

        let rtsp_result = manager
            .relay
            .switch_restream_protocol_with(
                &config,
                RestreamProtocol::Rtsp,
                &adopted,
                commit_restream_protocol_in_memory,
            )
            .await
            .unwrap();
        assert!(rtsp_result.desired);
        assert_eq!(rtsp_result.selected_protocol, RestreamProtocol::Rtsp);
        assert_eq!(
            active_restream_generation(&manager).await,
            Some(initial_generation + 2)
        );
        assert!(wait_for_udp_rebind(srt_port).await);

        manager.stop_restream_server().await.unwrap();
        assert!(std::net::TcpListener::bind(("127.0.0.1", rtsp_port)).is_ok());
    }

    #[tokio::test]
    async fn desired_recovering_and_failed_outputs_switch_to_the_new_protocol() {
        init_gstreamer();
        for prior_state in [RelayState::Recovering, RelayState::Failed] {
            let settings = restream_test_settings(RestreamProtocol::Rtsp);
            let srt_port = settings.srt_server.port;
            let config = AppConfig::for_test(settings.clone());
            let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
            let adopted = adopted_set(&[]);
            seed_desired_relay_state(&manager, &settings, prior_state).await;
            assert_eq!(
                compute_status(&manager.state).await.relay_state,
                prior_state
            );

            let result = manager
                .relay
                .switch_restream_protocol_with(
                    &config,
                    RestreamProtocol::Srt,
                    &adopted,
                    commit_restream_protocol_in_memory,
                )
                .await
                .unwrap();
            assert!(result.desired);
            assert_eq!(result.selected_protocol, RestreamProtocol::Srt);
            assert_eq!(result.server_info.unwrap().protocol, RestreamProtocol::Srt);
            let status = compute_status(&manager.state).await;
            assert!(status.desired);
            assert_eq!(status.active_protocol, Some(RestreamProtocol::Srt));
            assert!(status.server_running);

            manager.stop_restream_server().await.unwrap();
            assert!(wait_for_udp_rebind(srt_port).await);
        }
    }

    #[tokio::test]
    async fn settings_apply_restarts_only_active_changes_and_honors_enable() {
        init_gstreamer();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
        let adopted = adopted_set(&[]);
        manager
            .start_restream_server(&config, &adopted)
            .await
            .unwrap();
        let initial_generation = active_restream_generation(&manager).await.unwrap();

        let mut inactive_update = restream_update_from(&config.get(), true);
        inactive_update.srt_server.latency_ms = 250;
        let inactive_result = manager
            .relay
            .apply_restream_settings_with(
                &config,
                inactive_update,
                &adopted,
                commit_restream_settings_in_memory,
            )
            .await
            .unwrap();
        assert!(inactive_result.desired);
        assert_eq!(config.get().srt_server.latency_ms, 250);
        assert_eq!(
            active_restream_generation(&manager).await,
            Some(initial_generation)
        );

        let mut active_update = restream_update_from(&config.get(), true);
        active_update.rtsp_server.token = "fedcba9876543210".into();
        let active_result = manager
            .relay
            .apply_restream_settings_with(
                &config,
                active_update,
                &adopted,
                commit_restream_settings_in_memory,
            )
            .await
            .unwrap();
        assert!(active_result.desired);
        assert_eq!(
            active_restream_generation(&manager).await,
            Some(initial_generation + 1)
        );

        let disable_result = manager
            .relay
            .apply_restream_settings_with(
                &config,
                restream_update_from(&config.get(), false),
                &adopted,
                commit_restream_settings_in_memory,
            )
            .await
            .unwrap();
        assert!(!disable_result.desired);
        assert!(disable_result.server_info.is_none());
        assert!(!config.get().rtsp_server.enabled);
        assert!(active_restream_generation(&manager).await.is_none());

        let enable_result = manager
            .relay
            .apply_restream_settings_with(
                &config,
                restream_update_from(&config.get(), true),
                &adopted,
                commit_restream_settings_in_memory,
            )
            .await
            .unwrap();
        assert!(!enable_result.desired);
        assert!(enable_result.server_info.is_none());
        assert!(config.get().rtsp_server.enabled);
        assert!(active_restream_generation(&manager).await.is_none());
    }

    #[tokio::test]
    async fn srt_selected_enable_only_apply_stops_and_preserves_protocol_settings() {
        init_gstreamer();
        let mut settings = restream_test_settings(RestreamProtocol::Srt);
        settings.srt_server.latency_ms = 250;
        settings.srt_server.stream_id = "enable-only".into();
        settings.srt_server.passphrase = SrtPassphraseState::Available("strongPass1".into());
        let config = AppConfig::for_test(settings.clone());
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Srt);
        let adopted = adopted_set(&[]);
        manager
            .start_restream_server(&config, &adopted)
            .await
            .unwrap();
        assert!(active_restream_generation(&manager).await.is_some());

        for enabled in [false, true] {
            let result = manager
                .relay
                .apply_restream_settings_with(
                    &config,
                    restream_update_from(&config.get(), enabled),
                    &adopted,
                    commit_restream_settings_in_memory,
                )
                .await
                .unwrap();
            assert_eq!(result.selected_protocol, RestreamProtocol::Srt);
            assert!(!result.desired);
            assert!(result.server_info.is_none());
            assert!(active_restream_generation(&manager).await.is_none());
            let mut expected_rtsp = settings.rtsp_server.clone();
            expected_rtsp.enabled = enabled;
            assert_eq!(config.get().rtsp_server, expected_rtsp);
            assert!(config.get().srt_server == settings.srt_server);
            assert_eq!(config.get().restream_protocol, RestreamProtocol::Srt);
            let status = compute_status(&manager.state).await;
            assert!(!status.desired);
            assert!(!status.server_running);
            assert_eq!(status.active_protocol, None);
        }
        assert!(wait_for_udp_rebind(settings.srt_server.port).await);
    }

    #[tokio::test]
    async fn persistence_failures_restore_settings_selection_and_runtime() {
        init_gstreamer();
        let settings = restream_test_settings(RestreamProtocol::Rtsp);
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
        let adopted = adopted_set(&[]);
        manager
            .start_restream_server(&config, &adopted)
            .await
            .unwrap();
        let initial_generation = active_restream_generation(&manager).await.unwrap();

        let mut update = restream_update_from(&config.get(), true);
        update.rtsp_server.token = "fedcba9876543210".into();
        let settings_error = manager
            .relay
            .apply_restream_settings_with(&config, update, &adopted, |_, _| {
                Err(AppError::Config("injected settings write failure".into()))
            })
            .await
            .unwrap_err();
        assert_eq!(settings_error.kind(), "Config");
        assert_eq!(config.get().rtsp_server.token, "0123456789abcdef");
        assert_eq!(
            active_restream_generation(&manager).await,
            Some(initial_generation + 1)
        );
        {
            let state = manager.state.lock().await;
            assert!(state.relay_data.restream_desired);
            assert_eq!(state.relay_data.selected_protocol, RestreamProtocol::Rtsp);
            assert!(state
                .relay_data
                .restream_server
                .as_ref()
                .is_some_and(|server| server.protocol() == RestreamProtocol::Rtsp));
        }

        let selector_error = manager
            .relay
            .switch_restream_protocol_with(&config, RestreamProtocol::Srt, &adopted, |_, _| {
                Err(AppError::Config("injected selector write failure".into()))
            })
            .await
            .unwrap_err();
        assert_eq!(selector_error.kind(), "Config");
        assert_eq!(config.get().restream_protocol, RestreamProtocol::Rtsp);
        assert_eq!(
            active_restream_generation(&manager).await,
            Some(initial_generation + 2)
        );
        let status = compute_status(&manager.state).await;
        assert!(status.desired);
        assert_eq!(status.selected_protocol, RestreamProtocol::Rtsp);
        assert_eq!(status.active_protocol, Some(RestreamProtocol::Rtsp));

        manager.stop_restream_server().await.unwrap();
    }

    #[tokio::test]
    async fn persistence_and_restoration_failures_are_reported_together() {
        init_gstreamer();
        let settings = restream_test_settings(RestreamProtocol::Srt);
        let srt_port = settings.srt_server.port;
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Srt);
        let adopted = adopted_set(&[]);
        manager
            .start_restream_server(&config, &adopted)
            .await
            .unwrap();
        let occupied = std::sync::Mutex::new(None);

        let mut update = restream_update_from(&config.get(), true);
        update.srt_server.stream_id = "replacement".into();
        let error = manager
            .relay
            .apply_restream_settings_with(&config, update, &adopted, |_, _| {
                let listener = bind_udp_after_release(srt_port);
                *occupied.lock().unwrap() = Some(listener);
                Err(AppError::Config("injected settings write failure".into()))
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), "Config");
        assert!(error
            .to_string()
            .contains("injected settings write failure"));
        assert!(
            error
                .to_string()
                .contains("restoring the prior re-stream output also failed"),
            "unexpected error: {error}"
        );
        assert!(config.get().srt_server.stream_id.is_empty());
        let status = compute_status(&manager.state).await;
        assert!(status.desired);
        assert_eq!(status.relay_state, RelayState::Failed);
        assert!(!status.server_running);

        occupied.lock().unwrap().take();
        manager.stop_restream_server().await.unwrap();
    }

    #[tokio::test]
    async fn unavailable_live_srt_switch_fails_before_disrupting_rtsp() {
        init_gstreamer();
        let mut settings = restream_test_settings(RestreamProtocol::Rtsp);
        settings.srt_server.passphrase = SrtPassphraseState::Unavailable {
            preserved_ciphertext: "opaque-ciphertext".into(),
        };
        let config = AppConfig::for_test(settings);
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Rtsp);
        let adopted = adopted_set(&[]);
        manager
            .start_restream_server(&config, &adopted)
            .await
            .unwrap();
        let generation = active_restream_generation(&manager).await.unwrap();
        let epoch = manager
            .relay
            .restream_epoch
            .load(std::sync::atomic::Ordering::Acquire);
        let commit_called = std::sync::atomic::AtomicBool::new(false);

        let error = manager
            .relay
            .switch_restream_protocol_with(
                &config,
                RestreamProtocol::Srt,
                &adopted,
                |config, protocol| {
                    commit_called.store(true, std::sync::atomic::Ordering::Release);
                    commit_restream_protocol_in_memory(config, protocol)
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), "SrtPassphraseUnavailable");
        assert!(!error.to_string().contains("opaque-ciphertext"));
        assert!(!commit_called.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(
            manager
                .relay
                .restream_epoch
                .load(std::sync::atomic::Ordering::Acquire),
            epoch
        );
        assert_eq!(active_restream_generation(&manager).await, Some(generation));
        let status = compute_status(&manager.state).await;
        assert!(status.desired);
        assert_eq!(status.selected_protocol, RestreamProtocol::Rtsp);
        assert_eq!(status.active_protocol, Some(RestreamProtocol::Rtsp));

        manager.stop_restream_server().await.unwrap();
    }

    #[tokio::test]
    async fn srt_dispatch_populates_protocol_neutral_status() {
        init_gstreamer();
        let udp_port = unused_udp_port();
        let mut server_port = unused_udp_port();
        while server_port == udp_port {
            server_port = unused_udp_port();
        }
        let manager = StreamManager::with_selected_protocol(RestreamProtocol::Srt);
        let spec = ResolvedStartSpec {
            source: ResolvedSource::Udp { port: udp_port },
            output: ResolvedOutput::Srt {
                server_port,
                passphrase: String::new(),
                latency_ms: 125,
                stream_id: "field unit".into(),
            },
            bind_interface: Some("ZeroTier".into()),
            bind_identity: None,
            bind_scope: crate::network::bindings::BindScope::default(),
            bind_address: Some("127.0.0.1".into()),
            advertised_ip: "127.0.0.1".into(),
            username: String::new(),
            password: String::new(),
        };
        let health = Arc::new(RelayRuntimeHealth::new(73, relay::RelayIngestKind::Udp));
        let (_, built) = RelayService::build_restream_server(
            &spec,
            health.clone(),
            manager.relay.relay_event_tx.clone(),
            false,
            None,
        );
        let server = match built {
            Ok(server) => server,
            Err(failure) => panic!("SRT dispatch failed: {}", failure.error),
        };
        assert_eq!(server.protocol(), RestreamProtocol::Srt);
        assert_eq!(server.client_limit(), 10);
        assert!(server.loop_alive());
        assert!(matches!(server.fault_probe(), RelayFaultProbe::Srt(_)));

        {
            let mut state = manager.state.lock().await;
            state.relay_data.restream_desired = true;
            state.relay_data.restream_spec = Some(spec);
            state.relay_data.restream_health = Some(health);
            state.relay_data.restream_server = Some(server);
            state.relay_data.restream_intent_epoch = Some(0);
            state.relay_data.restream_start_time = Some(std::time::Instant::now());
        }
        let status = compute_status(&manager.state).await;
        assert_eq!(status.selected_protocol, RestreamProtocol::Srt);
        assert_eq!(status.active_protocol, Some(RestreamProtocol::Srt));
        assert!(status.server_running);
        let expected_url = format!("srt://127.0.0.1:{server_port}?streamid=field%20unit");
        let expected_display_url = format!("srt://127.0.0.1:{server_port}");
        assert_eq!(status.server_url.as_deref(), Some(expected_url.as_str()));
        assert_eq!(
            status.display_url.as_deref(),
            Some(expected_display_url.as_str())
        );

        let mut server = {
            let mut state = manager.state.lock().await;
            state.relay_data.restream_server.take().unwrap()
        };
        server.shutdown().await;
        assert!(!server.loop_alive());
    }

    #[tokio::test]
    async fn start_intent_is_visible_before_resolution_and_stop_supersedes_it() {
        let manager = StreamManager::new();
        let (start_epoch, preserve_prior_desired) = manager
            .relay
            .begin_restream_start_intent()
            .await
            .expect("start intent should remain current");
        assert!(!preserve_prior_desired);

        {
            let state = manager.state.lock().await;
            assert!(state.relay_data.restream_desired);
            assert_eq!(state.relay_data.restream_intent_epoch, Some(start_epoch));
            assert!(state.relay_data.restream_spec.is_none());
            assert!(state.relay_data.restream_health.is_none());
        }
        let status = compute_status(&manager.state).await;
        assert!(status.desired);
        assert_eq!(status.relay_state, RelayState::Starting);
        assert_eq!(status.active_protocol, None);

        let stop_intent = manager
            .relay
            .begin_restream_stop_intent()
            .await
            .expect("stop intent should remain current");
        assert!(stop_intent.epoch > start_epoch);
        assert!(!manager.relay.restream_intent_is_current(start_epoch).await);
        manager
            .relay
            .cancel_restream_start_intent(start_epoch, false)
            .await;

        let state = manager.state.lock().await;
        assert!(!state.relay_data.restream_desired);
        assert!(state.relay_data.restream_intent_epoch.is_none());
    }

    #[tokio::test]
    async fn failed_initial_start_clears_current_intent() {
        let manager = StreamManager::new();
        let (start_epoch, preserve_prior_desired) = manager
            .relay
            .begin_restream_start_intent()
            .await
            .expect("start intent should remain current");
        assert!(!preserve_prior_desired);

        manager
            .relay
            .cancel_restream_start_intent(start_epoch, preserve_prior_desired)
            .await;

        let state = manager.state.lock().await;
        assert!(!state.relay_data.restream_desired);
        assert!(state.relay_data.restream_intent_epoch.is_none());
        assert!(state.relay_data.restream_spec.is_none());
        assert!(state.relay_data.restream_health.is_none());
        assert!(state.relay_data.restream_start_time.is_none());
    }

    #[tokio::test]
    async fn stale_start_publication_cannot_reassert_desired() {
        let manager = StreamManager::new();
        manager
            .relay
            .restream_epoch
            .store(2, std::sync::atomic::Ordering::Release);

        assert!(manager
            .relay
            .publish_restream_start_intent(1)
            .await
            .is_none());
        let state = manager.state.lock().await;
        assert!(!state.relay_data.restream_desired);
        assert!(state.relay_data.restream_intent_epoch.is_none());
    }

    #[tokio::test]
    async fn settings_stop_claim_rejects_a_newer_start() {
        let manager = StreamManager::new();
        let operation_epoch = manager
            .relay
            .restream_epoch
            .load(std::sync::atomic::Ordering::Acquire);
        let (newer_epoch, _) = manager
            .relay
            .begin_restream_start_intent()
            .await
            .expect("newer start should publish");

        assert!(manager
            .relay
            .begin_restream_stop_intent_if_current(operation_epoch)
            .await
            .is_none());
        let state = manager.state.lock().await;
        assert!(state.relay_data.restream_desired);
        assert_eq!(state.relay_data.restream_intent_epoch, Some(newer_epoch));
    }

    #[tokio::test]
    async fn transactional_restart_cannot_override_a_newer_stop() {
        let manager = StreamManager::new();
        manager
            .relay
            .begin_restream_start_intent()
            .await
            .expect("initial start should publish");
        let transaction_stop = manager
            .relay
            .begin_restream_stop_intent()
            .await
            .expect("transaction stop should publish");
        manager
            .relay
            .begin_restream_stop_intent()
            .await
            .expect("newer stop should publish");

        assert!(manager
            .relay
            .begin_restream_start_intent_if_current(transaction_stop.epoch)
            .await
            .is_none());
        let state = manager.state.lock().await;
        assert!(!state.relay_data.restream_desired);
        assert!(state.relay_data.restream_intent_epoch.is_none());
    }

    #[test]
    fn stop_tears_down_the_stored_listener_not_an_in_flight_generation() {
        assert_eq!(restream_stop_target(true, Some(2), Some(1)), Some(1));
        assert_eq!(restream_stop_target(true, Some(2), None), None);
        assert_eq!(restream_stop_target(false, Some(2), Some(2)), None);
        assert_eq!(restream_stop_target(false, Some(2), Some(1)), Some(1));
    }

    #[tokio::test]
    async fn recovery_status_keeps_desired_urls_without_a_listener() {
        let manager = StreamManager::new();
        let spec = ResolvedStartSpec {
            source: ResolvedSource::Rtsp {
                url: "rtsp://192.0.2.20/live".into(),
            },
            output: ResolvedOutput::Rtsp {
                server_port: 8554,
                mount_path: "/stream-stable-token".into(),
            },
            bind_interface: Some("VPN".into()),
            bind_identity: None,
            bind_scope: crate::network::bindings::BindScope::default(),
            bind_address: Some("192.0.2.10".into()),
            advertised_ip: "192.0.2.10".into(),
            username: "camera".into(),
            password: "password".into(),
        };
        let expected_client_url = spec.client_url();
        let expected_display_url = spec.display_url();
        let health = Arc::new(RelayRuntimeHealth::new(1, spec.ingest_kind()));
        health.schedule_recovery_attempt();
        health.mark_recovery_in_progress();
        {
            let mut state = manager.state.lock().await;
            state.relay_data.restream_desired = true;
            state.relay_data.restream_spec = Some(spec);
            state.relay_data.restream_health = Some(health);
            state.relay_data.restream_intent_epoch = Some(0);
            state.relay_data.restream_start_time = Some(std::time::Instant::now());
        }

        let status = compute_status(&manager.state).await;
        assert!(status.desired);
        assert_eq!(status.active_protocol, Some(RestreamProtocol::Rtsp));
        assert!(!status.server_running);
        assert_eq!(status.relay_state, RelayState::Recovering);
        assert_eq!(
            status.server_url.as_deref(),
            Some(expected_client_url.as_str())
        );
        assert_eq!(
            status.display_url.as_deref(),
            Some(expected_display_url.as_str())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stop_interrupts_every_nonzero_recovery_backoff() {
        for delay in relay::RECOVERY_DELAYS
            .into_iter()
            .filter(|delay| !delay.is_zero())
        {
            let manager = StreamManager::new();
            seed_desired_relay(&manager, 1, 0).await;
            let state = manager.relay.state.clone();
            let epoch = manager.relay.restream_epoch.clone();
            let wake = manager.relay.relay_wake.clone();
            let started_at = tokio::time::Instant::now();
            let waiter = tokio::spawn(async move {
                wait_relay_backoff(&state, &epoch, &wake, 0, 1, delay).await
            });
            tokio::task::yield_now().await;

            manager
                .relay
                .restream_epoch
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            manager.relay.relay_wake.notify_waiters();
            assert!(!waiter.await.unwrap());
            assert!(tokio::time::Instant::now().duration_since(started_at) < delay);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn newer_manual_generation_interrupts_old_backoff() {
        let manager = StreamManager::new();
        seed_desired_relay(&manager, 1, 0).await;
        let state = manager.relay.state.clone();
        let epoch = manager.relay.restream_epoch.clone();
        let wake = manager.relay.relay_wake.clone();
        let waiter = tokio::spawn(async move {
            wait_relay_backoff(
                &state,
                &epoch,
                &wake,
                0,
                1,
                std::time::Duration::from_secs(60),
            )
            .await
        });
        tokio::task::yield_now().await;

        {
            let mut state = manager.state.lock().await;
            state.relay_data.restream_health = Some(Arc::new(RelayRuntimeHealth::new(
                2,
                relay::RelayIngestKind::Rtsp,
            )));
        }
        manager.relay.relay_wake.notify_waiters();
        assert!(!waiter.await.unwrap());
    }
}
