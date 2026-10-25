//! Typed local native operations. Address transactions retain their existing
//! serialization; the executor owns the complete IPC transaction and lost reply.
use super::interface::AddressIo;
use super::interface::{self, NativeAdapter, NativeIdentity};
use super::local_executor::{AdmissionError, Completion, LocalExecutor, Outcome};
use super::native_runner::{Cancellation, NativeProcessRunner, ProcessResult, Termination};
use crate::AppError;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, OnceLock};
use tauri::Manager;

pub(super) const SCRIPT: &str = include_str!("native-operations-v1.ps1");

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Inventory,
    Observe,
    AddAddress,
    RemoveAddress,
    StaticAddress,
    Dhcp,
    Restart,
    Renew,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct Operation {
    version: u8,
    kind: Kind,
    identity: Option<NativeIdentity>,
    address: Option<Ipv4Addr>,
    prefix: Option<u8>,
    automatic: bool,
}

pub(super) use crate::validation::validate_host;

impl Operation {
    fn selected(adapter: &NativeAdapter, kind: Kind) -> Result<Self, AppError> {
        let identity = adapter.identity();
        let valid_guid = identity.guid.len() == 36
            && identity.guid.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            });
        if !valid_guid
            || identity.index == 0
            || super::device_registry::canonical_mac(&identity.mac).is_none()
        {
            return Err(AppError::Network(
                "Selected native adapter identity is invalid".into(),
            ));
        }
        Ok(Self {
            version: 1,
            kind,
            identity: Some(identity),
            address: None,
            prefix: None,
            automatic: false,
        })
    }
    pub fn inventory() -> Self {
        Self {
            version: 1,
            kind: Kind::Inventory,
            identity: None,
            address: None,
            prefix: None,
            automatic: false,
        }
    }
    pub fn address(
        adapter: &NativeAdapter,
        ip: &str,
        prefix: u8,
        add: bool,
        automatic: bool,
    ) -> Result<Self, AppError> {
        let ip = ip
            .parse::<Ipv4Addr>()
            .map_err(|_| AppError::Network("Invalid IPv4 host address".into()))?;
        validate_host(ip, prefix)?;
        if automatic && (prefix != 24 || ip.is_link_local()) {
            return Err(AppError::Network(
                "Automatic address requires a non-APIPA /24 host".into(),
            ));
        }
        let mut op = Self::selected(
            adapter,
            if add {
                Kind::AddAddress
            } else {
                Kind::RemoveAddress
            },
        )?;
        op.address = Some(ip);
        op.prefix = Some(prefix);
        op.automatic = automatic;
        Ok(op)
    }
    pub fn static_address(adapter: &NativeAdapter, ip: &str, prefix: u8) -> Result<Self, AppError> {
        let mut op = Self::address(adapter, ip, prefix, true, false)?;
        op.kind = Kind::StaticAddress;
        Ok(op)
    }
    pub fn dhcp(adapter: &NativeAdapter) -> Result<Self, AppError> {
        Self::selected(adapter, Kind::Dhcp)
    }
    pub fn observe(adapter: &NativeAdapter) -> Result<Self, AppError> {
        Self::selected(adapter, Kind::Observe)
    }
    pub fn refresh(adapter: &NativeAdapter, hard: bool) -> Result<Self, AppError> {
        Self::selected(adapter, if hard { Kind::Restart } else { Kind::Renew })
    }
    pub(super) fn payload(&self) -> Result<Vec<u8>, AppError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| AppError::Network("Native input encoding failed".into()))?;
        if bytes.len() > 16384 {
            return Err(AppError::Network("Native input exceeds limit".into()));
        }
        Ok(bytes)
    }
    fn steps_match(&self, report: &Report) -> bool {
        let required: &[&str] = match self.kind {
            Kind::Inventory => &["inventory"],
            Kind::Observe => &["postcondition"],
            Kind::AddAddress => &["add_address", "postcondition"],
            Kind::RemoveAddress => &["remove_address", "postcondition"],
            Kind::StaticAddress => &["static_primary", "restore_secondaries", "postcondition"],
            Kind::Dhcp => &[
                "remove_manual_addresses",
                "remove_default_routes",
                "enable_dhcp",
                "reset_dns",
                "renew_lease",
                "verify_dns_reset",
                "postcondition",
            ],
            Kind::Restart => &["restart_adapter", "postcondition"],
            Kind::Renew => &["/release", "/renew", "postcondition"],
        };
        report
            .steps
            .iter()
            .map(|s| s.name.as_str())
            .eq(required.iter().copied())
    }
    fn native_effect_matches(&self, adapter: &NativeAdapter) -> bool {
        let address_present = self.address.is_some_and(|ip| {
            adapter
                .ips
                .iter()
                .any(|a| a.address == ip.to_string() && Some(a.prefix) == self.prefix)
        });
        match self.kind {
            Kind::Inventory | Kind::Observe | Kind::Restart => true,
            Kind::AddAddress | Kind::StaticAddress => address_present && !adapter.dhcp,
            Kind::RemoveAddress => self
                .address
                .is_some_and(|ip| !adapter.ips.iter().any(|a| a.address == ip.to_string())),
            Kind::Dhcp | Kind::Renew => adapter.dhcp,
        }
    }
    fn postcondition(&self, adapter: &NativeAdapter, data: Option<&serde_json::Value>) -> bool {
        let Some(reported) = data
            .cloned()
            .and_then(|d| serde_json::from_value::<ObservedState>(d).ok())
        else {
            return false;
        };
        let mut actual_ips: Vec<_> = adapter
            .ips
            .iter()
            .map(|a| (a.address.clone(), a.prefix))
            .collect();
        let mut reported_ips: Vec<_> = reported
            .addresses
            .into_iter()
            .map(|a| (a.address, a.prefix))
            .collect();
        actual_ips.sort();
        reported_ips.sort();
        let mut actual_gateways = adapter.gateways.clone();
        let mut reported_gateways = reported.gateways;
        actual_gateways.sort();
        actual_gateways.dedup();
        reported_gateways.sort();
        reported_gateways.dedup();
        reported.dhcp == adapter.dhcp
            && actual_ips == reported_ips
            && actual_gateways == reported_gateways
            && reported.dns.iter().all(|ip| ip.parse::<Ipv4Addr>().is_ok())
            && reported.dns_manual.len() <= 4096
            && self.native_effect_matches(adapter)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedAddress {
    address: String,
    prefix: u8,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedState {
    dhcp: bool,
    addresses: Vec<ObservedAddress>,
    gateways: Vec<String>,
    dns: Vec<String>,
    dns_manual: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    name: String,
    ok: bool,
    native_exit: Option<i32>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    version: u8,
    ok: bool,
    stage: String,
    mutated: bool,
    steps: Vec<Step>,
    data: Option<serde_json::Value>,
}

fn parse_report(result: &ProcessResult) -> Result<Report, AppError> {
    if result.termination != Termination::Exited
        || result.stdout.truncated
        || result.stderr.truncated
        || result.stdout.read_failed
        || result.stderr.read_failed
        || !result.observed_tree_exited
    {
        return Err(AppError::Network(
            "Native operation interrupted or output unavailable; reconciliation required".into(),
        ));
    }
    let report: Report = serde_json::from_slice(&result.stdout.bytes)
        .map_err(|_| AppError::Network("Invalid native result; reconciliation required".into()))?;
    if report.version != 1
        || report.ok != (result.exit_code == 0)
        || report.steps.len() > 64
        || report.stage.len() > 64
        || report.steps.iter().any(|s| {
            (report.ok && (!s.ok || s.native_exit.is_some_and(|exit| exit != 0)))
                || s.name.len() > 64
        })
    {
        return Err(AppError::Network(
            "Inconsistent native result; reconciliation required".into(),
        ));
    }
    Ok(report)
}

fn executor() -> &'static LocalExecutor {
    static EXECUTOR: OnceLock<LocalExecutor> = OnceLock::new();
    EXECUTOR.get_or_init(LocalExecutor::for_serialized_writers)
}
fn admission(error: AdmissionError) -> AppError {
    if error == AdmissionError::ReconciliationRequired
        && executor().retained().is_some_and(|(_, result)| {
            result
                .observation
                .as_ref()
                .is_some_and(|facts| facts["report"]["stage"] == "access")
        })
    {
        return AppError::Network("Administrator access is required; restart using the installed administrator build to reconcile network state".into());
    }
    AppError::Network(match error {
        AdmissionError::Busy => "Waiting for the current native operation; try again",
        AdmissionError::ShuttingDown => "PocketStream is shutting down; native writes are unavailable",
        AdmissionError::ReconciliationRequired => "Native operation recovery is pending; restart PocketStream to reconcile before changing network settings",
    }.into())
}

#[derive(Default)]
struct ScopeState {
    last: Option<Completion>,
    failed: bool,
    mutated: bool,
}

impl ScopeState {
    fn record(&mut self, completion: Completion, failed: bool) {
        self.failed |= failed;
        self.mutated |= completion.observation.as_ref().is_some_and(|facts| {
            facts["report"]["mutated"] == true
                || (completion.outcome == Outcome::Uncertain
                    && facts["operation"]["kind"] != "observe")
        });
        self.last = Some(completion);
    }

    fn finish(mut self, outcome: Outcome, step: &'static str) -> Completion {
        let mut completion = self
            .last
            .take()
            .unwrap_or_else(|| Completion::new(outcome, step));
        if completion.outcome != Outcome::Uncertain {
            completion.outcome = if (self.mutated && outcome != Outcome::Completed)
                || (self.failed && outcome == Outcome::Completed)
            {
                Outcome::Uncertain
            } else {
                outcome
            };
        }
        completion.step = step;
        completion
    }
}

tokio::task_local! {
    static NATIVE_SCOPE: (Cancellation, Arc<Mutex<ScopeState>>);
}

pub(crate) fn check_writes_available() -> Result<(), AppError> {
    if let Ok(available) = NATIVE_SCOPE
        .try_with(|(cancel, state)| !cancel.requested() && !state.lock().unwrap().failed)
    {
        return if available {
            Ok(())
        } else {
            Err(admission(AdmissionError::ReconciliationRequired))
        };
    }
    executor().available().map_err(admission)
}

pub(super) fn request_canceled() -> bool {
    NATIVE_SCOPE
        .try_with(|(cancel, _)| cancel.requested())
        .unwrap_or(false)
}

async fn request<T, F, Fut>(
    executor: &LocalExecutor,
    work: F,
    classify: fn(&T) -> Outcome,
) -> Result<T, AppError>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    let ticket = executor
        .submit_managed(move |cancel| async move {
            let state = Arc::new(Mutex::new(ScopeState::default()));
            let result = NATIVE_SCOPE
                .scope((cancel, state.clone()), async move { work().await })
                .await;
            let completion = std::mem::take(&mut *state.lock().unwrap())
                .finish(classify(&result), "transaction_finished");
            let _ = tx.send(result);
            completion
        })
        .map_err(admission)?;
    let id = ticket.id;
    let completion = ticket.wait().await.map_err(|_| {
        AppError::Network(
            "Native transaction completion unavailable; reconciliation required".into(),
        )
    })?;
    let result = rx.await.map_err(|_| {
        AppError::Network("Native transaction reply unavailable; reconciliation required".into())
    })?;
    if completion.outcome != Outcome::Uncertain {
        executor.acknowledge(id).map_err(admission)?;
    }
    Ok(result)
}

fn result_outcome<T>(result: &Result<T, AppError>) -> Outcome {
    if result.is_ok() {
        Outcome::Completed
    } else {
        Outcome::Failed
    }
}

pub(crate) async fn address_request(
    app: tauri::AppHandle,
    operation: super::manual_address::AddressRequest,
) -> Result<super::manual_address::AddressReply, AppError> {
    request(executor(), move || async move {
        let subnet = match &operation {
            super::manual_address::AddressRequest::RemoveSaved { subnet, .. } => Some(subnet.clone()),
            _ => None,
        };
        let reply = app.state::<std::sync::Arc<super::NetworkManager>>()
            .address_operation(&app.state::<std::sync::Arc<crate::config::AppConfig>>(), operation).await;
        if reply.outcome == super::manual_address::AddressOutcome::Success {
            if let Some(subnet) = subnet {
                use tauri::Emitter;
                let _ = app.emit("subnet-removed", serde_json::json!({"subnet":subnet,"adopted_ip":reply.view.address,"reason":"manual"}));
            }
        }
        reply
    }, |reply| match reply.outcome {
        super::manual_address::AddressOutcome::Success => Outcome::Completed,
        super::manual_address::AddressOutcome::Pending => Outcome::Uncertain,
        _ => Outcome::Failed,
    }).await
}

pub(crate) async fn mode_request(
    app: tauri::AppHandle,
    operation: super::ModeTransition,
) -> Result<super::ModeTransitionReply, AppError> {
    request(
        executor(),
        move || async move {
            app.state::<std::sync::Arc<super::NetworkManager>>()
                .transition_mode(
                    app.clone(),
                    &app.state::<std::sync::Arc<crate::config::AppConfig>>(),
                    operation,
                )
                .await
        },
        result_outcome,
    )
    .await?
}

pub(crate) async fn refresh_request(
    app: tauri::AppHandle,
    name: String,
    mode: super::adapter_refresh::RefreshMode,
) -> Result<(), AppError> {
    request(
        executor(),
        move || async move {
            app.state::<std::sync::Arc<super::NetworkManager>>()
                .refresh_native_adapter(
                    &app.state::<std::sync::Arc<crate::config::AppConfig>>(),
                    &name,
                    mode,
                )
                .await
        },
        result_outcome,
    )
    .await?
}

pub(crate) async fn select_request(
    app: tauri::AppHandle,
    mac: String,
) -> Result<super::AdapterSelection, AppError> {
    request(
        executor(),
        move || async move {
            let selection = app
                .state::<std::sync::Arc<super::NetworkManager>>()
                .select_adapter(
                    &app.state::<std::sync::Arc<crate::config::AppConfig>>(),
                    &app,
                    &mac,
                )
                .await?;
            super::watcher::emit_selection(&app, &selection);
            Ok(selection)
        },
        result_outcome,
    )
    .await?
}

pub(super) fn evaluate_result(
    operation: &Operation,
    before: Option<&NativeAdapter>,
    after: Option<&NativeAdapter>,
    process: &ProcessResult,
) -> (Completion, Result<Option<serde_json::Value>, AppError>) {
    let mut completion = Completion::new(Outcome::Uncertain, "native_result_unavailable");
    completion.observation = Some(serde_json::json!({
        "operation": operation, "native_before": before, "native_after": after,
        "exit_code": process.exit_code, "termination": format!("{:?}", process.termination),
        "stdout_truncated": process.stdout.truncated, "stderr_truncated": process.stderr.truncated,
    }));
    let identity_matches = operation
        .identity
        .as_ref()
        .is_none_or(|id| after.is_some_and(|a| a.identity() == *id));
    let report = match parse_report(process) {
        Ok(report) => report,
        Err(error) => {
            // A killed child may already have applied an address. Only simple
            // single-address effects can be fully accounted for by IP Helper;
            // composite DNS/route work needs its complete structured evidence.
            if identity_matches
                && matches!(operation.kind, Kind::AddAddress | Kind::RemoveAddress)
                && before.zip(after).is_some_and(|(before, after)| {
                    let unchanged = |adapter: &NativeAdapter| {
                        let mut ips: Vec<_> = adapter
                            .ips
                            .iter()
                            .filter(|ip| {
                                Some(ip.address.as_str())
                                    != operation
                                        .address
                                        .as_ref()
                                        .map(|ip| ip.to_string())
                                        .as_deref()
                            })
                            .map(|ip| (ip.address.clone(), ip.prefix))
                            .collect();
                        ips.sort();
                        ips
                    };
                    operation.native_effect_matches(after)
                        && unchanged(before) == unchanged(after)
                        && before.dhcp == after.dhcp
                        && before.gateways == after.gateways
                })
            {
                completion.outcome = Outcome::Completed;
                completion.step = "interrupted_address_effect_observed";
            }
            return (completion, Err(error));
        }
    };
    completion.observation.as_mut().unwrap()["report"] = serde_json::to_value(&report).unwrap();
    if !identity_matches
        || (report.ok
            && operation.identity.is_some()
            && after.is_none_or(|adapter| !operation.postcondition(adapter, report.data.as_ref())))
    {
        completion.step = "native_observation_failed";
        return (
            completion,
            Err(AppError::Network(
                "Native postcondition observation failed; reconciliation required".into(),
            )),
        );
    }
    if !report.ok {
        // A preflight refusal is known to have made no change. Partial work,
        // including failed DNS/route cleanup, cannot authorize a blind retry.
        completion.outcome = if report.mutated {
            Outcome::Uncertain
        } else {
            Outcome::Failed
        };
        completion.step = "native_step_failed";
        let detail = if report.stage == "access" {
            "Administrator access is required; launch the installed administrator build"
        } else {
            "Native operation failed; inspect network state before retrying"
        };
        log::warn!(
            "event=native_step_failed step={} mutated={}",
            super::log_value(&report.stage),
            report.mutated
        );
        return (completion, Err(AppError::Network(detail.into())));
    }
    if !operation.steps_match(&report) {
        return (
            completion,
            Err(AppError::Network(
                "Native operation omitted a required step; reconciliation required".into(),
            )),
        );
    }
    completion.outcome = Outcome::Completed;
    completion.step = "native_postconditions_verified";
    (completion, Ok(report.data))
}

async fn observed_result(
    operation: Operation,
    cancel: Cancellation,
) -> (Completion, Result<Option<serde_json::Value>, AppError>) {
    let before = if let Some(identity) = &operation.identity {
        match interface::operation_snapshot(&interface::RealAddressIo, &identity.mac).await {
            Ok(snapshot) if snapshot.selected.identity() == *identity => Some(snapshot.selected),
            _ => {
                return (
                    Completion::new(Outcome::Failed, "identity_preflight"),
                    Err(AppError::Network(
                        "Selected adapter changed or could not be observed before native dispatch"
                            .into(),
                    )),
                )
            }
        }
    } else {
        None
    };
    if cancel.requested() {
        return (
            Completion::new(Outcome::Canceled, "canceled_before_dispatch"),
            Err(AppError::Network(
                "Native operation canceled before dispatch".into(),
            )),
        );
    }
    let dispatched = operation.clone();
    let process =
        tokio::task::spawn_blocking(move || NativeProcessRunner::run_operation(dispatched, cancel))
            .await;
    // Observe even on interruption/failure; termination alone never establishes
    // that a provider made no mutation. These facts belong to the executor.
    let after = if let Some(identity) = &operation.identity {
        interface::read_native()
            .await
            .ok()
            .and_then(|all| interface::select_native(&all, &identity.mac).ok().cloned())
    } else {
        None
    };
    let process = match process {
        Ok(Ok(process)) => process,
        _ => {
            let mut completion = Completion::new(Outcome::Uncertain, "runner_unavailable");
            completion.observation = Some(
                serde_json::json!({"operation":operation,"native_before":before,"native_after":after}),
            );
            return (
                completion,
                Err(AppError::Network(
                    "Native process result unavailable; reconciliation required".into(),
                )),
            );
        }
    };
    log::info!("event=native_result exit={} termination={:?} elapsed_ms={} contained={} observed_children={}",
        process.exit_code, process.termination, process.elapsed.as_millis(), process.containment_verified_before_resume, process.observed_tree_pids.len());
    evaluate_result(&operation, before.as_ref(), after.as_ref(), &process)
}

pub(super) async fn execute(operation: Operation) -> Result<(), AppError> {
    if let Ok((cancel, state)) =
        NATIVE_SCOPE.try_with(|(cancel, state)| (cancel.clone(), state.clone()))
    {
        check_writes_available()?;
        let (completion, result) = observed_result(operation, cancel).await;
        let failed = completion.outcome != Outcome::Completed || result.is_err();
        state.lock().unwrap().record(completion, failed);
        return result.map(|_| ());
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    let ticket = executor()
        .submit(move |cancel| async move {
            let (completion, result) = observed_result(operation, cancel).await;
            let _ = tx.send(result);
            completion
        })
        .map_err(admission)?;
    let id = ticket.id;
    let completion = ticket.wait().await.map_err(|_| {
        AppError::Network("Native completion unavailable; reconciliation required".into())
    })?;
    let result = rx.await.map_err(|_| {
        AppError::Network("Native reply unavailable; reconciliation required".into())
    })?;
    if completion.outcome != Outcome::Uncertain {
        executor().acknowledge(id).map_err(admission)?;
    }
    result.map(|_| ())
}

pub(super) async fn inventory() -> Result<String, AppError> {
    // Read-only observations remain available while write recovery is blocked.
    struct CancelRead(Cancellation);
    impl Drop for CancelRead {
        fn drop(&mut self) {
            self.0.request();
        }
    }
    let cancel = Cancellation::default();
    let _cancel_read = CancelRead(cancel.clone());
    let (_, result) = observed_result(Operation::inventory(), cancel).await;
    serde_json::to_string(
        &result?.ok_or_else(|| AppError::Network("Native inventory missing".into()))?,
    )
    .map_err(|_| AppError::Network("Native inventory encoding failed".into()))
}

/// Firewall policy uses the same retained executor and cancellation barrier as
/// address writers. A maintenance child starts in reconciliation mode and
/// never acquires its parent's installation gate.
pub(super) async fn firewall_request(
    operation: super::firewall::Operation,
    recovery: bool,
) -> super::firewall::FirewallOutcome {
    use super::firewall::{self, FirewallOutcome};
    if let Ok((cancel, state)) =
        NATIVE_SCOPE.try_with(|(cancel, state)| (cancel.clone(), state.clone()))
    {
        if let Err(error) = check_writes_available() {
            return FirewallOutcome::Unavailable {
                reason: error.to_string(),
            };
        }
        let (completion, result) = firewall::execute(operation, cancel).await;
        let failed = completion.outcome != Outcome::Completed;
        state.lock().unwrap().record(completion, failed);
        return result;
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    let work = move |cancel| async move {
        let (completion, result) = firewall::execute(operation, cancel).await;
        if recovery {
            *firewall::MAINTENANCE_OBSERVATION.lock().unwrap() = completion.observation.clone();
        }
        let _ = tx.send(result);
        completion
    };
    let pending = if recovery {
        executor().reconcile(work)
    } else {
        executor().submit(work)
    };
    let ticket = match pending {
        Ok(ticket) => ticket,
        Err(error) => {
            return FirewallOutcome::Unavailable {
                reason: admission(error).to_string(),
            }
        }
    };
    let id = ticket.id;
    match ticket.wait().await {
        Ok(completion) => {
            if !recovery && completion.outcome != Outcome::Uncertain {
                let _ = executor().acknowledge(id);
            }
            rx.await.unwrap_or(FirewallOutcome::Failed {
                stage: "reply".into(),
                reason: "Native reply lost; reconciliation required".into(),
                uncertain: true,
            })
        }
        Err(_) => FirewallOutcome::Failed {
            stage: "completion".into(),
            reason: "Native completion lost; reconciliation required".into(),
            uncertain: true,
        },
    }
}

fn validate_recovery_settings(
    settings: &crate::config::AppSettings,
    all: &[NativeAdapter],
    io: &dyn AddressIo,
) -> Result<(), AppError> {
    let validate = |mac: &str, address: &str, prefix: u8| {
        let ip = address
            .parse()
            .map_err(|_| AppError::Network("Saved recovery address is malformed".into()))?;
        validate_host(ip, prefix)?;
        let adapter = interface::select_native(all, mac)?;
        if io
            .descriptor(adapter)
            .filter(interface::is_wired_physical)
            .is_none()
        {
            return Err(AppError::Network(
                "Recovery adapter requires physical Ethernet qualification".into(),
            ));
        }
        if adapter
            .ips
            .iter()
            .any(|ip| ip.address == address && ip.prefix != prefix)
        {
            return Err(AppError::Network(
                "Saved address prefix changed; no cleanup was attempted".into(),
            ));
        }
        Ok(())
    };
    for row in &settings.pending_addresses {
        if row.prefix != 24 {
            return Err(AppError::Network(
                "Pending automatic address prefix is invalid".into(),
            ));
        }
        validate(&row.adapter_mac, &row.address, row.prefix)?;
    }
    for row in settings.adopted_meta.values() {
        // Unowned legacy rows remain passive under the existing binding policy.
        let Some(mac) = &row.adapter_mac else {
            continue;
        };
        let address = row
            .address
            .as_deref()
            .ok_or_else(|| AppError::Network("Saved owned address is unknown".into()))?;
        let prefix = row
            .prefix
            .ok_or_else(|| AppError::Network("Saved owned prefix is unknown".into()))?;
        validate(mac, address, prefix)?;
    }
    Ok(())
}

pub(crate) async fn startup_reconcile(app: tauri::AppHandle) -> Result<(), AppError> {
    let ticket = executor()
        .reconcile(move |cancel| async move {
            let state = Arc::new(Mutex::new(ScopeState::default()));
            let tracked = state.clone();
            let result = NATIVE_SCOPE
                .scope((cancel, state), async move {
                    let firewall = super::firewall::startup().await;
                    app.state::<std::sync::Arc<crate::streaming::StreamManager>>()
                        .startup_firewall_status(firewall.clone())
                        .await;
                    match firewall {
                        super::firewall::FirewallOutcome::Inactive => {}
                        result => {
                            return Err(AppError::Network(format!(
                                "Windows rule startup reconciliation: {result:?}"
                            )))
                        }
                    }
                    let manager = app.state::<std::sync::Arc<super::NetworkManager>>();
                    let config = app.state::<std::sync::Arc<crate::config::AppConfig>>();
                    manager.hydrate_adoption_history(&config);
                    // A successful fresh read is required even when there are no rows.
                    interface::list_all_adapters().await?;
                    let before = interface::read_native().await?;
                    validate_recovery_settings(&config.get(), &before, &interface::RealAddressIo)?;
                    // Observe actual DNS/routes as well as addresses. Known
                    // pending intent (for example retained addresses on DHCP)
                    // must not prevent an explicit later mode correction.
                    let settings = config.get();
                    let mut owners = std::collections::BTreeSet::new();
                    if let Some(mac) = settings.selected_adapter_mac {
                        owners.insert(mac);
                    }
                    owners.extend(
                        settings
                            .pending_addresses
                            .iter()
                            .map(|r| r.adapter_mac.clone()),
                    );
                    owners.extend(
                        settings
                            .adopted_meta
                            .values()
                            .filter_map(|r| r.adapter_mac.clone()),
                    );
                    for owner in owners {
                        let adapter = interface::select_native(&before, &owner)?;
                        execute(Operation::observe(adapter)?).await?;
                    }

                    manager.load_adopted_from_config(&config, &app).await;
                    let after = interface::read_native().await?;
                    let settings = config.get();
                    validate_recovery_settings(&settings, &after, &interface::RealAddressIo)?;
                    if !settings.pending_addresses.is_empty() {
                        return Err(AppError::Network(
                            "Temporary native ownership remains unresolved".into(),
                        ));
                    }
                    Ok::<(), AppError>(())
                })
                .await;
            let state = std::mem::take(&mut *tracked.lock().unwrap());
            if result.is_ok() && !state.failed {
                state.finish(Outcome::Completed, "startup_reconciled")
            } else {
                log::warn!(
                    "Native startup recovery incomplete; conflicting writes remain blocked: {:?}",
                    result.err()
                );
                state.finish(Outcome::Uncertain, "startup_recovery_required")
            }
        })
        .map_err(admission)?;
    let completion = ticket
        .wait()
        .await
        .map_err(|_| AppError::Network("Startup recovery completion unavailable".into()))?;
    if completion.outcome == Outcome::Completed {
        log::info!("Native startup reconciliation completed; conflicting writes available");
        Ok(())
    } else {
        Err(admission(AdmissionError::ReconciliationRequired))
    }
}

pub(crate) async fn drain() {
    if NATIVE_SCOPE.try_with(|_| ()).is_ok() {
        return;
    }
    executor().wait_writer().await;
}
pub(crate) async fn shutdown() {
    executor().shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn caller_abort_after_native_success_retains_persistence_and_barrier() {
        use super::super::auto_adopt::{AdoptOps, PendingAdoptOps};
        use std::time::Duration;
        for persistence_fails in [false, true] {
            let executor = LocalExecutor::for_serialized_writers();
            executor
                .reconcile(|_| async { Completion::new(Outcome::Completed, "initial_observation") })
                .unwrap()
                .wait()
                .await
                .unwrap();
            let io = interface::address_test_io::FakeAddressIo::new(&[]);
            let config = Arc::new(crate::config::AppConfig::temporary_test_config(
                crate::config::AppSettings {
                    selected_adapter_mac: Some(io.table.lock().unwrap()[0].mac.clone()),
                    network_mode: crate::config::NetworkMode::StaticAuto,
                    ..Default::default()
                },
            ));
            let (ready, native_done) = tokio::sync::oneshot::channel();
            let (release, persist) = tokio::sync::oneshot::channel();
            let worker_io = io.clone();
            let worker_config = config.clone();
            let owned_executor = executor.clone();
            let caller = tokio::spawn(async move {
                request(
                    &owned_executor,
                    move || async move {
                        let native = worker_io.table.lock().unwrap()[0].clone();
                        let ops = PendingAdoptOps {
                            config: worker_config.as_ref(),
                            adapter_mac: &native.mac,
                            ops: super::super::AddressOps(worker_io.as_ref(), Some(&native)),
                            persist: |_| Ok(()),
                        };
                        ops.add(
                            &native.alias,
                            "192.0.2.254".parse().unwrap(),
                            "255.255.255.0",
                        )
                        .await?;
                        let mut child = Completion::new(Outcome::Completed, "native_success");
                        child.observation = Some(
                            serde_json::json!({"report":{"mutated":true},"address":"192.0.2.254"}),
                        );
                        NATIVE_SCOPE.with(|(_, state)| state.lock().unwrap().record(child, false));
                        ready.send(()).unwrap();
                        persist.await.unwrap();
                        assert!(request_canceled());
                        if persistence_fails {
                            return Err(AppError::Config(
                                "injected save failure after native success".into(),
                            ));
                        }
                        worker_io.claim(&worker_config, "192.0.2.254")
                    },
                    result_outcome,
                )
                .await
            });
            native_done.await.unwrap();
            caller.abort();
            assert!(caller.await.unwrap_err().is_cancelled());
            assert_eq!(executor.available(), Err(AdmissionError::Busy));
            // A watcher holding a manager lock can drain child-only work
            // without waiting on a managed transaction acquiring that lock.
            tokio::time::timeout(Duration::from_millis(200), executor.wait_writer())
                .await
                .unwrap();
            release.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(1), executor.wait_terminal())
                .await
                .unwrap();
            let (id, retained) = executor.retained().unwrap();
            assert_eq!(retained.observation.unwrap()["address"], "192.0.2.254");
            assert_eq!(
                retained.outcome,
                if persistence_fails {
                    Outcome::Uncertain
                } else {
                    Outcome::Completed
                }
            );
            assert_eq!(
                config.get().pending_addresses.len(),
                usize::from(persistence_fails)
            );
            assert_eq!(io.writes.lock().unwrap().len(), 1);
            assert_eq!(
                executor.available(),
                Err(AdmissionError::ReconciliationRequired)
            );
            if persistence_fails {
                assert_eq!(
                    executor.acknowledge(id),
                    Err(AdmissionError::ReconciliationRequired)
                );
            }
            executor.shutdown().await;
        }
    }

    #[test]
    fn an_ignored_native_failure_cannot_become_transaction_success() {
        let mut state = ScopeState::default();
        state.record(
            Completion::new(Outcome::Failed, "required_step_failed"),
            true,
        );
        assert_eq!(
            state
                .finish(Outcome::Completed, "parent_returned_ok")
                .outcome,
            Outcome::Uncertain
        );
    }

    #[tokio::test]
    async fn pending_absence_cannot_retire_ownership_while_native_work_is_fenced() {
        use super::super::auto_adopt::{AdoptOps, PendingAdoptOps};
        let io = interface::address_test_io::FakeAddressIo::new(&[]);
        let owner = io.table.lock().unwrap()[0].mac.clone();
        let row = crate::config::PendingAddress {
            adapter_mac: owner.clone(),
            address: "192.0.2.20".into(),
            prefix: 24,
        };
        let config = crate::config::AppConfig::temporary_test_config(crate::config::AppSettings {
            selected_adapter_mac: Some(owner.clone()),
            pending_addresses: vec![row.clone()],
            ..Default::default()
        });
        let ops = PendingAdoptOps {
            config: &config,
            adapter_mac: &owner,
            ops: super::super::AddressOps(io.as_ref(), None),
            persist: |_| Ok(()),
        };
        io.writes_blocked
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(ops
            .remove("Ethernet", "192.0.2.20".parse().unwrap())
            .await
            .is_err());
        assert_eq!(config.get().pending_addresses, vec![row]);
        assert!(io.writes.lock().unwrap().is_empty());
        io.writes_blocked
            .store(false, std::sync::atomic::Ordering::SeqCst);
        ops.remove("Ethernet", "192.0.2.20".parse().unwrap())
            .await
            .unwrap();
        assert!(config.get().pending_addresses.is_empty());
    }
    #[test]
    fn recovery_refuses_prefix_or_identity_conflicts_before_cleanup() {
        let io = interface::address_test_io::FakeAddressIo::new(&["192.0.2.20"]);
        let before = io.table.lock().unwrap().clone();
        let settings = crate::config::AppSettings {
            pending_addresses: vec![crate::config::PendingAddress {
                adapter_mac: before[0].mac.clone(),
                address: "192.0.2.20".into(),
                prefix: 24,
            }],
            ..Default::default()
        };
        validate_recovery_settings(&settings, &before, io.as_ref()).unwrap();
        let mut changed = before.clone();
        changed[0].ips[0].prefix = 25;
        assert!(validate_recovery_settings(&settings, &changed, io.as_ref()).is_err());
        changed = before;
        changed[0].guid = "replacement".into();
        assert!(validate_recovery_settings(&settings, &changed, io.as_ref()).is_err());
        assert!(io.writes.lock().unwrap().is_empty());
    }
    #[test]
    fn purpose_validation_preserves_apipa_and_point_to_point_hosts() {
        for (ip, prefix) in [("169.254.20.7", 16), ("192.0.2.0", 31), ("192.0.2.255", 32)] {
            validate_host(ip.parse().unwrap(), prefix).unwrap();
        }
        for (ip, prefix) in [
            ("0.0.0.0", 24),
            ("127.0.0.1", 8),
            ("224.0.0.1", 24),
            ("192.0.2.0", 24),
            ("192.0.2.255", 24),
            ("192.0.2.1", 0),
        ] {
            assert!(validate_host(ip.parse().unwrap(), prefix).is_err());
        }
    }
    #[test]
    fn alias_is_serialized_data_and_does_not_change_authority() {
        let mut a = NativeAdapter {
            index: 7,
            guid: "00112233-4455-6677-8899-aabbccddeeff".into(),
            mac: "40:cd:3a:00:00:01".into(),
            ..Default::default()
        };
        let identity = a.identity();
        a.alias = "a'\" ‘雪’\r\n*?[];$(bad)".into();
        assert_eq!(identity, a.identity());
        let op = Operation::address(&a, "192.0.2.20", 24, true, false).unwrap();
        let data: serde_json::Value = serde_json::from_slice(&op.payload().unwrap()).unwrap();
        assert_eq!(data["identity"]["alias"], a.alias);
        assert!(Operation::address(&a, "169.254.1.20", 24, true, true).is_err());
    }

    fn adapter() -> NativeAdapter {
        let io = interface::address_test_io::FakeAddressIo::new(&["192.0.2.10"]);
        let mut adapter = io.table.lock().unwrap()[0].clone();
        adapter.guid = "00112233-4455-6677-8899-aabbccddeeff".into();
        adapter
    }
    fn process(value: serde_json::Value, code: u32) -> ProcessResult {
        ProcessResult {
            exit_code: code,
            termination: Termination::Exited,
            stdout: super::super::native_runner::Captured {
                bytes: serde_json::to_vec(&value).unwrap(),
                ..Default::default()
            },
            stderr: Default::default(),
            observed_tree_pids: vec![123],
            observed_tree_exited: true,
            containment_verified_before_resume: true,
            elapsed: std::time::Duration::from_millis(1),
        }
    }
    #[test]
    fn partial_dns_or_route_change_retains_native_facts_and_blocks_retry() {
        let before = adapter();
        for stage in ["reset_dns", "remove_default_routes", "renew_lease"] {
            let operation = Operation::dhcp(&before).unwrap();
            let mut after = before.clone();
            after.dhcp = true;
            after.ips.clear();
            let process = process(
                serde_json::json!({"version":1,"ok":false,"stage":stage,"mutated":true,"steps":[],"data":null}),
                71,
            );
            let (completion, result) =
                evaluate_result(&operation, Some(&before), Some(&after), &process);
            assert_eq!(completion.outcome, Outcome::Uncertain);
            assert!(result.is_err());
            assert_eq!(
                completion.observation.unwrap()["native_after"]["dhcp"],
                true
            );
        }
    }
    #[test]
    fn zero_exit_without_all_composite_steps_is_not_success() {
        let mut before = adapter();
        before.dhcp = true;
        before.ips.clear();
        let operation = Operation::dhcp(&before).unwrap();
        let process = process(
            serde_json::json!({"version":1,"ok":true,"stage":"postcondition","mutated":true,
            "steps":[{"name":"postcondition","ok":true}],"data":{"dhcp":true,"addresses":[],"gateways":before.gateways,"dns":[],"dns_manual":""}}),
            0,
        );
        let (completion, result) =
            evaluate_result(&operation, Some(&before), Some(&before), &process);
        assert_eq!(completion.outcome, Outcome::Uncertain);
        assert!(result.is_err());
    }
    #[test]
    fn independent_native_read_rejects_false_success_and_replacement() {
        let before = adapter();
        let operation = Operation::address(&before, "192.0.2.20", 24, true, false).unwrap();
        let process = process(
            serde_json::json!({"version":1,"ok":true,"stage":"postcondition","mutated":true,
            "steps":[{"name":"add_address","ok":true},{"name":"postcondition","ok":true}],
            "data":{"dhcp":false,"addresses":[{"address":"192.0.2.20","prefix":24}],"gateways":[],"dns":[],"dns_manual":""}}),
            0,
        );
        for after in [
            None,
            Some(before.clone()),
            Some(NativeAdapter {
                guid: "different".into(),
                ..before.clone()
            }),
        ] {
            let (completion, result) =
                evaluate_result(&operation, Some(&before), after.as_ref(), &process);
            assert_eq!(completion.outcome, Outcome::Uncertain);
            assert!(result.is_err());
        }
    }
    #[test]
    fn canceled_single_address_effect_is_observed_but_composite_stays_uncertain() {
        let before = adapter();
        let mut after = before.clone();
        after.ips.push(interface::IpInfo {
            address: "192.0.2.20".into(),
            prefix: 24,
            subnet: String::new(),
        });
        let mut process = process(serde_json::Value::Null, 0xc000013a);
        process.termination = Termination::Canceled;
        let add = Operation::address(&before, "192.0.2.20", 24, true, false).unwrap();
        let (completion, result) = evaluate_result(&add, Some(&before), Some(&after), &process);
        assert_eq!(completion.outcome, Outcome::Completed);
        assert!(
            result.is_err(),
            "An interrupted command is never reported as a successful reply"
        );
        let primary = Operation::static_address(&before, "192.0.2.20", 24).unwrap();
        assert_eq!(
            evaluate_result(&primary, Some(&before), Some(&after), &process)
                .0
                .outcome,
            Outcome::Uncertain
        );
    }
}
