//! Program-scoped Windows rules. Block policy is observed and preserved.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallRule {
    Rtsp,
    Srt,
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Serialize)]
pub struct RoleDefinition {
    pub role: FirewallRule,
    pub name: &'static str,
    pub display_name: &'static str,
    pub protocol: &'static str,
    pub port: u16,
}
// The only role table. Maintenance and runtime send this same data to policy.
#[cfg(any(windows, test))]
pub const ROLES: [RoleDefinition; 2] = [
    RoleDefinition {
        role: FirewallRule::Rtsp,
        name: "PocketStream.RTSP.Inbound.v2",
        display_name: "PocketStream RTSP Server",
        protocol: "TCP",
        port: 8554,
    },
    RoleDefinition {
        role: FirewallRule::Srt,
        name: "PocketStream.SRT.Inbound.v2",
        display_name: "PocketStream SRT Server",
        protocol: "UDP",
        port: 8890,
    },
];
#[cfg(windows)]
pub const GROUP: &str = "PocketStream.Desktop.Managed.v2";

#[cfg(windows)]
pub(crate) static MAINTENANCE_OBSERVATION: std::sync::Mutex<Option<serde_json::Value>> =
    std::sync::Mutex::new(None);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum FirewallOutcome {
    #[default]
    Inactive,
    Applied {
        rule_name: String,
        action: RuleAction,
        verified_shape: bool,
        observed_block_rules: Vec<String>,
    },
    Unavailable {
        reason: String,
    },
    Failed {
        stage: String,
        reason: String,
        uncertain: bool,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Created,
    Updated,
    Unchanged,
}

#[cfg(windows)]
pub(super) const SCRIPT: &str = include_str!("firewall-policy-v2.ps1");

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Maintenance {
    Install,
    Uninstall,
}

#[cfg(windows)]
#[derive(Clone, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub(super) enum Operation {
    Startup,
    Install,
    Uninstall,
    Ensure {
        role: FirewallRule,
        port: u16,
        interface: Option<super::interface::NativeIdentity>,
    },
    Disable {
        role: FirewallRule,
    },
}
#[cfg(windows)]
impl Operation {
    fn mode(&self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Install => "install",
            Self::Uninstall => "uninstall",
            Self::Ensure { .. } => "ensure",
            Self::Disable { .. } => "disable",
        }
    }
    fn runtime_role(&self) -> Option<FirewallRule> {
        match self {
            Self::Ensure { role, .. } | Self::Disable { role } => Some(*role),
            _ => None,
        }
    }
    pub(super) fn payload(&self) -> Result<Vec<u8>, String> {
        let program = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|_| "Cannot resolve executing image".to_string())?;
        let program = program
            .to_str()
            .ok_or("Executing image path is not Unicode")?;
        let program = program.strip_prefix(r"\\?\").unwrap_or(program);
        if matches!(self, Self::Ensure { port: 0, .. }) {
            return Err("Invalid listener port".into());
        }
        serde_json::to_vec(&serde_json::json!({"version":2,"operation":self,"program":program,"group":GROUP,"roles":ROLES}))
            .map_err(|_| "Cannot encode firewall policy".into())
    }
}
#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    version: u8,
    ok: bool,
    stage: String,
    mutated: bool,
    outcome: FirewallOutcome,
    records: Vec<serde_json::Value>,
    #[serde(default)]
    timings_ms: std::collections::BTreeMap<String, u64>,
}

#[cfg(windows)]
pub(super) async fn execute(
    operation: Operation,
    cancel: super::native_runner::Cancellation,
) -> (super::local_executor::Completion, FirewallOutcome) {
    use super::native_runner::NativeProcessRunner;
    let mode = operation.mode();
    let process =
        tokio::task::spawn_blocking(move || NativeProcessRunner::run_firewall(operation, cancel))
            .await;
    match process {
        Ok(Ok(process)) => {
            let result = evaluate_process(process);
            if let Some(timings) = result
                .0
                .observation
                .as_ref()
                .and_then(|o| o.get("timings_ms"))
            {
                if let Some(total) = timings.get("total").and_then(serde_json::Value::as_u64) {
                    log::debug!("event=firewall_policy_timing mode={mode} total_ms={total} timings_ms={timings}");
                }
            }
            result
        }
        Ok(Err(error)) => {
            log::error!("event=firewall_native_setup error={error}");
            unavailable(
                "native_setup",
                "Firewall process setup failed; native recovery is required",
                None,
            )
        }
        Err(error) => {
            log::error!("event=firewall_native_task error={error}");
            unavailable(
                "native_task",
                "Firewall worker failed; native recovery is required",
                None,
            )
        }
    }
}

#[cfg(windows)]
pub(super) async fn execute_settling(
    operation: Operation,
    cancel: super::native_runner::Cancellation,
) -> (super::local_executor::Completion, FirewallOutcome) {
    execute_settling_with(operation, cancel, execute).await
}

// Focused execution seam: each attempt is the existing fixed policy/runner.
// Both follow-ups retain the parent's admission, with no recursive settlement.
#[cfg(windows)]
pub(super) async fn execute_settling_with<F, Fut>(
    operation: Operation,
    cancel: super::native_runner::Cancellation,
    mut run: F,
) -> (super::local_executor::Completion, FirewallOutcome)
where
    F: FnMut(Operation, super::native_runner::Cancellation) -> Fut,
    Fut: std::future::Future<Output = (super::local_executor::Completion, FirewallOutcome)>,
{
    use super::{local_executor::Outcome, native_runner::Cancellation};
    let (mut first, first_outcome) = run(operation.clone(), cancel.clone()).await;
    execution_evidence(&mut first, &operation, &first_outcome);
    if matches!(operation, Operation::Startup) {
        let eligible = first.step == "firewall_result_unavailable"
            && matches!(&first_outcome, FirewallOutcome::Failed { stage, .. }
            if matches!(stage.as_str(), "native_timeout" | "native_canceled" | "native_output" | "native_report"));
        if !eligible || !writers_retired(&first) || cancel.requested() {
            return (first, first_outcome);
        }
        let (mut last, outcome) = run(operation.clone(), cancel).await;
        execution_evidence(&mut last, &operation, &outcome);
        // Keep the final attempt's normal fields; the failed first attempt is
        // diagnostic only and is never recorded as a separate scope step.
        last.observation.as_mut().unwrap()["first_attempt"] = serde_json::json!(first.observation);
        log::info!(
            "event=firewall_startup_retry first_stage={} result={}",
            failure_stage(&first_outcome),
            result_label(&outcome)
        );
        return (last, outcome);
    }
    let Some(role) = operation.runtime_role() else {
        return (first, first_outcome);
    };
    if first.outcome != Outcome::Uncertain || !writers_retired(&first) {
        return (first, first_outcome);
    }
    let start = std::time::Instant::now();
    let disable = Operation::Disable { role };
    let (mut settle, settle_outcome) = run(disable.clone(), Cancellation::default()).await;
    execution_evidence(&mut settle, &disable, &settle_outcome);
    let retired = writers_retired(&settle);
    let verified = settle.outcome == Outcome::Completed
        && settle_outcome == FirewallOutcome::Inactive
        && retired;
    log::info!(
        "event=firewall_settle mode={} role={} first_stage={} settle={} elapsed_ms={}",
        operation.mode(),
        role_name(role),
        failure_stage(&first_outcome),
        result_label(&settle_outcome),
        start.elapsed().as_millis()
    );
    let outcome = if verified {
        first.step = "firewall_settled";
        if matches!(operation, Operation::Ensure { .. }) {
            first.outcome = Outcome::Failed;
            FirewallOutcome::Failed {
                stage: failure_stage(&first_outcome).into(),
                reason: format!("{}; rule verified disabled", failure_reason(&first_outcome)),
                uncertain: false,
            }
        } else {
            first.outcome = Outcome::Completed;
            FirewallOutcome::Inactive
        }
    } else {
        first_outcome
    };
    let evidence = first.observation.as_ref().unwrap()["firewall_execution"].clone();
    first.observation = Some(
        serde_json::json!({"first_attempt":first.observation,"settle":settle.observation,
        "firewall_execution":evidence,"firewall":outcome}),
    );
    first.observation.as_mut().unwrap()["firewall_execution"]["writers_retired"] =
        serde_json::json!(retired);
    (first, outcome)
}

#[cfg(windows)]
fn role_name(role: FirewallRule) -> &'static str {
    match role {
        FirewallRule::Rtsp => "rtsp",
        FirewallRule::Srt => "srt",
    }
}
#[cfg(windows)]
fn failure_stage(outcome: &FirewallOutcome) -> &str {
    match outcome {
        FirewallOutcome::Failed { stage, .. } => stage,
        _ => "firewall_recovery",
    }
}
#[cfg(windows)]
fn failure_reason(outcome: &FirewallOutcome) -> &str {
    match outcome {
        FirewallOutcome::Failed { reason, .. } | FirewallOutcome::Unavailable { reason } => reason,
        _ => "Firewall retirement was not verified",
    }
}
#[cfg(windows)]
fn result_label(outcome: &FirewallOutcome) -> &'static str {
    match outcome {
        FirewallOutcome::Inactive => "inactive",
        FirewallOutcome::Failed {
            uncertain: true, ..
        } => "uncertain",
        _ => "failed",
    }
}

#[cfg(windows)]
fn execution_evidence(
    completion: &mut super::local_executor::Completion,
    operation: &Operation,
    outcome: &FirewallOutcome,
) {
    let mut observation = completion
        .observation
        .take()
        .unwrap_or_else(|| serde_json::json!({}));
    let native = observation.get("native").unwrap_or(&observation);
    let retired = native["contained"] == true && native["tree_exited"] == true;
    observation["firewall_execution"] = serde_json::json!({"mode":operation.mode(),
        "role":operation.runtime_role().map(role_name),"writers_retired":retired});
    observation["firewall"] = serde_json::json!(outcome);
    completion.observation = Some(observation);
}
#[cfg(windows)]
fn writers_retired(completion: &super::local_executor::Completion) -> bool {
    completion
        .observation
        .as_ref()
        .is_some_and(|o| o["firewall_execution"]["writers_retired"] == true)
}

#[cfg(windows)]
pub(super) fn recovery_eligible(
    completion: &super::local_executor::Completion,
    role: FirewallRule,
) -> bool {
    use super::local_executor::Outcome;
    completion.outcome == Outcome::Uncertain
        && matches!(
            completion.step,
            "firewall_result_unavailable" | "firewall_policy"
        )
        && writers_retired(completion)
        && completion.observation.as_ref().is_some_and(|o| {
            o["firewall_execution"]["role"] == role_name(role)
                && matches!(
                    o["firewall_execution"]["mode"].as_str(),
                    Some("ensure" | "disable")
                )
        })
}

#[cfg(windows)]
pub(super) fn finish_recovery(
    mut original: super::local_executor::Completion,
    (mut latest, outcome): (super::local_executor::Completion, FirewallOutcome),
) -> (super::local_executor::Completion, FirewallOutcome) {
    use super::local_executor::Outcome;
    let retired = writers_retired(&original) && writers_retired(&latest);
    if latest.outcome == Outcome::Completed && outcome == FirewallOutcome::Inactive && retired {
        latest.observation.as_mut().unwrap()["recovered"] = serde_json::json!(original.observation);
        return (latest, outcome);
    }
    let prior = original.observation.take().unwrap();
    // Replace the latest failure rather than recursively retaining recoveries.
    let unresolved = prior.get("unresolved").unwrap_or(&prior);
    let result = FirewallOutcome::Failed {
        stage: "firewall_recovery".into(),
        reason: format!(
            "{}; recovery did not verify retirement: {}",
            unresolved["firewall"]["reason"]
                .as_str()
                .unwrap_or("Unresolved firewall operation")
                .chars()
                .take(384)
                .collect::<String>(),
            failure_reason(&outcome)
                .chars()
                .take(384)
                .collect::<String>()
        ),
        uncertain: true,
    };
    let mut evidence = prior["firewall_execution"].clone();
    evidence["writers_retired"] = serde_json::json!(retired);
    original.outcome = Outcome::Uncertain;
    original.observation = Some(
        serde_json::json!({"unresolved":unresolved,"latest_recovery":latest.observation,
        "firewall_execution":evidence,"firewall":result}),
    );
    (original, result)
}

#[cfg(windows)]
fn unavailable(
    stage: &str,
    reason: &str,
    observation: Option<serde_json::Value>,
) -> (super::local_executor::Completion, FirewallOutcome) {
    use super::local_executor::{Completion, Outcome};
    let mut completion = Completion::new(Outcome::Uncertain, "firewall_result_unavailable");
    completion.observation = observation;
    (
        completion,
        FirewallOutcome::Failed {
            stage: stage.into(),
            reason: reason.into(),
            uncertain: true,
        },
    )
}

#[cfg(windows)]
pub(super) fn evaluate_process(
    p: super::native_runner::ProcessResult,
) -> (super::local_executor::Completion, FirewallOutcome) {
    use super::local_executor::{Completion, Outcome};
    use super::native_runner::Termination;
    log::info!(
        "event=firewall_native_result exit={} termination={:?} elapsed_ms={} contained={} tree_exited={} stdout_truncated={} stderr_truncated={} stdout_read_failed={} stderr_read_failed={}",
        p.exit_code, p.termination, p.elapsed.as_millis(), p.containment_verified_before_resume,
        p.observed_tree_exited, p.stdout.truncated, p.stderr.truncated, p.stdout.read_failed, p.stderr.read_failed
    );
    let native = serde_json::json!({"exit_code":p.exit_code,"termination":format!("{:?}",p.termination),
        "elapsed_ms":p.elapsed.as_millis(),"contained":p.containment_verified_before_resume,"tree_exited":p.observed_tree_exited,
        "stdout_truncated":p.stdout.truncated,"stderr_truncated":p.stderr.truncated,
        "stdout_read_failed":p.stdout.read_failed,"stderr_read_failed":p.stderr.read_failed});
    let failure = match p.termination {
        Termination::TimedOut => Some((
            "native_timeout",
            "Firewall policy timed out; native recovery is required",
        )),
        Termination::Canceled => Some((
            "native_canceled",
            "Firewall policy was canceled; native recovery is required",
        )),
        Termination::Exited if !p.observed_tree_exited || !p.containment_verified_before_resume => {
            Some((
                "native_containment",
                "Firewall process containment is unverified; native recovery is required",
            ))
        }
        Termination::Exited
            if p.stdout.truncated
                || p.stderr.truncated
                || p.stdout.read_failed
                || p.stderr.read_failed =>
        {
            Some((
                "native_output",
                "Firewall output was incomplete; native recovery is required",
            ))
        }
        Termination::Exited => None,
    };
    if let Some((stage, reason)) = failure {
        return unavailable(stage, reason, Some(native));
    }
    let parsed = serde_json::from_slice::<Report>(&p.stdout.bytes)
        .ok()
        .filter(|report| {
            report.version == 2
                && report.ok == (p.exit_code == 0)
                && report.stage.len() <= 64
                && report.records.len() <= 64
                && report.timings_ms.len() <= 16
                && report.timings_ms.keys().all(|key| key.len() <= 64)
                && report.ok
                    == matches!(
                        report.outcome,
                        FirewallOutcome::Applied {
                            verified_shape: true,
                            ..
                        } | FirewallOutcome::Inactive
                    )
        });
    match parsed {
        Some(report) => {
            for record in &report.records {
                if let Some(name) = record
                    .get("repaired_template")
                    .or_else(|| record.get("defective_template"))
                {
                    log::info!(
                        "event=firewall_template_repair role={} prior_package={}",
                        name.as_str().unwrap_or_default(),
                        record["prior_package"].as_str().unwrap_or_default()
                    );
                }
            }
            let uncertain = matches!(
                report.outcome,
                FirewallOutcome::Failed {
                    uncertain: true,
                    ..
                }
            );
            let mut completion = Completion::new(
                if uncertain {
                    Outcome::Uncertain
                } else if report.ok {
                    Outcome::Completed
                } else {
                    Outcome::Failed
                },
                "firewall_policy",
            );
            completion.observation = Some(
                serde_json::json!({"native":native,"report":{"stage":report.stage,"mutated":report.mutated},"records":report.records,"firewall":report.outcome,"timings_ms":report.timings_ms}),
            );
            (completion, report.outcome)
        }
        None => unavailable(
            "native_report",
            "Firewall report was invalid; native recovery is required",
            Some(native),
        ),
    }
}
#[cfg(windows)]
pub(crate) async fn startup() -> FirewallOutcome {
    super::native_operations::firewall_request(Operation::Startup, false).await
}
#[cfg(windows)]
pub(crate) async fn maintenance(mode: Maintenance) -> FirewallOutcome {
    super::native_operations::firewall_request(
        match mode {
            Maintenance::Install => Operation::Install,
            Maintenance::Uninstall => Operation::Uninstall,
        },
        true,
    )
    .await
}
pub(crate) async fn ensure(
    rule: FirewallRule,
    port: u16,
    interface: Option<super::interface::NativeIdentity>,
) -> FirewallOutcome {
    #[cfg(all(windows, not(test)))]
    {
        super::native_operations::firewall_request(
            Operation::Ensure {
                role: rule,
                port,
                interface,
            },
            false,
        )
        .await
    }
    #[cfg(any(not(windows), test))]
    {
        let _ = (rule, port, interface);
        FirewallOutcome::Unavailable {
            reason: "Windows firewall automation is unavailable on this platform".into(),
        }
    }
}
pub(crate) async fn disable(rule: FirewallRule) -> FirewallOutcome {
    #[cfg(all(windows, not(test)))]
    {
        super::native_operations::firewall_request(Operation::Disable { role: rule }, false).await
    }
    #[cfg(any(not(windows), test))]
    {
        let _ = rule;
        FirewallOutcome::Inactive
    }
}
#[cfg(test)]
pub(super) mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn report_timings_are_optional_bounded_and_strict() {
        let mut p = process();
        let mut report: serde_json::Value = serde_json::from_slice(&p.stdout.bytes).unwrap();
        report["timings_ms"] = serde_json::json!({"input":0,"prepare":12,"total":30});
        p.stdout.bytes = serde_json::to_vec(&report).unwrap();
        assert_eq!(evaluate_process(p).1, FirewallOutcome::Inactive);
        for timings in [
            serde_json::json!({"input":-1}),
            serde_json::json!({"input":1.5}),
            serde_json::to_value(
                (0..17)
                    .map(|i| (i.to_string(), 0))
                    .collect::<std::collections::BTreeMap<_, _>>(),
            )
            .unwrap(),
        ] {
            let mut p = process();
            report["timings_ms"] = timings;
            p.stdout.bytes = serde_json::to_vec(&report).unwrap();
            assert!(matches!(
                evaluate_process(p).1,
                FirewallOutcome::Failed {
                    uncertain: true,
                    ..
                }
            ));
        }
        let mut p = process();
        report.as_object_mut().unwrap().remove("timings_ms");
        report["unknown"] = serde_json::json!(true);
        p.stdout.bytes = serde_json::to_vec(&report).unwrap();
        assert!(matches!(
            evaluate_process(p).1,
            FirewallOutcome::Failed {
                uncertain: true,
                ..
            }
        ));
    }

    #[cfg(windows)]
    pub(in crate::network) fn process() -> super::super::native_runner::ProcessResult {
        use super::super::native_runner::{Captured, ProcessResult, Termination};
        ProcessResult {
            exit_code: 0, termination: Termination::Exited,
            stdout: Captured { bytes: br#"{"version":2,"ok":true,"stage":"verified","mutated":false,"outcome":{"state":"inactive"},"records":[]}"#.to_vec(), ..Default::default() },
            stderr: Captured::default(), observed_tree_pids: vec![123], observed_tree_exited: true,
            containment_verified_before_resume: true, elapsed: std::time::Duration::from_secs(30),
        }
    }

    #[cfg(windows)]
    fn failed_process(uncertain: bool) -> super::super::native_runner::ProcessResult {
        let mut p = process();
        p.exit_code = 71;
        p.stdout.bytes = serde_json::to_vec(&serde_json::json!({"version":2,"ok":false,"stage":"access","mutated":false,
            "outcome":{"state":"failed","stage":"access","reason":"provider failure","uncertain":uncertain},"records":[]})).unwrap();
        p
    }

    #[cfg(windows)]
    async fn scripted(
        operation: Operation,
        cancel: super::super::native_runner::Cancellation,
        mut processes: Vec<Result<super::super::native_runner::ProcessResult, ()>>,
    ) -> (
        (super::super::local_executor::Completion, FirewallOutcome),
        Vec<(String, bool)>,
    ) {
        let mut calls = Vec::new();
        let result = execute_settling_with(operation, cancel, |op, cancel| {
            calls.push((op.mode().to_string(), cancel.requested()));
            std::future::ready(match processes.remove(0) {
                Ok(p) => evaluate_process(p),
                Err(()) => unavailable("native_setup", "Unknown writer lifetime", None),
            })
        })
        .await;
        (result, calls)
    }

    #[cfg(windows)]
    fn ensure_operation() -> Operation {
        Operation::Ensure {
            role: FirewallRule::Rtsp,
            port: 8554,
            interface: None,
        }
    }

    #[cfg(windows)]
    fn timed_out() -> super::super::native_runner::ProcessResult {
        let mut p = process();
        p.termination = super::super::native_runner::Termination::TimedOut;
        p
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn runtime_timeouts_settle_once_for_the_same_role_with_a_fresh_token() {
        use super::super::{local_executor::Outcome, native_runner::Cancellation};
        for operation in [
            ensure_operation(),
            Operation::Disable {
                role: FirewallRule::Rtsp,
            },
        ] {
            let ensure = matches!(operation, Operation::Ensure { .. });
            let cancel = Cancellation::default();
            cancel.request();
            let ((completion, outcome), calls) =
                scripted(operation, cancel, vec![Ok(timed_out()), Ok(process())]).await;
            assert_eq!(
                calls,
                vec![
                    (if ensure { "ensure" } else { "disable" }.into(), true),
                    ("disable".into(), false)
                ]
            );
            assert_eq!(completion.step, "firewall_settled");
            assert_eq!(
                completion.outcome,
                if ensure {
                    Outcome::Failed
                } else {
                    Outcome::Completed
                }
            );
            assert!(writers_retired(&completion));
            if ensure {
                assert!(matches!(
                    outcome,
                    FirewallOutcome::Failed {
                        uncertain: false,
                        ..
                    }
                ));
            } else {
                assert_eq!(outcome, FirewallOutcome::Inactive);
            }
            let evidence = completion.observation.unwrap();
            assert_eq!(evidence["first_attempt"]["termination"], "TimedOut");
            assert_eq!(evidence["settle"]["native"]["termination"], "Exited");
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn failed_settle_retains_the_original_cause_and_all_writer_evidence() {
        use super::super::native_runner::Cancellation;
        for retired in [true, false] {
            let mut settle = timed_out();
            settle.observed_tree_exited = retired;
            let ((completion, outcome), calls) = scripted(
                ensure_operation(),
                Cancellation::default(),
                vec![Ok(timed_out()), Ok(settle)],
            )
            .await;
            assert_eq!(calls.len(), 2);
            assert!(
                matches!(outcome, FirewallOutcome::Failed { stage, uncertain:true, .. } if stage == "native_timeout")
            );
            assert_eq!(recovery_eligible(&completion, FirewallRule::Rtsp), retired);
            assert!(!recovery_eligible(&completion, FirewallRule::Srt));
            let evidence = completion.observation.unwrap();
            assert_eq!(evidence["settle"]["tree_exited"], retired);
            assert_eq!(evidence["first_attempt"]["termination"], "TimedOut");
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn unknown_writer_lifetime_never_dispatches_a_followup() {
        use super::super::native_runner::{Cancellation, Termination};
        for termination in [
            Termination::TimedOut,
            Termination::Canceled,
            Termination::Exited,
        ] {
            for missing in [0, 1, 2] {
                for operation in [ensure_operation(), Operation::Startup] {
                    let mut p = process();
                    p.termination = termination;
                    if missing == 0 {
                        p.containment_verified_before_resume = false;
                    }
                    if missing == 1 {
                        p.observed_tree_exited = false;
                    }
                    let first = if missing == 2 { Err(()) } else { Ok(p) };
                    let ((completion, _), calls) =
                        scripted(operation, Cancellation::default(), vec![first]).await;
                    assert_eq!(calls.len(), 1);
                    assert!(!writers_retired(&completion));
                    assert!(!recovery_eligible(&completion, FirewallRule::Rtsp));
                }
            }
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn only_uncertain_runtime_policy_failures_get_one_settle() {
        use super::super::{local_executor::Outcome, native_runner::Cancellation};
        for uncertain in [true, false] {
            let ((completion, _), calls) = scripted(
                ensure_operation(),
                Cancellation::default(),
                vec![Ok(failed_process(uncertain)), Ok(failed_process(true))],
            )
            .await;
            assert_eq!(calls.len(), if uncertain { 2 } else { 1 });
            assert_eq!(
                completion.outcome,
                if uncertain {
                    Outcome::Uncertain
                } else {
                    Outcome::Failed
                }
            );
        }
        for operation in [Operation::Install, Operation::Uninstall] {
            let (_, calls) =
                scripted(operation, Cancellation::default(), vec![Ok(timed_out())]).await;
            assert_eq!(calls.len(), 1);
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn startup_retries_only_eligible_process_failures_and_keeps_final_fields() {
        use super::super::native_runner::{Cancellation, Termination};
        for case in 0..4 {
            let mut p = process();
            match case {
                0 => p.termination = Termination::TimedOut,
                1 => p.termination = Termination::Canceled,
                2 => p.stdout.truncated = true,
                _ => p.stdout.bytes = b"invalid JSON".to_vec(),
            }
            let ((completion, outcome), calls) = scripted(
                Operation::Startup,
                Cancellation::default(),
                vec![Ok(p), Ok(process())],
            )
            .await;
            assert_eq!(calls.len(), 2);
            assert_eq!(outcome, FirewallOutcome::Inactive);
            let evidence = completion.observation.unwrap();
            assert_eq!(evidence["report"]["stage"], "verified");
            assert!(evidence.get("first_attempt").is_some());
            assert!(!recovery_eligible(
                &super::super::local_executor::Completion {
                    observation: Some(evidence),
                    ..completion
                },
                FirewallRule::Rtsp
            ));
        }
        let (_, calls) = scripted(
            Operation::Startup,
            Cancellation::default(),
            vec![Ok(failed_process(false))],
        )
        .await;
        assert_eq!(calls.len(), 1);
        let mut policy = failed_process(true);
        let mut report: serde_json::Value = serde_json::from_slice(&policy.stdout.bytes).unwrap();
        report["outcome"]["stage"] = serde_json::json!("native_timeout");
        policy.stdout.bytes = serde_json::to_vec(&report).unwrap();
        let (_, calls) = scripted(
            Operation::Startup,
            Cancellation::default(),
            vec![Ok(policy)],
        )
        .await;
        assert_eq!(calls.len(), 1, "policy failures are never process retries");
        let cancel = Cancellation::default();
        cancel.request();
        let (_, calls) = scripted(Operation::Startup, cancel, vec![Ok(timed_out())]).await;
        assert_eq!(calls.len(), 1);
        let ((completion, _), calls) = scripted(
            Operation::Startup,
            Cancellation::default(),
            vec![Ok(timed_out()), Ok(timed_out())],
        )
        .await;
        assert_eq!(calls.len(), 2);
        assert_eq!(
            completion.outcome,
            super::super::local_executor::Outcome::Uncertain
        );
        assert!(completion
            .observation
            .unwrap()
            .get("first_attempt")
            .is_some());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn startup_second_attempt_honors_original_cancellation() {
        use super::super::native_runner::{Cancellation, Termination};
        let original = Cancellation::default();
        let mut calls = 0;
        let (_, outcome) =
            execute_settling_with(Operation::Startup, original.clone(), |_, token| {
                calls += 1;
                let p = if calls == 1 {
                    timed_out()
                } else {
                    original.request();
                    assert!(token.requested());
                    let mut p = process();
                    p.termination = Termination::Canceled;
                    p
                };
                std::future::ready(evaluate_process(p))
            })
            .await;
        assert_eq!(calls, 2);
        assert!(
            matches!(outcome, FirewallOutcome::Failed {stage, uncertain:true,..} if stage=="native_canceled")
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn abandoned_requester_still_settles_but_retains_acknowledgement_barrier() {
        use super::super::local_executor::{AdmissionError, Completion, LocalExecutor, Outcome};
        let executor = LocalExecutor::for_serialized_writers();
        executor
            .reconcile(|_| async { Completion::new(Outcome::Completed, "ready") })
            .unwrap()
            .wait()
            .await
            .unwrap();
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (release, wait) = tokio::sync::oneshot::channel();
        let ticket = executor
            .submit(|cancel| async move {
                entered.send(()).unwrap();
                wait.await.unwrap();
                let ((completion, _), calls) = scripted(
                    ensure_operation(),
                    cancel,
                    vec![Ok(timed_out()), Ok(process())],
                )
                .await;
                assert_eq!(
                    calls,
                    vec![("ensure".into(), true), ("disable".into(), false)]
                );
                completion
            })
            .unwrap();
        waiting.await.unwrap();
        drop(ticket);
        release.send(()).unwrap();
        executor.wait_terminal().await;
        let (_, retained) = executor.retained().unwrap();
        assert_eq!(retained.outcome, Outcome::Failed);
        assert!(writers_retired(&retained));
        assert!(!recovery_eligible(&retained, FirewallRule::Rtsp));
        assert_eq!(
            executor.available(),
            Err(AdmissionError::ReconciliationRequired)
        );
    }

    #[cfg(windows)]
    #[test]
    fn killed_firewall_result_retains_uncertainty_and_actual_termination() {
        use super::super::{local_executor::Outcome, native_runner::Termination};
        for (termination, stage) in [
            (Termination::TimedOut, "native_timeout"),
            (Termination::Canceled, "native_canceled"),
        ] {
            let mut p = process();
            p.termination = termination;
            // Even a buffered successful report cannot account for killed work.
            let (completion, result) = evaluate_process(p);
            assert_eq!(completion.outcome, Outcome::Uncertain);
            assert!(
                matches!(result, FirewallOutcome::Failed { stage:s, uncertain:true,.. } if s == stage)
            );
            assert_eq!(
                completion.observation.unwrap()["termination"],
                format!("{termination:?}")
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn invalid_or_incomplete_firewall_evidence_never_becomes_reconciled() {
        use super::super::local_executor::Outcome;
        for case in 0..8 {
            let mut p = process();
            match case {
                0 => p.stdout.bytes = b"not JSON".to_vec(),
                1 => p.exit_code = 71,
                2 => p.observed_tree_exited = false,
                3 => p.containment_verified_before_resume = false,
                4 => p.stdout.truncated = true,
                5 => p.stderr.truncated = true,
                6 => p.stdout.read_failed = true,
                _ => p.stderr.read_failed = true,
            }
            let (completion, result) = evaluate_process(p);
            assert_eq!(completion.outcome, Outcome::Uncertain, "case {case}");
            assert!(matches!(
                result,
                FirewallOutcome::Failed {
                    uncertain: true,
                    ..
                }
            ));
        }
    }

    #[cfg(windows)]
    #[test]
    fn verified_firewall_report_preserves_completion_and_policy_failure() {
        use super::super::local_executor::Outcome;
        let (completion, result) = evaluate_process(process());
        assert_eq!(completion.outcome, Outcome::Completed);
        assert_eq!(result, FirewallOutcome::Inactive);
        for uncertain in [false, true] {
            let mut p = process();
            p.exit_code = 71;
            p.stdout.bytes=serde_json::to_vec(&serde_json::json!({"version":2,"ok":false,"stage":"disable","mutated":true,
                "outcome":{"state":"failed","stage":"disable","reason":"provider failed","uncertain":uncertain},"records":[]})).unwrap();
            let (completion, result) = evaluate_process(p);
            assert_eq!(
                completion.outcome,
                if uncertain {
                    Outcome::Uncertain
                } else {
                    Outcome::Failed
                }
            );
            assert!(matches!(result,FirewallOutcome::Failed{stage,..} if stage=="disable"));
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn firewall_timeout_blocks_address_admission_until_verified_reconciliation() {
        use super::super::{
            local_executor::{AdmissionError, LocalExecutor, Outcome},
            native_runner::Termination,
        };
        let executor = LocalExecutor::for_serialized_writers();
        let pending = executor
            .reconcile(|_| async {
                let mut p = process();
                p.termination = Termination::TimedOut;
                evaluate_process(p).0
            })
            .unwrap();
        let id = pending.id;
        assert_eq!(pending.wait().await.unwrap().outcome, Outcome::Uncertain);
        assert_eq!(
            executor.available(),
            Err(AdmissionError::ReconciliationRequired)
        );
        assert_eq!(
            executor.acknowledge(id),
            Err(AdmissionError::ReconciliationRequired)
        );
        let (verified, _) = evaluate_process(process());
        executor
            .reconcile(|_| async move { verified })
            .unwrap()
            .wait()
            .await
            .unwrap();
        assert_eq!(executor.available(), Ok(()));
    }
    #[test]
    fn roles_and_wire_tags_are_stable() {
        assert_eq!(ROLES[0].name, "PocketStream.RTSP.Inbound.v2");
        assert_eq!((ROLES[1].protocol, ROLES[1].port), ("UDP", 8890));
        let applied = FirewallOutcome::Applied {
            rule_name: ROLES[0].name.into(),
            action: RuleAction::Updated,
            verified_shape: true,
            observed_block_rules: vec!["Query User deny".into()],
        };
        let wire = serde_json::to_value(&applied).unwrap();
        assert_eq!(wire["state"], "applied");
        assert_eq!(wire["action"], "updated");
        assert_eq!(
            serde_json::from_value::<FirewallOutcome>(wire).unwrap(),
            applied
        );
    }

    #[cfg(windows)]
    #[test]
    fn fixed_payloads_never_turn_aliases_into_source() {
        let identity = super::super::interface::NativeIdentity {
            guid: "01234567-89ab-cdef-0123-456789abcdef".into(),
            index: 15,
            mac: "00:11:22:33:44:55".into(),
            alias: "O'Brien \"Wi-Fi\" ‘日本語’\r\n".into(),
        };
        let operation = Operation::Ensure {
            role: FirewallRule::Srt,
            port: 8890,
            interface: Some(identity.clone()),
        };
        let payload: serde_json::Value =
            serde_json::from_slice(&operation.payload().unwrap()).unwrap();
        assert_eq!(payload["operation"]["interface"]["alias"], identity.alias);
        assert_eq!(payload["roles"][1]["name"], ROLES[1].name);
        assert!(!SCRIPT.contains(&identity.alias));
        assert!(Operation::Ensure {
            role: FirewallRule::Rtsp,
            port: 0,
            interface: None
        }
        .payload()
        .is_err());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &Operation::Disable {
                    role: FirewallRule::Rtsp
                }
                .payload()
                .unwrap()
            )
            .unwrap()["operation"]["mode"],
            "disable"
        );
    }
}
