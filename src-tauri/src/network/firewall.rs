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
}

#[cfg(windows)]
pub(super) async fn execute(
    operation: Operation,
    cancel: super::native_runner::Cancellation,
) -> (super::local_executor::Completion, FirewallOutcome) {
    use super::native_runner::NativeProcessRunner;
    let process =
        tokio::task::spawn_blocking(move || NativeProcessRunner::run_firewall(operation, cancel))
            .await;
    match process {
        Ok(Ok(process)) => evaluate_process(process),
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
fn evaluate_process(
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
                serde_json::json!({"native":native,"report":{"stage":report.stage,"mutated":report.mutated},"records":report.records,"firewall":report.outcome}),
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
mod tests {
    use super::*;

    #[cfg(windows)]
    fn process() -> super::super::native_runner::ProcessResult {
        use super::super::native_runner::{Captured, ProcessResult, Termination};
        ProcessResult {
            exit_code: 0, termination: Termination::Exited,
            stdout: Captured { bytes: br#"{"version":2,"ok":true,"stage":"verified","mutated":false,"outcome":{"state":"inactive"},"records":[]}"#.to_vec(), ..Default::default() },
            stderr: Captured::default(), observed_tree_pids: vec![123], observed_tree_exited: true,
            containment_verified_before_resume: true, elapsed: std::time::Duration::from_secs(30),
        }
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
