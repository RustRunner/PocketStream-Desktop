//! Program-scoped Windows rules. Block policy is observed and preserved.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallRule {
    Rtsp,
    Srt,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoleDefinition {
    pub role: FirewallRule,
    pub name: &'static str,
    pub display_name: &'static str,
    pub protocol: &'static str,
    pub port: u16,
}
// The only role table. Maintenance and runtime send this same data to policy.
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
    use super::local_executor::{Completion, Outcome};
    use super::native_runner::{NativeProcessRunner, Termination};
    let process =
        tokio::task::spawn_blocking(move || NativeProcessRunner::run_firewall(operation, cancel))
            .await;
    let parsed = process.ok().and_then(Result::ok).and_then(|p| {
        if p.termination != Termination::Exited
            || !p.observed_tree_exited
            || p.stdout.truncated
            || p.stderr.truncated
            || p.stdout.read_failed
            || p.stderr.read_failed
        {
            return None;
        }
        let report: Report = serde_json::from_slice(&p.stdout.bytes).ok()?;
        (report.version == 2
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
                ))
        .then_some(report)
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
                serde_json::json!({"report":{"stage":report.stage,"mutated":report.mutated},"records":report.records,"firewall":report.outcome}),
            );
            (completion, report.outcome)
        }
        None => (
            Completion::new(Outcome::Uncertain, "firewall_result_unavailable"),
            FirewallOutcome::Failed {
                stage: "native_result".into(),
                reason:
                    "Firewall result unavailable; restart with administrator access to reconcile"
                        .into(),
                uncertain: true,
            },
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
