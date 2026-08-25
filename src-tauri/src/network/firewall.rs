//! Windows Firewall management for re-stream listeners.
//!
//! Ensures the selected protocol's inbound allow rule exists and removes any
//! auto-generated "Query User" block rules that Windows creates when the user
//! dismisses the network access prompt.

use crate::error::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallRule {
    Rtsp,
    Srt,
}

#[cfg(any(target_os = "windows", test))]
impl FirewallRule {
    fn display_name(self) -> &'static str {
        match self {
            Self::Rtsp => "PocketStream RTSP Server",
            Self::Srt => "PocketStream SRT Server",
        }
    }

    fn transport(self) -> &'static str {
        match self {
            Self::Rtsp => "TCP",
            Self::Srt => "UDP",
        }
    }
}

/// Ensure the selected re-stream port is allowed through Windows Firewall.
/// This is idempotent and safe to call every time a listener starts.
#[cfg(target_os = "windows")]
pub async fn ensure_restream_allowed(rule: FirewallRule, port: u16) -> Result<(), AppError> {
    if cfg!(test) {
        return Ok(());
    }
    remove_block_rules().await;
    ensure_allow_rule(rule, port).await
}

#[cfg(not(target_os = "windows"))]
pub async fn ensure_restream_allowed(_rule: FirewallRule, _port: u16) -> Result<(), AppError> {
    Ok(())
}

/// Run PowerShell with the same 10-second bound as interface and ARP probes.
#[cfg(target_os = "windows")]
async fn ps(script: &str) -> Result<std::process::Output, AppError> {
    let fut = super::async_cmd("powershell")
        .args(["-NoProfile", "-Command", script])
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(std::time::Duration::from_secs(10), fut).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => Err(AppError::Network(format!(
            "Failed to run PowerShell: {error}"
        ))),
        Err(_) => Err(AppError::Network("PowerShell timed out after 10s".into())),
    }
}

#[cfg(target_os = "windows")]
fn redacted_stderr(output: &std::process::Output) -> String {
    let mut summary = String::from_utf8_lossy(&output.stderr)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if let Ok(executable) = std::env::current_exe() {
        summary = summary.replace(executable.to_string_lossy().as_ref(), "<application>");
    }
    let mut chars = summary.chars();
    let truncated: String = chars.by_ref().take(512).collect();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else if truncated.is_empty() {
        "no PowerShell error details".into()
    } else {
        truncated
    }
}

#[cfg(target_os = "windows")]
fn failed_command(action: &str, output: &std::process::Output) -> AppError {
    AppError::Network(format!(
        "Firewall {action} failed (exit {:?}): {}",
        output.status.code(),
        redacted_stderr(output)
    ))
}

#[cfg(any(target_os = "windows", test))]
fn rule_count_script(rule: FirewallRule) -> String {
    format!(
        r#"$ErrorActionPreference = 'Stop'
$rules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {{ $_.DisplayName -eq '{}' }})
[Console]::Out.WriteLine($rules.Count)"#,
        rule.display_name()
    )
}

#[cfg(any(target_os = "windows", test))]
fn update_rule_script(rule: FirewallRule, port: u16) -> String {
    format!(
        r#"$ErrorActionPreference = 'Stop'
$rules = @(Get-NetFirewallRule -DisplayName '{}' -ErrorAction Stop)
$rules | Set-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -Profile Any -ErrorAction Stop
$rules | Get-NetFirewallPortFilter -ErrorAction Stop | Set-NetFirewallPortFilter -Protocol {} -LocalPort {} -ErrorAction Stop"#,
        rule.display_name(),
        rule.transport(),
        port
    )
}

#[cfg(any(target_os = "windows", test))]
fn create_rule_script(rule: FirewallRule, port: u16) -> String {
    format!(
        r#"$ErrorActionPreference = 'Stop'
New-NetFirewallRule -DisplayName '{}' -Direction Inbound -Protocol {} -LocalPort {} -Action Allow -Profile Any -ErrorAction Stop | Out-Null"#,
        rule.display_name(),
        rule.transport(),
        port
    )
}

#[cfg(target_os = "windows")]
async fn ensure_allow_rule(rule: FirewallRule, port: u16) -> Result<(), AppError> {
    // Enumerating all rules makes a missing display name an ordinary zero
    // result while ErrorAction Stop still turns provider/query failures into
    // a nonzero process result. Never blind-create after an ambiguous query.
    let check = ps(&rule_count_script(rule)).await?;
    if !check.status.success() {
        return Err(failed_command("rule query", &check));
    }
    let count = String::from_utf8_lossy(&check.stdout)
        .trim()
        .parse::<u32>()
        .map_err(|_| AppError::Network("Firewall rule query returned an invalid count".into()))?;

    let (action, output) = if count == 0 {
        ("creation", ps(&create_rule_script(rule, port)).await?)
    } else {
        ("update", ps(&update_rule_script(rule, port)).await?)
    };
    if !output.status.success() {
        return Err(failed_command(action, &output));
    }

    log::info!(
        "Firewall rule '{}' configured for {} port {}",
        rule.display_name(),
        rule.transport(),
        port
    );
    Ok(())
}

/// Remove auto-generated inbound block rules for this executable. These can
/// override an explicit allow rule after a dismissed Windows prompt.
#[cfg(target_os = "windows")]
async fn remove_block_rules() {
    let exe_path = match std::env::current_exe() {
        Ok(path) => path.to_string_lossy().to_string(),
        Err(_) => return,
    };

    let script = format!(
        r#"Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue |
           Where-Object {{ $_.DisplayName -like 'Query User*' }} |
           Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue |
           Where-Object {{ $_.Program -eq '{}' }} |
           ForEach-Object {{
               Remove-NetFirewallRule -Name $_.InstanceID -ErrorAction SilentlyContinue
           }}"#,
        exe_path.replace('\'', "''")
    );

    match ps(&script).await {
        Ok(output) if output.status.success() => {
            log::info!("Cleaned up any stale firewall block rules");
        }
        Ok(_) => log::warn!("Failed to clean up stale firewall block rules"),
        Err(error) => log::warn!("Failed to clean up firewall block rules: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_metadata_is_exact() {
        assert_eq!(
            FirewallRule::Rtsp.display_name(),
            "PocketStream RTSP Server"
        );
        assert_eq!(FirewallRule::Rtsp.transport(), "TCP");
        assert_eq!(FirewallRule::Srt.display_name(), "PocketStream SRT Server");
        assert_eq!(FirewallRule::Srt.transport(), "UDP");
    }

    #[test]
    fn rule_scripts_are_strict_and_protocol_specific() {
        let query = rule_count_script(FirewallRule::Srt);
        assert!(query.contains("$ErrorActionPreference = 'Stop'"));
        assert!(query.contains("Get-NetFirewallRule -ErrorAction Stop"));
        assert!(!query.contains("SilentlyContinue"));

        let create = create_rule_script(FirewallRule::Srt, 8_890);
        assert!(create.contains("PocketStream SRT Server"));
        assert!(create.contains("-Protocol UDP -LocalPort 8890"));
        assert!(create.contains("-ErrorAction Stop"));

        let update = update_rule_script(FirewallRule::Rtsp, 8_554);
        assert!(update.contains("PocketStream RTSP Server"));
        assert!(update.contains("Set-NetFirewallPortFilter -Protocol TCP -LocalPort 8554"));
        assert!(update.contains("-Direction Inbound -Action Allow"));
    }
}
