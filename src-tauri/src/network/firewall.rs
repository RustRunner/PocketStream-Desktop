//! Windows Firewall management for the RTSP server.
//!
//! Ensures an inbound TCP allow rule exists for the RTSP port and removes
//! any auto-generated "Query User" block rules that Windows creates when
//! the user dismisses the network access prompt.

use crate::error::AppError;

#[cfg(target_os = "windows")]
const RULE_NAME: &str = "PocketStream RTSP Server";

/// Ensure the RTSP server port is allowed through Windows Firewall.
///
/// This is idempotent — safe to call every time the server starts.
/// It also removes stale block rules that Windows auto-creates.
#[cfg(target_os = "windows")]
pub async fn ensure_rtsp_allowed(port: u16) -> Result<(), AppError> {
    remove_block_rules().await;
    ensure_allow_rule(port).await
}

#[cfg(not(target_os = "windows"))]
pub async fn ensure_rtsp_allowed(_port: u16) -> Result<(), AppError> {
    Ok(())
}

/// Run a PowerShell script with the same 10s bound as the interface and
/// ARP probes. PowerShell/WMI queries have been observed to hang
/// indefinitely; an unbounded child here would wedge RTSP startup and
/// permanently occupy an async worker. kill_on_drop ensures the child is
/// reaped if the timeout fires and drops the future.
#[cfg(target_os = "windows")]
async fn ps(script: &str) -> Result<std::process::Output, AppError> {
    let fut = super::async_cmd("powershell")
        .args(["-NoProfile", "-Command", script])
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(std::time::Duration::from_secs(10), fut).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(e)) => Err(AppError::Network(format!(
            "Failed to run PowerShell: {}",
            e
        ))),
        Err(_) => Err(AppError::Network("PowerShell timed out after 10s".into())),
    }
}

/// Create the inbound TCP allow rule if it doesn't already exist.
#[cfg(target_os = "windows")]
async fn ensure_allow_rule(port: u16) -> Result<(), AppError> {
    // Check if the rule already exists. Parse the count as an integer,
    // and only trust it if the query actually succeeded. The old string
    // compare treated an empty / failed / noisy stdout as "rule exists"
    // (any non-"0"), which silently skipped creating the rule and left
    // RTSP blocked. A timed-out or failed query likewise lands on `None`.
    let count = match ps(&format!(
        "Get-NetFirewallRule -DisplayName '{}' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count",
        RULE_NAME
    ))
    .await
    {
        Ok(check) if check.status.success() => String::from_utf8_lossy(&check.stdout)
            .trim()
            .parse::<u32>()
            .ok(),
        Ok(_) => None,
        Err(e) => {
            log::warn!("Firewall rule check failed: {}", e);
            None
        }
    };

    match count {
        Some(n) if n > 0 => {
            // Rule exists — update the port in case it changed.
            let _ = ps(&format!(
                "Set-NetFirewallRule -DisplayName '{}' -LocalPort {}",
                RULE_NAME, port
            ))
            .await;
            log::info!(
                "Firewall rule '{}' already exists (port {})",
                RULE_NAME,
                port
            );
            return Ok(());
        }
        None => {
            // Query failed or unparseable — don't blind-create, because
            // New-NetFirewallRule duplicates a same-name rule on every
            // start. The server still works on localhost; a LAN client
            // may need a manual allow rule.
            log::warn!(
                "Could not determine firewall rule state; skipping create to avoid duplicates"
            );
            return Ok(());
        }
        Some(_) => { /* genuinely 0 — fall through and create */ }
    }

    // Create the rule
    match ps(&format!(
        "New-NetFirewallRule -DisplayName '{}' -Direction Inbound -Protocol TCP -LocalPort {} -Action Allow -Profile Any | Out-Null",
        RULE_NAME, port
    ))
    .await
    {
        Ok(result) if result.status.success() => {
            log::info!(
                "Created firewall rule '{}' for TCP port {}",
                RULE_NAME,
                port
            );
        }
        // Non-fatal — the server still works on localhost without the rule
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            log::warn!(
                "Could not create firewall rule (may need admin): {}",
                stderr.trim()
            );
        }
        Err(e) => {
            log::warn!("Could not create firewall rule (may need admin): {}", e);
        }
    }

    Ok(())
}

/// Remove any auto-generated "Query User" block rules for our executable.
/// Windows creates these when the user dismisses or denies the network
/// access prompt. They override explicit allow rules.
#[cfg(target_os = "windows")]
async fn remove_block_rules() {
    let exe_path = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().to_string(),
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
        Ok(output) => {
            if output.status.success() {
                log::info!("Cleaned up any stale firewall block rules");
            }
        }
        Err(e) => {
            log::warn!("Failed to clean up firewall block rules: {}", e);
        }
    }
}
