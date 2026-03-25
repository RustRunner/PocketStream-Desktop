//! Windows Firewall management for the RTSP server.
//!
//! Ensures an inbound TCP allow rule exists for the RTSP port and removes
//! any auto-generated "Query User" block rules that Windows creates when
//! the user dismisses the network access prompt.

use crate::error::AppError;

const RULE_NAME: &str = "PocketStream RTSP Server";

/// Ensure the RTSP server port is allowed through Windows Firewall.
///
/// This is idempotent — safe to call every time the server starts.
/// It also removes stale block rules that Windows auto-creates.
#[cfg(target_os = "windows")]
pub fn ensure_rtsp_allowed(port: u16) -> Result<(), AppError> {
    remove_block_rules();
    ensure_allow_rule(port)
}

#[cfg(not(target_os = "windows"))]
pub fn ensure_rtsp_allowed(_port: u16) -> Result<(), AppError> {
    Ok(())
}

/// Create the inbound TCP allow rule if it doesn't already exist.
#[cfg(target_os = "windows")]
fn ensure_allow_rule(port: u16) -> Result<(), AppError> {
    // Check if the rule already exists
    let check = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Get-NetFirewallRule -DisplayName '{}' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count",
                RULE_NAME
            ),
        ])
        .output()
        .map_err(|e| AppError::Network(format!("Failed to check firewall rule: {}", e)))?;

    let count = String::from_utf8_lossy(&check.stdout).trim().to_string();
    if count != "0" {
        // Rule exists — update the port in case it changed
        let _ = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Set-NetFirewallRule -DisplayName '{}' -LocalPort {}",
                    RULE_NAME, port
                ),
            ])
            .output();
        log::info!("Firewall rule '{}' already exists (port {})", RULE_NAME, port);
        return Ok(());
    }

    // Create the rule
    let result = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "New-NetFirewallRule -DisplayName '{}' -Direction Inbound -Protocol TCP -LocalPort {} -Action Allow -Profile Any | Out-Null",
                RULE_NAME, port
            ),
        ])
        .output()
        .map_err(|e| AppError::Network(format!("Failed to create firewall rule: {}", e)))?;

    if result.status.success() {
        log::info!("Created firewall rule '{}' for TCP port {}", RULE_NAME, port);
    } else {
        let stderr = String::from_utf8_lossy(&result.stderr);
        // Non-fatal — the server still works on localhost without the rule
        log::warn!("Could not create firewall rule (may need admin): {}", stderr.trim());
    }

    Ok(())
}

/// Remove any auto-generated "Query User" block rules for our executable.
/// Windows creates these when the user dismisses or denies the network
/// access prompt. They override explicit allow rules.
#[cfg(target_os = "windows")]
fn remove_block_rules() {
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

    match std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
    {
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
