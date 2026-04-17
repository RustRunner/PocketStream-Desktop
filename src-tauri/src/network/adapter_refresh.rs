//! Programmatic adapter refresh — forces Windows to re-probe NIC driver state.
//!
//! Two modes:
//! - `Soft`: `ipconfig /release` + `/renew`. No admin required. Fixes stale
//!   DHCP leases but does not reset the driver, so it won't un-stick a
//!   frozen PHY.
//! - `Hard`: `Restart-NetAdapter`. Full driver reset — programmatic
//!   equivalent of opening Properties and provoking a re-probe. Requires
//!   admin; tries unelevated first, then re-launches via `Start-Process
//!   -Verb RunAs` to trigger UAC.

use crate::error::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RefreshMode {
    Soft,
    Hard,
}

pub async fn refresh_adapter(interface: &str, mode: RefreshMode) -> Result<(), AppError> {
    validate_interface_name(interface)?;

    #[cfg(target_os = "windows")]
    {
        match mode {
            RefreshMode::Soft => soft_refresh_windows(interface).await,
            RefreshMode::Hard => hard_refresh_windows(interface).await,
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = mode;
        Err(AppError::Network(
            "Adapter refresh is only implemented on Windows".into(),
        ))
    }
}

fn validate_interface_name(name: &str) -> Result<(), AppError> {
    let known = super::interface::list_physical()?;
    if !known.iter().any(|i| i.name == name) {
        return Err(AppError::Network(format!(
            "Unknown network interface: {}",
            name
        )));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn soft_refresh_windows(interface: &str) -> Result<(), AppError> {
    use tokio::time::{timeout, Duration};

    // ipconfig /release — ignore non-zero exit; some adapters have no
    // lease to release but we still want to attempt the renew.
    let release = super::async_cmd("ipconfig")
        .args(["/release", interface])
        .output();
    match timeout(Duration::from_secs(15), release).await {
        Ok(Ok(out)) => {
            if !out.status.success() {
                log::info!(
                    "ipconfig /release returned {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
        }
        Ok(Err(e)) => log::warn!("ipconfig /release failed to launch: {}", e),
        Err(_) => log::warn!("ipconfig /release timed out"),
    }

    let renew = super::async_cmd("ipconfig")
        .args(["/renew", interface])
        .output();
    let out = timeout(Duration::from_secs(30), renew)
        .await
        .map_err(|_| AppError::Network("ipconfig /renew timed out after 30s".into()))?
        .map_err(|e| AppError::Network(format!("ipconfig /renew failed to launch: {}", e)))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(AppError::Network(format!(
            "ipconfig /renew failed: {}",
            stderr.trim()
        )));
    }
    log::info!("Soft-refreshed adapter '{}'", interface);
    Ok(())
}

#[cfg(target_os = "windows")]
async fn hard_refresh_windows(interface: &str) -> Result<(), AppError> {
    use tokio::time::{timeout, Duration};

    // PowerShell single-quote escaping: ' becomes ''
    let escaped = interface.replace('\'', "''");

    // Fast path: attempt without elevation. If the app was launched as
    // admin (common when netsh/IP config has been used), no UAC prompt.
    let direct_cmd = format!("Restart-NetAdapter -Name '{}' -Confirm:$false", escaped);
    let direct = super::async_cmd("powershell")
        .args(["-NoProfile", "-Command", &direct_cmd])
        .output();

    if let Ok(Ok(out)) = timeout(Duration::from_secs(30), direct).await {
        if out.status.success() {
            log::info!("Hard-refreshed adapter '{}' (unelevated)", interface);
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        log::info!(
            "Unelevated Restart-NetAdapter failed, attempting elevation: {}",
            stderr.trim()
        );
    }

    // Slow path: spawn an elevated PowerShell via `Start-Process -Verb RunAs`.
    // The user sees a UAC prompt. -Wait blocks until the elevated child exits
    // so we can tell whether the command actually ran.
    //
    // Inner quoting: we're already inside a -Command '...' block, so the
    // argument list uses doubled single quotes around the adapter name.
    let elevated_cmd = format!(
        "$ErrorActionPreference='Stop'; \
         Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait \
         -ArgumentList '-NoProfile','-Command',\
         'Restart-NetAdapter -Name ''{}'' -Confirm:$false'",
        escaped
    );
    let elevated = super::async_cmd("powershell")
        .args(["-NoProfile", "-Command", &elevated_cmd])
        .output();

    let out = timeout(Duration::from_secs(60), elevated)
        .await
        .map_err(|_| AppError::Network("Elevated refresh timed out after 60s".into()))?
        .map_err(|e| AppError::Network(format!("Failed to launch elevation: {}", e)))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // Common case: user clicked "No" on UAC → PowerShell exits with
        // "The operation was canceled by the user" on stderr.
        return Err(AppError::Network(format!(
            "Adapter reset failed (UAC may have been declined): {}",
            stderr.trim()
        )));
    }

    log::info!("Hard-refreshed adapter '{}' (elevated)", interface);
    Ok(())
}
