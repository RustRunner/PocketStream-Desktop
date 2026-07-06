use std::net::Ipv4Addr;

use crate::error::AppError;

/// Assign a static IP address to a network interface.
///
/// `preserve_secondaries` are addresses (e.g. adopted rescue IPs) that
/// must survive the set — the primary set wipes every address on the
/// adapter, so any of these still present get re-added afterward.
///
/// Platform-specific implementation:
/// - Windows: uses `netsh interface ip set address`
/// - Linux: uses `ip addr` commands
pub async fn assign_static_ip(
    interface: &str,
    ip: &str,
    subnet_mask: &str,
    gateway: Option<&str>,
    preserve_secondaries: &[Ipv4Addr],
) -> Result<(), AppError> {
    super::interface::validate_interface_name(interface).await?;
    validate_ip(ip)?;
    validate_ip(subnet_mask)?;
    if let Some(gw) = gateway {
        validate_ip(gw)?;
    }

    #[cfg(target_os = "windows")]
    {
        assign_windows(interface, ip, subnet_mask, gateway, preserve_secondaries).await
    }

    #[cfg(target_os = "linux")]
    {
        let _ = preserve_secondaries;
        assign_linux(interface, ip, subnet_mask, gateway).await
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = preserve_secondaries;
        Err(AppError::Network("Unsupported platform".into()))
    }
}

#[cfg(target_os = "windows")]
async fn assign_windows(
    interface: &str,
    ip: &str,
    subnet_mask: &str,
    gateway: Option<&str>,
    preserve_secondaries: &[Ipv4Addr],
) -> Result<(), AppError> {
    // Snapshot BEFORE the set. Propagate a snapshot failure instead of
    // treating it as an empty adapter: the old unwrap_or_default() would
    // then re-add nothing, silently wiping every secondary (including the
    // adopted rescue IP) when the set below replaces all addresses.
    let info = super::interface::get_by_name(interface).await?;

    // Choose which addresses to re-add by explicit membership in the
    // preserve set — NOT by position. Enumeration order isn't guaranteed
    // (so `.skip(1)` could re-add the real primary as a secondary), and
    // PrefixOrigin marks adopted and user statics both Manual, so origin
    // can't classify them either. The new primary is excluded.
    let to_restore: Vec<super::interface::IpInfo> = info
        .ips
        .into_iter()
        .filter(|sec| {
            sec.address != ip
                && sec
                    .address
                    .parse::<Ipv4Addr>()
                    .map(|a| preserve_secondaries.contains(&a))
                    .unwrap_or(false)
        })
        .collect();

    // Set primary static IP (replaces all existing IPs)
    let mut args = vec![
        "interface",
        "ip",
        "set",
        "address",
        interface,
        "static",
        ip,
        subnet_mask,
    ];
    if let Some(gw) = gateway {
        args.push(gw);
    }
    run_command("netsh", &args).await?;

    // Re-add the preserved secondaries wiped by the set (in parallel).
    // netsh add works here because the interface is now static.
    let mut tasks = Vec::new();
    for sec in &to_restore {
        let mask = prefix_to_mask(sec.prefix);
        let iface = interface.to_string();
        let addr = sec.address.clone();
        tasks.push(tokio::spawn(async move {
            let name_arg = format!("name={}", iface);
            if let Err(e) = run_command(
                "netsh",
                &["interface", "ip", "add", "address", &name_arg, &addr, &mask],
            )
            .await
            {
                log::warn!("Failed to restore secondary IP {}: {}", addr, e);
            }
        }));
    }
    for task in tasks {
        let _ = task.await;
    }

    Ok(())
}

/// Convert a CIDR prefix length to a dotted subnet mask.
#[cfg(target_os = "windows")]
fn prefix_to_mask(prefix: u8) -> String {
    let bits: u32 = if prefix >= 32 {
        0xFFFFFFFF
    } else {
        0xFFFFFFFF << (32 - prefix)
    };
    let o = bits.to_be_bytes();
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

#[cfg(target_os = "linux")]
async fn assign_linux(
    interface: &str,
    ip: &str,
    subnet_mask: &str,
    gateway: Option<&str>,
) -> Result<(), AppError> {
    let prefix = mask_to_prefix(subnet_mask)?;
    let cidr = format!("{}/{}", ip, prefix);

    // Flush existing addresses
    run_command("ip", &["addr", "flush", "dev", interface]).await?;

    // Add new address
    run_command("ip", &["addr", "add", &cidr, "dev", interface]).await?;

    // Set link up
    run_command("ip", &["link", "set", interface, "up"]).await?;

    // Add default gateway if provided
    if let Some(gw) = gateway {
        // Ignore error if route already exists
        let _ = run_command(
            "ip",
            &["route", "add", "default", "via", gw, "dev", interface],
        )
        .await;
    }

    Ok(())
}

pub(crate) async fn run_command(program: &str, args: &[&str]) -> Result<String, AppError> {
    let output = super::async_cmd(program)
        .args(args)
        .output()
        .await
        .map_err(|e| AppError::Network(format!("Failed to run {}: {}", program, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let msg = if stderr.trim().is_empty() {
            stdout
        } else {
            stderr
        };
        return Err(AppError::Network(format!(
            "{} failed: {}",
            program,
            msg.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn validate_ip(ip: &str) -> Result<(), AppError> {
    ip.parse::<std::net::Ipv4Addr>()
        .map_err(|_| AppError::Network(format!("Invalid IP address: {}", ip)))?;
    Ok(())
}

fn mask_to_prefix(mask: &str) -> Result<u8, AppError> {
    let addr: std::net::Ipv4Addr = mask
        .parse()
        .map_err(|_| AppError::Network(format!("Invalid subnet mask: {}", mask)))?;
    let bits: u32 = u32::from(addr);
    Ok(bits.count_ones() as u8)
}

/// Add a secondary IP address to an interface (preserves existing IPs).
///
/// Windows uses `New-NetIPAddress`, not `netsh interface ip add address`:
/// netsh refuses to add an IP on a DHCP-enabled adapter, which is exactly
/// the APIPA-rescue case (a camera dropped to 169.254/16 because DHCP
/// failed), so the rescue silently never worked. New-NetIPAddress adds
/// the address on DHCP and static interfaces alike.
pub async fn add_secondary_ip(interface: &str, ip: &str, mask: &str) -> Result<(), AppError> {
    super::interface::validate_interface_name(interface).await?;
    validate_ip(ip)?;
    validate_ip(mask)?;
    let prefix = mask_to_prefix(mask)?;

    #[cfg(target_os = "windows")]
    {
        let escaped = interface.replace('\'', "''");
        let script = format!(
            "New-NetIPAddress -InterfaceAlias '{}' -IPAddress '{}' -PrefixLength {} \
             -ErrorAction Stop | Out-Null",
            escaped, ip, prefix
        );
        run_command("powershell", &["-NoProfile", "-Command", &script]).await?;
    }

    #[cfg(target_os = "linux")]
    {
        let cidr = format!("{}/{}", ip, prefix);
        run_command("ip", &["addr", "add", &cidr, "dev", interface]).await?;
    }

    Ok(())
}

/// Switch the interface to DHCP mode (clears static IPs, enables DHCP for
/// IPv4 and DNS, renews the lease). Requires admin; same fast-path-then-
/// elevate pattern as `adapter_refresh::hard_refresh_windows`.
pub async fn set_dhcp(interface: &str) -> Result<(), AppError> {
    super::interface::validate_interface_name(interface).await?;

    #[cfg(target_os = "windows")]
    {
        set_dhcp_windows(interface).await
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err(AppError::Network(
            "DHCP toggle is only implemented on Windows".into(),
        ))
    }
}

#[cfg(target_os = "windows")]
async fn set_dhcp_windows(interface: &str) -> Result<(), AppError> {
    use tokio::time::{timeout, Duration};

    let escaped = interface.replace('\'', "''");

    // Multi-step: drop existing manual IPv4 addresses (DHCP doesn't displace
    // them on its own), drop any static default route (a gateway set via
    // `netsh set address` persists across the DHCP flip and — often at lower
    // metric than the DHCP-provided route — blackholes all off-subnet
    // traffic), flip the interface to DHCP, reset DNS to auto, then force an
    // immediate lease renewal so the new state is visible right away.
    // ErrorAction SilentlyContinue on the cleanup steps so an already-DHCP
    // adapter with no manual IPs or static route doesn't fail the whole
    // script.
    let inner_script = format!(
        "$alias='{}'; \
         Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -PrefixOrigin Manual -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; \
         Remove-NetRoute -InterfaceAlias $alias -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 -Confirm:$false -ErrorAction SilentlyContinue; \
         Set-NetIPInterface -InterfaceAlias $alias -Dhcp Enabled; \
         Set-DnsClientServerAddress -InterfaceAlias $alias -ResetServerAddresses; \
         ipconfig /renew $alias | Out-Null",
        escaped
    );

    // Fast path: try unelevated first. kill_on_drop matters here: the
    // timeout below drops this future, and without it the orphaned
    // PowerShell would keep mutating the adapter concurrently with the
    // elevated attempt that follows.
    let direct = super::async_cmd("powershell")
        .args(["-NoProfile", "-Command", &inner_script])
        .kill_on_drop(true)
        .output();
    if let Ok(Ok(out)) = timeout(Duration::from_secs(30), direct).await {
        if out.status.success() {
            log::info!("Switched '{}' to DHCP (unelevated)", interface);
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        log::info!(
            "Unelevated DHCP set failed, attempting elevation: {}",
            stderr.trim()
        );
    }

    // Slow path: spawn an elevated PowerShell via Start-Process -Verb RunAs.
    // Double every single-quote inside the inner script so the outer
    // PowerShell parser passes the original script through unchanged.
    let inner_for_arglist = inner_script.replace('\'', "''");
    let elevated_cmd = format!(
        "$ErrorActionPreference='Stop'; \
         Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait \
         -ArgumentList '-NoProfile','-Command','{}'",
        inner_for_arglist
    );
    let elevated = super::async_cmd("powershell")
        .args(["-NoProfile", "-Command", &elevated_cmd])
        .kill_on_drop(true)
        .output();

    let out = timeout(Duration::from_secs(60), elevated)
        .await
        .map_err(|_| AppError::Network("DHCP toggle timed out after 60s".into()))?
        .map_err(|e| AppError::Network(format!("Failed to launch elevation: {}", e)))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(AppError::Network(format!(
            "DHCP toggle failed (UAC may have been declined): {}",
            stderr.trim()
        )));
    }

    log::info!("Switched '{}' to DHCP (elevated)", interface);
    Ok(())
}

/// Read whether the interface is currently in DHCP mode for IPv4. No admin
/// required. Called by the dialog at open time to position the mode toggle.
pub async fn get_dhcp_state(interface: &str) -> Result<bool, AppError> {
    super::interface::validate_interface_name(interface).await?;

    #[cfg(target_os = "windows")]
    {
        let escaped = interface.replace('\'', "''");
        let script = format!(
            "(Get-NetIPInterface -InterfaceAlias '{}' -AddressFamily IPv4).Dhcp",
            escaped
        );
        let output = super::async_cmd("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()
            .await
            .map_err(|e| AppError::Network(format!("Failed to read DHCP state: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::Network(format!(
                "Get-NetIPInterface failed: {}",
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_lowercase();
        Ok(stdout == "enabled")
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = interface;
        Err(AppError::Network(
            "DHCP state query is only implemented on Windows".into(),
        ))
    }
}

/// Remove a secondary IP address from an interface.
pub async fn remove_secondary_ip(interface: &str, ip: &str) -> Result<(), AppError> {
    super::interface::validate_interface_name(interface).await?;
    validate_ip(ip)?;

    #[cfg(target_os = "windows")]
    {
        let name_arg = format!("name={}", interface);
        run_command(
            "netsh",
            &["interface", "ip", "delete", "address", &name_arg, ip],
        )
        .await?;
    }

    #[cfg(target_os = "linux")]
    {
        // Find the prefix for this IP — default to /24
        let cidr = format!("{}/24", ip);
        run_command("ip", &["addr", "del", &cidr, "dev", interface]).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_ip ─────────────────────────────────────────────────

    #[test]
    fn validate_ip_valid_addresses() {
        assert!(validate_ip("192.168.1.1").is_ok());
        assert!(validate_ip("10.0.0.1").is_ok());
        assert!(validate_ip("255.255.255.0").is_ok());
        assert!(validate_ip("0.0.0.0").is_ok());
        assert!(validate_ip("172.16.0.1").is_ok());
    }

    #[test]
    fn validate_ip_invalid_addresses() {
        assert!(validate_ip("").is_err());
        assert!(validate_ip("not-an-ip").is_err());
        assert!(validate_ip("256.1.1.1").is_err());
        assert!(validate_ip("192.168.1").is_err());
        assert!(validate_ip("192.168.1.1.1").is_err());
        assert!(validate_ip("::1").is_err()); // IPv6 rejected
    }

    #[test]
    fn validate_ip_error_message() {
        let err = validate_ip("bad").unwrap_err();
        assert!(err.to_string().contains("Invalid IP address"));
        assert!(err.to_string().contains("bad"));
    }

    // ── mask_to_prefix (Linux only) ─────────────────────────────────

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::super::*;

        #[test]
        fn mask_to_prefix_common_masks() {
            assert_eq!(mask_to_prefix("255.255.255.0").unwrap(), 24);
            assert_eq!(mask_to_prefix("255.255.0.0").unwrap(), 16);
            assert_eq!(mask_to_prefix("255.0.0.0").unwrap(), 8);
            assert_eq!(mask_to_prefix("255.255.255.255").unwrap(), 32);
            assert_eq!(mask_to_prefix("255.255.255.128").unwrap(), 25);
            assert_eq!(mask_to_prefix("255.255.252.0").unwrap(), 22);
        }

        #[test]
        fn mask_to_prefix_invalid() {
            assert!(mask_to_prefix("not-a-mask").is_err());
        }
    }
}
