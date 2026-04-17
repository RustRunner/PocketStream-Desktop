use crate::error::AppError;

/// Assign a static IP address to a network interface.
///
/// Platform-specific implementation:
/// - Windows: uses `netsh interface ip set address`
/// - Linux: uses `ip addr` commands
pub async fn assign_static_ip(
    interface: &str,
    ip: &str,
    subnet_mask: &str,
    gateway: Option<&str>,
) -> Result<(), AppError> {
    validate_interface_name(interface)?;
    validate_ip(ip)?;
    validate_ip(subnet_mask)?;
    if let Some(gw) = gateway {
        validate_ip(gw)?;
    }

    #[cfg(target_os = "windows")]
    {
        assign_windows(interface, ip, subnet_mask, gateway).await
    }

    #[cfg(target_os = "linux")]
    {
        assign_linux(interface, ip, subnet_mask, gateway).await
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err(AppError::Network("Unsupported platform".into()))
    }
}

#[cfg(target_os = "windows")]
async fn assign_windows(
    interface: &str,
    ip: &str,
    subnet_mask: &str,
    gateway: Option<&str>,
) -> Result<(), AppError> {
    // Snapshot existing secondary IPs before the set (which replaces all).
    let secondaries: Vec<super::interface::IpInfo> = super::interface::get_by_name(interface)
        .map(|info| info.ips.into_iter().skip(1).collect())
        .unwrap_or_default();

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

    // Re-add secondary IPs that were wiped by the set command (in parallel).
    // Skip the new primary if it happened to also be a secondary.
    let mut tasks = Vec::new();
    for sec in &secondaries {
        if sec.address == ip {
            continue;
        }
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

fn validate_interface_name(name: &str) -> Result<(), AppError> {
    let known = super::interface::list_physical()?;
    if !known.iter().any(|iface| iface.name == name) {
        return Err(AppError::Network(format!(
            "Unknown network interface: {}",
            name
        )));
    }
    Ok(())
}

fn validate_ip(ip: &str) -> Result<(), AppError> {
    ip.parse::<std::net::Ipv4Addr>()
        .map_err(|_| AppError::Network(format!("Invalid IP address: {}", ip)))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn mask_to_prefix(mask: &str) -> Result<u8, AppError> {
    let addr: std::net::Ipv4Addr = mask
        .parse()
        .map_err(|_| AppError::Network(format!("Invalid subnet mask: {}", mask)))?;
    let bits: u32 = u32::from(addr);
    Ok(bits.count_ones() as u8)
}

/// Add a secondary IP address to an interface (preserves existing IPs).
pub async fn add_secondary_ip(interface: &str, ip: &str, mask: &str) -> Result<(), AppError> {
    validate_interface_name(interface)?;
    validate_ip(ip)?;
    validate_ip(mask)?;

    #[cfg(target_os = "windows")]
    {
        let name_arg = format!("name={}", interface);
        run_command(
            "netsh",
            &["interface", "ip", "add", "address", &name_arg, ip, mask],
        )
        .await?;
    }

    #[cfg(target_os = "linux")]
    {
        let prefix = mask_to_prefix(mask)?;
        let cidr = format!("{}/{}", ip, prefix);
        run_command("ip", &["addr", "add", &cidr, "dev", interface]).await?;
    }

    Ok(())
}

/// Remove a secondary IP address from an interface.
pub async fn remove_secondary_ip(interface: &str, ip: &str) -> Result<(), AppError> {
    validate_interface_name(interface)?;
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
