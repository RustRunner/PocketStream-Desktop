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
    // Set static IP
    let mut args = vec![
        "interface", "ip", "set", "address",
        interface, "static", ip, subnet_mask,
    ];
    if let Some(gw) = gateway {
        args.push(gw);
    }

    run_command("netsh", &args).await?;
    Ok(())
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
        let _ = run_command("ip", &["route", "add", "default", "via", gw, "dev", interface]).await;
    }

    Ok(())
}

pub(crate) async fn run_command(program: &str, args: &[&str]) -> Result<String, AppError> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| AppError::Network(format!("Failed to run {}: {}", program, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let msg = if stderr.trim().is_empty() { stdout } else { stderr };
        return Err(AppError::Network(format!(
            "{} failed: {}",
            program,
            msg.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn validate_interface_name(name: &str) -> Result<(), AppError> {
    let known = super::interface::list_all()?;
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
