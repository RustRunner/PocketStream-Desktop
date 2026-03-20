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

async fn run_command(program: &str, args: &[&str]) -> Result<String, AppError> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| AppError::Network(format!("Failed to run {}: {}", program, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Network(format!(
            "{} failed: {}",
            program, stderr
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
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
