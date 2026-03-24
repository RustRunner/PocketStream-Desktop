use serde::Serialize;
use std::net::IpAddr;

use crate::error::AppError;

#[derive(Debug, Clone, Serialize)]
pub struct IpInfo {
    pub address: String,
    pub prefix: u8,
    pub subnet: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub display_name: String,
    pub ips: Vec<IpInfo>,
    pub mac: String,
    pub is_up: bool,
    pub is_ethernet: bool,
    pub is_vpn: bool,
}

/// List physical (non-VPN) network interfaces.
pub fn list_physical() -> Result<Vec<InterfaceInfo>, AppError> {
    #[cfg(target_os = "windows")]
    {
        list_physical_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(list_all_pnet()?.into_iter().filter(|i| !i.is_vpn).collect())
    }
}

/// List VPN interfaces only.
pub fn list_vpn() -> Result<Vec<InterfaceInfo>, AppError> {
    #[cfg(target_os = "windows")]
    {
        list_vpn_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(list_all_pnet()?.into_iter().filter(|i| i.is_vpn).collect())
    }
}

/// List all network interfaces with their details (physical + VPN).
pub fn list_all() -> Result<Vec<InterfaceInfo>, AppError> {
    #[cfg(target_os = "windows")]
    {
        let mut result = list_physical_windows()?;
        result.extend(list_vpn_windows()?);
        Ok(result)
    }
    #[cfg(not(target_os = "windows"))]
    {
        list_all_pnet()
    }
}

#[cfg(target_os = "windows")]
const VPN_KEYWORDS: &[&str] = &[
    "vpn", "tunnel", "tap-windows", "tap0", "wintun", "wireguard",
    "tailscale", "zerotier", "anyconnect", "fortinet", "pangp",
    "softether", "openvpn", "nordlynx",
];

#[cfg(target_os = "windows")]
fn is_vpn_adapter(description: &str) -> bool {
    let lower = description.to_lowercase();
    VPN_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

#[cfg(target_os = "windows")]
fn parse_adapter_json(stdout: &str) -> Result<Vec<serde_json::Value>, AppError> {
    if stdout.trim().is_empty() {
        return Ok(vec![]);
    }
    // PowerShell returns a single object (not array) if there's only one result
    if stdout.trim().starts_with('[') {
        serde_json::from_str(stdout)
            .map_err(|e| AppError::Network(format!("Failed to parse adapter JSON: {}", e)))
    } else {
        let single: serde_json::Value = serde_json::from_str(stdout)
            .map_err(|e| AppError::Network(format!("Failed to parse adapter JSON: {}", e)))?;
        Ok(vec![single])
    }
}

#[cfg(target_os = "windows")]
fn parse_adapter(a: &serde_json::Value, is_vpn: bool) -> InterfaceInfo {
    let name = a["Name"].as_str().unwrap_or("").to_string();
    let desc = a["Description"].as_str().unwrap_or("").to_string();
    let mac = a["MacAddress"].as_str().unwrap_or("").replace('-', ":");
    let media = a["MediaType"].as_str().unwrap_or("");

    let ip_entries = if a["IPs"].is_array() {
        a["IPs"].as_array().unwrap().clone()
    } else if a["IPs"].is_object() {
        vec![a["IPs"].clone()]
    } else {
        vec![]
    };

    let ips: Vec<IpInfo> = ip_entries.iter().filter_map(|ip_val| {
        let addr_str = ip_val["Address"].as_str()?;
        let prefix = ip_val["PrefixLength"].as_u64().unwrap_or(24) as u8;
        let addr: IpAddr = addr_str.parse().ok()?;
        let net = ipnetwork::IpNetwork::new(addr, prefix).ok()?;
        Some(IpInfo {
            address: addr_str.to_string(),
            prefix,
            subnet: format!("{}/{}", net.network(), net.prefix()),
        })
    }).collect();

    let is_ethernet = media.contains("802.3")
        || desc.to_lowercase().contains("ethernet")
        || name.to_lowercase().contains("ethernet");

    InterfaceInfo {
        display_name: name.clone(),
        name,
        ips,
        mac,
        is_up: true,
        is_ethernet,
        is_vpn,
    }
}

#[cfg(target_os = "windows")]
fn run_adapter_query(filter: &str) -> Result<String, AppError> {
    let script = format!(
        r#"Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' -and {} }} | ForEach-Object {{
            $adapter = $_
            $ips = @(Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
            [PSCustomObject]@{{
                Name = $adapter.Name
                Description = $adapter.InterfaceDescription
                MacAddress = $adapter.MacAddress
                MediaType = $adapter.MediaType
                Virtual = $adapter.Virtual
                IPs = @($ips | ForEach-Object {{
                    [PSCustomObject]@{{
                        Address = $_.IPAddress
                        PrefixLength = $_.PrefixLength
                    }}
                }})
            }}
        }} | ConvertTo-Json -Depth 3 -Compress"#,
        filter
    );
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .map_err(|e| AppError::Network(format!("Failed to run PowerShell: {}", e)))?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        log::warn!("PowerShell stderr: {}", stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(target_os = "windows")]
fn list_physical_windows() -> Result<Vec<InterfaceInfo>, AppError> {
    let stdout = run_adapter_query("$_.Virtual -eq $false")?;
    log::info!("Windows physical adapter enumeration: {}", stdout);
    let adapters = parse_adapter_json(&stdout)?;
    Ok(adapters.iter().map(|a| parse_adapter(a, false)).collect())
}

#[cfg(target_os = "windows")]
fn list_vpn_windows() -> Result<Vec<InterfaceInfo>, AppError> {
    let stdout = run_adapter_query("$_.Virtual -eq $true")?;
    let adapters = parse_adapter_json(&stdout)?;
    Ok(adapters
        .iter()
        .filter(|a| {
            let desc = a["Description"].as_str().unwrap_or("");
            is_vpn_adapter(desc)
        })
        .map(|a| parse_adapter(a, true))
        .collect())
}

#[cfg(not(target_os = "windows"))]
fn list_all_pnet() -> Result<Vec<InterfaceInfo>, AppError> {
    use pnet::datalink;

    let interfaces = datalink::interfaces();

    let result: Vec<InterfaceInfo> = interfaces
        .into_iter()
        .filter(|iface| !iface.is_loopback())
        .map(|iface| {
            let ips: Vec<IpInfo> = iface.ips.iter()
                .filter(|ip| ip.is_ipv4())
                .filter_map(|ip| {
                    let network: ipnetwork::IpNetwork = (*ip).into();
                    Some(IpInfo {
                        address: ip.ip().to_string(),
                        prefix: network.prefix(),
                        subnet: format!("{}/{}", network.network(), network.prefix()),
                    })
                })
                .collect();

            let lower = iface.name.to_lowercase();
            InterfaceInfo {
                name: iface.name.clone(),
                display_name: iface.name.clone(),
                ips,
                mac: iface.mac.map(|m| m.to_string()).unwrap_or_default(),
                is_up: iface.is_up(),
                is_ethernet: lower.starts_with("eth") || lower.starts_with("en"),
                is_vpn: lower.starts_with("tun")
                    || lower.starts_with("tap")
                    || lower.starts_with("wg")
                    || lower.contains("tailscale"),
            }
        })
        .collect();

    Ok(result)
}

/// Get info for a specific interface by name.
pub fn get_by_name(name: &str) -> Result<InterfaceInfo, AppError> {
    let all = list_all()?;
    all.into_iter()
        .find(|i| i.name == name)
        .ok_or_else(|| AppError::Network(format!("Interface '{}' not found", name)))
}
