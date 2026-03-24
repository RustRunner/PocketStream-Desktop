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
}

/// List all network interfaces with their details.
pub fn list_all() -> Result<Vec<InterfaceInfo>, AppError> {
    #[cfg(target_os = "windows")]
    {
        list_all_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        list_all_pnet()
    }
}

#[cfg(target_os = "windows")]
fn list_all_windows() -> Result<Vec<InterfaceInfo>, AppError> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile", "-Command",
            r#"Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Virtual -eq $false } | ForEach-Object {
                $adapter = $_
                $ips = @(Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
                [PSCustomObject]@{
                    Name = $adapter.Name
                    Description = $adapter.InterfaceDescription
                    MacAddress = $adapter.MacAddress
                    MediaType = $adapter.MediaType
                    Virtual = $adapter.Virtual
                    IPs = @($ips | ForEach-Object {
                        [PSCustomObject]@{
                            Address = $_.IPAddress
                            PrefixLength = $_.PrefixLength
                        }
                    })
                }
            } | ConvertTo-Json -Depth 3 -Compress"#
        ])
        .output()
        .map_err(|e| AppError::Network(format!("Failed to run PowerShell: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    log::info!("Windows adapter enumeration: {}", stdout);
    if !stderr.is_empty() {
        log::warn!("PowerShell stderr: {}", stderr);
    }

    if stdout.trim().is_empty() {
        return Ok(vec![]);
    }

    // PowerShell returns a single object (not array) if there's only one result
    let adapters: Vec<serde_json::Value> = if stdout.trim().starts_with('[') {
        serde_json::from_str(&stdout)
            .map_err(|e| AppError::Network(format!("Failed to parse adapter JSON: {}", e)))?
    } else {
        let single: serde_json::Value = serde_json::from_str(&stdout)
            .map_err(|e| AppError::Network(format!("Failed to parse adapter JSON: {}", e)))?;
        vec![single]
    };

    let result = adapters.into_iter().map(|a| {
        let name = a["Name"].as_str().unwrap_or("").to_string();
        let desc = a["Description"].as_str().unwrap_or("").to_string();
        let mac = a["MacAddress"].as_str().unwrap_or("").replace('-', ":");
        let media = a["MediaType"].as_str().unwrap_or("");

        // Parse all IPs — handle both single object and array from PowerShell
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
        }
    }).collect();

    Ok(result)
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

            InterfaceInfo {
                name: iface.name.clone(),
                display_name: iface.name.clone(),
                ips,
                mac: iface.mac.map(|m| m.to_string()).unwrap_or_default(),
                is_up: iface.is_up(),
                is_ethernet: {
                    let lower = iface.name.to_lowercase();
                    lower.starts_with("eth") || lower.starts_with("en")
                },
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
