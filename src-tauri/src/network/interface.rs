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
    pub is_wifi: bool,
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
    "vpn",
    "tunnel",
    "tap-windows",
    "tap0",
    "wintun",
    "wireguard",
    "tailscale",
    "zerotier",
    "anyconnect",
    "fortinet",
    "pangp",
    "softether",
    "openvpn",
    "nordlynx",
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
    let mac = a["MacAddress"].as_str().unwrap_or("").replace('-', ":");
    let media = a["MediaType"].as_str().unwrap_or("");

    let ip_entries = if a["IPs"].is_array() {
        a["IPs"].as_array().unwrap().clone()
    } else if a["IPs"].is_object() {
        vec![a["IPs"].clone()]
    } else {
        vec![]
    };

    let ips: Vec<IpInfo> = ip_entries
        .iter()
        .filter_map(|ip_val| {
            let addr_str = ip_val["Address"].as_str()?;
            let prefix = ip_val["PrefixLength"].as_u64().unwrap_or(24) as u8;
            let addr: IpAddr = addr_str.parse().ok()?;
            let net = ipnetwork::IpNetwork::new(addr, prefix).ok()?;
            Some(IpInfo {
                address: addr_str.to_string(),
                prefix,
                subnet: format!("{}/{}", net.network(), net.prefix()),
            })
        })
        .collect();

    let is_ethernet = media.contains("802.3");
    let is_wifi = media.contains("802.11") || media.contains("Native 802.11");

    InterfaceInfo {
        display_name: name.clone(),
        name,
        ips,
        mac,
        is_up: true,
        is_ethernet,
        is_wifi,
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
    let output = super::cmd("powershell")
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
            let ips: Vec<IpInfo> = iface
                .ips
                .iter()
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
                is_wifi: lower.starts_with("wl") || lower.starts_with("wlan"),
                is_vpn: lower.starts_with("tun")
                    || lower.starts_with("tap")
                    || lower.starts_with("wg")
                    || lower.contains("tailscale"),
            }
        })
        .collect();

    Ok(result)
}

/// Lightweight interface status check via pnet (no process spawning).
/// Matches by MAC address and returns (is_up, current_ipv4_ips).
/// This is cheap enough to poll every few seconds.
pub fn quick_status_by_mac(mac: &str) -> Option<(bool, Vec<IpInfo>)> {
    let target = mac.to_lowercase();
    let interfaces = pnet::datalink::interfaces();

    let iface = interfaces.iter().find(|i| {
        i.mac
            .map(|m| m.to_string().to_lowercase() == target)
            .unwrap_or(false)
    })?;

    let ips = iface
        .ips
        .iter()
        .filter(|ip_net| ip_net.is_ipv4())
        .map(|ip_net| IpInfo {
            address: ip_net.ip().to_string(),
            prefix: ip_net.prefix(),
            subnet: format!("{}/{}", ip_net.network(), ip_net.prefix()),
        })
        .collect();

    Some((iface.is_up(), ips))
}

/// Get info for a specific interface by name.
pub fn get_by_name(name: &str) -> Result<InterfaceInfo, AppError> {
    let all = list_all()?;
    all.into_iter()
        .find(|i| i.name == name)
        .ok_or_else(|| AppError::Network(format!("Interface '{}' not found", name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Data Structure Tests ────────────────────────────────────────

    #[test]
    fn ip_info_serializes() {
        let ip = IpInfo {
            address: "192.168.1.10".into(),
            prefix: 24,
            subnet: "192.168.1.0/24".into(),
        };
        let json = serde_json::to_string(&ip).unwrap();
        assert!(json.contains("192.168.1.10"));
        assert!(json.contains("\"prefix\":24"));
    }

    #[test]
    fn interface_info_serializes() {
        let iface = InterfaceInfo {
            name: "eth0".into(),
            display_name: "Ethernet".into(),
            ips: vec![IpInfo {
                address: "10.0.0.1".into(),
                prefix: 24,
                subnet: "10.0.0.0/24".into(),
            }],
            mac: "aa:bb:cc:dd:ee:ff".into(),
            is_up: true,
            is_ethernet: true,
            is_wifi: false,
            is_vpn: false,
        };
        let json = serde_json::to_string(&iface).unwrap();
        assert!(json.contains("\"name\":\"eth0\""));
        assert!(json.contains("\"is_up\":true"));
        assert!(json.contains("\"is_vpn\":false"));
    }

    // ── Windows-specific parse functions ─────────────────────────────

    #[cfg(target_os = "windows")]
    mod windows_tests {
        use super::super::*;

        #[test]
        fn is_vpn_adapter_matches_known_keywords() {
            assert!(is_vpn_adapter("Tailscale Tunnel"));
            assert!(is_vpn_adapter("TAP-Windows Adapter V9"));
            assert!(is_vpn_adapter("WireGuard Tunnel"));
            assert!(is_vpn_adapter("Cisco AnyConnect Virtual Miniport"));
            assert!(is_vpn_adapter("NordLynx Tunnel"));
            assert!(is_vpn_adapter("OpenVPN TAP-Windows6"));
            assert!(is_vpn_adapter("Fortinet Virtual Ethernet Adapter"));
            assert!(is_vpn_adapter("ZeroTier One Virtual Port"));
        }

        #[test]
        fn is_vpn_adapter_case_insensitive() {
            assert!(is_vpn_adapter("TAILSCALE TUNNEL"));
            assert!(is_vpn_adapter("wireguard"));
            assert!(is_vpn_adapter("VPN Connection"));
        }

        #[test]
        fn is_vpn_adapter_rejects_normal() {
            assert!(!is_vpn_adapter("Intel(R) Ethernet Connection I219-V"));
            assert!(!is_vpn_adapter("Realtek PCIe GBE Family Controller"));
            assert!(!is_vpn_adapter("Microsoft Wi-Fi Direct Virtual Adapter"));
        }

        #[test]
        fn parse_adapter_json_empty_string() {
            let result = parse_adapter_json("").unwrap();
            assert!(result.is_empty());
        }

        #[test]
        fn parse_adapter_json_single_object() {
            let json = r#"{"Name":"Ethernet","Description":"Intel Ethernet","MacAddress":"AA-BB-CC-DD-EE-FF","MediaType":"802.3","IPs":[]}"#;
            let result = parse_adapter_json(json).unwrap();
            assert_eq!(result.len(), 1);
            assert_eq!(result[0]["Name"].as_str().unwrap(), "Ethernet");
        }

        #[test]
        fn parse_adapter_json_array() {
            let json = r#"[{"Name":"Eth1","Description":"Intel","MacAddress":"","MediaType":"","IPs":[]},{"Name":"Eth2","Description":"Realtek","MacAddress":"","MediaType":"","IPs":[]}]"#;
            let result = parse_adapter_json(json).unwrap();
            assert_eq!(result.len(), 2);
        }

        #[test]
        fn parse_adapter_json_invalid() {
            assert!(parse_adapter_json("not json").is_err());
        }

        #[test]
        fn parse_adapter_basic() {
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "Ethernet 2",
                "Description": "Intel(R) I210 Gigabit Ethernet",
                "MacAddress": "AA-BB-CC-DD-EE-FF",
                "MediaType": "802.3",
                "IPs": [{"Address": "192.168.1.100", "PrefixLength": 24}]
            }"#,
            )
            .unwrap();
            let iface = parse_adapter(&json, false);
            assert_eq!(iface.name, "Ethernet 2");
            assert_eq!(iface.display_name, "Ethernet 2");
            assert_eq!(iface.mac, "AA:BB:CC:DD:EE:FF");
            assert!(iface.is_ethernet);
            assert!(!iface.is_vpn);
            assert!(iface.is_up);
            assert_eq!(iface.ips.len(), 1);
            assert_eq!(iface.ips[0].address, "192.168.1.100");
            assert_eq!(iface.ips[0].prefix, 24);
        }

        #[test]
        fn parse_adapter_vpn() {
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "Tailscale",
                "Description": "Tailscale Tunnel",
                "MacAddress": "",
                "MediaType": "",
                "IPs": []
            }"#,
            )
            .unwrap();
            let iface = parse_adapter(&json, true);
            assert!(iface.is_vpn);
            assert!(!iface.is_ethernet);
            assert!(iface.ips.is_empty());
        }

        #[test]
        fn parse_adapter_no_ips() {
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "Ethernet",
                "Description": "Realtek",
                "MacAddress": "",
                "MediaType": "802.3",
                "IPs": null
            }"#,
            )
            .unwrap();
            let iface = parse_adapter(&json, false);
            assert!(iface.ips.is_empty());
        }

        #[test]
        fn parse_adapter_ipv6_passthrough() {
            // parse_adapter accepts any valid IP (including IPv6)
            // because the PowerShell query already filters to IPv4.
            // Verify it doesn't panic on IPv6 input.
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "Ethernet",
                "Description": "Intel",
                "MacAddress": "",
                "MediaType": "802.3",
                "IPs": [{"Address": "fe80::1", "PrefixLength": 64}]
            }"#,
            )
            .unwrap();
            let iface = parse_adapter(&json, false);
            // IPv6 may or may not parse — the function shouldn't panic
            assert!(iface.ips.len() <= 1);
        }

        #[test]
        fn parse_adapter_ethernet_requires_802_3_media_type() {
            // Only MediaType "802.3" qualifies as ethernet — name/description
            // containing "ethernet" is NOT enough (avoids WiFi false positives).
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "Connection 1",
                "Description": "USB Ethernet Adapter",
                "MacAddress": "",
                "MediaType": "",
                "IPs": []
            }"#,
            )
            .unwrap();
            let iface = parse_adapter(&json, false);
            assert!(!iface.is_ethernet, "Empty MediaType should not be ethernet");

            let json_802_3: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "Connection 1",
                "Description": "USB Ethernet Adapter",
                "MacAddress": "",
                "MediaType": "802.3",
                "IPs": []
            }"#,
            )
            .unwrap();
            let iface2 = parse_adapter(&json_802_3, false);
            assert!(iface2.is_ethernet, "802.3 MediaType should be ethernet");
        }

        #[test]
        fn parse_adapter_wifi_not_ethernet() {
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "Wi-Fi",
                "Description": "Intel(R) Wi-Fi 6E AX211",
                "MacAddress": "AA-BB-CC-DD-EE-FF",
                "MediaType": "Native 802.11",
                "IPs": [{"Address": "192.168.1.50", "PrefixLength": 24}]
            }"#,
            )
            .unwrap();
            let iface = parse_adapter(&json, false);
            assert!(
                !iface.is_ethernet,
                "WiFi (802.11) must not be marked ethernet"
            );
            assert!(iface.is_wifi, "WiFi (802.11) must be marked as wifi");
        }
    }

    // ── Platform-independent tests ──────────────────────────────────

    #[test]
    fn list_physical_returns_ok() {
        // Should succeed on any platform (may be empty in CI)
        let result = list_physical();
        assert!(result.is_ok());
    }

    #[test]
    fn list_all_returns_ok() {
        let result = list_all();
        assert!(result.is_ok());
    }

    #[test]
    fn get_by_name_nonexistent_returns_err() {
        let result = get_by_name("__nonexistent_interface_42__");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("not found"));
    }
}
