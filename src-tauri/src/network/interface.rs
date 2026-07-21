use serde::Serialize;
#[cfg(target_os = "windows")]
use std::net::IpAddr;

use crate::error::AppError;

/// How long a validated interface name stays trusted before the next
/// `validate_interface_name` re-enumerates. Bounds staleness (an adapter
/// removed within the window still validates) while keeping the 2 s
/// auto-adopt loop from spawning PowerShell twice per cycle forever.
const VALIDATION_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// Names validated within [`VALIDATION_TTL`], with the time they were
/// confirmed present. Read on the hot path; the enumeration behind it is
/// the expensive part being skipped.
static VALIDATED_NAMES: std::sync::Mutex<
    Option<std::collections::HashMap<String, std::time::Instant>>,
> = std::sync::Mutex::new(None);

fn recently_validated(name: &str) -> bool {
    let guard = VALIDATED_NAMES.lock();
    let map = match guard {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    map.as_ref()
        .and_then(|m| m.get(name))
        .is_some_and(|t| t.elapsed() < VALIDATION_TTL)
}

fn remember_validated(name: &str) {
    let mut guard = match VALIDATED_NAMES.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    map.insert(name.to_string(), std::time::Instant::now());
}

/// Validate that `name` is a currently-known physical interface. Cached
/// for [`VALIDATION_TTL`] so the IP-config commands and the auto-adopt
/// loop don't re-run the adapter enumeration on every call. Consolidates
/// the two former per-module copies of this check.
pub async fn validate_interface_name(name: &str) -> Result<(), AppError> {
    if recently_validated(name) {
        return Ok(());
    }
    let known = list_physical().await?;
    if known.iter().any(|iface| iface.name == name) {
        remember_validated(name);
        Ok(())
    } else {
        Err(AppError::Network(format!(
            "Unknown network interface: {}",
            name
        )))
    }
}

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
    /// True for adapters the OS reports as virtual: Hyper-V/WSL virtual
    /// switches, VMware/VirtualBox host adapters, and most VPN tunnels.
    /// Distinct from `is_vpn` because a keyword-missed virtual adapter is
    /// still a structural non-wired interface that must be excluded from
    /// camera-port discovery. On Windows this is the `Virtual` property
    /// from `Get-NetAdapter`; on pnet it is inferred from the name.
    pub is_virtual: bool,
}

/// Structural half of the camera-port predicate: Ethernet media,
/// neither VPN nor OS-virtual, regardless of link state. This is the
/// gate for binding the capture listener — a disconnected wired port is
/// a valid capture source (it hears the link-up burst the moment a
/// cable arrives), but WiFi/VPN/virtual never is.
pub fn is_wired_physical(i: &InterfaceInfo) -> bool {
    i.is_ethernet && !i.is_vpn && !i.is_virtual
}

/// The shared "is this a wired camera port?" predicate. A camera-capable
/// adapter is up, Ethernet media, and neither a VPN nor an OS-virtual
/// adapter. Every adapter-selection site funnels through this so a
/// VPN-as-Ethernet or virtual-switch adapter can never be picked as the
/// camera port. Lives here (not in `ghost`) so selection sites can use it
/// without pulling in the ghost-subnet module.
pub fn is_wired_ethernet(i: &InterfaceInfo) -> bool {
    i.is_up && is_wired_physical(i)
}

/// List physical (non-VPN) network interfaces.
pub async fn list_physical() -> Result<Vec<InterfaceInfo>, AppError> {
    #[cfg(target_os = "windows")]
    {
        list_physical_windows().await
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(list_all_pnet()?.into_iter().filter(|i| !i.is_vpn).collect())
    }
}

/// List VPN interfaces only.
pub async fn list_vpn() -> Result<Vec<InterfaceInfo>, AppError> {
    #[cfg(target_os = "windows")]
    {
        list_vpn_windows().await
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(list_all_pnet()?.into_iter().filter(|i| i.is_vpn).collect())
    }
}

/// List all network interfaces with their details (physical + VPN).
pub async fn list_all() -> Result<Vec<InterfaceInfo>, AppError> {
    #[cfg(target_os = "windows")]
    {
        let mut result = list_physical_windows().await?;
        result.extend(list_vpn_windows().await?);
        Ok(result)
    }
    #[cfg(not(target_os = "windows"))]
    {
        list_all_pnet()
    }
}

/// List every Up/Disconnected adapter — physical *and* virtual — in a
/// single unfiltered enumeration. Unlike [`list_all`], this does not drop
/// virtual adapters whose description misses the VPN keyword list
/// (Hyper-V/WSL `vEthernet`, VMware/VirtualBox host adapters, some
/// enterprise VPN clients), so the ghost-subnet machinery can see the
/// networks they own. `is_vpn` is derived from the description keywords;
/// `is_virtual` from the OS `Virtual` flag.
///
/// Deliberately separate from [`list_all`]: `list_all` backs the VPN IPC
/// command and the streaming display-IP fallback, neither of which should
/// widen to advertise a virtual-switch NAT address.
pub async fn list_all_adapters() -> Result<Vec<InterfaceInfo>, AppError> {
    #[cfg(target_os = "windows")]
    {
        list_all_adapters_windows().await
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

/// `NDIS_PHYSICAL_MEDIUM` values whose physical transport is wireless:
/// 1 WirelessLan, 8 WirelessWan, 9 Native802_11, 10 Bluetooth, 12 WiMax,
/// 13 UWB, 20 Native802_15_4.
#[cfg(target_os = "windows")]
const WIRELESS_NDIS_PHYSICAL_MEDIUMS: [u64; 7] = [1, 8, 9, 10, 12, 13, 20];

/// Whether the adapter's *physical* transport is wireless, overriding its
/// logical media type. Some NDIS drivers (emulated-802.3 WiFi dongles,
/// wireless WAN modems) report a logical `MediaType` of `802.3` while the
/// radio underneath is anything but wired — trusting the logical value
/// alone would let them be selected as the camera port.
///
/// Precedence: a non-zero `NdisPhysicalMedium` decides outright — it is a
/// raw numeric on the adapter CIM instance, locale-proof by construction
/// (14 = physical 802.3 and other wired media are conclusively not
/// wireless). Zero (`Unspecified`) or absent falls back to the
/// `PhysicalMediaType` display string — the same trust class as the
/// `MediaType` string we already rely on. Neither present ⇒ not wireless,
/// leaving the logical media type as the decider (previous behavior).
#[cfg(target_os = "windows")]
fn physical_medium_is_wireless(ndis: Option<u64>, physical_media_type: &str) -> bool {
    match ndis {
        Some(n) if n != 0 => WIRELESS_NDIS_PHYSICAL_MEDIUMS.contains(&n),
        _ => {
            let s = physical_media_type.to_ascii_lowercase();
            s.contains("802.11") || s.contains("wireless")
        }
    }
}

/// Parse one `Get-NetAdapter` JSON object into an [`InterfaceInfo`].
///
/// `force_vpn` short-circuits the VPN classification to `true` (used by
/// `list_vpn_windows`, which has already keyword-filtered its input). When
/// `false`, VPN status is decided by the adapter description so a VPN
/// driver that registers as a physical (`Virtual = false`) adapter is
/// still flagged — a physical Ethernet/WiFi description never matches a
/// VPN keyword, so this does not reclassify real hardware.
#[cfg(target_os = "windows")]
fn parse_adapter(a: &serde_json::Value, force_vpn: bool) -> InterfaceInfo {
    let name = a["Name"].as_str().unwrap_or("").to_string();
    let description = a["Description"].as_str().unwrap_or("");
    let mac = a["MacAddress"].as_str().unwrap_or("").replace('-', ":");
    let media = a["MediaType"].as_str().unwrap_or("");
    let status = a["Status"].as_str().unwrap_or("");
    let is_virtual = a["Virtual"].as_bool().unwrap_or(false);

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

    // A wireless physical medium overrides a logical 802.3 claim so an
    // emulated-Ethernet wireless adapter can never classify as the wired
    // camera port.
    let physical_wireless = physical_medium_is_wireless(
        a["NdisPhysicalMedium"].as_u64(),
        a["PhysicalMediaType"].as_str().unwrap_or(""),
    );
    let is_ethernet = media.contains("802.3") && !physical_wireless;
    let is_wifi = media.contains("802.11") || media.contains("Native 802.11") || physical_wireless;
    // Windows reports 'Up' for fully operational adapters. Anything else
    // (Disconnected, Disabled, NotPresent) is treated as down so the UI
    // can surface a reset action without hiding the adapter entirely.
    let is_up = status.eq_ignore_ascii_case("Up");
    let is_vpn = force_vpn || is_vpn_adapter(description);

    InterfaceInfo {
        display_name: name.clone(),
        name,
        ips,
        mac,
        is_up,
        is_ethernet,
        is_wifi,
        is_vpn,
        is_virtual,
    }
}

#[cfg(target_os = "windows")]
async fn run_adapter_query(filter: &str) -> Result<String, AppError> {
    // Include both Up and Disconnected adapters. Disconnected adapters are
    // surfaced in the UI as "detected but no link" so users can click
    // Reset to provoke a driver re-probe — the workaround for the Windows
    // quirk where the adapter stays marked disconnected after plug-in
    // until someone opens its Properties dialog.
    let script = format!(
        r#"Get-NetAdapter | Where-Object {{ ($_.Status -eq 'Up' -or $_.Status -eq 'Disconnected') -and {} }} | ForEach-Object {{
            $adapter = $_
            $ips = @(Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
            [PSCustomObject]@{{
                Name = $adapter.Name
                Description = $adapter.InterfaceDescription
                MacAddress = $adapter.MacAddress
                MediaType = $adapter.MediaType
                PhysicalMediaType = [string]$adapter.PhysicalMediaType
                NdisPhysicalMedium = $adapter.NdisPhysicalMedium
                Status = $adapter.Status
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
    // Bounded so a hung PowerShell (broken WMI has been observed) can't
    // wedge the calling worker indefinitely. kill_on_drop ensures the
    // child is reaped if the timeout fires and drops the future.
    let fut = super::async_cmd("powershell")
        .args(["-NoProfile", "-Command", &script])
        .kill_on_drop(true)
        .output();
    let output = match tokio::time::timeout(std::time::Duration::from_secs(10), fut).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            return Err(AppError::Network(format!(
                "Failed to run PowerShell: {}",
                e
            )))
        }
        Err(_) => {
            return Err(AppError::Network(
                "Adapter enumeration timed out after 10s (PowerShell/WMI may be hung)".into(),
            ))
        }
    };

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        log::warn!("PowerShell stderr: {}", stderr);
    }

    // A non-zero exit must NOT be treated as an empty adapter list —
    // that made validators fail with "Unknown network interface", the
    // watcher emit its no-adapter sentinel, and adopted-subnet restore
    // silently skip. Surface it as an error instead.
    if !output.status.success() {
        return Err(AppError::Network(format!(
            "Adapter enumeration failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Last-logged adapter-enumeration output plus the count of identical
/// results suppressed since. The enumeration re-runs every ~30 s from
/// pollers, the watcher, and commands, and its full JSON dominates log
/// volume even though the result is nearly always unchanged — so it is
/// logged only when it differs from the previous logged result.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
static LAST_ENUM_LOG: std::sync::Mutex<Option<(String, u64)>> = std::sync::Mutex::new(None);

/// Change gate for the enumeration log line: `Some(suppressed)` means
/// "log now, noting how many identical results were withheld";
/// `None` means the result matches the last logged one.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn enumeration_log_action(last: &mut Option<(String, u64)>, current: &str) -> Option<u64> {
    match last {
        Some((prev, suppressed)) if prev == current => {
            *suppressed += 1;
            None
        }
        _ => {
            let suppressed = last.as_ref().map(|(_, n)| *n).unwrap_or(0);
            *last = Some((current.to_string(), 0));
            Some(suppressed)
        }
    }
}

#[cfg(target_os = "windows")]
async fn list_physical_windows() -> Result<Vec<InterfaceInfo>, AppError> {
    let stdout = run_adapter_query("$_.Virtual -eq $false").await?;
    {
        let mut last = LAST_ENUM_LOG
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(suppressed) = enumeration_log_action(&mut last, &stdout) {
            if suppressed == 0 {
                log::info!("Windows physical adapter enumeration: {}", stdout);
            } else {
                log::info!(
                    "Windows physical adapter enumeration (unchanged {} time(s) since last log): {}",
                    suppressed,
                    stdout
                );
            }
        }
    }
    let adapters = parse_adapter_json(&stdout)?;
    Ok(adapters.iter().map(|a| parse_adapter(a, false)).collect())
}

#[cfg(target_os = "windows")]
async fn list_vpn_windows() -> Result<Vec<InterfaceInfo>, AppError> {
    let stdout = run_adapter_query("$_.Virtual -eq $true").await?;
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

#[cfg(target_os = "windows")]
async fn list_all_adapters_windows() -> Result<Vec<InterfaceInfo>, AppError> {
    // `$true` splices into the shared filter as `(...) -and $true`, i.e. no
    // adapter-level filtering beyond the Up/Disconnected status gate — every
    // adapter, physical or virtual. `parse_adapter(a, false)` then lets the
    // description decide VPN status and reads `is_virtual` from `Virtual`.
    let stdout = run_adapter_query("$true").await?;
    let adapters = parse_adapter_json(&stdout)?;
    Ok(adapters.iter().map(|a| parse_adapter(a, false)).collect())
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
                .map(|ip| {
                    let network = *ip;
                    IpInfo {
                        address: ip.ip().to_string(),
                        prefix: network.prefix(),
                        subnet: format!("{}/{}", network.network(), network.prefix()),
                    }
                })
                .collect();

            let lower = iface.name.to_lowercase();
            // tun/tap/wg/tailscale are software tunnels — both VPN and
            // virtual. pnet exposes no OS virtual flag, so the name is the
            // only signal; anything else defaults to non-virtual.
            let is_tunnel = lower.starts_with("tun")
                || lower.starts_with("tap")
                || lower.starts_with("wg")
                || lower.contains("tailscale");
            InterfaceInfo {
                name: iface.name.clone(),
                display_name: iface.name.clone(),
                ips,
                mac: iface.mac.map(|m| m.to_string()).unwrap_or_default(),
                is_up: iface.is_up(),
                is_ethernet: lower.starts_with("eth") || lower.starts_with("en"),
                is_wifi: lower.starts_with("wl") || lower.starts_with("wlan"),
                is_vpn: is_tunnel,
                is_virtual: is_tunnel,
            }
        })
        .collect();

    Ok(result)
}

/// A local adapter's MAC, up-state, and IPv4 addresses as read from the IP
/// Helper API. Backs [`quick_status_by_mac`] and [`all_local_ipv4`] on
/// Windows without touching pnet.
#[cfg(target_os = "windows")]
struct WinAdapter {
    /// Colon-separated, matching the format `parse_adapter` produces, so
    /// callers can compare MACs regardless of which enumeration path built
    /// the value they hold.
    mac: String,
    is_up: bool,
    ips: Vec<IpInfo>,
}

/// Enumerate every local adapter's MAC, up-state, and IPv4 addresses via the
/// IP Helper `GetAdaptersAddresses`. In-memory, no process spawn.
///
/// This exists so the Windows status/collision helpers never call
/// `pnet::datalink::interfaces()`, whose Windows backend imports
/// `PacketGetAdapterNames` from Packet.dll. That DLL is delay-loaded and
/// intentionally never shipped (ARP capture runs on the in-box PacketMonitor
/// API), so the first pnet interface call would abort the process with the
/// delay-load "module not found" exception (0xC06D007E) — which is exactly
/// what happened on the first subnet adoption of a run. IP Helper carries no
/// such import. Failures return an empty list (fail-open).
#[cfg(target_os = "windows")]
fn local_adapters_iphelper() -> Vec<WinAdapter> {
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    // IF_OPER_STATUS value IfOperStatusUp — the adapter is operational.
    const IF_OPER_STATUS_UP: i32 = 1;

    let family = AF_INET as u32;
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

    // Start at the 15 KB Microsoft recommends and grow on overflow. Back the
    // buffer with u64 so it meets the 8-byte alignment the adapter structs
    // need — a Vec<u8> would only be 1-byte aligned.
    let mut size: u32 = 15 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    let mut ret = ERROR_BUFFER_OVERFLOW;
    for _ in 0..4 {
        buf.clear();
        buf.resize((size as usize).div_ceil(8), 0);
        ret = unsafe {
            GetAdaptersAddresses(
                family,
                flags,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        if ret != ERROR_BUFFER_OVERFLOW {
            break;
        }
    }
    if ret != 0 {
        log::debug!("GetAdaptersAddresses failed with code {}", ret);
        return Vec::new();
    }

    let mut adapters = Vec::new();
    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cur.is_null() {
        let ad = unsafe { &*cur };

        let mac = if ad.PhysicalAddressLength >= 6 {
            let p = &ad.PhysicalAddress;
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                p[0], p[1], p[2], p[3], p[4], p[5]
            )
        } else {
            String::new()
        };

        let is_up = ad.OperStatus == IF_OPER_STATUS_UP;

        let mut ips = Vec::new();
        let mut ua = ad.FirstUnicastAddress;
        while !ua.is_null() {
            let u = unsafe { &*ua };
            let sa = u.Address.lpSockaddr;
            if !sa.is_null() && unsafe { (*sa).sa_family } == AF_INET {
                let sin = sa as *const SOCKADDR_IN;
                let o = unsafe { (*sin).sin_addr.S_un.S_un_b };
                let addr = std::net::Ipv4Addr::new(o.s_b1, o.s_b2, o.s_b3, o.s_b4);
                let prefix = u.OnLinkPrefixLength;
                let subnet = ipnetwork::Ipv4Network::new(addr, prefix)
                    .map(|n| format!("{}/{}", n.network(), n.prefix()))
                    .unwrap_or_else(|_| format!("{}/{}", addr, prefix));
                ips.push(IpInfo {
                    address: addr.to_string(),
                    prefix,
                    subnet,
                });
            }
            ua = u.Next;
        }

        adapters.push(WinAdapter { mac, is_up, ips });
        cur = ad.Next;
    }
    adapters
}

/// Lightweight interface status check by MAC (no process spawning, no
/// network traffic). Matches by MAC address and returns (is_up,
/// current_ipv4_ips). Cheap enough to poll every few seconds.
///
/// On Windows this reads adapter state through the IP Helper API rather than
/// `pnet::datalink::interfaces()` — see [`local_adapters_iphelper`] for why
/// the pnet path must never run on Windows.
#[cfg(target_os = "windows")]
pub fn quick_status_by_mac(mac: &str) -> Option<(bool, Vec<IpInfo>)> {
    let target = mac.to_lowercase();
    local_adapters_iphelper()
        .into_iter()
        .find(|a| a.mac.to_lowercase() == target)
        .map(|a| (a.is_up, a.ips))
}

/// Lightweight interface status check via pnet (no process spawning).
/// Matches by MAC address and returns (is_up, current_ipv4_ips).
/// This is cheap enough to poll every few seconds.
#[cfg(not(target_os = "windows"))]
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

/// Every IPv4 address currently assigned to any local interface (in-memory,
/// no process spawn). Used by auto-adopt to avoid picking a candidate IP
/// already held by another adapter — an ARP probe can't detect the host's
/// own addresses, so e.g. a WiFi IP on the same /24 as the camera Ethernet
/// would look "free" and collide.
///
/// On Windows this reads through the IP Helper API for the same reason
/// [`quick_status_by_mac`] does; other platforms use pnet.
#[cfg(target_os = "windows")]
pub fn all_local_ipv4() -> Vec<std::net::Ipv4Addr> {
    local_adapters_iphelper()
        .iter()
        .flat_map(|a| &a.ips)
        .filter_map(|ip| ip.address.parse::<std::net::Ipv4Addr>().ok())
        .collect()
}

/// Every IPv4 address currently assigned to any local interface, read
/// from pnet (in-memory, no process spawn). See the Windows variant above.
#[cfg(not(target_os = "windows"))]
pub fn all_local_ipv4() -> Vec<std::net::Ipv4Addr> {
    pnet::datalink::interfaces()
        .iter()
        .flat_map(|i| &i.ips)
        .filter_map(|ipn| match ipn.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(_) => None,
        })
        .collect()
}

/// Get info for a specific interface by name.
pub async fn get_by_name(name: &str) -> Result<InterfaceInfo, AppError> {
    let all = list_all().await?;
    all.into_iter()
        .find(|i| i.name == name)
        .ok_or_else(|| AppError::Network(format!("Interface '{}' not found", name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Camera-port predicates ──────────────────────────────────────

    fn flags_iface(
        is_up: bool,
        is_ethernet: bool,
        is_vpn: bool,
        is_virtual: bool,
    ) -> InterfaceInfo {
        InterfaceInfo {
            name: "t".into(),
            display_name: "t".into(),
            ips: vec![],
            mac: String::new(),
            is_up,
            is_ethernet,
            is_wifi: false,
            is_vpn,
            is_virtual,
        }
    }

    #[test]
    fn wired_predicates_split_link_state_from_structure() {
        // A disconnected wired port is structurally valid but not "up".
        let down_wired = flags_iface(false, true, false, false);
        assert!(is_wired_physical(&down_wired));
        assert!(!is_wired_ethernet(&down_wired));
        // Up and wired satisfies both.
        let up_wired = flags_iface(true, true, false, false);
        assert!(is_wired_physical(&up_wired));
        assert!(is_wired_ethernet(&up_wired));
        // Structure rejects non-Ethernet, VPN, and virtual no matter
        // the link state.
        assert!(!is_wired_physical(&flags_iface(true, false, false, false)));
        assert!(!is_wired_physical(&flags_iface(true, true, true, false)));
        assert!(!is_wired_physical(&flags_iface(true, true, false, true)));
        assert!(!is_wired_ethernet(&flags_iface(true, true, true, false)));
    }

    // ── Enumeration log change-gate ─────────────────────────────────

    #[test]
    fn enumeration_log_first_result_logs_with_zero_suppressed() {
        let mut last = None;
        assert_eq!(enumeration_log_action(&mut last, "a"), Some(0));
    }

    #[test]
    fn enumeration_log_identical_results_are_suppressed_and_counted() {
        let mut last = None;
        let _ = enumeration_log_action(&mut last, "a");
        assert_eq!(enumeration_log_action(&mut last, "a"), None);
        assert_eq!(enumeration_log_action(&mut last, "a"), None);
        assert_eq!(enumeration_log_action(&mut last, "a"), None);
        // A change logs again and reports how many repeats were withheld.
        assert_eq!(enumeration_log_action(&mut last, "b"), Some(3));
        // The counter reset with the new value.
        assert_eq!(enumeration_log_action(&mut last, "c"), Some(0));
        assert_eq!(enumeration_log_action(&mut last, "c"), None);
    }

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
            is_virtual: false,
        };
        let json = serde_json::to_string(&iface).unwrap();
        assert!(json.contains("\"name\":\"eth0\""));
        assert!(json.contains("\"is_up\":true"));
        assert!(json.contains("\"is_vpn\":false"));
        assert!(json.contains("\"is_virtual\":false"));
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

        // ── physical-medium classification ────────────────────────────

        #[test]
        fn physical_medium_numeric_wireless_set() {
            for n in [1u64, 8, 9, 10, 12, 13, 20] {
                assert!(
                    physical_medium_is_wireless(Some(n), ""),
                    "NdisPhysicalMedium {n} must classify wireless"
                );
            }
            // 14 = physical 802.3; 2 = CableModem — wired media stay wired.
            assert!(!physical_medium_is_wireless(Some(14), ""));
            assert!(!physical_medium_is_wireless(Some(2), ""));
        }

        #[test]
        fn physical_medium_numeric_beats_string() {
            // A conclusive wired numeric wins even against a wireless string.
            assert!(!physical_medium_is_wireless(Some(14), "Native 802.11"));
        }

        #[test]
        fn physical_medium_string_fallback_variants() {
            assert!(physical_medium_is_wireless(None, "Native 802.11"));
            assert!(physical_medium_is_wireless(Some(0), "Wireless LAN"));
            assert!(physical_medium_is_wireless(None, "wireless wan"));
            assert!(physical_medium_is_wireless(None, "802.11"));
        }

        #[test]
        fn physical_medium_unspecified_falls_back_to_not_wireless() {
            assert!(!physical_medium_is_wireless(None, ""));
            assert!(!physical_medium_is_wireless(Some(0), "Unspecified"));
            assert!(!physical_medium_is_wireless(Some(0), ""));
        }

        #[test]
        fn parse_adapter_emulated_802_3_wireless_dongle_not_ethernet() {
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "Wi-Fi Dongle",
                "Description": "Generic USB Wireless Adapter",
                "MacAddress": "AA-BB-CC-00-11-22",
                "MediaType": "802.3",
                "NdisPhysicalMedium": 9,
                "Status": "Up",
                "IPs": []
            }"#,
            )
            .unwrap();
            let iface = parse_adapter(&json, false);
            assert!(
                !iface.is_ethernet,
                "wireless physical medium must override logical 802.3"
            );
            assert!(iface.is_wifi);
        }

        #[test]
        fn parse_adapter_physical_802_3_stays_ethernet() {
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "Ethernet",
                "Description": "Intel(R) Ethernet Connection I219-V",
                "MacAddress": "AA-BB-CC-DD-EE-FF",
                "MediaType": "802.3",
                "PhysicalMediaType": "802.3",
                "NdisPhysicalMedium": 14,
                "Status": "Up",
                "IPs": []
            }"#,
            )
            .unwrap();
            let iface = parse_adapter(&json, false);
            assert!(iface.is_ethernet);
            assert!(!iface.is_wifi);
        }

        #[test]
        fn parse_adapter_wireless_string_overrides_logical_802_3() {
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "Mobile Broadband",
                "Description": "WWAN Modem",
                "MacAddress": "AA-BB-CC-33-44-55",
                "MediaType": "802.3",
                "PhysicalMediaType": "Wireless WAN",
                "Status": "Up",
                "IPs": []
            }"#,
            )
            .unwrap();
            let iface = parse_adapter(&json, false);
            assert!(!iface.is_ethernet);
            assert!(iface.is_wifi);
        }

        #[test]
        fn parse_adapter_missing_physical_fields_keeps_today_behavior() {
            // Legacy JSON without either physical-medium field parses
            // exactly as before the physical-medium override existed.
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "Ethernet",
                "Description": "Realtek PCIe GbE",
                "MacAddress": "11-22-33-44-55-66",
                "MediaType": "802.3",
                "Status": "Up",
                "IPs": []
            }"#,
            )
            .unwrap();
            let iface = parse_adapter(&json, false);
            assert!(iface.is_ethernet);
            assert!(!iface.is_wifi);
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
                "Status": "Up",
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
        fn parse_adapter_disconnected() {
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "Ethernet",
                "Description": "Realtek PCIe GbE",
                "MacAddress": "11-22-33-44-55-66",
                "MediaType": "802.3",
                "Status": "Disconnected",
                "IPs": []
            }"#,
            )
            .unwrap();
            let iface = parse_adapter(&json, false);
            assert!(iface.is_ethernet);
            assert!(!iface.is_up, "Disconnected adapter must report is_up=false");
            assert!(iface.ips.is_empty());
        }

        #[test]
        fn parse_adapter_vpn() {
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "Tailscale",
                "Description": "Tailscale Tunnel",
                "MacAddress": "",
                "MediaType": "",
                "Status": "Up",
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

        #[test]
        fn parse_adapter_reads_virtual_flag() {
            // A virtual adapter whose description misses the VPN keyword
            // list (e.g. a Hyper-V/WSL vEthernet switch) must still be
            // marked is_virtual so the ghost machinery can see its subnet.
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "vEthernet (WSL)",
                "Description": "Hyper-V Virtual Ethernet Adapter",
                "MacAddress": "00-15-5D-00-00-01",
                "MediaType": "802.3",
                "Status": "Up",
                "Virtual": true,
                "IPs": [{"Address": "172.28.0.1", "PrefixLength": 20}]
            }"#,
            )
            .unwrap();
            let iface = parse_adapter(&json, false);
            assert!(iface.is_virtual, "Virtual=true must set is_virtual");
            assert!(
                !iface.is_vpn,
                "non-keyword description must not be classified VPN"
            );
        }

        #[test]
        fn parse_adapter_virtual_defaults_false() {
            // A real physical adapter reports Virtual=false (or omits it).
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "Ethernet",
                "Description": "Intel(R) I210 Gigabit Ethernet",
                "MacAddress": "AA-BB-CC-DD-EE-FF",
                "MediaType": "802.3",
                "Status": "Up",
                "Virtual": false,
                "IPs": []
            }"#,
            )
            .unwrap();
            let iface = parse_adapter(&json, false);
            assert!(!iface.is_virtual);
            assert!(!iface.is_vpn);
        }

        #[test]
        fn parse_adapter_vpn_from_description_when_physical() {
            // Defensive branch: a VPN driver that registers as physical
            // (Virtual=false) is still flagged is_vpn from its description,
            // even though list_physical passes force_vpn=false.
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                "Name": "Ethernet 3",
                "Description": "Fortinet SSL VPN Virtual Ethernet Adapter",
                "MacAddress": "",
                "MediaType": "802.3",
                "Status": "Up",
                "Virtual": false,
                "IPs": []
            }"#,
            )
            .unwrap();
            let iface = parse_adapter(&json, false);
            assert!(
                iface.is_vpn,
                "VPN keyword in description must set is_vpn even when Virtual=false"
            );
            assert!(!iface.is_virtual);
        }
    }

    // ── Platform-independent tests ──────────────────────────────────

    #[tokio::test]
    async fn list_physical_returns_ok() {
        // Should succeed on any platform (may be empty in CI)
        let result = list_physical().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn list_all_returns_ok() {
        let result = list_all().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn list_all_adapters_returns_ok() {
        // Full enumeration (physical + virtual) must succeed on any
        // platform; may be empty in CI.
        let result = list_all_adapters().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn get_by_name_nonexistent_returns_err() {
        let result = get_by_name("__nonexistent_interface_42__").await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("not found"));
    }

    #[test]
    fn validation_cache_remembers_within_ttl() {
        let name = "__ttl_cache_probe__";
        assert!(!recently_validated(name));
        remember_validated(name);
        assert!(recently_validated(name));
    }

    #[tokio::test]
    async fn validate_interface_name_rejects_unknown() {
        let result = validate_interface_name("__nonexistent_interface_43__").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unknown network interface"));
    }
}
