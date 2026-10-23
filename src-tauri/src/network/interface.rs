use serde::Serialize;
#[cfg(target_os = "windows")]
use std::net::IpAddr;

use crate::error::AppError;

/// Windows' NetAdapter/CIM provider is prone to hanging when multiple
/// PowerShell queries run concurrently. The app has several independent
/// interface pollers, so keep the shared provider boundary single-flight.
#[cfg(target_os = "windows")]
static ADAPTER_QUERY_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const ADAPTER_QUERY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
const SNAPSHOT_TTL: std::time::Duration = std::time::Duration::from_secs(5);
pub(crate) static NATIVE_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(windows)]
pub(crate) static PROVIDER_CALLS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

fn adapter_timeout() -> AppError {
    AppError::Network("Adapter enumeration timed out after 10s including queue wait; retry when the adapter provider recovers".into())
}

#[cfg(target_os = "windows")]
async fn with_adapter_query_lock<T, F, Fut>(
    gate: &tokio::sync::Mutex<()>,
    query: F,
) -> Result<T, AppError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, AppError>>,
{
    tokio::time::timeout(ADAPTER_QUERY_DEADLINE, async {
        let _query_guard = gate.lock().await;
        query().await
    })
    .await
    .map_err(|_| adapter_timeout())?
}

struct CachedAdapters {
    at: tokio::time::Instant,
    generation: u64,
    adapters: Vec<InterfaceInfo>,
}

#[derive(Default)]
struct AdapterSnapshot {
    value: std::sync::Mutex<Option<CachedAdapters>>,
    refresh: tokio::sync::Mutex<()>,
    generation: std::sync::atomic::AtomicU64,
    qualified: std::sync::Mutex<Vec<(NativeIdentity, InterfaceInfo)>>,
    topology: std::sync::Mutex<Vec<NativeIdentity>>,
    // The same snapshot holds source ownership. It is refreshed from IP Helper
    // at the proof boundary; the metadata TTL never authorizes a stale source.
    #[cfg(target_os = "windows")]
    sources: std::sync::Mutex<Vec<(u32, std::net::Ipv4Addr)>>,
}

impl AdapterSnapshot {
    fn cached(&self) -> Option<Vec<InterfaceInfo>> {
        let value = self.value.lock().unwrap_or_else(|p| p.into_inner());
        value
            .as_ref()
            .filter(|v| {
                v.generation == self.generation.load(std::sync::atomic::Ordering::Acquire)
                    && v.at.elapsed() < SNAPSHOT_TTL
            })
            .map(|v| v.adapters.clone())
    }

    #[cfg(any(windows, test))]
    fn invalidate(&self) {
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        *self.value.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.qualified
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    async fn get<F, Fut>(&self, query: F) -> Result<Vec<InterfaceInfo>, AppError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<InterfaceInfo>, AppError>>,
    {
        tokio::time::timeout(ADAPTER_QUERY_DEADLINE, async {
            if let Some(value) = self.cached() {
                return Ok(value);
            }
            let _refresh = self.refresh.lock().await;
            if let Some(value) = self.cached() {
                return Ok(value);
            }
            let generation = self.generation.load(std::sync::atomic::Ordering::Acquire);
            let adapters = query().await?;
            let mut value = self.value.lock().unwrap_or_else(|p| p.into_inner());
            if generation != self.generation.load(std::sync::atomic::Ordering::Acquire) {
                return Err(AppError::Network(
                    "Adapters changed during enumeration; retry".into(),
                ));
            }
            *value = Some(CachedAdapters {
                at: tokio::time::Instant::now(),
                generation,
                adapters: adapters.clone(),
            });
            Ok(adapters)
        })
        .await
        .map_err(|_| adapter_timeout())?
    }

    #[cfg(target_os = "windows")]
    fn source_matches(
        &self,
        index: u32,
        source: std::net::Ipv4Addr,
        fresh: Vec<(u32, std::net::Ipv4Addr)>,
    ) -> bool {
        let mut sources = self.sources.lock().unwrap_or_else(|p| p.into_inner());
        *sources = fresh;
        source_matches_index(index, source, sources.iter().copied())
    }
}

static ADAPTER_SNAPSHOT: std::sync::LazyLock<AdapterSnapshot> =
    std::sync::LazyLock::new(AdapterSnapshot::default);

/// Enumeration and qualification share in-flight work and the existing TTL.
/// Native identity/topology changes retire it; failures never reuse stale data.
async fn adapter_snapshot() -> Result<Vec<InterfaceInfo>, AppError> {
    // Establish identity before get() captures its generation. The first
    // notification must not invalidate its own cold metadata enumeration.
    #[cfg(windows)]
    observe_topology(&ADAPTER_SNAPSHOT, &local_adapters_iphelper()?);
    ADAPTER_SNAPSHOT
        .get(|| async {
            #[cfg(target_os = "windows")]
            {
                query_adapters_windows().await
            }
            #[cfg(not(target_os = "windows"))]
            {
                list_all_pnet()
            }
        })
        .await
        .and_then(current_adapter_addresses)
}

/// Cached metadata never masks an address add/remove between notifications.
fn current_adapter_addresses(adapters: Vec<InterfaceInfo>) -> Result<Vec<InterfaceInfo>, AppError> {
    #[cfg(target_os = "windows")]
    {
        overlay_adapter_addresses(adapters, local_adapters_iphelper())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(adapters)
    }
}

#[cfg(target_os = "windows")]
fn overlay_adapter_addresses(
    mut adapters: Vec<InterfaceInfo>,
    current: Result<Vec<NativeAdapter>, AppError>,
) -> Result<Vec<InterfaceInfo>, AppError> {
    // An unavailable native snapshot is not evidence that addresses vanished.
    // In particular, static Apply must not replace addresses it cannot restore.
    let current = current?;
    for adapter in &mut adapters {
        // MAC-less VPN/tunnel metadata still feeds subnet exclusions.
        // It cannot be selected for Ethernet proof; preserve its query data.
        if adapter.mac.is_empty() {
            continue;
        }
        if let Some(native) = current
            .iter()
            .find(|n| !n.mac.is_empty() && n.mac.eq_ignore_ascii_case(&adapter.mac))
        {
            adapter.is_up = native.is_up;
            adapter.ips = native.ips.clone();
        } else {
            adapter.is_up = false;
            adapter.ips.clear();
        }
    }
    Ok(adapters)
}

/// How long a validated interface name stays trusted before the next
/// `validate_interface_name` re-enumerates. Bounds staleness (an adapter
/// removed within the window still validates) while keeping the 2 s
/// auto-adopt loop from spawning PowerShell twice per cycle forever.
#[cfg_attr(windows, allow(dead_code))]
const VALIDATION_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// Names validated within [`VALIDATION_TTL`], with the time they were
/// confirmed present. Read on the hot path; the enumeration behind it is
/// the expensive part being skipped.
static VALIDATED_NAMES: std::sync::Mutex<
    Option<std::collections::HashMap<String, std::time::Instant>>,
> = std::sync::Mutex::new(None);

#[cfg_attr(windows, allow(dead_code))]
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

#[cfg_attr(windows, allow(dead_code))]
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
    #[cfg(windows)]
    {
        native_by_alias(&read_native().await?, name)?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        if recently_validated(name) {
            return Ok(());
        }
        if list_physical().await?.iter().any(|i| i.name == name) {
            remember_validated(name);
            Ok(())
        } else {
            Err(AppError::Network(format!(
                "Unknown network interface: {name}"
            )))
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IpInfo {
    pub address: String,
    pub prefix: u8,
    pub subnet: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub name: String,
    pub display_name: String,
    pub description: String,
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
    Ok(adapter_snapshot()
        .await?
        .into_iter()
        .filter(|i| {
            if cfg!(target_os = "windows") {
                !i.is_virtual
            } else {
                !i.is_vpn
            }
        })
        .collect())
}

/// List VPN interfaces only.
pub async fn list_vpn() -> Result<Vec<InterfaceInfo>, AppError> {
    Ok(adapter_snapshot()
        .await?
        .into_iter()
        .filter(|i| i.is_vpn && (!cfg!(target_os = "windows") || i.is_virtual))
        .collect())
}

/// List all network interfaces with their details (physical + VPN).
pub async fn list_all() -> Result<Vec<InterfaceInfo>, AppError> {
    Ok(adapter_snapshot()
        .await?
        .into_iter()
        .filter(|i| !cfg!(target_os = "windows") || !i.is_virtual || i.is_vpn)
        .collect())
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
    adapter_snapshot().await
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
        description: description.to_string(),
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
    PROVIDER_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                Guid = [string]$adapter.InterfaceGuid
                Index = $adapter.ifIndex
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
    // The deadline includes the shared provider-lock wait and drops/kills
    // the child on expiry. The snapshot also bounds its refresh-lock wait.
    let output = with_adapter_query_lock(&ADAPTER_QUERY_LOCK, || async {
        super::async_cmd("powershell")
            .args(["-NoProfile", "-Command", &script])
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|e| AppError::Network(format!("Failed to run PowerShell: {e}")))
    })
    .await?;

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

#[cfg(windows)]
fn qualified_descriptor(json: &serde_json::Value, native: &NativeAdapter) -> Option<InterfaceInfo> {
    if !json["Virtual"].is_boolean() || !json["MediaType"].is_string() {
        return None;
    }
    let info = parse_adapter(json, false);
    (native.alias == info.name
        && native.mac.eq_ignore_ascii_case(&info.mac)
        && json["Index"].as_u64() == Some(native.index as u64)
        && json["Guid"]
            .as_str()
            .is_some_and(|guid| guid_key(guid) == guid_key(&native.guid)))
    .then_some(info)
}

#[cfg(target_os = "windows")]
async fn query_adapters_windows() -> Result<Vec<InterfaceInfo>, AppError> {
    let generation = ADAPTER_SNAPSHOT
        .generation
        .load(std::sync::atomic::Ordering::Acquire);
    let stdout = run_adapter_query("$true").await?;
    {
        let mut last = LAST_ENUM_LOG
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(suppressed) = enumeration_log_action(&mut last, &stdout) {
            if suppressed == 0 {
                log::info!("Windows adapter enumeration: {}", stdout);
            } else {
                log::info!(
                    "Windows adapter enumeration (unchanged {} time(s) since last log): {}",
                    suppressed,
                    stdout
                );
            }
        }
    }
    let adapters = parse_adapter_json(&stdout)?;
    let native = read_native().await?;
    let qualified = native
        .iter()
        .flat_map(|adapter| {
            adapters.iter().filter_map(|json| {
                qualified_descriptor(json, adapter).map(|info| (adapter.identity(), info))
            })
        })
        .collect();
    publish_qualification(&ADAPTER_SNAPSHOT, generation, &native, qualified);
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
                description: iface.description.clone(),
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

pub(crate) type AddressFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, AppError>> + Send + 'a>>;

/// One object-safe OS seam; NetworkManager remains non-generic.
pub(crate) trait AddressIo: Send + Sync {
    fn native(&self) -> AddressFuture<'_, Vec<NativeAdapter>>;
    fn add<'a>(
        &'a self,
        adapter: &'a NativeAdapter,
        ip: &'a str,
        mask: &'a str,
    ) -> AddressFuture<'a, ()>;
    fn remove<'a>(&'a self, adapter: &'a NativeAdapter, ip: &'a str) -> AddressFuture<'a, ()>;
    fn persist_intent(
        &self,
        config: &crate::config::AppConfig,
        subnet: &str,
        row: crate::config::AdoptedMeta,
    ) -> Result<(), AppError> {
        self.persist_binding(config, subnet, row)
    }
    fn persist_binding(
        &self,
        config: &crate::config::AppConfig,
        subnet: &str,
        row: crate::config::AdoptedMeta,
    ) -> Result<(), AppError> {
        config.set_binding(subnet, row)
    }
    fn forget_unowned_binding(
        &self,
        config: &crate::config::AppConfig,
        subnet: &str,
        expected: &crate::config::AdoptedMeta,
    ) -> Result<(), AppError> {
        config.forget_unowned_binding(subnet, expected)
    }
    fn claim(&self, config: &crate::config::AppConfig, ip: &str) -> Result<(), AppError> {
        config.claim_binding(ip)
    }
    fn forget_completed_removal(
        &self,
        config: &crate::config::AppConfig,
        subnet: &str,
        expected: &crate::config::AdoptedMeta,
    ) -> Result<(), AppError> {
        config.forget_completed_removal(subnet, expected)
    }
    fn persist_primary(
        &self,
        config: &crate::config::AppConfig,
        mac: &str,
        cidr: &str,
    ) -> Result<(), AppError> {
        config.set_primary_address(mac, cidr)
    }
    fn descriptor(&self, native: &NativeAdapter) -> Option<InterfaceInfo> {
        ADAPTER_SNAPSHOT
            .qualified
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(id, _)| *id == native.identity())
            .map(|(_, info)| native.overlay(info))
    }
    fn qualify(&self) -> AddressFuture<'_, ()> {
        // A cold caller joins the query already running for startup, display
        // or the watcher instead of cancelling its metadata generation.
        Box::pin(async { adapter_snapshot().await.map(|_| ()) })
    }
}

pub(crate) struct RealAddressIo;

/// Single timeout for all operation native reads; a dropped late result has no
/// continuation capable of writing. Production native calls run off the executor.
pub(crate) async fn read_native_with(io: &dyn AddressIo) -> Result<Vec<NativeAdapter>, AppError> {
    NATIVE_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    tokio::time::timeout(std::time::Duration::from_secs(2), io.native())
        .await
        .map_err(|_| AppError::Network("Native adapter observation timed out after 2s".into()))?
}
#[cfg(windows)]
pub(crate) async fn read_native() -> Result<Vec<NativeAdapter>, AppError> {
    read_native_with(&RealAddressIo).await
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct NativeIdentity {
    pub guid: String,
    pub index: u32,
    pub mac: String,
    pub alias: String,
}
fn guid_key(guid: &str) -> String {
    guid.trim_matches(['{', '}']).to_ascii_lowercase()
}
impl NativeAdapter {
    pub(crate) fn identity(&self) -> NativeIdentity {
        NativeIdentity {
            guid: guid_key(&self.guid),
            index: self.index,
            mac: self.mac.replace('-', ":").to_ascii_lowercase(),
            alias: self.alias.clone(),
        }
    }
    pub(crate) fn overlay(&self, info: &InterfaceInfo) -> InterfaceInfo {
        InterfaceInfo {
            name: self.alias.clone(),
            display_name: self.alias.clone(),
            mac: self.mac.clone(),
            is_up: self.is_up,
            ips: self.ips.clone(),
            ..info.clone()
        }
    }
}
fn topology(adapters: &[NativeAdapter]) -> Vec<NativeIdentity> {
    let mut ids: Vec<_> = adapters.iter().map(NativeAdapter::identity).collect();
    ids.sort();
    ids
}
pub(crate) fn native_by_alias<'a>(
    adapters: &'a [NativeAdapter],
    alias: &str,
) -> Result<&'a NativeAdapter, AppError> {
    let matches: Vec<_> = adapters.iter().filter(|a| a.alias == alias).collect();
    match matches.as_slice() {
        [adapter] if !alias.is_empty() && adapter.index != 0 => Ok(adapter),
        [] => Err(AppError::Network(format!(
            "Unknown network interface: {alias}"
        ))),
        _ => Err(AppError::Network(
            "Native adapter alias/index is ambiguous or unavailable".into(),
        )),
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OperationSnapshot {
    pub selected: NativeAdapter,
    pub all: Vec<NativeAdapter>,
    pub iface: InterfaceInfo,
    pub candidates: Vec<InterfaceInfo>,
}
pub(crate) fn select_native<'a>(
    all: &'a [NativeAdapter],
    mac: &str,
) -> Result<&'a NativeAdapter, AppError> {
    let mac = mac.replace('-', ":").to_ascii_lowercase();
    let matches: Vec<_> = all
        .iter()
        .filter(|a| !a.mac.is_empty() && a.identity().mac == mac)
        .collect();
    match matches.as_slice() {
        [] => Err(AppError::Network(
            "Selected Ethernet adapter unavailable".into(),
        )),
        [a] if a.index != 0
            && !a.guid.is_empty()
            && !a.alias.is_empty()
            && all
                .iter()
                .filter(|n| {
                    n.index == a.index
                        || n.alias == a.alias
                        || guid_key(&n.guid) == guid_key(&a.guid)
                })
                .count()
                == 1 =>
        {
            Ok(a)
        }
        _ => Err(AppError::Network(
            "Native adapter identity/index is missing or ambiguous".into(),
        )),
    }
}
pub(crate) async fn operation_snapshot(
    io: &dyn AddressIo,
    mac: &str,
) -> Result<OperationSnapshot, AppError> {
    operation_snapshot_traced(io, mac, None).await
}
pub(super) async fn operation_snapshot_traced(
    io: &dyn AddressIo,
    mac: &str,
    trace: Option<&super::AddressTrace>,
) -> Result<OperationSnapshot, AppError> {
    if let Some(t) = trace {
        t.native_call();
    }
    let mut all = read_native_with(io).await?;
    let before = select_native(&all, mac)?.identity();
    if io.descriptor(select_native(&all, mac)?).is_none() {
        if let Some(t) = trace {
            t.provider_call();
        }
        io.qualify().await?;
        if let Some(t) = trace {
            t.native_call();
        }
        all = read_native_with(io).await?;
        if select_native(&all, mac)?.identity() != before {
            return Err(AppError::Network(
                "Adapter changed during qualification; retry".into(),
            ));
        }
    }
    snapshot_from_native(io, mac, all)
}
pub(crate) fn snapshot_from_native(
    io: &dyn AddressIo,
    mac: &str,
    all: Vec<NativeAdapter>,
) -> Result<OperationSnapshot, AppError> {
    let selected = select_native(&all, mac)?.clone();
    let iface = io
        .descriptor(&selected)
        .filter(is_wired_physical)
        .ok_or_else(|| {
            AppError::Network("Selected adapter requires physical Ethernet qualification".into())
        })?;
    let candidates = all
        .iter()
        .filter_map(|a| io.descriptor(a))
        .filter(is_wired_physical)
        .collect();
    Ok(OperationSnapshot {
        selected,
        all,
        iface,
        candidates,
    })
}

/// Native observations include unclassified and MAC-less adapters. They remain
/// conservative collision inputs, even when no descriptor can be published.
pub(crate) fn native_conflicts(
    snapshot: &OperationSnapshot,
    io: &dyn AddressIo,
) -> Vec<ipnetwork::Ipv4Network> {
    snapshot
        .all
        .iter()
        .filter(|a| a.identity() != snapshot.selected.identity())
        .filter(|a| io.descriptor(a).is_none_or(|i| !is_wired_physical(&i)))
        .flat_map(|a| &a.ips)
        .filter_map(|ip| {
            ip.address
                .parse()
                .ok()
                .and_then(|address| ipnetwork::Ipv4Network::new(address, ip.prefix).ok())
        })
        .collect()
}

#[cfg(windows)]
pub(crate) async fn notification_topology_changed() -> Result<bool, AppError> {
    let all = read_native().await?;
    Ok(observe_topology(&ADAPTER_SNAPSHOT, &all))
}
#[cfg(any(windows, test))]
fn observe_topology(cache: &AdapterSnapshot, all: &[NativeAdapter]) -> bool {
    let next = topology(all);
    let mut current = cache.topology.lock().unwrap_or_else(|p| p.into_inner());
    let changed = *current != next;
    if changed {
        cache.invalidate();
        *current = next;
    }
    changed
}

#[cfg_attr(not(windows), allow(dead_code))]
fn publish_qualification(
    cache: &AdapterSnapshot,
    generation: u64,
    native: &[NativeAdapter],
    qualified: Vec<(NativeIdentity, InterfaceInfo)>,
) {
    // Share the topology lock with invalidation so an older query cannot
    // publish qualification after a replacement/index change retires it.
    let mut current = cache.topology.lock().unwrap_or_else(|p| p.into_inner());
    if generation == cache.generation.load(std::sync::atomic::Ordering::Acquire) {
        *cache.qualified.lock().unwrap_or_else(|p| p.into_inner()) = qualified;
        *current = topology(native);
    }
}

/// A local adapter's MAC, up-state, and IPv4 addresses as read from the IP
/// Helper API. Backs [`quick_status_by_mac`] and [`all_local_ipv4`] on
/// Windows without touching pnet.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct NativeAdapter {
    pub index: u32,
    pub guid: String,
    pub alias: String,
    pub dhcp: bool,
    /// Colon-separated, matching the format `parse_adapter` produces, so
    /// callers can compare MACs regardless of which enumeration path built
    /// the value they hold.
    pub mac: String,
    pub is_up: bool,
    pub ips: Vec<IpInfo>,
    pub gateways: Vec<String>,
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
/// such import. Failures remain errors, distinct from a valid empty snapshot.
#[cfg(target_os = "windows")]
pub(super) fn local_adapters_iphelper() -> Result<Vec<NativeAdapter>, AppError> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_INCLUDE_GATEWAYS;
    local_adapters_iphelper_with(|buffer, size| unsafe {
        GetAdaptersAddresses(AF_INET as u32, flags, std::ptr::null(), buffer, size)
    })
}

#[cfg(target_os = "windows")]
fn local_adapters_iphelper_with(
    mut query: impl FnMut(
        *mut windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH,
        &mut u32,
    ) -> u32,
) -> Result<Vec<NativeAdapter>, AppError> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA};
    use windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    // IF_OPER_STATUS value IfOperStatusUp — the adapter is operational.
    const IF_OPER_STATUS_UP: i32 = 1;

    // Start at the 15 KB Microsoft recommends and grow on overflow. Back the
    // buffer with u64 so it meets the 8-byte alignment the adapter structs
    // need — a Vec<u8> would only be 1-byte aligned.
    let mut size: u32 = 15 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    let mut ret = ERROR_BUFFER_OVERFLOW;
    for _ in 0..4 {
        buf.clear();
        buf.resize((size as usize).div_ceil(8), 0);
        ret = query(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH, &mut size);
        if ret != ERROR_BUFFER_OVERFLOW {
            break;
        }
    }
    if ret == ERROR_NO_DATA {
        return Ok(Vec::new());
    }
    if ret != 0 {
        return Err(AppError::Network(format!(
            "GetAdaptersAddresses failed with code {ret}"
        )));
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

        let mut gateways = Vec::new();
        let mut gateway = ad.FirstGatewayAddress;
        while !gateway.is_null() {
            let row = unsafe { &*gateway };
            let sa = row.Address.lpSockaddr;
            if !sa.is_null() && unsafe { (*sa).sa_family } == AF_INET {
                let octets = unsafe { (*(sa as *const SOCKADDR_IN)).sin_addr.S_un.S_un_b };
                let address =
                    std::net::Ipv4Addr::new(octets.s_b1, octets.s_b2, octets.s_b3, octets.s_b4);
                if !address.is_unspecified() && !gateways.contains(&address.to_string()) {
                    gateways.push(address.to_string());
                }
            }
            gateway = row.Next;
        }
        adapters.push(NativeAdapter {
            index: unsafe { ad.Anonymous1.Anonymous.IfIndex },
            guid: if ad.AdapterName.is_null() {
                String::new()
            } else {
                unsafe { std::ffi::CStr::from_ptr(ad.AdapterName.cast()) }
                    .to_string_lossy()
                    .into_owned()
            },
            alias: if ad.FriendlyName.is_null() {
                String::new()
            } else {
                let mut len = 0;
                while len < 32768 && unsafe { *ad.FriendlyName.add(len) } != 0 {
                    len += 1;
                }
                String::from_utf16_lossy(unsafe {
                    std::slice::from_raw_parts(ad.FriendlyName, len)
                })
            },
            dhcp: unsafe { ad.Anonymous2.Flags }
                & windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_DHCP_ENABLED
                != 0,
            mac,
            is_up,
            ips,
            gateways,
        });
        cur = ad.Next;
    }
    Ok(adapters)
}

#[cfg(windows)]
pub(crate) async fn native_dhcp_state(alias: &str) -> Result<bool, AppError> {
    Ok(native_by_alias(&read_native().await?, alias)?.dhcp)
}

/// One native snapshot for the selected MAC's index and media state. Duplicate
/// MACs and enumeration failure are unavailable; never substitute another NIC.
pub(crate) fn quick_link_by_mac(mac: &str) -> Option<(u32, bool)> {
    let target = mac.replace('-', ":");
    #[cfg(target_os = "windows")]
    let matches: Vec<_> = local_adapters_iphelper()
        .ok()?
        .into_iter()
        .filter(|a| !a.mac.is_empty() && a.mac.eq_ignore_ascii_case(&target))
        .map(|a| (a.index, a.is_up))
        .collect();
    #[cfg(not(target_os = "windows"))]
    let matches: Vec<_> = pnet::datalink::interfaces()
        .into_iter()
        .filter(|a| {
            a.mac
                .is_some_and(|m| m.to_string().eq_ignore_ascii_case(&target))
        })
        .map(|a| (a.index, a.is_up()))
        .collect();
    match matches.as_slice() {
        [state] if state.0 != 0 => Some(*state),
        _ => None,
    }
}

/// Resolve the current adapter's IPv4 index without spawning PowerShell.
pub(crate) fn index_for_mac(mac: &str) -> Option<u32> {
    let target = mac.replace('-', ":");
    #[cfg(target_os = "windows")]
    let indices: Vec<u32> = local_adapters_iphelper()
        .ok()?
        .into_iter()
        .filter(|a| !a.mac.is_empty() && a.mac.eq_ignore_ascii_case(&target))
        .map(|a| a.index)
        .collect();
    #[cfg(not(target_os = "windows"))]
    let indices: Vec<u32> = pnet::datalink::interfaces()
        .into_iter()
        .filter(|a| {
            a.mac
                .is_some_and(|m| m.to_string().eq_ignore_ascii_case(&target))
        })
        .map(|a| a.index)
        .collect();
    match indices.as_slice() {
        [index] if *index != 0 => Some(*index),
        _ => None,
    }
}

/// SourceAddress selects an interface in ResolveIpNetEntry2: reject an
/// address shared by adapters as well as a missing/wrong-index source.
#[cfg(any(target_os = "windows", test))]
fn source_matches_index(
    index: u32,
    source: std::net::Ipv4Addr,
    addresses: impl Iterator<Item = (u32, std::net::Ipv4Addr)>,
) -> bool {
    let mut owners = addresses.filter(|(_, address)| *address == source);
    index != 0 && owners.next() == Some((index, source)) && owners.next().is_none()
}

#[cfg(target_os = "windows")]
pub(crate) fn source_matches_interface(index: u32, source: std::net::Ipv4Addr) -> bool {
    ADAPTER_SNAPSHOT.source_matches(
        index,
        source,
        local_adapters_iphelper()
            .unwrap_or_default()
            .into_iter()
            .flat_map(|adapter| {
                let index = adapter.index;
                adapter
                    .ips
                    .into_iter()
                    .filter_map(move |ip| ip.address.parse().ok().map(|address| (index, address)))
            })
            .collect(),
    )
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
        .ok()?
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
        .unwrap_or_default()
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

/// Host identity for discovery. Include every adapter, even one without an IP
/// or with its link down: an address collision on another interface does not
/// make an Ethernet peer the host, and a DHCP change does not change its MAC.
pub(crate) fn local_adapter_macs() -> std::collections::HashSet<[u8; 6]> {
    #[cfg(windows)]
    let macs = local_adapters_iphelper()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|a| super::parse_mac_bytes(&a.mac));
    #[cfg(not(windows))]
    let macs = pnet::datalink::interfaces()
        .into_iter()
        .filter_map(|a| a.mac.map(|mac| mac.octets()));
    macs.filter(|mac| *mac != [0; 6] && mac[0] & 1 == 0)
        .collect()
}

/// Get info for a specific interface by name.
pub async fn get_by_name(name: &str) -> Result<InterfaceInfo, AppError> {
    #[cfg(windows)]
    {
        let all = read_native().await?;
        let native = native_by_alias(&all, name).map_err(|e| {
            if all.iter().all(|n| n.alias != name) {
                AppError::Network(format!("Interface '{name}' not found"))
            } else {
                e
            }
        })?;
        if let Some(info) = RealAddressIo.descriptor(native) {
            return Ok(info);
        }
        RealAddressIo.qualify().await?;
        let fresh = read_native().await?;
        let current = native_by_alias(&fresh, name)?;
        if current.identity() != native.identity() {
            return Err(AppError::Network(
                "Adapter changed during qualification".into(),
            ));
        }
        RealAddressIo.descriptor(current).ok_or_else(|| {
            AppError::Network(format!("Interface '{name}' not found or unqualified"))
        })
    }
    #[cfg(not(windows))]
    {
        list_all()
            .await?
            .into_iter()
            .find(|i| i.name == name)
            .ok_or_else(|| AppError::Network(format!("Interface '{name}' not found")))
    }
}

/// Exercise the native error conversion and metadata overlay together, without
/// querying or mutating the host's adapters.
#[cfg(all(test, target_os = "windows"))]
pub(super) fn failed_native_snapshot(
    metadata: Vec<InterfaceInfo>,
) -> Result<Vec<InterfaceInfo>, AppError> {
    use windows_sys::Win32::Foundation::ERROR_NOT_ENOUGH_MEMORY;
    overlay_adapter_addresses(
        metadata,
        local_adapters_iphelper_with(|_, _| ERROR_NOT_ENOUGH_MEMORY),
    )
}

#[cfg(test)]
pub(super) mod address_test_io {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    };
    #[derive(Clone, Copy, Default)]
    pub enum Effect {
        #[default]
        Apply,
        Unchanged,
        ErrorAfter,
        TimeoutAfter,
    }
    pub struct FakeAddressIo {
        pub table: Mutex<Vec<NativeAdapter>>,
        cache: AdapterSnapshot,
        pub reads: AtomicUsize,
        pub providers: AtomicUsize,
        pub writes: Mutex<Vec<(bool, String)>>,
        pub saves: Mutex<Vec<String>>,
        pub fail_read: AtomicBool,
        pub fail_read_at: AtomicUsize,
        pub fail_save_at: AtomicUsize,
        pub delay: Mutex<std::time::Duration>,
        pub effect: Mutex<Effect>,
        pub legacy_callbacks: AtomicBool,
        pub external_address: AtomicBool,
        pub replace_after_write: AtomicBool,
        pub post_delay: Mutex<std::time::Duration>,
    }
    impl FakeAddressIo {
        pub fn new(ips: &[&str]) -> Arc<Self> {
            let native = NativeAdapter {
                guid: "guid-a".into(),
                index: 7,
                alias: "Ethernet".into(),
                mac: "40:cd:3a:00:00:01".into(),
                is_up: true,
                dhcp: false,
                gateways: vec![],
                ips: ips
                    .iter()
                    .map(|address| IpInfo {
                        address: (*address).into(),
                        prefix: 24,
                        subnet: "192.0.2.0/24".into(),
                    })
                    .collect(),
            };
            let iface = InterfaceInfo {
                name: native.alias.clone(),
                display_name: native.alias.clone(),
                description: "qualified physical Ethernet".into(),
                mac: native.mac.clone(),
                is_up: true,
                ips: vec![],
                is_ethernet: true,
                is_wifi: false,
                is_vpn: false,
                is_virtual: false,
            };
            let cache = AdapterSnapshot::default();
            *cache.qualified.lock().unwrap() = vec![(native.identity(), iface.clone())];
            *cache.topology.lock().unwrap() = topology(std::slice::from_ref(&native));
            *cache.value.lock().unwrap() = Some(CachedAdapters {
                at: tokio::time::Instant::now() - SNAPSHOT_TTL - std::time::Duration::from_secs(1),
                generation: 0,
                adapters: vec![iface],
            });
            Arc::new(Self {
                table: Mutex::new(vec![native]),
                cache,
                reads: AtomicUsize::new(0),
                providers: AtomicUsize::new(0),
                writes: Mutex::new(vec![]),
                saves: Mutex::new(vec![]),
                fail_read: AtomicBool::new(false),
                fail_read_at: AtomicUsize::new(0),
                fail_save_at: AtomicUsize::new(0),
                delay: Mutex::new(std::time::Duration::ZERO),
                effect: Mutex::new(Effect::Apply),
                legacy_callbacks: AtomicBool::new(false),
                external_address: AtomicBool::new(false),
                replace_after_write: AtomicBool::new(false),
                post_delay: Mutex::new(std::time::Duration::ZERO),
            })
        }
        pub fn callbacks(&self) {
            for _ in 0..12 {
                // both callback kinds, plus an external concurrent IP change
                if self.legacy_callbacks.load(Ordering::Relaxed) {
                    self.cache.invalidate();
                } else {
                    observe_topology(&self.cache, &self.table.lock().unwrap());
                }
            }
        }
        fn write(&self, add: bool, adapter: &NativeAdapter, ip: &str) -> Result<(), AppError> {
            self.writes.lock().unwrap().push((add, ip.into()));
            let effect = *self.effect.lock().unwrap();
            if !matches!(effect, Effect::Unchanged) {
                let mut table = self.table.lock().unwrap();
                let current = table
                    .iter_mut()
                    .find(|n| n.identity() == adapter.identity())
                    .ok_or_else(|| AppError::Network("fake adapter changed before write".into()))?;
                current.ips.retain(|a| a.address != ip);
                if add {
                    current.ips.push(IpInfo {
                        address: ip.into(),
                        prefix: 24,
                        subnet: "192.0.2.0/24".into(),
                    });
                }
                if self.external_address.load(Ordering::Relaxed)
                    && !current.ips.iter().any(|i| i.address == "192.0.2.77")
                {
                    current.ips.push(IpInfo {
                        address: "192.0.2.77".into(),
                        prefix: 24,
                        subnet: "192.0.2.0/24".into(),
                    });
                }
            }
            if self.replace_after_write.load(Ordering::Relaxed) {
                self.table.lock().unwrap()[0].index += 1;
            }
            *self.delay.lock().unwrap() = *self.post_delay.lock().unwrap();
            self.callbacks();
            match effect {
                Effect::ErrorAfter => Err(AppError::Network(
                    "injected command failure after effect".into(),
                )),
                Effect::TimeoutAfter => Err(AppError::Network(
                    "injected command timed out after effect".into(),
                )),
                _ => Ok(()),
            }
        }
    }
    impl AddressIo for FakeAddressIo {
        fn native(&self) -> AddressFuture<'_, Vec<NativeAdapter>> {
            let read = self.reads.fetch_add(1, Ordering::Relaxed) + 1;
            let fail = self.fail_read.load(Ordering::Relaxed)
                || self.fail_read_at.load(Ordering::Relaxed) == read;
            let delay = *self.delay.lock().unwrap();
            let rows = self.table.lock().unwrap().clone();
            Box::pin(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                if fail {
                    Err(AppError::Network(
                        "injected native observation unavailable".into(),
                    ))
                } else {
                    Ok(rows)
                }
            })
        }
        fn add<'a>(
            &'a self,
            adapter: &'a NativeAdapter,
            ip: &'a str,
            _: &'a str,
        ) -> AddressFuture<'a, ()> {
            Box::pin(async move { self.write(true, adapter, ip) })
        }
        fn remove<'a>(&'a self, adapter: &'a NativeAdapter, ip: &'a str) -> AddressFuture<'a, ()> {
            Box::pin(async move { self.write(false, adapter, ip) })
        }
        fn descriptor(&self, native: &NativeAdapter) -> Option<InterfaceInfo> {
            self.cache
                .qualified
                .lock()
                .unwrap()
                .iter()
                .find(|(id, _)| *id == native.identity())
                .map(|(_, i)| native.overlay(i))
        }
        fn qualify(&self) -> AddressFuture<'_, ()> {
            self.providers.fetch_add(1, Ordering::Relaxed);
            Box::pin(async {
                Err(AppError::Network(
                    "injected delayed provider timeout".into(),
                ))
            })
        }
        fn persist_binding(
            &self,
            config: &crate::config::AppConfig,
            subnet: &str,
            row: crate::config::AdoptedMeta,
        ) -> Result<(), AppError> {
            let mut saves = self.saves.lock().unwrap();
            let count = saves.len() + 1;
            if self.fail_save_at.load(Ordering::Relaxed) == count {
                return Err(AppError::Config("injected persistence failure".into()));
            }
            saves.push(subnet.into());
            let mut settings = config.settings.lock().unwrap();
            if row.desired == crate::config::BindingDesired::Removed {
                settings.adopted_subnets.remove(subnet);
            }
            settings.adopted_meta.insert(subnet.into(), row);
            Ok(())
        }
        fn claim(&self, config: &crate::config::AppConfig, ip: &str) -> Result<(), AppError> {
            let mut settings = config.settings.lock().unwrap();
            let removed: Vec<_> = settings
                .adopted_meta
                .iter()
                .filter(|(_, r)| r.address.as_deref() == Some(ip))
                .map(|(k, _)| k.clone())
                .collect();
            for subnet in removed {
                settings.adopted_meta.remove(&subnet);
                settings.adopted_subnets.remove(&subnet);
            }
            settings.pending_addresses.retain(|r| r.address != ip);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn sp_qualification_requires_native_guid_alias_index_and_known_classification() {
        let io = address_test_io::FakeAddressIo::new(&[]);
        let native = io.table.lock().unwrap()[0].clone();
        let json = serde_json::json!({"Name":"Ethernet", "MacAddress":native.mac,
            "Guid":"guid-a", "Index":7, "MediaType":"802.3", "Virtual":false});
        assert!(is_wired_physical(
            &qualified_descriptor(&json, &native).unwrap()
        ));
        for key in ["Virtual", "MediaType", "Guid", "Index", "Name"] {
            let mut unknown = json.clone();
            unknown.as_object_mut().unwrap().remove(key);
            assert!(qualified_descriptor(&unknown, &native).is_none());
        }
        let mut virtual_json = json.clone();
        virtual_json["Virtual"] = serde_json::json!(true);
        assert!(!is_wired_physical(
            &qualified_descriptor(&virtual_json, &native).unwrap()
        ));
        let mut replaced = native.clone();
        replaced.guid = "other-guid".into();
        assert!(qualified_descriptor(&json, &replaced).is_none());
    }

    #[tokio::test]
    async fn sp_native_snapshot_uses_expired_qualification_but_fresh_addresses_and_dhcp() {
        let io = address_test_io::FakeAddressIo::new(&["192.0.2.10"]);
        io.table.lock().unwrap()[0].dhcp = true;
        let s = operation_snapshot(io.as_ref(), "40:cd:3a:00:00:01")
            .await
            .unwrap();
        assert_eq!(s.iface.ips[0].address, "192.0.2.10");
        assert!(s.selected.dhcp);
        assert_eq!(io.providers.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(native_by_alias(&s.all, "old alias").is_err());
        let mut duplicate = s.all.clone();
        duplicate.push(s.selected.clone());
        assert!(select_native(&duplicate, &s.selected.mac).is_err());
        for kind in 0..4 {
            let mut changed = s.selected.clone();
            match kind {
                0 => changed.guid = "new-guid".into(),
                1 => changed.alias = "renamed".into(),
                2 => changed.index = 8,
                _ => changed.index = 0,
            }
            assert!(io.descriptor(&changed).is_none());
            assert!(
                snapshot_from_native(io.as_ref(), &changed.mac.clone(), vec![changed]).is_err()
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn sp_native_flags_and_alias_are_read_from_windows_sys_059_union() {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DHCP_ENABLED,
        };
        let alias: Vec<u16> = "Ethernet".encode_utf16().chain(Some(0)).collect();
        let guid = std::ffi::CString::new("{native-guid}").unwrap();
        for flag in [0, IP_ADAPTER_DHCP_ENABLED] {
            let mut raw: IP_ADAPTER_ADDRESSES_LH = unsafe { std::mem::zeroed() };
            raw.Anonymous1.Anonymous.IfIndex = 7;
            raw.Anonymous2.Flags = flag;
            raw.FriendlyName = alias.as_ptr().cast_mut();
            raw.AdapterName = guid.as_ptr().cast_mut().cast();
            let rows = local_adapters_iphelper_with(|buffer, _| {
                unsafe {
                    *buffer = raw;
                }
                0
            })
            .unwrap();
            assert_eq!(rows[0].guid, "{native-guid}");
            assert_eq!(native_by_alias(&rows, "Ethernet").unwrap().dhcp, flag != 0);
            let mut duplicate = rows.clone();
            duplicate.push(rows[0].clone());
            assert!(native_by_alias(&duplicate, "Ethernet").is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_gateway_is_read_from_windows_sys_059_adapter_data() {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_GATEWAY_ADDRESS_LH,
        };
        use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};
        let mut address: SOCKADDR_IN = unsafe { std::mem::zeroed() };
        address.sin_family = AF_INET;
        address.sin_addr.S_un.S_addr = u32::from_ne_bytes([192, 0, 2, 1]);
        let mut gateway: IP_ADAPTER_GATEWAY_ADDRESS_LH = unsafe { std::mem::zeroed() };
        gateway.Address.lpSockaddr = (&mut address as *mut SOCKADDR_IN).cast();
        gateway.Address.iSockaddrLength = std::mem::size_of::<SOCKADDR_IN>() as i32;
        let mut adapter: IP_ADAPTER_ADDRESSES_LH = unsafe { std::mem::zeroed() };
        adapter.FirstGatewayAddress = &mut gateway;
        let rows = local_adapters_iphelper_with(|buffer, _| {
            unsafe { *buffer = adapter };
            0
        })
        .unwrap();
        assert_eq!(rows[0].gateways, vec!["192.0.2.1"]);
        adapter.FirstGatewayAddress = std::ptr::null_mut();
        let rows = local_adapters_iphelper_with(|buffer, _| {
            unsafe { *buffer = adapter };
            0
        })
        .unwrap();
        assert!(rows[0].gateways.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn sp_native_read_timeout_has_no_late_write_continuation() {
        let io = address_test_io::FakeAddressIo::new(&[]);
        *io.delay.lock().unwrap() = std::time::Duration::from_secs(3);
        assert!(read_native_with(io.as_ref())
            .await
            .unwrap_err()
            .to_string()
            .contains("2s"));
        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        assert!(io.writes.lock().unwrap().is_empty());
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn native_failure_is_not_an_empty_snapshot_even_with_cached_metadata() {
        let snapshot = AdapterSnapshot::default();
        let mut iface = flags_iface(true, true, false, false);
        iface.mac = "40:cd:3a:00:00:01".into();
        iface.ips.push(IpInfo {
            address: "192.0.2.20".into(),
            prefix: 24,
            subnet: "192.0.2.0/24".into(),
        });
        let metadata = snapshot.get(|| async { Ok(vec![iface]) }).await.unwrap();
        let error = failed_native_snapshot(metadata).unwrap_err();
        assert!(error
            .to_string()
            .contains("GetAdaptersAddresses failed with code 8"));
        let cached = snapshot
            .get(|| async { panic!("metadata should still be cached") })
            .await
            .unwrap();
        assert!(failed_native_snapshot(cached.clone()).is_err());

        // A successful observation of no addresses is still usable.
        let native =
            local_adapters_iphelper_with(|_, _| windows_sys::Win32::Foundation::ERROR_NO_DATA);
        let empty = overlay_adapter_addresses(cached.clone(), native).unwrap();
        assert!(!empty[0].is_up && empty[0].ips.is_empty());
        // Recovery must overlay fresh native addresses, not cached ones.
        let recovered = overlay_adapter_addresses(
            cached,
            Ok(vec![NativeAdapter {
                index: 7,
                mac: "40:cd:3a:00:00:01".into(),
                is_up: true,
                ips: vec![],
                ..Default::default()
            }]),
        )
        .unwrap();
        assert!(recovered[0].is_up && recovered[0].ips.is_empty());
    }

    #[cfg(windows)]
    #[tokio::test(start_paused = true)]
    async fn native_link_expiry_runs_while_provider_and_discovery_locks_are_held() {
        use super::super::{AdapterSelection, DeviceRegistry, DeviceStatus, NetworkManager};
        use crate::config::NetworkMode;
        let manager = NetworkManager::new();
        let iface = InterfaceInfo {
            name: "USB".into(),
            display_name: "USB".into(),
            description: "ASIX".into(),
            mac: "40:cd:3a:00:00:01".into(),
            ips: vec![],
            is_up: true,
            is_ethernet: true,
            is_wifi: false,
            is_vpn: false,
            is_virtual: false,
        };
        let selection = AdapterSelection {
            selected_mac: Some(iface.mac.clone()),
            adapter: Some(iface.clone()),
            interface_index: Some(7),
            ..Default::default()
        };
        manager.presence.update(&selection, NetworkMode::Dhcp);
        let fence = manager.presence.snapshot().fence;
        let device = super::super::ArpDevice {
            mac: "aa:bb:cc:dd:ee:02".into(),
            ip: "192.0.2.20".into(),
            subnet: "192.0.2.0/24".into(),
            first_seen: "now".into(),
            last_seen: "now".into(),
        };
        let registry: std::sync::Arc<DeviceRegistry> = manager.registry();
        registry.merge_verified(&device, &iface.mac, "2026-10-20T00:00:00Z", &fence);
        let _provider = ADAPTER_QUERY_LOCK.lock().await;
        let _discovery = manager.discovery_op.lock().await;
        let provider_wait = with_adapter_query_lock(&ADAPTER_QUERY_LOCK, || async { Ok(()) });
        let discovery_wait = manager.discovery_op.lock();
        tokio::pin!(provider_wait, discovery_wait);
        manager.presence.observe_link(|_| Some((7, false)));
        for _ in 0..9 {
            tokio::select! {
                _ = &mut provider_wait => panic!("provider wait unexpectedly completed"),
                _ = &mut discovery_wait => panic!("discovery wait unexpectedly completed"),
                _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
            }
            manager.presence.observe_link(|_| Some((7, false)));
            manager.presence.tick(&registry);
        }
        assert_eq!(registry.snapshot()[0].status, DeviceStatus::Offline);
        assert!(fence.is_stale());
        assert_eq!(registry.snapshot().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn initial_topology_before_metadata_query_does_not_cancel_it_on_link_notification() {
        let cache = std::sync::Arc::new(AdapterSnapshot::default());
        let io = address_test_io::FakeAddressIo::new(&["192.168.2.100"]);
        let mut native = io.table.lock().unwrap().clone();
        assert!(observe_topology(&cache, &native));
        let c = cache.clone();
        let query = tokio::spawn(async move {
            c.get(|| async {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                Ok(vec![])
            })
            .await
        });
        tokio::task::yield_now().await;
        native[0].is_up = false;
        native[0].ips.clear();
        assert!(!observe_topology(&cache, &native));
        assert!(query.await.unwrap().is_ok());
        assert!(cache.cached().is_some());
    }

    #[test]
    fn topology_change_rejects_late_qualification_publication() {
        let cache = AdapterSnapshot::default();
        let io = address_test_io::FakeAddressIo::new(&["192.168.2.100"]);
        let mut native = io.table.lock().unwrap().clone();
        observe_topology(&cache, &native);
        let generation = cache.generation.load(std::sync::atomic::Ordering::Acquire);
        let qualified = vec![(native[0].identity(), io.descriptor(&native[0]).unwrap())];
        publish_qualification(&cache, generation, &native, qualified.clone());
        assert_eq!(cache.qualified.lock().unwrap().len(), 1);
        native[0].index += 1;
        assert!(observe_topology(&cache, &native));
        publish_qualification(&cache, generation, &native, qualified);
        assert!(cache.qualified.lock().unwrap().is_empty());
        assert_eq!(*cache.topology.lock().unwrap(), topology(&native));
    }

    #[tokio::test(start_paused = true)]
    async fn snapshot_ttl_coalesces_callers_and_caches_empty_success() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cache = AdapterSnapshot::default();
        let calls = AtomicUsize::new(0);
        let query = || async {
            calls.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            Ok(vec![])
        };
        let (first, second, third) =
            tokio::join!(cache.get(query), cache.get(query), cache.get(query));
        assert!(
            first.unwrap().is_empty() && second.unwrap().is_empty() && third.unwrap().is_empty()
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        tokio::time::advance(SNAPSHOT_TTL - std::time::Duration::from_secs(1)).await;
        cache.get(query).await.unwrap();
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "cache hits must not extend the TTL"
        );
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        cache.get(query).await.unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn snapshot_refresh_wait_has_total_deadline_without_starting_query() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let cache = std::sync::Arc::new(AdapterSnapshot::default());
        let entered = std::sync::Arc::new(AtomicBool::new(false));
        let held = cache.refresh.lock().await;
        let caller_cache = cache.clone();
        let called = entered.clone();
        let caller = tokio::spawn(async move {
            caller_cache
                .get(|| async {
                    called.store(true, Ordering::Relaxed);
                    Ok(vec![])
                })
                .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(ADAPTER_QUERY_DEADLINE).await;
        assert!(caller
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("including queue wait"));
        assert!(!entered.load(Ordering::Relaxed));
        drop(held);
        assert!(cache.get(|| async { Ok(vec![]) }).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn invalidation_rejects_inflight_snapshot_and_errors_never_reuse_stale_success() {
        let cache = std::sync::Arc::new(AdapterSnapshot::default());
        let caller_cache = cache.clone();
        let caller = tokio::spawn(async move {
            caller_cache
                .get(|| async {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    Ok(vec![])
                })
                .await
        });
        tokio::task::yield_now().await;
        cache.invalidate();
        assert!(caller
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("changed during enumeration"));
        assert!(cache.cached().is_none());
        cache.get(|| async { Ok(vec![]) }).await.unwrap();
        tokio::time::advance(SNAPSHOT_TTL).await;
        assert!(cache
            .get(|| async { Err(AppError::Network("provider failed".into())) })
            .await
            .is_err());
        assert!(cache.cached().is_none());
        assert!(cache.get(|| async { Ok(vec![]) }).await.is_ok());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn source_snapshot_requires_fresh_unique_ownership_after_removal_or_move() {
        let cache = AdapterSnapshot::default();
        let ip = "192.0.2.1".parse().unwrap();
        assert!(cache.source_matches(7, ip, vec![(7, ip)]));
        assert!(!cache.source_matches(7, ip, vec![]));
        assert!(!cache.source_matches(7, ip, vec![(8, ip)]));
        assert!(!cache.source_matches(7, ip, vec![(7, ip), (8, ip)]));
        assert!(cache.source_matches(8, ip, vec![(8, ip)]));
    }

    #[test]
    fn source_must_belong_uniquely_to_the_selected_index() {
        let wired = "192.168.1.101".parse().unwrap();
        let wifi = "192.168.1.102".parse().unwrap();
        let addresses = [(7, wired), (8, wifi)];
        assert!(source_matches_index(7, wired, addresses.into_iter()));
        assert!(!source_matches_index(8, wired, addresses.into_iter()));
        assert!(!source_matches_index(0, wired, addresses.into_iter()));
        assert!(!source_matches_index(7, wired, [].into_iter()));
        assert!(!source_matches_index(
            7,
            wired,
            [(7, wired), (8, wired)].into_iter()
        ));
    }

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
            description: String::new(),
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
    fn native_overlay_preserves_macless_vpn_addresses_for_exclusion() {
        let mut vpn = flags_iface(true, false, true, true);
        vpn.ips.push(IpInfo {
            address: "10.8.0.2".into(),
            prefix: 24,
            subnet: "10.8.0.0/24".into(),
        });
        #[cfg(target_os = "windows")]
        let actual = overlay_adapter_addresses(vec![vpn], Ok(vec![])).unwrap();
        #[cfg(not(target_os = "windows"))]
        let actual = current_adapter_addresses(vec![vpn]).unwrap();
        assert!(actual[0].is_up && actual[0].is_vpn);
        assert_eq!(actual[0].ips[0].address, "10.8.0.2");
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
            description: "Test Adapter".into(),
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

        #[tokio::test]
        async fn adapter_query_lock_serializes_callers() {
            use std::sync::atomic::{AtomicUsize, Ordering};

            async fn probe(
                gate: &tokio::sync::Mutex<()>,
                active: &AtomicUsize,
                peak: &AtomicUsize,
            ) {
                with_adapter_query_lock(gate, || async {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
                .unwrap();
            }

            let gate = tokio::sync::Mutex::new(());
            let active = AtomicUsize::new(0);
            let peak = AtomicUsize::new(0);
            tokio::join!(
                probe(&gate, &active, &peak),
                probe(&gate, &active, &peak),
                probe(&gate, &active, &peak),
            );

            assert_eq!(peak.load(Ordering::SeqCst), 1);
        }

        #[tokio::test(start_paused = true)]
        async fn adapter_deadline_includes_wait_before_query_and_preserves_gate() {
            use std::sync::atomic::{AtomicBool, Ordering};
            let gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
            let held = gate.lock().await;
            let entered = std::sync::Arc::new(AtomicBool::new(false));
            let g = gate.clone();
            let called = entered.clone();
            let caller = tokio::spawn(async move {
                with_adapter_query_lock(&g, || async {
                    called.store(true, Ordering::Relaxed);
                    Ok(())
                })
                .await
            });
            tokio::task::yield_now().await;
            tokio::time::advance(ADAPTER_QUERY_DEADLINE).await;
            assert!(caller
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("including queue wait"));
            assert!(!entered.load(Ordering::Relaxed));
            drop(held);
            assert!(with_adapter_query_lock(&gate, || async { Ok(()) })
                .await
                .is_ok());
        }

        #[tokio::test(start_paused = true)]
        async fn adapter_wait_and_query_share_one_deadline_and_cancel_running_work() {
            use std::sync::atomic::{AtomicBool, Ordering};
            struct Cancelled(std::sync::Arc<AtomicBool>);
            impl Drop for Cancelled {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Relaxed);
                }
            }
            let gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
            let held = gate.lock().await;
            let cancelled = std::sync::Arc::new(AtomicBool::new(false));
            let g = gate.clone();
            let c = cancelled.clone();
            let start = tokio::time::Instant::now();
            let caller = tokio::spawn(async move {
                with_adapter_query_lock(&g, || async {
                    let _cancelled = Cancelled(c);
                    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
                    Ok(())
                })
                .await
            });
            tokio::task::yield_now().await;
            tokio::time::advance(std::time::Duration::from_secs(6)).await;
            drop(held);
            tokio::task::yield_now().await;
            assert!(caller.await.unwrap().is_err());
            assert_eq!(start.elapsed(), ADAPTER_QUERY_DEADLINE);
            assert!(cancelled.load(Ordering::Relaxed));
            assert!(gate.try_lock().is_ok());
        }

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
        assert!(result.is_ok(), "physical enumeration failed: {result:?}");
    }

    #[tokio::test]
    async fn list_all_returns_ok() {
        let result = list_all().await;
        assert!(result.is_ok(), "combined enumeration failed: {result:?}");
    }

    #[tokio::test]
    async fn list_all_adapters_returns_ok() {
        // Full enumeration (physical + virtual) must succeed on any
        // platform; may be empty in CI.
        let result = list_all_adapters().await;
        assert!(result.is_ok(), "full enumeration failed: {result:?}");
    }

    #[tokio::test]
    async fn get_by_name_nonexistent_returns_err() {
        let result = get_by_name("__nonexistent_interface_42__").await;
        let err_msg = result
            .expect_err("the nonexistent interface unexpectedly resolved")
            .to_string();
        assert!(
            err_msg.contains("not found"),
            "unexpected lookup error: {err_msg}"
        );
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
        let err_msg = result
            .expect_err("the unknown interface unexpectedly validated")
            .to_string();
        assert!(
            err_msg.contains("Unknown network interface"),
            "unexpected validation error: {err_msg}"
        );
    }
}
