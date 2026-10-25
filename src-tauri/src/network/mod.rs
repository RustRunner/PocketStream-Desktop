mod adopt_loop;
mod capture_session;
mod discovery_session;
pub(crate) mod readiness;
mod scan;
use capture_session::{current_session_counters, park_capture_handle};
mod adapter_selector;
mod binding_store;
use adapter_selector::{adapter_candidate, adapter_mac, pick_adapter};
pub mod adapter_refresh;
pub mod arp;
pub mod auto_adopt;
pub mod bindings;
pub(crate) mod bound_tcp;
mod cache_probe;
pub mod device_registry;
pub mod firewall;
pub mod ghost;
pub mod interface;
pub mod ip_config;
pub mod ip_conflict;
pub mod manual_address;
pub mod ping_dot;
pub(crate) mod presence;
// Cross-platform compilable (libloading + extern "system" types build
// everywhere; PktMonApi.dll only resolves at runtime on Windows) so the
// pure-layout unit tests gate on both CI jobs. The runtime capture path
// is consumed by the arp.rs listener; the availability probe is called
// only from the Windows startup block, so it reads as dead on Linux.
pub mod pktmon;
pub mod reaper;
pub mod route;
pub mod scanner;
pub mod watcher;

#[cfg(windows)]
pub(crate) mod host_owner;
#[cfg(windows)]
mod local_executor;
#[cfg(windows)]
pub(crate) mod native_operations;
#[cfg(all(test, windows))]
#[path = "../../tests/fixtures/native_foundation.rs"]
mod native_qualification;
#[cfg(windows)]
mod native_runner;

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;

pub(crate) use arp::note_fence_drop;
pub use arp::ArpDevice;
pub use device_registry::{DeviceListEmitter, DeviceRecord, DeviceRegistry, DeviceStatus};
pub use interface::InterfaceInfo;
pub use scanner::ScanResult;

use crate::error::AppError;

/// Quote one non-secret diagnostic field; JSON escapes separators/control
/// characters so a value cannot inject another key or a forged log line.
pub(crate) fn log_value(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization")
}

// ── Hidden-window command helpers ────────────────────────────────────
// On Windows, every `Command::new()` spawns a visible console window
// unless CREATE_NO_WINDOW (0x0800_0000) is set.

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Create a `std::process::Command` that won't flash a console window.
pub(crate) fn cmd(program: &str) -> std::process::Command {
    #[allow(unused_mut)] // mut needed only on Windows for creation_flags()
    let mut c = std::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c
}

/// Create a `tokio::process::Command` that won't flash a console window.
#[cfg(not(windows))]
pub(crate) fn async_cmd(program: &str) -> tokio::process::Command {
    let std_cmd = cmd(program);
    tokio::process::Command::from(std_cmd)
}

/// Write alias changes through to every on-disk alias store so a
/// demoted CAM/PTU can't resurrect from a stale row: the device cache
/// and the manual-nodes config list. Full cache rows are upserted when
/// the current scan has open ports; an existing zero-port cache row still
/// receives the alias-only update so a hidden stale role cannot resurrect
/// on restart. Best-effort: a failed write logs and the registry stays
/// authoritative — the next successful persist self-heals the store.
pub(crate) fn persist_alias_writethrough(
    registry: &DeviceRegistry,
    config: &crate::config::AppConfig,
    keys: &[String],
) {
    for key in keys {
        let snapshot = registry.snapshot();
        let Some(record) = snapshot.iter().find(|r| r.mac == *key) else {
            continue;
        };
        let cached = registry.cache_record(key);
        let saved = if let Some(cached) = cached {
            config.upsert_cached_device(cached).map(|()| true)
        } else {
            config.update_cached_device_alias(key, &record.alias)
        };
        if let Err(e) = saved {
            log::warn!("Failed to persist alias for {}: {}", key, e);
        }
        if let Err(e) = config.update_manual_node_alias(key, &record.alias) {
            log::warn!("Failed to persist manual alias for {}: {}", key, e);
        }
    }
}

/// Session fence for sweep and capture work. Holds the discovery
/// generation captured when the work was scheduled plus handles to the
/// live generation/active flags, so stale work — a sweep or capture frame
/// from a prior session, or anything after a stop — drops itself before
/// merging into the shared registry or emitting. Gating on `active` (not
/// only the generation) is what catches a stop with no restart, e.g.
/// Static Auto → Manual, where the generation never advances.
#[derive(Clone)]
pub(crate) struct SweepFence {
    generation: u64,
    current: Arc<AtomicU64>,
    active: Arc<AtomicBool>,
}

impl SweepFence {
    pub(crate) fn new(generation: u64, current: Arc<AtomicU64>, active: Arc<AtomicBool>) -> Self {
        Self {
            generation,
            current,
            active,
        }
    }

    pub(crate) fn is_stale(&self) -> bool {
        !self.active.load(Ordering::Relaxed)
            || self.generation != self.current.load(Ordering::Relaxed)
    }

    /// Atomic fences also cancel queued work without waiting for a permit.
    pub(crate) async fn cancelled(&self) {
        while !self.is_stale() {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
}

/// What the persistent capture listener is currently bound to.
///
/// `source_id` is the PacketMonitor data-source id from the scope join
/// (`None` for an unscoped-fallback session). `active` is this
/// incarnation's lifecycle flag: allocated fresh for every attach and
/// flipped false forever on stop, so a wedged prior capture thread can
/// never merge again once a replacement attaches — the same
/// permanently-stale property the discovery generation gives sweeps.
#[derive(Debug, Clone)]
pub(crate) struct CaptureIdentity {
    pub(crate) iface_name: String,
    pub(crate) mac: Option<[u8; 6]>,
    pub(crate) source_id: Option<u32>,
    pub(crate) active: Arc<AtomicBool>,
}

/// One payload for capture events and the subscribe-then-fetch query.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CaptureState {
    pub candidate_count: usize,
    pub active: bool,
    pub adapter_name: Option<String>,
    pub outcome: Option<pktmon::ScopeOutcome>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AdapterSelection {
    pub selected_mac: Option<String>,
    pub adapter: Option<InterfaceInfo>,
    pub interface_index: Option<u32>,
    pub selection_required: bool,
    pub candidates: Vec<InterfaceInfo>,
}

/// DHCP already captures; enabling adoption does not need a new listener.
fn mode_keeps_capture(from: crate::config::NetworkMode, to: crate::config::NetworkMode) -> bool {
    from == crate::config::NetworkMode::Dhcp && to == crate::config::NetworkMode::StaticAuto
}

/// Invalidate in-flight address work before waiting for its serialization lock.
/// Drop always resumes scheduling, including error exits.
struct AddressPause {
    generation: Arc<AtomicU64>,
    active: Arc<AtomicBool>,
}

/// No await between durable commit and relinquishing the pending breadcrumb:
/// cancellation cleanup must never mistake a committed IP for temporary work.
async fn commit_pending_address(
    pending: &auto_adopt::PendingIps,
    iface: &str,
    ip: Ipv4Addr,
    id: u64,
    commit: impl FnOnce() -> Result<(), AppError>,
) -> Result<(), AppError> {
    let mut pending = pending.lock().await;
    commit()?;
    pending.retain(|entry| !(entry.iface == iface && entry.ip == ip && entry.adoption_id == id));
    Ok(())
}

impl AddressPause {
    fn new(generation: Arc<AtomicU64>, active: Arc<AtomicBool>) -> Self {
        active.store(false, Ordering::Release);
        generation.fetch_add(1, Ordering::AcqRel);
        Self { generation, active }
    }
}

impl Drop for AddressPause {
    fn drop(&mut self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.active.store(true, Ordering::Release);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum BindingAction {
    /// No current observation: retain the last known applied state, but exclude
    /// the binding from live routes until observation succeeds.
    Unavailable(String),
    Hold(String, bool),
    Observed(bool),
    Add(Ipv4Addr, u8),
    Remove(Ipv4Addr),
}

fn binding_link_changed(previous: &AdapterSelection, current: &AdapterSelection) -> bool {
    previous.selected_mac == current.selected_mac
        && previous.interface_index == current.interface_index
        && previous.adapter.as_ref().is_some_and(|i| i.is_up)
            != current.adapter.as_ref().is_some_and(|i| i.is_up)
}

#[derive(Debug)]
enum DiscoveryResume {
    Idle,
    RefreshSelection,
    Start(InterfaceInfo),
}

/// Cached metadata identifies the selected physical port; native reads supply
/// current link/index/addresses. Neither UI state nor a Wi-Fi prefix is authority.
fn discovery_resume_action(
    mode: crate::config::NetworkMode,
    available: bool,
    session_active: bool,
    selected_mac: Option<&str>,
    selection: &AdapterSelection,
    native: Option<(u32, bool, Vec<interface::IpInfo>)>,
    capture_active: bool,
) -> DiscoveryResume {
    if mode == crate::config::NetworkMode::StaticManual || !available {
        return DiscoveryResume::Idle;
    }
    if selected_mac.is_none() && selection.selection_required {
        return DiscoveryResume::Idle;
    }
    let selected = selected_mac.and_then(adapter_mac);
    if selected.is_none() || selected != selection.selected_mac.as_deref().and_then(adapter_mac) {
        return DiscoveryResume::RefreshSelection;
    }
    let Some((index, up, ips)) = native else {
        return if selection.adapter.is_some() {
            DiscoveryResume::RefreshSelection
        } else {
            DiscoveryResume::Idle
        };
    };
    let Some(iface) = selection
        .adapter
        .as_ref()
        .filter(|i| interface::is_wired_physical(i) && adapter_mac(&i.mac) == selected)
    else {
        return DiscoveryResume::RefreshSelection;
    };
    if index == 0 || selection.interface_index != Some(index) {
        return DiscoveryResume::RefreshSelection;
    }
    if session_active {
        return DiscoveryResume::Idle; // healthy only while the native identity still matches
    }
    if !up && capture_active {
        return DiscoveryResume::Idle; // already listening for the link-up burst
    }
    let mut iface = iface.clone();
    iface.is_up = up;
    iface.ips = ips;
    DiscoveryResume::Start(iface)
}

fn pending_binding_removal(mut row: crate::config::AdoptedMeta) -> crate::config::AdoptedMeta {
    row.desired = crate::config::BindingDesired::Removed;
    row.last_error = Some("Removal awaiting Windows confirmation".into());
    row
}

fn binding_action(
    subnet: &str,
    row: &crate::config::AdoptedMeta,
    iface: Option<&InterfaceInfo>,
    mode: crate::config::NetworkMode,
    dhcp: &Result<bool, String>,
    conflicts: &[ipnetwork::Ipv4Network],
) -> BindingAction {
    use crate::config::{BindingDesired, NetworkMode};
    let Some(iface) =
        iface.filter(|i| i.is_up || (row.desired == BindingDesired::Removed && dhcp.is_ok()))
    else {
        return BindingAction::Unavailable("selected adapter unavailable".into());
    };
    if row
        .adapter_mac
        .as_ref()
        .is_some_and(|mac| adapter_mac(mac) != adapter_mac(&iface.mac))
    {
        return BindingAction::Hold("adapter mismatch".into(), false);
    }
    let valid = subnet
        .parse::<ipnetwork::Ipv4Network>()
        .ok()
        .and_then(|net| {
            let ip = row.address.as_ref()?.parse::<Ipv4Addr>().ok()?;
            let prefix = row.prefix?;
            (prefix == net.prefix()
                && net.contains(ip)
                && ip != net.network()
                && ip != net.broadcast()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unspecified())
            .then_some((ip, prefix))
        });
    let Some((ip, prefix)) = valid else {
        return BindingAction::Hold("invalid saved address/prefix or subnet".into(), false);
    };
    let observed = iface.ips.iter().find(|a| a.address == ip.to_string());
    if observed.is_some_and(|a| a.prefix != prefix) {
        return BindingAction::Hold("address exists with a different prefix".into(), false);
    }
    let applied = observed.is_some();
    let is_dhcp = match dhcp {
        Ok(value) => *value,
        Err(error) => {
            return BindingAction::Hold(format!("DHCP state unavailable: {error}"), applied)
        }
    };
    if row.desired == BindingDesired::Removed {
        return if applied {
            BindingAction::Remove(ip)
        } else {
            BindingAction::Observed(false)
        };
    }
    if is_dhcp {
        return BindingAction::Hold("adapter is DHCP".into(), false);
    }
    if mode == NetworkMode::Dhcp {
        return BindingAction::Hold("saved mode is DHCP; adapter is static".into(), false);
    }
    if applied {
        BindingAction::Observed(true)
    } else if conflicts.iter().any(|net| net.contains(ip)) {
        BindingAction::Hold("subnet conflicts with another local adapter".into(), false)
    } else {
        BindingAction::Add(ip, prefix)
    }
}

/// The existing AdoptOps seam plus a fresh OS observation makes command
/// failure and stale applied flags testable without touching a real adapter.
async fn apply_binding<O, F, Fut>(
    ops: &O,
    mut row: crate::config::AdoptedMeta,
    action: BindingAction,
    iface: Option<&InterfaceInfo>,
    observe: F,
) -> crate::config::AdoptedMeta
where
    O: auto_adopt::AdoptOps,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<interface::IpInfo>, AppError>>,
{
    // An outage is not a new removal failure after absence was confirmed.
    // Fresh observations on adapter return still recheck the tombstone.
    if matches!(action, BindingAction::Unavailable(_))
        && row.desired == crate::config::BindingDesired::Removed
        && !row.applied
        && row.last_error.is_none()
    {
        return row;
    }
    row.last_error = None;
    match action {
        BindingAction::Unavailable(reason) => {
            row.last_error = Some(reason);
        }
        BindingAction::Hold(reason, applied) => {
            row.applied = applied;
            row.last_error = Some(reason);
        }
        BindingAction::Observed(applied) => {
            row.applied = applied;
        }
        action => {
            let iface = iface.expect("write actions require a selected adapter");
            let result = match action {
                BindingAction::Add(ip, prefix) => {
                    row.applied = false;
                    ops.add(&iface.name, ip, &ip_config::prefix_to_mask(prefix))
                        .await
                }
                BindingAction::Remove(ip) => {
                    row.applied = true;
                    ops.remove(&iface.name, ip).await
                }
                _ => unreachable!(),
            };
            let observed = observe().await;
            row.applied = observed
                .as_ref()
                .map(|ips| {
                    ips.iter().any(|a| {
                        Some(a.address.as_str()) == row.address.as_deref()
                            && Some(a.prefix) == row.prefix
                    })
                })
                .unwrap_or(row.applied);
            row.last_error = result
                .err()
                .map(|e| e.to_string())
                .or_else(|| observed.err().map(|e| e.to_string()));
            let wanted = row.desired == crate::config::BindingDesired::Present;
            if row.last_error.is_none() && row.applied != wanted {
                row.last_error = Some("OS did not apply the requested binding state".into());
            }
        }
    }
    if row.applied
        && row.desired == crate::config::BindingDesired::Present
        && row.last_error.is_none()
    {
        row.adapter_mac = iface.and_then(|i| adapter_mac(&i.mac));
    }
    row
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ModeTransition {
    pub name: String,
    pub mode: crate::config::NetworkMode,
    pub ip: Option<String>,
    pub subnet_mask: Option<String>,
    pub gateway: Option<String>,
    #[serde(default)]
    pub previous_address: Option<String>,
    #[serde(default)]
    pub confirmed: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct ModeTransitionReply {
    pub warning: Option<String>,
    pub mode: crate::config::NetworkMode,
    pub primary_address: Option<String>,
}

pub struct NetworkManager {
    selector: Arc<adapter_selector::AdapterSelector>,
    bindings: Arc<binding_store::BindingStore>,
    capture: Arc<capture_session::CaptureSession>,
    discovery: Arc<discovery_session::DiscoverySession>,
    bridge: Arc<dyn crate::bridge::AppBridge>,
    config: Arc<crate::config::AppConfig>,
    scans: scan::ScanWorkflow,
    readiness: Arc<readiness::CameraReadiness>,
    pinger: ping_dot::Pinger,
    /// Canonical store of merged device records (ARP + scan + cache +
    /// alias + status). Mutated alongside `arp_devices` during the
    /// transition; once the frontend is fully migrated to subscribe-only
    /// snapshots the legacy map can be deleted.
    device_registry: Arc<DeviceRegistry>,
    /// Constructed before hydration; its bridge is bound in setup.
    device_emitter: Arc<DeviceListEmitter>,
    /// Serializes the discovery lifecycle (start / stop / mode change /
    /// startup restore) so concurrent entry can't overwrite — and thereby
    /// orphan — the auto-adopt task handle. Non-reentrant: internal callers
    /// use the `*_locked` variants.
    discovery_op: Arc<Mutex<()>>,
}

/// One adopted subnet's lifecycle metadata as the UI consumes it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdoptedMetaView {
    /// RFC3339; `None` for entries recorded before metadata existed.
    pub adopted_at: Option<String>,
    /// RFC3339; `None` until positive evidence arrives.
    pub last_device_seen: Option<String>,
    /// Compatibility badge information; never authorizes removal of a
    /// committed binding. Hosts badge presentation is handled in S8.
    pub stale: bool,
    pub address: Option<String>,
    pub prefix: Option<u8>,
    pub adapter_mac: Option<String>,
    pub desired: crate::config::BindingDesired,
    pub applied: bool,
    pub last_error: Option<String>,
}

/// Atomic snapshot of the adoption state for the frontend — the
/// routing map and the per-subnet metadata views taken together so the
/// two can never disagree.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdoptionSnapshot {
    pub adopted_subnets: HashMap<String, String>,
    pub meta: HashMap<String, AdoptedMetaView>,
}

/// Both paths carry complete binding state; only fresh commits get a badge.
fn adoption_event(
    subnet: &str,
    ip: &str,
    meta: &AdoptedMetaView,
    restored: bool,
) -> serde_json::Value {
    let mut payload = serde_json::to_value(meta).expect("binding view serializes");
    payload["subnet"] = serde_json::json!(subnet);
    payload["adopted_ip"] = serde_json::json!(ip);
    payload["restored"] = serde_json::json!(restored);
    payload
}

/// Wall-clock age of the last recorded sighting (or of the adoption
/// itself when no device was ever seen), for the informational badge.
/// `None` when there is nothing to measure, the stamp is unparseable,
/// or it sits in the future — skew may mislabel a row, never more.
fn badge_age(
    meta: Option<&crate::config::AdoptedMeta>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<std::time::Duration> {
    let stamp = meta.and_then(|m| m.last_device_seen.as_ref().or(m.adopted_at.as_ref()))?;
    let parsed = chrono::DateTime::parse_from_rfc3339(stamp).ok()?;
    now.signed_duration_since(parsed.with_timezone(&chrono::Utc))
        .to_std()
        .ok()
}

/// Build the compatibility badge and durable binding status together.
fn adoption_meta_view(
    subnet: &str,
    meta: Option<&crate::config::AdoptedMeta>,
    last_positive_elapsed: Option<std::time::Duration>,
    session_elapsed: std::time::Duration,
    badge_age: Option<std::time::Duration>,
) -> AdoptedMetaView {
    let stale = reaper::lifecycle_verdict(&reaper::LifecycleInput {
        subnet: reaper::parse_subnet_key(subnet),
        last_positive_elapsed,
        session_elapsed,
        pinned: false,
        host_rescued: false,
        badge_age,
    }) != reaper::ReapVerdict::Keep;
    AdoptedMetaView {
        adopted_at: meta.and_then(|m| m.adopted_at.clone()),
        last_device_seen: meta.and_then(|m| m.last_device_seen.clone()),
        stale,
        address: meta.and_then(|m| m.address.clone()),
        prefix: meta.and_then(|m| m.prefix),
        adapter_mac: meta.and_then(|m| m.adapter_mac.clone()),
        desired: meta.map(|m| m.desired).unwrap_or_default(),
        applied: meta.is_some_and(|m| m.applied),
        last_error: meta.and_then(|m| m.last_error.clone()),
    }
}

/// Metadata-only config writes (liveness stamps) are coalesced: stamps
/// mark the state dirty and it flushes at most once per interval.
/// Adoption and removal writes persist immediately through their own
/// saves — this cadence exists so ARP frames and pings never translate
/// into per-event fsyncs.
const META_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

struct MetaFlush {
    dirty: bool,
    last_flush: std::time::Instant,
}

/// Mark the metadata dirty and decide whether a coarse flush is due.
/// Consumes the dirty state (and restarts the cadence) when it says
/// yes; otherwise the dirt persists for a later stamp or lifecycle
/// save to pick up.
fn meta_dirty_flush_due(state: &mut MetaFlush, now: std::time::Instant) -> bool {
    state.dirty = true;
    if now.saturating_duration_since(state.last_flush) >= META_FLUSH_INTERVAL {
        state.dirty = false;
        state.last_flush = now;
        true
    } else {
        false
    }
}

/// The `/24` adoption key `ip` falls under — the same derivation every
/// adoption path uses, so containment is exact key equality.
fn subnet_key_for(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.0/24", o[0], o[1], o[2])
}

/// Record positive device evidence for `ip` against the adoption maps.
/// Refreshes the session liveness clock and stamps the display
/// metadata. Returns whether the evidence landed on an adopted subnet
/// (the common case is no — the maps are untouched then).
fn record_positive_liveness(
    ip: Ipv4Addr,
    adopted: &HashMap<String, Ipv4Addr>,
    liveness: &mut HashMap<String, std::time::Instant>,
    meta: &mut HashMap<String, crate::config::AdoptedMeta>,
    now: std::time::Instant,
    wall_rfc3339: &str,
) -> bool {
    let subnet = subnet_key_for(ip);
    if !adopted.contains_key(&subnet) {
        return false;
    }
    liveness.insert(subnet.clone(), now);
    meta.entry(subnet).or_default().last_device_seen = Some(wall_rfc3339.to_string());
    true
}

/// DHCP never authorizes new addresses, including when its only address is APIPA.
fn dhcp_adoption_pause(is_dhcp: bool, ips: &[Ipv4Addr]) -> Option<&'static str> {
    if !is_dhcp {
        None
    } else if ips
        .iter()
        .all(|ip| crate::validation::prohibited_camera_ip(*ip))
    {
        Some("no usable address; set a static address")
    } else {
        Some("DHCP enabled; automatic address adoption paused")
    }
}

fn keep_prohibited_history_inactive(registry: &DeviceRegistry) -> bool {
    let mut changed = false;
    for record in registry.snapshot() {
        if record
            .ip
            .parse()
            .is_ok_and(crate::validation::prohibited_camera_ip)
        {
            changed |= registry.set_status(&record.mac, DeviceStatus::Offline);
        }
    }
    changed
}

/// Retained secondary addresses are never startup sweep sources. Deduplicate
/// by /24, matching the bounded ICMP pass; Refresh includes actual adopted IPs.
fn select_sweep_ips(
    ips: &[interface::IpInfo],
    retained: &HashSet<Ipv4Addr>,
    refresh: bool,
) -> Vec<String> {
    let mut subnets = HashSet::new();
    ips.iter()
        .filter_map(|info| {
            let ip: Ipv4Addr = info.address.parse().ok()?;
            if crate::validation::prohibited_camera_ip(ip) || (!refresh && retained.contains(&ip)) {
                return None;
            }
            let octets = ip.octets();
            subnets
                .insert([octets[0], octets[1], octets[2]])
                .then(|| ip.to_string())
        })
        .collect()
}

/// Drop pending (scratch / not-yet-handed-over) addresses from an
/// enumerated adapter list. Those are transient adoption machinery, not
/// host addresses: rendering one as a host row, or letting its
/// bind/release read as an IP change, misleads every consumer. Pure so
/// the filter is unit-testable; adapters are kept even when the filter
/// empties their address list (a port whose only address is a scratch
/// presents as disconnected, which is what it effectively is).
pub(crate) fn strip_pending_ips(
    mut list: Vec<interface::InterfaceInfo>,
    pending: &HashSet<String>,
) -> Vec<interface::InterfaceInfo> {
    if pending.is_empty() {
        return list;
    }
    for iface in &mut list {
        iface.ips.retain(|ip| !pending.contains(&ip.address));
    }
    list
}

#[derive(Clone, Copy)]
struct Solicitation {
    generation: u64,
    at: tokio::time::Instant,
    baseline: arp::CounterSnapshot,
}

impl interface::AddressIo for interface::RealAddressIo {
    fn check_writes_available(&self) -> Result<(), AppError> {
        #[cfg(windows)]
        {
            native_operations::check_writes_available()
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
    }
    fn native(&self) -> interface::AddressFuture<'_, Vec<interface::NativeAdapter>> {
        Box::pin(async {
            tokio::task::spawn_blocking(|| {
                #[cfg(windows)]
                {
                    interface::local_adapters_iphelper()
                }
                #[cfg(not(windows))]
                {
                    Err(AppError::Network(
                        "Native adapter reads require Windows".into(),
                    ))
                }
            })
            .await
            .map_err(|e| AppError::Network(format!("Native adapter read failed: {e}")))?
        })
    }
    fn add<'a>(
        &'a self,
        adapter: &'a interface::NativeAdapter,
        ip: &'a str,
        mask: &'a str,
    ) -> interface::AddressFuture<'a, ()> {
        Box::pin(ip_config::add_native_address(adapter, ip, mask))
    }
    fn remove<'a>(
        &'a self,
        adapter: &'a interface::NativeAdapter,
        ip: &'a str,
    ) -> interface::AddressFuture<'a, ()> {
        Box::pin(ip_config::remove_native_address(adapter, ip))
    }
    fn persist_intent(
        &self,
        config: &crate::config::AppConfig,
        subnet: &str,
        row: crate::config::AdoptedMeta,
    ) -> Result<(), AppError> {
        config.set_binding_intent(subnet, row)
    }
}

static ADDRESS_REQUEST: AtomicU64 = AtomicU64::new(0);
struct AddressTrace {
    id: u64,
    started: std::time::Instant,
    phase_at: StdMutex<std::time::Instant>,
    native: AtomicU64,
    provider: AtomicU64,
    success: AtomicBool,
}
impl AddressTrace {
    fn identity(&self, snapshot: &interface::OperationSnapshot, prefix: Option<u8>) {
        log::info!("event=address_operation operation={} adapter_guid={} adapter_mac={} interface_index={} alias={} prefix={}",
            self.id, log_value(&snapshot.selected.guid), log_value(&snapshot.selected.mac), snapshot.selected.index,
            log_value(&snapshot.selected.alias), prefix.map_or_else(|| "unknown".into(), |p| p.to_string()));
    }
    fn new(action: &str, address: &str) -> Self {
        let now = std::time::Instant::now();
        let value = Self {
            id: ADDRESS_REQUEST.fetch_add(1, Ordering::Relaxed) + 1,
            started: now,
            phase_at: StdMutex::new(now),
            native: AtomicU64::new(0),
            provider: AtomicU64::new(0),
            success: AtomicBool::new(false),
        };
        log::info!(
            "event=address_operation operation={} action={} address={} phase=request",
            value.id,
            action,
            log_value(address)
        );
        value
    }
    fn phase(&self, phase: &str) {
        let mut at = self.phase_at.lock().unwrap_or_else(|p| p.into_inner());
        log::info!("event=address_operation operation={} phase={} elapsed_ms={} phase_ms={} native_calls={} provider_calls={}",
            self.id, phase, self.started.elapsed().as_millis(), at.elapsed().as_millis(),
            self.native.load(Ordering::Relaxed),
            self.provider.load(Ordering::Relaxed));
        *at = std::time::Instant::now();
    }
    fn native_call(&self) {
        self.native.fetch_add(1, Ordering::Relaxed);
    }
    fn provider_call(&self) {
        self.provider.fetch_add(1, Ordering::Relaxed);
    }

    fn succeeded(&self) {
        self.success.store(true, Ordering::Relaxed);
    }
}
impl Drop for AddressTrace {
    fn drop(&mut self) {
        self.phase("reply");
        log::info!(
            "event=address_operation operation={} outcome={}",
            self.id,
            if self.success.load(Ordering::Relaxed) {
                "success"
            } else {
                "pending_or_failed"
            }
        );
    }
}

struct BindingContext<'a> {
    snapshot: &'a Result<interface::OperationSnapshot, AppError>,
    mode: crate::config::NetworkMode,
    trace: Option<&'a AddressTrace>,
}

struct AddressOps<'a>(
    &'a dyn interface::AddressIo,
    Option<&'a interface::NativeAdapter>,
);
impl auto_adopt::AdoptOps for AddressOps<'_> {
    fn check_writes_available(&self) -> Result<(), AppError> {
        self.0.check_writes_available()
    }
    async fn observe(&self, alias: &str) -> Result<InterfaceInfo, AppError> {
        let all = interface::read_native_with(self.0).await?;
        let native = interface::native_by_alias(&all, alias)?;
        self.0
            .descriptor(native)
            .ok_or_else(|| AppError::Network("Adapter requires qualification".into()))
    }
    async fn add(&self, alias: &str, ip: Ipv4Addr, mask: &str) -> Result<(), AppError> {
        let adapter = self
            .1
            .filter(|a| a.alias == alias)
            .ok_or_else(|| AppError::Network("Address writer has no validated adapter".into()))?;
        self.0.add(adapter, &ip.to_string(), mask).await
    }
    async fn remove(&self, alias: &str, ip: Ipv4Addr) -> Result<(), AppError> {
        let owned;
        let adapter = if let Some(adapter) = self.1 {
            adapter
        } else {
            owned = interface::read_native_with(self.0).await?;
            let native = interface::native_by_alias(&owned, alias)?;
            if self
                .0
                .descriptor(native)
                .filter(interface::is_wired_physical)
                .is_none()
            {
                return Err(AppError::Network("Adapter requires qualification".into()));
            }
            native
        };
        if adapter.alias != alias {
            return Err(AppError::Network("Adapter alias changed".into()));
        }
        self.0.remove(adapter, &ip.to_string()).await
    }
    async fn probe(&self, _: Ipv4Addr, _: Option<Ipv4Addr>) -> bool {
        true
    }
}

impl NetworkManager {
    pub(crate) fn emit_selection(&self, selection: &AdapterSelection) {
        self.selector.observe(selection);
        let _ = crate::bridge::emit(self.bridge.as_ref(), "adapter-selection-changed", selection);
        let _ = crate::bridge::emit(
            self.bridge.as_ref(),
            "interface-status-changed",
            &watcher::selected_status(selection),
        );
    }

    pub(crate) fn readiness(&self) -> Arc<readiness::CameraReadiness> {
        self.readiness.clone()
    }
    pub async fn scan_subnet(
        &self,
        subnet: &str,
        config: &crate::config::AppConfig,
    ) -> Result<Vec<ScanResult>, AppError> {
        self.scans
            .scan_subnet(&self.readiness, subnet, config)
            .await
    }
    pub async fn start_ping_dot(&self) {
        self.pinger
            .start(
                self.readiness.clone(),
                self.device_registry.clone(),
                self.bridge.clone(),
            )
            .await;
    }
    pub async fn stop_ping_dot(&self) {
        self.pinger.stop().await;
    }

    fn discovery_deps(&self) -> discovery_session::DiscoveryDeps {
        discovery_session::DiscoveryDeps {
            selector: self.selector.clone(),
            capture: self.capture.clone(),
            bindings: self.bindings.clone(),
            config: self.config.clone(),
            bridge: self.bridge.clone(),
            registry: self.device_registry.clone(),
            emitter: self.device_emitter.clone(),
        }
    }
    pub(crate) async fn start_presence(&self) {
        self.selector
            .start_presence(presence::PresenceDeps {
                owners: self.discovery_deps(),
                session: self.discovery.clone(),
            })
            .await;
    }

    async fn stop_capture_locked(&self) {
        self.capture.stop_capture_locked().await;
    }
    fn candidate_ingress(&self, index: u32, mac: Option<[u8; 6]>) -> Option<arp::CandidateIngress> {
        self.capture.candidate_ingress(index, mac)
    }
    pub async fn get_capture_state(&self) -> CaptureState {
        self.capture.get_capture_state().await
    }

    pub(crate) fn event_bridge(&self) -> Arc<dyn crate::bridge::AppBridge> {
        self.bridge.clone()
    }
    pub async fn adoption_snapshot(&self) -> AdoptionSnapshot {
        self.bindings
            .adoption_snapshot(&self.discovery.discovery_started)
            .await
    }

    pub(crate) async fn pending_ip_strings(&self) -> HashSet<String> {
        self.bindings.pending_ip_strings().await
    }
    pub async fn get_adopted_ips(&self) -> HashMap<String, String> {
        self.bindings.get_adopted_ips().await
    }
    #[cfg(windows)]
    pub(super) fn hydrate_adoption_history(&self, config: &crate::config::AppConfig) {
        self.bindings.hydrate_adoption_history(config);
    }

    #[cfg(test)]
    fn with_address_io(io: Arc<dyn interface::AddressIo>) -> Self {
        Self::with_io(
            Arc::new(crate::config::AppConfig::for_test(Default::default())),
            Arc::new(crate::bridge::TauriBridge::<tauri::Wry>::default()),
            io,
        )
    }

    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_dependencies(
            Arc::new(crate::config::AppConfig::for_test(Default::default())),
            Arc::new(crate::bridge::TauriBridge::<tauri::Wry>::default()),
        )
    }

    pub(crate) fn with_dependencies(
        config: Arc<crate::config::AppConfig>,
        bridge: Arc<dyn crate::bridge::AppBridge>,
    ) -> Self {
        Self::with_io(config, bridge, Arc::new(interface::RealAddressIo))
    }
    fn with_io(
        config: Arc<crate::config::AppConfig>,
        bridge: Arc<dyn crate::bridge::AppBridge>,
        io: Arc<dyn interface::AddressIo>,
    ) -> Self {
        let registry = Arc::new(DeviceRegistry::new());
        let emitter = DeviceListEmitter::new(bridge.clone(), registry.clone());
        let selector = Arc::new(adapter_selector::AdapterSelector::new());
        let mut store = binding_store::BindingStore::new(config.clone(), selector.clone());
        store.address_io = io;
        let bindings = Arc::new(store);
        let discovery = Arc::new(discovery_session::DiscoverySession::new());
        let pinger = ping_dot::Pinger::new();
        let readiness = Arc::new(readiness::CameraReadiness {
            selector: selector.clone(),
            bindings: bindings.clone(),
            discovery: discovery.clone(),
            device_registry: registry.clone(),
            device_emitter: emitter.clone(),
            config: config.clone(),
            diagnostic_ready: pinger.diagnostic_ready.clone(),
        });
        Self {
            selector,
            bindings,
            capture: Arc::new(capture_session::CaptureSession::new()),
            discovery,
            bridge,
            config,
            scans: scan::ScanWorkflow::new(),
            readiness,
            pinger,

            device_registry: registry,
            device_emitter: emitter,

            discovery_op: Arc::new(Mutex::new(())),
        }
    }

    /// Hydrate the device registry from the on-disk cache. Idempotent
    /// (the registry's own one-shot guard prevents re-hydration), but
    /// expected to be called once at startup before ARP discovery so
    /// the initial snapshot reflects last-known state.
    ///
    /// Topology conflicts stay inactive with a reason. Hydration never
    /// deletes stored history; APIPA remains stored outside live Nodes.
    pub async fn hydrate_device_registry(&self, config: &crate::config::AppConfig) {
        // Retain APIPA history on disk without making it a live node or
        // sending it through topology pruning and frontend verify/eviction.
        let cached = config
            .get_cache()
            .into_iter()
            .filter(|record| {
                !record
                    .ip
                    .parse::<Ipv4Addr>()
                    .is_ok_and(|ip| ip.is_link_local())
            })
            .collect();

        // Failed topology enumeration leaves history cached/inactive.
        let ghosts = ghost::non_wired_interface_networks().await;
        // A cached row belongs to this host only if its MAC matches a local
        // adapter. IPs can overlap across the Ethernet and Wi-Fi links.
        let local_macs = interface::local_adapter_macs();
        hydrate_retained_history(&self.device_registry, cached, &ghosts, &local_macs);

        // Keep conflicting legacy role identities for explicit reassignment.
        let camera_key = config.get().stream.camera_mac;
        let demoted = self
            .device_registry
            .normalize_role_duplicates(camera_key.as_deref());
        if !demoted.is_empty() {
            log::info!("Ambiguous role identities: {}", demoted.join(", "));
            persist_alias_writethrough(&self.device_registry, config, &demoted);
        }

        log::info!(
            "DeviceRegistry: retained {} cached identities",
            self.device_registry.snapshot().len()
        );
    }

    pub fn registry(&self) -> Arc<DeviceRegistry> {
        self.device_registry.clone()
    }

    /// Hydrate the device registry from the user's pinned manual-nodes
    /// list. Used by `NetworkMode::StaticManual` startup to populate the
    /// Nodes panel without going through ARP discovery.
    pub async fn hydrate_manual_nodes(&self, config: &crate::config::AppConfig) {
        let nodes = config.get_manual_nodes();
        if nodes.is_empty() {
            return;
        }
        let count = nodes.len();
        let mut hydrated = self.device_registry.hydrate_manual_nodes(&nodes);
        hydrated |= keep_prohibited_history_inactive(&self.device_registry);
        if hydrated {
            log::info!("DeviceRegistry: hydrated {} manual node(s)", count);
        }

        // Manual-node config rows can carry a legacy CAM/PTU alias that
        // collides with a discovered holder. Enforce the single-holder
        // invariant and write demotions back (registry + config), so a
        // mode toggle can't resurrect a duplicate.
        let camera_key = config.get().stream.camera_mac;
        let demoted = self
            .device_registry
            .normalize_role_duplicates(camera_key.as_deref());
        if !demoted.is_empty() {
            persist_alias_writethrough(&self.device_registry, config, &demoted);
        }

        if hydrated || !demoted.is_empty() {
            self.selector.presence.bootstrap();
            self.device_emitter.poke();
        }
    }

    /// Warn, fence and drain address work, change OS/config, observe the
    /// resulting state, then resume eligible work with a fresh DHCP cache.
    pub async fn transition_mode(
        &self,
        config: &crate::config::AppConfig,
        request: ModeTransition,
    ) -> Result<ModeTransitionReply, AppError> {
        use crate::config::NetworkMode;
        #[cfg(windows)]
        native_operations::check_writes_available()?;
        let _op = self.discovery_op.lock().await;
        let iface = self
            .bindings
            .selected_write_adapter(config, &request.name)
            .await?;
        // The warning response precedes even cancellation or a config mutation.
        if request.mode == NetworkMode::Dhcp && !request.confirmed {
            return Ok(ModeTransitionReply {
                warning: Some("Switching to DHCP removes manually configured addresses from this adapter. Saved managed secondaries will remain pending until a static mode returns. Continue?".into()),
                mode: config.get_network_mode(),
                primary_address: config.get().primary_addresses.get(&adapter_mac(&iface.mac).unwrap_or_default()).cloned(),
            });
        }
        if request.mode != NetworkMode::Dhcp {
            let ip = request
                .ip
                .as_deref()
                .ok_or_else(|| AppError::Network("Static address is required".into()))?;
            ip.parse::<Ipv4Addr>()
                .map_err(|_| AppError::Network("Invalid static address".into()))?;
            ip_config::mask_to_prefix(
                request
                    .subnet_mask
                    .as_deref()
                    .ok_or_else(|| AppError::Network("Subnet mask is required".into()))?,
            )?;
            if let Some(gw) = &request.gateway {
                gw.parse::<Ipv4Addr>()
                    .map_err(|_| AppError::Network("Invalid gateway".into()))?;
            }
        }
        let old_mode = config.get_network_mode();
        let preserve_capture = mode_keeps_capture(old_mode, request.mode);
        let pause = self.bindings.pause_addresses();
        // Every Apply cancels the session/address work. DHCP -> Auto keeps
        // the listener that is already hearing the camera's link-up burst.
        if preserve_capture {
            self.stop_session_locked().await;
        } else {
            self.stop_locked().await;
        }
        let address = self.bindings.address_work.lock().await;
        let result = async {
            #[cfg(windows)]
            native_operations::check_writes_available()?;
            // Refresh identity after waiting for in-flight scratch cleanup.
            let before = self.bindings.operation_snapshot(config).await?;
            if before.selected.alias != request.name
                || adapter_mac(&before.selected.mac) != adapter_mac(&iface.mac)
            {
                return Err(AppError::Network("Selected adapter changed".into()));
            }
            let previous = if request.mode != NetworkMode::Dhcp {
                self.bindings
                    .primary_to_replace(config, &before, &request)?
            } else {
                None
            };
            if request.mode == NetworkMode::Dhcp {
                ip_config::set_dhcp(&iface.name).await?;
            } else {
                ip_config::assign_static_ip(
                    &iface.name,
                    request.ip.as_deref().unwrap(),
                    request.subnet_mask.as_deref().unwrap(),
                    request.gateway.as_deref(),
                    &before.selected.identity(),
                )
                .await?;
                self.bindings
                    .finish_primary_change(config, &before, &request, previous)
                    .await?;
            }
            let actual_dhcp = ip_config::get_dhcp_state(&iface.name).await?;
            if actual_dhcp != (request.mode == NetworkMode::Dhcp) {
                return Err(AppError::Network(
                    "Windows did not apply the requested DHCP/static mode".into(),
                ));
            }
            config.set_network_mode(request.mode)?;
            Ok(())
        }
        .await;
        // Even partial OS/config failure is followed by a fresh observation.
        self.bindings.reconcile_temporary_locked(config).await;
        self.bindings.reconcile_bindings_locked(config).await;
        let mode = config.get_network_mode();
        self.update_presence_adapter(&self.adapter_selection_state().await, mode);
        self.selector.presence.tick(&self.device_registry);
        drop(address);
        drop(pause);
        if mode == NetworkMode::StaticManual && old_mode != mode {
            for record in self.device_registry.snapshot() {
                if record.mac.starts_with("manual:")
                    || record.open_ports.is_empty()
                    || record
                        .ip
                        .parse()
                        .is_ok_and(crate::validation::prohibited_camera_ip)
                {
                    continue;
                }
                if let Err(e) = config.add_manual_node(crate::config::ManualNode {
                    expected_mac: device_registry::canonical_mac(&record.mac),
                    ip: record.ip,
                    alias: record.alias,
                }) {
                    log::warn!("Failed to auto-pin device: {}", e);
                }
            }
        }
        self.hydrate_manual_nodes(config).await;
        #[cfg(windows)]
        let resume = !native_operations::request_canceled();
        #[cfg(not(windows))]
        let resume = true;
        if resume && mode != NetworkMode::StaticManual && crate::is_discovery_available() {
            if let Err(e) = self
                .start_arp_discovery_body(&iface.name, config, false, preserve_capture)
                .await
            {
                log::warn!("Discovery restart after mode transition: {}", e);
            }
        }
        self.selector.presence.bootstrap();
        if resume {
            self.start_ping_dot().await;
        }
        result?;
        Ok(ModeTransitionReply {
            warning: None,
            mode,
            primary_address: config
                .get()
                .primary_addresses
                .get(&adapter_mac(&iface.mac).unwrap_or_default())
                .cloned(),
        })
    }

    /// Borrow the emitter constructed with the registry before hydration.
    /// Mutators that want to publish a `device-list-changed` event call
    /// `.poke()` on the result.
    pub async fn emitter(&self) -> Option<Arc<DeviceListEmitter>> {
        Some(self.device_emitter.clone())
    }

    /// Reconcile durable intent from actual selected-adapter addresses. Never
    /// prune malformed, unavailable, DHCP, or adapter-mismatched saved rows.
    pub async fn load_adopted_from_config(&self, config: &crate::config::AppConfig) {
        let _op = self.discovery_op.lock().await;
        let pause = self.bindings.pause_addresses();
        let _address = self.bindings.address_work.lock().await;
        self.bindings.reconcile_temporary_locked(config).await;
        self.bindings.reconcile_bindings_locked(config).await;
        drop(_address);
        drop(pause);
        self.selector.presence.bootstrap();
        let snapshot = self.adoption_snapshot().await;
        for (subnet, ip) in &snapshot.adopted_subnets {
            let meta = &snapshot.meta[subnet];
            let _ = self
                .bridge
                .emit("subnet-adopted", adoption_event(subnet, ip, meta, true));
        }
    }

    pub async fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>, AppError> {
        let list = interface::list_physical().await?;
        // Scratch/pending addresses are transient probe state, not host
        // addresses — the UI must never render them as host rows, and
        // their bind/release must not read as an IP change.
        Ok(strip_pending_ips(list, &self.pending_ip_strings().await))
    }

    pub async fn adapter_selection_state(&self) -> AdapterSelection {
        self.selector.snapshot().await
    }

    pub(crate) fn selection_observed(&self, selection: &AdapterSelection) {
        self.selector.observe(selection);
    }

    pub(crate) fn update_presence_adapter(
        &self,
        selection: &AdapterSelection,
        mode: crate::config::NetworkMode,
    ) {
        self.selector.update_presence_adapter(selection, mode);
    }

    pub(crate) async fn stop_presence(&self) {
        self.selector.stop_presence(&self.device_registry).await;
    }

    async fn native_interfaces(
        &self,
        selected_mac: Option<&str>,
    ) -> Result<(Vec<interface::NativeAdapter>, Vec<InterfaceInfo>), AppError> {
        let Some(mac) = selected_mac else {
            let views = self.list_interfaces().await?;
            return Ok((
                interface::read_native_with(self.bindings.address_io.as_ref()).await?,
                views,
            ));
        };
        let mut all = interface::read_native_with(self.bindings.address_io.as_ref()).await?;
        if let Ok(selected) = interface::select_native(&all, mac) {
            if self.bindings.address_io.descriptor(selected).is_none() {
                let before = selected.identity();
                self.bindings.address_io.qualify().await?;
                all = interface::read_native_with(self.bindings.address_io.as_ref()).await?;
                if interface::select_native(&all, mac)?.identity() != before {
                    return Err(AppError::Network(
                        "Adapter changed during qualification".into(),
                    ));
                }
            }
        }
        let mut views: Vec<_> = all
            .iter()
            .filter_map(|n| self.bindings.address_io.descriptor(n))
            .collect();
        let pending = self.pending_ip_strings().await;
        views = strip_pending_ips(views, &pending);
        Ok((all, views))
    }

    /// A native display snapshot, without discovery/address locks or writes.
    /// It does not change the backend's selected adapter or session lifecycle.
    pub async fn adapter_selection_view(
        &self,
        config: &crate::config::AppConfig,
    ) -> Result<AdapterSelection, AppError> {
        let selected_mac = config.get().selected_adapter_mac;
        let (native, views) = self.native_interfaces(selected_mac.as_deref()).await?;
        if config.get().selected_adapter_mac != selected_mac {
            return Err(AppError::Network(
                "Selected adapter changed during display read; retry".into(),
            ));
        }
        let adapter = pick_adapter(&views, selected_mac.as_deref()).cloned();
        let interface_index = adapter
            .as_ref()
            .map(|a| interface::select_native(&native, &a.mac).map(|n| n.index))
            .transpose()?;
        let candidates: Vec<_> = views.into_iter().filter(adapter_candidate).collect();
        Ok(AdapterSelection {
            selection_required: selected_mac.is_none() && candidates.len() > 1,
            selected_mac,
            adapter,
            interface_index,
            candidates,
        })
    }

    pub async fn get_adapter_selection(
        &self,
        config: &crate::config::AppConfig,
    ) -> Result<AdapterSelection, AppError> {
        let (_, list) = self
            .native_interfaces(config.get().selected_adapter_mac.as_deref())
            .await?;
        self.resolve_adapter_selection(config, &list).await
    }

    pub async fn resolve_adapter_selection(
        &self,
        config: &crate::config::AppConfig,
        list: &[InterfaceInfo],
    ) -> Result<AdapterSelection, AppError> {
        let _op = self.discovery_op.lock().await;
        let previous = self.adapter_selection_state().await;
        let selection = self.resolve_adapter_locked(config, list).await?;
        // A cable cycle commonly retains the same Windows interface index.
        // Identity changes are restored by the watcher/start path; link-only
        // changes still reconcile pending additions and removals here.
        if binding_link_changed(&previous, &selection) {
            let _pause = self.bindings.pause_addresses();
            let _address = self.bindings.address_work.lock().await;
            self.bindings.reconcile_temporary_locked(config).await;
            self.bindings.reconcile_bindings_locked(config).await;
            self.selector.presence.bootstrap();
        }
        Ok(selection)
    }

    async fn resolve_adapter_locked(
        &self,
        config: &crate::config::AppConfig,
        list: &[InterfaceInfo],
    ) -> Result<AdapterSelection, AppError> {
        let selection = self.selector.propose(config, list)?;
        let mac = selection.selected_mac.clone();
        let adapter = selection.adapter.clone();
        let index = selection.interface_index;
        let previous = self.adapter_selection_state().await;
        let pending_selection = AdapterSelection {
            selected_mac: mac.clone(),
            adapter: adapter.clone(),
            interface_index: index,
            ..Default::default()
        };
        self.update_presence_adapter(&pending_selection, config.get_network_mode());
        self.selector.presence.tick(&self.device_registry);
        if previous.selected_mac != mac || previous.interface_index != index {
            if let Some(identity) = self.capture.capture_identity.lock().await.as_ref() {
                identity.active.store(false, Ordering::Release);
            }
            self.stop_locked().await;
            // Retire routes from the live map without losing saved bindings.
            self.bindings.adopted_ips.lock().await.clear();
            if let Ok(mut meta) = self.bindings.adopted_meta.lock() {
                for row in meta.values_mut() {
                    // Adapter loss must not reopen a completed deletion.
                    // Reconciliation rechecks its absence on adapter return.
                    if row.removal_complete() {
                        continue;
                    }
                    row.applied = false;
                    row.last_error = Some("selected adapter unavailable".into());
                }
            }
        }
        if previous.selected_mac != mac || previous.interface_index != index {
            log::info!(
                "event=adapter_selection adapter_mac={} interface_index={} available={}",
                log_value(mac.as_deref().unwrap_or("unknown")),
                index.unwrap_or(0),
                adapter.is_some()
            );
        }
        self.selector.commit(&selection).await;
        Ok(selection)
    }

    pub async fn select_adapter(
        &self,
        config: &crate::config::AppConfig,
        mac: &str,
    ) -> Result<AdapterSelection, AppError> {
        self.bindings.address_io.check_writes_available()?;
        {
            let _op = self.discovery_op.lock().await;
            let list = self.list_interfaces().await?;
            let iface = pick_adapter(&list, Some(mac)).ok_or_else(|| {
                AppError::Network("Selected Ethernet adapter is unavailable or ineligible".into())
            })?;
            config.set_selected_adapter_mac(adapter_mac(&iface.mac).unwrap())?;
            self.resolve_adapter_locked(config, &list).await?;
        }
        #[cfg(windows)]
        let resume = !native_operations::request_canceled();
        #[cfg(not(windows))]
        let resume = true;
        if resume {
            self.start_selected_adapter(config).await;
        }
        self.get_adapter_selection(config).await
    }

    pub async fn start_selected_adapter(&self, config: &crate::config::AppConfig) {
        self.load_adopted_from_config(config).await;
        let selection = self.adapter_selection_state().await;
        if config.get_network_mode() != crate::config::NetworkMode::StaticManual
            && crate::is_discovery_available()
        {
            if let Some(iface) = selection.adapter {
                if let Err(e) = self.start_arp_discovery(&iface.name, config).await {
                    log::info!("Selected Ethernet discovery waiting: {e}");
                }
            }
        }
    }

    /// Complete a pre-attach or retry a failed start without UI participation.
    /// True requests the watcher's normal metadata/identity refresh path.
    pub(crate) async fn resume_discovery(
        &self,
        config: &crate::config::AppConfig,
    ) -> Result<bool, AppError> {
        let Ok(_op) = self.discovery_op.try_lock() else {
            return Ok(false); // a start, stop or mode transition already owns it
        };
        let settings = config.get();
        if settings.network_mode == crate::config::NetworkMode::StaticManual
            || !crate::is_discovery_available()
            || self.selector.presence.stopped()
        {
            return Ok(false);
        }
        let mut selection = self.adapter_selection_state().await;
        let native = settings.selected_adapter_mac.as_deref().and_then(|mac| {
            let (index, link_up) = interface::quick_link_by_mac(mac)?;
            let (up, ips) = interface::quick_status_by_mac(mac)?;
            Some((index, link_up && up, ips))
        });
        let action = discovery_resume_action(
            settings.network_mode,
            crate::is_discovery_available(),
            self.discovery.discovery_active.load(Ordering::Acquire),
            settings.selected_adapter_mac.as_deref(),
            &selection,
            native,
            self.capture.capture_signal.lock().await.state.active,
        );
        match action {
            DiscoveryResume::Idle => Ok(false),
            DiscoveryResume::RefreshSelection => Ok(true),
            DiscoveryResume::Start(mut iface) => {
                let pending = self.pending_ip_strings().await;
                iface.ips.retain(|ip| !pending.contains(&ip.address));
                let up = iface.is_up;
                log::info!("event=discovery_resume adapter_mac={} interface_index={} phase=start link_up={}",
                    log_value(&iface.mac), selection.interface_index.unwrap_or(0), up);
                selection.adapter = Some(iface);
                self.update_presence_adapter(&selection, settings.network_mode);
                self.emit_selection(&selection);
                let result = self
                    .start_selected_discovery_locked(selection, config, false, true)
                    .await;
                if let Err(error) = result {
                    if up || !self.capture.capture_signal.lock().await.state.active {
                        return Err(error);
                    }
                    log::info!("event=discovery_resume phase=waiting_for_link");
                } else {
                    log::info!("event=discovery_resume phase=ready");
                }
                Ok(false)
            }
        }
    }

    pub(crate) async fn camera_ready(
        &self,
        target: &route::CameraTarget,
        config: &crate::config::AppConfig,
    ) -> Result<route::ReadyPath, AppError> {
        self.readiness.camera_path_now(target, config, false)
    }

    /// Native/in-memory checks only; callable on the relay's GLib threads.
    pub(crate) fn camera_ready_now(
        &self,
        target: &route::CameraTarget,
        config: &crate::config::AppConfig,
    ) -> Result<route::ReadyPath, AppError> {
        self.readiness.camera_path_now(target, config, false)
    }

    /// Start ARP discovery (PacketMonitor capture) on the Ethernet
    /// interface. Also spawns auto-adopt handler for foreign subnets.
    ///
    /// Public entry point: serializes the discovery lifecycle on the op
    /// lock so it cannot interleave with a concurrent stop / mode change /
    /// startup restore (which would orphan the auto-adopt loop).
    pub async fn start_arp_discovery(
        &self,
        interface_display_name: &str,
        config: &crate::config::AppConfig,
    ) -> Result<(), AppError> {
        let _op = self.discovery_op.lock().await;
        self.start_arp_discovery_locked(interface_display_name, config)
            .await
    }

    pub async fn refresh_arp_discovery(
        &self,
        interface: &str,
        config: &crate::config::AppConfig,
    ) -> Result<(), AppError> {
        let _op = self.discovery_op.lock().await;
        self.start_arp_discovery_body(interface, config, true, false)
            .await
    }

    /// Start body, run with the discovery op lock already held. Callers
    /// that already hold it (`apply_mode_change`) delegate here so the
    /// non-reentrant lock isn't acquired twice.
    async fn start_arp_discovery_locked(
        &self,
        interface_display_name: &str,
        config: &crate::config::AppConfig,
    ) -> Result<(), AppError> {
        self.start_arp_discovery_body(interface_display_name, config, false, false)
            .await
    }

    async fn start_arp_discovery_body(
        &self,
        interface_display_name: &str,
        config: &crate::config::AppConfig,
        refresh: bool,
        preserve_capture: bool,
    ) -> Result<(), AppError> {
        // Authoritative mode gate, read under the discovery op lock:
        // a start queued behind an Auto→Manual transition observes Manual
        // here. DHCP mode runs discovery
        // exactly like Static-Auto; only Static-Manual is refused.
        if config.get_network_mode() == crate::config::NetworkMode::StaticManual {
            return Err(AppError::Network(
                "ARP discovery does not run in Static-Manual mode".into(),
            ));
        }

        let list = self.list_interfaces().await?;
        let selection = self.resolve_adapter_locked(config, &list).await?;
        let iface_info = selection.adapter.as_ref().ok_or_else(|| AppError::Network("Selected Ethernet adapter unavailable; select an adapter in Configure when multiple candidates exist".into()))?;
        if iface_info.name != interface_display_name || selection.interface_index.is_none() {
            return Err(AppError::Network(
                "Discovery target does not match the selected Ethernet adapter".into(),
            ));
        }

        self.start_selected_discovery_locked(selection, config, refresh, preserve_capture)
            .await
    }

    /// Caller holds discovery_op and has resolved the selected MAC/index.
    /// Readiness retries use native addresses with validated cached metadata,
    /// rather than repeating the slow provider query after a link-up burst.
    async fn start_selected_discovery_locked(
        &self,
        selection: AdapterSelection,
        config: &crate::config::AppConfig,
        refresh: bool,
        preserve_capture: bool,
    ) -> Result<(), AppError> {
        if config.get_network_mode() == crate::config::NetworkMode::StaticManual {
            return Err(AppError::Network(
                "ARP discovery does not run in Static-Manual mode".into(),
            ));
        }
        let iface_info = selection
            .adapter
            .ok_or_else(|| AppError::Network("Selected Ethernet adapter unavailable".into()))?;
        let interface_display_name = iface_info.name.as_str();

        // Session-only teardown: a capture listener that is still valid
        // for this adapter is retained and re-evaluated below.
        self.stop_session_locked().await;

        // The adapter's MAC serves double duty: the capture session is
        // attach-time scoped to the data source carrying this MAC, and
        // the listener drops ARP frames the adapter itself sent (our own
        // gratuitous ARP).
        // Structural gate, media-independent: the capture listener may
        // bind a disconnected wired port — that is the point of
        // pre-attaching — but never WiFi/VPN/virtual. Callers supply
        // arbitrary names; the backend is the enforcement point. A
        // rejection here leaves any listener retained from a previously
        // validated adapter untouched.
        if !interface::is_wired_physical(&iface_info) {
            return Err(AppError::Network(format!(
                "'{}' is not a wired Ethernet adapter — ARP discovery only runs on the wired camera port",
                interface_display_name
            )));
        }
        let known_ips: Vec<String> = iface_info.ips.iter().map(|ip| ip.address.clone()).collect();
        let settings = config.get();
        let retained: HashSet<Ipv4Addr> = settings
            .adopted_subnets
            .values()
            .chain(
                settings
                    .adopted_meta
                    .values()
                    .filter_map(|m| m.address.as_ref()),
            )
            .filter_map(|ip| ip.parse().ok())
            .collect();
        let native_sweep_ips = select_sweep_ips(&iface_info.ips, &retained, false);
        let sweep_ips = select_sweep_ips(&iface_info.ips, &retained, refresh);
        let own_mac = parse_mac_bytes(&iface_info.mac);
        let interface_index = interface::index_for_mac(&iface_info.mac).ok_or_else(|| {
            AppError::Network(format!(
                "No unique IPv4 interface index for adapter '{}'",
                interface_display_name
            ))
        })?;
        // Capture identity for attach-time scoping: the same MAC that
        // feeds the own-frame filter, plus the display name for logs. A
        // None MAC (unparseable) makes the join fail and the capture
        // fall back to an unscoped session rather than guessing.
        let capture_scope = pktmon::CaptureScope {
            mac: own_mac,
            display_name: interface_display_name.to_string(),
            description: iface_info.description.clone(),
        };

        // Recognize this PC by all of its adapter MACs, not its IP addresses.
        // A wired peer can share an IP with Wi-Fi on a separate link. The same
        // shared set survives capture restarts and is refreshed each pass.
        self.selector.refresh_local_macs();
        let local_macs = self.selector.local_macs.clone();

        let registry = self.device_registry.clone();

        let emitter = self.device_emitter.clone();
        // Emit the initial snapshot so any frontend that's already
        // subscribed sees cache-hydrated devices without having to
        // separately call get_device_list.
        emitter.poke();

        let devices = self.discovery.arp_devices.clone();
        // Placeholder fence for the shared bundle: the listener swaps in
        // its capture-lifecycle fence inside `ensure_capture_listener`,
        // and the session halves below rebind the bundle with the real
        // session fence once the up-gate passes — this value itself
        // never fences a merge.
        let placeholder_fence = SweepFence::new(
            self.discovery.discovery_generation.load(Ordering::Relaxed),
            self.discovery.discovery_generation.clone(),
            self.discovery.discovery_active.clone(),
        );
        if interface_index == 0 || own_mac.is_none_or(|mac| mac == [0; 6] || mac[0] & 1 != 0) {
            return Err(AppError::Network(
                "Selected Ethernet identity is unavailable".into(),
            ));
        }
        let listener_params = arp::ListenerParams {
            candidates: self.candidate_ingress(interface_index, own_mac),
            devices: devices.clone(),
            registry: registry.clone(),
            emitter: emitter.clone(),
            bridge: self.bridge.clone(),
            config: self.config.clone(),
            local_macs: local_macs.clone(),
            own_mac,
            fence: placeholder_fence,
            scope: capture_scope,
        };
        // Attach, keep, or replace the persistent listener. The listener
        // runs under the capture-lifecycle fence that
        // `ensure_capture_listener` builds per incarnation.
        let activation_rx = self
            .capture
            .ensure_capture_listener(
                interface_display_name,
                own_mac,
                iface_info.is_up,
                &listener_params,
                preserve_capture,
            )
            .await?;

        // Up-gate: the session machinery below (sweep, watchdog, adopt)
        // needs a live link. On a down link the listener attached above
        // stays behind, already hearing the wire for the link-up burst,
        // and the caller gets the same error as always.
        if !iface_info.is_up {
            return Err(AppError::Network(format!(
                "'{}' is not an up, wired Ethernet adapter — ARP discovery only runs on the wired camera port",
                interface_display_name
            )));
        }

        self.discovery
            .start(
                self.discovery_deps(),
                discovery_session::StartDiscovery {
                    interface_display_name: interface_display_name.to_string(),
                    adapter_mac: iface_info.mac.clone(),
                    interface_index,
                    known_ips,
                    sweep_ips,
                    native_sweep_ips,
                    listener_params,
                    activation_rx,
                },
            )
            .await
    }

    /// Full stop — the session machinery plus the capture listener, in
    /// that order. Run with the discovery op lock already held.
    async fn stop_locked(&self) {
        self.stop_session_locked().await;
        self.stop_capture_locked().await;
        log::info!("ARP discovery stopped");
    }

    async fn stop_session_locked(&self) {
        self.discovery.stop_session_locked().await;
        // Reconcile any secondary IP the (now-stopped) adoption left bound
        // but unrecorded — scratch probes and final adds that never reached
        // adopted_ips. Best-effort; failures are logged and retried next stop.
        #[cfg(windows)]
        native_operations::drain().await;
        if let Ok(_address) = self.bindings.address_work.try_lock() {
            let initialized = self.capture.capture_signal.lock().await.app.is_some();
            if initialized {
                self.bindings.reconcile_temporary_locked(&self.config).await;
            }
        }
    }

    #[cfg(test)]
    pub async fn add_manual_address(
        &self,
        config: &crate::config::AppConfig,
        name: &str,
        ip: &str,
        mask: &str,
    ) -> Result<(), AppError> {
        self.address_operation(
            config,
            manual_address::AddressRequest::Add {
                name: name.into(),
                ip: ip.into(),
                mask: mask.into(),
            },
        )
        .await
        .legacy_result()
    }

    #[cfg(test)]
    pub async fn remove_adopted_subnet(
        &self,
        config: &crate::config::AppConfig,
        subnet: &str,
        iface_hint: Option<&str>,
    ) -> Result<Ipv4Addr, AppError> {
        let reply = self
            .address_operation(
                config,
                manual_address::AddressRequest::RemoveSaved {
                    subnet: subnet.into(),
                    hint: iface_hint.map(str::to_owned),
                },
            )
            .await;
        let address = reply
            .view
            .address
            .parse()
            .map_err(|_| AppError::Network("Invalid saved address".into()));
        reply.legacy_result()?;
        address
    }

    /// Only scratch and uncommitted final adds belong to shutdown cleanup.
    /// Committed addresses remain in Windows and in config, including APIPA.
    pub async fn cleanup_adopted_ips(&self, config: &crate::config::AppConfig) {
        // Stop producers before cleanup; the executor retains a dropped
        // request's child tree and barrier until the result is drained.
        let _op = self.discovery_op.lock().await;
        self.stop_locked().await;
        #[cfg(windows)]
        native_operations::drain().await;
        let _pause = self.bindings.pause_addresses();
        let _address = self.bindings.address_work.lock().await;
        self.bindings.reconcile_temporary_locked(config).await;
    }
}

/// Pick the wired-bound source IP for reaching `target`: the adopted
/// secondary IP whose subnet contains it wins (that binding was created
/// specifically to reach devices there), then the selected wired
/// interface's own IP on a containing network. `None` means no wired
/// route identity exists for this target — the caller must treat MAC
/// verification as failed, never probe unbound: an unbound ping routes
/// via the default gateway (possibly WiFi), the exact path wired-bound
/// verification exists to close. Malformed adopted keys are skipped.
fn select_wired_source(
    target: Ipv4Addr,
    adopted: &HashMap<String, Ipv4Addr>,
    iface_ips: &[interface::IpInfo],
) -> Option<Ipv4Addr> {
    for (subnet, ip) in adopted {
        if let Ok(net) = subnet.parse::<ipnetwork::Ipv4Network>() {
            if net.contains(target) {
                return Some(*ip);
            }
        }
    }
    for info in iface_ips {
        if let Ok(addr) = info.address.parse::<Ipv4Addr>() {
            if let Ok(net) = ipnetwork::Ipv4Network::new(addr, info.prefix) {
                if net.contains(target) {
                    return Some(addr);
                }
            }
        }
    }
    None
}

/// Parse a "AA:BB:CC:DD:EE:FF" or "AA-BB-..." MAC string into 6 bytes.
/// Returns None on any format mismatch so a missing/malformed MAC just
/// disables the self-filter rather than killing the listener.
fn parse_mac_bytes(mac: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

fn hydrate_retained_history(
    registry: &DeviceRegistry,
    cached: Vec<crate::config::CachedDevice>,
    ghosts: &[ipnetwork::Ipv4Network],
    local_macs: &HashSet<[u8; 6]>,
) {
    let (mut allowed, rejected) = ghost::partition_cached(cached, ghosts, local_macs);
    allowed.extend(rejected.iter().map(|(d, _)| d.clone()));
    registry.hydrate_from_cache(&allowed);
    for (d, reason) in rejected {
        registry.set_status(
            &d.mac,
            match reason {
                ghost::CacheReject::NonWiredSubnet => DeviceStatus::OfflineNonWiredSubnet,
                ghost::CacheReject::HostOwnedMac => DeviceStatus::OfflineHostOwnedIp,
            },
        );
    }
}

fn is_local_mac(mac: &str, local_macs: &HashSet<[u8; 6]>) -> bool {
    parse_mac_bytes(mac).is_some_and(|mac| local_macs.contains(&mac))
}

fn presence_target_is_host(
    job: &presence::Job,
    adapter: &InterfaceInfo,
    local_macs: &HashSet<[u8; 6]>,
) -> bool {
    // Resolving this NIC's own address cannot verify a peer. Addresses on
    // other adapters do not rule out a device on the selected Ethernet link.
    adapter
        .ips
        .iter()
        .any(|ip| ip.address == job.ip.to_string())
        || job
            .key
            .as_ref()
            .is_some_and(|key| is_local_mac(key, local_macs))
}

fn import_neighbors(
    entries: Vec<(Ipv4Addr, String)>,
    devices: &mut HashMap<String, ArpDevice>,
    excluded: &[ipnetwork::Ipv4Network],
    local_macs: &HashSet<[u8; 6]>,
    fence: &SweepFence,
    candidates: Option<&arp::CandidateIngress>,
) -> Vec<ArpDevice> {
    let mut collected = Vec::new();
    for (ip, mac) in entries {
        if fence.is_stale() {
            break;
        }
        if crate::validation::prohibited_camera_ip(ip)
            || is_local_mac(&mac, local_macs)
            || (candidates.is_none() && excluded.iter().any(|net| net.contains(ip)))
        {
            continue;
        }
        if let Some(ingress) = candidates {
            if let Some(mac) = parse_mac_bytes(&mac) {
                ingress.observe(ip, mac, fence, std::time::Instant::now());
            }
            continue;
        }
        if devices.contains_key(&mac) {
            continue;
        }
        let device = ArpDevice {
            ip: ip.to_string(),
            mac: mac.clone(),
            subnet: subnet_key_for(ip),
            first_seen: chrono::Utc::now().to_rfc3339(),
            last_seen: chrono::Utc::now().to_rfc3339(),
        };
        devices.insert(mac, device.clone());
        collected.push(device);
    }
    collected
}

/// Pending and removed saved rows never become live routing sources.
fn merge_adopted_config(
    live: &HashMap<String, Ipv4Addr>,
    meta: &HashMap<String, crate::config::AdoptedMeta>,
) -> HashMap<String, String> {
    live.iter()
        .filter(|(key, ip)| {
            meta.get(*key).is_some_and(|row| {
                row.desired == crate::config::BindingDesired::Present
                    && row.applied
                    && row.address.as_deref() == Some(ip.to_string().as_str())
                    && row.last_error.is_none()
            })
        })
        .map(|(key, ip)| (key.clone(), ip.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discovery_selection(up: bool) -> AdapterSelection {
        let mut iface = saved_adapter(&["192.168.1.100"]);
        iface.is_up = up;
        AdapterSelection {
            selected_mac: Some(iface.mac.clone()),
            adapter: Some(iface),
            interface_index: Some(7),
            ..Default::default()
        }
    }

    #[test]
    fn discovery_completes_pre_attach_on_native_up_without_an_identity_change() {
        let selection = discovery_selection(false);
        let ips = saved_adapter(&["192.168.1.100"]).ips;
        let decide = |up, capture| {
            discovery_resume_action(
                crate::config::NetworkMode::StaticAuto,
                true,
                false,
                selection.selected_mac.as_deref(),
                &selection,
                Some((7, up, ips.clone())),
                capture,
            )
        };
        assert!(matches!(decide(false, true), DiscoveryResume::Idle));
        assert!(matches!(decide(false, false), DiscoveryResume::Start(i) if !i.is_up));
        assert!(
            matches!(decide(true, true), DiscoveryResume::Start(i) if i.is_up && i.ips[0].address == "192.168.1.100")
        );
        // A rejected start never marks the session active, so the same native
        // state remains eligible on the next timer without another event.
        assert!(matches!(decide(true, true), DiscoveryResume::Start(_)));
    }

    #[test]
    fn discovery_retry_preserves_mode_identity_and_healthy_session_gates() {
        use crate::config::NetworkMode::{StaticAuto, StaticManual};
        let selection = discovery_selection(true);
        let native = Some((7, true, selection.adapter.as_ref().unwrap().ips.clone()));
        for (mode, available, active) in [
            (StaticManual, true, false),
            (StaticAuto, false, false),
            (StaticAuto, true, true),
        ] {
            assert!(matches!(
                discovery_resume_action(
                    mode,
                    available,
                    active,
                    selection.selected_mac.as_deref(),
                    &selection,
                    native.clone(),
                    true
                ),
                DiscoveryResume::Idle
            ));
        }
        for active in [false, true] {
            assert!(matches!(
                discovery_resume_action(
                    StaticAuto,
                    true,
                    active,
                    selection.selected_mac.as_deref(),
                    &selection,
                    Some((8, true, vec![])),
                    true
                ),
                DiscoveryResume::RefreshSelection
            ));
        }
        assert!(matches!(
            discovery_resume_action(
                StaticAuto,
                true,
                false,
                Some("40:cd:3a:00:00:02"),
                &selection,
                native,
                true
            ),
            DiscoveryResume::RefreshSelection
        ));
        let mut absent = selection.clone();
        absent.adapter = None;
        absent.interface_index = None;
        assert!(matches!(
            discovery_resume_action(
                StaticAuto,
                true,
                false,
                absent.selected_mac.as_deref(),
                &absent,
                None,
                false
            ),
            DiscoveryResume::Idle
        ));
        assert!(matches!(
            discovery_resume_action(
                StaticAuto,
                true,
                false,
                absent.selected_mac.as_deref(),
                &absent,
                Some((7, true, vec![])),
                false
            ),
            DiscoveryResume::RefreshSelection
        ));
        absent.selected_mac = None;
        absent.selection_required = true;
        assert!(matches!(
            discovery_resume_action(StaticAuto, true, false, None, &absent, None, false),
            DiscoveryResume::Idle
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn overlapping_wifi_address_requires_ethernet_proof_and_never_imports_host_mac() {
        use cache_probe::tests::MockProbeIo;
        let manager = NetworkManager::new();
        let selection = discovery_selection(true);
        manager
            .selector
            .presence
            .update(&selection, crate::config::NetworkMode::StaticAuto);
        manager.selector.presence.tick(&manager.registry());
        let snapshot = manager.selector.presence.snapshot();
        let ingress = manager
            .candidate_ingress(
                7,
                parse_mac_bytes(selection.selected_mac.as_deref().unwrap()),
            )
            .unwrap();
        let camera = "192.168.1.204".parse().unwrap();
        let wifi = "192.168.1.1".parse().unwrap();
        let peer = "40:cd:3a:03:8f:3f";
        let mut legacy = HashMap::new();
        let wired_mac = selection.selected_mac.as_deref().unwrap();
        let wifi_mac = "ac:45:ef:38:f9:f5";
        let local = HashSet::from([
            parse_mac_bytes(wired_mac).unwrap(),
            parse_mac_bytes(wifi_mac).unwrap(),
        ]);
        let excluded = ["192.168.1.0/24".parse().unwrap()];
        let imported = import_neighbors(
            vec![
                (camera, peer.into()),
                (wifi, "aa:bb:cc:dd:ee:04".into()),
                ("169.254.10.2".parse().unwrap(), peer.into()),
                ("192.168.1.100".parse().unwrap(), wired_mac.into()),
                (camera, wifi_mac.into()),
            ],
            &mut legacy,
            &excluded,
            &local,
            &snapshot.fence,
            Some(&ingress),
        );
        assert!(imported.is_empty() && legacy.is_empty());
        assert!(manager.registry().snapshot().is_empty());
        let candidates = manager
            .capture
            .candidates
            .snapshot(std::time::Instant::now());
        assert_eq!(candidates.len(), 2);
        import_neighbors(
            vec![("192.168.1.205".parse().unwrap(), peer.into())],
            &mut legacy,
            &excluded,
            &local,
            &fence(1, 2, true),
            Some(&ingress),
        );
        assert_eq!(
            manager.capture.candidates.count(std::time::Instant::now()),
            2
        );
        let mut clock = presence::Clock::default();
        let mut io = MockProbeIo::new();
        io.answers.insert(camera, peer.into());
        for _ in 0..2 {
            let job = clock
                .next(&snapshot, &manager.registry().snapshot(), &candidates)
                .unwrap();
            assert!(!presence_target_is_host(
                &job,
                snapshot.adapter.as_ref().unwrap(),
                &local
            ));
            assert_eq!(job.source, Some("192.168.1.100".parse().unwrap()));
            if let Some(proof) = presence::verify(&mut io, &job, &snapshot).await {
                let device = ArpDevice {
                    ip: proof.ip.to_string(),
                    mac: proof.mac.clone(),
                    subnet: subnet_key_for(proof.ip),
                    first_seen: proof.wall.clone(),
                    last_seen: proof.wall.clone(),
                };
                manager.registry().merge_verified(
                    &device,
                    selection.selected_mac.as_deref().unwrap(),
                    &proof.wall,
                    &snapshot.fence,
                );
                clock.verified(&proof.mac);
            }
        }
        assert_eq!(io.resolved_indices, [7, 7]);
        assert!(!io.events.iter().any(|e| e.starts_with("bind")));
        let records = manager.registry().snapshot();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ip, camera.to_string());
        assert_eq!(records[0].status, DeviceStatus::Live);
        assert!(manager.registry().cache_record(peer).is_some());
        assert!(manager
            .registry()
            .cache_record("aa:bb:cc:dd:ee:04")
            .is_none());
        // A successful response attributed to the wrong source/index is also
        // insufficient; it cannot rescue the Wi-Fi observation.
        io.source_index = 8;
        io.answers.insert(wifi, "aa:bb:cc:dd:ee:04".into());
        let job = presence::Job {
            key: None,
            ip: wifi,
            source: Some("192.168.1.100".parse().unwrap()),
        };
        assert!(presence::verify(&mut io, &job, &snapshot).await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn foreign_shared_prefix_candidates_require_auto_mode_and_fresh_proof() {
        use crate::config::NetworkMode::{Dhcp, StaticAuto, StaticManual};
        use cache_probe::tests::MockProbeIo;
        for mode in [StaticAuto, Dhcp, StaticManual] {
            let manager = NetworkManager::new();
            let mut selection = discovery_selection(true);
            selection.adapter.as_mut().unwrap().ips = saved_adapter(&["10.3.1.10"]).ips;
            manager.selector.presence.update(&selection, mode);
            manager.selector.presence.tick(&manager.registry());
            let snapshot = manager.selector.presence.snapshot();
            let ingress = manager
                .candidate_ingress(
                    7,
                    parse_mac_bytes(selection.selected_mac.as_deref().unwrap()),
                )
                .unwrap();
            let camera = "192.168.1.204".parse().unwrap();
            let peer = "40:cd:3a:03:8f:3f";
            import_neighbors(
                vec![(camera, peer.into())],
                &mut HashMap::new(),
                &["192.168.1.0/24".parse().unwrap()],
                &HashSet::new(),
                &snapshot.fence,
                Some(&ingress),
            );
            let candidates = manager
                .capture
                .candidates
                .snapshot(std::time::Instant::now());
            let job = presence::Clock::default().next(&snapshot, &[], &candidates);
            if mode != StaticAuto {
                assert!(job.is_none());
                continue;
            }
            let job = job.unwrap();
            assert_eq!(job.source, None);
            let mut io = MockProbeIo::new();
            assert!(presence::verify(&mut io, &job, &snapshot).await.is_none());
            assert!(io.bound.is_empty());
            assert!(!io.events.iter().any(|event| event.starts_with("adopt")));
            assert!(manager.registry().snapshot().is_empty());
            io.answers.insert(camera, peer.into());
            let proof = presence::verify(&mut io, &job, &snapshot).await.unwrap();
            assert_eq!(proof.mac, peer);
            assert_eq!(io.resolved_indices, [7, 7]);
            assert!(io.bound.is_empty());
            assert!(io.events.iter().any(|event| event.starts_with("adopt")));
        }
    }

    #[test]
    fn diagnostic_values_escape_field_and_line_injection() {
        let value = "adapter \" name\nforged=true\r\t";
        let quoted = log_value(value);
        assert_eq!(serde_json::from_str::<String>(&quoted).unwrap(), value);
        assert!(!quoted.contains('\n') && !quoted.contains('\r'));
        assert!(quoted.contains("\\n") && quoted.contains("\\\""));
    }

    #[test]
    fn adoption_events_distinguish_restore_and_carry_binding_ownership() {
        let mut row = saved_binding("172.26.95.99");
        row.applied = true;
        let view = adoption_meta_view(
            "172.26.95.0/24",
            Some(&row),
            None,
            std::time::Duration::ZERO,
            None,
        );
        for restored in [false, true] {
            let event = adoption_event("172.26.95.0/24", "172.26.95.99", &view, restored);
            assert_eq!(event["restored"], restored);
            assert_eq!(event["address"], "172.26.95.99");
            assert_eq!(event["prefix"], 24);
            assert_eq!(event["adapter_mac"], "40:cd:3a:00:00:01");
            assert_eq!(event["desired"], "present");
            assert_eq!(event["applied"], true);
        }
    }

    fn saved_binding(address: &str) -> crate::config::AdoptedMeta {
        crate::config::AdoptedMeta {
            adapter_mac: Some("40:cd:3a:00:00:01".into()),
            address: Some(address.into()),
            prefix: Some(24),
            ..Default::default()
        }
    }

    fn saved_adapter(ips: &[&str]) -> InterfaceInfo {
        let mut iface = adapter("Ethernet", ips);
        iface.mac = "40:cd:3a:00:00:01".into();
        iface
    }

    #[tokio::test]
    async fn adapter_selection_changes_preserve_completed_removals_without_hiding_pending_rows() {
        use crate::config::BindingDesired::Removed;
        use interface::address_test_io::FakeAddressIo;
        for previously_selected in [false, true] {
            let io = FakeAddressIo::new(&["192.168.2.100"]);
            let manager = NetworkManager::with_address_io(io.clone());
            let mut completed = saved_binding("172.26.95.99");
            completed.desired = Removed;
            let mut pending = saved_binding("198.51.100.20");
            pending.desired = Removed;
            pending.last_error = Some("Removal awaiting Windows confirmation".into());
            let mut still_applied = saved_binding("203.0.113.20");
            still_applied.desired = Removed;
            still_applied.applied = true;
            let mut present = saved_binding("192.0.2.20");
            present.applied = true;
            let rows: HashMap<_, _> = [
                ("172.26.95.0/24".into(), completed.clone()),
                ("198.51.100.0/24".into(), pending),
                ("203.0.113.0/24".into(), still_applied),
                ("192.0.2.0/24".into(), present),
            ]
            .into_iter()
            .collect();
            let config =
                crate::config::AppConfig::temporary_test_config(crate::config::AppSettings {
                    selected_adapter_mac: completed.adapter_mac.clone(),
                    adopted_meta: rows.clone(),
                    ..Default::default()
                });
            let before =
                serde_json::to_value(crate::config::AppSettingsView::from(&config.get())).unwrap();
            *manager.bindings.adopted_meta.lock().unwrap() = rows;
            manager
                .bindings
                .adopted_ips
                .lock()
                .await
                .insert("192.0.2.0/24".into(), ip("192.0.2.20"));
            if previously_selected {
                *manager.selector.adapter_selection.lock().await = discovery_selection(true);
            }

            let selection = manager
                .resolve_adapter_selection(&config, &[])
                .await
                .unwrap();
            assert!(selection.adapter.is_none());
            assert!(selection.interface_index.is_none());
            let snapshot = manager.adoption_snapshot().await;
            assert!(snapshot.adopted_subnets.is_empty());
            let removed = &snapshot.meta["172.26.95.0/24"];
            assert_eq!(removed.desired, Removed);
            assert!(!removed.applied);
            assert_eq!(
                removed.last_error, None,
                "adapter loss must not reopen a completed deletion"
            );
            assert_eq!(
                manager.bindings.adopted_meta.lock().unwrap()["172.26.95.0/24"],
                completed
            );
            for subnet in ["198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24"] {
                assert!(
                    snapshot.meta[subnet].last_error.is_some(),
                    "retain unresolved {subnet}"
                );
            }
            assert_eq!(
                serde_json::to_value(crate::config::AppSettingsView::from(&config.get())).unwrap(),
                before
            );
            assert!(io.writes.lock().unwrap().is_empty());
            assert!(io.saves.lock().unwrap().is_empty());
            assert_eq!(io.providers.load(Ordering::Relaxed), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn host_view_reads_fresh_link_and_ips_without_lifecycle_locks_or_writes() {
        use interface::address_test_io::FakeAddressIo;
        let io = FakeAddressIo::new(&["192.168.2.100", "192.168.1.100"]);
        let manager = NetworkManager::with_address_io(io.clone());
        let config = crate::config::AppConfig::temporary_test_config(crate::config::AppSettings {
            selected_adapter_mac: Some("40:cd:3a:00:00:01".into()),
            ..Default::default()
        });
        let before =
            serde_json::to_value(crate::config::AppSettingsView::from(&config.get())).unwrap();
        let _discovery = manager.discovery_op.lock().await;
        let _address = manager.bindings.address_work.lock().await;
        for up in [false, true] {
            io.table.lock().unwrap()[0].is_up = up;
            let view = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                manager.adapter_selection_view(&config),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(view.interface_index, Some(7));
            assert_eq!(view.selected_mac, config.get().selected_adapter_mac);
            let iface = view.adapter.unwrap();
            assert_eq!(iface.is_up, up);
            assert_eq!(iface.ips.len(), 2);
            assert_eq!(iface.ips[0].address, "192.168.2.100");
        }
        assert_eq!(io.providers.load(Ordering::Relaxed), 0);
        assert!(io.writes.lock().unwrap().is_empty());
        assert!(io.saves.lock().unwrap().is_empty());
        assert_eq!(
            serde_json::to_value(crate::config::AppSettingsView::from(&config.get())).unwrap(),
            before
        );
        assert!(manager.adapter_selection_state().await.adapter.is_none());
        assert!(!manager.discovery.discovery_active.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn host_view_native_absence_or_unknown_state_never_substitutes_another_adapter() {
        use interface::address_test_io::FakeAddressIo;
        for case in 0..4 {
            let io = FakeAddressIo::new(&["192.168.2.100"]);
            let config =
                crate::config::AppConfig::temporary_test_config(crate::config::AppSettings {
                    selected_adapter_mac: Some(
                        if case == 0 {
                            "aa:bb:cc:dd:ee:ff"
                        } else {
                            "40:cd:3a:00:00:01"
                        }
                        .into(),
                    ),
                    ..Default::default()
                });
            match case {
                1 => io.table.lock().unwrap().clear(),
                2 => io.fail_read.store(true, Ordering::Relaxed),
                3 => io.table.lock().unwrap()[0].index = 8,
                _ => {}
            }
            let manager = NetworkManager::with_address_io(io.clone());
            let result = manager.adapter_selection_view(&config).await;
            if case < 2 {
                let view = result.unwrap();
                assert!(view.adapter.is_none() && view.interface_index.is_none());
                assert_eq!(view.selected_mac, config.get().selected_adapter_mac);
            } else {
                assert!(result.is_err());
            }
            assert!(io.writes.lock().unwrap().is_empty());
            assert!(io.saves.lock().unwrap().is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn host_view_rejects_a_selection_changed_during_its_native_read() {
        use interface::address_test_io::FakeAddressIo;
        let io = FakeAddressIo::new(&["192.168.2.100"]);
        *io.delay.lock().unwrap() = std::time::Duration::from_millis(100);
        let manager = Arc::new(NetworkManager::with_address_io(io.clone()));
        let config = Arc::new(crate::config::AppConfig::temporary_test_config(
            crate::config::AppSettings {
                selected_adapter_mac: Some("40:cd:3a:00:00:01".into()),
                ..Default::default()
            },
        ));
        let (m, c) = (manager.clone(), config.clone());
        let read = tokio::spawn(async move { m.adapter_selection_view(&c).await });
        tokio::task::yield_now().await;
        config.settings.lock().unwrap().selected_adapter_mac = Some("aa:bb:cc:dd:ee:ff".into());
        assert!(read.await.unwrap().is_err());
        assert!(io.writes.lock().unwrap().is_empty());
    }

    #[derive(Default)]
    struct BindingOps {
        writes: StdMutex<Vec<(bool, Ipv4Addr)>>,
        fail_remove: bool,
    }

    impl auto_adopt::AdoptOps for BindingOps {
        async fn add(&self, _: &str, ip: Ipv4Addr, _: &str) -> Result<(), AppError> {
            self.writes.lock().unwrap().push((true, ip));
            Ok(())
        }
        async fn remove(&self, _: &str, ip: Ipv4Addr) -> Result<(), AppError> {
            self.writes.lock().unwrap().push((false, ip));
            if self.fail_remove {
                Err(AppError::Network("injected OS rejection".into()))
            } else {
                Ok(())
            }
        }
        async fn probe(&self, _: Ipv4Addr, _: Option<Ipv4Addr>) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn sp1_native_identity_change_after_write_never_claims_success() {
        use interface::address_test_io::FakeAddressIo;
        let io = FakeAddressIo::new(&["192.0.2.20"]);
        io.replace_after_write.store(true, Ordering::Relaxed);
        let manager = NetworkManager::with_address_io(io.clone());
        let mut settings = crate::config::AppSettings {
            selected_adapter_mac: Some("40:cd:3a:00:00:01".into()),
            ..Default::default()
        };
        let mut row = saved_binding("192.0.2.20");
        row.applied = true;
        settings
            .adopted_subnets
            .insert("192.0.2.0/24".into(), "192.0.2.20".into());
        settings.adopted_meta.insert("192.0.2.0/24".into(), row);
        let config = crate::config::AppConfig::temporary_test_config(settings);
        assert!(manager
            .remove_adopted_subnet(&config, "192.0.2.0/24", None)
            .await
            .is_err());
        assert_eq!(io.writes.lock().unwrap().len(), 1);
        assert!(config.get().adopted_meta["192.0.2.0/24"]
            .last_error
            .is_some());
    }

    #[tokio::test]
    async fn sp1_manual_operation_unknown_identity_or_dhcp_never_writes() {
        use interface::address_test_io::FakeAddressIo;
        for case in 0..9 {
            let io = FakeAddressIo::new(&["192.0.2.10"]);
            let mut settings = crate::config::AppSettings {
                selected_adapter_mac: Some("40:cd:3a:00:00:01".into()),
                ..Default::default()
            };
            {
                let mut table = io.table.lock().unwrap();
                match case {
                    0 => table.clear(),
                    1 => {
                        let duplicate = table[0].clone();
                        table.push(duplicate);
                    }
                    2 => table[0].index = 0,
                    3 => table[0].guid = "replacement-guid".into(),
                    4 => table[0].alias = "renamed".into(),
                    5 => table[0].mac = "40:cd:3a:00:00:02".into(),
                    6 => table[0].dhcp = true,
                    7 => settings.network_mode = crate::config::NetworkMode::Dhcp,
                    _ => io.fail_read.store(true, Ordering::Relaxed),
                }
            }
            let manager = NetworkManager::with_address_io(io.clone());
            let config = crate::config::AppConfig::temporary_test_config(settings);
            assert!(manager
                .add_manual_address(&config, "Ethernet", "192.0.2.20", "255.255.255.0")
                .await
                .is_err());
            assert!(io.writes.lock().unwrap().is_empty());
            assert!(io.saves.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn sp1_real_delete_preserves_native_failure_and_command_error_evidence() {
        use interface::address_test_io::{Effect, FakeAddressIo};
        for (effect, native_failure) in [
            (Effect::Unchanged, false),
            (Effect::ErrorAfter, false),
            (Effect::TimeoutAfter, false),
            (Effect::Apply, true),
        ] {
            let io = FakeAddressIo::new(&["192.0.2.20"]);
            *io.effect.lock().unwrap() = effect;
            io.fail_read.store(native_failure, Ordering::Relaxed);
            let manager = NetworkManager::with_address_io(io.clone());
            let mut settings = crate::config::AppSettings {
                selected_adapter_mac: Some("40:cd:3a:00:00:01".into()),
                ..Default::default()
            };
            let mut row = saved_binding("192.0.2.20");
            row.applied = true;
            settings
                .adopted_subnets
                .insert("192.0.2.0/24".into(), "192.0.2.20".into());
            settings.adopted_meta.insert("192.0.2.0/24".into(), row);
            let config = crate::config::AppConfig::temporary_test_config(settings);
            assert!(manager
                .remove_adopted_subnet(&config, "192.0.2.0/24", None)
                .await
                .is_err());
            assert_eq!(
                io.writes.lock().unwrap().len(),
                usize::from(!native_failure)
            );
            let row = &config.get().adopted_meta["192.0.2.0/24"];
            assert_eq!(row.desired, crate::config::BindingDesired::Removed);
            assert!(row.last_error.is_some());
            if native_failure {
                assert!(row.applied);
            }
        }
    }

    #[tokio::test]
    async fn sp02_real_delete_uses_native_proof_despite_both_callbacks_and_provider_timeout() {
        use interface::address_test_io::FakeAddressIo;
        for legacy in [true, false] {
            let io = FakeAddressIo::new(&["192.0.2.10", "192.0.2.20"]);
            io.legacy_callbacks.store(legacy, Ordering::Relaxed);
            io.external_address.store(true, Ordering::Relaxed);
            let manager = NetworkManager::with_address_io(io.clone());
            let mut settings = crate::config::AppSettings {
                selected_adapter_mac: Some("40:cd:3a:00:00:01".into()),
                ..Default::default()
            };
            let mut row = saved_binding("192.0.2.20");
            row.applied = true;
            settings
                .adopted_subnets
                .insert("192.0.2.0/24".into(), "192.0.2.20".into());
            settings.adopted_meta.insert("192.0.2.0/24".into(), row);
            let config = crate::config::AppConfig::temporary_test_config(settings);
            let result = manager
                .remove_adopted_subnet(&config, "192.0.2.0/24", Some("Ethernet"))
                .await;
            assert_eq!(
                result.is_err(),
                legacy,
                "legacy invalidation reproduces the false pending result"
            );
            assert_eq!(
                *io.writes.lock().unwrap(),
                vec![(false, "192.0.2.20".into())]
            );
            assert_eq!(
                io.providers.load(Ordering::Relaxed),
                0,
                "expired TTL must not force a provider read"
            );
            let table = io.table.lock().unwrap();
            assert!(!table[0].ips.iter().any(|i| i.address == "192.0.2.20"));
            assert!(table[0].ips.iter().any(|i| i.address == "192.0.2.77"));
            let row = &config.get().adopted_meta["192.0.2.0/24"];
            assert_eq!(row.desired, crate::config::BindingDesired::Removed);
            assert_eq!(row.last_error.is_some(), legacy);
            if !legacy {
                assert!(!row.applied);
            }
        }
    }

    #[tokio::test]
    async fn newly_requested_removal_waits_for_windows_confirmation() {
        let ops = BindingOps::default();
        for was_applied in [false, true] {
            let mut row = saved_binding("172.26.95.99");
            row.applied = was_applied;
            let row = pending_binding_removal(row);
            let action = binding_action(
                "172.26.95.0/24",
                &row,
                None,
                crate::config::NetworkMode::StaticAuto,
                &Ok(false),
                &[],
            );
            let row = apply_binding(&ops, row, action, None, || async {
                panic!("unavailable Windows state cannot confirm deletion")
            })
            .await;
            assert_eq!(row.applied, was_applied);
            assert!(
                row.last_error.is_some(),
                "new removal stays pending even if applied was false"
            );
            assert_eq!(row.desired, crate::config::BindingDesired::Removed);

            let iface = saved_adapter(&["192.168.1.100"]);
            let action = binding_action(
                "172.26.95.0/24",
                &row,
                Some(&iface),
                crate::config::NetworkMode::StaticAuto,
                &Ok(false),
                &[],
            );
            assert_eq!(action, BindingAction::Observed(false));
            let row = apply_binding(&ops, row, action, Some(&iface), || async {
                panic!("an observed absence needs no write")
            })
            .await;
            assert!(!row.applied && row.last_error.is_none());
            assert_eq!(row.desired, crate::config::BindingDesired::Removed);
        }
        assert!(ops.writes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn completed_removal_stays_complete_through_unavailable_observations() {
        let ops = BindingOps::default();
        let mut down = saved_adapter(&[]);
        down.is_up = false;
        let mut row = saved_binding("172.26.95.99");
        row.desired = crate::config::BindingDesired::Removed;
        row.applied = false;
        for mode in [
            crate::config::NetworkMode::StaticAuto,
            crate::config::NetworkMode::StaticManual,
            crate::config::NetworkMode::Dhcp,
        ] {
            for iface in [None, Some(&down)] {
                let action = binding_action(
                    "172.26.95.0/24",
                    &row,
                    iface,
                    mode,
                    &Err("adapter disconnected".into()),
                    &[],
                );
                row = apply_binding(&ops, row, action, iface, || async {
                    panic!("unavailable adapter must not mutate addresses")
                })
                .await;
                assert!(
                    !row.applied && row.last_error.is_none(),
                    "a completed removal must not become pending on disconnect"
                );
                row = apply_binding(
                    &ops,
                    row,
                    BindingAction::Unavailable("provider query failed".into()),
                    iface,
                    || async { panic!("failed provider must not mutate addresses") },
                )
                .await;
                assert!(!row.applied && row.last_error.is_none());
                assert_eq!(row.desired, crate::config::BindingDesired::Removed);
                assert_eq!(row.address.as_deref(), Some("172.26.95.99"));
            }
        }
        assert!(ops.writes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unavailable_adapter_does_not_complete_a_pending_removal() {
        let ops = BindingOps::default();
        for (applied, error) in [(true, None), (false, Some("remove failed".into()))] {
            let mut row = saved_binding("172.26.95.99");
            row.desired = crate::config::BindingDesired::Removed;
            row.applied = applied;
            row.last_error = error;
            let action = binding_action(
                "172.26.95.0/24",
                &row,
                None,
                crate::config::NetworkMode::StaticAuto,
                &Ok(false),
                &[],
            );
            let row = apply_binding(&ops, row, action, None, || async {
                panic!("unavailable adapter cannot prove successful removal")
            })
            .await;
            assert_eq!(row.applied, applied, "preserve the last actual observation");
            assert!(
                row.last_error.is_some(),
                "real pending removal stays visible"
            );
            assert_eq!(row.desired, crate::config::BindingDesired::Removed);
        }
        assert!(ops.writes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn completed_removal_is_rechecked_if_the_address_reappears() {
        let ops = BindingOps::default();
        let iface = saved_adapter(&["172.26.95.99", "192.168.1.100"]);
        let mut row = saved_binding("172.26.95.99");
        row.desired = crate::config::BindingDesired::Removed;
        row.applied = false;
        let action = binding_action(
            "172.26.95.0/24",
            &row,
            Some(&iface),
            crate::config::NetworkMode::StaticAuto,
            &Ok(false),
            &[],
        );
        assert_eq!(action, BindingAction::Remove(ip("172.26.95.99")));
        let row = apply_binding(&ops, row, action, Some(&iface), || async {
            Ok(saved_adapter(&["192.168.1.100"]).ips)
        })
        .await;
        assert!(!row.applied && row.last_error.is_none());
        assert_eq!(row.desired, crate::config::BindingDesired::Removed);
        assert_eq!(
            *ops.writes.lock().unwrap(),
            vec![(false, ip("172.26.95.99"))]
        );
    }

    #[tokio::test]
    async fn dhcp_restore_skips_add_and_static_reapplies_without_restart() {
        let ops = BindingOps::default();
        let mut row = saved_binding("172.31.169.253");
        row.applied = true; // stale persisted flag
        let iface = saved_adapter(&["192.168.1.20"]);
        let action = binding_action(
            "172.31.169.0/24",
            &row,
            Some(&iface),
            crate::config::NetworkMode::Dhcp,
            &Ok(true),
            &[],
        );
        row = apply_binding(&ops, row, action, Some(&iface), || async {
            panic!("hold must not mutate or re-observe")
        })
        .await;
        assert!(!row.applied);
        assert_eq!(row.last_error.as_deref(), Some("adapter is DHCP"));
        assert!(ops.writes.lock().unwrap().is_empty());
        let action = binding_action(
            "172.31.169.0/24",
            &row,
            Some(&iface),
            crate::config::NetworkMode::StaticManual,
            &Ok(false),
            &[],
        );
        row = apply_binding(&ops, row, action, Some(&iface), || async {
            Ok(vec![ip_info("172.31.169.253", 24)])
        })
        .await;
        assert!(row.applied && row.last_error.is_none());
        assert_eq!(
            *ops.writes.lock().unwrap(),
            vec![(true, ip("172.31.169.253"))]
        );
    }

    #[tokio::test]
    async fn dhcp_query_failure_and_invalid_entry_never_write() {
        let ops = BindingOps::default();
        let iface = saved_adapter(&["192.168.1.20"]);
        for (subnet, dhcp) in [
            ("172.31.169.0/24", Err("query timed out".into())),
            ("malformed", Ok(false)),
        ] {
            let row = saved_binding("172.31.169.253");
            let action = binding_action(
                subnet,
                &row,
                Some(&iface),
                crate::config::NetworkMode::StaticAuto,
                &dhcp,
                &[],
            );
            let row = apply_binding(&ops, row, action, Some(&iface), || async {
                panic!("invalid/query-failed entries must not write")
            })
            .await;
            assert!(!row.applied && row.last_error.is_some());
        }
        assert!(ops.writes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_unbind_retains_removed_intent_applied_address_and_error() {
        let ops = BindingOps {
            fail_remove: true,
            ..Default::default()
        };
        let iface = saved_adapter(&["172.31.169.253", "192.168.1.20"]);
        let mut row = saved_binding("172.31.169.253");
        row.desired = crate::config::BindingDesired::Removed;
        let action = binding_action(
            "172.31.169.0/24",
            &row,
            Some(&iface),
            crate::config::NetworkMode::StaticAuto,
            &Ok(false),
            &[],
        );
        row = apply_binding(&ops, row, action, Some(&iface), || async {
            Ok(iface.ips.clone())
        })
        .await;
        assert!(
            row.applied
                && row
                    .last_error
                    .as_ref()
                    .unwrap()
                    .contains("injected OS rejection")
        );
        assert_eq!(row.desired, crate::config::BindingDesired::Removed);
        assert_eq!(
            *ops.writes.lock().unwrap(),
            vec![(false, ip("172.31.169.253"))]
        );
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn failed_unbind_and_native_observation_failure_retain_applied_until_observed_absent() {
        let ops = BindingOps {
            fail_remove: true,
            ..Default::default()
        };
        let iface = saved_adapter(&["172.31.169.253", "192.168.1.20"]);
        let mut row = saved_binding("172.31.169.253");
        row.desired = crate::config::BindingDesired::Removed;
        row = apply_binding(
            &ops,
            row,
            BindingAction::Remove(ip("172.31.169.253")),
            Some(&iface),
            || async {
                interface::failed_native_snapshot(vec![iface.clone()])
                    .map(|mut rows| rows.remove(0).ips)
            },
        )
        .await;
        assert!(
            row.applied,
            "an unavailable observation cannot prove removal"
        );
        assert!(row
            .last_error
            .as_deref()
            .unwrap()
            .contains("injected OS rejection"));
        assert_eq!(row.desired, crate::config::BindingDesired::Removed);
        assert_eq!(
            *ops.writes.lock().unwrap(),
            vec![(false, ip("172.31.169.253"))]
        );

        // Repeated failure on the next reconciliation must not erase that fact.
        row = apply_binding(
            &ops,
            row,
            BindingAction::Unavailable("native observation unavailable".into()),
            None,
            || async { panic!("unavailable observations must not write") },
        )
        .await;
        assert!(row.applied && row.last_error.is_some());
        row = apply_binding(
            &ops,
            row,
            BindingAction::Remove(ip("172.31.169.253")),
            Some(&iface),
            || async { Ok(vec![]) },
        )
        .await;
        assert!(!row.applied, "a valid empty observation proves absence");
    }

    #[tokio::test]
    async fn legacy_ownership_is_recorded_only_after_observed_success() {
        let ops = BindingOps::default();
        let iface = saved_adapter(&["192.168.1.20"]);
        let mut row = saved_binding("172.31.169.253");
        row.adapter_mac = None;
        let row = apply_binding(
            &ops,
            row,
            BindingAction::Add(ip("172.31.169.253"), 24),
            Some(&iface),
            || async { Ok(vec![ip_info("172.31.169.253", 24)]) },
        )
        .await;
        assert_eq!(row.adapter_mac, adapter_mac(&iface.mac));
        assert!(row.applied && row.last_error.is_none());
    }

    #[tokio::test]
    async fn transition_fences_inflight_adoption_before_commit() {
        let manager = NetworkManager::new();
        let old = manager.bindings.address_fence();
        let pending = manager.bindings.pending_ips.clone();
        let ops = BindingOps::default();
        let worker = manager.bindings.address_work.lock().await;
        auto_adopt::bind_scratch(&ops, &pending, "Ethernet", ip("172.31.169.254"), 1)
            .await
            .unwrap();
        let pause = manager.bindings.pause_addresses();
        assert!(
            commit_pending_address(&pending, "Ethernet", ip("172.31.169.254"), 1, || {
                if old.is_stale() {
                    Err(AppError::Network("work was cancelled".into()))
                } else {
                    panic!("an invalidated adoption must not commit")
                }
            })
            .await
            .is_err()
        );
        assert_eq!(pending.lock().await.len(), 1);
        auto_adopt::reconcile_pending(&ops, &pending, Some(1)).await;
        drop(worker);
        let _transition = manager.bindings.address_work.lock().await;
        assert!(pending.lock().await.is_empty());
        assert_eq!(
            *ops.writes.lock().unwrap(),
            vec![(true, ip("172.31.169.254")), (false, ip("172.31.169.254"))]
        );
        drop(pause);
        assert!(old.is_stale());
        assert!(!manager.bindings.address_fence().is_stale());
    }

    #[tokio::test]
    async fn committed_handover_and_exit_cleanup_preserve_saved_apipa_and_plain_ips() {
        let manager = NetworkManager::new();
        let ops = BindingOps::default();
        let committed = ip("169.254.20.99");
        let plain = ip("172.31.169.253");
        manager.bindings.adopted_ips.lock().await.extend([
            ("169.254.20.0/24".into(), committed),
            ("172.31.169.0/24".into(), plain),
        ]);
        auto_adopt::bind_scratch(
            &ops,
            &manager.bindings.pending_ips,
            "Ethernet",
            committed,
            1,
        )
        .await
        .unwrap();
        commit_pending_address(
            &manager.bindings.pending_ips,
            "Ethernet",
            committed,
            1,
            || Ok(()),
        )
        .await
        .unwrap();
        auto_adopt::bind_scratch(
            &ops,
            &manager.bindings.pending_ips,
            "Ethernet",
            ip("172.31.170.254"),
            2,
        )
        .await
        .unwrap();
        manager.bindings.cleanup_pending_with(&ops).await;
        assert!(manager.bindings.pending_ips.lock().await.is_empty());
        assert_eq!(manager.bindings.adopted_ips.lock().await.len(), 2);
        let removed: Vec<_> = ops
            .writes
            .lock()
            .unwrap()
            .iter()
            .filter(|(add, _)| !add)
            .map(|(_, ip)| *ip)
            .collect();
        assert_eq!(removed, vec![ip("172.31.170.254")]);
    }

    #[test]
    fn link_return_reconciles_even_when_windows_index_does_not_change() {
        let mut down = AdapterSelection {
            selected_mac: Some("40:cd:3a:00:00:01".into()),
            interface_index: Some(12),
            adapter: Some(saved_adapter(&[])),
            ..Default::default()
        };
        down.adapter.as_mut().unwrap().is_up = false;
        let mut up = down.clone();
        up.adapter.as_mut().unwrap().is_up = true;
        assert!(binding_link_changed(&down, &up));
        assert!(binding_link_changed(&up, &down));
        assert!(!binding_link_changed(&up, &up));
        up.interface_index = Some(20);
        assert!(!binding_link_changed(&down, &up)); // identity-return path is the watcher
    }

    #[test]
    fn failed_mode_save_keeps_binding_status_truthful_when_os_and_saved_mode_differ() {
        let row = saved_binding("172.31.169.253");
        let iface = saved_adapter(&["192.168.1.20"]);
        assert_eq!(
            binding_action(
                "172.31.169.0/24",
                &row,
                Some(&iface),
                crate::config::NetworkMode::StaticAuto,
                &Ok(true),
                &[]
            ),
            BindingAction::Hold("adapter is DHCP".into(), false)
        );
        assert_eq!(
            binding_action(
                "172.31.169.0/24",
                &row,
                Some(&iface),
                crate::config::NetworkMode::Dhcp,
                &Ok(false),
                &[]
            ),
            BindingAction::Hold("saved mode is DHCP; adapter is static".into(), false)
        );
    }

    fn fence(generation: u64, current: u64, active: bool) -> SweepFence {
        SweepFence::new(
            generation,
            Arc::new(AtomicU64::new(current)),
            Arc::new(AtomicBool::new(active)),
        )
    }

    // ── capture-listener retention ────────────────────────────────

    // ── adoption-removal routing ──────────────────────────────────

    #[test]
    fn removed_binding_is_unbound_only_on_its_adapter() {
        let mut row = saved_binding("172.31.169.253");
        row.desired = crate::config::BindingDesired::Removed;
        let iface = saved_adapter(&["172.31.169.253", "192.168.1.20"]);
        assert_eq!(
            binding_action(
                "172.31.169.0/24",
                &row,
                Some(&iface),
                crate::config::NetworkMode::StaticAuto,
                &Ok(false),
                &[]
            ),
            BindingAction::Remove(ip("172.31.169.253"))
        );
        let absent = saved_adapter(&["192.168.1.20"]);
        assert_eq!(
            binding_action(
                "172.31.169.0/24",
                &row,
                Some(&absent),
                crate::config::NetworkMode::StaticAuto,
                &Ok(false),
                &[]
            ),
            BindingAction::Observed(false)
        );
    }

    // ── probe origin → adoption evidence ──────────────────────────

    fn adapter(name: &str, ips: &[&str]) -> interface::InterfaceInfo {
        interface::InterfaceInfo {
            name: name.into(),
            display_name: name.into(),
            description: String::new(),
            ips: ips
                .iter()
                .map(|addr| interface::IpInfo {
                    address: (*addr).into(),
                    prefix: 24,
                    subnet: String::new(),
                })
                .collect(),
            mac: String::new(),
            is_up: true,
            is_ethernet: true,
            is_wifi: false,
            is_vpn: false,
            is_virtual: false,
        }
    }

    #[test]
    fn strip_pending_ips_hides_scratch_addresses_only() {
        let pending: HashSet<String> = ["172.31.169.254".to_string()].into_iter().collect();

        let list = vec![adapter("Ethernet", &["192.168.1.101", "172.31.169.254"])];
        let out = strip_pending_ips(list, &pending);
        let ips: Vec<&str> = out[0].ips.iter().map(|i| i.address.as_str()).collect();
        assert_eq!(ips, vec!["192.168.1.101"]);

        // Empty pending set: untouched.
        let list = vec![adapter("Ethernet", &["192.168.1.101"])];
        assert_eq!(strip_pending_ips(list, &HashSet::new())[0].ips.len(), 1);

        // An adapter whose only address is a scratch stays listed — it
        // reads as disconnected, it is not dropped from the list.
        let list = vec![adapter("Ethernet 2", &["172.31.169.254"])];
        let out = strip_pending_ips(list, &pending);
        assert_eq!(out.len(), 1);
        assert!(out[0].ips.is_empty());
    }

    #[test]
    fn startup_sweeps_native_once_refresh_includes_three_retained_subnets() {
        let ips = vec![
            ip_info("192.168.1.2", 24),
            ip_info("192.168.1.3", 24),
            ip_info("10.1.1.253", 24),
            ip_info("10.2.2.253", 24),
            ip_info("10.3.3.253", 24),
            ip_info("169.254.1.2", 16),
        ];
        let retained = [ip("10.1.1.253"), ip("10.2.2.253"), ip("10.3.3.253")]
            .into_iter()
            .collect();
        assert_eq!(
            select_sweep_ips(&ips, &retained, false),
            vec!["192.168.1.2"]
        );
        assert_eq!(
            select_sweep_ips(&ips, &retained, true),
            vec!["192.168.1.2", "10.1.1.253", "10.2.2.253", "10.3.3.253"]
        );
        assert!(select_sweep_ips(&ips[2..], &retained, false).is_empty());
        assert!(select_sweep_ips(&[], &retained, true).is_empty());
    }

    // ── wired source selection for MAC verification ───────────────

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn ip_info(address: &str, prefix: u8) -> interface::IpInfo {
        let net = ipnetwork::Ipv4Network::new(address.parse().unwrap(), prefix).unwrap();
        interface::IpInfo {
            address: address.to_string(),
            prefix,
            subnet: format!("{}/{}", net.network(), net.prefix()),
        }
    }

    fn adopted(entries: &[(&str, &str)]) -> HashMap<String, Ipv4Addr> {
        entries
            .iter()
            .map(|(subnet, addr)| (subnet.to_string(), ip(addr)))
            .collect()
    }

    #[test]
    fn wired_source_prefers_adopted_ip_for_its_subnet() {
        let adopted = adopted(&[("172.31.169.0/24", "172.31.169.102")]);
        let native = [ip_info("192.168.1.101", 24)];
        assert_eq!(
            select_wired_source(ip("172.31.169.50"), &adopted, &native),
            Some(ip("172.31.169.102"))
        );
    }

    #[test]
    fn wired_source_adopted_beats_native_on_same_subnet() {
        // Both the adopted binding and a native IP contain the target —
        // the adopted binding wins (it was created to reach devices
        // there).
        let adopted = adopted(&[("192.168.1.0/24", "192.168.1.55")]);
        let native = [ip_info("192.168.1.101", 24)];
        assert_eq!(
            select_wired_source(ip("192.168.1.202"), &adopted, &native),
            Some(ip("192.168.1.55"))
        );
    }

    #[test]
    fn wired_source_uses_native_iface_ip() {
        let native = [ip_info("192.168.1.101", 24)];
        assert_eq!(
            select_wired_source(ip("192.168.1.202"), &HashMap::new(), &native),
            Some(ip("192.168.1.101"))
        );
    }

    #[test]
    fn wired_source_none_when_no_subnet_matches() {
        // A foreign-subnet target with no wired identity: verification
        // must fail rather than fall back to an unbound probe.
        let adopted = adopted(&[("172.31.169.0/24", "172.31.169.102")]);
        let native = [ip_info("192.168.1.101", 24)];
        assert_eq!(select_wired_source(ip("10.0.0.7"), &adopted, &native), None);
    }

    #[test]
    fn wired_source_skips_malformed_adopted_keys() {
        let adopted = adopted(&[("not-a-subnet", "172.31.169.102")]);
        let native = [ip_info("192.168.1.101", 24)];
        assert_eq!(
            select_wired_source(ip("192.168.1.202"), &adopted, &native),
            Some(ip("192.168.1.101"))
        );
    }

    #[test]
    fn wired_source_respects_non_24_prefixes() {
        let native = [ip_info("10.10.0.5", 16)];
        assert_eq!(
            select_wired_source(ip("10.10.200.9"), &HashMap::new(), &native),
            Some(ip("10.10.0.5"))
        );
        assert_eq!(
            select_wired_source(ip("10.11.0.9"), &HashMap::new(), &native),
            None
        );
    }

    #[test]
    fn subnet_key_matches_adoption_key_derivation() {
        assert_eq!(
            subnet_key_for(Ipv4Addr::new(169, 254, 168, 7)),
            "169.254.168.0/24"
        );
        assert_eq!(subnet_key_for(Ipv4Addr::new(10, 0, 0, 255)), "10.0.0.0/24");
    }

    #[test]
    fn positive_liveness_refreshes_only_adopted_subnets() {
        let mut adopted = HashMap::new();
        adopted.insert(
            "169.254.168.0/24".to_string(),
            Ipv4Addr::new(169, 254, 168, 102),
        );
        let mut liveness = HashMap::new();
        let mut meta = HashMap::new();
        let t0 = std::time::Instant::now();

        // Evidence from a device on the adopted subnet lands: session
        // clock refreshed, display metadata stamped.
        assert!(record_positive_liveness(
            Ipv4Addr::new(169, 254, 168, 7),
            &adopted,
            &mut liveness,
            &mut meta,
            t0,
            "2026-07-16T12:00:00+00:00",
        ));
        assert_eq!(liveness.get("169.254.168.0/24"), Some(&t0));
        assert_eq!(
            meta["169.254.168.0/24"].last_device_seen.as_deref(),
            Some("2026-07-16T12:00:00+00:00")
        );

        // Evidence from a non-adopted subnet touches nothing.
        assert!(!record_positive_liveness(
            Ipv4Addr::new(192, 168, 1, 50),
            &adopted,
            &mut liveness,
            &mut meta,
            t0,
            "2026-07-16T12:00:01+00:00",
        ));
        assert_eq!(liveness.len(), 1);
        assert_eq!(meta.len(), 1);

        // A later sighting advances both stamps.
        let t1 = t0 + std::time::Duration::from_secs(60);
        record_positive_liveness(
            Ipv4Addr::new(169, 254, 168, 9),
            &adopted,
            &mut liveness,
            &mut meta,
            t1,
            "2026-07-16T12:01:00+00:00",
        );
        assert_eq!(liveness.get("169.254.168.0/24"), Some(&t1));
        assert_eq!(
            meta["169.254.168.0/24"].last_device_seen.as_deref(),
            Some("2026-07-16T12:01:00+00:00")
        );
    }

    #[test]
    fn meta_flush_cadence_coalesces_writes() {
        let t0 = std::time::Instant::now();
        let mut state = MetaFlush {
            dirty: false,
            last_flush: t0,
        };
        // Stamps inside the interval mark dirty but never flush.
        assert!(!meta_dirty_flush_due(&mut state, t0));
        assert!(!meta_dirty_flush_due(
            &mut state,
            t0 + std::time::Duration::from_secs(299)
        ));
        assert!(state.dirty);
        // The first stamp past the interval flushes and resets both the
        // dirt and the cadence.
        assert!(meta_dirty_flush_due(
            &mut state,
            t0 + std::time::Duration::from_secs(300)
        ));
        assert!(!state.dirty);
        // …so the next stamp starts a fresh interval.
        assert!(!meta_dirty_flush_due(
            &mut state,
            t0 + std::time::Duration::from_secs(301)
        ));
        assert!(state.dirty);
    }

    #[test]
    fn badge_age_prefers_last_seen_and_tolerates_bad_stamps() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-16T12:00:00+00:00")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let seen = crate::config::AdoptedMeta {
            adopted_at: Some("2026-07-10T12:00:00+00:00".into()),
            last_device_seen: Some("2026-07-16T11:00:00+00:00".into()),
            ..Default::default()
        };
        assert_eq!(
            badge_age(Some(&seen), now),
            Some(std::time::Duration::from_secs(3600))
        );

        // Never seen: the adoption time itself anchors the badge.
        let never = crate::config::AdoptedMeta {
            adopted_at: Some("2026-07-16T10:00:00+00:00".into()),
            last_device_seen: None,
            ..Default::default()
        };
        assert_eq!(
            badge_age(Some(&never), now),
            Some(std::time::Duration::from_secs(7200))
        );

        // Nothing recorded, unparseable, or future stamps: no age —
        // skew and corruption may only mislabel toward "not stale".
        assert_eq!(badge_age(None, now), None);
        let garbage = crate::config::AdoptedMeta {
            adopted_at: Some("yesterday-ish".into()),
            last_device_seen: None,
            ..Default::default()
        };
        assert_eq!(badge_age(Some(&garbage), now), None);
        let future = crate::config::AdoptedMeta {
            adopted_at: Some("2026-07-17T00:00:00+00:00".into()),
            last_device_seen: None,
            ..Default::default()
        };
        assert_eq!(badge_age(Some(&future), now), None);
    }

    #[test]
    fn meta_view_staleness_follows_the_lifecycle_policy() {
        let min = |m: u64| std::time::Duration::from_secs(m * 60);
        let hour = |h: u64| std::time::Duration::from_secs(h * 3600);

        // APIPA, never sighted: stale only past the startup grace.
        let v = adoption_meta_view("169.254.168.0/24", None, None, min(11), None);
        assert!(v.stale);
        let v = adoption_meta_view("169.254.168.0/24", None, None, min(9), None);
        assert!(!v.stale);

        // APIPA sighted recently is healthy however old the session.
        let v = adoption_meta_view("169.254.168.0/24", None, Some(min(1)), hour(10), None);
        assert!(!v.stale);

        // Non-APIPA badges on the 24 h wall age only.
        let v = adoption_meta_view("172.31.169.0/24", None, None, hour(10), Some(hour(25)));
        assert!(v.stale);
        let v = adoption_meta_view("172.31.169.0/24", None, None, hour(10), Some(hour(23)));
        assert!(!v.stale);

        // The stored stamps ride through to the view unchanged.
        let meta = crate::config::AdoptedMeta {
            adopted_at: Some("2026-07-01T00:00:00+00:00".into()),
            last_device_seen: Some("2026-07-15T00:00:00+00:00".into()),
            ..Default::default()
        };
        let v = adoption_meta_view("172.31.169.0/24", Some(&meta), None, min(1), None);
        assert_eq!(v.adopted_at.as_deref(), Some("2026-07-01T00:00:00+00:00"));
        assert_eq!(
            v.last_device_seen.as_deref(),
            Some("2026-07-15T00:00:00+00:00")
        );
    }

    #[test]
    fn dhcp_never_adopts_even_with_only_apipa_or_no_address() {
        for ips in [vec![], vec![Ipv4Addr::new(169, 254, 7, 20)]] {
            assert_eq!(
                dhcp_adoption_pause(true, &ips),
                Some("no usable address; set a static address")
            );
            assert_eq!(dhcp_adoption_pause(false, &ips), None);
        }
        assert_eq!(
            dhcp_adoption_pause(true, &[Ipv4Addr::new(192, 168, 1, 10)]),
            Some("DHCP enabled; automatic address adoption paused")
        );
    }

    #[test]
    fn legacy_manual_apipa_stays_in_history_but_inactive() {
        let registry = DeviceRegistry::new();
        registry.hydrate_manual_nodes(&[
            crate::config::ManualNode {
                expected_mac: None,
                ip: "169.254.20.7".into(),
                alias: "bench PTU".into(),
            },
            crate::config::ManualNode {
                expected_mac: None,
                ip: "192.168.1.204".into(),
                alias: "camera".into(),
            },
        ]);
        assert!(!keep_prohibited_history_inactive(&registry));
        let records = registry.snapshot();
        assert_eq!(records.len(), 2);
        let historical = records.iter().find(|r| r.ip == "169.254.20.7").unwrap();
        assert_eq!(historical.status, DeviceStatus::Offline);
        assert_eq!(historical.alias, "bench PTU");
        assert!(!keep_prohibited_history_inactive(&registry));
    }

    #[test]
    fn neighbor_import_candidates_only_is_active() {
        let manager = NetworkManager::new();
        assert!(manager
            .candidate_ingress(7, Some([0x40, 0xcd, 0x3a, 0, 0, 1]))
            .is_some());
        let rows = arp::parse_neighbors_json(
            r#"[{"IPAddress":"192.168.1.204","LinkLayerAddress":"AA-BB-CC-DD-EE-02","State":"Stale"}]"#,
        );
        assert_eq!(rows.len(), 1);
        let ingress = arp::CandidateIngress {
            store: manager.capture.candidates.clone(),
            interface_index: 7,
            adapter_mac: [0x40, 0xcd, 0x3a, 0, 0, 1],
        };
        let mut devices = HashMap::new();
        let source_fence = fence(1, 1, true);
        let imported = import_neighbors(
            rows.clone(),
            &mut devices,
            &[],
            &HashSet::new(),
            &source_fence,
            Some(&ingress),
        );
        assert!(imported.is_empty());
        assert!(devices.is_empty());
        assert!(manager.registry().snapshot().is_empty());
        assert_eq!(
            manager.capture.candidates.count(std::time::Instant::now()),
            1
        );
        assert_eq!(
            import_neighbors(
                rows,
                &mut devices,
                &[],
                &HashSet::new(),
                &source_fence,
                None
            )
            .len(),
            1
        );
        assert_eq!(devices.len(), 1); // shipping legacy route still works
    }

    #[test]
    fn presence_distinguishes_ethernet_peer_from_local_adapters_at_the_same_ip() {
        let adapter = discovery_selection(true).adapter.unwrap();
        let wifi_mac = "ac:45:ef:38:f9:f5";
        let local = HashSet::from([
            parse_mac_bytes(&adapter.mac).unwrap(),
            parse_mac_bytes(wifi_mac).unwrap(),
        ]);
        let mut job = presence::Job {
            key: Some("40:cd:3a:03:8f:3f".into()),
            ip: "192.168.1.204".parse().unwrap(),
            source: Some("192.168.1.100".parse().unwrap()),
        };
        assert!(!presence_target_is_host(&job, &adapter, &local));
        job.key = Some(wifi_mac.into());
        assert!(presence_target_is_host(&job, &adapter, &local));
        job.key = None;
        assert!(!presence_target_is_host(&job, &adapter, &local));
        job.ip = "192.168.1.100".parse().unwrap();
        assert!(presence_target_is_host(&job, &adapter, &local));
    }

    #[test]
    fn topology_conflicts_retain_history_with_inactive_reasons() {
        let cached = |mac: &str, ip: &str| {
            serde_json::from_value::<crate::config::CachedDevice>(serde_json::json!({
                "mac": mac, "ip": ip, "subnet": "10.0.0.0/24", "last_seen": "2026-10-19T12:00:00Z"
            }))
            .unwrap()
        };
        let registry = DeviceRegistry::new();
        hydrate_retained_history(
            &registry,
            vec![
                cached("AA:01", "10.0.0.2"),
                cached("AA:BB:CC:DD:EE:02", "192.168.1.101"),
            ],
            &["10.0.0.0/24".parse().unwrap()],
            &HashSet::from([parse_mac_bytes("AA:BB:CC:DD:EE:02").unwrap()]),
        );
        let records = registry.snapshot();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records.iter().find(|r| r.mac == "AA:01").unwrap().status,
            DeviceStatus::OfflineNonWiredSubnet
        );
        assert_eq!(
            records
                .iter()
                .find(|r| r.mac == "AA:BB:CC:DD:EE:02")
                .unwrap()
                .status,
            DeviceStatus::OfflineHostOwnedIp
        );
        assert!(registry.merge_scan_result("AA:01", &[80]));
        assert!(registry.merge_scan_result("AA:BB:CC:DD:EE:02", &[80]));
        assert!(registry.snapshot().iter().all(|r| matches!(
            r.status,
            DeviceStatus::OfflineNonWiredSubnet | DeviceStatus::OfflineHostOwnedIp
        )));
    }
}

// Read-only session/capture views for existing sweep callbacks. Only the
// owners advance lifecycle authority; clones retain the original fences.
#[derive(Clone)]
struct SweepDeps {
    selector: Arc<adapter_selector::AdapterSelector>,
    capture: Arc<capture_session::CaptureSession>,
    pending: auto_adopt::PendingIps,
    generation: Arc<AtomicU64>,
    active: Arc<AtomicBool>,
    config: Arc<crate::config::AppConfig>,
    bridge: Arc<dyn crate::bridge::AppBridge>,
}
impl SweepDeps {
    fn fence(&self) -> SweepFence {
        SweepFence::new(
            self.generation.load(Ordering::Relaxed),
            self.generation.clone(),
            self.active.clone(),
        )
    }
}
