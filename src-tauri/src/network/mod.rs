pub mod adapter_refresh;
pub mod arp;
pub mod auto_adopt;
mod cache_probe;
pub mod device_registry;
pub mod firewall;
pub mod ghost;
pub mod interface;
pub mod ip_config;
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

/// Cooperative-shutdown handle for the auto-adopt loop: a `watch` signal
/// plus the task's join handle. A bare `JoinHandle` could only be aborted;
/// this lets `stop` ask the loop to exit at a `select!` point (so an
/// in-flight adoption cleans up), join with a bound, and fall back to abort
/// only if that times out.
struct AutoAdoptHandle {
    shutdown: tokio::sync::watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

/// How long a cooperative auto-adopt stop waits for the loop to exit before
/// aborting it. Abort is safe because the add/remove children are
/// kill-on-drop, so the dropped future takes any in-flight child with it.
const AUTO_ADOPT_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Handle to the capture-health watchdog. Like [`AutoAdoptHandle`], the
/// watchdog is asked to stop cooperatively — it may be mid-restart of the
/// capture session, and a cooperative exit lets it park or install the
/// in-flight session cleanly — with abort as the bounded fallback (safe:
/// an orphaned capture session tears itself down when its handle drops).
struct WatchdogHandle {
    shutdown: tokio::sync::watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

/// How long a cooperative watchdog stop waits before aborting.
const WATCHDOG_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Hard ceiling on a single adoption attempt. A probe can take ~11 s (1 s
/// ping + up to a 10 s neighbor lookup) across up to 11 candidates, so the
/// natural worst case is tens of seconds; 45 s bounds a pathological run
/// without thrashing the cooldown on a merely slow box. On timeout the adopt
/// future is dropped (killing its child) and its pending IPs are reconciled.
const ADOPT_MAX_TOTAL: std::time::Duration = std::time::Duration::from_secs(45);

/// Settle delay before an adoption is announced finished, covering the NIC
/// watcher's ~300 ms debounce so the final IP-change up-event is gated too.
const ADOPTION_SETTLE: std::time::Duration = std::time::Duration::from_millis(300);

/// Cooldown for subnets whose adoption FAILED (transient netsh errors, a
/// candidate that turned out to be in use, etc.). Replaces the old
/// permanent blacklist: subnet -> (next retry time, current backoff),
/// backoff doubling from 60 s, capped at 10 min. Shared by the adoption
/// tail and the reap pass's failure backoff.
const COOLDOWN_INITIAL: std::time::Duration = std::time::Duration::from_secs(60);
const COOLDOWN_MAX: std::time::Duration = std::time::Duration::from_secs(600);

/// RAII gate around a single adoption. On creation it emits
/// `adoption-started`; on drop — normal completion OR a dropped/aborted
/// future — it emits `adoption-finished` after a short settle. The frontend
/// suppresses watcher-driven discovery/stream restarts between the two so
/// the adoption's own IP churn (scratch bind/release, final add) is not
/// mistaken for a reconnect. The `adoption_id` lets the frontend ignore a
/// stale finish from a superseded adoption.
struct AdoptionGate {
    app_handle: tauri::AppHandle,
    adoption_id: u64,
}

impl AdoptionGate {
    fn start(app_handle: tauri::AppHandle, adoption_id: u64) -> Self {
        use tauri::Emitter;
        let _ = app_handle.emit(
            "adoption-started",
            serde_json::json!({ "adoption_id": adoption_id.to_string() }),
        );
        Self {
            app_handle,
            adoption_id,
        }
    }
}

impl Drop for AdoptionGate {
    fn drop(&mut self) {
        let app_handle = self.app_handle.clone();
        let adoption_id = self.adoption_id;
        let emit_finished = move || {
            use tauri::Emitter;
            let _ = app_handle.emit(
                "adoption-finished",
                serde_json::json!({ "adoption_id": adoption_id.to_string() }),
            );
        };
        // Drop can't await the settle, so run it on a short task; fall back
        // to an immediate emit if there is no runtime handle (e.g. during
        // shutdown) so the gate is never left stuck closed on the frontend.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    tokio::time::sleep(ADOPTION_SETTLE).await;
                    emit_finished();
                });
            }
            Err(_) => emit_finished(),
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

fn adapter_mac(mac: &str) -> Option<String> {
    let bytes = parse_mac_bytes(mac)?;
    (bytes != [0; 6] && bytes[0] & 1 == 0).then(|| mac.replace('-', ":").to_ascii_lowercase())
}

fn adapter_candidate(iface: &InterfaceInfo) -> bool {
    interface::is_wired_physical(iface) && !iface.is_wifi && adapter_mac(&iface.mac).is_some()
}

/// A saved identity wins even when absent; enumeration order never selects.
pub(crate) fn pick_adapter<'a>(
    list: &'a [InterfaceInfo],
    mac: Option<&str>,
) -> Option<&'a InterfaceInfo> {
    let mut candidates = list.iter().filter(|iface| adapter_candidate(iface));
    if let Some(mac) = mac {
        let mac = adapter_mac(mac)?;
        let mut matching =
            candidates.filter(|iface| adapter_mac(&iface.mac).as_ref() == Some(&mac));
        let found = matching.next()?;
        return matching.next().is_none().then_some(found);
    }
    let found = candidates.next()?;
    candidates.next().is_none().then_some(found)
}

#[derive(Default)]
struct CaptureSignal {
    state: CaptureState,
    app: Option<tauri::AppHandle>,
}

impl CaptureSignal {
    fn activate(&mut self, params: &arp::ListenerParams, outcome: pktmon::ScopeOutcome) {
        let scope = match &outcome {
            pktmon::ScopeOutcome::SelectedInterface { .. } => "selected_interface",
            pktmon::ScopeOutcome::ScopedByName { .. } => "scoped_by_name",
            pktmon::ScopeOutcome::UnscopedFallback { .. } => "unscoped",
        };
        log::info!("event=capture_state adapter_mac={} interface_index={} scope={} source_id={:?} active=true",
            log_value(&params.scope.mac.map(|m| arp::format_mac(&m)).unwrap_or_default()),
            params.candidates.as_ref().map_or(0, |c| c.interface_index), scope, outcome.source_id());
        self.app = Some(params.app_handle.clone());
        self.state = CaptureState {
            active: true,
            candidate_count: params
                .candidates
                .as_ref()
                .map_or(0, |i| i.store.count(std::time::Instant::now())),
            adapter_name: Some(params.scope.display_name.clone()),
            outcome: Some(outcome),
        };
        self.emit();
    }

    fn deactivate(&mut self) {
        if self.state.active {
            self.state.active = false;
            self.emit();
        }
    }

    fn emit(&self) {
        use tauri::Emitter;
        if let Some(app) = &self.app {
            let _ = app.emit("capture-active", &self.state);
        }
    }
}

/// A fresh look at the data source the capture scope would bind today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveSourceId {
    /// Native enumeration found this id for the adapter.
    Enumerated(u32),
    /// Enumeration was unavailable or failed. Fails open — a transient
    /// enumeration fault must never churn a healthy listener.
    EnumFailed,
}

/// What `ensure_capture_listener` does with the listener slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerAction {
    Attach,
    Keep,
    Replace(&'static str),
}

/// Pure decision for the capture-listener slot: keep a healthy binding,
/// replace an invalidated one, attach when none exists. `has_listener`
/// is the handle slot's occupancy — a recorded identity without a live
/// handle (a torn-down session whose reinstall failed) must attach, not
/// keep.
pub(crate) fn listener_action(
    current: Option<&CaptureIdentity>,
    has_listener: bool,
    desired_iface: &str,
    desired_mac: Option<[u8; 6]>,
    live: LiveSourceId,
) -> ListenerAction {
    let Some(current) = current else {
        return ListenerAction::Attach;
    };
    if !has_listener {
        return ListenerAction::Attach;
    }
    if !current.active.load(Ordering::Acquire) {
        return ListenerAction::Replace("capture inactive");
    }
    if current.iface_name != desired_iface || current.mac != desired_mac {
        return ListenerAction::Replace("adapter changed");
    }
    match (current.source_id, live) {
        // No live id to compare against — keep what runs.
        (_, LiveSourceId::EnumFailed) => ListenerAction::Keep,
        // An unscoped-fallback session never outlives the next start:
        // every ensure re-attempts the scoped join.
        (None, LiveSourceId::Enumerated(_)) => ListenerAction::Replace("retry scoped attach"),
        (Some(bound), LiveSourceId::Enumerated(live_id)) if bound != live_id => {
            ListenerAction::Replace("data source changed")
        }
        _ => ListenerAction::Keep,
    }
}

/// DHCP already captures; enabling adoption does not need a new listener.
fn mode_keeps_capture(from: crate::config::NetworkMode, to: crate::config::NetworkMode) -> bool {
    from == crate::config::NetworkMode::Dhcp && to == crate::config::NetworkMode::StaticAuto
}

fn mode_capture_action(action: ListenerAction, preserve: bool) -> ListenerAction {
    match (action, preserve) {
        (ListenerAction::Replace("retry scoped attach"), true) => ListenerAction::Keep,
        _ => action,
    }
}

/// RAII guard that removes a subnet from the active-scan set on drop, so a
/// cancelled `scan_subnet` future can't leave the subnet permanently marked
/// "scan in progress" (which would reject every later scan of it for the
/// process lifetime). Uses the std mutex so `Drop` can remove synchronously.
struct ScanGuard {
    active: Arc<std::sync::Mutex<HashSet<String>>>,
    subnet: String,
}

impl Drop for ScanGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = self.active.lock() {
            set.remove(&self.subnet);
        }
    }
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
    address_io: Arc<dyn interface::AddressIo>,
    active_scans: Arc<std::sync::Mutex<HashSet<String>>>,
    solicitations: tokio::sync::watch::Sender<Option<Solicitation>>,
    arp_devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    adopted_ips: Arc<Mutex<HashMap<String, Ipv4Addr>>>,
    arp_listener_handle: Arc<Mutex<Option<arp::ArpListenerHandle>>>,
    /// Capture threads told to stop but not yet observed dead. Every
    /// capture start drains this (bounded join) before attaching — the
    /// session name is fixed, so two live sessions must never overlap.
    prior_capture_joins: arp::PriorCaptureJoins,
    /// What the persistent capture listener is bound to (adapter, data
    /// source, incarnation lifecycle flag). `None` when no listener is
    /// attached.
    capture_identity: Arc<Mutex<Option<CaptureIdentity>>>,
    capture_signal: Arc<Mutex<CaptureSignal>>,
    candidates: Arc<arp::CandidateSet>,
    presence: Arc<presence::Control>,
    presence_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    address_work: Arc<Mutex<()>>,
    address_generation: Arc<AtomicU64>,
    address_active: Arc<AtomicBool>,
    /// Every IPv4 currently assigned to any local adapter. Shared with
    /// the capture callback and refreshed at every discovery start (and
    /// each adopt-loop pass), so a listener retained across sessions
    /// keeps an accurate self-filter.
    local_ips: Arc<StdMutex<HashSet<Ipv4Addr>>>,
    /// Legacy listener exclusions. Activated discovery clears these and
    /// uses selected-interface scope/verification even on overlapping subnets.
    excluded_subnets: Arc<StdMutex<Vec<ipnetwork::Ipv4Network>>>,
    auto_adopt_handle: Arc<Mutex<Option<AutoAdoptHandle>>>,
    /// Secondary IPs the auto-adopt loop has bound but not yet handed over
    /// to `adopted_ips` (scratch probes and unrecorded final adds), tagged
    /// with the owning adoption id. Reconciled on stop so a cancelled or
    /// timed-out adoption never leaks an untracked IP.
    pending_ips: auto_adopt::PendingIps,
    /// Monotonic source of adoption ids: each adoption pass takes the next
    /// value to tag its `pending_ips` entries.
    adoption_seq: Arc<AtomicU64>,
    /// Capture-health watchdog: restarts a provably deaf capture session
    /// (scoped retry, then forced-unscoped), and only when that ladder is
    /// exhausted emits `discovery-degraded`, then `discovery-recovered`
    /// on the first frame — the pre-ladder event contract, unchanged.
    discovery_watchdog_handle: Arc<Mutex<Option<WatchdogHandle>>>,
    interface_name: Arc<Mutex<Option<String>>>,
    interface_index: Arc<Mutex<Option<u32>>>,
    adapter_selection: Arc<Mutex<AdapterSelection>>,
    /// Canonical store of merged device records (ARP + scan + cache +
    /// alias + status). Mutated alongside `arp_devices` during the
    /// transition; once the frontend is fully migrated to subscribe-only
    /// snapshots the legacy map can be deleted.
    device_registry: Arc<DeviceRegistry>,
    /// Late-bound emitter that turns registry mutations into debounced
    /// `device-list-changed` events. None until `start_arp_discovery`
    /// (which receives the AppHandle) wires it up.
    device_emitter: Arc<Mutex<Option<Arc<DeviceListEmitter>>>>,
    /// Handle to the ICMP pinger task (green/red dot driver). Started
    /// by `start_ping_dot`, stopped on shutdown. Mode-independent: the
    /// pinger watches whatever the registry contains.
    ping_dot_handle: Arc<Mutex<Option<ping_dot::PingDotHandle>>>,
    /// Serializes the discovery lifecycle (start / stop / mode change /
    /// startup restore) so concurrent entry can't overwrite — and thereby
    /// orphan — the auto-adopt task handle. Non-reentrant: internal callers
    /// use the `*_locked` variants.
    discovery_op: Arc<Mutex<()>>,
    /// Advanced on every discovery start. Captured by sweeps and the
    /// capture listener so stale-session work fences itself out.
    discovery_generation: Arc<AtomicU64>,
    /// True while a discovery session is live; cleared by every stop. The
    /// generation only advances on start, so this flag is what lets a stop
    /// with no restart (Static Auto → Manual) still drop stragglers.
    discovery_active: Arc<AtomicBool>,
    /// Session-only positive-liveness clock per adopted subnet: the
    /// monotonic instant of the last accepted ARP frame, successful
    /// targeted scan, or successful ping from a device on the subnet.
    /// Never persisted — wall clock is display-only by design.
    adoption_liveness: Arc<std::sync::Mutex<HashMap<String, std::time::Instant>>>,
    /// In-memory working copy of the persisted adoption metadata
    /// (config's `adopted_meta`), stamped through the same choke point
    /// as `adoption_liveness` and flushed coarsely (see `MetaFlush`).
    adopted_meta: Arc<std::sync::Mutex<HashMap<String, crate::config::AdoptedMeta>>>,
    /// Flush cadence for metadata-only config writes.
    meta_flush: Arc<std::sync::Mutex<MetaFlush>>,
    /// Instant the current discovery session started; `None` while
    /// stopped. Anchors the startup-grace math when the adoption
    /// snapshot derives staleness (the reap pass carries its own copy
    /// into the loop task).
    discovery_started: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
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

/// Provoke ARP on the selected subnets, then merge the OS neighbor table.
/// Fence-checked throughout. Shared by discovery start (spawned after a
/// short delay so the capture attach lands first) and the capture-restart
/// ladder, which re-provokes so a fresh session has traffic to prove
/// itself against.
async fn provoke_sweep(params: &arp::ListenerParams, sweep_ips: &[String]) {
    if params.fence.is_stale() {
        return;
    }
    log::info!("Ping sweeping selected subnets to populate ARP");
    ping_sweep_subnets(sweep_ips, &params.fence, &params.app_handle).await;

    // One brief-lock snapshot for the whole merge pass (never lock per
    // entry); a poisoned lock degrades to an empty set, which filters
    // nothing — fail-open.
    let local_snapshot: HashSet<Ipv4Addr> = params
        .local_ips
        .lock()
        .map(|s| s.clone())
        .unwrap_or_default();
    let excluded_snapshot: Vec<ipnetwork::Ipv4Network> = params
        .excluded_subnets
        .lock()
        .map(|v| v.clone())
        .unwrap_or_default();

    // Neighbor observations from the selected pass still enter through the
    // fenced candidate path. Known retained devices use targeted presence.
    for sweep_iface_ip in sweep_ips {
        if params.fence.is_stale() {
            break;
        }
        if sweep_iface_ip.is_empty() {
            continue;
        }
        merge_arp_table(
            params.devices.clone(),
            params.registry.clone(),
            params.emitter.clone(),
            params.app_handle.clone(),
            sweep_iface_ip,
            &excluded_snapshot,
            &local_snapshot,
            &params.fence,
            params.candidates.as_ref(),
        )
        .await;
    }
}

/// The current capture session's counters, if a session is installed.
async fn current_session_counters(
    slot: &Arc<Mutex<Option<arp::ArpListenerHandle>>>,
) -> Option<Arc<arp::SessionCounters>> {
    slot.lock().await.as_ref().map(|h| h.counters())
}

/// Take the installed capture handle, signal it to stop, and park its
/// join in the prior-capture guard — ownership is retained; the next
/// capture start bounded-joins it there.
async fn park_capture_handle(
    slot: &Arc<Mutex<Option<arp::ArpListenerHandle>>>,
    prior: &arp::PriorCaptureJoins,
) {
    if let Some(h) = slot.lock().await.take() {
        prior.lock().await.push(h.stop_into_join());
    }
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

/// Long-lived clones the shared adoption tail needs, built once at
/// adopt-task start from the clones the task already owns. Lets the
/// broadcast dwell path and the cache probe drive one tail without a
/// dozen-argument signature.
struct AdoptionCtx {
    iface_name: String,
    adapter_mac: String,
    interface_index: u32,
    candidates: Option<arp::CandidateIngress>,
    app_handle: tauri::AppHandle,
    adopted: Arc<Mutex<HashMap<String, Ipv4Addr>>>,
    pending_ips: auto_adopt::PendingIps,
    adoption_seq: Arc<AtomicU64>,
    liveness: Arc<std::sync::Mutex<HashMap<String, std::time::Instant>>>,
    meta: Arc<std::sync::Mutex<HashMap<String, crate::config::AdoptedMeta>>>,
    devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    registry: Arc<DeviceRegistry>,
    emitter: Arc<DeviceListEmitter>,
    fence: SweepFence,
    address_fence: SweepFence,
    local_ips: Arc<std::sync::Mutex<HashSet<Ipv4Addr>>>,
}

/// Why an adoption attempt is justified. Logged only — `adopted_meta`
/// keeps its two-field schema; provenance has no consumer.
enum AdoptionEvidence {
    /// The dwell gate matured: two accepted broadcast frames.
    DwellMature { mac: String },
    /// The cache probe got a solicited, freshly MAC-verified reply from
    /// a device we have history with — strictly stronger evidence than
    /// two spontaneous frames, which is what justifies bypassing dwell.
    CachedMacMatch { cached_ip: Ipv4Addr, mac: String },
    /// A live first sighting confirmed by a directed on-link probe: the
    /// device answered a fresh ARP from the scratch with the same MAC
    /// the sighted frame carried. The solicited reply substitutes for
    /// the dwell gate's second spontaneous frame — freshness and
    /// identity-consistency evidence, so a stale or stray frame with no
    /// live sender behind it can never reach adoption.
    FreshSightingConfirmed { probed_ip: Ipv4Addr, mac: String },
}

impl std::fmt::Display for AdoptionEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdoptionEvidence::DwellMature { mac } => {
                write!(f, "confirmed by a repeat observation from {}", mac)
            }
            AdoptionEvidence::CachedMacMatch { cached_ip, mac } => {
                write!(f, "cached device {} freshly verified at {}", mac, cached_ip)
            }
            AdoptionEvidence::FreshSightingConfirmed { probed_ip, mac } => {
                write!(
                    f,
                    "fresh sighting {} confirmed by a directed probe at {}",
                    mac, probed_ip
                )
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdoptionAttemptOutcome {
    Adopted,
    NoOp,
    Failed,
    /// A stop raced the attempt — the caller must exit its loop.
    ShutdownRace,
}

/// The shared adoption tail: gate, bounded `adopt_subnet`, and every
/// success/failure consequence (liveness seed, metadata, events, pending
/// handover, post-adoption sweeps, config persist, cooldown handling).
/// Driven by the broadcast dwell path and the cache probe; the evidence
/// says which. Deliberately has no access to the dwell tracker — the
/// probe path must never touch it, so it stays at the broadcast site.
#[allow(clippy::too_many_arguments)]
async fn attempt_adoption(
    ctx: &AdoptionCtx,
    device_ip: Ipv4Addr,
    device_subnet: &str,
    evidence: AdoptionEvidence,
    current_ips: &[Ipv4Addr],
    cooldowns: &mut HashMap<String, (std::time::Instant, std::time::Duration)>,
    known_subnets: &mut HashSet<String>,
    shutdown_rx: &tokio::sync::watch::Receiver<bool>,
) -> AdoptionAttemptOutcome {
    use tauri::Emitter;
    use tauri::Manager;

    let config = ctx.app_handle.state::<crate::config::AppConfig>();
    let ops = auto_adopt::PendingAdoptOps::new(&config, &ctx.adapter_mac, auto_adopt::RealAdoptOps);
    if ctx.fence.is_stale()
        || ctx.address_fence.is_stale()
        || config.get_network_mode() != crate::config::NetworkMode::StaticAuto
    {
        return AdoptionAttemptOutcome::NoOp;
    }
    if crate::validation::prohibited_camera_ip(device_ip) {
        return AdoptionAttemptOutcome::NoOp;
    }
    if let Err(error) = ctx
        .app_handle
        .state::<NetworkManager>()
        .prepare_subnet_adoption(
            &config,
            device_subnet,
            &ctx.adapter_mac,
            ctx.interface_index,
            &ctx.fence,
            &ctx.address_fence,
        )
        .await
    {
        log::debug!("Adoption deferred for {}: {}", device_subnet, error);
        return AdoptionAttemptOutcome::NoOp;
    }

    log::info!("Foreign subnet {} — adopting ({})", device_subnet, evidence);

    let adoption_id = ctx.adoption_seq.fetch_add(1, Ordering::Relaxed) + 1;
    // Bracket the adoption with started/finished so the frontend
    // suppresses restarts from its own IP churn. The guard emits
    // `adoption-finished` on drop, so every terminal path below
    // (success, timeout, error, shutdown race, task abort) releases the
    // gate.
    let _gate = AdoptionGate::start(ctx.app_handle.clone(), adoption_id);
    // Fresh read at adoption time (not the shared filter set):
    // candidate-collision checking wants the newest possible view of our
    // own addresses, and the name must not shadow the shared `local_ips`
    // the post-adoption sweep clones below.
    let host_ips_now = interface::all_local_ipv4();
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        ADOPT_MAX_TOTAL,
        auto_adopt::adopt_subnet(
            &ops,
            &ctx.iface_name,
            device_ip,
            current_ips,
            &host_ips_now,
            &ctx.pending_ips,
            adoption_id,
            shutdown_rx,
        ),
    )
    .await;

    match outcome {
        Err(_elapsed) => {
            // ADOPT_MAX_TOTAL hit: the adopt future is dropped now, so
            // kill-on-drop took any in-flight child. Reconcile whatever
            // it bound and re-arm the cooldown. Logged distinctly so the
            // bound can be retuned from field data.
            log::warn!(
                "Adoption of {} exceeded the {}s bound (elapsed {}s) — dropped and reconciling",
                device_subnet,
                ADOPT_MAX_TOTAL.as_secs(),
                started.elapsed().as_secs()
            );
            auto_adopt::reconcile_pending(&ops, &ctx.pending_ips, Some(adoption_id)).await;
            let next_backoff = cooldowns
                .get(device_subnet)
                .map(|(_, b)| (*b * 2).min(COOLDOWN_MAX))
                .unwrap_or(COOLDOWN_INITIAL);
            cooldowns.insert(
                device_subnet.to_string(),
                (std::time::Instant::now() + next_backoff, next_backoff),
            );
            AdoptionAttemptOutcome::Failed
        }
        Ok(Ok(Some(adopted_ip))) => {
            // A stop may have raced the successful final bind. If so,
            // roll the IP back and do NOT record — recording an IP the
            // stop path won't clean is worse than re-adopting on the
            // next start.
            if *shutdown_rx.borrow() || ctx.fence.is_stale() || ctx.address_fence.is_stale() {
                log::info!(
                    "Shutdown raced adoption of {} — rolling back {}",
                    device_subnet,
                    adopted_ip
                );
                auto_adopt::reconcile_pending(&ops, &ctx.pending_ips, Some(adoption_id)).await;
                return AdoptionAttemptOutcome::ShutdownRace;
            }
            let adoption_wall = chrono::Utc::now().to_rfc3339();
            let row = crate::config::AdoptedMeta {
                adopted_at: Some(adoption_wall.clone()),
                last_device_seen: Some(adoption_wall.clone()),
                adapter_mac: adapter_mac(&ctx.adapter_mac),
                address: Some(adopted_ip.to_string()),
                prefix: Some(24),
                applied: true,
                ..Default::default()
            };
            // Commit before handover. A failed save leaves only this attempt's
            // pending breadcrumb, which is rolled back without touching saved IPs.
            if let Err(e) = commit_pending_address(
                &ctx.pending_ips,
                &ctx.iface_name,
                adopted_ip,
                adoption_id,
                || {
                    if ctx.fence.is_stale()
                        || ctx.address_fence.is_stale()
                        || config
                            .get()
                            .selected_adapter_mac
                            .as_deref()
                            .and_then(adapter_mac)
                            != adapter_mac(&ctx.adapter_mac)
                    {
                        return Err(AppError::Network(
                            "Adapter or address work changed before commit".into(),
                        ));
                    }
                    config.set_binding(device_subnet, row.clone())
                },
            )
            .await
            {
                log::warn!("Adoption commit failed for {}: {}", device_subnet, e);
                auto_adopt::reconcile_pending(&ops, &ctx.pending_ips, Some(adoption_id)).await;
                return AdoptionAttemptOutcome::Failed;
            }
            cooldowns.remove(device_subnet);
            ctx.adopted
                .lock()
                .await
                .insert(device_subnet.to_string(), adopted_ip);
            // Fresh adoption: the triggering device was observed moments
            // ago, so seed the session liveness clock and the persisted
            // metadata together.
            if let Ok(mut liveness) = ctx.liveness.lock() {
                liveness.insert(device_subnet.to_string(), std::time::Instant::now());
            }
            if let Ok(mut meta) = ctx.meta.lock() {
                meta.insert(device_subnet.to_string(), row.clone());
            }
            known_subnets.insert(device_subnet.to_string());

            let _ = ctx.app_handle.emit(
                "subnet-adopted",
                adoption_event(
                    device_subnet,
                    &adopted_ip.to_string(),
                    &adoption_meta_view(
                        device_subnet,
                        Some(&row),
                        Some(std::time::Duration::ZERO),
                        std::time::Duration::ZERO,
                        None,
                    ),
                    false,
                ),
            );

            log::info!("event=binding_change adapter_mac={} interface_index={} subnet={} address={} desired=Present applied=true reason=adopted",
                log_value(&ctx.adapter_mac), ctx.interface_index, log_value(device_subnet), adopted_ip);

            // One bounded pass after the new binding settles. Presence handles
            // later verification; a quiet adopted subnet is not swept repeatedly.
            let sweep_ip = adopted_ip.to_string();
            let sweep_devices = ctx.devices.clone();
            let sweep_registry = ctx.registry.clone();
            let sweep_emitter = ctx.emitter.clone();
            let sweep_handle = ctx.app_handle.clone();
            let sweep_fence = ctx.fence.clone();
            let sweep_candidates = ctx.candidates.clone();
            let sweep_local = ctx.local_ips.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                if sweep_fence.is_stale() {
                    return;
                }
                ping_sweep_subnets(std::slice::from_ref(&sweep_ip), &sweep_fence, &sweep_handle)
                    .await;
                let local_snapshot: HashSet<Ipv4Addr> =
                    sweep_local.lock().map(|s| s.clone()).unwrap_or_default();
                merge_arp_table(
                    sweep_devices.clone(),
                    sweep_registry.clone(),
                    sweep_emitter.clone(),
                    sweep_handle.clone(),
                    &sweep_ip,
                    &[],
                    &local_snapshot,
                    &sweep_fence,
                    sweep_candidates.as_ref(),
                )
                .await;
            });

            AdoptionAttemptOutcome::Adopted
        }
        Ok(Ok(None)) => {
            // Already on subnet, or a clean shutdown-before-bind.
            // Nothing was left bound.
            cooldowns.remove(device_subnet);
            known_subnets.insert(device_subnet.to_string());
            if *shutdown_rx.borrow() {
                AdoptionAttemptOutcome::ShutdownRace
            } else {
                AdoptionAttemptOutcome::NoOp
            }
        }
        Ok(Err(e)) => {
            // adopt_subnet cleaned its own breadcrumbs except a scratch
            // whose release failed; reconcile this id to catch that.
            // Cooldown instead of a permanent blacklist so a transient
            // failure is retried.
            auto_adopt::reconcile_pending(&ops, &ctx.pending_ips, Some(adoption_id)).await;
            let next_backoff = cooldowns
                .get(device_subnet)
                .map(|(_, b)| (*b * 2).min(COOLDOWN_MAX))
                .unwrap_or(COOLDOWN_INITIAL);
            cooldowns.insert(
                device_subnet.to_string(),
                (std::time::Instant::now() + next_backoff, next_backoff),
            );
            log::warn!(
                "Failed to auto-adopt {} ({}); retrying in {}s",
                device_subnet,
                e,
                next_backoff.as_secs()
            );
            let _ = ctx.app_handle.emit(
                "adoption-failed",
                serde_json::json!({
                    "subnet": device_subnet,
                    "error": e.to_string(),
                }),
            );
            AdoptionAttemptOutcome::Failed
        }
    }
}

/// Settle wait after binding an identity scratch, covering Windows
/// duplicate-address detection (~1 s per DAD transmit, three transmits
/// by default) so `SendARP` sourced from the scratch actually transmits.
const SCRATCH_SETTLE: std::time::Duration = std::time::Duration::from_secs(3);

/// Which adoption path is driving a probe pass. Picks the evidence
/// variant a hand-off carries and the prefix its log lines wear, so
/// fast-adopt activity never masquerades as cache-probe activity in
/// field logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeOrigin {
    CacheProbe,
    FastAdopt,
}

impl ProbeOrigin {
    fn label(self) -> &'static str {
        match self {
            ProbeOrigin::CacheProbe => "Cache probe",
            ProbeOrigin::FastAdopt => "Fast adopt",
        }
    }
}

/// Evidence for a probe-confirmed adoption, keyed by which path ran the
/// probe. Pure so the mapping stays testable — `RealProbeIo` itself
/// cannot be constructed in lib tests.
fn probe_evidence(origin: ProbeOrigin, ip: Ipv4Addr, mac: &str) -> AdoptionEvidence {
    match origin {
        ProbeOrigin::CacheProbe => AdoptionEvidence::CachedMacMatch {
            cached_ip: ip,
            mac: mac.to_string(),
        },
        ProbeOrigin::FastAdopt => AdoptionEvidence::FreshSightingConfirmed {
            probed_ip: ip,
            mac: mac.to_string(),
        },
    }
}

/// Production `ProbeIo`: scratch discipline via the auto-adopt
/// breadcrumb helpers, fresh resolution via `ResolveIpNetEntry2`, and the
/// shared adoption tail for hand-offs.
struct RealProbeIo<'a> {
    ctx: &'a AdoptionCtx,
    cooldowns: &'a mut HashMap<String, (std::time::Instant, std::time::Duration)>,
    known_subnets: &'a mut HashSet<String>,
    shutdown_rx: &'a tokio::sync::watch::Receiver<bool>,
    /// Adoption id minted for the currently-bound identity scratch.
    scratch_id: Option<u64>,
    /// Set when a hand-off observed a shutdown race; the adopt loop
    /// must break after the pass returns.
    stop: bool,
    /// Who is driving this pass — evidence variant and log prefix.
    origin: ProbeOrigin,
}

impl cache_probe::ProbeIo for RealProbeIo<'_> {
    fn interface_index(&self) -> u32 {
        self.ctx.interface_index
    }

    async fn bind_scratch(&mut self, subnet: &str, scratch: Ipv4Addr) -> bool {
        use tauri::Manager;
        let config = self.ctx.app_handle.state::<crate::config::AppConfig>();
        let ops = auto_adopt::PendingAdoptOps::new(
            &config,
            &self.ctx.adapter_mac,
            auto_adopt::RealAdoptOps,
        );
        if self.shutdown()
            || self.ctx.address_fence.is_stale()
            || config.get_network_mode() != crate::config::NetworkMode::StaticAuto
            || !matches!(
                ip_config::get_dhcp_state(&self.ctx.iface_name).await,
                Ok(false)
            )
        {
            return false;
        }
        if let Err(error) = self
            .ctx
            .app_handle
            .state::<NetworkManager>()
            .prepare_subnet_adoption(
                &config,
                subnet,
                &self.ctx.adapter_mac,
                self.ctx.interface_index,
                &self.ctx.fence,
                &self.ctx.address_fence,
            )
            .await
        {
            log::info!(
                "{}: probe deferred for {}: {}",
                self.origin.label(),
                subnet,
                error
            );
            return false;
        }
        if self.shutdown() || config.get_network_mode() != crate::config::NetworkMode::StaticAuto {
            return false;
        }

        let id = self.ctx.adoption_seq.fetch_add(1, Ordering::Relaxed) + 1;
        match auto_adopt::bind_scratch(
            &ops,
            &self.ctx.pending_ips,
            &self.ctx.iface_name,
            scratch,
            id,
        )
        .await
        {
            Ok(()) => {
                log::info!(
                    "{}: bound scratch {} for {}",
                    self.origin.label(),
                    scratch,
                    subnet
                );
                self.scratch_id = Some(id);
                // A freshly bound address sits in duplicate-address
                // detection (tentative) for ~1–3 s and is not usable as
                // an ARP source until that clears — the same window the
                // post-adoption sweep documents for its first pass. The
                // conflict-probe path absorbs it across its multi-
                // candidate loop; the identity probe gets one explicit
                // settle, counted against the pass budget.
                tokio::time::sleep(SCRATCH_SETTLE).await;
                true
            }
            Err(e) => {
                log::info!(
                    "{}: scratch bind failed for {}: {}",
                    self.origin.label(),
                    subnet,
                    e
                );
                false
            }
        }
    }

    async fn release_scratch(&mut self, _subnet: &str, scratch: Ipv4Addr) {
        use tauri::Manager;
        let config = self.ctx.app_handle.state::<crate::config::AppConfig>();
        let ops = auto_adopt::PendingAdoptOps::new(
            &config,
            &self.ctx.adapter_mac,
            auto_adopt::RealAdoptOps,
        );
        if let Some(id) = self.scratch_id.take() {
            auto_adopt::release_scratch(
                &ops,
                &self.ctx.pending_ips,
                &self.ctx.iface_name,
                scratch,
                id,
            )
            .await;
        }
    }

    async fn resolve(
        &mut self,
        target: Ipv4Addr,
        scratch: Ipv4Addr,
        interface_index: u32,
    ) -> Result<Option<String>, ()> {
        use tauri::Manager;
        if interface_index != self.ctx.interface_index || self.ctx.fence.is_stale() {
            return Err(());
        }
        // Logged at info per outcome — a silent miss here cost a field
        // session; the pass touches at most a handful of pairs.
        // The join owner retains this permit even if its session is dropped.
        static LIMIT: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
            std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(2)));
        let permit = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            LIMIT.clone().acquire_owned(),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
        if self.ctx.fence.is_stale() {
            return Err(());
        }
        self.ctx
            .app_handle
            .state::<NetworkManager>()
            .note_solicitation(&self.ctx.fence)
            .await;
        if self.ctx.fence.is_stale() {
            return Err(());
        }
        let native = tokio::spawn(async move {
            let _permit = permit;
            arp::fresh_resolve_mac(target, scratch, interface_index).await
        });
        // Timing out the join leaves its owner alive with the permit. A slow
        // OS call cannot stall the pass or create unbounded replacement work.
        let resolved = tokio::time::timeout(std::time::Duration::from_secs(8), native)
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
        if self.ctx.fence.is_stale() {
            return Err(());
        }
        log::debug!("event=identity_probe adapter_mac={} interface_index={} target={} source={} answered={} {}",
            log_value(&self.ctx.adapter_mac), interface_index, target, scratch,
            matches!(&resolved, Ok(Some(_))), arp::diagnostic_counts());
        match resolved {
            Ok(Some(mac)) => {
                log::info!("{}: {} answered with {}", self.origin.label(), target, mac);
                Ok(Some(mac))
            }
            Ok(None) => {
                log::info!(
                    "{}: {} did not answer a fresh ARP",
                    self.origin.label(),
                    target
                );
                Ok(None)
            }
            Err(e) => {
                log::info!(
                    "{}: fresh resolve of {} failed closed: {}",
                    self.origin.label(),
                    target,
                    e
                );
                Err(())
            }
        }
    }

    async fn adopt(&mut self, subnet: &str, ip: Ipv4Addr, mac: &str) -> bool {
        // Fresh read after the identity scratch was released, so the
        // adoption's own `already_on_subnet` check cannot see it and
        // silently no-op.
        let current_ips = get_interface_ips(&self.ctx.iface_name).await;
        let outcome = attempt_adoption(
            self.ctx,
            ip,
            subnet,
            probe_evidence(self.origin, ip, mac),
            &current_ips,
            self.cooldowns,
            self.known_subnets,
            self.shutdown_rx,
        )
        .await;
        if outcome == AdoptionAttemptOutcome::ShutdownRace {
            self.stop = true;
            return false;
        }
        true
    }

    fn shutdown(&self) -> bool {
        *self.shutdown_rx.borrow() || self.ctx.fence.is_stale() || self.ctx.address_fence.is_stale()
    }
}

#[derive(Clone, Copy)]
struct Solicitation {
    generation: u64,
    at: tokio::time::Instant,
    baseline: arp::CounterSnapshot,
}

/// No window runs until traffic was solicited in this capture attempt.
/// Retain the pre-send baseline even if scheduling delays the watchdog.
async fn watch_window(
    counters: &arp::SessionCounters,
    solicitations: &mut tokio::sync::watch::Receiver<Option<Solicitation>>,
    generation: u64,
    after: Option<tokio::time::Instant>,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    window: std::time::Duration,
) -> Option<(u64, u64)> {
    let solicitation = loop {
        if !solicitations.has_changed().ok()? {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => return None,
                changed = solicitations.changed() => { changed.ok()?; }
            }
        }
        let value = *solicitations.borrow_and_update();
        if let Some(value) =
            value.filter(|s| s.generation == generation && after.is_none_or(|at| s.at >= at))
        {
            break value;
        }
    };
    tokio::select! {
        biased;
        _ = shutdown_rx.changed() => return None,
        _ = tokio::time::sleep_until(solicitation.at + window) => {}
    }
    let now = counters.snapshot();
    Some((
        now.frames_seen
            .saturating_sub(solicitation.baseline.frames_seen),
        now.self_ip_dropped
            .saturating_sub(solicitation.baseline.self_ip_dropped),
    ))
}

/// Capture-health watchdog with a bounded self-heal ladder.
///
/// After each session activation, the provoking sweep plus a checkpoint
/// window prove the session delivers. A deaf-but-alive (or fully dead)
/// session is restarted: once scoped, covering transient attach races,
/// then forced-unscoped. If the escalation is also deaf — or any start
/// fails, an activation times out, or a teardown join times out — the
/// ladder exhausts into the pre-existing degraded event and bounded
/// recovery poll. Transparent retries and recoveries log only;
/// `discovery-degraded` fires at most once, on exhaustion, so the
/// degraded/recovered event contract is unchanged.
///
/// Runs below the discovery lifecycle mutex; a concurrent stop wins.
/// Every wait point also watches `shutdown_rx`, the fence is re-checked
/// under the handle-slot lock before a restarted session is installed,
/// and health is sampled through the installed handle's own counters
/// only — late callbacks from a torn-down session cannot satisfy a
/// checkpoint.
async fn watchdog_ladder(
    params: arp::ListenerParams,
    sweep_ips: Vec<String>,
    listener_slot: Arc<Mutex<Option<arp::ArpListenerHandle>>>,
    prior_joins: arp::PriorCaptureJoins,
    capture_identity: Arc<Mutex<Option<CaptureIdentity>>>,
    activation: (
        arp::ActivationRx,
        tokio::sync::watch::Receiver<Option<Solicitation>>,
    ),
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    use tauri::{Emitter, Manager};
    let (mut activation_rx, mut solicitations) = activation;
    let capture_signal = params
        .app_handle
        .state::<NetworkManager>()
        .capture_signal
        .clone();
    // The deadline starts at the solicitation, not at activation.
    const INITIAL_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
    const POLL: std::time::Duration = std::time::Duration::from_secs(2);
    const MAX_WATCH: std::time::Duration = std::time::Duration::from_secs(300);

    let mut restarts_used: u32 = 0;
    let mut last_self_delta: u64 = 0;
    'session: loop {
        // Consecutive quiet windows in this attempt. Structurally
        // consecutive: the only path to another window without a fresh
        // activation is the Rebaseline arm, so any other verdict ends
        // the run and the count never goes stale.
        let mut quiet_windows: u32 = 0;
        let mut window_after = (restarts_used > 0).then(tokio::time::Instant::now);
        let activation = tokio::select! {
            _ = shutdown_rx.changed() => None,
            outcome = tokio::time::timeout(arp::CAPTURE_ACTIVATION_TIMEOUT, activation_rx) => {
                Some(outcome)
            }
        };
        let mut event = match activation {
            None => arp::AttemptEvent::ShutdownSignalled,
            Some(Ok(Ok(Ok(scope)))) => {
                if restarts_used > 0 {
                    if params.fence.is_stale() {
                        return;
                    }
                    if let Some(identity) = capture_identity.lock().await.as_mut() {
                        identity.source_id = scope.source_id();
                    }
                    capture_signal.lock().await.activate(&params, scope);
                }
                match current_session_counters(&listener_slot).await {
                    None => arp::AttemptEvent::ShutdownSignalled, // stop already took the handle
                    Some(counters) => {
                        // Initial start schedules the native pass. Restarts
                        // provoke only native subnets; otherwise wait for ARP
                        // presence/cache verification or explicit Refresh.
                        if restarts_used > 0 {
                            provoke_sweep(&params, &sweep_ips).await;
                        }
                        match watch_window(
                            &counters,
                            &mut solicitations,
                            params.fence.generation,
                            window_after,
                            &mut shutdown_rx,
                            INITIAL_WINDOW,
                        )
                        .await
                        {
                            None => arp::AttemptEvent::ShutdownSignalled,
                            Some((payload_delta, self_delta)) => {
                                window_after = Some(tokio::time::Instant::now());
                                last_self_delta = self_delta;
                                arp::AttemptEvent::Verdict(arp::capture_health(
                                    payload_delta,
                                    self_delta,
                                ))
                            }
                        }
                    }
                }
            }
            // The capture thread already logged the start failure.
            Some(Ok(Ok(Err(_start_error)))) => arp::AttemptEvent::StartFailed,
            Some(Ok(Err(_channel_closed))) => arp::AttemptEvent::ActivationChannelClosed,
            Some(Err(_elapsed)) => {
                // The blocking thread may still complete the fixed-name
                // start later — retain ownership: park the unconfirmed
                // session so no future start can overlap it.
                park_capture_handle(&listener_slot, &prior_joins).await;
                arp::AttemptEvent::ActivationTimedOut
            }
        };

        // Act on decisions until this attempt resolves. Quiet windows
        // re-measure in place (bounded by MAX_QUIET_WINDOWS); a Restart
        // that faults feeds the fault back through the decision
        // function, which always exhausts.
        loop {
            match arp::next_ladder_step(event, restarts_used) {
                arp::LadderAction::Done => {
                    if restarts_used > 0 {
                        log::info!(
                            "Capture recovered: ARP payload events after restart (attempt {})",
                            restarts_used
                        );
                    }
                    return;
                }
                arp::LadderAction::Rebaseline => {
                    quiet_windows += 1;
                    if quiet_windows == 1 {
                        log::info!(
                            "Capture quiet: no traffic in either direction (link down or idle wire) — watchdog holding, no restart"
                        );
                    }
                    if quiet_windows >= arp::MAX_QUIET_WINDOWS {
                        // The hold has run long enough that "quiet wire"
                        // needs confirming — a session delivering nothing
                        // on a live link is dead, not quiet, and must
                        // resume the ladder rather than end the watch.
                        let link_up = interface::get_by_name(&params.scope.display_name)
                            .await
                            .ok()
                            .map(|i| i.is_up);
                        match arp::quiet_exhaust_event(link_up) {
                            Some(verdict) => {
                                log::warn!(
                                    "Capture quiet for {} windows with the link up — treating the session as dead",
                                    quiet_windows
                                );
                                quiet_windows = 0;
                                event = arp::AttemptEvent::Verdict(verdict);
                                continue;
                            }
                            None => {
                                log::info!(
                                    "Capture quiet with the link down or unreadable — ending the watch; the next discovery start re-arms it"
                                );
                                return;
                            }
                        }
                    }
                    // Another window requires a fresh solicitation in this session.
                    let Some(counters) = current_session_counters(&listener_slot).await else {
                        return; // stop already took the handle
                    };
                    match watch_window(
                        &counters,
                        &mut solicitations,
                        params.fence.generation,
                        window_after,
                        &mut shutdown_rx,
                        INITIAL_WINDOW,
                    )
                    .await
                    {
                        None => return, // shutdown mid-window — a stop wins
                        Some((payload_delta, self_delta)) => {
                            window_after = Some(tokio::time::Instant::now());
                            last_self_delta = self_delta;
                            event = arp::AttemptEvent::Verdict(arp::capture_health(
                                payload_delta,
                                self_delta,
                            ));
                            continue;
                        }
                    }
                }
                arp::LadderAction::Abort => return,
                arp::LadderAction::Exhaust => break 'session,
                arp::LadderAction::Restart(mode) => {
                    log::warn!(
                        "Capture Rx-dead (payload=0, self={}) — restarting capture (attempt {}, scope={:?})",
                        last_self_delta,
                        restarts_used + 1,
                        mode
                    );
                    // Retire the deaf incarnation's fence before tearing
                    // it down: with the flag false, even a wedged thread
                    // can never merge after the replacement attaches.
                    if let Some(identity) = capture_identity.lock().await.as_ref() {
                        identity.active.store(false, Ordering::Relaxed);
                    }
                    capture_signal.lock().await.deactivate();
                    // Tear down the deaf session; a stop that already
                    // took the handle wins.
                    let Some(old_handle) = listener_slot.lock().await.take() else {
                        return;
                    };
                    let mut old_join = old_handle.stop_into_join();
                    if tokio::time::timeout(arp::CAPTURE_JOIN_TIMEOUT, &mut old_join)
                        .await
                        .is_err()
                    {
                        // Wedged capture thread: park it so no future
                        // start can overlap it, and stop laddering.
                        prior_joins.lock().await.push(old_join);
                        event = arp::AttemptEvent::JoinTimedOut;
                        continue;
                    }
                    // A replacement is a fresh incarnation of the same
                    // binding: new lifecycle flag, new lifecycle fence.
                    let incarnation = Arc::new(AtomicBool::new(true));
                    let lifecycle_fence =
                        SweepFence::new(0, Arc::new(AtomicU64::new(0)), incarnation.clone());
                    match arp::start_listener(
                        params.with_fence(lifecycle_fence),
                        mode,
                        &prior_joins,
                    )
                    .await
                    {
                        Err(e) => {
                            log::warn!("Capture restart failed: {}", e);
                            event = arp::AttemptEvent::StartFailed;
                            continue;
                        }
                        Ok((new_handle, new_rx)) => {
                            let mut slot = listener_slot.lock().await;
                            if params.fence.is_stale() {
                                // Discovery stopped or restarted while we
                                // were attaching — the new session belongs
                                // to nobody; tear it straight back down.
                                incarnation.store(false, Ordering::Relaxed);
                                drop(slot);
                                prior_joins.lock().await.push(new_handle.stop_into_join());
                                return;
                            }
                            *slot = Some(new_handle);
                            drop(slot);
                            // Refresh the recorded identity: same
                            // adapter, new incarnation, and any bound
                            // source id is no longer this session's.
                            if let Some(identity) = capture_identity.lock().await.as_mut() {
                                identity.active = incarnation;
                                identity.source_id = None;
                            }
                            restarts_used += 1;
                            activation_rx = new_rx;
                            continue 'session;
                        }
                    }
                }
            }
        }
    }

    // Ladder exhausted — degrade exactly as the pre-ladder watchdog did,
    // then poll (bounded) for late recovery on the live session, if any.
    let missed = arp::missed_max();
    log::warn!(
        "Discovery degraded: no ARP payload events and the capture self-heal is exhausted (payload_total={}, missed_max={}, tasks_dropped={}, noneth_dropped={}, self_ip_dropped={}, prohibited_dropped={})",
        arp::frames_seen(),
        missed,
        arp::tasks_dropped(),
        arp::noneth_dropped(),
        arp::self_ip_dropped(),
        arp::prohibited_dropped()
    );
    log::warn!(
        "event=capture_exhausted adapter_mac={} interface_index={} cause=no_payload {}",
        log_value(
            &params
                .scope
                .mac
                .map(|m| arp::format_mac(&m))
                .unwrap_or_default()
        ),
        params.candidates.as_ref().map_or(0, |c| c.interface_index),
        arp::diagnostic_counts()
    );
    let _ = params.app_handle.emit(
        "discovery-degraded",
        serde_json::json!({
            "reason": "no-payload-events",
            "missed_packets": missed,
        }),
    );

    let Some(counters) = current_session_counters(&listener_slot).await else {
        return; // no live session left to watch
    };
    let baseline = counters.snapshot().frames_seen;
    let mut waited = std::time::Duration::ZERO;
    while waited < MAX_WATCH {
        tokio::select! {
            _ = shutdown_rx.changed() => return,
            _ = tokio::time::sleep(POLL) => {}
        }
        waited += POLL;
        if counters.snapshot().frames_seen > baseline {
            log::info!("Discovery recovered: ARP payload events resumed");
            let _ = params
                .app_handle
                .emit("discovery-recovered", serde_json::json!({}));
            return;
        }
    }
}

impl interface::AddressIo for interface::RealAddressIo {
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
    fn identity(&self, snapshot: &interface::OperationSnapshot, prefix: Option<u8>) {
        log::info!("event=address_operation operation={} adapter_guid={} adapter_mac={} interface_index={} alias={} prefix={}",
            self.id, log_value(&snapshot.selected.guid), log_value(&snapshot.selected.mac), snapshot.selected.index,
            log_value(&snapshot.selected.alias), prefix.map_or_else(|| "unknown".into(), |p| p.to_string()));
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
    #[cfg(test)]
    fn with_address_io(io: Arc<dyn interface::AddressIo>) -> Self {
        Self {
            address_io: io,
            ..Self::new()
        }
    }

    async fn operation_snapshot(
        &self,
        config: &crate::config::AppConfig,
    ) -> Result<interface::OperationSnapshot, AppError> {
        let mac = config
            .get()
            .selected_adapter_mac
            .ok_or_else(|| AppError::Network("Select an Ethernet adapter".into()))?;
        interface::operation_snapshot(self.address_io.as_ref(), &mac).await
    }
    async fn operation_snapshot_traced(
        &self,
        config: &crate::config::AppConfig,
        trace: Option<&AddressTrace>,
    ) -> Result<interface::OperationSnapshot, AppError> {
        let mac = config
            .get()
            .selected_adapter_mac
            .ok_or_else(|| AppError::Network("Select an Ethernet adapter".into()))?;
        interface::operation_snapshot_traced(self.address_io.as_ref(), &mac, trace).await
    }
    async fn observe_operation_traced(
        &self,
        before: &interface::OperationSnapshot,
        trace: Option<&AddressTrace>,
    ) -> Result<interface::OperationSnapshot, AppError> {
        if let Some(t) = trace {
            t.native_call();
        }
        let all = interface::read_native_with(self.address_io.as_ref()).await?;
        let after =
            interface::snapshot_from_native(self.address_io.as_ref(), &before.selected.mac, all)?;
        if before.selected.identity() != after.selected.identity() {
            return Err(AppError::Network(
                "Selected adapter changed during operation".into(),
            ));
        }
        Ok(after)
    }
    pub fn new() -> Self {
        Self {
            address_io: Arc::new(interface::RealAddressIo),
            active_scans: Arc::new(std::sync::Mutex::new(HashSet::new())),
            solicitations: tokio::sync::watch::channel(None).0,
            arp_devices: Arc::new(Mutex::new(HashMap::new())),
            adopted_ips: Arc::new(Mutex::new(HashMap::new())),
            arp_listener_handle: Arc::new(Mutex::new(None)),
            prior_capture_joins: Arc::new(Mutex::new(Vec::new())),
            capture_identity: Arc::new(Mutex::new(None)),
            capture_signal: Arc::new(Mutex::new(CaptureSignal::default())),
            candidates: Arc::new(arp::CandidateSet::default()),
            presence: Arc::new(presence::Control::default()),
            presence_handle: Mutex::new(None),
            address_work: Arc::new(Mutex::new(())),
            address_generation: Arc::new(AtomicU64::new(1)),
            address_active: Arc::new(AtomicBool::new(true)),
            local_ips: Arc::new(StdMutex::new(HashSet::new())),
            excluded_subnets: Arc::new(StdMutex::new(Vec::new())),
            auto_adopt_handle: Arc::new(Mutex::new(None)),
            pending_ips: Arc::new(Mutex::new(Vec::new())),
            adoption_seq: Arc::new(AtomicU64::new(0)),
            discovery_watchdog_handle: Arc::new(Mutex::new(None)),
            interface_name: Arc::new(Mutex::new(None)),
            interface_index: Arc::new(Mutex::new(None)),
            adapter_selection: Arc::new(Mutex::new(AdapterSelection::default())),
            device_registry: Arc::new(DeviceRegistry::new()),
            device_emitter: Arc::new(Mutex::new(None)),
            ping_dot_handle: Arc::new(Mutex::new(None)),
            discovery_op: Arc::new(Mutex::new(())),
            discovery_generation: Arc::new(AtomicU64::new(0)),
            discovery_active: Arc::new(AtomicBool::new(false)),
            adoption_liveness: Arc::new(std::sync::Mutex::new(HashMap::new())),
            adopted_meta: Arc::new(std::sync::Mutex::new(HashMap::new())),
            meta_flush: Arc::new(std::sync::Mutex::new(MetaFlush {
                dirty: false,
                last_flush: std::time::Instant::now(),
            })),
            discovery_started: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Atomic adoption snapshot for the frontend: the live adopted map
    /// plus per-subnet metadata views with staleness derived at call
    /// time from the same clocks the reap pass reads.
    pub async fn adoption_snapshot(&self) -> AdoptionSnapshot {
        let (adopted, meta_map) = self.adopted_config_snapshot().await;
        let liveness = self
            .adoption_liveness
            .lock()
            .map(|l| l.clone())
            .unwrap_or_default();
        let session_elapsed = self
            .discovery_started
            .lock()
            .ok()
            .and_then(|s| *s)
            .map(|t| t.elapsed())
            .unwrap_or_default();
        let wall_now = chrono::Utc::now();
        let meta = meta_map
            .keys()
            .map(|subnet| {
                let m = meta_map.get(subnet);
                (
                    subnet.clone(),
                    adoption_meta_view(
                        subnet,
                        m,
                        liveness.get(subnet).map(|t| t.elapsed()),
                        session_elapsed,
                        badge_age(m, wall_now),
                    ),
                )
            })
            .collect();
        AdoptionSnapshot {
            adopted_subnets: adopted,
            meta,
        }
    }

    pub(crate) async fn note_positive_liveness_fenced(
        &self,
        _app: &tauri::AppHandle,
        _ip: Ipv4Addr,
        _fence: &SweepFence,
    ) {
    }

    async fn note_verified_liveness(
        &self,
        app_handle: &tauri::AppHandle,
        ip: Ipv4Addr,
        fence: &SweepFence,
    ) {
        if fence.is_stale() {
            return;
        }
        let now = std::time::Instant::now();
        let wall = chrono::Utc::now().to_rfc3339();
        let landed = {
            let adopted = self.adopted_ips.lock().await;
            if fence.is_stale() {
                return;
            }
            match (self.adoption_liveness.lock(), self.adopted_meta.lock()) {
                (Ok(mut liveness), Ok(mut meta)) => {
                    record_positive_liveness(ip, &adopted, &mut liveness, &mut meta, now, &wall)
                }
                _ => false,
            }
        };
        if !landed {
            return;
        }
        let flush = self
            .meta_flush
            .lock()
            .map(|mut f| meta_dirty_flush_due(&mut f, now))
            .unwrap_or(false);
        if flush {
            self.flush_adoption_state(app_handle).await;
        }
    }

    /// Persist liveness stamps only; late flushes cannot change saved intent.
    pub async fn flush_adoption_state(&self, app_handle: &tauri::AppHandle) {
        let meta = self
            .adopted_meta
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default();
        let handle = app_handle.clone();
        let res = tokio::task::spawn_blocking(move || {
            use tauri::Manager;
            let config: tauri::State<'_, crate::config::AppConfig> = handle.state();
            config.update_adoption_liveness(meta)
        })
        .await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => log::warn!("Failed to persist adoption metadata: {}", e),
            Err(e) => log::warn!("Adoption metadata persist task failed to join: {}", e),
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
        // Host-owned IPs: a cached row at one of our own current addresses
        // is the host itself, not a device (e.g. a self-row captured before
        // live discovery filtered our own traffic). Same fail-open contract.
        let local_ips: HashSet<Ipv4Addr> = interface::all_local_ipv4().into_iter().collect();
        hydrate_retained_history(&self.device_registry, cached, &ghosts, &local_ips);

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

    /// Borrow the device registry. Used by IPC handlers that need to
    /// read snapshots or apply mutations.
    pub(crate) fn sweep_fence(&self) -> SweepFence {
        SweepFence::new(
            self.discovery_generation.load(Ordering::Relaxed),
            self.discovery_generation.clone(),
            self.discovery_active.clone(),
        )
    }

    async fn note_solicitation(&self, work: &SweepFence) {
        let fence = self.sweep_fence();
        if work.is_stale() || fence.is_stale() {
            return;
        }
        if let Some(counters) = current_session_counters(&self.arp_listener_handle).await {
            if !work.is_stale() && !fence.is_stale() {
                self.solicitations.send_replace(Some(Solicitation {
                    generation: fence.generation,
                    at: tokio::time::Instant::now(),
                    baseline: counters.snapshot(),
                }));
            }
        }
    }

    pub fn registry(&self) -> Arc<DeviceRegistry> {
        self.device_registry.clone()
    }

    /// S5a calls this only after fresh selected-adapter verification. Persist
    /// the first manual binding before exposing it as a verified identity.
    #[allow(dead_code)]
    pub(crate) fn merge_manual_verified(
        &self,
        config: &crate::config::AppConfig,
        ip: &str,
        device: &ArpDevice,
        adapter: &str,
        verified_at: &str,
        fence: &SweepFence,
    ) -> Result<device_registry::MergeResult, AppError> {
        if ip != device.ip
            || fence.is_stale()
            || !DeviceRegistry::verification_valid(device, adapter, verified_at)
        {
            return Ok(device_registry::MergeResult::default());
        }
        let mac = device_registry::canonical_mac(&device.mac).expect("validated MAC");
        let node = config.bind_manual_node(ip, &mac, fence)?;
        let mut result =
            self.device_registry
                .merge_manual_verified(&node, device, adapter, verified_at, fence);
        if !fence.is_stale() {
            result.changed |= !self
                .device_registry
                .normalize_role_duplicates(None)
                .is_empty();
        }
        Ok(result)
    }

    /// Create the device-list emitter if not already initialized. Safe
    /// to call multiple times — the first call wins so all subsequent
    /// callers see the same emitter. Decoupled from `start_arp_discovery`
    /// so Static-Manual (which never starts ARP) still has a working
    /// emitter for registry-change events.
    pub async fn init_emitter(&self, app_handle: tauri::AppHandle) -> Arc<DeviceListEmitter> {
        let mut slot = self.device_emitter.lock().await;
        if let Some(existing) = slot.as_ref() {
            return existing.clone();
        }
        let emitter = DeviceListEmitter::new(app_handle, self.device_registry.clone());
        *slot = Some(emitter.clone());
        emitter
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
            self.presence.bootstrap();
            if let Some(emitter) = self.device_emitter.lock().await.clone() {
                emitter.poke();
            }
        }
    }

    /// Warn, fence and drain address work, change OS/config, observe the
    /// resulting state, then resume eligible work with a fresh DHCP cache.
    pub async fn transition_mode(
        &self,
        app: tauri::AppHandle,
        config: &crate::config::AppConfig,
        request: ModeTransition,
    ) -> Result<ModeTransitionReply, AppError> {
        use crate::config::NetworkMode;
        let _op = self.discovery_op.lock().await;
        let iface = self.selected_write_adapter(config, &request.name).await?;
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
        let pause = self.pause_addresses();
        // Every Apply cancels the session/address work. DHCP -> Auto keeps
        // the listener that is already hearing the camera's link-up burst.
        if preserve_capture {
            self.stop_session_locked().await;
        } else {
            self.stop_locked().await;
        }
        let address = self.address_work.lock().await;
        let result = async {
            // Refresh identity after waiting for in-flight scratch cleanup.
            let before = self.operation_snapshot(config).await?;
            if before.selected.alias != request.name
                || adapter_mac(&before.selected.mac) != adapter_mac(&iface.mac)
            {
                return Err(AppError::Network("Selected adapter changed".into()));
            }
            let previous = if request.mode != NetworkMode::Dhcp {
                self.primary_to_replace(config, &before, &request)?
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
                self.finish_primary_change(config, &before, &request, previous)
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
        self.reconcile_temporary_locked(config).await;
        self.reconcile_bindings_locked(config).await;
        let mode = config.get_network_mode();
        self.update_presence_adapter(&self.adapter_selection_state().await, mode);
        self.presence.tick(&self.device_registry);
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
        if mode != NetworkMode::StaticManual && crate::is_discovery_available() {
            if let Err(e) = self
                .start_arp_discovery_body(&iface.name, config, app.clone(), false, preserve_capture)
                .await
            {
                log::warn!("Discovery restart after mode transition: {}", e);
            }
        }
        self.presence.bootstrap();
        self.start_ping_dot(app).await;
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

    pub(crate) async fn start_presence(&self, app: tauri::AppHandle) {
        let mut handle = self.presence_handle.lock().await;
        if handle.is_some() {
            return;
        }
        self.device_registry.set_verification_scope(None);
        let emitter = self.init_emitter(app.clone()).await;
        let control = self.presence.clone();
        let registry = self.device_registry.clone();
        let candidates = self.candidates.clone();
        *handle = Some(tokio::spawn(async move {
            let mut clock = presence::Clock::default();
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
            loop {
                if control.stopped() {
                    break;
                }
                if let Some(selection) = control.observe_link(interface::quick_link_by_mac) {
                    watcher::emit_selection(&app, &selection);
                }
                if control.tick(&registry) {
                    emitter.poke();
                }
                let snapshot = control.snapshot();
                let observations = candidates.snapshot(std::time::Instant::now());
                if let Some(job) = clock.next(&snapshot, &registry.snapshot(), &observations) {
                    let work = run_presence_job(app.clone(), job, snapshot);
                    tokio::pin!(work);
                    loop {
                        tokio::select! {
                            biased;
                            _ = tick.tick() => {
                                if let Some(selection) = control.observe_link(interface::quick_link_by_mac) {
                                    watcher::emit_selection(&app, &selection);
                                }
                                if control.tick(&registry) { emitter.poke(); }
                            }
                            result = &mut work => { if let Some(key) = result { clock.verified(&key); } break; }
                            _ = control.wake.notified() => { if control.tick(&registry) { emitter.poke(); } }
                        }
                    }
                } else {
                    tokio::select! { _ = tick.tick() => {}, _ = control.wake.notified() => {} }
                }
            }
        }));
    }

    pub(crate) fn update_presence_adapter(
        &self,
        selection: &AdapterSelection,
        mode: crate::config::NetworkMode,
    ) {
        self.presence
            .update_native(selection, mode, interface::quick_link_by_mac);
    }

    pub(crate) async fn stop_presence(&self) {
        self.presence.stop();
        self.device_registry.set_verification_scope(None);
        if let Some(mut handle) = self.presence_handle.lock().await.take() {
            if tokio::time::timeout(std::time::Duration::from_secs(5), &mut handle)
                .await
                .is_err()
            {
                handle.abort();
            }
        }
    }

    /// S9 consumes this wake; notifications carry no identity or liveness of their own.
    #[allow(dead_code)]
    pub(crate) async fn expected_device_verified(&self) {
        self.presence.verified.notified().await;
    }

    /// Start the ICMP-based reachability pinger. Mode-independent — the
    /// pinger reads the registry, so it works equally well for ARP-
    /// populated entries (Static-Auto, DHCP) and manual hydrations
    /// (Static-Manual). Safe to call multiple times; replaces any
    /// previously-running pinger.
    pub async fn start_ping_dot(&self, app_handle: tauri::AppHandle) {
        // Take the previous handle out and release the lock BEFORE awaiting
        // its stop — holding the guard across stop().await needlessly
        // serializes start/stop and would self-deadlock if the pinger were
        // ever changed to call back into this handle.
        let prev = self.ping_dot_handle.lock().await.take();
        if let Some(prev) = prev {
            prev.stop().await;
        }
        let handle = ping_dot::start(app_handle, self.device_registry.clone());
        *self.ping_dot_handle.lock().await = Some(handle);
        log::info!("Started ICMP ping-dot loop");
    }

    /// Stop the pinger task and drain. No-op if not running.
    pub async fn stop_ping_dot(&self) {
        // Take the handle out and drop the lock guard before awaiting stop
        // (the edition-2021 `if let` would otherwise keep the guard alive
        // across the await).
        let handle = self.ping_dot_handle.lock().await.take();
        if let Some(handle) = handle {
            handle.stop().await;
            log::info!("Stopped ICMP ping-dot loop");
        }
    }

    /// Borrow the device-list emitter. None before the first call to
    /// `start_arp_discovery` (which initializes it with the AppHandle).
    /// Mutators that want to publish a `device-list-changed` event call
    /// `.poke()` on the result.
    pub async fn emitter(&self) -> Option<Arc<DeviceListEmitter>> {
        self.device_emitter.lock().await.clone()
    }

    /// Reconcile durable intent from actual selected-adapter addresses. Never
    /// prune malformed, unavailable, DHCP, or adapter-mismatched saved rows.
    pub async fn load_adopted_from_config(
        &self,
        config: &crate::config::AppConfig,
        app: &tauri::AppHandle,
    ) {
        let _op = self.discovery_op.lock().await;
        let pause = self.pause_addresses();
        let _address = self.address_work.lock().await;
        self.reconcile_temporary_locked(config).await;
        self.reconcile_bindings_locked(config).await;
        drop(_address);
        drop(pause);
        self.presence.bootstrap();
        use tauri::Emitter;
        let snapshot = self.adoption_snapshot().await;
        for (subnet, ip) in &snapshot.adopted_subnets {
            let meta = &snapshot.meta[subnet];
            let _ = app.emit("subnet-adopted", adoption_event(subnet, ip, meta, true));
        }
    }

    fn address_fence(&self) -> SweepFence {
        SweepFence::new(
            self.address_generation.load(Ordering::Acquire),
            self.address_generation.clone(),
            self.address_active.clone(),
        )
    }

    fn pause_addresses(&self) -> AddressPause {
        AddressPause::new(self.address_generation.clone(), self.address_active.clone())
    }

    async fn publish_binding(
        &self,
        config: &crate::config::AppConfig,
        subnet: &str,
        mut row: crate::config::AdoptedMeta,
    ) -> crate::config::AdoptedMeta {
        if let Err(e) = self.address_io.persist_binding(config, subnet, row.clone()) {
            row.last_error = Some(format!(
                "{}; status save failed: {}",
                row.last_error.as_deref().unwrap_or("OS state observed"),
                e
            ));
        }
        let mut live = self.adopted_ips.lock().await;
        let changed = self
            .adopted_meta
            .lock()
            .map(|meta| meta.get(subnet) != Some(&row))
            .unwrap_or(true);
        if changed {
            log::info!("event=binding_change adapter_mac={} interface_index={} subnet={} address={} desired={:?} applied={} error={} reason={}",
                log_value(row.adapter_mac.as_deref().unwrap_or("unknown")),
                self.adapter_selection.lock().await.interface_index.unwrap_or(0),
                log_value(subnet), log_value(row.address.as_deref().unwrap_or("unknown")),
                row.desired, row.applied, row.last_error.is_some(),
                if row.last_error.is_some() { "pending" } else if row.applied { "applied" } else { "removed" });
        }
        if row.desired == crate::config::BindingDesired::Present
            && row.applied
            && row.last_error.is_none()
        {
            if let Some(ip) = row.address.as_ref().and_then(|a| a.parse().ok()) {
                live.insert(subnet.to_string(), ip);
            }
        } else {
            live.remove(subnet);
        }
        if let Ok(mut meta) = self.adopted_meta.lock() {
            meta.insert(subnet.to_string(), row.clone());
        }
        row
    }

    async fn reconcile_bindings_locked(&self, config: &crate::config::AppConfig) {
        self.reconcile_bindings_traced(config, None).await;
    }

    /// Caller holds address_work. A completed deletion may be superseded by
    /// fresh discovery, but pending removals and unknown native state cannot.
    /// Retire the exact saved row before reserving any new temporary address.
    async fn prepare_subnet_adoption(
        &self,
        config: &crate::config::AppConfig,
        subnet: &str,
        owner: &str,
        index: u32,
        session: &SweepFence,
        address: &SweepFence,
    ) -> Result<(), AppError> {
        let Some(row) = config.get().adopted_meta.get(subnet).cloned() else {
            return Ok(());
        };
        if !row.removal_complete() || session.is_stale() || address.is_stale() {
            return Err(AppError::Network(
                "Saved binding is still pending or present".into(),
            ));
        }
        let snapshot = self.operation_snapshot(config).await?;
        if session.is_stale()
            || address.is_stale()
            || !snapshot.selected.is_up
            || snapshot.selected.dhcp
            || adapter_mac(&snapshot.selected.mac) != adapter_mac(owner)
            || snapshot.selected.index != index
            || row.adapter_mac.as_deref().and_then(adapter_mac) != adapter_mac(owner)
            || !matches!(
                binding_action(
                    subnet,
                    &row,
                    Some(&snapshot.iface),
                    config.get_network_mode(),
                    &Ok(snapshot.selected.dhcp),
                    &[],
                ),
                BindingAction::Observed(false)
            )
        {
            return Err(AppError::Network(
                "Removal absence or selected adapter is unconfirmed".into(),
            ));
        }
        self.address_io
            .forget_completed_removal(config, subnet, &row)?;
        self.adopted_meta
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(subnet);
        self.adopted_ips.lock().await.remove(subnet);
        log::info!("event=adoption_eligible adapter_mac={} interface_index={} subnet={} reason=removal_completed",
            log_value(owner), index, log_value(subnet));
        Ok(())
    }
    async fn reconcile_bindings_traced(
        &self,
        config: &crate::config::AppConfig,
        trace: Option<&AddressTrace>,
    ) {
        let settings = config.get();
        let snapshot = self.operation_snapshot_traced(config, trace).await;
        if let Some(t) = trace {
            t.phase("preflight");
        }
        for (subnet, row) in settings.adopted_meta {
            let context = BindingContext {
                snapshot: &snapshot,
                mode: settings.network_mode,
                trace,
            };
            self.reconcile_binding_row(config, &subnet, row, context, || async {
                let before = snapshot
                    .as_ref()
                    .map_err(|e| AppError::Network(e.to_string()))?;
                Ok(self
                    .observe_operation_traced(before, trace)
                    .await?
                    .selected
                    .ips)
            })
            .await;
        }
    }

    async fn reconcile_binding_row<F, Fut>(
        &self,
        config: &crate::config::AppConfig,
        subnet: &str,
        row: crate::config::AdoptedMeta,
        context: BindingContext<'_>,
        observe: F,
    ) -> crate::config::AdoptedMeta
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<interface::IpInfo>, AppError>>,
    {
        let BindingContext {
            snapshot,
            mode,
            trace,
        } = context;
        if let (Some(t), Ok(snapshot)) = (trace, snapshot) {
            t.identity(snapshot, row.prefix);
        }
        let mut action = match snapshot {
            Ok(snapshot) => binding_action(
                subnet,
                &row,
                Some(&snapshot.iface),
                mode,
                &Ok(snapshot.selected.dhcp),
                &interface::native_conflicts(snapshot, self.address_io.as_ref()),
            ),
            Err(error) => BindingAction::Unavailable(error.to_string()),
        };
        if row.desired == crate::config::BindingDesired::Present
            && config.get().adopted_subnets.get(subnet) != row.address.as_ref()
        {
            action =
                BindingAction::Hold("saved routing address and metadata disagree".into(), false);
        }
        let ops = AddressOps(
            self.address_io.as_ref(),
            snapshot.as_ref().ok().map(|s| &s.selected),
        );
        let iface = snapshot.as_ref().ok().map(|s| &s.iface);
        let row = apply_binding(&ops, row, action, iface, observe).await;
        if let Some(t) = trace {
            t.phase("observation");
        }
        let row = self.publish_binding(config, subnet, row).await;
        if let Some(t) = trace {
            t.phase("status_save");
        }
        row
    }

    /// Routes contain only bindings both desired and last observed applied.
    async fn adopted_config_snapshot(
        &self,
    ) -> (
        HashMap<String, String>,
        HashMap<String, crate::config::AdoptedMeta>,
    ) {
        let live = self.adopted_ips.lock().await;
        let meta = self.adopted_meta.lock().unwrap_or_else(|e| e.into_inner());
        (merge_adopted_config(&live, &meta), meta.clone())
    }

    pub async fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>, AppError> {
        let list = interface::list_physical().await?;
        // Scratch/pending addresses are transient probe state, not host
        // addresses — the UI must never render them as host rows, and
        // their bind/release must not read as an IP change.
        Ok(strip_pending_ips(list, &self.pending_ip_strings().await))
    }

    pub async fn adapter_selection_state(&self) -> AdapterSelection {
        self.adapter_selection.lock().await.clone()
    }

    async fn native_interfaces(
        &self,
        selected_mac: Option<&str>,
    ) -> Result<(Vec<interface::NativeAdapter>, Vec<InterfaceInfo>), AppError> {
        let Some(mac) = selected_mac else {
            let views = self.list_interfaces().await?;
            return Ok((
                interface::read_native_with(self.address_io.as_ref()).await?,
                views,
            ));
        };
        let mut all = interface::read_native_with(self.address_io.as_ref()).await?;
        if let Ok(selected) = interface::select_native(&all, mac) {
            if self.address_io.descriptor(selected).is_none() {
                let before = selected.identity();
                self.address_io.qualify().await?;
                all = interface::read_native_with(self.address_io.as_ref()).await?;
                if interface::select_native(&all, mac)?.identity() != before {
                    return Err(AppError::Network(
                        "Adapter changed during qualification".into(),
                    ));
                }
            }
        }
        let mut views: Vec<_> = all
            .iter()
            .filter_map(|n| self.address_io.descriptor(n))
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
            let _pause = self.pause_addresses();
            let _address = self.address_work.lock().await;
            self.reconcile_temporary_locked(config).await;
            self.reconcile_bindings_locked(config).await;
            self.presence.bootstrap();
        }
        Ok(selection)
    }

    async fn resolve_adapter_locked(
        &self,
        config: &crate::config::AppConfig,
        list: &[InterfaceInfo],
    ) -> Result<AdapterSelection, AppError> {
        let mut mac = config.get().selected_adapter_mac;
        let adapter = pick_adapter(list, mac.as_deref()).cloned();
        if mac.is_none() {
            if let Some(iface) = &adapter {
                mac = adapter_mac(&iface.mac);
                config.set_selected_adapter_mac(mac.clone().unwrap())?;
            }
        }
        let index = adapter
            .as_ref()
            .and_then(|i| interface::index_for_mac(&i.mac));
        let previous = self.adapter_selection_state().await;
        let pending_selection = AdapterSelection {
            selected_mac: mac.clone(),
            adapter: adapter.clone(),
            interface_index: index,
            ..Default::default()
        };
        self.update_presence_adapter(&pending_selection, config.get_network_mode());
        self.presence.tick(&self.device_registry);
        if previous.selected_mac != mac || previous.interface_index != index {
            if let Some(identity) = self.capture_identity.lock().await.as_ref() {
                identity.active.store(false, Ordering::Release);
            }
            self.stop_locked().await;
            // Retire routes from the live map without losing saved bindings.
            self.adopted_ips.lock().await.clear();
            if let Ok(mut meta) = self.adopted_meta.lock() {
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
        let candidates: Vec<_> = list
            .iter()
            .filter(|i| adapter_candidate(i))
            .cloned()
            .collect();
        if previous.selected_mac != mac || previous.interface_index != index {
            log::info!(
                "event=adapter_selection adapter_mac={} interface_index={} available={}",
                log_value(mac.as_deref().unwrap_or("unknown")),
                index.unwrap_or(0),
                adapter.is_some()
            );
        }
        let selection = AdapterSelection {
            selection_required: mac.is_none() && candidates.len() > 1,
            selected_mac: mac,
            adapter,
            interface_index: index,
            candidates,
        };
        *self.interface_name.lock().await = selection
            .adapter
            .as_ref()
            .filter(|_| index.is_some())
            .map(|i| i.name.clone());
        *self.interface_index.lock().await = index;
        *self.adapter_selection.lock().await = selection.clone();
        Ok(selection)
    }

    pub async fn select_adapter(
        &self,
        config: &crate::config::AppConfig,
        app: &tauri::AppHandle,
        mac: &str,
    ) -> Result<AdapterSelection, AppError> {
        {
            let _op = self.discovery_op.lock().await;
            let list = self.list_interfaces().await?;
            let iface = pick_adapter(&list, Some(mac)).ok_or_else(|| {
                AppError::Network("Selected Ethernet adapter is unavailable or ineligible".into())
            })?;
            config.set_selected_adapter_mac(adapter_mac(&iface.mac).unwrap())?;
            self.resolve_adapter_locked(config, &list).await?;
        }
        self.start_selected_adapter(config, app).await;
        self.get_adapter_selection(config).await
    }

    pub async fn start_selected_adapter(
        &self,
        config: &crate::config::AppConfig,
        app: &tauri::AppHandle,
    ) {
        self.load_adopted_from_config(config, app).await;
        let selection = self.adapter_selection_state().await;
        if config.get_network_mode() != crate::config::NetworkMode::StaticManual
            && crate::is_discovery_available()
        {
            if let Some(iface) = selection.adapter {
                if let Err(e) = self
                    .start_arp_discovery(&iface.name, config, app.clone())
                    .await
                {
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
        app: &tauri::AppHandle,
    ) -> Result<bool, AppError> {
        let Ok(_op) = self.discovery_op.try_lock() else {
            return Ok(false); // a start, stop or mode transition already owns it
        };
        let settings = config.get();
        if settings.network_mode == crate::config::NetworkMode::StaticManual
            || !crate::is_discovery_available()
            || self.presence.stopped()
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
            self.discovery_active.load(Ordering::Acquire),
            settings.selected_adapter_mac.as_deref(),
            &selection,
            native,
            self.capture_signal.lock().await.state.active,
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
                watcher::emit_selection(app, &selection);
                let result = self
                    .start_selected_discovery_locked(selection, config, app.clone(), false, true)
                    .await;
                if let Err(error) = result {
                    if up || !self.capture_signal.lock().await.state.active {
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

    /// String forms of every pending (scratch or not-yet-handed-over)
    /// address, for filtering UI-facing interface enumerations.
    pub(crate) async fn pending_ip_strings(&self) -> HashSet<String> {
        self.pending_ips
            .lock()
            .await
            .iter()
            .map(|e| e.ip.to_string())
            .collect()
    }

    pub async fn get_interface(&self, name: &str) -> Result<InterfaceInfo, AppError> {
        interface::get_by_name(name).await
    }

    /// Current selected-adapter addresses from IP Helper, never the saved map.
    fn probe_scope(&self) -> Option<(InterfaceInfo, u32, SweepFence)> {
        let snapshot = self.presence.snapshot();
        let mut adapter = snapshot.adapter?;
        if snapshot.fence.is_stale() || interface::index_for_mac(&adapter.mac)? != snapshot.index {
            return None;
        }
        let (up, ips) = interface::quick_status_by_mac(&adapter.mac)?;
        if !up {
            return None;
        }
        adapter.ips = ips;
        let pending = self.pending_ips.try_lock().ok()?;
        adapter
            .ips
            .retain(|ip| !pending.iter().any(|p| p.ip.to_string() == ip.address));
        Some((adapter, snapshot.index, snapshot.fence))
    }

    pub(crate) async fn camera_ready(
        &self,
        target: &route::CameraTarget,
        config: &crate::config::AppConfig,
    ) -> Result<route::ReadyPath, AppError> {
        self.camera_ready_now(target, config)
    }

    /// Native/in-memory checks only; callable on the relay's GLib threads.
    pub(crate) fn camera_ready_now(
        &self,
        target: &route::CameraTarget,
        config: &crate::config::AppConfig,
    ) -> Result<route::ReadyPath, AppError> {
        if self.presence.tick(&self.device_registry) {
            if let Ok(emitter) = self.device_emitter.try_lock() {
                if let Some(emitter) = emitter.as_ref() {
                    emitter.poke();
                }
            } else {
                let slot = self.device_emitter.clone();
                tauri::async_runtime::spawn(async move {
                    if let Some(emitter) = slot.lock().await.as_ref() {
                        emitter.poke();
                    }
                });
            }
        }
        let mut target = target.clone();
        // A legacy manual key follows only its persisted first-verification
        // binding. An IP match is never a substitute for an expected MAC.
        if target.key.starts_with("manual:") {
            let node = config.get_manual_nodes().into_iter().find(|n| {
                crate::config::manual_node_key(n) == target.key
                    || format!("manual:{}", n.ip) == target.key
            });
            if let Some(expected) = node.and_then(|n| n.expected_mac) {
                if target
                    .expected_mac
                    .as_ref()
                    .is_some_and(|m| !m.eq_ignore_ascii_case(&expected))
                {
                    return Err(AppError::Network("Manual expected identity changed".into()));
                }
                target.key = expected.clone();
                target.expected_mac = Some(expected);
            }
        }
        let (adapter, index, fence) = self
            .probe_scope()
            .ok_or_else(|| AppError::Network("Selected Ethernet adapter unavailable".into()))?;
        let ip = crate::validation::parse_camera_ip(&target.ip)?;
        let source = route::check_ready(
            &target,
            Some(&adapter),
            index,
            &self.device_registry.snapshot(),
            route::egress_index(ip).ok(),
        )?;
        #[cfg(windows)]
        if !interface::source_matches_interface(index, source) {
            return Err(AppError::Network(
                "Ethernet source address is absent or ambiguous".into(),
            ));
        }
        if fence.is_stale() {
            return Err(AppError::Network("Ethernet adapter changed".into()));
        }
        Ok(route::ReadyPath {
            target,
            source,
            index,
            fence,
        })
    }

    pub async fn scan_subnet(
        &self,
        subnet: &str,
        config: &crate::config::AppConfig,
    ) -> Result<Vec<ScanResult>, AppError> {
        // RAII guard: the subnet is removed from the active set on drop —
        // normal return OR a cancelled future — so a cancellation at the
        // scan await below can't wedge the subnet as "scan in progress"
        // forever. Insert + guard creation happen under one lock.
        let _guard = {
            let mut active = self.active_scans.lock().unwrap_or_else(|p| p.into_inner());
            if !active.insert(subnet.to_string()) {
                return Err(AppError::Network(format!(
                    "Scan already in progress for {}",
                    subnet
                )));
            }
            ScanGuard {
                active: self.active_scans.clone(),
                subnet: subnet.to_string(),
            }
        };
        if config.get_network_mode() == crate::config::NetworkMode::StaticManual {
            return Err(AppError::Network(
                "Port scanning is disabled in Static-Manual".into(),
            ));
        }
        let (adapter, index, fence) = self
            .probe_scope()
            .ok_or_else(|| AppError::Network("Selected Ethernet adapter unavailable".into()))?;
        self.device_registry
            .expire_evidence(tokio::time::Instant::now());
        let identities = self
            .device_registry
            .snapshot()
            .into_iter()
            .filter(|r| {
                r.status == DeviceStatus::Live
                    && r.verified_by_mac
                        .as_ref()
                        .is_some_and(|m| m.eq_ignore_ascii_case(&adapter.mac))
            })
            .filter_map(|r| r.ip.parse().ok().map(|ip| (ip, r.mac)))
            .collect();
        let discovery = self.sweep_fence();
        if discovery.is_stale() {
            return Err(AppError::Network("Discovery session unavailable".into()));
        }
        let scope = scanner::ScanScope {
            index,
            fence: Some(fence.clone()),
            session: Some(discovery.clone()),
            ips: adapter.ips,
            identities,
        };
        let results = scanner::scan(subnet, scope).await?;
        if fence.is_stale() || discovery.is_stale() {
            arp::note_fence_drop("scan_results");
            return Ok(Vec::new());
        }
        let mut accepted = Vec::new();
        for result in results {
            let Some(key) = result.key.as_ref() else {
                continue;
            };
            let target = route::CameraTarget {
                key: key.clone(),
                expected_mac: Some(key.clone()),
                ip: result.ip.clone(),
            };
            let Ok(path) = self.camera_ready(&target, config).await else {
                continue;
            };
            if fence.is_stale()
                || discovery.is_stale()
                || path.index != result.interface_index
                || Some(path.source.to_string()) != result.source
            {
                continue;
            }
            if self
                .device_registry
                .merge_scan_result_fenced(key, &result.open_ports, Some(&fence))
            {
                if let Some(row) = self.device_registry.cache_record(key) {
                    config.upsert_cached_device_fenced(row, Some(&fence))?;
                }
                if let Some(emitter) = self.emitter().await {
                    emitter.poke();
                }
            }
            accepted.push(result);
        }
        Ok(accepted)
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
        app_handle: tauri::AppHandle,
    ) -> Result<(), AppError> {
        let _op = self.discovery_op.lock().await;
        self.start_arp_discovery_locked(interface_display_name, config, app_handle)
            .await
    }

    pub async fn refresh_arp_discovery(
        &self,
        interface: &str,
        config: &crate::config::AppConfig,
        app: tauri::AppHandle,
    ) -> Result<(), AppError> {
        let _op = self.discovery_op.lock().await;
        self.start_arp_discovery_body(interface, config, app, true, false)
            .await
    }

    /// Attach, keep, or replace the persistent capture listener so it
    /// matches the requested adapter. Runs under `discovery_op` (every
    /// caller holds it). Returns an already-resolved activation channel
    /// for the watchdog: on attach/replace this method awaited the real
    /// activation itself; on keep the retained listener proved
    /// activation when it originally attached.
    async fn ensure_capture_listener(
        &self,
        iface_name: &str,
        own_mac: Option<[u8; 6]>,
        iface_is_up: bool,
        base_params: &arp::ListenerParams,
        preserve_capture: bool,
    ) -> Result<arp::ActivationRx, AppError> {
        let has_listener = self.arp_listener_handle.lock().await.is_some();
        let same_adapter = {
            let identity = self.capture_identity.lock().await;
            identity
                .as_ref()
                .is_some_and(|c| c.iface_name == iface_name && c.mac == own_mac)
        };
        // Probe the live data-source id only when a matching listener
        // could be kept — its sole job is catching the source being
        // re-created underneath a retained binding (id churn after
        // driver-level adapter events).
        let live = if has_listener && same_adapter {
            let scope = base_params.scope.clone();
            match tokio::task::spawn_blocking(move || pktmon::live_source_id_for(&scope)).await {
                Ok(Ok(id)) => LiveSourceId::Enumerated(id),
                Ok(Err(e)) => {
                    log::debug!(
                        "Data-source liveness probe failed ({}) — keeping the listener",
                        e
                    );
                    LiveSourceId::EnumFailed
                }
                Err(e) => {
                    log::debug!(
                        "Data-source liveness probe did not complete ({}) — keeping the listener",
                        e
                    );
                    LiveSourceId::EnumFailed
                }
            }
        } else {
            LiveSourceId::EnumFailed
        };
        let action = {
            let identity = self.capture_identity.lock().await;
            mode_capture_action(
                listener_action(identity.as_ref(), has_listener, iface_name, own_mac, live),
                preserve_capture,
            )
        };

        let retained_outcome = self.capture_signal.lock().await.state.outcome.clone();
        if let (ListenerAction::Keep, Some(outcome)) = (action, retained_outcome) {
            log::info!("ARP capture retained across discovery restart");
            let (tx, rx) = tokio::sync::oneshot::channel();
            // The watchdog only cares that activation succeeded; the
            // retained session proved that when it attached.
            let _ = tx.send(Ok(outcome));
            return Ok(rx);
        }
        if let ListenerAction::Replace(reason) = action {
            log::info!("ARP capture replaced ({})", reason);
        }

        // Retire the old incarnation before tearing it down: with the
        // flag already false, even a wedged capture thread can never
        // merge again once the replacement attaches.
        if let Some(old) = self.capture_identity.lock().await.take() {
            old.active.store(false, Ordering::Relaxed);
        }
        self.capture_signal.lock().await.deactivate();
        self.candidates.clear();
        park_capture_handle(&self.arp_listener_handle, &self.prior_capture_joins).await;

        let incarnation = Arc::new(AtomicBool::new(true));
        let lifecycle_fence = SweepFence::new(0, Arc::new(AtomicU64::new(0)), incarnation.clone());
        let (handle, activation_rx) = arp::start_listener(
            base_params.with_fence(lifecycle_fence),
            pktmon::CaptureMode::PreferScoped,
            &self.prior_capture_joins,
        )
        .await?;
        *self.arp_listener_handle.lock().await = Some(handle);

        // Confirm activation here rather than leaving it to the
        // watchdog: the recorded identity must describe a live binding,
        // and an unconfirmed session is parked exactly as the watchdog's
        // activation-timeout arm parks one. The incarnation flag goes
        // false on every failure path so a late-activating stray can
        // never merge.
        let outcome =
            match tokio::time::timeout(arp::CAPTURE_ACTIVATION_TIMEOUT, activation_rx).await {
                Ok(Ok(Ok(outcome))) => outcome,
                Ok(Ok(Err(start_error))) => {
                    incarnation.store(false, Ordering::Relaxed);
                    park_capture_handle(&self.arp_listener_handle, &self.prior_capture_joins).await;
                    return Err(AppError::Network(format!(
                        "ARP capture session failed to start: {}",
                        start_error
                    )));
                }
                Ok(Err(_channel_closed)) => {
                    incarnation.store(false, Ordering::Relaxed);
                    park_capture_handle(&self.arp_listener_handle, &self.prior_capture_joins).await;
                    return Err(AppError::Network(
                        "ARP capture thread died before confirming activation".into(),
                    ));
                }
                Err(_elapsed) => {
                    incarnation.store(false, Ordering::Relaxed);
                    park_capture_handle(&self.arp_listener_handle, &self.prior_capture_joins).await;
                    return Err(AppError::Network(
                        "ARP capture session did not confirm activation in time".into(),
                    ));
                }
            };

        if !iface_is_up {
            if !matches!(outcome, pktmon::ScopeOutcome::SelectedInterface { .. }) {
                // A media-disconnected attach must be scoped-only: an
                // unscoped session hears every adapter, and with the
                // wire down nothing refreshes the shared self/ghost
                // filters — WiFi-side ARP could leak in as phantom
                // nodes. Park it and wait for the next trigger.
                incarnation.store(false, Ordering::Relaxed);
                park_capture_handle(&self.arp_listener_handle, &self.prior_capture_joins).await;
                log::info!(
                    "ARP pre-attach skipped: MAC-scoped join unavailable ({:?}) — retrying on the next discovery trigger",
                    outcome
                );
                let (tx, rx) = tokio::sync::oneshot::channel();
                let _ = tx.send(Ok(outcome));
                return Ok(rx);
            }
            log::info!(
                "ARP capture pre-attached on '{}' — listening before link-up",
                iface_name
            );
        }

        let source_id = outcome.source_id();
        *self.capture_identity.lock().await = Some(CaptureIdentity {
            iface_name: iface_name.to_string(),
            mac: own_mac,
            source_id,
            active: incarnation,
        });
        self.capture_signal
            .lock()
            .await
            .activate(base_params, outcome.clone());

        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = tx.send(Ok(outcome));
        Ok(rx)
    }

    /// Start body, run with the discovery op lock already held. Callers
    /// that already hold it (`apply_mode_change`) delegate here so the
    /// non-reentrant lock isn't acquired twice.
    async fn start_arp_discovery_locked(
        &self,
        interface_display_name: &str,
        config: &crate::config::AppConfig,
        app_handle: tauri::AppHandle,
    ) -> Result<(), AppError> {
        self.start_arp_discovery_body(interface_display_name, config, app_handle, false, false)
            .await
    }

    async fn start_arp_discovery_body(
        &self,
        interface_display_name: &str,
        config: &crate::config::AppConfig,
        app_handle: tauri::AppHandle,
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

        self.start_selected_discovery_locked(
            selection,
            config,
            app_handle,
            refresh,
            preserve_capture,
        )
        .await
    }

    /// Caller holds discovery_op and has resolved the selected MAC/index.
    /// Readiness retries use native addresses with validated cached metadata,
    /// rather than repeating the slow provider query after a link-up burst.
    async fn start_selected_discovery_locked(
        &self,
        selection: AdapterSelection,
        config: &crate::config::AppConfig,
        app_handle: tauri::AppHandle,
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
        *self.interface_index.lock().await = Some(interface_index);
        // Capture identity for attach-time scoping: the same MAC that
        // feeds the own-frame filter, plus the display name for logs. A
        // None MAC (unparseable) makes the join fail and the capture
        // fall back to an unscoped session rather than guessing.
        let capture_scope = pktmon::CaptureScope {
            mac: own_mac,
            display_name: interface_display_name.to_string(),
            description: iface_info.description.clone(),
        };

        // Every IPv4 currently assigned to any local adapter — not just the
        // camera port. The capture listener drops ARP sent from any of
        // these so the host never lists itself as a node (its own WiFi
        // traffic on a subnet shared with the wired port passes every other
        // filter). Manager-owned: every start refreshes the same shared
        // set (and the adopt loop refreshes it each pass), so a listener
        // retained across sessions keeps an accurate self-filter.
        if let Ok(mut set) = self.local_ips.lock() {
            *set = interface::all_local_ipv4().into_iter().collect();
        }
        let local_ips = self.local_ips.clone();

        // Activated discovery uses scope proof or fresh selected-interface
        // resolution, never subnet exclusion as an identity boundary. This
        // also avoids a second slow provider query before capture can listen.
        if let Ok(mut shared) = self.excluded_subnets.lock() {
            shared.clear();
        }

        let registry = self.device_registry.clone();

        // Late-bind the emitter now that we have an AppHandle. Reuse the
        // existing one if `init_emitter` already wired it at startup — two
        // live emitters poking the same registry would double every
        // device-list-changed event. Only create + store when the slot is
        // empty (the app handle is the same across interface switches).
        let emitter = {
            let mut slot = self.device_emitter.lock().await;
            match slot.as_ref() {
                Some(existing) => existing.clone(),
                None => {
                    let e = DeviceListEmitter::new(app_handle.clone(), registry.clone());
                    *slot = Some(e.clone());
                    e
                }
            }
        };
        // Emit the initial snapshot so any frontend that's already
        // subscribed sees cache-hydrated devices without having to
        // separately call get_device_list.
        emitter.poke();

        let devices = self.arp_devices.clone();
        // Placeholder fence for the shared bundle: the listener swaps in
        // its capture-lifecycle fence inside `ensure_capture_listener`,
        // and the session halves below rebind the bundle with the real
        // session fence once the up-gate passes — this value itself
        // never fences a merge.
        let placeholder_fence = SweepFence::new(
            self.discovery_generation.load(Ordering::Relaxed),
            self.discovery_generation.clone(),
            self.discovery_active.clone(),
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
            app_handle: app_handle.clone(),
            local_ips: local_ips.clone(),
            own_mac,
            fence: placeholder_fence,
            excluded_subnets: self.excluded_subnets.clone(),
            scope: capture_scope,
        };
        // Attach, keep, or replace the persistent listener. The listener
        // runs under the capture-lifecycle fence that
        // `ensure_capture_listener` builds per incarnation.
        let activation_rx = self
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

        // New discovery session: advance the generation and mark discovery
        // active so sweeps and capture frames from a prior session can
        // fence themselves out (that work captures the generation; the
        // active flag also covers a stop with no restart). Deliberately
        // after the up-gate — a pre-attach-only start must not burn a
        // generation or leave the active flag set with no session.
        let generation = self.discovery_generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.discovery_active.store(true, Ordering::Relaxed);
        log::debug!("Discovery session generation → {}", generation);

        // Session fence for sweeps and the adopt loop: stale-session work
        // (from a prior session, or after a stop) drops itself before
        // merging or emitting into the shared registry. The capture
        // listener does NOT use this fence — a retained listener must
        // keep merging across session restarts.
        let fence = SweepFence::new(
            generation,
            self.discovery_generation.clone(),
            self.discovery_active.clone(),
        );
        // Rebind the shared bundle onto the session fence for every
        // consumer below (sweeps, watchdog).
        let listener_params = listener_params.with_fence(fence.clone());

        *self.interface_name.lock().await = Some(interface_display_name.to_string());
        log::info!(
            "Starting ARP discovery on '{}' (IPs: {:?}, mac: {})",
            interface_display_name,
            known_ips,
            iface_info.mac
        );

        let adopted = self.adopted_ips.clone();
        let pending_ips = self.pending_ips.clone();
        let adoption_seq = self.adoption_seq.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let iface_name = interface_display_name.to_string();
        let app_handle_for_adopt = app_handle.clone();

        // Startup sweeps only native /24s. Explicit Refresh also includes
        // actually bound adopted /24s, through the same session fence.
        let sweep_params = listener_params.clone();
        let solicitations = self.solicitations.subscribe();
        tokio::spawn(async move {
            // Give a freshly attached capture time to start.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            provoke_sweep(&sweep_params, &sweep_ips).await;
        });

        // Capture-health watchdog. The ping sweep above provokes ARP; if
        // the session delivers no payload within the window, the watchdog
        // restarts the capture (bounded ladder) before degrading loudly.
        // It never flips availability, and emits at most one degraded per
        // session, cleared by a recovered on the first frame.
        let (watchdog_shutdown, watchdog_shutdown_rx) = tokio::sync::watch::channel(false);
        let watchdog = tokio::spawn(watchdog_ladder(
            listener_params.clone(),
            native_sweep_ips,
            self.arp_listener_handle.clone(),
            self.prior_capture_joins.clone(),
            self.capture_identity.clone(),
            (activation_rx, solicitations),
            watchdog_shutdown_rx,
        ));
        *self.discovery_watchdog_handle.lock().await = Some(WatchdogHandle {
            shutdown: watchdog_shutdown,
            join: watchdog,
        });

        // Auto-adopt handler for foreign subnets
        let address_work_for_adopt = self.address_work.clone();
        let candidates_for_adopt = listener_params.candidates.clone();
        let devices_for_adopt = devices.clone();
        let registry_for_adopt = registry.clone();
        let emitter_for_adopt = emitter.clone();
        let fence_for_loop = fence.clone();
        let binding_mac = config.get().selected_adapter_mac.unwrap_or_default();
        let address_generation = self.address_generation.clone();
        let address_active = self.address_active.clone();
        let liveness_for_adopt = self.adoption_liveness.clone();
        let meta_for_adopt = self.adopted_meta.clone();
        // One session-start instant shared by the loop's reap pass and
        // the adoption snapshot's staleness derivation. Anchors the
        // startup grace; restarts with discovery, so an interface
        // bounce re-arms it.
        let session_started = std::time::Instant::now();
        if let Ok(mut started) = self.discovery_started.lock() {
            *started = Some(session_started);
        }
        let adopt_handle = tokio::spawn(async move {
            use tauri::Emitter;
            use tauri::Manager;
            let mut shutdown_rx = shutdown_rx;
            // The shared adoption tail's context — one bundle of the
            // clones this task already owns, used by both the broadcast
            // path below and the cache probe.
            let mut ctx = AdoptionCtx {
                iface_name: iface_name.clone(),
                adapter_mac: binding_mac,
                interface_index,
                candidates: candidates_for_adopt,
                app_handle: app_handle_for_adopt.clone(),
                adopted: adopted.clone(),
                pending_ips: pending_ips.clone(),
                adoption_seq: adoption_seq.clone(),
                liveness: liveness_for_adopt.clone(),
                meta: meta_for_adopt.clone(),
                devices: devices_for_adopt.clone(),
                registry: registry_for_adopt.clone(),
                emitter: emitter_for_adopt.clone(),
                fence: fence_for_loop.clone(),
                address_fence: SweepFence::new(
                    address_generation.load(Ordering::Acquire),
                    address_generation.clone(),
                    address_active.clone(),
                ),
                local_ips: local_ips.clone(),
            };
            // Cached-device probe: at most one pass per discovery
            // session, deferred (not consumed) while the DHCP gate is
            // closed. Identity misses land in the attempted set, never
            // in the shared cooldowns.
            let mut cache_probe_done = false;
            let mut cache_probe_attempted: HashSet<String> = HashSet::new();
            let mut known_subnets: HashSet<String> = HashSet::new();
            // Two-observation gate: a subnet is adopted only after its
            // triggering device produces a second accepted ARP frame, so
            // a single spurious frame (which sits in the persistent
            // device map forever) can no longer bind a secondary IP.
            let mut dwell = auto_adopt::DwellTracker::new();
            // Mark subnets we already have IPs on as known
            for ip_str in &known_ips {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    let o = ip.octets();
                    known_subnets.insert(format!("{}.{}.{}.0/24", o[0], o[1], o[2]));
                }
            }

            // DHCP-state cache: re-reading via PowerShell on every iteration
            // would spam Get-NetIPInterface every 2s. Cache for 5s — short
            // enough that a user toggling Static via the dialog sees adoption
            // resume promptly.
            let mut cached_dhcp_state: Option<(bool, std::time::Instant)> = None;
            let mut last_dhcp_pause = None;
            const DHCP_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);

            // Failed-adoption backoff (module-level COOLDOWN_* constants).
            // Successful/already-adopted subnets use known_subnets
            // (permanent) as before.
            let mut cooldowns: HashMap<String, (std::time::Instant, std::time::Duration)> =
                HashMap::new();

            // Structural-ghost guard state. `ghost_until` is a short-lived
            // per-subnet ignore set: a ghost row can sit in `arp_devices`
            // forever (entries never expire), so re-check it at most once per
            // GHOST_SUBNET_RECHECK instead of every 2 s tick. Being TTL'd —
            // unlike the permanent `known_subnets` — a subnet becomes
            // adoptable again within one recheck once its WiFi/VPN/virtual
            // owner goes away. `cached_ghosts` memoizes the enumerated
            // non-wired network list so a surviving candidate doesn't spawn a
            // PowerShell adapter query every pass.
            let mut ghost_until: HashMap<String, std::time::Instant> = HashMap::new();
            let mut cached_ghosts: Option<(Vec<ipnetwork::Ipv4Network>, std::time::Instant)> = None;
            const GHOST_SUBNET_RECHECK: std::time::Duration = std::time::Duration::from_secs(300);
            const GHOST_NETS_TTL: std::time::Duration = std::time::Duration::from_secs(30);

            loop {
                // Shutdown-aware idle: wake on the 2 s tick or the moment a
                // stop is signalled, and exit promptly either way.
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                    res = shutdown_rx.changed() => {
                        if res.is_err() {
                            break;
                        }
                    }
                }
                if *shutdown_rx.borrow() {
                    break;
                }
                let next_address_fence = SweepFence::new(
                    address_generation.load(Ordering::Acquire),
                    address_generation.clone(),
                    address_active.clone(),
                );
                let _address = address_work_for_adopt.lock().await;
                if next_address_fence.is_stale() {
                    continue;
                }
                if ctx.fence.is_stale() || *shutdown_rx.borrow() {
                    break;
                }
                if ctx.address_fence.generation != next_address_fence.generation {
                    // A manual add/remove can invalidate permanent session
                    // knowledge without restarting capture or discovery.
                    known_subnets.clear();
                    dwell = auto_adopt::DwellTracker::new();
                    cache_probe_done = false;
                    cache_probe_attempted.clear();
                    cached_dhcp_state = None;
                }
                ctx.address_fence = next_address_fence;

                // Refresh the local-IP set the capture listener filters
                // against: addresses move under us (DHCP renew, WiFi roam)
                // and a stale set would re-admit the host as a peer. Runs
                // before the DHCP gate below so the set stays fresh even
                // while adoption is paused. In-memory IP Helper read — no
                // process spawn, so no TTL cache is needed. An empty read
                // (transient enumeration failure) keeps the previous set
                // rather than blanking the filter mid-session.
                let fresh: HashSet<Ipv4Addr> = interface::all_local_ipv4().into_iter().collect();
                if !fresh.is_empty() {
                    if let Ok(mut set) = local_ips.lock() {
                        *set = fresh;
                    }
                }

                // Committed bindings, including APIPA, live until explicit deletion.
                // Only PendingIps scratch/uncommitted entries are cleanup candidates.

                // DHCP never adds an address, including in APIPA-only state.
                // Failed DHCP-state reads pause all address changes.
                let needs_refresh = cached_dhcp_state
                    .map(|(_, t)| t.elapsed() > DHCP_CACHE_TTL)
                    .unwrap_or(true);
                let is_dhcp = if needs_refresh {
                    match ip_config::get_dhcp_state(&iface_name).await {
                        Ok(d) => {
                            cached_dhcp_state = Some((d, std::time::Instant::now()));
                            d
                        }
                        Err(e) => {
                            log::debug!(
                                "DHCP-state probe failed for {} ({}), pausing adoption",
                                iface_name,
                                e
                            );
                            // Cache the fail-open verdict with the same TTL
                            // as a success — otherwise a persistent probe
                            // failure re-spawns PowerShell every 2s instead
                            // of every 5s.
                            cached_dhcp_state = Some((true, std::time::Instant::now()));
                            true
                        }
                    }
                } else {
                    cached_dhcp_state.map(|(d, _)| d).unwrap_or(true)
                };

                let current_ips = if is_dhcp {
                    get_interface_ips(&iface_name).await
                } else {
                    Vec::new()
                };
                let pause = dhcp_adoption_pause(is_dhcp, &current_ips);
                if let Some(reason) = pause {
                    if pause != last_dhcp_pause
                        && current_ips
                            .iter()
                            .all(|ip| crate::validation::prohibited_camera_ip(*ip))
                    {
                        let reason = format!("{reason} on {iface_name}");
                        log::warn!("Discovery degraded: {reason}");
                        let _ = app_handle_for_adopt.emit(
                            "discovery-degraded",
                            serde_json::json!({
                                "reason": reason,
                                "missed_packets": 0,
                            }),
                        );
                    }
                    last_dhcp_pause = pause;
                    continue;
                }
                last_dhcp_pause = None;

                // Cached-device on-link probe: runs on the first tick the
                // DHCP gate allows adoption at all (the `continue` above
                // keeps it pending, so a DHCP→Static transition still
                // gets its pass). Rediscovers quiet known devices in
                // seconds instead of waiting for their spontaneous
                // broadcast ARP, which can be minutes apart on a quiet camera.
                if !cache_probe_done {
                    cache_probe_done = true;
                    let cached_records = {
                        let config: tauri::State<'_, crate::config::AppConfig> =
                            app_handle_for_adopt.state();
                        config.get_cache()
                    };
                    if !cached_records.is_empty() {
                        let native_subnets: HashSet<String> = get_interface_ips(&iface_name)
                            .await
                            .iter()
                            .map(|ip| {
                                let o = ip.octets();
                                format!("{}.{}.{}.0/24", o[0], o[1], o[2])
                            })
                            .collect();
                        let adopted_keys: HashSet<String> =
                            adopted.lock().await.keys().cloned().collect();
                        let pending_keys: HashSet<String> = meta_for_adopt
                            .lock()
                            .map(|m| {
                                m.iter()
                                    .filter(|(_, row)| !row.removal_complete())
                                    .map(|(subnet, _)| subnet.clone())
                                    .collect()
                            })
                            .unwrap_or_default();
                        let ghost_nets = ghost::non_wired_interface_networks().await;
                        cached_ghosts = Some((ghost_nets.clone(), std::time::Instant::now()));
                        let candidates = cache_probe::derive_candidates(
                            &cached_records,
                            &native_subnets,
                            &adopted_keys,
                            &pending_keys,
                            &ghost_nets,
                            &cache_probe_attempted,
                        );
                        if !candidates.is_empty() {
                            log::info!(
                                "Cache probe: verifying {} candidate subnet(s) from the device cache",
                                candidates.len()
                            );
                            let mut io = RealProbeIo {
                                ctx: &ctx,
                                cooldowns: &mut cooldowns,
                                known_subnets: &mut known_subnets,
                                shutdown_rx: &shutdown_rx,
                                scratch_id: None,
                                stop: false,
                                origin: ProbeOrigin::CacheProbe,
                            };
                            let report = cache_probe::run_pass(
                                &mut io,
                                candidates,
                                cache_probe::CACHE_PROBE_PASS_BUDGET,
                            )
                            .await;
                            let stop = io.stop;
                            log::info!(
                                "Cache probe pass finished: attempted={:?}, adopted={:?}",
                                report.attempted,
                                report.handed_off
                            );
                            cache_probe_attempted.extend(report.attempted);
                            if !report.skipped_at_budget.is_empty() {
                                log::warn!(
                                    "Cache probe hit its {}s budget — skipped subnets (their broadcast path still applies): {:?}",
                                    cache_probe::CACHE_PROBE_PASS_BUDGET.as_secs(),
                                    report.skipped_at_budget
                                );
                            }
                            if stop {
                                break;
                            }
                        }
                    }
                }

                let device_list: Vec<ArpDevice> = {
                    let map = devices.lock().await;
                    map.values().cloned().collect()
                };

                for device in &device_list {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                    let device_ip: Ipv4Addr = match device.ip.parse() {
                        Ok(ip) => ip,
                        Err(_) => continue,
                    };

                    if crate::validation::prohibited_camera_ip(device_ip) {
                        continue;
                    }

                    // Derive the subnet from the live IP rather than trusting
                    // a stored subnet left over from a previous address.
                    let o = device_ip.octets();
                    let device_subnet = format!("{}.{}.{}.0/24", o[0], o[1], o[2]);

                    if known_subnets.contains(&device_subnet) {
                        continue;
                    }

                    if adopted.lock().await.contains_key(&device_subnet) {
                        known_subnets.insert(device_subnet.clone());
                        continue;
                    }

                    // Refresh current IPs (may have changed since startup)
                    let current_ips = get_interface_ips(&iface_name).await;

                    if auto_adopt::already_on_subnet(device_ip, &current_ips) {
                        known_subnets.insert(device_subnet.clone());
                        continue;
                    }

                    // Still cooling down from a recent failed attempt? Skip
                    // until the retry time; a fresh success/failure below
                    // clears or re-arms it.
                    if let Some(&(retry_at, _)) = cooldowns.get(&device_subnet) {
                        if std::time::Instant::now() < retry_at {
                            continue;
                        }
                    }

                    if ctx.candidates.is_none() {
                        // Legacy structural-ghost guard: avoid a subnet owned by an
                        // up non-wired local interface (WiFi/VPN/virtual), even if
                        // its ARP reached the unscoped capture. Only candidates
                        // that already cleared known/adopted/native/cooldown get
                        // here — i.e. rarely — so the enumeration cost is bounded
                        // by the two TTLs.
                        if let Some(until) = ghost_until.get(&device_subnet) {
                            if std::time::Instant::now() < *until {
                                continue;
                            }
                        }
                        let ghosts_fresh = cached_ghosts
                            .as_ref()
                            .map(|(_, t)| t.elapsed() < GHOST_NETS_TTL)
                            .unwrap_or(false);
                        if !ghosts_fresh {
                            let nets = ghost::non_wired_interface_networks().await;
                            cached_ghosts = Some((nets, std::time::Instant::now()));
                        }
                        let ghost_nets: &[ipnetwork::Ipv4Network] = cached_ghosts
                            .as_ref()
                            .map(|(n, _)| n.as_slice())
                            .unwrap_or(&[]);
                        if ghost::is_structural_ghost_ip(device_ip, ghost_nets)
                            || ghost::is_structural_ghost_adoption(&device_subnet, ghost_nets)
                        {
                            log::info!(
                                "Skipping ghost subnet {} (owned by non-wired local interface)",
                                device_subnet
                            );
                            // TTL only — never poison the permanent `known_subnets`
                            // set, so the subnet is adoptable again after one
                            // recheck once WiFi/VPN/virtual goes down.
                            ghost_until.insert(
                                device_subnet.clone(),
                                std::time::Instant::now() + GHOST_SUBNET_RECHECK,
                            );
                            continue;
                        }
                    }

                    // All structural gates cleared — now require a second
                    // accepted frame from this device before binding.
                    // `last_seen` is rewritten on every accepted frame,
                    // so it serves as the observation token.
                    match dwell.check(
                        &device_subnet,
                        &device.mac,
                        &device.last_seen,
                        std::time::Instant::now(),
                    ) {
                        auto_adopt::DwellVerdict::Started => {
                            log::info!(
                                "Foreign subnet detected: {} — holding adoption until {} is observed again",
                                device_subnet,
                                device.mac
                            );
                            // Solicit the second observation instead of
                            // waiting out the device's beacon cadence: a
                            // directed probe answered with the sighted MAC
                            // is the repeat observation. A miss changes
                            // nothing — the candidacy above stays armed and
                            // the passive path remains the fallback, so the
                            // probe must never touch the cooldown map.
                            let Some(mac) = arp::normalize_mac(&device.mac) else {
                                continue;
                            };
                            log::info!(
                                "Fast adopt: soliciting confirmation from {} ({}) on {}",
                                device_ip,
                                mac,
                                device_subnet
                            );
                            let candidate = cache_probe::ProbeCandidate {
                                subnet: device_subnet.clone(),
                                pairs: vec![(device_ip, mac)],
                            };
                            let mut io = RealProbeIo {
                                ctx: &ctx,
                                cooldowns: &mut cooldowns,
                                known_subnets: &mut known_subnets,
                                shutdown_rx: &shutdown_rx,
                                scratch_id: None,
                                stop: false,
                                origin: ProbeOrigin::FastAdopt,
                            };
                            let report = cache_probe::run_pass(
                                &mut io,
                                vec![candidate],
                                cache_probe::FAST_ADOPT_PROBE_BUDGET,
                            )
                            .await;
                            if report.handed_off.is_empty() {
                                log::info!(
                                    "Fast adopt: {} did not confirm — leaving the two-observation gate armed",
                                    device_ip
                                );
                            } else {
                                log::info!(
                                    "Fast adopt: {} confirmed by directed probe",
                                    device_subnet
                                );
                                dwell.prune_subnet(&device_subnet);
                            }
                            // One probe per pass: the probe consumed this
                            // iteration's slot whatever the outcome, and the
                            // devices not reached keep their own `Started`
                            // for a later tick. A shutdown observed by the
                            // hand-off exits via the loop head's check, the
                            // same way the ShutdownRace break below does.
                            break;
                        }
                        auto_adopt::DwellVerdict::Waiting => continue,
                        auto_adopt::DwellVerdict::Mature => {}
                    }

                    let outcome = attempt_adoption(
                        &ctx,
                        device_ip,
                        &device_subnet,
                        AdoptionEvidence::DwellMature {
                            mac: device.mac.clone(),
                        },
                        &current_ips,
                        &mut cooldowns,
                        &mut known_subnets,
                        &shutdown_rx,
                    )
                    .await;

                    // Whatever the attempt's outcome, this subnet's dwell
                    // candidacy is spent — a later approach (post-cooldown
                    // retry, removal then re-appearance) restarts the
                    // two-observation gate. Dwell stays at this call site:
                    // the probe path must never touch the tracker.
                    dwell.prune_subnet(&device_subnet);
                    if outcome == AdoptionAttemptOutcome::ShutdownRace {
                        break;
                    }
                }
            }
            log::info!("Auto-adopt loop exited");
        });
        {
            let mut slot = self.auto_adopt_handle.lock().await;
            if slot.is_some() {
                log::warn!(
                    "auto_adopt_handle slot unexpectedly occupied at start — \
                     the preceding stop should have cleared it"
                );
            }
            *slot = Some(AutoAdoptHandle {
                shutdown: shutdown_tx,
                join: adopt_handle,
            });
        }

        Ok(())
    }

    pub async fn stop_arp_discovery(&self) {
        let _op = self.discovery_op.lock().await;
        self.stop_locked().await;
    }

    /// Full stop — the session machinery plus the capture listener, in
    /// that order. Run with the discovery op lock already held.
    async fn stop_locked(&self) {
        self.stop_session_locked().await;
        self.stop_capture_locked().await;
        log::info!("ARP discovery stopped");
    }

    /// Stop the session half only: sweeps' fence, the session clock,
    /// the adopt task, the watchdog, and pending-IP reconciliation. The
    /// capture listener keeps running — its frames are fenced by the
    /// capture lifecycle, not the discovery generation, so a retained
    /// listener keeps merging across session restarts.
    async fn stop_session_locked(&self) {
        // Mark inactive before tearing down handles so an in-flight sweep
        // or capture frame fences out. Cleared on every stop — including a
        // stop with no following start (Static Auto → Manual) — which a
        // generation counter alone would miss.
        self.discovery_active.store(false, Ordering::Relaxed);
        // No session, no session clock: the adoption snapshot's grace
        // math treats a stopped discovery as elapsed-zero (never badges
        // an APIPA entry stale on session evidence it cannot gather).
        if let Ok(mut started) = self.discovery_started.lock() {
            *started = None;
        }
        if let Some(h) = self.auto_adopt_handle.lock().await.take() {
            // Cooperative stop: ask the loop to exit at a select! point so an
            // in-flight adoption rolls back cleanly, then join with a bound.
            // Abort only if it doesn't exit in time — safe because the
            // add/remove children are kill-on-drop, so dropping the future
            // takes any in-flight child with it.
            let _ = h.shutdown.send(true);
            let abort = h.join.abort_handle();
            match tokio::time::timeout(AUTO_ADOPT_STOP_TIMEOUT, h.join).await {
                Ok(_) => log::info!("Auto-adopt task stopped cooperatively"),
                Err(_) => {
                    log::warn!(
                        "Auto-adopt task did not stop within {}s — aborting",
                        AUTO_ADOPT_STOP_TIMEOUT.as_secs()
                    );
                    abort.abort();
                }
            }
        }
        if let Some(h) = self.discovery_watchdog_handle.lock().await.take() {
            // Cooperative stop first: the watchdog may be mid-restart of
            // the capture session, and a cooperative exit parks or
            // installs the in-flight session cleanly. Abort is the
            // bounded fallback — safe, because an orphaned session tears
            // itself down when its handle drops.
            let _ = h.shutdown.send(true);
            let abort = h.join.abort_handle();
            if tokio::time::timeout(WATCHDOG_STOP_TIMEOUT, h.join)
                .await
                .is_err()
            {
                log::warn!(
                    "Discovery watchdog did not stop within {}s — aborting",
                    WATCHDOG_STOP_TIMEOUT.as_secs()
                );
                abort.abort();
            }
        }
        // Reconcile any secondary IP the (now-stopped) adoption left bound
        // but unrecorded — scratch probes and final adds that never reached
        // adopted_ips. Best-effort; failures are logged and retried next stop.
        if let Ok(_address) = self.address_work.try_lock() {
            let app = self.capture_signal.lock().await.app.clone();
            if let Some(app) = app {
                use tauri::Manager;
                self.reconcile_temporary_locked(&app.state::<crate::config::AppConfig>())
                    .await;
            }
        }
    }

    /// Stop the capture half: retire the incarnation's fence flag, park
    /// the capture thread's join, clear the recorded identity.
    async fn stop_capture_locked(&self) {
        // Flag first, park second — a wedged thread that outlives the
        // park can never merge once its incarnation is retired.
        if let Some(identity) = self.capture_identity.lock().await.take() {
            identity.active.store(false, Ordering::Relaxed);
        }
        self.capture_signal.lock().await.deactivate();
        self.candidates.clear();
        if let Some(h) = self.arp_listener_handle.lock().await.take() {
            // Signal shutdown and park the capture thread's join in the
            // guard — the next capture start bounded-joins it there, so
            // stop itself never blocks on the blocking thread.
            self.prior_capture_joins
                .lock()
                .await
                .push(h.stop_into_join());
            log::info!("ARP capture stopped");
        }
    }

    fn candidate_ingress(&self, index: u32, mac: Option<[u8; 6]>) -> Option<arp::CandidateIngress> {
        Some(arp::CandidateIngress {
            store: self.candidates.clone(),
            interface_index: index,
            adapter_mac: mac.unwrap_or([0; 6]),
        })
    }

    pub async fn get_capture_state(&self) -> CaptureState {
        let mut state = self.capture_signal.lock().await.state.clone();
        state.candidate_count = self.candidates.count(std::time::Instant::now());
        state
    }

    pub async fn get_adopted_ips(&self) -> HashMap<String, String> {
        let map = self.adopted_ips.lock().await;
        map.iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect()
    }

    /// Resolve the wired source IP for reaching `target`, for
    /// wired-bound cache verification. `None` (discovery never started,
    /// or no adopted/native wired subnet contains the target) means the
    /// verification must fail rather than probe unbound. The adapter
    /// re-read costs one PowerShell query per call — acceptable because
    /// this only runs after a TCP scan already succeeded; cache the
    /// selected adapter's IPs in memory if verify latency ever matters.
    pub async fn wired_source_for(&self, target: Ipv4Addr) -> Option<(u32, Ipv4Addr)> {
        let selection = self.adapter_selection_state().await;
        let index = selection.interface_index?;
        let mac = selection.selected_mac?;
        let adopted = self.adopted_ips.lock().await.clone();
        let iface = selection.adapter?.name;
        let info = interface::get_by_name(&iface).await.ok()?;
        if adapter_mac(&info.mac) != adapter_mac(&mac)
            || interface::index_for_mac(&info.mac)? != index
        {
            return None;
        }
        select_wired_source(target, &adopted, &info.ips).map(|source| (index, source))
    }

    /// Explicit Apply/Add Secondary transfers ownership to the user, including
    /// clearing any tombstone for that exact address. Call under address_work.
    async fn claim_binding_locked(
        &self,
        config: &crate::config::AppConfig,
        ip: &str,
        alias: &str,
    ) -> Result<(), AppError> {
        let before = config.get().adopted_meta;
        self.address_io.claim(config, ip)?;
        self.pending_ips
            .lock()
            .await
            .retain(|entry| entry.ip.to_string() != ip || entry.iface != alias);
        let adapter = config.get().selected_adapter_mac;
        log::info!(
            "event=binding_change adapter_mac={} interface_index={} address={} reason=manual_claim",
            log_value(adapter.as_deref().unwrap_or("unknown")),
            self.adapter_selection
                .lock()
                .await
                .interface_index
                .unwrap_or(0),
            log_value(ip)
        );
        let saved = config.get().adopted_meta;
        let claimed: HashSet<_> = before
            .keys()
            .filter(|key| !saved.contains_key(*key))
            .cloned()
            .collect();
        self.adopted_ips
            .lock()
            .await
            .retain(|key, _| !claimed.contains(key));
        if let Ok(mut meta) = self.adopted_meta.lock() {
            meta.retain(|key, _| !claimed.contains(key));
        }
        Ok(())
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
    async fn selected_write_adapter(
        &self,
        config: &crate::config::AppConfig,
        name: &str,
    ) -> Result<InterfaceInfo, AppError> {
        let snapshot = self.operation_snapshot(config).await?;
        if snapshot.iface.name != name {
            return Err(AppError::Network(
                "Selected Ethernet adapter unavailable or changed".into(),
            ));
        }
        Ok(snapshot.iface)
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
        let _pause = self.pause_addresses();
        let _address = self.address_work.lock().await;
        self.reconcile_temporary_locked(config).await;
    }

    async fn reconcile_temporary_locked(&self, config: &crate::config::AppConfig) {
        use auto_adopt::AdoptOps;
        let saved = config.get().pending_addresses;
        if saved.is_empty() {
            return;
        }
        let adapters = match interface::read_native_with(self.address_io.as_ref()).await {
            Ok(list) => list
                .iter()
                .filter_map(|n| self.address_io.descriptor(n))
                .collect::<Vec<_>>(),
            Err(e) => {
                log::warn!("Temporary cleanup waiting for native state: {e}");
                return;
            }
        };
        for row in saved {
            let Some(ip) = row
                .address
                .parse::<Ipv4Addr>()
                .ok()
                .filter(|ip| !crate::validation::prohibited_camera_ip(*ip))
            else {
                continue;
            };
            if row.prefix != 24 || adapter_mac(&row.adapter_mac).is_none() {
                continue;
            }
            let owners: Vec<_> = adapters
                .iter()
                .filter(|a| {
                    adapter_candidate(a) && adapter_mac(&a.mac) == adapter_mac(&row.adapter_mac)
                })
                .collect();
            let [iface] = owners.as_slice() else {
                continue;
            };
            if iface
                .ips
                .iter()
                .any(|a| a.address == row.address && a.prefix == row.prefix)
            {
                let mut pending = self.pending_ips.lock().await;
                if !pending.iter().any(|p| p.iface == iface.name && p.ip == ip) {
                    pending.push(auto_adopt::PendingIp {
                        iface: iface.name.clone(),
                        ip,
                        adoption_id: self.adoption_seq.fetch_add(1, Ordering::Relaxed) + 1,
                    });
                }
            }
            let ops = auto_adopt::PendingAdoptOps::new(
                config,
                &row.adapter_mac,
                AddressOps(self.address_io.as_ref(), None),
            );
            if let Err(e) = ops.remove(&iface.name, ip).await {
                log::warn!(
                    "Temporary address {}/{} on {} cleanup pending: {}",
                    ip,
                    row.prefix,
                    row.adapter_mac,
                    e
                );
            }
        }
        let remaining = config.get().pending_addresses;
        self.pending_ips
            .lock()
            .await
            .retain(|p| remaining.iter().any(|r| r.address == p.ip.to_string()));
    }

    #[cfg(test)]
    async fn cleanup_pending_with<O: auto_adopt::AdoptOps>(&self, ops: &O) {
        let _pause = self.pause_addresses();
        let _address = self.address_work.lock().await;
        auto_adopt::reconcile_pending(ops, &self.pending_ips, None).await;
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

async fn get_interface_ips(name: &str) -> Vec<Ipv4Addr> {
    match interface::get_by_name(name).await {
        Ok(info) => info
            .ips
            .iter()
            .filter_map(|ip| ip.address.parse().ok())
            .collect(),
        Err(_) => vec![],
    }
}

/// Fast parallel ping sweep of all /24 subnets to provoke ARP responses.
///
/// Each ping is issued with `-S <ip_str>` so Windows uses that address as
/// the source and therefore routes the packet out the adapter that owns
/// it. Without this, a /24 that overlaps another interface (very common:
/// 192.168.1.0/24 on both Ethernet-camera-network and home WiFi) can
/// silently route out the wrong NIC — the Ethernet capture listener
/// never sees the replies and passive devices on that subnet stay invisible.
async fn ping_sweep_subnets(interface_ips: &[String], fence: &SweepFence, app: &tauri::AppHandle) {
    use tauri::Manager;
    use tokio::sync::Semaphore;
    use tokio::task::JoinSet;

    // ICMP has a separate process bound; it never takes TCP scan permits.
    const MAX_CONCURRENT_PINGS: usize = 32;
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_PINGS));
    let mut join_set = JoinSet::new();
    let manager = app.state::<NetworkManager>();
    let Some((_, index, adapter_fence)) = manager.probe_scope() else {
        return;
    };
    let mut solicited = false;
    for ip_str in interface_ips {
        let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
            continue;
        };
        if crate::validation::prohibited_camera_ip(ip) {
            continue;
        }
        let o = ip.octets();
        for last in 1..=254 {
            let permit = tokio::select! {
                biased;
                _ = fence.cancelled() => return,
                _ = adapter_fence.cancelled() => return,
                permit = sem.clone().acquire_owned() => match permit { Ok(p) => p, Err(_) => return },
            };
            #[cfg(windows)]
            if !interface::source_matches_interface(index, ip) {
                break;
            }
            let target = Ipv4Addr::new(o[0], o[1], o[2], last);
            if interface_ips
                .iter()
                .any(|local| local == &target.to_string())
                || route::egress_index(target).ok() != Some(index)
            {
                continue;
            }
            if !solicited {
                manager.note_solicitation(fence).await;
                solicited = true;
            }
            if fence.is_stale() || adapter_fence.is_stale() {
                return;
            }
            let source = ip_str.clone();
            join_set.spawn(async move {
                let _permit = permit;
                let mut command = async_cmd("ping");
                command.kill_on_drop(true);
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    command
                        .args(["-n", "1", "-w", "200", "-S", &source, &target.to_string()])
                        .output(),
                )
                .await;
            });
        }
    }
    tokio::select! {
        biased;
        _ = fence.cancelled() => {},
        _ = adapter_fence.cancelled() => {},
        _ = async { while join_set.join_next().await.is_some() {} } => {},
    }
    log::info!("Ping sweep complete");
}

/// Read the OS ARP table and merge entries into the discovered devices map.
/// This catches hosts whose ARP entries were already cached in the OS
/// (e.g. from a prior browser visit), since the ping sweep won't generate
/// new ARP packets on the wire for those hosts.
#[allow(clippy::too_many_arguments)]
async fn merge_arp_table(
    devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    registry: Arc<DeviceRegistry>,
    emitter: Arc<DeviceListEmitter>,
    app_handle: tauri::AppHandle,
    interface_ip: &str,
    excluded: &[ipnetwork::Ipv4Network],
    local_ips: &HashSet<Ipv4Addr>,
    fence: &SweepFence,
    candidates: Option<&arp::CandidateIngress>,
) {
    use tauri::{Emitter, Manager};

    // Fence stale-session merges: a sweep from a prior discovery session
    // (or one still running after a stop) must not merge or emit into the
    // current session's shared registry.
    if fence.is_stale() {
        return;
    }

    let entries = arp::read_system_arp_table(interface_ip).await;
    let new_devices = import_neighbors(
        entries,
        &mut *devices.lock().await,
        excluded,
        local_ips,
        fence,
        candidates,
    );

    let mut registry_changed = false;
    for device in &new_devices {
        log::info!("ARP table: {} ({})", device.ip, device.mac);
        let _ = app_handle.emit("arp-device-discovered", device);
        // Positive-liveness stamp for the adoption lifecycle — a
        // neighbor-table row accepted here is device evidence just like
        // a captured frame.
        if let Ok(device_ip) = device.ip.parse::<Ipv4Addr>() {
            let manager: tauri::State<'_, NetworkManager> = app_handle.state();
            manager
                .note_positive_liveness_fenced(&app_handle, device_ip, fence)
                .await;
        }
        let result = registry.merge_arp_fenced(device, fence);
        if result.changed {
            registry_changed = true;
        }
        // Mirror same-IP dedup to the on-disk cache so reloads don't
        // resurrect the orphan rows.
        if !result.dropped_macs.is_empty() {
            // Off the executor: remove_cached_device does a synchronous
            // fsync'd cache rewrite under a std lock; on a slow disk during an
            // ARP burst that would stall this worker. Move the eviction to a
            // blocking thread with owned copies of the keys.
            let dropped = result.dropped_macs.clone();
            let survivor = device.mac.clone();
            let cache_handle = app_handle.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let config: tauri::State<'_, crate::config::AppConfig> = cache_handle.state();
                for mac in &dropped {
                    if let Err(e) = config.remove_cached_device(mac) {
                        log::warn!(
                            "Failed to evict dupe cache row {} (same IP as {}): {}",
                            mac,
                            survivor,
                            e
                        );
                    }
                }
            })
            .await;
        }
    }

    if !new_devices.is_empty() {
        log::info!("Merged {} devices from OS ARP table", new_devices.len());
    }
    // Coalesce all the new entries into one event. The emitter's 150 ms
    // window absorbs both this batch and any concurrent live-ARP merges.
    if registry_changed {
        emitter.poke();
    }
}

async fn run_presence_job(
    app: tauri::AppHandle,
    job: presence::Job,
    snapshot: presence::Snapshot,
) -> Option<String> {
    use tauri::Manager;
    let adapter = snapshot.adapter.as_ref()?;
    let manager = app.state::<NetworkManager>();
    if snapshot.fence.is_stale() {
        return None;
    }
    let address_fence = manager.address_fence();
    if job.source.is_none() && address_fence.is_stale() {
        return None;
    }
    let _address = if job.source.is_none() {
        Some(manager.address_work.lock().await)
    } else {
        None
    };
    if snapshot.fence.is_stale() || (job.source.is_none() && address_fence.is_stale()) {
        return None;
    }
    let own_ips: HashSet<_> = interface::all_local_ipv4().into_iter().collect();
    if own_ips.contains(&job.ip) {
        return None;
    }
    // Even a prefix also used by Wi-Fi may contain an Ethernet peer.
    // Foreign candidates still require mode-gated scratch work and fresh
    // selected-index resolution below; a Wi-Fi-only sender cannot promote.
    let emitter = manager.emitter().await?;
    let ctx = AdoptionCtx {
        iface_name: adapter.name.clone(),
        adapter_mac: adapter.mac.clone(),
        interface_index: snapshot.index,
        candidates: manager.candidate_ingress(snapshot.index, parse_mac_bytes(&adapter.mac)),
        app_handle: app.clone(),
        adopted: manager.adopted_ips.clone(),
        pending_ips: manager.pending_ips.clone(),
        adoption_seq: manager.adoption_seq.clone(),
        liveness: manager.adoption_liveness.clone(),
        meta: manager.adopted_meta.clone(),
        devices: manager.arp_devices.clone(),
        registry: manager.device_registry.clone(),
        emitter: emitter.clone(),
        fence: snapshot.fence.clone(),
        address_fence,
        local_ips: manager.local_ips.clone(),
    };
    let mut cooldowns = HashMap::new();
    let mut known_subnets = HashSet::new();
    let (_tx, shutdown) = tokio::sync::watch::channel(false);
    let mut io = RealProbeIo {
        ctx: &ctx,
        cooldowns: &mut cooldowns,
        known_subnets: &mut known_subnets,
        shutdown_rx: &shutdown,
        scratch_id: None,
        stop: false,
        origin: ProbeOrigin::CacheProbe,
    };
    let proof = presence::verify(&mut io, &job, &snapshot).await?;
    log::debug!("event=evidence adapter_mac={} interface_index={} identity={} ip={} evidence_age_ms={} origin=presence",
        log_value(&adapter.mac), snapshot.index, log_value(&proof.mac), proof.ip, proof.at.elapsed().as_millis());
    let mutation_fence = ctx.address_fence.clone();
    drop(_address);
    let cache_app = app.clone();
    let fence = snapshot.fence.clone();
    let adapter_mac = adapter.mac.clone();
    let commit_fence = fence.clone();
    let key = tokio::task::spawn_blocking(move || {
        let manager = cache_app.state::<NetworkManager>();
        let config = cache_app.state::<crate::config::AppConfig>();
        if commit_fence.is_stale()
            || mutation_fence.is_stale()
            || proof.at.elapsed() >= presence::FRESHNESS
        {
            arp::note_fence_drop("presence_commit");
            return None;
        }
        let registry = manager.registry();
        if job
            .key
            .as_ref()
            .is_some_and(|key| !registry.snapshot().iter().any(|r| r.mac == *key))
        {
            return None;
        }
        let device = ArpDevice {
            mac: proof.mac.clone(),
            ip: proof.ip.to_string(),
            subnet: subnet_key_for(proof.ip),
            first_seen: proof.wall.clone(),
            last_seen: proof.wall.clone(),
        };
        let pin = config.get_manual_nodes().into_iter().find(|n| {
            n.ip == device.ip
                && job.key.as_ref().is_some_and(|key| {
                    key == &crate::config::manual_node_key(n) || key == &format!("manual:{}", n.ip)
                })
        });
        let result = if let Some(node) = pin {
            manager
                .merge_manual_verified(
                    &config,
                    &node.ip,
                    &device,
                    &adapter_mac,
                    &proof.wall,
                    &commit_fence,
                )
                .ok()?
        } else {
            registry.merge_verified(&device, &adapter_mac, &proof.wall, &commit_fence)
        };
        if !result.changed || commit_fence.is_stale() || mutation_fence.is_stale() {
            return None;
        }
        registry.remember_verified_at(&proof.mac, &proof.wall, proof.at, &commit_fence);
        let key = registry
            .snapshot()
            .iter()
            .find(|r| r.mac.eq_ignore_ascii_case(&proof.mac))?
            .mac
            .clone();
        if let Some(row) = registry.cache_record(&key) {
            if let Err(e) = config.upsert_cached_device_fenced(row, Some(&commit_fence)) {
                log::warn!("Presence cache write failed: {e}");
            }
        }
        if commit_fence.is_stale()
            || mutation_fence.is_stale()
            || proof.at.elapsed() >= presence::FRESHNESS
        {
            return None;
        }
        let target = config.get().stream.camera_mac;
        if target
            .as_ref()
            .is_some_and(|m| m.eq_ignore_ascii_case(&proof.mac))
        {
            manager.presence.verified.notify_one();
        }
        Some(key)
    })
    .await
    .ok()
    .flatten()?;
    manager
        .note_verified_liveness(
            &app,
            job_ip_from_key(&manager.device_registry, &key)?,
            &fence,
        )
        .await;
    emitter.poke();
    Some(key)
}

fn job_ip_from_key(registry: &DeviceRegistry, key: &str) -> Option<Ipv4Addr> {
    registry
        .snapshot()
        .iter()
        .find(|r| r.mac == key)?
        .ip
        .parse()
        .ok()
}

fn hydrate_retained_history(
    registry: &DeviceRegistry,
    cached: Vec<crate::config::CachedDevice>,
    ghosts: &[ipnetwork::Ipv4Network],
    local_ips: &HashSet<Ipv4Addr>,
) {
    let (mut allowed, rejected) = ghost::partition_cached(cached, ghosts, local_ips);
    allowed.extend(rejected.iter().map(|(d, _)| d.clone()));
    registry.hydrate_from_cache(&allowed);
    for (d, reason) in rejected {
        registry.set_status(
            &d.mac,
            match reason {
                ghost::CacheReject::NonWiredSubnet => DeviceStatus::OfflineNonWiredSubnet,
                ghost::CacheReject::HostOwnedIp => DeviceStatus::OfflineHostOwnedIp,
            },
        );
    }
}

fn import_neighbors(
    entries: Vec<(Ipv4Addr, String)>,
    devices: &mut HashMap<String, ArpDevice>,
    excluded: &[ipnetwork::Ipv4Network],
    local_ips: &HashSet<Ipv4Addr>,
    fence: &SweepFence,
    candidates: Option<&arp::CandidateIngress>,
) -> Vec<ArpDevice> {
    let mut collected = Vec::new();
    for (ip, mac) in entries {
        if fence.is_stale() {
            break;
        }
        if crate::validation::prohibited_camera_ip(ip)
            || local_ips.contains(&ip)
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
    async fn shared_prefix_neighbors_require_fresh_ethernet_proof_and_never_persist_wifi() {
        use cache_probe::tests::MockProbeIo;
        let manager = NetworkManager::new();
        let selection = discovery_selection(true);
        manager
            .presence
            .update(&selection, crate::config::NetworkMode::StaticAuto);
        manager.presence.tick(&manager.registry());
        let snapshot = manager.presence.snapshot();
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
        let local = ["192.168.1.100".parse().unwrap()].into_iter().collect();
        let excluded = ["192.168.1.0/24".parse().unwrap()];
        let imported = import_neighbors(
            vec![
                (camera, peer.into()),
                (wifi, "aa:bb:cc:dd:ee:04".into()),
                ("169.254.10.2".parse().unwrap(), peer.into()),
                ("192.168.1.100".parse().unwrap(), peer.into()),
            ],
            &mut legacy,
            &excluded,
            &local,
            &snapshot.fence,
            Some(&ingress),
        );
        assert!(imported.is_empty() && legacy.is_empty());
        assert!(manager.registry().snapshot().is_empty());
        let candidates = manager.candidates.snapshot(std::time::Instant::now());
        assert_eq!(candidates.len(), 2);
        import_neighbors(
            vec![("192.168.1.205".parse().unwrap(), peer.into())],
            &mut legacy,
            &excluded,
            &local,
            &fence(1, 2, true),
            Some(&ingress),
        );
        assert_eq!(manager.candidates.count(std::time::Instant::now()), 2);
        let mut clock = presence::Clock::default();
        let mut io = MockProbeIo::new();
        io.answers.insert(camera, peer.into());
        for _ in 0..2 {
            let job = clock
                .next(&snapshot, &manager.registry().snapshot(), &candidates)
                .unwrap();
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
            manager.presence.update(&selection, mode);
            manager.presence.tick(&manager.registry());
            let snapshot = manager.presence.snapshot();
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
            let candidates = manager.candidates.snapshot(std::time::Instant::now());
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
            *manager.adopted_meta.lock().unwrap() = rows;
            manager
                .adopted_ips
                .lock()
                .await
                .insert("192.0.2.0/24".into(), ip("192.0.2.20"));
            if previously_selected {
                *manager.adapter_selection.lock().await = discovery_selection(true);
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
                manager.adopted_meta.lock().unwrap()["172.26.95.0/24"],
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
        let _address = manager.address_work.lock().await;
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
        assert!(!manager.discovery_active.load(Ordering::Relaxed));
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
        let old = manager.address_fence();
        let pending = manager.pending_ips.clone();
        let ops = BindingOps::default();
        let worker = manager.address_work.lock().await;
        auto_adopt::bind_scratch(&ops, &pending, "Ethernet", ip("172.31.169.254"), 1)
            .await
            .unwrap();
        let pause = manager.pause_addresses();
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
        let _transition = manager.address_work.lock().await;
        assert!(pending.lock().await.is_empty());
        assert_eq!(
            *ops.writes.lock().unwrap(),
            vec![(true, ip("172.31.169.254")), (false, ip("172.31.169.254"))]
        );
        drop(pause);
        assert!(old.is_stale());
        assert!(!manager.address_fence().is_stale());
    }

    #[tokio::test]
    async fn committed_handover_and_exit_cleanup_preserve_saved_apipa_and_plain_ips() {
        let manager = NetworkManager::new();
        let ops = BindingOps::default();
        let committed = ip("169.254.20.99");
        let plain = ip("172.31.169.253");
        manager.adopted_ips.lock().await.extend([
            ("169.254.20.0/24".into(), committed),
            ("172.31.169.0/24".into(), plain),
        ]);
        auto_adopt::bind_scratch(&ops, &manager.pending_ips, "Ethernet", committed, 1)
            .await
            .unwrap();
        commit_pending_address(&manager.pending_ips, "Ethernet", committed, 1, || Ok(()))
            .await
            .unwrap();
        auto_adopt::bind_scratch(
            &ops,
            &manager.pending_ips,
            "Ethernet",
            ip("172.31.170.254"),
            2,
        )
        .await
        .unwrap();
        manager.cleanup_pending_with(&ops).await;
        assert!(manager.pending_ips.lock().await.is_empty());
        assert_eq!(manager.adopted_ips.lock().await.len(), 2);
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

    #[tokio::test]
    async fn capture_state_starts_inactive_without_an_outcome() {
        let manager = NetworkManager::new();
        let state = manager.get_capture_state().await;
        assert!(!state.active);
        assert!(state.outcome.is_none());
        assert!(state.adapter_name.is_none());
    }

    #[test]
    fn capture_stop_keeps_last_scope_outcome_for_the_query() {
        let mut signal = CaptureSignal {
            state: CaptureState {
                active: true,
                candidate_count: 0,
                adapter_name: Some("Ethernet".into()),
                outcome: Some(pktmon::ScopeOutcome::ScopedByName { source_id: 42 }),
            },
            app: None,
        };
        signal.deactivate();
        signal.deactivate();
        let state = serde_json::to_value(&signal.state).unwrap();
        assert_eq!(state["active"], false);
        assert_eq!(state["adapter_name"], "Ethernet");
        assert_eq!(state["outcome"]["scope"], "scoped_by_name");
        assert_eq!(state["outcome"]["source_id"], 42);
    }

    fn identity(source_id: Option<u32>) -> CaptureIdentity {
        CaptureIdentity {
            iface_name: "Ethernet".into(),
            mac: Some([0x40, 0xcd, 0x3a, 0x00, 0x00, 0x01]),
            source_id,
            active: Arc::new(AtomicBool::new(true)),
        }
    }

    #[test]
    fn dhcp_to_auto_preserves_only_valid_capture_and_other_modes_restart() {
        use crate::config::NetworkMode::{Dhcp, StaticAuto, StaticManual};
        for from in [Dhcp, StaticAuto, StaticManual] {
            for to in [Dhcp, StaticAuto, StaticManual] {
                assert_eq!(
                    mode_keeps_capture(from, to),
                    from == Dhcp && to == StaticAuto
                );
            }
        }
        let current = identity(None);
        let decide = |current: Option<&CaptureIdentity>, has_handle| {
            mode_capture_action(
                listener_action(
                    current,
                    has_handle,
                    "Ethernet",
                    identity(None).mac,
                    LiveSourceId::Enumerated(42),
                ),
                true,
            )
        };
        assert_eq!(decide(Some(&current), true), ListenerAction::Keep);
        assert_eq!(decide(Some(&current), false), ListenerAction::Attach);
        assert_eq!(decide(None, false), ListenerAction::Attach);
        let changed = identity(Some(41));
        assert_eq!(
            decide(Some(&changed), true),
            ListenerAction::Replace("data source changed")
        );
        let mut other = identity(None);
        other.iface_name = "Dock".into();
        assert_eq!(
            decide(Some(&other), true),
            ListenerAction::Replace("adapter changed")
        );
        current.active.store(false, Ordering::Release);
        assert_eq!(
            decide(Some(&current), true),
            ListenerAction::Replace("capture inactive")
        );
        assert_eq!(
            mode_capture_action(ListenerAction::Replace("retry scoped attach"), false),
            ListenerAction::Replace("retry scoped attach")
        );
    }

    #[test]
    fn listener_action_attaches_when_nothing_is_bound() {
        let current = identity(Some(101));
        // No identity at all → attach.
        assert_eq!(
            listener_action(
                None,
                false,
                "Ethernet",
                current.mac,
                LiveSourceId::EnumFailed
            ),
            ListenerAction::Attach
        );
        // Identity without a live handle (a torn-down session whose
        // reinstall failed) must attach, never keep.
        assert_eq!(
            listener_action(
                Some(&current),
                false,
                "Ethernet",
                current.mac,
                LiveSourceId::Enumerated(101)
            ),
            ListenerAction::Attach
        );
    }

    #[test]
    fn listener_action_keeps_a_healthy_binding() {
        let current = identity(Some(101));
        assert_eq!(
            listener_action(
                Some(&current),
                true,
                "Ethernet",
                current.mac,
                LiveSourceId::Enumerated(101)
            ),
            ListenerAction::Keep
        );
        // Enumeration failure fails open to Keep — a transient fault
        // must never churn a healthy listener.
        assert_eq!(
            listener_action(
                Some(&current),
                true,
                "Ethernet",
                current.mac,
                LiveSourceId::EnumFailed
            ),
            ListenerAction::Keep
        );
    }

    #[test]
    fn listener_action_replaces_an_invalidated_binding() {
        let current = identity(Some(101));
        // Renamed adapter.
        assert_eq!(
            listener_action(
                Some(&current),
                true,
                "Ethernet 2",
                current.mac,
                LiveSourceId::Enumerated(101)
            ),
            ListenerAction::Replace("adapter changed")
        );
        // Same name, different MAC (hardware swapped under the name).
        assert_eq!(
            listener_action(
                Some(&current),
                true,
                "Ethernet",
                Some([0x2c, 0xa5, 0x9c, 0x00, 0x00, 0x02]),
                LiveSourceId::Enumerated(101)
            ),
            ListenerAction::Replace("adapter changed")
        );
        // Data-source churn under the same adapter.
        assert_eq!(
            listener_action(
                Some(&current),
                true,
                "Ethernet",
                current.mac,
                LiveSourceId::Enumerated(115)
            ),
            ListenerAction::Replace("data source changed")
        );
    }

    #[test]
    fn listener_action_unscoped_session_retries_scoped() {
        let unscoped = identity(None);
        // A live id exists → re-attempt the scoped join.
        assert_eq!(
            listener_action(
                Some(&unscoped),
                true,
                "Ethernet",
                unscoped.mac,
                LiveSourceId::Enumerated(101)
            ),
            ListenerAction::Replace("retry scoped attach")
        );
        // No live id → keep the unscoped session over churning.
        assert_eq!(
            listener_action(
                Some(&unscoped),
                true,
                "Ethernet",
                unscoped.mac,
                LiveSourceId::EnumFailed
            ),
            ListenerAction::Keep
        );
    }

    #[test]
    fn lifecycle_fence_stales_only_on_its_incarnation_flag() {
        // The listener's fence pins generation zero against a
        // permanently-zero counter, so staleness is exactly the
        // incarnation flag — a discovery restart (generation advance)
        // must not fence out a retained listener.
        let flag = Arc::new(AtomicBool::new(true));
        let lifecycle = SweepFence::new(0, Arc::new(AtomicU64::new(0)), flag.clone());
        assert!(!lifecycle.is_stale());
        flag.store(false, Ordering::Relaxed);
        assert!(lifecycle.is_stale());
    }

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

    #[test]
    fn probe_evidence_maps_each_origin_to_its_variant() {
        let ip: Ipv4Addr = "172.31.169.61".parse().unwrap();
        assert!(matches!(
            probe_evidence(ProbeOrigin::CacheProbe, ip, "2c:a5:9c:2b:a9:fc"),
            AdoptionEvidence::CachedMacMatch { cached_ip, ref mac }
                if cached_ip == ip && mac == "2c:a5:9c:2b:a9:fc"
        ));
        assert!(matches!(
            probe_evidence(ProbeOrigin::FastAdopt, ip, "2c:a5:9c:2b:a9:fc"),
            AdoptionEvidence::FreshSightingConfirmed { probed_ip, ref mac }
                if probed_ip == ip && mac == "2c:a5:9c:2b:a9:fc"
        ));
    }

    #[test]
    fn adoption_evidence_display_names_each_justification() {
        let ip: Ipv4Addr = "172.31.169.61".parse().unwrap();
        assert_eq!(
            AdoptionEvidence::DwellMature {
                mac: "aa:bb:cc:dd:ee:ff".into()
            }
            .to_string(),
            "confirmed by a repeat observation from aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(
            AdoptionEvidence::CachedMacMatch {
                cached_ip: ip,
                mac: "aa:bb:cc:dd:ee:ff".into()
            }
            .to_string(),
            "cached device aa:bb:cc:dd:ee:ff freshly verified at 172.31.169.61"
        );
        assert_eq!(
            AdoptionEvidence::FreshSightingConfirmed {
                probed_ip: ip,
                mac: "aa:bb:cc:dd:ee:ff".into()
            }
            .to_string(),
            "fresh sighting aa:bb:cc:dd:ee:ff confirmed by a directed probe at 172.31.169.61"
        );
    }

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
    fn persisted_adapter_survives_reordering_absence_and_return() {
        let mut dock = adapter("Dock", &["192.168.1.101"]);
        dock.mac = "40:cd:3a:00:00:01".into();
        let mut usb = adapter("USB", &["192.168.1.102"]);
        usb.mac = "40:cd:3a:00:00:02".into();
        for list in [
            vec![dock.clone(), usb.clone()],
            vec![usb.clone(), dock.clone()],
        ] {
            assert_eq!(
                pick_adapter(&list, Some("40-CD-3A-00-00-02")).unwrap().name,
                "USB"
            );
        }
        assert!(pick_adapter(&[dock], Some(&usb.mac)).is_none());
        assert_eq!(
            pick_adapter(&[usb], Some("40:cd:3a:00:00:02"))
                .unwrap()
                .name,
            "USB"
        );
    }

    #[test]
    fn automatic_selection_requires_one_eligible_physical_adapter() {
        let mut wired = adapter("Wired", &[]);
        wired.mac = "40:cd:3a:00:00:01".into();
        wired.is_up = false; // the only disconnected port can pre-attach
        assert_eq!(pick_adapter(&[wired.clone()], None).unwrap().name, "Wired");
        assert!(pick_adapter(&[], None).is_none());
        let mut other = wired.clone();
        other.mac = "40:cd:3a:00:00:02".into();
        other.is_up = true;
        assert!(pick_adapter(&[wired.clone(), other.clone()], None).is_none());
        assert!(pick_adapter(&[other.clone(), wired.clone()], None).is_none());
        for kind in ["wifi", "vpn", "virtual", "invalid_mac"] {
            let mut excluded = other.clone();
            match kind {
                "wifi" => excluded.is_wifi = true,
                "vpn" => excluded.is_vpn = true,
                "virtual" => excluded.is_virtual = true,
                _ => excluded.mac.clear(),
            }
            assert_eq!(
                pick_adapter(&[excluded, wired.clone()], None).unwrap().mac,
                wired.mac
            );
        }
        assert!(pick_adapter(&[wired], Some("invalid-mac")).is_none());
    }

    #[test]
    fn binding_on_another_adapter_is_pending_even_if_address_matches() {
        let mut row = saved_binding("172.31.169.253");
        row.adapter_mac = Some("40:cd:3a:00:00:02".into());
        let iface = saved_adapter(&["172.31.169.253"]);
        assert_eq!(
            binding_action(
                "172.31.169.0/24",
                &row,
                Some(&iface),
                crate::config::NetworkMode::StaticAuto,
                &Ok(false),
                &[]
            ),
            BindingAction::Hold("adapter mismatch".into(), false)
        );
    }

    #[test]
    fn stale_applied_flag_does_not_suppress_restore() {
        let mut row = saved_binding("172.31.169.253");
        row.applied = true;
        let iface = saved_adapter(&["192.168.1.20"]);
        assert_eq!(
            binding_action(
                "172.31.169.0/24",
                &row,
                Some(&iface),
                crate::config::NetworkMode::StaticAuto,
                &Ok(false),
                &[]
            ),
            BindingAction::Add(ip("172.31.169.253"), 24)
        );
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
    fn unavailable_binding_never_moves_to_a_different_adapter() {
        let row = saved_binding("172.31.169.253");
        assert_eq!(
            binding_action(
                "172.31.169.0/24",
                &row,
                None,
                crate::config::NetworkMode::StaticAuto,
                &Ok(false),
                &[]
            ),
            BindingAction::Unavailable("selected adapter unavailable".into())
        );
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

    #[tokio::test(start_paused = true)]
    async fn watchdog_waits_for_solicitation_and_rejects_old_attempts() {
        use std::time::Duration;
        let counters = Arc::new(arp::SessionCounters::default());
        let (tx, mut rx) = tokio::sync::watch::channel(None);
        let (shutdown, mut stop) = tokio::sync::watch::channel(false);
        let after = tokio::time::Instant::now();
        let make = |generation, at| Solicitation {
            generation,
            at,
            baseline: counters.snapshot(),
        };
        let c = counters.clone();
        let watch = tokio::spawn(async move {
            watch_window(
                &c,
                &mut rx,
                2,
                Some(after),
                &mut stop,
                Duration::from_secs(10),
            )
            .await
        });
        tokio::time::advance(Duration::from_secs(300)).await;
        assert!(!watch.is_finished(), "idle time cannot start a window");
        tx.send_replace(Some(make(1, tokio::time::Instant::now())));
        tokio::task::yield_now().await;
        tx.send_replace(Some(make(2, after - Duration::from_secs(1))));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(20)).await;
        assert!(
            !watch.is_finished(),
            "old session/capture attempt cannot arm it"
        );
        tx.send_replace(Some(make(2, tokio::time::Instant::now())));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(!watch.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(watch.await.unwrap(), Some((0, 0)));
        drop(shutdown);
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_preserves_pre_send_baseline_and_idle_shutdown_wins() {
        let counters = arp::SessionCounters::default();
        let (tx, mut rx) = tokio::sync::watch::channel(None);
        let (shutdown, mut stop) = tokio::sync::watch::channel(false);
        let at = tokio::time::Instant::now();
        tx.send_replace(Some(Solicitation {
            generation: 1,
            at,
            baseline: counters.snapshot(),
        }));
        tokio::time::advance(std::time::Duration::from_secs(9)).await;
        // A delayed watchdog still expires ten seconds after the send.
        let start = tokio::time::Instant::now();
        assert_eq!(
            watch_window(
                &counters,
                &mut rx,
                1,
                None,
                &mut stop,
                std::time::Duration::from_secs(10)
            )
            .await,
            Some((0, 0))
        );
        assert_eq!(start.elapsed(), std::time::Duration::from_secs(1));
        shutdown.send(true).unwrap();
        assert!(watch_window(
            &counters,
            &mut rx,
            1,
            None,
            &mut stop,
            std::time::Duration::from_secs(10)
        )
        .await
        .is_none());
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
    fn fence_fresh_session_is_not_stale() {
        assert!(!fence(1, 1, true).is_stale());
    }

    #[test]
    fn fence_superseded_generation_is_stale() {
        // A newer start advanced the generation past this work's capture.
        assert!(fence(1, 2, true).is_stale());
    }

    #[test]
    fn fence_inactive_discovery_is_stale() {
        // A stop with no restart clears `active` without moving the
        // generation (Static Auto -> Manual) — must still read as stale.
        assert!(fence(1, 1, false).is_stale());
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
    fn removal_checks_exact_prefix_instead_of_enumeration_order() {
        let mut row = saved_binding("172.31.169.253");
        row.desired = crate::config::BindingDesired::Removed;
        let mut iface = saved_adapter(&["172.31.169.253", "192.168.1.20"]);
        iface.ips[0].prefix = 16;
        assert_eq!(
            binding_action(
                "172.31.169.0/24",
                &row,
                Some(&iface),
                crate::config::NetworkMode::StaticAuto,
                &Ok(false),
                &[]
            ),
            BindingAction::Hold("address exists with a different prefix".into(), false)
        );
    }

    #[test]
    fn routes_exclude_removed_and_pending_saved_bindings() {
        let mut live = HashMap::new();
        live.insert("10.0.0.0/24".to_string(), Ipv4Addr::new(10, 0, 0, 100));
        let mut meta = HashMap::from([("10.0.0.0/24".into(), saved_binding("10.0.0.100"))]);
        assert!(merge_adopted_config(&live, &meta).is_empty());
        let row = meta.get_mut("10.0.0.0/24").unwrap();
        row.applied = true;
        assert_eq!(merge_adopted_config(&live, &meta).len(), 1);
        meta.get_mut("10.0.0.0/24").unwrap().desired = crate::config::BindingDesired::Removed;
        assert!(merge_adopted_config(&live, &meta).is_empty());
        assert_eq!(meta.len(), 1);
    }

    #[test]
    fn routes_require_the_exact_saved_address() {
        let mut live = HashMap::new();
        live.insert("10.0.0.0/24".to_string(), Ipv4Addr::new(10, 0, 0, 100));
        let mut row = saved_binding("10.0.0.200");
        row.applied = true;
        let meta = HashMap::from([("10.0.0.0/24".into(), row)]);
        assert!(merge_adopted_config(&live, &meta).is_empty());
    }

    #[test]
    fn scan_guard_removes_subnet_on_drop() {
        // A cancelled scan_subnet future drops its ScanGuard, which must
        // clear the active-scan flag so later scans of that subnet aren't
        // permanently rejected.
        let active = Arc::new(std::sync::Mutex::new(HashSet::new()));
        active.lock().unwrap().insert("10.0.0.0/24".to_string());
        {
            let _g = ScanGuard {
                active: active.clone(),
                subnet: "10.0.0.0/24".to_string(),
            };
            assert!(active.lock().unwrap().contains("10.0.0.0/24"));
        }
        assert!(!active.lock().unwrap().contains("10.0.0.0/24"));
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
            store: manager.candidates.clone(),
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
        assert_eq!(manager.candidates.count(std::time::Instant::now()), 1);
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
                cached("AA:02", "192.168.1.101"),
            ],
            &["10.0.0.0/24".parse().unwrap()],
            &["192.168.1.101".parse().unwrap()].into_iter().collect(),
        );
        let records = registry.snapshot();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records.iter().find(|r| r.mac == "AA:01").unwrap().status,
            DeviceStatus::OfflineNonWiredSubnet
        );
        assert_eq!(
            records.iter().find(|r| r.mac == "AA:02").unwrap().status,
            DeviceStatus::OfflineHostOwnedIp
        );
        assert!(registry.merge_scan_result("AA:01", &[80]));
        assert!(registry.merge_scan_result("AA:02", &[80]));
        assert!(registry.snapshot().iter().all(|r| matches!(
            r.status,
            DeviceStatus::OfflineNonWiredSubnet | DeviceStatus::OfflineHostOwnedIp
        )));
    }
}
