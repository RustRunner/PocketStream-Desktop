pub mod adapter_refresh;
pub mod arp;
pub mod auto_adopt;
pub mod device_registry;
pub mod firewall;
pub mod ghost;
pub mod interface;
pub mod ip_config;
pub mod ping_dot;
// Cross-platform compilable (libloading + extern "system" types build
// everywhere; PktMonApi.dll only resolves at runtime on Windows) so the
// pure-layout unit tests gate on both CI jobs. The runtime capture path
// is consumed by the arp.rs listener; the availability probe is called
// only from the Windows startup block, so it reads as dead on Linux.
pub mod pktmon;
pub mod reaper;
pub mod scanner;
pub mod watcher;

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;

pub use arp::ArpDevice;
pub use device_registry::{DeviceListEmitter, DeviceRecord, DeviceRegistry, DeviceStatus};
pub use interface::InterfaceInfo;
pub use scanner::ScanResult;

use crate::error::AppError;

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
/// (only rows with open ports live there — same gate as scan-result
/// persistence) and the manual-nodes config list. Best-effort: a
/// failed write logs and the registry stays authoritative — the next
/// successful persist of the record self-heals the store.
pub(crate) fn persist_alias_writethrough(
    registry: &DeviceRegistry,
    config: &crate::config::AppConfig,
    ips: &[String],
) {
    let snapshot = registry.snapshot();
    for ip in ips {
        let Some(record) = snapshot.iter().find(|r| r.ip == *ip) else {
            continue;
        };
        if !record.open_ports.is_empty() {
            if let Err(e) = config.upsert_cached_device(crate::config::CachedDevice {
                mac: record.mac.clone(),
                ip: record.ip.clone(),
                subnet: record.subnet.clone(),
                open_ports: record.open_ports.clone(),
                alias: record.alias.clone(),
                last_seen: record.last_seen.clone(),
            }) {
                log::warn!("Failed to persist alias change for {} to cache: {}", ip, e);
            }
        }
        if let Err(e) = config.update_manual_node_alias(ip, &record.alias) {
            log::warn!(
                "Failed to write alias change for {} to manual nodes: {}",
                ip,
                e
            );
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

/// Hard ceiling on a single adoption attempt. A probe can take ~11 s (1 s
/// ping + up to a 10 s neighbor lookup) across up to 11 candidates, so the
/// natural worst case is tens of seconds; 45 s bounds a pathological run
/// without thrashing the cooldown on a merely slow box. On timeout the adopt
/// future is dropped (killing its child) and its pending IPs are reconciled.
const ADOPT_MAX_TOTAL: std::time::Duration = std::time::Duration::from_secs(45);

/// Settle delay before an adoption is announced finished, covering the NIC
/// watcher's ~300 ms debounce so the final IP-change up-event is gated too.
const ADOPTION_SETTLE: std::time::Duration = std::time::Duration::from_millis(300);

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

pub struct NetworkManager {
    active_scans: Arc<std::sync::Mutex<HashSet<String>>>,
    arp_devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    adopted_ips: Arc<Mutex<HashMap<String, Ipv4Addr>>>,
    arp_listener_handle: Arc<Mutex<Option<arp::ArpListenerHandle>>>,
    auto_adopt_handle: Arc<Mutex<Option<AutoAdoptHandle>>>,
    /// Secondary IPs the auto-adopt loop has bound but not yet handed over
    /// to `adopted_ips` (scratch probes and unrecorded final adds), tagged
    /// with the owning adoption id. Reconciled on stop so a cancelled or
    /// timed-out adoption never leaks an untracked IP.
    pending_ips: auto_adopt::PendingIps,
    /// Monotonic source of adoption ids: each adoption pass takes the next
    /// value to tag its `pending_ips` entries.
    adoption_seq: Arc<AtomicU64>,
    /// Config entries whose startup re-add failed transiently (subnet -> ip).
    /// Kept OUT of the live `adopted_ips` map (so the UI never badges an
    /// unbound IP) but unioned into every persisted config snapshot so a
    /// later in-session save doesn't delete them — they retry next startup.
    pending_restore: Arc<Mutex<HashMap<String, Ipv4Addr>>>,
    /// Quiet-network watchdog: emits `discovery-degraded` if the capture
    /// backend delivers no ARP payload events shortly after the provoking
    /// ping sweep, then `discovery-recovered` on the first frame.
    discovery_watchdog_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    interface_name: Arc<Mutex<Option<String>>>,
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
    /// Stale by the applicable evidence threshold (APIPA session
    /// TTL/startup grace, non-APIPA 24 h wall badge). Derived without
    /// the pin/rescue vetoes: an unprotected stale APIPA entry reaps
    /// within a tick of crossing its threshold, so a row that stays
    /// visible with this flag set is exactly the held/manual-only case.
    pub stale: bool,
}

/// Atomic snapshot of the adoption state for the frontend — the
/// routing map and the per-subnet metadata views taken together so the
/// two can never disagree.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdoptionSnapshot {
    pub adopted_subnets: HashMap<String, String>,
    pub meta: HashMap<String, AdoptedMetaView>,
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

/// Build the UI view of one adoption from the same verdict function
/// the reap pass uses, so the badge and the removal policy cannot
/// drift apart.
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

/// True when the wired adapter has no native IPv4 address — nothing
/// that isn't APIPA, an adopted secondary, or a still-pending adoption
/// bind. In that state APIPA bindings are the host's only connectivity
/// (the adoption rescue path), so the lifecycle check must not remove
/// any of them. An older adopted non-APIPA secondary deliberately does
/// not count as native: it must not make a DHCP-less host look
/// connected.
fn host_in_apipa_rescue(
    current_ips: &[Ipv4Addr],
    adopted_ips: &HashSet<Ipv4Addr>,
    pending_ips: &HashSet<Ipv4Addr>,
) -> bool {
    !current_ips
        .iter()
        .any(|ip| !ip.is_link_local() && !adopted_ips.contains(ip) && !pending_ips.contains(ip))
}

/// Adapter guards for an automatic unbind, mirroring shutdown cleanup:
/// never strip the adapter's primary address, and never leave it with
/// zero IPv4 addresses (Windows often disables such an adapter — far
/// worse than a stray secondary surviving another cycle). Returns the
/// reason the unbind is blocked, or `None` when it may proceed.
fn unbind_guard_blocks(ip: &str, adapter_ips: &[String]) -> Option<&'static str> {
    if adapter_ips.first().map(String::as_str) == Some(ip) {
        return Some("is the adapter's primary IP");
    }
    if adapter_ips.len() <= 1 && adapter_ips.iter().any(|a| a == ip) {
        return Some("would leave the adapter with no other IPv4 address");
    }
    None
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            active_scans: Arc::new(std::sync::Mutex::new(HashSet::new())),
            arp_devices: Arc::new(Mutex::new(HashMap::new())),
            adopted_ips: Arc::new(Mutex::new(HashMap::new())),
            arp_listener_handle: Arc::new(Mutex::new(None)),
            auto_adopt_handle: Arc::new(Mutex::new(None)),
            pending_ips: Arc::new(Mutex::new(Vec::new())),
            adoption_seq: Arc::new(AtomicU64::new(0)),
            pending_restore: Arc::new(Mutex::new(HashMap::new())),
            discovery_watchdog_handle: Arc::new(Mutex::new(None)),
            interface_name: Arc::new(Mutex::new(None)),
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
        let adopted: HashMap<String, String> = self
            .adopted_ips
            .lock()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect();
        let meta_map = self
            .adopted_meta
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default();
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
        let meta = adopted
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

    /// Record positive evidence (accepted ARP frame, successful targeted
    /// scan, successful ping) that a device exists on `ip`'s subnet.
    /// Cheap no-op unless that subnet is adopted. Metadata reaches disk
    /// at most once per `META_FLUSH_INTERVAL` from here; adoption and
    /// removal writes flush immediately through their own saves.
    pub async fn note_positive_liveness(&self, app_handle: &tauri::AppHandle, ip: Ipv4Addr) {
        let now = std::time::Instant::now();
        let wall = chrono::Utc::now().to_rfc3339();
        let landed = {
            let adopted = self.adopted_ips.lock().await;
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

    /// Persist the adoption pair (subnets ∪ pending restores, metadata)
    /// through the atomic config writer, off the executor (the save is
    /// an fsync under a std lock). Best-effort: a failure is logged and
    /// the in-memory state stays authoritative for the next flush or
    /// lifecycle save.
    pub async fn flush_adoption_state(&self, app_handle: &tauri::AppHandle) {
        let adopted = self.adopted_config_snapshot().await;
        let meta = self
            .adopted_meta
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default();
        let handle = app_handle.clone();
        let res = tokio::task::spawn_blocking(move || {
            use tauri::Manager;
            let config: tauri::State<'_, crate::config::AppConfig> = handle.state();
            config.update_adoption_state(adopted, meta)
        })
        .await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => log::warn!("Failed to persist adoption metadata: {}", e),
            Err(e) => log::warn!("Adoption metadata persist task failed to join: {}", e),
        }
    }

    /// Drop session liveness and in-memory metadata for subnets that
    /// are no longer adopted. The next config save (aligned inside the
    /// writer) drops their persisted metadata too.
    fn forget_adoption_tracking(&self, subnets: &[String]) {
        if subnets.is_empty() {
            return;
        }
        if let Ok(mut liveness) = self.adoption_liveness.lock() {
            for s in subnets {
                liveness.remove(s);
            }
        }
        if let Ok(mut meta) = self.adopted_meta.lock() {
            for s in subnets {
                meta.remove(s);
            }
        }
    }

    /// Hydrate the device registry from the on-disk cache. Idempotent
    /// (the registry's own one-shot guard prevents re-hydration), but
    /// expected to be called once at startup before ARP discovery so
    /// the initial snapshot reflects last-known state.
    ///
    /// Cached rows on a subnet owned by an up non-wired local interface
    /// (WiFi/VPN/virtual), or sitting at an IP this host currently owns,
    /// are filtered out before hydration and evicted from the on-disk
    /// cache, so ghost devices and stale self-rows don't reappear as nodes
    /// or persist across restarts. Rejection keys on ghost overlap or
    /// host-owned IP only — never on offline status — so a foreign/offline
    /// camera (CAM/PTU) is kept.
    pub async fn hydrate_device_registry(&self, config: &crate::config::AppConfig) {
        let cached = config.get_cache();

        // Fail-open: an empty ghost set (enumeration failure) rejects
        // nothing, so a transient adapter-query hiccup can't wipe the cache.
        let ghosts = ghost::non_wired_interface_networks().await;
        // Host-owned IPs: a cached row at one of our own current addresses
        // is the host itself, not a device (e.g. a self-row captured before
        // live discovery filtered our own traffic). Same fail-open contract.
        let local_ips: HashSet<Ipv4Addr> = interface::all_local_ipv4().into_iter().collect();
        let (allowed, rejected) = ghost::partition_cached(cached, &ghosts, &local_ips);

        let result = self.device_registry.hydrate_from_cache(&allowed);

        // Evict rejected rows from the on-disk cache (best-effort) so they
        // don't resurrect on next startup. Runs independently of
        // `result.changed` — if every cached row was rejected, nothing
        // hydrated but the cache still needs cleaning.
        for (device, reason) in &rejected {
            let why = match reason {
                ghost::CacheReject::NonWiredSubnet => "on a non-wired subnet",
                ghost::CacheReject::HostOwnedIp => "at a host-owned IP",
            };
            log::info!(
                "Evicting cached device {} ({}) — {}",
                device.ip,
                device.mac,
                why
            );
            if let Err(e) = config.remove_cached_device(&device.mac) {
                log::warn!("Failed to evict cache row {}: {}", device.mac, e);
            }
        }

        // Mirror same-IP dedup decisions onto the on-disk cache so the
        // orphans don't reappear on next startup. Cache file mutations
        // are best-effort: a failure logs but doesn't block boot.
        for mac in &result.dropped_macs {
            if let Err(e) = config.remove_cached_device(mac) {
                log::warn!("Failed to evict dupe cache row {}: {}", mac, e);
            }
        }

        // Legacy cache files can hold CAM/PTU on more than one row.
        // Repair to a single holder per role now that all rows are in,
        // and write the demotions back so they don't return next launch.
        let camera_ip = config.get().stream.camera_ip;
        let demoted = self
            .device_registry
            .normalize_role_duplicates(Some(&camera_ip));
        if !demoted.is_empty() {
            log::info!("Demoted duplicate role alias on {}", demoted.join(", "));
            persist_alias_writethrough(&self.device_registry, config, &demoted);
        }

        if !result.changed && rejected.is_empty() {
            return;
        }
        log::info!(
            "DeviceRegistry: hydrated {} cached device(s) (dropped {} dupe(s), evicted {} rejected row(s))",
            allowed.len() - result.dropped_macs.len(),
            result.dropped_macs.len(),
            rejected.len()
        );
    }

    /// Borrow the device registry. Used by IPC handlers that need to
    /// read snapshots or apply mutations.
    pub fn registry(&self) -> Arc<DeviceRegistry> {
        self.device_registry.clone()
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
        let hydrated = self.device_registry.hydrate_manual_nodes(&nodes);
        if hydrated {
            log::info!("DeviceRegistry: hydrated {} manual node(s)", count);
        }

        // Manual-node config rows can carry a legacy CAM/PTU alias that
        // collides with a discovered holder. Enforce the single-holder
        // invariant and write demotions back (registry + config), so a
        // mode toggle can't resurrect a duplicate.
        let camera_ip = config.get().stream.camera_ip;
        let demoted = self
            .device_registry
            .normalize_role_duplicates(Some(&camera_ip));
        if !demoted.is_empty() {
            persist_alias_writethrough(&self.device_registry, config, &demoted);
        }

        if hydrated || !demoted.is_empty() {
            if let Some(emitter) = self.device_emitter.lock().await.clone() {
                emitter.poke();
            }
        }
    }

    /// Apply a runtime mode change: swap the active subsystems and
    /// rehydrate the registry to match what the new mode considers
    /// the source of truth. The caller has already persisted the new
    /// mode to config.
    ///
    /// Manual ↔ non-Manual transitions are the only ones that move
    /// real machinery — Auto ↔ DHCP is handled implicitly by the
    /// auto-adopt loop's per-iteration DHCP-state probe.
    pub async fn apply_mode_change(
        &self,
        app_handle: tauri::AppHandle,
        config: &crate::config::AppConfig,
        old_mode: crate::config::NetworkMode,
        new_mode: crate::config::NetworkMode,
    ) -> Result<(), crate::error::AppError> {
        use crate::config::NetworkMode;

        if old_mode == new_mode {
            return Ok(());
        }
        log::info!("Mode change: {:?} → {:?}", old_mode, new_mode);

        // Serialize against start/stop so a mode-change teardown/restart
        // can't interleave with a concurrent discovery start.
        let _op = self.discovery_op.lock().await;

        if new_mode == NetworkMode::StaticManual {
            // Going INTO Manual: merge everything the Nodes panel is
            // currently showing (real-MAC entries with at least one
            // discovered open port) into manual_nodes. add_manual_node
            // is IP-keyed so existing pins keep their state — the
            // merge is additive, not replacing.
            //
            // Runs on every Auto→Manual transition so a user who runs
            // discovery, switches to Manual, later flips back to Auto
            // to find more devices, then returns to Manual gets the
            // newly-discovered items merged in. If they don't want a
            // pin, they delete it from the modal; if the underlying
            // device is still on the broadcast domain a future
            // round-trip will re-pin it.
            let snapshot = self.device_registry.snapshot();
            for record in snapshot {
                if record.mac.starts_with("manual:") {
                    continue;
                }
                if record.open_ports.is_empty() {
                    continue;
                }
                let node = crate::config::ManualNode {
                    ip: record.ip,
                    alias: record.alias,
                };
                if let Err(e) = config.add_manual_node(node) {
                    log::warn!("Failed to auto-pin discovered device: {}", e);
                }
            }
            self.stop_locked().await;
            self.device_registry.clear();
            self.hydrate_manual_nodes(config).await;
        } else if old_mode == NetworkMode::StaticManual {
            // Leaving Manual: drop manual hydrations, restore the
            // cache, restart ARP discovery if an interface is known.
            self.device_registry.clear();
            self.hydrate_device_registry(config).await;
            if let Some(emitter) = self.device_emitter.lock().await.clone() {
                emitter.poke();
            }
            if crate::is_discovery_available() {
                let cached_name = self.interface_name.lock().await.clone();
                let iface = match cached_name {
                    Some(n) => Some(n),
                    None => interface::list_physical().await.ok().and_then(|list| {
                        list.into_iter()
                            .find(|i| interface::is_wired_ethernet(i) && !i.ips.is_empty())
                            .map(|i| i.name)
                    }),
                };
                if let Some(name) = iface {
                    if let Err(e) = self
                        .start_arp_discovery_locked(&name, app_handle.clone())
                        .await
                    {
                        log::warn!("Failed to start ARP after mode change: {}", e);
                    }
                }
            }
        }

        // Refresh the pinger so the next sweep targets the new set.
        self.start_ping_dot(app_handle).await;
        Ok(())
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

    /// Load previously adopted subnets from config and verify they still
    /// exist on the adapter. Re-add any that are missing.
    ///
    /// Entries whose subnet matches the adapter's native IPs are pruned —
    /// they were either saved by mistake or the adapter's primary IP
    /// changed to cover that subnet since the adoption.
    ///
    /// Concurrency: the `adopted_ips` mutex is held only for the synchronous
    /// classify+insert phase (microseconds). The slow netsh re-add calls run
    /// outside the lock — and in parallel — so IPC handlers querying the map
    /// during cold start aren't blocked behind a sequence of 100–500ms netsh
    /// invocations.
    ///
    /// `app_handle` is used to emit a `subnet-adopted` event for each
    /// restored entry so the frontend can populate its `adoptedSubnets`
    /// Map without racing the cold-start `getAdoptedSubnets` call. Without
    /// this signal, the frontend would query the in-memory map BEFORE
    /// Phase 1 completes (especially on slow Windows boxes where
    /// `interface::list_physical()` takes 100–300 ms), find it empty, and
    /// then never re-pull it — leaving restored IPs rendered as if they
    /// were native (no `(auto)` badge, wrong sort order).
    pub async fn load_adopted_from_config(
        &self,
        config: &crate::config::AppConfig,
        app_handle: &tauri::AppHandle,
    ) {
        let settings = config.get();
        if settings.adopted_subnets.is_empty() {
            return;
        }

        // Serialize against discovery start/stop: a watcher-driven start
        // must not spawn the auto-adopt loop while we're mid-restore (both
        // mutate adopted_ips and bind secondary IPs), and vice versa.
        let _op = self.discovery_op.lock().await;

        // Get the active ethernet interface
        let iface = match interface::list_physical().await {
            Ok(interfaces) => interfaces
                .into_iter()
                .find(|i| interface::is_wired_ethernet(i) && !i.ips.is_empty()),
            Err(_) => None,
        };

        let iface = match iface {
            Some(i) => i,
            None => {
                log::info!("No active interface — skipping adopted subnet restore");
                return;
            }
        };

        // Structural-ghost networks owned by up, non-wired local interfaces
        // (WiFi/VPN/virtual). Fails open to empty on an enumeration error, so
        // a transient adapter-query failure just skips ghost pruning this
        // boot rather than dropping legitimate adoptions.
        let ghosts = ghost::non_wired_interface_networks().await;

        // Build the set of /24 subnets the adapter already covers natively.
        // "Native" means: an IP on the adapter that is NOT the result of a
        // previous adoption. Without this filter, Windows' registry-backed
        // persistence of adopted secondary IPs makes every adopted subnet
        // look native on the next launch, and the pruning loop below would
        // wipe the config on every reboot — collapsing the primary/adopted
        // distinction in the UI.
        let adopted_ip_strs: HashSet<&String> = settings.adopted_subnets.values().collect();
        let native_subnets: HashSet<String> = iface
            .ips
            .iter()
            .filter(|ip| !adopted_ip_strs.contains(&ip.address))
            .filter_map(|ip| ip.address.parse::<Ipv4Addr>().ok())
            .map(|ip| {
                let o = ip.octets();
                format!("{}.{}.{}.0/24", o[0], o[1], o[2])
            })
            .collect();

        let current_ips: HashSet<String> = iface.ips.iter().map(|ip| ip.address.clone()).collect();

        // ── Phase 1: classify (no live insert) ──
        // Each surviving entry produces (subnet, ip_str, needs_netsh_add).
        // Nothing is inserted into the live `adopted_ips` map here — an
        // entry becomes live only once Phase 2 confirms it is bound, so the
        // UI never badges an IP that isn't actually on the adapter.
        let mut work_items: Vec<(String, String, bool)> = Vec::new();
        let mut kept: HashMap<String, String> = HashMap::new();
        let mut pruned = false;
        // Ghost adoptions whose secondary IP is still bound on the adapter (a
        // previous run crashed before shutdown cleanup) — unbound after the
        // config persist below.
        let mut ghost_bound: Vec<(String, String)> = Vec::new();
        for (subnet, ip_str) in &settings.adopted_subnets {
            match ghost::classify_adoption(subnet, ip_str, &native_subnets, &ghosts) {
                ghost::AdoptionClass::PruneNative => {
                    log::info!(
                        "Pruning adopted subnet {} ({}) — adapter already covers it natively",
                        subnet,
                        ip_str,
                    );
                    pruned = true;
                }
                ghost::AdoptionClass::PruneGhost => {
                    // Auto-heal a persisted WiFi/VPN/virtual-switch adoption:
                    // drop it from config and never re-bind it.
                    log::info!(
                        "Pruning adopted subnet {} ({}) — owned by a non-wired local interface (WiFi/VPN/virtual)",
                        subnet,
                        ip_str,
                    );
                    pruned = true;
                    // If the IP is still bound (a crash left it behind), queue
                    // it for an explicit unbind after the config persist.
                    if current_ips.contains(ip_str) {
                        ghost_bound.push((subnet.clone(), ip_str.clone()));
                    }
                }
                ghost::AdoptionClass::PruneInvalid => {
                    // Unparseable IP — proven invalid, drop it from config.
                    log::warn!("Dropping adopted subnet {} — invalid IP {}", subnet, ip_str);
                    pruned = true;
                }
                ghost::AdoptionClass::Keep => {
                    kept.insert(subnet.clone(), ip_str.clone());
                    work_items.push((
                        subnet.clone(),
                        ip_str.clone(),
                        !current_ips.contains(ip_str),
                    ));
                }
            }
        }

        // Seed the in-memory metadata working copy for the surviving
        // entries. Config load already backfilled legacy gaps, so every
        // kept subnet has an entry; pruned subnets are dropped here and
        // from the persisted map below.
        if let Ok(mut meta) = self.adopted_meta.lock() {
            *meta = settings
                .adopted_meta
                .iter()
                .filter(|(subnet, _)| kept.contains_key(*subnet))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
        }

        // Persist the pruned config (original − natively-covered − invalid),
        // computed independently of which re-adds later succeed: a transient
        // re-add failure must keep its config entry for a retry. Only write
        // when something was actually dropped. Lifecycle metadata rides the
        // same write: alignment inside the updater drops the pruned
        // subnets' metadata and backfills legacy entries that never had
        // any.
        if pruned {
            match config.update_adoption_state(kept, settings.adopted_meta.clone()) {
                Ok(()) => log::info!("Saved pruned adopted subnets to config"),
                Err(e) => log::warn!("Failed to persist pruned adopted subnets: {}", e),
            }
        }

        // Crash-leftover cleanup: a ghost adoption whose secondary IP is
        // still bound on the wired port (a prior run exited without cleanup)
        // is unbound here so the port isn't left holding a WiFi/VPN address.
        // Runs after the config persist so a failed unbind can't block the
        // prune. Guards mirror shutdown cleanup: never strip the adapter's
        // last IPv4 or its primary native address.
        if !ghost_bound.is_empty() {
            let primary_native: Option<&String> = iface
                .ips
                .iter()
                .map(|ip| &ip.address)
                .find(|addr| !adopted_ip_strs.contains(addr));
            for (subnet, ip_str) in &ghost_bound {
                if iface.ips.len() < 2 {
                    log::warn!(
                        "Skipping ghost unbind of {} ({}): would leave the adapter with no other IPv4 address",
                        ip_str,
                        subnet
                    );
                    continue;
                }
                if primary_native == Some(ip_str) {
                    log::warn!(
                        "Skipping ghost unbind of {} ({}): is the adapter's primary IP",
                        ip_str,
                        subnet
                    );
                    continue;
                }
                match auto_adopt::remove_adopted_ip(&iface.name, ip_str).await {
                    Ok(()) => {
                        log::info!("Unbound crash-leftover ghost IP {} ({})", ip_str, subnet)
                    }
                    Err(e) => log::warn!(
                        "Failed to unbind crash-leftover ghost IP {} ({}): {}",
                        ip_str,
                        subnet,
                        e
                    ),
                }
            }
        }

        // ── Phase 2: netsh re-add in parallel, outside the lock ────
        // Each task reports whether its IP is confirmed bound. Recording is
        // done back here (not in the task) so the live map / pending_restore
        // mutations and the success-only `subnet-adopted` emit happen in one
        // place with `&self` in scope.
        let mut tasks: tokio::task::JoinSet<(String, String, bool)> = tokio::task::JoinSet::new();
        for (subnet, ip_str, needs_add) in work_items {
            let iface_name = iface.name.clone();
            tasks.spawn(async move {
                let added_ok = if needs_add {
                    log::info!("Re-adding missing adopted IP {} to {}", ip_str, iface_name);
                    match ip_config::add_secondary_ip(&iface_name, &ip_str, "255.255.255.0").await {
                        Ok(()) => true,
                        Err(e) => {
                            log::warn!(
                                "Failed to re-add adopted IP {} ({}): {}",
                                ip_str,
                                subnet,
                                e
                            );
                            false
                        }
                    }
                } else {
                    log::info!("Adopted IP {} already on adapter", ip_str);
                    true
                };
                (subnet, ip_str, added_ok)
            });
        }

        // Confirmed-bound entries go live and emit `subnet-adopted`; a
        // transiently-failed re-add is held in `pending_restore` — not shown
        // as a live route, but retried next startup and never dropped from
        // config by an in-session save.
        use tauri::Emitter;
        while let Some(res) = tasks.join_next().await {
            let (subnet, ip_str, added_ok) = match res {
                Ok(t) => t,
                Err(e) => {
                    log::warn!("Adopted-restore task failed to join: {}", e);
                    continue;
                }
            };
            let ip: Ipv4Addr = match ip_str.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            if added_ok {
                self.adopted_ips.lock().await.insert(subnet.clone(), ip);
                self.pending_restore.lock().await.remove(&subnet);
                // A just-restored entry is never stale: its startup
                // grace begins with the discovery session, and the
                // badge is re-derived from the adoption snapshot
                // whenever the UI re-pulls it.
                let restored_meta = self
                    .adopted_meta
                    .lock()
                    .ok()
                    .and_then(|m| m.get(&subnet).cloned())
                    .unwrap_or_default();
                let _ = app_handle.emit(
                    "subnet-adopted",
                    serde_json::json!({
                        "subnet": subnet,
                        "adopted_ip": ip_str,
                        "adopted_at": restored_meta.adopted_at,
                        "last_device_seen": restored_meta.last_device_seen,
                        "stale": false,
                    }),
                );
            } else {
                self.pending_restore.lock().await.insert(subnet.clone(), ip);
                log::warn!(
                    "Adopted restore held for retry: {} ({}) — re-add failed",
                    subnet,
                    ip_str
                );
            }
        }
    }

    /// The config snapshot to persist: the live adopted map unioned with the
    /// pending-restore holds (live wins on conflict). Persisting only the
    /// live map would silently drop a transiently-failed restore.
    async fn adopted_config_snapshot(&self) -> HashMap<String, String> {
        let live = self.adopted_ips.lock().await.clone();
        let pending = self.pending_restore.lock().await.clone();
        merge_adopted_config(&live, &pending)
    }

    /// Save current adopted subnets and their lifecycle metadata to
    /// config in one atomic write.
    pub async fn save_adopted_to_config(&self, config: &crate::config::AppConfig) {
        let adopted = self.adopted_config_snapshot().await;
        let meta = self
            .adopted_meta
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default();
        if let Err(e) = config.update_adoption_state(adopted, meta) {
            log::warn!("Failed to save adopted subnets: {}", e);
        }
    }

    pub async fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>, AppError> {
        interface::list_physical().await
    }

    pub async fn get_interface(&self, name: &str) -> Result<InterfaceInfo, AppError> {
        interface::get_by_name(name).await
    }

    pub async fn scan_subnet(&self, subnet: &str) -> Result<Vec<ScanResult>, AppError> {
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
        scanner::scan(subnet).await
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
        app_handle: tauri::AppHandle,
    ) -> Result<(), AppError> {
        let _op = self.discovery_op.lock().await;
        self.start_arp_discovery_locked(interface_display_name, app_handle)
            .await
    }

    /// Start body, run with the discovery op lock already held. Callers
    /// that already hold it (`apply_mode_change`) delegate here so the
    /// non-reentrant lock isn't acquired twice.
    async fn start_arp_discovery_locked(
        &self,
        interface_display_name: &str,
        app_handle: tauri::AppHandle,
    ) -> Result<(), AppError> {
        self.stop_locked().await;

        // New discovery session: advance the generation and mark discovery
        // active so sweeps and capture frames from a prior session can
        // fence themselves out (that work captures the generation; the
        // active flag also covers a stop with no restart).
        let generation = self.discovery_generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.discovery_active.store(true, Ordering::Relaxed);
        log::debug!("Discovery session generation → {}", generation);

        // Session fence shared by the capture listener and every sweep so
        // stale-session work (from a prior session, or after a stop) drops
        // itself before merging or emitting into the shared registry.
        let fence = SweepFence::new(
            generation,
            self.discovery_generation.clone(),
            self.discovery_active.clone(),
        );

        *self.interface_name.lock().await = Some(interface_display_name.to_string());

        let devices = self.arp_devices.clone();
        let adopted = self.adopted_ips.clone();
        let pending_ips = self.pending_ips.clone();
        let adoption_seq = self.adoption_seq.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let iface_name = interface_display_name.to_string();
        let app_handle_for_adopt = app_handle.clone();

        // Get current IPs so auto-adopt knows which subnets are "known".
        // The adapter's MAC serves double duty: the capture session is
        // attach-time scoped to the data source carrying this MAC, and
        // the listener drops ARP frames the adapter itself sent (our own
        // gratuitous ARP).
        let iface_info = interface::get_by_name(interface_display_name).await?;
        // Backend authority: discovery only ever runs on an up, wired
        // Ethernet adapter, no matter what name a caller supplied. The
        // frontend mirrors this in its selection filters, but the backend
        // is the enforcement point.
        if !interface::is_wired_ethernet(&iface_info) {
            return Err(AppError::Network(format!(
                "'{}' is not an up, wired Ethernet adapter — ARP discovery only runs on the wired camera port",
                interface_display_name
            )));
        }
        let known_ips: Vec<String> = iface_info.ips.iter().map(|ip| ip.address.clone()).collect();
        let own_mac = parse_mac_bytes(&iface_info.mac);
        // Capture identity for attach-time scoping: the same MAC that
        // feeds the own-frame filter, plus the display name for logs. A
        // None MAC (unparseable) makes the join fail and the capture
        // fall back to an unscoped session rather than guessing.
        let capture_scope = pktmon::CaptureScope {
            mac: own_mac,
            display_name: interface_display_name.to_string(),
        };

        // Every IPv4 currently assigned to any local adapter — not just the
        // camera port. The capture listener drops ARP sent from any of
        // these so the host never lists itself as a node (its own WiFi
        // traffic on a subnet shared with the wired port passes every other
        // filter). The adopt loop refreshes the set each pass because
        // addresses move under us (DHCP renew, WiFi roam).
        let local_ips: Arc<StdMutex<HashSet<Ipv4Addr>>> = Arc::new(StdMutex::new(
            interface::all_local_ipv4().into_iter().collect(),
        ));
        log::info!(
            "Starting ARP discovery on '{}' (IPs: {:?}, mac: {})",
            interface_display_name,
            known_ips,
            iface_info.mac
        );

        // Scope discovery to the wired Ethernet port. The capture backend
        // is unscoped, so enumerate the subnets owned exclusively by
        // non-wired interfaces (WiFi/VPN/virtual) and drop ARP for any peer
        // on them. Cameras on the Ethernet subnet, or on a foreign/APIPA
        // subnet awaiting adoption, are untouched.
        let excluded_subnets = ghost::non_wired_interface_networks().await;
        if excluded_subnets.is_empty() {
            log::info!("Discovery: no non-wired subnets to exclude");
        } else {
            log::info!(
                "Discovery excluding non-wired (WiFi/VPN/virtual) subnets: {:?}",
                excluded_subnets
            );
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

        let handle = arp::start_listener(
            devices.clone(),
            registry.clone(),
            emitter.clone(),
            app_handle,
            local_ips.clone(),
            own_mac,
            fence.clone(),
            excluded_subnets.clone(),
            capture_scope,
        )?;
        *self.arp_listener_handle.lock().await = Some(handle);

        // Ping sweep known subnets to provoke ARP traffic so the capture
        // listener sees all devices, then read the OS ARP table to catch
        // cached entries that didn't generate new ARP packets on the wire.
        let sweep_ips = known_ips.clone();
        let sweep_devices = self.arp_devices.clone();
        let sweep_registry = registry.clone();
        let sweep_emitter = emitter.clone();
        let sweep_app_handle = app_handle_for_adopt.clone();
        let sweep_fence = fence.clone();
        let sweep_excluded = excluded_subnets;
        let sweep_local = local_ips.clone();
        tokio::spawn(async move {
            // Small delay to let the capture listener start first
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            // If discovery already restarted (or stopped) during that delay,
            // this sweep belongs to a dead session — don't touch the registry.
            if sweep_fence.is_stale() {
                return;
            }
            log::info!("Ping sweeping known subnets to populate ARP");
            ping_sweep_subnets(&sweep_ips).await;

            // One brief-lock snapshot for the whole merge pass (never lock
            // per entry); a poisoned lock degrades to an empty set, which
            // filters nothing — fail-open.
            let local_snapshot: HashSet<Ipv4Addr> =
                sweep_local.lock().map(|s| s.clone()).unwrap_or_default();

            // Merge the OS neighbor table for EVERY local/adopted IP, not
            // just the first — a neighbor learned via an adopted secondary
            // subnet would otherwise be missed at boot (in-session sweeps
            // cover it post-adoption, but not the cold-start merge). The
            // map dedup makes the extra queries harmless.
            for sweep_iface_ip in &sweep_ips {
                if sweep_fence.is_stale() {
                    break;
                }
                if sweep_iface_ip.is_empty() {
                    continue;
                }
                merge_arp_table(
                    sweep_devices.clone(),
                    sweep_registry.clone(),
                    sweep_emitter.clone(),
                    sweep_app_handle.clone(),
                    sweep_iface_ip,
                    &sweep_excluded,
                    &local_snapshot,
                    &sweep_fence,
                )
                .await;
            }
        });

        // Quiet-network watchdog. The ping sweep above provokes ARP; if
        // the capture backend delivers no parsed frames within the window
        // after it, discovery is degraded (e.g. a layout/floor issue where
        // the session starts but no payload arrives). This is a diagnostic
        // only — it never flips availability, and emits at most one
        // degraded per session, cleared by a recovered on the first frame.
        let watchdog_app = app_handle_for_adopt.clone();
        let watchdog = tokio::spawn(async move {
            use tauri::Emitter;
            // Longer than the 500 ms sweep-start delay plus the sweep
            // itself, so a healthy backend has time to deliver frames.
            const INITIAL_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
            const POLL: std::time::Duration = std::time::Duration::from_secs(2);
            const MAX_WATCH: std::time::Duration = std::time::Duration::from_secs(300);

            let baseline = arp::frames_seen();
            tokio::time::sleep(INITIAL_WINDOW).await;
            if arp::frames_seen() > baseline {
                return; // capture is delivering — healthy, no event
            }

            let missed = arp::missed_max();
            log::warn!(
                "Discovery degraded: no ARP payload events within {}s of the ping sweep (missed_max={}, tasks_dropped={}, noneth_dropped={}, self_ip_dropped={})",
                INITIAL_WINDOW.as_secs(),
                missed,
                arp::tasks_dropped(),
                arp::noneth_dropped(),
                arp::self_ip_dropped()
            );
            let _ = watchdog_app.emit(
                "discovery-degraded",
                serde_json::json!({
                    "reason": "no-payload-events",
                    "missed_packets": missed,
                }),
            );

            // Watch for the first frame (bounded — don't linger forever on
            // a genuinely dead backend; the single degraded warning stands).
            let mut waited = std::time::Duration::ZERO;
            while waited < MAX_WATCH {
                tokio::time::sleep(POLL).await;
                waited += POLL;
                if arp::frames_seen() > baseline {
                    log::info!("Discovery recovered: ARP payload events resumed");
                    let _ = watchdog_app.emit("discovery-recovered", serde_json::json!({}));
                    return;
                }
            }
        });
        *self.discovery_watchdog_handle.lock().await = Some(watchdog);

        // Auto-adopt handler for foreign subnets
        let devices_for_adopt = devices.clone();
        let registry_for_adopt = registry.clone();
        let emitter_for_adopt = emitter.clone();
        let fence_for_loop = fence.clone();
        let pending_restore = self.pending_restore.clone();
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
            // AdoptOps in scope: the reap pass calls the unbind through
            // the same seam the adoption rollback paths use.
            use auto_adopt::AdoptOps;
            use tauri::Emitter;
            use tauri::Manager;
            let mut shutdown_rx = shutdown_rx;
            let ops = auto_adopt::RealAdoptOps;
            let mut known_subnets: HashSet<String> = HashSet::new();
            // Two-observation gate: a subnet is adopted only after its
            // triggering device produces a second accepted ARP frame, so
            // a single spurious frame (which sits in the persistent
            // device map forever) can no longer bind a secondary IP.
            let mut dwell = auto_adopt::DwellTracker::new();
            // Failed or guard-blocked reaps back off here (60 s doubling
            // to 10 min, like adoption failures) instead of retrying —
            // and re-logging — every 2 s tick.
            let mut reap_cooldowns: HashMap<String, (std::time::Instant, std::time::Duration)> =
                HashMap::new();
            // Unparseable adoption keys are warned about once, then left
            // to the existing restore/manual-removal behavior.
            let mut invalid_warned: HashSet<String> = HashSet::new();

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
            const DHCP_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);

            // Cooldown for subnets whose adoption FAILED (transient netsh
            // errors, a candidate that turned out to be in use, etc.).
            // Replaces the old permanent blacklist: subnet -> (next retry
            // time, current backoff). Backoff doubles from 60s, capped at
            // 10 min. Successful/already-adopted subnets use known_subnets
            // (permanent) as before.
            let mut cooldowns: HashMap<String, (std::time::Instant, std::time::Duration)> =
                HashMap::new();
            const COOLDOWN_INITIAL: std::time::Duration = std::time::Duration::from_secs(60);
            const COOLDOWN_MAX: std::time::Duration = std::time::Duration::from_secs(600);

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

                // ── Adoption lifecycle pass ─────────────────────────────
                // Runs every tick BEFORE the DHCP gate below: reaping is
                // maintenance of existing bindings and must keep running
                // while new adoption is paused — that is the common state
                // in which a stale APIPA binding should disappear. The
                // cheap no-veto verdict screens first; only a would-reap
                // entry pays for the config/registry/interface reads.
                let adopted_snapshot: HashMap<String, Ipv4Addr> = adopted.lock().await.clone();
                for (reap_subnet, reap_ip) in &adopted_snapshot {
                    let parsed = reaper::parse_subnet_key(reap_subnet);
                    if parsed.is_none() {
                        if invalid_warned.insert(reap_subnet.clone()) {
                            log::warn!(
                                "Adopted subnet key {} does not parse — never auto-removed, remove manually if stale",
                                reap_subnet
                            );
                        }
                        continue;
                    }
                    let last_positive_elapsed = liveness_for_adopt
                        .lock()
                        .ok()
                        .and_then(|l| l.get(reap_subnet).map(|t| t.elapsed()));
                    let base_input = reaper::LifecycleInput {
                        subnet: parsed,
                        last_positive_elapsed,
                        session_elapsed: session_started.elapsed(),
                        pinned: false,
                        host_rescued: false,
                        badge_age: None,
                    };
                    if reaper::lifecycle_verdict(&base_input) != reaper::ReapVerdict::Reap {
                        continue;
                    }
                    if let Some(&(retry_at, _)) = reap_cooldowns.get(reap_subnet) {
                        if std::time::Instant::now() < retry_at {
                            continue;
                        }
                    }

                    // TTL crossed and not cooling down — gather the veto
                    // inputs. Pinned: any user-pinned device (alias,
                    // manual node, configured stream target) inside the
                    // subnet, whether or not it has a registry record.
                    let pins = {
                        let config: tauri::State<'_, crate::config::AppConfig> =
                            app_handle_for_adopt.state();
                        device_registry::configured_pins(&config.get())
                    };
                    let mut pinned_ips = registry_for_adopt.user_pinned_ips(&pins);
                    pinned_ips.extend(pins.iter().filter_map(|p| p.parse::<Ipv4Addr>().ok()));
                    let pinned = pinned_ips
                        .iter()
                        .any(|ip| &subnet_key_for(*ip) == reap_subnet);

                    let current_ips = get_interface_ips(&iface_name).await;
                    let adopted_vals: HashSet<Ipv4Addr> =
                        adopted_snapshot.values().copied().collect();
                    let pending_vals: HashSet<Ipv4Addr> =
                        pending_ips.lock().await.iter().map(|p| p.ip).collect();
                    let host_rescued =
                        host_in_apipa_rescue(&current_ips, &adopted_vals, &pending_vals);

                    let verdict = reaper::lifecycle_verdict(&reaper::LifecycleInput {
                        pinned,
                        host_rescued,
                        ..base_input
                    });
                    if verdict != reaper::ReapVerdict::Reap {
                        // Vetoed: stale-but-held. The UI badges it from
                        // the adoption snapshot; nothing to do here.
                        continue;
                    }

                    // Adapter guards, mirroring shutdown cleanup. A
                    // blocked reap arms the cooldown so the warning
                    // doesn't repeat every 2 s.
                    let adapter_ip_strs: Vec<String> = interface::get_by_name(&iface_name)
                        .await
                        .map(|i| i.ips.iter().map(|ip| ip.address.clone()).collect())
                        .unwrap_or_default();
                    if let Some(reason) =
                        unbind_guard_blocks(&reap_ip.to_string(), &adapter_ip_strs)
                    {
                        log::warn!(
                            "Holding reap of stale adoption {} ({}): {} — re-checking in {}s",
                            reap_subnet,
                            reap_ip,
                            reason,
                            COOLDOWN_INITIAL.as_secs()
                        );
                        reap_cooldowns.insert(
                            reap_subnet.clone(),
                            (
                                std::time::Instant::now() + COOLDOWN_INITIAL,
                                COOLDOWN_INITIAL,
                            ),
                        );
                        continue;
                    }

                    // Unbind first; only a successful OS removal may drop
                    // live state, so a failure can't strand a bound IP
                    // the maps no longer know about.
                    match ops.remove(&iface_name, *reap_ip).await {
                        Ok(()) => {
                            adopted.lock().await.remove(reap_subnet);
                            pending_restore.lock().await.remove(reap_subnet);
                            // Clear the loop-local traces too: a reaped
                            // subnet must be able to re-adopt in this
                            // session once a device really returns (the
                            // dwell gate demands two fresh observations,
                            // which is thrash protection enough).
                            known_subnets.remove(reap_subnet);
                            dwell.prune_subnet(reap_subnet);
                            reap_cooldowns.remove(reap_subnet);
                            if let Ok(mut liveness) = liveness_for_adopt.lock() {
                                liveness.remove(reap_subnet);
                            }
                            if let Ok(mut meta) = meta_for_adopt.lock() {
                                meta.remove(reap_subnet);
                            }

                            let live = adopted.lock().await.clone();
                            let pend = pending_restore.lock().await.clone();
                            let snapshot = merge_adopted_config(&live, &pend);
                            let meta_snapshot =
                                meta_for_adopt.lock().map(|m| m.clone()).unwrap_or_default();
                            let persist_handle = app_handle_for_adopt.clone();
                            let persisted = tokio::task::spawn_blocking(move || {
                                let config: tauri::State<'_, crate::config::AppConfig> =
                                    persist_handle.state();
                                config.update_adoption_state(snapshot, meta_snapshot)
                            })
                            .await;
                            match persisted {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => log::warn!(
                                    "Failed to persist reap of {} to config: {}",
                                    reap_subnet,
                                    e
                                ),
                                Err(e) => log::warn!(
                                    "Reap persist task for {} failed to join: {}",
                                    reap_subnet,
                                    e
                                ),
                            }

                            let _ = app_handle_for_adopt.emit(
                                "subnet-removed",
                                serde_json::json!({
                                    "subnet": reap_subnet,
                                    "adopted_ip": reap_ip.to_string(),
                                    "reason": "stale_apipa",
                                }),
                            );
                            log::info!(
                                "Reaped stale APIPA adoption {} ({}): no positive device evidence within the lifecycle window",
                                reap_subnet,
                                reap_ip
                            );
                        }
                        Err(e) => {
                            let next_backoff = reap_cooldowns
                                .get(reap_subnet)
                                .map(|(_, b)| (*b * 2).min(COOLDOWN_MAX))
                                .unwrap_or(COOLDOWN_INITIAL);
                            reap_cooldowns.insert(
                                reap_subnet.clone(),
                                (std::time::Instant::now() + next_backoff, next_backoff),
                            );
                            log::warn!(
                                "Failed to unbind stale adoption {} ({}): {} — retrying in {}s",
                                reap_subnet,
                                reap_ip,
                                e,
                                next_backoff.as_secs()
                            );
                        }
                    }
                }

                // Gate the adoption pass on host mode: while the adapter
                // is DHCP and *has a real lease*, any secondary we add is
                // at the mercy of the next renew/release cycle, so pause
                // until the user transitions to Static. BUT when DHCP has
                // failed to a 169.254/16 APIPA-only state, auto-adopt is
                // the user's only path to connectivity — keep it running
                // as a rescue. Read failures fail-open (treat as Static)
                // so a broken cmdlet doesn't permanently silence adoption.
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
                                "DHCP-state probe failed for {} ({}), allowing adoption",
                                iface_name,
                                e
                            );
                            // Cache the fail-open verdict with the same TTL
                            // as a success — otherwise a persistent probe
                            // failure re-spawns PowerShell every 2s instead
                            // of every 5s.
                            cached_dhcp_state = Some((false, std::time::Instant::now()));
                            false
                        }
                    }
                } else {
                    cached_dhcp_state.map(|(d, _)| d).unwrap_or(false)
                };

                if is_dhcp {
                    let current_ips = get_interface_ips(&iface_name).await;
                    let has_real_lease = current_ips.iter().any(|ip| !ip.is_link_local());
                    if has_real_lease {
                        continue;
                    }
                    // APIPA-only DHCP: fall through and adopt as rescue.
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

                    // Derive the subnet from the live IP rather than trusting
                    // the stored device.subnet — a device that first ARPed
                    // from APIPA then re-ARPed from its real address can carry
                    // a stale subnet, which would key the adoption wrongly.
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

                    // Structural-ghost guard: never adopt a subnet owned by an
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
                            continue;
                        }
                        auto_adopt::DwellVerdict::Waiting => continue,
                        auto_adopt::DwellVerdict::Mature => {}
                    }

                    log::info!(
                        "Foreign subnet {} confirmed by a repeat observation from {} — adopting",
                        device_subnet,
                        device.mac
                    );

                    let adoption_id = adoption_seq.fetch_add(1, Ordering::Relaxed) + 1;
                    // Bracket the adoption with started/finished so the
                    // frontend suppresses restarts from its own IP churn.
                    // The guard emits `adoption-finished` on drop, so every
                    // terminal path below (success, timeout, error, break,
                    // task abort) releases the gate.
                    let _gate = AdoptionGate::start(app_handle_for_adopt.clone(), adoption_id);
                    // Fresh read at adoption time (not the shared filter
                    // set): candidate-collision checking wants the newest
                    // possible view of our own addresses, and the name must
                    // not shadow the shared `local_ips` the post-adoption
                    // sweep clones below.
                    let host_ips_now = interface::all_local_ipv4();
                    let started = std::time::Instant::now();
                    let outcome = tokio::time::timeout(
                        ADOPT_MAX_TOTAL,
                        auto_adopt::adopt_subnet(
                            &ops,
                            &iface_name,
                            device_ip,
                            &current_ips,
                            &host_ips_now,
                            &pending_ips,
                            adoption_id,
                            &shutdown_rx,
                        ),
                    )
                    .await;

                    match outcome {
                        Err(_elapsed) => {
                            // ADOPT_MAX_TOTAL hit: the adopt future is dropped
                            // now, so kill-on-drop took any in-flight child.
                            // Reconcile whatever it bound and re-arm the
                            // cooldown. Logged distinctly so the bound can be
                            // retuned from field data.
                            log::warn!(
                                "Adoption of {} exceeded the {}s bound (elapsed {}s) — dropped and reconciling",
                                device_subnet,
                                ADOPT_MAX_TOTAL.as_secs(),
                                started.elapsed().as_secs()
                            );
                            auto_adopt::reconcile_pending(&ops, &pending_ips, Some(adoption_id))
                                .await;
                            let next_backoff = cooldowns
                                .get(&device_subnet)
                                .map(|(_, b)| (*b * 2).min(COOLDOWN_MAX))
                                .unwrap_or(COOLDOWN_INITIAL);
                            cooldowns.insert(
                                device_subnet.clone(),
                                (std::time::Instant::now() + next_backoff, next_backoff),
                            );
                        }
                        Ok(Ok(Some(adopted_ip))) => {
                            // A stop may have raced the successful final bind.
                            // If so, roll the IP back and do NOT record —
                            // recording an IP the stop path won't clean is
                            // worse than re-adopting on the next start.
                            if *shutdown_rx.borrow() {
                                log::info!(
                                    "Shutdown raced adoption of {} — rolling back {}",
                                    device_subnet,
                                    adopted_ip
                                );
                                auto_adopt::reconcile_pending(
                                    &ops,
                                    &pending_ips,
                                    Some(adoption_id),
                                )
                                .await;
                                break;
                            }
                            cooldowns.remove(&device_subnet);
                            adopted
                                .lock()
                                .await
                                .insert(device_subnet.clone(), adopted_ip);
                            // Fresh adoption: the triggering device was
                            // observed moments ago (twice, per the dwell
                            // gate), so seed the session liveness clock
                            // and the persisted metadata together.
                            let adoption_wall = chrono::Utc::now().to_rfc3339();
                            if let Ok(mut liveness) = liveness_for_adopt.lock() {
                                liveness.insert(device_subnet.clone(), std::time::Instant::now());
                            }
                            if let Ok(mut meta) = meta_for_adopt.lock() {
                                meta.insert(
                                    device_subnet.clone(),
                                    crate::config::AdoptedMeta {
                                        adopted_at: Some(adoption_wall.clone()),
                                        last_device_seen: Some(adoption_wall.clone()),
                                    },
                                );
                            }
                            // Handover: the IP is recorded and owned now, so
                            // drop its pending breadcrumb (adapter untouched).
                            auto_adopt::pending_handover(
                                &pending_ips,
                                &iface_name,
                                adopted_ip,
                                adoption_id,
                            )
                            .await;
                            known_subnets.insert(device_subnet.clone());

                            let _ = app_handle_for_adopt.emit(
                                "subnet-adopted",
                                serde_json::json!({
                                    "subnet": device_subnet,
                                    "adopted_ip": adopted_ip.to_string(),
                                    "adopted_at": adoption_wall,
                                    "last_device_seen": adoption_wall,
                                    // Freshly adopted is never stale — the
                                    // liveness clock was seeded moments ago.
                                    "stale": false,
                                }),
                            );

                            log::info!("Auto-adopted {} with IP {}", device_subnet, adopted_ip);

                            // Kick active-discovery passes on the newly-adopted
                            // /24. Without this, only the device that triggered
                            // the adoption is in arpDevices — passive hosts on
                            // the same subnet (cameras idle on their control
                            // port, etc.) never ARP on their own and stay
                            // invisible until the user manually refreshes.
                            //
                            // Multiple staggered passes cover three issues that
                            // routinely break a single-shot sweep on Windows:
                            //   1. The newly-bound secondary IP isn't fully
                            //      usable for ~1–3s after netsh returns — the
                            //      first ping via `-S adopted_ip` can silently
                            //      fail during that window.
                            //   2. If the /24 also overlaps WiFi, the route
                            //      metric may settle unpredictably and later
                            //      passes catch what an early pass missed.
                            //   3. Devices behind a slow switch / PoE injector
                            //      sometimes drop the first ARP broadcast.
                            let sweep_ip = adopted_ip.to_string();
                            let sweep_devices = devices_for_adopt.clone();
                            let sweep_registry = registry_for_adopt.clone();
                            let sweep_emitter = emitter_for_adopt.clone();
                            let sweep_handle = app_handle_for_adopt.clone();
                            let sweep_fence = fence_for_loop.clone();
                            let sweep_local = local_ips.clone();
                            tokio::spawn(async move {
                                let passes: [u64; 3] = [1500, 5000, 12000];
                                for (i, delay_ms) in passes.iter().enumerate() {
                                    tokio::time::sleep(std::time::Duration::from_millis(*delay_ms))
                                        .await;
                                    // A restart/stop during the staggered
                                    // delays means this belongs to a dead
                                    // session — stop pinging and merging.
                                    if sweep_fence.is_stale() {
                                        break;
                                    }
                                    log::info!(
                                        "Post-adoption sweep pass {}/{} on {}",
                                        i + 1,
                                        passes.len(),
                                        sweep_ip
                                    );
                                    ping_sweep_subnets(std::slice::from_ref(&sweep_ip)).await;
                                    // The adopted subnet is on the Ethernet
                                    // interface, so no non-Ethernet exclusion
                                    // applies to this post-adoption merge. The
                                    // self-IP filter still does — snapshot per
                                    // pass (the passes span ~12 s).
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
                                    )
                                    .await;
                                }
                            });

                            // Persist to config so the adoption survives a
                            // restart. Failure here is non-fatal (the IP is
                            // still bound to the interface for this session)
                            // but we want a log entry — silent loss leaves
                            // users debugging "where did my camera go?"
                            // after restart with no breadcrumb.
                            // This subnet is now live; drop any held-over
                            // restore for it so the persisted snapshot below
                            // reflects the live binding, not the stale hold.
                            pending_restore.lock().await.remove(&device_subnet);
                            let live = adopted.lock().await.clone();
                            let pend = pending_restore.lock().await.clone();
                            let snapshot = merge_adopted_config(&live, &pend);
                            let meta_snapshot =
                                meta_for_adopt.lock().map(|m| m.clone()).unwrap_or_default();
                            // Persist off the executor: update_adoption_state
                            // does a synchronous atomic_write + fsync (plus
                            // DPAPI on the credentials path) under a std lock,
                            // which would block a tokio worker across disk
                            // latency. Re-fetch the managed config inside so no
                            // borrow crosses the thread boundary.
                            let persist_handle = app_handle_for_adopt.clone();
                            let persisted = tokio::task::spawn_blocking(move || {
                                let config: tauri::State<'_, crate::config::AppConfig> =
                                    persist_handle.state();
                                config.update_adoption_state(snapshot, meta_snapshot)
                            })
                            .await;
                            match persisted {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => log::warn!(
                                    "Failed to persist adopted subnet {} to config: {}",
                                    device_subnet,
                                    e
                                ),
                                Err(e) => log::warn!(
                                    "Persist task for adopted subnet {} failed to join: {}",
                                    device_subnet,
                                    e
                                ),
                            }
                        }
                        Ok(Ok(None)) => {
                            // Already on subnet, or a clean shutdown-before-
                            // bind. Nothing was left bound.
                            cooldowns.remove(&device_subnet);
                            known_subnets.insert(device_subnet.clone());
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            // adopt_subnet cleaned its own breadcrumbs except a
                            // scratch whose release failed; reconcile this id
                            // to catch that. Cooldown instead of a permanent
                            // blacklist so a transient failure is retried.
                            auto_adopt::reconcile_pending(&ops, &pending_ips, Some(adoption_id))
                                .await;
                            let next_backoff = cooldowns
                                .get(&device_subnet)
                                .map(|(_, b)| (*b * 2).min(COOLDOWN_MAX))
                                .unwrap_or(COOLDOWN_INITIAL);
                            cooldowns.insert(
                                device_subnet.clone(),
                                (std::time::Instant::now() + next_backoff, next_backoff),
                            );
                            log::warn!(
                                "Failed to auto-adopt {} ({}); retrying in {}s",
                                device_subnet,
                                e,
                                next_backoff.as_secs()
                            );
                            let _ = app_handle_for_adopt.emit(
                                "adoption-failed",
                                serde_json::json!({
                                    "subnet": device_subnet,
                                    "error": e.to_string(),
                                }),
                            );
                        }
                    }

                    // Whatever the attempt's outcome, this subnet's dwell
                    // candidacy is spent — a later approach (post-cooldown
                    // retry, removal then re-appearance) restarts the
                    // two-observation gate.
                    dwell.prune_subnet(&device_subnet);
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

    /// Stop body, run with the discovery op lock already held.
    async fn stop_locked(&self) {
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
            h.abort();
        }
        if let Some(h) = self.arp_listener_handle.lock().await.take() {
            h.stop();
            log::info!("ARP discovery stopped");
        }
        // Reconcile any secondary IP the (now-stopped) adoption left bound
        // but unrecorded — scratch probes and final adds that never reached
        // adopted_ips. Best-effort; failures are logged and retried next stop.
        auto_adopt::reconcile_pending(&auto_adopt::RealAdoptOps, &self.pending_ips, None).await;
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
    pub async fn wired_source_for(&self, target: Ipv4Addr) -> Option<Ipv4Addr> {
        let adopted = self.adopted_ips.lock().await.clone();
        let iface = self.interface_name.lock().await.clone()?;
        let iface_ips = match interface::get_by_name(&iface).await {
            Ok(info) => info.ips,
            Err(_) => Vec::new(),
        };
        select_wired_source(target, &adopted, &iface_ips)
    }

    /// Forget that `ip` was auto-adopted. Used when the user manually
    /// claims an IP via Apply / Add Secondary — once they've taken
    /// ownership, the registry shouldn't keep tagging it as ours,
    /// otherwise the "(auto)" badge stays on a user-set IP forever.
    /// Returns true if any entry was removed.
    pub async fn untrack_adopted_ip(&self, ip: &str) -> bool {
        let removed: Vec<String> = {
            let mut map = self.adopted_ips.lock().await;
            let mut removed = Vec::new();
            map.retain(|subnet, v| {
                if v.to_string() == ip {
                    removed.push(subnet.clone());
                    false
                } else {
                    true
                }
            });
            removed
        };
        self.forget_adoption_tracking(&removed);
        !removed.is_empty()
    }

    /// Returns the unbound IP so the caller can emit the removal event.
    pub async fn remove_adopted_subnet(&self, subnet: &str) -> Result<Ipv4Addr, AppError> {
        let iface_name = self
            .interface_name
            .lock()
            .await
            .clone()
            .ok_or_else(|| AppError::Network("No interface configured".into()))?;

        // Read the IP without untracking yet — only remove from the map
        // after the netsh delete succeeds, so a failed delete can't leave
        // the IP on the interface while the map believes it's gone.
        let ip = {
            let map = self.adopted_ips.lock().await;
            *map.get(subnet)
                .ok_or_else(|| AppError::Network(format!("Subnet {} not adopted", subnet)))?
        };

        auto_adopt::remove_adopted_ip(&iface_name, &ip.to_string()).await?;
        self.adopted_ips.lock().await.remove(subnet);
        // A user removal also drops any held-over restore for this subnet so
        // it isn't resurrected into config by the next save.
        self.pending_restore.lock().await.remove(subnet);
        self.forget_adoption_tracking(std::slice::from_ref(&subnet.to_string()));
        Ok(ip)
    }

    /// Remove every currently-adopted secondary IP from the OS interface.
    ///
    /// Called from the `RunEvent::ExitRequested` handler so adopted IPs
    /// don't survive a graceful shutdown — they were added at runtime to
    /// reach foreign subnets and shouldn't pollute the user's persistent
    /// adapter config when PocketStream is closed.
    ///
    /// In-memory state and the on-disk `config.toml` are deliberately left
    /// untouched: the next startup's `load_adopted_from_config` will see
    /// the same entries and re-add the IPs (a fast no-op if they were
    /// already restored, otherwise a normal netsh add). After a hard crash
    /// (no graceful exit), the IPs persist on the interface; the next
    /// startup recovers them into in-memory state and the next graceful
    /// exit cleans them up. The system self-heals after one clean cycle.
    ///
    /// Cleanup runs in parallel with a per-call timeout so a stalled netsh
    /// can't hang the shutdown indefinitely.
    pub async fn cleanup_adopted_ips(&self) {
        let iface_name = match self.interface_name.lock().await.clone() {
            Some(n) => n,
            None => return,
        };

        let entries: Vec<(String, Ipv4Addr)> = {
            let map = self.adopted_ips.lock().await;
            map.iter().map(|(k, v)| (k.clone(), *v)).collect()
        };

        if entries.is_empty() {
            return;
        }

        // Snapshot the adapter's current IPs and the primary so we can
        // refuse to remove anything that would either orphan the adapter
        // (last IP) or strip its primary IP. Defense-in-depth: even if
        // adopted_ips somehow contains an entry that matches the primary
        // (shouldn't happen, but guards against a future bug or a
        // corrupted config), cleanup will skip it instead of disabling
        // the user's network.
        let current_iface = interface::get_by_name(&iface_name).await.ok();
        let current_ip_set: HashSet<String> = current_iface
            .as_ref()
            .map(|i| i.ips.iter().map(|ip| ip.address.clone()).collect())
            .unwrap_or_default();
        let primary_ip: Option<String> = current_iface
            .as_ref()
            .and_then(|i| i.ips.first().map(|ip| ip.address.clone()));
        let total_ip_count = current_ip_set.len();

        log::info!(
            "Removing {} adopted secondary IP(s) on shutdown (adapter has {} total)",
            entries.len(),
            total_ip_count
        );

        let mut tasks = tokio::task::JoinSet::new();
        for (subnet, ip) in entries {
            let ip_str = ip.to_string();

            // Safety check 1: if removing this would leave the adapter
            // with zero IPv4 addresses, refuse. The remove still works
            // mechanically, but Windows often disables an adapter that
            // has no IPv4 assignment, which is much worse than a stray
            // secondary IP lingering for one more session.
            if total_ip_count <= 1 && current_ip_set.contains(&ip_str) {
                log::warn!(
                    "Skipping cleanup of {} ({}): would leave adapter with zero IPv4 addresses",
                    ip_str,
                    subnet
                );
                continue;
            }

            // Safety check 2: never remove the primary. If something put
            // the primary IP in adopted_ips by mistake, removing it would
            // break the user's normal connectivity.
            if primary_ip.as_deref() == Some(&ip_str) {
                log::warn!(
                    "Skipping cleanup of {} ({}): is the adapter's primary IP",
                    ip_str,
                    subnet
                );
                continue;
            }

            let iface = iface_name.clone();
            tasks.spawn(async move {
                match auto_adopt::remove_adopted_ip(&iface, &ip_str).await {
                    Ok(()) => log::info!("Removed adopted IP {} ({})", ip_str, subnet),
                    Err(e) => {
                        log::warn!("Failed to remove adopted IP {} on shutdown: {}", ip_str, e)
                    }
                }
            });
        }
        while tasks.join_next().await.is_some() {}
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
async fn ping_sweep_subnets(interface_ips: &[String]) {
    use tokio::sync::Semaphore;
    use tokio::task::JoinSet;

    // Cap concurrent ping.exe spawns. Without this we were spawning all
    // 254 pings per interface IP simultaneously — on a USB Ethernet
    // adapter (notably ASIX AX88179) that burst was saturating the NIC
    // / Windows socket stack at exactly the moment a parallel stream
    // restart was trying to complete its RTSP DESCRIBE handshake, and
    // the camera would time out before the SDP exchange finished,
    // leaving the GStreamer pipeline stuck at Paused→Playing forever.
    // 32 is well under typical Windows ephemeral-port and process
    // pressure thresholds while still draining a /24 in ~1.5 s.
    const MAX_CONCURRENT_PINGS: usize = 32;
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_PINGS));
    let mut join_set = JoinSet::new();

    for ip_str in interface_ips {
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            let o = ip.octets();
            for last in 1..=254 {
                let target = format!("{}.{}.{}.{}", o[0], o[1], o[2], last);
                let source = ip_str.clone();
                let sem = sem.clone();
                join_set.spawn(async move {
                    let _permit = match sem.acquire().await {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    let _ = async_cmd("ping")
                        .args(["-n", "1", "-w", "200", "-S", &source, &target])
                        .output()
                        .await;
                });
            }
        }
    }

    while join_set.join_next().await.is_some() {}
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
) {
    use tauri::{Emitter, Manager};

    // Fence stale-session merges: a sweep from a prior discovery session
    // (or one still running after a stop) must not merge or emit into the
    // current session's shared registry.
    if fence.is_stale() {
        return;
    }

    let entries = arp::read_system_arp_table(interface_ip).await;
    let now = chrono::Utc::now().to_rfc3339();

    // Insert new entries into the legacy map under the lock, then release
    // it before the registry merge and any cache-file disk writes below —
    // holding `devices` across disk I/O stalls the listener during ARP
    // bursts (L31).
    let new_devices: Vec<ArpDevice> = {
        let mut map = devices.lock().await;
        let mut collected = Vec::new();
        for (ip, mac) in entries {
            if excluded.iter().any(|net| net.contains(ip)) {
                // Sender on a non-Ethernet (WiFi/VPN) subnet — not a wired
                // peer. The OS neighbor read is InterfaceIndex-scoped, so
                // this usually has nothing to drop; it is a safety net for a
                // shared-subnet or bridged layout.
                continue;
            }
            if local_ips.contains(&ip) {
                // Our own address (any adapter) — the host never lists
                // itself. Normally unreachable: the neighbor table holds
                // resolved peers, not local addresses; defense in depth
                // beside the subnet safety net above.
                log::debug!("ARP table: skipping our own IP {}", ip);
                continue;
            }
            if map.contains_key(&mac) {
                continue;
            }
            let octets = ip.octets();
            let device = ArpDevice {
                mac: mac.clone(),
                ip: ip.to_string(),
                subnet: format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]),
                first_seen: now.clone(),
                last_seen: now.clone(),
            };
            map.insert(mac, device.clone());
            collected.push(device);
        }
        collected
    };

    let mut registry_changed = false;
    for device in &new_devices {
        log::info!("ARP table: {} ({})", device.ip, device.mac);
        let _ = app_handle.emit("arp-device-discovered", device);
        // Positive-liveness stamp for the adoption lifecycle — a
        // neighbor-table row accepted here is device evidence just like
        // a captured frame.
        if let Ok(device_ip) = device.ip.parse::<Ipv4Addr>() {
            let manager: tauri::State<'_, NetworkManager> = app_handle.state();
            manager.note_positive_liveness(&app_handle, device_ip).await;
        }
        let result = registry.merge_arp(device);
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

/// Merge the live adopted map with the pending-restore map for persistence.
/// Live wins on a key conflict (a subnet that re-bound this session
/// supersedes its held-over restore). Pending-restore entries — transient
/// startup re-add failures — are retained so a wholesale config write does
/// not delete them, letting the next startup retry.
fn merge_adopted_config(
    live: &HashMap<String, Ipv4Addr>,
    pending: &HashMap<String, Ipv4Addr>,
) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = pending
        .iter()
        .map(|(k, v)| (k.clone(), v.to_string()))
        .collect();
    for (k, v) in live {
        out.insert(k.clone(), v.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fence(generation: u64, current: u64, active: bool) -> SweepFence {
        SweepFence::new(
            generation,
            Arc::new(AtomicU64::new(current)),
            Arc::new(AtomicBool::new(active)),
        )
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
        };
        assert_eq!(
            badge_age(Some(&seen), now),
            Some(std::time::Duration::from_secs(3600))
        );

        // Never seen: the adoption time itself anchors the badge.
        let never = crate::config::AdoptedMeta {
            adopted_at: Some("2026-07-16T10:00:00+00:00".into()),
            last_device_seen: None,
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
        };
        assert_eq!(badge_age(Some(&garbage), now), None);
        let future = crate::config::AdoptedMeta {
            adopted_at: Some("2026-07-17T00:00:00+00:00".into()),
            last_device_seen: None,
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
        };
        let v = adoption_meta_view("172.31.169.0/24", Some(&meta), None, min(1), None);
        assert_eq!(v.adopted_at.as_deref(), Some("2026-07-01T00:00:00+00:00"));
        assert_eq!(
            v.last_device_seen.as_deref(),
            Some("2026-07-15T00:00:00+00:00")
        );
    }

    #[test]
    fn rescue_state_ignores_apipa_adopted_and_pending_addresses() {
        let apipa_native = Ipv4Addr::new(169, 254, 7, 20);
        let adopted_foreign = Ipv4Addr::new(172, 31, 169, 102);
        let pending_scratch = Ipv4Addr::new(10, 0, 0, 254);
        let real_lease = Ipv4Addr::new(192, 168, 12, 64);
        let adopted: HashSet<Ipv4Addr> = [adopted_foreign].into_iter().collect();
        let pending: HashSet<Ipv4Addr> = [pending_scratch].into_iter().collect();

        // Only APIPA + adopted + pending addresses on the adapter: the
        // host is rescued. The adopted non-APIPA secondary deliberately
        // does not count as native connectivity.
        assert!(host_in_apipa_rescue(
            &[apipa_native, adopted_foreign, pending_scratch],
            &adopted,
            &pending,
        ));

        // A real (native, non-APIPA) address ends the rescue state.
        assert!(!host_in_apipa_rescue(
            &[apipa_native, adopted_foreign, real_lease],
            &adopted,
            &pending,
        ));

        // No addresses at all is rescue too — nothing native to rely on.
        assert!(host_in_apipa_rescue(&[], &adopted, &pending));
    }

    #[test]
    fn unbind_guards_block_primary_and_last_address_only() {
        let ips = vec![
            "192.168.12.64".to_string(),
            "169.254.168.102".to_string(),
            "172.31.169.102".to_string(),
        ];
        // A secondary among several: no block.
        assert_eq!(unbind_guard_blocks("169.254.168.102", &ips), None);
        // The primary (first) address is always blocked.
        assert!(unbind_guard_blocks("192.168.12.64", &ips).is_some());
        // The adapter's only address is blocked.
        let sole = vec!["169.254.168.102".to_string()];
        assert!(unbind_guard_blocks("169.254.168.102", &sole).is_some());
        // An address the adapter no longer holds: nothing to guard.
        assert_eq!(unbind_guard_blocks("169.254.43.102", &ips), None);
    }

    #[test]
    fn merge_keeps_pending_restore_entries() {
        // The core Fix 4 invariant: a transiently-failed restore held in
        // pending_restore survives a persist derived from the live map.
        let mut live = HashMap::new();
        live.insert("10.0.0.0/24".to_string(), Ipv4Addr::new(10, 0, 0, 100));
        let mut pending = HashMap::new();
        pending.insert("10.9.0.0/24".to_string(), Ipv4Addr::new(10, 9, 0, 100));
        let out = merge_adopted_config(&live, &pending);
        assert_eq!(
            out.get("10.0.0.0/24").map(String::as_str),
            Some("10.0.0.100")
        );
        assert_eq!(
            out.get("10.9.0.0/24").map(String::as_str),
            Some("10.9.0.100")
        );
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn merge_live_wins_on_conflict() {
        // If a subnet is both live and pending (shouldn't normally persist,
        // but be safe), the confirmed live binding wins.
        let mut live = HashMap::new();
        live.insert("10.0.0.0/24".to_string(), Ipv4Addr::new(10, 0, 0, 100));
        let mut pending = HashMap::new();
        pending.insert("10.0.0.0/24".to_string(), Ipv4Addr::new(10, 0, 0, 200));
        let out = merge_adopted_config(&live, &pending);
        assert_eq!(
            out.get("10.0.0.0/24").map(String::as_str),
            Some("10.0.0.100")
        );
        assert_eq!(out.len(), 1);
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
}
