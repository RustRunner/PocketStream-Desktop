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
        if self.device_registry.hydrate_manual_nodes(&nodes) {
            log::info!("DeviceRegistry: hydrated {} manual node(s)", count);
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

        // Persist the pruned config (original − natively-covered − invalid),
        // computed independently of which re-adds later succeed: a transient
        // re-add failure must keep its config entry for a retry. Only write
        // when something was actually dropped.
        if pruned {
            match config.update_adopted_subnets(kept) {
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
                let _ = app_handle.emit(
                    "subnet-adopted",
                    serde_json::json!({
                        "subnet": subnet,
                        "adopted_ip": ip_str,
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

    /// Save current adopted subnets to config.
    pub async fn save_adopted_to_config(&self, config: &crate::config::AppConfig) {
        let adopted = self.adopted_config_snapshot().await;
        if let Err(e) = config.update_adopted_subnets(adopted) {
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
        // (PacketMonitor captures unscoped — no capture-device matching
        // needed — but the listener still uses the adapter's own MAC to
        // filter our own gratuitous ARP.)
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
        let adopt_handle = tokio::spawn(async move {
            use tauri::Emitter;
            use tauri::Manager;
            let mut shutdown_rx = shutdown_rx;
            let ops = auto_adopt::RealAdoptOps;
            let mut known_subnets: HashSet<String> = HashSet::new();

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

                    log::info!("Foreign subnet detected: {}", device_subnet);

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
                            // Persist off the executor: update_adopted_subnets
                            // does a synchronous atomic_write + fsync (plus
                            // DPAPI on the credentials path) under a std lock,
                            // which would block a tokio worker across disk
                            // latency. Re-fetch the managed config inside so no
                            // borrow crosses the thread boundary.
                            let persist_handle = app_handle_for_adopt.clone();
                            let persisted = tokio::task::spawn_blocking(move || {
                                let config: tauri::State<'_, crate::config::AppConfig> =
                                    persist_handle.state();
                                config.update_adopted_subnets(snapshot)
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

    /// Forget that `ip` was auto-adopted. Used when the user manually
    /// claims an IP via Apply / Add Secondary — once they've taken
    /// ownership, the registry shouldn't keep tagging it as ours,
    /// otherwise the "(auto)" badge stays on a user-set IP forever.
    /// Returns true if any entry was removed.
    pub async fn untrack_adopted_ip(&self, ip: &str) -> bool {
        let mut map = self.adopted_ips.lock().await;
        let before = map.len();
        map.retain(|_, v| v.to_string() != ip);
        before != map.len()
    }

    pub async fn remove_adopted_subnet(&self, subnet: &str) -> Result<(), AppError> {
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
        Ok(())
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
