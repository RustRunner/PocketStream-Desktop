pub mod adapter_refresh;
pub mod arp;
pub mod auto_adopt;
pub mod device_registry;
pub mod firewall;
pub mod interface;
pub mod ip_config;
pub mod ping_dot;
pub mod scanner;
pub mod watcher;

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
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

pub struct NetworkManager {
    active_scans: Arc<Mutex<HashSet<String>>>,
    arp_devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    adopted_ips: Arc<Mutex<HashMap<String, Ipv4Addr>>>,
    arp_listener_handle: Arc<Mutex<Option<arp::ArpListenerHandle>>>,
    auto_adopt_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    auto_adopt_enabled: Arc<Mutex<bool>>,
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
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            active_scans: Arc::new(Mutex::new(HashSet::new())),
            arp_devices: Arc::new(Mutex::new(HashMap::new())),
            adopted_ips: Arc::new(Mutex::new(HashMap::new())),
            arp_listener_handle: Arc::new(Mutex::new(None)),
            auto_adopt_handle: Arc::new(Mutex::new(None)),
            auto_adopt_enabled: Arc::new(Mutex::new(true)),
            interface_name: Arc::new(Mutex::new(None)),
            device_registry: Arc::new(DeviceRegistry::new()),
            device_emitter: Arc::new(Mutex::new(None)),
            ping_dot_handle: Arc::new(Mutex::new(None)),
        }
    }

    /// Hydrate the device registry from the on-disk cache. Idempotent
    /// (the registry's own one-shot guard prevents re-hydration), but
    /// expected to be called once at startup before ARP discovery so
    /// the initial snapshot reflects last-known state.
    pub fn hydrate_device_registry(&self, config: &crate::config::AppConfig) {
        let cached = config.get_cache();
        let count = cached.len();
        let result = self.device_registry.hydrate_from_cache(&cached);
        if !result.changed {
            return;
        }
        // Mirror same-IP dedup decisions onto the on-disk cache so the
        // orphans don't reappear on next startup. Cache file mutations
        // are best-effort: a failure logs but doesn't block boot.
        for mac in &result.dropped_macs {
            if let Err(e) = config.remove_cached_device(mac) {
                log::warn!("Failed to evict dupe cache row {}: {}", mac, e);
            }
        }
        log::info!(
            "DeviceRegistry: hydrated {} cached device(s) (dropped {} dupe(s))",
            count - result.dropped_macs.len(),
            result.dropped_macs.len()
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

        if new_mode == NetworkMode::StaticManual {
            // Going INTO Manual: seed manual_nodes from whatever the
            // Nodes panel is currently showing — devices with at least
            // one discovered open port. ARP-only entries (no scan yet)
            // are skipped because they aren't surfaced to the user, so
            // pinning them would silently inflate the list.
            //
            // Only runs when the pinned pool is empty so a user who's
            // already curated their list doesn't get it re-polluted on
            // every mode flip (e.g., Manual → Auto → Manual would
            // otherwise re-pin anything they deleted in between).
            if config.get_manual_nodes().is_empty() {
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
            }
            self.stop_arp_discovery().await;
            self.device_registry.clear();
            self.hydrate_manual_nodes(config).await;
        } else if old_mode == NetworkMode::StaticManual {
            // Leaving Manual: drop manual hydrations, restore the
            // cache, restart ARP discovery if an interface is known.
            self.device_registry.clear();
            self.hydrate_device_registry(config);
            if let Some(emitter) = self.device_emitter.lock().await.clone() {
                emitter.poke();
            }
            if crate::is_npcap_available() {
                let iface = self
                    .interface_name
                    .lock()
                    .await
                    .clone()
                    .or_else(|| {
                        interface::list_physical()
                            .ok()
                            .and_then(|list| {
                                list.into_iter()
                                    .find(|i| i.is_up && i.is_ethernet && !i.ips.is_empty())
                                    .map(|i| i.name)
                            })
                    });
                if let Some(name) = iface {
                    if let Err(e) = self.start_arp_discovery(&name, app_handle.clone()).await {
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
        let mut slot = self.ping_dot_handle.lock().await;
        if let Some(prev) = slot.take() {
            prev.stop().await;
        }
        *slot = Some(ping_dot::start(app_handle, self.device_registry.clone()));
        log::info!("Started ICMP ping-dot loop");
    }

    /// Stop the pinger task and drain. No-op if not running.
    pub async fn stop_ping_dot(&self) {
        if let Some(handle) = self.ping_dot_handle.lock().await.take() {
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

        // Get the active ethernet interface
        let iface = match interface::list_physical() {
            Ok(interfaces) => interfaces
                .into_iter()
                .find(|i| i.is_up && i.is_ethernet && !i.ips.is_empty()),
            Err(_) => None,
        };

        let iface = match iface {
            Some(i) => i,
            None => {
                log::info!("No active interface — skipping adopted subnet restore");
                return;
            }
        };

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

        // ── Phase 1: classify + insert under the lock (no awaits) ──
        // Each entry produces (subnet, ip_str, needs_netsh_add). Pruned
        // entries are dropped from both the in-memory map and the on-disk
        // config.
        let (work_items, save_snapshot) = {
            let mut map = self.adopted_ips.lock().await;
            let mut work: Vec<(String, String, bool)> = Vec::new();
            let mut pruned = false;

            for (subnet, ip_str) in &settings.adopted_subnets {
                if native_subnets.contains(subnet) {
                    log::info!(
                        "Pruning adopted subnet {} ({}) — adapter already covers it natively",
                        subnet,
                        ip_str,
                    );
                    pruned = true;
                    continue;
                }

                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    map.insert(subnet.clone(), ip);
                    work.push((
                        subnet.clone(),
                        ip_str.clone(),
                        !current_ips.contains(ip_str),
                    ));
                }
            }

            let snapshot: Option<HashMap<String, String>> = if pruned {
                Some(
                    map.iter()
                        .map(|(k, v)| (k.clone(), v.to_string()))
                        .collect(),
                )
            } else {
                None
            };
            (work, snapshot)
        }; // lock dropped here

        // Persist the cleaned-up map so pruned entries don't come back.
        // Outside the lock — config.update writes to disk and shouldn't
        // block other readers of adopted_ips.
        if let Some(adopted) = save_snapshot {
            let mut new_settings = config.get();
            new_settings.adopted_subnets = adopted;
            match config.update(new_settings) {
                Ok(()) => log::info!("Saved pruned adopted subnets to config"),
                Err(e) => log::warn!("Failed to persist pruned adopted subnets: {}", e),
            }
        }

        // ── Phase 2: netsh re-add in parallel, outside the lock ────
        // After each entry is confirmed on the adapter (either already
        // present from a hard-crash recovery or freshly netsh-added),
        // emit `subnet-adopted` so the frontend's existing handler can
        // populate `adoptedSubnets` and re-render with the (auto) badge.
        // Failed adds skip the emission — the frontend shouldn't badge
        // an IP that isn't actually on the interface.
        use tauri::Emitter;
        let mut tasks = tokio::task::JoinSet::new();
        for (subnet, ip_str, needs_add) in work_items {
            let iface_name = iface.name.clone();
            let handle = app_handle.clone();
            tasks.spawn(async move {
                let added_ok = if needs_add {
                    log::info!("Re-adding missing adopted IP {} to {}", ip_str, iface_name);
                    match ip_config::add_secondary_ip(&iface_name, &ip_str, "255.255.255.0").await {
                        Ok(()) => true,
                        Err(e) => {
                            log::warn!("Failed to re-add adopted IP {}: {}", ip_str, e);
                            false
                        }
                    }
                } else {
                    log::info!("Adopted IP {} already on adapter", ip_str);
                    true
                };

                if added_ok {
                    let _ = handle.emit(
                        "subnet-adopted",
                        serde_json::json!({
                            "subnet": subnet,
                            "adopted_ip": ip_str,
                        }),
                    );
                }
            });
        }
        while tasks.join_next().await.is_some() {}
    }

    /// Save current adopted subnets to config.
    pub async fn save_adopted_to_config(&self, config: &crate::config::AppConfig) {
        let map = self.adopted_ips.lock().await;
        let adopted: HashMap<String, String> = map
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect();
        let mut settings = config.get();
        settings.adopted_subnets = adopted;
        if let Err(e) = config.update(settings) {
            log::warn!("Failed to save adopted subnets: {}", e);
        }
    }

    pub fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>, AppError> {
        interface::list_physical()
    }

    pub fn get_interface(&self, name: &str) -> Result<InterfaceInfo, AppError> {
        interface::get_by_name(name)
    }

    pub async fn scan_subnet(&self, subnet: &str) -> Result<Vec<ScanResult>, AppError> {
        {
            let mut active = self.active_scans.lock().await;
            if !active.insert(subnet.to_string()) {
                return Err(AppError::Network(format!(
                    "Scan already in progress for {}",
                    subnet
                )));
            }
        }
        let result = scanner::scan(subnet).await;
        self.active_scans.lock().await.remove(subnet);
        result
    }

    /// Start ARP discovery via pcap on the Ethernet interface.
    /// Also spawns auto-adopt handler for foreign subnets.
    pub async fn start_arp_discovery(
        &self,
        interface_display_name: &str,
        app_handle: tauri::AppHandle,
    ) -> Result<(), AppError> {
        self.stop_arp_discovery().await;

        *self.interface_name.lock().await = Some(interface_display_name.to_string());

        let devices = self.arp_devices.clone();
        let adopted = self.adopted_ips.clone();
        let auto_adopt = self.auto_adopt_enabled.clone();
        let iface_name = interface_display_name.to_string();
        let app_handle_for_adopt = app_handle.clone();

        // Get current IPs so auto-adopt knows which subnets are "known"
        // and so the pcap listener can match the correct capture device.
        let iface_info = interface::get_by_name(interface_display_name)?;
        let known_ips: Vec<String> = iface_info.ips.iter().map(|ip| ip.address.clone()).collect();
        let ethernet_ips: Vec<Ipv4Addr> =
            known_ips.iter().filter_map(|ip| ip.parse().ok()).collect();
        let own_mac = parse_mac_bytes(&iface_info.mac);
        log::info!(
            "Starting ARP discovery on '{}' (IPs: {:?}, mac: {})",
            interface_display_name,
            known_ips,
            iface_info.mac
        );

        let registry = self.device_registry.clone();

        // Late-bind the emitter now that we have an AppHandle. Replace
        // any previous emitter (e.g. from a prior interface switch) so
        // events fire under the current handle.
        let emitter = DeviceListEmitter::new(app_handle.clone(), registry.clone());
        *self.device_emitter.lock().await = Some(emitter.clone());
        // Emit the initial snapshot so any frontend that's already
        // subscribed sees cache-hydrated devices without having to
        // separately call get_device_list.
        emitter.poke();

        let handle = arp::start_listener(
            devices.clone(),
            registry.clone(),
            emitter.clone(),
            app_handle,
            ethernet_ips,
            own_mac,
        )?;
        *self.arp_listener_handle.lock().await = Some(handle);

        // Ping sweep known subnets to provoke ARP traffic so pcap sees all devices,
        // then read the OS ARP table to catch cached entries that didn't generate
        // new ARP packets on the wire.
        let sweep_ips = known_ips.clone();
        let sweep_devices = self.arp_devices.clone();
        let sweep_registry = registry.clone();
        let sweep_emitter = emitter.clone();
        let sweep_app_handle = app_handle_for_adopt.clone();
        let sweep_iface_ip = sweep_ips.first().cloned().unwrap_or_default();
        tokio::spawn(async move {
            // Small delay to let pcap listener start first
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            log::info!("Ping sweeping known subnets to populate ARP");
            ping_sweep_subnets(&sweep_ips).await;

            // Read OS ARP table scoped to the Ethernet interface only
            if !sweep_iface_ip.is_empty() {
                merge_arp_table(
                    sweep_devices,
                    sweep_registry,
                    sweep_emitter,
                    sweep_app_handle,
                    &sweep_iface_ip,
                )
                .await;
            }
        });

        // Auto-adopt handler for foreign subnets
        let devices_for_adopt = devices.clone();
        let registry_for_adopt = registry.clone();
        let emitter_for_adopt = emitter.clone();
        let adopt_handle = tokio::spawn(async move {
            use tauri::Emitter;
            use tauri::Manager;
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

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                if !*auto_adopt.lock().await {
                    continue;
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
                            false
                        }
                    }
                } else {
                    cached_dhcp_state.map(|(d, _)| d).unwrap_or(false)
                };

                if is_dhcp {
                    let current_ips = get_interface_ips(&iface_name);
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
                    if known_subnets.contains(&device.subnet) {
                        continue;
                    }

                    if adopted.lock().await.contains_key(&device.subnet) {
                        known_subnets.insert(device.subnet.clone());
                        continue;
                    }

                    let device_ip: Ipv4Addr = match device.ip.parse() {
                        Ok(ip) => ip,
                        Err(_) => continue,
                    };

                    // Refresh current IPs (may have changed since startup)
                    let current_ips = get_interface_ips(&iface_name);

                    if auto_adopt::already_on_subnet(device_ip, &current_ips) {
                        known_subnets.insert(device.subnet.clone());
                        continue;
                    }

                    log::info!("Foreign subnet detected: {}", device.subnet);

                    match auto_adopt::adopt_subnet(&iface_name, device_ip, &current_ips).await {
                        Ok(Some(adopted_ip)) => {
                            adopted
                                .lock()
                                .await
                                .insert(device.subnet.clone(), adopted_ip);
                            known_subnets.insert(device.subnet.clone());

                            let _ = app_handle_for_adopt.emit(
                                "subnet-adopted",
                                serde_json::json!({
                                    "subnet": device.subnet,
                                    "adopted_ip": adopted_ip.to_string(),
                                }),
                            );

                            log::info!("Auto-adopted {} with IP {}", device.subnet, adopted_ip);

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
                            tokio::spawn(async move {
                                let passes: [u64; 3] = [1500, 5000, 12000];
                                for (i, delay_ms) in passes.iter().enumerate() {
                                    tokio::time::sleep(std::time::Duration::from_millis(*delay_ms))
                                        .await;
                                    log::info!(
                                        "Post-adoption sweep pass {}/{} on {}",
                                        i + 1,
                                        passes.len(),
                                        sweep_ip
                                    );
                                    ping_sweep_subnets(std::slice::from_ref(&sweep_ip)).await;
                                    merge_arp_table(
                                        sweep_devices.clone(),
                                        sweep_registry.clone(),
                                        sweep_emitter.clone(),
                                        sweep_handle.clone(),
                                        &sweep_ip,
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
                            let config: tauri::State<'_, crate::config::AppConfig> =
                                app_handle_for_adopt.state();
                            let adopted_map = adopted.lock().await;
                            let mut settings = config.get();
                            settings.adopted_subnets = adopted_map
                                .iter()
                                .map(|(k, v)| (k.clone(), v.to_string()))
                                .collect();
                            drop(adopted_map);
                            if let Err(e) = config.update(settings) {
                                log::warn!(
                                    "Failed to persist adopted subnet {} to config: {}",
                                    device.subnet,
                                    e
                                );
                            }
                        }
                        Ok(None) => {
                            known_subnets.insert(device.subnet.clone());
                        }
                        Err(e) => {
                            log::warn!("Failed to auto-adopt {}: {}", device.subnet, e);
                            known_subnets.insert(device.subnet.clone());
                        }
                    }
                }
            }
        });
        *self.auto_adopt_handle.lock().await = Some(adopt_handle);

        Ok(())
    }

    pub async fn stop_arp_discovery(&self) {
        if let Some(h) = self.auto_adopt_handle.lock().await.take() {
            h.abort();
            log::info!("Auto-adopt task cancelled");
        }
        if let Some(h) = self.arp_listener_handle.lock().await.take() {
            h.stop();
            log::info!("ARP discovery stopped");
        }
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

        let ip = {
            let mut map = self.adopted_ips.lock().await;
            map.remove(subnet)
                .ok_or_else(|| AppError::Network(format!("Subnet {} not adopted", subnet)))?
        };

        auto_adopt::remove_adopted_ip(&iface_name, &ip.to_string()).await
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
        let current_iface = interface::get_by_name(&iface_name).ok();
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

fn get_interface_ips(name: &str) -> Vec<Ipv4Addr> {
    match interface::get_by_name(name) {
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
/// silently route out the wrong NIC — the Ethernet pcap listener never
/// sees the replies and passive devices on that subnet stay invisible.
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
async fn merge_arp_table(
    devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    registry: Arc<DeviceRegistry>,
    emitter: Arc<DeviceListEmitter>,
    app_handle: tauri::AppHandle,
    interface_ip: &str,
) {
    use tauri::{Emitter, Manager};

    let entries = arp::read_system_arp_table(interface_ip).await;
    let mut added = 0u32;
    let mut registry_changed = false;

    let mut map = devices.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    for (ip, mac) in entries {
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

        log::info!("ARP table: {} ({})", device.ip, device.mac);
        let _ = app_handle.emit("arp-device-discovered", &device);
        let result = registry.merge_arp(&device);
        if result.changed {
            registry_changed = true;
        }
        // Mirror same-IP dedup to the on-disk cache so reloads don't
        // resurrect the orphan rows.
        if !result.dropped_macs.is_empty() {
            let config: tauri::State<'_, crate::config::AppConfig> = app_handle.state();
            for dropped in &result.dropped_macs {
                if let Err(e) = config.remove_cached_device(dropped) {
                    log::warn!(
                        "Failed to evict dupe cache row {} (same IP as {}): {}",
                        dropped,
                        device.mac,
                        e
                    );
                }
            }
        }
        map.insert(mac, device);
        added += 1;
    }

    if added > 0 {
        log::info!("Merged {} devices from OS ARP table", added);
    }
    // Coalesce all the new entries into one event. The emitter's 150 ms
    // window absorbs both this batch and any concurrent live-ARP merges.
    if registry_changed {
        emitter.poke();
    }
}
