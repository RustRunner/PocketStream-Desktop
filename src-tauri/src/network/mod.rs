pub mod arp;
pub mod auto_adopt;
pub mod firewall;
pub mod interface;
pub mod ip_config;
pub mod scanner;

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;

pub use arp::ArpDevice;
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
        }
    }

    /// Load previously adopted subnets from config and verify they still
    /// exist on the adapter. Re-add any that are missing.
    ///
    /// Entries whose subnet matches the adapter's native IPs are pruned —
    /// they were either saved by mistake or the adapter's primary IP changed
    /// to cover that subnet since the adoption.
    pub async fn load_adopted_from_config(&self, config: &crate::config::AppConfig) {
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
        // Any adopted entry on a native subnet is redundant.
        let native_subnets: HashSet<String> = iface
            .ips
            .iter()
            .filter_map(|ip| ip.address.parse::<Ipv4Addr>().ok())
            .map(|ip| {
                let o = ip.octets();
                format!("{}.{}.{}.0/24", o[0], o[1], o[2])
            })
            .collect();

        let current_ips: std::collections::HashSet<String> =
            iface.ips.iter().map(|ip| ip.address.clone()).collect();

        let mut map = self.adopted_ips.lock().await;
        let mut pruned = false;

        for (subnet, ip_str) in &settings.adopted_subnets {
            // Skip entries whose subnet the adapter already covers natively
            if native_subnets.contains(subnet) {
                log::info!(
                    "Pruning adopted subnet {} ({}) — adapter already covers it natively",
                    subnet, ip_str,
                );
                pruned = true;
                continue;
            }

            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                map.insert(subnet.clone(), ip);

                if current_ips.contains(ip_str) {
                    log::info!("Adopted IP {} already on adapter", ip_str);
                } else {
                    log::info!("Re-adding missing adopted IP {} to {}", ip_str, iface.name);
                    if let Err(e) = ip_config::add_secondary_ip(
                        &iface.name,
                        ip_str,
                        "255.255.255.0",
                    ).await {
                        log::warn!("Failed to re-add adopted IP {}: {}", ip_str, e);
                    }
                }
            }
        }

        // Persist the cleaned-up map so pruned entries don't come back
        if pruned {
            let adopted: HashMap<String, String> = map
                .iter()
                .map(|(k, v)| (k.clone(), v.to_string()))
                .collect();
            let mut new_settings = config.get();
            new_settings.adopted_subnets = adopted;
            match config.update(new_settings) {
                Ok(()) => log::info!("Saved pruned adopted subnets to config"),
                Err(e) => log::warn!("Failed to persist pruned adopted subnets: {}", e),
            }
        }
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
        let ethernet_ips: Vec<Ipv4Addr> = known_ips
            .iter()
            .filter_map(|ip| ip.parse().ok())
            .collect();
        log::info!(
            "Starting ARP discovery on '{}' (IPs: {:?})",
            interface_display_name,
            known_ips
        );

        let handle = arp::start_listener(devices.clone(), app_handle, ethernet_ips)?;
        *self.arp_listener_handle.lock().await = Some(handle);

        // Ping sweep known subnets to provoke ARP traffic so pcap sees all devices,
        // then read the OS ARP table to catch cached entries that didn't generate
        // new ARP packets on the wire.
        let sweep_ips = known_ips.clone();
        let sweep_devices = self.arp_devices.clone();
        let sweep_app_handle = app_handle_for_adopt.clone();
        let sweep_iface_ip = sweep_ips.first().cloned().unwrap_or_default();
        tokio::spawn(async move {
            // Small delay to let pcap listener start first
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            log::info!("Ping sweeping known subnets to populate ARP");
            ping_sweep_subnets(&sweep_ips).await;

            // Read OS ARP table scoped to the Ethernet interface only
            if !sweep_iface_ip.is_empty() {
                merge_arp_table(sweep_devices, sweep_app_handle, &sweep_iface_ip).await;
            }
        });

        // Auto-adopt handler for foreign subnets
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

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                if !*auto_adopt.lock().await {
                    continue;
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

                    match auto_adopt::adopt_subnet(
                        &iface_name,
                        device_ip,
                        &current_ips,
                    )
                    .await
                    {
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

                            log::info!(
                                "Auto-adopted {} with IP {}",
                                device.subnet,
                                adopted_ip
                            );

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

    pub async fn get_arp_devices(&self) -> Vec<ArpDevice> {
        let map = self.arp_devices.lock().await;
        map.values().cloned().collect()
    }

    pub async fn get_adopted_ips(&self) -> HashMap<String, String> {
        let map = self.adopted_ips.lock().await;
        map.iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect()
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
async fn ping_sweep_subnets(interface_ips: &[String]) {
    use tokio::task::JoinSet;

    let mut join_set = JoinSet::new();

    for ip_str in interface_ips {
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            let o = ip.octets();
            for last in 1..=254 {
                let target = format!("{}.{}.{}.{}", o[0], o[1], o[2], last);
                join_set.spawn(async move {
                    let _ = async_cmd("ping")
                        .args(["-n", "1", "-w", "200", &target])
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
    app_handle: tauri::AppHandle,
    interface_ip: &str,
) {
    use tauri::Emitter;

    let entries = arp::read_system_arp_table(interface_ip).await;
    let mut added = 0u32;

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
        map.insert(mac, device);
        added += 1;
    }

    if added > 0 {
        log::info!("Merged {} devices from OS ARP table", added);
    }
}
