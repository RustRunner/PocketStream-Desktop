pub mod arp;
pub mod auto_adopt;
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

    pub fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>, AppError> {
        interface::list_all()
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
        let iface_info = interface::get_by_name(interface_display_name)?;
        let known_ips: Vec<String> = iface_info.ips.iter().map(|ip| ip.address.clone()).collect();
        log::info!(
            "Starting ARP discovery on '{}' (IPs: {:?})",
            interface_display_name,
            known_ips
        );

        let handle = arp::start_listener(devices.clone(), app_handle)?;
        *self.arp_listener_handle.lock().await = Some(handle);

        // Ping sweep known subnets to provoke ARP traffic so pcap sees all devices
        let sweep_ips = known_ips.clone();
        tokio::spawn(async move {
            // Small delay to let pcap listener start first
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            log::info!("Ping sweeping known subnets to populate ARP");
            ping_sweep_subnets(&sweep_ips).await;
        });

        // Auto-adopt handler for foreign subnets
        let adopt_handle = tokio::spawn(async move {
            use tauri::Emitter;
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
                    let _ = tokio::process::Command::new("ping")
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
