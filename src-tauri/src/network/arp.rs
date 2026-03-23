use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::Emitter;
use tokio::sync::Mutex;

use crate::error::AppError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpDevice {
    pub mac: String,
    pub ip: String,
    pub subnet: String,
    pub first_seen: String,
    pub last_seen: String,
}

pub struct ArpListenerHandle {
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl ArpListenerHandle {
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Start raw pcap ARP listener on the Ethernet interface.
/// Discovers all devices on the wire — both known and foreign subnets.
pub fn start_listener(
    devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    app_handle: tauri::AppHandle,
) -> Result<ArpListenerHandle, AppError> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    log::info!("Starting pcap ARP listener");

    tokio::task::spawn_blocking(move || {
        let pcap_devices = match pcap::Device::list() {
            Ok(devs) => devs,
            Err(e) => {
                log::warn!("pcap: failed to list devices: {}", e);
                return;
            }
        };

        log::info!("pcap: found {} capture devices", pcap_devices.len());

        // Find the Ethernet adapter by matching IPs
        let our_ips: Vec<std::net::IpAddr> = match crate::network::interface::list_all() {
            Ok(ifaces) => ifaces
                .iter()
                .filter(|i| i.is_ethernet && i.is_up)
                .flat_map(|i| {
                    i.ips
                        .iter()
                        .filter_map(|ip| ip.address.parse::<std::net::IpAddr>().ok())
                })
                .collect(),
            Err(_) => vec![],
        };

        let pcap_dev = pcap_devices.into_iter().find(|d| {
            d.addresses.iter().any(|a| our_ips.contains(&a.addr))
        });

        let pcap_dev = match pcap_dev {
            Some(d) => {
                log::info!("pcap: using device '{}'", d.name);
                d
            }
            None => {
                log::warn!("pcap: no device matched Ethernet IPs");
                return;
            }
        };

        let mut cap = match pcap::Capture::from_device(pcap_dev)
            .map_err(|e| format!("{}", e))
            .and_then(|c| {
                c.promisc(true)
                    .timeout(500)
                    .snaplen(64)
                    .open()
                    .map_err(|e| format!("{}", e))
            }) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("pcap: failed to open capture: {}", e);
                return;
            }
        };

        if let Err(e) = cap.filter("arp", true) {
            log::warn!("pcap: failed to set BPF filter: {}", e);
            return;
        }

        log::info!("pcap: ARP capture started");

        loop {
            if *shutdown_rx.borrow() {
                log::info!("pcap: shutting down");
                break;
            }

            match cap.next_packet() {
                Ok(packet) => {
                    if let Some((ip, mac)) = parse_arp_packet(packet.data) {
                        if ip == Ipv4Addr::new(0, 0, 0, 0) {
                            continue;
                        }

                        let ip_str = ip.to_string();
                        let mac_str = format_mac(&mac);

                        let devices = devices.clone();
                        let app_handle = app_handle.clone();
                        tokio::spawn(async move {
                            let octets = ip.octets();
                            let subnet = format!(
                                "{}.{}.{}.0/24",
                                octets[0], octets[1], octets[2]
                            );
                            let now = chrono::Utc::now().to_rfc3339();

                            let device = ArpDevice {
                                mac: mac_str.clone(),
                                ip: ip_str.clone(),
                                subnet,
                                first_seen: now.clone(),
                                last_seen: now,
                            };

                            let mut map = devices.lock().await;
                            let is_new = !map.contains_key(&mac_str);

                            let entry =
                                map.entry(mac_str.clone()).or_insert(device.clone());
                            entry.last_seen = device.last_seen.clone();
                            entry.ip = device.ip.clone();

                            if is_new {
                                log::info!("ARP: {} ({})", entry.ip, entry.mac);
                                let _ =
                                    app_handle.emit("arp-device-discovered", &device);
                            }
                        });
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    log::debug!("pcap: read error: {}", e);
                    continue;
                }
            }
        }
    });

    Ok(ArpListenerHandle { shutdown_tx })
}

fn parse_arp_packet(data: &[u8]) -> Option<(Ipv4Addr, [u8; 6])> {
    if data.len() < 42 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != 0x0806 {
        return None;
    }
    let arp = &data[14..];
    if u16::from_be_bytes([arp[0], arp[1]]) != 1
        || u16::from_be_bytes([arp[2], arp[3]]) != 0x0800
        || arp[4] != 6
        || arp[5] != 4
    {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&arp[8..14]);
    let ip = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
    if mac == [0xff; 6] {
        return None;
    }
    Some((ip, mac))
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Check if `target_ip` is in use by pinging and checking ARP table.
pub async fn send_arp_probe(
    target_ip: Ipv4Addr,
    timeout: std::time::Duration,
) -> Result<bool, AppError> {
    let timeout_ms = timeout.as_millis().to_string();
    let _ = tokio::process::Command::new("ping")
        .args(["-n", "1", "-w", &timeout_ms, &target_ip.to_string()])
        .output()
        .await;

    let output = tokio::process::Command::new("arp")
        .args(["-a"])
        .output()
        .await
        .map_err(|e| AppError::Network(format!("arp failed: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let target_str = target_ip.to_string();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == target_str && parts[2].to_lowercase() == "dynamic" {
            return Ok(true);
        }
    }
    Ok(false)
}
