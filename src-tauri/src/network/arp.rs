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

/// Start raw pcap ARP listener on the specified Ethernet interface.
/// Discovers all devices on the wire — both known and foreign subnets.
///
/// `ethernet_ips` — IPv4 addresses assigned to the target Ethernet adapter.
/// Used to match the correct pcap capture device (avoids picking WiFi).
pub fn start_listener(
    devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    app_handle: tauri::AppHandle,
    ethernet_ips: Vec<Ipv4Addr>,
) -> Result<ArpListenerHandle, AppError> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    log::info!(
        "Starting pcap ARP listener (target IPs: {:?})",
        ethernet_ips
    );

    tokio::task::spawn_blocking(move || {
        let pcap_devices = match pcap::Device::list() {
            Ok(devs) => devs,
            Err(e) => {
                log::warn!("pcap: failed to list devices: {}", e);
                return;
            }
        };

        log::info!("pcap: found {} capture devices", pcap_devices.len());

        // Log all pcap devices for diagnostics
        for d in &pcap_devices {
            let addrs: Vec<String> = d.addresses.iter().map(|a| a.addr.to_string()).collect();
            log::debug!("pcap: device '{}' addrs={:?}", d.name, addrs);
        }

        // Match the pcap device that has one of the target Ethernet IPs.
        // This ensures we capture on the Ethernet adapter, not WiFi.
        let target_addrs: Vec<std::net::IpAddr> = ethernet_ips
            .iter()
            .map(|ip| std::net::IpAddr::V4(*ip))
            .collect();

        let pcap_dev = pcap_devices
            .into_iter()
            .find(|d| d.addresses.iter().any(|a| target_addrs.contains(&a.addr)));

        let pcap_dev = match pcap_dev {
            Some(d) => {
                log::info!("pcap: using device '{}'", d.name);
                d
            }
            None => {
                log::warn!("pcap: no device matched Ethernet IPs {:?}", ethernet_ips);
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
                            let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
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

                            let entry = map.entry(mac_str.clone()).or_insert(device.clone());
                            entry.last_seen = device.last_seen.clone();
                            entry.ip = device.ip.clone();

                            if is_new {
                                log::info!("ARP: {} ({})", entry.ip, entry.mac);
                                let _ = app_handle.emit("arp-device-discovered", &device);
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

/// Read the OS ARP table for a specific interface and return dynamic entries.
///
/// Supplements pcap-based discovery: if a host is already in the OS
/// ARP cache (e.g. from a prior browser visit), the ping sweep won't
/// generate a new ARP request on the wire, so pcap never sees it.
///
/// `interface_ip` scopes the query to a single interface via `arp -a -N`,
/// preventing WiFi entries from leaking in.
pub async fn read_system_arp_table(interface_ip: &str) -> Vec<(Ipv4Addr, String)> {
    let output = match super::async_cmd("arp")
        .args(["-a", "-N", interface_ip])
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => {
            log::warn!("Failed to read ARP table: {}", e);
            return vec![];
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    log::debug!(
        "ARP table for {}: {} entries",
        interface_ip,
        stdout.lines().count()
    );
    parse_arp_table(&stdout)
}

/// Parse `arp -a` output into (IP, MAC) pairs.
/// Only returns dynamic entries with valid IPv4 addresses.
fn parse_arp_table(output: &str) -> Vec<(Ipv4Addr, String)> {
    let mut entries = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Windows `arp -a` format: "  192.168.1.207  aa-bb-cc-dd-ee-ff  dynamic"
        if parts.len() >= 3 && parts[2].eq_ignore_ascii_case("dynamic") {
            if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                // Normalize MAC from aa-bb-cc-dd-ee-ff to aa:bb:cc:dd:ee:ff
                let mac = parts[1].replace('-', ":").to_lowercase();
                // Skip incomplete entries (ff-ff-ff-ff-ff-ff or 00-00-00-00-00-00)
                if mac != "ff:ff:ff:ff:ff:ff" && mac != "00:00:00:00:00:00" {
                    entries.push((ip, mac));
                }
            }
        }
    }
    entries
}

/// Check if `target_ip` is in use by pinging and checking ARP table.
pub async fn send_arp_probe(
    target_ip: Ipv4Addr,
    timeout: std::time::Duration,
) -> Result<bool, AppError> {
    let timeout_ms = timeout.as_millis().to_string();
    let _ = super::async_cmd("ping")
        .args(["-n", "1", "-w", &timeout_ms, &target_ip.to_string()])
        .output()
        .await;

    let output = super::async_cmd("arp")
        .args(["-a"])
        .output()
        .await
        .map_err(|e| AppError::Network(format!("arp failed: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let target_str = target_ip.to_string();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == target_str && parts[2].to_lowercase() == "dynamic" {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Build a minimal valid ARP packet (42 bytes: 14 Ethernet + 28 ARP).
    fn make_arp_packet(sender_mac: [u8; 6], sender_ip: [u8; 4]) -> Vec<u8> {
        let mut pkt = vec![0u8; 42];
        // Destination MAC (6 bytes) + Source MAC (6 bytes) — left as zeros
        // Ethertype: ARP = 0x0806
        pkt[12] = 0x08;
        pkt[13] = 0x06;
        // ARP header starts at offset 14
        let arp = &mut pkt[14..];
        arp[0] = 0x00;
        arp[1] = 0x01; // Hardware type: Ethernet (1)
        arp[2] = 0x08;
        arp[3] = 0x00; // Protocol type: IPv4 (0x0800)
        arp[4] = 6; // Hardware address length
        arp[5] = 4; // Protocol address length
        arp[6] = 0x00;
        arp[7] = 0x02; // Opcode: Reply (2)
        arp[8..14].copy_from_slice(&sender_mac);
        arp[14..18].copy_from_slice(&sender_ip);
        pkt
    }

    #[test]
    fn parse_valid_arp_reply() {
        let pkt = make_arp_packet([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01], [192, 168, 1, 100]);
        let (ip, mac) = parse_arp_packet(&pkt).unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
    }

    #[test]
    fn parse_arp_different_subnet() {
        let pkt = make_arp_packet([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], [10, 0, 0, 42]);
        let (ip, mac) = parse_arp_packet(&pkt).unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 42));
        assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn parse_arp_high_octets() {
        let pkt = make_arp_packet([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54], [172, 16, 255, 254]);
        let (ip, _mac) = parse_arp_packet(&pkt).unwrap();
        assert_eq!(ip, Ipv4Addr::new(172, 16, 255, 254));
    }

    #[test]
    fn reject_packet_too_short() {
        assert!(parse_arp_packet(&[0u8; 41]).is_none());
    }

    #[test]
    fn reject_empty_packet() {
        assert!(parse_arp_packet(&[]).is_none());
    }

    #[test]
    fn reject_non_arp_ethertype() {
        let mut pkt = make_arp_packet([1; 6], [10, 0, 0, 1]);
        pkt[12] = 0x08;
        pkt[13] = 0x00; // IPv4 ethertype, not ARP
        assert!(parse_arp_packet(&pkt).is_none());
    }

    #[test]
    fn reject_non_ethernet_hardware_type() {
        let mut pkt = make_arp_packet([1; 6], [10, 0, 0, 1]);
        pkt[14] = 0x00;
        pkt[15] = 0x06; // Hardware type 6 (IEEE 802) instead of 1
        assert!(parse_arp_packet(&pkt).is_none());
    }

    #[test]
    fn reject_non_ipv4_protocol() {
        let mut pkt = make_arp_packet([1; 6], [10, 0, 0, 1]);
        pkt[16] = 0x86;
        pkt[17] = 0xDD; // IPv6 protocol type
        assert!(parse_arp_packet(&pkt).is_none());
    }

    #[test]
    fn reject_wrong_hardware_addr_len() {
        let mut pkt = make_arp_packet([1; 6], [10, 0, 0, 1]);
        pkt[18] = 8; // hw addr len 8 instead of 6
        assert!(parse_arp_packet(&pkt).is_none());
    }

    #[test]
    fn reject_wrong_protocol_addr_len() {
        let mut pkt = make_arp_packet([1; 6], [10, 0, 0, 1]);
        pkt[19] = 16; // proto addr len 16 instead of 4
        assert!(parse_arp_packet(&pkt).is_none());
    }

    #[test]
    fn reject_broadcast_mac() {
        let pkt = make_arp_packet([0xFF; 6], [192, 168, 1, 1]);
        assert!(parse_arp_packet(&pkt).is_none());
    }

    #[test]
    fn accept_exactly_42_bytes() {
        let pkt = make_arp_packet([0x01, 0x02, 0x03, 0x04, 0x05, 0x06], [1, 2, 3, 4]);
        assert_eq!(pkt.len(), 42);
        assert!(parse_arp_packet(&pkt).is_some());
    }

    #[test]
    fn accept_oversized_packet() {
        let mut pkt = make_arp_packet([0x01; 6], [192, 168, 0, 1]);
        pkt.extend_from_slice(&[0u8; 100]); // trailing data (padding)
        let (ip, _) = parse_arp_packet(&pkt).unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 0, 1));
    }

    // ── format_mac ──────────────────────────────────────────────────

    #[test]
    fn format_mac_standard() {
        assert_eq!(
            format_mac(&[0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03]),
            "aa:bb:cc:01:02:03"
        );
    }

    #[test]
    fn format_mac_all_zeros() {
        assert_eq!(format_mac(&[0; 6]), "00:00:00:00:00:00");
    }

    #[test]
    fn format_mac_all_ff() {
        assert_eq!(format_mac(&[0xFF; 6]), "ff:ff:ff:ff:ff:ff");
    }

    // ── parse_arp_table ─────────────────────────────────────────────

    #[test]
    fn parse_arp_table_windows_format() {
        let output = "\
Interface: 192.168.1.100 --- 0x6
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
  192.168.1.207         aa-bb-cc-dd-ee-02     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
";
        let entries = parse_arp_table(output);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(entries[0].1, "aa:bb:cc:dd:ee:01");
        assert_eq!(entries[1].0, Ipv4Addr::new(192, 168, 1, 207));
        assert_eq!(entries[1].1, "aa:bb:cc:dd:ee:02");
    }

    #[test]
    fn parse_arp_table_skips_static_entries() {
        let output = "  192.168.1.1  aa-bb-cc-dd-ee-ff  static\n";
        let entries = parse_arp_table(output);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_arp_table_skips_broadcast() {
        let output = "  192.168.1.255  ff-ff-ff-ff-ff-ff  dynamic\n";
        let entries = parse_arp_table(output);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_arp_table_skips_zeroed_mac() {
        let output = "  192.168.1.50  00-00-00-00-00-00  dynamic\n";
        let entries = parse_arp_table(output);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_arp_table_empty_output() {
        assert!(parse_arp_table("").is_empty());
    }

    #[test]
    fn parse_arp_table_header_lines_ignored() {
        let output = "\
Interface: 192.168.1.100 --- 0x6
  Internet Address      Physical Address      Type
";
        assert!(parse_arp_table(output).is_empty());
    }

    #[test]
    fn parse_arp_table_normalizes_mac() {
        let output = "  10.0.0.1  AA-BB-CC-DD-EE-FF  dynamic\n";
        let entries = parse_arp_table(output);
        assert_eq!(entries[0].1, "aa:bb:cc:dd:ee:ff");
    }
}
