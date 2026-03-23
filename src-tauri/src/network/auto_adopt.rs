use std::net::Ipv4Addr;

use crate::error::AppError;
use crate::network::ip_config;

/// Check if any of the given IPs are already on the same /24 subnet as the device.
pub fn already_on_subnet(device_ip: Ipv4Addr, current_ips: &[Ipv4Addr]) -> bool {
    let octets = device_ip.octets();
    current_ips.iter().any(|ip| {
        let o = ip.octets();
        o[0] == octets[0] && o[1] == octets[1] && o[2] == octets[2]
    })
}

/// Pick a candidate IP on the same /24 as `device_ip`.
/// Tries .100, then .101, .99, .102, .98, etc., skipping the device IP itself.
fn pick_candidate_ip(device_ip: Ipv4Addr) -> Vec<Ipv4Addr> {
    let octets = device_ip.octets();
    let device_last = octets[3];
    let base = [octets[0], octets[1], octets[2]];

    let mut candidates = Vec::new();
    let starts: &[u8] = &[100, 101, 99, 102, 98, 103, 97, 104, 96, 105, 95];
    for &last in starts {
        if last != device_last && last != 0 && last != 255 && last != 1 {
            candidates.push(Ipv4Addr::new(base[0], base[1], base[2], last));
        }
    }
    candidates
}

/// Adopt a foreign subnet by adding a secondary IP to the interface.
/// Returns the adopted IP if successful, or None if already on that subnet.
pub async fn adopt_subnet(
    interface_name: &str,
    device_ip: Ipv4Addr,
    current_ips: &[Ipv4Addr],
) -> Result<Option<Ipv4Addr>, AppError> {
    if already_on_subnet(device_ip, current_ips) {
        log::info!(
            "Already on subnet for {} — skipping auto-adopt",
            device_ip
        );
        return Ok(None);
    }

    let candidates = pick_candidate_ip(device_ip);

    for candidate in candidates {
        // ARP probe to check if candidate is in use
        let in_use = super::arp::send_arp_probe(
            candidate,
            std::time::Duration::from_secs(1),
        )
        .await?;

        if !in_use {
            log::info!(
                "Auto-adopting subnet: adding {} to {}",
                candidate,
                interface_name
            );
            ip_config::add_secondary_ip(interface_name, &candidate.to_string(), "255.255.255.0")
                .await?;
            return Ok(Some(candidate));
        }

        log::info!("Candidate {} is in use, trying next", candidate);
    }

    Err(AppError::Network(format!(
        "Could not find available IP on subnet for {}",
        device_ip
    )))
}

/// Remove a previously adopted secondary IP from the interface.
pub async fn remove_adopted_ip(interface_name: &str, ip: &str) -> Result<(), AppError> {
    log::info!("Removing adopted IP {} from {}", ip, interface_name);
    ip_config::remove_secondary_ip(interface_name, ip).await
}
