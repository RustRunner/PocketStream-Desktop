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
/// Tries .100, then .101, .99, .102, .98, etc., skipping the device IP itself
/// and any last-octet values already used by the interface (to keep IPs
/// distinguishable across subnets).
fn pick_candidate_ip(device_ip: Ipv4Addr, used_last_octets: &[u8]) -> Vec<Ipv4Addr> {
    let octets = device_ip.octets();
    let device_last = octets[3];
    let base = [octets[0], octets[1], octets[2]];

    let mut candidates = Vec::new();
    let starts: &[u8] = &[100, 101, 99, 102, 98, 103, 97, 104, 96, 105, 95];
    for &last in starts {
        if last != device_last
            && last != 0
            && last != 255
            && last != 1
            && !used_last_octets.contains(&last)
        {
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
        log::info!("Already on subnet for {} — skipping auto-adopt", device_ip);
        return Ok(None);
    }

    // Collect last octets from all existing IPs on the interface so the
    // candidate picker avoids them (keeps IPs distinguishable across subnets).
    let used_last_octets: Vec<u8> = current_ips.iter().map(|ip| ip.octets()[3]).collect();
    let candidates = pick_candidate_ip(device_ip, &used_last_octets);

    for candidate in candidates {
        // ARP probe to check if candidate is in use
        let in_use =
            super::arp::send_arp_probe(candidate, std::time::Duration::from_secs(1)).await?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ── already_on_subnet ───────────────────────────────────────────

    #[test]
    fn already_on_subnet_same_24() {
        let device = Ipv4Addr::new(192, 168, 1, 50);
        let ours = vec![Ipv4Addr::new(192, 168, 1, 100)];
        assert!(already_on_subnet(device, &ours));
    }

    #[test]
    fn already_on_subnet_different_third_octet() {
        let device = Ipv4Addr::new(192, 168, 2, 50);
        let ours = vec![Ipv4Addr::new(192, 168, 1, 100)];
        assert!(!already_on_subnet(device, &ours));
    }

    #[test]
    fn already_on_subnet_different_second_octet() {
        let device = Ipv4Addr::new(10, 1, 1, 50);
        let ours = vec![Ipv4Addr::new(10, 2, 1, 50)];
        assert!(!already_on_subnet(device, &ours));
    }

    #[test]
    fn already_on_subnet_empty_ips() {
        let device = Ipv4Addr::new(10, 0, 0, 1);
        assert!(!already_on_subnet(device, &[]));
    }

    #[test]
    fn already_on_subnet_multiple_ips_one_matches() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        let ours = vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(10, 0, 0, 100)];
        assert!(already_on_subnet(device, &ours));
    }

    #[test]
    fn already_on_subnet_exact_same_ip() {
        let device = Ipv4Addr::new(192, 168, 1, 100);
        let ours = vec![Ipv4Addr::new(192, 168, 1, 100)];
        assert!(already_on_subnet(device, &ours));
    }

    // ── pick_candidate_ip ───────────────────────────────────────────

    #[test]
    fn pick_candidate_returns_same_subnet() {
        let device = Ipv4Addr::new(192, 168, 5, 10);
        let candidates = pick_candidate_ip(device, &[]);
        assert!(!candidates.is_empty());
        for c in &candidates {
            let o = c.octets();
            assert_eq!(o[0], 192);
            assert_eq!(o[1], 168);
            assert_eq!(o[2], 5);
        }
    }

    #[test]
    fn pick_candidate_starts_at_100() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        let candidates = pick_candidate_ip(device, &[]);
        assert_eq!(candidates[0], Ipv4Addr::new(10, 0, 0, 100));
    }

    #[test]
    fn pick_candidate_skips_device_ip() {
        let device = Ipv4Addr::new(10, 0, 0, 100);
        let candidates = pick_candidate_ip(device, &[]);
        assert!(!candidates.contains(&Ipv4Addr::new(10, 0, 0, 100)));
    }

    #[test]
    fn pick_candidate_skips_reserved_addresses() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        let candidates = pick_candidate_ip(device, &[]);
        for c in &candidates {
            let last = c.octets()[3];
            assert_ne!(last, 0, "Should not pick .0 (network)");
            assert_ne!(last, 255, "Should not pick .255 (broadcast)");
            assert_ne!(last, 1, "Should not pick .1 (gateway)");
        }
    }

    #[test]
    fn pick_candidate_returns_multiple() {
        let device = Ipv4Addr::new(172, 16, 0, 50);
        let candidates = pick_candidate_ip(device, &[]);
        assert!(candidates.len() >= 5, "Should return several candidates");
    }

    #[test]
    fn pick_candidate_no_duplicates() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        let candidates = pick_candidate_ip(device, &[]);
        let unique: std::collections::HashSet<_> = candidates.iter().collect();
        assert_eq!(unique.len(), candidates.len());
    }

    #[test]
    fn pick_candidate_skips_used_last_octets() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        // Interface already has .100 — candidate should skip it
        let candidates = pick_candidate_ip(device, &[100]);
        assert!(!candidates.contains(&Ipv4Addr::new(10, 0, 0, 100)));
        // Should start with .101 instead
        assert_eq!(candidates[0], Ipv4Addr::new(10, 0, 0, 101));
    }

    #[test]
    fn pick_candidate_skips_multiple_used_octets() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        // Interface has .100 and .101
        let candidates = pick_candidate_ip(device, &[100, 101]);
        assert!(!candidates.contains(&Ipv4Addr::new(10, 0, 0, 100)));
        assert!(!candidates.contains(&Ipv4Addr::new(10, 0, 0, 101)));
        // Should start with .99
        assert_eq!(candidates[0], Ipv4Addr::new(10, 0, 0, 99));
    }
}
