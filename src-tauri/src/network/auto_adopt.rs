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
/// Tries .100, then .101, .99, .102, .98, etc., skipping the device IP
/// itself, the reserved .0/.1/.255, and any **full IP** already in
/// `used_ips`. `used_ips` compares whole addresses (not last octets) so
/// a .100 on a *different* /24 doesn't needlessly block .100 here, while
/// a .100 held by any local adapter on *this* /24 does.
fn pick_candidate_ip(device_ip: Ipv4Addr, used_ips: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    let octets = device_ip.octets();
    let device_last = octets[3];
    let base = [octets[0], octets[1], octets[2]];

    let mut candidates = Vec::new();
    let starts: &[u8] = &[100, 101, 99, 102, 98, 103, 97, 104, 96, 105, 95];
    for &last in starts {
        if last != device_last && last != 0 && last != 255 && last != 1 {
            let candidate = Ipv4Addr::new(base[0], base[1], base[2], last);
            if !used_ips.contains(&candidate) {
                candidates.push(candidate);
            }
        }
    }
    candidates
}

/// Pick a scratch last octet on the candidate /24 that isn't the device,
/// a candidate, or a reserved address. The scratch is bound temporarily
/// so conflict probes route on-link (see `adopt_subnet`).
fn pick_scratch(device_ip: Ipv4Addr, candidates: &[Ipv4Addr]) -> Ipv4Addr {
    let o = device_ip.octets();
    let device_last = o[3];
    let taken: Vec<u8> = candidates.iter().map(|c| c.octets()[3]).collect();
    for &last in &[254u8, 253, 252, 251, 250, 2, 3, 4, 5, 6] {
        if last != device_last && !taken.contains(&last) {
            return Ipv4Addr::new(o[0], o[1], o[2], last);
        }
    }
    Ipv4Addr::new(o[0], o[1], o[2], 254)
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

    // Exclude every IP held by ANY local interface, not just the target —
    // the ARP probe below can't detect the host's own addresses, so a
    // candidate already on e.g. WiFi would look "free" and collide. Union
    // with the passed-in target IPs in case pnet hasn't yet reflected a
    // freshly-added one.
    let mut used_ips = super::interface::all_local_ipv4();
    used_ips.extend_from_slice(current_ips);
    let candidates = pick_candidate_ip(device_ip, &used_ips);
    if candidates.is_empty() {
        return Err(AppError::Network(format!(
            "No candidate IPs available on subnet for {}",
            device_ip
        )));
    }

    // Temporarily bind a scratch address on the candidate /24 so the
    // conflict probes below route on-link. Without an address on this
    // subnet the probe is structurally blind and reports every candidate
    // free, risking a duplicate-IP assignment against a real camera-side
    // device. If the scratch can't be bound, fall back to the (blind)
    // gateway-routed probe rather than aborting — M6's cooldown and the
    // adoption-failed signal cover a subsequent conflict.
    let scratch = pick_scratch(device_ip, &candidates);
    let scratch_bound =
        ip_config::add_secondary_ip(interface_name, &scratch.to_string(), "255.255.255.0")
            .await
            .is_ok();
    if !scratch_bound {
        log::warn!(
            "Could not bind scratch {} for on-link conflict probe; probes may be blind",
            scratch
        );
    }
    let source = scratch_bound.then_some(scratch);

    // Probe candidates on-link, then always release the scratch.
    let mut chosen = None;
    for candidate in &candidates {
        // A probe error (couldn't determine conflict) is treated as
        // in-use — skip it rather than risk a duplicate assignment.
        let in_use =
            super::arp::send_arp_probe(*candidate, source, std::time::Duration::from_secs(1))
                .await
                .unwrap_or(true);
        if !in_use {
            chosen = Some(*candidate);
            break;
        }
        log::info!("Candidate {} is in use, trying next", candidate);
    }

    if scratch_bound {
        if let Err(e) = ip_config::remove_secondary_ip(interface_name, &scratch.to_string()).await {
            log::warn!("Failed to release scratch {}: {}", scratch, e);
        }
    }

    match chosen {
        Some(candidate) => {
            log::info!(
                "Auto-adopting subnet: adding {} to {}",
                candidate,
                interface_name
            );
            ip_config::add_secondary_ip(interface_name, &candidate.to_string(), "255.255.255.0")
                .await?;
            Ok(Some(candidate))
        }
        None => Err(AppError::Network(format!(
            "Could not find available IP on subnet for {}",
            device_ip
        ))),
    }
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
    fn pick_candidate_skips_used_ip() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        // A local adapter already holds .100 — candidate should skip it.
        let candidates = pick_candidate_ip(device, &[Ipv4Addr::new(10, 0, 0, 100)]);
        assert!(!candidates.contains(&Ipv4Addr::new(10, 0, 0, 100)));
        // Should start with .101 instead.
        assert_eq!(candidates[0], Ipv4Addr::new(10, 0, 0, 101));
    }

    #[test]
    fn pick_candidate_skips_multiple_used_ips() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        let used = [Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 101)];
        let candidates = pick_candidate_ip(device, &used);
        assert!(!candidates.contains(&Ipv4Addr::new(10, 0, 0, 100)));
        assert!(!candidates.contains(&Ipv4Addr::new(10, 0, 0, 101)));
        // Should start with .99.
        assert_eq!(candidates[0], Ipv4Addr::new(10, 0, 0, 99));
    }

    #[test]
    fn pick_candidate_excludes_full_ip_on_this_subnet_only() {
        // M7: a WiFi adapter holds 192.168.5.100 on the SAME /24 we're
        // adopting — that candidate must be excluded (an ARP probe can't
        // see the host's own IP).
        let device = Ipv4Addr::new(192, 168, 5, 10);
        let wifi_ip = Ipv4Addr::new(192, 168, 5, 100);
        let candidates = pick_candidate_ip(device, &[wifi_ip]);
        assert!(!candidates.contains(&wifi_ip));
    }

    #[test]
    fn pick_candidate_does_not_block_same_last_octet_on_other_subnet() {
        // A .100 on a DIFFERENT /24 must not block .100 here — the fix
        // compares full IPs, not last octets.
        let device = Ipv4Addr::new(192, 168, 5, 10);
        let other_subnet_ip = Ipv4Addr::new(10, 0, 0, 100);
        let candidates = pick_candidate_ip(device, &[other_subnet_ip]);
        assert!(candidates.contains(&Ipv4Addr::new(192, 168, 5, 100)));
    }

    // ── pick_scratch (D3 on-link probe) ─────────────────────────────

    #[test]
    fn pick_scratch_is_on_the_candidate_subnet() {
        let device = Ipv4Addr::new(192, 168, 5, 10);
        let candidates = pick_candidate_ip(device, &[]);
        let scratch = pick_scratch(device, &candidates);
        let o = scratch.octets();
        assert_eq!([o[0], o[1], o[2]], [192, 168, 5]);
    }

    #[test]
    fn pick_scratch_avoids_device_and_candidates() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        let candidates = pick_candidate_ip(device, &[]);
        let scratch = pick_scratch(device, &candidates);
        assert_ne!(scratch, device);
        assert!(!candidates.contains(&scratch));
    }
}
