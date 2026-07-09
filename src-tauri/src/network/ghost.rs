//! Structural-ghost subnet helpers.
//!
//! A *structural ghost* is a subnet owned by a currently-up local
//! interface that is not the wired camera port — WiFi, VPN, or any
//! virtual adapter (Hyper-V/WSL switches, VMware/VirtualBox host adapters,
//! keyword-missed VPN clients). Discovery, adoption, restore, and cache
//! hydration all reject these so only wired-Ethernet peers become nodes
//! and adoptions.
//!
//! Every enumeration failure fails open (empty ghost set) so a transient
//! WMI/PowerShell hiccup can never blind real camera discovery.
//!
//! All decision logic here is pure and unit-tested. `NetworkManager`
//! cannot be constructed in lib tests, so the `mod.rs` callers are thin
//! wiring over these functions.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;

use super::interface::{self, InterfaceInfo, IpInfo};

/// Canonical (network-address) `Ipv4Network` for an interface IP, or
/// `None` for an unparseable / non-IPv4 address. Keeps the real prefix
/// length — a WiFi/VPN network may be /16, /20, /23, /24, etc.
fn ip_to_network(ip: &IpInfo) -> Option<Ipv4Network> {
    let addr: Ipv4Addr = ip.address.parse().ok()?;
    let net = Ipv4Network::new(addr, ip.prefix).ok()?;
    Ipv4Network::new(net.network(), ip.prefix).ok()
}

/// Pure core of [`non_wired_interface_networks`]: the networks owned by
/// up, non-wired interfaces, minus any network also owned by a wired
/// Ethernet adapter. The carve-out means a camera deliberately sharing
/// the wired subnet is never treated as a ghost; a camera on a
/// foreign/APIPA subnet owned by no local interface is untouched because
/// that subnet appears in neither set.
pub fn non_wired_networks_of(ifaces: &[InterfaceInfo]) -> Vec<Ipv4Network> {
    let wired: Vec<Ipv4Network> = ifaces
        .iter()
        .filter(|i| interface::is_wired_ethernet(i))
        .flat_map(|i| i.ips.iter().filter_map(ip_to_network))
        .collect();
    let mut excluded: Vec<Ipv4Network> = Vec::new();
    for iface in ifaces
        .iter()
        .filter(|i| i.is_up && !interface::is_wired_ethernet(i))
    {
        for net in iface.ips.iter().filter_map(ip_to_network) {
            if !wired.contains(&net) && !excluded.contains(&net) {
                excluded.push(net);
            }
        }
    }
    excluded
}

/// Enumerate structural-ghost networks from the full adapter list
/// (physical *and* virtual). Fails open — logs and returns empty on an
/// enumeration error — so discovery/adoption is never blinded by a
/// transient adapter-query failure.
pub async fn non_wired_interface_networks() -> Vec<Ipv4Network> {
    match interface::list_all_adapters().await {
        Ok(ifaces) => non_wired_networks_of(&ifaces),
        Err(e) => {
            log::warn!(
                "Could not enumerate adapters to scope discovery to wired Ethernet: {}",
                e
            );
            Vec::new()
        }
    }
}

/// True if `ip` falls inside any structural-ghost network.
// Wired into the adoption-time guard.
#[allow(dead_code)]
pub fn is_structural_ghost_ip(ip: Ipv4Addr, networks: &[Ipv4Network]) -> bool {
    networks.iter().any(|net| net.contains(ip))
}

/// True if an adoption key (e.g. `"192.168.12.0/24"`) overlaps any
/// structural-ghost network. Two CIDR blocks overlap iff one contains the
/// other's network address (they are otherwise disjoint), so this catches
/// a /24 adoption key contained in a wider WiFi/VPN /16. A key that fails
/// to parse is treated as **not** a ghost — fail open, never prune an
/// adoption we cannot classify.
pub fn is_structural_ghost_adoption(subnet_key: &str, networks: &[Ipv4Network]) -> bool {
    let key_net: Ipv4Network = match subnet_key.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    networks
        .iter()
        .any(|net| net.contains(key_net.network()) || key_net.contains(net.network()))
}

/// How a persisted adoption entry should be handled on restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptionClass {
    /// Re-bind and keep.
    Keep,
    /// The wired adapter already covers this subnet natively — drop it.
    PruneNative,
    /// Owned by a non-wired local interface (WiFi/VPN/virtual) — drop it.
    PruneGhost,
    /// The saved IP does not parse — drop it.
    PruneInvalid,
}

/// Pure restore-time decision for one `adopted_subnets` entry. Precedence:
/// native coverage first (the adapter owns it outright), then structural
/// ghost (a non-wired interface owns it), then an unparseable IP; anything
/// else is kept and re-bound. A foreign camera subnet owned by no local
/// interface (e.g. CAM) is neither native nor ghost, so it is kept.
pub fn classify_adoption(
    subnet_key: &str,
    ip_str: &str,
    native_subnets: &HashSet<String>,
    ghosts: &[Ipv4Network],
) -> AdoptionClass {
    if native_subnets.contains(subnet_key) {
        AdoptionClass::PruneNative
    } else if is_structural_ghost_adoption(subnet_key, ghosts) {
        AdoptionClass::PruneGhost
    } else if ip_str.parse::<Ipv4Addr>().is_err() {
        AdoptionClass::PruneInvalid
    } else {
        AdoptionClass::Keep
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(addr: &str, prefix: u8) -> IpInfo {
        IpInfo {
            address: addr.into(),
            prefix,
            // Recomputed by ip_to_network from address/prefix; unused here.
            subnet: String::new(),
        }
    }

    fn ifc(
        ips: Vec<IpInfo>,
        is_up: bool,
        is_ethernet: bool,
        is_vpn: bool,
        is_virtual: bool,
    ) -> InterfaceInfo {
        InterfaceInfo {
            name: "t".into(),
            display_name: "t".into(),
            ips,
            mac: String::new(),
            is_up,
            is_ethernet,
            is_wifi: !is_ethernet,
            is_vpn,
            is_virtual,
        }
    }

    fn net(s: &str) -> Ipv4Network {
        s.parse().unwrap()
    }

    // ── is_wired_ethernet matrix ────────────────────────────────────

    #[test]
    fn wired_ethernet_only_for_up_physical_ethernet() {
        // The canonical camera port.
        assert!(interface::is_wired_ethernet(&ifc(
            vec![ip("192.168.1.10", 24)],
            true,
            true,
            false,
            false
        )));
        // Down Ethernet is not selectable as a live camera port.
        assert!(!interface::is_wired_ethernet(&ifc(
            vec![],
            false,
            true,
            false,
            false
        )));
        // WiFi (non-Ethernet media).
        assert!(!interface::is_wired_ethernet(&ifc(
            vec![ip("192.168.12.5", 24)],
            true,
            false,
            false,
            false
        )));
        // VPN reporting Ethernet media must be rejected.
        assert!(!interface::is_wired_ethernet(&ifc(
            vec![ip("10.39.129.5", 24)],
            true,
            true,
            true,
            false
        )));
        // Keyword-missed virtual switch reporting Ethernet media.
        assert!(!interface::is_wired_ethernet(&ifc(
            vec![ip("172.28.0.1", 20)],
            true,
            true,
            false,
            true
        )));
    }

    // ── non_wired_networks_of ───────────────────────────────────────

    #[test]
    fn non_wired_excludes_wifi_subnet() {
        let ifaces = vec![
            ifc(vec![ip("192.168.1.10", 24)], true, true, false, false), // wired
            ifc(vec![ip("192.168.12.5", 24)], true, false, false, false), // WiFi
        ];
        let excluded = non_wired_networks_of(&ifaces);
        assert_eq!(excluded, vec![net("192.168.12.0/24")]);
    }

    #[test]
    fn non_wired_carves_out_subnet_shared_with_wired() {
        // A camera deliberately placed on a /24 that WiFi also owns must
        // stay discoverable — the shared subnet is on wired, so it is
        // carved out of the ghost set.
        let ifaces = vec![
            ifc(vec![ip("10.0.0.5", 24)], true, true, false, false), // wired 10.0.0.0/24
            ifc(vec![ip("10.0.0.9", 24)], true, false, false, false), // WiFi 10.0.0.0/24
        ];
        assert!(non_wired_networks_of(&ifaces).is_empty());
    }

    #[test]
    fn non_wired_excludes_vpn_as_ethernet() {
        // VPN adapter reporting Ethernet media — the exact failure the fix
        // targets. Its subnet must land in the ghost set.
        let ifaces = vec![
            ifc(vec![ip("192.168.1.10", 24)], true, true, false, false),
            ifc(vec![ip("10.39.129.50", 24)], true, true, true, false),
        ];
        assert_eq!(non_wired_networks_of(&ifaces), vec![net("10.39.129.0/24")]);
    }

    #[test]
    fn non_wired_excludes_virtual_switch() {
        // Hyper-V/WSL vEthernet: Ethernet media, Virtual=true.
        let ifaces = vec![ifc(vec![ip("172.28.0.1", 20)], true, true, false, true)];
        assert_eq!(non_wired_networks_of(&ifaces), vec![net("172.28.0.0/20")]);
    }

    #[test]
    fn non_wired_ignores_down_interfaces() {
        let ifaces = vec![ifc(vec![ip("172.16.0.5", 24)], false, false, false, false)];
        assert!(non_wired_networks_of(&ifaces).is_empty());
    }

    #[test]
    fn non_wired_preserves_non_24_prefixes() {
        let ifaces = vec![
            ifc(vec![ip("172.28.5.4", 16)], true, false, false, false), // /16
            ifc(vec![ip("10.20.16.9", 20)], true, false, false, false), // /20
            ifc(vec![ip("10.30.2.9", 23)], true, false, false, false),  // /23
        ];
        let excluded = non_wired_networks_of(&ifaces);
        assert!(excluded.contains(&net("172.28.0.0/16")));
        assert!(excluded.contains(&net("10.20.16.0/20")));
        assert!(excluded.contains(&net("10.30.2.0/23")));
    }

    // ── is_structural_ghost_ip ──────────────────────────────────────

    #[test]
    fn ghost_ip_containment() {
        let ghosts = vec![net("192.168.12.0/24")];
        assert!(is_structural_ghost_ip(
            "192.168.12.50".parse().unwrap(),
            &ghosts
        ));
        assert!(!is_structural_ghost_ip(
            "192.168.1.50".parse().unwrap(),
            &ghosts
        ));
    }

    #[test]
    fn ghost_ip_containment_wide_prefix() {
        let ghosts = vec![net("172.28.0.0/16")];
        assert!(is_structural_ghost_ip(
            "172.28.240.9".parse().unwrap(),
            &ghosts
        ));
        assert!(!is_structural_ghost_ip(
            "172.29.0.9".parse().unwrap(),
            &ghosts
        ));
    }

    // ── is_structural_ghost_adoption ────────────────────────────────

    #[test]
    fn ghost_adoption_exact_match() {
        let ghosts = vec![net("192.168.12.0/24")];
        assert!(is_structural_ghost_adoption("192.168.12.0/24", &ghosts));
        assert!(!is_structural_ghost_adoption("192.168.1.0/24", &ghosts));
    }

    #[test]
    fn ghost_adoption_24_contained_in_ghost_16() {
        let ghosts = vec![net("172.28.0.0/16")];
        assert!(is_structural_ghost_adoption("172.28.5.0/24", &ghosts));
    }

    #[test]
    fn ghost_adoption_foreign_camera_subnet_survives() {
        // CAM on a legitimate foreign subnet owned by no local interface
        // must not be classified a ghost.
        let ghosts = vec![net("192.168.12.0/24"), net("10.39.129.0/24")];
        assert!(!is_structural_ghost_adoption("10.13.248.0/24", &ghosts));
    }

    #[test]
    fn ghost_adoption_unparseable_key_is_not_ghost() {
        // Fail open: a key we cannot parse is never pruned.
        let ghosts = vec![net("192.168.12.0/24")];
        assert!(!is_structural_ghost_adoption("not-a-subnet", &ghosts));
        assert!(!is_structural_ghost_adoption("", &ghosts));
    }

    // ── classify_adoption ───────────────────────────────────────────

    fn native(subnets: &[&str]) -> HashSet<String> {
        subnets.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn classify_native_subnet_prunes_native() {
        let n = native(&["192.168.1.0/24"]);
        assert_eq!(
            classify_adoption("192.168.1.0/24", "192.168.1.50", &n, &[]),
            AdoptionClass::PruneNative
        );
    }

    #[test]
    fn classify_ghost_subnet_prunes_ghost() {
        let ghosts = vec![net("192.168.12.0/24")];
        assert_eq!(
            classify_adoption("192.168.12.0/24", "192.168.12.103", &native(&[]), &ghosts),
            AdoptionClass::PruneGhost
        );
    }

    #[test]
    fn classify_invalid_ip_prunes_invalid() {
        assert_eq!(
            classify_adoption("10.5.0.0/24", "not-an-ip", &native(&[]), &[]),
            AdoptionClass::PruneInvalid
        );
    }

    #[test]
    fn classify_foreign_camera_subnet_is_kept() {
        // CAM: a foreign subnet owned by no local interface — neither
        // native nor ghost — must be re-bound.
        let ghosts = vec![net("192.168.12.0/24")];
        assert_eq!(
            classify_adoption(
                "10.13.248.0/24",
                "10.13.248.102",
                &native(&["192.168.1.0/24"]),
                &ghosts
            ),
            AdoptionClass::Keep
        );
    }

    #[test]
    fn classify_ghost_takes_precedence_over_valid_ip() {
        // A ghost subnet with a perfectly valid bound IP is still pruned.
        let ghosts = vec![net("172.28.0.0/16")];
        assert_eq!(
            classify_adoption("172.28.5.0/24", "172.28.5.42", &native(&[]), &ghosts),
            AdoptionClass::PruneGhost
        );
    }
}
