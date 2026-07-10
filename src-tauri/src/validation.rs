//! Input validation for IPC handlers.
//!
//! Centralizes the SSRF guards that were previously duplicated across
//! every camera-control command. The webview is sandboxed but is not
//! a trusted origin: a compromised script could craft IPC payloads
//! that pivot to arbitrary internal HTTP services if the backend
//! handler builds a URL from raw frontend input. Reject reserved
//! ranges before constructing any URL.

use std::net::Ipv4Addr;

use crate::error::AppError;
use crate::network::{DeviceRegistry, DeviceStatus};

/// Parse an IPv4 string and reject reserved ranges that have no business
/// being addressed as an external camera target. Returns the parsed
/// address on success so the caller can use it directly when building a
/// URL (avoids re-parsing or re-formatting the string).
///
/// Rejected ranges:
/// - `is_loopback()` (127.0.0.0/8) — would target the host itself.
/// - `is_link_local()` (169.254.0.0/16) — APIPA / no real network.
/// - `is_broadcast()` (255.255.255.255) — broadcast address.
/// - `is_unspecified()` (0.0.0.0) — wildcard / "any" address.
pub fn parse_camera_ip(ip: &str) -> Result<Ipv4Addr, AppError> {
    let addr: Ipv4Addr = ip
        .parse()
        .map_err(|_| AppError::Network(format!("Invalid IP address: {}", ip)))?;
    if addr.is_loopback() || addr.is_link_local() || addr.is_broadcast() || addr.is_unspecified() {
        return Err(AppError::Network(format!("IP address not allowed: {}", ip)));
    }
    Ok(addr)
}

/// Variant of [`parse_camera_ip`] for camera-control commands, which must
/// keep working during FLIR APIPA rescue: a camera that lost DHCP falls
/// back to 169.254.x.x, and discovery, adoption, and streaming all accept
/// those addresses — control traffic is needed exactly then. Blanket-
/// allowing link-local would relax the SSRF guard for arbitrary targets,
/// so 169.254.0.0/16 is accepted only when the target is currently known:
///
/// - a **Live** registry record (a FLIR in APIPA rescue is actively
///   ARPing, which flips its record to Live — a months-stale `CachedOnly`
///   row does not qualify),
/// - an explicit manual node, or
/// - an address inside a currently-adopted subnet.
///
/// Loopback, broadcast, and unspecified stay rejected unconditionally.
pub fn parse_known_camera_ip(
    ip: &str,
    registry: &DeviceRegistry,
    adopted_subnets: &[String],
) -> Result<Ipv4Addr, AppError> {
    let addr: Ipv4Addr = ip
        .parse()
        .map_err(|_| AppError::Network(format!("Invalid IP address: {}", ip)))?;
    if !addr.is_link_local() {
        // Everything except the APIPA case defers to the strict guard
        // (link-local is disjoint from the other reserved ranges, so
        // this covers loopback/broadcast/unspecified exactly).
        return parse_camera_ip(ip);
    }

    let known_device = registry.snapshot().into_iter().any(|r| {
        r.ip.parse::<Ipv4Addr>() == Ok(addr)
            && (r.status == DeviceStatus::Live || r.mac.starts_with("manual:"))
    });
    let on_adopted_subnet = adopted_subnets.iter().any(|s| cidr_contains(s, addr));
    if known_device || on_adopted_subnet {
        return Ok(addr);
    }
    Err(AppError::Network(format!(
        "IP address not allowed: {} (link-local target is not a known device)",
        ip
    )))
}

/// Extract and validate the host of a camera-control URL. PTZ/ONVIF
/// commands accept a full `camera_url` from the webview; before any
/// dispatch the host must be a literal IPv4 address that passes the
/// same reserved-range guard as every other camera target. Hostnames
/// are rejected (no DNS pivot), as is any URL carrying userinfo
/// (`http://user@host` smuggling) or a non-HTTP scheme. When ONVIF is
/// actually implemented, tighten this to the known-device validation
/// used by camera control so APIPA-rescue devices stay controllable.
pub fn parse_camera_url_host(url: &str) -> Result<Ipv4Addr, AppError> {
    let (scheme, rest) = url.split_once("://").ok_or_else(|| {
        AppError::Network(format!(
            "Invalid camera URL (expected scheme://host): {}",
            url
        ))
    })?;
    if scheme != "http" && scheme != "https" {
        return Err(AppError::Network(format!(
            "Camera URL scheme not allowed: {}",
            scheme
        )));
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return Err(AppError::Network(
            "Camera URL must not contain credentials".into(),
        ));
    }
    let host = authority.split(':').next().unwrap_or("");
    parse_camera_ip(host)
}

/// True when `addr` falls inside the CIDR block `cidr` ("a.b.c.0/24").
/// Malformed CIDR strings are treated as non-matching rather than
/// erroring — adopted-subnet keys are backend-generated, so a bad one
/// should fail closed for the link-local allowance, not break the command.
fn cidr_contains(cidr: &str, addr: Ipv4Addr) -> bool {
    match parse_cidr(cidr) {
        Ok((base, prefix)) => {
            if prefix == 0 {
                return true;
            }
            let shift = 32 - u32::from(prefix);
            (u32::from(addr) ^ u32::from(base)) >> shift == 0
        }
        Err(_) => false,
    }
}

/// Parse a CIDR string ("192.168.1.0/24") into its network base address
/// and prefix length. Used to validate the `subnet` parameter of
/// `scan_network` at the IPC boundary so a malformed value surfaces a
/// clean error before any scanning machinery spins up.
pub fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), AppError> {
    let (ip_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| AppError::Network(format!("Invalid CIDR (expected IP/prefix): {}", cidr)))?;
    let ip: Ipv4Addr = ip_str
        .parse()
        .map_err(|_| AppError::Network(format!("Invalid IP in CIDR: {}", cidr)))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| AppError::Network(format!("Invalid prefix length in CIDR: {}", cidr)))?;
    if prefix > 32 {
        return Err(AppError::Network(format!(
            "CIDR prefix must be 0..=32, got /{}",
            prefix
        )));
    }
    Ok((ip, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_camera_ip ────────────────────────────────────────────

    #[test]
    fn parse_camera_ip_accepts_routable_address() {
        let addr = parse_camera_ip("192.168.1.50").unwrap();
        assert_eq!(addr.octets(), [192, 168, 1, 50]);
    }

    #[test]
    fn parse_camera_ip_accepts_public_address() {
        // SSRF guard targets only the obviously-internal reserved
        // ranges; routable public IPs are caller's responsibility.
        let addr = parse_camera_ip("8.8.8.8").unwrap();
        assert_eq!(addr.octets(), [8, 8, 8, 8]);
    }

    #[test]
    fn parse_camera_ip_rejects_loopback() {
        let err = parse_camera_ip("127.0.0.1").unwrap_err();
        assert!(err.to_string().contains("not allowed"));
    }

    #[test]
    fn parse_camera_ip_rejects_link_local() {
        // 169.254.x.x is NOT protocol-invalid input — FLIR cameras fall
        // back to APIPA when DHCP is absent, and real devices live there.
        // This strict variant still rejects it; camera-control commands
        // use parse_known_camera_ip, which allows known APIPA devices.
        let err = parse_camera_ip("169.254.1.1").unwrap_err();
        assert!(err.to_string().contains("not allowed"));
    }

    #[test]
    fn parse_camera_ip_rejects_broadcast() {
        let err = parse_camera_ip("255.255.255.255").unwrap_err();
        assert!(err.to_string().contains("not allowed"));
    }

    #[test]
    fn parse_camera_ip_rejects_unspecified() {
        let err = parse_camera_ip("0.0.0.0").unwrap_err();
        assert!(err.to_string().contains("not allowed"));
    }

    #[test]
    fn parse_camera_ip_rejects_garbage() {
        let err = parse_camera_ip("not-an-ip").unwrap_err();
        assert!(err.to_string().contains("Invalid IP address"));
    }

    #[test]
    fn parse_camera_ip_rejects_ipv6() {
        // IPv4 only — gstreamer/reqwest/PTU stack assumes v4 elsewhere.
        let err = parse_camera_ip("::1").unwrap_err();
        assert!(err.to_string().contains("Invalid IP address"));
    }

    // ── parse_known_camera_ip ──────────────────────────────────────

    fn live_arp_device(ip: &str) -> crate::network::ArpDevice {
        let base = ip.rsplit_once('.').unwrap().0;
        crate::network::ArpDevice {
            mac: "AC-45-EF-38-F9-F5".to_string(),
            ip: ip.to_string(),
            subnet: format!("{}.0/24", base),
            first_seen: "2026-07-05T00:00:00Z".to_string(),
            last_seen: "2026-07-05T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn known_variant_accepts_link_local_live_device() {
        let registry = DeviceRegistry::new();
        registry.merge_arp(&live_arp_device("169.254.10.5"));
        let addr = parse_known_camera_ip("169.254.10.5", &registry, &[]).unwrap();
        assert_eq!(addr.octets(), [169, 254, 10, 5]);
    }

    #[test]
    fn known_variant_accepts_link_local_manual_node() {
        let registry = DeviceRegistry::new();
        registry.hydrate_manual_nodes(&[crate::config::ManualNode {
            ip: "169.254.20.7".to_string(),
            alias: "bench PTU".to_string(),
        }]);
        // Manual nodes qualify even when their dot has gone red — the
        // user pinned the address deliberately.
        registry.set_status("manual:169.254.20.7", DeviceStatus::Offline);
        assert!(parse_known_camera_ip("169.254.20.7", &registry, &[]).is_ok());
    }

    #[test]
    fn known_variant_accepts_link_local_on_adopted_subnet() {
        let registry = DeviceRegistry::new();
        let adopted = vec!["169.254.30.0/24".to_string()];
        assert!(parse_known_camera_ip("169.254.30.9", &registry, &adopted).is_ok());
    }

    #[test]
    fn known_variant_rejects_unknown_link_local() {
        let registry = DeviceRegistry::new();
        let adopted = vec!["192.168.12.0/24".to_string()];
        let err = parse_known_camera_ip("169.254.99.99", &registry, &adopted).unwrap_err();
        assert!(err.to_string().contains("not allowed"));
    }

    #[test]
    fn known_variant_rejects_cached_only_link_local() {
        // A months-stale cached APIPA row must not authorize a target;
        // a FLIR actually in rescue is ARPing, which makes it Live.
        let registry = DeviceRegistry::new();
        registry.hydrate_from_cache(&[crate::config::CachedDevice {
            mac: "AC-45-EF-38-F9-F5".to_string(),
            ip: "169.254.40.4".to_string(),
            subnet: "169.254.40.0/24".to_string(),
            open_ports: vec![80],
            alias: String::new(),
            last_seen: "2026-01-01T00:00:00Z".to_string(),
        }]);
        assert!(parse_known_camera_ip("169.254.40.4", &registry, &[]).is_err());
    }

    #[test]
    fn known_variant_still_rejects_loopback_and_friends() {
        let registry = DeviceRegistry::new();
        // Even a (nonsensical) adopted 127/8 entry must not open loopback.
        let adopted = vec!["127.0.0.0/8".to_string()];
        assert!(parse_known_camera_ip("127.0.0.1", &registry, &adopted).is_err());
        assert!(parse_known_camera_ip("255.255.255.255", &registry, &[]).is_err());
        assert!(parse_known_camera_ip("0.0.0.0", &registry, &[]).is_err());
    }

    #[test]
    fn known_variant_accepts_routable_without_registry() {
        let registry = DeviceRegistry::new();
        assert!(parse_known_camera_ip("192.168.1.50", &registry, &[]).is_ok());
    }

    // ── parse_camera_url_host ──────────────────────────────────────

    #[test]
    fn url_host_accepts_plain_ipv4_url() {
        let addr = parse_camera_url_host("http://192.168.1.50/onvif/device_service").unwrap();
        assert_eq!(addr.octets(), [192, 168, 1, 50]);
    }

    #[test]
    fn url_host_accepts_port_and_https() {
        assert!(parse_camera_url_host("https://192.168.1.50:8080/onvif").is_ok());
        assert!(parse_camera_url_host("http://10.0.0.2:80").is_ok());
    }

    #[test]
    fn url_host_rejects_hostnames() {
        // Only literal IPv4 — a resolvable name would let DNS pick the
        // real target after validation.
        assert!(parse_camera_url_host("http://camera.local/onvif").is_err());
        assert!(parse_camera_url_host("http://example.com").is_err());
    }

    #[test]
    fn url_host_rejects_reserved_ranges() {
        assert!(parse_camera_url_host("http://127.0.0.1/onvif").is_err());
        // Strict guard for the stubbed surface: link-local needs the
        // known-device context that camera control has and this doesn't.
        assert!(parse_camera_url_host("http://169.254.1.1/onvif").is_err());
        assert!(parse_camera_url_host("http://0.0.0.0/").is_err());
    }

    #[test]
    fn url_host_rejects_userinfo() {
        assert!(parse_camera_url_host("http://admin@192.168.1.50/onvif").is_err());
        assert!(parse_camera_url_host("http://a:b@192.168.1.50").is_err());
    }

    #[test]
    fn url_host_rejects_missing_or_odd_scheme() {
        assert!(parse_camera_url_host("192.168.1.50/onvif").is_err());
        assert!(parse_camera_url_host("file://192.168.1.50/etc").is_err());
        assert!(parse_camera_url_host("gopher://192.168.1.50").is_err());
    }

    // ── cidr_contains ──────────────────────────────────────────────

    #[test]
    fn cidr_contains_basics() {
        let ip: Ipv4Addr = "169.254.30.9".parse().unwrap();
        assert!(cidr_contains("169.254.30.0/24", ip));
        assert!(!cidr_contains("169.254.31.0/24", ip));
        assert!(cidr_contains("169.254.0.0/16", ip));
        assert!(cidr_contains("0.0.0.0/0", ip));
        assert!(!cidr_contains("garbage", ip));
    }

    // ── parse_cidr ─────────────────────────────────────────────────

    #[test]
    fn parse_cidr_accepts_class_c() {
        let (ip, prefix) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(ip.octets(), [192, 168, 1, 0]);
        assert_eq!(prefix, 24);
    }

    #[test]
    fn parse_cidr_accepts_max_prefix() {
        let (_, prefix) = parse_cidr("10.0.0.1/32").unwrap();
        assert_eq!(prefix, 32);
    }

    #[test]
    fn parse_cidr_accepts_zero_prefix() {
        let (_, prefix) = parse_cidr("0.0.0.0/0").unwrap();
        assert_eq!(prefix, 0);
    }

    #[test]
    fn parse_cidr_rejects_missing_slash() {
        assert!(parse_cidr("192.168.1.0").is_err());
    }

    #[test]
    fn parse_cidr_rejects_bad_ip() {
        assert!(parse_cidr("not-an-ip/24").is_err());
    }

    #[test]
    fn parse_cidr_rejects_bad_prefix() {
        assert!(parse_cidr("192.168.1.0/abc").is_err());
    }

    #[test]
    fn parse_cidr_rejects_oversized_prefix() {
        let err = parse_cidr("192.168.1.0/33").unwrap_err();
        assert!(err.to_string().contains("0..=32"));
    }
}
