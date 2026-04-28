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
