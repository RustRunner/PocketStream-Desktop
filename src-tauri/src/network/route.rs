//! Route checks are preflights, not route ownership. S6 never installs routes.
use std::net::Ipv4Addr;

use super::{DeviceRecord, DeviceStatus, InterfaceInfo};
use crate::error::AppError;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct CameraTarget {
    pub key: String,
    pub expected_mac: Option<String>,
    pub ip: String,
}

#[derive(Clone)]
pub struct ReadyPath {
    pub(crate) target: CameraTarget,
    pub(crate) source: Ipv4Addr,
    pub(crate) index: u32,
    pub(crate) fence: super::SweepFence,
}

pub fn egress_index(destination: Ipv4Addr) -> Result<u32, AppError> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterfaceEx;
        use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR, SOCKADDR_IN};
        let mut address: SOCKADDR_IN = unsafe { std::mem::zeroed() };
        address.sin_family = AF_INET;
        address.sin_addr.S_un.S_addr = u32::from_ne_bytes(destination.octets());
        let mut index = 0;
        // Both pointers are valid for the synchronous call. IPv4 bytes use
        // network order in memory, matching the OS sockaddr layout.
        let code =
            unsafe { GetBestInterfaceEx(&address as *const _ as *const SOCKADDR, &mut index) };
        if code == 0 && index != 0 {
            return Ok(index);
        }
        Err(AppError::Network(format!("Route lookup failed ({code})")))
    }
    #[cfg(not(windows))]
    {
        let _ = destination;
        Err(AppError::Network(
            "Camera route preflight requires Windows".into(),
        ))
    }
}

/// Pure policy over a current OS address snapshot and an already-expired
/// registry snapshot. Saved/adopted maps never establish applied addresses.
pub(super) fn check_ready(
    target: &CameraTarget,
    adapter: Option<&InterfaceInfo>,
    index: u32,
    records: &[DeviceRecord],
    egress: Option<u32>,
) -> Result<Ipv4Addr, AppError> {
    if egress != Some(index) {
        return Err(AppError::Network(
            "Ethernet not ready: OS route does not select the selected Ethernet adapter".into(),
        ));
    }
    check_bound_ready(target, adapter, index, records)
}

/// An explicitly source/interface-bound transport does not use the default
/// route. It still requires the same applied address and fresh MAC evidence.
pub(super) fn check_bound_ready(
    target: &CameraTarget,
    adapter: Option<&InterfaceInfo>,
    index: u32,
    records: &[DeviceRecord],
) -> Result<Ipv4Addr, AppError> {
    let fail = |reason: &str| AppError::Network(format!("Ethernet not ready: {reason}"));
    let ip = crate::validation::parse_camera_ip(&target.ip)?;
    let adapter = adapter
        .filter(|a| a.is_up && a.is_ethernet && !a.is_wifi && !a.is_virtual && !a.is_vpn)
        .ok_or_else(|| fail("selected adapter unavailable"))?;
    if index == 0 {
        return Err(fail("selected adapter has no interface index"));
    }
    let source = super::select_wired_source(ip, &Default::default(), &adapter.ips)
        .filter(|source| *source != ip && !crate::validation::prohibited_camera_ip(*source))
        .ok_or_else(|| fail("no applied address on the selected adapter for this subnet"))?;
    let expected = target
        .expected_mac
        .as_deref()
        .and_then(super::device_registry::canonical_mac)
        .ok_or_else(|| fail("expected device identity has not been verified"))?;
    let adapter_mac = super::device_registry::canonical_mac(&adapter.mac)
        .filter(|mac| mac != &expected)
        .ok_or_else(|| fail("invalid or self adapter identity"))?;
    let row = records
        .iter()
        .find(|r| r.mac.eq_ignore_ascii_case(&target.key))
        .ok_or_else(|| fail("selected record is unavailable"))?;
    if !row.mac.eq_ignore_ascii_case(&expected)
        || row.ip != target.ip
        || row.status != DeviceStatus::Live
        || row.last_verified_at.is_none()
        || row
            .verified_by_mac
            .as_deref()
            .and_then(super::device_registry::canonical_mac)
            != Some(adapter_mac)
    {
        return Err(fail("expected MAC lacks fresh evidence at this endpoint"));
    }
    Ok(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_requires_route_applied_address_identity_and_fresh_status() {
        let adapter = InterfaceInfo {
            name: "USB".into(),
            display_name: "USB".into(),
            description: "ASIX".into(),
            mac: "40:cd:3a:00:00:01".into(),
            ips: vec![super::super::interface::IpInfo {
                address: "192.168.1.101".into(),
                prefix: 24,
                subnet: "192.168.1.0/24".into(),
            }],
            is_up: true,
            is_ethernet: true,
            is_wifi: false,
            is_vpn: false,
            is_virtual: false,
        };
        let registry = super::super::DeviceRegistry::new();
        let device = super::super::ArpDevice {
            mac: "aa:bb:cc:dd:ee:01".into(),
            ip: "192.168.1.204".into(),
            subnet: "192.168.1.0/24".into(),
            first_seen: "now".into(),
            last_seen: "now".into(),
        };
        let epoch = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1));
        let active = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let fence = super::super::SweepFence::new(1, epoch, active);
        registry.merge_verified(&device, &adapter.mac, "2026-10-19T12:00:00Z", &fence);
        let target = CameraTarget {
            key: device.mac.clone(),
            expected_mac: Some(device.mac),
            ip: device.ip,
        };
        let rows = registry.snapshot();
        assert_eq!(
            check_ready(&target, Some(&adapter), 7, &rows, Some(7)).unwrap(),
            "192.168.1.101".parse::<Ipv4Addr>().unwrap()
        );
        assert!(check_ready(&target, None, 7, &rows, Some(7)).is_err());
        for route in [None, Some(0), Some(8)] {
            assert!(check_ready(&target, Some(&adapter), 7, &rows, route).is_err());
        }
        // Explicitly bound RTSP can use Ethernet even when Wi-Fi owns the
        // same destination IP and wins GetBestInterfaceEx's unbound lookup.
        assert_eq!(
            check_bound_ready(&target, Some(&adapter), 7, &rows).unwrap(),
            "192.168.1.101".parse::<Ipv4Addr>().unwrap()
        );
        assert!(check_bound_ready(&target, Some(&adapter), 0, &rows).is_err());
        assert!(check_bound_ready(&target, None, 7, &rows).is_err());
        let mut missing = adapter.clone();
        missing.ips.clear();
        assert!(check_ready(&target, Some(&missing), 7, &rows, Some(7)).is_err());
        assert!(check_bound_ready(&target, Some(&missing), 7, &rows).is_err());
        let mut wrong = target.clone();
        wrong.expected_mac = Some("aa:bb:cc:dd:ee:02".into());
        assert!(check_ready(&wrong, Some(&adapter), 7, &rows, Some(7)).is_err());
        assert!(check_bound_ready(&wrong, Some(&adapter), 7, &rows).is_err());
        wrong = target.clone();
        wrong.ip = "169.254.1.204".into();
        assert!(check_ready(&wrong, Some(&adapter), 7, &rows, Some(7)).is_err());
        wrong = target.clone();
        wrong.expected_mac = None;
        assert!(check_ready(&wrong, Some(&adapter), 7, &rows, Some(7)).is_err());
        for status in [
            DeviceStatus::CachedOnly,
            DeviceStatus::Verifying,
            DeviceStatus::Offline,
            DeviceStatus::OfflineDifferentDevice,
            DeviceStatus::OfflineNonWiredSubnet,
            DeviceStatus::OfflineHostOwnedIp,
        ] {
            let mut stale = rows.clone();
            stale[0].status = status;
            assert!(check_ready(&target, Some(&adapter), 7, &stale, Some(7)).is_err());
            assert!(check_bound_ready(&target, Some(&adapter), 7, &stale).is_err());
        }
        let mut other_adapter = rows.clone();
        other_adapter[0].verified_by_mac = Some("40:cd:3a:00:00:02".into());
        assert!(check_ready(&target, Some(&adapter), 7, &other_adapter, Some(7)).is_err());
        assert!(check_bound_ready(&target, Some(&adapter), 7, &other_adapter).is_err());
        assert!(registry
            .expire_evidence(tokio::time::Instant::now() + super::super::presence::FRESHNESS));
        assert!(check_ready(&target, Some(&adapter), 7, &registry.snapshot(), Some(7)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn native_route_index_matches_local_adapter_inventory() {
        // Loopback's local route is deterministic and sends no packets.
        let index = egress_index(Ipv4Addr::LOCALHOST).unwrap();
        assert!(super::super::interface::source_matches_interface(
            index,
            Ipv4Addr::LOCALHOST
        ));
    }
}
