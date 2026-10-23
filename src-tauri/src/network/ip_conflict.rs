//! Current PC address ownership, separate from device identity and presence.
use crate::error::AppError;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct HostIpOwner {
    pub address: String,
    pub adapter_name: String,
    pub retained_route: bool,
}

pub fn local_ip_owners() -> Result<Vec<HostIpOwner>, AppError> {
    #[cfg(windows)]
    {
        Ok(owners_from_native(
            super::interface::local_adapters_iphelper()?,
            |ip| super::route::egress_index(ip).ok(),
        ))
    }
    #[cfg(not(windows))]
    {
        let owners = pnet::datalink::interfaces()
            .into_iter()
            .filter(|adapter| adapter.is_up())
            .flat_map(|adapter| {
                let name = adapter.name;
                adapter
                    .ips
                    .into_iter()
                    .filter(|ip| ip.is_ipv4())
                    .map(move |ip| HostIpOwner {
                        address: ip.ip().to_string(),
                        adapter_name: name.clone(),
                        retained_route: false,
                    })
            })
            .collect();
        Ok(normalize(owners))
    }
}

#[cfg(any(windows, test))]
fn owners_from_native(
    adapters: Vec<super::interface::NativeAdapter>,
    mut egress: impl FnMut(std::net::Ipv4Addr) -> Option<u32>,
) -> Vec<HostIpOwner> {
    let mut owners = Vec::new();
    for adapter in adapters {
        let name = if adapter.alias.is_empty() {
            format!("Adapter {}", adapter.index)
        } else {
            adapter.alias
        };
        for ip in adapter.ips {
            let Ok(address) = crate::validation::parse_camera_ip(&ip.address) else {
                continue;
            };
            // Radio-off can retain a local /32 route even while IP Helper
            // reports the adapter down. Warn while Windows still selects it;
            // a dormant address routed elsewhere must not block the camera.
            if !adapter.is_up && (adapter.index == 0 || egress(address) != Some(adapter.index)) {
                continue;
            }
            owners.push(HostIpOwner {
                address: ip.address,
                adapter_name: name.clone(),
                retained_route: !adapter.is_up,
            });
        }
    }
    normalize(owners)
}

fn normalize(mut owners: Vec<HostIpOwner>) -> Vec<HostIpOwner> {
    owners.retain(|owner| crate::validation::parse_camera_ip(&owner.address).is_ok());
    owners.sort();
    owners.dedup();
    owners
}

pub fn conflict_message(ip: &str, owners: &[HostIpOwner]) -> Option<String> {
    let names: std::collections::BTreeSet<_> = owners
        .iter()
        .filter(|owner| owner.address == ip)
        .map(|owner| owner.adapter_name.as_str())
        .collect();
    if names.is_empty() {
        return None;
    }
    let retained: std::collections::BTreeSet<_> = owners
        .iter()
        .filter(|owner| owner.address == ip && owner.retained_route)
        .map(|owner| owner.adapter_name.as_str())
        .collect();
    if !retained.is_empty() {
        return Some(format!(
            "IP conflict: {ip} is still reserved by this PC ({}). Turning off Wi-Fi alone may not release the address. Fully disable {} in Windows Network Connections, or change the PC's address.",
            names.into_iter().collect::<Vec<_>>().join(", "),
            retained.into_iter().collect::<Vec<_>>().join(", "),
        ));
    }
    Some(format!(
        "IP conflict: {ip} is also assigned to this PC ({}). Change the device's IP or the PC's address to restore full access.",
        names.into_iter().collect::<Vec<_>>().join(", ")
    ))
}

/// Wi-Fi/VPN DHCP changes must update warnings even when Ethernet is quiet.
pub fn start_monitor(handle: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        use tauri::Emitter;
        let mut previous = None;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Ok(owners) = local_ip_owners() {
                if previous.as_ref() != Some(&owners) {
                    let _ = handle.emit("host-ip-owners-changed", &owners);
                    previous = Some(owners);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wifi_conflict_tracks_retained_route_and_full_adapter_disable() {
        use crate::network::interface::{IpInfo, NativeAdapter};
        let wifi = NativeAdapter {
            index: 8,
            alias: "Wi-Fi 2".into(),
            is_up: true,
            ips: vec![IpInfo {
                address: "192.168.1.204".into(),
                prefix: 24,
                subnet: "192.168.1.0/24".into(),
            }],
            ..Default::default()
        };
        let active = owners_from_native(vec![wifi.clone()], |_| {
            panic!("active owner needs no route lookup")
        });
        assert!(!active[0].retained_route);
        assert!(conflict_message("192.168.1.204", &active).is_some());
        let mut disconnected = wifi.clone();
        // Radio off; IP Helper retains the address.
        disconnected.is_up = false;
        // A fresh snapshot must also warn: no previous monitor state required.
        let retained = owners_from_native(vec![disconnected.clone()], |ip| {
            assert_eq!(ip.to_string(), "192.168.1.204");
            Some(8)
        });
        assert_eq!(retained.len(), 1);
        assert!(retained[0].retained_route);
        let warning = conflict_message("192.168.1.204", &retained).unwrap();
        assert!(warning.contains("still reserved by this PC"));
        assert!(warning.contains("Fully disable Wi-Fi 2 in Windows Network Connections"));
        // A dormant address no longer routed to Wi-Fi does not block Ethernet.
        assert!(owners_from_native(vec![disconnected.clone()], |_| Some(15)).is_empty());
        assert!(owners_from_native(vec![disconnected.clone()], |_| None).is_empty());
        // Fully disabling the adapter removes it from the native snapshot.
        assert!(owners_from_native(vec![], |_| panic!("no adapter needs no lookup")).is_empty());
        let mut vpn = wifi.clone();
        vpn.index = 24;
        vpn.alias = "VPN".into();
        let owners = owners_from_native(vec![disconnected, vpn], |_| Some(15));
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].adapter_name, "VPN");
        assert!(conflict_message("192.168.1.204", &owners).is_some());
        let reenabled =
            owners_from_native(vec![wifi], |_| panic!("active owner needs no route lookup"));
        assert!(!reenabled[0].retained_route);
        assert!(conflict_message("192.168.1.204", &reenabled).is_some());
    }

    #[test]
    fn conflict_matches_exact_pc_address_and_names_every_owner() {
        let owners = normalize(vec![
            HostIpOwner {
                address: "192.168.1.204".into(),
                adapter_name: "Wi-Fi 2".into(),
                retained_route: false,
            },
            HostIpOwner {
                address: "192.168.1.100".into(),
                adapter_name: "Ethernet".into(),
                retained_route: false,
            },
            HostIpOwner {
                address: "192.168.1.204".into(),
                adapter_name: "VPN".into(),
                retained_route: false,
            },
            HostIpOwner {
                address: "192.168.1.204".into(),
                adapter_name: "Wi-Fi 2".into(),
                retained_route: false,
            },
            HostIpOwner {
                address: "127.0.0.1".into(),
                adapter_name: "Loopback".into(),
                retained_route: false,
            },
        ]);
        assert_eq!(owners.len(), 3);
        let warning = conflict_message("192.168.1.204", &owners).unwrap();
        assert!(warning.contains("VPN, Wi-Fi 2"));
        assert!(warning.contains("Change the device's IP or the PC's address"));
        assert!(conflict_message("192.168.1.205", &owners).is_none());
        assert!(conflict_message("192.168.1.204", &[]).is_none());
    }

    #[test]
    #[ignore = "requires an explicitly selected address currently assigned to this PC"]
    fn detects_actual_pc_address_conflict() {
        let ip = std::env::var("POCKETSTREAM_CONFLICT_SMOKE_IP").unwrap();
        let warning = conflict_message(&ip, &local_ip_owners().unwrap())
            .expect("expected PC address conflict");
        println!("{warning}");
    }
}
