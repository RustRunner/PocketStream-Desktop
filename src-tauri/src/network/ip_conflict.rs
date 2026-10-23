//! Current PC address ownership, separate from device identity and presence.
use crate::error::AppError;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct HostIpOwner {
    pub address: String,
    pub adapter_name: String,
}

pub fn local_ip_owners() -> Result<Vec<HostIpOwner>, AppError> {
    #[cfg(windows)]
    {
        Ok(owners_from_native(
            super::interface::local_adapters_iphelper()?,
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
                    })
            })
            .collect();
        Ok(normalize(owners))
    }
}

#[cfg(any(windows, test))]
fn owners_from_native(adapters: Vec<super::interface::NativeAdapter>) -> Vec<HostIpOwner> {
    // Windows can retain unicast addresses while Wi-Fi is disconnected or
    // disabled. Those dormant addresses do not establish an active conflict.
    let owners = adapters
        .into_iter()
        .filter(|adapter| adapter.is_up)
        .flat_map(|adapter| {
            let name = if adapter.alias.is_empty() {
                format!("Adapter {}", adapter.index)
            } else {
                adapter.alias
            };
            adapter.ips.into_iter().map(move |ip| HostIpOwner {
                address: ip.address,
                adapter_name: name.clone(),
            })
        })
        .collect();
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
    (!names.is_empty()).then(|| format!(
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
    fn retained_wifi_address_stops_conflicting_when_adapter_goes_down_and_returns_when_up() {
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
        assert!(
            conflict_message("192.168.1.204", &owners_from_native(vec![wifi.clone()])).is_some()
        );
        let mut disabled = wifi.clone();
        disabled.is_up = false; // IP Helper still supplies the very same address.
        assert!(owners_from_native(vec![disabled.clone()]).is_empty());
        // A fresh startup snapshot with Wi-Fi off is also clear; no prior
        // monitor state, node clearing or settings deletion is required.
        assert!(
            conflict_message("192.168.1.204", &owners_from_native(vec![disabled.clone()]))
                .is_none()
        );
        let mut vpn = wifi.clone();
        vpn.alias = "VPN".into();
        let owners = owners_from_native(vec![disabled, vpn]);
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].adapter_name, "VPN");
        assert!(conflict_message("192.168.1.204", &owners).is_some());
        assert!(conflict_message("192.168.1.204", &owners_from_native(vec![wifi])).is_some());
    }

    #[test]
    fn conflict_matches_exact_pc_address_and_names_every_owner() {
        let owners = normalize(vec![
            HostIpOwner {
                address: "192.168.1.204".into(),
                adapter_name: "Wi-Fi 2".into(),
            },
            HostIpOwner {
                address: "192.168.1.100".into(),
                adapter_name: "Ethernet".into(),
            },
            HostIpOwner {
                address: "192.168.1.204".into(),
                adapter_name: "VPN".into(),
            },
            HostIpOwner {
                address: "192.168.1.204".into(),
                adapter_name: "Wi-Fi 2".into(),
            },
            HostIpOwner {
                address: "127.0.0.1".into(),
                adapter_name: "Loopback".into(),
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
