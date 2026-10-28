//! Selection uses qualified metadata; exposure uses the unfiltered native IPv4
//! inventory. Both consume the existing IP Helper reader and watcher.
use super::interface::{self, NativeAdapter, NativeIdentity};
use crate::AppError;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketFamily {
    Ipv4,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindInterface {
    pub id: String,
    pub alias: String,
    pub kind: String,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundAddress {
    pub id: String,
    pub alias: String,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BindScope {
    AllAddresses {
        family: SocketFamily,
        addresses: Vec<BoundAddress>,
        topology_revision: u64,
    },
    Interface {
        id: String,
        alias: String,
        address: String,
        family: SocketFamily,
        topology_revision: u64,
    },
    Unknown {
        reason: String,
    },
}
impl Default for BindScope {
    fn default() -> Self {
        Self::Unknown {
            reason: "No active listener".into(),
        }
    }
}

#[derive(Default)]
struct Topology {
    revision: u64,
    fingerprint: Option<String>,
}
static TOPOLOGY: LazyLock<Mutex<Topology>> = LazyLock::new(|| Mutex::new(Topology::default()));

fn record(topology: &mut Topology, observation: &Result<Vec<NativeAdapter>, AppError>) -> bool {
    let fingerprint = observation
        .as_ref()
        .ok()
        .and_then(|rows| serde_json::to_string(rows).ok());
    // A failed observation immediately retires the last known inventory.
    if topology.revision == 0 || fingerprint != topology.fingerprint {
        topology.revision += 1;
        topology.fingerprint = fingerprint;
        true
    } else {
        false
    }
}
pub(crate) fn revision() -> u64 {
    TOPOLOGY.lock().unwrap().revision
}

async fn native() -> Result<Vec<NativeAdapter>, AppError> {
    #[cfg(windows)]
    {
        interface::read_native().await
    }
    #[cfg(not(windows))]
    {
        Err(AppError::Network(
            "Native binding inventory is unavailable on this platform".into(),
        ))
    }
}

pub(crate) fn usable(ips: &[interface::IpInfo], adopted: &HashSet<String>) -> Option<String> {
    ips.iter()
        .map(|ip| &ip.address)
        .find(|ip| {
            ip.parse::<std::net::Ipv4Addr>()
                .is_ok_and(|a| !a.is_unspecified() && !a.is_loopback() && !a.is_link_local())
                && !adopted.contains(*ip)
        })
        .cloned()
}

pub(crate) fn select<'a>(
    rows: &'a [NativeAdapter],
    id: Option<&str>,
    alias: &str,
) -> Result<&'a NativeAdapter, AppError> {
    let matches: Vec<_> = rows
        .iter()
        .filter(|row| match id {
            Some(id) => row
                .identity()
                .guid
                .eq_ignore_ascii_case(id.trim_matches(['{', '}'])),
            None => row.alias == alias,
        })
        .collect();
    if matches.len() != 1 || !matches[0].is_up || matches[0].identity().guid.is_empty() {
        return Err(AppError::Stream(format!(
            "Saved bind interface '{alias}' is unavailable or ambiguous; choose an interface"
        )));
    }
    Ok(matches[0])
}

pub(crate) fn exposure(rows: &[NativeAdapter], revision: u64) -> BindScope {
    let mut addresses: Vec<_> = rows
        .iter()
        .flat_map(|row| {
            row.ips.iter().map(|ip| BoundAddress {
                id: row.identity().guid,
                alias: row.alias.clone(),
                address: ip.address.clone(),
            })
        })
        .collect();
    addresses.sort_by(|a, b| (&a.id, &a.address, &a.alias).cmp(&(&b.id, &b.address, &b.alias)));
    addresses.dedup();
    BindScope::AllAddresses {
        family: SocketFamily::Ipv4,
        addresses,
        topology_revision: revision,
    }
}

pub(crate) async fn resolve(
    alias: Option<&str>,
    id: Option<&str>,
    adopted: &HashSet<String>,
) -> Result<(Option<NativeIdentity>, BindScope), AppError> {
    let revision = revision();
    let rows = native().await?;
    let Some(alias) = alias else {
        return Ok((None, exposure(&rows, revision)));
    };
    let row = select(&rows, id, alias)?;
    let address = usable(&row.ips, adopted).ok_or_else(|| {
        AppError::Stream(format!(
            "Interface '{}' has no usable non-adopted, non-APIPA IPv4 address",
            row.alias
        ))
    })?;
    let identity = row.identity();
    Ok((
        Some(identity.clone()),
        BindScope::Interface {
            id: identity.guid,
            alias: row.alias.clone(),
            address,
            family: SocketFamily::Ipv4,
            topology_revision: revision,
        },
    ))
}

pub(crate) async fn list(
    adopted: &HashSet<String>,
    camera_mac: Option<&str>,
) -> Result<Vec<BindInterface>, AppError> {
    let rows = native().await?;
    let metadata = interface::list_all_adapters().await?;
    Ok(bind_options(&rows, &metadata, adopted, camera_mac))
}

fn bind_options(
    rows: &[NativeAdapter],
    metadata: &[interface::InterfaceInfo],
    adopted: &HashSet<String>,
    camera_mac: Option<&str>,
) -> Vec<BindInterface> {
    let camera_mac = camera_mac.and_then(super::device_registry::canonical_mac);
    let mut result = Vec::new();
    for row in rows {
        // Exclude the camera link itself, including its primary address.
        // Other wired uplinks remain valid re-stream output choices.
        if !row.is_up
            || camera_mac.as_ref().is_some_and(|camera| {
                super::device_registry::canonical_mac(&row.mac).as_ref() == Some(camera)
            })
        {
            continue;
        }
        let candidates: Vec<_> = metadata
            .iter()
            .filter(|m| m.name == row.alias && m.mac.eq_ignore_ascii_case(&row.mac))
            .collect();
        if candidates.len() != 1 {
            continue;
        }
        let m = candidates[0];
        if !(m.is_vpn || (!m.is_virtual && (m.is_wifi || m.is_ethernet))) {
            continue;
        }
        if let Some(address) = usable(&row.ips, adopted) {
            result.push(BindInterface {
                id: row.identity().guid,
                alias: row.alias.clone(),
                kind: if m.is_vpn {
                    "vpn"
                } else if m.is_wifi {
                    "wifi"
                } else {
                    "ethernet"
                }
                .into(),
                address,
            });
        }
    }
    result
}

pub(crate) async fn migrate(config: &crate::config::AppConfig) -> Result<(), AppError> {
    let settings = config.get();
    if settings.bind_identity_migration_complete {
        return Ok(());
    }
    let adopted = settings.adopted_subnets.into_values().collect();
    // Failed/ambiguous observations retain the original unavailable selection.
    if let Ok(interfaces) = list(&adopted, None).await {
        config.migrate_bind_ids(&interfaces)?;
    }
    Ok(())
}

/// Existing native observation is independent of selected-camera refresh.
pub(crate) async fn refresh() -> Option<TopologyObservation> {
    let rows = native().await;
    topology_observation(&TOPOLOGY, rows)
}

pub(crate) struct TopologyObservation {
    pub(crate) changed: bool,
    pub(crate) revision: u64,
    pub(crate) scope: BindScope,
}

fn topology_observation(
    topology: &Mutex<Topology>,
    rows: Result<Vec<NativeAdapter>, AppError>,
) -> Option<TopologyObservation> {
    let (changed, revision) = {
        let mut topology = topology.lock().unwrap();
        (record(&mut topology, &rows), topology.revision)
    };
    if !changed && rows.is_err() {
        return None;
    }
    let scope = match rows {
        Ok(rows) => exposure(&rows, revision),
        Err(error) => BindScope::Unknown {
            reason: error.to_string(),
        },
    };
    Some(TopologyObservation {
        changed,
        revision,
        scope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_retries_unchanged_success_but_suppresses_repeated_failure() {
        let topology = Mutex::new(Topology::default());
        let inventory = vec![row("ethernet", "Camera", &["192.0.2.1"])];
        let first = topology_observation(&topology, Ok(inventory.clone())).unwrap();
        assert!(first.changed);
        let retry = topology_observation(&topology, Ok(inventory)).unwrap();
        assert!(!retry.changed);
        assert_eq!(retry.revision, first.revision);
        let failed =
            topology_observation(&topology, Err(AppError::Network("unavailable".into()))).unwrap();
        assert!(failed.changed);
        assert!(matches!(failed.scope, BindScope::Unknown { .. }));
        assert!(
            topology_observation(&topology, Err(AppError::Network("unavailable".into()))).is_none()
        );
    }

    #[test]
    fn unrelated_adapter_observation_advances_topology_without_camera_selection() {
        let topology = Mutex::new(Topology::default());
        let camera = row("ethernet", "Camera", &["192.0.2.1"]);
        let first = topology_observation(&topology, Ok(vec![camera.clone()])).unwrap();
        let unrelated = row("vpn", "Unrelated", &["198.51.100.1"]);
        let next = topology_observation(&topology, Ok(vec![camera, unrelated])).unwrap();
        assert!(next.changed && next.revision > first.revision);
        let BindScope::AllAddresses { addresses, .. } = next.scope else {
            panic!("native exposure required");
        };
        assert_eq!(addresses.len(), 2);
    }
    fn row(id: &str, alias: &str, ips: &[&str]) -> NativeAdapter {
        NativeAdapter {
            guid: id.into(),
            alias: alias.into(),
            index: 1,
            mac: "00:11:22:33:44:55".into(),
            is_up: true,
            dhcp: false,
            gateways: vec![],
            ips: ips
                .iter()
                .map(|ip| interface::IpInfo {
                    address: (*ip).into(),
                    prefix: 24,
                    subnet: "test".into(),
                })
                .collect(),
        }
    }
    #[test]
    fn wildcard_includes_loopback_apipa_secondary_and_hidden_virtual() {
        let rows = vec![
            row("loopback", "Loopback", &["127.0.0.1"]),
            row(
                "virtual",
                "Hidden vEthernet",
                &["172.20.0.1", "169.254.1.2"],
            ),
            row("eth", "Ethernet", &["192.0.2.2", "198.51.100.2"]),
        ];
        let BindScope::AllAddresses { addresses, .. } = exposure(&rows, 7) else {
            panic!()
        };
        assert_eq!(addresses.len(), 5);
        assert!(addresses.iter().any(|a| a.address == "169.254.1.2"));
        assert_eq!(
            usable(&rows[1].ips, &HashSet::from(["172.20.0.1".into()])),
            None
        );
    }
    #[test]
    fn stable_id_follows_rename_and_rejects_reused_alias() {
        let rows = vec![
            row("a", "Renamed", &["192.0.2.2"]),
            row("b", "Old alias", &["198.51.100.2"]),
        ];
        assert_eq!(
            select(&rows, Some("a"), "Old alias").unwrap().alias,
            "Renamed"
        );
        assert!(select(&rows, Some("missing"), "Old alias").is_err());
        assert!(select(&[rows[0].clone(), rows[0].clone()], None, "Renamed").is_err());
    }

    #[test]
    fn camera_adapter_is_not_an_output_even_with_a_usable_primary_address() {
        let mut camera = row(
            "camera",
            "Renamed Camera Port",
            &["192.168.0.100", "172.31.169.100"],
        );
        camera.mac = "40:c2:ba:cf:d5:75".into();
        let mut uplink = row("uplink", "Ethernet 2", &["198.51.100.2"]);
        uplink.mac = "40:c2:ba:cf:d5:76".into();
        let mut wifi = row("wifi", "Wi-Fi", &["203.0.113.2"]);
        wifi.mac = "40:c2:ba:cf:d5:77".into();
        let rows = vec![camera, uplink, wifi];
        let metadata: Vec<_> = rows
            .iter()
            .map(|r| interface::InterfaceInfo {
                name: r.alias.clone(),
                display_name: r.alias.clone(),
                description: String::new(),
                ips: r.ips.clone(),
                mac: r.mac.clone(),
                is_up: true,
                is_ethernet: r.guid != "wifi",
                is_wifi: r.guid == "wifi",
                is_vpn: false,
                is_virtual: false,
            })
            .collect();
        let adopted = HashSet::from(["172.31.169.100".into()]);
        let options = bind_options(&rows, &metadata, &adopted, Some("40-C2-BA-CF-D5-75"));
        assert_eq!(
            options.iter().map(|o| o.id.as_str()).collect::<Vec<_>>(),
            ["uplink", "wifi"]
        );
        // Changing the selected camera port changes only that exclusion.
        let options = bind_options(&rows, &metadata, &adopted, Some(&rows[1].mac));
        assert_eq!(
            options.iter().map(|o| o.id.as_str()).collect::<Vec<_>>(),
            ["camera", "wifi"]
        );
        // Migration can still identify an older saved binding without offering
        // it as a new choice or silently changing it to a wildcard listener.
        assert_eq!(bind_options(&rows, &metadata, &adopted, None).len(), 3);
    }
    #[test]
    fn unrelated_changes_and_failures_retire_inventory() {
        let mut t = Topology::default();
        let mut rows = vec![
            row("eth", "Camera Ethernet", &["192.0.2.2"]),
            row("wifi", "Wi-Fi", &["198.51.100.2"]),
        ];
        assert!(record(&mut t, &Ok(rows.clone())));
        assert!(!record(&mut t, &Ok(rows.clone())));
        rows[1].ips[0].address = "198.51.100.3".into();
        assert!(record(&mut t, &Ok(rows)));
        assert!(record(
            &mut t,
            &Err(AppError::Network("observation failed".into()))
        ));
        assert!(t.fingerprint.is_none());
        assert_eq!(t.revision, 3);
    }
}
