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

pub(crate) async fn list(adopted: &HashSet<String>) -> Result<Vec<BindInterface>, AppError> {
    let rows = native().await?;
    let metadata = interface::list_all_adapters().await?;
    let mut result = Vec::new();
    for row in &rows {
        if !row.is_up {
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
    Ok(result)
}

pub(crate) async fn migrate(config: &crate::config::AppConfig) -> Result<(), AppError> {
    let settings = config.get();
    if settings.bind_identity_migration_complete {
        return Ok(());
    }
    let adopted = settings.adopted_subnets.into_values().collect();
    // Failed/ambiguous observations retain the original unavailable selection.
    if let Ok(interfaces) = list(&adopted).await {
        config.migrate_bind_ids(&interfaces)?;
    }
    Ok(())
}

/// Runs independently of selected-camera refresh success and on its retry tick.
pub(crate) async fn refresh(handle: &tauri::AppHandle) {
    use tauri::{Emitter, Manager};
    let rows = native().await;
    let (changed, revision) = {
        let mut t = TOPOLOGY.lock().unwrap();
        (record(&mut t, &rows), t.revision)
    };
    if !changed {
        return;
    }
    let scope = match rows {
        Ok(rows) => exposure(&rows, revision),
        Err(error) => BindScope::Unknown {
            reason: error.to_string(),
        },
    };
    let _ = handle.emit(
        "binding-topology-changed",
        serde_json::json!({"topology_revision":revision}),
    );
    handle
        .state::<crate::streaming::StreamManager>()
        .binding_topology_changed(scope, revision)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
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
