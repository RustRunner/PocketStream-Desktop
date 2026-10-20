//! Single source of truth for device records, on the backend.
//!
//! Each `DeviceRecord` represents one host on the network with all the
//! information the UI cares about: identity (mac/ip/subnet), discovery
//! result (open_ports), user-assigned label (alias), and live status
//! (Live / Verifying / Offline / CachedOnly). Replaces the prior split
//! across four frontend Maps + three frontend Sets that had to be kept
//! in sync by hand across the discovery/scan/cache paths.
//!
//! The registry is a write-only mutator API for backend code. It does
//! not emit events on its own; emission is the responsibility of the
//! caller (NetworkManager) so it can debounce / batch.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{AppSettings, CachedDevice, ManualNode};
use crate::network::ArpDevice;

/// User-visible reachability status of a device record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    /// Confirmed reachable in the current session (ARP + at least one
    /// successful port scan, or fresh ARP that hasn't been scanned yet).
    Live,
    /// Cached entry being verified by an in-flight targeted scan.
    Verifying,
    /// Cached entry whose verification scan failed all retries.
    Offline,
    /// Hydrated from disk cache only, never confirmed by live ARP this
    /// session. Render path scopes these to currently-routable subnets.
    CachedOnly,
    OfflineNonWiredSubnet,
    OfflineHostOwnedIp,
    OfflineDifferentDevice,
    OfflineAmbiguousRole,
}

/// Unified device record. Replaces the old split between ARP map +
/// scan-result map + alias map + cache file rows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceRecord {
    #[serde(default)]
    pub verified_by_mac: Option<String>,
    #[serde(default)]
    pub last_verified_at: Option<String>,
    pub mac: String,
    pub ip: String,
    pub subnet: String,
    #[serde(default)]
    pub open_ports: Vec<u16>,
    #[serde(default)]
    pub alias: String,
    pub status: DeviceStatus,
    pub first_seen: String,
    pub last_seen: String,
}

/// Owns the canonical `mac → DeviceRecord` map. Mutators return a bool
/// indicating whether anything actually changed, so callers can skip
/// emitting redundant `device-list-changed` events for no-op writes.
pub struct DeviceRegistry {
    devices: Mutex<HashMap<String, DeviceRecord>>,
    evidence: Mutex<HashMap<String, tokio::time::Instant>>,
    verification_scope: Mutex<Option<Option<String>>>,
}

/// The set of user-configured pinned IPs: every manual node plus the
/// persisted stream target. The stream target participates because the
/// CAM can be selected for streaming without ever receiving an alias —
/// that config entry is just as much a statement of user intent as a
/// label.
pub fn configured_pins(settings: &AppSettings) -> HashSet<String> {
    let mut pins: HashSet<String> = settings.manual_nodes.iter().map(|n| n.ip.clone()).collect();
    if !settings.stream.camera_ip.is_empty() {
        pins.insert(settings.stream.camera_ip.clone());
    }
    pins
}

/// One reusable definition of "the user meant to keep this device":
/// a pinned registry entry (`manual:` key), any non-empty alias, or an
/// IP in the configured pin set. Every automatic-removal path shares
/// this so protection can't drift between them. Deliberately excludes
/// transient reachability (`Live` and friends) — a status guard
/// belongs to the individual removal path, not to identity.
pub fn is_user_pinned(key: &str, alias: &str, ip: &str, configured_pins: &HashSet<String>) -> bool {
    key.starts_with("manual:") || !alias.is_empty() || configured_pins.contains(ip)
}

/// Mutation result. Retained identities never populate dropped_macs; the
/// empty compatibility field lets old callers remain wired until S5a.
#[derive(Debug, Default, PartialEq)]
pub struct MergeResult {
    pub changed: bool,
    pub dropped_macs: Vec<String>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self {
            devices: Mutex::new(HashMap::new()),
            evidence: Mutex::new(HashMap::new()),
            verification_scope: Mutex::new(None),
        }
    }

    /// Drop every record. Used by `apply_mode_change` when the source
    /// of truth flips (e.g., Static-Auto → Static-Manual replaces the
    /// cache+ARP set with the user's pinned list). Returns true if
    /// anything was actually removed.
    #[cfg(test)]
    pub fn clear(&self) -> bool {
        let mut map = self.lock();
        let had_entries = !map.is_empty();
        map.clear();
        had_entries
    }

    /// Drop a single record by MAC key. Returns true if the key existed.
    /// Used by `remove_manual_node` to clear the synthetic registry
    /// entry — real-MAC entries are owned by ARP/cache and stay put.
    pub fn remove_by_mac(&self, mac: &str) -> bool {
        let mut map = self.lock();
        map.remove(mac).is_some()
    }

    /// Drop every synthetic manual entry (keys starting with `manual:`),
    /// leaving real-MAC ARP/cache records intact. Used by Clear All so
    /// pins are dropped without nuking discovered devices.
    pub fn remove_manual_entries(&self) -> bool {
        let mut map = self.lock();
        let before = map.len();
        map.retain(|key, _| !key.starts_with("manual:"));
        before != map.len()
    }

    /// Snapshot of all records, sorted by subnet then IP for stable
    /// ordering across emissions.
    pub fn snapshot(&self) -> Vec<DeviceRecord> {
        let map = self.lock();
        let mut list: Vec<DeviceRecord> = map.values().cloned().collect();
        list.sort_by(|a, b| {
            a.subnet
                .cmp(&b.subnet)
                .then_with(|| compare_ips(&a.ip, &b.ip))
                .then_with(|| a.mac.cmp(&b.mac))
        });
        list
    }

    /// Retain every cached identity, including different MACs at one IP.
    /// Historical verification metadata never establishes current liveness.
    pub fn hydrate_from_cache(&self, cached: &[CachedDevice]) -> MergeResult {
        let mut map = self.lock();
        if !map.is_empty() {
            return MergeResult::default();
        }
        for entry in cached {
            if entry.mac.is_empty() || entry.ip.parse::<std::net::Ipv4Addr>().is_err() {
                continue;
            }
            let key = record_key_for_mac(&map, &entry.mac).unwrap_or_else(|| entry.mac.clone());
            if map
                .get(&key)
                .is_some_and(|r| r.last_seen >= entry.last_seen)
            {
                continue;
            }
            map.insert(
                key.clone(),
                DeviceRecord {
                    mac: key,
                    ip: entry.ip.clone(),
                    subnet: entry.subnet.clone(),
                    open_ports: entry.open_ports.clone(),
                    alias: entry.alias.clone(),
                    status: DeviceStatus::CachedOnly,
                    first_seen: entry.last_seen.clone(),
                    last_seen: entry.last_seen.clone(),
                    verified_by_mac: entry.verified_by_mac.clone(),
                    last_verified_at: entry.last_verified_at.clone(),
                },
            );
        }
        MergeResult {
            changed: !map.is_empty(),
            dropped_macs: vec![],
        }
    }

    /// Unknown legacy pins keep their manual key until fresh verification;
    /// an address alone never joins them to a discovered identity.
    pub fn hydrate_manual_nodes(&self, nodes: &[ManualNode]) -> bool {
        let mut map = self.lock();
        let mut changed = false;
        for node in nodes {
            let key = node
                .expected_mac
                .as_ref()
                .and_then(|mac| record_key_for_mac(&map, mac))
                .unwrap_or_else(|| crate::config::manual_node_key(node));
            let subnet = subnet_for(&node.ip);
            if let Some(existing) = map.get_mut(&key) {
                if existing.alias != node.alias {
                    existing.alias = node.alias.clone();
                    changed = true;
                }
                continue;
            }
            let now = chrono::Utc::now().to_rfc3339();
            map.insert(
                key.clone(),
                DeviceRecord {
                    verified_by_mac: None,
                    last_verified_at: None,
                    mac: key,
                    ip: node.ip.clone(),
                    subnet,
                    open_ports: vec![],
                    alias: node.alias.clone(),
                    status: DeviceStatus::Offline,
                    first_seen: now.clone(),
                    last_seen: now,
                },
            );
            changed = true;
        }
        changed
    }

    /// Called only with fresh proof; the manager saves the learned MAC first.
    #[allow(dead_code)] // S5a wires manual presence verification.
    pub(crate) fn merge_manual_verified(
        &self,
        node: &ManualNode,
        device: &ArpDevice,
        adapter: &str,
        verified_at: &str,
        fence: &super::SweepFence,
    ) -> MergeResult {
        if node.ip != device.ip || !Self::verification_valid(device, adapter, verified_at) {
            return MergeResult::default();
        }
        let mut map = self.lock();
        if fence.is_stale()
            || !self.proof_allowed(adapter)
            || Self::has_newer_proof(&map, device, verified_at)
        {
            return MergeResult::default();
        }
        let expected = node.expected_mac.as_deref().unwrap_or(&device.mac);
        let expected_key = record_key_for_mac(&map, expected).unwrap_or_else(|| expected.into());
        let same = same_mac(expected, &device.mac);
        let mut result = self.merge_verified_locked(&mut map, device, adapter, verified_at);
        if !same {
            if let Some(old) = map.get_mut(&expected_key) {
                result.changed |= old.status != DeviceStatus::OfflineDifferentDevice;
                old.status = DeviceStatus::OfflineDifferentDevice;
            }
            return result;
        }
        let manual_key = format!("manual:{}", node.ip);
        let pin = map.remove(&manual_key);
        let key = record_key_for_mac(&map, &device.mac).expect("verified identity");
        if let Some(record) = map.get_mut(&key) {
            let alias = pin
                .as_ref()
                .map(|r| r.alias.as_str())
                .filter(|a| !a.is_empty())
                .unwrap_or(&node.alias);
            if !alias.is_empty() && record.alias != alias {
                record.alias = alias.into();
                result.changed = true;
            }
        }
        result.changed |= pin.is_some();
        result
    }

    /// Insert or refresh a record from a live ARP discovery. New entries
    /// land as `Live`. Existing entries get their ip/subnet/last_seen
    /// refreshed; cached and topology-conflicting entries become Live after
    /// passing current capture filters. Verifying/Offline remain owned by
    /// the legacy verify path until S5a activation.
    #[allow(dead_code)] // Legacy mutator remains available until S5a.
    pub fn merge_arp(&self, device: &ArpDevice) -> MergeResult {
        if self
            .verification_scope
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some()
        {
            return MergeResult::default();
        }
        Self::merge_arp_locked(&mut self.lock(), device)
    }

    pub(crate) fn merge_arp_fenced(
        &self,
        device: &ArpDevice,
        fence: &super::SweepFence,
    ) -> MergeResult {
        let mut map = self.lock();
        if fence.is_stale()
            || self
                .verification_scope
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_some()
        {
            return MergeResult::default();
        }
        Self::merge_arp_locked(&mut map, device)
    }

    // Wired by S5a's verifier, never by the legacy observation path.
    #[allow(dead_code)]
    pub(crate) fn merge_verified(
        &self,
        device: &ArpDevice,
        adapter: &str,
        verified_at: &str,
        fence: &super::SweepFence,
    ) -> MergeResult {
        if !Self::verification_valid(device, adapter, verified_at) {
            return MergeResult::default();
        }
        let mut map = self.lock();
        if fence.is_stale()
            || !self.proof_allowed(adapter)
            || Self::has_newer_proof(&map, device, verified_at)
        {
            return MergeResult::default();
        }
        self.merge_verified_locked(&mut map, device, adapter, verified_at)
    }

    pub(crate) fn verification_valid(device: &ArpDevice, adapter: &str, verified_at: &str) -> bool {
        canonical_mac(adapter).is_some()
            && canonical_mac(&device.mac).is_some()
            && chrono::DateTime::parse_from_rfc3339(verified_at).is_ok()
            && device
                .ip
                .parse()
                .is_ok_and(|ip| !crate::validation::prohibited_camera_ip(ip))
            && !same_mac(adapter, &device.mac)
    }

    fn merge_verified_locked(
        &self,
        map: &mut HashMap<String, DeviceRecord>,
        device: &ArpDevice,
        adapter: &str,
        verified_at: &str,
    ) -> MergeResult {
        let mut result = Self::merge_arp_locked(map, device);
        let key = record_key_for_mac(map, &device.mac).expect("merged record");
        let record = map.get_mut(&key).unwrap();
        let adapter = canonical_mac(adapter).expect("validated adapter");
        result.changed |= record.verified_by_mac.as_ref() != Some(&adapter)
            || record.last_verified_at.as_deref() != Some(verified_at)
            || record.status != DeviceStatus::Live;
        record.verified_by_mac = Some(adapter);
        record.last_verified_at = Some(verified_at.into());
        record.status = DeviceStatus::Live;
        self.evidence
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                record.mac.clone(),
                tokio::time::Instant::now() + super::presence::FRESHNESS,
            );
        result
    }

    fn merge_arp_locked(
        map: &mut HashMap<String, DeviceRecord>,
        device: &ArpDevice,
    ) -> MergeResult {
        let key = record_key_for_mac(map, &device.mac).unwrap_or_else(|| device.mac.clone());
        let mut retired = false;
        for other in map
            .values_mut()
            .filter(|r| r.ip == device.ip && r.mac != key)
        {
            if other.status != DeviceStatus::Offline {
                other.status = DeviceStatus::Offline;
                retired = true;
            }
        }

        let upsert_changed = match map.get_mut(&key) {
            Some(existing) => {
                let mut changed = false;
                if existing.ip != device.ip {
                    existing.ip = device.ip.clone();
                    existing.verified_by_mac = None;
                    existing.last_verified_at = None;
                    changed = true;
                }
                if existing.subnet != device.subnet {
                    existing.subnet = device.subnet.clone();
                    changed = true;
                }
                if existing.last_seen != device.last_seen {
                    existing.last_seen = device.last_seen.clone();
                    changed = true;
                }
                if matches!(
                    existing.status,
                    DeviceStatus::CachedOnly
                        | DeviceStatus::OfflineNonWiredSubnet
                        | DeviceStatus::OfflineHostOwnedIp
                ) {
                    existing.status = DeviceStatus::Live;
                    changed = true;
                }
                changed
            }
            None => {
                map.insert(
                    key.clone(),
                    DeviceRecord {
                        verified_by_mac: None,
                        last_verified_at: None,
                        mac: key.clone(),
                        ip: device.ip.clone(),
                        subnet: device.subnet.clone(),
                        open_ports: Vec::new(),
                        alias: String::new(),
                        status: DeviceStatus::Live,
                        first_seen: device.first_seen.clone(),
                        last_seen: device.last_seen.clone(),
                    },
                );
                true
            }
        };

        MergeResult {
            changed: upsert_changed || retired,
            dropped_macs: vec![],
        }
    }

    /// Identity-keyed persistence; legacy port-bearing rows remain compatible
    /// until S5a replaces their promotion path. Verified zero-port rows persist.
    pub(crate) fn cache_record(&self, key: &str) -> Option<CachedDevice> {
        let map = self.lock();
        let r = map.get(key)?;
        if r.open_ports.is_empty() && (r.verified_by_mac.is_none() || r.last_verified_at.is_none())
        {
            return None;
        }
        Some(CachedDevice {
            mac: r.mac.clone(),
            ip: r.ip.clone(),
            subnet: r.subnet.clone(),
            open_ports: r.open_ports.clone(),
            alias: r.alias.clone(),
            last_seen: r.last_seen.clone(),
            verified_by_mac: r.verified_by_mac.clone(),
            last_verified_at: r.last_verified_at.clone(),
        })
    }

    /// Capability data is identity-keyed and never establishes presence.
    #[allow(dead_code)] // Convenience for deterministic registry tests.
    pub fn merge_scan_result(&self, key: &str, open_ports: &[u16]) -> bool {
        self.merge_scan_result_fenced(key, open_ports, None)
    }

    pub(crate) fn merge_scan_result_fenced(
        &self,
        key: &str,
        open_ports: &[u16],
        fence: Option<&super::SweepFence>,
    ) -> bool {
        let mut map = self.lock();
        if fence.is_some_and(|f| f.is_stale()) {
            return false;
        }
        match map.get_mut(key) {
            Some(record) if record.open_ports != open_ports => {
                record.open_ports = open_ports.to_vec();
                true
            }
            _ => false,
        }
    }

    /// The parsed IP of every user-pinned record (see `is_user_pinned`).
    /// Lets removal paths ask "does a pinned device sit inside this
    /// subnet" without exposing the key map — the `manual:` key prefix
    /// only exists on the map keys, not in the records a `snapshot()`
    /// returns.
    pub fn user_pinned_ips(&self, configured_pins: &HashSet<String>) -> Vec<std::net::Ipv4Addr> {
        let map = self.lock();
        map.iter()
            .filter(|(key, r)| is_user_pinned(key, &r.alias, &r.ip, configured_pins))
            .filter_map(|(_, r)| r.ip.parse().ok())
            .collect()
    }

    /// Explicit role assignment changes only the selected key and the
    /// previous holder. An unknown key cannot demote an existing role.
    pub fn set_alias(&self, key: &str, alias: &str) -> Vec<String> {
        let mut map = self.lock();
        if !map.contains_key(key) {
            return vec![];
        }
        let mut changed = vec![];
        for record in map.values_mut() {
            if record.mac == key {
                if record.alias != alias {
                    record.alias = alias.into();
                    changed.push(record.mac.clone());
                }
            } else if is_role_alias(alias) && record.alias == alias {
                record.alias.clear();
                changed.push(record.mac.clone());
            }
        }
        let ambiguous: Vec<_> = ROLE_ALIASES
            .into_iter()
            .filter(|role| map.values().filter(|r| r.alias == *role).count() > 1)
            .collect();
        for record in map.values_mut() {
            if record.status == DeviceStatus::OfflineAmbiguousRole
                && !ambiguous.contains(&record.alias.as_str())
            {
                record.status = DeviceStatus::Offline;
                changed.push(record.mac.clone());
            }
        }
        changed.sort();
        changed.dedup();
        changed
    }

    /// Preserve ambiguous legacy roles for explicit reassignment. Neither
    /// a configured address nor observation recency can choose an identity.
    pub fn normalize_role_duplicates(&self, _camera_key: Option<&str>) -> Vec<String> {
        let mut map = self.lock();
        let mut changed = vec![];
        for role in ROLE_ALIASES {
            if map.values().filter(|r| r.alias == role).count() < 2 {
                continue;
            }
            log::warn!(
                "Ambiguous {} device identities; reassign the role explicitly",
                role
            );
            for record in map.values_mut().filter(|r| r.alias == role) {
                if record.status != DeviceStatus::OfflineAmbiguousRole {
                    record.status = DeviceStatus::OfflineAmbiguousRole;
                    changed.push(record.mac.clone());
                }
            }
        }
        changed.sort();
        changed
    }

    /// Set the status for the device with this MAC.
    pub fn set_status(&self, mac: &str, status: DeviceStatus) -> bool {
        if status == DeviceStatus::Live {
            return false;
        }
        let mut map = self.lock();
        match map.get_mut(mac) {
            Some(record) if record.status != status => {
                record.status = status;
                true
            }
            _ => false,
        }
    }

    pub(crate) fn set_verification_scope(&self, adapter: Option<&str>) {
        *self
            .verification_scope
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(adapter.and_then(canonical_mac));
    }

    fn has_newer_proof(map: &HashMap<String, DeviceRecord>, device: &ArpDevice, at: &str) -> bool {
        let Ok(incoming) = chrono::DateTime::parse_from_rfc3339(at) else {
            return true;
        };
        map.values()
            .filter(|r| {
                r.status == DeviceStatus::Live
                    && (same_mac(&r.mac, &device.mac) || r.ip == device.ip)
            })
            .filter_map(|r| {
                r.last_verified_at
                    .as_ref()
                    .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            })
            .any(|existing| existing > incoming)
    }

    fn proof_allowed(&self, adapter: &str) -> bool {
        match &*self
            .verification_scope
            .lock()
            .unwrap_or_else(|p| p.into_inner())
        {
            None => true, // standalone registry tests; setup installs the scope
            Some(Some(expected)) => canonical_mac(adapter).as_ref() == Some(expected),
            Some(None) => false,
        }
    }

    pub(crate) fn remember_verified_at(
        &self,
        mac: &str,
        wall: &str,
        at: tokio::time::Instant,
        fence: &super::SweepFence,
    ) {
        let map = self.lock();
        if fence.is_stale() {
            return;
        }
        if let Some(key) = record_key_for_mac(&map, mac)
            .filter(|k| map[k].last_verified_at.as_deref() == Some(wall))
        {
            self.evidence
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(key, at + super::presence::FRESHNESS);
        }
    }

    pub(crate) fn expire_evidence(&self, now: tokio::time::Instant) -> bool {
        let mut map = self.lock();
        let mut deadlines = self.evidence.lock().unwrap_or_else(|p| p.into_inner());
        let mut changed = false;
        for record in map.values_mut() {
            if record.status == DeviceStatus::Live
                && deadlines.get(&record.mac).is_none_or(|t| now >= *t)
            {
                record.status = DeviceStatus::Offline;
                changed = true;
            }
        }
        deadlines.retain(|key, time| map.contains_key(key) && now < *time);
        changed
    }

    pub(crate) fn expire_all(&self) -> bool {
        let mut map = self.lock();
        self.evidence
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        let mut changed = false;
        for record in map.values_mut().filter(|r| r.status == DeviceStatus::Live) {
            record.status = DeviceStatus::Offline;
            changed = true;
        }
        changed
    }

    /// Drop the record for this MAC entirely.
    pub fn forget(&self, mac: &str) -> bool {
        let mut map = self.lock();
        map.remove(mac).is_some()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, DeviceRecord>> {
        match self.devices.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!("DeviceRegistry mutex poisoned, recovering");
                poisoned.into_inner()
            }
        }
    }
}

impl Default for DeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Aliases with reserved role semantics: at most one record may hold
/// each at any time. Exact, case-sensitive match — "Cam" or "CAM2" are
/// ordinary custom names.
const ROLE_ALIASES: [&str; 2] = ["CAM", "PTU"];

pub(crate) fn is_role_alias(alias: &str) -> bool {
    ROLE_ALIASES.contains(&alias)
}

pub(crate) fn canonical_mac(mac: &str) -> Option<String> {
    let bytes = super::parse_mac_bytes(mac)?;
    if bytes == [0; 6] || bytes[0] & 1 != 0 {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn same_mac(a: &str, b: &str) -> bool {
    match (canonical_mac(a), canonical_mac(b)) {
        (Some(a), Some(b)) => a == b,
        _ => a == b,
    }
}

fn record_key_for_mac(map: &HashMap<String, DeviceRecord>, mac: &str) -> Option<String> {
    if map.contains_key(mac) {
        return Some(mac.into());
    }
    map.keys().find(|key| same_mac(key, mac)).cloned()
}

/// Compare two dotted-quad IP strings numerically. Falls back to
/// lexicographic comparison if either side fails to parse.
fn compare_ips(a: &str, b: &str) -> std::cmp::Ordering {
    use std::net::Ipv4Addr;
    match (a.parse::<Ipv4Addr>(), b.parse::<Ipv4Addr>()) {
        (Ok(ai), Ok(bi)) => ai.cmp(&bi),
        _ => a.cmp(b),
    }
}

/// Derive the `/24` subnet string from an IPv4 address. Returns
/// `0.0.0.0/24` if the input is unparseable — the registry tolerates
/// a missing subnet for synthetic records like manual-pin hydrations
/// rather than refusing to insert them.
fn subnet_for(ip: &str) -> String {
    match ip.parse::<std::net::Ipv4Addr>() {
        Ok(addr) => {
            let o = addr.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Err(_) => "0.0.0.0/24".to_string(),
    }
}

/// Window during which multiple registry mutations coalesce into a
/// single `device-list-changed` emission. ARP bursts (initial ping
/// sweep, post-adoption sweeps) routinely produce dozens of mutations
/// in a few hundred ms; emitting per-mutation would force the renderer
/// to redraw the device list 50 times for one logical event. 150 ms
/// is short enough to feel instant on a single discovery and long
/// enough to amortize a burst.
const EMIT_COALESCE_WINDOW: Duration = Duration::from_millis(150);

/// Tauri-aware companion that turns registry mutations into
/// `device-list-changed` events on a debounced schedule.
///
/// Construction requires an `AppHandle`, so this type lives outside
/// the registry itself (which is deliberately tauri-free for testing).
/// Wired up in `NetworkManager::start_arp_discovery` once the handle
/// is available.
pub struct DeviceListEmitter {
    handle: tauri::AppHandle,
    registry: Arc<DeviceRegistry>,
    dirty: AtomicBool,
}

impl DeviceListEmitter {
    pub fn new(handle: tauri::AppHandle, registry: Arc<DeviceRegistry>) -> Arc<Self> {
        Arc::new(Self {
            handle,
            registry,
            dirty: AtomicBool::new(false),
        })
    }

    /// Mark the device list as changed. The first poke in a coalesce
    /// window arms a 150 ms timer; subsequent pokes within the window
    /// are absorbed. When the timer fires, a single snapshot is emitted.
    pub fn poke(self: &Arc<Self>) {
        // swap returns the previous value. If we won the race to set
        // dirty=true, we own the spawn responsibility. Otherwise some
        // other caller already armed a timer that will pick up our
        // mutation (snapshots are read-after-flag-clear).
        if !self.dirty.swap(true, Ordering::AcqRel) {
            let me = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(EMIT_COALESCE_WINDOW).await;
                // Clear the flag *before* taking the snapshot. Any
                // mutation that lands between these two lines re-arms
                // the timer (poke wins the swap race because we just
                // released the flag) and gets its own emission window.
                me.dirty.store(false, Ordering::Release);
                let snapshot = me.registry.snapshot();
                use tauri::Emitter;
                let _ = me.handle.emit("device-list-changed", &snapshot);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arp(mac: &str, ip: &str, subnet: &str) -> ArpDevice {
        ArpDevice {
            mac: mac.into(),
            ip: ip.into(),
            subnet: subnet.into(),
            first_seen: "2026-04-27T00:00:00Z".into(),
            last_seen: "2026-04-27T00:00:00Z".into(),
        }
    }

    fn cached(mac: &str, ip: &str, subnet: &str, ports: Vec<u16>, alias: &str) -> CachedDevice {
        CachedDevice {
            verified_by_mac: None,
            last_verified_at: None,
            mac: mac.into(),
            ip: ip.into(),
            subnet: subnet.into(),
            open_ports: ports,
            alias: alias.into(),
            last_seen: "2026-04-26T00:00:00Z".into(),
        }
    }

    #[test]
    fn snapshot_starts_empty() {
        let r = DeviceRegistry::new();
        assert!(r.snapshot().is_empty());
    }

    #[test]
    fn merge_scan_result_zero_ports_does_not_promote_to_live() {
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[cached(
            "AA:BB:CC:DD:EE:01",
            "192.168.1.10",
            "192.168.1.0/24",
            vec![80],
            "",
        )]);
        // Cached row starts CachedOnly. A zero-port verify must NOT flip
        // it to Live (that resurrected dead devices).
        r.merge_scan_result("AA:BB:CC:DD:EE:01", &[]);
        assert_eq!(r.snapshot()[0].status, DeviceStatus::CachedOnly);
        // A non-empty scan remains capability data, not presence.
        r.merge_scan_result("AA:BB:CC:DD:EE:01", &[80]);
        assert_eq!(r.snapshot()[0].status, DeviceStatus::CachedOnly);
    }

    #[test]
    fn configured_pins_collects_manual_nodes_and_stream_target() {
        let mut settings = AppSettings::default();
        settings.manual_nodes.push(ManualNode {
            expected_mac: None,
            ip: "192.168.4.202".into(),
            alias: "PTU".into(),
        });
        settings.stream.camera_ip = "172.31.169.65".into();
        let pins = configured_pins(&settings);
        assert!(pins.contains("192.168.4.202"));
        assert!(pins.contains("172.31.169.65"));

        // An unset stream target must not pin the empty string.
        settings.stream.camera_ip = String::new();
        assert!(!configured_pins(&settings).contains(""));
    }

    #[test]
    fn user_pinned_ips_returns_pinned_records_only() {
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[
            cached(
                "AA:BB:CC:DD:EE:01",
                "192.168.4.65",
                "192.168.4.0/24",
                vec![80],
                "CAM",
            ),
            cached(
                "AA:BB:CC:DD:EE:02",
                "192.168.4.90",
                "192.168.4.0/24",
                vec![80],
                "",
            ),
            cached("AA:BB:CC:DD:EE:03", "10.0.0.5", "10.0.0.0/24", vec![], ""),
        ]);
        let pins: HashSet<String> = ["10.0.0.5".to_string()].into_iter().collect();
        let mut ips = r.user_pinned_ips(&pins);
        ips.sort();
        // The aliased CAM and the configured pin qualify; the anonymous
        // row does not.
        assert_eq!(
            ips,
            vec![
                "10.0.0.5".parse::<std::net::Ipv4Addr>().unwrap(),
                "192.168.4.65".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn is_user_pinned_covers_every_intent_signal_and_nothing_else() {
        let pins: HashSet<String> = ["10.0.0.5".to_string()].into_iter().collect();
        // Pinned registry entry, regardless of alias.
        assert!(is_user_pinned("manual:10.0.0.9", "", "10.0.0.9", &pins));
        // Any non-empty alias — CAM, PTU, or a custom name.
        assert!(is_user_pinned(
            "AA:BB:CC:DD:EE:01",
            "CAM",
            "10.0.0.1",
            &pins
        ));
        assert!(is_user_pinned(
            "AA:BB:CC:DD:EE:02",
            "PTU",
            "10.0.0.2",
            &pins
        ));
        assert!(is_user_pinned(
            "AA:BB:CC:DD:EE:03",
            "warehouse-cam",
            "10.0.0.3",
            &pins
        ));
        // Configured pin (manual node or stream target).
        assert!(is_user_pinned("AA:BB:CC:DD:EE:04", "", "10.0.0.5", &pins));
        // Unaliased, unconfigured, ordinary MAC key — not pinned.
        assert!(!is_user_pinned("AA:BB:CC:DD:EE:05", "", "10.0.0.6", &pins));
    }

    #[test]
    fn hydrate_from_cache_drops_non_ipv4_rows() {
        let r = DeviceRegistry::new();
        let result = r.hydrate_from_cache(&[
            cached(
                "AA:BB:CC:DD:EE:01",
                "192.168.1.10",
                "192.168.1.0/24",
                vec![80],
                "",
            ),
            cached(
                "AA:BB:CC:DD:EE:02",
                "camera.local",
                "192.168.1.0/24",
                vec![80],
                "",
            ),
            cached("", "192.168.1.11", "192.168.1.0/24", vec![], ""),
            cached(
                "AA:BB:CC:DD:EE:04",
                "169.254.5.5",
                "169.254.0.0/24",
                vec![],
                "",
            ),
        ]);
        assert!(result.changed);
        let snap = r.snapshot();
        // Only the valid-IPv4, non-empty-MAC rows survive: 192.168.1.10
        // and the APIPA one. The hostname and empty-MAC rows are dropped.
        let ips: Vec<&str> = snap.iter().map(|d| d.ip.as_str()).collect();
        assert!(ips.contains(&"192.168.1.10"));
        assert!(ips.contains(&"169.254.5.5"));
        assert!(!ips.contains(&"camera.local"));
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn merge_arp_inserts_new_record_as_live() {
        let r = DeviceRegistry::new();
        let result = r.merge_arp(&arp("AA:BB:CC:DD:EE:01", "192.168.1.10", "192.168.1.0/24"));
        assert!(result.changed);
        let snap = r.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].status, DeviceStatus::Live);
        assert!(snap[0].open_ports.is_empty());
        assert_eq!(snap[0].alias, "");
    }

    #[test]
    fn merge_arp_idempotent_when_nothing_changed() {
        let r = DeviceRegistry::new();
        let dev = arp("AA:BB:CC:DD:EE:01", "192.168.1.10", "192.168.1.0/24");
        assert!(r.merge_arp(&dev).changed);
        assert!(
            !r.merge_arp(&dev).changed,
            "second merge with identical data must be a no-op"
        );
    }

    #[test]
    fn merge_arp_promotes_cached_only_to_live() {
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[cached(
            "AA:BB:CC:DD:EE:01",
            "192.168.1.10",
            "192.168.1.0/24",
            vec![80],
            "",
        )]);
        assert_eq!(r.snapshot()[0].status, DeviceStatus::CachedOnly);

        let result = r.merge_arp(&arp("AA:BB:CC:DD:EE:01", "192.168.1.10", "192.168.1.0/24"));
        assert!(
            result.changed,
            "promoting CachedOnly → Live counts as a change"
        );
        assert_eq!(r.snapshot()[0].status, DeviceStatus::Live);
    }

    #[test]
    fn merge_scan_result_populates_ports_without_promoting() {
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[cached(
            "AA:BB:CC:DD:EE:01",
            "192.168.1.10",
            "192.168.1.0/24",
            vec![],
            "",
        )]);
        r.set_status("AA:BB:CC:DD:EE:01", DeviceStatus::Verifying);
        assert_eq!(r.snapshot()[0].status, DeviceStatus::Verifying);

        let changed = r.merge_scan_result("AA:BB:CC:DD:EE:01", &[80, 554]);
        assert!(changed);
        let snap = r.snapshot();
        assert_eq!(snap[0].open_ports, vec![80, 554]);
        assert_eq!(snap[0].status, DeviceStatus::Verifying);
    }

    #[test]
    fn merge_scan_result_noop_when_ip_unknown() {
        let r = DeviceRegistry::new();
        assert!(!r.merge_scan_result("10.0.0.1", &[22]));
    }

    #[test]
    fn set_alias_updates_existing_record() {
        let r = DeviceRegistry::new();
        r.merge_arp(&arp("AA:BB:CC:DD:EE:01", "192.168.1.10", "192.168.1.0/24"));
        assert_eq!(
            r.set_alias("AA:BB:CC:DD:EE:01", "CAM"),
            vec!["AA:BB:CC:DD:EE:01".to_string()]
        );
        assert_eq!(r.snapshot()[0].alias, "CAM");
        assert!(
            r.set_alias("AA:BB:CC:DD:EE:01", "CAM").is_empty(),
            "identical write is a no-op"
        );
        assert_eq!(
            r.set_alias("AA:BB:CC:DD:EE:01", ""),
            vec!["AA:BB:CC:DD:EE:01".to_string()],
            "empty string clears"
        );
        assert_eq!(r.snapshot()[0].alias, "");
    }

    // ── role exclusivity (single-holder invariant) ──────────────────

    #[test]
    fn role_alias_match_is_exact_and_case_sensitive() {
        assert!(is_role_alias("CAM"));
        assert!(is_role_alias("PTU"));
        // Near-misses are ordinary custom names.
        assert!(!is_role_alias("Cam"));
        assert!(!is_role_alias("cam"));
        assert!(!is_role_alias("CAM2"));
        assert!(!is_role_alias("ptu"));
        assert!(!is_role_alias(""));
    }

    /// Count of records currently holding `role`.
    fn holders(r: &DeviceRegistry, role: &str) -> usize {
        r.snapshot().iter().filter(|d| d.alias == role).count()
    }

    fn alias_of(r: &DeviceRegistry, ip: &str) -> String {
        r.snapshot()
            .iter()
            .find(|d| d.ip == ip)
            .map(|d| d.alias.clone())
            .unwrap_or_default()
    }

    #[test]
    fn set_alias_unknown_ip_is_noop_and_keeps_holder() {
        let r = DeviceRegistry::new();
        r.merge_arp(&arp("MAC:A", "192.168.1.10", "192.168.1.0/24"));
        r.set_alias("MAC:A", "CAM");
        assert!(
            r.set_alias("10.9.9.9", "CAM").is_empty(),
            "unknown target must change nothing"
        );
        assert_eq!(alias_of(&r, "192.168.1.10"), "CAM");
    }

    #[test]
    fn set_alias_role_steal_demotes_previous_holder() {
        let r = DeviceRegistry::new();
        r.merge_arp(&arp("MAC:A", "192.168.1.10", "192.168.1.0/24"));
        r.merge_arp(&arp("MAC:B", "192.168.1.20", "192.168.1.0/24"));
        r.set_alias("MAC:A", "CAM");

        let changed = r.set_alias("MAC:B", "CAM");
        assert_eq!(changed, vec!["MAC:A".to_string(), "MAC:B".to_string()]);
        assert_eq!(alias_of(&r, "192.168.1.10"), "", "previous holder reverts");
        assert_eq!(alias_of(&r, "192.168.1.20"), "CAM");
        assert_eq!(holders(&r, "CAM"), 1);
    }

    #[test]
    fn set_alias_cam_and_ptu_coexist_on_different_nodes() {
        let r = DeviceRegistry::new();
        r.merge_arp(&arp("MAC:A", "192.168.1.10", "192.168.1.0/24"));
        r.merge_arp(&arp("MAC:B", "192.168.1.20", "192.168.1.0/24"));
        r.set_alias("MAC:A", "CAM");
        let changed = r.set_alias("MAC:B", "PTU");
        assert_eq!(changed, vec!["MAC:B".to_string()]);
        assert_eq!(alias_of(&r, "192.168.1.10"), "CAM");
        assert_eq!(alias_of(&r, "192.168.1.20"), "PTU");
    }

    #[test]
    fn set_alias_cross_role_overwrite_leaves_single_holders() {
        // Assigning CAM onto the node that holds PTU: the node's PTU is
        // overwritten and the previous CAM holder is demoted — exactly
        // one CAM and zero PTUs remain.
        let r = DeviceRegistry::new();
        r.merge_arp(&arp("MAC:A", "192.168.1.10", "192.168.1.0/24"));
        r.merge_arp(&arp("MAC:B", "192.168.1.20", "192.168.1.0/24"));
        r.set_alias("MAC:A", "CAM");
        r.set_alias("MAC:B", "PTU");

        let changed = r.set_alias("MAC:B", "CAM");
        assert_eq!(changed, vec!["MAC:A".to_string(), "MAC:B".to_string()]);
        assert_eq!(alias_of(&r, "192.168.1.20"), "CAM");
        assert_eq!(alias_of(&r, "192.168.1.10"), "");
        assert_eq!(holders(&r, "CAM"), 1);
        assert_eq!(holders(&r, "PTU"), 0);
    }

    #[test]
    fn set_alias_custom_name_never_demotes_roles() {
        let r = DeviceRegistry::new();
        r.merge_arp(&arp("MAC:A", "192.168.1.10", "192.168.1.0/24"));
        r.merge_arp(&arp("MAC:B", "192.168.1.20", "192.168.1.0/24"));
        r.set_alias("MAC:A", "CAM");
        let changed = r.set_alias("MAC:B", "Bench unit");
        assert_eq!(changed, vec!["MAC:B".to_string()]);
        assert_eq!(alias_of(&r, "192.168.1.10"), "CAM");
    }

    #[test]
    fn set_alias_repairs_duplicate_even_when_target_already_holds_role() {
        // Legacy cache state can hold two CAMs. Re-assigning CAM to one
        // of them is a no-op on the target but must still demote the
        // other holder.
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[
            cached("MAC:A", "192.168.1.10", "192.168.1.0/24", vec![80], "CAM"),
            cached("MAC:B", "192.168.1.20", "192.168.1.0/24", vec![80], "CAM"),
        ]);
        assert_eq!(holders(&r, "CAM"), 2, "legacy duplicate precondition");

        let changed = r.set_alias("MAC:A", "CAM");
        assert_eq!(changed, vec!["MAC:B".to_string()]);
        assert_eq!(alias_of(&r, "192.168.1.10"), "CAM");
        assert_eq!(holders(&r, "CAM"), 1);
    }

    // ── normalize_role_duplicates ───────────────────────────────────

    fn cached_at(mac: &str, ip: &str, alias: &str, last_seen: &str) -> CachedDevice {
        CachedDevice {
            verified_by_mac: None,
            last_verified_at: None,
            mac: mac.into(),
            ip: ip.into(),
            subnet: "192.168.1.0/24".into(),
            open_ports: vec![80],
            alias: alias.into(),
            last_seen: last_seen.into(),
        }
    }

    #[test]
    fn normalize_is_noop_without_duplicates() {
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[
            cached_at("MAC:A", "192.168.1.10", "CAM", "2026-07-01T00:00:00Z"),
            cached_at("MAC:B", "192.168.1.20", "PTU", "2026-07-01T00:00:00Z"),
        ]);
        assert!(r.normalize_role_duplicates(None).is_empty());
        assert_eq!(alias_of(&r, "192.168.1.10"), "CAM");
        assert_eq!(alias_of(&r, "192.168.1.20"), "PTU");
    }

    #[test]
    fn normalize_is_deterministic_across_insertion_orders() {
        let rows = [
            cached_at("MAC:A", "192.168.1.10", "CAM", "2026-07-01T00:00:00Z"),
            cached_at("MAC:B", "192.168.1.20", "CAM", "2026-07-01T00:00:00Z"),
            cached_at("MAC:C", "192.168.1.30", "CAM", "2026-07-01T00:00:00Z"),
        ];
        let forward = DeviceRegistry::new();
        forward.hydrate_from_cache(&rows);
        forward.normalize_role_duplicates(None);

        let mut reversed_rows = rows.to_vec();
        reversed_rows.reverse();
        let reversed = DeviceRegistry::new();
        reversed.hydrate_from_cache(&reversed_rows);
        reversed.normalize_role_duplicates(None);

        assert_eq!(alias_of(&forward, "192.168.1.10"), "CAM");
        assert_eq!(alias_of(&reversed, "192.168.1.10"), "CAM");
        assert_eq!(holders(&forward, "CAM"), 3);
        assert_eq!(holders(&reversed, "CAM"), 3);
    }

    #[test]
    fn normalize_is_idempotent() {
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[
            cached_at("MAC:A", "192.168.1.10", "CAM", "2026-07-01T00:00:00Z"),
            cached_at("MAC:B", "192.168.1.20", "CAM", "2026-07-10T00:00:00Z"),
        ]);
        assert!(!r.normalize_role_duplicates(None).is_empty());
        assert!(r.normalize_role_duplicates(None).is_empty());
    }

    // ── merge paths move roles, never copy them ─────────────────────

    #[test]
    fn merge_arp_keeps_role_with_original_identity() {
        // One CAM before the MAC change at its IP → one CAM after.
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[cached(
            "OLD:MAC",
            "192.168.1.10",
            "192.168.1.0/24",
            vec![80],
            "CAM",
        )]);
        r.merge_arp(&arp("NEW:MAC", "192.168.1.10", "192.168.1.0/24"));
        assert_eq!(holders(&r, "CAM"), 1);
        assert_eq!(
            r.snapshot().iter().find(|r| r.alias == "CAM").unwrap().mac,
            "OLD:MAC"
        );
    }

    #[test]
    fn hydrate_keeps_each_alias_with_its_identity() {
        // One CAM among the same-IP duplicates → one CAM after hydration.
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[
            cached_at("OLD:MAC", "192.168.1.10", "CAM", "2026-06-01T00:00:00Z"),
            cached_at("NEW:MAC", "192.168.1.10", "", "2026-07-01T00:00:00Z"),
        ]);
        assert_eq!(holders(&r, "CAM"), 1);
        let snap = r.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(
            snap.iter().find(|r| r.alias == "CAM").unwrap().mac,
            "OLD:MAC"
        );
    }

    #[test]
    fn forget_removes_record() {
        let r = DeviceRegistry::new();
        r.merge_arp(&arp("AA:BB:CC:DD:EE:01", "192.168.1.10", "192.168.1.0/24"));
        assert!(r.forget("AA:BB:CC:DD:EE:01"));
        assert!(r.snapshot().is_empty());
        assert!(!r.forget("AA:BB:CC:DD:EE:01"), "second forget is a no-op");
    }

    #[test]
    fn hydrate_from_cache_skips_when_already_populated() {
        let r = DeviceRegistry::new();
        r.merge_arp(&arp("AA:BB:CC:DD:EE:01", "192.168.1.10", "192.168.1.0/24"));
        let result = r.hydrate_from_cache(&[cached(
            "FF:FF:FF:FF:FF:FF",
            "10.0.0.1",
            "10.0.0.0/24",
            vec![],
            "",
        )]);
        assert!(
            !result.changed,
            "hydrate is a one-shot — must skip if registry isn't empty"
        );
        assert_eq!(r.snapshot().len(), 1);
    }

    #[test]
    fn snapshot_sorts_by_subnet_then_ip_numerically() {
        let r = DeviceRegistry::new();
        r.merge_arp(&arp("MAC:1", "192.168.1.20", "192.168.1.0/24"));
        r.merge_arp(&arp("MAC:2", "192.168.1.3", "192.168.1.0/24"));
        r.merge_arp(&arp("MAC:3", "10.0.0.5", "10.0.0.0/24"));

        let snap = r.snapshot();
        assert_eq!(snap[0].ip, "10.0.0.5");
        assert_eq!(snap[1].ip, "192.168.1.3");
        assert_eq!(snap[2].ip, "192.168.1.20");
    }

    #[test]
    fn set_status_returns_false_for_unknown_mac() {
        let r = DeviceRegistry::new();
        assert!(!r.set_status("DOES:NOT:EXIST", DeviceStatus::Offline));
    }

    #[test]
    fn merge_arp_retains_stale_record_at_same_ip() {
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[cached(
            "OLD:MAC",
            "192.168.1.202",
            "192.168.1.0/24",
            vec![80],
            "PTU",
        )]);

        let result = r.merge_arp(&arp("NEW:MAC", "192.168.1.202", "192.168.1.0/24"));

        assert!(result.changed);
        assert!(result.dropped_macs.is_empty());
        let snap = r.snapshot();
        assert_eq!(snap.len(), 2);
        let old = snap.iter().find(|r| r.mac == "OLD:MAC").unwrap();
        let new = snap.iter().find(|r| r.mac == "NEW:MAC").unwrap();
        assert_eq!(old.status, DeviceStatus::Offline);
        assert_eq!(old.alias, "PTU");
        assert!(new.alias.is_empty());
        assert_eq!(new.status, DeviceStatus::Live);
        assert!(r.merge_scan_result(&new.mac, &[554]));
        let after_scan = r.snapshot();
        let old = after_scan.iter().find(|r| r.mac == "OLD:MAC").unwrap();
        let new = after_scan.iter().find(|r| r.mac == "NEW:MAC").unwrap();
        assert_eq!(old.status, DeviceStatus::Offline);
        assert_eq!(old.open_ports, vec![80]);
        assert_eq!(new.open_ports, vec![554]);
    }

    #[test]
    fn merge_arp_preserves_explicit_alias_over_inherited() {
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[
            cached(
                "OLD:MAC",
                "192.168.1.202",
                "192.168.1.0/24",
                vec![80],
                "Old",
            ),
            cached("NEW:MAC", "10.0.0.5", "10.0.0.0/24", vec![80], "Explicit"),
        ]);
        // NEW:MAC moves to PTU's IP. Its existing alias should not be
        // clobbered by the inheriting code path.
        r.merge_arp(&arp("NEW:MAC", "192.168.1.202", "192.168.1.0/24"));

        let snap = r.snapshot();
        let new_record = snap.iter().find(|r| r.mac == "NEW:MAC").unwrap();
        assert_eq!(new_record.alias, "Explicit");
    }

    #[test]
    fn hydrate_retains_same_ip_identities_without_alias_transfer() {
        let r = DeviceRegistry::new();
        let older = CachedDevice {
            verified_by_mac: None,
            last_verified_at: None,
            mac: "OLD:MAC".into(),
            ip: "192.168.1.202".into(),
            subnet: "192.168.1.0/24".into(),
            open_ports: vec![80],
            alias: "PTU".into(),
            last_seen: "2026-04-01T00:00:00Z".into(),
        };
        let newer = CachedDevice {
            verified_by_mac: None,
            last_verified_at: None,
            mac: "NEW:MAC".into(),
            ip: "192.168.1.202".into(),
            subnet: "192.168.1.0/24".into(),
            open_ports: vec![80],
            alias: "".into(),
            last_seen: "2026-05-01T00:00:00Z".into(),
        };
        let result = r.hydrate_from_cache(&[older, newer]);

        assert!(result.changed);
        assert!(result.dropped_macs.is_empty());
        let snap = r.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(
            snap.iter().find(|r| r.mac == "OLD:MAC").unwrap().alias,
            "PTU"
        );
        assert!(snap
            .iter()
            .find(|r| r.mac == "NEW:MAC")
            .unwrap()
            .alias
            .is_empty());
        assert!(snap.iter().all(|r| r.status == DeviceStatus::CachedOnly));
    }

    // ── hydrate_manual_nodes ────────────────────────────────────────

    fn manual(ip: &str, alias: &str) -> ManualNode {
        ManualNode {
            expected_mac: None,
            ip: ip.into(),
            alias: alias.into(),
        }
    }

    #[test]
    fn hydrate_manual_nodes_inserts_records_with_synthetic_mac() {
        let r = DeviceRegistry::new();
        let changed = r.hydrate_manual_nodes(&[
            manual("192.168.1.50", "CAM"),
            manual("192.168.1.202", "PTU"),
        ]);
        assert!(changed);
        let snap = r.snapshot();
        assert_eq!(snap.len(), 2);
        // Synthetic MAC keys mark these as manual hydrations, so any
        // MAC-parsing code path will reject them cleanly rather than
        // mistaking them for real ARP records.
        assert!(snap.iter().all(|d| d.mac.starts_with("manual:")));
    }

    #[test]
    fn hydrate_manual_nodes_derives_subnet_from_ip() {
        let r = DeviceRegistry::new();
        r.hydrate_manual_nodes(&[manual("10.13.248.55", "")]);
        let snap = r.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].subnet, "10.13.248.0/24");
    }

    #[test]
    fn hydrate_manual_nodes_idempotent_for_unchanged_input() {
        let r = DeviceRegistry::new();
        let nodes = vec![manual("192.168.1.50", "CAM")];
        assert!(r.hydrate_manual_nodes(&nodes));
        // Second call with identical input must report no-change so
        // callers can skip a redundant device-list-changed emission.
        assert!(!r.hydrate_manual_nodes(&nodes));
    }

    #[test]
    fn hydrate_manual_nodes_updates_alias_in_place() {
        let r = DeviceRegistry::new();
        r.hydrate_manual_nodes(&[manual("192.168.1.50", "OLD")]);
        let changed = r.hydrate_manual_nodes(&[manual("192.168.1.50", "NEW")]);
        assert!(changed, "alias rename must register as a change");
        let snap = r.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].alias, "NEW");
    }

    #[test]
    fn hydrate_manual_nodes_empty_list_is_noop() {
        let r = DeviceRegistry::new();
        assert!(!r.hydrate_manual_nodes(&[]));
        assert!(r.snapshot().is_empty());
    }

    // ── clear ───────────────────────────────────────────────────────

    #[test]
    fn clear_returns_false_when_empty() {
        let r = DeviceRegistry::new();
        assert!(!r.clear());
    }

    #[test]
    fn clear_drops_all_records_and_returns_true() {
        let r = DeviceRegistry::new();
        r.merge_arp(&arp("AA:BB:CC:DD:EE:01", "192.168.1.10", "192.168.1.0/24"));
        r.hydrate_manual_nodes(&[manual("192.168.1.50", "CAM")]);
        assert_eq!(r.snapshot().len(), 2);
        assert!(r.clear());
        assert!(r.snapshot().is_empty());
    }

    #[test]
    fn verified_zero_port_cache_is_keyed_and_round_trips_without_promoting_on_load() {
        let registry = DeviceRegistry::new();
        let active = Arc::new(AtomicBool::new(true));
        let fence = super::super::SweepFence::new(
            1,
            Arc::new(std::sync::atomic::AtomicU64::new(1)),
            active.clone(),
        );
        let device = arp("aa:bb:cc:dd:ee:02", "192.168.1.204", "192.168.1.0/24");
        assert!(
            registry
                .merge_verified(&device, "40:cd:3a:00:00:01", "2026-10-19T12:00:00Z", &fence)
                .changed
        );
        assert!(registry.cache_record(&device.ip).is_none());
        let cached = registry.cache_record(&device.mac).unwrap();
        assert!(cached.open_ports.is_empty());
        let restored: CachedDevice = toml::from_str(&toml::to_string(&cached).unwrap()).unwrap();
        assert_eq!(
            restored.verified_by_mac.as_deref(),
            Some("40:cd:3a:00:00:01")
        );
        assert_eq!(
            restored.last_verified_at.as_deref(),
            Some("2026-10-19T12:00:00Z")
        );
        let cold = DeviceRegistry::new();
        cold.hydrate_from_cache(&[restored]);
        assert_eq!(cold.snapshot()[0].status, DeviceStatus::CachedOnly);
        active.store(false, Ordering::Relaxed);
        let before = registry.snapshot();
        assert!(!registry.merge_scan_result_fenced(&device.mac, &[80], Some(&fence)));
        assert!(
            !registry
                .merge_verified(
                    &arp("aa:bb:cc:dd:ee:04", &device.ip, &device.subnet),
                    "40:cd:3a:00:00:01",
                    "2026-10-19T12:00:01Z",
                    &fence
                )
                .changed
        );
        assert!(!registry.merge_arp_fenced(&device, &fence).changed);
        assert_eq!(registry.snapshot(), before);
    }

    #[test]
    fn same_ip_role_and_capability_actions_follow_the_selected_key() {
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[
            cached("OLD", "192.168.1.204", "192.168.1.0/24", vec![80], "CAM"),
            cached("NEW", "192.168.1.204", "192.168.1.0/24", vec![554], ""),
        ]);
        assert!(r.set_alias("192.168.1.204", "PTU").is_empty());
        assert!(!r.merge_scan_result("192.168.1.204", &[22]));
        assert_eq!(r.set_alias("NEW", "CAM"), vec!["NEW", "OLD"]);
        assert!(r.merge_scan_result("OLD", &[443]));
        let snapshot = r.snapshot();
        let old = snapshot.iter().find(|r| r.mac == "OLD").unwrap();
        let new = snapshot.iter().find(|r| r.mac == "NEW").unwrap();
        assert_eq!(old.alias, "");
        assert_eq!(new.alias, "CAM");
        assert_eq!(old.open_ports, vec![443]);
        assert_eq!(new.open_ports, vec![554]);
        assert_eq!(old.status, DeviceStatus::CachedOnly);
        assert_eq!(new.status, DeviceStatus::CachedOnly);
        assert_eq!(r.set_alias("OLD", "PTU"), vec!["OLD"]);
        assert_eq!(r.set_alias("NEW", ""), vec!["NEW"]);
    }

    #[test]
    fn duplicate_roles_are_flagged_without_selecting_by_ip_or_time() {
        for role in ["CAM", "PTU"] {
            for preferred in [None, Some("MAC:A"), Some("192.168.1.204")] {
                let r = DeviceRegistry::new();
                r.hydrate_from_cache(&[
                    cached_at("MAC:A", "192.168.1.204", role, "2026-07-01T00:00:00Z"),
                    cached_at("MAC:B", "192.168.1.204", role, "2026-07-10T00:00:00Z"),
                ]);
                assert_eq!(
                    r.normalize_role_duplicates(preferred),
                    vec!["MAC:A", "MAC:B"]
                );
                assert!(r
                    .snapshot()
                    .iter()
                    .all(|r| r.alias == role && r.status == DeviceStatus::OfflineAmbiguousRole));
                r.set_alias("MAC:B", role);
                assert_eq!(holders(&r, role), 1);
                assert!(r
                    .snapshot()
                    .iter()
                    .all(|r| r.status == DeviceStatus::Offline));
            }
        }
    }

    fn proof_fence() -> super::super::SweepFence {
        super::super::SweepFence::new(
            1,
            Arc::new(std::sync::atomic::AtomicU64::new(1)),
            Arc::new(AtomicBool::new(true)),
        )
    }

    #[test]
    fn legacy_manual_pin_does_not_guess_a_mac_from_the_address() {
        let r = DeviceRegistry::new();
        let device = arp("aa:bb:cc:dd:ee:02", "192.168.1.204", "192.168.1.0/24");
        r.merge_arp(&device);
        let node = manual(&device.ip, "CAM");
        r.hydrate_manual_nodes(std::slice::from_ref(&node));
        assert_eq!(r.snapshot().len(), 2);
        let manual = r
            .snapshot()
            .into_iter()
            .find(|r| r.mac.starts_with("manual:"))
            .unwrap();
        assert_eq!(manual.status, DeviceStatus::Offline);
        assert!(manual.last_verified_at.is_none());
        assert!(
            r.merge_manual_verified(
                &node,
                &device,
                "40:cd:3a:00:00:01",
                "2026-10-19T12:00:00Z",
                &proof_fence()
            )
            .changed
        );
        let snapshot = r.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].mac, device.mac);
        assert_eq!(snapshot[0].alias, "CAM");
        assert_eq!(snapshot[0].status, DeviceStatus::Live);
        assert_eq!(holders(&r, "CAM"), 1);
    }

    #[test]
    fn manual_binding_survives_reload_and_replacement_stays_separate() {
        let mut node = manual("192.168.1.204", "CAM");
        node.expected_mac = Some("aa:bb:cc:dd:ee:02".into());
        let node: ManualNode = toml::from_str(&toml::to_string(&node).unwrap()).unwrap();
        let r = DeviceRegistry::new();
        r.hydrate_manual_nodes(std::slice::from_ref(&node));
        assert_eq!(r.snapshot()[0].status, DeviceStatus::Offline);
        let replacement = arp("aa:bb:cc:dd:ee:04", &node.ip, "192.168.1.0/24");
        r.merge_manual_verified(
            &node,
            &replacement,
            "40:cd:3a:00:00:01",
            "2026-10-19T12:00:00Z",
            &proof_fence(),
        );
        let snapshot = r.snapshot();
        assert_eq!(snapshot.len(), 2);
        let pinned = snapshot
            .iter()
            .find(|r| r.mac == "aa:bb:cc:dd:ee:02")
            .unwrap();
        assert_eq!(pinned.status, DeviceStatus::OfflineDifferentDevice);
        assert_eq!(pinned.alias, "CAM");
        assert_eq!(
            snapshot
                .iter()
                .find(|r| r.mac == replacement.mac)
                .unwrap()
                .alias,
            ""
        );
        assert_eq!(node.expected_mac.as_deref(), Some("aa:bb:cc:dd:ee:02"));
    }

    #[test]
    fn learned_manual_and_cached_mac_casing_resolve_to_one_record() {
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[
            cached(
                "AA:BB:CC:DD:EE:02",
                "192.168.1.204",
                "192.168.1.0/24",
                vec![554],
                "CAM",
            ),
            cached(
                "aa:bb:cc:dd:ee:02",
                "192.168.1.204",
                "192.168.1.0/24",
                vec![554],
                "CAM",
            ),
        ]);
        let mut node = manual("192.168.1.204", "CAM");
        node.expected_mac = Some("aa:bb:cc:dd:ee:02".into());
        r.hydrate_manual_nodes(std::slice::from_ref(&node));
        assert_eq!(r.snapshot().len(), 1);
        r.merge_manual_verified(
            &node,
            &arp("aa:bb:cc:dd:ee:02", &node.ip, "192.168.1.0/24"),
            "40:cd:3a:00:00:01",
            "2026-10-19T12:00:00Z",
            &proof_fence(),
        );
        assert_eq!(r.snapshot().len(), 1);
        assert_eq!(holders(&r, "CAM"), 1);
        assert_eq!(r.snapshot()[0].status, DeviceStatus::Live);
    }

    #[test]
    fn manual_verification_rejects_stale_invalid_and_wrong_endpoint_proof() {
        let r = DeviceRegistry::new();
        let node = manual("192.168.1.204", "CAM");
        r.hydrate_manual_nodes(std::slice::from_ref(&node));
        let device = arp("aa:bb:cc:dd:ee:02", "192.168.1.204", "192.168.1.0/24");
        let retired = super::super::SweepFence::new(
            1,
            Arc::new(std::sync::atomic::AtomicU64::new(2)),
            Arc::new(AtomicBool::new(true)),
        );
        let before = r.snapshot();
        assert!(
            !r.merge_manual_verified(
                &node,
                &device,
                "40:cd:3a:00:00:01",
                "2026-10-19T12:00:00Z",
                &retired
            )
            .changed
        );
        assert!(
            !r.merge_manual_verified(
                &node,
                &device,
                "40:cd:3a:00:00:01",
                "invalid",
                &proof_fence()
            )
            .changed
        );
        let other = arp(&device.mac, "192.168.1.205", "192.168.1.0/24");
        assert!(
            !r.merge_manual_verified(
                &node,
                &other,
                "40:cd:3a:00:00:01",
                "2026-10-19T12:00:00Z",
                &proof_fence()
            )
            .changed
        );
        assert_eq!(r.snapshot(), before);
    }
}
