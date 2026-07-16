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
}

/// Unified device record. Replaces the old split between ARP map +
/// scan-result map + alias map + cache file rows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceRecord {
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

/// Result of a mutation that may also drop stale records (e.g. merge_arp
/// dedups records at the same IP with different MACs). `dropped_macs`
/// lets callers with access to the on-disk cache mirror the removal so
/// the cache file doesn't keep the orphan rows.
#[derive(Debug, Default, PartialEq)]
pub struct MergeResult {
    pub changed: bool,
    pub dropped_macs: Vec<String>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self {
            devices: Mutex::new(HashMap::new()),
        }
    }

    /// Drop every record. Used by `apply_mode_change` when the source
    /// of truth flips (e.g., Static-Auto → Static-Manual replaces the
    /// cache+ARP set with the user's pinned list). Returns true if
    /// anything was actually removed.
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
        });
        list
    }

    /// Hydrate from the on-disk cache. Records start as `CachedOnly` —
    /// a live ARP discovery flips them to `Live`, and the verify path
    /// flips them to `Verifying` then `Live` or `Offline`. No-op if
    /// the registry already has entries (cache load is one-shot).
    ///
    /// Dedups by IP: when the cache contains multiple rows at the same
    /// IP (different MACs left over from device replacement, firmware
    /// re-flash, etc.), keep the row with the newest `last_seen` and
    /// inherit its alias if the survivor's is empty. Dropped MACs are
    /// returned so the caller can remove them from the on-disk cache
    /// file too.
    pub fn hydrate_from_cache(&self, cached: &[CachedDevice]) -> MergeResult {
        let mut map = self.lock();
        if !map.is_empty() {
            return MergeResult::default();
        }

        // Group cached rows by IP, keep newest per IP, surface losers.
        let mut by_ip: HashMap<String, &CachedDevice> = HashMap::new();
        let mut dropped: Vec<String> = Vec::new();
        for entry in cached {
            // Drop rows whose IP isn't a valid IPv4 address (corrupted
            // cache, a hand-edited hostname): otherwise the string reaches
            // ping.exe's argv and triggers a DNS lookup / false dot.
            // APIPA (169.254.x.x) parses fine and is kept.
            if entry.mac.is_empty() || entry.ip.parse::<std::net::Ipv4Addr>().is_err() {
                continue;
            }
            match by_ip.get(&entry.ip) {
                Some(existing) if existing.last_seen >= entry.last_seen => {
                    dropped.push(entry.mac.clone());
                }
                Some(existing) => {
                    dropped.push(existing.mac.clone());
                    by_ip.insert(entry.ip.clone(), entry);
                }
                None => {
                    by_ip.insert(entry.ip.clone(), entry);
                }
            }
        }

        // Inherit aliases from dropped duplicates if the surviving row
        // is unnamed — the user's "this is my CAM" label should follow
        // the IP, not the (potentially-replaced) MAC.
        let mut inherited_alias_by_ip: HashMap<String, String> = HashMap::new();
        for entry in cached {
            if entry.alias.is_empty() {
                continue;
            }
            if dropped.contains(&entry.mac) {
                inherited_alias_by_ip
                    .entry(entry.ip.clone())
                    .or_insert_with(|| entry.alias.clone());
            }
        }

        for (_, entry) in by_ip {
            let alias = if entry.alias.is_empty() {
                inherited_alias_by_ip
                    .get(&entry.ip)
                    .cloned()
                    .unwrap_or_default()
            } else {
                entry.alias.clone()
            };
            map.insert(
                entry.mac.clone(),
                DeviceRecord {
                    mac: entry.mac.clone(),
                    ip: entry.ip.clone(),
                    subnet: entry.subnet.clone(),
                    open_ports: entry.open_ports.clone(),
                    alias,
                    status: DeviceStatus::CachedOnly,
                    first_seen: entry.last_seen.clone(),
                    last_seen: entry.last_seen.clone(),
                },
            );
        }

        MergeResult {
            changed: !map.is_empty() || !dropped.is_empty(),
            dropped_macs: dropped,
        }
    }

    /// Populate the registry from a list of user-pinned manual nodes.
    /// Used by `NetworkMode::StaticManual` to seed the Nodes panel
    /// without going through ARP discovery.
    ///
    /// Manual nodes don't have a real MAC at pin time — the user only
    /// types IP + alias — so the registry key uses a synthetic prefix
    /// `manual:<ip>`. This is intentionally not a valid MAC: any code
    /// path that parses MACs will reject it cleanly rather than mis-
    /// using the synthetic value. Replaces any existing record at the
    /// same key so a second hydration (e.g., user added a node) takes
    /// effect.
    pub fn hydrate_manual_nodes(&self, nodes: &[ManualNode]) -> bool {
        let mut map = self.lock();
        let mut changed = false;
        for node in nodes {
            let subnet = subnet_for(&node.ip);

            // If a record (manual or ARP-derived) already lives at this
            // IP, patch its alias / subnet in place rather than spawning
            // a duplicate. This is what lets a user pin an existing
            // discovered device by IP without ending up with two rows
            // for the same physical box in the Nodes panel.
            let existing_key = map
                .values()
                .find(|r| r.ip == node.ip)
                .map(|r| r.mac.clone());
            if let Some(key) = existing_key {
                if let Some(existing) = map.get_mut(&key) {
                    if existing.alias != node.alias || existing.subnet != subnet {
                        existing.alias = node.alias.clone();
                        existing.subnet = subnet;
                        changed = true;
                    }
                }
                continue;
            }

            // No record at this IP yet — insert the synthetic manual
            // entry. The pinger will flip its dot via the ping-result
            // event stream within seconds of hydration.
            let key = format!("manual:{}", node.ip);
            let now = chrono::Utc::now().to_rfc3339();
            map.insert(
                key.clone(),
                DeviceRecord {
                    mac: key,
                    ip: node.ip.clone(),
                    subnet,
                    open_ports: Vec::new(),
                    alias: node.alias.clone(),
                    status: DeviceStatus::Live,
                    first_seen: now.clone(),
                    last_seen: now,
                },
            );
            changed = true;
        }
        changed
    }

    /// Insert or refresh a record from a live ARP discovery. New entries
    /// land as `Live`. Existing entries get their ip/subnet/last_seen
    /// refreshed; status is promoted from CachedOnly → Live (since live
    /// ARP confirms the device is here now), but Verifying/Offline are
    /// left alone — the verify path owns those transitions.
    pub fn merge_arp(&self, device: &ArpDevice) -> MergeResult {
        let mut map = self.lock();

        // Collect other records at the same IP with a different MAC — these
        // are stale identities (device replaced, MAC randomization toggled,
        // firmware re-flash, etc.) that would otherwise appear as duplicate
        // rows in the UI and cause the IP-scoped `merge_scan_result` to mark
        // both Live on a single successful verify. Surface them so the caller
        // can drop them from the on-disk cache too.
        let stale_macs: Vec<String> = map
            .values()
            .filter(|r| r.ip == device.ip && r.mac != device.mac)
            .map(|r| r.mac.clone())
            .collect();

        let inherited_alias: Option<String> = stale_macs
            .iter()
            .filter_map(|mac| map.get(mac))
            .find_map(|r| {
                if r.alias.is_empty() {
                    None
                } else {
                    Some(r.alias.clone())
                }
            });

        for mac in &stale_macs {
            map.remove(mac);
        }

        let upsert_changed = match map.get_mut(&device.mac) {
            Some(existing) => {
                let mut changed = false;
                if existing.ip != device.ip {
                    existing.ip = device.ip.clone();
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
                if existing.status == DeviceStatus::CachedOnly {
                    existing.status = DeviceStatus::Live;
                    changed = true;
                }
                // Adopt the alias from a stale record at the same IP only
                // when the surviving record doesn't already have one.
                if existing.alias.is_empty() {
                    if let Some(alias) = inherited_alias {
                        existing.alias = alias;
                        changed = true;
                    }
                }
                changed
            }
            None => {
                map.insert(
                    device.mac.clone(),
                    DeviceRecord {
                        mac: device.mac.clone(),
                        ip: device.ip.clone(),
                        subnet: device.subnet.clone(),
                        open_ports: Vec::new(),
                        alias: inherited_alias.unwrap_or_default(),
                        status: DeviceStatus::Live,
                        first_seen: device.first_seen.clone(),
                        last_seen: device.last_seen.clone(),
                    },
                );
                true
            }
        };

        MergeResult {
            changed: upsert_changed || !stale_macs.is_empty(),
            dropped_macs: stale_macs,
        }
    }

    /// Apply the result of a successful port scan. Looks the device up by
    /// IP (scans don't carry MACs) and updates `open_ports` + flips
    /// `Verifying`/`CachedOnly` → `Live`. No-op if the IP isn't tracked
    /// — discovery has to land first.
    pub fn merge_scan_result(&self, ip: &str, open_ports: &[u16]) -> bool {
        let mut map = self.lock();
        let mut changed = false;
        for record in map.values_mut() {
            if record.ip != ip {
                continue;
            }
            if record.open_ports != open_ports {
                record.open_ports = open_ports.to_vec();
                changed = true;
            }
            // Promote to Live only on a non-empty port set. A zero-port
            // scan is not evidence a device is alive — promoting on it
            // would resurrect a dead device as Live (the eviction path
            // handles the zero-port case instead).
            if !open_ports.is_empty() && record.status != DeviceStatus::Live {
                record.status = DeviceStatus::Live;
                changed = true;
            }
        }
        changed
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

    /// Evict a phantom cached device: a non-`Live` record at `ip` whose
    /// targeted verify found no open ports and which the user hasn't
    /// pinned (see `is_user_pinned`: aliased entries like the labelled
    /// CAM/PTU, `manual:` nodes, and configured pins — the persisted
    /// stream target counts even without an alias). `Live` records
    /// (ARP-confirmed this session) are additionally never evicted —
    /// an eviction-specific liveness guard on top of identity. Returns
    /// the dropped MAC so the caller can remove the cache row.
    pub fn evict_phantom(&self, ip: &str, configured_pins: &HashSet<String>) -> Option<String> {
        let mut map = self.lock();
        let mac = map
            .iter()
            .find(|(key, r)| {
                r.ip == ip
                    && !is_user_pinned(key, &r.alias, &r.ip, configured_pins)
                    && matches!(
                        r.status,
                        DeviceStatus::CachedOnly | DeviceStatus::Offline | DeviceStatus::Verifying
                    )
            })
            .map(|(k, _)| k.clone())?;
        map.remove(&mac);
        Some(mac)
    }

    /// Set or clear an alias for the device with this IP. Empty string
    /// clears. No-op if the IP isn't tracked.
    pub fn set_alias(&self, ip: &str, alias: &str) -> bool {
        let mut map = self.lock();
        let mut changed = false;
        for record in map.values_mut() {
            if record.ip == ip && record.alias != alias {
                record.alias = alias.to_string();
                changed = true;
            }
        }
        changed
    }

    /// Set the status for the device with this MAC.
    pub fn set_status(&self, mac: &str, status: DeviceStatus) -> bool {
        let mut map = self.lock();
        match map.get_mut(mac) {
            Some(record) if record.status != status => {
                record.status = status;
                true
            }
            _ => false,
        }
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
        r.merge_scan_result("192.168.1.10", &[]);
        assert_eq!(r.snapshot()[0].status, DeviceStatus::CachedOnly);
        // A non-empty scan does promote.
        r.merge_scan_result("192.168.1.10", &[80]);
        assert_eq!(r.snapshot()[0].status, DeviceStatus::Live);
    }

    #[test]
    fn evict_phantom_removes_unaliased_cached_row() {
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[cached(
            "AA:BB:CC:DD:EE:01",
            "192.168.1.10",
            "192.168.1.0/24",
            vec![],
            "",
        )]);
        assert_eq!(
            r.evict_phantom("192.168.1.10", &HashSet::new()).as_deref(),
            Some("AA:BB:CC:DD:EE:01")
        );
        assert!(r.snapshot().is_empty());
    }

    #[test]
    fn evict_phantom_exempts_aliased_and_live() {
        // Aliased CAM/PTU are treated as fixed and never auto-removed.
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[cached(
            "AA:BB:CC:DD:EE:01",
            "192.168.1.10",
            "192.168.1.0/24",
            vec![],
            "CAM",
        )]);
        assert!(r.evict_phantom("192.168.1.10", &HashSet::new()).is_none());
        assert_eq!(r.snapshot().len(), 1);

        // A Live (ARP-confirmed) device is never evicted either.
        let r2 = DeviceRegistry::new();
        r2.merge_arp(&arp("AA:BB:CC:DD:EE:02", "192.168.1.11", "192.168.1.0/24"));
        assert!(r2.evict_phantom("192.168.1.11", &HashSet::new()).is_none());
        assert_eq!(r2.snapshot().len(), 1);
    }

    #[test]
    fn evict_phantom_exempts_configured_pins() {
        // A record with no alias whose IP is user-configured (the
        // persisted stream target here) is user intent — never evicted
        // even though nothing on the registry row itself marks it.
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[cached(
            "AA:BB:CC:DD:EE:01",
            "172.31.169.65",
            "172.31.169.0/24",
            vec![],
            "",
        )]);
        let mut settings = AppSettings::default();
        settings.stream.camera_ip = "172.31.169.65".into();
        let pins = configured_pins(&settings);
        assert!(r.evict_phantom("172.31.169.65", &pins).is_none());
        assert_eq!(r.snapshot().len(), 1);
    }

    #[test]
    fn configured_pins_collects_manual_nodes_and_stream_target() {
        let mut settings = AppSettings::default();
        settings.manual_nodes.push(ManualNode {
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
    fn merge_scan_result_populates_open_ports_and_flips_to_live() {
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

        let changed = r.merge_scan_result("192.168.1.10", &[80, 554]);
        assert!(changed);
        let snap = r.snapshot();
        assert_eq!(snap[0].open_ports, vec![80, 554]);
        assert_eq!(snap[0].status, DeviceStatus::Live);
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
        assert!(r.set_alias("192.168.1.10", "CAM"));
        assert_eq!(r.snapshot()[0].alias, "CAM");
        assert!(
            !r.set_alias("192.168.1.10", "CAM"),
            "identical write is a no-op"
        );
        assert!(r.set_alias("192.168.1.10", ""), "empty string clears");
        assert_eq!(r.snapshot()[0].alias, "");
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
    fn merge_arp_drops_stale_record_at_same_ip() {
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
        assert_eq!(result.dropped_macs, vec!["OLD:MAC".to_string()]);
        let snap = r.snapshot();
        assert_eq!(snap.len(), 1, "stale MAC must be dropped, not co-listed");
        assert_eq!(snap[0].mac, "NEW:MAC");
        assert_eq!(
            snap[0].alias, "PTU",
            "alias should follow the IP across MAC changes"
        );
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
    fn hydrate_dedups_same_ip_keeping_newest() {
        let r = DeviceRegistry::new();
        let older = CachedDevice {
            mac: "OLD:MAC".into(),
            ip: "192.168.1.202".into(),
            subnet: "192.168.1.0/24".into(),
            open_ports: vec![80],
            alias: "PTU".into(),
            last_seen: "2026-04-01T00:00:00Z".into(),
        };
        let newer = CachedDevice {
            mac: "NEW:MAC".into(),
            ip: "192.168.1.202".into(),
            subnet: "192.168.1.0/24".into(),
            open_ports: vec![80],
            alias: "".into(),
            last_seen: "2026-05-01T00:00:00Z".into(),
        };
        let result = r.hydrate_from_cache(&[older, newer]);

        assert!(result.changed);
        assert_eq!(result.dropped_macs, vec!["OLD:MAC".to_string()]);
        let snap = r.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].mac, "NEW:MAC");
        assert_eq!(
            snap[0].alias, "PTU",
            "alias inherits from the dropped duplicate when survivor is unnamed"
        );
    }

    // ── hydrate_manual_nodes ────────────────────────────────────────

    fn manual(ip: &str, alias: &str) -> ManualNode {
        ManualNode {
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
}
