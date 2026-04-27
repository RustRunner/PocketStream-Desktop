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

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::CachedDevice;
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

impl DeviceRegistry {
    pub fn new() -> Self {
        Self {
            devices: Mutex::new(HashMap::new()),
        }
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
    pub fn hydrate_from_cache(&self, cached: &[CachedDevice]) -> bool {
        let mut map = self.lock();
        if !map.is_empty() {
            return false;
        }
        for entry in cached {
            if entry.mac.is_empty() || entry.ip.is_empty() {
                continue;
            }
            map.insert(
                entry.mac.clone(),
                DeviceRecord {
                    mac: entry.mac.clone(),
                    ip: entry.ip.clone(),
                    subnet: entry.subnet.clone(),
                    open_ports: entry.open_ports.clone(),
                    alias: entry.alias.clone(),
                    status: DeviceStatus::CachedOnly,
                    first_seen: entry.last_seen.clone(),
                    last_seen: entry.last_seen.clone(),
                },
            );
        }
        true
    }

    /// Insert or refresh a record from a live ARP discovery. New entries
    /// land as `Live`. Existing entries get their ip/subnet/last_seen
    /// refreshed; status is promoted from CachedOnly → Live (since live
    /// ARP confirms the device is here now), but Verifying/Offline are
    /// left alone — the verify path owns those transitions.
    pub fn merge_arp(&self, device: &ArpDevice) -> bool {
        let mut map = self.lock();
        match map.get_mut(&device.mac) {
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
                        alias: String::new(),
                        status: DeviceStatus::Live,
                        first_seen: device.first_seen.clone(),
                        last_seen: device.last_seen.clone(),
                    },
                );
                true
            }
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
            if record.status != DeviceStatus::Live {
                record.status = DeviceStatus::Live;
                changed = true;
            }
        }
        changed
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
    fn merge_arp_inserts_new_record_as_live() {
        let r = DeviceRegistry::new();
        let changed = r.merge_arp(&arp("AA:BB:CC:DD:EE:01", "192.168.1.10", "192.168.1.0/24"));
        assert!(changed);
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
        assert!(r.merge_arp(&dev));
        assert!(!r.merge_arp(&dev), "second merge with identical data must be a no-op");
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

        let changed = r.merge_arp(&arp("AA:BB:CC:DD:EE:01", "192.168.1.10", "192.168.1.0/24"));
        assert!(changed, "promoting CachedOnly → Live counts as a change");
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
        assert!(!r.set_alias("192.168.1.10", "CAM"), "identical write is a no-op");
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
        let did_hydrate = r.hydrate_from_cache(&[cached(
            "FF:FF:FF:FF:FF:FF",
            "10.0.0.1",
            "10.0.0.0/24",
            vec![],
            "",
        )]);
        assert!(!did_hydrate, "hydrate is a one-shot — must skip if registry isn't empty");
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
}
