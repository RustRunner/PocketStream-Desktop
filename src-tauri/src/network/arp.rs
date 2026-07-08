use std::collections::HashMap;
use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};
use tokio::sync::Mutex;

use super::pktmon;
use crate::error::AppError;
use crate::network::device_registry::{DeviceListEmitter, DeviceRegistry};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpDevice {
    pub mac: String,
    pub ip: String,
    pub subnet: String,
    pub first_seen: String,
    pub last_seen: String,
}

pub struct ArpListenerHandle {
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

/// Monotonic count of ARP frames the capture backend has delivered and
/// parsed (incremented in [`on_arp_seen`], which only the capture
/// callback reaches — the OS ARP-table merge does not touch it). The
/// quiet-network watchdog compares this against a per-session baseline
/// to tell "capture is delivering payload events" from silence.
static ARP_FRAMES_SEEN: AtomicU64 = AtomicU64::new(0);

/// Largest missed-packet count the ring has reported in any callback —
/// a nonzero value means the callback fell behind at least once. Surfaced
/// in the degraded-discovery diagnostic; never resets (worst-seen).
static ARP_MISSED_MAX: AtomicU64 = AtomicU64::new(0);

/// Total ARP frames parsed by the capture backend so far this process.
pub fn frames_seen() -> u64 {
    ARP_FRAMES_SEEN.load(Ordering::Relaxed)
}

/// Worst missed-packet count the capture ring has reported.
pub fn missed_max() -> u64 {
    ARP_MISSED_MAX.load(Ordering::Relaxed)
}

impl ArpListenerHandle {
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Content-dedupe window: PktMon reports the same frame once per stack
/// component it traverses (distinct `PktGroupId` each — the id does not
/// group appearances), so one wire ARP arrives as several callbacks. The
/// registry merge is idempotent regardless, so this LRU only saves
/// spawn/lock traffic; it keys on frame content, never on component or
/// appearance order.
const DEDUPE_TTL: Duration = Duration::from_secs(2);
const DEDUPE_CAP: usize = 256;

struct DedupeLru {
    seen: HashMap<(u16, [u8; 6], [u8; 4]), Instant>,
}

impl DedupeLru {
    fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// True if this (op, sender_mac, sender_ip) hasn't been seen within
    /// the TTL. Records it and evicts expired entries.
    fn admit(&mut self, op: u16, mac: [u8; 6], ip: [u8; 4], now: Instant) -> bool {
        self.seen
            .retain(|_, &mut t| now.duration_since(t) < DEDUPE_TTL);
        let key = (op, mac, ip);
        if self.seen.contains_key(&key) {
            return false;
        }
        // ARP volume under the EtherType constraint is tiny; a hard cap
        // is a runaway backstop, not a working-set limit.
        if self.seen.len() >= DEDUPE_CAP {
            self.seen.clear();
        }
        self.seen.insert(key, now);
        true
    }
}

/// Everything the C data callback needs. Reached through the stream's
/// `user_context` pointer; lives (in an `Arc`) on the listener's
/// spawn_blocking thread for the whole session, so the pointer stays
/// valid until after `SetSessionActive(FALSE)` — no callback fires
/// afterward.
struct CallbackContext {
    own_mac: Option<[u8; 6]>,
    dedupe: StdMutex<DedupeLru>,
    runtime: tokio::runtime::Handle,
    devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    registry: Arc<DeviceRegistry>,
    emitter: Arc<DeviceListEmitter>,
    app_handle: tauri::AppHandle,
    /// Session fence: a live capture frame from a prior discovery session
    /// (or one still firing after a stop) drops itself before merging or
    /// emitting into the shared registry.
    fence: super::SweepFence,
    /// One-shot latches so the diagnostics don't spam per packet.
    missed_logged: AtomicBool,
    canary_logged: AtomicBool,
}

/// No-op event callback. The realtime stream signals lifecycle events
/// here; none need handling, but the spike ran with a non-null callback,
/// so keep one rather than passing null.
unsafe extern "system" fn event_cb(_ctx: *mut c_void, _info: *const c_void, _kind: u32) {}

/// Per-packet data callback. Runs on the API's stream thread — kept
/// minimal (parse + dedupe + marshal); no registry work here. A slow
/// callback drops packets, surfaced by the missed-packet counters.
unsafe extern "system" fn data_cb(ctx: *mut c_void, d: *const pktmon::StreamDataDescriptor) {
    if ctx.is_null() || d.is_null() {
        return;
    }
    let ctx = &*(ctx as *const CallbackContext);
    let desc = *d;
    if desc.data.is_null() {
        return;
    }
    let blob = std::slice::from_raw_parts(desc.data, desc.data_size as usize);

    let missed = desc
        .missed_packet_write_count
        .max(desc.missed_packet_read_count);
    if missed > 0 {
        ARP_MISSED_MAX.fetch_max(missed as u64, Ordering::Relaxed);
        if !ctx.missed_logged.swap(true, Ordering::Relaxed) {
            log::warn!(
                "PktMon ring reported drops (write={}, read={}) — capture callback may be too slow",
                desc.missed_packet_write_count,
                desc.missed_packet_read_count
            );
        }
    }

    // Metadata is only needed for the PacketType==7 fallback framing and
    // the layout canary; capture works without it (default to Ethernet II).
    let meta = pktmon::read_metadata(blob, desc.metadata_offset as usize);
    if let Some(m) = &meta {
        if !pktmon::metadata_plausible(m) && !ctx.canary_logged.swap(true, Ordering::Relaxed) {
            log::warn!(
                "PktMon metadata out of documented range — the pinned layout may have changed on this Windows build"
            );
        }
    }
    let packet_type = meta.map(|m| m.packet_type).unwrap_or(0);

    let po = desc.packet_offset as usize;
    let pl = desc.packet_length as usize;
    if pl == 0 || blob.len() < po + pl {
        return;
    }
    let frame = &blob[po..po + pl];

    let Some((op, mac, ip)) = extract_arp(frame, packet_type) else {
        return;
    };
    if ip == Ipv4Addr::new(0, 0, 0, 0) {
        return;
    }
    // Skip our own gratuitous ARP (emitted when we add a secondary IP);
    // otherwise it lands as a phantom peer that gets scanned against our
    // own IP and cached as a ghost node.
    if let Some(own) = ctx.own_mac {
        if mac == own {
            return;
        }
    }

    if let Ok(mut lru) = ctx.dedupe.lock() {
        if !lru.admit(op, mac, ip.octets(), Instant::now()) {
            return;
        }
    }

    // Fence stale-session frames: a callback from a prior listener (or one
    // still firing after a stop) must not merge or emit into the current
    // session's shared registry. Checked here, before the spawn, so a stale
    // frame costs nothing.
    if ctx.fence.is_stale() {
        return;
    }

    // Marshal onto the tokio runtime — the merge/emit tail is async
    // (tokio Mutex, registry, cache I/O) and must not run here.
    let devices = ctx.devices.clone();
    let registry = ctx.registry.clone();
    let emitter = ctx.emitter.clone();
    let app_handle = ctx.app_handle.clone();
    ctx.runtime.spawn(async move {
        on_arp_seen(ip, mac, devices, registry, emitter, app_handle).await;
    });
}

/// Merge one observed (ip, mac) into the legacy map and the canonical
/// registry, mirror same-IP cache evictions, and emit on first sight.
/// Extracted from the old listener loop unchanged so swapping the
/// capture backend doesn't disturb it.
async fn on_arp_seen(
    ip: Ipv4Addr,
    mac: [u8; 6],
    devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    registry: Arc<DeviceRegistry>,
    emitter: Arc<DeviceListEmitter>,
    app_handle: tauri::AppHandle,
) {
    // Payload-event liveness signal for the quiet-network watchdog.
    ARP_FRAMES_SEEN.fetch_add(1, Ordering::Relaxed);

    let ip_str = ip.to_string();
    let mac_str = format_mac(&mac);
    let octets = ip.octets();
    let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
    let now = chrono::Utc::now().to_rfc3339();

    let device = ArpDevice {
        mac: mac_str.clone(),
        ip: ip_str.clone(),
        subnet,
        first_seen: now.clone(),
        last_seen: now,
    };

    // Update the legacy map under the lock, then release it before any
    // disk I/O — the cache-file write below must NOT run while the
    // `devices` mutex is held, or it stalls the listener/merge during an
    // ARP burst (exactly the window M2's concurrent-write race worries
    // about). The legacy map is still mutated because the auto-adopt loop
    // iterates over it; can be retired once auto-adopt uses the registry.
    let is_new = {
        let mut map = devices.lock().await;
        let is_new = !map.contains_key(&mac_str);
        let entry = map.entry(mac_str.clone()).or_insert(device.clone());
        entry.last_seen = device.last_seen.clone();
        entry.ip = device.ip.clone();
        // Refresh the subnet too: a FLIR that first ARPs from APIPA then
        // re-ARPs from its real address must not keep the stale subnet
        // paired with the fresh IP, or adoption is keyed under the wrong
        // subnet.
        entry.subnet = device.subnet.clone();
        is_new
    };

    // Mirror into the canonical DeviceRegistry (its own lock) and evict
    // same-IP dupe cache rows — all outside the `devices` lock.
    let result = registry.merge_arp(&device);
    if result.changed {
        emitter.poke();
    }
    if !result.dropped_macs.is_empty() {
        let cfg: tauri::State<'_, crate::config::AppConfig> = app_handle.state();
        for dropped in &result.dropped_macs {
            if let Err(e) = cfg.remove_cached_device(dropped) {
                log::warn!(
                    "Failed to evict dupe cache row {} (same IP as {}): {}",
                    dropped,
                    device.mac,
                    e
                );
            }
        }
    }

    if is_new {
        log::info!("ARP: {} ({})", device.ip, device.mac);
        let _ = app_handle.emit("arp-device-discovered", &device);
    }
}

/// Start the PacketMonitor ARP listener. Signature preserved from the
/// pcap backend so `mod.rs` callers don't change.
///
/// `ethernet_ips` — the target adapter's IPv4 addresses. No longer used
/// to select a capture device (PacketMonitor captures unscoped, with the
/// in-driver EtherType constraint doing the filtering), kept for the
/// startup log and signature stability.
///
/// `own_mac` — the target adapter's own MAC; ARP frames sent by it are
/// skipped (see [`on_arp_seen`]'s phantom-peer note).
pub(crate) fn start_listener(
    devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    registry: Arc<DeviceRegistry>,
    emitter: Arc<DeviceListEmitter>,
    app_handle: tauri::AppHandle,
    ethernet_ips: Vec<Ipv4Addr>,
    own_mac: Option<[u8; 6]>,
    fence: super::SweepFence,
) -> Result<ArpListenerHandle, AppError> {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let runtime = tokio::runtime::Handle::current();

    log::info!(
        "Starting PacketMonitor ARP listener (adapter IPs: {:?})",
        ethernet_ips
    );

    tokio::task::spawn_blocking(move || {
        let ctx = Arc::new(CallbackContext {
            own_mac,
            dedupe: StdMutex::new(DedupeLru::new()),
            runtime: runtime.clone(),
            devices,
            registry,
            emitter,
            app_handle,
            fence,
            missed_logged: AtomicBool::new(false),
            canary_logged: AtomicBool::new(false),
        });

        let config = pktmon::RealtimeStreamConfiguration {
            user_context: Arc::as_ptr(&ctx) as *mut c_void,
            event_callback: Some(event_cb),
            data_callback: Some(data_cb),
            buffer_size_multiplier: 4,
            truncation_size: 128,
        };

        let session = match pktmon::CaptureSession::start("PocketStreamArpCapture", config) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("PacketMonitor: capture start failed: {}", e);
                return;
            }
        };
        log::info!("PacketMonitor: ARP capture active");

        // Block this thread until the shutdown flip. `changed()` is
        // async; run it on the captured handle (this is a blocking-pool
        // thread, so block_on is allowed). The ctx Arc stays alive here,
        // keeping the user_context pointer valid for every callback.
        if !*shutdown_rx.borrow() {
            runtime.block_on(async {
                let _ = shutdown_rx.changed().await;
            });
        }
        log::info!("PacketMonitor: shutting down capture");
        session.stop();
        drop(ctx);
    });

    Ok(ArpListenerHandle { shutdown_tx })
}

/// Parse a full Ethernet II frame carrying an ARP payload into
/// `(sender_ip, sender_mac)`. Byte-level contract unchanged from the
/// pcap era — the capture backend feeds it the same 42-byte frames.
fn parse_arp_packet(data: &[u8]) -> Option<(Ipv4Addr, [u8; 6])> {
    if data.len() < 42 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != 0x0806 {
        return None;
    }
    let (_, mac, ip) = parse_arp_header(&data[14..])?;
    Some((ip, mac))
}

/// Validate a 28-byte ARP header (Ethernet/IPv4 only) and return
/// `(opcode, sender_mac, sender_ip)`. Shared by the Ethernet II framing
/// and the PacketType==7 direct-ARP fallback.
fn parse_arp_header(arp: &[u8]) -> Option<(u16, [u8; 6], Ipv4Addr)> {
    if arp.len() < 28 {
        return None;
    }
    if u16::from_be_bytes([arp[0], arp[1]]) != 1
        || u16::from_be_bytes([arp[2], arp[3]]) != 0x0800
        || arp[4] != 6
        || arp[5] != 4
    {
        return None;
    }
    let op = u16::from_be_bytes([arp[6], arp[7]]);
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&arp[8..14]);
    let ip = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
    if mac == [0xff; 6] {
        return None;
    }
    Some((op, mac, ip))
}

/// Extract `(opcode, sender_mac, sender_ip)` from a captured frame.
/// PacketMonitor delivers Ethernet II framing in practice (the observed
/// S4 case); the `PacketType == 7` direct-ARP path is defensive — never
/// observed, but documented as possible.
fn extract_arp(frame: &[u8], packet_type: u16) -> Option<(u16, [u8; 6], Ipv4Addr)> {
    if frame.len() >= 42 && frame[12] == 0x08 && frame[13] == 0x06 {
        // Full validation via the documented Ethernet II parser; the
        // opcode sits at ARP-header offset 6 (frame offset 20).
        let (ip, mac) = parse_arp_packet(frame)?;
        let op = u16::from_be_bytes([frame[20], frame[21]]);
        return Some((op, mac, ip));
    }
    if packet_type == 7 && frame.len() >= 28 {
        return parse_arp_header(frame);
    }
    None
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Read the OS ARP table for a specific interface and return dynamic entries.
///
/// Supplements live capture: if a host is already in the OS ARP cache
/// (e.g. from a prior browser visit), the ping sweep won't generate a
/// new ARP request on the wire, so the capture listener never sees it.
///
/// `interface_ip` scopes the query to the interface that owns it (by
/// `InterfaceIndex`), preventing WiFi entries from leaking in.
///
/// Uses `Get-NetNeighbor` rather than `arp -a`: the cmdlet's JSON is
/// locale-invariant (the `State` field is numeric / an invariant enum
/// name), whereas `arp -a`'s "dynamic"/"static" column is localized —
/// on a German or French Windows the old parser matched nothing and
/// silently returned no neighbors.
pub async fn read_system_arp_table(interface_ip: &str) -> Vec<(Ipv4Addr, String)> {
    let script = format!(
        "$idx=(Get-NetIPAddress -IPAddress '{ip}' -AddressFamily IPv4 -ErrorAction SilentlyContinue \
         | Select-Object -First 1).InterfaceIndex; \
         if ($null -ne $idx) {{ Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex $idx \
         -ErrorAction SilentlyContinue | Select-Object IPAddress,LinkLayerAddress,State \
         | ConvertTo-Json -Compress }}",
        ip = interface_ip.replace('\'', "''"),
    );
    let stdout = match run_powershell(&script).await {
        Some(s) => s,
        None => return vec![],
    };
    let entries = parse_neighbors_json(&stdout);
    log::debug!("Neighbors for {}: {} entries", interface_ip, entries.len());
    entries
}

/// Run a PowerShell script, returning stdout on success (exit 0), or
/// None on spawn failure, non-zero exit, or timeout. Bounded so a hung
/// PowerShell can't wedge the caller.
async fn run_powershell(script: &str) -> Option<String> {
    let fut = super::async_cmd("powershell")
        .args(["-NoProfile", "-Command", script])
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(std::time::Duration::from_secs(10), fut).await {
        Ok(Ok(o)) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).to_string()),
        Ok(Ok(o)) => {
            log::warn!("Get-NetNeighbor exited {}", o.status.code().unwrap_or(-1));
            None
        }
        Ok(Err(e)) => {
            log::warn!("Get-NetNeighbor spawn failed: {}", e);
            None
        }
        Err(_) => {
            log::warn!("Get-NetNeighbor timed out");
            None
        }
    }
}

/// Parse `Get-NetNeighbor | ConvertTo-Json` output into dynamic
/// (IP, MAC) pairs. ConvertTo-Json emits a bare object for one row and
/// an array for many.
fn parse_neighbors_json(stdout: &str) -> Vec<(Ipv4Addr, String)> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return vec![];
    }
    let values: Vec<serde_json::Value> = if trimmed.starts_with('[') {
        serde_json::from_str(trimmed).unwrap_or_default()
    } else {
        serde_json::from_str::<serde_json::Value>(trimmed)
            .map(|v| vec![v])
            .unwrap_or_default()
    };

    values
        .iter()
        .filter(|v| neighbor_state_is_dynamic(&v["State"]))
        .filter_map(|v| {
            let ip = v["IPAddress"].as_str()?.parse::<Ipv4Addr>().ok()?;
            let mac = normalize_mac(v["LinkLayerAddress"].as_str()?)?;
            Some((ip, mac))
        })
        .collect()
}

/// True for the `NlNeighborState` values that mean "a resolved neighbor
/// with a real unicast MAC" — the locale-invariant equivalent of what
/// `arp -a` labelled "dynamic". Excludes 6=Permanent (static, which
/// covers multicast/broadcast rows — matching by MAC regex would newly
/// admit those) and 0=Unreachable / 1=Incomplete (no usable MAC).
/// Accepts either the numeric serialization or the invariant enum name.
fn neighbor_state_is_dynamic(state: &serde_json::Value) -> bool {
    if let Some(n) = state.as_u64() {
        return (2..=5).contains(&n);
    }
    if let Some(s) = state.as_str() {
        let s = s.to_ascii_lowercase();
        return matches!(s.as_str(), "probe" | "delay" | "stale" | "reachable");
    }
    false
}

/// Normalize a `Get-NetNeighbor` LinkLayerAddress (e.g. `AA-BB-CC-DD-EE-FF`)
/// to the codebase's colon-lowercase form, rejecting the empty /
/// broadcast / zeroed placeholders.
fn normalize_mac(raw: &str) -> Option<String> {
    let mac = raw.replace('-', ":").to_lowercase();
    if mac.is_empty() || mac == "ff:ff:ff:ff:ff:ff" || mac == "00:00:00:00:00:00" {
        return None;
    }
    Some(mac)
}

/// Resolve the MAC address currently bound to `target_ip` from the
/// Windows ARP cache. Pings the target first so the cache entry is fresh
/// (a stale entry could otherwise return the MAC of a *previous* device
/// at this IP, defeating the purpose of identity verification). Returns
/// None if the IP doesn't respond or no ARP entry exists.
///
/// Used by the cache-verify path: a successful port scan only proves
/// *something* answers at the IP — to claim a cached record is "still
/// live" we additionally need the MAC to match. Otherwise an unrelated
/// device that happens to have the same IP today will resurrect a stale
/// record as a false-positive Live.
pub async fn resolve_mac_for_ip(
    target_ip: Ipv4Addr,
    timeout: std::time::Duration,
) -> Result<Option<String>, AppError> {
    let timeout_ms = timeout.as_millis().to_string();
    let _ = super::async_cmd("ping")
        .args(["-n", "1", "-w", &timeout_ms, &target_ip.to_string()])
        .output()
        .await;

    // Get-NetNeighbor for the single target — locale-invariant, unlike
    // the old `arp -a` "dynamic" text match.
    let script = format!(
        "Get-NetNeighbor -AddressFamily IPv4 -IPAddress '{ip}' -ErrorAction SilentlyContinue \
         | Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Json -Compress",
        ip = target_ip
    );
    let stdout = run_powershell(&script)
        .await
        .ok_or_else(|| AppError::Network("Get-NetNeighbor failed".into()))?;

    Ok(parse_neighbors_json(&stdout)
        .into_iter()
        .find(|(ip, _)| *ip == target_ip)
        .map(|(_, mac)| mac))
}

/// Check if `target_ip` is in use by pinging it and checking the
/// neighbor table.
///
/// `source` is the ICMP source address (`ping -S`). Passing a scratch
/// address already bound on the target's subnet makes the probe
/// **on-link**: without it, when the host has no address on the target
/// subnet the OS has no on-link route, so the ping exits via the default
/// gateway (or fails), no neighbor entry is ever created, and every
/// candidate reports "free" — the pre-adoption blindness that let
/// auto-adopt assign a duplicate IP against field gear.
pub async fn send_arp_probe(
    target_ip: Ipv4Addr,
    source: Option<Ipv4Addr>,
    timeout: std::time::Duration,
) -> Result<bool, AppError> {
    let timeout_ms = timeout.as_millis().to_string();
    let target_str = target_ip.to_string();
    let source_str = source.map(|s| s.to_string());
    let mut ping_args = vec!["-n", "1", "-w", &timeout_ms];
    if let Some(ref src) = source_str {
        ping_args.push("-S");
        ping_args.push(src);
    }
    ping_args.push(&target_str);
    let _ = super::async_cmd("ping").args(&ping_args).output().await;

    let script = format!(
        "Get-NetNeighbor -AddressFamily IPv4 -IPAddress '{ip}' -ErrorAction SilentlyContinue \
         | Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Json -Compress",
        ip = target_ip
    );
    let stdout = run_powershell(&script)
        .await
        .ok_or_else(|| AppError::Network("Get-NetNeighbor failed".into()))?;

    Ok(!parse_neighbors_json(&stdout).is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Build a minimal valid ARP packet (42 bytes: 14 Ethernet + 28 ARP).
    fn make_arp_packet(sender_mac: [u8; 6], sender_ip: [u8; 4]) -> Vec<u8> {
        let mut pkt = vec![0u8; 42];
        // Destination MAC (6 bytes) + Source MAC (6 bytes) — left as zeros
        // Ethertype: ARP = 0x0806
        pkt[12] = 0x08;
        pkt[13] = 0x06;
        // ARP header starts at offset 14
        let arp = &mut pkt[14..];
        arp[0] = 0x00;
        arp[1] = 0x01; // Hardware type: Ethernet (1)
        arp[2] = 0x08;
        arp[3] = 0x00; // Protocol type: IPv4 (0x0800)
        arp[4] = 6; // Hardware address length
        arp[5] = 4; // Protocol address length
        arp[6] = 0x00;
        arp[7] = 0x02; // Opcode: Reply (2)
        arp[8..14].copy_from_slice(&sender_mac);
        arp[14..18].copy_from_slice(&sender_ip);
        pkt
    }

    #[test]
    fn parse_valid_arp_reply() {
        let pkt = make_arp_packet([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01], [192, 168, 1, 100]);
        let (ip, mac) = parse_arp_packet(&pkt).unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
    }

    #[test]
    fn parse_arp_different_subnet() {
        let pkt = make_arp_packet([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], [10, 0, 0, 42]);
        let (ip, mac) = parse_arp_packet(&pkt).unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 42));
        assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn parse_arp_high_octets() {
        let pkt = make_arp_packet([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54], [172, 16, 255, 254]);
        let (ip, _mac) = parse_arp_packet(&pkt).unwrap();
        assert_eq!(ip, Ipv4Addr::new(172, 16, 255, 254));
    }

    #[test]
    fn reject_packet_too_short() {
        assert!(parse_arp_packet(&[0u8; 41]).is_none());
    }

    #[test]
    fn reject_empty_packet() {
        assert!(parse_arp_packet(&[]).is_none());
    }

    #[test]
    fn reject_non_arp_ethertype() {
        let mut pkt = make_arp_packet([1; 6], [10, 0, 0, 1]);
        pkt[12] = 0x08;
        pkt[13] = 0x00; // IPv4 ethertype, not ARP
        assert!(parse_arp_packet(&pkt).is_none());
    }

    #[test]
    fn reject_non_ethernet_hardware_type() {
        let mut pkt = make_arp_packet([1; 6], [10, 0, 0, 1]);
        pkt[14] = 0x00;
        pkt[15] = 0x06; // Hardware type 6 (IEEE 802) instead of 1
        assert!(parse_arp_packet(&pkt).is_none());
    }

    #[test]
    fn reject_non_ipv4_protocol() {
        let mut pkt = make_arp_packet([1; 6], [10, 0, 0, 1]);
        pkt[16] = 0x86;
        pkt[17] = 0xDD; // IPv6 protocol type
        assert!(parse_arp_packet(&pkt).is_none());
    }

    #[test]
    fn reject_wrong_hardware_addr_len() {
        let mut pkt = make_arp_packet([1; 6], [10, 0, 0, 1]);
        pkt[18] = 8; // hw addr len 8 instead of 6
        assert!(parse_arp_packet(&pkt).is_none());
    }

    #[test]
    fn reject_wrong_protocol_addr_len() {
        let mut pkt = make_arp_packet([1; 6], [10, 0, 0, 1]);
        pkt[19] = 16; // proto addr len 16 instead of 4
        assert!(parse_arp_packet(&pkt).is_none());
    }

    #[test]
    fn reject_broadcast_mac() {
        let pkt = make_arp_packet([0xFF; 6], [192, 168, 1, 1]);
        assert!(parse_arp_packet(&pkt).is_none());
    }

    #[test]
    fn accept_exactly_42_bytes() {
        let pkt = make_arp_packet([0x01, 0x02, 0x03, 0x04, 0x05, 0x06], [1, 2, 3, 4]);
        assert_eq!(pkt.len(), 42);
        assert!(parse_arp_packet(&pkt).is_some());
    }

    #[test]
    fn accept_oversized_packet() {
        let mut pkt = make_arp_packet([0x01; 6], [192, 168, 0, 1]);
        pkt.extend_from_slice(&[0u8; 100]); // trailing data (padding)
        let (ip, _) = parse_arp_packet(&pkt).unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 0, 1));
    }

    // ── extract_arp / parse_arp_header (capture-backend feed) ───────

    /// Real S4-captured ARP request frame (Ethernet II, 42 bytes):
    /// gateway 192.168.12.1 asking, laptop AC-45-EF-38-F9-F5 sender.
    const S4_REQUEST: [u8; 42] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xAC, 0x45, 0xEF, 0x38, 0xF9, 0xF5, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xAC, 0x45, 0xEF, 0x38, 0xF9, 0xF5, 0xC0, 0xA8,
        0x0C, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xA8, 0x0C, 0x01,
    ];

    /// Real S4-captured ARP reply frame (Ethernet II, 42 bytes):
    /// gateway 192.168.12.1 / 64-67-72-20-06-A3 replying.
    const S4_REPLY: [u8; 42] = [
        0xAC, 0x45, 0xEF, 0x38, 0xF9, 0xF5, 0x64, 0x67, 0x72, 0x20, 0x06, 0xA3, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x64, 0x67, 0x72, 0x20, 0x06, 0xA3, 0xC0, 0xA8,
        0x0C, 0x01, 0xAC, 0x45, 0xEF, 0x38, 0xF9, 0xF5, 0xC0, 0xA8, 0x0C, 0x40,
    ];

    #[test]
    fn extract_arp_from_real_request_frame() {
        let (op, mac, ip) = extract_arp(&S4_REQUEST, 1).unwrap();
        assert_eq!(op, 1); // request
        assert_eq!(mac, [0xAC, 0x45, 0xEF, 0x38, 0xF9, 0xF5]);
        assert_eq!(ip, Ipv4Addr::new(192, 168, 12, 64));
    }

    #[test]
    fn extract_arp_from_real_reply_frame() {
        let (op, mac, ip) = extract_arp(&S4_REPLY, 1).unwrap();
        assert_eq!(op, 2); // reply
        assert_eq!(mac, [0x64, 0x67, 0x72, 0x20, 0x06, 0xA3]);
        assert_eq!(ip, Ipv4Addr::new(192, 168, 12, 1));
    }

    #[test]
    fn extract_arp_accepts_direct_header_when_packet_type_7() {
        // PacketType==7 payload starts at the ARP header (no Ethernet II
        // prefix). Defensive path — never observed in S4.
        let direct = &S4_REQUEST[14..];
        assert_eq!(direct.len(), 28);
        let (op, mac, ip) = extract_arp(direct, 7).unwrap();
        assert_eq!(op, 1);
        assert_eq!(mac, [0xAC, 0x45, 0xEF, 0x38, 0xF9, 0xF5]);
        assert_eq!(ip, Ipv4Addr::new(192, 168, 12, 64));
    }

    #[test]
    fn extract_arp_rejects_bare_header_without_type_7() {
        // Same 28-byte header but packet_type=1 (Ethernet II expected):
        // no 0x0806 at offset 12, so it must not parse.
        let direct = &S4_REQUEST[14..];
        assert!(extract_arp(direct, 1).is_none());
    }

    #[test]
    fn extract_arp_rejects_non_arp_frame() {
        let mut frame = S4_REQUEST;
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4, not ARP
        assert!(extract_arp(&frame, 1).is_none());
    }

    // ── DedupeLru ───────────────────────────────────────────────────

    #[test]
    fn dedupe_suppresses_repeat_within_ttl() {
        let mut lru = DedupeLru::new();
        let t0 = Instant::now();
        let mac = [0xAC, 0x45, 0xEF, 0x38, 0xF9, 0xF5];
        let ip = [192, 168, 12, 64];
        assert!(lru.admit(1, mac, ip, t0));
        // Same content again immediately — suppressed.
        assert!(!lru.admit(1, mac, ip, t0));
        // Different opcode is a different key.
        assert!(lru.admit(2, mac, ip, t0));
    }

    #[test]
    fn dedupe_readmits_after_ttl() {
        let mut lru = DedupeLru::new();
        let t0 = Instant::now();
        let mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let ip = [10, 0, 0, 5];
        assert!(lru.admit(1, mac, ip, t0));
        let later = t0 + DEDUPE_TTL + Duration::from_millis(1);
        assert!(lru.admit(1, mac, ip, later));
    }

    // ── format_mac ──────────────────────────────────────────────────

    #[test]
    fn format_mac_standard() {
        assert_eq!(
            format_mac(&[0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03]),
            "aa:bb:cc:01:02:03"
        );
    }

    #[test]
    fn format_mac_all_zeros() {
        assert_eq!(format_mac(&[0; 6]), "00:00:00:00:00:00");
    }

    #[test]
    fn format_mac_all_ff() {
        assert_eq!(format_mac(&[0xFF; 6]), "ff:ff:ff:ff:ff:ff");
    }

    // ── parse_neighbors_json ────────────────────────────────────────
    // Get-NetNeighbor JSON is locale-invariant, so unlike the old
    // arp -a parser these fixtures are the same on any Windows language.

    #[test]
    fn parse_neighbors_json_array_numeric_state() {
        // State: 5=Reachable, 4=Stale (both dynamic), 6=Permanent (static).
        let json = r#"[
            {"IPAddress":"192.168.1.1","LinkLayerAddress":"AA-BB-CC-DD-EE-01","State":5},
            {"IPAddress":"192.168.1.207","LinkLayerAddress":"aa-bb-cc-dd-ee-02","State":4},
            {"IPAddress":"192.168.1.255","LinkLayerAddress":"FF-FF-FF-FF-FF-FF","State":6}
        ]"#;
        let entries = parse_neighbors_json(json);
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0],
            (Ipv4Addr::new(192, 168, 1, 1), "aa:bb:cc:dd:ee:01".into())
        );
        assert_eq!(
            entries[1],
            (Ipv4Addr::new(192, 168, 1, 207), "aa:bb:cc:dd:ee:02".into())
        );
    }

    #[test]
    fn parse_neighbors_json_single_object() {
        // ConvertTo-Json emits a bare object for a single row.
        let json = r#"{"IPAddress":"10.0.0.5","LinkLayerAddress":"11-22-33-44-55-66","State":5}"#;
        let entries = parse_neighbors_json(json);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, "11:22:33:44:55:66");
    }

    #[test]
    fn parse_neighbors_json_accepts_enum_name_state() {
        // Defensive: if State serializes as the (invariant) enum name
        // rather than the number, we still classify it correctly.
        let json = r#"[
            {"IPAddress":"10.0.0.1","LinkLayerAddress":"AA-BB-CC-DD-EE-FF","State":"Reachable"},
            {"IPAddress":"10.0.0.2","LinkLayerAddress":"AA-BB-CC-DD-EE-01","State":"Permanent"}
        ]"#;
        let entries = parse_neighbors_json(json);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn parse_neighbors_json_excludes_permanent_and_incomplete() {
        // 6=Permanent (multicast/broadcast/static), 1=Incomplete (no MAC),
        // 0=Unreachable — none should appear.
        let json = r#"[
            {"IPAddress":"224.0.0.22","LinkLayerAddress":"01-00-5E-00-00-16","State":6},
            {"IPAddress":"192.168.1.50","LinkLayerAddress":"","State":1},
            {"IPAddress":"192.168.1.51","LinkLayerAddress":"AA-BB-CC-DD-EE-02","State":0}
        ]"#;
        assert!(parse_neighbors_json(json).is_empty());
    }

    #[test]
    fn parse_neighbors_json_skips_placeholder_macs() {
        let json = r#"[
            {"IPAddress":"192.168.1.255","LinkLayerAddress":"FF-FF-FF-FF-FF-FF","State":5},
            {"IPAddress":"192.168.1.50","LinkLayerAddress":"00-00-00-00-00-00","State":5}
        ]"#;
        assert!(parse_neighbors_json(json).is_empty());
    }

    #[test]
    fn parse_neighbors_json_empty_and_blank() {
        assert!(parse_neighbors_json("").is_empty());
        assert!(parse_neighbors_json("   \r\n ").is_empty());
    }
}
