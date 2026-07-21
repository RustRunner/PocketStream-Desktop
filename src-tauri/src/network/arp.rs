use std::collections::{HashMap, HashSet};
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

/// Handle to a live capture session.
///
/// Drop-safety: dropping the handle drops `shutdown_tx`; the blocking
/// capture thread's `changed()` then errors, `session.stop()` runs, and
/// the callback context is released — a dropped handle can never leak a
/// live fixed-name capture session. [`ArpListenerHandle::stop_into_join`]
/// is the deliberate path; the drop path is the safety net.
pub struct ArpListenerHandle {
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// The spawn_blocking capture thread. A blocking task cannot be
    /// aborted, so teardown must either bounded-join this or park it in
    /// the prior-capture guard — never abandon it while a new session
    /// start is possible (the session name is fixed).
    join: tokio::task::JoinHandle<()>,
    counters: Arc<SessionCounters>,
}

/// Monotonic count of ARP frames the capture backend has delivered and
/// parsed. Incremented synchronously in the data callback the moment a
/// frame passes the sender gate — before the dedupe window, the session
/// fence, and the task bound — so it cannot under-count during a flood
/// or a slow registry. Cumulative across sessions; the watchdog samples
/// the per-session [`SessionCounters`] instead.
static ARP_FRAMES_SEEN: AtomicU64 = AtomicU64::new(0);

/// Largest missed-packet count the ring has reported in any callback —
/// a nonzero value means the callback fell behind at least once. Surfaced
/// in the degraded-discovery diagnostic; never resets (worst-seen).
static ARP_MISSED_MAX: AtomicU64 = AtomicU64::new(0);

/// One-shot latch so a caught data-callback panic logs once per session
/// rather than once per packet.
static DATA_CB_PANIC_LOGGED: AtomicBool = AtomicBool::new(false);

/// Count of ARP frames dropped because the in-flight on_arp_seen task bound
/// was saturated (a distinct-tuple flood or a slow registry). Never resets.
static ARP_TASKS_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Count of ARP frames dropped because the sender IP is on a subnet owned
/// exclusively by a non-Ethernet interface (WiFi/VPN). The capture backend
/// is unscoped, so wireless ARP (the WiFi gateway and other wireless hosts)
/// reaches the callback; discovery is wired-Ethernet only, so these are
/// filtered before they can become nodes. Never resets.
static ARP_NONETH_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Count of ARP frames dropped because the sender IP is one of the host's
/// own addresses. The unscoped capture sees this host's own ARP traffic
/// from every adapter — e.g. the WiFi NIC refreshing its gateway entry —
/// and when a non-wired adapter shares the wired port's subnet, the
/// subnet filter above cannot catch it. The host never lists itself as a
/// node. Never resets.
static ARP_SELF_IP_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Total ARP frames dropped due to the callback-task bound this session.
/// A diagnostic companion to [`frames_seen`] / [`missed_max`].
pub fn tasks_dropped() -> u64 {
    ARP_TASKS_DROPPED.load(Ordering::Relaxed)
}

/// Total ARP frames dropped because the sender IP is on a non-Ethernet
/// (WiFi/VPN) subnet — filtered out to keep discovery wired-Ethernet only.
pub fn noneth_dropped() -> u64 {
    ARP_NONETH_DROPPED.load(Ordering::Relaxed)
}

/// Total ARP frames dropped because the sender IP belongs to this host —
/// the host never appears in its own node list.
pub fn self_ip_dropped() -> u64 {
    ARP_SELF_IP_DROPPED.load(Ordering::Relaxed)
}

/// Total ARP frames parsed by the capture backend so far this process.
pub fn frames_seen() -> u64 {
    ARP_FRAMES_SEEN.load(Ordering::Relaxed)
}

/// Worst missed-packet count the capture ring has reported.
pub fn missed_max() -> u64 {
    ARP_MISSED_MAX.load(Ordering::Relaxed)
}

/// Verdict over one watchdog checkpoint window, derived from counter
/// deltas sampled at the window edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureHealth {
    /// Payload frames arrived — the inbound path is delivering.
    Healthy,
    /// No payload, but the host's own frames were delivered: the session
    /// is alive yet deaf to inbound traffic.
    RxDead,
    /// Nothing was delivered in either direction. A down or idle wire
    /// looks exactly like this — nothing transmitted, nothing to hear —
    /// so the watchdog holds and re-baselines instead of burning a
    /// restart against a wire that cannot answer.
    Quiet,
    /// Nothing delivered although the wire should be answering. Never
    /// produced by [`capture_health`] — counters alone cannot tell a
    /// dead session from a dead wire — only synthesized when a quiet
    /// hold expires while the adapter still reports the link up.
    FullyDead,
}

/// Classify a checkpoint window. Pure so the decision is unit-testable
/// without constructing any capture state.
pub(crate) fn capture_health(payload_delta: u64, self_delta: u64) -> CaptureHealth {
    if payload_delta > 0 {
        CaptureHealth::Healthy
    } else if self_delta > 0 {
        CaptureHealth::RxDead
    } else {
        CaptureHealth::Quiet
    }
}

/// Per-session counters for the two signals the health verdict needs.
///
/// The process-global counters cannot isolate a capture-only restart: it
/// keeps the same discovery generation, so already-spawned callbacks from
/// a torn-down session still pass the fence and keep incrementing the
/// globals — a deaf replacement session could look healthy at its
/// checkpoint. Each listener start gets its own instance, shared between
/// the callback context and the returned handle; health checks sample
/// deltas through the current handle only.
#[derive(Debug, Default)]
pub(crate) struct SessionCounters {
    frames_seen: AtomicU64,
    self_ip_dropped: AtomicU64,
}

/// A point-in-time read of one session's counters, for delta math across
/// a checkpoint window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CounterSnapshot {
    pub frames_seen: u64,
    pub self_ip_dropped: u64,
}

impl SessionCounters {
    pub(crate) fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            frames_seen: self.frames_seen.load(Ordering::Relaxed),
            self_ip_dropped: self.self_ip_dropped.load(Ordering::Relaxed),
        }
    }

    fn note_self_ip_dropped(&self) {
        self.self_ip_dropped.fetch_add(1, Ordering::Relaxed);
    }
}

/// Synchronous accept-point bookkeeping, called by the data callback the
/// moment a frame passes the sender gate — before the dedupe window, the
/// session fence, and the task bound — so the liveness signal never
/// depends on Tokio scheduling or the flood bound. Registry merging stays
/// in the spawned task; only the counting lives here.
fn record_accepted_frame(counters: &SessionCounters) {
    counters.frames_seen.fetch_add(1, Ordering::Relaxed);
    ARP_FRAMES_SEEN.fetch_add(1, Ordering::Relaxed);
}

/// One observation the capture-restart ladder reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttemptEvent {
    /// Checkpoint verdict for a session that confirmed activation.
    Verdict(CaptureHealth),
    /// The session never confirmed activation within the bound; its
    /// still-live thread has been parked in the prior-capture guard.
    ActivationTimedOut,
    /// The capture thread died without reporting (panic before the send).
    ActivationChannelClosed,
    /// The session start reported failure, or a restart's listener start
    /// failed outright.
    StartFailed,
    /// A torn-down session's thread did not exit within the join bound.
    JoinTimedOut,
    /// Discovery is stopping; the ladder must yield immediately.
    ShutdownSignalled,
}

/// What the ladder does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LadderAction {
    /// Healthy — the ladder ends without emitting anything.
    Done,
    /// Quiet wire: take a fresh baseline and re-run the checkpoint
    /// window without consuming a restart attempt.
    Rebaseline,
    /// Tear down the current session and restart at the given scope mode.
    Restart(pktmon::CaptureMode),
    /// Give up loudly: degraded event, then the bounded recovery poll.
    Exhaust,
    /// A stop won; end silently.
    Abort,
}

/// Restarts one discovery session's ladder may spend: a scoped retry,
/// then a forced-unscoped escalation. Re-armed only by a discovery
/// restart, so a genuinely dead backend cannot flap capture forever.
pub(crate) const LADDER_MAX_RESTARTS: u32 = 2;

/// The ladder's single decision point — every observation routes through
/// here. Pure so sequencing, the per-session cap, fault handling, and
/// shutdown priority are unit-testable without any capture state.
pub(crate) fn next_ladder_step(event: AttemptEvent, restarts_used: u32) -> LadderAction {
    match event {
        AttemptEvent::ShutdownSignalled => LadderAction::Abort,
        AttemptEvent::Verdict(CaptureHealth::Healthy) => LadderAction::Done,
        AttemptEvent::Verdict(CaptureHealth::Quiet) => LadderAction::Rebaseline,
        AttemptEvent::Verdict(_) => {
            if restarts_used == 0 {
                LadderAction::Restart(pktmon::CaptureMode::PreferScoped)
            } else if restarts_used < LADDER_MAX_RESTARTS {
                LadderAction::Restart(pktmon::CaptureMode::ForcedUnscoped)
            } else {
                LadderAction::Exhaust
            }
        }
        // Lifecycle faults never retry: a failed start, an unconfirmed
        // start, or an unjoinable teardown mean the backend is not
        // behaving predictably — degrade loudly instead of flapping.
        AttemptEvent::ActivationTimedOut
        | AttemptEvent::ActivationChannelClosed
        | AttemptEvent::StartFailed
        | AttemptEvent::JoinTimedOut => LadderAction::Exhaust,
    }
}

/// Consecutive quiet checkpoint windows the watchdog holds through
/// before the hold itself needs explaining (~5 min at the 10 s window).
/// Bounds the rebaseline loop so a silent session is never watched
/// forever.
pub(crate) const MAX_QUIET_WINDOWS: u32 = 30;

/// What an expired quiet hold means, given the adapter's link state at
/// that moment (`None` = the state could not be read). Counters alone
/// cannot distinguish a dead wire from a session delivering nothing on
/// a live link, so the link is the tie-breaker: up means the silence is
/// the session's fault — resume the ladder with a fully-dead verdict;
/// down or unknown means the hold was correct — end the watch quietly
/// (the next discovery start re-arms it).
pub(crate) fn quiet_exhaust_event(link_up: Option<bool>) -> Option<CaptureHealth> {
    match link_up {
        Some(true) => Some(CaptureHealth::FullyDead),
        _ => None,
    }
}

/// Resolves once the blocking capture thread has run session start: the
/// achieved scope on success, or the start error. A receiver that drops
/// without listening loses nothing — the send is fire-and-forget.
pub(crate) type ActivationRx = tokio::sync::oneshot::Receiver<Result<pktmon::ScopeOutcome, String>>;

/// Bound on waiting for a session to confirm activation. Generous —
/// activation is normally near-instant; a session that cannot confirm
/// within this is treated as wedged and its thread stays parked.
pub(crate) const CAPTURE_ACTIVATION_TIMEOUT: Duration = Duration::from_secs(15);

/// Bound on joining a prior capture thread before starting a new session.
pub(crate) const CAPTURE_JOIN_TIMEOUT: Duration = Duration::from_secs(10);

/// JoinHandles of capture threads that were told to stop but have not yet
/// been observed dead. The session name is fixed, so a second session must
/// never start while one of these may still hold the old one open — every
/// capture start drains this first. A Vec because a stop can park a handle
/// while an earlier parked one is still running out.
///
/// Callers of [`drain_prior_capture`] are serialized structurally, not by
/// this lock: the initial start runs under the discovery lifecycle mutex,
/// and any restart path is cooperatively stopped before a new start
/// reaches the guard.
pub(crate) type PriorCaptureJoins = Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>;

/// Join every parked capture thread within [`CAPTURE_JOIN_TIMEOUT`].
/// `Ok` ⇒ all prior threads exited (the fixed session name is free);
/// `Err` ⇒ at least one still lives — it is re-parked and the caller must
/// not start a capture session.
pub(crate) async fn drain_prior_capture(slot: &PriorCaptureJoins) -> Result<(), AppError> {
    drain_prior_capture_within(slot, CAPTURE_JOIN_TIMEOUT).await
}

async fn drain_prior_capture_within(
    slot: &PriorCaptureJoins,
    bound: Duration,
) -> Result<(), AppError> {
    // Join in place, holding the guard's lock: if this future is dropped
    // mid-drain (a watchdog stop's abort fallback can do that), every
    // unfinished handle is still parked in the guard — nothing detaches.
    let mut guard = slot.lock().await;
    if guard.is_empty() {
        return Ok(());
    }
    let deadline = tokio::time::Instant::now() + bound;
    let mut i = 0;
    while i < guard.len() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        // `&mut JoinHandle` is pollable, so a timeout does not consume
        // the handle — an unfinished thread stays parked, never lost.
        let exited = tokio::time::timeout(remaining, &mut guard[i]).await.is_ok();
        if exited {
            // A panic also counts — either way the thread is gone.
            guard.remove(i);
        } else {
            i += 1;
        }
    }
    if guard.is_empty() {
        Ok(())
    } else {
        Err(AppError::Network(format!(
            "{} previous capture thread(s) have not exited — refusing to start a second fixed-name capture session",
            guard.len()
        )))
    }
}

impl ArpListenerHandle {
    /// Signal shutdown and surrender the blocking thread's JoinHandle so
    /// the caller can bounded-join it or park it in the prior-capture
    /// guard. The shutdown is already sent when this returns; dropping
    /// the returned handle does not un-stop the thread.
    pub fn stop_into_join(self) -> tokio::task::JoinHandle<()> {
        let _ = self.shutdown_tx.send(true);
        self.join
    }

    /// The session's own counters — the only valid sampling source for
    /// health checks against this session.
    pub(crate) fn counters(&self) -> Arc<SessionCounters> {
        self.counters.clone()
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

/// Verdict for a captured ARP sender: admit it as a peer, or drop it.
/// When several drop conditions apply at once the precedence is
/// non-wired subnet, then self IP, then own MAC — all three drop the
/// frame, so the order only decides which counter and log fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SenderVerdict {
    Accept,
    /// Sender is on a subnet owned exclusively by a non-wired local
    /// interface (WiFi/VPN/virtual) — not a wired peer.
    DropNonWiredSubnet,
    /// Sender IP is currently assigned to this host (any adapter). The
    /// host never lists itself; this catches our own traffic on a subnet
    /// the wired port shares with a non-wired adapter, where the subnet
    /// filter is structurally blind.
    DropSelfIp,
    /// Sender MAC is the wired adapter's own — our gratuitous ARP.
    DropOwnMac,
}

/// Pure sender gate for the capture callback: scope discovery to the
/// wired port's peers and reject the host's own traffic. An empty
/// `local_ips` or `excluded` disables that check (fail-open). A wired
/// camera — on the Ethernet port's subnet or a foreign/APIPA subnet —
/// matches none of the drop conditions. Module-level and pure so it is
/// unit-testable without constructing any capture state.
fn classify_sender(
    ip: Ipv4Addr,
    mac: [u8; 6],
    own_mac: Option<[u8; 6]>,
    local_ips: &HashSet<Ipv4Addr>,
    excluded: &[ipnetwork::Ipv4Network],
) -> SenderVerdict {
    if excluded.iter().any(|net| net.contains(ip)) {
        return SenderVerdict::DropNonWiredSubnet;
    }
    if local_ips.contains(&ip) {
        return SenderVerdict::DropSelfIp;
    }
    if own_mac == Some(mac) {
        return SenderVerdict::DropOwnMac;
    }
    SenderVerdict::Accept
}

/// Everything the C data callback needs. Reached through the stream's
/// `user_context` pointer; lives (in an `Arc`) on the listener's
/// spawn_blocking thread for the whole session, so the pointer stays
/// valid until after `SetSessionActive(FALSE)` — no callback fires
/// afterward.
struct CallbackContext {
    own_mac: Option<[u8; 6]>,
    /// Every IPv4 address currently assigned to any local adapter, shared
    /// with the discovery loop that refreshes it as addresses change
    /// (DHCP renew, WiFi roam). A frame sent from one of these is the
    /// host itself, never a peer. Locked briefly on the capture thread —
    /// same discipline as `dedupe`; lock failure fails open.
    local_ips: Arc<StdMutex<HashSet<Ipv4Addr>>>,
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
    /// Bounds concurrent on_arp_seen tasks so a distinct-tuple ARP flood
    /// can't spawn unbounded workers that starve discovery.
    arp_task_sem: Arc<tokio::sync::Semaphore>,
    /// One-shot latches so the diagnostics don't spam per packet.
    missed_logged: AtomicBool,
    canary_logged: AtomicBool,
    /// One-shot latch for the task-bound-reached (flood) warning.
    flood_logged: AtomicBool,
    /// One-shot latch for the "filtering non-Ethernet subnet" notice.
    noneth_logged: AtomicBool,
    /// One-shot latch for the "filtering our own IP" notice.
    selfip_logged: AtomicBool,
    /// Subnets owned exclusively by non-Ethernet interfaces (WiFi/VPN). An
    /// ARP whose sender IP falls in one of these is dropped, so only the
    /// wired Ethernet port's peers become nodes. Empty ⇒ no filtering
    /// (interface enumeration failed, or there were no such subnets).
    /// Shared with the manager, which refreshes it at every discovery
    /// start; read under a brief per-frame lock, poison fails open.
    excluded_subnets: Arc<StdMutex<Vec<ipnetwork::Ipv4Network>>>,
    /// This session's liveness counters, shared with the returned handle.
    counters: Arc<SessionCounters>,
}

/// No-op event callback. The realtime stream signals lifecycle events
/// here; none need handling, but the spike ran with a non-null callback,
/// so keep one rather than passing null.
unsafe extern "system" fn event_cb(_ctx: *mut c_void, _info: *const c_void, _kind: u32) {}

/// Maximum plausible frame-buffer size from a single PacketMonitor
/// descriptor. Real Ethernet frames are ~1.5 KB (jumbo ~9 KB); 64 KiB is a
/// generous ceiling that rejects an implausibly large `data_size` before it
/// reaches `from_raw_parts`. This bounds blast radius — it cannot prove the
/// pointer is valid for a below-cap length.
const MAX_DESCRIPTOR_BYTES: u32 = 64 * 1024;

/// True if a descriptor's `data_size` is plausible: non-zero and within the
/// blast-radius cap.
fn data_size_ok(data_size: u32) -> bool {
    data_size != 0 && data_size <= MAX_DESCRIPTOR_BYTES
}

/// Validate a packet's (offset, length) against the buffer length,
/// overflow-safe. Returns the in-bounds `[start, end)` range, or None if the
/// length is zero, offset+length overflows, or the end runs past the buffer.
/// The overflow guard is only load-bearing on a 32-bit build (unreachable on
/// the shipped 64-bit target, where the u32 fields widen well within usize);
/// it stays as cheap defense.
fn checked_packet_range(
    blob_len: usize,
    packet_offset: usize,
    packet_length: usize,
) -> Option<(usize, usize)> {
    if packet_length == 0 {
        return None;
    }
    let end = packet_offset.checked_add(packet_length)?;
    if end > blob_len {
        return None;
    }
    Some((packet_offset, end))
}

/// Max concurrent `on_arp_seen` tasks. Mirrors the ping-sweep semaphore
/// (32): a distinct-tuple ARP flood bypasses the identical-tuple dedupe, and
/// each task blocking-locks the registry across an O(n log n) snapshot, so an
/// unbounded spawn would starve discovery under a storm.
const MAX_INFLIGHT_ARP_TASKS: usize = 32;

/// Reserve a slot for an on_arp_seen task without blocking (the FFI callback
/// thread must never block). `Some(permit)` to hold for the task's lifetime,
/// or `None` when the bound is already saturated.
fn try_admit_arp_task(
    sem: &Arc<tokio::sync::Semaphore>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    sem.clone().try_acquire_owned().ok()
}

/// Per-packet data callback (the extern "C" boundary). Wraps the real work
/// in `catch_unwind`: a panic unwinding across `extern "system"` aborts the
/// process, so catch it, log once per session, and return. `AssertUnwindSafe`
/// is sound here — the only shared state a mid-parse panic can leave
/// inconsistent is the dedupe `StdMutex`, which poisons and then self-
/// disables for the rest of the session (the `if let Ok(lru)` below skips a
/// poisoned lock). `catch_unwind` guards against panics introduced by future
/// edits; it cannot intercept a segfault from a malformed descriptor pointer
/// (that is not an unwind) — the `data_size` cap only bounds that blast
/// radius.
unsafe extern "system" fn data_cb(ctx: *mut c_void, d: *const pktmon::StreamDataDescriptor) {
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        data_cb_inner(ctx, d);
    }));
    if caught.is_err() && !DATA_CB_PANIC_LOGGED.swap(true, Ordering::Relaxed) {
        log::error!(
            "PacketMonitor data callback panicked — suppressed to avoid an \
             FFI-boundary process abort; capture continues"
        );
    }
}

/// The real per-packet parse. Runs on the API's stream thread — kept minimal
/// (parse + dedupe + marshal); no registry work here. A slow callback drops
/// packets, surfaced by the missed-packet counters.
unsafe fn data_cb_inner(ctx: *mut c_void, d: *const pktmon::StreamDataDescriptor) {
    if ctx.is_null() || d.is_null() {
        return;
    }
    let ctx = &*(ctx as *const CallbackContext);
    let desc = *d;
    if desc.data.is_null() {
        return;
    }
    // Descriptor sanity before from_raw_parts: reject a zero or implausibly
    // large data_size. This bounds the blast radius of a malformed
    // descriptor but does NOT prove the pointer is valid for a below-cap
    // length — residual trust in the OS descriptor contract remains.
    if !data_size_ok(desc.data_size) {
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
    let Some((frame_start, frame_end)) = checked_packet_range(blob.len(), po, pl) else {
        return;
    };
    let frame = &blob[frame_start..frame_end];

    let Some((op, mac, ip)) = extract_arp(frame, packet_type) else {
        return;
    };
    if ip == Ipv4Addr::new(0, 0, 0, 0) {
        return;
    }
    // Gate discovery to the wired Ethernet port's peers. The capture
    // backend is unscoped (only the in-driver EtherType=ARP constraint
    // applies), so ARP from the WiFi side — the gateway, other wireless
    // hosts, and this host's own WiFi NIC — reaches this callback and
    // would otherwise become phantom nodes. A wired camera, including one
    // still on its factory/APIPA subnet awaiting adoption, matches none
    // of the drop conditions. A poisoned local-IP lock fails open (frame
    // admitted) — same tolerance as the dedupe lock below.
    // Snapshot the exclusion set first (brief lock; poison fails open to
    // "no filtering", the same tolerance as the local-IP set) so the two
    // locks are never held together.
    let excluded: Vec<ipnetwork::Ipv4Network> = ctx
        .excluded_subnets
        .lock()
        .map(|v| v.clone())
        .unwrap_or_default();
    let verdict = match ctx.local_ips.lock() {
        Ok(local) => classify_sender(ip, mac, ctx.own_mac, &local, &excluded),
        Err(_) => classify_sender(ip, mac, ctx.own_mac, &HashSet::new(), &excluded),
    };
    match verdict {
        SenderVerdict::Accept => {}
        SenderVerdict::DropNonWiredSubnet => {
            ARP_NONETH_DROPPED.fetch_add(1, Ordering::Relaxed);
            if !ctx.noneth_logged.swap(true, Ordering::Relaxed) {
                log::info!(
                    "Filtering ARP {} on a non-Ethernet subnet out of discovery (packet_type={})",
                    ip,
                    packet_type
                );
            }
            return;
        }
        SenderVerdict::DropSelfIp => {
            ARP_SELF_IP_DROPPED.fetch_add(1, Ordering::Relaxed);
            ctx.counters.note_self_ip_dropped();
            if !ctx.selfip_logged.swap(true, Ordering::Relaxed) {
                log::info!(
                    "Filtering ARP from our own IP {} out of discovery — the host never lists itself",
                    ip
                );
            }
            return;
        }
        // Our own gratuitous ARP (emitted when we add a secondary IP);
        // it would otherwise land as a phantom peer that gets scanned
        // against our own IP and cached as a ghost node.
        SenderVerdict::DropOwnMac => return,
    }

    // Liveness is recorded here, at parse-accept — a deduped or fenced
    // frame still proves the inbound path delivers.
    record_accepted_frame(&ctx.counters);

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

    // Bound in-flight on_arp_seen tasks: a distinct-tuple ARP flood bypasses
    // the identical-tuple dedupe, and each task blocking-locks the registry
    // across an O(n log n) snapshot. Reserve a slot without blocking (this is
    // the FFI thread); if the bound is saturated, drop the frame — ARP is
    // best-effort and the OS ARP-table sweep backfills — and count it so a
    // storm is visible in diagnostics.
    let permit = match try_admit_arp_task(&ctx.arp_task_sem) {
        Some(p) => p,
        None => {
            ARP_TASKS_DROPPED.fetch_add(1, Ordering::Relaxed);
            if !ctx.flood_logged.swap(true, Ordering::Relaxed) {
                log::warn!(
                    "ARP callback task bound ({}) reached — dropping frames (flood or slow registry); the OS ARP-table sweep backfills",
                    MAX_INFLIGHT_ARP_TASKS
                );
            }
            return;
        }
    };

    // Marshal onto the tokio runtime — the merge/emit tail is async
    // (tokio Mutex, registry, cache I/O) and must not run here.
    let devices = ctx.devices.clone();
    let registry = ctx.registry.clone();
    let emitter = ctx.emitter.clone();
    let app_handle = ctx.app_handle.clone();
    ctx.runtime.spawn(async move {
        // Hold the permit for the task's lifetime; dropping it on completion
        // frees the slot for the next admitted frame.
        let _permit = permit;
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

    // Positive-liveness stamp for the adoption lifecycle: an accepted
    // frame is proof a device exists on the sender's subnet. Cheap
    // no-op unless that subnet is adopted.
    {
        let manager: tauri::State<'_, crate::network::NetworkManager> = app_handle.state();
        manager.note_positive_liveness(&app_handle, ip).await;
    }

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

/// Everything a capture listener start needs. Bundled so a restart path
/// can hold a clone and start an identical session later.
#[derive(Clone)]
pub(crate) struct ListenerParams {
    pub devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    pub registry: Arc<DeviceRegistry>,
    pub emitter: Arc<DeviceListEmitter>,
    pub app_handle: tauri::AppHandle,
    /// Every IPv4 address currently assigned to any local adapter, shared
    /// with the discovery loop that refreshes it as addresses change. A
    /// captured ARP sent from one of these is the host itself and is
    /// dropped — the host never lists itself as a peer.
    pub local_ips: Arc<StdMutex<HashSet<Ipv4Addr>>>,
    /// The target adapter's own MAC; ARP frames sent by it are skipped
    /// (see [`on_arp_seen`]'s phantom-peer note).
    pub own_mac: Option<[u8; 6]>,
    pub fence: super::SweepFence,
    /// Subnets owned exclusively by non-Ethernet interfaces; a captured
    /// ARP whose sender IP is in one is dropped. Shared with the
    /// manager, which refreshes it at every discovery start — the
    /// callback reads it per frame, so a listener retained across
    /// sessions picks up new exclusions without re-attaching.
    pub excluded_subnets: Arc<StdMutex<Vec<ipnetwork::Ipv4Network>>>,
    /// The selected wired adapter's capture identity.
    pub scope: pktmon::CaptureScope,
}

impl ListenerParams {
    /// Clone with a different fence. The capture listener runs under
    /// the manager's capture-lifecycle fence while sweeps carry the
    /// discovery-session fence; the bundles are otherwise identical, so
    /// the swap lives here.
    pub(crate) fn with_fence(&self, fence: super::SweepFence) -> Self {
        Self {
            fence,
            ..self.clone()
        }
    }
}

/// Start the PacketMonitor ARP listener. The capture session is scoped
/// at attach time to the selected wired adapter's data source (with an
/// unscoped fresh session as the fail-open fallback), and the in-driver
/// EtherType constraint keeps it ARP-only. The per-frame filters below
/// stay active in both modes as defense-in-depth — they are the only
/// scoping when the fallback is in effect.
///
/// The first await drains the prior-capture guard: the session name is
/// fixed, so no new session may start while a previous capture thread
/// may still hold it. The returned [`ActivationRx`] resolves once the
/// blocking thread has actually run the session start.
pub(crate) async fn start_listener(
    params: ListenerParams,
    mode: pktmon::CaptureMode,
    prior: &PriorCaptureJoins,
) -> Result<(ArpListenerHandle, ActivationRx), AppError> {
    drain_prior_capture(prior).await?;

    let ListenerParams {
        devices,
        registry,
        emitter,
        app_handle,
        local_ips,
        own_mac,
        fence,
        excluded_subnets,
        scope,
    } = params;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let (activation_tx, activation_rx) = tokio::sync::oneshot::channel();
    let counters = Arc::new(SessionCounters::default());
    let counters_for_ctx = counters.clone();
    let runtime = tokio::runtime::Handle::current();

    {
        let snapshot: Vec<Ipv4Addr> = local_ips
            .lock()
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        log::info!(
            "Starting PacketMonitor ARP listener (self-filtering local IPs: {:?})",
            snapshot
        );
    }

    let join = tokio::task::spawn_blocking(move || {
        let ctx = Arc::new(CallbackContext {
            own_mac,
            local_ips,
            dedupe: StdMutex::new(DedupeLru::new()),
            runtime: runtime.clone(),
            devices,
            registry,
            emitter,
            app_handle,
            fence,
            arp_task_sem: Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_ARP_TASKS)),
            missed_logged: AtomicBool::new(false),
            canary_logged: AtomicBool::new(false),
            flood_logged: AtomicBool::new(false),
            noneth_logged: AtomicBool::new(false),
            selfip_logged: AtomicBool::new(false),
            excluded_subnets,
            counters: counters_for_ctx,
        });

        let config = pktmon::RealtimeStreamConfiguration {
            user_context: Arc::as_ptr(&ctx) as *mut c_void,
            event_callback: Some(event_cb),
            data_callback: Some(data_cb),
            buffer_size_multiplier: 4,
            truncation_size: 128,
        };

        let session = match pktmon::CaptureSession::start(
            "PocketStreamArpCapture",
            config,
            &scope,
            mode,
        ) {
            Ok((s, outcome)) => {
                match &outcome {
                    pktmon::ScopeOutcome::SelectedInterface => {
                        log::info!(
                            "PacketMonitor: ARP capture active (scope=selected-interface, adapter='{}')",
                            scope.display_name
                        );
                    }
                    pktmon::ScopeOutcome::UnscopedFallback { reason } => {
                        log::warn!(
                            "PacketMonitor: ARP capture active (scope=unscoped-fallback, adapter='{}'): {}",
                            scope.display_name,
                            reason
                        );
                    }
                }
                let _ = activation_tx.send(Ok(outcome));
                s
            }
            Err(e) => {
                log::warn!("PacketMonitor: capture start failed: {}", e);
                let _ = activation_tx.send(Err(e));
                return;
            }
        };

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

    Ok((
        ArpListenerHandle {
            shutdown_tx,
            join,
            counters,
        },
        activation_rx,
    ))
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

/// Force a fresh on-wire ARP resolution of `target`, pinned to the
/// adapter that owns `scratch` (the caller's temporary probe address).
///
/// Two steps, neither of which parses localized OS text:
/// 1. Flush the target's neighbor entry, scoped to the adapter — so a
///    Stale/Delay/Probe leftover cannot masquerade as a fresh answer.
///    Flush failure fails closed.
/// 2. `SendARP` (IP Helper) with the scratch as the source: it transmits
///    a real ARP request and returns the responder's MAC directly.
///    Because step 1 emptied the cache entry, any MAC returned is fresh
///    on-wire evidence by construction — and being pure ARP, devices
///    that drop ICMP still answer. Runs on the blocking pool relying on
///    the call's own internal retry bound (a few seconds);
///    `spawn_blocking` cannot be aborted, so no abort wrapper is
///    layered on top — the caller budgets for the duration instead.
///
/// `Ok(Some(mac))` — colon-lowercase MAC of the fresh responder;
/// `Ok(None)` — no response; `Err` — the resolution could not be
/// attempted (flush failed, task lost).
pub(crate) async fn fresh_resolve_mac(
    target: Ipv4Addr,
    scratch: Ipv4Addr,
) -> Result<Option<String>, AppError> {
    flush_neighbor(target, scratch).await?;

    #[cfg(target_os = "windows")]
    {
        tokio::task::spawn_blocking(move || send_arp_blocking(target, scratch))
            .await
            .map_err(|e| AppError::Network(format!("SendARP task failed to join: {}", e)))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(AppError::Network(
            "fresh ARP resolution is Windows-only".into(),
        ))
    }
}

/// Remove the target's neighbor-cache entry on the adapter owning
/// `scratch`. Success is signalled by our own sentinel on stdout, never
/// by parsing cmdlet output (which is localized). A missing sentinel —
/// no adapter owns the scratch, cmdlet failure, timeout — is an error:
/// the caller must fail closed rather than trust a possibly-stale cache.
async fn flush_neighbor(target: Ipv4Addr, scratch: Ipv4Addr) -> Result<(), AppError> {
    let script = format!(
        "$idx=(Get-NetIPAddress -IPAddress '{scratch}' -AddressFamily IPv4 -ErrorAction SilentlyContinue \
         | Select-Object -First 1).InterfaceIndex; \
         if ($null -ne $idx) {{ Remove-NetNeighbor -InterfaceIndex $idx -IPAddress '{target}' \
         -Confirm:$false -ErrorAction SilentlyContinue; Write-Output 'flushed' }}"
    );
    match run_powershell(&script).await {
        Some(out) if out.contains("flushed") => Ok(()),
        _ => Err(AppError::Network(format!(
            "could not flush the neighbor entry for {} on the adapter owning {}",
            target, scratch
        ))),
    }
}

/// Blocking `SendARP` call (IP Helper — kernel-provided FFI, no
/// Packet.dll involvement). `IPAddr` is a u32 holding the address bytes
/// in network order in memory; reinterpreting the octets native-endian
/// produces exactly that layout on either endianness.
#[cfg(target_os = "windows")]
fn send_arp_blocking(target: Ipv4Addr, scratch: Ipv4Addr) -> Option<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::SendARP;
    let dest = u32::from_ne_bytes(target.octets());
    let src = u32::from_ne_bytes(scratch.octets());
    let mut mac = [0u8; 8];
    let mut len: u32 = mac.len() as u32;
    let rc = unsafe { SendARP(dest, src, mac.as_mut_ptr() as *mut _, &mut len) };
    if rc == 0 && len == 6 {
        Some(format_mac(&[
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        ]))
    } else {
        None
    }
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
pub(crate) fn normalize_mac(raw: &str) -> Option<String> {
    let mac = raw.replace('-', ":").to_lowercase();
    if mac.is_empty() || mac == "ff:ff:ff:ff:ff:ff" || mac == "00:00:00:00:00:00" {
        return None;
    }
    Some(mac)
}

/// Resolve the MAC address currently bound to `target_ip`, wired-bound:
/// the refreshing ping is sourced from `source` (`ping -S`, routing out
/// the adapter that owns it) and the neighbor lookup is scoped to that
/// adapter's `InterfaceIndex`. A device that answers over a different
/// interface — a WiFi gateway on a subnet the wired port also numbers —
/// is invisible here by construction and cannot MAC-verify as a wired
/// device.
///
/// `source == None` means no wired source IP exists for the target's
/// subnet; verification fails immediately (`Ok(None)`) rather than
/// probing unbound, because an unbound ping routes via the default
/// gateway (possibly WiFi) — the exact path this binding closes. The
/// policy lives here, in the probing function, so no caller can bypass
/// it.
///
/// Used by the cache-verify path: a successful port scan only proves
/// *something* answers at the IP — to claim a cached record is "still
/// live" we additionally need the MAC to match. Otherwise an unrelated
/// device that happens to have the same IP today will resurrect a stale
/// record as a false-positive Live.
pub async fn resolve_mac_for_ip(
    target_ip: Ipv4Addr,
    source: Option<Ipv4Addr>,
    timeout: std::time::Duration,
) -> Result<Option<String>, AppError> {
    let Some(source) = source else {
        log::debug!(
            "MAC verify for {}: no wired source IP for its subnet — verification fails",
            target_ip
        );
        return Ok(None);
    };

    let timeout_ms = timeout.as_millis().to_string();
    let source_str = source.to_string();
    let _ = super::async_cmd("ping")
        .args([
            "-n",
            "1",
            "-w",
            &timeout_ms,
            "-S",
            &source_str,
            &target_ip.to_string(),
        ])
        .output()
        .await;

    // Get-NetNeighbor scoped to the interface that owns the source IP
    // (same InterfaceIndex pattern as `read_system_arp_table`), for the
    // single target — locale-invariant, unlike the old `arp -a`
    // "dynamic" text match. A null $idx yields no output ⇒ no MAC ⇒
    // verification fails closed.
    let script = format!(
        "$idx=(Get-NetIPAddress -IPAddress '{src}' -AddressFamily IPv4 -ErrorAction SilentlyContinue \
         | Select-Object -First 1).InterfaceIndex; \
         if ($null -ne $idx) {{ Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex $idx \
         -IPAddress '{ip}' -ErrorAction SilentlyContinue \
         | Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Json -Compress }}",
        src = source,
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

    #[test]
    fn capture_health_verdict_table() {
        use CaptureHealth::*;
        // Payload delivered — healthy regardless of self noise.
        assert_eq!(capture_health(5, 100), Healthy);
        // A single frame landing exactly at the window edge still counts.
        assert_eq!(capture_health(1, 0), Healthy);
        // Alive (own sweep frames delivered) but deaf to inbound.
        assert_eq!(capture_health(0, 7447), RxDead);
        assert_eq!(capture_health(0, 1), RxDead);
        // Nothing delivered in either direction — a quiet or dead wire,
        // never immediately a dead session.
        assert_eq!(capture_health(0, 0), Quiet);
    }

    #[test]
    fn ladder_sequences_scoped_then_unscoped_then_exhausts() {
        use AttemptEvent::Verdict;
        assert_eq!(
            next_ladder_step(Verdict(CaptureHealth::RxDead), 0),
            LadderAction::Restart(pktmon::CaptureMode::PreferScoped)
        );
        assert_eq!(
            next_ladder_step(Verdict(CaptureHealth::RxDead), 1),
            LadderAction::Restart(pktmon::CaptureMode::ForcedUnscoped)
        );
        assert_eq!(
            next_ladder_step(Verdict(CaptureHealth::RxDead), 2),
            LadderAction::Exhaust
        );
        // A fully-dead session (synthesized at quiet exhaustion on a
        // live link) climbs the same ladder.
        assert_eq!(
            next_ladder_step(Verdict(CaptureHealth::FullyDead), 0),
            LadderAction::Restart(pktmon::CaptureMode::PreferScoped)
        );
        assert_eq!(
            next_ladder_step(Verdict(CaptureHealth::FullyDead), 1),
            LadderAction::Restart(pktmon::CaptureMode::ForcedUnscoped)
        );
        assert_eq!(
            next_ladder_step(Verdict(CaptureHealth::FullyDead), 2),
            LadderAction::Exhaust
        );
    }

    #[test]
    fn ladder_quiet_rebaselines_at_any_depth() {
        // A quiet wire never consumes a restart attempt, no matter how
        // many the session has already spent.
        for used in 0..=LADDER_MAX_RESTARTS {
            assert_eq!(
                next_ladder_step(AttemptEvent::Verdict(CaptureHealth::Quiet), used),
                LadderAction::Rebaseline
            );
        }
    }

    #[test]
    fn quiet_exhaust_resumes_ladder_only_on_a_live_link() {
        // Link up: the silence is the session's fault, not the wire's.
        assert_eq!(
            quiet_exhaust_event(Some(true)),
            Some(CaptureHealth::FullyDead)
        );
        // Link down: the hold was correct — end the watch quietly.
        assert_eq!(quiet_exhaust_event(Some(false)), None);
        // Unreadable state: never degrade loudly on a probe fault.
        assert_eq!(quiet_exhaust_event(None), None);
    }

    #[test]
    fn ladder_healthy_is_done_at_any_depth() {
        for used in 0..=LADDER_MAX_RESTARTS {
            assert_eq!(
                next_ladder_step(AttemptEvent::Verdict(CaptureHealth::Healthy), used),
                LadderAction::Done
            );
        }
    }

    #[test]
    fn ladder_faults_exhaust_at_any_depth_without_restarting() {
        // Every lifecycle fault ends the ladder — no overlap between a
        // fault and a fresh restart attempt is ever possible.
        for event in [
            AttemptEvent::ActivationTimedOut,
            AttemptEvent::ActivationChannelClosed,
            AttemptEvent::StartFailed,
            AttemptEvent::JoinTimedOut,
        ] {
            for used in 0..=LADDER_MAX_RESTARTS {
                assert_eq!(next_ladder_step(event, used), LadderAction::Exhaust);
            }
        }
    }

    #[test]
    fn ladder_shutdown_wins_at_any_depth() {
        // A stop beats even a would-be restart or exhaustion: the ladder
        // yields silently, emitting nothing.
        for used in 0..=LADDER_MAX_RESTARTS {
            assert_eq!(
                next_ladder_step(AttemptEvent::ShutdownSignalled, used),
                LadderAction::Abort
            );
        }
    }

    #[test]
    fn session_counters_isolated_across_instances() {
        // The sampling seam of a capture restart: late callbacks bound to
        // a torn-down session's counters must not satisfy a checkpoint
        // that samples the replacement session's counters.
        let old_session = SessionCounters::default();
        let new_session = SessionCounters::default();
        record_accepted_frame(&old_session);
        record_accepted_frame(&old_session);
        old_session.note_self_ip_dropped();
        let stale = old_session.snapshot();
        let fresh = new_session.snapshot();
        assert_eq!((stale.frames_seen, stale.self_ip_dropped), (2, 1));
        assert_eq!((fresh.frames_seen, fresh.self_ip_dropped), (0, 0));
    }

    #[test]
    fn accepted_frame_counts_even_when_task_bound_saturated() {
        // A frame the parser accepts must register as liveness even when
        // the on_arp_seen task bound would drop it.
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let _held = try_admit_arp_task(&sem).expect("first admit");
        assert!(try_admit_arp_task(&sem).is_none());
        let counters = SessionCounters::default();
        record_accepted_frame(&counters);
        assert_eq!(counters.snapshot().frames_seen, 1);
    }

    #[tokio::test]
    async fn drain_prior_capture_empty_is_ok() {
        let slot: PriorCaptureJoins = Arc::new(Mutex::new(Vec::new()));
        assert!(drain_prior_capture(&slot).await.is_ok());
    }

    #[tokio::test]
    async fn drain_prior_capture_joins_exited_thread() {
        let slot: PriorCaptureJoins = Arc::new(Mutex::new(Vec::new()));
        slot.lock().await.push(tokio::task::spawn_blocking(|| {}));
        assert!(drain_prior_capture(&slot).await.is_ok());
        assert!(slot.lock().await.is_empty());
    }

    #[tokio::test]
    async fn drain_prior_capture_reparks_stuck_thread_then_recovers() {
        let slot: PriorCaptureJoins = Arc::new(Mutex::new(Vec::new()));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        slot.lock().await.push(tokio::task::spawn_blocking(move || {
            let _ = release_rx.recv();
        }));
        // Stuck thread: the bounded join must fail without losing the
        // handle, so no capture start can proceed while it lives.
        let res = drain_prior_capture_within(&slot, Duration::from_millis(100)).await;
        assert!(res.is_err());
        assert_eq!(slot.lock().await.len(), 1);
        // Once the thread exits, the next drain frees the session name.
        release_tx.send(()).expect("release stuck thread");
        assert!(drain_prior_capture(&slot).await.is_ok());
        assert!(slot.lock().await.is_empty());
    }

    #[test]
    fn checked_range_rejects_zero_length() {
        assert_eq!(checked_packet_range(100, 0, 0), None);
    }

    #[test]
    fn checked_range_rejects_overflow() {
        assert_eq!(checked_packet_range(100, usize::MAX, 1), None);
    }

    #[test]
    fn checked_range_rejects_end_past_buffer() {
        assert_eq!(checked_packet_range(100, 50, 60), None);
    }

    #[test]
    fn checked_range_accepts_valid() {
        assert_eq!(checked_packet_range(100, 14, 42), Some((14, 56)));
    }

    #[test]
    fn data_size_cap_rejects_zero_and_oversized() {
        assert!(!data_size_ok(0));
        assert!(!data_size_ok(MAX_DESCRIPTOR_BYTES + 1));
        assert!(data_size_ok(1500));
        assert!(data_size_ok(MAX_DESCRIPTOR_BYTES));
    }

    #[test]
    fn arp_task_admission_respects_bound() {
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        let p1 = try_admit_arp_task(&sem);
        let p2 = try_admit_arp_task(&sem);
        assert!(p1.is_some() && p2.is_some());
        // Bound reached — the next frame is refused (dropped) rather than
        // spawning an unbounded worker.
        assert!(try_admit_arp_task(&sem).is_none());
        // Releasing a permit frees a slot for the next admitted frame.
        drop(p1);
        assert!(try_admit_arp_task(&sem).is_some());
    }

    #[tokio::test]
    async fn resolve_mac_without_source_returns_none() {
        // No wired source ⇒ verification fails immediately, in the
        // probing function itself — no ping, no neighbor query, so no
        // unbound path a caller could accidentally re-open.
        let result = resolve_mac_for_ip(
            Ipv4Addr::new(192, 168, 1, 1),
            None,
            std::time::Duration::from_millis(10),
        )
        .await
        .unwrap();
        assert_eq!(result, None);
    }

    // ── classify_sender ─────────────────────────────────────────────
    //
    // Reference topology: the wired port holds a static 192.168.1.101/24
    // (to reach a fixed-IP device at 192.168.1.202) while WiFi holds DHCP
    // 192.168.1.204/24 — both adapters own 192.168.1.0/24, so the shared
    // subnet is deliberately absent from the excluded set and only the
    // self-IP / own-MAC checks can reject the host's own WiFi traffic.

    fn ipv4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn local_set(ips: &[&str]) -> HashSet<Ipv4Addr> {
        ips.iter().map(|s| ipv4(s)).collect()
    }

    const WIRED_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const OTHER_MAC: [u8; 6] = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

    #[test]
    fn sender_own_wifi_ip_on_shared_subnet_dropped_as_self() {
        // Our own WiFi NIC ARPing on the shared subnet: wrong MAC for the
        // own-MAC check, subnet not excludable — the self-IP check is the
        // only thing standing between this frame and a phantom node.
        let local = local_set(&["192.168.1.101", "192.168.1.204"]);
        assert_eq!(
            classify_sender(
                ipv4("192.168.1.204"),
                OTHER_MAC,
                Some(WIRED_MAC),
                &local,
                &[]
            ),
            SenderVerdict::DropSelfIp
        );
    }

    #[test]
    fn sender_own_mac_dropped() {
        // Our gratuitous ARP for a just-bound secondary IP: the IP may not
        // be in the local set yet (set refresh races the bind), so the MAC
        // check must catch it on its own.
        let local = local_set(&["192.168.1.101"]);
        assert_eq!(
            classify_sender(
                ipv4("10.13.248.102"),
                WIRED_MAC,
                Some(WIRED_MAC),
                &local,
                &[]
            ),
            SenderVerdict::DropOwnMac
        );
    }

    #[test]
    fn sender_on_excluded_subnet_dropped() {
        let excluded = vec!["192.168.12.0/24".parse().unwrap()];
        assert_eq!(
            classify_sender(
                ipv4("192.168.12.1"),
                OTHER_MAC,
                Some(WIRED_MAC),
                &local_set(&["192.168.1.101"]),
                &excluded
            ),
            SenderVerdict::DropNonWiredSubnet
        );
    }

    #[test]
    fn wired_peers_accepted_beside_local_ips_on_same_subnet() {
        // A fixed-IP wired device sharing the /24 with two of our own
        // addresses must never be rejected, and neither may a camera on a
        // foreign adopted subnet.
        let local = local_set(&["192.168.1.101", "192.168.1.204"]);
        assert_eq!(
            classify_sender(
                ipv4("192.168.1.202"),
                OTHER_MAC,
                Some(WIRED_MAC),
                &local,
                &[]
            ),
            SenderVerdict::Accept
        );
        assert_eq!(
            classify_sender(
                ipv4("10.194.200.24"),
                OTHER_MAC,
                Some(WIRED_MAC),
                &local,
                &[]
            ),
            SenderVerdict::Accept
        );
    }

    #[test]
    fn empty_sets_fail_open() {
        // Enumeration failure yields empty sets; the filter must admit
        // everything rather than blind discovery.
        assert_eq!(
            classify_sender(ipv4("192.168.1.204"), OTHER_MAC, None, &HashSet::new(), &[]),
            SenderVerdict::Accept
        );
    }

    #[test]
    fn excluded_subnet_takes_precedence_over_self_ip() {
        // An IP that is both ours and on an excluded subnet counts as a
        // non-wired drop — pins which counter/log fires.
        let excluded = vec!["192.168.12.0/24".parse().unwrap()];
        assert_eq!(
            classify_sender(
                ipv4("192.168.12.103"),
                OTHER_MAC,
                Some(WIRED_MAC),
                &local_set(&["192.168.12.103"]),
                &excluded
            ),
            SenderVerdict::DropNonWiredSubnet
        );
    }

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
