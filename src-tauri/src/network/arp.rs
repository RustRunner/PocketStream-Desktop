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

const CANDIDATE_TTL: Duration = Duration::from_secs(30);
const MAX_CANDIDATES: usize = 1024;
type CandidateKey = (u32, [u8; 6], Ipv4Addr, [u8; 6]);

/// Read by S5a's verifier; never serialized or used as presence evidence.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct Candidate {
    pub interface_index: u32,
    pub adapter_mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub observed_at: Instant,
}

/// Transient observations, never registry records or cache rows.
#[derive(Default)]
pub(crate) struct CandidateSet {
    entries: StdMutex<HashMap<CandidateKey, Instant>>,
}

impl CandidateSet {
    #[allow(dead_code)] // S5a consumes the dormant queue.
    pub(crate) fn snapshot(&self, now: Instant) -> Vec<Candidate> {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.retain(|_, seen| now.saturating_duration_since(*seen) < CANDIDATE_TTL);
        entries
            .iter()
            .map(|((index, adapter, ip, mac), observed_at)| Candidate {
                interface_index: *index,
                adapter_mac: *adapter,
                ip: *ip,
                mac: *mac,
                observed_at: *observed_at,
            })
            .collect()
    }
    pub(crate) fn count(&self, now: Instant) -> usize {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.retain(|_, seen| now.saturating_duration_since(*seen) < CANDIDATE_TTL);
        entries.len()
    }

    pub(crate) fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }
}

#[derive(Clone)]
pub(crate) struct CandidateIngress {
    pub(crate) store: Arc<CandidateSet>,
    pub(crate) interface_index: u32,
    pub(crate) adapter_mac: [u8; 6],
}

impl CandidateIngress {
    pub(crate) fn observe(
        &self,
        ip: Ipv4Addr,
        mac: [u8; 6],
        fence: &super::SweepFence,
        now: Instant,
    ) {
        let mut entries = self.store.entries.lock().unwrap_or_else(|p| p.into_inner());
        let reason = if fence.is_stale() {
            Some("stale_fence")
        } else if self.interface_index == 0 {
            Some("missing_index")
        } else if crate::validation::prohibited_camera_ip(ip) {
            Some("prohibited_ip")
        } else if mac == [0; 6] || mac[0] & 1 != 0 {
            Some("invalid_peer_mac")
        } else if mac == self.adapter_mac {
            Some("own_mac")
        } else if self.adapter_mac == [0; 6] || self.adapter_mac[0] & 1 != 0 {
            Some("invalid_adapter_mac")
        } else {
            None
        };
        if let Some(reason) = reason {
            if reason == "stale_fence" {
                note_fence_drop("candidate");
            }
            note_candidate_rejection(reason, self.interface_index, self.adapter_mac, mac, ip);
            return;
        }
        entries.retain(|_, seen| now.saturating_duration_since(*seen) < CANDIDATE_TTL);
        let key = (self.interface_index, self.adapter_mac, ip, mac);
        if entries.len() >= MAX_CANDIDATES && !entries.contains_key(&key) {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, seen)| **seen)
                .map(|(key, _)| *key)
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(key, now);
    }
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

/// Legacy listener frames dropped by subnet when no verifier is installed.
/// Activated discovery uses capture scope or fresh selected-interface proof,
/// including on overlapping subnets. Never resets.
static ARP_NONETH_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Frames sent by another local adapter, such as Wi-Fi traffic seen by an
/// unscoped capture. Compare MAC identity, since a wired peer can use the
/// same IP on a separate link. Never resets.
static ARP_LOCAL_MAC_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Prohibited sender addresses (including APIPA), rejected before merging.
static ARP_PROHIBITED_DROPPED: AtomicU64 = AtomicU64::new(0);

static CANDIDATES_REJECTED: AtomicU64 = AtomicU64::new(0);
static REJECTIONS_BY_REASON: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];

fn note_candidate_rejection(
    reason: &'static str,
    index: u32,
    adapter: [u8; 6],
    mac: [u8; 6],
    ip: Ipv4Addr,
) {
    CANDIDATES_REJECTED.fetch_add(1, Ordering::Relaxed);
    let bucket = match reason {
        "stale_fence" => 0,
        "missing_index" => 1,
        "prohibited_ip" => 2,
        "invalid_peer_mac" => 3,
        "own_mac" => 4,
        "invalid_adapter_mac" => 5,
        "local_mac" => 6,
        _ => 7,
    };
    let count = REJECTIONS_BY_REASON[bucket].fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        log::debug!("event=candidate_rejected adapter_mac={} interface_index={} identity={} ip={} reason={} count={}",
            format_mac(&adapter), index, format_mac(&mac), ip, reason, count);
    }
}

static FENCE_DROPS: AtomicU64 = AtomicU64::new(0);
static PROBES_STARTED: AtomicU64 = AtomicU64::new(0);
static PROBES_ANSWERED: AtomicU64 = AtomicU64::new(0);
static PROBES_FAILED: AtomicU64 = AtomicU64::new(0);

pub(crate) fn diagnostic_counts() -> String {
    format!("probes_started={} probes_answered={} probes_failed={} candidates_rejected={} fence_drops={}",
        PROBES_STARTED.load(Ordering::Relaxed), PROBES_ANSWERED.load(Ordering::Relaxed),
        PROBES_FAILED.load(Ordering::Relaxed), CANDIDATES_REJECTED.load(Ordering::Relaxed), FENCE_DROPS.load(Ordering::Relaxed))
}

pub(crate) fn note_fence_drop(path: &'static str) {
    let count = FENCE_DROPS.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        log::debug!("event=fence_drop path={} count={}", path, count);
    }
}

pub fn prohibited_dropped() -> u64 {
    ARP_PROHIBITED_DROPPED.load(Ordering::Relaxed)
}

/// Total ARP frames dropped due to the callback-task bound this session.
/// A diagnostic companion to [`frames_seen`] / [`missed_max`].
pub fn tasks_dropped() -> u64 {
    ARP_TASKS_DROPPED.load(Ordering::Relaxed)
}

/// Total legacy frames dropped by the non-Ethernet subnet prefilter.
pub fn noneth_dropped() -> u64 {
    ARP_NONETH_DROPPED.load(Ordering::Relaxed)
}

/// Total ARP frames dropped because their sender MAC belongs to this host.
pub fn local_mac_dropped() -> u64 {
    ARP_LOCAL_MAC_DROPPED.load(Ordering::Relaxed)
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

/// Per-session health and prohibited-drop counters.
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
    local_mac_dropped: AtomicU64,
    prohibited_dropped: AtomicU64,
}

/// A point-in-time read of one session's counters, for delta math across
/// a checkpoint window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CounterSnapshot {
    pub frames_seen: u64,
    pub local_mac_dropped: u64,
    pub prohibited_dropped: u64,
}

impl SessionCounters {
    pub(crate) fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            frames_seen: self.frames_seen.load(Ordering::Relaxed),
            local_mac_dropped: self.local_mac_dropped.load(Ordering::Relaxed),
            prohibited_dropped: self.prohibited_dropped.load(Ordering::Relaxed),
        }
    }

    fn note_local_mac_dropped(&self) {
        self.local_mac_dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn note_prohibited_dropped(&self) {
        self.prohibited_dropped.fetch_add(1, Ordering::Relaxed);
        ARP_PROHIBITED_DROPPED.fetch_add(1, Ordering::Relaxed);
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
/// prohibited address, legacy non-wired subnet, selected MAC, then other local MAC — all drop the
/// frame, so the order only decides which counter and log fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SenderVerdict {
    Accept,
    DropProhibited,
    /// Sender is on a subnet owned exclusively by a non-wired local
    /// interface (WiFi/VPN/virtual) — not a wired peer.
    DropNonWiredSubnet,
    /// Sender MAC belongs to another local adapter, regardless of IP.
    DropLocalMac,
    /// Sender MAC is the wired adapter's own — our gratuitous ARP.
    DropOwnMac,
}

/// Sender gate for the capture callback: scope discovery to the
/// wired port's peers and reject the host's own traffic. On the verified path,
/// topology cannot exclude a sender: MAC-scoped capture proves its interface,
/// and all other observations require fresh verification on that interface.
/// An overlapping or stale Wi-Fi prefix is not evidence against either path.
/// On the legacy path, an empty
/// `local_macs` or `excluded` disables that check (fail-open). A wired
/// camera with a permitted address — on the Ethernet or a foreign subnet —
/// matches none of the drop conditions. Prohibited drops are counted here,
/// before any registry/callback work, with no dependency on topology reads.
fn classify_sender(
    ip: Ipv4Addr,
    mac: [u8; 6],
    own_mac: Option<[u8; 6]>,
    local_macs: &HashSet<[u8; 6]>,
    excluded: &[ipnetwork::Ipv4Network],
    counters: &SessionCounters,
    has_verifier: bool,
) -> SenderVerdict {
    if crate::validation::prohibited_camera_ip(ip) {
        counters.note_prohibited_dropped();
        return SenderVerdict::DropProhibited;
    }
    if !has_verifier && excluded.iter().any(|net| net.contains(ip)) {
        return SenderVerdict::DropNonWiredSubnet;
    }
    if own_mac == Some(mac) {
        return SenderVerdict::DropOwnMac;
    }
    if local_macs.contains(&mac) {
        return SenderVerdict::DropLocalMac;
    }
    SenderVerdict::Accept
}

fn identity_scoped(outcome: &pktmon::ScopeOutcome) -> bool {
    matches!(
        outcome,
        pktmon::ScopeOutcome::SelectedInterface { source_id: Some(_) }
    )
}

/// Everything the C data callback needs. Reached through the stream's
/// `user_context` pointer; lives (in an `Arc`) on the listener's
/// spawn_blocking thread for the whole session, so the pointer stays
/// valid until after `SetSessionActive(FALSE)` — no callback fires
/// afterward.
struct CallbackContext {
    candidates: Option<CandidateIngress>,
    scope_proven: AtomicBool,
    own_mac: Option<[u8; 6]>,
    /// MAC identities of all local adapters, shared with the discovery loop.
    /// An IP collision on another link is not evidence of a self frame.
    /// Locked briefly on the capture thread —
    /// same discipline as `dedupe`; lock failure fails open.
    local_macs: Arc<StdMutex<HashSet<[u8; 6]>>>,
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
    /// One-shot latch for the "filtering a local adapter" notice.
    localmac_logged: AtomicBool,
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
    // Scope proof or fresh selected-interface verification owns admission.
    // The subnet exclusion remains only for a legacy listener with no
    // candidate verifier. Self/prohibited senders are rejected in every scope.
    // Snapshot the exclusion set first (brief lock; poison fails open to
    // "no filtering", the same tolerance as the local-MAC set) so the two
    // locks are never held together.
    let excluded: Vec<ipnetwork::Ipv4Network> = ctx
        .excluded_subnets
        .lock()
        .map(|v| v.clone())
        .unwrap_or_default();
    let verdict = match ctx.local_macs.lock() {
        Ok(local) => classify_sender(
            ip,
            mac,
            ctx.own_mac,
            &local,
            &excluded,
            &ctx.counters,
            ctx.candidates.is_some(),
        ),
        Err(_) => classify_sender(
            ip,
            mac,
            ctx.own_mac,
            &HashSet::new(),
            &excluded,
            &ctx.counters,
            ctx.candidates.is_some(),
        ),
    };
    let reject = |reason| {
        if let Some(ingress) = &ctx.candidates {
            note_candidate_rejection(
                reason,
                ingress.interface_index,
                ingress.adapter_mac,
                mac,
                ip,
            );
        }
    };
    match verdict {
        SenderVerdict::Accept => {}
        SenderVerdict::DropProhibited => {
            reject("prohibited_ip");
            return;
        }
        SenderVerdict::DropNonWiredSubnet => {
            reject("non_wired_subnet");
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
        SenderVerdict::DropLocalMac => {
            reject("local_mac");
            ARP_LOCAL_MAC_DROPPED.fetch_add(1, Ordering::Relaxed);
            ctx.counters.note_local_mac_dropped();
            if !ctx.localmac_logged.swap(true, Ordering::Relaxed) {
                log::info!(
                    "Filtering ARP from local adapter {} ({}) out of discovery",
                    format_mac(&mac),
                    ip
                );
            }
            return;
        }
        // Our own gratuitous ARP (emitted when we add a secondary IP);
        // it would otherwise land as a phantom peer that gets scanned
        // against our own IP and cached as a ghost node.
        SenderVerdict::DropOwnMac => {
            reject("own_mac");
            ARP_LOCAL_MAC_DROPPED.fetch_add(1, Ordering::Relaxed);
            ctx.counters.note_local_mac_dropped();
            return;
        }
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
        note_fence_drop("capture_callback");
        return;
    }

    if !ctx.scope_proven.load(Ordering::Acquire) {
        if let Some(candidates) = &ctx.candidates {
            candidates.observe(ip, mac, &ctx.fence, Instant::now());
            return;
        }
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
    let fence = ctx.fence.clone();
    // Only the D1 input wired by S5a can authorize the new verified path.
    let verified_by = ctx.candidates.as_ref().map(|ingress| ingress.adapter_mac);
    ctx.runtime.spawn(async move {
        // Hold the permit for the task's lifetime; dropping it on completion
        // frees the slot for the next admitted frame.
        let _permit = permit;
        on_arp_seen(
            ip,
            mac,
            devices,
            registry,
            emitter,
            app_handle,
            &fence,
            verified_by,
        )
        .await;
    });
}

/// Merge one observed (ip, mac) into the legacy map and the canonical
/// registry, persist verified identities, and emit on first sight. The
/// legacy observation path stays wired until S5a supplies candidate ingress.
#[allow(clippy::too_many_arguments)]
async fn on_arp_seen(
    ip: Ipv4Addr,
    mac: [u8; 6],
    devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    registry: Arc<DeviceRegistry>,
    emitter: Arc<DeviceListEmitter>,
    app_handle: tauri::AppHandle,
    fence: &super::SweepFence,
    verified_by: Option<[u8; 6]>,
) {
    if fence.is_stale() {
        note_fence_drop("capture_merge");
        return;
    }
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
        if fence.is_stale() {
            return;
        }
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
        let manager: tauri::State<'_, std::sync::Arc<crate::network::NetworkManager>> =
            app_handle.state();
        manager
            .note_positive_liveness_fenced(&app_handle, ip, fence)
            .await;
    }

    // Merge into the canonical registry outside the `devices` lock.
    // Other identities at the same IP stay inactive with their own aliases.
    let result = match verified_by {
        Some(adapter) => {
            registry.merge_verified(&device, &format_mac(&adapter), &device.last_seen, fence)
        }
        None => registry.merge_arp_fenced(&device, fence),
    };
    if result.changed {
        emitter.poke();
    }
    if verified_by.is_some() {
        if let Some(record) = registry.cache_record(&device.mac) {
            let cache_handle = app_handle.clone();
            let cache_fence = fence.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let config: tauri::State<'_, std::sync::Arc<crate::config::AppConfig>> =
                    cache_handle.state();
                if let Err(e) = config.upsert_cached_device_fenced(record, Some(&cache_fence)) {
                    log::warn!("Failed to persist verified capture identity: {e}");
                }
            })
            .await;
        }
    }
    if !result.dropped_macs.is_empty() {
        let cfg: tauri::State<'_, std::sync::Arc<crate::config::AppConfig>> = app_handle.state();
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
    pub candidates: Option<CandidateIngress>,
    pub devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    pub registry: Arc<DeviceRegistry>,
    pub emitter: Arc<DeviceListEmitter>,
    pub app_handle: tauri::AppHandle,
    /// MAC identities of every local adapter, refreshed by the discovery loop.
    /// A matching sender is the host; an IP match alone is not sufficient.
    pub local_macs: Arc<StdMutex<HashSet<[u8; 6]>>>,
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
        candidates,
        devices,
        registry,
        emitter,
        app_handle,
        local_macs,
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
        let snapshot: Vec<String> = local_macs
            .lock()
            .map(|s| s.iter().map(format_mac).collect())
            .unwrap_or_default();
        log::info!(
            "Starting PacketMonitor ARP listener (self-filtering local MACs: {:?})",
            snapshot
        );
    }

    let join = tokio::task::spawn_blocking(move || {
        let ctx = Arc::new(CallbackContext {
            candidates,
            scope_proven: AtomicBool::new(false),
            own_mac,
            local_macs,
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
            localmac_logged: AtomicBool::new(false),
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
                ctx.scope_proven
                    .store(identity_scoped(&outcome), Ordering::Release);
                match &outcome {
                    pktmon::ScopeOutcome::SelectedInterface { source_id } => {
                        log::info!(
                            "PacketMonitor: ARP capture active (scope=selected-interface, source_id={}, adapter='{}')",
                            source_id.map_or_else(|| "unknown".to_string(), |v| v.to_string()),
                            scope.display_name
                        );
                    }
                    pktmon::ScopeOutcome::ScopedByName { source_id } => {
                        log::warn!(
                            "PacketMonitor: ARP capture active (scope=scoped-by-name, source_id={}, adapter='{}'); name match is not identity proof",
                            source_id,
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

pub(crate) fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Fresh ARP on the selected interface. ResolveIpNetEntry2 flushes the
/// matching neighbor entry itself, then sends ARP; never read the cache as
/// a fallback. The source must uniquely belong to this index. One native
/// resolution stays in flight until it returns; spawn_blocking cannot be
/// aborted, so the sequential caller retains its pass budget and fence.
pub(crate) async fn fresh_resolve_mac(
    target: Ipv4Addr,
    scratch: Ipv4Addr,
    interface_index: u32,
) -> Result<Option<String>, AppError> {
    PROBES_STARTED.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let result = async {
        crate::validation::parse_camera_ip(&target.to_string())?;
        #[cfg(target_os = "windows")]
        {
            tokio::task::spawn_blocking(move || {
                resolve_neighbor_blocking(target, scratch, interface_index)
            })
            .await
            .map_err(|e| {
                AppError::Network(format!("ResolveIpNetEntry2 task failed to join: {e}"))
            })?
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (target, scratch, interface_index);
            Err(AppError::Network(
                "fresh ARP resolution is Windows-only".into(),
            ))
        }
    }
    .await;
    if matches!(&result, Ok(Some(_))) {
        PROBES_ANSWERED.fetch_add(1, Ordering::Relaxed);
    } else {
        PROBES_FAILED.fetch_add(1, Ordering::Relaxed);
    }
    log::debug!(
        "event=arp_probe interface_index={} target={} source={} answered={} duration_ms={} {}",
        interface_index,
        target,
        scratch,
        matches!(&result, Ok(Some(_))),
        started.elapsed().as_millis(),
        diagnostic_counts()
    );
    result
}

#[cfg(target_os = "windows")]
fn resolve_neighbor_blocking(
    target: Ipv4Addr,
    source: Ipv4Addr,
    interface_index: u32,
) -> Result<Option<String>, AppError> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{ResolveIpNetEntry2, MIB_IPNET_ROW2};
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN, SOCKADDR_INET};

    if !super::interface::source_matches_interface(interface_index, source) {
        return Err(AppError::Network(format!(
            "ARP source {source} does not uniquely belong to interface {interface_index}"
        )));
    }
    // Zeroed rows/addresses are valid initializers. Only Address and the
    // selected InterfaceIndex are supplied; no cached MAC enters the call.
    let mut row: MIB_IPNET_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceIndex = interface_index;
    let sockaddr = |ip: Ipv4Addr| {
        let mut address: SOCKADDR_IN = unsafe { std::mem::zeroed() };
        address.sin_family = AF_INET;
        address.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        SOCKADDR_INET { Ipv4: address }
    };
    row.Address = sockaddr(target);
    let src = sockaddr(source);
    let result = unsafe { ResolveIpNetEntry2(&mut row, &src) };
    let mac = resolved_neighbor_mac(result, interface_index, &row)?;
    if !super::interface::source_matches_interface(interface_index, source) {
        return Err(AppError::Network(
            "ARP source changed during resolution".into(),
        ));
    }
    Ok(Some(mac))
}

#[cfg(target_os = "windows")]
fn resolved_neighbor_mac(
    result: u32,
    interface_index: u32,
    row: &windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPNET_ROW2,
) -> Result<String, AppError> {
    use windows_sys::Win32::Networking::WinSock::NlnsReachable;
    if result != 0 {
        return Err(AppError::Network(format!(
            "ResolveIpNetEntry2 failed: {result}"
        )));
    }
    if row.InterfaceIndex != interface_index
        || row.State != NlnsReachable
        || row.PhysicalAddressLength != 6
    {
        return Err(AppError::Network(
            "ARP resolution returned invalid interface/state/MAC length".into(),
        ));
    }
    let mac: [u8; 6] = row.PhysicalAddress[..6].try_into().unwrap();
    if mac == [0; 6] || mac[0] & 1 != 0 {
        return Err(AppError::Network(
            "ARP resolution returned a non-unicast MAC".into(),
        ));
    }
    Ok(format_mac(&mac))
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
    #[cfg(windows)]
    {
        let Some(source) = interface_ip.parse::<Ipv4Addr>().ok() else {
            return vec![];
        };
        native_neighbors(source).await.unwrap_or_else(|error| {
            log::warn!("Neighbor observation unavailable: {error}");
            vec![]
        })
    }
    #[cfg(not(windows))]
    {
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
}

/// Run a PowerShell script, returning stdout on success (exit 0), or
/// None on spawn failure, non-zero exit, or timeout. Bounded so a hung
/// PowerShell can't wedge the caller.
#[cfg(not(windows))]
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
#[cfg(any(not(windows), test))]
pub(crate) fn parse_neighbors_json(stdout: &str) -> Vec<(Ipv4Addr, String)> {
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
#[cfg(any(not(windows), test))]
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
    #[cfg(windows)]
    {
        let source = source.ok_or_else(|| {
            AppError::Network("A bound source is required for the conflict probe".into())
        })?;
        let index = native_source_index(source).await?;
        // A non-reply is valid ICMP data; provider/identity failures remain
        // errors and are conservatively treated as occupied by AdoptOps.
        let _ = bound_ping(target_ip, source, index, timeout).await?;
        Ok(native_neighbors(source)
            .await?
            .iter()
            .any(|(ip, _)| *ip == target_ip))
    }
    #[cfg(not(windows))]
    {
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
}

#[cfg(windows)]
async fn native_source_index(source: Ipv4Addr) -> Result<u32, AppError> {
    let all = super::interface::read_native().await?;
    let owners: Vec<_> = all
        .iter()
        .filter(|a| a.ips.iter().any(|ip| ip.address == source.to_string()))
        .collect();
    match owners.as_slice() {
        [owner] if owner.index != 0 => Ok(owner.index),
        _ => Err(AppError::Network(
            "Neighbor source ownership is unavailable or ambiguous".into(),
        )),
    }
}

#[cfg(windows)]
fn cached_neighbor(
    row: &windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPNET_ROW2,
    index: u32,
) -> Option<(Ipv4Addr, String)> {
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    if row.InterfaceIndex != index
        || unsafe { row.Address.si_family } != AF_INET
        || !(2..=5).contains(&row.State)
        || row.PhysicalAddressLength != 6
    {
        return None;
    }
    let mac: [u8; 6] = row.PhysicalAddress[..6].try_into().ok()?;
    if mac == [0; 6] || mac[0] & 1 != 0 {
        return None;
    }
    let ip = Ipv4Addr::from(unsafe { row.Address.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes());
    Some((ip, format_mac(&mac)))
}

#[cfg(windows)]
pub(super) async fn native_neighbors(
    source: Ipv4Addr,
) -> Result<Vec<(Ipv4Addr, String)>, AppError> {
    let index = native_source_index(source).await?;
    tokio::task::spawn_blocking(move || {
        use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            FreeMibTable, GetIpNetTable2, MIB_IPNET_TABLE2,
        };
        use windows_sys::Win32::Networking::WinSock::AF_INET;
        struct Table(*mut MIB_IPNET_TABLE2);
        impl Drop for Table {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe {
                        FreeMibTable(self.0.cast());
                    }
                }
            }
        }
        let mut raw = std::ptr::null_mut();
        let status = unsafe { GetIpNetTable2(AF_INET, &mut raw) };
        let table = Table(raw);
        if status == ERROR_NOT_FOUND {
            return Ok(vec![]);
        }
        if status != 0 || table.0.is_null() {
            return Err(AppError::Network(format!(
                "Native neighbor observation failed: {status}"
            )));
        }
        let count = unsafe { (*table.0).NumEntries } as usize;
        if count > 65536 {
            return Err(AppError::Network(
                "Native neighbor table exceeds bound".into(),
            ));
        }
        let rows = unsafe {
            std::slice::from_raw_parts(std::ptr::addr_of!((*table.0).Table).cast(), count)
        };
        if !super::interface::source_matches_interface(index, source) {
            return Err(AppError::Network(
                "Neighbor source changed during observation".into(),
            ));
        }
        Ok(rows
            .iter()
            .filter_map(|row| cached_neighbor(row, index))
            .collect())
    })
    .await
    .map_err(|_| AppError::Network("Native neighbor observation task failed".into()))?
}

/// Bounded native ICMP avoids launching an elevated shell/ping process. The
/// unique source and egress index are checked before and after the call.
#[cfg(windows)]
pub(crate) async fn bound_ping(
    target: Ipv4Addr,
    source: Ipv4Addr,
    index: u32,
    timeout: std::time::Duration,
) -> Result<bool, AppError> {
    crate::validation::parse_camera_ip(&target.to_string())?;
    tokio::task::spawn_blocking(move || {
        use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2Ex, ICMP_ECHO_REPLY,
        };
        struct Icmp(windows_sys::Win32::Foundation::HANDLE);
        impl Drop for Icmp {
            fn drop(&mut self) {
                unsafe {
                    IcmpCloseHandle(self.0);
                }
            }
        }
        if !super::interface::source_matches_interface(index, source)
            || super::route::egress_index(target).ok() != Some(index)
        {
            return Err(AppError::Network("Bound ICMP source/route changed".into()));
        }
        let raw = unsafe { IcmpCreateFile() };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return Err(AppError::Network("Native ICMP handle unavailable".into()));
        }
        let handle = Icmp(raw);
        let data = [0u8; 16];
        // usize alignment satisfies the native reply structure, including x64.
        let mut reply = [0usize; 128];
        let count = unsafe {
            IcmpSendEcho2Ex(
                handle.0,
                std::ptr::null_mut(),
                None,
                std::ptr::null(),
                u32::from_ne_bytes(source.octets()),
                u32::from_ne_bytes(target.octets()),
                data.as_ptr().cast(),
                data.len() as u16,
                std::ptr::null(),
                reply.as_mut_ptr().cast(),
                std::mem::size_of_val(&reply) as u32,
                timeout.as_millis().clamp(1, 2000) as u32,
            )
        };
        let native_error = unsafe { GetLastError() };
        if !super::interface::source_matches_interface(index, source)
            || super::route::egress_index(target).ok() != Some(index)
        {
            return Err(AppError::Network(
                "Bound ICMP source/route changed during probe".into(),
            ));
        }
        if count == 0 {
            let error = native_error;
            return match error {
                11002..=11005 | 11010 => Ok(false),
                _ => Err(AppError::Network(format!("Native ICMP failed: {error}"))),
            };
        }
        let response = unsafe { &*reply.as_ptr().cast::<ICMP_ECHO_REPLY>() };
        Ok(response.Status == 0 && response.Address == u32::from_ne_bytes(target.octets()))
    })
    .await
    .map_err(|_| AppError::Network("Native ICMP task failed".into()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    #[test]
    fn fresh_neighbor_result_rejects_errors_stale_rows_and_wrong_interfaces() {
        use windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPNET_ROW2;
        use windows_sys::Win32::Networking::WinSock::{
            NlnsDelay, NlnsProbe, NlnsReachable, NlnsStale,
        };
        let mut row: MIB_IPNET_ROW2 = unsafe { std::mem::zeroed() };
        row.InterfaceIndex = 7;
        row.State = NlnsReachable;
        row.PhysicalAddressLength = 6;
        row.PhysicalAddress[..6].copy_from_slice(&[0x40, 0xcd, 0x3a, 3, 0x28, 0xe2]);
        assert_eq!(
            resolved_neighbor_mac(0, 7, &row).unwrap(),
            "40:cd:3a:03:28:e2"
        );
        // A failed native flush/resolve never returns a populated old MAC.
        for error in [5, 53, 1168] {
            assert!(resolved_neighbor_mac(error, 7, &row).is_err());
        }
        assert!(resolved_neighbor_mac(0, 8, &row).is_err());
        for state in [NlnsStale, NlnsDelay, NlnsProbe] {
            row.State = state;
            assert!(resolved_neighbor_mac(0, 7, &row).is_err());
        }
        row.State = NlnsReachable;
        row.PhysicalAddressLength = 8;
        assert!(resolved_neighbor_mac(0, 7, &row).is_err());
        row.PhysicalAddressLength = 6;
        for mac in [[0; 6], [0xff; 6], [1, 2, 3, 4, 5, 6]] {
            row.PhysicalAddress[..6].copy_from_slice(&mac);
            assert!(resolved_neighbor_mac(0, 7, &row).is_err());
        }
    }
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
        old_session.note_local_mac_dropped();
        let stale = old_session.snapshot();
        let fresh = new_session.snapshot();
        assert_eq!((stale.frames_seen, stale.local_mac_dropped), (2, 1));
        assert_eq!((fresh.frames_seen, fresh.local_mac_dropped), (0, 0));
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

    const WIRED_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const WIFI_MAC: [u8; 6] = [0xac, 0x45, 0xef, 0x38, 0xf9, 0xf5];
    const OTHER_MAC: [u8; 6] = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

    #[test]
    fn prohibited_senders_drop_without_topology_and_do_not_count_as_payload() {
        let counters = SessionCounters::default();
        let before = prohibited_dropped();
        for ip in [
            "169.254.0.0",
            "169.254.73.42",
            "169.254.255.255",
            "0.0.0.0",
            "127.0.0.1",
            "255.255.255.255",
        ] {
            assert_eq!(
                classify_sender(
                    ipv4(ip),
                    OTHER_MAC,
                    None,
                    &HashSet::new(),
                    &[],
                    &counters,
                    false
                ),
                SenderVerdict::DropProhibited
            );
        }
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.prohibited_dropped, 6);
        assert_eq!(snapshot.frames_seen, 0);
        assert_eq!(snapshot.local_mac_dropped, 0);
        assert!(prohibited_dropped() >= before + 6);
    }

    #[tokio::test]
    async fn apipa_verification_fails_before_any_native_or_ping_work() {
        let ip = ipv4("169.254.73.42");
        assert!(fresh_resolve_mac(ip, ipv4("169.254.73.99"), 0)
            .await
            .unwrap_err()
            .to_string()
            .contains("routable IPv4 address first"));
    }

    #[test]
    fn ethernet_peer_sharing_wifi_ip_is_distinct_from_both_local_adapters() {
        let local = HashSet::from([WIRED_MAC, WIFI_MAC]);
        // Reproduce the reported collision. The same IP must be accepted for
        // the Ethernet peer and rejected for either of the PC's NICs.
        for verified in [false, true] {
            for (mac, expected) in [
                (OTHER_MAC, SenderVerdict::Accept),
                (WIFI_MAC, SenderVerdict::DropLocalMac),
                (WIRED_MAC, SenderVerdict::DropOwnMac),
            ] {
                let frame = make_arp_packet(mac, [192, 168, 1, 204]);
                let (_, sender, ip) = extract_arp(&frame, 1).unwrap();
                assert_eq!(
                    classify_sender(
                        ip,
                        sender,
                        Some(WIRED_MAC),
                        &local,
                        &[],
                        &SessionCounters::default(),
                        verified
                    ),
                    expected
                );
            }
            // DHCP/address churn must not turn our Wi-Fi traffic into a node.
            assert_eq!(
                classify_sender(
                    ipv4("10.0.0.23"),
                    WIFI_MAC,
                    Some(WIRED_MAC),
                    &local,
                    &[],
                    &SessionCounters::default(),
                    verified
                ),
                SenderVerdict::DropLocalMac
            );
        }
    }

    #[test]
    fn verified_path_accepts_a_camera_even_with_a_stale_wifi_exclusion() {
        let local = HashSet::from([WIRED_MAC, WIFI_MAC]);
        let excluded = ["192.168.1.0/24".parse().unwrap()];
        let counters = SessionCounters::default();
        assert_eq!(
            classify_sender(
                ipv4("192.168.1.204"),
                OTHER_MAC,
                Some(WIRED_MAC),
                &local,
                &excluded,
                &counters,
                true
            ),
            SenderVerdict::Accept
        );
        assert_eq!(
            classify_sender(
                ipv4("192.168.1.100"),
                WIFI_MAC,
                Some(WIRED_MAC),
                &local,
                &excluded,
                &counters,
                true
            ),
            SenderVerdict::DropLocalMac
        );
        assert_eq!(
            classify_sender(
                ipv4("192.168.1.204"),
                WIRED_MAC,
                Some(WIRED_MAC),
                &local,
                &excluded,
                &counters,
                true
            ),
            SenderVerdict::DropOwnMac
        );
        for has_verifier in [false, true] {
            assert_eq!(
                classify_sender(
                    ipv4("169.254.10.2"),
                    OTHER_MAC,
                    Some(WIRED_MAC),
                    &local,
                    &excluded,
                    &counters,
                    has_verifier
                ),
                SenderVerdict::DropProhibited
            );
        }
        assert_eq!(counters.snapshot().prohibited_dropped, 2);
    }

    #[test]
    fn sender_own_mac_dropped() {
        // Our gratuitous ARP for a just-bound secondary IP: the IP may not
        // be in the local set yet (set refresh races the bind), so the MAC
        // check must catch it on its own.
        let local = HashSet::new();
        assert_eq!(
            classify_sender(
                ipv4("10.13.248.102"),
                WIRED_MAC,
                Some(WIRED_MAC),
                &local,
                &[],
                &SessionCounters::default(),
                false
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
                &HashSet::from([WIRED_MAC]),
                &excluded,
                &SessionCounters::default(),
                false
            ),
            SenderVerdict::DropNonWiredSubnet
        );
    }

    #[test]
    fn wired_peers_accepted_beside_local_macs_on_same_subnet() {
        // A fixed-IP wired device sharing the /24 with two of our own
        // addresses must never be rejected, and neither may a camera on a
        // foreign adopted subnet.
        let local = HashSet::from([WIRED_MAC, WIFI_MAC]);
        assert_eq!(
            classify_sender(
                ipv4("192.168.1.202"),
                OTHER_MAC,
                Some(WIRED_MAC),
                &local,
                &[],
                &SessionCounters::default(),
                false
            ),
            SenderVerdict::Accept
        );
        assert_eq!(
            classify_sender(
                ipv4("10.194.200.24"),
                OTHER_MAC,
                Some(WIRED_MAC),
                &local,
                &[],
                &SessionCounters::default(),
                false
            ),
            SenderVerdict::Accept
        );
    }

    #[test]
    fn empty_topology_sets_admit_a_permitted_peer() {
        // Missing topology does not block a permitted peer; prohibited
        // senders are rejected independently of these sets.
        assert_eq!(
            classify_sender(
                ipv4("192.168.1.204"),
                OTHER_MAC,
                None,
                &HashSet::new(),
                &[],
                &SessionCounters::default(),
                false
            ),
            SenderVerdict::Accept
        );
    }

    #[test]
    fn excluded_subnet_takes_precedence_over_local_mac() {
        // An IP that is both ours and on an excluded subnet counts as a
        // non-wired drop — pins which counter/log fires.
        let excluded = vec!["192.168.12.0/24".parse().unwrap()];
        assert_eq!(
            classify_sender(
                ipv4("192.168.12.103"),
                OTHER_MAC,
                Some(WIRED_MAC),
                &HashSet::from([OTHER_MAC]),
                &excluded,
                &SessionCounters::default(),
                false
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

    #[test]
    fn candidate_ttl_scope_bound_and_retirement() {
        let store = Arc::new(CandidateSet::default());
        let ingress = CandidateIngress {
            store: store.clone(),
            interface_index: 7,
            adapter_mac: WIRED_MAC,
        };
        let active = Arc::new(AtomicBool::new(true));
        let fence = super::super::SweepFence::new(1, Arc::new(AtomicU64::new(1)), active.clone());
        let now = Instant::now();
        ingress.observe(ipv4("192.168.1.204"), OTHER_MAC, &fence, now);
        assert_eq!(store.count(now), 1);
        let observed = store.snapshot(now);
        assert_eq!(observed[0].interface_index, 7);
        assert_eq!(observed[0].adapter_mac, WIRED_MAC);
        assert_eq!(observed[0].ip, ipv4("192.168.1.204"));
        assert_eq!(observed[0].mac, OTHER_MAC);
        assert_eq!(observed[0].observed_at, now);
        ingress.observe(ipv4("169.254.1.1"), OTHER_MAC, &fence, now);
        assert_eq!(store.count(now), 1);
        assert_eq!(store.count(now + CANDIDATE_TTL), 0);
        for i in 0..(MAX_CANDIDATES + 1) {
            ingress.observe(
                Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8),
                OTHER_MAC,
                &fence,
                now,
            );
        }
        assert_eq!(store.count(now), MAX_CANDIDATES);
        store.clear();
        active.store(false, Ordering::Relaxed);
        ingress.observe(ipv4("192.168.1.204"), OTHER_MAC, &fence, now);
        assert_eq!(store.count(now), 0);
    }

    #[test]
    fn name_and_unscoped_capture_require_candidate_verification() {
        assert!(!identity_scoped(&pktmon::ScopeOutcome::ScopedByName {
            source_id: 42
        }));
        assert!(!identity_scoped(&pktmon::ScopeOutcome::UnscopedFallback {
            reason: "join failed".into()
        }));
        assert!(!identity_scoped(&pktmon::ScopeOutcome::SelectedInterface {
            source_id: None
        }));
        assert!(identity_scoped(&pktmon::ScopeOutcome::SelectedInterface {
            source_id: Some(42)
        }));
    }
}
