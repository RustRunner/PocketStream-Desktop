//! Discovery producers, clock and generation. Native drain stays at the facade.
use super::adopt_loop::AdoptionCtx;
use super::*;
/// Cooperative-shutdown handle for the auto-adopt loop: a `watch` signal
/// plus the task's join handle. A bare `JoinHandle` could only be aborted;
/// this lets `stop` ask the loop to exit at a `select!` point (so an
/// in-flight adoption cleans up), join with a bound, and fall back to abort
/// only if that times out.
struct AutoAdoptHandle {
    shutdown: tokio::sync::watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

/// How long a cooperative auto-adopt stop waits for the loop to exit before
/// aborting its caller. The executor retains the child/job and write barrier
/// until native completion/observation; pending intent survives uncertainty.
const AUTO_ADOPT_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Handle to the capture-health watchdog. Like [`AutoAdoptHandle`], the
/// watchdog is asked to stop cooperatively — it may be mid-restart of the
/// capture session, and a cooperative exit lets it park or install the
/// in-flight session cleanly — with abort as the bounded fallback (safe:
/// an orphaned capture session tears itself down when its handle drops).
struct WatchdogHandle {
    shutdown: tokio::sync::watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

/// How long a cooperative watchdog stop waits before aborting.
const WATCHDOG_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(super) struct DiscoverySession {
    auto_adopt_handle: Arc<Mutex<Option<AutoAdoptHandle>>>,
    /// Capture-health watchdog: restarts a provably deaf capture session
    /// (scoped retry, then forced-unscoped), and only when that ladder is
    /// exhausted emits `discovery-degraded`, then `discovery-recovered`
    /// on the first frame — the pre-ladder event contract, unchanged.
    discovery_watchdog_handle: Arc<Mutex<Option<WatchdogHandle>>>,
    /// Advanced on every discovery start. Captured by sweeps and the
    /// capture listener so stale-session work fences itself out.
    pub(super) discovery_generation: Arc<AtomicU64>,
    /// True while a discovery session is live; cleared by every stop. The
    /// generation only advances on start, so this flag is what lets a stop
    /// with no restart (Static Auto → Manual) still drop stragglers.
    pub(super) discovery_active: Arc<AtomicBool>,
    /// Instant the current discovery session started; `None` while
    /// stopped. Anchors the startup-grace math when the adoption
    /// snapshot derives staleness (the reap pass carries its own copy
    /// into the loop task).
    pub(super) discovery_started: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
    pub(super) arp_devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
}
impl DiscoverySession {
    pub(super) fn new() -> Self {
        Self {
            auto_adopt_handle: Arc::new(Mutex::new(None)),
            discovery_watchdog_handle: Arc::new(Mutex::new(None)),
            discovery_generation: Arc::new(AtomicU64::new(0)),
            discovery_active: Arc::new(AtomicBool::new(false)),
            discovery_started: Arc::new(std::sync::Mutex::new(None)),
            arp_devices: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub(super) fn sweep_fence(&self) -> SweepFence {
        SweepFence::new(
            self.discovery_generation.load(Ordering::Relaxed),
            self.discovery_generation.clone(),
            self.discovery_active.clone(),
        )
    }
    pub(super) async fn start(
        &self,
        deps: DiscoveryDeps,
        request: StartDiscovery,
    ) -> Result<(), AppError> {
        let StartDiscovery {
            interface_display_name,
            adapter_mac,
            interface_index,
            known_ips,
            sweep_ips,
            native_sweep_ips,
            listener_params,
            activation_rx,
        } = request;
        let config = deps.config.as_ref();
        let local_macs = deps.selector.local_macs.clone();
        let devices = self.arp_devices.clone();
        let registry = deps.registry.clone();
        let emitter = deps.emitter.clone();
        // New discovery session: advance the generation and mark discovery
        // active so sweeps and capture frames from a prior session can
        // fence themselves out (that work captures the generation; the
        // active flag also covers a stop with no restart). Deliberately
        // after the up-gate — a pre-attach-only start must not burn a
        // generation or leave the active flag set with no session.
        let generation = self.discovery_generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.discovery_active.store(true, Ordering::Relaxed);
        log::debug!("Discovery session generation → {}", generation);

        // Session fence for sweeps and the adopt loop: stale-session work
        // (from a prior session, or after a stop) drops itself before
        // merging or emitting into the shared registry. The capture
        // listener does NOT use this fence — a retained listener must
        // keep merging across session restarts.
        let fence = SweepFence::new(
            generation,
            self.discovery_generation.clone(),
            self.discovery_active.clone(),
        );
        // Rebind the shared bundle onto the session fence for every
        // consumer below (sweeps, watchdog).
        let listener_params = listener_params.with_fence(fence.clone());

        log::info!(
            "Starting ARP discovery on '{}' (IPs: {:?}, mac: {})",
            interface_display_name,
            known_ips,
            adapter_mac
        );

        let adopted = deps.bindings.adopted_ips.clone();
        let pending_ips = deps.bindings.pending_ips.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let iface_name = interface_display_name.to_string();
        let adopt_sweep = deps.sweep(self);

        // Startup sweeps only native /24s. Explicit Refresh also includes
        // actually bound adopted /24s, through the same session fence.
        let sweep_params = listener_params.clone();
        let sweep_deps = deps.sweep(self);
        let solicitations = deps.capture.solicitations.subscribe();
        tokio::spawn(async move {
            // Give a freshly attached capture time to start.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            provoke_sweep(&sweep_params, &sweep_ips, &sweep_deps).await;
        });

        // Capture-health watchdog. The ping sweep above provokes ARP; if
        // the session delivers no payload within the window, the watchdog
        // restarts the capture (bounded ladder) before degrading loudly.
        // It never flips availability, and emits at most one degraded per
        // session, cleared by a recovered on the first frame.
        let (watchdog_shutdown, watchdog_shutdown_rx) = tokio::sync::watch::channel(false);
        let watchdog = tokio::spawn(watchdog_ladder(
            listener_params.clone(),
            native_sweep_ips,
            deps.sweep(self),
            (activation_rx, solicitations),
            watchdog_shutdown_rx,
        ));
        *self.discovery_watchdog_handle.lock().await = Some(WatchdogHandle {
            shutdown: watchdog_shutdown,
            join: watchdog,
        });

        // Auto-adopt handler for foreign subnets
        let candidates_for_adopt = listener_params.candidates.clone();
        let devices_for_adopt = devices.clone();
        let registry_for_adopt = registry.clone();
        let emitter_for_adopt = emitter.clone();
        let fence_for_loop = fence.clone();
        let binding_mac = config.get().selected_adapter_mac.unwrap_or_default();
        let address_generation = deps.bindings.address_generation.clone();
        let address_active = deps.bindings.address_active.clone();
        // One session-start instant shared by the loop's reap pass and
        // the adoption snapshot's staleness derivation. Anchors the
        // startup grace; restarts with discovery, so an interface
        // bounce re-arms it.
        let session_started = std::time::Instant::now();
        if let Ok(mut started) = self.discovery_started.lock() {
            *started = Some(session_started);
        }
        let ctx = AdoptionCtx {
            sweep: adopt_sweep,
            iface_name: iface_name.clone(),
            adapter_mac: binding_mac,
            interface_index,
            candidates: candidates_for_adopt,
            config: deps.config.clone(),
            bridge: deps.bridge.clone(),
            bindings: deps.bindings.clone(),
            adopted: adopted.clone(),
            pending_ips: pending_ips.clone(),

            devices: devices_for_adopt.clone(),
            registry: registry_for_adopt.clone(),
            emitter: emitter_for_adopt.clone(),
            fence: fence_for_loop.clone(),
            address_fence: SweepFence::new(
                address_generation.load(Ordering::Acquire),
                address_generation.clone(),
                address_active.clone(),
            ),
            local_macs: local_macs.clone(),
        };
        let adopt_handle = tokio::spawn(adopt_loop::run(
            ctx,
            known_ips,
            deps.bindings.clone(),
            shutdown_rx,
        ));
        {
            let mut slot = self.auto_adopt_handle.lock().await;
            if slot.is_some() {
                log::warn!(
                    "auto_adopt_handle slot unexpectedly occupied at start — \
                     the preceding stop should have cleared it"
                );
            }
            *slot = Some(AutoAdoptHandle {
                shutdown: shutdown_tx,
                join: adopt_handle,
            });
        }

        Ok(())
    }
    /// Stop the session half only: sweeps' fence, the session clock,
    /// the adopt task, the watchdog, and pending-IP reconciliation. The
    /// capture listener keeps running — its frames are fenced by the
    /// capture lifecycle, not the discovery generation, so a retained
    /// listener keeps merging across session restarts.
    pub(super) async fn stop_session_locked(&self) {
        // Mark inactive before tearing down handles so an in-flight sweep
        // or capture frame fences out. Cleared on every stop — including a
        // stop with no following start (Static Auto → Manual) — which a
        // generation counter alone would miss.
        self.discovery_active.store(false, Ordering::Relaxed);
        // No session, no session clock: the adoption snapshot's grace
        // math treats a stopped discovery as elapsed-zero (never badges
        // an APIPA entry stale on session evidence it cannot gather).
        if let Ok(mut started) = self.discovery_started.lock() {
            *started = None;
        }
        if let Some(h) = self.auto_adopt_handle.lock().await.take() {
            // Cooperative stop: ask the loop to exit at a select! point so an
            // in-flight adoption rolls back cleanly, then join with a bound.
            // Abort only the caller on expiry. Its executor owns/drains the
            // child tree and retains any uncertain result independently.
            let _ = h.shutdown.send(true);
            let abort = h.join.abort_handle();
            match tokio::time::timeout(AUTO_ADOPT_STOP_TIMEOUT, h.join).await {
                Ok(_) => log::info!("Auto-adopt task stopped cooperatively"),
                Err(_) => {
                    log::warn!(
                        "Auto-adopt task did not stop within {}s — aborting",
                        AUTO_ADOPT_STOP_TIMEOUT.as_secs()
                    );
                    abort.abort();
                }
            }
        }
        if let Some(h) = self.discovery_watchdog_handle.lock().await.take() {
            // Cooperative stop first: the watchdog may be mid-restart of
            // the capture session, and a cooperative exit parks or
            // installs the in-flight session cleanly. Abort is the
            // bounded fallback — safe, because an orphaned session tears
            // itself down when its handle drops.
            let _ = h.shutdown.send(true);
            let abort = h.join.abort_handle();
            if tokio::time::timeout(WATCHDOG_STOP_TIMEOUT, h.join)
                .await
                .is_err()
            {
                log::warn!(
                    "Discovery watchdog did not stop within {}s — aborting",
                    WATCHDOG_STOP_TIMEOUT.as_secs()
                );
                abort.abort();
            }
        }
    }
}
#[derive(Clone)]
pub(super) struct DiscoveryDeps {
    pub(super) selector: Arc<adapter_selector::AdapterSelector>,
    pub(super) capture: Arc<capture_session::CaptureSession>,
    pub(super) bindings: Arc<binding_store::BindingStore>,
    pub(super) config: Arc<crate::config::AppConfig>,
    pub(super) bridge: Arc<dyn crate::bridge::AppBridge>,
    pub(super) registry: Arc<DeviceRegistry>,
    pub(super) emitter: Arc<DeviceListEmitter>,
}
impl DiscoveryDeps {
    pub(super) fn sweep(&self, session: &DiscoverySession) -> SweepDeps {
        SweepDeps {
            selector: self.selector.clone(),
            capture: self.capture.clone(),
            pending: self.bindings.pending_ips.clone(),
            generation: session.discovery_generation.clone(),
            active: session.discovery_active.clone(),
            config: self.config.clone(),
            bridge: self.bridge.clone(),
        }
    }
}
pub(super) struct StartDiscovery {
    pub(super) interface_display_name: String,
    pub(super) adapter_mac: String,
    pub(super) interface_index: u32,
    pub(super) known_ips: Vec<String>,
    pub(super) sweep_ips: Vec<String>,
    pub(super) native_sweep_ips: Vec<String>,
    pub(super) listener_params: arp::ListenerParams,
    pub(super) activation_rx: arp::ActivationRx,
}

/// No window runs until traffic was solicited in this capture attempt.
/// Retain the pre-send baseline even if scheduling delays the watchdog.
pub(super) async fn watch_window(
    counters: &arp::SessionCounters,
    solicitations: &mut tokio::sync::watch::Receiver<Option<Solicitation>>,
    generation: u64,
    after: Option<tokio::time::Instant>,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    window: std::time::Duration,
) -> Option<(u64, u64)> {
    let solicitation = loop {
        if !solicitations.has_changed().ok()? {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => return None,
                changed = solicitations.changed() => { changed.ok()?; }
            }
        }
        let value = *solicitations.borrow_and_update();
        if let Some(value) =
            value.filter(|s| s.generation == generation && after.is_none_or(|at| s.at >= at))
        {
            break value;
        }
    };
    tokio::select! {
        biased;
        _ = shutdown_rx.changed() => return None,
        _ = tokio::time::sleep_until(solicitation.at + window) => {}
    }
    let now = counters.snapshot();
    Some((
        now.frames_seen
            .saturating_sub(solicitation.baseline.frames_seen),
        now.local_mac_dropped
            .saturating_sub(solicitation.baseline.local_mac_dropped),
    ))
}

/// Capture-health watchdog with a bounded self-heal ladder.
///
/// After each session activation, the provoking sweep plus a checkpoint
/// window prove the session delivers. A deaf-but-alive (or fully dead)
/// session is restarted: once scoped, covering transient attach races,
/// then forced-unscoped. If the escalation is also deaf — or any start
/// fails, an activation times out, or a teardown join times out — the
/// ladder exhausts into the pre-existing degraded event and bounded
/// recovery poll. Transparent retries and recoveries log only;
/// `discovery-degraded` fires at most once, on exhaustion, so the
/// degraded/recovered event contract is unchanged.
///
/// Runs below the discovery lifecycle mutex; a concurrent stop wins.
/// Every wait point also watches `shutdown_rx`, the fence is re-checked
/// under the handle-slot lock before a restarted session is installed,
/// and health is sampled through the installed handle's own counters
/// only — late callbacks from a torn-down session cannot satisfy a
/// checkpoint.
pub(super) async fn watchdog_ladder(
    params: arp::ListenerParams,
    sweep_ips: Vec<String>,
    deps: SweepDeps,
    activation: (
        arp::ActivationRx,
        tokio::sync::watch::Receiver<Option<Solicitation>>,
    ),
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let (mut activation_rx, mut solicitations) = activation;
    let capture_signal = deps.capture.capture_signal.clone();
    let listener_slot = deps.capture.arp_listener_handle.clone();
    let prior_joins = deps.capture.prior_capture_joins.clone();
    let capture_identity = deps.capture.capture_identity.clone();
    // The deadline starts at the solicitation, not at activation.
    const INITIAL_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
    const POLL: std::time::Duration = std::time::Duration::from_secs(2);
    const MAX_WATCH: std::time::Duration = std::time::Duration::from_secs(300);

    let mut restarts_used: u32 = 0;
    let mut last_self_delta: u64 = 0;
    'session: loop {
        // Consecutive quiet windows in this attempt. Structurally
        // consecutive: the only path to another window without a fresh
        // activation is the Rebaseline arm, so any other verdict ends
        // the run and the count never goes stale.
        let mut quiet_windows: u32 = 0;
        let mut window_after = (restarts_used > 0).then(tokio::time::Instant::now);
        let activation = tokio::select! {
            _ = shutdown_rx.changed() => None,
            outcome = tokio::time::timeout(arp::CAPTURE_ACTIVATION_TIMEOUT, activation_rx) => {
                Some(outcome)
            }
        };
        let mut event = match activation {
            None => arp::AttemptEvent::ShutdownSignalled,
            Some(Ok(Ok(Ok(scope)))) => {
                if restarts_used > 0 {
                    if params.fence.is_stale() {
                        return;
                    }
                    if let Some(identity) = capture_identity.lock().await.as_mut() {
                        identity.source_id = scope.source_id();
                    }
                    capture_signal.lock().await.activate(&params, scope);
                }
                match current_session_counters(&listener_slot).await {
                    None => arp::AttemptEvent::ShutdownSignalled, // stop already took the handle
                    Some(counters) => {
                        // Initial start schedules the native pass. Restarts
                        // provoke only native subnets; otherwise wait for ARP
                        // presence/cache verification or explicit Refresh.
                        if restarts_used > 0 {
                            provoke_sweep(&params, &sweep_ips, &deps).await;
                        }
                        match watch_window(
                            &counters,
                            &mut solicitations,
                            params.fence.generation,
                            window_after,
                            &mut shutdown_rx,
                            INITIAL_WINDOW,
                        )
                        .await
                        {
                            None => arp::AttemptEvent::ShutdownSignalled,
                            Some((payload_delta, self_delta)) => {
                                window_after = Some(tokio::time::Instant::now());
                                last_self_delta = self_delta;
                                arp::AttemptEvent::Verdict(arp::capture_health(
                                    payload_delta,
                                    self_delta,
                                ))
                            }
                        }
                    }
                }
            }
            // The capture thread already logged the start failure.
            Some(Ok(Ok(Err(_start_error)))) => arp::AttemptEvent::StartFailed,
            Some(Ok(Err(_channel_closed))) => arp::AttemptEvent::ActivationChannelClosed,
            Some(Err(_elapsed)) => {
                // The blocking thread may still complete the fixed-name
                // start later — retain ownership: park the unconfirmed
                // session so no future start can overlap it.
                park_capture_handle(&listener_slot, &prior_joins).await;
                arp::AttemptEvent::ActivationTimedOut
            }
        };

        // Act on decisions until this attempt resolves. Quiet windows
        // re-measure in place (bounded by MAX_QUIET_WINDOWS); a Restart
        // that faults feeds the fault back through the decision
        // function, which always exhausts.
        loop {
            match arp::next_ladder_step(event, restarts_used) {
                arp::LadderAction::Done => {
                    if restarts_used > 0 {
                        log::info!(
                            "Capture recovered: ARP payload events after restart (attempt {})",
                            restarts_used
                        );
                    }
                    return;
                }
                arp::LadderAction::Rebaseline => {
                    quiet_windows += 1;
                    if quiet_windows == 1 {
                        log::info!(
                            "Capture quiet: no traffic in either direction (link down or idle wire) — watchdog holding, no restart"
                        );
                    }
                    if quiet_windows >= arp::MAX_QUIET_WINDOWS {
                        // The hold has run long enough that "quiet wire"
                        // needs confirming — a session delivering nothing
                        // on a live link is dead, not quiet, and must
                        // resume the ladder rather than end the watch.
                        let link_up = interface::get_by_name(&params.scope.display_name)
                            .await
                            .ok()
                            .map(|i| i.is_up);
                        match arp::quiet_exhaust_event(link_up) {
                            Some(verdict) => {
                                log::warn!(
                                    "Capture quiet for {} windows with the link up — treating the session as dead",
                                    quiet_windows
                                );
                                quiet_windows = 0;
                                event = arp::AttemptEvent::Verdict(verdict);
                                continue;
                            }
                            None => {
                                log::info!(
                                    "Capture quiet with the link down or unreadable — ending the watch; the next discovery start re-arms it"
                                );
                                return;
                            }
                        }
                    }
                    // Another window requires a fresh solicitation in this session.
                    let Some(counters) = current_session_counters(&listener_slot).await else {
                        return; // stop already took the handle
                    };
                    match watch_window(
                        &counters,
                        &mut solicitations,
                        params.fence.generation,
                        window_after,
                        &mut shutdown_rx,
                        INITIAL_WINDOW,
                    )
                    .await
                    {
                        None => return, // shutdown mid-window — a stop wins
                        Some((payload_delta, self_delta)) => {
                            window_after = Some(tokio::time::Instant::now());
                            last_self_delta = self_delta;
                            event = arp::AttemptEvent::Verdict(arp::capture_health(
                                payload_delta,
                                self_delta,
                            ));
                            continue;
                        }
                    }
                }
                arp::LadderAction::Abort => return,
                arp::LadderAction::Exhaust => break 'session,
                arp::LadderAction::Restart(mode) => {
                    log::warn!(
                        "Capture Rx-dead (payload=0, self={}) — restarting capture (attempt {}, scope={:?})",
                        last_self_delta,
                        restarts_used + 1,
                        mode
                    );
                    // Retire the deaf incarnation's fence before tearing
                    // it down: with the flag false, even a wedged thread
                    // can never merge after the replacement attaches.
                    if let Some(identity) = capture_identity.lock().await.as_ref() {
                        identity.active.store(false, Ordering::Relaxed);
                    }
                    capture_signal.lock().await.deactivate();
                    // Tear down the deaf session; a stop that already
                    // took the handle wins.
                    let Some(old_handle) = listener_slot.lock().await.take() else {
                        return;
                    };
                    let mut old_join = old_handle.stop_into_join();
                    if tokio::time::timeout(arp::CAPTURE_JOIN_TIMEOUT, &mut old_join)
                        .await
                        .is_err()
                    {
                        // Wedged capture thread: park it so no future
                        // start can overlap it, and stop laddering.
                        prior_joins.lock().await.push(old_join);
                        event = arp::AttemptEvent::JoinTimedOut;
                        continue;
                    }
                    // A replacement is a fresh incarnation of the same
                    // binding: new lifecycle flag, new lifecycle fence.
                    let incarnation = Arc::new(AtomicBool::new(true));
                    let lifecycle_fence =
                        SweepFence::new(0, Arc::new(AtomicU64::new(0)), incarnation.clone());
                    match arp::start_listener(
                        params.with_fence(lifecycle_fence),
                        mode,
                        &prior_joins,
                    )
                    .await
                    {
                        Err(e) => {
                            log::warn!("Capture restart failed: {}", e);
                            event = arp::AttemptEvent::StartFailed;
                            continue;
                        }
                        Ok((new_handle, new_rx)) => {
                            let mut slot = listener_slot.lock().await;
                            if params.fence.is_stale() {
                                // Discovery stopped or restarted while we
                                // were attaching — the new session belongs
                                // to nobody; tear it straight back down.
                                incarnation.store(false, Ordering::Relaxed);
                                drop(slot);
                                prior_joins.lock().await.push(new_handle.stop_into_join());
                                return;
                            }
                            *slot = Some(new_handle);
                            drop(slot);
                            // Refresh the recorded identity: same
                            // adapter, new incarnation, and any bound
                            // source id is no longer this session's.
                            if let Some(identity) = capture_identity.lock().await.as_mut() {
                                identity.active = incarnation;
                                identity.source_id = None;
                            }
                            restarts_used += 1;
                            activation_rx = new_rx;
                            continue 'session;
                        }
                    }
                }
            }
        }
    }

    // Ladder exhausted — degrade exactly as the pre-ladder watchdog did,
    // then poll (bounded) for late recovery on the live session, if any.
    let missed = arp::missed_max();
    log::warn!(
        "Discovery degraded: no ARP payload events and the capture self-heal is exhausted (payload_total={}, missed_max={}, tasks_dropped={}, noneth_dropped={}, local_mac_dropped={}, prohibited_dropped={})",
        arp::frames_seen(),
        missed,
        arp::tasks_dropped(),
        arp::noneth_dropped(),
        arp::local_mac_dropped(),
        arp::prohibited_dropped()
    );
    log::warn!(
        "event=capture_exhausted adapter_mac={} interface_index={} cause=no_payload {}",
        log_value(
            &params
                .scope
                .mac
                .map(|m| arp::format_mac(&m))
                .unwrap_or_default()
        ),
        params.candidates.as_ref().map_or(0, |c| c.interface_index),
        arp::diagnostic_counts()
    );
    let _ = params.bridge.emit(
        "discovery-degraded",
        serde_json::json!({
            "reason": "no-payload-events",
            "missed_packets": missed,
        }),
    );

    let Some(counters) = current_session_counters(&listener_slot).await else {
        return; // no live session left to watch
    };
    let baseline = counters.snapshot().frames_seen;
    let mut waited = std::time::Duration::ZERO;
    while waited < MAX_WATCH {
        tokio::select! {
            _ = shutdown_rx.changed() => return,
            _ = tokio::time::sleep(POLL) => {}
        }
        waited += POLL;
        if counters.snapshot().frames_seen > baseline {
            log::info!("Discovery recovered: ARP payload events resumed");
            let _ = params
                .bridge
                .emit("discovery-recovered", serde_json::json!({}));
            return;
        }
    }
}

/// Provoke ARP on the selected subnets, then merge the OS neighbor table.
/// Fence-checked throughout. Shared by discovery start (spawned after a
/// short delay so the capture attach lands first) and the capture-restart
/// ladder, which re-provokes so a fresh session has traffic to prove
/// itself against.
pub(super) async fn provoke_sweep(
    params: &arp::ListenerParams,
    sweep_ips: &[String],
    deps: &SweepDeps,
) {
    if params.fence.is_stale() {
        return;
    }
    log::info!("Soliciting selected subnets to populate ARP");
    ping_sweep_subnets(sweep_ips, &params.fence, deps).await;

    // One brief-lock snapshot for the whole merge pass (never lock per
    // entry); a poisoned lock degrades to an empty set, which filters
    // nothing — fail-open.
    let local_snapshot: HashSet<[u8; 6]> = params
        .local_macs
        .lock()
        .map(|s| s.clone())
        .unwrap_or_default();

    // Neighbor observations from the selected pass still enter through the
    // fenced candidate path. Known retained devices use targeted presence.
    for sweep_iface_ip in sweep_ips {
        if params.fence.is_stale() {
            break;
        }
        if sweep_iface_ip.is_empty() {
            continue;
        }
        merge_arp_table(
            params.devices.clone(),
            params.registry.clone(),
            params.emitter.clone(),
            params.bridge.clone(),
            params.config.clone(),
            sweep_iface_ip,
            &[],
            &local_snapshot,
            &params.fence,
            params.candidates.as_ref(),
        )
        .await;
    }
}

/// Solicit ARP on the selected adapter's /24s. On Windows, short TCP probes
/// bind both source and interface, including when Wi-Fi wins the unbound route.
/// Their connect result never establishes presence: the existing ARP capture
/// and fresh-MAC verification pipeline remains the only admission path.
pub(super) async fn ping_sweep_subnets(
    interface_ips: &[String],
    fence: &SweepFence,
    deps: &SweepDeps,
) {
    use tokio::sync::Semaphore;
    use tokio::task::JoinSet;

    // Solicitation has its own bound and never takes device-scan permits.
    const MAX_CONCURRENT_SOLICITATIONS: usize = 32;
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_SOLICITATIONS));
    let mut join_set = JoinSet::new();
    let Some((_, index, adapter_fence)) = deps.selector.probe_scope(&deps.pending) else {
        return;
    };
    let mut solicited = false;
    let local_ips = interface::all_local_ipv4();
    for ip_str in interface_ips {
        let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
            continue;
        };
        if crate::validation::prohibited_camera_ip(ip) {
            continue;
        }
        let o = ip.octets();
        for last in 1..=254 {
            let permit = tokio::select! {
                biased;
                _ = fence.cancelled() => return,
                _ = adapter_fence.cancelled() => return,
                permit = sem.clone().acquire_owned() => match permit { Ok(p) => p, Err(_) => return },
            };
            #[cfg(windows)]
            if !interface::source_matches_interface(index, ip) {
                break;
            }
            let target = Ipv4Addr::new(o[0], o[1], o[2], last);
            if local_ips.contains(&target)
                || interface_ips
                    .iter()
                    .any(|local| local == &target.to_string())
            {
                continue;
            }
            #[cfg(not(windows))]
            if route::egress_index(target).ok() != Some(index) {
                continue;
            }
            if !solicited {
                deps.capture.note_solicitation(fence, &deps.fence()).await;
                solicited = true;
            }
            if fence.is_stale() || adapter_fence.is_stale() {
                return;
            }
            #[cfg(not(windows))]
            let source = ip_str.clone();
            #[cfg(windows)]
            let probe_fence = fence.clone();
            #[cfg(windows)]
            let probe_adapter = adapter_fence.clone();
            join_set.spawn(async move {
                let _permit = permit;
                #[cfg(windows)]
                {
                    if probe_fence.is_stale()
                        || probe_adapter.is_stale()
                        || !interface::source_matches_interface(index, ip)
                    {
                        return;
                    }
                    let Ok(socket) = super::bound_tcp::bind_socket(ip, index) else {
                        return;
                    };
                    // Any TCP port provokes neighbor resolution; no HTTP or
                    // PTU payload is sent, and closed/filtered ports are fine.
                    tokio::select! {
                        biased;
                        _ = probe_fence.cancelled() => {},
                        _ = probe_adapter.cancelled() => {},
                        _ = tokio::time::timeout(std::time::Duration::from_millis(200),
                            socket.connect(std::net::SocketAddrV4::new(target, 80).into())) => {},
                    }
                }
                #[cfg(not(windows))]
                {
                    let mut command = async_cmd("ping");
                    command.kill_on_drop(true);
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        command
                            .args(["-n", "1", "-w", "200", "-S", &source, &target.to_string()])
                            .output(),
                    )
                    .await;
                }
            });
        }
    }
    tokio::select! {
        biased;
        _ = fence.cancelled() => {},
        _ = adapter_fence.cancelled() => {},
        _ = async { while join_set.join_next().await.is_some() {} } => {},
    }
    log::info!("ARP solicitation sweep complete");
}

pub(super) async fn get_interface_ips(name: &str) -> Vec<Ipv4Addr> {
    match interface::get_by_name(name).await {
        Ok(info) => info
            .ips
            .iter()
            .filter_map(|ip| ip.address.parse().ok())
            .collect(),
        Err(_) => vec![],
    }
}

/// Read the OS ARP table and merge entries into the discovered devices map.
/// This catches hosts whose ARP entries were already cached in the OS
/// (e.g. from a prior browser visit), since the ping sweep won't generate
/// new ARP packets on the wire for those hosts.
#[allow(clippy::too_many_arguments)]
pub(super) async fn merge_arp_table(
    devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    registry: Arc<DeviceRegistry>,
    emitter: Arc<DeviceListEmitter>,
    bridge: Arc<dyn crate::bridge::AppBridge>,
    config: Arc<crate::config::AppConfig>,
    interface_ip: &str,
    excluded: &[ipnetwork::Ipv4Network],
    local_macs: &HashSet<[u8; 6]>,
    fence: &SweepFence,
    candidates: Option<&arp::CandidateIngress>,
) {
    // Fence stale-session merges: a sweep from a prior discovery session
    // (or one still running after a stop) must not merge or emit into the
    // current session's shared registry.
    if fence.is_stale() {
        return;
    }

    let entries = arp::read_system_arp_table(interface_ip).await;
    let new_devices = import_neighbors(
        entries,
        &mut *devices.lock().await,
        excluded,
        local_macs,
        fence,
        candidates,
    );

    let mut registry_changed = false;
    for device in &new_devices {
        log::info!("ARP table: {} ({})", device.ip, device.mac);
        let _ = crate::bridge::emit(bridge.as_ref(), "arp-device-discovered", device);
        let result = registry.merge_arp_fenced(device, fence);
        if result.changed {
            registry_changed = true;
        }
        // Mirror same-IP dedup to the on-disk cache so reloads don't
        // resurrect the orphan rows.
        if !result.dropped_macs.is_empty() {
            // Off the executor: remove_cached_device does a synchronous
            // fsync'd cache rewrite under a std lock; on a slow disk during an
            // ARP burst that would stall this worker. Move the eviction to a
            // blocking thread with owned copies of the keys.
            let dropped = result.dropped_macs.clone();
            let survivor = device.mac.clone();
            let config = config.clone();
            let _ = tokio::task::spawn_blocking(move || {
                for mac in &dropped {
                    if let Err(e) = config.remove_cached_device(mac) {
                        log::warn!(
                            "Failed to evict dupe cache row {} (same IP as {}): {}",
                            mac,
                            survivor,
                            e
                        );
                    }
                }
            })
            .await;
        }
    }

    if !new_devices.is_empty() {
        log::info!("Merged {} devices from OS ARP table", new_devices.len());
    }
    // Coalesce all the new entries into one event. The emitter's 150 ms
    // window absorbs both this batch and any concurrent live-ARP merges.
    if registry_changed {
        emitter.poke();
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stop_retires_session_clock_before_joining_adopt_then_watchdog() {
        let session = DiscoverySession::new();
        session.discovery_active.store(true, Ordering::Release);
        *session.discovery_started.lock().unwrap() = Some(std::time::Instant::now());
        let fence = session.sweep_fence();
        let calls = Arc::new(StdMutex::new(Vec::new()));
        let (shutdown, mut rx) = tokio::sync::watch::channel(false);
        let active = session.discovery_active.clone();
        let clock = session.discovery_started.clone();
        let order = calls.clone();
        let join = tokio::spawn(async move {
            rx.changed().await.unwrap();
            assert!(!active.load(Ordering::Acquire));
            assert!(clock.lock().unwrap().is_none());
            order.lock().unwrap().push("adopt");
        });
        *session.auto_adopt_handle.lock().await = Some(AutoAdoptHandle { shutdown, join });
        let (shutdown, mut rx) = tokio::sync::watch::channel(false);
        let order = calls.clone();
        let join = tokio::spawn(async move {
            rx.changed().await.unwrap();
            assert_eq!(*order.lock().unwrap(), ["adopt"]);
            order.lock().unwrap().push("watchdog");
        });
        *session.discovery_watchdog_handle.lock().await = Some(WatchdogHandle { shutdown, join });
        session.stop_session_locked().await;
        assert!(fence.is_stale());
        assert_eq!(*calls.lock().unwrap(), ["adopt", "watchdog"]);
    }
    fn fence(generation: u64, current: u64, active: bool) -> SweepFence {
        SweepFence::new(
            generation,
            Arc::new(AtomicU64::new(current)),
            Arc::new(AtomicBool::new(active)),
        )
    }
    #[tokio::test(start_paused = true)]
    async fn watchdog_waits_for_solicitation_and_rejects_old_attempts() {
        use std::time::Duration;
        let counters = Arc::new(arp::SessionCounters::default());
        let (tx, mut rx) = tokio::sync::watch::channel(None);
        let (shutdown, mut stop) = tokio::sync::watch::channel(false);
        let after = tokio::time::Instant::now();
        let make = |generation, at| Solicitation {
            generation,
            at,
            baseline: counters.snapshot(),
        };
        let c = counters.clone();
        let watch = tokio::spawn(async move {
            watch_window(
                &c,
                &mut rx,
                2,
                Some(after),
                &mut stop,
                Duration::from_secs(10),
            )
            .await
        });
        tokio::time::advance(Duration::from_secs(300)).await;
        assert!(!watch.is_finished(), "idle time cannot start a window");
        tx.send_replace(Some(make(1, tokio::time::Instant::now())));
        tokio::task::yield_now().await;
        tx.send_replace(Some(make(2, after - Duration::from_secs(1))));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(20)).await;
        assert!(
            !watch.is_finished(),
            "old session/capture attempt cannot arm it"
        );
        tx.send_replace(Some(make(2, tokio::time::Instant::now())));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(!watch.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(watch.await.unwrap(), Some((0, 0)));
        drop(shutdown);
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_preserves_pre_send_baseline_and_idle_shutdown_wins() {
        let counters = arp::SessionCounters::default();
        let (tx, mut rx) = tokio::sync::watch::channel(None);
        let (shutdown, mut stop) = tokio::sync::watch::channel(false);
        let at = tokio::time::Instant::now();
        tx.send_replace(Some(Solicitation {
            generation: 1,
            at,
            baseline: counters.snapshot(),
        }));
        tokio::time::advance(std::time::Duration::from_secs(9)).await;
        // A delayed watchdog still expires ten seconds after the send.
        let start = tokio::time::Instant::now();
        assert_eq!(
            watch_window(
                &counters,
                &mut rx,
                1,
                None,
                &mut stop,
                std::time::Duration::from_secs(10)
            )
            .await,
            Some((0, 0))
        );
        assert_eq!(start.elapsed(), std::time::Duration::from_secs(1));
        shutdown.send(true).unwrap();
        assert!(watch_window(
            &counters,
            &mut rx,
            1,
            None,
            &mut stop,
            std::time::Duration::from_secs(10)
        )
        .await
        .is_none());
    }

    #[test]
    fn fence_fresh_session_is_not_stale() {
        assert!(!fence(1, 1, true).is_stale());
    }

    #[test]
    fn fence_superseded_generation_is_stale() {
        // A newer start advanced the generation past this work's capture.
        assert!(fence(1, 2, true).is_stale());
    }

    #[test]
    fn fence_inactive_discovery_is_stale() {
        // A stop with no restart clears `active` without moving the
        // generation (Static Auto -> Manual) — must still read as stale.
        assert!(fence(1, 1, false).is_stale());
    }
}
