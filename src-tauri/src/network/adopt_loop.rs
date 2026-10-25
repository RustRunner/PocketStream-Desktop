//! Existing adoption loop and probe seams, with explicit owner dependencies.
use super::discovery_session::{get_interface_ips, merge_arp_table, ping_sweep_subnets};
use super::*;
/// Hard ceiling on a single adoption attempt. A probe can take ~11 s (1 s
/// ping + up to a 10 s neighbor lookup) across up to 11 candidates, so the
/// natural worst case is tens of seconds; 45 s bounds a pathological run
/// without thrashing the cooldown on a merely slow box. On timeout the adopt
/// caller is dropped (requesting cancellation). Its child is drained before
/// cleanup; uncertain effects keep conflicting writes blocked for recovery.
const ADOPT_MAX_TOTAL: std::time::Duration = std::time::Duration::from_secs(45);

/// Settle delay before an adoption is announced finished, covering the NIC
/// watcher's ~300 ms debounce so the final IP-change up-event is gated too.
const ADOPTION_SETTLE: std::time::Duration = std::time::Duration::from_millis(300);

/// Cooldown for subnets whose adoption FAILED (transient netsh errors, a
/// candidate that turned out to be in use, etc.). Replaces the old
/// permanent blacklist: subnet -> (next retry time, current backoff),
/// backoff doubling from 60 s, capped at 10 min. Shared by the adoption
/// tail and the reap pass's failure backoff.
const COOLDOWN_INITIAL: std::time::Duration = std::time::Duration::from_secs(60);
const COOLDOWN_MAX: std::time::Duration = std::time::Duration::from_secs(600);

/// RAII gate around a single adoption. On creation it emits
/// `adoption-started`; on drop — normal completion OR a dropped/aborted
/// future — it emits `adoption-finished` after a short settle. The frontend
/// suppresses watcher-driven discovery/stream restarts between the two so
/// the adoption's own IP churn (scratch bind/release, final add) is not
/// mistaken for a reconnect. The `adoption_id` lets the frontend ignore a
/// stale finish from a superseded adoption.
struct AdoptionGate {
    app_handle: Arc<dyn crate::bridge::AppBridge>,
    adoption_id: u64,
}

impl AdoptionGate {
    fn start(app_handle: Arc<dyn crate::bridge::AppBridge>, adoption_id: u64) -> Self {
        let _ = app_handle.emit(
            "adoption-started",
            serde_json::json!({ "adoption_id": adoption_id.to_string() }),
        );
        Self {
            app_handle,
            adoption_id,
        }
    }
}

impl Drop for AdoptionGate {
    fn drop(&mut self) {
        let app_handle = self.app_handle.clone();
        let adoption_id = self.adoption_id;
        let emit_finished = move || {
            let _ = app_handle.emit(
                "adoption-finished",
                serde_json::json!({ "adoption_id": adoption_id.to_string() }),
            );
        };
        // Drop can't await the settle, so run it on a short task; fall back
        // to an immediate emit if there is no runtime handle (e.g. during
        // shutdown) so the gate is never left stuck closed on the frontend.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    tokio::time::sleep(ADOPTION_SETTLE).await;
                    emit_finished();
                });
            }
            Err(_) => emit_finished(),
        }
    }
}

/// Long-lived clones the shared adoption tail needs, built once at
/// adopt-task start from the clones the task already owns. Lets the
/// broadcast dwell path and the cache probe drive one tail without a
/// dozen-argument signature.
pub(super) struct AdoptionCtx {
    pub(super) sweep: SweepDeps,
    pub(super) iface_name: String,
    pub(super) adapter_mac: String,
    pub(super) interface_index: u32,
    pub(super) candidates: Option<arp::CandidateIngress>,
    pub(super) config: Arc<crate::config::AppConfig>,
    pub(super) bridge: Arc<dyn crate::bridge::AppBridge>,
    pub(super) bindings: Arc<binding_store::BindingStore>,
    /// Read-only live-route view for loop decisions; BindingStore publishes it.
    pub(super) adopted: Arc<Mutex<HashMap<String, Ipv4Addr>>>,
    /// Existing mutable AdoptOps adapter; durable intent remains cleanup authority.
    pub(super) pending_ips: auto_adopt::PendingIps,
    /// Legacy callback map owned by DiscoverySession; adoption only reads it.
    pub(super) devices: Arc<Mutex<HashMap<String, ArpDevice>>>,
    pub(super) registry: Arc<DeviceRegistry>,
    pub(super) emitter: Arc<DeviceListEmitter>,
    /// Read-only session view; only DiscoverySession advances this epoch.
    pub(super) fence: SweepFence,
    /// Read-only address pause view, refreshed at the existing iteration gate.
    pub(super) address_fence: SweepFence,
    /// Synchronous callback view owned/refreshed by AdapterSelector.
    pub(super) local_macs: Arc<std::sync::Mutex<HashSet<[u8; 6]>>>,
}

/// Why an adoption attempt is justified. Logged only — `adopted_meta`
/// keeps its two-field schema; provenance has no consumer.
enum AdoptionEvidence {
    /// The dwell gate matured: two accepted broadcast frames.
    DwellMature { mac: String },
    /// The cache probe got a solicited, freshly MAC-verified reply from
    /// a device we have history with — strictly stronger evidence than
    /// two spontaneous frames, which is what justifies bypassing dwell.
    CachedMacMatch { cached_ip: Ipv4Addr, mac: String },
    /// A live first sighting confirmed by a directed on-link probe: the
    /// device answered a fresh ARP from the scratch with the same MAC
    /// the sighted frame carried. The solicited reply substitutes for
    /// the dwell gate's second spontaneous frame — freshness and
    /// identity-consistency evidence, so a stale or stray frame with no
    /// live sender behind it can never reach adoption.
    FreshSightingConfirmed { probed_ip: Ipv4Addr, mac: String },
}

impl std::fmt::Display for AdoptionEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdoptionEvidence::DwellMature { mac } => {
                write!(f, "confirmed by a repeat observation from {}", mac)
            }
            AdoptionEvidence::CachedMacMatch { cached_ip, mac } => {
                write!(f, "cached device {} freshly verified at {}", mac, cached_ip)
            }
            AdoptionEvidence::FreshSightingConfirmed { probed_ip, mac } => {
                write!(
                    f,
                    "fresh sighting {} confirmed by a directed probe at {}",
                    mac, probed_ip
                )
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdoptionAttemptOutcome {
    Adopted,
    NoOp,
    Failed,
    /// A stop raced the attempt — the caller must exit its loop.
    ShutdownRace,
}

/// The shared adoption tail: gate, bounded `adopt_subnet`, and every
/// success/failure consequence (liveness seed, metadata, events, pending
/// handover, post-adoption sweeps, config persist, cooldown handling).
/// Driven by the broadcast dwell path and the cache probe; the evidence
/// says which. Deliberately has no access to the dwell tracker — the
/// probe path must never touch it, so it stays at the broadcast site.
#[allow(clippy::too_many_arguments)]
async fn attempt_adoption(
    ctx: &AdoptionCtx,
    device_ip: Ipv4Addr,
    device_subnet: &str,
    evidence: AdoptionEvidence,
    current_ips: &[Ipv4Addr],
    cooldowns: &mut HashMap<String, (std::time::Instant, std::time::Duration)>,
    known_subnets: &mut HashSet<String>,
    shutdown_rx: &tokio::sync::watch::Receiver<bool>,
) -> AdoptionAttemptOutcome {
    let config = ctx.config.clone();
    let ops = auto_adopt::PendingAdoptOps::new(&config, &ctx.adapter_mac, auto_adopt::RealAdoptOps);
    if ctx.fence.is_stale()
        || ctx.address_fence.is_stale()
        || config.get_network_mode() != crate::config::NetworkMode::StaticAuto
    {
        return AdoptionAttemptOutcome::NoOp;
    }
    if crate::validation::prohibited_camera_ip(device_ip) {
        return AdoptionAttemptOutcome::NoOp;
    }
    if let Err(error) = ctx
        .bindings
        .prepare_subnet_adoption(
            &config,
            device_subnet,
            &ctx.adapter_mac,
            ctx.interface_index,
            &ctx.fence,
            &ctx.address_fence,
        )
        .await
    {
        log::debug!("Adoption deferred for {}: {}", device_subnet, error);
        return AdoptionAttemptOutcome::NoOp;
    }

    log::info!("Foreign subnet {} — adopting ({})", device_subnet, evidence);

    let adoption_id = ctx.bindings.next_adoption_id();
    // Bracket the adoption with started/finished so the frontend
    // suppresses restarts from its own IP churn. The guard emits
    // `adoption-finished` on drop, so every terminal path below
    // (success, timeout, error, shutdown race, task abort) releases the
    // gate.
    let _gate = AdoptionGate::start(ctx.bridge.clone(), adoption_id);
    // Fresh read at adoption time (not the shared filter set):
    // candidate-collision checking wants the newest possible view of our
    // own addresses. This allocation check intentionally uses IPs; discovery
    // identity checks use the local adapter MACs instead.
    let host_ips_now = interface::all_local_ipv4();
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        ADOPT_MAX_TOTAL,
        auto_adopt::adopt_subnet(
            &ops,
            &ctx.iface_name,
            device_ip,
            current_ips,
            &host_ips_now,
            &ctx.pending_ips,
            adoption_id,
            shutdown_rx,
        ),
    )
    .await;

    match outcome {
        Err(_elapsed) => {
            // Dropping the caller requests cancellation. Drain the executor
            // before attempting cleanup; an uncertain result retains its
            // barrier and durable intent rather than authorizing a retry.
            #[cfg(windows)]
            native_operations::drain().await;
            log::warn!(
                "Adoption of {} exceeded the {}s bound (elapsed {}s) — dropped and reconciling",
                device_subnet,
                ADOPT_MAX_TOTAL.as_secs(),
                started.elapsed().as_secs()
            );
            auto_adopt::reconcile_pending(&ops, &ctx.pending_ips, Some(adoption_id)).await;
            let next_backoff = cooldowns
                .get(device_subnet)
                .map(|(_, b)| (*b * 2).min(COOLDOWN_MAX))
                .unwrap_or(COOLDOWN_INITIAL);
            cooldowns.insert(
                device_subnet.to_string(),
                (std::time::Instant::now() + next_backoff, next_backoff),
            );
            AdoptionAttemptOutcome::Failed
        }
        Ok(Ok(Some(adopted_ip))) => {
            // A stop may have raced the successful final bind. If so,
            // roll the IP back and do NOT record — recording an IP the
            // stop path won't clean is worse than re-adopting on the
            // next start.
            if *shutdown_rx.borrow() || ctx.fence.is_stale() || ctx.address_fence.is_stale() {
                log::info!(
                    "Shutdown raced adoption of {} — rolling back {}",
                    device_subnet,
                    adopted_ip
                );
                auto_adopt::reconcile_pending(&ops, &ctx.pending_ips, Some(adoption_id)).await;
                return AdoptionAttemptOutcome::ShutdownRace;
            }
            let adoption_wall = chrono::Utc::now().to_rfc3339();
            let row = crate::config::AdoptedMeta {
                adopted_at: Some(adoption_wall.clone()),
                last_device_seen: Some(adoption_wall.clone()),
                adapter_mac: adapter_mac(&ctx.adapter_mac),
                address: Some(adopted_ip.to_string()),
                prefix: Some(24),
                applied: true,
                ..Default::default()
            };
            // Commit before handover. A failed save leaves only this attempt's
            // pending breadcrumb, which is rolled back without touching saved IPs.
            if let Err(e) = commit_pending_address(
                &ctx.pending_ips,
                &ctx.iface_name,
                adopted_ip,
                adoption_id,
                || {
                    if ctx.fence.is_stale()
                        || ctx.address_fence.is_stale()
                        || config
                            .get()
                            .selected_adapter_mac
                            .as_deref()
                            .and_then(adapter_mac)
                            != adapter_mac(&ctx.adapter_mac)
                    {
                        return Err(AppError::Network(
                            "Adapter or address work changed before commit".into(),
                        ));
                    }
                    config.set_binding(device_subnet, row.clone())
                },
            )
            .await
            {
                log::warn!("Adoption commit failed for {}: {}", device_subnet, e);
                auto_adopt::reconcile_pending(&ops, &ctx.pending_ips, Some(adoption_id)).await;
                return AdoptionAttemptOutcome::Failed;
            }
            cooldowns.remove(device_subnet);
            ctx.bindings
                .publish_adoption(device_subnet, adopted_ip, row.clone())
                .await;
            known_subnets.insert(device_subnet.to_string());

            let _ = ctx.bridge.emit(
                "subnet-adopted",
                adoption_event(
                    device_subnet,
                    &adopted_ip.to_string(),
                    &adoption_meta_view(
                        device_subnet,
                        Some(&row),
                        Some(std::time::Duration::ZERO),
                        std::time::Duration::ZERO,
                        None,
                    ),
                    false,
                ),
            );

            log::info!("event=binding_change adapter_mac={} interface_index={} subnet={} address={} desired=Present applied=true reason=adopted",
                log_value(&ctx.adapter_mac), ctx.interface_index, log_value(device_subnet), adopted_ip);

            // One bounded pass after the new binding settles. Presence handles
            // later verification; a quiet adopted subnet is not swept repeatedly.
            let sweep_ip = adopted_ip.to_string();
            let sweep_devices = ctx.devices.clone();
            let sweep_registry = ctx.registry.clone();
            let sweep_emitter = ctx.emitter.clone();
            let sweep_bridge = ctx.sweep.bridge.clone();
            let sweep_config = ctx.sweep.config.clone();
            let sweep_deps = ctx.sweep.clone();
            let sweep_fence = ctx.fence.clone();
            let sweep_candidates = ctx.candidates.clone();
            let sweep_local = ctx.local_macs.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                if sweep_fence.is_stale() {
                    return;
                }
                ping_sweep_subnets(std::slice::from_ref(&sweep_ip), &sweep_fence, &sweep_deps)
                    .await;
                let local_snapshot: HashSet<[u8; 6]> =
                    sweep_local.lock().map(|s| s.clone()).unwrap_or_default();
                merge_arp_table(
                    sweep_devices.clone(),
                    sweep_registry.clone(),
                    sweep_emitter.clone(),
                    sweep_bridge.clone(),
                    sweep_config.clone(),
                    &sweep_ip,
                    &[],
                    &local_snapshot,
                    &sweep_fence,
                    sweep_candidates.as_ref(),
                )
                .await;
            });

            AdoptionAttemptOutcome::Adopted
        }
        Ok(Ok(None)) => {
            // Already on subnet, or a clean shutdown-before-bind.
            // Nothing was left bound.
            cooldowns.remove(device_subnet);
            known_subnets.insert(device_subnet.to_string());
            if *shutdown_rx.borrow() {
                AdoptionAttemptOutcome::ShutdownRace
            } else {
                AdoptionAttemptOutcome::NoOp
            }
        }
        Ok(Err(e)) => {
            // adopt_subnet cleaned its own breadcrumbs except a scratch
            // whose release failed; reconcile this id to catch that.
            // Cooldown instead of a permanent blacklist so a transient
            // failure is retried.
            auto_adopt::reconcile_pending(&ops, &ctx.pending_ips, Some(adoption_id)).await;
            let next_backoff = cooldowns
                .get(device_subnet)
                .map(|(_, b)| (*b * 2).min(COOLDOWN_MAX))
                .unwrap_or(COOLDOWN_INITIAL);
            cooldowns.insert(
                device_subnet.to_string(),
                (std::time::Instant::now() + next_backoff, next_backoff),
            );
            log::warn!(
                "Failed to auto-adopt {} ({}); retrying in {}s",
                device_subnet,
                e,
                next_backoff.as_secs()
            );
            let _ = ctx.bridge.emit(
                "adoption-failed",
                serde_json::json!({
                    "subnet": device_subnet,
                    "error": e.to_string(),
                }),
            );
            AdoptionAttemptOutcome::Failed
        }
    }
}

/// Settle wait after binding an identity scratch, covering Windows
/// duplicate-address detection (~1 s per DAD transmit, three transmits
/// by default) so `SendARP` sourced from the scratch actually transmits.
const SCRATCH_SETTLE: std::time::Duration = std::time::Duration::from_secs(3);

/// Which adoption path is driving a probe pass. Picks the evidence
/// variant a hand-off carries and the prefix its log lines wear, so
/// fast-adopt activity never masquerades as cache-probe activity in
/// field logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProbeOrigin {
    CacheProbe,
    FastAdopt,
}

impl ProbeOrigin {
    fn label(self) -> &'static str {
        match self {
            ProbeOrigin::CacheProbe => "Cache probe",
            ProbeOrigin::FastAdopt => "Fast adopt",
        }
    }
}

/// Evidence for a probe-confirmed adoption, keyed by which path ran the
/// probe. Pure so the mapping stays testable — `RealProbeIo` itself
/// cannot be constructed in lib tests.
fn probe_evidence(origin: ProbeOrigin, ip: Ipv4Addr, mac: &str) -> AdoptionEvidence {
    match origin {
        ProbeOrigin::CacheProbe => AdoptionEvidence::CachedMacMatch {
            cached_ip: ip,
            mac: mac.to_string(),
        },
        ProbeOrigin::FastAdopt => AdoptionEvidence::FreshSightingConfirmed {
            probed_ip: ip,
            mac: mac.to_string(),
        },
    }
}

/// Production `ProbeIo`: scratch discipline via the auto-adopt
/// breadcrumb helpers, fresh resolution via `ResolveIpNetEntry2`, and the
/// shared adoption tail for hand-offs.
pub(super) struct RealProbeIo<'a> {
    pub(super) ctx: &'a AdoptionCtx,
    pub(super) cooldowns: &'a mut HashMap<String, (std::time::Instant, std::time::Duration)>,
    pub(super) known_subnets: &'a mut HashSet<String>,
    pub(super) shutdown_rx: &'a tokio::sync::watch::Receiver<bool>,
    /// Adoption id minted for the currently-bound identity scratch.
    pub(super) scratch_id: Option<u64>,
    /// Set when a hand-off observed a shutdown race; the adopt loop
    /// must break after the pass returns.
    pub(super) stop: bool,
    /// Who is driving this pass — evidence variant and log prefix.
    pub(super) origin: ProbeOrigin,
}

impl cache_probe::ProbeIo for RealProbeIo<'_> {
    fn interface_index(&self) -> u32 {
        self.ctx.interface_index
    }

    async fn bind_scratch(&mut self, subnet: &str, scratch: Ipv4Addr) -> bool {
        let config = self.ctx.config.clone();
        let ops = auto_adopt::PendingAdoptOps::new(
            &config,
            &self.ctx.adapter_mac,
            auto_adopt::RealAdoptOps,
        );
        if self.shutdown()
            || self.ctx.address_fence.is_stale()
            || config.get_network_mode() != crate::config::NetworkMode::StaticAuto
            || !matches!(
                ip_config::get_dhcp_state(&self.ctx.iface_name).await,
                Ok(false)
            )
        {
            return false;
        }
        if let Err(error) = self
            .ctx
            .bindings
            .prepare_subnet_adoption(
                &config,
                subnet,
                &self.ctx.adapter_mac,
                self.ctx.interface_index,
                &self.ctx.fence,
                &self.ctx.address_fence,
            )
            .await
        {
            log::info!(
                "{}: probe deferred for {}: {}",
                self.origin.label(),
                subnet,
                error
            );
            return false;
        }
        if self.shutdown() || config.get_network_mode() != crate::config::NetworkMode::StaticAuto {
            return false;
        }

        let id = self.ctx.bindings.next_adoption_id();
        match auto_adopt::bind_scratch(
            &ops,
            &self.ctx.pending_ips,
            &self.ctx.iface_name,
            scratch,
            id,
        )
        .await
        {
            Ok(()) => {
                log::info!(
                    "{}: bound scratch {} for {}",
                    self.origin.label(),
                    scratch,
                    subnet
                );
                self.scratch_id = Some(id);
                // A freshly bound address sits in duplicate-address
                // detection (tentative) for ~1–3 s and is not usable as
                // an ARP source until that clears — the same window the
                // post-adoption sweep documents for its first pass. The
                // conflict-probe path absorbs it across its multi-
                // candidate loop; the identity probe gets one explicit
                // settle, counted against the pass budget.
                tokio::time::sleep(SCRATCH_SETTLE).await;
                true
            }
            Err(e) => {
                log::info!(
                    "{}: scratch bind failed for {}: {}",
                    self.origin.label(),
                    subnet,
                    e
                );
                false
            }
        }
    }

    async fn release_scratch(&mut self, _subnet: &str, scratch: Ipv4Addr) {
        let config = self.ctx.config.clone();
        let ops = auto_adopt::PendingAdoptOps::new(
            &config,
            &self.ctx.adapter_mac,
            auto_adopt::RealAdoptOps,
        );
        if let Some(id) = self.scratch_id.take() {
            auto_adopt::release_scratch(
                &ops,
                &self.ctx.pending_ips,
                &self.ctx.iface_name,
                scratch,
                id,
            )
            .await;
        }
    }

    async fn resolve(
        &mut self,
        target: Ipv4Addr,
        scratch: Ipv4Addr,
        interface_index: u32,
    ) -> Result<Option<String>, ()> {
        if interface_index != self.ctx.interface_index || self.ctx.fence.is_stale() {
            return Err(());
        }
        // Logged at info per outcome — a silent miss here cost a field
        // session; the pass touches at most a handful of pairs.
        // The join owner retains this permit even if its session is dropped.
        static LIMIT: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
            std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(2)));
        let permit = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            LIMIT.clone().acquire_owned(),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
        if self.ctx.fence.is_stale() {
            return Err(());
        }
        self.ctx
            .sweep
            .capture
            .note_solicitation(&self.ctx.fence, &self.ctx.sweep.fence())
            .await;
        if self.ctx.fence.is_stale() {
            return Err(());
        }
        let native = tokio::spawn(async move {
            let _permit = permit;
            arp::fresh_resolve_mac(target, scratch, interface_index).await
        });
        // Timing out the join leaves its owner alive with the permit. A slow
        // OS call cannot stall the pass or create unbounded replacement work.
        let resolved = tokio::time::timeout(std::time::Duration::from_secs(8), native)
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
        if self.ctx.fence.is_stale() {
            return Err(());
        }
        log::debug!("event=identity_probe adapter_mac={} interface_index={} target={} source={} answered={} {}",
            log_value(&self.ctx.adapter_mac), interface_index, target, scratch,
            matches!(&resolved, Ok(Some(_))), arp::diagnostic_counts());
        match resolved {
            Ok(Some(mac)) if is_local_mac(&mac, &interface::local_adapter_macs()) => {
                log::info!(
                    "{}: {} resolved to local adapter {}; ignoring host traffic",
                    self.origin.label(),
                    target,
                    mac
                );
                Ok(None)
            }
            Ok(Some(mac)) => {
                log::info!("{}: {} answered with {}", self.origin.label(), target, mac);
                Ok(Some(mac))
            }
            Ok(None) => {
                log::info!(
                    "{}: {} did not answer a fresh ARP",
                    self.origin.label(),
                    target
                );
                Ok(None)
            }
            Err(e) => {
                log::info!(
                    "{}: fresh resolve of {} failed closed: {}",
                    self.origin.label(),
                    target,
                    e
                );
                Err(())
            }
        }
    }

    async fn adopt(&mut self, subnet: &str, ip: Ipv4Addr, mac: &str) -> bool {
        // Fresh read after the identity scratch was released, so the
        // adoption's own `already_on_subnet` check cannot see it and
        // silently no-op.
        let current_ips = get_interface_ips(&self.ctx.iface_name).await;
        let outcome = attempt_adoption(
            self.ctx,
            ip,
            subnet,
            probe_evidence(self.origin, ip, mac),
            &current_ips,
            self.cooldowns,
            self.known_subnets,
            self.shutdown_rx,
        )
        .await;
        if outcome == AdoptionAttemptOutcome::ShutdownRace {
            self.stop = true;
            return false;
        }
        true
    }

    fn shutdown(&self) -> bool {
        *self.shutdown_rx.borrow() || self.ctx.fence.is_stale() || self.ctx.address_fence.is_stale()
    }
}

pub(super) async fn run(
    mut ctx: AdoptionCtx,
    known_ips: Vec<String>,
    bindings: Arc<binding_store::BindingStore>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    ctx.address_fence = bindings.address_fence();
    let iface_name = ctx.iface_name.clone();
    let devices = ctx.devices.clone();
    let adopted = ctx.adopted.clone();
    let address_work_for_adopt = bindings.address_work.clone();
    let address_generation = bindings.address_generation.clone();
    let address_active = bindings.address_active.clone();
    // Read-only metadata view for existing cache-probe admission; BindingStore publishes it.
    let meta_for_adopt = bindings.adopted_meta.clone();
    // Cached-device probe: at most one pass per discovery
    // session, deferred (not consumed) while the DHCP gate is
    // closed. Identity misses land in the attempted set, never
    // in the shared cooldowns.
    let mut cache_probe_done = false;
    let mut cache_probe_attempted: HashSet<String> = HashSet::new();
    let mut known_subnets: HashSet<String> = HashSet::new();
    // Two-observation gate: a subnet is adopted only after its
    // triggering device produces a second accepted ARP frame, so
    // a single spurious frame (which sits in the persistent
    // device map forever) can no longer bind a secondary IP.
    let mut dwell = auto_adopt::DwellTracker::new();
    // Mark subnets we already have IPs on as known
    for ip_str in &known_ips {
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            let o = ip.octets();
            known_subnets.insert(format!("{}.{}.{}.0/24", o[0], o[1], o[2]));
        }
    }

    // DHCP-state cache: re-reading via PowerShell on every iteration
    // would spam Get-NetIPInterface every 2s. Cache for 5s — short
    // enough that a user toggling Static via the dialog sees adoption
    // resume promptly.
    let mut cached_dhcp_state: Option<(bool, std::time::Instant)> = None;
    let mut last_dhcp_pause = None;
    const DHCP_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);

    // Failed-adoption backoff (module-level COOLDOWN_* constants).
    // Successful/already-adopted subnets use known_subnets
    // (permanent) as before.
    let mut cooldowns: HashMap<String, (std::time::Instant, std::time::Duration)> = HashMap::new();

    // Structural-ghost guard state. `ghost_until` is a short-lived
    // per-subnet ignore set: a ghost row can sit in `arp_devices`
    // forever (entries never expire), so re-check it at most once per
    // GHOST_SUBNET_RECHECK instead of every 2 s tick. Being TTL'd —
    // unlike the permanent `known_subnets` — a subnet becomes
    // adoptable again within one recheck once its WiFi/VPN/virtual
    // owner goes away. `cached_ghosts` memoizes the enumerated
    // non-wired network list so a surviving candidate doesn't spawn a
    // PowerShell adapter query every pass.
    let mut ghost_until: HashMap<String, std::time::Instant> = HashMap::new();
    let mut cached_ghosts: Option<(Vec<ipnetwork::Ipv4Network>, std::time::Instant)> = None;
    const GHOST_SUBNET_RECHECK: std::time::Duration = std::time::Duration::from_secs(300);
    const GHOST_NETS_TTL: std::time::Duration = std::time::Duration::from_secs(30);

    loop {
        // Shutdown-aware idle: wake on the 2 s tick or the moment a
        // stop is signalled, and exit promptly either way.
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
            res = shutdown_rx.changed() => {
                if res.is_err() {
                    break;
                }
            }
        }
        if *shutdown_rx.borrow() {
            break;
        }
        let next_address_fence = SweepFence::new(
            address_generation.load(Ordering::Acquire),
            address_generation.clone(),
            address_active.clone(),
        );
        let _address = address_work_for_adopt.lock().await;
        #[cfg(windows)]
        if native_operations::check_writes_available().is_err() {
            continue;
        }
        if next_address_fence.is_stale() {
            continue;
        }
        if ctx.fence.is_stale() || *shutdown_rx.borrow() {
            break;
        }
        if ctx.address_fence.generation != next_address_fence.generation {
            // A manual add/remove can invalidate permanent session
            // knowledge without restarting capture or discovery.
            known_subnets.clear();
            dwell = auto_adopt::DwellTracker::new();
            cache_probe_done = false;
            cache_probe_attempted.clear();
            cached_dhcp_state = None;
        }
        ctx.address_fence = next_address_fence;

        // Refresh local MAC identities as adapters come and go. Runs
        // before the DHCP gate below so the set stays fresh even
        // while adoption is paused. In-memory IP Helper read — no
        // process spawn, so no TTL cache is needed. An empty read
        // (transient enumeration failure) keeps the previous set
        // rather than blanking the filter mid-session.
        ctx.sweep.selector.refresh_observed_local_macs();

        // Committed bindings, including APIPA, live until explicit deletion.
        // Only PendingIps scratch/uncommitted entries are cleanup candidates.

        // DHCP never adds an address, including in APIPA-only state.
        // Failed DHCP-state reads pause all address changes.
        let needs_refresh = cached_dhcp_state
            .map(|(_, t)| t.elapsed() > DHCP_CACHE_TTL)
            .unwrap_or(true);
        let is_dhcp = if needs_refresh {
            match ip_config::get_dhcp_state(&iface_name).await {
                Ok(d) => {
                    cached_dhcp_state = Some((d, std::time::Instant::now()));
                    d
                }
                Err(e) => {
                    log::debug!(
                        "DHCP-state probe failed for {} ({}), pausing adoption",
                        iface_name,
                        e
                    );
                    // Cache the fail-open verdict with the same TTL
                    // as a success — otherwise a persistent probe
                    // failure re-spawns PowerShell every 2s instead
                    // of every 5s.
                    cached_dhcp_state = Some((true, std::time::Instant::now()));
                    true
                }
            }
        } else {
            cached_dhcp_state.map(|(d, _)| d).unwrap_or(true)
        };

        let current_ips = if is_dhcp {
            get_interface_ips(&iface_name).await
        } else {
            Vec::new()
        };
        let pause = dhcp_adoption_pause(is_dhcp, &current_ips);
        if let Some(reason) = pause {
            if pause != last_dhcp_pause
                && current_ips
                    .iter()
                    .all(|ip| crate::validation::prohibited_camera_ip(*ip))
            {
                let reason = format!("{reason} on {iface_name}");
                log::warn!("Discovery degraded: {reason}");
                let _ = ctx.bridge.emit(
                    "discovery-degraded",
                    serde_json::json!({
                        "reason": reason,
                        "missed_packets": 0,
                    }),
                );
            }
            last_dhcp_pause = pause;
            continue;
        }
        last_dhcp_pause = None;

        // Cached-device on-link probe: runs on the first tick the
        // DHCP gate allows adoption at all (the `continue` above
        // keeps it pending, so a DHCP→Static transition still
        // gets its pass). Rediscovers quiet known devices in
        // seconds instead of waiting for their spontaneous
        // broadcast ARP, which can be minutes apart on a quiet camera.
        if !cache_probe_done {
            cache_probe_done = true;
            let cached_records = {
                let config = &ctx.config;
                config.get_cache()
            };
            if !cached_records.is_empty() {
                let native_subnets: HashSet<String> = get_interface_ips(&iface_name)
                    .await
                    .iter()
                    .map(|ip| {
                        let o = ip.octets();
                        format!("{}.{}.{}.0/24", o[0], o[1], o[2])
                    })
                    .collect();
                let adopted_keys: HashSet<String> = adopted.lock().await.keys().cloned().collect();
                let pending_keys: HashSet<String> = meta_for_adopt
                    .lock()
                    .map(|m| {
                        m.iter()
                            .filter(|(_, row)| !row.removal_complete())
                            .map(|(subnet, _)| subnet.clone())
                            .collect()
                    })
                    .unwrap_or_default();
                let ghost_nets = ghost::non_wired_interface_networks().await;
                cached_ghosts = Some((ghost_nets.clone(), std::time::Instant::now()));
                let candidates = cache_probe::derive_candidates(
                    &cached_records,
                    &native_subnets,
                    &adopted_keys,
                    &pending_keys,
                    &ghost_nets,
                    &cache_probe_attempted,
                );
                if !candidates.is_empty() {
                    log::info!(
                        "Cache probe: verifying {} candidate subnet(s) from the device cache",
                        candidates.len()
                    );
                    let mut io = RealProbeIo {
                        ctx: &ctx,
                        cooldowns: &mut cooldowns,
                        known_subnets: &mut known_subnets,
                        shutdown_rx: &shutdown_rx,
                        scratch_id: None,
                        stop: false,
                        origin: ProbeOrigin::CacheProbe,
                    };
                    let report = cache_probe::run_pass(
                        &mut io,
                        candidates,
                        cache_probe::CACHE_PROBE_PASS_BUDGET,
                    )
                    .await;
                    let stop = io.stop;
                    log::info!(
                        "Cache probe pass finished: attempted={:?}, adopted={:?}",
                        report.attempted,
                        report.handed_off
                    );
                    cache_probe_attempted.extend(report.attempted);
                    if !report.skipped_at_budget.is_empty() {
                        log::warn!(
                            "Cache probe hit its {}s budget — skipped subnets (their broadcast path still applies): {:?}",
                            cache_probe::CACHE_PROBE_PASS_BUDGET.as_secs(),
                            report.skipped_at_budget
                        );
                    }
                    if stop {
                        break;
                    }
                }
            }
        }

        let device_list: Vec<ArpDevice> = {
            let map = devices.lock().await;
            map.values().cloned().collect()
        };

        for device in &device_list {
            if *shutdown_rx.borrow() {
                break;
            }
            let device_ip: Ipv4Addr = match device.ip.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };

            if crate::validation::prohibited_camera_ip(device_ip) {
                continue;
            }

            // Derive the subnet from the live IP rather than trusting
            // a stored subnet left over from a previous address.
            let o = device_ip.octets();
            let device_subnet = format!("{}.{}.{}.0/24", o[0], o[1], o[2]);

            if known_subnets.contains(&device_subnet) {
                continue;
            }

            if adopted.lock().await.contains_key(&device_subnet) {
                known_subnets.insert(device_subnet.clone());
                continue;
            }

            // Refresh current IPs (may have changed since startup)
            let current_ips = get_interface_ips(&iface_name).await;

            if auto_adopt::already_on_subnet(device_ip, &current_ips) {
                known_subnets.insert(device_subnet.clone());
                continue;
            }

            // Still cooling down from a recent failed attempt? Skip
            // until the retry time; a fresh success/failure below
            // clears or re-arms it.
            if let Some(&(retry_at, _)) = cooldowns.get(&device_subnet) {
                if std::time::Instant::now() < retry_at {
                    continue;
                }
            }

            if ctx.candidates.is_none() {
                // Legacy structural-ghost guard: avoid a subnet owned by an
                // up non-wired local interface (WiFi/VPN/virtual), even if
                // its ARP reached the unscoped capture. Only candidates
                // that already cleared known/adopted/native/cooldown get
                // here — i.e. rarely — so the enumeration cost is bounded
                // by the two TTLs.
                if let Some(until) = ghost_until.get(&device_subnet) {
                    if std::time::Instant::now() < *until {
                        continue;
                    }
                }
                let ghosts_fresh = cached_ghosts
                    .as_ref()
                    .map(|(_, t)| t.elapsed() < GHOST_NETS_TTL)
                    .unwrap_or(false);
                if !ghosts_fresh {
                    let nets = ghost::non_wired_interface_networks().await;
                    cached_ghosts = Some((nets, std::time::Instant::now()));
                }
                let ghost_nets: &[ipnetwork::Ipv4Network] = cached_ghosts
                    .as_ref()
                    .map(|(n, _)| n.as_slice())
                    .unwrap_or(&[]);
                if ghost::is_structural_ghost_ip(device_ip, ghost_nets)
                    || ghost::is_structural_ghost_adoption(&device_subnet, ghost_nets)
                {
                    log::info!(
                        "Skipping ghost subnet {} (owned by non-wired local interface)",
                        device_subnet
                    );
                    // TTL only — never poison the permanent `known_subnets`
                    // set, so the subnet is adoptable again after one
                    // recheck once WiFi/VPN/virtual goes down.
                    ghost_until.insert(
                        device_subnet.clone(),
                        std::time::Instant::now() + GHOST_SUBNET_RECHECK,
                    );
                    continue;
                }
            }

            // All structural gates cleared — now require a second
            // accepted frame from this device before binding.
            // `last_seen` is rewritten on every accepted frame,
            // so it serves as the observation token.
            match dwell.check(
                &device_subnet,
                &device.mac,
                &device.last_seen,
                std::time::Instant::now(),
            ) {
                auto_adopt::DwellVerdict::Started => {
                    log::info!(
                        "Foreign subnet detected: {} — holding adoption until {} is observed again",
                        device_subnet,
                        device.mac
                    );
                    // Solicit the second observation instead of
                    // waiting out the device's beacon cadence: a
                    // directed probe answered with the sighted MAC
                    // is the repeat observation. A miss changes
                    // nothing — the candidacy above stays armed and
                    // the passive path remains the fallback, so the
                    // probe must never touch the cooldown map.
                    let Some(mac) = arp::normalize_mac(&device.mac) else {
                        continue;
                    };
                    log::info!(
                        "Fast adopt: soliciting confirmation from {} ({}) on {}",
                        device_ip,
                        mac,
                        device_subnet
                    );
                    let candidate = cache_probe::ProbeCandidate {
                        subnet: device_subnet.clone(),
                        pairs: vec![(device_ip, mac)],
                    };
                    let mut io = RealProbeIo {
                        ctx: &ctx,
                        cooldowns: &mut cooldowns,
                        known_subnets: &mut known_subnets,
                        shutdown_rx: &shutdown_rx,
                        scratch_id: None,
                        stop: false,
                        origin: ProbeOrigin::FastAdopt,
                    };
                    let report = cache_probe::run_pass(
                        &mut io,
                        vec![candidate],
                        cache_probe::FAST_ADOPT_PROBE_BUDGET,
                    )
                    .await;
                    if report.handed_off.is_empty() {
                        log::info!(
                            "Fast adopt: {} did not confirm — leaving the two-observation gate armed",
                            device_ip
                        );
                    } else {
                        log::info!("Fast adopt: {} confirmed by directed probe", device_subnet);
                        dwell.prune_subnet(&device_subnet);
                    }
                    // One probe per pass: the probe consumed this
                    // iteration's slot whatever the outcome, and the
                    // devices not reached keep their own `Started`
                    // for a later tick. A shutdown observed by the
                    // hand-off exits via the loop head's check, the
                    // same way the ShutdownRace break below does.
                    break;
                }
                auto_adopt::DwellVerdict::Waiting => continue,
                auto_adopt::DwellVerdict::Mature => {}
            }

            let outcome = attempt_adoption(
                &ctx,
                device_ip,
                &device_subnet,
                AdoptionEvidence::DwellMature {
                    mac: device.mac.clone(),
                },
                &current_ips,
                &mut cooldowns,
                &mut known_subnets,
                &shutdown_rx,
            )
            .await;

            // Whatever the attempt's outcome, this subnet's dwell
            // candidacy is spent — a later approach (post-cooldown
            // retry, removal then re-appearance) restarts the
            // two-observation gate. Dwell stays at this call site:
            // the probe path must never touch the tracker.
            dwell.prune_subnet(&device_subnet);
            if outcome == AdoptionAttemptOutcome::ShutdownRace {
                break;
            }
        }
    }
    log::info!("Auto-adopt loop exited");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn aborting_adoption_caller_keeps_paired_finish_after_settle() {
        let bridge = Arc::new(crate::bridge::RecordingBridge::default());
        let task_bridge = bridge.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let caller = tokio::spawn(async move {
            let _gate = AdoptionGate::start(task_bridge, 42);
            started.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        tokio::task::yield_now().await;
        assert_eq!(bridge.0.lock().unwrap().len(), 1);
        tokio::time::advance(ADOPTION_SETTLE).await;
        tokio::task::yield_now().await;
        let events = bridge.0.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            ["adoption-started", "adoption-finished"]
        );
        assert_eq!(events[0].1, events[1].1);
        assert_eq!(events[1].1["adoption_id"], "42");
    }
    #[test]
    fn probe_evidence_maps_each_origin_to_its_variant() {
        let ip: Ipv4Addr = "172.31.169.61".parse().unwrap();
        assert!(matches!(
            probe_evidence(ProbeOrigin::CacheProbe, ip, "2c:a5:9c:2b:a9:fc"),
            AdoptionEvidence::CachedMacMatch { cached_ip, ref mac }
                if cached_ip == ip && mac == "2c:a5:9c:2b:a9:fc"
        ));
        assert!(matches!(
            probe_evidence(ProbeOrigin::FastAdopt, ip, "2c:a5:9c:2b:a9:fc"),
            AdoptionEvidence::FreshSightingConfirmed { probed_ip, ref mac }
                if probed_ip == ip && mac == "2c:a5:9c:2b:a9:fc"
        ));
    }

    #[test]
    fn adoption_evidence_display_names_each_justification() {
        let ip: Ipv4Addr = "172.31.169.61".parse().unwrap();
        assert_eq!(
            AdoptionEvidence::DwellMature {
                mac: "aa:bb:cc:dd:ee:ff".into()
            }
            .to_string(),
            "confirmed by a repeat observation from aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(
            AdoptionEvidence::CachedMacMatch {
                cached_ip: ip,
                mac: "aa:bb:cc:dd:ee:ff".into()
            }
            .to_string(),
            "cached device aa:bb:cc:dd:ee:ff freshly verified at 172.31.169.61"
        );
        assert_eq!(
            AdoptionEvidence::FreshSightingConfirmed {
                probed_ip: ip,
                mac: "aa:bb:cc:dd:ee:ff".into()
            }
            .to_string(),
            "fresh sighting aa:bb:cc:dd:ee:ff confirmed by a directed probe at 172.31.169.61"
        );
    }
}
