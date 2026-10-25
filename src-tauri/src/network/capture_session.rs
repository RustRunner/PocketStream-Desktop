//! Persistent capture incarnation and parked native thread joins.
use super::*;

pub(super) struct CaptureSession {
    pub(super) arp_listener_handle: Arc<Mutex<Option<arp::ArpListenerHandle>>>,
    /// Capture threads told to stop but not yet observed dead. Every
    /// capture start drains this (bounded join) before attaching — the
    /// session name is fixed, so two live sessions must never overlap.
    pub(super) prior_capture_joins: arp::PriorCaptureJoins,
    /// What the persistent capture listener is bound to (adapter, data
    /// source, incarnation lifecycle flag). `None` when no listener is
    /// attached.
    pub(super) capture_identity: Arc<Mutex<Option<CaptureIdentity>>>,
    pub(super) capture_signal: Arc<Mutex<CaptureSignal>>,
    pub(super) candidates: Arc<arp::CandidateSet>,
    pub(super) solicitations: tokio::sync::watch::Sender<Option<Solicitation>>,
}
impl CaptureSession {
    pub(super) fn new() -> Self {
        Self {
            arp_listener_handle: Arc::new(Mutex::new(None)),
            prior_capture_joins: Arc::new(Mutex::new(Vec::new())),
            capture_identity: Arc::new(Mutex::new(None)),
            capture_signal: Arc::new(Mutex::new(CaptureSignal::default())),
            candidates: Arc::new(arp::CandidateSet::default()),
            solicitations: tokio::sync::watch::channel(None).0,
        }
    }
    pub(super) async fn note_solicitation(&self, work: &SweepFence, fence: &SweepFence) {
        if work.is_stale() || fence.is_stale() {
            return;
        }
        if let Some(counters) = current_session_counters(&self.arp_listener_handle).await {
            if !work.is_stale() && !fence.is_stale() {
                self.solicitations.send_replace(Some(Solicitation {
                    generation: fence.generation,
                    at: tokio::time::Instant::now(),
                    baseline: counters.snapshot(),
                }));
            }
        }
    }
    /// Attach, keep, or replace the persistent capture listener so it
    /// matches the requested adapter. Runs under `discovery_op` (every
    /// caller holds it). Returns an already-resolved activation channel
    /// for the watchdog: on attach/replace this method awaited the real
    /// activation itself; on keep the retained listener proved
    /// activation when it originally attached.
    pub(super) async fn ensure_capture_listener(
        &self,
        iface_name: &str,
        own_mac: Option<[u8; 6]>,
        iface_is_up: bool,
        base_params: &arp::ListenerParams,
        preserve_capture: bool,
    ) -> Result<arp::ActivationRx, AppError> {
        let has_listener = self.arp_listener_handle.lock().await.is_some();
        let same_adapter = {
            let identity = self.capture_identity.lock().await;
            identity
                .as_ref()
                .is_some_and(|c| c.iface_name == iface_name && c.mac == own_mac)
        };
        // Probe the live data-source id only when a matching listener
        // could be kept — its sole job is catching the source being
        // re-created underneath a retained binding (id churn after
        // driver-level adapter events).
        let live = if has_listener && same_adapter {
            let scope = base_params.scope.clone();
            match tokio::task::spawn_blocking(move || pktmon::live_source_id_for(&scope)).await {
                Ok(Ok(id)) => LiveSourceId::Enumerated(id),
                Ok(Err(e)) => {
                    log::debug!(
                        "Data-source liveness probe failed ({}) — keeping the listener",
                        e
                    );
                    LiveSourceId::EnumFailed
                }
                Err(e) => {
                    log::debug!(
                        "Data-source liveness probe did not complete ({}) — keeping the listener",
                        e
                    );
                    LiveSourceId::EnumFailed
                }
            }
        } else {
            LiveSourceId::EnumFailed
        };
        let action = {
            let identity = self.capture_identity.lock().await;
            mode_capture_action(
                listener_action(identity.as_ref(), has_listener, iface_name, own_mac, live),
                preserve_capture,
            )
        };

        let retained_outcome = self.capture_signal.lock().await.state.outcome.clone();
        if let (ListenerAction::Keep, Some(outcome)) = (action, retained_outcome) {
            log::info!("ARP capture retained across discovery restart");
            let (tx, rx) = tokio::sync::oneshot::channel();
            // The watchdog only cares that activation succeeded; the
            // retained session proved that when it attached.
            let _ = tx.send(Ok(outcome));
            return Ok(rx);
        }
        if let ListenerAction::Replace(reason) = action {
            log::info!("ARP capture replaced ({})", reason);
        }

        // Retire the old incarnation before tearing it down: with the
        // flag already false, even a wedged capture thread can never
        // merge again once the replacement attaches.
        if let Some(old) = self.capture_identity.lock().await.take() {
            old.active.store(false, Ordering::Relaxed);
        }
        self.capture_signal.lock().await.deactivate();
        self.candidates.clear();
        park_capture_handle(&self.arp_listener_handle, &self.prior_capture_joins).await;

        let incarnation = Arc::new(AtomicBool::new(true));
        let lifecycle_fence = SweepFence::new(0, Arc::new(AtomicU64::new(0)), incarnation.clone());
        let (handle, activation_rx) = arp::start_listener(
            base_params.with_fence(lifecycle_fence),
            pktmon::CaptureMode::PreferScoped,
            &self.prior_capture_joins,
        )
        .await?;
        *self.arp_listener_handle.lock().await = Some(handle);

        // Confirm activation here rather than leaving it to the
        // watchdog: the recorded identity must describe a live binding,
        // and an unconfirmed session is parked exactly as the watchdog's
        // activation-timeout arm parks one. The incarnation flag goes
        // false on every failure path so a late-activating stray can
        // never merge.
        let outcome =
            match tokio::time::timeout(arp::CAPTURE_ACTIVATION_TIMEOUT, activation_rx).await {
                Ok(Ok(Ok(outcome))) => outcome,
                Ok(Ok(Err(start_error))) => {
                    incarnation.store(false, Ordering::Relaxed);
                    park_capture_handle(&self.arp_listener_handle, &self.prior_capture_joins).await;
                    return Err(AppError::Network(format!(
                        "ARP capture session failed to start: {}",
                        start_error
                    )));
                }
                Ok(Err(_channel_closed)) => {
                    incarnation.store(false, Ordering::Relaxed);
                    park_capture_handle(&self.arp_listener_handle, &self.prior_capture_joins).await;
                    return Err(AppError::Network(
                        "ARP capture thread died before confirming activation".into(),
                    ));
                }
                Err(_elapsed) => {
                    incarnation.store(false, Ordering::Relaxed);
                    park_capture_handle(&self.arp_listener_handle, &self.prior_capture_joins).await;
                    return Err(AppError::Network(
                        "ARP capture session did not confirm activation in time".into(),
                    ));
                }
            };

        if !iface_is_up {
            if !matches!(outcome, pktmon::ScopeOutcome::SelectedInterface { .. }) {
                // A media-disconnected attach must be scoped-only: an
                // unscoped session hears every adapter, and with the
                // wire down nothing refreshes the shared self/ghost
                // filters — WiFi-side ARP could leak in as phantom
                // nodes. Park it and wait for the next trigger.
                incarnation.store(false, Ordering::Relaxed);
                park_capture_handle(&self.arp_listener_handle, &self.prior_capture_joins).await;
                log::info!(
                    "ARP pre-attach skipped: MAC-scoped join unavailable ({:?}) — retrying on the next discovery trigger",
                    outcome
                );
                let (tx, rx) = tokio::sync::oneshot::channel();
                let _ = tx.send(Ok(outcome));
                return Ok(rx);
            }
            log::info!(
                "ARP capture pre-attached on '{}' — listening before link-up",
                iface_name
            );
        }

        let source_id = outcome.source_id();
        *self.capture_identity.lock().await = Some(CaptureIdentity {
            iface_name: iface_name.to_string(),
            mac: own_mac,
            source_id,
            active: incarnation,
        });
        self.capture_signal
            .lock()
            .await
            .activate(base_params, outcome.clone());

        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = tx.send(Ok(outcome));
        Ok(rx)
    }

    /// Stop the capture half: retire the incarnation's fence flag, park
    /// the capture thread's join, clear the recorded identity.
    pub(super) async fn stop_capture_locked(&self) {
        // Flag first, park second — a wedged thread that outlives the
        // park can never merge once its incarnation is retired.
        if let Some(identity) = self.capture_identity.lock().await.take() {
            identity.active.store(false, Ordering::Relaxed);
        }
        self.capture_signal.lock().await.deactivate();
        self.candidates.clear();
        if let Some(h) = self.arp_listener_handle.lock().await.take() {
            // Signal shutdown and park the capture thread's join in the
            // guard — the next capture start bounded-joins it there, so
            // stop itself never blocks on the blocking thread.
            self.prior_capture_joins
                .lock()
                .await
                .push(h.stop_into_join());
            log::info!("ARP capture stopped");
        }
    }

    pub(super) fn candidate_ingress(
        &self,
        index: u32,
        mac: Option<[u8; 6]>,
    ) -> Option<arp::CandidateIngress> {
        Some(arp::CandidateIngress {
            store: self.candidates.clone(),
            interface_index: index,
            adapter_mac: mac.unwrap_or([0; 6]),
        })
    }

    pub async fn get_capture_state(&self) -> CaptureState {
        let mut state = self.capture_signal.lock().await.state.clone();
        state.candidate_count = self.candidates.count(std::time::Instant::now());
        state
    }
}
#[derive(Default)]
pub(super) struct CaptureSignal {
    pub(super) state: CaptureState,
    pub(super) app: Option<Arc<dyn crate::bridge::AppBridge>>,
}

impl CaptureSignal {
    pub(super) fn activate(&mut self, params: &arp::ListenerParams, outcome: pktmon::ScopeOutcome) {
        let scope = match &outcome {
            pktmon::ScopeOutcome::SelectedInterface { .. } => "selected_interface",
            pktmon::ScopeOutcome::ScopedByName { .. } => "scoped_by_name",
            pktmon::ScopeOutcome::UnscopedFallback { .. } => "unscoped",
        };
        log::info!("event=capture_state adapter_mac={} interface_index={} scope={} source_id={:?} active=true",
            log_value(&params.scope.mac.map(|m| arp::format_mac(&m)).unwrap_or_default()),
            params.candidates.as_ref().map_or(0, |c| c.interface_index), scope, outcome.source_id());
        self.app = Some(params.bridge.clone());
        self.state = CaptureState {
            active: true,
            candidate_count: params
                .candidates
                .as_ref()
                .map_or(0, |i| i.store.count(std::time::Instant::now())),
            adapter_name: Some(params.scope.display_name.clone()),
            outcome: Some(outcome),
        };
        self.emit();
    }

    pub(super) fn deactivate(&mut self) {
        if self.state.active {
            self.state.active = false;
            self.emit();
        }
    }

    fn emit(&self) {
        if let Some(app) = &self.app {
            let _ = crate::bridge::emit(app.as_ref(), "capture-active", &self.state);
        }
    }
}

/// The current capture session's counters, if a session is installed.
pub(super) async fn current_session_counters(
    slot: &Arc<Mutex<Option<arp::ArpListenerHandle>>>,
) -> Option<Arc<arp::SessionCounters>> {
    slot.lock().await.as_ref().map(|h| h.counters())
}

/// Take the installed capture handle, signal it to stop, and park its
/// join in the prior-capture guard — ownership is retained; the next
/// capture start bounded-joins it there.
pub(super) async fn park_capture_handle(
    slot: &Arc<Mutex<Option<arp::ArpListenerHandle>>>,
    prior: &arp::PriorCaptureJoins,
) {
    if let Some(h) = slot.lock().await.take() {
        prior.lock().await.push(h.stop_into_join());
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stop_retires_callback_before_parking_join_without_waiting_for_it() {
        let capture = CaptureSession::new();
        let old = identity(Some(7));
        let fence = SweepFence::new(0, Arc::new(AtomicU64::new(0)), old.active.clone());
        *capture.capture_identity.lock().await = Some(old.clone());
        let (release, waiting) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = waiting.await;
        });
        let (listener, mut shutdown) = arp::ArpListenerHandle::for_test(task);
        *capture.arp_listener_handle.lock().await = Some(listener);
        capture.stop_capture_locked().await;
        assert!(!old.active.load(Ordering::Acquire));
        shutdown.changed().await.unwrap();
        assert!(*shutdown.borrow());
        assert!(capture.capture_identity.lock().await.is_none());
        assert_eq!(capture.prior_capture_joins.lock().await.len(), 1);
        assert!(!capture.prior_capture_joins.lock().await[0].is_finished());
        let ingress = capture.candidate_ingress(7, old.mac).unwrap();
        ingress.observe(
            "192.0.2.204".parse().unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 2],
            &fence,
            std::time::Instant::now(),
        );
        assert_eq!(capture.candidates.count(std::time::Instant::now()), 0);
        release.send(()).unwrap();
        arp::drain_prior_capture(&capture.prior_capture_joins)
            .await
            .unwrap();
        assert!(capture.prior_capture_joins.lock().await.is_empty());
    }
    fn identity(source_id: Option<u32>) -> CaptureIdentity {
        CaptureIdentity {
            iface_name: "Ethernet".into(),
            mac: Some([0x40, 0xcd, 0x3a, 0x00, 0x00, 0x01]),
            source_id,
            active: Arc::new(AtomicBool::new(true)),
        }
    }

    #[tokio::test]
    async fn capture_state_starts_inactive_without_an_outcome() {
        let manager = NetworkManager::new();
        let state = manager.get_capture_state().await;
        assert!(!state.active);
        assert!(state.outcome.is_none());
        assert!(state.adapter_name.is_none());
    }

    #[test]
    fn capture_stop_keeps_last_scope_outcome_for_the_query() {
        let mut signal = CaptureSignal {
            state: CaptureState {
                active: true,
                candidate_count: 0,
                adapter_name: Some("Ethernet".into()),
                outcome: Some(pktmon::ScopeOutcome::ScopedByName { source_id: 42 }),
            },
            app: None,
        };
        signal.deactivate();
        signal.deactivate();
        let state = serde_json::to_value(&signal.state).unwrap();
        assert_eq!(state["active"], false);
        assert_eq!(state["adapter_name"], "Ethernet");
        assert_eq!(state["outcome"]["scope"], "scoped_by_name");
        assert_eq!(state["outcome"]["source_id"], 42);
    }

    #[test]
    fn dhcp_to_auto_preserves_only_valid_capture_and_other_modes_restart() {
        use crate::config::NetworkMode::{Dhcp, StaticAuto, StaticManual};
        for from in [Dhcp, StaticAuto, StaticManual] {
            for to in [Dhcp, StaticAuto, StaticManual] {
                assert_eq!(
                    mode_keeps_capture(from, to),
                    from == Dhcp && to == StaticAuto
                );
            }
        }
        let current = identity(None);
        let decide = |current: Option<&CaptureIdentity>, has_handle| {
            mode_capture_action(
                listener_action(
                    current,
                    has_handle,
                    "Ethernet",
                    identity(None).mac,
                    LiveSourceId::Enumerated(42),
                ),
                true,
            )
        };
        assert_eq!(decide(Some(&current), true), ListenerAction::Keep);
        assert_eq!(decide(Some(&current), false), ListenerAction::Attach);
        assert_eq!(decide(None, false), ListenerAction::Attach);
        let changed = identity(Some(41));
        assert_eq!(
            decide(Some(&changed), true),
            ListenerAction::Replace("data source changed")
        );
        let mut other = identity(None);
        other.iface_name = "Dock".into();
        assert_eq!(
            decide(Some(&other), true),
            ListenerAction::Replace("adapter changed")
        );
        current.active.store(false, Ordering::Release);
        assert_eq!(
            decide(Some(&current), true),
            ListenerAction::Replace("capture inactive")
        );
        assert_eq!(
            mode_capture_action(ListenerAction::Replace("retry scoped attach"), false),
            ListenerAction::Replace("retry scoped attach")
        );
    }

    #[test]
    fn listener_action_attaches_when_nothing_is_bound() {
        let current = identity(Some(101));
        // No identity at all → attach.
        assert_eq!(
            listener_action(
                None,
                false,
                "Ethernet",
                current.mac,
                LiveSourceId::EnumFailed
            ),
            ListenerAction::Attach
        );
        // Identity without a live handle (a torn-down session whose
        // reinstall failed) must attach, never keep.
        assert_eq!(
            listener_action(
                Some(&current),
                false,
                "Ethernet",
                current.mac,
                LiveSourceId::Enumerated(101)
            ),
            ListenerAction::Attach
        );
    }

    #[test]
    fn listener_action_keeps_a_healthy_binding() {
        let current = identity(Some(101));
        assert_eq!(
            listener_action(
                Some(&current),
                true,
                "Ethernet",
                current.mac,
                LiveSourceId::Enumerated(101)
            ),
            ListenerAction::Keep
        );
        // Enumeration failure fails open to Keep — a transient fault
        // must never churn a healthy listener.
        assert_eq!(
            listener_action(
                Some(&current),
                true,
                "Ethernet",
                current.mac,
                LiveSourceId::EnumFailed
            ),
            ListenerAction::Keep
        );
    }

    #[test]
    fn listener_action_replaces_an_invalidated_binding() {
        let current = identity(Some(101));
        // Renamed adapter.
        assert_eq!(
            listener_action(
                Some(&current),
                true,
                "Ethernet 2",
                current.mac,
                LiveSourceId::Enumerated(101)
            ),
            ListenerAction::Replace("adapter changed")
        );
        // Same name, different MAC (hardware swapped under the name).
        assert_eq!(
            listener_action(
                Some(&current),
                true,
                "Ethernet",
                Some([0x2c, 0xa5, 0x9c, 0x00, 0x00, 0x02]),
                LiveSourceId::Enumerated(101)
            ),
            ListenerAction::Replace("adapter changed")
        );
        // Data-source churn under the same adapter.
        assert_eq!(
            listener_action(
                Some(&current),
                true,
                "Ethernet",
                current.mac,
                LiveSourceId::Enumerated(115)
            ),
            ListenerAction::Replace("data source changed")
        );
    }

    #[test]
    fn listener_action_unscoped_session_retries_scoped() {
        let unscoped = identity(None);
        // A live id exists → re-attempt the scoped join.
        assert_eq!(
            listener_action(
                Some(&unscoped),
                true,
                "Ethernet",
                unscoped.mac,
                LiveSourceId::Enumerated(101)
            ),
            ListenerAction::Replace("retry scoped attach")
        );
        // No live id → keep the unscoped session over churning.
        assert_eq!(
            listener_action(
                Some(&unscoped),
                true,
                "Ethernet",
                unscoped.mac,
                LiveSourceId::EnumFailed
            ),
            ListenerAction::Keep
        );
    }

    #[test]
    fn lifecycle_fence_stales_only_on_its_incarnation_flag() {
        // The listener's fence pins generation zero against a
        // permanently-zero counter, so staleness is exactly the
        // incarnation flag — a discovery restart (generation advance)
        // must not fence out a retained listener.
        let flag = Arc::new(AtomicBool::new(true));
        let lifecycle = SweepFence::new(0, Arc::new(AtomicU64::new(0)), flag.clone());
        assert!(!lifecycle.is_stale());
        flag.store(false, Ordering::Relaxed);
        assert!(lifecycle.is_stale());
    }
}

/// A fresh look at the data source the capture scope would bind today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveSourceId {
    /// Native enumeration found this id for the adapter.
    Enumerated(u32),
    /// Enumeration was unavailable or failed. Fails open — a transient
    /// enumeration fault must never churn a healthy listener.
    EnumFailed,
}

/// What `ensure_capture_listener` does with the listener slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerAction {
    Attach,
    Keep,
    Replace(&'static str),
}

/// Pure decision for the capture-listener slot: keep a healthy binding,
/// replace an invalidated one, attach when none exists. `has_listener`
/// is the handle slot's occupancy — a recorded identity without a live
/// handle (a torn-down session whose reinstall failed) must attach, not
/// keep.
pub(crate) fn listener_action(
    current: Option<&CaptureIdentity>,
    has_listener: bool,
    desired_iface: &str,
    desired_mac: Option<[u8; 6]>,
    live: LiveSourceId,
) -> ListenerAction {
    let Some(current) = current else {
        return ListenerAction::Attach;
    };
    if !has_listener {
        return ListenerAction::Attach;
    }
    if !current.active.load(Ordering::Acquire) {
        return ListenerAction::Replace("capture inactive");
    }
    if current.iface_name != desired_iface || current.mac != desired_mac {
        return ListenerAction::Replace("adapter changed");
    }
    match (current.source_id, live) {
        // No live id to compare against — keep what runs.
        (_, LiveSourceId::EnumFailed) => ListenerAction::Keep,
        // An unscoped-fallback session never outlives the next start:
        // every ensure re-attempts the scoped join.
        (None, LiveSourceId::Enumerated(_)) => ListenerAction::Replace("retry scoped attach"),
        (Some(bound), LiveSourceId::Enumerated(live_id)) if bound != live_id => {
            ListenerAction::Replace("data source changed")
        }
        _ => ListenerAction::Keep,
    }
}

pub(super) fn mode_capture_action(action: ListenerAction, preserve: bool) -> ListenerAction {
    match (action, preserve) {
        (ListenerAction::Replace("retry scoped attach"), true) => ListenerAction::Keep,
        _ => action,
    }
}
