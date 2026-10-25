//! Address ownership and local workflow serialization. The facade holds the
//! lifecycle lock before pausing/admitting writes; native admission remains separate.
use super::*;

pub(super) struct BindingStore {
    config: Arc<crate::config::AppConfig>,
    pub(super) selector: Arc<adapter_selector::AdapterSelector>,
    pub(super) address_io: Arc<dyn interface::AddressIo>,
    pub(super) adopted_ips: Arc<Mutex<HashMap<String, Ipv4Addr>>>,
    /// In-memory working copy of the persisted adoption metadata
    /// (config's `adopted_meta`), stamped through the same choke point
    /// as `adoption_liveness` and flushed coarsely (see `MetaFlush`).
    pub(super) adopted_meta: Arc<std::sync::Mutex<HashMap<String, crate::config::AdoptedMeta>>>,
    /// Secondary IPs the auto-adopt loop has bound but not yet handed over
    /// to `adopted_ips` (scratch probes and unrecorded final adds), tagged
    /// with the owning adoption id. Reconciled on stop so a cancelled or
    /// timed-out adoption never leaks an untracked IP.
    pub(super) pending_ips: auto_adopt::PendingIps,
    /// Monotonic source of adoption ids: each adoption pass takes the next
    /// value to tag its `pending_ips` entries.
    pub(super) adoption_seq: Arc<AtomicU64>,
    /// Session-only positive-liveness clock per adopted subnet: the
    /// monotonic instant of the last accepted ARP frame, successful
    /// targeted scan, or successful ping from a device on the subnet.
    /// Never persisted — wall clock is display-only by design.
    pub(super) adoption_liveness: Arc<std::sync::Mutex<HashMap<String, std::time::Instant>>>,
    /// Flush cadence for metadata-only config writes.
    pub(super) meta_flush: Arc<std::sync::Mutex<MetaFlush>>,
    pub(super) address_work: Arc<Mutex<()>>,
    pub(super) address_generation: Arc<AtomicU64>,
    pub(super) address_active: Arc<AtomicBool>,
}

impl BindingStore {
    pub(super) fn next_adoption_id(&self) -> u64 {
        self.adoption_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// The existing automatic tail calls this only after durable commit and
    /// pending handover, while still holding address_work and both fences.
    pub(super) async fn publish_adoption(
        &self,
        subnet: &str,
        ip: Ipv4Addr,
        row: crate::config::AdoptedMeta,
    ) {
        self.adopted_ips.lock().await.insert(subnet.to_string(), ip);
        if let Ok(mut liveness) = self.adoption_liveness.lock() {
            liveness.insert(subnet.to_string(), std::time::Instant::now());
        }
        if let Ok(mut meta) = self.adopted_meta.lock() {
            meta.insert(subnet.to_string(), row);
        }
    }

    pub(super) fn new(
        config: Arc<crate::config::AppConfig>,
        selector: Arc<adapter_selector::AdapterSelector>,
    ) -> Self {
        Self {
            config,
            selector,
            address_io: Arc::new(interface::RealAddressIo),
            adopted_ips: Arc::new(Mutex::new(HashMap::new())),
            adopted_meta: Arc::new(std::sync::Mutex::new(HashMap::new())),
            pending_ips: Arc::new(Mutex::new(Vec::new())),
            adoption_seq: Arc::new(AtomicU64::new(0)),
            adoption_liveness: Arc::new(std::sync::Mutex::new(HashMap::new())),
            meta_flush: Arc::new(std::sync::Mutex::new(MetaFlush {
                dirty: false,
                last_flush: std::time::Instant::now(),
            })),
            address_work: Arc::new(Mutex::new(())),
            address_generation: Arc::new(AtomicU64::new(1)),
            address_active: Arc::new(AtomicBool::new(true)),
        }
    }
    pub(super) async fn operation_snapshot(
        &self,
        config: &crate::config::AppConfig,
    ) -> Result<interface::OperationSnapshot, AppError> {
        let mac = config
            .get()
            .selected_adapter_mac
            .ok_or_else(|| AppError::Network("Select an Ethernet adapter".into()))?;
        interface::operation_snapshot(self.address_io.as_ref(), &mac).await
    }

    pub(super) async fn operation_snapshot_traced(
        &self,
        config: &crate::config::AppConfig,
        trace: Option<&AddressTrace>,
    ) -> Result<interface::OperationSnapshot, AppError> {
        let mac = config
            .get()
            .selected_adapter_mac
            .ok_or_else(|| AppError::Network("Select an Ethernet adapter".into()))?;
        interface::operation_snapshot_traced(self.address_io.as_ref(), &mac, trace).await
    }

    pub(super) async fn observe_operation_traced(
        &self,
        before: &interface::OperationSnapshot,
        trace: Option<&AddressTrace>,
    ) -> Result<interface::OperationSnapshot, AppError> {
        if let Some(t) = trace {
            t.native_call();
        }
        let all = interface::read_native_with(self.address_io.as_ref()).await?;
        let after =
            interface::snapshot_from_native(self.address_io.as_ref(), &before.selected.mac, all)?;
        if before.selected.identity() != after.selected.identity() {
            return Err(AppError::Network(
                "Selected adapter changed during operation".into(),
            ));
        }
        Ok(after)
    }

    /// Atomic adoption snapshot for the frontend: the live adopted map
    /// plus per-subnet metadata views with staleness derived at call
    /// time from the same clocks the reap pass reads.
    pub async fn adoption_snapshot(
        &self,
        // Read-only clock view; DiscoverySession alone starts/retires it.
        session_started: &StdMutex<Option<std::time::Instant>>,
    ) -> AdoptionSnapshot {
        let (adopted, meta_map) = self.adopted_config_snapshot().await;
        let liveness = self
            .adoption_liveness
            .lock()
            .map(|l| l.clone())
            .unwrap_or_default();
        let session_elapsed = session_started
            .lock()
            .ok()
            .and_then(|s| *s)
            .map(|t| t.elapsed())
            .unwrap_or_default();
        let wall_now = chrono::Utc::now();
        let meta = meta_map
            .keys()
            .map(|subnet| {
                let m = meta_map.get(subnet);
                (
                    subnet.clone(),
                    adoption_meta_view(
                        subnet,
                        m,
                        liveness.get(subnet).map(|t| t.elapsed()),
                        session_elapsed,
                        badge_age(m, wall_now),
                    ),
                )
            })
            .collect();
        AdoptionSnapshot {
            adopted_subnets: adopted,
            meta,
        }
    }

    pub(super) async fn note_verified_liveness(&self, ip: Ipv4Addr, fence: &SweepFence) {
        if fence.is_stale() {
            return;
        }
        let now = std::time::Instant::now();
        let wall = chrono::Utc::now().to_rfc3339();
        let landed = {
            let adopted = self.adopted_ips.lock().await;
            if fence.is_stale() {
                return;
            }
            match (self.adoption_liveness.lock(), self.adopted_meta.lock()) {
                (Ok(mut liveness), Ok(mut meta)) => {
                    record_positive_liveness(ip, &adopted, &mut liveness, &mut meta, now, &wall)
                }
                _ => false,
            }
        };
        if !landed {
            return;
        }
        let flush = self
            .meta_flush
            .lock()
            .map(|mut f| meta_dirty_flush_due(&mut f, now))
            .unwrap_or(false);
        if flush {
            self.flush_adoption_state().await;
        }
    }

    /// Persist liveness stamps only; late flushes cannot change saved intent.
    pub async fn flush_adoption_state(&self) {
        let meta = self
            .adopted_meta
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default();
        let config = self.config.clone();
        let res = tokio::task::spawn_blocking(move || config.update_adoption_liveness(meta)).await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => log::warn!("Failed to persist adoption metadata: {}", e),
            Err(e) => log::warn!("Adoption metadata persist task failed to join: {}", e),
        }
    }

    #[cfg(windows)]
    pub(super) fn hydrate_adoption_history(&self, config: &crate::config::AppConfig) {
        let mut history = self.adopted_meta.lock().unwrap_or_else(|p| p.into_inner());
        for (subnet, mut row) in config.get().adopted_meta {
            row.last_error = Some(
                "Waiting for native startup reconciliation; network changes remain unavailable"
                    .into(),
            );
            history.insert(subnet, row);
        }
    }

    pub(super) fn address_fence(&self) -> SweepFence {
        SweepFence::new(
            self.address_generation.load(Ordering::Acquire),
            self.address_generation.clone(),
            self.address_active.clone(),
        )
    }

    pub(super) fn pause_addresses(&self) -> AddressPause {
        AddressPause::new(self.address_generation.clone(), self.address_active.clone())
    }

    pub(super) async fn publish_binding(
        &self,
        config: &crate::config::AppConfig,
        subnet: &str,
        mut row: crate::config::AdoptedMeta,
    ) -> crate::config::AdoptedMeta {
        if let Err(e) = self.address_io.persist_binding(config, subnet, row.clone()) {
            row.last_error = Some(format!(
                "{}; status save failed: {}",
                row.last_error.as_deref().unwrap_or("OS state observed"),
                e
            ));
        }
        let mut live = self.adopted_ips.lock().await;
        let changed = self
            .adopted_meta
            .lock()
            .map(|meta| meta.get(subnet) != Some(&row))
            .unwrap_or(true);
        if changed {
            log::info!("event=binding_change adapter_mac={} interface_index={} subnet={} address={} desired={:?} applied={} error={} reason={}",
                log_value(row.adapter_mac.as_deref().unwrap_or("unknown")),
                self.selector.adapter_selection.lock().await.interface_index.unwrap_or(0),
                log_value(subnet), log_value(row.address.as_deref().unwrap_or("unknown")),
                row.desired, row.applied, row.last_error.is_some(),
                if row.last_error.is_some() { "pending" } else if row.applied { "applied" } else { "removed" });
        }
        if row.desired == crate::config::BindingDesired::Present
            && row.applied
            && row.last_error.is_none()
        {
            if let Some(ip) = row.address.as_ref().and_then(|a| a.parse().ok()) {
                live.insert(subnet.to_string(), ip);
            }
        } else {
            live.remove(subnet);
        }
        if let Ok(mut meta) = self.adopted_meta.lock() {
            meta.insert(subnet.to_string(), row.clone());
        }
        row
    }

    pub(super) async fn reconcile_bindings_locked(&self, config: &crate::config::AppConfig) {
        self.reconcile_bindings_traced(config, None).await;
    }

    /// Caller holds address_work. A completed deletion may be superseded by
    /// fresh discovery, but pending removals and unknown native state cannot.
    /// Retire the exact saved row before reserving any new temporary address.
    pub(super) async fn prepare_subnet_adoption(
        &self,
        config: &crate::config::AppConfig,
        subnet: &str,
        owner: &str,
        index: u32,
        session: &SweepFence,
        address: &SweepFence,
    ) -> Result<(), AppError> {
        self.address_io.check_writes_available()?;
        let Some(row) = config.get().adopted_meta.get(subnet).cloned() else {
            return Ok(());
        };
        if !row.removal_complete() || session.is_stale() || address.is_stale() {
            return Err(AppError::Network(
                "Saved binding is still pending or present".into(),
            ));
        }
        let snapshot = self.operation_snapshot(config).await?;
        if session.is_stale()
            || address.is_stale()
            || !snapshot.selected.is_up
            || snapshot.selected.dhcp
            || adapter_mac(&snapshot.selected.mac) != adapter_mac(owner)
            || snapshot.selected.index != index
            || row.adapter_mac.as_deref().and_then(adapter_mac) != adapter_mac(owner)
            || !matches!(
                binding_action(
                    subnet,
                    &row,
                    Some(&snapshot.iface),
                    config.get_network_mode(),
                    &Ok(snapshot.selected.dhcp),
                    &[],
                ),
                BindingAction::Observed(false)
            )
        {
            return Err(AppError::Network(
                "Removal absence or selected adapter is unconfirmed".into(),
            ));
        }
        self.address_io
            .forget_completed_removal(config, subnet, &row)?;
        self.adopted_meta
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(subnet);
        self.adopted_ips.lock().await.remove(subnet);
        log::info!("event=adoption_eligible adapter_mac={} interface_index={} subnet={} reason=removal_completed",
            log_value(owner), index, log_value(subnet));
        Ok(())
    }

    pub(super) async fn reconcile_bindings_traced(
        &self,
        config: &crate::config::AppConfig,
        trace: Option<&AddressTrace>,
    ) {
        if self.address_io.check_writes_available().is_err() {
            return;
        }
        let settings = config.get();
        let snapshot = self.operation_snapshot_traced(config, trace).await;
        if let Some(t) = trace {
            t.phase("preflight");
        }
        for (subnet, row) in settings.adopted_meta {
            let context = BindingContext {
                snapshot: &snapshot,
                mode: settings.network_mode,
                trace,
            };
            self.reconcile_binding_row(config, &subnet, row, context, || async {
                let before = snapshot
                    .as_ref()
                    .map_err(|e| AppError::Network(e.to_string()))?;
                Ok(self
                    .observe_operation_traced(before, trace)
                    .await?
                    .selected
                    .ips)
            })
            .await;
        }
    }

    pub(super) async fn reconcile_binding_row<F, Fut>(
        &self,
        config: &crate::config::AppConfig,
        subnet: &str,
        row: crate::config::AdoptedMeta,
        context: BindingContext<'_>,
        observe: F,
    ) -> crate::config::AdoptedMeta
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<interface::IpInfo>, AppError>>,
    {
        let BindingContext {
            snapshot,
            mode,
            trace,
        } = context;
        if let (Some(t), Ok(snapshot)) = (trace, snapshot) {
            t.identity(snapshot, row.prefix);
        }
        let mut action = match snapshot {
            Ok(snapshot) => binding_action(
                subnet,
                &row,
                Some(&snapshot.iface),
                mode,
                &Ok(snapshot.selected.dhcp),
                &interface::native_conflicts(snapshot, self.address_io.as_ref()),
            ),
            Err(error) => BindingAction::Unavailable(error.to_string()),
        };
        if row.desired == crate::config::BindingDesired::Present
            && config.get().adopted_subnets.get(subnet) != row.address.as_ref()
        {
            action =
                BindingAction::Hold("saved routing address and metadata disagree".into(), false);
        }
        let ops = AddressOps(
            self.address_io.as_ref(),
            snapshot.as_ref().ok().map(|s| &s.selected),
        );
        let iface = snapshot.as_ref().ok().map(|s| &s.iface);
        let row = apply_binding(&ops, row, action, iface, observe).await;
        if let Some(t) = trace {
            t.phase("observation");
        }
        let row = self.publish_binding(config, subnet, row).await;
        if let Some(t) = trace {
            t.phase("status_save");
        }
        row
    }

    /// Routes contain only bindings both desired and last observed applied.
    pub(super) async fn adopted_config_snapshot(
        &self,
    ) -> (
        HashMap<String, String>,
        HashMap<String, crate::config::AdoptedMeta>,
    ) {
        let live = self.adopted_ips.lock().await;
        let meta = self.adopted_meta.lock().unwrap_or_else(|e| e.into_inner());
        (merge_adopted_config(&live, &meta), meta.clone())
    }

    /// String forms of every pending (scratch or not-yet-handed-over)
    /// address, for filtering UI-facing interface enumerations.
    pub(crate) async fn pending_ip_strings(&self) -> HashSet<String> {
        self.pending_ips
            .lock()
            .await
            .iter()
            .map(|e| e.ip.to_string())
            .collect()
    }

    pub async fn get_adopted_ips(&self) -> HashMap<String, String> {
        let map = self.adopted_ips.lock().await;
        map.iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect()
    }

    /// Explicit Apply/Add Secondary transfers ownership to the user, including
    /// clearing any tombstone for that exact address. Call under address_work.
    pub(super) async fn claim_binding_locked(
        &self,
        config: &crate::config::AppConfig,
        ip: &str,
        alias: &str,
    ) -> Result<(), AppError> {
        let before = config.get().adopted_meta;
        self.address_io.claim(config, ip)?;
        self.pending_ips
            .lock()
            .await
            .retain(|entry| entry.ip.to_string() != ip || entry.iface != alias);
        let adapter = config.get().selected_adapter_mac;
        log::info!(
            "event=binding_change adapter_mac={} interface_index={} address={} reason=manual_claim",
            log_value(adapter.as_deref().unwrap_or("unknown")),
            self.selector
                .adapter_selection
                .lock()
                .await
                .interface_index
                .unwrap_or(0),
            log_value(ip)
        );
        let saved = config.get().adopted_meta;
        let claimed: HashSet<_> = before
            .keys()
            .filter(|key| !saved.contains_key(*key))
            .cloned()
            .collect();
        self.adopted_ips
            .lock()
            .await
            .retain(|key, _| !claimed.contains(key));
        if let Ok(mut meta) = self.adopted_meta.lock() {
            meta.retain(|key, _| !claimed.contains(key));
        }
        Ok(())
    }

    pub(super) async fn selected_write_adapter(
        &self,
        config: &crate::config::AppConfig,
        name: &str,
    ) -> Result<InterfaceInfo, AppError> {
        let snapshot = self.operation_snapshot(config).await?;
        if snapshot.iface.name != name {
            return Err(AppError::Network(
                "Selected Ethernet adapter unavailable or changed".into(),
            ));
        }
        Ok(snapshot.iface)
    }

    pub(super) async fn reconcile_temporary_locked(&self, config: &crate::config::AppConfig) {
        if self.address_io.check_writes_available().is_err() {
            return;
        }
        use auto_adopt::AdoptOps;
        let saved = config.get().pending_addresses;
        if saved.is_empty() {
            return;
        }
        let adapters = match interface::read_native_with(self.address_io.as_ref()).await {
            Ok(list) => list
                .iter()
                .filter_map(|n| self.address_io.descriptor(n))
                .collect::<Vec<_>>(),
            Err(e) => {
                log::warn!("Temporary cleanup waiting for native state: {e}");
                return;
            }
        };
        for row in saved {
            let Some(ip) = row
                .address
                .parse::<Ipv4Addr>()
                .ok()
                .filter(|ip| !crate::validation::prohibited_camera_ip(*ip))
            else {
                continue;
            };
            if row.prefix != 24 || adapter_mac(&row.adapter_mac).is_none() {
                continue;
            }
            let owners: Vec<_> = adapters
                .iter()
                .filter(|a| {
                    adapter_candidate(a) && adapter_mac(&a.mac) == adapter_mac(&row.adapter_mac)
                })
                .collect();
            let [iface] = owners.as_slice() else {
                continue;
            };
            if iface
                .ips
                .iter()
                .any(|a| a.address == row.address && a.prefix == row.prefix)
            {
                let mut pending = self.pending_ips.lock().await;
                if !pending.iter().any(|p| p.iface == iface.name && p.ip == ip) {
                    pending.push(auto_adopt::PendingIp {
                        iface: iface.name.clone(),
                        ip,
                        adoption_id: self.adoption_seq.fetch_add(1, Ordering::Relaxed) + 1,
                    });
                }
            }
            let ops = auto_adopt::PendingAdoptOps::new(
                config,
                &row.adapter_mac,
                AddressOps(self.address_io.as_ref(), None),
            );
            if let Err(e) = ops.remove(&iface.name, ip).await {
                log::warn!(
                    "Temporary address {}/{} on {} cleanup pending: {}",
                    ip,
                    row.prefix,
                    row.adapter_mac,
                    e
                );
            }
        }
        let remaining = config.get().pending_addresses;
        self.pending_ips
            .lock()
            .await
            .retain(|p| remaining.iter().any(|r| r.address == p.ip.to_string()));
    }

    #[cfg(test)]
    pub(super) async fn cleanup_pending_with<O: auto_adopt::AdoptOps>(&self, ops: &O) {
        let _pause = self.pause_addresses();
        let _address = self.address_work.lock().await;
        auto_adopt::reconcile_pending(ops, &self.pending_ips, None).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn owner_pause_invalidates_old_work_even_when_admission_is_canceled() {
        let store = BindingStore::new(
            Arc::new(crate::config::AppConfig::for_test(Default::default())),
            Arc::new(adapter_selector::AdapterSelector::new()),
        );
        let old = store.address_fence();
        let held = store.address_work.lock().await;
        let pause = store.pause_addresses();
        let during = store.address_fence();
        assert!(old.is_stale() && during.is_stale());
        // Dropping a partially admitted workflow resumes scheduling but never
        // makes an earlier callback/fence current again.
        drop(pause);
        assert!(old.is_stale() && during.is_stale());
        assert!(!store.address_fence().is_stale());
        assert!(store.address_work.try_lock().is_err());
        drop(held);
        assert!(store.address_work.try_lock().is_ok());
    }
    fn adapter(name: &str, ips: &[&str]) -> interface::InterfaceInfo {
        interface::InterfaceInfo {
            name: name.into(),
            display_name: name.into(),
            description: String::new(),
            ips: ips
                .iter()
                .map(|addr| interface::IpInfo {
                    address: (*addr).into(),
                    prefix: 24,
                    subnet: String::new(),
                })
                .collect(),
            mac: String::new(),
            is_up: true,
            is_ethernet: true,
            is_wifi: false,
            is_vpn: false,
            is_virtual: false,
        }
    }
    fn saved_binding(address: &str) -> crate::config::AdoptedMeta {
        crate::config::AdoptedMeta {
            adapter_mac: Some("40:cd:3a:00:00:01".into()),
            address: Some(address.into()),
            prefix: Some(24),
            ..Default::default()
        }
    }

    fn saved_adapter(ips: &[&str]) -> InterfaceInfo {
        let mut iface = adapter("Ethernet", ips);
        iface.mac = "40:cd:3a:00:00:01".into();
        iface
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn binding_on_another_adapter_is_pending_even_if_address_matches() {
        let mut row = saved_binding("172.31.169.253");
        row.adapter_mac = Some("40:cd:3a:00:00:02".into());
        let iface = saved_adapter(&["172.31.169.253"]);
        assert_eq!(
            binding_action(
                "172.31.169.0/24",
                &row,
                Some(&iface),
                crate::config::NetworkMode::StaticAuto,
                &Ok(false),
                &[]
            ),
            BindingAction::Hold("adapter mismatch".into(), false)
        );
    }

    #[test]
    fn stale_applied_flag_does_not_suppress_restore() {
        let mut row = saved_binding("172.31.169.253");
        row.applied = true;
        let iface = saved_adapter(&["192.168.1.20"]);
        assert_eq!(
            binding_action(
                "172.31.169.0/24",
                &row,
                Some(&iface),
                crate::config::NetworkMode::StaticAuto,
                &Ok(false),
                &[]
            ),
            BindingAction::Add(ip("172.31.169.253"), 24)
        );
    }

    #[test]
    fn unavailable_binding_never_moves_to_a_different_adapter() {
        let row = saved_binding("172.31.169.253");
        assert_eq!(
            binding_action(
                "172.31.169.0/24",
                &row,
                None,
                crate::config::NetworkMode::StaticAuto,
                &Ok(false),
                &[]
            ),
            BindingAction::Unavailable("selected adapter unavailable".into())
        );
    }

    #[test]
    fn removal_checks_exact_prefix_instead_of_enumeration_order() {
        let mut row = saved_binding("172.31.169.253");
        row.desired = crate::config::BindingDesired::Removed;
        let mut iface = saved_adapter(&["172.31.169.253", "192.168.1.20"]);
        iface.ips[0].prefix = 16;
        assert_eq!(
            binding_action(
                "172.31.169.0/24",
                &row,
                Some(&iface),
                crate::config::NetworkMode::StaticAuto,
                &Ok(false),
                &[]
            ),
            BindingAction::Hold("address exists with a different prefix".into(), false)
        );
    }

    #[test]
    fn routes_exclude_removed_and_pending_saved_bindings() {
        let mut live = HashMap::new();
        live.insert("10.0.0.0/24".to_string(), Ipv4Addr::new(10, 0, 0, 100));
        let mut meta = HashMap::from([("10.0.0.0/24".into(), saved_binding("10.0.0.100"))]);
        assert!(merge_adopted_config(&live, &meta).is_empty());
        let row = meta.get_mut("10.0.0.0/24").unwrap();
        row.applied = true;
        assert_eq!(merge_adopted_config(&live, &meta).len(), 1);
        meta.get_mut("10.0.0.0/24").unwrap().desired = crate::config::BindingDesired::Removed;
        assert!(merge_adopted_config(&live, &meta).is_empty());
        assert_eq!(meta.len(), 1);
    }

    #[test]
    fn routes_require_the_exact_saved_address() {
        let mut live = HashMap::new();
        live.insert("10.0.0.0/24".to_string(), Ipv4Addr::new(10, 0, 0, 100));
        let mut row = saved_binding("10.0.0.200");
        row.applied = true;
        let meta = HashMap::from([("10.0.0.0/24".into(), row)]);
        assert!(merge_adopted_config(&live, &meta).is_empty());
    }
}
