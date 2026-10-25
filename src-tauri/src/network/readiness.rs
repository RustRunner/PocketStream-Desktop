//! Narrow shared network reads. Snapshot probes keep try_lock admission.
use super::*;
pub(crate) struct CameraReadiness {
    pub(super) selector: Arc<adapter_selector::AdapterSelector>,
    pub(super) bindings: Arc<binding_store::BindingStore>,
    pub(super) discovery: Arc<discovery_session::DiscoverySession>,
    pub(super) device_registry: Arc<DeviceRegistry>,
    pub(super) device_emitter: Arc<DeviceListEmitter>,
    pub(super) config: Arc<crate::config::AppConfig>,
    // Read-only view of the pinger's former APP initialization gate. It stays
    // enabled after a stop, matching the old process-lifetime OnceLock.
    pub(super) diagnostic_ready: Arc<AtomicBool>,
}

impl CameraReadiness {
    pub(super) fn probe_scope(&self) -> Option<(InterfaceInfo, u32, SweepFence)> {
        self.selector.probe_scope(&self.bindings.pending_ips)
    }

    pub(super) fn camera_path_now(
        &self,
        target: &route::CameraTarget,
        config: &crate::config::AppConfig,
        bound: bool,
    ) -> Result<route::ReadyPath, AppError> {
        if self.selector.presence.tick(&self.device_registry) {
            self.device_emitter.poke();
        }
        let mut target = target.clone();
        // A legacy manual key follows only its persisted first-verification
        // binding. An IP match is never a substitute for an expected MAC.
        if target.key.starts_with("manual:") {
            let node = config.get_manual_nodes().into_iter().find(|n| {
                crate::config::manual_node_key(n) == target.key
                    || format!("manual:{}", n.ip) == target.key
            });
            if let Some(expected) = node.and_then(|n| n.expected_mac) {
                if target
                    .expected_mac
                    .as_ref()
                    .is_some_and(|m| !m.eq_ignore_ascii_case(&expected))
                {
                    return Err(AppError::Network("Manual expected identity changed".into()));
                }
                target.key = expected.clone();
                target.expected_mac = Some(expected);
            }
        }
        let (adapter, index, fence) = self
            .probe_scope()
            .ok_or_else(|| AppError::Network("Selected Ethernet adapter unavailable".into()))?;
        let ip = crate::validation::parse_camera_ip(&target.ip)?;
        let records = self.device_registry.snapshot();
        let source = if bound {
            route::check_bound_ready(&target, Some(&adapter), index, &records)
        } else {
            route::check_ready(
                &target,
                Some(&adapter),
                index,
                &records,
                route::egress_index(ip).ok(),
            )
        }?;
        #[cfg(windows)]
        if !interface::source_matches_interface(index, source) {
            return Err(AppError::Network(
                "Ethernet source address is absent or ambiguous".into(),
            ));
        }
        if fence.is_stale() {
            return Err(AppError::Network("Ethernet adapter changed".into()));
        }
        Ok(route::ReadyPath {
            target,
            source,
            index,
            fence,
        })
    }
    pub(crate) fn bound_now(
        &self,
        target: &route::CameraTarget,
    ) -> Result<route::ReadyPath, AppError> {
        self.camera_path_now(target, &self.config, true)
    }
    pub(crate) async fn ready(
        &self,
        target: &route::CameraTarget,
    ) -> Result<route::ReadyPath, AppError> {
        self.camera_path_now(target, &self.config, false)
    }
    pub(crate) async fn selection(&self) -> AdapterSelection {
        self.selector.snapshot().await
    }
    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<AdapterSelection> {
        self.selector.subscribe()
    }
    pub(crate) async fn adopted_addresses(&self) -> HashSet<String> {
        self.bindings
            .get_adopted_ips()
            .await
            .into_values()
            .collect()
    }
    pub(crate) async fn verified(&self) {
        self.selector.expected_device_verified().await;
    }
    pub(crate) fn records(&self) -> Vec<DeviceRecord> {
        self.device_registry.snapshot()
    }
    pub(crate) async fn diagnostic_probe(&self, ip: &str) -> bool {
        ping_dot::probe(self, ip).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn readiness_and_diagnostic_decline_without_starting_native_work() {
        let manager = NetworkManager::new();
        let readiness = manager.readiness();
        let _lifecycle = manager.discovery_op.lock().await;
        let _address = manager.bindings.address_work.lock().await;
        let _pending = manager.bindings.pending_ips.lock().await;
        let target = route::CameraTarget {
            key: "manual:192.0.2.204".into(),
            expected_mac: None,
            ip: "192.0.2.204".into(),
        };
        assert!(readiness.bound_now(&target).is_err());
        assert!(!readiness.diagnostic_probe(&target.ip).await);
        assert!(readiness.adopted_addresses().await.is_empty());
        assert!(readiness.records().is_empty());
        assert!(readiness.subscribe().borrow().adapter.is_none());
    }
}
