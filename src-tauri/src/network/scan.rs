//! Duplicate-scan admission and cancellation-safe session-fenced scans.
use super::*;
/// RAII guard that removes a subnet from the active-scan set on drop, so a
/// cancelled `scan_subnet` future can't leave the subnet permanently marked
/// "scan in progress" (which would reject every later scan of it for the
/// process lifetime). Uses the std mutex so `Drop` can remove synchronously.
struct ScanGuard {
    active: Arc<std::sync::Mutex<HashSet<String>>>,
    subnet: String,
}

impl Drop for ScanGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = self.active.lock() {
            set.remove(&self.subnet);
        }
    }
}

pub(super) struct ScanWorkflow {
    active_scans: Arc<StdMutex<HashSet<String>>>,
}
impl ScanWorkflow {
    pub(super) fn new() -> Self {
        Self {
            active_scans: Arc::new(StdMutex::new(HashSet::new())),
        }
    }
    pub async fn scan_subnet(
        &self,
        readiness: &readiness::CameraReadiness,
        subnet: &str,
        config: &crate::config::AppConfig,
    ) -> Result<Vec<ScanResult>, AppError> {
        // RAII guard: the subnet is removed from the active set on drop —
        // normal return OR a cancelled future — so a cancellation at the
        // scan await below can't wedge the subnet as "scan in progress"
        // forever. Insert + guard creation happen under one lock.
        let _guard = {
            let mut active = self.active_scans.lock().unwrap_or_else(|p| p.into_inner());
            if !active.insert(subnet.to_string()) {
                return Err(AppError::Network(format!(
                    "Scan already in progress for {}",
                    subnet
                )));
            }
            ScanGuard {
                active: self.active_scans.clone(),
                subnet: subnet.to_string(),
            }
        };
        if config.get_network_mode() == crate::config::NetworkMode::StaticManual {
            return Err(AppError::Network(
                "Port scanning is disabled in Static-Manual".into(),
            ));
        }
        let (adapter, index, fence) = readiness
            .probe_scope()
            .ok_or_else(|| AppError::Network("Selected Ethernet adapter unavailable".into()))?;
        readiness
            .device_registry
            .expire_evidence(tokio::time::Instant::now());
        let identities = readiness
            .device_registry
            .snapshot()
            .into_iter()
            .filter(|r| {
                r.status == DeviceStatus::Live
                    && r.verified_by_mac
                        .as_ref()
                        .is_some_and(|m| m.eq_ignore_ascii_case(&adapter.mac))
            })
            .filter_map(|r| r.ip.parse().ok().map(|ip| (ip, r.mac)))
            .collect();
        let discovery = readiness.discovery.sweep_fence();
        if discovery.is_stale() {
            return Err(AppError::Network("Discovery session unavailable".into()));
        }
        let scope = scanner::ScanScope {
            index,
            fence: Some(fence.clone()),
            session: Some(discovery.clone()),
            ips: adapter.ips,
            identities,
        };
        let results = scanner::scan(subnet, scope).await?;
        if fence.is_stale() || discovery.is_stale() {
            arp::note_fence_drop("scan_results");
            return Ok(Vec::new());
        }
        let mut accepted = Vec::new();
        for result in results {
            let Some(key) = result.key.as_ref() else {
                continue;
            };
            let target = route::CameraTarget {
                key: key.clone(),
                expected_mac: Some(key.clone()),
                ip: result.ip.clone(),
            };
            let Ok(path) = readiness.camera_path_now(&target, config, false) else {
                continue;
            };
            if fence.is_stale()
                || discovery.is_stale()
                || path.index != result.interface_index
                || Some(path.source.to_string()) != result.source
            {
                continue;
            }
            if readiness.device_registry.merge_scan_result_fenced(
                key,
                &result.open_ports,
                Some(&fence),
            ) {
                if let Some(row) = readiness.device_registry.cache_record(key) {
                    config.upsert_cached_device_fenced(row, Some(&fence))?;
                }
                readiness.device_emitter.poke();
            }
            accepted.push(result);
        }
        Ok(accepted)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scan_guard_removes_subnet_on_drop() {
        // A cancelled scan_subnet future drops its ScanGuard, which must
        // clear the active-scan flag so later scans of that subnet aren't
        // permanently rejected.
        let active = Arc::new(std::sync::Mutex::new(HashSet::new()));
        active.lock().unwrap().insert("10.0.0.0/24".to_string());
        {
            let _g = ScanGuard {
                active: active.clone(),
                subnet: "10.0.0.0/24".to_string(),
            };
            assert!(active.lock().unwrap().contains("10.0.0.0/24"));
        }
        assert!(!active.lock().unwrap().contains("10.0.0.0/24"));
    }
}
