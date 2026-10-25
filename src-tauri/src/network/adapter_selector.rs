//! Selected adapter authority. The facade retires old work before commit.
use super::*;

pub(super) struct AdapterSelector {
    pub(super) adapter_selection: Arc<Mutex<AdapterSelection>>,
    pub(super) presence: Arc<presence::Control>,
    pub(super) presence_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Local adapter MAC identities shared by capture and neighbor imports.
    /// Refreshed at discovery start and each adoption pass so retained capture
    /// sessions recognize newly attached adapters without hiding IP collisions.
    pub(super) local_macs: Arc<StdMutex<HashSet<[u8; 6]>>>,
    selection_tx: tokio::sync::watch::Sender<AdapterSelection>,
}

impl AdapterSelector {
    /// Current selected-adapter addresses from IP Helper, never the saved map.
    pub(super) fn probe_scope(
        &self,
        pending_ips: &auto_adopt::PendingIps,
    ) -> Option<(InterfaceInfo, u32, SweepFence)> {
        let snapshot = self.presence.snapshot();
        let mut adapter = snapshot.adapter?;
        if snapshot.fence.is_stale() || interface::index_for_mac(&adapter.mac)? != snapshot.index {
            return None;
        }
        let (up, ips) = interface::quick_status_by_mac(&adapter.mac)?;
        if !up {
            return None;
        }
        adapter.ips = ips;
        let pending = pending_ips.try_lock().ok()?;
        adapter
            .ips
            .retain(|ip| !pending.iter().any(|p| p.ip.to_string() == ip.address));
        Some((adapter, snapshot.index, snapshot.fence))
    }
    pub(super) fn new() -> Self {
        Self {
            adapter_selection: Arc::new(Mutex::new(AdapterSelection::default())),
            presence: Arc::new(presence::Control::default()),
            presence_handle: Mutex::new(None),
            // Shared read-only identity set for synchronous capture callbacks.
            local_macs: Arc::new(StdMutex::new(HashSet::new())),
            selection_tx: tokio::sync::watch::channel(AdapterSelection::default()).0,
        }
    }
    pub(super) async fn snapshot(&self) -> AdapterSelection {
        self.adapter_selection.lock().await.clone()
    }
    pub(super) fn subscribe(&self) -> tokio::sync::watch::Receiver<AdapterSelection> {
        self.selection_tx.subscribe()
    }
    // send_replace also retains the latest value before there are subscribers.
    // Repeated watcher emissions must wake streaming even for identical data.
    pub(super) fn observe(&self, selection: &AdapterSelection) {
        self.selection_tx.send_replace(selection.clone());
    }
    pub(super) async fn commit(&self, selection: &AdapterSelection) {
        *self.adapter_selection.lock().await = selection.clone();
    }
    pub(super) fn propose(
        &self,
        config: &crate::config::AppConfig,
        list: &[InterfaceInfo],
    ) -> Result<AdapterSelection, AppError> {
        let mut mac = config.get().selected_adapter_mac;
        let adapter = pick_adapter(list, mac.as_deref()).cloned();
        if mac.is_none() {
            if let Some(iface) = &adapter {
                mac = adapter_mac(&iface.mac);
                config.set_selected_adapter_mac(mac.clone().unwrap())?;
            }
        }
        let index = adapter
            .as_ref()
            .and_then(|i| interface::index_for_mac(&i.mac));
        let candidates: Vec<_> = list
            .iter()
            .filter(|i| adapter_candidate(i))
            .cloned()
            .collect();
        Ok(AdapterSelection {
            selection_required: mac.is_none() && candidates.len() > 1,
            selected_mac: mac,
            adapter,
            interface_index: index,
            candidates,
        })
    }
    pub(crate) fn update_presence_adapter(
        &self,
        selection: &AdapterSelection,
        mode: crate::config::NetworkMode,
    ) {
        self.presence
            .update_native(selection, mode, interface::quick_link_by_mac);
    }
    pub(super) async fn stop_presence(&self, registry: &DeviceRegistry) {
        self.presence.stop();
        registry.set_verification_scope(None);
        if let Some(mut handle) = self.presence_handle.lock().await.take() {
            if tokio::time::timeout(std::time::Duration::from_secs(5), &mut handle)
                .await
                .is_err()
            {
                handle.abort();
            }
        }
    }
    /// S9 consumes this wake; notifications carry no identity or liveness of their own.
    #[allow(dead_code)]
    pub(crate) async fn expected_device_verified(&self) {
        self.presence.verified.notified().await;
    }
}

pub(super) fn adapter_mac(mac: &str) -> Option<String> {
    let bytes = parse_mac_bytes(mac)?;
    (bytes != [0; 6] && bytes[0] & 1 == 0).then(|| mac.replace('-', ":").to_ascii_lowercase())
}

pub(super) fn adapter_candidate(iface: &InterfaceInfo) -> bool {
    interface::is_wired_physical(iface) && !iface.is_wifi && adapter_mac(&iface.mac).is_some()
}

/// A saved identity wins even when absent; enumeration order never selects.
pub(crate) fn pick_adapter<'a>(
    list: &'a [InterfaceInfo],
    mac: Option<&str>,
) -> Option<&'a InterfaceInfo> {
    let mut candidates = list.iter().filter(|iface| adapter_candidate(iface));
    if let Some(mac) = mac {
        let mac = adapter_mac(mac)?;
        let mut matching =
            candidates.filter(|iface| adapter_mac(&iface.mac).as_ref() == Some(&mac));
        let found = matching.next()?;
        return matching.next().is_none().then_some(found);
    }
    let found = candidates.next()?;
    candidates.next().is_none().then_some(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proposals_do_not_commit_before_old_work_is_retired() {
        let selector = AdapterSelector::new();
        let config = crate::config::AppConfig::for_test(crate::config::AppSettings {
            selected_adapter_mac: Some("40:cd:3a:00:00:01".into()),
            ..Default::default()
        });
        let proposal = selector.propose(&config, &[]).unwrap();
        assert!(selector.snapshot().await.selected_mac.is_none());
        assert_eq!(proposal.selected_mac, config.get().selected_adapter_mac);
        selector.commit(&proposal).await;
        assert_eq!(
            selector.snapshot().await.selected_mac,
            proposal.selected_mac
        );
    }

    #[tokio::test]
    async fn selection_watch_retains_initial_latest_and_repeated_wakes() {
        let selector = AdapterSelector::new();
        let mut rx = selector.subscribe();
        assert!(rx.borrow_and_update().selected_mac.is_none());
        let mut selection = AdapterSelection {
            interface_index: Some(7),
            ..Default::default()
        };
        selector.observe(&selection);
        rx.changed().await.unwrap();
        assert_eq!(rx.borrow_and_update().interface_index, Some(7));
        selector.observe(&selection);
        assert!(rx.has_changed().unwrap());
        rx.borrow_and_update();
        for index in [8, 9, 10] {
            selection.interface_index = Some(index);
            selector.observe(&selection);
        }
        rx.changed().await.unwrap();
        assert_eq!(rx.borrow_and_update().interface_index, Some(10));
        drop(rx);
        selector.observe(&selection);
        assert_eq!(selector.subscribe().borrow().interface_index, Some(10));
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
    #[test]
    fn persisted_adapter_survives_reordering_absence_and_return() {
        let mut dock = adapter("Dock", &["192.168.1.101"]);
        dock.mac = "40:cd:3a:00:00:01".into();
        let mut usb = adapter("USB", &["192.168.1.102"]);
        usb.mac = "40:cd:3a:00:00:02".into();
        for list in [
            vec![dock.clone(), usb.clone()],
            vec![usb.clone(), dock.clone()],
        ] {
            assert_eq!(
                pick_adapter(&list, Some("40-CD-3A-00-00-02")).unwrap().name,
                "USB"
            );
        }
        assert!(pick_adapter(&[dock], Some(&usb.mac)).is_none());
        assert_eq!(
            pick_adapter(&[usb], Some("40:cd:3a:00:00:02"))
                .unwrap()
                .name,
            "USB"
        );
    }

    #[test]
    fn automatic_selection_requires_one_eligible_physical_adapter() {
        let mut wired = adapter("Wired", &[]);
        wired.mac = "40:cd:3a:00:00:01".into();
        wired.is_up = false; // the only disconnected port can pre-attach
        assert_eq!(pick_adapter(&[wired.clone()], None).unwrap().name, "Wired");
        assert!(pick_adapter(&[], None).is_none());
        let mut other = wired.clone();
        other.mac = "40:cd:3a:00:00:02".into();
        other.is_up = true;
        assert!(pick_adapter(&[wired.clone(), other.clone()], None).is_none());
        assert!(pick_adapter(&[other.clone(), wired.clone()], None).is_none());
        for kind in ["wifi", "vpn", "virtual", "invalid_mac"] {
            let mut excluded = other.clone();
            match kind {
                "wifi" => excluded.is_wifi = true,
                "vpn" => excluded.is_vpn = true,
                "virtual" => excluded.is_virtual = true,
                _ => excluded.mac.clear(),
            }
            assert_eq!(
                pick_adapter(&[excluded, wired.clone()], None).unwrap().mac,
                wired.mac
            );
        }
        assert!(pick_adapter(&[wired], Some("invalid-mac")).is_none());
    }
}
