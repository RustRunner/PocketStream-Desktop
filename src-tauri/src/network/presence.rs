//! Selected-adapter presence scheduling, independent of capture sessions.
use super::adopt_loop::{AdoptionCtx, ProbeOrigin, RealProbeIo};
use super::{
    device_registry, interface, log_value, parse_mac_bytes, presence_target_is_host,
    subnet_key_for, AppError, ArpDevice,
};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::Instant;

use super::cache_probe::ProbeIo;
use super::{
    arp, AdapterSelection, DeviceRecord, DeviceRegistry, DeviceStatus, InterfaceInfo, SweepFence,
};
use crate::config::NetworkMode;

pub(crate) const FRESHNESS: Duration = Duration::from_secs(15);
const ACTIVE_INTERVAL: Duration = Duration::from_secs(5);
const INACTIVE_INTERVAL: Duration = Duration::from_secs(60);
const DOWN_HOLD: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub(crate) struct Snapshot {
    pub adapter: Option<InterfaceInfo>,
    pub index: u32,
    pub mode: NetworkMode,
    pub revision: u64,
    pub fence: SweepFence,
}

#[derive(Default)]
struct State {
    selection: AdapterSelection,
    mode: NetworkMode,
    revision: u64,
    expire_at: Option<Instant>,
    ready_at: Option<Instant>,
}

pub(crate) struct Control {
    state: Mutex<State>,
    epoch: Arc<AtomicU64>,
    active: Arc<AtomicBool>,
    pub wake: Notify,
    pub verified: Notify,
}

impl Default for Control {
    fn default() -> Self {
        Self {
            state: Mutex::new(State::default()),
            epoch: Arc::new(AtomicU64::new(0)),
            active: Arc::new(AtomicBool::new(true)),
            wake: Notify::new(),
            verified: Notify::new(),
        }
    }
}

fn up(selection: &AdapterSelection) -> bool {
    selection.interface_index.is_some_and(|i| i != 0)
        && selection
            .adapter
            .as_ref()
            .is_some_and(|i| i.is_up && super::device_registry::canonical_mac(&i.mac).is_some())
}

impl Control {
    pub(crate) fn update_native(
        &self,
        selection: &AdapterSelection,
        mode: NetworkMode,
        read: impl FnOnce(&str) -> Option<(u32, bool)>,
    ) {
        let mut current = selection.clone();
        if let Some(mac) = current.selected_mac.as_deref() {
            let (index, is_up) = read(mac).unwrap_or((0, false));
            current.interface_index = (index != 0).then_some(index);
            if let Some(adapter) = &mut current.adapter {
                adapter.is_up = is_up && index != 0;
            }
        }
        self.update(&current, mode);
    }

    pub fn update(&self, selection: &AdapterSelection, mode: NetworkMode) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if self.update_locked(&mut state, selection, mode) {
            drop(state);
            self.wake.notify_one();
        }
    }

    fn update_locked(
        &self,
        state: &mut State,
        selection: &AdapterSelection,
        mode: NetworkMode,
    ) -> bool {
        let identity_changed = state.selection.selected_mac != selection.selected_mac
            || state.selection.interface_index != selection.interface_index;
        let was_up = up(&state.selection);
        let is_up = up(selection);
        let changed = identity_changed
            || state.mode != mode
            || was_up != is_up
            || serde_json::to_value(&state.selection.adapter).ok()
                != serde_json::to_value(&selection.adapter).ok();
        if !changed {
            return false;
        }
        if identity_changed || state.mode != mode || was_up != is_up {
            self.epoch.fetch_add(1, Ordering::AcqRel);
        }
        if (identity_changed && state.selection.selected_mac.is_some()) || (was_up && !is_up) {
            state.expire_at = Some(Instant::now() + DOWN_HOLD);
            state.ready_at = is_up.then_some(Instant::now() + DOWN_HOLD);
        } else if is_up && !was_up && !identity_changed {
            state.expire_at = None; // a short link bounce never expires history
            state.ready_at = None;
        }
        state.selection = selection.clone();
        state.mode = mode;
        state.revision += 1;
        true
    }

    /// Native link/index observation must not wait for provider enumeration or
    /// discovery/address locks. Preserve metadata/filtered IPs from the watcher.
    pub(crate) fn observe_link(
        &self,
        read: impl FnOnce(&str) -> Option<(u32, bool)>,
    ) -> Option<AdapterSelection> {
        let (mut selection, revision) = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            (state.selection.clone(), state.revision)
        };
        let mac = selection.selected_mac.as_deref()?;
        let (index, is_up) = read(mac).unwrap_or((0, false));
        selection.interface_index = (index != 0).then_some(index);
        if let Some(adapter) = &mut selection.adapter {
            adapter.is_up = is_up && index != 0;
        }
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        // A concurrent explicit selection/mode update wins this native read.
        if state.revision != revision {
            return None;
        }
        let mode = state.mode;
        if !self.update_locked(&mut state, &selection, mode) {
            return None;
        }
        drop(state);
        self.wake.notify_one();
        Some(selection)
    }

    pub fn bootstrap(&self) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .revision += 1;
        self.wake.notify_one();
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        Snapshot {
            adapter: (!self.stopped()
                && up(&state.selection)
                && state.ready_at.is_none_or(|t| Instant::now() >= t))
            .then(|| state.selection.adapter.clone())
            .flatten(),
            index: state.selection.interface_index.unwrap_or(0),
            mode: state.mode,
            revision: state.revision,
            fence: SweepFence::new(
                self.epoch.load(Ordering::Acquire),
                self.epoch.clone(),
                self.active.clone(),
            ),
        }
    }

    pub fn tick(&self, registry: &DeviceRegistry) -> bool {
        let expire = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.expire_at.is_some_and(|t| Instant::now() >= t) {
                state.expire_at = None;
                state.ready_at = None;
                true
            } else {
                false
            }
        };
        let snapshot = self.snapshot();
        registry.set_verification_scope(snapshot.adapter.as_ref().map(|a| a.mac.as_str()));
        (expire && registry.expire_all()) | registry.expire_evidence(Instant::now())
    }

    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
        self.wake.notify_one();
    }
    pub fn stopped(&self) -> bool {
        !self.active.load(Ordering::Acquire)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Job {
    pub key: Option<String>,
    pub ip: Ipv4Addr,
    pub source: Option<Ipv4Addr>,
}

#[derive(Debug)]
pub(crate) struct Proof {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub at: Instant,
    pub wall: String,
}

#[derive(Default)]
pub(crate) struct Clock {
    revision: Option<u64>,
    due: HashMap<String, Instant>,
    candidates: HashMap<(u32, Ipv4Addr, [u8; 6]), std::time::Instant>,
    candidate_turn: bool,
}

impl Clock {
    pub fn next(
        &mut self,
        snapshot: &Snapshot,
        records: &[DeviceRecord],
        candidates: &[arp::Candidate],
    ) -> Option<Job> {
        let adapter = snapshot.adapter.as_ref()?;
        if snapshot.fence.is_stale() {
            return None;
        }
        if self.revision != Some(snapshot.revision) {
            self.due.clear();
            self.candidates.clear();
            self.revision = Some(snapshot.revision);
        }
        self.due
            .retain(|key, _| records.iter().any(|r| r.mac == *key));
        self.candidates.retain(|key, _| {
            candidates
                .iter()
                .any(|c| (c.interface_index, c.ip, c.mac) == *key)
        });
        let source = |ip| super::select_wired_source(ip, &HashMap::new(), &adapter.ips);
        let eligible = |ip| {
            !crate::validation::prohibited_camera_ip(ip)
                && !adapter.ips.iter().any(|i| i.address == ip.to_string())
                && (source(ip).is_some() || snapshot.mode == NetworkMode::StaticAuto)
        };
        let known = records
            .iter()
            .filter_map(|r| {
                let ip: Ipv4Addr = r.ip.parse().ok()?;
                (eligible(ip)
                    && self.due.get(&r.mac).is_none_or(|t| {
                        Instant::now() >= *t
                            || (r.status == DeviceStatus::Live
                                && *t > Instant::now() + ACTIVE_INTERVAL)
                    }))
                .then_some((r, ip))
            })
            .min_by_key(|(r, _)| self.due.get(&r.mac).copied());
        let candidate = candidates.iter().find(|c| {
            c.interface_index == snapshot.index
                && super::parse_mac_bytes(&adapter.mac) == Some(c.adapter_mac)
                && eligible(c.ip)
                && self.candidates.get(&(c.interface_index, c.ip, c.mac)) != Some(&c.observed_at)
        });
        self.candidate_turn = !self.candidate_turn;
        if let Some(c) = candidate.filter(|_| self.candidate_turn || known.is_none()) {
            self.candidates
                .insert((c.interface_index, c.ip, c.mac), c.observed_at);
            return Some(Job {
                key: None,
                ip: c.ip,
                source: source(c.ip),
            });
        }
        let (record, ip) = known?;
        let interval = if record.status == DeviceStatus::Live {
            ACTIVE_INTERVAL
        } else {
            INACTIVE_INTERVAL
        };
        self.due
            .insert(record.mac.clone(), Instant::now() + interval);
        Some(Job {
            key: Some(record.mac.clone()),
            ip,
            source: source(ip),
        })
    }

    pub fn verified(&mut self, key: &str) {
        self.due
            .insert(key.into(), Instant::now() + ACTIVE_INTERVAL);
    }
}

/// One native call at a time. No timeout drops a running native future;
/// the caller polls its expiry tick independently while this is pending.
pub(crate) async fn verify<I: ProbeIo>(
    io: &mut I,
    job: &Job,
    snapshot: &Snapshot,
) -> Option<Proof> {
    if io.shutdown() || snapshot.fence.is_stale() || io.interface_index() != snapshot.index {
        return None;
    }
    let foreign = job.source.is_none();
    if foreign && snapshot.mode != NetworkMode::StaticAuto {
        return None;
    }
    let subnet = super::subnet_key_for(job.ip);
    let source = job
        .source
        .unwrap_or_else(|| super::auto_adopt::pick_scratch(job.ip, &[job.ip]));
    if foreign && !io.bind_scratch(&subnet, source).await {
        return None;
    }
    let result = if io.shutdown() || snapshot.fence.is_stale() {
        None
    } else {
        io.resolve(job.ip, source, snapshot.index)
            .await
            .ok()
            .flatten()
    };
    let at = Instant::now();
    let wall = chrono::Utc::now().to_rfc3339();
    if foreign {
        io.release_scratch(&subnet, source).await;
    }
    if io.shutdown() || snapshot.fence.is_stale() {
        return None;
    }
    let mac = super::device_registry::canonical_mac(&result?)?;
    if foreign && !io.adopt(&subnet, job.ip, &mac).await {
        return None;
    }
    if io.shutdown() || snapshot.fence.is_stale() || at.elapsed() >= FRESHNESS {
        return None;
    }
    Some(Proof {
        ip: job.ip,
        mac,
        at,
        wall,
    })
}

#[cfg(test)]
mod tests {
    use super::super::cache_probe::tests::MockProbeIo;
    use super::*;
    use crate::config::{CachedDevice, ManualNode};

    fn selection(index: u32, is_up: bool) -> AdapterSelection {
        AdapterSelection {
            selected_mac: Some("40:cd:3a:00:00:01".into()),
            interface_index: Some(index),
            adapter: Some(InterfaceInfo {
                name: "USB".into(),
                display_name: "USB".into(),
                description: "ASIX".into(),
                mac: "40:cd:3a:00:00:01".into(),
                ips: vec![super::super::interface::IpInfo {
                    address: "192.168.1.101".into(),
                    prefix: 24,
                    subnet: "192.168.1.0/24".into(),
                }],
                is_up,
                is_ethernet: true,
                is_wifi: false,
                is_vpn: false,
                is_virtual: false,
            }),
            ..Default::default()
        }
    }
    fn known() -> DeviceRegistry {
        let r = DeviceRegistry::new();
        r.hydrate_from_cache(&[CachedDevice {
            mac: "aa:bb:cc:dd:ee:02".into(),
            ip: "192.168.1.204".into(),
            subnet: "192.168.1.0/24".into(),
            alias: "CAM".into(),
            open_ports: vec![],
            last_seen: "2026-10-19T12:00:00Z".into(),
            verified_by_mac: None,
            last_verified_at: None,
        }]);
        r
    }
    fn io() -> MockProbeIo {
        let mut io = MockProbeIo::new();
        io.answers
            .insert("192.168.1.204".parse().unwrap(), "aa:bb:cc:dd:ee:02".into());
        io
    }

    #[tokio::test(start_paused = true)]
    async fn native_link_hold_is_not_extended_by_polls_or_stale_provider_updates() {
        let r = known();
        let c = Control::default();
        let selected = selection(7, true);
        c.update(&selected, NetworkMode::Dhcp);
        let snapshot = c.snapshot();
        let job = Clock::default()
            .next(&snapshot, &r.snapshot(), &[])
            .unwrap();
        promote(
            &r,
            &verify(&mut io(), &job, &snapshot).await.unwrap(),
            &snapshot,
        );
        assert!(c
            .observe_link(|mac| {
                assert_eq!(mac, selected.selected_mac.as_deref().unwrap());
                Some((7, false))
            })
            .is_some());
        assert!(snapshot.fence.is_stale());
        for _ in 0..8 {
            tokio::time::advance(Duration::from_millis(250)).await;
            assert!(c.observe_link(|_| Some((7, false))).is_none());
            c.update_native(&selected, NetworkMode::Dhcp, |_| Some((7, false)));
            c.tick(&r);
        }
        assert_eq!(r.snapshot()[0].status, DeviceStatus::Offline);
        assert_eq!(r.snapshot().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn native_link_short_bounce_and_new_selection_cannot_revive_old_work() {
        let c = Control::default();
        c.update(&selection(7, true), NetworkMode::Dhcp);
        let old = c.snapshot().fence;
        c.observe_link(|_| Some((7, false)));
        tokio::time::advance(Duration::from_secs(1)).await;
        c.observe_link(|_| Some((7, true)));
        assert!(old.is_stale());
        assert!(c.state.lock().unwrap().expire_at.is_none());
        assert!(c
            .observe_link(|_| {
                c.update(&selection(8, true), NetworkMode::Dhcp);
                None
            })
            .is_none());
        assert_eq!(c.snapshot().index, 8);
        let missing = c.observe_link(|_| None).unwrap();
        assert_eq!(missing.interface_index, None);
        assert!(c.snapshot().adapter.is_none());
        let unselected = Control::default();
        assert!(unselected
            .observe_link(|_| panic!("no selected adapter"))
            .is_none());
    }
    fn promote(r: &DeviceRegistry, proof: &Proof, snapshot: &Snapshot) {
        let device = super::super::ArpDevice {
            mac: proof.mac.clone(),
            ip: proof.ip.to_string(),
            subnet: super::super::subnet_key_for(proof.ip),
            first_seen: proof.wall.clone(),
            last_seen: proof.wall.clone(),
        };
        assert!(
            r.merge_verified(
                &device,
                &snapshot.adapter.as_ref().unwrap().mac,
                &proof.wall,
                &snapshot.fence
            )
            .changed
        );
        r.remember_verified_at(&proof.mac, &proof.wall, proof.at, &snapshot.fence);
    }

    #[tokio::test(start_paused = true)]
    async fn bootstrap_native_history_and_manual_pins_in_every_mode() {
        for mode in [
            NetworkMode::StaticAuto,
            NetworkMode::Dhcp,
            NetworkMode::StaticManual,
        ] {
            let r = known();
            r.hydrate_manual_nodes(&[ManualNode {
                ip: "192.168.1.205".into(),
                alias: "PTU".into(),
                expected_mac: None,
            }]);
            let control = Control::default();
            control.update(&selection(7, true), mode);
            control.tick(&r);
            let snapshot = control.snapshot();
            let mut clock = Clock::default();
            let mut io = io();
            io.answers
                .insert("192.168.1.205".parse().unwrap(), "aa:bb:cc:dd:ee:04".into());
            for _ in 0..2 {
                let job = clock.next(&snapshot, &r.snapshot(), &[]).unwrap();
                let proof = verify(&mut io, &job, &snapshot).await.unwrap();
                assert!(job.source.is_some());
                assert_eq!(proof.ip, job.ip);
            }
            assert!(clock.next(&snapshot, &r.snapshot(), &[]).is_none());
            assert_eq!(io.resolved_indices, vec![7, 7]);
            assert!(!io.events.iter().any(|e| e.starts_with("bind")));
            assert_eq!(r.snapshot().len(), 2);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn active_five_seconds_and_inactive_sixty_seconds() {
        let r = known();
        let control = Control::default();
        control.update(&selection(7, true), NetworkMode::Dhcp);
        let snapshot = control.snapshot();
        let mut clock = Clock::default();
        let mut io = io();
        let job = clock.next(&snapshot, &r.snapshot(), &[]).unwrap();
        let proof = verify(&mut io, &job, &snapshot).await.unwrap();
        promote(&r, &proof, &snapshot);
        clock.verified(&proof.mac);
        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(clock.next(&snapshot, &r.snapshot(), &[]).is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(clock.next(&snapshot, &r.snapshot(), &[]).is_some());
        r.expire_all();
        control.bootstrap();
        let snapshot = control.snapshot();
        assert!(clock.next(&snapshot, &r.snapshot(), &[]).is_some());
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(clock.next(&snapshot, &r.snapshot(), &[]).is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(clock.next(&snapshot, &r.snapshot(), &[]).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn first_bootstrap_failure_recovers_without_a_broadcast() {
        let r = known();
        let control = Control::default();
        control.update(&selection(7, true), NetworkMode::Dhcp);
        let snapshot = control.snapshot();
        let mut clock = Clock::default();
        let mut io = MockProbeIo::new();
        let job = clock.next(&snapshot, &r.snapshot(), &[]).unwrap();
        assert!(verify(&mut io, &job, &snapshot).await.is_none());
        tokio::time::advance(INACTIVE_INTERVAL).await;
        io.answers.insert(job.ip, "aa:bb:cc:dd:ee:02".into());
        let job = clock.next(&snapshot, &r.snapshot(), &[]).unwrap();
        promote(
            &r,
            &verify(&mut io, &job, &snapshot).await.unwrap(),
            &snapshot,
        );
        assert_eq!(r.snapshot()[0].status, DeviceStatus::Live);
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_runs_while_a_native_pass_is_still_waiting() {
        let r = known();
        let control = Control::default();
        control.update(&selection(7, true), NetworkMode::Dhcp);
        let snapshot = control.snapshot();
        let job = Clock::default()
            .next(&snapshot, &r.snapshot(), &[])
            .unwrap();
        let mut fast = io();
        promote(
            &r,
            &verify(&mut fast, &job, &snapshot).await.unwrap(),
            &snapshot,
        );
        let mut slow = io();
        slow.resolve_delay = Duration::from_secs(60);
        let pending = verify(&mut slow, &job, &snapshot);
        tokio::pin!(pending);
        tokio::select! { _ = &mut pending => panic!("slow native call finished early"), _ = tokio::time::sleep(FRESHNESS) => {} }
        assert!(control.tick(&r));
        assert_eq!(r.snapshot()[0].status, DeviceStatus::Offline);
        assert_eq!(r.snapshot().len(), 1);
        assert_eq!(r.snapshot()[0].alias, "CAM");
    }

    #[tokio::test(start_paused = true)]
    async fn link_down_hold_and_short_bounce_match_backend_expiry() {
        for bounce in [false, true] {
            let r = known();
            let control = Control::default();
            control.update(&selection(7, true), NetworkMode::Dhcp);
            let snapshot = control.snapshot();
            let mut io = io();
            let job = Clock::default()
                .next(&snapshot, &r.snapshot(), &[])
                .unwrap();
            promote(
                &r,
                &verify(&mut io, &job, &snapshot).await.unwrap(),
                &snapshot,
            );
            control.update(&selection(7, false), NetworkMode::Dhcp);
            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(!control.tick(&r));
            assert_eq!(r.snapshot()[0].status, DeviceStatus::Live);
            if bounce {
                control.update(&selection(7, true), NetworkMode::Dhcp);
            }
            tokio::time::advance(Duration::from_secs(1)).await;
            control.tick(&r);
            assert_eq!(
                r.snapshot()[0].status,
                if bounce {
                    DeviceStatus::Live
                } else {
                    DeviceStatus::Offline
                }
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn epoch_discards_a_late_reply_and_uses_the_new_index() {
        let r = known();
        let control = Control::default();
        control.update(&selection(7, true), NetworkMode::Dhcp);
        let snapshot = control.snapshot();
        let job = Clock::default()
            .next(&snapshot, &r.snapshot(), &[])
            .unwrap();
        let mut old = io();
        old.resolve_delay = Duration::from_secs(5);
        let pending = verify(&mut old, &job, &snapshot);
        tokio::pin!(pending);
        tokio::select! { _ = &mut pending => panic!("reply finished early"), _ = tokio::time::sleep(Duration::from_secs(1)) => {} }
        control.update(&selection(8, true), NetworkMode::Dhcp);
        assert!(pending.await.is_none());
        control.tick(&r);
        assert_ne!(r.snapshot()[0].status, DeviceStatus::Live);
        let snapshot = control.snapshot();
        let mut next = io();
        next.interface_index = 8;
        next.source_index = 8;
        let job = Clock::default()
            .next(&snapshot, &r.snapshot(), &[])
            .unwrap();
        assert!(verify(&mut next, &job, &snapshot).await.is_some());
        assert_eq!(next.resolved_indices, vec![8]);
    }

    #[tokio::test(start_paused = true)]
    async fn candidate_only_becomes_history_after_native_verification() {
        let manager = super::super::NetworkManager::new();
        let control = Control::default();
        control.update(&selection(7, true), NetworkMode::Dhcp);
        let snapshot = control.snapshot();
        let ingress = manager
            .candidate_ingress(7, Some([0x40, 0xcd, 0x3a, 0, 0, 1]))
            .unwrap();
        ingress.observe(
            "192.168.1.204".parse().unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 2],
            &snapshot.fence,
            std::time::Instant::now(),
        );
        let observations = manager
            .capture
            .candidates
            .snapshot(std::time::Instant::now());
        let r = manager.registry();
        let mut clock = Clock::default();
        assert!(r.snapshot().is_empty());
        let job = clock.next(&snapshot, &r.snapshot(), &observations).unwrap();
        let mut io = io();
        let proof = verify(&mut io, &job, &snapshot).await.unwrap();
        promote(&r, &proof, &snapshot);
        assert_eq!(r.snapshot()[0].mac, proof.mac);
        assert!(r.cache_record(&proof.mac).unwrap().open_ports.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn foreign_candidates_wait_in_dhcp_and_manual_and_clean_up_before_adoption() {
        for mode in [
            NetworkMode::Dhcp,
            NetworkMode::StaticManual,
            NetworkMode::StaticAuto,
        ] {
            let control = Control::default();
            control.update(&selection(7, true), mode);
            let snapshot = control.snapshot();
            let job = Job {
                key: None,
                ip: "10.9.0.204".parse().unwrap(),
                source: None,
            };
            let candidate = arp::Candidate {
                interface_index: 7,
                adapter_mac: [0x40, 0xcd, 0x3a, 0, 0, 1],
                ip: job.ip,
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 2],
                observed_at: std::time::Instant::now(),
            };
            let mut clock = Clock::default();
            let mut io = io();
            io.answers.insert(job.ip, "aa:bb:cc:dd:ee:02".into());
            if mode != NetworkMode::StaticAuto {
                assert!(clock.next(&snapshot, &[], &[candidate]).is_none());
                assert!(verify(&mut io, &job, &snapshot).await.is_none());
                assert!(io.events.is_empty());
            } else {
                let job = clock.next(&snapshot, &[], &[candidate]).unwrap();
                assert!(verify(&mut io, &job, &snapshot).await.is_some());
                assert!(io.bound.is_empty());
                assert!(io.events[0].starts_with("bind"));
                assert!(io.events[2].starts_with("release"));
                assert!(io.events[3].starts_with("adopt"));
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn mode_change_discards_foreign_work_and_releases_its_scratch() {
        let control = Control::default();
        control.update(&selection(7, true), NetworkMode::StaticAuto);
        let snapshot = control.snapshot();
        let job = Job {
            key: None,
            ip: "10.9.0.204".parse().unwrap(),
            source: None,
        };
        let mut io = io();
        io.answers.insert(job.ip, "aa:bb:cc:dd:ee:02".into());
        io.resolve_delay = Duration::from_secs(5);
        {
            let pending = verify(&mut io, &job, &snapshot);
            tokio::pin!(pending);
            tokio::select! { _ = &mut pending => panic!("reply finished early"), _ = tokio::time::sleep(Duration::from_secs(1)) => {} }
            control.update(&selection(7, true), NetworkMode::Dhcp);
            assert!(pending.await.is_none());
        }
        assert!(io.bound.is_empty());
        assert!(!io.events.iter().any(|e| e.starts_with("adopt")));
    }

    #[tokio::test(start_paused = true)]
    async fn scope_and_time_order_guards_reject_unverified_or_older_writes() {
        let r = known();
        let control = Control::default();
        control.update(&selection(7, true), NetworkMode::Dhcp);
        control.tick(&r);
        let snapshot = control.snapshot();
        let mut device = super::super::ArpDevice {
            mac: "aa:bb:cc:dd:ee:02".into(),
            ip: "192.168.1.205".into(),
            subnet: "192.168.1.0/24".into(),
            first_seen: "2026-10-19T12:00:01Z".into(),
            last_seen: "2026-10-19T12:00:01Z".into(),
        };
        assert!(
            !r.merge_verified(
                &device,
                "40:cd:3a:00:00:02",
                &device.last_seen,
                &snapshot.fence
            )
            .changed
        );
        assert!(!r.set_status(&device.mac, DeviceStatus::Live));
        assert!(!r.merge_arp_fenced(&device, &snapshot.fence).changed);
        assert!(
            r.merge_verified(
                &device,
                "40:cd:3a:00:00:01",
                &device.last_seen,
                &snapshot.fence
            )
            .changed
        );
        let before = r.snapshot();
        device.ip = "192.168.1.204".into();
        device.last_seen = "2026-10-19T12:00:00Z".into();
        assert!(
            !r.merge_verified(
                &device,
                "40:cd:3a:00:00:01",
                &device.last_seen,
                &snapshot.fence
            )
            .changed
        );
        assert_eq!(r.snapshot(), before);
        let mut newer = device.clone();
        newer.mac = "aa:bb:cc:dd:ee:04".into();
        newer.ip = "192.168.1.205".into();
        assert!(
            r.merge_verified(
                &newer,
                "40:cd:3a:00:00:01",
                "2026-10-19T12:00:03Z",
                &snapshot.fence
            )
            .changed
        );
        device.ip = newer.ip;
        assert!(
            !r.merge_verified(
                &device,
                "40:cd:3a:00:00:01",
                "2026-10-19T12:00:02Z",
                &snapshot.fence
            )
            .changed
        );
        control.stop();
        control.tick(&r);
        assert!(
            !r.merge_verified(
                &device,
                "40:cd:3a:00:00:01",
                "2026-10-19T12:00:02Z",
                &snapshot.fence
            )
            .changed
        );
    }

    #[tokio::test(start_paused = true)]
    async fn mode_round_trip_bootstraps_without_losing_history() {
        let r = known();
        let control = Control::default();
        let mut clock = Clock::default();
        for mode in [
            NetworkMode::StaticAuto,
            NetworkMode::StaticManual,
            NetworkMode::Dhcp,
            NetworkMode::StaticAuto,
        ] {
            control.update(&selection(7, true), mode);
            let snapshot = control.snapshot();
            assert!(clock.next(&snapshot, &r.snapshot(), &[]).is_some());
            assert_eq!(r.snapshot().len(), 1);
        }
    }
}

#[derive(Clone)]
pub(super) struct PresenceDeps {
    pub(super) owners: super::discovery_session::DiscoveryDeps,
    pub(super) session: Arc<super::discovery_session::DiscoverySession>,
}
pub(super) async fn run_presence_job(
    deps: PresenceDeps,
    job: Job,
    snapshot: Snapshot,
) -> Option<String> {
    let adapter = snapshot.adapter.as_ref()?;
    if snapshot.fence.is_stale() {
        return None;
    }
    let address_fence = deps.owners.bindings.address_fence();
    if job.source.is_none() && address_fence.is_stale() {
        return None;
    }
    let _address = if job.source.is_none() {
        Some(deps.owners.bindings.address_work.lock().await)
    } else {
        None
    };
    if snapshot.fence.is_stale() || (job.source.is_none() && address_fence.is_stale()) {
        return None;
    }
    if presence_target_is_host(&job, adapter, &interface::local_adapter_macs()) {
        return None;
    }
    // Even a prefix also used by Wi-Fi may contain an Ethernet peer.
    // Foreign candidates still require mode-gated scratch work and fresh
    // selected-index resolution below; a Wi-Fi-only sender cannot promote.
    let emitter = deps.owners.emitter.clone();
    let ctx = AdoptionCtx {
        sweep: deps.owners.sweep(&deps.session),
        iface_name: adapter.name.clone(),
        adapter_mac: adapter.mac.clone(),
        interface_index: snapshot.index,
        candidates: deps
            .owners
            .capture
            .candidate_ingress(snapshot.index, parse_mac_bytes(&adapter.mac)),
        config: deps.owners.config.clone(),
        bridge: deps.owners.bridge.clone(),
        bindings: deps.owners.bindings.clone(),
        adopted: deps.owners.bindings.adopted_ips.clone(),
        pending_ips: deps.owners.bindings.pending_ips.clone(),
        adoption_seq: deps.owners.bindings.adoption_seq.clone(),
        liveness: deps.owners.bindings.adoption_liveness.clone(),
        meta: deps.owners.bindings.adopted_meta.clone(),
        devices: deps.session.arp_devices.clone(),
        registry: deps.owners.registry.clone(),
        emitter: emitter.clone(),
        fence: snapshot.fence.clone(),
        address_fence,
        local_macs: deps.owners.selector.local_macs.clone(),
    };
    let mut cooldowns = HashMap::new();
    let mut known_subnets = HashSet::new();
    let (_tx, shutdown) = tokio::sync::watch::channel(false);
    let mut io = RealProbeIo {
        ctx: &ctx,
        cooldowns: &mut cooldowns,
        known_subnets: &mut known_subnets,
        shutdown_rx: &shutdown,
        scratch_id: None,
        stop: false,
        origin: ProbeOrigin::CacheProbe,
    };
    let proof = verify(&mut io, &job, &snapshot).await?;
    log::debug!("event=evidence adapter_mac={} interface_index={} identity={} ip={} evidence_age_ms={} origin=presence",
        log_value(&adapter.mac), snapshot.index, log_value(&proof.mac), proof.ip, proof.at.elapsed().as_millis());
    let mutation_fence = ctx.address_fence.clone();
    drop(_address);
    let cache_deps = deps.clone();
    let fence = snapshot.fence.clone();
    let adapter_mac = adapter.mac.clone();
    let commit_fence = fence.clone();
    let key = tokio::task::spawn_blocking(move || {
        let config = cache_deps.owners.config.clone();
        if commit_fence.is_stale() || mutation_fence.is_stale() || proof.at.elapsed() >= FRESHNESS {
            arp::note_fence_drop("presence_commit");
            return None;
        }
        let registry = cache_deps.owners.registry.clone();
        if job
            .key
            .as_ref()
            .is_some_and(|key| !registry.snapshot().iter().any(|r| r.mac == *key))
        {
            return None;
        }
        let device = ArpDevice {
            mac: proof.mac.clone(),
            ip: proof.ip.to_string(),
            subnet: subnet_key_for(proof.ip),
            first_seen: proof.wall.clone(),
            last_seen: proof.wall.clone(),
        };
        let pin = config.get_manual_nodes().into_iter().find(|n| {
            n.ip == device.ip
                && job.key.as_ref().is_some_and(|key| {
                    key == &crate::config::manual_node_key(n) || key == &format!("manual:{}", n.ip)
                })
        });
        let result = if let Some(node) = pin {
            merge_manual_verified(
                &registry,
                &config,
                &node.ip,
                &device,
                &adapter_mac,
                &proof.wall,
                &commit_fence,
            )
            .ok()?
        } else {
            registry.merge_verified(&device, &adapter_mac, &proof.wall, &commit_fence)
        };
        if !result.changed || commit_fence.is_stale() || mutation_fence.is_stale() {
            return None;
        }
        registry.remember_verified_at(&proof.mac, &proof.wall, proof.at, &commit_fence);
        let key = registry
            .snapshot()
            .iter()
            .find(|r| r.mac.eq_ignore_ascii_case(&proof.mac))?
            .mac
            .clone();
        if let Some(row) = registry.cache_record(&key) {
            if let Err(e) = config.upsert_cached_device_fenced(row, Some(&commit_fence)) {
                log::warn!("Presence cache write failed: {e}");
            }
        }
        if commit_fence.is_stale() || mutation_fence.is_stale() || proof.at.elapsed() >= FRESHNESS {
            return None;
        }
        let target = config.get().stream.camera_mac;
        if target
            .as_ref()
            .is_some_and(|m| m.eq_ignore_ascii_case(&proof.mac))
        {
            cache_deps.owners.selector.presence.verified.notify_one();
        }
        Some(key)
    })
    .await
    .ok()
    .flatten()?;
    deps.owners
        .bindings
        .note_verified_liveness(job_ip_from_key(&deps.owners.registry, &key)?, &fence)
        .await;
    emitter.poke();
    Some(key)
}
/// S5a calls this only after fresh selected-adapter verification. Persist
/// the first manual binding before exposing it as a verified identity.
#[allow(dead_code)]
pub(crate) fn merge_manual_verified(
    registry: &DeviceRegistry,
    config: &crate::config::AppConfig,
    ip: &str,
    device: &ArpDevice,
    adapter: &str,
    verified_at: &str,
    fence: &SweepFence,
) -> Result<device_registry::MergeResult, AppError> {
    if ip != device.ip
        || fence.is_stale()
        || !DeviceRegistry::verification_valid(device, adapter, verified_at)
    {
        return Ok(device_registry::MergeResult::default());
    }
    let mac = device_registry::canonical_mac(&device.mac).expect("validated MAC");
    let node = config.bind_manual_node(ip, &mac, fence)?;
    let mut result = registry.merge_manual_verified(&node, device, adapter, verified_at, fence);
    if !fence.is_stale() {
        result.changed |= !registry.normalize_role_duplicates(None).is_empty();
    }
    Ok(result)
}
fn job_ip_from_key(registry: &DeviceRegistry, key: &str) -> Option<Ipv4Addr> {
    registry
        .snapshot()
        .iter()
        .find(|r| r.mac == key)?
        .ip
        .parse()
        .ok()
}
