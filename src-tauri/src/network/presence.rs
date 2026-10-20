//! Selected-adapter presence scheduling, independent of capture sessions.
use std::collections::HashMap;
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
    pub fn update(&self, selection: &AdapterSelection, mode: NetworkMode) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
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
            return;
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
        drop(state);
        self.wake.notify_one();
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
        let observations = manager.candidates.snapshot(std::time::Instant::now());
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
