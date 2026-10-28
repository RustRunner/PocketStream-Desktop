use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{watch, Mutex};

use crate::error::AppError;
use crate::network::ip_config;

/// Minimum age of a subnet's first qualifying observation before a repeat
/// observation may trigger adoption. Adds ~one loop pass to a real
/// device's adoption; a device that never re-ARPs never adopts.
const DWELL_MIN: Duration = Duration::from_secs(2);

/// Candidates not re-encountered within this window are dropped. A live
/// candidate is re-checked every adopt-loop pass, so only devices whose
/// subnet stopped clearing the adoption gates (adopted via another
/// device, native IP added, cooldown) go quiet and age out. Purely a
/// growth bound — an expired device restarts its dwell from scratch.
const DWELL_CANDIDATE_TTL: Duration = Duration::from_secs(600);

/// Outcome of one dwell check for an adoption candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DwellVerdict {
    /// First qualifying observation — start waiting for a repeat.
    Started,
    /// Still waiting: no new frame yet, or the repeat came too soon.
    Waiting,
    /// A distinct later frame arrived and the dwell has elapsed — adopt.
    Mature,
}

struct DwellCandidate {
    /// The device's `last_seen` string at the first qualifying
    /// observation. The ARP map rewrites `last_seen` on every accepted
    /// frame, so any difference proves a second frame — whereas the map
    /// entry itself is persistent and would look identical across
    /// arbitrarily many loop passes.
    token: String,
    first_qualifying: Instant,
    last_checked: Instant,
    probe_started: bool,
}

/// Gate that requires a device to produce two distinct accepted ARP
/// frames before its subnet is adopted, so one spurious frame from the
/// session-persistent device map can no longer bind an IP.
///
/// Candidates are keyed per (subnet, MAC): a second device appearing on
/// the same subnet opens its own candidacy and neither matures nor
/// resets another device's wait. The tracker is loop-local state, pure
/// over injected `Instant`s.
pub struct DwellTracker {
    candidates: HashMap<(String, String), DwellCandidate>,
}

impl DwellTracker {
    pub fn new() -> Self {
        Self {
            candidates: HashMap::new(),
        }
    }

    /// Check one gate-clearing device against its dwell candidacy.
    /// `token` is the device's current `last_seen` observation string.
    pub fn check(&mut self, subnet: &str, mac: &str, token: &str, now: Instant) -> DwellVerdict {
        self.candidates
            .retain(|_, c| now.saturating_duration_since(c.last_checked) < DWELL_CANDIDATE_TTL);
        // A device observed on a new subnet abandons its old candidacy —
        // the old (subnet, MAC) pairing no longer describes the device.
        self.candidates
            .retain(|(s, m), _| !(m == mac && s != subnet));

        let key = (subnet.to_string(), mac.to_string());
        match self.candidates.get_mut(&key) {
            None => {
                self.candidates.insert(
                    key,
                    DwellCandidate {
                        token: token.to_string(),
                        first_qualifying: now,
                        last_checked: now,
                        probe_started: false,
                    },
                );
                DwellVerdict::Started
            }
            Some(c) => {
                c.last_checked = now;
                if c.token != token
                    && now.saturating_duration_since(c.first_qualifying) >= DWELL_MIN
                {
                    DwellVerdict::Mature
                } else {
                    DwellVerdict::Waiting
                }
            }
        }
    }

    /// Give ordinary repeat broadcasts one short dwell before soliciting a
    /// quiet device. Each candidate gets only one directed identity probe.
    pub fn take_probe_due(&mut self, subnet: &str, mac: &str, now: Instant) -> bool {
        let Some(candidate) = self
            .candidates
            .get_mut(&(subnet.to_string(), mac.to_string()))
        else {
            return false;
        };
        if candidate.probe_started
            || now.saturating_duration_since(candidate.first_qualifying) < DWELL_MIN
        {
            return false;
        }
        candidate.probe_started = true;
        true
    }

    /// Confirmed sightings precede speculative probes, then oldest first.
    pub(super) fn priority(
        &self,
        subnet: &str,
        mac: &str,
        token: &str,
        now: Instant,
    ) -> (bool, Instant) {
        self.candidates
            .get(&(subnet.into(), mac.into()))
            .map(|c| {
                (
                    !(c.token != token
                        && now.saturating_duration_since(c.first_qualifying) >= DWELL_MIN),
                    c.first_qualifying,
                )
            })
            .unwrap_or((true, now))
    }

    /// Drop every candidate on `subnet`. Called once an adoption attempt
    /// for the subnet finishes (success or failure) or the subnet is
    /// removed, so the next approach restarts the two-observation gate.
    pub fn prune_subnet(&mut self, subnet: &str) {
        self.candidates.retain(|(s, _), _| s != subnet);
    }
}

impl Default for DwellTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if any of the given IPs are already on the same /24 subnet as the device.
pub fn already_on_subnet(device_ip: Ipv4Addr, current_ips: &[Ipv4Addr]) -> bool {
    let octets = device_ip.octets();
    current_ips.iter().any(|ip| {
        let o = ip.octets();
        o[0] == octets[0] && o[1] == octets[1] && o[2] == octets[2]
    })
}

/// Pick a candidate IP on the same /24 as `device_ip`.
/// Tries .100, then .101, .99, .102, .98, etc., skipping the device IP
/// itself, the reserved .0/.1/.255, and any **full IP** already in
/// `used_ips`. `used_ips` compares whole addresses (not last octets) so
/// a .100 on a *different* /24 doesn't needlessly block .100 here, while
/// a .100 held by any local adapter on *this* /24 does.
fn pick_candidate_ip(device_ip: Ipv4Addr, used_ips: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    let octets = device_ip.octets();
    let device_last = octets[3];
    let base = [octets[0], octets[1], octets[2]];

    let mut candidates = Vec::new();
    let starts: &[u8] = &[100, 101, 99, 102, 98, 103, 97, 104, 96, 105, 95];
    for &last in starts {
        if last != device_last && last != 0 && last != 255 && last != 1 {
            let candidate = Ipv4Addr::new(base[0], base[1], base[2], last);
            if !used_ips.contains(&candidate) {
                candidates.push(candidate);
            }
        }
    }
    candidates
}

/// Pick a scratch last octet on the candidate /24 that isn't the device,
/// a candidate, or a reserved address. The scratch is bound temporarily
/// so conflict probes route on-link (see `adopt_subnet`); the cache
/// probe uses the same picker for its identity scratch.
pub(crate) fn pick_scratch(device_ip: Ipv4Addr, candidates: &[Ipv4Addr]) -> Ipv4Addr {
    let o = device_ip.octets();
    let device_last = o[3];
    let taken: Vec<u8> = candidates.iter().map(|c| c.octets()[3]).collect();
    for &last in &[254u8, 253, 252, 251, 250, 2, 3, 4, 5, 6] {
        if last != device_last && !taken.contains(&last) {
            return Ipv4Addr::new(o[0], o[1], o[2], last);
        }
    }
    Ipv4Addr::new(o[0], o[1], o[2], 254)
}

/// A secondary IP the auto-adopt path has bound (or is mid-binding) but not
/// yet handed over to `adopted_ips`. Tagged with the adoption id that owns
/// it so a rollback or reconcile only ever removes its own IP, never one a
/// newer adoption has since bound at the same (deterministic) address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingIp {
    pub iface: String,
    pub ip: Ipv4Addr,
    pub adoption_id: u64,
}

/// Shared registry of `PendingIp`s. Lives on `NetworkManager`; a clone is
/// handed to the auto-adopt loop and reconciled on stop.
pub type PendingIps = Arc<Mutex<Vec<PendingIp>>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeSourceState {
    Ready,
    Pending,
    #[cfg(windows)]
    Tentative,
    #[cfg(windows)]
    RoutePending {
        expected: u32,
        observed: u32,
    },
}

/// Injectable seam for the OS-touching work `adopt_subnet` performs, so its
/// scratch/final bookkeeping and rollback can be unit-tested without binding
/// real addresses or probing the wire.
#[allow(async_fn_in_trait)]
pub trait AdoptOps {
    fn check_writes_available(&self) -> Result<(), AppError> {
        Ok(())
    }
    async fn observe(&self, _iface: &str) -> Result<super::InterfaceInfo, AppError> {
        Err(AppError::Network("Adapter observation unavailable".into()))
    }
    /// Bind a secondary IP (production: `New-NetIPAddress`).
    async fn add(&self, iface: &str, ip: Ipv4Addr, mask: &str) -> Result<(), AppError>;
    /// Remove a secondary IP (production: `netsh delete address`).
    async fn remove(&self, iface: &str, ip: Ipv4Addr) -> Result<(), AppError>;
    /// A newly added address can still be tentative while Windows runs DAD.
    /// Only a preferred source with an on-link route can run conflict probes.
    async fn probe_ready(
        &self,
        _iface: &str,
        _source: Ipv4Addr,
        _target: Ipv4Addr,
    ) -> Result<bool, AppError> {
        Err(AppError::Network(
            "Probe source readiness unavailable".into(),
        ))
    }
    async fn probe_state(
        &self,
        iface: &str,
        source: Ipv4Addr,
        target: Ipv4Addr,
    ) -> Result<ProbeSourceState, AppError> {
        self.probe_ready(iface, source, target).await.map(|ready| {
            if ready {
                ProbeSourceState::Ready
            } else {
                ProbeSourceState::Pending
            }
        })
    }
    /// Probe whether `target` is already in use on-link. Returns `true` for
    /// in-use OR indeterminate — the caller must not claim a maybe-used IP.
    async fn probe(&self, target: Ipv4Addr, source: Option<Ipv4Addr>) -> bool;
}

/// Production `AdoptOps`: delegates to typed native address operations and
/// bound probes. Dropping an adoption requests cancellation; the executor
/// retains its child, observation and conflicting-write barrier until drained.
pub struct RealAdoptOps;

fn temporary_observation(
    mut current: super::InterfaceInfo,
    native: Option<(bool, Vec<super::interface::IpInfo>)>,
) -> Result<super::InterfaceInfo, AppError> {
    let (is_up, ips) = native
        .ok_or_else(|| AppError::Network("Temporary adapter observation unavailable".into()))?;
    current.is_up = is_up;
    current.ips = ips;
    Ok(current)
}

impl AdoptOps for RealAdoptOps {
    fn check_writes_available(&self) -> Result<(), AppError> {
        #[cfg(windows)]
        {
            super::native_operations::check_writes_available()
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
    }
    async fn observe(&self, iface: &str) -> Result<super::InterfaceInfo, AppError> {
        let current = super::interface::get_by_name(iface).await?;
        if super::interface::index_for_mac(&current.mac).is_none() {
            return Err(AppError::Network(
                "Temporary adapter index is unavailable or ambiguous".into(),
            ));
        }
        let native = super::interface::quick_status_by_mac(&current.mac);
        temporary_observation(current, native)
    }
    async fn add(&self, iface: &str, ip: Ipv4Addr, mask: &str) -> Result<(), AppError> {
        ip_config::add_secondary_ip(iface, &ip.to_string(), mask).await
    }
    async fn remove(&self, iface: &str, ip: Ipv4Addr) -> Result<(), AppError> {
        ip_config::remove_secondary_ip(iface, &ip.to_string()).await
    }
    async fn probe_ready(
        &self,
        iface: &str,
        source: Ipv4Addr,
        target: Ipv4Addr,
    ) -> Result<bool, AppError> {
        self.probe_state(iface, source, target)
            .await
            .map(|state| state == ProbeSourceState::Ready)
    }
    async fn probe_state(
        &self,
        iface: &str,
        source: Ipv4Addr,
        target: Ipv4Addr,
    ) -> Result<ProbeSourceState, AppError> {
        #[cfg(windows)]
        {
            super::interface::conflict_probe_source_state(iface, source, target).await
        }
        #[cfg(not(windows))]
        {
            let _ = (iface, source, target);
            Err(AppError::Network(
                "Native source readiness requires Windows".into(),
            ))
        }
    }
    async fn probe(&self, target: Ipv4Addr, source: Option<Ipv4Addr>) -> bool {
        // A probe error (couldn't determine conflict) is treated as in-use.
        match super::arp::send_arp_probe(target, source, std::time::Duration::from_secs(1)).await {
            Ok(occupied) => occupied,
            Err(error) => {
                log::warn!("Conflict probe for {target} from {source:?} is inconclusive: {error}");
                true
            }
        }
    }
}

/// Temporary writes use the existing config transaction before the OS call.
/// Ordinary committed restore/removal continues to use RealAdoptOps directly.
pub(crate) struct PendingAdoptOps<'a, O> {
    pub config: &'a crate::config::AppConfig,
    pub adapter_mac: &'a str,
    pub ops: O,
    pub persist: fn(&crate::config::AppSettings) -> Result<(), AppError>,
}

impl<'a, O: AdoptOps> PendingAdoptOps<'a, O> {
    pub fn new(config: &'a crate::config::AppConfig, adapter_mac: &'a str, ops: O) -> Self {
        Self {
            config,
            adapter_mac,
            ops,
            persist: crate::config::save_to_disk,
        }
    }

    async fn observe_owned(&self, iface: &str) -> Result<super::InterfaceInfo, AppError> {
        let current = self.ops.observe(iface).await?;
        if super::device_registry::canonical_mac(&current.mac)
            != super::device_registry::canonical_mac(self.adapter_mac)
            || super::device_registry::canonical_mac(self.adapter_mac).is_none()
        {
            return Err(AppError::Network(
                "Temporary address adapter changed".into(),
            ));
        }
        Ok(current)
    }
}

impl<O: AdoptOps> AdoptOps for PendingAdoptOps<'_, O> {
    fn check_writes_available(&self) -> Result<(), AppError> {
        self.ops.check_writes_available()
    }
    async fn add(&self, iface: &str, ip: Ipv4Addr, mask: &str) -> Result<(), AppError> {
        self.check_writes_available()?;
        let prefix = ip_config::mask_to_prefix(mask)?;
        let owner = super::device_registry::canonical_mac(self.adapter_mac)
            .ok_or_else(|| AppError::Network("Invalid temporary adapter owner".into()))?;
        let row = crate::config::PendingAddress {
            adapter_mac: owner,
            address: ip.to_string(),
            prefix,
        };
        let current = self.observe_owned(iface).await?;
        if current.ips.iter().any(|a| a.address == row.address) {
            return Err(AppError::Network(
                "Address already exists; temporary ownership not claimed".into(),
            ));
        }
        // An earlier failed remove can leave only its durable record. A fresh
        // observation of absence retires it before reserving the next attempt.
        if self.config.get().pending_addresses.contains(&row) {
            self.config.forget_temporary_with(&row, self.persist)?;
        }
        self.config
            .reserve_temporary_with(row.clone(), self.persist)?;
        // Observe again after the save: an external address added before our
        // OS operation must not be claimed or later removed by this attempt.
        if self
            .observe_owned(iface)
            .await?
            .ips
            .iter()
            .any(|a| a.address == row.address)
        {
            self.config.forget_temporary_with(&row, self.persist)?;
            return Err(AppError::Network(
                "Address appeared before temporary add; no OS change made".into(),
            ));
        }
        // Any error is ambiguous until reconciliation observes OS state; keep
        // the durable ownership even if the child timed out after applying.
        self.ops.add(iface, ip, mask).await
    }

    async fn remove(&self, iface: &str, ip: Ipv4Addr) -> Result<(), AppError> {
        self.check_writes_available()?;
        let settings = self.config.get();
        let row = settings.pending_addresses.into_iter().find(|p| {
            p.address == ip.to_string()
                && Some(p.adapter_mac.clone())
                    == super::device_registry::canonical_mac(self.adapter_mac)
        });
        let Some(row) = row else {
            return Ok(());
        }; // committed/manual claim wins
        if settings.adopted_meta.values().any(|m| {
            m.address.as_ref() == Some(&row.address)
                && m.adapter_mac.as_ref() == Some(&row.adapter_mac)
        }) {
            return self.config.forget_temporary_with(&row, self.persist);
        }
        let current = self.observe_owned(iface).await?;
        let observed = current.ips.iter().find(|a| a.address == row.address);
        if let Some(observed) = observed {
            if observed.prefix != row.prefix {
                return Err(AppError::Network(
                    "Temporary address prefix changed; no removal made".into(),
                ));
            }
            self.ops.remove(iface, ip).await?;
            if self
                .observe_owned(iface)
                .await?
                .ips
                .iter()
                .any(|a| a.address == row.address)
            {
                return Err(AppError::Network(
                    "Temporary address remains after removal".into(),
                ));
            }
        }
        self.config.forget_temporary_with(&row, self.persist)
    }

    async fn probe_ready(
        &self,
        iface: &str,
        source: Ipv4Addr,
        target: Ipv4Addr,
    ) -> Result<bool, AppError> {
        self.ops.probe_ready(iface, source, target).await
    }
    async fn probe_state(
        &self,
        iface: &str,
        source: Ipv4Addr,
        target: Ipv4Addr,
    ) -> Result<ProbeSourceState, AppError> {
        self.ops.probe_state(iface, source, target).await
    }
    async fn probe(&self, target: Ipv4Addr, source: Option<Ipv4Addr>) -> bool {
        self.ops.probe(target, source).await
    }
}

async fn pending_insert(pending: &PendingIps, iface: &str, ip: Ipv4Addr, adoption_id: u64) {
    pending.lock().await.push(PendingIp {
        iface: iface.to_string(),
        ip,
        adoption_id,
    });
}

async fn pending_remove(pending: &PendingIps, iface: &str, ip: Ipv4Addr, adoption_id: u64) {
    pending
        .lock()
        .await
        .retain(|e| !(e.iface == iface && e.ip == ip && e.adoption_id == adoption_id));
}

/// Drop a pending entry after its IP has been recorded in `adopted_ips` and
/// is owned. Does NOT touch the OS — the IP stays bound. Removes only the
/// exact `(iface, ip, adoption_id)` entry, so a still-pending scratch from a
/// failed release under the same id is left for reconciliation.
#[cfg(test)]
pub async fn pending_handover(pending: &PendingIps, iface: &str, ip: Ipv4Addr, adoption_id: u64) {
    pending_remove(pending, iface, ip, adoption_id).await;
}

/// Bind a standalone scratch address with the breadcrumb-first
/// discipline `adopt_subnet` uses internally: the pending entry is
/// registered before the bind. Ambiguous failures keep their breadcrumb
/// until reconciliation observes the OS; production ops persist it too.
pub async fn bind_scratch<O: AdoptOps>(
    ops: &O,
    pending: &PendingIps,
    iface: &str,
    scratch: Ipv4Addr,
    adoption_id: u64,
) -> Result<(), AppError> {
    pending_insert(pending, iface, scratch, adoption_id).await;
    match ops.add(iface, scratch, "255.255.255.0").await {
        Ok(()) => Ok(()),
        Err(e) => {
            // Production removal observes exact ownership/OS state. If that
            // fails, both breadcrumbs remain for restart reconciliation.
            release_scratch(ops, pending, iface, scratch, adoption_id).await;
            Err(e)
        }
    }
}

/// Release a scratch bound by [`bind_scratch`]. A successful remove
/// drops the breadcrumb; a failed remove keeps it so `reconcile_pending`
/// retries later — the scratch is never silently orphaned.
pub async fn release_scratch<O: AdoptOps>(
    ops: &O,
    pending: &PendingIps,
    iface: &str,
    scratch: Ipv4Addr,
    adoption_id: u64,
) {
    match ops.remove(iface, scratch).await {
        Ok(()) => pending_remove(pending, iface, scratch, adoption_id).await,
        Err(e) => log::warn!(
            "Failed to release probe scratch {} on {} (adoption {}): {} — breadcrumb kept for reconcile",
            scratch,
            iface,
            adoption_id,
            e
        ),
    }
}

/// Roll back leftover pending IPs with a best-effort OS remove. `filter =
/// Some(id)` acts only on entries owned by that adoption (per-adoption
/// timeout / rollback); `None` acts on every entry (stop reconciliation).
/// An entry whose remove succeeds is dropped; one whose remove fails is kept
/// so a later reconcile retries it.
pub async fn reconcile_pending<O: AdoptOps>(ops: &O, pending: &PendingIps, filter: Option<u64>) {
    let targets: Vec<PendingIp> = {
        let guard = pending.lock().await;
        guard
            .iter()
            .filter(|e| filter.is_none_or(|id| e.adoption_id == id))
            .cloned()
            .collect()
    };
    for entry in targets {
        match ops.remove(&entry.iface, entry.ip).await {
            Ok(()) => {
                log::info!(
                    "Pending-IP reconcile: removed leftover {} on {} (adoption {})",
                    entry.ip,
                    entry.iface,
                    entry.adoption_id
                );
                pending_remove(pending, &entry.iface, entry.ip, entry.adoption_id).await;
            }
            Err(e) => log::warn!(
                "Pending-IP reconcile: failed to remove {} (adoption {}): {} — will retry",
                entry.ip,
                entry.adoption_id,
                e
            ),
        }
    }
}

// The five-second limit proved too short during rapid remove/re-add on Windows.
// Polling still returns immediately on readiness; the longer ceiling is only
// for a source/route that remains pending, never permission to probe blindly.
const PROBE_SOURCE_READY_TIMEOUT: Duration = Duration::from_secs(12);
const PROBE_SOURCE_POLL: Duration = Duration::from_millis(100);

/// Address creation acknowledges presence before Windows finishes DAD and
/// installs its usable route. Wait on native state; never interpret a source
/// that is still tentative as evidence that all candidate addresses are busy.
pub(super) async fn wait_for_probe_source<O: AdoptOps>(
    ops: &O,
    iface: &str,
    source: Ipv4Addr,
    target: Ipv4Addr,
    shutdown: &watch::Receiver<bool>,
) -> Result<bool, AppError> {
    let mut shutdown = shutdown.clone();
    let started = tokio::time::Instant::now();
    let mut last_state = None;
    tokio::time::timeout(PROBE_SOURCE_READY_TIMEOUT, async {
        loop {
            if *shutdown.borrow() {
                return Ok(false);
            }
            let state = ops.probe_state(iface, source, target).await?;
            if last_state != Some(state) {
                log::info!("event=adoption_source_state source={} target={} state={:?} elapsed_ms={}",
                    source, target, state, started.elapsed().as_millis());
                last_state = Some(state);
            }
            if state == ProbeSourceState::Ready {
                return Ok(true);
            }
            tokio::select! {
                _ = tokio::time::sleep(PROBE_SOURCE_POLL) => {},
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        return Ok(false);
                    }
                }
            }
        }
    })
    .await
    .map_err(|_| {
        AppError::AddressNotReady(format!(
            "Adoption address {source} did not become usable on {iface} within {}s (last state: {last_state:?})",
            PROBE_SOURCE_READY_TIMEOUT.as_secs()
        ))
    })?
}

/// Adopt a foreign subnet by adding a secondary IP to the interface.
/// Returns the adopted IP if successful, or `None` if already on that subnet
/// (or if a shutdown was signalled before the final bind).
///
/// Every secondary IP this binds is registered in `pending` (tagged with
/// `adoption_id`) before the bind and removed once released or handed over,
/// so a dropped future or an interrupting stop leaves a breadcrumb that
/// `reconcile_pending` can clean up. The caller removes the final entry via
/// `pending_handover` only after recording the adoption in `adopted_ips`.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub async fn adopt_subnet<O: AdoptOps>(
    ops: &O,
    interface_name: &str,
    device_ip: Ipv4Addr,
    current_ips: &[Ipv4Addr],
    local_ips: &[Ipv4Addr],
    pending: &PendingIps,
    adoption_id: u64,
    shutdown: &watch::Receiver<bool>,
) -> Result<Option<Ipv4Addr>, AppError> {
    adopt_subnet_with_scratch(
        ops,
        interface_name,
        device_ip,
        current_ips,
        local_ips,
        pending,
        adoption_id,
        shutdown,
        None,
    )
    .await
}

/// A probe's owned temporary address can serve the conflict checks too.
/// The caller retains cleanup responsibility on every early return/drop.
#[derive(Clone, Copy)]
pub(super) struct PreparedScratch {
    pub address: Ipv4Addr,
    pub adoption_id: u64,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn adopt_subnet_with_scratch<O: AdoptOps>(
    ops: &O,
    interface_name: &str,
    device_ip: Ipv4Addr,
    current_ips: &[Ipv4Addr],
    local_ips: &[Ipv4Addr],
    pending: &PendingIps,
    adoption_id: u64,
    shutdown: &watch::Receiver<bool>,
    prepared: Option<PreparedScratch>,
) -> Result<Option<Ipv4Addr>, AppError> {
    if let Some(scratch) = prepared {
        if scratch.adoption_id != adoption_id
            || scratch.address == device_ip
            || !already_on_subnet(device_ip, &[scratch.address])
            || !pending.lock().await.iter().any(|p| {
                p.iface == interface_name && p.ip == scratch.address && p.adoption_id == adoption_id
            })
        {
            return Err(AppError::Network(
                "Prepared probe address ownership is unconfirmed".into(),
            ));
        }
    }
    // Only the exact owned scratch is exempt from the existing-address gate.
    let current_ips: Vec<_> = current_ips
        .iter()
        .copied()
        .filter(|ip| prepared.is_none_or(|scratch| scratch.address != *ip))
        .collect();
    if already_on_subnet(device_ip, &current_ips) {
        log::info!("Already on subnet for {} — skipping auto-adopt", device_ip);
        return Ok(None);
    }

    // Exclude every IP held by ANY local interface, not just the target —
    // the ARP probe below can't detect the host's own addresses, so a
    // candidate already on e.g. WiFi would look "free" and collide. Union
    // with the passed-in target IPs in case enumeration hasn't yet reflected
    // a freshly-added one.
    let mut used_ips = local_ips.to_vec();
    used_ips.extend_from_slice(&current_ips);
    let candidates = pick_candidate_ip(device_ip, &used_ips);
    if candidates.is_empty() {
        return Err(AppError::Network(format!(
            "No candidate IPs available on subnet for {}",
            device_ip
        )));
    }

    // Temporarily bind a scratch address on the candidate /24 so the
    // conflict probes below route on-link. Without an address on this
    // subnet the probe is structurally blind and risks a duplicate-IP
    // assignment. A failed scratch bind aborts; never probe unbound.
    let scratch = prepared
        .map(|p| p.address)
        .unwrap_or_else(|| pick_scratch(device_ip, &candidates));
    log::info!(
        "Auto-adopt {}: {} scratch {} on {} for on-link probe",
        adoption_id,
        if prepared.is_some() {
            "reusing"
        } else {
            "binding"
        },
        scratch,
        interface_name
    );
    if prepared.is_none() {
        bind_scratch(ops, pending, interface_name, scratch, adoption_id).await?;
    }
    let source = Some(scratch);

    // Even readiness failure/shutdown follows the scratch cleanup below.
    log::info!("Auto-adopt {adoption_id}: waiting for probe source {scratch} to become usable");
    let readiness = wait_for_probe_source(ops, interface_name, scratch, device_ip, shutdown).await;
    let mut chosen = None;
    if matches!(readiness, Ok(true)) {
        for candidate in &candidates {
            if *shutdown.borrow() {
                break;
            }
            if !ops.probe(*candidate, source).await {
                chosen = Some(*candidate);
                break;
            }
            log::info!(
                "Candidate {} is occupied or its conflict probe is inconclusive, trying next",
                candidate
            );
        }
    }

    {
        match ops.remove(interface_name, scratch).await {
            Ok(()) => {
                pending_remove(pending, interface_name, scratch, adoption_id).await;
                log::info!("Auto-adopt {}: released scratch {}", adoption_id, scratch);
            }
            // Scratch still bound — keep the breadcrumb for reconcile.
            Err(e) => log::warn!(
                "Failed to release scratch {} (left for reconcile): {}",
                scratch,
                e
            ),
        }
    }

    if !readiness? || *shutdown.borrow() {
        return Ok(None);
    }
    let candidate = match chosen {
        Some(c) => c,
        None => {
            return Err(AppError::Network(format!(
                "Could not find available IP on subnet for {}",
                device_ip
            )))
        }
    };

    // Shutdown check immediately before the final bind: a stop signalled
    // during probing means we should not bind at all. Nothing final is
    // registered yet, so there is nothing to roll back and the caller will
    // not record.
    if *shutdown.borrow() {
        log::info!(
            "Auto-adopt {}: shutdown before final bind — aborting cleanly",
            adoption_id
        );
        return Ok(None);
    }

    log::info!(
        "Auto-adopting subnet: adding {} to {}",
        candidate,
        interface_name
    );
    // Register the final IP BEFORE binding: a drop between the bind and the
    // caller's record leaves this breadcrumb for reconciliation.
    pending_insert(pending, interface_name, candidate, adoption_id).await;
    if let Err(e) = ops.add(interface_name, candidate, "255.255.255.0").await {
        release_scratch(ops, pending, interface_name, candidate, adoption_id).await;
        return Err(e);
    }
    // The final address also starts tentative. Do not publish adoption or
    // launch the subnet sweep until this source and its route are usable.
    log::info!("Auto-adopt {adoption_id}: waiting for adopted source {candidate} to become usable");
    match wait_for_probe_source(ops, interface_name, candidate, device_ip, shutdown).await {
        Ok(true) if !*shutdown.borrow() => Ok(Some(candidate)),
        result => {
            release_scratch(ops, pending, interface_name, candidate, adoption_id).await;
            result.map(|_| None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const OWNER: &str = "40:cd:3a:00:00:01";
    fn no_save(_: &crate::config::AppSettings) -> Result<(), AppError> {
        Ok(())
    }
    fn fail_save(_: &crate::config::AppSettings) -> Result<(), AppError> {
        Err(AppError::Network("injected save failure".into()))
    }
    fn temporary_config() -> crate::config::AppConfig {
        crate::config::AppConfig::temporary_test_config(crate::config::AppSettings {
            selected_adapter_mac: Some(OWNER.into()),
            network_mode: crate::config::NetworkMode::StaticAuto,
            ..Default::default()
        })
    }
    #[derive(Clone, Default)]
    struct CrashOps {
        addresses: Arc<std::sync::Mutex<Vec<super::super::interface::IpInfo>>>,
        fail_observe: Arc<std::sync::atomic::AtomicBool>,
        fail_after_add: Arc<std::sync::atomic::AtomicBool>,
        fail_remove: Arc<std::sync::atomic::AtomicBool>,
        writes: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }
    impl AdoptOps for CrashOps {
        async fn observe(&self, iface: &str) -> Result<super::super::InterfaceInfo, AppError> {
            if self.fail_observe.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(AppError::Network("native observation unavailable".into()));
            }
            Ok(super::super::InterfaceInfo {
                name: iface.into(),
                display_name: iface.into(),
                description: "test".into(),
                mac: OWNER.into(),
                ips: self.addresses.lock().unwrap().clone(),
                is_up: true,
                is_ethernet: true,
                is_wifi: false,
                is_vpn: false,
                is_virtual: false,
            })
        }
        async fn add(&self, _: &str, ip: Ipv4Addr, _: &str) -> Result<(), AppError> {
            self.writes.lock().unwrap().push("add");
            self.addresses
                .lock()
                .unwrap()
                .push(super::super::interface::IpInfo {
                    address: ip.to_string(),
                    prefix: 24,
                    subnet: "172.31.169.0/24".into(),
                });
            if self
                .fail_after_add
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                Err(AppError::Network("applied then timed out".into()))
            } else {
                Ok(())
            }
        }
        async fn remove(&self, _: &str, ip: Ipv4Addr) -> Result<(), AppError> {
            self.writes.lock().unwrap().push("remove");
            if self.fail_remove.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(AppError::Network("remove unavailable".into()));
            }
            self.addresses
                .lock()
                .unwrap()
                .retain(|a| a.address != ip.to_string());
            Ok(())
        }
        async fn probe_ready(
            &self,
            iface: &str,
            source: Ipv4Addr,
            _: Ipv4Addr,
        ) -> Result<bool, AppError> {
            Ok(self
                .observe(iface)
                .await?
                .ips
                .iter()
                .any(|ip| ip.address == source.to_string()))
        }
        async fn probe(&self, _: Ipv4Addr, _: Option<Ipv4Addr>) -> bool {
            false
        }
    }
    fn tracked<'a>(
        config: &'a crate::config::AppConfig,
        ops: &CrashOps,
    ) -> PendingAdoptOps<'a, CrashOps> {
        PendingAdoptOps {
            config,
            adapter_mac: OWNER,
            ops: ops.clone(),
            persist: no_save,
        }
    }

    #[tokio::test]
    async fn temporary_native_observation_requires_success_and_replaces_metadata_addresses() {
        let os = CrashOps::default();
        let metadata = os.observe("USB").await.unwrap();
        assert!(temporary_observation(metadata.clone(), None).is_err());
        let ip = super::super::interface::IpInfo {
            address: "172.31.169.254".into(),
            prefix: 24,
            subnet: "172.31.169.0/24".into(),
        };
        let current = temporary_observation(metadata, Some((false, vec![ip]))).unwrap();
        assert!(!current.is_up);
        assert_eq!(current.ips[0].address, "172.31.169.254");
        assert_eq!(current.ips[0].prefix, 24);
    }

    #[tokio::test]
    async fn temporary_observation_failure_retains_memory_and_durable_ownership() {
        let config = temporary_config();
        let os = CrashOps::default();
        let pending = new_pending();
        let ip = "172.31.169.254".parse().unwrap();
        let ops = tracked(&config, &os);
        bind_scratch(&ops, &pending, "USB", ip, 1).await.unwrap();
        os.fail_observe
            .store(true, std::sync::atomic::Ordering::Relaxed);
        release_scratch(&ops, &pending, "USB", ip, 1).await;
        assert_eq!(pending.lock().await.len(), 1);
        assert_eq!(config.get().pending_addresses.len(), 1);
        assert_eq!(os.addresses.lock().unwrap().len(), 1);
        assert_eq!(os.writes.lock().unwrap().as_slice(), ["add"]);
        os.fail_observe
            .store(false, std::sync::atomic::Ordering::Relaxed);
        release_scratch(&ops, &pending, "USB", ip, 1).await;
        assert!(pending.lock().await.is_empty());
        assert!(config.get().pending_addresses.is_empty());
        assert!(os.addresses.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn temporary_restart_recovers_scratch_and_uncommitted_final_without_memory() {
        for final_add in [false, true] {
            let config = temporary_config();
            let os = CrashOps::default();
            let pending = new_pending();
            let ops = tracked(&config, &os);
            let ip = if final_add {
                let (_tx, rx) = watch::channel(false);
                adopt_subnet(
                    &ops,
                    "old name",
                    "172.31.169.20".parse().unwrap(),
                    &[],
                    &[],
                    &pending,
                    1,
                    &rx,
                )
                .await
                .unwrap()
                .unwrap()
            } else {
                let ip = "172.31.169.254".parse().unwrap();
                bind_scratch(&ops, &pending, "old name", ip, 1)
                    .await
                    .unwrap();
                ip
            };
            let saved = crate::config::test_support::serialize_for_test(&config.get());
            drop(pending); // the entire process-local ownership list is lost
            let restarted = crate::config::AppConfig::temporary_test_config(
                crate::config::test_support::parse_for_test(&saved).unwrap(),
            );
            assert_eq!(restarted.get().pending_addresses.len(), 1);
            tracked(&restarted, &os)
                .remove("renamed adapter", ip)
                .await
                .unwrap();
            assert!(os.addresses.lock().unwrap().is_empty());
            assert!(restarted.get().pending_addresses.is_empty());
        }
    }

    #[tokio::test]
    async fn temporary_failed_save_and_existing_external_address_do_not_write() {
        let config = temporary_config();
        let os = CrashOps::default();
        let ip = "172.31.169.254".parse().unwrap();
        let mut ops = tracked(&config, &os);
        ops.persist = fail_save;
        assert!(ops.add("USB", ip, "255.255.255.0").await.is_err());
        assert!(config.get().pending_addresses.is_empty());
        assert!(os.writes.lock().unwrap().is_empty());
        os.add("USB", ip, "255.255.255.0").await.unwrap();
        os.writes.lock().unwrap().clear();
        let pending = new_pending();
        assert!(bind_scratch(&tracked(&config, &os), &pending, "USB", ip, 1)
            .await
            .is_err());
        assert_eq!(os.addresses.lock().unwrap().len(), 1);
        assert!(config.get().pending_addresses.is_empty());
        assert!(pending.lock().await.is_empty());
        assert!(os.writes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn temporary_ambiguous_add_and_failed_cleanup_remain_recoverable_after_restart() {
        let config = temporary_config();
        let os = CrashOps::default();
        let ip = "172.31.169.254".parse().unwrap();
        os.fail_after_add
            .store(true, std::sync::atomic::Ordering::Relaxed);
        os.fail_remove
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let pending = new_pending();
        assert!(bind_scratch(&tracked(&config, &os), &pending, "USB", ip, 1)
            .await
            .is_err());
        assert_eq!(config.get().pending_addresses.len(), 1);
        assert_eq!(pending.lock().await.len(), 1);
        let restarted = crate::config::AppConfig::temporary_test_config(
            crate::config::test_support::parse_for_test(
                &crate::config::test_support::serialize_for_test(&config.get()),
            )
            .unwrap(),
        );
        os.fail_remove
            .store(false, std::sync::atomic::Ordering::Relaxed);
        tracked(&restarted, &os).remove("USB", ip).await.unwrap();
        assert!(os.addresses.lock().unwrap().is_empty());
        assert!(restarted.get().pending_addresses.is_empty());
    }

    #[tokio::test]
    async fn temporary_commit_handoff_and_changed_prefix_protect_addresses() {
        let config = temporary_config();
        let os = CrashOps::default();
        let ip = "172.31.169.100".parse().unwrap();
        let ops = tracked(&config, &os);
        ops.add("USB", ip, "255.255.255.0").await.unwrap();
        os.addresses.lock().unwrap()[0].prefix = 25;
        assert!(ops.remove("USB", ip).await.is_err());
        assert_eq!(config.get().pending_addresses.len(), 1);
        assert_eq!(os.writes.lock().unwrap().as_slice(), ["add"]);
        os.addresses.lock().unwrap()[0].prefix = 24;
        // Production set_binding performs this exact atomic config transaction.
        config
            .set_temporary_test_binding(
                "172.31.169.0/24",
                crate::config::AdoptedMeta {
                    address: Some(ip.to_string()),
                    prefix: Some(24),
                    adapter_mac: Some(OWNER.into()),
                    applied: true,
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(config.get().pending_addresses.is_empty());
        ops.remove("USB", ip).await.unwrap(); // late cleanup cannot remove a committed address
        assert_eq!(os.addresses.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn temporary_status_save_failure_after_remove_retries_without_another_os_write() {
        let config = temporary_config();
        let os = CrashOps::default();
        let ip = "172.31.169.254".parse().unwrap();
        tracked(&config, &os)
            .add("USB", ip, "255.255.255.0")
            .await
            .unwrap();
        let mut ops = tracked(&config, &os);
        ops.persist = fail_save;
        assert!(ops.remove("USB", ip).await.is_err());
        assert!(os.addresses.lock().unwrap().is_empty());
        assert_eq!(config.get().pending_addresses.len(), 1);
        tracked(&config, &os).remove("USB", ip).await.unwrap();
        assert!(config.get().pending_addresses.is_empty());
        assert_eq!(os.writes.lock().unwrap().as_slice(), ["add", "remove"]);
    }

    // ── DwellTracker (two-observation adoption gate) ─────────────────

    const SUBNET_A: &str = "169.254.168.0/24";
    const SUBNET_B: &str = "169.254.43.0/24";
    const MAC_1: &str = "AA:BB:CC:DD:EE:01";
    const MAC_2: &str = "AA:BB:CC:DD:EE:02";

    #[test]
    fn dwell_first_observation_starts_and_waits() {
        let mut d = DwellTracker::new();
        let t0 = Instant::now();
        assert_eq!(d.check(SUBNET_A, MAC_1, "t0", t0), DwellVerdict::Started);
    }

    #[test]
    fn dwell_allows_one_directed_probe_only_after_the_broadcast_window() {
        let mut dwell = DwellTracker::new();
        let now = Instant::now();
        assert!(!dwell.take_probe_due(SUBNET_A, MAC_1, now));
        dwell.check(SUBNET_A, MAC_1, "first", now);
        assert!(!dwell.take_probe_due(SUBNET_A, MAC_1, now));
        assert!(!dwell.take_probe_due(SUBNET_A, MAC_1, now + Duration::from_secs(1)));
        let due = now + DWELL_MIN;
        assert_eq!(
            dwell.check(SUBNET_A, MAC_1, "first", due),
            DwellVerdict::Waiting
        );
        assert!(dwell.take_probe_due(SUBNET_A, MAC_1, due));
        assert!(!dwell.take_probe_due(SUBNET_A, MAC_1, due + Duration::from_secs(60)));
        assert_eq!(
            dwell.check(SUBNET_A, MAC_1, "repeat", due),
            DwellVerdict::Mature
        );
        dwell.prune_subnet(SUBNET_A);
        dwell.check(SUBNET_A, MAC_1, "later", due);
        assert!(dwell.take_probe_due(SUBNET_A, MAC_1, due + DWELL_MIN));
    }

    #[test]
    fn dwell_tracks_both_subnets_before_either_needs_a_slow_identity_probe() {
        let mut dwell = DwellTracker::new();
        let now = Instant::now();
        for (subnet, mac) in [(SUBNET_A, MAC_1), (SUBNET_B, MAC_2)] {
            assert_eq!(
                dwell.check(subnet, mac, "first", now),
                DwellVerdict::Started
            );
            assert!(!dwell.take_probe_due(subnet, mac, now));
        }
        for (subnet, mac) in [(SUBNET_A, MAC_1), (SUBNET_B, MAC_2)] {
            assert_eq!(
                dwell.check(subnet, mac, "repeat", now + DWELL_MIN),
                DwellVerdict::Mature
            );
        }
    }

    #[test]
    fn dwell_unchanged_token_never_matures() {
        // The ARP map is persistent: one frame re-appears in every later
        // snapshot. However many passes elapse, the same token must wait.
        let mut d = DwellTracker::new();
        let t0 = Instant::now();
        d.check(SUBNET_A, MAC_1, "t0", t0);
        for secs in [2u64, 10, 60, 300] {
            assert_eq!(
                d.check(SUBNET_A, MAC_1, "t0", t0 + Duration::from_secs(secs)),
                DwellVerdict::Waiting,
                "same token at +{}s must not mature",
                secs
            );
        }
    }

    #[test]
    fn dwell_advanced_token_before_min_waits() {
        let mut d = DwellTracker::new();
        let t0 = Instant::now();
        d.check(SUBNET_A, MAC_1, "t0", t0);
        assert_eq!(
            d.check(SUBNET_A, MAC_1, "t1", t0 + Duration::from_secs(1)),
            DwellVerdict::Waiting
        );
    }

    #[test]
    fn dwell_advanced_token_after_min_matures() {
        let mut d = DwellTracker::new();
        let t0 = Instant::now();
        d.check(SUBNET_A, MAC_1, "t0", t0);
        assert_eq!(
            d.check(SUBNET_A, MAC_1, "t1", t0 + Duration::from_secs(2)),
            DwellVerdict::Mature
        );
    }

    #[test]
    fn dwell_early_second_frame_matures_on_a_later_pass() {
        // The second frame lands quickly (a boot-time ARP burst); the
        // token difference is durable, so the candidate matures on the
        // first pass at or after the dwell minimum.
        let mut d = DwellTracker::new();
        let t0 = Instant::now();
        d.check(SUBNET_A, MAC_1, "t0", t0);
        assert_eq!(
            d.check(SUBNET_A, MAC_1, "t1", t0 + Duration::from_millis(500)),
            DwellVerdict::Waiting
        );
        assert_eq!(
            d.check(SUBNET_A, MAC_1, "t1", t0 + Duration::from_secs(2)),
            DwellVerdict::Mature
        );
    }

    #[test]
    fn dwell_mac_moving_subnets_restarts() {
        let mut d = DwellTracker::new();
        let t0 = Instant::now();
        d.check(SUBNET_A, MAC_1, "t0", t0);
        // Same device re-ARPs from a different subnet: old candidacy is
        // abandoned, the new one starts fresh.
        assert_eq!(
            d.check(SUBNET_B, MAC_1, "t1", t0 + Duration::from_secs(3)),
            DwellVerdict::Started
        );
        // Returning to the original subnet also starts fresh — the old
        // candidate is gone, an advanced token alone must not mature.
        assert_eq!(
            d.check(SUBNET_A, MAC_1, "t2", t0 + Duration::from_secs(6)),
            DwellVerdict::Started
        );
    }

    #[test]
    fn dwell_two_devices_on_one_subnet_are_independent() {
        // Two devices alternating single frames must not reset each
        // other (a subnet-keyed candidate overwritten by each new MAC
        // would loop forever) and must not mature each other.
        let mut d = DwellTracker::new();
        let t0 = Instant::now();
        assert_eq!(d.check(SUBNET_A, MAC_1, "a0", t0), DwellVerdict::Started);
        assert_eq!(
            d.check(SUBNET_A, MAC_2, "b0", t0 + Duration::from_secs(1)),
            DwellVerdict::Started
        );
        // Device 1 unchanged: still waiting, unaffected by device 2.
        assert_eq!(
            d.check(SUBNET_A, MAC_1, "a0", t0 + Duration::from_secs(3)),
            DwellVerdict::Waiting
        );
        // Device 1's own repeat matures only its own candidacy…
        assert_eq!(
            d.check(SUBNET_A, MAC_1, "a1", t0 + Duration::from_secs(5)),
            DwellVerdict::Mature
        );
        // …device 2 with its original token keeps waiting.
        assert_eq!(
            d.check(SUBNET_A, MAC_2, "b0", t0 + Duration::from_secs(5)),
            DwellVerdict::Waiting
        );
    }

    #[test]
    fn dwell_prune_subnet_clears_only_that_subnet() {
        let mac_3 = "AA:BB:CC:DD:EE:03";
        let mut d = DwellTracker::new();
        let t0 = Instant::now();
        d.check(SUBNET_A, MAC_1, "a0", t0);
        d.check(SUBNET_A, MAC_2, "b0", t0);
        d.check(SUBNET_B, mac_3, "c0", t0);
        d.prune_subnet(SUBNET_A);
        // Both subnet-A candidates restart from scratch.
        assert_eq!(
            d.check(SUBNET_A, MAC_1, "a1", t0 + Duration::from_secs(9)),
            DwellVerdict::Started
        );
        assert_eq!(
            d.check(SUBNET_A, MAC_2, "b1", t0 + Duration::from_secs(9)),
            DwellVerdict::Started
        );
        // The untouched subnet-B candidate survived: its own repeat
        // observation matures normally.
        assert_eq!(
            d.check(SUBNET_B, mac_3, "c1", t0 + Duration::from_secs(9)),
            DwellVerdict::Mature
        );
    }

    #[test]
    fn dwell_stale_candidate_expires_and_restarts() {
        // A candidate that stopped being re-checked (its subnet no
        // longer clears the gates) ages out; when it qualifies again an
        // advanced token alone must not mature — the dwell restarts.
        let mut d = DwellTracker::new();
        let t0 = Instant::now();
        d.check(SUBNET_A, MAC_1, "t0", t0);
        assert_eq!(
            d.check(SUBNET_A, MAC_1, "t1", t0 + Duration::from_secs(601)),
            DwellVerdict::Started
        );
    }

    // ── already_on_subnet ───────────────────────────────────────────

    #[test]
    fn already_on_subnet_same_24() {
        let device = Ipv4Addr::new(192, 168, 1, 50);
        let ours = vec![Ipv4Addr::new(192, 168, 1, 100)];
        assert!(already_on_subnet(device, &ours));
    }

    #[test]
    fn already_on_subnet_different_third_octet() {
        let device = Ipv4Addr::new(192, 168, 2, 50);
        let ours = vec![Ipv4Addr::new(192, 168, 1, 100)];
        assert!(!already_on_subnet(device, &ours));
    }

    #[test]
    fn already_on_subnet_different_second_octet() {
        let device = Ipv4Addr::new(10, 1, 1, 50);
        let ours = vec![Ipv4Addr::new(10, 2, 1, 50)];
        assert!(!already_on_subnet(device, &ours));
    }

    #[test]
    fn already_on_subnet_empty_ips() {
        let device = Ipv4Addr::new(10, 0, 0, 1);
        assert!(!already_on_subnet(device, &[]));
    }

    #[test]
    fn already_on_subnet_multiple_ips_one_matches() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        let ours = vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(10, 0, 0, 100)];
        assert!(already_on_subnet(device, &ours));
    }

    #[test]
    fn already_on_subnet_exact_same_ip() {
        let device = Ipv4Addr::new(192, 168, 1, 100);
        let ours = vec![Ipv4Addr::new(192, 168, 1, 100)];
        assert!(already_on_subnet(device, &ours));
    }

    // ── pick_candidate_ip ───────────────────────────────────────────

    #[test]
    fn pick_candidate_returns_same_subnet() {
        let device = Ipv4Addr::new(192, 168, 5, 10);
        let candidates = pick_candidate_ip(device, &[]);
        assert!(!candidates.is_empty());
        for c in &candidates {
            let o = c.octets();
            assert_eq!(o[0], 192);
            assert_eq!(o[1], 168);
            assert_eq!(o[2], 5);
        }
    }

    #[test]
    fn pick_candidate_starts_at_100() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        let candidates = pick_candidate_ip(device, &[]);
        assert_eq!(candidates[0], Ipv4Addr::new(10, 0, 0, 100));
    }

    #[test]
    fn pick_candidate_skips_device_ip() {
        let device = Ipv4Addr::new(10, 0, 0, 100);
        let candidates = pick_candidate_ip(device, &[]);
        assert!(!candidates.contains(&Ipv4Addr::new(10, 0, 0, 100)));
    }

    #[test]
    fn pick_candidate_skips_reserved_addresses() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        let candidates = pick_candidate_ip(device, &[]);
        for c in &candidates {
            let last = c.octets()[3];
            assert_ne!(last, 0, "Should not pick .0 (network)");
            assert_ne!(last, 255, "Should not pick .255 (broadcast)");
            assert_ne!(last, 1, "Should not pick .1 (gateway)");
        }
    }

    #[test]
    fn pick_candidate_returns_multiple() {
        let device = Ipv4Addr::new(172, 16, 0, 50);
        let candidates = pick_candidate_ip(device, &[]);
        assert!(candidates.len() >= 5, "Should return several candidates");
    }

    #[test]
    fn pick_candidate_no_duplicates() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        let candidates = pick_candidate_ip(device, &[]);
        let unique: std::collections::HashSet<_> = candidates.iter().collect();
        assert_eq!(unique.len(), candidates.len());
    }

    #[test]
    fn pick_candidate_skips_used_ip() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        // A local adapter already holds .100 — candidate should skip it.
        let candidates = pick_candidate_ip(device, &[Ipv4Addr::new(10, 0, 0, 100)]);
        assert!(!candidates.contains(&Ipv4Addr::new(10, 0, 0, 100)));
        // Should start with .101 instead.
        assert_eq!(candidates[0], Ipv4Addr::new(10, 0, 0, 101));
    }

    #[test]
    fn pick_candidate_skips_multiple_used_ips() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        let used = [Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 101)];
        let candidates = pick_candidate_ip(device, &used);
        assert!(!candidates.contains(&Ipv4Addr::new(10, 0, 0, 100)));
        assert!(!candidates.contains(&Ipv4Addr::new(10, 0, 0, 101)));
        // Should start with .99.
        assert_eq!(candidates[0], Ipv4Addr::new(10, 0, 0, 99));
    }

    #[test]
    fn pick_candidate_excludes_full_ip_on_this_subnet_only() {
        // M7: a WiFi adapter holds 192.168.5.100 on the SAME /24 we're
        // adopting — that candidate must be excluded (an ARP probe can't
        // see the host's own IP).
        let device = Ipv4Addr::new(192, 168, 5, 10);
        let wifi_ip = Ipv4Addr::new(192, 168, 5, 100);
        let candidates = pick_candidate_ip(device, &[wifi_ip]);
        assert!(!candidates.contains(&wifi_ip));
    }

    #[test]
    fn pick_candidate_does_not_block_same_last_octet_on_other_subnet() {
        // A .100 on a DIFFERENT /24 must not block .100 here — the fix
        // compares full IPs, not last octets.
        let device = Ipv4Addr::new(192, 168, 5, 10);
        let other_subnet_ip = Ipv4Addr::new(10, 0, 0, 100);
        let candidates = pick_candidate_ip(device, &[other_subnet_ip]);
        assert!(candidates.contains(&Ipv4Addr::new(192, 168, 5, 100)));
    }

    // ── pick_scratch (D3 on-link probe) ─────────────────────────────

    #[test]
    fn pick_scratch_is_on_the_candidate_subnet() {
        let device = Ipv4Addr::new(192, 168, 5, 10);
        let candidates = pick_candidate_ip(device, &[]);
        let scratch = pick_scratch(device, &candidates);
        let o = scratch.octets();
        assert_eq!([o[0], o[1], o[2]], [192, 168, 5]);
    }

    #[test]
    fn pick_scratch_avoids_device_and_candidates() {
        let device = Ipv4Addr::new(10, 0, 0, 50);
        let candidates = pick_candidate_ip(device, &[]);
        let scratch = pick_scratch(device, &candidates);
        assert_ne!(scratch, device);
        assert!(!candidates.contains(&scratch));
    }

    // ── adopt_subnet cleanup / cancellation (via the AdoptOps seam) ──────
    //
    // A fake AdoptOps records the simulated adapter state (`bound`) and lets
    // tests script which candidates read as in-use and which add/remove
    // calls fail — so the pending-IP bookkeeping and rollback can be
    // exercised without binding real addresses or probing the wire.

    struct FakeOps {
        bound: std::sync::Mutex<Vec<Ipv4Addr>>,
        in_use: Vec<Ipv4Addr>,
        fail_add: Vec<Ipv4Addr>,
        fail_remove: Vec<Ipv4Addr>,
        ready_after: Duration,
        added_at: std::sync::Mutex<Option<tokio::time::Instant>>,
        probes: std::sync::Mutex<Vec<Ipv4Addr>>,
        never_ready: Vec<Ipv4Addr>,
        readiness_error: bool,
    }

    impl FakeOps {
        fn new() -> Self {
            Self {
                bound: std::sync::Mutex::new(Vec::new()),
                in_use: Vec::new(),
                fail_add: Vec::new(),
                fail_remove: Vec::new(),
                ready_after: Duration::ZERO,
                added_at: std::sync::Mutex::new(None),
                probes: std::sync::Mutex::new(Vec::new()),
                never_ready: Vec::new(),
                readiness_error: false,
            }
        }
        fn bound_ips(&self) -> Vec<Ipv4Addr> {
            self.bound.lock().unwrap().clone()
        }
    }

    impl AdoptOps for FakeOps {
        async fn add(&self, _iface: &str, ip: Ipv4Addr, _mask: &str) -> Result<(), AppError> {
            if self.fail_add.contains(&ip) {
                return Err(AppError::Network(format!("fake add fail {}", ip)));
            }
            self.bound.lock().unwrap().push(ip);
            *self.added_at.lock().unwrap() = Some(tokio::time::Instant::now());
            Ok(())
        }
        async fn remove(&self, _iface: &str, ip: Ipv4Addr) -> Result<(), AppError> {
            if self.fail_remove.contains(&ip) {
                return Err(AppError::Network(format!("fake remove fail {}", ip)));
            }
            self.bound.lock().unwrap().retain(|b| *b != ip);
            Ok(())
        }
        async fn probe_ready(
            &self,
            _: &str,
            source: Ipv4Addr,
            _: Ipv4Addr,
        ) -> Result<bool, AppError> {
            if self.readiness_error || !self.bound_ips().contains(&source) {
                return Err(AppError::Network("Probe source observation failed".into()));
            }
            Ok(!self.never_ready.contains(&source)
                && self.added_at.lock().unwrap().unwrap().elapsed() >= self.ready_after)
        }
        async fn probe(&self, target: Ipv4Addr, source: Option<Ipv4Addr>) -> bool {
            self.probes.lock().unwrap().push(target);
            // A tentative source cannot send: production conservatively
            // treats that probe error as occupied, which caused the loop.
            !self
                .probe_ready("eth", source.unwrap(), target)
                .await
                .unwrap_or(false)
                || self.in_use.contains(&target)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn verified_scratch_is_reused_without_a_second_bind_or_dad_wait() {
        let mut ops = FakeOps::new();
        ops.ready_after = Duration::from_secs(3);
        let pending = new_pending();
        let (_tx, rx) = watch::channel(false);
        bind_scratch(&ops, &pending, "eth", SCRATCH, 7)
            .await
            .unwrap();
        tokio::time::advance(ops.ready_after).await;
        ops.fail_add.push(SCRATCH); // any redundant bind would fail
        let start = tokio::time::Instant::now();
        let adopted = adopt_subnet_with_scratch(
            &ops,
            "eth",
            DEVICE,
            &[SCRATCH],
            &[SCRATCH],
            &pending,
            7,
            &rx,
            Some(PreparedScratch {
                address: SCRATCH,
                adoption_id: 7,
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            start.elapsed(),
            ops.ready_after,
            "only the final address needs DAD"
        );
        assert_eq!(ops.bound_ips(), [adopted]);
        assert_eq!(ops.probes.lock().unwrap().as_slice(), [adopted]);
        assert_eq!(
            pending.lock().await.as_slice(),
            [PendingIp {
                iface: "eth".into(),
                ip: adopted,
                adoption_id: 7
            }]
        );
    }

    #[tokio::test]
    async fn scratch_reuse_requires_exact_owner_and_does_not_hide_an_existing_host_address() {
        let ops = FakeOps::new();
        let pending = new_pending();
        let (_tx, rx) = watch::channel(false);
        bind_scratch(&ops, &pending, "eth", SCRATCH, 7)
            .await
            .unwrap();
        for (iface, id) in [("eth", 8), ("other", 7)] {
            assert!(adopt_subnet_with_scratch(
                &ops,
                iface,
                DEVICE,
                &[SCRATCH],
                &[SCRATCH],
                &pending,
                id,
                &rx,
                Some(PreparedScratch {
                    address: SCRATCH,
                    adoption_id: id
                })
            )
            .await
            .is_err());
        }
        assert_eq!(ops.bound_ips(), [SCRATCH]);
        let existing = Ipv4Addr::new(
            DEVICE.octets()[0],
            DEVICE.octets()[1],
            DEVICE.octets()[2],
            101,
        );
        assert_eq!(
            adopt_subnet_with_scratch(
                &ops,
                "eth",
                DEVICE,
                &[SCRATCH, existing],
                &[SCRATCH, existing],
                &pending,
                7,
                &rx,
                Some(PreparedScratch {
                    address: SCRATCH,
                    adoption_id: 7
                })
            )
            .await
            .unwrap(),
            None
        );
        reconcile_pending(&ops, &pending, Some(7)).await;
        assert!(ops.bound_ips().is_empty());
        assert!(ops.probes.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn reused_scratch_still_checks_readiness_and_cleans_up_on_failure() {
        let mut ops = FakeOps::new();
        ops.never_ready.push(SCRATCH);
        let pending = new_pending();
        let (_tx, rx) = watch::channel(false);
        bind_scratch(&ops, &pending, "eth", SCRATCH, 7)
            .await
            .unwrap();
        assert!(adopt_subnet_with_scratch(
            &ops,
            "eth",
            DEVICE,
            &[SCRATCH],
            &[SCRATCH],
            &pending,
            7,
            &rx,
            Some(PreparedScratch {
                address: SCRATCH,
                adoption_id: 7
            })
        )
        .await
        .is_err());
        assert!(ops.bound_ips().is_empty());
        assert!(pending.lock().await.is_empty());
        assert!(ops.probes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn bind_scratch_registers_breadcrumb_before_bind() {
        let ops = FakeOps::new();
        let pending = new_pending();
        bind_scratch(&ops, &pending, "eth0", SCRATCH, 7)
            .await
            .unwrap();
        assert_eq!(ops.bound_ips(), vec![SCRATCH]);
        // The breadcrumb survives until an explicit release/handover, so a
        // dropped future still leaves reconcile something to find.
        assert_eq!(pending.lock().await.len(), 1);
        assert_eq!(pending.lock().await[0].adoption_id, 7);
    }

    #[tokio::test]
    async fn bind_scratch_failure_drops_breadcrumb_and_errors() {
        let mut ops = FakeOps::new();
        ops.fail_add.push(SCRATCH);
        let pending = new_pending();
        assert!(bind_scratch(&ops, &pending, "eth0", SCRATCH, 7)
            .await
            .is_err());
        assert!(ops.bound_ips().is_empty());
        assert!(pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn release_scratch_success_clears_breadcrumb() {
        let ops = FakeOps::new();
        let pending = new_pending();
        bind_scratch(&ops, &pending, "eth0", SCRATCH, 7)
            .await
            .unwrap();
        release_scratch(&ops, &pending, "eth0", SCRATCH, 7).await;
        assert!(ops.bound_ips().is_empty());
        assert!(pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn release_scratch_failure_keeps_breadcrumb_for_reconcile() {
        let mut ops = FakeOps::new();
        ops.fail_remove.push(SCRATCH);
        let pending = new_pending();
        bind_scratch(&ops, &pending, "eth0", SCRATCH, 7)
            .await
            .unwrap();
        release_scratch(&ops, &pending, "eth0", SCRATCH, 7).await;
        // Remove failed: the address is still bound and the breadcrumb is
        // kept so reconcile_pending retries — never silently orphaned.
        assert_eq!(ops.bound_ips(), vec![SCRATCH]);
        assert_eq!(pending.lock().await.len(), 1);
    }

    fn new_pending() -> PendingIps {
        std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()))
    }

    const CANDIDATE: Ipv4Addr = Ipv4Addr::new(10, 99, 99, 100);
    const SCRATCH: Ipv4Addr = Ipv4Addr::new(10, 99, 99, 254);
    const DEVICE: Ipv4Addr = Ipv4Addr::new(10, 99, 99, 50);

    #[tokio::test(start_paused = true)]
    async fn performance_ready_sources_add_no_fixed_settle_delay() {
        let ops = FakeOps::new();
        let pending = new_pending();
        let (_tx, rx) = watch::channel(false);
        let started = tokio::time::Instant::now();
        assert_eq!(
            adopt_subnet(&ops, "eth", DEVICE, &[], &[], &pending, 1, &rx)
                .await
                .unwrap(),
            Some(CANDIDATE)
        );
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(ops.bound_ips(), [CANDIDATE]);
        assert_eq!(*ops.probes.lock().unwrap(), [CANDIDATE]);
    }

    #[tokio::test(start_paused = true)]
    async fn performance_ready_sources_are_not_delayed_by_more_than_one_poll() {
        let mut ops = FakeOps::new();
        // Neither source becomes ready exactly on a poll boundary.
        ops.ready_after = Duration::from_millis(3050);
        let pending = new_pending();
        let (_tx, rx) = watch::channel(false);
        let started = tokio::time::Instant::now();
        assert_eq!(
            adopt_subnet(&ops, "eth", DEVICE, &[], &[], &pending, 1, &rx)
                .await
                .unwrap(),
            Some(CANDIDATE)
        );
        assert!(started.elapsed() >= Duration::from_millis(6100));
        // Fixed budget, independent of the production polling constant: an
        // accidentally slower poll must fail instead of moving this goalpost.
        assert!(started.elapsed() <= Duration::from_millis(6300));
        assert_eq!(ops.bound_ips(), [CANDIDATE]);
    }

    #[tokio::test(start_paused = true)]
    async fn adoption_waits_for_tentative_sources_before_probing_and_publishing() {
        let mut ops = FakeOps::new();
        ops.ready_after = Duration::from_secs(3);
        let pending = new_pending();
        let (_tx, rx) = watch::channel(false);
        let started = tokio::time::Instant::now();
        let result = adopt_subnet(&ops, "eth", DEVICE, &[], &[], &pending, 1, &rx).await;
        assert_eq!(result.unwrap(), Some(CANDIDATE));
        assert!(started.elapsed() >= Duration::from_secs(6));
        assert!(ops.probe_ready("eth", CANDIDATE, DEVICE).await.unwrap());
        assert_eq!(*ops.probes.lock().unwrap(), vec![CANDIDATE]);
        assert_eq!(ops.bound_ips(), vec![CANDIDATE]);
    }

    #[tokio::test(start_paused = true)]
    async fn adoption_still_rejects_occupied_candidate_after_source_becomes_ready() {
        let mut ops = FakeOps::new();
        ops.ready_after = Duration::from_secs(3);
        ops.in_use.push(CANDIDATE);
        let pending = new_pending();
        let (_tx, rx) = watch::channel(false);
        let next = Ipv4Addr::new(10, 99, 99, 101);
        assert_eq!(
            adopt_subnet(&ops, "eth", DEVICE, &[], &[], &pending, 1, &rx)
                .await
                .unwrap(),
            Some(next)
        );
        assert_eq!(*ops.probes.lock().unwrap(), vec![CANDIDATE, next]);
        assert_eq!(ops.bound_ips(), vec![next]);
    }

    #[tokio::test(start_paused = true)]
    async fn adoption_waits_through_slow_windows_readiness_instead_of_abandoning_the_subnet() {
        let mut ops = FakeOps::new();
        ops.ready_after = Duration::from_secs(7);
        let pending = new_pending();
        let (_tx, rx) = watch::channel(false);
        let started = tokio::time::Instant::now();
        assert_eq!(
            adopt_subnet(&ops, "eth", DEVICE, &[], &[], &pending, 1, &rx)
                .await
                .unwrap(),
            Some(CANDIDATE)
        );
        assert_eq!(
            started.elapsed(),
            Duration::from_secs(14),
            "both scratch and final readiness must pass"
        );
        assert_eq!(ops.probes.lock().unwrap().as_slice(), [CANDIDATE]);
        assert_eq!(ops.bound_ips(), [CANDIDATE]);
        assert_eq!(
            pending.lock().await.len(),
            1,
            "final remains owned until durable handover"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn adoption_unusable_source_times_out_without_probing_and_cleans_scratch() {
        let mut ops = FakeOps::new();
        ops.never_ready.push(SCRATCH);
        let pending = new_pending();
        let (_tx, rx) = watch::channel(false);
        let started = tokio::time::Instant::now();
        let error = adopt_subnet(&ops, "eth", DEVICE, &[], &[], &pending, 1, &rx)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("usable"), "{error}");
        assert!(matches!(error, AppError::AddressNotReady(_)));
        assert_eq!(started.elapsed(), PROBE_SOURCE_READY_TIMEOUT);
        assert!(ops.probes.lock().unwrap().is_empty());
        assert!(ops.bound_ips().is_empty());
        assert!(pending.lock().await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn adoption_source_observation_error_is_not_reported_as_ip_conflict() {
        let mut ops = FakeOps::new();
        ops.readiness_error = true;
        let pending = new_pending();
        let (_tx, rx) = watch::channel(false);
        let error = adopt_subnet(&ops, "eth", DEVICE, &[], &[], &pending, 1, &rx)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("observation failed"), "{error}");
        assert!(
            matches!(error, AppError::Network(_)),
            "unknown ownership is not a transient settling timeout"
        );
        assert!(ops.probes.lock().unwrap().is_empty());
        assert!(ops.bound_ips().is_empty());
        assert!(pending.lock().await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn adoption_shutdown_during_source_wait_releases_scratch() {
        let mut ops = FakeOps::new();
        ops.ready_after = Duration::from_secs(3);
        let pending = new_pending();
        let (tx, rx) = watch::channel(false);
        let stop = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            tx.send(true).unwrap();
        };
        let (result, ()) = tokio::join!(
            adopt_subnet(&ops, "eth", DEVICE, &[], &[], &pending, 1, &rx),
            stop
        );
        assert_eq!(result.unwrap(), None);
        assert!(ops.probes.lock().unwrap().is_empty());
        assert!(ops.bound_ips().is_empty());
        assert!(pending.lock().await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn adoption_unusable_final_address_is_released_without_publishing() {
        let mut ops = FakeOps::new();
        ops.never_ready.push(CANDIDATE);
        let pending = new_pending();
        let (_tx, rx) = watch::channel(false);
        let error = adopt_subnet(&ops, "eth", DEVICE, &[], &[], &pending, 1, &rx)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains(&CANDIDATE.to_string()),
            "{error}"
        );
        assert!(error.to_string().contains("usable"), "{error}");
        assert_eq!(*ops.probes.lock().unwrap(), vec![CANDIDATE]);
        assert!(ops.bound_ips().is_empty());
        assert!(pending.lock().await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn adoption_shutdown_during_final_source_wait_releases_both_addresses() {
        let mut ops = FakeOps::new();
        ops.ready_after = Duration::from_secs(3);
        let pending = new_pending();
        let (tx, rx) = watch::channel(false);
        let stop = async {
            tokio::time::sleep(Duration::from_secs(4)).await;
            tx.send(true).unwrap();
        };
        let (result, ()) = tokio::join!(
            adopt_subnet(&ops, "eth", DEVICE, &[], &[], &pending, 1, &rx),
            stop
        );
        assert_eq!(result.unwrap(), None);
        assert_eq!(*ops.probes.lock().unwrap(), vec![CANDIDATE]);
        assert!(ops.bound_ips().is_empty());
        assert!(pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn adopt_binds_deterministic_candidate_and_registers_pending() {
        let ops = FakeOps::new();
        let pending = new_pending();
        let (_tx, rx) = tokio::sync::watch::channel(false);

        let got = adopt_subnet(&ops, "eth", DEVICE, &[], &[], &pending, 1, &rx)
            .await
            .unwrap();
        assert_eq!(got, Some(CANDIDATE));
        // Scratch was bound then released; only the final candidate remains.
        assert_eq!(ops.bound_ips(), vec![CANDIDATE]);
        // The final IP is registered as pending until the caller hands over.
        {
            let p = pending.lock().await;
            assert_eq!(p.len(), 1);
            assert_eq!(p[0].ip, CANDIDATE);
            assert_eq!(p[0].adoption_id, 1);
        }
        // Handover clears the bookkeeping without touching the adapter.
        pending_handover(&pending, "eth", CANDIDATE, 1).await;
        assert!(pending.lock().await.is_empty());
        assert_eq!(ops.bound_ips(), vec![CANDIDATE]);
    }

    #[tokio::test]
    async fn reconcile_removes_unrecorded_final_after_drop() {
        // A cancellation landing after the final add registered in pending
        // but before the caller recorded it: reconcile must remove the bound
        // IP and empty the registry.
        let ops = FakeOps::new();
        let pending = new_pending();
        let (_tx, rx) = tokio::sync::watch::channel(false);

        let got = adopt_subnet(&ops, "eth", DEVICE, &[], &[], &pending, 7, &rx)
            .await
            .unwrap();
        assert_eq!(got, Some(CANDIDATE));
        // Caller never hands over (task dropped). Reconcile by id cleans it.
        reconcile_pending(&ops, &pending, Some(7)).await;
        assert!(ops.bound_ips().is_empty());
        assert!(pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn shutdown_before_final_binds_nothing() {
        let ops = FakeOps::new();
        let pending = new_pending();
        let (_tx, rx) = tokio::sync::watch::channel(true); // already shutting down

        let got = adopt_subnet(&ops, "eth", DEVICE, &[], &[], &pending, 3, &rx)
            .await
            .unwrap();
        assert_eq!(got, None);
        // Scratch was bound + released; no final bind happened.
        assert!(ops.bound_ips().is_empty());
        assert!(pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn reconcile_by_id_ignores_other_adoptions_ip() {
        // A leftover from adoption 1 must not be removed by a reconcile
        // scoped to adoption 2, even though the IP is identical (the
        // candidate is deterministic). This is the abort-then-reuse guard:
        // a stale rollback never removes a newer adoption's IP.
        let ops = FakeOps::new();
        ops.bound.lock().unwrap().push(CANDIDATE);
        let pending = new_pending();
        pending.lock().await.push(PendingIp {
            iface: "eth".into(),
            ip: CANDIDATE,
            adoption_id: 1,
        });

        reconcile_pending(&ops, &pending, Some(2)).await; // wrong id
        assert_eq!(
            ops.bound_ips(),
            vec![CANDIDATE],
            "an id-2 reconcile must not touch id-1's IP"
        );
        assert_eq!(pending.lock().await.len(), 1);

        reconcile_pending(&ops, &pending, Some(1)).await; // owning id
        assert!(ops.bound_ips().is_empty());
        assert!(pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn scratch_release_failure_keeps_breadcrumb() {
        // If releasing the scratch fails, its pending entry is kept so a
        // later reconcile retries it; the final IP is still adopted.
        let mut ops = FakeOps::new();
        ops.fail_remove = vec![SCRATCH];
        let pending = new_pending();
        let (_tx, rx) = tokio::sync::watch::channel(false);

        let got = adopt_subnet(&ops, "eth", DEVICE, &[], &[], &pending, 9, &rx)
            .await
            .unwrap();
        assert_eq!(got, Some(CANDIDATE));
        // Both the un-released scratch and the final are still bound...
        let bound = ops.bound_ips();
        assert!(
            bound.contains(&SCRATCH),
            "scratch left bound after failed release"
        );
        assert!(bound.contains(&CANDIDATE));
        // ...and both carry pending breadcrumbs under id 9.
        let ips: Vec<Ipv4Addr> = pending.lock().await.iter().map(|e| e.ip).collect();
        assert!(ips.contains(&SCRATCH));
        assert!(ips.contains(&CANDIDATE));
    }
}
