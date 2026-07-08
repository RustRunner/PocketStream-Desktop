use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::{watch, Mutex};

use crate::error::AppError;
use crate::network::ip_config;

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
/// so conflict probes route on-link (see `adopt_subnet`).
fn pick_scratch(device_ip: Ipv4Addr, candidates: &[Ipv4Addr]) -> Ipv4Addr {
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

/// Injectable seam for the OS-touching work `adopt_subnet` performs, so its
/// scratch/final bookkeeping and rollback can be unit-tested without binding
/// real addresses or probing the wire.
#[allow(async_fn_in_trait)]
pub trait AdoptOps {
    /// Bind a secondary IP (production: `New-NetIPAddress`).
    async fn add(&self, iface: &str, ip: Ipv4Addr, mask: &str) -> Result<(), AppError>;
    /// Remove a secondary IP (production: `netsh delete address`).
    async fn remove(&self, iface: &str, ip: Ipv4Addr) -> Result<(), AppError>;
    /// Probe whether `target` is already in use on-link. Returns `true` for
    /// in-use OR indeterminate — the caller must not claim a maybe-used IP.
    async fn probe(&self, target: Ipv4Addr, source: Option<Ipv4Addr>) -> bool;
}

/// Production `AdoptOps`: the real ip_config / ARP-probe calls. Both `add`
/// and `remove` are kill-on-drop (via ip_config), so dropping an in-flight
/// adoption future takes its child process with it.
pub struct RealAdoptOps;

impl AdoptOps for RealAdoptOps {
    async fn add(&self, iface: &str, ip: Ipv4Addr, mask: &str) -> Result<(), AppError> {
        ip_config::add_secondary_ip(iface, &ip.to_string(), mask).await
    }
    async fn remove(&self, iface: &str, ip: Ipv4Addr) -> Result<(), AppError> {
        ip_config::remove_secondary_ip(iface, &ip.to_string()).await
    }
    async fn probe(&self, target: Ipv4Addr, source: Option<Ipv4Addr>) -> bool {
        // A probe error (couldn't determine conflict) is treated as in-use.
        super::arp::send_arp_probe(target, source, std::time::Duration::from_secs(1))
            .await
            .unwrap_or(true)
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
pub async fn pending_handover(pending: &PendingIps, iface: &str, ip: Ipv4Addr, adoption_id: u64) {
    pending_remove(pending, iface, ip, adoption_id).await;
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
            .filter(|e| filter.map_or(true, |id| e.adoption_id == id))
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
    if already_on_subnet(device_ip, current_ips) {
        log::info!("Already on subnet for {} — skipping auto-adopt", device_ip);
        return Ok(None);
    }

    // Exclude every IP held by ANY local interface, not just the target —
    // the ARP probe below can't detect the host's own addresses, so a
    // candidate already on e.g. WiFi would look "free" and collide. Union
    // with the passed-in target IPs in case enumeration hasn't yet reflected
    // a freshly-added one.
    let mut used_ips = local_ips.to_vec();
    used_ips.extend_from_slice(current_ips);
    let candidates = pick_candidate_ip(device_ip, &used_ips);
    if candidates.is_empty() {
        return Err(AppError::Network(format!(
            "No candidate IPs available on subnet for {}",
            device_ip
        )));
    }

    // Temporarily bind a scratch address on the candidate /24 so the
    // conflict probes below route on-link. Without an address on this
    // subnet the probe is structurally blind and reports every candidate
    // free, risking a duplicate-IP assignment against a real camera-side
    // device. If the scratch can't be bound, fall back to the (blind)
    // gateway-routed probe rather than aborting.
    let scratch = pick_scratch(device_ip, &candidates);
    log::info!(
        "Auto-adopt {}: binding scratch {} on {} for on-link probe",
        adoption_id,
        scratch,
        interface_name
    );
    // Register BEFORE binding: a drop between the bind and the release below
    // must leave a breadcrumb for reconciliation.
    pending_insert(pending, interface_name, scratch, adoption_id).await;
    let scratch_bound = ops
        .add(interface_name, scratch, "255.255.255.0")
        .await
        .is_ok();
    if !scratch_bound {
        log::warn!(
            "Could not bind scratch {} for on-link conflict probe; probes may be blind",
            scratch
        );
        // Nothing bound — drop the breadcrumb.
        pending_remove(pending, interface_name, scratch, adoption_id).await;
    }
    let source = scratch_bound.then_some(scratch);

    // Probe candidates on-link, then always release the scratch.
    let mut chosen = None;
    for candidate in &candidates {
        if !ops.probe(*candidate, source).await {
            chosen = Some(*candidate);
            break;
        }
        log::info!("Candidate {} is in use, trying next", candidate);
    }

    if scratch_bound {
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
    match ops.add(interface_name, candidate, "255.255.255.0").await {
        Ok(()) => Ok(Some(candidate)),
        Err(e) => {
            // Add failed — nothing bound, drop the breadcrumb.
            pending_remove(pending, interface_name, candidate, adoption_id).await;
            Err(e)
        }
    }
}

/// Remove a previously adopted secondary IP from the interface.
pub async fn remove_adopted_ip(interface_name: &str, ip: &str) -> Result<(), AppError> {
    log::info!("Removing adopted IP {} from {}", ip, interface_name);
    ip_config::remove_secondary_ip(interface_name, ip).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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
    }

    impl FakeOps {
        fn new() -> Self {
            Self {
                bound: std::sync::Mutex::new(Vec::new()),
                in_use: Vec::new(),
                fail_add: Vec::new(),
                fail_remove: Vec::new(),
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
            Ok(())
        }
        async fn remove(&self, _iface: &str, ip: Ipv4Addr) -> Result<(), AppError> {
            if self.fail_remove.contains(&ip) {
                return Err(AppError::Network(format!("fake remove fail {}", ip)));
            }
            self.bound.lock().unwrap().retain(|b| *b != ip);
            Ok(())
        }
        async fn probe(&self, target: Ipv4Addr, _source: Option<Ipv4Addr>) -> bool {
            self.in_use.contains(&target)
        }
    }

    fn new_pending() -> PendingIps {
        std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()))
    }

    const CANDIDATE: Ipv4Addr = Ipv4Addr::new(10, 99, 99, 100);
    const SCRATCH: Ipv4Addr = Ipv4Addr::new(10, 99, 99, 254);
    const DEVICE: Ipv4Addr = Ipv4Addr::new(10, 99, 99, 50);

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
        assert!(bound.contains(&SCRATCH), "scratch left bound after failed release");
        assert!(bound.contains(&CANDIDATE));
        // ...and both carry pending breadcrumbs under id 9.
        let ips: Vec<Ipv4Addr> = pending.lock().await.iter().map(|e| e.ip).collect();
        assert!(ips.contains(&SCRATCH));
        assert!(ips.contains(&CANDIDATE));
    }
}
