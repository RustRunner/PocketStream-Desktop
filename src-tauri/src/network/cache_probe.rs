//! Cached-device on-link probe.
//!
//! Rediscovery of known devices must not depend on catching their
//! spontaneous broadcast ARP (minutes apart on a quiet camera). Early in
//! a discovery session, for every cached device whose subnet is foreign
//! and unadopted, the pass scratch-binds the subnet, forces a fresh
//! on-wire ARP resolution of each cached IP, verifies the responder's
//! MAC against the cache, and hands the first match to the shared
//! adoption tail — a solicited, freshly MAC-verified reply from a device
//! we have history with is stronger evidence than two broadcast frames,
//! which is what justifies bypassing the dwell gate.
//!
//! The pass runs inside the sequential auto-adopt task (single-flight
//! serialization, shutdown, and the DHCP policy come from the task), so
//! it is budgeted: a large cache must not stall the reaper and broadcast
//! adoption for many command timeouts.

use std::collections::{BTreeMap, HashSet};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::config::CachedDevice;

use super::{arp, auto_adopt, ghost};

/// One probe-eligible subnet with its cached (ip, mac) pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProbeCandidate {
    /// Canonical `a.b.c.0/24`, derived from the cached IP's octets —
    /// never from the stored record subnet, which can be stale.
    pub subnet: String,
    /// Cached (ip, colon-lowercase mac) pairs, IP-ordered.
    pub pairs: Vec<(Ipv4Addr, String)>,
}

/// Derive the probe candidate set from the device cache. Excluded rows
/// keep their existing discovery paths:
/// - rows without a usable stored MAC (the MAC match is the identity
///   evidence that justifies the dwell bypass);
/// - subnets native to the adapter, currently adopted, held for restore,
///   or already probed this session;
/// - subnets owned by a non-wired local interface (same structural
///   screens the broadcast path applies). APIPA subnets pass — a camera
///   in APIPA fallback is a primary use case.
///
/// Candidates sharing a /24 are grouped so the pass binds one scratch
/// per subnet.
pub(crate) fn derive_candidates(
    cached: &[CachedDevice],
    native_subnets: &HashSet<String>,
    adopted: &HashSet<String>,
    pending_restore: &HashSet<String>,
    ghost_nets: &[ipnetwork::Ipv4Network],
    attempted: &HashSet<String>,
) -> Vec<ProbeCandidate> {
    let mut by_subnet: BTreeMap<String, Vec<(Ipv4Addr, String)>> = BTreeMap::new();
    for record in cached {
        let Some(mac) = arp::normalize_mac(&record.mac) else {
            continue;
        };
        let Ok(ip) = record.ip.parse::<Ipv4Addr>() else {
            continue;
        };
        let o = ip.octets();
        let subnet = format!("{}.{}.{}.0/24", o[0], o[1], o[2]);
        if native_subnets.contains(&subnet)
            || adopted.contains(&subnet)
            || pending_restore.contains(&subnet)
            || attempted.contains(&subnet)
        {
            continue;
        }
        if ghost::is_structural_ghost_ip(ip, ghost_nets)
            || ghost::is_structural_ghost_adoption(&subnet, ghost_nets)
        {
            continue;
        }
        by_subnet.entry(subnet).or_default().push((ip, mac));
    }
    by_subnet
        .into_iter()
        .map(|(subnet, mut pairs)| {
            pairs.sort();
            pairs.dedup();
            ProbeCandidate { subnet, pairs }
        })
        .collect()
}

/// The OS-touching seam of a probe pass, injectable so budgeting,
/// cleanup ordering, and cancellation are unit-testable without binding
/// real addresses.
#[allow(async_fn_in_trait)]
pub(crate) trait ProbeIo {
    /// Bind the subnet's scratch address. `false` = bind failed; the
    /// pass moves to the next subnet.
    async fn bind_scratch(&mut self, subnet: &str, scratch: Ipv4Addr) -> bool;
    /// Release a scratch bound by `bind_scratch`.
    async fn release_scratch(&mut self, subnet: &str, scratch: Ipv4Addr);
    /// Fresh on-wire MAC resolution of `target`, sourced from `scratch`.
    /// `Ok(None)` = no response; `Err(())` = could not attempt (flush
    /// failed) — the pair fails closed.
    async fn resolve(&mut self, target: Ipv4Addr, scratch: Ipv4Addr) -> Result<Option<String>, ()>;
    /// Hand a freshly verified (ip, mac) match to the adoption tail. The
    /// scratch is already released when this is called. `false` = stop
    /// the whole pass (a shutdown raced the adoption).
    async fn adopt(&mut self, subnet: &str, ip: Ipv4Addr, mac: &str) -> bool;
    /// Whether a discovery stop has been signalled.
    fn shutdown(&self) -> bool;
}

/// What one probe pass did, for logging and the per-session attempted
/// set. `skipped_at_budget` is reported loudly — silent truncation would
/// read as "covered everything"; skipped subnets keep their normal
/// broadcast path.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PassReport {
    pub attempted: Vec<String>,
    pub handed_off: Vec<String>,
    pub skipped_at_budget: Vec<String>,
}

/// Whole-pass wall-clock budget. The pass shares the sequential
/// auto-adopt task with the reaper and broadcast adoption, so a large
/// cache must not stall them for long: sized as a small multiple of the
/// worst per-command bound in the chain (the 30 s scratch bind/release;
/// flush and `SendARP` are 10 s and ~3 s).
pub(crate) const CACHE_PROBE_PASS_BUDGET: Duration = Duration::from_secs(90);

/// Run one probe pass over the candidate set. Per subnet: one scratch
/// bind, each cached pair resolved in order, first fresh MAC match wins
/// (remaining pairs skipped), and the scratch is always released before
/// the adoption hand-off — the adoption's own scratch/conflict cycle
/// must never see the identity scratch as a native address.
///
/// The budget and the shutdown signal are checked before every subnet
/// and between every pair; expiry releases any bound scratch and records
/// the remaining subnets as skipped. Identity misses (no answer, MAC
/// mismatch, failed flush) probe the next pair — no cache mutation, and
/// no cooldown: this pass has no access to the shared cooldown map by
/// construction, so a stale cache row can never suppress a legitimate
/// broadcast adoption.
pub(crate) async fn run_pass<I: ProbeIo>(
    io: &mut I,
    candidates: Vec<ProbeCandidate>,
    budget: Duration,
) -> PassReport {
    let deadline = tokio::time::Instant::now() + budget;
    let mut report = PassReport::default();
    let mut remaining = candidates.into_iter();
    while let Some(candidate) = remaining.next() {
        if io.shutdown() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            report.skipped_at_budget.push(candidate.subnet);
            report.skipped_at_budget.extend(remaining.map(|c| c.subnet));
            break;
        }
        // One probe attempt per subnet per session, whatever the result.
        report.attempted.push(candidate.subnet.clone());
        let pair_ips: Vec<Ipv4Addr> = candidate.pairs.iter().map(|(ip, _)| *ip).collect();
        let scratch = auto_adopt::pick_scratch(pair_ips[0], &pair_ips);
        if !io.bind_scratch(&candidate.subnet, scratch).await {
            continue;
        }
        let mut matched: Option<(Ipv4Addr, String)> = None;
        for (ip, cached_mac) in &candidate.pairs {
            if io.shutdown() || tokio::time::Instant::now() >= deadline {
                break;
            }
            match io.resolve(*ip, scratch).await {
                Ok(Some(fresh_mac)) if fresh_mac == *cached_mac => {
                    matched = Some((*ip, fresh_mac));
                    break;
                }
                // Squatter or readdressed device: no adoption, and no
                // cache eviction — eviction stays the province of the
                // verify path. A no-answer or failed flush likewise just
                // tries the next pair.
                Ok(Some(_)) | Ok(None) | Err(()) => {}
            }
        }
        io.release_scratch(&candidate.subnet, scratch).await;
        if let Some((ip, mac)) = matched {
            report.handed_off.push(candidate.subnet.clone());
            if !io.adopt(&candidate.subnet, ip, &mac).await {
                break;
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(mac: &str, ip: &str, stored_subnet: &str) -> CachedDevice {
        CachedDevice {
            mac: mac.into(),
            ip: ip.into(),
            subnet: stored_subnet.into(),
            open_ports: vec![80],
            alias: String::new(),
            last_seen: "2026-07-17T01:10:18Z".into(),
        }
    }

    fn sets(entries: &[&str]) -> HashSet<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    // ── candidate derivation ─────────────────────────────────────────

    #[test]
    fn candidates_require_stored_mac_and_derive_subnet_from_ip() {
        let cached = vec![
            // Stored subnet lies — the canonical subnet must come from
            // the IP's octets.
            record("40-CD-3A-03-28-E2", "172.31.169.64", "10.0.0.0/24"),
            // MAC-less rows (manual nodes never observed) are excluded.
            record("", "172.31.170.5", "172.31.170.0/24"),
            // Broadcast/zero placeholders don't count as identity.
            record("ff:ff:ff:ff:ff:ff", "172.31.171.5", "172.31.171.0/24"),
            // Unparseable IP rows are skipped.
            record("aa:bb:cc:dd:ee:01", "not-an-ip", "172.31.172.0/24"),
        ];
        let none = HashSet::new();
        let out = derive_candidates(&cached, &none, &none, &none, &[], &none);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].subnet, "172.31.169.0/24");
        // Dash-uppercase cached MAC arrives normalized colon-lowercase.
        assert_eq!(
            out[0].pairs,
            vec![("172.31.169.64".parse().unwrap(), "40:cd:3a:03:28:e2".into())]
        );
    }

    #[test]
    fn candidates_exclude_native_adopted_pending_and_attempted() {
        let cached = vec![
            record("aa:bb:cc:dd:ee:01", "192.168.1.20", "192.168.1.0/24"),
            record("aa:bb:cc:dd:ee:02", "172.31.169.64", "172.31.169.0/24"),
            record("aa:bb:cc:dd:ee:03", "172.31.170.64", "172.31.170.0/24"),
            record("aa:bb:cc:dd:ee:04", "172.31.171.64", "172.31.171.0/24"),
            record("aa:bb:cc:dd:ee:05", "172.31.172.64", "172.31.172.0/24"),
        ];
        let out = derive_candidates(
            &cached,
            &sets(&["192.168.1.0/24"]),
            &sets(&["172.31.169.0/24"]),
            &sets(&["172.31.170.0/24"]),
            &[],
            &sets(&["172.31.171.0/24"]),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].subnet, "172.31.172.0/24");
    }

    #[test]
    fn candidates_apply_ghost_screen_but_admit_apipa() {
        let cached = vec![
            // Owned by a non-wired local interface — structurally ghost.
            record("aa:bb:cc:dd:ee:01", "10.5.0.9", "10.5.0.0/24"),
            // APIPA is a primary use case (camera DHCP fallback) — in.
            record("2c:a5:9c:2b:a9:fc", "169.254.73.42", "169.254.73.0/24"),
        ];
        let ghost_nets = vec!["10.5.0.0/16".parse::<ipnetwork::Ipv4Network>().unwrap()];
        let none = HashSet::new();
        let out = derive_candidates(&cached, &none, &none, &none, &ghost_nets, &none);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].subnet, "169.254.73.0/24");
    }

    #[test]
    fn candidates_group_same_subnet_under_one_entry() {
        let cached = vec![
            record("aa:bb:cc:dd:ee:02", "172.31.169.65", "172.31.169.0/24"),
            record("aa:bb:cc:dd:ee:01", "172.31.169.64", "172.31.169.0/24"),
        ];
        let none = HashSet::new();
        let out = derive_candidates(&cached, &none, &none, &none, &[], &none);
        assert_eq!(out.len(), 1);
        // IP-ordered, so the pass probes deterministically.
        assert_eq!(out[0].pairs.len(), 2);
        assert!(out[0].pairs[0].0 < out[0].pairs[1].0);
    }

    // ── pass engine (mock ProbeIo) ───────────────────────────────────

    #[derive(Default)]
    struct MockProbeIo {
        /// (target, result-mac). Missing target ⇒ no answer; the literal
        /// mac "FLUSH-FAIL" scripts an `Err(())`.
        answers: std::collections::HashMap<Ipv4Addr, String>,
        resolve_delay: Duration,
        fail_bind: bool,
        /// `shutdown()` reports true once `events.len() >= n`.
        shutdown_at_event: Option<usize>,
        adopt_returns: bool,
        events: Vec<String>,
        bound: Vec<Ipv4Addr>,
    }

    impl MockProbeIo {
        fn new() -> Self {
            Self {
                adopt_returns: true,
                ..Self::default()
            }
        }
    }

    impl ProbeIo for MockProbeIo {
        async fn bind_scratch(&mut self, subnet: &str, scratch: Ipv4Addr) -> bool {
            self.events.push(format!("bind {} {}", subnet, scratch));
            if self.fail_bind {
                return false;
            }
            self.bound.push(scratch);
            true
        }
        async fn release_scratch(&mut self, subnet: &str, scratch: Ipv4Addr) {
            self.events.push(format!("release {} {}", subnet, scratch));
            self.bound.retain(|s| *s != scratch);
        }
        async fn resolve(
            &mut self,
            target: Ipv4Addr,
            _scratch: Ipv4Addr,
        ) -> Result<Option<String>, ()> {
            self.events.push(format!("resolve {}", target));
            tokio::time::sleep(self.resolve_delay).await;
            match self.answers.get(&target) {
                Some(mac) if mac == "FLUSH-FAIL" => Err(()),
                Some(mac) => Ok(Some(mac.clone())),
                None => Ok(None),
            }
        }
        async fn adopt(&mut self, subnet: &str, ip: Ipv4Addr, mac: &str) -> bool {
            assert!(
                self.bound.is_empty(),
                "adopt called while a probe scratch is still bound"
            );
            self.events.push(format!("adopt {} {} {}", subnet, ip, mac));
            self.adopt_returns
        }
        fn shutdown(&self) -> bool {
            self.shutdown_at_event
                .is_some_and(|n| self.events.len() >= n)
        }
    }

    fn candidate(subnet: &str, pairs: &[(&str, &str)]) -> ProbeCandidate {
        ProbeCandidate {
            subnet: subnet.into(),
            pairs: pairs
                .iter()
                .map(|(ip, mac)| (ip.parse().unwrap(), (*mac).to_string()))
                .collect(),
        }
    }

    #[tokio::test]
    async fn match_releases_scratch_before_adopt_and_skips_remaining_pairs() {
        let mut io = MockProbeIo::new();
        io.answers
            .insert("172.31.169.64".parse().unwrap(), "40:cd:3a:03:28:e2".into());
        let c = candidate(
            "172.31.169.0/24",
            &[
                ("172.31.169.64", "40:cd:3a:03:28:e2"),
                ("172.31.169.65", "aa:bb:cc:dd:ee:02"),
            ],
        );
        let report = run_pass(&mut io, vec![c], CACHE_PROBE_PASS_BUDGET).await;
        assert_eq!(report.handed_off, vec!["172.31.169.0/24"]);
        // First match wins: the second pair is never resolved, the
        // scratch is released before the hand-off (asserted in adopt).
        let kinds: Vec<&str> = io
            .events
            .iter()
            .map(|e| e.split(' ').next().unwrap())
            .collect();
        assert_eq!(kinds, vec!["bind", "resolve", "release", "adopt"]);
        assert!(io.bound.is_empty());
    }

    #[tokio::test]
    async fn misses_mismatches_and_failed_flushes_leave_no_adoption() {
        let mut io = MockProbeIo::new();
        // .64 answers with a different MAC (squatter), .65 not at all,
        // .66 can't even be flushed.
        io.answers
            .insert("172.31.169.64".parse().unwrap(), "de:ad:be:ef:00:01".into());
        io.answers
            .insert("172.31.169.66".parse().unwrap(), "FLUSH-FAIL".into());
        let c = candidate(
            "172.31.169.0/24",
            &[
                ("172.31.169.64", "40:cd:3a:03:28:e2"),
                ("172.31.169.65", "aa:bb:cc:dd:ee:02"),
                ("172.31.169.66", "aa:bb:cc:dd:ee:03"),
            ],
        );
        let report = run_pass(&mut io, vec![c], CACHE_PROBE_PASS_BUDGET).await;
        assert!(report.handed_off.is_empty());
        assert_eq!(report.attempted, vec!["172.31.169.0/24"]);
        // Every pair was tried, nothing adopted, scratch released.
        assert!(io.events.iter().any(|e| e == "resolve 172.31.169.66"));
        assert!(!io.events.iter().any(|e| e.starts_with("adopt")));
        assert!(io.bound.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn budget_expiry_releases_scratch_and_records_skips() {
        let mut io = MockProbeIo::new();
        io.resolve_delay = Duration::from_secs(60);
        let c1 = candidate(
            "172.31.169.0/24",
            &[
                ("172.31.169.64", "aa:bb:cc:dd:ee:01"),
                ("172.31.169.65", "aa:bb:cc:dd:ee:02"),
            ],
        );
        let c2 = candidate("172.31.170.0/24", &[("172.31.170.64", "aa:bb:cc:dd:ee:03")]);
        let report = run_pass(&mut io, vec![c1, c2], Duration::from_secs(90)).await;
        // Pair 1 resolves at t=60 (< 90), pair 2 starts before a check…
        // actually the between-pair check at t=60 admits it; its resolve
        // ends at t=120, past the deadline, so the subnet-level check
        // skips candidate 2 loudly. No silent truncation.
        assert_eq!(report.attempted, vec!["172.31.169.0/24"]);
        assert_eq!(report.skipped_at_budget, vec!["172.31.170.0/24"]);
        assert!(
            io.bound.is_empty(),
            "budget expiry must release the scratch"
        );
        assert!(!io.events.iter().any(|e| e.starts_with("bind 172.31.170")));
    }

    #[tokio::test]
    async fn shutdown_mid_pass_stops_promptly_without_orphans() {
        let mut io = MockProbeIo::new();
        // Events: bind(1) resolve(2) → shutdown reads true from then on:
        // the pair loop breaks, the scratch is still released, and the
        // next subnet is never attempted.
        io.shutdown_at_event = Some(2);
        let c1 = candidate(
            "172.31.169.0/24",
            &[
                ("172.31.169.64", "aa:bb:cc:dd:ee:01"),
                ("172.31.169.65", "aa:bb:cc:dd:ee:02"),
            ],
        );
        let c2 = candidate("172.31.170.0/24", &[("172.31.170.64", "aa:bb:cc:dd:ee:03")]);
        let report = run_pass(&mut io, vec![c1, c2], CACHE_PROBE_PASS_BUDGET).await;
        assert_eq!(report.attempted, vec!["172.31.169.0/24"]);
        assert!(report.skipped_at_budget.is_empty());
        assert!(io.bound.is_empty(), "shutdown must not orphan the scratch");
        assert!(!io.events.iter().any(|e| e.starts_with("bind 172.31.170")));
    }

    #[tokio::test]
    async fn bind_failure_moves_to_next_subnet() {
        let mut io = MockProbeIo::new();
        io.fail_bind = true;
        let c1 = candidate("172.31.169.0/24", &[("172.31.169.64", "aa:bb:cc:dd:ee:01")]);
        let c2 = candidate("172.31.170.0/24", &[("172.31.170.64", "aa:bb:cc:dd:ee:02")]);
        let report = run_pass(&mut io, vec![c1, c2], CACHE_PROBE_PASS_BUDGET).await;
        // Both marked attempted (one probe attempt per subnet per
        // session), neither resolved, nothing released or adopted.
        assert_eq!(report.attempted, vec!["172.31.169.0/24", "172.31.170.0/24"]);
        assert!(!io.events.iter().any(|e| e.starts_with("resolve")));
        assert!(!io.events.iter().any(|e| e.starts_with("release")));
        assert!(io.bound.is_empty());
    }

    #[tokio::test]
    async fn adopt_stop_signal_ends_the_pass() {
        let mut io = MockProbeIo::new();
        io.adopt_returns = false; // shutdown raced the adoption hand-off
        io.answers
            .insert("172.31.169.64".parse().unwrap(), "aa:bb:cc:dd:ee:01".into());
        let c1 = candidate("172.31.169.0/24", &[("172.31.169.64", "aa:bb:cc:dd:ee:01")]);
        let c2 = candidate("172.31.170.0/24", &[("172.31.170.64", "aa:bb:cc:dd:ee:02")]);
        let report = run_pass(&mut io, vec![c1, c2], CACHE_PROBE_PASS_BUDGET).await;
        assert_eq!(report.handed_off, vec!["172.31.169.0/24"]);
        assert!(!io.events.iter().any(|e| e.starts_with("bind 172.31.170")));
    }
}
