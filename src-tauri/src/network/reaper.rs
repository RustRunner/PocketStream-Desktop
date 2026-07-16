//! Pure lifecycle decisions for adopted subnets.
//!
//! Decides what should happen to one adoption given the evidence:
//! `Keep` it, badge it as `StaleOnly` (informational, UI-only), or
//! `Reap` it (unbind and forget). The decision is deliberately a pure
//! function over pre-gathered inputs so the whole policy matrix is
//! unit-testable — `NetworkManager` cannot be constructed in lib
//! tests, so nothing here may touch it.
//!
//! Policy boundaries encoded structurally rather than as stored state:
//!
//! - Only a subnet parsed inside 169.254.0.0/16 (APIPA) at decision
//!   time can ever be reaped. Nothing trusts a persisted flag — the
//!   boundary is re-derived from the key on every call, and the
//!   non-APIPA branch cannot return `Reap`.
//! - Removal timing uses the session's monotonic clocks only. Wall
//!   time feeds the informational badge and nothing else, so clock
//!   skew or suspend can mislabel a row but never unbind one.
//! - User pins and host APIPA-rescue state are vetoes that downgrade a
//!   reap to a badge; they never silently reset the evidence clocks.

use std::net::Ipv4Addr;
use std::time::Duration;

/// How long after the last positive sighting this session (accepted
/// ARP, successful scan or ping) an unprotected APIPA adoption
/// survives before reaping. Generous on purpose: a camera being
/// actively probed refreshes this continuously, so only a subnet whose
/// device has produced nothing for the whole window crosses it.
pub const REAP_TTL: Duration = Duration::from_secs(30 * 60);

/// Grace after discovery start for adoptions with no positive sighting
/// this session — typically entries restored from config at launch
/// whose device may just be slow to appear. Crossing it with still no
/// evidence means the device isn't there.
pub const STARTUP_GRACE: Duration = Duration::from_secs(10 * 60);

/// Wall-clock age of the last recorded sighting after which any
/// adoption badges as stale in the UI. Informational only — never a
/// removal input, so skew can only mislabel.
pub const STALE_BADGE: Duration = Duration::from_secs(24 * 60 * 60);

/// What the lifecycle check wants done with one adoption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReapVerdict {
    /// Healthy (or unparseable — proven-invalid keys are left to the
    /// existing restore/manual paths, never auto-removed).
    Keep,
    /// Stale by the applicable threshold but not removable: non-APIPA,
    /// or an APIPA reap held off by a pin/rescue veto. Badge only.
    StaleOnly,
    /// Unbind and forget. Only reachable for a parsed APIPA subnet.
    Reap,
}

/// Evidence for one adoption, gathered by the caller at decision time.
#[derive(Debug, Clone)]
pub struct LifecycleInput {
    /// Network address parsed from the subnet key (`parse_subnet_key`).
    /// `None` — the key doesn't parse — is never auto-removed.
    pub subnet: Option<Ipv4Addr>,
    /// Monotonic time since the last positive sighting this session;
    /// `None` when the subnet has produced no evidence since discovery
    /// started.
    pub last_positive_elapsed: Option<Duration>,
    /// Monotonic time since this discovery session started. Restarted
    /// with discovery itself, so an interface bounce re-arms the grace.
    pub session_elapsed: Duration,
    /// A user-pinned device (alias, manual node, configured stream
    /// target) sits inside this subnet.
    pub pinned: bool,
    /// The host itself is in APIPA rescue: no native, non-adopted,
    /// non-APIPA IPv4 on the wired adapter. While true, APIPA bindings
    /// are the host's only connectivity and nothing reaps.
    pub host_rescued: bool,
    /// Wall-clock age of the last recorded sighting (or of the adoption
    /// itself when no device was ever seen). Badge input only.
    pub badge_age: Option<Duration>,
}

/// Parse an adoption key of the exact shape every adoption path writes
/// (`"a.b.c.0/24"`) into its network address. Anything else is `None`.
pub fn parse_subnet_key(key: &str) -> Option<Ipv4Addr> {
    key.strip_suffix("/24")?.parse().ok()
}

/// The lifecycle decision for one adoption. See the module docs for
/// the policy; the containment invariant — non-APIPA can never return
/// `Reap` — is tested directly.
pub fn lifecycle_verdict(input: &LifecycleInput) -> ReapVerdict {
    let Some(net) = input.subnet else {
        return ReapVerdict::Keep;
    };

    if !net.is_link_local() {
        // Non-APIPA adoptions are removed by the user or not at all.
        // The 24 h badge is the only automatic outcome, keyed off the
        // persisted wall timestamps.
        return match input.badge_age {
            Some(age) if age >= STALE_BADGE => ReapVerdict::StaleOnly,
            _ => ReapVerdict::Keep,
        };
    }

    // APIPA: session evidence only. A subnet sighted this session gets
    // the full TTL from its latest sighting; one never sighted gets the
    // startup grace from discovery start.
    let ttl_crossed = match input.last_positive_elapsed {
        Some(elapsed) => elapsed >= REAP_TTL,
        None => input.session_elapsed >= STARTUP_GRACE,
    };
    if !ttl_crossed {
        return ReapVerdict::Keep;
    }
    if input.pinned || input.host_rescued {
        return ReapVerdict::StaleOnly;
    }
    ReapVerdict::Reap
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 60;
    const HOUR: u64 = 3600;

    fn apipa_input() -> LifecycleInput {
        LifecycleInput {
            subnet: parse_subnet_key("169.254.168.0/24"),
            last_positive_elapsed: None,
            session_elapsed: Duration::from_secs(0),
            pinned: false,
            host_rescued: false,
            badge_age: None,
        }
    }

    fn foreign_input() -> LifecycleInput {
        LifecycleInput {
            subnet: parse_subnet_key("172.31.169.0/24"),
            ..apipa_input()
        }
    }

    // ── key parsing ──────────────────────────────────────────────────

    #[test]
    fn parse_subnet_key_accepts_the_canonical_shape() {
        assert_eq!(
            parse_subnet_key("169.254.168.0/24"),
            Some(Ipv4Addr::new(169, 254, 168, 0))
        );
    }

    #[test]
    fn parse_subnet_key_rejects_other_shapes() {
        assert_eq!(parse_subnet_key("169.254.0.0/16"), None);
        assert_eq!(parse_subnet_key("169.254.168.0"), None);
        assert_eq!(parse_subnet_key("not-a-subnet/24"), None);
        assert_eq!(parse_subnet_key(""), None);
    }

    // ── containment: only parsed APIPA can reap ──────────────────────

    #[test]
    fn non_apipa_never_reaps_even_with_every_flag_favoring_removal() {
        let input = LifecycleInput {
            last_positive_elapsed: None,
            session_elapsed: Duration::from_secs(100 * HOUR),
            badge_age: Some(Duration::from_secs(100 * HOUR)),
            ..foreign_input()
        };
        assert_eq!(lifecycle_verdict(&input), ReapVerdict::StaleOnly);
    }

    #[test]
    fn unparseable_key_is_always_kept() {
        let input = LifecycleInput {
            subnet: None,
            session_elapsed: Duration::from_secs(100 * HOUR),
            badge_age: Some(Duration::from_secs(100 * HOUR)),
            ..apipa_input()
        };
        assert_eq!(lifecycle_verdict(&input), ReapVerdict::Keep);
    }

    // ── non-APIPA badge ──────────────────────────────────────────────

    #[test]
    fn non_apipa_badges_at_24_hours_and_not_before() {
        let fresh = LifecycleInput {
            badge_age: Some(Duration::from_secs(23 * HOUR)),
            ..foreign_input()
        };
        assert_eq!(lifecycle_verdict(&fresh), ReapVerdict::Keep);

        let stale = LifecycleInput {
            badge_age: Some(Duration::from_secs(24 * HOUR)),
            ..foreign_input()
        };
        assert_eq!(lifecycle_verdict(&stale), ReapVerdict::StaleOnly);

        // No badge age at all (freshly recorded metadata): keep.
        assert_eq!(lifecycle_verdict(&foreign_input()), ReapVerdict::Keep);
    }

    // ── APIPA TTL after a sighting ───────────────────────────────────

    #[test]
    fn apipa_recently_sighted_is_kept() {
        let input = LifecycleInput {
            last_positive_elapsed: Some(Duration::from_secs(29 * MIN)),
            session_elapsed: Duration::from_secs(10 * HOUR),
            ..apipa_input()
        };
        assert_eq!(lifecycle_verdict(&input), ReapVerdict::Keep);
    }

    #[test]
    fn apipa_reaps_thirty_minutes_after_its_last_sighting() {
        let input = LifecycleInput {
            last_positive_elapsed: Some(Duration::from_secs(30 * MIN)),
            session_elapsed: Duration::from_secs(10 * HOUR),
            ..apipa_input()
        };
        assert_eq!(lifecycle_verdict(&input), ReapVerdict::Reap);
    }

    #[test]
    fn a_sighting_outranks_the_startup_grace() {
        // Sighted once, recently — kept even though the session is far
        // past the grace window.
        let input = LifecycleInput {
            last_positive_elapsed: Some(Duration::from_secs(MIN)),
            session_elapsed: Duration::from_secs(10 * HOUR),
            ..apipa_input()
        };
        assert_eq!(lifecycle_verdict(&input), ReapVerdict::Keep);
    }

    // ── APIPA startup grace (never sighted this session) ─────────────

    #[test]
    fn apipa_never_sighted_survives_the_grace_window() {
        let input = LifecycleInput {
            session_elapsed: Duration::from_secs(9 * MIN),
            ..apipa_input()
        };
        assert_eq!(lifecycle_verdict(&input), ReapVerdict::Keep);
    }

    #[test]
    fn apipa_never_sighted_reaps_after_the_grace_window() {
        let input = LifecycleInput {
            session_elapsed: Duration::from_secs(10 * MIN),
            ..apipa_input()
        };
        assert_eq!(lifecycle_verdict(&input), ReapVerdict::Reap);
    }

    // ── vetoes downgrade to a badge ──────────────────────────────────

    #[test]
    fn pinned_apipa_badges_instead_of_reaping() {
        let input = LifecycleInput {
            session_elapsed: Duration::from_secs(HOUR),
            pinned: true,
            ..apipa_input()
        };
        assert_eq!(lifecycle_verdict(&input), ReapVerdict::StaleOnly);
    }

    #[test]
    fn rescued_host_holds_every_apipa_reap() {
        let input = LifecycleInput {
            session_elapsed: Duration::from_secs(HOUR),
            host_rescued: true,
            ..apipa_input()
        };
        assert_eq!(lifecycle_verdict(&input), ReapVerdict::StaleOnly);
    }

    #[test]
    fn vetoes_do_not_mask_a_healthy_subnet() {
        // Pinned + within TTL is plain Keep, not a badge.
        let input = LifecycleInput {
            last_positive_elapsed: Some(Duration::from_secs(MIN)),
            session_elapsed: Duration::from_secs(HOUR),
            pinned: true,
            ..apipa_input()
        };
        assert_eq!(lifecycle_verdict(&input), ReapVerdict::Keep);
    }

    // ── wall clock can never remove ──────────────────────────────────

    #[test]
    fn badge_age_is_irrelevant_to_the_apipa_reap_decision() {
        // Ancient wall timestamps with a fresh session sighting: kept.
        // Wall time is display-only; only monotonic session evidence
        // may remove.
        let input = LifecycleInput {
            last_positive_elapsed: Some(Duration::from_secs(MIN)),
            session_elapsed: Duration::from_secs(10 * HOUR),
            badge_age: Some(Duration::from_secs(1000 * HOUR)),
            ..apipa_input()
        };
        assert_eq!(lifecycle_verdict(&input), ReapVerdict::Keep);
    }
}
