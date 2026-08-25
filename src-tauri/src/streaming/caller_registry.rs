//! Strict pre-accept admission accounting for the SRT listener.
//!
//! Caller identities are intentionally opaque: neither this module's key nor
//! its state implements `Debug` or `Display`. Callback failures return only
//! fixed, redacted capability errors so addresses and Stream IDs cannot leak
//! into retained relay faults or logs.

use gio::prelude::*;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use thiserror::Error;

pub(super) const MAX_SRT_CALLERS: u32 = 10;
pub(super) const PENDING_CALLER_TTL: Duration = Duration::from_secs(10);

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct CallerAddress {
    ip: IpAddr,
    port: u16,
}

impl CallerAddress {
    #[cfg(test)]
    fn for_test(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AdmissionDecision {
    Accept,
    RejectStreamId,
    RejectCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(super) enum CallerRegistryFault {
    #[error("SRT callback omitted the caller address")]
    MissingAddress,
    #[error("SRT callback supplied an invalid caller address type")]
    InvalidAddressType,
    #[error("SRT callback supplied a non-internet caller address")]
    NonInternetAddress,
    #[error("SRT callback supplied an invalid internet caller address")]
    InvalidInternetAddress,
    #[error("SRT callback omitted the caller Stream ID")]
    MissingStreamId,
    #[error("SRT callback supplied an invalid caller Stream ID type")]
    InvalidStreamIdType,
    #[error("SRT callback omitted its documented unused argument")]
    MissingUnusedArgument,
    #[error("SRT callback supplied an invalid unused argument type")]
    InvalidUnusedArgumentType,
    #[error("SRT callback's documented unused argument was not zero")]
    NonzeroUnusedArgument,
    #[error("SRT caller-added duplicated an active caller")]
    DuplicateAddedCaller,
    #[error("SRT caller-added arrived without a pending reservation")]
    AddedWithoutReservation,
    #[error("SRT caller-added would exceed the caller limit")]
    AddedOverCapacity,
    #[error("SRT caller existed in both pending and active state")]
    InconsistentCallerState,
    #[error("SRT caller-removed had no active caller")]
    RemovedWithoutActiveCaller,
    #[error("SRT caller registry exceeded its occupancy invariant")]
    OccupancyInvariantExceeded,
}

/// Convert the callback's `GSocketAddress` into the one identity used by all
/// admission transitions. The key stores a parsed IP address plus UDP port,
/// avoiding textual IPv6 representation differences between signals.
pub(super) fn canonical_caller_address(
    value: Option<&glib::Value>,
) -> Result<CallerAddress, CallerRegistryFault> {
    let socket = value
        .ok_or(CallerRegistryFault::MissingAddress)?
        .get::<gio::SocketAddress>()
        .map_err(|_| CallerRegistryFault::InvalidAddressType)?;
    let inet = socket
        .downcast::<gio::InetSocketAddress>()
        .map_err(|_| CallerRegistryFault::NonInternetAddress)?;
    let ip = inet
        .address()
        .to_string()
        .parse::<IpAddr>()
        .map_err(|_| CallerRegistryFault::InvalidInternetAddress)?;
    Ok(CallerAddress {
        ip,
        port: inet.port(),
    })
}

/// Decode the nullable string used by `caller-connecting`. A null value is
/// the callback representation of an absent Stream ID and therefore becomes
/// the empty byte sequence.
pub(super) fn caller_stream_id(
    value: Option<&glib::Value>,
) -> Result<Vec<u8>, CallerRegistryFault> {
    value
        .ok_or(CallerRegistryFault::MissingStreamId)?
        .get::<Option<String>>()
        .map_err(|_| CallerRegistryFault::InvalidStreamIdType)
        .map(|stream_id| stream_id.unwrap_or_default().into_bytes())
}

/// Decode the integer argument on `caller-added` and `caller-removed`. The
/// patched-runtime G2 gate proves this ABI slot is unused and always zero.
pub(super) fn caller_unused_argument(
    value: Option<&glib::Value>,
) -> Result<i32, CallerRegistryFault> {
    value
        .ok_or(CallerRegistryFault::MissingUnusedArgument)?
        .get::<i32>()
        .map_err(|_| CallerRegistryFault::InvalidUnusedArgumentType)
}

struct RegistryState {
    pending: HashMap<CallerAddress, Instant>,
    active: HashSet<CallerAddress>,
}

impl RegistryState {
    fn occupancy(&self) -> usize {
        self.pending.len() + self.active.len()
    }

    fn prune_expired(&mut self, now: Instant) {
        self.pending.retain(|_, reserved_at| {
            now.saturating_duration_since(*reserved_at) < PENDING_CALLER_TTL
        });
    }
}

/// Thread-safe pending/active state shared by the SRT signal callbacks and
/// status reporting. The optional expected Stream ID participates only in an
/// exact byte comparison and is never exposed by this type.
pub(super) struct CallerRegistry {
    expected_stream_id: Option<Box<[u8]>>,
    state: Mutex<RegistryState>,
}

impl CallerRegistry {
    pub(super) fn new(expected_stream_id: Option<&str>) -> Self {
        Self {
            expected_stream_id: expected_stream_id
                .filter(|stream_id| !stream_id.is_empty())
                .map(|stream_id| stream_id.as_bytes().into()),
            state: Mutex::new(RegistryState {
                pending: HashMap::new(),
                active: HashSet::new(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, RegistryState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(super) fn caller_connecting(
        &self,
        address: CallerAddress,
        stream_id: &[u8],
        now: Instant,
    ) -> Result<AdmissionDecision, CallerRegistryFault> {
        let mut state = self.lock();
        state.prune_expired(now);

        if state.occupancy() > MAX_SRT_CALLERS as usize {
            return Err(CallerRegistryFault::OccupancyInvariantExceeded);
        }
        if state.pending.contains_key(&address) && state.active.contains(&address) {
            return Err(CallerRegistryFault::InconsistentCallerState);
        }
        if self
            .expected_stream_id
            .as_deref()
            .is_some_and(|expected| expected != stream_id)
        {
            return Ok(AdmissionDecision::RejectStreamId);
        }
        if state.active.contains(&address) {
            return Ok(AdmissionDecision::Accept);
        }
        if let Some(reserved_at) = state.pending.get_mut(&address) {
            *reserved_at = now;
            return Ok(AdmissionDecision::Accept);
        }
        if state.occupancy() >= MAX_SRT_CALLERS as usize {
            return Ok(AdmissionDecision::RejectCapacity);
        }

        state.pending.insert(address, now);
        Ok(AdmissionDecision::Accept)
    }

    pub(super) fn caller_added(
        &self,
        address: CallerAddress,
        unused: i32,
    ) -> Result<u32, CallerRegistryFault> {
        if unused != 0 {
            return Err(CallerRegistryFault::NonzeroUnusedArgument);
        }

        let mut state = self.lock();
        if state.occupancy() > MAX_SRT_CALLERS as usize {
            return Err(CallerRegistryFault::OccupancyInvariantExceeded);
        }
        let pending = state.pending.contains_key(&address);
        let active = state.active.contains(&address);
        match (pending, active) {
            (true, true) => Err(CallerRegistryFault::InconsistentCallerState),
            (false, true) => Err(CallerRegistryFault::DuplicateAddedCaller),
            (false, false) if state.occupancy() >= MAX_SRT_CALLERS as usize => {
                Err(CallerRegistryFault::AddedOverCapacity)
            }
            (false, false) => Err(CallerRegistryFault::AddedWithoutReservation),
            (true, false) => {
                state.pending.remove(&address);
                state.active.insert(address);
                if state.occupancy() > MAX_SRT_CALLERS as usize {
                    return Err(CallerRegistryFault::OccupancyInvariantExceeded);
                }
                Ok(state.active.len() as u32)
            }
        }
    }

    pub(super) fn caller_removed(
        &self,
        address: &CallerAddress,
        unused: i32,
    ) -> Result<u32, CallerRegistryFault> {
        if unused != 0 {
            return Err(CallerRegistryFault::NonzeroUnusedArgument);
        }

        let mut state = self.lock();
        if !state.active.remove(address) {
            return Err(CallerRegistryFault::RemovedWithoutActiveCaller);
        }
        Ok(state.active.len() as u32)
    }

    pub(super) fn active_count(&self) -> u32 {
        self.lock().active.len() as u32
    }

    pub(super) fn clear(&self) {
        let mut state = self.lock();
        state.pending.clear();
        state.active.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use glib::value::ToValue;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn address(index: u8) -> CallerAddress {
        CallerAddress::for_test(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, index)),
            8_000 + index as u16,
        )
    }

    fn assert_decision(
        actual: Result<AdmissionDecision, CallerRegistryFault>,
        expected: AdmissionDecision,
    ) {
        assert!(matches!(actual, Ok(decision) if decision == expected));
    }

    #[test]
    fn canonicalizes_ipv4_and_ipv6_socket_addresses() {
        for (text, expected) in [
            ("192.0.2.4", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4))),
            (
                "2001:db8::4",
                IpAddr::V6("2001:db8::4".parse::<Ipv6Addr>().unwrap()),
            ),
        ] {
            let inet_address = gio::InetAddress::from_string(text).unwrap();
            let socket: gio::SocketAddress =
                gio::InetSocketAddress::new(&inet_address, 8_890).upcast();
            let value = socket.to_value();
            let actual = canonical_caller_address(Some(&value)).unwrap();
            assert!(actual == CallerAddress::for_test(expected, 8_890));
        }
    }

    #[test]
    fn rejects_missing_and_mistyped_callback_values_without_echoing_them() {
        let wrong_type = 42_u32.to_value();
        assert!(matches!(
            canonical_caller_address(None),
            Err(CallerRegistryFault::MissingAddress)
        ));
        assert!(matches!(
            canonical_caller_address(Some(&wrong_type)),
            Err(CallerRegistryFault::InvalidAddressType)
        ));
        assert!(matches!(
            caller_stream_id(None),
            Err(CallerRegistryFault::MissingStreamId)
        ));
        assert!(matches!(
            caller_stream_id(Some(&wrong_type)),
            Err(CallerRegistryFault::InvalidStreamIdType)
        ));
        assert!(matches!(
            caller_unused_argument(None),
            Err(CallerRegistryFault::MissingUnusedArgument)
        ));
        assert!(matches!(
            caller_unused_argument(Some(&"not-an-integer".to_value())),
            Err(CallerRegistryFault::InvalidUnusedArgumentType)
        ));
    }

    #[test]
    fn decodes_null_and_exact_utf8_stream_ids() {
        let missing = Option::<String>::None.to_value();
        assert_eq!(caller_stream_id(Some(&missing)).unwrap(), b"");

        let expected = "#!::r=Pocket Stream/%#&=,snowman-☃";
        let present = Some(expected.to_owned()).to_value();
        assert_eq!(
            caller_stream_id(Some(&present)).unwrap(),
            expected.as_bytes()
        );
    }

    #[test]
    fn exact_stream_id_mismatch_never_reserves_a_slot() {
        let registry = CallerRegistry::new(Some("required"));
        let now = Instant::now();
        assert_decision(
            registry.caller_connecting(address(1), b"wrong", now),
            AdmissionDecision::RejectStreamId,
        );
        assert_eq!(registry.lock().occupancy(), 0);
        assert_decision(
            registry.caller_connecting(address(1), b"required", now),
            AdmissionDecision::Accept,
        );
        assert_eq!(registry.lock().occupancy(), 1);
    }

    #[test]
    fn empty_stream_id_policy_accepts_any_caller_value() {
        let now = Instant::now();
        for policy in [None, Some("")] {
            let registry = CallerRegistry::new(policy);
            assert_decision(
                registry.caller_connecting(address(1), b"caller-supplied", now),
                AdmissionDecision::Accept,
            );
        }
    }

    #[test]
    fn same_address_refreshes_one_pending_reservation() {
        let registry = CallerRegistry::new(None);
        let first = Instant::now();
        let caller = address(1);
        assert_decision(
            registry.caller_connecting(caller.clone(), b"", first),
            AdmissionDecision::Accept,
        );
        assert_decision(
            registry.caller_connecting(caller.clone(), b"", first + Duration::from_secs(9)),
            AdmissionDecision::Accept,
        );

        let state = registry.lock();
        assert_eq!(state.pending.len(), 1);
        assert_eq!(
            state.pending.get(&caller),
            Some(&(first + Duration::from_secs(9)))
        );
    }

    #[test]
    fn admission_prunes_expired_pending_but_preserves_active_callers() {
        let registry = CallerRegistry::new(None);
        let first = Instant::now();
        let active = address(1);
        let stale = address(2);
        assert_decision(
            registry.caller_connecting(active.clone(), b"", first),
            AdmissionDecision::Accept,
        );
        assert_eq!(registry.caller_added(active.clone(), 0), Ok(1));
        assert_decision(
            registry.caller_connecting(stale, b"", first),
            AdmissionDecision::Accept,
        );

        assert_decision(
            registry.caller_connecting(address(3), b"", first + PENDING_CALLER_TTL),
            AdmissionDecision::Accept,
        );
        let state = registry.lock();
        assert_eq!(state.active.len(), 1);
        assert!(state.active.contains(&active));
        assert_eq!(state.pending.len(), 1);
    }

    #[test]
    fn cap_counts_pending_plus_active_and_allows_same_address_refresh() {
        let registry = CallerRegistry::new(None);
        let now = Instant::now();
        for index in 1..=MAX_SRT_CALLERS as u8 {
            assert_decision(
                registry.caller_connecting(address(index), b"", now),
                AdmissionDecision::Accept,
            );
        }
        assert_decision(
            registry.caller_connecting(address(1), b"", now + Duration::from_secs(1)),
            AdmissionDecision::Accept,
        );
        assert_decision(
            registry.caller_connecting(address(11), b"", now),
            AdmissionDecision::RejectCapacity,
        );
        assert_eq!(registry.lock().occupancy(), MAX_SRT_CALLERS as usize);
    }

    #[test]
    fn added_and_removed_move_one_caller_atomically() {
        let registry = CallerRegistry::new(None);
        let caller = address(1);
        assert_decision(
            registry.caller_connecting(caller.clone(), b"", Instant::now()),
            AdmissionDecision::Accept,
        );
        assert_eq!(registry.caller_added(caller.clone(), 0), Ok(1));
        {
            let state = registry.lock();
            assert!(state.pending.is_empty());
            assert!(state.active.contains(&caller));
            assert_eq!(state.occupancy(), 1);
        }
        assert_eq!(registry.caller_removed(&caller, 0), Ok(0));
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn impossible_or_out_of_order_transitions_are_faults_without_mutation() {
        let registry = CallerRegistry::new(None);
        let caller = address(1);
        assert_eq!(
            registry.caller_added(caller.clone(), 0),
            Err(CallerRegistryFault::AddedWithoutReservation)
        );
        assert_eq!(
            registry.caller_removed(&caller, 0),
            Err(CallerRegistryFault::RemovedWithoutActiveCaller)
        );
        assert_eq!(
            registry.caller_added(caller.clone(), 7),
            Err(CallerRegistryFault::NonzeroUnusedArgument)
        );
        assert_eq!(registry.lock().occupancy(), 0);
    }

    #[test]
    fn duplicate_and_over_capacity_adds_are_capability_faults() {
        let registry = CallerRegistry::new(None);
        let now = Instant::now();
        let first = address(1);
        assert_decision(
            registry.caller_connecting(first.clone(), b"", now),
            AdmissionDecision::Accept,
        );
        assert_eq!(registry.caller_added(first.clone(), 0), Ok(1));
        assert_eq!(
            registry.caller_added(first, 0),
            Err(CallerRegistryFault::DuplicateAddedCaller)
        );

        for index in 2..=MAX_SRT_CALLERS as u8 {
            let caller = address(index);
            assert_decision(
                registry.caller_connecting(caller.clone(), b"", now),
                AdmissionDecision::Accept,
            );
            assert!(registry.caller_added(caller, 0).is_ok());
        }
        assert_eq!(
            registry.caller_added(address(11), 0),
            Err(CallerRegistryFault::AddedOverCapacity)
        );
        assert_eq!(registry.active_count(), MAX_SRT_CALLERS);
    }

    #[test]
    fn inconsistent_internal_state_is_detected_before_admission_or_add() {
        let registry = CallerRegistry::new(None);
        let caller = address(1);
        {
            let mut state = registry.lock();
            state.pending.insert(caller.clone(), Instant::now());
            state.active.insert(caller.clone());
        }
        assert_eq!(
            registry.caller_connecting(caller.clone(), b"", Instant::now()),
            Err(CallerRegistryFault::InconsistentCallerState)
        );
        assert_eq!(
            registry.caller_added(caller, 0),
            Err(CallerRegistryFault::InconsistentCallerState)
        );
    }

    #[test]
    fn clear_releases_pending_and_active_registrations() {
        let registry = CallerRegistry::new(None);
        let active = address(1);
        assert_decision(
            registry.caller_connecting(active.clone(), b"", Instant::now()),
            AdmissionDecision::Accept,
        );
        registry.caller_added(active, 0).unwrap();
        assert_decision(
            registry.caller_connecting(address(2), b"", Instant::now()),
            AdmissionDecision::Accept,
        );
        registry.clear();
        assert_eq!(registry.lock().occupancy(), 0);
    }

    #[test]
    fn concurrent_admission_never_exceeds_the_combined_limit() {
        let registry = Arc::new(CallerRegistry::new(None));
        let barrier = Arc::new(Barrier::new(21));
        let now = Instant::now();
        let mut threads = Vec::new();
        for index in 1..=20 {
            let registry = registry.clone();
            let barrier = barrier.clone();
            threads.push(thread::spawn(move || {
                barrier.wait();
                registry
                    .caller_connecting(address(index), b"", now)
                    .unwrap()
            }));
        }
        barrier.wait();

        let accepted = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|decision| *decision == AdmissionDecision::Accept)
            .count();
        assert_eq!(accepted, MAX_SRT_CALLERS as usize);
        assert_eq!(registry.lock().occupancy(), MAX_SRT_CALLERS as usize);
    }

    #[test]
    fn concurrent_add_and_remove_keeps_active_count_accurate() {
        let registry = Arc::new(CallerRegistry::new(None));
        let now = Instant::now();
        for index in 1..=MAX_SRT_CALLERS as u8 {
            assert_decision(
                registry.caller_connecting(address(index), b"", now),
                AdmissionDecision::Accept,
            );
        }

        let add_threads: Vec<_> = (1..=MAX_SRT_CALLERS as u8)
            .map(|index| {
                let registry = registry.clone();
                thread::spawn(move || registry.caller_added(address(index), 0).unwrap())
            })
            .collect();
        for handle in add_threads {
            handle.join().unwrap();
        }
        assert_eq!(registry.active_count(), MAX_SRT_CALLERS);

        let remove_threads: Vec<_> = (1..=MAX_SRT_CALLERS as u8)
            .map(|index| {
                let registry = registry.clone();
                thread::spawn(move || registry.caller_removed(&address(index), 0).unwrap())
            })
            .collect();
        for handle in remove_threads {
            handle.join().unwrap();
        }
        assert_eq!(registry.active_count(), 0);
    }
}
