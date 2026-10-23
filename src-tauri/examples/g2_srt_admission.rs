//! G2 runtime gate for GStreamer's dynamic SRT caller signals.
//!
//! This is deliberately an example target rather than production code. The
//! feature specification requires the callback ABI and strict admission model
//! to be proven against the patched runtime before the production
//! `CallerRegistry` is implemented.

use gio::prelude::*;
use glib::value::ToValue;
use gst::prelude::*;
use gstreamer as gst;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::env;
use std::error::Error;
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::net::UdpSocket;
use std::os::raw::c_void;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

const EXPECTED_SRT_VERSION: u32 = 0x010507;
const CLIENT_LIMIT: usize = 10;
const PENDING_TTL: Duration = Duration::from_secs(10);
const WAIT_STEP: Duration = Duration::from_millis(25);
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(8);
const TEST_PASSPHRASE: &str = "PocketStream-G2-Transport-Key";
const WRONG_PASSPHRASE: &str = "PocketStream-G2-Wrong-Key";
const TEST_STREAM_ID: &str = "#!::r=Pocket Stream/%#&=,snowman-\u{2603}";

type HarnessResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug)]
struct HarnessError(String);

impl fmt::Display for HarnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for HarnessError {}

fn fail<T>(message: impl Into<String>) -> HarnessResult<T> {
    Err(Box::new(HarnessError(message.into())))
}

fn require(condition: bool, message: impl Into<String>) -> HarnessResult<()> {
    if condition {
        Ok(())
    } else {
        fail(message)
    }
}

#[derive(Debug, Clone)]
struct SignalEvent {
    sequence: u64,
    kind: &'static str,
    key: Option<String>,
    stream_id: Vec<u8>,
    decision: Option<&'static str>,
    unused: Option<i32>,
}

#[derive(Debug, Clone)]
struct RegistryState {
    pending: HashMap<String, Instant>,
    active: HashSet<String>,
    events: Vec<SignalEvent>,
    faults: Vec<String>,
    next_sequence: u64,
    max_occupancy: usize,
    new_reservations: usize,
    refreshed_reservations: usize,
    expired_reservations: usize,
    application_rejections: usize,
    rejection_signals: usize,
}

impl RegistryState {
    fn new() -> Self {
        Self {
            pending: HashMap::new(),
            active: HashSet::new(),
            events: Vec::new(),
            faults: Vec::new(),
            next_sequence: 1,
            max_occupancy: 0,
            new_reservations: 0,
            refreshed_reservations: 0,
            expired_reservations: 0,
            application_rejections: 0,
            rejection_signals: 0,
        }
    }

    fn occupancy(&self) -> usize {
        self.pending.len() + self.active.len()
    }

    fn update_max_occupancy(&mut self) {
        self.max_occupancy = self.max_occupancy.max(self.occupancy());
    }

    fn record(
        &mut self,
        kind: &'static str,
        key: Option<String>,
        stream_id: Vec<u8>,
        decision: Option<&'static str>,
        unused: Option<i32>,
    ) {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.events.push(SignalEvent {
            sequence,
            kind,
            key,
            stream_id,
            decision,
            unused,
        });
    }

    fn prune_expired(&mut self, now: Instant) {
        let expired: Vec<String> = self
            .pending
            .iter()
            .filter(|&(_, reserved_at)| now.duration_since(*reserved_at) >= PENDING_TTL)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.pending.remove(&key);
            self.expired_reservations += 1;
            self.record("pending-expired", Some(key), Vec::new(), None, None);
        }
    }
}

type SharedRegistry = Arc<Mutex<RegistryState>>;

fn lock_registry(registry: &SharedRegistry) -> MutexGuard<'_, RegistryState> {
    registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug, Clone)]
struct AdmissionPolicy {
    authentication: bool,
    reject_all: bool,
    expected_stream_id: Option<Vec<u8>>,
}

impl AdmissionPolicy {
    fn open(authentication: bool) -> Self {
        Self {
            authentication,
            reject_all: false,
            expected_stream_id: None,
        }
    }
}

fn canonical_socket_key(value: Option<&glib::Value>) -> Result<String, String> {
    let socket = value
        .ok_or_else(|| "signal omitted GSocketAddress".to_owned())?
        .get::<gio::SocketAddress>()
        .map_err(|error| format!("signal address was not GSocketAddress: {error}"))?;
    let inet = socket
        .downcast::<gio::InetSocketAddress>()
        .map_err(|_| "signal address was not an internet socket address".to_owned())?;
    let address = inet.address().to_string();
    if address.contains(':') {
        Ok(format!("[{address}]:{}", inet.port()))
    } else {
        Ok(format!("{address}:{}", inet.port()))
    }
}

fn signal_stream_id(value: Option<&glib::Value>) -> Result<Vec<u8>, String> {
    let stream_id = value
        .ok_or_else(|| "signal omitted Stream ID".to_owned())?
        .get::<Option<String>>()
        .map_err(|error| format!("signal Stream ID was not a nullable string: {error}"))?
        .unwrap_or_default();
    Ok(stream_id.into_bytes())
}

fn install_signal_handlers(sink: &gst::Element, registry: SharedRegistry, policy: AdmissionPolicy) {
    let connecting_registry = registry.clone();
    let connecting_policy = policy.clone();
    sink.connect("caller-connecting", false, move |values| {
        let key = match canonical_socket_key(values.get(1)) {
            Ok(key) => key,
            Err(error) => {
                lock_registry(&connecting_registry).faults.push(error);
                return Some(false.to_value());
            }
        };
        let stream_id = match signal_stream_id(values.get(2)) {
            Ok(stream_id) => stream_id,
            Err(error) => {
                lock_registry(&connecting_registry).faults.push(error);
                return Some(false.to_value());
            }
        };

        let now = Instant::now();
        let mut state = lock_registry(&connecting_registry);
        state.prune_expired(now);

        if connecting_policy.reject_all {
            state.application_rejections += 1;
            state.record(
                "caller-connecting",
                Some(key),
                stream_id,
                Some("rejected-policy"),
                None,
            );
            return Some(false.to_value());
        }

        if connecting_policy
            .expected_stream_id
            .as_ref()
            .is_some_and(|expected| expected.as_slice() != stream_id.as_slice())
        {
            state.application_rejections += 1;
            state.record(
                "caller-connecting",
                Some(key),
                stream_id,
                Some("rejected-stream-id"),
                None,
            );
            return Some(false.to_value());
        }

        let decision = if state.active.contains(&key) {
            "accepted-active"
        } else if let Some(reserved_at) = state.pending.get_mut(&key) {
            *reserved_at = now;
            state.refreshed_reservations += 1;
            "accepted-refresh"
        } else if state.occupancy() >= CLIENT_LIMIT {
            state.application_rejections += 1;
            state.record(
                "caller-connecting",
                Some(key),
                stream_id,
                Some("rejected-capacity"),
                None,
            );
            return Some(false.to_value());
        } else {
            state.pending.insert(key.clone(), now);
            state.new_reservations += 1;
            state.update_max_occupancy();
            "accepted-new"
        };

        state.record(
            "caller-connecting",
            Some(key),
            stream_id,
            Some(decision),
            None,
        );
        Some(true.to_value())
    });

    let added_registry = registry.clone();
    let added_policy = policy.clone();
    sink.connect("caller-added", false, move |values| {
        let unused = values.get(1).and_then(|value| value.get::<i32>().ok());
        let key = match canonical_socket_key(values.get(2)) {
            Ok(key) => key,
            Err(error) => {
                lock_registry(&added_registry).faults.push(error);
                return None;
            }
        };
        let mut state = lock_registry(&added_registry);
        if unused != Some(0) {
            state.faults.push(format!(
                "caller-added ABI argument was {unused:?}, not zero"
            ));
        }
        let had_reservation = state.pending.remove(&key).is_some();
        if added_policy.authentication && !had_reservation {
            state.faults.push(format!(
                "caller-added arrived without a pending reservation for {key}"
            ));
        }
        if !state.active.insert(key.clone()) {
            state
                .faults
                .push(format!("caller-added duplicated active key {key}"));
        }
        state.update_max_occupancy();
        if state.occupancy() > CLIENT_LIMIT {
            state.faults.push(format!(
                "caller-added exceeded the {CLIENT_LIMIT}-caller invariant"
            ));
        }
        state.record("caller-added", Some(key), Vec::new(), None, unused);
        None
    });

    let removed_registry = registry.clone();
    sink.connect("caller-removed", false, move |values| {
        let unused = values.get(1).and_then(|value| value.get::<i32>().ok());
        let key = match canonical_socket_key(values.get(2)) {
            Ok(key) => key,
            Err(error) => {
                lock_registry(&removed_registry).faults.push(error);
                return None;
            }
        };
        let mut state = lock_registry(&removed_registry);
        if unused != Some(0) {
            state.faults.push(format!(
                "caller-removed ABI argument was {unused:?}, not zero"
            ));
        }
        if !state.active.remove(&key) {
            state
                .faults
                .push(format!("caller-removed had no active key {key}"));
        }
        state.record("caller-removed", Some(key), Vec::new(), None, unused);
        None
    });

    sink.connect("caller-rejected", false, move |values| {
        let key = canonical_socket_key(values.get(1));
        let stream_id = signal_stream_id(values.get(2));
        let mut state = lock_registry(&registry);
        match (key, stream_id) {
            (Ok(key), Ok(stream_id)) => {
                state.rejection_signals += 1;
                state.record("caller-rejected", Some(key), stream_id, None, None);
            }
            (Err(error), _) | (_, Err(error)) => state.faults.push(error),
        }
        None
    });
}

struct Listener {
    pipeline: gst::Pipeline,
    registry: SharedRegistry,
}

impl Listener {
    fn start(port: u16, policy: AdmissionPolicy, passphrase: Option<&str>) -> HarnessResult<Self> {
        let element = gst::parse::launch(
            "fakesrc is-live=true sync=true sizetype=fixed sizemax=1316 filltype=zero \
             datarate=131600 ! queue ! srtsink name=g2sink",
        )?;
        let pipeline = element
            .downcast::<gst::Pipeline>()
            .map_err(|_| HarnessError("listener launch did not create a Pipeline".to_owned()))?;
        let sink = pipeline
            .by_name("g2sink")
            .ok_or_else(|| HarnessError("listener has no g2sink element".to_owned()))?;
        sink.set_property_from_str("mode", "listener");
        sink.set_property("localaddress", "127.0.0.1");
        sink.set_property("localport", u32::from(port));
        sink.set_property("wait-for-connection", false);
        sink.set_property("authentication", policy.authentication);
        sink.set_property("latency", 20i32);
        sink.set_property("poll-timeout", 100i32);
        if let Some(passphrase) = passphrase {
            sink.set_property("passphrase", passphrase);
            sink.set_property_from_str("pbkeylen", "16");
        }

        let registry = Arc::new(Mutex::new(RegistryState::new()));
        install_signal_handlers(&sink, registry.clone(), policy);
        pipeline.set_state(gst::State::Playing).map_err(|_| {
            HarnessError(format!("listener failed to enter PLAYING on port {port}"))
        })?;
        thread::sleep(Duration::from_millis(350));
        if let Some(message) = pipeline.bus().and_then(|bus| {
            bus.timed_pop_filtered(gst::ClockTime::ZERO, &[gst::MessageType::Error])
        }) {
            if let gst::MessageView::Error(error) = message.view() {
                return fail(format!(
                    "listener bus error on port {port}: {} ({:?})",
                    error.error(),
                    error.debug()
                ));
            }
        }
        Ok(Self { pipeline, registry })
    }

    fn snapshot(&self) -> RegistryState {
        lock_registry(&self.registry).clone()
    }

    fn stop(&self) {
        let _ = self.pipeline.set_state(gst::State::Null);
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.pipeline.set_state(gst::State::Null);
    }
}

struct Client {
    pipeline: gst::Pipeline,
    startup_failed: bool,
}

impl Client {
    fn start(port: u16, passphrase: Option<&str>, stream_id: Option<&str>) -> HarnessResult<Self> {
        let element = gst::parse::launch("srtsrc name=g2src ! fakesink sync=false")?;
        let pipeline = element
            .downcast::<gst::Pipeline>()
            .map_err(|_| HarnessError("client launch did not create a Pipeline".to_owned()))?;
        let source = pipeline
            .by_name("g2src")
            .ok_or_else(|| HarnessError("client has no g2src element".to_owned()))?;
        source.set_property("uri", format!("srt://127.0.0.1:{port}"));
        source.set_property_from_str("mode", "caller");
        source.set_property("latency", 20i32);
        source.set_property("poll-timeout", 100i32);
        source.set_property("auto-reconnect", false);
        if let Some(passphrase) = passphrase {
            source.set_property("passphrase", passphrase);
            source.set_property_from_str("pbkeylen", "16");
        }
        if let Some(stream_id) = stream_id {
            source.set_property("streamid", stream_id);
        }
        let startup_failed = pipeline.set_state(gst::State::Playing).is_err();
        Ok(Self {
            pipeline,
            startup_failed,
        })
    }

    fn wait_for_failure(&self, timeout: Duration) -> bool {
        if self.startup_failed {
            return true;
        }
        let Some(bus) = self.pipeline.bus() else {
            return false;
        };
        let message = bus.timed_pop_filtered(
            gst::ClockTime::from_nseconds(timeout.as_nanos() as u64),
            &[gst::MessageType::Error, gst::MessageType::Eos],
        );
        matches!(
            message.as_ref().map(|message| message.view()),
            Some(gst::MessageView::Error(_))
        )
    }

    fn stop(&self) {
        let _ = self.pipeline.set_state(gst::State::Null);
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.pipeline.set_state(gst::State::Null);
    }
}

fn wait_for_registry<F>(
    listener: &Listener,
    description: &str,
    predicate: F,
) -> HarnessResult<RegistryState>
where
    F: Fn(&RegistryState) -> bool,
{
    let deadline = Instant::now() + CALLBACK_TIMEOUT;
    loop {
        let snapshot = listener.snapshot();
        if !snapshot.faults.is_empty() {
            return fail(format!(
                "{description} encountered registry faults: {}",
                snapshot.faults.join("; ")
            ));
        }
        if predicate(&snapshot) {
            return Ok(snapshot);
        }
        if Instant::now() >= deadline {
            return fail(format!(
                "timed out waiting for {description}; pending={}, active={}, events={}, rejections={}",
                snapshot.pending.len(),
                snapshot.active.len(),
                snapshot.events.len(),
                snapshot.application_rejections
            ));
        }
        thread::sleep(WAIT_STEP);
    }
}

fn free_udp_port(used: &mut HashSet<u16>) -> HarnessResult<u16> {
    for _ in 0..32 {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        let port = socket.local_addr()?.port();
        drop(socket);
        if used.insert(port) {
            return Ok(port);
        }
    }
    fail("could not allocate a unique loopback UDP port")
}

#[repr(C)]
struct SrtSockAddrIn {
    family: u16,
    port: u16,
    address: u32,
    zero: [u8; 8],
}

fn ipv4_sockaddr(port: u16) -> SrtSockAddrIn {
    SrtSockAddrIn {
        family: 2, // AF_INET on every SRT-supported platform.
        port: port.to_be(),
        // Store the bytes in network order in memory, independent of host
        // integer endianness.
        address: u32::from_ne_bytes([127, 0, 0, 1]),
        zero: [0; 8],
    }
}

/// Make one blocking caller handshake from an explicitly bound UDP port.
///
/// GStreamer's caller-mode element intentionally ignores `localport`, so it
/// cannot reproduce two handshakes from one canonical address. This tiny
/// dynamically loaded client uses the exact staged libsrt DLL and only the
/// public socket API needed to bind, attempt a deliberately wrong encrypted
/// handshake, and close. The listener and all assertions remain GStreamer.
fn run_bound_wrong_handshake(
    libsrt_path: &Path,
    local_port: u16,
    listener_port: u16,
) -> HarnessResult<()> {
    type CreateSocket = unsafe extern "C" fn() -> i32;
    type SetSockOpt = unsafe extern "C" fn(i32, i32, i32, *const c_void, i32) -> i32;
    type Bind = unsafe extern "C" fn(i32, *const c_void, i32) -> i32;
    type Connect = unsafe extern "C" fn(i32, *const c_void, i32) -> i32;
    type Close = unsafe extern "C" fn(i32) -> i32;

    let library = unsafe { libloading::Library::new(libsrt_path)? };
    let create_socket: libloading::Symbol<'_, CreateSocket> =
        unsafe { library.get(b"srt_create_socket\0")? };
    let set_sock_opt: libloading::Symbol<'_, SetSockOpt> =
        unsafe { library.get(b"srt_setsockopt\0")? };
    let bind: libloading::Symbol<'_, Bind> = unsafe { library.get(b"srt_bind\0")? };
    let connect: libloading::Symbol<'_, Connect> = unsafe { library.get(b"srt_connect\0")? };
    let close: libloading::Symbol<'_, Close> = unsafe { library.get(b"srt_close\0")? };

    let socket = unsafe { create_socket() };
    require(
        socket >= 0,
        "srt_create_socket failed for bound retry probe",
    )?;
    let attempt = (|| -> HarnessResult<()> {
        let wrong_passphrase = CString::new(WRONG_PASSPHRASE)?;
        let key_length = 16i32;
        let connect_timeout_ms = 1_500i32;
        // SRT 1.5.7 public SRT_SOCKOPT values from srt.h.
        const SRTO_PASSPHRASE: i32 = 26;
        const SRTO_PBKEYLEN: i32 = 27;
        const SRTO_CONNTIMEO: i32 = 36;
        let passphrase_result = unsafe {
            set_sock_opt(
                socket,
                0,
                SRTO_PASSPHRASE,
                wrong_passphrase.as_ptr().cast(),
                WRONG_PASSPHRASE.len() as i32,
            )
        };
        require(
            passphrase_result == 0,
            "srt_setsockopt(SRTO_PASSPHRASE) failed",
        )?;
        let key_result = unsafe {
            set_sock_opt(
                socket,
                0,
                SRTO_PBKEYLEN,
                (&key_length as *const i32).cast(),
                std::mem::size_of::<i32>() as i32,
            )
        };
        require(key_result == 0, "srt_setsockopt(SRTO_PBKEYLEN) failed")?;
        let timeout_result = unsafe {
            set_sock_opt(
                socket,
                0,
                SRTO_CONNTIMEO,
                (&connect_timeout_ms as *const i32).cast(),
                std::mem::size_of::<i32>() as i32,
            )
        };
        require(timeout_result == 0, "srt_setsockopt(SRTO_CONNTIMEO) failed")?;

        let local = ipv4_sockaddr(local_port);
        let bind_result = unsafe {
            bind(
                socket,
                (&local as *const SrtSockAddrIn).cast(),
                std::mem::size_of::<SrtSockAddrIn>() as i32,
            )
        };
        require(
            bind_result == 0,
            format!("srt_bind failed for fixed caller port {local_port}"),
        )?;
        let remote = ipv4_sockaddr(listener_port);
        let connect_result = unsafe {
            connect(
                socket,
                (&remote as *const SrtSockAddrIn).cast(),
                std::mem::size_of::<SrtSockAddrIn>() as i32,
            )
        };
        require(
            connect_result != 0,
            "wrong-passphrase bound caller unexpectedly connected",
        )?;
        Ok(())
    })();
    unsafe {
        close(socket);
    }
    attempt
}

fn events_of<'a>(state: &'a RegistryState, kind: &str) -> Vec<&'a SignalEvent> {
    state
        .events
        .iter()
        .filter(|event| event.kind == kind)
        .collect()
}

fn event_keys(events: &[&SignalEvent]) -> HashSet<String> {
    events
        .iter()
        .filter_map(|event| event.key.clone())
        .collect()
}

#[derive(Debug, Serialize)]
struct AuthenticationGateEvidence {
    unauthenticated_successful_callers: usize,
    caller_connecting_count: usize,
    caller_added_count: usize,
    caller_removed_count: usize,
    callback_requires_authentication: bool,
}

fn test_authentication_gate(
    used_ports: &mut HashSet<u16>,
) -> HarnessResult<AuthenticationGateEvidence> {
    let port = free_udp_port(used_ports)?;
    let listener = Listener::start(port, AdmissionPolicy::open(false), None)?;
    let client = Client::start(port, None, None)?;
    require(
        !client.startup_failed,
        "authentication=false client failed to start",
    )?;
    wait_for_registry(&listener, "authentication=false caller-added", |state| {
        state.active.len() == 1
    })?;
    client.stop();
    let snapshot = wait_for_registry(&listener, "authentication=false caller-removed", |state| {
        events_of(state, "caller-removed").len() == 1 && state.active.is_empty()
    })?;
    listener.stop();

    let connecting = events_of(&snapshot, "caller-connecting").len();
    let added = events_of(&snapshot, "caller-added").len();
    let removed = events_of(&snapshot, "caller-removed").len();
    require(
        connecting == 0,
        "caller-connecting fired with authentication=false",
    )?;
    require(
        added == 1 && removed == 1,
        "unauthenticated caller lifecycle was incomplete",
    )?;
    require(
        snapshot.faults.is_empty(),
        "authentication gate registry faulted",
    )?;
    Ok(AuthenticationGateEvidence {
        unauthenticated_successful_callers: 1,
        caller_connecting_count: connecting,
        caller_added_count: added,
        caller_removed_count: removed,
        callback_requires_authentication: true,
    })
}

#[derive(Debug, Serialize)]
struct RejectionEvidence {
    connecting_decision: &'static str,
    caller_rejected_signals: usize,
    caller_added_signals: usize,
    client_failed: bool,
    false_return_prevented_add: bool,
}

fn test_application_rejection(used_ports: &mut HashSet<u16>) -> HarnessResult<RejectionEvidence> {
    let port = free_udp_port(used_ports)?;
    let mut policy = AdmissionPolicy::open(true);
    policy.reject_all = true;
    let listener = Listener::start(port, policy, None)?;
    let client = Client::start(port, None, None)?;
    let snapshot = wait_for_registry(&listener, "application caller rejection", |state| {
        state.application_rejections >= 1 && state.rejection_signals >= 1
    })?;
    let client_failed = client.wait_for_failure(Duration::from_secs(2));
    client.stop();
    listener.stop();
    let added = events_of(&snapshot, "caller-added").len();
    require(
        added == 0,
        "a callback false return still produced caller-added",
    )?;
    require(client_failed, "application-rejected caller did not fail")?;
    require(
        snapshot.events.iter().any(|event| {
            event.kind == "caller-connecting" && event.decision == Some("rejected-policy")
        }),
        "application rejection decision was not observed",
    )?;
    Ok(RejectionEvidence {
        connecting_decision: "false",
        caller_rejected_signals: snapshot.rejection_signals,
        caller_added_signals: added,
        client_failed,
        false_return_prevented_add: true,
    })
}

#[derive(Debug, Serialize)]
struct SuccessfulLifecycleEvidence {
    ordering: Vec<&'static str>,
    caller_added_unused_values: Vec<i32>,
    caller_removed_unused_values: Vec<i32>,
    canonical_key_format: &'static str,
    canonical_key_equal_across_signals: bool,
    stream_id_utf8_bytes: usize,
    stream_id_delivered_byte_for_byte: bool,
    active_after_removal: usize,
}

fn test_successful_lifecycle(
    used_ports: &mut HashSet<u16>,
) -> HarnessResult<SuccessfulLifecycleEvidence> {
    let port = free_udp_port(used_ports)?;
    let mut policy = AdmissionPolicy::open(true);
    policy.expected_stream_id = Some(TEST_STREAM_ID.as_bytes().to_vec());
    let listener = Listener::start(port, policy, None)?;
    let client = Client::start(port, None, Some(TEST_STREAM_ID))?;
    require(
        !client.startup_failed,
        "successful Stream ID client failed to start",
    )?;
    wait_for_registry(&listener, "successful caller-added", |state| {
        state.active.len() == 1
    })?;
    client.stop();
    let snapshot = wait_for_registry(&listener, "successful caller-removed", |state| {
        state.active.is_empty() && !events_of(state, "caller-removed").is_empty()
    })?;
    listener.stop();

    let connecting = events_of(&snapshot, "caller-connecting");
    let added = events_of(&snapshot, "caller-added");
    let removed = events_of(&snapshot, "caller-removed");
    require(
        !connecting.is_empty(),
        "authentication=true did not fire caller-connecting",
    )?;
    require(
        added.len() == 1 && removed.len() == 1,
        "successful lifecycle signal counts differ",
    )?;
    let connecting_key = connecting[0]
        .key
        .as_ref()
        .ok_or_else(|| HarnessError("caller-connecting had no canonical key".to_owned()))?;
    require(
        connecting_key.starts_with("127.0.0.1:") && connecting_key.rsplit(':').next().is_some(),
        format!("unexpected canonical loopback key format: {connecting_key}"),
    )?;
    let all_keys = connecting
        .iter()
        .chain(added.iter())
        .chain(removed.iter())
        .filter_map(|event| event.key.as_ref())
        .all(|key| key == connecting_key);
    require(
        all_keys,
        "canonical address key changed across successful lifecycle",
    )?;
    require(
        connecting
            .iter()
            .all(|event| event.stream_id.as_slice() == TEST_STREAM_ID.as_bytes()),
        "Stream ID bytes changed in caller-connecting",
    )?;
    let first_connecting = connecting[0].sequence;
    let first_added = added[0].sequence;
    let first_removed = removed[0].sequence;
    require(
        first_connecting < first_added && first_added < first_removed,
        "successful caller signals were out of order",
    )?;
    let added_unused: Vec<i32> = added.iter().filter_map(|event| event.unused).collect();
    let removed_unused: Vec<i32> = removed.iter().filter_map(|event| event.unused).collect();
    require(
        added_unused == vec![0],
        "caller-added ABI argument was not exactly zero",
    )?;
    require(
        removed_unused == vec![0],
        "caller-removed ABI argument was not exactly zero",
    )?;

    Ok(SuccessfulLifecycleEvidence {
        ordering: vec!["caller-connecting", "caller-added", "caller-removed"],
        caller_added_unused_values: added_unused,
        caller_removed_unused_values: removed_unused,
        canonical_key_format: "IP-plus-UDP-port",
        canonical_key_equal_across_signals: true,
        stream_id_utf8_bytes: TEST_STREAM_ID.len(),
        stream_id_delivered_byte_for_byte: true,
        active_after_removal: snapshot.active.len(),
    })
}

#[derive(Debug, Serialize)]
struct PasswordFailureEvidence {
    wrong_passphrase_client_failed: bool,
    missing_passphrase_client_failed: bool,
    application_rejections_for_library_failures: usize,
    caller_rejected_signals_for_library_failures: usize,
    active_during_library_failures: usize,
    pending_before_expiry: usize,
    repeated_same_key_refreshes: usize,
    expired_on_next_admission: usize,
    correct_passphrase_active_after_expiry: usize,
    active_after_removal: usize,
}

fn test_password_failures_and_ttl(
    used_ports: &mut HashSet<u16>,
    libsrt_path: &Path,
) -> HarnessResult<PasswordFailureEvidence> {
    let port = free_udp_port(used_ports)?;
    let listener = Listener::start(port, AdmissionPolicy::open(true), Some(TEST_PASSPHRASE))?;

    let before_wrong = listener.snapshot().events.len();
    let wrong = Client::start(port, Some(WRONG_PASSPHRASE), None)?;
    wait_for_registry(&listener, "wrong-passphrase caller-connecting", |state| {
        events_of(state, "caller-connecting").len() > before_wrong
    })?;
    let wrong_failed = wrong.wait_for_failure(CALLBACK_TIMEOUT);
    wrong.stop();
    require(
        wrong_failed,
        "wrong-passphrase caller did not fail in libsrt",
    )?;

    let before_missing = events_of(&listener.snapshot(), "caller-connecting").len();
    let missing = Client::start(port, None, None)?;
    wait_for_registry(&listener, "missing-passphrase caller-connecting", |state| {
        events_of(state, "caller-connecting").len() > before_missing
    })?;
    let missing_failed = missing.wait_for_failure(CALLBACK_TIMEOUT);
    missing.stop();
    require(
        missing_failed,
        "missing-passphrase caller did not fail in libsrt",
    )?;

    // Two deliberately failed handshakes from the same explicitly bound
    // remote UDP socket prove that the second callback refreshes one pending
    // reservation instead of consuming another slot.
    let repeated_port = free_udp_port(used_ports)?;
    let before_repeat = events_of(&listener.snapshot(), "caller-connecting").len();
    run_bound_wrong_handshake(libsrt_path, repeated_port, port)?;
    let after_first = wait_for_registry(&listener, "first fixed-port failed handshake", |state| {
        events_of(state, "caller-connecting").len() > before_repeat
    })?;
    let after_first_count = events_of(&after_first, "caller-connecting").len();
    thread::sleep(Duration::from_millis(150));
    run_bound_wrong_handshake(libsrt_path, repeated_port, port)?;
    let after_second =
        wait_for_registry(&listener, "repeated fixed-port failed handshake", |state| {
            events_of(state, "caller-connecting").len() > after_first_count
        })?;
    let repeated_events: Vec<&SignalEvent> = events_of(&after_second, "caller-connecting")
        .into_iter()
        .filter(|event| {
            event.sequence > after_first.events.last().map_or(0, |event| event.sequence)
        })
        .collect();
    require(
        repeated_events
            .iter()
            .any(|event| event.decision == Some("accepted-refresh")),
        "second fixed-port handshake did not refresh its pending reservation",
    )?;

    let failed_snapshot = listener.snapshot();
    let connecting = events_of(&failed_snapshot, "caller-connecting");
    let failed_keys = event_keys(&connecting);
    let rejected_keys = event_keys(&events_of(&failed_snapshot, "caller-rejected"));
    require(
        failed_snapshot.application_rejections == 0,
        "wrong or missing passphrase was attributed to an application rejection",
    )?;
    require(
        failed_keys.is_disjoint(&rejected_keys),
        "wrong or missing passphrase emitted caller-rejected",
    )?;
    require(
        failed_snapshot.active.is_empty(),
        "wrong or missing passphrase produced an active caller",
    )?;
    require(
        failed_snapshot.pending.len() >= 2,
        "failed handshakes did not leave distinct pending reservations",
    )?;
    require(
        failed_snapshot.refreshed_reservations > 0,
        "no repeated handshake refreshed an existing remote-socket reservation",
    )?;

    let pending_before_expiry = failed_snapshot.pending.len();
    let refreshes = failed_snapshot.refreshed_reservations;
    thread::sleep(PENDING_TTL + Duration::from_millis(750));

    let correct = Client::start(port, Some(TEST_PASSPHRASE), None)?;
    require(
        !correct.startup_failed,
        "correct-passphrase caller failed to start",
    )?;
    let active_snapshot =
        wait_for_registry(&listener, "post-expiry correct caller-added", |state| {
            state.active.len() == 1
        })?;
    require(
        active_snapshot.expired_reservations >= pending_before_expiry,
        "expired failed-handshake reservations were not pruned on admission",
    )?;
    require(
        active_snapshot.pending.is_empty(),
        "successful caller did not atomically move pending to active",
    )?;
    correct.stop();
    let final_snapshot = wait_for_registry(&listener, "post-expiry caller removal", |state| {
        state.active.is_empty() && !events_of(state, "caller-removed").is_empty()
    })?;
    listener.stop();

    Ok(PasswordFailureEvidence {
        wrong_passphrase_client_failed: wrong_failed,
        missing_passphrase_client_failed: missing_failed,
        application_rejections_for_library_failures: 0,
        caller_rejected_signals_for_library_failures: 0,
        active_during_library_failures: failed_snapshot.active.len(),
        pending_before_expiry,
        repeated_same_key_refreshes: refreshes,
        expired_on_next_admission: active_snapshot.expired_reservations,
        correct_passphrase_active_after_expiry: active_snapshot.active.len(),
        active_after_removal: final_snapshot.active.len(),
    })
}

#[derive(Debug, Serialize)]
struct CapacityEvidence {
    simultaneous_attempts: usize,
    admitted_before_cap: usize,
    eleventh_application_rejected: bool,
    eleventh_caller_rejected_signal: bool,
    maximum_pending_plus_active: usize,
    active_at_cap: usize,
    slot_reused_after_removal: bool,
    active_after_teardown: usize,
}

fn test_capacity(used_ports: &mut HashSet<u16>) -> HarnessResult<CapacityEvidence> {
    let port = free_udp_port(used_ports)?;
    let listener = Listener::start(port, AdmissionPolicy::open(true), None)?;
    let mut clients = Vec::new();
    for expected_active in 1..=CLIENT_LIMIT {
        let client = Client::start(port, None, None)?;
        require(
            !client.startup_failed,
            format!("caller {expected_active} failed to start"),
        )?;
        wait_for_registry(&listener, "capacity caller-added", |state| {
            state.active.len() == expected_active
        })?;
        clients.push(client);
    }

    let rejected_before = listener.snapshot().application_rejections;
    let eleventh = Client::start(port, None, None)?;
    let capped = wait_for_registry(&listener, "eleventh caller capacity rejection", |state| {
        state.application_rejections > rejected_before && state.rejection_signals >= 1
    })?;
    let eleventh_failed = eleventh.wait_for_failure(Duration::from_secs(2));
    eleventh.stop();
    require(
        eleventh_failed,
        "eleventh caller did not fail after capacity rejection",
    )?;
    require(
        capped.active.len() == CLIENT_LIMIT,
        "capacity rejection changed active count",
    )?;
    require(
        capped.pending.is_empty(),
        "capacity test retained unexpected pending callers",
    )?;
    require(
        capped.max_occupancy == CLIENT_LIMIT,
        format!(
            "maximum occupancy was {}, not {CLIENT_LIMIT}",
            capped.max_occupancy
        ),
    )?;

    clients[0].stop();
    wait_for_registry(&listener, "capacity slot removal", |state| {
        state.active.len() == CLIENT_LIMIT - 1
    })?;
    let replacement = Client::start(port, None, None)?;
    require(
        !replacement.startup_failed,
        "replacement caller failed to start",
    )?;
    wait_for_registry(&listener, "capacity slot reuse", |state| {
        state.active.len() == CLIENT_LIMIT
    })?;

    for client in clients.iter().skip(1) {
        client.stop();
    }
    replacement.stop();
    let final_snapshot = wait_for_registry(&listener, "capacity teardown", |state| {
        state.active.is_empty()
    })?;
    listener.stop();
    require(
        final_snapshot.faults.is_empty(),
        "capacity registry faulted",
    )?;

    Ok(CapacityEvidence {
        simultaneous_attempts: CLIENT_LIMIT + 1,
        admitted_before_cap: CLIENT_LIMIT,
        eleventh_application_rejected: true,
        eleventh_caller_rejected_signal: true,
        maximum_pending_plus_active: final_snapshot.max_occupancy,
        active_at_cap: capped.active.len(),
        slot_reused_after_removal: true,
        active_after_teardown: final_snapshot.active.len(),
    })
}

#[derive(Debug, Serialize)]
struct RuntimeEvidence {
    gstreamer_version: String,
    srt_plugin_version: String,
    srt_plugin_filename: String,
    srt_getversion_hex: String,
    isolated_plugin_negative_control: &'static str,
    required_elements: Vec<&'static str>,
}

fn inspect_runtime(libsrt_path: &Path) -> HarnessResult<RuntimeEvidence> {
    let srt_version = unsafe {
        let library = libloading::Library::new(libsrt_path)?;
        let get_version: libloading::Symbol<'_, unsafe extern "C" fn() -> u32> =
            library.get(b"srt_getversion\0")?;
        get_version()
    };
    require(
        srt_version == EXPECTED_SRT_VERSION,
        format!(
            "staged srt_getversion returned 0x{srt_version:06X}, expected 0x{EXPECTED_SRT_VERSION:06X}"
        ),
    )?;

    gst::init()?;
    let gstreamer_version = gst::version_string().to_string();
    require(
        gstreamer_version.contains("1.26.11"),
        format!("GStreamer runtime is not 1.26.11: {gstreamer_version}"),
    )?;
    require(
        gst::ElementFactory::find("opusdec").is_none(),
        "plugin isolation failed: non-bundled opusdec is visible",
    )?;
    let required_elements = vec!["fakesrc", "queue", "fakesink", "srtsink", "srtsrc"];
    for element in &required_elements {
        require(
            gst::ElementFactory::find(element).is_some(),
            format!("isolated runtime is missing {element}"),
        )?;
    }
    let factory = gst::ElementFactory::find("srtsink")
        .ok_or_else(|| HarnessError("srtsink factory disappeared".to_owned()))?;
    let plugin = factory
        .plugin()
        .ok_or_else(|| HarnessError("srtsink factory has no plugin".to_owned()))?;
    let plugin_filename = plugin
        .filename()
        .ok_or_else(|| HarnessError("SRT plugin has no filename".to_owned()))?;

    Ok(RuntimeEvidence {
        gstreamer_version,
        srt_plugin_version: plugin.version().to_string(),
        srt_plugin_filename: plugin_filename.to_string_lossy().into_owned(),
        srt_getversion_hex: format!("0x{srt_version:06X}"),
        isolated_plugin_negative_control: "opusdec absent",
        required_elements,
    })
}

#[derive(Debug, Serialize)]
struct HarnessConstants {
    client_limit: usize,
    pending_ttl_seconds: u64,
    canonical_remote_identity: &'static str,
}

#[derive(Debug, Serialize)]
struct ScenarioEvidence {
    authentication_gate: AuthenticationGateEvidence,
    application_rejection: RejectionEvidence,
    successful_lifecycle: SuccessfulLifecycleEvidence,
    password_failures_and_pending_ttl: PasswordFailureEvidence,
    strict_capacity: CapacityEvidence,
}

#[derive(Debug, Serialize)]
struct HarnessReport {
    schema_version: u32,
    harness: &'static str,
    result: &'static str,
    runtime: RuntimeEvidence,
    constants: HarnessConstants,
    scenarios: ScenarioEvidence,
}

fn parse_arguments() -> HarnessResult<(PathBuf, PathBuf)> {
    let mut arguments = env::args_os().skip(1);
    let mut libsrt = None;
    let mut output = None;
    while let Some(argument) = arguments.next() {
        match argument.to_string_lossy().as_ref() {
            "--libsrt" => libsrt = arguments.next().map(PathBuf::from),
            "--output" => output = arguments.next().map(PathBuf::from),
            other => return fail(format!("unknown or incomplete argument: {other}")),
        }
    }
    let libsrt = libsrt.ok_or_else(|| HarnessError("--libsrt is required".to_owned()))?;
    let output = output.ok_or_else(|| HarnessError("--output is required".to_owned()))?;
    require(
        libsrt.is_file(),
        format!("libsrt DLL is missing: {}", libsrt.display()),
    )?;
    Ok((libsrt, output))
}

fn run() -> HarnessResult<()> {
    let (libsrt_path, output_path) = parse_arguments()?;
    let runtime = inspect_runtime(&libsrt_path)?;
    let mut used_ports = HashSet::new();
    let scenarios = ScenarioEvidence {
        authentication_gate: test_authentication_gate(&mut used_ports)?,
        application_rejection: test_application_rejection(&mut used_ports)?,
        successful_lifecycle: test_successful_lifecycle(&mut used_ports)?,
        password_failures_and_pending_ttl: test_password_failures_and_ttl(
            &mut used_ports,
            &libsrt_path,
        )?,
        strict_capacity: test_capacity(&mut used_ports)?,
    };
    let report = HarnessReport {
        schema_version: 1,
        harness: "g2_srt_admission",
        result: "pass",
        runtime,
        constants: HarnessConstants {
            client_limit: CLIENT_LIMIT,
            pending_ttl_seconds: PENDING_TTL.as_secs(),
            canonical_remote_identity: "IP address plus UDP port",
        },
        scenarios,
    };
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("G2 admission harness failed: {error}");
        std::process::exit(1);
    }
}
