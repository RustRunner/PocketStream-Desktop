//! PacketMonitor (PktMon) realtime-capture FFI — the OS-native capture
//! backend for ARP discovery.
//!
//! `PktMonApi.dll` ships in-box on modern Windows (WS2022/Win11-era;
//! the driver is `PktMon.sys`). Microsoft documents the `PacketMonitor*`
//! function family but publishes **no SDK header or import library by
//! design** — the documented usage is `LoadLibrary`/`GetProcAddress`,
//! which is what this module does (via `libloading`). Consequently a
//! handful of layout constants are not expressible from any header and
//! were pinned empirically on real hardware (Win11 26200); each such
//! constant is marked below. Two mitigations back them:
//! - descriptor offsets are always honored, never assumed, and
//! - [`metadata_plausible`] is a cheap per-session canary that flags a
//!   future layout change in the logs instead of silently misparsing.
//!
//! Capture flow (all HRESULT-checked except teardown):
//! Initialize → CreateLiveSession → AddCaptureConstraint(EtherType=ARP)
//! → CreateRealtimeStream(callbacks) → AttachOutputToSession →
//! SetSessionActive(TRUE) … DataCallback per packet … then
//! SetSessionActive(FALSE) → CloseRealtimeStream → CloseSessionHandle →
//! Uninitialize. The `Close*`/`Uninitialize` returns are garbage on
//! real systems while behavior is correct — they are treated as void.
//!
//! Sessions are process-owned kernel handles: process death tears them
//! down, multiple sessions coexist (including an external `pktmon.exe`
//! capture), and there is no stale-named-session recovery path to
//! implement.

use std::ffi::c_void;

/// PACKETMONITOR_API_VERSION_1_0 — the version handshake value for
/// `PacketMonitorInitialize`.
pub const API_VERSION_1_0: u32 = 0x0001_0000;

type Hresult = i32;
type PmHandle = *mut c_void;

// ── Documented structs ──────────────────────────────────────────────

/// `PACKETMONITOR_STREAM_DATA_DESCRIPTOR` — documented contract; one is
/// passed to the data callback per captured packet. Frame bytes are
/// `data[packet_offset .. packet_offset + packet_length]`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct StreamDataDescriptor {
    pub data: *const u8,
    pub data_size: u32,
    pub metadata_offset: u32,
    pub packet_offset: u32,
    pub packet_length: u32,
    pub missed_packet_write_count: u32,
    pub missed_packet_read_count: u32,
}

/// `PACKETMONITOR_STREAM_METADATA` — documented field list, but the
/// layout is **empirically pinned as packed, 40 bytes** (natural MSVC
/// alignment of the same fields would be 48). Confirmed on hardware by
/// `PacketOffset == 40` on every metadata-first event and a
/// FILETIME-magnitude timestamp at offset 32. Do not "fix" this to a
/// natural `#[repr(C)]` layout — DropReason and later fields would read
/// garbage.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct StreamMetadata {
    pub pkt_group_id: u64,     // @0  (distinct per appearance — does NOT group)
    pub pkt_count: u16,        // @8
    pub appearance_count: u16, // @10
    pub direction_name: u16,   // @12
    pub packet_type: u16,      // @14 (1=Ethernet, 2=WiFi, 7=ARP-direct)
    pub component_id: u16,     // @16 (per-box diagnostics, never logic input)
    pub edge_id: u16,          // @18
    pub reserved: u16,         // @20
    pub drop_reason: u32,      // @22 (unaligned — hence packed)
    pub drop_location: u32,    // @26
    pub processor: u16,        // @30
    pub timestamp: i64,        // @32 FILETIME; total size 40
}

/// `PACKETMONITOR_REALTIME_STREAM_CONFIGURATION`.
///
/// `buffer_size_multiplier` scales the shared ring buffer (4 ⇒ 1 MB —
/// zero losses at ~2,000 pkt/s on hardware). `truncation_size` caps
/// bytes per packet (ARP needs 42; 128 leaves headroom).
#[repr(C)]
pub struct RealtimeStreamConfiguration {
    pub user_context: *mut c_void,
    pub event_callback: Option<unsafe extern "system" fn(*mut c_void, *const c_void, u32)>,
    pub data_callback: Option<unsafe extern "system" fn(*mut c_void, *const StreamDataDescriptor)>,
    pub buffer_size_multiplier: u16,
    pub truncation_size: u16,
}

// ── Capture constraint (empirically pinned) ─────────────────────────

/// `PACKETMONITOR_PROTOCOL_CONSTRAINT` total size:
/// `align8(2*64 (Name WCHARs) + 88)` = 216 bytes.
pub const CONSTRAINT_SIZE: usize = 216;
/// `IsPresentValue` (u32 bitfield) offset — which fields of the
/// constraint are active.
const CONSTRAINT_IS_PRESENT_OFFSET: usize = 128;
/// Bit 3 of IsPresentValue = "EtherType is present".
const IS_PRESENT_ETHERTYPE_BIT: u32 = 1 << 3;
/// EtherType u16 offset. **Host byte order** — 0x0806 matches ARP;
/// the byte-swapped 0x0608 was verified to match nothing.
const CONSTRAINT_ETHERTYPE_OFFSET: usize = 146;
/// ARP EtherType, host order as the constraint expects it.
pub const ETHERTYPE_ARP: u16 = 0x0806;

/// Build the in-driver ARP filter constraint. Name left zeroed (valid).
/// Functionally equivalent to the old BPF `filter("arp")`: on hardware
/// it reduced a 16,199-packet flood to the 16 ARP frames within it.
pub fn build_arp_constraint() -> [u8; CONSTRAINT_SIZE] {
    let mut c = [0u8; CONSTRAINT_SIZE];
    c[CONSTRAINT_IS_PRESENT_OFFSET..CONSTRAINT_IS_PRESENT_OFFSET + 4]
        .copy_from_slice(&IS_PRESENT_ETHERTYPE_BIT.to_le_bytes());
    c[CONSTRAINT_ETHERTYPE_OFFSET..CONSTRAINT_ETHERTYPE_OFFSET + 2]
        .copy_from_slice(&ETHERTYPE_ARP.to_le_bytes());
    c
}

// ── Metadata helpers ────────────────────────────────────────────────

/// Read the packed metadata out of a callback blob. Honors the
/// descriptor's offset rather than assuming metadata-first.
pub fn read_metadata(blob: &[u8], metadata_offset: usize) -> Option<StreamMetadata> {
    if blob.len() < metadata_offset.checked_add(std::mem::size_of::<StreamMetadata>())? {
        return None;
    }
    // SAFETY: bounds checked above; read_unaligned because the struct
    // is packed and the blob offset carries no alignment guarantee.
    Some(unsafe {
        std::ptr::read_unaligned(blob.as_ptr().add(metadata_offset) as *const StreamMetadata)
    })
}

/// Cheap canary for a future metadata-layout change: the documented
/// enums are small, so implausible values mean the pinned offsets no
/// longer hold on this Windows build. Log it (once per session) —
/// never gate behavior on it.
pub fn metadata_plausible(m: &StreamMetadata) -> bool {
    let packet_type = m.packet_type;
    let direction = m.direction_name;
    packet_type <= 11 && direction <= 6
}

// ── API loading (tier-0 probe) ──────────────────────────────────────

/// Every documented `PacketMonitor*` export. Tier-0 availability means
/// ALL of these resolve — a partial surface is treated as unavailable
/// (the expected shape on pre-API Windows builds is the DLL or the
/// whole family missing).
const REQUIRED_EXPORTS: [&[u8]; 11] = [
    b"PacketMonitorInitialize",
    b"PacketMonitorUninitialize",
    b"PacketMonitorCreateLiveSession",
    b"PacketMonitorCloseSessionHandle",
    b"PacketMonitorEnumDataSources",
    b"PacketMonitorAddSingleDataSourceToSession",
    b"PacketMonitorAddCaptureConstraint",
    b"PacketMonitorCreateRealtimeStream",
    b"PacketMonitorAttachOutputToSession",
    b"PacketMonitorCloseRealtimeStream",
    b"PacketMonitorSetSessionActive",
];

/// Resolved API surface. Holds the `Library` so the function pointers
/// stay valid for the struct's lifetime. Capture is scoped at attach
/// time to the selected wired adapter's data source; the reason a WiFi
/// source is never attached is that a WiFi-scoped capture yields
/// native-802.11 framing, unparseable as Ethernet II — the unscoped
/// fallback (plus the per-frame filters) covers that case instead.
pub struct PktMonApi {
    _lib: libloading::Library,
    initialize: unsafe extern "system" fn(u32, *mut c_void, *mut PmHandle) -> Hresult,
    uninitialize: unsafe extern "system" fn(PmHandle) -> Hresult,
    create_live_session: unsafe extern "system" fn(PmHandle, *const u16, *mut PmHandle) -> Hresult,
    close_session_handle: unsafe extern "system" fn(PmHandle) -> Hresult,
    enum_data_sources:
        unsafe extern "system" fn(PmHandle, u32, u8, usize, *mut usize, *mut u8) -> Hresult,
    add_single_data_source: unsafe extern "system" fn(PmHandle, *const u8) -> Hresult,
    add_capture_constraint: unsafe extern "system" fn(PmHandle, *const u8) -> Hresult,
    create_realtime_stream: unsafe extern "system" fn(
        PmHandle,
        *const RealtimeStreamConfiguration,
        *mut PmHandle,
    ) -> Hresult,
    attach_output_to_session: unsafe extern "system" fn(PmHandle, PmHandle) -> Hresult,
    close_realtime_stream: unsafe extern "system" fn(PmHandle) -> Hresult,
    set_session_active: unsafe extern "system" fn(PmHandle, u8) -> Hresult,
}

impl PktMonApi {
    /// Load the DLL and resolve the full export surface (tier 0).
    /// The error string names exactly what was missing — that line is
    /// the key field diagnostic for the Windows-floor question.
    pub fn load() -> Result<Self, String> {
        unsafe {
            let lib = libloading::Library::new("PktMonApi.dll")
                .map_err(|e| format!("PktMonApi.dll did not load: {e}"))?;

            for name in REQUIRED_EXPORTS {
                if lib.get::<*mut c_void>(name).is_err() {
                    return Err(format!(
                        "PktMonApi.dll is missing export {}",
                        String::from_utf8_lossy(name)
                    ));
                }
            }

            macro_rules! sym {
                ($name:literal) => {
                    // Presence was verified above; resolve to the raw fn
                    // pointer (valid as long as `lib` lives, which the
                    // struct guarantees).
                    *lib.get($name)
                        .map_err(|e| format!("resolving {}: {e}", String::from_utf8_lossy($name)))?
                };
            }

            Ok(Self {
                initialize: sym!(b"PacketMonitorInitialize"),
                uninitialize: sym!(b"PacketMonitorUninitialize"),
                create_live_session: sym!(b"PacketMonitorCreateLiveSession"),
                close_session_handle: sym!(b"PacketMonitorCloseSessionHandle"),
                enum_data_sources: sym!(b"PacketMonitorEnumDataSources"),
                add_single_data_source: sym!(b"PacketMonitorAddSingleDataSourceToSession"),
                add_capture_constraint: sym!(b"PacketMonitorAddCaptureConstraint"),
                create_realtime_stream: sym!(b"PacketMonitorCreateRealtimeStream"),
                attach_output_to_session: sym!(b"PacketMonitorAttachOutputToSession"),
                close_realtime_stream: sym!(b"PacketMonitorCloseRealtimeStream"),
                set_session_active: sym!(b"PacketMonitorSetSessionActive"),
                _lib: lib,
            })
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ── Data-source scoping ─────────────────────────────────────────────

/// `PacketMonitorDataSourceKindNetworkInterface`.
pub const DATA_SOURCE_KIND_NETWORK_INTERFACE: u32 = 1;
/// Size of one data-source specification, verified against live
/// enumeration output (consecutive in-buffer entries are exactly this
/// far apart).
pub const DATA_SOURCE_SPEC_SIZE: usize = 424;
/// The list buffer: `u32` count at offset 0, then the pointer array.
const DATA_SOURCE_LIST_PTRS_OFFSET: usize = 8;
/// Sanity ceiling for the enumeration buffer — a machine has dozens of
/// adapters at most, never megabytes of them.
const DATA_SOURCE_ENUM_MAX_BYTES: usize = 4 * 1024 * 1024;

/// `PACKETMONITOR_DATA_SOURCE_SPECIFICATION`, hardware-verified layout.
/// For network-interface sources the adapter MAC sits at `detail[0..6]`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DataSourceSpecification {
    pub kind: u32,               // 0
    pub name: [u16; 64],         // 4   — driver binary name, e.g. "e1dn.sys"
    pub description: [u16; 128], // 132 — driver display string
    pub id: u32,                 // 388
    pub secondary_id: u32,       // 392
    pub parent_id: u32,          // 396
    pub is_present: i32,         // 400 — flag-bearing BOOL: 8/9 observed, never 1
    _pad: u32,                   // 404
    pub detail: [u8; 16],        // 408 — union; MAC at [0..6] for NIC kind
}

/// One parsed data source, carrying its byte offset inside the
/// enumeration buffer — `PacketMonitorAddSingleDataSourceToSession`
/// must receive the original in-buffer entry pointer, so the offset is
/// the identity that survives parsing.
pub struct DataSourceEntry {
    pub offset: usize,
    pub name: String,
    pub description: String,
    pub id: u32,
    pub is_present: bool,
    /// `detail[0..6]`; `None` when all-zero.
    pub mac: Option<[u8; 6]>,
}

/// Decode a NUL-terminated UTF-16 field.
fn utf16_z(a: &[u16]) -> String {
    let end = a.iter().position(|&c| c == 0).unwrap_or(a.len());
    String::from_utf16_lossy(&a[..end])
}

/// Parse a `PACKETMONITOR_DATA_SOURCE_LIST` buffer: count at offset 0,
/// pointer array at offset 8, each pointer an absolute address inside
/// the buffer itself. Every pointer is resolved against the buffer's
/// own base and bounds-checked for a full entry; ANY violation fails
/// the whole parse — a partial list must never be scoped to, the
/// caller falls back to an unscoped session instead.
pub fn parse_data_source_list(buf: &[u8]) -> Result<Vec<DataSourceEntry>, String> {
    if buf.len() < DATA_SOURCE_LIST_PTRS_OFFSET {
        return Err(format!("data-source list too small: {} bytes", buf.len()));
    }
    let count = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    let ptr_end = count
        .checked_mul(8)
        .and_then(|n| n.checked_add(DATA_SOURCE_LIST_PTRS_OFFSET))
        .ok_or("data-source count overflows")?;
    if buf.len() < ptr_end {
        return Err(format!(
            "data-source pointer array truncated: {count} entries need {ptr_end} bytes, have {}",
            buf.len()
        ));
    }
    let base = buf.as_ptr() as usize;
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let slot = DATA_SOURCE_LIST_PTRS_OFFSET + i * 8;
        let p = usize::from_le_bytes(buf[slot..slot + 8].try_into().unwrap());
        let end = p
            .checked_add(DATA_SOURCE_SPEC_SIZE)
            .ok_or("data-source entry pointer overflows")?;
        if p < base || end > base + buf.len() {
            return Err(format!(
                "data-source entry {i} pointer 0x{p:X} outside its buffer (base 0x{base:X}, len {})",
                buf.len()
            ));
        }
        let off = p - base;
        // SAFETY: bounds checked above; read_unaligned because in-buffer
        // entries carry no alignment guarantee.
        let spec = unsafe {
            std::ptr::read_unaligned(buf.as_ptr().add(off) as *const DataSourceSpecification)
        };
        let mac: [u8; 6] = spec.detail[0..6].try_into().unwrap();
        entries.push(DataSourceEntry {
            offset: off,
            name: utf16_z(&spec.name),
            description: utf16_z(&spec.description),
            id: spec.id,
            is_present: spec.is_present != 0,
            mac: if mac == [0u8; 6] { None } else { Some(mac) },
        });
    }
    Ok(entries)
}

/// Identity of the selected wired adapter for attach-time scoping. MAC
/// is the join key — it is the only machine identity present in both
/// the data source (`detail[0..6]`) and the adapter info the discovery
/// path already resolves; no GUID exists in the enumeration output.
/// `display_name` anchors log lines only.
#[derive(Clone)]
pub struct CaptureScope {
    pub mac: Option<[u8; 6]>,
    pub display_name: String,
}

/// How the caller wants the session scoped. `PreferScoped` preserves the
/// long-standing behavior — scoped attach with the automatic unscoped
/// fallback on scope-join failure; the mode split does not remove that
/// fallback. `ForcedUnscoped` demands unscoped from the outset, for a
/// caller escalating past a scoped session that proved deaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    PreferScoped,
    ForcedUnscoped,
}

/// How the session ended up scoped — logged exactly once per start.
pub enum ScopeOutcome {
    /// Scoped to the selected adapter's data source. The id is what the
    /// join bound — recorded so a later liveness probe can detect the
    /// source being re-created (id churn) under a persistent listener.
    SelectedInterface {
        source_id: Option<u32>,
    },
    UnscopedFallback {
        reason: String,
    },
}

/// Why the join produced no scoped source.
#[derive(Debug, PartialEq, Eq)]
pub enum JoinFailure {
    NoIdentity,
    NoMatch,
    Ambiguous(usize),
}

impl std::fmt::Display for JoinFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JoinFailure::NoIdentity => {
                write!(
                    f,
                    "selected adapter has no usable MAC to match a capture source"
                )
            }
            JoinFailure::NoMatch => {
                write!(
                    f,
                    "no present capture source matched the selected adapter's MAC"
                )
            }
            JoinFailure::Ambiguous(n) => {
                write!(
                    f,
                    "{n} capture sources matched the selected adapter's MAC (ambiguous)"
                )
            }
        }
    }
}

/// Pure join: exactly one present, MAC-matching source or a failure the
/// caller converts into the unscoped fallback. Never picks "closest",
/// never more than one. `is_present` is a flag-bearing BOOL on real
/// hardware (values 8 and 9 observed), so presence means nonzero.
pub fn select_scoped_source(
    entries: &[DataSourceEntry],
    scope: &CaptureScope,
) -> Result<usize, JoinFailure> {
    let mac = scope.mac.ok_or(JoinFailure::NoIdentity)?;
    let matches: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.is_present && e.mac == Some(mac))
        .map(|(i, _)| i)
        .collect();
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(JoinFailure::NoMatch),
        n => Err(JoinFailure::Ambiguous(n)),
    }
}

// ── Availability probe ──────────────────────────────────────────────

/// Two-tier, capability-based availability probe.
///
/// Tier 0 — presence: the DLL loads and all 11 exports resolve.
/// Tier 1 — do the thing: `PacketMonitorInitialize` and
/// `PacketMonitorCreateLiveSession` succeed (immediate teardown).
///
/// The error string carries the real failure (missing export or live
/// HRESULT) for the log line; static facts like the Windows build
/// number are the caller's to log as diagnostics — they are never the
/// gate. Requires elevation, which the app always has.
///
/// Called only from the Windows startup path; on other targets it is
/// unreferenced (the module still compiles so the layout tests run).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn probe() -> Result<(), String> {
    let api = PktMonApi::load()?;
    unsafe {
        let mut handle: PmHandle = std::ptr::null_mut();
        let hr = (api.initialize)(API_VERSION_1_0, std::ptr::null_mut(), &mut handle);
        if hr != 0 {
            return Err(format!(
                "PacketMonitorInitialize failed: HRESULT 0x{hr:08X}"
            ));
        }
        let mut session: PmHandle = std::ptr::null_mut();
        let name = wide("PocketStreamProbe");
        let hr = (api.create_live_session)(handle, name.as_ptr(), &mut session);
        if hr != 0 {
            let _ = (api.uninitialize)(handle);
            return Err(format!(
                "PacketMonitorCreateLiveSession failed: HRESULT 0x{hr:08X}"
            ));
        }
        let _ = (api.close_session_handle)(session);
        let _ = (api.uninitialize)(handle);
    }
    Ok(())
}

// ── Capture session lifecycle ───────────────────────────────────────

/// A live, active capture session with the in-driver ARP constraint
/// applied. Callbacks in `config` fire on the API's stream thread —
/// keep them cheap or the ring drops packets (the descriptor's
/// missed-packet counters surface that).
///
/// The caller owns `config.user_context` and must keep it alive until
/// after [`CaptureSession::stop`] returns.
pub struct CaptureSession {
    api: PktMonApi,
    handle: PmHandle,
    session: PmHandle,
    stream: PmHandle,
}

// SAFETY: the three PacketMonitor handles are opaque, process-owned
// kernel-object handles; the API is documented multisession and its
// entry points are not thread-affine. The session is created on one
// thread and torn down from the shutdown task's thread.
unsafe impl Send for CaptureSession {}

/// Resolve the data-source id the given scope would join right now,
/// without building a session: initialize, enumerate + join, release.
/// Native calls only (sub-100 ms) — used to detect data-source churn
/// underneath a persistent capture listener. Blocking; call from a
/// blocking context.
pub fn live_source_id_for(scope: &CaptureScope) -> Result<u32, String> {
    let api = PktMonApi::load()?;
    unsafe {
        let mut handle: PmHandle = std::ptr::null_mut();
        let hr = (api.initialize)(API_VERSION_1_0, std::ptr::null_mut(), &mut handle);
        if hr != 0 {
            return Err(format!("PacketMonitorInitialize: HRESULT 0x{hr:08X}"));
        }
        let result = CaptureSession::enumerate_and_join(&api, handle, scope).map(|(_, _, id)| id);
        let _ = (api.uninitialize)(handle);
        result
    }
}

impl CaptureSession {
    /// Start a capture scoped to the selected wired adapter. All-or-
    /// nothing: if any part of the scoped build fails — enumeration,
    /// join, or attach — the partial session is fully unwound and a
    /// fresh unscoped session (per-frame filters still active) is built
    /// from scratch. The returned [`ScopeOutcome`] says which happened;
    /// the caller logs it exactly once per start. `ForcedUnscoped` skips
    /// the scoped attempt entirely.
    pub fn start(
        session_name: &str,
        config: RealtimeStreamConfiguration,
        scope: &CaptureScope,
        mode: CaptureMode,
    ) -> Result<(Self, ScopeOutcome), String> {
        let api = PktMonApi::load()?;
        if mode == CaptureMode::ForcedUnscoped {
            let (handle, session, stream, _) = Self::try_start(&api, session_name, &config, None)?;
            return Ok((
                Self {
                    api,
                    handle,
                    session,
                    stream,
                },
                ScopeOutcome::UnscopedFallback {
                    reason: "unscoped demanded by the capture-restart ladder".into(),
                },
            ));
        }
        match Self::try_start(&api, session_name, &config, Some(scope)) {
            Ok((handle, session, stream, scoped_id)) => Ok((
                Self {
                    api,
                    handle,
                    session,
                    stream,
                },
                ScopeOutcome::SelectedInterface {
                    source_id: scoped_id,
                },
            )),
            Err(scoped_reason) => {
                let (handle, session, stream, _) =
                    Self::try_start(&api, session_name, &config, None).map_err(|e| {
                        format!(
                        "scoped start failed ({scoped_reason}); unscoped fallback also failed: {e}"
                    )
                    })?;
                Ok((
                    Self {
                        api,
                        handle,
                        session,
                        stream,
                    },
                    ScopeOutcome::UnscopedFallback {
                        reason: scoped_reason,
                    },
                ))
            }
        }
    }

    /// Run the full documented startup sequence once, scoped or not.
    /// Every startup HRESULT is checked; any failure unwinds the
    /// partial state in reverse and reports which call failed.
    fn try_start(
        api: &PktMonApi,
        session_name: &str,
        config: &RealtimeStreamConfiguration,
        scope: Option<&CaptureScope>,
    ) -> Result<(PmHandle, PmHandle, PmHandle, Option<u32>), String> {
        unsafe {
            let mut handle: PmHandle = std::ptr::null_mut();
            let hr = (api.initialize)(API_VERSION_1_0, std::ptr::null_mut(), &mut handle);
            if hr != 0 {
                return Err(format!("PacketMonitorInitialize: HRESULT 0x{hr:08X}"));
            }

            // Enumeration needs only the post-Initialize handle; join
            // before any session exists so a failure unwinds cheaply.
            let scoped_source: Option<(Vec<u8>, usize, u32)> = match scope {
                Some(s) => match Self::enumerate_and_join(api, handle, s) {
                    Ok(found) => Some(found),
                    Err(e) => {
                        let _ = (api.uninitialize)(handle);
                        return Err(e);
                    }
                },
                None => None,
            };

            let mut session: PmHandle = std::ptr::null_mut();
            let name = wide(session_name);
            let hr = (api.create_live_session)(handle, name.as_ptr(), &mut session);
            if hr != 0 {
                let _ = (api.uninitialize)(handle);
                return Err(format!(
                    "PacketMonitorCreateLiveSession: HRESULT 0x{hr:08X}"
                ));
            }

            let constraint = build_arp_constraint();
            let hr = (api.add_capture_constraint)(session, constraint.as_ptr());
            if hr != 0 {
                let _ = (api.close_session_handle)(session);
                let _ = (api.uninitialize)(handle);
                return Err(format!(
                    "PacketMonitorAddCaptureConstraint: HRESULT 0x{hr:08X}"
                ));
            }

            // Attach exactly the returned in-buffer specification. The
            // API copies what it needs at Add time (hardware-verified),
            // but the buffer stays alive through activation anyway.
            if let Some((buf, offset, _)) = &scoped_source {
                let hr = (api.add_single_data_source)(session, buf.as_ptr().add(*offset));
                if hr != 0 {
                    let _ = (api.close_session_handle)(session);
                    let _ = (api.uninitialize)(handle);
                    return Err(format!(
                        "PacketMonitorAddSingleDataSourceToSession: HRESULT 0x{hr:08X}"
                    ));
                }
            }

            let mut stream: PmHandle = std::ptr::null_mut();
            let hr = (api.create_realtime_stream)(handle, config, &mut stream);
            if hr != 0 {
                let _ = (api.close_session_handle)(session);
                let _ = (api.uninitialize)(handle);
                return Err(format!(
                    "PacketMonitorCreateRealtimeStream: HRESULT 0x{hr:08X}"
                ));
            }

            let hr = (api.attach_output_to_session)(session, stream);
            if hr != 0 {
                let _ = (api.close_realtime_stream)(stream);
                let _ = (api.close_session_handle)(session);
                let _ = (api.uninitialize)(handle);
                return Err(format!(
                    "PacketMonitorAttachOutputToSession: HRESULT 0x{hr:08X}"
                ));
            }

            let hr = (api.set_session_active)(session, 1);
            if hr != 0 {
                let _ = (api.close_realtime_stream)(stream);
                let _ = (api.close_session_handle)(session);
                let _ = (api.uninitialize)(handle);
                return Err(format!("PacketMonitorSetSessionActive: HRESULT 0x{hr:08X}"));
            }

            let scoped_id = scoped_source.as_ref().map(|(_, _, id)| *id);
            drop(scoped_source);
            Ok((handle, session, stream, scoped_id))
        }
    }

    /// Two-call enumeration of visible network-interface data sources,
    /// then the pure join. Returns the raw list buffer plus the byte
    /// offset of the matched entry — the original in-buffer pointer is
    /// what `PacketMonitorAddSingleDataSourceToSession` must receive —
    /// and the matched entry's data-source id.
    fn enumerate_and_join(
        api: &PktMonApi,
        handle: PmHandle,
        scope: &CaptureScope,
    ) -> Result<(Vec<u8>, usize, u32), String> {
        unsafe {
            let mut needed: usize = 0;
            let hr = (api.enum_data_sources)(
                handle,
                DATA_SOURCE_KIND_NETWORK_INTERFACE,
                0,
                0,
                &mut needed,
                std::ptr::null_mut(),
            );
            if needed == 0 || needed > DATA_SOURCE_ENUM_MAX_BYTES {
                return Err(format!(
                    "PacketMonitorEnumDataSources size query returned {needed} bytes (HRESULT 0x{hr:08X})"
                ));
            }
            let mut buf = vec![0u8; needed];
            let hr = (api.enum_data_sources)(
                handle,
                DATA_SOURCE_KIND_NETWORK_INTERFACE,
                0,
                buf.len(),
                &mut needed,
                buf.as_mut_ptr(),
            );
            if hr != 0 {
                return Err(format!("PacketMonitorEnumDataSources: HRESULT 0x{hr:08X}"));
            }
            let entries = parse_data_source_list(&buf)?;
            let idx = select_scoped_source(&entries, scope).map_err(|e| e.to_string())?;
            log::debug!(
                "Capture scope join: '{}' -> data source id={} ({}, {})",
                scope.display_name,
                entries[idx].id,
                entries[idx].name,
                entries[idx].description
            );
            let offset = entries[idx].offset;
            let source_id = entries[idx].id;
            Ok((buf, offset, source_id))
        }
    }

    /// Deactivate and tear down. Teardown return values are treated as
    /// void — S4 observed garbage HRESULTs from `Close*`/`Uninitialize`
    /// while behavior was correct. After this returns, no callback will
    /// fire again and `user_context` may be freed.
    pub fn stop(self) {
        unsafe {
            let _ = (self.api.set_session_active)(self.session, 0);
            let _ = (self.api.close_realtime_stream)(self.stream);
            let _ = (self.api.close_session_handle)(self.session);
            let _ = (self.api.uninitialize)(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    // Pure layout asserts — the encoded contract of the empirically
    // pinned constants. No driver or DLL needed; runs on every CI job.

    #[test]
    fn stream_metadata_is_packed_40_bytes() {
        assert_eq!(size_of::<StreamMetadata>(), 40);
        assert_eq!(offset_of!(StreamMetadata, pkt_group_id), 0);
        assert_eq!(offset_of!(StreamMetadata, pkt_count), 8);
        assert_eq!(offset_of!(StreamMetadata, appearance_count), 10);
        assert_eq!(offset_of!(StreamMetadata, direction_name), 12);
        assert_eq!(offset_of!(StreamMetadata, packet_type), 14);
        assert_eq!(offset_of!(StreamMetadata, component_id), 16);
        assert_eq!(offset_of!(StreamMetadata, edge_id), 18);
        assert_eq!(offset_of!(StreamMetadata, reserved), 20);
        assert_eq!(offset_of!(StreamMetadata, drop_reason), 22);
        assert_eq!(offset_of!(StreamMetadata, drop_location), 26);
        assert_eq!(offset_of!(StreamMetadata, processor), 30);
        assert_eq!(offset_of!(StreamMetadata, timestamp), 32);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn descriptor_and_config_sizes() {
        assert_eq!(size_of::<StreamDataDescriptor>(), 32);
        assert_eq!(size_of::<RealtimeStreamConfiguration>(), 32);
    }

    #[test]
    fn data_source_spec_layout_is_424_bytes() {
        assert_eq!(size_of::<DataSourceSpecification>(), DATA_SOURCE_SPEC_SIZE);
        assert_eq!(offset_of!(DataSourceSpecification, kind), 0);
        assert_eq!(offset_of!(DataSourceSpecification, name), 4);
        assert_eq!(offset_of!(DataSourceSpecification, description), 132);
        assert_eq!(offset_of!(DataSourceSpecification, id), 388);
        assert_eq!(offset_of!(DataSourceSpecification, secondary_id), 392);
        assert_eq!(offset_of!(DataSourceSpecification, parent_id), 396);
        assert_eq!(offset_of!(DataSourceSpecification, is_present), 400);
        assert_eq!(offset_of!(DataSourceSpecification, detail), 408);
    }

    // ── data-source list parsing ──────────────────────────────────

    /// Raw 424-byte entry with the fields the parser reads.
    fn spec_bytes(name: &str, id: u32, is_present: i32, mac: [u8; 6]) -> Vec<u8> {
        let mut b = vec![0u8; DATA_SOURCE_SPEC_SIZE];
        b[0..4].copy_from_slice(&DATA_SOURCE_KIND_NETWORK_INTERFACE.to_le_bytes());
        for (i, u) in name.encode_utf16().take(63).enumerate() {
            b[4 + i * 2..6 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        for (i, u) in "Test Adapter".encode_utf16().enumerate() {
            b[132 + i * 2..134 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        b[388..392].copy_from_slice(&id.to_le_bytes());
        b[392..396].copy_from_slice(&id.to_le_bytes());
        b[400..404].copy_from_slice(&is_present.to_le_bytes());
        b[408..414].copy_from_slice(&mac);
        b
    }

    /// List buffer with real absolute in-buffer pointers, like the API
    /// returns. Pre-sized so the heap block (and thus the patched
    /// pointers) never moves.
    fn list_buf(specs: &[Vec<u8>]) -> Vec<u8> {
        let count = specs.len();
        let entries_start = 8 + count * 8;
        let mut buf = vec![0u8; entries_start + count * DATA_SOURCE_SPEC_SIZE];
        buf[0..4].copy_from_slice(&(count as u32).to_le_bytes());
        let base = buf.as_ptr() as usize;
        for (i, s) in specs.iter().enumerate() {
            let off = entries_start + i * DATA_SOURCE_SPEC_SIZE;
            buf[off..off + DATA_SOURCE_SPEC_SIZE].copy_from_slice(s);
            let p = base + off;
            buf[8 + i * 8..16 + i * 8].copy_from_slice(&p.to_le_bytes());
        }
        buf
    }

    const MAC_WIRED: [u8; 6] = [0x40, 0xC2, 0xBA, 0xCF, 0xD5, 0x75];
    const MAC_WIFI: [u8; 6] = [0xAC, 0x45, 0xEF, 0x38, 0xF9, 0xF5];

    #[test]
    fn parse_data_source_list_reads_entries() {
        let buf = list_buf(&[
            spec_bytes("e1dn.sys", 70, 8, MAC_WIRED),
            spec_bytes("Netwaw18.sys", 71, 8, MAC_WIFI),
        ]);
        let entries = parse_data_source_list(&buf).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "e1dn.sys");
        assert_eq!(entries[0].description, "Test Adapter");
        assert_eq!(entries[0].id, 70);
        assert!(entries[0].is_present, "is_present=8 means present");
        assert_eq!(entries[0].mac, Some(MAC_WIRED));
        assert_eq!(entries[1].mac, Some(MAC_WIFI));
        assert_eq!(entries[0].offset, 8 + 2 * 8);
    }

    #[test]
    fn parse_data_source_list_empty_list_ok() {
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse_data_source_list(&buf).unwrap().is_empty());
    }

    #[test]
    fn parse_data_source_list_rejects_truncated_header() {
        assert!(parse_data_source_list(&[0u8; 4]).is_err());
    }

    #[test]
    fn parse_data_source_list_rejects_truncated_pointer_array() {
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&3u32.to_le_bytes());
        assert!(parse_data_source_list(&buf).is_err());
    }

    #[test]
    fn parse_data_source_list_rejects_out_of_bounds_pointer() {
        // Pointer below the buffer base.
        let mut buf = list_buf(&[spec_bytes("e1dn.sys", 70, 8, MAC_WIRED)]);
        let bogus = (buf.as_ptr() as usize).wrapping_sub(4096);
        buf[8..16].copy_from_slice(&bogus.to_le_bytes());
        assert!(parse_data_source_list(&buf).is_err());

        // Pointer whose 424-byte entry would run past the buffer end.
        let mut buf = list_buf(&[spec_bytes("e1dn.sys", 70, 8, MAC_WIRED)]);
        let past = buf.as_ptr() as usize + buf.len() - 8;
        buf[8..16].copy_from_slice(&past.to_le_bytes());
        assert!(parse_data_source_list(&buf).is_err());
    }

    #[test]
    fn parse_data_source_list_zero_mac_is_none() {
        let buf = list_buf(&[spec_bytes("bthpan.sys", 3, 9, [0; 6])]);
        let entries = parse_data_source_list(&buf).unwrap();
        assert_eq!(entries[0].mac, None);
    }

    // ── scoped-source join ────────────────────────────────────────

    fn entry(mac: Option<[u8; 6]>, present: bool) -> DataSourceEntry {
        DataSourceEntry {
            offset: 0,
            name: "test.sys".into(),
            description: String::new(),
            id: 1,
            is_present: present,
            mac,
        }
    }

    fn wired_scope() -> CaptureScope {
        CaptureScope {
            mac: Some(MAC_WIRED),
            display_name: "Ethernet".into(),
        }
    }

    #[test]
    fn select_scoped_source_exact_mac_match() {
        let entries = [entry(Some(MAC_WIFI), true), entry(Some(MAC_WIRED), true)];
        assert_eq!(select_scoped_source(&entries, &wired_scope()), Ok(1));
    }

    #[test]
    fn select_scoped_source_no_match() {
        let entries = [entry(Some(MAC_WIFI), true)];
        assert_eq!(
            select_scoped_source(&entries, &wired_scope()),
            Err(JoinFailure::NoMatch)
        );
    }

    #[test]
    fn select_scoped_source_ambiguous_duplicate_mac() {
        let entries = [entry(Some(MAC_WIRED), true), entry(Some(MAC_WIRED), true)];
        assert_eq!(
            select_scoped_source(&entries, &wired_scope()),
            Err(JoinFailure::Ambiguous(2))
        );
    }

    #[test]
    fn select_scoped_source_requires_identity() {
        let entries = [entry(Some(MAC_WIRED), true)];
        let scope = CaptureScope {
            mac: None,
            display_name: "Ethernet".into(),
        };
        assert_eq!(
            select_scoped_source(&entries, &scope),
            Err(JoinFailure::NoIdentity)
        );
    }

    #[test]
    fn select_scoped_source_skips_absent_sources() {
        // A matching MAC on a non-present source must not be scoped to.
        let entries = [entry(Some(MAC_WIRED), false)];
        assert_eq!(
            select_scoped_source(&entries, &wired_scope()),
            Err(JoinFailure::NoMatch)
        );
    }

    #[test]
    fn select_scoped_source_other_adapter_mac_never_matches() {
        // A WiFi source can never satisfy a wired-adapter scope: the
        // join is exact-MAC, so no "closest" pick exists.
        let entries = [entry(Some(MAC_WIFI), true), entry(None, true)];
        assert_eq!(
            select_scoped_source(&entries, &wired_scope()),
            Err(JoinFailure::NoMatch)
        );
    }

    #[test]
    fn arp_constraint_layout() {
        let c = build_arp_constraint();
        assert_eq!(c.len(), 216);
        // IsPresentValue: only the EtherType bit (bit 3).
        assert_eq!(u32::from_le_bytes(c[128..132].try_into().unwrap()), 1 << 3);
        // EtherType 0x0806 in HOST byte order.
        assert_eq!(u16::from_le_bytes(c[146..148].try_into().unwrap()), 0x0806);
        // Everything else zero (Name zeroed is valid; no other fields
        // marked present).
        for (i, b) in c.iter().enumerate() {
            if !(128..132).contains(&i) && !(146..148).contains(&i) {
                assert_eq!(*b, 0, "unexpected nonzero byte at offset {i}");
            }
        }
    }

    #[test]
    fn read_metadata_decodes_pinned_offsets() {
        // Synthetic 40-byte blob with distinct values at every pinned
        // offset (little-endian), prefixed by 4 junk bytes to prove the
        // offset parameter is honored.
        let mut blob = vec![0xEEu8; 4];
        let mut m = [0u8; 40];
        m[0..8].copy_from_slice(&0x1122334455667788u64.to_le_bytes()); // pkt_group_id
        m[8..10].copy_from_slice(&2u16.to_le_bytes()); // pkt_count
        m[10..12].copy_from_slice(&3u16.to_le_bytes()); // appearance_count
        m[12..14].copy_from_slice(&1u16.to_le_bytes()); // direction_name
        m[14..16].copy_from_slice(&7u16.to_le_bytes()); // packet_type
        m[16..18].copy_from_slice(&41u16.to_le_bytes()); // component_id
        m[18..20].copy_from_slice(&5u16.to_le_bytes()); // edge_id
        m[22..26].copy_from_slice(&0xA1A2A3A4u32.to_le_bytes()); // drop_reason
        m[26..30].copy_from_slice(&0xB1B2B3B4u32.to_le_bytes()); // drop_location
        m[30..32].copy_from_slice(&9u16.to_le_bytes()); // processor
        m[32..40].copy_from_slice(&0x01DB0000_00000042i64.to_le_bytes()); // timestamp
        blob.extend_from_slice(&m);

        let meta = read_metadata(&blob, 4).unwrap();
        assert_eq!({ meta.pkt_group_id }, 0x1122334455667788);
        assert_eq!({ meta.pkt_count }, 2);
        assert_eq!({ meta.appearance_count }, 3);
        assert_eq!({ meta.direction_name }, 1);
        assert_eq!({ meta.packet_type }, 7);
        assert_eq!({ meta.component_id }, 41);
        assert_eq!({ meta.edge_id }, 5);
        assert_eq!({ meta.drop_reason }, 0xA1A2A3A4);
        assert_eq!({ meta.drop_location }, 0xB1B2B3B4);
        assert_eq!({ meta.processor }, 9);
        assert_eq!({ meta.timestamp }, 0x01DB0000_00000042);
    }

    #[test]
    fn read_metadata_rejects_short_blob() {
        assert!(read_metadata(&[0u8; 39], 0).is_none());
        assert!(read_metadata(&[0u8; 43], 4).is_none());
        assert!(read_metadata(&[], usize::MAX).is_none());
    }

    #[test]
    fn plausibility_canary() {
        let meta = |packet_type, direction_name| StreamMetadata {
            packet_type,
            direction_name,
            ..Default::default()
        };
        assert!(metadata_plausible(&meta(1, 2)));
        assert!(!metadata_plausible(&meta(12, 2))); // packet_type beyond the enum
        assert!(!metadata_plausible(&meta(1, 7))); // direction beyond the enum
    }
}
