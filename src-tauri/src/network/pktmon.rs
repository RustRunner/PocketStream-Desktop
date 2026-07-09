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

/// `packet_type` value for a frame captured on a Wi-Fi adapter. The
/// capture runs unscoped (all NICs), so ARP from the wireless side —
/// the WiFi gateway and other wireless hosts — is delivered here too,
/// normalized to Ethernet II framing; discovery drops these so only the
/// wired Ethernet port's peers become nodes.
pub const PACKET_TYPE_WIFI: u16 = 2;

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
/// stay valid for the struct's lifetime. Only the functions the capture
/// path uses are stored; the data-source enumeration pair is
/// presence-checked (tier 0) but unused — capture runs unscoped by
/// design (NIC-scoped capture yields native-802.11 framing on Wi-Fi,
/// unparseable as Ethernet II).
pub struct PktMonApi {
    _lib: libloading::Library,
    initialize: unsafe extern "system" fn(u32, *mut c_void, *mut PmHandle) -> Hresult,
    uninitialize: unsafe extern "system" fn(PmHandle) -> Hresult,
    create_live_session: unsafe extern "system" fn(PmHandle, *const u16, *mut PmHandle) -> Hresult,
    close_session_handle: unsafe extern "system" fn(PmHandle) -> Hresult,
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

impl CaptureSession {
    /// Run the full documented startup sequence. Every startup HRESULT
    /// is checked; any failure unwinds the partial state and reports
    /// which call failed.
    pub fn start(session_name: &str, config: RealtimeStreamConfiguration) -> Result<Self, String> {
        let api = PktMonApi::load()?;
        unsafe {
            let mut handle: PmHandle = std::ptr::null_mut();
            let hr = (api.initialize)(API_VERSION_1_0, std::ptr::null_mut(), &mut handle);
            if hr != 0 {
                return Err(format!("PacketMonitorInitialize: HRESULT 0x{hr:08X}"));
            }

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

            let mut stream: PmHandle = std::ptr::null_mut();
            let hr = (api.create_realtime_stream)(handle, &config, &mut stream);
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

            Ok(Self {
                api,
                handle,
                session,
                stream,
            })
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
