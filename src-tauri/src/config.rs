use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Camera input protocol. Serializes as the lowercase wire strings
/// `"rtsp"` / `"udp"` (unchanged from when this was a bare `String`), so
/// a junk value now fails deserialization at the IPC boundary and, for a
/// config file, routes to the quarantine path instead of silently
/// falling through to RTSP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum StreamProtocol {
    #[default]
    Rtsp,
    Udp,
}

/// Selected re-stream output protocol. Missing persisted values default to
/// RTSP so pre-selector installations retain their existing output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RestreamProtocol {
    #[default]
    Rtsp,
    Srt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    /// Input protocol.
    pub protocol: StreamProtocol,
    /// Camera RTSP port (default 554)
    pub rtsp_port: u16,
    /// Camera RTSP path (default "/z3-1.sdp")
    pub rtsp_path: String,
    /// UDP stream port (default 8600)
    pub udp_port: u16,
    /// Camera IP address (discovered or manual)
    pub camera_ip: String,
    #[serde(default)]
    pub camera_mac: Option<String>,
    /// Whether audio playback is muted. `false` by default — audio
    /// plays when a stream carries a supported track. `serde(default)`
    /// migrates config files that predate the field.
    #[serde(default)]
    pub audio_muted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RtspServerConfig {
    /// Whether RTSP re-streaming is enabled
    pub enabled: bool,
    /// RTSP server output port (default 8554)
    pub port: u16,
    /// Authentication token for RTSP access
    pub token: String,
    /// Network interface to bind the RTSP server to (empty = all interfaces)
    #[serde(default)]
    pub bind_interface: String,
}

/// Runtime-only SRT passphrase state. Deliberately neither `Debug` nor
/// serializable: plaintext and preserved ciphertext may only cross the
/// explicit persistence/view boundaries below.
#[derive(Clone, PartialEq, Eq)]
pub enum SrtPassphraseState {
    Unencrypted,
    Available(String),
    Unavailable { preserved_ciphertext: String },
}

/// Validated, narrow runtime SRT settings.
#[derive(Clone, PartialEq, Eq)]
pub struct SrtServerConfig {
    pub port: u16,
    pub passphrase: SrtPassphraseState,
    pub latency_ms: u32,
    pub stream_id: String,
    pub bind_interface: String,
}

impl Default for SrtServerConfig {
    fn default() -> Self {
        Self {
            port: 8890,
            passphrase: SrtPassphraseState::Unencrypted,
            latency_ms: 125,
            stream_id: String::new(),
            bind_interface: String::new(),
        }
    }
}

/// IPC update shape. Re-stream numerics stay wide until the centralized
/// prospective-settings validator accepts them, so negative and oversized
/// values produce a typed validation error instead of a serde boundary error.
#[derive(Debug, Clone, Deserialize)]
pub struct RtspServerUpdate {
    pub port: i64,
    pub token: String,
    pub bind_interface: String,
}

/// Explicit passphrase intent. `Keep` is the only untouched-field action;
/// an empty `Replace` is invalid, while `Clear` intentionally requests an
/// unencrypted listener.
#[derive(Clone, Deserialize)]
#[serde(tag = "action", content = "value", rename_all = "snake_case")]
pub enum SrtPassphraseUpdate {
    Keep,
    Replace(String),
    Clear,
}

#[derive(Clone, Deserialize)]
pub struct SrtServerUpdate {
    pub port: i64,
    pub passphrase: SrtPassphraseUpdate,
    pub latency_ms: i64,
    pub stream_id: String,
    pub bind_interface: String,
}

#[derive(Clone, Deserialize)]
pub struct RestreamSettingsUpdate {
    pub enabled: bool,
    pub rtsp_server: RtspServerUpdate,
    pub srt_server: SrtServerUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// Camera username (encrypted at rest)
    pub username: String,
    /// Camera password (encrypted at rest)
    pub password: String,
}

/// User's chosen network mode. Drives which discovery subsystems run.
///
/// - `Dhcp`: adapter on DHCP. ARP listener + auto-adopt loop run, but
///   auto-adopt is gated to APIPA-rescue (when DHCP failed and only
///   169.254/16 is on the adapter); otherwise paused.
/// - `StaticAuto`: adapter on a user-set static IP. ARP listener,
///   auto-adopt loop, and port scanner all run.
/// - `StaticManual`: adapter on a user-set static IP. None of the
///   discovery subsystems run; the Nodes panel reflects only the
///   explicitly-added `manual_nodes` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    Dhcp,
    // Existing installs (config.toml predates this field) keep the
    // historic behavior — ARP discovery + auto-adopt. Fresh installs
    // hit this default too; the IP Config dialog is how users move to
    // DHCP or Static-Manual.
    #[default]
    StaticAuto,
    StaticManual,
}

/// A user-pinned device for `NetworkMode::StaticManual`. Survives mode
/// toggles so users can flip Auto → Manual → Auto without losing pins.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManualNode {
    #[serde(default)]
    pub expected_mac: Option<String>,
    pub ip: String,
    #[serde(default)]
    pub alias: String,
}

/// Cached metadata for a previously-discovered device.
///
/// Persisted across sessions so the nodes panel can render immediately
/// on startup with the last-known state, before any network activity.
/// Cached entries are flagged as "verifying" in the UI until a fresh
/// targeted port scan confirms they are still reachable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDevice {
    #[serde(default)]
    pub verified_by_mac: Option<String>,
    #[serde(default)]
    pub last_verified_at: Option<String>,
    pub mac: String,
    pub ip: String,
    pub subnet: String,
    #[serde(default)]
    pub open_ports: Vec<u16>,
    #[serde(default)]
    pub alias: String,
    /// RFC3339 timestamp of the last successful scan
    pub last_seen: String,
}

/// Lifecycle metadata for one adopted subnet. Persisted as a map
/// parallel to `adopted_subnets` (never a value-type change to that
/// map, so configs written by older builds keep loading untouched).
/// Saved intent and the last observed OS state. Wall-clock liveness is
/// informational; committed bindings are removed only by explicit user intent.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdoptedMeta {
    /// RFC3339 wall time the subnet was adopted. For adoptions
    /// persisted by builds that predate this metadata, backfilled with
    /// the load time of the first build that records it.
    #[serde(default)]
    pub adopted_at: Option<String>,
    /// RFC3339 wall time of the last positive evidence from a device
    /// on the subnet (accepted ARP, successful targeted scan or ping).
    /// `None` until evidence arrives.
    #[serde(default)]
    pub last_device_seen: Option<String>,
    #[serde(default)]
    pub adapter_mac: Option<String>,
    #[serde(default)]
    pub prefix: Option<u8>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub desired: BindingDesired,
    #[serde(default)]
    pub applied: bool,
    #[serde(default)]
    pub last_error: Option<String>,
}

impl AdoptedMeta {
    /// Removal is a transaction, not a permanent subnet exclusion. Only an
    /// observed, successfully saved absence permits a fresh adoption attempt.
    pub(crate) fn removal_complete(&self) -> bool {
        self.desired == BindingDesired::Removed && !self.applied && self.last_error.is_none()
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BindingDesired {
    #[default]
    Present,
    Removed,
}

/// Exact write-ahead ownership of an uncommitted OS address. Backend-owned;
/// cleared atomically when a binding commits or the user claims the address.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PendingAddress {
    pub adapter_mac: String,
    pub address: String,
    pub prefix: u8,
}

/// Backfill legacy metadata without discarding detached removal intent.
pub fn align_adopted_meta(
    adopted: &HashMap<String, String>,
    meta: &mut HashMap<String, AdoptedMeta>,
    now_rfc3339: &str,
) {
    meta.retain(|subnet, row| {
        adopted.contains_key(subnet) || row.desired == BindingDesired::Removed
    });
    for (subnet, address) in adopted {
        let row = meta.entry(subnet.clone()).or_insert_with(|| AdoptedMeta {
            adopted_at: Some(now_rfc3339.to_string()),
            ..Default::default()
        });
        row.address.get_or_insert_with(|| address.clone());
        if row.prefix.is_none() {
            row.prefix = subnet.rsplit_once('/').and_then(|(_, p)| p.parse().ok());
        }
    }
}

/// Retire exactly one route, retaining its exact address and removal intent.
/// Returns whether the subnet entry existed. Pure so the surgical
/// contract is unit-testable.
fn remove_adoption_entry(
    adopted: &mut HashMap<String, String>,
    meta: &mut HashMap<String, AdoptedMeta>,
    subnet: &str,
) -> bool {
    let address = adopted.remove(subnet);
    if address.is_none() && !meta.contains_key(subnet) {
        return false;
    }
    let row = meta.entry(subnet.to_string()).or_default();
    if row.address.is_none() {
        row.address = address;
    }
    if row.prefix.is_none() {
        row.prefix = subnet.rsplit_once('/').and_then(|(_, p)| p.parse().ok());
    }
    row.desired = BindingDesired::Removed;
    true
}

#[derive(Clone)]
pub struct AppSettings {
    pub selected_adapter_mac: Option<String>,
    /// Explicit primary IPv4 CIDR per adapter MAC. Empty means the user removed
    /// the primary; an absent entry is legacy/unknown, never enumeration order.
    pub primary_addresses: HashMap<String, String>,
    pub stream: StreamConfig,
    /// Persisted output selector. Missing values in pre-neutralization config
    /// files migrate to RTSP.
    pub restream_protocol: RestreamProtocol,
    pub rtsp_server: RtspServerConfig,
    pub srt_server: SrtServerConfig,
    pub credentials: Credentials,
    /// Auto-adopted subnet IPs: subnet string -> adopted IP address
    pub adopted_subnets: HashMap<String, String>,
    /// Lifecycle metadata per adopted subnet, keyed like
    /// `adopted_subnets`. See `AdoptedMeta` for what is (and is
    /// deliberately not) stored.
    pub adopted_meta: HashMap<String, AdoptedMeta>,
    pub pending_addresses: Vec<PendingAddress>,
    /// Last zoom slider position (0–100 %) per camera IP.
    /// Restored on launch so the slider doesn't reset to Wide when the
    /// camera is still pointed at the last-set zoom. Stored as percent
    /// rather than raw integer so different max ranges remain portable.
    pub zoom_positions: HashMap<String, i32>,
    /// User's chosen network mode. See `NetworkMode` doc-comment.
    pub network_mode: NetworkMode,
    /// User-pinned nodes for `NetworkMode::StaticManual`. Persisted
    /// across mode toggles; the typical workflow is to use `StaticAuto`
    /// to discover IPs, then switch to `StaticManual` for steady-state
    /// operation against the discovered set.
    pub manual_nodes: Vec<ManualNode>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            selected_adapter_mac: None,
            primary_addresses: HashMap::new(),
            stream: StreamConfig {
                camera_mac: None,
                protocol: StreamProtocol::Rtsp,
                rtsp_port: 554,
                rtsp_path: "/z3-1.sdp".into(),
                udp_port: 8600,
                camera_ip: String::new(),
                audio_muted: false,
            },
            restream_protocol: RestreamProtocol::Rtsp,
            rtsp_server: RtspServerConfig {
                enabled: false,
                port: 8554,
                token: generate_token(),
                bind_interface: String::new(),
            },
            srt_server: SrtServerConfig::default(),
            credentials: Credentials {
                username: String::new(),
                password: String::new(),
            },
            adopted_subnets: HashMap::new(),
            adopted_meta: HashMap::new(),
            pending_addresses: Vec::new(),
            zoom_positions: HashMap::new(),
            network_mode: NetworkMode::default(),
            manual_nodes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SrtPassphraseAvailability {
    Unencrypted,
    Available,
    Unavailable,
}

/// IPC-only secret projection. Do not derive `Debug`: `value` can contain
/// authorized plaintext for the masked settings control.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct SrtPassphraseView {
    pub state: SrtPassphraseAvailability,
    pub value: Option<String>,
}

impl From<&SrtPassphraseState> for SrtPassphraseView {
    fn from(passphrase: &SrtPassphraseState) -> Self {
        match passphrase {
            SrtPassphraseState::Unencrypted => Self {
                state: SrtPassphraseAvailability::Unencrypted,
                value: None,
            },
            SrtPassphraseState::Available(value) => Self {
                state: SrtPassphraseAvailability::Available,
                value: Some(value.clone()),
            },
            SrtPassphraseState::Unavailable { .. } => Self {
                state: SrtPassphraseAvailability::Unavailable,
                value: None,
            },
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct SrtServerView {
    pub port: u16,
    pub passphrase: SrtPassphraseView,
    pub latency_ms: u32,
    pub stream_id: String,
    pub bind_interface: String,
}

impl From<&SrtServerConfig> for SrtServerView {
    fn from(settings: &SrtServerConfig) -> Self {
        Self {
            port: settings.port,
            passphrase: SrtPassphraseView::from(&settings.passphrase),
            latency_ms: settings.latency_ms,
            stream_id: settings.stream_id.clone(),
            bind_interface: settings.bind_interface.clone(),
        }
    }
}

/// Explicit frontend view. Runtime settings and opaque SRT ciphertext remain
/// behind this boundary; only available plaintext is intentionally exposed
/// for the existing masked/copy settings interaction.
#[derive(Clone, Serialize)]
pub struct AppSettingsView {
    pub selected_adapter_mac: Option<String>,
    pub primary_addresses: HashMap<String, String>,
    pub stream: StreamConfig,
    pub restream_protocol: RestreamProtocol,
    pub rtsp_server: RtspServerConfig,
    pub srt_server: SrtServerView,
    pub credentials: Credentials,
    pub adopted_subnets: HashMap<String, String>,
    pub adopted_meta: HashMap<String, AdoptedMeta>,
    pub zoom_positions: HashMap<String, i32>,
    pub network_mode: NetworkMode,
    pub manual_nodes: Vec<ManualNode>,
}

impl From<&AppSettings> for AppSettingsView {
    fn from(settings: &AppSettings) -> Self {
        Self {
            selected_adapter_mac: settings.selected_adapter_mac.clone(),
            primary_addresses: settings.primary_addresses.clone(),
            stream: settings.stream.clone(),
            restream_protocol: settings.restream_protocol,
            rtsp_server: settings.rtsp_server.clone(),
            srt_server: SrtServerView::from(&settings.srt_server),
            credentials: settings.credentials.clone(),
            adopted_subnets: settings.adopted_subnets.clone(),
            adopted_meta: settings.adopted_meta.clone(),
            zoom_positions: settings.zoom_positions.clone(),
            network_mode: settings.network_mode,
            manual_nodes: settings.manual_nodes.clone(),
        }
    }
}

/// Private on-disk re-stream shapes keep numerics wide so invalid hand-edited
/// values reach the centralized validator instead of failing at serde's
/// integer narrowing boundary.
#[derive(Clone, Serialize, Deserialize)]
struct PersistedRtspServerConfig {
    enabled: bool,
    port: i64,
    token: String,
    #[serde(default)]
    bind_interface: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
struct PersistedSrtServerConfig {
    port: i64,
    passphrase: String,
    latency_ms: i64,
    stream_id: String,
    bind_interface: String,
}

impl Default for PersistedSrtServerConfig {
    fn default() -> Self {
        Self {
            port: 8890,
            passphrase: String::new(),
            latency_ms: 125,
            stream_id: String::new(),
            bind_interface: String::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedAppSettings {
    #[serde(default)]
    selected_adapter_mac: Option<String>,
    #[serde(default)]
    primary_addresses: HashMap<String, String>,
    #[serde(default)]
    pending_addresses: Vec<PendingAddress>,
    stream: StreamConfig,
    #[serde(default)]
    restream_protocol: RestreamProtocol,
    rtsp_server: PersistedRtspServerConfig,
    #[serde(default)]
    srt_server: PersistedSrtServerConfig,
    credentials: Credentials,
    #[serde(default)]
    adopted_subnets: HashMap<String, String>,
    #[serde(default)]
    adopted_meta: HashMap<String, AdoptedMeta>,
    #[serde(default)]
    zoom_positions: HashMap<String, i32>,
    #[serde(default)]
    network_mode: NetworkMode,
    #[serde(default)]
    manual_nodes: Vec<ManualNode>,
}

/// Resolve the stored SRT passphrase without ever treating decryption failure
/// as an intentionally empty secret. The original ciphertext is retained for
/// a later Replace/Clear repair or an unrelated save under a replacement key.
fn resolve_srt_passphrase(stored: String, key: Option<&[u8]>) -> SrtPassphraseState {
    if stored.is_empty() {
        return SrtPassphraseState::Unencrypted;
    }
    if let Some(plaintext) = key
        .filter(|key| key.len() == 32)
        .and_then(|key| decrypt_string(&stored, key))
    {
        return SrtPassphraseState::Available(plaintext);
    }

    log::error!(
        "config: saved SRT passphrase could not be decrypted; preserving it as unavailable until the user replaces or explicitly clears it"
    );
    SrtPassphraseState::Unavailable {
        preserved_ciphertext: stored,
    }
}

fn runtime_settings_from_persisted(
    persisted: PersistedAppSettings,
    key: Option<&[u8]>,
) -> Result<AppSettings, crate::AppError> {
    let PersistedAppSettings {
        selected_adapter_mac,
        primary_addresses,
        pending_addresses,
        stream,
        restream_protocol,
        rtsp_server,
        srt_server,
        credentials,
        adopted_subnets,
        adopted_meta,
        zoom_positions,
        network_mode,
        manual_nodes,
    } = persisted;

    let (username, password) =
        resolve_credentials(&credentials.username, &credentials.password, key);
    let passphrase = resolve_srt_passphrase(srt_server.passphrase, key);
    let (rtsp_server, srt_server) = crate::settings_validation::normalize_restream_servers(
        &stream,
        rtsp_server.enabled,
        RtspServerUpdate {
            port: rtsp_server.port,
            token: rtsp_server.token,
            bind_interface: rtsp_server.bind_interface,
        },
        crate::settings_validation::ResolvedSrtServerUpdate {
            port: srt_server.port,
            passphrase,
            latency_ms: srt_server.latency_ms,
            stream_id: srt_server.stream_id,
            bind_interface: srt_server.bind_interface,
        },
    )?;

    crate::settings_validation::validate_prospective_settings(AppSettings {
        selected_adapter_mac,
        primary_addresses,
        pending_addresses,
        stream,
        restream_protocol,
        rtsp_server,
        srt_server,
        credentials: Credentials { username, password },
        adopted_subnets,
        adopted_meta,
        zoom_positions,
        network_mode,
        manual_nodes,
    })
}

fn persisted_settings_with_srt_encryptor<F>(
    settings: &AppSettings,
    key: &[u8],
    encrypt_srt: F,
) -> Result<PersistedAppSettings, crate::AppError>
where
    F: FnOnce(&str, &[u8]) -> Result<String, crate::AppError>,
{
    let settings = crate::settings_validation::validate_prospective_settings(settings.clone())?;
    let passphrase = match &settings.srt_server.passphrase {
        SrtPassphraseState::Unencrypted => String::new(),
        SrtPassphraseState::Available(plaintext) => {
            let encrypted = encrypt_srt(plaintext, key)?;
            if encrypted.is_empty() {
                return Err(crate::AppError::Config(
                    "protected SRT passphrase encryption returned no ciphertext; settings were not saved"
                        .into(),
                ));
            }
            encrypted
        }
        SrtPassphraseState::Unavailable {
            preserved_ciphertext,
        } => {
            if preserved_ciphertext.is_empty() {
                return Err(crate::AppError::Config(
                    "unavailable SRT passphrase has no preserved ciphertext; settings were not saved"
                        .into(),
                ));
            }
            preserved_ciphertext.clone()
        }
    };

    Ok(PersistedAppSettings {
        selected_adapter_mac: settings.selected_adapter_mac,
        primary_addresses: settings.primary_addresses,
        pending_addresses: settings.pending_addresses,
        stream: settings.stream,
        restream_protocol: settings.restream_protocol,
        rtsp_server: PersistedRtspServerConfig {
            enabled: settings.rtsp_server.enabled,
            port: i64::from(settings.rtsp_server.port),
            token: settings.rtsp_server.token,
            bind_interface: settings.rtsp_server.bind_interface,
        },
        srt_server: PersistedSrtServerConfig {
            port: i64::from(settings.srt_server.port),
            passphrase,
            latency_ms: i64::from(settings.srt_server.latency_ms),
            stream_id: settings.srt_server.stream_id,
            bind_interface: settings.srt_server.bind_interface,
        },
        credentials: Credentials {
            username: encrypt_string(&settings.credentials.username, key),
            password: encrypt_string(&settings.credentials.password, key),
        },
        adopted_subnets: settings.adopted_subnets,
        adopted_meta: settings.adopted_meta,
        zoom_positions: settings.zoom_positions,
        network_mode: settings.network_mode,
        manual_nodes: settings.manual_nodes,
    })
}

fn serialize_settings_with_srt_encryptor<F>(
    settings: &AppSettings,
    key: &[u8],
    encrypt_srt: F,
) -> Result<String, crate::AppError>
where
    F: FnOnce(&str, &[u8]) -> Result<String, crate::AppError>,
{
    let persisted = persisted_settings_with_srt_encryptor(settings, key, encrypt_srt)?;
    toml::to_string_pretty(&persisted).map_err(|error| crate::AppError::Config(error.to_string()))
}

fn save_settings_to_path_with_srt_encryptor<F>(
    settings: &AppSettings,
    path: &Path,
    key: &[u8],
    encrypt_srt: F,
) -> Result<(), crate::AppError>
where
    F: FnOnce(&str, &[u8]) -> Result<String, crate::AppError>,
{
    let content = serialize_settings_with_srt_encryptor(settings, key, encrypt_srt)?;
    atomic_write(path, content.as_bytes())
        .map_err(|error| crate::AppError::Config(error.to_string()))
}

/// On-disk shape of `device_cache.toml`. Wrapping `Vec<CachedDevice>`
/// in a struct makes the file land as `[[devices]]` array-of-tables
/// rather than a bare top-level array, which is more forgiving to
/// hand-edit and lets us add sibling fields later without breaking
/// older readers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CacheFile {
    #[serde(default)]
    devices: Vec<CachedDevice>,
}

pub struct AppConfig {
    pub settings: Mutex<AppSettings>,
    /// Cached devices from prior sessions, keyed by MAC. Stored in
    /// `device_cache.toml` separately from settings so that any future
    /// settings-save bug structurally cannot wipe the cache. Mutated
    /// only via the cache mutation helpers below (called from the
    /// DeviceRegistry-backed IPC handlers in commands::network).
    cache: Mutex<Vec<CachedDevice>>,
    /// User-facing messages about salvage actions taken during load —
    /// e.g. a corrupted file quarantined and defaults applied. The
    /// frontend fetches these once at init and surfaces them as error
    /// toasts; without this, a settings reset is invisible to the user.
    startup_notices: Mutex<Vec<String>>,
}

fn update_cached_alias_in_place(cache: &mut [CachedDevice], mac: &str, alias: &str) -> bool {
    match cache.iter_mut().find(|device| device.mac == mac) {
        Some(device) if device.alias != alias => {
            device.alias = alias.to_string();
            true
        }
        _ => false,
    }
}

impl AppConfig {
    #[cfg(test)]
    pub(crate) fn temporary_test_config(settings: AppSettings) -> Self {
        Self {
            settings: Mutex::new(settings),
            cache: Mutex::new(vec![]),
            startup_notices: Mutex::new(vec![]),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_temporary_test_binding(
        &self,
        subnet: &str,
        row: AdoptedMeta,
    ) -> Result<(), crate::AppError> {
        self.set_binding_with(subnet, row, |_| Ok(()))
    }

    pub(crate) fn reserve_temporary_with(
        &self,
        row: PendingAddress,
        persist: impl FnOnce(&AppSettings) -> Result<(), crate::AppError>,
    ) -> Result<(), crate::AppError> {
        self.change_settings_with(
            |s| {
                let owner = crate::network::device_registry::canonical_mac(&row.adapter_mac);
                if owner.is_none()
                    || owner
                        != s.selected_adapter_mac
                            .as_deref()
                            .and_then(crate::network::device_registry::canonical_mac)
                    || s.network_mode != NetworkMode::StaticAuto
                    || row.prefix != 24
                    || crate::validation::parse_camera_ip(&row.address).is_err()
                    || s.adopted_meta
                        .values()
                        .any(|m| m.address.as_ref() == Some(&row.address))
                    || s.pending_addresses
                        .iter()
                        .any(|p| p.adapter_mac == row.adapter_mac && p.address == row.address)
                {
                    return Err(crate::AppError::Network(
                        "Temporary address ownership unavailable or already reserved".into(),
                    ));
                }
                s.pending_addresses.push(row);
                Ok(())
            },
            persist,
        )
    }

    pub(crate) fn forget_temporary_with(
        &self,
        row: &PendingAddress,
        persist: impl FnOnce(&AppSettings) -> Result<(), crate::AppError>,
    ) -> Result<(), crate::AppError> {
        self.change_settings_with(
            |s| {
                s.pending_addresses.retain(|p| p != row);
                Ok(())
            },
            persist,
        )
    }
    pub fn load_or_default() -> Self {
        let mut notices = Vec::new();
        let mut settings = load_from_disk(&mut notices).unwrap_or_default();

        // Adoptions persisted by builds that predate lifecycle metadata
        // arrive with no `adopted_meta` entry. Backfill in memory (load
        // time as the adoption time, no device seen yet) rather than
        // writing back immediately — the next lifecycle save persists
        // it, and re-deriving on every load is idempotent.
        align_adopted_meta(
            &settings.adopted_subnets,
            &mut settings.adopted_meta,
            &chrono::Utc::now().to_rfc3339(),
        );

        // Cache loading: prefer the dedicated file. If it doesn't exist,
        // try to migrate the legacy `device_cache` field that lived in
        // `config.toml` before this split (one-time read, then we never
        // look there again — the next config.toml save naturally drops
        // the field since AppSettings doesn't contain it anymore).
        let cache = match load_cache_from_disk(&mut notices) {
            Some(c) => c,
            None => {
                let migrated = std::fs::read_to_string(config_path())
                    .ok()
                    .and_then(|content| extract_legacy_device_cache(&content))
                    .unwrap_or_default();
                if !migrated.is_empty() {
                    log::info!(
                        "Migrating {} cached device(s) from legacy config.toml \
                         to device_cache.toml",
                        migrated.len()
                    );
                    if let Err(e) = save_cache_to_disk(&migrated) {
                        log::warn!("Failed to write migrated cache file: {}", e);
                    }
                }
                migrated
            }
        };

        Self {
            settings: Mutex::new(settings),
            cache: Mutex::new(cache),
            startup_notices: Mutex::new(notices),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(settings: AppSettings) -> Self {
        Self {
            settings: Mutex::new(settings),
            cache: Mutex::new(Vec::new()),
            startup_notices: Mutex::new(Vec::new()),
        }
    }

    /// Messages about salvage actions taken during load, for the
    /// frontend to surface once at startup.
    pub fn startup_notices(&self) -> Vec<String> {
        match self.startup_notices.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn save(&self) -> Result<(), crate::AppError> {
        let _save_guard = CONFIG_SAVE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let settings = match self.settings.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                log::error!("Config mutex poisoned during save, recovering");
                poisoned.into_inner().clone()
            }
        };
        save_to_disk(&settings)
    }

    pub fn get(&self) -> AppSettings {
        match self.settings.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                log::error!("Config mutex poisoned during get, recovering");
                poisoned.into_inner().clone()
            }
        }
    }

    // NOTE: there is deliberately no whole-struct `update(AppSettings)`
    // setter. Every writer below owns one field group; a frontend
    // get→mutate→replace cycle over the whole struct would race concurrent
    // backend writers of unrelated sections.

    /// Replace just the stream config and persist.
    pub fn update_stream(&self, stream: StreamConfig) -> Result<(), crate::AppError> {
        self.update_stream_with(stream, save_to_disk)
    }

    fn update_stream_with(
        &self,
        stream: StreamConfig,
        persist: impl FnOnce(&AppSettings) -> Result<(), crate::AppError>,
    ) -> Result<(), crate::AppError> {
        self.change_settings_with(
            |settings| {
                settings.stream = stream;
                crate::settings_validation::validate_prospective_settings(settings.clone())?;
                Ok(())
            },
            persist,
        )
    }

    /// Atomically persist the shared Enable field and both protocol sections,
    /// then publish the same validated snapshot in memory. The caller owns
    /// the surrounding runtime stop/restore/restart transaction, so no narrow
    /// re-stream writer can expose a partially updated configuration.
    pub fn commit_restream_settings(
        &self,
        rtsp_server: RtspServerConfig,
        srt_server: SrtServerConfig,
    ) -> Result<AppSettings, crate::AppError> {
        self.commit_restream_settings_with(rtsp_server, srt_server, save_to_disk)
    }

    pub(crate) fn commit_restream_settings_with<F>(
        &self,
        rtsp_server: RtspServerConfig,
        srt_server: SrtServerConfig,
        persist: F,
    ) -> Result<AppSettings, crate::AppError>
    where
        F: FnOnce(&AppSettings) -> Result<(), crate::AppError>,
    {
        let _save_guard = CONFIG_SAVE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut prospective = self.get();
        prospective.rtsp_server = rtsp_server.clone();
        prospective.srt_server = srt_server.clone();
        let prospective = crate::settings_validation::validate_prospective_settings(prospective)?;
        persist(&prospective)?;
        match self.settings.lock() {
            Ok(mut guard) => {
                guard.rtsp_server = rtsp_server;
                guard.srt_server = srt_server;
            }
            Err(poisoned) => {
                log::error!("Config mutex poisoned during re-stream commit, recovering");
                let mut guard = poisoned.into_inner();
                guard.rtsp_server = rtsp_server;
                guard.srt_server = srt_server;
            }
        }
        Ok(prospective)
    }

    /// Atomically persist the output selector before publishing it in memory.
    /// StreamManager owns the surrounding stop/restore/restart transaction.
    pub fn commit_restream_protocol(
        &self,
        protocol: RestreamProtocol,
    ) -> Result<AppSettings, crate::AppError> {
        self.commit_restream_protocol_with(protocol, save_to_disk)
    }

    pub(crate) fn commit_restream_protocol_with<F>(
        &self,
        protocol: RestreamProtocol,
        persist: F,
    ) -> Result<AppSettings, crate::AppError>
    where
        F: FnOnce(&AppSettings) -> Result<(), crate::AppError>,
    {
        let _save_guard = CONFIG_SAVE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut prospective = self.get();
        prospective.restream_protocol = protocol;
        let prospective = crate::settings_validation::validate_prospective_settings(prospective)?;
        persist(&prospective)?;
        match self.settings.lock() {
            Ok(mut guard) => guard.restream_protocol = protocol,
            Err(poisoned) => {
                log::error!("Config mutex poisoned during re-stream selector commit, recovering");
                poisoned.into_inner().restream_protocol = protocol;
            }
        }
        Ok(prospective)
    }

    /// Liveness writes cannot change ownership, desired state, or saved addresses.
    pub fn update_adoption_liveness(
        &self,
        meta: HashMap<String, AdoptedMeta>,
    ) -> Result<(), crate::AppError> {
        self.change_settings_with(
            |s| {
                for (subnet, incoming) in meta {
                    if let Some(row) = s.adopted_meta.get_mut(&subnet) {
                        if row.desired == BindingDesired::Present && row.address == incoming.address
                        {
                            row.last_device_seen = incoming.last_device_seen;
                        }
                    }
                }
                Ok(())
            },
            save_to_disk,
        )
    }

    /// Persist an observed binding state. Late status/restore writes cannot
    /// overwrite removal intent. Fresh adoption first retires a completed
    /// removal after verifying native absence under the address-work lock.
    pub fn set_binding(&self, subnet: &str, row: AdoptedMeta) -> Result<(), crate::AppError> {
        self.set_binding_with(subnet, row, save_to_disk)
    }

    pub fn set_binding_intent(
        &self,
        subnet: &str,
        row: AdoptedMeta,
    ) -> Result<(), crate::AppError> {
        self.set_binding_for_operation_with(subnet, row, true, save_to_disk)
    }
    fn set_binding_with(
        &self,
        subnet: &str,
        row: AdoptedMeta,
        persist: impl FnOnce(&AppSettings) -> Result<(), crate::AppError>,
    ) -> Result<(), crate::AppError> {
        self.set_binding_for_operation_with(subnet, row, false, persist)
    }

    pub(crate) fn set_binding_for_operation_with(
        &self,
        subnet: &str,
        row: AdoptedMeta,
        force_intent: bool,
        persist: impl FnOnce(&AppSettings) -> Result<(), crate::AppError>,
    ) -> Result<(), crate::AppError> {
        self.change_settings_if_with(
            |s| {
                let needs_handover = row.desired == BindingDesired::Present
                    && row.applied
                    && row.last_error.is_none()
                    && s.pending_addresses.iter().any(|p| {
                        Some(&p.adapter_mac) == row.adapter_mac.as_ref()
                            && Some(&p.address) == row.address.as_ref()
                            && Some(p.prefix) == row.prefix
                    });
                if !force_intent && s.adopted_meta.get(subnet) == Some(&row) && !needs_handover {
                    return Ok(((), false));
                }
                if row.desired == BindingDesired::Present
                    && s.adopted_meta
                        .get(subnet)
                        .is_some_and(|m| m.desired == BindingDesired::Removed)
                {
                    return Err(crate::AppError::Network(
                        "Binding was removed by the user".into(),
                    ));
                }
                if row.desired == BindingDesired::Removed {
                    remove_adoption_entry(&mut s.adopted_subnets, &mut s.adopted_meta, subnet);
                } else if let Some(address) = &row.address {
                    s.adopted_subnets
                        .entry(subnet.to_string())
                        .or_insert_with(|| address.clone());
                }
                if row.desired == BindingDesired::Present && row.applied && row.last_error.is_none()
                {
                    s.pending_addresses.retain(|p| {
                        Some(&p.adapter_mac) != row.adapter_mac.as_ref()
                            || Some(&p.address) != row.address.as_ref()
                            || Some(p.prefix) != row.prefix
                    });
                }
                s.adopted_meta.insert(subnet.to_string(), row);
                Ok(((), true))
            },
            persist,
        )
    }

    /// Explicit cleanup of a legacy binding after the caller observes its address
    /// absent from every native adapter under the address-work lock. This never
    /// grants ownership to the selected adapter or creates an OS removal intent.
    pub(crate) fn forget_unowned_binding(
        &self,
        subnet: &str,
        expected: &AdoptedMeta,
    ) -> Result<(), crate::AppError> {
        self.forget_unowned_binding_with(subnet, expected, save_to_disk)
    }

    pub(crate) fn forget_unowned_binding_with(
        &self,
        subnet: &str,
        expected: &AdoptedMeta,
        persist: impl FnOnce(&AppSettings) -> Result<(), crate::AppError>,
    ) -> Result<(), crate::AppError> {
        self.change_settings_with(
            |s| {
                if expected.adapter_mac.is_some()
                    || expected.address.is_none()
                    || s.adopted_meta.get(subnet) != Some(expected)
                    || s.adopted_subnets
                        .get(subnet)
                        .is_some_and(|ip| Some(ip) != expected.address.as_ref())
                    || s.pending_addresses
                        .iter()
                        .any(|p| Some(&p.address) == expected.address.as_ref())
                {
                    return Err(crate::AppError::Network(
                        "Saved binding changed or address ownership is pending; retry removal"
                            .into(),
                    ));
                }
                s.adopted_subnets.remove(subnet);
                s.adopted_meta.remove(subnet);
                Ok(())
            },
            persist,
        )
    }

    pub fn claim_binding(&self, address: &str) -> Result<(), crate::AppError> {
        self.claim_binding_with(address, save_to_disk)
    }

    pub(crate) fn forget_completed_removal(
        &self,
        subnet: &str,
        expected: &AdoptedMeta,
    ) -> Result<(), crate::AppError> {
        self.forget_completed_removal_with(subnet, expected, save_to_disk)
    }

    pub(crate) fn forget_completed_removal_with(
        &self,
        subnet: &str,
        expected: &AdoptedMeta,
        persist: impl FnOnce(&AppSettings) -> Result<(), crate::AppError>,
    ) -> Result<(), crate::AppError> {
        self.change_settings_with(
            |s| {
                let owner = expected
                    .adapter_mac
                    .as_deref()
                    .and_then(crate::network::device_registry::canonical_mac);
                if !expected.removal_complete()
                    || s.adopted_meta.get(subnet) != Some(expected)
                    || s.adopted_subnets.contains_key(subnet)
                    || s.network_mode != NetworkMode::StaticAuto
                    || owner.is_none()
                    || owner
                        != s.selected_adapter_mac
                            .as_deref()
                            .and_then(crate::network::device_registry::canonical_mac)
                {
                    return Err(crate::AppError::Network(
                        "Saved removal changed or is not complete".into(),
                    ));
                }
                s.adopted_meta.remove(subnet);
                Ok(())
            },
            persist,
        )
    }

    pub(crate) fn claim_binding_with(
        &self,
        address: &str,
        persist: impl FnOnce(&AppSettings) -> Result<(), crate::AppError>,
    ) -> Result<(), crate::AppError> {
        self.change_settings_with(
            |s| {
                s.pending_addresses.retain(|p| {
                    p.address != address
                        || crate::network::device_registry::canonical_mac(&p.adapter_mac)
                            != s.selected_adapter_mac
                                .as_deref()
                                .and_then(crate::network::device_registry::canonical_mac)
                });
                let keys: Vec<_> = s
                    .adopted_meta
                    .iter()
                    .filter(|(_, row)| {
                        row.address.as_deref() == Some(address)
                            && row.adapter_mac.as_ref().is_none_or(|owner| {
                                s.selected_adapter_mac.as_ref().is_some_and(|selected| {
                                    crate::network::device_registry::canonical_mac(owner)
                                        == crate::network::device_registry::canonical_mac(selected)
                                })
                            })
                    })
                    .map(|(key, _)| key.clone())
                    .collect();
                for key in keys {
                    s.adopted_subnets.remove(&key);
                    s.adopted_meta.remove(&key);
                }
                Ok(())
            },
            persist,
        )
    }

    /// The same write-before-publish seam as manual-node identity binding.
    fn change_settings_with<T>(
        &self,
        change: impl FnOnce(&mut AppSettings) -> Result<T, crate::AppError>,
        persist: impl FnOnce(&AppSettings) -> Result<(), crate::AppError>,
    ) -> Result<T, crate::AppError> {
        self.change_settings_if_with(|s| change(s).map(|value| (value, true)), persist)
    }
    fn change_settings_if_with<T>(
        &self,
        change: impl FnOnce(&mut AppSettings) -> Result<(T, bool), crate::AppError>,
        persist: impl FnOnce(&AppSettings) -> Result<(), crate::AppError>,
    ) -> Result<T, crate::AppError> {
        let _save = CONFIG_SAVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut settings = self.settings.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = settings.clone();
        let (result, changed) = change(&mut next)?;
        if changed {
            persist(&next)?;
            *settings = next;
        }
        Ok(result)
    }

    /// Persist one zoom-slider position (clamped to 0–100). Field-scoped
    /// for the same reason as `update_adoption_state`.
    pub fn update_zoom_position(
        &self,
        camera_ip: String,
        percent: i32,
    ) -> Result<(), crate::AppError> {
        let clamped = percent.clamp(0, 100);
        match self.settings.lock() {
            Ok(mut guard) => {
                guard.zoom_positions.insert(camera_ip, clamped);
            }
            Err(poisoned) => {
                log::error!("Config mutex poisoned during update_zoom_position, recovering");
                poisoned
                    .into_inner()
                    .zoom_positions
                    .insert(camera_ip, clamped);
            }
        }
        self.save()
    }

    /// Replace just the credentials and persist.
    pub fn update_credentials(&self, credentials: Credentials) -> Result<(), crate::AppError> {
        match self.settings.lock() {
            Ok(mut guard) => guard.credentials = credentials,
            Err(poisoned) => {
                log::error!("Config mutex poisoned during update_credentials, recovering");
                poisoned.into_inner().credentials = credentials;
            }
        }
        self.save()
    }

    /// Read the current network mode.
    pub fn get_network_mode(&self) -> NetworkMode {
        match self.settings.lock() {
            Ok(guard) => guard.network_mode,
            Err(poisoned) => {
                log::error!("Config mutex poisoned during get_network_mode, recovering");
                poisoned.into_inner().network_mode
            }
        }
    }

    /// Persist before exposing the new selection to network operations.
    pub fn set_selected_adapter_mac(&self, mac: String) -> Result<(), crate::AppError> {
        let _save = CONFIG_SAVE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut settings = self.settings.lock().unwrap_or_else(|p| p.into_inner());
        let mut next = settings.clone();
        next.selected_adapter_mac = Some(mac);
        save_to_disk(&next)?;
        *settings = next;
        Ok(())
    }

    /// Replace the network mode and persist.
    pub fn set_network_mode(&self, mode: NetworkMode) -> Result<(), crate::AppError> {
        self.change_settings_with(
            |s| {
                s.network_mode = mode;
                Ok(())
            },
            save_to_disk,
        )
    }

    pub(crate) fn set_primary_address(&self, mac: &str, cidr: &str) -> Result<(), crate::AppError> {
        self.set_primary_address_with(mac, cidr, save_to_disk)
    }

    pub(crate) fn set_primary_address_with(
        &self,
        mac: &str,
        cidr: &str,
        persist: impl FnOnce(&AppSettings) -> Result<(), crate::AppError>,
    ) -> Result<(), crate::AppError> {
        let mac = crate::network::device_registry::canonical_mac(mac)
            .ok_or_else(|| crate::AppError::Config("Invalid primary adapter MAC".into()))?;
        if !cidr.is_empty() {
            crate::validation::parse_cidr(cidr)?;
        }
        self.change_settings_with(
            |s| {
                s.primary_addresses.insert(mac, cidr.into());
                Ok(())
            },
            persist,
        )
    }

    /// Replace just the audio mute preference and persist.
    pub fn set_audio_muted(&self, muted: bool) -> Result<(), crate::AppError> {
        match self.settings.lock() {
            Ok(mut guard) => guard.stream.audio_muted = muted,
            Err(poisoned) => {
                log::error!("Config mutex poisoned during set_audio_muted, recovering");
                poisoned.into_inner().stream.audio_muted = muted;
            }
        }
        self.save()
    }

    /// Snapshot of the manual-nodes list.
    pub fn get_manual_nodes(&self) -> Vec<ManualNode> {
        match self.settings.lock() {
            Ok(guard) => guard.manual_nodes.clone(),
            Err(poisoned) => {
                log::error!("Config mutex poisoned during get_manual_nodes, recovering");
                poisoned.into_inner().manual_nodes.clone()
            }
        }
    }

    /// Add a manual node. If an entry with the same IP exists, its alias
    /// is updated in place rather than producing a duplicate row.
    pub fn add_manual_node(&self, node: ManualNode) -> Result<(), crate::AppError> {
        let mut guard = match self.settings.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!("Config mutex poisoned during add_manual_node, recovering");
                poisoned.into_inner()
            }
        };
        if let Some(existing) = guard.manual_nodes.iter_mut().find(|n| n.ip == node.ip) {
            if existing.expected_mac.is_some()
                && node.expected_mac.is_some()
                && existing.expected_mac != node.expected_mac
            {
                return Err(crate::AppError::Network(
                    "different device at this address; remove the old pin before reassigning"
                        .into(),
                ));
            }
            existing.alias = node.alias;
            if existing.expected_mac.is_none() {
                existing.expected_mac = node.expected_mac;
            }
        } else {
            guard.manual_nodes.push(node);
        }
        drop(guard);
        self.save()
    }

    /// Update the alias of an existing manual node in place. Returns
    /// Ok(true) when a pinned entry existed and actually changed (and
    /// was saved); Ok(false) when the IP isn't pinned or the alias
    /// already matches. Used by the role single-holder enforcement to
    /// write demotions through to config — a registry-only demotion
    /// would resurrect on the next manual-node hydration.
    pub fn update_manual_node_alias(
        &self,
        key: &str,
        alias: &str,
    ) -> Result<bool, crate::AppError> {
        let changed = {
            let mut guard = match self.settings.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    log::error!(
                        "Config mutex poisoned during update_manual_node_alias, recovering"
                    );
                    poisoned.into_inner()
                }
            };
            match guard
                .manual_nodes
                .iter_mut()
                .find(|n| manual_node_key(n).eq_ignore_ascii_case(key))
            {
                Some(node) if node.alias != alias => {
                    node.alias = alias.to_string();
                    true
                }
                _ => false,
            }
        };
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    /// Persist first-verification identity before the registry can promote it.
    #[allow(dead_code)] // S5a's presence task consumes this transaction.
    pub(crate) fn bind_manual_node(
        &self,
        ip: &str,
        mac: &str,
        fence: &crate::network::SweepFence,
    ) -> Result<ManualNode, crate::AppError> {
        self.bind_manual_node_with(ip, mac, fence, save_to_disk)
    }

    fn bind_manual_node_with(
        &self,
        ip: &str,
        mac: &str,
        fence: &crate::network::SweepFence,
        save: impl FnOnce(&AppSettings) -> Result<(), crate::AppError>,
    ) -> Result<ManualNode, crate::AppError> {
        let mac = crate::network::device_registry::canonical_mac(mac)
            .ok_or_else(|| crate::AppError::Network("Invalid device MAC".into()))?;
        let _save = CONFIG_SAVE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut settings = self.settings.lock().unwrap_or_else(|p| p.into_inner());
        if fence.is_stale() {
            return Err(crate::AppError::Network("verification retired".into()));
        }
        let mut next = settings.clone();
        let node = next
            .manual_nodes
            .iter_mut()
            .find(|n| n.ip == ip)
            .ok_or_else(|| crate::AppError::Network("manual node no longer exists".into()))?;
        let changed = bind_manual_identity(node, &mac);
        let bound = node.clone();
        if changed {
            save(&next)?;
            *settings = next;
            log::info!(
                "Manual node {} bound on first fresh verification to {}",
                ip,
                mac
            );
        }
        Ok(bound)
    }

    /// Compare the expected identity too, so a stale removal cannot delete a new pin.
    pub fn remove_manual_node(
        &self,
        ip: &str,
        expected_mac: Option<&str>,
    ) -> Result<bool, crate::AppError> {
        let _save = CONFIG_SAVE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut settings = self.settings.lock().unwrap_or_else(|p| p.into_inner());
        let mut next = settings.clone();
        next.manual_nodes
            .retain(|n| n.ip != ip || !same_expected_mac(n.expected_mac.as_deref(), expected_mac));
        if next.manual_nodes.len() == settings.manual_nodes.len() {
            return Ok(false);
        }
        save_to_disk(&next)?;
        *settings = next;
        Ok(true)
    }

    /// Drop every pinned manual node.
    pub fn clear_manual_nodes(&self) -> Result<(), crate::AppError> {
        match self.settings.lock() {
            Ok(mut guard) => guard.manual_nodes.clear(),
            Err(poisoned) => {
                log::error!("Config mutex poisoned during clear_manual_nodes, recovering");
                poisoned.into_inner().manual_nodes.clear();
            }
        }
        self.save()
    }

    /// Snapshot of the current device cache. Returns a clone so the
    /// caller can drop the lock immediately.
    pub fn get_cache(&self) -> Vec<CachedDevice> {
        match self.cache.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                log::error!("Cache mutex poisoned during get, recovering");
                poisoned.into_inner().clone()
            }
        }
    }

    /// Update only the alias of an existing cached row, including legacy
    /// or temporarily-unreachable rows whose open-port list is empty.
    /// Never inserts a new row: manual/synthetic records with no scan
    /// result do not belong in the device cache. Returns whether a row
    /// actually changed.
    pub fn update_cached_device_alias(
        &self,
        mac: &str,
        alias: &str,
    ) -> Result<bool, crate::AppError> {
        let changed = match self.cache.lock() {
            Ok(mut guard) => update_cached_alias_in_place(&mut guard, mac, alias),
            Err(poisoned) => {
                log::error!("Cache mutex poisoned during alias update, recovering");
                let mut guard = poisoned.into_inner();
                update_cached_alias_in_place(&mut guard, mac, alias)
            }
        };
        if changed {
            self.save_cache()?;
        }
        Ok(changed)
    }

    /// Insert or update a cached device entry (keyed by MAC).
    /// Persists the cache file after mutation.
    pub fn upsert_cached_device(&self, device: CachedDevice) -> Result<(), crate::AppError> {
        self.upsert_cached_device_fenced(device, None)
    }

    pub(crate) fn upsert_cached_device_fenced(
        &self,
        device: CachedDevice,
        fence: Option<&crate::network::SweepFence>,
    ) -> Result<(), crate::AppError> {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if !upsert_cache_record(&mut cache, device, fence) {
            return Ok(());
        }
        drop(cache);
        self.save_cache()
    }

    /// Remove a cached device by MAC address.
    /// No-op if the MAC is not present.
    pub fn remove_cached_device(&self, mac: &str) -> Result<(), crate::AppError> {
        let removed = match self.cache.lock() {
            Ok(mut guard) => {
                let before = guard.len();
                guard.retain(|d| d.mac != mac);
                before != guard.len()
            }
            Err(poisoned) => {
                log::error!("Cache mutex poisoned during remove, recovering");
                let mut guard = poisoned.into_inner();
                let before = guard.len();
                guard.retain(|d| d.mac != mac);
                before != guard.len()
            }
        };
        if removed {
            self.save_cache()
        } else {
            Ok(())
        }
    }

    fn save_cache(&self) -> Result<(), crate::AppError> {
        let _save_guard = CACHE_SAVE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let cache = match self.cache.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                log::error!("Cache mutex poisoned during save, recovering");
                poisoned.into_inner().clone()
            }
        };
        save_cache_to_disk(&cache)
    }
}

/// Serialize complete save cycles (snapshot clone → serialize → write)
/// per file. Unique staging names in `atomic_write` prevent torn staging
/// files, but two concurrent saves could still clone their snapshots in
/// one order and rename in the other, persisting the older snapshot.
/// Holding one of these across the clone makes snapshot order match
/// write order — which is why `save`/`save_cache` take it BEFORE locking
/// the data mutex, not inside the write helper.
static CONFIG_SAVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn upsert_cache_record(
    cache: &mut Vec<CachedDevice>,
    device: CachedDevice,
    fence: Option<&crate::network::SweepFence>,
) -> bool {
    if fence.is_some_and(|f| f.is_stale()) {
        return false;
    }
    if let Some(existing) = cache.iter_mut().find(|r| r.mac == device.mac) {
        *existing = device;
    } else {
        cache.push(device);
    }
    true
}

pub(crate) fn manual_node_key(node: &ManualNode) -> String {
    node.expected_mac
        .clone()
        .unwrap_or_else(|| format!("manual:{}", node.ip))
}

fn same_expected_mac(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    }
}

fn bind_manual_identity(node: &mut ManualNode, mac: &str) -> bool {
    if node.expected_mac.is_some() {
        return false;
    }
    node.expected_mac = Some(mac.into());
    true
}

static CACHE_SAVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("PocketStream")
}

fn config_path() -> PathBuf {
    config_dir().join("config.toml")
}

fn cache_path() -> PathBuf {
    config_dir().join("device_cache.toml")
}

fn key_path() -> PathBuf {
    config_dir().join(".key")
}

fn load_cache_from_disk(notices: &mut Vec<String>) -> Option<Vec<CachedDevice>> {
    let path = cache_path();
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            log::error!("config: failed to read {}: {}", path.display(), e);
            return None;
        }
    };
    parse_cache(&content, &path, notices)
}

/// Parse the device-cache TOML; on failure quarantine the file and
/// record a user-facing startup notice. Split from `load_cache_from_disk`
/// so the salvage behavior is testable without touching the real path.
fn parse_cache(content: &str, path: &Path, notices: &mut Vec<String>) -> Option<Vec<CachedDevice>> {
    match toml::from_str::<CacheFile>(content) {
        Ok(parsed) => Some(parsed.devices),
        Err(e) => {
            log::error!(
                "config: device_cache.toml parse failed ({}). Moving aside to {} \
                 so the next save can write a clean file; cached devices will be \
                 rebuilt from the next ARP sweep.",
                e,
                quarantine_path(path).display()
            );
            quarantine(path);
            notices.push(format!(
                "The saved device cache could not be read; it was preserved as {} \
                 and devices will be rediscovered on the next network sweep.",
                quarantine_file_name(path)
            ));
            None
        }
    }
}

fn save_cache_to_disk(cache: &[CachedDevice]) -> Result<(), crate::AppError> {
    let dir = config_dir();
    fs::create_dir_all(&dir).map_err(|e| crate::AppError::Config(e.to_string()))?;
    let file = CacheFile {
        devices: cache.to_vec(),
    };
    let content =
        toml::to_string_pretty(&file).map_err(|e| crate::AppError::Config(e.to_string()))?;
    atomic_write(&cache_path(), content.as_bytes())
        .map_err(|e| crate::AppError::Config(e.to_string()))?;
    Ok(())
}

/// Monotonic discriminator for staging-file names. Combined with the
/// process id it gives every in-flight write its own staging file, so
/// concurrent writers to the same path can't truncate each other's
/// staged bytes and rename a torn file into place.
static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Crash-safe file write: stage to a uniquely-named `.tmp` sibling,
/// fsync, then rename onto the final path. The rename is atomic on NTFS
/// and on POSIX filesystems (same-volume rename is a single inode
/// operation), so a reader either sees the old complete file or the new
/// complete file — never a half-written one. Replaces the prior
/// `fs::write` calls in the config save paths, where a kill -9
/// mid-write would leave a truncated TOML and the next launch would
/// silently fall back to defaults.
fn atomic_write(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    fs::create_dir_all(parent)?;

    // Suffix on the full filename rather than via with_extension —
    // config.toml.<pid>.<n>.tmp is more obviously a staging file than
    // config.tmp, and avoids stomping a sibling file that happens to
    // share the stem. pid+counter uniqueness means an abandoned staging
    // file from a crashed run is simply ignored, never renamed over.
    let mut tmp_name = path
        .file_name()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
        })?
        .to_owned();
    tmp_name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let tmp_path = parent.join(&tmp_name);

    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(content)?;
        file.sync_all()?;
    }

    // On Unix the directory entry change isn't durable until we fsync
    // the parent dir too; on Windows the rename itself is journaled so
    // the parent fsync is unnecessary (and File::open on a directory
    // would fail anyway).
    if let Err(e) = fs::rename(&tmp_path, path) {
        // Don't leave uniquely-named staging orphans behind on failure.
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    #[cfg(unix)]
    {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Build the quarantine path for a corrupted file. Pure function so the
/// log message and the rename target stay in sync.
fn quarantine_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_owned())
        .unwrap_or_else(|| std::ffi::OsString::from("config"));
    name.push(".parse-error");
    path.parent()
        .map(|p| p.join(&name))
        .unwrap_or_else(|| PathBuf::from(name))
}

/// File name (not full path) of the quarantine target, for user-facing
/// notices where the full path would be noise.
fn quarantine_file_name(path: &Path) -> String {
    quarantine_path(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "parse-error".into())
}

/// Move a corrupted config file aside. Best-effort — if the rename
/// fails (e.g., quarantine target also exists from a prior failure)
/// the original stays put and the next save will overwrite it via
/// atomic_write. Either way the user isn't worse off than the prior
/// silent-default behavior.
fn quarantine(path: &Path) {
    let dest = quarantine_path(path);
    if let Err(e) = fs::rename(path, &dest) {
        log::warn!(
            "config: failed to quarantine corrupted {} to {}: {}",
            path.display(),
            dest.display(),
            e
        );
    }
}

/// Pull the legacy `device_cache` array out of an older `config.toml`
/// that pre-dates the cache-file split. Returns `None` if the field is
/// absent or unparseable. One-shot use during `load_or_default` only.
fn extract_legacy_device_cache(toml_content: &str) -> Option<Vec<CachedDevice>> {
    let value: toml::Value = toml::from_str(toml_content).ok()?;
    let cache_value = value.get("device_cache")?.clone();
    cache_value.try_into().ok()
}

/// Parse the settings TOML; on failure quarantine the file and record a
/// user-facing startup notice. Split from `load_from_disk` so the
/// salvage behavior is testable without touching the real config path.
/// The notice mentions the token because falling back to defaults
/// regenerates the RTSP access token, which invalidates saved client
/// URLs.
fn parse_settings(
    content: &str,
    path: &Path,
    notices: &mut Vec<String>,
    key: Option<&[u8]>,
) -> Option<AppSettings> {
    let parsed = match toml::from_str::<PersistedAppSettings>(content) {
        Ok(settings) => runtime_settings_from_persisted(settings, key),
        Err(error) => Err(crate::AppError::Config(error.to_string())),
    };
    match parsed {
        Ok(settings) => Some(settings),
        Err(error) => {
            log::error!(
                "config: config.toml parse failed ({}). Moving aside to {} and \
                 launching with defaults; the corrupted file is preserved for \
                 inspection.",
                error,
                quarantine_path(path).display()
            );
            quarantine(path);
            notices.push(format!(
                "Settings could not be read and were reset to defaults. The old \
                 file was preserved as {}, and the RTSP access token was \
                 regenerated.",
                quarantine_file_name(path)
            ));
            None
        }
    }
}

fn load_from_disk(notices: &mut Vec<String>) -> Option<AppSettings> {
    let path = config_path();
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            log::error!("config: failed to read {}: {}", path.display(), e);
            return None;
        }
    };

    // A transient key read error does not regenerate the key. Camera
    // credentials follow their established clear-for-this-load policy; a
    // non-empty SRT ciphertext becomes Unavailable and remains preserved.
    let key: Option<[u8; 32]> = match read_key() {
        Ok(Some((key, _needs_rewrap))) => Some(key),
        Ok(None) => None,
        Err(error) => {
            log::error!(
                "config: encryption key is temporarily unreadable; protected fields will remain unavailable for this launch: {}",
                error
            );
            None
        }
    };
    parse_settings(&content, &path, notices, key.as_ref().map(|key| &key[..]))
}

/// Resolve stored (possibly encrypted) credential fields to plaintext.
/// `key` is `None` when no usable key is available — in that case a
/// non-empty (ciphertext) field is cleared, never passed through.
fn resolve_credentials(username: &str, password: &str, key: Option<&[u8]>) -> (String, String) {
    match key {
        Some(k) if k.len() == 32 => (
            decrypt_field(username, k, "username"),
            decrypt_field(password, k, "password"),
        ),
        _ => {
            if !username.is_empty() || !password.is_empty() {
                log::error!(
                    "config: stored credentials present but the encryption key is \
                     unavailable — clearing so they aren't re-encrypted as garbage. \
                     Re-enter them in Settings."
                );
            }
            (String::new(), String::new())
        }
    }
}

/// Decrypt one credential field, applying the clear-on-failure policy:
/// an empty field stays empty silently; a non-empty field that fails to
/// decrypt (corruption or wrong key) is logged and cleared.
fn decrypt_field(field: &str, key: &[u8], label: &str) -> String {
    match decrypt_string(field, key) {
        Some(s) => s,
        None if field.is_empty() => String::new(),
        None => {
            log::error!(
                "config: failed to decrypt stored {} — clearing. \
                 User will need to re-enter credentials.",
                label
            );
            String::new()
        }
    }
}

pub(crate) fn save_to_disk(settings: &AppSettings) -> Result<(), crate::AppError> {
    let dir = config_dir();
    fs::create_dir_all(&dir).map_err(|e| crate::AppError::Config(e.to_string()))?;

    let key_bytes = get_or_create_key()?;
    save_settings_to_path_with_srt_encryptor(
        settings,
        &config_path(),
        &key_bytes,
        encrypt_string_checked,
    )
}

/// DPAPI-wrap bytes for the current user (Windows). Returns the opaque
/// blob to store on disk, or None if the OS call fails.
#[cfg(windows)]
fn dpapi_protect(plain: &[u8]) -> Option<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: plain.len() as u32,
            pbData: plain.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = CryptProtectData(
            &in_blob,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        );
        if ok == 0 || out_blob.pbData.is_null() {
            return None;
        }
        let bytes = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        LocalFree(out_blob.pbData as _);
        Some(bytes)
    }
}

/// DPAPI-unwrap a blob produced by [`dpapi_protect`] for the current
/// user (Windows). Returns None if the blob can't be decrypted (wrong
/// user, corruption).
#[cfg(windows)]
fn dpapi_unprotect(blob: &[u8]) -> Option<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: blob.len() as u32,
            pbData: blob.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = CryptUnprotectData(
            &in_blob,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        );
        if ok == 0 || out_blob.pbData.is_null() {
            return None;
        }
        let bytes = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        LocalFree(out_blob.pbData as _);
        Some(bytes)
    }
}

/// Read the 32-byte AES key from `path`.
///
/// Returns `Ok(Some((key, needs_rewrap)))` for a usable key —
/// `needs_rewrap` flags a legacy unprotected key that should be upgraded
/// to DPAPI on the next write. `Ok(None)` means the key is absent
/// (regenerate is correct) or a DPAPI blob that won't decrypt for this
/// user (unrecoverable — regenerate). `Err` is reserved for transient
/// read failures (AV lock, permissions) where the caller must **not**
/// regenerate, so existing ciphertext isn't orphaned.
fn read_key_from(path: &Path) -> std::io::Result<Option<([u8; 32], bool)>> {
    let raw = match fs::read(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    // A file of exactly 32 bytes is a legacy raw key (pre-DPAPI). On
    // Windows it should be re-wrapped; on Unix it's the normal format.
    if raw.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);
        let needs_rewrap = cfg!(windows);
        return Ok(Some((key, needs_rewrap)));
    }

    #[cfg(windows)]
    {
        match dpapi_unprotect(&raw) {
            Some(plain) if plain.len() == 32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&plain);
                Ok(Some((key, false)))
            }
            // Blob present but unusable for this user — treat like absent
            // so a fresh key is generated (the old ciphertext is already
            // unrecoverable), never a hard failure.
            _ => Ok(None),
        }
    }
    #[cfg(not(windows))]
    {
        // Non-Windows only ever writes 32-byte raw keys; anything else is
        // unexpected — regenerate rather than fail.
        Ok(None)
    }
}

fn read_key() -> std::io::Result<Option<([u8; 32], bool)>> {
    read_key_from(&key_path())
}

/// Write the 32-byte key, DPAPI-wrapped on Windows, via `atomic_write`
/// (the previous plain `fs::write` could leave a truncated key on a
/// mid-write crash).
fn write_key_to(path: &Path, key: &[u8; 32]) -> Result<(), crate::AppError> {
    let on_disk: Vec<u8> = {
        #[cfg(windows)]
        {
            dpapi_protect(key).ok_or_else(|| {
                crate::AppError::Config("DPAPI protection of the encryption key failed".into())
            })?
        }
        #[cfg(not(windows))]
        {
            key.to_vec()
        }
    };

    atomic_write(path, &on_disk).map_err(|e| crate::AppError::Config(e.to_string()))?;

    // Restrict the key file to the current user. On Windows the DPAPI
    // wrap already binds it to the user account (and AppData inherits a
    // user-only ACL); on Unix the umask can default world-readable, so
    // set 0600 explicitly.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
            log::warn!("Failed to chmod 0600 on key file {}: {}", path.display(), e);
        }
    }

    Ok(())
}

fn get_or_create_key() -> Result<Vec<u8>, crate::AppError> {
    get_or_create_key_at(&key_path())
}

fn get_or_create_key_at(path: &Path) -> Result<Vec<u8>, crate::AppError> {
    match read_key_from(path) {
        Ok(Some((key, needs_rewrap))) => {
            if needs_rewrap {
                // Upgrade a legacy unprotected key to DPAPI in place. The
                // key bytes are unchanged, so existing ciphertext stays
                // valid; a failure is non-fatal (keep using the raw key).
                if let Err(e) = write_key_to(path, &key) {
                    log::warn!("Failed to upgrade encryption key to DPAPI: {}", e);
                }
            }
            Ok(key.to_vec())
        }
        Ok(None) => {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            write_key_to(path, &key)?;
            Ok(key.to_vec())
        }
        // Transient read failure — do NOT regenerate (that would orphan
        // the existing ciphertext). Fail the save so the caller retries.
        Err(e) => Err(crate::AppError::Config(format!(
            "encryption key is present but unreadable: {}",
            e
        ))),
    }
}

fn encrypt_string(plaintext: &str, key: &[u8]) -> String {
    encrypt_string_checked(plaintext, key).unwrap_or_else(|error| {
        // Preserve the established camera-credential behavior. SRT never
        // calls this lossy wrapper; its checked path aborts the whole save.
        log::error!("config: credential encryption failed: {}", error);
        String::new()
    })
}

fn encrypt_string_checked(plaintext: &str, key: &[u8]) -> Result<String, crate::AppError> {
    if plaintext.is_empty() {
        return Ok(String::new());
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| crate::AppError::Config("invalid protected-secret key length".into()))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).map_err(|_| {
        crate::AppError::Config(
            "protected-secret encryption failed; settings were not saved".into(),
        )
    })?;
    let mut combined = nonce_bytes.to_vec();
    combined.extend(ciphertext);
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &combined,
    ))
}

fn decrypt_string(encrypted: &str, key: &[u8]) -> Option<String> {
    if encrypted.is_empty() {
        return Some(String::new());
    }
    let combined =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encrypted).ok()?;
    if combined.len() < 12 {
        return None;
    }
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;
    String::from_utf8(plaintext).ok()
}

pub fn generate_token() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(&bytes)
}

// Inline hex encoding to avoid adding another dependency
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    pub(crate) const TEST_KEY: [u8; 32] = [0x42; 32];

    pub(crate) fn serialize_for_test(settings: &AppSettings) -> String {
        serialize_settings_with_srt_encryptor(settings, &TEST_KEY, encrypt_string_checked)
            .expect("test settings should serialize")
    }

    pub(crate) fn parse_for_test(content: &str) -> Result<AppSettings, crate::AppError> {
        let persisted: PersistedAppSettings =
            toml::from_str(content).map_err(|error| crate::AppError::Config(error.to_string()))?;
        runtime_settings_from_persisted(persisted, Some(&TEST_KEY))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::test_support::{parse_for_test, serialize_for_test, TEST_KEY};

    fn apply_stream_settings_for_test(settings: &mut AppSettings, incoming: AppSettings) {
        let config = AppConfig::for_test(settings.clone());
        config
            .update_stream_with(incoming.stream, |_| Ok(()))
            .unwrap();
        *settings = config.get();
    }

    #[test]
    fn protected_srt_and_durable_network_settings_round_trip_together() {
        let mut settings = AppSettings {
            selected_adapter_mac: Some("40:cd:3a:00:00:01".into()),
            ..Default::default()
        };
        settings
            .primary_addresses
            .insert("40:cd:3a:00:00:01".into(), "192.0.2.10/24".into());
        settings.pending_addresses.push(PendingAddress {
            adapter_mac: "40:cd:3a:00:00:01".into(),
            address: "198.51.100.100".into(),
            prefix: 24,
        });
        settings.restream_protocol = RestreamProtocol::Srt;
        settings.srt_server.passphrase = SrtPassphraseState::Available("merged-srt-secret".into());
        let encoded = serialize_for_test(&settings);
        assert!(!encoded.contains("merged-srt-secret"));
        let restored = parse_for_test(&encoded).unwrap();
        assert_eq!(restored.selected_adapter_mac, settings.selected_adapter_mac);
        assert_eq!(restored.primary_addresses, settings.primary_addresses);
        assert_eq!(restored.pending_addresses, settings.pending_addresses);
        assert_eq!(restored.restream_protocol, RestreamProtocol::Srt);
        assert!(restored.srt_server == settings.srt_server);
    }

    #[test]
    fn failed_stream_save_preserves_camera_identity_and_network_ownership() {
        let mut settings = AppSettings::default();
        settings.stream.camera_mac = Some("aa:bb:cc:dd:ee:01".into());
        settings.selected_adapter_mac = Some("40:cd:3a:00:00:01".into());
        let config = AppConfig::for_test(settings.clone());
        assert!(config
            .update_stream_with(
                StreamConfig {
                    camera_mac: Some("aa:bb:cc:dd:ee:02".into()),
                    ..settings.stream.clone()
                },
                |_| Err(crate::AppError::Config("save failed".into()))
            )
            .is_err());
        assert_eq!(config.get().stream.camera_mac, settings.stream.camera_mac);
        assert_eq!(
            config.get().selected_adapter_mac,
            settings.selected_adapter_mac
        );
    }

    // ── Encryption / Decryption ─────────────────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = vec![0xABu8; 32];
        let plaintext = "hunter2";
        let encrypted = encrypt_string(plaintext, &key);
        assert_ne!(encrypted, plaintext);
        assert!(!encrypted.is_empty());
        let decrypted = decrypt_string(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_unicode() {
        let key = vec![0x42u8; 32];
        let plaintext = "p\u{00e4}ssw\u{00f6}rd \u{1f512}";
        let encrypted = encrypt_string(plaintext, &key);
        let decrypted = decrypt_string(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // ── Credential resolution against the key state ─────────────────

    #[test]
    fn resolve_credentials_decrypts_with_key() {
        let key = [7u8; 32];
        let u = encrypt_string("admin", &key);
        let p = encrypt_string("s3cr3t", &key);
        let (du, dp) = resolve_credentials(&u, &p, Some(&key));
        assert_eq!(du, "admin");
        assert_eq!(dp, "s3cr3t");
    }

    #[test]
    fn resolve_credentials_clears_ciphertext_when_key_absent() {
        // The load-passthrough bug: without a key, non-empty (ciphertext)
        // fields must be cleared, not handed to the UI as literal creds.
        let key = [7u8; 32];
        let u = encrypt_string("admin", &key);
        let (du, dp) = resolve_credentials(&u, "", None);
        assert_eq!(du, "");
        assert_eq!(dp, "");
    }

    #[test]
    fn resolve_credentials_clears_on_wrong_key() {
        let key = [7u8; 32];
        let wrong = [9u8; 32];
        let u = encrypt_string("admin", &key);
        let (du, _) = resolve_credentials(&u, "", Some(&wrong));
        assert_eq!(du, "");
    }

    #[test]
    fn resolve_credentials_empty_stays_empty_without_key() {
        let (du, dp) = resolve_credentials("", "", None);
        assert_eq!(du, "");
        assert_eq!(dp, "");
    }

    // ── Key file read policy ────────────────────────────────────────

    #[test]
    fn read_key_absent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join(".key");
        assert!(read_key_from(&missing).unwrap().is_none());
    }

    #[test]
    fn read_key_legacy_32_bytes_is_usable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".key");
        fs::write(&path, [0x5Au8; 32]).unwrap();
        let (key, needs_rewrap) = read_key_from(&path).unwrap().unwrap();
        assert_eq!(key, [0x5Au8; 32]);
        // Legacy raw key is upgrade-worthy on Windows, already-normal on Unix.
        assert_eq!(needs_rewrap, cfg!(windows));
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_roundtrip() {
        let key = [0xC3u8; 32];
        let wrapped = dpapi_protect(&key).expect("DPAPI protect");
        assert_ne!(wrapped.as_slice(), &key[..]);
        let unwrapped = dpapi_unprotect(&wrapped).expect("DPAPI unprotect");
        assert_eq!(unwrapped, key.to_vec());
    }

    #[cfg(windows)]
    #[test]
    fn read_key_roundtrips_dpapi_blob() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".key");
        let key = [0x1Fu8; 32];
        let blob = dpapi_protect(&key).unwrap();
        fs::write(&path, &blob).unwrap();
        let (read, needs_rewrap) = read_key_from(&path).unwrap().unwrap();
        assert_eq!(read, key);
        assert!(!needs_rewrap); // already DPAPI-wrapped
    }

    #[test]
    fn encrypt_empty_returns_empty() {
        let key = vec![0x42u8; 32];
        assert_eq!(encrypt_string("", &key), "");
    }

    #[test]
    fn decrypt_empty_returns_empty() {
        let key = vec![0x42u8; 32];
        assert_eq!(decrypt_string("", &key), Some(String::new()));
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = vec![0xAAu8; 32];
        let key2 = vec![0xBBu8; 32];
        let encrypted = encrypt_string("secret", &key1);
        assert!(decrypt_string(&encrypted, &key2).is_none());
    }

    #[test]
    fn decrypt_truncated_ciphertext_fails() {
        let key = vec![0xCCu8; 32];
        // Base64 of 5 bytes (less than 12 byte nonce)
        let short =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [1, 2, 3, 4, 5]);
        assert!(decrypt_string(&short, &key).is_none());
    }

    #[test]
    fn decrypt_invalid_base64_fails() {
        let key = vec![0xDDu8; 32];
        assert!(decrypt_string("not-valid-base64!!!", &key).is_none());
    }

    #[test]
    fn decrypt_corrupted_ciphertext_fails() {
        let key = vec![0xEEu8; 32];
        let encrypted = encrypt_string("secret", &key);
        let mut combined =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &encrypted).unwrap();
        // Flip a byte in the ciphertext (after the 12-byte nonce)
        if combined.len() > 13 {
            combined[13] ^= 0xFF;
        }
        let corrupted =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &combined);
        assert!(decrypt_string(&corrupted, &key).is_none());
    }

    #[test]
    fn different_encryptions_produce_different_ciphertext() {
        let key = vec![0xFFu8; 32];
        let e1 = encrypt_string("same", &key);
        let e2 = encrypt_string("same", &key);
        // Random nonce means different ciphertext each time
        assert_ne!(e1, e2);
        // But both decrypt to the same value
        assert_eq!(
            decrypt_string(&e1, &key).unwrap(),
            decrypt_string(&e2, &key).unwrap()
        );
    }

    #[test]
    fn encrypt_long_plaintext() {
        let key = vec![0x11u8; 32];
        let plaintext = "A".repeat(10_000);
        let encrypted = encrypt_string(&plaintext, &key);
        let decrypted = decrypt_string(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // ── Token Generation ────────────────────────────────────────────

    #[test]
    fn generate_token_is_16_hex_chars() {
        let token = generate_token();
        assert_eq!(token.len(), 16);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_token_is_lowercase() {
        let token = generate_token();
        assert_eq!(token, token.to_lowercase());
    }

    #[test]
    fn generate_token_uniqueness() {
        let tokens: std::collections::HashSet<String> =
            (0..100).map(|_| generate_token()).collect();
        assert_eq!(tokens.len(), 100, "100 tokens should all be unique");
    }

    // ── Hex Encoding ────────────────────────────────────────────────

    #[test]
    fn hex_encode_basic() {
        assert_eq!(hex::encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
    }

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex::encode(&[]), "");
    }

    #[test]
    fn hex_encode_all_zeros() {
        assert_eq!(hex::encode(&[0, 0, 0]), "000000");
    }

    #[test]
    fn hex_encode_single_byte() {
        assert_eq!(hex::encode(&[0x0A]), "0a");
    }

    // ── Default Settings ────────────────────────────────────────────

    #[test]
    fn default_settings_stream_config() {
        let s = AppSettings::default();
        assert_eq!(s.stream.protocol, StreamProtocol::Rtsp);
        assert_eq!(s.stream.rtsp_port, 554);
        assert_eq!(s.stream.rtsp_path, "/z3-1.sdp");
        assert_eq!(s.stream.udp_port, 8600);
        assert!(s.stream.camera_ip.is_empty());
        // Audio is on by default; the mute button is the opt-out.
        assert!(!s.stream.audio_muted);
    }

    #[test]
    fn default_settings_rtsp_server() {
        let s = AppSettings::default();
        assert_eq!(s.restream_protocol, RestreamProtocol::Rtsp);
        assert!(!s.rtsp_server.enabled);
        assert_eq!(s.rtsp_server.port, 8554);
        assert!(!s.rtsp_server.token.is_empty());
        assert!(s.rtsp_server.bind_interface.is_empty());
    }

    #[test]
    fn default_settings_credentials_empty() {
        let s = AppSettings::default();
        assert!(s.credentials.username.is_empty());
        assert!(s.credentials.password.is_empty());
    }

    #[test]
    fn default_settings_srt_server_is_passwordless() {
        let s = AppSettings::default();
        assert_eq!(s.srt_server.port, 8_890);
        assert_eq!(s.srt_server.latency_ms, 125);
        assert!(s.srt_server.stream_id.is_empty());
        assert!(s.srt_server.bind_interface.is_empty());
        assert!(matches!(
            s.srt_server.passphrase,
            SrtPassphraseState::Unencrypted
        ));
    }

    #[test]
    fn settings_view_exposes_only_available_srt_plaintext() {
        let mut settings = AppSettings::default();

        let unencrypted = serde_json::to_value(AppSettingsView::from(&settings)).unwrap();
        assert_eq!(
            unencrypted["srt_server"]["passphrase"]["state"],
            "unencrypted"
        );
        assert!(unencrypted["srt_server"]["passphrase"]["value"].is_null());

        settings.srt_server.passphrase = SrtPassphraseState::Available("strongPass1".into());
        let available = serde_json::to_value(AppSettingsView::from(&settings)).unwrap();
        assert_eq!(available["srt_server"]["passphrase"]["state"], "available");
        assert_eq!(
            available["srt_server"]["passphrase"]["value"],
            "strongPass1"
        );

        settings.srt_server.passphrase = SrtPassphraseState::Unavailable {
            preserved_ciphertext: "ciphertext-must-not-cross-ipc".into(),
        };
        let unavailable = serde_json::to_value(AppSettingsView::from(&settings)).unwrap();
        assert_eq!(
            unavailable["srt_server"]["passphrase"]["state"],
            "unavailable"
        );
        assert!(unavailable["srt_server"]["passphrase"]["value"].is_null());
        assert!(!unavailable
            .to_string()
            .contains("ciphertext-must-not-cross-ipc"));
    }

    #[test]
    fn srt_passphrase_update_json_requires_an_explicit_action() {
        assert!(matches!(
            serde_json::from_str::<SrtPassphraseUpdate>(r#"{"action":"keep"}"#).unwrap(),
            SrtPassphraseUpdate::Keep
        ));
        assert!(matches!(
            serde_json::from_str::<SrtPassphraseUpdate>(r#"{"action":"clear"}"#).unwrap(),
            SrtPassphraseUpdate::Clear
        ));
        match serde_json::from_str::<SrtPassphraseUpdate>(
            r#"{"action":"replace","value":"strongPass1"}"#,
        )
        .unwrap()
        {
            SrtPassphraseUpdate::Replace(value) => assert_eq!(value, "strongPass1"),
            _ => panic!("replace action should carry its explicit value"),
        }

        for malformed in [
            r#"{}"#,
            r#"{"action":""}"#,
            r#"{"action":"replace"}"#,
            r#"{"value":"strongPass1"}"#,
            r#"{"action":"keep","value":"strongPass1"}"#,
        ] {
            assert!(serde_json::from_str::<SrtPassphraseUpdate>(malformed).is_err());
        }
    }

    // ── TOML Serialization ──────────────────────────────────────────

    #[test]
    fn junk_protocol_fails_deserialize() {
        // A typo'd protocol used to silently become RTSP. It now fails to
        // deserialize, so load_from_disk quarantines the file instead of
        // streaming the wrong thing.
        let toml_str = r#"
[stream]
protocol = "htsp"
rtsp_port = 554
rtsp_path = "/z3-1.sdp"
udp_port = 8600
camera_ip = ""

[rtsp_server]
enabled = false
port = 8554
token = "0123456789abcdef"

[credentials]
username = ""
password = ""
"#;
        assert!(toml::from_str::<PersistedAppSettings>(toml_str).is_err());
    }

    #[test]
    fn protocol_wire_strings_are_lowercase() {
        assert_eq!(
            toml::Value::try_from(StreamProtocol::Rtsp).unwrap(),
            toml::Value::String("rtsp".into())
        );
        assert_eq!(
            toml::Value::try_from(StreamProtocol::Udp).unwrap(),
            toml::Value::String("udp".into())
        );
        assert_eq!(
            toml::Value::try_from(RestreamProtocol::Rtsp).unwrap(),
            toml::Value::String("rtsp".into())
        );
        assert_eq!(
            toml::Value::try_from(RestreamProtocol::Srt).unwrap(),
            toml::Value::String("srt".into())
        );
    }

    #[test]
    fn srt_selection_is_available_on_the_wire() {
        assert_eq!(
            serde_json::from_str::<RestreamProtocol>("\"srt\"").unwrap(),
            RestreamProtocol::Srt
        );
    }

    #[test]
    fn selector_commit_publishes_only_after_persistence_succeeds() {
        let config = AppConfig::for_test(AppSettings::default());
        let error = match config.commit_restream_protocol_with(RestreamProtocol::Srt, |_| {
            Err(crate::AppError::Config("injected write failure".into()))
        }) {
            Ok(_) => panic!("injected persistence failure must abort the selector commit"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), "Config");
        assert_eq!(config.get().restream_protocol, RestreamProtocol::Rtsp);

        let committed = config
            .commit_restream_protocol_with(RestreamProtocol::Srt, |prospective| {
                assert_eq!(prospective.restream_protocol, RestreamProtocol::Srt);
                Ok(())
            })
            .unwrap();
        assert_eq!(committed.restream_protocol, RestreamProtocol::Srt);
        assert_eq!(config.get().restream_protocol, RestreamProtocol::Srt);
    }

    #[test]
    fn restream_settings_commit_publishes_both_sections_only_after_persistence() {
        let config = AppConfig::for_test(AppSettings::default());
        let rtsp = RtspServerConfig {
            enabled: true,
            port: 9_554,
            token: "fedcba9876543210".into(),
            bind_interface: "ZeroTier".into(),
        };
        let srt = SrtServerConfig {
            port: 9_000,
            passphrase: SrtPassphraseState::Unavailable {
                preserved_ciphertext: "opaque-ciphertext".into(),
            },
            latency_ms: 250,
            stream_id: "field unit".into(),
            bind_interface: "ZeroTier".into(),
        };

        let error = match config.commit_restream_settings_with(rtsp.clone(), srt.clone(), |_| {
            Err(crate::AppError::Config("injected write failure".into()))
        }) {
            Ok(_) => panic!("injected persistence failure must abort both sections"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), "Config");
        let unchanged = config.get();
        assert_eq!(unchanged.rtsp_server.port, 8_554);
        assert_eq!(unchanged.srt_server.port, 8_890);
        assert!(matches!(
            unchanged.srt_server.passphrase,
            SrtPassphraseState::Unencrypted
        ));

        let committed = config
            .commit_restream_settings_with(rtsp, srt, |prospective| {
                assert_eq!(prospective.rtsp_server.port, 9_554);
                assert_eq!(prospective.srt_server.port, 9_000);
                Ok(())
            })
            .unwrap();
        assert_eq!(committed.rtsp_server.port, 9_554);
        assert_eq!(config.get().srt_server.stream_id, "field unit");
        assert!(matches!(
            config.get().srt_server.passphrase,
            SrtPassphraseState::Unavailable { ref preserved_ciphertext }
                if preserved_ciphertext == "opaque-ciphertext"
        ));
    }

    #[test]
    fn app_settings_view_exposes_the_neutral_selector() {
        let settings = AppSettings::default();
        let value = serde_json::to_value(AppSettingsView::from(&settings)).unwrap();
        assert_eq!(value["restream_protocol"], "rtsp");

        let mut settings = settings;
        settings.restream_protocol = RestreamProtocol::Srt;
        let value = serde_json::to_value(AppSettingsView::from(&settings)).unwrap();
        assert_eq!(value["restream_protocol"], "srt");
    }

    #[test]
    fn settings_toml_roundtrip() {
        let original = AppSettings::default();
        let toml_str = serialize_for_test(&original);
        let parsed = parse_for_test(&toml_str).unwrap();
        assert_eq!(parsed.stream.protocol, original.stream.protocol);
        assert_eq!(parsed.stream.rtsp_port, original.stream.rtsp_port);
        assert_eq!(parsed.rtsp_server.port, original.rtsp_server.port);
        assert_eq!(parsed.rtsp_server.token, original.rtsp_server.token);
    }

    #[test]
    fn srt_selector_persists_and_roundtrips() {
        let original = AppSettings {
            restream_protocol: RestreamProtocol::Srt,
            ..AppSettings::default()
        };
        let content = serialize_for_test(&original);
        assert!(content.contains("restream_protocol = \"srt\""));
        let parsed = parse_for_test(&content).unwrap();
        assert_eq!(parsed.restream_protocol, RestreamProtocol::Srt);
    }

    #[test]
    fn settings_toml_with_populated_fields() {
        let settings = AppSettings {
            selected_adapter_mac: None,
            primary_addresses: HashMap::new(),
            stream: StreamConfig {
                camera_mac: None,
                protocol: StreamProtocol::Udp,
                rtsp_port: 8554,
                rtsp_path: "/cam1".into(),
                udp_port: 9000,
                camera_ip: "10.0.0.5".into(),
                audio_muted: true,
            },
            restream_protocol: RestreamProtocol::Rtsp,
            rtsp_server: RtspServerConfig {
                enabled: true,
                port: 9554,
                token: "0123456789abcdef".into(),
                bind_interface: "Ethernet 2".into(),
            },
            srt_server: SrtServerConfig::default(),
            credentials: Credentials {
                username: "admin".into(),
                password: "secret".into(),
            },
            adopted_subnets: std::collections::HashMap::new(),
            adopted_meta: std::collections::HashMap::new(),
            pending_addresses: Vec::new(),
            zoom_positions: std::collections::HashMap::new(),
            network_mode: NetworkMode::default(),
            manual_nodes: Vec::new(),
        };
        let toml_str = serialize_for_test(&settings);
        let parsed = parse_for_test(&toml_str).unwrap();
        assert_eq!(parsed.stream.protocol, StreamProtocol::Udp);
        assert_eq!(parsed.stream.camera_ip, "10.0.0.5");
        assert_eq!(parsed.rtsp_server.bind_interface, "Ethernet 2");
        assert!(parsed.rtsp_server.enabled);
        assert_eq!(parsed.credentials.username, "admin");
        assert!(parsed.stream.audio_muted);
    }

    #[test]
    fn explicit_primary_roundtrip_is_backend_owned_and_failed_save_does_not_publish() {
        let config = AppConfig::temporary_test_config(AppSettings::default());
        config
            .set_primary_address_with("40-CD-3A-00-00-01", "192.0.2.10/24", |_| Ok(()))
            .unwrap();
        assert!(config
            .set_primary_address_with("40:cd:3a:00:00:01", "198.51.100.10/24", |_| Err(
                crate::AppError::Config("save failed".into())
            ))
            .is_err());
        assert_eq!(
            config.get().primary_addresses["40:cd:3a:00:00:01"],
            "192.0.2.10/24"
        );
        let mut saved = config.get();
        apply_stream_settings_for_test(&mut saved, AppSettings::default());
        let encoded = serialize_for_test(&saved);
        let decoded: AppSettings = parse_for_test(&encoded).unwrap();
        assert_eq!(decoded.primary_addresses, saved.primary_addresses);
        let mut old: toml::Value = toml::from_str(&serialize_for_test(&saved)).unwrap();
        old.as_table_mut().unwrap().remove("primary_addresses");
        let legacy = parse_for_test(&toml::to_string(&old).unwrap()).unwrap();
        assert!(legacy.primary_addresses.is_empty());
    }

    #[test]
    fn stream_config_missing_audio_muted_defaults_false() {
        // A config file written before the field existed must load
        // with audio on — the migration default.
        let toml_str = r#"
            [stream]
            protocol = "rtsp"
            rtsp_port = 554
            rtsp_path = "/live"
            udp_port = 8600
            camera_ip = "192.168.1.10"

            [rtsp_server]
            enabled = false
            port = 8554
            token = "0123456789abcdef"

            [credentials]
            username = ""
            password = ""
        "#;
        let parsed = parse_for_test(toml_str).unwrap();
        assert!(!parsed.stream.audio_muted);
        // The rest of the stream section must survive the migration.
        assert_eq!(parsed.stream.camera_ip, "192.168.1.10");
        assert_eq!(parsed.stream.rtsp_path, "/live");
    }

    #[test]
    fn srt_available_passphrase_is_encrypted_at_rest_and_roundtrips() {
        let mut settings = AppSettings::default();
        settings.srt_server.port = 9_001;
        settings.srt_server.passphrase = SrtPassphraseState::Available("strongPass1".into());
        settings.srt_server.latency_ms = 250;
        settings.srt_server.stream_id = "#!::name=Field Unit 7".into();
        settings.srt_server.bind_interface = "ZeroTier One".into();

        let content = serialize_for_test(&settings);
        assert!(!content.contains("strongPass1"));
        let persisted: PersistedAppSettings = toml::from_str(&content).unwrap();
        assert!(!persisted.srt_server.passphrase.is_empty());
        assert_ne!(persisted.srt_server.passphrase, "strongPass1");

        let parsed = parse_for_test(&content).unwrap();
        assert_eq!(parsed.srt_server.port, 9_001);
        assert_eq!(parsed.srt_server.latency_ms, 250);
        assert_eq!(parsed.srt_server.stream_id, "#!::name=Field Unit 7");
        assert_eq!(parsed.srt_server.bind_interface, "ZeroTier One");
        match parsed.srt_server.passphrase {
            SrtPassphraseState::Available(value) => assert_eq!(value, "strongPass1"),
            _ => panic!("encrypted SRT passphrase should decrypt as Available"),
        }
    }

    #[test]
    fn missing_wrong_or_corrupt_key_preserves_srt_ciphertext_as_unavailable() {
        let mut settings = AppSettings::default();
        settings.srt_server.passphrase = SrtPassphraseState::Available("strongPass1".into());
        let persisted =
            persisted_settings_with_srt_encryptor(&settings, &TEST_KEY, encrypt_string_checked)
                .unwrap();
        let ciphertext = persisted.srt_server.passphrase.clone();

        for loaded in [
            runtime_settings_from_persisted(persisted.clone(), None).unwrap(),
            runtime_settings_from_persisted(persisted.clone(), Some(&[0x99; 32])).unwrap(),
        ] {
            match loaded.srt_server.passphrase {
                SrtPassphraseState::Unavailable {
                    preserved_ciphertext,
                } => assert_eq!(preserved_ciphertext, ciphertext),
                _ => panic!("an unreadable protected passphrase must remain Unavailable"),
            }
        }

        let mut corrupt = persisted;
        corrupt.srt_server.passphrase = "not-valid-base64!!!".into();
        let loaded = runtime_settings_from_persisted(corrupt, Some(&TEST_KEY)).unwrap();
        match loaded.srt_server.passphrase {
            SrtPassphraseState::Unavailable {
                preserved_ciphertext,
            } => assert_eq!(preserved_ciphertext, "not-valid-base64!!!"),
            _ => panic!("corrupt ciphertext must remain Unavailable"),
        }
    }

    #[test]
    fn unrelated_save_preserves_unavailable_srt_ciphertext_exactly() {
        let mut settings = AppSettings::default();
        settings.srt_server.passphrase = SrtPassphraseState::Available("strongPass1".into());
        let persisted =
            persisted_settings_with_srt_encryptor(&settings, &TEST_KEY, encrypt_string_checked)
                .unwrap();
        let ciphertext = persisted.srt_server.passphrase.clone();
        let mut unavailable = runtime_settings_from_persisted(persisted, None).unwrap();
        unavailable.network_mode = NetworkMode::Dhcp;

        let replacement_key = [0x77; 32];
        let content = serialize_settings_with_srt_encryptor(
            &unavailable,
            &replacement_key,
            encrypt_string_checked,
        )
        .unwrap();
        let rewritten: PersistedAppSettings = toml::from_str(&content).unwrap();
        assert_eq!(rewritten.srt_server.passphrase, ciphertext);
    }

    #[test]
    fn explicit_passwordless_srt_serializes_as_empty_passphrase() {
        let settings = AppSettings::default();
        let content = serialize_for_test(&settings);
        let persisted: PersistedAppSettings = toml::from_str(&content).unwrap();
        assert!(persisted.srt_server.passphrase.is_empty());
        assert!(content.contains("passphrase = \"\""));
    }

    #[test]
    fn srt_encryption_failure_preserves_existing_settings_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "existing settings").unwrap();
        let mut settings = AppSettings::default();
        settings.srt_server.passphrase = SrtPassphraseState::Available("strongPass1".into());

        let error =
            save_settings_to_path_with_srt_encryptor(&settings, &path, &TEST_KEY, |_, _| {
                Err(crate::AppError::Config(
                    "injected encryption failure".into(),
                ))
            })
            .expect_err("save must fail closed");

        assert_eq!(error.kind(), "Config");
        assert_eq!(fs::read_to_string(path).unwrap(), "existing settings");
    }

    #[test]
    fn protected_srt_states_can_never_serialize_an_empty_ciphertext() {
        let mut available = AppSettings::default();
        available.srt_server.passphrase = SrtPassphraseState::Available("strongPass1".into());
        let error =
            serialize_settings_with_srt_encryptor(&available, &TEST_KEY, |_, _| Ok(String::new()))
                .expect_err("an empty encryption result must fail closed");
        assert_eq!(error.kind(), "Config");

        let mut unavailable = AppSettings::default();
        unavailable.srt_server.passphrase = SrtPassphraseState::Unavailable {
            preserved_ciphertext: String::new(),
        };
        let error =
            serialize_settings_with_srt_encryptor(&unavailable, &TEST_KEY, encrypt_string_checked)
                .expect_err("Unavailable must always retain non-empty ciphertext");
        assert_eq!(error.kind(), "Config");
    }

    #[test]
    fn checked_secret_encryption_rejects_invalid_key_length() {
        let error =
            encrypt_string_checked("strongPass1", &[0x42; 31]).expect_err("invalid key must fail");
        assert_eq!(error.kind(), "Config");
    }

    #[test]
    fn persisted_wide_restream_values_reach_typed_validation() {
        let base = persisted_settings_with_srt_encryptor(
            &AppSettings::default(),
            &TEST_KEY,
            encrypt_string_checked,
        )
        .unwrap();

        for port in [i64::MIN, -1, 0, 65_536, i64::MAX] {
            let mut candidate = base.clone();
            candidate.rtsp_server.port = port;
            let error = runtime_settings_from_persisted(candidate, Some(&TEST_KEY))
                .err()
                .expect("wide RTSP port must be rejected by validation");
            assert_eq!(error.kind(), "Validation");
        }
        for port in [i64::MIN, -1, 0, 65_536, i64::MAX] {
            let mut candidate = base.clone();
            candidate.srt_server.port = port;
            let error = runtime_settings_from_persisted(candidate, Some(&TEST_KEY))
                .err()
                .expect("wide SRT port must be rejected by validation");
            assert_eq!(error.kind(), "Validation");
        }
        for latency_ms in [i64::MIN, -1, 0, 19, 8_001, i64::MAX] {
            let mut candidate = base.clone();
            candidate.srt_server.latency_ms = latency_ms;
            let error = runtime_settings_from_persisted(candidate, Some(&TEST_KEY))
                .err()
                .expect("wide SRT latency must be rejected by validation");
            assert_eq!(error.kind(), "Validation");
        }
    }

    // ── Config Paths ────────────────────────────────────────────────

    #[test]
    fn config_dir_contains_pocketstream() {
        let dir = config_dir();
        assert!(dir.to_string_lossy().contains("PocketStream"));
    }

    #[test]
    fn config_path_ends_with_toml() {
        let path = config_path();
        assert_eq!(path.extension().unwrap(), "toml");
        assert!(path.to_string_lossy().contains("config"));
    }

    #[test]
    fn key_path_ends_with_key() {
        let path = key_path();
        assert_eq!(path.file_name().unwrap(), ".key");
    }

    // ── Key Management ──────────────────────────────────────────────

    #[test]
    fn get_or_create_key_returns_stable_32_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".key");
        let k1 = get_or_create_key_at(&path).unwrap();
        assert_eq!(k1.len(), 32, "key should be 32 bytes");
        let k2 = get_or_create_key_at(&path).unwrap();
        assert_eq!(k1, k2, "same key should be returned on subsequent calls");
    }

    // ── User-Settings Merge ─────────────────────────────────────────
    // Regression for the prior `save_config` behavior, where a frontend
    // payload that omitted a backend-owned field would deserialize via
    // serde-default to empty and the next save would persist the empty
    // value. The device_cache angle is now structurally impossible
    // (cache lives in its own file outside AppSettings); these tests
    // still cover the remaining backend-owned fields.

    #[test]
    fn persisted_settings_exclude_device_cache() {
        // The private persisted DTO structurally excludes device_cache,
        // which lives in device_cache.toml. Keep that separation visible in
        // the complete serialized settings form.
        let s = AppSettings::default();
        let toml_str = serialize_for_test(&s);
        assert!(
            !toml_str.contains("device_cache"),
            "AppSettings must not serialize a device_cache field — \
             the cache lives in device_cache.toml. Found:\n{}",
            toml_str
        );
    }

    #[test]
    fn remove_adoption_entry_is_surgical() {
        let mut adopted = HashMap::new();
        adopted.insert("172.31.169.0/24".to_string(), "172.31.169.100".to_string());
        adopted.insert("169.254.73.0/24".to_string(), "169.254.73.99".to_string());
        let mut meta = HashMap::new();
        meta.insert(
            "172.31.169.0/24".to_string(),
            AdoptedMeta {
                adopted_at: Some("2026-07-16T00:20:37Z".into()),
                last_device_seen: Some("2026-07-17T01:10:18Z".into()),
                ..Default::default()
            },
        );
        meta.insert(
            "169.254.73.0/24".to_string(),
            AdoptedMeta {
                adopted_at: Some("2026-07-16T00:20:37Z".into()),
                last_device_seen: None,
                ..Default::default()
            },
        );

        assert!(remove_adoption_entry(
            &mut adopted,
            &mut meta,
            "172.31.169.0/24"
        ));
        // The other entry AND its metadata survive untouched — removing
        // one adoption must never rebuild (and thereby wipe) the rest.
        assert_eq!(adopted.len(), 1);
        assert_eq!(
            adopted.get("169.254.73.0/24"),
            Some(&"169.254.73.99".to_string())
        );
        assert_eq!(meta.len(), 2);
        let removed = &meta["172.31.169.0/24"];
        assert_eq!(removed.desired, BindingDesired::Removed);
        assert_eq!(removed.address.as_deref(), Some("172.31.169.100"));
        assert_eq!(removed.prefix, Some(24));
        align_adopted_meta(&adopted, &mut meta, "later");
        assert_eq!(
            meta.get("169.254.73.0/24").unwrap().adopted_at.as_deref(),
            Some("2026-07-16T00:20:37Z")
        );

        // Absent subnet: a reported no-op, nothing else disturbed.
        assert!(!remove_adoption_entry(
            &mut adopted,
            &mut meta,
            "10.0.0.0/24"
        ));
        assert_eq!(adopted.len(), 1);
        assert_eq!(meta.len(), 2);
    }

    fn binding_test_config() -> AppConfig {
        AppConfig {
            settings: Mutex::new(AppSettings {
                selected_adapter_mac: Some("40:cd:3a:00:00:01".into()),
                ..Default::default()
            }),
            cache: Mutex::new(vec![]),
            startup_notices: Mutex::new(vec![]),
        }
    }

    #[test]
    fn temporary_claim_commit_and_user_saves_preserve_write_order_and_legacy_defaults() {
        let config = AppConfig::temporary_test_config(AppSettings {
            selected_adapter_mac: Some("40:CD:3A:00:00:01".into()),
            network_mode: NetworkMode::StaticAuto,
            ..Default::default()
        });
        let pending = PendingAddress {
            adapter_mac: "40:cd:3a:00:00:01".into(),
            address: "172.31.169.100".into(),
            prefix: 24,
        };
        config
            .reserve_temporary_with(pending.clone(), |_| Ok(()))
            .unwrap();
        let mut settings = config.get();
        apply_stream_settings_for_test(&mut settings, AppSettings::default());
        assert_eq!(settings.pending_addresses, vec![pending.clone()]);
        assert!(config
            .claim_binding_with(&pending.address, |_| Err(crate::AppError::Network(
                "save failed".into()
            )))
            .is_err());
        assert_eq!(config.get().pending_addresses, vec![pending.clone()]);
        config
            .claim_binding_with(&pending.address, |_| Ok(()))
            .unwrap();
        assert!(config.get().pending_addresses.is_empty());
        config
            .reserve_temporary_with(pending.clone(), |_| Ok(()))
            .unwrap();
        let row = AdoptedMeta {
            adapter_mac: Some(pending.adapter_mac.clone()),
            address: Some(pending.address.clone()),
            prefix: Some(24),
            applied: true,
            ..Default::default()
        };
        assert!(config
            .set_binding_with("172.31.169.0/24", row.clone(), |_| Err(
                crate::AppError::Network("save failed".into())
            ))
            .is_err());
        assert_eq!(config.get().pending_addresses, vec![pending]);
        assert!(config.get().adopted_subnets.is_empty());
        config
            .set_binding_with("172.31.169.0/24", row, |saved| {
                assert!(saved.pending_addresses.is_empty());
                assert_eq!(
                    saved
                        .adopted_subnets
                        .get("172.31.169.0/24")
                        .map(String::as_str),
                    Some("172.31.169.100")
                );
                Ok(())
            })
            .unwrap();
        let legacy =
            serialize_for_test(&AppSettings::default()).replace("pending_addresses = []\n", "");
        assert!(parse_for_test(&legacy)
            .unwrap()
            .pending_addresses
            .is_empty());
    }

    #[test]
    fn fresh_adoption_retires_only_the_unchanged_completed_removal() {
        let subnet = "192.0.2.0/24";
        let owner = "40:cd:3a:00:00:01";
        let removed = AdoptedMeta {
            adapter_mac: Some(owner.into()),
            address: Some("192.0.2.100".into()),
            prefix: Some(24),
            desired: BindingDesired::Removed,
            ..Default::default()
        };
        for case in 0..6 {
            let mut settings = AppSettings {
                selected_adapter_mac: Some(owner.into()),
                network_mode: NetworkMode::StaticAuto,
                ..Default::default()
            };
            settings.adopted_meta.insert(subnet.into(), removed.clone());
            match case {
                0 => {
                    settings.adopted_meta.get_mut(subnet).unwrap().last_error =
                        Some("new removal".into())
                }
                1 => {
                    settings.adopted_meta.get_mut(subnet).unwrap().address =
                        Some("192.0.2.101".into())
                }
                2 => settings.selected_adapter_mac = Some("aa:bb:cc:dd:ee:ff".into()),
                3 => settings.network_mode = NetworkMode::StaticManual,
                4 => {
                    settings
                        .adopted_subnets
                        .insert(subnet.into(), "192.0.2.100".into());
                }
                _ => {}
            }
            let config = AppConfig::temporary_test_config(settings);
            let before = config.get();
            let calls = std::cell::Cell::new(0);
            let result = config.forget_completed_removal_with(subnet, &removed, |_| {
                calls.set(calls.get() + 1);
                Ok(())
            });
            if case < 5 {
                assert!(result.is_err());
                assert_eq!(calls.get(), 0);
                assert_eq!(config.get().adopted_meta, before.adopted_meta);
            } else {
                result.unwrap();
                assert_eq!(calls.get(), 1);
                assert!(!config.get().adopted_meta.contains_key(subnet));
            }
        }
    }

    #[test]
    fn sp_status_equality_skips_atomic_save_but_repeated_intent_is_a_barrier() {
        let config = AppConfig::temporary_test_config(AppSettings::default());
        let mut row = AdoptedMeta {
            address: Some("192.0.2.20".into()),
            prefix: Some(24),
            adapter_mac: Some("40:cd:3a:00:00:01".into()),
            ..Default::default()
        };
        let count = std::cell::Cell::new(0);
        let persist = |_: &AppSettings| {
            count.set(count.get() + 1);
            Ok(())
        };
        config
            .set_binding_with("192.0.2.0/24", row.clone(), persist)
            .unwrap();
        config
            .set_binding_with("192.0.2.0/24", row.clone(), |_| {
                panic!("equal status must not fsync")
            })
            .unwrap();
        assert_eq!(count.get(), 1);
        config.settings.lock().unwrap().stream.camera_ip = "keep-current-user-setting".into();
        row.applied = true;
        config
            .set_binding_with("192.0.2.0/24", row.clone(), persist)
            .unwrap();
        assert_eq!(config.get().stream.camera_ip, "keep-current-user-setting");
        row.last_error = Some("temporary failure".into());
        config
            .set_binding_with("192.0.2.0/24", row.clone(), persist)
            .unwrap();
        config
            .settings
            .lock()
            .unwrap()
            .pending_addresses
            .push(PendingAddress {
                adapter_mac: row.adapter_mac.clone().unwrap(),
                address: row.address.clone().unwrap(),
                prefix: 24,
            });
        config
            .set_binding_with("192.0.2.0/24", row.clone(), |_| {
                panic!("equal failed status cannot retire ownership or save")
            })
            .unwrap();
        assert_eq!(config.get().pending_addresses.len(), 1);
        row.desired = BindingDesired::Removed;
        row.last_error = Some("Removal awaiting Windows confirmation".into());
        for _ in 0..2 {
            config
                .set_binding_for_operation_with("192.0.2.0/24", row.clone(), true, persist)
                .unwrap();
        }
        assert_eq!(
            count.get(),
            5,
            "each new removal crosses the durability barrier"
        );
        assert!(!config.get().adopted_subnets.contains_key("192.0.2.0/24"));
        assert_eq!(config.get().adopted_meta["192.0.2.0/24"], row);
    }

    #[test]
    fn binding_removal_save_failure_precedes_os_write_and_restart_retains_intent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let config = binding_test_config();
        let row = AdoptedMeta {
            adapter_mac: Some("40:cd:3a:00:00:01".into()),
            prefix: Some(24),
            address: Some("172.31.169.99".into()),
            applied: true,
            adopted_at: Some("2026-10-20T00:00:00Z".into()),
            ..Default::default()
        };
        let persist = |s: &AppSettings| {
            atomic_write(&path, serialize_for_test(s).as_bytes()).map_err(crate::AppError::Io)
        };
        config
            .set_binding_with("172.31.169.0/24", row.clone(), persist)
            .unwrap();
        let blocked = dir.path().join("not-a-directory");
        fs::write(&blocked, b"block").unwrap();
        let mut removed = row.clone();
        removed.desired = BindingDesired::Removed;
        let mut os_writes = 0;
        if config
            .set_binding_with("172.31.169.0/24", removed.clone(), |s| {
                atomic_write(
                    &blocked.join("config.toml"),
                    serialize_for_test(s).as_bytes(),
                )
                .map_err(crate::AppError::Io)
            })
            .is_ok()
        {
            os_writes += 1;
        }
        assert_eq!(os_writes, 0);
        assert_eq!(config.get().adopted_meta["172.31.169.0/24"], row);
        config
            .set_binding_with("172.31.169.0/24", removed.clone(), persist)
            .unwrap();
        // Restart after the intent save and before the OS unbind.
        let mut restarted: AppSettings =
            parse_for_test(&fs::read_to_string(&path).unwrap()).unwrap();
        align_adopted_meta(
            &restarted.adopted_subnets,
            &mut restarted.adopted_meta,
            "later",
        );
        assert!(restarted.adopted_subnets.is_empty());
        assert_eq!(restarted.adopted_meta["172.31.169.0/24"], removed);
        assert!(config
            .set_binding_with("172.31.169.0/24", row, |_| panic!(
                "late adoption must not save"
            ))
            .is_err());
        let mut edited = AppSettings::default();
        edited.adopted_meta.clear();
        apply_stream_settings_for_test(&mut restarted, edited);
        assert_eq!(
            restarted.adopted_meta["172.31.169.0/24"].desired,
            BindingDesired::Removed
        );
        config
            .change_settings_with(
                |s| {
                    s.selected_adapter_mac = Some("40:cd:3a:00:00:02".into());
                    Ok(())
                },
                persist,
            )
            .unwrap();
        config.claim_binding_with("172.31.169.99", persist).unwrap();
        assert_eq!(
            config.get().adopted_meta["172.31.169.0/24"].desired,
            BindingDesired::Removed
        );
        config
            .change_settings_with(
                |s| {
                    s.selected_adapter_mac = Some("40:cd:3a:00:00:01".into());
                    Ok(())
                },
                persist,
            )
            .unwrap();
        config.claim_binding_with("172.31.169.99", persist).unwrap();
        assert!(config.get().adopted_meta.is_empty());
    }

    #[test]
    fn mode_save_failure_does_not_publish_an_unpersisted_mode() {
        let config = binding_test_config();
        let before = config.get_network_mode();
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("not-a-directory");
        fs::write(&blocked, b"block").unwrap();
        assert!(config
            .change_settings_with(
                |s| {
                    s.network_mode = NetworkMode::Dhcp;
                    Ok(())
                },
                |s| atomic_write(
                    &blocked.join("config.toml"),
                    serialize_for_test(s).as_bytes()
                )
                .map_err(crate::AppError::Io)
            )
            .is_err());
        assert_eq!(config.get_network_mode(), before);
        let legacy: AdoptedMeta = toml::from_str("adopted_at='old'").unwrap();
        assert_eq!(legacy.desired, BindingDesired::Present);
        assert!(!legacy.applied && legacy.adapter_mac.is_none());
    }

    #[test]
    fn durable_fields_round_trip_repeatedly_and_previous_metadata_schema_still_parses() {
        #[derive(Deserialize)]
        struct PreviousMeta {
            adopted_at: Option<String>,
            last_device_seen: Option<String>,
        }
        #[derive(Deserialize)]
        struct PreviousSettings {
            adopted_subnets: HashMap<String, String>,
            adopted_meta: HashMap<String, PreviousMeta>,
        }
        let mut settings = AppSettings::default();
        settings
            .adopted_subnets
            .insert("172.26.95.0/24".into(), "172.26.95.99".into());
        settings.adopted_meta.insert(
            "169.254.20.0/24".into(),
            AdoptedMeta {
                address: Some("169.254.20.99".into()),
                prefix: Some(24),
                adapter_mac: Some("40:cd:3a:00:00:01".into()),
                desired: BindingDesired::Removed,
                applied: true,
                last_error: Some("OS rejected removal".into()),
                adopted_at: Some("original timestamp".into()),
                last_device_seen: Some("last seen".into()),
            },
        );
        align_adopted_meta(
            &settings.adopted_subnets,
            &mut settings.adopted_meta,
            "backfilled",
        );
        let original = settings.adopted_meta.clone();
        for _ in 0..2 {
            let encoded = serialize_for_test(&settings);
            let previous: PreviousSettings = toml::from_str(&encoded).unwrap();
            assert_eq!(previous.adopted_subnets, settings.adopted_subnets);
            assert_eq!(
                previous.adopted_meta["169.254.20.0/24"]
                    .adopted_at
                    .as_deref(),
                Some("original timestamp")
            );
            assert_eq!(
                previous.adopted_meta["169.254.20.0/24"]
                    .last_device_seen
                    .as_deref(),
                Some("last seen")
            );
            settings = parse_for_test(&encoded).unwrap();
            align_adopted_meta(
                &settings.adopted_subnets,
                &mut settings.adopted_meta,
                "later load",
            );
            assert_eq!(settings.adopted_meta, original);
        }
    }

    #[test]
    fn stream_update_preserves_adopted_subnets() {
        let mut current = AppSettings::default();
        current
            .adopted_subnets
            .insert("192.168.1.0/24".into(), "192.168.1.50".into());

        let incoming = AppSettings::default();
        apply_stream_settings_for_test(&mut current, incoming);

        assert_eq!(current.adopted_subnets.len(), 1);
        assert_eq!(
            current.adopted_subnets.get("192.168.1.0/24"),
            Some(&"192.168.1.50".to_string())
        );
    }

    #[test]
    fn stream_update_preserves_zoom_positions() {
        let mut current = AppSettings::default();
        current.zoom_positions.insert("192.168.1.10".into(), 75);

        let incoming = AppSettings::default();
        apply_stream_settings_for_test(&mut current, incoming);

        assert_eq!(current.zoom_positions.len(), 1);
        assert_eq!(current.zoom_positions.get("192.168.1.10"), Some(&75));
    }

    #[test]
    fn stream_update_preserves_network_mode() {
        // A partial frontend payload (just stream/rtsp/credentials) must
        // not clobber the user's chosen mode via serde defaults.
        let mut current = AppSettings {
            network_mode: NetworkMode::StaticManual,
            ..Default::default()
        };
        apply_stream_settings_for_test(&mut current, AppSettings::default());
        assert_eq!(current.network_mode, NetworkMode::StaticManual);
    }

    #[test]
    fn selected_adapter_is_defaulted_round_tripped_and_backend_owned() {
        let legacy = serialize_for_test(&AppSettings::default());
        assert!(!legacy.contains("selected_adapter_mac"));
        let mut settings: AppSettings = parse_for_test(&legacy).unwrap();
        assert_eq!(settings.selected_adapter_mac, None);
        settings.selected_adapter_mac = Some("40:cd:3a:00:00:01".into());
        apply_stream_settings_for_test(&mut settings, AppSettings::default());
        let encoded = serialize_for_test(&settings);
        let restored: AppSettings = parse_for_test(&encoded).unwrap();
        assert_eq!(
            restored.selected_adapter_mac.as_deref(),
            Some("40:cd:3a:00:00:01")
        );
    }

    #[test]
    fn stream_update_preserves_manual_nodes() {
        let mut current = AppSettings::default();
        current.manual_nodes.push(ManualNode {
            expected_mac: None,
            ip: "192.168.1.50".into(),
            alias: "CAM".into(),
        });
        apply_stream_settings_for_test(&mut current, AppSettings::default());
        assert_eq!(current.manual_nodes.len(), 1);
        assert_eq!(current.manual_nodes[0].ip, "192.168.1.50");
        assert_eq!(current.manual_nodes[0].alias, "CAM");
    }

    // ── Network Mode ────────────────────────────────────────────────

    #[test]
    fn network_mode_default_is_static_auto() {
        assert_eq!(NetworkMode::default(), NetworkMode::StaticAuto);
    }

    #[test]
    fn network_mode_serializes_snake_case() {
        // Frontend matches strings exactly; renaming a variant would
        // silently break the IPC contract. Lock in the expected wire shape.
        assert_eq!(
            serde_json::to_string(&NetworkMode::StaticManual).unwrap(),
            "\"static_manual\""
        );
        assert_eq!(
            serde_json::to_string(&NetworkMode::StaticAuto).unwrap(),
            "\"static_auto\""
        );
        assert_eq!(
            serde_json::to_string(&NetworkMode::Dhcp).unwrap(),
            "\"dhcp\""
        );
    }

    #[test]
    fn manual_node_toml_roundtrip() {
        let mut settings = AppSettings::default();
        settings.manual_nodes.push(ManualNode {
            expected_mac: None,
            ip: "192.168.1.202".into(),
            alias: "PTU".into(),
        });
        settings.manual_nodes.push(ManualNode {
            expected_mac: None,
            ip: "10.13.248.55".into(),
            alias: String::new(),
        });
        let toml_str = serialize_for_test(&settings);
        let parsed = parse_for_test(&toml_str).unwrap();
        assert_eq!(parsed.manual_nodes.len(), 2);
        assert_eq!(parsed.manual_nodes[0].ip, "192.168.1.202");
        assert_eq!(parsed.manual_nodes[0].alias, "PTU");
        assert_eq!(parsed.manual_nodes[1].alias, "");
    }

    #[test]
    fn old_config_without_new_fields_loads_with_defaults() {
        // Existing v0.4.x users have config.toml without network_mode or
        // manual_nodes. serde defaults must kick in so an upgrade doesn't
        // refuse to load.
        let legacy = r#"
[stream]
protocol = "rtsp"
rtsp_port = 554
rtsp_path = "/z3-1.sdp"
udp_port = 8600
camera_ip = ""

[rtsp_server]
enabled = false
port = 8554
token = "0123456789abcdef"

[credentials]
username = ""
password = ""
"#;
        let parsed = parse_for_test(legacy).unwrap();
        assert_eq!(parsed.restream_protocol, RestreamProtocol::Rtsp);
        assert_eq!(parsed.network_mode, NetworkMode::StaticAuto);
        assert!(parsed.manual_nodes.is_empty());
        assert_eq!(parsed.srt_server.port, 8_890);
        assert_eq!(parsed.srt_server.latency_ms, 125);
        assert!(matches!(
            parsed.srt_server.passphrase,
            SrtPassphraseState::Unencrypted
        ));
    }

    #[test]
    fn adopted_meta_toml_roundtrip() {
        let mut settings = AppSettings::default();
        settings
            .adopted_subnets
            .insert("169.254.168.0/24".into(), "169.254.168.102".into());
        settings.adopted_meta.insert(
            "169.254.168.0/24".into(),
            AdoptedMeta {
                adopted_at: Some("2026-07-16T10:29:13+00:00".into()),
                last_device_seen: None,
                ..Default::default()
            },
        );
        let toml_str = serialize_for_test(&settings);
        let parsed = parse_for_test(&toml_str).unwrap();
        assert_eq!(parsed.adopted_meta.len(), 1);
        let meta = &parsed.adopted_meta["169.254.168.0/24"];
        assert_eq!(
            meta.adopted_at.as_deref(),
            Some("2026-07-16T10:29:13+00:00")
        );
        assert_eq!(meta.last_device_seen, None);
    }

    #[test]
    fn config_with_adoptions_but_no_meta_loads_with_empty_map() {
        // Configs written before lifecycle metadata carry adopted
        // subnets with no adopted_meta table; serde defaults must fill
        // the map so the upgrade loads (backfill happens separately).
        let legacy = r#"
[stream]
protocol = "rtsp"
rtsp_port = 554
rtsp_path = "/z3-1.sdp"
udp_port = 8600
camera_ip = ""

[rtsp_server]
enabled = false
port = 8554
token = "0123456789abcdef"

[credentials]
username = ""
password = ""

[adopted_subnets]
"169.254.168.0/24" = "169.254.168.102"
"#;
        let parsed = parse_for_test(legacy).unwrap();
        assert_eq!(parsed.adopted_subnets.len(), 1);
        assert!(parsed.adopted_meta.is_empty());
    }

    #[test]
    fn align_adopted_meta_backfills_and_prunes() {
        let mut adopted = HashMap::new();
        adopted.insert(
            "169.254.168.0/24".to_string(),
            "169.254.168.102".to_string(),
        );
        let mut meta: HashMap<String, AdoptedMeta> = HashMap::new();
        // Stray metadata for a subnet not being persisted…
        meta.insert("10.0.0.0/24".into(), AdoptedMeta::default());
        align_adopted_meta(&adopted, &mut meta, "2026-07-16T00:00:00+00:00");
        // …is dropped, and the subnet lacking metadata is backfilled
        // with the supplied time and no device sighting.
        assert_eq!(meta.len(), 1);
        let m = &meta["169.254.168.0/24"];
        assert_eq!(m.adopted_at.as_deref(), Some("2026-07-16T00:00:00+00:00"));
        assert_eq!(m.last_device_seen, None);
    }

    #[test]
    fn align_adopted_meta_preserves_existing_entries() {
        let mut adopted = HashMap::new();
        adopted.insert("172.31.169.0/24".to_string(), "172.31.169.102".to_string());
        let mut meta = HashMap::new();
        meta.insert(
            "172.31.169.0/24".to_string(),
            AdoptedMeta {
                adopted_at: Some("2026-07-01T00:00:00+00:00".into()),
                last_device_seen: Some("2026-07-15T00:00:00+00:00".into()),
                ..Default::default()
            },
        );
        align_adopted_meta(&adopted, &mut meta, "2026-07-16T00:00:00+00:00");
        let m = &meta["172.31.169.0/24"];
        assert_eq!(m.adopted_at.as_deref(), Some("2026-07-01T00:00:00+00:00"));
        assert_eq!(
            m.last_device_seen.as_deref(),
            Some("2026-07-15T00:00:00+00:00")
        );
    }

    // ── Device Cache File ───────────────────────────────────────────

    #[test]
    fn cache_path_ends_with_device_cache_toml() {
        let path = cache_path();
        assert_eq!(path.file_name().unwrap(), "device_cache.toml");
        assert!(path.to_string_lossy().contains("PocketStream"));
    }

    #[test]
    fn cache_file_toml_roundtrip() {
        let original = CacheFile {
            devices: vec![
                CachedDevice {
                    verified_by_mac: None,
                    last_verified_at: None,
                    mac: "AA:BB:CC:DD:EE:FF".into(),
                    ip: "192.168.1.10".into(),
                    subnet: "192.168.1.0/24".into(),
                    open_ports: vec![80, 554],
                    alias: "Front".into(),
                    last_seen: "2026-04-27T12:00:00Z".into(),
                },
                CachedDevice {
                    verified_by_mac: None,
                    last_verified_at: None,
                    mac: "11:22:33:44:55:66".into(),
                    ip: "192.168.1.20".into(),
                    subnet: "192.168.1.0/24".into(),
                    open_ports: vec![],
                    alias: String::new(),
                    last_seen: "2026-04-27T12:00:00Z".into(),
                },
            ],
        };
        let toml_str = toml::to_string_pretty(&original).unwrap();
        let parsed: CacheFile = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.devices.len(), 2);
        assert_eq!(parsed.devices[0].mac, "AA:BB:CC:DD:EE:FF");
        assert_eq!(parsed.devices[0].open_ports, vec![80, 554]);
        assert_eq!(parsed.devices[1].alias, "");
    }

    #[test]
    fn cache_file_default_is_empty() {
        let parsed: CacheFile = toml::from_str("").unwrap();
        assert!(parsed.devices.is_empty());
    }

    #[test]
    fn cached_alias_update_includes_zero_port_rows_without_inserting() {
        let mut cache = vec![CachedDevice {
            verified_by_mac: None,
            last_verified_at: None,
            mac: "AA:BB:CC:DD:EE:FF".into(),
            ip: "192.168.1.207".into(),
            subnet: "192.168.1.0/24".into(),
            open_ports: vec![],
            alias: "PTU".into(),
            last_seen: "2026-08-18T12:49:46Z".into(),
        }];

        assert!(update_cached_alias_in_place(
            &mut cache,
            "AA:BB:CC:DD:EE:FF",
            ""
        ));
        assert!(cache[0].alias.is_empty());
        assert!(cache[0].open_ports.is_empty(), "scan metadata is preserved");
        assert!(
            !update_cached_alias_in_place(&mut cache, "missing", "PTU"),
            "an alias-only write must not create a cache row"
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cached_alias_update_is_idempotent() {
        let mut cache = vec![CachedDevice {
            verified_by_mac: None,
            last_verified_at: None,
            mac: "AA:BB:CC:DD:EE:FF".into(),
            ip: "192.168.1.207".into(),
            subnet: "192.168.1.0/24".into(),
            open_ports: vec![80],
            alias: "PTU".into(),
            last_seen: "2026-08-18T12:49:46Z".into(),
        }];

        assert!(!update_cached_alias_in_place(
            &mut cache,
            "AA:BB:CC:DD:EE:FF",
            "PTU"
        ));
    }

    // ── Legacy Cache Migration ──────────────────────────────────────
    // T1.10 split the cache out of config.toml into device_cache.toml.
    // On first load after the upgrade, extract_legacy_device_cache
    // pulls the old field out of an existing config.toml so the cache
    // migrates instead of disappearing.

    #[test]
    fn extract_legacy_cache_returns_devices_when_field_present() {
        let toml_content = r#"
[stream]
protocol = "rtsp"
rtsp_port = 554
rtsp_path = "/z3-1.sdp"
udp_port = 8600
camera_ip = ""

[rtsp_server]
enabled = false
port = 8554
token = "abc"

[credentials]
username = ""
password = ""

[[device_cache]]
mac = "AA:BB:CC:DD:EE:FF"
ip = "192.168.1.10"
subnet = "192.168.1.0/24"
open_ports = [80, 554]
alias = "Cam"
last_seen = "2026-04-27T12:00:00Z"
"#;
        let extracted = extract_legacy_device_cache(toml_content);
        assert!(extracted.is_some(), "must extract legacy device_cache");
        let cache = extracted.unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache[0].mac, "AA:BB:CC:DD:EE:FF");
        assert_eq!(cache[0].open_ports, vec![80, 554]);
    }

    #[test]
    fn extract_legacy_cache_returns_none_when_field_absent() {
        // A modern config.toml (post-T1.10) doesn't have device_cache.
        // The migration path must recognise that and not invent data.
        let toml_content = r#"
[stream]
protocol = "rtsp"
rtsp_port = 554
rtsp_path = "/z3-1.sdp"
udp_port = 8600
camera_ip = ""

[rtsp_server]
enabled = false
port = 8554
token = "abc"

[credentials]
username = ""
password = ""
"#;
        assert!(extract_legacy_device_cache(toml_content).is_none());
    }

    #[test]
    fn extract_legacy_cache_returns_none_for_malformed_input() {
        assert!(extract_legacy_device_cache("not toml at all !!! [[[").is_none());
    }

    // ── Atomic Writes ───────────────────────────────────────────────
    // Crash safety: writes go through .tmp + rename so a kill -9 in the
    // middle of a save can't truncate the live file. tempfile-backed
    // tests use a real temp directory so the rename and the tmp suffix
    // logic exercise actual filesystem semantics.

    #[test]
    fn atomic_write_creates_file_with_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        atomic_write(&path, b"hello").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
    }

    #[test]
    fn atomic_write_overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "old contents").unwrap();
        atomic_write(&path, b"new contents").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new contents");
    }

    #[test]
    fn atomic_write_leaves_no_tmp_file_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        atomic_write(&path, b"data").unwrap();
        // Staging names are unique per write, so scan for any leftover
        // rather than probing one fixed name.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "staging file must be renamed away on success: {:?}",
            leftovers
        );
    }

    #[test]
    fn atomic_write_creates_missing_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("config.toml");
        atomic_write(&nested, b"data").unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn atomic_write_preserves_existing_file_when_write_fails_mid_flight() {
        // Simulate the kill-9 scenario by planting an abandoned staging
        // file from a "previous run", then doing a real atomic_write —
        // the abandoned tmp must never be renamed over the live file.
        // Staging names are unique per write, so the abandoned file is
        // simply ignored, not consumed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let tmp = dir.path().join("config.toml.99999.0.tmp");
        fs::write(&path, "live data").unwrap();
        fs::write(&tmp, "abandoned tmp").unwrap();

        atomic_write(&path, b"new data").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new data");
        assert_eq!(fs::read_to_string(&tmp).unwrap(), "abandoned tmp");
    }

    #[test]
    fn atomic_write_survives_concurrent_writers_to_same_path() {
        // Regression for the fixed-staging-name race: concurrent writers
        // used to truncate each other's staged bytes via File::create on
        // the shared .tmp name, so a torn file could be renamed into
        // place. With unique staging names, the final file must always
        // be exactly ONE writer's complete payload.
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().join("config.toml"));

        let threads: Vec<_> = (0..8)
            .map(|t| {
                let path = Arc::clone(&path);
                std::thread::spawn(move || {
                    for i in 0..25 {
                        // Distinct, self-describing payloads long enough
                        // that a torn write is detectable.
                        let payload = format!("writer={} iteration={} {}", t, i, "x".repeat(512));
                        atomic_write(&path, payload.as_bytes()).unwrap();
                        // A read racing a rename can transiently fail on
                        // Windows sharing semantics — that's fine; what
                        // must never happen is reading TORN content.
                        if let Ok(read_back) = fs::read_to_string(&*path) {
                            assert!(
                                read_back.starts_with("writer=") && read_back.ends_with('x'),
                                "torn read: {:?}",
                                &read_back[..read_back.len().min(60)]
                            );
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        let final_content = fs::read_to_string(&*path).unwrap();
        assert!(final_content.starts_with("writer=") && final_content.ends_with('x'));
    }

    #[test]
    fn quarantine_path_appends_parse_error_suffix() {
        let p = PathBuf::from("/tmp/PocketStream/config.toml");
        let q = quarantine_path(&p);
        assert_eq!(q.file_name().unwrap(), "config.toml.parse-error");
        assert_eq!(q.parent().unwrap(), p.parent().unwrap());
    }

    #[test]
    fn quarantine_moves_file_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "corrupted contents").unwrap();
        quarantine(&path);
        let dest = dir.path().join("config.toml.parse-error");
        assert!(!path.exists(), "original file should have been moved");
        assert!(
            dest.exists(),
            "quarantine target should now hold the contents"
        );
        assert_eq!(fs::read_to_string(dest).unwrap(), "corrupted contents");
    }

    #[test]
    fn quarantine_is_silent_no_op_when_source_missing() {
        // Best-effort semantics: quarantine on an already-missing file
        // (e.g., raced with another caller) must not panic. The warning
        // log is exercised by the missing-file path; we just verify the
        // function returns cleanly.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.toml");
        quarantine(&path);
    }

    #[test]
    fn corrupt_settings_toml_quarantines_and_records_notice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "not [valid toml").unwrap();
        let mut notices = Vec::new();
        let parsed = parse_settings("not [valid toml", &path, &mut notices, None);
        assert!(parsed.is_none());
        assert!(!path.exists(), "corrupted file should be moved aside");
        assert!(dir.path().join("config.toml.parse-error").exists());
        assert_eq!(notices.len(), 1);
        // The notice must name the preserved file and the token reset —
        // it's the only user-visible record of the salvage.
        assert!(notices[0].contains("config.toml.parse-error"));
        assert!(notices[0].contains("token"));
    }

    #[test]
    fn clean_settings_toml_records_no_notice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let content = serialize_for_test(&AppSettings::default());
        let mut notices = Vec::new();
        let parsed = parse_settings(&content, &path, &mut notices, Some(&TEST_KEY));
        assert!(parsed.is_some());
        assert!(notices.is_empty());
    }

    #[test]
    fn invalid_persisted_restream_settings_are_quarantined() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut persisted = persisted_settings_with_srt_encryptor(
            &AppSettings::default(),
            &TEST_KEY,
            encrypt_string_checked,
        )
        .unwrap();
        persisted.srt_server.port = 65_536;
        let content = toml::to_string(&persisted).unwrap();
        fs::write(&path, &content).unwrap();

        let mut notices = Vec::new();
        let parsed = parse_settings(&content, &path, &mut notices, Some(&TEST_KEY));

        assert!(parsed.is_none());
        assert!(!path.exists());
        assert!(dir.path().join("config.toml.parse-error").exists());
        assert_eq!(notices.len(), 1);
    }

    #[test]
    fn corrupt_cache_toml_quarantines_and_records_notice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device_cache.toml");
        fs::write(&path, "devices = not-a-list").unwrap();
        let mut notices = Vec::new();
        let parsed = parse_cache("devices = not-a-list", &path, &mut notices);
        assert!(parsed.is_none());
        assert!(dir.path().join("device_cache.toml.parse-error").exists());
        assert_eq!(notices.len(), 1);
        assert!(notices[0].contains("device_cache.toml.parse-error"));
    }

    #[test]
    fn extract_legacy_cache_returns_empty_vec_for_empty_array() {
        // device_cache must come BEFORE any [section] header — TOML
        // top-level keys are illegal once a section is open.
        let toml_content = r#"
device_cache = []

[stream]
protocol = "rtsp"
rtsp_port = 554
rtsp_path = "/z3-1.sdp"
udp_port = 8600
camera_ip = ""

[rtsp_server]
enabled = false
port = 8554
token = "abc"

[credentials]
username = ""
password = ""
"#;
        let extracted = extract_legacy_device_cache(toml_content);
        assert!(extracted.is_some());
        assert!(extracted.unwrap().is_empty());
    }

    #[test]
    fn cache_identity_write_fences_stale_results_and_keeps_zero_ports() {
        let make = |mac: &str| CachedDevice {
            mac: mac.into(),
            ip: "192.168.1.204".into(),
            subnet: "192.168.1.0/24".into(),
            open_ports: vec![],
            alias: "CAM".into(),
            last_seen: "2026-10-19T12:00:00Z".into(),
            verified_by_mac: Some("40:cd:3a:00:00:01".into()),
            last_verified_at: Some("2026-10-19T12:00:00Z".into()),
        };
        let active = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let fence = crate::network::SweepFence::new(
            1,
            std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
            active.clone(),
        );
        let mut cache = vec![];
        assert!(upsert_cache_record(&mut cache, make("old"), Some(&fence)));
        assert!(upsert_cache_record(&mut cache, make("new"), Some(&fence)));
        active.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(!upsert_cache_record(
            &mut cache,
            make("stale"),
            Some(&fence)
        ));
        let parsed: CacheFile =
            toml::from_str(&toml::to_string(&CacheFile { devices: cache }).unwrap()).unwrap();
        assert_eq!(parsed.devices.len(), 2);
        assert!(parsed.devices.iter().all(|d| d.open_ports.is_empty()
            && d.verified_by_mac.is_some()
            && d.last_verified_at.is_some()));
        let legacy: CachedDevice = toml::from_str(
            r#"mac='old'
ip='192.168.1.204'
subnet='192.168.1.0/24'
last_seen='old'"#,
        )
        .unwrap();
        assert!(legacy.verified_by_mac.is_none() && legacy.last_verified_at.is_none());
    }

    #[test]
    fn first_manual_verification_is_saved_once_and_survives_restart() {
        let mut settings = AppSettings::default();
        settings.manual_nodes.push(ManualNode {
            ip: "192.168.1.204".into(),
            alias: "CAM".into(),
            expected_mac: None,
        });
        let config = AppConfig {
            settings: Mutex::new(settings),
            cache: Mutex::new(vec![]),
            startup_notices: Mutex::new(vec![]),
        };
        let fence = crate::network::SweepFence::new(
            1,
            std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        config
            .bind_manual_node_with("192.168.1.204", "aa:bb:cc:dd:ee:02", &fence, |s| {
                std::fs::write(&path, serialize_for_test(s)).unwrap();
                Ok(())
            })
            .unwrap();
        let disk: AppSettings = parse_for_test(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            disk.manual_nodes[0].expected_mac.as_deref(),
            Some("aa:bb:cc:dd:ee:02")
        );
        let bound = config
            .bind_manual_node_with("192.168.1.204", "aa:bb:cc:dd:ee:04", &fence, |_| {
                panic!("replacement must not rebind or save")
            })
            .unwrap();
        assert_eq!(bound.expected_mac, disk.manual_nodes[0].expected_mac);
        assert_eq!(config.get_manual_nodes(), disk.manual_nodes);
    }

    #[test]
    fn failed_or_retired_manual_binding_does_not_publish_the_identity() {
        let mut settings = AppSettings::default();
        settings.manual_nodes.push(ManualNode {
            ip: "192.168.1.204".into(),
            alias: "".into(),
            expected_mac: None,
        });
        let config = AppConfig {
            settings: Mutex::new(settings),
            cache: Mutex::new(vec![]),
            startup_notices: Mutex::new(vec![]),
        };
        let active = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let fence = crate::network::SweepFence::new(
            1,
            std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
            active.clone(),
        );
        assert!(config
            .bind_manual_node_with("192.168.1.204", "aa:bb:cc:dd:ee:02", &fence, |_| Err(
                crate::AppError::Network("save failed".into())
            ))
            .is_err());
        assert!(config.get_manual_nodes()[0].expected_mac.is_none());
        active.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(config
            .bind_manual_node_with("192.168.1.204", "aa:bb:cc:dd:ee:02", &fence, |_| panic!(
                "retired proof must not save"
            ))
            .is_err());
        assert!(config.get_manual_nodes()[0].expected_mac.is_none());
    }

    #[test]
    fn target_fields_default_and_round_trip_with_user_settings() {
        let legacy = serialize_for_test(&AppSettings::default());
        let mut settings: AppSettings = parse_for_test(&legacy).unwrap();
        assert!(settings.stream.camera_mac.is_none());
        let node: ManualNode = toml::from_str("ip='192.168.1.204'\nalias='CAM'").unwrap();
        assert!(node.expected_mac.is_none());
        settings.stream.camera_ip = node.ip.clone();
        settings.stream.camera_mac = Some("aa:bb:cc:dd:ee:02".into());
        settings.manual_nodes.push(node);
        let stream: StreamConfig =
            toml::from_str(&toml::to_string(&settings.stream).unwrap()).unwrap();
        let incoming = AppSettings {
            stream,
            ..Default::default()
        };
        apply_stream_settings_for_test(&mut settings, incoming);
        let disk: AppSettings = parse_for_test(&serialize_for_test(&settings)).unwrap();
        assert_eq!(disk.stream.camera_mac.as_deref(), Some("aa:bb:cc:dd:ee:02"));
        assert_eq!(disk.stream.camera_ip, "192.168.1.204");
        assert_eq!(disk.manual_nodes.len(), 1);
    }
}
