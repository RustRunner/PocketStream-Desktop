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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    /// Input protocol: "rtsp" or "udp"
    pub protocol: String,
    /// Camera RTSP port (default 554)
    pub rtsp_port: u16,
    /// Camera RTSP path (default "/z3-1.sdp")
    pub rtsp_path: String,
    /// UDP stream port (default 8600)
    pub udp_port: u16,
    /// Camera IP address (discovered or manual)
    pub camera_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    Dhcp,
    StaticAuto,
    StaticManual,
}

impl Default for NetworkMode {
    fn default() -> Self {
        // Existing installs (config.toml predates this field) keep the
        // historic behavior — ARP discovery + auto-adopt. Fresh installs
        // hit this default too; the IP Config dialog is how users move to
        // DHCP or Static-Manual.
        NetworkMode::StaticAuto
    }
}

/// A user-pinned device for `NetworkMode::StaticManual`. Survives mode
/// toggles so users can flip Auto → Manual → Auto without losing pins.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManualNode {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub stream: StreamConfig,
    pub rtsp_server: RtspServerConfig,
    pub credentials: Credentials,
    /// Auto-adopted subnet IPs: subnet string -> adopted IP address
    #[serde(default)]
    pub adopted_subnets: HashMap<String, String>,
    /// Last zoom slider position (0–100 %) per camera IP.
    /// Restored on launch so the slider doesn't reset to Wide when the
    /// camera is still pointed at the last-set zoom. Stored as percent
    /// rather than raw integer so different max ranges remain portable.
    #[serde(default)]
    pub zoom_positions: HashMap<String, i32>,
    /// User's chosen network mode. See `NetworkMode` doc-comment.
    #[serde(default)]
    pub network_mode: NetworkMode,
    /// User-pinned nodes for `NetworkMode::StaticManual`. Persisted
    /// across mode toggles; the typical workflow is to use `StaticAuto`
    /// to discover IPs, then switch to `StaticManual` for steady-state
    /// operation against the discovered set.
    #[serde(default)]
    pub manual_nodes: Vec<ManualNode>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            stream: StreamConfig {
                protocol: "rtsp".into(),
                rtsp_port: 554,
                rtsp_path: "/z3-1.sdp".into(),
                udp_port: 8600,
                camera_ip: String::new(),
            },
            rtsp_server: RtspServerConfig {
                enabled: false,
                port: 8554,
                token: generate_token(),
                bind_interface: String::new(),
            },
            credentials: Credentials {
                username: String::new(),
                password: String::new(),
            },
            adopted_subnets: HashMap::new(),
            zoom_positions: HashMap::new(),
            network_mode: NetworkMode::default(),
            manual_nodes: Vec::new(),
        }
    }
}

impl AppSettings {
    /// Apply only the user-editable sections (`stream`, `rtsp_server`,
    /// `credentials`) from `incoming`, leaving backend-owned fields
    /// (`adopted_subnets`, `zoom_positions`) untouched. The device cache
    /// is no longer part of `AppSettings` at all (lives in its own
    /// file — see `cache_path`), so `save_config` is structurally
    /// incapable of wiping it now; this merge still guards the other
    /// two backend-owned fields against the same class of bug.
    pub fn merge_user_fields(&mut self, incoming: AppSettings) {
        self.stream = incoming.stream;
        self.rtsp_server = incoming.rtsp_server;
        self.credentials = incoming.credentials;
    }
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
    /// only via `upsert_cached_device` / `remove_cached_device` (called
    /// from the DeviceRegistry-backed IPC handlers in commands::network).
    cache: Mutex<Vec<CachedDevice>>,
}

impl AppConfig {
    pub fn load_or_default() -> Self {
        let settings = load_from_disk().unwrap_or_default();

        // Cache loading: prefer the dedicated file. If it doesn't exist,
        // try to migrate the legacy `device_cache` field that lived in
        // `config.toml` before this split (one-time read, then we never
        // look there again — the next config.toml save naturally drops
        // the field since AppSettings doesn't contain it anymore).
        let cache = match load_cache_from_disk() {
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
        }
    }

    pub fn save(&self) -> Result<(), crate::AppError> {
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

    pub fn update(&self, new_settings: AppSettings) -> Result<(), crate::AppError> {
        match self.settings.lock() {
            Ok(mut guard) => *guard = new_settings,
            Err(poisoned) => {
                log::error!("Config mutex poisoned during update, recovering");
                *poisoned.into_inner() = new_settings;
            }
        }
        self.save()
    }

    /// Apply user-editable sections from `incoming` and persist, preserving
    /// backend-owned fields. Use from IPC handlers that take a full
    /// `AppSettings` from the frontend; see `AppSettings::merge_user_fields`
    /// for the rationale.
    pub fn merge_user_settings(&self, incoming: AppSettings) -> Result<(), crate::AppError> {
        match self.settings.lock() {
            Ok(mut guard) => guard.merge_user_fields(incoming),
            Err(poisoned) => {
                log::error!("Config mutex poisoned during merge, recovering");
                poisoned.into_inner().merge_user_fields(incoming);
            }
        }
        self.save()
    }

    /// Replace just the stream config and persist.
    pub fn update_stream(&self, stream: StreamConfig) -> Result<(), crate::AppError> {
        match self.settings.lock() {
            Ok(mut guard) => guard.stream = stream,
            Err(poisoned) => {
                log::error!("Config mutex poisoned during update_stream, recovering");
                poisoned.into_inner().stream = stream;
            }
        }
        self.save()
    }

    /// Replace just the RTSP server config and persist.
    pub fn update_rtsp(&self, rtsp_server: RtspServerConfig) -> Result<(), crate::AppError> {
        match self.settings.lock() {
            Ok(mut guard) => guard.rtsp_server = rtsp_server,
            Err(poisoned) => {
                log::error!("Config mutex poisoned during update_rtsp, recovering");
                poisoned.into_inner().rtsp_server = rtsp_server;
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

    /// Replace the network mode and persist.
    pub fn set_network_mode(&self, mode: NetworkMode) -> Result<(), crate::AppError> {
        match self.settings.lock() {
            Ok(mut guard) => guard.network_mode = mode,
            Err(poisoned) => {
                log::error!("Config mutex poisoned during set_network_mode, recovering");
                poisoned.into_inner().network_mode = mode;
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
            existing.alias = node.alias;
        } else {
            guard.manual_nodes.push(node);
        }
        drop(guard);
        self.save()
    }

    /// Remove a manual node by IP. No-op if the IP isn't pinned.
    pub fn remove_manual_node(&self, ip: &str) -> Result<(), crate::AppError> {
        let removed = match self.settings.lock() {
            Ok(mut guard) => {
                let before = guard.manual_nodes.len();
                guard.manual_nodes.retain(|n| n.ip != ip);
                before != guard.manual_nodes.len()
            }
            Err(poisoned) => {
                log::error!("Config mutex poisoned during remove_manual_node, recovering");
                let mut guard = poisoned.into_inner();
                let before = guard.manual_nodes.len();
                guard.manual_nodes.retain(|n| n.ip != ip);
                before != guard.manual_nodes.len()
            }
        };
        if removed {
            self.save()
        } else {
            Ok(())
        }
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

    /// Insert or update a cached device entry (keyed by MAC).
    /// Persists the cache file after mutation.
    pub fn upsert_cached_device(&self, device: CachedDevice) -> Result<(), crate::AppError> {
        match self.cache.lock() {
            Ok(mut guard) => {
                if let Some(existing) = guard.iter_mut().find(|d| d.mac == device.mac) {
                    *existing = device;
                } else {
                    guard.push(device);
                }
            }
            Err(poisoned) => {
                log::error!("Cache mutex poisoned during upsert, recovering");
                let mut guard = poisoned.into_inner();
                if let Some(existing) = guard.iter_mut().find(|d| d.mac == device.mac) {
                    *existing = device;
                } else {
                    guard.push(device);
                }
            }
        }
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

fn load_cache_from_disk() -> Option<Vec<CachedDevice>> {
    let path = cache_path();
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            log::error!("config: failed to read {}: {}", path.display(), e);
            return None;
        }
    };
    match toml::from_str::<CacheFile>(&content) {
        Ok(parsed) => Some(parsed.devices),
        Err(e) => {
            log::error!(
                "config: device_cache.toml parse failed ({}). Moving aside to {} \
                 so the next save can write a clean file; cached devices will be \
                 rebuilt from the next ARP sweep.",
                e,
                quarantine_path(&path).display()
            );
            quarantine(&path);
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

/// Crash-safe file write: stage to `<path>.tmp`, fsync, then rename
/// onto the final path. The rename is atomic on NTFS and on POSIX
/// filesystems (same-volume rename is a single inode operation), so a
/// reader either sees the old complete file or the new complete file —
/// never a half-written one. Replaces the prior `fs::write` calls in
/// the config save paths, where a kill -9 mid-write would leave a
/// truncated TOML and the next launch would silently fall back to
/// defaults.
fn atomic_write(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    fs::create_dir_all(parent)?;

    // .tmp suffix on the full filename rather than via with_extension
    // — config.toml.tmp is more obviously a staging file than config.tmp,
    // and avoids stomping a sibling file that happens to share the stem.
    let mut tmp_name = path
        .file_name()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
        })?
        .to_owned();
    tmp_name.push(".tmp");
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
    fs::rename(&tmp_path, path)?;
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

fn load_from_disk() -> Option<AppSettings> {
    let path = config_path();
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            log::error!("config: failed to read {}: {}", path.display(), e);
            return None;
        }
    };

    let mut settings: AppSettings = match toml::from_str(&content) {
        Ok(s) => s,
        Err(e) => {
            log::error!(
                "config: config.toml parse failed ({}). Moving aside to {} and \
                 launching with defaults; the corrupted file is preserved for \
                 inspection.",
                e,
                quarantine_path(&path).display()
            );
            quarantine(&path);
            return None;
        }
    };

    // Decrypt credentials if key exists. A decrypt failure means the
    // ciphertext is corrupted or the key changed (e.g., user copied
    // config.toml between machines without .key); log and clear the
    // field rather than handing the encrypted base64 back to the UI as
    // if it were the username.
    if let Ok(key_bytes) = fs::read(key_path()) {
        if key_bytes.len() == 32 {
            settings.credentials.username =
                match decrypt_string(&settings.credentials.username, &key_bytes) {
                    Some(s) => s,
                    None if settings.credentials.username.is_empty() => String::new(),
                    None => {
                        log::error!(
                            "config: failed to decrypt stored username — clearing. \
                             User will need to re-enter credentials."
                        );
                        String::new()
                    }
                };
            settings.credentials.password =
                match decrypt_string(&settings.credentials.password, &key_bytes) {
                    Some(s) => s,
                    None if settings.credentials.password.is_empty() => String::new(),
                    None => {
                        log::error!(
                            "config: failed to decrypt stored password — clearing. \
                             User will need to re-enter credentials."
                        );
                        String::new()
                    }
                };
        }
    }

    Some(settings)
}

fn save_to_disk(settings: &AppSettings) -> Result<(), crate::AppError> {
    let dir = config_dir();
    fs::create_dir_all(&dir).map_err(|e| crate::AppError::Config(e.to_string()))?;

    let key_bytes = get_or_create_key()?;

    let mut save_settings = settings.clone();
    save_settings.credentials.username = encrypt_string(&settings.credentials.username, &key_bytes);
    save_settings.credentials.password = encrypt_string(&settings.credentials.password, &key_bytes);

    let content = toml::to_string_pretty(&save_settings)
        .map_err(|e| crate::AppError::Config(e.to_string()))?;
    atomic_write(&config_path(), content.as_bytes())
        .map_err(|e| crate::AppError::Config(e.to_string()))?;
    Ok(())
}

fn get_or_create_key() -> Result<Vec<u8>, crate::AppError> {
    let path = key_path();
    if let Ok(key) = fs::read(&path) {
        if key.len() == 32 {
            return Ok(key);
        }
    }
    let mut key = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    fs::write(&path, &key).map_err(|e| crate::AppError::Config(e.to_string()))?;

    // Restrict the key file to the current user. On Windows this is
    // typically already the case (AppData/Roaming inherits a user-only
    // ACL), but enforcing it explicitly removes the dependency on that
    // OS default. On Unix it depends on umask, which can default to
    // world-readable — set 0600 explicitly so the AES key never leaks
    // to other local users via a permissive umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
            log::warn!("Failed to chmod 0600 on key file {}: {}", path.display(), e);
        }
    }

    Ok(key)
}

fn encrypt_string(plaintext: &str, key: &[u8]) -> String {
    if plaintext.is_empty() {
        return String::new();
    }
    let cipher = Aes256Gcm::new_from_slice(key).expect("invalid key length");
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.encrypt(nonce, plaintext.as_bytes()) {
        Ok(ciphertext) => {
            let mut combined = nonce_bytes.to_vec();
            combined.extend(ciphertext);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &combined)
        }
        Err(_) => String::new(),
    }
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
mod tests {
    use super::*;

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
        assert_eq!(s.stream.protocol, "rtsp");
        assert_eq!(s.stream.rtsp_port, 554);
        assert_eq!(s.stream.rtsp_path, "/z3-1.sdp");
        assert_eq!(s.stream.udp_port, 8600);
        assert!(s.stream.camera_ip.is_empty());
    }

    #[test]
    fn default_settings_rtsp_server() {
        let s = AppSettings::default();
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

    // ── TOML Serialization ──────────────────────────────────────────

    #[test]
    fn settings_toml_roundtrip() {
        let original = AppSettings::default();
        let toml_str = toml::to_string_pretty(&original).unwrap();
        let parsed: AppSettings = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.stream.protocol, original.stream.protocol);
        assert_eq!(parsed.stream.rtsp_port, original.stream.rtsp_port);
        assert_eq!(parsed.rtsp_server.port, original.rtsp_server.port);
        assert_eq!(parsed.rtsp_server.token, original.rtsp_server.token);
    }

    #[test]
    fn settings_toml_with_populated_fields() {
        let settings = AppSettings {
            stream: StreamConfig {
                protocol: "udp".into(),
                rtsp_port: 8554,
                rtsp_path: "/cam1".into(),
                udp_port: 9000,
                camera_ip: "10.0.0.5".into(),
            },
            rtsp_server: RtspServerConfig {
                enabled: true,
                port: 9554,
                token: "abc123".into(),
                bind_interface: "Ethernet 2".into(),
            },
            credentials: Credentials {
                username: "admin".into(),
                password: "secret".into(),
            },
            adopted_subnets: std::collections::HashMap::new(),
            zoom_positions: std::collections::HashMap::new(),
            network_mode: NetworkMode::default(),
            manual_nodes: Vec::new(),
        };
        let toml_str = toml::to_string_pretty(&settings).unwrap();
        let parsed: AppSettings = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.stream.protocol, "udp");
        assert_eq!(parsed.stream.camera_ip, "10.0.0.5");
        assert_eq!(parsed.rtsp_server.bind_interface, "Ethernet 2");
        assert!(parsed.rtsp_server.enabled);
        assert_eq!(parsed.credentials.username, "admin");
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
    #[cfg_attr(not(target_os = "windows"), ignore)]
    fn get_or_create_key_returns_32_bytes() {
        // Uses the real config dir (%APPDATA%/PocketStream/.key).
        // Skipped on Linux CI where the dir doesn't exist.
        let key = get_or_create_key().unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    #[cfg_attr(not(target_os = "windows"), ignore)]
    fn get_or_create_key_is_stable() {
        // Uses the real config dir. Skipped on Linux CI.
        let k1 = get_or_create_key().unwrap();
        let k2 = get_or_create_key().unwrap();
        assert_eq!(k1, k2, "Same key should be returned on subsequent calls");
    }

    // ── User-Settings Merge ─────────────────────────────────────────
    // Regression for the prior `save_config` behavior, where a frontend
    // payload that omitted a backend-owned field would deserialize via
    // serde-default to empty and the next save would persist the empty
    // value. The device_cache angle is now structurally impossible
    // (cache lives in its own file outside AppSettings); these tests
    // still cover the remaining backend-owned fields.

    #[test]
    fn appsettings_no_longer_carries_device_cache() {
        // Compile-time check that AppSettings doesn't accidentally
        // regrow a `device_cache` field — if someone re-adds it the
        // round-trip TOML would carry it, and we'd be back where T0.1
        // started. The field name must not appear in the serialized
        // form.
        let s = AppSettings::default();
        let toml_str = toml::to_string_pretty(&s).unwrap();
        assert!(
            !toml_str.contains("device_cache"),
            "AppSettings must not serialize a device_cache field — \
             the cache lives in device_cache.toml. Found:\n{}",
            toml_str
        );
    }

    #[test]
    fn merge_user_fields_preserves_adopted_subnets() {
        let mut current = AppSettings::default();
        current
            .adopted_subnets
            .insert("192.168.1.0/24".into(), "192.168.1.50".into());

        let incoming = AppSettings::default();
        current.merge_user_fields(incoming);

        assert_eq!(current.adopted_subnets.len(), 1);
        assert_eq!(
            current.adopted_subnets.get("192.168.1.0/24"),
            Some(&"192.168.1.50".to_string())
        );
    }

    #[test]
    fn merge_user_fields_preserves_zoom_positions() {
        let mut current = AppSettings::default();
        current.zoom_positions.insert("192.168.1.10".into(), 75);

        let incoming = AppSettings::default();
        current.merge_user_fields(incoming);

        assert_eq!(current.zoom_positions.len(), 1);
        assert_eq!(current.zoom_positions.get("192.168.1.10"), Some(&75));
    }

    #[test]
    fn merge_user_fields_preserves_network_mode() {
        // A partial frontend payload (just stream/rtsp/credentials) must
        // not clobber the user's chosen mode via serde defaults.
        let mut current = AppSettings::default();
        current.network_mode = NetworkMode::StaticManual;
        current.merge_user_fields(AppSettings::default());
        assert_eq!(current.network_mode, NetworkMode::StaticManual);
    }

    #[test]
    fn merge_user_fields_preserves_manual_nodes() {
        let mut current = AppSettings::default();
        current.manual_nodes.push(ManualNode {
            ip: "192.168.1.50".into(),
            alias: "CAM".into(),
        });
        current.merge_user_fields(AppSettings::default());
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
            ip: "192.168.1.202".into(),
            alias: "PTU".into(),
        });
        settings.manual_nodes.push(ManualNode {
            ip: "10.13.248.55".into(),
            alias: String::new(),
        });
        let toml_str = toml::to_string_pretty(&settings).unwrap();
        let parsed: AppSettings = toml::from_str(&toml_str).unwrap();
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
token = "abc"

[credentials]
username = ""
password = ""
"#;
        let parsed: AppSettings = toml::from_str(legacy).unwrap();
        assert_eq!(parsed.network_mode, NetworkMode::StaticAuto);
        assert!(parsed.manual_nodes.is_empty());
    }

    #[test]
    fn merge_user_fields_applies_user_editable_fields() {
        let mut current = AppSettings::default();
        let mut incoming = AppSettings::default();
        incoming.stream.protocol = "udp".into();
        incoming.stream.rtsp_port = 9999;
        incoming.rtsp_server.enabled = true;
        incoming.rtsp_server.port = 7777;
        incoming.credentials.username = "admin".into();
        incoming.credentials.password = "hunter2".into();

        current.merge_user_fields(incoming);

        assert_eq!(current.stream.protocol, "udp");
        assert_eq!(current.stream.rtsp_port, 9999);
        assert!(current.rtsp_server.enabled);
        assert_eq!(current.rtsp_server.port, 7777);
        assert_eq!(current.credentials.username, "admin");
        assert_eq!(current.credentials.password, "hunter2");
    }

    #[test]
    fn merge_user_fields_clears_user_editable_fields_when_incoming_empty() {
        // Sanity check: user-editable fields are *replaced*, not merged
        // within. An empty username in `incoming` must clear the existing
        // value — otherwise a user can't actually unset a credential.
        let mut current = AppSettings::default();
        current.credentials.username = "old_user".into();
        current.credentials.password = "old_pass".into();

        let incoming = AppSettings::default();
        current.merge_user_fields(incoming);

        assert!(current.credentials.username.is_empty());
        assert!(current.credentials.password.is_empty());
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
                    mac: "AA:BB:CC:DD:EE:FF".into(),
                    ip: "192.168.1.10".into(),
                    subnet: "192.168.1.0/24".into(),
                    open_ports: vec![80, 554],
                    alias: "Front".into(),
                    last_seen: "2026-04-27T12:00:00Z".into(),
                },
                CachedDevice {
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
        let tmp = dir.path().join("config.toml.tmp");
        assert!(
            !tmp.exists(),
            "tmp staging file must be renamed away on success"
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
        // Simulate the kill-9 scenario by writing the staging file
        // ourselves, leaving it abandoned, and then doing a real
        // atomic_write — the abandoned tmp must not corrupt the live
        // file on the rename.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let tmp = dir.path().join("config.toml.tmp");
        fs::write(&path, "live data").unwrap();
        fs::write(&tmp, "abandoned tmp").unwrap();

        atomic_write(&path, b"new data").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new data");
        assert!(!tmp.exists());
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
}
