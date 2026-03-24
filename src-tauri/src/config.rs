use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    /// Input protocol: "rtsp" or "udp"
    pub protocol: String,
    /// Camera RTSP port (default 554)
    pub rtsp_port: u16,
    /// Camera RTSP path (default "/live")
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub stream: StreamConfig,
    pub rtsp_server: RtspServerConfig,
    pub credentials: Credentials,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            stream: StreamConfig {
                protocol: "rtsp".into(),
                rtsp_port: 554,
                rtsp_path: "/live".into(),
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
        }
    }
}

pub struct AppConfig {
    pub settings: Mutex<AppSettings>,
}

impl AppConfig {
    pub fn load_or_default() -> Self {
        let settings = load_from_disk().unwrap_or_default();
        Self {
            settings: Mutex::new(settings),
        }
    }

    pub fn save(&self) -> Result<(), crate::AppError> {
        let settings = self.settings.lock().unwrap().clone();
        save_to_disk(&settings)
    }

    pub fn get(&self) -> AppSettings {
        self.settings.lock().unwrap().clone()
    }

    pub fn update(&self, new_settings: AppSettings) -> Result<(), crate::AppError> {
        *self.settings.lock().unwrap() = new_settings;
        self.save()
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

fn key_path() -> PathBuf {
    config_dir().join(".key")
}

fn load_from_disk() -> Option<AppSettings> {
    let content = fs::read_to_string(config_path()).ok()?;
    // For credentials, decrypt after loading
    let mut settings: AppSettings = toml::from_str(&content).ok()?;

    // Decrypt credentials if key exists
    if let Ok(key_bytes) = fs::read(key_path()) {
        if key_bytes.len() == 32 {
            settings.credentials.username =
                decrypt_string(&settings.credentials.username, &key_bytes)
                    .unwrap_or(settings.credentials.username);
            settings.credentials.password =
                decrypt_string(&settings.credentials.password, &key_bytes)
                    .unwrap_or(settings.credentials.password);
        }
    }

    Some(settings)
}

fn save_to_disk(settings: &AppSettings) -> Result<(), crate::AppError> {
    let dir = config_dir();
    fs::create_dir_all(&dir).map_err(|e| crate::AppError::Config(e.to_string()))?;

    // Ensure encryption key exists
    let key_bytes = get_or_create_key()?;

    // Encrypt credentials before saving
    let mut save_settings = settings.clone();
    save_settings.credentials.username =
        encrypt_string(&settings.credentials.username, &key_bytes);
    save_settings.credentials.password =
        encrypt_string(&settings.credentials.password, &key_bytes);

    let content =
        toml::to_string_pretty(&save_settings).map_err(|e| crate::AppError::Config(e.to_string()))?;
    fs::write(config_path(), content).map_err(|e| crate::AppError::Config(e.to_string()))?;
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
        let short = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &[1, 2, 3, 4, 5],
        );
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
        let mut combined = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &encrypted,
        )
        .unwrap();
        // Flip a byte in the ciphertext (after the 12-byte nonce)
        if combined.len() > 13 {
            combined[13] ^= 0xFF;
        }
        let corrupted = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &combined,
        );
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
        assert_eq!(s.stream.rtsp_path, "/live");
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
    fn get_or_create_key_returns_32_bytes() {
        // This test uses the real config dir — idempotent since it
        // only creates the key if it doesn't already exist.
        let key = get_or_create_key().unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn get_or_create_key_is_stable() {
        let k1 = get_or_create_key().unwrap();
        let k2 = get_or_create_key().unwrap();
        assert_eq!(k1, k2, "Same key should be returned on subsequent calls");
    }
}
