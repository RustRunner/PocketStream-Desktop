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
