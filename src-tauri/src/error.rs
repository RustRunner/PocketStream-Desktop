use serde::ser::SerializeStruct;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Network error: {0}")]
    Network(String),

    /// Npcap is required for raw ARP capture but isn't installed. Carries
    /// no message — the frontend recognizes the discriminator and surfaces
    /// the install dialog directly. The Display impl provides a fallback
    /// for plain logging.
    #[error(
        "Npcap is not installed -- ARP discovery requires Npcap (https://npcap.com/#download)"
    )]
    NpcapMissing,

    #[error("Stream error: {0}")]
    Stream(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Camera error: {0}")]
    Camera(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

impl AppError {
    /// Stable discriminator for frontend branching. Don't rename casually —
    /// these strings are part of the IPC contract.
    pub fn kind(&self) -> &'static str {
        match self {
            AppError::Network(_) => "Network",
            AppError::NpcapMissing => "NpcapMissing",
            AppError::Stream(_) => "Stream",
            AppError::Config(_) => "Config",
            AppError::Camera(_) => "Camera",
            AppError::Io(_) => "Io",
            AppError::Serde(_) => "Serde",
        }
    }
}

/// Serialize as `{ "kind": "<variant>", "message": "<display>" }` so the
/// frontend can both display a human-readable message AND branch on the
/// discriminator (e.g., `if (err.kind === "NpcapMissing") openInstallDialog()`).
/// All frontend toast/log sites should run errors through `formatError(e)`
/// in `src/lib/errors.js` to survive both this object shape and any legacy
/// string error that escapes the typed channel.
impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("AppError", 2)?;
        s.serialize_field("kind", self.kind())?;
        s.serialize_field("message", &self.to_string())?;
        s.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Display ─────────────────────────────────────────────────────

    #[test]
    fn display_network_error() {
        let err = AppError::Network("timeout".into());
        assert_eq!(err.to_string(), "Network error: timeout");
    }

    #[test]
    fn display_stream_error() {
        let err = AppError::Stream("pipeline failed".into());
        assert_eq!(err.to_string(), "Stream error: pipeline failed");
    }

    #[test]
    fn display_config_error() {
        let err = AppError::Config("bad toml".into());
        assert_eq!(err.to_string(), "Config error: bad toml");
    }

    #[test]
    fn display_camera_error() {
        let err = AppError::Camera("no device".into());
        assert_eq!(err.to_string(), "Camera error: no device");
    }

    #[test]
    fn display_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let err = AppError::Io(io_err);
        assert_eq!(err.to_string(), "IO error: gone");
    }

    #[test]
    fn display_npcap_missing() {
        let err = AppError::NpcapMissing;
        assert!(err.to_string().contains("Npcap"));
        assert!(err.to_string().contains("npcap.com"));
    }

    // ── Discriminator (kind) ────────────────────────────────────────

    #[test]
    fn kind_returns_stable_discriminators() {
        assert_eq!(AppError::Network("x".into()).kind(), "Network");
        assert_eq!(AppError::NpcapMissing.kind(), "NpcapMissing");
        assert_eq!(AppError::Stream("x".into()).kind(), "Stream");
        assert_eq!(AppError::Config("x".into()).kind(), "Config");
        assert_eq!(AppError::Camera("x".into()).kind(), "Camera");
    }

    // ── Serialization (typed shape) ─────────────────────────────────

    #[test]
    fn serialize_emits_kind_and_message() {
        let err = AppError::Network("test error".into());
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["kind"], "Network");
        assert_eq!(json["message"], "Network error: test error");
    }

    #[test]
    fn serialize_config_error_emits_typed_object() {
        let err = AppError::Config("missing key".into());
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["kind"], "Config");
        assert_eq!(json["message"], "Config error: missing key");
    }

    #[test]
    fn serialize_npcap_missing_carries_install_url_in_message() {
        let err = AppError::NpcapMissing;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["kind"], "NpcapMissing");
        // Message must remain useful for plain toast display even when
        // the frontend doesn't branch on the kind.
        let msg = json["message"].as_str().unwrap();
        assert!(msg.contains("Npcap"));
        assert!(msg.contains("npcap.com"));
    }

    #[test]
    fn serialize_io_error_emits_typed_object() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err: AppError = io_err.into();
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["kind"], "Io");
        assert!(json["message"].as_str().unwrap().contains("denied"));
    }

    // ── From impls ──────────────────────────────────────────────────

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err: AppError = io_err.into();
        assert!(matches!(err, AppError::Io(_)));
        assert!(err.to_string().contains("denied"));
    }

    #[test]
    fn from_serde_error() {
        let bad_json = "not json";
        let serde_err = serde_json::from_str::<serde_json::Value>(bad_json).unwrap_err();
        let err: AppError = serde_err.into();
        assert!(matches!(err, AppError::Serde(_)));
    }
}
