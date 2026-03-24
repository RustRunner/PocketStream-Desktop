use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Network error: {0}")]
    Network(String),

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

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn serialize_to_json_string() {
        let err = AppError::Network("test error".into());
        let json = serde_json::to_string(&err).unwrap();
        assert_eq!(json, "\"Network error: test error\"");
    }

    #[test]
    fn serialize_config_error_to_json() {
        let err = AppError::Config("missing key".into());
        let json = serde_json::to_string(&err).unwrap();
        assert_eq!(json, "\"Config error: missing key\"");
    }

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
