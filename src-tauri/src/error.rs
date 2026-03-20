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
