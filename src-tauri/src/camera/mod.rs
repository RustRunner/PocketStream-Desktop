pub mod flir_ptu;
pub mod onvif;
pub mod ptz;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct OnvifDevice {
    /// Device IP address
    pub ip: String,
    /// Device name / model
    pub name: String,
    /// Manufacturer
    pub manufacturer: String,
    /// ONVIF device service URL
    pub service_url: String,
    /// Whether PTZ is supported
    pub ptz_supported: bool,
    /// Available stream profiles
    pub profiles: Vec<StreamProfile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamProfile {
    pub name: String,
    pub token: String,
    pub resolution_width: u32,
    pub resolution_height: u32,
    pub stream_uri: String,
}

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct PtzPreset {
    pub number: u32,
    pub name: String,
}
