//! ONVIF device discovery and management.
//!
//! ONVIF (Open Network Video Interface Forum) is the standard protocol
//! for IP camera interoperability. This module handles:
//! - WS-Discovery for finding cameras on the network
//! - Device information retrieval
//! - Stream profile enumeration
//! - PTZ capability detection
//!
//! # Implementation Notes
//!
//! ONVIF uses SOAP/XML over HTTP. For the initial implementation,
//! we use raw HTTP requests with handcrafted SOAP envelopes.
//! Consider the `onvif` crate once it stabilizes.

use crate::camera::{OnvifDevice, StreamProfile};
use crate::error::AppError;

/// WS-Discovery multicast address and port
#[allow(dead_code)]
const WS_DISCOVERY_ADDR: &str = "239.255.255.250:3702";

/// Discover ONVIF devices on the network via WS-Discovery.
///
/// Sends a multicast probe and collects responses.
/// If `subnet` is provided, only returns devices in that range.
pub async fn discover(subnet: Option<&str>) -> Result<Vec<OnvifDevice>, AppError> {
    log::info!("Starting ONVIF discovery (subnet filter: {:?})", subnet);

    // TODO: Implement WS-Discovery
    //
    // 1. Create UDP socket bound to 0.0.0.0:0
    // 2. Set multicast TTL
    // 3. Send SOAP Probe message to 239.255.255.250:3702:
    //
    //    <?xml version="1.0" encoding="UTF-8"?>
    //    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    //                xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    //                xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
    //                xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
    //      <s:Header>
    //        <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
    //        <a:MessageID>uuid:...</a:MessageID>
    //        <a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
    //      </s:Header>
    //      <s:Body>
    //        <d:Probe>
    //          <d:Types>dn:NetworkVideoTransmitter</d:Types>
    //        </d:Probe>
    //      </s:Body>
    //    </s:Envelope>
    //
    // 4. Collect ProbeMatch responses (3 second timeout)
    // 5. Parse XAddrs from each response
    // 6. Query each device for capabilities

    Ok(vec![])
}

/// Get detailed info from an ONVIF device.
#[allow(dead_code)]
pub async fn get_device_info(service_url: &str) -> Result<OnvifDevice, AppError> {
    log::info!("Querying ONVIF device: {}", service_url);

    // TODO: Send GetDeviceInformation SOAP request
    // TODO: Send GetProfiles SOAP request
    // TODO: Send GetServiceCapabilities to check PTZ support

    Err(AppError::Camera("ONVIF not yet implemented".into()))
}

/// Get stream URIs for all profiles on a device.
#[allow(dead_code)]
pub async fn get_stream_profiles(service_url: &str) -> Result<Vec<StreamProfile>, AppError> {
    log::info!("Getting stream profiles from: {}", service_url);

    // TODO: Send GetProfiles, then GetStreamUri for each profile token

    Ok(vec![])
}
