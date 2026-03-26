use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use crate::error::AppError;

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub ip: String,
    pub reachable: bool,
    /// Ports found open during scan
    pub open_ports: Vec<u16>,
}

/// Common ports to check on discovered hosts.
const PROBE_PORTS: &[u16] = &[
    22,   // SSH
    80,   // HTTP
    443,  // HTTPS
    554,  // RTSP
    8080, // Alt HTTP
    8554, // Alt RTSP
    8899, // Common camera port
];

const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_CONCURRENT: usize = 64;

/// Scan a subnet (e.g. "192.168.1.0/24") for reachable hosts.
pub async fn scan(subnet: &str) -> Result<Vec<ScanResult>, AppError> {
    let network: ipnetwork::IpNetwork = subnet
        .parse()
        .map_err(|e| AppError::Network(format!("Invalid subnet: {}", e)))?;

    let hosts: Vec<IpAddr> = network.iter().collect();
    let mut results = Vec::new();
    let mut join_set = JoinSet::new();
    let mut pending = 0;

    for host in hosts {
        // Skip network and broadcast addresses for /24+
        if network.prefix() >= 24 {
            let octets = match host {
                IpAddr::V4(v4) => v4.octets(),
                _ => continue,
            };
            if octets[3] == 0 || octets[3] == 255 {
                continue;
            }
        }

        join_set.spawn(probe_host(host));
        pending += 1;

        // Limit concurrency
        if pending >= MAX_CONCURRENT {
            if let Some(result) = join_set.join_next().await {
                pending -= 1;
                if let Ok(scan_result) = result {
                    if scan_result.reachable {
                        results.push(scan_result);
                    }
                }
            }
        }
    }

    // Collect remaining
    while let Some(result) = join_set.join_next().await {
        if let Ok(scan_result) = result {
            if scan_result.reachable {
                results.push(scan_result);
            }
        }
    }

    results.sort_by_key(|r| r.ip.parse::<IpAddr>().ok());
    Ok(results)
}

async fn probe_host(ip: IpAddr) -> ScanResult {
    let mut set = JoinSet::new();

    for &port in PROBE_PORTS {
        let addr = SocketAddr::new(ip, port);
        set.spawn(async move {
            match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(_)) => Some(port),
                _ => None,
            }
        });
    }

    let mut open_ports = Vec::new();
    while let Some(result) = set.join_next().await {
        if let Ok(Some(port)) = result {
            open_ports.push(port);
        }
    }
    open_ports.sort();

    ScanResult {
        ip: ip.to_string(),
        reachable: !open_ports.is_empty(),
        open_ports,
    }
}
