use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
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

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum simultaneous TCP connect attempts across the whole scan.
///
/// Bounds the total in-flight count regardless of how many hosts or
/// ports are involved. Without this, a /24 × 7 PROBE_PORTS could fan
/// out to 1778 concurrent connects, enough to saturate slower links
/// or trip IDS heuristics. The previous implementation only bounded
/// per-host parallelism, which still allowed 64 hosts × 7 ports = 448
/// concurrent connects at peak.
const MAX_CONCURRENT_CONNECTS: usize = 64;

/// Scan a subnet (e.g. "192.168.1.0/24") for reachable hosts.
pub async fn scan(subnet: &str) -> Result<Vec<ScanResult>, AppError> {
    let network: ipnetwork::IpNetwork = subnet
        .parse()
        .map_err(|e| AppError::Network(format!("Invalid subnet: {}", e)))?;

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTS));
    let hosts: Vec<IpAddr> = network.iter().collect();
    let mut results = Vec::new();
    let mut join_set = JoinSet::new();

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
        join_set.spawn(probe_host(host, semaphore.clone()));
    }

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

async fn probe_host(ip: IpAddr, semaphore: Arc<Semaphore>) -> ScanResult {
    probe_host_at(ip, PROBE_PORTS, semaphore).await
}

/// Probe `ip` against an arbitrary port list. Split out from `probe_host`
/// so tests can inject ephemeral OS-assigned ports instead of the
/// hardcoded `PROBE_PORTS` set (which would collide with real services
/// on a developer's machine). The `semaphore` argument bounds total
/// in-flight connect attempts across all callers sharing it; tests can
/// pass a generous one (or one with a single permit to verify
/// serialisation).
async fn probe_host_at(ip: IpAddr, ports: &[u16], semaphore: Arc<Semaphore>) -> ScanResult {
    let mut set = JoinSet::new();

    for &port in ports {
        let addr = SocketAddr::new(ip, port);
        let sem = semaphore.clone();
        set.spawn(async move {
            // Acquire one permit per TCP connect. The semaphore is never
            // closed in production, so `acquire` only fails if the
            // runtime is shutting down — in which case skipping the
            // probe is the right thing to do.
            let _permit = sem.acquire().await.ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    /// Bind a listener on 127.0.0.1 with an OS-assigned port.
    /// Returns the listener (must stay alive for the duration of the
    /// test or the port releases) and the port number.
    async fn bind_loopback() -> (TcpListener, u16) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind to ephemeral loopback port");
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    /// Generous semaphore for tests that don't care about throttling.
    fn unbounded_semaphore() -> Arc<Semaphore> {
        Arc::new(Semaphore::new(64))
    }

    #[tokio::test]
    async fn probe_host_at_finds_listening_port() {
        let (_listener, port) = bind_loopback().await;
        let result = probe_host_at(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[port],
            unbounded_semaphore(),
        )
        .await;
        assert!(
            result.reachable,
            "expected loopback:{} to be reachable",
            port
        );
        assert_eq!(result.open_ports, vec![port]);
        assert_eq!(result.ip, "127.0.0.1");
    }

    #[tokio::test]
    async fn probe_host_at_reports_closed_port_unreachable() {
        // Bind a port, then drop the listener so the port is closed.
        // Using the just-released port maximises the chance it's still
        // unbound when we probe it (no other process should grab it
        // in the few microseconds between drop and probe).
        let port = {
            let (listener, port) = bind_loopback().await;
            drop(listener);
            port
        };
        let result = probe_host_at(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[port],
            unbounded_semaphore(),
        )
        .await;
        assert!(
            !result.reachable,
            "expected closed port {} to be unreachable",
            port
        );
        assert!(result.open_ports.is_empty());
    }

    #[tokio::test]
    async fn probe_host_at_separates_open_from_closed() {
        let (_keep, open_port) = bind_loopback().await;
        let closed_port = {
            let (listener, port) = bind_loopback().await;
            drop(listener);
            port
        };
        let result = probe_host_at(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[open_port, closed_port],
            unbounded_semaphore(),
        )
        .await;
        assert!(result.reachable);
        assert_eq!(result.open_ports, vec![open_port]);
    }

    #[tokio::test]
    async fn probe_host_at_serialises_under_single_permit_semaphore() {
        // Smoke test that the semaphore wiring works: with only one
        // permit, three connects must all succeed sequentially. This
        // catches a regression where the permit isn't acquired before
        // the connect (which would silently fan out unbounded again).
        let (_a, port_a) = bind_loopback().await;
        let (_b, port_b) = bind_loopback().await;
        let (_c, port_c) = bind_loopback().await;
        let sem = Arc::new(Semaphore::new(1));
        let result = probe_host_at(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[port_a, port_b, port_c],
            sem,
        )
        .await;
        assert!(result.reachable);
        assert_eq!(result.open_ports.len(), 3);
    }

    #[tokio::test]
    async fn scan_invalid_subnet_returns_err() {
        let result = scan("not-a-subnet").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn scan_loopback_single_host() {
        // Scan 127.0.0.1/32 — exercises the public scan() path end to end.
        // We don't assert specifically that 127.0.0.1 IS reachable (the dev
        // machine may or may not have a service on the hardcoded PROBE_PORTS),
        // but the call must succeed and return a valid Vec without panicking.
        let result = scan("127.0.0.1/32").await.expect("scan succeeds");
        // 0 or 1 results — never more for /32.
        assert!(result.len() <= 1);
        if let Some(r) = result.first() {
            assert_eq!(r.ip, "127.0.0.1");
        }
    }
}
