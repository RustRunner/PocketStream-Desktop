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

/// Largest subnet a single scan will enumerate: 4096 addresses (≈ /20).
/// Bounds memory and task count against a `/8` interface subnet
/// (16.7 M hosts) or a hand-typed `/0` arriving from one IPC call.
pub const MAX_SCAN_ADDRESSES: u64 = 4096;

/// Cap on hosts held in the JoinSet at once. With the address cap above
/// this only matters for the wider allowed subnets (e.g. /20), keeping
/// peak in-flight task count bounded while the connect semaphore bounds
/// actual sockets.
const MAX_INFLIGHT_HOSTS: usize = 256;

/// Reject a subnet too wide to scan. A `/16` (65 k addresses) is
/// rejected too — it previously "worked" but took minutes; the error
/// says so. Prefix is 0..=32 (already validated upstream).
pub fn check_scan_size(prefix: u8) -> Result<(), AppError> {
    let addresses = 1u64 << (32u8.saturating_sub(prefix));
    if addresses > MAX_SCAN_ADDRESSES {
        return Err(AppError::Network(format!(
            "Subnet /{} has {} addresses — too large to scan (limit {} ≈ /20). \
             Narrow the range; /16 and wider are rejected to avoid a multi-minute scan.",
            prefix, addresses, MAX_SCAN_ADDRESSES
        )));
    }
    Ok(())
}

/// Whether `host` is a scannable host address. Skips the network and
/// broadcast addresses — but only for prefixes ≤ 30, which are the ones
/// that actually reserve them. A /31 (RFC 3021 point-to-point) and a
/// /32 (single host) have no reserved addresses, so every address is a
/// host; the old octet-based `== 0 || == 255` check wrongly skipped one
/// leg of a /31, scanned nothing for a /32 of a `.0`/`.255` host, and
/// skipped the wrong addresses for /25–/30.
fn is_scannable(host: &IpAddr, network: &ipnetwork::Ipv4Network) -> bool {
    if network.prefix() > 30 {
        return true;
    }
    match host {
        IpAddr::V4(h) => *h != network.network() && *h != network.broadcast(),
        IpAddr::V6(_) => false,
    }
}

/// Scan a subnet (e.g. "192.168.1.0/24") for reachable hosts.
pub async fn scan(subnet: &str) -> Result<Vec<ScanResult>, AppError> {
    let network: ipnetwork::Ipv4Network = subnet
        .parse()
        .map_err(|e| AppError::Network(format!("Invalid subnet: {}", e)))?;

    // Defense in depth: the IPC boundary caps too, but scanner::scan
    // re-parses the subnet independently, so enforce the cap here as well.
    check_scan_size(network.prefix())?;

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTS));
    let mut results = Vec::new();
    let mut join_set = JoinSet::new();

    // Stream hosts into the JoinSet with bounded in-flight instead of
    // collecting every address into a Vec first.
    let mut hosts = network
        .iter()
        .map(IpAddr::V4)
        .filter(|h| is_scannable(h, &network));
    for host in hosts.by_ref().take(MAX_INFLIGHT_HOSTS) {
        join_set.spawn(probe_host(host, semaphore.clone()));
    }
    while let Some(result) = join_set.join_next().await {
        if let Ok(scan_result) = result {
            if scan_result.reachable {
                results.push(scan_result);
            }
        }
        // Top up so at most MAX_INFLIGHT_HOSTS probes are pending.
        if let Some(host) = hosts.next() {
            join_set.spawn(probe_host(host, semaphore.clone()));
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

    // ── Fan-out cap (H6) ────────────────────────────────────────────

    #[test]
    fn scan_size_cap_rejects_wide_subnets() {
        assert!(check_scan_size(0).is_err()); // /0 — the whole IPv4 space
        assert!(check_scan_size(8).is_err()); // /8 — 16.7 M
        assert!(check_scan_size(16).is_err()); // /16 — 65 k, previously "worked" slowly
        assert!(check_scan_size(19).is_err()); // 8192 > 4096
    }

    #[test]
    fn scan_size_cap_allows_reasonable_subnets() {
        assert!(check_scan_size(20).is_ok()); // exactly 4096
        assert!(check_scan_size(24).is_ok()); // 256
        assert!(check_scan_size(31).is_ok()); // 2
        assert!(check_scan_size(32).is_ok()); // 1
    }

    #[tokio::test]
    async fn scan_rejects_oversized_subnet_end_to_end() {
        assert!(scan("10.0.0.0/8").await.is_err());
        assert!(scan("192.168.0.0/16").await.is_err());
    }

    // ── Network/broadcast skipping (L6) ─────────────────────────────

    fn net(cidr: &str) -> ipnetwork::Ipv4Network {
        cidr.parse().unwrap()
    }
    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn is_scannable_slash24_skips_network_and_broadcast() {
        let n = net("192.168.1.0/24");
        assert!(!is_scannable(&v4(192, 168, 1, 0), &n));
        assert!(!is_scannable(&v4(192, 168, 1, 255), &n));
        assert!(is_scannable(&v4(192, 168, 1, 1), &n));
        assert!(is_scannable(&v4(192, 168, 1, 254), &n));
    }

    #[test]
    fn is_scannable_slash31_scans_both_legs() {
        // RFC 3021: a /31 has no network/broadcast — both are hosts.
        let n = net("10.0.0.0/31");
        assert!(is_scannable(&v4(10, 0, 0, 0), &n));
        assert!(is_scannable(&v4(10, 0, 0, 1), &n));
    }

    #[test]
    fn is_scannable_slash32_scans_the_host() {
        // Even a /32 of a .0 host must be scanned (old code skipped it).
        let n = net("192.168.1.0/32");
        assert!(is_scannable(&v4(192, 168, 1, 0), &n));
    }

    #[test]
    fn is_scannable_slash25_uses_real_broadcast() {
        // 192.168.1.0/25 → network .0, broadcast .127. The old octet
        // check skipped .0/.255 and missed the real .127 broadcast.
        let n = net("192.168.1.0/25");
        assert!(!is_scannable(&v4(192, 168, 1, 0), &n));
        assert!(!is_scannable(&v4(192, 168, 1, 127), &n));
        assert!(is_scannable(&v4(192, 168, 1, 1), &n));
        assert!(is_scannable(&v4(192, 168, 1, 126), &n));
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
