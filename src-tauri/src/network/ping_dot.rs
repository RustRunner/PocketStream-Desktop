//! Selected-Ethernet ICMP diagnostics. Node dots use backend presence;
//! these results never promote a record or stamp positive evidence.
//!
//! Pings every IP in the device registry on a 30 s cadence, with a
//! 100 ms stagger between probes so the pinger doesn't burst the
//! adapter (especially relevant on the ASIX AX88179 — see comment in
//! `mod.rs::ping_sweep_subnets`).
//!
//! The first pass runs immediately and emits attributed diagnostic
//! `device-ping-result` events for verified records only.
//!
//! Runs in every mode (Static-Manual, Static-Auto, DHCP). The pinger
//! declines records without fresh selected-adapter identity and source.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;

#[cfg(not(windows))]
use crate::network::async_cmd;
use crate::network::DeviceRegistry;

/// Cadence between full registry sweeps once steady state is reached.
const PING_INTERVAL: Duration = Duration::from_secs(30);
/// Gap between successive probes inside one sweep. Spreads the load so
/// 20+ nodes don't all hit the adapter in the same millisecond.
const PING_STAGGER: Duration = Duration::from_millis(100);
/// Per-probe timeout passed to `ping -w`. 1 s is enough for any LAN
/// device that's actually present; longer just delays the red-dot
/// verdict.
const PING_TIMEOUT_MS: u32 = 1000;

pub struct PingDotHandle {
    cancel: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl PingDotHandle {
    /// Cancel the polling loop and wait for the task to drain.
    pub async fn stop(self) {
        let _ = self.cancel.send(true);
        let _ = self.task.await;
    }
}

/// Spawn the pinger task. Returns a handle so the caller (typically
/// `NetworkManager`) can stop it on shutdown or mode change.
fn start(
    readiness: Arc<super::readiness::CameraReadiness>,
    bridge: Arc<dyn crate::bridge::AppBridge>,
    registry: Arc<DeviceRegistry>,
) -> PingDotHandle {
    readiness
        .diagnostic_ready
        .store(true, std::sync::atomic::Ordering::Release);
    let (cancel_tx, mut cancel_rx) = watch::channel(false);

    let task = tokio::spawn(async move {
        let mut first_pass = true;

        loop {
            if !first_pass {
                tokio::select! {
                    _ = tokio::time::sleep(PING_INTERVAL) => {}
                    _ = cancel_rx.changed() => return,
                }
            }
            first_pass = false;

            if *cancel_rx.borrow() {
                return;
            }

            // Snapshot IPs once per pass. New devices arriving mid-pass
            // get picked up on the next iteration — within 30 s. Only
            // valid IPv4 addresses go to ping.exe — a garbage string (from
            // a corrupted cache row) would otherwise trigger a DNS lookup
            // and a false dot.
            let rows: Vec<_> = registry
                .snapshot()
                .into_iter()
                .filter(|d| d.ip.parse::<std::net::Ipv4Addr>().is_ok())
                .collect();

            for row in rows {
                if *cancel_rx.borrow() {
                    return;
                }
                let readiness = readiness.clone();
                let bridge = bridge.clone();
                tokio::spawn(async move {
                    let target = super::route::CameraTarget {
                        key: row.mac.clone(),
                        expected_mac: Some(row.mac),
                        ip: row.ip,
                    };
                    let Ok(path) = readiness.ready(&target).await else {
                        return;
                    };
                    let reachable = probe_bound(&target.ip, path.source, path.index).await;
                    let Ok(current) = readiness.ready(&target).await else {
                        return;
                    };
                    if path.fence.is_stale()
                        || current.source != path.source
                        || current.index != path.index
                    {
                        return;
                    }
                    // Reachability only. No registry or positive-presence write.
                    log::info!(
                        "Selected-adapter ICMP result: target={} source={} interface_index={} reachable={}",
                        target.ip,
                        path.source,
                        path.index,
                        reachable
                    );
                    let _ = bridge.emit(
                        "device-ping-result",
                        serde_json::json!({
                            "ip": target.ip,
                            "key": target.key,
                            "interface_index": path.index,
                            "source": path.source.to_string(),
                            "reachable": reachable,
                        }),
                    );
                });

                // Stagger inside the pass. The select! lets a cancel
                // arrive promptly even mid-stagger.
                tokio::select! {
                    _ = tokio::time::sleep(PING_STAGGER) => {}
                    _ = cancel_rx.changed() => return,
                }
            }
        }
    });

    PingDotHandle {
        cancel: cancel_tx,
        task,
    }
}

/// One-shot ICMP probe via `ping.exe`. Returns true on a real echo
/// reply.
///
/// Windows `ping` is sloppy about exit codes — it can exit 0 on
/// "Destination host unreachable" depending on routing, and exit
/// non-zero only when *every* probe times out. And `Reply from` alone
/// is not the signal either: an unreachable local-subnet device (ARP
/// failure) prints `Reply from <own-ip>: Destination host unreachable.`
/// — a "reply" from ourselves or a router saying the target is dead.
/// Only real echo replies carry a `TTL=` field, and localized Windows
/// keeps that token untranslated, so it's the discriminator.
pub(super) async fn probe(readiness: &super::readiness::CameraReadiness, ip: &str) -> bool {
    // The existing stall diagnostic has only an endpoint. Keep that API,
    // but decline unless selected-adapter context and an applied source
    // exist. Its result is diagnostic only, never a record/presence write.
    let Ok(target) = crate::validation::parse_camera_ip(ip) else {
        return false;
    };
    if !readiness
        .diagnostic_ready
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return false;
    }
    let Some((adapter, index, fence)) = readiness.probe_scope() else {
        return false;
    };
    let Some(source) = super::select_wired_source(target, &Default::default(), &adapter.ips) else {
        return false;
    };
    if super::route::egress_index(target).ok() != Some(index) {
        return false;
    }
    #[cfg(windows)]
    if !super::interface::source_matches_interface(index, source) {
        return false;
    }
    let reachable = probe_bound(ip, source, index).await;
    reachable && !fence.is_stale() && super::route::egress_index(target).ok() == Some(index)
}

async fn probe_bound(ip: &str, source: std::net::Ipv4Addr, index: u32) -> bool {
    #[cfg(windows)]
    {
        let Some(target) = ip.parse().ok() else {
            return false;
        };
        super::arp::bound_ping(
            target,
            source,
            index,
            std::time::Duration::from_millis(PING_TIMEOUT_MS as u64),
        )
        .await
        .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        let _ = index;
        let timeout = PING_TIMEOUT_MS.to_string();
        let source = source.to_string();
        let output = async_cmd("ping")
            .args(["-n", "1", "-w", &timeout, "-S", &source, ip])
            .output()
            .await;

        match output {
            Ok(o) => is_echo_reply(&String::from_utf8_lossy(&o.stdout)),
            Err(_) => false,
        }
    }
}

/// True only for output containing a genuine echo reply. See `probe`
/// for why `TTL=` and not `Reply from`.
#[cfg(any(not(windows), test))]
fn is_echo_reply(stdout: &str) -> bool {
    stdout.contains("TTL=")
}

/// Handle authority lives here; diagnostic_ready preserves the previous
/// process-lifetime APP initialization point without retaining an AppHandle.
pub(super) struct Pinger {
    handle: tokio::sync::Mutex<Option<PingDotHandle>>,
    pub(super) diagnostic_ready: Arc<std::sync::atomic::AtomicBool>,
}
impl Pinger {
    pub(super) fn new() -> Self {
        Self {
            handle: tokio::sync::Mutex::new(None),
            diagnostic_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
    pub(super) async fn start(
        &self,
        readiness: Arc<super::readiness::CameraReadiness>,
        registry: Arc<DeviceRegistry>,
        bridge: Arc<dyn crate::bridge::AppBridge>,
    ) {
        let prev = self.handle.lock().await.take();
        if let Some(prev) = prev {
            prev.stop().await;
        }
        let handle = start(readiness, bridge, registry);
        *self.handle.lock().await = Some(handle);
        log::info!("Started ICMP ping-dot loop");
    }
    pub(super) async fn stop(&self) {
        let handle = self.handle.lock().await.take();
        if let Some(handle) = handle {
            handle.stop().await;
            log::info!("Stopped ICMP ping-dot loop");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_echo_reply;

    #[tokio::test(start_paused = true)]
    async fn owner_stop_keeps_waiting_for_pinger_after_five_seconds() {
        let pinger = std::sync::Arc::new(super::Pinger::new());
        let (cancel, mut canceled) = tokio::sync::watch::channel(false);
        let (release, wait) = tokio::sync::oneshot::channel();
        let (seen, received) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            canceled.changed().await.unwrap();
            seen.send(()).unwrap();
            wait.await.unwrap();
        });
        *pinger.handle.lock().await = Some(super::PingDotHandle { cancel, task });
        let owner = pinger.clone();
        let stop = tokio::spawn(async move {
            owner.stop().await;
        });
        received.await.unwrap();
        tokio::time::advance(std::time::Duration::from_secs(6)).await;
        assert!(!stop.is_finished());
        release.send(()).unwrap();
        stop.await.unwrap();
        assert!(pinger.handle.lock().await.is_none());
    }

    #[test]
    fn real_echo_reply_is_reachable() {
        let out = "\r\nPinging 192.168.12.1 with 32 bytes of data:\r\n\
                   Reply from 192.168.12.1: bytes=32 time=1ms TTL=64\r\n\r\n\
                   Ping statistics for 192.168.12.1:\r\n\
                       Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),\r\n";
        assert!(is_echo_reply(out));
    }

    #[test]
    fn unreachable_reported_by_self_is_not_reachable() {
        // ARP failure on the local subnet: our own adapter "replies".
        // This is the exact output for an unplugged camera.
        let out = "\r\nPinging 192.168.12.77 with 32 bytes of data:\r\n\
                   Reply from 192.168.12.64: Destination host unreachable.\r\n\r\n\
                   Ping statistics for 192.168.12.77:\r\n\
                       Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),\r\n";
        assert!(!is_echo_reply(out));
    }

    #[test]
    fn unreachable_reported_by_router_is_not_reachable() {
        let out = "\r\nPinging 10.20.30.40 with 32 bytes of data:\r\n\
                   Reply from 192.168.12.1: Destination host unreachable.\r\n";
        assert!(!is_echo_reply(out));
    }

    #[test]
    fn timeout_is_not_reachable() {
        let out = "\r\nPinging 192.168.12.77 with 32 bytes of data:\r\n\
                   Request timed out.\r\n\r\n\
                   Ping statistics for 192.168.12.77:\r\n\
                       Packets: Sent = 1, Received = 0, Lost = 1 (100% loss),\r\n";
        assert!(!is_echo_reply(out));
    }
}
