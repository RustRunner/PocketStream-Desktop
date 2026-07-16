//! Periodic ICMP probe that drives the green/red reachability dot in
//! the Nodes panel.
//!
//! Pings every IP in the device registry on a 30 s cadence, with a
//! 100 ms stagger between probes so the pinger doesn't burst the
//! adapter (especially relevant on the ASIX AX88179 — see comment in
//! `mod.rs::ping_sweep_subnets`).
//!
//! On startup the first pass runs immediately, so the dots resolve
//! within ~1-2 s of the app reaching steady state rather than waiting
//! a full interval. Emits `device-ping-result` events the frontend
//! subscribes to for live dot updates.
//!
//! Runs in every mode (Static-Manual, Static-Auto, DHCP). The pinger
//! doesn't care which subsystem populated the registry — ARP, cache,
//! or manual-node hydration are all equally valid sources.

use std::sync::Arc;
use std::time::Duration;

use tauri::{AppHandle, Emitter};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::network::{async_cmd, DeviceRegistry};

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
pub fn start(app_handle: AppHandle, registry: Arc<DeviceRegistry>) -> PingDotHandle {
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
            let ips: Vec<String> = registry
                .snapshot()
                .into_iter()
                .map(|d| d.ip)
                .filter(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
                .collect();

            for ip in ips {
                if *cancel_rx.borrow() {
                    return;
                }
                let ah = app_handle.clone();
                let target = ip.clone();
                tokio::spawn(async move {
                    let reachable = probe(&target).await;
                    // A real echo reply is positive device evidence for
                    // the adoption lifecycle: a quiet-but-reachable
                    // camera may never ARP on its own, but these
                    // periodic probes keep proving it exists. Timeouts
                    // and unreachable verdicts stamp nothing.
                    if reachable {
                        if let Ok(parsed) = target.parse::<std::net::Ipv4Addr>() {
                            use tauri::Manager;
                            let manager: tauri::State<'_, crate::network::NetworkManager> =
                                ah.state();
                            manager.note_positive_liveness(&ah, parsed).await;
                        }
                    }
                    let _ = ah.emit(
                        "device-ping-result",
                        serde_json::json!({
                            "ip": target,
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
pub(crate) async fn probe(ip: &str) -> bool {
    let timeout = PING_TIMEOUT_MS.to_string();
    let output = async_cmd("ping")
        .args(["-n", "1", "-w", &timeout, ip])
        .output()
        .await;

    match output {
        Ok(o) => is_echo_reply(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => false,
    }
}

/// True only for output containing a genuine echo reply. See `probe`
/// for why `TTL=` and not `Reply from`.
fn is_echo_reply(stdout: &str) -> bool {
    stdout.contains("TTL=")
}

#[cfg(test)]
mod tests {
    use super::is_echo_reply;

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
