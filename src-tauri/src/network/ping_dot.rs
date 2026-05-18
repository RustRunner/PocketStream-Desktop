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
            // get picked up on the next iteration — within 30 s.
            let ips: Vec<String> = registry
                .snapshot()
                .into_iter()
                .map(|d| d.ip)
                .collect();

            for ip in ips {
                if *cancel_rx.borrow() {
                    return;
                }
                let ah = app_handle.clone();
                let target = ip.clone();
                tokio::spawn(async move {
                    let reachable = probe(&target).await;
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
/// non-zero only when *every* probe times out. Checking the stdout
/// for the `Reply from` marker is the only reliable signal that a
/// real response came back. Same approach the existing
/// `ping_sweep_subnets` relies on implicitly via its successful-output
/// check.
pub(crate) async fn probe(ip: &str) -> bool {
    let timeout = PING_TIMEOUT_MS.to_string();
    let output = async_cmd("ping")
        .args(["-n", "1", "-w", &timeout, ip])
        .output()
        .await;

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains("Reply from")
        }
        Err(_) => false,
    }
}
