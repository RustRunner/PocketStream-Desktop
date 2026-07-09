//! Event-driven NIC state watcher.
//!
//! On Windows, subscribes to `NotifyIpInterfaceChange` and
//! `NotifyUnicastIpAddressChange` so link-state and IP changes are delivered
//! as callbacks instead of discovered by polling. Callbacks push a wake
//! signal through an mpsc channel to a tokio task, which debounces (~300 ms)
//! and re-enumerates interfaces before emitting `interface-status-changed`.
//!
//! The callback runs on a system thread owned by IP Helper. It is deliberately
//! tiny (just a non-blocking send) to avoid holding that thread.
//!
//! On non-Windows platforms this module is a no-op — the legacy pnet-based
//! watcher in `lib.rs::watch_interface` continues to handle those.

use tauri::AppHandle;

#[cfg(target_os = "windows")]
pub fn start(handle: AppHandle) -> bool {
    imp::start(handle)
}

#[cfg(not(target_os = "windows"))]
pub fn start(_handle: AppHandle) -> bool {
    false
}

#[cfg(target_os = "windows")]
mod imp {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::OnceLock;
    use std::time::Duration;

    use tauri::{AppHandle, Emitter};
    use tokio::sync::mpsc;

    use windows_sys::Win32::Foundation::{BOOLEAN, HANDLE, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, NotifyIpInterfaceChange, NotifyUnicastIpAddressChange,
        MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
    };

    use crate::network::interface;

    // AF_UNSPEC covers both IPv4 and IPv6 in a single registration.
    const AF_UNSPEC: u16 = 0;

    // Replaceable slot (not a OnceLock): a failed init attempt sets it,
    // then a retry must be able to overwrite it — a OnceLock would strand
    // the first attempt's sender, whose receiver was already dropped, and
    // every callback wake would then go nowhere.
    static SENDER: std::sync::RwLock<Option<mpsc::UnboundedSender<()>>> =
        std::sync::RwLock::new(None);
    static INITIALIZED: AtomicBool = AtomicBool::new(false);

    fn wake() {
        if let Ok(guard) = SENDER.read() {
            if let Some(tx) = guard.as_ref() {
                let _ = tx.send(());
            }
        }
    }

    // Keep the notification handles alive for the life of the process.
    // Dropping them would implicitly cancel the subscription, which we
    // never want before shutdown.
    struct WatcherHandles {
        _iface: HANDLE,
        _addr: HANDLE,
    }
    unsafe impl Send for WatcherHandles {}
    unsafe impl Sync for WatcherHandles {}
    static HANDLES: OnceLock<WatcherHandles> = OnceLock::new();

    unsafe extern "system" fn interface_cb(
        _ctx: *const c_void,
        _row: *const MIB_IPINTERFACE_ROW,
        _ty: MIB_NOTIFICATION_TYPE,
    ) {
        wake();
    }

    unsafe extern "system" fn address_cb(
        _ctx: *const c_void,
        _row: *const MIB_UNICASTIPADDRESS_ROW,
        _ty: MIB_NOTIFICATION_TYPE,
    ) {
        wake();
    }

    pub fn start(handle: AppHandle) -> bool {
        // Claim the init slot. INITIALIZED stays true ONLY on success —
        // a failed attempt below resets it so a later call can retry.
        // (The old code latched it before registration, so one failure
        // permanently disabled the watcher.)
        if INITIALIZED
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return true;
        }

        let (tx, rx) = mpsc::unbounded_channel();
        // Overwrite any sender a prior failed attempt left behind.
        if let Ok(mut guard) = SENDER.write() {
            *guard = Some(tx);
        }

        let mut iface_handle: HANDLE = std::ptr::null_mut();
        let mut addr_handle: HANDLE = std::ptr::null_mut();

        let ok = unsafe {
            let r1 = NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(interface_cb),
                std::ptr::null(),
                0 as BOOLEAN,
                &mut iface_handle,
            );
            if r1 != NO_ERROR {
                log::warn!("NotifyIpInterfaceChange failed with code {}", r1);
                INITIALIZED.store(false, Ordering::SeqCst);
                return false;
            }

            let r2 = NotifyUnicastIpAddressChange(
                AF_UNSPEC,
                Some(address_cb),
                std::ptr::null(),
                0 as BOOLEAN,
                &mut addr_handle,
            );
            if r2 != NO_ERROR {
                log::warn!("NotifyUnicastIpAddressChange failed with code {}", r2);
                // Free the first registration instead of leaking it, so a
                // retry starts clean.
                CancelMibChangeNotify2(iface_handle);
                INITIALIZED.store(false, Ordering::SeqCst);
                return false;
            }
            true
        };

        if !ok {
            INITIALIZED.store(false, Ordering::SeqCst);
            return false;
        }

        let _ = HANDLES.set(WatcherHandles {
            _iface: iface_handle,
            _addr: addr_handle,
        });

        log::info!("Event-driven NIC watcher active (NotifyIpInterfaceChange + NotifyUnicastIpAddressChange)");
        // MUST use tauri::async_runtime::spawn, not tokio::spawn.
        // This function is called synchronously from Tauri's setup closure,
        // which runs outside any tokio runtime context — a bare tokio::spawn
        // panics with "there is no reactor running", killing the process
        // silently on a Windows GUI app (no stderr to see the panic).
        tauri::async_runtime::spawn(debounce_loop(rx, handle));
        true
    }

    async fn debounce_loop(mut rx: mpsc::UnboundedReceiver<()>, handle: AppHandle) {
        loop {
            if rx.recv().await.is_none() {
                return;
            }

            // Coalesce bursts — a link transition often fires several
            // IP/interface notifications in quick succession.
            tokio::time::sleep(Duration::from_millis(300)).await;
            while rx.try_recv().is_ok() {}

            let list = match interface::list_physical().await {
                Ok(l) => l,
                Err(e) => {
                    log::debug!("Watcher enumeration failed: {}", e);
                    continue;
                }
            };

            // Prefer an ethernet adapter that has at least one IPv4 address.
            // Fall back to the first ethernet adapter so "disconnected but
            // still known" surfaces in the UI as per the relaxed-filter plan.
            // Exclude VPN and virtual adapters from both arms so a
            // VPN-as-Ethernet or virtual switch never drives the camera-port
            // banner; the relaxed up-state (no is_up check) is kept on
            // purpose so a disconnected wired port still shows the banner.
            let pick = list
                .iter()
                .find(|i| i.is_ethernet && !i.is_vpn && !i.is_virtual && !i.ips.is_empty())
                .or_else(|| {
                    list.iter()
                        .find(|i| i.is_ethernet && !i.is_vpn && !i.is_virtual)
                })
                .cloned();

            if let Some(iface) = pick {
                log::debug!(
                    "Watcher emitting interface-status-changed: '{}' ips={}",
                    iface.display_name,
                    iface.ips.len()
                );
                let _ = handle.emit("interface-status-changed", &iface);
            } else {
                // No ethernet adapter present — emit an empty sentinel so
                // the UI can show the "no adapter" banner.
                let sentinel = interface::InterfaceInfo {
                    name: String::new(),
                    display_name: String::new(),
                    ips: vec![],
                    mac: String::new(),
                    is_up: false,
                    is_ethernet: true,
                    is_wifi: false,
                    is_vpn: false,
                    is_virtual: false,
                };
                let _ = handle.emit("interface-status-changed", &sentinel);
            }
        }
    }
}
