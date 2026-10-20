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
//! Where native notifications are unavailable, `lib.rs::watch_interface`
//! polls this same selection refresh path.

use super::{AdapterSelection, InterfaceInfo, NetworkManager};
use tauri::{AppHandle, Emitter, Manager};

pub(crate) fn selected_status(selection: &AdapterSelection) -> InterfaceInfo {
    selection
        .adapter
        .clone()
        .filter(|_| selection.interface_index.is_some())
        .unwrap_or_else(|| InterfaceInfo {
            name: String::new(),
            display_name: "Selected Ethernet adapter unavailable".into(),
            description: String::new(),
            mac: selection.selected_mac.clone().unwrap_or_default(),
            ips: vec![],
            is_up: false,
            is_ethernet: true,
            is_wifi: false,
            is_vpn: false,
            is_virtual: false,
        })
}

pub(crate) fn emit_selection(handle: &AppHandle, selection: &AdapterSelection) {
    let _ = handle.emit("adapter-selection-changed", selection);
    let _ = handle.emit("interface-status-changed", selected_status(selection));
}

/// Shared by native notifications, the fallback poller and the UI query.
pub(crate) async fn refresh(handle: &AppHandle) -> Result<(), crate::AppError> {
    let manager = handle.state::<NetworkManager>();
    let config = handle.state::<crate::config::AppConfig>();
    let previous = manager.adapter_selection_state().await;
    let mut selection = manager.get_adapter_selection(&config).await?;
    manager.update_presence_adapter(&selection, config.get_network_mode());
    if (previous.selected_mac != selection.selected_mac
        || previous.interface_index != selection.interface_index)
        && selection.adapter.is_some()
        && selection.interface_index.is_some()
    {
        manager.start_selected_adapter(&config, handle).await;
        selection = manager.get_adapter_selection(&config).await?;
    }
    if serde_json::to_value(previous).ok() != serde_json::to_value(&selection).ok() {
        emit_selection(handle, &selection);
    }
    Ok(())
}

/// Interface enumeration goes through the manager, which strips pending
/// scratch addresses before selection or emission.
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

    use tauri::AppHandle;
    use tokio::sync::mpsc;

    use windows_sys::Win32::Foundation::{BOOLEAN, HANDLE, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, NotifyIpInterfaceChange, NotifyUnicastIpAddressChange,
        MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
    };

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

            if let Err(e) = super::refresh(&handle).await {
                log::debug!("Watcher selection refresh failed: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watcher_reports_selected_usb_or_unavailable_never_the_dock() {
        let iface = |name: &str, mac: &str| InterfaceInfo {
            name: name.into(),
            display_name: name.into(),
            description: String::new(),
            ips: vec![],
            mac: mac.into(),
            is_up: true,
            is_ethernet: true,
            is_wifi: false,
            is_vpn: false,
            is_virtual: false,
        };
        let dock = iface("Dock", "40:cd:3a:00:00:01");
        let usb = iface("USB", "40:cd:3a:00:00:02");
        for list in [
            vec![dock.clone(), usb.clone()],
            vec![usb.clone(), dock.clone()],
            vec![dock],
        ] {
            let adapter = crate::network::pick_adapter(&list, Some(&usb.mac)).cloned();
            let selection = AdapterSelection {
                selected_mac: Some(usb.mac.clone()),
                interface_index: adapter.as_ref().map(|_| 23),
                adapter,
                ..Default::default()
            };
            let event = selected_status(&selection);
            assert_eq!(event.mac, usb.mac);
            if selection.adapter.is_some() {
                assert_eq!(event.name, "USB");
            } else {
                assert!(event.name.is_empty());
                assert!(!event.is_up);
            }
        }
    }
}
