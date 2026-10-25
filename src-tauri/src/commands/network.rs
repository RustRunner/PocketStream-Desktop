//! Network interface, IP config, scan, and ARP discovery IPC handlers.

use tauri::State;

use crate::config::{AppConfig, ManualNode, NetworkMode};
use crate::error::AppError;
use crate::network::{DeviceRecord, NetworkManager, ScanResult};
use crate::validation::parse_cidr;

#[tauri::command]
pub fn get_host_ip_owners() -> Result<Vec<crate::network::ip_conflict::HostIpOwner>, AppError> {
    crate::network::ip_conflict::local_ip_owners()
}

#[tauri::command]
pub async fn scan_network(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    subnet: String,
) -> Result<Vec<ScanResult>, AppError> {
    // Reject malformed CIDR at the boundary so the active-scans
    // dedupe set doesn't cache a garbage key, and the user sees a
    // clean error instead of whatever scanner::scan() would emit
    // mid-iteration. Also reject subnets too wide to scan before any
    // scanning machinery spins up.
    let (ip, prefix) = parse_cidr(&subnet)?;
    crate::network::scanner::check_scan_size(prefix)?;
    let network =
        ipnetwork::Ipv4Network::new(ip, prefix).map_err(|e| AppError::Network(e.to_string()))?;
    // Equivalent CIDRs share the manager's dedupe key, fence and TCP budget.
    manager
        .scan_subnet(&format!("{}/{}", network.network(), prefix), &config)
        .await
}

#[tauri::command]
pub async fn get_capture_state(
    manager: State<'_, NetworkManager>,
) -> Result<crate::network::CaptureState, AppError> {
    Ok(manager.get_capture_state().await)
}

#[tauri::command]
pub async fn get_adapter_selection(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
) -> Result<crate::network::AdapterSelection, AppError> {
    // Display reads must not queue behind discovery/capture or address writes.
    // Startup and the existing NIC watcher own selection and reconciliation.
    manager.adapter_selection_view(&config).await
}

#[tauri::command]
pub async fn select_adapter(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    app: tauri::AppHandle,
    mac: String,
) -> Result<crate::network::AdapterSelection, AppError> {
    #[cfg(windows)]
    {
        let _ = (&manager, &config);
        crate::network::native_operations::select_request(app, mac).await
    }
    #[cfg(not(windows))]
    {
        let selection = manager.select_adapter(&config, &app, &mac).await?;
        crate::network::watcher::emit_selection(&app, &selection);
        Ok(selection)
    }
}

#[tauri::command]
pub async fn list_bind_interfaces(
    config: State<'_, AppConfig>,
) -> Result<Vec<crate::network::bindings::BindInterface>, AppError> {
    let adopted = config.get().adopted_subnets.into_values().collect();
    crate::network::bindings::list(&adopted).await
}

#[tauri::command]
pub async fn add_secondary_ip(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    app: tauri::AppHandle,
    name: String,
    ip: String,
    subnet_mask: String,
) -> Result<crate::network::manual_address::AddressReply, AppError> {
    let request = crate::network::manual_address::AddressRequest::Add {
        name,
        ip,
        mask: subnet_mask,
    };
    #[cfg(windows)]
    {
        let _ = (&manager, &config);
        crate::network::native_operations::address_request(app, request).await
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        Ok(manager.address_operation(&config, request).await)
    }
}

#[tauri::command]
pub async fn remove_secondary_ip(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    app: tauri::AppHandle,
    name: String,
    ip: String,
    primary: Option<bool>,
) -> Result<crate::network::manual_address::AddressReply, AppError> {
    let request = if primary.unwrap_or(false) {
        crate::network::manual_address::AddressRequest::RemovePrimary { name, ip }
    } else {
        crate::network::manual_address::AddressRequest::RemoveManual { name, ip }
    };
    #[cfg(windows)]
    {
        let _ = (&manager, &config);
        crate::network::native_operations::address_request(app, request).await
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        Ok(manager.address_operation(&config, request).await)
    }
}

#[tauri::command]
pub async fn get_dhcp_state(name: String) -> Result<bool, AppError> {
    crate::network::ip_config::get_dhcp_state(&name).await
}

// ── Network Mode ────────────────────────────────────────────────────
// One fenced OS/config transition is shared by every mode change.

#[tauri::command]
pub fn get_network_mode(config: State<'_, AppConfig>) -> NetworkMode {
    config.get_network_mode()
}

#[tauri::command]
pub async fn set_network_mode(
    config: State<'_, AppConfig>,
    manager: State<'_, NetworkManager>,
    app: tauri::AppHandle,
    request: crate::network::ModeTransition,
) -> Result<crate::network::ModeTransitionReply, AppError> {
    #[cfg(windows)]
    {
        let _ = (&manager, &config);
        crate::network::native_operations::mode_request(app, request).await
    }
    #[cfg(not(windows))]
    {
        manager.transition_mode(app, &config, request).await
    }
}

// ── Manual Nodes ────────────────────────────────────────────────────
// Pinned devices for `NetworkMode::StaticManual`. The list persists
// across mode toggles so users can flip between Auto and Manual without
// losing their pins.

#[tauri::command]
pub async fn add_manual_node(
    config: State<'_, AppConfig>,
    manager: State<'_, NetworkManager>,
    ip: String,
    alias: String,
    expected_mac: Option<String>,
) -> Result<(), AppError> {
    let mut node = validated_manual_node(ip, alias)?;
    node.expected_mac = expected_mac
        .map(|mac| {
            crate::network::device_registry::canonical_mac(&mac)
                .ok_or_else(|| AppError::Network("Invalid expected device MAC".into()))
        })
        .transpose()?;
    config.add_manual_node(node)?;
    // Reflect the new pin in the live registry so the Nodes panel
    // updates without a full mode-switch. hydrate_manual_nodes patches
    // an existing record at the same IP rather than spawning a dupe.
    manager.hydrate_manual_nodes(&config).await;
    Ok(())
}

fn validated_manual_node(ip: String, alias: String) -> Result<ManualNode, AppError> {
    // Validate IP shape at the boundary so a malformed string can't end
    // up persisted and re-served to the frontend.
    crate::validation::parse_camera_ip(&ip)?;
    // CAM/PTU are single-holder role designations with their own
    // assignment path; accepting them here would bypass the
    // single-holder enforcement.
    if crate::network::device_registry::is_role_alias(&alias) {
        return Err(AppError::Network(
            "CAM and PTU are assigned from the Nodes panel".into(),
        ));
    }
    Ok(ManualNode {
        ip,
        alias,
        expected_mac: None,
    })
}

#[tauri::command]
pub async fn remove_manual_node(
    config: State<'_, AppConfig>,
    manager: State<'_, NetworkManager>,
    ip: String,
    expected_mac: Option<String>,
) -> Result<(), AppError> {
    if !config.remove_manual_node(&ip, expected_mac.as_deref())? {
        return Ok(());
    }
    let registry = manager.registry();
    let key = expected_mac
        .as_ref()
        .and_then(|mac| {
            registry
                .snapshot()
                .into_iter()
                .find(|r| r.mac.eq_ignore_ascii_case(mac))
                .map(|r| r.mac)
        })
        .unwrap_or_else(|| format!("manual:{}", ip));
    config.remove_cached_device(&key)?;
    if registry.remove_by_mac(&key) {
        if let Some(emitter) = manager.emitter().await {
            emitter.poke();
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn clear_manual_nodes(
    config: State<'_, AppConfig>,
    manager: State<'_, NetworkManager>,
) -> Result<(), AppError> {
    config.clear_manual_nodes()?;
    if manager.registry().remove_manual_entries() {
        if let Some(emitter) = manager.emitter().await {
            emitter.poke();
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn refresh_adapter(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    app: tauri::AppHandle,
    name: String,
    mode: String,
) -> Result<(), AppError> {
    let mode = match mode.as_str() {
        "soft" => crate::network::adapter_refresh::RefreshMode::Soft,
        "hard" => crate::network::adapter_refresh::RefreshMode::Hard,
        other => {
            return Err(AppError::Network(format!(
                "Invalid refresh mode '{}' (expected 'soft' or 'hard')",
                other
            )))
        }
    };
    #[cfg(windows)]
    {
        let _ = (&manager, &config);
        crate::network::native_operations::refresh_request(app, name, mode).await
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        manager.refresh_native_adapter(&config, &name, mode).await
    }
}

// ── ARP Discovery ───────────────────────────────────────────────────

#[tauri::command]
pub async fn start_arp_discovery(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    app: tauri::AppHandle,
    interface: String,
    refresh: Option<bool>,
) -> Result<(), AppError> {
    if !crate::is_discovery_available() {
        return Err(AppError::DiscoveryUnavailable(
            "Packet capture is not available on this Windows build".into(),
        ));
    }
    if refresh.unwrap_or(false) {
        manager
            .refresh_arp_discovery(&interface, &config, app)
            .await
    } else {
        manager.start_arp_discovery(&interface, &config, app).await
    }
}

/// Snapshot of every device the backend currently knows about — the
/// canonical replacement for the frontend's old patchwork of arpDevices
/// + tcpScanResults + nodeAliases + cache file. Frontend calls this once
/// on startup, then subscribes to `device-list-changed` events for live
/// updates.
#[tauri::command]
pub async fn get_device_list(
    manager: State<'_, NetworkManager>,
) -> Result<Vec<DeviceRecord>, AppError> {
    Ok(manager.registry().snapshot())
}

/// Set or clear the user-assigned alias for this record key.
/// Empty string clears. Assigning CAM or PTU demotes any previous
/// holder (single-holder invariant), so more than one record can
/// change. Every changed record is written through to the cache and
/// manual-nodes stores (best-effort — the registry is authoritative,
/// so the event still emits when a disk write fails and the UI
/// converges on registry state). The authoritative post-write snapshot
/// is also returned directly: a stale/no-op frontend action produces no
/// change event, but still needs a response that reconciles and unlocks
/// its role dropdown.
#[tauri::command]
pub async fn set_device_alias(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    key: String,
    alias: String,
) -> Result<Vec<DeviceRecord>, AppError> {
    let registry = manager.registry();
    let changed = registry.set_alias(&key, &alias);
    if !changed.is_empty() {
        crate::network::persist_alias_writethrough(&registry, &config, &changed);
        if let Some(emitter) = manager.emitter().await {
            emitter.poke();
        }
    }
    Ok(registry.snapshot())
}

/// Drop a device from the registry and the on-disk cache. Used by the
/// "forget this device" affordance in the offline-cache dialog.
#[tauri::command]
pub async fn forget_device(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    mac: String,
) -> Result<(), AppError> {
    // A verified manual pin shares the discovered identity; explicit forget
    // removes that matching pin too, so a later hydration cannot resurrect it.
    for node in config.get_manual_nodes().iter().filter(|n| {
        n.expected_mac
            .as_ref()
            .is_some_and(|m| m.eq_ignore_ascii_case(&mac))
    }) {
        config.remove_manual_node(&node.ip, node.expected_mac.as_deref())?;
    }
    if !manager.registry().forget(&mac) {
        return Ok(());
    }
    config.remove_cached_device(&mac)?;
    if let Some(emitter) = manager.emitter().await {
        emitter.poke();
    }
    Ok(())
}

/// Atomic adoption snapshot: the routing map plus per-subnet lifecycle
/// metadata, with staleness derived backend-side so the UI badge and
/// the removal policy share one implementation.
#[tauri::command]
pub async fn get_adoption_state(
    manager: State<'_, NetworkManager>,
) -> Result<crate::network::AdoptionSnapshot, AppError> {
    Ok(manager.adoption_snapshot().await)
}

#[tauri::command]
pub async fn remove_adopted_subnet(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    app: tauri::AppHandle,
    subnet: String,
    iface_hint: Option<String>,
) -> Result<crate::network::manual_address::AddressReply, AppError> {
    #[cfg(windows)]
    {
        let _ = (&manager, &config);
        crate::network::native_operations::address_request(
            app,
            crate::network::manual_address::AddressRequest::RemoveSaved {
                subnet,
                hint: iface_hint,
            },
        )
        .await
    }
    #[cfg(not(windows))]
    {
        let reply = manager
            .address_operation(
                &config,
                crate::network::manual_address::AddressRequest::RemoveSaved {
                    subnet: subnet.clone(),
                    hint: iface_hint,
                },
            )
            .await;
        if reply.outcome == crate::network::manual_address::AddressOutcome::Success {
            use tauri::Emitter;
            let _ = app.emit("subnet-removed", serde_json::json!({"subnet": subnet, "adopted_ip": reply.view.address, "reason": "manual"}));
        }
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_apipa_is_rejected_before_persistence_or_hydration() {
        let error = validated_manual_node("169.254.20.7".into(), "bench PTU".into())
            .unwrap_err()
            .to_string();
        assert!(error.contains("give the camera a routable IPv4 address first"));
        let node = validated_manual_node("192.168.1.204".into(), "bench PTU".into()).unwrap();
        assert_eq!(node.ip, "192.168.1.204");
        assert!(validated_manual_node("192.168.1.204".into(), "CAM".into()).is_err());
    }
}
