//! Network interface, IP config, scan, and ARP discovery IPC handlers.

use tauri::State;

use crate::config::{AppConfig, ManualNode, NetworkMode};
use crate::error::AppError;
use crate::network::{DeviceRecord, DeviceStatus, InterfaceInfo, NetworkManager, ScanResult};
use crate::validation::parse_cidr;

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
    let (_, prefix) = parse_cidr(&subnet)?;
    crate::network::scanner::check_scan_size(prefix)?;
    manager.scan_subnet(&subnet, &config).await
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
    app: tauri::AppHandle,
) -> Result<crate::network::AdapterSelection, AppError> {
    crate::network::watcher::refresh(&app).await?;
    Ok(manager.adapter_selection_state().await)
}

#[tauri::command]
pub async fn select_adapter(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    app: tauri::AppHandle,
    mac: String,
) -> Result<crate::network::AdapterSelection, AppError> {
    let selection = manager.select_adapter(&config, &app, &mac).await?;
    crate::network::watcher::emit_selection(&app, &selection);
    Ok(selection)
}

#[tauri::command]
pub async fn list_interfaces(
    manager: State<'_, NetworkManager>,
) -> Result<Vec<InterfaceInfo>, AppError> {
    manager.list_interfaces().await
}

#[tauri::command]
pub async fn list_vpn_interfaces() -> Result<Vec<InterfaceInfo>, AppError> {
    crate::network::interface::list_vpn().await
}

#[tauri::command]
pub async fn get_interface_info(
    manager: State<'_, NetworkManager>,
    name: String,
) -> Result<InterfaceInfo, AppError> {
    manager.get_interface(&name).await
}

#[tauri::command]
pub async fn set_static_ip(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    name: String,
    ip: String,
    subnet_mask: String,
    gateway: Option<String>,
) -> Result<(), AppError> {
    // Adopted rescue IPs must survive the primary set — pass them so the
    // secondary re-add classifies by membership, not by enumeration order.
    let preserve: Vec<std::net::Ipv4Addr> = manager
        .get_adopted_ips()
        .await
        .into_values()
        .filter_map(|ip| ip.parse().ok())
        .collect();
    crate::network::ip_config::assign_static_ip(
        &name,
        &ip,
        &subnet_mask,
        gateway.as_deref(),
        &preserve,
    )
    .await?;
    // Manual ownership trumps auto-adopt: drop any registry entry for
    // this IP so the "(auto)" badge stops shadowing a user-set IP, and
    // persist the prune so the state survives a restart.
    if manager.untrack_adopted_ip(&ip).await {
        manager.save_adopted_to_config(&config).await;
    }
    Ok(())
}

#[tauri::command]
pub async fn add_secondary_ip(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    name: String,
    ip: String,
    subnet_mask: String,
) -> Result<(), AppError> {
    crate::network::ip_config::add_secondary_ip(&name, &ip, &subnet_mask).await?;
    if manager.untrack_adopted_ip(&ip).await {
        manager.save_adopted_to_config(&config).await;
    }
    Ok(())
}

#[tauri::command]
pub async fn remove_secondary_ip(name: String, ip: String) -> Result<(), AppError> {
    crate::network::ip_config::remove_secondary_ip(&name, &ip).await
}

#[tauri::command]
pub async fn set_dhcp(name: String) -> Result<(), AppError> {
    crate::network::ip_config::set_dhcp(&name).await
}

#[tauri::command]
pub async fn get_dhcp_state(name: String) -> Result<bool, AppError> {
    crate::network::ip_config::get_dhcp_state(&name).await
}

// ── Network Mode ────────────────────────────────────────────────────
// The user's chosen mode drives which discovery subsystems run. Slice 1
// just persists the value; the subsystem gating lands in slice 2.

#[tauri::command]
pub fn get_network_mode(config: State<'_, AppConfig>) -> NetworkMode {
    config.get_network_mode()
}

#[tauri::command]
pub async fn set_network_mode(
    config: State<'_, AppConfig>,
    manager: State<'_, NetworkManager>,
    app: tauri::AppHandle,
    mode: NetworkMode,
) -> Result<(), AppError> {
    let old_mode = config.get_network_mode();
    if old_mode == mode {
        return Ok(());
    }
    config.set_network_mode(mode)?;
    manager
        .apply_mode_change(app, &config, old_mode, mode)
        .await
}

// ── Manual Nodes ────────────────────────────────────────────────────
// Pinned devices for `NetworkMode::StaticManual`. The list persists
// across mode toggles so users can flip between Auto and Manual without
// losing their pins.

#[tauri::command]
pub fn get_manual_nodes(config: State<'_, AppConfig>) -> Vec<ManualNode> {
    config.get_manual_nodes()
}

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

/// Diagnostic only: this legacy neighbor lookup never authorizes promotion.
/// Look up the MAC at `ip`, bound to the wired path. Used by the
/// cache-verify path to confirm a cached record at an IP is still the
/// same physical device, not just *something else* with the same
/// address today. The probe and neighbor lookup are scoped to the
/// wired source the backend resolves for the target's subnet, so a
/// WiFi responder on a shared subnet can never verify a wired record.
/// Returns null if no wired source exists, the IP doesn't respond over
/// the wired path, or no ARP entry forms there.
#[tauri::command]
pub async fn resolve_mac(
    manager: State<'_, NetworkManager>,
    ip: String,
) -> Result<Option<String>, AppError> {
    let parsed = crate::validation::parse_camera_ip(&ip)?;
    let source = manager.wired_source_for(parsed).await;
    crate::network::arp::resolve_mac_for_ip(parsed, source, std::time::Duration::from_secs(1)).await
}

#[tauri::command]
pub async fn refresh_adapter(name: String, mode: String) -> Result<(), AppError> {
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
    crate::network::adapter_refresh::refresh_adapter(&name, mode).await
}

// ── ARP Discovery ───────────────────────────────────────────────────

#[tauri::command]
pub async fn start_arp_discovery(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    app: tauri::AppHandle,
    interface: String,
) -> Result<(), AppError> {
    if !crate::is_discovery_available() {
        return Err(AppError::DiscoveryUnavailable(
            "Packet capture is not available on this Windows build".into(),
        ));
    }
    manager.start_arp_discovery(&interface, &config, app).await
}

#[tauri::command]
pub async fn stop_arp_discovery(manager: State<'_, NetworkManager>) -> Result<(), AppError> {
    manager.stop_arp_discovery().await;
    Ok(())
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

/// Attach capability data to the requested identity, without promoting it.
#[tauri::command]
pub async fn report_scan_result(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    key: String,
    open_ports: Vec<u16>,
) -> Result<(), AppError> {
    // Results are now committed at scan completion with their original
    // adapter epoch, source and identity. A later frontend echo has lost
    // that provenance and cannot write capabilities into any record.
    let _ = (manager, config, key, open_ports);
    Ok(())
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

/// Update the reachability status of a device by MAC. Used by the
/// cache-verification path on the frontend to flip Verifying/Offline
/// without changing scan results. Status is not persisted to the
/// cache file — it's session-local.
#[tauri::command]
pub async fn set_device_status(
    manager: State<'_, NetworkManager>,
    mac: String,
    status: DeviceStatus,
) -> Result<(), AppError> {
    if !manager.registry().set_status(&mac, status) {
        return Ok(());
    }
    if let Some(emitter) = manager.emitter().await {
        emitter.poke();
    }
    Ok(())
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
) -> Result<(), AppError> {
    // The manager owns persistence for both routes: a snapshot-save for a
    // live adoption, a surgical single-entry purge for a config-only one
    // (a snapshot here would rebuild from empty live state and wipe every
    // other adoption).
    let ip = manager
        .remove_adopted_subnet(&config, &subnet, iface_hint.as_deref())
        .await?;
    // Same event the lifecycle reaper emits, so every UI surface follows
    // backend state through one listener whichever path removed the row.
    use tauri::Emitter;
    let _ = app.emit(
        "subnet-removed",
        serde_json::json!({
            "subnet": subnet,
            "adopted_ip": ip.to_string(),
            "reason": "manual",
        }),
    );
    Ok(())
}

/// Persisted adoption entries (subnet -> IP) straight from config, for
/// the Configure dialog's removal routing only. A config-only adoption
/// (nothing restored this session) must still route through the
/// adoption-aware removal — but an entry here is not necessarily bound,
/// so this must never feed the frontend's live routing map.
#[tauri::command]
pub async fn get_configured_adoptions(
    config: State<'_, AppConfig>,
) -> Result<std::collections::HashMap<String, String>, AppError> {
    Ok(config.get().adopted_subnets)
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
