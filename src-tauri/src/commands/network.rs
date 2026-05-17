//! Network interface, IP config, scan, and ARP discovery IPC handlers.

use tauri::State;

use crate::config::{AppConfig, CachedDevice, ManualNode, NetworkMode};
use crate::error::AppError;
use crate::network::{DeviceRecord, DeviceStatus, InterfaceInfo, NetworkManager, ScanResult};
use crate::validation::parse_cidr;

#[tauri::command]
pub async fn scan_network(
    manager: State<'_, NetworkManager>,
    subnet: String,
) -> Result<Vec<ScanResult>, AppError> {
    // Reject malformed CIDR at the boundary so the active-scans
    // dedupe set doesn't cache a garbage key, and the user sees a
    // clean error instead of whatever scanner::scan() would emit
    // mid-iteration.
    parse_cidr(&subnet)?;
    manager.scan_subnet(&subnet).await
}

#[tauri::command]
pub async fn list_interfaces(
    manager: State<'_, NetworkManager>,
) -> Result<Vec<InterfaceInfo>, AppError> {
    manager.list_interfaces()
}

#[tauri::command]
pub async fn list_vpn_interfaces() -> Result<Vec<InterfaceInfo>, AppError> {
    crate::network::interface::list_vpn()
}

#[tauri::command]
pub async fn get_interface_info(
    manager: State<'_, NetworkManager>,
    name: String,
) -> Result<InterfaceInfo, AppError> {
    manager.get_interface(&name)
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
    crate::network::ip_config::assign_static_ip(&name, &ip, &subnet_mask, gateway.as_deref())
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
    manager.apply_mode_change(app, &config, old_mode, mode).await
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
) -> Result<(), AppError> {
    // Validate IP shape at the boundary so a malformed string can't end
    // up persisted and re-served to the frontend.
    ip.parse::<std::net::Ipv4Addr>()
        .map_err(|_| AppError::Network(format!("Invalid IP: {}", ip)))?;
    config.add_manual_node(ManualNode { ip, alias })?;
    // Reflect the new pin in the live registry so the Nodes panel
    // updates without a full mode-switch. hydrate_manual_nodes patches
    // an existing record at the same IP rather than spawning a dupe.
    manager.hydrate_manual_nodes(&config).await;
    Ok(())
}

#[tauri::command]
pub async fn remove_manual_node(
    config: State<'_, AppConfig>,
    manager: State<'_, NetworkManager>,
    ip: String,
) -> Result<(), AppError> {
    config.remove_manual_node(&ip)?;
    // Drop the synthetic registry entry too. Real-MAC entries that the
    // pin may have aliased stay in the registry — the user's "remove
    // this row" intent only un-pins, not forget.
    let synthetic_key = format!("manual:{}", ip);
    if manager.registry().remove_by_mac(&synthetic_key) {
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

/// Look up the MAC at `ip` from the live ARP cache. Used by the
/// cache-verify path to confirm a cached record at an IP is still the
/// same physical device, not just *something else* with the same
/// address today. Returns null if the IP doesn't respond.
#[tauri::command]
pub async fn resolve_mac(ip: String) -> Result<Option<String>, AppError> {
    let parsed: std::net::Ipv4Addr = ip
        .parse()
        .map_err(|_| AppError::Network(format!("Invalid IP: {}", ip)))?;
    crate::network::arp::resolve_mac_for_ip(parsed, std::time::Duration::from_secs(1)).await
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
    app: tauri::AppHandle,
    interface: String,
) -> Result<(), AppError> {
    if !crate::is_npcap_available() {
        return Err(AppError::NpcapMissing);
    }
    manager.start_arp_discovery(&interface, app).await
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

/// Apply the result of a successful port scan to the canonical registry.
/// Updates the matching record's `open_ports` and flips its status to
/// `Live`, then persists the change to `device_cache.toml` so cold-start
/// hydration sees it. Emits a debounced `device-list-changed` event.
///
/// No-op if no record matches `ip` — discovery has to land first.
#[tauri::command]
pub async fn report_scan_result(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    ip: String,
    open_ports: Vec<u16>,
) -> Result<(), AppError> {
    let registry = manager.registry();
    if !registry.merge_scan_result(&ip, &open_ports) {
        return Ok(());
    }
    persist_record_for_ip(&registry, &config, &ip)?;
    if let Some(emitter) = manager.emitter().await {
        emitter.poke();
    }
    Ok(())
}

/// Set or clear the user-assigned alias for the device with this IP.
/// Empty string clears. Persists to cache (if the device has open
/// ports — cache rows without ports aren't useful) and emits.
#[tauri::command]
pub async fn set_device_alias(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    ip: String,
    alias: String,
) -> Result<(), AppError> {
    let registry = manager.registry();
    if !registry.set_alias(&ip, &alias) {
        return Ok(());
    }
    persist_record_for_ip(&registry, &config, &ip)?;
    if let Some(emitter) = manager.emitter().await {
        emitter.poke();
    }
    Ok(())
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
    if !manager.registry().forget(&mac) {
        return Ok(());
    }
    config.remove_cached_device(&mac)?;
    if let Some(emitter) = manager.emitter().await {
        emitter.poke();
    }
    Ok(())
}

/// Look up the registry record for `ip` and persist it to the cache
/// file (if it has open ports). No-op for records with no open ports
/// since the cache only stores entries useful for cold-start render.
fn persist_record_for_ip(
    registry: &crate::network::DeviceRegistry,
    config: &AppConfig,
    ip: &str,
) -> Result<(), AppError> {
    let record = match registry.snapshot().into_iter().find(|r| r.ip == ip) {
        Some(r) => r,
        None => return Ok(()),
    };
    if record.open_ports.is_empty() {
        return Ok(());
    }
    config.upsert_cached_device(CachedDevice {
        mac: record.mac,
        ip: record.ip,
        subnet: record.subnet,
        open_ports: record.open_ports,
        alias: record.alias,
        last_seen: record.last_seen,
    })
}

#[tauri::command]
pub async fn get_adopted_subnets(
    manager: State<'_, NetworkManager>,
) -> Result<std::collections::HashMap<String, String>, AppError> {
    Ok(manager.get_adopted_ips().await)
}

#[tauri::command]
pub async fn remove_adopted_subnet(
    manager: State<'_, NetworkManager>,
    config: State<'_, AppConfig>,
    subnet: String,
) -> Result<(), AppError> {
    manager.remove_adopted_subnet(&subnet).await?;
    manager.save_adopted_to_config(&config).await;
    Ok(())
}
