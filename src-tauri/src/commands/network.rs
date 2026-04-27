//! Network interface, IP config, scan, and ARP discovery IPC handlers.

use tauri::State;

use crate::config::AppConfig;
use crate::error::AppError;
use crate::network::{ArpDevice, InterfaceInfo, NetworkManager, ScanResult};

#[tauri::command]
pub async fn scan_network(
    manager: State<'_, NetworkManager>,
    subnet: String,
) -> Result<Vec<ScanResult>, AppError> {
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
    name: String,
    ip: String,
    subnet_mask: String,
    gateway: Option<String>,
) -> Result<(), AppError> {
    crate::network::ip_config::assign_static_ip(&name, &ip, &subnet_mask, gateway.as_deref()).await
}

#[tauri::command]
pub async fn add_secondary_ip(
    name: String,
    ip: String,
    subnet_mask: String,
) -> Result<(), AppError> {
    crate::network::ip_config::add_secondary_ip(&name, &ip, &subnet_mask).await
}

#[tauri::command]
pub async fn remove_secondary_ip(name: String, ip: String) -> Result<(), AppError> {
    crate::network::ip_config::remove_secondary_ip(&name, &ip).await
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

#[tauri::command]
pub async fn get_arp_devices(
    manager: State<'_, NetworkManager>,
) -> Result<Vec<ArpDevice>, AppError> {
    Ok(manager.get_arp_devices().await)
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
