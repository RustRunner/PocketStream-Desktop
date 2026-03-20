pub mod interface;
pub mod ip_config;
pub mod scanner;

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

pub use interface::InterfaceInfo;
pub use scanner::ScanResult;

use crate::error::AppError;

pub struct NetworkManager {
    /// Track which subnets are currently being scanned
    active_scans: Arc<Mutex<HashSet<String>>>,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            active_scans: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>, AppError> {
        interface::list_all()
    }

    pub fn get_interface(&self, name: &str) -> Result<InterfaceInfo, AppError> {
        interface::get_by_name(name)
    }

    pub async fn scan_subnet(&self, subnet: &str) -> Result<Vec<ScanResult>, AppError> {
        {
            let mut active = self.active_scans.lock().await;
            if !active.insert(subnet.to_string()) {
                return Err(AppError::Network(format!(
                    "Scan already in progress for {}",
                    subnet
                )));
            }
        }

        let result = scanner::scan(subnet).await;

        self.active_scans.lock().await.remove(subnet);
        result
    }
}
