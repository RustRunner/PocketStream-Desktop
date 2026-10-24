//! Typed adapter refresh; no nested elevation or wildcard adapter commands.
use crate::error::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RefreshMode {
    Soft,
    Hard,
}

impl super::NetworkManager {
    pub async fn refresh_native_adapter(
        &self,
        config: &crate::config::AppConfig,
        name: &str,
        mode: RefreshMode,
    ) -> Result<(), AppError> {
        #[cfg(windows)]
        super::native_operations::check_writes_available()?;
        let _op = self.discovery_op.lock().await;
        let _pause = self.pause_addresses();
        self.stop_locked().await;
        let _address = self.address_work.lock().await;
        let before = self.operation_snapshot(config).await?;
        if before.selected.alias != name {
            return Err(AppError::Network(
                "Selected adapter changed before refresh".into(),
            ));
        }
        #[cfg(windows)]
        {
            super::native_operations::execute(super::native_operations::Operation::refresh(
                &before.selected,
                mode == RefreshMode::Hard,
            )?)
            .await
        }
        #[cfg(not(windows))]
        {
            let _ = mode;
            Err(AppError::Network(
                "Adapter refresh is only implemented on Windows".into(),
            ))
        }
    }
}
