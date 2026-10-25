//! Concrete projections retain the existing single serialization boundary.
//! A playback caller cannot obtain a mutable relay view through this API.
use super::*;
use tokio::sync::{MappedMutexGuard, MutexGuard};

#[derive(Clone)]
pub(super) struct PlaybackSlot {
    shared: Arc<Mutex<StreamState>>,
}

impl PlaybackSlot {
    pub(super) fn new(shared: Arc<Mutex<StreamState>>) -> Self {
        Self { shared }
    }

    pub(super) async fn lock(&self) -> MappedMutexGuard<'_, playback::PlaybackData> {
        MutexGuard::map(self.shared.lock().await, |s| &mut s.playback_data)
    }

    pub(super) async fn lock_for_start(
        &self,
        udp_port: Option<u16>,
    ) -> Result<MappedMutexGuard<'_, playback::PlaybackData>, AppError> {
        let shared = self.shared.lock().await;
        if let Some(port) = udp_port {
            udp::guard_playback(&shared, port)?;
        }
        Ok(MutexGuard::map(shared, |s| &mut s.playback_data))
    }
}
