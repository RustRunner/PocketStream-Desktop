//! Concrete projections retain the existing single serialization boundary.
//! A playback caller cannot obtain a mutable relay view through this API.
use super::*;
use tokio::sync::{MappedMutexGuard, MutexGuard};

// No service receives this unprojected storage. Status can read it as a whole;
// the facade's only retained unprojected view is compiled solely for scenarios.
pub(super) struct StreamState {
    pub(super) playback_data: playback::PlaybackData,
    pub(super) relay_data: relay_service::RelayData,
}

pub(super) fn new(selected_protocol: RestreamProtocol) -> Arc<Mutex<StreamState>> {
    Arc::new(Mutex::new(StreamState {
        playback_data: playback::PlaybackData::default(),
        relay_data: relay_service::RelayData::new(selected_protocol),
    }))
}

#[derive(Clone)]
pub(super) struct RelaySlot {
    shared: Arc<Mutex<StreamState>>,
}

impl RelaySlot {
    pub(super) fn new(shared: Arc<Mutex<StreamState>>) -> Self {
        Self { shared }
    }
    pub(super) async fn lock(&self) -> RelayGuard<'_> {
        RelayGuard {
            shared: self.shared.lock().await,
        }
    }
}

pub(super) struct RelayGuard<'a> {
    shared: MutexGuard<'a, StreamState>,
}

impl RelayGuard<'_> {
    pub(super) fn guard_udp(&self, port: u16) -> Result<(), AppError> {
        udp::guard_relay(&self.shared, port)
    }
}
impl std::ops::Deref for RelayGuard<'_> {
    type Target = relay_service::RelayData;
    fn deref(&self) -> &Self::Target {
        &self.shared.relay_data
    }
}
impl std::ops::DerefMut for RelayGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.shared.relay_data
    }
}

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
