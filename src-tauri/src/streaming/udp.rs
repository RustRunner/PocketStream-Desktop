//! UDP admission is atomic with intent publication under the common state lock.
//! Keeping that lock avoids a second claim that could outlive its real consumer.
use super::*;

pub(super) fn guard_playback(state: &StreamState, port: u16) -> Result<(), AppError> {
    if (state.relay_data.restream_desired
        && state
            .relay_data
            .restream_spec
            .as_ref()
            .and_then(ResolvedStartSpec::udp_ingest_port)
            == Some(port))
        || state
            .relay_data
            .restream_server
            .as_ref()
            .and_then(RestreamServer::udp_ingest_port)
            == Some(port)
    {
        return Err(AppError::Stream(format!("UDP port {} is already claimed by the re-stream server. Stop it first or switch the input to RTSP.", port)));
    }
    Ok(())
}

pub(super) fn guard_relay(state: &StreamState, port: u16) -> Result<(), AppError> {
    if state.playback_data.playback_source == Some(SourceMode::Udp { port }) {
        return Err(AppError::Stream(format!(
            "UDP port {} is already claimed by the running preview - only one consumer can receive a UDP stream. Stop the stream first, or switch the input to RTSP.", port
        )));
    }
    Ok(())
}
