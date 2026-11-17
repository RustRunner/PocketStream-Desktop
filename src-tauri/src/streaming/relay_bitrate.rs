//! Measure selected video bytes before decoding to budget H.264 conversion.
use gstreamer as gst;
use gstreamer::prelude::*;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(super) const STARTUP_KBPS: u32 = 256;
const SAMPLE_WINDOW: Duration = Duration::from_secs(2);

#[derive(Default)]
struct InputRate {
    started: Option<Instant>,
    bytes: u64,
}

impl InputRate {
    fn observe(&mut self, bytes: u64, now: Instant) -> Option<u32> {
        let Some(started) = self.started else {
            self.started = Some(now);
            return None;
        };
        self.bytes = self.bytes.saturating_add(bytes);
        let elapsed = now.saturating_duration_since(started);
        if elapsed < SAMPLE_WINDOW {
            return None;
        }
        let kbps =
            (u128::from(self.bytes) * 8_000_000 / elapsed.as_nanos()).clamp(1, 2_048_000) as u32;
        self.started = Some(now);
        self.bytes = 0;
        Some(kbps)
    }
}

pub(super) fn follow_input(pad: &gst::Pad, encoder: &gst::Element) {
    let rate = Mutex::new(InputRate::default());
    let encoder = encoder.downgrade();
    pad.add_probe(
        gst::PadProbeType::BUFFER | gst::PadProbeType::BUFFER_LIST,
        move |_pad, info| {
            let bytes = match info.data.as_ref() {
                Some(gst::PadProbeData::Buffer(buffer)) => buffer.size() as u64,
                Some(gst::PadProbeData::BufferList(buffers)) => {
                    buffers.iter().map(|buffer| buffer.size() as u64).sum()
                }
                _ => return gst::PadProbeReturn::Ok,
            };
            let target = rate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .observe(bytes, Instant::now());
            if let (Some(kbps), Some(encoder)) = (target, encoder.upgrade()) {
                if encoder.property::<u32>("bitrate") != kbps {
                    encoder.set_property("bitrate", kbps);
                    log::debug!("event=relay_bitrate target_kbps={kbps}");
                }
            }
            gst::PadProbeReturn::Ok
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measures_video_rate_and_follows_increases_and_decreases() {
        let mut rate = InputRate::default();
        let start = Instant::now();
        // Exclude the first buffer from the counter baseline, including a large keyframe.
        assert_eq!(rate.observe(1_000_000, start), None);
        assert_eq!(rate.observe(125_000, start + Duration::from_secs(1)), None);
        assert_eq!(
            rate.observe(125_000, start + Duration::from_secs(2)),
            Some(1000)
        );
        assert_eq!(
            rate.observe(1_000_000, start + Duration::from_secs(4)),
            Some(4000)
        );
        assert_eq!(
            rate.observe(62_500, start + Duration::from_secs(6)),
            Some(250)
        );
    }

    #[test]
    fn accounts_for_actual_elapsed_time_and_encoder_limits() {
        let mut rate = InputRate::default();
        let start = Instant::now();
        rate.observe(0, start);
        assert_eq!(
            rate.observe(500_000, start + Duration::from_secs(4)),
            Some(1000)
        );
        assert_eq!(rate.observe(0, start + Duration::from_secs(6)), Some(1));
        assert_eq!(
            rate.observe(u64::MAX, start + Duration::from_secs(8)),
            Some(2_048_000)
        );
    }
}
