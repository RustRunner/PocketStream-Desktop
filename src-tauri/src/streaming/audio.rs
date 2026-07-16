//! Stream-selection and pad-routing policy for multi-track RTSP input.
//!
//! rtspsrc creates one source pad per selected RTP stream. A camera
//! that announces audio alongside video therefore produces more pads
//! than the playback pipeline has consumers, and an unlinked selected
//! pad's `GST_FLOW_NOT_LINKED` kills the whole stream loop. The policy
//! here decides, per stream, whether to SETUP it at all
//! (`select_playback`) and, per pad, where it must be routed
//! (`route_pad`) so that no selected pad is ever left unlinked.
//!
//! Everything except `classify_rtp_caps` is pure and free of GStreamer
//! state: registry lookups are injected as a closure so the policy is
//! unit-testable — lib tests must not initialize GStreamer.

use std::sync::atomic::{AtomicBool, Ordering};

use gstreamer as gst;

/// Audio codecs the playback pipeline knows how to decode.
///
/// Extending support is local to this table: add a variant, its
/// element names, and its branch description; `select_playback` and
/// the routing code consume the table without changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodec {
    /// G.711 µ-law (RTP static payload 0).
    Pcmu,
    /// G.711 a-law (RTP static payload 8).
    Pcma,
}

impl AudioCodec {
    /// RTP encoding-name, also used for user-facing codec labels.
    pub fn name(self) -> &'static str {
        match self {
            AudioCodec::Pcmu => "PCMU",
            AudioCodec::Pcma => "PCMA",
        }
    }

    /// RTP depayloader element for this codec.
    pub fn depay(self) -> &'static str {
        match self {
            AudioCodec::Pcmu => "rtppcmudepay",
            AudioCodec::Pcma => "rtppcmadepay",
        }
    }

    /// Decoder element for this codec.
    pub fn decoder(self) -> &'static str {
        match self {
            AudioCodec::Pcmu => "mulawdec",
            AudioCodec::Pcma => "alawdec",
        }
    }

    /// Every element the full playback branch needs. A stream is only
    /// accepted at SETUP when all of these exist in the registry —
    /// accepting on the decoder alone would admit a track the branch
    /// then cannot terminate audibly.
    pub fn required_elements(self) -> [&'static str; 6] {
        [
            self.depay(),
            self.decoder(),
            "audioconvert",
            "audioresample",
            "volume",
            "autoaudiosink",
        ]
    }
}

/// Coarse classification of an RTP stream's `media` caps field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    Video,
    Audio,
    Other,
}

/// Classify the SDP/caps `media` value. Anything that is not
/// recognizably video or audio — including a missing field — is
/// `Other` and gets declined/terminated by the policy below.
pub fn classify_media(media: Option<&str>) -> MediaKind {
    match media {
        Some(m) if m.eq_ignore_ascii_case("video") => MediaKind::Video,
        Some(m) if m.eq_ignore_ascii_case("audio") => MediaKind::Audio,
        _ => MediaKind::Other,
    }
}

/// Identify a supported audio codec from RTP caps fields.
///
/// An explicit `encoding-name` is authoritative: an unknown name
/// rejects even when the payload number would match, because a camera
/// that names its codec knows better than the static-payload table.
/// The payload fallback (0 → PCMU, 8 → PCMA per RFC 3551) applies only
/// when the name is absent.
pub fn audio_codec_from_caps(
    encoding_name: Option<&str>,
    payload: Option<i32>,
) -> Option<AudioCodec> {
    match encoding_name {
        Some(name) if name.eq_ignore_ascii_case("PCMU") => Some(AudioCodec::Pcmu),
        Some(name) if name.eq_ignore_ascii_case("PCMA") => Some(AudioCodec::Pcma),
        Some(_) => None,
        None => match payload {
            Some(0) => Some(AudioCodec::Pcmu),
            Some(8) => Some(AudioCodec::Pcma),
            _ => None,
        },
    }
}

/// True only when every element the codec's branch needs exists per
/// the injected registry check.
pub fn audio_codec_supported(codec: AudioCodec, has_element: impl Fn(&str) -> bool) -> bool {
    codec.required_elements().into_iter().all(has_element)
}

/// Where a newly appeared rtspsrc pad must be routed. Every variant is
/// a terminal decision — there is no "leave unlinked" outcome.
#[derive(Debug, PartialEq, Eq)]
pub enum PadRoute {
    /// The selected video pad: link to the decodebin sink.
    VideoDecoder,
    /// Terminate the pad in its own fakesink; the payload is the
    /// reason for the log line.
    Fakesink(&'static str),
}

/// Occupancy state shared by the SETUP-time (`select-stream`) and
/// pad-time (`pad-added`) callbacks of one pipeline. Both fire on
/// rtspsrc streaming threads, so each slot is claimed with a
/// compare-and-set — two concurrent offers cannot both win.
#[derive(Debug, Default)]
pub struct SelectionState {
    video_selected: AtomicBool,
    audio_selected: AtomicBool,
    video_routed: AtomicBool,
    audio_routed: AtomicBool,
}

impl SelectionState {
    /// SETUP-time policy for the playback pipeline: accept the first
    /// video stream and the first *supported* audio stream; decline
    /// everything else. Unsupported audio is declined without claiming
    /// the audio slot, so a later supported track can still take it.
    pub fn select_playback(
        &self,
        kind: MediaKind,
        codec: Option<AudioCodec>,
        supported: bool,
    ) -> bool {
        match kind {
            MediaKind::Video => self
                .video_selected
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            MediaKind::Audio => {
                if codec.is_none() || !supported {
                    return false;
                }
                self.audio_selected
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            }
            MediaKind::Other => false,
        }
    }

    /// Pad-time routing verdict. The first video pad goes to the
    /// decoder; every other pad — duplicates, audio, surprises —
    /// terminates in a fakesink. Audio termination is the safety net
    /// for pads that appear despite `select_playback` (or, currently,
    /// for accepted audio: the audible playback branch does not exist
    /// yet, so accepted audio parks here).
    pub fn route_pad(&self, kind: MediaKind) -> PadRoute {
        match kind {
            MediaKind::Video => {
                if self
                    .video_routed
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    PadRoute::VideoDecoder
                } else {
                    PadRoute::Fakesink("duplicate video pad")
                }
            }
            MediaKind::Audio => {
                if self
                    .audio_routed
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    PadRoute::Fakesink("audio playback branch unavailable")
                } else {
                    PadRoute::Fakesink("duplicate audio pad")
                }
            }
            MediaKind::Other => PadRoute::Fakesink("unexpected media type"),
        }
    }
}

/// Pull `media` / `encoding-name` / `payload` out of an
/// `application/x-rtp` caps structure and classify.
///
/// Deliberately not unit-tested: constructing `Caps` requires
/// GStreamer init, which lib tests must not do. It stays a thin
/// extraction shim over the pure functions above.
pub fn classify_rtp_caps(caps: &gst::CapsRef) -> (MediaKind, Option<AudioCodec>) {
    let Some(s) = caps.structure(0) else {
        return (MediaKind::Other, None);
    };
    let kind = classify_media(s.get::<&str>("media").ok());
    let codec = audio_codec_from_caps(
        s.get::<&str>("encoding-name").ok(),
        s.get::<i32>("payload").ok(),
    );
    (kind, codec)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── classify_media ──────────────────────────────────────────────

    #[test]
    fn media_video_and_audio_recognized() {
        assert_eq!(classify_media(Some("video")), MediaKind::Video);
        assert_eq!(classify_media(Some("audio")), MediaKind::Audio);
    }

    #[test]
    fn media_matching_is_case_insensitive() {
        assert_eq!(classify_media(Some("VIDEO")), MediaKind::Video);
        assert_eq!(classify_media(Some("Audio")), MediaKind::Audio);
    }

    #[test]
    fn media_unknown_or_missing_is_other() {
        // "application" is a real SDP media type (e.g. ONVIF metadata
        // streams) — it must classify as Other, not error.
        assert_eq!(classify_media(Some("application")), MediaKind::Other);
        assert_eq!(classify_media(Some("")), MediaKind::Other);
        assert_eq!(classify_media(None), MediaKind::Other);
    }

    // ── audio_codec_from_caps ───────────────────────────────────────

    #[test]
    fn codec_names_recognized_case_insensitively() {
        assert_eq!(
            audio_codec_from_caps(Some("PCMU"), None),
            Some(AudioCodec::Pcmu)
        );
        assert_eq!(
            audio_codec_from_caps(Some("pcmu"), None),
            Some(AudioCodec::Pcmu)
        );
        assert_eq!(
            audio_codec_from_caps(Some("PCMA"), None),
            Some(AudioCodec::Pcma)
        );
        assert_eq!(
            audio_codec_from_caps(Some("Pcma"), None),
            Some(AudioCodec::Pcma)
        );
    }

    #[test]
    fn explicit_unknown_name_rejects_even_with_matching_payload() {
        // A camera that names its codec is authoritative — payload 0
        // must not override an explicit non-PCMU name.
        assert_eq!(audio_codec_from_caps(Some("G726-32"), Some(0)), None);
        assert_eq!(audio_codec_from_caps(Some("MPEG4-GENERIC"), Some(8)), None);
    }

    #[test]
    fn static_payload_fallback_applies_only_without_name() {
        assert_eq!(audio_codec_from_caps(None, Some(0)), Some(AudioCodec::Pcmu));
        assert_eq!(audio_codec_from_caps(None, Some(8)), Some(AudioCodec::Pcma));
    }

    #[test]
    fn unknown_payload_or_nothing_rejects() {
        assert_eq!(audio_codec_from_caps(None, Some(96)), None);
        assert_eq!(audio_codec_from_caps(None, None), None);
    }

    // ── audio_codec_supported ───────────────────────────────────────

    #[test]
    fn supported_when_every_required_element_exists() {
        assert!(audio_codec_supported(AudioCodec::Pcmu, |_| true));
        assert!(audio_codec_supported(AudioCodec::Pcma, |_| true));
    }

    #[test]
    fn any_single_missing_element_rejects() {
        for codec in [AudioCodec::Pcmu, AudioCodec::Pcma] {
            for missing in codec.required_elements() {
                assert!(
                    !audio_codec_supported(codec, |e| e != missing),
                    "{codec:?} must be unsupported when {missing} is absent"
                );
            }
        }
    }

    #[test]
    fn branch_elements_are_codec_specific() {
        assert!(AudioCodec::Pcmu
            .required_elements()
            .contains(&"rtppcmudepay"));
        assert!(AudioCodec::Pcmu.required_elements().contains(&"mulawdec"));
        assert!(AudioCodec::Pcma
            .required_elements()
            .contains(&"rtppcmadepay"));
        assert!(AudioCodec::Pcma.required_elements().contains(&"alawdec"));
    }

    // ── select_playback ─────────────────────────────────────────────

    #[test]
    fn first_video_accepted_later_video_declined() {
        let s = SelectionState::default();
        assert!(s.select_playback(MediaKind::Video, None, false));
        assert!(!s.select_playback(MediaKind::Video, None, false));
    }

    #[test]
    fn first_supported_audio_accepted_later_declined() {
        let s = SelectionState::default();
        assert!(s.select_playback(MediaKind::Audio, Some(AudioCodec::Pcmu), true));
        assert!(!s.select_playback(MediaKind::Audio, Some(AudioCodec::Pcma), true));
    }

    #[test]
    fn unsupported_audio_declined_without_claiming_the_slot() {
        let s = SelectionState::default();
        // Unrecognized codec, then recognized-but-missing-elements:
        // neither may occupy the audio slot...
        assert!(!s.select_playback(MediaKind::Audio, None, false));
        assert!(!s.select_playback(MediaKind::Audio, Some(AudioCodec::Pcmu), false));
        // ...so a later fully supported track is still accepted.
        assert!(s.select_playback(MediaKind::Audio, Some(AudioCodec::Pcma), true));
    }

    #[test]
    fn other_media_always_declined() {
        let s = SelectionState::default();
        assert!(!s.select_playback(MediaKind::Other, None, false));
        assert!(!s.select_playback(MediaKind::Other, None, true));
    }

    #[test]
    fn video_and_audio_slots_are_independent() {
        let s = SelectionState::default();
        assert!(s.select_playback(MediaKind::Audio, Some(AudioCodec::Pcmu), true));
        assert!(s.select_playback(MediaKind::Video, None, false));
    }

    // ── route_pad ───────────────────────────────────────────────────

    #[test]
    fn first_video_pad_routes_to_decoder() {
        let s = SelectionState::default();
        assert_eq!(s.route_pad(MediaKind::Video), PadRoute::VideoDecoder);
    }

    #[test]
    fn duplicate_video_pad_routes_to_fakesink() {
        let s = SelectionState::default();
        assert_eq!(s.route_pad(MediaKind::Video), PadRoute::VideoDecoder);
        assert!(matches!(
            s.route_pad(MediaKind::Video),
            PadRoute::Fakesink(_)
        ));
    }

    #[test]
    fn audio_pads_route_to_fakesink() {
        // No audible branch exists yet: accepted audio parks in a
        // fakesink, and so does a duplicate.
        let s = SelectionState::default();
        assert!(matches!(
            s.route_pad(MediaKind::Audio),
            PadRoute::Fakesink(_)
        ));
        assert!(matches!(
            s.route_pad(MediaKind::Audio),
            PadRoute::Fakesink(_)
        ));
    }

    #[test]
    fn other_pads_route_to_fakesink() {
        let s = SelectionState::default();
        assert!(matches!(
            s.route_pad(MediaKind::Other),
            PadRoute::Fakesink(_)
        ));
    }

    #[test]
    fn every_non_video_outcome_is_the_fakesink_path() {
        // The structural guarantee: route_pad has no outcome that
        // leaves a pad unlinked. Exactly one VideoDecoder verdict
        // exists per pipeline; everything else is a Fakesink.
        let s = SelectionState::default();
        let verdicts = [
            s.route_pad(MediaKind::Video),
            s.route_pad(MediaKind::Video),
            s.route_pad(MediaKind::Audio),
            s.route_pad(MediaKind::Audio),
            s.route_pad(MediaKind::Other),
        ];
        let decoders = verdicts
            .iter()
            .filter(|v| **v == PadRoute::VideoDecoder)
            .count();
        assert_eq!(decoders, 1);
        assert!(verdicts[1..]
            .iter()
            .all(|v| matches!(v, PadRoute::Fakesink(_))));
    }
}
