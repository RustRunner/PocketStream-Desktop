//! Pure validation for a complete prospective settings snapshot.
//!
//! Camera URL/IP/CIDR safety remains in `validation.rs`. This module owns
//! re-stream configuration invariants so loading, starting, and every writer
//! use one boundary instead of independently narrowing or normalizing fields.

use crate::config::{
    AppSettings, RestreamSettingsUpdate, RtspServerConfig, RtspServerUpdate, SrtPassphraseState,
    SrtPassphraseUpdate, SrtServerConfig, StreamConfig, StreamProtocol,
};
use crate::error::AppError;

const RTSP_TOKEN_LEN: usize = 16;
const SRT_PASSPHRASE_MIN_BYTES: usize = 10;
const SRT_PASSPHRASE_MAX_BYTES: usize = 79;
const SRT_LATENCY_MIN_MS: u32 = 20;
const SRT_LATENCY_MAX_MS: u32 = 8_000;
const SRT_STREAM_ID_MAX_BYTES: usize = 512;

/// SRT update after the Keep/Replace/Clear action has been resolved against
/// the current runtime secret state. This stays non-Debug because it can hold
/// plaintext or preserved ciphertext.
pub(crate) struct ResolvedSrtServerUpdate {
    pub port: i64,
    pub passphrase: SrtPassphraseState,
    pub latency_ms: i64,
    pub stream_id: String,
    pub bind_interface: String,
}

fn validation_error(message: impl Into<String>) -> AppError {
    AppError::Validation(message.into())
}

fn validate_rtsp_token(token: &str) -> Result<(), AppError> {
    if token.len() == RTSP_TOKEN_LEN
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(validation_error(
            "RTSP access token must be exactly 16 lowercase hexadecimal characters",
        ))
    }
}

fn narrow_port(port: i64, protocol: &str) -> Result<u16, AppError> {
    u16::try_from(port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| {
            validation_error(format!(
                "{protocol} server port must be between 1 and 65535"
            ))
        })
}

fn validate_srt_passphrase(passphrase: &SrtPassphraseState) -> Result<(), AppError> {
    let SrtPassphraseState::Available(value) = passphrase else {
        // Unencrypted is explicit, and Unavailable preserves opaque
        // ciphertext without pretending that it is plaintext.
        return Ok(());
    };
    let byte_len = value.len();
    if !(SRT_PASSPHRASE_MIN_BYTES..=SRT_PASSPHRASE_MAX_BYTES).contains(&byte_len) {
        return Err(validation_error(
            "SRT passphrase must be 10 to 79 bytes, or explicitly cleared",
        ));
    }
    if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(validation_error(
            "SRT passphrase must contain only printable ASCII characters without spaces",
        ));
    }
    Ok(())
}

fn validate_srt_stream_id(stream_id: &str) -> Result<(), AppError> {
    if stream_id.len() > SRT_STREAM_ID_MAX_BYTES {
        return Err(validation_error(
            "SRT Stream ID must be at most 512 UTF-8 bytes",
        ));
    }
    if stream_id.chars().any(char::is_control) {
        return Err(validation_error(
            "SRT Stream ID must not contain NUL or control characters",
        ));
    }
    Ok(())
}

/// Validate wide re-stream values and narrow them exactly once. Both the IPC
/// update path and private persisted DTO use this function, so negative and
/// oversized hand-authored values reach typed validation failures.
pub(crate) fn normalize_restream_servers(
    stream: &StreamConfig,
    enabled: bool,
    rtsp: RtspServerUpdate,
    srt: ResolvedSrtServerUpdate,
) -> Result<(RtspServerConfig, SrtServerConfig), AppError> {
    let rtsp_port = narrow_port(rtsp.port, "RTSP")?;
    validate_rtsp_token(&rtsp.token)?;

    let srt_port = narrow_port(srt.port, "SRT")?;
    let latency_ms = u32::try_from(srt.latency_ms)
        .ok()
        .filter(|latency| (SRT_LATENCY_MIN_MS..=SRT_LATENCY_MAX_MS).contains(latency))
        .ok_or_else(|| validation_error("SRT latency must be between 20 and 8000 ms"))?;
    validate_srt_passphrase(&srt.passphrase)?;
    validate_srt_stream_id(&srt.stream_id)?;

    if stream.protocol == StreamProtocol::Udp && stream.udp_port == srt_port {
        return Err(validation_error(
            "SRT server port must differ from the UDP camera input port",
        ));
    }

    Ok((
        RtspServerConfig {
            enabled,
            port: rtsp_port,
            token: rtsp.token,
            bind_interface: rtsp.bind_interface,
        },
        SrtServerConfig {
            port: srt_port,
            passphrase: srt.passphrase,
            latency_ms,
            stream_id: srt.stream_id,
            bind_interface: srt.bind_interface,
        },
    ))
}

/// Validate and return a complete prospective snapshot. Returning ownership
/// prevents callers from assigning partially checked narrow fields.
pub fn validate_prospective_settings(mut settings: AppSettings) -> Result<AppSettings, AppError> {
    let (rtsp_server, srt_server) = normalize_restream_servers(
        &settings.stream,
        settings.rtsp_server.enabled,
        RtspServerUpdate {
            port: i64::from(settings.rtsp_server.port),
            token: settings.rtsp_server.token.clone(),
            bind_interface: settings.rtsp_server.bind_interface.clone(),
        },
        ResolvedSrtServerUpdate {
            port: i64::from(settings.srt_server.port),
            passphrase: settings.srt_server.passphrase.clone(),
            latency_ms: i64::from(settings.srt_server.latency_ms),
            stream_id: settings.srt_server.stream_id.clone(),
            bind_interface: settings.srt_server.bind_interface.clone(),
        },
    )?;
    settings.rtsp_server = rtsp_server;
    settings.srt_server = srt_server;
    Ok(settings)
}

/// Resolve the secret action, apply both protocol sections to a clone, and
/// validate the complete result before any in-memory or on-disk mutation.
pub fn prospective_restream_settings(
    current: &AppSettings,
    update: RestreamSettingsUpdate,
) -> Result<AppSettings, AppError> {
    let passphrase = match update.srt_server.passphrase {
        SrtPassphraseUpdate::Keep => current.srt_server.passphrase.clone(),
        SrtPassphraseUpdate::Replace(value) => SrtPassphraseState::Available(value),
        SrtPassphraseUpdate::Clear => SrtPassphraseState::Unencrypted,
    };
    let (rtsp_server, srt_server) = normalize_restream_servers(
        &current.stream,
        update.enabled,
        update.rtsp_server,
        ResolvedSrtServerUpdate {
            port: update.srt_server.port,
            passphrase,
            latency_ms: update.srt_server.latency_ms,
            stream_id: update.srt_server.stream_id,
            bind_interface: update.srt_server.bind_interface,
        },
    )?;

    let mut prospective = current.clone();
    prospective.rtsp_server = rtsp_server;
    prospective.srt_server = srt_server;
    validate_prospective_settings(prospective)
}

/// An unavailable secret is a valid preservation state but cannot start an
/// SRT listener. Runtime/switch/recovery paths call this before disruption or
/// bind once the SRT protocol variant is enabled.
#[allow(dead_code)] // Wired into the SRT runtime start path in the next slice.
pub fn validate_srt_startable(settings: &AppSettings) -> Result<(), AppError> {
    if matches!(
        &settings.srt_server.passphrase,
        SrtPassphraseState::Unavailable { .. }
    ) {
        Err(AppError::SrtPassphraseUnavailable(
            "the saved SRT passphrase cannot be decrypted; replace it or explicitly clear encryption"
                .into(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SrtServerUpdate;

    fn update(
        rtsp_port: i64,
        srt_port: i64,
        latency_ms: i64,
        passphrase: SrtPassphraseUpdate,
        stream_id: &str,
    ) -> RestreamSettingsUpdate {
        RestreamSettingsUpdate {
            enabled: true,
            rtsp_server: RtspServerUpdate {
                port: rtsp_port,
                token: "0123456789abcdef".into(),
                bind_interface: String::new(),
            },
            srt_server: SrtServerUpdate {
                port: srt_port,
                passphrase,
                latency_ms,
                stream_id: stream_id.into(),
                bind_interface: String::new(),
            },
        }
    }

    fn validation_failure(update: RestreamSettingsUpdate) -> AppError {
        prospective_restream_settings(&AppSettings::default(), update)
            .err()
            .expect("settings should fail validation")
    }

    #[test]
    fn accepts_valid_port_and_latency_boundaries() {
        for rtsp_port in [1, 8_554, 65_535] {
            for srt_port in [1, 8_890, 65_535] {
                for latency in [20, 125, 8_000] {
                    let settings = prospective_restream_settings(
                        &AppSettings::default(),
                        update(rtsp_port, srt_port, latency, SrtPassphraseUpdate::Keep, ""),
                    )
                    .expect("boundary settings should validate");
                    assert_eq!(settings.rtsp_server.port, rtsp_port as u16);
                    assert_eq!(settings.srt_server.port, srt_port as u16);
                    assert_eq!(settings.srt_server.latency_ms, latency as u32);
                }
            }
        }
    }

    #[test]
    fn wide_ports_and_latencies_reach_typed_validation() {
        for port in [-1, 0, 65_536, i64::MAX] {
            assert_eq!(
                validation_failure(update(port, 8_890, 125, SrtPassphraseUpdate::Keep, "")).kind(),
                "Validation"
            );
            assert_eq!(
                validation_failure(update(8_554, port, 125, SrtPassphraseUpdate::Keep, "")).kind(),
                "Validation"
            );
        }
        for latency in [-1, 0, 19, 8_001, i64::MAX] {
            assert_eq!(
                validation_failure(update(8_554, 8_890, latency, SrtPassphraseUpdate::Keep, ""))
                    .kind(),
                "Validation"
            );
        }
    }

    #[test]
    fn token_is_exact_lowercase_hex() {
        for token in [
            "0123456789abcde",
            "0123456789abcdef0",
            "0123456789ABCDEf",
            "0123456789abcdeg",
        ] {
            let mut candidate = update(8_554, 8_890, 125, SrtPassphraseUpdate::Keep, "");
            candidate.rtsp_server.token = token.into();
            assert!(prospective_restream_settings(&AppSettings::default(), candidate).is_err());
        }
    }

    #[test]
    fn passphrase_requires_explicit_clear_or_printable_ascii_10_to_79_bytes() {
        let valid_values = ["1234567890".to_string(), "x".repeat(79)];
        for valid in valid_values {
            let settings = prospective_restream_settings(
                &AppSettings::default(),
                update(8_554, 8_890, 125, SrtPassphraseUpdate::Replace(valid), ""),
            )
            .expect("valid passphrase");
            assert!(matches!(
                settings.srt_server.passphrase,
                SrtPassphraseState::Available(_)
            ));
        }

        let invalid_values = [
            String::new(),
            "123456789".into(),
            "x".repeat(80),
            "has space!".into(),
            "123456789\n".into(),
            "nönascii123".into(),
        ];
        for invalid in invalid_values {
            assert!(prospective_restream_settings(
                &AppSettings::default(),
                update(8_554, 8_890, 125, SrtPassphraseUpdate::Replace(invalid), "",)
            )
            .is_err());
        }

        let cleared = prospective_restream_settings(
            &AppSettings::default(),
            update(8_554, 8_890, 125, SrtPassphraseUpdate::Clear, ""),
        )
        .expect("explicit Clear should be valid");
        assert!(matches!(
            cleared.srt_server.passphrase,
            SrtPassphraseState::Unencrypted
        ));
    }

    #[test]
    fn stream_id_uses_utf8_byte_limit_and_rejects_controls() {
        let valid_values = ["#!::name=a b&c=d,%#".to_string(), "é".repeat(256)];
        for valid in valid_values {
            assert!(prospective_restream_settings(
                &AppSettings::default(),
                update(8_554, 8_890, 125, SrtPassphraseUpdate::Keep, &valid,)
            )
            .is_ok());
        }
        let invalid_values = [
            "é".repeat(257),
            "contains\0nul".into(),
            "contains\nnewline".into(),
        ];
        for invalid in invalid_values {
            assert!(prospective_restream_settings(
                &AppSettings::default(),
                update(8_554, 8_890, 125, SrtPassphraseUpdate::Keep, &invalid,)
            )
            .is_err());
        }
    }

    #[test]
    fn udp_input_and_srt_output_ports_must_differ_even_while_rtsp_is_selected() {
        let mut current = AppSettings::default();
        current.stream.protocol = StreamProtocol::Udp;
        current.stream.udp_port = 8_890;
        assert!(prospective_restream_settings(
            &current,
            update(8_554, 8_890, 125, SrtPassphraseUpdate::Keep, "",)
        )
        .is_err());

        let mut later_camera_update = AppSettings::default();
        later_camera_update.srt_server.port = 9_000;
        later_camera_update.stream.protocol = StreamProtocol::Udp;
        later_camera_update.stream.udp_port = 9_000;
        assert!(validate_prospective_settings(later_camera_update).is_err());
    }

    #[test]
    fn keep_preserves_unavailable_ciphertext_and_startability_fails_closed() {
        let mut current = AppSettings::default();
        current.srt_server.passphrase = SrtPassphraseState::Unavailable {
            preserved_ciphertext: "opaque-ciphertext".into(),
        };
        let prospective = prospective_restream_settings(
            &current,
            update(8_554, 9_000, 250, SrtPassphraseUpdate::Keep, "saved id"),
        )
        .expect("Unavailable is a valid preservation state");
        match &prospective.srt_server.passphrase {
            SrtPassphraseState::Unavailable {
                preserved_ciphertext,
            } => assert_eq!(preserved_ciphertext, "opaque-ciphertext"),
            _ => panic!("Keep must preserve Unavailable"),
        }
        let error = validate_srt_startable(&prospective).expect_err("start must fail closed");
        assert_eq!(error.kind(), "SrtPassphraseUnavailable");
    }

    #[test]
    fn replace_and_clear_are_the_only_repairs_for_unavailable_passphrase() {
        let mut current = AppSettings::default();
        current.srt_server.passphrase = SrtPassphraseState::Unavailable {
            preserved_ciphertext: "opaque-ciphertext".into(),
        };

        let replaced = prospective_restream_settings(
            &current,
            update(
                8_554,
                8_890,
                125,
                SrtPassphraseUpdate::Replace("replacement1".into()),
                "",
            ),
        )
        .expect("valid replacement should repair the secret state");
        match replaced.srt_server.passphrase {
            SrtPassphraseState::Available(value) => assert_eq!(value, "replacement1"),
            _ => panic!("Replace must produce Available plaintext"),
        }

        let cleared = prospective_restream_settings(
            &current,
            update(8_554, 8_890, 125, SrtPassphraseUpdate::Clear, ""),
        )
        .expect("explicit Clear should repair to passwordless mode");
        assert!(matches!(
            cleared.srt_server.passphrase,
            SrtPassphraseState::Unencrypted
        ));
    }
}
