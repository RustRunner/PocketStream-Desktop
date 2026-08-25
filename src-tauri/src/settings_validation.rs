//! Pure validation for a complete prospective settings snapshot.
//!
//! Camera URL/IP/CIDR safety remains in `validation.rs`. This module owns
//! re-stream configuration invariants so loading, starting, and every writer
//! use one boundary instead of independently narrowing or normalizing fields.

use crate::config::{AppSettings, RestreamSettingsUpdate, RtspServerConfig};
use crate::error::AppError;

const RTSP_TOKEN_LEN: usize = 16;

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

/// Validate and return a complete prospective snapshot. Returning ownership
/// prevents callers from assigning partially checked narrow fields.
pub fn validate_prospective_settings(settings: AppSettings) -> Result<AppSettings, AppError> {
    if settings.rtsp_server.port == 0 {
        return Err(validation_error(
            "RTSP server port must be between 1 and 65535",
        ));
    }
    validate_rtsp_token(&settings.rtsp_server.token)?;
    Ok(settings)
}

/// Apply the wide IPC update to a cloned snapshot, then validate the entire
/// prospective settings value before any in-memory or on-disk mutation.
pub fn prospective_restream_settings(
    current: &AppSettings,
    update: RestreamSettingsUpdate,
) -> Result<AppSettings, AppError> {
    let port = u16::try_from(update.rtsp_server.port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| validation_error("RTSP server port must be between 1 and 65535"))?;

    let mut prospective = current.clone();
    prospective.rtsp_server = RtspServerConfig {
        enabled: update.enabled,
        port,
        token: update.rtsp_server.token,
        bind_interface: update.rtsp_server.bind_interface,
    };
    validate_prospective_settings(prospective)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RestreamSettingsUpdate, RtspServerUpdate};

    fn update(port: i64, token: &str) -> RestreamSettingsUpdate {
        RestreamSettingsUpdate {
            enabled: true,
            rtsp_server: RtspServerUpdate {
                port,
                token: token.into(),
                bind_interface: String::new(),
            },
        }
    }

    #[test]
    fn accepts_valid_rtsp_port_boundaries() {
        for port in [1, 8_554, 65_535] {
            let settings = prospective_restream_settings(
                &AppSettings::default(),
                update(port, "0123456789abcdef"),
            )
            .unwrap();
            assert_eq!(settings.rtsp_server.port, port as u16);
        }
    }

    #[test]
    fn wide_ports_reach_typed_validation() {
        for port in [-1, 0, 65_536, i64::MAX] {
            let error = prospective_restream_settings(
                &AppSettings::default(),
                update(port, "0123456789abcdef"),
            )
            .unwrap_err();
            assert_eq!(error.kind(), "Validation");
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
            assert!(
                prospective_restream_settings(&AppSettings::default(), update(8554, token))
                    .is_err()
            );
        }
    }
}
