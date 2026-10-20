//! Recovery policy uses GError domains/codes, never translated message text.
use gstreamer as gst;

pub(super) fn bus_fault(
    error: &glib::Error,
    friendly: String,
    rtsp_status: Option<u32>,
    debug: &str,
) -> super::relay::PlaybackFault {
    use glib::translate::ToGlibPtr;
    let raw_error: *const glib::ffi::GError = error.to_glib_none().0;
    // rtspsrc reports otherwise-unhandled 403 responses as RESOURCE READ,
    // retaining the current response in typed error details (not debug text).
    let denied = error.matches(gst::ResourceError::Read) && rtsp_status == Some(403);
    // setup_auth reports this one permanent authentication case as OPEN_READ.
    // Its debug literal is source-defined and untranslated; transport failures
    // with the same code still retry. Friendly display text is never policy.
    let unsupported_auth = error.matches(gst::ResourceError::OpenRead)
        && debug.contains("No supported authentication protocol was found");
    let reason = if unsupported_auth {
        "Unsupported camera authentication protocol. Check camera authentication settings.".into()
    } else if error.matches(gst::ResourceError::NotAuthorized) || denied {
        "Camera authorization failed. Check Username/Password and camera permissions.".into()
    } else if error.matches(gst::ResourceError::NotFound) {
        "Stream path not found. Check the Path in settings.".into()
    } else if error.is::<gst::StreamError>() && !retryable(error) {
        "Unsupported or undecodable media. Check the camera codec and stream format.".into()
    } else {
        friendly
    };
    super::relay::PlaybackFault {
        kind: super::relay::PlaybackFaultKind::BusError,
        domain: Some(error.domain().as_str().to_string()),
        // GError owns this pointer for the duration of this synchronous read.
        code: Some(unsafe { (*raw_error).code }),
        reason,
        retryable: retryable(error) && !denied && !unsupported_auth,
    }
}

pub(super) fn retryable(error: &glib::Error) -> bool {
    // rtspsrc's send/error_response posts RESOURCE NOT_FOUND for 404 and
    // NOT_AUTHORIZED for 401. Transport open/read failures are retryable.
    // https://github.com/GStreamer/gstreamer/blob/1.26.11/subprojects/gst-plugins-good/gst/rtsp/gstrtspsrc.c
    if let Some(code) = error.kind::<gst::ResourceError>() {
        return !matches!(
            code,
            gst::ResourceError::NotFound
                | gst::ResourceError::NotAuthorized
                | gst::ResourceError::Settings
                | gst::ResourceError::NoSpaceLeft
                | gst::ResourceError::OpenWrite
                | gst::ResourceError::Write
        );
    }
    if let Some(code) = error.kind::<gst::StreamError>() {
        return matches!(code, gst::StreamError::Failed);
    }
    if error.is::<gst::CoreError>() || error.is::<gst::LibraryError>() {
        return false;
    }
    // GIO transport failures, including connection closed/refused/timed out.
    if let Some(code) = error.kind::<gio::IOErrorEnum>() {
        return !matches!(
            code,
            gio::IOErrorEnum::PermissionDenied
                | gio::IOErrorEnum::NotFound
                | gio::IOErrorEnum::InvalidArgument
                | gio::IOErrorEnum::NotSupported
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_errors_retry_regardless_of_message() {
        for code in [
            gst::ResourceError::OpenRead,
            gst::ResourceError::Read,
            gst::ResourceError::Busy,
        ] {
            assert!(retryable(&glib::Error::new(
                code,
                "401 cached in debug; stalled"
            )));
        }
        for code in [
            gio::IOErrorEnum::ConnectionRefused,
            gio::IOErrorEnum::TimedOut,
            gio::IOErrorEnum::BrokenPipe,
        ] {
            assert!(retryable(&glib::Error::new(code, "transport")));
        }
    }

    #[test]
    fn permanent_errors_do_not_retry_even_with_transport_words() {
        for code in [
            gst::ResourceError::NotAuthorized,
            gst::ResourceError::NotFound,
            gst::ResourceError::Settings,
            gst::ResourceError::NoSpaceLeft,
        ] {
            assert!(!retryable(&glib::Error::new(
                code,
                "timeout connection reset"
            )));
        }
        for code in [
            gst::StreamError::Decode,
            gst::StreamError::CodecNotFound,
            gst::StreamError::Format,
            gst::StreamError::Demux,
        ] {
            assert!(!retryable(&glib::Error::new(code, "stalled")));
        }
        assert!(!retryable(&glib::Error::new(
            gst::CoreError::Negotiation,
            "timeout"
        )));
    }

    #[test]
    fn current_rtsp_response_details_handle_access_denied_without_text_matching() {
        let error = glib::Error::new(gst::ResourceError::Read, "localized text");
        assert!(!bus_fault(&error, "localized".into(), Some(403), "").retryable);
        let fault = bus_fault(
            &error,
            "cached 401 404 stalled".into(),
            None,
            "cached 401 404",
        );
        assert!(fault.retryable);
        assert_eq!(fault.domain.as_deref(), Some("gst-resource-error-quark"));
        assert_eq!(fault.code, Some(9));
        assert!(bus_fault(&error, "busy".into(), Some(503), "").retryable);
        let auth = glib::Error::new(gst::ResourceError::OpenRead, "localized");
        assert!(
            !bus_fault(
                &auth,
                "localized".into(),
                None,
                "No supported authentication protocol was found"
            )
            .retryable
        );
        assert!(
            bus_fault(
                &auth,
                "localized".into(),
                None,
                "connection refused; cached 401"
            )
            .retryable
        );
    }
}
