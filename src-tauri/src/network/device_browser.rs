//! Browser access to a verified Ethernet device when Windows would route its
//! IP through another adapter. Each device has its own loopback HTTP origin.
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    LazyLock, Mutex,
};

use super::bound_tcp::{BoundTcpTransport, PathReady};
use crate::error::AppError;

const MAX_DEVICE_PAGES: usize = 8;

// HTTP cookies are scoped by host, not port. Allocate distinct loopback hosts
// for device sessions rather than sharing 127.0.0.1 with different ports.
// A randomized starting point also avoids routinely reusing old browser hosts
// after an app restart; the counter prevents reuse during this process.
static NEXT_HOST: LazyLock<AtomicU32> =
    LazyLock::new(|| AtomicU32::new(rand::random::<u32>() % 0x00ff_fffe));

fn next_loopback_host() -> Ipv4Addr {
    let value = NEXT_HOST.fetch_add(1, Ordering::Relaxed) % 0x00ff_fffe + 1;
    Ipv4Addr::new(127, (value >> 16) as u8, (value >> 8) as u8, value as u8)
}

#[derive(Default)]
pub(crate) struct DeviceBrowser {
    transports: Mutex<HashMap<String, BoundTcpTransport>>,
}

impl DeviceBrowser {
    pub(crate) fn url_for(&self, ready: PathReady) -> Result<String, AppError> {
        let path = ready()?;
        let mut transports = self
            .transports
            .lock()
            .map_err(|_| AppError::Network("Device browser service unavailable".into()))?;
        // A changed adapter, address or identity retires the old origin. Never
        // reuse one device's browser origin/cookies for a different device.
        transports.retain(|_, transport| transport.is_ready());
        if let Some(transport) = transports.get(&path.target.key) {
            return Ok(format!("http://{}/", transport.address()));
        }
        if transports.len() >= MAX_DEVICE_PAGES {
            return Err(AppError::Network(
                "Too many device browser sessions; restart PocketStream to close them".into(),
            ));
        }
        let transport = BoundTcpTransport::start_on_loopback(
            &format!("http://{}/", path.target.ip),
            ready,
            next_loopback_host(),
        )?;
        let url = format!("http://{}/", transport.address());
        transports.insert(path.target.key, transport);
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn browser_origin_is_reused_only_for_the_same_verified_device_path() {
        let browser = DeviceBrowser::default();
        let path = Arc::new(Mutex::new(super::super::bound_tcp::test_path("192.0.2.1")));
        let current = path.clone();
        let ready: PathReady = Arc::new(move || Ok(current.lock().unwrap().clone()));
        let first = browser.url_for(ready.clone()).unwrap();
        assert!(first.starts_with("http://127."));
        assert_eq!(browser.url_for(ready.clone()).unwrap(), first);
        path.lock().unwrap().target.ip = "192.0.2.2".into();
        let next = browser.url_for(ready).unwrap();
        assert_ne!(first, next);
        assert_ne!(
            reqwest::Url::parse(&first).unwrap().host_str(),
            reqwest::Url::parse(&next).unwrap().host_str()
        );
        let invalid: PathReady =
            Arc::new(|| Err(AppError::Network("Device is no longer verified".into())));
        assert!(browser.url_for(invalid).is_err());
        drop(browser);
    }

    /// Set POCKETSTREAM_WEB_SMOKE_IP, _SOURCE and _INDEX for an HTTP camera.
    #[tokio::test]
    #[ignore = "requires an explicitly selected HTTP camera and Ethernet source"]
    async fn camera_web_page_and_asset_through_bound_transport() {
        let ip = std::env::var("POCKETSTREAM_WEB_SMOKE_IP").unwrap();
        let mut path = super::super::bound_tcp::test_path(&ip);
        path.source = std::env::var("POCKETSTREAM_WEB_SMOKE_SOURCE")
            .unwrap()
            .parse()
            .unwrap();
        path.index = std::env::var("POCKETSTREAM_WEB_SMOKE_INDEX")
            .unwrap()
            .parse()
            .unwrap();
        let browser = DeviceBrowser::default();
        let url = browser.url_for(Arc::new(move || Ok(path.clone()))).unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(8))
            .build()
            .unwrap();
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let body = response.text().await.unwrap();
        assert!(body.to_ascii_lowercase().contains("<html"));
        if let Ok(asset) = std::env::var("POCKETSTREAM_WEB_SMOKE_ASSET") {
            assert!(!asset.starts_with('/') && !asset.contains("://"));
            let response = client.get(format!("{url}{asset}")).send().await.unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            assert!(!response.bytes().await.unwrap().is_empty());
        }
    }
}
