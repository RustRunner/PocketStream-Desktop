//! One HTTP/1.1 control request per verified Ethernet-bound connection.
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;

use super::{bound_tcp::bind_socket, route::ReadyPath};
use crate::error::{AppError, ReadinessRefusal};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_BODY: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub(crate) struct Error {
    pub(crate) error: AppError,
    pub(crate) retryable: bool,
}

impl From<AppError> for Error {
    fn from(error: AppError) -> Self {
        Self {
            error,
            retryable: false,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Response {
    pub(crate) status: StatusCode,
    pub(crate) body: Vec<u8>,
}

fn stale_selection() -> AppError {
    AppError::Network("Ethernet adapter changed".into())
        .with_readiness_reason(ReadinessRefusal::StaleSelection)
}

fn check_path(
    path: &ReadyPath,
    ready: &impl Fn() -> Result<ReadyPath, AppError>,
) -> Result<(), AppError> {
    if path.fence.is_stale() {
        return Err(stale_selection());
    }
    let current = ready()?;
    if path.fence.is_stale() || current.fence.is_stale() {
        return Err(stale_selection());
    }
    if current.index != path.index || current.source != path.source || current.target != path.target
    {
        return Err(AppError::Network("Device Ethernet path changed".into())
            .with_readiness_reason(ReadinessRefusal::PathChanged));
    }
    Ok(())
}

pub(crate) async fn post_form(
    path: &ReadyPath,
    ready: impl Fn() -> Result<ReadyPath, AppError>,
    resource: &str,
    body: String,
    headers: &[(&str, &str)],
) -> Result<Response, Error> {
    post_form_on_port(path, ready, 80, resource, body, headers).await
}

async fn post_form_on_port(
    path: &ReadyPath,
    ready: impl Fn() -> Result<ReadyPath, AppError>,
    port: u16,
    resource: &str,
    body: String,
    headers: &[(&str, &str)],
) -> Result<Response, Error> {
    let received_headers = AtomicBool::new(false);
    let transport_error = |error: String| Error {
        error: AppError::Camera(format!("Ethernet HTTP request failed: {error}")),
        retryable: !received_headers.load(Ordering::Relaxed),
    };
    let request = async {
        let ip = path
            .target
            .ip
            .parse::<Ipv4Addr>()
            .map_err(|_| AppError::Camera("Device HTTP requires an IPv4 address".into()))?;
        let mut request = Request::post(resource)
            .header("Host", format!("{ip}:{port}"))
            .header("Connection", "close")
            .header("Content-Type", "application/x-www-form-urlencoded");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = request
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| AppError::Camera(format!("Invalid device HTTP request: {e}")))?;
        check_path(path, &ready)?;
        let socket = bind_socket(path.source, path.index)
            .map_err(|e| AppError::Camera(format!("Ethernet HTTP binding failed: {e}")))?;
        let stream = socket
            .connect(SocketAddrV4::new(ip, port).into())
            .await
            .map_err(|e| transport_error(e.to_string()))?;
        check_path(path, &ready)?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| transport_error(e.to_string()))?;
        let exchange = async {
            let response = sender
                .send_request(request)
                .await
                .map_err(|e| transport_error(e.to_string()))?;
            received_headers.store(true, Ordering::Relaxed);
            let status = response.status();
            let mut incoming = response.into_body();
            let mut body = Vec::new();
            while let Some(frame) = incoming.frame().await {
                let frame = frame.map_err(|e| transport_error(e.to_string()))?;
                if let Ok(data) = frame.into_data() {
                    if data.len() > MAX_BODY - body.len() {
                        return Err(
                            AppError::Camera("Device HTTP response exceeds 64 KiB".into()).into(),
                        );
                    }
                    body.extend_from_slice(&data);
                }
            }
            Ok(Response { status, body })
        };
        // Drive the connection here: dropping this request must close the socket
        // before the caller releases its PTU send lock, even on cancellation.
        tokio::pin!(exchange);
        tokio::select! {
            biased;
            result = &mut exchange => result,
            // Consume any response already delivered before a connection error
            // so an HTTP rejection cannot become a retryable send failure.
            _ = connection => exchange.await,
        }
    };
    tokio::select! {
        biased;
        _ = path.fence.cancelled() => Err(stale_selection().into()),
        result = tokio::time::timeout(REQUEST_TIMEOUT, request) => {
            result.unwrap_or_else(|_| Err(transport_error("timed out after 3 seconds".into())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{bound_tcp::test_path, SweepFence};
    use std::sync::{atomic::AtomicU64, Arc};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;

    async fn read_request(socket: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        loop {
            let byte = socket.read_u8().await.unwrap();
            bytes.push(byte);
            if bytes.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let headers = String::from_utf8(bytes.clone()).unwrap();
        let length: usize = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(|v| v.parse().unwrap())
            })
            .unwrap();
        let mut body = vec![0; length];
        socket.read_exact(&mut body).await.unwrap();
        bytes.extend(body);
        String::from_utf8(bytes).unwrap()
    }

    async fn assert_closed(socket: &mut TcpStream) {
        let mut byte = [0];
        match timeout(Duration::from_secs(1), socket.read(&mut byte))
            .await
            .unwrap()
        {
            Ok(0) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {}
            other => panic!("request left a live socket or extra bytes: {other:?}"),
        }
    }

    #[tokio::test]
    async fn binds_each_request_source_and_never_follows_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let redirect = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let location = redirect.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut peers = Vec::new();
            for _ in 0..3 {
                let (mut socket, peer) = listener.accept().await.unwrap();
                peers.push(peer.ip());
                let request = read_request(&mut socket).await;
                assert!(request.starts_with("POST /API/PTCmd HTTP/1.1\r\n"));
                assert!(request
                    .to_ascii_lowercase()
                    .contains("content-type: application/x-www-form-urlencoded\r\n"));
                assert!(request.ends_with("C=V&PS=0&TS=0"));
                socket.write_all(format!("HTTP/1.1 302 Found\r\nLocation: http://{location}/\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.unwrap();
                assert_closed(&mut socket).await;
            }
            peers
        });
        let mut path = test_path("127.0.0.1");
        for source in ["127.0.0.2", "127.0.0.1", "127.0.0.1"] {
            path.source = source.parse().unwrap();
            let response = post_form_on_port(
                &path,
                || Ok(path.clone()),
                port,
                "/API/PTCmd",
                "C=V&PS=0&TS=0".into(),
                &[],
            )
            .await
            .unwrap();
            assert_eq!(response.status, 302);
        }
        assert_eq!(
            server.await.unwrap(),
            ["127.0.0.2", "127.0.0.1", "127.0.0.1"].map(|s| s.parse::<std::net::IpAddr>().unwrap())
        );
        assert!(timeout(Duration::from_millis(30), redirect.accept())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rechecks_path_after_connect_before_any_http_bytes() {
        for changed in ["source", "index", "identity", "target", "fence"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let path = test_path("127.0.0.1");
            let calls = AtomicU64::new(0);
            let ready = || {
                let mut current = path.clone();
                if calls.fetch_add(1, Ordering::Relaxed) > 0 {
                    match changed {
                        "source" => current.source = "127.0.0.2".parse().unwrap(),
                        "index" => current.index += 1,
                        "identity" => {
                            current.target.expected_mac = Some("aa:bb:cc:dd:ee:02".into())
                        }
                        "target" => current.target.ip = "127.0.0.2".into(),
                        "fence" => {
                            current.fence = SweepFence::new(
                                1,
                                Arc::new(AtomicU64::new(2)),
                                Arc::new(AtomicBool::new(true)),
                            )
                        }
                        _ => unreachable!(),
                    }
                }
                Ok(current)
            };
            let error = post_form_on_port(&path, ready, port, "/", "move".into(), &[])
                .await
                .unwrap_err();
            assert!(!error.retryable);
            assert_eq!(calls.load(Ordering::Relaxed), 2);
            let (mut socket, _) = listener.accept().await.unwrap();
            assert_closed(&mut socket).await;
        }
    }

    #[tokio::test]
    async fn stale_fence_and_binding_failure_refuse_without_connecting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        for stale in [true, false] {
            let mut path = test_path("127.0.0.1");
            if stale {
                path.fence = SweepFence::new(
                    1,
                    Arc::new(AtomicU64::new(2)),
                    Arc::new(AtomicBool::new(true)),
                );
            } else {
                path.index = 0;
            }
            let error =
                post_form_on_port(&path, || Ok(path.clone()), port, "/", "move".into(), &[])
                    .await
                    .unwrap_err();
            assert!(!error.retryable);
            assert!(timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn deadline_closes_pending_response_before_next_serialized_send() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let path = test_path("127.0.0.1");
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let send_lock = lock.clone();
        let first_path = path.clone();
        let first = tokio::spawn(async move {
            let _guard = send_lock.lock().await;
            post_form_on_port(
                &first_path,
                || Ok(first_path.clone()),
                port,
                "/",
                "move".into(),
                &[],
            )
            .await
        });
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request(&mut socket).await;
        // Delayed headers must not give the body a fresh three-second budget.
        tokio::time::sleep(Duration::from_secs(2)).await;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx")
            .await
            .unwrap();
        let second = tokio::spawn(async move {
            let _guard = lock.lock().await;
            post_form_on_port(&path, || Ok(path.clone()), port, "/", "halt".into(), &[]).await
        });
        let error = timeout(Duration::from_millis(1500), first)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(!error.retryable);
        assert_closed(&mut socket).await;
        let (mut next, _) = listener.accept().await.unwrap();
        assert!(read_request(&mut next).await.ends_with("halt"));
        next.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(second.await.unwrap().unwrap().status, 204);
        assert_closed(&mut next).await;
    }

    #[tokio::test]
    async fn fence_cancellation_and_caller_drop_close_inflight_socket() {
        for cancel_fence in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let mut path = test_path("127.0.0.1");
            let active = Arc::new(AtomicBool::new(true));
            path.fence = SweepFence::new(1, Arc::new(AtomicU64::new(1)), active.clone());
            let request = tokio::spawn(async move {
                post_form_on_port(&path, || Ok(path.clone()), port, "/", "move".into(), &[]).await
            });
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request(&mut socket).await;
            if cancel_fence {
                active.store(false, Ordering::Relaxed);
                let error = timeout(Duration::from_secs(1), request)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap_err();
                assert!(matches!(
                    error.error,
                    AppError::Readiness {
                        reason: ReadinessRefusal::StaleSelection,
                        ..
                    }
                ));
                assert!(!error.retryable);
            } else {
                request.abort();
                assert!(request.await.unwrap_err().is_cancelled());
            }
            assert_closed(&mut socket).await;
        }
    }

    #[tokio::test]
    async fn caps_chunked_response_and_preserves_success_body_and_ajax_header() {
        for length in [MAX_BODY, MAX_BODY + 1] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                assert!(request
                    .to_ascii_lowercase()
                    .contains("x-requested-with: xmlhttprequest\r\n"));
                assert!(
                    request.ends_with("action=CameraControl&command=zoom_direct+100&cam_index=1")
                );
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{length:x}\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                socket.write_all(&vec![b'x'; length]).await.unwrap();
                socket.write_all(b"\r\n0\r\n\r\n").await.unwrap();
                assert_closed(&mut socket).await;
            });
            let path = test_path("127.0.0.1");
            let result = post_form_on_port(
                &path,
                || Ok(path.clone()),
                port,
                "/cgi-bin/control.cgi",
                "action=CameraControl&command=zoom_direct+100&cam_index=1".into(),
                &[("X-Requested-With", "XMLHttpRequest")],
            )
            .await;
            if length == MAX_BODY {
                let response = result.unwrap();
                assert_eq!(response.status, 200);
                assert_eq!(response.body, vec![b'x'; length]);
            } else {
                let error = result.unwrap_err();
                assert!(error.to_string().contains("64 KiB"));
                assert!(!error.retryable);
            }
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn only_failures_before_response_headers_allow_the_zoom_retry() {
        for response in [
            "",
            "not HTTP\r\n\r\n",
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\n\r\nx",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                read_request(&mut socket).await;
                socket.write_all(response.as_bytes()).await.unwrap();
            });
            let path = test_path("127.0.0.1");
            let error =
                post_form_on_port(&path, || Ok(path.clone()), port, "/", "zoom".into(), &[])
                    .await
                    .unwrap_err();
            assert_eq!(error.retryable, !response.starts_with("HTTP/1.1 500"));
            server.await.unwrap();
        }
    }
}
