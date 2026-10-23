//! Loopback TCP forwarding bound to a freshly verified Ethernet device.
//! No default-route fallback; the owner and identity fence govern all sockets.
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinSet;

use crate::error::AppError;
use crate::network::route::ReadyPath;

pub type PathReady = Arc<dyn Fn() -> Result<ReadyPath, AppError> + Send + Sync>;

const CHECK_INTERVAL: Duration = Duration::from_secs(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 8;

struct Gate {
    path: ReadyPath,
    ready: PathReady,
    active: AtomicBool,
}

impl Gate {
    fn check(&self) -> Result<(), AppError> {
        if !self.active.load(Ordering::Acquire) || self.path.fence.is_stale() {
            return Err(AppError::Network("Device Ethernet session retired".into()));
        }
        let current = (self.ready)()?;
        if current.fence.is_stale()
            || current.index != self.path.index
            || current.source != self.path.source
            || current.target != self.path.target
        {
            return Err(AppError::Network("Device Ethernet path changed".into()));
        }
        Ok(())
    }
}

pub(crate) struct BoundTcpTransport {
    address: SocketAddr,
    gate: Arc<Gate>,
    task: tauri::async_runtime::JoinHandle<()>,
}

impl BoundTcpTransport {
    pub(crate) fn start(url: &str, ready: PathReady) -> Result<Self, AppError> {
        Self::start_on_loopback(url, ready, Ipv4Addr::LOCALHOST)
    }

    pub(crate) fn start_on_loopback(
        url: &str,
        ready: PathReady,
        listen_ip: Ipv4Addr,
    ) -> Result<Self, AppError> {
        if !listen_ip.is_loopback() {
            return Err(AppError::Network(
                "Device bridge must listen on loopback".into(),
            ));
        }
        let path = ready()?;
        let endpoint = reqwest::Url::parse(url)
            .map_err(|_| AppError::Stream("Invalid device TCP URL".into()))?;
        let ip = path
            .target
            .ip
            .parse::<Ipv4Addr>()
            .map_err(|_| AppError::Stream("Camera requires an IPv4 address".into()))?;
        if !matches!(endpoint.scheme(), "rtsp" | "http")
            || endpoint.host_str().and_then(|h| h.parse::<Ipv4Addr>().ok()) != Some(ip)
            || path.index == 0
            || endpoint.port() == Some(0)
        {
            return Err(AppError::Stream(
                "Device URL does not match the verified Ethernet path".into(),
            ));
        }
        let destination = SocketAddrV4::new(
            ip,
            endpoint
                .port()
                .unwrap_or(if endpoint.scheme() == "rtsp" { 554 } else { 80 }),
        );
        let gate = Arc::new(Gate {
            path,
            ready,
            active: AtomicBool::new(true),
        });
        gate.check()?;
        let listener = TcpListener::bind((listen_ip, 0)).map_err(transport_error)?;
        listener.set_nonblocking(true).map_err(transport_error)?;
        let address = listener.local_addr().map_err(transport_error)?;
        let current = gate.clone();
        // Conversion happens inside the runtime: lazy RTSP media is constructed
        // on a GLib thread without a Tokio reactor entered on that thread.
        let task = tauri::async_runtime::spawn(async move {
            if let Err(error) = serve(listener, destination, current.clone()).await {
                log::warn!("Ethernet-bound TCP transport stopped: {error}");
            }
            current.active.store(false, Ordering::Release);
        });
        Ok(Self {
            address,
            gate,
            task,
        })
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.gate.check().is_ok()
    }

    pub(crate) fn readiness_check(&self) -> impl Fn() -> bool + Send + Sync + 'static {
        let gate = self.gate.clone();
        move || gate.check().is_ok()
    }

    pub(crate) fn shutdown(&self) {
        self.gate.active.store(false, Ordering::Release);
        self.task.abort();
    }
}

impl Drop for BoundTcpTransport {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn transport_error(error: std::io::Error) -> AppError {
    AppError::Network(format!("Ethernet-bound TCP transport: {error}"))
}

async fn serve(
    listener: TcpListener,
    destination: SocketAddrV4,
    gate: Arc<Gate>,
) -> Result<(), AppError> {
    let listener = tokio::net::TcpListener::from_std(listener).map_err(transport_error)?;
    let mut connections = JoinSet::new();
    let mut interval = tokio::time::interval(CHECK_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = gate.path.fence.cancelled() => return Ok(()),
            _ = interval.tick() => gate.check()?,
            _ = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let (client, _) = accepted.map_err(transport_error)?;
                gate.check()?;
                if connections.len() < MAX_CONNECTIONS {
                    let current = gate.clone();
                    connections.spawn(async move {
                        if let Err(error) = forward(client, destination, current).await {
                            log::debug!("Ethernet-bound TCP connection closed: {error}");
                        }
                    });
                }
            }
        }
    }
    // Dropping JoinSet aborts every forwarding task, including pending connects.
}

fn bind_socket(path: &ReadyPath) -> std::io::Result<TcpSocket> {
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::V4(SocketAddrV4::new(path.source, 0)))?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            setsockopt, WSAGetLastError, IPPROTO_IP, IP_UNICAST_IF, SOCKET_ERROR,
        };
        // IP_UNICAST_IF expects a DWORD interface index in network byte order.
        let index = path.index.to_be();
        // The socket and option bytes remain valid throughout this call.
        let result = unsafe {
            setsockopt(
                socket.as_raw_socket() as _,
                IPPROTO_IP,
                IP_UNICAST_IF,
                (&index as *const u32).cast(),
                std::mem::size_of_val(&index) as i32,
            )
        };
        if result == SOCKET_ERROR {
            return Err(std::io::Error::from_raw_os_error(unsafe {
                WSAGetLastError()
            }));
        }
    }
    Ok(socket)
}

async fn forward(
    mut client: TcpStream,
    destination: SocketAddrV4,
    gate: Arc<Gate>,
) -> Result<(), AppError> {
    gate.check()?;
    let socket = bind_socket(&gate.path).map_err(transport_error)?;
    let mut camera = tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(destination.into()))
        .await
        .map_err(|_| AppError::Network("Camera TCP connection timed out on Ethernet".into()))?
        .map_err(transport_error)?;
    gate.check()?;
    camera.set_nodelay(true).map_err(transport_error)?;
    client.set_nodelay(true).map_err(transport_error)?;
    tokio::io::copy_bidirectional(&mut client, &mut camera)
        .await
        .map_err(transport_error)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_path(ip: &str) -> ReadyPath {
    use std::sync::atomic::AtomicU64;
    ReadyPath {
        target: crate::network::route::CameraTarget {
            key: "aa:bb:cc:dd:ee:01".into(),
            expected_mac: Some("aa:bb:cc:dd:ee:01".into()),
            ip: ip.into(),
        },
        source: Ipv4Addr::LOCALHOST,
        index: crate::network::route::egress_index(Ipv4Addr::LOCALHOST).unwrap_or(1),
        fence: crate::network::SweepFence::new(
            1,
            Arc::new(AtomicU64::new(1)),
            Arc::new(AtomicBool::new(true)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn closed(socket: &mut TcpStream) {
        let mut byte = [0];
        let read = tokio::time::timeout(Duration::from_secs(3), socket.read(&mut byte))
            .await
            .expect("transport did not close");
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "unexpected bytes after cancellation"
        );
    }

    async fn listener_closed(address: SocketAddr) {
        // Closing active peers and the listener is asynchronous. Windows may
        // complete an already queued TCP handshake during socket teardown;
        // even a fully closed loopback port takes about 2 seconds to refuse.
        tokio::time::timeout(Duration::from_secs(6), async {
            while let Ok(mut connection) = TcpStream::connect(address).await {
                closed(&mut connection).await;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("listener remained open after transport retirement");
    }

    async fn connected() -> (
        BoundTcpTransport,
        TcpStream,
        TcpStream,
        Arc<Mutex<ReadyPath>>,
    ) {
        let camera = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let path = Arc::new(Mutex::new(test_path("127.0.0.1")));
        let current = path.clone();
        let transport = BoundTcpTransport::start(
            &format!("rtsp://{}/live", camera.local_addr().unwrap()),
            Arc::new(move || Ok(current.lock().unwrap().clone())),
        )
        .unwrap();
        let client = TcpStream::connect(transport.address).await.unwrap();
        let (upstream, peer) = tokio::time::timeout(Duration::from_secs(3), camera.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer.ip(), std::net::IpAddr::V4(path.lock().unwrap().source));
        (transport, client, upstream, path)
    }

    #[tokio::test]
    async fn bound_transport_preserves_requests_and_interleaved_media_and_closes_on_drop() {
        let (transport, mut client, mut camera, _) = connected().await;
        // No URL/auth rewriting and no interpretation of binary RTP/RTCP.
        let request = b"DESCRIBE rtsp://127.0.0.1/live RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        client.write_all(request).await.unwrap();
        let mut received = vec![0; request.len()];
        tokio::time::timeout(Duration::from_secs(2), camera.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, request);
        let media = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n$\x00\x00\x04\x00\xff\x10\x80";
        camera.write_all(media).await.unwrap();
        received.resize(media.len(), 0);
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, media);
        let address = transport.address;
        drop(transport);
        closed(&mut client).await;
        closed(&mut camera).await;
        listener_closed(address).await;
    }

    #[tokio::test]
    async fn transport_retires_on_source_interface_identity_or_fence_change() {
        for change in 0..4 {
            let (transport, mut client, mut camera, path) = connected().await;
            {
                let mut current = path.lock().unwrap();
                match change {
                    0 => current.source = Ipv4Addr::new(192, 0, 2, 1),
                    1 => current.index += 1,
                    2 => current.target.expected_mac = Some("aa:bb:cc:dd:ee:02".into()),
                    _ => {
                        current.fence = crate::network::SweepFence::new(
                            1,
                            Arc::new(std::sync::atomic::AtomicU64::new(2)),
                            Arc::new(AtomicBool::new(true)),
                        )
                    }
                }
            }
            closed(&mut client).await;
            closed(&mut camera).await;
            listener_closed(transport.address).await;
        }
    }

    #[tokio::test]
    async fn failed_source_bind_never_falls_back_to_default_routing() {
        let camera = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let mut path = test_path("127.0.0.1");
        path.source = Ipv4Addr::new(192, 0, 2, 123);
        let transport = BoundTcpTransport::start(
            &format!("rtsp://{}/live", camera.local_addr().unwrap()),
            Arc::new(move || Ok(path.clone())),
        )
        .unwrap();
        let mut client = TcpStream::connect(transport.address).await.unwrap();
        closed(&mut client).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), camera.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn readiness_loss_blocks_new_connections_and_url_must_match_verified_ip() {
        let camera = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let active = Arc::new(AtomicBool::new(true));
        let current = active.clone();
        let gate: PathReady = Arc::new(move || {
            if current.load(Ordering::Acquire) {
                Ok(test_path("127.0.0.1"))
            } else {
                Err(AppError::Network("Camera proof expired".into()))
            }
        });
        assert!(BoundTcpTransport::start("rtsp://192.0.2.1/live", gate.clone()).is_err());
        let transport = BoundTcpTransport::start(
            &format!("rtsp://{}/live", camera.local_addr().unwrap()),
            gate.clone(),
        )
        .unwrap();
        active.store(false, Ordering::Release);
        if let Ok(mut client) = TcpStream::connect(transport.address).await {
            closed(&mut client).await;
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), camera.accept())
                .await
                .is_err()
        );
        assert!(BoundTcpTransport::start("rtsp://127.0.0.1/live", gate).is_err());
    }
}
