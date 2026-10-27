//! The real listener: timeouts, connection handling, shutdown.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use common::*;
use postal_pigeon::server;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

struct Running {
    addr: SocketAddr,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
    _app: TestApp,
}

async fn start(header_timeout_secs: u64) -> Running {
    let app = TestApp::builder()
        .limits(move |l| l.header_read_timeout_secs = header_timeout_secs)
        .build()
        .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = oneshot::channel::<()>();
    let router = app.router.clone();
    let limits = app.settings.limits.clone();
    let task = tokio::spawn(async move {
        server::serve(listener, router, &limits, async {
            let _ = rx.await;
        })
        .await;
    });
    Running {
        addr,
        stop,
        task,
        _app: app,
    }
}

/// Reads until the peer closes or `within` passes; returns what came and
/// whether the connection was closed by the server.
async fn read_until_closed(s: &mut TcpStream, within: Duration) -> (String, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, s.read(&mut buf)).await {
            Err(_) => return (String::from_utf8_lossy(&out).into_owned(), false),
            Ok(Ok(0)) | Ok(Err(_)) => return (String::from_utf8_lossy(&out).into_owned(), true),
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
        }
    }
}

#[tokio::test]
async fn it_serves_requests_with_the_peer_address() {
    let r = start(5).await;
    let mut s = TcpStream::connect(r.addr).await.unwrap();
    s.write_all(b"GET /v1/challenge HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let (text, closed) = read_until_closed(&mut s, Duration::from_secs(5)).await;
    assert!(closed);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("\"challenge\""), "{text}");
    assert!(
        text.to_ascii_lowercase()
            .contains("cache-control: no-store")
    );
    let _ = r.stop.send(());
    r.task.await.unwrap();
}

#[tokio::test]
async fn a_client_that_trickles_its_headers_is_cut_off() {
    let r = start(1).await;
    let mut s = TcpStream::connect(r.addr).await.unwrap();
    s.write_all(b"GET /healthz HTTP/1.1\r\nhost:")
        .await
        .unwrap();
    let started = Instant::now();
    let (_, closed) = read_until_closed(&mut s, Duration::from_secs(6)).await;
    assert!(closed, "the connection was still open after 6 s");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    let _ = r.stop.send(());
    r.task.await.unwrap();
}

#[tokio::test]
async fn a_client_that_sends_nothing_is_cut_off() {
    let r = start(1).await;
    let mut s = TcpStream::connect(r.addr).await.unwrap();
    let (_, closed) = read_until_closed(&mut s, Duration::from_secs(6)).await;
    assert!(closed, "an idle connection must not live forever");
    let _ = r.stop.send(());
    r.task.await.unwrap();
}

#[tokio::test]
async fn an_idle_kept_alive_connection_is_closed() {
    let r = start(1).await;
    let mut s = TcpStream::connect(r.addr).await.unwrap();
    s.write_all(b"GET /healthz HTTP/1.1\r\nhost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let n = s.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    let (_, closed) = read_until_closed(&mut s, Duration::from_secs(6)).await;
    assert!(closed, "the keep-alive connection was left open");
    let _ = r.stop.send(());
    r.task.await.unwrap();
}

#[tokio::test]
async fn it_stops_when_told_to() {
    let r = start(5).await;
    // An open, quiet connection doesn't keep the server from stopping.
    let _idle = TcpStream::connect(r.addr).await.unwrap();
    let _ = r.stop.send(());
    tokio::time::timeout(Duration::from_secs(10), r.task)
        .await
        .expect("serve returns after shutdown")
        .unwrap();
}
