//! Tests for the findings of the October 2026 security review
//! (docs/security-review-2026-10.md).

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::Request;
use common::*;
use serde_json::json;
use tower::ServiceExt as _;

fn device_body(n: u8) -> String {
    json!({ "app": "hedgerow", "environment": "production", "token": token(n) }).to_string()
}

fn post(path: &str, content_type: Option<&str>, body: String) -> Request<Body> {
    let mut b = Request::builder().method("POST").uri(path);
    if let Some(ct) = content_type {
        b = b.header("content-type", ct);
    }
    b.body(Body::from(body)).unwrap()
}

async fn device_count(app: &TestApp) -> i64 {
    app.state
        .db
        .call(|c| postal_pigeon::db::count_devices(c).unwrap())
        .await
}

// ---- PIG-01: a browser must not be able to post to the relay cross-site ----

#[tokio::test]
async fn a_body_that_is_not_json_is_refused_so_a_browser_cannot_post_it_cross_site() {
    let app = TestApp::new().await;
    // These are the content types a web page may send to any site without the
    // browser asking first. If the relay took them, a page could register
    // devices from every visitor's address.
    for ct in [
        Some("text/plain"),
        Some("text/plain;charset=UTF-8"),
        Some("application/x-www-form-urlencoded"),
        Some("multipart/form-data; boundary=x"),
        None,
    ] {
        for path in ["/v1/devices", "/v1/instances", "/v1/push"] {
            let ip = app.next_ip();
            let r = app.raw_from(&ip, post(path, ct, device_body(1))).await;
            assert_eq!(
                (r.status.as_u16(), r.error()),
                (415, "unsupported_media_type"),
                "{path} {ct:?}"
            );
        }
    }
    assert_eq!(device_count(&app).await, 0, "nothing was registered");

    // JSON, with or without parameters and in any case, still works.
    for ct in [
        "application/json",
        "application/json; charset=utf-8",
        "Application/JSON",
    ] {
        let ip = app.next_ip();
        let r = app
            .raw_from(&ip, post("/v1/devices", Some(ct), device_body(2)))
            .await;
        assert_eq!(r.status, 201, "{ct}: {}", r.json);
    }
}

#[tokio::test]
async fn a_cross_origin_preflight_is_not_granted() {
    let app = TestApp::new().await;
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/v1/devices")
        .header("origin", "https://evil.example")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .body(Body::empty())
        .unwrap();
    let r = app.raw(req).await;
    assert!(r.status.is_client_error(), "{}", r.status);
    assert!(
        r.headers
            .keys()
            .all(|k| !k.as_str().starts_with("access-control-")),
        "{:?}",
        r.headers
    );
}

// ---- PIG-02: junk can't lock new devices out of a full table ---------------

async fn try_register(app: &TestApp, n: u8) -> Resp {
    let ip = app.next_ip();
    app.call_from(
        &ip,
        "POST",
        "/v1/devices",
        None,
        Some(json!({ "app": "hedgerow", "environment": "production", "token": token(n) })),
        None,
    )
    .await
}

#[tokio::test]
async fn a_full_table_makes_room_by_dropping_old_devices_nobody_uses() {
    let app = TestApp::builder()
        .limits(|l| l.max_devices = 3)
        .build()
        .await;
    let d1 = app.new_device(&token(1)).await;
    let d2 = app.new_device(&token(2)).await;
    let d3 = app.new_device(&token(3)).await;
    // Device 1 has been given to a server, so it is in use.
    app.new_handle(&d1).await;

    // A device that registered a minute ago may be about to ask for its first
    // handle: while all are young, a full table stays full.
    let r = try_register(&app, 4).await;
    assert_eq!((r.status.as_u16(), r.error()), (503, "overloaded"));

    // Later, the oldest one that nobody uses makes room.
    app.clock.advance_secs(2 * 3600);
    let r = try_register(&app, 4).await;
    assert_eq!(r.status, 201, "{}", r.json);
    assert!(
        app.device_exists(&d1.id).await,
        "a device with a handle stays"
    );
    assert!(!app.device_exists(&d2.id).await, "the oldest idle one goes");
    assert!(app.device_exists(&d3.id).await);
    assert_eq!(device_count(&app).await, 3);
}

#[tokio::test]
async fn a_table_full_of_devices_in_use_still_refuses_more() {
    let app = TestApp::builder()
        .limits(|l| l.max_devices = 2)
        .build()
        .await;
    for n in 1..=2 {
        let d = app.new_device(&token(n)).await;
        app.new_handle(&d).await;
    }
    app.clock.advance_secs(2 * 3600);
    let r = try_register(&app, 3).await;
    assert_eq!((r.status.as_u16(), r.error()), (503, "overloaded"));
    assert_eq!(device_count(&app).await, 2);
}

// ---- PIG-03: one address can't use up every request permit ------------------

/// A POST whose body never arrives, from `ip`, running as a task.
fn slow_request(app: &TestApp, ip: &str) -> tokio::task::JoinHandle<()> {
    let mut req = Request::builder()
        .method("POST")
        .uri("/v1/devices")
        .header("content-type", "application/json")
        .body(Body::from_stream(futures_util::stream::pending::<
            Result<Bytes, std::io::Error>,
        >()))
        .unwrap();
    let peer: SocketAddr = format!("{ip}:40000").parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    let router = app.router.clone();
    tokio::spawn(async move {
        let _ = router.oneshot(req).await;
    })
}

#[tokio::test]
async fn an_address_that_holds_requests_open_cannot_take_every_permit() {
    let app = TestApp::builder()
        .limits(|l| {
            l.max_inflight_per_addr = 2;
            l.max_inflight_requests = 8;
        })
        .build()
        .await;
    let slow = [
        slow_request(&app, "198.51.100.7"),
        slow_request(&app, "198.51.100.7"),
    ];
    tokio::time::sleep(Duration::from_millis(150)).await;

    // The same address is at its limit...
    let r = app
        .call_from("198.51.100.7", "GET", "/v1/status", None, None, None)
        .await;
    assert_eq!((r.status.as_u16(), r.error()), (429, "rate_limited"));
    assert_eq!(r.retry_after(), Some(1));
    // ...another address is not, and the health check is never held up.
    let r = app
        .call_from("198.51.100.8", "GET", "/v1/status", None, None, None)
        .await;
    assert_eq!(r.status, 200);
    let r = app
        .call_from("198.51.100.7", "GET", "/healthz", None, None, None)
        .await;
    assert_eq!(r.status, 200);

    // Hanging up frees the slots.
    for t in &slow {
        t.abort();
    }
    for t in slow {
        let _ = t.await;
    }
    assert!(app.state.addr_inflight.is_empty());
    let r = app
        .call_from("198.51.100.7", "GET", "/v1/status", None, None, None)
        .await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn the_per_address_cap_follows_the_client_behind_a_proxy() {
    // Behind the proxy, the cap is on the real client, not on the proxy.
    let app = TestApp::builder()
        .proxies(&["10.0.0.1"])
        .limits(|l| l.max_inflight_per_addr = 1)
        .build()
        .await;
    let mut req = Request::builder()
        .method("POST")
        .uri("/v1/devices")
        .header("content-type", "application/json")
        .header("x-forwarded-for", "203.0.113.5")
        .body(Body::from_stream(futures_util::stream::pending::<
            Result<Bytes, std::io::Error>,
        >()))
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo("10.0.0.1:40000".parse::<SocketAddr>().unwrap()));
    let router = app.router.clone();
    let held = tokio::spawn(async move {
        let _ = router.oneshot(req).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let r = app
        .call_from(
            "10.0.0.1",
            "GET",
            "/v1/status",
            None,
            None,
            Some("203.0.113.5"),
        )
        .await;
    assert_eq!(r.status, 429, "the same client");
    let r = app
        .call_from(
            "10.0.0.1",
            "GET",
            "/v1/status",
            None,
            None,
            Some("203.0.113.6"),
        )
        .await;
    assert_eq!(r.status, 200, "another client behind the same proxy");
    held.abort();
}

// ---- PIG-07: errors the framework makes are in the API's format -------------

#[tokio::test]
async fn errors_the_framework_makes_are_in_the_api_format() {
    let app = TestApp::new().await;
    let r = app.call("DELETE", "/v1/push", None, None).await;
    assert_eq!((r.status.as_u16(), r.error()), (405, "method_not_allowed"));
    assert!(r.headers.contains_key("allow"));

    // A path parameter that is not valid UTF-8 once decoded.
    let r = app
        .call("GET", "/v1/devices/%ff/handles", Some("hrm_x"), None)
        .await;
    assert!(r.status.is_client_error(), "{}", r.status);
    assert!(r.json["error"].is_string(), "{}", r.json);
}
