//! How the relay talks to Apple, against a mock APNs server (never the real one).

mod common;

use common::*;
use serde_json::json;

struct World {
    app: TestApp,
    cred: String,
    dev: Device,
    handle: Handle,
    token: String,
}

async fn world() -> World {
    let app = TestApp::new().await;
    let cred = app.new_instance().await;
    let token = token(0x11);
    let dev = app.new_device(&token).await;
    let handle = app.new_handle(&dev).await;
    World {
        app,
        cred,
        dev,
        handle,
        token,
    }
}

impl World {
    async fn sync(&self) -> String {
        let r = self
            .app
            .push(&self.cred, &[&self.handle.secret], "sync")
            .await;
        assert_eq!(r.status, 200, "{}", r.json);
        TestApp::status_of(&r, 0)
    }
}

#[tokio::test]
async fn unregistered_deletes_the_device_when_apples_timestamp_is_newer() {
    let w = world().await;
    let ts = w.app.clock.now_ms() + 1_000;
    w.app.mock.script(&w.token, vec![Reply::unregistered(ts)]);
    assert_eq!(w.sync().await, "gone");
    assert!(!w.app.device_exists(&w.dev.id).await);
    // Its handles went with it, and the app is told on its next call.
    assert_eq!(w.sync().await, "gone");
    let r = w
        .app
        .call(
            "PUT",
            &format!("/v1/devices/{}", w.dev.id),
            Some(&w.dev.key),
            Some(json!({})),
        )
        .await;
    assert_eq!(r.status, 404);
}

#[tokio::test]
async fn an_old_unregistered_answer_does_not_delete_a_newer_token() {
    let w = world().await;
    let ts = w.app.clock.now_ms() - 60_000;
    w.app.mock.script(&w.token, vec![Reply::unregistered(ts)]);
    assert_eq!(w.sync().await, "gone");
    assert!(
        w.app.device_exists(&w.dev.id).await,
        "the token was registered after Apple's timestamp"
    );
    assert_eq!(w.sync().await, "accepted");
}

#[tokio::test]
async fn unregistered_without_a_timestamp_deletes() {
    let w = world().await;
    w.app.mock.script(
        &w.token,
        vec![Reply {
            status: 410,
            body: Some(json!({ "reason": "Unregistered" })),
            headers: vec![],
        }],
    );
    assert_eq!(w.sync().await, "gone");
    assert!(!w.app.device_exists(&w.dev.id).await);
}

#[tokio::test]
async fn three_bad_token_strikes_in_a_row_delete_the_device() {
    let w = world().await;
    w.app.mock.script(
        &w.token,
        vec![
            Reply::reason(400, "BadDeviceToken"),
            Reply::reason(400, "DeviceTokenNotForTopic"),
            Reply::reason(400, "BadDeviceToken"),
        ],
    );
    assert_eq!(w.sync().await, "unavailable");
    assert_eq!(w.sync().await, "unavailable");
    assert!(w.app.device_exists(&w.dev.id).await);
    assert_eq!(w.sync().await, "gone");
    assert!(!w.app.device_exists(&w.dev.id).await);
}

#[tokio::test]
async fn a_success_clears_the_strikes() {
    let w = world().await;
    w.app.mock.script(
        &w.token,
        vec![
            Reply::reason(400, "BadDeviceToken"),
            Reply::status(200),
            Reply::reason(400, "BadDeviceToken"),
            Reply::reason(400, "BadDeviceToken"),
        ],
    );
    assert_eq!(w.sync().await, "unavailable");
    assert_eq!(w.sync().await, "accepted");
    assert_eq!(w.sync().await, "unavailable");
    assert_eq!(w.sync().await, "unavailable");
    assert!(w.app.device_exists(&w.dev.id).await);
}

#[tokio::test]
async fn operator_problems_never_delete_anything() {
    let w = world().await;
    for reason in [
        "InvalidProviderToken",
        "MissingProviderToken",
        "BadCertificate",
        "Forbidden",
    ] {
        w.app
            .mock
            .script(&w.token, vec![Reply::reason(403, reason)]);
        assert_eq!(w.sync().await, "unavailable", "{reason}");
        assert!(w.app.device_exists(&w.dev.id).await, "{reason}");
    }
    assert_eq!(w.app.get("/v1/status").await.json["apns"], "degraded");
    assert_eq!(w.sync().await, "accepted");
    assert_eq!(w.app.get("/v1/status").await.json["apns"], "ok");
}

#[tokio::test]
async fn expired_provider_token_is_renewed_once_if_the_rule_allows() {
    let w = world().await;
    assert_eq!(w.sync().await, "accepted");
    let first = w.app.mock.last().header("authorization").to_string();

    // Apple says the token expired, but it is only 5 minutes old: Apple would
    // refuse a new one (TooManyProviderTokenUpdates), so the push fails.
    w.app.clock.advance_secs(5 * 60);
    w.app
        .mock
        .script(&w.token, vec![Reply::reason(403, "ExpiredProviderToken")]);
    assert_eq!(w.sync().await, "unavailable");
    assert!(w.app.device_exists(&w.dev.id).await);

    // At 25 minutes a new token is allowed, and the push is retried once.
    w.app.clock.advance_secs(20 * 60);
    w.app.mock.script(
        &w.token,
        vec![
            Reply::reason(403, "ExpiredProviderToken"),
            Reply::status(200),
        ],
    );
    let before = w.app.mock.count();
    assert_eq!(w.sync().await, "accepted");
    let sent = w.app.mock.requests();
    assert_eq!(sent.len(), before + 2);
    let (a, b) = (&sent[before], &sent[before + 1]);
    assert_eq!(a.header("authorization"), first);
    assert_ne!(
        b.header("authorization"),
        first,
        "the retry carries a new token"
    );
}

#[tokio::test]
async fn too_many_requests_backs_off_that_device() {
    let w = world().await;
    w.app.mock.script(
        &w.token,
        vec![Reply {
            status: 429,
            body: Some(json!({ "reason": "TooManyRequests" })),
            headers: vec![("retry-after", "30".into())],
        }],
    );
    let r = w.app.push(&w.cred, &[&w.handle.secret], "sync").await;
    assert_eq!(TestApp::status_of(&r, 0), "limited");
    assert_eq!(r.json["results"][0]["retry_after"], 30);
    let count = w.app.mock.count();

    // Honoured: nothing more goes to Apple for this device meanwhile.
    assert_eq!(w.sync().await, "limited");
    assert_eq!(w.app.mock.count(), count);

    w.app.clock.advance_secs(31);
    assert_eq!(w.sync().await, "accepted");
}

#[tokio::test]
async fn server_errors_are_retried_once() {
    let w = world().await;
    w.app
        .mock
        .script(&w.token, vec![Reply::status(500), Reply::status(503)]);
    assert_eq!(w.sync().await, "unavailable");
    assert_eq!(w.app.mock.count(), 2);

    w.app
        .mock
        .script(&w.token, vec![Reply::status(500), Reply::status(200)]);
    assert_eq!(w.sync().await, "accepted");
    assert_eq!(w.app.mock.count(), 4);
    assert!(w.app.device_exists(&w.dev.id).await);
}

#[tokio::test]
async fn unexpected_answers_are_unavailable_and_delete_nothing() {
    let w = world().await;
    for reply in [
        Reply::reason(413, "PayloadTooLarge"),
        Reply::reason(400, "PayloadEmpty"),
    ] {
        w.app.mock.script(&w.token, vec![reply]);
        assert_eq!(w.sync().await, "unavailable");
    }
    assert!(w.app.device_exists(&w.dev.id).await);
}

#[tokio::test]
async fn repeated_failures_open_a_circuit_breaker_for_30_seconds() {
    let w = world().await;
    let handles = {
        let mut v = vec![];
        for _ in 0..8 {
            v.push(w.app.new_handle(&w.dev).await);
        }
        v
    };
    w.app
        .mock
        .script(&w.token, (0..10).map(|_| Reply::status(503)).collect());
    for h in &handles[..5] {
        let r = w.app.push(&w.cred, &[&h.secret], "sync").await;
        assert_eq!(TestApp::status_of(&r, 0), "unavailable");
    }
    assert_eq!(w.app.mock.count(), 10, "each failed push was tried twice");
    assert_eq!(w.app.get("/v1/status").await.json["apns"], "degraded");

    // Open: the next push fails at once without calling Apple.
    let r = w.app.push(&w.cred, &[&handles[5].secret], "sync").await;
    assert_eq!(TestApp::status_of(&r, 0), "unavailable");
    assert_eq!(w.app.mock.count(), 10);

    w.app.clock.advance_secs(31);
    let r = w.app.push(&w.cred, &[&handles[6].secret], "sync").await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted");
    assert_eq!(w.app.mock.count(), 11);
    assert_eq!(w.app.get("/v1/status").await.json["apns"], "ok");
}

#[tokio::test]
async fn the_provider_token_is_signed_cached_and_refreshed() {
    let w = world().await;
    assert_eq!(w.app.get("/v1/status").await.json["apns"], "unknown");
    assert_eq!(w.sync().await, "accepted");
    assert_eq!(w.sync().await, "accepted");
    let sent = w.app.mock.requests();
    let (a, b) = (
        sent[0].header("authorization"),
        sent[1].header("authorization"),
    );
    assert_eq!(a, b, "the same token is reused");

    let (header, claims, whole) = decode_jwt(a);
    assert_eq!(header, json!({ "alg": "ES256", "kid": KEY_ID }));
    assert_eq!(claims["iss"], TEAM_ID);
    let iat = claims["iat"].as_i64().unwrap();
    assert!((iat - w.app.clock.now_secs()).abs() <= 2);
    assert!(
        jwt_signature_ok(&w.app.public_key, &whole),
        "ES256 signature checks out"
    );

    // Still the same after 39 minutes, new after 41.
    w.app.clock.advance_secs(39 * 60);
    w.sync().await;
    assert_eq!(w.app.mock.last().header("authorization"), a);
    w.app.clock.advance_secs(2 * 60);
    w.sync().await;
    let c = w.app.mock.last().header("authorization").to_string();
    assert_ne!(c, a);
    let (_, claims2, whole2) = decode_jwt(&c);
    assert!(claims2["iat"].as_i64().unwrap() >= iat + 40 * 60);
    assert!(jwt_signature_ok(&w.app.public_key, &whole2));
}

#[tokio::test]
async fn http2_is_used_toward_apple() {
    // The mock only speaks HTTP/2 cleartext; a push that arrives proves it.
    let w = world().await;
    assert_eq!(w.sync().await, "accepted");
    assert_eq!(w.app.mock.count(), 1);
}
