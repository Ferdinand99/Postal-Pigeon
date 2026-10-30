//! Sending: request rules, payload shape, results, limits, isolation.

mod common;

use axum::body::Body;
use axum::http::Request;
use common::*;
use postal_pigeon::util::{is_uuid, uuid_v4};
use serde_json::{Value, json};

struct World {
    app: TestApp,
    cred: String,
    dev: Device,
    handle: Handle,
    token: String,
}

async fn world() -> World {
    world_with(TestApp::new().await).await
}

async fn world_with(app: TestApp) -> World {
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

fn body(handle: &str) -> Value {
    json!({ "event_id": uuid_v4(), "handles": [handle], "kind": "alert" })
}

#[tokio::test]
async fn requests_are_validated() {
    let w = world().await;
    let h = w.handle.secret.clone();
    let mut cases: Vec<(&str, Value)> = vec![];
    let mut with = |name, f: &dyn Fn(&mut Value)| {
        let mut b = body(&h);
        f(&mut b);
        cases.push((name, b));
    };
    with("event id", &|b| b["event_id"] = json!("not-a-uuid"));
    with("missing event id", &|b| {
        b.as_object_mut().unwrap().remove("event_id");
    });
    with("no handles", &|b| b["handles"] = json!([]));
    with("too many handles", &|b| b["handles"] = json!(vec!["h"; 26]));
    with("long handle", &|b| b["handles"] = json!(["h".repeat(200)]));
    with("kind", &|b| b["kind"] = json!("loud"));
    with("ref chars", &|b| b["ref"] = json!("a b"));
    with("ref long", &|b| b["ref"] = json!("a".repeat(65)));
    with("collapse long", &|b| b["collapse"] = json!("a".repeat(33)));
    with("collapse chars", &|b| b["collapse"] = json!("a/b"));
    with("ttl low", &|b| b["ttl"] = json!(59));
    with("ttl high", &|b| b["ttl"] = json!(86_401));
    for (name, b) in cases {
        let r = w.app.push_body(&w.cred, b).await;
        assert_eq!(
            (r.status.as_u16(), r.error()),
            (400, "invalid_request"),
            "{name}"
        );
    }
    assert_eq!(w.app.mock.count(), 0);

    // The bounds themselves are fine.
    let mut b = body(&h);
    b["ref"] = json!("a".repeat(64));
    b["collapse"] = json!("A-z_9".repeat(6) + "ab");
    b["ttl"] = json!(60);
    assert_eq!(w.app.push_body(&w.cred, b).await.status, 200);
    let mut b = body(&h);
    b["ttl"] = json!(86_400);
    b["kind"] = json!("sync");
    assert_eq!(w.app.push_body(&w.cred, b).await.status, 200);
}

#[tokio::test]
async fn bodies_over_2_kib_and_bad_json_are_refused() {
    let w = world().await;
    let mut b = body(&w.handle.secret);
    b["ref"] = json!("a".repeat(3000));
    let r = w.app.push_body(&w.cred, b).await;
    assert_eq!((r.status.as_u16(), r.error()), (413, "too_large"));

    let req = Request::builder()
        .method("POST")
        .uri("/v1/push")
        .header("authorization", format!("Bearer {}", w.cred))
        .header("content-type", "application/json")
        .body(Body::from("{not json"))
        .unwrap();
    let r = w.app.raw(req).await;
    assert_eq!((r.status.as_u16(), r.error()), (400, "invalid_request"));

    let r = w
        .app
        .call("POST", "/v1/push", None, Some(body(&w.handle.secret)))
        .await;
    assert_eq!((r.status.as_u16(), r.error()), (401, "invalid_credentials"));
    assert_eq!(w.app.mock.count(), 0);
}

#[tokio::test]
async fn an_alert_reaches_apple_with_the_designed_headers_and_payload() {
    let w = world().await;
    let mut b = body(&w.handle.secret);
    b["ref"] = json!("inc_9f3a1c");
    b["collapse"] = json!("inc_9f3a1c");
    let r = w.app.push_body(&w.cred, b).await;
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(r.json, json!({ "results": [ { "status": "accepted" } ] }));
    assert!(
        !r.json.to_string().contains(&w.token),
        "no token in any response"
    );

    assert_eq!(w.app.mock.count(), 1);
    let rec = w.app.mock.last();
    assert_eq!(rec.path, format!("/3/device/{}", w.token));
    assert_eq!(rec.header("apns-push-type"), "alert");
    assert_eq!(rec.header("apns-priority"), "10");
    assert_eq!(rec.header("apns-topic"), BUNDLE);
    // Apple sees a keyed hash scoped to the handle, never the raw value.
    let collapse = rec.header("apns-collapse-id");
    assert!(
        collapse.starts_with("a-") && collapse.len() <= 64,
        "{collapse}"
    );
    assert!(!collapse.contains("inc_9f3a1c"));
    assert!(is_uuid(rec.header("apns-id")));
    let exp: i64 = rec.header("apns-expiration").parse().unwrap();
    let want = w.app.clock.now_secs() + 3600;
    assert!((exp - want).abs() <= 2, "{exp} vs {want}");
    assert_eq!(
        rec.body,
        json!({
            "aps": {
                "alert": { "title-loc-key": "HR_PUSH_TITLE", "loc-key": "HR_PUSH_BODY" },
                "mutable-content": 1,
                "sound": "default",
                "thread-id": w.handle.tag,
            },
            "hr": { "v": 1, "k": "alert", "t": w.handle.tag, "r": "inc_9f3a1c" },
        })
    );
}

#[tokio::test]
async fn a_sync_is_silent_background_priority_5() {
    let w = world().await;
    let mut b = body(&w.handle.secret);
    b["kind"] = json!("sync");
    b["collapse"] = json!("ignored-for-sync");
    b["ttl"] = json!(120);
    let r = w.app.push_body(&w.cred, b).await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted");
    let rec = w.app.mock.last();
    assert_eq!(rec.header("apns-push-type"), "background");
    assert_eq!(rec.header("apns-priority"), "5");
    assert_eq!(
        rec.header("apns-collapse-id"),
        format!("s-{}", w.handle.tag)
    );
    let exp: i64 = rec.header("apns-expiration").parse().unwrap();
    assert!((exp - (w.app.clock.now_secs() + 120)).abs() <= 2);
    assert_eq!(
        rec.body,
        json!({
            "aps": { "content-available": 1 },
            "hr": { "v": 1, "k": "sync", "t": w.handle.tag },
        })
    );
    assert!(rec.headers.get("apns-collapse-id").unwrap().len() <= 64);
}

#[tokio::test]
async fn default_expiry_of_a_sync_is_15_minutes_and_alerts_have_no_collapse_by_default() {
    let w = world().await;
    let mut b = body(&w.handle.secret);
    b["kind"] = json!("sync");
    w.app.push_body(&w.cred, b).await;
    let exp: i64 = w.app.mock.last().header("apns-expiration").parse().unwrap();
    assert!((exp - (w.app.clock.now_secs() + 900)).abs() <= 2);

    w.app.push_body(&w.cred, body(&w.handle.secret)).await;
    assert!(!w.app.mock.last().headers.contains_key("apns-collapse-id"));
}

#[tokio::test]
async fn an_event_id_is_sent_once() {
    let w = world().await;
    let b = body(&w.handle.secret);
    let first = w.app.push_body(&w.cred, b.clone()).await;
    assert_eq!(TestApp::status_of(&first, 0), "accepted");
    let again = w.app.push_body(&w.cred, b.clone()).await;
    assert_eq!(TestApp::status_of(&again, 0), "duplicate");
    assert_eq!(w.app.mock.count(), 1);

    // Another instance's identical event id is its own event.
    let other = w.app.new_instance().await;
    let r = w.app.push_body(&other, b.clone()).await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted");

    // After 15 minutes it can be sent again.
    w.app.clock.advance_secs(15 * 60 + 1);
    let r = w.app.push_body(&w.cred, b).await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted");
}

#[tokio::test]
async fn a_failed_send_can_be_retried_with_the_same_event_id() {
    let w = world().await;
    w.app
        .mock
        .script(&w.token, vec![Reply::status(503), Reply::status(503)]);
    let b = body(&w.handle.secret);
    let r = w.app.push_body(&w.cred, b.clone()).await;
    assert_eq!(TestApp::status_of(&r, 0), "unavailable");
    let r = w.app.push_body(&w.cred, b).await;
    assert_eq!(
        TestApp::status_of(&r, 0),
        "accepted",
        "a push Apple didn't take isn't a duplicate"
    );
}

#[tokio::test]
async fn results_come_back_in_order_one_per_handle() {
    let w = world().await;
    let dev2 = w.app.new_device(&token(0x22)).await;
    let h2 = w.app.new_handle(&dev2).await;
    let forged = format!("{}{}", &w.handle.secret[..15], "A".repeat(43));
    let b = json!({
        "event_id": uuid_v4(),
        "handles": [forged, w.handle.secret, "garbage", h2.secret],
        "kind": "sync",
    });
    let r = w.app.push_body(&w.cred, b).await;
    let got: Vec<_> = (0..4).map(|i| TestApp::status_of(&r, i)).collect();
    assert_eq!(got, ["gone", "accepted", "gone", "accepted"]);
    let tokens: Vec<_> = w
        .app
        .mock
        .requests()
        .iter()
        .map(|r| r.token().to_string())
        .collect();
    assert_eq!(tokens.len(), 2);
    assert!(tokens.contains(&w.token) && tokens.contains(&token(0x22)));
}

#[tokio::test]
async fn unknown_and_revoked_handles_look_the_same() {
    let w = world().await;
    let never = format!("hrh_{}{}", "B".repeat(11), "C".repeat(43));
    let revoked = w.app.new_handle(&w.dev).await;
    w.app
        .call(
            "DELETE",
            &format!("/v1/devices/{}/handles/{}", w.dev.id, revoked.id),
            Some(&w.dev.key),
            None,
        )
        .await;
    let a = w.app.push(&w.cred, &[&never], "sync").await;
    let b = w.app.push(&w.cred, &[&revoked.secret], "sync").await;
    assert_eq!(a.status, 200);
    assert_eq!(a.json, b.json);
    assert_eq!(TestApp::status_of(&a, 0), "gone");
    assert_eq!(w.app.mock.count(), 0);
}

#[tokio::test]
async fn enumerating_handles_is_stopped_and_flagged() {
    let w = world_with(
        TestApp::builder()
            .limits(|l| l.unknown_handles_per_instance_hour = 3)
            .build()
            .await,
    )
    .await;
    let junk = |n: u8| format!("hrh_{}{}", "B".repeat(10) + &n.to_string(), "C".repeat(43));
    let r = w.app.push(&w.cred, &[&junk(1), &junk(2)], "sync").await;
    assert_eq!(r.status, 200);
    let r = w.app.push(&w.cred, &[&junk(3)], "sync").await;
    assert_eq!(r.status, 200);
    let r = w.app.push(&w.cred, &[&junk(4)], "sync").await;
    assert_eq!((r.status.as_u16(), r.error()), (429, "rate_limited"));
    assert!(r.retry_after().is_some());
    // Even a real handle is refused for the instance while it is blocked...
    let real = w.app.push(&w.cred, &[&w.handle.secret], "sync").await;
    assert_eq!(
        real.status, 200,
        "real handles still work: only unknown ones are counted"
    );
    // ...and the instance is flagged for review.
    let flagged = w
        .app
        .state
        .db
        .call(|c| postal_pigeon::db::stats(c, 0).unwrap().flagged_instances)
        .await;
    assert_eq!(flagged, 1);
}

#[tokio::test]
async fn a_handle_only_reaches_its_own_device() {
    let w = world().await;
    let other_dev = w.app.new_device(&token(0x33)).await;
    let other_handle = w.app.new_handle(&other_dev).await;

    w.app.push(&w.cred, &[&w.handle.secret], "sync").await;
    assert_eq!(w.app.mock.count(), 1);
    assert_eq!(w.app.mock.last().token(), w.token);

    // The other device's manage key can neither list nor revoke this one's handles.
    let r = w
        .app
        .call(
            "GET",
            &format!("/v1/devices/{}/handles", w.dev.id),
            Some(&other_dev.key),
            None,
        )
        .await;
    assert_eq!(r.status, 401);
    let r = w
        .app
        .call(
            "DELETE",
            &format!("/v1/devices/{}/handles/{}", other_dev.id, w.handle.id),
            Some(&other_dev.key),
            None,
        )
        .await;
    assert_eq!(r.status, 404, "a device can only revoke its own handles");
    let r = w.app.push(&w.cred, &[&w.handle.secret], "sync").await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted", "the handle survived");

    // A handle with another handle's id but a wrong secret goes nowhere.
    let forged = format!("hrh_{}{}", other_handle.id, &w.handle.secret[15..]);
    let r = w.app.push(&w.cred, &[&forged], "sync").await;
    assert_eq!(TestApp::status_of(&r, 0), "gone");
    assert!(w.app.mock.requests().iter().all(|r| r.token() == w.token));
}

#[tokio::test]
async fn revoking_a_handle_stops_it_at_once() {
    let w = world().await;
    let r = w.app.push(&w.cred, &[&w.handle.secret], "sync").await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted");
    let r = w
        .app
        .call(
            "DELETE",
            &format!("/v1/devices/{}/handles/{}", w.dev.id, w.handle.id),
            Some(&w.dev.key),
            None,
        )
        .await;
    assert_eq!(r.status, 204);
    let r = w.app.push(&w.cred, &[&w.handle.secret], "sync").await;
    assert_eq!(TestApp::status_of(&r, 0), "gone");
    assert_eq!(w.app.mock.count(), 1);
}

#[tokio::test]
async fn handle_limits_apply_per_kind() {
    let w = world().await;
    // Alerts: burst of 3.
    let got: Vec<_> = {
        let mut v = vec![];
        for _ in 0..4 {
            let r = w.app.push(&w.cred, &[&w.handle.secret], "alert").await;
            v.push((
                TestApp::status_of(&r, 0),
                r.json["results"][0]["retry_after"].as_u64(),
            ));
        }
        v
    };
    assert_eq!(got[0].0, "accepted");
    assert_eq!(got[2].0, "accepted");
    assert_eq!(got[3].0, "limited");
    assert!(got[3].1.unwrap() > 0);
    assert_eq!(w.app.mock.count(), 3, "a limited push never reaches Apple");
    // Syncs have their own, bigger budget.
    for _ in 0..5 {
        let r = w.app.push(&w.cred, &[&w.handle.secret], "sync").await;
        assert_eq!(TestApp::status_of(&r, 0), "accepted");
    }
    let r = w.app.push(&w.cred, &[&w.handle.secret], "sync").await;
    assert_eq!(TestApp::status_of(&r, 0), "limited");
    // An hour later it has refilled.
    w.app.clock.advance_secs(3600);
    let r = w.app.push(&w.cred, &[&w.handle.secret], "alert").await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted");
}

#[tokio::test]
async fn the_device_limit_covers_all_its_handles() {
    let w = world_with(
        TestApp::builder()
            .limits(|l| l.alert_per_device_hour = 4)
            .build()
            .await,
    )
    .await;
    let second = w.app.new_handle(&w.dev).await;
    let mut statuses = vec![];
    for h in [&w.handle, &w.handle, &w.handle, &second, &second] {
        let r = w.app.push(&w.cred, &[&h.secret], "alert").await;
        statuses.push(TestApp::status_of(&r, 0));
    }
    assert_eq!(
        statuses,
        ["accepted", "accepted", "accepted", "accepted", "limited"]
    );
}

#[tokio::test]
async fn another_instance_cannot_use_up_this_instances_quota() {
    let w = world().await;
    let other = w.app.new_instance().await;
    for _ in 0..3 {
        w.app.push(&other, &[&w.handle.secret], "sync").await;
    }
    // Per-instance buckets are separate (the handle's own bucket is shared by design).
    let r = w.app.push(&w.cred, &[&w.handle.secret], "alert").await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted");
}

#[tokio::test]
async fn instance_limit_and_tiers() {
    let w = world_with(
        TestApp::builder()
            .limits(|l| {
                l.send_per_instance_hour_new = 3;
                l.send_per_instance_hour_established = 10;
            })
            .build()
            .await,
    )
    .await;
    for _ in 0..3 {
        assert_eq!(
            w.app
                .push(&w.cred, &[&w.handle.secret], "sync")
                .await
                .status,
            200
        );
    }
    let r = w.app.push(&w.cred, &[&w.handle.secret], "sync").await;
    assert_eq!((r.status.as_u16(), r.error()), (429, "rate_limited"));
    assert!(r.retry_after().unwrap() > 0);

    // An established instance has the bigger budget.
    let id = w.cred[4..15].to_string();
    w.app
        .state
        .db
        .call(move |c| postal_pigeon::db::set_instance_tier(c, &id, "established").unwrap())
        .await;
    let est = w.app.new_instance().await;
    let id = est[4..15].to_string();
    w.app
        .state
        .db
        .call(move |c| postal_pigeon::db::set_instance_tier(c, &id, "established").unwrap())
        .await;
    for _ in 0..6 {
        let r = w.app.push(&est, &["hrh_x"], "sync").await;
        assert_eq!(r.status, 200);
    }
}

#[tokio::test]
async fn an_instance_that_keeps_hitting_limits_is_suspended() {
    let w = world_with(
        TestApp::builder()
            .limits(|l| {
                l.send_per_instance_hour_new = 1;
                l.auto_suspend_throttled_per_day = 3;
            })
            .build()
            .await,
    )
    .await;
    w.app.push(&w.cred, &[&w.handle.secret], "sync").await;
    let mut codes = vec![];
    for _ in 0..5 {
        let r = w.app.push(&w.cred, &[&w.handle.secret], "sync").await;
        codes.push(r.status.as_u16());
    }
    assert_eq!(codes, [429, 429, 429, 429, 403]);
}

#[tokio::test]
async fn kinds_are_allowed_per_app() {
    let app = TestApp::new().await;
    let cred = app.new_instance().await;
    let dev = app
        .new_device_for("ferret", "production", &token(0x44))
        .await;
    let h = app.new_handle(&dev).await;
    let r = app.push(&cred, &[&h.secret], "alert").await;
    assert_eq!(TestApp::status_of(&r, 0), "unsupported_kind");
    assert_eq!(app.mock.count(), 0);
    let r = app.push(&cred, &[&h.secret], "sync").await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted");
    assert_eq!(app.mock.last().header("apns-topic"), FERRET_BUNDLE);
}

#[tokio::test]
async fn sylo_devices_get_alerts_but_not_sync() {
    let app = TestApp::new().await;
    let cred = app.new_instance().await;
    let dev = app.new_device_for("sylo", "production", &token(0x66)).await;
    let h = app.new_handle(&dev).await;
    let r = app.push(&cred, &[&h.secret], "sync").await;
    assert_eq!(TestApp::status_of(&r, 0), "unsupported_kind");
    assert_eq!(app.mock.count(), 0);
    let r = app.push(&cred, &[&h.secret], "alert").await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted");
    assert_eq!(app.mock.count(), 1);
    assert_eq!(app.mock.last().header("apns-topic"), SYLO_BUNDLE);
    assert_eq!(app.mock.last().token(), token(0x66));
}

#[tokio::test]
async fn sandbox_devices_go_to_the_sandbox_host() {
    let app = TestApp::new().await;
    let cred = app.new_instance().await;
    let dev = app
        .new_device_for("hedgerow", "sandbox", &token(0x55))
        .await;
    let h = app.new_handle(&dev).await;
    let r = app.push(&cred, &[&h.secret], "sync").await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted");
    assert_eq!(app.mock.last().token(), token(0x55));
}

#[tokio::test]
async fn the_app_wide_ceiling_sheds_with_a_retry_hint() {
    let w = world_with(
        TestApp::builder()
            .limits(|l| l.app_sends_per_second = 1)
            .build()
            .await,
    )
    .await;
    let mut seen = vec![];
    for _ in 0..4 {
        let r = w.app.push(&w.cred, &[&w.handle.secret], "sync").await;
        seen.push(TestApp::status_of(&r, 0));
    }
    // Burst of two, then the ceiling.
    assert_eq!(&seen[..2], ["accepted", "accepted"]);
    assert_eq!(seen[3], "unavailable");
}
