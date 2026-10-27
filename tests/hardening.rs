//! Findings of the October security review: address handling, registration
//! pressure, Apple's relay-wide answers, deduplication.

mod common;

use axum::body::Body;
use axum::http::Request;
use common::*;
use postal_pigeon::admin::{self, AdminCommand};
use postal_pigeon::apns::{Apns, Outcome, PushRequest};
use postal_pigeon::config::{Env, Kind};
use postal_pigeon::util::uuid_v4;
use serde_json::{Value, json};

struct World {
    app: TestApp,
    cred: String,
    dev: Device,
    handle: Handle,
    token: String,
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

async fn world() -> World {
    world_with(TestApp::new().await).await
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

fn register_request(body: &Value, xff_lines: &[&str]) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/v1/instances")
        .header("content-type", "application/json");
    for line in xff_lines {
        b = b.header("x-forwarded-for", *line);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

// ---- PP-01, PP-02: addresses behind a proxy ------------------------------

#[tokio::test]
async fn an_untrusted_peer_sending_forwarded_for_is_logged_once() {
    let (buf, _guard) = capture_logs(postal_pigeon::logging::filter(Some("info")));
    let app = TestApp::builder().proxies(&["10.0.0.1"]).build().await;
    for _ in 0..3 {
        let r = app
            .call_from(
                "198.51.100.7",
                "GET",
                "/v1/challenge",
                None,
                None,
                Some("192.0.2.1"),
            )
            .await;
        assert_eq!(r.status, 200);
    }
    // The trusted proxy itself sending it is normal.
    app.call_from(
        "10.0.0.1",
        "GET",
        "/v1/challenge",
        None,
        None,
        Some("192.0.2.1"),
    )
    .await;
    let logs = buf.text();
    assert_eq!(
        logs.matches("PP_TRUSTED_PROXIES").count(),
        1,
        "once, however often it happens:\n{logs}"
    );
    assert!(
        !logs.contains("198.51.100.7") && !logs.contains("192.0.2.1"),
        "no addresses"
    );
}

#[tokio::test]
async fn every_forwarded_for_line_counts_and_the_proxys_is_the_last() {
    let app = TestApp::builder().proxies(&["10.0.0.1"]).build().await;
    // The proxy appends the real client as the last entry of the last line; a
    // client can only add lines before it. Spoofing the first line changes nothing.
    let mut last = 0;
    for i in 1..=6 {
        let (c, d) = app.challenge_from("10.0.0.1").await;
        let spoof = format!("1.1.1.{i}");
        let r = app
            .raw_from(
                "10.0.0.1",
                register_request(&app.registration(&c, d), &[&spoof, "192.0.2.50"]),
            )
            .await;
        last = r.status.as_u16();
        if i <= 5 {
            assert_eq!(last, 201, "{}", r.json);
        }
    }
    assert_eq!(last, 429, "one real client, however many spoofed lines");
    // A different real client behind the same proxy has its own budget.
    let (c, d) = app.challenge_from("10.0.0.1").await;
    let r = app
        .raw_from(
            "10.0.0.1",
            register_request(&app.registration(&c, d), &["1.1.1.1", "192.0.2.51"]),
        )
        .await;
    assert_eq!(r.status, 201, "{}", r.json);
}

// ---- PP-03, PP-04: registration pressure ---------------------------------

#[tokio::test]
async fn a_network_has_a_budget_and_the_proof_of_work_rises_with_volume() {
    let app = TestApp::builder()
        .limits(|l| {
            l.instance_reg_per_prefix_day = 4;
            l.pow_adaptive_threshold_per_hour = 2;
            l.pow_adaptive_max_extra_bits = 3;
        })
        .build()
        .await;
    let mut difficulties = vec![];
    for i in 1..=4 {
        let ip = format!("198.51.100.{i}");
        let (c, d) = app.challenge_from(&ip).await;
        difficulties.push(d);
        let r = app
            .call_from(
                &ip,
                "POST",
                "/v1/instances",
                None,
                Some(app.registration(&c, d)),
                None,
            )
            .await;
        assert_eq!(r.status, 201, "{}", r.json);
    }
    // 4 base bits, one more at 2 registrations an hour, another at 4.
    assert_eq!(difficulties, [4, 4, 5, 5]);
    let (_, d) = app.challenge_from("198.51.101.1").await;
    assert_eq!(d, 6);

    // Four different addresses of one /24 used the network's budget...
    let r = app
        .call_from("198.51.100.99", "GET", "/v1/challenge", None, None, None)
        .await;
    assert_eq!((r.status.as_u16(), r.error()), (429, "rate_limited"));
    // ...another network has its own.
    app.challenge_from("198.51.102.1").await;
}

#[tokio::test]
async fn the_difficulty_is_fixed_when_the_challenge_is_issued() {
    let app = TestApp::builder()
        .limits(|l| {
            l.pow_adaptive_threshold_per_hour = 1;
            l.pow_adaptive_max_extra_bits = 4;
        })
        .build()
        .await;
    let (early, early_d) = app.challenge_from("198.51.100.1").await;
    assert_eq!(early_d, 4);
    for i in 1..=3 {
        let ip = format!("198.51.101.{i}");
        let (c, d) = app.challenge_from(&ip).await;
        let r = app
            .call_from(
                &ip,
                "POST",
                "/v1/instances",
                None,
                Some(app.registration(&c, d)),
                None,
            )
            .await;
        assert_eq!(r.status, 201);
    }
    assert!(app.state.current_difficulty() > early_d);
    // A challenge issued before the rise is still honoured at its own difficulty.
    let r = app
        .call_from(
            "198.51.100.1",
            "POST",
            "/v1/instances",
            None,
            Some(app.registration(&early, early_d)),
            None,
        )
        .await;
    assert_eq!(r.status, 201, "{}", r.json);
}

// ---- PP-05: devices ------------------------------------------------------

#[tokio::test]
async fn device_registration_has_a_network_bucket_too() {
    let app = TestApp::builder()
        .limits(|l| l.device_reg_per_prefix_hour = 3)
        .build()
        .await;
    let mut codes = vec![];
    for i in 1..=4u8 {
        let r = app
            .call_from(
                &format!("198.51.100.{i}"),
                "POST",
                "/v1/devices",
                None,
                Some(json!({ "app": "hedgerow", "environment": "production", "token": token(i) })),
                None,
            )
            .await;
        codes.push(r.status.as_u16());
    }
    assert_eq!(codes, [201, 201, 201, 429]);
    let r = app
        .call_from(
            "198.51.101.1",
            "POST",
            "/v1/devices",
            None,
            Some(json!({ "app": "hedgerow", "environment": "production", "token": token(9) })),
            None,
        )
        .await;
    assert_eq!(r.status, 201, "another network");
}

#[tokio::test]
async fn registering_a_known_token_works_even_when_the_table_is_full() {
    let app = TestApp::builder()
        .limits(|l| l.max_devices = 2)
        .build()
        .await;
    let first = app.new_device(&token(1)).await;
    app.new_device(&token(2)).await;
    // A reinstall of a known device replaces its row; it is not a new one.
    let again = app.new_device(&token(1)).await;
    assert_ne!(first.id, again.id);
    // A third token really is one more.
    let ip = app.next_ip();
    let r = app
        .call_from(
            &ip,
            "POST",
            "/v1/devices",
            None,
            Some(json!({ "app": "hedgerow", "environment": "production", "token": token(3) })),
            None,
        )
        .await;
    assert_eq!((r.status.as_u16(), r.error()), (503, "overloaded"));
}

// ---- PP-06: unverified devices -------------------------------------------

#[tokio::test]
async fn a_device_apple_never_accepted_gets_a_small_quota_until_one_succeeds() {
    let w = world_with(
        TestApp::builder()
            .limits(|l| l.unverified_device_per_hour = 2)
            .build()
            .await,
    )
    .await;
    w.app.mock.script(
        &w.token,
        vec![
            Reply::reason(400, "BadDeviceToken"),
            Reply::reason(400, "BadDeviceToken"),
        ],
    );
    assert_eq!(w.sync().await, "unavailable");
    assert_eq!(w.sync().await, "unavailable");
    assert_eq!(w.sync().await, "limited");
    assert_eq!(w.app.mock.count(), 2, "the third never reached Apple");

    // An hour later one is tried, Apple takes it, and the quota ends.
    w.app.clock.advance_secs(3600);
    assert_eq!(w.sync().await, "accepted");
    for _ in 0..3 {
        assert_eq!(w.sync().await, "accepted");
    }
}

// ---- PP-07, PP-08: Apple's answers about the relay itself -----------------

/// Registers `n` devices with a handle each. With `verified`, one push to each
/// is accepted first, so Apple has taken a push for them.
async fn devices(app: &TestApp, n: u8, verified: bool, creds: &[String]) -> Vec<(Device, Handle)> {
    let mut out = vec![];
    for i in 1..=n {
        let t = token(i);
        let dev = app.new_device(&t).await;
        let h = app.new_handle(&dev).await;
        if verified {
            let r = app
                .push(&creds[i as usize % creds.len()], &[&h.secret], "sync")
                .await;
            assert_eq!(TestApp::status_of(&r, 0), "accepted");
        }
        app.mock.script(
            &t,
            (0..3)
                .map(|_| Reply::reason(400, "BadDeviceToken"))
                .collect(),
        );
        out.push((dev, h));
    }
    out
}

/// Three rounds of pushes to every device, from rotating instances.
async fn rounds(app: &TestApp, devices: &[(Device, Handle)], creds: &[String]) {
    for round in 0..3 {
        for (k, (_, h)) in devices.iter().enumerate() {
            let cred = &creds[(k + round) % creds.len()];
            let r = app.push(cred, &[&h.secret], "sync").await;
            assert_ne!(TestApp::status_of(&r, 0), "accepted");
        }
    }
}

#[tokio::test]
async fn many_working_devices_from_several_instances_answering_badly_stop_the_striking() {
    let app = TestApp::builder()
        .limits(|l| {
            l.strike_trip_devices = 4;
            l.strike_trip_percent = 40;
        })
        .build()
        .await;
    let creds = vec![
        app.new_instance().await,
        app.new_instance().await,
        app.new_instance().await,
    ];
    let devices = devices(&app, 6, true, &creds).await;
    assert_ne!(app.get("/v1/status").await.json["apns"], "degraded");
    rounds(&app, &devices, &creds).await;
    // Without the breaker every device would have been struck three times and
    // deleted. With it, none is.
    for (dev, _) in &devices {
        assert!(app.device_exists(&dev.id).await);
    }
    assert_eq!(app.get("/v1/status").await.json["apns"], "degraded");
    let ratios = app.state.guard.ratios();
    assert_eq!(ratios.len(), 1);
    assert_eq!(ratios[0].app, "hedgerow");
    assert!(
        ratios[0].bad_devices >= 4 && ratios[0].bad_instances >= 3,
        "{ratios:?}"
    );

    // It closes by itself after an hour, and striking works again.
    app.clock.advance_secs(3601);
    assert_ne!(app.get("/v1/status").await.json["apns"], "degraded");
}

#[tokio::test]
async fn only_one_or_two_instances_cannot_trip_the_breaker() {
    let app = TestApp::builder()
        .limits(|l| {
            l.strike_trip_devices = 4;
            l.strike_trip_percent = 40;
        })
        .build()
        .await;
    let creds = vec![app.new_instance().await, app.new_instance().await];
    let devices = devices(&app, 6, true, &creds).await;
    rounds(&app, &devices, &creds).await;
    assert!(!app.state.guard.is_tripped());
    assert_ne!(app.get("/v1/status").await.json["apns"], "degraded");
    // So the bad tokens were struck and deleted as normal.
    for (dev, _) in &devices {
        assert!(!app.device_exists(&dev.id).await);
    }
}

#[tokio::test]
async fn a_flood_of_junk_devices_never_trips_the_breaker_and_is_cleaned_up() {
    let app = TestApp::builder()
        .limits(|l| {
            l.strike_trip_devices = 4;
            l.strike_trip_percent = 40;
        })
        .build()
        .await;
    let creds = vec![
        app.new_instance().await,
        app.new_instance().await,
        app.new_instance().await,
        app.new_instance().await,
    ];
    // Devices Apple never accepted anything for, from every instance.
    let junk = devices(&app, 20, false, &creds).await;
    rounds(&app, &junk, &creds).await;
    assert!(!app.state.guard.is_tripped());
    assert_ne!(app.get("/v1/status").await.json["apns"], "degraded");
    assert!(
        app.state.guard.ratios().is_empty(),
        "junk is not even counted"
    );
    // The breaker never protects them: every one was struck out and deleted.
    for (dev, _) in &junk {
        assert!(!app.device_exists(&dev.id).await);
    }
}

#[tokio::test]
async fn a_rejected_topic_is_a_configuration_error_not_the_devices_fault() {
    let w = world().await;
    w.app.mock.script(
        &w.token,
        vec![
            Reply::reason(400, "BadTopic"),
            Reply::reason(400, "TopicDisallowed"),
        ],
    );
    assert_eq!(w.sync().await, "unavailable");
    assert_eq!(w.sync().await, "unavailable");
    let strikes = w
        .app
        .state
        .db
        .call({
            let id = w.dev.id.clone();
            move |c| {
                postal_pigeon::db::get_device(c, &id)
                    .unwrap()
                    .unwrap()
                    .strikes
            }
        })
        .await;
    assert_eq!(strikes, 0);
    assert!(w.app.device_exists(&w.dev.id).await);
    assert_eq!(w.app.get("/v1/status").await.json["apns"], "degraded");
}

#[tokio::test]
async fn too_many_provider_token_updates_pauses_everything() {
    let w = world().await;
    assert_eq!(w.sync().await, "accepted");
    w.app.mock.script(
        &w.token,
        vec![Reply::reason(429, "TooManyProviderTokenUpdates")],
    );
    let r = w.app.push(&w.cred, &[&w.handle.secret], "sync").await;
    assert_eq!(TestApp::status_of(&r, 0), "unavailable");
    let wait = r.json["results"][0]["retry_after"].as_u64().unwrap();
    assert!(
        wait > 60,
        "wait out Apple's 20 minute rule, not a minute: {wait}"
    );
    let sent = w.app.mock.count();

    // Nothing at all goes to Apple meanwhile, for any device.
    let other = w.app.new_device(&token(0x22)).await;
    let oh = w.app.new_handle(&other).await;
    let r = w
        .app
        .push(&w.cred, &[&oh.secret, &w.handle.secret], "sync")
        .await;
    assert_eq!(TestApp::status_of(&r, 0), "unavailable");
    assert_eq!(TestApp::status_of(&r, 1), "unavailable");
    assert_eq!(w.app.mock.count(), sent);
    assert_eq!(w.app.get("/v1/status").await.json["apns"], "degraded");
    assert!(w.app.device_exists(&w.dev.id).await);

    w.app.clock.advance_secs(wait as i64 + 1);
    assert_eq!(w.sync().await, "accepted");
}

#[tokio::test]
async fn an_unknown_429_reason_is_treated_as_relay_wide() {
    let w = world().await;
    w.app
        .mock
        .script(&w.token, vec![Reply::reason(429, "SomethingNew")]);
    assert_eq!(w.sync().await, "unavailable");
    let sent = w.app.mock.count();
    assert_eq!(w.sync().await, "unavailable");
    assert_eq!(
        w.app.mock.count(),
        sent,
        "a pause for everybody, not one device"
    );
    w.app.clock.advance_secs(61);
    assert_eq!(w.sync().await, "accepted");
}

#[tokio::test]
async fn the_provider_token_is_shared_with_other_processes() {
    let w = world().await;
    assert_eq!(w.sync().await, "accepted");
    let relay_jwt = w.app.mock.last().header("authorization").to_string();

    // The admin commands are another process with its own client, but the same
    // runtime folder: it uses the relay's token instead of minting one.
    let cli = Apns::from_pem(
        &w.app.pem,
        KEY_ID,
        TEAM_ID,
        w.app.settings.apns_urls.clone(),
        w.app.clock.clone(),
    )
    .unwrap()
    .with_token_dir(w.app.runtime_dir.join("postal-pigeon"));
    let req = PushRequest {
        token: &"ee".repeat(32),
        env: Env::Production,
        topic: BUNDLE,
        kind: Kind::Sync,
        tag: "t",
        reference: None,
        collapse: None,
        ttl_secs: 60,
    };
    assert_eq!(cli.send(&req).await, Outcome::Accepted);
    assert_eq!(w.app.mock.last().header("authorization"), relay_jwt);

    // One that does not share would sign its own.
    let alone = Apns::from_pem(
        &w.app.pem,
        KEY_ID,
        TEAM_ID,
        w.app.settings.apns_urls.clone(),
        w.app.clock.clone(),
    )
    .unwrap();
    w.app.clock.advance_secs(2);
    alone.send(&req).await;
    assert_ne!(w.app.mock.last().header("authorization"), relay_jwt);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let file = w
            .app
            .runtime_dir
            .join("postal-pigeon")
            .join("apns-token.json");
        let mode = std::fs::metadata(file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[tokio::test]
async fn check_apns_reports_without_touching_anything() {
    let app = TestApp::new().await;
    let probe = "00".repeat(32);
    app.mock.script(
        &probe,
        (0..4)
            .map(|_| Reply::reason(400, "BadDeviceToken"))
            .collect(),
    );
    let out = admin::run(&app.state, AdminCommand::CheckApns)
        .await
        .unwrap();
    assert_eq!(
        out.matches(": ok:").count(),
        4,
        "two apps, two environments:\n{out}"
    );
    let topics: Vec<String> = app
        .mock
        .requests()
        .iter()
        .map(|r| r.header("apns-topic").to_string())
        .collect();
    assert_eq!(topics.iter().filter(|t| *t == BUNDLE).count(), 2);
    assert_eq!(topics.iter().filter(|t| *t == FERRET_BUNDLE).count(), 2);
    // Nothing recorded or deleted: no devices, no usage.
    let (devices, usage) = app
        .state
        .db
        .call(|c| {
            (
                postal_pigeon::db::count_devices(c).unwrap(),
                postal_pigeon::db::stats(c, 0).unwrap().sends_7d.sends,
            )
        })
        .await;
    assert_eq!((devices, usage), (0, 0));

    // A bad key or team.
    let bad_key = TestApp::new().await;
    bad_key.mock.script(
        &probe,
        (0..4)
            .map(|_| Reply::reason(403, "InvalidProviderToken"))
            .collect(),
    );
    let err = admin::run(&bad_key.state, AdminCommand::CheckApns)
        .await
        .unwrap_err();
    assert!(
        err.contains("FAILED")
            && err.contains("provider token")
            && err.contains("InvalidProviderToken"),
        "{err}"
    );

    // A bundle id Apple does not accept.
    let bad_topic = TestApp::new().await;
    bad_topic.mock.script(
        &probe,
        (0..4).map(|_| Reply::reason(400, "BadTopic")).collect(),
    );
    let err = admin::run(&bad_topic.state, AdminCommand::CheckApns)
        .await
        .unwrap_err();
    assert!(
        err.contains("FAILED") && err.contains("topic") && err.contains("BadTopic"),
        "{err}"
    );
}

// ---- PP-11, PP-12: collapse ids and deduplication --------------------------

#[tokio::test]
async fn collapse_ids_do_not_collide_between_handles() {
    let app = TestApp::new().await;
    let cred = app.new_instance().await;
    let other_cred = app.new_instance().await;
    let dev = app.new_device(&token(1)).await;
    let a = app.new_handle(&dev).await;
    let b = app.new_handle(&dev).await;
    let send = |cred: String, h: String| {
        let app = &app;
        async move {
            let mut body = json!({ "event_id": uuid_v4(), "handles": [h], "kind": "alert" });
            body["collapse"] = json!("incident-1");
            app.push_body(&cred, body).await;
            app.mock.last().header("apns-collapse-id").to_string()
        }
    };
    let from_a = send(cred.clone(), a.secret.clone()).await;
    let from_b = send(other_cred, b.secret.clone()).await;
    let from_a_again = send(cred, a.secret.clone()).await;
    assert_ne!(
        from_a, from_b,
        "two servers can't replace each other's alerts"
    );
    assert_eq!(
        from_a, from_a_again,
        "one server's own updates still collapse"
    );
    assert!(!from_a.contains("incident"));
}

#[tokio::test]
async fn a_handle_listed_twice_is_sent_once() {
    let w = world().await;
    let r = w
        .app
        .push(
            &w.cred,
            &[&w.handle.secret, &w.handle.secret, "garbage", "garbage"],
            "sync",
        )
        .await;
    let got: Vec<_> = (0..4).map(|i| TestApp::status_of(&r, i)).collect();
    assert_eq!(got, ["accepted", "duplicate", "gone", "duplicate"]);
    assert_eq!(w.app.mock.count(), 1);
}

#[tokio::test]
async fn concurrent_requests_with_one_event_id_send_once() {
    let w = world().await;
    let body = json!({ "event_id": uuid_v4(), "handles": [w.handle.secret], "kind": "sync" });
    let (a, b) = tokio::join!(
        w.app.push_body(&w.cred, body.clone()),
        w.app.push_body(&w.cred, body.clone())
    );
    let mut got = vec![TestApp::status_of(&a, 0), TestApp::status_of(&b, 0)];
    got.sort();
    assert_eq!(got, ["accepted", "duplicate"]);
    assert_eq!(w.app.mock.count(), 1);
}

#[tokio::test]
async fn a_full_event_set_forgets_the_oldest_instead_of_giving_up() {
    let app = TestApp::builder()
        .limits(|l| {
            l.max_tracked_keys = 16;
            l.handle_create_per_device_hour = 100;
        })
        .build()
        .await;
    let cred = app.new_instance().await;
    let dev = app.new_device(&token(1)).await;
    let mut events = vec![];
    let mut handles = vec![];
    for _ in 0..20 {
        handles.push(app.new_handle(&dev).await);
        events.push(uuid_v4());
    }
    for (e, h) in events.iter().zip(&handles) {
        let r = app
            .push_body(
                &cred,
                json!({ "event_id": e, "handles": [h.secret], "kind": "sync" }),
            )
            .await;
        assert_eq!(TestApp::status_of(&r, 0), "accepted");
        app.clock.advance_secs(1);
    }
    // The newest are still remembered (not silently disabled)...
    let r = app
        .push_body(
            &cred,
            json!({ "event_id": events[19], "handles": [handles[19].secret], "kind": "sync" }),
        )
        .await;
    assert_eq!(TestApp::status_of(&r, 0), "duplicate");
    // ...and the oldest made room.
    let r = app
        .push_body(
            &cred,
            json!({ "event_id": events[0], "handles": [handles[0].secret], "kind": "sync" }),
        )
        .await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted");
}

// ---- cancelled requests ------------------------------------------------------

#[tokio::test]
async fn a_cancelled_request_does_not_leave_its_event_claimed() {
    let w = world().await;
    // Apple takes its time; the caller gives up (the handler future is dropped
    // in the middle of the send).
    w.app.mock.script(&w.token, vec![Reply::slow(800)]);
    let body = json!({ "event_id": uuid_v4(), "handles": [w.handle.secret], "kind": "sync" });
    let cancelled = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        w.app.push_body(&w.cred, body.clone()),
    )
    .await;
    assert!(cancelled.is_err(), "the request was still running");
    assert!(w.app.mock.count() >= 1, "it did reach the send");
    // The retry is sent, not answered `duplicate` for the next 15 minutes.
    let r = w.app.push_body(&w.cred, body.clone()).await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted");
    // And a completed push still keeps its claim.
    let r = w.app.push_body(&w.cred, body).await;
    assert_eq!(TestApp::status_of(&r, 0), "duplicate");
}
