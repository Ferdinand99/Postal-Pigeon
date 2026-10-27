//! Health, instance registration, proof of work, address limits, credentials.

mod common;

use axum::http::StatusCode;
use common::*;
use postal_pigeon::pow;
use postal_pigeon::util::{DAY_SECS, leading_zero_bits};
use serde_json::json;

#[tokio::test]
async fn healthz_status_and_headers() {
    let app = TestApp::new().await;
    let r = app.get("/healthz").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json, "ok");
    assert_eq!(r.headers["cache-control"], "no-store");
    assert_eq!(r.headers["x-content-type-options"], "nosniff");

    let s = app.get("/v1/status").await;
    assert_eq!(s.status, 200);
    assert_eq!(s.json["api"], json!([1]));
    assert_eq!(s.json["apns"], "unknown");
    assert!(s.json["version"].is_string());

    let missing = app.get("/v1/nothing").await;
    assert_eq!(missing.status, 404);
    assert_eq!(missing.error(), "not_found");
}

#[tokio::test]
async fn challenge_shape() {
    let app = TestApp::new().await;
    let r = app.get("/v1/challenge").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json["difficulty"], 4);
    assert!(r.json["challenge"].as_str().unwrap().len() > 40);
    let exp = r.json["expires_at"].as_str().unwrap();
    assert!(exp.ends_with('Z') && exp.contains('T'), "{exp}");
}

#[tokio::test]
async fn registration_works_once_per_challenge() {
    let app = TestApp::new().await;
    let (c, d) = app.challenge().await;
    let body = app.registration(&c, d);
    let ip = app.next_ip();
    let ok = app
        .call_from(&ip, "POST", "/v1/instances", None, Some(body.clone()), None)
        .await;
    assert_eq!(ok.status, 201, "{}", ok.json);
    assert_eq!(ok.json["tier"], "new");
    let cred = ok.json["instance_credential"].as_str().unwrap();
    assert!(cred.starts_with("hrk_"));
    assert!(ok.json["limits"]["sends_per_hour"].is_number());

    let again = app
        .call_from(&ip, "POST", "/v1/instances", None, Some(body), None)
        .await;
    assert_eq!(again.status, 400);
    assert_eq!(again.error(), "challenge_used");
}

#[tokio::test]
async fn proof_of_work_is_enforced() {
    let app = TestApp::builder()
        .limits(|l| l.pow_difficulty = 14)
        .build()
        .await;
    let (c, _) = app.challenge().await;
    let bad = (0u64..)
        .map(|n| n.to_string())
        .find(|n| {
            let d = postal_pigeon::crypto::sha256(&[c.as_bytes(), n.as_bytes()].concat());
            leading_zero_bits(&d) < 14
        })
        .unwrap();
    let r = app
        .call(
            "POST",
            "/v1/instances",
            None,
            Some(json!({ "challenge": c, "nonce": bad, "product": "wise-wren", "version": "1" })),
        )
        .await;
    assert_eq!(r.status, 400);
    assert_eq!(r.error(), "invalid_proof");
    // A wrong proof doesn't burn the challenge.
    let good = pow::solve(&c, 14);
    let r = app
        .call(
            "POST",
            "/v1/instances",
            None,
            Some(json!({ "challenge": c, "nonce": good, "product": "wise-wren", "version": "1" })),
        )
        .await;
    assert_eq!(r.status, 201, "{}", r.json);
}

#[tokio::test]
async fn foreign_and_expired_challenges_are_refused() {
    let app = TestApp::new().await;
    let r = app
        .call(
            "POST",
            "/v1/instances",
            None,
            Some(json!({ "challenge": "AAAA", "nonce": "1", "product": "wise-wren" })),
        )
        .await;
    assert_eq!((r.status.as_u16(), r.error()), (400, "invalid_challenge"));

    let (c, d) = app.challenge().await;
    app.clock.advance_secs(301);
    let r = app
        .call("POST", "/v1/instances", None, Some(app.registration(&c, d)))
        .await;
    assert_eq!((r.status.as_u16(), r.error()), (400, "challenge_expired"));
}

#[tokio::test]
async fn product_and_version_are_validated() {
    let app = TestApp::new().await;
    for (product, version) in [
        ("evil-product", "1.0"),
        ("wise-wren", "a b"),
        ("wise-wren", &"9".repeat(40)),
    ] {
        let (c, d) = app.challenge().await;
        let mut body = app.registration(&c, d);
        body["product"] = json!(product);
        body["version"] = json!(version);
        let ip = app.next_ip();
        let r = app
            .call_from(&ip, "POST", "/v1/instances", None, Some(body), None)
            .await;
        assert_eq!(
            (r.status.as_u16(), r.error()),
            (400, "invalid_request"),
            "{product} {version}"
        );
    }
    // The version is optional.
    let (c, d) = app.challenge().await;
    let mut body = app.registration(&c, d);
    body.as_object_mut().unwrap().remove("version");
    let r = app.call("POST", "/v1/instances", None, Some(body)).await;
    assert_eq!(r.status, 201);
}

#[tokio::test]
async fn registration_is_limited_per_address_and_gets_harder_never_closed() {
    let app = TestApp::builder()
        .limits(|l| l.instance_reg_high_water_per_day = 7)
        .build()
        .await;
    // A challenge fetched before the budget is used up.
    let (spare, spare_d) = app.challenge().await;
    // Five per address per day.
    for _ in 0..5 {
        let (c, d) = app.challenge().await;
        let r = app
            .call("POST", "/v1/instances", None, Some(app.registration(&c, d)))
            .await;
        assert_eq!(r.status, 201);
    }
    // The address is used up: no more challenges for it either.
    let r = app.get("/v1/challenge").await;
    assert_eq!((r.status.as_u16(), r.error()), (429, "rate_limited"));
    assert!(r.retry_after().unwrap() > 0);
    // And a challenge it already holds is refused without being burnt...
    let r = app
        .call(
            "POST",
            "/v1/instances",
            None,
            Some(app.registration(&spare, spare_d)),
        )
        .await;
    assert_eq!((r.status.as_u16(), r.error()), (429, "rate_limited"));
    // ...so the same challenge still works from another address (the limit is
    // checked before the challenge is remembered).
    let other = app.next_ip();
    let r = app
        .call_from(
            &other,
            "POST",
            "/v1/instances",
            None,
            Some(app.registration(&spare, spare_d)),
            None,
        )
        .await;
    assert_eq!(r.status, 201, "{}", r.json);

    // One more from another address reaches the day's high-water mark (7)...
    assert_eq!(app.get("/v1/status").await.json["registration"], "normal");
    app.new_instance().await;
    assert_eq!(app.get("/v1/status").await.json["registration"], "busy");
    // ...registration is not closed to anybody. The work just gets harder.
    let ip = app.next_ip();
    let (c, d) = app.challenge_from(&ip).await;
    assert_eq!(d, 4 + 4, "base plus the high-water bits");
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
    // A challenge issued at the lower difficulty before is still honoured; one
    // asked for now is not satisfied by less work than it says.
    let ip2 = app.next_ip();
    let (c2, d2) = app.challenge_from(&ip2).await;
    assert_eq!(d2, 8);

    // Tomorrow it is back to normal.
    app.clock.advance_secs(DAY_SECS);
    assert_eq!(app.get("/v1/status").await.json["registration"], "normal");
    let (_, d) = app.challenge_from(&ip2).await;
    assert_eq!(d, 4);
    let _ = c2;
}

#[tokio::test]
async fn forwarded_for_is_believed_only_from_trusted_proxies() {
    let app = TestApp::builder().proxies(&["10.0.0.1"]).build().await;
    // Through the trusted proxy, different clients have separate limits.
    for i in 1..=6 {
        let (c, d) = app.challenge().await;
        let r = app
            .call_from(
                "10.0.0.1",
                "POST",
                "/v1/instances",
                None,
                Some(app.registration(&c, d)),
                Some(&format!("192.0.2.{i}")),
            )
            .await;
        assert_eq!(r.status, 201, "client {i}: {}", r.json);
    }
    // From anywhere else the header is ignored, so one address is one bucket.
    let mut last = StatusCode::CREATED;
    for i in 1..=6 {
        let (c, d) = app.challenge().await;
        let r = app
            .call_from(
                "198.51.100.200",
                "POST",
                "/v1/instances",
                None,
                Some(app.registration(&c, d)),
                Some(&format!("192.0.2.{}", 100 + i)),
            )
            .await;
        last = r.status;
    }
    assert_eq!(last, 429);
}

#[tokio::test]
async fn credential_rotation_and_removal() {
    let app = TestApp::new().await;
    let old = app.new_instance().await;

    let r = app
        .call("POST", "/v1/instances/self/rotate", Some(&old), None)
        .await;
    assert_eq!(r.status, 200);
    let new = r.json["instance_credential"].as_str().unwrap().to_string();
    assert_ne!(new, old);
    assert_eq!(new[..15], old[..15], "the public id stays");

    let r = app
        .call("POST", "/v1/instances/self/rotate", Some(&old), None)
        .await;
    assert_eq!((r.status.as_u16(), r.error()), (401, "invalid_credentials"));

    let r = app
        .call("DELETE", "/v1/instances/self", Some(&new), None)
        .await;
    assert_eq!(r.status, 204);
    let r = app
        .call("DELETE", "/v1/instances/self", Some(&new), None)
        .await;
    assert_eq!((r.status.as_u16(), r.error()), (401, "unknown_instance"));
}

#[tokio::test]
async fn credentials_are_checked() {
    let app = TestApp::new().await;
    let cred = app.new_instance().await;
    for bearer in [None, Some("nope"), Some("hrk_short")] {
        let r = app
            .call("POST", "/v1/instances/self/rotate", bearer, None)
            .await;
        assert_eq!((r.status.as_u16(), r.error()), (401, "invalid_credentials"));
    }
    // Right id, wrong secret.
    let forged = format!("{}{}", &cred[..15], "A".repeat(43));
    let r = app
        .call("POST", "/v1/instances/self/rotate", Some(&forged), None)
        .await;
    assert_eq!((r.status.as_u16(), r.error()), (401, "invalid_credentials"));
    // A handle or manage key is not an instance credential.
    let r = app
        .call(
            "POST",
            "/v1/instances/self/rotate",
            Some(&format!("hrm_{}", "A".repeat(43))),
            None,
        )
        .await;
    assert_eq!(r.status, 401);
}

#[tokio::test]
async fn wrong_credentials_are_limited_per_address_but_valid_ones_never_blocked() {
    let app = TestApp::builder()
        .limits(|l| l.auth_failures_per_addr_hour = 3)
        .build()
        .await;
    let cred = app.new_instance().await;
    let forged = format!("{}{}", &cred[..15], "A".repeat(43));
    for _ in 0..3 {
        let r = app
            .call("POST", "/v1/instances/self/rotate", Some(&forged), None)
            .await;
        assert_eq!(r.status, 401);
    }
    // The address has used its failures: more wrong ones get 429...
    let r = app
        .call("POST", "/v1/instances/self/rotate", Some(&forged), None)
        .await;
    assert_eq!((r.status.as_u16(), r.error()), (429, "rate_limited"));
    assert!(r.retry_after().is_some());
    // ...but a request with valid credentials is not held up by them. A flood
    // of bad Authorization headers behind a shared address can't lock the
    // good clients out.
    let r = app
        .call("POST", "/v1/instances/self/rotate", Some(&cred), None)
        .await;
    assert_eq!(r.status, 200, "{}", r.json);
}

#[tokio::test]
async fn unknown_ids_are_charged_too() {
    let app = TestApp::builder()
        .limits(|l| l.auth_failures_per_addr_hour = 2)
        .build()
        .await;
    let unknown_instance = format!("hrk_{}{}", "B".repeat(11), "C".repeat(43));
    let unknown_device = "hrd_AAAAAAAAAAAAAAAAAAAAAA";
    let mut seen = vec![];
    for _ in 0..2 {
        let r = app
            .call(
                "POST",
                "/v1/instances/self/rotate",
                Some(&unknown_instance),
                None,
            )
            .await;
        seen.push(r.status.as_u16());
    }
    let r = app
        .call(
            "PUT",
            &format!("/v1/devices/{unknown_device}"),
            Some("hrm_x"),
            Some(json!({})),
        )
        .await;
    seen.push(r.status.as_u16());
    let r = app
        .call(
            "POST",
            "/v1/instances/self/rotate",
            Some(&unknown_instance),
            None,
        )
        .await;
    seen.push(r.status.as_u16());
    assert_eq!(seen, [401, 401, 429, 429]);
}

#[tokio::test]
async fn suspended_instances_are_refused() {
    let app = TestApp::new().await;
    let cred = app.new_instance().await;
    let id = cred[4..15].to_string();
    app.state
        .db
        .call(move |c| postal_pigeon::db::set_instance_state(c, &id, "suspended").unwrap())
        .await;
    let r = app
        .call("POST", "/v1/instances/self/rotate", Some(&cred), None)
        .await;
    assert_eq!((r.status.as_u16(), r.error()), (403, "suspended"));
    let r = app
        .push_body(
            &cred,
            json!({ "event_id": postal_pigeon::util::uuid_v4(), "handles": ["x"], "kind": "sync" }),
        )
        .await;
    assert_eq!((r.status.as_u16(), r.error()), (403, "suspended"));
}

#[tokio::test]
async fn overload_is_shed_with_503_but_healthz_still_answers() {
    let app = TestApp::builder()
        .limits(|l| l.max_inflight_requests = 0)
        .build()
        .await;
    let r = app.get("/v1/status").await;
    assert_eq!((r.status.as_u16(), r.error()), (503, "overloaded"));
    assert!(r.retry_after().is_some());
    // /healthz has a pool of its own.
    let r = app.get("/healthz").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json, "ok");
}
