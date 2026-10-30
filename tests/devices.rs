//! Devices, manage keys and handles.

mod common;

use common::*;
use postal_pigeon::config::Env;
use postal_pigeon::util::{b64, day_string, random_bytes};
use serde_json::json;

#[tokio::test]
async fn registration_returns_ids_and_never_the_token() {
    let app = TestApp::new().await;
    let tok = token(0xab);
    let ip = app.next_ip();
    let r = app
        .call_from(
            &ip,
            "POST",
            "/v1/devices",
            None,
            Some(json!({ "app": "hedgerow", "environment": "production", "token": tok.to_uppercase() })),
            None,
        )
        .await;
    assert_eq!(r.status, 201, "{}", r.json);
    assert!(r.json["device_id"].as_str().unwrap().starts_with("hrd_"));
    assert!(r.json["manage_key"].as_str().unwrap().starts_with("hrm_"));
    assert!(!r.json.to_string().contains(&tok));
}

#[tokio::test]
async fn sylo_is_a_configured_app() {
    let app = TestApp::new().await;
    for env in ["production", "sandbox"] {
        let ip = app.next_ip();
        let r = app
            .call_from(
                &ip,
                "POST",
                "/v1/devices",
                None,
                Some(json!({ "app": "sylo", "environment": env, "token": token(0x21) })),
                None,
            )
            .await;
        assert_eq!(r.status, 201, "{env}: {}", r.json);
        assert!(r.json["device_id"].as_str().unwrap().starts_with("hrd_"));
    }
}

#[tokio::test]
async fn registration_is_validated() {
    let app = TestApp::builder()
        .environments(&[Env::Production])
        .build()
        .await;
    let ok_token = token(1);
    let cases = [
        json!({ "app": "nope", "environment": "production", "token": ok_token }),
        json!({ "app": "hedgerow", "environment": "sandbox", "token": ok_token }),
        json!({ "app": "hedgerow", "environment": "staging", "token": ok_token }),
        json!({ "app": "hedgerow", "environment": "production", "token": "abcd" }),
        json!({ "app": "hedgerow", "environment": "production", "token": "zz".repeat(32) }),
        json!({ "app": "hedgerow", "environment": "production", "token": "ab".repeat(201) }),
        json!({ "app": "hedgerow", "environment": "production" }),
    ];
    for body in cases {
        let ip = app.next_ip();
        let r = app
            .call_from(&ip, "POST", "/v1/devices", None, Some(body.clone()), None)
            .await;
        assert_eq!(
            (r.status.as_u16(), r.error()),
            (400, "invalid_request"),
            "{body}"
        );
    }
    // 32 and 200 bytes are the bounds.
    for len in [32usize, 200] {
        let ip = app.next_ip();
        let t = format!("{:02x}", len).repeat(len);
        let r = app
            .call_from(
                &ip,
                "POST",
                "/v1/devices",
                None,
                Some(json!({ "app": "hedgerow", "environment": "production", "token": t })),
                None,
            )
            .await;
        assert_eq!(r.status, 201, "{len}: {}", r.json);
    }
}

#[tokio::test]
async fn registration_is_limited_per_address() {
    let app = TestApp::builder()
        .limits(|l| {
            l.device_reg_per_addr_hour = 3;
            l.device_reg_per_addr_day = 5;
        })
        .build()
        .await;
    let mut statuses = vec![];
    for n in 0..4u8 {
        let r = app
            .call(
                "POST",
                "/v1/devices",
                None,
                Some(json!({ "app": "hedgerow", "environment": "production", "token": token(n) })),
            )
            .await;
        statuses.push(r.status.as_u16());
        if n == 3 {
            assert_eq!(r.error(), "rate_limited");
            assert!(r.retry_after().unwrap() > 0);
        }
    }
    assert_eq!(statuses, vec![201, 201, 201, 429]);
    // An hour later the hourly bucket has refilled; the daily one has 2 left.
    app.clock.advance_secs(3601);
    for n in 10..12u8 {
        let r = app
            .call(
                "POST",
                "/v1/devices",
                None,
                Some(json!({ "app": "hedgerow", "environment": "production", "token": token(n) })),
            )
            .await;
        assert_eq!(r.status, 201);
    }
    let r = app
        .call(
            "POST",
            "/v1/devices",
            None,
            Some(json!({ "app": "hedgerow", "environment": "production", "token": token(20) })),
        )
        .await;
    assert_eq!(r.status, 429, "the daily limit applies");
}

#[tokio::test]
async fn row_cap_is_enforced() {
    let app = TestApp::builder()
        .limits(|l| l.max_devices = 2)
        .build()
        .await;
    app.new_device(&token(1)).await;
    app.new_device(&token(2)).await;
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

#[tokio::test]
async fn same_token_replaces_the_old_record_and_its_handles() {
    let app = TestApp::new().await;
    let first = app.new_device(&token(5)).await;
    let h = app.new_handle(&first).await;
    let cred = app.new_instance().await;

    let second = app.new_device(&token(5)).await;
    assert_ne!(first.id, second.id);

    let r = app
        .call(
            "GET",
            &format!("/v1/devices/{}/handles", first.id),
            Some(&first.key),
            None,
        )
        .await;
    assert_eq!(r.status, 404, "the old record is gone");
    let r = app.push(&cred, &[&h.secret], "alert").await;
    assert_eq!(TestApp::status_of(&r, 0), "gone");
    assert_eq!(app.mock.count(), 0);
}

#[tokio::test]
async fn manage_key_authenticates_each_call() {
    let app = TestApp::new().await;
    let a = app.new_device(&token(1)).await;
    let b = app.new_device(&token(2)).await;
    let paths = [
        ("GET", format!("/v1/devices/{}/handles", a.id)),
        ("POST", format!("/v1/devices/{}/handles", a.id)),
        ("PUT", format!("/v1/devices/{}", a.id)),
        ("DELETE", format!("/v1/devices/{}", a.id)),
        (
            "DELETE",
            format!("/v1/devices/{}/handles/{}", a.id, "A".repeat(11)),
        ),
    ];
    for (method, path) in &paths {
        let body = Some(json!({ "tag": b64(&random_bytes::<16>()), "token": token(9) }));
        for bearer in [None, Some(b.key.as_str()), Some("hrm_nope")] {
            let r = app.call(method, path, bearer, body.clone()).await;
            assert_eq!(
                (r.status.as_u16(), r.error()),
                (401, "invalid_credentials"),
                "{method} {path} {bearer:?}"
            );
        }
    }
    // Unknown and malformed ids.
    let r = app
        .call(
            "PUT",
            "/v1/devices/hrd_AAAAAAAAAAAAAAAAAAAAAA",
            Some(&a.key),
            Some(json!({})),
        )
        .await;
    assert_eq!(r.status, 404);
    let r = app
        .call("PUT", "/v1/devices/whatever", Some(&a.key), Some(json!({})))
        .await;
    assert_eq!(r.status, 404);
}

#[tokio::test]
async fn update_rotates_the_token_and_keeps_the_device() {
    let app = TestApp::new().await;
    let dev = app.new_device(&token(1)).await;
    let h = app.new_handle(&dev).await;
    let cred = app.new_instance().await;
    let path = format!("/v1/devices/{}", dev.id);

    // A keep-alive without a token.
    let r = app
        .call("PUT", &path, Some(&dev.key), Some(json!({})))
        .await;
    assert_eq!(r.status, 204);

    let r = app
        .call(
            "PUT",
            &path,
            Some(&dev.key),
            Some(json!({ "token": token(2), "environment": "sandbox" })),
        )
        .await;
    assert_eq!(r.status, 204);

    let r = app.push(&cred, &[&h.secret], "alert").await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted");
    assert_eq!(app.mock.last().token(), token(2), "the new token is used");

    // Bad input.
    let r = app
        .call(
            "PUT",
            &path,
            Some(&dev.key),
            Some(json!({ "token": "xyz" })),
        )
        .await;
    assert_eq!(r.status, 400);
    let r = app
        .call(
            "PUT",
            &path,
            Some(&dev.key),
            Some(json!({ "environment": "moon" })),
        )
        .await;
    assert_eq!(r.status, 400);
}

#[tokio::test]
async fn update_is_rate_limited_and_404_after_removal() {
    let app = TestApp::builder()
        .limits(|l| l.device_update_per_hour = 2)
        .build()
        .await;
    let dev = app.new_device(&token(1)).await;
    let path = format!("/v1/devices/{}", dev.id);
    for _ in 0..2 {
        assert_eq!(
            app.call("PUT", &path, Some(&dev.key), Some(json!({})))
                .await
                .status,
            204
        );
    }
    assert_eq!(
        app.call("PUT", &path, Some(&dev.key), Some(json!({})))
            .await
            .status,
        429
    );

    assert_eq!(
        app.call("DELETE", &path, Some(&dev.key), None).await.status,
        204
    );
    let r = app
        .call("PUT", &path, Some(&dev.key), Some(json!({})))
        .await;
    assert_eq!(r.status, 404, "the app registers again on 404");
}

#[tokio::test]
async fn deleting_a_device_deletes_its_handles() {
    let app = TestApp::new().await;
    let dev = app.new_device(&token(1)).await;
    let h = app.new_handle(&dev).await;
    let cred = app.new_instance().await;
    assert_eq!(
        app.call(
            "DELETE",
            &format!("/v1/devices/{}", dev.id),
            Some(&dev.key),
            None
        )
        .await
        .status,
        204
    );
    let r = app.push(&cred, &[&h.secret], "sync").await;
    assert_eq!(TestApp::status_of(&r, 0), "gone");
    assert_eq!(app.mock.count(), 0);
}

#[tokio::test]
async fn handles_are_created_listed_and_revoked() {
    let app = TestApp::new().await;
    let dev = app.new_device(&token(1)).await;
    let base = format!("/v1/devices/{}/handles", dev.id);

    // The tag must be 16 bytes of unpadded base64url.
    for tag in [
        "",
        "short",
        &b64(&random_bytes::<15>()),
        &b64(&random_bytes::<17>()),
        "!!!!!!!!!!!!!!!!!!!!!!",
    ] {
        let r = app
            .call("POST", &base, Some(&dev.key), Some(json!({ "tag": tag })))
            .await;
        assert_eq!(
            (r.status.as_u16(), r.error()),
            (400, "invalid_request"),
            "{tag}"
        );
    }

    let h = app.new_handle(&dev).await;
    assert!(h.secret.starts_with("hrh_"));
    assert!(
        h.secret.contains(&h.id),
        "the public id is inside the handle"
    );

    let r = app.call("GET", &base, Some(&dev.key), None).await;
    assert_eq!(r.status, 200);
    let list = r.json["handles"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["handle_id"], h.id);
    assert_eq!(list[0]["tag"], h.tag);
    assert_eq!(list[0]["created"], day_string(app.clock.today()));
    assert!(list[0]["last_used"].is_null());
    assert!(
        !r.json.to_string().contains("hrh_"),
        "listing never shows the secret"
    );

    // Using it records a date, not a time.
    let cred = app.new_instance().await;
    app.push(&cred, &[&h.secret], "sync").await;
    let r = app.call("GET", &base, Some(&dev.key), None).await;
    assert_eq!(
        r.json["handles"][0]["last_used"],
        day_string(app.clock.today())
    );

    let one = format!("{base}/{}", h.id);
    assert_eq!(
        app.call("DELETE", &one, Some(&dev.key), None).await.status,
        204
    );
    assert_eq!(
        app.call("DELETE", &one, Some(&dev.key), None).await.status,
        404
    );
    let r = app.call("GET", &base, Some(&dev.key), None).await;
    assert!(r.json["handles"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn handle_limits() {
    let app = TestApp::builder()
        .limits(|l| {
            l.handle_create_per_device_hour = 5;
            l.max_handles_per_device = 3;
        })
        .build()
        .await;
    let dev = app.new_device(&token(1)).await;
    let base = format!("/v1/devices/{}/handles", dev.id);
    let create = || async {
        app.call(
            "POST",
            &base,
            Some(&dev.key),
            Some(json!({ "tag": b64(&random_bytes::<16>()) })),
        )
        .await
    };
    for _ in 0..3 {
        assert_eq!(create().await.status, 201);
    }
    let r = create().await;
    assert_eq!((r.status.as_u16(), r.error()), (409, "limit_reached"));

    // Revoking frees a slot; the hourly creation budget (5) still runs out.
    let list = app.call("GET", &base, Some(&dev.key), None).await;
    let id = list.json["handles"][0]["handle_id"]
        .as_str()
        .unwrap()
        .to_string();
    app.call("DELETE", &format!("{base}/{id}"), Some(&dev.key), None)
        .await;
    assert_eq!(create().await.status, 201);
    let r = create().await;
    assert_eq!(r.status, 429, "the hourly budget of five is used up");
    assert!(r.retry_after().is_some());
}
