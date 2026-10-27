//! Storage rules, retention, key rotation, logs and the admin commands.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::*;
use postal_pigeon::admin::{self, AdminCommand};
use postal_pigeon::crypto::Keys;
use postal_pigeon::db::{self, Db, Usage};
use postal_pigeon::maintenance;
use postal_pigeon::util::{DAY_SECS, random_bytes};
use serde_json::json;

fn instance_id(cred: &str) -> String {
    cred[4..15].to_string()
}

#[tokio::test]
async fn tokens_are_sealed_at_rest() {
    let app = TestApp::new().await;
    let tok = token(0xcd);
    let dev = app.new_device(&tok).await;
    let id = dev.id.clone();
    let (dump, kid) = app
        .state
        .db
        .call(move |c| {
            // Every column of every table, as text.
            let mut all = String::new();
            for table in ["devices", "handles", "instances", "instance_usage"] {
                let mut stmt = c.prepare(&format!("SELECT * FROM {table}")).unwrap();
                let n = stmt.column_count();
                let mut rows = stmt.query([]).unwrap();
                while let Some(row) = rows.next().unwrap() {
                    for i in 0..n {
                        let v: rusqlite::types::Value = row.get(i).unwrap();
                        all.push_str(&format!("{v:?}|"));
                    }
                }
            }
            let d = db::get_device(c, &id).unwrap().unwrap();
            (all, d.seal_key_id)
        })
        .await;
    assert!(!dump.contains(&tok), "the token never appears in clear");
    assert!(!dump.contains(&dev.key), "nor the manage key");
    assert_eq!(kid, app.state.keys.current_seal_id());
}

#[tokio::test]
async fn no_table_links_an_instance_to_a_device_or_handle() {
    let app = TestApp::new().await;
    let tables: Vec<(String, Vec<String>)> = app
        .state
        .db
        .call(|c| {
            let names: Vec<String> = c
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            names
                .into_iter()
                .map(|n| {
                    let cols = c
                        .prepare(&format!("PRAGMA table_info({n})"))
                        .unwrap()
                        .query_map([], |r| r.get::<_, String>(1))
                        .unwrap()
                        .map(Result::unwrap)
                        .collect();
                    (n, cols)
                })
                .collect()
        })
        .await;
    assert!(tables.len() >= 4);
    for (name, cols) in &tables {
        let mentions = |words: &[&str]| {
            words
                .iter()
                .any(|w| name.contains(w) || cols.iter().any(|c| c.contains(w)))
        };
        // `handles` and `devices` are linked to each other, never to an instance.
        assert!(
            !(mentions(&["instance"]) && mentions(&["device", "handle"])),
            "table {name} ties an instance to a device or handle: {cols:?}"
        );
    }
    // Nor does usage hold a handle or device (design section 9).
    let usage = &tables
        .iter()
        .find(|(n, _)| n == "instance_usage")
        .unwrap()
        .1;
    assert!(
        usage
            .iter()
            .all(|c| !c.contains("handle") && !c.contains("device"))
    );
}

#[tokio::test]
async fn no_ref_event_or_address_is_stored() {
    let app = TestApp::new().await;
    let cred = app.new_instance().await;
    let dev = app.new_device(&token(1)).await;
    let h = app.new_handle(&dev).await;
    let event = postal_pigeon::util::uuid_v4();
    app.push_body(
        &cred,
        json!({ "event_id": event, "handles": [h.secret], "kind": "alert", "ref": "REFVALUE123" }),
    )
    .await;
    let dump = app
        .state
        .db
        .call(|c| {
            let mut all = String::new();
            for table in ["devices", "handles", "instances", "instance_usage"] {
                let mut stmt = c.prepare(&format!("SELECT * FROM {table}")).unwrap();
                let n = stmt.column_count();
                let mut rows = stmt.query([]).unwrap();
                while let Some(row) = rows.next().unwrap() {
                    for i in 0..n {
                        let v: rusqlite::types::Value = row.get(i).unwrap();
                        all.push_str(&format!("{v:?}|"));
                    }
                }
            }
            all
        })
        .await;
    for secret in [
        "REFVALUE123",
        event.as_str(),
        cred.as_str(),
        h.secret.as_str(),
        "203.0.113.10",
    ] {
        assert!(!dump.contains(secret), "{secret} must not be stored");
    }
    // Only the coarse prefix, for 30 days.
    assert!(dump.contains("/24"));
}

#[tokio::test]
async fn retention_rules() {
    let app = TestApp::new().await;
    let silent = app.new_device(&token(1)).await;
    let kept_alive = app.new_device(&token(2)).await;
    let cred_idle = app.new_instance().await;
    let cred_busy = app.new_instance().await;
    let prefixes = |app: &TestApp| {
        let db = app.state.db.clone();
        async move {
            db.call(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM instances WHERE reg_prefix IS NOT NULL",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap()
            })
            .await
        }
    };
    assert_eq!(prefixes(&app).await, 2);

    app.state
        .db
        .call({
            let id = instance_id(&cred_idle);
            let today = app.clock.today();
            move |c| {
                db::add_usage(
                    c,
                    &id,
                    today,
                    Usage {
                        sends: 1,
                        ..Usage::default()
                    },
                )
                .unwrap();
            }
        })
        .await;

    // Day 29: the registration prefix is still there; day 31: gone.
    app.clock.advance_secs(29 * DAY_SECS);
    let run = |app: &TestApp| {
        let s = app.state.clone();
        async move {
            tokio::task::spawn_blocking(move || maintenance::run_once(&s).unwrap())
                .await
                .unwrap()
        }
    };
    run(&app).await;
    assert_eq!(prefixes(&app).await, 2);
    app.clock.advance_secs(2 * DAY_SECS);
    let r = run(&app).await;
    assert_eq!(r.prefixes_cleared, 2);
    assert_eq!(prefixes(&app).await, 0);

    // Usage is kept 30 days.
    assert_eq!(r.usage_expired, 1);

    // The keep-alive resets the 90 days; flagged as stale after 60.
    app.clock.advance_secs(29 * DAY_SECS); // day 60
    let r = run(&app).await;
    assert_eq!(r.stale_devices, 0, "exactly 60 days is not yet stale");
    app.clock.advance_secs(2 * DAY_SECS); // day 62
    app.call(
        "PUT",
        &format!("/v1/devices/{}", kept_alive.id),
        Some(&kept_alive.key),
        Some(json!({})),
    )
    .await;
    let r = run(&app).await;
    assert_eq!(r.stale_devices, 1, "only flagged, not deleted yet");
    assert!(app.device_exists(&silent.id).await);

    app.clock.advance_secs(29 * DAY_SECS); // day 91
    let r = run(&app).await;
    assert_eq!(r.devices_expired, 1);
    assert!(!app.device_exists(&silent.id).await);
    assert!(app.device_exists(&kept_alive.id).await);

    // Instances unused for 180 days go; a used one stays.
    app.clock.advance_secs(80 * DAY_SECS); // day 171
    let rotated = app
        .call("POST", "/v1/instances/self/rotate", Some(&cred_busy), None)
        .await;
    let cred_busy = rotated.json["instance_credential"]
        .as_str()
        .unwrap()
        .to_string();
    app.clock.advance_secs(10 * DAY_SECS); // day 181
    let r = run(&app).await;
    assert_eq!(r.instances_expired, 1);
    let r = app
        .call("POST", "/v1/instances/self/rotate", Some(&cred_idle), None)
        .await;
    assert_eq!(r.error(), "unknown_instance");
    let r = app
        .call("POST", "/v1/instances/self/rotate", Some(&cred_busy), None)
        .await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn instances_become_established_after_a_week_without_limit_hits() {
    let app = TestApp::new().await;
    let calm = app.new_instance().await;
    let noisy = app.new_instance().await;
    let tier = |app: &TestApp, cred: &str| {
        let (db, id) = (app.state.db.clone(), instance_id(cred));
        async move {
            db.call(move |c| db::get_instance(c, &id).unwrap().unwrap().tier)
                .await
        }
    };
    let run = |app: &TestApp| {
        let s = app.state.clone();
        async move {
            tokio::task::spawn_blocking(move || maintenance::run_once(&s).unwrap())
                .await
                .unwrap()
        }
    };
    app.clock.advance_secs(3 * DAY_SECS);
    let (day, id) = (app.clock.today(), instance_id(&noisy));
    app.state
        .db
        .call(move |c| {
            db::add_usage(
                c,
                &id,
                day,
                Usage {
                    throttled: 1,
                    ..Usage::default()
                },
            )
            .unwrap();
        })
        .await;
    app.clock.advance_secs(4 * DAY_SECS);
    assert_eq!(run(&app).await.promoted, 1);
    assert_eq!(tier(&app, &calm).await, "established");
    assert_eq!(
        tier(&app, &noisy).await,
        "new",
        "a limit hit within the week holds it back"
    );
    app.clock.advance_secs(5 * DAY_SECS);
    run(&app).await;
    assert_eq!(tier(&app, &noisy).await, "established");
}

#[tokio::test]
async fn sealing_keys_can_be_rotated() {
    let hmac = random_bytes::<32>();
    let old = random_bytes::<32>();
    let new = random_bytes::<32>();
    let db = Db::open_memory().unwrap();

    let before = TestApp::builder()
        .keys(Keys::new(&hmac, &old, &[]))
        .db(db.clone())
        .build()
        .await;
    let tok = token(0x77);
    let dev = before.new_device(&tok).await;
    let handle = before.new_handle(&dev).await;
    let cred = before.new_instance().await;

    let after = TestApp::builder()
        .keys(Keys::new(&hmac, &new, &[old.to_vec()]))
        .db(db)
        .build()
        .await;
    // The old key still works for sending...
    let r = after.push(&cred, &[&handle.secret], "sync").await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted");
    assert_eq!(after.mock.last().token(), tok);

    // ...and re-sealing moves every token to the new key.
    let n = maintenance::reseal(&after.state).unwrap();
    assert_eq!(n, 1);
    let id = dev.id.clone();
    let kid = after
        .state
        .db
        .call(move |c| db::get_device(c, &id).unwrap().unwrap().seal_key_id)
        .await;
    assert_eq!(kid, after.state.keys.current_seal_id());
    let r = after.push(&cred, &[&handle.secret], "sync").await;
    assert_eq!(TestApp::status_of(&r, 0), "accepted");
    assert_eq!(after.mock.last().token(), tok);
    assert_eq!(maintenance::reseal(&after.state).unwrap(), 0);
}

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn logs_never_hold_tokens_handles_credentials_refs_or_addresses() {
    let buf = LogBuf::default();
    let sub = tracing_subscriber::fmt()
        .with_writer({
            let buf = buf.clone();
            move || buf.clone()
        })
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "info,postal_pigeon=trace",
        ))
        .finish();
    let _guard = tracing::subscriber::set_default(sub);

    let app = TestApp::new().await;
    let cred = app.new_instance().await;
    let tok = token(0x99);
    let dev = app.new_device(&tok).await;
    let handle = app.new_handle(&dev).await;
    let event = postal_pigeon::util::uuid_v4();

    // Good paths and every kind of bad one Apple can produce.
    app.mock.script(
        &tok,
        vec![
            Reply::status(200),
            Reply::reason(403, "InvalidProviderToken"),
            Reply::reason(400, "PayloadEmpty"),
            Reply::reason(429, "TooManyRequests"),
            Reply::status(500),
            Reply::status(500),
        ],
    );
    for i in 0..6 {
        let ev = if i == 0 {
            event.clone()
        } else {
            postal_pigeon::util::uuid_v4()
        };
        app.push_body(
            &cred,
            json!({ "event_id": ev, "handles": [handle.secret], "kind": "sync", "ref": "REFVALUE123" }),
        )
        .await;
    }
    // Failed logins, unknown handles, a bad token.
    app.call("POST", "/v1/instances/self/rotate", Some("hrk_wrong"), None)
        .await;
    app.push(&cred, &["hrh_unknownunknown"], "sync").await;
    app.call(
        "PUT",
        &format!("/v1/devices/{}", dev.id),
        Some("hrm_wrong"),
        Some(json!({ "token": tok })),
    )
    .await;

    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("apns_operator_problem"),
        "the capture works:\n{logs}"
    );
    for secret in [
        tok.as_str(),
        dev.id.as_str(),
        dev.key.as_str(),
        handle.secret.as_str(),
        handle.id.as_str(),
        handle.tag.as_str(),
        cred.as_str(),
        &cred[4..15],
        "REFVALUE123",
        event.as_str(),
        "203.0.113",
        "198.51.",
    ] {
        assert!(
            !logs.contains(secret),
            "{secret} found in the logs:\n{logs}"
        );
    }
}

#[tokio::test]
async fn admin_commands() {
    let app = TestApp::new().await;
    let cred = app.new_instance().await;
    let id = instance_id(&cred);
    let tok = token(0xee);
    let dev = app.new_device(&tok).await;
    let handle = app.new_handle(&dev).await;
    app.push(&cred, &[&handle.secret], "sync").await;
    let st = &app.state;

    let out = admin::run(st, AdminCommand::Instances).await.unwrap();
    assert!(
        out.contains(&id) && out.contains("vigilant-vole") && out.contains("new"),
        "{out}"
    );
    assert!(!out.contains(&cred));

    let out = admin::run(st, AdminCommand::Stats).await.unwrap();
    assert!(out.contains("new / active: 1"), "{out}");
    assert!(out.contains("hedgerow / production: 1"), "{out}");
    assert!(out.contains("handles: 1"), "{out}");
    assert!(out.contains("1 accepted"), "{out}");
    assert!(!out.contains(&tok));

    // Block and unblock.
    admin::run(st, AdminCommand::BlockInstance { id: id.clone() })
        .await
        .unwrap();
    assert_eq!(app.push(&cred, &[&handle.secret], "sync").await.status, 403);
    admin::run(st, AdminCommand::UnblockInstance { id: id.clone() })
        .await
        .unwrap();
    assert_eq!(app.push(&cred, &[&handle.secret], "sync").await.status, 200);
    assert!(
        admin::run(st, AdminCommand::BlockInstance { id: "nope".into() })
            .await
            .is_err()
    );

    // Tiers.
    admin::run(
        st,
        AdminCommand::SetTier {
            id: id.clone(),
            tier: "established".into(),
        },
    )
    .await
    .unwrap();
    assert!(
        admin::run(
            st,
            AdminCommand::SetTier {
                id: id.clone(),
                tier: "vip".into()
            }
        )
        .await
        .is_err()
    );
    let out = admin::run(st, AdminCommand::Instances).await.unwrap();
    assert!(out.contains("established"));

    // A test push, by handle and by device id, ignoring rate limits.
    let before = app.mock.count();
    let out = admin::run(
        st,
        AdminCommand::SendTest {
            device: handle.secret.clone(),
            kind: "alert".into(),
        },
    )
    .await
    .unwrap();
    assert!(out.starts_with("accepted"), "{out}");
    assert!(!out.contains(&tok));
    let rec = app.mock.last();
    assert_eq!(app.mock.count(), before + 1);
    assert_eq!(rec.token(), tok);
    assert_eq!(rec.header("apns-push-type"), "alert");
    assert_eq!(rec.body["aps"]["mutable-content"], 1);
    assert_eq!(rec.body["hr"]["t"], handle.tag);

    let out = admin::run(
        st,
        AdminCommand::SendTest {
            device: dev.id.clone(),
            kind: "sync".into(),
        },
    )
    .await
    .unwrap();
    assert!(out.starts_with("accepted"), "{out}");
    assert_eq!(app.mock.last().header("apns-push-type"), "background");

    assert!(
        admin::run(
            st,
            AdminCommand::SendTest {
                device: "hrd_AAAAAAAAAAAAAAAAAAAAAA".into(),
                kind: "alert".into()
            }
        )
        .await
        .is_err()
    );
    assert!(
        admin::run(
            st,
            AdminCommand::SendTest {
                device: "garbage".into(),
                kind: "alert".into()
            }
        )
        .await
        .is_err()
    );

    // Deleting.
    admin::run(st, AdminCommand::DeleteDevice { id: dev.id.clone() })
        .await
        .unwrap();
    assert!(!app.device_exists(&dev.id).await);
    admin::run(st, AdminCommand::DeleteInstance { id })
        .await
        .unwrap();
    let r = app
        .call("POST", "/v1/instances/self/rotate", Some(&cred), None)
        .await;
    assert_eq!(r.error(), "unknown_instance");
}
