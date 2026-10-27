//! Test harness: the relay's router in-process, a mock APNs server over
//! cleartext HTTP/2, and helpers for the usual flows. Nothing here ever
//! reaches Apple.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use postal_pigeon::api;
use postal_pigeon::apns::Apns;
use postal_pigeon::clock::Clock;
use postal_pigeon::config::{ApnsSettings, ApnsUrls, AppConfig, Env, Settings};
use postal_pigeon::crypto::Keys;
use postal_pigeon::db::Db;
use postal_pigeon::limits::Limits;
use postal_pigeon::pow;
use postal_pigeon::state::AppState;
use postal_pigeon::util::{IpNet, b64, random_bytes};
use serde_json::{Value, json};
use tower::ServiceExt as _;

pub const BUNDLE: &str = "tools.hedgerow.app";
pub const FERRET_BUNDLE: &str = "tools.hedgerow.ferret";
pub const KEY_ID: &str = "ABC123DEFG";
pub const TEAM_ID: &str = "TEAM123456";

/// A 64-hex-character device token made of one repeated byte.
pub fn token(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

// ---- Mock APNs --------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Recorded {
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Value,
}

impl Recorded {
    pub fn token(&self) -> &str {
        self.path.trim_start_matches("/3/device/")
    }

    pub fn header(&self, name: &str) -> &str {
        self.headers.get(name).map(String::as_str).unwrap_or("")
    }
}

pub struct Reply {
    pub status: u16,
    pub body: Option<Value>,
    pub headers: Vec<(&'static str, String)>,
}

impl Reply {
    pub fn status(status: u16) -> Reply {
        Reply {
            status,
            body: None,
            headers: vec![],
        }
    }

    pub fn reason(status: u16, reason: &str) -> Reply {
        Reply {
            status,
            body: Some(json!({ "reason": reason })),
            headers: vec![],
        }
    }

    pub fn unregistered(timestamp_ms: i64) -> Reply {
        Reply {
            status: 410,
            body: Some(json!({ "reason": "Unregistered", "timestamp": timestamp_ms })),
            headers: vec![],
        }
    }
}

#[derive(Default)]
struct MockInner {
    requests: Mutex<Vec<Recorded>>,
    /// Scripted answers per device token, used in order; 200 when empty.
    script: Mutex<HashMap<String, VecDeque<Reply>>>,
}

#[derive(Clone, Default)]
pub struct Mock(Arc<MockInner>);

impl Mock {
    pub fn requests(&self) -> Vec<Recorded> {
        self.0.requests.lock().unwrap().clone()
    }

    pub fn count(&self) -> usize {
        self.0.requests.lock().unwrap().len()
    }

    pub fn last(&self) -> Recorded {
        self.requests().pop().expect("a request reached the mock")
    }

    /// The next answers for pushes to `token`.
    pub fn script(&self, token: &str, replies: Vec<Reply>) {
        self.0
            .script
            .lock()
            .unwrap()
            .insert(token.to_string(), replies.into());
    }
}

async fn mock_handler(State(mock): State<Mock>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
    let headers: HashMap<String, String> = parts
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let rec = Recorded {
        path: parts.uri.path().to_string(),
        headers,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    };
    let token = rec.token().to_string();
    mock.0.requests.lock().unwrap().push(rec);
    let reply = mock
        .0
        .script
        .lock()
        .unwrap()
        .get_mut(&token)
        .and_then(VecDeque::pop_front)
        .unwrap_or_else(|| Reply::status(200));
    let mut resp = match reply.body {
        Some(b) => (StatusCode::from_u16(reply.status).unwrap(), axum::Json(b)).into_response(),
        None => StatusCode::from_u16(reply.status).unwrap().into_response(),
    };
    for (k, v) in reply.headers {
        resp.headers_mut()
            .insert(k, HeaderValue::from_str(&v).unwrap());
    }
    resp
}

async fn start_mock() -> (SocketAddr, Mock) {
    let mock = Mock::default();
    let app = Router::new()
        .fallback(mock_handler)
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, mock)
}

// ---- The app under test -----------------------------------------------------

pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub json: Value,
}

impl Resp {
    pub fn error(&self) -> &str {
        self.json["error"].as_str().unwrap_or("")
    }

    pub fn retry_after(&self) -> Option<u64> {
        self.headers.get("retry-after")?.to_str().ok()?.parse().ok()
    }
}

pub struct Device {
    pub id: String,
    pub key: String,
}

pub struct Handle {
    pub id: String,
    pub secret: String,
    pub tag: String,
}

pub struct Builder {
    limits: Limits,
    proxies: Vec<IpNet>,
    environments: Vec<Env>,
    keys: Option<Keys>,
    db: Option<Db>,
}

impl Builder {
    pub fn limits(mut self, f: impl FnOnce(&mut Limits)) -> Self {
        f(&mut self.limits);
        self
    }

    pub fn proxies(mut self, nets: &[&str]) -> Self {
        self.proxies = nets.iter().map(|n| IpNet::parse(n).unwrap()).collect();
        self
    }

    pub fn environments(mut self, envs: &[Env]) -> Self {
        self.environments = envs.to_vec();
        self
    }

    pub fn keys(mut self, keys: Keys) -> Self {
        self.keys = Some(keys);
        self
    }

    pub fn db(mut self, db: Db) -> Self {
        self.db = Some(db);
        self
    }

    pub async fn build(self) -> TestApp {
        TestApp::from_builder(self).await
    }
}

pub struct TestApp {
    pub router: Router,
    pub state: AppState,
    pub clock: Clock,
    pub mock: Mock,
    pub public_key: Vec<u8>,
    pub settings: Settings,
    pub pem: String,
    pub runtime_dir: std::path::PathBuf,
    ips: AtomicU32,
}

pub fn pem_key() -> (String, Vec<u8>) {
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
        .unwrap();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref()).unwrap();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(doc.as_ref())
    );
    (pem, pair.public_key().as_ref().to_vec())
}

impl TestApp {
    pub fn builder() -> Builder {
        Builder {
            limits: Limits {
                // Four bits keep registration fast in tests.
                pow_difficulty: 4,
                // Registering junk devices is rate-limited in production; most
                // tests are not about that.
                unverified_device_per_hour: 1000,
                // Fewer extra bits when many instances register in a test.
                pow_adaptive_threshold_per_hour: 1000,
                ..Limits::default()
            },
            proxies: vec![],
            environments: vec![Env::Production, Env::Sandbox],
            keys: None,
            db: None,
        }
    }

    pub async fn new() -> TestApp {
        Self::builder().build().await
    }

    async fn from_builder(b: Builder) -> TestApp {
        let (addr, mock) = start_mock().await;
        let runtime_dir =
            std::env::temp_dir().join(format!("pp-test-{}", postal_pigeon::util::uuid_v4()));
        let url = format!("http://{addr}");
        let (pem, public_key) = pem_key();
        let settings = Settings {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir: std::env::temp_dir(),
            public_url: Some("https://pigeon.example.test".into()),
            apps: vec![
                AppConfig::parse(&format!("hedgerow={BUNDLE}")).unwrap(),
                AppConfig::parse(&format!("ferret={FERRET_BUNDLE}:sync")).unwrap(),
            ],
            environments: b.environments,
            apns: Some(ApnsSettings {
                key_path: "unused.p8".into(),
                key_id: KEY_ID.into(),
                team_id: TEAM_ID.into(),
            }),
            apns_urls: ApnsUrls {
                production: url.clone(),
                sandbox: url,
            },
            trusted_proxies: b.proxies,
            limits: b.limits,
            hmac_key_file: None,
            seal_key_file: None,
            seal_old_key_files: vec![],
            allow_no_proxy: true,
            runtime_dir: runtime_dir.clone(),
            allow_insecure_apns_urls: true,
        };
        let clock = Clock::new();
        let apns = Apns::from_pem(
            &pem,
            KEY_ID,
            TEAM_ID,
            settings.apns_urls.clone(),
            clock.clone(),
        )
        .unwrap()
        .with_retry_delay(Duration::from_millis(1))
        .with_token_dir(runtime_dir.join("postal-pigeon"));
        let state = AppState::new(
            settings.clone(),
            b.db.unwrap_or_else(|| Db::open_memory().unwrap()),
            b.keys.unwrap_or_else(Keys::ephemeral),
            clock.clone(),
            apns,
        );
        TestApp {
            router: api::router(state.clone()),
            state,
            clock,
            mock,
            public_key,
            settings,
            pem,
            runtime_dir,
            ips: AtomicU32::new(1),
        }
    }

    /// A fresh client address, so helpers don't share per-address limits.
    pub fn next_ip(&self) -> String {
        let n = self.ips.fetch_add(1, Ordering::Relaxed);
        format!("198.51.{}.{}", 100 + n / 250, n % 250 + 1)
    }

    pub async fn call_from(
        &self,
        ip: &str,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<Value>,
        forwarded_for: Option<&str>,
    ) -> Resp {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(b) = bearer {
            req = req.header("authorization", format!("Bearer {b}"));
        }
        if let Some(x) = forwarded_for {
            req = req.header("x-forwarded-for", x);
        }
        let body = match body {
            Some(v) => {
                req = req.header("content-type", "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        let mut req = req.body(body).unwrap();
        let peer: SocketAddr = format!("{ip}:40000").parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        self.finish(req).await
    }

    pub async fn raw(&self, req: Request) -> Resp {
        self.raw_from("203.0.113.10", req).await
    }

    /// A hand-made request arriving from `ip`.
    pub async fn raw_from(&self, ip: &str, req: Request) -> Resp {
        let mut req = req;
        let peer: SocketAddr = format!("{ip}:40000").parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        self.finish(req).await
    }

    async fn finish(&self, req: Request) -> Resp {
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
        let json = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Resp {
            status: parts.status,
            headers: parts.headers,
            json,
        }
    }

    /// A request from the default address.
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> Resp {
        self.call_from("203.0.113.10", method, path, bearer, body, None)
            .await
    }

    pub async fn get(&self, path: &str) -> Resp {
        self.call("GET", path, None, None).await
    }

    // ---- flows ----

    pub async fn challenge(&self) -> (String, u32) {
        self.challenge_from("203.0.113.10").await
    }

    /// A challenge fetched from the given address.
    pub async fn challenge_from(&self, ip: &str) -> (String, u32) {
        let r = self
            .call_from(ip, "GET", "/v1/challenge", None, None, None)
            .await;
        assert_eq!(r.status, 200, "{}", r.json);
        (
            r.json["challenge"].as_str().unwrap().to_string(),
            r.json["difficulty"].as_u64().unwrap() as u32,
        )
    }

    pub fn registration(&self, challenge: &str, difficulty: u32) -> Value {
        json!({
            "challenge": challenge,
            "nonce": pow::solve(challenge, difficulty),
            "product": "vigilant-vole",
            "version": "0.14.0",
        })
    }

    /// Registers an instance from a fresh address; returns its credential.
    pub async fn new_instance(&self) -> String {
        let ip = self.next_ip();
        let (c, d) = self.challenge_from(&ip).await;
        let r = self
            .call_from(
                &ip,
                "POST",
                "/v1/instances",
                None,
                Some(self.registration(&c, d)),
                None,
            )
            .await;
        assert_eq!(r.status, 201, "{}", r.json);
        r.json["instance_credential"].as_str().unwrap().to_string()
    }

    pub async fn new_device_for(&self, app: &str, env: &str, token: &str) -> Device {
        let ip = self.next_ip();
        let r = self
            .call_from(
                &ip,
                "POST",
                "/v1/devices",
                None,
                Some(json!({ "app": app, "environment": env, "token": token })),
                None,
            )
            .await;
        assert_eq!(r.status, 201, "{}", r.json);
        Device {
            id: r.json["device_id"].as_str().unwrap().to_string(),
            key: r.json["manage_key"].as_str().unwrap().to_string(),
        }
    }

    pub async fn new_device(&self, token: &str) -> Device {
        self.new_device_for("hedgerow", "production", token).await
    }

    pub async fn new_handle(&self, dev: &Device) -> Handle {
        let tag = b64(&random_bytes::<16>());
        let r = self
            .call(
                "POST",
                &format!("/v1/devices/{}/handles", dev.id),
                Some(&dev.key),
                Some(json!({ "tag": tag })),
            )
            .await;
        assert_eq!(r.status, 201, "{}", r.json);
        Handle {
            id: r.json["handle_id"].as_str().unwrap().to_string(),
            secret: r.json["handle"].as_str().unwrap().to_string(),
            tag,
        }
    }

    /// Pushes `kind` to the given handles with a fresh event id.
    pub async fn push(&self, cred: &str, handles: &[&str], kind: &str) -> Resp {
        self.push_body(
            cred,
            json!({ "event_id": postal_pigeon::util::uuid_v4(), "handles": handles, "kind": kind }),
        )
        .await
    }

    pub async fn push_body(&self, cred: &str, body: Value) -> Resp {
        self.call("POST", "/v1/push", Some(cred), Some(body)).await
    }

    /// The status of the n-th result of a push response.
    pub fn status_of(resp: &Resp, n: usize) -> String {
        resp.json["results"][n]["status"]
            .as_str()
            .unwrap_or("?")
            .to_string()
    }

    pub async fn device_exists(&self, id: &str) -> bool {
        let id = id.to_string();
        self.state
            .db
            .call(move |c| postal_pigeon::db::get_device(c, &id).unwrap().is_some())
            .await
    }
}

/// Decoded parts of an Apple provider token.
pub fn decode_jwt(bearer: &str) -> (Value, Value, String) {
    let jwt = bearer.strip_prefix("bearer ").expect("bearer scheme");
    let mut parts = jwt.split('.');
    let (h, c, s) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let dec = |p: &str| -> Value {
        serde_json::from_slice(&postal_pigeon::util::b64_decode(p).unwrap()).unwrap()
    };
    (dec(h), dec(c), format!("{h}.{c}.{s}"))
}

/// Verifies the ES256 signature of a provider token with the test key.
pub fn jwt_signature_ok(public_key: &[u8], jwt: &str) -> bool {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    let (input, sig) = jwt.rsplit_once('.').unwrap();
    let sig = postal_pigeon::util::b64_decode(sig).unwrap();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
        .verify(input.as_bytes(), &sig)
        .is_ok()
}

impl Drop for TestApp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.runtime_dir);
    }
}

/// Log lines written while a test runs.
#[derive(Clone, Default)]
pub struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogBuf {
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// Starts capturing this thread's log lines through `filter`. Keep the guard
/// alive for as long as the capture should run.
pub fn capture_logs(
    filter: tracing_subscriber::EnvFilter,
) -> (LogBuf, tracing::subscriber::DefaultGuard) {
    let buf = LogBuf::default();
    let sub = tracing_subscriber::fmt()
        .with_writer({
            let buf = buf.clone();
            move || buf.clone()
        })
        .with_ansi(false)
        .with_env_filter(filter)
        .finish();
    (buf, tracing::subscriber::set_default(sub))
}
