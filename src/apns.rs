//! The APNs client (docs/design.md sections 7 and 8).
//!
//! * Token-based authentication: an ES256 JWT signed with the `.p8` key,
//!   cached and refreshed about every 40 minutes. Apple refuses providers that
//!   refresh more often than every 20 minutes and tokens older than 60.
//! * One HTTP/2 client with a pooled, kept-alive connection, no redirects.
//! * Content-free payloads built here from validated fields only.
//! * Apple's answers are turned into [`Outcome`]s following the design's table.
//!
//! Nothing here logs a token, a tag, a reference or a handle.

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use crate::clock::Clock;
use crate::config::{ApnsSettings, ApnsUrls, Env, Kind};
use crate::util::{b64, uuid_v4};

/// A JWT is reused for this long (seconds).
const JWT_REFRESH_SECS: i64 = 40 * 60;
/// Apple refuses a new JWT sooner than this after the previous one (seconds).
const JWT_MIN_AGE_SECS: i64 = 20 * 60;
/// Consecutive transient failures that open a per-environment circuit breaker.
const BREAKER_THRESHOLD: u32 = 5;
/// How long a breaker stays open (milliseconds).
const BREAKER_OPEN_MS: i64 = 30_000;
/// Simultaneous requests toward Apple.
const MAX_INFLIGHT: usize = 200;
/// Default wait for a `429` without `Retry-After` (seconds).
const DEFAULT_RETRY_AFTER: u64 = 60;

/// Why the client couldn't be built.
#[derive(Debug)]
pub struct ApnsError(pub String);

impl fmt::Display for ApnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ApnsError {}

/// What to push, already validated.
#[derive(Debug)]
pub struct PushRequest<'a> {
    /// The device token (hex), only ever put in the request path.
    pub token: &'a str,
    pub env: Env,
    /// The app's bundle id.
    pub topic: &'a str,
    pub kind: Kind,
    /// The handle's opaque tag.
    pub tag: &'a str,
    pub reference: Option<&'a str>,
    pub collapse: Option<&'a str>,
    pub ttl_secs: i64,
}

/// What came of a push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Apple took it.
    Accepted,
    /// `410 Unregistered`, with Apple's timestamp (ms) when it gave one.
    Unregistered { timestamp_ms: Option<i64> },
    /// `BadDeviceToken` or `DeviceTokenNotForTopic`.
    BadToken,
    /// `429`: back off for this many seconds.
    TooManyRequests { retry_after: u64 },
    /// Our credentials or configuration are wrong; nothing is the device's fault.
    OperatorProblem,
    /// Apple or the network failed, or the answer was unexpected.
    Failed,
}

/// The default expiry when the instance gives no `ttl` (docs/design.md section 8).
pub fn default_ttl_secs(kind: Kind) -> i64 {
    match kind {
        Kind::Alert => 3600,
        Kind::Sync => 900,
    }
}

/// The body of the push. Fixed fields only; the `loc-key`s live in the app.
pub fn payload(kind: Kind, tag: &str, reference: Option<&str>) -> Value {
    let mut hr = json!({ "v": 1, "k": kind.as_str(), "t": tag });
    if let Some(r) = reference {
        hr["r"] = json!(r);
    }
    match kind {
        Kind::Alert => json!({
            "aps": {
                "alert": { "title-loc-key": "HR_PUSH_TITLE", "loc-key": "HR_PUSH_BODY" },
                "mutable-content": 1,
                "sound": "default",
                "thread-id": tag,
            },
            "hr": hr,
        }),
        Kind::Sync => json!({ "aps": { "content-available": 1 }, "hr": hr }),
    }
}

/// The `apns-collapse-id`: the instance's `collapse` for alerts (`a-<collapse>`),
/// the tag for syncs (`s-<tag>`), never more than 64 bytes.
pub fn collapse_id(kind: Kind, tag: &str, collapse: Option<&str>) -> Option<String> {
    let id = match (kind, collapse) {
        (Kind::Alert, Some(c)) => format!("a-{c}"),
        (Kind::Alert, None) => return None,
        (Kind::Sync, _) => format!("s-{tag}"),
    };
    Some(id.chars().take(64).collect())
}

struct Jwt {
    token: String,
    issued_secs: i64,
}

#[derive(Default)]
struct Health {
    last_ok_ms: Option<i64>,
    last_bad_ms: Option<i64>,
}

#[derive(Default, Clone, Copy)]
struct Breaker {
    failures: u32,
    open_until_ms: i64,
}

/// The client. Cheap to share behind an `Arc`.
pub struct Apns {
    key: EcdsaKeyPair,
    key_id: String,
    team_id: String,
    urls: ApnsUrls,
    client: reqwest::Client,
    clock: Clock,
    jwt: Mutex<Option<Jwt>>,
    health: Mutex<Health>,
    breakers: Mutex<[Breaker; 2]>,
    inflight: Arc<Semaphore>,
    retry_delay: Duration,
}

impl fmt::Debug for Apns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Apns")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl Apns {
    /// Reads the `.p8` key named in the settings.
    pub fn from_settings(
        settings: &ApnsSettings,
        urls: ApnsUrls,
        clock: Clock,
    ) -> Result<Apns, ApnsError> {
        let pem = read_key_pem(&settings.key_path)?;
        Apns::from_pem(&pem, &settings.key_id, &settings.team_id, urls, clock)
    }

    /// Builds the client from the text of a `.p8` file.
    pub fn from_pem(
        pem: &str,
        key_id: &str,
        team_id: &str,
        urls: ApnsUrls,
        clock: Clock,
    ) -> Result<Apns, ApnsError> {
        let der = pem_to_der(pem)?;
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der)
            .map_err(|_| ApnsError("the APNs key is not a P-256 PKCS#8 key".into()))?;
        let client = reqwest::Client::builder()
            // Apple only speaks HTTP/2, so don't even offer anything else.
            .http2_prior_knowledge()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(4))
            .pool_idle_timeout(None)
            .http2_keep_alive_interval(Duration::from_secs(60))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_keep_alive_while_idle(true)
            .user_agent(concat!("postal-pigeon/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ApnsError(format!("can't build the HTTP client: {e}")))?;
        Ok(Apns {
            key,
            key_id: key_id.to_string(),
            team_id: team_id.to_string(),
            urls,
            client,
            clock,
            jwt: Mutex::new(None),
            health: Mutex::new(Health::default()),
            breakers: Mutex::new([Breaker::default(); 2]),
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
            retry_delay: Duration::from_millis(200),
        })
    }

    /// Waits this long before the one retry of a `5xx`. For tests.
    pub fn with_retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = delay;
        self
    }

    fn sign_jwt(&self, now_secs: i64) -> Jwt {
        let header = json!({ "alg": "ES256", "kid": self.key_id });
        let claims = json!({ "iss": self.team_id, "iat": now_secs });
        let input = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        let sig = self
            .key
            .sign(&SystemRandom::new(), input.as_bytes())
            .expect("ES256 signing");
        Jwt {
            token: format!("{input}.{}", b64(sig.as_ref())),
            issued_secs: now_secs,
        }
    }

    /// The JWT to use now, and when it was issued. Reused until it is about 40
    /// minutes old.
    fn current_jwt(&self) -> (String, i64) {
        let now = self.clock.now_secs();
        let mut cached = self.jwt.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(j) = cached.as_ref()
            && now - j.issued_secs < JWT_REFRESH_SECS
        {
            return (j.token.clone(), j.issued_secs);
        }
        let fresh = self.sign_jwt(now);
        let out = (fresh.token.clone(), fresh.issued_secs);
        *cached = Some(fresh);
        out
    }

    /// After `ExpiredProviderToken` for the JWT issued at `used`: a newer JWT if
    /// one exists or Apple's 20-minute rule allows making one, else `None`.
    fn jwt_after_expired(&self, used: i64) -> Option<(String, i64)> {
        let now = self.clock.now_secs();
        let mut cached = self.jwt.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(j) = cached.as_ref() {
            if j.issued_secs > used {
                return Some((j.token.clone(), j.issued_secs));
            }
            if now - j.issued_secs < JWT_MIN_AGE_SECS {
                return None;
            }
        }
        let fresh = self.sign_jwt(now);
        let out = (fresh.token.clone(), fresh.issued_secs);
        *cached = Some(fresh);
        Some(out)
    }

    fn env_index(env: Env) -> usize {
        match env {
            Env::Production => 0,
            Env::Sandbox => 1,
        }
    }

    fn breaker_open(&self, env: Env) -> bool {
        let now = self.clock.now_ms();
        self.breakers.lock().unwrap_or_else(|e| e.into_inner())[Self::env_index(env)].open_until_ms
            > now
    }

    fn note_transient(&self, env: Env) {
        let now = self.clock.now_ms();
        {
            let mut all = self.breakers.lock().unwrap_or_else(|e| e.into_inner());
            let b = &mut all[Self::env_index(env)];
            b.failures += 1;
            if b.failures >= BREAKER_THRESHOLD {
                b.open_until_ms = now + BREAKER_OPEN_MS;
                b.failures = 0;
                tracing::warn!(env = env.as_str(), "apns_circuit_open");
            }
        }
        self.health
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_bad_ms = Some(now);
    }

    fn note_answered(&self, env: Env) {
        let now = self.clock.now_ms();
        self.breakers.lock().unwrap_or_else(|e| e.into_inner())[Self::env_index(env)].failures = 0;
        self.health
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_ok_ms = Some(now);
    }

    fn note_operator_problem(&self) {
        let now = self.clock.now_ms();
        self.health
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_bad_ms = Some(now);
    }

    /// `ok`, `degraded` or `unknown`, from recent real sends (not a call to Apple).
    pub fn status(&self) -> &'static str {
        let now = self.clock.now_ms();
        let h = self.health.lock().unwrap_or_else(|e| e.into_inner());
        let breaker_open = self
            .breakers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|b| b.open_until_ms > now);
        if breaker_open {
            return "degraded";
        }
        match (h.last_ok_ms, h.last_bad_ms) {
            (_, Some(bad)) if now - bad < 600_000 && h.last_ok_ms.is_none_or(|ok| ok < bad) => {
                "degraded"
            }
            (Some(ok), _) if now - ok < 3_600_000 => "ok",
            _ => "unknown",
        }
    }

    /// Sends one push and says what Apple (or the network) made of it.
    pub async fn send(&self, req: &PushRequest<'_>) -> Outcome {
        if self.breaker_open(req.env) {
            return Outcome::Failed;
        }
        let Ok(_permit) = self.inflight.clone().try_acquire_owned() else {
            return Outcome::Failed;
        };

        let base = match req.env {
            Env::Production => &self.urls.production,
            Env::Sandbox => &self.urls.sandbox,
        };
        let url = format!("{}/3/device/{}", base.trim_end_matches('/'), req.token);
        let body = payload(req.kind, req.tag, req.reference).to_string();
        let expiration = self.clock.now_secs() + req.ttl_secs;
        let (push_type, priority) = match req.kind {
            Kind::Alert => ("alert", "10"),
            Kind::Sync => ("background", "5"),
        };
        let collapse = collapse_id(req.kind, req.tag, req.collapse);

        let (mut jwt, mut jwt_issued) = self.current_jwt();
        let mut retried_5xx = false;
        let mut retried_jwt = false;
        loop {
            let mut builder = self
                .client
                .post(&url)
                .header("authorization", format!("bearer {jwt}"))
                .header("apns-push-type", push_type)
                .header("apns-priority", priority)
                .header("apns-topic", req.topic)
                .header("apns-expiration", expiration.to_string())
                .header("apns-id", uuid_v4())
                .header("content-type", "application/json")
                .body(body.clone());
            if let Some(c) = &collapse {
                builder = builder.header("apns-collapse-id", c);
            }

            let response = match builder.send().await {
                Ok(r) => r,
                Err(_) => {
                    if !retried_5xx {
                        retried_5xx = true;
                        tokio::time::sleep(self.retry_delay).await;
                        continue;
                    }
                    self.note_transient(req.env);
                    return Outcome::Failed;
                }
            };

            let status = response.status().as_u16();
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok());
            let answer: Value = if status == 200 {
                Value::Null
            } else {
                response.json().await.unwrap_or(Value::Null)
            };
            let reason = answer.get("reason").and_then(Value::as_str).unwrap_or("");

            match status {
                200 => {
                    self.note_answered(req.env);
                    return Outcome::Accepted;
                }
                410 => {
                    self.note_answered(req.env);
                    return Outcome::Unregistered {
                        timestamp_ms: answer.get("timestamp").and_then(Value::as_i64),
                    };
                }
                400 if matches!(reason, "BadDeviceToken" | "DeviceTokenNotForTopic") => {
                    self.note_answered(req.env);
                    return Outcome::BadToken;
                }
                403 if reason == "ExpiredProviderToken" && !retried_jwt => {
                    retried_jwt = true;
                    match self.jwt_after_expired(jwt_issued) {
                        Some((t, i)) => {
                            jwt = t;
                            jwt_issued = i;
                            continue;
                        }
                        None => {
                            tracing::error!("apns_expired_provider_token");
                            self.note_operator_problem();
                            return Outcome::OperatorProblem;
                        }
                    }
                }
                403 => {
                    // InvalidProviderToken, MissingProviderToken, BadCertificate*,
                    // Forbidden: our key or team, never the device's fault.
                    tracing::error!(reason = %safe_reason(reason), "apns_operator_problem");
                    self.note_operator_problem();
                    return Outcome::OperatorProblem;
                }
                429 => {
                    self.note_answered(req.env);
                    return Outcome::TooManyRequests {
                        retry_after: retry_after.unwrap_or(DEFAULT_RETRY_AFTER).clamp(1, 3600),
                    };
                }
                500..=599 => {
                    if !retried_5xx {
                        retried_5xx = true;
                        tokio::time::sleep(self.retry_delay).await;
                        continue;
                    }
                    self.note_transient(req.env);
                    return Outcome::Failed;
                }
                _ => {
                    // 413 and any other 4xx: a bug in the relay.
                    tracing::error!(status, reason = %safe_reason(reason), "apns_unexpected_answer");
                    self.note_answered(req.env);
                    return Outcome::Failed;
                }
            }
        }
    }
}

/// Apple's `reason` is a short fixed word; still, never log anything odd.
fn safe_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(40)
        .collect()
}

fn read_key_pem(path: &Path) -> Result<String, ApnsError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(meta) = std::fs::metadata(path)
            && meta.permissions().mode() & 0o077 != 0
        {
            tracing::warn!(
                "{} is readable by other users; use mode 0400 or 0600",
                path.display()
            );
        }
    }
    std::fs::read_to_string(path)
        .map_err(|e| ApnsError(format!("can't read the APNs key {}: {e}", path.display())))
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, ApnsError> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    STANDARD
        .decode(body)
        .map_err(|_| ApnsError("the APNs key file is not PEM".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_payload_matches_the_design() {
        let p = payload(Kind::Alert, "TAG", Some("inc_1"));
        assert_eq!(
            p,
            json!({
                "aps": {
                    "alert": { "title-loc-key": "HR_PUSH_TITLE", "loc-key": "HR_PUSH_BODY" },
                    "mutable-content": 1,
                    "sound": "default",
                    "thread-id": "TAG"
                },
                "hr": { "v": 1, "k": "alert", "t": "TAG", "r": "inc_1" }
            })
        );
    }

    #[test]
    fn sync_payload_is_silent() {
        let p = payload(Kind::Sync, "TAG", None);
        assert_eq!(
            p,
            json!({
                "aps": { "content-available": 1 },
                "hr": { "v": 1, "k": "sync", "t": "TAG" }
            })
        );
    }

    #[test]
    fn collapse_ids() {
        assert_eq!(
            collapse_id(Kind::Alert, "T", Some("x")).as_deref(),
            Some("a-x")
        );
        assert_eq!(collapse_id(Kind::Alert, "T", None), None);
        assert_eq!(
            collapse_id(Kind::Sync, "T", Some("x")).as_deref(),
            Some("s-T")
        );
        let long = "c".repeat(100);
        assert!(collapse_id(Kind::Alert, "T", Some(&long)).unwrap().len() <= 64);
    }

    #[test]
    fn pem_is_unwrapped() {
        let der =
            pem_to_der("-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n").unwrap();
        assert_eq!(der, vec![1, 2, 3]);
        assert!(pem_to_der("-----BEGIN-----\n!!!\n-----END-----").is_err());
    }
}
