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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use reqwest::header::HeaderValue;
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

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
/// File names in the token directory (see `Apns::with_token_dir`).
const TOKEN_FILE: &str = "apns-token.json";
const LOCK_FILE: &str = "apns-token.lock";

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
///
/// The reason strings come from Apple's "Handling notification responses from
/// APNs" (https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns):
/// 400 BadDeviceToken, DeviceTokenNotForTopic, BadTopic, TopicDisallowed;
/// 403 ExpiredProviderToken, InvalidProviderToken, MissingProviderToken, Forbidden,
/// BadCertificate, BadCertificateEnvironment; 410 Unregistered (and ExpiredToken);
/// 429 TooManyRequests (one device token) and TooManyProviderTokenUpdates (the
/// provider token was refreshed too often, which concerns the whole relay);
/// 500/503 InternalServerError, ServiceUnavailable, Shutdown. Apple's page is
/// rendered by script, so the list was also checked against the open-source
/// `a2` crate's `ErrorReason`, which mirrors it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Apple took it.
    Accepted,
    /// `410` (`Unregistered`, `ExpiredToken`), with Apple's timestamp (ms) when it gave one.
    Unregistered { timestamp_ms: Option<i64> },
    /// `BadDeviceToken` or `DeviceTokenNotForTopic`: a strike for the device,
    /// unless they come from many devices at once (see `guard`).
    BadToken,
    /// `BadTopic` or `TopicDisallowed`: the relay's bundle id or key doesn't
    /// fit. Never the device's fault.
    ConfigError(String),
    /// `429 TooManyRequests`: back off from this device for this many seconds.
    TooManyRequests { retry_after: u64 },
    /// A `429` about the whole relay (`TooManyProviderTokenUpdates`, or a
    /// reason we don't know): nothing is sent to Apple for this many seconds.
    RelayBackoff { retry_after: u64 },
    /// Our credentials are wrong; nothing is the device's fault.
    OperatorProblem(String),
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
    /// Where the provider token is shared with other processes (the admin commands).
    token_dir: Option<PathBuf>,
    /// No request goes to Apple before this time (ms): a relay-wide `429`.
    block_until_ms: AtomicI64,
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
            token_dir: None,
            block_until_ms: AtomicI64::new(0),
        })
    }

    /// Waits this long before the one retry of a `5xx`. For tests.
    pub fn with_retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = delay;
        self
    }

    /// Shares the provider token through files in `dir` (mode 0600, ideally a
    /// tmpfs): the relay and the admin commands then use one token instead of
    /// each minting its own, which Apple limits to one per 20 minutes.
    ///
    /// The folder must be a real directory (not a link) that only this user can
    /// enter, else it is not used and every process makes its own token: a
    /// predictable folder in a shared temp directory could otherwise be made by
    /// someone else first, to read the token or to plant one.
    pub fn with_token_dir(mut self, dir: PathBuf) -> Self {
        match std::fs::create_dir_all(&dir).and_then(|()| private_dir(&dir)) {
            Ok(()) => self.token_dir = Some(dir),
            Err(e) => tracing::warn!(error = %e, "apns_token_dir_unusable"),
        }
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

    /// The newest provider token this process or another one (the admin
    /// commands run in their own process) has stored in the shared token file.
    fn load_shared(&self) -> Option<Jwt> {
        let dir = self.token_dir.as_ref()?;
        let text = std::fs::read_to_string(dir.join(TOKEN_FILE)).ok()?;
        let v: Value = serde_json::from_str(&text).ok()?;
        // Only a token for this key and team counts.
        if v["kid"].as_str()? != self.key_id || v["iss"].as_str()? != self.team_id {
            return None;
        }
        Some(Jwt {
            token: v["token"].as_str()?.to_string(),
            issued_secs: v["issued"].as_i64()?,
        })
    }

    fn store_shared(&self, jwt: &Jwt) {
        let Some(dir) = self.token_dir.as_ref() else {
            return;
        };
        let body = json!({
            "kid": self.key_id, "iss": self.team_id,
            "token": jwt.token, "issued": jwt.issued_secs,
        });
        let tmp = dir.join(format!("{TOKEN_FILE}.tmp"));
        let result = write_private(&tmp, body.to_string().as_bytes())
            .and_then(|()| std::fs::rename(&tmp, dir.join(TOKEN_FILE)));
        if result.is_err() {
            tracing::warn!("apns_token_file_unwritable");
        }
    }

    /// Takes the cross-process lock that keeps two processes from minting
    /// provider tokens at the same moment (Apple refuses updates more often
    /// than every 20 minutes). `None` without a token directory or lock.
    fn lock_tokens(&self) -> Option<std::fs::File> {
        let dir = self.token_dir.as_ref()?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(LOCK_FILE))
            .ok()?;
        file.lock().ok()?;
        Some(file)
    }

    /// The JWT to use now, and when it was issued. Reused until it is about 40
    /// minutes old; a newer one stored by another process is used instead of
    /// minting.
    fn current_jwt(&self) -> (String, i64) {
        let now = self.clock.now_secs();
        let mut cached = self.jwt.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(j) = cached.as_ref()
            && now - j.issued_secs < JWT_REFRESH_SECS
        {
            return (j.token.clone(), j.issued_secs);
        }
        let _lock = self.lock_tokens();
        if let Some(shared) = self.load_shared()
            && now - shared.issued_secs < JWT_REFRESH_SECS
            && shared.issued_secs <= now + 60
        {
            let out = (shared.token.clone(), shared.issued_secs);
            *cached = Some(shared);
            return out;
        }
        let fresh = self.sign_jwt(now);
        self.store_shared(&fresh);
        let out = (fresh.token.clone(), fresh.issued_secs);
        *cached = Some(fresh);
        out
    }

    /// After `ExpiredProviderToken` for the JWT issued at `used`: a newer JWT if
    /// one exists or Apple's 20-minute rule allows making one, else `None`.
    fn jwt_after_expired(&self, used: i64) -> Option<(String, i64)> {
        let now = self.clock.now_secs();
        let mut cached = self.jwt.lock().unwrap_or_else(|e| e.into_inner());
        let _lock = self.lock_tokens();
        let newest = [cached.take(), self.load_shared()]
            .into_iter()
            .flatten()
            .max_by_key(|j| j.issued_secs);
        if let Some(j) = newest {
            if j.issued_secs > used {
                let out = (j.token.clone(), j.issued_secs);
                *cached = Some(j);
                return Some(out);
            }
            if now - j.issued_secs < JWT_MIN_AGE_SECS {
                *cached = Some(j);
                return None;
            }
        }
        let fresh = self.sign_jwt(now);
        self.store_shared(&fresh);
        let out = (fresh.token.clone(), fresh.issued_secs);
        *cached = Some(fresh);
        Some(out)
    }

    /// Seconds until Apple would accept a new provider token (20 minutes after
    /// the newest one), at least `floor`.
    fn token_update_wait(&self, floor: u64) -> u64 {
        let now = self.clock.now_secs();
        let newest = [
            self.jwt
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|j| Jwt {
                    token: String::new(),
                    issued_secs: j.issued_secs,
                }),
            self.load_shared(),
        ]
        .into_iter()
        .flatten()
        .map(|j| j.issued_secs)
        .max();
        let wait = newest.map_or(0, |i| (i + JWT_MIN_AGE_SECS - now).max(0) as u64);
        wait.max(floor)
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
        if breaker_open || self.block_until_ms.load(Ordering::Relaxed) > now {
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

    /// Stops all requests to Apple for `secs` seconds.
    fn block_for(&self, secs: u64) {
        let until = self.clock.now_ms() + (secs as i64) * 1000;
        self.block_until_ms.fetch_max(until, Ordering::Relaxed);
    }

    /// Sends one push and says what Apple (or the network) made of it.
    pub async fn send(&self, req: &PushRequest<'_>) -> Outcome {
        let blocked = self.block_until_ms.load(Ordering::Relaxed) - self.clock.now_ms();
        if blocked > 0 {
            return Outcome::RelayBackoff {
                retry_after: (blocked as u64).div_ceil(1000),
            };
        }
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
            // The provider token is a bearer credential: mark it sensitive so
            // no Debug output or log level of the HTTP stack prints it.
            let Ok(mut auth) = HeaderValue::from_str(&format!("bearer {jwt}")) else {
                return Outcome::Failed;
            };
            auth.set_sensitive(true);
            let mut builder = self
                .client
                .post(&url)
                .header("authorization", auth)
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
            let reason = safe_reason(answer.get("reason").and_then(Value::as_str).unwrap_or(""));

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
                400 if matches!(reason.as_str(), "BadDeviceToken" | "DeviceTokenNotForTopic") => {
                    self.note_answered(req.env);
                    return Outcome::BadToken;
                }
                400 if matches!(reason.as_str(), "BadTopic" | "TopicDisallowed") => {
                    tracing::error!(reason = %reason, "apns_topic_rejected");
                    self.note_operator_problem();
                    return Outcome::ConfigError(reason);
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
                            return Outcome::OperatorProblem(reason);
                        }
                    }
                }
                403 => {
                    // InvalidProviderToken, MissingProviderToken, BadCertificate*,
                    // Forbidden: our key or team, never the device's fault.
                    tracing::error!(reason = %reason, "apns_operator_problem");
                    self.note_operator_problem();
                    return Outcome::OperatorProblem(reason);
                }
                429 if reason == "TooManyRequests" => {
                    self.note_answered(req.env);
                    return Outcome::TooManyRequests {
                        retry_after: retry_after.unwrap_or(DEFAULT_RETRY_AFTER).clamp(1, 3600),
                    };
                }
                429 => {
                    // TooManyProviderTokenUpdates, or a reason we do not know:
                    // about the relay as a whole, so every device waits. For the
                    // token updates, wait out Apple's 20-minute rule.
                    let wait = if reason == "TooManyProviderTokenUpdates" {
                        self.token_update_wait(DEFAULT_RETRY_AFTER)
                    } else {
                        retry_after.unwrap_or(DEFAULT_RETRY_AFTER)
                    }
                    .clamp(1, 3600);
                    tracing::error!(reason = %reason, wait, "apns_relay_wide_429");
                    self.note_operator_problem();
                    self.block_for(wait);
                    return Outcome::RelayBackoff { retry_after: wait };
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
                    tracing::error!(status, reason = %reason, "apns_unexpected_answer");
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

/// Makes sure `dir` is a directory this user owns and nobody else can enter:
/// not a symbolic link, and (on Unix) mode 0700 after we set it, which fails
/// for a directory somebody else owns.
fn private_dir(dir: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(std::io::Error::other("not a plain directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        if std::fs::metadata(dir)?.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::other("others can enter the directory"));
        }
    }
    Ok(())
}

/// Writes a file only the owner can read.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

fn read_key_pem(path: &Path) -> Result<Zeroizing<String>, ApnsError> {
    crate::crypto::check_key_mode(path).map_err(|e| ApnsError(e.0))?;
    std::fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|e| ApnsError(format!("can't read the APNs key {}: {e}", path.display())))
}

fn pem_to_der(pem: &str) -> Result<Zeroizing<Vec<u8>>, ApnsError> {
    let body: Zeroizing<String> = Zeroizing::new(
        pem.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("-----"))
            .collect(),
    );
    STANDARD
        .decode(body.as_bytes())
        .map(Zeroizing::new)
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

    #[cfg(unix)]
    #[test]
    fn the_token_dir_must_be_a_real_private_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let base = std::env::temp_dir().join(format!("pp-dir-{}", uuid_v4()));
        std::fs::create_dir_all(&base).unwrap();

        // A directory that is ours is closed to others.
        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(private_dir(&real).is_ok());
        let mode = std::fs::metadata(&real).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        // A link, even to a good directory, is not followed, and neither is a file.
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(private_dir(&link).is_err());
        let file = base.join("file");
        std::fs::write(&file, "x").unwrap();
        assert!(private_dir(&file).is_err());
        assert!(private_dir(&base.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn pem_is_unwrapped() {
        let der =
            pem_to_der("-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n").unwrap();
        assert_eq!(*der, vec![1, 2, 3]);
        assert!(pem_to_der("-----BEGIN-----\n!!!\n-----END-----").is_err());
    }
}
