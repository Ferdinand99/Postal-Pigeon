//! Sending (docs/design.md section 6.4).
//!
//! The relay sees an instance and a handle together only inside one request. It
//! stores no pair: usage is counted per instance, limits per handle, device and
//! app, and the "already sent" memory holds only a hash of the three ids.

use std::collections::HashSet;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use futures_util::future::join_all;
use serde::Deserialize;
use serde_json::{Value, json};

use super::instances::authenticate;
use super::{ApiError, ApiJson, ApiResult, ClientAddr};
use crate::apns::{Outcome, PushRequest, default_ttl_secs};
use crate::config::{Env, Kind};
use crate::crypto::{PREFIX_HANDLE, ct_eq, parse_id_secret, sha256};
use crate::db::{self, DeviceRow, HandleRow, InstanceRow, Usage};
use crate::state::AppState;
use crate::util::is_uuid;

/// The relay answers within about this long (design section 6.4).
const SEND_DEADLINE: Duration = Duration::from_secs(5);
/// Strikes in a row (`BadDeviceToken`) that delete a device.
const MAX_STRIKES: i64 = 3;

#[derive(Deserialize)]
pub struct PushBody {
    event_id: String,
    handles: Vec<String>,
    kind: String,
    #[serde(rename = "ref")]
    reference: Option<String>,
    collapse: Option<String>,
    ttl: Option<i64>,
}

/// The result for one handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Accepted,
    Duplicate,
    Gone,
    Limited(u64),
    Unavailable(Option<u64>),
    UnsupportedKind,
}

impl Status {
    fn to_json(&self) -> Value {
        match self {
            Status::Accepted => json!({ "status": "accepted" }),
            Status::Duplicate => json!({ "status": "duplicate" }),
            Status::Gone => json!({ "status": "gone" }),
            Status::Limited(s) => json!({ "status": "limited", "retry_after": s }),
            Status::Unavailable(Some(s)) => json!({ "status": "unavailable", "retry_after": s }),
            Status::Unavailable(None) => json!({ "status": "unavailable" }),
            Status::UnsupportedKind => json!({ "status": "unsupported_kind" }),
        }
    }
}

fn id_chars_ok(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// What to send to a device.
pub struct Message<'a> {
    pub kind: Kind,
    pub reference: Option<&'a str>,
    pub collapse: Option<&'a str>,
    pub ttl_secs: i64,
    /// What the collapse id is scoped to (the handle id, or the device id for an
    /// admin test), so one server's `collapse` can't replace another's.
    pub scope: &'a str,
}

/// Hands one push to Apple for `device` and applies what Apple says to the
/// database (`410` and strikes delete the device). No limits are checked here.
pub async fn deliver(state: &AppState, device: &DeviceRow, tag: &str, msg: &Message<'_>) -> Status {
    let Some(app) = state.settings.app(&device.app) else {
        return Status::Gone;
    };
    let Some(env) = Env::parse(&device.environment) else {
        return Status::Unavailable(None);
    };
    let Ok(token) = state
        .keys
        .open(&device.seal_key_id, &device.token_sealed, &device.id)
    else {
        tracing::error!("token_unreadable");
        return Status::Unavailable(None);
    };
    let Ok(token) = String::from_utf8(token) else {
        return Status::Unavailable(None);
    };

    // What Apple sees as the collapse id is a keyed hash, never the raw value.
    let collapse = msg
        .collapse
        .map(|c| state.keys.scoped_collapse(msg.scope, c));
    let outcome = state
        .apns
        .send(&PushRequest {
            token: &token,
            env,
            topic: &app.bundle_id,
            kind: msg.kind,
            tag,
            reference: msg.reference,
            collapse: collapse.as_deref(),
            ttl_secs: msg.ttl_secs,
        })
        .await;

    let id = device.id.clone();
    match outcome {
        Outcome::Accepted => {
            state.guard.record_ok(&app.id, &device.id);
            let day = state.clock.today();
            let _ = state.db.call(move |c| db::mark_verified(c, &id, day)).await;
            Status::Accepted
        }
        Outcome::Unregistered { timestamp_ms } => {
            state.guard.record_ok(&app.id, &device.id);
            let ts = timestamp_ms.unwrap_or(i64::MAX);
            let _ = state
                .db
                .call(move |c| db::delete_device_unregistered(c, &id, ts))
                .await;
            Status::Gone
        }
        Outcome::BadToken => {
            // Feed the breaker first: if many devices answer like this at once
            // the fault is ours, and nobody is struck or deleted.
            state.guard.record_bad(&app.id, &device.id);
            if state.guard.is_tripped() {
                return Status::Unavailable(None);
            }
            let strikes = state
                .db
                .call(move |c| {
                    let n = db::add_strike(c, &id)?;
                    if n >= MAX_STRIKES {
                        db::delete_device(c, &id)?;
                    }
                    Ok::<_, rusqlite::Error>(n)
                })
                .await
                .unwrap_or(0);
            if strikes >= MAX_STRIKES {
                Status::Gone
            } else {
                Status::Unavailable(None)
            }
        }
        Outcome::ConfigError(_) => {
            // The relay's own bundle id or key: counts toward the breaker, never
            // against the device.
            state.guard.record_bad(&app.id, &device.id);
            Status::Unavailable(None)
        }
        Outcome::TooManyRequests { retry_after } => {
            state.set_backoff(&device.id, retry_after);
            Status::Limited(retry_after)
        }
        Outcome::RelayBackoff { retry_after } => Status::Unavailable(Some(retry_after)),
        Outcome::OperatorProblem(_) | Outcome::Failed => Status::Unavailable(None),
    }
}

/// The key under which a delivered push is remembered for 15 minutes.
fn event_key(instance: &str, event: &str, handle: &str) -> [u8; 16] {
    let mut input = Vec::new();
    for part in [instance, event, handle] {
        input.extend_from_slice(part.as_bytes());
        input.push(0);
    }
    sha256(&input)[..16].try_into().expect("16 bytes")
}

/// Looks up a presented handle. `None` for an unknown, revoked or malformed
/// one, with no way to tell which.
fn resolve(
    c: &rusqlite::Connection,
    presented: &str,
) -> rusqlite::Result<Option<(HandleRow, DeviceRow)>> {
    let Some((id, hash)) = parse_id_secret(PREFIX_HANDLE, presented) else {
        return Ok(None);
    };
    Ok(db::get_handle_with_device(c, &id)?.filter(|(h, _)| ct_eq(&h.hash, &hash)))
}

/// What a presented handle turned out to be.
enum Resolved {
    /// The same string appeared earlier in this request.
    Repeat,
    /// Unknown, revoked or malformed (indistinguishable on purpose).
    Unknown,
    Found(Box<(HandleRow, DeviceRow)>),
}

impl From<Option<(HandleRow, DeviceRow)>> for Resolved {
    fn from(r: Option<(HandleRow, DeviceRow)>) -> Self {
        match r {
            Some(pair) => Resolved::Found(Box::new(pair)),
            None => Resolved::Unknown,
        }
    }
}

/// Records a throttled request, and suspends the instance past the daily limit.
async fn note_throttled(state: &AppState, inst: &InstanceRow, flag: bool) {
    let day = state.clock.today();
    let limit = i64::from(state.settings.limits.auto_suspend_throttled_per_day);
    let id = inst.id.clone();
    let _ = state
        .db
        .call(move |c| {
            let total = db::add_usage(
                c,
                &id,
                day,
                Usage {
                    throttled: 1,
                    ..Usage::default()
                },
            )?;
            if flag || total > limit {
                db::flag_instance(c, &id)?;
            }
            if total > limit {
                db::set_instance_state(c, &id, "suspended")?;
                tracing::warn!("instance_auto_suspended");
            }
            Ok::<_, rusqlite::Error>(())
        })
        .await;
}

/// `POST /v1/push`
pub async fn push(
    State(state): State<AppState>,
    addr: ClientAddr,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PushBody>,
) -> ApiResult<impl IntoResponse> {
    let inst = authenticate(&state, &headers, &addr).await?;
    let limits = &state.settings.limits;

    // Validate the request.
    if !is_uuid(&body.event_id) {
        return Err(ApiError::invalid("event_id must be a UUID"));
    }
    if body.handles.is_empty() || body.handles.len() > limits.max_handles_per_request {
        return Err(ApiError::invalid(format!(
            "handles must hold 1 to {} handles",
            limits.max_handles_per_request
        )));
    }
    if body.handles.iter().any(|h| h.len() > 128) {
        return Err(ApiError::invalid("a handle is too long"));
    }
    let kind =
        Kind::parse(&body.kind).ok_or_else(|| ApiError::invalid("kind must be alert or sync"))?;
    if let Some(r) = &body.reference
        && !id_chars_ok(r, 64)
    {
        return Err(ApiError::invalid(
            "ref is at most 64 characters of A-Z a-z 0-9 _ -",
        ));
    }
    if let Some(c) = &body.collapse
        && !id_chars_ok(c, 32)
    {
        return Err(ApiError::invalid(
            "collapse is at most 32 characters of A-Z a-z 0-9 _ -",
        ));
    }
    let ttl = match body.ttl {
        None => default_ttl_secs(kind),
        Some(t) if (60..=86_400).contains(&t) => t,
        Some(_) => return Err(ApiError::invalid("ttl is 60 to 86400 seconds")),
    };

    // A handle listed twice in one request counts and is sent once; the repeats
    // answer `duplicate`.
    let mut seen = HashSet::new();
    let first: Vec<bool> = body
        .handles
        .iter()
        .map(|h| seen.insert(h.as_str()))
        .collect();

    // The instance's own limit, by tier: one send per distinct handle.
    let n = first.iter().filter(|f| **f).count() as u32;
    let tier_limiter = if inst.tier == "established" {
        &state.limiters.instance_established
    } else {
        &state.limiters.instance_new
    };
    if let Err(wait) = tier_limiter.take_n(&inst.id, n) {
        note_throttled(&state, &inst, false).await;
        return Err(ApiError::rate_limited(wait));
    }

    // Resolve every handle first, so an enumeration attempt is stopped before
    // anything is sent. If the unknown ones are more than the instance's hourly
    // allowance, the whole request is refused and nothing is sent.
    let presented = body.handles.clone();
    let wanted = first.clone();
    let resolved = state
        .db
        .call(move |c| {
            presented
                .iter()
                .zip(wanted)
                .map(|(p, first)| {
                    if first {
                        resolve(c, p).map(Resolved::from)
                    } else {
                        Ok(Resolved::Repeat)
                    }
                })
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .await?;
    let unknown = resolved
        .iter()
        .filter(|r| matches!(r, Resolved::Unknown))
        .count() as u32;
    if unknown > 0
        && let Err(wait) = state.limiters.unknown_handles.take_n(&inst.id, unknown)
    {
        note_throttled(&state, &inst, true).await;
        return Err(ApiError::rate_limited(wait));
    }

    let mut results: Vec<Option<Status>> = vec![None; resolved.len()];
    let mut to_send: Vec<(usize, HandleRow, DeviceRow)> = Vec::new();
    let (handle_limiter, device_limiter) = match kind {
        Kind::Alert => (&state.limiters.alert_handle, &state.limiters.alert_device),
        Kind::Sync => (&state.limiters.sync_handle, &state.limiters.sync_device),
    };
    for (i, r) in resolved.into_iter().enumerate() {
        let (handle, device) = match r {
            Resolved::Repeat => {
                results[i] = Some(Status::Duplicate);
                continue;
            }
            Resolved::Unknown => {
                results[i] = Some(Status::Gone);
                continue;
            }
            Resolved::Found(pair) => *pair,
        };
        let Some(app) = state.settings.app(&device.app) else {
            results[i] = Some(Status::Gone);
            continue;
        };
        if !app.kinds.contains(&kind) {
            results[i] = Some(Status::UnsupportedKind);
            continue;
        }
        let key = event_key(&inst.id, &body.event_id, &handle.id);
        if state.events.contains(&key) {
            results[i] = Some(Status::Duplicate);
            continue;
        }
        if let Some(left) = state.backoff_left(&device.id) {
            results[i] = Some(Status::Limited(left));
            continue;
        }
        // A device that Apple has never accepted a push for gets a small quota
        // until one succeeds, so registering junk tokens does not turn the
        // relay into a way to hammer Apple with them.
        if !device.verified
            && let Err(wait) = state.limiters.unverified_device.take(&device.id)
        {
            results[i] = Some(Status::Limited(wait));
            continue;
        }
        if let Err(wait) = handle_limiter.take(&handle.id) {
            results[i] = Some(Status::Limited(wait));
            continue;
        }
        if let Err(wait) = device_limiter.has(&device.id, 1) {
            results[i] = Some(Status::Limited(wait));
            continue;
        }
        let _ = device_limiter.take(&device.id);
        if let Err(wait) = state.limiters.app_sends.take(&app.id) {
            results[i] = Some(Status::Unavailable(Some(wait)));
            continue;
        }
        // Claim the event before sending, so a concurrent request with the same
        // event id sees `duplicate` instead of sending a second push. A claim
        // that does not end in `accepted` is released below. A full set drops
        // its oldest entry rather than stop deduplicating.
        if !state.events.insert_evicting(key) {
            results[i] = Some(Status::Duplicate);
            continue;
        }
        to_send.push((i, handle, device));
    }

    // Send, concurrently, each within the deadline.
    let sends = to_send.iter().map(|(_, handle, device)| {
        let state = &state;
        let msg = Message {
            kind,
            reference: body.reference.as_deref(),
            collapse: body.collapse.as_deref(),
            ttl_secs: ttl,
            scope: &handle.id,
        };
        async move {
            tokio::time::timeout(SEND_DEADLINE, deliver(state, device, &handle.tag, &msg))
                .await
                .unwrap_or(Status::Unavailable(None))
        }
    });
    let outcomes = join_all(sends).await;

    let day = state.clock.today();
    let mut used: Vec<String> = Vec::new();
    for ((i, handle, _), status) in to_send.iter().zip(outcomes) {
        if status == Status::Accepted {
            used.push(handle.id.clone());
        } else {
            // Not delivered: the same event may be tried again.
            state
                .events
                .remove(&event_key(&inst.id, &body.event_id, &handle.id));
        }
        results[*i] = Some(status);
    }

    let statuses: Vec<Status> = results
        .into_iter()
        .map(|r| r.unwrap_or(Status::Unavailable(None)))
        .collect();
    let usage = Usage {
        sends: statuses.iter().filter(|s| **s == Status::Accepted).count() as i64,
        limited: statuses
            .iter()
            .filter(|s| matches!(s, Status::Limited(_)))
            .count() as i64,
        failures: statuses
            .iter()
            .filter(|s| matches!(s, Status::Unavailable(_)))
            .count() as i64,
        throttled: 0,
    };
    let id = inst.id.clone();
    let _ = state
        .db
        .call(move |c| {
            for h in &used {
                db::touch_handle_used(c, h, day)?;
            }
            db::add_usage(c, &id, day, usage)
        })
        .await;

    Ok(Json(json!({
        "results": statuses.iter().map(Status::to_json).collect::<Vec<_>>(),
    })))
}
