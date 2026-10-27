//! Instance registration and management (docs/design.md section 6.1).

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;

use super::{ApiError, ApiJson, ApiResult, ClientAddr, bearer};
use crate::crypto::{PREFIX_INSTANCE, ct_eq, new_id_secret, new_secret_for, parse_id_secret};
use crate::db::{self, InstanceRow};
use crate::pow::{self, PowError};
use crate::state::AppState;
use crate::util::{DAY_SECS, addr_prefix, rfc3339};

/// The products that may register (informational only; not an identity proof).
pub const PRODUCTS: [&str; 4] = [
    "vigilant-vole",
    "keen-kestrel",
    "wise-wren",
    "faithful-ferret",
];

/// `GET /v1/challenge`
pub async fn challenge(State(state): State<AppState>) -> impl IntoResponse {
    let limits = &state.settings.limits;
    let (challenge, expires) = pow::issue(&state.keys, &state.clock, limits.challenge_ttl_secs);
    Json(json!({
        "challenge": challenge,
        "difficulty": limits.pow_difficulty,
        "expires_at": rfc3339(expires),
    }))
}

#[derive(Deserialize)]
pub struct RegisterBody {
    challenge: String,
    nonce: String,
    product: String,
    #[serde(default)]
    version: String,
}

fn valid_version(v: &str) -> bool {
    v.len() <= 32
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'+' | b'-'))
}

/// `POST /v1/instances`
pub async fn register(
    State(state): State<AppState>,
    addr: ClientAddr,
    ApiJson(body): ApiJson<RegisterBody>,
) -> ApiResult<impl IntoResponse> {
    if !PRODUCTS.contains(&body.product.as_str()) {
        return Err(ApiError::invalid("unknown product"));
    }
    if !valid_version(&body.version) {
        return Err(ApiError::invalid(
            "version is at most 32 characters of A-Z a-z 0-9 . _ + -",
        ));
    }

    let limits = &state.settings.limits;
    let id = pow::verify(
        &state.keys,
        &state.clock,
        limits.challenge_ttl_secs,
        limits.pow_difficulty,
        &body.challenge,
        &body.nonce,
    )
    .map_err(|e| match e {
        PowError::Invalid => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_challenge",
            "the challenge was not issued by this relay",
        ),
        PowError::Expired => ApiError::new(
            StatusCode::BAD_REQUEST,
            "challenge_expired",
            "the challenge has expired; fetch a new one",
        ),
        PowError::BadProof => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "the nonce does not meet the difficulty",
        ),
    })?;
    match state.challenges.insert(id) {
        Ok(true) => {}
        Ok(false) => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "challenge_used",
                "the challenge was already used; fetch a new one",
            ));
        }
        Err(_) => return Err(ApiError::overloaded(60)),
    }

    state
        .limiters
        .instance_reg_addr
        .take(&addr.key())
        .map_err(ApiError::rate_limited)?;

    let today = state.clock.today();
    let per_day = i64::from(limits.instance_reg_per_day);
    let credential = {
        let cred = new_id_secret(PREFIX_INSTANCE);
        let prefix = addr_prefix(addr.0);
        let (c, product, version) = (cred.clone(), body.product, body.version);
        let created = state
            .db
            .call(move |conn| {
                if db::count_instances_created_on(conn, today)? >= per_day {
                    return Ok(false);
                }
                db::insert_instance(conn, &c.id, &c.hash, &product, &version, today, &prefix)?;
                Ok::<_, rusqlite::Error>(true)
            })
            .await?;
        if !created {
            let until_midnight = (today + 1) * DAY_SECS - state.clock.now_secs();
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "registration_closed",
                "today's registrations are used up; try again after midnight UTC",
            )
            .with_retry_after(until_midnight as u64));
        }
        cred.full
    };

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "instance_credential": credential,
            "tier": "new",
            "limits": {
                "sends_per_hour": limits.send_per_instance_hour_new,
                "handles_per_request": limits.max_handles_per_request,
                "unknown_handles_per_hour": limits.unknown_handles_per_instance_hour,
            },
        })),
    ))
}

/// Checks the instance credential in `Authorization`. Wrong credentials count
/// against the caller's address.
pub(super) async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    addr: &ClientAddr,
) -> ApiResult<InstanceRow> {
    let key = addr.key();
    state
        .limiters
        .auth_failures
        .has(&key, 1)
        .map_err(ApiError::rate_limited)?;
    let fail = || {
        let _ = state.limiters.auth_failures.take(&key);
        ApiError::invalid_credentials()
    };

    let presented = bearer(headers).ok_or_else(fail)?;
    let (id, hash) = parse_id_secret(PREFIX_INSTANCE, presented).ok_or_else(fail)?;
    let lookup = id.clone();
    let row = state
        .db
        .call(move |c| db::get_instance(c, &lookup))
        .await?
        .ok_or_else(ApiError::unknown_instance)?;
    if !ct_eq(&row.hash, &hash) {
        return Err(fail());
    }
    if row.state != "active" {
        return Err(ApiError::suspended());
    }
    let today = state.clock.today();
    if row.last_used_day < today {
        state
            .db
            .call(move |c| db::touch_instance(c, &id, today))
            .await?;
    }
    Ok(row)
}

/// `POST /v1/instances/self/rotate`
pub async fn rotate(
    State(state): State<AppState>,
    addr: ClientAddr,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let inst = authenticate(&state, &headers, &addr).await?;
    let fresh = new_secret_for(PREFIX_INSTANCE, &inst.id);
    let (id, hash) = (inst.id, fresh.hash);
    state
        .db
        .call(move |c| db::set_instance_hash(c, &id, &hash))
        .await?;
    Ok(Json(json!({ "instance_credential": fresh.full })))
}

/// `DELETE /v1/instances/self`
pub async fn remove(
    State(state): State<AppState>,
    addr: ClientAddr,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let inst = authenticate(&state, &headers, &addr).await?;
    state
        .db
        .call(move |c| db::delete_instance(c, &inst.id))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
