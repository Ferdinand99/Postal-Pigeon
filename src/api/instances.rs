//! Instance registration and management (docs/design.md section 6.1).

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;

use super::{ApiError, ApiJson, ApiResult, ClientAddr, bearer, charge_failure};
use crate::crypto::{PREFIX_INSTANCE, ct_eq, new_id_secret, new_secret_for, parse_id_secret};
use crate::db::{self, InstanceRow};
use crate::pow::{self, PowError};
use crate::state::AppState;
use crate::util::{addr_prefix, prefix_key, rfc3339};

/// The products that may register (informational only; not an identity proof).
pub const PRODUCTS: [&str; 4] = [
    "vigilant-vole",
    "keen-kestrel",
    "wise-wren",
    "faithful-ferret",
];

/// `GET /v1/challenge`
///
/// Asks for the current difficulty, which rises with recent registration
/// volume. An address that has already used up its registrations gets `429`
/// instead of a challenge, so it can't pile up work the relay would only throw
/// away.
pub async fn challenge(
    State(state): State<AppState>,
    addr: ClientAddr,
) -> ApiResult<impl IntoResponse> {
    let limits = &state.settings.limits;
    state
        .limiters
        .instance_reg_addr
        .has(&addr.key(), 1)
        .map_err(ApiError::rate_limited)?;
    state
        .limiters
        .instance_reg_prefix
        .has(&prefix_key(addr.0), 1)
        .map_err(ApiError::rate_limited)?;
    let difficulty = state.current_difficulty();
    let (challenge, expires) = pow::issue(
        &state.keys,
        &state.clock,
        limits.challenge_ttl_secs,
        difficulty,
    );
    Ok(Json(json!({
        "challenge": challenge,
        "difficulty": difficulty,
        "expires_at": rfc3339(expires),
    })))
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

fn challenge_used() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "challenge_used",
        "the challenge was already used; fetch a new one",
    )
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
    let checked = pow::check(
        &state.keys,
        &state.clock,
        limits.challenge_ttl_secs,
        &body.challenge,
    )
    .map_err(|e| match e {
        PowError::Expired => ApiError::new(
            StatusCode::BAD_REQUEST,
            "challenge_expired",
            "the challenge has expired; fetch a new one",
        ),
        _ => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_challenge",
            "the challenge was not issued by this relay",
        ),
    })?;
    if state.challenges.contains(&checked.id) {
        return Err(challenge_used());
    }
    pow::check_proof(&body.challenge, &body.nonce, checked.difficulty).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "the nonce does not meet the difficulty",
        )
    })?;

    // The address and network limits come before the challenge is remembered,
    // so a flood of solved-but-limited requests can't fill the used-challenge
    // set and lock everybody else out.
    state
        .limiters
        .instance_reg_addr
        .take(&addr.key())
        .map_err(ApiError::rate_limited)?;
    state
        .limiters
        .instance_reg_prefix
        .take(&prefix_key(addr.0))
        .map_err(ApiError::rate_limited)?;
    match state.challenges.insert(checked.id) {
        Ok(true) => {}
        Ok(false) => return Err(challenge_used()),
        Err(_) => return Err(ApiError::overloaded(60)),
    }

    let today = state.clock.today();
    let credential = {
        let cred = new_id_secret(PREFIX_INSTANCE);
        let prefix = addr_prefix(addr.0);
        let (c, product, version) = (cred.clone(), body.product, body.version);
        state
            .db
            .call(move |conn| {
                db::insert_instance(conn, &c.id, &c.hash, &product, &version, today, &prefix)
            })
            .await?;
        cred.full
    };
    // Registration is never closed to everybody. Past the high-water mark the
    // proof of work just gets harder (see AppState::current_difficulty).
    state.note_registration();

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

/// Checks the instance credential in `Authorization`. Valid credentials are
/// never held up by the failure limit; a wrong or unknown one is charged to the
/// caller's address (and answered `429` once the address has used its budget).
pub(super) async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    addr: &ClientAddr,
) -> ApiResult<InstanceRow> {
    let presented = bearer(headers)
        .ok_or_else(|| charge_failure(state, addr, ApiError::invalid_credentials()))?;
    let (id, hash) = parse_id_secret(PREFIX_INSTANCE, presented)
        .ok_or_else(|| charge_failure(state, addr, ApiError::invalid_credentials()))?;
    let lookup = id.clone();
    let row = state
        .db
        .call(move |c| db::get_instance(c, &lookup))
        .await?
        .ok_or_else(|| charge_failure(state, addr, ApiError::unknown_instance()))?;
    if !ct_eq(&row.hash, &hash) {
        return Err(charge_failure(state, addr, ApiError::invalid_credentials()));
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
