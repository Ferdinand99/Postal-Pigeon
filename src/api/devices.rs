//! Devices and handles (docs/design.md section 6.3). The app calls these;
//! no instance ever does, and no response contains a device token.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;

use super::{ApiError, ApiJson, ApiResult, ClientAddr, bearer, charge_failure};
use crate::config::Env;
use crate::crypto::{
    PREFIX_HANDLE, ct_eq, is_device_id, is_handle_id, new_device_id, new_id_secret, new_manage_key,
    parse_manage_key,
};
use crate::db::{self, DeviceRow, NewDevice};
use crate::state::AppState;
use crate::util::{b64_decode, day_string, prefix_key};

/// Normalises a device token: hexadecimal, 32 to 200 bytes, lower case.
fn clean_token(token: &str) -> Option<String> {
    let t = token.trim();
    if t.len() < 64
        || t.len() > 400
        || !t.len().is_multiple_of(2)
        || !t.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }
    Some(t.to_ascii_lowercase())
}

fn parse_env(state: &AppState, s: &str) -> ApiResult<Env> {
    Env::parse(s)
        .filter(|e| state.settings.env_allowed(*e))
        .ok_or_else(|| {
            ApiError::invalid("environment must be a configured one: production or sandbox")
        })
}

#[derive(Deserialize)]
pub struct RegisterBody {
    app: String,
    environment: String,
    token: String,
}

/// `POST /v1/devices`
pub async fn register(
    State(state): State<AppState>,
    addr: ClientAddr,
    ApiJson(body): ApiJson<RegisterBody>,
) -> ApiResult<impl IntoResponse> {
    if state.settings.app(&body.app).is_none() {
        return Err(ApiError::invalid("unknown app"));
    }
    let env = parse_env(&state, &body.environment)?;
    let token = clean_token(&body.token)
        .ok_or_else(|| ApiError::invalid("token must be 32 to 200 bytes of hexadecimal"))?;

    let key = addr.key();
    state
        .limiters
        .device_reg_addr_hour
        .take(&key)
        .map_err(ApiError::rate_limited)?;
    state
        .limiters
        .device_reg_addr_day
        .take(&key)
        .map_err(ApiError::rate_limited)?;
    // A coarser bucket for the whole network (the IPv4 /24 or IPv6 /48), so
    // spreading over many addresses of one network does not help.
    let prefix = prefix_key(addr.0);
    state
        .limiters
        .device_reg_prefix_hour
        .take(&prefix)
        .map_err(ApiError::rate_limited)?;
    state
        .limiters
        .device_reg_prefix_day
        .take(&prefix)
        .map_err(ApiError::rate_limited)?;

    let device_id = new_device_id();
    let (manage_key, key_hash) = new_manage_key();
    let (seal_key_id, sealed) = state.keys.seal(token.as_bytes(), &device_id);
    let fp = state.keys.token_fingerprint(&token);
    let (day, now_ms) = (state.clock.today(), state.clock.now_ms());
    let max = i64::from(state.settings.limits.max_devices);

    let (id, app) = (device_id.clone(), body.app);
    let stored = state
        .db
        .call(move |c| {
            // A record with the same token is replaced, so it adds no row and
            // is allowed even when the table is full.
            if !db::device_fp_exists(c, &fp)? && db::count_devices(c)? >= max {
                return Ok(false);
            }
            db::insert_device(
                c,
                &NewDevice {
                    id: &id,
                    key_hash: &key_hash,
                    app: &app,
                    environment: env.as_str(),
                    token_sealed: &sealed,
                    seal_key_id: &seal_key_id,
                    token_fp: &fp,
                    day,
                    now_ms,
                },
            )?;
            Ok::<_, rusqlite::Error>(true)
        })
        .await?;
    if !stored {
        return Err(ApiError::overloaded(3600));
    }
    Ok((
        StatusCode::CREATED,
        Json(json!({ "device_id": device_id, "manage_key": manage_key })),
    ))
}

/// Finds the device and checks its manage key. A wrong key counts against the
/// caller's address.
async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    addr: &ClientAddr,
    device_id: &str,
) -> ApiResult<DeviceRow> {
    if !is_device_id(device_id) {
        return Err(charge_failure(state, addr, ApiError::not_found()));
    }
    let id = device_id.to_string();
    let device = state
        .db
        .call(move |c| db::get_device(c, &id))
        .await?
        .ok_or_else(|| charge_failure(state, addr, ApiError::not_found()))?;
    let presented = bearer(headers).and_then(parse_manage_key);
    match presented {
        Some(hash) if ct_eq(&hash, &device.key_hash) => Ok(device),
        _ => Err(charge_failure(state, addr, ApiError::invalid_credentials())),
    }
}

#[derive(Deserialize)]
pub struct UpdateBody {
    token: Option<String>,
    environment: Option<String>,
}

/// `PUT /v1/devices/{device_id}`: a new token and/or a keep-alive.
pub async fn update(
    State(state): State<AppState>,
    addr: ClientAddr,
    Path(device_id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<UpdateBody>,
) -> ApiResult<impl IntoResponse> {
    let device = authorize(&state, &headers, &addr, &device_id).await?;
    let env = match &body.environment {
        Some(e) => parse_env(&state, e)?,
        None => Env::parse(&device.environment).unwrap_or(Env::Production),
    };
    let token = match &body.token {
        Some(t) => Some(
            clean_token(t)
                .ok_or_else(|| ApiError::invalid("token must be 32 to 200 bytes of hexadecimal"))?,
        ),
        None => None,
    };
    state
        .limiters
        .device_update
        .take(&device.id)
        .map_err(ApiError::rate_limited)?;

    let (day, now_ms) = (state.clock.today(), state.clock.now_ms());
    let env_changed = env.as_str() != device.environment;
    let new_sealed = token.as_ref().map(|t| {
        let fp = state.keys.token_fingerprint(t);
        let (kid, sealed) = state.keys.seal(t.as_bytes(), &device.id);
        (fp, kid, sealed)
    });
    let id = device.id.clone();
    state
        .db
        .call(move |c| match new_sealed {
            Some((fp, kid, sealed)) => {
                db::update_device_token(c, &id, env.as_str(), &sealed, &kid, &fp, now_ms, day)
                    .map(|_| ())
            }
            None if env_changed => {
                // The environment changed without a new token: the same token
                // now means something else, so it counts as a new registration.
                let Some(d) = db::get_device(c, &id)? else {
                    return Ok(());
                };
                c.execute(
                    "UPDATE devices SET environment = ?2, token_set_ms = ?3, last_seen_day = ?4, strikes = 0 WHERE id = ?1",
                    rusqlite::params![d.id, env.as_str(), now_ms, day],
                )
                .map(|_| ())
            }
            None => db::touch_device(c, &id, day),
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/devices/{device_id}`
pub async fn remove(
    State(state): State<AppState>,
    addr: ClientAddr,
    Path(device_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let device = authorize(&state, &headers, &addr, &device_id).await?;
    state
        .db
        .call(move |c| db::delete_device(c, &device.id))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct HandleBody {
    tag: String,
}

/// `POST /v1/devices/{device_id}/handles`
pub async fn create_handle(
    State(state): State<AppState>,
    addr: ClientAddr,
    Path(device_id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<HandleBody>,
) -> ApiResult<impl IntoResponse> {
    let device = authorize(&state, &headers, &addr, &device_id).await?;
    let tag_ok = body.tag.len() == 22 && b64_decode(&body.tag).is_some_and(|b| b.len() == 16);
    if !tag_ok {
        return Err(ApiError::invalid(
            "tag must be 16 bytes as unpadded URL-safe base64",
        ));
    }
    state
        .limiters
        .handle_create
        .take(&device.id)
        .map_err(ApiError::rate_limited)?;

    let handle = new_id_secret(PREFIX_HANDLE);
    let max = i64::from(state.settings.limits.max_handles_per_device);
    let (h, did, tag, day) = (handle.clone(), device.id, body.tag, state.clock.today());
    let created = state
        .db
        .call(move |c| {
            if db::count_handles(c, &did)? >= max {
                return Ok(false);
            }
            db::insert_handle(c, &h.id, &h.hash, &did, &tag, day)?;
            Ok::<_, rusqlite::Error>(true)
        })
        .await?;
    if !created {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "limit_reached",
            "this device already has the most handles it may have",
        ));
    }
    Ok((
        StatusCode::CREATED,
        Json(json!({ "handle_id": handle.id, "handle": handle.full })),
    ))
}

/// `GET /v1/devices/{device_id}/handles`
pub async fn list_handles(
    State(state): State<AppState>,
    addr: ClientAddr,
    Path(device_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let device = authorize(&state, &headers, &addr, &device_id).await?;
    let rows = state
        .db
        .call(move |c| db::list_handles(c, &device.id))
        .await?;
    let handles: Vec<_> = rows
        .into_iter()
        .map(|h| {
            json!({
                "handle_id": h.id,
                "tag": h.tag,
                "created": day_string(h.created_day),
                "last_used": h.last_used_day.map(day_string),
            })
        })
        .collect();
    Ok(Json(json!({ "handles": handles })))
}

/// `DELETE /v1/devices/{device_id}/handles/{handle_id}`
pub async fn revoke_handle(
    State(state): State<AppState>,
    addr: ClientAddr,
    Path((device_id, handle_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let device = authorize(&state, &headers, &addr, &device_id).await?;
    if !is_handle_id(&handle_id) {
        return Err(ApiError::not_found());
    }
    let removed = state
        .db
        .call(move |c| db::delete_handle(c, &device.id, &handle_id))
        .await?;
    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found())
    }
}
