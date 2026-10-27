//! The HTTP API (docs/design.md section 6, docs/api.md).

mod devices;
mod error;
mod instances;
pub mod push;
mod status;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequest, FromRequestParts, Request, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, X_CONTENT_TYPE_OPTIONS};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use serde::de::DeserializeOwned;

pub use error::{ApiError, ApiResult};

use crate::state::AppState;
use crate::util::{addr_key, client_ip};

/// Largest request body (docs/design.md section 6).
pub const MAX_BODY: usize = 2048;
/// How long reading a request body may take.
const BODY_TIMEOUT: Duration = Duration::from_secs(10);

/// The whole API as a router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(status::healthz))
        .route("/v1/status", get(status::status))
        .route("/v1/challenge", get(instances::challenge))
        .route("/v1/instances", post(instances::register))
        .route("/v1/instances/self/rotate", post(instances::rotate))
        .route("/v1/instances/self", delete(instances::remove))
        .route("/v1/devices", post(devices::register))
        .route(
            "/v1/devices/{device_id}",
            put(devices::update).delete(devices::remove),
        )
        .route(
            "/v1/devices/{device_id}/handles",
            post(devices::create_handle).get(devices::list_handles),
        )
        .route(
            "/v1/devices/{device_id}/handles/{handle_id}",
            delete(devices::revoke_handle),
        )
        .route("/v1/push", post(push::push))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

async fn not_found() -> ApiError {
    ApiError::not_found()
}

/// Sheds load beyond the in-flight limit and sets headers on every answer.
async fn guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    // /healthz has a small pool of its own, so it keeps answering while the
    // rest is being shed.
    let pool = if req.uri().path() == "/healthz" {
        &state.health_inflight
    } else {
        &state.inflight
    };
    let Ok(_permit) = pool.clone().try_acquire_owned() else {
        return ApiError::overloaded(1).into_response();
    };
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    resp
}

/// The client's address, behind the configured proxies.
pub struct ClientAddr(pub IpAddr);

impl ClientAddr {
    /// The key rate limits use for this address.
    pub fn key(&self) -> String {
        addr_key(self.0)
    }
}

impl FromRequestParts<AppState> for ClientAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        // Every X-Forwarded-For line counts (a request may carry several), read
        // from the right.
        let forwarded: Vec<&str> = parts
            .headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        let trusted = &state.settings.trusted_proxies;
        if !forwarded.is_empty() && !trusted.iter().any(|n| n.contains(peer)) {
            state.note_untrusted_forwarded_for();
        }
        Ok(ClientAddr(client_ip(peer, &forwarded, trusted)))
    }
}

/// A JSON body of at most [`MAX_BODY`] bytes, read within a deadline. Errors
/// are the API's own (`413 too_large`, `400 invalid_request`).
pub struct ApiJson<T>(pub T);

impl<T: DeserializeOwned> FromRequest<AppState> for ApiJson<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let read = tokio::time::timeout(BODY_TIMEOUT, Bytes::from_request(req, state)).await;
        let bytes = match read {
            Err(_) => {
                return Err(ApiError::new(
                    StatusCode::REQUEST_TIMEOUT,
                    "timeout",
                    "the request body took too long",
                ));
            }
            Ok(Err(rej)) if rej.status() == StatusCode::PAYLOAD_TOO_LARGE => {
                return Err(ApiError::too_large());
            }
            Ok(Err(_)) => return Err(ApiError::invalid("the request body could not be read")),
            Ok(Ok(b)) => b,
        };
        serde_json::from_slice(&bytes)
            .map(ApiJson)
            .map_err(|_| ApiError::invalid("the body is not the JSON this call expects"))
    }
}

/// The secret in `Authorization: Bearer <secret>`, if there is one.
pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, secret) = v.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(secret.trim())
        .filter(|s| !s.is_empty())
}

/// Charges a failed attempt (wrong secret, unknown id) to the caller's address
/// and returns the error to send; once the address has used up its failures, it
/// gets `429` instead. Requests that present valid credentials never come here,
/// so a flood of bad ones from a shared address can't lock the good ones out.
pub(crate) fn charge_failure(state: &AppState, addr: &ClientAddr, err: ApiError) -> ApiError {
    match state.limiters.auth_failures.take(&addr.key()) {
        Ok(()) => err,
        Err(wait) => ApiError::rate_limited(wait),
    }
}
