//! `GET /healthz` and `GET /v1/status`.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::json;

use crate::state::AppState;

/// `200 ok` if the process is up and the database answers. Reveals nothing else.
pub async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    if state.db.ping().await {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "database unavailable")
    }
}

/// The supported API versions, how Apple has been answering, and our version.
pub async fn status(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "api": [1],
        "apns": state.apns_status(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
