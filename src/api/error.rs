//! API errors: `{"error": "<code>", "message": "<text>"}` with a stable code.

use axum::Json;
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub retry_after: Option<u64>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            code,
            message: message.into(),
            retry_after: None,
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }

    pub fn invalid_credentials() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "the credential is missing or wrong",
        )
    }

    pub fn unknown_instance() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unknown_instance",
            "this instance is not registered; register again",
        )
    }

    pub fn suspended() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "suspended",
            "this instance is suspended; do not register again",
        )
    }

    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "there is nothing here")
    }

    pub fn too_large() -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "the request body is larger than 2 KiB",
        )
    }

    pub fn rate_limited(retry_after: u64) -> Self {
        let mut e = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "a limit applies; retry later",
        );
        e.retry_after = Some(retry_after.max(1));
        e
    }

    pub fn overloaded(retry_after: u64) -> Self {
        let mut e = Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            "the relay is busy; retry later",
        );
        e.retry_after = Some(retry_after.max(1));
        e
    }

    /// A database or other internal failure. Nothing about the cause is
    /// logged or returned, since it could be near a secret.
    pub fn internal() -> Self {
        tracing::error!("internal_error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "something went wrong on the relay",
        )
    }

    pub fn with_retry_after(mut self, secs: u64) -> Self {
        self.retry_after = Some(secs.max(1));
        self
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(_: rusqlite::Error) -> Self {
        ApiError::internal()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut resp = (
            self.status,
            Json(json!({ "error": self.code, "message": self.message })),
        )
            .into_response();
        if let Some(secs) = self.retry_after
            && let Ok(v) = HeaderValue::from_str(&secs.to_string())
        {
            resp.headers_mut().insert(RETRY_AFTER, v);
        }
        resp
    }
}
