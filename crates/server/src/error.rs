// SPDX-License-Identifier: AGPL-3.0-or-later

//! Errors of the REST API.

use axum::Json;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::http::header::RETRY_AFTER;
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use tavern_protocol::rest::{ErrorBody, ErrorCode};

/// An error returned to an API client.
///
/// The message is for logs and developers; it never contains secrets, and
/// never says more than the code about why a credential was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// Machine-readable code.
    pub code: ErrorCode,
    /// English explanation.
    pub message: &'static str,
    /// Suggested delay before a retry, in milliseconds.
    pub retry_after_ms: Option<u64>,
}

/// Result of a request handler.
pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    /// Builds an error.
    pub const fn new(code: ErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message,
            retry_after_ms: None,
        }
    }

    /// A malformed or out-of-range field.
    pub const fn invalid(message: &'static str) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }

    /// Missing or invalid session or token.
    pub const fn unauthenticated() -> Self {
        Self::new(ErrorCode::Unauthenticated, "authentication is required")
    }

    /// Authenticated but not allowed.
    pub const fn forbidden() -> Self {
        Self::new(ErrorCode::Forbidden, "not allowed")
    }

    /// The resource does not exist.
    pub const fn not_found() -> Self {
        Self::new(ErrorCode::NotFound, "not found")
    }

    /// No such route, or no such method on this route. A client that gets
    /// this from an instance it already validated is newer than the server.
    pub const fn unknown_endpoint() -> Self {
        Self::new(
            ErrorCode::UnknownEndpoint,
            "this server has no such endpoint",
        )
    }

    /// Wrong handle or password. The same error for every cause.
    pub const fn invalid_credentials() -> Self {
        Self::new(ErrorCode::InvalidCredentials, "invalid credentials")
    }

    /// An exchange timed out, or its identifier is unknown or already used.
    pub const fn exchange_expired() -> Self {
        Self::new(
            ErrorCode::ExchangeExpired,
            "this exchange expired, start again",
        )
    }

    /// The server is saturated.
    pub const fn unavailable() -> Self {
        Self {
            code: ErrorCode::Unavailable,
            message: "the server is busy, retry shortly",
            retry_after_ms: Some(5_000),
        }
    }

    /// Too many requests.
    pub const fn rate_limited(retry_after_ms: u64) -> Self {
        Self {
            code: ErrorCode::RateLimited,
            message: "too many requests",
            retry_after_ms: Some(retry_after_ms),
        }
    }

    /// An unexpected failure. Details go to the log, not to the client.
    pub fn internal(context: &'static str, error: &dyn std::fmt::Display) -> Self {
        tracing::error!(%error, context, "internal error");
        Self::new(ErrorCode::Internal, "internal error")
    }

    fn status(&self) -> StatusCode {
        match self.code {
            ErrorCode::InvalidArgument
            | ErrorCode::InvalidHandle
            | ErrorCode::InvalidDeviceCertificate
            | ErrorCode::InvalidKeyPackage => StatusCode::BAD_REQUEST,
            ErrorCode::Unauthenticated
            | ErrorCode::InvalidCredentials
            | ErrorCode::TotpRequired
            | ErrorCode::TotpInvalid
            | ErrorCode::InvalidProof => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden | ErrorCode::AccountDisabled | ErrorCode::InvalidInvite => {
                StatusCode::FORBIDDEN
            }
            ErrorCode::NotFound | ErrorCode::UnknownEndpoint => StatusCode::NOT_FOUND,
            ErrorCode::AlreadyExists | ErrorCode::HandleTaken | ErrorCode::TooManyDevices => {
                StatusCode::CONFLICT
            }
            ErrorCode::ExchangeExpired => StatusCode::GONE,
            ErrorCode::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::internal("database", &error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = ErrorBody {
            code: self.code,
            message: self.message.to_owned(),
            retry_after_ms: self.retry_after_ms,
        };
        let mut response = (status, Json(body)).into_response();
        if let Some(ms) = self.retry_after_ms {
            let seconds = ms.div_ceil(1000).max(1);
            if let Ok(value) = seconds.to_string().parse() {
                response.headers_mut().insert(RETRY_AFTER, value);
            }
        }
        response
    }
}

/// `axum::Json` with refusals in the API's own error format.
///
/// The stock extractor answers a malformed or mistyped body with plain text.
/// Every error of this API is an [`ErrorBody`], so that clients never have to
/// guess what a response means.
#[derive(Debug, Clone, Copy)]
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> ApiResult<Self> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(match rejection.status() {
                StatusCode::PAYLOAD_TOO_LARGE => {
                    ApiError::new(ErrorCode::PayloadTooLarge, "the request body is too large")
                }
                _ => ApiError::invalid("the request body is not valid for this endpoint"),
            }),
        }
    }
}

/// Whether a database error is a violation of the named unique constraint.
pub fn is_unique_violation(error: &sqlx::Error, constraint: &str) -> bool {
    error.as_database_error().is_some_and(|db| {
        db.code().as_deref() == Some("23505") && db.constraint() == Some(constraint)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_failures_share_one_status() {
        assert_eq!(
            ApiError::invalid_credentials().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiError::unauthenticated().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn rate_limit_sets_retry_after_in_seconds() {
        let response = ApiError::rate_limited(1_200).into_response();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[RETRY_AFTER], "2");
    }
}
