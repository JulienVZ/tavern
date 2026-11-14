// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP routes and their OpenAPI description.

pub mod account;
pub mod admin;
pub mod auth;
pub mod credentials;
pub mod devices;
pub mod gateway;
pub mod system;

use axum::routing::get;
use axum::{Json, Router, middleware};
use tavern_protocol::handle::Handle;
use tavern_protocol::rest::{B64, ErrorCode};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::{ApiError, ApiResult};
use crate::{AppState, ExchangeId, rate_limit};

#[derive(OpenApi)]
#[openapi(info(
    title = "Tavern instance API",
    description = "REST API of a Tavern instance. Binary fields are unpadded base64url strings. \
                   The server never receives passwords, private keys or message content.",
    license(name = "AGPL-3.0-or-later")
))]
struct ApiDoc;

/// Routes of the server, without the outer middleware.
pub fn router(state: AppState) -> Router<AppState> {
    // Every route under /v1/auth is limited per client address.
    let auth = OpenApiRouter::new()
        .routes(routes!(auth::register_start))
        .routes(routes!(auth::register_finish))
        .routes(routes!(auth::login_start))
        .routes(routes!(auth::login_finish))
        .routes(routes!(auth::login_totp))
        .routes(routes!(auth::logout))
        .routes(routes!(credentials::reauth_start))
        .routes(routes!(credentials::reauth_finish))
        .routes(routes!(credentials::recover_start))
        .routes(routes!(credentials::recover_finish))
        .layer(middleware::from_fn_with_state(
            state,
            rate_limit::limit_by_ip,
        ));

    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(system::health))
        .routes(routes!(system::version))
        .merge(auth)
        .routes(routes!(devices::enrol, devices::list))
        .routes(routes!(devices::revoke))
        .routes(routes!(devices::reopen_session))
        .routes(routes!(account::me))
        .routes(routes!(account::totp_enable))
        .routes(routes!(account::totp_confirm))
        .routes(routes!(account::totp_disable))
        .routes(routes!(credentials::password_start))
        .routes(routes!(credentials::password_finish))
        .routes(routes!(credentials::rotate_recovery_key))
        .routes(routes!(admin::create_invite, admin::list_invites))
        .routes(routes!(admin::revoke_invite))
        .routes(routes!(admin::list_users))
        .routes(routes!(admin::disable_user))
        .routes(routes!(admin::enable_user))
        .routes(routes!(admin::disable_user_totp))
        .split_for_parts();

    router
        .route(
            "/v1/openapi.json",
            get(move || std::future::ready(Json(api.clone()))),
        )
        .route(tavern_protocol::GATEWAY_PATH, get(gateway::connect))
        // Unknown routes and methods answer in the API's error format, with
        // a code that tells a newer client "this server does not know this".
        .fallback(|| std::future::ready(ApiError::unknown_endpoint()))
        .method_not_allowed_fallback(|| std::future::ready(ApiError::unknown_endpoint()))
}

/// Parses a handle received from a client: it must already be canonical.
pub(crate) fn parse_handle(raw: &str) -> ApiResult<Handle> {
    Handle::parse_canonical(raw)
        .map_err(|_| ApiError::new(ErrorCode::InvalidHandle, "the handle is not valid"))
}

/// Reads an exchange identifier sent by a client.
pub(crate) fn exchange_id(raw: &B64) -> ApiResult<ExchangeId> {
    raw.as_slice()
        .try_into()
        .map_err(|_| ApiError::exchange_expired())
}

/// Checks a display name: 1 to 64 characters, no control characters, no
/// leading or trailing white space.
pub(crate) fn validate_display_name(name: &str) -> ApiResult<()> {
    let length = name.chars().count();
    if !(1..=64).contains(&length) || name.trim() != name || name.chars().any(char::is_control) {
        return Err(ApiError::invalid("the display name is not valid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_are_validated() {
        assert!(validate_display_name("Julien").is_ok());
        assert!(validate_display_name("Zoé 🍺").is_ok());
        assert!(validate_display_name(&"x".repeat(64)).is_ok());
        for bad in ["", " x", "x ", "a\nb", "a\u{0}b", &"x".repeat(65)] {
            assert!(validate_display_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn handles_must_arrive_canonical() {
        assert!(parse_handle("alice").is_ok());
        assert_eq!(
            parse_handle("Alice").unwrap_err().code,
            ErrorCode::InvalidHandle
        );
        assert_eq!(
            parse_handle("al ice").unwrap_err().code,
            ErrorCode::InvalidHandle
        );
    }
}
