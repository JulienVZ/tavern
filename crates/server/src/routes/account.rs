// SPDX-License-Identifier: AGPL-3.0-or-later

//! The signed-in account: profile and TOTP settings.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use tavern_crypto::token::{self, HumanCode};
use tavern_protocol::rest::{
    B64, ErrorBody, ErrorCode, Me, TotpCodeRequest, TotpEnrolment, TotpRecoveryCodes,
};

use crate::error::{ApiError, ApiJson, ApiResult};
use crate::session::Session;
use crate::{AppState, totp};

/// Returns the signed-in account.
#[utoipa::path(
    get,
    path = "/v1/users/me",
    tag = "account",
    security(("session" = [])),
    responses((status = 200, body = Me), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn me(State(state): State<AppState>, session: Session) -> ApiResult<Json<Me>> {
    let (handle, display_name, is_admin, totp_enabled, identity_key): (
        String,
        String,
        bool,
        bool,
        Vec<u8>,
    ) = sqlx::query_as(
        "SELECT handle, display_name, is_admin, totp_enabled_at IS NOT NULL, identity_key \
         FROM users WHERE id = $1",
    )
    .bind(session.user_id)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(Me {
        user_id: session.user_id,
        handle,
        display_name,
        is_admin,
        totp_enabled,
        identity_key: B64(identity_key),
        device_id: session.device_id,
    }))
}

/// Starts enabling TOTP: generates a secret, which becomes active once
/// confirmed with a first code.
#[utoipa::path(
    post,
    path = "/v1/account/totp/enable",
    tag = "account",
    security(("session" = [])),
    responses((status = 200, body = TotpEnrolment), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn totp_enable(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<TotpEnrolment>> {
    let (handle, enabled): (String, bool) =
        sqlx::query_as("SELECT handle, totp_enabled_at IS NOT NULL FROM users WHERE id = $1")
            .bind(session.user_id)
            .fetch_one(&state.db)
            .await?;
    if enabled {
        return Err(ApiError::new(
            ErrorCode::AlreadyExists,
            "TOTP is already enabled",
        ));
    }

    let secret: [u8; totp::SECRET_LEN] = token::random_bytes();
    let sealed = totp::seal(&state.secrets.totp_key, session.user_id, &secret)?;
    sqlx::query("UPDATE users SET totp_secret = $2, totp_last_step = NULL WHERE id = $1")
        .bind(session.user_id)
        .bind(&sealed)
        .execute(&state.db)
        .await?;

    let (secret, otpauth_url) = totp::enrolment(&secret, &handle)?;
    Ok(Json(TotpEnrolment {
        secret,
        otpauth_url,
    }))
}

/// Confirms TOTP with a first code and returns the recovery codes.
#[utoipa::path(
    post,
    path = "/v1/account/totp/confirm",
    tag = "account",
    request_body = TotpCodeRequest,
    security(("session" = [])),
    responses((status = 200, body = TotpRecoveryCodes), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn totp_confirm(
    State(state): State<AppState>,
    session: Session,
    ApiJson(request): ApiJson<TotpCodeRequest>,
) -> ApiResult<Json<TotpRecoveryCodes>> {
    let enabled: bool =
        sqlx::query_scalar("SELECT totp_enabled_at IS NOT NULL FROM users WHERE id = $1")
            .bind(session.user_id)
            .fetch_one(&state.db)
            .await?;
    if enabled {
        return Err(ApiError::new(
            ErrorCode::AlreadyExists,
            "TOTP is already enabled",
        ));
    }
    totp::verify_code(
        &state.db,
        &state.secrets.totp_key,
        session.user_id,
        &request.code,
        false,
    )
    .await?;

    let codes: Vec<HumanCode> = (0..totp::RECOVERY_CODES)
        .map(|_| HumanCode::generate())
        .collect();
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET totp_enabled_at = now() WHERE id = $1")
        .bind(session.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM totp_recovery_codes WHERE user_id = $1")
        .bind(session.user_id)
        .execute(&mut *tx)
        .await?;
    for code in &codes {
        sqlx::query("INSERT INTO totp_recovery_codes (user_id, code_hash) VALUES ($1, $2)")
            .bind(session.user_id)
            .bind(code.hash().as_slice())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    tracing::info!(user_id = %session.user_id, "TOTP enabled");
    Ok(Json(TotpRecoveryCodes {
        recovery_codes: codes
            .iter()
            .map(|code| code.display().to_string())
            .collect(),
    }))
}

/// Disables TOTP. Requires a current code or a recovery code.
#[utoipa::path(
    post,
    path = "/v1/account/totp/disable",
    tag = "account",
    request_body = TotpCodeRequest,
    security(("session" = [])),
    responses((status = 204), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn totp_disable(
    State(state): State<AppState>,
    session: Session,
    ApiJson(request): ApiJson<TotpCodeRequest>,
) -> ApiResult<StatusCode> {
    totp::verify_code_or_recovery(
        &state.db,
        &state.secrets.totp_key,
        session.user_id,
        &request.code,
    )
    .await?;
    totp::clear(&state.db, session.user_id).await?;
    tracing::info!(user_id = %session.user_id, "TOTP disabled by the user");
    Ok(StatusCode::NO_CONTENT)
}
