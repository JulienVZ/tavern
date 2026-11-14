// SPDX-License-Identifier: AGPL-3.0-or-later

//! Registration and login.
//!
//! The server runs the server half of OPAQUE: it never receives a password.
//! Answers are built so that they do not reveal whether a handle exists,
//! except to someone holding a valid invitation code.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use sqlx::PgPool;
use tavern_crypto::identity::{IdentityPublicKey, WRAPPED_KEY_LEN};
use tavern_crypto::opaque::{self, server};
use tavern_crypto::token::{self, HumanCode};
use tavern_protocol::rest::{
    B64, ErrorBody, ErrorCode, LoginFinishRequest, LoginGrant, LoginOutcome, LoginStartRequest,
    LoginStartResponse, LoginTotpRequest, RegisterFinishRequest, RegisterFinishResponse,
    RegisterStartRequest, RegistrationResponse,
};
use uuid::Uuid;

use super::{exchange_id, parse_handle, validate_display_name};
use crate::error::{ApiError, ApiJson, ApiResult, is_unique_violation};
use crate::gateway::RevocationReason;
use crate::session::Session;
use crate::{AppState, CLIENT_TOKEN_LEN, Enrolment, ExchangeId, PendingLogin, totp};

/// Wrong TOTP codes accepted for one login before it must be restarted.
const MAX_TOTP_ATTEMPTS: u8 = 5;

fn invalid_invite() -> ApiError {
    ApiError::new(ErrorCode::InvalidInvite, "the invitation code is not valid")
}

fn opaque_error(error: tavern_crypto::CryptoError) -> ApiError {
    match error {
        tavern_crypto::CryptoError::AuthenticationFailed => ApiError::invalid_credentials(),
        tavern_crypto::CryptoError::Internal => ApiError::internal("opaque", &error),
        _ => ApiError::invalid("malformed OPAQUE message"),
    }
}

/// Finds a usable invitation by its code. With `lock`, the row is locked for
/// the current transaction so that two registrations cannot share a last use.
async fn usable_invite<'e, E>(db: E, code: &str, lock: bool) -> ApiResult<(Uuid, bool)>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let code = HumanCode::parse(code).map_err(|_| invalid_invite())?;
    let query = if lock {
        "SELECT id, grants_admin FROM instance_invites \
         WHERE code_hash = $1 AND revoked_at IS NULL AND uses < max_uses \
           AND (expires_at IS NULL OR expires_at > now()) FOR UPDATE"
    } else {
        "SELECT id, grants_admin FROM instance_invites \
         WHERE code_hash = $1 AND revoked_at IS NULL AND uses < max_uses \
           AND (expires_at IS NULL OR expires_at > now())"
    };
    sqlx::query_as(query)
        .bind(code.hash().as_slice())
        .fetch_optional(db)
        .await?
        .ok_or_else(invalid_invite)
}

async fn handle_exists(db: &PgPool, handle: &str) -> ApiResult<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE handle = $1)")
            .bind(handle)
            .fetch_one(db)
            .await?,
    )
}

/// Starts a registration. Requires a valid invitation code.
#[utoipa::path(
    post,
    path = "/v1/auth/register/start",
    tag = "auth",
    request_body = RegisterStartRequest,
    responses((status = 200, body = RegistrationResponse), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn register_start(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<RegisterStartRequest>,
) -> ApiResult<Json<RegistrationResponse>> {
    let handle = parse_handle(&request.handle)?;
    state.rate_limits.check_handle(&handle)?;
    usable_invite(&state.db, &request.invite_code, false).await?;
    // Only the holder of a valid invitation learns that a handle is taken.
    if handle_exists(&state.db, handle.as_str()).await? {
        return Err(ApiError::new(
            ErrorCode::HandleTaken,
            "this handle is already in use",
        ));
    }

    let response = state
        .secrets
        .opaque
        .registration_start(request.registration_request.as_slice(), &handle)
        .map_err(opaque_error)?;
    Ok(Json(RegistrationResponse {
        registration_response: B64(response),
        opaque_suite: opaque::SUITE,
    }))
}

/// Completes a registration and consumes one use of the invitation.
#[utoipa::path(
    post,
    path = "/v1/auth/register/finish",
    tag = "auth",
    request_body = RegisterFinishRequest,
    responses((status = 201, body = RegisterFinishResponse), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn register_finish(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<RegisterFinishRequest>,
) -> ApiResult<(StatusCode, Json<RegisterFinishResponse>)> {
    let handle = parse_handle(&request.handle)?;
    validate_display_name(&request.display_name)?;
    let identity_key = IdentityPublicKey::from_bytes(request.identity_key.as_slice())
        .map_err(|_| ApiError::invalid("the identity key is not valid"))?;
    if request.wrapped_password_copy.0.len() != WRAPPED_KEY_LEN
        || request.wrapped_recovery_copy.0.len() != WRAPPED_KEY_LEN
    {
        return Err(ApiError::invalid("a wrapped key has the wrong length"));
    }
    let record = server::registration_finish(request.registration_upload.as_slice())
        .map_err(opaque_error)?;

    let mut tx = state.db.begin().await?;
    let (invite_id, grants_admin) = usable_invite(&mut *tx, &request.invite_code, true).await?;

    let inserted: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
        "INSERT INTO users (handle, display_name, is_admin, opaque_suite, opaque_record, \
             identity_key, identity_key_wrapped_pw, identity_key_wrapped_rk) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(handle.as_str())
    .bind(&request.display_name)
    .bind(grants_admin)
    .bind(i16::try_from(opaque::SUITE).unwrap_or(i16::MAX))
    .bind(&record)
    .bind(identity_key.to_bytes().as_slice())
    .bind(request.wrapped_password_copy.as_slice())
    .bind(request.wrapped_recovery_copy.as_slice())
    .fetch_one(&mut *tx)
    .await;
    let user_id = match inserted {
        Ok(id) => id,
        Err(error) if is_unique_violation(&error, "users_handle_key") => {
            return Err(ApiError::new(
                ErrorCode::HandleTaken,
                "this handle is already in use",
            ));
        }
        Err(error) => return Err(error.into()),
    };

    sqlx::query("UPDATE instance_invites SET uses = uses + 1 WHERE id = $1")
        .bind(invite_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO instance_invite_uses (invite_id, user_id) VALUES ($1, $2)")
        .bind(invite_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    tracing::info!(%user_id, is_admin = grants_admin, "account registered");
    Ok((
        StatusCode::CREATED,
        Json(RegisterFinishResponse {
            user_id,
            is_admin: grants_admin,
        }),
    ))
}

/// Starts an OPAQUE login for `handle` and remembers its state.
///
/// Shared by login and re-authentication. An unknown handle and a disabled
/// account get a decoy record: the answer has the same shape either way.
pub(crate) async fn start_login(
    state: &AppState,
    raw_handle: &str,
    credential_request: &[u8],
    reauth_for: Option<Uuid>,
) -> ApiResult<LoginStartResponse> {
    let handle = parse_handle(raw_handle)?;
    state.rate_limits.check_handle(&handle)?;

    let account: Option<(Uuid, Vec<u8>, i16)> =
        sqlx::query_as("SELECT id, opaque_record, opaque_suite FROM users WHERE handle = $1")
            .bind(handle.as_str())
            .fetch_optional(&state.db)
            .await?;
    let (user_id, record, suite) = match account {
        Some((id, record, suite)) => (Some(id), Some(record), suite),
        None => (None, None, i16::try_from(opaque::SUITE).unwrap_or(i16::MAX)),
    };

    let (login, response) = state
        .secrets
        .opaque
        .login_start(record.as_deref(), credential_request, &handle)
        .map_err(opaque_error)?;

    let login_id: ExchangeId = token::random_bytes();
    if !state.pending.logins.insert(
        login_id,
        PendingLogin {
            state: login,
            user_id,
            reauth_for,
        },
    ) {
        return Err(ApiError::unavailable());
    }
    Ok(LoginStartResponse {
        login_id: B64::from(login_id),
        credential_response: B64(response),
        opaque_suite: u16::try_from(suite).unwrap_or(opaque::SUITE),
    })
}

/// Verifies the second half of an OPAQUE login. Returns the account.
///
/// Every failure, whatever its cause, is the same `INVALID_CREDENTIALS`.
pub(crate) fn finish_login(
    state: &AppState,
    login_id: &B64,
    finalization: &[u8],
    reauth_for: Option<Uuid>,
) -> ApiResult<Uuid> {
    let pending = state
        .pending
        .logins
        .take(&exchange_id(login_id)?)
        .ok_or_else(ApiError::exchange_expired)?;
    if pending.reauth_for != reauth_for {
        return Err(ApiError::exchange_expired());
    }
    pending
        .state
        .finish(finalization)
        .map_err(|_| ApiError::invalid_credentials())?;
    // A decoy record can never pass `finish`; this is a second line of defence.
    pending.user_id.ok_or_else(ApiError::invalid_credentials)
}

/// Starts a login.
#[utoipa::path(
    post,
    path = "/v1/auth/login/start",
    tag = "auth",
    request_body = LoginStartRequest,
    responses((status = 200, body = LoginStartResponse), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn login_start(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<LoginStartRequest>,
) -> ApiResult<Json<LoginStartResponse>> {
    start_login(
        &state,
        &request.handle,
        request.credential_request.as_slice(),
        None,
    )
    .await
    .map(Json)
}

/// Builds what a completed login gives the client: an enrolment token and the
/// wrapped account key. Called only after the password check, and after the
/// TOTP check when TOTP is enabled.
async fn grant(state: &AppState, user_id: Uuid) -> ApiResult<LoginGrant> {
    let (handle, display_name, is_admin, identity_key, wrapped): (
        String,
        String,
        bool,
        Vec<u8>,
        Vec<u8>,
    ) = sqlx::query_as(
        "SELECT handle, display_name, is_admin, identity_key, identity_key_wrapped_pw \
         FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;

    let enrolment_token: [u8; CLIENT_TOKEN_LEN] = token::random_bytes();
    let session_nonce = token::random_bytes();
    if !state.pending.enrolments.insert(
        token::hash(&enrolment_token),
        Enrolment {
            user_id,
            session_nonce,
        },
    ) {
        return Err(ApiError::unavailable());
    }

    Ok(LoginGrant {
        user_id,
        handle,
        display_name,
        is_admin,
        enrolment_token: B64::from(enrolment_token),
        session_nonce: B64::from(session_nonce),
        identity_key: B64(identity_key),
        wrapped_password_copy: B64(wrapped),
    })
}

/// Completes a login. Returns the grant, or asks for a TOTP code.
#[utoipa::path(
    post,
    path = "/v1/auth/login/finish",
    tag = "auth",
    request_body = LoginFinishRequest,
    responses((status = 200, body = LoginOutcome), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn login_finish(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<LoginFinishRequest>,
) -> ApiResult<Json<LoginOutcome>> {
    let user_id = finish_login(
        &state,
        &request.login_id,
        request.credential_finalization.as_slice(),
        None,
    )?;

    let (disabled, totp_enabled): (bool, bool) = sqlx::query_as(
        "SELECT disabled_at IS NOT NULL, totp_enabled_at IS NOT NULL FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    // Told only to someone who proved knowledge of the password.
    if disabled {
        return Err(ApiError::new(
            ErrorCode::AccountDisabled,
            "this account is disabled",
        ));
    }
    if totp_enabled {
        if !state
            .pending
            .totp
            .insert(exchange_id(&request.login_id)?, (user_id, 0))
        {
            return Err(ApiError::unavailable());
        }
        return Ok(Json(LoginOutcome::TotpRequired));
    }
    grant(&state, user_id).await.map(LoginOutcome::Ok).map(Json)
}

/// Completes a login with a TOTP code or a TOTP recovery code.
#[utoipa::path(
    post,
    path = "/v1/auth/login/totp",
    tag = "auth",
    request_body = LoginTotpRequest,
    responses((status = 200, body = LoginOutcome), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn login_totp(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<LoginTotpRequest>,
) -> ApiResult<Json<LoginOutcome>> {
    let login_id = exchange_id(&request.login_id)?;
    let (user_id, failures) = state
        .pending
        .totp
        .take(&login_id)
        .ok_or_else(ApiError::exchange_expired)?;

    match totp::verify_code_or_recovery(&state.db, &state.secrets.totp_key, user_id, &request.code)
        .await
    {
        Ok(()) => grant(&state, user_id).await.map(LoginOutcome::Ok).map(Json),
        Err(error) => {
            // Leave the exchange open for a few more attempts.
            if error.code == ErrorCode::TotpInvalid && failures + 1 < MAX_TOTP_ATTEMPTS {
                state.pending.totp.insert(login_id, (user_id, failures + 1));
            }
            Err(error)
        }
    }
}

/// Ends the current session. The device stays enrolled.
#[utoipa::path(
    post,
    path = "/v1/auth/logout",
    tag = "auth",
    security(("session" = [])),
    responses((status = 204), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn logout(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<StatusCode> {
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE device_id = $1")
        .bind(session.device_id)
        .execute(&state.db)
        .await?;
    state.gateway.notify_device(
        session.device_id,
        crate::gateway::Event::SessionRevoked(RevocationReason::Revoked),
    );
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use tavern_crypto::CryptoError;

    use super::*;

    #[test]
    fn opaque_failures_do_not_leak_their_cause() {
        assert_eq!(
            opaque_error(CryptoError::AuthenticationFailed).code,
            ErrorCode::InvalidCredentials
        );
        assert_eq!(
            opaque_error(CryptoError::InvalidMessage).code,
            ErrorCode::InvalidArgument
        );
    }
}
