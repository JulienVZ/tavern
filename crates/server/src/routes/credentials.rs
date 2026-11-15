// SPDX-License-Identifier: AGPL-3.0-or-later

//! Credential changes: re-authentication, password change, recovery with the
//! recovery key, and recovery key rotation.
//!
//! Every change is authorised by a signature of the account identity key over
//! a single-use challenge, the handle and the new values. The server only
//! checks that signature against the public key it holds: it never sees a
//! password, a recovery key or the identity private key.
//!
//! See `docs/adr/0003-opaque-authentication.md`, "Credential changes".

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use tavern_crypto::identity::{
    self, CHALLENGE_LEN, CredentialUpdate, CredentialUpdatePurpose, IdentityPublicKey,
    WRAPPED_KEY_LEN,
};
use tavern_crypto::opaque::{self, server};
use tavern_crypto::token;
use tavern_protocol::handle::Handle;
use tavern_protocol::rest::{
    B64, ErrorBody, ErrorCode, LoginStartResponse, PasswordFinishRequest, PasswordStartRequest,
    ReauthFinishRequest, ReauthGrant, ReauthStartRequest, RecoverFinishRequest,
    RecoverStartRequest, RecoverStartResponse, RegistrationResponse, RotateRecoveryKeyRequest,
};
use uuid::Uuid;

use super::auth::{finish_login, start_login};
use super::{exchange_id, parse_handle};
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::gateway::RevocationReason;
use crate::notices::{self, NoticeKind};
use crate::session::{self, Session};
use crate::{AppState, CLIENT_TOKEN_LEN, CredentialChange, ExchangeId, totp};

/// One refusal for every way a credential change can fail to prove itself:
/// unknown account, wrong key, altered values, replayed challenge.
fn invalid_proof() -> ApiError {
    ApiError::new(
        ErrorCode::InvalidProof,
        "the credential change is not authorised",
    )
}

fn malformed() -> ApiError {
    ApiError::invalid("malformed credential change")
}

fn wrapped_key(bytes: &B64) -> ApiResult<&[u8]> {
    if bytes.0.len() == WRAPPED_KEY_LEN {
        Ok(bytes.as_slice())
    } else {
        Err(malformed())
    }
}

async fn stored_identity_key(state: &AppState, user_id: Uuid) -> ApiResult<IdentityPublicKey> {
    let bytes: Vec<u8> = sqlx::query_scalar("SELECT identity_key FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;
    IdentityPublicKey::from_bytes(&bytes)
        .map_err(|error| ApiError::internal("stored identity key", &error))
}

/// Takes the re-authentication token of the calling session.
fn take_reauth(state: &AppState, session: &Session, raw: &B64) -> ApiResult<CredentialChange> {
    let change = state
        .pending
        .reauths
        .take(&token::hash(raw.as_slice()))
        .ok_or_else(ApiError::exchange_expired)?;
    // A token is bound to the session that obtained it.
    if change.user_id != Some(session.user_id) || change.device_id != Some(session.device_id) {
        return Err(ApiError::exchange_expired());
    }
    Ok(change)
}

// --- Re-authentication --------------------------------------------------------------

/// Starts a fresh password check from an existing session.
#[utoipa::path(
    post,
    path = "/v1/auth/reauth/start",
    tag = "credentials",
    request_body = ReauthStartRequest,
    security(("session" = [])),
    responses((status = 200, body = LoginStartResponse), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn reauth_start(
    State(state): State<AppState>,
    session: Session,
    ApiJson(request): ApiJson<ReauthStartRequest>,
) -> ApiResult<Json<LoginStartResponse>> {
    let handle: String = sqlx::query_scalar("SELECT handle FROM users WHERE id = $1")
        .bind(session.user_id)
        .fetch_one(&state.db)
        .await?;
    start_login(
        &state,
        &handle,
        request.credential_request.as_slice(),
        Some(session.device_id),
    )
    .await
    .map(Json)
}

/// Completes the password check (and the TOTP check when enabled) and returns
/// what one credential change needs: a token, a challenge and the wrapped key.
#[utoipa::path(
    post,
    path = "/v1/auth/reauth/finish",
    tag = "credentials",
    request_body = ReauthFinishRequest,
    security(("session" = [])),
    responses((status = 200, body = ReauthGrant), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn reauth_finish(
    State(state): State<AppState>,
    session: Session,
    ApiJson(request): ApiJson<ReauthFinishRequest>,
) -> ApiResult<Json<ReauthGrant>> {
    let user_id = finish_login(
        &state,
        &request.login_id,
        request.credential_finalization.as_slice(),
        Some(session.device_id),
    )?;
    if user_id != session.user_id {
        return Err(ApiError::invalid_credentials());
    }

    let (handle, totp_enabled, wrapped): (String, bool, Vec<u8>) = sqlx::query_as(
        "SELECT handle, totp_enabled_at IS NOT NULL, identity_key_wrapped_pw \
         FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    // The wrapped key is never returned before the second factor.
    if totp_enabled {
        let code = request.totp_code.as_deref().ok_or(ApiError::new(
            ErrorCode::TotpRequired,
            "a TOTP code is required",
        ))?;
        totp::verify_code_or_recovery(&state.db, &state.secrets.totp_key, user_id, code).await?;
    }

    let reauth_token: [u8; CLIENT_TOKEN_LEN] = token::random_bytes();
    let challenge: [u8; CHALLENGE_LEN] = token::random_bytes();
    let change = CredentialChange {
        user_id: Some(user_id),
        handle: parse_handle(&handle)?,
        challenge,
        device_id: Some(session.device_id),
    };
    if !state
        .pending
        .reauths
        .insert(token::hash(&reauth_token), change)
    {
        return Err(ApiError::unavailable());
    }
    Ok(Json(ReauthGrant {
        reauth_token: B64::from(reauth_token),
        challenge: B64::from(challenge),
        wrapped_password_copy: B64(wrapped),
    }))
}

// --- Password change ------------------------------------------------------------------

/// First half of the OPAQUE registration of the new password.
#[utoipa::path(
    post,
    path = "/v1/account/password/start",
    tag = "credentials",
    request_body = PasswordStartRequest,
    security(("session" = [])),
    responses((status = 200, body = RegistrationResponse), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn password_start(
    State(state): State<AppState>,
    session: Session,
    ApiJson(request): ApiJson<PasswordStartRequest>,
) -> ApiResult<Json<RegistrationResponse>> {
    // The token is only looked at here; `password/finish` consumes it.
    let change = state
        .pending
        .reauths
        .peek(&token::hash(request.reauth_token.as_slice()))
        .filter(|change| change.user_id == Some(session.user_id))
        .ok_or_else(ApiError::exchange_expired)?;
    let response = state
        .secrets
        .opaque
        .registration_start(request.registration_request.as_slice(), &change.handle)
        .map_err(|_| malformed())?;
    Ok(Json(RegistrationResponse {
        registration_response: B64(response),
        opaque_suite: opaque::SUITE,
    }))
}

/// Replaces the password record and the "password" wrapped copy, then ends
/// every other session of the account.
#[utoipa::path(
    post,
    path = "/v1/account/password/finish",
    tag = "credentials",
    request_body = PasswordFinishRequest,
    security(("session" = [])),
    responses((status = 204), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn password_finish(
    State(state): State<AppState>,
    session: Session,
    ApiJson(request): ApiJson<PasswordFinishRequest>,
) -> ApiResult<StatusCode> {
    let change = take_reauth(&state, &session, &request.reauth_token)?;
    let wrapped = wrapped_key(&request.wrapped_password_copy)?;
    stored_identity_key(&state, session.user_id)
        .await?
        .verify_credential_update(
            &CredentialUpdate {
                purpose: CredentialUpdatePurpose::PasswordChange,
                challenge: &change.challenge,
                handle: &change.handle,
                opaque_upload: request.registration_upload.as_slice(),
                wrapped_password_copy: wrapped,
                wrapped_recovery_copy: &[],
            },
            request.signature.as_slice(),
        )
        .map_err(|_| invalid_proof())?;
    let record = server::registration_finish(request.registration_upload.as_slice())
        .map_err(|_| malformed())?;

    store_password(&state, session.user_id, &record, wrapped).await?;
    // Not pushed: the other devices are signed out below, and read the
    // notice when their user signs in again.
    notices::store(
        &state,
        session.user_id,
        NoticeKind::PasswordChanged,
        Some(session.device_id),
    )
    .await?;
    session::revoke_all(
        &state,
        session.user_id,
        Some(session.device_id),
        RevocationReason::CredentialsChanged,
    )
    .await?;
    tracing::info!(user_id = %session.user_id, "password changed");
    Ok(StatusCode::NO_CONTENT)
}

async fn store_password(
    state: &AppState,
    user_id: Uuid,
    record: &[u8],
    wrapped: &[u8],
) -> ApiResult<()> {
    sqlx::query(
        "UPDATE users SET opaque_record = $2, opaque_suite = $3, identity_key_wrapped_pw = $4 \
         WHERE id = $1",
    )
    .bind(user_id)
    .bind(record)
    .bind(i16::try_from(opaque::SUITE).unwrap_or(i16::MAX))
    .bind(wrapped)
    .execute(&state.db)
    .await?;
    Ok(())
}

// --- Recovery key rotation --------------------------------------------------------------

/// Replaces the "recovery" wrapped copy. The previous recovery key stops working.
#[utoipa::path(
    post,
    path = "/v1/account/recovery-key",
    tag = "credentials",
    request_body = RotateRecoveryKeyRequest,
    security(("session" = [])),
    responses((status = 204), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn rotate_recovery_key(
    State(state): State<AppState>,
    session: Session,
    ApiJson(request): ApiJson<RotateRecoveryKeyRequest>,
) -> ApiResult<StatusCode> {
    let change = take_reauth(&state, &session, &request.reauth_token)?;
    let wrapped = wrapped_key(&request.wrapped_recovery_copy)?;
    stored_identity_key(&state, session.user_id)
        .await?
        .verify_credential_update(
            &CredentialUpdate {
                purpose: CredentialUpdatePurpose::RecoveryKeyRotation,
                challenge: &change.challenge,
                handle: &change.handle,
                opaque_upload: &[],
                wrapped_password_copy: &[],
                wrapped_recovery_copy: wrapped,
            },
            request.signature.as_slice(),
        )
        .map_err(|_| invalid_proof())?;

    sqlx::query("UPDATE users SET identity_key_wrapped_rk = $2 WHERE id = $1")
        .bind(session.user_id)
        .bind(wrapped)
        .execute(&state.db)
        .await?;
    notices::record(
        &state,
        session.user_id,
        NoticeKind::RecoveryKeyReplaced,
        Some(session.device_id),
    )
    .await?;
    tracing::info!(user_id = %session.user_id, "recovery key replaced");
    Ok(StatusCode::NO_CONTENT)
}

// --- Recovery with the recovery key -------------------------------------------------------

/// What `recover/start` returns for a handle: the real values, or decoys that
/// are a stable function of the handle, so that the answer does not reveal
/// whether the account exists.
async fn recovery_material(
    state: &AppState,
    handle: &Handle,
) -> ApiResult<(Option<Uuid>, Vec<u8>, Vec<u8>)> {
    let account: Option<(Uuid, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT id, identity_key, identity_key_wrapped_rk FROM users WHERE handle = $1",
    )
    .bind(handle.as_str())
    .fetch_optional(&state.db)
    .await?;
    // Computed in both cases, so that the two paths do the same work.
    let key = &state.secrets.handle_privacy_key;
    let decoy_key = identity::decoy_identity_key(key, handle)
        .map_err(|error| ApiError::internal("decoy", &error))?;
    let decoy_copy = identity::decoy_wrapped_key(key, handle)
        .map_err(|error| ApiError::internal("decoy", &error))?;

    Ok(match account {
        Some((user_id, identity_key, wrapped)) => (Some(user_id), identity_key, wrapped),
        None => (None, decoy_key.to_bytes().to_vec(), decoy_copy),
    })
}

/// Starts a recovery: returns the "recovery" wrapped copy, a challenge, and
/// the first half of the OPAQUE registration of the new password.
#[utoipa::path(
    post,
    path = "/v1/auth/recover/start",
    tag = "credentials",
    request_body = RecoverStartRequest,
    responses((status = 200, body = RecoverStartResponse), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn recover_start(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<RecoverStartRequest>,
) -> ApiResult<Json<RecoverStartResponse>> {
    let handle = parse_handle(&request.handle)?;
    state.rate_limits.check_handle(&handle)?;

    let (user_id, identity_key, wrapped) = recovery_material(&state, &handle).await?;
    let registration_response = state
        .secrets
        .opaque
        .registration_start(request.registration_request.as_slice(), &handle)
        .map_err(|_| malformed())?;

    let recovery_id: ExchangeId = token::random_bytes();
    let challenge: [u8; CHALLENGE_LEN] = token::random_bytes();
    let change = CredentialChange {
        user_id,
        handle,
        challenge,
        device_id: None,
    };
    if !state.pending.recoveries.insert(recovery_id, change) {
        return Err(ApiError::unavailable());
    }
    Ok(Json(RecoverStartResponse {
        recovery_id: B64::from(recovery_id),
        challenge: B64::from(challenge),
        identity_key: B64(identity_key),
        wrapped_recovery_copy: B64(wrapped),
        registration_response: B64(registration_response),
        opaque_suite: opaque::SUITE,
    }))
}

/// Completes a recovery: sets the new password and ends every session.
///
/// TOTP, when enabled, stays enabled: the recovery key replaces a forgotten
/// password, not the second factor.
#[utoipa::path(
    post,
    path = "/v1/auth/recover/finish",
    tag = "credentials",
    request_body = RecoverFinishRequest,
    responses((status = 204), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn recover_finish(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<RecoverFinishRequest>,
) -> ApiResult<StatusCode> {
    let change = state
        .pending
        .recoveries
        .take(&exchange_id(&request.recovery_id)?)
        .ok_or_else(ApiError::exchange_expired)?;
    let wrapped = wrapped_key(&request.wrapped_password_copy)?;
    // An unknown handle got decoys at `start`: nothing can verify for it.
    let user_id = change.user_id.ok_or_else(invalid_proof)?;

    stored_identity_key(&state, user_id)
        .await?
        .verify_credential_update(
            &CredentialUpdate {
                purpose: CredentialUpdatePurpose::Recovery,
                challenge: &change.challenge,
                handle: &change.handle,
                opaque_upload: request.registration_upload.as_slice(),
                wrapped_password_copy: wrapped,
                wrapped_recovery_copy: &[],
            },
            request.signature.as_slice(),
        )
        .map_err(|_| invalid_proof())?;
    let record = server::registration_finish(request.registration_upload.as_slice())
        .map_err(|_| malformed())?;

    store_password(&state, user_id, &record, wrapped).await?;
    // Not pushed: every device is signed out below.
    notices::store(&state, user_id, NoticeKind::AccountRecovered, None).await?;
    session::revoke_all(&state, user_id, None, RevocationReason::CredentialsChanged).await?;
    tracing::info!(%user_id, "account recovered with the recovery key");
    Ok(StatusCode::NO_CONTENT)
}
