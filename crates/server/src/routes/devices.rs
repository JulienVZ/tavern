// SPDX-License-Identifier: AGPL-3.0-or-later

//! Devices: enrolment, listing, revocation, reopening a session.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use tavern_crypto::identity::{DevicePublicKey, IdentityPublicKey, SessionChallenge};
use tavern_protocol::rest::{
    B64, DeviceInfo, DeviceList, EnrolDeviceRequest, ErrorBody, ErrorCode, Platform,
    ReopenSessionRequest, SessionResponse,
};
use uuid::Uuid;

use crate::AppState;
use crate::error::{ApiError, ApiJson, ApiResult, is_unique_violation};
use crate::gateway::{Event, RevocationReason};
use crate::notices::{self, NoticeKind};
use crate::session::{self, EnrolmentAuth, Session};

/// Active devices allowed per account.
pub const MAX_DEVICES: i64 = 10;
/// Largest encrypted device name accepted, in bytes.
const MAX_NAME_LEN: usize = 256;

type DeviceRow = (Uuid, i16, Vec<u8>, Option<Vec<u8>>, i64, Option<i64>);

fn invalid_certificate() -> ApiError {
    ApiError::new(
        ErrorCode::InvalidDeviceCertificate,
        "the device certificate is not valid",
    )
}

/// Enrols a new device for the account that just logged in, and opens its
/// session. Every other device of the account is notified.
#[utoipa::path(
    post,
    path = "/v1/devices",
    tag = "devices",
    request_body = EnrolDeviceRequest,
    security(("enrolment" = [])),
    responses((status = 201, body = SessionResponse), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn enrol(
    State(state): State<AppState>,
    EnrolmentAuth(enrolment): EnrolmentAuth,
    ApiJson(request): ApiJson<EnrolDeviceRequest>,
) -> ApiResult<(StatusCode, Json<SessionResponse>)> {
    if request
        .name_encrypted
        .as_ref()
        .is_some_and(|name| name.0.len() > MAX_NAME_LEN)
    {
        return Err(ApiError::invalid("the encrypted device name is too long"));
    }
    let user_id = enrolment.user_id;

    let identity_key: Vec<u8> =
        sqlx::query_scalar("SELECT identity_key FROM users WHERE id = $1 AND disabled_at IS NULL")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(ApiError::unauthenticated)?;
    let identity_key = IdentityPublicKey::from_bytes(&identity_key)
        .map_err(|error| ApiError::internal("stored identity key", &error))?;

    // The certificate must be signed by this account's identity key and name
    // this account: the server cannot be made to attach a device elsewhere.
    let certificate = identity_key
        .verify_device_certificate(request.certificate.as_slice())
        .map_err(|_| invalid_certificate())?;
    if certificate.user_id != *user_id.as_bytes() {
        return Err(invalid_certificate());
    }
    let device_id = Uuid::from_bytes(certificate.device_id);

    let mut tx = state.db.begin().await?;
    // Serialise enrolments of one account so that the limit holds.
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM devices WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    if active >= MAX_DEVICES {
        return Err(ApiError::new(
            ErrorCode::TooManyDevices,
            "this account has the maximum number of devices; revoke one first",
        ));
    }

    let inserted = sqlx::query(
        "INSERT INTO devices (id, user_id, signature_key, certificate, name_encrypted, platform) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(device_id)
    .bind(user_id)
    .bind(certificate.device_key.to_bytes().as_slice())
    .bind(request.certificate.as_slice())
    .bind(request.name_encrypted.as_ref().map(B64::as_slice))
    .bind(request.platform.to_db())
    .execute(&mut *tx)
    .await;
    if let Err(error) = inserted {
        if is_unique_violation(&error, "devices_pkey")
            || is_unique_violation(&error, "devices_signature_key_key")
        {
            return Err(ApiError::new(
                ErrorCode::AlreadyExists,
                "this device is already enrolled",
            ));
        }
        return Err(error.into());
    }
    let response = session::create(&mut tx, device_id, state.settings.session_ttl).await?;
    tx.commit().await?;

    tracing::info!(%user_id, %device_id, "device enrolled");
    state.gateway.notify_user(
        user_id,
        Some(device_id),
        Event::DeviceListChanged {
            device_id,
            added: true,
        },
    );
    Ok((StatusCode::CREATED, Json(response)))
}

/// Reopens the session of a device that is already enrolled, after a login.
///
/// The device proves possession of its key by signing the single-use nonce
/// issued with the enrolment token. Revoked devices are refused.
#[utoipa::path(
    post,
    path = "/v1/devices/{device_id}/session",
    tag = "devices",
    params(("device_id" = Uuid, Path, description = "The device asking for a session")),
    request_body = ReopenSessionRequest,
    security(("enrolment" = [])),
    responses((status = 200, body = SessionResponse), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn reopen_session(
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
    EnrolmentAuth(enrolment): EnrolmentAuth,
    ApiJson(request): ApiJson<ReopenSessionRequest>,
) -> ApiResult<Json<SessionResponse>> {
    let refused = || ApiError::new(ErrorCode::InvalidProof, "the session proof is not valid");

    // One query, one error: an unknown device, a device of another account and
    // a revoked device are indistinguishable to the caller.
    let signature_key: Vec<u8> = sqlx::query_scalar(
        "SELECT signature_key FROM devices \
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(device_id)
    .bind(enrolment.user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(refused)?;

    let device_key = DevicePublicKey::from_bytes(&signature_key)
        .map_err(|error| ApiError::internal("stored device key", &error))?;
    let challenge = SessionChallenge {
        nonce: &enrolment.session_nonce,
        user_id: enrolment.user_id.as_bytes(),
        device_id: device_id.as_bytes(),
    };
    device_key
        .verify_session_proof(&challenge, request.proof.as_slice())
        .map_err(|_| refused())?;

    let mut db = state.db.acquire().await?;
    session::create(&mut db, device_id, state.settings.session_ttl)
        .await
        .map(Json)
}

/// Lists the active devices of the account.
#[utoipa::path(
    get,
    path = "/v1/devices",
    tag = "devices",
    security(("session" = [])),
    responses((status = 200, body = DeviceList), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn list(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<DeviceList>> {
    let rows: Vec<DeviceRow> = sqlx::query_as(
        "SELECT id, platform, certificate, name_encrypted, \
                (extract(epoch FROM created_at) * 1000)::bigint, \
                (extract(epoch FROM last_seen_at) * 1000)::bigint \
         FROM devices WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at",
    )
    .bind(session.user_id)
    .fetch_all(&state.db)
    .await?;

    let devices = rows
        .into_iter()
        .map(
            |(device_id, platform, certificate, name, created, seen)| DeviceInfo {
                device_id,
                platform: Platform::from_db(platform).unwrap_or(Platform::Linux),
                certificate: B64(certificate),
                name_encrypted: name.map(B64),
                created_at_ms: u64::try_from(created).unwrap_or_default(),
                last_seen_at_ms: seen.and_then(|ms| u64::try_from(ms).ok()),
                current: device_id == session.device_id,
            },
        )
        .collect();
    Ok(Json(DeviceList { devices }))
}

/// Revokes a device of the account and ends its session.
#[utoipa::path(
    delete,
    path = "/v1/devices/{device_id}",
    tag = "devices",
    params(("device_id" = Uuid, Path, description = "The device to revoke")),
    security(("session" = [])),
    responses((status = 204), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn revoke(
    State(state): State<AppState>,
    session: Session,
    Path(device_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let mut tx = state.db.begin().await?;
    let revoked = sqlx::query(
        // The server's part of its local store key goes with it: a store
        // left on a revoked device can never be opened again (ADR 0017).
        "UPDATE devices SET revoked_at = now(), local_store_share = NULL \
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(device_id)
    .bind(session.user_id)
    .execute(&mut *tx)
    .await?;
    if revoked.rows_affected() == 0 {
        return Err(ApiError::not_found());
    }
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE device_id = $1")
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    // The user's other devices are told, including those that are offline.
    let acting = Some(session.device_id);
    let notice =
        notices::insert(&mut tx, session.user_id, NoticeKind::DeviceRevoked, acting).await?;
    tx.commit().await?;

    tracing::info!(user_id = %session.user_id, %device_id, "device revoked");
    state
        .gateway
        .notify_device(device_id, Event::SessionRevoked(RevocationReason::Revoked));
    // After the revocation: the connection of the revoked device is closing,
    // so the notice reaches the remaining devices only.
    notices::publish(&state, session.user_id, notice, acting);
    state.gateway.notify_user(
        session.user_id,
        Some(device_id),
        Event::DeviceListChanged {
            device_id,
            added: false,
        },
    );
    Ok(StatusCode::NO_CONTENT)
}
