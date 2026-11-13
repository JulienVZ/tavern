// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sessions: creation, lookup from the `Authorization` header, revocation.
//!
//! A session token is 32 random bytes. The server stores its SHA-256 only, so
//! a database leak does not yield usable tokens.

use std::time::Duration;

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use data_encoding::BASE64URL_NOPAD;
use sqlx::PgPool;
use tavern_crypto::token;
use tavern_protocol::rest::{B64, SessionResponse};
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::gateway::{Event, RevocationReason};
use crate::{AppState, CLIENT_TOKEN_LEN, Enrolment};

/// Reads `Authorization: Bearer <base64url>` and returns the token bytes.
pub fn bearer_token(parts: &Parts) -> Option<Vec<u8>> {
    let value = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Bearer ")?;
    let token = BASE64URL_NOPAD.decode(encoded.trim().as_bytes()).ok()?;
    (token.len() == CLIENT_TOKEN_LEN).then_some(token)
}

/// An authenticated request: the session's account and device.
#[derive(Debug, Clone)]
pub struct Session {
    /// The account.
    pub user_id: Uuid,
    /// The device the session belongs to.
    pub device_id: Uuid,
    /// Whether the account administers the instance.
    pub is_admin: bool,
}

impl Session {
    /// Fails with `FORBIDDEN` unless the account is an administrator.
    pub fn require_admin(&self) -> ApiResult<()> {
        if self.is_admin {
            Ok(())
        } else {
            Err(ApiError::forbidden())
        }
    }
}

/// Finds the live session for a token: not revoked, not expired, on a device
/// that is not revoked, for an account that is not disabled.
pub async fn lookup(db: &PgPool, token: &[u8], ttl: Duration) -> ApiResult<Option<Session>> {
    let row: Option<(Uuid, Uuid, bool, bool)> = sqlx::query_as(
        "SELECT u.id, d.id, u.is_admin, s.last_used_at < now() - interval '1 hour' \
         FROM sessions s \
         JOIN devices d ON d.id = s.device_id \
         JOIN users u ON u.id = d.user_id \
         WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now() \
           AND d.revoked_at IS NULL AND u.disabled_at IS NULL",
    )
    .bind(token::hash(token).as_slice())
    .fetch_optional(db)
    .await?;

    let Some((user_id, device_id, is_admin, stale)) = row else {
        return Ok(None);
    };
    if stale {
        // Sliding expiry, refreshed at most once an hour. The device's
        // activity is recorded with day precision only.
        sqlx::query(
            "UPDATE sessions SET last_used_at = now(), expires_at = now() + make_interval(secs => $2) \
             WHERE device_id = $1",
        )
        .bind(device_id)
        .bind(ttl.as_secs_f64())
        .execute(db)
        .await?;
        sqlx::query("UPDATE devices SET last_seen_at = date_trunc('day', now()) WHERE id = $1")
            .bind(device_id)
            .execute(db)
            .await?;
    }
    Ok(Some(Session {
        user_id,
        device_id,
        is_admin,
    }))
}

impl FromRequestParts<AppState> for Session {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let token = bearer_token(parts).ok_or_else(ApiError::unauthenticated)?;
        lookup(&state.db, &token, state.settings.session_ttl)
            .await?
            .ok_or_else(ApiError::unauthenticated)
    }
}

/// A request authorised by an enrolment token, issued by a completed login.
/// The token is consumed by the extraction: it works once.
#[derive(Debug, Clone, Copy)]
pub struct EnrolmentAuth(pub Enrolment);

impl FromRequestParts<AppState> for EnrolmentAuth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let token = bearer_token(parts).ok_or_else(ApiError::unauthenticated)?;
        state
            .pending
            .enrolments
            .take(&token::hash(&token))
            .map(Self)
            .ok_or_else(ApiError::unauthenticated)
    }
}

/// Creates the session of a device, replacing any previous one.
pub async fn create<'e, E>(db: E, device_id: Uuid, ttl: Duration) -> ApiResult<SessionResponse>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let token: [u8; CLIENT_TOKEN_LEN] = token::random_bytes();
    let expires_at_ms: i64 = sqlx::query_scalar(
        "INSERT INTO sessions (device_id, token_hash, expires_at) \
         VALUES ($1, $2, now() + make_interval(secs => $3)) \
         ON CONFLICT (device_id) DO UPDATE SET token_hash = EXCLUDED.token_hash, \
             created_at = now(), last_used_at = now(), expires_at = EXCLUDED.expires_at, \
             revoked_at = NULL \
         RETURNING (extract(epoch FROM expires_at) * 1000)::bigint",
    )
    .bind(device_id)
    .bind(token::hash(&token).as_slice())
    .bind(ttl.as_secs_f64())
    .fetch_one(db)
    .await?;

    Ok(SessionResponse {
        device_id,
        session_token: B64(token.to_vec()),
        expires_at_ms: u64::try_from(expires_at_ms).unwrap_or_default(),
    })
}

/// Revokes every session of an account, except the one of `keep_device`, and
/// tells the affected devices if they are connected.
pub async fn revoke_all(
    state: &AppState,
    user_id: Uuid,
    keep_device: Option<Uuid>,
    reason: RevocationReason,
) -> ApiResult<()> {
    let devices: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE sessions s SET revoked_at = now() FROM devices d \
         WHERE d.id = s.device_id AND d.user_id = $1 AND s.revoked_at IS NULL \
           AND ($2::uuid IS NULL OR d.id <> $2) \
         RETURNING d.id",
    )
    .bind(user_id)
    .bind(keep_device)
    .fetch_all(&state.db)
    .await?;

    for device_id in devices {
        state
            .gateway
            .notify_device(device_id, Event::SessionRevoked(reason));
    }
    Ok(())
}
