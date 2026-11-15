// SPDX-License-Identifier: AGPL-3.0-or-later

//! Instance administration: invitations and accounts.
//!
//! Every action that changes another account is recorded in
//! `admin_audit_log` (who, what, whom, when; no free text).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use sqlx::PgPool;
use tavern_crypto::token::HumanCode;
use tavern_protocol::rest::{
    AdminUser, AdminUserList, CreateInviteRequest, CreatedInvite, ErrorBody, InviteInfo, InviteList,
};
use uuid::Uuid;

use crate::error::{ApiError, ApiJson, ApiResult};
use crate::gateway::RevocationReason;
use crate::notices::{self, NoticeKind};
use crate::session::{self, Session};
use crate::{AppState, totp};

/// Codes stored in `admin_audit_log.action`. Never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i16)]
pub enum AuditAction {
    /// An invitation was created.
    InviteCreated = 1,
    /// An invitation was revoked.
    InviteRevoked = 2,
    /// An account was disabled.
    UserDisabled = 3,
    /// An account was re-enabled.
    UserEnabled = 4,
    /// An administrator disabled a user's TOTP.
    UserTotpDisabled = 5,
}

/// Default validity of an invitation: one week.
const DEFAULT_INVITE_HOURS: u32 = 7 * 24;
/// Longest validity of an invitation: one year.
const MAX_INVITE_HOURS: u32 = 365 * 24;
/// Most uses one invitation can have.
const MAX_INVITE_USES: u32 = 100;

/// Records an administrative action. `actor` is `None` for actions run on the host.
pub async fn audit<'e, E>(
    db: E,
    actor: Option<Uuid>,
    action: AuditAction,
    target: Option<Uuid>,
) -> ApiResult<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query("INSERT INTO admin_audit_log (actor_id, action, target_id) VALUES ($1, $2, $3)")
        .bind(actor)
        .bind(action as i16)
        .bind(target)
        .execute(db)
        .await?;
    Ok(())
}

type InviteRow = (Uuid, i32, i32, bool, bool, i64, Option<i64>);
type UserRow = (Uuid, String, String, bool, bool, bool, i64, i64);

/// The columns of an [`InviteRow`], as a literal so that queries stay static.
macro_rules! invite_columns {
    () => {
        "id, max_uses, uses, grants_admin, revoked_at IS NOT NULL, \
         (extract(epoch FROM created_at) * 1000)::bigint, \
         (extract(epoch FROM expires_at) * 1000)::bigint"
    };
}

fn invite_info(row: InviteRow) -> InviteInfo {
    let (invite_id, max_uses, uses, grants_admin, revoked, created, expires) = row;
    InviteInfo {
        invite_id,
        max_uses: u32::try_from(max_uses).unwrap_or_default(),
        uses: u32::try_from(uses).unwrap_or_default(),
        grants_admin,
        revoked,
        created_at_ms: u64::try_from(created).unwrap_or_default(),
        expires_at_ms: expires.and_then(|ms| u64::try_from(ms).ok()),
    }
}

/// Creates an invitation and returns its code, which is shown only once.
pub async fn insert_invite(
    db: &PgPool,
    created_by: Option<Uuid>,
    max_uses: u32,
    expires_in_hours: u32,
    grants_admin: bool,
) -> ApiResult<CreatedInvite> {
    let code = HumanCode::generate();
    let mut tx = db.begin().await?;
    let row: InviteRow = sqlx::query_as(concat!(
        "INSERT INTO instance_invites (code_hash, created_by, grants_admin, max_uses, expires_at) \
         VALUES ($1, $2, $3, $4, now() + make_interval(hours => $5)) RETURNING ",
        invite_columns!()
    ))
    .bind(code.hash().as_slice())
    .bind(created_by)
    .bind(grants_admin)
    .bind(i32::try_from(max_uses).unwrap_or(1))
    .bind(i32::try_from(expires_in_hours).unwrap_or(i32::MAX))
    .fetch_one(&mut *tx)
    .await?;
    audit(
        &mut *tx,
        created_by,
        AuditAction::InviteCreated,
        Some(row.0),
    )
    .await?;
    tx.commit().await?;

    Ok(CreatedInvite {
        code: code.display().to_string(),
        invite: invite_info(row),
    })
}

/// Creates an invitation code.
#[utoipa::path(
    post,
    path = "/v1/admin/invites",
    tag = "admin",
    request_body = CreateInviteRequest,
    security(("session" = [])),
    responses((status = 201, body = CreatedInvite), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn create_invite(
    State(state): State<AppState>,
    session: Session,
    ApiJson(request): ApiJson<CreateInviteRequest>,
) -> ApiResult<(StatusCode, Json<CreatedInvite>)> {
    session.require_admin()?;
    let max_uses = request.max_uses.unwrap_or(1);
    let hours = request.expires_in_hours.unwrap_or(DEFAULT_INVITE_HOURS);
    if !(1..=MAX_INVITE_USES).contains(&max_uses) || !(1..=MAX_INVITE_HOURS).contains(&hours) {
        return Err(ApiError::invalid(
            "max_uses or expires_in_hours is out of range",
        ));
    }
    let created = insert_invite(&state.db, Some(session.user_id), max_uses, hours, false).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

/// Lists invitations, newest first. Codes are not recoverable.
#[utoipa::path(
    get,
    path = "/v1/admin/invites",
    tag = "admin",
    security(("session" = [])),
    responses((status = 200, body = InviteList), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn list_invites(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<InviteList>> {
    session.require_admin()?;
    let rows: Vec<InviteRow> = sqlx::query_as(concat!(
        "SELECT ",
        invite_columns!(),
        " FROM instance_invites ORDER BY created_at DESC LIMIT 500"
    ))
    .fetch_all(&state.db)
    .await?;
    Ok(Json(InviteList {
        invites: rows.into_iter().map(invite_info).collect(),
    }))
}

/// Revokes an invitation. Accounts already created with it are unaffected.
#[utoipa::path(
    delete,
    path = "/v1/admin/invites/{invite_id}",
    tag = "admin",
    params(("invite_id" = Uuid, Path, description = "The invitation to revoke")),
    security(("session" = [])),
    responses((status = 204), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn revoke_invite(
    State(state): State<AppState>,
    session: Session,
    Path(invite_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    session.require_admin()?;
    let revoked = sqlx::query(
        "UPDATE instance_invites SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(invite_id)
    .execute(&state.db)
    .await?;
    if revoked.rows_affected() == 0 {
        return Err(ApiError::not_found());
    }
    audit(
        &state.db,
        Some(session.user_id),
        AuditAction::InviteRevoked,
        Some(invite_id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Lists the accounts of the instance.
#[utoipa::path(
    get,
    path = "/v1/admin/users",
    tag = "admin",
    security(("session" = [])),
    responses((status = 200, body = AdminUserList), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn list_users(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<AdminUserList>> {
    session.require_admin()?;
    let rows: Vec<UserRow> = sqlx::query_as(
        "SELECT u.id, u.handle, u.display_name, u.is_admin, u.disabled_at IS NOT NULL, \
                u.totp_enabled_at IS NOT NULL, \
                (SELECT count(*) FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NULL), \
                (extract(epoch FROM u.created_at) * 1000)::bigint \
         FROM users u ORDER BY u.created_at",
    )
    .fetch_all(&state.db)
    .await?;

    let users = rows
        .into_iter()
        .map(
            |(
                user_id,
                handle,
                display_name,
                is_admin,
                disabled,
                totp_enabled,
                devices,
                created,
            )| {
                AdminUser {
                    user_id,
                    handle,
                    display_name,
                    is_admin,
                    disabled,
                    totp_enabled,
                    device_count: u32::try_from(devices).unwrap_or_default(),
                    created_at_ms: u64::try_from(created).unwrap_or_default(),
                }
            },
        )
        .collect();
    Ok(Json(AdminUserList { users }))
}

async fn require_other_user(state: &AppState, session: &Session, user_id: Uuid) -> ApiResult<()> {
    if user_id == session.user_id {
        return Err(ApiError::invalid(
            "this action cannot target your own account",
        ));
    }
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;
    if exists {
        Ok(())
    } else {
        Err(ApiError::not_found())
    }
}

/// Disables an account: its sessions end and it can no longer log in.
#[utoipa::path(
    post,
    path = "/v1/admin/users/{user_id}/disable",
    tag = "admin",
    params(("user_id" = Uuid, Path, description = "The account to disable")),
    security(("session" = [])),
    responses((status = 204), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn disable_user(
    State(state): State<AppState>,
    session: Session,
    Path(user_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    session.require_admin()?;
    require_other_user(&state, &session, user_id).await?;
    sqlx::query("UPDATE users SET disabled_at = now() WHERE id = $1 AND disabled_at IS NULL")
        .bind(user_id)
        .execute(&state.db)
        .await?;
    session::revoke_all(&state, user_id, None, RevocationReason::AccountDisabled).await?;
    audit(
        &state.db,
        Some(session.user_id),
        AuditAction::UserDisabled,
        Some(user_id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Re-enables a disabled account.
#[utoipa::path(
    post,
    path = "/v1/admin/users/{user_id}/enable",
    tag = "admin",
    params(("user_id" = Uuid, Path, description = "The account to enable")),
    security(("session" = [])),
    responses((status = 204), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn enable_user(
    State(state): State<AppState>,
    session: Session,
    Path(user_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    session.require_admin()?;
    require_other_user(&state, &session, user_id).await?;
    sqlx::query("UPDATE users SET disabled_at = NULL WHERE id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await?;
    audit(
        &state.db,
        Some(session.user_id),
        AuditAction::UserEnabled,
        Some(user_id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Disables TOTP for a user who lost both their authenticator and their
/// recovery codes.
///
/// TOTP is a server-side check, so an administrator removing it does not give
/// access to anything the server could not already reach: the password is
/// still required, and the wrapped account key is protected by the password,
/// not by TOTP. Every device of the user is told, at once or at its next
/// connection, and the action is recorded.
#[utoipa::path(
    post,
    path = "/v1/admin/users/{user_id}/totp/disable",
    tag = "admin",
    params(("user_id" = Uuid, Path, description = "The account whose TOTP is disabled")),
    security(("session" = [])),
    responses((status = 204), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn disable_user_totp(
    State(state): State<AppState>,
    session: Session,
    Path(user_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    session.require_admin()?;
    require_other_user(&state, &session, user_id).await?;
    totp::clear(&state.db, user_id).await?;
    audit(
        &state.db,
        Some(session.user_id),
        AuditAction::UserTotpDisabled,
        Some(user_id),
    )
    .await?;
    notices::record(&state, user_id, NoticeKind::TotpDisabledByAdmin, None).await?;
    tracing::warn!(admin = %session.user_id, %user_id, "TOTP disabled by an administrator");
    Ok(StatusCode::NO_CONTENT)
}
