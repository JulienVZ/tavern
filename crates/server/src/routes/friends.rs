// SPDX-License-Identifier: AGPL-3.0-or-later

//! Friends and blocks (ADR 0020).
//!
//! A pair of users has at most one row in `friendships`: a request, or a
//! friendship. Operations on one pair take turns on a lock held until their
//! transaction ends, so that two crossed requests, an acceptance and a block
//! never interleave. A block is never disclosed to the blocked user: what
//! they see is what an unfriending or an unanswered request shows. A request
//! they send to their blocker is kept as theirs alone, never shown to the
//! blocker, and deleted when the block is lifted.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use sqlx::{PgConnection, PgExecutor};
use tavern_protocol::rest::{
    B64, ErrorBody, ErrorCode, FriendList, FriendRequest, FriendRequestAnswer, RequestOutcome,
    UserSummary,
};
use uuid::Uuid;

use crate::AppState;
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::gateway::{Event, Relation};
use crate::routes::parse_handle;
use crate::session::Session;

/// A pair as `friendships` stores it: smaller id first. PostgreSQL and
/// `Uuid` order ids alike, byte by byte.
pub(crate) fn pair(a: Uuid, b: Uuid) -> (Uuid, Uuid) {
    if a < b { (a, b) } else { (b, a) }
}

/// The row of a pair.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Row {
    /// Friends, not a request.
    pub(crate) accepted: bool,
    requested_by: Uuid,
    hidden: bool,
}

impl Row {
    /// Whether `user` sees this row: a hidden request is its sender's only.
    fn seen_by(self, user: Uuid) -> bool {
        !self.hidden || self.requested_by == user
    }
}

/// Takes the pair's turn, until the transaction ends, and reads its row.
/// Creating the pair's DM takes the same turn, so that it never interleaves
/// with an unfriending or a block.
pub(crate) async fn lock_pair(conn: &mut PgConnection, a: Uuid, b: Uuid) -> ApiResult<Option<Row>> {
    let (low, high) = pair(a, b);
    // An advisory lock: the row may not exist yet.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("tavern.friendships:{low}:{high}"))
        .execute(&mut *conn)
        .await?;
    let row: Option<(bool, Uuid, bool)> = sqlx::query_as(
        "SELECT status = 'accepted', requested_by, hidden FROM friendships \
         WHERE user_low = $1 AND user_high = $2",
    )
    .bind(low)
    .bind(high)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(|(accepted, requested_by, hidden)| Row {
        accepted,
        requested_by,
        hidden,
    }))
}

async fn delete_pair(conn: &mut PgConnection, a: Uuid, b: Uuid) -> ApiResult<()> {
    let (low, high) = pair(a, b);
    sqlx::query("DELETE FROM friendships WHERE user_low = $1 AND user_high = $2")
        .bind(low)
        .bind(high)
        .execute(conn)
        .await?;
    Ok(())
}

async fn accept_pair(conn: &mut PgConnection, a: Uuid, b: Uuid) -> ApiResult<()> {
    let (low, high) = pair(a, b);
    sqlx::query(
        "UPDATE friendships SET status = 'accepted', accepted_at = now() \
         WHERE user_low = $1 AND user_high = $2",
    )
    .bind(low)
    .bind(high)
    .execute(conn)
    .await?;
    Ok(())
}

async fn blocks<'c>(db: impl PgExecutor<'c>, blocker: Uuid, blocked: Uuid) -> ApiResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2)",
    )
    .bind(blocker)
    .bind(blocked)
    .fetch_one(db)
    .await?)
}

async fn user_exists<'c>(db: impl PgExecutor<'c>, user: Uuid) -> ApiResult<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
            .bind(user)
            .fetch_one(db)
            .await?,
    )
}

/// Tells `user`'s connected devices where they now stand with `other`.
fn tell(state: &AppState, user: Uuid, other: Uuid, relation: Relation) {
    state.gateway.notify_user(
        user,
        None,
        Event::FriendshipChanged {
            user_id: other,
            relation,
        },
    );
}

/// Tells the connected devices of `user`'s friends that `user` enrolled
/// (`added`) or revoked `device`. Called once the change is committed: a
/// failure here is logged, and the change stands.
pub(crate) async fn tell_friends_about_device(
    state: &AppState,
    user: Uuid,
    device: Uuid,
    added: bool,
) {
    let friends: Result<Vec<Uuid>, sqlx::Error> = sqlx::query_scalar(
        "SELECT CASE WHEN user_low = $1 THEN user_high ELSE user_low END FROM friendships \
         WHERE (user_low = $1 OR user_high = $1) AND status = 'accepted'",
    )
    .bind(user)
    .fetch_all(&state.db)
    .await;
    match friends {
        Ok(friends) => {
            for friend in friends {
                state.gateway.notify_user(
                    friend,
                    None,
                    Event::UserDevicesChanged {
                        user_id: user,
                        device_id: device,
                        added,
                    },
                );
            }
        }
        Err(error) => tracing::warn!(%error, "friends not told about a device"),
    }
}

type SummaryRow = (Uuid, String, String, Vec<u8>, i64);
/// A summary, then whether the friendship is accepted, and who asked.
type RelationRow = (Uuid, String, String, Vec<u8>, i64, bool, Uuid);

fn summary((user_id, handle, display_name, identity_key, since): SummaryRow) -> UserSummary {
    UserSummary {
        user_id,
        handle,
        display_name,
        identity_key: B64(identity_key),
        since_ms: u64::try_from(since).unwrap_or_default(),
    }
}

/// The user's friends, the requests they received and sent, and the users
/// they block.
#[utoipa::path(
    get,
    path = "/v1/friends",
    tag = "friends",
    security(("session" = [])),
    responses((status = 200, body = FriendList), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn list(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<FriendList>> {
    let me = session.user_id;
    let rows: Vec<RelationRow> = sqlx::query_as(
        "SELECT u.id, u.handle, u.display_name, u.identity_key, \
                (extract(epoch FROM COALESCE(f.accepted_at, f.created_at)) * 1000)::bigint, \
                f.status = 'accepted', f.requested_by \
         FROM friendships f \
         JOIN users u ON u.id = CASE WHEN f.user_low = $1 THEN f.user_high ELSE f.user_low END \
         WHERE (f.user_low = $1 OR f.user_high = $1) AND (NOT f.hidden OR f.requested_by = $1) \
         ORDER BY u.handle",
    )
    .bind(me)
    .fetch_all(&state.db)
    .await?;
    let mut list = FriendList {
        friends: Vec::new(),
        received: Vec::new(),
        sent: Vec::new(),
        blocked: Vec::new(),
    };
    for (id, handle, name, key, since, accepted, requested_by) in rows {
        let entry = summary((id, handle, name, key, since));
        if accepted {
            list.friends.push(entry);
        } else if requested_by == me {
            list.sent.push(entry);
        } else {
            list.received.push(entry);
        }
    }
    let blocked: Vec<SummaryRow> = sqlx::query_as(
        "SELECT u.id, u.handle, u.display_name, u.identity_key, \
                (extract(epoch FROM b.created_at) * 1000)::bigint \
         FROM blocks b JOIN users u ON u.id = b.blocked_id \
         WHERE b.blocker_id = $1 ORDER BY u.handle",
    )
    .bind(me)
    .fetch_all(&state.db)
    .await?;
    list.blocked = blocked.into_iter().map(summary).collect();
    Ok(Json(list))
}

/// Sends a friend request, by handle. A request crossing one from the same
/// user makes both friends. Sending it again changes nothing. A request to a
/// user who blocks the sender looks sent, and stays the sender's alone. At
/// most 20 requests an hour per user (configurable), unknown handles
/// included.
#[utoipa::path(
    post,
    path = "/v1/friends/requests",
    tag = "friends",
    request_body = FriendRequest,
    security(("session" = [])),
    responses((status = 200, body = FriendRequestAnswer), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn request(
    State(state): State<AppState>,
    session: Session,
    ApiJson(request): ApiJson<FriendRequest>,
) -> ApiResult<Json<FriendRequestAnswer>> {
    let me = session.user_id;
    state.rate_limits.friend_requests.check(me)?;
    let handle = parse_handle(&request.handle)?;
    let target: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE handle = $1")
        .bind(handle.as_str())
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if target == me {
        return Err(ApiError::invalid(
            "one cannot send a friend request to oneself",
        ));
    }

    let mut tx = state.db.begin().await?;
    let row = lock_pair(&mut tx, me, target).await?;
    if blocks(&mut *tx, me, target).await? {
        return Err(ApiError::new(
            ErrorCode::Blocked,
            "you block this user: unblock them first",
        ));
    }
    let (outcome, events) = match row {
        Some(row) if row.accepted => {
            return Err(ApiError::new(ErrorCode::AlreadyExists, "already friends"));
        }
        // Sent again: one request per pair.
        Some(row) if row.requested_by == me => (RequestOutcome::RequestSent, Vec::new()),
        // Crossed: the other user asked first.
        Some(_) => {
            accept_pair(&mut tx, me, target).await?;
            (
                RequestOutcome::Friends,
                vec![
                    (me, target, Relation::Friends),
                    (target, me, Relation::Friends),
                ],
            )
        }
        None => {
            let hidden = blocks(&mut *tx, target, me).await?;
            let (low, high) = pair(me, target);
            sqlx::query(
                "INSERT INTO friendships (user_low, user_high, status, requested_by, hidden) \
                 VALUES ($1, $2, 'pending', $3, $4)",
            )
            .bind(low)
            .bind(high)
            .bind(me)
            .bind(hidden)
            .execute(&mut *tx)
            .await?;
            let mut events = vec![(me, target, Relation::RequestSent)];
            if !hidden {
                events.push((target, me, Relation::RequestReceived));
            }
            (RequestOutcome::RequestSent, events)
        }
    };
    tx.commit().await?;
    for (user, other, relation) in events {
        tell(&state, user, other, relation);
    }
    Ok(Json(FriendRequestAnswer {
        user_id: target,
        outcome,
    }))
}

/// Accepts the friend request `user_id` sent.
#[utoipa::path(
    post,
    path = "/v1/friends/requests/{user_id}/accept",
    tag = "friends",
    params(("user_id" = Uuid, Path, description = "The user who sent the request")),
    security(("session" = [])),
    responses((status = 204), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn accept(
    State(state): State<AppState>,
    session: Session,
    Path(user_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let me = session.user_id;
    let mut tx = state.db.begin().await?;
    match lock_pair(&mut tx, me, user_id).await? {
        Some(row) if !row.accepted && row.requested_by == user_id && row.seen_by(me) => {
            accept_pair(&mut tx, me, user_id).await?;
        }
        _ => return Err(ApiError::not_found()),
    }
    tx.commit().await?;
    tell(&state, me, user_id, Relation::Friends);
    tell(&state, user_id, me, Relation::Friends);
    Ok(StatusCode::NO_CONTENT)
}

/// Declines the request `user_id` sent, or cancels the one sent to them.
#[utoipa::path(
    delete,
    path = "/v1/friends/requests/{user_id}",
    tag = "friends",
    params(("user_id" = Uuid, Path, description = "The other user of the request")),
    security(("session" = [])),
    responses((status = 204), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn remove_request(
    State(state): State<AppState>,
    session: Session,
    Path(user_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let me = session.user_id;
    let mut tx = state.db.begin().await?;
    let row = match lock_pair(&mut tx, me, user_id).await? {
        Some(row) if !row.accepted && row.seen_by(me) => row,
        _ => return Err(ApiError::not_found()),
    };
    delete_pair(&mut tx, me, user_id).await?;
    tx.commit().await?;
    tell(&state, me, user_id, Relation::None);
    if row.seen_by(user_id) {
        tell(&state, user_id, me, Relation::None);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Ends a friendship.
#[utoipa::path(
    delete,
    path = "/v1/friends/{user_id}",
    tag = "friends",
    params(("user_id" = Uuid, Path, description = "The friend")),
    security(("session" = [])),
    responses((status = 204), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn unfriend(
    State(state): State<AppState>,
    session: Session,
    Path(user_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let me = session.user_id;
    let mut tx = state.db.begin().await?;
    match lock_pair(&mut tx, me, user_id).await? {
        Some(row) if row.accepted => delete_pair(&mut tx, me, user_id).await?,
        _ => return Err(ApiError::not_found()),
    }
    tx.commit().await?;
    tell(&state, me, user_id, Relation::None);
    tell(&state, user_id, me, Relation::None);
    Ok(StatusCode::NO_CONTENT)
}

/// Blocks a user. A friendship or a request between the two ends. The
/// blocked user sees what an unfriending shows, and is not told of the
/// block. Blocking again changes nothing.
#[utoipa::path(
    put,
    path = "/v1/blocks/{user_id}",
    tag = "friends",
    params(("user_id" = Uuid, Path, description = "The user to block")),
    security(("session" = [])),
    responses((status = 204), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn block(
    State(state): State<AppState>,
    session: Session,
    Path(user_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let me = session.user_id;
    if user_id == me {
        return Err(ApiError::invalid("one cannot block oneself"));
    }
    if !user_exists(&state.db, user_id).await? {
        return Err(ApiError::not_found());
    }
    let mut tx = state.db.begin().await?;
    let row = lock_pair(&mut tx, me, user_id).await?;
    let inserted = sqlx::query(
        "INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(me)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Ok(StatusCode::NO_CONTENT);
    }
    delete_pair(&mut tx, me, user_id).await?;
    tx.commit().await?;
    tell(&state, me, user_id, Relation::Blocked);
    if row.is_some_and(|row| row.seen_by(user_id)) {
        tell(&state, user_id, me, Relation::None);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Lifts a block. A request the blocked user sent meanwhile is deleted:
/// being reachable again accepts nothing that was sent before.
#[utoipa::path(
    delete,
    path = "/v1/blocks/{user_id}",
    tag = "friends",
    params(("user_id" = Uuid, Path, description = "The user to unblock")),
    security(("session" = [])),
    responses((status = 204), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn unblock(
    State(state): State<AppState>,
    session: Session,
    Path(user_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let me = session.user_id;
    let mut tx = state.db.begin().await?;
    let row = lock_pair(&mut tx, me, user_id).await?;
    let removed = sqlx::query("DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2")
        .bind(me)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    if removed.rows_affected() == 0 {
        return Err(ApiError::not_found());
    }
    let sent_meanwhile = row.filter(|row| row.hidden && row.requested_by == user_id);
    if sent_meanwhile.is_some() {
        delete_pair(&mut tx, me, user_id).await?;
    }
    tx.commit().await?;
    tell(&state, me, user_id, Relation::None);
    if sent_meanwhile.is_some() {
        tell(&state, user_id, me, Relation::None);
    }
    Ok(StatusCode::NO_CONTENT)
}
