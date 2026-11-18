// SPDX-License-Identifier: AGPL-3.0-or-later

//! Conversations (ADR 0019, section 4): in M2, the DM between two friends,
//! one per pair.
//!
//! Creating a DM reserves the conversation; its first device builds the MLS
//! group and submits the first commit (tasks 8 and 9). A conversation may
//! therefore have no group (`epoch` null): any active device of either user
//! may then create it, the first commit for epoch 0 wins.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use sqlx::PgExecutor;
use tavern_protocol::rest::{
    Conversation, ConversationKind, ConversationList, CreateDmRequest, ErrorBody, ErrorCode,
};
use uuid::Uuid;

use crate::AppState;
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::gateway::Event;
use crate::routes::friends;
use crate::session::Session;

fn not_friends() -> ApiError {
    ApiError::new(
        ErrorCode::NotFriends,
        "a DM needs two users who are friends",
    )
}

/// A DM, its group if any, and whether its users are friends.
type Row = (Uuid, i64, Uuid, Uuid, Option<i64>, Option<i64>, bool);

/// The DMs of `user`, or the one with id `only`, oldest first.
async fn dms<'c>(db: impl PgExecutor<'c>, user: Uuid, only: Option<Uuid>) -> ApiResult<Vec<Row>> {
    Ok(sqlx::query_as(
        "SELECT c.id, c.last_seq, d.user_low, d.user_high, g.generation, g.epoch, \
                EXISTS (SELECT 1 FROM friendships f \
                        WHERE f.user_low = d.user_low AND f.user_high = d.user_high \
                          AND f.status = 'accepted') \
         FROM dm_conversations d \
         JOIN conversations c ON c.id = d.conversation_id \
         LEFT JOIN mls_groups g ON g.conversation_id = c.id \
         WHERE (d.user_low = $1 OR d.user_high = $1) AND ($2::uuid IS NULL OR c.id = $2) \
         ORDER BY c.created_at, c.id",
    )
    .bind(user)
    .bind(only)
    .fetch_all(db)
    .await?)
}

fn view((id, last_seq, low, high, generation, epoch, friends): Row) -> Conversation {
    Conversation {
        conversation_id: id,
        kind: ConversationKind::Dm,
        members: vec![low, high],
        generation: generation.and_then(|generation| u32::try_from(generation).ok()),
        epoch: epoch.and_then(|epoch| u64::try_from(epoch).ok()),
        last_seq: u64::try_from(last_seq).unwrap_or_default(),
        read_only: !friends,
    }
}

/// Creates the DM with a friend, or returns it if it exists: one DM per
/// pair, also when two creations cross, and the same DM when two users
/// become friends again. `201` when created, `200` when it existed. Anyone
/// who is not a friend, an unknown user and a blocked or blocking one
/// alike, gets `NOT_FRIENDS`.
#[utoipa::path(
    post,
    path = "/v1/conversations",
    tag = "conversations",
    request_body = CreateDmRequest,
    security(("session" = [])),
    responses(
        (status = 201, body = Conversation),
        (status = 200, body = Conversation),
        (status = "4XX", body = ErrorBody)
    )
)]
pub(crate) async fn create(
    State(state): State<AppState>,
    session: Session,
    ApiJson(request): ApiJson<CreateDmRequest>,
) -> ApiResult<(StatusCode, Json<Conversation>)> {
    let me = session.user_id;
    let peer = request.user_id;
    if peer == me {
        return Err(ApiError::invalid("a DM needs two users"));
    }
    let (low, high) = friends::pair(me, peer);

    let mut tx = state.db.begin().await?;
    // The pair's turn: crossed creations, an unfriending and a block take
    // it too.
    let friendship = friends::lock_pair(&mut tx, me, peer).await?;
    if !friendship.is_some_and(|row| row.accepted) {
        return Err(not_friends());
    }
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT conversation_id FROM dm_conversations WHERE user_low = $1 AND user_high = $2",
    )
    .bind(low)
    .bind(high)
    .fetch_optional(&mut *tx)
    .await?;
    let (id, status) = match existing {
        Some(id) => (id, StatusCode::OK),
        None => {
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO conversations (kind, created_by) VALUES ('dm', $1) RETURNING id",
            )
            .bind(me)
            .fetch_one(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO dm_conversations (conversation_id, user_low, user_high) \
                 VALUES ($1, $2, $3)",
            )
            .bind(id)
            .bind(low)
            .bind(high)
            .execute(&mut *tx)
            .await?;
            (id, StatusCode::CREATED)
        }
    };
    let row = dms(&mut *tx, me, Some(id))
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::internal("conversations", &"the DM just written is gone"))?;
    tx.commit().await?;

    if status == StatusCode::CREATED {
        let event = Event::ConversationCreated {
            conversation_id: id,
            members: [low, high],
        };
        state.gateway.notify_user(me, None, event);
        state.gateway.notify_user(peer, None, event);
    }
    Ok((status, Json(view(row))))
}

/// The user's conversations, oldest first, each with its group's generation
/// and epoch (`null` while it has no group), and `read_only` for a DM whose
/// users are not friends any more.
#[utoipa::path(
    get,
    path = "/v1/conversations",
    tag = "conversations",
    security(("session" = [])),
    responses((status = 200, body = ConversationList), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn list(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<ConversationList>> {
    let rows = dms(&state.db, session.user_id, None).await?;
    Ok(Json(ConversationList {
        conversations: rows.into_iter().map(view).collect(),
    }))
}
