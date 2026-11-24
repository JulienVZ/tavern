// SPDX-License-Identifier: AGPL-3.0-or-later

//! A conversation's sequence (ADR 0019, sections 4 to 7, 12 and 16).
//!
//! Every request that adds to a conversation's sequence locks the
//! conversation's row first: commits, application messages and the server's
//! proposals are numbered one at a time ([`append`]), strictly increasing
//! and without gaps, since a transaction that fails takes its number back
//! with it. The group's devices (`conversation_devices`) are computed from
//! the public tree merged in the same transaction, never from what a client
//! says; they are who receives what.
//!
//! A DM whose users are not friends any more is read-only (section 16): no
//! application message, no new leaf and no GroupInfo, while removals and
//! updates of one's own leaf go through. The blocked user is answered what
//! an unfriended one is (`NOT_FRIENDS`), by the same work; only the blocker
//! gets `BLOCKED` (ADR 0020).
//!
//! A device the server asked to remove (`pending_removals`, sections 6 and
//! 15) is cut off from its proposal on: it is told nothing more of the
//! conversation, reads the sequence up to that proposal and no further, and
//! sends nothing. It may still fetch the GroupInfo and come back by external
//! commit if it is active again (a device back after an inactivity), and
//! that commit, which removes its earlier leaf, settles the removal.

use std::sync::Arc;

use sqlx::PgConnection;
use tavern_crypto::mls::group_id::GroupIdentity;
use tavern_crypto::mls::{
    ExpectedGroup, MlsError, PROPOSAL_QUEUE_KIND, PublicState, Refusal, ServerSigner, VerifiedLeaf,
    application_header, first_commit_sender, welcome_key_packages,
};
use tavern_protocol::gateway::v1 as proto;
use tavern_protocol::{
    MAX_APPLICATION_MESSAGE_BYTES, MAX_COMMIT_BYTES, MAX_FETCH_MESSAGES, MAX_GROUP_INFO_BYTES,
    MAX_WELCOME_BYTES,
};
use uuid::Uuid;

use crate::AppState;
use crate::activity;
use crate::gateway::Event;
use crate::mls::{self, ServerRoster, StateError};
use crate::routes::friends;
use crate::session::Session;

/// A refused request: what the gateway answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    /// The code.
    pub code: proto::ErrorCode,
    /// For logs and developers; never says more than the code.
    pub message: &'static str,
    /// With `STALE_EPOCH`, the group's current epoch when known; 0
    /// otherwise.
    pub current_epoch: u64,
}

impl Refused {
    const fn new(code: proto::ErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message,
            current_epoch: 0,
        }
    }

    /// The error frame's payload.
    pub fn to_proto(self) -> proto::Error {
        proto::Error {
            code: self.code.into(),
            message: self.message.to_owned(),
            retry_after_ms: 0,
            current_epoch: self.current_epoch,
        }
    }

    fn stale_at(current_epoch: u64) -> Self {
        Self {
            current_epoch,
            ..Self::stale()
        }
    }

    fn internal() -> Self {
        Self::new(proto::ErrorCode::Internal, "internal error")
    }

    fn invalid(message: &'static str) -> Self {
        Self::new(proto::ErrorCode::InvalidArgument, message)
    }

    fn not_a_member() -> Self {
        Self::new(
            proto::ErrorCode::NotAMember,
            "not a device of this conversation",
        )
    }

    fn stale() -> Self {
        Self::new(
            proto::ErrorCode::StaleEpoch,
            "for a past epoch: apply what is new, then send again",
        )
    }

    fn invalid_commit() -> Self {
        Self::new(
            proto::ErrorCode::InvalidCommit,
            "the commit fails validation against the group",
        )
    }

    fn wrong_welcome() -> Self {
        Self::new(
            proto::ErrorCode::InvalidCommit,
            "the Welcome is not for exactly the KeyPackages the commit adds",
        )
    }
}

impl From<sqlx::Error> for Refused {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "database");
        Self::internal()
    }
}

type Result<T> = std::result::Result<T, Refused>;

/// What a commit's refusal tells the device, the group being at
/// `current_epoch`.
fn commit_refused(error: MlsError, current_epoch: u64) -> Refused {
    match error {
        MlsError::Refused(Refusal::PastEpoch) => Refused::stale_at(current_epoch),
        MlsError::RemovalPending => Refused::new(
            proto::ErrorCode::RemovalPending,
            "commit the server's pending removals too",
        ),
        MlsError::Library(error) => {
            tracing::error!(%error, "MLS library");
            Refused::internal()
        }
        MlsError::Alarm(_)
        | MlsError::Leaf(_)
        | MlsError::Policy(_)
        | MlsError::Refused(_)
        | MlsError::OutOfSync(_)
        | MlsError::BeingRemoved
        | MlsError::WrongSender
        | MlsError::GroupInfo
        | MlsError::Invalid(_)
        | MlsError::Padding(_)
        | MlsError::Malformed
        | MlsError::Parameters
        | MlsError::UnexpectedGroup => Refused::invalid_commit(),
    }
}

fn state_refused(error: StateError) -> Refused {
    match error {
        // Another device created the group, or committed, first.
        StateError::GenerationExists => Refused::stale(),
        StateError::Mls(error) => commit_refused(error, 0),
        StateError::Database(error) => error.into(),
        StateError::NoConversation => Refused::not_a_member(),
        StateError::Inconsistent => {
            tracing::error!("a group's stored state does not match it");
            Refused::internal()
        }
    }
}

/// What an entry of the sequence is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An application message (MLS `PrivateMessage`).
    Application,
    /// A commit (MLS `PublicMessage`).
    Commit,
    /// One of the server's `Remove` proposals (MLS `PublicMessage`).
    Proposal,
}

impl Kind {
    fn code(self) -> i16 {
        match self {
            Self::Application => 1,
            Self::Commit => 2,
            Self::Proposal => 3,
        }
    }

    fn from_code(code: i16) -> proto::MessageKind {
        match code {
            1 => proto::MessageKind::Application,
            2 => proto::MessageKind::Commit,
            3 => proto::MessageKind::Proposal,
            _ => proto::MessageKind::Unspecified,
        }
    }
}

/// An entry just appended to a sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appended {
    /// Its number in the sequence.
    pub seq: i64,
    /// When the server took it, in milliseconds since the Unix epoch.
    pub at_ms: i64,
}

/// Appends an entry to `conversation`'s sequence. The caller holds the
/// conversation's row ([`lock`]) in this transaction: the entry gets the
/// next number, which a failed transaction takes back.
pub async fn append(
    conn: &mut PgConnection,
    conversation: Uuid,
    kind: Kind,
    epoch: u64,
    sender: Option<Uuid>,
    payload: &[u8],
    retention_days: u32,
) -> std::result::Result<Appended, sqlx::Error> {
    let (seq, at_ms): (i64, i64) = sqlx::query_as(
        "WITH next AS ( \
             UPDATE conversations SET last_seq = last_seq + 1 WHERE id = $1 RETURNING last_seq) \
         INSERT INTO messages \
             (conversation_id, seq, epoch, kind, sender_device_id, payload, expires_at) \
         SELECT $1, last_seq, $2, $3, $4, $5, now() + make_interval(days => $6) FROM next \
         RETURNING seq, (extract(epoch FROM created_at) * 1000)::bigint",
    )
    .bind(conversation)
    .bind(i64::try_from(epoch).unwrap_or(i64::MAX))
    .bind(kind.code())
    .bind(sender)
    .bind(payload)
    .bind(i32::try_from(retention_days).unwrap_or(i32::MAX))
    .fetch_one(conn)
    .await?;
    Ok(Appended { seq, at_ms })
}

/// A DM, locked for this transaction.
#[derive(Debug, Clone, Copy)]
pub struct Dm {
    /// The conversation.
    pub conversation: Uuid,
    /// Its users, smaller id first.
    pub users: [Uuid; 2],
}

impl Dm {
    fn peer(self, me: Uuid) -> Uuid {
        if self.users[0] == me {
            self.users[1]
        } else {
            self.users[0]
        }
    }

    fn participants(self) -> [[u8; 16]; 2] {
        [*self.users[0].as_bytes(), *self.users[1].as_bytes()]
    }
}

/// Locks `conversation`'s row until the transaction ends: requests that add
/// to its sequence take turns. Refused with `NOT_A_MEMBER` unless `me` is
/// one of its users, an unknown conversation alike.
pub async fn lock(conn: &mut PgConnection, conversation: Uuid, me: Uuid) -> Result<Dm> {
    let row: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT d.user_low, d.user_high FROM conversations c \
         JOIN dm_conversations d ON d.conversation_id = c.id \
         WHERE c.id = $1 FOR UPDATE OF c",
    )
    .bind(conversation)
    .fetch_optional(conn)
    .await?;
    match row {
        Some((low, high)) if me == low || me == high => Ok(Dm {
            conversation,
            users: [low, high],
        }),
        _ => Err(Refused::not_a_member()),
    }
}

/// Whether `me` may add to the DM with `peer`: only between friends
/// (section 16). Whoever blocks whom, the same query runs and the blocked
/// user gets what an unfriended one gets.
async fn writable(conn: &mut PgConnection, me: Uuid, peer: Uuid) -> Result<()> {
    let (low, high) = friends::pair(me, peer);
    let (friends, blocks): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM friendships \
                        WHERE user_low = $1 AND user_high = $2 AND status = 'accepted'), \
                EXISTS (SELECT 1 FROM blocks WHERE blocker_id = $3 AND blocked_id = $4)",
    )
    .bind(low)
    .bind(high)
    .bind(me)
    .bind(peer)
    .fetch_one(conn)
    .await?;
    if friends {
        Ok(())
    } else if blocks {
        Err(Refused::new(
            proto::ErrorCode::Blocked,
            "you block this user: unblock them to write",
        ))
    } else {
        Err(Refused::new(
            proto::ErrorCode::NotFriends,
            "read-only: the users are not friends any more",
        ))
    }
}

/// The conversation's group: generation and epoch.
pub(crate) async fn group_of(
    conn: &mut PgConnection,
    conversation: Uuid,
) -> std::result::Result<Option<(u32, u64)>, sqlx::Error> {
    let row: Option<(i64, i64)> =
        sqlx::query_as("SELECT generation, epoch FROM mls_groups WHERE conversation_id = $1")
            .bind(conversation)
            .fetch_optional(conn)
            .await?;
    Ok(row.and_then(|(generation, epoch)| {
        Some((u32::try_from(generation).ok()?, u64::try_from(epoch).ok()?))
    }))
}

/// The SQL condition, on a row of `conversation_devices` named by the
/// alias, that a device of the group meets when it is not cut off by a
/// pending removal: who receives what, and who may send. A string literal,
/// for `concat!`: queries stay static.
macro_rules! not_cut_off {
    ($alias:literal) => {
        concat!(
            "NOT EXISTS (SELECT 1 FROM pending_removals p WHERE p.conversation_id = ",
            $alias,
            ".conversation_id AND p.device_id = ",
            $alias,
            ".device_id)"
        )
    };
}
pub(crate) use not_cut_off;

/// The devices of the conversation's group that receive what is appended
/// to its sequence: not those the server asked to remove.
pub(crate) async fn members(
    conn: &mut PgConnection,
    conversation: Uuid,
) -> std::result::Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(concat!(
        "SELECT device_id FROM conversation_devices d \
         WHERE conversation_id = $1 AND left_seq IS NULL AND ",
        not_cut_off!("d")
    ))
    .bind(conversation)
    .fetch_all(conn)
    .await
}

/// Whether the two users of a DM are friends: only then is it open to
/// writing, and only then are devices left out told to join (section 4).
async fn friends_now(conn: &mut PgConnection, dm: Dm) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM friendships \
                        WHERE user_low = $1 AND user_high = $2 AND status = 'accepted')",
    )
    .bind(dm.users[0])
    .bind(dm.users[1])
    .fetch_one(conn)
    .await?)
}

/// The active devices of the DM's users that are not in its group, or that
/// the server asked to remove: they have the conversation to join by
/// external commit (section 4). Computed, never stored.
async fn left_out(
    conn: &mut PgConnection,
    dm: Dm,
    inactive_days: u32,
) -> std::result::Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(concat!(
        "SELECT d.id FROM devices d JOIN users u ON u.id = d.user_id \
         WHERE d.user_id = ANY($1) AND ",
        activity::active_device!("$3"),
        " AND NOT EXISTS (SELECT 1 FROM conversation_devices c \
                          WHERE c.conversation_id = $2 AND c.device_id = d.id \
                            AND c.left_seq IS NULL AND ",
        not_cut_off!("c"),
        ") ORDER BY d.id"
    ))
    .bind(&dm.users[..])
    .bind(dm.conversation)
    .bind(activity::window(inactive_days))
    .fetch_all(conn)
    .await
}

/// Keeps `pending_removals` as the merged state has it: a row goes when its
/// leaf is no longer to remove (a commit removed it), and a removal asked
/// again after an external commit moves to its new proposal.
async fn settle_removals(
    conn: &mut PgConnection,
    conversation: Uuid,
    still_pending: &[i32],
    reissued: &[(i32, i64)],
) -> std::result::Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM pending_removals \
         WHERE conversation_id = $1 AND NOT (leaf_index = ANY($2))",
    )
    .bind(conversation)
    .bind(still_pending)
    .execute(&mut *conn)
    .await?;
    for (leaf, seq) in reissued {
        sqlx::query(
            "UPDATE pending_removals SET proposal_seq = $3 \
             WHERE conversation_id = $1 AND leaf_index = $2",
        )
        .bind(conversation)
        .bind(leaf)
        .bind(seq)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Writes the group's devices as the merged tree has them, `seq` being the
/// commit that made it so: a device gone leaves at it, a device that joins,
/// or that came back under another leaf (a resync), reads the sequence
/// after it.
async fn sync_leaves(
    conn: &mut PgConnection,
    conversation: Uuid,
    leaves: &[(u32, VerifiedLeaf)],
    seq: i64,
) -> Result<()> {
    let devices: Vec<Uuid> = leaves
        .iter()
        .map(|(_, leaf)| Uuid::from_bytes(leaf.device_id))
        .collect();
    let indexes: Vec<i32> = leaves
        .iter()
        .map(|(index, _)| i32::try_from(*index).unwrap_or(i32::MAX))
        .collect();
    sqlx::query(
        "UPDATE conversation_devices SET left_seq = $2 \
         WHERE conversation_id = $1 AND left_seq IS NULL \
           AND (device_id, leaf_index) NOT IN ( \
               SELECT device, leaf FROM unnest($3::uuid[], $4::integer[]) AS t(device, leaf))",
    )
    .bind(conversation)
    .bind(seq)
    .bind(&devices)
    .bind(&indexes)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO conversation_devices \
             (conversation_id, device_id, leaf_index, joined_seq, acked_seq) \
         SELECT $1, device, leaf, $4, $4 \
         FROM unnest($2::uuid[], $3::integer[]) AS t(device, leaf) \
         ON CONFLICT (conversation_id, device_id) DO UPDATE \
         SET leaf_index = EXCLUDED.leaf_index, joined_seq = EXCLUDED.joined_seq, \
             acked_seq = EXCLUDED.acked_seq, left_seq = NULL \
         WHERE conversation_devices.left_seq IS NOT NULL",
    )
    .bind(conversation)
    .bind(&devices)
    .bind(&indexes)
    .bind(seq)
    .execute(conn)
    .await?;
    Ok(())
}

/// Checks that `welcome` is for exactly the KeyPackages `added` (their
/// references), the ones a member's commit adds; no Welcome when it adds
/// none.
fn welcome_covers(welcome: &[u8], mut added: Vec<Vec<u8>>) -> Result<()> {
    if added.is_empty() {
        return if welcome.is_empty() {
            Ok(())
        } else {
            Err(Refused::wrong_welcome())
        };
    }
    let mut covered = welcome_key_packages(welcome).map_err(|_| Refused::wrong_welcome())?;
    covered.sort_unstable();
    added.sort_unstable();
    if covered == added {
        Ok(())
    } else {
        Err(Refused::wrong_welcome())
    }
}

/// Checks that the Welcome of a group's first commit is for exactly the
/// KeyPackages it adds. The server cannot read that commit (it has no state
/// of epoch 0, section 4), but the tree has, for each device the commit
/// adds, the leaf of the package that added it, whose key the server kept
/// with the package (`key_packages.leaf_key`) when it served it.
async fn first_welcome_covers(
    conn: &mut PgConnection,
    welcome: &[u8],
    mut added: Vec<(Uuid, Vec<u8>)>,
) -> Result<()> {
    if added.is_empty() {
        return if welcome.is_empty() {
            Ok(())
        } else {
            Err(Refused::wrong_welcome())
        };
    }
    let references = welcome_key_packages(welcome).map_err(|_| Refused::wrong_welcome())?;
    let mut covered: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT device_id, leaf_key FROM key_packages \
         WHERE reference = ANY($1) AND (served_at IS NOT NULL OR last_resort)",
    )
    .bind(&references)
    .fetch_all(conn)
    .await?;
    // References are unique: one row per reference the server served.
    if covered.len() != references.len() {
        return Err(Refused::wrong_welcome());
    }
    covered.sort_unstable();
    added.sort_unstable();
    if covered == added {
        Ok(())
    } else {
        Err(Refused::wrong_welcome())
    }
}

fn conversation_id(bytes: &[u8]) -> Result<Uuid> {
    Uuid::from_slice(bytes).map_err(|_| Refused::invalid("invalid conversation id"))
}

fn too_large() -> Refused {
    Refused::new(proto::ErrorCode::PayloadTooLarge, "too large")
}

pub(crate) fn stored(
    conversation: Uuid,
    entry: Appended,
    epoch: u64,
    kind: Kind,
    sender: Option<Uuid>,
    payload: Vec<u8>,
) -> Arc<proto::StoredMessage> {
    Arc::new(proto::StoredMessage {
        conversation_id: conversation.as_bytes().to_vec(),
        seq: u64::try_from(entry.seq).unwrap_or_default(),
        epoch,
        kind: Kind::from_code(kind.code()).into(),
        sender_device_id: sender.map(|id| id.as_bytes().to_vec()).unwrap_or_default(),
        server_time_ms: u64::try_from(entry.at_ms).unwrap_or_default(),
        mls_message: payload,
    })
}

/// What a commit adds, which its Welcome must be for.
enum Packages {
    /// A member's or an external commit: the references of the KeyPackages
    /// its Add proposals carry.
    Member(Vec<Vec<u8>>),
    /// A group's first commit: each device added, with its leaf's key.
    First(Vec<(Uuid, Vec<u8>)>),
}

/// `SubmitCommit`: the group's first commit, from any active device of a
/// participant when the conversation has none (section 4); a member's
/// commit; or an external commit (section 5). One commit per epoch: the
/// others get `STALE_EPOCH`. The Welcome is for exactly the KeyPackages the
/// commit adds.
pub async fn submit_commit(
    state: &AppState,
    session: &Session,
    request: proto::SubmitCommit,
) -> Result<proto::CommitAck> {
    if request.mls_group_info.is_empty() {
        return Err(Refused::new(
            proto::ErrorCode::GroupInfoRequired,
            "a commit comes with its new epoch's GroupInfo",
        ));
    }
    if request.mls_commit.len() > MAX_COMMIT_BYTES
        || request.mls_welcome.len() > MAX_WELCOME_BYTES
        || request.mls_group_info.len() > MAX_GROUP_INFO_BYTES
    {
        return Err(too_large());
    }
    let conversation = conversation_id(&request.conversation_id)?;
    let me = session.user_id;
    let submitter = VerifiedLeaf {
        user_id: *me.as_bytes(),
        device_id: *session.device_id.as_bytes(),
    };
    let retention = state.settings.message_retention_days;

    let mut tx = state.db.begin().await?;
    let dm = lock(&mut tx, conversation, me).await?;
    let participants = dm.participants();
    let roster = ServerRoster::load(&mut tx, &dm.users, state.settings.device_inactive_days)
        .await
        .map_err(state_refused)?;
    let before = members(&mut tx, conversation).await?;

    let (old_epoch, new_epoch, leaves, reissued, still_pending, welcomed, packages) =
        match group_of(&mut tx, conversation).await? {
            None => {
                if request.epoch != 0 {
                    return Err(Refused::invalid_commit());
                }
                // A new group adds leaves: between friends only.
                writable(&mut tx, me, dm.peer(me)).await?;
                let expected = ExpectedGroup {
                    identity: GroupIdentity {
                        conversation_id: *conversation.as_bytes(),
                        generation: 0,
                    },
                    participants: &participants,
                };
                let (public, devices) = PublicState::create(
                    &request.mls_group_info,
                    &expected,
                    submitter,
                    &roster,
                    &state.secrets.external_sender.public_bytes(),
                )
                .map_err(|error| commit_refused(error, 0))?;
                let leaves = public.leaves();
                let added = public
                    .leaf_keys()
                    .into_iter()
                    .filter(|(leaf, _)| *leaf != submitter)
                    .map(|(leaf, key)| (Uuid::from_bytes(leaf.device_id), key))
                    .collect();
                // What the server can check of a commit it cannot process: a
                // commit of this group at epoch 0, by the submitter's leaf.
                let committer = first_commit_sender(&request.mls_commit, expected.identity)
                    .map_err(|_| Refused::invalid_commit())?;
                if !leaves
                    .iter()
                    .any(|(index, leaf)| *index == committer && *leaf == submitter)
                {
                    return Err(Refused::invalid_commit());
                }
                mls::insert(&mut tx, public).await.map_err(state_refused)?;
                (
                    0,
                    1,
                    leaves,
                    Vec::new(),
                    Vec::new(),
                    devices,
                    Packages::First(added),
                )
            }
            Some((generation, epoch)) => {
                if request.epoch < epoch {
                    return Err(Refused::stale_at(epoch));
                }
                // An epoch the group has not reached: the device is confused,
                // and its commit could not be valid.
                if request.epoch > epoch {
                    return Err(Refused::invalid_commit());
                }
                let expected = ExpectedGroup {
                    identity: GroupIdentity {
                        conversation_id: *conversation.as_bytes(),
                        generation,
                    },
                    participants: &participants,
                };
                let mut loaded = mls::load(&mut tx, expected.identity)
                    .await
                    .map_err(state_refused)?
                    .ok_or_else(Refused::internal)?;
                let validated = loaded
                    .state
                    .validate_commit(
                        &request.mls_commit,
                        &request.mls_group_info,
                        submitter,
                        &expected,
                        &roster,
                    )
                    .map_err(|error| commit_refused(error, epoch))?;
                // An added leaf, by Add or by external commit, needs friends;
                // removals and updates go through in a read-only DM.
                if !validated.changes().added.is_empty() {
                    writable(&mut tx, me, dm.peer(me)).await?;
                }
                let added = validated.added_key_packages().to_vec();
                let merged = loaded
                    .state
                    .merge(
                        validated,
                        &ServerSigner::new(&state.secrets.external_sender),
                    )
                    .map_err(|error| commit_refused(error, epoch))?;
                let leaves = loaded.state.leaves();
                let still_pending = loaded
                    .state
                    .pending_removals()
                    .map_err(|error| commit_refused(error, epoch))?
                    .into_iter()
                    .map(|leaf| i32::try_from(leaf.u32()).unwrap_or(i32::MAX))
                    .collect();
                mls::save(&mut tx, loaded).await.map_err(state_refused)?;
                (
                    epoch,
                    merged.epoch,
                    leaves,
                    merged.reissued,
                    still_pending,
                    merged.changes.added,
                    Packages::Member(added),
                )
            }
        };
    let welcomed: Vec<Uuid> = welcomed
        .into_iter()
        .filter(|device| *device != submitter)
        .map(|device| Uuid::from_bytes(device.device_id))
        .collect();
    match packages {
        Packages::Member(added) => welcome_covers(&request.mls_welcome, added)?,
        Packages::First(added) => {
            first_welcome_covers(&mut tx, &request.mls_welcome, added).await?
        }
    }

    let commit = append(
        &mut tx,
        conversation,
        Kind::Commit,
        old_epoch,
        Some(session.device_id),
        &request.mls_commit,
        retention,
    )
    .await?;
    let mut proposals = Vec::with_capacity(reissued.len());
    let mut moved = Vec::with_capacity(reissued.len());
    for tavern_crypto::mls::Reissued { leaf, proposal } in reissued {
        let entry = append(
            &mut tx,
            conversation,
            Kind::Proposal,
            new_epoch,
            None,
            &proposal,
            retention,
        )
        .await?;
        moved.push((i32::try_from(leaf).unwrap_or(i32::MAX), entry.seq));
        proposals.push(stored(
            conversation,
            entry,
            new_epoch,
            Kind::Proposal,
            None,
            proposal,
        ));
    }
    settle_removals(&mut tx, conversation, &still_pending, &moved).await?;
    sync_leaves(&mut tx, conversation, &leaves, commit.seq).await?;
    let welcomes: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "INSERT INTO welcomes (conversation_id, recipient_device_id, payload, expires_at) \
         SELECT $1, device, $3, now() + make_interval(days => $4) FROM unnest($2::uuid[]) AS device \
         RETURNING id, recipient_device_id",
    )
    .bind(conversation)
    .bind(&welcomed)
    .bind(&request.mls_welcome)
    .bind(i32::try_from(retention).unwrap_or(i32::MAX))
    .fetch_all(&mut *tx)
    .await?;
    let after = members(&mut tx, conversation).await?;
    let to_join = if friends_now(&mut tx, dm).await? {
        left_out(&mut tx, dm, state.settings.device_inactive_days).await?
    } else {
        Vec::new()
    };
    tx.commit().await?;

    // The devices that held the group before the commit process it; all of
    // them now store the server's proposals; the new ones join by Welcome.
    let message = stored(
        conversation,
        commit,
        old_epoch,
        Kind::Commit,
        Some(session.device_id),
        request.mls_commit,
    );
    for device in before.into_iter().filter(|d| *d != session.device_id) {
        state
            .gateway
            .notify_device(device, Event::Sequenced(message.clone()));
    }
    for proposal in proposals {
        for device in &after {
            state
                .gateway
                .notify_device(*device, Event::Sequenced(proposal.clone()));
        }
    }
    for (welcome_id, device) in welcomes {
        let welcome = Arc::new(proto::WelcomeEvent {
            welcome_id: welcome_id.as_bytes().to_vec(),
            conversation_id: conversation.as_bytes().to_vec(),
            mls_welcome: request.mls_welcome.clone(),
        });
        state.gateway.notify_device(device, Event::Welcome(welcome));
    }
    for device in to_join {
        state.gateway.notify_device(
            device,
            Event::JoinConversation {
                conversation_id: conversation,
            },
        );
    }
    Ok(proto::CommitAck {
        seq: u64::try_from(commit.seq).unwrap_or_default(),
        new_epoch,
        server_time_ms: u64::try_from(commit.at_ms).unwrap_or_default(),
    })
}

/// `SendMessage`: an application message for the group's current epoch,
/// from one of its devices. A resend with the same `client_message_id` gets
/// the original acknowledgement, and is neither stored nor delivered again
/// (section 7).
pub async fn send_message(
    state: &AppState,
    session: &Session,
    request: proto::SendMessage,
) -> Result<proto::SendMessageAck> {
    if request.mls_message.len() > MAX_APPLICATION_MESSAGE_BYTES {
        return Err(too_large());
    }
    let conversation = conversation_id(&request.conversation_id)?;
    let client_message_id = Uuid::from_slice(&request.client_message_id)
        .map_err(|_| Refused::invalid("invalid client message id"))?;
    let header = application_header(&request.mls_message)
        .map_err(|_| Refused::invalid("not an MLS application message"))?;
    let me = session.user_id;

    let mut tx = state.db.begin().await?;
    let dm = lock(&mut tx, conversation, me).await?;
    let sent: Option<(Uuid, i64, i64)> = sqlx::query_as(
        "SELECT conversation_id, seq, (extract(epoch FROM sent_at) * 1000)::bigint \
         FROM sent_messages WHERE device_id = $1 AND client_message_id = $2",
    )
    .bind(session.device_id)
    .bind(client_message_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((sent_in, seq, at_ms)) = sent {
        if sent_in != conversation {
            return Err(used_elsewhere());
        }
        return Ok(proto::SendMessageAck {
            seq: u64::try_from(seq).unwrap_or_default(),
            server_time_ms: u64::try_from(at_ms).unwrap_or_default(),
        });
    }
    // A device the server asked to remove sends nothing more.
    let leaf: bool = sqlx::query_scalar(concat!(
        "SELECT EXISTS (SELECT 1 FROM conversation_devices d \
                        WHERE conversation_id = $1 AND device_id = $2 AND left_seq IS NULL AND ",
        not_cut_off!("d"),
        ")"
    ))
    .bind(conversation)
    .bind(session.device_id)
    .fetch_one(&mut *tx)
    .await?;
    if !leaf {
        return Err(Refused::not_a_member());
    }
    writable(&mut tx, me, dm.peer(me)).await?;
    let (generation, epoch) = group_of(&mut tx, conversation)
        .await?
        .ok_or_else(Refused::not_a_member)?;
    if header.group.conversation_id != *conversation.as_bytes() {
        return Err(Refused::invalid("the message is for another conversation"));
    }
    if (header.group.generation, header.epoch) < (generation, epoch) {
        return Err(Refused::stale_at(epoch));
    }
    if (header.group.generation, header.epoch) != (generation, epoch) {
        return Err(Refused::invalid("the message is for a later epoch"));
    }
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mls_group_entries e \
                        JOIN mls_groups g ON g.group_id = e.group_id \
                        WHERE g.conversation_id = $1 AND e.kind = $2)",
    )
    .bind(conversation)
    .bind(PROPOSAL_QUEUE_KIND)
    .fetch_one(&mut *tx)
    .await?;
    if pending {
        return Err(Refused::new(
            proto::ErrorCode::RemovalPending,
            "commit the server's pending removals, then send again",
        ));
    }

    let retention = state.settings.message_retention_days;
    let entry = append(
        &mut tx,
        conversation,
        Kind::Application,
        epoch,
        Some(session.device_id),
        &request.mls_message,
        retention,
    )
    .await?;
    // The same id sent at once in another conversation, under another lock:
    // the first to commit keeps it, and this transaction, its number with it,
    // goes back.
    let recorded = sqlx::query(
        "INSERT INTO sent_messages \
             (device_id, client_message_id, conversation_id, seq, sent_at, expires_at) \
         VALUES ($1, $2, $3, $4, to_timestamp($5::double precision / 1000), \
                 now() + make_interval(days => $6)) \
         ON CONFLICT (device_id, client_message_id) DO NOTHING",
    )
    .bind(session.device_id)
    .bind(client_message_id)
    .bind(conversation)
    .bind(entry.seq)
    .bind(entry.at_ms)
    .bind(i32::try_from(retention.saturating_mul(2)).unwrap_or(i32::MAX))
    .execute(&mut *tx)
    .await?;
    if recorded.rows_affected() == 0 {
        return Err(used_elsewhere());
    }
    let recipients = members(&mut tx, conversation).await?;
    tx.commit().await?;

    let message = stored(
        conversation,
        entry,
        epoch,
        Kind::Application,
        Some(session.device_id),
        request.mls_message,
    );
    for device in recipients.into_iter().filter(|d| *d != session.device_id) {
        state
            .gateway
            .notify_device(device, Event::Sequenced(message.clone()));
    }
    Ok(proto::SendMessageAck {
        seq: u64::try_from(entry.seq).unwrap_or_default(),
        server_time_ms: u64::try_from(entry.at_ms).unwrap_or_default(),
    })
}

fn used_elsewhere() -> Refused {
    Refused::invalid("this client message id was used elsewhere")
}

type MessageRow = (i64, i64, i16, Option<Uuid>, i64, Vec<u8>);

/// `FetchMessages`: the sequence after `after_seq`, from when this device
/// joined the group to the commit that removed it, if one did, or to the
/// server's proposal to remove it while that is pending: what follows is
/// not for it.
pub async fn fetch_messages(
    state: &AppState,
    session: &Session,
    request: proto::FetchMessages,
) -> Result<proto::MessageBatch> {
    let conversation = conversation_id(&request.conversation_id)?;
    let limit = match request.limit {
        0 => MAX_FETCH_MESSAGES,
        limit => limit.min(MAX_FETCH_MESSAGES),
    };
    // LEAST ignores a NULL: the earlier of the two ends there is.
    let span: Option<(i64, Option<i64>)> = sqlx::query_as(
        "SELECT d.joined_seq, LEAST(d.left_seq, p.proposal_seq) FROM conversation_devices d \
         LEFT JOIN pending_removals p \
           ON p.conversation_id = d.conversation_id AND p.device_id = d.device_id \
         WHERE d.conversation_id = $1 AND d.device_id = $2",
    )
    .bind(conversation)
    .bind(session.device_id)
    .fetch_optional(&state.db)
    .await?;
    let (joined, left) = span.ok_or_else(Refused::not_a_member)?;
    let after = i64::try_from(request.after_seq)
        .unwrap_or(i64::MAX)
        .max(joined);
    let mut rows: Vec<MessageRow> = sqlx::query_as(
        "SELECT seq, epoch, kind, sender_device_id, \
                (extract(epoch FROM created_at) * 1000)::bigint, payload \
         FROM messages \
         WHERE conversation_id = $1 AND seq > $2 AND ($3::bigint IS NULL OR seq <= $3) \
         ORDER BY seq LIMIT $4",
    )
    .bind(conversation)
    .bind(after)
    .bind(left)
    .bind(i64::from(limit) + 1)
    .fetch_all(&state.db)
    .await?;
    let more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    let messages = rows
        .into_iter()
        .map(
            |(seq, epoch, kind, sender, at_ms, payload)| proto::StoredMessage {
                conversation_id: conversation.as_bytes().to_vec(),
                seq: u64::try_from(seq).unwrap_or_default(),
                epoch: u64::try_from(epoch).unwrap_or_default(),
                kind: Kind::from_code(kind).into(),
                sender_device_id: sender.map(|id| id.as_bytes().to_vec()).unwrap_or_default(),
                server_time_ms: u64::try_from(at_ms).unwrap_or_default(),
                mls_message: payload,
            },
        )
        .collect();
    Ok(proto::MessageBatch { messages, more })
}

/// `AckMessages`: this device has durably processed the sequence up to
/// `up_to_seq`. Its cursor only moves forward, and never past what it may
/// read. What every device acknowledged is deleted by the purge
/// ([`crate::purge`]).
pub async fn ack_messages(
    state: &AppState,
    session: &Session,
    request: proto::AckMessages,
) -> Result<()> {
    let conversation = conversation_id(&request.conversation_id)?;
    let up_to = i64::try_from(request.up_to_seq).unwrap_or(i64::MAX);
    let updated = sqlx::query(
        "UPDATE conversation_devices d \
         SET acked_seq = GREATEST(d.acked_seq, LEAST($3, COALESCE( \
                 LEAST(d.left_seq, (SELECT p.proposal_seq FROM pending_removals p \
                                    WHERE p.conversation_id = d.conversation_id \
                                      AND p.device_id = d.device_id)), \
                 c.last_seq))) \
         FROM conversations c \
         WHERE d.conversation_id = $1 AND d.device_id = $2 AND c.id = d.conversation_id",
    )
    .bind(conversation)
    .bind(session.device_id)
    .bind(up_to)
    .execute(&state.db)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(Refused::not_a_member());
    }
    Ok(())
}

/// `AckWelcome`: this device has joined, or refused, the group of a
/// Welcome; it is not sent again. Deleted by the purge ([`crate::purge`]).
pub async fn ack_welcome(
    state: &AppState,
    session: &Session,
    request: proto::AckWelcome,
) -> Result<()> {
    let id = Uuid::from_slice(&request.welcome_id)
        .map_err(|_| Refused::invalid("invalid welcome id"))?;
    let found = sqlx::query(
        "UPDATE welcomes SET acked_at = COALESCE(acked_at, now()) \
         WHERE id = $1 AND recipient_device_id = $2",
    )
    .bind(id)
    .bind(session.device_id)
    .execute(&state.db)
    .await?;
    if found.rows_affected() == 0 {
        return Err(Refused::new(proto::ErrorCode::NotFound, "no such welcome"));
    }
    Ok(())
}

/// A DM's users, and its group's epoch and GroupInfo if it has one.
type GroupInfoRow = (Uuid, Uuid, Option<i64>, Option<Vec<u8>>);

/// `FetchGroupInfo`: the group's latest GroupInfo, to join it by external
/// commit. Any device of a participant may read it, between friends only:
/// in a read-only DM, where an external commit is refused anyway, the tree
/// it holds would tell the other user of every change of devices. The
/// blocked user is answered what an unfriended one is.
pub async fn fetch_group_info(
    state: &AppState,
    session: &Session,
    request: proto::FetchGroupInfo,
) -> Result<proto::GroupInfo> {
    let conversation = conversation_id(&request.conversation_id)?;
    let mut conn = state.db.acquire().await?;
    let row: Option<GroupInfoRow> = sqlx::query_as(
        "SELECT d.user_low, d.user_high, g.epoch, g.group_info FROM dm_conversations d \
         LEFT JOIN mls_groups g ON g.conversation_id = d.conversation_id \
         WHERE d.conversation_id = $1",
    )
    .bind(conversation)
    .fetch_optional(&mut *conn)
    .await?;
    let me = session.user_id;
    let Some((low, high, epoch, info)) = row.filter(|(low, high, ..)| me == *low || me == *high)
    else {
        return Err(Refused::not_a_member());
    };
    writable(&mut conn, me, if me == low { high } else { low }).await?;
    match (epoch, info) {
        (Some(epoch), Some(info)) => Ok(proto::GroupInfo {
            epoch: u64::try_from(epoch).unwrap_or_default(),
            mls_group_info: info,
        }),
        _ => Err(Refused::new(
            proto::ErrorCode::NotFound,
            "the conversation has no group yet",
        )),
    }
}

/// The Welcomes this device has not acknowledged, oldest first: sent again
/// at each connection.
pub async fn pending_welcomes(
    state: &AppState,
    session: &Session,
) -> std::result::Result<Vec<proto::WelcomeEvent>, sqlx::Error> {
    let rows: Vec<(Uuid, Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT id, conversation_id, payload FROM welcomes \
         WHERE recipient_device_id = $1 AND acked_at IS NULL AND expires_at > now() \
         ORDER BY created_at, id",
    )
    .bind(session.device_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, conversation, payload)| proto::WelcomeEvent {
            welcome_id: id.as_bytes().to_vec(),
            conversation_id: conversation.as_bytes().to_vec(),
            mls_welcome: payload,
        })
        .collect())
}
