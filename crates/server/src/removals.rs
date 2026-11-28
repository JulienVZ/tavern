// SPDX-License-Identifier: AGPL-3.0-or-later

//! The server's removals (ADR 0019, sections 6 and 15).
//!
//! A device revoked, a device of a disabled account, and a device away for
//! longer than `TAVERN_DEVICE_INACTIVE_DAYS` leave the groups of their
//! conversations: in each one, the server signs a `Remove` proposal with
//! the external sender key, stores it with the group's public state,
//! appends it to the conversation's sequence and tells the group. From that
//! proposal on, the device is cut off ([`crate::delivery`]), and the group
//! takes no application message until a member commits the removal
//! (`REMOVAL_PENDING`).
//!
//! The server also removes a leaf still as its KeyPackage made it, never
//! updated, 7 days before the end of its lifetime
//! ([`LEAF_EXPIRY_MARGIN_DAYS`]): once it is over, OpenMLS refuses every
//! join of the group, by Welcome and by external commit. Such a leaf is a
//! device that never processed its Welcome, or never updated since; once
//! removed, it rejoins by external commit if it is active
//! (`JoinConversation`), as any device left out (ADR 0019, section 3).
//!
//! A group whose leaves are all being removed has no member left that can
//! commit those removals (nor anything else): the server declares it dead
//! (`conversations.group_dead`) and asks its participants to recreate it
//! ([`declare_dead`]): checked with each removal, at each sweep, and when a
//! device reports it cannot join ([`check`], `ReportUnjoinable`).
//!
//! A revocation and the disabling of an account ask for their removals
//! right after their own transaction, which cannot fail because of them;
//! the hourly [`sweep`] asks for any that is missing (an inactive device, or
//! a server stopped in between). Asking twice changes nothing: one proposal
//! per device and group.

/// Days before the end of its lifetime at which the server asks to remove a
/// leaf still as its KeyPackage made it (ADR 0019, section 3): once that
/// lifetime is over, OpenMLS refuses to join the group.
pub const LEAF_EXPIRY_MARGIN_DAYS: i32 = 7;

use sqlx::PgConnection;
use tavern_crypto::mls::group_id::GroupIdentity;
use tavern_crypto::mls::{ServerSigner, VerifiedLeaf};
use uuid::Uuid;

use crate::AppState;
use crate::activity;
use crate::delivery::{self, Kind};
use crate::gateway::Event;
use crate::mls::{self, StateError};

/// Asks for the removal of `device` from the group of each conversation it
/// is in. Returns the number of proposals issued.
pub async fn remove_device(state: &AppState, device: Uuid) -> Result<usize, StateError> {
    let conversations: Vec<Uuid> = sqlx::query_scalar(concat!(
        "SELECT conversation_id FROM conversation_devices d \
         WHERE device_id = $1 AND left_seq IS NULL AND ",
        delivery::not_cut_off!("d"),
        " ORDER BY conversation_id"
    ))
    .bind(device)
    .fetch_all(&state.db)
    .await?;
    let mut issued = 0;
    for conversation in conversations {
        if remove_from(state, conversation, device).await? {
            issued += 1;
        }
    }
    Ok(issued)
}

/// Asks for the removal of every device of `user` (a disabled account) from
/// its groups. Returns the number of proposals issued.
pub async fn remove_user_devices(state: &AppState, user: Uuid) -> Result<usize, StateError> {
    let devices: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM devices WHERE user_id = $1 ORDER BY id")
            .bind(user)
            .fetch_all(&state.db)
            .await?;
    let mut issued = 0;
    for device in devices {
        issued += remove_device(state, device).await?;
    }
    Ok(issued)
}

/// Asks for every removal that is missing: each leaf whose device is no
/// longer active (revoked, of a disabled account, or away for longer than
/// `TAVERN_DEVICE_INACTIVE_DAYS`), and each leaf never updated whose
/// lifetime ends within [`LEAF_EXPIRY_MARGIN_DAYS`], that the server has not
/// asked to remove yet. Returns the number of proposals issued. A failure
/// in one conversation is logged and does not stop the others.
pub async fn sweep(state: &AppState) -> Result<usize, StateError> {
    let issued = remove_due(state, None).await?;
    // Groups whose leaves were all being removed before this check existed,
    // or whose check failed: declared now.
    let stuck: Vec<Uuid> = sqlx::query_scalar(concat!(
        "SELECT c.id FROM conversations c \
         WHERE NOT c.needs_recreation \
           AND EXISTS (SELECT 1 FROM mls_groups g WHERE g.conversation_id = c.id) \
           AND NOT EXISTS (SELECT 1 FROM conversation_devices m \
                           WHERE m.conversation_id = c.id AND m.left_seq IS NULL AND ",
        delivery::not_cut_off!("m"),
        ") ORDER BY c.id"
    ))
    .fetch_all(&state.db)
    .await?;
    for conversation in stuck {
        if let Err(error) = declare_if_dead(state, conversation).await {
            tracing::error!(%error, %conversation, "cannot check a group for members");
        }
    }
    Ok(issued)
}

/// Whether the leaf of a device in a conversation, row `c` of
/// `conversation_devices` joined with its device `d` and user `u`, is due
/// for removal: its device no longer active (window bound as `$w`), or the
/// leaf never updated and ending within [`LEAF_EXPIRY_MARGIN_DAYS`] (bound
/// as `$m`). A string literal, for `concat!`.
macro_rules! due {
    ($w:literal, $m:literal) => {
        concat!(
            "(NOT (",
            activity::active_device!($w),
            ") OR c.leaf_expires_at <= now() + make_interval(days => ",
            $m,
            "))"
        )
    };
}

/// Asks for the removals due in every conversation, or in `only`. A failure
/// in one conversation is logged and does not stop the others.
async fn remove_due(state: &AppState, only: Option<Uuid>) -> Result<usize, StateError> {
    let leaves: Vec<(Uuid, Uuid)> = sqlx::query_as(concat!(
        "SELECT c.conversation_id, c.device_id FROM conversation_devices c \
         JOIN devices d ON d.id = c.device_id JOIN users u ON u.id = d.user_id \
         WHERE c.left_seq IS NULL AND ($3::uuid IS NULL OR c.conversation_id = $3) AND ",
        due!("$1", "$2"),
        " AND ",
        delivery::not_cut_off!("c"),
        " ORDER BY c.conversation_id, c.device_id"
    ))
    .bind(activity::window(state.settings.device_inactive_days))
    .bind(LEAF_EXPIRY_MARGIN_DAYS)
    .bind(only)
    .fetch_all(&state.db)
    .await?;
    let mut issued = 0;
    for (conversation, device) in leaves {
        match remove_from(state, conversation, device).await {
            Ok(true) => issued += 1,
            Ok(false) => {}
            Err(error) => {
                tracing::error!(%error, %conversation, "cannot ask for a device's removal");
            }
        }
    }
    Ok(issued)
}

/// A device reports it cannot join `conversation`'s group (a leaf outlived
/// its KeyPackage): the removals due there are asked for now, then whether
/// any member can still commit is checked. Nothing of the report is taken
/// on trust; it only makes the server look at once instead of at its next
/// sweep.
pub async fn check(state: &AppState, conversation: Uuid) -> Result<(), StateError> {
    remove_due(state, Some(conversation)).await?;
    declare_if_dead(state, conversation).await?;
    Ok(())
}

/// [`check`], on the report of `reporter`, which has no usable state for
/// the group (its Welcome never processed, its store reset, its resync
/// failed): its own leaf, if it has one, is removed first, by the path of
/// every removal. Never another device's: those are removed only when due.
/// It rejoins by external commit, or with the recreation of the group if no
/// member is left that can commit.
pub async fn check_reported(
    state: &AppState,
    conversation: Uuid,
    reporter: Uuid,
) -> Result<(), StateError> {
    remove_leaf(state, conversation, reporter, Reason::Reported).await?;
    check(state, conversation).await
}

/// Declares `conversation`'s group dead, under the conversation's lock, if
/// none of its leaves can commit, and tells its participants. Returns
/// whether it was declared now.
async fn declare_if_dead(state: &AppState, conversation: Uuid) -> Result<bool, StateError> {
    let mut tx = state.db.begin().await?;
    sqlx::query("SELECT 1 FROM conversations WHERE id = $1 FOR UPDATE")
        .bind(conversation)
        .execute(&mut *tx)
        .await?;
    let told = declare_dead(&mut tx, conversation, state.settings.device_inactive_days).await?;
    tx.commit().await?;
    notify_dead(state, conversation, told.as_deref().unwrap_or_default());
    Ok(told.is_some())
}

/// In the caller's transaction, under the conversation's lock: if the group
/// has leaves, none of which can commit (each being removed by the server),
/// marks it dead: only its recreation, at the next generation, is accepted
/// from now on (`needs_recreation`, `group_dead`; ADR 0019, sections 3 and
/// 17). Returns the active devices of its participants, to tell after the
/// commit; `None` if it was not declared now.
pub(crate) async fn declare_dead(
    conn: &mut PgConnection,
    conversation: Uuid,
    inactive_days: u32,
) -> Result<Option<Vec<Uuid>>, StateError> {
    let declared: Option<Uuid> = sqlx::query_scalar(concat!(
        "UPDATE conversations c SET needs_recreation = true, group_dead = true \
         WHERE c.id = $1 AND NOT c.needs_recreation \
           AND EXISTS (SELECT 1 FROM conversation_devices m \
                       WHERE m.conversation_id = c.id AND m.left_seq IS NULL) \
           AND NOT EXISTS (SELECT 1 FROM conversation_devices m \
                           WHERE m.conversation_id = c.id AND m.left_seq IS NULL AND ",
        delivery::not_cut_off!("m"),
        ") RETURNING c.id"
    ))
    .bind(conversation)
    .fetch_optional(&mut *conn)
    .await?;
    if declared.is_none() {
        return Ok(None);
    }
    tracing::warn!(%conversation, "a group has no member that can commit: to recreate");
    Ok(Some(
        sqlx::query_scalar(concat!(
            "SELECT d.id FROM devices d JOIN users u ON u.id = d.user_id \
         JOIN dm_conversations m ON d.user_id IN (m.user_low, m.user_high) \
         WHERE m.conversation_id = $1 AND ",
            activity::active_device!("$2"),
            " ORDER BY d.id"
        ))
        .bind(conversation)
        .bind(activity::window(inactive_days))
        .fetch_all(conn)
        .await?,
    ))
}

/// Tells the devices [`declare_dead`] returned to recreate the group.
fn notify_dead(state: &AppState, conversation: Uuid, devices: &[Uuid]) {
    for device in devices {
        state.gateway.notify_device(
            *device,
            Event::RecreateConversation {
                conversation_id: conversation,
            },
        );
    }
}

/// Asks for the removal of `device` from `conversation`'s group, in one
/// transaction under the conversation's lock: `true` if the removal is now
/// recorded (a proposal issued, or one the state already held given its
/// row), `false` if there is nothing to do (the device is not a leaf any
/// more, or its removal is already recorded).
pub async fn remove_from(
    state: &AppState,
    conversation: Uuid,
    device: Uuid,
) -> Result<bool, StateError> {
    remove_leaf(state, conversation, device, Reason::Due).await
}

/// Why a leaf is removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    /// Its device is no longer active, or the leaf nears its end: read again
    /// under the lock.
    Due,
    /// Its own device reports it has no usable state for the group.
    Reported,
}

async fn remove_leaf(
    state: &AppState,
    conversation: Uuid,
    device: Uuid,
    reason: Reason,
) -> Result<bool, StateError> {
    let mut tx = state.db.begin().await?;
    // The same lock as every request that adds to the sequence, taken
    // first, as they do.
    let locked: Option<bool> =
        sqlx::query_scalar("SELECT needs_recreation FROM conversations WHERE id = $1 FOR UPDATE")
            .bind(conversation)
            .fetch_optional(&mut *tx)
            .await?;
    // A group to recreate after a restore is not changed any more: the new
    // group takes active devices only (section 17).
    if locked.is_none_or(|needs_recreation| needs_recreation) {
        return Ok(false);
    }
    // Due still, read under the lock: a leaf updated, or a device back,
    // since it was picked keeps its place.
    let leaf: Option<Uuid> = sqlx::query_scalar(concat!(
        "SELECT d.user_id FROM conversation_devices c \
         JOIN devices d ON d.id = c.device_id JOIN users u ON u.id = d.user_id \
         WHERE c.conversation_id = $1 AND c.device_id = $2 AND c.left_seq IS NULL \
           AND ($5 OR ",
        due!("$3", "$4"),
        ") AND ",
        delivery::not_cut_off!("c")
    ))
    .bind(conversation)
    .bind(device)
    .bind(activity::window(state.settings.device_inactive_days))
    .bind(LEAF_EXPIRY_MARGIN_DAYS)
    .bind(reason == Reason::Reported)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(user) = leaf else {
        return Ok(false);
    };
    let Some((generation, _)) = delivery::group_of(&mut tx, conversation).await? else {
        return Ok(false);
    };
    let identity = GroupIdentity {
        conversation_id: *conversation.as_bytes(),
        generation,
    };
    let mut loaded = mls::load(&mut tx, identity)
        .await?
        .ok_or(StateError::Inconsistent)?;
    let Some(leaf) = loaded.state.leaf_of(VerifiedLeaf {
        user_id: *user.as_bytes(),
        device_id: *device.as_bytes(),
    }) else {
        // `conversation_devices` is written from the merged tree: they
        // cannot disagree.
        return Err(StateError::Inconsistent);
    };
    let epoch = loaded.state.epoch();
    let signer = ServerSigner::new(&state.secrets.external_sender);
    let leaf_index = i32::try_from(leaf.u32()).unwrap_or(i32::MAX);
    let Some(proposal) = loaded.state.remove(leaf, &signer)? else {
        // Asked for in the state, but without its row (a removal stored
        // before the row existed): the row is written, and the device is
        // cut off from now on, the end of the sequence standing for its
        // proposal. Nothing is appended: the members hold the proposal.
        tracing::warn!(%conversation, "a removal was stored without its row");
        sqlx::query(
            "INSERT INTO pending_removals (conversation_id, device_id, leaf_index, proposal_seq) \
             SELECT $1, $2, $3, last_seq FROM conversations WHERE id = $1",
        )
        .bind(conversation)
        .bind(device)
        .bind(leaf_index)
        .execute(&mut *tx)
        .await?;
        let dead = declare_dead(&mut tx, conversation, state.settings.device_inactive_days).await?;
        tx.commit().await?;
        notify_dead(state, conversation, dead.as_deref().unwrap_or_default());
        return Ok(true);
    };
    mls::save(&mut tx, loaded).await?;
    let entry = delivery::append(
        &mut tx,
        conversation,
        Kind::Proposal,
        epoch,
        None,
        &proposal,
        state.settings.message_retention_days,
    )
    .await?;
    sqlx::query(
        "INSERT INTO pending_removals (conversation_id, device_id, leaf_index, proposal_seq) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(conversation)
    .bind(device)
    .bind(leaf_index)
    .bind(entry.seq)
    .execute(&mut *tx)
    .await?;
    let recipients = delivery::members(&mut tx, conversation).await?;
    let dead = declare_dead(&mut tx, conversation, state.settings.device_inactive_days).await?;
    tx.commit().await?;

    tracing::info!(%conversation, "removal of a device asked for");
    let message = delivery::stored(conversation, entry, epoch, Kind::Proposal, None, proposal);
    // The members, and the device itself, which learns of its removal if it
    // is connected; nothing more goes to it.
    for recipient in recipients.into_iter().chain(std::iter::once(device)) {
        state
            .gateway
            .notify_device(recipient, Event::Sequenced(message.clone()));
    }
    notify_dead(state, conversation, dead.as_deref().unwrap_or_default());
    Ok(true)
}

/// Writes, from each group's stored public state, the end of each leaf still
/// as its KeyPackage made it: for the groups of an instance that ran before
/// migration 0016, whose leaves had none written yet, and harmless for the
/// others (it writes what their last commit wrote). Run once at start-up,
/// before the first sweep, on every group (`only`: one conversation's).
/// Returns the number of groups read; a failure in one is logged and does
/// not stop the others.
pub async fn fill_leaf_ends(state: &AppState, only: Option<Uuid>) -> Result<usize, StateError> {
    let groups: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT g.conversation_id, g.generation FROM mls_groups g \
         JOIN conversations c ON c.id = g.conversation_id \
         WHERE NOT c.needs_recreation AND ($1::uuid IS NULL OR c.id = $1) \
         ORDER BY g.conversation_id",
    )
    .bind(only)
    .fetch_all(&state.db)
    .await?;
    let mut read = 0;
    for (conversation, generation) in groups {
        match fill_group(state, conversation, generation).await {
            Ok(()) => read += 1,
            Err(error) => {
                tracing::error!(%error, %conversation, "cannot write the ends of a group's leaves");
            }
        }
    }
    Ok(read)
}

async fn fill_group(
    state: &AppState,
    conversation: Uuid,
    generation: i64,
) -> Result<(), StateError> {
    let mut tx = state.db.begin().await?;
    // The lock of every request that changes the group, taken first.
    sqlx::query("SELECT 1 FROM conversations WHERE id = $1 FOR UPDATE")
        .bind(conversation)
        .execute(&mut *tx)
        .await?;
    let identity = GroupIdentity {
        conversation_id: *conversation.as_bytes(),
        generation: u32::try_from(generation).map_err(|_| StateError::Inconsistent)?,
    };
    if let Some(loaded) = mls::load(&mut tx, identity).await? {
        delivery::write_leaf_ends(&mut tx, conversation, &loaded.state.key_package_leaves())
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
