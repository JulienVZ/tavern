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
//! A revocation and the disabling of an account ask for their removals
//! right after their own transaction, which cannot fail because of them;
//! the hourly [`sweep`] asks for any that is missing (an inactive device, or
//! a server stopped in between). Asking twice changes nothing: one proposal
//! per device and group.

/// Days before the end of its lifetime at which the server asks to remove a
/// leaf still as its KeyPackage made it (ADR 0019, section 3): once that
/// lifetime is over, OpenMLS refuses to join the group.
pub const LEAF_EXPIRY_MARGIN_DAYS: i32 = 7;

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
    let leaves: Vec<(Uuid, Uuid)> = sqlx::query_as(concat!(
        "SELECT c.conversation_id, c.device_id FROM conversation_devices c \
         JOIN devices d ON d.id = c.device_id JOIN users u ON u.id = d.user_id \
         WHERE c.left_seq IS NULL AND (NOT (",
        activity::active_device!("$1"),
        ") OR c.leaf_expires_at <= now() + make_interval(days => $2)) AND ",
        delivery::not_cut_off!("c"),
        " ORDER BY c.conversation_id, c.device_id"
    ))
    .bind(activity::window(state.settings.device_inactive_days))
    .bind(LEAF_EXPIRY_MARGIN_DAYS)
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
    let leaf: Option<Uuid> = sqlx::query_scalar(concat!(
        "SELECT v.user_id FROM conversation_devices c JOIN devices v ON v.id = c.device_id \
         WHERE c.conversation_id = $1 AND c.device_id = $2 AND c.left_seq IS NULL AND ",
        delivery::not_cut_off!("c")
    ))
    .bind(conversation)
    .bind(device)
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
        tx.commit().await?;
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
    Ok(true)
}
