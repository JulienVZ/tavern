// SPDX-License-Identifier: AGPL-3.0-or-later

//! The hourly purge (ADR 0019, sections 3, 12 and 15).
//!
//! At start-up, then every hour, the server deletes what it no longer has to
//! keep, and asks for the removals that are missing ([`removals::sweep`]):
//!
//! - a message of a conversation's sequence once every device it was for
//!   has acknowledged it, or once it expired (`TAVERN_MESSAGE_RETENTION_DAYS`).
//!   It was for every device of the group that read the sequence at its
//!   number: after the commit that added the device, up to the commit that
//!   removed it or the server's proposal to remove it, the sender excepted;
//! - a Welcome once acknowledged, or expired;
//! - an idempotency record of a sent message once expired (twice the
//!   retention);
//! - a KeyPackage once expired, served or not;
//! - the row of a device that left a group, once it has acknowledged the
//!   sequence up to its departure, or the commit of its departure is gone.
//!
//! Each pass runs under [`panics::guard`]: a panic ends that pass, never the
//! server. Only counts are logged.

use std::time::Duration;

use sqlx::PgPool;
use tokio::task::JoinHandle;

use crate::{AppState, panics, removals};

/// How often the purge runs.
pub const INTERVAL: Duration = Duration::from_secs(3600);

/// What one pass deleted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Messages of conversations' sequences.
    pub messages: u64,
    /// Welcomes.
    pub welcomes: u64,
    /// Idempotency records of sent messages.
    pub sent_messages: u64,
    /// KeyPackages.
    pub key_packages: u64,
    /// Rows of devices that left a group.
    pub departed_devices: u64,
}

/// Deletes what the server no longer has to keep (see the module
/// documentation), table by table.
pub async fn purge(db: &PgPool) -> Result<Counts, sqlx::Error> {
    // LEAST ignores a NULL: the earlier of the two ends there is, if any.
    let messages = sqlx::query(
        "DELETE FROM messages m \
         WHERE m.expires_at <= now() \
            OR NOT EXISTS ( \
                SELECT 1 FROM conversation_devices d \
                LEFT JOIN pending_removals p \
                  ON p.conversation_id = d.conversation_id AND p.device_id = d.device_id \
                WHERE d.conversation_id = m.conversation_id \
                  AND d.joined_seq < m.seq \
                  AND m.seq <= COALESCE(LEAST(d.left_seq, p.proposal_seq), m.seq) \
                  AND d.device_id IS DISTINCT FROM m.sender_device_id \
                  AND d.acked_seq < m.seq)",
    )
    .execute(db)
    .await?
    .rows_affected();
    let welcomes =
        sqlx::query("DELETE FROM welcomes WHERE acked_at IS NOT NULL OR expires_at <= now()")
            .execute(db)
            .await?
            .rows_affected();
    let sent_messages = sqlx::query("DELETE FROM sent_messages WHERE expires_at <= now()")
        .execute(db)
        .await?
        .rows_affected();
    let key_packages = sqlx::query("DELETE FROM key_packages WHERE expires_at <= now()")
        .execute(db)
        .await?
        .rows_affected();
    let departed_devices = sqlx::query(
        "DELETE FROM conversation_devices d \
         WHERE d.left_seq IS NOT NULL \
           AND (d.acked_seq >= d.left_seq \
                OR NOT EXISTS (SELECT 1 FROM messages m \
                               WHERE m.conversation_id = d.conversation_id \
                                 AND m.seq = d.left_seq))",
    )
    .execute(db)
    .await?
    .rows_affected();
    Ok(Counts {
        messages,
        welcomes,
        sent_messages,
        key_packages,
        departed_devices,
    })
}

/// One pass: the purge, then the removals that are missing.
pub async fn run_once(state: &AppState) {
    match purge(&state.db).await {
        Ok(counts) => tracing::info!(
            messages = counts.messages,
            welcomes = counts.welcomes,
            sent_messages = counts.sent_messages,
            key_packages = counts.key_packages,
            departed_devices = counts.departed_devices,
            "purge done"
        ),
        Err(error) => tracing::error!(%error, "purge failed"),
    }
    match removals::sweep(state).await {
        Ok(issued) => tracing::info!(issued, "missing removals asked for"),
        Err(error) => tracing::error!(%error, "cannot look for missing removals"),
    }
}

/// Runs [`run_once`] now, then every [`INTERVAL`], until the runtime stops.
pub fn spawn(state: AppState) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
            if panics::guard(run_once(&state)).await.is_err() {
                tracing::error!("a pass of the purge panicked; the next one runs in an hour");
            }
        }
    })
}
