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
//!   removed it or the server's proposal to remove it, the sender excepted.
//!   A revoked device is waited for no more: it will never read;
//! - a Welcome once acknowledged, or expired;
//! - an idempotency record of a sent message once expired (twice the
//!   retention);
//! - a KeyPackage once expired, served or not;
//! - the row of a device that left a group, once no message it was for and
//!   has not acknowledged remains (whatever expired first, whatever the
//!   retention), or once the device is revoked.
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
                JOIN devices v ON v.id = d.device_id AND v.revoked_at IS NULL \
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
           AND (EXISTS (SELECT 1 FROM devices v WHERE v.id = d.device_id AND v.revoked_at IS NOT NULL) \
                OR NOT EXISTS (SELECT 1 FROM messages m \
                               WHERE m.conversation_id = d.conversation_id \
                                 AND m.seq > GREATEST(d.joined_seq, d.acked_seq) \
                                 AND m.seq <= d.left_seq \
                                 AND m.sender_device_id IS DISTINCT FROM d.device_id))",
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
    spawn_every(INTERVAL, move || {
        let state = state.clone();
        async move { run_once(&state).await }
    })
}

/// Runs `pass` now, then every `every`, each run under [`panics::guard`]:
/// a pass that panics ends, and the next one runs at its time.
fn spawn_every<F, Fut>(every: Duration, pass: F) -> JoinHandle<()>
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(every);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
            if panics::guard(pass()).await.is_err() {
                tracing::error!("a pass of the purge panicked; the next one runs at its time");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[tokio::test]
    async fn a_pass_that_panics_does_not_stop_the_next_ones() {
        let passes = Arc::new(AtomicU32::new(0));
        let handle = spawn_every(Duration::from_millis(5), {
            let passes = Arc::clone(&passes);
            move || {
                let passes = Arc::clone(&passes);
                async move {
                    if passes.fetch_add(1, Ordering::SeqCst) == 0 {
                        panic!("the first pass fails");
                    }
                }
            }
        });
        tokio::time::timeout(Duration::from_secs(10), async {
            while passes.load(Ordering::SeqCst) < 3 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the passes after a panic never ran");
        assert!(!handle.is_finished());
        handle.abort();
    }
}
