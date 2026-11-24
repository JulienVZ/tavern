// SPDX-License-Identifier: AGPL-3.0-or-later

//! A restored backup (ADR 0019, sections 15 and 17).
//!
//! A restored database rewinds the instance: its groups are behind the
//! devices', and whatever changed after the backup is undone, revocations
//! included. The server tells it in two independent ways:
//!
//! - `restore.sh` raises the **instance generation** (`instance_state`) and
//!   records the date of the backup;
//! - the server keeps a **marker** in its data directory, outside the
//!   database: the instance generation and the counter of changes
//!   (`instance_changes`, advanced by every write to the database), written
//!   at start-up, every [`MARKER_INTERVAL`] when something changed, and at a
//!   clean stop. A database whose generation, or whose counter at the same
//!   generation, is behind the marker was restored, whoever restored it:
//!   the server raises the generation itself.
//!
//! At start-up, before it serves anything, the server handles a generation
//! it has not handled yet, in one transaction ([`handle`]): every session
//! revoked, the notice `INSTANCE_RESTORED` recorded for every account with
//! the date of the backup, every one-time KeyPackage deleted (those served
//! after the backup would be available again, and served twice), every
//! conversation marked for the recreation of its group. The generation is
//! marked handled at the end of that transaction only: a server stopped
//! halfway handles it again from the start. If the transaction fails, the
//! server does not start.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sqlx::{PgConnection, PgPool};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::panics;

/// The marker's file, in `TAVERN_DATA_DIR`.
pub const MARKER_FILE: &str = "instance-marker";
/// How often the marker is brought up to date, when something changed.
pub const MARKER_INTERVAL: Duration = Duration::from_secs(10);

const MARKER_HEADER: &str = "tavern-instance-marker 1";

/// What the server last saw of its database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Marker {
    /// The database it was (`instance_state.instance_id`): a marker of
    /// another database tells nothing about this one.
    pub instance_id: Uuid,
    /// The instance generation.
    pub generation: i64,
    /// The counter of changes.
    pub changes: i64,
}

impl Marker {
    fn encode(self) -> String {
        format!(
            "{MARKER_HEADER}\ninstance {}\ngeneration {}\nchanges {}\n",
            self.instance_id, self.generation, self.changes
        )
    }

    fn decode(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        if lines.next()? != MARKER_HEADER {
            return None;
        }
        let mut field = |name: &str| lines.next()?.strip_prefix(name)?.strip_prefix(' ');
        let instance_id = Uuid::parse_str(field("instance")?).ok()?;
        let generation = field("generation")?.parse().ok()?;
        let changes = field("changes")?.parse().ok()?;
        (lines.next().is_none() && generation >= 0 && changes >= 0).then_some(Self {
            instance_id,
            generation,
            changes,
        })
    }
}

/// The marker cannot be read or written.
#[derive(Debug, thiserror::Error)]
pub enum MarkerError {
    /// Reading, writing or creating the directory failed.
    #[error(
        "cannot use the marker {path}: {source}. Set TAVERN_DATA_DIR to a directory \
         the server can write to, outside the database's volume"
    )]
    Io {
        /// The marker's path.
        path: PathBuf,
        /// What failed.
        source: std::io::Error,
    },
    /// The blocking work on the file panicked or was cancelled.
    #[error("the work on the instance marker was interrupted")]
    Interrupted,
    /// The file is not a marker.
    #[error(
        "{0} is not a Tavern instance marker. If it was replaced by mistake, delete it: the \
         server writes a new one, without telling whether the database was restored this time"
    )]
    Malformed(PathBuf),
}

/// Handling a restore at start-up failed: the server does not start.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    /// The marker.
    #[error(transparent)]
    Marker(#[from] MarkerError),
    /// The database.
    #[error("cannot check whether the database was restored from a backup: {0}")]
    Database(#[from] sqlx::Error),
}

fn marker_path(dir: &Path) -> PathBuf {
    dir.join(MARKER_FILE)
}

/// Reads the marker in `dir`, if there is one.
pub fn read_marker(dir: &Path) -> Result<Option<Marker>, MarkerError> {
    let path = marker_path(dir);
    match std::fs::read_to_string(&path) {
        Ok(text) => Marker::decode(&text)
            .map(Some)
            .ok_or(MarkerError::Malformed(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(MarkerError::Io { path, source }),
    }
}

/// Writes the marker in `dir`, creating the directory if needed: to a
/// temporary file, synced, then renamed over the previous one, so that a
/// crash leaves the old marker or the new one, never half of one.
pub fn write_marker(dir: &Path, marker: Marker) -> Result<(), MarkerError> {
    let path = marker_path(dir);
    let io = |source| MarkerError::Io {
        path: path.clone(),
        source,
    };
    std::fs::create_dir_all(dir).map_err(io)?;
    let temporary = dir.join(format!("{MARKER_FILE}.tmp"));
    let mut file = std::fs::File::create(&temporary).map_err(io)?;
    file.write_all(marker.encode().as_bytes()).map_err(io)?;
    file.sync_all().map_err(io)?;
    drop(file);
    std::fs::rename(&temporary, &path).map_err(io)?;
    #[cfg(unix)]
    std::fs::File::open(dir)
        .and_then(|directory| directory.sync_all())
        .map_err(io)?;
    Ok(())
}

async fn changes(conn: &mut PgConnection) -> Result<i64, sqlx::Error> {
    let (last, called): (i64, bool) =
        sqlx::query_as("SELECT last_value, is_called FROM instance_changes")
            .fetch_one(conn)
            .await?;
    Ok(if called { last } else { 0 })
}

/// What the database is now, as the marker records it.
pub async fn current(db: &PgPool) -> Result<Marker, sqlx::Error> {
    let mut conn = db.acquire().await?;
    let (instance_id, generation): (Uuid, i64) =
        sqlx::query_as("SELECT instance_id, generation FROM instance_state")
            .fetch_one(&mut *conn)
            .await?;
    Ok(Marker {
        instance_id,
        generation,
        changes: changes(&mut conn).await?,
    })
}

/// The instance generation, announced in `Ready`.
pub async fn generation(db: &PgPool) -> Result<u64, sqlx::Error> {
    let generation: i64 = sqlx::query_scalar("SELECT generation FROM instance_state")
        .fetch_one(db)
        .await?;
    Ok(u64::try_from(generation).unwrap_or_default())
}

/// What the start-up found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start {
    /// The database was not restored since the last generation handled.
    Unchanged,
    /// A restore, handled now.
    Restored(Handled),
}

/// What handling a restore did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handled {
    /// The new instance generation.
    pub generation: i64,
    /// Whether the marker told it, `restore.sh` not having recorded it.
    pub by_marker: bool,
    /// When the backup was taken, in milliseconds since the Unix epoch, if
    /// known.
    pub backup_taken_at_ms: Option<i64>,
    /// Sessions revoked.
    pub sessions: u64,
    /// Notices recorded: one per account.
    pub notices: u64,
    /// One-time KeyPackages deleted.
    pub key_packages: u64,
    /// Conversations marked for the recreation of their group.
    pub conversations: u64,
}

/// At start-up, before serving anything: reads the marker in `dir`, handles
/// a restore if there is one ([`handle`]), then writes the marker for the
/// database as it is now, which it returns. Any failure stops the start-up.
pub async fn at_start(db: &PgPool, dir: &Path) -> Result<(Start, Marker), RestoreError> {
    let read = dir.to_owned();
    let marker = panics::blocking(move || read_marker(&read))
        .await
        .map_err(|_| MarkerError::Interrupted)??;
    let start = handle(db, marker).await?;
    let marker = record(db, dir).await?;
    Ok((start, marker))
}

/// Writes the marker for the database as it is now, and records in the
/// database when it did: the date that stands for the backup's when
/// `restore.sh` did not record one.
pub async fn record(db: &PgPool, dir: &Path) -> Result<Marker, RestoreError> {
    let marker = current(db).await?;
    sqlx::query("UPDATE instance_state SET alive_at = now()")
        .execute(db)
        .await?;
    let write = dir.to_owned();
    panics::blocking(move || write_marker(&write, marker))
        .await
        .map_err(|_| MarkerError::Interrupted)??;
    Ok(marker)
}

/// Brings the marker up to date every [`MARKER_INTERVAL`], when the database
/// changed, until the runtime stops. A failure is logged, and the next
/// pass tries again.
pub fn spawn_marker(db: PgPool, dir: PathBuf, mut last: Marker) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(MARKER_INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
            let pass = async {
                if current(&db).await? == last {
                    return Ok(None);
                }
                record(&db, &dir).await.map(Some)
            };
            match panics::guard(pass).await {
                Ok(Ok(Some(marker))) => last = marker,
                Ok(Ok(None)) => {}
                Ok(Err(error)) => tracing::error!(%error, "cannot update the instance marker"),
                Err(panics::Panicked) => tracing::error!("updating the instance marker panicked"),
            }
        }
    })
}

/// Handles a restore, if there is one, in one transaction: a generation
/// raised by `restore.sh` and not handled yet, or a database behind
/// `marker`. See the module documentation.
pub async fn handle(db: &PgPool, marker: Option<Marker>) -> Result<Start, sqlx::Error> {
    let mut tx = db.begin().await?;
    let (instance_id, generation, handled, backup_taken_at, alive_at): (
        Uuid,
        i64,
        i64,
        Option<i64>,
        Option<i64>,
    ) = sqlx::query_as(
        "SELECT instance_id, generation, handled_generation, \
                (extract(epoch FROM backup_taken_at) * 1000)::bigint, \
                (extract(epoch FROM alive_at) * 1000)::bigint \
         FROM instance_state FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?;
    let changes = changes(&mut tx).await?;
    let marker = match marker {
        Some(marker) if marker.instance_id != instance_id => {
            tracing::warn!(
                "the instance marker is for another database: it is replaced, and does not \
                 tell whether this one was restored"
            );
            None
        }
        marker => marker,
    };
    let behind = marker.is_some_and(|marker| {
        generation < marker.generation
            || (generation == marker.generation && changes < marker.changes)
    });
    let recorded = generation > handled;
    if !behind && !recorded {
        tx.rollback().await?;
        return Ok(Start::Unchanged);
    }
    // Above every generation the devices may have seen.
    let new_generation = match marker {
        Some(marker) if generation <= marker.generation => marker.generation + 1,
        _ => generation,
    };
    // `restore.sh` records the date of the backup it restores; otherwise
    // the last change the server recorded before the backup stands for it,
    // a few seconds earlier at most.
    let backup_taken_at_ms = backup_taken_at.filter(|_| recorded).or(alive_at);

    sqlx::query(
        "UPDATE instance_state SET generation = $1, \
             backup_taken_at = to_timestamp($2::double precision / 1000)",
    )
    .bind(new_generation)
    .bind(backup_taken_at_ms)
    .execute(&mut *tx)
    .await?;
    let sessions = sqlx::query("UPDATE sessions SET revoked_at = now() WHERE revoked_at IS NULL")
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let notices = sqlx::query(
        "INSERT INTO security_notices (user_id, kind, backup_taken_at) \
         SELECT id, $1, to_timestamp($2::double precision / 1000) FROM users",
    )
    .bind(crate::notices::NoticeKind::InstanceRestored as i16)
    .bind(backup_taken_at_ms)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let key_packages = sqlx::query("DELETE FROM key_packages WHERE NOT last_resort")
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let conversations = sqlx::query("UPDATE conversations SET needs_recreation = true")
        .execute(&mut *tx)
        .await?
        .rows_affected();
    // Last: the generation counts as handled once all of it is done.
    sqlx::query("UPDATE instance_state SET handled_generation = generation")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let handled = Handled {
        generation: new_generation,
        by_marker: behind,
        backup_taken_at_ms,
        sessions,
        notices,
        key_packages,
        conversations,
    };
    tracing::warn!(
        generation = handled.generation,
        by_marker = handled.by_marker,
        sessions = handled.sessions,
        notices = handled.notices,
        key_packages = handled.key_packages,
        conversations = handled.conversations,
        "the database was restored from a backup: every session is revoked, and every \
         conversation's group must be recreated"
    );
    Ok(Start::Restored(handled))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker() -> Marker {
        Marker {
            instance_id: Uuid::from_u128(7),
            generation: 2,
            changes: 345,
        }
    }

    #[test]
    fn a_marker_reads_back_what_was_written() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("not-yet-created");
        assert_eq!(read_marker(&nested).unwrap(), None);
        write_marker(&nested, marker()).unwrap();
        assert_eq!(read_marker(&nested).unwrap(), Some(marker()));
        let later = Marker {
            changes: 400,
            ..marker()
        };
        write_marker(&nested, later).unwrap();
        assert_eq!(read_marker(&nested).unwrap(), Some(later));
        assert!(!nested.join(format!("{MARKER_FILE}.tmp")).exists());
    }

    #[test]
    fn anything_else_is_not_a_marker() {
        let encoded = marker().encode();
        assert_eq!(Marker::decode(&encoded), Some(marker()));
        for text in [
            "",
            "tavern-instance-marker 2\ninstance 00000000-0000-0000-0000-000000000007\ngeneration 2\nchanges 345\n",
            "tavern-instance-marker 1\ninstance nope\ngeneration 2\nchanges 345\n",
            "tavern-instance-marker 1\ninstance 00000000-0000-0000-0000-000000000007\ngeneration -1\nchanges 345\n",
            "tavern-instance-marker 1\ninstance 00000000-0000-0000-0000-000000000007\ngeneration 2\n",
            "tavern-instance-marker 1\ninstance 00000000-0000-0000-0000-000000000007\ngeneration 2\nchanges 345\nmore\n",
        ] {
            assert_eq!(Marker::decode(text), None, "{text:?}");
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(MARKER_FILE), "garbage").unwrap();
        assert!(matches!(
            read_marker(dir.path()),
            Err(MarkerError::Malformed(_))
        ));
    }
}
