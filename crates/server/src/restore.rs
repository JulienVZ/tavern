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

use crate::notices::NoticeKind;
use crate::panics;

/// How far each conversation's numbering jumps at a restore: above any
/// number it can have given after the backup (2^32 messages, commits and
/// proposals since the backup), with room for 2^31 restores in a `bigint`.
pub const SEQUENCE_JUMP: i64 = 1 << 32;

/// The marker's file, in `TAVERN_DATA_DIR`.
pub const MARKER_FILE: &str = "instance-marker";
/// How often the marker is brought up to date, when something changed.
pub const MARKER_INTERVAL: Duration = Duration::from_secs(1);

const MARKER_HEADER: &str = "tavern-instance-marker 1";

/// What the server last saw of its database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Marker {
    /// The database it was (`instance_state.instance_id`): a database
    /// that finds the marker of another is handled as restored.
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
    /// The database went back behind the marker while the server ran.
    #[error(
        "the database went back in time while the server was running: it was restored without \
         stopping the server. The server stops; its next start handles the restore"
    )]
    WentBack,
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

/// What the database is now, as the marker records it: one query, which
/// is all the marker loop costs each second when nothing changed.
pub async fn current(db: &PgPool) -> Result<Marker, sqlx::Error> {
    let (instance_id, generation, last, called): (Uuid, i64, i64, bool) = sqlx::query_as(
        "SELECT s.instance_id, s.generation, c.last_value, c.is_called \
         FROM instance_state s, instance_changes c",
    )
    .fetch_one(db)
    .await?;
    Ok(Marker {
        instance_id,
        generation,
        changes: if called { last } else { 0 },
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
    /// Notices to administrators recorded: one per administrator.
    pub admin_notices: u64,
    /// Invitations still valid, revoked.
    pub invitations: u64,
    /// One-time KeyPackages deleted.
    pub key_packages: u64,
    /// Conversations marked for the recreation of their group.
    pub conversations: u64,
}

/// At start-up, before serving anything: reads the marker in `dir`, handles
/// a restore if there is one ([`handle`]), then writes the marker for the
/// database as it is now, which it returns. Any failure stops the start-up.
pub async fn at_start(db: &PgPool, dir: &Path) -> Result<(Start, Marker), RestoreError> {
    let marker = read(dir).await?;
    let start = handle(db, marker).await?;
    // Whatever the marker said, it is now behind, or of another database:
    // replaced.
    let marker = current(db).await?;
    write(db, dir, marker).await?;
    Ok((start, marker))
}

/// What the server does from its start to its stop, around `serve`: the
/// start-up ([`at_start`]) first, whose outcome `serve` is given; the marker
/// brought up to date every `every` meanwhile ([`spawn_marker`]); and at a
/// clean stop, the marker as the database is then ([`record`]). If the
/// database goes back meanwhile (restored while the server ran), `serve` is
/// dropped and [`RestoreError::WentBack`] returned: the server stops, and
/// its next start handles the restore.
pub async fn run<F, Fut, T>(
    db: &PgPool,
    dir: &Path,
    every: Duration,
    serve: F,
) -> Result<T, RestoreError>
where
    F: FnOnce(Start) -> Fut,
    Fut: Future<Output = T>,
{
    let (start, last) = at_start(db, dir).await?;
    let mut watch = spawn_marker(db.clone(), dir.to_owned(), last, every);
    let outcome = tokio::select! {
        outcome = serve(start) => outcome,
        _ = &mut watch => return Err(RestoreError::WentBack),
    };
    watch.abort();
    record(db, dir).await?;
    Ok(outcome)
}

async fn read(dir: &Path) -> Result<Option<Marker>, MarkerError> {
    let read = dir.to_owned();
    panics::blocking(move || read_marker(&read))
        .await
        .map_err(|_| MarkerError::Interrupted)?
}

async fn write(db: &PgPool, dir: &Path, marker: Marker) -> Result<(), RestoreError> {
    sqlx::query("UPDATE instance_state SET alive_at = now()")
        .execute(db)
        .await?;
    let write = dir.to_owned();
    panics::blocking(move || write_marker(&write, marker))
        .await
        .map_err(|_| MarkerError::Interrupted)??;
    Ok(())
}

/// Whether the database `now` is behind the marker `written`: another
/// database, an earlier generation, or fewer changes at the same one.
fn went_back(now: Marker, written: Marker) -> bool {
    now.instance_id != written.instance_id
        || now.generation < written.generation
        || (now.generation == written.generation && now.changes < written.changes)
}

/// Writes the marker for the database as it is now, and records in the
/// database when it did: the date that stands for the backup's when
/// `restore.sh` did not record one. Never backwards: a database behind the
/// marker on disk was restored while the server ran, and is left for the
/// next start to handle ([`RestoreError::WentBack`]).
pub async fn record(db: &PgPool, dir: &Path) -> Result<Marker, RestoreError> {
    let marker = current(db).await?;
    if let Some(written) = read(dir).await?
        && went_back(marker, written)
    {
        return Err(RestoreError::WentBack);
    }
    write(db, dir, marker).await?;
    Ok(marker)
}

/// Brings the marker up to date every `every`, when the database changed
/// ([`record`]). Ends only when the database went back: the restore is then
/// for the next start. Any other failure is logged, and the next pass tries
/// again.
pub fn spawn_marker(db: PgPool, dir: PathBuf, mut last: Marker, every: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(every);
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
                Ok(Err(RestoreError::WentBack)) => {
                    tracing::error!("{}", RestoreError::WentBack);
                    return;
                }
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
    // A marker of another database: this database may be a backup of the
    // instance restored on a new volume, or a new instance on an old one.
    // Handled as a restore: a false alarm costs every device a sign-in.
    let foreign = marker.is_some_and(|marker| marker.instance_id != instance_id);
    if foreign {
        tracing::warn!(
            "the instance marker in TAVERN_DATA_DIR was written for another database: this \
             database is handled as restored from a backup (every session revoked, every \
             conversation's group to recreate). If it is a new database on an old data \
             volume, nothing is lost but a sign-in on every device"
        );
    }
    let behind = foreign
        || marker.is_some_and(|marker| {
            generation < marker.generation
                || (generation == marker.generation && changes < marker.changes)
        });
    let recorded = generation > handled;
    if !behind && !recorded {
        tx.rollback().await?;
        return Ok(Start::Unchanged);
    }
    // A new generation (`restore.sh` raised it already), above every
    // generation the devices may have seen.
    let new_generation = if recorded { generation } else { generation + 1 };
    let new_generation = match marker {
        Some(marker) if new_generation <= marker.generation => marker.generation + 1,
        _ => new_generation,
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
    .bind(NoticeKind::InstanceRestored as i16)
    .bind(backup_taken_at_ms)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    // What the administrators did after the backup is undone too: accounts
    // disabled since are enabled again, roles and TOTP as they were. They
    // are told, as administrators of the restored database.
    let admin_notices = sqlx::query(
        "INSERT INTO security_notices (user_id, kind, backup_taken_at) \
         SELECT id, $1, to_timestamp($2::double precision / 1000) FROM users WHERE is_admin",
    )
    .bind(NoticeKind::InstanceRestoredAdmin as i16)
    .bind(backup_taken_at_ms)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    // An invitation revoked or used up after the backup is valid again:
    // none is, until an administrator creates new ones.
    let invitations = sqlx::query(
        "UPDATE instance_invites SET revoked_at = now() \
         WHERE revoked_at IS NULL AND uses < max_uses \
           AND (expires_at IS NULL OR expires_at > now())",
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let key_packages = sqlx::query("DELETE FROM key_packages WHERE NOT last_resort")
        .execute(&mut *tx)
        .await?
        .rows_affected();
    // The sequence numbers given after the backup are lost with it: each
    // conversation's numbering goes on above any of them, so that a device
    // never takes a new message for one it read before the restore.
    let conversations = sqlx::query(
        "UPDATE conversations SET needs_recreation = true, group_dead = false, \
                                      last_seq = last_seq + $1",
    )
    .bind(SEQUENCE_JUMP)
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
        admin_notices,
        invitations,
        key_packages,
        conversations,
    };
    tracing::warn!(
        generation = handled.generation,
        by_marker = handled.by_marker,
        sessions = handled.sessions,
        notices = handled.notices,
        admin_notices = handled.admin_notices,
        invitations = handled.invitations,
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
